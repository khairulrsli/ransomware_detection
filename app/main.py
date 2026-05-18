import fnmatch
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from datetime import datetime

import pandas as pd
import psutil
from tensorflow.keras.models import load_model
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from detection_config import APP_DETECTION_THRESHOLD, ML_ALERT_THRESHOLD, WEIGHTS
import behavior_logger
from early_detection import predict_early_windows, DEFAULT_WINDOWS
from preprocessing import read_events_from_log
from process_supervisor import run_in_sandbox
from threat_database import db

APP_DIR    = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(APP_DIR)
MODEL_DIR  = os.path.join(PARENT_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "trained_model.h5")
LOG_FILE   = os.path.join(PARENT_DIR, "logs", "api_logs.csv")


def cvss_severity(composite: float):
    """Convert composite score [0-1] to CVSS v3.1 score [0-10] and severity label."""
    score = round(composite * 10, 1)
    if score == 0.0:
        label = "None"
    elif score < 4.0:
        label = "Low"
    elif score < 7.0:
        label = "Medium"
    elif score < 9.0:
        label = "High"
    else:
        label = "Critical"
    return score, label


# ── WHITELIST ──────────────────────────────────────────────────────────────────
LEGITIMATE_INSTALLERS = {
    'chrome':        r'chromesetup|chrome.*installer|googlechrome',
    'firefox':       r'firefoxsetup|firefox.*installer',
    'edge':          r'edgesetup|edge.*installer|microsoftedgeenterprise',
    'opera':         r'opera.*setup|operainstaller',
    'brave':         r'brave.*setup|bravebrowser',
    'winrar':        r'winrar|rar\.exe|unrar',
    '7zip':          r'7z|7-?zip',
    'python':        r'python.*msi|python.*exe|python-?\d',
    'git':           r'git.*setup|gitinstall|git-\d',
    'vscode':        r'vscode.*setup|vscodesetup|code.*setup',
    'nodejs':        r'node.*msi|nodejs|node-v\d',
    'java':          r'jdk.*installer|jre.*installer|java.*setup',
    'visualstudio':  r'vs_community|vs_professional|vs_enterprise|visualstudiosetup',
    'notepadpp':     r'npp.*installer|notepad\+\+',
    'office':        r'office.*setup|officesetup|outlook|word|excel|powerpoint',
    'libreoffice':   r'libreoffice.*install',
    'adobe':         r'adobe.*reader|acrobat.*install|adobereader',
    'zoom':          r'zoominstaller|zoom.*setup',
    'teams':         r'teams.*setup|msteams|microsoftteams',
    'discord':       r'discordsetup|discord.*install',
    'slack':         r'slack.*setup|slackinstall',
    'telegram':      r'telegramsetup|telegram.*desktop',
    'vlc':           r'vlc.*win|vlc.*setup|vlc-\d',
    'spotify':       r'spotifysetup|spotify.*install',
    'obs':           r'obs-studio|obs.*setup',
    'malwarebytes':  r'mbsetup|malwarebytes.*setup',
    'steam':         r'steamsetup|steam.*install',
    '.net':          r'dotnet.*installer|\.net.*framework|dotnet-runtime',
    'vcredist':      r'vcredist|visualcpp',
    'virtualbox':    r'virtualbox.*setup',
    'vmware':        r'vmware.*workstation|vmwareplayer',
    'wireshark':     r'wireshark.*setup',
    'putty':         r'putty.*installer|putty-.*-installer',
    'nvidia':        r'nvidia.*setup|geforce.*experience',
    'amd':           r'amd.*setup|radeon.*install',
}


def is_legitimate_installer(file_path):
    file_name = os.path.basename(file_path).lower()
    for app_name, pattern in LEGITIMATE_INSTALLERS.items():
        if re.search(pattern, file_name, re.IGNORECASE):
            return True, app_name
    return False, None


def validate_pe_file(file_path):
    try:
        if not os.path.exists(file_path):
            return False, "File does not exist"
        file_size = os.path.getsize(file_path)
        if file_size < 1024:
            return False, f"File too small ({file_size} bytes)"
        if file_size > 500 * 1024 * 1024:
            return False, f"File too large ({file_size / 1024 / 1024:.1f} MB)"
        with open(file_path, 'rb') as f:
            if f.read(2) != b'MZ':
                return False, "Not a valid Windows executable (missing MZ header)"
            f.seek(0x3C)
            offset_bytes = f.read(4)
            if len(offset_bytes) != 4:
                return False, "Invalid PE header"
            pe_offset = int.from_bytes(offset_bytes, 'little')
            if pe_offset <= 0 or pe_offset > file_size - 4:
                return False, "Invalid PE header offset"
            f.seek(pe_offset)
            if f.read(4) != b'PE\x00\x00':
                return False, "Not a valid Windows executable"
        return True, "Valid"
    except Exception as e:
        return False, f"Validation error: {e}"


# Load model once at startup
try:
    model = load_model(MODEL_PATH)
    print(f"[+] Model loaded from {MODEL_PATH}")
except FileNotFoundError:
    messagebox.showerror("Error", "Model not found! Run model/train_model.py first.")
    exit()
except Exception as e:
    messagebox.showerror("Error", f"Failed to load model: {e}")
    exit()


def kill_process_tree(file_path):
    """Suspend all processes from the same executable, then kill them."""
    all_procs = []
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            if proc.info['exe'] and os.path.abspath(proc.info['exe']) == os.path.abspath(file_path):
                all_procs.append(proc)
                try:
                    all_procs.extend(proc.children(recursive=True))
                except Exception:
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    for proc in all_procs:
        try:
            proc.suspend()
        except Exception:
            pass

    terminated = []
    for proc in all_procs:
        try:
            proc.kill()
            terminated.append(proc.pid)
            print(f"[!] Killed PID: {proc.pid}")
        except Exception:
            pass

    if all_procs:
        try:
            taskkill = shutil.which("taskkill") or r"C:\Windows\System32\taskkill.exe"
            subprocess.run(
                [taskkill, "/F", "/T", "/PID", str(all_procs[0].pid)],
                capture_output=True, timeout=3, check=False
            )
        except Exception:
            pass

    return terminated


def quarantine_file(file_path, file_name):
    """Move file to quarantine. Returns (success, quarantine_path)."""
    try:
        quarantine_dir = os.path.join(PARENT_DIR, "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        quarantine_path = os.path.join(quarantine_dir, file_name)
        if os.path.exists(file_path):
            shutil.move(file_path, quarantine_path)
            print(f"[+] Quarantined: {quarantine_path}")
            return True, quarantine_path
    except Exception as e:
        print(f"[!] Quarantine failed: {e}")
    return False, None


# Known ransomware-dropped component patterns: (glob, human label)
RANSOMWARE_DROP_PATTERNS = [
    ("*.wnry",     "WannaCry component"),
    ("taskdl.exe", "WannaCry task deleter"),
    ("taskse.exe", "WannaCry worm spreader"),
]


def scan_dropped_files(scan_dirs, skip_path=None):
    """
    Find known ransomware-dropped files in the given directories.
    Returns list of (abs_path, filename, label).
    skip_path: absolute path to exclude (the already-quarantined main file).
    """
    found = []
    skip_abs = os.path.abspath(skip_path) if skip_path else None
    for directory in scan_dirs:
        if not os.path.isdir(directory):
            continue
        try:
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if not os.path.isfile(fpath):
                    continue
                if skip_abs and os.path.abspath(fpath) == skip_abs:
                    continue
                for pattern, label in RANSOMWARE_DROP_PATTERNS:
                    if fnmatch.fnmatch(fname.lower(), pattern.lower()):
                        found.append((fpath, fname, label))
                        break
        except (OSError, PermissionError):
            pass
    return found


def run_on_ui(callback, *args, wait=False, **kwargs):
    """Run a Tkinter callback on the main UI thread."""
    if threading.current_thread() is threading.main_thread():
        return callback(*args, **kwargs)

    done = threading.Event()
    result = {"value": None, "error": None}

    def _wrapper():
        try:
            result["value"] = callback(*args, **kwargs)
        except Exception as exc:
            result["error"] = exc
        finally:
            done.set()

    root.after(0, _wrapper)
    if not wait:
        return None

    done.wait()
    exc = result["error"]
    if exc is not None:
        raise exc
    return result["value"]


def set_text_widget(widget, content):
    widget.config(state="normal")
    widget.delete("1.0", "end")
    widget.insert("end", content)
    widget.config(state="disabled")


def set_progress(status, progress, progress_text):
    status_var.set(status)
    progress_var.set(progress)
    progress_text_var.set(progress_text)
    prog_info_var.set(progress_text)
    frac = max(0.0, min(1.0, progress / 100.0))
    prog_fill.place(relwidth=frac)


def compute_threat_score(prediction, early_result, df, events):
    """
    Weighted Multi-Signal Fusion Engine.

    Combines 8 independent threat signals into a single composite score [0.0–1.0].
    Each signal is weighted by its discriminative power for ransomware detection.
    This replaces the naive OR-based rule system with a precision-optimized approach.
    """
    write_ops       = df[df["event"] == "WriteFile"].shape[0]
    rapid_writes    = df[df["event"] == "RapidFileWrite"].shape[0]
    busy_loops      = df[df["event"] == "BusyLoop"].shape[0]
    network_ops     = df[df["event"] == "NetworkConnect"].shape[0]
    high_entropy    = df[df["event"] == "HighEntropyFile"].shape[0]
    canary_hits     = df[df["event"] == "CanaryViolation"].shape[0]
    shadow_deletes  = df[df["event"] == "ShadowCopyDelete"].shape[0]
    suspicious_kids = df[df["event"] == "SuspiciousChild"].shape[0]
    early_terms     = df[df["event"] == "EarlyTermination"].shape[0]
    total_events    = len(df)

    # ── Signal 1: ML prediction score (weight: 0.30) ─────────────────────
    # Suppress ML signal when too few raw API events — LSTM is unreliable
    # on short sequences (early detection weakness; needs 150+ events).
    ml_signal = prediction if len(events) >= 50 else 0.0

    # ── Signal 2: Early detection alert (weight: 0.15) ───────────────────
    early_signal = 0.0
    if early_result["earliest_alert_window"] is not None:
        window = early_result["earliest_alert_window"]
        # Only trust early alerts from windows with enough data (>= 20 calls)
        # and scale gently — small windows are unreliable
        if window >= 20:
            early_signal = min(1.0, early_result["earliest_alert_score"])
        elif window >= 10:
            early_signal = min(1.0, early_result["earliest_alert_score"] * 0.5)

    # ── Signal 3: Rapid write intensity (weight: 0.15) ───────────────────
    # Require at least 2 rapid writes — a single file save is normal
    rapid_signal = min(1.0, max(0, rapid_writes - 1) / 3.0)

    # ── Signal 4: File entropy anomaly (weight: 0.15) ────────────────────
    entropy_signal = min(1.0, high_entropy / 2.0)

    # ── Signal 5: Canary violation — near-definitive (weight: 0.10) ──────
    canary_signal = min(1.0, canary_hits)

    # ── Signal 6: Shadow copy deletion — near-definitive (weight: 0.05) ──
    shadow_signal = min(1.0, shadow_deletes)

    # ── Signal 7: Network connections (weight: 0.05) ──────────────────────
    # 3+ outbound connections triggers full signal; single connection is benign
    network_signal = min(1.0, network_ops / 3.0)

    # ── Signal 8: Suspicious child processes (weight: 0.05) ──────────────
    child_signal = min(1.0, suspicious_kids / 2.0)

    composite = (
        WEIGHTS['ml']      * ml_signal +
        WEIGHTS['early']   * early_signal +
        WEIGHTS['rapid']   * rapid_signal +
        WEIGHTS['entropy'] * entropy_signal +
        WEIGHTS['canary']  * canary_signal +
        WEIGHTS['shadow']  * shadow_signal +
        WEIGHTS['network'] * network_signal +
        WEIGHTS['child']   * child_signal
    )

    # ── Override rules — definitive indicators bypass scoring ─────────────
    if canary_hits >= 1 or shadow_deletes >= 1:
        composite = max(composite, 0.95)
    if early_terms >= 1:
        composite = max(composite, 0.80)

    # Streaming risk from behavior_logger
    streaming_risk = behavior_logger.streaming_risk_score
    if streaming_risk > 0.5:
        composite = max(composite, streaming_risk * 0.9)

    # Determine threat level
    if composite >= 0.60:
        threat_level = "CRITICAL"
    elif composite >= 0.40:
        threat_level = "HIGH"
    elif composite >= 0.25:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    signals = {
        'ml_signal': ml_signal, 'early_signal': early_signal,
        'rapid_signal': rapid_signal, 'entropy_signal': entropy_signal,
        'canary_signal': canary_signal, 'shadow_signal': shadow_signal,
        'network_signal': network_signal, 'child_signal': child_signal,
        'streaming_risk': streaming_risk,
    }

    metrics = {
        'write_ops': write_ops, 'rapid_writes': rapid_writes,
        'busy_loops': busy_loops, 'network_ops': network_ops,
        'high_entropy': high_entropy, 'canary_violations': canary_hits,
        'shadow_deletes': shadow_deletes, 'suspicious_children': suspicious_kids,
    }

    return composite, threat_level, signals, metrics


def _hide_verdict_cards():
    verdict_idle.pack_forget()
    verdict_ransom.pack_forget()
    verdict_benign.pack_forget()


def _show_ransomware_card(composite, cvss_score, cvss_label):
    _hide_verdict_cards()
    verdict_score_var.set(f"{composite:.3f}")
    verdict_cvss_var.set(f"CVSS {cvss_score}")
    verdict_severity_var.set(cvss_label.upper())
    verdict_ransom.pack(fill="both", expand=True)


def _show_benign_card(composite, cvss_score, cvss_label):
    _hide_verdict_cards()
    benign_score_var.set(f"{composite:.3f}")
    benign_cvss_var.set(f"CVSS {cvss_score}")
    verdict_benign.pack(fill="both", expand=True)


def _update_metrics_panel(ml_score, write_ops, rapid_writes, busy_loops,
                          network_ops, ioc_items, action_text=None):
    """Update metrics panel after a scan.
    ioc_items: list of (name, count, severity) where severity is
               'critical', 'warning', or 'info'.
    """
    ml_conf_var.set(f"{ml_score * 100:.1f}%")

    bar_data = [
        (ml_score,     1.0),
        (write_ops,    200.0),
        (rapid_writes, 10.0),
        (busy_loops,   20.0),
        (network_ops,  10.0),
    ]
    raw_display = [
        f"{ml_score:.3f}",
        str(write_ops),
        str(rapid_writes),
        str(busy_loops),
        str(network_ops),
    ]
    for i, ((val, max_val), display) in enumerate(zip(bar_data, raw_display)):
        bar_value_vars[i].set(display)
        frac = min(1.0, float(val) / max_val) if max_val > 0 else 0.0
        bar_fills[i].place(relwidth=frac)

    for w in ioc_badges_frame.winfo_children():
        w.destroy()
    if not ioc_items:
        tk.Label(ioc_badges_frame, text="No indicators triggered",
                 font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
    else:
        SEVERITY_STYLE = {
            "critical": ("#3d0000", DANGER_RED,    "#ff444455"),
            "warning":  ("#3d1a00", WARN_ORANGE,   "#ffa50055"),
            "info":     (BG_INPUT,  TEXT_MUTED,    BORDER_COLOR),
        }
        for name, count, severity in ioc_items:
            bg_c, fg_c, bd_c = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
            chip = tk.Frame(ioc_badges_frame, bg=bg_c,
                            highlightbackground=bd_c, highlightthickness=1)
            chip.pack(side="left", padx=(0, 4), pady=2)
            tk.Label(chip, text=f"{name} ×{count}",
                     font=("Segoe UI", 8), fg=fg_c, bg=bg_c,
                     padx=6, pady=2).pack()

    for w in action_status_frame.winfo_children():
        w.destroy()
    if action_text:
        tk.Label(action_status_frame, text=f"✓  {action_text}",
                 font=("Segoe UI", 9, "bold"), fg=SUCCESS_GREEN,
                 bg="#0f1f0f", padx=8, pady=4).pack(side="left")
        action_status_frame.pack(fill="x", pady=(6, 0))
    else:
        action_status_frame.pack_forget()


def analyze_in_thread(file_path):
    try:
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path) / 1024

        run_on_ui(file_path_var.set, file_path, wait=True)
        run_on_ui(current_file.set, f"{file_name}\n({file_size:.1f} KB)", wait=True)
        run_on_ui(set_progress, "Executing behavioral sandbox analysis...", 10, "10% - Running analysis", wait=True)
        run_on_ui(result_var.set, "", wait=True)
        run_on_ui(_hide_verdict_cards, wait=True)
        run_on_ui(verdict_idle.pack, wait=True)
        run_on_ui(delete_btn.config, state="disabled", wait=True)

        # Known installer names are useful context, but filename alone is not a
        # trustworthy allow-list signal. Continue with analysis either way.
        is_legit, app_name = is_legitimate_installer(file_path)
        installer_note = f"Installer-name match: {app_name}. " if is_legit else ""

        run_in_sandbox(file_path)

        if not os.path.exists(LOG_FILE):
            run_on_ui(messagebox.showerror, "Error", f"Log file not created: {LOG_FILE}", wait=True)
            run_on_ui(set_progress, "Error: Log file not created", 0, "Failed", wait=True)
            return

        if behavior_logger.early_termination_triggered:
            run_on_ui(set_progress, "Early termination - threat detected fast!", 60,
                      "60% - Early threat detected", wait=True)

        run_on_ui(set_progress, "Analyzing behavioral logs...", 50,
                  "50% - Processing logs", wait=True)

        df = pd.read_csv(LOG_FILE)
        if len(df) == 0 or "event" not in df.columns:
            _cvss_score, _cvss_label = cvss_severity(0.0)
            run_on_ui(_show_benign, "No activity detected", "BENIGN", "N/A", wait=True)
            run_on_ui(_show_benign_card, 0.0, _cvss_score, _cvss_label, wait=True)
            run_on_ui(_update_metrics_panel, 0.0, 0, 0, 0, 0, [], None, wait=True)
            return

        # LSTM prediction with enhanced early detection
        # Strip derived/heuristic events — they aren't in the training vocabulary
        # and map to <OOV>, corrupting the LSTM score. Heuristics are already
        # counted separately in the composite score signals below.
        DERIVED_EVENTS = {
            "RapidFileWrite", "BusyLoop", "HighEntropyFile", "CanaryViolation",
            "ShadowCopyDelete", "SuspiciousChild", "EarlyTermination",
            "TerminateProcess", "NetworkConnect",
        }
        events = read_events_from_log(LOG_FILE)
        raw_events = [e for e in events if e not in DERIVED_EVENTS]
        early_result = predict_early_windows(model, raw_events, windows=DEFAULT_WINDOWS, threshold=ML_ALERT_THRESHOLD)
        prediction   = early_result["final_score"]

        run_on_ui(progress_var.set, 75, wait=True)
        run_on_ui(progress_text_var.set, "75% - Multi-Signal Fusion", wait=True)

        # ── WEIGHTED MULTI-SIGNAL FUSION ─────────────────────────────────
        composite, threat_level, signals, metrics = compute_threat_score(
            prediction, early_result, df, raw_events
        )

        write_ops    = metrics['write_ops']
        rapid_writes = metrics['rapid_writes']
        busy_loops   = metrics['busy_loops']
        network_ops  = metrics['network_ops']

        # Archivers/installers produce high-entropy rapid-write patterns that
        # resemble ransomware. Discount score when whitelist matches and no
        # definitive indicator (canary, shadow delete) fired.
        if is_legit and metrics.get('canary_violations', 0) == 0 and metrics.get('shadow_deletes', 0) == 0:
            composite *= 0.5
            if composite >= 0.60:   threat_level = "CRITICAL"
            elif composite >= 0.40: threat_level = "HIGH"
            elif composite >= 0.25: threat_level = "MEDIUM"
            else:                   threat_level = "LOW"

        # Detection threshold: composite >= APP_DETECTION_THRESHOLD triggers ransomware verdict.
        # Keep this named because it requires calibration when datasets change.
        is_ransomware = composite >= APP_DETECTION_THRESHOLD

        if is_ransomware:
            run_on_ui(set_progress, "Terminating malicious process...", 85,
                      "85% - Responding to threat", wait=True)

            terminated = kill_process_tree(file_path)
            time.sleep(1)
            quarantined, quarantine_path = quarantine_file(file_path, file_name)

            if quarantined:
                db.add_quarantine(file_name, quarantine_path, file_path, threat_level)

            # Scan for and quarantine dropped components (e.g. WannaCry *.wnry, taskdl.exe)
            drop_scan_dirs = list({
                os.path.dirname(file_path),
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.environ.get("TEMP", ""),
            })
            dropped_found = scan_dropped_files(drop_scan_dirs, skip_path=file_path)
            dropped_lines = []
            for fpath, fname, label in dropped_found:
                ok, qpath = quarantine_file(fpath, fname)
                status = "quarantined" if ok else "locked"
                if ok:
                    db.add_quarantine(fname, qpath, fpath, f"DROPPED:{threat_level}")
                    print(f"[+] Dropped component quarantined: {fname}")
                dropped_lines.append(f"  * {fname:<22}: {label} [{status}]")
            cleanup_section = "\n".join(dropped_lines) if dropped_lines else "  No dropped components found"

            cvss_score, cvss_label = cvss_severity(composite)

            ioc_lines = []
            ioc_map = [
                ("RapidFileWrite",   rapid_writes,                          "events"),
                ("HighEntropyFile",  metrics.get("high_entropy", 0),        "files"),
                ("CanaryViolation",  metrics.get("canary_violations", 0),   "hits"),
                ("ShadowCopyDelete", metrics.get("shadow_deletes", 0),      "events"),
                ("NetworkConnect",   network_ops,                           "outbound"),
                ("SuspiciousChild",  metrics.get("suspicious_children", 0), "processes"),
                ("BusyLoop",         busy_loops,                            "events"),
            ]
            for name, count, unit in ioc_map:
                if count > 0:
                    ioc_lines.append(f"  * {name:<20}: {count} {unit}")
            ioc_section = "\n".join(ioc_lines) if ioc_lines else "  No indicators triggered"

            IOC_SEVERITY = {
                "CanaryViolation":  "critical",
                "ShadowCopyDelete": "critical",
                "RapidFileWrite":   "warning",
                "HighEntropyFile":  "warning",
            }
            ioc_badge_items = []
            for name, count, unit in ioc_map:
                if count > 0:
                    sev = IOC_SEVERITY.get(name, "info")
                    ioc_badge_items.append((name, count, sev))

            action_str = (f"Process killed · "
                          f"{'Quarantined' if quarantined else 'Not quarantined'}")
            run_on_ui(_show_ransomware_card, composite, cvss_score, cvss_label, wait=True)
            run_on_ui(_update_metrics_panel,
                      prediction, write_ops, rapid_writes, busy_loops, network_ops,
                      ioc_badge_items, action_str, wait=True)

            if quarantined and quarantine_path:
                def _delete_permanently(qpath=quarantine_path, fname=file_name):
                    try:
                        if os.path.exists(qpath):
                            os.chmod(qpath, stat.S_IWRITE | stat.S_IREAD)
                            os.remove(qpath)
                        delete_btn.config(state="disabled", text="Permanently Deleted")
                        messagebox.showinfo("Deleted", f"{fname} permanently deleted.")
                    except Exception as e:
                        messagebox.showerror("Error", f"Could not delete: {e}")
                run_on_ui(delete_btn.config,
                    state="normal",
                    command=_delete_permanently,
                    wait=True
                )

            if early_result["earliest_alert_window"] is not None:
                reason = (f"Early detection at call {early_result['earliest_alert_window']} "
                          f"(score: {early_result['earliest_alert_score']*100:.1f}%)")
            else:
                reason = f"Threat score {composite:.3f} ({threat_level})"
            reason = installer_note + reason

            run_on_ui(result_var.set, "RANSOMWARE DETECTED", wait=True)
            run_on_ui(confidence_var.set, f"Score: {composite*100:.1f}% | {threat_level}", wait=True)
            run_on_ui(status_var.set, f"Complete: {reason}", wait=True)
            run_on_ui(status_label.config, fg=DANGER_RED, wait=True)
            action = "QUARANTINED" if quarantined else "ALERTED"
            run_on_ui(add_history_entry, file_name, "RANSOMWARE", f"{composite*100:.1f}%", wait=True)
            db.add_analysis(file_name, "RANSOMWARE", composite, prediction,
                {'write_ops': write_ops, 'rapid_writes': rapid_writes,
                 'busy_loops': busy_loops, 'network_ops': network_ops},
                action, reason)

        else:
            cvss_score, cvss_label = cvss_severity(composite)

            ioc_lines = []
            ioc_map = [
                ("RapidFileWrite",   rapid_writes,                          "events"),
                ("HighEntropyFile",  metrics.get("high_entropy", 0),        "files"),
                ("CanaryViolation",  metrics.get("canary_violations", 0),   "hits"),
                ("ShadowCopyDelete", metrics.get("shadow_deletes", 0),      "events"),
                ("NetworkConnect",   network_ops,                           "outbound"),
                ("SuspiciousChild",  metrics.get("suspicious_children", 0), "processes"),
                ("BusyLoop",         busy_loops,                            "events"),
            ]
            for name, count, unit in ioc_map:
                if count > 0:
                    ioc_lines.append(f"  * {name:<20}: {count} {unit}")
            ioc_section = "\n".join(ioc_lines) if ioc_lines else "  No indicators triggered"

            IOC_SEVERITY = {
                "CanaryViolation":  "critical",
                "ShadowCopyDelete": "critical",
                "RapidFileWrite":   "warning",
                "HighEntropyFile":  "warning",
            }
            ioc_badge_items = []
            for name, count, unit in ioc_map:
                if count > 0:
                    sev = IOC_SEVERITY.get(name, "info")
                    ioc_badge_items.append((name, count, sev))
            run_on_ui(_show_benign_card, composite, cvss_score, cvss_label, wait=True)
            run_on_ui(_update_metrics_panel,
                      prediction, write_ops, rapid_writes, busy_loops, network_ops,
                      ioc_badge_items, None, wait=True)
            run_on_ui(_show_benign, "Normal application behavior", "BENIGN", f"{composite*100:.1f}%", wait=True)
            db.add_analysis(file_name, "BENIGN FILE", composite, prediction,
                {'write_ops': write_ops, 'rapid_writes': rapid_writes,
                 'busy_loops': busy_loops, 'network_ops': network_ops},
                "NONE", installer_note + "Normal behavior")

        run_on_ui(progress_var.set, 100, wait=True)
        run_on_ui(progress_text_var.set, "100% - Complete", wait=True)

    except Exception as e:
        run_on_ui(messagebox.showerror, "Error", f"Analysis failed: {str(e)}", wait=True)
        run_on_ui(set_progress, "Error during analysis", 0, "Failed", wait=True)


def _show_benign(reason, history_verdict, history_conf):
    result_var.set("BENIGN FILE")
    confidence_var.set(f"Confidence: {history_conf}")
    status_var.set(f"Complete: {reason}")
    status_label.config(fg=SUCCESS_GREEN)
    progress_var.set(100)
    progress_text_var.set("100% - Complete")
    prog_info_var.set("100% - Complete")
    prog_fill.place(relwidth=1.0)
    add_history_entry(
        current_file.get().split("\n")[0],
        history_verdict, history_conf
    )


def start_analysis():
    file_path = filedialog.askopenfilename(
        filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")]
    )
    if not file_path:
        return
    is_valid, msg = validate_pe_file(file_path)
    if not is_valid:
        messagebox.showerror("Invalid File", f"File validation failed:\n\n{msg}")
        return
    worker = threading.Thread(target=analyze_in_thread, args=(file_path,), daemon=True)
    worker.start()


def add_history_entry(filename, verdict, confidence):
    tag = "ransom" if "RANSOM" in verdict.upper() else "benign"
    entry = f"  ● {filename[:28]}  [{verdict}]  {confidence}"
    analysis_history.insert(0, (entry, tag))
    if len(analysis_history) > 8:
        analysis_history.pop()
    history_text.config(state="normal")
    history_text.delete("1.0", "end")
    for item, t in analysis_history:
        history_text.insert("end", item + "   ", t)
    history_text.config(state="disabled")
    history_count_var.set(f"{len(analysis_history)} scans this session")


def refresh_statistics():
    stats = db.get_statistics()
    total = max(stats.get('total_scans', 1), 1)
    rate  = stats.get('ransomware_detected', 0) / total * 100
    content = (
        f"Total Scans         : {stats.get('total_scans', 0)}\n"
        f"Ransomware Detected : {stats.get('ransomware_detected', 0)}\n"
        f"Benign Files        : {stats.get('benign_detected', 0)}\n"
        f"Avg ML Confidence   : {stats.get('avg_confidence', 0):.3f}\n"
        f"Detection Rate      : {rate:.1f}%\n"
    )
    stats_text.config(state="normal")
    stats_text.delete("1.0", "end")
    stats_text.insert("end", content)
    stats_text.config(state="disabled")

    recent = db.get_recent_analyses(20)
    history_view.config(state="normal")
    history_view.delete("1.0", "end")
    history_view.insert("end",
        f"{'Timestamp':<20} {'Filename':<25} {'Verdict':<20} Score\n" + "-" * 75 + "\n")
    for r in recent:
        ts = r['timestamp'].split('.')[0] if r['timestamp'] else "N/A"
        try:
            score = float(r['ml_score']) if r['ml_score'] is not None else 0.0
        except (ValueError, TypeError):
            score = 0.0
        history_view.insert("end",
            f"{ts:<20} {r['filename'][:24]:<25} {r['verdict'][:19]:<20} {score:.3f}\n")
    history_view.config(state="disabled")


def export_report():
    csv_content = db.export_analysis_report()
    if not csv_content:
        messagebox.showwarning("No Data", "No analysis history to export.")
        return
    save_path = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV Files", "*.csv")]
    )
    if save_path:
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(csv_content)
        messagebox.showinfo("Exported", f"Report saved to:\n{save_path}")


def clear_history():
    """Clear all analysis history and quarantine records from the database."""
    confirm = messagebox.askyesno("Clear History",
        "This will delete ALL analysis history and quarantine records.\n\n"
        "This cannot be undone. Continue?")
    if not confirm:
        return
    db.clear_all_data()
    refresh_statistics()
    show_quarantine()
    # Clear session history in GUI
    history_text.config(state="normal")
    history_text.delete("1.0", "end")
    history_text.config(state="disabled")
    analysis_history.clear()
    history_count_var.set("0 scans this session")
    messagebox.showinfo("Cleared", "All history and quarantine records deleted.")


def show_quarantine():
    quarantine_list = db.get_quarantine_list()
    quarantine_view.config(state="normal")
    quarantine_view.delete("1.0", "end")
    if not quarantine_list:
        quarantine_view.insert("end", "No quarantined files.\n")
    else:
        quarantine_view.insert("end",
            f"{'Date':<20} {'Filename':<35} Threat Level\n" + "-" * 70 + "\n")
        for q in quarantine_list:
            ts = q['timestamp'].split('.')[0] if q['timestamp'] else "N/A"
            quarantine_view.insert("end",
                f"{ts:<20} {q['filename'][:34]:<35} {q['threat_level']}\n")
    quarantine_view.config(state="disabled")


def delete_quarantine_file():
    """Delete selected quarantined file permanently from disk and database."""
    quarantine_list = db.get_quarantine_list()
    if not quarantine_list:
        messagebox.showinfo("No Files", "No quarantined files to delete.")
        return

    # Build selection dialog
    sel_win = tk.Toplevel(root)
    sel_win.title("Delete Quarantined File")
    sel_win.geometry("480x380")
    sel_win.config(bg="#f8f9fb")
    sel_win.transient(root)
    sel_win.grab_set()

    tk.Label(sel_win, text="Select file to delete:", font=HEADER_FONT,
             bg="#f8f9fb", fg="#1f2937").pack(pady=(16, 8))

    listbox = tk.Listbox(sel_win, font=MONO_FONT, height=12, selectmode="single",
                          bg="#ffffff", fg="#1f2937", relief="flat",
                          selectbackground="#6366f1", selectforeground="white",
                          highlightbackground="#e1e4e8", highlightthickness=1)
    listbox.pack(fill="both", expand=True, padx=20, pady=4)

    for q in quarantine_list:
        listbox.insert("end", f"{q['filename']}  ({q['threat_level']})")

    def _do_delete():
        sel = listbox.curselection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a file first.", parent=sel_win)
            return
        idx = sel[0]
        q = quarantine_list[idx]
        confirm = messagebox.askyesno("Confirm Delete",
            f"Permanently delete {q['filename']}?\n\nThis cannot be undone.",
            parent=sel_win)
        if not confirm:
            return
        try:
            qpath = q.get('quarantine_path', '')
            if qpath and os.path.exists(qpath):
                os.chmod(qpath, stat.S_IWRITE | stat.S_IREAD)
                os.remove(qpath)
        except Exception as e:
            print(f"[!] Could not delete file: {e}")
        db.delete_quarantine(q['id'])
        messagebox.showinfo("Deleted", f"{q['filename']} permanently deleted.", parent=sel_win)
        sel_win.destroy()
        show_quarantine()

    btn_frame = tk.Frame(sel_win, bg="#f8f9fb")
    btn_frame.pack(fill="x", padx=20, pady=14)
    tk.Button(btn_frame, text="DELETE", font=BTN_FONT, bg=DANGER_COLOR,
              fg="white", command=_do_delete, padx=18, pady=8,
              border=0, cursor="hand2", activebackground="#dc2626").pack(side="left", padx=4)
    tk.Button(btn_frame, text="Cancel", font=BTN_FONT, bg="#d1d5db",
              fg="#374151", command=sel_win.destroy, padx=18, pady=8,
              border=0, cursor="hand2", activebackground="#b8bcc4").pack(side="right", padx=4)


# ── GUI ────────────────────────────────────────────────────────────────────────
root = tk.Tk()
root.title("Ransomware Detection System")
root.geometry("1120x860")
root.resizable(True, True)

# ── THEME PALETTE (Dark / Cyber) ──────────────────────────────────────────────
BG_DEEP         = "#0d1117"   # window background
BG_CARD         = "#161b22"   # card / panel backgrounds
BG_INPUT        = "#21262d"   # input fields, progress track
BORDER_COLOR    = "#30363d"   # all card/panel borders
TEXT_PRIMARY    = "#e6edf3"   # primary text
TEXT_MUTED      = "#8b949e"   # labels, secondary text
ACCENT_BLUE     = "#58a6ff"   # accent, links
DANGER_RED      = "#ff4444"   # ransomware verdict, critical IOCs
WARN_ORANGE     = "#ffa500"   # warning IOCs
SUCCESS_GREEN   = "#3fb950"   # benign verdict, quarantine confirmed
BTN_BLUE        = "#1f6feb"   # primary action button fill
BTN_BLUE_BORDER = "#388bfd"
DANGER_DARK     = "#1a0000"   # ransomware card background
SUCCESS_DARK    = "#0f3d1f"   # benign card background

# Aliases kept so existing references compile unchanged
BG_DARK         = BG_DEEP
SURFACE         = BG_CARD
SURFACE_LIGHT   = BG_INPUT
PRIMARY_COLOR   = ACCENT_BLUE
SECONDARY_COLOR = ACCENT_BLUE
SUCCESS_COLOR   = SUCCESS_GREEN
DANGER_COLOR    = DANGER_RED
WARNING_COLOR   = WARN_ORANGE
BG_COLOR        = BG_DEEP
DARK_TEXT       = TEXT_PRIMARY
LIGHT_TEXT      = TEXT_MUTED
INPUT_BG        = BG_INPUT
HEADER_BG       = BG_CARD

root.config(bg=BG_DEEP)

TITLE_FONT  = ("Segoe UI", 18, "bold")
HEADER_FONT = ("Segoe UI", 12, "bold")
BTN_FONT    = ("Segoe UI", 10, "bold")
TEXT_FONT   = ("Segoe UI", 10)
SMALL_FONT  = ("Segoe UI", 9)
MONO_FONT   = ("Consolas", 9)


def _hover(w, enter_bg, leave_bg):
    w.bind("<Enter>", lambda e: w.config(bg=enter_bg))
    w.bind("<Leave>", lambda e: w.config(bg=leave_bg))


def _btn(parent, text, bg_c, cmd, **pack_kw):
    b = tk.Button(parent, text=text, font=BTN_FONT, bg=bg_c, fg="white",
                  command=cmd, padx=18, pady=9, border=0, cursor="hand2",
                  activebackground=bg_c, activeforeground="white")
    _hover(b, _lit(bg_c), bg_c)
    b.pack(**pack_kw)
    return b


def _lit(hc):
    r, g, b = int(hc[1:3], 16), int(hc[3:5], 16), int(hc[5:7], 16)
    return f"#{min(255,r+30):02x}{min(255,g+30):02x}{min(255,b+30):02x}"


current_file      = tk.StringVar(value="No file selected")
confidence_var    = tk.StringVar(value="")
progress_var      = tk.DoubleVar(value=0)
progress_text_var = tk.StringVar(value="")
status_var        = tk.StringVar(value="Ready")
result_var        = tk.StringVar()
analysis_history  = []

# ── TTK STYLES ─────────────────────────────────────────────────────────────────
style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook", background=BG_DEEP, borderwidth=0)
style.configure("TNotebook.Tab", background=BG_CARD, foreground=TEXT_MUTED,
                padding=[18, 10], font=BTN_FONT, borderwidth=0)
style.map("TNotebook.Tab",
          background=[("selected", BG_DEEP)],
          foreground=[("selected", ACCENT_BLUE)])
style.configure("Custom.Horizontal.TProgressbar",
                background=ACCENT_BLUE, troughcolor=BG_INPUT,
                borderwidth=0, thickness=8)

# ── HEADER ─────────────────────────────────────────────────────────────────────
header = tk.Frame(root, bg=BG_CARD, height=52)
header.pack(fill="x")
header.pack_propagate(False)
tk.Frame(root, bg=BORDER_COLOR, height=1).pack(fill="x")

hf = tk.Frame(header, bg=BG_CARD)
hf.pack(fill="both", expand=True, padx=20)

title_f = tk.Frame(hf, bg=BG_CARD)
title_f.pack(side="left", fill="y", pady=8)
tk.Label(title_f, text="●", font=("Segoe UI", 10), fg=DANGER_RED,
         bg=BG_CARD).pack(side="left", padx=(0, 8))
tk.Label(title_f, text="RANSOMWARE DETECTION SYSTEM",
         font=("Segoe UI", 11, "bold"), fg=ACCENT_BLUE, bg=BG_CARD).pack(side="left")

si = tk.Frame(hf, bg=BG_CARD)
si.pack(side="right", pady=8)
active_bg = tk.Frame(si, bg="#0f3d1f", padx=8, pady=2)
active_bg.pack(side="right")
tk.Label(active_bg, text="● ACTIVE", font=("Segoe UI", 9, "bold"),
         fg=SUCCESS_GREEN, bg="#0f3d1f").pack()

# ── NOTEBOOK ───────────────────────────────────────────────────────────────────
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=14, pady=(14, 0))

# ── TAB 1: ANALYSIS ───────────────────────────────────────────────────────────
at = tk.Frame(notebook, bg=BG_DEEP)
notebook.add(at, text="  Analysis  ")
ac = tk.Frame(at, bg=BG_DEEP)
ac.pack(fill="both", expand=True, padx=12, pady=10)

# ── File row ──────────────────────────────────────────────────────────────────
file_row = tk.Frame(ac, bg=BG_DEEP)
file_row.pack(fill="x", pady=(0, 8))

file_path_var = tk.StringVar(value="No file selected")
path_entry = tk.Entry(file_row, textvariable=file_path_var, font=MONO_FONT,
                      bg=BG_CARD, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                      relief="flat", bd=0, highlightbackground=BORDER_COLOR,
                      highlightthickness=1, readonlybackground=BG_CARD,
                      state="readonly")
path_entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 6))

browse_btn = tk.Button(file_row, text="Browse", font=BTN_FONT,
                       bg=BG_INPUT, fg=TEXT_PRIMARY, padx=14, pady=7,
                       border=0, cursor="hand2",
                       activebackground=BORDER_COLOR, activeforeground=TEXT_PRIMARY,
                       highlightbackground=BORDER_COLOR, highlightthickness=1,
                       command=start_analysis)
browse_btn.pack(side="left", padx=(0, 6))

scan_btn = tk.Button(file_row, text="Scan", font=("Segoe UI", 10, "bold"),
                     bg=BTN_BLUE, fg="white", padx=20, pady=7,
                     border=0, cursor="hand2",
                     activebackground=BTN_BLUE_BORDER, activeforeground="white",
                     command=start_analysis)
scan_btn.pack(side="left")

# ── Progress bar card ─────────────────────────────────────────────────────────
prog_card = tk.Frame(ac, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                     highlightthickness=1)
prog_card.pack(fill="x", pady=(0, 8))

prog_inner = tk.Frame(prog_card, bg=BG_CARD)
prog_inner.pack(fill="x", padx=14, pady=8)

prog_label_row = tk.Frame(prog_inner, bg=BG_CARD)
prog_label_row.pack(fill="x", pady=(0, 4))
tk.Label(prog_label_row, text="Behavioral Analysis", font=("Segoe UI", 9),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
prog_info_var = tk.StringVar(value="")
tk.Label(prog_label_row, textvariable=prog_info_var, font=("Segoe UI", 9),
         fg=ACCENT_BLUE, bg=BG_CARD).pack(side="right")

prog_track = tk.Frame(prog_inner, bg=BG_INPUT, height=5)
prog_track.pack(fill="x")
prog_track.pack_propagate(False)
prog_fill = tk.Frame(prog_track, bg=ACCENT_BLUE, height=5)
prog_fill.place(x=0, y=0, relheight=1.0, relwidth=0.0)

status_label = tk.Label(prog_inner, textvariable=status_var, font=("Segoe UI", 9),
                        fg=TEXT_MUTED, bg=BG_CARD, anchor="w")
status_label.pack(fill="x", pady=(3, 0))

# ── Result row: verdict card (left) + metrics panel (right) ───────────────────
result_row = tk.Frame(ac, bg=BG_DEEP)
result_row.pack(fill="both", expand=True)

# Verdict card ─────────────────────────────────────────────────────────────────
verdict_outer = tk.Frame(result_row, bg=BG_DEEP, width=170)
verdict_outer.pack(side="left", fill="y", padx=(0, 8))
verdict_outer.pack_propagate(False)

# Idle placeholder (shown before first scan)
verdict_idle = tk.Frame(verdict_outer, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                        highlightthickness=1)
verdict_idle.pack(fill="both", expand=True)
tk.Label(verdict_idle, text="No scan\nyet", font=("Segoe UI", 10),
         fg=TEXT_MUTED, bg=BG_CARD, justify="center").pack(expand=True)

# Ransomware card (hidden until ransomware detected)
verdict_ransom = tk.Frame(verdict_outer, bg=DANGER_DARK,
                          highlightbackground=DANGER_RED, highlightthickness=1)
vr = tk.Frame(verdict_ransom, bg=DANGER_DARK)
vr.pack(fill="both", expand=True, padx=10, pady=10)
tk.Label(vr, text="⚠", font=("Segoe UI", 20), fg=DANGER_RED,
         bg=DANGER_DARK).pack(pady=(0, 2))
tk.Label(vr, text="RANSOMWARE", font=("Segoe UI", 9, "bold"),
         fg=DANGER_RED, bg=DANGER_DARK).pack()
tk.Label(vr, text="DETECTED", font=("Segoe UI", 8),
         fg="#ff666688", bg=DANGER_DARK).pack(pady=(0, 8))
vr_score_frame = tk.Frame(vr, bg="#2a0000")
vr_score_frame.pack(fill="x", pady=(0, 4))
tk.Label(vr_score_frame, text="THREAT SCORE", font=("Segoe UI", 7),
         fg=TEXT_MUTED, bg="#2a0000").pack(pady=(4, 0))
verdict_score_var = tk.StringVar(value="0.000")
tk.Label(vr_score_frame, textvariable=verdict_score_var,
         font=("Segoe UI", 16, "bold"), fg=DANGER_RED, bg="#2a0000").pack(pady=(0, 4))
vr_cvss_frame = tk.Frame(vr, bg="#2a0000")
vr_cvss_frame.pack(fill="x", pady=(0, 8))
verdict_cvss_var = tk.StringVar(value="CVSS -")
tk.Label(vr_cvss_frame, textvariable=verdict_cvss_var,
         font=("Segoe UI", 9, "bold"), fg=WARN_ORANGE, bg="#2a0000").pack(pady=2)
verdict_severity_var = tk.StringVar(value="")
tk.Label(vr_cvss_frame, textvariable=verdict_severity_var,
         font=("Segoe UI", 8), fg=DANGER_RED, bg="#2a0000").pack(pady=(0, 4))
quarantine_btn = tk.Button(vr, text="QUARANTINE", font=("Segoe UI", 8, "bold"),
                           bg=BG_CARD, fg=ACCENT_BLUE, padx=6, pady=4,
                           border=0, cursor="hand2",
                           activebackground=BG_INPUT, activeforeground=ACCENT_BLUE)
quarantine_btn.pack(fill="x", pady=(0, 3))
delete_btn = tk.Button(vr, text="DELETE", font=("Segoe UI", 8, "bold"),
                       bg=DANGER_DARK, fg=DANGER_RED, padx=6, pady=4,
                       border=0, cursor="hand2", state="disabled",
                       highlightbackground=DANGER_RED, highlightthickness=1,
                       activebackground="#2a0000", activeforeground=DANGER_RED)
delete_btn.pack(fill="x")

# Benign card (hidden until benign result)
verdict_benign = tk.Frame(verdict_outer, bg=SUCCESS_DARK,
                          highlightbackground=SUCCESS_GREEN, highlightthickness=1)
vb = tk.Frame(verdict_benign, bg=SUCCESS_DARK)
vb.pack(fill="both", expand=True, padx=10, pady=10)
tk.Label(vb, text="✓", font=("Segoe UI", 20), fg=SUCCESS_GREEN,
         bg=SUCCESS_DARK).pack(pady=(0, 2))
tk.Label(vb, text="SAFE", font=("Segoe UI", 9, "bold"),
         fg=SUCCESS_GREEN, bg=SUCCESS_DARK).pack()
tk.Label(vb, text="BENIGN", font=("Segoe UI", 8),
         fg="#3fb95088", bg=SUCCESS_DARK).pack(pady=(0, 8))
vb_score_frame = tk.Frame(vb, bg="#0a2a12")
vb_score_frame.pack(fill="x", pady=(0, 4))
tk.Label(vb_score_frame, text="THREAT SCORE", font=("Segoe UI", 7),
         fg=TEXT_MUTED, bg="#0a2a12").pack(pady=(4, 0))
benign_score_var = tk.StringVar(value="0.000")
tk.Label(vb_score_frame, textvariable=benign_score_var,
         font=("Segoe UI", 16, "bold"), fg=SUCCESS_GREEN, bg="#0a2a12").pack(pady=(0, 4))
vb_cvss_frame = tk.Frame(vb, bg="#0a2a12")
vb_cvss_frame.pack(fill="x")
benign_cvss_var = tk.StringVar(value="CVSS -")
tk.Label(vb_cvss_frame, textvariable=benign_cvss_var,
         font=("Segoe UI", 9, "bold"), fg=SUCCESS_GREEN, bg="#0a2a12").pack(pady=4)

# Metrics panel ────────────────────────────────────────────────────────────────
metrics_outer = tk.Frame(result_row, bg=BG_CARD,
                         highlightbackground=BORDER_COLOR, highlightthickness=1)
metrics_outer.pack(side="left", fill="both", expand=True)
mp = tk.Frame(metrics_outer, bg=BG_CARD)
mp.pack(fill="both", expand=True, padx=14, pady=10)

# ML confidence header row
ml_hdr = tk.Frame(mp, bg=BG_CARD)
ml_hdr.pack(fill="x", pady=(0, 8))
tk.Label(ml_hdr, text="ML Confidence", font=("Segoe UI", 9),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
ml_conf_var = tk.StringVar(value="-")
tk.Label(ml_hdr, textvariable=ml_conf_var,
         font=("Segoe UI", 13, "bold"), fg=DANGER_RED, bg=BG_CARD).pack(side="right")

# Progress bars
BAR_DEFS = [
    ("ML Score",     DANGER_RED),
    ("Write Ops",    WARN_ORANGE),
    ("Rapid Writes", WARN_ORANGE),
    ("Busy Loops",   ACCENT_BLUE),
    ("Network Conn", ACCENT_BLUE),
]
bar_value_vars = []
bar_fills = []
for label_text, bar_color in BAR_DEFS:
    brow = tk.Frame(mp, bg=BG_CARD)
    brow.pack(fill="x", pady=2)
    bl = tk.Frame(brow, bg=BG_CARD)
    bl.pack(fill="x", pady=(0, 2))
    tk.Label(bl, text=label_text, font=("Segoe UI", 8),
             fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
    val_var = tk.StringVar(value="-")
    bar_value_vars.append(val_var)
    tk.Label(bl, textvariable=val_var, font=("Segoe UI", 8),
             fg=bar_color, bg=BG_CARD).pack(side="right")
    track = tk.Frame(brow, bg=BG_INPUT, height=4)
    track.pack(fill="x")
    track.pack_propagate(False)
    fill = tk.Frame(track, bg=bar_color, height=4)
    fill.place(x=0, y=0, relheight=1.0, relwidth=0.0)
    bar_fills.append(fill)

# Divider
tk.Frame(mp, bg=BORDER_COLOR, height=1).pack(fill="x", pady=8)

# IOC badges container
ioc_label_row = tk.Frame(mp, bg=BG_CARD)
ioc_label_row.pack(fill="x", pady=(0, 4))
tk.Label(ioc_label_row, text="IOC INDICATORS", font=("Segoe UI", 8, "bold"),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
ioc_badges_frame = tk.Frame(mp, bg=BG_CARD)
ioc_badges_frame.pack(fill="x")
tk.Label(ioc_badges_frame, text="No scan yet", font=("Segoe UI", 8),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")

# Action status row (shown after ransomware result)
action_status_frame = tk.Frame(mp, bg="#0f1f0f",
                               highlightbackground="#238636", highlightthickness=1)
action_status_var = tk.StringVar(value="")

# Dummy metrics_text widget (kept for backward compat with any stray references)
metrics_text = tk.Text(mp, height=1, width=1, state="disabled")
metrics_text.pack_forget()

# ── TAB 2: STATISTICS ─────────────────────────────────────────────────────────
st_tab = tk.Frame(notebook, bg=BG_DEEP)
notebook.add(st_tab, text="  Statistics  ")
sc = tk.Frame(st_tab, bg=BG_DEEP)
sc.pack(fill="both", expand=True, padx=14, pady=14)

stats_card = tk.Frame(sc, bg=SURFACE, highlightbackground=BORDER_COLOR, highlightthickness=1)
stats_card.pack(fill="x", pady=(0, 10))
tk.Label(stats_card, text="OVERVIEW", font=("Segoe UI", 10, "bold"),
         fg=LIGHT_TEXT, bg=SURFACE).pack(anchor="w", padx=16, pady=(14, 0))
tk.Frame(stats_card, bg=BORDER_COLOR, height=1).pack(fill="x", padx=16, pady=(6, 0))
stats_text = tk.Text(stats_card, font=MONO_FONT, height=6, wrap="word",
                      bg=INPUT_BG, fg="#1f2937", relief="flat", padx=12, pady=10,
                      state="disabled", highlightbackground=BORDER_COLOR,
                      highlightthickness=1)
stats_text.pack(fill="x", padx=16, pady=(8, 16))

br = tk.Frame(sc, bg=BG_DARK)
br.pack(fill="x", pady=6)
_btn(br, "Refresh", SECONDARY_COLOR, refresh_statistics, side="left", padx=4)
_btn(br, "Export CSV", WARNING_COLOR, export_report, side="left", padx=4)
_btn(br, "Clear History", DANGER_COLOR, clear_history, side="left", padx=4)

hist_card = tk.Frame(sc, bg=SURFACE, highlightbackground=BORDER_COLOR, highlightthickness=1)
hist_card.pack(fill="both", expand=True, pady=(6, 0))
tk.Label(hist_card, text="ANALYSIS HISTORY", font=("Segoe UI", 10, "bold"),
         fg=LIGHT_TEXT, bg=SURFACE).pack(anchor="w", padx=16, pady=(14, 0))
tk.Frame(hist_card, bg=BORDER_COLOR, height=1).pack(fill="x", padx=16, pady=(6, 0))
history_view = tk.Text(hist_card, font=MONO_FONT, height=16, wrap="word",
                        bg=INPUT_BG, fg="#1f2937", relief="flat", padx=12, pady=10,
                        state="disabled", highlightbackground=BORDER_COLOR,
                        highlightthickness=1)
history_view.pack(fill="both", expand=True, padx=16, pady=(8, 16))

# ── TAB 3: QUARANTINE ─────────────────────────────────────────────────────────
qt_tab = tk.Frame(notebook, bg=BG_DEEP)
notebook.add(qt_tab, text="  Quarantine  ")
qc = tk.Frame(qt_tab, bg=BG_DEEP)
qc.pack(fill="both", expand=True, padx=14, pady=14)

qbr = tk.Frame(qc, bg=BG_DARK)
qbr.pack(fill="x", pady=(0, 10))
_btn(qbr, "Refresh", SECONDARY_COLOR, show_quarantine, side="left", padx=4)
_btn(qbr, "Delete File", DANGER_COLOR, delete_quarantine_file, side="left", padx=4)

q_card = tk.Frame(qc, bg=SURFACE, highlightbackground=BORDER_COLOR, highlightthickness=1)
q_card.pack(fill="both", expand=True)
tk.Label(q_card, text="QUARANTINED FILES", font=("Segoe UI", 10, "bold"),
         fg=LIGHT_TEXT, bg=SURFACE).pack(anchor="w", padx=16, pady=(14, 0))
tk.Frame(q_card, bg=BORDER_COLOR, height=1).pack(fill="x", padx=16, pady=(6, 0))
quarantine_view = tk.Text(q_card, font=MONO_FONT, height=20, wrap="word",
                           bg=INPUT_BG, fg="#1f2937", relief="flat", padx=12, pady=10,
                           state="disabled", highlightbackground=BORDER_COLOR,
                           highlightthickness=1)
quarantine_view.pack(fill="both", expand=True, padx=16, pady=(8, 16))

# ── FOOTER: SESSION HISTORY ───────────────────────────────────────────────────
tk.Frame(root, bg=BORDER_COLOR, height=1).pack(fill="x", side="bottom")
footer = tk.Frame(root, bg=BG_CARD)
footer.pack(fill="x", side="bottom")
fh = tk.Frame(footer, bg=BG_CARD)
fh.pack(fill="x", padx=20, pady=(8, 0))
tk.Label(fh, text="SCAN HISTORY", font=("Segoe UI", 8, "bold"),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
history_count_var = tk.StringVar(value="0 scans this session")
tk.Label(fh, textvariable=history_count_var, font=("Segoe UI", 8),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="right")
history_text = tk.Text(footer, font=MONO_FONT, height=2, width=110,
                       state="disabled", wrap="none", bg=BG_CARD, fg=TEXT_PRIMARY,
                       relief="flat", padx=10, pady=6,
                       highlightbackground=BORDER_COLOR, highlightthickness=0)
history_text.pack(fill="x", expand=False, padx=20, pady=(4, 10))
history_text.tag_configure("ransom", foreground=DANGER_RED)
history_text.tag_configure("benign", foreground=SUCCESS_GREEN)

refresh_statistics()
show_quarantine()
root.mainloop()
