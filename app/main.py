import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
from tensorflow.keras.models import load_model
import threading
import os
import psutil
import shutil
import stat
import time
import subprocess
from process_supervisor import run_in_sandbox
import behavior_logger
from preprocessing import read_events_from_log
from early_detection import predict_early_windows, DEFAULT_WINDOWS
from datetime import datetime
from threat_database import db
import re

APP_DIR    = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(APP_DIR)
MODEL_DIR  = os.path.join(PARENT_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "trained_model.h5")
LOG_FILE   = os.path.join(PARENT_DIR, "logs", "api_logs.csv")
APP_DETECTION_THRESHOLD = 0.25  # Calibrated: best precision/FP tradeoff on real-only test set
ML_ALERT_THRESHOLD = 0.5


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
                capture_output=True, timeout=3
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
    if result["error"] is not None:
        raise result["error"]
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

    # ── Weighted fusion ──────────────────────────────────────────────────
    WEIGHTS = {
        'ml':      0.30,
        'early':   0.15,
        'rapid':   0.15,
        'entropy': 0.15,
        'canary':  0.10,
        'shadow':  0.05,
        'network': 0.05,
        'child':   0.05,
    }

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


def analyze_in_thread(file_path):
    try:
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path) / 1024

        run_on_ui(current_file.set, f"{file_name}\n({file_size:.1f} KB)", wait=True)
        run_on_ui(set_progress, "Executing in VM analysis runner...", 10, "10% - Running VM runner", wait=True)
        run_on_ui(result_var.set, "", wait=True)
        run_on_ui(result_label.config, bg="#f0f1f4", fg="#6b7280", wait=True)
        run_on_ui(delete_btn.pack_forget, wait=True)

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
            run_on_ui(_show_benign, "No activity detected", "BENIGN", "N/A", wait=True)
            run_on_ui(set_text_widget, metrics_text,
                "No behavioral events recorded.\n"
                "File appears benign or exited too quickly.\n"
            , wait=True)
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

            run_on_ui(set_text_widget, metrics_text,
                f"Threat Score : {composite:.3f} ({threat_level})"
                f"   CVSS: {cvss_score} ({cvss_label})\n"
                f"ML Score     : {prediction:.3f}\n\n"
                f"Write Ops    : {write_ops}\n"
                f"Rapid Writes : {rapid_writes}\n"
                f"Busy Loops   : {busy_loops}\n"
                f"Network Conn : {network_ops}\n"
                f"High Entropy : {metrics.get('high_entropy', 0)}\n"
                f"Canary Hits  : {metrics.get('canary_violations', 0)}\n\n"
                f"Terminated   : {len(terminated)} processes\n"
                f"Status       : {'Quarantined' if quarantined else 'Not quarantined'}\n\n"
                f"IOC INDICATORS\n"
                f"--------------\n"
                f"{ioc_section}\n"
            , wait=True)

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
                    text="DELETE PERMANENTLY",
                    command=_delete_permanently,
                    wait=True
                )
                run_on_ui(delete_btn.pack, pady=8, fill="x", padx=5, wait=True)

            if early_result["earliest_alert_window"] is not None:
                reason = (f"Early detection at call {early_result['earliest_alert_window']} "
                          f"(score: {early_result['earliest_alert_score']*100:.1f}%)")
            else:
                reason = f"Threat score {composite:.3f} ({threat_level})"
            reason = installer_note + reason

            run_on_ui(result_var.set, "RANSOMWARE DETECTED", wait=True)
            run_on_ui(result_label.config, bg=DANGER_COLOR, fg="white", wait=True)
            run_on_ui(confidence_var.set, f"Score: {composite*100:.1f}% | {threat_level}", wait=True)
            run_on_ui(status_var.set, f"Complete: {reason}", wait=True)
            run_on_ui(status_label.config, fg=DANGER_COLOR, wait=True)
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

            run_on_ui(set_text_widget, metrics_text,
                f"Score        : {composite:.3f} (SAFE)"
                f"   CVSS: {cvss_score} ({cvss_label})\n"
                f"ML Score     : {prediction:.3f}\n\n"
                f"Write Ops    : {write_ops}\n"
                f"Busy Loops   : {busy_loops}\n"
                f"Network Conn : {network_ops}\n\n"
                f"FILE SAFE\n\n"
                f"IOC INDICATORS\n"
                f"--------------\n"
                f"{ioc_section}\n"
            , wait=True)
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
    result_label.config(bg=SUCCESS_COLOR, fg="white")
    confidence_var.set(f"Confidence: {history_conf}")
    status_var.set(f"Complete: {reason}")
    status_label.config(fg=SUCCESS_COLOR)
    progress_var.set(100)
    progress_text_var.set("100% - Complete")
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
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"{ts} | {filename[:28]:28} | {verdict:15} | {confidence}"
    analysis_history.insert(0, entry)
    if len(analysis_history) > 10:
        analysis_history.pop()
    history_text.config(state="normal")
    history_text.delete("1.0", "end")
    for item in analysis_history:
        history_text.insert("end", item + "\n")
    history_text.config(state="disabled")


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
        with open(save_path, 'w') as f:
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

# ── THEME PALETTE (Light) ──────────────────────────────────────────────────────
BG_DARK         = "#f3f4f6"      # main background
SURFACE         = "#ffffff"      # cards / panels
SURFACE_LIGHT   = "#f0f1f4"      # inset areas
BORDER_COLOR    = "#e1e4e8"      # subtle borders
PRIMARY_COLOR   = "#6366f1"      # indigo accent
SECONDARY_COLOR = "#818cf8"      # lighter indigo
SUCCESS_COLOR   = "#16a34a"      # green
DANGER_COLOR    = "#dc2626"      # red
WARNING_COLOR   = "#d97706"      # amber
BG_COLOR        = "#f3f4f6"
DARK_TEXT        = "#1f2937"      # dark text
LIGHT_TEXT       = "#6b7280"      # muted text
INPUT_BG         = "#f9fafb"      # input / text area bg
HEADER_BG        = "#1e293b"      # dark header / footer

root.config(bg=BG_DARK)

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
style.configure("TNotebook", background=BG_DARK, borderwidth=0)
style.configure("TNotebook.Tab", background="#e5e7eb", foreground=LIGHT_TEXT,
                padding=[18, 10], font=BTN_FONT, borderwidth=0)
style.map("TNotebook.Tab",
           background=[("selected", SURFACE)],
           foreground=[("selected", "#1f2937")])
style.configure("Custom.Horizontal.TProgressbar",
                background=PRIMARY_COLOR, troughcolor=SURFACE_LIGHT,
                borderwidth=0, thickness=8)

# ── HEADER ─────────────────────────────────────────────────────────────────────
header = tk.Frame(root, bg=HEADER_BG, height=72)
header.pack(fill="x")
header.pack_propagate(False)
tk.Frame(root, bg=PRIMARY_COLOR, height=3).pack(fill="x")  # accent stripe

hf = tk.Frame(header, bg=HEADER_BG)
hf.pack(fill="both", expand=True, padx=28)

title_f = tk.Frame(hf, bg=HEADER_BG)
title_f.pack(side="left", fill="y", pady=10)
tk.Label(title_f, text="*", font=("Segoe UI", 22), fg="#818cf8",
         bg=HEADER_BG).pack(side="left", padx=(0, 12))
ti = tk.Frame(title_f, bg=HEADER_BG)
ti.pack(side="left")
tk.Label(ti, text="RANSOMWARE DETECTION", font=("Segoe UI", 15, "bold"),
         fg="#f1f5f9", bg=HEADER_BG).pack(anchor="w")
tk.Label(ti, text="Advanced Behavioral Analysis Engine", font=("Segoe UI", 9),
         fg="#94a3b8", bg=HEADER_BG).pack(anchor="w")

si = tk.Frame(hf, bg=HEADER_BG)
si.pack(side="right", pady=10)
tk.Label(si, text="*", font=("Segoe UI", 8), fg=SUCCESS_COLOR,
         bg=HEADER_BG).pack(side="left", padx=(0, 5))
tk.Label(si, text="Model Active", font=SMALL_FONT, fg="#94a3b8",
         bg=HEADER_BG).pack(side="left")

# ── NOTEBOOK ───────────────────────────────────────────────────────────────────
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=14, pady=(14, 0))

# ── TAB 1: ANALYSIS ───────────────────────────────────────────────────────────
at = tk.Frame(notebook, bg=BG_DARK)
notebook.add(at, text="  Analysis  ")
ac = tk.Frame(at, bg=BG_DARK)
ac.pack(fill="both", expand=True, padx=8, pady=10)

# Left panel
lp = tk.Frame(ac, bg=SURFACE, highlightbackground=BORDER_COLOR, highlightthickness=1)
lp.pack(side="left", fill="both", expand=True, padx=(0, 6))

# File Selection
fs_hdr = tk.Frame(lp, bg=SURFACE)
fs_hdr.pack(fill="x", padx=18, pady=(18, 0))
tk.Label(fs_hdr, text="FILE SELECTION", font=("Segoe UI", 10, "bold"),
         fg=LIGHT_TEXT, bg=SURFACE).pack(anchor="w")
tk.Frame(fs_hdr, bg=BORDER_COLOR, height=1).pack(fill="x", pady=(6, 0))

fs = tk.Frame(lp, bg=SURFACE)
fs.pack(fill="x", padx=18, pady=(8, 4))
tk.Label(fs, textvariable=current_file, font=SMALL_FONT, fg=LIGHT_TEXT,
         bg=SURFACE, wraplength=260).pack(pady=6)
scan_btn = tk.Button(fs, text="SELECT FILE & ANALYZE", font=BTN_FONT,
                     bg=PRIMARY_COLOR, fg="white", padx=22, pady=11,
                     border=0, cursor="hand2", command=start_analysis,
                     activebackground=_lit(PRIMARY_COLOR), activeforeground="white")
_hover(scan_btn, _lit(PRIMARY_COLOR), PRIMARY_COLOR)
scan_btn.pack(pady=(4, 8), fill="x")

# Status
st_hdr = tk.Frame(lp, bg=SURFACE)
st_hdr.pack(fill="x", padx=18, pady=(12, 0))
tk.Label(st_hdr, text="STATUS", font=("Segoe UI", 10, "bold"),
         fg=LIGHT_TEXT, bg=SURFACE).pack(anchor="w")
tk.Frame(st_hdr, bg=BORDER_COLOR, height=1).pack(fill="x", pady=(6, 0))

ss = tk.Frame(lp, bg=SURFACE)
ss.pack(fill="x", padx=18, pady=(8, 4))
status_label = tk.Label(ss, textvariable=status_var, font=TEXT_FONT,
                         fg=LIGHT_TEXT, bg=SURFACE, wraplength=260, justify="left")
status_label.pack(anchor="w", pady=4)
ttk.Progressbar(ss, variable=progress_var, maximum=100, length=260,
                 mode="determinate", style="Custom.Horizontal.TProgressbar"
                 ).pack(fill="x", pady=6)
tk.Label(ss, textvariable=progress_text_var, font=SMALL_FONT,
         fg=LIGHT_TEXT, bg=SURFACE).pack(pady=2)

# Result
rs_hdr = tk.Frame(lp, bg=SURFACE)
rs_hdr.pack(fill="x", padx=18, pady=(12, 0))
tk.Label(rs_hdr, text="DETECTION RESULT", font=("Segoe UI", 10, "bold"),
         fg=LIGHT_TEXT, bg=SURFACE).pack(anchor="w")
tk.Frame(rs_hdr, bg=BORDER_COLOR, height=1).pack(fill="x", pady=(6, 0))

vs = tk.Frame(lp, bg=SURFACE)
vs.pack(fill="x", padx=18, pady=(8, 18))
result_label = tk.Label(vs, textvariable=result_var,
                         font=("Segoe UI", 16, "bold"), height=2,
                         bg=SURFACE_LIGHT, fg=LIGHT_TEXT, relief="flat")
result_label.pack(pady=8, fill="x")
tk.Label(vs, textvariable=confidence_var, font=TEXT_FONT,
         fg=LIGHT_TEXT, bg=SURFACE).pack(pady=2)
delete_btn = tk.Button(vs, text="DELETE PERMANENTLY", font=BTN_FONT,
                        bg=DANGER_COLOR, fg="white", state="disabled",
                        padx=16, pady=8, border=0, cursor="hand2",
                        activebackground="#dc2626")

# Right panel — Behavioral Metrics
rp = tk.Frame(ac, bg=SURFACE, highlightbackground=BORDER_COLOR, highlightthickness=1)
rp.pack(side="right", fill="both", expand=True, padx=(6, 0))

ms_hdr = tk.Frame(rp, bg=SURFACE)
ms_hdr.pack(fill="x", padx=18, pady=(18, 0))
tk.Label(ms_hdr, text="BEHAVIORAL METRICS", font=("Segoe UI", 10, "bold"),
         fg=LIGHT_TEXT, bg=SURFACE).pack(anchor="w")
tk.Frame(ms_hdr, bg=BORDER_COLOR, height=1).pack(fill="x", pady=(6, 0))

ms = tk.Frame(rp, bg=SURFACE)
ms.pack(fill="both", expand=True, padx=18, pady=(8, 18))
metrics_text = tk.Text(ms, font=MONO_FONT, height=18, width=36,
                        state="disabled", wrap="word", bg=INPUT_BG, fg="#1f2937",
                        relief="flat", padx=10, pady=10, insertbackground="#1f2937",
                        highlightbackground=BORDER_COLOR, highlightthickness=1)
metrics_text.pack(fill="both", expand=True)

# ── TAB 2: STATISTICS ─────────────────────────────────────────────────────────
st_tab = tk.Frame(notebook, bg=BG_DARK)
notebook.add(st_tab, text="  Statistics  ")
sc = tk.Frame(st_tab, bg=BG_DARK)
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
qt_tab = tk.Frame(notebook, bg=BG_DARK)
notebook.add(qt_tab, text="  Quarantine  ")
qc = tk.Frame(qt_tab, bg=BG_DARK)
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
footer = tk.Frame(root, bg=HEADER_BG)
footer.pack(fill="x", side="bottom")
tk.Frame(root, bg=PRIMARY_COLOR, height=2).pack(fill="x", side="bottom")  # accent stripe
fh = tk.Frame(footer, bg=HEADER_BG)
fh.pack(fill="x", padx=20, pady=(10, 0))
tk.Label(fh, text="SESSION HISTORY", font=("Segoe UI", 10, "bold"),
         fg="#94a3b8", bg=HEADER_BG).pack(anchor="w")
tk.Frame(fh, bg="#334155", height=1).pack(fill="x", pady=(6, 0))
history_text = tk.Text(footer, font=MONO_FONT, height=3, width=110,
                        state="disabled", wrap="word", bg="#0f172a", fg="#cbd5e1",
                        relief="flat", padx=10, pady=8, highlightbackground="#334155",
                        highlightthickness=1)
history_text.pack(fill="both", expand=True, padx=20, pady=(8, 12))

refresh_statistics()
show_quarantine()
root.mainloop()
