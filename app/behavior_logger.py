import csv
import hashlib
import math
import os
import subprocess
import tempfile
import threading
import time

import pandas as pd
import psutil

# Use absolute path so log location is consistent regardless of working directory
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(APP_DIR)
LOG_FILE = os.path.join(PARENT_DIR, "logs", "api_logs.csv")
WATCH_DIRS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    tempfile.gettempdir()
]

# Shared flag for early termination — set by logger, read by main.py
early_termination_triggered = False

# ── Streaming risk score — updated in real-time, read by main.py ──────────
streaming_risk_score = 0.0
streaming_risk_details = {}


def _file_entropy(filepath, block_size=4096):
    """
    Calculate Shannon entropy of a file's first block.
    Encrypted files approach 8.0 bits/byte; normal text/binaries are 4–6.
    This is a KEY ransomware indicator — encryption produces near-random bytes.
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read(block_size)
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    except (OSError, PermissionError):
        return 0.0


def _deploy_canary_files(watch_dirs):
    """
    Deploy invisible canary/honeypot files in watched directories.
    If a canary file is modified or deleted, it's a STRONG ransomware indicator
    since no legitimate application should touch these files.
    Returns (canaries, created_paths), where canaries maps
    {canary_path: original_hash} and created_paths only contains files this
    logger created during this run.
    """
    canaries = {}
    created_paths = []
    canary_names = ['.~sysconfig.dat', '.~thumbcache.db', '.~desktop.ini.bak']

    for watch_dir in watch_dirs:
        if not os.path.exists(watch_dir):
            continue
        for name in canary_names:
            canary_path = os.path.join(watch_dir, name)
            try:
                if not os.path.exists(canary_path):
                    # Create a small canary file with known content
                    content = f"CANARY_{hashlib.md5(watch_dir.encode(), usedforsecurity=False).hexdigest()}"
                    with open(canary_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    created_paths.append(canary_path)
                    # Set hidden attribute on Windows
                    if os.name == 'nt':
                        try:
                            import ctypes
                            ctypes.windll.kernel32.SetFileAttributesW(canary_path, 0x02)
                        except Exception:
                            pass
                # Store hash for integrity checking
                with open(canary_path, 'rb') as f:
                    canaries[canary_path] = hashlib.sha256(f.read()).hexdigest()
            except (OSError, PermissionError):
                pass
    return canaries, created_paths


def _cleanup_created_canaries(created_paths):
    """Remove only canary files created by this logger run."""
    for path in created_paths:
        try:
            if os.path.exists(path):
                os.chmod(path, 0o600)
                os.remove(path)
        except (OSError, PermissionError):
            pass


def _check_canary_integrity(canaries):
    """Check if any canary files were modified or deleted. Returns list of violations."""
    violations = []
    for path, original_hash in canaries.items():
        try:
            if not os.path.exists(path):
                violations.append(('DELETED', path))
            else:
                with open(path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != original_hash:
                    violations.append(('MODIFIED', path))
        except (OSError, PermissionError):
            violations.append(('INACCESSIBLE', path))
    return violations


def _check_shadow_copies():
    """
    Check if Volume Shadow Copies are being deleted (vssadmin).
    Ransomware almost always deletes shadow copies to prevent recovery.
    """
    if os.name != 'nt':
        return False
    try:
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                name = (proc.info.get('name') or '').lower()
                cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
                if ('vssadmin' in name and 'delete' in cmdline) or \
                   ('wmic' in name and 'shadowcopy' in cmdline) or \
                   ('bcdedit' in name and 'recoveryenabled' in cmdline):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return False


def _detect_suspicious_child_processes(pid):
    """
    Detect suspicious child process spawning patterns.
    Ransomware often spawns cmd.exe, powershell, or vssadmin as children.
    """
    suspicious = []
    suspicious_names = {'cmd.exe', 'powershell.exe', 'vssadmin.exe', 'wmic.exe',
                        'bcdedit.exe', 'cipher.exe', 'wbadmin.exe', 'icacls.exe',
                        'attrib.exe', 'net.exe', 'schtasks.exe'}
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child_name = child.name().lower()
                if child_name in suspicious_names:
                    suspicious.append(child_name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return suspicious


def _kill_process_now(pid):
    """Kill process tree in a daemon thread so callers never block."""
    def _do_kill():
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True, timeout=5, check=False
            )
            print(f"[!] taskkill used on PID: {pid}")
        except Exception:
            pass
        try:
            proc = psutil.Process(pid)
            for p in [proc] + proc.children(recursive=True):
                try:
                    p.kill()
                    print(f"[!] Killed PID: {p.pid}")
                except Exception:
                    pass
        except Exception:
            pass
        print(f"[+] Process tree neutralised for PID: {pid}")

    t = threading.Thread(target=_do_kill, daemon=True)
    t.start()
    t.join(timeout=8)


def log_behavior(pid=None, duration=35):
    global early_termination_triggered, streaming_risk_score, streaming_risk_details
    early_termination_triggered = False
    streaming_risk_score = 0.0
    streaming_risk_details = {}

    log_dir = os.path.join(PARENT_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)

    def snapshot_files(directory):
        """Return path -> (mtime, size, entropy_sample) for files in a watched directory."""
        snapshot = {}
        try:
            for name in os.listdir(directory):
                path = os.path.join(directory, name)
                if os.path.isfile(path):
                    try:
                        stat = os.stat(path)
                        snapshot[path] = (stat.st_mtime, stat.st_size)
                    except (OSError, PermissionError):
                        pass
        except (OSError, PermissionError):
            pass
        return snapshot

    # Track created and modified files in common user directories.
    known_files = {}
    for watch_dir in WATCH_DIRS:
        if os.path.exists(watch_dir):
            known_files[watch_dir] = snapshot_files(watch_dir)

    # Deploy canary honeypot files
    canaries, created_canaries = _deploy_canary_files(WATCH_DIRS)

    # Clear and initialize the log file
    with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pid", "event"])
        f.flush()
        os.fsync(f.fileno())

    # Helper function to safely append to CSV
    def append_log_entry(timestamp, process_id, event_type):
        try:
            with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, process_id, event_type])
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            print(f"[!] Error writing log: {e}")

    start_time = time.time()
    rapid_write_counter   = 0
    rapid_file_write_events = 0
    total_write_ops       = 0
    total_busy_loops      = 0
    total_network_ops     = 0
    high_entropy_files    = 0
    canary_violations     = 0
    suspicious_children   = set()
    poll_interval         = 0.5   # Adaptive: speeds up when suspicious

    # ── Cumulative risk scoring weights ───────────────────────────────────
    RISK_WEIGHTS = {
        'rapid_write':       0.25,
        'high_entropy_file': 0.30,
        'canary_violation':  0.50,   # Near-definitive ransomware indicator
        'shadow_copy_delete':0.50,   # Near-definitive ransomware indicator
        'busy_loop':         0.05,
        'network_connect':   0.10,
        'suspicious_child':  0.20,
        'write_burst':       0.15,
    }

    try:
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            iteration_risk = 0.0

            # If specific PID provided, monitor it
            if pid is not None:
                try:
                    process = psutil.Process(pid)

                    if not process.is_running():
                        append_log_entry(time.time(), pid, "TerminateProcess")
                        break

                    # CPU activity
                    cpu = process.cpu_percent(interval=0.1)
                    if cpu > 70:
                        append_log_entry(time.time(), pid, "BusyLoop")
                        total_busy_loops += 1
                        iteration_risk += RISK_WEIGHTS['busy_loop']

                    # Memory spike
                    mem = process.memory_info().rss
                    if mem > 80 * 1024 * 1024:
                        append_log_entry(time.time(), pid, "VirtualAlloc")

                    # File enumeration detection
                    try:
                        open_files = process.open_files()
                        if len(open_files) > 5:
                            append_log_entry(time.time(), pid, "FindFirstFile")
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    # Network detection
                    try:
                        connections = process.connections()
                        for conn in connections:
                            if conn.status == 'ESTABLISHED':
                                append_log_entry(time.time(), pid, "NetworkConnect")
                                total_network_ops += 1
                                iteration_risk += RISK_WEIGHTS['network_connect']
                                break
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    # Suspicious child process detection
                    new_suspicious = _detect_suspicious_child_processes(pid)
                    for child_name in new_suspicious:
                        if child_name not in suspicious_children:
                            suspicious_children.add(child_name)
                            append_log_entry(time.time(), pid, "SuspiciousChild")
                            iteration_risk += RISK_WEIGHTS['suspicious_child']
                            print(f"[!] Suspicious child process: {child_name}")

                except psutil.NoSuchProcess:
                    append_log_entry(time.time(), pid, "TerminateProcess")
                    break

            # ── Shadow copy deletion check ────────────────────────────────
            if _check_shadow_copies():
                append_log_entry(time.time(), pid or 0, "ShadowCopyDelete")
                iteration_risk += RISK_WEIGHTS['shadow_copy_delete']
                print("[!] CRITICAL: Shadow copy deletion detected!")

            # ── Canary file integrity check ───────────────────────────────
            violations = _check_canary_integrity(canaries)
            for vtype, vpath in violations:
                if vpath in canaries:
                    del canaries[vpath]   # Don't re-alert
                    canary_violations += 1
                    append_log_entry(time.time(), pid or 0, "CanaryViolation")
                    iteration_risk += RISK_WEIGHTS['canary_violation']
                    print(f"[!] CANARY {vtype}: {vpath}")

            # Multi-directory file monitoring (works regardless of PID)
            for watch_dir, known in known_files.items():
                if not os.path.exists(watch_dir):
                    continue

                try:
                    current_files = snapshot_files(watch_dir)
                    new_files = set(current_files) - set(known)
                    modified_files = {
                        path for path in set(current_files) & set(known)
                        if current_files[path] != known[path]
                    }
                    changed_count = len(new_files) + len(modified_files)

                    if changed_count > 0:
                        append_log_entry(time.time(), pid or 0, "WriteFile")
                        rapid_write_counter += changed_count
                        total_write_ops += changed_count

                    # ── File entropy analysis on changed files ─────────
                    for changed_path in (new_files | modified_files):
                        try:
                            entropy = _file_entropy(changed_path)
                            if entropy > 7.5:
                                # Very high entropy = likely encrypted
                                append_log_entry(time.time(), pid or 0, "HighEntropyFile")
                                high_entropy_files += 1
                                iteration_risk += RISK_WEIGHTS['high_entropy_file']
                                print(f"[!] High entropy ({entropy:.2f}): {os.path.basename(changed_path)}")
                        except Exception:
                            pass

                    known_files[watch_dir] = current_files
                except (OSError, PermissionError):
                    pass

            # Rapid write detection (KEY RANSOMWARE INDICATOR)
            if rapid_write_counter >= 10:
                append_log_entry(time.time(), pid or 0, "RapidFileWrite")
                iteration_risk += RISK_WEIGHTS['rapid_write']
                rapid_write_counter = 0
                rapid_file_write_events += 1

            # ── UPDATE STREAMING RISK SCORE ───────────────────────────────
            # Exponential moving average: recent signals weighted more heavily
            alpha = 0.3   # Smoothing factor
            streaming_risk_score = min(1.0, streaming_risk_score * (1 - alpha) + iteration_risk * alpha)
            streaming_risk_details = {
                'total_write_ops': total_write_ops,
                'total_busy_loops': total_busy_loops,
                'total_network_ops': total_network_ops,
                'high_entropy_files': high_entropy_files,
                'canary_violations': canary_violations,
                'suspicious_children': list(suspicious_children),
                'elapsed': elapsed,
                'risk_score': streaming_risk_score,
            }

            # ── ADAPTIVE POLL RATE ────────────────────────────────────────
            # Speed up monitoring when we detect suspicious activity
            if streaming_risk_score > 0.3:
                poll_interval = 0.15   # 150ms — aggressive monitoring
            elif streaming_risk_score > 0.1:
                poll_interval = 0.25   # 250ms — heightened awareness
            else:
                poll_interval = 0.5    # 500ms — normal monitoring

            # ── EARLY TERMINATION TRIGGERS ─────────────────────────────────
            # TIER 1: Canary violation → IMMEDIATE KILL
            if canary_violations >= 1:
                print(f"[!] TIER-1 TERMINATION: Canary violation at {elapsed:.1f}s — killing process!")
                if pid is not None:
                    _kill_process_now(pid)
                append_log_entry(time.time(), pid or 0, "EarlyTermination")
                early_termination_triggered = True
                break

            # TIER 2: RapidFileWrite + high entropy → KILL
            if rapid_file_write_events >= 1 and high_entropy_files >= 1:
                print(f"[!] TIER-2 TERMINATION: RapidWrite+HighEntropy at {elapsed:.1f}s — killing process!")
                if pid is not None:
                    _kill_process_now(pid)
                append_log_entry(time.time(), pid or 0, "EarlyTermination")
                early_termination_triggered = True
                break

            # TIER 3: RapidFileWrite alone (fallback)
            if rapid_file_write_events >= 2:
                print(f"[!] TIER-3 TERMINATION: Multiple RapidFileWrite at {elapsed:.1f}s — killing process!")
                if pid is not None:
                    _kill_process_now(pid)
                append_log_entry(time.time(), pid or 0, "EarlyTermination")
                early_termination_triggered = True
                break

            # TIER 4: High write + busy loops within first 10 seconds
            if elapsed <= 10 and total_write_ops >= 3 and total_busy_loops >= 2:
                print(f"[!] TIER-4 TERMINATION: High write+CPU at {elapsed:.1f}s — killing process!")
                if pid is not None:
                    _kill_process_now(pid)
                append_log_entry(time.time(), pid or 0, "EarlyTermination")
                early_termination_triggered = True
                break

            # TIER 5: Streaming risk score exceeds critical threshold
            if streaming_risk_score >= 0.8:
                print(f"[!] TIER-5 TERMINATION: Risk score {streaming_risk_score:.3f} at {elapsed:.1f}s — killing process!")
                if pid is not None:
                    _kill_process_now(pid)
                append_log_entry(time.time(), pid or 0, "EarlyTermination")
                early_termination_triggered = True
                break

            time.sleep(poll_interval)

    except Exception as e:
        print(f"[!] Logging error: {e}")
        pass
    finally:
        _cleanup_created_canaries(created_canaries)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        pid = int(sys.argv[1])
        log_behavior(pid)
