import subprocess
import time
import threading
import os
import shutil
import psutil
import behavior_logger


def run_in_sandbox(exe_path):
    """
    Launch the target executable inside the VM analysis runner.

    Runner controls applied:
      1. CREATE_SUSPENDED — process starts frozen, giving the logger time to attach
      2. CREATE_NO_WINDOW — suppresses cmd/console popups
      3. SW_HIDE via STARTUPINFO — hides any GUI windows the process tries to show
      4. Below-normal priority — limits CPU impact on the VM
      5. Aggressive kill loop — checks every 250ms for early termination

    This is process supervision, not a containment boundary. The VM provides
    isolation.
    """
    print("[*] Executing in VM analysis environment:", exe_path)

    if not os.path.exists(exe_path):
        print(f"[!] File not found: {exe_path}")
        raise FileNotFoundError(f"Executable not found: {exe_path}")

    process = None
    try:
        if os.name == "nt":
            # ── Windows: launch hidden and suspended ─────────────────────
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags = subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE — no visible window

            creation_flags = (
                subprocess.CREATE_NEW_PROCESS_GROUP |
                subprocess.CREATE_NO_WINDOW |        # No console window
                0x00000004                           # CREATE_SUSPENDED
            )

            process = subprocess.Popen(
                [exe_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                creationflags=creation_flags,
            )
            print(f"[+] Process started SUSPENDED with PID: {process.pid}")

            # Set below-normal priority to limit CPU impact
            try:
                p = psutil.Process(process.pid)
                p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            except Exception:
                pass

            # Start the behavior logger BEFORE resuming the process
            # This ensures monitoring is active from the very first instruction
            log_thread = threading.Thread(
                target=lambda: behavior_logger.log_behavior(process.pid, duration=35),
                daemon=True
            )
            log_thread.start()

            # Give logger a moment to initialize, then resume the process
            time.sleep(0.3)

            # Resume the suspended process
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                # Open the main thread and resume it
                THREAD_SUSPEND_RESUME = 0x0002
                # Get the main thread ID
                pid = process.pid
                p = psutil.Process(pid)
                threads = p.threads()
                for thread in threads:
                    handle = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, thread.id)
                    if handle:
                        kernel32.ResumeThread(handle)
                        kernel32.CloseHandle(handle)
                print(f"[+] Process RESUMED — monitoring active")
            except Exception as e:
                print(f"[!] Could not resume process, killing it: {e}")
                try:
                    process.kill()
                except Exception:
                    pass
                # Fallback: restart without suspension
                process = subprocess.Popen(
                    [exe_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
                )
                print(f"[+] Fallback: process started with PID: {process.pid}")

                log_thread = threading.Thread(
                    target=lambda: behavior_logger.log_behavior(process.pid, duration=35),
                    daemon=True
                )
                log_thread.start()

        else:
            # ── Non-Windows fallback ─────────────────────────────────────
            process = subprocess.Popen(
                [exe_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            print(f"[+] Process started with PID: {process.pid}")

            log_thread = threading.Thread(
                target=lambda: behavior_logger.log_behavior(process.pid, duration=35),
                daemon=True
            )
            log_thread.start()

        # ── Main monitoring loop ─────────────────────────────────────────
        # Check every 250ms (was 500ms) for faster response to threats
        start_time = time.time()
        while True:
            if behavior_logger.early_termination_triggered:
                print("[!] Early termination flag detected by sandbox runner")
                _force_kill(process)
                break

            if process.poll() is not None:
                print("[+] Process completed")
                break

            if time.time() - start_time >= 35:
                print("[!] Process timeout, terminating...")
                _force_kill(process)
                break

            time.sleep(0.25)

        log_thread.join(timeout=5)
        return process.pid

    except Exception as e:
        print(f"[!] Error executing process: {e}")
        if process is not None:
            _force_kill(process)
        raise


def _force_kill(process):
    """Kill a process and all its children aggressively."""
    pid = process.pid
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)

        # Suspend everything first to prevent spawning
        for p in [parent] + children:
            try:
                p.suspend()
            except Exception:
                pass

        # Kill everything
        for p in [parent] + children:
            try:
                p.kill()
            except Exception:
                pass
    except Exception:
        pass

    # Fallback: taskkill /F /T
    try:
        taskkill = shutil.which("taskkill") or r"C:\Windows\System32\taskkill.exe"
        subprocess.run(
            [taskkill, "/F", "/T", "/PID", str(pid)],
            capture_output=True, timeout=3
        )
    except Exception:
        pass

    # Final: make sure subprocess object is cleaned up
    try:
        process.kill()
        process.wait(timeout=3)
    except Exception:
        pass
