"""
Generate synthetic behavioral event CSVs in behavior_logger vocabulary.

Problem: tokenizer trained on Mendeley raw API calls. Behavior_logger emits
synthetic events (RapidFileWrite, HighEntropyFile, CanaryViolation, BusyLoop,
FindFirstFile, ShadowCopyDelete) that are ALL OOV — LSTM can't see them.

Fix: Add benign-installer and ransomware-behavioral samples so tokenizer
learns these tokens and LSTM learns to distinguish:
  - Benign installer:  WriteFile + RapidFileWrite + BusyLoop, NO HighEntropyFile
  - Ransomware:        WriteFile + RapidFileWrite + HighEntropyFile + CanaryViolation/ShadowCopyDelete

Output:
  data/raw/benign/benign_installer_NNNN.csv    (N_INSTALLER samples)
  data/raw/ransomware/ransomware_behav_NNNN.csv (N_RANSOM samples)
"""

import csv
import os
import random

random.seed(42)

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
BENIGN_DIR  = os.path.join(PROJECT_DIR, "data", "raw", "benign")
RANSOM_DIR  = os.path.join(PROJECT_DIR, "data", "raw", "ransomware")

N_INSTALLER = 120   # benign installer samples
N_RANSOM    = 120   # ransomware behavioral samples

# ── Common Mendeley-vocab filler (already in tokenizer vocab) ─────────────
COMMON_API = [
    "CloseHandle", "CreateFileW", "VirtualAlloc", "VirtualFree",
    "ReadFile", "GetFileSize", "SetFilePointer", "FlushFileBuffers",
    "RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey",
    "GetModuleFileNameW", "LoadLibraryW", "FreeLibrary",
    "OpenProcess", "GetCurrentProcess", "TerminateProcess",
    "CreateThread", "WaitForSingleObject", "ReleaseMutex",
    "FindFirstFileW", "FindNextFileW", "FindClose",
    "GetTempPathW", "GetSystemDirectoryW", "GetWindowsDirectoryW",
    "SHGetFolderPathW", "CoInitialize", "CoUninitialize",
    "_wcsicmp", "_stricmp", "wcslen", "strlen", "memcpy", "memset",
]

# ── Behavior_logger synthetic events ──────────────────────────────────────
BL_WRITE          = "WriteFile"
BL_RAPID          = "RapidFileWrite"
BL_ENTROPY        = "HighEntropyFile"
BL_CANARY         = "CanaryViolation"
BL_SHADOW         = "ShadowCopyDelete"
BL_BUSY           = "BusyLoop"
BL_FIND           = "FindFirstFile"
BL_NET            = "NetworkConnect"
BL_VALLOC         = "VirtualAlloc"
BL_EARLY_TERM     = "EarlyTermination"


def _filler(n):
    return [random.choice(COMMON_API) for _ in range(n)]


def generate_installer_sample(length=None):
    """
    Realistic installer behavioral sequence.
    Phase 1 (recon):   FindFirstFile, CreateFileW, CloseHandle
    Phase 2 (extract): WriteFile bursts, RapidFileWrite, BusyLoop, VirtualAlloc
    Phase 3 (finish):  CloseHandle, registry calls, filler
    No HighEntropyFile, CanaryViolation, ShadowCopyDelete.
    """
    if length is None:
        length = random.randint(200, 450)

    events = []

    # Phase 1: recon (~25% of length)
    p1_len = int(length * 0.25)
    for _ in range(p1_len):
        events.append(random.choice([
            BL_FIND, "CreateFileW", "CloseHandle", "FindFirstFileW",
            "FindNextFileW", "GetFileSize", "ReadFile", "_wcsicmp",
        ]))

    # Phase 2: extraction (~55% of length)
    p2_len = int(length * 0.55)
    rapid_quota = random.randint(2, 6)   # how many RapidFileWrite events
    rapid_interval = max(1, p2_len // (rapid_quota + 1))
    rapid_idx = set(range(rapid_interval, p2_len, rapid_interval))

    for i in range(p2_len):
        if i in rapid_idx:
            events.append(BL_RAPID)
        else:
            events.append(random.choice([
                BL_WRITE, BL_WRITE, BL_WRITE,   # weighted heavy
                BL_BUSY, BL_VALLOC,
                "CreateFileW", "CloseHandle", "SetFilePointer",
                "FlushFileBuffers", "GetFileSize",
            ]))

    # Phase 3: finish (~20% of length)
    events.extend(_filler(length - len(events)))

    random.shuffle(events[int(length * 0.25): int(length * 0.80)])  # shuffle mid only
    return events


def generate_ransomware_sample(length=None):
    """
    Ransomware behavioral sequence using behavior_logger vocabulary.
    Phase 1 (recon):   FindFirstFile, OpenFile
    Phase 2 (encrypt): WriteFile + HighEntropyFile interleaved, RapidFileWrite
    Phase 3 (cover):   ShadowCopyDelete or CanaryViolation, EarlyTermination
    """
    if length is None:
        length = random.randint(200, 450)

    events = []

    # Phase 1: recon (~30%)
    p1_len = int(length * 0.30)
    for _ in range(p1_len):
        events.append(random.choice([
            BL_FIND, "CreateFileW", "CloseHandle",
            "FindFirstFileW", "FindNextFileW", "OpenProcess",
            "_wcsicmp", "ReadFile", "GetFileSize",
        ]))

    # Phase 2: encrypt (~55%)
    p2_len = int(length * 0.55)
    rapid_quota = random.randint(2, 5)
    entropy_ratio = random.uniform(0.20, 0.40)   # fraction that trigger entropy
    rapid_positions = sorted(random.sample(
        range(p2_len), min(rapid_quota, p2_len)
    ))
    rapid_set = set(rapid_positions)

    for i in range(p2_len):
        if i in rapid_set:
            events.append(BL_RAPID)
        elif random.random() < entropy_ratio:
            events.append(BL_ENTROPY)
        else:
            events.append(random.choice([
                BL_WRITE, BL_WRITE, BL_WRITE,
                BL_BUSY, BL_VALLOC, "CloseHandle",
            ]))

    # Phase 3: cover tracks (~15%)
    # Always at least one definitive indicator
    definitive = random.choice([
        [BL_CANARY],
        [BL_SHADOW],
        [BL_CANARY, BL_SHADOW],
    ])
    events.extend(definitive)

    # Optional network exfil
    if random.random() < 0.4:
        events.extend([BL_NET] * random.randint(1, 3))

    events.append(BL_EARLY_TERM)

    # Pad / trim to length
    while len(events) < length:
        events.append(random.choice([BL_WRITE, BL_ENTROPY, "CloseHandle"]))
    events = events[:length]

    return events


def write_csv(path, events):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pid", "event"])
        pid = random.randint(1000, 9999)
        for ts, ev in enumerate(events):
            writer.writerow([ts, pid, ev])


def main():
    # Find next available index for benign installer files
    existing_b = [
        f for f in os.listdir(BENIGN_DIR)
        if f.startswith("benign_installer_")
    ]
    b_start = len(existing_b)

    # Find next available index for ransomware behavioral files
    existing_r = [
        f for f in os.listdir(RANSOM_DIR)
        if f.startswith("ransomware_behav_")
    ]
    r_start = len(existing_r)

    print(f"[*] Generating {N_INSTALLER} benign installer samples -> {BENIGN_DIR}")
    for i in range(N_INSTALLER):
        events = generate_installer_sample()
        fname  = f"benign_installer_{b_start + i:04d}.csv"
        write_csv(os.path.join(BENIGN_DIR, fname), events)

    print(f"[*] Generating {N_RANSOM} ransomware behavioral samples -> {RANSOM_DIR}")
    for i in range(N_RANSOM):
        events = generate_ransomware_sample()
        fname  = f"ransomware_behav_{r_start + i:04d}.csv"
        write_csv(os.path.join(RANSOM_DIR, fname), events)

    print(f"[+] Done. {N_INSTALLER} benign + {N_RANSOM} ransomware samples generated.")
    print(f"    Benign total : {len(os.listdir(BENIGN_DIR))}")
    print(f"    Ransomware total: {len(os.listdir(RANSOM_DIR))}")


if __name__ == "__main__":
    main()
