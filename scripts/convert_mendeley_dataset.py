"""
Convert Mendeley Ransomware/Benignware System Calls dataset to project format.

Sources:
  - Ransomwares Syscall CSV/Part1-8.zip  : raw ransomware API sequences (tab-sep)
  - dataset - System calls.csv           : feature matrix (semicolon-sep, all 540 samples)
  - dataset - output.csv                 : labels ("Ransomware" / "Benignware")

Output (timestamp,pid,event):
  - data/raw/ransomware/ransomware_real_NNN.csv
  - data/raw/benign/benign_real_NNN.csv

Backup: old data/raw copied to data/raw_backup before any changes.
"""

import os
import re
import csv
import zipfile
import shutil
import random

# ── Paths ──────────────────────────────────────────────────────────────────
DOWNLOADS = os.path.join(os.path.expanduser("~"), "Downloads")
MENDELEY  = os.path.join(DOWNLOADS, "RansomwareBenignware System Calls")
EXTRACT   = os.path.join(DOWNLOADS, "mendeley_extract")

PROJECT   = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW_DIR   = os.path.join(PROJECT, "data", "raw")
BACKUP    = os.path.join(PROJECT, "data", "raw_backup")
BENIGN_OUT     = os.path.join(RAW_DIR, "benign")
RANSOMWARE_OUT = os.path.join(RAW_DIR, "ransomware")

MAX_EVENTS = 500   # events per sample (caps huge files, still above MAX_LEN=200)
MIN_EVENTS = 10    # skip near-empty samples


def extract_api_name(raw: str) -> str:
    """'CreateFileW ( "C:\\path", ... )' → 'CreateFileW'"""
    raw = raw.strip()
    m = re.match(r'^([\w:~<>]+)\s*\(', raw)
    if m:
        return m.group(1)
    return raw.split("(")[0].strip()


def backup_old_data():
    if os.path.exists(BACKUP):
        shutil.rmtree(BACKUP)
    shutil.copytree(RAW_DIR, BACKUP)
    print(f"[+] Backed up old data -> {BACKUP}")


def clear_old_csvs():
    for d in [BENIGN_OUT, RANSOMWARE_OUT]:
        removed = 0
        for f in os.listdir(d):
            if f.endswith(".csv"):
                os.remove(os.path.join(d, f))
                removed += 1
        print(f"[+] Cleared {removed} CSV files from {os.path.basename(d)}/")


def write_sample(out_path: str, events: list, pid: int):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pid", "event"])
        for ts, evt in enumerate(events):
            writer.writerow([ts, pid, evt])


def process_ransomware_parts() -> int:
    part_dir = os.path.join(MENDELEY, "Ransomwares Syscall CSV")
    zips = sorted(f for f in os.listdir(part_dir) if f.endswith(".zip"))
    count = 0

    for zip_name in zips:
        zip_path = os.path.join(part_dir, zip_name)
        tag = zip_name.replace(".zip", "").replace(" ", "")
        dst = os.path.join(EXTRACT, tag)

        print(f"[*] Extracting {zip_name} …")
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(dst)

        for root, _, files in os.walk(dst):
            for fname in sorted(files):
                if not fname.endswith(".csv"):
                    continue
                fpath = os.path.join(root, fname)
                events = []

                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        reader = csv.reader(f, delimiter="\t")
                        for i, row in enumerate(reader):
                            if i == 0:
                                continue  # skip "API" header
                            if not row or not row[0].strip():
                                continue
                            name = extract_api_name(row[0])
                            if name:
                                events.append(name)
                            if len(events) >= MAX_EVENTS:
                                break
                except Exception as e:
                    print(f"  [!] {fname}: {e}")
                    continue

                if len(events) < MIN_EVENTS:
                    continue

                out = os.path.join(RANSOMWARE_OUT, f"ransomware_real_{count:04d}.csv")
                write_sample(out, events, pid=2000 + count)
                count += 1

        print(f"  [+] Running total ransomware samples: {count}")

    print(f"[+] Ransomware done: {count} samples")
    return count


def process_benign_from_matrix() -> int:
    matrix_path = os.path.join(EXTRACT, "syscalls", "dataset - System calls.csv")
    labels_path = os.path.join(MENDELEY, "dataset - output.csv")

    # Read labels (skip header "y")
    with open(labels_path, "r", encoding="utf-8") as f:
        all_labels = [ln.strip() for ln in f.readlines()]
    labels = all_labels[1:]  # drop "y" header

    # Read feature matrix header
    with open(matrix_path, "r", encoding="utf-8", errors="replace") as f:
        header_line = f.readline()
    api_names = [n.strip() for n in header_line.split(";")]

    count = 0
    with open(matrix_path, "r", encoding="utf-8", errors="replace") as f:
        f.readline()  # skip header
        for row_idx, line in enumerate(f):
            if row_idx >= len(labels):
                break
            if labels[row_idx].strip().lower() != "benignware":
                continue

            parts = line.strip().split(";")
            events = []
            for api_idx, val in enumerate(parts):
                if api_idx >= len(api_names):
                    break
                try:
                    n = int(val.strip())
                except ValueError:
                    continue
                if n > 0:
                    api = api_names[api_idx].strip()
                    if api:
                        # Cap per-API repetition to avoid bloat from very common calls
                        events.extend([api] * min(n, 20))
                if len(events) >= MAX_EVENTS:
                    break

            events = events[:MAX_EVENTS]
            if len(events) < MIN_EVENTS:
                continue

            random.shuffle(events)  # break grouped-block ordering from feature matrix

            out = os.path.join(BENIGN_OUT, f"benign_real_{count:04d}.csv")
            write_sample(out, events, pid=1000 + count)
            count += 1

    print(f"[+] Benign done: {count} samples")
    return count


def main():
    print("=" * 50)
    print("  Mendeley Dataset Converter")
    print("=" * 50)

    for d in [BENIGN_OUT, RANSOMWARE_OUT]:
        os.makedirs(d, exist_ok=True)

    print("\n[1] Backing up old data …")
    backup_old_data()

    print("\n[2] Clearing old CSVs …")
    clear_old_csvs()

    print("\n[3] Processing ransomware sequences …")
    r_count = process_ransomware_parts()

    print("\n[4] Processing benign from feature matrix …")
    b_count = process_benign_from_matrix()

    print("\n" + "=" * 50)
    print(f"  Ransomware samples : {r_count}")
    print(f"  Benign samples     : {b_count}")
    print(f"  Old data backup    : {BACKUP}")
    print("=" * 50)


if __name__ == "__main__":
    main()
