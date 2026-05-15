# Ransomware Detection Using Dynamic Analysis

A behavioral analysis tool that detects ransomware in real-time by running executables in a monitored VM environment, applying LSTM-based ML inference, and fusing 8 independent threat signals into a composite risk score.

---

## How It Works

1. **Sandbox execution** — target `.exe` is launched suspended inside the VM; a behavior logger attaches before the process resumes.
2. **Behavioral monitoring** — `behavior_logger.py` polls every 150–500ms (adaptive) for file writes, entropy spikes, CPU bursts, network connections, suspicious child processes, shadow copy deletions, and canary file violations.
3. **Early termination** — five tiered kill triggers stop the process immediately if definitive indicators fire (canary hit, rapid write + high entropy, etc.) before the 35-second window ends.
4. **LSTM inference** — `early_detection.py` evaluates the model at multiple partial windows (10, 20, 30, 50, 75, 100, 150 API calls) for sub-sequence detection, then scores the full log.
5. **Multi-signal fusion** — `compute_threat_score()` combines 8 weighted signals into a composite score [0.0–1.0]; definitive indicators override scoring to ≥ 0.95.
6. **Response** — processes above the detection threshold (0.25) are killed, quarantined, and logged to SQLite.

---

## Threat Signals (Weighted Fusion)

| Signal               | Weight | Description                                           |
| -------------------- | ------ | ----------------------------------------------------- |
| ML prediction        | 0.30   | LSTM score on full API-call sequence                  |
| Early detection      | 0.15   | Earliest window crossing ML threshold                 |
| Rapid file write     | 0.15   | Burst write ops (>=3 files changed rapidly)           |
| High entropy files   | 0.15   | Modified files with Shannon entropy > 7.5 (encrypted) |
| Canary violation     | 0.10   | Hidden honeypot files modified/deleted                |
| Shadow copy deletion | 0.05   | vssadmin/wmic shadow copy delete commands             |
| Write + CPU combo    | 0.05   | High write density combined with busy loops           |
| Suspicious children  | 0.05   | Child processes: cmd, powershell, vssadmin, etc.      |

Canary violations or shadow copy deletions force composite >= 0.95 regardless of other signals.

---

## Early Termination Tiers

| Tier | Trigger                                   | Latency         |
| ---- | ----------------------------------------- | --------------- |
| 1    | Canary violation                          | Immediate       |
| 2    | RapidFileWrite + HighEntropyFile          | Next poll cycle |
| 3    | >= 2 RapidFileWrite events                | Next poll cycle |
| 4    | >=3 write ops + >=2 busy loops within 10s | Next poll cycle |
| 5    | Streaming risk score >= 0.8               | Next poll cycle |

---

## Project Structure

```
ransomware_detection1/
├── app/
│   ├── main.py               # GUI (Tkinter), analysis orchestration
│   ├── behavior_logger.py    # Real-time process/filesystem monitor
│   ├── early_detection.py    # Multi-window LSTM inference
│   ├── preprocessing.py      # Tokenizer, event-to-sequence conversion
│   ├── process_supervisor.py # Sandbox launcher (CREATE_SUSPENDED + resume)
│   └── threat_database.py    # SQLite persistence (history, quarantine, stats)
├── model/
│   ├── trained_model.h5      # Trained LSTM model
│   └── tokenizer.pkl         # Fitted Keras tokenizer
├── data/
│   └── raw/
│       ├── benign/           # Benign API-call CSVs for training
│       └── ransomware/       # Ransomware API-call CSVs for training
├── logs/
│   └── api_logs.csv          # Live behavioral log (overwritten each scan)
├── quarantine/               # Quarantined executables
└── threat_database.db        # SQLite database
```

---

## Requirements

- Python 3.9+
- Windows (sandbox uses Win32 `CREATE_SUSPENDED` + `ResumeThread`)
- Run inside a VM — the sandbox provides process supervision, not OS-level isolation

```
pip install tensorflow pandas numpy scikit-learn psutil
```

---

## Usage

Train the model first (if `model/trained_model.h5` is missing):

```bash
python model/train_model.py
```

Launch the GUI:

```bash
python app/main.py
```

Click **SELECT FILE & ANALYZE**, choose an `.exe`. Results appear in the Analysis tab; history and quarantine are in their respective tabs.

Early detection CLI (score a log file directly):

```bash
python app/early_detection.py logs/api_logs.csv
```

---

## Threat Score Thresholds

| Score   | Level                           |
| ------- | ------------------------------- |
| >= 0.60 | CRITICAL                        |
| >= 0.40 | HIGH                            |
| >= 0.25 | MEDIUM / detected as ransomware |
| < 0.25  | LOW / benign                    |

Known legitimate installer names (Chrome, Firefox, VS Code, etc.) receive a 0.5x score discount when no definitive indicator fired — this prevents false positives from archivers and installers whose write patterns resemble ransomware.

---

## Database

SQLite at `threat_database.db`. Tables:

- `analysis_history` — per-scan verdicts, scores, metrics, actions
- `quarantine_log` — quarantined file records with paths and threat level
- `statistics` — aggregate counters (total scans, detection rate, avg confidence)
- `threat_rules` — configurable rule thresholds (default used by scoring engine)

Export history as CSV from the Statistics tab -> **Export CSV**.
