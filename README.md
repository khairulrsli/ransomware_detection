# Ransomware Detection Using Behavioural Event Analysis

**Student:** Khairul Ikhwan Bin Rusli (52215224240)  
**Program:** Bachelor of Information Technology (Hons) - Computer System Security  
**Institution:** Universiti Kuala Lumpur MIIT  
**Supervisor:** Madam Mardiana Binti Mahari

---

## Project Overview

This project is a ransomware detection prototype that uses dynamic behavioural monitoring and LSTM sequence classification. Suspicious Windows executables are intended to be tested inside an isolated Windows virtual machine. The VM provides the containment layer, while the Python application performs process-level execution control, behavioural logging, machine-learning prediction, scan history recording, and quarantine handling.

The GUI contains three implemented tabs: **Analysis**, **Statistics**, and **Quarantine**.

Important wording: this project observes behavioural events and process activity. It is not a full Windows API-hooking system and it is not a standalone hypervisor sandbox.

---

## Core Features

| Feature | Description |
|---|---|
| VM-based malware testing | Intended to run inside a dedicated Windows VM with snapshots enabled. |
| PE file validation | Checks executable structure before analysis. |
| Behavioural monitoring | Observes process, file-system, CPU, memory, child-process, canary-file, and network indicators. |
| Early detection mechanism | Can terminate suspicious runs based on rapid writes, high entropy files, canary violations, shadow-copy activity, and high risk score. |
| LSTM prediction | Classifies event sequences using a trained TensorFlow/Keras model. |
| Multi-signal scoring | Combines ML score, early-window prediction, and runtime behavioural indicators. |
| Quarantine system | Moves detected threats into `quarantine/` and records them in SQLite. |
| Statistics dashboard | Shows scan history, detection counts, and recent analysis records. |
| Unit tests | Includes focused tests for preprocessing statistics and database behaviour. |

---

## Dataset

The included raw sequence dataset contains **2,450 CSV files**:

- **1,172 benign sequence samples**
- **1,278 ransomware/malicious sequence samples**

The training pipeline uses CSV files from `data/raw/benign/` and `data/raw/ransomware/`.

Current regenerated model results from `model/evaluation_results.txt`:

| Metric | Value |
|---|---:|
| Accuracy | 92.65% |
| Precision | 95.45% |
| Recall | 90.23% |
| F1-score | 92.77% |

Confusion matrix:

```text
Actual Benign:    223 predicted benign, 11 predicted malicious
Actual Malicious: 25 predicted benign, 231 predicted malicious
```

Early-window results are weaker before 100 calls. The strongest early result in the current report is at the first 100 calls: **91.56% accuracy**, **95.71% precision**, **88.14% recall**, and **91.77% F1-score**.

---

## System Workflow

```text
User selects suspicious .exe
        |
        v
PE file validation
        |
        v
Installer-name context check
(does not skip analysis)
        |
        v
Execution inside isolated Windows VM
        |
        v
Process-level behavioural monitoring
        |
        v
Event log generation
        |
        v
LSTM sequence preprocessing and prediction
        |
        v
Multi-signal scoring and early-detection rules
        |
        v
Terminate process and quarantine detected threat when needed
        |
        v
Save scan result to SQLite database
```

---

## Quick Start

1. Start a clean Windows VM snapshot.
2. Keep the VM isolated from the host where possible.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Train or retrain the model when needed:

```bash
python model/train_model.py
```

5. Run the application:

```bash
python app/main.py
```

6. Run tests:

```bash
python -m unittest discover -s tests
```

---

## GUI Tabs

1. **Analysis**
   - Select one executable file.
   - Run behavioural analysis inside the VM.
   - View behavioural metrics, ML score, threat score, and final verdict.

2. **Statistics**
   - View scan count, ransomware count, benign count, average confidence, and recent history.
   - Export analysis history as CSV.
   - Clear history and reset aggregate statistics.

3. **Quarantine**
   - View quarantined files.
   - Permanently delete quarantined files.

---

## Project Structure

```text
app/
  main.py              GUI and main workflow
  sandbox_runner.py    Process launch and timeout control
  behavior_logger.py   Runtime behaviour monitoring and early triggers
  preprocessing.py     Tokenisation, padding, and event statistics
  early_detection.py   Partial-sequence LSTM checks
  threat_database.py   SQLite scan history and quarantine records

model/
  train_model.py       Training and evaluation pipeline
  lstm_model.py        Model architecture
  trained_model.h5     Saved Keras model
  tokenizer.pkl        Saved tokenizer
  evaluation_results.txt
  training_epochs.txt

data/raw/
  benign/              Benign event-sequence CSV samples
  ransomware/          Malicious event-sequence CSV samples

logs/
  api_logs.csv         Runtime behavioural event log

quarantine/
  quarantined files

tests/
  test_preprocessing.py
  test_threat_database.py
```

---

## Important Safety Notes

The Python application is not a full sandbox by itself. The **virtual machine** provides isolation. Always test malware only inside a dedicated VM with snapshots enabled.

Recommended VM precautions:

- Use a clean snapshot before every malware test.
- Disable shared folders during malware execution.
- Use host-only networking or disconnected networking.
- Revert the snapshot after each malware test.
- Do not test real malware on your main machine.

---

## Current Limitations

- The app depends on the VM for real containment.
- Behaviour logging uses process and filesystem observation, not full Windows API hooking.
- File-change monitoring can be affected by unrelated activity inside watched directories.
- Early detection before 100 calls is currently much weaker than full-log classification.
- The current model is evaluated on the included dataset; broader validation with more real-world ransomware families is recommended.
- Results should be presented as prototype findings, not production antivirus performance.
