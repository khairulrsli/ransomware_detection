"""Calibrate the composite-score detection threshold.

This script sweeps APP_DETECTION_THRESHOLD across a range of values and
reports precision / recall / F1 on the real-only test subset. The output
is used in the thesis to justify the chosen operating point instead of
leaving the threshold as an unexplained constant.

Usage:
    python scripts/calibrate_threshold.py

Reads:
    model/trained_model.h5
    model/tokenizer.pkl
    data/raw/{benign,ransomware}/*.csv

Writes:
    reports/threshold_calibration.txt
    reports/threshold_calibration.csv
"""

import os
import sys
import csv
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# Make the app/ modules importable so we reuse the exact scoring used at runtime.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "app"))
sys.path.insert(0, os.path.join(ROOT, "model"))

import tensorflow as tf
from tensorflow.keras.models import load_model

from train_model import load_training_data, encode_sequence_with_tokenizer, MAX_LEN
from early_detection import predict_early_windows, DEFAULT_WINDOWS
from preprocessing import compute_event_statistics
import pickle

ML_ALERT_THRESHOLD = 0.5


def synthesize_runtime_dataframe(events):
    """Build a minimal DataFrame matching what behavior_logger writes at runtime.

    The training CSVs only contain raw event names. At runtime, behavior_logger
    also emits derived events such as RapidFileWrite, HighEntropyFile, etc.
    Since the training data does not include those, we approximate them here by
    counting only the events that actually appear in the trace. This is the
    same approximation used in the GUI when no derived events fire.
    """
    return pd.DataFrame({"event": events})


def runtime_composite_score(model, events, tokenizer):
    """Recompute the same composite score the GUI uses at runtime."""
    df = synthesize_runtime_dataframe(events)

    # Encode for the model
    full_padded = np.array([encode_sequence_with_tokenizer(events, tokenizer)])
    ml_signal = float(model.predict(full_padded, verbose=0)[0][0])

    # Run early-window prediction (uses preprocessing.preprocess_events under the hood)
    early_result = predict_early_windows(model, events,
                                         windows=DEFAULT_WINDOWS,
                                         threshold=ML_ALERT_THRESHOLD)

    # Replicate compute_threat_score from app/main.py
    write_ops      = (df["event"] == "WriteFile").sum()
    rapid_writes   = (df["event"] == "RapidFileWrite").sum()
    busy_loops     = (df["event"] == "BusyLoop").sum()
    high_entropy   = (df["event"] == "HighEntropyFile").sum()
    canary_hits    = (df["event"] == "CanaryViolation").sum()
    shadow_deletes = (df["event"] == "ShadowCopyDelete").sum()
    suspicious_kids = (df["event"] == "SuspiciousChild").sum()
    early_terms    = (df["event"] == "EarlyTermination").sum()
    total_events   = len(df)

    early_signal = 0.0
    if early_result["earliest_alert_window"] is not None:
        w = early_result["earliest_alert_window"]
        if w >= 20:
            early_signal = min(1.0, early_result["earliest_alert_score"])
        elif w >= 10:
            early_signal = min(1.0, early_result["earliest_alert_score"] * 0.5)

    rapid_signal   = min(1.0, max(0, rapid_writes - 1) / 3.0)
    entropy_signal = min(1.0, high_entropy / 2.0)
    canary_signal  = min(1.0, canary_hits)
    shadow_signal  = min(1.0, shadow_deletes)

    combo_signal = 0.0
    if total_events > 0:
        write_density = write_ops / max(total_events, 1)
        loop_density  = busy_loops / max(total_events, 1)
        combo_signal = min(1.0, (write_density * 3 + loop_density * 5))

    child_signal = min(1.0, suspicious_kids / 2.0)

    WEIGHTS = {'ml':0.30, 'early':0.15, 'rapid':0.15, 'entropy':0.15,
               'canary':0.10, 'shadow':0.05, 'combo':0.05, 'child':0.05}

    composite = (
        WEIGHTS['ml']      * ml_signal +
        WEIGHTS['early']   * early_signal +
        WEIGHTS['rapid']   * rapid_signal +
        WEIGHTS['entropy'] * entropy_signal +
        WEIGHTS['canary']  * canary_signal +
        WEIGHTS['shadow']  * shadow_signal +
        WEIGHTS['combo']   * combo_signal +
        WEIGHTS['child']   * child_signal
    )

    if canary_hits >= 1 or shadow_deletes >= 1:
        composite = max(composite, 0.95)
    if early_terms >= 1:
        composite = max(composite, 0.80)

    return composite


def main():
    print("[*] Loading model and tokenizer...")
    model = load_model(os.path.join(ROOT, "model", "trained_model.h5"), compile=False)
    tokenizer_path = os.path.join(ROOT, "model", "tokenizer.pkl")
    resolved = os.path.realpath(tokenizer_path)
    allowed_dir = os.path.realpath(os.path.join(ROOT, "model"))
    if not resolved.startswith(allowed_dir + os.sep) and resolved != allowed_dir:
        raise ValueError(f"Tokenizer path outside model directory: {resolved}")
    with open(resolved, "rb") as f:
        tokenizer = pickle.load(f)

    print("[*] Loading dataset (mirrors training split exactly)...")
    sequences, labels, sources = load_training_data()
    strat_key = [f"{l}_{s}" for l, s in zip(labels, sources)]
    _, seq_te, _, y_te, _, src_te = train_test_split(
        sequences, labels, sources,
        test_size=0.2, random_state=42, stratify=strat_key
    )

    # Real-only test set
    real_idx = [i for i, s in enumerate(src_te) if s == "real"]
    real_sequences = [seq_te[i] for i in real_idx]
    real_labels    = np.array([y_te[i] for i in real_idx])
    print(f"[*] Real test samples: {len(real_sequences)} "
          f"(benign={(real_labels==0).sum()}, ransom={(real_labels==1).sum()})")

    if len(real_sequences) == 0:
        print("[!] No real test samples found. Aborting.")
        return

    print("[*] Computing composite scores...")
    composites = []
    for i, ev in enumerate(real_sequences):
        composites.append(runtime_composite_score(model, ev, tokenizer))
        if (i+1) % 5 == 0:
            print(f"    {i+1}/{len(real_sequences)}")
    composites = np.array(composites)

    print("\n[*] Sweeping thresholds...")
    rows = []
    best_f1 = (-1, None)
    best_p95 = (None, -1)  # (threshold, recall) where precision >= 0.95
    for t in np.arange(0.10, 0.91, 0.05):
        pred = (composites >= t).astype(int)
        p = precision_score(real_labels, pred, zero_division=0)
        r = recall_score(real_labels, pred, zero_division=0)
        f = f1_score(real_labels, pred, zero_division=0)
        cm = confusion_matrix(real_labels, pred, labels=[0,1])
        tn, fp, fn, tp = cm.ravel()
        rows.append({
            "threshold": round(t, 2),
            "precision": round(p, 4),
            "recall":    round(r, 4),
            "f1":        round(f, 4),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        })
        if f > best_f1[0]:
            best_f1 = (f, t)
        if p >= 0.95 and r > best_p95[1]:
            best_p95 = (t, r)

    out_txt = os.path.join(ROOT, "reports", "threshold_calibration.txt")
    out_csv = os.path.join(ROOT, "reports", "threshold_calibration.csv")
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["threshold","precision","recall","f1","tn","fp","fn","tp"])
        w.writeheader()
        for row in rows:
            w.writerow(row)

    lines = []
    lines.append("COMPOSITE-SCORE THRESHOLD CALIBRATION")
    lines.append("Evaluated on real-only held-out test samples")
    lines.append(f"n = {len(real_sequences)} "
                 f"(benign={(real_labels==0).sum()}, ransom={(real_labels==1).sum()})")
    lines.append("="*72)
    lines.append(f"{'Threshold':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} "
                 f"{'TN':>5} {'FP':>5} {'FN':>5} {'TP':>5}")
    lines.append("-"*72)
    for r in rows:
        lines.append(f"{r['threshold']:>10.2f} {r['precision']*100:>9.2f}% "
                     f"{r['recall']*100:>9.2f}% {r['f1']*100:>9.2f}% "
                     f"{r['tn']:>5} {r['fp']:>5} {r['fn']:>5} {r['tp']:>5}")
    lines.append("-"*72)
    lines.append("")
    lines.append(f"Best F1:               threshold={best_f1[1]:.2f}  F1={best_f1[0]*100:.2f}%")
    if best_p95[0] is not None:
        lines.append(f"Best recall @ P>=95%:  threshold={best_p95[0]:.2f}  Recall={best_p95[1]*100:.2f}%")
    else:
        lines.append("Best recall @ P>=95%:  no threshold achieved >=95% precision")
    lines.append("")
    lines.append("Recommendation: pick the threshold that best matches the deployment")
    lines.append("priority. Maximising F1 balances false alarms and missed detections.")
    lines.append("If false alarms are costly (consumer deployment), pick the highest")
    lines.append("threshold with recall>=80% that keeps precision>=95%.")

    with open(out_txt, "w") as f:
        f.write("\n".join(lines))

    print("\n" + "\n".join(lines))
    print(f"\n[OK] Saved {out_txt}")
    print(f"[OK] Saved {out_csv}")


if __name__ == "__main__":
    main()
