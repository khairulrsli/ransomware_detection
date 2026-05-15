"""Early ransomware detection utilities.

This module evaluates the model on partial API-call sequences so the system can
raise an alert before the full sandbox run finishes. Enhanced with streaming
inference, graduated confidence scoring, and temporal acceleration analysis.
"""

import os
import sys
from typing import Dict, Iterable, List, Optional

import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from preprocessing import preprocess_events, read_events_from_log, compute_event_statistics


DEFAULT_WINDOWS = (10, 20, 30, 50, 75, 100, 150)


def predict_early_windows(model, events: List[str], windows: Iterable[int] = DEFAULT_WINDOWS, threshold: float = 0.5) -> Dict:
    """
    Predict ransomware probability at multiple early API-call windows.

    Enhanced features:
    - More granular windows (5,10,15,20,30,50,75,100,150) for faster detection
    - Score acceleration tracking (rapid score increase = high threat)
    - Behavioral statistics integrated into final assessment
    - Graduated confidence: early high score = higher confidence

    Returns a dictionary with:
    - scores: probability per evaluated window
    - earliest_alert_window: first window crossing threshold, or None
    - earliest_alert_score: probability at first alert, or None
    - final_score: score using the full event sequence
    - score_acceleration: rate of score increase across windows
    - behavioral_stats: statistical features from the event sequence
    - confidence_level: graduated confidence (CRITICAL/HIGH/MEDIUM/LOW)
    """
    if not events:
        return {
            "scores": {},
            "earliest_alert_window": None,
            "earliest_alert_score": None,
            "final_score": 0.0,
            "score_acceleration": 0.0,
            "behavioral_stats": {},
            "confidence_level": "NONE",
        }

    scores = {}
    score_values = []
    earliest_window: Optional[int] = None
    earliest_score: Optional[float] = None

    for window in windows:
        if window <= 0:
            continue
        if len(events) < window:
            continue

        data = preprocess_events(events, max_events=window)
        score = float(model.predict(data, verbose=0)[0][0])
        scores[int(window)] = score
        score_values.append((window, score))

        if earliest_window is None and score >= threshold:
            earliest_window = int(window)
            earliest_score = score

    full_data = preprocess_events(events)
    final_score = float(model.predict(full_data, verbose=0)[0][0])
    scores["full"] = final_score

    # NOTE: we do NOT backfill earliest_alert_window from the full-log score.
    # Doing so caused compute_threat_score() to double-count the ML signal:
    # once via ml_signal (weight 0.30) and again via early_signal (weight 0.15).
    # An "early alert" should mean exactly that — the model crossed threshold
    # on a partial sequence — not "the full log also crossed threshold."

    # ── Score acceleration analysis ──────────────────────────────────────
    # A rapidly increasing score across windows indicates escalating threat
    score_acceleration = 0.0
    if len(score_values) >= 2:
        # Linear regression slope of scores across windows
        windows_arr = np.array([s[0] for s in score_values], dtype=float)
        scores_arr = np.array([s[1] for s in score_values], dtype=float)
        if np.std(windows_arr) > 0:
            score_acceleration = float(np.corrcoef(windows_arr, scores_arr)[0, 1])
            if np.isnan(score_acceleration):
                score_acceleration = 0.0

    # ── Behavioral statistics ────────────────────────────────────────────
    behavioral_stats = compute_event_statistics(events)

    # ── Graduated confidence level ───────────────────────────────────────
    # Combine ML score, acceleration, and behavioral features
    confidence_level = "LOW"
    if earliest_window is not None:
        if earliest_window <= 10:
            confidence_level = "CRITICAL"
        elif earliest_window <= 30:
            confidence_level = "HIGH"
        elif earliest_window <= 75:
            confidence_level = "MEDIUM"
    elif final_score >= 0.8:
        confidence_level = "HIGH"
    elif final_score >= 0.5:
        confidence_level = "MEDIUM"

    # Boost confidence if behavioral indicators align
    if behavioral_stats.get('write_ratio', 0) > 0.3 and behavioral_stats.get('phase_ratio', 0) > 0.1:
        if confidence_level == "MEDIUM":
            confidence_level = "HIGH"
        elif confidence_level == "HIGH":
            confidence_level = "CRITICAL"

    return {
        "scores": scores,
        "earliest_alert_window": earliest_window,
        "earliest_alert_score": earliest_score,
        "final_score": final_score,
        "score_acceleration": score_acceleration,
        "behavioral_stats": behavioral_stats,
        "confidence_level": confidence_level,
    }


def format_early_detection_report(result: Dict) -> str:
    """Create a compact multiline report for the GUI/console."""
    lines = ["Early Detection Windows:"]
    for window, score in result.get("scores", {}).items():
        label = f"first {window} calls" if isinstance(window, int) else "full log"
        # Add visual indicator
        indicator = "🔴" if score >= 0.7 else ("🟡" if score >= 0.4 else "🟢")
        lines.append(f"  {label:16}: {score:.3f} {indicator}")

    if result.get("earliest_alert_window") is not None:
        lines.append(
            f"Earliest Alert: call {result['earliest_alert_window']} "
            f"({result['earliest_alert_score']:.3f})"
        )
    else:
        lines.append("Earliest Alert: none")

    # Score acceleration
    accel = result.get("score_acceleration", 0)
    accel_label = "RISING" if accel > 0.5 else ("STABLE" if accel > -0.2 else "FALLING")
    lines.append(f"Score Trend: {accel_label} ({accel:+.3f})")

    # Confidence level
    confidence = result.get("confidence_level", "UNKNOWN")
    lines.append(f"Confidence: {confidence}")

    # Key behavioral stats
    stats = result.get("behavioral_stats", {})
    if stats:
        lines.append("─── Behavioral Analysis ───")
        lines.append(f"  Event Entropy  : {stats.get('event_entropy', 0):.3f}")
        lines.append(f"  Write Ratio    : {stats.get('write_ratio', 0):.3f}")
        lines.append(f"  Enum Ratio     : {stats.get('enum_ratio', 0):.3f}")
        lines.append(f"  Max Write Burst: {stats.get('write_burst_max', 0)}")
        lines.append(f"  Phase Pattern  : {stats.get('phase_ratio', 0):.4f}")
        lines.append(f"  Transitions    : {stats.get('transition_diversity', 0)}")

    return "\n".join(lines)


def evaluate_dataset_early_detection(model, csv_files: List[str], labels: List[int], windows: Iterable[int] = DEFAULT_WINDOWS, threshold: float = 0.5) -> Dict:
    """Evaluate accuracy, precision, recall, F1, and false-positive rate per early window."""
    report = {}

    for window in list(windows) + [None]:
        y_true, y_pred, y_score = [], [], []

        for filepath, label in zip(csv_files, labels):
            try:
                events = read_events_from_log(filepath)
                if window is not None and len(events) < window:
                    continue
                data = preprocess_events(events, max_events=window)
                score = float(model.predict(data, verbose=0)[0][0])
                y_true.append(label)
                y_pred.append(1 if score >= threshold else 0)
                y_score.append(score)
            except Exception as exc:
                print(f"[!] Skipping {os.path.basename(filepath)} during early evaluation: {exc}")

        if not y_true:
            continue

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0

        key = f"first_{window}_calls" if window is not None else "full_log"
        report[key] = {
            "samples": len(y_true),
            "accuracy": accuracy_score(y_true, y_pred),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1": f1_score(y_true, y_pred, zero_division=0),
            "false_positive_rate": fpr,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        }

    return report


if __name__ == "__main__":
    # CLI usage: python app/early_detection.py path/to/log.csv
    from tensorflow.keras.models import load_model

    if len(sys.argv) < 2:
        print("Usage: python early_detection.py <api_log.csv>")
        raise SystemExit(1)

    app_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(app_dir)
    model_path = os.path.join(parent_dir, "model", "trained_model.h5")

    model = load_model(model_path)
    events = read_events_from_log(sys.argv[1])
    result = predict_early_windows(model, events)
    print(format_early_detection_report(result))
