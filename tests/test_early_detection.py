import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import numpy as np

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT_DIR, "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from early_detection import (
    predict_early_windows,
    format_early_detection_report,
    DEFAULT_WINDOWS,
)


def make_model(*scores):
    """Return a mock model whose predict() returns each score in sequence."""
    score_iter = iter(scores)
    model = MagicMock()
    model.predict.side_effect = lambda data, verbose=0: np.array([[next(score_iter)]])
    return model


class PredictEarlyWindowsTests(unittest.TestCase):
    def setUp(self):
        # Patch load_tokenizer so tests don't need a real tokenizer.pkl
        self.tok_patcher = patch("preprocessing.load_tokenizer", return_value=MagicMock(
            texts_to_sequences=lambda texts: [[1, 2, 3]]
        ))
        self.tok_patcher.start()

    def tearDown(self):
        self.tok_patcher.stop()

    def test_empty_events_returns_none_alert(self):
        model = MagicMock()
        result = predict_early_windows(model, [])

        self.assertIsNone(result["earliest_alert_window"])
        self.assertIsNone(result["earliest_alert_score"])
        self.assertEqual(result["final_score"], 0.0)
        self.assertEqual(result["confidence_level"], "NONE")
        self.assertEqual(result["scores"], {})

    def test_skips_windows_larger_than_event_count(self):
        events = ["WriteFile"] * 5
        # 5 events → only windows ≤ 5 should be evaluated
        model = make_model(0.3, 0.9)  # window=10 skipped, only full-log called
        result = predict_early_windows(model, events, windows=[10, 20], threshold=0.5)

        # Both windows larger than 5 events → no window scores, only full score
        self.assertEqual(set(result["scores"].keys()), {"full"})

    def test_earliest_alert_window_set_when_threshold_crossed(self):
        events = ["WriteFile"] * 100
        # windows 10→0.2, 20→0.6 (crosses 0.5), 30→0.8, full→0.9
        model = make_model(0.2, 0.6, 0.8, 0.9)
        result = predict_early_windows(model, events, windows=[10, 20, 30], threshold=0.5)

        self.assertEqual(result["earliest_alert_window"], 20)
        self.assertAlmostEqual(result["earliest_alert_score"], 0.6)

    def test_no_alert_when_all_scores_below_threshold(self):
        events = ["WriteFile"] * 100
        model = make_model(0.1, 0.2, 0.3, 0.4)
        result = predict_early_windows(model, events, windows=[10, 20, 30], threshold=0.5)

        self.assertIsNone(result["earliest_alert_window"])
        self.assertIsNone(result["earliest_alert_score"])

    def test_confidence_level_critical_for_window_10(self):
        events = ["WriteFile"] * 100
        # Threshold crossed at window=10
        model = make_model(0.9, 0.9, 0.9, 0.9)
        result = predict_early_windows(model, events, windows=[10, 20, 30], threshold=0.5)

        self.assertEqual(result["confidence_level"], "CRITICAL")

    def test_confidence_level_high_for_window_between_11_and_30(self):
        events = ["WriteFile"] * 100
        # window=10 misses, window=20 hits
        model = make_model(0.3, 0.9, 0.9, 0.9)
        result = predict_early_windows(model, events, windows=[10, 20, 30], threshold=0.5)

        self.assertEqual(result["confidence_level"], "HIGH")

    def test_confidence_level_medium_for_window_between_31_and_75(self):
        events = ["WriteFile"] * 100
        # windows 10,20,30 miss; window=50 hits
        model = make_model(0.3, 0.3, 0.3, 0.9, 0.9)
        result = predict_early_windows(model, events, windows=[10, 20, 30, 50], threshold=0.5)

        self.assertEqual(result["confidence_level"], "MEDIUM")

    def test_confidence_level_high_from_final_score_above_0_8(self):
        events = ["WriteFile"] * 5
        # No windows qualify (all > events), full score = 0.85
        model = make_model(0.85)
        result = predict_early_windows(model, events, windows=[10, 20], threshold=0.5)

        self.assertEqual(result["confidence_level"], "HIGH")

    def test_confidence_level_medium_from_final_score_between_0_5_and_0_8(self):
        events = ["WriteFile"] * 5
        model = make_model(0.65)
        result = predict_early_windows(model, events, windows=[10, 20], threshold=0.5)

        self.assertEqual(result["confidence_level"], "MEDIUM")

    def test_confidence_boosted_by_behavioral_stats(self):
        # High write_ratio + high phase_ratio should boost MEDIUM → HIGH
        events = (
            ["FindFirstFile"] * 30 +  # enum in first half
            ["WriteFile"] * 70        # writes in second half
        )
        # Final score 0.65 → starts at MEDIUM, but behavior boosts it
        model = make_model(0.65)
        result = predict_early_windows(model, events, windows=[200], threshold=0.5)

        # write_ratio and phase_ratio should be high → boosted to HIGH
        self.assertIn(result["confidence_level"], ("HIGH", "CRITICAL"))

    def test_score_acceleration_computed_for_multiple_windows(self):
        events = ["WriteFile"] * 200
        # Rising scores → positive acceleration
        model = make_model(0.1, 0.3, 0.5, 0.7, 0.9, 0.95, 0.98, 0.99)
        result = predict_early_windows(model, events, windows=DEFAULT_WINDOWS, threshold=0.99)

        self.assertIn("score_acceleration", result)
        self.assertIsInstance(result["score_acceleration"], float)

    def test_final_score_always_present(self):
        events = ["WriteFile"] * 200
        model = make_model(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8)
        result = predict_early_windows(model, events, windows=DEFAULT_WINDOWS, threshold=0.5)

        self.assertIn("full", result["scores"])
        self.assertAlmostEqual(result["final_score"], result["scores"]["full"])

    def test_behavioral_stats_populated(self):
        events = ["WriteFile", "OpenFile", "DeleteFile"] * 50
        model = make_model(0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99)
        result = predict_early_windows(model, events, windows=DEFAULT_WINDOWS, threshold=0.5)

        stats = result["behavioral_stats"]
        self.assertIn("write_ratio", stats)
        self.assertIn("event_entropy", stats)
        self.assertGreater(stats["write_ratio"], 0)


class FormatEarlyDetectionReportTests(unittest.TestCase):
    def _make_result(self, **overrides):
        base = {
            "scores": {10: 0.3, 20: 0.7, "full": 0.85},
            "earliest_alert_window": 20,
            "earliest_alert_score": 0.7,
            "final_score": 0.85,
            "score_acceleration": 0.6,
            "behavioral_stats": {
                "event_entropy": 2.5,
                "write_ratio": 0.4,
                "enum_ratio": 0.2,
                "write_burst_max": 5,
                "phase_ratio": 0.12,
                "transition_diversity": 8,
            },
            "confidence_level": "HIGH",
        }
        base.update(overrides)
        return base

    def test_report_contains_earliest_alert_line(self):
        report = format_early_detection_report(self._make_result())
        self.assertIn("Earliest Alert: call 20", report)

    def test_report_shows_none_when_no_alert(self):
        result = self._make_result(earliest_alert_window=None, earliest_alert_score=None)
        report = format_early_detection_report(result)
        self.assertIn("Earliest Alert: none", report)

    def test_report_contains_confidence_level(self):
        report = format_early_detection_report(self._make_result())
        self.assertIn("Confidence: HIGH", report)

    def test_report_contains_score_trend(self):
        report = format_early_detection_report(self._make_result(score_acceleration=0.6))
        self.assertIn("RISING", report)

    def test_report_contains_behavioral_section(self):
        report = format_early_detection_report(self._make_result())
        self.assertIn("Behavioral Analysis", report)
        self.assertIn("Write Ratio", report)

    def test_report_falling_trend_label(self):
        report = format_early_detection_report(self._make_result(score_acceleration=-0.5))
        self.assertIn("FALLING", report)

    def test_report_stable_trend_label(self):
        report = format_early_detection_report(self._make_result(score_acceleration=0.0))
        self.assertIn("STABLE", report)

    def test_report_empty_behavioral_stats_omits_section(self):
        result = self._make_result(behavioral_stats={})
        report = format_early_detection_report(result)
        self.assertNotIn("Behavioral Analysis", report)


from early_detection import evaluate_dataset_early_detection


class ZeroNegativeWindowTests(unittest.TestCase):
    def setUp(self):
        self.tok_patcher = patch("preprocessing.load_tokenizer", return_value=MagicMock(
            texts_to_sequences=lambda texts: [[1, 2, 3]]
        ))
        self.tok_patcher.start()

    def tearDown(self):
        self.tok_patcher.stop()

    def test_zero_window_skipped(self):
        events = ["WriteFile"] * 100
        model = make_model(0.9)  # called only for full log
        result = predict_early_windows(model, events, windows=[0], threshold=0.5)
        self.assertNotIn(0, result["scores"])
        self.assertIn("full", result["scores"])

    def test_negative_window_skipped(self):
        events = ["WriteFile"] * 100
        model = make_model(0.9)
        result = predict_early_windows(model, events, windows=[-5], threshold=0.5)
        self.assertNotIn(-5, result["scores"])


class ConfidenceHighToCriticalBoostTests(unittest.TestCase):
    def setUp(self):
        self.tok_patcher = patch("preprocessing.load_tokenizer", return_value=MagicMock(
            texts_to_sequences=lambda texts: [[1, 2, 3]]
        ))
        self.tok_patcher.start()

    def tearDown(self):
        self.tok_patcher.stop()

    def test_confidence_boosted_from_high_to_critical(self):
        # Enum phase followed by heavy writes → high write_ratio + phase_ratio
        events = ["FindFirstFile"] * 30 + ["WriteFile"] * 70
        # No qualifying windows (window=200 > 100 events) → final_score=0.85 → HIGH
        # Behavioral stats (write_ratio=0.7, high phase_ratio) then boost HIGH → CRITICAL
        model = make_model(0.85)
        result = predict_early_windows(model, events, windows=[200], threshold=0.5)
        self.assertEqual(result["confidence_level"], "CRITICAL")


class EvaluateDatasetEarlyDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tok_patcher = patch("preprocessing.load_tokenizer", return_value=MagicMock(
            texts_to_sequences=lambda texts: [[1, 2, 3]]
        ))
        self.tok_patcher.start()

    def tearDown(self):
        self.tok_patcher.stop()

    def _model(self, score=0.8):
        m = MagicMock()
        m.predict.return_value = np.array([[score]])
        return m

    def test_returns_window_keys(self):
        with patch("early_detection.read_events_from_log", return_value=["WriteFile"] * 50), \
             patch("early_detection.preprocess_events", return_value=np.zeros((1, 100))):
            result = evaluate_dataset_early_detection(
                self._model(), ["/fake/a.csv"], [1], windows=[10, 20]
            )
        self.assertIn("first_10_calls", result)
        self.assertIn("first_20_calls", result)
        self.assertIn("full_log", result)

    def test_metrics_keys_present(self):
        with patch("early_detection.read_events_from_log", return_value=["WriteFile"] * 50), \
             patch("early_detection.preprocess_events", return_value=np.zeros((1, 100))):
            result = evaluate_dataset_early_detection(
                self._model(), ["/fake/a.csv"], [1], windows=[10]
            )
        entry = result["first_10_calls"]
        for key in ("accuracy", "precision", "recall", "f1", "false_positive_rate", "confusion_matrix"):
            self.assertIn(key, entry)

    def test_skips_short_sequences(self):
        # 5 events < window=10 → window skipped, full_log still present
        with patch("early_detection.read_events_from_log", return_value=["WriteFile"] * 5), \
             patch("early_detection.preprocess_events", return_value=np.zeros((1, 100))):
            result = evaluate_dataset_early_detection(
                self._model(), ["/fake/a.csv"], [1], windows=[10, 20]
            )
        self.assertNotIn("first_10_calls", result)
        self.assertIn("full_log", result)

    def test_skips_file_on_exception(self):
        with patch("early_detection.read_events_from_log", side_effect=Exception("bad file")):
            result = evaluate_dataset_early_detection(
                self._model(), ["/bad/a.csv"], [1], windows=[10]
            )
        self.assertNotIn("first_10_calls", result)

    def test_empty_file_list_returns_empty(self):
        result = evaluate_dataset_early_detection(self._model(), [], [], windows=[10])
        self.assertEqual(result, {})

    def test_correct_prediction_updates_confusion_matrix(self):
        # Model predicts 0.2 (below 0.5) for benign sample → TN
        with patch("early_detection.read_events_from_log", return_value=["ReadFile"] * 50), \
             patch("early_detection.preprocess_events", return_value=np.zeros((1, 100))):
            result = evaluate_dataset_early_detection(
                self._model(score=0.2), ["/fake/a.csv"], [0], windows=[10]
            )
        cm = result["first_10_calls"]["confusion_matrix"]
        self.assertEqual(cm["tn"], 1)
        self.assertEqual(cm["fp"], 0)

    def test_fpr_zero_when_no_false_positives(self):
        # All samples are ransomware, model predicts ransomware → no FP
        with patch("early_detection.read_events_from_log", return_value=["WriteFile"] * 50), \
             patch("early_detection.preprocess_events", return_value=np.zeros((1, 100))):
            result = evaluate_dataset_early_detection(
                self._model(score=0.9), ["/fake/a.csv"], [1], windows=[10]
            )
        self.assertAlmostEqual(result["first_10_calls"]["false_positive_rate"], 0.0)

    def test_none_window_produces_full_log_key(self):
        with patch("early_detection.read_events_from_log", return_value=["WriteFile"] * 50), \
             patch("early_detection.preprocess_events", return_value=np.zeros((1, 100))):
            result = evaluate_dataset_early_detection(
                self._model(), ["/fake/a.csv"], [1], windows=[]
            )
        self.assertIn("full_log", result)


if __name__ == "__main__":
    unittest.main()
