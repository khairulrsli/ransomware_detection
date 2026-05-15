import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(ROOT_DIR, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from generate_report_charts import (
    confusion_matrix_svg,
    metrics_bar_svg,
    parse_evaluation_results,
    parse_training_history,
    read_text,
    training_history_svg,
    write_svg,
)

SAMPLE_EVAL = (
    "Accuracy : 96.50%\n"
    "Precision : 97.20%\n"
    "Recall : 95.80%\n"
    "F1-Score : 96.49%\n"
    "TN=120 FP=3 FN=5 TP=112\n"
)

SAMPLE_TRAINING = (
    "  1  0.5432  89.12%  0.4321  91.23%\n"
    "  2  0.3210  92.45%  0.3100  93.10%\n"
    "  3  0.2100  95.00%  0.2200  94.50%\n"
)


class TestReadText(unittest.TestCase):
    def test_reads_file_content(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("hello world")
            tmp = f.name
        try:
            self.assertEqual(read_text(tmp), "hello world")
        finally:
            os.unlink(tmp)


class TestParseEvaluationResults(unittest.TestCase):
    def _patch(self):
        return patch("generate_report_charts.read_text", return_value=SAMPLE_EVAL)

    def test_parses_accuracy(self):
        with self._patch():
            metrics, _ = parse_evaluation_results()
        self.assertAlmostEqual(metrics["Accuracy"], 96.50)

    def test_parses_precision(self):
        with self._patch():
            metrics, _ = parse_evaluation_results()
        self.assertAlmostEqual(metrics["Precision"], 97.20)

    def test_parses_recall(self):
        with self._patch():
            metrics, _ = parse_evaluation_results()
        self.assertAlmostEqual(metrics["Recall"], 95.80)

    def test_parses_f1(self):
        with self._patch():
            metrics, _ = parse_evaluation_results()
        self.assertAlmostEqual(metrics["F1-Score"], 96.49)

    def test_parses_confusion_matrix(self):
        with self._patch():
            _, matrix = parse_evaluation_results()
        self.assertEqual(matrix, [[120, 3], [5, 112]])

    def test_raises_on_missing_confusion_matrix(self):
        with patch("generate_report_charts.read_text", return_value="Accuracy: 90.0%"):
            with self.assertRaises(ValueError):
                parse_evaluation_results()


class TestParseTrainingHistory(unittest.TestCase):
    def _patch(self):
        return patch("generate_report_charts.read_text", return_value=SAMPLE_TRAINING)

    def test_returns_correct_epoch_count(self):
        with self._patch():
            rows = parse_training_history()
        self.assertEqual(len(rows), 3)

    def test_first_row_epoch_and_loss(self):
        with self._patch():
            rows = parse_training_history()
        self.assertEqual(rows[0]["epoch"], 1)
        self.assertAlmostEqual(rows[0]["loss"], 0.5432)
        self.assertAlmostEqual(rows[0]["accuracy"], 89.12)

    def test_last_row_val_accuracy(self):
        with self._patch():
            rows = parse_training_history()
        self.assertAlmostEqual(rows[2]["val_accuracy"], 94.50)

    def test_empty_text_returns_no_rows(self):
        with patch("generate_report_charts.read_text", return_value="no data here"):
            rows = parse_training_history()
        self.assertEqual(rows, [])


class TestConfusionMatrixSvg(unittest.TestCase):
    def setUp(self):
        self.svg = confusion_matrix_svg([[120, 3], [5, 112]])

    def test_returns_svg_element(self):
        self.assertIn("<svg", self.svg)

    def test_contains_tn_value(self):
        self.assertIn(">120<", self.svg)

    def test_contains_fp_value(self):
        self.assertIn(">3<", self.svg)

    def test_contains_fn_value(self):
        self.assertIn(">5<", self.svg)

    def test_contains_tp_value(self):
        self.assertIn(">112<", self.svg)

    def test_title_present(self):
        self.assertIn("Confusion Matrix", self.svg)

    def test_cell_labels_present(self):
        for label in ("True Negative", "False Positive", "False Negative", "True Positive"):
            self.assertIn(label, self.svg)

    def test_high_value_uses_dark_text(self):
        svg = confusion_matrix_svg([[1000, 1], [1, 1000]])
        self.assertIn("#ffffff", svg)

    def test_low_value_uses_light_background(self):
        svg = confusion_matrix_svg([[1, 100], [100, 1]])
        self.assertIn("rgb(", svg)


class TestMetricsBarSvg(unittest.TestCase):
    def setUp(self):
        self.metrics = {"Accuracy": 96.5, "Precision": 97.2, "Recall": 95.8, "F1-Score": 96.49}
        self.svg = metrics_bar_svg(self.metrics)

    def test_returns_svg_element(self):
        self.assertIn("<svg", self.svg)

    def test_contains_metric_names(self):
        for name in self.metrics:
            self.assertIn(name, self.svg)

    def test_title_present(self):
        self.assertIn("Model Performance Metrics", self.svg)

    def test_empty_metrics_still_returns_svg(self):
        svg = metrics_bar_svg({})
        self.assertIn("<svg", svg)

    def test_bar_values_formatted(self):
        self.assertIn("96.50%", self.svg)


class TestTrainingHistorySvg(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"epoch": 1, "loss": 0.5, "accuracy": 89.0, "val_loss": 0.4, "val_accuracy": 91.0},
            {"epoch": 2, "loss": 0.3, "accuracy": 93.0, "val_loss": 0.3, "val_accuracy": 93.0},
            {"epoch": 3, "loss": 0.2, "accuracy": 96.0, "val_loss": 0.25, "val_accuracy": 95.0},
        ]
        self.svg = training_history_svg(self.rows)

    def test_returns_svg_element(self):
        self.assertIn("<svg", self.svg)

    def test_title_present(self):
        self.assertIn("Training Accuracy History", self.svg)

    def test_epoch_axis_label(self):
        self.assertIn("Epoch", self.svg)

    def test_legend_labels(self):
        self.assertIn("Training Accuracy", self.svg)
        self.assertIn("Validation Accuracy", self.svg)

    def test_single_epoch_no_crash(self):
        rows = [{"epoch": 1, "loss": 0.5, "accuracy": 89.0, "val_loss": 0.4, "val_accuracy": 91.0}]
        svg = training_history_svg(rows)
        self.assertIn("<svg", svg)

    def test_polyline_present(self):
        self.assertIn("<polyline", self.svg)


class TestWriteSvg(unittest.TestCase):
    def test_writes_and_returns_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_report_charts.REPORT_DIR", tmpdir):
                path = write_svg("test.svg", "<svg/>")
        self.assertTrue(path.endswith("test.svg"))

    def test_content_matches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_report_charts.REPORT_DIR", tmpdir):
                path = write_svg("out.svg", "<svg>content</svg>")
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), "<svg>content</svg>")

    def test_creates_report_dir_if_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "reports")
            with patch("generate_report_charts.REPORT_DIR", subdir):
                write_svg("x.svg", "<svg/>")
            self.assertTrue(os.path.isdir(subdir))


if __name__ == "__main__":
    unittest.main()
