import os
import sys
import pickle
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT_DIR, "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import preprocessing
from preprocessing import compute_event_statistics, read_events_from_log, preprocess_events


class EventStatisticsTests(unittest.TestCase):
    def test_empty_events_returns_empty_dict(self):
        self.assertEqual(compute_event_statistics([]), {})

    def test_write_and_phase_metrics(self):
        events = [
            "FindFirstFile",
            "FindNextFile",
            "OpenFile",
            "WriteFile",
            "RapidFileWrite",
            "WriteFile",
        ]

        stats = compute_event_statistics(events)

        self.assertAlmostEqual(stats["write_ratio"], 3 / 6)
        self.assertAlmostEqual(stats["enum_ratio"], 3 / 6)
        self.assertEqual(stats["write_burst_max"], 3)
        self.assertGreater(stats["transition_diversity"], 0)
        self.assertGreater(stats["phase_ratio"], 0)

    def test_single_event_entropy_is_zero(self):
        stats = compute_event_statistics(["WriteFile"])
        self.assertAlmostEqual(stats["event_entropy"], 0.0)

    def test_write_burst_resets_on_non_write(self):
        # burst of 2, break, burst of 1 → max should be 2
        events = ["WriteFile", "WriteFile", "OpenFile", "DeleteFile"]
        stats = compute_event_statistics(events)
        self.assertEqual(stats["write_burst_max"], 2)

    def test_busy_loop_density(self):
        events = ["BusyLoop", "BusyLoop", "WriteFile", "WriteFile"]
        stats = compute_event_statistics(events)
        self.assertAlmostEqual(stats["busy_loop_density"], 0.5)

    def test_transition_diversity_counts_unique_pairs(self):
        # A→B, B→A, A→B — unique pairs: (A,B) and (B,A) = 2
        events = ["WriteFile", "OpenFile", "WriteFile", "OpenFile"]
        stats = compute_event_statistics(events)
        self.assertEqual(stats["transition_diversity"], 2)

    def test_no_phase_ratio_when_no_enum_or_write(self):
        events = ["BusyLoop", "BusyLoop", "BusyLoop", "BusyLoop"]
        stats = compute_event_statistics(events)
        self.assertAlmostEqual(stats["phase_ratio"], 0.0)


class ReadEventsFromLogTests(unittest.TestCase):
    def _write_csv(self, content):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        f.write(content)
        f.close()
        return f.name

    def tearDown(self):
        # Reset any temp files created
        pass

    def test_returns_event_list_from_valid_csv(self):
        path = self._write_csv("event\nWriteFile\nOpenFile\nDeleteFile\n")
        try:
            events = read_events_from_log(path)
            self.assertEqual(events, ["WriteFile", "OpenFile", "DeleteFile"])
        finally:
            os.unlink(path)

    def test_raises_when_file_not_found(self):
        with self.assertRaises(Exception) as ctx:
            read_events_from_log("/nonexistent/path/file.csv")
        self.assertIn("not found", str(ctx.exception))

    def test_raises_when_event_column_missing(self):
        path = self._write_csv("api_call\nWriteFile\nOpenFile\n")
        try:
            with self.assertRaises(Exception) as ctx:
                read_events_from_log(path)
            self.assertIn("event", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_raises_on_empty_file(self):
        path = self._write_csv("")
        try:
            with self.assertRaises(Exception):
                read_events_from_log(path)
        finally:
            os.unlink(path)

    def test_raises_when_no_rows(self):
        path = self._write_csv("event\n")
        try:
            with self.assertRaises(Exception) as ctx:
                read_events_from_log(path)
            self.assertIn("No events", str(ctx.exception))
        finally:
            os.unlink(path)


class LoadTokenizerTests(unittest.TestCase):
    def setUp(self):
        preprocessing._cached_tokenizer = None
        preprocessing._cached_tokenizer_path = None

    def _expected_tokenizer_path(self):
        app_dir = os.path.dirname(os.path.abspath(preprocessing.__file__))
        model_dir = os.path.join(os.path.dirname(app_dir), "model")
        return os.path.join(model_dir, "tokenizer.pkl")

    def test_raises_when_tokenizer_file_missing(self):
        with patch("builtins.open", side_effect=FileNotFoundError("no file")):
            with self.assertRaises(Exception) as ctx:
                preprocessing.load_tokenizer()
        self.assertIn("Train the model first", str(ctx.exception))

    def test_returns_cached_tokenizer_without_disk_read(self):
        sentinel = object()
        expected_path = self._expected_tokenizer_path()
        preprocessing._cached_tokenizer = sentinel
        preprocessing._cached_tokenizer_path = expected_path

        with patch("builtins.open", side_effect=AssertionError("should not read file")):
            result = preprocessing.load_tokenizer()

        self.assertIs(result, sentinel)

    def test_path_traversal_raises_value_error(self):
        with patch("preprocessing.os.path.realpath") as mock_realpath:
            outside_path = os.path.join(os.path.sep, "outside", "tokenizer.pkl")
            allowed_dir = os.path.join(os.path.sep, "model")

            call_count = [0]
            def side_effect(p):
                call_count[0] += 1
                if call_count[0] == 1:
                    return outside_path
                return allowed_dir

            mock_realpath.side_effect = side_effect

            with self.assertRaises(ValueError) as ctx:
                preprocessing.load_tokenizer()
        self.assertIn("outside model directory", str(ctx.exception))


class PreprocessEventsTests(unittest.TestCase):
    def test_empty_events_returns_zero_array(self):
        import numpy as np
        fake_tok = MagicMock()
        with patch("preprocessing.load_tokenizer", return_value=fake_tok):
            result = preprocess_events([])
        self.assertEqual(result.shape, (1, preprocessing.MAX_LEN))
        self.assertTrue((result == 0).all())

    def test_max_events_truncates_input(self):
        fake_tok = MagicMock()
        fake_tok.texts_to_sequences.return_value = [[1, 2]]
        with patch("preprocessing.load_tokenizer", return_value=fake_tok):
            preprocess_events(["WriteFile"] * 50, max_events=5)

        called_text = fake_tok.texts_to_sequences.call_args[0][0][0]
        self.assertEqual(called_text.count("WriteFile"), 5)

    def test_output_shape_matches_max_len(self):
        fake_tok = MagicMock()
        fake_tok.texts_to_sequences.return_value = [[1, 2, 3]]
        with patch("preprocessing.load_tokenizer", return_value=fake_tok):
            result = preprocess_events(["WriteFile", "OpenFile", "DeleteFile"])
        self.assertEqual(result.shape[1], preprocessing.MAX_LEN)

    def test_unknown_events_return_zero_array(self):
        import numpy as np
        fake_tok = MagicMock()
        fake_tok.texts_to_sequences.return_value = [[]]  # OOV → empty sequence
        with patch("preprocessing.load_tokenizer", return_value=fake_tok):
            result = preprocess_events(["UnknownEvent"])
        self.assertTrue((result == 0).all())


if __name__ == "__main__":
    unittest.main()
