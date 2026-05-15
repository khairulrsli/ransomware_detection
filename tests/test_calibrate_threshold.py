import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Import pandas/numpy BEFORE patch.dict so they stay in sys.modules
# through patching and don't get reloaded afterward (avoids numpy reload warning
# and isinstance mismatch between two different DataFrame classes).
import numpy  # noqa: F401
import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT_DIR, "app")
SCRIPTS_DIR = os.path.join(ROOT_DIR, "scripts")
MODEL_DIR = os.path.join(ROOT_DIR, "model")

for path in (APP_DIR, SCRIPTS_DIR, MODEL_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

# Mock TF and train_model before importing calibrate_threshold.
sys.modules.pop("calibrate_threshold", None)
with patch.dict(sys.modules, {
    "tensorflow": MagicMock(),
    "tensorflow.keras": MagicMock(),
    "tensorflow.keras.models": MagicMock(),
    "tensorflow.keras.preprocessing": MagicMock(),
    "tensorflow.keras.preprocessing.sequence": MagicMock(),
    "train_model": MagicMock(
        load_training_data=MagicMock(return_value=([], [], [])),
        encode_sequence_with_tokenizer=MagicMock(return_value=[1, 2, 3]),
        MAX_LEN=100,
    ),
}):
    from calibrate_threshold import synthesize_runtime_dataframe


class TestSynthesizeRuntimeDataframe(unittest.TestCase):
    def test_returns_dataframe(self):
        df = synthesize_runtime_dataframe(["WriteFile", "ReadFile"])
        self.assertIsInstance(df, pd.DataFrame)

    def test_event_column_exists(self):
        df = synthesize_runtime_dataframe(["WriteFile"])
        self.assertIn("event", df.columns)

    def test_length_matches_input(self):
        events = ["WriteFile"] * 10 + ["ReadFile"] * 5
        df = synthesize_runtime_dataframe(events)
        self.assertEqual(len(df), 15)

    def test_event_values_preserved(self):
        events = ["WriteFile", "RapidFileWrite", "HighEntropyFile"]
        df = synthesize_runtime_dataframe(events)
        self.assertEqual(list(df["event"]), events)

    def test_empty_events_returns_empty_df(self):
        df = synthesize_runtime_dataframe([])
        self.assertEqual(len(df), 0)
        self.assertIn("event", df.columns)

    def test_event_counts_correct(self):
        events = ["WriteFile"] * 3 + ["ReadFile"] * 2
        df = synthesize_runtime_dataframe(events)
        self.assertEqual(df["event"].tolist().count("WriteFile"), 3)
        self.assertEqual(df["event"].tolist().count("ReadFile"), 2)

    def test_single_event(self):
        df = synthesize_runtime_dataframe(["CanaryViolation"])
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["event"], "CanaryViolation")

    def test_only_column_is_event(self):
        df = synthesize_runtime_dataframe(["WriteFile"])
        self.assertEqual(list(df.columns), ["event"])

    def test_duplicate_events_preserved(self):
        events = ["WriteFile", "WriteFile", "WriteFile"]
        df = synthesize_runtime_dataframe(events)
        self.assertEqual(df["event"].tolist().count("WriteFile"), 3)


if __name__ == "__main__":
    unittest.main()
