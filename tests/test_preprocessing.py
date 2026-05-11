import os
import sys
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT_DIR, "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from preprocessing import compute_event_statistics


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


if __name__ == "__main__":
    unittest.main()
