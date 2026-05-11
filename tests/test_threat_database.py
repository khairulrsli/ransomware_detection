import os
import sys
import tempfile
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT_DIR, "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from threat_database import ThreatDatabase


class ThreatDatabaseTests(unittest.TestCase):
    def make_database(self, temp_dir):
        database = ThreatDatabase()
        database.db_path = os.path.join(temp_dir, "test_threat_database.db")
        database.init_database()
        return database

    def test_add_analysis_updates_statistics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)

            database.add_analysis(
                "sample.exe",
                "RANSOMWARE",
                0.91,
                0.88,
                {"write_ops": 3, "rapid_writes": 1, "busy_loops": 1, "network_ops": 0},
                "QUARANTINED",
                "test",
            )

            stats = database.get_statistics()
            self.assertEqual(stats["total_scans"], 1)
            self.assertEqual(stats["ransomware_detected"], 1)
            self.assertEqual(stats["benign_detected"], 0)
            self.assertAlmostEqual(stats["avg_confidence"], 0.91)

    def test_clear_all_data_resets_statistics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            database.add_analysis("clean.exe", "BENIGN FILE", 0.2, 0.1, {}, "NONE", "")

            database.clear_all_data()

            stats = database.get_statistics()
            self.assertEqual(stats["total_scans"], 0)
            self.assertEqual(stats["ransomware_detected"], 0)
            self.assertEqual(stats["benign_detected"], 0)
            self.assertEqual(stats["avg_confidence"], 0)
            self.assertEqual(database.get_recent_analyses(), [])


if __name__ == "__main__":
    unittest.main()
