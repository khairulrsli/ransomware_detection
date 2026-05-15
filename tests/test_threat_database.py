import csv
import io
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

    def test_add_quarantine_and_retrieve(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            database.add_quarantine("evil.exe", "/quarantine/evil.exe", "/downloads/evil.exe", "HIGH")

            records = database.get_quarantine_list()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["filename"], "evil.exe")
            self.assertEqual(records[0]["threat_level"], "HIGH")
            self.assertEqual(records[0]["original_path"], "/downloads/evil.exe")

    def test_delete_quarantine_removes_record(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            database.add_quarantine("evil.exe", "/q/evil.exe", "/d/evil.exe", "HIGH")

            records = database.get_quarantine_list()
            record_id = records[0]["id"]

            database.delete_quarantine(record_id)

            self.assertEqual(database.get_quarantine_list(), [])

    def test_delete_quarantine_nonexistent_id_is_noop(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            database.delete_quarantine(99999)  # should not raise
            self.assertEqual(database.get_quarantine_list(), [])

    def test_export_analysis_report_returns_csv_string(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            database.add_analysis("a.exe", "RANSOMWARE", 0.9, 0.85, {}, "KILL", "")
            database.add_analysis("b.exe", "BENIGN", 0.1, 0.05, {}, "NONE", "")

            report = database.export_analysis_report()

            self.assertIsNotNone(report)
            reader = csv.reader(io.StringIO(report))
            rows = list(reader)
            self.assertGreater(len(rows), 2)  # header + 2 data rows
            self.assertIn("filename", rows[0])
            filenames = [row[rows[0].index("filename")] for row in rows[1:]]
            self.assertIn("a.exe", filenames)
            self.assertIn("b.exe", filenames)

    def test_export_analysis_report_returns_none_when_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            self.assertIsNone(database.export_analysis_report())

    def test_get_recent_analyses_respects_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            for i in range(5):
                database.add_analysis(f"file{i}.exe", "BENIGN", 0.1, 0.05, {}, "NONE", "")

            results = database.get_recent_analyses(limit=3)
            self.assertEqual(len(results), 3)

    def test_benign_verdict_increments_benign_count(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            database.add_analysis("clean.exe", "BENIGN", 0.05, 0.02, {}, "NONE", "")

            stats = database.get_statistics()
            self.assertEqual(stats["benign_detected"], 1)
            self.assertEqual(stats["ransomware_detected"], 0)

    def test_connection_rollback_on_exception(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self.make_database(temp_dir)
            # Trigger exception inside context manager by corrupting the sql
            with self.assertRaises(Exception):
                with database.get_connection() as conn:
                    conn.execute("SELECT * FROM nonexistent_table_xyz")
            # Database should still be functional after rollback
            stats = database.get_statistics()
            self.assertIsNotNone(stats)


if __name__ == "__main__":
    unittest.main()
