"""
Threat Detection Database - Persistent history and statistics.
This version automatically creates/repairs missing tables, including analysis_history.
"""
import csv
import io
import os
import sqlite3
from contextlib import contextmanager

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(APP_DIR)
DB_PATH = os.path.join(PARENT_DIR, "threat_database.db")


class ThreatDatabase:
    def __init__(self):
        self.db_path = DB_PATH
        self.init_database()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_database(self):
        """Create missing database tables. Safe to call many times."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    filename TEXT NOT NULL,
                    file_path TEXT,
                    file_size INTEGER,
                    verdict TEXT NOT NULL,
                    confidence REAL,
                    ml_score REAL,
                    write_ops INTEGER DEFAULT 0,
                    rapid_writes INTEGER DEFAULT 0,
                    busy_loops INTEGER DEFAULT 0,
                    network_ops INTEGER DEFAULT 0,
                    action_taken TEXT,
                    details TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY,
                    total_scans INTEGER DEFAULT 0,
                    ransomware_detected INTEGER DEFAULT 0,
                    benign_detected INTEGER DEFAULT 0,
                    avg_confidence REAL DEFAULT 0,
                    last_update DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT UNIQUE NOT NULL,
                    rapid_write_threshold INTEGER DEFAULT 1,
                    write_ops_threshold INTEGER DEFAULT 3,
                    busy_loop_threshold INTEGER DEFAULT 1,
                    ml_score_threshold REAL DEFAULT 0.5,
                    enabled BOOLEAN DEFAULT 1
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    filename TEXT NOT NULL,
                    quarantine_path TEXT,
                    original_path TEXT,
                    threat_level TEXT,
                    recovery_attempted BOOLEAN DEFAULT 0
                )
            """)

            cursor.execute("SELECT COUNT(*) FROM statistics")
            if cursor.fetchone()[0] == 0:
                cursor.execute("""
                    INSERT INTO statistics
                    (id, total_scans, ransomware_detected, benign_detected, avg_confidence)
                    VALUES (1, 0, 0, 0, 0)
                """)

            cursor.execute("""
                INSERT OR IGNORE INTO threat_rules
                (rule_name, rapid_write_threshold, write_ops_threshold, busy_loop_threshold, ml_score_threshold, enabled)
                VALUES ('default', 1, 3, 1, 0.5, 1)
            """)

    def ensure_ready(self):
        """Repair schema before operations, useful when an old DB file exists."""
        self.init_database()

    def add_analysis(self, filename, verdict, confidence, ml_score, metrics, action, details=""):
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO analysis_history
                (filename, verdict, confidence, ml_score, write_ops, rapid_writes, busy_loops, network_ops, action_taken, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                filename,
                verdict,
                confidence,
                ml_score,
                metrics.get('write_ops', 0),
                metrics.get('rapid_writes', 0),
                metrics.get('busy_loops', 0),
                metrics.get('network_ops', 0),
                action,
                details,
            ))
        self.update_statistics(verdict, confidence)

    def update_statistics(self, verdict, confidence):
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            is_ransomware = str(verdict).upper().startswith("RANSOMWARE") or str(verdict).upper() == "MALICIOUS"
            if is_ransomware:
                cursor.execute("""
                    UPDATE statistics
                    SET total_scans = total_scans + 1,
                        ransomware_detected = ransomware_detected + 1,
                        last_update = CURRENT_TIMESTAMP
                    WHERE id = 1
                """)
            else:
                cursor.execute("""
                    UPDATE statistics
                    SET total_scans = total_scans + 1,
                        benign_detected = benign_detected + 1,
                        last_update = CURRENT_TIMESTAMP
                    WHERE id = 1
                """)

            cursor.execute("""
                UPDATE statistics
                SET avg_confidence = COALESCE((
                    SELECT AVG(confidence) FROM analysis_history WHERE confidence IS NOT NULL
                ), 0)
                WHERE id = 1
            """)

    def get_statistics(self):
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM statistics WHERE id = 1")
            row = cursor.fetchone()
            return dict(row) if row else {}

    def get_recent_analyses(self, limit=10):
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM analysis_history
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def add_quarantine(self, filename, quarantine_path, original_path, threat_level):
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quarantine_log (filename, quarantine_path, original_path, threat_level)
                VALUES (?, ?, ?, ?)
            """, (filename, quarantine_path, original_path, threat_level))

    def get_quarantine_list(self):
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_log ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    def delete_quarantine(self, quarantine_id):
        """Remove a quarantine record by its ID."""
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM quarantine_log WHERE id = ?", (quarantine_id,))

    def clear_all_data(self):
        """Clear all analysis history and quarantine records."""
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM analysis_history")
            cursor.execute("DELETE FROM quarantine_log")
            cursor.execute("""
                UPDATE statistics
                SET total_scans = 0,
                    ransomware_detected = 0,
                    benign_detected = 0,
                    avg_confidence = 0,
                    last_update = CURRENT_TIMESTAMP
                WHERE id = 1
            """)

    def export_analysis_report(self):
        self.ensure_ready()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM analysis_history ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            if not rows:
                return None

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([description[0] for description in cursor.description])
            for row in rows:
                writer.writerow(["" if val is None else val for val in row])
            return output.getvalue()


# Initialize database on import.
db = ThreatDatabase()
