import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT_DIR, "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import behavior_logger


class CanaryCleanupTests(unittest.TestCase):
    def test_cleanup_removes_only_canaries_created_by_logger(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            canaries, created = behavior_logger._deploy_canary_files([temp_dir])

            self.assertEqual(len(canaries), 3)
            self.assertEqual(len(created), 3)
            for path in created:
                self.assertTrue(os.path.exists(path))

            behavior_logger._cleanup_created_canaries(created)

            for path in created:
                self.assertFalse(os.path.exists(path))

    def test_cleanup_keeps_preexisting_canary_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            preexisting = os.path.join(temp_dir, ".~sysconfig.dat")
            with open(preexisting, "w") as f:
                f.write("keep me")

            canaries, created = behavior_logger._deploy_canary_files([temp_dir])

            self.assertIn(preexisting, canaries)
            self.assertNotIn(preexisting, created)

            behavior_logger._cleanup_created_canaries(created)

            self.assertTrue(os.path.exists(preexisting))
            with open(preexisting, "r") as f:
                self.assertEqual(f.read(), "keep me")


class FileEntropyTests(unittest.TestCase):
    def test_uniform_bytes_have_maximum_entropy(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # 256 distinct bytes → max entropy = 8.0
            f.write(bytes(range(256)))
            path = f.name
        try:
            entropy = behavior_logger._file_entropy(path)
            self.assertAlmostEqual(entropy, 8.0, places=5)
        finally:
            os.unlink(path)

    def test_single_repeated_byte_has_zero_entropy(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'\x00' * 1024)
            path = f.name
        try:
            entropy = behavior_logger._file_entropy(path)
            self.assertAlmostEqual(entropy, 0.0)
        finally:
            os.unlink(path)

    def test_empty_file_returns_zero(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            entropy = behavior_logger._file_entropy(path)
            self.assertEqual(entropy, 0.0)
        finally:
            os.unlink(path)

    def test_missing_file_returns_zero(self):
        entropy = behavior_logger._file_entropy("/nonexistent/path/file.bin")
        self.assertEqual(entropy, 0.0)

    def test_normal_text_has_low_entropy(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as f:
            f.write("hello world " * 100)
            path = f.name
        try:
            entropy = behavior_logger._file_entropy(path)
            self.assertLess(entropy, 4.0)
        finally:
            os.unlink(path)


class CanaryIntegrityTests(unittest.TestCase):
    def test_unmodified_canary_no_violations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            canaries, created = behavior_logger._deploy_canary_files([temp_dir])
            violations = behavior_logger._check_canary_integrity(canaries)
            behavior_logger._cleanup_created_canaries(created)
            self.assertEqual(violations, [])

    def test_deleted_canary_reported_as_deleted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            canaries, created = behavior_logger._deploy_canary_files([temp_dir])
            target = created[0]
            os.remove(target)

            violations = behavior_logger._check_canary_integrity(canaries)

            behavior_logger._cleanup_created_canaries(created)
            types = [v[0] for v in violations]
            self.assertIn("DELETED", types)

    def test_modified_canary_reported_as_modified(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp_dir:
            # Build canary dict manually to avoid Windows hidden-attribute write block
            target = os.path.join(temp_dir, "test_canary.dat")
            original_content = b"original"
            with open(target, 'wb') as f:
                f.write(original_content)
            original_hash = hashlib.sha256(original_content).hexdigest()
            canaries = {target: original_hash}

            # Modify the file
            with open(target, 'wb') as f:
                f.write(b"tampered content!")

            violations = behavior_logger._check_canary_integrity(canaries)
            types = [v[0] for v in violations]
            self.assertIn("MODIFIED", types)

    def test_empty_canaries_dict_returns_no_violations(self):
        violations = behavior_logger._check_canary_integrity({})
        self.assertEqual(violations, [])


class ShadowCopyCheckTests(unittest.TestCase):
    def test_returns_false_on_non_windows(self):
        with patch("behavior_logger.os.name", "posix"):
            result = behavior_logger._check_shadow_copies()
        self.assertFalse(result)

    def test_returns_false_when_no_suspicious_processes(self):
        mock_proc = MagicMock()
        mock_proc.info = {"name": "notepad.exe", "cmdline": ["notepad.exe"]}
        with patch("behavior_logger.os.name", "nt"), \
             patch("behavior_logger.psutil.process_iter", return_value=[mock_proc]):
            result = behavior_logger._check_shadow_copies()
        self.assertFalse(result)

    def test_returns_true_when_vssadmin_delete_running(self):
        mock_proc = MagicMock()
        mock_proc.info = {
            "name": "vssadmin.exe",
            "cmdline": ["vssadmin.exe", "delete", "shadows", "/all"]
        }
        with patch("behavior_logger.os.name", "nt"), \
             patch("behavior_logger.psutil.process_iter", return_value=[mock_proc]):
            result = behavior_logger._check_shadow_copies()
        self.assertTrue(result)

    def test_returns_true_when_wmic_shadowcopy_running(self):
        mock_proc = MagicMock()
        mock_proc.info = {
            "name": "wmic.exe",
            "cmdline": ["wmic.exe", "shadowcopy", "delete"]
        }
        with patch("behavior_logger.os.name", "nt"), \
             patch("behavior_logger.psutil.process_iter", return_value=[mock_proc]):
            result = behavior_logger._check_shadow_copies()
        self.assertTrue(result)


class DetectSuspiciousChildProcessesTests(unittest.TestCase):
    def test_returns_empty_when_no_children(self):
        mock_parent = MagicMock()
        mock_parent.children.return_value = []
        with patch("behavior_logger.psutil.Process", return_value=mock_parent):
            result = behavior_logger._detect_suspicious_child_processes(1234)
        self.assertEqual(result, [])

    def test_detects_cmd_as_suspicious_child(self):
        mock_child = MagicMock()
        mock_child.name.return_value = "cmd.exe"
        mock_parent = MagicMock()
        mock_parent.children.return_value = [mock_child]
        with patch("behavior_logger.psutil.Process", return_value=mock_parent):
            result = behavior_logger._detect_suspicious_child_processes(1234)
        self.assertIn("cmd.exe", result)

    def test_detects_powershell_as_suspicious_child(self):
        mock_child = MagicMock()
        mock_child.name.return_value = "powershell.exe"
        mock_parent = MagicMock()
        mock_parent.children.return_value = [mock_child]
        with patch("behavior_logger.psutil.Process", return_value=mock_parent):
            result = behavior_logger._detect_suspicious_child_processes(1234)
        self.assertIn("powershell.exe", result)

    def test_ignores_benign_child_processes(self):
        mock_child = MagicMock()
        mock_child.name.return_value = "notepad.exe"
        mock_parent = MagicMock()
        mock_parent.children.return_value = [mock_child]
        with patch("behavior_logger.psutil.Process", return_value=mock_parent):
            result = behavior_logger._detect_suspicious_child_processes(1234)
        self.assertEqual(result, [])

    def test_returns_empty_when_process_not_found(self):
        import psutil
        with patch("behavior_logger.psutil.Process", side_effect=psutil.NoSuchProcess(9999)):
            result = behavior_logger._detect_suspicious_child_processes(9999)
        self.assertEqual(result, [])

    def test_deploy_canary_skips_nonexistent_dir(self):
        canaries, created = behavior_logger._deploy_canary_files(["/path/that/does/not/exist/xyz"])
        self.assertEqual(canaries, {})
        self.assertEqual(created, [])


if __name__ == "__main__":
    unittest.main()
