import os
import sys
import unittest
from unittest.mock import MagicMock, patch, call
import psutil

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT_DIR, "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import process_supervisor


class RunInSandboxTests(unittest.TestCase):
    def test_raises_file_not_found_for_missing_exe(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            process_supervisor.run_in_sandbox("/nonexistent/path/evil.exe")
        self.assertIn("not found", str(ctx.exception))

    def test_raises_file_not_found_for_empty_path(self):
        with self.assertRaises(FileNotFoundError):
            process_supervisor.run_in_sandbox("/no/such/file/ransomware.exe")


class ForceKillTests(unittest.TestCase):
    def _make_mock_process(self, pid=1234):
        proc = MagicMock()
        proc.pid = pid
        return proc

    def test_kills_process_when_psutil_process_not_found(self):
        mock_proc = self._make_mock_process()
        with patch("process_supervisor.psutil.Process",
                   side_effect=psutil.NoSuchProcess(1234)):
            # Should not raise — NoSuchProcess is caught
            process_supervisor._force_kill(mock_proc)

        mock_proc.kill.assert_called()

    def test_kills_children_via_psutil(self):
        mock_child = MagicMock()
        mock_child.pid = 5678
        mock_parent_psutil = MagicMock()
        mock_parent_psutil.children.return_value = [mock_child]

        mock_proc = self._make_mock_process()

        with patch("process_supervisor.psutil.Process", return_value=mock_parent_psutil), \
             patch("process_supervisor.subprocess.run"):
            process_supervisor._force_kill(mock_proc)

        mock_child.kill.assert_called()
        mock_child.suspend.assert_not_called()

    def test_taskkill_called_first_with_correct_args(self):
        call_order = []
        mock_proc = self._make_mock_process(pid=9999)

        mock_psutil = MagicMock()
        mock_psutil.children.return_value = []

        def _record_run(args, **kwargs):
            call_order.append(("taskkill", args))
            return MagicMock()

        def _record_psutil(pid):
            call_order.append(("psutil", pid))
            return mock_psutil

        with patch("process_supervisor.psutil.Process", side_effect=_record_psutil), \
             patch("process_supervisor.subprocess.run", side_effect=_record_run), \
             patch("process_supervisor.shutil.which", return_value=r"C:\Windows\System32\taskkill.exe"):
            process_supervisor._force_kill(mock_proc)

        # taskkill must come before psutil
        taskkill_idx = next(i for i, (k, _) in enumerate(call_order) if k == "taskkill")
        psutil_idx = next(i for i, (k, _) in enumerate(call_order) if k == "psutil")
        self.assertLess(taskkill_idx, psutil_idx)

        # verify /F /T /PID 9999 in taskkill args
        tk_args = call_order[taskkill_idx][1]
        self.assertIn("/F", tk_args)
        self.assertIn("/T", tk_args)
        self.assertIn("9999", tk_args)

    def test_force_kill_survives_all_exceptions(self):
        mock_proc = self._make_mock_process()
        # Everything raises — _force_kill must not propagate
        with patch("process_supervisor.psutil.Process", side_effect=Exception("boom")), \
             patch("process_supervisor.subprocess.run", side_effect=Exception("boom2")):
            mock_proc.kill.side_effect = Exception("boom3")
            # Should not raise
            try:
                process_supervisor._force_kill(mock_proc)
            except Exception as e:
                self.fail(f"_force_kill raised unexpectedly: {e}")


if __name__ == "__main__":
    unittest.main()
