import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT_DIR, "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

# Import behavior_logger BEFORE patch.dict so the same module object is used
# by both main.py (imported inside the patch) and the test assertions.
import behavior_logger  # noqa: E402

# Import main with heavy/GUI deps mocked so module-level code doesn't crash.
# patch.dict restores sys.modules after the block; main's internal bindings
# already resolved to the mocks, so subsequent calls work correctly.
sys.modules.pop("main", None)
with patch.dict(sys.modules, {
    "tkinter": MagicMock(),
    "tkinter.filedialog": MagicMock(),
    "tkinter.messagebox": MagicMock(),
    "tkinter.ttk": MagicMock(),
    "tensorflow": MagicMock(),
    "tensorflow.keras": MagicMock(),
    "tensorflow.keras.models": MagicMock(),
    "tensorflow.keras.preprocessing": MagicMock(),
    "tensorflow.keras.preprocessing.sequence": MagicMock(),
    "process_supervisor": MagicMock(),
}):
    import main  # noqa: E402

import pandas as pd


def _make_valid_pe(size=2048):
    buf = bytearray(size)
    buf[0:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_offset)
    buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    return bytes(buf)


class TestIsLegitimateInstaller(unittest.TestCase):
    def test_chrome_installer(self):
        ok, name = main.is_legitimate_installer("ChromeSetup.exe")
        self.assertTrue(ok)
        self.assertEqual(name, "chrome")

    def test_firefox_installer(self):
        ok, _ = main.is_legitimate_installer("FirefoxSetup102.exe")
        self.assertTrue(ok)

    def test_vlc_installer(self):
        ok, name = main.is_legitimate_installer("vlc-3.0.18-win64.exe")
        self.assertTrue(ok)
        self.assertEqual(name, "vlc")

    def test_7zip_installer(self):
        ok, _ = main.is_legitimate_installer("7z2301-x64.exe")
        self.assertTrue(ok)

    def test_git_installer(self):
        ok, name = main.is_legitimate_installer("Git-2.43.0-64-bit.exe")
        self.assertTrue(ok)
        self.assertEqual(name, "git")

    def test_python_installer(self):
        ok, _ = main.is_legitimate_installer("python-3.12.0-amd64.exe")
        self.assertTrue(ok)

    def test_discord_installer(self):
        ok, _ = main.is_legitimate_installer("DiscordSetup.exe")
        self.assertTrue(ok)

    def test_vscode_installer(self):
        ok, _ = main.is_legitimate_installer("VSCodeSetup-x64-1.85.exe")
        self.assertTrue(ok)

    def test_unknown_binary_not_whitelisted(self):
        ok, name = main.is_legitimate_installer("suspicious_payload.exe")
        self.assertFalse(ok)
        self.assertIsNone(name)

    def test_case_insensitive_match(self):
        ok, _ = main.is_legitimate_installer("CHROMESETUP.EXE")
        self.assertTrue(ok)

    def test_steam_installer(self):
        ok, name = main.is_legitimate_installer("SteamSetup.exe")
        self.assertTrue(ok)
        self.assertEqual(name, "steam")

    def test_spotify_installer(self):
        ok, _ = main.is_legitimate_installer("SpotifySetup.exe")
        self.assertTrue(ok)

    def test_zoom_installer(self):
        ok, _ = main.is_legitimate_installer("ZoomInstaller.exe")
        self.assertTrue(ok)

    def test_random_exe_not_whitelisted(self):
        ok, name = main.is_legitimate_installer("update_v2.exe")
        self.assertFalse(ok)
        self.assertIsNone(name)


class TestValidatePeFile(unittest.TestCase):
    def _write_temp(self, content):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        f.write(content)
        f.close()
        return f.name

    def test_valid_pe_accepted(self):
        path = self._write_temp(_make_valid_pe())
        try:
            ok, msg = main.validate_pe_file(path)
            self.assertTrue(ok)
            self.assertEqual(msg, "Valid")
        finally:
            os.unlink(path)

    def test_nonexistent_file_rejected(self):
        ok, msg = main.validate_pe_file("/nonexistent/path/nope.exe")
        self.assertFalse(ok)
        self.assertIn("does not exist", msg)

    def test_file_too_small_rejected(self):
        path = self._write_temp(b"MZ" + b"\x00" * 100)
        try:
            ok, msg = main.validate_pe_file(path)
            self.assertFalse(ok)
            self.assertIn("too small", msg)
        finally:
            os.unlink(path)

    def test_missing_mz_header_rejected(self):
        path = self._write_temp(b"NZ" + b"\x00" * 2048)
        try:
            ok, msg = main.validate_pe_file(path)
            self.assertFalse(ok)
            self.assertIn("MZ header", msg)
        finally:
            os.unlink(path)

    def test_invalid_pe_signature_rejected(self):
        buf = bytearray(2048)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, 0x80)
        buf[0x80:0x84] = b"XX\x00\x00"
        path = self._write_temp(bytes(buf))
        try:
            ok, msg = main.validate_pe_file(path)
            self.assertFalse(ok)
        finally:
            os.unlink(path)

    def test_file_too_large_rejected(self):
        with patch("main.os.path.exists", return_value=True), \
             patch("main.os.path.getsize", return_value=600 * 1024 * 1024):
            ok, msg = main.validate_pe_file("fake.exe")
        self.assertFalse(ok)
        self.assertIn("too large", msg)

    def test_invalid_pe_offset_rejected(self):
        buf = bytearray(2048)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, 9999)  # offset beyond file
        path = self._write_temp(bytes(buf))
        try:
            ok, msg = main.validate_pe_file(path)
            self.assertFalse(ok)
        finally:
            os.unlink(path)


class TestComputeThreatScore(unittest.TestCase):
    def setUp(self):
        behavior_logger.streaming_risk_score = 0.0

    def _early(self, window=None, score=None):
        return {"earliest_alert_window": window, "earliest_alert_score": score}

    def _df(self, events):
        return pd.DataFrame({"event": events})

    def test_zero_signals_gives_low_level(self):
        score, level, _, _ = main.compute_threat_score(0.0, self._early(), self._df([]), [])
        self.assertEqual(level, "LOW")
        self.assertAlmostEqual(score, 0.0)

    def test_ml_only_signal(self):
        # Provide 50+ raw events so ML signal is not suppressed
        events = ["NtCreateFile"] * 50
        score, _, signals, _ = main.compute_threat_score(1.0, self._early(), self._df([]), events)
        self.assertAlmostEqual(signals["ml_signal"], 1.0)
        self.assertAlmostEqual(score, 0.30, places=5)

    def test_canary_violation_forces_95_floor(self):
        score, level, _, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["CanaryViolation"]), []
        )
        self.assertGreaterEqual(score, 0.95)
        self.assertEqual(level, "CRITICAL")

    def test_shadow_delete_forces_95_floor(self):
        score, level, _, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["ShadowCopyDelete"]), []
        )
        self.assertGreaterEqual(score, 0.95)

    def test_early_termination_forces_80_floor(self):
        score, _, _, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["EarlyTermination"]), []
        )
        self.assertGreaterEqual(score, 0.80)

    def test_rapid_writes_increase_score(self):
        s_none, _, _, _ = main.compute_threat_score(0.0, self._early(), self._df([]), [])
        s_rapid, _, _, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["RapidFileWrite"] * 5), []
        )
        self.assertGreater(s_rapid, s_none)

    def test_high_entropy_signal(self):
        s_none, _, _, _ = main.compute_threat_score(0.0, self._early(), self._df([]), [])
        s_entr, _, _, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["HighEntropyFile", "HighEntropyFile"]), []
        )
        self.assertGreater(s_entr, s_none)

    def test_early_window_gte_20_adds_signal(self):
        s_no, _, _, _ = main.compute_threat_score(0.0, self._early(), self._df([]), [])
        s_ew, _, _, _ = main.compute_threat_score(
            0.0, self._early(window=25, score=0.9), self._df([]), []
        )
        self.assertGreater(s_ew, s_no)

    def test_early_window_10_to_19_half_weight(self):
        _, _, signals, _ = main.compute_threat_score(
            0.0, self._early(window=15, score=1.0), self._df([]), []
        )
        self.assertAlmostEqual(signals["early_signal"], 0.5)

    def test_early_window_lt_10_ignored(self):
        _, _, signals, _ = main.compute_threat_score(
            0.0, self._early(window=5, score=1.0), self._df([]), []
        )
        self.assertAlmostEqual(signals["early_signal"], 0.0)

    def test_streaming_risk_above_threshold_boosts(self):
        behavior_logger.streaming_risk_score = 0.8
        score, _, _, _ = main.compute_threat_score(0.0, self._early(), self._df([]), [])
        self.assertGreaterEqual(score, 0.8 * 0.9)

    def test_streaming_risk_below_threshold_ignored(self):
        behavior_logger.streaming_risk_score = 0.3
        score, _, _, _ = main.compute_threat_score(0.0, self._early(), self._df([]), [])
        self.assertLess(score, 0.3 * 0.9)

    def test_threat_level_medium_from_ml_only(self):
        # ml=1.0 contributes weight 0.30 → score=0.30, which is MEDIUM (0.25–0.39)
        events = ["NtCreateFile"] * 50
        score, level, _, _ = main.compute_threat_score(1.0, self._early(), self._df([]), events)
        self.assertAlmostEqual(score, 0.30, places=5)
        self.assertEqual(level, "MEDIUM")

    def test_threat_level_critical_with_multiple_signals(self):
        # canary violation alone forces composite >= 0.95 → CRITICAL
        _, level, _, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["CanaryViolation"]), []
        )
        self.assertEqual(level, "CRITICAL")

    def test_metrics_write_ops_counted(self):
        _, _, _, metrics = main.compute_threat_score(
            0.0, self._early(), self._df(["WriteFile", "WriteFile", "ReadFile"]), []
        )
        self.assertEqual(metrics["write_ops"], 2)

    def test_metrics_rapid_writes_counted(self):
        _, _, _, metrics = main.compute_threat_score(
            0.0, self._early(), self._df(["RapidFileWrite"] * 3), []
        )
        self.assertEqual(metrics["rapid_writes"], 3)

    def test_metrics_shadow_deletes_counted(self):
        _, _, _, metrics = main.compute_threat_score(
            0.0, self._early(), self._df(["ShadowCopyDelete"]), []
        )
        self.assertEqual(metrics["shadow_deletes"], 1)

    def test_network_signal_contributes_to_score(self):
        df = self._df(["NetworkConnect", "NetworkConnect", "NetworkConnect"])
        composite, _, signals, _ = main.compute_threat_score(0.0, self._early(), df, [])
        self.assertGreater(composite, 0.0)
        self.assertIn("network_signal", signals)
        self.assertAlmostEqual(signals["network_signal"], 1.0)

    def test_network_signal_zero_when_no_connections(self):
        _, _, signals, _ = main.compute_threat_score(0.0, self._early(), self._df(["WriteFile"]), [])
        self.assertAlmostEqual(signals["network_signal"], 0.0)

    def test_network_signal_partial(self):
        _, _, signals, _ = main.compute_threat_score(0.0, self._early(), self._df(["NetworkConnect"]), [])
        self.assertAlmostEqual(signals["network_signal"], round(1 / 3.0, 5), places=4)

    def test_child_signal_scales_with_count(self):
        _, _, signals_1, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["SuspiciousChild"]), []
        )
        _, _, signals_2, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["SuspiciousChild", "SuspiciousChild"]), []
        )
        self.assertGreater(signals_2["child_signal"], signals_1["child_signal"])

    def test_all_signals_keys_present(self):
        _, _, signals, _ = main.compute_threat_score(0.0, self._early(), self._df([]), [])
        for key in ("ml_signal", "early_signal", "rapid_signal", "entropy_signal",
                    "canary_signal", "shadow_signal", "network_signal", "child_signal"):
            self.assertIn(key, signals)

    def test_rapid_writes_single_no_signal(self):
        # Only 1 rapid write — signal = max(0, 1-1)/3 = 0
        _, _, signals, _ = main.compute_threat_score(
            0.0, self._early(), self._df(["RapidFileWrite"]), []
        )
        self.assertAlmostEqual(signals["rapid_signal"], 0.0)


class TestKillProcessTree(unittest.TestCase):
    def _make_proc(self, exe, pid):
        p = MagicMock()
        p.info = {"exe": exe, "pid": pid}
        p.pid = pid
        p.children.return_value = []
        return p

    def test_empty_when_no_match(self):
        with patch("main.psutil.process_iter", return_value=[]):
            result = main.kill_process_tree("/evil.exe")
        self.assertEqual(result, [])

    def test_kills_matching_process(self):
        proc = self._make_proc("/evil.exe", 1234)
        with patch("main.psutil.process_iter", return_value=[proc]), \
             patch("main.subprocess.run"), \
             patch("main.shutil.which", return_value="taskkill"):
            result = main.kill_process_tree("/evil.exe")
        proc.suspend.assert_called()
        proc.kill.assert_called()
        self.assertIn(1234, result)

    def test_includes_children(self):
        child = MagicMock()
        child.pid = 5678
        proc = self._make_proc("/evil.exe", 1234)
        proc.children.return_value = [child]
        with patch("main.psutil.process_iter", return_value=[proc]), \
             patch("main.subprocess.run"), \
             patch("main.shutil.which", return_value="taskkill"):
            result = main.kill_process_tree("/evil.exe")
        child.suspend.assert_called()
        child.kill.assert_called()

    def test_skips_process_with_no_exe(self):
        proc = self._make_proc(None, 9999)
        with patch("main.psutil.process_iter", return_value=[proc]):
            result = main.kill_process_tree("/evil.exe")
        self.assertEqual(result, [])

    def test_returns_empty_on_no_such_process(self):
        import psutil as _psutil
        proc = MagicMock()
        proc.info = {"exe": "/evil.exe", "pid": 1111}
        proc.pid = 1111
        proc.children.side_effect = _psutil.NoSuchProcess(1111)
        with patch("main.psutil.process_iter", return_value=[proc]), \
             patch("main.subprocess.run"), \
             patch("main.shutil.which", return_value="taskkill"):
            result = main.kill_process_tree("/evil.exe")
        self.assertIsInstance(result, list)

    def test_taskkill_called_when_procs_found(self):
        proc = self._make_proc("/evil.exe", 2222)
        with patch("main.psutil.process_iter", return_value=[proc]), \
             patch("main.subprocess.run") as mock_run, \
             patch("main.shutil.which", return_value="taskkill"):
            main.kill_process_tree("/evil.exe")
        mock_run.assert_called()


class TestQuarantineFile(unittest.TestCase):
    def test_moves_file_successfully(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "evil.exe")
            with open(src, "wb") as f:
                f.write(b"evil content")
            with patch("main.PARENT_DIR", tmpdir):
                ok, qpath = main.quarantine_file(src, "evil.exe")
        self.assertTrue(ok)
        self.assertIsNotNone(qpath)
        self.assertFalse(os.path.exists(src))

    def test_returns_false_when_file_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("main.PARENT_DIR", tmpdir):
                ok, qpath = main.quarantine_file("/nonexistent/path/evil.exe", "evil.exe")
        self.assertFalse(ok)
        self.assertIsNone(qpath)

    def test_returns_quarantine_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "malware.exe")
            with open(src, "wb") as f:
                f.write(b"x")
            with patch("main.PARENT_DIR", tmpdir):
                ok, qpath = main.quarantine_file(src, "malware.exe")
        self.assertTrue(ok)
        self.assertIn("malware.exe", qpath)


class TestSetTextWidget(unittest.TestCase):
    def test_sets_content_and_disables(self):
        widget = MagicMock()
        main.set_text_widget(widget, "scan complete")
        widget.config.assert_any_call(state="normal")
        widget.delete.assert_called_with("1.0", "end")
        widget.insert.assert_called_with("end", "scan complete")
        widget.config.assert_called_with(state="disabled")

    def test_empty_content(self):
        widget = MagicMock()
        main.set_text_widget(widget, "")
        widget.insert.assert_called_with("end", "")


class TestSetProgress(unittest.TestCase):
    def test_does_not_raise(self):
        main.set_progress("Scanning...", 50, "50% - Running")

    def test_different_values(self):
        main.set_progress("Done", 100, "100% - Complete")


if __name__ == "__main__":
    unittest.main()
