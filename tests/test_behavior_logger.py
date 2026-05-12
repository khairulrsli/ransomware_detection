import os
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
