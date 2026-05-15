import ast
import os
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class StaticHardeningTests(unittest.TestCase):
    def read_source(self, relative_path):
        with open(os.path.join(ROOT_DIR, relative_path), "r", encoding="utf-8") as f:
            return f.read()

    def test_start_analysis_launches_worker_thread(self):
        source = self.read_source(os.path.join("app", "main.py"))
        tree = ast.parse(source)
        start_analysis = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "start_analysis"
        )

        calls = [
            node for node in ast.walk(start_analysis)
            if isinstance(node, ast.Call)
        ]
        creates_thread = any(
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "Thread"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "threading"
            for call in calls
        )
        starts_thread = any(
            isinstance(call.func, ast.Attribute) and call.func.attr == "start"
            for call in calls
        )

        self.assertTrue(creates_thread)
        self.assertTrue(starts_thread)

    def test_main_uses_named_threshold_constant(self):
        source = self.read_source(os.path.join("app", "main.py"))

        self.assertIn("APP_DETECTION_THRESHOLD = 0.25", source)
        self.assertIn("is_ransomware = composite >= APP_DETECTION_THRESHOLD", source)

    def test_runner_uses_vm_analysis_wording(self):
        source = self.read_source(os.path.join("app", "process_supervisor.py"))

        self.assertIn("VM analysis runner", source)
        self.assertNotIn("restricted sandbox environment", source)


if __name__ == "__main__":
    unittest.main()
