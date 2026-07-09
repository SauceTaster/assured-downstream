from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.recon import inspect_repository
from assured_downstream.release_profile import plan_release_profile


class ReleaseProfileTests(unittest.TestCase):
    def test_plans_python_release_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project]\nname = 'demo-package'\n",
                encoding="utf-8",
            )
            report = inspect_repository(root)
            profile = plan_release_profile(report)

        self.assertEqual(profile["status"], "draft-human-review-required")
        self.assertEqual(profile["project"]["name"], "demo-package")
        self.assertEqual(profile["project"]["language_family"], "python")
        self.assertIn("actions/attest", profile["release"]["required_actions"])
        self.assertIn("dist/*.whl", profile["release"]["artifact_paths"])

    def test_plans_go_release_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text("module github.com/example/tool\n", encoding="utf-8")
            (root / "main.go").write_text("package main\n", encoding="utf-8")
            report = inspect_repository(root)
            profile = plan_release_profile(report)

        self.assertEqual(profile["project"]["name"], "tool")
        self.assertEqual(profile["project"]["language_family"], "go")
        self.assertIn("go build", "\n".join(profile["release"]["build_commands"]))


if __name__ == "__main__":
    unittest.main()

