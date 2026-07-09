from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.recon import inspect_repository


class ReconTests(unittest.TestCase):
    def test_detects_repo_shape_and_workflow_risks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text("module example.com/project\n", encoding="utf-8")
            (root / "main.go").write_text("package main\n", encoding="utf-8")
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "release.yml").write_text(
                """
                on:
                  pull_request_target:
                permissions: write-all
                jobs:
                  build:
                    steps:
                      - uses: actions/checkout@v4
                      - uses: softprops/action-gh-release@v2
                """,
                encoding="utf-8",
            )

            report = inspect_repository(root)

        self.assertEqual(report["languages"], {"Go": 1})
        self.assertEqual(report["package_managers"][0]["name"], "go")
        self.assertEqual(report["ci"]["workflow_count"], 1)
        self.assertTrue(report["ci"]["workflows"][0]["uses_pull_request_target"])
        self.assertTrue(report["release_signals"]["uploads_github_release"])
        self.assertGreaterEqual(len(report["risk_signals"]), 3)


if __name__ == "__main__":
    unittest.main()

