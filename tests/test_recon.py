from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.recon import inspect_repository
from assured_downstream.workflow_yaml import parse_workflow_yaml


FIXTURES = Path(__file__).parent / "fixtures" / "recon"


class ReconTests(unittest.TestCase):
    def test_workflow_yaml_parser_handles_common_workflow_shapes(self) -> None:
        parsed = parse_workflow_yaml(
            """
            on: [push, workflow_dispatch]
            permissions: {contents: read, id-token: write}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - name: Build
                    run: |
                      mkdir -p dist
                      go build -o dist/tool .
                  - uses: actions/upload-artifact@v4
                    with:
                      name: binary
                      path: dist/tool
            """
        )

        self.assertEqual(parsed["on"], ["push", "workflow_dispatch"])
        self.assertEqual(parsed["permissions"]["id-token"], "write")
        steps = parsed["jobs"]["build"]["steps"]
        self.assertIn("go build", steps[0]["run"])
        self.assertEqual(steps[1]["with"]["path"], "dist/tool")

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
        workflow = report["ci"]["workflows"][0]
        self.assertTrue(workflow["parsed"])
        self.assertEqual(workflow["triggers"][0]["event"], "pull_request_target")
        self.assertEqual(workflow["permissions"]["mode"], "write-all")
        self.assertTrue(workflow["uses_pull_request_target"])
        self.assertEqual(workflow["jobs"][0]["steps"][0]["uses"]["name"], "actions/checkout")
        self.assertTrue(report["release_signals"]["uploads_github_release"])
        self.assertGreaterEqual(len(report["risk_signals"]), 3)

    def test_first_lane_fixtures_produce_structural_workflow_recon(self) -> None:
        cases = {
            "go": {
                "language": "Go",
                "package_manager": "go",
                "action": "softprops/action-gh-release",
                "artifact_path": "dist/go-tool",
                "release_event": "push",
                "release_signal": "uploads_github_release",
            },
            "rust": {
                "language": "Rust",
                "package_manager": "cargo",
                "action": "actions/checkout",
                "artifact_path": "target/release/rust-tool",
                "release_event": "push",
                "release_signal": "uploads_github_release",
            },
            "python": {
                "language": "Python",
                "package_manager": "python",
                "action": "pypa/gh-action-pypi-publish",
                "artifact_path": "dist/*.whl",
                "release_event": "release",
                "release_signal": "publishes_pypi",
            },
        }

        for fixture, expected in cases.items():
            with self.subTest(fixture=fixture):
                report = inspect_repository(FIXTURES / fixture)
                workflows = report["ci"]["workflows"]
                action_names = {
                    action["name"]
                    for workflow in workflows
                    for action in workflow["actions"]
                }
                package_managers = {
                    entry["name"]
                    for entry in report["package_managers"]
                }
                artifact_paths = {
                    path
                    for candidate in report["artifact_candidates"]
                    for path in candidate["paths"]
                }
                release_events = {
                    trigger["event"]
                    for trigger in report["release_triggers"]
                }

                self.assertIn(expected["language"], report["languages"])
                self.assertIn(expected["package_manager"], package_managers)
                self.assertTrue(all(workflow["parsed"] for workflow in workflows))
                self.assertIn(expected["action"], action_names)
                self.assertIn(expected["artifact_path"], artifact_paths)
                self.assertIn(expected["release_event"], release_events)
                self.assertTrue(report["release_signals"][expected["release_signal"]])

    def test_go_fixture_records_permissions_jobs_steps_and_artifact_candidates(self) -> None:
        report = inspect_repository(FIXTURES / "go")
        workflow = report["ci"]["workflows"][0]
        job = workflow["jobs"][0]

        self.assertEqual(workflow["permissions"]["scopes"]["id-token"], "write")
        self.assertEqual(job["id"], "build")
        self.assertEqual(job["permissions"]["scopes"]["contents"], "write")
        self.assertEqual(job["steps"][1]["uses"]["name"], "actions/setup-go")
        self.assertEqual(workflow["artifact_steps"][0]["kind"], "upload-artifact")
        self.assertEqual(report["artifact_candidates"][0]["paths"], ["dist/go-tool"])

    def test_malformed_workflow_reports_parse_error_and_fallback_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "bad.yml").write_text(
                """
                on:
                  push:
                    branches: [main
                permissions: write-all
                jobs:
                  build:
                    steps:
                      - uses: actions/checkout@v4
                """,
                encoding="utf-8",
            )

            report = inspect_repository(root)

        workflow = report["ci"]["workflows"][0]
        signals = [risk["signal"] for risk in report["risk_signals"]]
        self.assertFalse(workflow["parsed"])
        self.assertIn("unterminated flow sequence", workflow["parse_error"])
        self.assertEqual(workflow["actions"][0]["name"], "actions/checkout")
        self.assertTrue(any("could not be parsed" in signal for signal in signals))
        self.assertTrue(any("write-all" in signal for signal in signals))
        self.assertTrue(any("not pinned" in signal for signal in signals))


if __name__ == "__main__":
    unittest.main()
