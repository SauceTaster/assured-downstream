from __future__ import annotations

import unittest
from pathlib import Path

from assured_downstream.behavior import compare_behavior_reports, normalize_trace


class BehaviorTests(unittest.TestCase):
    def test_normalizes_trace_without_pid_noise(self) -> None:
        trace_a = {
            "events": [
                {"kind": "process", "pid": 1, "ppid": 0, "exe": "/workspace/go", "argv": ["go", "build"]},
                {"kind": "file", "op": "write", "path": "/workspace/dist/tool"},
                {"kind": "network", "host": "proxy.golang.org", "port": 443},
                {"kind": "syscall", "name": "ptrace"},
            ]
        }
        trace_b = {
            "events": [
                {"kind": "process", "pid": 99, "ppid": 4, "exe": "/workspace/go", "argv": ["go", "build"]},
                {"kind": "file", "op": "write", "path": "/workspace/dist/tool"},
                {"kind": "network", "host": "proxy.golang.org", "port": 443},
                {"kind": "syscall", "name": "ptrace"},
            ]
        }

        report_a = normalize_trace(trace_a, workspace_root=Path("/workspace"))
        report_b = normalize_trace(trace_b, workspace_root=Path("/workspace"))

        self.assertEqual(report_a["digest"], report_b["digest"])
        self.assertEqual(report_a["summary"]["syscalls"], 1)

    def test_compares_behavior_difference(self) -> None:
        left = normalize_trace({"events": [{"kind": "network", "host": "example.com"}]})
        right = normalize_trace({"events": [{"kind": "network", "host": "evil.example"}]})

        result = compare_behavior_reports(left, right)

        self.assertFalse(result["ok"])
        self.assertIn("network", result["differences"])

    def test_normalizes_known_python_build_temp_paths(self) -> None:
        left = {
            "events": [
                {
                    "kind": "file",
                    "operation": "write",
                    "outcome": "success",
                    "count": 1,
                    "path": (
                        "/tmp/build-via-sdist-5o3g4k_9/project-1.0/"
                        "package.egg-info/tmp3kqdcdbb"
                    ),
                },
                {
                    "kind": "file",
                    "operation": "write",
                    "outcome": "success",
                    "count": 1,
                    "path": "/workspace/output/dist/.tmp-5yfn3ix9/project.whl",
                },
                {
                    "kind": "file",
                    "operation": "access",
                    "outcome": "success",
                    "count": 1,
                    "path": (
                        "/usr/local/lib/python3.12/__pycache__/"
                        "contextvars.cpython-312.pyc.139920542125840"
                    ),
                },
            ]
        }
        right = {
            "events": [
                {
                    "kind": "file",
                    "operation": "write",
                    "outcome": "success",
                    "count": 1,
                    "path": (
                        "/tmp/build-via-sdist-z9_a1b2c/project-1.0/"
                        "package.egg-info/tmpd1ism5rw"
                    ),
                },
                {
                    "kind": "file",
                    "operation": "write",
                    "outcome": "success",
                    "count": 1,
                    "path": "/workspace/output/dist/.tmp-da1c_r81/project.whl",
                },
                {
                    "kind": "file",
                    "operation": "access",
                    "outcome": "success",
                    "count": 1,
                    "path": (
                        "/usr/local/lib/python3.12/__pycache__/"
                        "contextvars.cpython-312.pyc.140000000000001"
                    ),
                },
            ]
        }

        left_report = normalize_trace(left, workspace_root=Path("/workspace"))
        right_report = normalize_trace(right, workspace_root=Path("/workspace"))

        self.assertEqual(left_report["schema_version"], 2)
        self.assertEqual(left_report["digest"], right_report["digest"])

    def test_preserves_event_count_and_outcome(self) -> None:
        baseline = normalize_trace(
            {
                "events": [
                    {
                        "kind": "syscall",
                        "name": "connect",
                        "outcome": "failed",
                        "count": 4,
                    }
                ]
            }
        )
        changed_count = normalize_trace(
            {
                "events": [
                    {
                        "kind": "syscall",
                        "name": "connect",
                        "outcome": "failed",
                        "count": 5,
                    }
                ]
            }
        )
        changed_outcome = normalize_trace(
            {
                "events": [
                    {
                        "kind": "syscall",
                        "name": "connect",
                        "outcome": "success",
                        "count": 4,
                    }
                ]
            }
        )

        self.assertNotEqual(baseline["digest"], changed_count["digest"])
        self.assertNotEqual(baseline["digest"], changed_outcome["digest"])

    def test_workspace_replacement_is_path_boundary_aware(self) -> None:
        report = normalize_trace(
            {
                "events": [
                    {
                        "kind": "file",
                        "path": "/workspace-other/secret",
                    }
                ]
            },
            workspace_root=Path("/workspace"),
        )

        self.assertIn("/workspace-other/secret", report["normalized"]["files"][0])
        self.assertNotIn("$WORKSPACE-other", report["normalized"]["files"][0])


if __name__ == "__main__":
    unittest.main()
