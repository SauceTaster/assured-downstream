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


if __name__ == "__main__":
    unittest.main()

