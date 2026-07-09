from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.cli import (
    build_parser,
    command_create_liaison_packet,
    select_fork_plan_entry,
)


class CliTests(unittest.TestCase):
    def test_pilot_parser_accepts_selection_policy_args(self) -> None:
        args = build_parser().parse_args(
            [
                "pilot",
                "--seed",
                "awesome.md",
                "--org",
                "assured-oss",
                "--run-dir",
                "runs/pilot-001",
                "--allowlist",
                "allow.json",
                "--suppress",
                "suppress.json",
                "--run-index",
                "runs/index.json",
                "--run-id",
                "pilot-001",
            ]
        )

        self.assertEqual(args.allowlist, Path("allow.json"))
        self.assertEqual(args.suppression, Path("suppress.json"))
        self.assertEqual(args.run_index, Path("runs/index.json"))
        self.assertEqual(args.run_id, "pilot-001")

    def test_select_fork_plan_entry_requires_selector_for_multiple_forks(self) -> None:
        fork_plan = {
            "forks": [
                {"source_full_name": "owner/a", "target_full_name": "org/a"},
                {"source_full_name": "owner/b", "target_full_name": "org/b"},
            ]
        }

        with self.assertRaises(ValueError):
            select_fork_plan_entry(fork_plan)

        selected = select_fork_plan_entry(fork_plan, source="owner/b")
        self.assertEqual(selected["target_full_name"], "org/b")

    def test_create_liaison_packet_command_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fork_plan = root / "fork-plan.json"
            overlay_plan = root / "overlay-plan.json"
            output = root / "liaison.json"
            markdown = root / "LIAISON.md"
            fork_plan.write_text(
                json.dumps(
                    {
                        "forks": [
                            {
                                "source_full_name": "owner/project",
                                "target_full_name": "assured-oss/project",
                                "metadata": {"default_branch": "main"},
                                "branch_model": {"proposal_prefix": "proposal/"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            overlay_plan.write_text(
                json.dumps(
                    {
                        "proposed_changes": [
                            {
                                "id": "dependabot-baseline",
                                "paths": [".github/dependabot.yml"],
                                "rationale": "Add dependency update monitoring.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            args = build_parser().parse_args(
                [
                    "create-liaison-packet",
                    "--fork-plan",
                    str(fork_plan),
                    "--overlay-plan",
                    str(overlay_plan),
                    "--output",
                    str(output),
                    "--markdown-output",
                    str(markdown),
                ]
            )

            code = command_create_liaison_packet(args)

            self.assertEqual(code, 0)
            packet = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(packet["status"], "draft-local-only")
            self.assertIn("git fetch", markdown.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
