from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.cli import (
    build_parser,
    command_create_project_packet,
    select_fork_plan_entry,
)


class CliTests(unittest.TestCase):
    def test_agent_run_parser_defaults_to_luna_advisory_mode(self) -> None:
        args = build_parser().parse_args(
            [
                "agent-run",
                "--seed",
                "awesome.md",
                "--org",
                "assured-oss",
                "--run-dir",
                "runs/intake-001",
            ]
        )

        self.assertEqual(args.codex_mode, "advisory")
        self.assertEqual(args.codex_profile, "assured-downstream-luna")
        self.assertEqual(args.codex_timeout, 90)
        self.assertFalse(args.enrich)
        self.assertEqual(args.token_env, "GITHUB_TOKEN")

    def test_agent_run_parser_accepts_personal_prefixed_target(self) -> None:
        args = build_parser().parse_args(
            [
                "agent-run",
                "--seed",
                "awesome.md",
                "--user",
                "SauceTaster",
                "--name-prefix",
                "assured-",
                "--run-dir",
                "runs/intake-001",
            ]
        )

        self.assertIsNone(args.org)
        self.assertEqual(args.target_user, "SauceTaster")
        self.assertEqual(args.name_prefix, "assured-")

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

    def test_self_test_parser_defaults_to_all_ecosystems(self) -> None:
        args = build_parser().parse_args(
            [
                "self-test",
                "--output-dir",
                "runs/self-test",
            ]
        )

        self.assertIsNone(args.ecosystem)
        self.assertEqual(args.output_dir, Path("runs/self-test"))

    def test_checkout_run_parser_keeps_sync_execution_explicit(self) -> None:
        args = build_parser().parse_args(
            [
                "checkout-run",
                "--fork-plan",
                "fork-plan.json",
                "--state",
                "state.json",
                "--workspace",
                "worktrees",
                "--run-dir",
                "runs/checkout-001",
            ]
        )

        self.assertFalse(args.execute_sync)
        self.assertEqual(args.target, "Attested")

    def test_patch_run_parser_keeps_both_mutations_explicit(self) -> None:
        args = build_parser().parse_args(
            [
                "patch-run",
                "--analysis-index",
                "analysis-index.json",
                "--pins",
                "pins.json",
                "--tooling-policy",
                "policies/approved-tooling.json",
                "--approval",
                "approval.json",
                "--workspace",
                "worktrees",
                "--run-dir",
                "runs/patch-001",
            ]
        )

        self.assertFalse(args.execute_patch)
        self.assertFalse(args.execute_publish)

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

    def test_create_project_packet_command_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fork_plan = root / "fork-plan.json"
            overlay_plan = root / "overlay-plan.json"
            output = root / "project-publication.json"
            markdown = root / "PROJECT.md"
            fork_plan.write_text(
                json.dumps(
                    {
                        "forks": [
                            {
                                "source_full_name": "owner/project",
                                "target_full_name": "assured-oss/project",
                                "metadata": {"default_branch": "main"},
                                "branch_model": {"secure_default": "secure/<default>"},
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
                    "create-project-packet",
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

            code = command_create_project_packet(args)

            self.assertEqual(code, 0)
            packet = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(packet["status"], "passive-publication-ready")
            self.assertFalse(packet["publication"]["outbound_contact"])
            self.assertIn("git fetch", markdown.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
