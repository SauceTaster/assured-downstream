from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.cli import (
    build_parser,
    command_create_project_packet,
    command_evaluate_release,
    select_fork_plan_entry,
)
from assured_downstream.evidence import create_evidence_manifest, sha256_file


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

    def test_release_attestation_verifier_requires_policy_and_output(self) -> None:
        args = build_parser().parse_args(
            [
                "verify-release-attestations",
                "--evidence",
                "evidence.json",
                "--policy",
                "policies/release-verification.json",
                "--output",
                "verification.json",
            ]
        )

        self.assertEqual(args.evidence, Path("evidence.json"))
        self.assertEqual(args.policy, Path("policies/release-verification.json"))
        self.assertEqual(args.output, Path("verification.json"))

    def test_reproducibility_run_requires_two_declared_executions(self) -> None:
        args = build_parser().parse_args(
            [
                "reproducibility-run",
                "--left-evidence",
                "left/evidence.json",
                "--right-evidence",
                "right/evidence.json",
                "--left-execution-id",
                "github-actions:1",
                "--right-execution-id",
                "github-actions:2",
                "--policy",
                "policies/build-verification.json",
                "--trust-policy",
                "policies/release-verification.json",
                "--run-dir",
                "runs/repro-001",
            ]
        )

        self.assertEqual(args.left_execution_id, "github-actions:1")
        self.assertEqual(args.right_execution_id, "github-actions:2")
        self.assertEqual(args.run_dir, Path("runs/repro-001"))

    def test_build_verification_v3_run_has_separate_policy_lane(self) -> None:
        args = build_parser().parse_args(
            [
                "build-verification-v3-run",
                "--evidence",
                "evidence-v3.json",
                "--policy",
                "policies/build-verification-v3.json",
                "--trust-policy",
                "policies/release-verification.json",
                "--run-dir",
                "runs/build-verify-v3",
            ]
        )

        self.assertEqual(args.evidence, Path("evidence-v3.json"))
        self.assertEqual(
            args.policy,
            Path("policies/build-verification-v3.json"),
        )
        self.assertEqual(args.run_dir, Path("runs/build-verify-v3"))

    def test_reproducibility_v3_run_has_separate_agent_lane(self) -> None:
        args = build_parser().parse_args(
            [
                "reproducibility-v3-run",
                "--left-evidence",
                "left/evidence.json",
                "--right-evidence",
                "right/evidence.json",
                "--left-execution-id",
                "github-actions:1001",
                "--right-execution-id",
                "github-actions:1002",
                "--policy",
                "policies/build-verification-v3.json",
                "--trust-policy",
                "policies/release-verification.json",
                "--run-dir",
                "runs/repro-v3",
            ]
        )

        self.assertEqual(args.left_execution_id, "github-actions:1001")
        self.assertEqual(args.right_execution_id, "github-actions:1002")
        self.assertEqual(args.run_dir, Path("runs/repro-v3"))

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

    def test_patch_run_parser_has_no_remote_publication_switch(self) -> None:
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
                "--publication-policy",
                "publication-policy.json",
                "--workspace",
                "worktrees",
                "--run-dir",
                "runs/patch-001",
            ]
        )

        self.assertFalse(args.execute_patch)
        self.assertFalse(hasattr(args, "execute_publish"))

    def test_publication_run_parser_keeps_remote_mutation_explicit(self) -> None:
        args = build_parser().parse_args(
            [
                "publication-run",
                "--request",
                "request.json",
                "--bundle",
                "bundle.json",
                "--publication-policy",
                "publication-policy.json",
                "--checkout",
                "worktrees/repository",
                "--workspace",
                "worktrees",
                "--run-dir",
                "runs/publication-001",
            ]
        )

        self.assertFalse(args.execute)

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

    def test_evaluate_release_cli_blocks_caller_supplied_attested_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifact.bin"
            sbom = root / "sbom.spdx.json"
            attestation = root / "attestation.sigstore.json"
            artifact.write_bytes(b"artifact\n")
            sbom.write_text("{}\n", encoding="utf-8")
            attestation.write_text("{}\n", encoding="utf-8")
            manifest = create_evidence_manifest(
                project="owner/project",
                target_repo="target/project",
                upstream_ref="a" * 40,
                overlay_ref="b" * 40,
                release_tag="secure-v1",
                assurance="Evidence-candidate",
                files={
                    "artifacts": [artifact],
                    "sboms": [sbom],
                    "attestations": [attestation],
                    "traces": [],
                    "reports": [],
                },
                root=root,
            )
            evidence = write_json(root / "evidence.json", manifest)
            attestation_verification = write_json(
                root / "attestation-verification.json",
                {
                    "ok": True,
                    "verification_type": "sigstore-bundle",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "signer": "caller-supplied",
                    "verified_subjects": [{"sha256": sha256_file(artifact)}],
                },
            )
            tooling_verification = write_json(
                root / "tooling-verification.json",
                {
                    "ok": True,
                    "policy_sha256": "1" * 64,
                    "lock_sha256": "2" * 64,
                },
            )
            workflow_verification = write_json(
                root / "workflow-verification.json",
                {
                    "ok": True,
                    "analyzed_workflow_sha256": "3" * 64,
                    "findings": [],
                },
            )
            output = root / "evaluation.json"
            args = build_parser().parse_args(
                [
                    "evaluate-release",
                    "--evidence",
                    str(evidence),
                    "--target",
                    "Attested",
                    "--attestation-verification",
                    str(attestation_verification),
                    "--tooling-verification",
                    str(tooling_verification),
                    "--workflow-risk-verification",
                    str(workflow_verification),
                    "--output",
                    str(output),
                ]
            )

            code = command_evaluate_release(args)
            evaluation = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(code, 1)
        self.assertEqual(evaluation["decision"], "block")
        self.assertIn("code-anchored", evaluation["failures"][-1])


def write_json(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


if __name__ == "__main__":
    unittest.main()
