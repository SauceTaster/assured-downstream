from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from assured_downstream.evidence import sha256_file
from assured_downstream.patch_agents import run_patch_publication_agent_system
from assured_downstream.patch_approval import (
    create_patch_approval,
    policy_eligible_change_ids,
)
from assured_downstream.managed_checkout_agents import write_json_atomic
from tests.test_secure_patch import managed_checkout, overlay_plan, pin_lock
from tests.git_test_support import git


TOOLING_POLICY_SHA256 = "f" * 64


class PatchAgentTests(unittest.TestCase):
    def test_policy_approval_selects_only_supported_additive_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, _target = managed_checkout(root)
            analysis_path, pins_path = write_analysis_bundle(root, checkout)
            tooling_path = tooling_policy_path(root)
            analysis = read_json(analysis_path)
            pins = read_json(pins_path)

            approval = create_patch_approval(
                analysis_index=analysis,
                analysis_index_sha256=sha256_file(analysis_path),
                pin_lock=pins,
                pin_lock_sha256=sha256_file(pins_path),
                tooling_policy=read_json(tooling_path),
                tooling_policy_sha256=sha256_file(tooling_path),
                target_full_name="user/target",
                auto_approve_safe=True,
            )

            self.assertEqual(approval["status"], "approved")
            self.assertEqual(approval["approval_type"], "policy")
            self.assertEqual(
                approval["repository"]["approved_change_ids"],
                ["dependency-review"],
            )
            self.assertFalse(approval["repository"]["publish_secure_branch"])

    def test_policy_requires_exact_paths_and_explicit_false_review_marker(self) -> None:
        overlay = overlay_plan()
        change = overlay["proposed_changes"][0]
        del change["human_review_required"]
        self.assertEqual(
            eligible_change_ids(overlay, pin_lock()),
            [],
        )
        change["human_review_required"] = False
        change["paths"] = [".github/workflows/not-the-approved-template.yml"]
        self.assertEqual(
            eligible_change_ids(overlay, pin_lock()),
            [],
        )

    def test_policy_rejects_malformed_or_unfresh_pin_entries(self) -> None:
        malformed = pin_lock()
        malformed["entries"]["actions/checkout"]["sha"] = "not-a-commit"
        malformed["pins"]["actions/checkout"] = "not-a-commit"
        self.assertEqual(
            eligible_change_ids(overlay_plan(), malformed),
            [],
        )

        missing_freshness = pin_lock()
        del missing_freshness["entries"]["actions/checkout"]["expires_at"]
        self.assertEqual(
            eligible_change_ids(overlay_plan(), missing_freshness),
            [],
        )

        reduced_coverage = pin_lock()
        reduced_coverage["coverage"]["required_actions"].remove(
            "ossf/scorecard-action"
        )
        reduced_coverage["coverage"]["resolved_actions"].remove(
            "ossf/scorecard-action"
        )
        del reduced_coverage["pins"]["ossf/scorecard-action"]
        del reduced_coverage["entries"]["ossf/scorecard-action"]
        self.assertEqual(
            eligible_change_ids(overlay_plan(), reduced_coverage),
            [],
        )

    def test_durable_patch_lane_commits_locally_and_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, target = managed_checkout(root)
            base_sha = git("-C", str(checkout), "rev-parse", "refs/heads/secure/main")
            analysis_path, pins_path = write_analysis_bundle(root, checkout)
            approval_path = root / "approval.json"
            approval = create_patch_approval(
                analysis_index=read_json(analysis_path),
                analysis_index_sha256=sha256_file(analysis_path),
                pin_lock=read_json(pins_path),
                pin_lock_sha256=sha256_file(pins_path),
                tooling_policy=read_json(tooling_policy_path(root)),
                tooling_policy_sha256=sha256_file(tooling_policy_path(root)),
                target_full_name="user/target",
                auto_approve_safe=True,
            )
            write_json_atomic(approval_path, approval)
            run_dir = root / "patch-run"

            result = run_patch_publication_agent_system(
                analysis_index_path=analysis_path,
                pin_lock_path=pins_path,
                tooling_policy_path=tooling_policy_path(root),
                approval_path=approval_path,
                workspace=root / "managed",
                run_dir=run_dir,
                run_id="patch-test",
                execute_patch=True,
                allow_local_test_remotes=True,
            )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 2)
            self.assertEqual(result["summary"]["handoff_agents"], [
                "patch",
                "secure-branch-publisher",
            ])
            self.assertTrue(result["artifact_verification"]["ok"])
            patch_result = read_json(run_dir / "patch-result.json")
            self.assertEqual(patch_result["action"], "committed")
            self.assertNotEqual(patch_result["patch_sha"], base_sha)
            publication = read_json(run_dir / "secure-branch-publication.json")
            self.assertEqual(publication["status"], "not-authorized")
            self.assertFalse(publication["executed"])
            self.assertIsNone(remote_ref(target, "refs/heads/secure/main"))

            resumed = run_patch_publication_agent_system(
                analysis_index_path=analysis_path,
                pin_lock_path=pins_path,
                tooling_policy_path=tooling_policy_path(root),
                approval_path=approval_path,
                workspace=root / "managed",
                run_dir=run_dir,
                run_id="patch-test",
                execute_patch=True,
                allow_local_test_remotes=True,
            )
            self.assertEqual(resumed["status"], "succeeded")
            self.assertEqual(resumed["processed_count"], 0)

    def test_pending_approval_blocks_before_secure_ref_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, _target = managed_checkout(root)
            base_sha = git("-C", str(checkout), "rev-parse", "refs/heads/secure/main")
            analysis_path, pins_path = write_analysis_bundle(root, checkout)
            approval_path = root / "approval.json"
            approval = create_patch_approval(
                analysis_index=read_json(analysis_path),
                analysis_index_sha256=sha256_file(analysis_path),
                pin_lock=read_json(pins_path),
                pin_lock_sha256=sha256_file(pins_path),
                tooling_policy=read_json(tooling_policy_path(root)),
                tooling_policy_sha256=sha256_file(tooling_policy_path(root)),
                target_full_name="user/target",
                auto_approve_safe=False,
            )
            write_json_atomic(approval_path, approval)

            result = run_patch_publication_agent_system(
                analysis_index_path=analysis_path,
                pin_lock_path=pins_path,
                tooling_policy_path=tooling_policy_path(root),
                approval_path=approval_path,
                workspace=root / "managed",
                run_dir=root / "blocked-run",
                run_id="blocked-patch",
                execute_patch=True,
                allow_local_test_remotes=True,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["processed_count"], 1)
            self.assertEqual(
                git("-C", str(checkout), "rev-parse", "refs/heads/secure/main"),
                base_sha,
            )

    def test_future_dated_approval_blocks_before_secure_ref_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, _target = managed_checkout(root)
            base_sha = git("-C", str(checkout), "rev-parse", "refs/heads/secure/main")
            analysis_path, pins_path = write_analysis_bundle(root, checkout)
            approval_path = root / "approval.json"
            approval = create_patch_approval(
                analysis_index=read_json(analysis_path),
                analysis_index_sha256=sha256_file(analysis_path),
                pin_lock=read_json(pins_path),
                pin_lock_sha256=sha256_file(pins_path),
                tooling_policy=read_json(tooling_policy_path(root)),
                tooling_policy_sha256=sha256_file(tooling_policy_path(root)),
                target_full_name="user/target",
                auto_approve_safe=True,
            )
            approval["approved_at"] = "2099-01-01T00:00:00+00:00"
            approval["expires_at"] = "2099-01-02T00:00:00+00:00"
            write_json_atomic(approval_path, approval)

            result = run_patch_publication_agent_system(
                analysis_index_path=analysis_path,
                pin_lock_path=pins_path,
                tooling_policy_path=tooling_policy_path(root),
                approval_path=approval_path,
                workspace=root / "managed",
                run_dir=root / "future-approval-run",
                run_id="future-approval",
                execute_patch=True,
                allow_local_test_remotes=True,
            )

            self.assertEqual(result["status"], "blocked")
            gate = read_json(root / "future-approval-run" / "patch-gate-decision.json")
            self.assertIn("future-dated", gate["reason"])
            self.assertEqual(
                git("-C", str(checkout), "rev-parse", "refs/heads/secure/main"),
                base_sha,
            )

    def test_local_human_record_cannot_execute_remote_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, target = managed_checkout(root)
            analysis_path, pins_path = write_analysis_bundle(root, checkout)
            approval_path = root / "approval.json"
            approval = create_patch_approval(
                analysis_index=read_json(analysis_path),
                analysis_index_sha256=sha256_file(analysis_path),
                pin_lock=read_json(pins_path),
                pin_lock_sha256=sha256_file(pins_path),
                tooling_policy=read_json(tooling_policy_path(root)),
                tooling_policy_sha256=sha256_file(tooling_policy_path(root)),
                target_full_name="user/target",
                auto_approve_safe=True,
            )
            approval.update(
                {
                    "approval_type": "human-record",
                    "approved_by": "local-test-operator",
                    "authentication": "local-record-only",
                }
            )
            approval["repository"]["publish_secure_branch"] = True
            write_json_atomic(approval_path, approval)
            run_dir = root / "unauthenticated-publication-run"

            result = run_patch_publication_agent_system(
                analysis_index_path=analysis_path,
                pin_lock_path=pins_path,
                tooling_policy_path=tooling_policy_path(root),
                approval_path=approval_path,
                workspace=root / "managed",
                run_dir=run_dir,
                run_id="unauthenticated-publication",
                execute_patch=True,
                execute_publish=True,
                allow_local_test_remotes=True,
            )

            self.assertEqual(result["status"], "blocked")
            publication = read_json(run_dir / "secure-branch-publication.json")
            self.assertIn("authenticated approval backend", publication["reason"])
            self.assertFalse(publication["executed"])
            self.assertIsNone(remote_ref(target, "refs/heads/secure/main"))

    def test_expired_approval_is_rejected_again_at_publication_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, target = managed_checkout(root)
            analysis_path, pins_path = write_analysis_bundle(root, checkout)
            approval_path = root / "approval.json"
            approval = create_patch_approval(
                analysis_index=read_json(analysis_path),
                analysis_index_sha256=sha256_file(analysis_path),
                pin_lock=read_json(pins_path),
                pin_lock_sha256=sha256_file(pins_path),
                tooling_policy=read_json(tooling_policy_path(root)),
                tooling_policy_sha256=sha256_file(tooling_policy_path(root)),
                target_full_name="user/target",
                auto_approve_safe=True,
            )
            write_json_atomic(approval_path, approval)
            run_dir = root / "delayed-publication-run"

            first = run_patch_publication_agent_system(
                analysis_index_path=analysis_path,
                pin_lock_path=pins_path,
                tooling_policy_path=tooling_policy_path(root),
                approval_path=approval_path,
                workspace=root / "managed",
                run_dir=run_dir,
                run_id="delayed-publication",
                execute_patch=True,
                max_items=1,
                allow_local_test_remotes=True,
            )
            self.assertEqual(first["status"], "running")

            real_datetime = datetime

            class FutureDateTime(datetime):
                @classmethod
                def now(cls, tz=None):
                    value = real_datetime.now(UTC) + timedelta(days=8)
                    return value if tz is not None else value.replace(tzinfo=None)

            with patch("assured_downstream.patch_approval.datetime", FutureDateTime):
                resumed = run_patch_publication_agent_system(
                    analysis_index_path=analysis_path,
                    pin_lock_path=pins_path,
                    tooling_policy_path=tooling_policy_path(root),
                    approval_path=approval_path,
                    workspace=root / "managed",
                    run_dir=run_dir,
                    run_id="delayed-publication",
                    execute_patch=True,
                    allow_local_test_remotes=True,
                )

            self.assertEqual(resumed["status"], "blocked")
            publication = read_json(run_dir / "secure-branch-publication.json")
            self.assertIn("expired", publication["reason"])
            self.assertIsNone(remote_ref(target, "refs/heads/secure/main"))

    def test_tampered_nested_overlay_blocks_before_secure_ref_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, _target = managed_checkout(root)
            base_sha = git("-C", str(checkout), "rev-parse", "refs/heads/secure/main")
            analysis_path, pins_path = write_analysis_bundle(root, checkout)
            approval_path = root / "approval.json"
            approval = create_patch_approval(
                analysis_index=read_json(analysis_path),
                analysis_index_sha256=sha256_file(analysis_path),
                pin_lock=read_json(pins_path),
                pin_lock_sha256=sha256_file(pins_path),
                tooling_policy=read_json(tooling_policy_path(root)),
                tooling_policy_sha256=sha256_file(tooling_policy_path(root)),
                target_full_name="user/target",
                auto_approve_safe=True,
            )
            write_json_atomic(approval_path, approval)
            overlay_path = Path(
                read_json(analysis_path)["repositories"][0]["overlay_plan_path"]
            )
            with overlay_path.open("a", encoding="utf-8") as handle:
                handle.write("\n")

            result = run_patch_publication_agent_system(
                analysis_index_path=analysis_path,
                pin_lock_path=pins_path,
                tooling_policy_path=tooling_policy_path(root),
                approval_path=approval_path,
                workspace=root / "managed",
                run_dir=root / "tampered-run",
                run_id="tampered-patch",
                execute_patch=True,
                allow_local_test_remotes=True,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(
                git("-C", str(checkout), "rev-parse", "refs/heads/secure/main"),
                base_sha,
            )


def write_analysis_bundle(root: Path, checkout: Path) -> tuple[Path, Path]:
    overlay = overlay_plan()
    overlay["proposed_changes"].append(
        {
            "id": "gha-pin-actions",
            "stage": "Hardened",
            "action": "modify",
            "paths": [".github/workflows/upstream.yml"],
            "rationale": "Repository-specific workflow surgery.",
            "human_review_required": False,
        }
    )
    repository_dir = root / "analysis" / "repository"
    overlay_path = repository_dir / "overlay-plan.json"
    write_json_atomic(overlay_path, overlay)
    secure_sha = git("-C", str(checkout), "rev-parse", "refs/heads/secure/main")
    analysis = {
        "schema_version": 1,
        "assurance_target": "Hardened",
        "repository_count": 1,
        "repositories": [
            {
                "source_full_name": "owner/upstream",
                "target_full_name": "user/target",
                "default_branch": "main",
                "local_path": str(checkout.resolve()),
                "analysis_sha": secure_sha,
                "secure_branch_sha": secure_sha,
                "overlay_plan_path": str(overlay_path.resolve()),
                "overlay_plan_sha256": sha256_file(overlay_path),
            }
        ],
    }
    analysis_path = root / "analysis" / "analysis-index.json"
    pins_path = root / "pins.json"
    policy_path = tooling_policy_path(root)
    write_json_atomic(analysis_path, analysis)
    write_json_atomic(policy_path, tooling_policy())
    pins = pin_lock()
    pins["source_policy_sha256"] = sha256_file(policy_path)
    write_json_atomic(pins_path, pins)
    return analysis_path, pins_path


def eligible_change_ids(overlay: dict, pins: dict) -> list[str]:
    return policy_eligible_change_ids(
        overlay,
        pin_lock=pins,
        tooling_policy=tooling_policy(),
        tooling_policy_sha256=TOOLING_POLICY_SHA256,
    )


def tooling_policy() -> dict:
    return {
        "schema_version": 1,
        "status": "dev-idea-stage",
        "github_actions": [
            {
                "name": "actions/checkout",
                "ref": "v4",
                "requires_full_sha_pin": True,
            },
            {
                "name": "actions/dependency-review-action",
                "ref": "v4",
                "requires_full_sha_pin": True,
            },
            {
                "name": "ossf/scorecard-action",
                "ref": "main",
                "requires_full_sha_pin": True,
            },
        ],
    }


def tooling_policy_path(root: Path) -> Path:
    return root / "tooling-policy.json"


def read_json(path: Path) -> dict:
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def remote_ref(repository: Path, ref: str) -> str | None:
    import subprocess

    completed = subprocess.run(
        ["git", "--git-dir", str(repository), "show-ref", "--verify", "--hash", ref],
        check=False,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


if __name__ == "__main__":
    unittest.main()
