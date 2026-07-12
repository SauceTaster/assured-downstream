from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assured_downstream.command_runner import CommandResult
from assured_downstream.evidence import sha256_file
from assured_downstream.managed_checkout_agents import write_json_atomic
from assured_downstream.patch_agents import run_patch_publication_agent_system
from assured_downstream.patch_approval import create_patch_approval
from assured_downstream.publication_agents import (
    run_authorized_publication_agent_system,
)
from assured_downstream.publication_ledger import (
    PublicationLedger,
    PublicationLedgerError,
)
from tests.publication_test_support import (
    trust_publication_policy,
    verification_output,
    write_publication_policy,
)
from tests.test_patch_agents import (
    read_json,
    remote_ref,
    tooling_policy_path,
    write_analysis_bundle,
)
from tests.test_secure_patch import managed_checkout


class StaticVerifierRunner:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.calls = 0

    def run(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        self.calls += 1
        return CommandResult(
            command=command,
            executed=True,
            returncode=0,
            stdout=self.stdout,
        )


class PublicationAgentTests(unittest.TestCase):
    def test_attested_authorization_publishes_exact_patch_and_blocks_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, target = managed_checkout(root)
            analysis_path, pins_path = write_analysis_bundle(root, checkout)
            policy_path, policy = write_publication_policy(root)
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
                    "approved_by": "integration-reviewer",
                    "authentication": "local-record-only",
                }
            )
            approval["repository"]["publish_secure_branch"] = True
            write_json_atomic(approval_path, approval)
            patch_run_dir = root / "patch-run"

            with trust_publication_policy(policy_path):
                patch_run = run_patch_publication_agent_system(
                    analysis_index_path=analysis_path,
                    pin_lock_path=pins_path,
                    tooling_policy_path=tooling_policy_path(root),
                    approval_path=approval_path,
                    publication_policy_path=policy_path,
                    workspace=root / "managed",
                    run_dir=patch_run_dir,
                    run_id="patch-run",
                    execute_patch=True,
                    allow_local_test_remotes=True,
                )
            self.assertEqual(patch_run["status"], "succeeded")
            request_path = patch_run_dir / "publication-request.json"
            request = read_json(request_path)
            request_sha256 = sha256_file(request_path)
            bundle_path = root / "authorization.sigstore.json"
            bundle_path.write_text('{"test":"sigstore-bundle"}\n', encoding="utf-8")
            verifier = StaticVerifierRunner(
                verification_output(request, request_sha256, policy)
            )
            ledger_path = root / "publication-ledger.sqlite3"
            original_mark_published = PublicationLedger.mark_published
            mark_calls = 0

            def flaky_mark_published(self, **kwargs):
                nonlocal mark_calls
                mark_calls += 1
                if mark_calls == 1:
                    raise PublicationLedgerError("simulated post-push crash")
                return original_mark_published(self, **kwargs)

            with (
                trust_publication_policy(policy_path),
                patch(
                    "assured_downstream.publication_agents.trusted_publication_ledger_path",
                    return_value=ledger_path,
                ),
                patch.object(
                    PublicationLedger,
                    "mark_published",
                    new=flaky_mark_published,
                ),
            ):
                publication = run_authorized_publication_agent_system(
                    request_path=request_path,
                    bundle_path=bundle_path,
                    publication_policy_path=policy_path,
                    checkout_path=checkout,
                    workspace=root / "managed",
                    run_dir=root / "publication-run",
                    run_id="publication-run",
                    execute=True,
                    allow_local_test_remotes=True,
                    verifier_runner=verifier,
                )

            self.assertEqual(publication["status"], "succeeded")
            self.assertEqual(
                publication["summary"]["handoff_agents"],
                ["publication-authorizer", "secure-branch-publisher"],
            )
            published = read_json(
                root / "publication-run" / "secure-branch-publication.json"
            )
            self.assertEqual(published["status"], "already-published")
            self.assertEqual(mark_calls, 2)
            self.assertEqual(
                remote_ref(target, "refs/heads/secure/main"),
                request["scope"]["patch_sha"],
            )
            self.assertEqual(
                PublicationLedger(ledger_path).get(request["request_id"])["status"],
                "published",
            )

            with (
                trust_publication_policy(policy_path),
                patch(
                    "assured_downstream.publication_agents.trusted_publication_ledger_path",
                    return_value=ledger_path,
                ),
            ):
                replay = run_authorized_publication_agent_system(
                    request_path=request_path,
                    bundle_path=bundle_path,
                    publication_policy_path=policy_path,
                    checkout_path=checkout,
                    workspace=root / "managed",
                    run_dir=root / "replay-run",
                    run_id="replay-run",
                    execute=True,
                    allow_local_test_remotes=True,
                    verifier_runner=verifier,
                )
            self.assertEqual(replay["status"], "blocked")
            replay_result = read_json(
                root / "replay-run" / "secure-branch-publication.json"
            )
            self.assertIn("replay", replay_result["reason"])

    def test_invalid_attestation_never_routes_work_to_publisher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, target = managed_checkout(root)
            policy_path, policy = write_publication_policy(root)
            request = manual_request(policy, sha256_file(policy_path))
            request_path = root / "request.json"
            write_json_atomic(request_path, request)
            bundle_path = root / "bundle.json"
            bundle_path.write_text("{}\n", encoding="utf-8")

            with trust_publication_policy(policy_path):
                result = run_authorized_publication_agent_system(
                    request_path=request_path,
                    bundle_path=bundle_path,
                    publication_policy_path=policy_path,
                    checkout_path=checkout,
                    workspace=root / "managed",
                    run_dir=root / "invalid-run",
                    run_id="invalid-run",
                    execute=True,
                    allow_local_test_remotes=True,
                    verifier_runner=StaticVerifierRunner("[]"),
                )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(
                result["summary"]["handoff_agents"],
                ["publication-authorizer"],
            )
            self.assertIsNone(remote_ref(target, "refs/heads/secure/main"))


def manual_request(policy: dict, policy_sha256: str) -> dict:
    from datetime import UTC, datetime, timedelta

    from assured_downstream.publication_authorization import create_publication_request

    now = datetime.now(UTC)
    return create_publication_request(
        source_full_name="owner/upstream",
        target_full_name="user/target",
        secure_branch="secure/main",
        patch_sha="a" * 40,
        patch_base_sha="b" * 40,
        required_upstream_sha="b" * 40,
        expected_remote_sha=None,
        approved_change_ids=["dependency-review"],
        approved_at=(now - timedelta(minutes=1)).isoformat(),
        approval_expires_at=(now + timedelta(days=1)).isoformat(),
        analysis_index_sha256="c" * 64,
        pin_lock_sha256="d" * 64,
        tooling_policy_sha256="e" * 64,
        patch_approval_sha256="f" * 64,
        publication_policy=policy,
        publication_policy_sha256=policy_sha256,
        patch_result_sha256="1" * 64,
    )


if __name__ == "__main__":
    unittest.main()
