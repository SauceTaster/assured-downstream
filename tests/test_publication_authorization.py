from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from assured_downstream.command_runner import CommandResult
from assured_downstream.evidence import sha256_file
from assured_downstream.managed_checkout_agents import write_json_atomic
from assured_downstream.publication_authorization import (
    PublicationAuthorizationError,
    create_publication_request,
    validate_authorization_record,
    validate_publication_request,
    verify_publication_authorization,
)
from tests.publication_test_support import (
    trust_publication_policy,
    verification_output,
    write_publication_policy,
)


class FakeVerifierRunner:
    def __init__(self, stdout: str, *, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.calls: list[dict] = []

    def run(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        self.calls.append({"command": command, "cwd": cwd, "env": env})
        return CommandResult(
            command=command,
            executed=True,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr="verification rejected" if self.returncode else "",
        )


class PublicationAuthorizationTests(unittest.TestCase):
    def test_request_is_deterministic_and_binds_full_publication_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request = make_request(policy, sha256_file(policy_path))
            repeated = make_request(policy, sha256_file(policy_path))

            self.assertEqual(request, repeated)
            self.assertEqual(request["scope"]["target_full_name"], "user/target")
            self.assertEqual(request["scope"]["secure_branch"], "secure/main")
            self.assertEqual(request["scope"]["expected_remote_sha"], None)
            self.assertTrue(request["request_id"].startswith("sha256:"))
            self.assertEqual(
                request["evidence"]["publication_policy_sha256"],
                sha256_file(policy_path),
            )

    def test_verifies_exact_sigstore_statement_in_isolated_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request_path = root / "request.json"
            request = make_request(policy, sha256_file(policy_path))
            write_json_atomic(request_path, request)
            bundle_path = root / "bundle.json"
            bundle_path.write_text('{"mediaType":"application/vnd.dev.sigstore.bundle+json"}\n')
            runner = FakeVerifierRunner(
                verification_output(request, sha256_file(request_path), policy)
            )

            with trust_publication_policy(policy_path):
                record = verify_publication_authorization(
                    request_path=request_path,
                    bundle_path=bundle_path,
                    policy_path=policy_path,
                    runner=runner,
                    now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                )

            self.assertEqual(record["status"], "verified")
            self.assertEqual(record["verified_timestamp_count"], 1)
            self.assertEqual(len(runner.calls), 1)
            call = runner.calls[0]
            self.assertNotEqual(call["cwd"], str(root))
            self.assertEqual(call["env"]["GH_CONFIG_DIR"].split("/")[-1], "gh-config")
            command = call["command"]
            self.assertEqual(command[0].split("/")[-1], "gh")
            self.assertIn("--deny-self-hosted-runners", command)
            self.assertIn("--signer-digest", command)
            self.assertIn(policy["signer"]["workflow_digest"], command)
            self.assertIn("--cert-identity", command)

            with trust_publication_policy(policy_path):
                validate_authorization_record(
                    record,
                    request=request,
                    request_sha256=sha256_file(request_path),
                    bundle_sha256=sha256_file(bundle_path),
                    policy=policy,
                    policy_sha256=sha256_file(policy_path),
                    now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                )

    def test_rejects_attestation_for_a_different_patch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request_path = root / "request.json"
            request = make_request(policy, sha256_file(policy_path))
            write_json_atomic(request_path, request)
            bundle_path = root / "bundle.json"
            bundle_path.write_text("{}\n", encoding="utf-8")
            output = json.loads(
                verification_output(request, sha256_file(request_path), policy)
            )
            output[0]["verificationResult"]["statement"]["predicate"]["patchSha"] = (
                "9" * 40
            )

            with trust_publication_policy(policy_path):
                with self.assertRaisesRegex(
                    PublicationAuthorizationError,
                    "exact publication request",
                ):
                    verify_publication_authorization(
                        request_path=request_path,
                        bundle_path=bundle_path,
                        policy_path=policy_path,
                        runner=FakeVerifierRunner(json.dumps(output)),
                        now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                    )

    def test_rejects_expired_request_before_running_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request_path = root / "request.json"
            request = make_request(policy, sha256_file(policy_path))
            write_json_atomic(request_path, request)
            bundle_path = root / "bundle.json"
            bundle_path.write_text("{}\n", encoding="utf-8")
            runner = FakeVerifierRunner("[]")

            with trust_publication_policy(policy_path):
                with self.assertRaisesRegex(PublicationAuthorizationError, "expired"):
                    verify_publication_authorization(
                        request_path=request_path,
                        bundle_path=bundle_path,
                        policy_path=policy_path,
                        runner=runner,
                        now=datetime(2026, 7, 20, tzinfo=UTC),
                    )
            self.assertEqual(runner.calls, [])

    def test_rejects_tampered_verifier_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request_path = root / "request.json"
            request = make_request(policy, sha256_file(policy_path))
            write_json_atomic(request_path, request)
            bundle_path = root / "bundle.json"
            bundle_path.write_text("{}\n", encoding="utf-8")
            executable = Path(policy["verifier"]["executable"])
            executable.chmod(0o700)
            executable.write_bytes(b"tampered\n")
            runner = FakeVerifierRunner("[]")

            with trust_publication_policy(policy_path):
                with self.assertRaisesRegex(
                    PublicationAuthorizationError,
                    "executable digest",
                ):
                    verify_publication_authorization(
                        request_path=request_path,
                        bundle_path=bundle_path,
                        policy_path=policy_path,
                        runner=runner,
                        now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                    )
            self.assertEqual(runner.calls, [])

    def test_rejects_caller_selected_policy_before_verifier_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request_path = root / "request.json"
            write_json_atomic(
                request_path,
                make_request(policy, sha256_file(policy_path)),
            )
            bundle_path = root / "bundle.json"
            bundle_path.write_text("{}\n", encoding="utf-8")
            runner = FakeVerifierRunner("[]")

            with self.assertRaisesRegex(
                PublicationAuthorizationError,
                "not anchored by this build",
            ):
                verify_publication_authorization(
                    request_path=request_path,
                    bundle_path=bundle_path,
                    policy_path=policy_path,
                    runner=runner,
                    now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                )
            self.assertEqual(runner.calls, [])

    def test_rejects_target_outside_policy_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request = make_request(policy, sha256_file(policy_path))
            request["scope"]["target_full_name"] = "other/target"
            request_path = root / "request.json"
            write_json_atomic(request_path, request)

            with self.assertRaisesRegex(
                PublicationAuthorizationError,
                "canonical content",
            ):
                validate_publication_request(
                    request,
                    policy=policy,
                    policy_sha256=sha256_file(policy_path),
                    request_sha256=sha256_file(request_path),
                    now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                )


def make_request(policy: dict, policy_sha256: str) -> dict:
    issued = datetime(2026, 7, 11, 12, tzinfo=UTC)
    return create_publication_request(
        source_full_name="owner/upstream",
        target_full_name="user/target",
        secure_branch="secure/main",
        patch_sha="a" * 40,
        patch_base_sha="b" * 40,
        required_upstream_sha="b" * 40,
        expected_remote_sha=None,
        approved_change_ids=["dependency-review"],
        approved_at=issued.isoformat(),
        approval_expires_at=(issued + timedelta(days=1)).isoformat(),
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
