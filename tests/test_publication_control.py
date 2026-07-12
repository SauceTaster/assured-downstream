from __future__ import annotations

import base64
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from assured_downstream.command_runner import CommandResult
from assured_downstream.evidence import sha256_file
from assured_downstream.managed_checkout_agents import write_json_atomic
from assured_downstream.publication_authorization import PublicationAuthorizationError
from assured_downstream.publication_control import (
    dispatch_publication_authorization,
)
from tests.publication_test_support import (
    trust_publication_policy,
    write_publication_policy,
)
from tests.test_publication_authorization import make_request


class DispatchRunner:
    def __init__(self, stdout: str, *, actor: str = "user") -> None:
        self.stdout = stdout
        self.actor = actor
        self.command: list[str] | None = None
        self.input_text: str | None = None
        self.commands: list[list[str]] = []

    def run(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        self.command = command
        self.commands.append(command)
        if command[1:] == ["api", "user"]:
            return CommandResult(
                command=command,
                executed=True,
                returncode=0,
                stdout=json.dumps({"login": self.actor}),
            )
        self.input_text = input_text
        return CommandResult(
            command=command,
            executed=True,
            returncode=0,
            stdout=self.stdout,
        )


def github_account_boundary() -> dict:
    return {
        "schema_version": 1,
        "status": "active",
        "github_host": "github.com",
        "required_actor": "user",
        "allowed_target_owners": ["user"],
        "controls": {
            "allow_auth_switch": False,
            "allow_external_collaborators": False,
            "allow_external_reviewers": False,
            "require_identity_check_before_mutation": True,
            "on_identity_mismatch": "fail_closed",
            "on_independent_approval_unavailable": "fail_closed",
        },
    }


class PublicationControlTests(unittest.TestCase):
    def test_dispatches_exact_request_over_json_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request_path = root / "request.json"
            request = make_request(policy, sha256_file(policy_path))
            write_json_atomic(request_path, request)
            runner = DispatchRunner(
                "https://github.com/user/control/actions/runs/12345\n"
            )

            with trust_publication_policy(policy_path):
                result = dispatch_publication_authorization(
                    request_path=request_path,
                    policy_path=policy_path,
                    execute=True,
                    runner=runner,
                    now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                    account_boundary=github_account_boundary(),
                )

            self.assertEqual(result["status"], "dispatched")
            self.assertEqual(result["run_id"], "12345")
            assert runner.command is not None and runner.input_text is not None
            self.assertEqual(runner.commands[0][1:], ["api", "user"])
            self.assertEqual(runner.command[1:4], ["workflow", "run", "authorize-publication.yml"])
            self.assertIn("--json", runner.command)
            submitted = json.loads(runner.input_text)
            self.assertEqual(
                base64.b64decode(submitted["request_base64"]),
                request_path.read_bytes(),
            )
            self.assertEqual(
                submitted["request_sha256"],
                sha256_file(request_path),
            )

    def test_rejects_run_url_from_another_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request_path = root / "request.json"
            write_json_atomic(
                request_path,
                make_request(policy, sha256_file(policy_path)),
            )

            with trust_publication_policy(policy_path):
                with self.assertRaisesRegex(
                    PublicationAuthorizationError,
                    "trusted workflow run URL",
                ):
                    dispatch_publication_authorization(
                        request_path=request_path,
                        policy_path=policy_path,
                        execute=True,
                        runner=DispatchRunner(
                            "https://github.com/attacker/control/actions/runs/12345\n"
                        ),
                        now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                        account_boundary=github_account_boundary(),
                    )

    def test_rejects_dispatch_when_authenticated_actor_differs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path, policy = write_publication_policy(root)
            request_path = root / "request.json"
            write_json_atomic(
                request_path,
                make_request(policy, sha256_file(policy_path)),
            )
            runner = DispatchRunner(
                "https://github.com/user/control/actions/runs/12345\n",
                actor="different-user",
            )

            with trust_publication_policy(policy_path):
                with self.assertRaisesRegex(
                    PublicationAuthorizationError,
                    "identity check failed",
                ):
                    dispatch_publication_authorization(
                        request_path=request_path,
                        policy_path=policy_path,
                        execute=True,
                        runner=runner,
                        now=datetime(2026, 7, 11, 13, tzinfo=UTC),
                        account_boundary=github_account_boundary(),
                    )

            self.assertEqual(len(runner.commands), 1)
            self.assertEqual(runner.commands[0][1:], ["api", "user"])


if __name__ == "__main__":
    unittest.main()
