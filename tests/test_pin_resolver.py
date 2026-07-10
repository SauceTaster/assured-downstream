from __future__ import annotations

import unittest

from assured_downstream.pin_resolver import action_repository, resolve_tooling_pins


FULL_SHA = "0123456789abcdef0123456789abcdef01234567"


class FakeCommitResolver:
    def resolve_commit(self, owner: str, name: str, ref: str) -> str:
        return FULL_SHA


class PinResolverTests(unittest.TestCase):
    def test_resolves_policy_actions_to_sha_pins(self) -> None:
        policy = {
            "status": "dev-idea-stage",
            "github_actions": [
                {
                    "name": "actions/checkout",
                    "ref": "v4",
                    "requires_full_sha_pin": True,
                }
            ],
        }

        lock = resolve_tooling_pins(
            policy,
            client=FakeCommitResolver(),
            source_policy_sha256="a" * 64,
        )

        self.assertEqual(lock["pins"]["actions/checkout"], FULL_SHA)
        self.assertEqual(lock["entries"]["actions/checkout"]["status"], "resolved")
        self.assertEqual(lock["entries"]["actions/checkout"]["resolved_ref"], "v4")
        self.assertEqual(lock["entries"]["actions/checkout"]["refresh_status"], "current")
        self.assertEqual(lock["coverage"]["required_actions"], ["actions/checkout"])
        self.assertEqual(lock["coverage"]["missing_actions"], [])
        self.assertEqual(lock["status"], "complete")
        self.assertEqual(lock["source_policy_sha256"], "a" * 64)
        self.assertIn("expires_at", lock["entries"]["actions/checkout"])

    def test_marks_lock_incomplete_when_required_action_cannot_resolve(self) -> None:
        class FailingCommitResolver:
            def resolve_commit(self, owner: str, name: str, ref: str) -> str:
                raise RuntimeError("not found")

        policy = {
            "status": "dev-idea-stage",
            "github_actions": [
                {
                    "name": "actions/checkout",
                    "ref": "v4",
                    "requires_full_sha_pin": True,
                }
            ],
        }

        lock = resolve_tooling_pins(policy, client=FailingCommitResolver())

        self.assertEqual(lock["status"], "incomplete")
        self.assertEqual(lock["coverage"]["missing_actions"], ["actions/checkout"])
        self.assertEqual(lock["entries"]["actions/checkout"]["status"], "failed")

    def test_extracts_repository_from_action_with_subpath(self) -> None:
        self.assertEqual(
            action_repository("github/codeql-action/upload-sarif"),
            ("github", "codeql-action"),
        )


if __name__ == "__main__":
    unittest.main()
