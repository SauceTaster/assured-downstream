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

        lock = resolve_tooling_pins(policy, client=FakeCommitResolver())

        self.assertEqual(lock["pins"]["actions/checkout"], FULL_SHA)
        self.assertEqual(lock["entries"]["actions/checkout"]["status"], "resolved")

    def test_extracts_repository_from_action_with_subpath(self) -> None:
        self.assertEqual(
            action_repository("github/codeql-action/upload-sarif"),
            ("github", "codeql-action"),
        )


if __name__ == "__main__":
    unittest.main()

