from __future__ import annotations

import unittest
from pathlib import Path

from assured_downstream.account_boundary import load_github_account_boundary


ROOT = Path(__file__).resolve().parents[1]


class AccountBoundaryAssetTests(unittest.TestCase):
    def test_github_account_boundary_fails_closed(self) -> None:
        path = ROOT / "policies" / "github-account-boundary.json"
        policy = load_github_account_boundary(path)

        self.assertEqual(policy["schema_version"], 1)
        self.assertEqual(policy["status"], "active")
        self.assertEqual(policy["required_actor"], "SauceTaster")
        self.assertEqual(policy["allowed_target_owners"], ["SauceTaster"])
        controls = policy["controls"]
        self.assertFalse(controls["allow_auth_switch"])
        self.assertFalse(controls["allow_external_collaborators"])
        self.assertFalse(controls["allow_external_reviewers"])
        self.assertTrue(controls["require_identity_check_before_mutation"])
        self.assertEqual(controls["on_identity_mismatch"], "fail_closed")
        self.assertEqual(
            controls["on_independent_approval_unavailable"],
            "fail_closed",
        )

    def test_repository_agent_rules_enforce_the_boundary(self) -> None:
        rules = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

        self.assertIn("gh api user --jq .login", rules)
        self.assertIn("Never run `gh auth switch`", rules)
        self.assertIn("separation by crossing accounts.", rules)


if __name__ == "__main__":
    unittest.main()
