from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from assured_downstream.publication_authorization import (
    TRUSTED_PUBLICATION_POLICY_SHA256,
    validate_publication_policy,
)
from assured_downstream.evidence import sha256_file


ROOT = Path(__file__).resolve().parents[1]


class PublicationControlAssetTests(unittest.TestCase):
    def test_control_workflow_has_static_gate_and_sha_pinned_actions(self) -> None:
        path = ROOT / "control-plane" / "github" / "authorize-publication.yml"
        text = path.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", text)
        self.assertIn("environment: secure-publication", text)
        self.assertIn("id-token: write", text)
        self.assertIn("predicate-type:", text)
        self.assertNotIn("pull_request:", text)
        action_refs = re.findall(r"uses: ([^@\s]+)@([^\s]+)", text)
        self.assertEqual(
            {name for name, _ref in action_refs},
            {"actions/attest", "actions/upload-artifact"},
        )
        for _name, ref in action_refs:
            self.assertRegex(ref, r"^[0-9a-f]{40}$")

    def test_no_live_environment_configuration_is_retained(self) -> None:
        path = ROOT / "control-plane" / "github" / "environment-protection.json"
        self.assertFalse(path.exists())

    def test_publication_policy_is_disabled_fail_closed(self) -> None:
        path = ROOT / "policies" / "publication-authorization.json"
        policy = json.loads(path.read_text(encoding="utf-8"))

        validate_publication_policy(policy, require_active=False)
        with self.assertRaisesRegex(Exception, "not active"):
            validate_publication_policy(policy, require_active=True)
        self.assertEqual(sha256_file(path), TRUSTED_PUBLICATION_POLICY_SHA256)
        self.assertEqual(policy["status"], "disabled")
        self.assertEqual(
            policy["signer"]["workflow_digest"],
            policy["signer"]["source_digest"],
        )


if __name__ == "__main__":
    unittest.main()
