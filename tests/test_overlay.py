from __future__ import annotations

import unittest

from assured_downstream.overlay import plan_overlay


class OverlayTests(unittest.TestCase):
    def test_plans_hardened_overlay_from_workflow_risks(self) -> None:
        recon = {
            "path": "/tmp/project",
            "generated_at": "2026-07-09T00:00:00+00:00",
            "ci": {
                "provider": "github-actions",
                "workflows": [
                    {
                        "path": ".github/workflows/ci.yml",
                        "has_permissions_block": False,
                    }
                ],
            },
            "security_controls": {
                "has_dependabot": False,
                "mentions_scorecard": False,
                "mentions_harden_runner": False,
            },
            "release_signals": {},
            "risk_signals": [
                {
                    "path": ".github/workflows/ci.yml",
                    "signal": "action actions/checkout@v4 is not pinned to a full commit SHA",
                    "severity": "medium",
                }
            ],
        }

        plan = plan_overlay(recon, target="Hardened")
        change_ids = {change["id"] for change in plan["proposed_changes"]}

        self.assertIn("gha-minimal-permissions", change_ids)
        self.assertIn("gha-pin-actions", change_ids)
        self.assertIn("harden-runner-audit", change_ids)
        self.assertEqual(plan["summary"]["Hardened"], len(plan["proposed_changes"]))

    def test_attested_target_adds_release_evidence_changes(self) -> None:
        recon = {
            "path": "/tmp/project",
            "generated_at": "2026-07-09T00:00:00+00:00",
            "ci": {"provider": None, "workflows": []},
            "security_controls": {},
            "release_signals": {"uploads_github_release": True},
            "risk_signals": [],
        }

        plan = plan_overlay(recon, target="Attested")
        change_ids = {change["id"] for change in plan["proposed_changes"]}

        self.assertIn("gha-bootstrap", change_ids)
        self.assertIn("sbom-generation", change_ids)
        self.assertIn("slsa-provenance", change_ids)
        self.assertIn("sigstore-signing", change_ids)
        self.assertIn("in-toto-evidence", change_ids)


if __name__ == "__main__":
    unittest.main()

