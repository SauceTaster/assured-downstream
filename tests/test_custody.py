from __future__ import annotations

import json
import unittest

from assured_downstream.custody import create_custodian_review


class CustodyTests(unittest.TestCase):
    def test_creates_packet_for_archived_repository(self) -> None:
        catalog = {
            "repositories": [
                {
                    "owner": "owner",
                    "name": "project",
                    "html_url": "https://github.com/owner/project",
                    "score": 50,
                    "recommended_mode": "CustodianReview",
                    "github": {
                        "archived": True,
                        "pushed_at": "2020-01-01T00:00:00Z",
                        "license_spdx_id": "MIT",
                        "has_releases": True,
                        "stargazers_count": 100,
                        "forks_count": 10,
                    },
                }
            ]
        }

        packet = create_custodian_review(catalog)

        self.assertEqual(packet["status"], "human-review-required")
        self.assertEqual(len(packet["candidates"]), 1)
        candidate = packet["candidates"][0]
        self.assertTrue(candidate["criteria"]["archived"])
        self.assertIn("trademark", " ".join(candidate["required_human_review"]))
        self.assertEqual(candidate["maintainer_contact"]["status"], "human-review-required")
        self.assertEqual(candidate["naming_trademark_review"]["status"], "human-review-required")
        self.assertEqual(
            candidate["custodian_claim_gate"]["status"],
            "human-approval-required",
        )
        self.assertFalse(candidate["custodian_claim_gate"]["claim_allowed"])

    def test_skips_active_downstream_candidates(self) -> None:
        catalog = {
            "repositories": [
                {
                    "owner": "owner",
                    "name": "project",
                    "score": 50,
                    "recommended_mode": "DownstreamAssured",
                    "github": {
                        "archived": False,
                        "pushed_at": "2999-01-01T00:00:00Z",
                    },
                }
            ]
        }

        packet = create_custodian_review(catalog)

        self.assertEqual(packet["candidates"], [])

    def test_records_maintainer_contact_evidence_by_repo_name(self) -> None:
        catalog = {
            "repositories": [
                {
                    "owner": "owner",
                    "name": "project",
                    "html_url": "https://github.com/owner/project",
                    "score": 50,
                    "recommended_mode": "CustodianReview",
                    "github": {
                        "archived": True,
                        "pushed_at": "2020-01-01T00:00:00Z",
                    },
                }
            ]
        }

        packet = create_custodian_review(
            catalog,
            maintainer_contacts={
                "OWNER/PROJECT": {
                    "attempts": [{"channel": "issue", "url": "https://example.test/1"}],
                    "maintainer_preference": "no-outreach",
                    "last_contacted_at": "2026-07-01T00:00:00Z",
                    "notes": ["maintainer asked for a pause"],
                }
            },
        )

        contact = packet["candidates"][0]["maintainer_contact"]

        self.assertEqual(len(contact["attempts"]), 1)
        self.assertEqual(contact["maintainer_preference"], "no-outreach")
        self.assertEqual(contact["last_contacted_at"], "2026-07-01T00:00:00Z")

    def test_wording_does_not_claim_project_authority(self) -> None:
        catalog = {
            "repositories": [
                {
                    "owner": "owner",
                    "name": "project",
                    "html_url": "https://github.com/owner/project",
                    "score": 50,
                    "recommended_mode": "CustodianReview",
                    "github": {
                        "archived": True,
                        "pushed_at": "2020-01-01T00:00:00Z",
                    },
                }
            ]
        }

        packet = create_custodian_review(catalog)
        text = json.dumps(packet).lower()

        self.assertNotIn("official ownership", text)
        self.assertNotIn("official successor", text)
        self.assertNotIn("we own", text)
        self.assertNotIn("endorsed by maintainers", text)


if __name__ == "__main__":
    unittest.main()
