from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()

