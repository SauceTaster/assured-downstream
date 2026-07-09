from __future__ import annotations

import unittest

from assured_downstream.scoring import score_repository


class ScoringTests(unittest.TestCase):
    def test_scores_enriched_active_release_candidate(self) -> None:
        repo = {
            "owner": "owner",
            "name": "security-tool",
            "seeds": [],
            "github": {
                "description": "security scanner",
                "topics": ["security"],
                "stargazers_count": 1000,
                "forks_count": 100,
                "has_releases": True,
                "license_spdx_id": "Apache-2.0",
                "languages": {"Go": 1000},
                "pushed_at": "2026-07-01T00:00:00Z",
                "archived": False,
            },
        }

        score, breakdown, _notes = score_repository(repo)

        self.assertGreater(score, 40)
        self.assertEqual(repo["recommended_mode"], "DownstreamAssured")
        self.assertIn("has_releases", breakdown)

    def test_recommends_custodian_review_for_archived_repo(self) -> None:
        repo = {
            "owner": "owner",
            "name": "abandoned-security-tool",
            "seeds": [],
            "github": {
                "description": "security scanner",
                "topics": ["security"],
                "stargazers_count": 10,
                "forks_count": 2,
                "has_releases": True,
                "license_spdx_id": "MIT",
                "languages": {"C#": 1000},
                "pushed_at": "2020-01-01T00:00:00Z",
                "archived": True,
            },
        }

        score, _breakdown, notes = score_repository(repo)

        self.assertGreater(score, 0)
        self.assertEqual(repo["recommended_mode"], "CustodianReview")
        self.assertTrue(any("custodian" in note for note in notes))


if __name__ == "__main__":
    unittest.main()
