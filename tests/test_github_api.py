from __future__ import annotations

import unittest

from assured_downstream.github_api import normalize_repository_metadata


class GitHubApiTests(unittest.TestCase):
    def test_normalizes_repository_metadata(self) -> None:
        metadata = normalize_repository_metadata(
            repository={
                "full_name": "owner/project",
                "description": "Project",
                "homepage": "",
                "default_branch": "main",
                "archived": False,
                "disabled": False,
                "fork": False,
                "private": False,
                "stargazers_count": 10,
                "forks_count": 2,
                "open_issues_count": 3,
                "pushed_at": "2026-01-01T00:00:00Z",
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "license": {"spdx_id": "Apache-2.0"},
            },
            topics=["security", "slsa"],
            languages={"Go": 100},
            releases=[
                {
                    "tag_name": "v1.0.0",
                    "name": "v1.0.0",
                    "published_at": "2026-01-01T00:00:00Z",
                    "draft": False,
                    "prerelease": False,
                    "assets": [{}, {}],
                }
            ],
        )

        self.assertEqual(metadata["license_spdx_id"], "Apache-2.0")
        self.assertTrue(metadata["has_releases"])
        self.assertEqual(metadata["latest_releases"][0]["assets_count"], 2)


if __name__ == "__main__":
    unittest.main()

