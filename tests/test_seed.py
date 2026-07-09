from __future__ import annotations

import unittest
from unittest.mock import patch

from assured_downstream.seed import parse_seed_source, parse_seed_text


class SeedParserTests(unittest.TestCase):
    def test_extracts_https_and_ssh_github_repositories(self) -> None:
        text = """
        - https://github.com/owner/project
        - git@github.com:other/repo.git
        """

        findings = parse_seed_text(text, source="seed.md")

        self.assertEqual(
            [(finding.owner, finding.name) for finding in findings],
            [("owner", "project"), ("other", "repo")],
        )

    def test_ignores_platform_urls(self) -> None:
        text = """
        - https://github.com/topics/security
        - https://github.com/owner/project/blob/main/README.md
        """

        findings = parse_seed_text(text, source="seed.md")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].html_url, "https://github.com/owner/project")

    def test_deduplicates_same_repo_on_same_line(self) -> None:
        text = "- https://github.com/owner/project https://github.com/owner/project"

        findings = parse_seed_text(text, source="seed.md")

        self.assertEqual(len(findings), 1)

    def test_parses_url_seed_source(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return b"- https://github.com/owner/project\n"

        with patch("assured_downstream.seed.urlopen", return_value=FakeResponse()):
            findings = parse_seed_source("https://example.com/awesome.md")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "https://example.com/awesome.md")


if __name__ == "__main__":
    unittest.main()
