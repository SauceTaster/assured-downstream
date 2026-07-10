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

    def test_ignores_github_subdomain_documentation_urls(self) -> None:
        findings = parse_seed_text(
            "https://docs.github.com/en/actions/security-guides\n",
            source="docs.md",
        )

        self.assertEqual(findings, [])

    def test_parses_url_seed_source(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, *_args):
                return b"- https://github.com/owner/project\n"

        public_address = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with (
            patch("assured_downstream.seed.urlopen", return_value=FakeResponse()),
            patch("assured_downstream.seed.socket.getaddrinfo", return_value=public_address),
        ):
            findings = parse_seed_source("https://example.com/awesome.md")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "https://example.com/awesome.md")

    def test_rejects_private_remote_seed_address(self) -> None:
        with self.assertRaises(ValueError):
            parse_seed_source("https://127.0.0.1/awesome.md")


if __name__ == "__main__":
    unittest.main()
