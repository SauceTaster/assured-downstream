from __future__ import annotations

import unittest

from assured_downstream.catalog import empty_catalog, upsert_findings
from assured_downstream.enrichment import enrich_catalog
from assured_downstream.seed import parse_seed_text


class FakeMetadataClient:
    def repository_metadata(self, owner: str, name: str) -> dict:
        return {
            "full_name": f"{owner}/{name}",
            "stargazers_count": 42,
            "archived": False,
            "topics": ["security"],
            "languages": {"Go": 1000},
            "has_releases": True,
        }


class EnrichmentTests(unittest.TestCase):
    def test_enriches_catalog_entries(self) -> None:
        catalog = empty_catalog()
        findings = parse_seed_text("- https://github.com/owner/project", source="seed.md")
        upsert_findings(catalog, findings)

        result = enrich_catalog(catalog, client=FakeMetadataClient())

        self.assertEqual(result.enriched, 1)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(result.failed, 0)
        self.assertEqual(catalog["repositories"][0]["github"]["full_name"], "owner/project")

    def test_skips_existing_metadata_without_refresh(self) -> None:
        catalog = empty_catalog()
        findings = parse_seed_text("- https://github.com/owner/project", source="seed.md")
        upsert_findings(catalog, findings)
        catalog["repositories"][0]["github"] = {"full_name": "owner/project"}

        result = enrich_catalog(catalog, client=FakeMetadataClient())

        self.assertEqual(result.enriched, 0)
        self.assertEqual(result.skipped, 1)


if __name__ == "__main__":
    unittest.main()

