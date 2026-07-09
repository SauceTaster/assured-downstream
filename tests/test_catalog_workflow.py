from __future__ import annotations

import unittest

from assured_downstream.catalog import empty_catalog, upsert_findings
from assured_downstream.fork_plan import create_fork_plan
from assured_downstream.scoring import score_catalog
from assured_downstream.seed import parse_seed_text


class CatalogWorkflowTests(unittest.TestCase):
    def test_ingest_score_and_plan(self) -> None:
        text = """
        - [dnSpyEx](https://github.com/dnSpyEx/dnSpy)
        - [YARA](https://github.com/VirusTotal/yara)
        - [Another YARA](https://github.com/example/yara)
        """
        findings = parse_seed_text(text, source="seed.md")
        catalog = empty_catalog()

        added_repositories, added_seed_refs = upsert_findings(catalog, findings)
        self.assertEqual(added_repositories, 3)
        self.assertEqual(added_seed_refs, 3)

        score_catalog(catalog)
        plan = create_fork_plan(catalog, org="assured-oss", limit=3)

        self.assertEqual(plan["mode"], "dry_run")
        self.assertEqual(len(plan["forks"]), 3)
        targets = {entry["target_full_name"] for entry in plan["forks"]}
        self.assertIn("assured-oss/VirusTotal-yara", targets)
        self.assertIn("assured-oss/example-yara", targets)
        self.assertIn("recommended_mode", plan["forks"][0])


if __name__ == "__main__":
    unittest.main()
