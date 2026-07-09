from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.pipeline import run_pilot_pipeline


class FakeClient:
    pass


class PipelineTests(unittest.TestCase):
    def test_runs_observe_first_pilot_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "awesome.md"
            run_dir = root / "run"
            seed.write_text(
                "- https://github.com/VirusTotal/yara\n"
                "- https://github.com/dnSpyEx/dnSpy\n",
                encoding="utf-8",
            )

            summary = run_pilot_pipeline(
                seed_paths=[seed],
                org="assured-oss",
                run_dir=run_dir,
                client=FakeClient(),
                limit=1,
            )

            self.assertEqual(summary["repositories"], 2)
            self.assertTrue((run_dir / "catalog.json").exists())
            self.assertTrue((run_dir / "fork-plan.json").exists())
            self.assertTrue((run_dir / "selection-reasons.json").exists())
            self.assertTrue((run_dir / "state.json").exists())
            self.assertTrue((run_dir / "sync-plan.json").exists())
            self.assertTrue((run_dir / "RUN_SUMMARY.md").exists())
            self.assertTrue((root / "index.json").exists())
            self.assertEqual(summary["selection_counts"]["selected"], 1)

    def test_pilot_policy_suppresses_fork_plan_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "awesome.md"
            run_dir = root / "runs" / "pilot-001"
            suppressions = root / "suppressions.json"
            seed.write_text(
                "- https://github.com/VirusTotal/yara\n"
                "- https://github.com/dnSpyEx/dnSpy\n",
                encoding="utf-8",
            )
            suppressions.write_text(
                json.dumps(
                    {
                        "repositories": [
                            {
                                "full_name": "VirusTotal/yara",
                                "reason": "not in this pilot",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            summary = run_pilot_pipeline(
                seed_paths=[seed],
                org="assured-oss",
                run_dir=run_dir,
                client=FakeClient(),
                suppression_path=suppressions,
            )

            with (run_dir / "fork-plan.json").open("r", encoding="utf-8") as handle:
                fork_plan = json.load(handle)
            sources = {entry["source_full_name"] for entry in fork_plan["forks"]}
            self.assertNotIn("VirusTotal/yara", sources)
            self.assertEqual(summary["selection_counts"]["suppressed"], 1)

    def test_failed_pilot_appends_run_index_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs_dir = root / "runs"
            seed = root / "awesome.md"
            seed.write_text("- https://github.com/VirusTotal/yara\n", encoding="utf-8")
            index_path = runs_dir / "index.json"

            run_pilot_pipeline(
                seed_paths=[seed],
                org="assured-oss",
                run_dir=runs_dir / "pilot-good",
                client=FakeClient(),
                run_index_path=index_path,
            )
            with self.assertRaises(FileNotFoundError):
                run_pilot_pipeline(
                    seed_paths=[root / "missing.md"],
                    org="assured-oss",
                    run_dir=runs_dir / "pilot-failed",
                    client=FakeClient(),
                    run_index_path=index_path,
                )

            with index_path.open("r", encoding="utf-8") as handle:
                index = json.load(handle)
            self.assertEqual([run["status"] for run in index["runs"]], ["succeeded", "failed"])
            self.assertEqual(index["runs"][0]["run_id"], "pilot-good")
            self.assertEqual(index["runs"][1]["run_id"], "pilot-failed")
            self.assertEqual(index["runs"][1]["failures"][0]["type"], "FileNotFoundError")

    def test_partial_pilot_failure_records_counts_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "awesome.md"
            run_dir = root / "runs" / "pilot-partial"
            index_path = root / "runs" / "index.json"
            seed.write_text("- https://github.com/VirusTotal/yara\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                run_pilot_pipeline(
                    seed_paths=[seed],
                    org="assured-oss",
                    run_dir=run_dir,
                    client=FakeClient(),
                    resolve_pins=True,
                    tooling_path=None,
                    run_index_path=index_path,
                )

            with index_path.open("r", encoding="utf-8") as handle:
                index = json.load(handle)
            run = index["runs"][0]
            self.assertEqual(run["status"], "failed")
            self.assertEqual(run["counts"]["repositories"], 1)
            self.assertEqual(run["counts"]["fork_plan_entries"], 1)
            self.assertEqual(run["failures"][0]["type"], "ValueError")
            self.assertTrue((run_dir / "catalog.json").exists())
            self.assertTrue((run_dir / "fork-plan.json").exists())


if __name__ == "__main__":
    unittest.main()
