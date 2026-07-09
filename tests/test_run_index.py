from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.run_index import (
    append_run_record,
    create_pilot_run_record,
    load_run_index,
)


class RunIndexTests(unittest.TestCase):
    def test_appends_failed_run_without_corrupting_prior_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index_path = root / "runs" / "index.json"

            append_run_record(
                index_path,
                pilot_record(root, "pilot-001", "succeeded"),
            )
            append_run_record(
                index_path,
                pilot_record(
                    root,
                    "pilot-002",
                    "failed",
                    failures=[{"type": "RuntimeError", "message": "boom"}],
                ),
            )

            index = load_run_index(index_path)
            self.assertEqual([run["run_id"] for run in index["runs"]], ["pilot-001", "pilot-002"])
            self.assertEqual([run["status"] for run in index["runs"]], ["succeeded", "failed"])
            self.assertEqual(index["runs"][0]["failures"], [])
            self.assertEqual(index["runs"][1]["failures"][0]["type"], "RuntimeError")

    def test_recovers_malformed_index_by_preserving_corrupt_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index_path = root / "runs" / "index.json"
            index_path.parent.mkdir(parents=True)
            index_path.write_text("{not valid json", encoding="utf-8")

            appended = append_run_record(index_path, pilot_record(root, "pilot-001", "failed"))

            index = load_run_index(index_path)
            self.assertEqual(len(index["runs"]), 1)
            self.assertEqual(index["runs"][0]["run_id"], "pilot-001")
            self.assertEqual(appended["warnings"][0]["code"], "run_index_recovered")
            backups = list(index_path.parent.glob("index.json.corrupt-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(encoding="utf-8"), "{not valid json")


def pilot_record(
    root: Path,
    run_id: str,
    status: str,
    *,
    failures: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return create_pilot_run_record(
        run_id=run_id,
        started_at="2026-07-09T00:00:00+00:00",
        seed_refs=["seed.md"],
        org="assured-oss",
        run_dir=root / "runs" / run_id,
        output_paths={
            "catalog": str(root / "runs" / run_id / "catalog.json"),
            "fork_plan": str(root / "runs" / run_id / "fork-plan.json"),
        },
        counts={"repositories": 1, "fork_plan_entries": 1},
        status=status,
        failures=failures,
    )


if __name__ == "__main__":
    unittest.main()
