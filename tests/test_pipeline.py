from __future__ import annotations

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
            self.assertTrue((run_dir / "state.json").exists())
            self.assertTrue((run_dir / "sync-plan.json").exists())
            self.assertTrue((run_dir / "RUN_SUMMARY.md").exists())


if __name__ == "__main__":
    unittest.main()

