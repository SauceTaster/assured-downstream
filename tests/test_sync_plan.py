from __future__ import annotations

import unittest
from pathlib import Path

from assured_downstream.sync_plan import create_sync_plan


class SyncPlanTests(unittest.TestCase):
    def test_creates_sync_commands_from_fork_plan(self) -> None:
        fork_plan = {
            "forks": [
                {
                    "source_full_name": "owner/project",
                    "target_full_name": "assured-oss/project",
                    "metadata": {"default_branch": "trunk"},
                }
            ]
        }

        plan = create_sync_plan(fork_plan, workspace=Path("/tmp/work"))

        repo = plan["repositories"][0]
        self.assertEqual(repo["default_branch"], "trunk")
        self.assertEqual(repo["local_path"], "/tmp/work/assured-oss__project")
        self.assertIn("git clone", repo["commands"][0]["display"])
        self.assertIn("secure/trunk", repo["commands"][-1]["display"])


if __name__ == "__main__":
    unittest.main()

