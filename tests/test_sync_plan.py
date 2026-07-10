from __future__ import annotations

import unittest
from pathlib import Path

from assured_downstream.sync_plan import create_sync_plan, validate_default_branch
from tests.git_test_support import local_fork_plan


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
        self.assertEqual(plan["schema_version"], 2)
        self.assertEqual(repo["default_branch"], "trunk")
        self.assertEqual(
            repo["local_path"],
            str(Path("/tmp/work/assured-oss__project").resolve()),
        )
        self.assertIn("git clone", repo["commands"][0]["display"])
        self.assertIn("branch secure/trunk", repo["commands"][-1]["display"])
        self.assertIn("refs/remotes/upstream/trunk", repo["commands"][-1]["display"])
        self.assertEqual(
            plan["reconciliation_policy"]["secure_branch"],
            "create-if-missing-preserve-if-present",
        )
        self.assertEqual(plan["reconciliation_policy"]["remote_pushes"], "disabled")

    def test_rejects_clone_url_overrides_outside_local_test_mode(self) -> None:
        fork_plan = local_fork_plan(
            upstream_bare=Path("/tmp/upstream.git"),
            target_bare=Path("/tmp/target.git"),
        )

        with self.assertRaises(ValueError):
            create_sync_plan(fork_plan, workspace=Path("/tmp/work"))

    def test_rejects_invalid_default_branch_components(self) -> None:
        for branch in ("foo.lock/bar", "foo/.bar", "foo/bar.lock", "bad..branch"):
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                validate_default_branch(branch)


if __name__ == "__main__":
    unittest.main()
