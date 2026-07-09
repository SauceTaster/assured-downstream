from __future__ import annotations

import unittest

from assured_downstream.command_runner import CommandResult
from assured_downstream.lifecycle import StateStore
from assured_downstream.sync_apply import apply_sync_plan


class FakeRunner:
    def run(self, command: list[str], *, cwd: str | None = None) -> CommandResult:
        return CommandResult(command=command, executed=False, returncode=0)


class SyncApplyTests(unittest.TestCase):
    def test_apply_sync_plan_records_state(self) -> None:
        plan = {
            "repositories": [
                {
                    "source_full_name": "owner/project",
                    "target_full_name": "assured-oss/project",
                    "local_path": "/tmp/work/project",
                    "commands": [
                        {"argv": ["git", "clone", "url", "/tmp/work/project"]},
                        {"argv": ["git", "fetch", "upstream"]},
                    ],
                }
            ]
        }
        state = StateStore.empty()

        result = apply_sync_plan(plan, state=state, runner=FakeRunner())

        self.assertEqual(result.succeeded, 1)
        repo = state.data["repositories"]["owner/project"]
        self.assertEqual(repo["current_state"], "SyncPlanned")
        self.assertEqual(len(repo["events"][0]["detail"]["commands"]), 2)


if __name__ == "__main__":
    unittest.main()

