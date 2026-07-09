from __future__ import annotations

import unittest

from assured_downstream.command_runner import CommandResult
from assured_downstream.fork_apply import apply_fork_plan
from assured_downstream.lifecycle import StateStore


class FakeRunner:
    def run(self, command: list[str], *, cwd: str | None = None) -> CommandResult:
        return CommandResult(command=command, executed=False, returncode=0)


class ForkApplyTests(unittest.TestCase):
    def test_apply_fork_plan_records_dry_run_state(self) -> None:
        plan = {
            "org": "assured-oss",
            "forks": [
                {
                    "source_full_name": "owner/project",
                    "target_full_name": "assured-oss/project",
                }
            ],
        }
        state = StateStore.empty()

        result = apply_fork_plan(plan, state=state, runner=FakeRunner())

        self.assertEqual(result.succeeded, 1)
        repo = state.data["repositories"]["owner/project"]
        self.assertEqual(repo["current_state"], "ForkPlanned")
        self.assertEqual(repo["events"][0]["event"], "ForkPlanned")


if __name__ == "__main__":
    unittest.main()

