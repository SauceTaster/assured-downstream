from __future__ import annotations

import json
import unittest

from assured_downstream.command_runner import CommandResult
from assured_downstream.fork_apply import apply_fork_plan
from assured_downstream.lifecycle import StateStore


class FakeRunner:
    def __init__(self, responses: list[CommandResult] | None = None) -> None:
        self.responses = list(responses or [])
        self.commands: list[list[str]] = []

    def run(self, command: list[str], *, cwd: str | None = None) -> CommandResult:
        self.commands.append(command)
        if self.responses:
            response = self.responses.pop(0)
            return CommandResult(
                command=command,
                executed=response.executed,
                returncode=response.returncode,
                stdout=response.stdout,
                stderr=response.stderr,
            )
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

    def test_personal_target_uses_prefix_without_org_flag(self) -> None:
        plan = {
            "target": {
                "owner": "SauceTaster",
                "owner_type": "user",
                "name_prefix": "assured-",
            },
            "forks": [
                {
                    "source_full_name": "owner/project",
                    "target_full_name": "SauceTaster/assured-project",
                    "target_repo_name": "assured-project",
                }
            ],
        }
        state = StateStore.empty()
        runner = FakeRunner()

        result = apply_fork_plan(plan, state=state, runner=runner)

        self.assertEqual(result.succeeded, 1)
        self.assertEqual(
            runner.commands,
            [[
                "gh",
                "repo",
                "fork",
                "owner/project",
                "--fork-name",
                "assured-project",
                "--clone=false",
            ]],
        )

    def test_execute_skips_existing_fork_with_matching_parent(self) -> None:
        plan = {
            "target": {
                "owner": "SauceTaster",
                "owner_type": "user",
                "name_prefix": "assured-",
            },
            "forks": [
                {
                    "source_full_name": "owner/project",
                    "target_full_name": "SauceTaster/assured-project",
                    "target_repo_name": "assured-project",
                }
            ],
        }
        lookup = CommandResult(
            command=[],
            executed=True,
            returncode=0,
            stdout=json.dumps(
                {
                    "fork": True,
                    "parent": {"full_name": "owner/project"},
                }
            ),
        )
        identity = CommandResult(
            command=[],
            executed=True,
            returncode=0,
            stdout=json.dumps({"login": "SauceTaster"}),
        )
        state = StateStore.empty()
        runner = FakeRunner([identity, lookup])

        result = apply_fork_plan(plan, state=state, execute=True, runner=runner)

        self.assertEqual(result.succeeded, 0)
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(
            runner.commands,
            [
                ["gh", "api", "user"],
                ["gh", "api", "repos/SauceTaster/assured-project"],
            ],
        )
        repo = state.data["repositories"]["owner/project"]
        self.assertEqual(repo["current_state"], "ForkVerified")

    def test_execute_creates_missing_fork_then_verifies_parent(self) -> None:
        plan = {
            "target": {
                "owner": "SauceTaster",
                "owner_type": "user",
                "name_prefix": "assured-",
            },
            "forks": [
                {
                    "source_full_name": "owner/project",
                    "target_full_name": "SauceTaster/assured-project",
                    "target_repo_name": "assured-project",
                }
            ],
        }
        identity = CommandResult(
            command=[],
            executed=True,
            returncode=0,
            stdout=json.dumps({"login": "SauceTaster"}),
        )
        missing = CommandResult(
            command=[],
            executed=True,
            returncode=1,
            stderr="gh: Not Found (HTTP 404)",
        )
        created = CommandResult(
            command=[],
            executed=True,
            returncode=0,
            stdout="https://github.com/SauceTaster/assured-project\n",
        )
        verified = CommandResult(
            command=[],
            executed=True,
            returncode=0,
            stdout=json.dumps(
                {
                    "fork": True,
                    "parent": {"full_name": "owner/project"},
                }
            ),
        )
        state = StateStore.empty()
        runner = FakeRunner([identity, missing, created, verified])

        result = apply_fork_plan(plan, state=state, execute=True, runner=runner)

        self.assertEqual(result.succeeded, 1)
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(
            runner.commands,
            [
                ["gh", "api", "user"],
                ["gh", "api", "repos/SauceTaster/assured-project"],
                [
                    "gh",
                    "repo",
                    "fork",
                    "owner/project",
                    "--fork-name",
                    "assured-project",
                    "--clone=false",
                ],
                ["gh", "api", "repos/SauceTaster/assured-project"],
            ],
        )
        repo = state.data["repositories"]["owner/project"]
        self.assertEqual(repo["current_state"], "Forked")
        self.assertEqual(
            repo["events"][0]["detail"]["verification"]["parent_full_name"],
            "owner/project",
        )

    def test_execute_blocks_existing_repository_with_wrong_lineage(self) -> None:
        plan = {
            "org": "assured-oss",
            "forks": [
                {
                    "source_full_name": "owner/project",
                    "target_full_name": "assured-oss/project",
                }
            ],
        }
        lookup = CommandResult(
            command=[],
            executed=True,
            returncode=0,
            stdout=json.dumps({"fork": False, "parent": None}),
        )
        state = StateStore.empty()

        result = apply_fork_plan(
            plan,
            state=state,
            execute=True,
            runner=FakeRunner([lookup]),
        )

        self.assertEqual(result.failed, 1)
        repo = state.data["repositories"]["owner/project"]
        self.assertEqual(repo["current_state"], "Blocked")
        self.assertEqual(repo["events"][0]["event"], "ForkConflict")

    def test_execute_blocks_personal_target_when_authenticated_user_differs(self) -> None:
        plan = {
            "target": {
                "owner": "SauceTaster",
                "owner_type": "user",
                "name_prefix": "assured-",
            },
            "forks": [
                {
                    "source_full_name": "owner/project",
                    "target_full_name": "SauceTaster/assured-project",
                    "target_repo_name": "assured-project",
                }
            ],
        }
        identity = CommandResult(
            command=[],
            executed=True,
            returncode=0,
            stdout=json.dumps({"login": "someone-else"}),
        )
        state = StateStore.empty()
        runner = FakeRunner([identity])

        result = apply_fork_plan(plan, state=state, execute=True, runner=runner)

        self.assertEqual(result.failed, 1)
        self.assertEqual(runner.commands, [["gh", "api", "user"]])
        event = state.data["repositories"]["owner/project"]["events"][0]
        self.assertEqual(event["event"], "ForkPreflightFailed")
        self.assertEqual(event["detail"]["actual_login"], "someone-else")


if __name__ == "__main__":
    unittest.main()
