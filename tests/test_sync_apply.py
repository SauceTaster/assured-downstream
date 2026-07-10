from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.command_runner import CommandResult
from assured_downstream.lifecycle import StateStore
from assured_downstream.sync_apply import apply_sync_plan
from assured_downstream.sync_plan import create_sync_plan
from tests.git_test_support import create_remote_fixture, git, local_fork_plan


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

    def test_live_reconciliation_is_repeat_safe_and_preserves_secure_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upstream_work, upstream_bare, target_bare = create_remote_fixture(root)
            plan = local_sync_plan(
                root,
                upstream_bare=upstream_bare,
                target_bare=target_bare,
            )
            state = StateStore.empty()

            first = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(first.succeeded, 1)
            self.assertEqual(first.failed, 0)
            self.assertEqual(first.review_required, 0)
            local_path = Path(plan["repositories"][0]["local_path"])
            initial_upstream = git(
                "-C",
                str(local_path),
                "rev-parse",
                "refs/heads/upstream/main",
            )
            initial_secure = git(
                "-C",
                str(local_path),
                "rev-parse",
                "refs/heads/secure/main",
            )
            self.assertEqual(initial_upstream, initial_secure)

            second = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(second.succeeded, 1)
            second_event = state.data["repositories"]["owner/upstream"]["events"][-1]
            self.assertEqual(second_event["detail"]["checkout_action"], "reused")
            self.assertFalse(second_event["detail"]["upstream_mirror_updated"])
            self.assertEqual(second_event["detail"]["secure_branch_action"], "preserved")

            git("-C", str(local_path), "config", "user.name", "Assured Test")
            git("-C", str(local_path), "config", "user.email", "assured@example.invalid")
            git("-C", str(local_path), "switch", "secure/main")
            (local_path / "overlay.txt").write_text("overlay\n", encoding="utf-8")
            git("-C", str(local_path), "add", "overlay.txt")
            git("-C", str(local_path), "commit", "-m", "add secure overlay")
            git("-C", str(local_path), "switch", "main")
            secure_before_sync = git(
                "-C",
                str(local_path),
                "rev-parse",
                "refs/heads/secure/main",
            )
            git(
                "-C",
                str(local_path),
                "config",
                "--replace-all",
                "remote.origin.fetch",
                "+refs/heads/*:refs/heads/secure/*",
            )

            (upstream_work / "upstream.txt").write_text("new upstream\n", encoding="utf-8")
            git("-C", str(upstream_work), "add", "upstream.txt")
            git("-C", str(upstream_work), "commit", "-m", "advance upstream")
            git("-C", str(upstream_work), "push", "origin", "main")

            third = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(third.succeeded, 1)
            self.assertEqual(third.review_required, 1)
            self.assertEqual(
                git(
                    "-C",
                    str(local_path),
                    "rev-parse",
                    "refs/heads/secure/main",
                ),
                secure_before_sync,
            )
            third_event = state.data["repositories"]["owner/upstream"]["events"][-1]
            self.assertEqual(third_event["event"], "SyncReviewRequired")
            self.assertTrue(third_event["detail"]["upstream_mirror_updated"])
            self.assertEqual(third_event["detail"]["secure_upstream_commits"], 1)
            self.assertEqual(third_event["detail"]["secure_unique_commits"], 1)
            self.assertTrue(third_event["detail"]["fork_default_update_required"])

    def test_live_reconciliation_blocks_wrong_origin_before_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _upstream_work, upstream_bare, target_bare = create_remote_fixture(root)
            plan = local_sync_plan(
                root,
                upstream_bare=upstream_bare,
                target_bare=target_bare,
            )
            local_path = Path(plan["repositories"][0]["local_path"])
            local_path.parent.mkdir(parents=True)
            git("clone", str(upstream_bare), str(local_path))
            state = StateStore.empty()

            result = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(result.succeeded, 0)
            self.assertEqual(result.failed, 1)
            event = state.data["repositories"]["owner/upstream"]["events"][-1]
            self.assertEqual(event["event"], "SyncConflict")
            self.assertIn("origin remote", event["detail"]["reason"])

    def test_live_reconciliation_preserves_validated_remote_transports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _upstream_work, upstream_bare, target_bare = create_remote_fixture(root)
            plan = local_sync_plan(
                root,
                upstream_bare=upstream_bare,
                target_bare=target_bare,
            )
            state = StateStore.empty()
            first = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )
            self.assertEqual(first.failed, 0)
            local_path = Path(plan["repositories"][0]["local_path"])
            origin_transport = target_bare.as_uri()
            upstream_transport = upstream_bare.as_uri()
            git(
                "-C",
                str(local_path),
                "remote",
                "set-url",
                "origin",
                origin_transport,
            )
            git(
                "-C",
                str(local_path),
                "remote",
                "set-url",
                "upstream",
                upstream_transport,
            )

            second = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(second.failed, 0)
            detail = state.data["repositories"]["owner/upstream"]["events"][-1][
                "detail"
            ]
            self.assertEqual(detail["origin_remote"]["url"], origin_transport)
            self.assertEqual(detail["upstream_remote"]["url"], upstream_transport)
            fetch_commands = [
                entry["command"]
                for entry in detail["commands"]
                if " fetch " in entry["command"]
            ]
            self.assertTrue(
                any(origin_transport in command for command in fetch_commands)
            )
            self.assertTrue(
                any(upstream_transport in command for command in fetch_commands)
            )

    def test_live_reconciliation_rejects_tampered_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _work, upstream_bare, target_bare = create_remote_fixture(root)
            plan = local_sync_plan(
                root,
                upstream_bare=upstream_bare,
                target_bare=target_bare,
            )
            plan["repositories"][0]["source_url"] = (
                "https://github.com/attacker/not-the-upstream.git"
            )
            state = StateStore.empty()

            result = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(result.failed, 1)
            self.assertFalse((root / "managed").exists())
            event = state.data["repositories"]["owner/upstream"]["events"][-1]
            self.assertIn("identity", event["detail"]["reason"])

    def test_live_reconciliation_rejects_tampered_branch_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _work, upstream_bare, target_bare = create_remote_fixture(root)
            plan = local_sync_plan(
                root,
                upstream_bare=upstream_bare,
                target_bare=target_bare,
            )
            plan["repositories"][0]["branch_model"]["secure_branch"] = "main"
            state = StateStore.empty()

            result = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(result.failed, 1)
            self.assertFalse((root / "managed").exists())
            event = state.data["repositories"]["owner/upstream"]["events"][-1]
            self.assertIn("branch model", event["detail"]["reason"])

    def test_live_reconciliation_records_malformed_plan_as_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _work, upstream_bare, target_bare = create_remote_fixture(root)
            plan = local_sync_plan(
                root,
                upstream_bare=upstream_bare,
                target_bare=target_bare,
            )
            plan["repositories"][0]["default_branch"] = "bad~branch"
            state = StateStore.empty()

            result = apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(result.failed, 1)
            self.assertFalse((root / "managed").exists())
            event = state.data["repositories"]["owner/upstream"]["events"][-1]
            self.assertEqual(event["event"], "SyncConflict")
            self.assertIn("invalid", event["detail"]["reason"])
            self.assertIn("default branch", event["detail"]["error"])


def local_sync_plan(
    root: Path,
    *,
    upstream_bare: Path,
    target_bare: Path,
) -> dict:
    return create_sync_plan(
        local_fork_plan(
            upstream_bare=upstream_bare,
            target_bare=target_bare,
        ),
        workspace=root / "managed",
        allow_local_remotes=True,
    )


if __name__ == "__main__":
    unittest.main()
