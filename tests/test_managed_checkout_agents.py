from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from assured_downstream.agent_runtime import AgentRuntime
from assured_downstream.agent_store import AgentStore
from assured_downstream.lifecycle import StateStore
from assured_downstream.managed_checkout_agents import (
    managed_checkout_handlers,
    run_managed_checkout_agent_system,
    write_json_atomic,
)
from tests.git_test_support import create_remote_fixture, git, local_fork_plan


class ManagedCheckoutAgentTests(unittest.TestCase):
    def test_reconciles_recons_and_plans_overlays_through_durable_handoffs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _work, upstream_bare, target_bare = create_remote_fixture(root)
            fork_plan_path = root / "fork-plan.json"
            write_json(
                fork_plan_path,
                local_fork_plan(
                    upstream_bare=upstream_bare,
                    target_bare=target_bare,
                ),
            )
            state_path = root / "fork-state.json"
            verified_fork_state().save(state_path)
            run_dir = root / "run"

            result = run_managed_checkout_agent_system(
                fork_plan_path=fork_plan_path,
                state_path=state_path,
                workspace=root / "managed",
                run_dir=run_dir,
                run_id="managed-checkout",
                execute_sync=True,
                allow_local_test_remotes=True,
            )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 3)
            self.assertEqual(result["pending_count"], 0)
            self.assertTrue(result["artifact_verification"]["ok"])
            self.assertEqual(
                result["summary"]["event_types"],
                [
                    "UpstreamChanged",
                    "SyncReady",
                    "CheckoutAnalyzed",
                    "AnalysisBundleReady",
                ],
            )
            self.assertEqual(result["summary"]["handoff_count"], 3)
            self.assertEqual(result["summary"]["artifact_count"], 9)

            analysis = read_json(run_dir / "analysis-index.json")
            self.assertEqual(analysis["assurance_target"], "Attested")
            self.assertEqual(analysis["repository_count"], 1)
            repository = analysis["repositories"][0]
            self.assertTrue(Path(repository["overlay_plan_path"]).is_file())
            self.assertTrue(Path(repository["release_profile_path"]).is_file())
            self.assertTrue(repository["release_human_review_required"])
            release_profile = read_json(Path(repository["release_profile_path"]))
            self.assertEqual(
                release_profile["lineage"]["source_full_name"],
                "owner/upstream",
            )
            self.assertEqual(
                release_profile["lineage"]["upstream_ref"],
                repository["analysis_sha"],
            )

            resumed = run_managed_checkout_agent_system(
                fork_plan_path=fork_plan_path,
                state_path=state_path,
                workspace=root / "managed",
                run_dir=run_dir,
                run_id="managed-checkout",
                execute_sync=True,
                allow_local_test_remotes=True,
            )
            self.assertEqual(resumed["status"], "succeeded")
            self.assertEqual(resumed["processed_count"], 0)

            enqueue_resume = run_managed_checkout_agent_system(
                fork_plan_path=fork_plan_path,
                state_path=state_path,
                workspace=root / "managed",
                run_dir=run_dir,
                run_id="managed-checkout",
                execute_sync=True,
                enqueue_only=True,
                allow_local_test_remotes=True,
            )
            self.assertEqual(enqueue_resume["status"], "succeeded")
            self.assertEqual(enqueue_resume["processed_count"], 0)
            self.assertEqual(enqueue_resume["pending_count"], 0)

    def test_execute_blocks_unverified_fork_state_before_clone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _work, upstream_bare, target_bare = create_remote_fixture(root)
            fork_plan_path = root / "fork-plan.json"
            write_json(
                fork_plan_path,
                local_fork_plan(
                    upstream_bare=upstream_bare,
                    target_bare=target_bare,
                ),
            )
            state = StateStore.empty()
            state.record(
                source_full_name="owner/upstream",
                target_full_name="user/target",
                event="ForkPlanned",
                status="ok",
            )
            state_path = root / "fork-state.json"
            state.save(state_path)
            workspace = root / "managed"

            result = run_managed_checkout_agent_system(
                fork_plan_path=fork_plan_path,
                state_path=state_path,
                workspace=workspace,
                run_dir=root / "run",
                run_id="blocked-checkout",
                execute_sync=True,
                allow_local_test_remotes=True,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["processed_count"], 1)
            self.assertFalse(workspace.exists())
            gate = read_json(root / "run" / "sync-gate-decision.json")
            checks = {item["check"]: item["passed"] for item in gate["checks"]}
            self.assertFalse(checks["fork-lineage-state"])

    def test_recon_analyzes_exact_synchronized_upstream_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upstream_work, upstream_bare, target_bare = create_remote_fixture(root)
            (upstream_work / "upstream_only.py").write_text(
                "print('new upstream')\n",
                encoding="utf-8",
            )
            git("-C", str(upstream_work), "add", "upstream_only.py")
            git("-C", str(upstream_work), "commit", "-m", "advance upstream")
            git("-C", str(upstream_work), "push", "origin", "main")
            upstream_sha = git("-C", str(upstream_work), "rev-parse", "HEAD")

            fork_plan_path = root / "fork-plan.json"
            write_json(
                fork_plan_path,
                local_fork_plan(
                    upstream_bare=upstream_bare,
                    target_bare=target_bare,
                ),
            )
            state_path = root / "fork-state.json"
            verified_fork_state().save(state_path)
            run_dir = root / "run"

            result = run_managed_checkout_agent_system(
                fork_plan_path=fork_plan_path,
                state_path=state_path,
                workspace=root / "managed",
                run_dir=run_dir,
                run_id="upstream-snapshot",
                execute_sync=True,
                allow_local_test_remotes=True,
            )

            self.assertEqual(result["status"], "succeeded")
            analysis = read_json(run_dir / "analysis-index.json")
            repository = analysis["repositories"][0]
            self.assertEqual(repository["analysis_sha"], upstream_sha)
            self.assertEqual(
                git("-C", repository["analysis_path"], "rev-parse", "HEAD"),
                upstream_sha,
            )
            recon = read_json(Path(repository["recon_path"]))
            self.assertIn("Python", recon["languages"])
            self.assertNotEqual(
                git("-C", repository["local_path"], "rev-parse", "HEAD"),
                upstream_sha,
            )

    def test_recon_rejects_tampered_sync_plan_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _work, upstream_bare, target_bare = create_remote_fixture(root)
            fork_plan_path = root / "fork-plan.json"
            write_json(
                fork_plan_path,
                local_fork_plan(
                    upstream_bare=upstream_bare,
                    target_bare=target_bare,
                ),
            )
            state_path = root / "fork-state.json"
            verified_fork_state().save(state_path)
            run_dir = root / "run"
            database = run_dir / "agents.sqlite3"
            run_managed_checkout_agent_system(
                fork_plan_path=fork_plan_path,
                state_path=state_path,
                workspace=root / "managed",
                run_dir=run_dir,
                database_path=database,
                run_id="tampered-handoff",
                execute_sync=True,
                enqueue_only=True,
                allow_local_test_remotes=True,
            )
            store = AgentStore(database)
            runtime = AgentRuntime(
                backend=store,
                handlers=managed_checkout_handlers(allow_local_test_remotes=True),
                worker_id="test-worker",
            )
            first = runtime.run_once(run_id="tampered-handoff")
            self.assertEqual(first["agent_id"], "fork-sync")
            with (run_dir / "sync-plan.json").open("a", encoding="utf-8") as handle:
                handle.write("\n")

            result = runtime.drain(run_id="tampered-handoff", max_items=3)

            self.assertEqual(result["status"], "failed")
            self.assertFalse((run_dir / "recon-index.json").exists())

    def test_atomic_writer_uses_collision_safe_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "result.json"

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(
                    executor.map(
                        lambda value: write_json_atomic(path, {"value": value}),
                        range(32),
                    )
                )

            payload = read_json(path)
            self.assertIn(payload["value"], range(32))
            self.assertEqual(list(root.glob(".result.json.*.tmp")), [])


def verified_fork_state() -> StateStore:
    state = StateStore.empty()
    state.record(
        source_full_name="owner/upstream",
        target_full_name="user/target",
        event="ForkVerified",
        status="ok",
    )
    return state


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
