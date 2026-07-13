from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from assured_downstream.agent_runtime import AgentRuntime
from assured_downstream.agent_contracts import (
    AgentContext,
    AgentResult,
    ArtifactOutput,
    EventRecord,
    WorkItem,
)
from assured_downstream.agent_store import AgentStore
from assured_downstream.lifecycle import StateStore
from assured_downstream.managed_checkout_agents import (
    read_verified_attempt_json,
    managed_checkout_handlers,
    run_managed_checkout_agent_system,
    write_attempt_json,
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
            self.assertEqual(result["processed_count"], 4)
            self.assertEqual(result["pending_count"], 0)
            self.assertTrue(result["artifact_verification"]["ok"])
            self.assertEqual(
                result["summary"]["event_types"],
                [
                    "UpstreamChanged",
                    "SyncReady",
                    "CheckoutAnalyzed",
                    "BuildProfilesPlanned",
                    "AnalysisBundleReady",
                ],
            )
            self.assertEqual(result["summary"]["handoff_count"], 4)
            self.assertEqual(result["summary"]["artifact_count"], 11)
            with sqlite3.connect(run_dir / "agent-control-plane.sqlite3") as connection:
                persisted = connection.execute(
                    """
                    SELECT artifacts.path, work_items.agent_id, attempts.attempt_id
                    FROM artifacts
                    JOIN work_items USING(work_id)
                    JOIN attempts USING(work_id)
                    WHERE attempts.status = 'succeeded'
                    ORDER BY artifacts.path
                    """
                ).fetchall()
            self.assertEqual(len(persisted), 11)
            for path, agent_id, attempt_id in persisted:
                self.assertTrue(
                    Path(path).is_relative_to(
                        run_dir.resolve() / "attempts" / attempt_id / agent_id
                    )
                )

            analysis = read_json(
                only_attempt_artifact(run_dir, "overlay-planner", "analysis-index.json")
            )
            self.assertEqual(analysis["assurance_target"], "Attested")
            self.assertEqual(analysis["repository_count"], 1)
            repository = analysis["repositories"][0]
            self.assertTrue(Path(repository["overlay_plan_path"]).is_file())
            self.assertTrue(Path(repository["release_profile_path"]).is_file())
            self.assertTrue(repository["release_human_review_required"])
            self.assertFalse(repository["ecosystem_execution_permitted"])
            self.assertTrue(Path(repository["ecosystem_profile_path"]).is_file())
            ecosystem_profile = read_json(
                Path(repository["ecosystem_profile_path"])
            )
            self.assertEqual(
                ecosystem_profile["source"]["identity_binding"],
                "verified-managed-handoff",
            )
            self.assertEqual(
                ecosystem_profile["source"]["git_tree"],
                repository["analysis_git_tree"],
            )
            self.assertIn(
                "/attempts/",
                repository["ecosystem_profile_path"],
            )
            for path_key in (
                "analysis_path",
                "recon_path",
                "ecosystem_profile_path",
                "overlay_plan_path",
                "release_profile_path",
            ):
                self.assertIn("/attempts/", repository[path_key])
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
            gate = read_json(
                only_attempt_artifact(
                    root / "run", "fork-sync", "sync-gate-decision.json"
                )
            )
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
            analysis = read_json(
                only_attempt_artifact(run_dir, "overlay-planner", "analysis-index.json")
            )
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
            sync_plan_path = only_attempt_artifact(
                run_dir, "fork-sync", "sync-plan.json"
            )
            with sync_plan_path.open("a", encoding="utf-8") as handle:
                handle.write("\n")

            result = runtime.drain(run_id="tampered-handoff", max_items=3)

            self.assertEqual(result["status"], "failed")
            self.assertEqual(
                list(run_dir.glob("attempts/*/recon/recon-index.json")),
                [],
            )

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

    def test_attempt_reader_rejects_path_outside_producer_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            run_dir.mkdir()
            outside = root / "outside.json"
            payload = b'{"outside": true}\n'
            outside.write_bytes(payload)
            context = fake_context(run_dir, agent_id="recon", attempt_id="b" * 32)
            reference = {
                "path": str(outside),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "producer_agent_id": "fork-sync",
                "producer_attempt_id": "a" * 32,
            }

            with self.assertRaisesRegex(ValueError, "escapes"):
                read_verified_attempt_json(
                    context,
                    reference,
                    expected_agent_id="fork-sync",
                    label="hostile handoff",
                )

    def test_attempt_reader_rejects_symlinked_producer_directory(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            producer_root = run_dir / "attempts" / ("a" * 32)
            producer_root.mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            payload = b'{"outside": true}\n'
            (outside / "sync-plan.json").write_bytes(payload)
            (producer_root / "fork-sync").symlink_to(
                outside,
                target_is_directory=True,
            )
            context = fake_context(run_dir, agent_id="recon", attempt_id="b" * 32)
            reference = {
                "path": str(producer_root / "fork-sync" / "sync-plan.json"),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "producer_agent_id": "fork-sync",
                "producer_attempt_id": "a" * 32,
            }

            with self.assertRaisesRegex(ValueError, "symlink"):
                read_verified_attempt_json(
                    context,
                    reference,
                    expected_agent_id="fork-sync",
                    label="hostile handoff",
                )

    def test_attempt_reader_rejects_reference_to_a_different_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            artifact = (
                run_dir
                / "attempts"
                / ("a" * 32)
                / "fork-sync"
                / "sync-plan.json"
            )
            artifact.parent.mkdir(parents=True)
            payload = b'{"old": true}\n'
            artifact.write_bytes(payload)
            context = fake_context(
                run_dir,
                agent_id="recon",
                attempt_id="b" * 32,
                producer_attempt_id="c" * 32,
            )
            reference = {
                "path": str(artifact),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "producer_agent_id": "fork-sync",
                "producer_attempt_id": "a" * 32,
            }

            with self.assertRaisesRegex(ValueError, "producing event"):
                read_verified_attempt_json(
                    context,
                    reference,
                    expected_agent_id="fork-sync",
                    label="stale handoff",
                )

    def test_attempt_reader_and_writer_reject_replaced_run_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            run_dir = root / "run"
            artifact = (
                run_dir
                / "attempts"
                / ("a" * 32)
                / "fork-sync"
                / "sync-plan.json"
            )
            artifact.parent.mkdir(parents=True)
            payload = b'{"original": true}\n'
            artifact.write_bytes(payload)
            context = fake_context(
                run_dir,
                agent_id="recon",
                attempt_id="b" * 32,
            )
            retained = root / "retained-run"
            run_dir.rename(retained)
            replacement = (
                run_dir
                / "attempts"
                / ("a" * 32)
                / "fork-sync"
                / "sync-plan.json"
            )
            replacement.parent.mkdir(parents=True)
            replacement.write_bytes(payload)
            reference = {
                "path": str(replacement),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "producer_agent_id": "fork-sync",
                "producer_attempt_id": "a" * 32,
            }

            with self.assertRaisesRegex(ValueError, "identity changed"):
                read_verified_attempt_json(
                    context,
                    reference,
                    expected_agent_id="fork-sync",
                    label="replaced handoff",
                )
            with self.assertRaisesRegex(ValueError, "identity changed"):
                write_attempt_json(context, Path("result.json"), {"bad": True})

    def test_retry_writes_distinct_attempt_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = AgentStore(root / "agents.sqlite3")
            handler = RetryingAttemptHandler()
            runtime = AgentRuntime(
                backend=store,
                handlers=[handler],
                routes={"RetryRequested": [handler.agent_id]},
                worker_id="retry-worker",
            )
            runtime.create_run(
                run_id="attempt-retry",
                run_dir=root / "run",
                metadata={"artifact_scope": "attempt-scoped-v1"},
            )
            runtime.publish_external(
                run_id="attempt-retry",
                event_type="RetryRequested",
                payload={},
            )

            first = runtime.run_once(run_id="attempt-retry")
            second = runtime.run_once(run_id="attempt-retry")

            self.assertEqual(first["status"], "queued")
            self.assertEqual(second["status"], "succeeded")
            self.assertEqual(len(handler.paths), 2)
            self.assertNotEqual(handler.paths[0], handler.paths[1])
            self.assertEqual(
                [read_json(path)["ordinal"] for path in handler.paths],
                [1, 2],
            )
            self.assertEqual(store.verify_artifacts("attempt-retry")["checked"], 1)


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


def only_attempt_artifact(run_dir: Path, agent_id: str, name: str) -> Path:
    matches = list(run_dir.glob(f"attempts/*/{agent_id}/{name}"))
    if len(matches) != 1:
        raise AssertionError(
            f"Expected one {agent_id}/{name} attempt artifact, found {matches}"
        )
    return matches[0]


def fake_context(
    run_dir: Path,
    *,
    agent_id: str,
    attempt_id: str,
    producer_attempt_id: str = "a" * 32,
) -> AgentContext:
    return AgentContext(
        run_id="fake-run",
        run_dir=run_dir,
        worker_id="fake-worker",
        work=WorkItem(
            work_id="fake-work",
            run_id="fake-run",
            event_id="fake-event",
            agent_id=agent_id,
            status="running",
            attempts=1,
            max_attempts=3,
            lease_owner="fake-worker",
            lease_expires_at="2999-01-01T00:00:00+00:00",
            current_attempt_id=attempt_id,
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
        ),
        event=EventRecord(
            event_id="fake-event",
            run_id="fake-run",
            event_type="FakeEvent",
            payload={},
            payload_sha256="0" * 64,
            created_at="2026-01-01T00:00:00+00:00",
            producer_agent_id="fork-sync",
            producer_attempt_id=producer_attempt_id,
        ),
        run_metadata={
            "run_dir": str(run_dir),
            "run_root_identity": {
                "device": run_dir.stat().st_dev,
                "inode": run_dir.stat().st_ino,
            },
        },
    )


class RetryingAttemptHandler:
    agent_id = "retry-test"

    def __init__(self) -> None:
        self.paths: list[Path] = []

    def handle(self, context: AgentContext) -> AgentResult:
        ordinal = len(self.paths) + 1
        path = write_attempt_json(
            context,
            Path("result.json"),
            {"ordinal": ordinal},
        )
        self.paths.append(path)
        if ordinal == 1:
            raise RuntimeError("planned retry")
        return AgentResult(
            status="succeeded",
            summary="retry completed",
            artifacts=[ArtifactOutput(role="retry-result", path=path)],
        )


if __name__ == "__main__":
    unittest.main()
