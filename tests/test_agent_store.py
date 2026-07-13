from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from assured_downstream.agent_contracts import (
    AgentResult,
    ArtifactOutput,
    EventOutput,
)
from assured_downstream.agent_store import AgentStore
from assured_downstream.secure_path import (
    directory_identity_record,
    secure_directory_identity,
)


class AgentStoreTests(unittest.TestCase):
    def test_deduplicates_events_and_scopes_claims_to_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp) / "agents.sqlite3")
            store.create_run("run-a", {"run_dir": tmp})
            store.create_run("run-b", {"run_dir": tmp})
            first = store.publish_event(
                run_id="run-a",
                event_type="Input",
                payload={"value": 1},
                agent_ids=["worker-agent"],
                dedupe_key="same-input",
            )
            duplicate = store.publish_event(
                run_id="run-a",
                event_type="Input",
                payload={"value": 1},
                agent_ids=["worker-agent"],
                dedupe_key="same-input",
            )
            store.publish_event(
                run_id="run-b",
                event_type="Input",
                payload={"value": 2},
                agent_ids=["worker-agent"],
                dedupe_key="same-input",
            )

            self.assertEqual(first.event_id, duplicate.event_id)
            with self.assertRaises(ValueError):
                store.publish_event(
                    run_id="run-a",
                    event_type="Input",
                    payload={"value": "different"},
                    agent_ids=["worker-agent"],
                    dedupe_key="same-input",
                )
            work = store.claim_work(
                worker_id="worker-b",
                agent_ids=["worker-agent"],
                run_id="run-b",
            )
            self.assertIsNotNone(work)
            assert work is not None
            self.assertEqual(work.run_id, "run-b")

    def test_expired_lease_is_recovered_and_retried(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp) / "agents.sqlite3")
            store.create_run("run", {"run_dir": tmp})
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["agent"],
            )
            first = store.claim_work(
                worker_id="worker-1",
                run_id="run",
                lease_seconds=-1,
            )
            second = store.claim_work(worker_id="worker-2", run_id="run")

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            assert first is not None and second is not None
            self.assertEqual(first.work_id, second.work_id)
            self.assertEqual(second.attempts, 2)
            store.complete_work(
                work=second,
                worker_id="worker-2",
                result=AgentResult(status="succeeded", summary="recovered"),
                routed_events=[],
            )
            self.assertEqual(store.work_status_counts("run"), {"succeeded": 1})

    def test_run_scoped_claim_does_not_recover_another_runs_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp) / "agents.sqlite3")
            store.create_run("run-a", {"run_dir": tmp})
            store.create_run("run-b", {"run_dir": tmp})
            for run_id in ("run-a", "run-b"):
                store.publish_event(
                    run_id=run_id,
                    event_type="Input",
                    payload={"run_id": run_id},
                    agent_ids=["agent"],
                )
            claimed_a = store.claim_work(
                worker_id="worker-a",
                run_id="run-a",
                lease_seconds=-1,
            )
            claimed_b = store.claim_work(worker_id="worker-b", run_id="run-b")

            self.assertIsNotNone(claimed_a)
            self.assertIsNotNone(claimed_b)
            self.assertEqual(store.work_status_counts("run-a"), {"running": 1})

    def test_retry_exhaustion_dead_letters_work_and_fails_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp) / "agents.sqlite3")
            store.create_run("run", {"run_dir": tmp})
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["agent"],
                max_attempts=2,
            )
            first = store.claim_work(worker_id="worker", run_id="run")
            assert first is not None
            self.assertEqual(
                store.fail_work(
                    work=first,
                    worker_id="worker",
                    error={"message": "first failure"},
                ),
                "queued",
            )
            second = store.claim_work(worker_id="worker", run_id="run")
            assert second is not None
            self.assertEqual(
                store.fail_work(
                    work=second,
                    worker_id="worker",
                    error={"message": "second failure"},
                ),
                "dead_letter",
            )
            self.assertEqual(store.get_run("run")["status"], "failed")
            self.assertEqual(store.work_status_counts("run"), {"dead_letter": 1})

    def test_final_expired_lease_dead_letters_work_and_fails_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp) / "agents.sqlite3")
            store.create_run("run", {"run_dir": tmp})
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["agent"],
                max_attempts=1,
            )
            claimed = store.claim_work(
                worker_id="abandoned-worker",
                run_id="run",
                lease_seconds=-1,
            )
            self.assertIsNotNone(claimed)
            self.assertIsNone(store.claim_work(worker_id="next-worker", run_id="run"))
            self.assertEqual(store.get_run("run")["status"], "failed")
            self.assertEqual(store.work_status_counts("run"), {"dead_letter": 1})

    def test_stale_attempt_cannot_complete_after_lease_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp) / "agents.sqlite3")
            store.create_run("run", {"run_dir": tmp})
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["agent"],
            )
            stale = store.claim_work(
                worker_id="same-worker",
                run_id="run",
                lease_seconds=-1,
            )
            replacement = store.claim_work(
                worker_id="same-worker",
                run_id="run",
            )
            assert stale is not None and replacement is not None

            with self.assertRaisesRegex(RuntimeError, "active lease"):
                store.complete_work(
                    work=stale,
                    worker_id="same-worker",
                    result=AgentResult(status="succeeded", summary="stale"),
                    routed_events=[],
                )
            store.complete_work(
                work=replacement,
                worker_id="same-worker",
                result=AgentResult(status="succeeded", summary="current"),
                routed_events=[],
            )

    def test_expired_lease_cannot_complete_without_recovery_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp) / "agents.sqlite3")
            store.create_run("run", {"run_dir": tmp})
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["agent"],
            )
            expired = store.claim_work(
                worker_id="worker",
                run_id="run",
                lease_seconds=-1,
            )
            assert expired is not None

            with self.assertRaisesRegex(RuntimeError, "active lease"):
                store.complete_work(
                    work=expired,
                    worker_id="worker",
                    result=AgentResult(status="succeeded", summary="late"),
                    routed_events=[],
                )

    def test_artifact_verification_detects_post_handoff_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = AgentStore(root / "agents.sqlite3")
            store.create_run("run", {"run_dir": tmp})
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["agent"],
            )
            work = store.claim_work(worker_id="worker", run_id="run")
            assert work is not None
            artifact = root / "artifact.json"
            artifact.write_text('{"state":"original"}\n', encoding="utf-8")
            store.complete_work(
                work=work,
                worker_id="worker",
                result=AgentResult(
                    status="succeeded",
                    summary="recorded",
                    artifacts=[ArtifactOutput(role="report", path=artifact)],
                ),
                routed_events=[],
            )
            self.assertTrue(store.verify_artifacts("run")["ok"])

            artifact.write_text('{"state":"tampered"}\n', encoding="utf-8")
            verification = store.verify_artifacts("run")
            self.assertFalse(verification["ok"])
            self.assertEqual(verification["failures"][0]["reason"], "digest_mismatch")

    def test_output_event_is_bound_to_its_successful_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp) / "agents.sqlite3")
            store.create_run("run", {"run_dir": tmp})
            source = store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["producer"],
            )
            work = store.claim_work(worker_id="worker", run_id="run")
            assert work is not None and work.current_attempt_id is not None
            output = EventOutput(
                event_type="Output",
                payload={"value": 1},
                dedupe_key="output",
            )

            completion = store.complete_work(
                work=work,
                worker_id="worker",
                result=AgentResult(
                    status="succeeded",
                    summary="produced",
                    events=[output],
                ),
                routed_events=[(output, [])],
            )
            event = store.get_event(completion["output_event_ids"][0])

            self.assertEqual(event.producer_agent_id, "producer")
            self.assertEqual(event.producer_attempt_id, work.current_attempt_id)
            self.assertEqual(event.causation_id, source.event_id)

    def test_v1_store_migration_backfills_producer_attempt_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "agents.sqlite3"
            store = AgentStore(database)
            store.create_run("run", {"run_dir": tmp})
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["producer"],
            )
            work = store.claim_work(worker_id="worker", run_id="run")
            assert work is not None and work.current_attempt_id is not None
            output = EventOutput(
                event_type="Output",
                payload={"value": 1},
                dedupe_key="output",
            )
            completion = store.complete_work(
                work=work,
                worker_id="worker",
                result=AgentResult(
                    status="succeeded",
                    summary="produced",
                    events=[output],
                ),
                routed_events=[(output, [])],
            )
            event_id = completion["output_event_ids"][0]
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "UPDATE events SET producer_attempt_id = NULL WHERE event_id = ?",
                    (event_id,),
                )
                connection.execute(
                    "UPDATE schema_metadata SET value = '1' WHERE key = 'schema_version'"
                )

            migrated = AgentStore(database)

            self.assertEqual(
                migrated.get_event(event_id).producer_attempt_id,
                work.current_attempt_id,
            )

    def test_attempt_scoped_persistence_rejects_symlinked_parent(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            run_dir = root / "run"
            run_dir.mkdir()
            store = AgentStore(root / "agents.sqlite3")
            store.create_run(
                "run",
                {
                    "run_dir": str(run_dir),
                    "artifact_scope": "attempt-scoped-v1",
                    "run_root_identity": directory_identity_record(
                        secure_directory_identity(run_dir)
                    ),
                },
            )
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["producer"],
            )
            work = store.claim_work(worker_id="worker", run_id="run")
            assert work is not None and work.current_attempt_id is not None
            outside = root / "outside"
            artifact_parent = outside / work.current_attempt_id / work.agent_id
            artifact_parent.mkdir(parents=True)
            (artifact_parent / "artifact.json").write_text(
                '{"outside":true}\n',
                encoding="utf-8",
            )
            (run_dir / "attempts").symlink_to(outside, target_is_directory=True)
            lexical_artifact = (
                run_dir
                / "attempts"
                / work.current_attempt_id
                / work.agent_id
                / "artifact.json"
            )

            with self.assertRaisesRegex(FileNotFoundError, "stable regular file"):
                store.complete_work(
                    work=work,
                    worker_id="worker",
                    result=AgentResult(
                        status="succeeded",
                        summary="hostile",
                        artifacts=[
                            ArtifactOutput(role="report", path=lexical_artifact)
                        ],
                    ),
                    routed_events=[],
                )

    def test_attempt_scoped_verification_rejects_replaced_parent(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            run_dir = root / "run"
            run_dir.mkdir()
            store = AgentStore(root / "agents.sqlite3")
            store.create_run(
                "run",
                {
                    "run_dir": str(run_dir),
                    "artifact_scope": "attempt-scoped-v1",
                    "run_root_identity": directory_identity_record(
                        secure_directory_identity(run_dir)
                    ),
                },
            )
            store.publish_event(
                run_id="run",
                event_type="Input",
                payload={},
                agent_ids=["producer"],
            )
            work = store.claim_work(worker_id="worker", run_id="run")
            assert work is not None and work.current_attempt_id is not None
            artifact = (
                run_dir
                / "attempts"
                / work.current_attempt_id
                / work.agent_id
                / "artifact.json"
            )
            artifact.parent.mkdir(parents=True)
            artifact.write_text('{"inside":true}\n', encoding="utf-8")
            store.complete_work(
                work=work,
                worker_id="worker",
                result=AgentResult(
                    status="succeeded",
                    summary="recorded",
                    artifacts=[ArtifactOutput(role="report", path=artifact)],
                ),
                routed_events=[],
            )
            retained_attempts = root / "retained-attempts"
            (run_dir / "attempts").rename(retained_attempts)
            (run_dir / "attempts").symlink_to(
                retained_attempts,
                target_is_directory=True,
            )

            verification = store.verify_artifacts("run")

            self.assertFalse(verification["ok"])
            self.assertEqual(verification["failures"][0]["reason"], "missing")


if __name__ == "__main__":
    unittest.main()
