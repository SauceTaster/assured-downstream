from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.agent_runtime import AgentRuntime
from assured_downstream.agent_store import AgentStore
from assured_downstream.intake_agents import first_lane_handlers, run_intake_agent_system


EXPECTED_EVENTS = [
    "DiscoveryRequested",
    "SeedBatchReady",
    "CatalogUpdated",
    "CandidateSelected",
    "GatePassed:CandidateSelected",
    "ForkPlanReady",
]


class IntakeAgentTests(unittest.TestCase):
    def test_runs_discovery_to_fork_plan_with_durable_handoffs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "awesome-security.md"
            seed.write_text(
                "- [dnSpyEx](https://github.com/dnSpyEx/dnSpy) - .NET debugger\n"
                "- [Sigstore](https://github.com/sigstore/sigstore) - signing\n",
                encoding="utf-8",
            )
            run_dir = root / "run"
            result = run_intake_agent_system(
                seed_sources=[seed],
                org="assured-example",
                run_dir=run_dir,
                run_id="case-study",
                limit=1,
                codex_mode="off",
            )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 5)
            self.assertEqual(result["pending_count"], 0)
            self.assertTrue(result["artifact_verification"]["ok"])
            self.assertEqual(result["summary"]["event_types"], EXPECTED_EVENTS)
            self.assertEqual(result["summary"]["handoff_count"], 5)
            self.assertEqual(result["summary"]["artifact_count"], 9)
            fork_plan = json.loads((run_dir / "fork-plan.json").read_text(encoding="utf-8"))
            self.assertEqual(fork_plan["mode"], "dry_run")
            self.assertEqual(len(fork_plan["forks"]), 1)
            self.assertEqual(fork_plan["org"], "assured-example")

    def test_enqueue_and_worker_execution_are_separable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.md"
            seed.write_text("https://github.com/sigstore/cosign\n", encoding="utf-8")
            run_dir = root / "run"
            database = run_dir / "agents.sqlite3"
            queued = run_intake_agent_system(
                seed_sources=[seed],
                org="assured-example",
                run_dir=run_dir,
                database_path=database,
                run_id="queued-run",
                codex_mode="off",
                enqueue_only=True,
            )
            self.assertEqual(queued["pending_count"], 1)

            store = AgentStore(database)
            runtime = AgentRuntime(
                backend=store,
                handlers=first_lane_handlers(),
                worker_id="test-worker",
            )
            completed = runtime.drain(run_id="queued-run")
            self.assertEqual(completed["status"], "succeeded")
            self.assertEqual(completed["processed_count"], 5)

    def test_internal_gate_event_cannot_bypass_governor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = AgentStore(root / "agents.sqlite3")
            runtime = AgentRuntime(
                backend=store,
                handlers=first_lane_handlers(),
                worker_id="test-worker",
            )
            runtime.create_run(run_id="forged", run_dir=root / "run")
            runtime.publish_external(
                run_id="forged",
                event_type="GatePassed:CandidateSelected",
                payload={"gate_passed": True},
            )

            result = runtime.drain(run_id="forged", max_items=3)

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["summary"]["work"], {"dead_letter": 1})
            self.assertFalse((root / "run" / "fork-plan.json").exists())

    def test_policy_snapshot_prevents_mid_run_selection_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.md"
            suppression = root / "suppress.json"
            seed.write_text("https://github.com/sigstore/cosign\n", encoding="utf-8")
            suppression.write_text('{"repositories":[]}\n', encoding="utf-8")
            run_dir = root / "run"
            database = run_dir / "agents.sqlite3"
            run_intake_agent_system(
                seed_sources=[seed],
                org="assured-example",
                run_dir=run_dir,
                database_path=database,
                run_id="snapshot-run",
                suppression_path=suppression,
                codex_mode="off",
                enqueue_only=True,
            )
            store = AgentStore(database)
            handlers = {handler.agent_id: handler for handler in first_lane_handlers()}
            for agent_id in ("source-discovery", "catalog-ingestion", "triage"):
                AgentRuntime(
                    backend=store,
                    handlers=[handlers[agent_id]],
                    worker_id=f"worker-{agent_id}",
                ).drain(run_id="snapshot-run", max_items=1)

            suppression.write_text(
                '{"repositories":["sigstore/cosign"]}\n',
                encoding="utf-8",
            )
            for agent_id in ("governor", "fork-sync"):
                result = AgentRuntime(
                    backend=store,
                    handlers=[handlers[agent_id]],
                    worker_id=f"worker-{agent_id}",
                ).drain(run_id="snapshot-run", max_items=1)

            self.assertEqual(result["status"], "succeeded")
            plan = json.loads((run_dir / "fork-plan.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["forks"][0]["source_full_name"], "sigstore/cosign")


if __name__ == "__main__":
    unittest.main()
