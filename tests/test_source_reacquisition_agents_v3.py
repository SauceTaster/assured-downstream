from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assured_downstream.agent_runtime import AgentRuntime
from assured_downstream.cli import main
from assured_downstream.evidence_agents import EvidenceLaneError
from assured_downstream.source_reacquisition_agents_v3 import (
    run_source_reacquisition_v3_agent_system,
)
from tests.test_source_reacquisition_v3 import (
    TEST_GIT_HTTPS_HELPER_PATH,
    TEST_GIT_HTTPS_HELPER_SHA256,
    TEST_GIT_PATH,
    TEST_GIT_SHA256,
    create_source_fixture,
)


class SourceReacquisitionV3AgentTests(unittest.TestCase):
    def test_durable_agent_reacquires_and_compares_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root / "fixture", object_format="sha1")
            arguments = {
                "trusted_inventory_path": fixture["report"],
                "source_ref": "refs/heads/main",
                "object_format": "sha1",
                "run_dir": root / "run",
                "execute_reacquisition": True,
                "git_path": TEST_GIT_PATH,
                "expected_git_sha256": TEST_GIT_SHA256,
                "https_helper_path": TEST_GIT_HTTPS_HELPER_PATH,
                "expected_https_helper_sha256": TEST_GIT_HTTPS_HELPER_SHA256,
                "run_id": "source-reacquisition-v3-match",
                "test_remote_url": str(fixture["remote"]),
                "allow_test_local_remote": True,
            }

            result = run_source_reacquisition_v3_agent_system(**arguments)

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 1)
            self.assertEqual(result["pending_count"], 0)
            self.assertEqual(result["artifact_verification"]["checked"], 2)
            self.assertTrue(result["artifact_verification"]["ok"])
            self.assertIn(
                "SourceReacquiredV3Compared",
                result["summary"]["event_types"],
            )
            report = read_json(Path(result["report"]["path"]))
            self.assertTrue(report["ok"])
            self.assertFalse(report["claims"]["upstream_lineage"])
            self.assertFalse(report["claims"]["provider_independent"])
            self.assertIn("attempts", Path(result["report"]["path"]).parts)
            self.assertFalse((root / "run" / "source-reacquisition-v3.json").exists())

            resumed = run_source_reacquisition_v3_agent_system(**arguments)
            self.assertEqual(resumed["processed_count"], 0)
            self.assertEqual(resumed["pending_count"], 0)
            self.assertTrue(resumed["artifact_verification"]["ok"])

            other = create_source_fixture(root / "other", object_format="sha1")
            with self.assertRaisesRegex(ValueError, "different configuration"):
                run_source_reacquisition_v3_agent_system(
                    **{**arguments, "test_remote_url": str(other["remote"])}
                )

    def test_resume_republishes_after_create_run_publish_crash_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root / "fixture", object_format="sha1")
            arguments = {
                "trusted_inventory_path": fixture["report"],
                "source_ref": "refs/heads/main",
                "object_format": "sha1",
                "run_dir": root / "run",
                "execute_reacquisition": True,
                "git_path": TEST_GIT_PATH,
                "expected_git_sha256": TEST_GIT_SHA256,
                "https_helper_path": TEST_GIT_HTTPS_HELPER_PATH,
                "expected_https_helper_sha256": TEST_GIT_HTTPS_HELPER_SHA256,
                "run_id": "source-reacquisition-v3-publish-recovery",
                "test_remote_url": str(fixture["remote"]),
                "allow_test_local_remote": True,
            }

            with patch.object(
                AgentRuntime,
                "publish_external",
                side_effect=RuntimeError("simulated crash before event publication"),
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    run_source_reacquisition_v3_agent_system(**arguments)

            recovered = run_source_reacquisition_v3_agent_system(**arguments)

            self.assertEqual(recovered["status"], "succeeded")
            self.assertEqual(recovered["summary"]["event_count"], 2)
            self.assertTrue(read_json(Path(recovered["report"]["path"]))["ok"])

    def test_manual_worker_reconstructs_the_bound_test_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root / "fixture", object_format="sha1")
            queued = run_source_reacquisition_v3_agent_system(
                trusted_inventory_path=fixture["report"],
                source_ref="refs/heads/main",
                object_format="sha1",
                run_dir=root / "run",
                execute_reacquisition=True,
                git_path=TEST_GIT_PATH,
                expected_git_sha256=TEST_GIT_SHA256,
                https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                run_id="source-reacquisition-v3-manual-worker",
                enqueue_only=True,
                test_remote_url=str(fixture["remote"]),
                allow_test_local_remote=True,
            )

            self.assertEqual(queued["pending_count"], 1)
            exit_code = main(
                [
                    "agent-worker",
                    "--database",
                    queued["database_path"],
                    "--run-id",
                    queued["run_id"],
                    "--agent",
                    "source-reacquirer-v3",
                ]
            )

            self.assertEqual(exit_code, 0)
            reports = list(
                (root / "run" / "attempts").glob("*/source-reacquisition-v3.json")
            )
            self.assertEqual(len(reports), 1)
            self.assertTrue(read_json(reports[0])["ok"])

    def test_mismatch_is_blocked_and_retained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root / "fixture", object_format="sha1")
            trusted = read_json(fixture["report"])
            entry = next(
                item
                for item in trusted["inventory"]["entries"]
                if item["path"] == "README.md"
            )
            entry["size"] += 1
            trusted["inventory"]["tree_sha256"] = inventory_digest(
                trusted["inventory"]["entries"]
            )
            write_json(fixture["report"], trusted)

            result = run_source_reacquisition_v3_agent_system(
                trusted_inventory_path=fixture["report"],
                source_ref="refs/heads/main",
                object_format="sha1",
                run_dir=root / "run",
                execute_reacquisition=True,
                git_path=TEST_GIT_PATH,
                expected_git_sha256=TEST_GIT_SHA256,
                https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                run_id="source-reacquisition-v3-mismatch",
                test_remote_url=str(fixture["remote"]),
                allow_test_local_remote=True,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "SourceReacquisitionV3Mismatch",
                result["summary"]["event_types"],
            )
            report = read_json(Path(result["report"]["path"]))
            self.assertEqual(report["status"], "mismatch")
            self.assertFalse(report["ok"])

    def test_fetch_failure_is_a_durable_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root / "fixture", object_format="sha1")

            result = run_source_reacquisition_v3_agent_system(
                trusted_inventory_path=fixture["report"],
                source_ref="refs/heads/missing",
                object_format="sha1",
                run_dir=root / "run",
                execute_reacquisition=True,
                git_path=TEST_GIT_PATH,
                expected_git_sha256=TEST_GIT_SHA256,
                https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                run_id="source-reacquisition-v3-rejected",
                test_remote_url=str(fixture["remote"]),
                allow_test_local_remote=True,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "SourceReacquisitionV3Rejected",
                result["summary"]["event_types"],
            )
            rejection = read_json(Path(result["report"]["path"]))
            self.assertEqual(rejection["status"], "rejected")
            self.assertFalse(rejection["claims"]["source_reacquisition_match"])

    def test_network_execution_and_regular_input_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root / "fixture", object_format="sha1")
            with self.assertRaisesRegex(ValueError, "execute-reacquisition"):
                run_source_reacquisition_v3_agent_system(
                    trusted_inventory_path=fixture["report"],
                    source_ref="refs/heads/main",
                    object_format="sha1",
                    run_dir=root / "not-executed",
                    execute_reacquisition=False,
                    git_path=TEST_GIT_PATH,
                    expected_git_sha256=TEST_GIT_SHA256,
                    https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                    expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                )

            alias = root / "trusted-alias.json"
            alias.symlink_to(fixture["report"])
            with self.assertRaises(EvidenceLaneError):
                run_source_reacquisition_v3_agent_system(
                    trusted_inventory_path=alias,
                    source_ref="refs/heads/main",
                    object_format="sha1",
                    run_dir=root / "symlink",
                    execute_reacquisition=True,
                    git_path=TEST_GIT_PATH,
                    expected_git_sha256=TEST_GIT_SHA256,
                    https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                    expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                    test_remote_url=str(fixture["remote"]),
                    allow_test_local_remote=True,
                )


def inventory_digest(entries: list[dict]) -> str:
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
