from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.evidence_agents import (
    EvidenceLaneError,
    run_release_evidence_agent_system,
)


class EvidenceAgentTests(unittest.TestCase):
    def test_ingests_build_trace_and_attestation_through_durable_agents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            run_dir = root / "run"

            result = run_lane(inputs, run_dir=run_dir, allow_test_fixture=True)

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 4)
            self.assertEqual(result["pending_count"], 0)
            self.assertTrue(result["artifact_verification"]["ok"])
            self.assertEqual(
                result["summary"]["event_types"],
                [
                    "BuildResultRecorded",
                    "BuildArtifactsReady",
                    "TraceReady",
                    "ReleaseEvidenceReady",
                    "EvidenceCandidateReady",
                ],
            )
            self.assertEqual(result["summary"]["handoff_count"], 4)
            evaluation = read_json(run_dir / "release-evaluation.json")
            self.assertEqual(evaluation["decision"], "candidate")
            self.assertTrue(evaluation["trace_coverage"]["syscall"])
            self.assertIn("caller-supplied evidence shape", evaluation["claim_limit"])
            self.assertIn("untrusted input shape", evaluation["authority"])
            self.assertTrue((run_dir / "evidence.json").is_file())
            self.assertTrue((run_dir / "VERIFY.md").is_file())

            resumed = run_lane(inputs, run_dir=run_dir, allow_test_fixture=True)
            self.assertEqual(resumed["status"], "succeeded")
            self.assertEqual(resumed["processed_count"], 0)

    def test_fixture_builder_is_never_allowed_by_production_cli_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)

            result = run_lane(
                inputs,
                run_dir=root / "run",
                allow_test_fixture=False,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["processed_count"], 1)
            decision = read_json(root / "run" / "build-intake-decision.json")
            failed = [
                check["check"] for check in decision["checks"] if not check["passed"]
            ]
            self.assertEqual(failed, ["builder-mode"])

    def test_trace_policy_blocks_successful_network_activity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root, successful_network=True)

            result = run_lane(
                inputs,
                run_dir=root / "run",
                allow_test_fixture=True,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["processed_count"], 2)
            policy = read_json(root / "run" / "trace-policy.json")
            self.assertFalse(policy["passed"])
            self.assertIn("network activity succeeded", policy["failures"][0])

    def test_rejects_evidence_path_traversal_before_enqueue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            build_result = read_json(inputs["build_result_path"])
            build_result["evidence"]["artifacts"] = ["../artifact.bin"]
            write_json(inputs["build_result_path"], build_result)

            with self.assertRaisesRegex(EvidenceLaneError, "escapes its root"):
                run_lane(
                    inputs,
                    run_dir=root / "run",
                    allow_test_fixture=True,
                )


def write_inputs(root: Path, *, successful_network: bool = False) -> dict[str, Path]:
    evidence_root = root / "evidence-input"
    (evidence_root / "dist").mkdir(parents=True)
    (evidence_root / "sbom").mkdir()
    (evidence_root / "attestations").mkdir()
    (evidence_root / "traces").mkdir()
    (evidence_root / "reports").mkdir()
    artifact = evidence_root / "dist" / "artifact.bin"
    artifact.write_bytes(b"isolated fixture artifact\n")
    (evidence_root / "sbom" / "sbom.spdx.json").write_text(
        '{"spdxVersion":"SPDX-2.3","name":"fixture"}\n',
        encoding="utf-8",
    )
    (evidence_root / "attestations" / "artifact.sigstore.json").write_text(
        '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n',
        encoding="utf-8",
    )
    network_outcome = "success" if successful_network else "denied"
    write_json(
        evidence_root / "traces" / "raw-trace.json",
        {
            "schema_version": 1,
            "collector": {
                "name": "fixture-v1",
                "version": "1",
                "platform": "linux",
            },
            "coverage": {
                "process": True,
                "file": True,
                "network": True,
                "syscall": True,
            },
            "events": [
                {
                    "kind": "process",
                    "parent_exe": "/usr/bin/env",
                    "exe": "/workspace/.venv/bin/python",
                    "argv": ["python", "-m", "build"],
                },
                {
                    "kind": "file",
                    "operation": "write",
                    "path": "/workspace/dist/artifact.bin",
                    "outcome": "success",
                },
                {
                    "kind": "network",
                    "host": "pypi.org",
                    "port": 443,
                    "outcome": network_outcome,
                },
                {
                    "kind": "syscall",
                    "name": "mount",
                    "outcome": "denied",
                },
            ],
        },
    )
    (evidence_root / "reports" / "builder.json").write_text(
        '{"runner":"fixture"}\n',
        encoding="utf-8",
    )
    build_result_path = root / "build-result.json"
    write_json(
        build_result_path,
        {
            "schema_version": 1,
            "status": "succeeded",
            "project": {
                "source_full_name": "owner/project",
                "target_full_name": "SauceTaster/assured-project",
                "upstream_ref": "a" * 40,
                "overlay_ref": "b" * 40,
                "release_tag": "secure-v0.0.0+fixture",
            },
            "builder": {
                "mode": "test-fixture",
                "builder_id": "fixture-builder-v1",
                "isolated": True,
                "secrets_exposed": False,
                "network_policy": "deny",
                "workspace_root": "/workspace",
            },
            "evidence": {
                "artifacts": ["dist/artifact.bin"],
                "sboms": ["sbom/sbom.spdx.json"],
                "attestations": ["attestations/artifact.sigstore.json"],
                "raw_traces": ["traces/raw-trace.json"],
                "reports": ["reports/builder.json"],
            },
        },
    )
    controls = root / "controls"
    controls.mkdir()
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    attestation_verification_path = controls / "attestation-verification.json"
    write_json(
        attestation_verification_path,
        {
            "ok": True,
            "verification_type": "sigstore-bundle",
            "issuer": "https://token.actions.githubusercontent.com",
            "signer": "owner/project/.github/workflows/release.yml",
            "verified_subjects": [{"sha256": artifact_sha}],
        },
    )
    tooling_verification_path = controls / "tooling-verification.json"
    write_json(
        tooling_verification_path,
        {
            "ok": True,
            "policy_sha256": "1" * 64,
            "lock_sha256": "2" * 64,
        },
    )
    workflow_risk_verification_path = controls / "workflow-risk-verification.json"
    write_json(
        workflow_risk_verification_path,
        {
            "ok": True,
            "analyzed_workflow_sha256": "3" * 64,
            "findings": [],
        },
    )
    return {
        "build_result_path": build_result_path,
        "evidence_root": evidence_root,
        "attestation_verification_path": attestation_verification_path,
        "tooling_verification_path": tooling_verification_path,
        "workflow_risk_verification_path": workflow_risk_verification_path,
    }


def run_lane(
    inputs: dict[str, Path],
    *,
    run_dir: Path,
    allow_test_fixture: bool,
) -> dict:
    return run_release_evidence_agent_system(
        **inputs,
        run_dir=run_dir,
        run_id="evidence-agent-test",
        allow_test_fixture=allow_test_fixture,
    )


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
