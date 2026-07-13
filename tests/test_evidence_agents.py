from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest.mock import patch

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
            self.assertEqual(result["processed_count"], 5)
            self.assertEqual(result["pending_count"], 0)
            self.assertTrue(result["artifact_verification"]["ok"])
            self.assertEqual(
                result["summary"]["event_types"],
                [
                    "BuildResultRecorded",
                    "BuildArtifactsReady",
                    "TraceReady",
                    "ReleaseEvidenceReady",
                    "ReleaseAttestationsVerified",
                    "EvidenceCandidateReady",
                ],
            )
            self.assertEqual(result["summary"]["handoff_count"], 5)
            evaluation = read_json(run_dir / "release-evaluation.json")
            self.assertEqual(evaluation["decision"], "candidate")
            self.assertTrue(evaluation["trace_coverage"]["syscall"])
            self.assertIn("tooling and builder claims", evaluation["claim_limit"])
            self.assertIn("untrusted input shape", evaluation["authority"])
            self.assertEqual(
                evaluation["attestation_authority"],
                "test-fixture-non-authoritative",
            )
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

    def test_release_verification_rejection_is_a_durable_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)

            result = run_lane(
                inputs,
                run_dir=root / "run",
                allow_test_fixture=True,
                use_fixture_verifier=False,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["processed_count"], 4)
            self.assertIn(
                "ReleaseAttestationsRejected",
                result["summary"]["event_types"],
            )
            rejection = read_json(
                root / "run" / "release-attestation-verification.json"
            )
            self.assertEqual(rejection["status"], "rejected")
            self.assertIn("not anchored", rejection["error"])

    def test_post_verification_record_failure_is_a_durable_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)

            result = run_lane(
                inputs,
                run_dir=root / "run",
                allow_test_fixture=True,
                fixture_verifier=invalid_fixture_release_verifier,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "ReleaseAttestationsRejected",
                result["summary"]["event_types"],
            )
            rejection = read_json(
                root / "run" / "release-attestation-verification.json"
            )
            self.assertIn("authority is invalid", rejection["error"])

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
    for name in (
        "provenance.sigstore.json",
        "sbom.sigstore.json",
        "policy.sigstore.json",
    ):
        (evidence_root / "attestations" / name).write_text(
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
                "attestations": [
                    "attestations/provenance.sigstore.json",
                    "attestations/sbom.sigstore.json",
                    "attestations/policy.sigstore.json",
                ],
                "raw_traces": ["traces/raw-trace.json"],
                "reports": ["reports/builder.json"],
            },
        },
    )
    controls = root / "controls"
    controls.mkdir()
    release_verification_policy_path = controls / "release-verification-policy.json"
    write_json(
        release_verification_policy_path,
        {
            "schema_version": 1,
            "status": "test-fixture-only",
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
        "release_verification_policy_path": release_verification_policy_path,
        "tooling_verification_path": tooling_verification_path,
        "workflow_risk_verification_path": workflow_risk_verification_path,
    }


def run_lane(
    inputs: dict[str, Path],
    *,
    run_dir: Path,
    allow_test_fixture: bool,
    use_fixture_verifier: bool = True,
    fixture_verifier: Callable[..., dict] | None = None,
) -> dict:
    kwargs = {
        **inputs,
        "run_dir": run_dir,
        "run_id": "evidence-agent-test",
        "allow_test_fixture": allow_test_fixture,
    }
    if allow_test_fixture and use_fixture_verifier:
        with patch(
            "assured_downstream.evidence_agents.verify_release_attestations",
            side_effect=fixture_verifier or fixture_release_verifier,
        ):
            return run_release_evidence_agent_system(**kwargs)
    return run_release_evidence_agent_system(**kwargs)


def fixture_release_verifier(*, evidence_path: Path, policy_path: Path) -> dict:
    del policy_path
    manifest = read_json(evidence_path)
    project = manifest["project"]
    return {
        "schema_version": 1,
        "status": "verified",
        "ok": True,
        "authority": "test-fixture-non-authoritative",
        "verification_type": "sigstore-bundle",
        "issuer": "https://token.actions.githubusercontent.com",
        "signer": (
            f"{project['target_full_name']}/.github/workflows/"
            "assured-downstream-attested-release.yml"
        ),
        "verified_subjects": [
            {"sha256": entry["sha256"]} for entry in manifest["evidence"]["artifacts"]
        ],
    }


def invalid_fixture_release_verifier(*, evidence_path: Path, policy_path: Path) -> dict:
    result = fixture_release_verifier(
        evidence_path=evidence_path,
        policy_path=policy_path,
    )
    result["authority"] = "caller-authored-ok"
    return result


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
