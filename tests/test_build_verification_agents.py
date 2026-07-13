from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assured_downstream.build_verification import BuildVerificationError
from assured_downstream.build_verification_agents import (
    run_build_verification_agent_system,
)
from assured_downstream.evidence_agents import EvidenceLaneError


class BuildVerificationAgentTests(unittest.TestCase):
    def test_runs_builder_verifier_through_durable_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            run_dir = root / "run"
            with patch(
                "assured_downstream.build_verification_agents.verify_build_attestations",
                return_value=verified_record(),
            ):
                result = run_build_verification_agent_system(
                    **inputs,
                    run_dir=run_dir,
                    run_id="build-verify-test",
                )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 1)
            self.assertEqual(
                result["summary"]["event_types"],
                ["BuildVerificationRequested", "BuildAttestationsVerified"],
            )
            self.assertTrue(result["artifact_verification"]["ok"])
            record = read_json(run_dir / "build-attestation-verification.json")
            self.assertEqual(record["status"], "verified-evidence-candidate")

            with patch(
                "assured_downstream.build_verification_agents.verify_build_attestations",
                return_value=verified_record(),
            ):
                resumed = run_build_verification_agent_system(
                    **inputs,
                    run_dir=run_dir,
                    run_id="build-verify-test",
                )
            self.assertEqual(resumed["processed_count"], 0)

    def test_verifier_rejection_becomes_a_durable_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            with patch(
                "assured_downstream.build_verification_agents.verify_build_attestations",
                side_effect=BuildVerificationError("certificate mismatch"),
            ):
                result = run_build_verification_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="build-verify-rejected",
                )

            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "BuildAttestationsRejected",
                result["summary"]["event_types"],
            )
            rejection = read_json(root / "run" / "build-attestation-verification.json")
            self.assertEqual(rejection["status"], "rejected")
            self.assertIn("certificate mismatch", rejection["error"])

    def test_rejects_symlinked_source_manifest_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            source = inputs["evidence_path"]
            alias = root / "evidence-alias.json"
            alias.symlink_to(source)
            inputs["evidence_path"] = alias

            with self.assertRaisesRegex(EvidenceLaneError, "not a regular file"):
                run_build_verification_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="build-verify-symlink",
                )

    def test_rejects_hard_linked_source_manifest_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            source = inputs["evidence_path"]
            alias = root / "evidence-hard-link.json"
            alias.hardlink_to(source)
            inputs["evidence_path"] = alias

            with self.assertRaisesRegex(EvidenceLaneError, "not a regular file"):
                run_build_verification_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="build-verify-hard-link",
                )


def write_inputs(root: Path) -> dict[str, Path]:
    evidence_root = root / "evidence"
    artifact = evidence_root / "dist" / "artifact.whl"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"artifact\n")
    artifact_bytes = artifact.read_bytes()
    manifest = {
        "schema_version": 1,
        "generated_at": "2026-07-13T00:00:00+00:00",
        "project": {
            "source_full_name": "PyCQA/bandit",
            "target_full_name": "SauceTaster/assured-bandit",
            "upstream_ref": "a" * 40,
            "overlay_ref": "a" * 40,
            "release_tag": "case-001-bandit-source-canary",
            "assurance": "Evidence-candidate",
        },
        "evidence": {
            "artifacts": [
                {
                    "name": artifact.name,
                    "path": "dist/artifact.whl",
                    "role": "artifacts",
                    "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                    "size": len(artifact_bytes),
                }
            ]
        },
    }
    evidence_path = evidence_root / "evidence.json"
    write_json(evidence_path, manifest)
    policy_path = root / "build-policy.json"
    trust_policy_path = root / "trust-policy.json"
    write_json(policy_path, {"fixture": "build-policy"})
    write_json(trust_policy_path, {"fixture": "trust-policy"})
    return {
        "evidence_path": evidence_path,
        "policy_path": policy_path,
        "trust_policy_path": trust_policy_path,
    }


def verified_record() -> dict:
    return {
        "schema_version": 1,
        "status": "verified-evidence-candidate",
        "ok": True,
        "authority": "code-anchored-reusable-workflow-sigstore",
    }


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
