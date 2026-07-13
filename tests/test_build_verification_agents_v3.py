from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assured_downstream.build_verification_agents_v3 import (
    run_build_verification_v3_agent_system,
)
from assured_downstream.build_verification_v3 import BuildVerificationError
from assured_downstream.evidence_agents import EvidenceLaneError


class BuildVerificationV3AgentTests(unittest.TestCase):
    def test_snapshots_and_runs_v3_verifier_through_durable_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            run_dir = root / "run"
            with patch(
                "assured_downstream.build_verification_agents_v3."
                "verify_build_attestations",
                return_value=verified_record(),
            ):
                result = run_build_verification_v3_agent_system(
                    **inputs,
                    run_dir=run_dir,
                    run_id="build-verify-v3-test",
                )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 1)
            self.assertEqual(
                result["summary"]["event_types"],
                ["BuildVerificationV3Requested", "BuildAttestationsV3Verified"],
            )
            self.assertTrue(result["artifact_verification"]["ok"])
            record = read_json(
                run_dir / "build-attestation-verification-v3.json"
            )
            self.assertEqual(record["status"], "verified-evidence-candidate")
            staged = read_json(run_dir / "inputs" / "evidence-v3.json")
            for entries in staged["evidence"].values():
                for entry in entries:
                    self.assertNotEqual(entry["path"], entry["logical_path"])
                    self.assertTrue(entry["path"].startswith("files/"))

            with patch(
                "assured_downstream.build_verification_agents_v3."
                "verify_build_attestations",
                return_value=verified_record(),
            ):
                resumed = run_build_verification_v3_agent_system(
                    **inputs,
                    run_dir=run_dir,
                    run_id="build-verify-v3-test",
                )
            self.assertEqual(resumed["processed_count"], 0)

    def test_v3_rejection_becomes_a_durable_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            with patch(
                "assured_downstream.build_verification_agents_v3."
                "verify_build_attestations",
                side_effect=BuildVerificationError("certificate mismatch"),
            ):
                result = run_build_verification_v3_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="build-verify-v3-rejected",
                )

            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "BuildAttestationsV3Rejected",
                result["summary"]["event_types"],
            )
            rejection = read_json(
                root / "run" / "build-attestation-verification-v3.json"
            )
            self.assertEqual(rejection["status"], "rejected")
            self.assertIn("certificate mismatch", rejection["error"])

    def test_rejects_symlinked_v3_manifest_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            alias = root / "evidence-alias.json"
            alias.symlink_to(inputs["evidence_path"])
            inputs["evidence_path"] = alias

            with self.assertRaisesRegex(EvidenceLaneError, "not a regular file"):
                run_build_verification_v3_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="build-verify-v3-symlink",
                )


def write_inputs(root: Path) -> dict[str, Path]:
    evidence_root = root / "evidence"
    logical_paths = {
        "artifacts": "dist/artifact.whl",
        "attestations": "attestations/build.sigstore.json",
        "raw_artifacts": "raw-artifacts/artifact.whl",
        "reports": "reports/builder.json",
        "sboms": "sbom/sbom.spdx.json",
        "traces": "traces/observed-trace.json",
    }
    roles = {}
    for role, logical_path in logical_paths.items():
        payload = f"{role}\n".encode()
        path = evidence_root / logical_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        roles[role] = [
            {
                "logical_path": logical_path,
                "name": path.name,
                "path": logical_path,
                "role": role,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        ]
    manifest = {
        "schema_version": 2,
        "generated_at": "2026-07-13T00:00:00+00:00",
        "project": {
            "source_full_name": "PyCQA/bandit",
            "target_full_name": "SauceTaster/assured-bandit",
            "upstream_ref": "a" * 40,
            "overlay_ref": "a" * 40,
            "release_tag": "case-001-bandit-source-canary-v3",
            "assurance": "Evidence-candidate",
        },
        "evidence": roles,
    }
    evidence_path = evidence_root / "evidence.json"
    write_json(evidence_path, manifest)
    policy_path = root / "build-policy-v3.json"
    trust_policy_path = root / "trust-policy.json"
    write_json(policy_path, {"fixture": "build-policy-v3"})
    write_json(trust_policy_path, {"fixture": "trust-policy"})
    return {
        "evidence_path": evidence_path,
        "policy_path": policy_path,
        "trust_policy_path": trust_policy_path,
    }


def verified_record() -> dict:
    return {
        "schema_version": 2,
        "status": "verified-evidence-candidate",
        "ok": True,
        "authority": "code-anchored-reusable-workflow-sigstore",
    }


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
