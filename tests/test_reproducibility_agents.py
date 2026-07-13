from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assured_downstream.agent_store import AgentStore
from assured_downstream.build_verification import BuildVerificationError
from assured_downstream.reproducibility import ReproducibilityAnalysis
from assured_downstream.reproducibility_agents import (
    run_reproducibility_agent_system,
)
from tests.test_reproducibility import verification_record, write_bundle


class ReproducibilityAgentTests(unittest.TestCase):
    def test_runs_matching_rebuilds_through_durable_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            run_dir = root / "run"
            with (
                patch(
                    "assured_downstream.reproducibility_agents."
                    "verify_build_attestations",
                    side_effect=[verified_record("1"), verified_record("2")],
                ),
                patch(
                    "assured_downstream.reproducibility_agents."
                    "compare_verified_builds",
                    return_value=analysis(reproducible=True),
                ),
            ):
                result = run_reproducibility_agent_system(
                    **inputs,
                    run_dir=run_dir,
                    run_id="repro-matched",
                )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 2)
            self.assertEqual(
                result["summary"]["event_types"],
                [
                    "RebuildComparisonRequested",
                    "RebuildCompared",
                    "ReproducibilityCandidateReady",
                ],
            )
            self.assertTrue(result["artifact_verification"]["ok"])
            self.assertTrue(read_json(run_dir / "rebuild-comparison.json")["ok"])

            resumed = run_reproducibility_agent_system(
                **inputs,
                run_dir=run_dir,
                run_id="repro-matched",
            )
            self.assertEqual(resumed["processed_count"], 0)

    def test_mismatch_becomes_durable_human_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            with (
                patch(
                    "assured_downstream.reproducibility_agents."
                    "verify_build_attestations",
                    side_effect=[verified_record("1"), verified_record("2")],
                ),
                patch(
                    "assured_downstream.reproducibility_agents."
                    "compare_verified_builds",
                    return_value=analysis(reproducible=False),
                ),
            ):
                result = run_reproducibility_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="repro-mismatch",
                )

            self.assertEqual(result["status"], "needs_human_review")
            self.assertIn("RebuildMismatch", result["summary"]["event_types"])
            self.assertIn("GateBlocked", result["summary"]["event_types"])
            mismatch = read_json(root / "run" / "rebuild-mismatch-review.json")
            self.assertFalse(mismatch["reproducible"])
            self.assertEqual(
                mismatch["blocking_findings"][0]["code"],
                "artifact-byte-mismatch",
            )
            gate = read_json(root / "run" / "reproducibility-gate.json")
            self.assertFalse(gate["passed"])
            self.assertFalse(gate["promotion_authorized"])
            reopened = AgentStore(root / "run" / "agent-control-plane.sqlite3")
            self.assertEqual(
                reopened.get_run("repro-mismatch")["status"],
                "needs_human_review",
            )

    def test_verification_failure_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            with patch(
                "assured_downstream.reproducibility_agents."
                "verify_build_attestations",
                side_effect=BuildVerificationError("untrusted signer"),
            ):
                result = run_reproducibility_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="repro-rejected",
                )

            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "RebuildComparisonRejected",
                result["summary"]["event_types"],
            )
            rejection = read_json(
                root / "run" / "rebuild-comparison-rejection.json"
            )
            self.assertIn("untrusted signer", rejection["error"])

    def test_real_comparator_is_reached_after_both_verifier_handoffs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = write_bundle(
                root / "left",
                archive_mtime=100,
                builder_started="2026-07-13T01:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="left",
                temp_token="aaaaaaaa",
            )
            right = write_bundle(
                root / "right",
                archive_mtime=200,
                builder_started="2026-07-13T02:00:00Z",
                sbom_created="2026-07-13T02:01:00Z",
                namespace="right",
                temp_token="bbbbbbbb",
            )
            policy = root / "build-policy.json"
            trust_policy = root / "trust-policy.json"
            write_json(policy, {"fixture": "build-policy"})
            write_json(trust_policy, {"fixture": "trust-policy"})
            tokens = iter(("1", "2"))

            def fake_verifier(**kwargs: object) -> dict[str, object]:
                return verification_record(
                    next(tokens),
                    Path(kwargs["evidence_path"]),
                )

            with patch(
                "assured_downstream.reproducibility_agents."
                "verify_build_attestations",
                side_effect=fake_verifier,
            ) as verifier:
                result = run_reproducibility_agent_system(
                    left_evidence_path=left,
                    right_evidence_path=right,
                    left_execution_id="github-actions:1",
                    right_execution_id="github-actions:2",
                    policy_path=policy,
                    trust_policy_path=trust_policy,
                    run_dir=root / "run",
                    run_id="repro-real-comparator",
                )

            self.assertEqual(verifier.call_count, 2)
            self.assertEqual(result["status"], "needs_human_review")
            comparison = read_json(root / "run" / "rebuild-comparison.json")
            self.assertEqual(
                comparison["artifacts"]["comparisons"][1]["classification"],
                "archive-metadata-only",
            )
            self.assertFalse(
                read_json(root / "run" / "reproducibility-gate.json")["passed"]
            )


def write_inputs(root: Path) -> dict[str, object]:
    left = write_evidence(root / "left", b"left artifact\n")
    right = write_evidence(root / "right", b"right artifact\n")
    policy = root / "build-policy.json"
    trust_policy = root / "trust-policy.json"
    write_json(policy, {"fixture": "build-policy"})
    write_json(trust_policy, {"fixture": "trust-policy"})
    return {
        "left_evidence_path": left,
        "right_evidence_path": right,
        "left_execution_id": "github-actions:1",
        "right_execution_id": "github-actions:2",
        "policy_path": policy,
        "trust_policy_path": trust_policy,
    }


def write_evidence(root: Path, payload: bytes) -> Path:
    artifact = root / "dist" / "artifact.whl"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(payload)
    manifest = {
        "schema_version": 1,
        "project": {
            "source_full_name": "example/project",
            "target_full_name": "SauceTaster/assured-project",
            "upstream_ref": "a" * 40,
            "overlay_ref": "a" * 40,
            "release_tag": "case-project",
            "assurance": "Evidence-candidate",
        },
        "evidence": {
            "artifacts": [
                {
                    "name": artifact.name,
                    "path": "dist/artifact.whl",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            ]
        },
    }
    path = root / "evidence.json"
    write_json(path, manifest)
    return path


def analysis(*, reproducible: bool) -> ReproducibilityAnalysis:
    findings = []
    if not reproducible:
        findings = [
            {
                "code": "artifact-byte-mismatch",
                "subject": "artifact.whl",
                "classification": "byte-mismatch",
                "detail": "Artifact bytes differ.",
            }
        ]
    report = {
        "schema_version": 1,
        "status": "matched" if reproducible else "mismatch",
        "ok": reproducible,
        "reproducible": reproducible,
        "comparison_eligible": True,
        "provider_independent": False,
        "identity": {
            "checks": [
                {
                    "field": "source_repository",
                    "passed": True,
                    "left": "example/project",
                    "right": "example/project",
                },
                {
                    "field": "target_full_name",
                    "passed": True,
                    "left": "SauceTaster/assured-project",
                    "right": "SauceTaster/assured-project",
                },
            ]
        },
        "artifacts": {"exact_match": reproducible},
        "sbom": {"exact_match": reproducible},
        "materials": {"semantic_match": True},
        "builder": {"stable_match": True},
        "behavior_diagnostic": {
            "normalized_match": True,
            "promotion_gate": False,
        },
        "blocking_findings": findings,
        "warnings": [],
        "claim_limit": "fixture claim limit",
    }
    behavior = {
        "schema_version": 2,
        "digest": "a" * 64,
        "summary": {},
        "normalized": {},
    }
    return ReproducibilityAnalysis(
        report=report,
        left_behavior=behavior,
        right_behavior=behavior,
    )


def verified_record(token: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "verified-evidence-candidate",
        "ok": True,
        "authority": "code-anchored-reusable-workflow-sigstore",
        "bundles": {"build": {"sha256": token * 64}},
    }


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
