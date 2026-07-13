from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from functools import partial
from pathlib import Path
from unittest.mock import patch

from assured_downstream.build_verification_v3 import BuildVerificationError
from assured_downstream.reproducibility_agents_v3 import (
    reproducibility_v3_gate_checks,
    run_reproducibility_v3_agent_system,
    verified_current_run_artifact,
)
from assured_downstream.evidence_agents import EvidenceLaneError, artifact_reference
from assured_downstream.reproducibility_v3 import (
    REPRODUCIBILITY_V3_CORE_CHECKS,
    ReproducibilityV3Analysis,
)
from tests.test_reproducibility_v3 import write_bundle


class ReproducibilityV3AgentTests(unittest.TestCase):
    def test_repro_and_governor_emit_bounded_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            with (
                patch(
                    "assured_downstream.reproducibility_agents_v3."
                    "verify_build_attestations",
                    side_effect=verified_record_for_call,
                ),
                patch(
                    "assured_downstream.reproducibility_agents_v3."
                    "compare_verified_builds_v3",
                    side_effect=partial(analysis_for_call, matched=True),
                ),
            ):
                result = run_reproducibility_v3_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="repro-v3-test",
                )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["processed_count"], 2)
            self.assertEqual(
                result["summary"]["event_types"],
                [
                    "RebuildComparisonV3Requested",
                    "RebuildV3Compared",
                    "ReproducibilityV3CandidateReady",
                ],
            )
            gate = read_json(root / "run" / "reproducibility-gate-v3.json")
            self.assertTrue(gate["passed"])
            self.assertFalse(gate["promotion_authorized"])
            self.assertFalse(gate["provider_independent"])
            self.assertTrue(result["artifact_verification"]["ok"])

    def test_mismatch_is_retained_for_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            with (
                patch(
                    "assured_downstream.reproducibility_agents_v3."
                    "verify_build_attestations",
                    side_effect=verified_record_for_call,
                ),
                patch(
                    "assured_downstream.reproducibility_agents_v3."
                    "compare_verified_builds_v3",
                    side_effect=partial(analysis_for_call, matched=False),
                ),
            ):
                result = run_reproducibility_v3_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="repro-v3-mismatch",
                )

            self.assertEqual(result["status"], "needs_human_review")
            self.assertIn("RebuildV3Mismatch", result["summary"]["event_types"])
            gate = read_json(root / "run" / "reproducibility-gate-v3.json")
            self.assertFalse(gate["passed"])
            mismatch = read_json(root / "run" / "rebuild-mismatch-v3.json")
            self.assertFalse(mismatch["reproducible"])

    def test_verification_failure_blocks_before_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = write_inputs(root)
            with patch(
                "assured_downstream.reproducibility_agents_v3."
                "verify_build_attestations",
                side_effect=BuildVerificationError("signature mismatch"),
            ):
                result = run_reproducibility_v3_agent_system(
                    **inputs,
                    run_dir=root / "run",
                    run_id="repro-v3-rejected",
                )

            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "RebuildComparisonV3Rejected",
                result["summary"]["event_types"],
            )

    def test_incomplete_core_check_set_cannot_pass(self) -> None:
        report = analysis(matched=True).report
        report["core_checks"].pop("stable_builder")
        expected = {
            "handoff": report["agent_handoff"],
            "executions": report["executions"],
            "evidence": report["evidence"],
        }

        checks = reproducibility_v3_gate_checks(
            report,
            matched_event=True,
            expected_binding=expected,
        )

        by_name = {item["check"]: item["passed"] for item in checks}
        self.assertFalse(by_name["core-checks-exact"])

    def test_false_artifact_candidate_or_blocker_cannot_pass(self) -> None:
        report = analysis(matched=True).report
        expected = {
            "handoff": report["agent_handoff"],
            "executions": report["executions"],
            "evidence": report["evidence"],
        }

        report["artifact_reproducibility_candidate"] = False
        checks = reproducibility_v3_gate_checks(
            report,
            matched_event=True,
            expected_binding=expected,
        )
        by_name = {item["check"]: item["passed"] for item in checks}
        self.assertFalse(by_name["artifact-candidate-matched"])

        report["artifact_reproducibility_candidate"] = True
        report["blocking_findings"] = [
            {"code": "injected", "check": "artifact identity"}
        ]
        checks = reproducibility_v3_gate_checks(
            report,
            matched_event=True,
            expected_binding=expected,
        )
        by_name = {item["check"]: item["passed"] for item in checks}
        self.assertFalse(by_name["blocking-findings-consistent"])

    def test_governor_rejects_artifact_from_another_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "current"
            stale = root / "stale" / "rebuild-comparison-v3.json"
            current.mkdir()
            stale.parent.mkdir()
            write_json(stale, {"status": "matched"})

            with self.assertRaisesRegex(EvidenceLaneError, "current run"):
                verified_current_run_artifact(
                    artifact_reference(stale),
                    run_dir=current,
                    expected_name="rebuild-comparison-v3.json",
                    label="rebuild comparison v3",
                )


def write_inputs(root: Path) -> dict:
    left, _ = write_bundle(
        root / "left",
        run_id="4001",
        temp_token="abcdefgh",
        raw_sdist=b"raw-left",
    )
    right, _ = write_bundle(
        root / "right",
        run_id="4002",
        temp_token="ijklmnop",
        raw_sdist=b"raw-right",
    )
    policy = root / "policy.json"
    trust_policy = root / "trust-policy.json"
    write_json(policy, {"fixture": "policy"})
    write_json(trust_policy, {"fixture": "trust-policy"})
    return {
        "left_evidence_path": left,
        "right_evidence_path": right,
        "left_execution_id": "github-actions:4001",
        "right_execution_id": "github-actions:4002",
        "policy_path": policy,
        "trust_policy_path": trust_policy,
    }


def verified_record_for_call(*, evidence_path: Path, **_: object) -> dict:
    return {
        "status": "verified-evidence-candidate",
        "ok": True,
        "evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
    }


def analysis_for_call(
    *,
    matched: bool,
    left_verification: dict,
    right_verification: dict,
    left_execution_id: str,
    right_execution_id: str,
    **_: object,
) -> ReproducibilityV3Analysis:
    result = analysis(matched=matched)
    result.report["executions"] = {
        "left": left_execution_id,
        "right": right_execution_id,
    }
    result.report["evidence"] = {
        "left_sha256": left_verification["evidence_sha256"],
        "right_sha256": right_verification["evidence_sha256"],
    }
    return result


def analysis(*, matched: bool) -> ReproducibilityV3Analysis:
    core_checks = {name: True for name in REPRODUCIBILITY_V3_CORE_CHECKS}
    if not matched:
        core_checks["artifacts"] = False
    report = {
        "schema_version": 1,
        "status": "matched" if matched else "mismatch",
        "ok": matched,
        "reproducible": matched,
        "artifact_reproducibility_candidate": matched,
        "behavior_reproducibility_candidate": matched,
        "provider_independent": False,
        "promotion_authority": "none",
        "core_checks": core_checks,
        "agent_handoff": {
            "schema_version": 1,
            "run_id": "fixture-run",
            "input_event_id": "fixture-event",
            "input_payload_sha256": "1" * 64,
            "inputs_sha256": "2" * 64,
            "execution_sha256": "3" * 64,
        },
        "executions": {"left": "github-actions:1", "right": "github-actions:2"},
        "evidence": {"left_sha256": "4" * 64, "right_sha256": "5" * 64},
        "trace": {},
        "blocking_findings": (
            []
            if matched
            else [{"code": "artifacts-mismatch", "check": "artifacts"}]
        ),
        "claim_limit": "Fixture comparison has no promotion authority.",
    }
    behavior = {
        "schema_version": 2,
        "generated_at": "2026-07-13T00:00:00+00:00",
        "digest": "1" * 64,
        "summary": {},
        "normalized": {},
    }
    return ReproducibilityV3Analysis(
        report=report,
        left_behavior=behavior,
        right_behavior=behavior,
    )


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
