from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from assured_downstream.agent_contracts import (
    AgentContext,
    AgentResult,
    ArtifactOutput,
    EventOutput,
    content_digest,
)
from assured_downstream.agent_runtime import AgentHandler, AgentRuntime
from assured_downstream.agent_store import AgentStore
from assured_downstream.build_verification_agents_v3 import (
    snapshot_evidence_bundle_v3,
)
from assured_downstream.build_verification_v3 import (
    BuildVerificationError,
    verify_build_attestations,
)
from assured_downstream.evidence_agents import (
    EvidenceLaneError,
    artifact_reference,
    read_json,
    snapshot_regular_file,
    verified_artifact_path,
    write_json_atomic,
)
from assured_downstream.reproducibility_v3 import (
    REPRODUCIBILITY_V3_CORE_CHECKS,
    ReproducibilityV3Error,
    compare_verified_builds_v3,
)


REPRODUCIBILITY_V3_WORKFLOW = "retained-build-reproducibility-v3"
REPRODUCIBILITY_V3_EVENT = "RebuildComparisonV3Requested"
REPRODUCIBILITY_V3_COMPARED_EVENT = "RebuildV3Compared"
REPRODUCIBILITY_V3_MISMATCH_EVENT = "RebuildV3Mismatch"
REPRODUCIBILITY_V3_REJECTED_EVENT = "RebuildComparisonV3Rejected"


class ReproducibilityV3Handler:
    agent_id = "repro-v3"

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != REPRODUCIBILITY_V3_EVENT:
            raise ValueError("Repro v3 Agent requires RebuildComparisonV3Requested")
        if context.event.producer_agent_id is not None:
            raise ValueError("RebuildComparisonV3Requested must be external")
        if content_digest(context.event.payload) != context.event.payload_sha256:
            raise ValueError("Rebuild comparison v3 event payload digest is invalid")
        inputs = context.event.payload.get("inputs")
        execution = context.event.payload.get("execution")
        if not isinstance(inputs, dict) or not isinstance(execution, dict):
            raise ValueError("Rebuild comparison v3 event has no input references")
        try:
            left_evidence = verified_artifact_path(
                inputs.get("left_evidence"),
                label="left v3 build evidence manifest",
            )
            right_evidence = verified_artifact_path(
                inputs.get("right_evidence"),
                label="right v3 build evidence manifest",
            )
            policy = verified_artifact_path(
                inputs.get("policy"),
                label="build verification v3 policy",
            )
            trust_policy = verified_artifact_path(
                inputs.get("trust_policy"),
                label="Sigstore trust policy",
            )
            left_verification = verify_build_attestations(
                evidence_path=left_evidence,
                policy_path=policy,
                trust_policy_path=trust_policy,
            )
            require_authoritative_v3_verification(left_verification, label="left")
            left_verification_path = (
                context.run_dir / "left-build-attestation-verification-v3.json"
            )
            write_json_atomic(left_verification_path, left_verification)

            right_verification = verify_build_attestations(
                evidence_path=right_evidence,
                policy_path=policy,
                trust_policy_path=trust_policy,
            )
            require_authoritative_v3_verification(right_verification, label="right")
            right_verification_path = (
                context.run_dir / "right-build-attestation-verification-v3.json"
            )
            write_json_atomic(right_verification_path, right_verification)

            analysis = compare_verified_builds_v3(
                left_evidence_path=left_evidence,
                right_evidence_path=right_evidence,
                left_verification=left_verification,
                right_verification=right_verification,
                left_execution_id=execution.get("left_id"),
                right_execution_id=execution.get("right_id"),
            )
        except (
            BuildVerificationError,
            EvidenceLaneError,
            FileNotFoundError,
            KeyError,
            OSError,
            ReproducibilityV3Error,
            TypeError,
            ValueError,
        ) as exc:
            return rejected_result(
                context,
                inputs=inputs,
                execution=execution,
                error=str(exc),
            )

        left_behavior_path = context.run_dir / "behavior" / "left-v3-normalized.json"
        right_behavior_path = context.run_dir / "behavior" / "right-v3-normalized.json"
        write_json_atomic(left_behavior_path, analysis.left_behavior)
        write_json_atomic(right_behavior_path, analysis.right_behavior)
        comparison = analysis.report
        handoff_binding = {
            "schema_version": 1,
            "run_id": context.run_id,
            "input_event_id": context.event.event_id,
            "input_payload_sha256": context.event.payload_sha256,
            "inputs_sha256": content_digest(inputs),
            "execution_sha256": content_digest(execution),
        }
        comparison["agent_handoff"] = handoff_binding
        comparison["trace"]["normalized_reports"] = {
            "left": artifact_reference(left_behavior_path),
            "right": artifact_reference(right_behavior_path),
        }
        comparison_path = context.run_dir / "rebuild-comparison-v3.json"
        write_json_atomic(comparison_path, comparison)
        verification_references = {
            "left": artifact_reference(left_verification_path),
            "right": artifact_reference(right_verification_path),
        }
        base_payload = {
            "comparison": artifact_reference(comparison_path),
            "verifications": verification_references,
            "inputs": inputs,
            "execution": execution,
            "handoff": handoff_binding,
            "provider_independent": False,
            "promotion_authorized": False,
        }
        artifacts = [
            ArtifactOutput(role="left-v3-build-evidence", path=left_evidence),
            ArtifactOutput(role="right-v3-build-evidence", path=right_evidence),
            ArtifactOutput(
                role="left-v3-build-attestation-verification",
                path=left_verification_path,
            ),
            ArtifactOutput(
                role="right-v3-build-attestation-verification",
                path=right_verification_path,
            ),
            ArtifactOutput(role="left-v3-normalized-behavior", path=left_behavior_path),
            ArtifactOutput(
                role="right-v3-normalized-behavior",
                path=right_behavior_path,
            ),
            ArtifactOutput(role="rebuild-comparison-v3", path=comparison_path),
        ]
        if comparison["reproducible"]:
            return AgentResult(
                status="succeeded",
                summary=(
                    "Two v3 evidence bundles matched as a same-provider artifact "
                    "and behavior reproducibility candidate."
                ),
                events=[
                    EventOutput(
                        event_type=REPRODUCIBILITY_V3_COMPARED_EVENT,
                        payload=base_payload,
                        source_repository=context.event.source_repository,
                        dedupe_key=content_digest(base_payload),
                    )
                ],
                artifacts=artifacts,
            )

        mismatch = {
            "schema_version": 1,
            "status": "needs-human-review",
            "comparison_sha256": base_payload["comparison"]["sha256"],
            "reproducible": False,
            "provider_independent": False,
            "blocking_findings": comparison["blocking_findings"],
            "claim_limit": comparison["claim_limit"],
        }
        mismatch_path = context.run_dir / "rebuild-mismatch-v3.json"
        write_json_atomic(mismatch_path, mismatch)
        payload = {**base_payload, "mismatch": artifact_reference(mismatch_path)}
        artifacts.append(ArtifactOutput(role="rebuild-mismatch-v3", path=mismatch_path))
        return AgentResult(
            status="needs_human_review",
            summary="V3 rebuild comparison found promotion-blocking differences.",
            events=[
                EventOutput(
                    event_type=REPRODUCIBILITY_V3_MISMATCH_EVENT,
                    payload=payload,
                    source_repository=context.event.source_repository,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
            human_review=[
                f"{finding['code']}: {finding['check']}"
                for finding in comparison["blocking_findings"]
            ],
        )


class ReproducibilityV3GovernorHandler:
    agent_id = "governor-v3"

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.producer_agent_id != "repro-v3":
            raise ValueError("V3 comparison events must be produced by repro-v3")
        if context.event.event_type not in {
            REPRODUCIBILITY_V3_COMPARED_EVENT,
            REPRODUCIBILITY_V3_MISMATCH_EVENT,
        }:
            raise ValueError("Governor v3 requires a rebuild v3 comparison event")
        if content_digest(context.event.payload) != context.event.payload_sha256:
            raise ValueError("Governor v3 event payload digest is invalid")
        comparison_path = verified_current_run_artifact(
            context.event.payload.get("comparison"),
            run_dir=context.run_dir,
            expected_name="rebuild-comparison-v3.json",
            label="rebuild comparison v3",
        )
        comparison = read_json(comparison_path)
        expected_binding = expected_governor_handoff(context)
        matched_event = context.event.event_type == REPRODUCIBILITY_V3_COMPARED_EVENT
        checks = reproducibility_v3_gate_checks(
            comparison,
            matched_event=matched_event,
            expected_binding=expected_binding,
        )
        coherent = all(check["passed"] for check in checks)
        if not matched_event:
            mismatch_path = verified_current_run_artifact(
                context.event.payload.get("mismatch"),
                run_dir=context.run_dir,
                expected_name="rebuild-mismatch-v3.json",
                label="rebuild mismatch v3",
            )
            mismatch = read_json(mismatch_path)
            mismatch_bound = (
                mismatch.get("status") == "needs-human-review"
                and mismatch.get("reproducible") is False
                and mismatch.get("comparison_sha256")
                == context.event.payload["comparison"]["sha256"]
            )
            checks.append(
                {
                    "check": "mismatch-review-bound",
                    "passed": mismatch_bound,
                    "detail": "mismatch review must bind the exact comparison",
                }
            )
            coherent = coherent and mismatch_bound
        gate_passed = matched_event and coherent
        decision = {
            "schema_version": 1,
            "gate": "v3-reproducibility-candidate",
            "passed": gate_passed,
            "artifact_reproducibility_candidate": comparison.get(
                "artifact_reproducibility_candidate"
            )
            is True,
            "behavior_reproducibility_candidate": comparison.get(
                "behavior_reproducibility_candidate"
            )
            is True,
            "authority": "durable-v3-reproducibility-candidate-gate",
            "promotion_authorized": False,
            "provider_independent": False,
            "checks": checks,
            "comparison": context.event.payload["comparison"],
            "claim_limit": (
                "This gate can emit a same-provider v3 reproducibility candidate. "
                "It cannot authorize release promotion or independent-builder claims."
            ),
        }
        decision_path = context.run_dir / "reproducibility-gate-v3.json"
        write_json_atomic(decision_path, decision)
        payload = {
            "gate": artifact_reference(decision_path),
            "comparison": context.event.payload["comparison"],
            "promotion_authorized": False,
        }
        artifact = ArtifactOutput(
            role="v3-reproducibility-candidate-gate",
            path=decision_path,
        )
        if gate_passed:
            return AgentResult(
                status="succeeded",
                summary=(
                    "Governor accepted a same-provider v3 reproducibility "
                    "candidate without authorizing promotion."
                ),
                events=[
                    EventOutput(
                        event_type="ReproducibilityV3CandidateReady",
                        payload=payload,
                        source_repository=context.event.source_repository,
                        dedupe_key=content_digest(payload),
                    )
                ],
                artifacts=[artifact],
            )
        failed_checks = [
            check["detail"] for check in checks if not check["passed"]
        ]
        return AgentResult(
            status="needs_human_review" if coherent else "blocked",
            summary="Governor v3 blocked reproducibility promotion.",
            events=[
                EventOutput(
                    event_type="ReproducibilityV3GateBlocked",
                    payload=payload,
                    source_repository=context.event.source_repository,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[artifact],
            human_review=failed_checks,
        )


def reproducibility_v3_handlers() -> list[AgentHandler]:
    return [ReproducibilityV3Handler(), ReproducibilityV3GovernorHandler()]


def reproducibility_v3_routes() -> dict[str, list[str]]:
    return {
        REPRODUCIBILITY_V3_EVENT: ["repro-v3"],
        REPRODUCIBILITY_V3_COMPARED_EVENT: ["governor-v3"],
        REPRODUCIBILITY_V3_MISMATCH_EVENT: ["governor-v3"],
        REPRODUCIBILITY_V3_REJECTED_EVENT: [],
        "ReproducibilityV3CandidateReady": [],
        "ReproducibilityV3GateBlocked": [],
    }


def run_reproducibility_v3_agent_system(
    *,
    left_evidence_path: Path,
    right_evidence_path: Path,
    left_execution_id: str,
    right_execution_id: str,
    policy_path: Path,
    trust_policy_path: Path,
    run_dir: Path,
    database_path: Path | None = None,
    run_id: str | None = None,
    worker_id: str | None = None,
    max_items: int = 20,
    enqueue_only: bool = False,
) -> dict[str, Any]:
    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    if not isinstance(left_execution_id, str) or not left_execution_id.strip():
        raise ValueError("left_execution_id is required")
    if not isinstance(right_execution_id, str) or not right_execution_id.strip():
        raise ValueError("right_execution_id is required")
    if left_execution_id.strip() == right_execution_id.strip():
        raise ValueError("Rebuild execution identifiers must be distinct")
    run_dir = run_dir.expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    left_evidence = snapshot_evidence_bundle_v3(
        left_evidence_path,
        run_dir=run_dir,
        namespace="left",
    )
    right_evidence = snapshot_evidence_bundle_v3(
        right_evidence_path,
        run_dir=run_dir,
        namespace="right",
    )
    policy = snapshot_regular_file(
        policy_path,
        target_dir=run_dir / "inputs" / "control",
        label="build-verification-v3-policy.json",
    )
    trust_policy = snapshot_regular_file(
        trust_policy_path,
        target_dir=run_dir / "inputs" / "control",
        label="Sigstore-trust-policy.json",
    )
    inputs = {
        "left_evidence": left_evidence,
        "right_evidence": right_evidence,
        "policy": policy,
        "trust_policy": trust_policy,
    }
    execution = {
        "left_id": left_execution_id.strip(),
        "right_id": right_execution_id.strip(),
    }
    config = {"inputs": inputs, "execution": execution}
    effective_run_id = run_id or f"repro-v3-{uuid.uuid4().hex[:12]}"
    database_path = (
        (database_path or run_dir / "agent-control-plane.sqlite3")
        .expanduser()
        .resolve()
    )
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=reproducibility_v3_handlers(),
        routes=reproducibility_v3_routes(),
        worker_id=worker_id or f"local-{os.getpid()}",
    )
    created = ensure_reproducibility_v3_run(
        store,
        runtime=runtime,
        run_id=effective_run_id,
        run_dir=run_dir,
        config=config,
    )
    left_manifest = read_json(Path(left_evidence["path"]))
    project = left_manifest.get("project")
    source_repository = (
        project.get("source_full_name") if isinstance(project, dict) else None
    )
    if created:
        runtime.publish_external(
            run_id=effective_run_id,
            event_type=REPRODUCIBILITY_V3_EVENT,
            payload={"inputs": inputs, "execution": execution},
            source_repository=source_repository,
            dedupe_key=content_digest(
                {
                    "left_source_manifest": left_evidence[
                        "source_manifest_sha256"
                    ],
                    "right_source_manifest": right_evidence[
                        "source_manifest_sha256"
                    ],
                    "execution": execution,
                    "policy": policy["sha256"],
                    "trust_policy": trust_policy["sha256"],
                }
            ),
        )
    if enqueue_only:
        result = {
            "run_id": effective_run_id,
            "status": store.get_run(effective_run_id)["status"],
            "processed": [],
            "processed_count": 0,
            "pending_count": store.pending_count(effective_run_id),
            "artifact_verification": store.verify_artifacts(effective_run_id),
            "summary": store.run_summary(effective_run_id),
        }
    else:
        result = runtime.drain(run_id=effective_run_id, max_items=max_items)
    result["database_path"] = str(database_path)
    result["run_dir"] = str(run_dir)
    summary_path = run_dir / "reproducibility-v3-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def ensure_reproducibility_v3_run(
    store: AgentStore,
    *,
    runtime: AgentRuntime,
    run_id: str,
    run_dir: Path,
    config: dict[str, Any],
) -> bool:
    try:
        existing = store.get_run(run_id)
    except KeyError:
        runtime.create_run(
            run_id=run_id,
            run_dir=run_dir,
            metadata={"workflow": REPRODUCIBILITY_V3_WORKFLOW, "config": config},
        )
        return True
    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != REPRODUCIBILITY_V3_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False


def require_authoritative_v3_verification(
    verification: dict[str, Any],
    *,
    label: str,
) -> None:
    if (
        verification.get("status") != "verified-evidence-candidate"
        or verification.get("ok") is not True
    ):
        raise ReproducibilityV3Error(
            f"{label.capitalize()} verifier returned a non-authoritative result"
        )


def reproducibility_v3_gate_checks(
    comparison: dict[str, Any],
    *,
    matched_event: bool,
    expected_binding: dict[str, Any],
) -> list[dict[str, Any]]:
    expected_match = bool(matched_event)
    core_checks = comparison.get("core_checks")
    return [
        {
            "check": "comparison-event-consistent",
            "passed": (
                comparison.get("status")
                == ("matched" if matched_event else "mismatch")
                and comparison.get("ok") is expected_match
                and comparison.get("reproducible") is expected_match
            ),
            "detail": "event type must agree with the v3 comparison",
        },
        {
            "check": "core-checks-exact",
            "passed": (
                isinstance(core_checks, dict)
                and set(core_checks) == REPRODUCIBILITY_V3_CORE_CHECKS
                and all(type(value) is bool for value in core_checks.values())
                and (
                    all(core_checks.values())
                    if matched_event
                    else not all(core_checks.values())
                )
            ),
            "detail": "all v3 core decisions must agree with the event",
        },
        {
            "check": "current-run-handoff-bound",
            "passed": comparison.get("agent_handoff")
            == expected_binding["handoff"],
            "detail": "comparison must bind the current Repro input event and run",
        },
        {
            "check": "execution-input-bound",
            "passed": comparison.get("executions")
            == expected_binding["executions"],
            "detail": "comparison executions must match the current handoff",
        },
        {
            "check": "evidence-input-bound",
            "passed": comparison.get("evidence") == expected_binding["evidence"],
            "detail": "comparison evidence must match the current handoff",
        },
        {
            "check": "artifact-candidate-matched",
            "passed": (
                comparison.get("artifact_reproducibility_candidate")
                is expected_match
            ),
            "detail": "artifact identity must agree with the candidate event",
        },
        {
            "check": "behavior-candidate-matched",
            "passed": (
                comparison.get("behavior_reproducibility_candidate")
                is expected_match
            ),
            "detail": "normalized behavior must agree with the candidate event",
        },
        {
            "check": "blocking-findings-consistent",
            "passed": (
                isinstance(comparison.get("blocking_findings"), list)
                and (
                    not comparison["blocking_findings"]
                    if matched_event
                    else bool(comparison["blocking_findings"])
                )
            ),
            "detail": "candidate events cannot carry promotion-blocking findings",
        },
        {
            "check": "provider-independence-not-claimed",
            "passed": comparison.get("provider_independent") is False,
            "detail": "same-provider evidence cannot claim provider independence",
        },
        {
            "check": "promotion-authority-absent",
            "passed": comparison.get("promotion_authority") == "none",
            "detail": "the v3 candidate cannot authorize promotion",
        },
    ]


def expected_governor_handoff(context: AgentContext) -> dict[str, Any]:
    payload = context.event.payload
    inputs = payload.get("inputs")
    execution = payload.get("execution")
    handoff = payload.get("handoff")
    if (
        not isinstance(inputs, dict)
        or set(inputs)
        != {"left_evidence", "right_evidence", "policy", "trust_policy"}
        or not isinstance(execution, dict)
        or set(execution) != {"left_id", "right_id"}
        or not isinstance(handoff, dict)
        or context.event.causation_id is None
    ):
        raise EvidenceLaneError("Governor v3 handoff payload is invalid")
    for name in ("left_evidence", "right_evidence", "policy", "trust_policy"):
        reference = inputs[name]
        if (
            not isinstance(reference, dict)
            or not isinstance(reference.get("sha256"), str)
            or not isinstance(reference.get("path"), str)
        ):
            raise EvidenceLaneError("Governor v3 input reference is invalid")
    expected_handoff = {
        "schema_version": 1,
        "run_id": context.run_id,
        "input_event_id": context.event.causation_id,
        "input_payload_sha256": content_digest(
            {"inputs": inputs, "execution": execution}
        ),
        "inputs_sha256": content_digest(inputs),
        "execution_sha256": content_digest(execution),
    }
    if handoff != expected_handoff:
        raise EvidenceLaneError("Governor v3 handoff is not current-run bound")
    return {
        "handoff": expected_handoff,
        "executions": {
            "left": execution["left_id"],
            "right": execution["right_id"],
        },
        "evidence": {
            "left_sha256": inputs["left_evidence"]["sha256"],
            "right_sha256": inputs["right_evidence"]["sha256"],
        },
    }


def verified_current_run_artifact(
    value: Any,
    *,
    run_dir: Path,
    expected_name: str,
    label: str,
) -> Path:
    path = verified_artifact_path(value, label=label)
    root = run_dir.resolve()
    expected = (root / expected_name).resolve()
    if path != expected or not path.is_relative_to(root):
        raise EvidenceLaneError(
            f"{label.capitalize()} is not an artifact of the current run"
        )
    return path


def rejected_result(
    context: AgentContext,
    *,
    inputs: dict[str, Any],
    execution: dict[str, Any],
    error: str,
) -> AgentResult:
    rejection = {
        "schema_version": 1,
        "status": "rejected",
        "authority": "none",
        "error": error,
        "execution": execution,
    }
    rejection_path = context.run_dir / "rebuild-comparison-v3-rejection.json"
    write_json_atomic(rejection_path, rejection)
    payload = {
        "rejection": artifact_reference(rejection_path),
        "inputs": inputs,
        "execution": execution,
    }
    return AgentResult(
        status="blocked",
        summary="V3 rebuild comparison was rejected before a candidate decision.",
        events=[
            EventOutput(
                event_type=REPRODUCIBILITY_V3_REJECTED_EVENT,
                payload=payload,
                source_repository=context.event.source_repository,
                dedupe_key=content_digest(payload),
            )
        ],
        artifacts=[
            ArtifactOutput(role="rebuild-comparison-v3-rejection", path=rejection_path)
        ],
        human_review=[error],
    )
