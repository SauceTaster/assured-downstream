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
from assured_downstream.build_verification import (
    BuildVerificationError,
    verify_build_attestations,
)
from assured_downstream.build_verification_agents import snapshot_evidence_bundle
from assured_downstream.evidence_agents import (
    EvidenceLaneError,
    artifact_reference,
    read_json,
    snapshot_regular_file,
    verified_artifact_path,
    write_json_atomic,
)
from assured_downstream.reproducibility import (
    ReproducibilityError,
    compare_verified_builds,
    create_rebuild_mismatch_packet,
)


REPRODUCIBILITY_WORKFLOW = "retained-build-reproducibility-v1"
REPRODUCIBILITY_EVENT = "RebuildComparisonRequested"


class ReproducibilityHandler:
    agent_id = "repro"

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != REPRODUCIBILITY_EVENT:
            raise ValueError(
                "Repro Agent requires RebuildComparisonRequested"
            )
        if context.event.producer_agent_id is not None:
            raise ValueError("RebuildComparisonRequested must be an external event")
        inputs = context.event.payload.get("inputs")
        execution = context.event.payload.get("execution")
        if not isinstance(inputs, dict) or not isinstance(execution, dict):
            raise ValueError("Rebuild comparison event has no input references")

        try:
            left_evidence = verified_artifact_path(
                inputs.get("left_evidence"),
                label="left build evidence manifest",
            )
            right_evidence = verified_artifact_path(
                inputs.get("right_evidence"),
                label="right build evidence manifest",
            )
            policy = verified_artifact_path(
                inputs.get("policy"),
                label="build verification policy",
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
            require_authoritative_verification(left_verification, label="left")
            left_verification_path = (
                context.run_dir / "left-build-attestation-verification.json"
            )
            write_json_atomic(left_verification_path, left_verification)

            right_verification = verify_build_attestations(
                evidence_path=right_evidence,
                policy_path=policy,
                trust_policy_path=trust_policy,
            )
            require_authoritative_verification(right_verification, label="right")
            right_verification_path = (
                context.run_dir / "right-build-attestation-verification.json"
            )
            write_json_atomic(right_verification_path, right_verification)

            analysis = compare_verified_builds(
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
            ReproducibilityError,
            TypeError,
            ValueError,
        ) as exc:
            return rejected_result(
                context,
                inputs=inputs,
                execution=execution,
                error=str(exc),
            )

        left_behavior_path = context.run_dir / "behavior" / "left-normalized.json"
        right_behavior_path = context.run_dir / "behavior" / "right-normalized.json"
        write_json_atomic(left_behavior_path, analysis.left_behavior)
        write_json_atomic(right_behavior_path, analysis.right_behavior)
        comparison = analysis.report
        comparison["behavior_diagnostic"]["reports"] = {
            "left": artifact_reference(left_behavior_path),
            "right": artifact_reference(right_behavior_path),
        }
        comparison_path = context.run_dir / "rebuild-comparison.json"
        write_json_atomic(comparison_path, comparison)

        verification_references = {
            "left": artifact_reference(left_verification_path),
            "right": artifact_reference(right_verification_path),
        }
        base_payload = {
            "comparison": artifact_reference(comparison_path),
            "verifications": verification_references,
            "inputs": {
                "left_evidence": inputs["left_evidence"],
                "right_evidence": inputs["right_evidence"],
            },
            "provider_independent": False,
        }
        artifacts = [
            ArtifactOutput(role="left-build-evidence", path=left_evidence),
            ArtifactOutput(role="right-build-evidence", path=right_evidence),
            ArtifactOutput(
                role="left-build-attestation-verification",
                path=left_verification_path,
            ),
            ArtifactOutput(
                role="right-build-attestation-verification",
                path=right_verification_path,
            ),
            ArtifactOutput(role="left-normalized-behavior", path=left_behavior_path),
            ArtifactOutput(
                role="right-normalized-behavior",
                path=right_behavior_path,
            ),
            ArtifactOutput(role="rebuild-comparison", path=comparison_path),
        ]
        if comparison["reproducible"]:
            return AgentResult(
                status="succeeded",
                summary=(
                    "Two retained builds matched exactly under the same verified "
                    "identity controls; provider independence remains unproven."
                ),
                events=[
                    EventOutput(
                        event_type="RebuildCompared",
                        payload=base_payload,
                        source_repository=context.event.source_repository,
                        dedupe_key=content_digest(base_payload),
                    )
                ],
                artifacts=artifacts,
            )

        mismatch = create_rebuild_mismatch_packet(
            comparison,
            comparison_sha256=base_payload["comparison"]["sha256"],
        )
        mismatch_path = context.run_dir / "rebuild-mismatch-review.json"
        write_json_atomic(mismatch_path, mismatch)
        payload = {**base_payload, "mismatch": artifact_reference(mismatch_path)}
        artifacts.append(
            ArtifactOutput(role="rebuild-mismatch-review", path=mismatch_path)
        )
        return AgentResult(
            status="needs_human_review",
            summary=(
                "Rebuild comparison found promotion-blocking differences and "
                "retained a mismatch review packet."
            ),
            events=[
                EventOutput(
                    event_type="RebuildMismatch",
                    payload=payload,
                    source_repository=context.event.source_repository,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
            human_review=[
                (
                    f"{finding['code']}: {finding['subject']} "
                    f"({finding['classification']})"
                )
                for finding in comparison["blocking_findings"]
            ],
        )


class ReproducibilityGovernorHandler:
    agent_id = "governor"

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.producer_agent_id != "repro":
            raise ValueError(
                f"{context.event.event_type} must be produced by the repro agent"
            )
        if context.event.event_type not in {"RebuildCompared", "RebuildMismatch"}:
            raise ValueError(
                "Reproducibility Governor requires a rebuild comparison event"
            )
        comparison_path = verified_artifact_path(
            context.event.payload.get("comparison"),
            label="rebuild comparison",
        )
        comparison = read_json(comparison_path)
        matched_event = context.event.event_type == "RebuildCompared"
        checks = reproducibility_gate_checks(
            comparison,
            matched_event=matched_event,
        )
        coherent = all(check["passed"] for check in checks)
        mismatch_path = None
        if not matched_event:
            mismatch_path = verified_artifact_path(
                context.event.payload.get("mismatch"),
                label="rebuild mismatch review",
            )
            mismatch = read_json(mismatch_path)
            coherent = coherent and (
                mismatch.get("status") == "needs-human-review"
                and mismatch.get("reproducible") is False
                and mismatch.get("comparison_sha256")
                == context.event.payload["comparison"]["sha256"]
            )
            checks.append(
                {
                    "check": "mismatch-review-bound",
                    "passed": coherent,
                    "detail": "review packet must bind the exact failed comparison",
                }
            )

        gate_passed = matched_event and coherent
        decision = {
            "schema_version": 1,
            "gate": "artifact-reproducibility-candidate",
            "passed": gate_passed,
            "comparison_matched": comparison.get("reproducible") is True,
            "authority": "durable-reproducibility-candidate-gate",
            "promotion_authorized": False,
            "checks": checks,
            "comparison": context.event.payload["comparison"],
            "claim_limit": (
                "This gate blocks mismatches and can emit a reproducibility "
                "candidate after exact artifact and SBOM comparison. It does not "
                "authorize release promotion or establish independent builders."
            ),
        }
        decision_path = context.run_dir / "reproducibility-gate.json"
        write_json_atomic(decision_path, decision)
        payload = {
            "gate": artifact_reference(decision_path),
            "comparison": context.event.payload["comparison"],
            "promotion_authorized": False,
        }
        artifact = ArtifactOutput(
            role="reproducibility-candidate-gate",
            path=decision_path,
        )
        if gate_passed:
            return AgentResult(
                status="succeeded",
                summary=(
                    "Governor accepted an exact reproducibility candidate; no "
                    "release promotion or independent-builder claim was granted."
                ),
                events=[
                    EventOutput(
                        event_type="ReproducibilityCandidateReady",
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
        if coherent and not matched_event:
            failed_checks = [
                (
                    "Artifact reproducibility mismatch requires review; release "
                    "promotion remains blocked."
                )
            ]
        return AgentResult(
            status=(
                "needs_human_review"
                if coherent and not matched_event
                else "blocked"
            ),
            summary="Governor blocked artifact reproducibility promotion.",
            events=[
                EventOutput(
                    event_type="GateBlocked",
                    payload=payload,
                    source_repository=context.event.source_repository,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[artifact],
            human_review=failed_checks,
        )


def reproducibility_handlers() -> list[AgentHandler]:
    return [ReproducibilityHandler(), ReproducibilityGovernorHandler()]


def reproducibility_routes() -> dict[str, list[str]]:
    return {
        REPRODUCIBILITY_EVENT: ["repro"],
        "RebuildCompared": ["governor"],
        "RebuildMismatch": ["governor"],
        "RebuildComparisonRejected": [],
        "ReproducibilityCandidateReady": [],
        "GateBlocked": [],
    }


def run_reproducibility_agent_system(
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
    left_evidence = snapshot_evidence_bundle(
        left_evidence_path,
        run_dir=run_dir,
        namespace="left",
    )
    right_evidence = snapshot_evidence_bundle(
        right_evidence_path,
        run_dir=run_dir,
        namespace="right",
    )
    policy = snapshot_regular_file(
        policy_path,
        target_dir=run_dir / "inputs" / "control",
        label="build-verification-policy.json",
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
    effective_run_id = run_id or f"repro-{uuid.uuid4().hex[:12]}"
    database_path = (
        (database_path or run_dir / "agent-control-plane.sqlite3")
        .expanduser()
        .resolve()
    )
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=reproducibility_handlers(),
        routes=reproducibility_routes(),
        worker_id=worker_id or f"local-{os.getpid()}",
    )
    created = ensure_reproducibility_run(
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
            event_type=REPRODUCIBILITY_EVENT,
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
    summary_path = run_dir / "reproducibility-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def ensure_reproducibility_run(
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
            metadata={"workflow": REPRODUCIBILITY_WORKFLOW, "config": config},
        )
        return True
    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != REPRODUCIBILITY_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False


def require_authoritative_verification(
    verification: dict[str, Any], *, label: str
) -> None:
    if (
        verification.get("status") != "verified-evidence-candidate"
        or verification.get("ok") is not True
    ):
        raise ReproducibilityError(
            f"{label.capitalize()} verifier returned a non-authoritative result"
        )


def reproducibility_gate_checks(
    comparison: dict[str, Any],
    *,
    matched_event: bool,
) -> list[dict[str, Any]]:
    expected_match = bool(matched_event)
    artifact_match = nested_flag(comparison, "artifacts", "exact_match")
    sbom_match = nested_flag(comparison, "sbom", "exact_match")
    materials_match = nested_flag(comparison, "materials", "semantic_match")
    builder_match = nested_flag(comparison, "builder", "stable_match")
    checks = [
        (
            "comparison-event-consistent",
            comparison.get("status")
            == ("matched" if matched_event else "mismatch")
            and comparison.get("ok") is expected_match
            and comparison.get("reproducible") is expected_match,
            "event type must agree with the comparison decision",
        ),
        (
            "comparison-eligible",
            comparison.get("comparison_eligible") is True,
            "both freshly verified evidence sets must be comparable",
        ),
        (
            "component-decisions-present",
            all(
                type(value) is bool
                for value in (
                    artifact_match,
                    sbom_match,
                    materials_match,
                    builder_match,
                )
            ),
            "artifact, SPDX, material, and builder decisions must be explicit",
        ),
        (
            "provider-independence-not-claimed",
            comparison.get("provider_independent") is False,
            "same-provider evidence cannot claim provider independence",
        ),
        (
            "behavior-remains-diagnostic",
            nested_flag(
                comparison,
                "behavior_diagnostic",
                "promotion_gate",
            )
            is False,
            "behavior evidence must not gate this artifact stage",
        ),
    ]
    if matched_event:
        checks.extend(
            [
                (
                    "artifact-bytes",
                    artifact_match is True,
                    "artifact subjects must be byte-for-byte identical",
                ),
                (
                    "spdx-bytes",
                    sbom_match is True,
                    "SPDX documents must be byte-for-byte identical",
                ),
                (
                    "source-materials",
                    materials_match is True,
                    "source inventories must match",
                ),
                (
                    "stable-builder",
                    builder_match is True,
                    "stable builder configuration and outcomes must match",
                ),
            ]
        )
    else:
        findings = comparison.get("blocking_findings")
        checks.append(
            (
                "blocking-findings-retained",
                isinstance(findings, list) and bool(findings),
                "a failed comparison must retain blocking findings",
            )
        )
    return [
        {"check": name, "passed": passed, "detail": detail}
        for name, passed, detail in checks
    ]


def nested_flag(value: dict[str, Any], *path: str) -> Any:
    current: Any = value
    for component in path:
        if not isinstance(current, dict):
            return None
        current = current.get(component)
    return current


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
    output_path = context.run_dir / "rebuild-comparison-rejection.json"
    write_json_atomic(output_path, rejection)
    payload = {
        "rejection": artifact_reference(output_path),
        "inputs": inputs,
    }
    return AgentResult(
        status="blocked",
        summary="Rebuild comparison inputs or attestations were rejected.",
        events=[
            EventOutput(
                event_type="RebuildComparisonRejected",
                payload=payload,
                source_repository=context.event.source_repository,
                dedupe_key=content_digest(payload),
            )
        ],
        artifacts=[
            ArtifactOutput(role="rebuild-comparison-rejection", path=output_path)
        ],
        human_review=[error],
    )
