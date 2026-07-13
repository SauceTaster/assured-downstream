from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path, PurePosixPath
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
from assured_downstream.attestations import create_intoto_statement
from assured_downstream.behavior import event_kind, normalize_trace, syscall_category
from assured_downstream.evidence import (
    create_evidence_manifest,
    sha256_file,
    verify_evidence_manifest,
)
from assured_downstream.policy_eval import evaluate_release_candidate
from assured_downstream.release_verification import (
    ReleaseVerificationError,
    verify_release_attestations,
)
from assured_downstream.verification_guide import create_verification_guide


RELEASE_EVIDENCE_WORKFLOW = "release-evidence-ingestion-v1"
BUILD_RESULT_SCHEMA_VERSION = 1
GIT_SHA_LENGTH = 40
EVIDENCE_ROLES = (
    "artifacts",
    "sboms",
    "attestations",
    "raw_traces",
    "reports",
)
COPY_CHUNK_SIZE = 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 1024 * 1024 * 1024
MAX_EVIDENCE_FILES = 10000


class EvidenceLaneError(RuntimeError):
    pass


class BuildResultHandler:
    agent_id = "build"

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != "BuildResultRecorded":
            raise ValueError("Build Agent requires BuildResultRecorded")
        if context.event.producer_agent_id is not None:
            raise ValueError("BuildResultRecorded must be an external event")
        config = require_evidence_config(context.event.payload)
        index_path = verified_path(
            config["input_index_path"],
            config["input_index_sha256"],
            label="release evidence input index",
        )
        index = read_json(index_path)
        checks = validate_input_index(
            index,
            allow_test_fixture=config["allow_test_fixture"],
        )
        decision = {
            "schema_version": 1,
            "gate": "external-build-result-intake",
            "passed": all(check["passed"] for check in checks),
            "checks": checks,
        }
        decision_path = context.run_dir / "build-intake-decision.json"
        write_json_atomic(decision_path, decision)
        artifacts = [
            ArtifactOutput(role="build-intake-decision", path=decision_path),
            ArtifactOutput(role="release-evidence-input-index", path=index_path),
        ]
        for role in EVIDENCE_ROLES:
            artifacts.extend(
                ArtifactOutput(role=f"build-input-{role}", path=Path(entry["path"]))
                for entry in index["evidence"][role]
            )
        artifacts.extend(
            ArtifactOutput(role=f"build-input-{name}", path=Path(reference["path"]))
            for name, reference in index["verifications"].items()
        )
        if not decision["passed"]:
            return AgentResult(
                status="blocked",
                summary="External build result failed the intake gate.",
                artifacts=artifacts,
                human_review=[
                    check["detail"] for check in checks if not check["passed"]
                ],
            )
        payload = {
            "config": config,
            "input_index": artifact_reference(index_path),
        }
        return AgentResult(
            status="succeeded",
            summary=(
                "Accepted immutable outputs with an external isolation declaration; "
                "builder identity and containment remain unverified."
            ),
            events=[
                EventOutput(
                    event_type="BuildArtifactsReady",
                    payload=payload,
                    source_repository=index["project"]["source_full_name"],
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
        )


class TraceEvidenceHandler:
    agent_id = "trace"

    def handle(self, context: AgentContext) -> AgentResult:
        require_producer(context, "build")
        if context.event.event_type != "BuildArtifactsReady":
            raise ValueError("Trace Agent requires BuildArtifactsReady")
        config = require_evidence_config(context.event.payload)
        index_path = verified_artifact_path(
            context.event.payload.get("input_index"),
            label="release evidence input index",
        )
        index = read_json(index_path)
        traces = index["evidence"]["raw_traces"]
        trace_reports: list[dict[str, Any]] = []
        artifacts: list[ArtifactOutput] = []
        policy_failures: list[str] = []
        coverage = {
            "status": "unsupported",
            "collectors": [],
            "process": False,
            "file": False,
            "network": False,
            "syscall": False,
        }
        for position, entry in enumerate(traces, start=1):
            trace_path = verified_path(
                entry["path"],
                entry["sha256"],
                label="raw build trace",
            )
            trace = read_json(trace_path)
            validate_raw_trace(trace)
            report = normalize_trace(
                trace,
                workspace_root=Path(index["builder"]["workspace_root"]),
            )
            report["coverage"] = normalize_trace_coverage(trace.get("coverage"))
            report["collector"] = trace.get("collector")
            report_path = context.run_dir / "traces" / f"normalized-{position}.json"
            write_json_atomic(report_path, report)
            artifacts.append(
                ArtifactOutput(role="normalized-build-trace", path=report_path)
            )
            trace_reports.append(artifact_reference(report_path))
            merge_coverage(coverage, report)
            policy_failures.extend(
                trace_policy_failures(
                    trace,
                    network_policy=index["builder"]["network_policy"],
                )
            )

        trace_policy = {
            "schema_version": 1,
            "passed": not policy_failures,
            "coverage": coverage,
            "failures": sorted(set(policy_failures)),
            "claim_limit": (
                "Trace evidence records collector-observed behavior only; it is "
                "not a containment boundary or completeness proof."
            ),
        }
        policy_path = context.run_dir / "trace-policy.json"
        write_json_atomic(policy_path, trace_policy)
        artifacts.append(ArtifactOutput(role="trace-policy", path=policy_path))
        if policy_failures:
            return AgentResult(
                status="blocked",
                summary="Trace policy detected forbidden build behavior.",
                artifacts=artifacts,
                human_review=trace_policy["failures"],
            )
        payload = {
            "config": config,
            "input_index": context.event.payload["input_index"],
            "trace_reports": trace_reports,
            "trace_policy": artifact_reference(policy_path),
        }
        return AgentResult(
            status="succeeded",
            summary=(
                f"Normalized {len(trace_reports)} build trace(s); coverage status "
                f"is {coverage['status']}."
            ),
            events=[
                EventOutput(
                    event_type="TraceReady",
                    payload=payload,
                    source_repository=index["project"]["source_full_name"],
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
            human_review=(
                []
                if coverage["status"] == "recorded"
                else ["Trace collector coverage is unavailable for this build."]
            ),
        )


class ReleaseAttestationHandler:
    agent_id = "attestation"

    def handle(self, context: AgentContext) -> AgentResult:
        require_producer(context, "trace")
        if context.event.event_type != "TraceReady":
            raise ValueError("Attestation Agent requires TraceReady")
        config = require_evidence_config(context.event.payload)
        index_path = verified_artifact_path(
            context.event.payload.get("input_index"),
            label="release evidence input index",
        )
        index = read_json(index_path)
        trace_policy_path = verified_artifact_path(
            context.event.payload.get("trace_policy"),
            label="trace policy",
        )
        trace_policy = read_json(trace_policy_path)
        if trace_policy.get("passed") is not True:
            raise EvidenceLaneError("Trace policy did not pass")
        trace_paths = [
            verified_artifact_path(reference, label="normalized trace")
            for reference in context.event.payload.get("trace_reports", [])
        ]
        artifacts = verified_index_paths(index, "artifacts")
        sboms = verified_index_paths(index, "sboms")
        signed_attestations = verified_index_paths(index, "attestations")
        reports = verified_index_paths(index, "reports")

        statement = create_intoto_statement(
            subjects=artifacts,
            predicate_type=(
                "https://assured-downstream.dev/attestation/build-trace-binding/v1"
            ),
            predicate={
                "sourceRepository": index["project"]["source_full_name"],
                "targetRepository": index["project"]["target_full_name"],
                "upstreamRef": index["project"]["upstream_ref"],
                "overlayRef": index["project"]["overlay_ref"],
                "builder": index["builder"],
                "buildResultSha256": index["build_result"]["sha256"],
                "traceDigests": [read_json(path)["digest"] for path in trace_paths],
                "attestationMode": "local-unsigned-evidence-binding",
                "claimLimit": (
                    "This statement binds collected evidence but is not itself a "
                    "Sigstore signature or SLSA level claim."
                ),
                "builderTrust": "unverified-external-declaration",
            },
        )
        statement_path = context.run_dir / "build-trace.intoto.json"
        write_json_atomic(statement_path, statement)
        manifest = create_evidence_manifest(
            project=index["project"]["source_full_name"],
            target_repo=index["project"]["target_full_name"],
            upstream_ref=index["project"]["upstream_ref"],
            overlay_ref=index["project"]["overlay_ref"],
            release_tag=index["project"]["release_tag"],
            assurance="Evidence-candidate",
            files={
                "artifacts": artifacts,
                "sboms": sboms,
                "attestations": signed_attestations,
                "statements": [statement_path],
                "traces": trace_paths,
                "reports": [*reports, trace_policy_path],
            },
            root=context.run_dir,
        )
        manifest_path = context.run_dir / "evidence.json"
        write_json_atomic(manifest_path, manifest)
        verification = verify_evidence_manifest(manifest, base_dir=context.run_dir)
        verification_path = context.run_dir / "evidence-verification.json"
        write_json_atomic(verification_path, verification)
        guide_path = context.run_dir / "VERIFY.md"
        guide_path.write_text(create_verification_guide(manifest), encoding="utf-8")
        output_artifacts = [
            ArtifactOutput(role="local-in-toto-statement", path=statement_path),
            ArtifactOutput(role="release-evidence-manifest", path=manifest_path),
            ArtifactOutput(role="evidence-verification", path=verification_path),
            ArtifactOutput(
                role="release-verification-guide",
                path=guide_path,
                media_type="text/markdown",
            ),
        ]
        if not verification["ok"]:
            return AgentResult(
                status="blocked",
                summary="Release evidence manifest failed local verification.",
                artifacts=output_artifacts,
                human_review=verification["failures"],
            )
        payload = {
            "config": config,
            "input_index": context.event.payload["input_index"],
            "evidence": artifact_reference(manifest_path),
            "evidence_verification": artifact_reference(verification_path),
            "verification_guide": artifact_reference(guide_path),
            "trace_policy": context.event.payload["trace_policy"],
        }
        return AgentResult(
            status="succeeded",
            summary="Assembled and locally verified the candidate release evidence bundle.",
            events=[
                EventOutput(
                    event_type="ReleaseEvidenceReady",
                    payload=payload,
                    source_repository=index["project"]["source_full_name"],
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=output_artifacts,
        )


class ReleaseVerificationHandler:
    agent_id = "release-verifier"

    def handle(self, context: AgentContext) -> AgentResult:
        require_producer(context, "attestation")
        if context.event.event_type != "ReleaseEvidenceReady":
            raise ValueError("Release Verifier Agent requires ReleaseEvidenceReady")
        config: dict[str, Any] | None = None
        index: dict[str, Any] | None = None
        try:
            config = require_evidence_config(context.event.payload)
            index_path = verified_artifact_path(
                context.event.payload.get("input_index"),
                label="release evidence input index",
            )
            index = read_json(index_path)
            evidence_path = verified_artifact_path(
                context.event.payload.get("evidence"),
                label="release evidence manifest",
            )
            policy_path = verified_index_reference(
                index,
                "release_verification_policy",
            )
            verification = verify_release_attestations(
                evidence_path=evidence_path,
                policy_path=policy_path,
            )
            if (
                not isinstance(verification, dict)
                or verification.get("status") != "verified"
                or verification.get("ok") is not True
            ):
                raise EvidenceLaneError(
                    "Release verifier returned a non-authoritative result"
                )
            validate_release_verification_record(
                verification,
                index=index,
                evidence_path=evidence_path,
                policy_path=policy_path,
                allow_test_fixture=config["allow_test_fixture"],
            )
        except (
            ReleaseVerificationError,
            EvidenceLaneError,
            FileNotFoundError,
            KeyError,
            ValueError,
        ) as exc:
            rejected = {
                "schema_version": 1,
                "status": "rejected",
                "authority": "none",
                "error": str(exc),
            }
            rejected_path = context.run_dir / "release-attestation-verification.json"
            write_json_atomic(rejected_path, rejected)
            payload: dict[str, Any] = {
                "rejection": artifact_reference(rejected_path)
            }
            if config is not None:
                payload["config"] = config
            for field in ("input_index", "evidence"):
                if field in context.event.payload:
                    payload[field] = context.event.payload[field]
            source_repository = context.event.source_repository
            if index is not None and isinstance(index.get("project"), dict):
                source_repository = index["project"].get("source_full_name")
            return AgentResult(
                status="blocked",
                summary="Release attestation verification failed.",
                events=[
                    EventOutput(
                        event_type="ReleaseAttestationsRejected",
                        payload=payload,
                        source_repository=source_repository,
                        dedupe_key=content_digest(payload),
                    )
                ],
                artifacts=[
                    ArtifactOutput(
                        role="release-attestation-verification",
                        path=rejected_path,
                    )
                ],
                human_review=[str(exc)],
            )
        verification_path = context.run_dir / "release-attestation-verification.json"
        write_json_atomic(verification_path, verification)
        payload = {
            "config": config,
            "input_index": context.event.payload["input_index"],
            "evidence": context.event.payload["evidence"],
            "evidence_verification": context.event.payload["evidence_verification"],
            "verification_guide": context.event.payload["verification_guide"],
            "trace_policy": context.event.payload["trace_policy"],
            "attestation_verification": artifact_reference(verification_path),
        }
        return AgentResult(
            status="succeeded",
            summary="Cryptographically verified retained release attestations.",
            events=[
                EventOutput(
                    event_type="ReleaseAttestationsVerified",
                    payload=payload,
                    source_repository=index["project"]["source_full_name"],
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[
                ArtifactOutput(
                    role="release-attestation-verification",
                    path=verification_path,
                )
            ],
        )


class EvidenceGovernorHandler:
    agent_id = "governor"

    def handle(self, context: AgentContext) -> AgentResult:
        require_producer(context, "release-verifier")
        if context.event.event_type != "ReleaseAttestationsVerified":
            raise ValueError("Evidence Governor requires ReleaseAttestationsVerified")
        require_evidence_config(context.event.payload)
        index = read_json(
            verified_artifact_path(
                context.event.payload.get("input_index"),
                label="release evidence input index",
            )
        )
        evidence = read_json(
            verified_artifact_path(
                context.event.payload.get("evidence"),
                label="release evidence manifest",
            )
        )
        evidence_verification = read_json(
            verified_artifact_path(
                context.event.payload.get("evidence_verification"),
                label="evidence verification",
            )
        )
        attestation_verification = read_json(
            verified_artifact_path(
                context.event.payload.get("attestation_verification"),
                label="release attestation verification",
            )
        )
        tooling_verification = read_json(
            verified_index_reference(index, "tooling_verification")
        )
        workflow_risk_verification = read_json(
            verified_index_reference(index, "workflow_risk_verification")
        )
        evaluation = evaluate_release_candidate(
            evidence=evidence,
            target="Attested",
            evidence_verification=evidence_verification,
            attestation_verification=attestation_verification,
            tooling_verification=tooling_verification,
            workflow_risk_verification=workflow_risk_verification,
        )
        trace_policy = read_json(
            verified_artifact_path(
                context.event.payload.get("trace_policy"),
                label="trace policy",
            )
        )
        evaluation["trace_coverage"] = trace_policy["coverage"]
        evaluation["claim_limit"] = (
            "This result validates local evidence consistency and cryptographic "
            "attestations; tooling and builder claims remain unverified, and it does "
            "not claim isolation, reproducibility, behavior parity, syscall "
            "completeness, or safety."
        )
        evaluation["authority"] = "none; untrusted input shape validation only"
        evaluation["attestation_authority"] = attestation_verification.get("authority")
        evaluation_path = context.run_dir / "release-evaluation.json"
        write_json_atomic(evaluation_path, evaluation)
        artifact = ArtifactOutput(role="release-evaluation", path=evaluation_path)
        if evaluation["decision"] != "candidate":
            return AgentResult(
                status="blocked",
                summary="Governor blocked the evidence-candidate input shape.",
                artifacts=[artifact],
                human_review=evaluation["failures"],
            )
        payload = {
            "evaluation": artifact_reference(evaluation_path),
            "evidence": context.event.payload["evidence"],
        }
        return AgentResult(
            status="succeeded",
            summary=(
                "Governor found the evidence-candidate input shape complete; no "
                "security assurance or release authority was granted."
            ),
            events=[
                EventOutput(
                    event_type="EvidenceCandidateReady",
                    payload=payload,
                    source_repository=index["project"]["source_full_name"],
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[artifact],
        )


def release_evidence_handlers() -> list[AgentHandler]:
    return [
        BuildResultHandler(),
        TraceEvidenceHandler(),
        ReleaseAttestationHandler(),
        ReleaseVerificationHandler(),
        EvidenceGovernorHandler(),
    ]


def release_evidence_routes() -> dict[str, list[str]]:
    return {
        "BuildResultRecorded": ["build"],
        "BuildArtifactsReady": ["trace"],
        "TraceReady": ["attestation"],
        "ReleaseEvidenceReady": ["release-verifier"],
        "ReleaseAttestationsVerified": ["governor"],
        "ReleaseAttestationsRejected": [],
        "EvidenceCandidateReady": [],
    }


def run_release_evidence_agent_system(
    *,
    build_result_path: Path,
    evidence_root: Path,
    release_verification_policy_path: Path,
    tooling_verification_path: Path,
    workflow_risk_verification_path: Path,
    run_dir: Path,
    database_path: Path | None = None,
    run_id: str | None = None,
    worker_id: str | None = None,
    max_items: int = 100,
    enqueue_only: bool = False,
    allow_test_fixture: bool = False,
) -> dict[str, Any]:
    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    run_dir = run_dir.expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    input_index_path = prepare_release_evidence_inputs(
        build_result_path=build_result_path,
        evidence_root=evidence_root,
        release_verification_policy_path=release_verification_policy_path,
        tooling_verification_path=tooling_verification_path,
        workflow_risk_verification_path=workflow_risk_verification_path,
        run_dir=run_dir,
    )
    config = {
        "input_index_path": str(input_index_path),
        "input_index_sha256": sha256_file(input_index_path),
        "allow_test_fixture": allow_test_fixture,
    }
    effective_run_id = run_id or f"evidence-{uuid.uuid4().hex[:12]}"
    database_path = (
        (database_path or run_dir / "agent-control-plane.sqlite3")
        .expanduser()
        .resolve()
    )
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=release_evidence_handlers(),
        routes=release_evidence_routes(),
        worker_id=worker_id or f"local-{os.getpid()}",
    )
    created = ensure_evidence_run(
        store,
        runtime=runtime,
        run_id=effective_run_id,
        run_dir=run_dir,
        database_path=database_path,
        config=config,
    )
    if created:
        runtime.publish_external(
            run_id=effective_run_id,
            event_type="BuildResultRecorded",
            payload={"config": config},
            dedupe_key=f"build-result:{config['input_index_sha256']}",
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
    summary_path = run_dir / "release-evidence-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def prepare_release_evidence_inputs(
    *,
    build_result_path: Path,
    evidence_root: Path,
    release_verification_policy_path: Path,
    tooling_verification_path: Path,
    workflow_risk_verification_path: Path,
    run_dir: Path,
) -> Path:
    build_snapshot = snapshot_regular_file(
        build_result_path,
        target_dir=run_dir / "inputs" / "control",
        label="build-result.json",
    )
    build_result = read_json(Path(build_snapshot["path"]))
    if not isinstance(build_result.get("evidence"), dict):
        raise EvidenceLaneError("Build result evidence map is invalid")
    root = evidence_root.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(root)
    staged_evidence: dict[str, list[dict[str, Any]]] = {}
    evidence_file_count = 0
    for role in EVIDENCE_ROLES:
        values = build_result["evidence"].get(role, [])
        if not isinstance(values, list) or not all(
            isinstance(value, str) and value for value in values
        ):
            raise EvidenceLaneError(f"Build result {role} paths are invalid")
        evidence_file_count += len(values)
        if evidence_file_count > MAX_EVIDENCE_FILES:
            raise EvidenceLaneError("Build result contains too many evidence files")
        staged_evidence[role] = [
            {
                "original_path": value,
                **snapshot_regular_file(
                    guarded_evidence_path(root, value),
                    target_dir=run_dir / "inputs" / "evidence" / role,
                    label=Path(value).name,
                ),
            }
            for value in values
        ]
    verification_sources = {
        "release_verification_policy": release_verification_policy_path,
        "tooling_verification": tooling_verification_path,
        "workflow_risk_verification": workflow_risk_verification_path,
    }
    verifications = {
        name: snapshot_regular_file(
            path,
            target_dir=run_dir / "inputs" / "verification",
            label=f"{name}.json",
        )
        for name, path in verification_sources.items()
    }
    index = {
        "schema_version": 1,
        "workflow": RELEASE_EVIDENCE_WORKFLOW,
        "build_result": build_snapshot,
        "project": build_result.get("project"),
        "builder": build_result.get("builder"),
        "status": build_result.get("status"),
        "evidence": staged_evidence,
        "verifications": verifications,
    }
    index_path = run_dir / "inputs" / "release-evidence-input-index.json"
    write_json_atomic(index_path, index)
    return index_path.resolve()


def validate_input_index(
    index: dict[str, Any],
    *,
    allow_test_fixture: bool,
) -> list[dict[str, Any]]:
    project = index.get("project") if isinstance(index.get("project"), dict) else {}
    builder = index.get("builder") if isinstance(index.get("builder"), dict) else {}
    evidence = index.get("evidence") if isinstance(index.get("evidence"), dict) else {}
    mode = builder.get("mode")
    checks = [
        gate_check(
            "schema",
            index.get("schema_version") == BUILD_RESULT_SCHEMA_VERSION
            and index.get("workflow") == RELEASE_EVIDENCE_WORKFLOW,
            "release evidence input index schema or workflow is invalid",
        ),
        gate_check(
            "build-status",
            index.get("status") == "succeeded",
            "external builder did not report success",
        ),
        gate_check(
            "project-identity",
            all(
                isinstance(project.get(key), str) and bool(project[key])
                for key in (
                    "source_full_name",
                    "target_full_name",
                    "release_tag",
                )
            )
            and valid_git_sha(project.get("upstream_ref"))
            and valid_git_sha(project.get("overlay_ref")),
            "project identity or source/overlay commit is invalid",
        ),
        gate_check(
            "declared-isolation",
            builder.get("isolated") is True
            and builder.get("secrets_exposed") is False
            and builder.get("network_policy") == "deny"
            and isinstance(builder.get("workspace_root"), str)
            and str(builder.get("workspace_root")).startswith("/"),
            "builder must declare isolation, no secret exposure, and denied network",
        ),
        gate_check(
            "builder-mode",
            mode == "external-isolated"
            or (mode == "test-fixture" and allow_test_fixture),
            "builder mode is not allowed for this run",
        ),
        gate_check(
            "required-evidence",
            all(evidence.get(role) for role in ("artifacts", "sboms", "attestations")),
            "build result is missing artifact, SBOM, or signed attestation evidence",
        ),
    ]
    for role in EVIDENCE_ROLES:
        for entry in evidence.get(role, []):
            try:
                verified_path(entry["path"], entry["sha256"], label=role)
            except (KeyError, EvidenceLaneError, FileNotFoundError) as exc:
                checks.append(gate_check(f"{role}-digest", False, str(exc)))
    return checks


def validate_raw_trace(trace: dict[str, Any]) -> None:
    if trace.get("schema_version") != 1:
        raise EvidenceLaneError("Raw trace schema is invalid")
    if not isinstance(trace.get("events"), list) or not all(
        isinstance(event, dict) for event in trace["events"]
    ):
        raise EvidenceLaneError("Raw trace events are invalid")
    if not isinstance(trace.get("collector"), dict):
        raise EvidenceLaneError("Raw trace collector identity is missing")


def normalize_trace_coverage(value: Any) -> dict[str, bool]:
    source = value if isinstance(value, dict) else {}
    return {
        category: source.get(category) is True
        for category in ("process", "file", "network", "syscall")
    }


def validate_release_verification_record(
    value: dict[str, Any],
    *,
    index: dict[str, Any],
    evidence_path: Path,
    policy_path: Path,
    allow_test_fixture: bool,
) -> None:
    evidence = read_json(evidence_path)
    evidence_roles = evidence.get("evidence")
    artifact_entries = (
        evidence_roles.get("artifacts") if isinstance(evidence_roles, dict) else None
    )
    if not isinstance(artifact_entries, list) or not artifact_entries:
        raise EvidenceLaneError("Release verification has no artifact subjects")
    expected_subjects = {
        require_sha256(entry.get("sha256"), label="artifact digest")
        for entry in artifact_entries
        if isinstance(entry, dict)
    }
    verified_subjects = value.get("verified_subjects")
    if not isinstance(verified_subjects, list):
        raise EvidenceLaneError("Release verification subject set is invalid")
    actual_subjects = {
        require_sha256(entry.get("sha256"), label="verified artifact digest")
        for entry in verified_subjects
        if isinstance(entry, dict)
    }
    if (
        len(expected_subjects) != len(artifact_entries)
        or len(actual_subjects) != len(verified_subjects)
        or actual_subjects != expected_subjects
    ):
        raise EvidenceLaneError(
            "Release verification subjects do not exactly match artifacts"
        )

    builder = index.get("builder") if isinstance(index.get("builder"), dict) else {}
    fixture_mode = allow_test_fixture and builder.get("mode") == "test-fixture"
    if fixture_mode:
        if value.get("authority") != "test-fixture-non-authoritative":
            raise EvidenceLaneError("Test fixture verification authority is invalid")
        return

    project = index.get("project") if isinstance(index.get("project"), dict) else {}
    required = {
        "authority": "code-anchored-github-sigstore",
        "evidence_sha256": sha256_file(evidence_path),
        "policy_sha256": sha256_file(policy_path),
        "target_full_name": project.get("target_full_name"),
        "overlay_ref": project.get("overlay_ref"),
        "release_tag": project.get("release_tag"),
    }
    for field, expected in required.items():
        if value.get(field) != expected:
            raise EvidenceLaneError(
                f"Release verification does not bind the expected {field}"
            )


def merge_coverage(coverage: dict[str, Any], report: dict[str, Any]) -> None:
    collector = report.get("collector")
    if isinstance(collector, dict):
        coverage["collectors"].append(collector)
    report_coverage = report.get("coverage") or {}
    for category in ("process", "file", "network", "syscall"):
        coverage[category] = coverage[category] or report_coverage.get(category) is True
    coverage["status"] = "recorded"


def trace_policy_failures(
    trace: dict[str, Any],
    *,
    network_policy: str,
) -> list[str]:
    failures = []
    for event in trace["events"]:
        kind = event_kind(event)
        outcome = str(event.get("outcome") or event.get("result") or "unknown")
        denied = outcome in {"blocked", "denied", "failed"}
        if kind == "network" and network_policy == "deny" and not denied:
            failures.append("network activity succeeded under deny policy")
        if kind == "syscall":
            name = str(event.get("name") or event.get("syscall") or "unknown")
            if syscall_category(name) == "privileged" and not denied:
                failures.append(f"privileged syscall succeeded: {name}")
        if kind == "file":
            operation = str(event.get("op") or event.get("operation") or "access")
            path = str(event.get("path") or event.get("file") or "")
            if operation in {"create", "delete", "rename", "write"} and path.startswith(
                ("/etc", "/root", "/home")
            ):
                failures.append(f"host-sensitive file mutation observed: {path}")
    return failures


def verified_index_paths(index: dict[str, Any], role: str) -> list[Path]:
    return [
        verified_path(entry["path"], entry["sha256"], label=role)
        for entry in index["evidence"][role]
    ]


def verified_index_reference(index: dict[str, Any], name: str) -> Path:
    reference = index["verifications"][name]
    return verified_path(reference["path"], reference["sha256"], label=name)


def ensure_evidence_run(
    store: AgentStore,
    *,
    runtime: AgentRuntime,
    run_id: str,
    run_dir: Path,
    database_path: Path,
    config: dict[str, Any],
) -> bool:
    try:
        existing = store.get_run(run_id)
    except KeyError:
        runtime.create_run(
            run_id=run_id,
            run_dir=run_dir,
            metadata={
                "workflow": RELEASE_EVIDENCE_WORKFLOW,
                "database_path": str(database_path),
                "config": config,
            },
        )
        return True
    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != RELEASE_EVIDENCE_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False


def require_evidence_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = payload.get("config")
    if not isinstance(config, dict):
        raise ValueError("Release evidence event is missing config")
    if not isinstance(config.get("input_index_path"), str):
        raise ValueError("Release evidence input index path is invalid")
    require_sha256(config.get("input_index_sha256"), label="input index digest")
    if not isinstance(config.get("allow_test_fixture"), bool):
        raise ValueError("Release evidence test-fixture policy is invalid")
    return config


def snapshot_regular_file(
    source: Path,
    *,
    target_dir: Path,
    label: str,
) -> dict[str, Any]:
    source = source.expanduser()
    try:
        source_stat = source.lstat()
    except OSError as exc:
        raise FileNotFoundError(source) from exc
    if (
        not stat.S_ISREG(source_stat.st_mode)
        or source.is_symlink()
        or source_stat.st_nlink != 1
    ):
        raise EvidenceLaneError(f"Evidence input is not a regular file: {source}")
    if source_stat.st_size > MAX_EVIDENCE_FILE_BYTES:
        raise EvidenceLaneError(f"Evidence input exceeds the file-size limit: {source}")
    safe_name = "".join(
        character if character.isalnum() or character in "-_." else "_"
        for character in label
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    temporary = target_dir / f".snapshot.{uuid.uuid4().hex}.tmp"
    digest_state = hashlib.sha256()
    copied_size = 0
    source_descriptor: int | None = None
    target_descriptor: int | None = None
    try:
        source_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            source_flags |= os.O_NOFOLLOW
        source_descriptor = os.open(source, source_flags)
        opened_stat = os.fstat(source_descriptor)
        if evidence_file_identity(opened_stat) != evidence_file_identity(source_stat):
            raise EvidenceLaneError(
                f"Evidence input changed before snapshotting: {source}"
            )
        target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            target_flags |= os.O_NOFOLLOW
        target_descriptor = os.open(temporary, target_flags, 0o600)
        while chunk := os.read(source_descriptor, COPY_CHUNK_SIZE):
            copied_size += len(chunk)
            if copied_size > MAX_EVIDENCE_FILE_BYTES:
                raise EvidenceLaneError(
                    f"Evidence input exceeds the file-size limit: {source}"
                )
            digest_state.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise EvidenceLaneError(
                        f"Evidence snapshot write stalled: {temporary}"
                    )
                view = view[written:]
        os.fchmod(target_descriptor, 0o400)
        os.fsync(target_descriptor)
        final_opened_stat = os.fstat(source_descriptor)
        final_stat = source.lstat()
        source_identity = evidence_file_identity(source_stat)
        if (
            source_identity != evidence_file_identity(final_opened_stat)
            or source_identity != evidence_file_identity(final_stat)
            or copied_size != source_stat.st_size
        ):
            raise EvidenceLaneError(
                f"Evidence input changed while snapshotting: {source}"
            )
        os.close(target_descriptor)
        target_descriptor = None
        os.close(source_descriptor)
        source_descriptor = None
        digest = digest_state.hexdigest()
        target = target_dir / f"{digest}-{safe_name}"
        if target.exists():
            target_stat = target.lstat()
            if (
                not stat.S_ISREG(target_stat.st_mode)
                or target.is_symlink()
                or target_stat.st_nlink != 1
                or target_stat.st_size != copied_size
                or sha256_file(target) != digest
            ):
                raise EvidenceLaneError(
                    f"Persisted evidence snapshot changed: {target}"
                )
        else:
            os.replace(temporary, target)
            fsync_evidence_directory(target_dir)
    finally:
        if target_descriptor is not None:
            os.close(target_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
        temporary.unlink(missing_ok=True)
    return {
        "path": str(target.resolve()),
        "sha256": digest,
        "size": copied_size,
    }


def evidence_file_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_nlink,
    )


def fsync_evidence_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def guarded_evidence_path(root: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise EvidenceLaneError(f"Evidence path escapes its root: {value}")
    candidate = root.joinpath(*relative.parts)
    try:
        candidate.lstat()
    except OSError as exc:
        raise FileNotFoundError(candidate) from exc
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root) or candidate.is_symlink():
        raise EvidenceLaneError(f"Evidence path escapes its root: {value}")
    return candidate


def verified_path(path_value: Any, digest_value: Any, *, label: str) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise EvidenceLaneError(f"{label.capitalize()} path is invalid")
    digest = require_sha256(digest_value, label=f"{label} digest")
    candidate = Path(path_value)
    if candidate.is_symlink():
        raise EvidenceLaneError(f"{label.capitalize()} symlink is forbidden")
    path = candidate.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    if sha256_file(path) != digest:
        raise EvidenceLaneError(f"{label.capitalize()} digest changed")
    return path


def artifact_reference(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": sha256_file(resolved),
        "size": resolved.stat().st_size,
    }


def verified_artifact_path(value: Any, *, label: str) -> Path:
    if not isinstance(value, dict):
        raise EvidenceLaneError(f"{label.capitalize()} artifact reference is invalid")
    return verified_path(value.get("path"), value.get("sha256"), label=label)


def require_sha256(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EvidenceLaneError(f"{label.capitalize()} is invalid")
    return value


def valid_git_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == GIT_SHA_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def gate_check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "passed": bool(passed), "detail": detail}


def require_producer(context: AgentContext, expected: str) -> None:
    if context.event.producer_agent_id != expected:
        raise ValueError(
            f"{context.event.event_type} must be produced by the {expected} agent"
        )


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceLaneError(f"Unable to read JSON evidence: {path}") from exc
    if not isinstance(value, dict):
        raise EvidenceLaneError(f"JSON evidence must be an object: {path}")
    return value


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
