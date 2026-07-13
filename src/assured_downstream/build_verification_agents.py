from __future__ import annotations

import copy
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
from assured_downstream.evidence_agents import (
    EvidenceLaneError,
    artifact_reference,
    read_json,
    snapshot_regular_file,
    verified_artifact_path,
    write_json_atomic,
)
from assured_downstream.release_verification import resolve_evidence_entry


BUILD_VERIFICATION_WORKFLOW = "retained-build-verification-v1"
BUILD_VERIFICATION_EVENT = "BuildVerificationRequested"


class BuilderVerificationHandler:
    agent_id = "builder-verifier"

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != BUILD_VERIFICATION_EVENT:
            raise ValueError(
                "Builder Verifier Agent requires BuildVerificationRequested"
            )
        if context.event.producer_agent_id is not None:
            raise ValueError("BuildVerificationRequested must be an external event")
        inputs = context.event.payload.get("inputs")
        if not isinstance(inputs, dict):
            raise ValueError("Builder verification event has no input references")
        output_path = context.run_dir / "build-attestation-verification.json"
        try:
            evidence_path = verified_artifact_path(
                inputs.get("evidence"),
                label="build evidence manifest",
            )
            policy_path = verified_artifact_path(
                inputs.get("policy"),
                label="build verification policy",
            )
            trust_policy_path = verified_artifact_path(
                inputs.get("trust_policy"),
                label="Sigstore trust policy",
            )
            verification = verify_build_attestations(
                evidence_path=evidence_path,
                policy_path=policy_path,
                trust_policy_path=trust_policy_path,
            )
            if (
                verification.get("status") != "verified-evidence-candidate"
                or verification.get("ok") is not True
            ):
                raise EvidenceLaneError(
                    "Builder verifier returned a non-authoritative result"
                )
        except (
            BuildVerificationError,
            EvidenceLaneError,
            FileNotFoundError,
            KeyError,
            ValueError,
        ) as exc:
            rejection = {
                "schema_version": 1,
                "status": "rejected",
                "authority": "none",
                "error": str(exc),
            }
            write_json_atomic(output_path, rejection)
            payload = {
                "verification": artifact_reference(output_path),
                "inputs": inputs,
            }
            return AgentResult(
                status="blocked",
                summary="Builder attestation verification was rejected.",
                events=[
                    EventOutput(
                        event_type="BuildAttestationsRejected",
                        payload=payload,
                        source_repository=context.event.source_repository,
                        dedupe_key=content_digest(payload),
                    )
                ],
                artifacts=[
                    ArtifactOutput(
                        role="build-attestation-rejection",
                        path=output_path,
                    )
                ],
                human_review=[str(exc)],
            )

        write_json_atomic(output_path, verification)
        payload = {
            "verification": artifact_reference(output_path),
            "evidence": inputs["evidence"],
        }
        return AgentResult(
            status="succeeded",
            summary=(
                "Verified retained build attestations as an evidence candidate; "
                "no release assurance was granted."
            ),
            events=[
                EventOutput(
                    event_type="BuildAttestationsVerified",
                    payload=payload,
                    source_repository=context.event.source_repository,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[
                ArtifactOutput(
                    role="build-attestation-verification",
                    path=output_path,
                )
            ],
        )


def build_verification_handlers() -> list[AgentHandler]:
    return [BuilderVerificationHandler()]


def build_verification_routes() -> dict[str, list[str]]:
    return {
        BUILD_VERIFICATION_EVENT: ["builder-verifier"],
        "BuildAttestationsVerified": [],
        "BuildAttestationsRejected": [],
    }


def run_build_verification_agent_system(
    *,
    evidence_path: Path,
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
    run_dir = run_dir.expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    staged_evidence = snapshot_evidence_bundle(evidence_path, run_dir=run_dir)
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
        "evidence": staged_evidence,
        "policy": policy,
        "trust_policy": trust_policy,
    }
    config = {"inputs": inputs}
    effective_run_id = run_id or f"build-verify-{uuid.uuid4().hex[:12]}"
    database_path = (
        (database_path or run_dir / "agent-control-plane.sqlite3")
        .expanduser()
        .resolve()
    )
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=build_verification_handlers(),
        routes=build_verification_routes(),
        worker_id=worker_id or f"local-{os.getpid()}",
    )
    created = ensure_build_verification_run(
        store,
        runtime=runtime,
        run_id=effective_run_id,
        run_dir=run_dir,
        config=config,
    )
    manifest = read_json(Path(staged_evidence["path"]))
    project = manifest.get("project")
    source_repository = (
        project.get("source_full_name") if isinstance(project, dict) else None
    )
    if created:
        runtime.publish_external(
            run_id=effective_run_id,
            event_type=BUILD_VERIFICATION_EVENT,
            payload={"inputs": inputs},
            source_repository=source_repository,
            dedupe_key=f"build-verification:{staged_evidence['sha256']}",
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
    summary_path = run_dir / "build-verification-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def snapshot_evidence_bundle(evidence_path: Path, *, run_dir: Path) -> dict[str, Any]:
    source_manifest = evidence_path.expanduser()
    source_root = source_manifest.parent.resolve()
    source_manifest_snapshot = snapshot_regular_file(
        source_manifest,
        target_dir=run_dir / "inputs" / "source",
        label="source-evidence.json",
    )
    manifest = read_json(Path(source_manifest_snapshot["path"]))
    roles = manifest.get("evidence")
    if not isinstance(roles, dict):
        raise EvidenceLaneError("Build evidence manifest roles are invalid")
    staged = copy.deepcopy(manifest)
    staged_roles = staged["evidence"]
    entry_count = 0
    for role, entries in roles.items():
        if not isinstance(role, str) or not isinstance(entries, list):
            raise EvidenceLaneError("Build evidence manifest roles are invalid")
        staged_entries = []
        for position, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict):
                raise EvidenceLaneError("Build evidence entry is invalid")
            entry_count += 1
            if entry_count > 10_000:
                raise EvidenceLaneError("Build evidence has too many entries")
            source = resolve_evidence_entry(
                entry,
                base_dir=source_root,
                label=f"{role} evidence",
            )
            snapshot = snapshot_regular_file(
                source,
                target_dir=run_dir / "inputs" / "evidence" / role,
                label=f"{position}-{source.name}",
            )
            if snapshot["sha256"] != entry.get("sha256"):
                raise EvidenceLaneError("Build evidence digest changed during snapshot")
            staged_entry = dict(entry)
            staged_entry["original_path"] = entry.get("path")
            staged_entry.update(snapshot)
            staged_entries.append(staged_entry)
        staged_roles[role] = staged_entries
    staged_manifest = run_dir / "inputs" / "evidence.json"
    write_json_atomic(staged_manifest, staged)
    return artifact_reference(staged_manifest)


def ensure_build_verification_run(
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
            metadata={"workflow": BUILD_VERIFICATION_WORKFLOW, "config": config},
        )
        return True
    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != BUILD_VERIFICATION_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False
