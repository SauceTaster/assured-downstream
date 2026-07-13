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
from assured_downstream.build_verification_v3 import (
    BuildVerificationError,
    decode_json_object,
    resolve_v3_storage_path,
    validate_v3_evidence_manifest,
    verify_build_attestations,
)
from assured_downstream.evidence_agents import (
    EvidenceLaneError,
    artifact_reference,
    snapshot_regular_file,
    verified_artifact_path,
    write_json_atomic,
)
from assured_downstream.release_verification import MAX_JSON_BYTES, snapshot_bytes


BUILD_VERIFICATION_V3_WORKFLOW = "retained-build-verification-v3"
BUILD_VERIFICATION_V3_EVENT = "BuildVerificationV3Requested"
BUILD_VERIFICATION_V3_VERIFIED_EVENT = "BuildAttestationsV3Verified"
BUILD_VERIFICATION_V3_REJECTED_EVENT = "BuildAttestationsV3Rejected"


class BuilderVerificationV3Handler:
    agent_id = "builder-verifier-v3"

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != BUILD_VERIFICATION_V3_EVENT:
            raise ValueError(
                "Builder Verifier v3 Agent requires BuildVerificationV3Requested"
            )
        if context.event.producer_agent_id is not None:
            raise ValueError("BuildVerificationV3Requested must be an external event")
        inputs = context.event.payload.get("inputs")
        if not isinstance(inputs, dict):
            raise ValueError("Builder verification v3 event has no input references")
        output_path = context.run_dir / "build-attestation-verification-v3.json"
        try:
            evidence_path = verified_artifact_path(
                inputs.get("evidence"),
                label="build evidence manifest",
            )
            policy_path = verified_artifact_path(
                inputs.get("policy"),
                label="build verification v3 policy",
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
                    "Builder verifier v3 returned a non-authoritative result"
                )
        except (
            BuildVerificationError,
            EvidenceLaneError,
            FileNotFoundError,
            KeyError,
            OSError,
            TypeError,
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
                summary="Builder attestation verification v3 was rejected.",
                events=[
                    EventOutput(
                        event_type=BUILD_VERIFICATION_V3_REJECTED_EVENT,
                        payload=payload,
                        source_repository=context.event.source_repository,
                        dedupe_key=content_digest(payload),
                    )
                ],
                artifacts=[
                    ArtifactOutput(
                        role="build-attestation-v3-rejection",
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
                "Verified retained v3 build attestations as an evidence candidate; "
                "no release assurance was granted."
            ),
            events=[
                EventOutput(
                    event_type=BUILD_VERIFICATION_V3_VERIFIED_EVENT,
                    payload=payload,
                    source_repository=context.event.source_repository,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[
                ArtifactOutput(
                    role="build-attestation-v3-verification",
                    path=output_path,
                )
            ],
        )


def build_verification_v3_handlers() -> list[AgentHandler]:
    return [BuilderVerificationV3Handler()]


def build_verification_v3_routes() -> dict[str, list[str]]:
    return {
        BUILD_VERIFICATION_V3_EVENT: ["builder-verifier-v3"],
        BUILD_VERIFICATION_V3_VERIFIED_EVENT: [],
        BUILD_VERIFICATION_V3_REJECTED_EVENT: [],
    }


def run_build_verification_v3_agent_system(
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
    staged_evidence = snapshot_evidence_bundle_v3(evidence_path, run_dir=run_dir)
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
        "evidence": staged_evidence,
        "policy": policy,
        "trust_policy": trust_policy,
    }
    config = {"inputs": inputs}
    effective_run_id = run_id or f"build-verify-v3-{uuid.uuid4().hex[:12]}"
    database_path = (
        (database_path or run_dir / "agent-control-plane.sqlite3")
        .expanduser()
        .resolve()
    )
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=build_verification_v3_handlers(),
        routes=build_verification_v3_routes(),
        worker_id=worker_id or f"local-{os.getpid()}",
    )
    created = ensure_build_verification_v3_run(
        store,
        runtime=runtime,
        run_id=effective_run_id,
        run_dir=run_dir,
        config=config,
    )
    manifest_path = Path(staged_evidence["path"])
    manifest_bytes, manifest_sha256 = snapshot_bytes(
        manifest_path,
        label="staged build evidence manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    if manifest_sha256 != staged_evidence["sha256"]:
        raise EvidenceLaneError("Staged evidence manifest changed before enqueue")
    manifest = decode_json_object(
        manifest_bytes,
        label="staged build evidence manifest",
    )
    project = manifest.get("project")
    source_repository = (
        project.get("source_full_name") if isinstance(project, dict) else None
    )
    if created:
        runtime.publish_external(
            run_id=effective_run_id,
            event_type=BUILD_VERIFICATION_V3_EVENT,
            payload={"inputs": inputs},
            source_repository=source_repository,
            dedupe_key=f"build-verification-v3:{staged_evidence['sha256']}",
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
    summary_path = run_dir / "build-verification-v3-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def snapshot_evidence_bundle_v3(
    evidence_path: Path,
    *,
    run_dir: Path,
    namespace: str | None = None,
) -> dict[str, Any]:
    if namespace is not None and (
        not namespace
        or len(namespace) > 64
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in namespace
        )
    ):
        raise EvidenceLaneError("Evidence snapshot namespace is invalid")
    input_root = run_dir / "inputs"
    if namespace is not None:
        input_root /= namespace
    source_manifest = evidence_path.expanduser()
    source_root = source_manifest.parent.resolve()
    source_manifest_snapshot = snapshot_regular_file(
        source_manifest,
        target_dir=input_root / "source",
        label="source-evidence-v3.json",
    )
    source_bytes, source_digest = snapshot_bytes(
        Path(source_manifest_snapshot["path"]),
        label="source evidence v3 manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    if source_digest != source_manifest_snapshot["sha256"]:
        raise EvidenceLaneError("Source evidence manifest changed during snapshot")
    manifest = decode_json_object(source_bytes, label="source evidence v3 manifest")
    roles = validate_v3_evidence_manifest(manifest, base_dir=source_root)
    staged = copy.deepcopy(manifest)
    staged_roles = staged["evidence"]
    for role in sorted(roles):
        staged_entries = []
        for position, entry in enumerate(roles[role], start=1):
            source = resolve_v3_storage_path(entry["path"], base_dir=source_root)
            snapshot = snapshot_regular_file(
                source,
                target_dir=input_root / "files" / role,
                label=f"{position:05d}-{entry['name']}",
            )
            if (
                snapshot["sha256"] != entry["sha256"]
                or snapshot["size"] != entry["size"]
            ):
                raise EvidenceLaneError("Build evidence changed during v3 snapshot")
            staged_entry = dict(entry)
            staged_entry["path"] = (
                Path(snapshot["path"]).relative_to(input_root).as_posix()
            )
            staged_entries.append(staged_entry)
        staged_roles[role] = staged_entries
    staged_manifest = input_root / "evidence-v3.json"
    write_json_atomic(staged_manifest, staged)
    validate_v3_evidence_manifest(staged, base_dir=input_root)
    reference = artifact_reference(staged_manifest)
    reference["source_manifest_sha256"] = source_manifest_snapshot["sha256"]
    return reference


def ensure_build_verification_v3_run(
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
            metadata={
                "workflow": BUILD_VERIFICATION_V3_WORKFLOW,
                "config": config,
            },
        )
        return True
    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != BUILD_VERIFICATION_V3_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False
