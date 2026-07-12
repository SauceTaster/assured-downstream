from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
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
from assured_downstream.command_runner import CommandRunner
from assured_downstream.managed_checkout_agents import (
    artifact_reference,
    write_json_atomic,
)
from assured_downstream.publication_authorization import (
    PublicationAuthorizationError,
    decode_json_object,
    parse_timestamp,
    snapshot_file,
    validate_authorization_record,
    verify_publication_authorization,
)
from assured_downstream.publication_ledger import (
    PublicationLedger,
    PublicationLedgerError,
    trusted_publication_ledger_path,
)
from assured_downstream.secure_publish import SecurePublishError, publish_secure_branch


AUTHORIZED_PUBLICATION_WORKFLOW = "authorized-secure-branch-publication"


class PublicationAuthorizationHandler:
    agent_id = "publication-authorizer"

    def __init__(self, *, verifier_runner: CommandRunner | None = None) -> None:
        self.verifier_runner = verifier_runner

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != "PublicationAuthorizationRecorded":
            raise ValueError(
                "Publication Authorization Agent requires PublicationAuthorizationRecorded"
            )
        if context.event.producer_agent_id is not None:
            raise ValueError(
                "PublicationAuthorizationRecorded must be an external event"
            )
        config = require_publication_config(context.event.payload)
        result_path = context.run_dir / "publication-authorization-verification.json"
        try:
            record = verify_publication_authorization(
                request_path=Path(config["request_path"]),
                bundle_path=Path(config["bundle_path"]),
                policy_path=Path(config["publication_policy_path"]),
                runner=self.verifier_runner,
            )
            for field, config_field in (
                ("request_sha256", "request_path_sha256"),
                ("bundle_sha256", "bundle_path_sha256"),
                ("policy_sha256", "publication_policy_path_sha256"),
            ):
                if record[field] != config[config_field]:
                    raise PublicationAuthorizationError(
                        f"Verified authorization does not match configured {field}"
                    )
        except PublicationAuthorizationError as exc:
            blocked = {
                "schema_version": 1,
                "status": "blocked",
                "reason": str(exc),
                "verified": False,
            }
            write_json_atomic(result_path, blocked)
            return AgentResult(
                status="blocked",
                summary="Publication authorization verification failed closed.",
                artifacts=[
                    ArtifactOutput(
                        role="publication-authorization-verification",
                        path=result_path,
                    )
                ],
                human_review=[str(exc)],
            )

        write_json_atomic(result_path, record)
        payload = {
            "config": config,
            "authorization": artifact_reference(result_path),
        }
        return AgentResult(
            status="succeeded",
            summary=(
                "Verified digest-bound publication authorization for "
                f"{record['target_full_name']}."
            ),
            events=[
                EventOutput(
                    event_type="SecureBranchPublicationAuthorized",
                    payload=payload,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[
                ArtifactOutput(
                    role="publication-authorization-verification",
                    path=result_path,
                )
            ],
        )


class SecureBranchPublisherHandler:
    agent_id = "secure-branch-publisher"

    def __init__(self, *, allow_local_remotes: bool = False) -> None:
        self.allow_local_remotes = allow_local_remotes

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != "SecureBranchPublicationAuthorized":
            raise ValueError(
                "Secure Branch Publisher requires SecureBranchPublicationAuthorized"
            )
        if context.event.producer_agent_id != "publication-authorizer":
            raise ValueError(
                "SecureBranchPublicationAuthorized must be produced by the "
                "Publication Authorization Agent"
            )
        config = require_publication_config(context.event.payload)
        result_path = context.run_dir / "secure-branch-publication.json"
        reserved = False
        request_id: str | None = None
        ledger: PublicationLedger | None = None
        try:
            request_bytes = verified_snapshot(
                Path(config["request_path"]),
                config["request_path_sha256"],
                label="publication request",
            )
            policy_bytes = verified_snapshot(
                Path(config["publication_policy_path"]),
                config["publication_policy_path_sha256"],
                label="publication authorization policy",
            )
            verified_snapshot(
                Path(config["bundle_path"]),
                config["bundle_path_sha256"],
                label="publication authorization bundle",
            )
            authorization_ref = context.event.payload.get("authorization")
            authorization_path, authorization_sha256 = verified_artifact_reference(
                authorization_ref,
                label="publication authorization verification",
            )
            authorization_bytes = verified_snapshot(
                authorization_path,
                authorization_sha256,
                label="publication authorization verification",
            )
            request = decode_json_object(
                request_bytes,
                label="publication request",
            )
            policy = decode_json_object(
                policy_bytes,
                label="publication authorization policy",
            )
            authorization = decode_json_object(
                authorization_bytes,
                label="publication authorization verification",
            )
            scope = validate_authorization_record(
                authorization,
                request=request,
                request_sha256=config["request_path_sha256"],
                bundle_sha256=config["bundle_path_sha256"],
                policy=policy,
                policy_sha256=config["publication_policy_path_sha256"],
            )
            checkout_path = guarded_checkout_path(
                config["checkout_path"],
                workspace=Path(config["workspace"]),
            )
            ensure_unexpired_work_lease(context)
            request_id = request["request_id"]
            if config["execute"]:
                ledger = PublicationLedger(Path(config["authorization_ledger_path"]))
                ledger.reserve(
                    request_id=request_id,
                    request_sha256=config["request_path_sha256"],
                    run_id=context.run_id,
                    work_id=context.work.work_id,
                    target_full_name=scope["target_full_name"],
                    secure_branch=scope["secure_branch"],
                    patch_sha=scope["patch_sha"],
                    expected_remote_sha=scope["expected_remote_sha"],
                )
                reserved = True
            publication = publish_secure_branch(
                checkout_path=checkout_path,
                target_full_name=scope["target_full_name"],
                secure_branch=scope["secure_branch"],
                patch_sha=scope["patch_sha"],
                patch_base_sha=scope["patch_base_sha"],
                required_upstream_sha=scope["required_upstream_sha"],
                authorization_expires_at=request["expires_at"],
                lease_expires_at=str(context.work.lease_expires_at),
                expected_remote_sha=scope["expected_remote_sha"],
                execute=config["execute"],
                allow_local_remotes=self.allow_local_remotes,
            )
            if reserved and ledger is not None:
                ledger.mark_published(
                    request_id=request_id,
                    run_id=context.run_id,
                    work_id=context.work.work_id,
                    result_status=publication["status"],
                )
        except (
            PublicationAuthorizationError,
            PublicationLedgerError,
            SecurePublishError,
            ValueError,
        ) as exc:
            if reserved:
                raise RuntimeError(
                    "Reserved publication attempt requires exact-state retry: "
                    f"{exc}"
                ) from exc
            blocked = {
                "schema_version": 1,
                "status": "blocked",
                "reason": str(exc),
                "executed": False,
            }
            write_json_atomic(result_path, blocked)
            return AgentResult(
                status="blocked",
                summary="Secure branch publication was blocked.",
                artifacts=[
                    ArtifactOutput(
                        role="secure-branch-publication",
                        path=result_path,
                    )
                ],
                human_review=[str(exc)],
            )

        write_json_atomic(result_path, publication)
        event_type = (
            "SecureBranchPublished"
            if publication["status"] in {"published", "already-published"}
            else "SecureBranchPublicationPlanned"
        )
        payload = {"publication": artifact_reference(result_path)}
        return AgentResult(
            status="succeeded",
            summary=(
                f"Secure branch publication status: {publication['status']} for "
                f"{publication['target_full_name']}."
            ),
            events=[
                EventOutput(
                    event_type=event_type,
                    payload=payload,
                    source_repository=request["scope"]["source_full_name"],
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[
                ArtifactOutput(role="secure-branch-publication", path=result_path)
            ],
        )


def authorized_publication_handlers(
    *,
    allow_local_test_remotes: bool = False,
    verifier_runner: CommandRunner | None = None,
) -> list[AgentHandler]:
    return [
        PublicationAuthorizationHandler(verifier_runner=verifier_runner),
        SecureBranchPublisherHandler(
            allow_local_remotes=allow_local_test_remotes,
        ),
    ]


def run_authorized_publication_agent_system(
    *,
    request_path: Path,
    bundle_path: Path,
    publication_policy_path: Path,
    checkout_path: Path,
    workspace: Path,
    run_dir: Path,
    execute: bool = False,
    database_path: Path | None = None,
    run_id: str | None = None,
    worker_id: str | None = None,
    max_items: int = 100,
    enqueue_only: bool = False,
    allow_local_test_remotes: bool = False,
    verifier_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    run_dir = run_dir.expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    checkout_path = checkout_path.expanduser().resolve()
    workspace = workspace.expanduser().resolve()
    authorization_ledger_path = trusted_publication_ledger_path()
    request_snapshot, request_sha256 = persist_input_snapshot(
        request_path,
        run_dir=run_dir,
        name="publication-request.json",
        label="publication request",
    )
    bundle_snapshot, bundle_sha256 = persist_input_snapshot(
        bundle_path,
        run_dir=run_dir,
        name="publication-authorization.sigstore.json",
        label="publication authorization bundle",
    )
    policy_snapshot, policy_sha256 = persist_input_snapshot(
        publication_policy_path,
        run_dir=run_dir,
        name="publication-authorization-policy.json",
        label="publication authorization policy",
    )
    guarded_checkout_path(str(checkout_path), workspace=workspace)
    effective_run_id = run_id or f"publication-{uuid.uuid4().hex[:12]}"
    database_path = (
        database_path or run_dir / "agent-control-plane.sqlite3"
    ).expanduser().resolve()
    config = {
        "request_path": str(request_snapshot),
        "request_path_sha256": request_sha256,
        "bundle_path": str(bundle_snapshot),
        "bundle_path_sha256": bundle_sha256,
        "publication_policy_path": str(policy_snapshot),
        "publication_policy_path_sha256": policy_sha256,
        "checkout_path": str(checkout_path),
        "workspace": str(workspace),
        "authorization_ledger_path": str(authorization_ledger_path),
        "execute": execute,
    }
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=authorized_publication_handlers(
            allow_local_test_remotes=allow_local_test_remotes,
            verifier_runner=verifier_runner,
        ),
        worker_id=worker_id or f"local-{os.getpid()}",
    )
    created = ensure_publication_run(
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
            event_type="PublicationAuthorizationRecorded",
            payload={"config": config},
            dedupe_key=f"authorization:{request_sha256}:{bundle_sha256}",
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
    result["authorization_ledger_path"] = str(authorization_ledger_path)
    summary_path = run_dir / "authorized-publication-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def ensure_publication_run(
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
                "workflow": AUTHORIZED_PUBLICATION_WORKFLOW,
                "database_path": str(database_path),
                "config": config,
            },
        )
        return True
    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != AUTHORIZED_PUBLICATION_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False


def require_publication_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = payload.get("config")
    if not isinstance(config, dict):
        raise ValueError("Publication event is missing config")
    for key in (
        "request_path",
        "bundle_path",
        "publication_policy_path",
        "checkout_path",
        "workspace",
        "authorization_ledger_path",
    ):
        if not isinstance(config.get(key), str) or not config[key]:
            raise ValueError(f"Publication config has invalid {key}")
    for key in (
        "request_path_sha256",
        "bundle_path_sha256",
        "publication_policy_path_sha256",
    ):
        require_sha256_string(config.get(key), label=key)
    if not isinstance(config.get("execute"), bool):
        raise ValueError("Publication config has invalid execute")
    return config


def persist_input_snapshot(
    source: Path,
    *,
    run_dir: Path,
    name: str,
    label: str,
) -> tuple[Path, str]:
    source = source.expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    value, digest = snapshot_file(source, label=label)
    target = run_dir / "inputs" / f"{digest}-{name}"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        existing, existing_digest = snapshot_file(target, label=f"persisted {label}")
        if existing_digest != digest or existing != value:
            raise ValueError(f"Persisted {label} snapshot has changed")
        return target.resolve(), digest
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(value)
        temporary.chmod(0o400)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return target.resolve(), digest


def verified_snapshot(path: Path, digest: str, *, label: str) -> bytes:
    require_sha256_string(digest, label=f"{label} digest")
    value, actual = snapshot_file(path.resolve(), label=label)
    if actual != digest:
        raise PublicationAuthorizationError(f"{label.capitalize()} digest changed")
    return value


def verified_artifact_reference(value: Any, *, label: str) -> tuple[Path, str]:
    if not isinstance(value, dict):
        raise PublicationAuthorizationError(
            f"{label.capitalize()} artifact reference is invalid"
        )
    path = value.get("path")
    digest = value.get("sha256")
    if not isinstance(path, str):
        raise PublicationAuthorizationError(
            f"{label.capitalize()} artifact path is invalid"
        )
    require_sha256_string(digest, label=f"{label} artifact digest")
    return Path(path).resolve(), digest


def require_sha256_string(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PublicationAuthorizationError(f"{label.capitalize()} is invalid")
    return value


def guarded_checkout_path(value: Any, *, workspace: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise PublicationAuthorizationError("Publication checkout path is invalid")
    workspace = workspace.expanduser().resolve()
    path = Path(value).expanduser().resolve()
    if path == workspace or not path.is_relative_to(workspace):
        raise PublicationAuthorizationError(
            "Publication checkout path escapes the configured workspace"
        )
    if not path.is_dir():
        raise PublicationAuthorizationError(
            f"Publication checkout is missing: {path}"
        )
    return path


def ensure_unexpired_work_lease(context: AgentContext) -> None:
    attempt_id = context.work.current_attempt_id
    expires_at = context.work.lease_expires_at
    if not attempt_id or not expires_at:
        raise PublicationAuthorizationError(
            "Publisher does not hold a fenced work attempt"
        )
    expiry = parse_timestamp(expires_at, label="publisher work lease expiry")
    if expiry <= datetime.now(UTC):
        raise PublicationAuthorizationError(
            "Publisher work lease expired before remote mutation"
        )
