from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from assured_downstream.agent_contracts import content_digest
from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.secure_patch import (
    SecurePatchError,
    require_full_sha,
    require_sha256,
)
from assured_downstream.sync_plan import validate_default_branch


PUBLICATION_REQUEST_SCHEMA_VERSION = 1
PUBLICATION_POLICY_SCHEMA_VERSION = 1
PUBLICATION_AUTHORIZATION_SCHEMA_VERSION = 1
PUBLICATION_AUTHORIZATION_PREDICATE_TYPE = (
    "https://assured-downstream.dev/attestation/secure-branch-publication/v1"
)
PUBLICATION_REQUEST_TYPE = "secure-branch-publication"
MAX_REQUEST_LIFETIME = timedelta(days=7)
GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
TRUSTED_PUBLICATION_POLICY_SHA256 = (
    "ae7e53343e32546d9e9d563fa26c023f62f8ec25c321bd2bf9ca4e100b0bc1c8"
)


class PublicationAuthorizationError(RuntimeError):
    pass


def create_publication_request(
    *,
    source_full_name: str,
    target_full_name: str,
    secure_branch: str,
    patch_sha: str,
    patch_base_sha: str,
    required_upstream_sha: str,
    expected_remote_sha: str | None,
    approved_change_ids: list[str],
    approved_at: str,
    approval_expires_at: str,
    analysis_index_sha256: str,
    pin_lock_sha256: str,
    tooling_policy_sha256: str,
    patch_approval_sha256: str,
    publication_policy: dict[str, Any],
    publication_policy_sha256: str,
    patch_result_sha256: str,
) -> dict[str, Any]:
    policy = validate_publication_policy(publication_policy, require_active=True)
    require_digest(publication_policy_sha256, label="publication policy digest")
    issued_at = parse_timestamp(approved_at, label="publication request issued_at")
    approval_expiry = parse_timestamp(
        approval_expires_at,
        label="publication request approval expiry",
    )
    policy_expiry = issued_at + timedelta(
        seconds=policy["scope"]["max_request_lifetime_seconds"]
    )
    expires_at = min(approval_expiry, policy_expiry)
    if expires_at <= issued_at:
        raise PublicationAuthorizationError(
            "Publication request expires before it is issued"
        )

    scope = {
        "source_full_name": require_repository_name(
            source_full_name,
            label="source repository",
        ),
        "target_full_name": require_repository_name(
            target_full_name,
            label="target repository",
        ),
        "secure_branch": require_secure_branch(secure_branch),
        "patch_sha": require_git_sha(patch_sha, label="secure patch commit"),
        "patch_base_sha": require_git_sha(
            patch_base_sha,
            label="secure patch base commit",
        ),
        "required_upstream_sha": require_git_sha(
            required_upstream_sha,
            label="required upstream commit",
        ),
        "expected_remote_sha": (
            None
            if expected_remote_sha is None
            else require_git_sha(
                expected_remote_sha,
                label="expected remote secure commit",
            )
        ),
    }
    validate_policy_scope(scope, policy)
    if (
        not isinstance(approved_change_ids, list)
        or not approved_change_ids
        or not all(isinstance(item, str) and item for item in approved_change_ids)
        or len(set(approved_change_ids)) != len(approved_change_ids)
    ):
        raise PublicationAuthorizationError(
            "Publication request has no valid approved change set"
        )
    evidence = {
        "analysis_index_sha256": require_digest(
            analysis_index_sha256,
            label="analysis index digest",
        ),
        "pin_lock_sha256": require_digest(
            pin_lock_sha256,
            label="pin lock digest",
        ),
        "tooling_policy_sha256": require_digest(
            tooling_policy_sha256,
            label="tooling policy digest",
        ),
        "patch_approval_sha256": require_digest(
            patch_approval_sha256,
            label="patch approval digest",
        ),
        "publication_policy_sha256": publication_policy_sha256,
        "patch_result_sha256": require_digest(
            patch_result_sha256,
            label="patch result digest",
        ),
        "approved_change_ids": sorted(approved_change_ids),
    }
    body = {
        "schema_version": PUBLICATION_REQUEST_SCHEMA_VERSION,
        "request_type": PUBLICATION_REQUEST_TYPE,
        "issued_at": format_timestamp(issued_at),
        "expires_at": format_timestamp(expires_at),
        "scope": scope,
        "evidence": evidence,
    }
    return {
        **body,
        "request_id": f"sha256:{content_digest(body)}",
    }


def validate_publication_request(
    request: dict[str, Any],
    *,
    policy: dict[str, Any],
    policy_sha256: str,
    request_sha256: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    effective_policy = validate_publication_policy(policy, require_active=True)
    require_exact_keys(
        request,
        {
            "schema_version",
            "request_type",
            "request_id",
            "issued_at",
            "expires_at",
            "scope",
            "evidence",
        },
        label="publication request",
    )
    if request.get("schema_version") != PUBLICATION_REQUEST_SCHEMA_VERSION:
        raise PublicationAuthorizationError(
            "Unsupported publication request schema"
        )
    if request.get("request_type") != PUBLICATION_REQUEST_TYPE:
        raise PublicationAuthorizationError("Unsupported publication request type")
    require_digest(policy_sha256, label="publication policy digest")
    require_digest(request_sha256, label="publication request digest")

    body = {key: value for key, value in request.items() if key != "request_id"}
    expected_request_id = f"sha256:{content_digest(body)}"
    if not hmac.compare_digest(str(request.get("request_id")), expected_request_id):
        raise PublicationAuthorizationError(
            "Publication request id does not match its canonical content"
        )

    issued_at = parse_timestamp(
        request.get("issued_at"),
        label="publication request issued_at",
    )
    expires_at = parse_timestamp(
        request.get("expires_at"),
        label="publication request expires_at",
    )
    current = (now or datetime.now(UTC)).astimezone(UTC)
    maximum_lifetime = timedelta(
        seconds=effective_policy["scope"]["max_request_lifetime_seconds"]
    )
    if issued_at > current:
        raise PublicationAuthorizationError("Publication request is future-dated")
    if expires_at <= issued_at:
        raise PublicationAuthorizationError(
            "Publication request expires before it is issued"
        )
    if expires_at - issued_at > maximum_lifetime:
        raise PublicationAuthorizationError(
            "Publication request lifetime exceeds authorization policy"
        )
    if expires_at <= current:
        raise PublicationAuthorizationError("Publication request has expired")

    scope = request.get("scope")
    if not isinstance(scope, dict):
        raise PublicationAuthorizationError("Publication request scope is invalid")
    require_exact_keys(
        scope,
        {
            "source_full_name",
            "target_full_name",
            "secure_branch",
            "patch_sha",
            "patch_base_sha",
            "required_upstream_sha",
            "expected_remote_sha",
        },
        label="publication request scope",
    )
    require_repository_name(scope.get("source_full_name"), label="source repository")
    require_repository_name(scope.get("target_full_name"), label="target repository")
    require_secure_branch(scope.get("secure_branch"))
    for field, label in (
        ("patch_sha", "secure patch commit"),
        ("patch_base_sha", "secure patch base commit"),
        ("required_upstream_sha", "required upstream commit"),
    ):
        require_git_sha(scope.get(field), label=label)
    expected_remote = scope.get("expected_remote_sha")
    if expected_remote is not None:
        require_git_sha(expected_remote, label="expected remote secure commit")
    validate_policy_scope(scope, effective_policy)

    evidence = request.get("evidence")
    if not isinstance(evidence, dict):
        raise PublicationAuthorizationError("Publication request evidence is invalid")
    require_exact_keys(
        evidence,
        {
            "analysis_index_sha256",
            "pin_lock_sha256",
            "tooling_policy_sha256",
            "patch_approval_sha256",
            "publication_policy_sha256",
            "patch_result_sha256",
            "approved_change_ids",
        },
        label="publication request evidence",
    )
    for field in (
        "analysis_index_sha256",
        "pin_lock_sha256",
        "tooling_policy_sha256",
        "patch_approval_sha256",
        "publication_policy_sha256",
        "patch_result_sha256",
    ):
        require_digest(evidence.get(field), label=field.replace("_", " "))
    if not hmac.compare_digest(
        str(evidence.get("publication_policy_sha256")),
        policy_sha256,
    ):
        raise PublicationAuthorizationError(
            "Publication request does not bind this authorization policy"
        )
    approved_change_ids = evidence.get("approved_change_ids")
    if (
        not isinstance(approved_change_ids, list)
        or not approved_change_ids
        or approved_change_ids != sorted(approved_change_ids)
        or not all(isinstance(item, str) and item for item in approved_change_ids)
        or len(set(approved_change_ids)) != len(approved_change_ids)
    ):
        raise PublicationAuthorizationError(
            "Publication request approved change set is invalid"
        )
    return scope


def verify_publication_authorization(
    *,
    request_path: Path,
    bundle_path: Path,
    policy_path: Path,
    runner: CommandRunner | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    request_path = request_path.resolve()
    bundle_path = bundle_path.resolve()
    policy_path = policy_path.resolve()
    for path, label in (
        (request_path, "publication request"),
        (bundle_path, "publication authorization bundle"),
        (policy_path, "publication authorization policy"),
    ):
        if not path.is_file():
            raise PublicationAuthorizationError(f"Missing {label}: {path}")

    request_bytes, request_sha256 = snapshot_file(
        request_path,
        label="publication request",
    )
    bundle_bytes, bundle_sha256 = snapshot_file(
        bundle_path,
        label="publication authorization bundle",
    )
    policy_bytes, policy_sha256 = snapshot_file(
        policy_path,
        label="publication authorization policy",
    )
    require_trusted_publication_policy_digest(policy_sha256)
    request = decode_json_object(request_bytes, label="publication request")
    policy = decode_json_object(
        policy_bytes,
        label="publication authorization policy",
    )
    scope = validate_publication_request(
        request,
        policy=policy,
        policy_sha256=policy_sha256,
        request_sha256=request_sha256,
        now=now,
    )
    effective_policy = validate_publication_policy(policy, require_active=True)
    verifier = effective_policy["verifier"]
    executable = Path(verifier["executable"])
    if not executable.is_absolute() or not executable.is_file():
        raise PublicationAuthorizationError(
            "Publication verifier executable must be an existing absolute file"
        )
    executable_bytes, executable_sha256 = snapshot_file(
        executable,
        label="publication verifier executable",
    )
    if executable_sha256 != verifier["sha256"]:
        raise PublicationAuthorizationError(
            "Publication verifier executable digest does not match policy"
        )

    effective_runner = runner or CommandRunner(execute=True)
    with tempfile.TemporaryDirectory(prefix="assured-publication-verify-") as tmp:
        isolation_root = Path(tmp)
        home = isolation_root / "home"
        gh_config = isolation_root / "gh-config"
        staged_request = isolation_root / "publication-request.json"
        staged_bundle = isolation_root / "publication-authorization.sigstore.json"
        staged_executable = isolation_root / "gh"
        home.mkdir(mode=0o700)
        gh_config.mkdir(mode=0o700)
        staged_request.write_bytes(request_bytes)
        staged_bundle.write_bytes(bundle_bytes)
        staged_executable.write_bytes(executable_bytes)
        staged_request.chmod(0o400)
        staged_bundle.chmod(0o400)
        staged_executable.chmod(0o500)
        command = github_attestation_verify_command(
            request_path=staged_request,
            bundle_path=staged_bundle,
            policy=effective_policy,
            executable_path=staged_executable,
        )
        result = effective_runner.run(
            command,
            cwd=str(isolation_root),
            env={
                "HOME": str(home),
                "GH_CONFIG_DIR": str(gh_config),
                "GH_NO_UPDATE_NOTIFIER": "1",
                "GH_PROMPT_DISABLED": "1",
                "GIT_CONFIG_COUNT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_PARAMETERS": "",
                "GIT_TERMINAL_PROMPT": "0",
                "PATH": "/usr/bin:/bin",
            },
        )
    if not result.executed:
        raise PublicationAuthorizationError(
            "Publication attestation verifier did not execute"
        )
    if not result.ok:
        detail = (result.stderr or result.stdout).strip() or "verification failed"
        if len(detail) > 2048:
            detail = detail[:2048] + "...<truncated>"
        raise PublicationAuthorizationError(
            f"Publication attestation verification failed: {detail}"
        )
    try:
        verification_entries = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PublicationAuthorizationError(
            "Publication attestation verifier returned invalid JSON"
        ) from exc
    timestamp_count = validate_verification_output(
        verification_entries,
        request=request,
        request_sha256=request_sha256,
        policy=effective_policy,
    )
    current = (now or datetime.now(UTC)).astimezone(UTC)
    return {
        "schema_version": PUBLICATION_AUTHORIZATION_SCHEMA_VERSION,
        "status": "verified",
        "request_id": request["request_id"],
        "request_sha256": request_sha256,
        "bundle_sha256": bundle_sha256,
        "policy_sha256": policy_sha256,
        "target_full_name": scope["target_full_name"],
        "secure_branch": scope["secure_branch"],
        "patch_sha": scope["patch_sha"],
        "predicate_type": effective_policy["predicate_type"],
        "control_repository": effective_policy["control_repository"],
        "signer_workflow": effective_policy["signer"]["workflow"],
        "signer_digest": effective_policy["signer"]["workflow_digest"],
        "verified_at": format_timestamp(current),
        "expires_at": request["expires_at"],
        "verified_timestamp_count": timestamp_count,
        "command": display_command(command),
    }


def validate_authorization_record(
    record: dict[str, Any],
    *,
    request: dict[str, Any],
    request_sha256: str,
    bundle_sha256: str,
    policy: dict[str, Any],
    policy_sha256: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    require_trusted_publication_policy_digest(policy_sha256)
    scope = validate_publication_request(
        request,
        policy=policy,
        policy_sha256=policy_sha256,
        request_sha256=request_sha256,
        now=now,
    )
    effective_policy = validate_publication_policy(policy, require_active=True)
    expected = {
        "schema_version": PUBLICATION_AUTHORIZATION_SCHEMA_VERSION,
        "status": "verified",
        "request_id": request["request_id"],
        "request_sha256": request_sha256,
        "bundle_sha256": bundle_sha256,
        "policy_sha256": policy_sha256,
        "target_full_name": scope["target_full_name"],
        "secure_branch": scope["secure_branch"],
        "patch_sha": scope["patch_sha"],
        "predicate_type": effective_policy["predicate_type"],
        "control_repository": effective_policy["control_repository"],
        "signer_workflow": effective_policy["signer"]["workflow"],
        "signer_digest": effective_policy["signer"]["workflow_digest"],
        "expires_at": request["expires_at"],
    }
    for field, value in expected.items():
        if record.get(field) != value:
            raise PublicationAuthorizationError(
                f"Publication authorization record does not match {field}"
            )
    parse_timestamp(record.get("verified_at"), label="authorization verified_at")
    timestamp_count = record.get("verified_timestamp_count")
    if not isinstance(timestamp_count, int) or timestamp_count < 1:
        raise PublicationAuthorizationError(
            "Publication authorization has no verified transparency timestamp"
        )
    return scope


def github_attestation_verify_command(
    *,
    request_path: Path,
    bundle_path: Path,
    policy: dict[str, Any],
    executable_path: Path | None = None,
) -> list[str]:
    signer = policy["signer"]
    command = [
        str(executable_path or policy["verifier"]["executable"]),
        "attestation",
        "verify",
        str(request_path),
        "--bundle",
        str(bundle_path),
        "--repo",
        policy["control_repository"],
        "--predicate-type",
        policy["predicate_type"],
        "--signer-digest",
        signer["workflow_digest"],
        "--source-digest",
        signer["source_digest"],
        "--source-ref",
        signer["source_ref"],
        "--cert-identity",
        signer["certificate_identity"],
        "--cert-oidc-issuer",
        signer["oidc_issuer"],
        "--format",
        "json",
    ]
    if signer["deny_self_hosted_runners"]:
        command.append("--deny-self-hosted-runners")
    return command


def validate_verification_output(
    entries: Any,
    *,
    request: dict[str, Any],
    request_sha256: str,
    policy: dict[str, Any],
) -> int:
    if not isinstance(entries, list) or not entries:
        raise PublicationAuthorizationError(
            "Publication verifier returned no verified attestations"
        )
    expected_predicate = {
        "schemaVersion": 1,
        "decision": "authorized",
        "requestId": request["request_id"],
        "requestSha256": request_sha256,
        "targetFullName": request["scope"]["target_full_name"],
        "secureBranch": request["scope"]["secure_branch"],
        "patchSha": request["scope"]["patch_sha"],
        "environment": policy["environment"],
    }
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        verification = entry.get("verificationResult")
        if not isinstance(verification, dict):
            continue
        statement = verification.get("statement")
        timestamps = verification.get("verifiedTimestamps")
        if not isinstance(statement, dict) or not isinstance(timestamps, list):
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or len(subjects) != 1:
            continue
        subject = subjects[0]
        if not isinstance(subject, dict):
            continue
        digest = subject.get("digest")
        if not isinstance(digest, dict):
            continue
        if (
            statement.get("predicateType") == policy["predicate_type"]
            and hmac.compare_digest(str(digest.get("sha256")), request_sha256)
            and statement.get("predicate") == expected_predicate
            and timestamps
        ):
            return len(timestamps)
    raise PublicationAuthorizationError(
        "Verified attestation does not authorize this exact publication request"
    )


def validate_publication_policy(
    policy: dict[str, Any],
    *,
    require_active: bool,
) -> dict[str, Any]:
    require_exact_keys(
        policy,
        {
            "schema_version",
            "status",
            "predicate_type",
            "control_repository",
            "environment",
            "signer",
            "verifier",
            "scope",
        },
        label="publication authorization policy",
    )
    if policy.get("schema_version") != PUBLICATION_POLICY_SCHEMA_VERSION:
        raise PublicationAuthorizationError(
            "Unsupported publication authorization policy schema"
        )
    if policy.get("status") not in {"active", "disabled"}:
        raise PublicationAuthorizationError(
            "Publication authorization policy status is invalid"
        )
    if require_active and policy.get("status") != "active":
        raise PublicationAuthorizationError(
            "Publication authorization policy is not active"
        )
    if policy.get("predicate_type") != PUBLICATION_AUTHORIZATION_PREDICATE_TYPE:
        raise PublicationAuthorizationError(
            "Publication authorization predicate type is not approved"
        )
    control_repository = require_repository_name(
        policy.get("control_repository"),
        label="control repository",
    )
    environment = policy.get("environment")
    if not isinstance(environment, str) or not environment:
        raise PublicationAuthorizationError(
            "Publication authorization environment is invalid"
        )

    signer = policy.get("signer")
    if not isinstance(signer, dict):
        raise PublicationAuthorizationError("Publication signer policy is invalid")
    require_exact_keys(
        signer,
        {
            "workflow",
            "workflow_digest",
            "source_digest",
            "source_ref",
            "certificate_identity",
            "oidc_issuer",
            "deny_self_hosted_runners",
        },
        label="publication signer policy",
    )
    workflow = signer.get("workflow")
    workflow_prefix = f"{control_repository}/.github/workflows/"
    if (
        not isinstance(workflow, str)
        or not workflow.startswith(workflow_prefix)
        or not workflow.endswith((".yml", ".yaml"))
        or ".." in workflow
    ):
        raise PublicationAuthorizationError(
            "Publication signer workflow is outside the control repository"
        )
    require_git_sha(signer.get("workflow_digest"), label="signer workflow digest")
    require_git_sha(signer.get("source_digest"), label="signer source digest")
    source_ref = signer.get("source_ref")
    if (
        not isinstance(source_ref, str)
        or not source_ref.startswith("refs/heads/")
        or source_ref.endswith("/")
        or ".." in source_ref
    ):
        raise PublicationAuthorizationError("Publication signer source ref is invalid")
    expected_identity = f"https://github.com/{workflow}@{source_ref}"
    if signer.get("certificate_identity") != expected_identity:
        raise PublicationAuthorizationError(
            "Publication signer certificate identity is not exact"
        )
    if signer.get("oidc_issuer") != GITHUB_ACTIONS_OIDC_ISSUER:
        raise PublicationAuthorizationError(
            "Publication signer OIDC issuer is not approved"
        )
    if signer.get("deny_self_hosted_runners") is not True:
        raise PublicationAuthorizationError(
            "Publication signer must reject self-hosted runners"
        )

    verifier = policy.get("verifier")
    if not isinstance(verifier, dict):
        raise PublicationAuthorizationError("Publication verifier policy is invalid")
    require_exact_keys(
        verifier,
        {"executable", "sha256"},
        label="publication verifier policy",
    )
    executable = verifier.get("executable")
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        raise PublicationAuthorizationError(
            "Publication verifier executable path must be absolute"
        )
    require_digest(verifier.get("sha256"), label="publication verifier digest")

    scope = policy.get("scope")
    if not isinstance(scope, dict):
        raise PublicationAuthorizationError("Publication policy scope is invalid")
    require_exact_keys(
        scope,
        {
            "target_owner",
            "repository_prefix",
            "branch_prefix",
            "max_request_lifetime_seconds",
        },
        label="publication policy scope",
    )
    target_owner = scope.get("target_owner")
    repository_prefix = scope.get("repository_prefix")
    branch_prefix = scope.get("branch_prefix")
    if not isinstance(target_owner, str) or not target_owner:
        raise PublicationAuthorizationError("Publication target owner is invalid")
    if not isinstance(repository_prefix, str) or not repository_prefix:
        raise PublicationAuthorizationError(
            "Publication repository prefix is invalid"
        )
    if branch_prefix != "secure/":
        raise PublicationAuthorizationError(
            "Publication policy must restrict branches to secure/"
        )
    lifetime = scope.get("max_request_lifetime_seconds")
    if (
        not isinstance(lifetime, int)
        or isinstance(lifetime, bool)
        or lifetime < 300
        or timedelta(seconds=lifetime) > MAX_REQUEST_LIFETIME
    ):
        raise PublicationAuthorizationError(
            "Publication request lifetime policy must be between five minutes and seven days"
        )
    return policy


def validate_policy_scope(scope: dict[str, Any], policy: dict[str, Any]) -> None:
    target = str(scope["target_full_name"])
    owner, repository = target.split("/", 1)
    policy_scope = policy["scope"]
    if owner != policy_scope["target_owner"]:
        raise PublicationAuthorizationError(
            "Publication target owner is outside authorization policy"
        )
    if not repository.startswith(policy_scope["repository_prefix"]):
        raise PublicationAuthorizationError(
            "Publication target repository is outside authorization policy"
        )
    if not str(scope["secure_branch"]).startswith(policy_scope["branch_prefix"]):
        raise PublicationAuthorizationError(
            "Publication branch is outside authorization policy"
        )


def require_repository_name(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or value.count("/") != 1:
        raise PublicationAuthorizationError(f"{label.capitalize()} is invalid")
    owner, repository = value.split("/", 1)
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if (
        not owner
        or not repository
        or any(character not in allowed for character in value.replace("/", ""))
        or owner in {".", ".."}
        or repository in {".", ".."}
    ):
        raise PublicationAuthorizationError(f"{label.capitalize()} is invalid")
    return value


def require_secure_branch(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("secure/"):
        raise PublicationAuthorizationError("Secure publication branch is invalid")
    try:
        validate_default_branch(value)
    except ValueError as exc:
        raise PublicationAuthorizationError(str(exc)) from exc
    return value


def require_git_sha(value: Any, *, label: str) -> str:
    try:
        return require_full_sha(value, label=label)
    except SecurePatchError as exc:
        raise PublicationAuthorizationError(str(exc)) from exc


def require_digest(value: Any, *, label: str) -> str:
    try:
        return require_sha256(value, label=label)
    except SecurePatchError as exc:
        raise PublicationAuthorizationError(str(exc)) from exc


def require_trusted_publication_policy_digest(value: Any) -> str:
    digest = require_digest(value, label="publication policy trust root")
    if not hmac.compare_digest(digest, TRUSTED_PUBLICATION_POLICY_SHA256):
        raise PublicationAuthorizationError(
            "Publication authorization policy is not anchored by this build"
        )
    return digest


def require_exact_keys(
    value: dict[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if unexpected:
            detail.append(f"unexpected {', '.join(unexpected)}")
        raise PublicationAuthorizationError(
            f"{label.capitalize()} fields are invalid: {'; '.join(detail)}"
        )


def parse_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PublicationAuthorizationError(f"{label.capitalize()} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PublicationAuthorizationError(f"{label.capitalize()} is invalid") from exc
    if parsed.tzinfo is None:
        raise PublicationAuthorizationError(
            f"{label.capitalize()} must include a timezone"
        )
    return parsed.astimezone(UTC)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds")


def snapshot_file(path: Path, *, label: str) -> tuple[bytes, str]:
    try:
        with path.open("rb") as handle:
            value = handle.read()
    except OSError as exc:
        raise PublicationAuthorizationError(f"Unable to read {label}: {path}") from exc
    return value, hashlib.sha256(value).hexdigest()


def decode_json_object(value: bytes, *, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationAuthorizationError(
            f"{label.capitalize()} is invalid JSON"
        ) from exc
    value = decoded
    if not isinstance(value, dict):
        raise PublicationAuthorizationError(f"{label.capitalize()} must be an object")
    return value
