from __future__ import annotations

import base64
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from assured_downstream.account_boundary import (
    AccountBoundaryError,
    require_allowed_target_owner,
    verify_authenticated_actor,
)
from assured_downstream.agent_contracts import canonical_json
from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.publication_authorization import (
    PublicationAuthorizationError,
    decode_json_object,
    format_timestamp,
    require_trusted_publication_policy_digest,
    snapshot_file,
    validate_publication_policy,
    validate_publication_request,
)


RUN_URL_PATTERN = re.compile(
    r"^https://github\.com/(?P<repository>[^/]+/[^/]+)/actions/runs/(?P<run_id>[0-9]+)$"
)


def dispatch_publication_authorization(
    *,
    request_path: Path,
    policy_path: Path,
    execute: bool = False,
    runner: CommandRunner | None = None,
    now: datetime | None = None,
    account_boundary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request_path = request_path.expanduser().resolve()
    policy_path = policy_path.expanduser().resolve()
    request_bytes, request_sha256 = snapshot_file(
        request_path,
        label="publication request",
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
    effective_policy = validate_publication_policy(policy, require_active=True)
    validate_publication_request(
        request,
        policy=effective_policy,
        policy_sha256=policy_sha256,
        request_sha256=request_sha256,
        now=now,
    )

    executable = Path(effective_policy["verifier"]["executable"])
    executable_bytes, executable_sha256 = snapshot_file(
        executable,
        label="publication control executable",
    )
    if executable_sha256 != effective_policy["verifier"]["sha256"]:
        raise PublicationAuthorizationError(
            "Publication control executable digest does not match policy"
        )
    signer = effective_policy["signer"]
    workflow_file = signer["workflow"].rsplit("/", 1)[1]
    source_ref = signer["source_ref"].removeprefix("refs/heads/")
    input_value = canonical_json(
        {
            "request_base64": base64.b64encode(request_bytes).decode("ascii"),
            "request_sha256": request_sha256,
        }
    )
    planned_command = [
        str(executable),
        "workflow",
        "run",
        workflow_file,
        "--repo",
        effective_policy["control_repository"],
        "--ref",
        source_ref,
        "--json",
    ]
    record = {
        "schema_version": 1,
        "status": "planned" if not execute else "dispatching",
        "executed": False,
        "request_id": request["request_id"],
        "request_sha256": request_sha256,
        "policy_sha256": policy_sha256,
        "control_repository": effective_policy["control_repository"],
        "workflow": signer["workflow"],
        "workflow_digest": signer["workflow_digest"],
        "source_ref": signer["source_ref"],
        "command": display_command(planned_command),
        "run_id": None,
        "run_url": None,
    }
    if not execute:
        return record

    if account_boundary is None:
        raise PublicationAuthorizationError(
            "GitHub account boundary policy is required for mutation"
        )
    try:
        control_owner = effective_policy["control_repository"].split("/", 1)[0]
        require_allowed_target_owner(account_boundary, control_owner)
        require_allowed_target_owner(
            account_boundary,
            effective_policy["scope"]["target_owner"],
        )
    except AccountBoundaryError as exc:
        raise PublicationAuthorizationError(str(exc)) from exc

    effective_runner = runner or CommandRunner(execute=True)
    with tempfile.TemporaryDirectory(prefix="assured-publication-dispatch-") as tmp:
        staged_executable = Path(tmp) / "gh"
        staged_executable.write_bytes(executable_bytes)
        staged_executable.chmod(0o500)
        mutation_env = {
            "GH_NO_UPDATE_NOTIFIER": "1",
            "GH_PROMPT_DISABLED": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        identity = effective_runner.run(
            [str(staged_executable), "api", "user"],
            env=mutation_env,
        )
        identity_ok, identity_detail = verify_authenticated_actor(
            identity,
            account_boundary,
        )
        if not identity_ok:
            raise PublicationAuthorizationError(
                "GitHub mutation identity check failed: "
                f"{identity_detail.get('reason', 'identity mismatch')}"
            )
        command = [str(staged_executable), *planned_command[1:]]
        result = effective_runner.run(
            command,
            env=mutation_env,
            input_text=input_value + "\n",
        )
    if not result.executed:
        raise PublicationAuthorizationError(
            "Publication authorization dispatch did not execute"
        )
    if not result.ok:
        detail = (result.stderr or result.stdout).strip() or "dispatch failed"
        if len(detail) > 2048:
            detail = detail[:2048] + "...<truncated>"
        raise PublicationAuthorizationError(
            f"Publication authorization dispatch failed: {detail}"
        )
    run_url = parse_run_url(result.stdout, effective_policy["control_repository"])
    match = RUN_URL_PATTERN.fullmatch(run_url)
    assert match is not None
    current = now or datetime.now().astimezone()
    return {
        **record,
        "status": "dispatched",
        "executed": True,
        "dispatched_at": format_timestamp(current),
        "run_id": match.group("run_id"),
        "run_url": run_url,
    }


def parse_run_url(output: str, expected_repository: str) -> str:
    matches = []
    for line in output.splitlines():
        candidate = line.strip()
        match = RUN_URL_PATTERN.fullmatch(candidate)
        if match is not None and match.group("repository") == expected_repository:
            matches.append(candidate)
    if len(matches) != 1:
        raise PublicationAuthorizationError(
            "Publication dispatch did not return one trusted workflow run URL"
        )
    return matches[0]
