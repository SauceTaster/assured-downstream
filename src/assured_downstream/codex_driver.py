from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assured_downstream.agent_contracts import ModelExecution


DEFAULT_CODEX_PROFILE = "assured-downstream-luna"
DEFAULT_CODEX_TIMEOUT_SECONDS = 90
CODEX_PROFILE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
DEFAULT_RESULT_SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "policies"
    / "schemas"
    / "codex-agent-result.schema.json"
)


class CodexDriverError(RuntimeError):
    pass


@dataclass(frozen=True)
class CodexProfile:
    name: str
    path: Path
    model: str | None
    reasoning_effort: str | None


@dataclass(frozen=True)
class CodexResult:
    payload: dict[str, Any]
    execution: ModelExecution


class CodexDriver:
    """Constrained noninteractive Codex adapter for judgment-heavy agent steps."""

    def __init__(
        self,
        *,
        profile: str = DEFAULT_CODEX_PROFILE,
        timeout_seconds: int = DEFAULT_CODEX_TIMEOUT_SECONDS,
        sandbox: str = "read-only",
        schema_path: Path = DEFAULT_RESULT_SCHEMA,
        executable: str = "codex",
        codex_home: Path | None = None,
    ) -> None:
        if not CODEX_PROFILE_PATTERN.fullmatch(profile):
            raise ValueError(f"Invalid Codex profile name: {profile!r}")
        if timeout_seconds <= 0:
            raise ValueError("Codex timeout must be positive")
        if sandbox != "read-only":
            raise ValueError("Cognitive agents must use the read-only Codex sandbox")
        self.profile_name = profile
        self.timeout_seconds = timeout_seconds
        self.sandbox = sandbox
        self.schema_path = schema_path.resolve()
        self.executable = executable
        self.codex_home = (
            codex_home
            or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
        ).resolve()

    def profile(self) -> CodexProfile:
        path = self.codex_home / f"{self.profile_name}.config.toml"
        if not path.exists():
            raise CodexDriverError(
                f"Codex profile {self.profile_name!r} is not installed at {path}"
            )
        try:
            with path.open("rb") as handle:
                config = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise CodexDriverError(f"Codex profile could not be loaded: {path}") from exc
        return CodexProfile(
            name=self.profile_name,
            path=path,
            model=string_or_none(config.get("model")),
            reasoning_effort=string_or_none(config.get("model_reasoning_effort")),
        )

    def preflight(self) -> dict[str, Any]:
        executable_path = shutil.which(self.executable)
        if executable_path is None:
            raise CodexDriverError(f"Codex executable not found: {self.executable}")
        if not self.schema_path.exists():
            raise CodexDriverError(f"Codex result schema not found: {self.schema_path}")
        profile = self.profile()
        try:
            version = subprocess.run(
                [executable_path, "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise CodexDriverError("Codex version preflight failed") from exc
        return {
            "executable": executable_path,
            "version": version,
            "profile": profile.name,
            "profile_path": str(profile.path),
            "model": profile.model,
            "reasoning_effort": profile.reasoning_effort,
            "sandbox": self.sandbox,
            "schema_path": str(self.schema_path),
        }

    def command(
        self,
        *,
        workdir: Path,
        output_path: Path,
        prompt: str,
    ) -> list[str]:
        executable_path = shutil.which(self.executable) or self.executable
        return [
            executable_path,
            "-a",
            "never",
            "exec",
            "-p",
            self.profile_name,
            "--ephemeral",
            "--skip-git-repo-check",
            "-s",
            self.sandbox,
            "-C",
            str(workdir.resolve()),
            "--output-schema",
            str(self.schema_path),
            "-o",
            str(output_path.resolve()),
            prompt,
        ]

    def run(
        self,
        *,
        workdir: Path,
        output_path: Path,
        prompt: str,
    ) -> CodexResult:
        preflight = self.preflight()
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.unlink(missing_ok=True)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                self.command(
                    workdir=workdir,
                    output_path=output_path,
                    prompt=prompt,
                ),
                check=False,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - started
            raise CodexDriverError(
                f"Codex timed out after {duration:.1f}s for profile {self.profile_name}"
            ) from exc
        except OSError as exc:
            raise CodexDriverError(f"Codex could not be started: {exc}") from exc

        duration = time.monotonic() - started
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise CodexDriverError(
                f"Codex exited {completed.returncode}: {detail[-2000:]}"
            )
        if not output_path.exists():
            raise CodexDriverError("Codex completed without writing its structured result")

        try:
            with output_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise CodexDriverError(
                f"Codex wrote an unreadable structured result: {output_path}"
            ) from exc
        validate_result(payload)
        return CodexResult(
            payload=payload,
            execution=ModelExecution(
                driver="codex-exec",
                profile=self.profile_name,
                model=preflight["model"],
                reasoning_effort=preflight["reasoning_effort"],
                sandbox=self.sandbox,
                codex_version=preflight["version"],
                duration_seconds=round(duration, 3),
                result_path=str(output_path),
                status=str(payload["status"]),
            ),
        )


def validate_result(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise CodexDriverError("Codex result must be a JSON object")
    required = {
        "schema_version",
        "status",
        "summary",
        "findings",
        "recommendations",
        "data",
    }
    missing = sorted(required - payload.keys())
    extra = sorted(payload.keys() - required)
    if missing or extra:
        raise CodexDriverError(
            f"Codex result fields are invalid; missing={missing}, extra={extra}"
        )
    if payload["schema_version"] != 1:
        raise CodexDriverError("Codex result has an unsupported schema version")
    if payload["status"] not in {"succeeded", "blocked", "needs_human_review"}:
        raise CodexDriverError(f"Codex result status is invalid: {payload['status']!r}")
    if not isinstance(payload["summary"], str):
        raise CodexDriverError("Codex result summary must be a string")
    if not isinstance(payload["recommendations"], list) or not all(
        isinstance(item, str) for item in payload["recommendations"]
    ):
        raise CodexDriverError("Codex result recommendations must be strings")
    if not isinstance(payload["findings"], list):
        raise CodexDriverError("Codex result findings must be an array")
    for finding in payload["findings"]:
        if not isinstance(finding, dict) or set(finding) != {
            "code",
            "severity",
            "message",
            "path",
        }:
            raise CodexDriverError("Codex result contains an invalid finding")
        if finding["severity"] not in {"info", "low", "medium", "high", "critical"}:
            raise CodexDriverError("Codex result contains an invalid finding severity")
        if not all(
            isinstance(finding[key], str)
            for key in ("code", "severity", "message")
        ) or (finding["path"] is not None and not isinstance(finding["path"], str)):
            raise CodexDriverError("Codex finding values have invalid types")
    if not isinstance(payload["data"], list):
        raise CodexDriverError("Codex result data must be an array")
    for item in payload["data"]:
        if not isinstance(item, dict) or set(item) != {"key", "value_json"}:
            raise CodexDriverError("Codex result contains an invalid data item")
        if not isinstance(item["key"], str) or not isinstance(item["value_json"], str):
            raise CodexDriverError("Codex data values must be strings")


def string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None
