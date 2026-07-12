from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    executed: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    def __init__(self, *, execute: bool) -> None:
        self.execute = execute

    def run(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        if not self.execute:
            return CommandResult(command=command, executed=False, returncode=0)

        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=None if env is None else {**os.environ, **env},
                input=input_text,
                check=False,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            return CommandResult(
                command=command,
                executed=True,
                returncode=124,
                stdout=stdout,
                stderr=(
                    stderr
                    or f"Command timed out after {timeout_seconds} seconds"
                ),
            )
        return CommandResult(
            command=command,
            executed=True,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def display_command(command: list[str]) -> str:
    return " ".join(shell_quote(part) for part in command)


def shell_quote(value: str) -> str:
    if value and all(character.isalnum() or character in "-_./:=@" for character in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"
