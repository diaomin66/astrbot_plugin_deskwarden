from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MAX_COMMAND_LENGTH = 2000
MAX_OUTPUT_BYTES = 32 * 1024
DEFAULT_TIMEOUT_SECONDS = 5
MAX_TIMEOUT_SECONDS = 30
CONTROL_OPERATORS = re.compile(r"[\r\n|&;<>`]")
FORBIDDEN_EXECUTABLES = {
    "bitsadmin",
    "cmd",
    "curl",
    "del",
    "erase",
    "format",
    "net",
    "netsh",
    "powershell",
    "pwsh",
    "rd",
    "reg",
    "regedit",
    "rm",
    "rmdir",
    "runas",
    "schtasks",
    "sc",
    "sudo",
    "wget",
}
FORBIDDEN_PHRASES = {
    "invoke-expression",
    "invoke-webrequest",
    "new-service",
    "remove-item",
    "set-executionpolicy",
    "start-process",
    "startup",
}


class ShellSandboxError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ShellPlan:
    command: str
    argv: list[str]
    cwd: str
    timeout_seconds: int
    allowlist_match: str
    risk_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "argv": self.argv,
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
            "allowlist_match": self.allowlist_match,
            "risk_reason": self.risk_reason,
        }


@dataclass(frozen=True)
class ShellRunResult:
    command: str
    cwd: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    stdout_truncated: bool
    stderr_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }


class RestrictedShell:
    def __init__(
        self,
        enabled: bool = False,
        allowlist: Iterable[str] | None = None,
        workspace_dirs: Iterable[str | Path] | None = None,
    ):
        self.enabled = enabled
        self.workspace_dirs = [_resolve_path(Path(path)) for path in (workspace_dirs or []) if str(path).strip()]
        self.allowlist = [entry.strip() for entry in (allowlist or []) if entry.strip()]
        self._allowlist_tokens = [self._parse_prefix(entry) for entry in self.allowlist]

    def plan(self, command: str, cwd: str = "", timeout_seconds: int | None = None) -> ShellPlan:
        if not self.enabled:
            raise ShellSandboxError("SHELL_DISABLED", "Restricted shell is disabled by daemon configuration.")

        resolved_cwd = self._resolve_cwd(cwd)
        timeout = _clamp_timeout(timeout_seconds)
        argv = self._parse_command(command)
        match = self._match_allowlist(argv)
        if match is None:
            raise ShellSandboxError("SHELL_NOT_ALLOWED", "Command is not in the daemon shell allowlist.")

        return ShellPlan(
            command=command.strip(),
            argv=argv,
            cwd=str(resolved_cwd),
            timeout_seconds=timeout,
            allowlist_match=match,
            risk_reason="Restricted shell commands are mutating-capable and always require owner approval.",
        )

    def run(self, command: str, cwd: str = "", timeout_seconds: int | None = None) -> ShellRunResult:
        plan = self.plan(command, cwd, timeout_seconds)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                plan.argv,
                cwd=plan.cwd,
                capture_output=True,
                check=False,
                shell=False,
                timeout=plan.timeout_seconds,
            )
            stdout, stdout_truncated = _decode_output(completed.stdout)
            stderr, stderr_truncated = _decode_output(completed.stderr)
            return ShellRunResult(
                command=plan.command,
                cwd=plan.cwd,
                exit_code=completed.returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
                duration_ms=_elapsed_ms(started),
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        except subprocess.TimeoutExpired as exc:
            stdout, stdout_truncated = _decode_output(exc.stdout or b"")
            stderr, stderr_truncated = _decode_output(exc.stderr or b"")
            return ShellRunResult(
                command=plan.command,
                cwd=plan.cwd,
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
                duration_ms=_elapsed_ms(started),
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        except OSError as exc:
            raise ShellSandboxError("SHELL_EXEC_FAILED", f"Command could not be started: {exc}") from exc

    def _parse_command(self, command: str) -> list[str]:
        command = command.strip()
        if not command:
            raise ShellSandboxError("SHELL_EMPTY_COMMAND", "Shell command is empty.")
        if len(command) > MAX_COMMAND_LENGTH:
            raise ShellSandboxError("SHELL_COMMAND_TOO_LONG", "Shell command is too long.")
        if CONTROL_OPERATORS.search(command):
            raise ShellSandboxError("SHELL_CONTROL_OPERATOR", "Shell control operators are not allowed.")

        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            raise ShellSandboxError("SHELL_PARSE_FAILED", "Shell command could not be parsed.") from exc

        if not argv:
            raise ShellSandboxError("SHELL_EMPTY_COMMAND", "Shell command is empty.")

        executable = _normalize_executable(argv[0])
        if executable in FORBIDDEN_EXECUTABLES:
            raise ShellSandboxError("SHELL_FORBIDDEN", f"Executable is forbidden: {executable}")
        if Path(argv[0]).name != argv[0]:
            raise ShellSandboxError("SHELL_EXECUTABLE_PATH", "Shell allowlist entries must use bare executable names.")

        lowered = command.lower()
        if any(phrase in lowered for phrase in FORBIDDEN_PHRASES):
            raise ShellSandboxError("SHELL_FORBIDDEN", "Command contains a forbidden high-risk operation.")

        return argv

    def _parse_prefix(self, command_prefix: str) -> list[str]:
        return [_normalize_token(token, index) for index, token in enumerate(shlex.split(command_prefix, posix=True))]

    def _match_allowlist(self, argv: list[str]) -> str | None:
        normalized = [_normalize_token(token, index) for index, token in enumerate(argv)]
        for original, prefix in zip(self.allowlist, self._allowlist_tokens):
            if prefix and normalized[: len(prefix)] == prefix:
                return original
        return None

    def _resolve_cwd(self, cwd: str) -> Path:
        if not self.workspace_dirs:
            raise ShellSandboxError("SHELL_NO_WORKSPACE", "No shell workspace directories are configured.")

        requested = cwd.strip()
        path = _resolve_path(Path(requested)) if requested else self.workspace_dirs[0]
        matched_workspace = next((workspace for workspace in self.workspace_dirs if _is_relative_to(path, workspace)), None)
        if matched_workspace is None:
            raise ShellSandboxError("SHELL_CWD_OUTSIDE_WORKSPACE", "Shell cwd is outside configured workspaces.")
        if path.exists() and not path.is_dir():
            raise ShellSandboxError("SHELL_BAD_CWD", "Shell cwd exists but is not a directory.")
        path.mkdir(parents=True, exist_ok=True)
        return path


def _decode_output(value: bytes | str) -> tuple[str, bool]:
    if isinstance(value, str):
        raw = value.encode("utf-8", errors="replace")
    else:
        raw = value
    truncated = len(raw) > MAX_OUTPUT_BYTES
    raw = raw[:MAX_OUTPUT_BYTES]
    text = raw.decode("utf-8", errors="replace")
    if truncated:
        text += "\n...[truncated]"
    return text, truncated


def _clamp_timeout(value: int | None) -> int:
    try:
        parsed = int(value if value is not None else DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        parsed = DEFAULT_TIMEOUT_SECONDS
    return max(1, min(parsed, MAX_TIMEOUT_SECONDS))


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _normalize_executable(value: str) -> str:
    executable = Path(value).name.lower()
    if os.name == "nt" and executable.endswith((".exe", ".bat", ".cmd")):
        executable = executable.rsplit(".", 1)[0]
    return executable


def _normalize_token(value: str, index: int) -> str:
    return _normalize_executable(value) if index == 0 else value.lower()


def _resolve_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
