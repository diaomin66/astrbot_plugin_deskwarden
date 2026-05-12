from __future__ import annotations

import difflib
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MAX_READ_BYTES = 256 * 1024
MAX_WRITE_BYTES = 512 * 1024
FORBIDDEN_PARTS = {
    ".aws",
    ".azure",
    ".gnupg",
    ".ssh",
    "appdata",
    "credentials",
    "microsoft",
    "program files",
    "program files (x86)",
    "windows",
}
FORBIDDEN_NAME_FRAGMENTS = {
    ".env",
    "credential",
    "id_rsa",
    "id_ed25519",
    "private_key",
    "secret",
    "token",
}


class FileSandboxError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class FileDiff:
    path: str
    diff: str
    existing: bool
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "diff": self.diff,
            "existing": self.existing,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class FileWriteResult:
    path: str
    backup_ref: str | None
    bytes_written: int
    verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "backup_ref": self.backup_ref,
            "bytes_written": self.bytes_written,
            "verified": self.verified,
        }


class FileSandbox:
    def __init__(self, workspace_dirs: Iterable[str | Path] | None, backup_dir: Path):
        self.workspace_dirs = [_resolve_path(Path(path)) for path in (workspace_dirs or []) if str(path).strip()]
        self.backup_dir = backup_dir

    def read_text(self, requested_path: str) -> dict[str, Any]:
        path = self._resolve_allowed(requested_path)
        if not path.exists() or not path.is_file():
            raise FileSandboxError("FILE_NOT_FOUND", "The requested file does not exist inside a configured workspace.")

        size = path.stat().st_size
        if size > MAX_READ_BYTES:
            raise FileSandboxError("FILE_TOO_LARGE", f"File exceeds the {MAX_READ_BYTES} byte read limit.")

        content = path.read_text(encoding="utf-8", errors="replace")
        return {"path": str(path), "content": content, "size_bytes": size}

    def build_diff(self, requested_path: str, new_content: str) -> FileDiff:
        path = self._resolve_allowed(requested_path)
        encoded = new_content.encode("utf-8")
        if len(encoded) > MAX_WRITE_BYTES:
            raise FileSandboxError("WRITE_TOO_LARGE", f"Write exceeds the {MAX_WRITE_BYTES} byte limit.")

        existing = path.exists()
        old_content = ""
        if existing:
            if not path.is_file():
                raise FileSandboxError("NOT_A_FILE", "The requested path exists but is not a regular file.")
            if path.stat().st_size > MAX_READ_BYTES:
                raise FileSandboxError("FILE_TOO_LARGE", f"Existing file exceeds the {MAX_READ_BYTES} byte read limit.")
            old_content = path.read_text(encoding="utf-8", errors="replace")

        diff = "".join(
            difflib.unified_diff(
                old_content.splitlines(keepends=True),
                new_content.splitlines(keepends=True),
                fromfile=str(path),
                tofile=str(path),
            )
        )
        return FileDiff(path=str(path), diff=diff, existing=existing, size_bytes=len(encoded))

    def write_text(self, requested_path: str, new_content: str, proposal_id: str) -> FileWriteResult:
        path = self._resolve_allowed(requested_path)
        encoded = new_content.encode("utf-8")
        if len(encoded) > MAX_WRITE_BYTES:
            raise FileSandboxError("WRITE_TOO_LARGE", f"Write exceeds the {MAX_WRITE_BYTES} byte limit.")

        backup_ref: str | None = None
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not path.is_file():
                raise FileSandboxError("NOT_A_FILE", "The requested path exists but is not a regular file.")
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            backup_name = f"{int(time.time())}-{proposal_id}-{path.name}.bak"
            backup_path = self.backup_dir / backup_name
            shutil.copy2(path, backup_path)
            backup_ref = str(backup_path)

        path.write_text(new_content, encoding="utf-8")
        verified = path.read_text(encoding="utf-8", errors="replace") == new_content
        if not verified:
            raise FileSandboxError("VERIFY_FAILED", "The file was written but verification failed. Backup was retained.")

        return FileWriteResult(path=str(path), backup_ref=backup_ref, bytes_written=len(encoded), verified=True)

    def _resolve_allowed(self, requested_path: str) -> Path:
        if not self.workspace_dirs:
            raise FileSandboxError("NO_WORKSPACE", "No file sandbox workspace directories are configured.")

        if not requested_path or "\x00" in requested_path:
            raise FileSandboxError("BAD_PATH", "File path is empty or invalid.")

        path = _resolve_path(Path(requested_path))
        matched_workspace = next((workspace for workspace in self.workspace_dirs if _is_relative_to(path, workspace)), None)
        if matched_workspace is None:
            raise FileSandboxError("PATH_OUTSIDE_WORKSPACE", "Path is outside the configured file sandbox workspaces.")

        parts = {part.lower() for part in path.relative_to(matched_workspace).parts}
        if parts & FORBIDDEN_PARTS:
            raise FileSandboxError("FORBIDDEN_PATH", "Path crosses a forbidden system or credential directory.")

        lowered_name = path.name.lower()
        if any(fragment in lowered_name for fragment in FORBIDDEN_NAME_FRAGMENTS):
            raise FileSandboxError("FORBIDDEN_FILE", "Credential, token, key, secret, and .env files are forbidden.")

        return path


def _resolve_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
