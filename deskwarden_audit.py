from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

try:
    from .deskwarden_types import AuditRecord
except ImportError:  # pragma: no cover
    from deskwarden_types import AuditRecord


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()

    def append(self, record: AuditRecord) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(record.to_json_line())
                handle.write("\n")

    def latest(self, limit: int = 10) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit or 10), 100))
        with self._lock:
            if not self.path.exists():
                return []

            lines = self.path.read_text(encoding="utf-8").splitlines()
            records: list[dict[str, Any]] = []
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    records.append(value)
                if len(records) >= limit:
                    break
            records.reverse()
            return records

    def purge(self) -> int:
        with self._lock:
            count = 0
            if self.path.exists():
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        count += 1
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            return count
