from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


REDACTED = "[REDACTED]"
SYSTEM_LOG = "system"


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    operation: str
    success: bool
    failure_class: str | None = None
    mcp_user: str | None = None


class AuditLogger:
    def __init__(self, log_dir: str, *, rotate_max_bytes: int = 1_000_000, rotate_backup_count: int = 3) -> None:
        self._log_dir = Path(log_dir)
        self._rotate_max_bytes = rotate_max_bytes
        self._rotate_backup_count = rotate_backup_count
        self._lock = threading.RLock()
        self._log_dir.mkdir(parents=True, exist_ok=True)

    def log_tool_invocation(self, event: AuditEvent) -> None:
        username = event.mcp_user or SYSTEM_LOG
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "request_id": event.request_id,
            "mcp_user": event.mcp_user,
            "operation": event.operation,
            "success": event.success,
            "failure_class": event.failure_class,
            "message_content": REDACTED,
        }
        self._write_line(username, json.dumps(payload, separators=(",", ":")))

    def _write_line(self, username: str, line: str) -> None:
        file_path = self._log_dir / f"{username}.log"
        with self._lock:
            self._rotate_if_needed(file_path, len(line) + 1)
            with file_path.open("a", encoding="utf-8") as f:
                f.write(line)
                f.write("\n")

    def _rotate_if_needed(self, file_path: Path, incoming_bytes: int) -> None:
        if not file_path.exists():
            return
        if file_path.stat().st_size + incoming_bytes <= self._rotate_max_bytes:
            return

        oldest = file_path.with_name(f"{file_path.name}.{self._rotate_backup_count}")
        if oldest.exists():
            oldest.unlink()

        for idx in range(self._rotate_backup_count - 1, 0, -1):
            src = file_path.with_name(f"{file_path.name}.{idx}")
            if src.exists():
                src.rename(file_path.with_name(f"{file_path.name}.{idx + 1}"))

        file_path.rename(file_path.with_name(f"{file_path.name}.1"))
