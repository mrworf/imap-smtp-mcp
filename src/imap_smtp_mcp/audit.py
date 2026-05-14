from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REDACTED = "[REDACTED]"
SYSTEM_LOG = "system"
SECRET_FIELD_MARKERS = ("PASSWORD", "TOKEN", "SECRET", "KEY", "AUTHORIZATION", "AUTH_HEADER")


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    operation: str
    success: bool
    failure_class: str | None = None
    mcp_user: str | None = None
    metadata: dict[str, Any] | None = None
    arguments: Any = None
    result: Any = None
    exception_type: str | None = None
    exception_message: str | None = None
    exception_cause: str | None = None
    exception_traceback: str | None = None
    message_content: Any = None


class AuditLogger:
    def __init__(self, log_dir: str, *, rotate_max_bytes: int = 1_000_000, rotate_backup_count: int = 3, debug_unredacted_logs: bool = False) -> None:
        self._log_dir = Path(log_dir)
        self._rotate_max_bytes = rotate_max_bytes
        self._rotate_backup_count = rotate_backup_count
        self._debug_unredacted_logs = debug_unredacted_logs
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
            "message_content": _sanitize(event.message_content) if self._debug_unredacted_logs and event.message_content is not None else REDACTED,
        }
        if event.metadata:
            payload["metadata"] = _sanitize(event.metadata)
        if event.exception_type:
            payload["exception_type"] = event.exception_type
        if event.exception_message:
            payload["exception_message"] = event.exception_message
        if event.exception_cause:
            payload["exception_cause"] = event.exception_cause
        if self._debug_unredacted_logs:
            if event.arguments is not None:
                payload["arguments"] = _sanitize(event.arguments)
            if event.result is not None:
                payload["result"] = _sanitize(event.result)
            if event.exception_traceback:
                payload["exception_traceback"] = event.exception_traceback
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


def _sanitize(value: Any, *, key_hint: str = "") -> Any:
    if key_hint and any(marker in key_hint.upper() for marker in SECRET_FIELD_MARKERS):
        return REDACTED
    if isinstance(value, dict):
        return {str(key): _sanitize(item, key_hint=str(key)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return value
