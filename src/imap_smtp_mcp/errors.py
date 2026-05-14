from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MCPError(Exception):
    code: str
    message: str
    metadata: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


class NotFoundError(MCPError):
    def __init__(self, message: str, *, metadata: dict[str, Any] | None = None):
        super().__init__(code="not_found", message=message, metadata=metadata)


class PermissionDisabledError(MCPError):
    def __init__(self, message: str, *, metadata: dict[str, Any] | None = None):
        super().__init__(code="permission_disabled", message=message, metadata=metadata)


class BackendUnavailableError(MCPError):
    def __init__(self, message: str, *, metadata: dict[str, Any] | None = None):
        super().__init__(code="backend_unavailable", message=message, metadata=metadata)


class InvalidInputError(MCPError):
    def __init__(self, message: str, *, metadata: dict[str, Any] | None = None):
        super().__init__(code="invalid_input", message=message, metadata=metadata)


class AuthSessionError(MCPError):
    def __init__(self, message: str, *, metadata: dict[str, Any] | None = None):
        super().__init__(code="invalid_session", message=message, metadata=metadata)
