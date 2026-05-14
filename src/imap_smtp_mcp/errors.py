from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MCPError(Exception):
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


class NotFoundError(MCPError):
    def __init__(self, message: str):
        super().__init__(code="not_found", message=message)


class PermissionDisabledError(MCPError):
    def __init__(self, message: str):
        super().__init__(code="permission_disabled", message=message)


class BackendUnavailableError(MCPError):
    def __init__(self, message: str):
        super().__init__(code="backend_unavailable", message=message)


class InvalidInputError(MCPError):
    def __init__(self, message: str):
        super().__init__(code="invalid_input", message=message)


class AuthSessionError(MCPError):
    def __init__(self, message: str):
        super().__init__(code="invalid_session", message=message)
