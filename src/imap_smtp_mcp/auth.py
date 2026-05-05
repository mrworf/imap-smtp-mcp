from dataclasses import dataclass

from .config import AppConfig, UserCredentials


class AuthError(PermissionError):
    pass


@dataclass(frozen=True)
class AuthenticatedUser:
    username: str
    credentials: UserCredentials


def authenticate_user(mcp_username: str, config: AppConfig) -> AuthenticatedUser:
    if mcp_username not in config.allowed_users:
        raise AuthError("Unauthorized MCP user")
    return AuthenticatedUser(username=mcp_username, credentials=config.users[mcp_username])
