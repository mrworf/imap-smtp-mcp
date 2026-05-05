from dataclasses import dataclass

from .auth import AuthenticatedUser, authenticate_user
from .capabilities import ensure_action_enabled
from .config import AppConfig, load_config


@dataclass
class MCPServer:
    config: AppConfig

    @classmethod
    def from_env(cls) -> "MCPServer":
        return cls(config=load_config())

    def preflight(self, mcp_user: str, action: str) -> AuthenticatedUser:
        user = authenticate_user(mcp_user, self.config)
        ensure_action_enabled(action, self.config)
        return user
