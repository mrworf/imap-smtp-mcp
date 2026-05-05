from .config import AppConfig


class CapabilityError(PermissionError):
    pass


def ensure_action_enabled(action: str, config: AppConfig) -> None:
    enabled = config.action_flags.get(action)
    if enabled is None:
        raise CapabilityError(f"Unknown action: {action}")
    if not enabled:
        raise CapabilityError(f"Action disabled: {action}")
