from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from enum import Enum


class ConfigError(ValueError):
    pass


class ProtocolMode(str, Enum):
    SSL = "ssl"
    STARTTLS = "starttls"


@dataclass(frozen=True)
class EndpointConfig:
    host: str
    port: int
    mode: ProtocolMode


@dataclass(frozen=True)
class UserCredentials:
    username: str
    imap_username: str
    imap_password: str
    smtp_username: str
    smtp_password: str


@dataclass(frozen=True)
class AppConfig:
    allowed_users: tuple[str, ...]
    imap: EndpointConfig
    smtp: EndpointConfig
    sent_folder: str
    trash_folder: str
    imap_tls_verify: bool
    imap_tls_ca_bundle_path: str | None
    imap_max_retries: int
    action_flags: dict[str, bool]
    users: dict[str, UserCredentials]
    audit_log_dir: str
    preshared_key: str


def _require(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise ConfigError(f"Missing required environment variable: {name}")
    return val


def _parse_port(name: str) -> int:
    raw = _require(name)
    try:
        port = int(raw)
    except ValueError as exc:
        raise ConfigError(f"Invalid port for {name}: {raw}") from exc
    if not (1 <= port <= 65535):
        raise ConfigError(f"Port out of range for {name}: {raw}")
    return port


def _parse_mode(name: str) -> ProtocolMode:
    raw = _require(name).lower()
    try:
        return ProtocolMode(raw)
    except ValueError as exc:
        raise ConfigError(f"Invalid protocol mode for {name}: {raw}") from exc


def _parse_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    norm = raw.strip().lower()
    if norm in {"1", "true", "yes", "on"}:
        return True
    if norm in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"Invalid boolean for {name}: {raw}")


def _parse_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise ConfigError(f"Invalid integer for {name}: {raw}") from exc
    return parsed



def _load_preshared_key() -> str:
    configured = os.getenv("MCP_PRESHARED_KEY")
    if configured:
        return configured
    generated = secrets.token_urlsafe(32)
    print(f"Generated MCP preshared key for this run: {generated}")
    return generated

def load_config() -> AppConfig:
    allowed_users = tuple(u.strip() for u in _require("MCP_ALLOWED_USERS").split(",") if u.strip())
    if not allowed_users:
        raise ConfigError("MCP_ALLOWED_USERS must include at least one user")

    imap = EndpointConfig(_require("IMAP_HOST"), _parse_port("IMAP_PORT"), _parse_mode("IMAP_MODE"))
    smtp = EndpointConfig(_require("SMTP_HOST"), _parse_port("SMTP_PORT"), _parse_mode("SMTP_MODE"))

    imap_tls_verify = _parse_bool("IMAP_TLS_VERIFY", True)
    if not imap_tls_verify:
        raise ConfigError("IMAP_TLS_VERIFY must be true")

    imap_max_retries = _parse_int("IMAP_MAX_RETRIES", 2)
    if imap_max_retries < 0:
        raise ConfigError("IMAP_MAX_RETRIES must be >= 0")

    actions = {
        "list_folders": _parse_bool("ACTION_LIST_FOLDERS", True),
        "search_emails": _parse_bool("ACTION_SEARCH_EMAILS", True),
        "list_emails": _parse_bool("ACTION_LIST_EMAILS", True),
        "read_email": _parse_bool("ACTION_READ_EMAIL", True),
        "send_email": _parse_bool("ACTION_SEND_EMAIL", True),
        "mark_read_state": _parse_bool("ACTION_MARK_READ_STATE", True),
        "move_email": _parse_bool("ACTION_MOVE_EMAIL", True),
        "copy_email": _parse_bool("ACTION_COPY_EMAIL", True),
        "delete_email_permanent": _parse_bool("ACTION_DELETE_EMAIL_PERMANENT", True),
        "move_to_trash": _parse_bool("ACTION_MOVE_TO_TRASH", True),
        "empty_trash": _parse_bool("ACTION_EMPTY_TRASH", True),
    }

    users: dict[str, UserCredentials] = {}
    for username in allowed_users:
        key = username.upper().replace("-", "_")
        users[username] = UserCredentials(
            username=username,
            imap_username=_require(f"USER_{key}_IMAP_USERNAME"),
            imap_password=_require(f"USER_{key}_IMAP_PASSWORD"),
            smtp_username=_require(f"USER_{key}_SMTP_USERNAME"),
            smtp_password=_require(f"USER_{key}_SMTP_PASSWORD"),
        )

    return AppConfig(
        allowed_users=allowed_users,
        imap=imap,
        smtp=smtp,
        sent_folder=_require("IMAP_SENT_FOLDER"),
        trash_folder=_require("IMAP_TRASH_FOLDER"),
        imap_tls_verify=imap_tls_verify,
        imap_tls_ca_bundle_path=os.getenv("IMAP_TLS_CA_BUNDLE_PATH"),
        imap_max_retries=imap_max_retries,
        action_flags=actions,
        users=users,
        audit_log_dir=_require("AUDIT_LOG_DIR"),
        preshared_key=_load_preshared_key(),
    )
