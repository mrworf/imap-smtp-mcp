from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_network
from pathlib import Path
import re
from urllib.parse import urlparse


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
class OAuthConfig:
    public_base_url: str = "http://127.0.0.1:8000"
    issuer: str = "http://127.0.0.1:8000"
    audience: str = "http://127.0.0.1:8000"
    signing_key: str = "dev-signing-key"
    encryption_key: str = ""
    cookie_secret: str = "dev-cookie-secret"
    access_token_ttl_seconds: int = 3600
    authorization_code_ttl_seconds: int = 300
    refresh_token_ttl_seconds: int = 2_592_000
    required_scopes: tuple[str, ...] = ("mail:read", "mail:send", "mail:write")
    username_claim: str = "sub"
    store_path: str = "/var/lib/imap-smtp-mcp/oauth.sqlite3"


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    trust_proxy_headers: bool = False
    allowed_proxy_cidrs: tuple[str, ...] = ("127.0.0.1/32", "::1/128")
    internal_https: bool = False
    allow_self_signed_internal_https: bool = False
    tls_cert_file: str | None = None
    tls_key_file: str | None = None


@dataclass(frozen=True)
class AppConfig:
    imap: EndpointConfig
    smtp: EndpointConfig
    smtp_from_domain: str | None
    sent_folder: str
    trash_folder: str
    imap_tls_verify: bool
    imap_tls_ca_bundle_path: str | None
    imap_max_retries: int
    smtp_timeout_seconds: int
    action_flags: dict[str, bool]
    audit_log_dir: str
    app_data_dir: str = "/var/lib/imap-smtp-mcp"
    oauth: OAuthConfig = OAuthConfig()
    server: ServerConfig = ServerConfig()


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


def _parse_scopes(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.getenv(name)
    if raw is None:
        return default
    scopes = tuple(scope.strip() for scope in raw.replace(",", " ").split() if scope.strip())
    if not scopes:
        raise ConfigError(f"{name} must include at least one scope")
    return scopes


def _parse_optional_domain(name: str) -> str | None:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return None
    domain = raw.strip().lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", domain):
        raise ConfigError(f"{name} must be a bare domain like example.com")
    return domain


def _parse_url(name: str, default: str) -> str:
    raw = os.getenv(name, default).rstrip("/")
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"Invalid URL for {name}: {raw}")
    return raw


def _validate_https_public_url(public_base_url: str) -> None:
    allow_insecure = _parse_bool("MCP_ALLOW_INSECURE_PUBLIC_URL", False)
    parsed = urlparse(public_base_url)
    if parsed.scheme == "https":
        return
    if allow_insecure or parsed.hostname in {"127.0.0.1", "localhost"}:
        return
    raise ConfigError("MCP_PUBLIC_BASE_URL must use https in production")


def _parse_proxy_cidrs() -> tuple[str, ...]:
    raw = os.getenv("MCP_ALLOWED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
    cidrs = tuple(item.strip() for item in raw.split(",") if item.strip())
    if not cidrs:
        raise ConfigError("MCP_ALLOWED_PROXY_CIDRS must include at least one CIDR")
    for cidr in cidrs:
        try:
            ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid CIDR in MCP_ALLOWED_PROXY_CIDRS: {cidr}") from exc
    return cidrs


def _load_oauth_config(app_data_dir: str) -> OAuthConfig:
    public_base_url = _parse_url("MCP_PUBLIC_BASE_URL", "http://127.0.0.1:8000")
    _validate_https_public_url(public_base_url)
    issuer = _parse_url("OAUTH_ISSUER", public_base_url)
    audience = os.getenv("OAUTH_AUDIENCE", public_base_url)
    signing_key = os.getenv("OAUTH_SIGNING_KEY", "dev-signing-key")
    cookie_secret = os.getenv("OAUTH_COOKIE_SECRET", "dev-cookie-secret")
    encryption_key = os.getenv("OAUTH_ENCRYPTION_KEY", "")
    if urlparse(public_base_url).scheme == "https":
        if signing_key == "dev-signing-key":
            raise ConfigError("OAUTH_SIGNING_KEY must be set for production HTTPS deployments")
        if cookie_secret == "dev-cookie-secret":
            raise ConfigError("OAUTH_COOKIE_SECRET must be set for production HTTPS deployments")
        if not encryption_key:
            raise ConfigError("OAUTH_ENCRYPTION_KEY must be set for production HTTPS deployments")
    access_ttl = _parse_int("OAUTH_ACCESS_TOKEN_TTL_SECONDS", 3600)
    code_ttl = _parse_int("OAUTH_AUTH_CODE_TTL_SECONDS", 300)
    refresh_ttl = _parse_int("OAUTH_REFRESH_TOKEN_TTL_SECONDS", 2_592_000)
    if access_ttl <= 0:
        raise ConfigError("OAUTH_ACCESS_TOKEN_TTL_SECONDS must be > 0")
    if code_ttl <= 0:
        raise ConfigError("OAUTH_AUTH_CODE_TTL_SECONDS must be > 0")
    if refresh_ttl <= 0:
        raise ConfigError("OAUTH_REFRESH_TOKEN_TTL_SECONDS must be > 0")
    store_path = os.getenv("OAUTH_STORE_PATH", str(Path(app_data_dir) / "oauth.sqlite3"))
    return OAuthConfig(
        public_base_url=public_base_url,
        issuer=issuer,
        audience=audience,
        signing_key=signing_key,
        encryption_key=encryption_key,
        cookie_secret=cookie_secret,
        access_token_ttl_seconds=access_ttl,
        authorization_code_ttl_seconds=code_ttl,
        refresh_token_ttl_seconds=refresh_ttl,
        required_scopes=_parse_scopes("OAUTH_REQUIRED_SCOPES", ("mail:read", "mail:send", "mail:write")),
        username_claim=os.getenv("OAUTH_USERNAME_CLAIM", "sub"),
        store_path=store_path,
    )


def _load_server_config() -> ServerConfig:
    port_raw = os.getenv("MCP_PORT")
    port = 8000 if port_raw is None else _parse_port("MCP_PORT")
    internal_https = _parse_bool("MCP_INTERNAL_HTTPS", False)
    allow_self_signed = _parse_bool("MCP_ALLOW_SELF_SIGNED_INTERNAL_HTTPS", False)
    if allow_self_signed and not internal_https:
        raise ConfigError("MCP_ALLOW_SELF_SIGNED_INTERNAL_HTTPS requires MCP_INTERNAL_HTTPS=true")
    tls_cert_file = os.getenv("MCP_TLS_CERT_FILE")
    tls_key_file = os.getenv("MCP_TLS_KEY_FILE")
    if internal_https and (not tls_cert_file or not tls_key_file):
        raise ConfigError("MCP_INTERNAL_HTTPS requires MCP_TLS_CERT_FILE and MCP_TLS_KEY_FILE")
    return ServerConfig(
        host=os.getenv("MCP_HOST", "0.0.0.0"),
        port=port,
        trust_proxy_headers=_parse_bool("MCP_TRUST_PROXY_HEADERS", False),
        allowed_proxy_cidrs=_parse_proxy_cidrs(),
        internal_https=internal_https,
        allow_self_signed_internal_https=allow_self_signed,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
    )


def load_config() -> AppConfig:
    imap = EndpointConfig(_require("IMAP_HOST"), _parse_port("IMAP_PORT"), _parse_mode("IMAP_MODE"))
    smtp = EndpointConfig(_require("SMTP_HOST"), _parse_port("SMTP_PORT"), _parse_mode("SMTP_MODE"))
    app_data_dir = os.getenv("APP_DATA_DIR", "/var/lib/imap-smtp-mcp")

    imap_tls_verify = _parse_bool("IMAP_TLS_VERIFY", True)
    if not imap_tls_verify:
        raise ConfigError("IMAP_TLS_VERIFY must be true")

    imap_max_retries = _parse_int("IMAP_MAX_RETRIES", 2)
    if imap_max_retries < 0:
        raise ConfigError("IMAP_MAX_RETRIES must be >= 0")
    smtp_timeout_seconds = _parse_int("SMTP_TIMEOUT_SECONDS", 30)
    if smtp_timeout_seconds <= 0:
        raise ConfigError("SMTP_TIMEOUT_SECONDS must be > 0")

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
        "create_folder": _parse_bool("ACTION_CREATE_FOLDER", True),
        "rename_folder": _parse_bool("ACTION_RENAME_FOLDER", True),
        "delete_folder": _parse_bool("ACTION_DELETE_FOLDER", True),
    }

    return AppConfig(
        imap=imap,
        smtp=smtp,
        smtp_from_domain=_parse_optional_domain("SMTP_FROM_DOMAIN"),
        sent_folder=_require("IMAP_SENT_FOLDER"),
        trash_folder=_require("IMAP_TRASH_FOLDER"),
        imap_tls_verify=imap_tls_verify,
        imap_tls_ca_bundle_path=os.getenv("IMAP_TLS_CA_BUNDLE_PATH"),
        imap_max_retries=imap_max_retries,
        smtp_timeout_seconds=smtp_timeout_seconds,
        action_flags=actions,
        audit_log_dir=_require("AUDIT_LOG_DIR"),
        app_data_dir=app_data_dir,
        oauth=_load_oauth_config(app_data_dir),
        server=_load_server_config(),
    )
