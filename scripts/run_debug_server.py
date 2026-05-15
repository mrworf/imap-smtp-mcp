#!/usr/bin/env python3
"""Run the IMAP/SMTP MCP server directly from a shell for debugging.

This helper is intentionally not a production launcher.
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


SECRET_KEYS = {"OAUTH_SIGNING_KEY", "OAUTH_COOKIE_SECRET", "OAUTH_ENCRYPTION_KEY"}
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
REQUIRED_MAIL_ENV = (
    "IMAP_HOST",
    "IMAP_PORT",
    "IMAP_MODE",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_MODE",
    "IMAP_SENT_FOLDER",
    "IMAP_TRASH_FOLDER",
)


@dataclass(frozen=True)
class DebugConfig:
    mode: str
    host: str
    port: int
    public_base_url: str
    runtime_dir: Path
    server_command: tuple[str, ...]
    print_env: bool
    cert_file: Path | None
    key_file: Path | None


def parse_args(argv: Sequence[str] | None = None) -> DebugConfig:
    parser = argparse.ArgumentParser(description="Run the IMAP/SMTP MCP server locally for debugging.")
    parser.add_argument("--mode", choices=("reverse-proxy", "https"), default="reverse-proxy")
    parser.add_argument("--host", default=os.getenv("MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_PORT", "8000")))
    parser.add_argument("--public-base-url")
    parser.add_argument("--runtime-dir", type=Path, default=Path(".tmp/debug"))
    parser.add_argument("--server-command", default=f"{sys.executable} -m imap_smtp_mcp.server")
    parser.add_argument("--cert-file", type=Path)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--print-env", action="store_true")
    args = parser.parse_args(argv)

    public_base_url = args.public_base_url or _default_public_base_url(args.mode, args.host, args.port)
    return DebugConfig(
        mode=args.mode,
        host=args.host,
        port=args.port,
        public_base_url=public_base_url.rstrip("/"),
        runtime_dir=args.runtime_dir,
        server_command=tuple(args.server_command.split()),
        print_env=bool(args.print_env),
        cert_file=args.cert_file,
        key_file=args.key_file,
    )


def build_env(config: DebugConfig, base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    _require_mail_env(env)
    data_dir = config.runtime_dir / "data"
    audit_dir = config.runtime_dir / "audit"
    tls_dir = config.runtime_dir / "tls"
    for path in (data_dir, audit_dir, tls_dir):
        path.mkdir(parents=True, exist_ok=True)

    env.update(
        {
            "PYTHONPATH": _pythonpath(env),
            "MCP_HOST": config.host,
            "MCP_PORT": str(config.port),
            "MCP_PUBLIC_BASE_URL": config.public_base_url,
            "MCP_ALLOW_INSECURE_PUBLIC_URL": "true",
            "OAUTH_DEV_INSECURE_SECRETS": env.get("OAUTH_DEV_INSECURE_SECRETS", "true"),
            "OAUTH_ISSUER": config.public_base_url,
            "OAUTH_AUDIENCE": config.public_base_url,
            "APP_DATA_DIR": str(data_dir),
            "AUDIT_LOG_DIR": str(audit_dir),
            "OAUTH_STORE_PATH": str(data_dir / "oauth.sqlite3"),
            "OAUTH_SIGNING_KEY": env.get("OAUTH_SIGNING_KEY") or _debug_secret(),
            "OAUTH_COOKIE_SECRET": env.get("OAUTH_COOKIE_SECRET") or _debug_secret(),
            "OAUTH_ENCRYPTION_KEY": env.get("OAUTH_ENCRYPTION_KEY") or _fernet_key(),
        }
    )
    if config.mode == "https":
        cert_file, key_file = _resolve_tls_files(config, tls_dir)
        env.update(
            {
                "MCP_INTERNAL_HTTPS": "true",
                "MCP_ALLOW_SELF_SIGNED_INTERNAL_HTTPS": "true",
                "MCP_TLS_CERT_FILE": str(cert_file),
                "MCP_TLS_KEY_FILE": str(key_file),
            }
        )
    else:
        env.update({"MCP_INTERNAL_HTTPS": "false", "MCP_TLS_CERT_FILE": "", "MCP_TLS_KEY_FILE": ""})
    return env


def render_env(env: dict[str, str]) -> str:
    lines: list[str] = []
    for key in sorted(k for k in env if _is_debug_key(k)):
        value = "[REDACTED]" if key in SECRET_KEYS else env[key]
        lines.append(f"{key}={value}")
    return "\n".join(lines)


def warning_for_host(host: str) -> str | None:
    if host in {"127.0.0.1", "localhost", "::1"}:
        return None
    return "WARNING: debug server is bound to a non-loopback host; restrict access with a firewall."


def main(argv: Sequence[str] | None = None) -> int:
    config = parse_args(argv)
    try:
        env = build_env(config)
    except RuntimeError as exc:
        print(f"debug server setup failed: {exc}", file=sys.stderr)
        return 2
    warning = warning_for_host(config.host)
    if warning:
        print(warning, file=sys.stderr)
    print(render_env(env))
    if config.print_env:
        return 0
    print("Starting:", " ".join(config.server_command), file=sys.stderr)
    return subprocess.call(config.server_command, env=env)


def _default_public_base_url(mode: str, host: str, port: int) -> str:
    scheme = "https" if mode == "https" else "http"
    display_host = "127.0.0.1" if host == "0.0.0.0" else host
    return f"{scheme}://{display_host}:{port}"


def _debug_secret() -> str:
    return f"debug-{secrets.token_urlsafe(32)}"


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _require_mail_env(env: dict[str, str]) -> None:
    missing = [name for name in REQUIRED_MAIL_ENV if not env.get(name)]
    if missing:
        raise RuntimeError(f"missing required mail environment variables: {', '.join(missing)}")


def _resolve_tls_files(config: DebugConfig, tls_dir: Path) -> tuple[Path, Path]:
    cert_file = config.cert_file or tls_dir / "debug-mcp.crt"
    key_file = config.key_file or tls_dir / "debug-mcp.key"
    if cert_file.exists() and key_file.exists():
        return cert_file, key_file
    if config.cert_file or config.key_file:
        raise RuntimeError("HTTPS mode requires both --cert-file and --key-file to exist")
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("HTTPS mode requires existing cert/key files or openssl to generate a debug self-signed certificate")
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_file),
            "-out",
            str(cert_file),
            "-days",
            "7",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert_file, key_file


def _pythonpath(env: dict[str, str]) -> str:
    existing = env.get("PYTHONPATH")
    if existing:
        return f"{SRC_DIR}{os.pathsep}{existing}"
    return str(SRC_DIR)


def _is_debug_key(key: str) -> bool:
    return key.startswith(("MCP_", "OAUTH_", "APP_DATA_DIR", "AUDIT_LOG_DIR", "IMAP_", "SMTP_"))


if __name__ == "__main__":
    raise SystemExit(main())
