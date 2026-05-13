#!/usr/bin/env python3
"""Manual compatibility suite for the IMAP/SMTP MCP OAuth endpoint.

WARNING: This script is destructive and intended only for dedicated test inboxes.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

REQUIRED_CONFIRMATION = "I UNDERSTAND THIS WILL MODIFY MAIL"


@dataclass(frozen=True)
class SuiteConfig:
    server_command: tuple[str, ...]
    host: str
    port: int
    public_base_url: str
    test_email: str
    imap_username: str
    imap_password: str
    smtp_username: str
    smtp_password: str
    inbox_folder: str
    test_folder: str
    trash_folder: str
    poll_attempts: int
    poll_interval_seconds: int
    use_existing_server: bool


@dataclass
class MCPClient:
    base_url: str
    access_token: str

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": f"req-{secrets.token_hex(4)}",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        response = _request_json(
            "POST",
            f"{self.base_url}/sse",
            payload,
            headers={"Authorization": f"Bearer {self.access_token}"},
        )
        if "error" in response:
            raise RuntimeError(f"MCP tool {name} returned error: {response['error']}")
        result = response.get("result", {})
        if isinstance(result, dict) and "structuredContent" in result:
            return result["structuredContent"]
        return result


def _manual_gate() -> None:
    if not sys.stdin.isatty():
        raise RuntimeError("Refusing to run: interactive TTY required (piped input is not accepted).")

    print("=" * 72)
    print("DANGER: THIS WILL CREATE, MOVE, DELETE, AND EXPUNGE EMAILS")
    print("Only run against a dedicated non-production mailbox and email account.")
    print("=" * 72)
    phrase = input(f"Type exact phrase to continue: {REQUIRED_CONFIRMATION}\n> ").strip()
    if phrase != REQUIRED_CONFIRMATION:
        raise RuntimeError("Confirmation phrase did not match exactly. Aborting.")

    for i in (3, 2, 1):
        print(f"Starting in {i}s...")
        time.sleep(1)


def _extract_uids(search_result: Any) -> list[str]:
    if isinstance(search_result, dict):
        for key in ("uids", "ids", "result"):
            if isinstance(search_result.get(key), list):
                return [str(v) for v in search_result[key]]
    if isinstance(search_result, list):
        return [str(v) for v in search_result]
    return []


def _extract_email_address(value: str) -> str:
    _, addr = parseaddr(value)
    return addr or value


def _env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return default if raw is None else int(raw)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def load_suite_config() -> SuiteConfig:
    port = _env_int("MCP_COMPAT_PORT", _free_port())
    base_url = os.getenv("MCP_COMPAT_PUBLIC_BASE_URL", f"http://127.0.0.1:{port}")
    command = tuple(os.getenv("MCP_COMPAT_SERVER_COMMAND", f"{sys.executable} -m imap_smtp_mcp.server").split())
    return SuiteConfig(
        server_command=command,
        host=os.getenv("MCP_COMPAT_HOST", "127.0.0.1"),
        port=port,
        public_base_url=base_url,
        test_email=_env_required("MCP_COMPAT_TEST_EMAIL"),
        imap_username=_env_required("MCP_COMPAT_IMAP_USERNAME"),
        imap_password=_env_required("MCP_COMPAT_IMAP_PASSWORD"),
        smtp_username=_env_required("MCP_COMPAT_SMTP_USERNAME"),
        smtp_password=_env_required("MCP_COMPAT_SMTP_PASSWORD"),
        inbox_folder=os.getenv("MCP_COMPAT_INBOX_FOLDER", "INBOX"),
        test_folder=_env_required("MCP_COMPAT_TEST_FOLDER"),
        trash_folder=_env_required("MCP_COMPAT_TRASH_FOLDER"),
        poll_attempts=_env_int("MCP_COMPAT_POLL_ATTEMPTS", 10),
        poll_interval_seconds=_env_int("MCP_COMPAT_POLL_INTERVAL_SECONDS", 3),
        use_existing_server=os.getenv("MCP_COMPAT_USE_EXISTING_SERVER", "").lower() in {"1", "true", "yes", "on"},
    )


def _server_env(config: SuiteConfig, audit_dir: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "MCP_HOST": config.host,
            "MCP_PORT": str(config.port),
            "MCP_PUBLIC_BASE_URL": config.public_base_url,
            "MCP_ALLOW_INSECURE_PUBLIC_URL": "true",
            "OAUTH_ISSUER": config.public_base_url,
            "OAUTH_AUDIENCE": config.public_base_url,
            "OAUTH_SIGNING_KEY": os.getenv("OAUTH_SIGNING_KEY", secrets.token_urlsafe(32)),
            "OAUTH_COOKIE_SECRET": os.getenv("OAUTH_COOKIE_SECRET", secrets.token_urlsafe(32)),
            "OAUTH_ENCRYPTION_KEY": os.getenv("OAUTH_ENCRYPTION_KEY", _fernet_key()),
            "APP_DATA_DIR": os.path.join(audit_dir, "data"),
            "OAUTH_STORE_PATH": os.path.join(audit_dir, "data", "oauth.sqlite3"),
            "IMAP_SENT_FOLDER": os.getenv("IMAP_SENT_FOLDER", "Sent"),
            "IMAP_TRASH_FOLDER": config.trash_folder,
            "AUDIT_LOG_DIR": audit_dir,
        }
    )
    return env


def _fernet_key() -> str:
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _wait_ready(base_url: str, proc: subprocess.Popen[str]) -> None:
    deadline = time.time() + 20
    last_error: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"MCP server exited early with status {proc.returncode}")
        try:
            ready = _request_json("GET", f"{base_url}/readyz", None)
            if ready.get("ready") is True:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"MCP server did not become ready: {last_error}")


def _request_json(method: str, url: str, payload: dict[str, Any] | None, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    parsed = urlparse(url)
    conn = _http_connection(parsed)
    body = None if payload is None else json.dumps(payload)
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    conn.request(method, parsed.path or "/", body=body, headers=request_headers)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    conn.close()
    if resp.status >= 400:
        raise RuntimeError(f"{method} {url} failed with HTTP {resp.status}: {raw}")
    return json.loads(raw or "{}")


def _request_form(method: str, url: str, form: dict[str, str]) -> tuple[int, dict[str, str], str]:
    parsed = urlparse(url)
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    conn = _http_connection(parsed)
    conn.request(method, path, body=urlencode(form), headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    headers = {key.lower(): value for key, value in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, headers, raw


def _http_connection(parsed):
    conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return conn_cls(parsed.hostname, port, timeout=20)


def _oauth_token(config: SuiteConfig) -> str:
    client = _request_json(
        "POST",
        f"{config.public_base_url}/oauth/register",
        {"redirect_uris": ["https://chatgpt.com/connector/oauth/manual-compat"], "client_name": "Manual MCP Compatibility Suite"},
    )
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client["client_id"],
            "redirect_uri": "https://chatgpt.com/connector/oauth/manual-compat",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mail:read mail:send mail:write",
            "resource": config.public_base_url,
            "state": "manual",
        }
    )
    status, headers, body = _request_form(
        "POST",
        f"{config.public_base_url}/oauth/authorize?{query}",
        {
            "imap_username": config.imap_username,
            "imap_password": config.imap_password,
            "smtp_username": config.smtp_username,
            "smtp_password": config.smtp_password,
        },
    )
    if status != 302:
        raise RuntimeError(f"OAuth authorization failed with HTTP {status}: {body}")
    code = parse_qs(urlparse(headers["location"]).query)["code"][0]
    token = _request_form(
        "POST",
        f"{config.public_base_url}/oauth/token",
        {
            "grant_type": "authorization_code",
            "client_id": str(client["client_id"]),
            "redirect_uri": "https://chatgpt.com/connector/oauth/manual-compat",
            "code": code,
            "code_verifier": verifier,
        },
    )
    if token[0] != 200:
        raise RuntimeError(f"OAuth token exchange failed with HTTP {token[0]}: {token[2]}")
    return str(json.loads(token[2])["access_token"])


def run_suite() -> None:
    _manual_gate()
    config = load_suite_config()
    if config.use_existing_server:
        _request_json("GET", f"{config.public_base_url}/readyz", None)
        token = _oauth_token(config)
        _run_mail_flow(MCPClient(config.public_base_url, token), config)
        return
    with tempfile.TemporaryDirectory(prefix="imap-smtp-mcp-audit-") as audit_dir:
        proc = subprocess.Popen(
            config.server_command,
            env=_server_env(config, audit_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_ready(config.public_base_url, proc)
            token = _oauth_token(config)
            client = MCPClient(config.public_base_url, token)
            _run_mail_flow(client, config)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _run_mail_flow(client: MCPClient, args: SuiteConfig) -> None:
    marker = f"mcp-compat-{int(time.time())}-{secrets.token_hex(3)}"
    print("[1/12] list_folders")
    print(f"  folders response: {client.call_tool('list_folders', {})}")

    print("[2/12] send_email (self-addressed)")
    body = f"manual compatibility test marker: {marker}"
    client.call_tool("send_email", {"from_address": args.test_email, "to_addresses": [args.test_email], "subject": f"MCP compatibility {marker}", "body_text": body})

    print("[3/12] search_emails")
    found_uid = None
    for _ in range(args.poll_attempts):
        uids = _extract_uids(client.call_tool("search_emails", {"folder": args.inbox_folder, "query": marker, "limit": 10}))
        if uids:
            found_uid = uids[-1]
            break
        time.sleep(args.poll_interval_seconds)
    if not found_uid:
        raise RuntimeError("Sent message was not discovered in inbox during polling window.")

    print("[4/12] list_emails")
    listed = client.call_tool("list_emails", {"folder": args.inbox_folder, "offset": 0, "limit": 50})
    print(f"  listed response length: {len(listed) if isinstance(listed, list) else 'n/a'}")

    print("[5/12] read_email")
    read_result = client.call_tool("read_email", {"folder": args.inbox_folder, "uid": found_uid, "max_chars": 50000})
    if marker not in json.dumps(read_result):
        raise RuntimeError("Read-email payload did not contain expected marker text.")
    sender = _extract_email_address(str(read_result.get("from_address", ""))) if isinstance(read_result, dict) else ""
    if sender and sender.lower() != args.test_email.lower():
        raise RuntimeError(f"Unexpected sender address: {sender} != {args.test_email}")

    print("[6/12] copy_email")
    client.call_tool("copy_email", {"source_folder": args.inbox_folder, "target_folder": args.test_folder, "uid": found_uid})
    print("[7/12] move_email")
    client.call_tool("move_email", {"source_folder": args.inbox_folder, "target_folder": args.test_folder, "uid": found_uid})

    print("[8/12] search copied/moved in test folder")
    moved_uids = _extract_uids(client.call_tool("search_emails", {"folder": args.test_folder, "query": marker, "limit": 20}))
    if not moved_uids:
        raise RuntimeError("Could not find message in target test folder after move/copy.")
    test_uid = moved_uids[-1]

    print("[9/12] mark_read_state true/false")
    client.call_tool("mark_read_state", {"folder": args.test_folder, "uid": test_uid, "is_read": True})
    client.call_tool("mark_read_state", {"folder": args.test_folder, "uid": test_uid, "is_read": False})
    print("[10/12] move_to_trash")
    client.call_tool("move_to_trash", {"source_folder": args.test_folder, "uid": test_uid})
    print("[11/12] delete_email_permanent")
    trash_uids = _extract_uids(client.call_tool("search_emails", {"folder": args.trash_folder, "query": marker, "limit": 20}))
    if trash_uids:
        client.call_tool("delete_email_permanent", {"folder": args.trash_folder, "uid": trash_uids[-1]})
    print("[12/12] empty_trash")
    client.call_tool("empty_trash", {})
    print("SUCCESS: Manual MCP compatibility suite completed.")


if __name__ == "__main__":
    run_suite()
