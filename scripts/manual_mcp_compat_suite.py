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
import re
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
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT, "src")
SECRET_ENV_MARKERS = ("PASSWORD", "SECRET", "TOKEN", "KEY")


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
    sender_display_name: str
    sender_email: str
    inbox_folder: str
    trash_folder: str
    poll_attempts: int
    poll_interval_seconds: int
    http_timeout_seconds: int
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


def _require_folders(folders: Any, required: tuple[str, ...]) -> None:
    if isinstance(folders, dict) and isinstance(folders.get("folders"), list):
        folders = folders["folders"]
    available = set(str(folder) for folder in folders) if isinstance(folders, list) else set()
    missing = [folder for folder in required if folder not in available]
    if missing:
        raise RuntimeError(f"Required folders missing from mailbox: {', '.join(missing)}")


def _temporary_folders(marker: str) -> tuple[str, str]:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", marker)
    created = f"MCP_COMPAT_TEST_{safe}"
    return created, f"{created}_RENAMED"


def _safe_delete_folder(client: MCPClient, folder: str) -> None:
    try:
        client.call_tool("delete_folder", {"folder": folder})
    except RuntimeError as exc:
        print(f"  cleanup warning: could not delete temporary folder {folder}: {exc}")


def _find_marker_uid(client: MCPClient, folder: str, marker: str, args: SuiteConfig, *, step: str, limit: int = 20) -> str:
    for _ in range(args.poll_attempts):
        uids = _extract_uids(client.call_tool("search_emails", {"folder": folder, "query": marker, "limit": limit}))
        if uids:
            return uids[-1]
        time.sleep(args.poll_interval_seconds)
    raise RuntimeError(f"Could not find marker UID for {step} in folder {folder}: {marker}")


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
        sender_display_name=os.getenv("MCP_COMPAT_SENDER_DISPLAY_NAME", "MCP Compatibility Test"),
        sender_email=os.getenv("MCP_COMPAT_SENDER_EMAIL", _env_required("MCP_COMPAT_TEST_EMAIL")),
        inbox_folder=os.getenv("MCP_COMPAT_INBOX_FOLDER", "INBOX"),
        trash_folder=_env_required("MCP_COMPAT_TRASH_FOLDER"),
        poll_attempts=_env_int("MCP_COMPAT_POLL_ATTEMPTS", 10),
        poll_interval_seconds=_env_int("MCP_COMPAT_POLL_INTERVAL_SECONDS", 3),
        http_timeout_seconds=_env_int("MCP_COMPAT_HTTP_TIMEOUT_SECONDS", 120),
        use_existing_server=os.getenv("MCP_COMPAT_USE_EXISTING_SERVER", "").lower() in {"1", "true", "yes", "on"},
    )


def _server_env(config: SuiteConfig, audit_dir: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": _pythonpath(env),
            "MCP_HOST": config.host,
            "MCP_PORT": str(config.port),
            "MCP_PUBLIC_BASE_URL": config.public_base_url,
            "MCP_ALLOW_INSECURE_PUBLIC_URL": "true",
            "OAUTH_ISSUER": config.public_base_url,
            "OAUTH_AUDIENCE": config.public_base_url,
            "OAUTH_ALLOWED_REDIRECT_URI_PATTERNS": os.getenv("OAUTH_ALLOWED_REDIRECT_URI_PATTERNS", r"https://chatgpt\.com/connector/oauth/manual-compat"),
            "OAUTH_SIGNING_KEY": os.getenv("OAUTH_SIGNING_KEY", secrets.token_urlsafe(32)),
            "OAUTH_COOKIE_SECRET": os.getenv("OAUTH_COOKIE_SECRET", secrets.token_urlsafe(32)),
            "OAUTH_ENCRYPTION_KEY": os.getenv("OAUTH_ENCRYPTION_KEY", _fernet_key()),
            "APP_DATA_DIR": os.path.join(audit_dir, "data"),
            "OAUTH_STORE_PATH": os.path.join(audit_dir, "data", "oauth.sqlite3"),
            "IMAP_SENT_FOLDER": os.getenv("IMAP_SENT_FOLDER", "Sent"),
            "IMAP_TRASH_FOLDER": config.trash_folder,
            "AUDIT_LOG_DIR": audit_dir,
            "ACTION_LIST_FOLDERS": "true",
            "ACTION_SEARCH_EMAILS": "true",
            "ACTION_LIST_EMAILS": "true",
            "ACTION_READ_EMAIL": "true",
            "ACTION_SEND_EMAIL": "true",
            "ACTION_MARK_READ_STATE": "true",
            "ACTION_MOVE_EMAIL": "true",
            "ACTION_COPY_EMAIL": "true",
            "ACTION_DELETE_EMAIL_PERMANENT": "true",
            "ACTION_MOVE_TO_TRASH": "true",
            "ACTION_EMPTY_TRASH": "true",
            "ACTION_CREATE_FOLDER": "true",
            "ACTION_RENAME_FOLDER": "true",
            "ACTION_DELETE_FOLDER": "true",
        }
    )
    return env


def _pythonpath(env: dict[str, str]) -> str:
    existing = env.get("PYTHONPATH")
    if existing:
        return os.pathsep.join((SRC_DIR, existing))
    return SRC_DIR


def _fernet_key() -> str:
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _wait_ready(base_url: str, proc: subprocess.Popen[str], redaction_values: tuple[str, ...] = ()) -> None:
    deadline = time.time() + 20
    last_error: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            output = _process_output_tail(proc, redaction_values)
            details = f"\n{output}" if output else ""
            raise RuntimeError(f"MCP server exited early with status {proc.returncode}{details}")
        try:
            ready = _request_json("GET", f"{base_url}/readyz", None)
            if ready.get("ready") is True:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"MCP server did not become ready: {last_error}")


def _process_output_tail(proc: subprocess.Popen[str], redaction_values: tuple[str, ...]) -> str:
    try:
        stdout, stderr = proc.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        return "server output unavailable: process did not finish flushing stdout/stderr"
    lines: list[str] = []
    if stdout:
        lines.append("server stdout:")
        lines.extend(stdout.strip().splitlines()[-20:])
    if stderr:
        lines.append("server stderr:")
        lines.extend(stderr.strip().splitlines()[-20:])
    return _redact("\n".join(lines), redaction_values)[-4000:]


def _redaction_values(env: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        value
        for key, value in env.items()
        if value and len(value) >= 4 and any(marker in key.upper() for marker in SECRET_ENV_MARKERS)
    )


def _redact(value: str, secrets_to_redact: tuple[str, ...]) -> str:
    redacted = value
    for secret in sorted(set(secrets_to_redact), key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def _request_json(method: str, url: str, payload: dict[str, Any] | None, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload)
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    status, _, raw = _request_raw(method, url, body, headers=request_headers)
    if status >= 400:
        raise RuntimeError(f"{method} {url} failed with HTTP {status}: {raw}")
    return json.loads(raw or "{}")


def _request_form(method: str, url: str, form: dict[str, str], *, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
    request_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        request_headers.update(headers)
    return _request_raw(method, url, urlencode(form), headers=request_headers)


def _request_raw(method: str, url: str, body: str | None, *, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
    parsed = urlparse(url)
    conn = _http_connection(parsed)
    conn.request(method, _path_with_query(parsed), body=body, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    headers = {key.lower(): value for key, value in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, headers, raw


def _path_with_query(parsed) -> str:
    path = parsed.path or "/"
    return path + (f"?{parsed.query}" if parsed.query else "")


def _http_connection(parsed):
    conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return conn_cls(parsed.hostname, port, timeout=_http_timeout_seconds())


def _http_timeout_seconds() -> int:
    return _env_int("MCP_COMPAT_HTTP_TIMEOUT_SECONDS", 120)


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
    authorize_url = f"{config.public_base_url}/oauth/authorize?{query}"
    status, headers, body = _request_raw("GET", authorize_url, None)
    if status != 200:
        raise RuntimeError(f"OAuth authorize form failed with HTTP {status}: {body}")
    csrf_cookie = _authorize_csrf_cookie(headers)
    csrf_token = _csrf_token_from_html(body)
    status, headers, body = _request_form(
        "POST",
        authorize_url,
        {
            "imap_username": config.imap_username,
            "imap_password": config.imap_password,
            "smtp_username": config.smtp_username,
            "smtp_password": config.smtp_password,
            "sender_display_name": config.sender_display_name,
            "sender_email": config.sender_email,
            "csrf_token": csrf_token,
        },
        headers={"Cookie": csrf_cookie},
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


def _authorize_csrf_cookie(headers: dict[str, str]) -> str:
    raw_cookie = headers.get("set-cookie", "")
    match = re.search(r"(oauth_authorize_csrf=[^;]+)", raw_cookie)
    if not match:
        raise RuntimeError("OAuth authorize form did not return CSRF cookie")
    return match.group(1)


def _csrf_token_from_html(body: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', body)
    if not match:
        raise RuntimeError("OAuth authorize form did not include CSRF token")
    return match.group(1)


def run_suite() -> None:
    _manual_gate()
    config = load_suite_config()
    if config.use_existing_server:
        _request_json("GET", f"{config.public_base_url}/readyz", None)
        token = _oauth_token(config)
        _run_mail_flow(MCPClient(config.public_base_url, token), config)
        return
    with tempfile.TemporaryDirectory(prefix="imap-smtp-mcp-audit-") as audit_dir:
        env = _server_env(config, audit_dir)
        proc = subprocess.Popen(
            config.server_command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_ready(config.public_base_url, proc, _redaction_values(env))
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
    created_folder, test_folder = _temporary_folders(marker)
    cleanup_folder: str | None = None
    print("[1/15] list_folders")
    folders = client.call_tool("list_folders", {})
    print(f"  folders response: {folders}")
    _require_folders(folders, (args.inbox_folder, args.trash_folder))

    try:
        print("[2/15] create_folder")
        client.call_tool("create_folder", {"folder": created_folder})
        cleanup_folder = created_folder
        print("[3/15] rename_folder")
        client.call_tool("rename_folder", {"source_folder": created_folder, "target_folder": test_folder})
        cleanup_folder = test_folder

        print("[4/15] send_email (self-addressed)")
        body = f"manual compatibility test marker: {marker}"
        client.call_tool("send_email", {"to_addresses": [args.test_email], "subject": f"MCP compatibility {marker}", "body_text": body})

        print("[5/15] search_emails")
        found_uid = _find_marker_uid(client, args.inbox_folder, marker, args, step="initial inbox search", limit=10)

        print("[6/15] list_emails")
        listed = client.call_tool("list_emails", {"folder": args.inbox_folder, "offset": 0, "limit": 50})
        listed_items = listed.get("emails", []) if isinstance(listed, dict) else listed
        print(f"  listed response length: {len(listed_items) if isinstance(listed_items, list) else 'n/a'}")

        print("[7/15] read_email")
        read_result = client.call_tool("read_email", {"folder": args.inbox_folder, "uid": found_uid, "max_chars": 50000})
        if marker not in json.dumps(read_result):
            raise RuntimeError("Read-email payload did not contain expected marker text.")
        sender = _extract_email_address(str(read_result.get("from_address", ""))) if isinstance(read_result, dict) else ""
        if sender and sender.lower() != args.sender_email.lower():
            raise RuntimeError(f"Unexpected sender address: {sender} != {args.sender_email}")

        print("[8/15] copy_email")
        copy_uid = _find_marker_uid(client, args.inbox_folder, marker, args, step="copy_email", limit=10)
        client.call_tool("copy_email", {"source_folder": args.inbox_folder, "target_folder": test_folder, "uid": copy_uid})
        print("[9/15] move_email")
        move_uid = _find_marker_uid(client, args.inbox_folder, marker, args, step="move_email", limit=10)
        client.call_tool("move_email", {"source_folder": args.inbox_folder, "target_folder": test_folder, "uid": move_uid})

        print("[10/15] search copied/moved in test folder")
        moved_uids = _extract_uids(client.call_tool("search_emails", {"folder": test_folder, "query": marker, "limit": 20}))
        if not moved_uids:
            raise RuntimeError("Could not find message in target test folder after move/copy.")
        test_uid = moved_uids[-1]

        print("[11/15] mark_read_state true/false")
        client.call_tool("mark_read_state", {"folder": test_folder, "uid": test_uid, "is_read": True})
        client.call_tool("mark_read_state", {"folder": test_folder, "uid": test_uid, "is_read": False})
        print("[12/15] move_to_trash")
        for uid in moved_uids:
            client.call_tool("move_to_trash", {"source_folder": test_folder, "uid": uid})
        print("[13/15] delete_email_permanent")
        trash_uids = _extract_uids(client.call_tool("search_emails", {"folder": args.trash_folder, "query": marker, "limit": 20}))
        for uid in trash_uids:
            client.call_tool("delete_email_permanent", {"folder": args.trash_folder, "uid": uid})
        print("[14/15] empty_trash")
        client.call_tool("empty_trash", {})
        print("[15/15] delete_folder")
        client.call_tool("delete_folder", {"folder": test_folder})
        cleanup_folder = None
        print("SUCCESS: Manual MCP compatibility suite completed.")
    finally:
        if cleanup_folder:
            _safe_delete_folder(client, cleanup_folder)


if __name__ == "__main__":
    run_suite()
