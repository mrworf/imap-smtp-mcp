from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import threading
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from imap_smtp_mcp.config import load_config
from imap_smtp_mcp.oauth import CredentialVault, OAuthService
from imap_smtp_mcp.server import AUTHORIZE_CSRF_COOKIE, MAX_FORM_BODY_BYTES, MAX_JSON_BODY_BYTES, MCPHTTPServer, MCPRequestHandler, StartupError, build_server
from imap_smtp_mcp.tool_controller import TOOL_SCHEMAS


class FakeController:
    def list_tools(self):
        return [{"name": name, "inputSchema": schema} for name, schema in TOOL_SCHEMAS.items()]

    def call_tool(self, name, arguments, credentials, *, request_id, subject):
        return {"tool": name, "imap_username": credentials.imap_username, "smtp_username": credentials.smtp_username}


@pytest.fixture
def server_env(monkeypatch, tmp_path):
    env = {
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_MODE": "starttls",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "AUDIT_LOG_DIR": str(tmp_path),
        "APP_DATA_DIR": str(tmp_path / "data"),
        "OAUTH_STORE_PATH": str(tmp_path / "data" / "oauth.sqlite3"),
        "MCP_PUBLIC_BASE_URL": "http://127.0.0.1:8000",
        "MCP_ALLOW_INSECURE_PUBLIC_URL": "true",
        "OAUTH_ISSUER": "http://127.0.0.1:8000",
        "OAUTH_AUDIENCE": "http://127.0.0.1:8000",
        "OAUTH_SIGNING_KEY": "test-signing-key-0123456789abcdef",
        "OAUTH_COOKIE_SECRET": "test-cookie-secret-0123456789abcdef",
        "OAUTH_ENCRYPTION_KEY": CredentialVault.generate_key(),
        "OAUTH_ALLOWED_REDIRECT_URI_PATTERNS": r"https://chatgpt\.com/connector/oauth/cb",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def http_server(server_env):
    config = load_config()
    oauth = OAuthService(config, imap_verifier=lambda username, password: None)
    server = MCPHTTPServer(("127.0.0.1", 0), MCPRequestHandler, config=config, oauth_service=oauth, tool_controller=FakeController())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    yield base_url, server
    server.shutdown()
    thread.join(timeout=5)


def _request(method: str, url: str, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
    parsed = urlparse(url)
    body = None if payload is None else json.dumps(payload)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    conn.request(method, parsed.path + (f"?{parsed.query}" if parsed.query else ""), body=body, headers={"Content-Type": "application/json", **(headers or {})})
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    response_headers = {key.lower(): value for key, value in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, response_headers, raw


def _form(method: str, url: str, form: dict[str, str], headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
    parsed = urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    conn.request(method, parsed.path + (f"?{parsed.query}" if parsed.query else ""), body=urlencode(form), headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    headers = {key.lower(): value for key, value in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, headers, raw


def _raw(method: str, url: str, body: str, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
    parsed = urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    conn.putrequest(method, parsed.path + (f"?{parsed.query}" if parsed.query else ""))
    for key, value in headers.items():
        conn.putheader(key, value)
    conn.endheaders()
    if body:
        conn.send(body.encode("utf-8"))
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    response_headers = {key.lower(): value for key, value in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, response_headers, raw


def _csrf_token_from_html(value: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', value)
    assert match is not None
    return match.group(1)


def _authorize_query(client_id: str, *, scope: str = "mail:read mail:send mail:write") -> str:
    verifier = "verifier"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": scope,
            "resource": "http://127.0.0.1:8000",
        }
    )


def _token(base_url: str) -> str:
    status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    assert status == 201
    client_id = json.loads(raw)["client_id"]
    verifier = "verifier"
    query = _authorize_query(client_id)
    status, get_headers, html = _request("GET", f"{base_url}/oauth/authorize?{query}")
    assert status == 200
    csrf_token = _csrf_token_from_html(html)
    csrf_cookie = get_headers["set-cookie"].split(";", 1)[0]
    status, headers, _ = _form(
        "POST",
        f"{base_url}/oauth/authorize?{query}",
        {
            "imap_username": "imap-user",
            "imap_password": "imap-pass",
            "smtp_username": "smtp-user",
            "smtp_password": "smtp-pass",
            "sender_display_name": "Test Sender",
            "sender_email": "sender@example.com",
            "csrf_token": csrf_token,
        },
        headers={"Cookie": csrf_cookie},
    )
    assert status == 302
    code = parse_qs(urlparse(headers["location"]).query)["code"][0]
    status, _, raw = _form(
        "POST",
        f"{base_url}/oauth/token",
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
            "code": code,
            "code_verifier": verifier,
        },
    )
    assert status == 200
    return json.loads(raw)["access_token"]


def test_health_ready_and_metadata(http_server):
    base_url, _ = http_server
    assert _request("GET", f"{base_url}/healthz")[0] == 200
    status, _, raw = _request("GET", f"{base_url}/.well-known/oauth-protected-resource")
    assert status == 200
    assert json.loads(raw)["resource"] == "http://127.0.0.1:8000"


def test_authorize_get_sets_csrf_cookie_and_hidden_field(http_server):
    base_url, _ = http_server
    status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    client_id = json.loads(raw)["client_id"]
    status, headers, html = _request("GET", f"{base_url}/oauth/authorize?{_authorize_query(client_id)}")

    assert status == 200
    assert f"{AUTHORIZE_CSRF_COOKIE}=" in headers["set-cookie"]
    assert "HttpOnly" in headers["set-cookie"]
    assert "SameSite=Lax" in headers["set-cookie"]
    assert "Secure" not in headers["set-cookie"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert _csrf_token_from_html(html)
    assert 'name="sender_display_name"' in html
    assert 'name="sender_email"' in html


def test_authorize_form_identifies_app_and_groups_credentials(http_server):
    base_url, _ = http_server
    status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"], "client_name": "<ChatGPT Connector>"})
    client_id = json.loads(raw)["client_id"]
    status, _, html = _request("GET", f"{base_url}/oauth/authorize?{_authorize_query(client_id)}")

    assert status == 200
    assert "<h1" in html
    assert "Authorize IMAP/SMTP MCP" in html
    assert "lets authorized MCP clients use your configured IMAP and SMTP account" in html
    assert 'href="https://github.com/mrworf/imap-smtp-mcp"' in html
    assert 'target="_blank" rel="noopener noreferrer"' in html
    assert "&lt;ChatGPT Connector&gt;" in html
    assert client_id in html
    assert "https://chatgpt.com" in html
    assert "https://chatgpt.com/connector/oauth/cb" in html
    assert "http://127.0.0.1:8000" in html
    assert "mail:read, mail:send, mail:write" in html
    assert "ChatGPT is requesting" not in html
    assert "<legend>IMAP credentials</legend>" in html
    assert "<legend>SMTP credentials</legend>" in html
    assert "<legend>Sender identity</legend>" in html
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in html
    assert 'input id="imap_username" name="imap_username"' in html
    assert 'input id="imap_password" name="imap_password" type="password"' in html
    assert 'input id="smtp_username" name="smtp_username"' in html
    assert 'input id="smtp_password" name="smtp_password" type="password"' in html
    assert "https://cdn" not in html
    assert "bootstrap" not in html.lower()
    assert "tailwind" not in html.lower()


def test_authorize_get_sets_secure_cookie_for_https_public_url(server_env, monkeypatch):
    monkeypatch.setenv("MCP_PUBLIC_BASE_URL", "https://mcp.example.com")
    monkeypatch.setenv("OAUTH_ISSUER", "https://mcp.example.com")
    monkeypatch.setenv("OAUTH_AUDIENCE", "https://mcp.example.com")
    config = load_config()
    oauth = OAuthService(config, imap_verifier=lambda *_: None)
    server = MCPHTTPServer(("127.0.0.1", 0), MCPRequestHandler, config=config, oauth_service=oauth, tool_controller=FakeController())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    try:
        status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
        client_id = json.loads(raw)["client_id"]
        query = _authorize_query(client_id).replace("http%3A%2F%2F127.0.0.1%3A8000", "https%3A%2F%2Fmcp.example.com")
        status, headers, _ = _request("GET", f"{base_url}/oauth/authorize?{query}")
        assert status == 200
        assert "Secure" in headers["set-cookie"]
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_authorize_form_suggests_sender_email_from_smtp_domain(server_env, monkeypatch):
    monkeypatch.setenv("SMTP_FROM_DOMAIN", "example.com")
    monkeypatch.setenv("MCP_DEBUG_UNREDACTED_LOGS", "true")
    config = load_config()
    oauth = OAuthService(config, imap_verifier=lambda *_: None)
    server = MCPHTTPServer(("127.0.0.1", 0), MCPRequestHandler, config=config, oauth_service=oauth, tool_controller=FakeController())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    try:
        status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
        client_id = json.loads(raw)["client_id"]
        status, _, html = _request("GET", f"{base_url}/oauth/authorize?{_authorize_query(client_id)}")
        assert status == 200
        assert 'const smtpFromDomain = "example.com";' in html
        assert 'username.includes("@")' in html
        assert '${username}@${smtpFromDomain}' in html
        assert "Debug logging is enabled" in html
        assert "Email subjects, bodies, tool arguments, and tool results may be written" in html
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_authorize_post_requires_matching_csrf_cookie(http_server):
    base_url, _ = http_server
    status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    client_id = json.loads(raw)["client_id"]
    query = _authorize_query(client_id)

    def fresh_form():
        status, headers, html = _request("GET", f"{base_url}/oauth/authorize?{query}")
        assert status == 200
        csrf_token = _csrf_token_from_html(html)
        csrf_cookie = headers["set-cookie"].split(";", 1)[0]
        form = {
            "imap_username": "imap-user",
            "imap_password": "imap-pass",
            "smtp_username": "smtp-user",
            "smtp_password": "smtp-pass",
            "sender_display_name": "Test Sender",
            "sender_email": "sender@example.com",
            "csrf_token": csrf_token,
        }
        return csrf_cookie, form

    csrf_cookie, form = fresh_form()
    missing = _form("POST", f"{base_url}/oauth/authorize?{query}", form)
    assert missing[0] == 400
    assert "Missing OAuth authorization CSRF cookie" in missing[2]

    csrf_cookie, form = fresh_form()
    tampered = _form("POST", f"{base_url}/oauth/authorize?{query}", form, headers={"Cookie": f"{AUTHORIZE_CSRF_COOKIE}=bad"})
    assert tampered[0] == 400

    csrf_cookie, form = fresh_form()
    mismatched = _form("POST", f"{base_url}/oauth/authorize?{query}", {**form, "csrf_token": "other"}, headers={"Cookie": csrf_cookie})
    assert mismatched[0] == 400
    assert "CSRF token mismatch" in mismatched[2]

    csrf_cookie, form = fresh_form()
    swapped_query = _authorize_query(client_id, scope="mail:read mail:send")
    swapped = _form("POST", f"{base_url}/oauth/authorize?{swapped_query}", form, headers={"Cookie": csrf_cookie})
    assert swapped[0] == 400
    assert "Invalid OAuth authorization CSRF cookie" in swapped[2]

    csrf_cookie, form = fresh_form()
    ok = _form("POST", f"{base_url}/oauth/authorize?{query}", form, headers={"Cookie": csrf_cookie})
    assert ok[0] == 302
    assert f"{AUTHORIZE_CSRF_COOKIE}=;" in ok[1]["set-cookie"]


def test_authorize_post_rejects_reused_csrf_token(http_server):
    base_url, _ = http_server
    status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    client_id = json.loads(raw)["client_id"]
    query = _authorize_query(client_id)
    status, headers, html = _request("GET", f"{base_url}/oauth/authorize?{query}")
    csrf_token = _csrf_token_from_html(html)
    csrf_cookie = headers["set-cookie"].split(";", 1)[0]
    form = {
        "imap_username": "imap-user",
        "imap_password": "imap-pass",
        "smtp_username": "smtp-user",
        "smtp_password": "smtp-pass",
        "sender_display_name": "Test Sender",
        "sender_email": "sender@example.com",
        "csrf_token": csrf_token,
    }

    assert _form("POST", f"{base_url}/oauth/authorize?{query}", form, headers={"Cookie": csrf_cookie})[0] == 302
    status, _, raw = _form("POST", f"{base_url}/oauth/authorize?{query}", form, headers={"Cookie": csrf_cookie})

    assert status == 400
    assert "expired or already been used" in raw


def test_authorize_post_rate_limit_blocks_before_credential_auth(server_env, monkeypatch):
    monkeypatch.setenv("OAUTH_AUTHORIZE_RATE_LIMIT_ATTEMPTS", "1")
    config = load_config()
    called = {"authorize": 0}

    class CountingOAuth(OAuthService):
        def authorize_with_credentials(self, *args, **kwargs):
            called["authorize"] += 1
            return super().authorize_with_credentials(*args, **kwargs)

    oauth = CountingOAuth(config, imap_verifier=lambda *_: None)
    server = MCPHTTPServer(("127.0.0.1", 0), MCPRequestHandler, config=config, oauth_service=oauth, tool_controller=FakeController())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    try:
        status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
        client_id = json.loads(raw)["client_id"]
        query = _authorize_query(client_id)
        status, headers, html = _request("GET", f"{base_url}/oauth/authorize?{query}")
        csrf_token = _csrf_token_from_html(html)
        csrf_cookie = headers["set-cookie"].split(";", 1)[0]
        form = {
            "imap_username": "imap-user",
            "imap_password": "imap-pass",
            "smtp_username": "smtp-user",
            "smtp_password": "smtp-pass",
            "sender_display_name": "Test Sender",
            "sender_email": "sender@example.com",
            "csrf_token": csrf_token,
        }

        assert _form("POST", f"{base_url}/oauth/authorize?{query}", form, headers={"Cookie": csrf_cookie})[0] == 302
        status, headers, html = _request("GET", f"{base_url}/oauth/authorize?{query}")
        csrf_token = _csrf_token_from_html(html)
        csrf_cookie = headers["set-cookie"].split(";", 1)[0]
        form["csrf_token"] = csrf_token
        status, _, raw = _form("POST", f"{base_url}/oauth/authorize?{query}", form, headers={"Cookie": csrf_cookie})

        assert status == 429
        assert json.loads(raw)["error"] == "slow_down"
        assert called["authorize"] == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_register_rate_limit_blocks_storage_before_second_client(server_env, monkeypatch):
    monkeypatch.setenv("OAUTH_REGISTER_RATE_LIMIT_ATTEMPTS", "1")
    config = load_config()
    oauth = OAuthService(config, imap_verifier=lambda *_: None)
    server = MCPHTTPServer(("127.0.0.1", 0), MCPRequestHandler, config=config, oauth_service=oauth, tool_controller=FakeController())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    try:
        payload = {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]}
        assert _request("POST", f"{base_url}/oauth/register", payload)[0] == 201
        status, _, raw = _request("POST", f"{base_url}/oauth/register", payload)

        assert status == 429
        assert json.loads(raw)["error"] == "slow_down"
        stored = oauth.store._conn.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0]
        assert stored == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_authorize_post_rejects_pre_body_csrf_before_credential_auth(server_env):
    config = load_config()
    called = {"authorize": 0}

    class CountingOAuth(OAuthService):
        def authorize_with_credentials(self, *args, **kwargs):
            called["authorize"] += 1
            return super().authorize_with_credentials(*args, **kwargs)

    oauth = CountingOAuth(config, imap_verifier=lambda *_: None)
    server = MCPHTTPServer(("127.0.0.1", 0), MCPRequestHandler, config=config, oauth_service=oauth, tool_controller=FakeController())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    try:
        status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
        client_id = json.loads(raw)["client_id"]
        query = _authorize_query(client_id)
        form = urlencode(
            {
                "imap_username": "imap-user",
                "imap_password": "imap-pass",
                "smtp_username": "smtp-user",
                "smtp_password": "smtp-pass",
                "sender_display_name": "Test Sender",
                "sender_email": "sender@example.com",
                "csrf_token": "missing",
            }
        )
        status, _, raw = _raw(
            "POST",
            f"{base_url}/oauth/authorize?{query}",
            form,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(form))},
        )
        assert status == 400
        assert "Missing OAuth authorization CSRF cookie" in raw
        assert called["authorize"] == 0
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_authorize_post_rejects_oversized_form_body_before_credential_auth(server_env):
    config = load_config()
    called = {"authorize": 0}

    class CountingOAuth(OAuthService):
        def authorize_with_credentials(self, *args, **kwargs):
            called["authorize"] += 1
            return super().authorize_with_credentials(*args, **kwargs)

    oauth = CountingOAuth(config, imap_verifier=lambda *_: None)
    server = MCPHTTPServer(("127.0.0.1", 0), MCPRequestHandler, config=config, oauth_service=oauth, tool_controller=FakeController())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    try:
        status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
        client_id = json.loads(raw)["client_id"]
        query = _authorize_query(client_id)
        status, headers, html = _request("GET", f"{base_url}/oauth/authorize?{query}")
        csrf_cookie = headers["set-cookie"].split(";", 1)[0]
        csrf_token = _csrf_token_from_html(html)
        body = urlencode({"csrf_token": csrf_token, "imap_username": "x" * MAX_FORM_BODY_BYTES})
        status, _, raw = _raw(
            "POST",
            f"{base_url}/oauth/authorize?{query}",
            body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body)), "Cookie": csrf_cookie},
        )
        assert status == 413
        assert f"Request body exceeds {MAX_FORM_BODY_BYTES} bytes" in raw
        assert called["authorize"] == 0
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_authorize_post_rejects_invalid_content_length(http_server):
    base_url, _ = http_server
    status, _, raw = _request("POST", f"{base_url}/oauth/register", {"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    client_id = json.loads(raw)["client_id"]
    query = _authorize_query(client_id)
    status, headers, _ = _request("GET", f"{base_url}/oauth/authorize?{query}")
    csrf_cookie = headers["set-cookie"].split(";", 1)[0]

    status, _, raw = _raw(
        "POST",
        f"{base_url}/oauth/authorize?{query}",
        "",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "not-a-number", "Cookie": csrf_cookie},
    )
    assert status == 400
    assert "Content-Length must be a non-negative integer" in raw


def test_json_body_limits_for_register_and_mcp(http_server):
    base_url, _ = http_server
    oversized = "{" + f'"x":"{"a" * MAX_JSON_BODY_BYTES}"' + "}"
    status, _, raw = _raw("POST", f"{base_url}/oauth/register", oversized, headers={"Content-Type": "application/json", "Content-Length": str(len(oversized))})
    assert status == 413
    assert f"Request body exceeds {MAX_JSON_BODY_BYTES} bytes" in raw

    status, headers, raw = _raw("POST", f"{base_url}/oauth/register", "{bad-json", headers={"Content-Type": "application/json", "Content-Length": "9"})
    assert status == 400
    assert headers["x-content-type-options"] == "nosniff"
    assert json.loads(raw)["error"] == "invalid_request"

    status, _, raw = _raw("POST", f"{base_url}/sse", "", headers={"Content-Type": "application/json", "Content-Length": "wat"})
    assert status == 400
    assert "Content-Length must be a non-negative integer" in raw


def test_mcp_requires_bearer_and_lists_tools(http_server):
    base_url, _ = http_server
    status, headers, raw = _request("POST", f"{base_url}/sse", {"jsonrpc": "2.0", "id": "1", "method": "tools/list"})
    assert status == 401
    assert "www-authenticate" in headers
    assert "oauth-protected-resource" in headers["www-authenticate"]
    assert headers["x-content-type-options"] == "nosniff"

    token = _token(base_url)
    status, _, raw = _request("POST", f"{base_url}/sse", {"jsonrpc": "2.0", "id": "2", "method": "tools/list"}, headers={"Authorization": f"Bearer {token}"})
    assert status == 200
    tools = json.loads(raw)["result"]["tools"]
    assert any(tool["name"] == "read_email" for tool in tools)
    assert any(tool["name"] == "get_sender_identity" for tool in tools)
    create_folder = next(tool for tool in tools if tool["name"] == "create_folder")
    assert create_folder["inputSchema"]["required"] == ["folder"]


def test_mcp_tool_call_uses_oauth_session_credentials(http_server):
    base_url, _ = http_server
    token = _token(base_url)
    status, _, raw = _request(
        "POST",
        f"{base_url}/sse",
        {"jsonrpc": "2.0", "id": "3", "method": "tools/call", "params": {"name": "list_folders", "arguments": {}}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert status == 200
    content = json.loads(raw)["result"]["structuredContent"]
    assert content == {"tool": "list_folders", "imap_username": "imap-user", "smtp_username": "smtp-user"}


def test_readyz_reports_injected_startup_error(server_env):
    config = load_config()
    server = MCPHTTPServer(("127.0.0.1", 0), MCPRequestHandler, config=config, oauth_service=OAuthService(config, imap_verifier=lambda *_: None), tool_controller=FakeController(), startup_error="store failed")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        status, _, raw = _request("GET", f"http://{host}:{port}/readyz")
        assert status == 503
        assert json.loads(raw) == {"ready": False, "error": "store failed"}
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_startup_fails_with_stable_message_when_audit_path_is_file(server_env, monkeypatch, tmp_path):
    audit_file = tmp_path / "audit-as-file"
    audit_file.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("AUDIT_LOG_DIR", str(audit_file))
    with pytest.raises(StartupError, match="AUDIT_LOG_DIR must be a writable directory"):
        build_server()


def test_internal_https_wraps_socket(server_env, monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("fake cert", encoding="utf-8")
    key.write_text("fake key", encoding="utf-8")
    monkeypatch.setenv("MCP_INTERNAL_HTTPS", "true")
    monkeypatch.setenv("MCP_TLS_CERT_FILE", str(cert))
    monkeypatch.setenv("MCP_TLS_KEY_FILE", str(key))
    seen = {}

    class FakeContext:
        def __init__(self, protocol):
            seen["protocol"] = protocol

        def load_cert_chain(self, certfile, keyfile):
            seen["certfile"] = certfile
            seen["keyfile"] = keyfile

        def wrap_socket(self, sock, *, server_side):
            seen["wrapped"] = server_side
            return sock

    monkeypatch.setattr("imap_smtp_mcp.server.ssl.SSLContext", FakeContext)
    server = build_server(load_config())
    try:
        assert seen["certfile"] == str(cert)
        assert seen["keyfile"] == str(key)
        assert seen["wrapped"] is True
    finally:
        server.server_close()
