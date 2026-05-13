from __future__ import annotations

import html
import hashlib
import hmac
import json
import secrets
import ssl
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .audit import AuditEvent, AuditLogger
from .config import AppConfig, ConfigError, load_config
from .errors import MCPError
from .oauth import OAuthError, OAuthService
from .tool_controller import TOOL_SCOPES, MailToolController


JSON = "application/json; charset=utf-8"
AUTHORIZE_CSRF_COOKIE = "oauth_authorize_csrf"
MAX_FORM_BODY_BYTES = 16_384
MAX_JSON_BODY_BYTES = 1_048_576


class StartupError(RuntimeError):
    pass


class RequestBodyError(ValueError):
    def __init__(self, message: str, status: HTTPStatus) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


class MCPHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        *,
        config: AppConfig,
        oauth_service: OAuthService | None = None,
        tool_controller: MailToolController | None = None,
        audit_logger: AuditLogger | None = None,
        startup_error: str | None = None,
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.config = config
        self.startup_error = startup_error
        self.oauth_service = oauth_service or OAuthService(config)
        self.tool_controller = tool_controller or MailToolController(config)
        self.audit_logger = audit_logger or AuditLogger(config.audit_log_dir)


class MCPRequestHandler(BaseHTTPRequestHandler):
    server: MCPHTTPServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send_json({"ok": True})
            return
        if parsed.path == "/readyz":
            if self.server.startup_error:
                self._send_json({"ready": False, "error": self.server.startup_error}, status=HTTPStatus.SERVICE_UNAVAILABLE)
            else:
                self._send_json({"ready": True})
            return
        if parsed.path == "/.well-known/oauth-protected-resource":
            self._send_json(self.server.oauth_service.protected_resource_metadata())
            return
        if parsed.path == "/.well-known/oauth-authorization-server":
            self._send_json(self.server.oauth_service.authorization_server_metadata())
            return
        if parsed.path == "/oauth/authorize":
            self._handle_authorize_get(parsed.query)
            return
        if parsed.path == "/sse":
            self._send_sse_preamble()
            return
        self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/oauth/register":
            self._handle_register()
            return
        if parsed.path == "/oauth/token":
            self._handle_token()
            return
        if parsed.path == "/oauth/authorize":
            self._handle_authorize_post(parsed.query)
            return
        if parsed.path == "/sse":
            self._handle_mcp_jsonrpc()
            return
        self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _handle_register(self) -> None:
        try:
            payload = self._read_json()
            response = self.server.oauth_service.register_client(payload)
            self._audit_system("oauth_register", True)
            self._send_json(response, status=HTTPStatus.CREATED)
        except RequestBodyError as exc:
            self._audit_system("oauth_register", False, "invalid_request")
            self._send_json({"error": "invalid_request", "error_description": exc.message}, status=exc.status)
        except OAuthError as exc:
            self._audit_system("oauth_register", False, exc.error)
            self._send_oauth_error(exc, status=HTTPStatus.BAD_REQUEST)

    def _handle_authorize_get(self, raw_query: str) -> None:
        query = _single_value_query(raw_query)
        try:
            self.server.oauth_service.validate_authorize_request(query)
        except OAuthError as exc:
            self._send_oauth_error(exc, status=HTTPStatus.BAD_REQUEST)
            return
        csrf_token = secrets.token_urlsafe(32)
        cookie_value = _sign_authorize_cookie(self.server.config, csrf_token, raw_query)
        self._send_html(
            _login_form(raw_query, self.server.config.oauth.required_scopes, csrf_token),
            headers={"Set-Cookie": _build_authorize_cookie(self.server.config, cookie_value)},
        )

    def _handle_authorize_post(self, raw_query: str) -> None:
        query = _single_value_query(raw_query)
        try:
            self.server.oauth_service.validate_authorize_request(query)
            cookie_token = _verify_authorize_cookie_for_query(self.server.config, raw_query, self.headers.get("Cookie", ""))
            form = self._read_form()
            _verify_authorize_form_token(cookie_token, form.get("csrf_token", ""))
            redirect = self.server.oauth_service.authorize_with_credentials(
                query,
                imap_username=form.get("imap_username", ""),
                imap_password=form.get("imap_password", ""),
                smtp_username=form.get("smtp_username", ""),
                smtp_password=form.get("smtp_password", ""),
            )
            self._audit_system("oauth_authorize", True)
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", redirect)
            self.send_header("Set-Cookie", _clear_authorize_cookie(self.server.config))
            self.end_headers()
        except RequestBodyError as exc:
            self._audit_system("oauth_authorize", False, "invalid_request")
            self._send_json({"error": "invalid_request", "error_description": exc.message}, status=exc.status)
        except OAuthError as exc:
            self._audit_system("oauth_authorize", False, exc.error)
            self._send_oauth_error(exc, status=HTTPStatus.BAD_REQUEST)

    def _handle_token(self) -> None:
        try:
            payload = self._read_form()
            response = self.server.oauth_service.exchange_code(payload)
            self._audit_system("oauth_token", True)
            self._send_json(response)
        except RequestBodyError as exc:
            self._audit_system("oauth_token", False, "invalid_request")
            self._send_json({"error": "invalid_request", "error_description": exc.message}, status=exc.status)
        except OAuthError as exc:
            self._audit_system("oauth_token", False, exc.error)
            self._send_oauth_error(exc, status=HTTPStatus.BAD_REQUEST)

    def _handle_mcp_jsonrpc(self) -> None:
        try:
            payload = self._read_json()
        except RequestBodyError as exc:
            self._send_json(_jsonrpc_error(None, -32600, exc.message), status=exc.status)
            return
        except ValueError:
            self._send_json(_jsonrpc_error(None, -32700, "Parse error"))
            return
        request_id = str(payload.get("id", ""))
        method = payload.get("method")
        if method == "initialize":
            self._send_json({"jsonrpc": "2.0", "id": payload.get("id"), "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "imap-smtp-mcp", "version": "0.1.0"}, "capabilities": {"tools": {}}}})
            return
        if method == "tools/list":
            if not self._require_bearer((), request_id):
                return
            self._send_json({"jsonrpc": "2.0", "id": payload.get("id"), "result": {"tools": self.server.tool_controller.list_tools()}})
            return
        if method == "tools/call":
            params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
            name = str(params.get("name", ""))
            required_scopes = TOOL_SCOPES.get(name, ())
            auth = self._require_bearer(required_scopes, request_id)
            if not auth:
                return
            claims, credentials = auth
            try:
                raw_arguments = params.get("arguments")
                arguments: dict[str, Any] = raw_arguments if isinstance(raw_arguments, dict) else {}
                result = self.server.tool_controller.call_tool(name, arguments, credentials, request_id=request_id, subject=claims.subject)
                self._send_json(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "result": {
                            "content": [{"type": "text", "text": json.dumps(result, separators=(",", ":"))}],
                            "structuredContent": result,
                        },
                    }
                )
            except MCPError as exc:
                self._send_json(_jsonrpc_error(payload.get("id"), -32000, exc.message, {"code": exc.code}))
            return
        self._send_json(_jsonrpc_error(payload.get("id"), -32601, f"Unknown method: {method}"))

    def _require_bearer(self, scopes: tuple[str, ...], request_id: str):
        try:
            return self.server.oauth_service.authenticate_bearer(self.headers.get("Authorization"), required_scopes=scopes)
        except OAuthError as exc:
            self._audit_system("mcp_auth", False, exc.error, request_id=request_id)
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("Content-Type", JSON)
            self.send_header("WWW-Authenticate", _bearer_challenge(self.server.config, exc))
            self.end_headers()
            self.wfile.write(json.dumps({"error": exc.error, "error_description": exc.description}).encode("utf-8"))
            return None

    def _read_json(self) -> dict[str, Any]:
        length = self._content_length(MAX_JSON_BODY_BYTES)
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(payload, dict):
            raise ValueError("JSON request body must be an object")
        return payload

    def _read_form(self) -> dict[str, str]:
        length = self._content_length(MAX_FORM_BODY_BYTES)
        raw = self.rfile.read(length).decode("utf-8")
        return _single_value_query(raw)

    def _content_length(self, max_bytes: int) -> int:
        raw = self.headers.get("Content-Length")
        if raw is None:
            raise RequestBodyError("Content-Length is required", HTTPStatus.BAD_REQUEST)
        try:
            length = int(raw)
        except ValueError as exc:
            raise RequestBodyError("Content-Length must be a non-negative integer", HTTPStatus.BAD_REQUEST) from exc
        if length < 0:
            raise RequestBodyError("Content-Length must be a non-negative integer", HTTPStatus.BAD_REQUEST)
        if length > max_bytes:
            raise RequestBodyError(f"Request body exceeds {max_bytes} bytes", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        return length

    def _send_json(self, payload: dict[str, Any], *, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", JSON)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, value: str, *, headers: dict[str, str] | None = None) -> None:
        body = value.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, item in (headers or {}).items():
            self.send_header(key, item)
        self.end_headers()
        self.wfile.write(body)

    def _send_sse_preamble(self) -> None:
        body = b"event: endpoint\ndata: /sse\n\n"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_oauth_error(self, exc: OAuthError, *, status: HTTPStatus) -> None:
        self._send_json({"error": exc.error, "error_description": exc.description}, status=status)

    def _audit_system(self, operation: str, success: bool, failure_class: str | None = None, *, request_id: str = "") -> None:
        self.server.audit_logger.log_tool_invocation(AuditEvent(request_id=request_id or "-", operation=operation, success=success, failure_class=failure_class))


def _single_value_query(raw: str) -> dict[str, str]:
    parsed = parse_qs(raw, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def _login_form(raw_query: str, scopes: tuple[str, ...], csrf_token: str) -> str:
    action = f"/oauth/authorize?{html.escape(raw_query, quote=True)}"
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorize Mail MCP</title></head>
<body>
<main>
<h1>Authorize Mail MCP</h1>
<p>ChatGPT is requesting: {html.escape(", ".join(scopes))}</p>
<form method="post" action="{action}">
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
<label>IMAP username <input name="imap_username" autocomplete="username" required></label><br>
<label>IMAP password <input name="imap_password" type="password" autocomplete="current-password" required></label><br>
<label>SMTP username <input name="smtp_username" required></label><br>
<label>SMTP password <input name="smtp_password" type="password" required></label><br>
<button type="submit">Authorize</button>
</form>
</main>
</body>
</html>"""


def _sign_authorize_cookie(config: AppConfig, csrf_token: str, raw_query: str) -> str:
    query_hash = hashlib.sha256(raw_query.encode("utf-8")).hexdigest()
    signing_input = f"{csrf_token}.{query_hash}"
    signature = hmac.new(config.oauth.cookie_secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{csrf_token}.{signature}"


def _verify_authorize_cookie_for_query(config: AppConfig, raw_query: str, cookie_header: str) -> str:
    cookie_value = _extract_cookie(cookie_header, AUTHORIZE_CSRF_COOKIE)
    if not cookie_value:
        raise OAuthError("invalid_request", "Missing OAuth authorization CSRF cookie")
    try:
        cookie_token, _ = cookie_value.rsplit(".", 1)
    except ValueError as exc:
        raise OAuthError("invalid_request", "Malformed OAuth authorization CSRF cookie") from exc
    expected = _sign_authorize_cookie(config, cookie_token, raw_query)
    if not hmac.compare_digest(cookie_value, expected):
        raise OAuthError("invalid_request", "Invalid OAuth authorization CSRF cookie")
    return cookie_token


def _verify_authorize_form_token(cookie_token: str, form_token: str) -> None:
    if not form_token or not hmac.compare_digest(cookie_token, form_token):
        raise OAuthError("invalid_request", "OAuth authorization CSRF token mismatch")


def _extract_cookie(cookie_header: str, name: str) -> str | None:
    for part in cookie_header.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            return value
    return None


def _build_authorize_cookie(config: AppConfig, value: str) -> str:
    secure = "; Secure" if config.oauth.public_base_url.startswith("https://") else ""
    return f"{AUTHORIZE_CSRF_COOKIE}={value}; Path=/oauth/authorize; HttpOnly; SameSite=Lax{secure}"


def _clear_authorize_cookie(config: AppConfig) -> str:
    secure = "; Secure" if config.oauth.public_base_url.startswith("https://") else ""
    return f"{AUTHORIZE_CSRF_COOKIE}=; Path=/oauth/authorize; Max-Age=0; HttpOnly; SameSite=Lax{secure}"


def _jsonrpc_error(request_id: object, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _bearer_challenge(config: AppConfig, exc: OAuthError) -> str:
    metadata_url = f"{config.oauth.public_base_url}/.well-known/oauth-protected-resource"
    params = {
        "resource_metadata": metadata_url,
        "scope": " ".join(config.oauth.required_scopes),
        "error": exc.error,
        "error_description": exc.description,
    }
    return "Bearer " + ", ".join(f'{key}="{value}"' for key, value in params.items())


def is_trusted_proxy(config: AppConfig, client_ip: str) -> bool:
    if not config.server.trust_proxy_headers:
        return False
    ip = ip_address(client_ip)
    return any(ip in ip_network(cidr, strict=False) for cidr in config.server.allowed_proxy_cidrs)


def build_server(config: AppConfig | None = None) -> MCPHTTPServer:
    cfg = config or load_config()
    validate_startup(cfg)
    server = MCPHTTPServer((cfg.server.host, cfg.server.port), MCPRequestHandler, config=cfg)
    if cfg.server.internal_https:
        if cfg.server.tls_cert_file is None or cfg.server.tls_key_file is None:
            raise StartupError("MCP_INTERNAL_HTTPS requires MCP_TLS_CERT_FILE and MCP_TLS_KEY_FILE")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cfg.server.tls_cert_file, keyfile=cfg.server.tls_key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def validate_startup(config: AppConfig) -> None:
    _ensure_writable_dir(config.app_data_dir, "APP_DATA_DIR")
    _ensure_writable_dir(config.audit_log_dir, "AUDIT_LOG_DIR")
    store_parent = str(Path(config.oauth.store_path).parent)
    _ensure_writable_dir(store_parent, "OAUTH_STORE_PATH directory")
    if config.server.internal_https:
        _ensure_readable_file(config.server.tls_cert_file, "MCP_TLS_CERT_FILE")
        _ensure_readable_file(config.server.tls_key_file, "MCP_TLS_KEY_FILE")


def _ensure_writable_dir(path_value: str, label: str) -> None:
    path = Path(path_value)
    if path.exists() and not path.is_dir():
        raise StartupError(f"{label} must be a writable directory: {path}")
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write-test"
        with probe.open("w", encoding="utf-8") as f:
            f.write("ok")
        probe.unlink()
    except OSError as exc:
        raise StartupError(f"{label} must be a writable directory: {path}") from exc


def _ensure_readable_file(path_value: str | None, label: str) -> None:
    if not path_value:
        raise StartupError(f"{label} is required")
    path = Path(path_value)
    if not path.is_file():
        raise StartupError(f"{label} must be a readable file: {path}")
    try:
        with path.open("rb"):
            pass
    except OSError as exc:
        raise StartupError(f"{label} must be a readable file: {path}") from exc


def main() -> None:
    try:
        server = build_server()
    except (ConfigError, StartupError) as exc:
        print(f"Startup failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"Serving IMAP/SMTP MCP on {server.config.server.host}:{server.config.server.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
