from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "manual_mcp_compat_suite.py"


def _load_manual_suite():
    spec = importlib.util.spec_from_file_location("manual_mcp_compat_suite_for_tests", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


manual_suite = _load_manual_suite()
SuiteConfig = manual_suite.SuiteConfig
_server_env = manual_suite._server_env


def _suite_config() -> SuiteConfig:
    return SuiteConfig(
        server_command=("python", "-m", "imap_smtp_mcp.server"),
        host="127.0.0.1",
        port=8123,
        public_base_url="http://127.0.0.1:8123",
        test_email="test@example.com",
        imap_username="imap-user",
        imap_password="imap-pass",
        smtp_username="smtp-user",
        smtp_password="smtp-pass",
        imap_host="imap.example.com",
        imap_port=993,
        imap_mode="ssl",
        sender_display_name="MCP Compatibility Test",
        sender_email="test@example.com",
        inbox_folder="INBOX",
        trash_folder="Trash",
        poll_attempts=1,
        poll_interval_seconds=1,
        http_timeout_seconds=120,
        use_existing_server=False,
    )


def _suite_config_with_poll_attempts(attempts: int) -> SuiteConfig:
    return SuiteConfig(**{**_suite_config().__dict__, "poll_attempts": attempts})


def test_manual_suite_server_env_is_oauth_only(tmp_path) -> None:
    config = _suite_config()
    env = _server_env(config, str(tmp_path))

    assert env["APP_DATA_DIR"] == str(tmp_path / "data")
    assert env["OAUTH_STORE_PATH"] == str(tmp_path / "data" / "oauth.sqlite3")
    assert "MCP_" + "ALLOWED_USERS" not in env
    assert "USER_OAUTH_" + "IMAP_USERNAME" not in env
    assert str(ROOT / "src") in env["PYTHONPATH"].split(os.pathsep)
    assert env["OAUTH_ALLOWED_REDIRECT_URI_PATTERNS"] == r"https://chatgpt\.com/connector/oauth/manual-compat"
    assert env["ACTION_CREATE_FOLDER"] == "true"
    assert env["ACTION_RENAME_FOLDER"] == "true"
    assert env["ACTION_DELETE_FOLDER"] == "true"


def test_manual_suite_server_env_preserves_existing_pythonpath(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PYTHONPATH", "/existing/path")
    env = _server_env(_suite_config(), str(tmp_path))

    assert env["PYTHONPATH"].split(os.pathsep)[:2] == [str(ROOT / "src"), "/existing/path"]


def test_manual_suite_http_timeout_default_and_override(monkeypatch) -> None:
    monkeypatch.delenv("MCP_COMPAT_HTTP_TIMEOUT_SECONDS", raising=False)
    assert manual_suite._http_timeout_seconds() == 120

    monkeypatch.setenv("MCP_COMPAT_HTTP_TIMEOUT_SECONDS", "45")
    assert manual_suite._http_timeout_seconds() == 45


def test_wait_ready_reports_redacted_server_output() -> None:
    secret = "super-secret-password"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; print('stdout super-secret-password'); print('stderr super-secret-password', file=sys.stderr); raise SystemExit(1)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        manual_suite._wait_ready("http://127.0.0.1:1", proc, (secret,))
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        message = str(exc)
        assert "MCP server exited early with status 1" in message
        assert "server stdout:" in message
        assert "server stderr:" in message
        assert "[REDACTED]" in message
        assert secret not in message


def test_oauth_token_uses_csrf_authorize_form(monkeypatch) -> None:
    calls: list[tuple[str, str, object]] = []

    def fake_json(method, url, payload, *, headers=None):
        calls.append((method, url, payload))
        return {"client_id": "client-1"}

    def fake_raw(method, url, body, *, headers=None):
        calls.append((method, url, headers))
        assert method == "GET"
        assert url.startswith("http://127.0.0.1:8123/oauth/authorize?")
        return 200, {"set-cookie": "oauth_authorize_csrf=cookie-token.sig; Path=/oauth/authorize"}, '<input type="hidden" name="csrf_token" value="form-token">'

    def fake_form(method, url, form, *, headers=None):
        calls.append((method, url, {"form": form, "headers": headers}))
        if url.startswith("http://127.0.0.1:8123/oauth/authorize?"):
            assert form["csrf_token"] == "form-token"
            assert form["sender_display_name"] == "MCP Compatibility Test"
            assert form["sender_email"] == "test@example.com"
            assert headers == {"Cookie": "oauth_authorize_csrf=cookie-token.sig"}
            return 302, {"location": "https://chatgpt.com/connector/oauth/manual-compat?code=code-1&state=manual"}, ""
        assert url == "http://127.0.0.1:8123/oauth/token"
        assert form["code"] == "code-1"
        return 200, {}, '{"access_token":"access-1"}'

    monkeypatch.setattr(manual_suite, "_request_json", fake_json)
    monkeypatch.setattr(manual_suite, "_request_raw", fake_raw)
    monkeypatch.setattr(manual_suite, "_request_form", fake_form)

    assert manual_suite._oauth_token(_suite_config()) == "access-1"
    assert [call[0] for call in calls] == ["POST", "GET", "POST", "POST"]


def test_oauth_token_requires_csrf_cookie(monkeypatch) -> None:
    monkeypatch.setattr(manual_suite, "_request_json", lambda *args, **kwargs: {"client_id": "client-1"})
    monkeypatch.setattr(manual_suite, "_request_raw", lambda *args, **kwargs: (200, {}, '<input type="hidden" name="csrf_token" value="form-token">'))

    try:
        manual_suite._oauth_token(_suite_config())
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "CSRF cookie" in str(exc)


def test_oauth_token_requires_hidden_csrf_token(monkeypatch) -> None:
    monkeypatch.setattr(manual_suite, "_request_json", lambda *args, **kwargs: {"client_id": "client-1"})
    monkeypatch.setattr(
        manual_suite,
        "_request_raw",
        lambda *args, **kwargs: (200, {"set-cookie": "oauth_authorize_csrf=cookie-token.sig; Path=/oauth/authorize"}, "<html></html>"),
    )

    try:
        manual_suite._oauth_token(_suite_config())
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "CSRF token" in str(exc)


class FakeManualClient:
    def __init__(self, search_results: list[list[str]] | None = None, folders: list[str] | None = None) -> None:
        self.search_results = search_results or [["10"], ["11"], ["12"], ["21"], ["31"]]
        self.folders = folders or ["INBOX", "MCP_TEST", "Trash"]
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call_tool(self, name: str, arguments: dict[str, object]):
        self.calls.append((name, arguments))
        if name == "list_folders":
            return {"folders": self.folders}
        if name == "send_email":
            return {"sent": True}
        if name == "search_emails":
            return {"uids": self.search_results.pop(0)}
        if name == "list_emails":
            return {"emails": [{"uid": "10"}]}
        if name == "read_email":
            return {
                "from_address": "test@example.com",
                "body_text": f"manual compatibility test marker: {arguments.get('marker', '')}",
                "attachments": [],
            }
        if name == "get_email_attachment":
            return {"filename": "note.txt", "content_type": "text/plain", "size_bytes": 5, "content_base64": "aGVsbG8="}
        if name in {"create_folder", "rename_folder", "copy_email", "move_email", "mark_read_state", "move_to_trash", "delete_email_permanent", "empty_trash", "delete_folder"}:
            return {"ok": True}
        raise AssertionError(f"Unexpected tool: {name}")


def test_find_marker_uid_retries_and_uses_latest_uid(monkeypatch) -> None:
    monkeypatch.setattr(manual_suite.time, "sleep", lambda *_: None)
    config = _suite_config_with_poll_attempts(2)
    client = FakeManualClient(search_results=[[], ["3", "8"]])

    assert manual_suite._find_marker_uid(client, "INBOX", "marker-1", config, step="copy_email") == "8"
    assert [call[0] for call in client.calls] == ["search_emails", "search_emails"]


def test_find_marker_uid_exhaustion_names_step_and_folder(monkeypatch) -> None:
    monkeypatch.setattr(manual_suite.time, "sleep", lambda *_: None)
    config = _suite_config()
    client = FakeManualClient(search_results=[[], []])

    try:
        manual_suite._find_marker_uid(client, "INBOX", "marker-1", config, step="move_email")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        message = str(exc)
        assert "move_email" in message
        assert "INBOX" in message
        assert "marker-1" in message


def test_run_mail_flow_checks_required_inbox_and_trash_before_send(monkeypatch) -> None:
    monkeypatch.setattr(manual_suite.time, "sleep", lambda *_: None)
    client = FakeManualClient(folders=["INBOX"])

    try:
        manual_suite._run_mail_flow(client, _suite_config())
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "Required folders missing from mailbox: Trash" in str(exc)
    assert [call[0] for call in client.calls] == ["list_folders"]


def test_run_mail_flow_creates_renames_uses_and_deletes_temp_folder(monkeypatch) -> None:
    marker = "mcp-compat-1234567890-abc123"
    monkeypatch.setattr(manual_suite.time, "sleep", lambda *_: None)
    monkeypatch.setattr(manual_suite.time, "time", lambda: 1234567890)
    monkeypatch.setattr(manual_suite.secrets, "token_hex", lambda *_: "abc123")
    monkeypatch.setattr(manual_suite, "_append_direct_blocked_attachment_message", lambda *_: None)

    class FlowClient(FakeManualClient):
        def call_tool(self, name: str, arguments: dict[str, object]):
            self.calls.append((name, arguments))
            if name == "list_folders":
                return {"folders": self.folders}
            if name == "send_email":
                if arguments.get("attachments") and arguments["attachments"][0]["filename"].endswith(".html"):
                    raise RuntimeError("MCP tool send_email returned error: blocked by MIME type")
                return {"sent": True}
            if name == "search_emails":
                return {"uids": self.search_results.pop(0)}
            if name == "list_emails":
                return {"emails": [{"uid": "initial"}]}
            if name == "read_email":
                uid = arguments.get("uid")
                if uid == "blocked-fixture":
                    return {
                        "from_address": "test@example.com",
                        "body_text": f"blocked {marker}-blocked",
                        "attachments": [
                            {
                                "attachment_id": "part-2",
                                "filename": manual_suite.BLOCKED_HTML_ATTACHMENT_FILENAME,
                                "content_type": "text/html",
                                "size_bytes": 10,
                                "retrievable": False,
                                "blocked_reason": "blocked_mime_type",
                            },
                            {
                                "attachment_id": "part-3",
                                "filename": manual_suite.BLOCKED_JS_ATTACHMENT_FILENAME,
                                "content_type": "application/javascript",
                                "size_bytes": 10,
                                "retrievable": False,
                                "blocked_reason": "blocked_mime_type",
                            },
                        ],
                    }
                return {
                    "from_address": "test@example.com",
                    "body_text": marker,
                    "attachments": [
                        {
                            "attachment_id": "part-2",
                            "filename": manual_suite.ALLOWED_ATTACHMENT_FILENAME,
                            "content_type": "text/plain",
                            "size_bytes": 63,
                            "retrievable": True,
                            "blocked_reason": None,
                        }
                    ],
                }
            if name == "get_email_attachment":
                if arguments.get("uid") == "blocked-fixture":
                    raise RuntimeError("MCP tool get_email_attachment returned error: blocked by MIME type")
                attachment_text = f"manual compatibility attachment marker: {marker}"
                return {
                    "filename": manual_suite.ALLOWED_ATTACHMENT_FILENAME,
                    "content_type": "text/plain",
                    "size_bytes": len(attachment_text),
                    "content_base64": manual_suite.base64.b64encode(attachment_text.encode("utf-8")).decode("ascii"),
                }
            if name in {"create_folder", "rename_folder", "copy_email", "move_email", "mark_read_state", "move_to_trash", "delete_email_permanent", "empty_trash", "delete_folder"}:
                return {"ok": True}
            raise AssertionError(f"Unexpected tool: {name}")

    client = FlowClient(
        search_results=[
            ["initial"],
            [],
            ["blocked-fixture"],
            ["copy-fresh"],
            ["move-fresh"],
            ["test-folder-uid-a", "test-folder-uid-b"],
            ["trash-uid-a", "trash-uid-b"],
            ["blocked-fixture"],
            ["blocked-trash"],
        ]
    )
    manual_suite._run_mail_flow(client, _suite_config())

    create_call = next(args for name, args in client.calls if name == "create_folder")
    rename_call = next(args for name, args in client.calls if name == "rename_folder")
    copy_call = next(args for name, args in client.calls if name == "copy_email")
    move_call = next(args for name, args in client.calls if name == "move_email")
    delete_call = [args for name, args in client.calls if name == "delete_folder"][-1]
    assert create_call["folder"] == "MCP_COMPAT_TEST_mcp-compat-1234567890-abc123"
    assert rename_call == {
        "source_folder": "MCP_COMPAT_TEST_mcp-compat-1234567890-abc123",
        "target_folder": "MCP_COMPAT_TEST_mcp-compat-1234567890-abc123_RENAMED",
    }
    assert copy_call["uid"] == "copy-fresh"
    assert copy_call["target_folder"] == "MCP_COMPAT_TEST_mcp-compat-1234567890-abc123_RENAMED"
    assert move_call["uid"] == "move-fresh"
    assert move_call["target_folder"] == "MCP_COMPAT_TEST_mcp-compat-1234567890-abc123_RENAMED"
    assert delete_call["folder"] == "MCP_COMPAT_TEST_mcp-compat-1234567890-abc123_RENAMED"
    send_call = next(args for name, args in client.calls if name == "send_email")
    assert "from_address" not in send_call
    assert send_call["attachments"][0]["filename"] == manual_suite.ALLOWED_ATTACHMENT_FILENAME
    assert any(name == "get_email_attachment" for name, _ in client.calls)
    search_calls = [args for name, args in client.calls if name == "search_emails"]
    assert len(search_calls) >= 9
    assert all(json.dumps(args).find("mcp-compat-1234567890-abc123") >= 0 for args in search_calls)


def test_run_mail_flow_cleans_up_created_folder_on_failure(monkeypatch) -> None:
    monkeypatch.setattr(manual_suite.time, "sleep", lambda *_: None)
    monkeypatch.setattr(manual_suite.time, "time", lambda: 1234567890)
    monkeypatch.setattr(manual_suite.secrets, "token_hex", lambda *_: "abc123")

    class FailingFlowClient(FakeManualClient):
        def call_tool(self, name: str, arguments: dict[str, object]):
            self.calls.append((name, arguments))
            if name == "list_folders":
                return {"folders": self.folders}
            if name == "create_folder":
                return {"created": True}
            if name == "rename_folder":
                raise RuntimeError("rename failed")
            if name == "delete_folder":
                return {"deleted": True}
            raise AssertionError(f"Unexpected tool: {name}")

    client = FailingFlowClient()
    try:
        manual_suite._run_mail_flow(client, _suite_config())
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "rename failed" in str(exc)

    delete_call = next(args for name, args in client.calls if name == "delete_folder")
    assert delete_call["folder"] == "MCP_COMPAT_TEST_mcp-compat-1234567890-abc123"


def test_manual_suite_test_imports_with_src_only_pythonpath() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_manual_suite.py", "-k", "server_env_is_oauth_only"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
