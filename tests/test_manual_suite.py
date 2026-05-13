from __future__ import annotations

from scripts.manual_mcp_compat_suite import SuiteConfig, _server_env


def test_manual_suite_server_env_is_oauth_only(tmp_path) -> None:
    config = SuiteConfig(
        server_command=("python", "-m", "imap_smtp_mcp.server"),
        host="127.0.0.1",
        port=8123,
        public_base_url="http://127.0.0.1:8123",
        test_email="test@example.com",
        imap_username="imap-user",
        imap_password="imap-pass",
        smtp_username="smtp-user",
        smtp_password="smtp-pass",
        inbox_folder="INBOX",
        test_folder="MCP_TEST",
        trash_folder="Trash",
        poll_attempts=1,
        poll_interval_seconds=1,
        use_existing_server=False,
    )
    env = _server_env(config, str(tmp_path))

    assert env["APP_DATA_DIR"] == str(tmp_path / "data")
    assert env["OAUTH_STORE_PATH"] == str(tmp_path / "data" / "oauth.sqlite3")
    assert "MCP_" + "ALLOWED_USERS" not in env
    assert "USER_OAUTH_" + "IMAP_USERNAME" not in env
