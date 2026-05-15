import pytest

from imap_smtp_mcp.audit import AuditEvent, AuditLogger
from imap_smtp_mcp.config import ConfigError, load_config
from imap_smtp_mcp.server import build_server


@pytest.fixture
def container_like_env(monkeypatch):
    env = {
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_MODE": "starttls",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "AUDIT_LOG_DIR": "/tmp/imap-smtp-audit",
        "OAUTH_DEV_INSECURE_SECRETS": "true",
        "IMAP_TLS_VERIFY": "true",
        "IMAP_MAX_RETRIES": "2",
        "ACTION_LIST_FOLDERS": "true",
        "ACTION_SEARCH_EMAILS": "true",
        "ACTION_LIST_EMAILS": "true",
        "ACTION_READ_EMAIL": "true",
        "ACTION_SEND_EMAIL": "true",
        "ACTION_MARK_READ_STATE": "false",
        "ACTION_MOVE_EMAIL": "false",
        "ACTION_COPY_EMAIL": "false",
        "ACTION_DELETE_EMAIL_PERMANENT": "false",
        "ACTION_MOVE_TO_TRASH": "false",
        "ACTION_EMPTY_TRASH": "false",
        "ACTION_CREATE_FOLDER": "false",
        "ACTION_RENAME_FOLDER": "false",
        "ACTION_DELETE_FOLDER": "false",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_container_env_config_parses(container_like_env):
    config = load_config()
    assert config.imap.port == 993
    assert config.smtp.port == 587
    assert config.action_flags["move_email"] is False
    assert config.action_flags["create_folder"] is False


def test_startup_fails_fast_when_env_missing(container_like_env, monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    with pytest.raises(ConfigError, match="Missing required environment variable: SMTP_HOST"):
        build_server()


def test_audit_logger_fails_when_log_path_is_file(tmp_path):
    log_path = tmp_path / "audit-as-file"
    log_path.write_text("not-a-directory", encoding="utf-8")

    with pytest.raises(FileExistsError):
        AuditLogger(str(log_path))


def test_audit_logger_writes_when_log_path_is_writable_directory(tmp_path):
    logger = AuditLogger(str(tmp_path))
    logger.log_tool_invocation(
        AuditEvent(
            request_id="milestone-7",
            operation="startup",
            success=True,
            mcp_user="alice",
        )
    )

    assert (tmp_path / "alice.log").exists()
