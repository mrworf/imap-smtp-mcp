import pytest

from imap_smtp_mcp.capabilities import CapabilityError, ensure_action_enabled
from imap_smtp_mcp.config import ConfigError, load_config


@pytest.fixture
def base_env(monkeypatch):
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
        "ACTION_SEND_EMAIL": "false",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_valid_config_loads(base_env):
    config = load_config()
    assert config.imap.port == 993
    assert config.smtp.mode.value == "starttls"
    assert config.action_flags["read_email"] is True
    assert config.action_flags["send_email"] is False
    assert config.action_flags["delete_email_permanent"] is False
    assert config.action_flags["empty_trash"] is False
    assert config.action_flags["delete_folder"] is False


def test_missing_required_env_fails(monkeypatch):
    monkeypatch.delenv("IMAP_HOST", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_invalid_port_fails(base_env, monkeypatch):
    monkeypatch.setenv("IMAP_PORT", "99999")
    with pytest.raises(ConfigError):
        load_config()


def test_oauth_config_loads_without_static_users(base_env):
    config = load_config()
    assert config.oauth.audience == "http://127.0.0.1:8000"
    assert config.oauth.store_path.endswith("/oauth.sqlite3")


def test_disabled_action_rejected_before_network_call(base_env):
    config = load_config()
    with pytest.raises(CapabilityError):
        ensure_action_enabled("send_email", config)


def test_refresh_token_ttl_must_be_positive(base_env, monkeypatch):
    monkeypatch.setenv("OAUTH_REFRESH_TOKEN_TTL_SECONDS", "0")
    with pytest.raises(ConfigError, match="OAUTH_REFRESH_TOKEN_TTL_SECONDS must be > 0"):
        load_config()
