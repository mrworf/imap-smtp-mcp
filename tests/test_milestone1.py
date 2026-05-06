import pytest

from imap_smtp_mcp.auth import AuthError, authenticate_user
from imap_smtp_mcp.capabilities import CapabilityError, ensure_action_enabled
from imap_smtp_mcp.config import ConfigError, load_config


@pytest.fixture
def base_env(monkeypatch):
    env = {
        "MCP_ALLOWED_USERS": "alice",
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_MODE": "starttls",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "SMTP_FROM_ADDRESS": "sender@example.com",
        "IMAP_TLS_VERIFY": "true",
        "IMAP_MAX_RETRIES": "2",
        "ACTION_LIST_FOLDERS": "true",
        "ACTION_SEARCH_EMAILS": "true",
        "ACTION_SEND_EMAIL": "false",
        "USER_ALICE_IMAP_USERNAME": "alice-imap",
        "USER_ALICE_IMAP_PASSWORD": "imap-pass",
        "USER_ALICE_SMTP_USERNAME": "alice-smtp",
        "USER_ALICE_SMTP_PASSWORD": "smtp-pass",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_valid_config_loads(base_env):
    config = load_config()
    assert config.imap.port == 993
    assert config.smtp.mode.value == "starttls"


def test_missing_required_env_fails(monkeypatch):
    monkeypatch.delenv("MCP_ALLOWED_USERS", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_invalid_port_fails(base_env, monkeypatch):
    monkeypatch.setenv("IMAP_PORT", "99999")
    with pytest.raises(ConfigError):
        load_config()


def test_unauthorized_user_rejected(base_env):
    config = load_config()
    with pytest.raises(AuthError):
        authenticate_user("mallory", config)


def test_authorized_user_accepted(base_env):
    config = load_config()
    user = authenticate_user("alice", config)
    assert user.credentials.imap_username == "alice-imap"


def test_imap_smtp_credentials_separate(base_env):
    config = load_config()
    creds = config.users["alice"]
    assert creds.imap_username != creds.smtp_username


def test_disabled_action_rejected_before_network_call(base_env):
    config = load_config()
    with pytest.raises(CapabilityError):
        ensure_action_enabled("send_email", config)
