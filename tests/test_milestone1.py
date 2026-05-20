import pytest

from imap_smtp_mcp.attachments import DEFAULT_BLOCKED_EXTENSIONS, DEFAULT_BLOCKED_MIME_TYPES
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
    assert config.attachment_policy.max_count == 10
    assert config.attachment_policy.max_bytes == 1_048_576
    assert config.attachment_policy.blocked_mime_types == DEFAULT_BLOCKED_MIME_TYPES
    assert config.attachment_policy.blocked_extensions == DEFAULT_BLOCKED_EXTENSIONS
    assert config.max_json_body_bytes > 1_048_576
    assert config.app_metadata.display_name == "Personal Email Connector"
    assert config.app_metadata.description == "Find, read, organize, and send email from your configured IMAP/SMTP mailbox."
    assert config.app_metadata.website_url == "https://github.com/mrworf/imap-smtp-mcp"
    assert config.app_metadata.privacy_policy_url is None
    assert config.app_metadata.terms_of_service_url is None


def test_app_metadata_overrides_load(base_env, monkeypatch):
    monkeypatch.setenv("MCP_APP_DISPLAY_NAME", "Team Email")
    monkeypatch.setenv("MCP_APP_DESCRIPTION", "Search and send team mail.")
    monkeypatch.setenv("MCP_APP_WEBSITE_URL", "https://mail.example.com/docs")
    monkeypatch.setenv("MCP_APP_PRIVACY_POLICY_URL", "https://mail.example.com/privacy")
    monkeypatch.setenv("MCP_APP_TERMS_OF_SERVICE_URL", "https://mail.example.com/terms")

    config = load_config()

    assert config.app_metadata.display_name == "Team Email"
    assert config.app_metadata.description == "Search and send team mail."
    assert config.app_metadata.website_url == "https://mail.example.com/docs"
    assert config.app_metadata.privacy_policy_url == "https://mail.example.com/privacy"
    assert config.app_metadata.terms_of_service_url == "https://mail.example.com/terms"


@pytest.mark.parametrize(
    ("name", "value", "message"),
    (
        ("MCP_APP_DISPLAY_NAME", " ", "MCP_APP_DISPLAY_NAME must not be empty"),
        ("MCP_APP_DESCRIPTION", "", "MCP_APP_DESCRIPTION must not be empty"),
        ("MCP_APP_WEBSITE_URL", "http://mail.example.com", "MCP_APP_WEBSITE_URL must be an absolute https URL"),
        ("MCP_APP_PRIVACY_POLICY_URL", "/privacy", "MCP_APP_PRIVACY_POLICY_URL must be an absolute https URL"),
        ("MCP_APP_TERMS_OF_SERVICE_URL", "not-a-url", "MCP_APP_TERMS_OF_SERVICE_URL must be an absolute https URL"),
    ),
)
def test_app_metadata_rejects_invalid_values(base_env, monkeypatch, name, value, message):
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError, match=message):
        load_config()


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


def test_attachment_policy_overrides_and_empty_blocklists(base_env, monkeypatch):
    monkeypatch.setenv("MCP_ATTACHMENT_MAX_COUNT", "2")
    monkeypatch.setenv("MCP_ATTACHMENT_MAX_BYTES", "512")
    monkeypatch.setenv("MCP_ATTACHMENT_BLOCKED_MIME_TYPES", "")
    monkeypatch.setenv("MCP_ATTACHMENT_BLOCKED_EXTENSIONS", "")

    config = load_config()

    assert config.attachment_policy.max_count == 2
    assert config.attachment_policy.max_bytes == 512
    assert config.attachment_policy.blocked_mime_types == ()
    assert config.attachment_policy.blocked_extensions == ()


def test_attachment_policy_normalizes_blocklists(base_env, monkeypatch):
    monkeypatch.setenv("MCP_ATTACHMENT_BLOCKED_MIME_TYPES", "Text/HTML; charset=utf-8, APPLICATION/JAVASCRIPT")
    monkeypatch.setenv("MCP_ATTACHMENT_BLOCKED_EXTENSIONS", "HTML, .JS")

    config = load_config()

    assert config.attachment_policy.blocked_mime_types == ("text/html", "application/javascript")
    assert config.attachment_policy.blocked_extensions == (".html", ".js")


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("MCP_ATTACHMENT_MAX_COUNT", "-1", "MCP_ATTACHMENT_MAX_COUNT must be >= 0"),
        ("MCP_ATTACHMENT_MAX_BYTES", "0", "MCP_ATTACHMENT_MAX_BYTES must be > 0"),
        ("MCP_ATTACHMENT_BLOCKED_MIME_TYPES", "text html", "Invalid MIME type"),
        ("MCP_ATTACHMENT_BLOCKED_EXTENSIONS", ".", "Invalid extension"),
    ],
)
def test_attachment_policy_rejects_invalid_values(base_env, monkeypatch, name, value, message):
    monkeypatch.setenv(name, value)

    with pytest.raises(ConfigError, match=message):
        load_config()


def test_attachment_policy_rejects_unreasonable_json_body_limit(base_env, monkeypatch):
    monkeypatch.setenv("MCP_ATTACHMENT_MAX_COUNT", "200")
    monkeypatch.setenv("MCP_ATTACHMENT_MAX_BYTES", str(10 * 1024 * 1024))

    with pytest.raises(ConfigError, match="computed MCP JSON body limit exceeds"):
        load_config()
