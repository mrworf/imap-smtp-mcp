from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_docs_describe_streamable_http_limitations() -> None:
    deployment = (ROOT / "docs/deployment.md").read_text(encoding="utf-8")
    manual = (ROOT / "docs/manual_mcp_compat_suite.md").read_text(encoding="utf-8")

    for text in (deployment, manual):
        assert "Streamable HTTP" in text
        assert "not a strict legacy long-lived SSE" in text
        assert "Native stdio" in text


def test_manual_suite_docs_describe_csrf_and_source_checkout_launch() -> None:
    manual = (ROOT / "docs/manual_mcp_compat_suite.md").read_text(encoding="utf-8")

    assert "CSRF-protected authorize form path" in manual
    assert "GET /oauth/authorize" in manual
    assert "POST /oauth/authorize" in manual
    assert "PYTHONPATH" in manual
    assert "src" in manual
    assert "configured inbox and trash folder exist" in manual
    assert "creates a unique temporary test folder" in manual
    assert "re-searches for the unique per-run marker before copy and move" in manual


def test_env_example_uses_oauth_only_persistent_config() -> None:
    env_example = (ROOT / "env.example").read_text(encoding="utf-8")

    assert "APP_DATA_DIR=" in env_example
    assert "OAUTH_STORE_PATH=" in env_example
    assert "OAUTH_REFRESH_TOKEN_TTL_SECONDS=" in env_example
    assert "OAUTH_COOKIE_SECRET=replace-with-long-random-csrf-cookie-signing-secret" in env_example
    assert "MCP_TLS_CERT_FILE=" in env_example
    assert "MCP_TLS_KEY_FILE=" in env_example
    assert "MCP_DEBUG_UNREDACTED_LOGS=false" in env_example
    assert "MCP_APP_DISPLAY_NAME=Personal Email Connector" in env_example
    assert "MCP_APP_WEBSITE_URL=https://github.com/mrworf/imap-smtp-mcp" in env_example
    assert "MCP_APP_PRIVACY_POLICY_URL=" in env_example
    assert "MCP_APP_TERMS_OF_SERVICE_URL=" in env_example
    assert "SMTP_TIMEOUT_SECONDS=30" in env_example
    assert "SMTP_FROM_DOMAIN=example.com" in env_example
    assert "ACTION_CREATE_FOLDER=false" in env_example
    assert "ACTION_RENAME_FOLDER=false" in env_example
    assert "ACTION_DELETE_FOLDER=false" in env_example
    assert "MCP_" + "PRESHARED_KEY" not in env_example
    assert "MCP_" + "ALLOWED_USERS" not in env_example
    assert "USER_ALICE_" + "IMAP_USERNAME" not in env_example


def test_docs_explain_cookie_secret_usage() -> None:
    deployment = (ROOT / "docs/deployment.md").read_text(encoding="utf-8")
    security = (ROOT / "docs/security_operations.md").read_text(encoding="utf-8")

    for text in (deployment, security):
        assert "OAUTH_COOKIE_SECRET" in text
        assert "CSRF" in text
        assert "in-flight authorization forms" in text


def test_docs_describe_oauth_endpoint_proxy_rate_limits() -> None:
    deployment = (ROOT / "docs/deployment.md").read_text(encoding="utf-8")
    security = (ROOT / "docs/security_operations.md").read_text(encoding="utf-8")

    for text in (deployment, security):
        assert "GET /oauth/authorize" in text
        assert "POST /oauth/authorize" in text
        assert "POST /oauth/register" in text
        assert "POST /oauth/token" in text
        assert "reverse-proxy request/IP limits" in text

    assert "limit_req" in deployment
    assert "OAUTH_AUTHORIZE_CSRF_MAX_TOKENS" in security


def test_local_debug_docs_cover_shell_modes() -> None:
    local_debug_path = ROOT / "docs/local_debug.md"
    assert local_debug_path.exists()
    local_debug = local_debug_path.read_text(encoding="utf-8")
    deployment = (ROOT / "docs/deployment.md").read_text(encoding="utf-8")

    assert "reverse proxy runs somewhere else on your LAN or VPN" in local_debug
    assert "--host 0.0.0.0" in local_debug
    assert "--mode https" in local_debug
    assert "self-signed certificate" in local_debug
    assert "Local Shell Debugging](local_debug.md)" in deployment


def test_readme_describes_project_and_links_docs() -> None:
    readme_path = ROOT / "README.md"
    assert readme_path.exists()
    readme = readme_path.read_text(encoding="utf-8")

    assert "actions/workflows/ci.yml/badge.svg?branch=main" in readme
    assert '<img src="imap-smtp-mcp.png" alt="Personal Email Connector logo"' in readme
    assert "[![Docker image](https://img.shields.io/badge/GHCR-imap--smtp--mcp-2ea44f?logo=github)]" in readme
    assert "ghcr.io/mrworf/imap-smtp-mcp" in readme
    assert "github.com/mrworf/imap-smtp-mcp/pkgs/container/imap-smtp-mcp" in readme
    assert "ghcr.io/mrworf/imap-smtp-mcp/pkgs" not in readme
    assert "Docker image" in readme
    assert "ChatGPT-compatible remote MCP" in readme
    assert "encrypted" in readme
    assert "creating, renaming, and deleting folders" in readme
    assert "docs/deployment.md" in readme
    assert "docs/configuration.md" in readme
    assert "docs/example_prompts.md" in readme
    assert "docs/local_debug.md" in readme
    assert "docs/manual_mcp_compat_suite.md" in readme
    assert "IMPLEMENTATION_PLAN.md" not in readme


def test_docs_use_current_app_name() -> None:
    docs = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
    for path in docs:
        text = path.read_text(encoding="utf-8")
        assert "Personal Email Connector" in text
        assert "Personal IMAP/SMTP Mail Connector" not in text


def test_agent_instructions_are_self_contained() -> None:
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "IMPLEMENTATION_PLAN.md" not in agents


def test_configuration_reference_covers_environment_variables() -> None:
    config_path = ROOT / "docs/configuration.md"
    assert config_path.exists()
    config = config_path.read_text(encoding="utf-8")
    env_example = (ROOT / "env.example").read_text(encoding="utf-8")

    env_names = []
    for line in env_example.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        env_names.append(line.split("=", 1)[0])
    env_names.extend(["MCP_ALLOW_INSECURE_PUBLIC_URL", "OAUTH_USERNAME_CLAIM"])

    for name in env_names:
        assert name in config

    assert "MCP_COMPAT_TEST_EMAIL" in config
    assert "MCP_COMPAT_USE_EXISTING_SERVER" in config
    assert "not by the production server" in config


def test_configuration_docs_are_linked_and_stale_docs_removed() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    deployment = (ROOT / "docs/deployment.md").read_text(encoding="utf-8")

    assert "docs/configuration.md" in readme
    assert "Configuration Reference](configuration.md)" in deployment
    assert not (ROOT / "IMPLEMENTATION_PLAN.md").exists()
    assert not (ROOT / "docs/milestone4.md").exists()
    assert not (ROOT / "docs/milestone6.md").exists()


def test_security_docs_name_folder_action_flags() -> None:
    security = (ROOT / "docs/security_operations.md").read_text(encoding="utf-8")

    assert "ACTION_CREATE_FOLDER" in security
    assert "ACTION_RENAME_FOLDER" in security
    assert "ACTION_DELETE_FOLDER" in security


def test_docs_describe_captured_sender_identity() -> None:
    deployment = (ROOT / "docs/deployment.md").read_text(encoding="utf-8")
    manual = (ROOT / "docs/manual_mcp_compat_suite.md").read_text(encoding="utf-8")
    security = (ROOT / "docs/security_operations.md").read_text(encoding="utf-8")

    for text in (deployment, manual, security):
        assert "SMTP_FROM_DOMAIN" in text
    assert "cannot choose `From` or `Reply-To`" in deployment
    assert "sender_identity_override" in security
    assert "does not include `from_address`" in manual


def test_docs_describe_debug_unredacted_logging() -> None:
    deployment = (ROOT / "docs/deployment.md").read_text(encoding="utf-8")
    local_debug = (ROOT / "docs/local_debug.md").read_text(encoding="utf-8")
    security = (ROOT / "docs/security_operations.md").read_text(encoding="utf-8")

    for text in (deployment, local_debug, security):
        assert "MCP_DEBUG_UNREDACTED_LOGS" in text
        assert "traceback" in text.lower()
        assert "redact" in text.lower()


def test_example_prompts_cover_common_and_full_capability_flows() -> None:
    prompts_path = ROOT / "docs/example_prompts.md"
    assert prompts_path.exists()
    prompts = prompts_path.read_text(encoding="utf-8")

    assert '{"type":"since","value":"2026-05-13"}' in prompts
    assert "`text` is the intended full-message search type" in prompts
    assert "intended full-marker `search_emails` criteria" in prompts
    assert "Full Capability Smoke Prompt" in prompts
    assert "guarded skip" in prompts
    assert "call empty_trash only if Trash is confirmed to contain no messages except MCP-created messages" in prompts
    assert "Prefer the ChatGPT-friendly aliases `search_mail`, `get_recent_mail`, and `send_mail`" in prompts

    for capability in (
        "list_folders",
        "search_emails",
        "search_mail",
        "list_emails",
        "get_recent_mail",
        "read_email",
        "get_email_attachment",
        "get_sender_identity",
        "send_email",
        "send_mail",
        "mark_read_state",
        "move_email",
        "copy_email",
        "delete_email_permanent",
        "move_to_trash",
        "empty_trash",
        "create_folder",
        "rename_folder",
        "delete_folder",
    ):
        assert capability in prompts
