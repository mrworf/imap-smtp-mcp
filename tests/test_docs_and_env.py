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


def test_env_example_uses_oauth_only_persistent_config() -> None:
    env_example = (ROOT / "env.example").read_text(encoding="utf-8")

    assert "APP_DATA_DIR=" in env_example
    assert "OAUTH_STORE_PATH=" in env_example
    assert "OAUTH_REFRESH_TOKEN_TTL_SECONDS=" in env_example
    assert "OAUTH_COOKIE_SECRET=replace-with-long-random-csrf-cookie-signing-secret" in env_example
    assert "MCP_TLS_CERT_FILE=" in env_example
    assert "MCP_TLS_KEY_FILE=" in env_example
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
