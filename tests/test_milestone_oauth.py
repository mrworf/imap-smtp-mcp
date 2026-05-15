from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest

from imap_smtp_mcp.config import ConfigError, load_config
from imap_smtp_mcp.oauth import CredentialSession, CredentialVault, MailCredentials, OAuthError, OAuthService, TokenClaims
from imap_smtp_mcp.server import is_trusted_proxy


def _challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")


@pytest.fixture
def oauth_env(monkeypatch, tmp_path):
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
        "MCP_PUBLIC_BASE_URL": "https://mcp.example.com",
        "OAUTH_ISSUER": "https://mcp.example.com",
        "OAUTH_AUDIENCE": "https://mcp.example.com",
        "OAUTH_SIGNING_KEY": "test-signing-key-0123456789abcdef",
        "OAUTH_COOKIE_SECRET": "test-cookie-secret-0123456789abcdef",
        "OAUTH_ENCRYPTION_KEY": CredentialVault.generate_key(),
        "OAUTH_REQUIRED_SCOPES": "mail:read mail:send mail:write",
        "OAUTH_ALLOWED_REDIRECT_URI_PATTERNS": r"https://chatgpt\.com/connector/oauth/cb",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def _service(config):
    return OAuthService(config, imap_verifier=lambda username, password: None)


def test_oauth_metadata_and_dcr(oauth_env):
    config = load_config()
    service = _service(config)

    protected = service.protected_resource_metadata()
    assert protected["resource"] == "https://mcp.example.com"
    assert protected["authorization_servers"] == ["https://mcp.example.com"]

    metadata = service.authorization_server_metadata()
    assert metadata["authorization_endpoint"] == "https://mcp.example.com/oauth/authorize"
    assert metadata["registration_endpoint"] == "https://mcp.example.com/oauth/register"
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]

    client = service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    assert client["client_id"].startswith("client-")


def test_dcr_rejects_non_https_redirect(oauth_env):
    service = _service(load_config())
    with pytest.raises(OAuthError, match="absolute https URLs"):
        service.register_client({"redirect_uris": ["http://chatgpt.test/cb"]})


@pytest.mark.parametrize(
    ("uri", "message"),
    [
        ("https://attacker.example/cb", "not allowed"),
        ("https://user@chatgpt.com/connector/oauth/cb", "userinfo"),
        ("https://chatgpt.com/connector/oauth/cb#frag", "fragments"),
        ("https://chatgpt.com/connector/oauth/cb\r\nX-Bad: yes", "control"),
        ("https://chatgpt.com/connector/oauth/cb with-space", "whitespace"),
        ("https://chatgpt.com\\connector\\oauth\\cb", "backslashes"),
    ],
)
def test_dcr_rejects_malformed_or_unlisted_redirects(oauth_env, uri, message):
    service = _service(load_config())
    with pytest.raises(OAuthError, match=message):
        service.register_client({"redirect_uris": [uri]})


def test_dcr_requires_redirect_allowlist(oauth_env, monkeypatch):
    monkeypatch.delenv("OAUTH_ALLOWED_REDIRECT_URI_PATTERNS")
    service = _service(load_config())
    with pytest.raises(OAuthError, match="allowlist"):
        service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})


def test_dcr_bounds_client_name_and_redirects(oauth_env):
    service = _service(load_config())
    with pytest.raises(OAuthError, match="client_name must be at most"):
        service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"], "client_name": "A" * 129})
    with pytest.raises(OAuthError, match="at most 5"):
        service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"] * 6})


def test_authorization_code_and_token_flow_preserves_separate_credentials(oauth_env):
    config = load_config()
    service = _service(config)
    client = service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    verifier = "verifier-value"
    query = {
        "response_type": "code",
        "client_id": str(client["client_id"]),
        "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
        "code_challenge": _challenge(verifier),
        "code_challenge_method": "S256",
        "scope": "mail:read mail:send",
        "resource": "https://mcp.example.com",
        "state": "state-1",
    }

    redirect = service.authorize_with_credentials(
        query,
        imap_username="imap-user",
        imap_password="imap-secret",
        smtp_username="smtp-user",
        smtp_password="smtp-secret",
        sender_display_name="Alice Sender",
        sender_email="alice@example.com",
    )
    assert redirect.startswith("https://chatgpt.com/connector/oauth/cb?")
    code = redirect.split("code=", 1)[1].split("&", 1)[0]

    token_response = service.exchange_code(
        {
            "grant_type": "authorization_code",
            "client_id": str(client["client_id"]),
            "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
            "code": code,
            "code_verifier": verifier,
        }
    )
    token = str(token_response["access_token"])
    assert "imap-secret" not in token
    assert "smtp-secret" not in token

    claims, credentials = service.authenticate_bearer(f"Bearer {token}", required_scopes=("mail:read",))
    assert claims.subject == "imap-user"
    assert credentials.imap_username == "imap-user"
    assert credentials.smtp_username == "smtp-user"
    assert credentials.imap_password == "imap-secret"
    assert credentials.smtp_password == "smtp-secret"
    assert credentials.sender_display_name == "Alice Sender"
    assert credentials.sender_email == "alice@example.com"


def test_authorize_requires_sender_identity(oauth_env):
    service = _service(load_config())
    client = service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    query = {
        "response_type": "code",
        "client_id": str(client["client_id"]),
        "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
        "code_challenge": _challenge("verifier"),
        "code_challenge_method": "S256",
        "scope": "mail:read mail:send",
        "resource": "https://mcp.example.com",
    }

    with pytest.raises(OAuthError, match="Sender display name is required"):
        service.authorize_with_credentials(
            query,
            imap_username="imap-user",
            imap_password="imap-secret",
            smtp_username="smtp-user",
            smtp_password="smtp-secret",
            sender_display_name=" ",
            sender_email="alice@example.com",
        )
    with pytest.raises(OAuthError, match="valid outbound sender email"):
        service.authorize_with_credentials(
            query,
            imap_username="imap-user",
            imap_password="imap-secret",
            smtp_username="smtp-user",
            smtp_password="smtp-secret",
            sender_display_name="Alice Sender",
            sender_email="not-an-email",
        )


def test_oauth_state_survives_service_restart(oauth_env):
    config = load_config()
    service = _service(config)
    client = service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    verifier = "restart-verifier"
    query = {
        "response_type": "code",
        "client_id": str(client["client_id"]),
        "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
        "code_challenge": _challenge(verifier),
        "code_challenge_method": "S256",
        "scope": "mail:read mail:send",
        "resource": "https://mcp.example.com",
    }
    redirect = service.authorize_with_credentials(
        query,
        imap_username="imap-user",
        imap_password="imap-secret",
        smtp_username="smtp-user",
        smtp_password="smtp-secret",
        sender_display_name="Alice Sender",
        sender_email="alice@example.com",
    )
    code = redirect.split("code=", 1)[1].split("&", 1)[0]

    restarted = _service(config)
    token_response = restarted.exchange_code(
        {
            "grant_type": "authorization_code",
            "client_id": str(client["client_id"]),
            "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
            "code": code,
            "code_verifier": verifier,
        }
    )
    claims, credentials = restarted.authenticate_bearer(f"Bearer {token_response['access_token']}", required_scopes=("mail:read",))
    assert claims.subject == "imap-user"
    assert credentials.smtp_username == "smtp-user"
    assert credentials.sender_email == "alice@example.com"


def test_refresh_token_rotation_and_storage_redaction(oauth_env):
    config = load_config()
    service = _service(config)
    client = service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    verifier = "refresh-verifier"
    query = {
        "response_type": "code",
        "client_id": str(client["client_id"]),
        "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
        "code_challenge": _challenge(verifier),
        "code_challenge_method": "S256",
        "scope": "mail:read mail:send",
        "resource": "https://mcp.example.com",
    }
    redirect = service.authorize_with_credentials(
        query,
        imap_username="imap-user",
        imap_password="imap-secret",
        smtp_username="smtp-user",
        smtp_password="smtp-secret",
        sender_display_name="Alice Sender",
        sender_email="alice@example.com",
    )
    code = redirect.split("code=", 1)[1].split("&", 1)[0]
    token_response = service.exchange_code(
        {
            "grant_type": "authorization_code",
            "client_id": str(client["client_id"]),
            "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
            "code": code,
            "code_verifier": verifier,
        }
    )
    refresh_token = str(token_response["refresh_token"])
    rotated = service.exchange_code({"grant_type": "refresh_token", "client_id": str(client["client_id"]), "refresh_token": refresh_token})
    assert rotated["refresh_token"] != refresh_token
    with pytest.raises(OAuthError, match="revoked"):
        service.exchange_code({"grant_type": "refresh_token", "client_id": str(client["client_id"]), "refresh_token": refresh_token})

    db_text = open(config.oauth.store_path, "rb").read().decode("latin1", errors="ignore")
    assert "imap-secret" not in db_text
    assert "smtp-secret" not in db_text
    assert refresh_token not in db_text


def test_token_exchange_rejects_wrong_pkce_and_reuse(oauth_env):
    service = _service(load_config())
    client = service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    query = {
        "response_type": "code",
        "client_id": str(client["client_id"]),
        "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
        "code_challenge": _challenge("right"),
        "code_challenge_method": "S256",
        "scope": "mail:read",
        "resource": "https://mcp.example.com",
    }
    redirect = service.authorize_with_credentials(
        query,
        imap_username="u",
        imap_password="p",
        smtp_username="s",
        smtp_password="sp",
        sender_display_name="Sender",
        sender_email="sender@example.com",
    )
    code = redirect.split("code=", 1)[1].split("&", 1)[0]
    payload = {
        "grant_type": "authorization_code",
        "client_id": str(client["client_id"]),
        "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
        "code": code,
        "code_verifier": "wrong",
    }
    with pytest.raises(OAuthError, match="PKCE verification failed"):
        service.exchange_code(payload)

    payload["code_verifier"] = "right"
    token_response = service.exchange_code(payload)
    with pytest.raises(OAuthError, match="already been used"):
        service.exchange_code(payload)
    with pytest.raises(OAuthError, match="Credential session is no longer available"):
        service.authenticate_bearer(f"Bearer {token_response['access_token']}", required_scopes=("mail:read",))


def test_token_exchange_rejects_non_ascii_pkce(oauth_env):
    service = _service(load_config())
    client = service.register_client({"redirect_uris": ["https://chatgpt.com/connector/oauth/cb"]})
    query = {
        "response_type": "code",
        "client_id": str(client["client_id"]),
        "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
        "code_challenge": _challenge("right"),
        "code_challenge_method": "S256",
        "scope": "mail:read",
        "resource": "https://mcp.example.com",
    }
    redirect = service.authorize_with_credentials(
        query,
        imap_username="u",
        imap_password="p",
        smtp_username="s",
        smtp_password="sp",
        sender_display_name="Sender",
        sender_email="sender@example.com",
    )
    code = redirect.split("code=", 1)[1].split("&", 1)[0]

    with pytest.raises(OAuthError, match="code_verifier must be ASCII"):
        service.exchange_code(
            {
                "grant_type": "authorization_code",
                "client_id": str(client["client_id"]),
                "redirect_uri": "https://chatgpt.com/connector/oauth/cb",
                "code": code,
                "code_verifier": "snowman-\u2603",
            }
        )


def test_expired_token_and_missing_scope_rejected(oauth_env):
    config = load_config()
    service = _service(config)
    token = service.signer.issue(
        claims=TokenClaims(
            issuer=config.oauth.issuer,
            audience=config.oauth.audience,
            subject="u",
            scopes=("mail:read",),
            session_id="missing",
            expires_at=int(time.time()) - 1,
        )
    )
    with pytest.raises(OAuthError, match="Expired bearer token"):
        service.authenticate_bearer(f"Bearer {token}", required_scopes=("mail:read",))


def test_bearer_token_subject_must_match_session(oauth_env):
    config = load_config()
    service = _service(config)
    encrypted = service.vault.encrypt(
        MailCredentials(
            imap_username="real-user",
            imap_password="imap-password",
            smtp_username="smtp-user",
            smtp_password="smtp-password",
            sender_display_name="Sender",
            sender_email="sender@example.com",
        )
    )
    service.store.save_session(
        CredentialSession(
            session_id="sess-real",
            subject="real-user",
            scopes=("mail:read",),
            created_at=int(time.time()),
            encrypted_credentials=encrypted,
        )
    )
    token = service.signer.issue(
        TokenClaims(
            issuer=config.oauth.issuer,
            audience=config.oauth.audience,
            subject="forged-user",
            scopes=("mail:read",),
            session_id="sess-real",
            expires_at=int(time.time()) + 60,
        )
    )

    with pytest.raises(OAuthError, match="subject does not match"):
        service.authenticate_bearer(f"Bearer {token}", required_scopes=("mail:read",))


def test_proxy_config_and_public_url_validation(oauth_env, monkeypatch):
    monkeypatch.setenv("MCP_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("MCP_ALLOWED_PROXY_CIDRS", "10.0.0.0/8,127.0.0.1/32")
    config = load_config()
    assert is_trusted_proxy(config, "10.1.2.3")
    assert not is_trusted_proxy(config, "192.168.1.10")

    monkeypatch.setenv("MCP_PUBLIC_BASE_URL", "http://mcp.example.com")
    with pytest.raises(ConfigError, match="MCP_PUBLIC_BASE_URL must use https"):
        load_config()


def test_oauth_secrets_must_be_strong_without_dev_escape_hatch(oauth_env, monkeypatch):
    monkeypatch.setenv("OAUTH_SIGNING_KEY", "short")
    with pytest.raises(ConfigError, match="OAUTH_SIGNING_KEY"):
        load_config()

    monkeypatch.setenv("OAUTH_SIGNING_KEY", "strong-signing-key-0123456789abcdef")
    monkeypatch.setenv("OAUTH_COOKIE_SECRET", "short")
    with pytest.raises(ConfigError, match="OAUTH_COOKIE_SECRET"):
        load_config()

    monkeypatch.setenv("OAUTH_COOKIE_SECRET", "strong-cookie-secret-0123456789abcdef")
    monkeypatch.delenv("OAUTH_ENCRYPTION_KEY")
    with pytest.raises(ConfigError, match="OAUTH_ENCRYPTION_KEY"):
        load_config()


def test_oauth_dev_insecure_secrets_allows_local_defaults(oauth_env, monkeypatch):
    monkeypatch.delenv("OAUTH_SIGNING_KEY")
    monkeypatch.delenv("OAUTH_COOKIE_SECRET")
    monkeypatch.delenv("OAUTH_ENCRYPTION_KEY")
    monkeypatch.setenv("OAUTH_DEV_INSECURE_SECRETS", "true")

    config = load_config()

    assert config.oauth.dev_insecure_secrets is True
    assert config.oauth.signing_key == "dev-signing-key"


def test_smtp_from_domain_validation(oauth_env, monkeypatch):
    monkeypatch.setenv("SMTP_FROM_DOMAIN", "Example.COM")
    assert load_config().smtp_from_domain == "example.com"

    monkeypatch.setenv("SMTP_FROM_DOMAIN", "https://example.com")
    with pytest.raises(ConfigError, match="SMTP_FROM_DOMAIN must be a bare domain"):
        load_config()


def test_debug_unredacted_logs_flag_validation(oauth_env, monkeypatch):
    monkeypatch.setenv("MCP_DEBUG_UNREDACTED_LOGS", "true")
    assert load_config().debug_unredacted_logs is True

    monkeypatch.setenv("MCP_DEBUG_UNREDACTED_LOGS", "wat")
    with pytest.raises(ConfigError, match="Invalid boolean for MCP_DEBUG_UNREDACTED_LOGS"):
        load_config()


def test_invalid_oauth_ttl_rejected(oauth_env, monkeypatch):
    monkeypatch.setenv("OAUTH_ACCESS_TOKEN_TTL_SECONDS", "0")
    with pytest.raises(ConfigError, match="OAUTH_ACCESS_TOKEN_TTL_SECONDS must be > 0"):
        load_config()


def test_internal_https_requires_cert_and_key(oauth_env, monkeypatch):
    monkeypatch.setenv("MCP_INTERNAL_HTTPS", "true")
    with pytest.raises(ConfigError, match="MCP_INTERNAL_HTTPS requires MCP_TLS_CERT_FILE and MCP_TLS_KEY_FILE"):
        load_config()


def test_token_payload_does_not_contain_passwords(oauth_env):
    service = _service(load_config())
    vault = CredentialVault(service.config.oauth.encryption_key)
    encrypted = vault.encrypt(
        MailCredentials(
            imap_username="u",
            imap_password="imap-password",
            smtp_username="s",
            smtp_password="smtp-password",
            sender_display_name="Sender",
            sender_email="sender@example.com",
        )
    )
    assert "imap-password" not in encrypted
    assert "smtp-password" not in encrypted
    decoded = vault.decrypt(encrypted)
    assert decoded.imap_password == "imap-password"
    assert decoded.sender_email == "sender@example.com"


def test_credential_vault_decrypts_old_sessions_without_sender_identity(oauth_env):
    vault = CredentialVault(load_config().oauth.encryption_key)
    legacy_payload = {
        "imap_username": "u",
        "imap_password": "imap-password",
        "smtp_username": "s",
        "smtp_password": "smtp-password",
    }
    encrypted = vault._fernet.encrypt(json.dumps(legacy_payload, separators=(",", ":")).encode("utf-8")).decode("ascii")

    decoded = vault.decrypt(encrypted)

    assert decoded.sender_display_name is None
    assert decoded.sender_email is None
