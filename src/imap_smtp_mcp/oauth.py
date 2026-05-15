from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse, urlencode

from cryptography.fernet import Fernet, InvalidToken

from .config import AppConfig
from .imap_adapter import ImapAdapter, ImapAdapterError


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_CLIENT_NAME_LENGTH = 128
MAX_REDIRECT_URIS = 5
MAX_REDIRECT_URI_LENGTH = 2048
CONTROL_CHARS = frozenset(chr(value) for value in range(0x20)) | {"\x7f"}


class OAuthError(PermissionError):
    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    redirect_uris: tuple[str, ...]
    client_name: str


@dataclass(frozen=True)
class AuthorizationCode:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: tuple[str, ...]
    resource: str
    session_id: str
    subject: str
    expires_at: int
    used: bool = False


@dataclass(frozen=True)
class MailCredentials:
    imap_username: str
    imap_password: str
    smtp_username: str
    smtp_password: str
    sender_display_name: str | None = None
    sender_email: str | None = None


@dataclass(frozen=True)
class CredentialSession:
    session_id: str
    subject: str
    scopes: tuple[str, ...]
    created_at: int
    encrypted_credentials: str
    revoked: bool = False


@dataclass(frozen=True)
class RefreshTokenRecord:
    token_hash: str
    client_id: str
    session_id: str
    subject: str
    scopes: tuple[str, ...]
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True)
class TokenClaims:
    issuer: str
    audience: str
    subject: str
    scopes: tuple[str, ...]
    session_id: str
    expires_at: int


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


class TokenSigner:
    def __init__(self, signing_key: str) -> None:
        self._key = signing_key.encode("utf-8")

    def issue(self, claims: TokenClaims) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "iss": claims.issuer,
            "aud": claims.audience,
            "sub": claims.subject,
            "scope": " ".join(claims.scopes),
            "sid": claims.session_id,
            "exp": claims.expires_at,
            "iat": int(time.time()),
        }
        signing_input = ".".join(
            (
                _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
                _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
            )
        )
        signature = hmac.new(self._key, signing_input.encode("ascii"), hashlib.sha256).digest()
        return f"{signing_input}.{_b64url_encode(signature)}"

    def verify(self, token: str, *, issuer: str, audience: str, required_scopes: tuple[str, ...]) -> TokenClaims:
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")
        except ValueError as exc:
            raise OAuthError("invalid_token", "Malformed bearer token") from exc

        signing_input = f"{header_b64}.{payload_b64}"
        expected = hmac.new(self._key, signing_input.encode("ascii"), hashlib.sha256).digest()
        try:
            actual = _b64url_decode(signature_b64)
            payload = json.loads(_b64url_decode(payload_b64))
        except (ValueError, json.JSONDecodeError) as exc:
            raise OAuthError("invalid_token", "Malformed bearer token") from exc
        if not hmac.compare_digest(expected, actual):
            raise OAuthError("invalid_token", "Invalid bearer token signature")
        if payload.get("iss") != issuer:
            raise OAuthError("invalid_token", "Invalid bearer token issuer")
        if payload.get("aud") != audience:
            raise OAuthError("invalid_token", "Invalid bearer token audience")
        exp = int(payload.get("exp", 0))
        if exp <= int(time.time()):
            raise OAuthError("invalid_token", "Expired bearer token")
        scopes = tuple(str(payload.get("scope", "")).split())
        missing = [scope for scope in required_scopes if scope not in scopes]
        if missing:
            raise OAuthError("insufficient_scope", "Bearer token is missing required scope")
        session_id = str(payload.get("sid", ""))
        subject = str(payload.get("sub", ""))
        if not session_id or not subject:
            raise OAuthError("invalid_token", "Bearer token is missing required claims")
        return TokenClaims(
            issuer=issuer,
            audience=audience,
            subject=subject,
            scopes=scopes,
            session_id=session_id,
            expires_at=exp,
        )


class CredentialVault:
    def __init__(self, encryption_key: str | None = None) -> None:
        if encryption_key:
            key = encryption_key.encode("ascii")
        else:
            key = Fernet.generate_key()
        self._fernet = Fernet(key)

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode("ascii")

    def encrypt(self, credentials: MailCredentials) -> str:
        payload = json.dumps(credentials.__dict__, separators=(",", ":")).encode("utf-8")
        return self._fernet.encrypt(payload).decode("ascii")

    def decrypt(self, value: str) -> MailCredentials:
        try:
            payload = json.loads(self._fernet.decrypt(value.encode("ascii")))
        except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
            raise OAuthError("invalid_session", "Credential session could not be decrypted") from exc
        return MailCredentials(
            imap_username=str(payload["imap_username"]),
            imap_password=str(payload["imap_password"]),
            smtp_username=str(payload["smtp_username"]),
            smtp_password=str(payload["smtp_password"]),
            sender_display_name=str(payload["sender_display_name"]) if payload.get("sender_display_name") is not None else None,
            sender_email=str(payload["sender_email"]) if payload.get("sender_email") is not None else None,
        )


class OAuthStore:
    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id TEXT PRIMARY KEY,
                redirect_uris TEXT NOT NULL,
                client_name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS authorization_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                code_challenge_method TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource TEXT NOT NULL,
                session_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS credential_sessions (
                session_id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                encrypted_credentials TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                scopes TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save_client(self, client: OAuthClient) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO oauth_clients (client_id, redirect_uris, client_name) VALUES (?, ?, ?)",
            (client.client_id, json.dumps(list(client.redirect_uris)), client.client_name),
        )
        self._conn.commit()

    def get_client(self, client_id: str) -> OAuthClient | None:
        row = self._conn.execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)).fetchone()
        if row is None:
            return None
        return OAuthClient(client_id=row["client_id"], redirect_uris=tuple(json.loads(row["redirect_uris"])), client_name=row["client_name"])

    def save_code(self, code: AuthorizationCode) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO authorization_codes
            (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, resource, session_id, subject, expires_at, used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                code.code,
                code.client_id,
                code.redirect_uri,
                code.code_challenge,
                code.code_challenge_method,
                " ".join(code.scope),
                code.resource,
                code.session_id,
                code.subject,
                code.expires_at,
                int(code.used),
            ),
        )
        self._conn.commit()

    def get_code(self, code: str) -> AuthorizationCode | None:
        row = self._conn.execute("SELECT * FROM authorization_codes WHERE code = ?", (code,)).fetchone()
        if row is None:
            return None
        return AuthorizationCode(
            code=row["code"],
            client_id=row["client_id"],
            redirect_uri=row["redirect_uri"],
            code_challenge=row["code_challenge"],
            code_challenge_method=row["code_challenge_method"],
            scope=tuple(row["scope"].split()),
            resource=row["resource"],
            session_id=row["session_id"],
            subject=row["subject"],
            expires_at=int(row["expires_at"]),
            used=bool(row["used"]),
        )

    def mark_code_used(self, code: str) -> bool:
        cursor = self._conn.execute("UPDATE authorization_codes SET used = 1 WHERE code = ? AND used = 0", (code,))
        self._conn.commit()
        return cursor.rowcount == 1

    def save_session(self, session: CredentialSession) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO credential_sessions
            (session_id, subject, scopes, created_at, encrypted_credentials, revoked)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session.session_id, session.subject, " ".join(session.scopes), session.created_at, session.encrypted_credentials, int(session.revoked)),
        )
        self._conn.commit()

    def get_session(self, session_id: str) -> CredentialSession | None:
        row = self._conn.execute("SELECT * FROM credential_sessions WHERE session_id = ?", (session_id,)).fetchone()
        if row is None:
            return None
        return CredentialSession(
            session_id=row["session_id"],
            subject=row["subject"],
            scopes=tuple(row["scopes"].split()),
            created_at=int(row["created_at"]),
            encrypted_credentials=row["encrypted_credentials"],
            revoked=bool(row["revoked"]),
        )

    def revoke_session(self, session_id: str) -> None:
        self._conn.execute("UPDATE credential_sessions SET revoked = 1 WHERE session_id = ?", (session_id,))
        self._conn.commit()

    def save_refresh_token(self, token: RefreshTokenRecord) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO refresh_tokens
            (token_hash, client_id, session_id, subject, scopes, expires_at, revoked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (token.token_hash, token.client_id, token.session_id, token.subject, " ".join(token.scopes), token.expires_at, int(token.revoked)),
        )
        self._conn.commit()

    def get_refresh_token(self, token_hash: str) -> RefreshTokenRecord | None:
        row = self._conn.execute("SELECT * FROM refresh_tokens WHERE token_hash = ?", (token_hash,)).fetchone()
        if row is None:
            return None
        return RefreshTokenRecord(
            token_hash=row["token_hash"],
            client_id=row["client_id"],
            session_id=row["session_id"],
            subject=row["subject"],
            scopes=tuple(row["scopes"].split()),
            expires_at=int(row["expires_at"]),
            revoked=bool(row["revoked"]),
        )

    def revoke_refresh_token(self, token_hash: str) -> None:
        self._conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", (token_hash,))
        self._conn.commit()

    def cleanup_expired(self, now: int | None = None) -> None:
        cutoff = int(time.time()) if now is None else now
        self._conn.execute("DELETE FROM authorization_codes WHERE expires_at <= ?", (cutoff,))
        self._conn.execute("DELETE FROM refresh_tokens WHERE expires_at <= ?", (cutoff,))
        self._conn.commit()


ImapVerifier = Callable[[str, str], None]


class OAuthService:
    def __init__(
        self,
        config: AppConfig,
        *,
        store: OAuthStore | None = None,
        vault: CredentialVault | None = None,
        signer: TokenSigner | None = None,
        imap_verifier: ImapVerifier | None = None,
    ) -> None:
        self.config = config
        self.store = store or OAuthStore(config.oauth.store_path)
        self.vault = vault or CredentialVault(config.oauth.encryption_key or None)
        self.signer = signer or TokenSigner(config.oauth.signing_key)
        self._imap_verifier = imap_verifier or self._verify_imap_login

    def protected_resource_metadata(self) -> dict[str, object]:
        return {
            "resource": self.config.oauth.audience,
            "authorization_servers": [self.config.oauth.issuer],
            "scopes_supported": list(self.config.oauth.required_scopes),
            "resource_documentation": f"{self.config.oauth.public_base_url}/docs",
        }

    def authorization_server_metadata(self) -> dict[str, object]:
        base = self.config.oauth.public_base_url
        return {
            "issuer": self.config.oauth.issuer,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": list(self.config.oauth.required_scopes),
        }

    def register_client(self, payload: dict[str, object]) -> dict[str, object]:
        redirect_uris = payload.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            raise OAuthError("invalid_client_metadata", "redirect_uris must be a non-empty list")
        if len(redirect_uris) > MAX_REDIRECT_URIS:
            raise OAuthError("invalid_client_metadata", f"redirect_uris must include at most {MAX_REDIRECT_URIS} URLs")
        normalized: list[str] = []
        for uri in redirect_uris:
            if not isinstance(uri, str):
                raise OAuthError("invalid_redirect_uri", "redirect_uris must be absolute https URLs")
            _validate_redirect_uri(uri, self.config.oauth.allowed_redirect_uri_patterns)
            normalized.append(uri)
        raw_client_name = payload.get("client_name") or "ChatGPT"
        if not isinstance(raw_client_name, str):
            raise OAuthError("invalid_client_metadata", "client_name must be a string")
        client_name = raw_client_name.strip()
        if not client_name:
            raise OAuthError("invalid_client_metadata", "client_name must not be empty")
        if len(client_name) > MAX_CLIENT_NAME_LENGTH:
            raise OAuthError("invalid_client_metadata", f"client_name must be at most {MAX_CLIENT_NAME_LENGTH} characters")
        client_id = f"client-{secrets.token_urlsafe(24)}"
        client = OAuthClient(
            client_id=client_id,
            redirect_uris=tuple(normalized),
            client_name=client_name,
        )
        self.store.save_client(client)
        return {
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": list(client.redirect_uris),
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }

    def validate_authorize_request(self, query: dict[str, str]) -> OAuthClient:
        if query.get("response_type") != "code":
            raise OAuthError("unsupported_response_type", "response_type must be code")
        client_id = query.get("client_id", "")
        client = self.store.get_client(client_id)
        if client is None:
            raise OAuthError("invalid_client", "Unknown OAuth client")
        redirect_uri = query.get("redirect_uri", "")
        if redirect_uri not in client.redirect_uris:
            raise OAuthError("invalid_redirect_uri", "redirect_uri is not registered")
        if query.get("code_challenge_method") != "S256":
            raise OAuthError("invalid_request", "code_challenge_method must be S256")
        if not query.get("code_challenge"):
            raise OAuthError("invalid_request", "code_challenge is required")
        if query.get("resource") != self.config.oauth.audience:
            raise OAuthError("invalid_target", "resource does not match this MCP server")
        scopes = tuple(query.get("scope", "").split())
        if not scopes:
            raise OAuthError("invalid_scope", "scope is required")
        for scope in scopes:
            if scope not in self.config.oauth.required_scopes:
                raise OAuthError("invalid_scope", f"Unsupported scope: {scope}")
        return client

    def authorize_with_credentials(
        self,
        query: dict[str, str],
        *,
        imap_username: str,
        imap_password: str,
        smtp_username: str,
        smtp_password: str,
        sender_display_name: str,
        sender_email: str,
    ) -> str:
        self.validate_authorize_request(query)
        if not imap_username or not imap_password or not smtp_username or not smtp_password:
            raise OAuthError("access_denied", "IMAP and SMTP credentials are required")
        normalized_display_name = sender_display_name.strip()
        normalized_sender_email = sender_email.strip()
        if not normalized_display_name:
            raise OAuthError("access_denied", "Sender display name is required")
        if not normalized_sender_email or not EMAIL_PATTERN.match(normalized_sender_email):
            raise OAuthError("access_denied", "A valid outbound sender email is required")
        self._imap_verifier(imap_username, imap_password)
        scopes = tuple(query["scope"].split())
        session_id = f"sess-{secrets.token_urlsafe(24)}"
        encrypted = self.vault.encrypt(
            MailCredentials(
                imap_username=imap_username,
                imap_password=imap_password,
                smtp_username=smtp_username,
                smtp_password=smtp_password,
                sender_display_name=normalized_display_name,
                sender_email=normalized_sender_email,
            )
        )
        self.store.save_session(CredentialSession(
            session_id=session_id,
            subject=imap_username,
            scopes=scopes,
            created_at=int(time.time()),
            encrypted_credentials=encrypted,
        ))
        code = f"code-{secrets.token_urlsafe(24)}"
        self.store.save_code(AuthorizationCode(
            code=code,
            client_id=query["client_id"],
            redirect_uri=query["redirect_uri"],
            code_challenge=query["code_challenge"],
            code_challenge_method=query["code_challenge_method"],
            scope=scopes,
            resource=query["resource"],
            session_id=session_id,
            subject=imap_username,
            expires_at=int(time.time()) + self.config.oauth.authorization_code_ttl_seconds,
        ))
        separator = "&" if "?" in query["redirect_uri"] else "?"
        return f"{query['redirect_uri']}{separator}{urlencode({'code': code, 'state': query.get('state', '')})}"

    def exchange_code(self, payload: dict[str, str]) -> dict[str, object]:
        if payload.get("grant_type") == "refresh_token":
            return self.exchange_refresh_token(payload)
        if payload.get("grant_type") != "authorization_code":
            raise OAuthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
        code_value = payload.get("code", "")
        code = self.store.get_code(code_value)
        if code is None:
            raise OAuthError("invalid_grant", "Unknown authorization code")
        if code.used:
            self.store.revoke_session(code.session_id)
            raise OAuthError("invalid_grant", "Authorization code has already been used")
        if code.expires_at <= int(time.time()):
            raise OAuthError("invalid_grant", "Authorization code has expired")
        if payload.get("client_id") != code.client_id:
            raise OAuthError("invalid_client", "client_id does not match authorization code")
        if payload.get("redirect_uri") != code.redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri does not match authorization code")
        verifier = payload.get("code_verifier", "")
        challenge = _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
        if not hmac.compare_digest(challenge, code.code_challenge):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        if not self.store.mark_code_used(code.code):
            self.store.revoke_session(code.session_id)
            raise OAuthError("invalid_grant", "Authorization code has already been used")
        expires_at = int(time.time()) + self.config.oauth.access_token_ttl_seconds
        token = self.signer.issue(
            TokenClaims(
                issuer=self.config.oauth.issuer,
                audience=self.config.oauth.audience,
                subject=code.subject,
                scopes=code.scope,
                session_id=code.session_id,
                expires_at=expires_at,
            )
        )
        refresh_token = f"refresh-{secrets.token_urlsafe(32)}"
        self.store.save_refresh_token(
            RefreshTokenRecord(
                token_hash=self.hash_refresh_token(refresh_token),
                client_id=code.client_id,
                session_id=code.session_id,
                subject=code.subject,
                scopes=code.scope,
                expires_at=int(time.time()) + self.config.oauth.refresh_token_ttl_seconds,
            )
        )
        return {
            "access_token": token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self.config.oauth.access_token_ttl_seconds,
            "scope": " ".join(code.scope),
        }

    def exchange_refresh_token(self, payload: dict[str, str]) -> dict[str, object]:
        refresh_token = payload.get("refresh_token", "")
        client_id = payload.get("client_id", "")
        record = self.store.get_refresh_token(self.hash_refresh_token(refresh_token))
        if record is None:
            raise OAuthError("invalid_grant", "Unknown refresh token")
        if record.revoked:
            raise OAuthError("invalid_grant", "Refresh token has been revoked")
        if record.expires_at <= int(time.time()):
            raise OAuthError("invalid_grant", "Refresh token has expired")
        if record.client_id != client_id:
            raise OAuthError("invalid_client", "client_id does not match refresh token")
        session = self.store.get_session(record.session_id)
        if session is None or session.revoked:
            raise OAuthError("invalid_session", "Credential session is no longer available")

        self.store.revoke_refresh_token(record.token_hash)
        new_refresh_token = f"refresh-{secrets.token_urlsafe(32)}"
        self.store.save_refresh_token(
            RefreshTokenRecord(
                token_hash=self.hash_refresh_token(new_refresh_token),
                client_id=record.client_id,
                session_id=record.session_id,
                subject=record.subject,
                scopes=record.scopes,
                expires_at=int(time.time()) + self.config.oauth.refresh_token_ttl_seconds,
            )
        )
        expires_at = int(time.time()) + self.config.oauth.access_token_ttl_seconds
        access_token = self.signer.issue(
            TokenClaims(
                issuer=self.config.oauth.issuer,
                audience=self.config.oauth.audience,
                subject=record.subject,
                scopes=record.scopes,
                session_id=record.session_id,
                expires_at=expires_at,
            )
        )
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": self.config.oauth.access_token_ttl_seconds,
            "scope": " ".join(record.scopes),
        }

    def hash_refresh_token(self, refresh_token: str) -> str:
        return hmac.new(self.config.oauth.signing_key.encode("utf-8"), refresh_token.encode("utf-8"), hashlib.sha256).hexdigest()

    def authenticate_bearer(self, authorization_header: str | None, *, required_scopes: tuple[str, ...] = ()) -> tuple[TokenClaims, MailCredentials]:
        if not authorization_header or not authorization_header.startswith("Bearer "):
            raise OAuthError("invalid_token", "Missing bearer token")
        token = authorization_header.removeprefix("Bearer ").strip()
        scopes = required_scopes or ()
        claims = self.signer.verify(
            token,
            issuer=self.config.oauth.issuer,
            audience=self.config.oauth.audience,
            required_scopes=scopes,
        )
        session = self.store.get_session(claims.session_id)
        if session is None or session.revoked:
            raise OAuthError("invalid_session", "Credential session is no longer available")
        if claims.subject != session.subject:
            raise OAuthError("invalid_token", "Bearer token subject does not match credential session")
        credentials = self.vault.decrypt(session.encrypted_credentials)
        return claims, credentials

    def _verify_imap_login(self, username: str, password: str) -> None:
        try:
            client = ImapAdapter(self.config).connect(username, password)
            logout = getattr(client, "logout", None)
            if callable(logout):
                logout()
        except ImapAdapterError as exc:
            raise OAuthError("access_denied", "IMAP login failed") from exc


def _validate_redirect_uri(uri: str, allowed_patterns: tuple[str, ...]) -> None:
    if len(uri) > MAX_REDIRECT_URI_LENGTH:
        raise OAuthError("invalid_redirect_uri", f"redirect_uris must be at most {MAX_REDIRECT_URI_LENGTH} characters")
    if any(char in CONTROL_CHARS for char in uri) or " " in uri or "\\" in uri:
        raise OAuthError("invalid_redirect_uri", "redirect_uris must not contain whitespace, control characters, or backslashes")
    parsed = urlparse(uri)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise OAuthError("invalid_redirect_uri", "redirect_uris must be absolute https URLs without userinfo or fragments")
    if not allowed_patterns:
        raise OAuthError("invalid_redirect_uri", "No OAuth redirect URI allowlist is configured")
    if not any(re.fullmatch(pattern, uri) for pattern in allowed_patterns):
        raise OAuthError("invalid_redirect_uri", "redirect_uri is not allowed by this server")
