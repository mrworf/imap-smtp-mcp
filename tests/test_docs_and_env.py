from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _documentation_paths() -> list[Path]:
    return [
        ROOT / "AGENTS.md",
        ROOT / "README.md",
        ROOT / "INTEGRATIONS.md",
        ROOT / "env.example",
        *sorted((ROOT / "docs").glob("*.md")),
    ]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_configuration_reference_covers_environment_variables() -> None:
    config = _read(ROOT / "docs/configuration.md")
    env_example = _read(ROOT / "env.example")

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


def test_documentation_links_are_current_and_not_redundant() -> None:
    readme = _read(ROOT / "README.md")
    deployment = _read(ROOT / "docs/deployment.md")
    config = _read(ROOT / "docs/configuration.md")

    assert (ROOT / "INTEGRATIONS.md").exists()
    assert "INTEGRATIONS.md" in readme
    assert "Integration Guide](../INTEGRATIONS.md)" in deployment
    assert "Integration Guide](../INTEGRATIONS.md)" in config
    assert "### Quirk with ChatGPT" not in readme
    assert "https://chatgpt\\.com/connector/oauth/cb" not in "\n".join(
        _read(path) for path in _documentation_paths()
    )
    assert not (ROOT / "IMPLEMENTATION_PLAN.md").exists()
    assert not (ROOT / "docs/milestone4.md").exists()
    assert not (ROOT / "docs/milestone6.md").exists()


def test_integration_guide_tracks_supported_and_untested_clients() -> None:
    integrations = _read(ROOT / "INTEGRATIONS.md")

    assert "ChatGPT is the primary tested integration target" in integrations
    for client in ("Claude", "Mistral Le Chat", "Perplexity", "Other MCP Clients"):
        assert f"## {client}" in integrations
    assert (
        "OAUTH_ALLOWED_REDIRECT_URI_PATTERNS=^https://chatgpt\\.com/connector/oauth/[A-Za-z0-9_-]+$"
        in integrations
    )


def test_docs_use_current_app_name_consistently() -> None:
    for path in [ROOT / "README.md", ROOT / "INTEGRATIONS.md", *sorted((ROOT / "docs").glob("*.md"))]:
        text = _read(path)
        assert "Personal Email Connector" in text
        assert "Personal IMAP/SMTP Mail Connector" not in text


def test_documentation_has_no_obvious_real_sensitive_values() -> None:
    combined = "\n".join(_read(path) for path in _documentation_paths())

    assert not re.search(r"\b\d{3}-\d{2}-\d{4}\b", combined)
    assert not _contains_luhn_credit_card(combined)
    assert "password123" not in combined.lower()
    assert "BEGIN PRIVATE KEY" not in combined

    for name, value in _env_assignments(combined):
        if not _looks_sensitive_env_name(name) or value in {"", "false", "true"}:
            continue
        assert _is_placeholder_value(value), f"{name} must use placeholder-safe documentation"


def test_documentation_has_no_obvious_production_configuration() -> None:
    combined = "\n".join(_read(path) for path in _documentation_paths())

    assert "mail-mcp.example.com" in combined
    assert "test-mailbox@example.com" in combined
    assert not re.search(r"https://(?![^/\s]*example\.com)[^/\s]*\.(?:corp|internal)\b", combined)
    assert not re.search(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b", combined)


def _env_assignments(text: str) -> list[tuple[str, str]]:
    assignments = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", name):
            assignments.append((name, value.strip()))
    return assignments


def _looks_sensitive_env_name(name: str) -> bool:
    sensitive_names = {
        "OAUTH_SIGNING_KEY",
        "OAUTH_COOKIE_SECRET",
        "OAUTH_ENCRYPTION_KEY",
        "MCP_COMPAT_IMAP_PASSWORD",
        "MCP_COMPAT_SMTP_PASSWORD",
    }
    return name in sensitive_names or name.endswith("_PASSWORD")


def _is_placeholder_value(value: str) -> bool:
    placeholder_markers = (
        "<",
        "replace-with",
        "example",
        "fake",
        "your-",
        "YOUR_",
        "$",
        "/run/secrets/",
    )
    return any(marker in value for marker in placeholder_markers)


def _contains_luhn_credit_card(text: str) -> bool:
    for match in re.finditer(r"\b(?:\d[ -]?){13,19}\b", text):
        digits = re.sub(r"\D", "", match.group(0))
        if len(digits) < 13:
            continue
        if _luhn_valid(digits):
            return True
    return False


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0
