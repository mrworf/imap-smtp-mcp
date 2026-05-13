from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "run_debug_server.py"


def _load_debug_script():
    spec = importlib.util.spec_from_file_location("run_debug_server_for_tests", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


debug_script = _load_debug_script()


def _mail_env() -> dict[str, str]:
    return {
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_MODE": "starttls",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
    }


def test_reverse_proxy_mode_resolves_runtime_paths_and_custom_bind(tmp_path) -> None:
    config = debug_script.parse_args(
        [
            "--mode",
            "reverse-proxy",
            "--host",
            "0.0.0.0",
            "--port",
            "8123",
            "--public-base-url",
            "https://mail-mcp.example.com",
            "--runtime-dir",
            str(tmp_path),
            "--print-env",
        ]
    )
    env = debug_script.build_env(config, _mail_env())
    rendered = debug_script.render_env(env)

    assert env["MCP_HOST"] == "0.0.0.0"
    assert env["MCP_PORT"] == "8123"
    assert env["MCP_PUBLIC_BASE_URL"] == "https://mail-mcp.example.com"
    assert env["MCP_ALLOW_INSECURE_PUBLIC_URL"] == "true"
    assert str(ROOT / "src") in env["PYTHONPATH"].split(os.pathsep)
    assert env["APP_DATA_DIR"] == str(tmp_path / "data")
    assert env["OAUTH_STORE_PATH"] == str(tmp_path / "data" / "oauth.sqlite3")
    assert "MCP_HOST=0.0.0.0" in rendered
    assert "MCP_PORT=8123" in rendered
    assert "OAUTH_SIGNING_KEY=[REDACTED]" in rendered
    assert debug_script.warning_for_host("0.0.0.0")


def test_loopback_host_has_no_warning() -> None:
    assert debug_script.warning_for_host("127.0.0.1") is None


def test_https_mode_uses_existing_cert_and_key(tmp_path) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    config = debug_script.parse_args(
        [
            "--mode",
            "https",
            "--cert-file",
            str(cert),
            "--key-file",
            str(key),
            "--runtime-dir",
            str(tmp_path / "runtime"),
        ]
    )
    env = debug_script.build_env(config, _mail_env())

    assert env["MCP_INTERNAL_HTTPS"] == "true"
    assert env["MCP_TLS_CERT_FILE"] == str(cert)
    assert env["MCP_TLS_KEY_FILE"] == str(key)
    assert env["MCP_PUBLIC_BASE_URL"].startswith("https://")


def test_https_mode_fails_without_cert_key_or_openssl(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(debug_script.shutil, "which", lambda name: None)
    config = debug_script.parse_args(["--mode", "https", "--runtime-dir", str(tmp_path)])

    try:
        debug_script.build_env(config, _mail_env())
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "openssl" in str(exc)


def test_missing_mail_env_fails_clearly(tmp_path) -> None:
    config = debug_script.parse_args(["--runtime-dir", str(tmp_path)])
    try:
        debug_script.build_env(config, {})
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "missing required mail environment variables" in str(exc)
