from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "manual_mcp_compat_suite.py"


def _load_manual_suite():
    spec = importlib.util.spec_from_file_location("manual_mcp_compat_suite_for_tests", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


manual_suite = _load_manual_suite()
SuiteConfig = manual_suite.SuiteConfig
_server_env = manual_suite._server_env


def test_manual_suite_server_env_is_oauth_only(tmp_path) -> None:
    config = SuiteConfig(
        server_command=("python", "-m", "imap_smtp_mcp.server"),
        host="127.0.0.1",
        port=8123,
        public_base_url="http://127.0.0.1:8123",
        test_email="test@example.com",
        imap_username="imap-user",
        imap_password="imap-pass",
        smtp_username="smtp-user",
        smtp_password="smtp-pass",
        inbox_folder="INBOX",
        test_folder="MCP_TEST",
        trash_folder="Trash",
        poll_attempts=1,
        poll_interval_seconds=1,
        use_existing_server=False,
    )
    env = _server_env(config, str(tmp_path))

    assert env["APP_DATA_DIR"] == str(tmp_path / "data")
    assert env["OAUTH_STORE_PATH"] == str(tmp_path / "data" / "oauth.sqlite3")
    assert "MCP_" + "ALLOWED_USERS" not in env
    assert "USER_OAUTH_" + "IMAP_USERNAME" not in env


def test_manual_suite_test_imports_with_src_only_pythonpath() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_manual_suite.py", "-k", "server_env_is_oauth_only"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
