#!/usr/bin/env python3
"""Manual compatibility suite for IMAP/SMTP MCP servers.

WARNING: This script is destructive and intended only for dedicated test inboxes.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Any

REQUIRED_CONFIRMATION = "I UNDERSTAND THIS WILL MODIFY MAIL"


@dataclass
class MCPClient:
    command: str

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": f"req-{secrets.token_hex(4)}",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        proc = subprocess.run(
            self.command,
            shell=True,
            input=json.dumps(payload) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"MCP command failed for {name}: {proc.stderr.strip()}")

        response_line = _extract_json_line(proc.stdout)
        response = json.loads(response_line)
        if "error" in response:
            raise RuntimeError(f"MCP tool {name} returned error: {response['error']}")
        return response.get("result")


def _extract_json_line(output: str) -> str:
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return line
    raise RuntimeError(f"No JSON response line found in output: {output!r}")


def _manual_gate() -> None:
    if not sys.stdin.isatty():
        raise RuntimeError("Refusing to run: interactive TTY required (piped input is not accepted).")

    print("=" * 72)
    print("DANGER: THIS WILL CREATE, MOVE, DELETE, AND EXPUNGE EMAILS")
    print("Only run against a dedicated non-production mailbox and email account.")
    print("=" * 72)
    phrase = input(f"Type exact phrase to continue: {REQUIRED_CONFIRMATION}\n> ").strip()
    if phrase != REQUIRED_CONFIRMATION:
        raise RuntimeError("Confirmation phrase did not match exactly. Aborting.")

    for i in (3, 2, 1):
        print(f"Starting in {i}s...")
        time.sleep(1)


def _extract_uids(search_result: Any) -> list[str]:
    if isinstance(search_result, dict):
        for key in ("uids", "ids", "result"):
            if isinstance(search_result.get(key), list):
                return [str(v) for v in search_result[key]]
    if isinstance(search_result, list):
        return [str(v) for v in search_result]
    return []


def _extract_email_address(value: str) -> str:
    _, addr = parseaddr(value)
    return addr or value


def run_suite(args: argparse.Namespace) -> None:
    _manual_gate()
    client = MCPClient(args.mcp_command)

    marker = f"mcp-compat-{int(time.time())}-{secrets.token_hex(3)}"
    test_folder = args.test_folder

    print("[1/12] list_folders")
    folders = client.call_tool("list_folders", {})
    print(f"  folders response: {folders}")

    print("[2/12] send_email (self-addressed)")
    body = f"manual compatibility test marker: {marker}"
    client.call_tool(
        "send_email",
        {
            "to_addresses": [args.test_email],
            "subject": f"MCP compatibility {marker}",
            "body_text": body,
        },
    )

    print("[3/12] search_emails")
    found_uid = None
    for _ in range(args.poll_attempts):
        search_result = client.call_tool("search_emails", {"folder": args.inbox_folder, "query": marker, "limit": 10})
        uids = _extract_uids(search_result)
        if uids:
            found_uid = uids[-1]
            break
        time.sleep(args.poll_interval_seconds)
    if not found_uid:
        raise RuntimeError("Sent message was not discovered in inbox during polling window.")

    print("[4/12] list_emails")
    listed = client.call_tool("list_emails", {"folder": args.inbox_folder, "offset": 0, "limit": 50})
    print(f"  listed response length: {len(listed) if isinstance(listed, list) else 'n/a'}")

    print("[5/12] read_email")
    read_result = client.call_tool("read_email", {"folder": args.inbox_folder, "uid": found_uid, "max_chars": 50000})
    read_text = json.dumps(read_result)
    if marker not in read_text:
        raise RuntimeError("Read-email payload did not contain expected marker text.")
    sender = _extract_email_address(str(read_result.get("from_address", ""))) if isinstance(read_result, dict) else ""
    if sender and sender.lower() != args.test_email.lower():
        raise RuntimeError(f"Unexpected sender address: {sender} != {args.test_email}")

    print("[6/12] copy_email")
    client.call_tool("copy_email", {"source_folder": args.inbox_folder, "target_folder": test_folder, "uid": found_uid})

    print("[7/12] move_email")
    client.call_tool("move_email", {"source_folder": args.inbox_folder, "target_folder": test_folder, "uid": found_uid})

    print("[8/12] search copied/moved in test folder")
    moved_search = client.call_tool("search_emails", {"folder": test_folder, "query": marker, "limit": 20})
    moved_uids = _extract_uids(moved_search)
    if not moved_uids:
        raise RuntimeError("Could not find message in target test folder after move/copy.")
    test_uid = moved_uids[-1]

    print("[9/12] mark_read_state true/false")
    client.call_tool("mark_read_state", {"folder": test_folder, "uid": test_uid, "is_read": True})
    client.call_tool("mark_read_state", {"folder": test_folder, "uid": test_uid, "is_read": False})

    print("[10/12] move_to_trash")
    client.call_tool("move_to_trash", {"source_folder": test_folder, "uid": test_uid})

    print("[11/12] delete_email_permanent")
    trash_search = client.call_tool("search_emails", {"folder": args.trash_folder, "query": marker, "limit": 20})
    trash_uids = _extract_uids(trash_search)
    if trash_uids:
        client.call_tool("delete_email_permanent", {"folder": args.trash_folder, "uid": trash_uids[-1]})

    print("[12/12] empty_trash")
    client.call_tool("empty_trash", {})

    print("SUCCESS: Manual MCP compatibility suite completed.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manual, destructive MCP compatibility suite for real inboxes.")
    parser.add_argument("--mcp-command", required=True, help="Shell command that executes one MCP JSON-RPC tool call via stdin/stdout.")
    parser.add_argument("--test-email", required=True, help="Dedicated test email address (must email itself).")
    parser.add_argument("--inbox-folder", default="INBOX")
    parser.add_argument("--test-folder", required=True, help="Pre-created dedicated test folder used for copy/move operations.")
    parser.add_argument("--trash-folder", required=True)
    parser.add_argument("--poll-attempts", type=int, default=10)
    parser.add_argument("--poll-interval-seconds", type=int, default=3)
    return parser.parse_args()


if __name__ == "__main__":
    run_suite(parse_args())
