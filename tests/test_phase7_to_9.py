from __future__ import annotations

import asyncio
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from deskwarden_browser import BrowserResult
from deskwarden_daemon import DaemonState, create_handler
from deskwarden_rpc import DeskWardenRpcClient
from deskwarden_shell import RestrictedShell
from deskwarden_types import ApprovalRequest, ApprovalStatus


class FakeBrowser:
    enabled = True

    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def open_url(self, url: str) -> BrowserResult:
        self.calls.append(("open_url", {"url": url}))
        return BrowserResult({"action": "open_url", "url": url, "title": "Example"})

    def title(self) -> BrowserResult:
        self.calls.append(("title", {}))
        return BrowserResult({"action": "title", "url": "https://example.com", "title": "Example"})

    def screenshot(self) -> BrowserResult:
        self.calls.append(("screenshot", {}))
        return BrowserResult({"action": "screenshot", "url": "https://example.com", "title": "Example"}, "shot.png")

    def click(self, selector: str) -> BrowserResult:
        self.calls.append(("click", {"selector": selector}))
        return BrowserResult({"action": "click", "selector": selector, "url": "https://example.com", "title": "Example"})

    def type_text(self, selector: str, text: str) -> BrowserResult:
        self.calls.append(("type_text", {"selector": selector, "text": text}))
        return BrowserResult(
            {
                "action": "type_text",
                "selector": selector,
                "text_length": len(text),
                "url": "https://example.com",
                "title": "Example",
            }
        )

    def download(self, selector: str) -> BrowserResult:
        self.calls.append(("download", {"selector": selector}))
        return BrowserResult({"action": "download", "download_ref": "download.bin"})


class Phase7To9Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.browser = FakeBrowser()
        self.state = DaemonState(
            state_path=self.root / "daemon_state.json",
            workspace_dirs=[self.workspace],
            shell_sandbox=RestrictedShell(
                enabled=True,
                allowlist=[f"{Path(sys.executable).name} -c"],
                workspace_dirs=[self.workspace],
            ),
            browser_sandbox=self.browser,
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        pairing = asyncio.run(DeskWardenRpcClient(self.base_url).pair(self.state.pairing_token, "test-client"))
        self.client = DeskWardenRpcClient(self.base_url, pairing.shared_secret, timeout_seconds=3)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp_dir.cleanup()

    def test_restricted_shell_requires_approval_and_rejects_replay(self) -> None:
        command = f'{Path(sys.executable).name} -c "print(\'ok\')"'
        plan = asyncio.run(self.client.shell_plan("session", "owner", command))
        self.assertTrue(plan.result.ok)
        self.assertEqual(plan.proposal.action_type, "shell_run")

        payload = plan.proposal.payload
        approval = ApprovalRequest.create(plan.proposal, "owner").with_status(ApprovalStatus.APPROVED)
        run = asyncio.run(
            self.client.shell_run(
                "session",
                "owner",
                str(payload["command"]),
                str(payload["cwd"]),
                int(payload["timeout_seconds"]),
                plan.proposal,
                approval,
            )
        )
        self.assertTrue(run.result.ok)
        self.assertIn("ok", run.result.output["stdout"])

        replay = asyncio.run(
            self.client.shell_run(
                "session",
                "owner",
                str(payload["command"]),
                str(payload["cwd"]),
                int(payload["timeout_seconds"]),
                plan.proposal,
                approval,
            )
        )
        self.assertFalse(replay.result.ok)
        self.assertEqual(replay.result.error_code, "APPROVAL_REPLAYED")

        forbidden = asyncio.run(self.client.shell_plan("session", "owner", "powershell Get-ChildItem"))
        self.assertFalse(forbidden.result.ok)
        self.assertEqual(forbidden.result.error_code, "SHELL_FORBIDDEN")

    def test_browser_sensitive_actions_require_one_time_approval(self) -> None:
        opened = asyncio.run(
            self.client.browser_action("session", "owner", "open_url", {"url": "https://example.com"})
        )
        self.assertTrue(opened.result.ok)
        self.assertEqual(self.browser.calls[-1][0], "open_url")

        risky = asyncio.run(
            self.client.browser_action(
                "session",
                "owner",
                "type_text",
                {"selector": "#password", "text": "login password"},
            )
        )
        self.assertFalse(risky.result.ok)
        self.assertEqual(risky.result.error_code, "APPROVAL_REQUIRED")

        approval = ApprovalRequest.create(risky.proposal, "owner").with_status(ApprovalStatus.APPROVED)
        approved = asyncio.run(
            self.client.browser_action(
                "session",
                "owner",
                "type_text",
                {"selector": "#password", "text": "login password"},
                proposal=risky.proposal,
                approval=approval,
            )
        )
        self.assertTrue(approved.result.ok)
        self.assertEqual(self.browser.calls[-1][0], "type_text")

        replay = asyncio.run(
            self.client.browser_action(
                "session",
                "owner",
                "type_text",
                {"selector": "#password", "text": "login password"},
                proposal=risky.proposal,
                approval=approval,
            )
        )
        self.assertFalse(replay.result.ok)
        self.assertEqual(replay.result.error_code, "APPROVAL_REPLAYED")

    def test_audit_redacts_file_contents(self) -> None:
        path = self.workspace / "note.txt"
        path.write_text("secret file body\n", encoding="utf-8")

        read = asyncio.run(self.client.file_read("session", "owner", str(path)))
        self.assertTrue(read.result.ok)

        audit = asyncio.run(self.client.audit_latest(1))
        record = audit["records"][0]
        self.assertTrue(record["redaction_applied"])
        self.assertEqual(record["result"]["output"]["content"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
