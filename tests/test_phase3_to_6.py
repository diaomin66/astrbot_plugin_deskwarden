from __future__ import annotations

import asyncio
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from deskwarden_control import ControlResult
from deskwarden_daemon import DaemonState, create_handler
from deskwarden_observe import CaptureResult, ObserveBlocked, WindowInfo
from deskwarden_rpc import DeskWardenRpcClient
from deskwarden_types import ApprovalRequest, ApprovalStatus


class FakeObserver:
    def __init__(self, sensitive: bool = False):
        self.sensitive = sensitive

    def list_windows(self) -> list[WindowInfo]:
        title = "Bitwarden Vault" if self.sensitive else "Notes"
        return [
            WindowInfo(
                window_id="0x10",
                title=title,
                process_id=123,
                process_name="notes.exe",
                is_active=True,
                is_visible=True,
                is_sensitive=self.sensitive,
            )
        ]

    def active_window(self) -> WindowInfo | None:
        return self.list_windows()[0]

    def capture_screen(self) -> CaptureResult:
        if self.sensitive:
            raise ObserveBlocked("SENSITIVE_WINDOW_VISIBLE", "sensitive visible")
        return CaptureResult("screen.bmp", {"scope": "screen"})

    def capture_active_window(self) -> CaptureResult:
        if self.sensitive:
            raise ObserveBlocked("SENSITIVE_ACTIVE_WINDOW", "sensitive active")
        return CaptureResult("active.bmp", {"scope": "active_window"})

    def process_summary(self) -> list[dict[str, Any]]:
        return [{"image_name": "notes.exe", "pid": 123}]

    def summarize_state(self) -> dict[str, Any]:
        windows = self.list_windows()
        return {
            "active_window": windows[0].to_public_dict(),
            "window_count": 1,
            "sensitive_window_visible": self.sensitive,
            "windows": [window.to_public_dict() for window in windows],
            "processes": self.process_summary(),
        }


class FakeController:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def execute(self, action_type: str, payload: Mapping[str, Any]) -> ControlResult:
        self.calls.append((action_type, dict(payload)))
        return ControlResult({"action_type": action_type, "performed": True})


class Phase3To6Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = FakeController()
        self.state = DaemonState(
            state_path=self.root / "daemon_state.json",
            observer=FakeObserver(),
            controller=self.controller,
            workspace_dirs=[self.workspace],
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        pairing = asyncio.run(DeskWardenRpcClient(self.base_url).pair(self.state.pairing_token, "test-client"))
        self.client = DeskWardenRpcClient(self.base_url, pairing.shared_secret, timeout_seconds=2)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp_dir.cleanup()

    def test_observe_redacts_sensitive_windows_and_blocks_screenshots(self) -> None:
        self.state.observer = FakeObserver(sensitive=True)

        windows = asyncio.run(self.client.list_windows("session", "owner"))
        self.assertTrue(windows.result.ok)
        self.assertTrue(windows.redaction_applied)
        self.assertEqual(windows.result.output["windows"][0]["title"], "[SENSITIVE WINDOW REDACTED]")

        screen = asyncio.run(self.client.observe_screen("session", "owner"))
        self.assertFalse(screen.result.ok)
        self.assertEqual(screen.result.error_code, "SENSITIVE_WINDOW_VISIBLE")
        self.assertIsNone(screen.result.screenshot_ref)

    def test_interaction_approval_and_emergency_stop(self) -> None:
        click = asyncio.run(self.client.interact("session", "owner", "click", {"x": 1, "y": 2}))
        self.assertTrue(click.result.ok)
        self.assertEqual(self.controller.calls[-1], ("click", {"x": 1, "y": 2}))

        risky = asyncio.run(self.client.interact("session", "owner", "type_text", {"text": "submit payment"}))
        self.assertFalse(risky.result.ok)
        self.assertEqual(risky.result.error_code, "APPROVAL_REQUIRED")

        approval = ApprovalRequest.create(risky.proposal, "owner").with_status(ApprovalStatus.APPROVED)
        approved = asyncio.run(
            self.client.interact(
                "session",
                "owner",
                "type_text",
                {"text": "submit payment"},
                proposal=risky.proposal,
                approval=approval,
            )
        )
        self.assertTrue(approved.result.ok)
        self.assertEqual(self.controller.calls[-1], ("type_text", {"text": "submit payment"}))

        replay = asyncio.run(
            self.client.interact(
                "session",
                "owner",
                "type_text",
                {"text": "submit payment"},
                proposal=risky.proposal,
                approval=approval,
            )
        )
        self.assertFalse(replay.result.ok)
        self.assertEqual(replay.result.error_code, "APPROVAL_REPLAYED")

        changed = asyncio.run(self.client.interact("session", "owner", "type_text", {"text": "delete account"}))
        changed_approval = ApprovalRequest.create(changed.proposal, "owner").with_status(ApprovalStatus.APPROVED)
        mismatch = asyncio.run(
            self.client.interact(
                "session",
                "owner",
                "type_text",
                {"text": "delete everything"},
                proposal=changed.proposal,
                approval=changed_approval,
            )
        )
        self.assertFalse(mismatch.result.ok)
        self.assertEqual(mismatch.result.error_code, "PAYLOAD_MISMATCH")

        stop = asyncio.run(self.client.emergency_stop("session", "owner"))
        self.assertTrue(stop.result.ok)
        refused = asyncio.run(self.client.interact("session", "owner", "click", {"x": 1, "y": 2}))
        self.assertFalse(refused.result.ok)
        self.assertEqual(refused.result.error_code, "EMERGENCY_STOPPED")

    def test_file_sandbox_diff_write_backup_and_path_rejection(self) -> None:
        path = self.workspace / "note.txt"
        path.write_text("old\n", encoding="utf-8")

        read = asyncio.run(self.client.file_read("session", "owner", str(path)))
        self.assertTrue(read.result.ok)
        self.assertEqual(read.result.output["content"], "old\n")

        outside = asyncio.run(self.client.file_read("session", "owner", str(self.root / "outside.txt")))
        self.assertFalse(outside.result.ok)
        self.assertEqual(outside.result.error_code, "PATH_OUTSIDE_WORKSPACE")

        diff = asyncio.run(self.client.file_diff("session", "owner", str(path), "new\n"))
        self.assertTrue(diff.result.ok)
        self.assertIn("-old", diff.result.output["diff"])
        self.assertIn("+new", diff.result.output["diff"])

        approval = ApprovalRequest.create(diff.proposal, "owner").with_status(ApprovalStatus.APPROVED)
        write = asyncio.run(self.client.file_write("session", "owner", str(path), "new\n", diff.proposal, approval))
        self.assertTrue(write.result.ok)
        self.assertEqual(path.read_text(encoding="utf-8"), "new\n")
        self.assertTrue(Path(write.result.output["backup_ref"]).exists())

        audit = asyncio.run(self.client.audit_latest(10))
        self.assertGreaterEqual(len(audit["records"]), 3)


if __name__ == "__main__":
    unittest.main()
