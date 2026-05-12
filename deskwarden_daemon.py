from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

try:
    from .deskwarden_audit import AuditLog
    from .deskwarden_browser import BrowserSandbox, BrowserSandboxError
    from .deskwarden_control import ControlError, create_controller
    from .deskwarden_files import FileSandbox, FileSandboxError
    from .deskwarden_observe import ObserveBlocked, ObserveError, create_observer
    from .deskwarden_policy import classify_browser_action, classify_file_read, classify_file_write, classify_interaction, classify_shell_command
    from .deskwarden_protocol import (
        HEADER_NONCE,
        HEADER_SIGNATURE,
        HEADER_TIMESTAMP,
        generate_pairing_token,
        generate_shared_secret,
        load_json_object,
        sign_request,
        signatures_match,
    )
    from .deskwarden_types import (
        ActionProposal,
        ActionResult,
        ApprovalRequest,
        ApprovalStatus,
        AuditRecord,
        CapabilityTier,
        SessionState,
        now_ts,
    )
    from .deskwarden_shell import RestrictedShell, ShellSandboxError
except ImportError:  # pragma: no cover - allows `python deskwarden_daemon.py`.
    from deskwarden_audit import AuditLog
    from deskwarden_browser import BrowserSandbox, BrowserSandboxError
    from deskwarden_control import ControlError, create_controller
    from deskwarden_files import FileSandbox, FileSandboxError
    from deskwarden_observe import ObserveBlocked, ObserveError, create_observer
    from deskwarden_policy import classify_browser_action, classify_file_read, classify_file_write, classify_interaction, classify_shell_command
    from deskwarden_protocol import (
        HEADER_NONCE,
        HEADER_SIGNATURE,
        HEADER_TIMESTAMP,
        generate_pairing_token,
        generate_shared_secret,
        load_json_object,
        sign_request,
        signatures_match,
    )
    from deskwarden_types import (
        ActionProposal,
        ActionResult,
        ApprovalRequest,
        ApprovalStatus,
        AuditRecord,
        CapabilityTier,
        SessionState,
        now_ts,
    )
    from deskwarden_shell import RestrictedShell, ShellSandboxError


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_TIMESTAMP_TOLERANCE_SECONDS = 300
DEFAULT_NONCE_TTL_SECONDS = 600
DEFAULT_MAX_AUTH_FAILURES = 5
MAX_BODY_BYTES = 1024 * 1024


class DaemonState:
    def __init__(
        self,
        state_path: Path,
        timestamp_tolerance_seconds: int = DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
        nonce_ttl_seconds: int = DEFAULT_NONCE_TTL_SECONDS,
        max_auth_failures: int = DEFAULT_MAX_AUTH_FAILURES,
        audit_path: Path | None = None,
        screenshot_dir: Path | None = None,
        backup_dir: Path | None = None,
        workspace_dirs: list[str | Path] | None = None,
        shell_enabled: bool = False,
        shell_allowlist: list[str] | None = None,
        browser_enabled: bool = False,
        browser_allow_private_hosts: bool = False,
        observer: Any | None = None,
        controller: Any | None = None,
        file_sandbox: FileSandbox | None = None,
        shell_sandbox: RestrictedShell | None = None,
        browser_sandbox: BrowserSandbox | None = None,
    ):
        self.state_path = state_path
        self.timestamp_tolerance_seconds = timestamp_tolerance_seconds
        self.nonce_ttl_seconds = nonce_ttl_seconds
        self.max_auth_failures = max_auth_failures
        self.lock = threading.RLock()
        self.status = SessionState.LOCKED.value
        self.pairing_token = generate_pairing_token()
        self.shared_secret: str | None = None
        self.paired_at: int | None = None
        self.secret_rotated_at: int | None = None
        self.auth_failures = 0
        self.auth_locked = False
        self.emergency_stopped = False
        self._nonces: dict[str, float] = {}
        self._consumed_approval_ids: set[str] = set()

        data_dir = state_path.parent
        self.audit_log = AuditLog(audit_path or data_dir / "audit.jsonl")
        self.observer = observer or create_observer(screenshot_dir or data_dir / "screenshots")
        self.controller = controller or create_controller()
        self.file_sandbox = file_sandbox or FileSandbox(workspace_dirs or [], backup_dir or data_dir / "backups")
        self.shell_sandbox = shell_sandbox or RestrictedShell(
            enabled=shell_enabled,
            allowlist=shell_allowlist or [],
            workspace_dirs=workspace_dirs or [],
        )
        self.browser_sandbox = browser_sandbox or BrowserSandbox(
            enabled=browser_enabled,
            profile_dir=data_dir / "browser_profile",
            screenshot_dir=data_dir / "browser_screenshots",
            downloads_dir=data_dir / "browser_downloads",
            allow_private_hosts=browser_allow_private_hosts,
        )
        self._load()

    @property
    def paired(self) -> bool:
        return bool(self.shared_secret)

    def health(self) -> dict[str, Any]:
        with self.lock:
            return {
                "ok": True,
                "name": "DeskWarden daemon",
                "state": self.status,
                "paired": self.paired,
                "auth_locked": self.auth_locked,
                "emergency_stopped": self.emergency_stopped,
                "pairing_required": not self.paired,
                "shell_enabled": self.shell_sandbox.enabled,
                "browser_enabled": self.browser_sandbox.enabled,
                "timestamp": now_ts(),
            }

    def signed_status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "ok": True,
                "state": self.status,
                "paired": self.paired,
                "auth_failures": self.auth_failures,
                "auth_locked": self.auth_locked,
                "emergency_stopped": self.emergency_stopped,
                "max_auth_failures": self.max_auth_failures,
                "shell_enabled": self.shell_sandbox.enabled,
                "browser_enabled": self.browser_sandbox.enabled,
                "paired_at": self.paired_at,
                "secret_rotated_at": self.secret_rotated_at,
                "timestamp": now_ts(),
            }

    def pair(self, token: str) -> tuple[int, dict[str, Any]]:
        with self.lock:
            if self.auth_locked:
                return self._error(HTTPStatus.LOCKED, "AUTH_LOCKED", "Daemon is locked after repeated auth failures.")
            if self.paired:
                return self._error(HTTPStatus.CONFLICT, "ALREADY_PAIRED", "Daemon is already paired.")
            if not token or token != self.pairing_token:
                self._record_auth_failure()
                return self._error(HTTPStatus.UNAUTHORIZED, "BAD_PAIRING_TOKEN", "Pairing token is invalid.")

            self.shared_secret = generate_shared_secret()
            self.pairing_token = ""
            self.paired_at = now_ts()
            self.secret_rotated_at = self.paired_at
            self.auth_failures = 0
            self.auth_locked = False
            self._nonces.clear()
            self._save()
            return HTTPStatus.OK, {
                "ok": True,
                "state": self.status,
                "paired": True,
                "shared_secret": self.shared_secret,
            }

    def rotate_secret(self) -> dict[str, Any]:
        with self.lock:
            self.shared_secret = generate_shared_secret()
            self.secret_rotated_at = now_ts()
            self.auth_failures = 0
            self.auth_locked = False
            self._nonces.clear()
            self._save()
            return {
                "ok": True,
                "state": self.status,
                "paired": True,
                "shared_secret": self.shared_secret,
            }

    def verify_request(self, method: str, path: str, headers: Any, body: bytes) -> tuple[bool, int, dict[str, Any]]:
        with self.lock:
            if not self.shared_secret:
                return False, *self._error(HTTPStatus.UNAUTHORIZED, "UNPAIRED", "Daemon has not been paired.")
            if self.auth_locked:
                return False, *self._error(HTTPStatus.LOCKED, "AUTH_LOCKED", "Daemon is locked after repeated auth failures.")

            timestamp = str(headers.get(HEADER_TIMESTAMP, ""))
            nonce = str(headers.get(HEADER_NONCE, ""))
            signature = str(headers.get(HEADER_SIGNATURE, ""))

            if not timestamp or not nonce or not signature:
                self._record_auth_failure()
                return False, *self._error(HTTPStatus.UNAUTHORIZED, "MISSING_SIGNATURE", "Signed request headers are incomplete.")

            try:
                request_time = int(timestamp)
            except ValueError:
                self._record_auth_failure()
                return False, *self._error(HTTPStatus.UNAUTHORIZED, "BAD_TIMESTAMP", "Signed request timestamp is invalid.")

            now = now_ts()
            if abs(now - request_time) > self.timestamp_tolerance_seconds:
                self._record_auth_failure()
                return False, *self._error(HTTPStatus.UNAUTHORIZED, "STALE_TIMESTAMP", "Signed request timestamp is outside tolerance.")

            self._purge_nonces(now)
            if nonce in self._nonces:
                self._record_auth_failure()
                return False, *self._error(HTTPStatus.UNAUTHORIZED, "REPLAYED_NONCE", "Signed request nonce has already been used.")

            expected = sign_request(self.shared_secret, method, path, timestamp, nonce, body)
            if not signatures_match(expected, signature):
                self._record_auth_failure()
                return False, *self._error(HTTPStatus.UNAUTHORIZED, "BAD_SIGNATURE", "Signed request HMAC is invalid.")

            self._nonces[nonce] = now
            self.auth_failures = 0
            return True, HTTPStatus.OK, {"ok": True}

    def handle_observe(self, action_type: str, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        proposal = ActionProposal.create(
            session_id=session_id,
            action_type=action_type,
            tier=CapabilityTier.OBSERVE,
            summary=f"Observe desktop via {action_type}.",
            target="desktop",
            payload={},
            risk_reason="Read-only observation action.",
            rollback_hint="No system changes are made.",
        )

        redaction = False
        try:
            if action_type == "observe_screen":
                capture = self.observer.capture_screen()
                result = ActionResult(proposal.id, True, output=capture.output, screenshot_ref=capture.screenshot_ref)
                redaction = capture.redaction_applied
            elif action_type == "observe_active_window":
                capture = self.observer.capture_active_window()
                result = ActionResult(proposal.id, True, output=capture.output, screenshot_ref=capture.screenshot_ref)
                redaction = capture.redaction_applied
            elif action_type == "list_windows":
                windows = self.observer.list_windows()
                redaction = any(window.is_sensitive for window in windows)
                result = ActionResult(
                    proposal.id,
                    True,
                    output={"windows": [window.to_public_dict() for window in windows]},
                )
            elif action_type == "summarize_state":
                summary = self.observer.summarize_state()
                redaction = bool(summary.get("sensitive_window_visible"))
                result = ActionResult(proposal.id, True, output=summary)
            else:
                result = ActionResult(proposal.id, False, error_code="UNKNOWN_OBSERVE_ACTION", error_message="Unknown observe action.")
        except ObserveBlocked as exc:
            redaction = True
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))
        except ObserveError as exc:
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))

        self._audit(session_id, user_id, proposal, None, result, redaction)
        return HTTPStatus.OK, self._action_response(proposal, result, redaction)

    def handle_interaction(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        action_type = str(payload.get("action_type", ""))
        action_payload = dict(payload.get("payload") or {})
        target = str(payload.get("target", "desktop"))
        summary = str(payload.get("summary", f"Desktop interaction: {action_type}"))
        tier, risk_reason, needs_approval = classify_interaction(action_type, action_payload, target, summary)
        supplied_proposal = _proposal_from_payload(payload)
        proposal = supplied_proposal or ActionProposal.create(
            session_id=session_id,
            action_type=action_type,
            tier=tier,
            summary=summary,
            target=target,
            payload=action_payload,
            risk_reason=risk_reason,
            rollback_hint="Use /desk emergency to stop further actions; manually undo UI changes if needed.",
        )
        approval = _approval_from_payload(payload.get("approval"))
        redaction = False

        if supplied_proposal is not None and (
            supplied_proposal.action_type != action_type
            or dict(supplied_proposal.payload) != action_payload
            or supplied_proposal.target != target
        ):
            result = ActionResult(proposal.id, False, error_code="PAYLOAD_MISMATCH", error_message="Approved proposal payload does not match the interaction request.")
            self._audit(session_id, user_id, proposal, approval, result, redaction)
            return HTTPStatus.OK, self._action_response(proposal, result, redaction)

        error = self._preflight_action(proposal, approval, needs_approval, user_id)
        if error is not None:
            result = error
            self._audit(session_id, user_id, proposal, approval, result, redaction)
            return HTTPStatus.OK, self._action_response(proposal, result, redaction)

        try:
            active = self.observer.active_window()
            if active is not None and active.is_sensitive:
                raise ControlError("SENSITIVE_ACTIVE_WINDOW", "The active window is sensitive; interaction was refused.")
            before_ref, before_redacted = self._safe_screen_ref()
            redaction = redaction or before_redacted
            control_result = self.controller.execute(action_type, action_payload)
            after_ref, after_redacted = self._safe_screen_ref()
            redaction = redaction or after_redacted
            output = {
                **control_result.output,
                "before_screenshot_ref": before_ref,
                "after_screenshot_ref": after_ref,
            }
            result = ActionResult(proposal.id, True, output=output)
        except ControlError as exc:
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))
        except ObserveError as exc:
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))

        self._audit(session_id, user_id, proposal, approval, result, redaction)
        return HTTPStatus.OK, self._action_response(proposal, result, redaction)

    def handle_emergency_stop(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        with self.lock:
            self.emergency_stopped = True
            self.status = SessionState.PAUSED.value

        proposal = ActionProposal.create(
            session_id=session_id,
            action_type="emergency_stop",
            tier=CapabilityTier.DANGEROUS,
            summary="Emergency stop all DeskWarden actions.",
            target="daemon",
            risk_reason="Operator requested a hard stop.",
            rollback_hint="Restart or explicitly clear the daemon state before resuming actions.",
        )
        result = ActionResult(proposal.id, True, output={"emergency_stopped": True, "state": self.status})
        self._audit(session_id, user_id, proposal, None, result, False)
        return HTTPStatus.OK, self._action_response(proposal, result, False)

    def handle_file_read(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        path = str(payload.get("path", ""))
        tier, risk_reason, _needs_approval = classify_file_read()
        proposal = ActionProposal.create(
            session_id=session_id,
            action_type="file_read",
            tier=tier,
            summary=f"Read file: {path}",
            target=path,
            payload={"path": path},
            risk_reason=risk_reason,
            rollback_hint="No system changes are made.",
        )
        try:
            output = self.file_sandbox.read_text(path)
            result = ActionResult(proposal.id, True, output=output)
        except FileSandboxError as exc:
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))

        self._audit(session_id, user_id, proposal, None, result, False)
        return HTTPStatus.OK, self._action_response(proposal, result, False)

    def handle_file_diff(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        path = str(payload.get("path", ""))
        content = str(payload.get("content", ""))
        tier, risk_reason, _needs_approval = classify_file_write()
        proposal = ActionProposal.create(
            session_id=session_id,
            action_type="file_write",
            tier=tier,
            summary=f"Write file after diff review: {path}",
            target=path,
            payload={"path": path, "content_sha256": _sha256_text(content)},
            risk_reason=risk_reason,
            rollback_hint="A backup is created before writing an existing file.",
        )
        try:
            file_diff = self.file_sandbox.build_diff(path, content)
            result = ActionResult(proposal.id, True, output=file_diff.to_dict())
        except FileSandboxError as exc:
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))

        return HTTPStatus.OK, self._action_response(proposal, result, False)

    def handle_file_write(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        path = str(payload.get("path", ""))
        content = str(payload.get("content", ""))
        tier, risk_reason, _needs_approval = classify_file_write()
        proposal = _proposal_from_payload(payload) or ActionProposal.create(
            session_id=session_id,
            action_type="file_write",
            tier=tier,
            summary=f"Write file: {path}",
            target=path,
            payload={"path": path, "content_sha256": _sha256_text(content)},
            risk_reason=risk_reason,
            rollback_hint="A backup is created before writing an existing file.",
        )
        approval = _approval_from_payload(payload.get("approval"))

        expected_hash = str(proposal.payload.get("content_sha256", ""))
        expected_path = str(proposal.payload.get("path", ""))
        if expected_hash != _sha256_text(content) or expected_path != path:
            error = ActionResult(proposal.id, False, error_code="PAYLOAD_MISMATCH", error_message="Approved payload no longer matches the write request.")
        else:
            error = self._preflight_action(proposal, approval, True, user_id)
        if error is not None:
            result = error
            self._audit(session_id, user_id, proposal, approval, result, False)
            return HTTPStatus.OK, self._action_response(proposal, result, False)

        try:
            write_result = self.file_sandbox.write_text(path, content, proposal.id)
            result = ActionResult(proposal.id, True, output=write_result.to_dict())
        except FileSandboxError as exc:
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))

        self._audit(session_id, user_id, proposal, approval, result, False)
        return HTTPStatus.OK, self._action_response(proposal, result, False)

    def handle_shell_plan(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        command = str(payload.get("command", ""))
        cwd = str(payload.get("cwd", ""))
        timeout_seconds = _safe_int(payload.get("timeout_seconds"), 5)
        tier, risk_reason, _needs_approval = classify_shell_command()
        proposal_payload = {"command": command.strip(), "cwd": cwd.strip(), "timeout_seconds": timeout_seconds}

        try:
            plan = self.shell_sandbox.plan(command, cwd, timeout_seconds)
            proposal_payload = {
                "command": plan.command,
                "cwd": plan.cwd,
                "timeout_seconds": plan.timeout_seconds,
            }
            result = ActionResult("", True, output=plan.to_dict())
        except ShellSandboxError as exc:
            result = ActionResult("", False, error_code=exc.code, error_message=str(exc))

        proposal = ActionProposal.create(
            session_id=session_id,
            action_type="shell_run",
            tier=tier,
            summary=f"Run restricted shell command: {command.strip()}",
            target=str(proposal_payload.get("cwd") or "workspace"),
            payload=proposal_payload,
            risk_reason=risk_reason,
            rollback_hint="Review command output and manually undo any changes made by the approved command.",
        )
        result = ActionResult(
            proposal.id,
            result.ok,
            output=result.output,
            screenshot_ref=result.screenshot_ref,
            error_code=result.error_code,
            error_message=result.error_message,
        )
        self._audit(session_id, user_id, proposal, None, result, False)
        return HTTPStatus.OK, self._action_response(proposal, result, False)

    def handle_shell_run(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        command = str(payload.get("command", ""))
        cwd = str(payload.get("cwd", ""))
        timeout_seconds = _safe_int(payload.get("timeout_seconds"), 5)
        tier, risk_reason, _needs_approval = classify_shell_command()
        proposal = _proposal_from_payload(payload) or ActionProposal.create(
            session_id=session_id,
            action_type="shell_run",
            tier=tier,
            summary=f"Run restricted shell command: {command.strip()}",
            target=cwd,
            payload={"command": command.strip(), "cwd": cwd.strip(), "timeout_seconds": timeout_seconds},
            risk_reason=risk_reason,
            rollback_hint="Review command output and manually undo any changes made by the approved command.",
        )
        approval = _approval_from_payload(payload.get("approval"))

        try:
            plan = self.shell_sandbox.plan(command, cwd, timeout_seconds)
            expected_payload = {"command": plan.command, "cwd": plan.cwd, "timeout_seconds": plan.timeout_seconds}
            plan_error: ActionResult | None = None
        except ShellSandboxError as exc:
            expected_payload = {}
            plan_error = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))

        if plan_error is not None:
            result = plan_error
            self._audit(session_id, user_id, proposal, approval, result, False)
            return HTTPStatus.OK, self._action_response(proposal, result, False)

        if proposal.action_type != "shell_run" or dict(proposal.payload) != expected_payload:
            result = ActionResult(proposal.id, False, error_code="PAYLOAD_MISMATCH", error_message="Approved shell payload does not match the run request.")
            self._audit(session_id, user_id, proposal, approval, result, False)
            return HTTPStatus.OK, self._action_response(proposal, result, False)

        error = self._preflight_action(proposal, approval, True, user_id)
        if error is not None:
            result = error
            self._audit(session_id, user_id, proposal, approval, result, False)
            return HTTPStatus.OK, self._action_response(proposal, result, False)

        try:
            shell_result = self.shell_sandbox.run(command, cwd, timeout_seconds)
            ok = not shell_result.timed_out and shell_result.exit_code == 0
            result = ActionResult(proposal.id, ok, output=shell_result.to_dict())
        except ShellSandboxError as exc:
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))

        self._audit(session_id, user_id, proposal, approval, result, False)
        return HTTPStatus.OK, self._action_response(proposal, result, False)

    def handle_browser_action(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        session_id, user_id = _context(payload)
        action_type = str(payload.get("action_type", ""))
        action_payload = dict(payload.get("payload") or {})
        target = str(payload.get("target", "isolated_browser"))
        summary = str(payload.get("summary", f"Browser action: {action_type}"))
        tier, risk_reason, needs_approval = classify_browser_action(action_type, action_payload, target, summary)
        proposal_payload = _browser_proposal_payload(action_type, action_payload)
        supplied_proposal = _proposal_from_payload(payload)
        proposal = supplied_proposal or ActionProposal.create(
            session_id=session_id,
            action_type=action_type,
            tier=tier,
            summary=summary,
            target=target,
            payload=proposal_payload,
            risk_reason=risk_reason,
            rollback_hint="Close the isolated browser or manually reverse the page action if needed.",
        )
        approval = _approval_from_payload(payload.get("approval"))

        if supplied_proposal is not None and (
            supplied_proposal.action_type != action_type
            or dict(supplied_proposal.payload) != proposal_payload
            or supplied_proposal.target != target
        ):
            result = ActionResult(proposal.id, False, error_code="PAYLOAD_MISMATCH", error_message="Approved browser payload does not match the action request.")
            self._audit(session_id, user_id, proposal, approval, result, False)
            return HTTPStatus.OK, self._action_response(proposal, result, False)

        error = self._preflight_action(proposal, approval, needs_approval, user_id)
        if error is not None:
            result = error
            self._audit(session_id, user_id, proposal, approval, result, False)
            return HTTPStatus.OK, self._action_response(proposal, result, False)

        try:
            browser_result = self._execute_browser(action_type, action_payload)
            result = ActionResult(proposal.id, True, output=browser_result.output, screenshot_ref=browser_result.screenshot_ref)
        except BrowserSandboxError as exc:
            result = ActionResult(proposal.id, False, error_code=exc.code, error_message=str(exc))

        self._audit(session_id, user_id, proposal, approval, result, False)
        return HTTPStatus.OK, self._action_response(proposal, result, False)

    def handle_audit_latest(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        limit = _safe_int(payload.get("limit", 10), 10)
        return HTTPStatus.OK, {"ok": True, "records": self.audit_log.latest(limit)}

    def handle_audit_purge(self, payload: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        purged = self.audit_log.purge()
        return HTTPStatus.OK, {"ok": True, "purged_records": purged}

    def _execute_browser(self, action_type: str, payload: Mapping[str, Any]):
        action = action_type.lower().strip()
        if action == "open_url":
            return self.browser_sandbox.open_url(str(payload.get("url", "")))
        if action == "title":
            return self.browser_sandbox.title()
        if action == "screenshot":
            return self.browser_sandbox.screenshot()
        if action == "click":
            return self.browser_sandbox.click(str(payload.get("selector", "")))
        if action == "type_text":
            return self.browser_sandbox.type_text(str(payload.get("selector", "")), str(payload.get("text", "")))
        if action == "download":
            return self.browser_sandbox.download(str(payload.get("selector", "")))
        raise BrowserSandboxError("UNKNOWN_BROWSER_ACTION", f"Unsupported browser action: {action_type}")

    def _preflight_action(
        self,
        proposal: ActionProposal,
        approval: ApprovalRequest | None,
        needs_approval: bool,
        user_id: str,
    ) -> ActionResult | None:
        if self.emergency_stopped:
            return ActionResult(proposal.id, False, error_code="EMERGENCY_STOPPED", error_message="Emergency stop is active; all actions are refused.")
        if proposal.is_expired():
            return ActionResult(proposal.id, False, error_code="PROPOSAL_EXPIRED", error_message="The action proposal has expired.")
        if needs_approval and not _approval_ok(proposal, approval):
            return ActionResult(proposal.id, False, error_code="APPROVAL_REQUIRED", error_message="This action requires a fresh owner approval.")
        if needs_approval and approval is not None and approval.user_id != user_id:
            return ActionResult(proposal.id, False, error_code="APPROVAL_USER_MISMATCH", error_message="Approval user does not match the request user.")
        if needs_approval and approval is not None:
            with self.lock:
                if approval.proposal_id in self._consumed_approval_ids:
                    return ActionResult(proposal.id, False, error_code="APPROVAL_REPLAYED", error_message="This approval has already been consumed.")
                self._consumed_approval_ids.add(approval.proposal_id)
        return None

    def _safe_screen_ref(self) -> tuple[str | None, bool]:
        try:
            capture = self.observer.capture_screen()
            return capture.screenshot_ref, capture.redaction_applied
        except ObserveBlocked:
            return None, True
        except ObserveError:
            return None, False

    def _audit(
        self,
        session_id: str,
        user_id: str,
        proposal: ActionProposal,
        approval: ApprovalRequest | Mapping[str, Any] | None,
        result: ActionResult,
        redaction: bool,
    ) -> None:
        self.audit_log.append(AuditRecord.create(session_id, user_id, proposal, approval, result, redaction))

    @staticmethod
    def _action_response(proposal: ActionProposal, result: ActionResult, redaction: bool) -> dict[str, Any]:
        return {
            "ok": True,
            "proposal": proposal.to_dict(),
            "action_result": result.to_dict(),
            "redaction_applied": redaction,
        }

    def _record_auth_failure(self) -> None:
        self.auth_failures += 1
        if self.auth_failures >= self.max_auth_failures:
            self.auth_locked = True
            self.status = SessionState.LOCKED.value

    def _purge_nonces(self, now: int) -> None:
        expired = [nonce for nonce, seen_at in self._nonces.items() if now - seen_at > self.nonce_ttl_seconds]
        for nonce in expired:
            del self._nonces[nonce]

    def _load(self) -> None:
        if not self.state_path.exists():
            return

        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        if isinstance(payload, dict):
            self.shared_secret = str(payload.get("shared_secret") or "") or None
            self.paired_at = _optional_int(payload.get("paired_at"))
            self.secret_rotated_at = _optional_int(payload.get("secret_rotated_at"))

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "shared_secret": self.shared_secret,
            "paired_at": self.paired_at,
            "secret_rotated_at": self.secret_rotated_at,
        }
        self.state_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        try:
            self.state_path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _error(status: int, code: str, message: str) -> tuple[int, dict[str, Any]]:
        return status, {"ok": False, "error_code": code, "error_message": message}


def create_handler(state: DaemonState) -> type[BaseHTTPRequestHandler]:
    class DeskWardenRequestHandler(BaseHTTPRequestHandler):
        server_version = "DeskWardenDaemon/0.6"

        def do_GET(self) -> None:
            if not self._reject_remote_client():
                return

            if self.path == "/health":
                self._send_json(HTTPStatus.OK, state.health())
                return

            if self.path == "/status":
                body = b""
                ok, status, payload = state.verify_request("GET", "/status", self.headers, body)
                if not ok:
                    self._send_json(status, payload)
                    return
                self._send_json(HTTPStatus.OK, state.signed_status())
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error_code": "NOT_FOUND", "error_message": "Unknown endpoint."})

        def do_POST(self) -> None:
            if not self._reject_remote_client():
                return

            body = self._read_body()
            if body is None:
                return

            if self.path == "/pair":
                try:
                    payload = load_json_object(body)
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error_code": "BAD_JSON", "error_message": "Request body must be a JSON object."})
                    return
                status, response = state.pair(str(payload.get("pairing_token", "")))
                self._send_json(status, response)
                return

            if self.path == "/rotate-secret":
                ok, status, payload = state.verify_request("POST", "/rotate-secret", self.headers, body)
                if not ok:
                    self._send_json(status, payload)
                    return
                self._send_json(HTTPStatus.OK, state.rotate_secret())
                return

            signed_routes = {
                "/observe/screen": lambda payload: state.handle_observe("observe_screen", payload),
                "/observe/active-window": lambda payload: state.handle_observe("observe_active_window", payload),
                "/observe/windows": lambda payload: state.handle_observe("list_windows", payload),
                "/observe/summary": lambda payload: state.handle_observe("summarize_state", payload),
                "/interact": state.handle_interaction,
                "/emergency-stop": state.handle_emergency_stop,
                "/file/read": state.handle_file_read,
                "/file/diff": state.handle_file_diff,
                "/file/write": state.handle_file_write,
                "/shell/plan": state.handle_shell_plan,
                "/shell/run": state.handle_shell_run,
                "/browser/action": state.handle_browser_action,
                "/audit/latest": state.handle_audit_latest,
                "/audit/purge": state.handle_audit_purge,
            }

            handler = signed_routes.get(self.path)
            if handler is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error_code": "NOT_FOUND", "error_message": "Unknown endpoint."})
                return

            ok, status, auth_payload = state.verify_request("POST", self.path, self.headers, body)
            if not ok:
                self._send_json(status, auth_payload)
                return

            try:
                request_payload = load_json_object(body)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error_code": "BAD_JSON", "error_message": "Request body must be a JSON object."})
                return

            status, response = handler(request_payload)
            self._send_json(status, response)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_body(self) -> bytes | None:
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error_code": "BAD_LENGTH", "error_message": "Content-Length is invalid."})
                return None

            if content_length > MAX_BODY_BYTES:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "error_code": "BODY_TOO_LARGE", "error_message": "Request body is too large."})
                return None

            return self.rfile.read(content_length)

        def _reject_remote_client(self) -> bool:
            client_host = self.client_address[0]
            try:
                if ipaddress.ip_address(client_host).is_loopback:
                    return True
            except ValueError:
                pass

            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error_code": "REMOTE_CLIENT", "error_message": "Only loopback clients are allowed."})
            return False

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            response = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    return DeskWardenRequestHandler


def serve(
    host: str,
    port: int,
    state_path: Path,
    audit_path: Path | None = None,
    screenshot_dir: Path | None = None,
    backup_dir: Path | None = None,
    workspace_dirs: list[str] | None = None,
    shell_enabled: bool = False,
    shell_allowlist: list[str] | None = None,
    browser_enabled: bool = False,
    browser_allow_private_hosts: bool = False,
) -> None:
    _validate_loopback_host(host)
    state = DaemonState(
        state_path=state_path,
        audit_path=audit_path,
        screenshot_dir=screenshot_dir,
        backup_dir=backup_dir,
        workspace_dirs=workspace_dirs or [],
        shell_enabled=shell_enabled,
        shell_allowlist=shell_allowlist or [],
        browser_enabled=browser_enabled,
        browser_allow_private_hosts=browser_allow_private_hosts,
    )
    server = ThreadingHTTPServer((host, port), create_handler(state))
    print(f"DeskWarden daemon listening on http://{host}:{server.server_port}")
    print("Daemon state: LOCKED")
    print(f"Restricted shell: {'enabled' if state.shell_sandbox.enabled else 'disabled'}")
    print(f"Isolated browser: {'enabled' if state.browser_sandbox.enabled else 'disabled'}")
    if state.paired:
        print("Already paired. Use /desk rotate-key to rotate the shared secret.")
    else:
        print(f"Pairing token: {state.pairing_token}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="DeskWarden local loopback daemon.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Loopback host to bind. Defaults to 127.0.0.1.")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Loopback port to bind. Defaults to 8765.")
    parser.add_argument(
        "--state-path",
        default=str(Path(__file__).resolve().parent / ".deskwarden" / "daemon_state.json"),
        help="Path where the daemon stores its shared secret.",
    )
    parser.add_argument("--audit-path", default="", help="JSONL audit log path. Defaults under the state directory.")
    parser.add_argument("--screenshot-dir", default="", help="Directory for observation screenshots. Defaults under the state directory.")
    parser.add_argument("--backup-dir", default="", help="Directory for file write backups. Defaults under the state directory.")
    parser.add_argument(
        "--workspace",
        action="append",
        default=[],
        help="Allowed file sandbox workspace directory. Repeat this option for multiple workspaces.",
    )
    parser.add_argument("--enable-shell", action="store_true", help="Enable restricted shell endpoints. Disabled by default.")
    parser.add_argument(
        "--shell-allow",
        action="append",
        default=[],
        help='Allowed shell command prefix, for example "git status". Repeat for multiple prefixes.',
    )
    parser.add_argument("--enable-browser", action="store_true", help="Enable isolated Playwright browser endpoints. Disabled by default.")
    parser.add_argument(
        "--browser-allow-private-hosts",
        action="store_true",
        help="Allow the isolated browser to open loopback and private network hosts.",
    )
    args = parser.parse_args()
    serve(
        args.host,
        args.port,
        Path(args.state_path),
        Path(args.audit_path) if args.audit_path else None,
        Path(args.screenshot_dir) if args.screenshot_dir else None,
        Path(args.backup_dir) if args.backup_dir else None,
        args.workspace,
        args.enable_shell,
        args.shell_allow,
        args.enable_browser,
        args.browser_allow_private_hosts,
    )


def _validate_loopback_host(host: str) -> None:
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        if host == "localhost":
            return
    raise ValueError("DeskWarden daemon must bind to a loopback host.")


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _context(payload: Mapping[str, Any]) -> tuple[str, str]:
    return str(payload.get("session_id", "")), str(payload.get("user_id", ""))


def _proposal_from_payload(payload: Mapping[str, Any]) -> ActionProposal | None:
    value = payload.get("proposal")
    if not isinstance(value, Mapping):
        return None
    return ActionProposal.from_dict(value)


def _approval_from_payload(value: Any) -> ApprovalRequest | None:
    if not isinstance(value, Mapping):
        return None
    return ApprovalRequest.from_dict(value)


def _browser_proposal_payload(action_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    action = action_type.lower().strip()
    if action == "type_text":
        return {
            "selector": str(payload.get("selector", "")),
            "text_sha256": _sha256_text(str(payload.get("text", ""))),
            "text_length": len(str(payload.get("text", ""))),
        }
    return dict(payload)


def _approval_ok(proposal: ActionProposal, approval: ApprovalRequest | None) -> bool:
    if approval is None:
        return False
    if approval.proposal_id != proposal.id:
        return False
    if approval.status != ApprovalStatus.APPROVED:
        return False
    if approval.expires_at and now_ts() > approval.expires_at:
        return False
    return True


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


if __name__ == "__main__":
    main()
