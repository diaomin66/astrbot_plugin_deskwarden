from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register

try:
    from .deskwarden_policy import classify_interaction
    from .deskwarden_rpc import ActionResponse, DeskWardenRpcClient, RpcError
    from .deskwarden_types import ActionProposal, ApprovalRequest, ApprovalStatus, CapabilityTier, SessionState, now_ts
except ImportError:  # pragma: no cover - keeps local smoke tests simple.
    from deskwarden_policy import classify_interaction
    from deskwarden_rpc import ActionResponse, DeskWardenRpcClient, RpcError
    from deskwarden_types import ActionProposal, ApprovalRequest, ApprovalStatus, CapabilityTier, SessionState, now_ts


PLUGIN_NAME = "astrbot_plugin_deskwarden"
REFUSAL_MESSAGE = "DeskWarden: refused. Owner private chat only."
DEFAULT_DAEMON_URL = "http://127.0.0.1:8765"
DEFAULT_DATA_DIR = ".deskwarden"
DEFAULT_RPC_TIMEOUT_SECONDS = 3.0
PHASE_SCOPE = (
    "Enabled phases: observe, interaction, approval/audit, file sandbox, restricted shell, isolated browser. "
    "Shell and browser capabilities remain daemon-disabled unless explicitly configured."
)


@dataclass
class PendingAction:
    kind: str
    proposal: ActionProposal
    approval: ApprovalRequest
    request: dict[str, Any]


class SharedSecretStore:
    def __init__(self, data_dir: Path):
        self.path = data_dir / "plugin_secret.json"

    def load(self) -> str | None:
        if not self.path.exists():
            return None

        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("DeskWarden could not read shared secret store: %s", self.path)
            return None

        secret = str(payload.get("shared_secret") or "").strip()
        return secret or None

    def save(self, shared_secret: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"shared_secret": shared_secret}
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass


@register(PLUGIN_NAME, "DeskWarden", "Owner-only desktop control guard for AstrBot.", "0.9.0")
class DeskWardenPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig | None = None):
        super().__init__(context)
        self.config: Mapping[str, Any] = config or {}
        self.owner_id = str(self.config.get("owner_id", "")).strip()
        self.daemon_url = str(self.config.get("daemon_url", DEFAULT_DAEMON_URL) or DEFAULT_DAEMON_URL).strip()
        self.rpc_timeout_seconds = _float_config(self.config.get("rpc_timeout_seconds"), DEFAULT_RPC_TIMEOUT_SECONDS)
        self.data_dir = self._resolve_data_dir(str(self.config.get("data_dir", DEFAULT_DATA_DIR) or DEFAULT_DATA_DIR))
        self.secret_store = SharedSecretStore(self.data_dir)
        self.shared_secret = self.secret_store.load()
        self.state = SessionState.IDLE
        self.session_id: str | None = None
        self._state_before_pause: SessionState | None = None
        self.pending: dict[str, PendingAction] = {}

    async def initialize(self):
        logger.info("DeskWarden loaded with phases 3-6 enabled.")

    async def terminate(self):
        logger.info("DeskWarden terminated.")

    @filter.command_group("desk")
    def desk(self):
        """DeskWarden command group."""
        pass

    @desk.command("start")
    async def start(self, event: AstrMessageEvent):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return

        if self.state == SessionState.PAUSED:
            yield event.plain_result(await self._format_status("DeskWarden is paused. Use /desk resume first."))
            return

        daemon_ready, daemon_message = await self._check_signed_daemon()
        if not daemon_ready:
            self.state = SessionState.LOCKED
            yield event.plain_result(await self._format_status(f"DeskWarden cannot start: {daemon_message}"))
            return

        self.state = SessionState.OBSERVING
        self.session_id = self._get_session_id(event)
        self._state_before_pause = None
        yield event.plain_result(await self._format_status("DeskWarden started. Signed daemon RPC is healthy."))

    @desk.command("status")
    async def status(self, event: AstrMessageEvent):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return
        yield event.plain_result(await self._format_status("DeskWarden status:"))

    @desk.command("pair")
    async def pair(self, event: AstrMessageEvent, token: str = ""):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return

        pairing_token = (token or self._extract_command_argument(event, "pair")).strip()
        if not pairing_token:
            yield event.plain_result("Usage: /desk pair <daemon pairing token>")
            return

        try:
            result = await self._rpc_client(shared_secret=None).pair(pairing_token, PLUGIN_NAME)
        except (RpcError, ValueError) as exc:
            self.state = SessionState.LOCKED
            yield event.plain_result(await self._format_status(f"Pairing failed: {self._describe_error(exc)}"))
            return

        self.shared_secret = result.shared_secret
        self.secret_store.save(result.shared_secret)
        self.state = SessionState.LOCKED
        self._state_before_pause = None
        yield event.plain_result(await self._format_status("Pairing succeeded. Daemon remains LOCKED until /desk start."))

    @desk.command("rotate-key")
    async def rotate_key(self, event: AstrMessageEvent):
        self._stop_event(event)
        guard = await self._owner_guard(event, require_active=False)
        if guard:
            yield event.plain_result(guard)
            return

        try:
            result = await self._rpc_client().rotate_secret()
        except (RpcError, ValueError) as exc:
            self.state = SessionState.LOCKED
            yield event.plain_result(await self._format_status(f"Key rotation failed: {self._describe_error(exc)}"))
            return

        self.shared_secret = result.shared_secret
        self.secret_store.save(result.shared_secret)
        yield event.plain_result(await self._format_status("Key rotation succeeded."))

    @desk.command("stop")
    async def stop(self, event: AstrMessageEvent):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return

        self.state = SessionState.IDLE
        self.session_id = None
        self._state_before_pause = None
        self.pending.clear()
        yield event.plain_result(await self._format_status("DeskWarden stopped."))

    @desk.command("pause")
    async def pause(self, event: AstrMessageEvent):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return

        if self.state == SessionState.IDLE:
            yield event.plain_result(await self._format_status("DeskWarden has no active session."))
            return

        if self.state != SessionState.PAUSED:
            self._state_before_pause = self.state
            self.state = SessionState.PAUSED

        yield event.plain_result(await self._format_status("DeskWarden paused."))

    @desk.command("resume")
    async def resume(self, event: AstrMessageEvent):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return

        if self.state != SessionState.PAUSED:
            yield event.plain_result(await self._format_status("DeskWarden is not paused."))
            return

        self.state = self._state_before_pause or SessionState.OBSERVING
        self._state_before_pause = None
        if self.session_id is None:
            self.session_id = self._get_session_id(event)

        yield event.plain_result(await self._format_status("DeskWarden resumed."))

    @desk.command("observe")
    async def observe(self, event: AstrMessageEvent, mode: str = "screen"):
        self._stop_event(event)
        guard = await self._owner_guard(event)
        if guard:
            yield event.plain_result(guard)
            return

        mode = (mode or self._extract_command_argument(event, "observe") or "screen").strip().lower()
        session_id, user_id = self._session_user(event)
        try:
            if mode in {"active", "active-window", "window"}:
                response = await self._rpc_client().observe_active_window(session_id, user_id)
            else:
                response = await self._rpc_client().observe_screen(session_id, user_id)
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"Observe failed: {self._describe_error(exc)}")
            return

        yield event.plain_result(self._format_action_response("Observe result", response))

    @desk.command("windows")
    async def windows(self, event: AstrMessageEvent):
        self._stop_event(event)
        guard = await self._owner_guard(event)
        if guard:
            yield event.plain_result(guard)
            return

        session_id, user_id = self._session_user(event)
        try:
            response = await self._rpc_client().list_windows(session_id, user_id)
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"Window listing failed: {self._describe_error(exc)}")
            return

        yield event.plain_result(self._format_windows(response))

    @desk.command("summarize")
    async def summarize(self, event: AstrMessageEvent):
        self._stop_event(event)
        guard = await self._owner_guard(event)
        if guard:
            yield event.plain_result(guard)
            return

        session_id, user_id = self._session_user(event)
        try:
            response = await self._rpc_client().summarize_state(session_id, user_id)
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"Summary failed: {self._describe_error(exc)}")
            return

        yield event.plain_result(self._format_action_response("Desktop summary", response))

    @desk.command("click")
    async def click(self, event: AstrMessageEvent, x: str = "", y: str = ""):
        self._stop_event(event)
        args = self._args(event, "click", [x, y])
        if len(args) < 2:
            yield event.plain_result("Usage: /desk click <x> <y>")
            return
        yield event.plain_result(await self._interaction(event, "click", {"x": _int(args[0]), "y": _int(args[1])}))

    @desk.command("double-click")
    async def double_click(self, event: AstrMessageEvent, x: str = "", y: str = ""):
        self._stop_event(event)
        args = self._args(event, "double-click", [x, y])
        if len(args) < 2:
            yield event.plain_result("Usage: /desk double-click <x> <y>")
            return
        yield event.plain_result(await self._interaction(event, "double_click", {"x": _int(args[0]), "y": _int(args[1])}))

    @desk.command("right-click")
    async def right_click(self, event: AstrMessageEvent, x: str = "", y: str = ""):
        self._stop_event(event)
        args = self._args(event, "right-click", [x, y])
        if len(args) < 2:
            yield event.plain_result("Usage: /desk right-click <x> <y>")
            return
        yield event.plain_result(await self._interaction(event, "right_click", {"x": _int(args[0]), "y": _int(args[1])}))

    @desk.command("scroll")
    async def scroll(self, event: AstrMessageEvent, x: str = "", y: str = "", delta: str = ""):
        self._stop_event(event)
        args = self._args(event, "scroll", [x, y, delta])
        if len(args) < 3:
            yield event.plain_result("Usage: /desk scroll <x> <y> <delta>")
            return
        yield event.plain_result(await self._interaction(event, "scroll", {"x": _int(args[0]), "y": _int(args[1]), "delta": _int(args[2])}))

    @desk.command("drag")
    async def drag(self, event: AstrMessageEvent, x1: str = "", y1: str = "", x2: str = "", y2: str = "", duration_ms: str = "250"):
        self._stop_event(event)
        args = self._args(event, "drag", [x1, y1, x2, y2, duration_ms])
        if len(args) < 4:
            yield event.plain_result("Usage: /desk drag <x1> <y1> <x2> <y2> [duration_ms]")
            return
        payload = {"x1": _int(args[0]), "y1": _int(args[1]), "x2": _int(args[2]), "y2": _int(args[3]), "duration_ms": _int(args[4], 250) if len(args) > 4 else 250}
        yield event.plain_result(await self._interaction(event, "drag", payload))

    @desk.command("type")
    async def type_text(self, event: AstrMessageEvent, text: str = ""):
        self._stop_event(event)
        value = text or self._extract_command_argument(event, "type")
        if not value:
            yield event.plain_result("Usage: /desk type <text>")
            return
        yield event.plain_result(await self._interaction(event, "type_text", {"text": value}, summary="Type text into the active window."))

    @desk.command("hotkey")
    async def hotkey(self, event: AstrMessageEvent, keys: str = ""):
        self._stop_event(event)
        value = keys or self._extract_command_argument(event, "hotkey")
        if not value:
            yield event.plain_result("Usage: /desk hotkey <ctrl+s>")
            return
        yield event.plain_result(await self._interaction(event, "hotkey", {"keys": value}, summary=f"Press hotkey {value}."))

    @desk.command("focus")
    async def focus(self, event: AstrMessageEvent, window_id: str = ""):
        self._stop_event(event)
        value = (window_id or self._extract_command_argument(event, "focus")).strip()
        if not value:
            yield event.plain_result("Usage: /desk focus <window_id>")
            return
        yield event.plain_result(await self._interaction(event, "focus_window", {"window_id": value}, target=value, summary=f"Focus window {value}."))

    @desk.command("emergency")
    async def emergency(self, event: AstrMessageEvent):
        self._stop_event(event)
        guard = await self._owner_guard(event, require_active=False)
        if guard:
            yield event.plain_result(guard)
            return

        session_id, user_id = self._session_user(event)
        try:
            response = await self._rpc_client().emergency_stop(session_id, user_id)
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"Emergency stop failed: {self._describe_error(exc)}")
            return

        self.state = SessionState.PAUSED
        yield event.plain_result(self._format_action_response("Emergency stop", response))

    @desk.command("approve")
    async def approve(self, event: AstrMessageEvent, proposal_id: str = ""):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return

        action_id = (proposal_id or self._extract_command_argument(event, "approve")).strip()
        pending = self.pending.pop(action_id, None)
        if pending is None:
            yield event.plain_result("No pending approval with that id.")
            return
        if pending.proposal.is_expired():
            self._restore_after_pending()
            yield event.plain_result("Approval expired and was discarded.")
            return

        approval = pending.approval.with_status(ApprovalStatus.APPROVED)
        session_id, user_id = self._session_user(event)
        self.state = SessionState.EXECUTING
        try:
            if pending.kind == "interaction":
                req = pending.request
                response = await self._rpc_client().interact(
                    session_id,
                    user_id,
                    str(req["action_type"]),
                    dict(req["payload"]),
                    str(req.get("target", "desktop")),
                    str(req.get("summary", "")),
                    pending.proposal,
                    approval,
                )
            elif pending.kind == "file_write":
                req = pending.request
                response = await self._rpc_client().file_write(
                    session_id,
                    user_id,
                    str(req["path"]),
                    str(req["content"]),
                    pending.proposal,
                    approval,
                )
            elif pending.kind == "shell_run":
                req = pending.request
                response = await self._rpc_client().shell_run(
                    session_id,
                    user_id,
                    str(req["command"]),
                    str(req.get("cwd", "")),
                    _int(req.get("timeout_seconds"), 5),
                    pending.proposal,
                    approval,
                )
            elif pending.kind == "browser_action":
                req = pending.request
                response = await self._rpc_client().browser_action(
                    session_id,
                    user_id,
                    str(req["action_type"]),
                    dict(req.get("payload") or {}),
                    summary=str(req.get("summary", "")),
                    proposal=pending.proposal,
                    approval=approval,
                )
            else:
                raise RpcError("UNKNOWN_PENDING_ACTION", f"Unknown pending action kind: {pending.kind}")
        except (RpcError, ValueError) as exc:
            self._restore_after_pending()
            yield event.plain_result(f"Approved action failed: {self._describe_error(exc)}")
            return

        self._restore_after_pending()
        yield event.plain_result(self._format_action_response("Approved action result", response))

    @desk.command("deny")
    async def deny(self, event: AstrMessageEvent, proposal_id: str = ""):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return

        action_id = (proposal_id or self._extract_command_argument(event, "deny")).strip()
        pending = self.pending.pop(action_id, None)
        if pending is None:
            yield event.plain_result("No pending approval with that id.")
            return
        self._restore_after_pending()
        yield event.plain_result(f"Denied proposal {action_id}.")

    @desk.command("read-file")
    async def read_file(self, event: AstrMessageEvent, path: str = ""):
        self._stop_event(event)
        guard = await self._owner_guard(event)
        if guard:
            yield event.plain_result(guard)
            return

        requested_path = path or self._extract_command_argument(event, "read-file")
        if not requested_path:
            yield event.plain_result("Usage: /desk read-file <path>")
            return

        session_id, user_id = self._session_user(event)
        try:
            response = await self._rpc_client().file_read(session_id, user_id, requested_path)
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"File read failed: {self._describe_error(exc)}")
            return
        yield event.plain_result(self._format_file_read(response))

    @desk.command("write-file")
    async def write_file(self, event: AstrMessageEvent, path: str = "", content: str = ""):
        self._stop_event(event)
        guard = await self._owner_guard(event)
        if guard:
            yield event.plain_result(guard)
            return

        requested_path, new_content = self._parse_write_file_args(event, path, content)
        if not requested_path:
            yield event.plain_result("Usage: /desk write-file <path> <new content>")
            return

        session_id, user_id = self._session_user(event)
        try:
            response = await self._rpc_client().file_diff(session_id, user_id, requested_path, new_content)
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"File diff failed: {self._describe_error(exc)}")
            return
        if not response.result.ok:
            yield event.plain_result(self._format_action_response("File diff refused", response))
            return

        pending = self._store_pending(
            event,
            kind="file_write",
            proposal=response.proposal,
            request={"path": requested_path, "content": new_content},
        )
        diff = str((response.result.output or {}).get("diff", ""))
        yield event.plain_result(pending + "\n\nDiff:\n" + _truncate(diff, 2500))

    @desk.command("shell")
    async def shell(self, event: AstrMessageEvent, command: str = ""):
        self._stop_event(event)
        guard = await self._owner_guard(event)
        if guard:
            yield event.plain_result(guard)
            return

        raw_command = self._extract_command_argument(event, "shell") or command
        if not raw_command:
            yield event.plain_result("Usage: /desk shell <allowlisted command>")
            return

        session_id, user_id = self._session_user(event)
        try:
            response = await self._rpc_client().shell_plan(session_id, user_id, raw_command)
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"Shell planning failed: {self._describe_error(exc)}")
            return
        if not response.result.ok:
            yield event.plain_result(self._format_action_response("Shell command refused", response))
            return

        request = dict(response.proposal.payload)
        pending = self._store_pending(event, kind="shell_run", proposal=response.proposal, request=request)
        plan = json.dumps(response.result.output or {}, ensure_ascii=False, indent=2)
        yield event.plain_result(pending + "\n\nPlan:\n" + _truncate(plan, 1800))

    @desk.command("browser")
    async def browser(self, event: AstrMessageEvent, action: str = ""):
        self._stop_event(event)
        guard = await self._owner_guard(event)
        if guard:
            yield event.plain_result(guard)
            return

        raw = (self._extract_command_argument(event, "browser") or action).strip()
        parsed = self._parse_browser_command(raw)
        if isinstance(parsed, str):
            yield event.plain_result(parsed)
            return

        action_type, payload, summary = parsed
        session_id, user_id = self._session_user(event)
        try:
            response = await self._rpc_client().browser_action(session_id, user_id, action_type, payload, summary=summary)
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"Browser action failed: {self._describe_error(exc)}")
            return

        if response.result.error_code == "APPROVAL_REQUIRED":
            pending = self._store_pending(
                event,
                kind="browser_action",
                proposal=response.proposal,
                request={"action_type": action_type, "payload": payload, "summary": summary},
            )
            yield event.plain_result(pending)
            return

        yield event.plain_result(self._format_action_response("Browser result", response))

    @desk.command("audit")
    async def audit(self, event: AstrMessageEvent, action: str = "latest", limit: str = "10"):
        self._stop_event(event)
        guard = await self._owner_guard(event, require_active=False)
        if guard:
            yield event.plain_result(guard)
            return

        choice = (action or self._extract_command_argument(event, "audit") or "latest").strip().lower()
        try:
            if choice.startswith("purge"):
                response = await self._rpc_client().audit_purge()
                yield event.plain_result(f"Audit purged. records={response.get('purged_records', 0)}")
            else:
                count = _int(limit, 10)
                response = await self._rpc_client().audit_latest(count)
                yield event.plain_result(self._format_audit(response.get("records", [])))
        except (RpcError, ValueError) as exc:
            yield event.plain_result(f"Audit command failed: {self._describe_error(exc)}")

    async def _interaction(
        self,
        event: AstrMessageEvent,
        action_type: str,
        payload: Mapping[str, Any],
        target: str = "desktop",
        summary: str = "",
    ) -> str:
        guard = await self._owner_guard(event)
        if guard:
            return guard

        tier, risk_reason, needs_approval = classify_interaction(action_type, payload, target, summary)
        session_id, user_id = self._session_user(event)
        summary = summary or f"Desktop interaction: {action_type}"

        if needs_approval:
            proposal = ActionProposal.create(
                session_id=session_id,
                action_type=action_type,
                tier=tier,
                summary=summary,
                target=target,
                payload=dict(payload),
                risk_reason=risk_reason,
                rollback_hint="Use /desk emergency to stop further actions; manually undo UI changes if needed.",
            )
            return self._store_pending(
                event,
                kind="interaction",
                proposal=proposal,
                request={"action_type": action_type, "payload": dict(payload), "target": target, "summary": summary},
            )

        self.state = SessionState.EXECUTING
        try:
            response = await self._rpc_client().interact(session_id, user_id, action_type, payload, target, summary)
        except (RpcError, ValueError) as exc:
            self.state = SessionState.OBSERVING
            return f"Interaction failed: {self._describe_error(exc)}"

        self.state = SessionState.OBSERVING
        return self._format_action_response("Interaction result", response)

    def _store_pending(
        self,
        event: AstrMessageEvent,
        kind: str,
        proposal: ActionProposal,
        request: Mapping[str, Any],
    ) -> str:
        self._prune_expired_pending()
        if self.pending:
            return "Another approval is already pending. Approve, deny, or let it expire first."

        _session_id, user_id = self._session_user(event)
        approval = ApprovalRequest.create(proposal, user_id)
        self.pending[proposal.id] = PendingAction(kind=kind, proposal=proposal, approval=approval, request=dict(request))
        self.state = SessionState.WAITING_APPROVAL
        return self._format_approval_card(proposal)

    async def _owner_guard(self, event: AstrMessageEvent, require_active: bool = True) -> str | None:
        refusal = self._authorization_refusal(event)
        if refusal:
            return refusal
        if not self.shared_secret:
            self.state = SessionState.LOCKED
            return await self._format_status("DeskWarden is not paired. Run /desk pair <token> first.")
        if self.state == SessionState.PAUSED:
            return await self._format_status("DeskWarden is paused.")
        if require_active and self.state not in {SessionState.OBSERVING, SessionState.WAITING_APPROVAL}:
            return await self._format_status("DeskWarden is not active. Run /desk start first.")
        if require_active and self.state == SessionState.WAITING_APPROVAL:
            self._prune_expired_pending()
            if self.pending:
                return "DeskWarden is waiting for approval. Use /desk approve <id> or /desk deny <id>."
            self.state = SessionState.OBSERVING
        return None

    def _is_authorized(self, event: AstrMessageEvent) -> bool:
        return self._authorization_refusal(event) is None

    def _authorization_refusal(self, event: AstrMessageEvent) -> str | None:
        sender_id = str(event.get_sender_id()).strip()
        is_private = self._is_private_chat(event)
        allowed = bool(self.owner_id) and is_private and sender_id == self.owner_id

        if allowed:
            return None

        logger.warning(
            "DeskWarden refused command: sender_id=%s private=%s owner_configured=%s",
            sender_id,
            is_private,
            bool(self.owner_id),
        )

        if not self.owner_id:
            return (
                f"{REFUSAL_MESSAGE}\n"
                "reason: owner_id is not configured\n"
                f"sender_id: {sender_id}\n"
                "Set owner_id to this sender_id in the plugin config, then use a private chat."
            )
        if not is_private:
            return (
                f"{REFUSAL_MESSAGE}\n"
                "reason: command was not received as a private chat\n"
                f"sender_id: {sender_id}"
            )
        return (
            f"{REFUSAL_MESSAGE}\n"
            "reason: sender_id does not match configured owner_id\n"
            f"sender_id: {sender_id}"
        )

    @staticmethod
    def _is_private_chat(event: AstrMessageEvent) -> bool:
        group_id = ""
        group_signal_seen = False
        if hasattr(event, "get_group_id"):
            group_signal_seen = True
            group_id = DeskWardenPlugin._event_value(event, "get_group_id")

        message_obj = getattr(event, "message_obj", None)
        if not _has_event_value(group_id) and message_obj is not None and hasattr(message_obj, "group_id"):
            group_signal_seen = True
            group_id = getattr(message_obj, "group_id", "")

        if _has_event_value(group_id):
            return False

        message_type = DeskWardenPlugin._event_value(event, "get_message_type")
        if not _has_event_value(message_type) and message_obj is not None:
            message_type = getattr(message_obj, "type", "")
        message_type_text = _event_text(message_type)
        if message_type_text:
            if any(token in message_type_text for token in ("group", "guild", "channel")):
                return False
            if any(token in message_type_text for token in ("private", "friend", "direct")):
                return True

        origin_text = _event_text(DeskWardenPlugin._event_value(event, "unified_msg_origin"))
        if origin_text:
            if any(token in origin_text for token in ("group", "guild", "channel")):
                return False
            if any(token in origin_text for token in ("private", "friend", "direct")):
                return True

        if group_signal_seen:
            return True

        private_signal = DeskWardenPlugin._event_value(event, "is_private_chat")
        if private_signal is not None:
            return bool(private_signal)

        return False

    @staticmethod
    def _event_value(event: AstrMessageEvent, attr_name: str) -> Any:
        if not hasattr(event, attr_name):
            return None
        value = getattr(event, attr_name)
        if callable(value):
            try:
                return value()
            except TypeError:
                return None
        return value

    @staticmethod
    def _get_session_id(event: AstrMessageEvent) -> str:
        if hasattr(event, "get_session_id"):
            return str(event.get_session_id())
        message_obj = getattr(event, "message_obj", None)
        session_id = getattr(message_obj, "session_id", "")
        if session_id:
            return str(session_id)
        if hasattr(event, "unified_msg_origin"):
            return str(event.unified_msg_origin)
        return str(event.get_sender_id())

    def _session_user(self, event: AstrMessageEvent) -> tuple[str, str]:
        session_id = self.session_id or self._get_session_id(event)
        self.session_id = session_id
        return session_id, str(event.get_sender_id()).strip()

    @staticmethod
    def _stop_event(event: AstrMessageEvent) -> None:
        if hasattr(event, "stop_event"):
            event.stop_event()

    @staticmethod
    def _extract_command_argument(event: AstrMessageEvent, command_name: str) -> str:
        message_text = ""
        for attr_name in ("message_str", "raw_message", "message"):
            value = getattr(event, attr_name, "")
            if callable(value):
                try:
                    value = value()
                except TypeError:
                    value = ""
            if value:
                message_text = str(value)
                break

        marker = f"/desk {command_name}"
        if marker not in message_text:
            return ""
        return message_text.split(marker, 1)[1].strip()

    def _args(self, event: AstrMessageEvent, command_name: str, explicit: list[str]) -> list[str]:
        values = [value for value in explicit if str(value).strip()]
        if values:
            return [str(value).strip() for value in values]
        return self._extract_command_argument(event, command_name).split()

    def _parse_write_file_args(self, event: AstrMessageEvent, path: str, content: str) -> tuple[str, str]:
        if path and content:
            return path, content
        raw = self._extract_command_argument(event, "write-file")
        if not raw:
            return path, content
        parts = raw.split(maxsplit=1)
        if len(parts) == 1:
            return parts[0], ""
        return parts[0], parts[1]

    @staticmethod
    def _parse_browser_command(raw: str) -> tuple[str, dict[str, Any], str] | str:
        if not raw:
            return "Usage: /desk browser <open|title|screenshot|click|type|download> ..."
        try:
            parts = shlex.split(raw, posix=True)
        except ValueError:
            return "Browser command could not be parsed. Quote selectors or text that contain spaces."
        if not parts:
            return "Usage: /desk browser <open|title|screenshot|click|type|download> ..."

        action = parts[0].lower()
        if action in {"open", "go", "goto"}:
            if len(parts) < 2:
                return "Usage: /desk browser open <https-url>"
            return "open_url", {"url": parts[1]}, f"Open isolated browser URL: {parts[1]}"
        if action in {"title", "read-title"}:
            return "title", {}, "Read isolated browser title."
        if action in {"screenshot", "shot"}:
            return "screenshot", {}, "Capture isolated browser screenshot."
        if action == "click":
            if len(parts) < 2:
                return "Usage: /desk browser click <selector>"
            selector = " ".join(parts[1:])
            return "click", {"selector": selector}, f"Click isolated browser selector: {selector}"
        if action == "type":
            if len(parts) < 3:
                return "Usage: /desk browser type <selector> <text>"
            return "type_text", {"selector": parts[1], "text": " ".join(parts[2:])}, f"Type into isolated browser selector: {parts[1]}"
        if action == "download":
            if len(parts) < 2:
                return "Usage: /desk browser download <selector>"
            selector = " ".join(parts[1:])
            return "download", {"selector": selector}, f"Download from isolated browser selector: {selector}"
        return "Unknown browser action. Use open, title, screenshot, click, type, or download."

    def _rpc_client(self, shared_secret: str | None = None) -> DeskWardenRpcClient:
        return DeskWardenRpcClient(
            self.daemon_url,
            self.shared_secret if shared_secret is None else shared_secret,
            timeout_seconds=self.rpc_timeout_seconds,
        )

    async def _check_signed_daemon(self) -> tuple[bool, str]:
        if not self.shared_secret:
            try:
                health = await self._rpc_client(shared_secret=None).health()
            except (RpcError, ValueError) as exc:
                return False, self._describe_error(exc)
            if not health.get("paired"):
                return False, "daemon is not paired. Start daemon and run /desk pair <token>."
            return False, "local plugin secret is missing. Pair again or rotate the key."

        try:
            await self._rpc_client().status()
        except (RpcError, ValueError) as exc:
            return False, self._describe_error(exc)
        return True, "ok"

    async def _format_status(self, headline: str) -> str:
        session_id = self.session_id or "-"
        owner_configured = "yes" if self.owner_id else "no"
        paired = "yes" if self.shared_secret else "no"
        daemon_line = await self._daemon_status_line()
        return (
            f"{headline}\n"
            f"state: {self.state.value}\n"
            f"session: {session_id}\n"
            f"owner_configured: {owner_configured}\n"
            f"paired: {paired}\n"
            f"pending_approvals: {len(self.pending)}\n"
            f"daemon_url: {self.daemon_url}\n"
            f"{daemon_line}\n"
            f"{PHASE_SCOPE}"
        )

    async def _daemon_status_line(self) -> str:
        try:
            if self.shared_secret:
                status = await self._rpc_client().status()
                return (
                    "daemon: "
                    f"state={status.get('state', '-')}, "
                    f"paired={_yes_no(status.get('paired'))}, "
                    f"auth_locked={_yes_no(status.get('auth_locked'))}, "
                    f"emergency_stopped={_yes_no(status.get('emergency_stopped'))}, "
                    f"shell_enabled={_yes_no(status.get('shell_enabled'))}, "
                    f"browser_enabled={_yes_no(status.get('browser_enabled'))}"
                )

            health = await self._rpc_client(shared_secret=None).health()
            return (
                "daemon: "
                f"state={health.get('state', '-')}, "
                f"paired={_yes_no(health.get('paired'))}, "
                f"auth_locked={_yes_no(health.get('auth_locked'))}, "
                f"emergency_stopped={_yes_no(health.get('emergency_stopped'))}, "
                f"shell_enabled={_yes_no(health.get('shell_enabled'))}, "
                f"browser_enabled={_yes_no(health.get('browser_enabled'))}"
            )
        except (RpcError, ValueError) as exc:
            return f"daemon: unavailable ({self._describe_error(exc)})"

    @staticmethod
    def _format_action_response(title: str, response: ActionResponse) -> str:
        result = response.result
        lines = [
            title,
            f"proposal_id: {response.proposal.id}",
            f"ok: {_yes_no(result.ok)}",
        ]
        if result.screenshot_ref:
            lines.append(f"screenshot_ref: {result.screenshot_ref}")
        if response.redaction_applied:
            lines.append("redaction_applied: yes")
        if result.error_code:
            lines.append(f"error: {result.error_code}: {result.error_message}")
        elif result.output is not None:
            lines.append("output: " + _truncate(json.dumps(result.output, ensure_ascii=False, indent=2), 1800))
        return "\n".join(lines)

    @staticmethod
    def _format_windows(response: ActionResponse) -> str:
        if not response.result.ok:
            return DeskWardenPlugin._format_action_response("Window listing refused", response)
        windows = (response.result.output or {}).get("windows", [])
        lines = [f"Windows ({len(windows)}):"]
        for window in windows[:20]:
            marker = "*" if window.get("is_active") else "-"
            lines.append(f"{marker} {window.get('window_id')} | {window.get('title')} | {window.get('process_name')}")
        if response.redaction_applied:
            lines.append("redaction_applied: yes")
        return "\n".join(lines)

    @staticmethod
    def _format_file_read(response: ActionResponse) -> str:
        if not response.result.ok:
            return DeskWardenPlugin._format_action_response("File read refused", response)
        output = response.result.output or {}
        content = _truncate(str(output.get("content", "")), 3000)
        return f"File: {output.get('path')}\nsize_bytes: {output.get('size_bytes')}\n\n{content}"

    @staticmethod
    def _format_audit(records: Any) -> str:
        if not records:
            return "Audit log is empty."
        lines = [f"Audit latest ({len(records)}):"]
        for record in records[-20:]:
            proposal = record.get("proposal") or {}
            result = record.get("result") or {}
            lines.append(
                f"- {record.get('timestamp')} {proposal.get('action_type')} "
                f"id={proposal.get('id')} ok={result.get('ok')} redacted={record.get('redaction_applied')}"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_approval_card(proposal: ActionProposal) -> str:
        return (
            "Approval required\n"
            f"id: {proposal.id}\n"
            f"tier: {proposal.tier.value}\n"
            f"summary: {proposal.summary}\n"
            f"target: {proposal.target}\n"
            f"risk: {proposal.risk_reason}\n"
            f"rollback: {proposal.rollback_hint}\n"
            f"expires_at: {proposal.expires_at}\n"
            f"Approve with: /desk approve {proposal.id}\n"
            f"Deny with: /desk deny {proposal.id}"
        )

    def _prune_expired_pending(self) -> None:
        expired = [action_id for action_id, pending in self.pending.items() if pending.proposal.is_expired()]
        for action_id in expired:
            del self.pending[action_id]
        if expired:
            self._restore_after_pending()

    def _restore_after_pending(self) -> None:
        self.state = SessionState.WAITING_APPROVAL if self.pending else SessionState.OBSERVING

    @staticmethod
    def _describe_error(error: Exception) -> str:
        if isinstance(error, RpcError):
            return f"{error.code}: {error}"
        return str(error)

    @staticmethod
    def _resolve_data_dir(value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = Path(__file__).resolve().parent / path
        return path


def _float_config(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _yes_no(value: Any) -> str:
    return "yes" if bool(value) else "no"


def _has_event_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def _event_text(value: Any) -> str:
    if value is None:
        return ""
    return str(getattr(value, "value", value)).strip().lower()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 20)] + "\n...[truncated]"
