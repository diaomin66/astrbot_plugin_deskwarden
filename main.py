from __future__ import annotations

import json
import shlex
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register

try:
    from astrbot.api.event import EventMessageType
except ImportError:  # pragma: no cover - AstrBot stubs and older releases may not expose it.
    EventMessageType = None

try:
    from .deskwarden_agent import (
        DEFAULT_AGENT_SUMMARY_LIMIT,
        DEFAULT_MAX_AGENT_STEPS,
        AgentModelError,
        AgentRunResult,
        AgentRunner,
        AgentToolResult,
        ToolCall,
    )
    from .deskwarden_policy import classify_interaction
    from .deskwarden_rpc import ActionResponse, DeskWardenRpcClient, RpcError
    from .deskwarden_types import ActionProposal, ApprovalRequest, ApprovalStatus, CapabilityTier, SessionState, now_ts
except ImportError:  # pragma: no cover - keeps local smoke tests simple.
    from deskwarden_agent import (
        DEFAULT_AGENT_SUMMARY_LIMIT,
        DEFAULT_MAX_AGENT_STEPS,
        AgentModelError,
        AgentRunResult,
        AgentRunner,
        AgentToolResult,
        ToolCall,
    )
    from deskwarden_policy import classify_interaction
    from deskwarden_rpc import ActionResponse, DeskWardenRpcClient, RpcError
    from deskwarden_types import ActionProposal, ApprovalRequest, ApprovalStatus, CapabilityTier, SessionState, now_ts


PLUGIN_NAME = "astrbot_plugin_deskwarden"
REFUSAL_MESSAGE = "DeskWarden: refused. Owner private chat only."
DEFAULT_DAEMON_URL = "http://127.0.0.1:8765"
DEFAULT_DATA_DIR = ".deskwarden"
DEFAULT_RPC_TIMEOUT_SECONDS = 3.0
PHASE_SCOPE = (
    "Enabled phases: natural language agent, observe, interaction, approval/audit, file sandbox, restricted shell, isolated browser. "
    "Shell and browser capabilities remain daemon-disabled unless explicitly configured."
)


def _private_message_filter(func):
    event_message_type = getattr(filter, "event_message_type", None)
    event_type_namespace = getattr(filter, "EventMessageType", None) or EventMessageType
    private_event_type = None
    if event_type_namespace is not None:
        private_event_type = (
            getattr(event_type_namespace, "PRIVATE_MESSAGE", None)
            or getattr(event_type_namespace, "PRIVATE", None)
            or getattr(event_type_namespace, "FRIEND_MESSAGE", None)
        )
    if callable(event_message_type) and private_event_type is not None:
        return event_message_type(private_event_type)(func)
    return func


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


class DeskWardenAgentToolExecutor:
    def __init__(self, plugin: "DeskWardenPlugin", event: AstrMessageEvent):
        self.plugin = plugin
        self.event = event

    async def execute(self, call: ToolCall) -> AgentToolResult:
        return await self.plugin._execute_agent_tool(self.event, call)


@register(PLUGIN_NAME, "DeskWarden", "Owner-only desktop control guard for AstrBot.", "0.9.0")
class DeskWardenPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig | None = None):
        super().__init__(context)
        self.config: Mapping[str, Any] = config or {}
        self.owner_id = str(self.config.get("owner_id", "")).strip()
        self.daemon_url = str(self.config.get("daemon_url", DEFAULT_DAEMON_URL) or DEFAULT_DAEMON_URL).strip()
        self.rpc_timeout_seconds = _float_config(self.config.get("rpc_timeout_seconds"), DEFAULT_RPC_TIMEOUT_SECONDS)
        self.data_dir = self._resolve_data_dir(str(self.config.get("data_dir", DEFAULT_DATA_DIR) or DEFAULT_DATA_DIR))
        self.agent_enabled = _bool_config(self.config.get("agent_enabled"), True)
        self.agent_auto_capture_private_messages = _bool_config(
            self.config.get("agent_auto_capture_private_messages"),
            False,
        )
        self.max_agent_steps = _int_config(self.config.get("max_agent_steps"), DEFAULT_MAX_AGENT_STEPS, 1, 30)
        self.llm_vision_enabled = _bool_config(self.config.get("llm_vision_enabled"), True)
        self.approval_for_all_mutations = _bool_config(self.config.get("approval_for_all_mutations"), False)
        self.agent_summary_limit = _int_config(
            self.config.get("agent_summary_limit"),
            DEFAULT_AGENT_SUMMARY_LIMIT,
            500,
            20000,
        )
        self.secret_store = SharedSecretStore(self.data_dir)
        self.shared_secret = self.secret_store.load()
        self.state = SessionState.IDLE
        self.session_id: str | None = None
        self._state_before_pause: SessionState | None = None
        self.pending: dict[str, PendingAction] = {}
        self.agent_mode_enabled = False
        self.agent_current_task = ""
        self.agent_turns: list[Any] = []
        self.agent_last_result: AgentRunResult | None = None
        self.agent_model_client: Callable[[str, str, list[str]], Awaitable[str]] | None = None

    async def initialize(self):
        logger.info("DeskWarden loaded with natural language agent support.")

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

    @desk.command("chat")
    async def chat(self, event: AstrMessageEvent, task: str = ""):
        self._stop_event(event)
        requested_task = task or self._extract_command_argument(event, "chat")
        yield event.plain_result(await self._run_agent_task(event, requested_task))

    @desk.command("agent")
    async def agent(self, event: AstrMessageEvent, action: str = ""):
        self._stop_event(event)
        refusal = self._authorization_refusal(event)
        if refusal:
            yield event.plain_result(refusal)
            return

        raw = (action or self._extract_command_argument(event, "agent") or "status").strip()
        parts = raw.split(maxsplit=1)
        choice = parts[0].lower() if parts else "status"

        if choice in {"on", "enable", "start"}:
            if not self.agent_enabled:
                yield event.plain_result("DeskWarden agent is disabled by config.")
                return
            self.agent_mode_enabled = True
            yield event.plain_result(
                "DeskWarden agent mode is on. Owner private messages can be captured when "
                "agent_auto_capture_private_messages is enabled."
            )
            return

        if choice in {"off", "disable", "stop"}:
            self.agent_mode_enabled = False
            yield event.plain_result("DeskWarden agent mode is off.")
            return

        if choice == "reset":
            self.agent_current_task = ""
            self.agent_turns.clear()
            self.agent_last_result = None
            yield event.plain_result("DeskWarden agent memory reset.")
            return

        if choice == "status":
            yield event.plain_result(self._format_agent_status())
            return

        yield event.plain_result("Usage: /desk agent <on|off|reset|status>")

    @_private_message_filter
    async def agent_private_message(self, event: AstrMessageEvent):
        if not self.agent_enabled or not self.agent_mode_enabled or not self.agent_auto_capture_private_messages:
            return

        message_text = self._event_message_text(event).strip()
        if not message_text or message_text.startswith("/desk"):
            return

        self._stop_event(event)
        yield event.plain_result(await self._run_agent_task(event, message_text))

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

    async def _run_agent_task(self, event: AstrMessageEvent, task: str) -> str:
        if not self.agent_enabled:
            return "DeskWarden agent is disabled by config."

        guard = await self._owner_guard(event)
        if guard:
            return guard

        task = task.strip()
        if not task:
            return "Usage: /desk chat <natural language task>"

        self.agent_current_task = task
        runner = AgentRunner(
            model_client=lambda system_prompt, prompt, image_paths: self._call_agent_model(
                event,
                system_prompt,
                prompt,
                image_paths,
            ),
            tool_executor=DeskWardenAgentToolExecutor(self, event),
            max_steps=self.max_agent_steps,
            summary_limit=self.agent_summary_limit,
            vision_enabled=self.llm_vision_enabled,
        )

        try:
            result = await runner.run(task)
        except (RpcError, ValueError, AgentModelError) as exc:
            self.agent_current_task = ""
            return f"Agent failed: {self._describe_error(exc)}"

        self.agent_last_result = result
        self.agent_turns.extend(result.turns)
        self.agent_turns = self.agent_turns[-20:]
        if result.completed or not result.pending_approval_id:
            self.agent_current_task = ""
        return self._format_agent_run_result(result)

    async def _execute_agent_tool(self, event: AstrMessageEvent, call: ToolCall) -> AgentToolResult:
        session_id, user_id = self._session_user(event)
        rpc = self._rpc_client()

        try:
            if call.name == "summarize_state":
                response = await rpc.summarize_state(session_id, user_id)
                return self._agent_result_from_response("Agent summary", response)
            if call.name == "observe_screen":
                response = await rpc.observe_screen(session_id, user_id)
                return self._agent_result_from_response("Agent observe screen", response)
            if call.name == "observe_active_window":
                response = await rpc.observe_active_window(session_id, user_id)
                return self._agent_result_from_response("Agent observe active window", response)
            if call.name == "list_windows":
                response = await rpc.list_windows(session_id, user_id)
                return self._agent_result_from_response("Agent windows", response)
            if call.name in {"click", "double_click", "right_click", "scroll", "drag", "type_text", "hotkey", "focus_window"}:
                return await self._execute_agent_interaction(event, call)
            if call.name == "read_file":
                response = await rpc.file_read(session_id, user_id, str(call.args["path"]))
                return self._agent_result_from_response("Agent read file", response)
            if call.name == "write_file_diff":
                return await self._execute_agent_file_write_diff(event, call)
            if call.name == "shell_plan":
                return await self._execute_agent_shell_plan(event, call)
            if call.name in {"browser_open", "browser_click", "browser_type", "browser_screenshot"}:
                return await self._execute_agent_browser_action(event, call)
        except (RpcError, ValueError) as exc:
            return AgentToolResult(False, f"Agent tool failed: {self._describe_error(exc)}", error_code="TOOL_FAILED")

        return AgentToolResult(False, f"Unsupported agent tool: {call.name}", error_code="UNKNOWN_AGENT_TOOL")

    async def _execute_agent_interaction(self, event: AstrMessageEvent, call: ToolCall) -> AgentToolResult:
        action_type = call.name
        payload = dict(call.args)
        target = "desktop"
        summary = call.summary or f"Agent desktop interaction: {action_type}"
        tier, risk_reason, needs_approval = classify_interaction(action_type, payload, target, summary)
        if self.approval_for_all_mutations:
            needs_approval = True
            if tier == CapabilityTier.INTERACT:
                tier = CapabilityTier.MUTATE
                risk_reason = "Config requires approval for all agent desktop interactions."

        session_id, user_id = self._session_user(event)
        if needs_approval:
            proposal = ActionProposal.create(
                session_id=session_id,
                action_type=action_type,
                tier=tier,
                summary=summary,
                target=target,
                payload=payload,
                risk_reason=risk_reason,
                rollback_hint="Use /desk emergency to stop further actions; manually undo UI changes if needed.",
            )
            message = self._store_pending(
                event,
                kind="interaction",
                proposal=proposal,
                request={"action_type": action_type, "payload": payload, "target": target, "summary": summary},
            )
            return AgentToolResult(
                False,
                message,
                pending_approval_id=proposal.id if proposal.id in self.pending else None,
                error_code="APPROVAL_REQUIRED",
            )

        self.state = SessionState.EXECUTING
        try:
            response = await self._rpc_client().interact(session_id, user_id, action_type, payload, target, summary)
        finally:
            if self.state == SessionState.EXECUTING:
                self.state = SessionState.OBSERVING
        return self._agent_result_from_response("Agent interaction", response)

    async def _execute_agent_file_write_diff(self, event: AstrMessageEvent, call: ToolCall) -> AgentToolResult:
        session_id, user_id = self._session_user(event)
        path = str(call.args["path"])
        content = str(call.args.get("content", ""))
        response = await self._rpc_client().file_diff(session_id, user_id, path, content)
        if not response.result.ok:
            return self._agent_result_from_response("Agent file diff refused", response)

        message = self._store_pending(
            event,
            kind="file_write",
            proposal=response.proposal,
            request={"path": path, "content": content},
        )
        diff = str((response.result.output or {}).get("diff", ""))
        pending_id = response.proposal.id if response.proposal.id in self.pending else None
        return AgentToolResult(
            False,
            message + "\n\nDiff:\n" + _truncate(diff, 2500),
            output=response.result.output,
            pending_approval_id=pending_id,
            error_code="APPROVAL_REQUIRED",
        )

    async def _execute_agent_shell_plan(self, event: AstrMessageEvent, call: ToolCall) -> AgentToolResult:
        session_id, user_id = self._session_user(event)
        response = await self._rpc_client().shell_plan(
            session_id,
            user_id,
            str(call.args["command"]),
            str(call.args.get("cwd", "")),
            _int(call.args.get("timeout_seconds"), 5),
        )
        if not response.result.ok:
            return self._agent_result_from_response("Agent shell refused", response)

        request = dict(response.proposal.payload)
        message = self._store_pending(event, kind="shell_run", proposal=response.proposal, request=request)
        pending_id = response.proposal.id if response.proposal.id in self.pending else None
        plan = json.dumps(response.result.output or {}, ensure_ascii=False, indent=2)
        return AgentToolResult(
            False,
            message + "\n\nPlan:\n" + _truncate(plan, 1800),
            output=response.result.output,
            pending_approval_id=pending_id,
            error_code="APPROVAL_REQUIRED",
        )

    async def _execute_agent_browser_action(self, event: AstrMessageEvent, call: ToolCall) -> AgentToolResult:
        session_id, user_id = self._session_user(event)
        action_type, payload, summary = self._agent_browser_rpc_payload(call)

        if self.approval_for_all_mutations and action_type in {"click", "type_text"}:
            proposal = ActionProposal.create(
                session_id=session_id,
                action_type=action_type,
                tier=CapabilityTier.MUTATE,
                summary=summary,
                target="isolated_browser",
                payload=_browser_proposal_payload(action_type, payload),
                risk_reason="Config requires approval for all agent browser interactions.",
                rollback_hint="Close the isolated browser or manually reverse the page action if needed.",
            )
            message = self._store_pending(
                event,
                kind="browser_action",
                proposal=proposal,
                request={"action_type": action_type, "payload": payload, "summary": summary},
            )
            return AgentToolResult(
                False,
                message,
                pending_approval_id=proposal.id if proposal.id in self.pending else None,
                error_code="APPROVAL_REQUIRED",
            )

        response = await self._rpc_client().browser_action(session_id, user_id, action_type, payload, summary=summary)
        if response.result.error_code == "APPROVAL_REQUIRED":
            message = self._store_pending(
                event,
                kind="browser_action",
                proposal=response.proposal,
                request={"action_type": action_type, "payload": payload, "summary": summary},
            )
            return AgentToolResult(
                False,
                message,
                output=response.result.output,
                screenshot_ref=response.result.screenshot_ref,
                pending_approval_id=response.proposal.id if response.proposal.id in self.pending else None,
                error_code=response.result.error_code,
            )
        return self._agent_result_from_response("Agent browser result", response)

    @staticmethod
    def _agent_browser_rpc_payload(call: ToolCall) -> tuple[str, dict[str, Any], str]:
        if call.name == "browser_open":
            url = str(call.args["url"])
            return "open_url", {"url": url}, f"Agent open isolated browser URL: {url}"
        if call.name == "browser_click":
            selector = str(call.args["selector"])
            return "click", {"selector": selector}, f"Agent click isolated browser selector: {selector}"
        if call.name == "browser_type":
            selector = str(call.args["selector"])
            return "type_text", {"selector": selector, "text": str(call.args.get("text", ""))}, f"Agent type into isolated browser selector: {selector}"
        return "screenshot", {}, "Agent capture isolated browser screenshot."

    @staticmethod
    def _agent_result_from_response(title: str, response: ActionResponse) -> AgentToolResult:
        result = response.result
        output = result.output
        screenshot_ref = result.screenshot_ref
        if screenshot_ref is None and isinstance(output, Mapping):
            screenshot_ref = (
                _optional_output_str(output.get("after_screenshot_ref"))
                or _optional_output_str(output.get("before_screenshot_ref"))
            )
        return AgentToolResult(
            ok=result.ok,
            message=DeskWardenPlugin._format_action_response(title, response),
            output=output,
            screenshot_ref=screenshot_ref,
            redaction_applied=response.redaction_applied,
            error_code=result.error_code,
        )

    async def _call_agent_model(
        self,
        event: AstrMessageEvent,
        system_prompt: str,
        prompt: str,
        image_paths: list[str],
    ) -> str:
        if self.agent_model_client is not None:
            return await self.agent_model_client(system_prompt, prompt, image_paths)

        context = getattr(self, "context", None)
        if context is None:
            raise AgentModelError("AstrBot context is unavailable; cannot call an LLM provider.")

        last_error: Exception | None = None
        provider_id_getter = getattr(context, "get_current_chat_provider_id", None)
        llm_generate = getattr(context, "llm_generate", None)
        if callable(provider_id_getter) and callable(llm_generate):
            try:
                provider_id = await _maybe_await(
                    provider_id_getter(umo=getattr(event, "unified_msg_origin", self._get_session_id(event)))
                )
            except TypeError:
                provider_id = await _maybe_await(provider_id_getter())
            for kwargs in _agent_model_call_kwargs(event, system_prompt, prompt, image_paths, provider_id=provider_id):
                try:
                    response = await _maybe_await(llm_generate(**kwargs))
                    return _extract_llm_text(response)
                except TypeError as exc:
                    last_error = exc

        for method_name in ("llm_generate", "generate", "ask"):
            method = getattr(context, method_name, None)
            if callable(method):
                for kwargs in _agent_model_call_kwargs(event, system_prompt, prompt, image_paths):
                    try:
                        response = await _maybe_await(method(**kwargs))
                        return _extract_llm_text(response)
                    except TypeError as exc:
                        last_error = exc

        provider = self._get_astrbot_provider(event)
        if provider is not None:
            for method_name in ("text_chat", "chat", "generate", "ask"):
                method = getattr(provider, method_name, None)
                if callable(method):
                    for kwargs in _agent_model_call_kwargs(event, system_prompt, prompt, image_paths):
                        try:
                            response = await _maybe_await(method(**kwargs))
                            return _extract_llm_text(response)
                        except TypeError as exc:
                            last_error = exc

        detail = f" Last error: {last_error}" if last_error is not None else ""
        raise AgentModelError("No compatible AstrBot LLM provider method was found." + detail)

    def _get_astrbot_provider(self, event: AstrMessageEvent) -> Any:
        context = getattr(self, "context", None)
        if context is None:
            return None
        getter = getattr(context, "get_using_provider", None)
        if not callable(getter):
            return None
        for args in ((self._get_session_id(event),), (getattr(event, "unified_msg_origin", ""),), ()):
            try:
                return getter(*args)
            except TypeError:
                continue
        return None

    def _format_agent_run_result(self, result: AgentRunResult) -> str:
        lines = [
            "DeskWarden agent result",
            f"completed: {_yes_no(result.completed)}",
            f"steps: {result.steps}",
        ]
        if result.pending_approval_id:
            lines.append(f"pending_approval_id: {result.pending_approval_id}")
        if result.last_screenshot_ref:
            lines.append(f"last_screenshot_ref: {result.last_screenshot_ref}")
        lines.append("")
        lines.append(_truncate(result.message, self.agent_summary_limit))

        recent_actions = [turn.model_action.name for turn in result.turns[-4:] if turn.model_action is not None]
        if recent_actions:
            lines.append("")
            lines.append("recent_actions: " + ", ".join(recent_actions))
        return "\n".join(lines)

    def _format_agent_status(self) -> str:
        last = self.agent_last_result
        lines = [
            "DeskWarden agent status:",
            f"agent_enabled: {_yes_no(self.agent_enabled)}",
            f"agent_mode_enabled: {_yes_no(self.agent_mode_enabled)}",
            f"auto_capture_private_messages: {_yes_no(self.agent_auto_capture_private_messages)}",
            f"vision_enabled: {_yes_no(self.llm_vision_enabled)}",
            f"max_agent_steps: {self.max_agent_steps}",
            f"current_task: {self.agent_current_task or '-'}",
            f"remembered_turns: {len(self.agent_turns)}",
            f"pending_approvals: {len(self.pending)}",
        ]
        if last is not None:
            lines.extend(
                [
                    f"last_completed: {_yes_no(last.completed)}",
                    f"last_steps: {last.steps}",
                    f"last_pending_approval_id: {last.pending_approval_id or '-'}",
                    f"last_screenshot_ref: {last.last_screenshot_ref or '-'}",
                ]
            )
        return "\n".join(lines)

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
        message_text = DeskWardenPlugin._event_message_text(event)
        marker = f"/desk {command_name}"
        if marker not in message_text:
            return ""
        return message_text.split(marker, 1)[1].strip()

    @staticmethod
    def _event_message_text(event: AstrMessageEvent) -> str:
        for attr_name in ("message_str", "raw_message", "message"):
            value = getattr(event, attr_name, "")
            if callable(value):
                try:
                    value = value()
                except TypeError:
                    value = ""
            if value:
                return str(value)
        return ""

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


def _int_config(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def _bool_config(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    return default


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


def _optional_output_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _browser_proposal_payload(action_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if action_type == "type_text":
        text = str(payload.get("text", ""))
        return {
            "selector": str(payload.get("selector", "")),
            "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "text_length": len(text),
        }
    return dict(payload)


def _agent_model_call_kwargs(
    event: AstrMessageEvent,
    system_prompt: str,
    prompt: str,
    image_paths: list[str],
    provider_id: str | None = None,
) -> list[dict[str, Any]]:
    base = {"system_prompt": system_prompt, "prompt": prompt}
    message = [{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt}]
    candidates: list[dict[str, Any]] = []
    provider_fields = {"chat_provider_id": provider_id} if provider_id else {}
    if image_paths:
        candidates.extend(
            [
                {**provider_fields, **base, "image_urls": image_paths},
                {**provider_fields, **base, "images": image_paths},
                {**provider_fields, **base, "image_paths": image_paths},
            ]
        )
    candidates.extend(
        [
            {**provider_fields, **base},
            {**provider_fields, "prompt": prompt},
            {**provider_fields, "message": prompt, "system_prompt": system_prompt},
            {**provider_fields, "messages": message},
        ]
    )
    session_id = getattr(event, "unified_msg_origin", "") or DeskWardenPlugin._get_session_id(event)
    return [{**candidate, "session_id": session_id} for candidate in candidates] + candidates


async def _maybe_await(value: Any) -> Any:
    if hasattr(value, "__await__"):
        return await value
    return value


def _extract_llm_text(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, Mapping):
        for key in ("completion_text", "text", "content", "message", "result", "response"):
            value = response.get(key)
            if value:
                return str(value)
    for attr_name in ("completion_text", "text", "content", "message", "result", "response"):
        value = getattr(response, attr_name, None)
        if value:
            if isinstance(value, list):
                return "\n".join(str(item) for item in value)
            return str(value)
    return str(response)
