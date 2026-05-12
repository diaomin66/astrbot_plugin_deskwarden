from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Protocol


DEFAULT_MAX_AGENT_STEPS = 8
DEFAULT_AGENT_SUMMARY_LIMIT = 4000
MAX_COORDINATE = 100000
MAX_TYPE_TEXT_LENGTH = 4096
MAX_PATH_LENGTH = 4096
MAX_URL_LENGTH = 2048
MAX_SELECTOR_LENGTH = 512
MAX_SHELL_COMMAND_LENGTH = 2000
MAX_AGENT_MESSAGE_LENGTH = 3000


OBSERVE_TOOLS = {
    "observe_screen",
    "observe_active_window",
    "list_windows",
    "summarize_state",
}
DESKTOP_INTERACTION_TOOLS = {
    "click",
    "double_click",
    "right_click",
    "scroll",
    "drag",
    "type_text",
    "hotkey",
    "focus_window",
}
BROWSER_TOOLS = {
    "browser_open",
    "browser_click",
    "browser_type",
    "browser_screenshot",
}
FILE_TOOLS = {
    "read_file",
    "write_file_diff",
}
SHELL_TOOLS = {"shell_plan"}
TERMINAL_TOOLS = {"finish", "ask_user"}
ALLOWED_TOOLS = OBSERVE_TOOLS | DESKTOP_INTERACTION_TOOLS | BROWSER_TOOLS | FILE_TOOLS | SHELL_TOOLS | TERMINAL_TOOLS
POST_ACTION_OBSERVE_TOOLS = DESKTOP_INTERACTION_TOOLS | {"browser_open", "browser_click", "browser_type"}


SYSTEM_PROMPT = """You are DeskWarden Agent, a guarded desktop-control planner.

You control a Windows desktop only through the listed structured tools. You must:
- Observe before acting, then re-check the result after UI actions.
- Return exactly one JSON object per turn.
- Use only allowed tool names and validated arguments.
- Never ask to bypass approval, audit, pairing, HMAC, policy, or emergency stop.
- Do not handle passwords, OTPs, private keys, bank/payment/transfer flows, identity verification, or CAPTCHA solving. Ask the user to take over or request approval when appropriate.
- Do not guess screen coordinates. Use coordinates only when they are grounded in the current screenshot or window context.
- Prefer concise, reversible steps. Stop with finish when the user goal is complete.

Return JSON in this shape:
{
  "thought_summary": "short user-visible reason for the next step",
  "action": "one_allowed_tool_name",
  "args": {},
  "risk_hint": "brief risk note or empty string"
}
"""


TOOL_SCHEMA_TEXT = """Allowed tools and arguments:
- summarize_state: {}
- observe_screen: {}
- observe_active_window: {}
- list_windows: {}
- click: {"x": int, "y": int}
- double_click: {"x": int, "y": int}
- right_click: {"x": int, "y": int}
- scroll: {"x": int, "y": int, "delta": int}
- drag: {"x1": int, "y1": int, "x2": int, "y2": int, "duration_ms": optional int}
- type_text: {"text": string}
- hotkey: {"keys": string or string[]}
- focus_window: {"window_id": string}
- read_file: {"path": string}
- write_file_diff: {"path": string, "content": string}
- shell_plan: {"command": string, "cwd": optional string, "timeout_seconds": optional int}
- browser_open: {"url": string}
- browser_click: {"selector": string}
- browser_type: {"selector": string, "text": string}
- browser_screenshot: {}
- ask_user: {"question": string}
- finish: {"message": string}
"""


class AgentError(RuntimeError):
    pass


class AgentValidationError(AgentError):
    pass


class AgentModelError(AgentError):
    pass


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    summary: str = ""


@dataclass(frozen=True)
class AgentToolResult:
    ok: bool
    message: str
    output: Any = None
    screenshot_ref: str | None = None
    redaction_applied: bool = False
    pending_approval_id: str | None = None
    error_code: str | None = None

    def to_public_dict(self, limit: int = DEFAULT_AGENT_SUMMARY_LIMIT) -> dict[str, Any]:
        output = self.output
        if output is not None:
            output = _truncate(json.dumps(output, ensure_ascii=False, indent=2, default=str), limit)
        return {
            "ok": self.ok,
            "message": _truncate(self.message, limit),
            "output": output,
            "screenshot_ref": self.screenshot_ref,
            "redaction_applied": self.redaction_applied,
            "pending_approval_id": self.pending_approval_id,
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class AgentTurn:
    user_message: str
    observation: dict[str, Any]
    model_action: ToolCall | None = None
    execution_result: dict[str, Any] | None = None
    completed: bool = False
    thought_summary: str = ""
    risk_hint: str = ""


@dataclass(frozen=True)
class AgentRunResult:
    completed: bool
    message: str
    steps: int
    pending_approval_id: str | None = None
    last_screenshot_ref: str | None = None
    turns: list[AgentTurn] = field(default_factory=list)


class AgentToolExecutor(Protocol):
    async def execute(self, call: ToolCall) -> AgentToolResult:
        ...


AgentModelClient = Callable[[str, str, list[str]], Awaitable[str]]


class AgentRunner:
    def __init__(
        self,
        model_client: AgentModelClient,
        tool_executor: AgentToolExecutor,
        max_steps: int = DEFAULT_MAX_AGENT_STEPS,
        summary_limit: int = DEFAULT_AGENT_SUMMARY_LIMIT,
        vision_enabled: bool = True,
    ):
        self.model_client = model_client
        self.tool_executor = tool_executor
        self.max_steps = max(1, min(int(max_steps or DEFAULT_MAX_AGENT_STEPS), 30))
        self.summary_limit = max(500, min(int(summary_limit or DEFAULT_AGENT_SUMMARY_LIMIT), 20000))
        self.vision_enabled = bool(vision_enabled)

    async def run(self, user_message: str) -> AgentRunResult:
        task = user_message.strip()
        if not task:
            return AgentRunResult(False, "Usage: /desk chat <task>", 0)

        turns: list[AgentTurn] = []
        last_screenshot_ref: str | None = None
        initial = await self._initial_observation()
        last_screenshot_ref = _first_screenshot(initial) or last_screenshot_ref
        observation = {"initial_observation": initial}

        for step in range(1, self.max_steps + 1):
            image_paths = [last_screenshot_ref] if self.vision_enabled and last_screenshot_ref else []
            prompt = build_agent_prompt(task, turns, observation, self.summary_limit)
            try:
                raw_decision = await self.model_client(SYSTEM_PROMPT, prompt, image_paths)
                decision = parse_model_decision(raw_decision)
                call = validate_tool_call(decision)
            except AgentError as exc:
                message = f"Agent stopped before executing an action: {exc}"
                turns.append(
                    AgentTurn(
                        user_message=task,
                        observation=observation,
                        execution_result={"ok": False, "error": str(exc)},
                    )
                )
                return AgentRunResult(False, message, step - 1, last_screenshot_ref=last_screenshot_ref, turns=turns)
            except Exception as exc:
                message = f"Agent stopped before executing an action: model call failed: {exc}"
                turns.append(
                    AgentTurn(
                        user_message=task,
                        observation=observation,
                        execution_result={"ok": False, "error": str(exc)},
                    )
                )
                return AgentRunResult(False, message, step - 1, last_screenshot_ref=last_screenshot_ref, turns=turns)

            thought_summary = str(decision.get("thought_summary", "")).strip()
            risk_hint = str(decision.get("risk_hint", "")).strip()

            if call.name == "finish":
                message = str(call.args.get("message") or "Done.").strip()
                turns.append(
                    AgentTurn(
                        user_message=task,
                        observation=observation,
                        model_action=call,
                        completed=True,
                        thought_summary=thought_summary,
                        risk_hint=risk_hint,
                    )
                )
                return AgentRunResult(True, message, step, last_screenshot_ref=last_screenshot_ref, turns=turns)

            if call.name == "ask_user":
                question = str(call.args.get("question") or "I need more information.").strip()
                turns.append(
                    AgentTurn(
                        user_message=task,
                        observation=observation,
                        model_action=call,
                        thought_summary=thought_summary,
                        risk_hint=risk_hint,
                    )
                )
                return AgentRunResult(False, question, step, last_screenshot_ref=last_screenshot_ref, turns=turns)

            result = await self.tool_executor.execute(call)
            last_screenshot_ref = result.screenshot_ref or _first_screenshot(result.output) or last_screenshot_ref
            execution_public = result.to_public_dict(self.summary_limit)
            turns.append(
                AgentTurn(
                    user_message=task,
                    observation=observation,
                    model_action=call,
                    execution_result=execution_public,
                    thought_summary=thought_summary,
                    risk_hint=risk_hint,
                )
            )

            if result.pending_approval_id:
                return AgentRunResult(
                    False,
                    result.message,
                    step,
                    pending_approval_id=result.pending_approval_id,
                    last_screenshot_ref=last_screenshot_ref,
                    turns=turns,
                )

            if not result.ok:
                observation = {"last_tool": call.name, "last_result": execution_public}
                continue

            if call.name in POST_ACTION_OBSERVE_TOOLS:
                follow_up = await self._post_action_observation(call.name)
                last_screenshot_ref = _first_screenshot(follow_up) or last_screenshot_ref
                observation = {
                    "last_tool": call.name,
                    "last_result": execution_public,
                    "post_action_observation": follow_up,
                }
            else:
                observation = {"last_tool": call.name, "last_result": execution_public}

        return AgentRunResult(
            False,
            f"Agent stopped after reaching max_agent_steps={self.max_steps}.",
            self.max_steps,
            last_screenshot_ref=last_screenshot_ref,
            turns=turns,
        )

    async def _initial_observation(self) -> dict[str, Any]:
        summary = await self.tool_executor.execute(ToolCall("summarize_state", {}))
        screen = await self.tool_executor.execute(ToolCall("observe_screen", {}))
        observation: dict[str, Any] = {
            "summary": summary.to_public_dict(self.summary_limit),
            "screen": screen.to_public_dict(self.summary_limit),
        }
        if not screen.ok:
            active = await self.tool_executor.execute(ToolCall("observe_active_window", {}))
            observation["active_window"] = active.to_public_dict(self.summary_limit)
            if not active.ok:
                windows = await self.tool_executor.execute(ToolCall("list_windows", {}))
                observation["windows"] = windows.to_public_dict(self.summary_limit)
        return observation

    async def _post_action_observation(self, tool_name: str) -> dict[str, Any]:
        if tool_name.startswith("browser_"):
            result = await self.tool_executor.execute(ToolCall("browser_screenshot", {}))
            return {"browser_screenshot": result.to_public_dict(self.summary_limit)}
        result = await self.tool_executor.execute(ToolCall("observe_active_window", {}))
        if not result.ok:
            fallback = await self.tool_executor.execute(ToolCall("list_windows", {}))
            return {
                "active_window": result.to_public_dict(self.summary_limit),
                "windows": fallback.to_public_dict(self.summary_limit),
            }
        return {"active_window": result.to_public_dict(self.summary_limit)}


def build_agent_prompt(
    user_message: str,
    turns: list[AgentTurn],
    observation: Mapping[str, Any],
    summary_limit: int = DEFAULT_AGENT_SUMMARY_LIMIT,
) -> str:
    recent_turns = [
        {
            "action": turn.model_action.name if turn.model_action else None,
            "args": turn.model_action.args if turn.model_action else None,
            "thought_summary": turn.thought_summary,
            "risk_hint": turn.risk_hint,
            "execution_result": turn.execution_result,
            "completed": turn.completed,
        }
        for turn in turns[-6:]
    ]
    payload = {
        "user_task": user_message,
        "tool_schema": TOOL_SCHEMA_TEXT,
        "current_observation": observation,
        "recent_turns": recent_turns,
        "instruction": "Choose exactly one next tool call or finish/ask_user.",
    }
    return _truncate(json.dumps(payload, ensure_ascii=False, indent=2, default=str), summary_limit * 2)


def parse_model_decision(value: str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Mapping):
        payload = dict(value)
    else:
        text = str(value or "").strip()
        if not text:
            raise AgentModelError("Model returned an empty response.")
        payload = _loads_json_object(_extract_json_object(text))

    action = str(payload.get("action", "")).strip()
    if not action:
        raise AgentValidationError("Model response is missing action.")
    args = payload.get("args", {})
    if args is None:
        args = {}
    if not isinstance(args, Mapping):
        raise AgentValidationError("Model response args must be an object.")
    return {
        "thought_summary": str(payload.get("thought_summary", "")),
        "action": _normalize_action_name(action),
        "args": dict(args),
        "risk_hint": str(payload.get("risk_hint", "")),
    }


def validate_tool_call(decision: Mapping[str, Any]) -> ToolCall:
    name = _normalize_action_name(str(decision.get("action", "")))
    args = dict(decision.get("args") or {})
    if name not in ALLOWED_TOOLS:
        raise AgentValidationError(f"Unknown or disallowed tool: {name}")

    normalized: dict[str, Any]
    if name in OBSERVE_TOOLS or name == "browser_screenshot":
        normalized = {}
    elif name in {"click", "double_click", "right_click"}:
        normalized = {"x": _coord(args, "x"), "y": _coord(args, "y")}
    elif name == "scroll":
        normalized = {
            "x": _coord(args, "x"),
            "y": _coord(args, "y"),
            "delta": _bounded_int(args, "delta", -10000, 10000),
        }
    elif name == "drag":
        normalized = {
            "x1": _coord(args, "x1"),
            "y1": _coord(args, "y1"),
            "x2": _coord(args, "x2"),
            "y2": _coord(args, "y2"),
            "duration_ms": _bounded_int(args, "duration_ms", 0, 60000, default=250),
        }
    elif name == "type_text":
        normalized = {"text": _string_arg(args, "text", MAX_TYPE_TEXT_LENGTH, allow_empty=False)}
    elif name == "hotkey":
        keys = args.get("keys")
        if isinstance(keys, list):
            normalized = {"keys": [_string_value(item, 32, allow_empty=False) for item in keys][:8]}
        else:
            normalized = {"keys": _string_arg(args, "keys", 128, allow_empty=False)}
    elif name == "focus_window":
        normalized = {"window_id": _string_arg(args, "window_id", 64, allow_empty=False)}
    elif name == "read_file":
        normalized = {"path": _string_arg(args, "path", MAX_PATH_LENGTH, allow_empty=False)}
    elif name == "write_file_diff":
        normalized = {
            "path": _string_arg(args, "path", MAX_PATH_LENGTH, allow_empty=False),
            "content": _string_arg(args, "content", 512 * 1024, allow_empty=True),
        }
    elif name == "shell_plan":
        normalized = {
            "command": _string_arg(args, "command", MAX_SHELL_COMMAND_LENGTH, allow_empty=False),
            "cwd": _string_arg(args, "cwd", MAX_PATH_LENGTH, allow_empty=True) if "cwd" in args else "",
            "timeout_seconds": _bounded_int(args, "timeout_seconds", 1, 30, default=5),
        }
    elif name == "browser_open":
        url = _string_arg(args, "url", MAX_URL_LENGTH, allow_empty=False)
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise AgentValidationError("browser_open.url must start with http:// or https://.")
        normalized = {"url": url}
    elif name == "browser_click":
        normalized = {"selector": _string_arg(args, "selector", MAX_SELECTOR_LENGTH, allow_empty=False)}
    elif name == "browser_type":
        normalized = {
            "selector": _string_arg(args, "selector", MAX_SELECTOR_LENGTH, allow_empty=False),
            "text": _string_arg(args, "text", MAX_TYPE_TEXT_LENGTH, allow_empty=True),
        }
    elif name == "finish":
        normalized = {"message": _string_arg(args, "message", MAX_AGENT_MESSAGE_LENGTH, allow_empty=True) or "Done."}
    elif name == "ask_user":
        normalized = {"question": _string_arg(args, "question", MAX_AGENT_MESSAGE_LENGTH, allow_empty=False)}
    else:  # pragma: no cover - guarded by ALLOWED_TOOLS.
        raise AgentValidationError(f"Unsupported tool: {name}")

    return ToolCall(name=name, args=normalized, summary=str(decision.get("thought_summary", "")).strip())


def _normalize_action_name(value: str) -> str:
    lowered = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "doubleclick": "double_click",
        "rightclick": "right_click",
        "type": "type_text",
        "browser_open_url": "browser_open",
        "browser_type_text": "browser_type",
        "browser_shot": "browser_screenshot",
        "file_read": "read_file",
        "file_write_diff": "write_file_diff",
    }
    return aliases.get(lowered, lowered)


def _extract_json_object(text: str) -> str:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.IGNORECASE | re.DOTALL)
    if fenced:
        return fenced.group(1)
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    raise AgentModelError("Model did not return a JSON object.")


def _loads_json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AgentModelError(f"Model returned invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AgentModelError("Model JSON must be an object.")
    return value


def _coord(args: Mapping[str, Any], key: str) -> int:
    return _bounded_int(args, key, 0, MAX_COORDINATE)


def _bounded_int(
    args: Mapping[str, Any],
    key: str,
    minimum: int,
    maximum: int,
    default: int | None = None,
) -> int:
    if key not in args:
        if default is None:
            raise AgentValidationError(f"Missing integer argument: {key}")
        return default
    try:
        value = int(args.get(key))
    except (TypeError, ValueError) as exc:
        raise AgentValidationError(f"Argument {key} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise AgentValidationError(f"Argument {key} is outside {minimum}..{maximum}.")
    return value


def _string_arg(args: Mapping[str, Any], key: str, limit: int, allow_empty: bool) -> str:
    if key not in args:
        if allow_empty:
            return ""
        raise AgentValidationError(f"Missing string argument: {key}")
    return _string_value(args.get(key), limit, allow_empty)


def _string_value(value: Any, limit: int, allow_empty: bool) -> str:
    text = str(value if value is not None else "")
    if not allow_empty and not text.strip():
        raise AgentValidationError("String argument must not be empty.")
    if len(text.encode("utf-8")) > limit:
        raise AgentValidationError(f"String argument exceeds {limit} bytes.")
    return text


def _first_screenshot(value: Any) -> str | None:
    if isinstance(value, AgentToolResult):
        return value.screenshot_ref or _first_screenshot(value.output)
    if isinstance(value, Mapping):
        for key in ("screenshot_ref", "before_screenshot_ref", "after_screenshot_ref"):
            raw = value.get(key)
            if raw:
                return str(raw)
        for item in value.values():
            found = _first_screenshot(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _first_screenshot(item)
            if found:
                return found
    return None


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 20)] + "\n...[truncated]"
