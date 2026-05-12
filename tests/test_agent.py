from __future__ import annotations

import asyncio
import importlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any

from deskwarden_agent import AgentRunner, AgentToolResult, ToolCall, parse_model_decision, validate_tool_call
from deskwarden_rpc import ActionResponse
from deskwarden_types import ActionProposal, ActionResult, CapabilityTier, SessionState


def _install_astrbot_stubs() -> None:
    if "astrbot.api" in sys.modules:
        return

    astrbot_module = types.ModuleType("astrbot")
    api_module = types.ModuleType("astrbot.api")
    event_module = types.ModuleType("astrbot.api.event")
    star_module = types.ModuleType("astrbot.api.star")

    class FakeLogger:
        def info(self, *_args, **_kwargs) -> None:
            pass

        def warning(self, *_args, **_kwargs) -> None:
            pass

    class FakeStar:
        def __init__(self, context=None) -> None:
            self.context = context

    class FakeCommandGroup:
        def __init__(self, func):
            self.func = func

        def __call__(self, *args, **kwargs):
            return self.func(*args, **kwargs)

        def command(self, *_args, **_kwargs):
            def decorator(func):
                return func

            return decorator

    class FakeFilter:
        @staticmethod
        def command_group(*_args, **_kwargs):
            def decorator(func):
                return FakeCommandGroup(func)

            return decorator

    def register(*_args, **_kwargs):
        def decorator(cls):
            return cls

        return decorator

    api_module.AstrBotConfig = dict
    api_module.logger = FakeLogger()
    event_module.AstrMessageEvent = object
    event_module.filter = FakeFilter
    star_module.Context = object
    star_module.Star = FakeStar
    star_module.register = register

    sys.modules["astrbot"] = astrbot_module
    sys.modules["astrbot.api"] = api_module
    sys.modules["astrbot.api.event"] = event_module
    sys.modules["astrbot.api.star"] = star_module


_install_astrbot_stubs()
main = importlib.import_module("main")


class FakeEvent:
    def __init__(self, text: str = "", sender_id: str = "owner", group_id: str = "") -> None:
        self.message_str = text
        self.sender_id = sender_id
        self.group_id = group_id
        self.message_obj = types.SimpleNamespace(group_id=group_id, session_id="session", type="private")
        self.stopped = False

    def get_sender_id(self) -> str:
        return self.sender_id

    def get_group_id(self) -> str:
        return self.group_id

    def get_message_type(self) -> str:
        return "private"

    def stop_event(self) -> None:
        self.stopped = True

    def plain_result(self, text: str) -> str:
        return text


class FakeExecutor:
    def __init__(self):
        self.calls: list[ToolCall] = []

    async def execute(self, call: ToolCall) -> AgentToolResult:
        self.calls.append(call)
        if call.name == "observe_screen":
            return AgentToolResult(True, "screen", output={"scope": "screen"}, screenshot_ref="screen.bmp")
        if call.name == "observe_active_window":
            return AgentToolResult(True, "active", output={"scope": "active"}, screenshot_ref="active.bmp")
        return AgentToolResult(True, call.name, output={"tool": call.name})


class FakeRpc:
    def __init__(self):
        self.calls: list[tuple[str, Any]] = []

    async def summarize_state(self, session_id: str, user_id: str) -> ActionResponse:
        self.calls.append(("summarize_state", {}))
        return _response(session_id, "summarize_state", output={"active_window": {"title": "Notes"}})

    async def observe_screen(self, session_id: str, user_id: str) -> ActionResponse:
        self.calls.append(("observe_screen", {}))
        return _response(session_id, "observe_screen", output={"scope": "screen"}, screenshot_ref="screen.bmp")

    async def observe_active_window(self, session_id: str, user_id: str) -> ActionResponse:
        self.calls.append(("observe_active_window", {}))
        return _response(session_id, "observe_active_window", output={"scope": "active_window"}, screenshot_ref="active.bmp")

    async def list_windows(self, session_id: str, user_id: str) -> ActionResponse:
        self.calls.append(("list_windows", {}))
        return _response(session_id, "list_windows", output={"windows": []})

    async def interact(
        self,
        session_id: str,
        user_id: str,
        action_type: str,
        payload: dict[str, Any],
        target: str,
        summary: str,
    ) -> ActionResponse:
        self.calls.append(("interact", {"action_type": action_type, "payload": payload}))
        return _response(
            session_id,
            action_type,
            tier=CapabilityTier.INTERACT,
            output={"performed": True, "after_screenshot_ref": "after.bmp"},
        )

    async def shell_plan(self, session_id: str, user_id: str, command: str, cwd: str = "", timeout_seconds: int = 5) -> ActionResponse:
        self.calls.append(("shell_plan", {"command": command, "cwd": cwd, "timeout_seconds": timeout_seconds}))
        proposal = ActionProposal.create(
            session_id=session_id,
            action_type="shell_run",
            tier=CapabilityTier.DANGEROUS,
            summary=f"Run restricted shell command: {command}",
            target=cwd or "workspace",
            payload={"command": command, "cwd": cwd, "timeout_seconds": timeout_seconds},
            risk_reason="Restricted shell commands always require owner approval.",
        )
        result = ActionResult(proposal.id, True, output={"command": command})
        return ActionResponse(proposal, result)


def _response(
    session_id: str,
    action_type: str,
    tier: CapabilityTier = CapabilityTier.OBSERVE,
    output: Any = None,
    screenshot_ref: str | None = None,
) -> ActionResponse:
    proposal = ActionProposal.create(
        session_id=session_id,
        action_type=action_type,
        tier=tier,
        summary=action_type,
        target="desktop",
    )
    return ActionResponse(proposal, ActionResult(proposal.id, True, output=output or {}, screenshot_ref=screenshot_ref))


async def _collect(async_iterable) -> list[str]:
    return [item async for item in async_iterable]


class AgentCoreTests(unittest.TestCase):
    def test_parse_and_validate_rejects_bad_actions_and_coordinates(self) -> None:
        decision = parse_model_decision('```json\n{"action":"click","args":{"x":10,"y":20}}\n```')
        call = validate_tool_call(decision)
        self.assertEqual(call.name, "click")
        self.assertEqual(call.args, {"x": 10, "y": 20})

        with self.assertRaises(Exception):
            validate_tool_call({"action": "rm_rf", "args": {}})
        with self.assertRaises(Exception):
            validate_tool_call({"action": "click", "args": {"x": -1, "y": 20}})

    def test_runner_observes_clicks_observes_then_finishes(self) -> None:
        executor = FakeExecutor()
        decisions = [
            {"action": "click", "args": {"x": 3, "y": 4}, "thought_summary": "Click the target."},
            {"action": "finish", "args": {"message": "Done."}},
        ]

        async def model(_system: str, _prompt: str, _images: list[str]) -> str:
            return json.dumps(decisions.pop(0))

        result = asyncio.run(AgentRunner(model, executor, max_steps=4).run("click it"))

        self.assertTrue(result.completed)
        self.assertEqual(result.message, "Done.")
        self.assertEqual([call.name for call in executor.calls], ["summarize_state", "observe_screen", "click", "observe_active_window"])

    def test_runner_stops_at_step_limit(self) -> None:
        executor = FakeExecutor()

        async def model(_system: str, _prompt: str, _images: list[str]) -> str:
            return json.dumps({"action": "summarize_state", "args": {}})

        result = asyncio.run(AgentRunner(model, executor, max_steps=2).run("keep going"))

        self.assertFalse(result.completed)
        self.assertIn("max_agent_steps=2", result.message)


class AgentPluginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.rpc = FakeRpc()
        self.plugin = main.DeskWardenPlugin(
            None,
            {"owner_id": "owner", "data_dir": str(Path(self.temp_dir.name))},
        )
        self.plugin.shared_secret = "secret"
        self.plugin.state = SessionState.OBSERVING
        self.plugin._rpc_client = lambda shared_secret=None: self.rpc

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_chat_runs_agent_loop_for_owner_private_chat(self) -> None:
        decisions = [
            {"action": "click", "args": {"x": 1, "y": 2}, "thought_summary": "Click Notes."},
            {"action": "finish", "args": {"message": "Clicked Notes."}},
        ]

        async def model(_system: str, _prompt: str, _images: list[str]) -> str:
            return json.dumps(decisions.pop(0))

        self.plugin.agent_model_client = model
        event = FakeEvent("/desk chat click notes")

        output = asyncio.run(_collect(self.plugin.chat(event)))[0]

        self.assertIn("completed: yes", output)
        self.assertIn("Clicked Notes.", output)
        self.assertIn(("interact", {"action_type": "click", "payload": {"x": 1, "y": 2}}), self.rpc.calls)

    def test_shell_plan_from_agent_creates_pending_approval(self) -> None:
        async def model(_system: str, _prompt: str, _images: list[str]) -> str:
            return json.dumps({"action": "shell_plan", "args": {"command": "python -m unittest", "timeout_seconds": 5}})

        self.plugin.agent_model_client = model
        event = FakeEvent("/desk chat run tests")

        output = asyncio.run(_collect(self.plugin.chat(event)))[0]

        self.assertIn("pending_approval_id:", output)
        self.assertEqual(len(self.plugin.pending), 1)
        pending = next(iter(self.plugin.pending.values()))
        self.assertEqual(pending.kind, "shell_run")

    def test_non_owner_chat_is_refused(self) -> None:
        self.plugin.agent_model_client = lambda _system, _prompt, _images: json.dumps({"action": "finish", "args": {}})
        event = FakeEvent("/desk chat click", sender_id="intruder")

        output = asyncio.run(_collect(self.plugin.chat(event)))[0]

        self.assertIn("refused", output.lower())


if __name__ == "__main__":
    unittest.main()
