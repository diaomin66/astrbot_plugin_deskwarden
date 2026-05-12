from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path


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
    def __init__(
        self,
        sender_id: str = "owner",
        group_id: str = "",
        private_signal: bool | None = None,
        message_type: str = "",
        origin: str = "",
    ) -> None:
        self.sender_id = sender_id
        self.group_id = group_id
        self.private_signal = private_signal
        self.message_type = message_type
        self.unified_msg_origin = origin
        self.message_obj = types.SimpleNamespace(group_id=group_id, type=message_type)

    def get_sender_id(self) -> str:
        return self.sender_id

    def get_group_id(self) -> str:
        return self.group_id

    def get_message_type(self) -> str:
        return self.message_type

    def is_private_chat(self) -> bool:
        return bool(self.private_signal)


class PluginAuthorizationTests(unittest.TestCase):
    def test_empty_group_id_keeps_private_chat_even_when_private_signal_is_false(self) -> None:
        event = FakeEvent(group_id="", private_signal=False)

        self.assertTrue(main.DeskWardenPlugin._is_private_chat(event))

    def test_group_id_blocks_group_chat_even_when_private_signal_is_true(self) -> None:
        event = FakeEvent(group_id="123456", private_signal=True)

        self.assertFalse(main.DeskWardenPlugin._is_private_chat(event))

    def test_missing_owner_id_refusal_reports_sender_id(self) -> None:
        plugin = main.DeskWardenPlugin(None, {"data_dir": str(Path("build/test-deskwarden"))})

        refusal = plugin._authorization_refusal(FakeEvent(sender_id="42"))

        self.assertIn("owner_id is not configured", refusal)
        self.assertIn("sender_id: 42", refusal)

    def test_owner_authorizes_when_group_signal_indicates_private(self) -> None:
        plugin = main.DeskWardenPlugin(
            None,
            {"owner_id": "42", "data_dir": str(Path("build/test-deskwarden"))},
        )

        refusal = plugin._authorization_refusal(FakeEvent(sender_id="42", group_id="", private_signal=False))

        self.assertIsNone(refusal)


if __name__ == "__main__":
    unittest.main()
