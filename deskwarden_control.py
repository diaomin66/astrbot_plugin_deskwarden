from __future__ import annotations

import ctypes
import sys
import time
from dataclasses import dataclass
from typing import Any, Mapping


class ControlError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ControlResult:
    output: dict[str, Any]


def create_controller() -> "BaseController":
    if sys.platform == "win32":
        return WindowsController()
    return UnsupportedController("CONTROL_UNSUPPORTED", "Desktop control is currently implemented for Windows only.")


class BaseController:
    def execute(self, action_type: str, payload: Mapping[str, Any]) -> ControlResult:
        raise NotImplementedError


class UnsupportedController(BaseController):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message

    def execute(self, action_type: str, payload: Mapping[str, Any]) -> ControlResult:
        raise ControlError(self.code, self.message)


class WindowsController(BaseController):
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    MOUSEEVENTF_RIGHTDOWN = 0x0008
    MOUSEEVENTF_RIGHTUP = 0x0010
    MOUSEEVENTF_WHEEL = 0x0800
    KEYEVENTF_KEYUP = 0x0002
    KEYEVENTF_UNICODE = 0x0004

    VK = {
        "alt": 0x12,
        "backspace": 0x08,
        "ctrl": 0x11,
        "control": 0x11,
        "delete": 0x2E,
        "down": 0x28,
        "enter": 0x0D,
        "esc": 0x1B,
        "escape": 0x1B,
        "left": 0x25,
        "right": 0x27,
        "shift": 0x10,
        "space": 0x20,
        "tab": 0x09,
        "up": 0x26,
        "win": 0x5B,
        "windows": 0x5B,
    }

    def __init__(self):
        self.user32 = ctypes.windll.user32

    def execute(self, action_type: str, payload: Mapping[str, Any]) -> ControlResult:
        action = action_type.lower().strip()
        if action == "click":
            self._click(_int(payload.get("x")), _int(payload.get("y")), "left", 1)
        elif action == "double_click":
            self._click(_int(payload.get("x")), _int(payload.get("y")), "left", 2)
        elif action == "right_click":
            self._click(_int(payload.get("x")), _int(payload.get("y")), "right", 1)
        elif action == "scroll":
            self._move(_int(payload.get("x")), _int(payload.get("y")))
            self.user32.mouse_event(self.MOUSEEVENTF_WHEEL, 0, 0, _int(payload.get("delta", 0)), 0)
        elif action == "drag":
            self._drag(
                _int(payload.get("x1")),
                _int(payload.get("y1")),
                _int(payload.get("x2")),
                _int(payload.get("y2")),
                max(0, _int(payload.get("duration_ms", 250))),
            )
        elif action == "type_text":
            self._type_text(str(payload.get("text", "")))
        elif action == "hotkey":
            keys = payload.get("keys") or []
            if isinstance(keys, str):
                keys = [part for part in keys.replace("+", " ").split() if part]
            self._hotkey([str(key) for key in keys])
        elif action == "focus_window":
            self._focus_window(str(payload.get("window_id", "")))
        else:
            raise ControlError("UNKNOWN_ACTION", f"Unsupported interaction action: {action_type}")

        return ControlResult(output={"action_type": action, "performed": True})

    def _move(self, x: int, y: int) -> None:
        if not self.user32.SetCursorPos(x, y):
            raise ControlError("CURSOR_MOVE_FAILED", "Could not move the cursor.")

    def _click(self, x: int, y: int, button: str, count: int) -> None:
        self._move(x, y)
        if button == "right":
            down = self.MOUSEEVENTF_RIGHTDOWN
            up = self.MOUSEEVENTF_RIGHTUP
        else:
            down = self.MOUSEEVENTF_LEFTDOWN
            up = self.MOUSEEVENTF_LEFTUP

        for _ in range(max(1, count)):
            self.user32.mouse_event(down, 0, 0, 0, 0)
            self.user32.mouse_event(up, 0, 0, 0, 0)
            time.sleep(0.05)

    def _drag(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int) -> None:
        self._move(x1, y1)
        self.user32.mouse_event(self.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        steps = max(1, min(60, duration_ms // 16 if duration_ms else 1))
        for step in range(1, steps + 1):
            ratio = step / steps
            self._move(int(x1 + (x2 - x1) * ratio), int(y1 + (y2 - y1) * ratio))
            time.sleep(max(0.001, duration_ms / steps / 1000) if duration_ms else 0.001)
        self.user32.mouse_event(self.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

    def _type_text(self, text: str) -> None:
        for char in text:
            self._send_unicode_char(char)

    def _send_unicode_char(self, char: str) -> None:
        code_unit = ord(char)
        for flags in (self.KEYEVENTF_UNICODE, self.KEYEVENTF_UNICODE | self.KEYEVENTF_KEYUP):
            keyboard = _KEYBDINPUT(0, code_unit, flags, 0, None)
            event = _INPUT(1, _INPUT_UNION(ki=keyboard))
            sent = self.user32.SendInput(1, ctypes.byref(event), ctypes.sizeof(event))
            if sent != 1:
                raise ControlError("TYPE_TEXT_FAILED", "Windows SendInput failed while typing text.")

    def _hotkey(self, keys: list[str]) -> None:
        vk_codes = [self._vk_for_key(key) for key in keys]
        for vk_code in vk_codes:
            self.user32.keybd_event(vk_code, 0, 0, 0)
        for vk_code in reversed(vk_codes):
            self.user32.keybd_event(vk_code, 0, self.KEYEVENTF_KEYUP, 0)

    def _vk_for_key(self, key: str) -> int:
        lowered = key.lower()
        if lowered in self.VK:
            return self.VK[lowered]
        if len(key) == 1:
            value = self.user32.VkKeyScanW(ord(key))
            if value != -1:
                return value & 0xFF
        if lowered.startswith("f") and lowered[1:].isdigit():
            number = int(lowered[1:])
            if 1 <= number <= 24:
                return 0x70 + number - 1
        raise ControlError("UNKNOWN_KEY", f"Unsupported hotkey key: {key}")

    def _focus_window(self, window_id: str) -> None:
        try:
            hwnd = int(window_id, 16) if window_id.lower().startswith("0x") else int(window_id)
        except ValueError as exc:
            raise ControlError("BAD_WINDOW_ID", "Window id must be an integer or hex HWND.") from exc

        SW_SHOW = 5
        self.user32.ShowWindow(hwnd, SW_SHOW)
        if not self.user32.SetForegroundWindow(hwnd):
            raise ControlError("FOCUS_WINDOW_FAILED", "Could not focus the requested window.")


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [("ki", _KEYBDINPUT)]


class _INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("union", _INPUT_UNION)]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
