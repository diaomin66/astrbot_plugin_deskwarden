from __future__ import annotations

import csv
import ctypes
import os
import platform
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SENSITIVE_TITLE_KEYWORDS = {
    "1password",
    "authenticator",
    "bank",
    "bitwarden",
    "credential",
    "keepass",
    "lastpass",
    "metamask",
    "otp",
    "password",
    "paypal",
    "private key",
    "secret",
    "ssh key",
    "token",
    "wallet",
    "\u51ed\u636e",
    "\u5bc6\u7801",
    "\u94b1\u5305",
    "\u94f6\u884c",
    "\u652f\u4ed8",
}

REDACTED_TITLE = "[SENSITIVE WINDOW REDACTED]"


class ObserveError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ObserveBlocked(ObserveError):
    pass


@dataclass(frozen=True)
class WindowInfo:
    window_id: str
    title: str
    process_id: int
    process_name: str
    is_active: bool
    is_visible: bool
    is_sensitive: bool

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "title": REDACTED_TITLE if self.is_sensitive else self.title,
            "process_id": self.process_id,
            "process_name": self.process_name,
            "is_active": self.is_active,
            "is_visible": self.is_visible,
            "is_sensitive": self.is_sensitive,
        }


@dataclass(frozen=True)
class CaptureResult:
    screenshot_ref: str | None
    output: dict[str, Any]
    redaction_applied: bool = False


def is_sensitive_title(title: str, keywords: Iterable[str] | None = None) -> bool:
    normalized = title.lower()
    return any(keyword.lower() in normalized for keyword in (keywords or SENSITIVE_TITLE_KEYWORDS))


def create_observer(screenshot_dir: Path) -> "BaseObserver":
    if sys.platform == "win32":
        return WindowsObserver(screenshot_dir)
    return UnsupportedObserver("OBSERVE_UNSUPPORTED", "Desktop observation is currently implemented for Windows only.")


class BaseObserver:
    def list_windows(self) -> list[WindowInfo]:
        raise NotImplementedError

    def active_window(self) -> WindowInfo | None:
        windows = self.list_windows()
        return next((window for window in windows if window.is_active), None)

    def capture_screen(self) -> CaptureResult:
        raise NotImplementedError

    def capture_active_window(self) -> CaptureResult:
        raise NotImplementedError

    def process_summary(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def summarize_state(self) -> dict[str, Any]:
        windows = self.list_windows()
        active = next((window for window in windows if window.is_active), None)
        return {
            "active_window": active.to_public_dict() if active else None,
            "window_count": len(windows),
            "sensitive_window_visible": any(window.is_sensitive for window in windows),
            "windows": [window.to_public_dict() for window in windows[:20]],
            "processes": self.process_summary()[:50],
        }


class UnsupportedObserver(BaseObserver):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message

    def _raise(self) -> None:
        raise ObserveError(self.code, self.message)

    def list_windows(self) -> list[WindowInfo]:
        self._raise()
        return []

    def capture_screen(self) -> CaptureResult:
        self._raise()
        return CaptureResult(None, {})

    def capture_active_window(self) -> CaptureResult:
        self._raise()
        return CaptureResult(None, {})

    def process_summary(self) -> list[dict[str, Any]]:
        self._raise()
        return []


class WindowsObserver(BaseObserver):
    def __init__(self, screenshot_dir: Path):
        self.screenshot_dir = screenshot_dir
        self.user32 = ctypes.windll.user32
        self.gdi32 = ctypes.windll.gdi32
        self.kernel32 = ctypes.windll.kernel32

    def list_windows(self) -> list[WindowInfo]:
        active_hwnd = int(self.user32.GetForegroundWindow())
        windows: list[WindowInfo] = []

        enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def callback(hwnd: int, _lparam: int) -> bool:
            if not self.user32.IsWindowVisible(hwnd):
                return True

            title = self._window_title(hwnd)
            if not title:
                return True

            process_id = self._window_process_id(hwnd)
            windows.append(
                WindowInfo(
                    window_id=hex(int(hwnd)),
                    title=title,
                    process_id=process_id,
                    process_name=self._process_name(process_id),
                    is_active=int(hwnd) == active_hwnd,
                    is_visible=True,
                    is_sensitive=is_sensitive_title(title),
                )
            )
            return True

        self.user32.EnumWindows(enum_proc(callback), 0)
        return windows

    def capture_screen(self) -> CaptureResult:
        windows = self.list_windows()
        sensitive = [window for window in windows if window.is_sensitive]
        if sensitive:
            raise ObserveBlocked(
                "SENSITIVE_WINDOW_VISIBLE",
                "A sensitive window is visible, so a full-screen screenshot was not returned.",
            )

        left = self.user32.GetSystemMetrics(76)
        top = self.user32.GetSystemMetrics(77)
        width = self.user32.GetSystemMetrics(78)
        height = self.user32.GetSystemMetrics(79)
        screenshot_ref = self._capture_region(left, top, width, height, "screen")
        return CaptureResult(
            screenshot_ref=screenshot_ref,
            output={"scope": "screen", "width": width, "height": height},
            redaction_applied=False,
        )

    def capture_active_window(self) -> CaptureResult:
        active = self.active_window()
        if active is None:
            raise ObserveError("NO_ACTIVE_WINDOW", "No active window could be detected.")
        if active.is_sensitive:
            raise ObserveBlocked(
                "SENSITIVE_ACTIVE_WINDOW",
                "The active window title is sensitive, so its screenshot was not returned.",
            )

        hwnd = int(active.window_id, 16)
        rect = _RECT()
        if not self.user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            raise ObserveError("WINDOW_RECT_FAILED", "Could not read the active window bounds.")

        width = max(1, rect.right - rect.left)
        height = max(1, rect.bottom - rect.top)
        screenshot_ref = self._capture_region(rect.left, rect.top, width, height, "active-window")
        return CaptureResult(
            screenshot_ref=screenshot_ref,
            output={"scope": "active_window", "window": active.to_public_dict(), "width": width, "height": height},
            redaction_applied=False,
        )

    def process_summary(self) -> list[dict[str, Any]]:
        try:
            completed = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                check=False,
                text=True,
                timeout=3,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []

        if completed.returncode != 0:
            return []

        rows = csv.reader(completed.stdout.splitlines())
        processes: list[dict[str, Any]] = []
        for row in rows:
            if len(row) < 5:
                continue
            try:
                pid = int(row[1])
            except ValueError:
                pid = 0
            processes.append(
                {
                    "image_name": row[0],
                    "pid": pid,
                    "session_name": row[2],
                    "session_number": row[3],
                    "mem_usage": row[4],
                }
            )
        return processes

    def _window_title(self, hwnd: int) -> str:
        length = self.user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return ""
        buffer = ctypes.create_unicode_buffer(length + 1)
        self.user32.GetWindowTextW(hwnd, buffer, length + 1)
        return buffer.value.strip()

    def _window_process_id(self, hwnd: int) -> int:
        pid = ctypes.c_ulong()
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return int(pid.value)

    def _process_name(self, process_id: int) -> str:
        if process_id <= 0:
            return ""

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process_id)
        if not handle:
            return ""
        try:
            size = ctypes.c_ulong(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            query = self.kernel32.QueryFullProcessImageNameW
            if query(handle, 0, buffer, ctypes.byref(size)):
                return Path(buffer.value).name
        finally:
            self.kernel32.CloseHandle(handle)
        return ""

    def _capture_region(self, left: int, top: int, width: int, height: int, prefix: str) -> str:
        if width <= 0 or height <= 0:
            raise ObserveError("BAD_CAPTURE_REGION", "Screenshot region has invalid dimensions.")

        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        path = self.screenshot_dir / f"{prefix}-{int(time.time() * 1000)}-{os.getpid()}.bmp"

        desktop = self.user32.GetDesktopWindow()
        src_dc = self.user32.GetWindowDC(desktop)
        if not src_dc:
            raise ObserveError("CAPTURE_DC_FAILED", "Could not acquire the desktop device context.")

        mem_dc = self.gdi32.CreateCompatibleDC(src_dc)
        bitmap = self.gdi32.CreateCompatibleBitmap(src_dc, width, height)
        old_bitmap = self.gdi32.SelectObject(mem_dc, bitmap)

        try:
            SRCCOPY = 0x00CC0020
            if not self.gdi32.BitBlt(mem_dc, 0, 0, width, height, src_dc, left, top, SRCCOPY):
                raise ObserveError("CAPTURE_FAILED", "Windows BitBlt screenshot capture failed.")

            buffer_size = width * height * 4
            pixel_buffer = ctypes.create_string_buffer(buffer_size)
            bitmap_info = _BITMAPINFO()
            bitmap_info.bmiHeader.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
            bitmap_info.bmiHeader.biWidth = width
            bitmap_info.bmiHeader.biHeight = -height
            bitmap_info.bmiHeader.biPlanes = 1
            bitmap_info.bmiHeader.biBitCount = 32
            bitmap_info.bmiHeader.biCompression = 0
            bitmap_info.bmiHeader.biSizeImage = buffer_size

            DIB_RGB_COLORS = 0
            if not self.gdi32.GetDIBits(
                mem_dc,
                bitmap,
                0,
                height,
                pixel_buffer,
                ctypes.byref(bitmap_info),
                DIB_RGB_COLORS,
            ):
                raise ObserveError("CAPTURE_DIB_FAILED", "Could not read screenshot bitmap pixels.")

            _write_bmp(path, width, height, pixel_buffer.raw)
        finally:
            self.gdi32.SelectObject(mem_dc, old_bitmap)
            self.gdi32.DeleteObject(bitmap)
            self.gdi32.DeleteDC(mem_dc)
            self.user32.ReleaseDC(desktop, src_dc)

        return str(path)


class _RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", ctypes.c_uint32),
        ("biWidth", ctypes.c_int32),
        ("biHeight", ctypes.c_int32),
        ("biPlanes", ctypes.c_uint16),
        ("biBitCount", ctypes.c_uint16),
        ("biCompression", ctypes.c_uint32),
        ("biSizeImage", ctypes.c_uint32),
        ("biXPelsPerMeter", ctypes.c_int32),
        ("biYPelsPerMeter", ctypes.c_int32),
        ("biClrUsed", ctypes.c_uint32),
        ("biClrImportant", ctypes.c_uint32),
    ]


class _BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", _BITMAPINFOHEADER), ("bmiColors", ctypes.c_uint32 * 3)]


def _write_bmp(path: Path, width: int, height: int, bgra_pixels: bytes) -> None:
    header_size = 14 + 40
    image_size = len(bgra_pixels)
    file_size = header_size + image_size

    file_header = b"BM" + struct.pack("<IHHI", file_size, 0, 0, header_size)
    info_header = struct.pack(
        "<IiiHHIIiiII",
        40,
        width,
        -height,
        1,
        32,
        0,
        image_size,
        0,
        0,
        0,
        0,
    )
    path.write_bytes(file_header + info_header + bgra_pixels)
