from __future__ import annotations

import ipaddress
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_URL_LENGTH = 2048
MAX_SELECTOR_LENGTH = 512
MAX_TYPE_TEXT_LENGTH = 4096
BROWSER_TIMEOUT_MS = 15_000


class BrowserSandboxError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class BrowserResult:
    output: dict[str, Any]
    screenshot_ref: str | None = None


class BrowserSandbox:
    def __init__(
        self,
        enabled: bool,
        profile_dir: Path,
        screenshot_dir: Path,
        downloads_dir: Path,
        allow_private_hosts: bool = False,
    ):
        self.enabled = enabled
        self.profile_dir = profile_dir
        self.screenshot_dir = screenshot_dir
        self.downloads_dir = downloads_dir
        self.allow_private_hosts = allow_private_hosts
        self._lock = threading.RLock()
        self._playwright: Any | None = None
        self._context: Any | None = None
        self._page: Any | None = None

    def open_url(self, url: str) -> BrowserResult:
        url = _validate_url(url, self.allow_private_hosts)
        with self._lock:
            page = self._ensure_page()
            page.goto(url, wait_until="domcontentloaded", timeout=BROWSER_TIMEOUT_MS)
            return BrowserResult(self._page_state(page, {"action": "open_url"}))

    def title(self) -> BrowserResult:
        with self._lock:
            page = self._ensure_page()
            return BrowserResult(self._page_state(page, {"action": "title"}))

    def screenshot(self) -> BrowserResult:
        with self._lock:
            page = self._ensure_page()
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
            path = self.screenshot_dir / f"browser-{int(time.time() * 1000)}.png"
            page.screenshot(path=str(path), full_page=True, timeout=BROWSER_TIMEOUT_MS)
            return BrowserResult(self._page_state(page, {"action": "screenshot"}), screenshot_ref=str(path))

    def click(self, selector: str) -> BrowserResult:
        selector = _validate_selector(selector)
        with self._lock:
            page = self._ensure_page()
            page.click(selector, timeout=BROWSER_TIMEOUT_MS)
            return BrowserResult(self._page_state(page, {"action": "click", "selector": selector}))

    def type_text(self, selector: str, text: str) -> BrowserResult:
        selector = _validate_selector(selector)
        if len(text) > MAX_TYPE_TEXT_LENGTH:
            raise BrowserSandboxError("BROWSER_TEXT_TOO_LONG", "Browser text input is too long.")
        with self._lock:
            page = self._ensure_page()
            page.fill(selector, text, timeout=BROWSER_TIMEOUT_MS)
            return BrowserResult(
                self._page_state(page, {"action": "type_text", "selector": selector, "text_length": len(text)})
            )

    def download(self, selector: str) -> BrowserResult:
        selector = _validate_selector(selector)
        with self._lock:
            page = self._ensure_page()
            self.downloads_dir.mkdir(parents=True, exist_ok=True)
            with page.expect_download(timeout=BROWSER_TIMEOUT_MS) as download_info:
                page.click(selector, timeout=BROWSER_TIMEOUT_MS)
            download = download_info.value
            suggested = Path(download.suggested_filename).name or f"download-{int(time.time())}"
            target = self.downloads_dir / suggested
            download.save_as(str(target))
            return BrowserResult(
                self._page_state(page, {"action": "download", "selector": selector, "download_ref": str(target)})
            )

    def close(self) -> None:
        with self._lock:
            if self._context is not None:
                self._context.close()
            if self._playwright is not None:
                self._playwright.stop()
            self._context = None
            self._page = None
            self._playwright = None

    def _ensure_page(self) -> Any:
        if not self.enabled:
            raise BrowserSandboxError("BROWSER_DISABLED", "Isolated browser control is disabled by daemon configuration.")
        if self._context is None:
            try:
                from playwright.sync_api import sync_playwright
            except ImportError as exc:
                raise BrowserSandboxError(
                    "BROWSER_DEPENDENCY_MISSING",
                    "Playwright is not installed. Install requirements and run `playwright install chromium`.",
                ) from exc

            self.profile_dir.mkdir(parents=True, exist_ok=True)
            self.downloads_dir.mkdir(parents=True, exist_ok=True)
            self._playwright = sync_playwright().start()
            self._context = self._playwright.chromium.launch_persistent_context(
                user_data_dir=str(self.profile_dir),
                accept_downloads=True,
                headless=False,
            )

        if self._page is None or self._page.is_closed():
            pages = [page for page in self._context.pages if not page.is_closed()]
            self._page = pages[0] if pages else self._context.new_page()
        return self._page

    @staticmethod
    def _page_state(page: Any, extra: dict[str, Any]) -> dict[str, Any]:
        output = dict(extra)
        output["title"] = page.title()
        output["url"] = page.url
        return output


def _validate_url(url: str, allow_private_hosts: bool) -> str:
    url = url.strip()
    if not url:
        raise BrowserSandboxError("BROWSER_BAD_URL", "Browser URL is empty.")
    if len(url) > MAX_URL_LENGTH:
        raise BrowserSandboxError("BROWSER_URL_TOO_LONG", "Browser URL is too long.")

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise BrowserSandboxError("BROWSER_BAD_SCHEME", "Browser URL must use http or https.")
    if not parsed.hostname:
        raise BrowserSandboxError("BROWSER_BAD_URL", "Browser URL must include a host.")
    if not allow_private_hosts and _is_private_host(parsed.hostname):
        raise BrowserSandboxError("BROWSER_PRIVATE_HOST", "Private, loopback, and local browser hosts are disabled.")
    return url


def _validate_selector(selector: str) -> str:
    selector = selector.strip()
    if not selector:
        raise BrowserSandboxError("BROWSER_BAD_SELECTOR", "Browser selector is empty.")
    if len(selector) > MAX_SELECTOR_LENGTH:
        raise BrowserSandboxError("BROWSER_SELECTOR_TOO_LONG", "Browser selector is too long.")
    return selector


def _is_private_host(hostname: str) -> bool:
    lowered = hostname.lower().rstrip(".")
    if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)
