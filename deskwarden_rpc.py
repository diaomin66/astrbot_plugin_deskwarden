from __future__ import annotations

import asyncio
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

try:
    from .deskwarden_protocol import build_auth_headers, dumps_json_bytes
    from .deskwarden_types import ActionProposal, ActionResult, ApprovalRequest
except ImportError:  # pragma: no cover - allows running this module outside a package.
    from deskwarden_protocol import build_auth_headers, dumps_json_bytes
    from deskwarden_types import ActionProposal, ActionResult, ApprovalRequest


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class RpcError(RuntimeError):
    def __init__(self, code: str, message: str, status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class PairingResult:
    shared_secret: str
    state: str
    paired: bool


@dataclass(frozen=True)
class ActionResponse:
    proposal: ActionProposal
    result: ActionResult
    redaction_applied: bool = False


class DeskWardenRpcClient:
    def __init__(self, base_url: str, shared_secret: str | None = None, timeout_seconds: float = 3.0):
        self.base_url = _normalize_loopback_url(base_url)
        self.shared_secret = shared_secret
        self.timeout_seconds = timeout_seconds

    async def health(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._request_json, "GET", "/health", None, False)

    async def pair(self, pairing_token: str, client_name: str) -> PairingResult:
        payload = {"pairing_token": pairing_token, "client_name": client_name}
        response = await asyncio.to_thread(self._request_json, "POST", "/pair", payload, False)
        shared_secret = str(response.get("shared_secret", ""))
        if not shared_secret:
            raise RpcError("MISSING_SHARED_SECRET", "Daemon paired but did not return a shared secret.")
        return PairingResult(
            shared_secret=shared_secret,
            state=str(response.get("state", "LOCKED")),
            paired=bool(response.get("paired", True)),
        )

    async def status(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._request_json, "GET", "/status", None, True)

    async def rotate_secret(self) -> PairingResult:
        response = await asyncio.to_thread(self._request_json, "POST", "/rotate-secret", {}, True)
        shared_secret = str(response.get("shared_secret", ""))
        if not shared_secret:
            raise RpcError("MISSING_SHARED_SECRET", "Daemon rotated the key but did not return a shared secret.")
        return PairingResult(
            shared_secret=shared_secret,
            state=str(response.get("state", "LOCKED")),
            paired=bool(response.get("paired", True)),
        )

    async def observe_screen(self, session_id: str, user_id: str) -> ActionResponse:
        return await self._action("POST", "/observe/screen", _context_payload(session_id, user_id))

    async def observe_active_window(self, session_id: str, user_id: str) -> ActionResponse:
        return await self._action("POST", "/observe/active-window", _context_payload(session_id, user_id))

    async def list_windows(self, session_id: str, user_id: str) -> ActionResponse:
        return await self._action("POST", "/observe/windows", _context_payload(session_id, user_id))

    async def summarize_state(self, session_id: str, user_id: str) -> ActionResponse:
        return await self._action("POST", "/observe/summary", _context_payload(session_id, user_id))

    async def interact(
        self,
        session_id: str,
        user_id: str,
        action_type: str,
        payload: Mapping[str, Any],
        target: str = "desktop",
        summary: str = "",
        proposal: ActionProposal | None = None,
        approval: ApprovalRequest | None = None,
    ) -> ActionResponse:
        body: dict[str, Any] = {
            **_context_payload(session_id, user_id),
            "action_type": action_type,
            "payload": dict(payload),
            "target": target,
            "summary": summary or f"Desktop interaction: {action_type}",
        }
        if proposal is not None:
            body["proposal"] = proposal.to_dict()
        if approval is not None:
            body["approval"] = approval.to_dict()
        return await self._action("POST", "/interact", body)

    async def emergency_stop(self, session_id: str, user_id: str) -> ActionResponse:
        return await self._action("POST", "/emergency-stop", _context_payload(session_id, user_id))

    async def file_read(self, session_id: str, user_id: str, path: str) -> ActionResponse:
        return await self._action("POST", "/file/read", {**_context_payload(session_id, user_id), "path": path})

    async def file_diff(self, session_id: str, user_id: str, path: str, content: str) -> ActionResponse:
        return await self._action(
            "POST",
            "/file/diff",
            {**_context_payload(session_id, user_id), "path": path, "content": content},
        )

    async def file_write(
        self,
        session_id: str,
        user_id: str,
        path: str,
        content: str,
        proposal: ActionProposal,
        approval: ApprovalRequest,
    ) -> ActionResponse:
        return await self._action(
            "POST",
            "/file/write",
            {
                **_context_payload(session_id, user_id),
                "path": path,
                "content": content,
                "proposal": proposal.to_dict(),
                "approval": approval.to_dict(),
            },
        )

    async def shell_plan(
        self,
        session_id: str,
        user_id: str,
        command: str,
        cwd: str = "",
        timeout_seconds: int = 5,
    ) -> ActionResponse:
        return await self._action(
            "POST",
            "/shell/plan",
            {
                **_context_payload(session_id, user_id),
                "command": command,
                "cwd": cwd,
                "timeout_seconds": timeout_seconds,
            },
        )

    async def shell_run(
        self,
        session_id: str,
        user_id: str,
        command: str,
        cwd: str,
        timeout_seconds: int,
        proposal: ActionProposal,
        approval: ApprovalRequest,
    ) -> ActionResponse:
        return await self._action(
            "POST",
            "/shell/run",
            {
                **_context_payload(session_id, user_id),
                "command": command,
                "cwd": cwd,
                "timeout_seconds": timeout_seconds,
                "proposal": proposal.to_dict(),
                "approval": approval.to_dict(),
            },
        )

    async def browser_action(
        self,
        session_id: str,
        user_id: str,
        action_type: str,
        payload: Mapping[str, Any] | None = None,
        target: str = "isolated_browser",
        summary: str = "",
        proposal: ActionProposal | None = None,
        approval: ApprovalRequest | None = None,
    ) -> ActionResponse:
        body: dict[str, Any] = {
            **_context_payload(session_id, user_id),
            "action_type": action_type,
            "payload": dict(payload or {}),
            "target": target,
            "summary": summary or f"Browser action: {action_type}",
        }
        if proposal is not None:
            body["proposal"] = proposal.to_dict()
        if approval is not None:
            body["approval"] = approval.to_dict()
        return await self._action("POST", "/browser/action", body)

    async def audit_latest(self, limit: int = 10) -> dict[str, Any]:
        return await asyncio.to_thread(self._request_json, "POST", "/audit/latest", {"limit": limit}, True)

    async def audit_purge(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._request_json, "POST", "/audit/purge", {}, True)

    async def _action(self, method: str, path: str, payload: Mapping[str, Any]) -> ActionResponse:
        response = await asyncio.to_thread(self._request_json, method, path, payload, True)
        return _decode_action_response(response)

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None,
        signed: bool,
    ) -> dict[str, Any]:
        body = b"" if method == "GET" and payload is None else dumps_json_bytes(payload)
        headers = {
            "Accept": "application/json",
            "User-Agent": "astrbot-plugin-deskwarden/0.6",
        }

        if body:
            headers["Content-Type"] = "application/json"

        if signed:
            if not self.shared_secret:
                raise RpcError("UNPAIRED", "DeskWarden has no shared secret. Run /desk pair <token> first.")
            headers.update(build_auth_headers(self.shared_secret, method, path, body))

        request = urllib.request.Request(
            urllib.parse.urljoin(self.base_url, path),
            data=None if method == "GET" else body,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                response_body = response.read()
        except urllib.error.HTTPError as exc:
            raise _rpc_error_from_http(exc) from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            raise RpcError("DAEMON_UNREACHABLE", f"Cannot reach DeskWarden daemon: {exc}") from exc

        return _decode_response(response_body)


def _normalize_loopback_url(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url.strip())
    if parsed.scheme != "http":
        raise ValueError("DeskWarden daemon_url must use http:// on loopback.")
    if parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError("DeskWarden daemon_url must point to 127.0.0.1, localhost, or ::1.")
    if not parsed.netloc:
        raise ValueError("DeskWarden daemon_url must include a host and port.")
    return base_url.rstrip("/") + "/"


def _decode_response(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise RpcError("BAD_DAEMON_RESPONSE", "Daemon returned invalid JSON.") from exc

    if not isinstance(payload, dict):
        raise RpcError("BAD_DAEMON_RESPONSE", "Daemon returned a non-object JSON response.")
    if payload.get("ok") is False:
        raise RpcError(str(payload.get("error_code", "DAEMON_ERROR")), str(payload.get("error_message", "")))
    return payload


def _decode_action_response(response: Mapping[str, Any]) -> ActionResponse:
    proposal_payload = response.get("proposal")
    result_payload = response.get("action_result")
    if not isinstance(proposal_payload, Mapping) or not isinstance(result_payload, Mapping):
        raise RpcError("BAD_ACTION_RESPONSE", "Daemon action response is missing proposal or action_result.")
    return ActionResponse(
        proposal=ActionProposal.from_dict(proposal_payload),
        result=ActionResult.from_dict(result_payload),
        redaction_applied=bool(response.get("redaction_applied", False)),
    )


def _rpc_error_from_http(exc: urllib.error.HTTPError) -> RpcError:
    try:
        payload = _decode_response(exc.read())
    except RpcError as decode_error:
        if decode_error.code != "BAD_DAEMON_RESPONSE":
            return RpcError(decode_error.code, str(decode_error), exc.code)
        return RpcError("HTTP_ERROR", f"Daemon returned HTTP {exc.code}.", exc.code)

    return RpcError(
        str(payload.get("error_code", "HTTP_ERROR")),
        str(payload.get("error_message", f"Daemon returned HTTP {exc.code}.")),
        exc.code,
    )


def _context_payload(session_id: str, user_id: str) -> dict[str, str]:
    return {"session_id": session_id, "user_id": user_id}
