from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


SENSITIVE_AUDIT_EXACT_KEYS = {
    "authorization",
    "content",
    "cookie",
    "diff",
    "text",
}
SENSITIVE_AUDIT_KEY_FRAGMENTS = {
    "credential",
    "pairing_token",
    "password",
    "secret",
    "shared_secret",
    "signature",
    "token",
}
REDACTED_VALUE = "[REDACTED]"


class SessionState(str, Enum):
    IDLE = "IDLE"
    OBSERVING = "OBSERVING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    PAUSED = "PAUSED"
    LOCKED = "LOCKED"


class CapabilityTier(str, Enum):
    OBSERVE = "OBSERVE"
    INTERACT = "INTERACT"
    MUTATE = "MUTATE"
    DANGEROUS = "DANGEROUS"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


def now_ts() -> int:
    return int(time.time())


def new_action_id() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class ActionProposal:
    id: str
    session_id: str
    action_type: str
    tier: CapabilityTier
    summary: str
    target: str
    payload: dict[str, Any] = field(default_factory=dict)
    risk_reason: str = ""
    rollback_hint: str = ""
    expires_at: int = 0

    @classmethod
    def create(
        cls,
        session_id: str,
        action_type: str,
        tier: CapabilityTier,
        summary: str,
        target: str = "",
        payload: Mapping[str, Any] | None = None,
        risk_reason: str = "",
        rollback_hint: str = "",
        ttl_seconds: int = 120,
    ) -> "ActionProposal":
        return cls(
            id=new_action_id(),
            session_id=session_id,
            action_type=action_type,
            tier=tier,
            summary=summary,
            target=target,
            payload=dict(payload or {}),
            risk_reason=risk_reason,
            rollback_hint=rollback_hint,
            expires_at=now_ts() + ttl_seconds,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ActionProposal":
        return cls(
            id=str(value.get("id", "")),
            session_id=str(value.get("session_id", "")),
            action_type=str(value.get("action_type", "")),
            tier=_capability_tier(value.get("tier", CapabilityTier.OBSERVE.value)),
            summary=str(value.get("summary", "")),
            target=str(value.get("target", "")),
            payload=dict(value.get("payload") or {}),
            risk_reason=str(value.get("risk_reason", "")),
            rollback_hint=str(value.get("rollback_hint", "")),
            expires_at=int(value.get("expires_at") or 0),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "action_type": self.action_type,
            "tier": self.tier.value,
            "summary": self.summary,
            "target": self.target,
            "payload": self.payload,
            "risk_reason": self.risk_reason,
            "rollback_hint": self.rollback_hint,
            "expires_at": self.expires_at,
        }

    def is_expired(self, at: int | None = None) -> bool:
        return bool(self.expires_at) and (at if at is not None else now_ts()) > self.expires_at


@dataclass(frozen=True)
class ApprovalRequest:
    proposal_id: str
    user_id: str
    created_at: int
    expires_at: int
    status: ApprovalStatus

    @classmethod
    def create(cls, proposal: ActionProposal, user_id: str) -> "ApprovalRequest":
        return cls(
            proposal_id=proposal.id,
            user_id=user_id,
            created_at=now_ts(),
            expires_at=proposal.expires_at,
            status=ApprovalStatus.PENDING,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ApprovalRequest":
        return cls(
            proposal_id=str(value.get("proposal_id", "")),
            user_id=str(value.get("user_id", "")),
            created_at=int(value.get("created_at") or 0),
            expires_at=int(value.get("expires_at") or 0),
            status=_approval_status(value.get("status", ApprovalStatus.PENDING.value)),
        )

    def with_status(self, status: ApprovalStatus) -> "ApprovalRequest":
        return ApprovalRequest(
            proposal_id=self.proposal_id,
            user_id=self.user_id,
            created_at=self.created_at,
            expires_at=self.expires_at,
            status=status,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "user_id": self.user_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
        }


@dataclass(frozen=True)
class ActionResult:
    proposal_id: str
    ok: bool
    output: Any = None
    screenshot_ref: str | None = None
    error_code: str | None = None
    error_message: str | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ActionResult":
        return cls(
            proposal_id=str(value.get("proposal_id", "")),
            ok=bool(value.get("ok", False)),
            output=value.get("output"),
            screenshot_ref=_optional_str(value.get("screenshot_ref")),
            error_code=_optional_str(value.get("error_code")),
            error_message=_optional_str(value.get("error_message")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "ok": self.ok,
            "output": self.output,
            "screenshot_ref": self.screenshot_ref,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


@dataclass(frozen=True)
class AuditRecord:
    timestamp: int
    session_id: str
    user_id: str
    proposal: dict[str, Any]
    approval: dict[str, Any] | None
    result: dict[str, Any] | None
    redaction_applied: bool

    @classmethod
    def create(
        cls,
        session_id: str,
        user_id: str,
        proposal: ActionProposal,
        approval: ApprovalRequest | Mapping[str, Any] | None,
        result: ActionResult | Mapping[str, Any] | None,
        redaction_applied: bool = False,
    ) -> "AuditRecord":
        redacted = redaction_applied
        if isinstance(approval, ApprovalRequest):
            approval_payload: dict[str, Any] | None = approval.to_dict()
        elif approval is None:
            approval_payload = None
        else:
            approval_payload = dict(approval)

        if isinstance(result, ActionResult):
            result_payload: dict[str, Any] | None = result.to_dict()
        elif result is None:
            result_payload = None
        else:
            result_payload = dict(result)

        proposal_payload, proposal_redacted = _sanitize_audit_value(proposal.to_dict())
        approval_payload, approval_redacted = _sanitize_audit_value(approval_payload)
        result_payload, result_redacted = _sanitize_audit_value(result_payload)
        redacted = redacted or proposal_redacted or approval_redacted or result_redacted

        return cls(
            timestamp=now_ts(),
            session_id=session_id,
            user_id=user_id,
            proposal=proposal_payload if isinstance(proposal_payload, dict) else {},
            approval=approval_payload,
            result=result_payload,
            redaction_applied=redacted,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuditRecord":
        return cls(
            timestamp=int(value.get("timestamp") or 0),
            session_id=str(value.get("session_id", "")),
            user_id=str(value.get("user_id", "")),
            proposal=dict(value.get("proposal") or {}),
            approval=dict(value["approval"]) if isinstance(value.get("approval"), Mapping) else None,
            result=dict(value["result"]) if isinstance(value.get("result"), Mapping) else None,
            redaction_applied=bool(value.get("redaction_applied", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "proposal": self.proposal,
            "approval": self.approval,
            "result": self.result,
            "redaction_applied": self.redaction_applied,
        }

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _sanitize_audit_value(value: Any) -> tuple[Any, bool]:
    if isinstance(value, Mapping):
        redacted = False
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_audit_key(key_text):
                sanitized[key_text] = REDACTED_VALUE
                redacted = True
                continue
            sanitized_item, item_redacted = _sanitize_audit_value(item)
            sanitized[key_text] = sanitized_item
            redacted = redacted or item_redacted
        return sanitized, redacted

    if isinstance(value, list):
        redacted = False
        sanitized_list: list[Any] = []
        for item in value:
            sanitized_item, item_redacted = _sanitize_audit_value(item)
            sanitized_list.append(sanitized_item)
            redacted = redacted or item_redacted
        return sanitized_list, redacted

    return value, False


def _is_sensitive_audit_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in SENSITIVE_AUDIT_EXACT_KEYS or any(
        fragment in lowered for fragment in SENSITIVE_AUDIT_KEY_FRAGMENTS
    )


def _capability_tier(value: Any) -> CapabilityTier:
    try:
        return CapabilityTier(str(value))
    except ValueError:
        return CapabilityTier.DANGEROUS


def _approval_status(value: Any) -> ApprovalStatus:
    try:
        return ApprovalStatus(str(value))
    except ValueError:
        return ApprovalStatus.DENIED
