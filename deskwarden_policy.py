from __future__ import annotations

from typing import Any, Mapping

try:
    from .deskwarden_types import CapabilityTier
except ImportError:  # pragma: no cover
    from deskwarden_types import CapabilityTier


RISKY_INTERACTION_KEYWORDS = {
    "buy",
    "checkout",
    "confirm",
    "delete",
    "download",
    "login",
    "log in",
    "pay",
    "purchase",
    "remove",
    "send",
    "submit",
    "transfer",
    "upload",
    "付款",
    "删除",
    "提交",
    "确认",
    "登录",
    "支付",
    "转账",
}

BROWSER_SENSITIVE_KEYWORDS = RISKY_INTERACTION_KEYWORDS | {
    "account",
    "auth",
    "credential",
    "identity",
    "password",
    "signin",
    "sign in",
    "signup",
    "sign up",
    "ssn",
    "verify",
    "验证码",
    "身份",
    "银行卡",
}


def classify_interaction(
    action_type: str,
    payload: Mapping[str, Any] | None = None,
    target: str = "",
    summary: str = "",
) -> tuple[CapabilityTier, str, bool]:
    action = action_type.lower().strip()
    payload = payload or {}
    haystack = " ".join(
        [
            action,
            target,
            summary,
            str(payload.get("text", "")),
            str(payload.get("keys", "")),
            str(payload.get("label", "")),
        ]
    ).lower()

    if action in {"type_text", "hotkey"} and any(keyword in haystack for keyword in RISKY_INTERACTION_KEYWORDS):
        return CapabilityTier.MUTATE, "Text or hotkey appears to submit, authenticate, pay, delete, or transfer.", True

    if any(keyword in haystack for keyword in RISKY_INTERACTION_KEYWORDS):
        return CapabilityTier.MUTATE, "Target or summary contains a risky action keyword.", True

    if action in {"click", "double_click", "right_click", "scroll", "drag", "type_text", "hotkey", "focus_window"}:
        return CapabilityTier.INTERACT, "Low-risk desktop interaction in an unlocked owner session.", False

    return CapabilityTier.DANGEROUS, "Unknown interaction action type.", True


def classify_file_read() -> tuple[CapabilityTier, str, bool]:
    return CapabilityTier.OBSERVE, "Read-only file access inside a configured workspace.", False


def classify_file_write() -> tuple[CapabilityTier, str, bool]:
    return CapabilityTier.MUTATE, "File writes require diff review, backup creation, and owner approval.", True


def classify_shell_command() -> tuple[CapabilityTier, str, bool]:
    return CapabilityTier.DANGEROUS, "Restricted shell commands always require owner approval.", True


def classify_browser_action(
    action_type: str,
    payload: Mapping[str, Any] | None = None,
    target: str = "",
    summary: str = "",
) -> tuple[CapabilityTier, str, bool]:
    action = action_type.lower().strip()
    payload = payload or {}
    haystack = " ".join(
        [
            action,
            target,
            summary,
            str(payload.get("url", "")),
            str(payload.get("selector", "")),
            str(payload.get("text", "")),
        ]
    ).lower()

    if action in {"open_url", "title", "screenshot"}:
        return CapabilityTier.OBSERVE, "Isolated browser observation does not touch the user's main browser profile.", False

    if action == "download":
        return CapabilityTier.MUTATE, "Browser downloads are saved only into the isolated downloads directory.", True

    if action in {"click", "type_text"}:
        if any(keyword in haystack for keyword in BROWSER_SENSITIVE_KEYWORDS):
            return CapabilityTier.DANGEROUS, "Browser action appears to involve login, payment, identity, or submission.", True
        return CapabilityTier.INTERACT, "Low-risk interaction inside the isolated browser profile.", False

    return CapabilityTier.DANGEROUS, "Unknown browser action type.", True


def requires_approval(tier: CapabilityTier) -> bool:
    return tier in {CapabilityTier.MUTATE, CapabilityTier.DANGEROUS}
