from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Mapping


HEADER_TIMESTAMP = "X-DeskWarden-Timestamp"
HEADER_NONCE = "X-DeskWarden-Nonce"
HEADER_SIGNATURE = "X-DeskWarden-Signature"


def dumps_json_bytes(payload: Mapping[str, Any] | None) -> bytes:
    if payload is None:
        payload = {}
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def load_json_object(body: bytes) -> dict[str, Any]:
    if not body:
        return {}

    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON body must be an object.")
    return value


def generate_pairing_token() -> str:
    return secrets.token_urlsafe(24)


def generate_shared_secret() -> str:
    return secrets.token_urlsafe(48)


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def signing_base(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    canonical = "\n".join(
        [
            method.upper(),
            path,
            timestamp,
            nonce,
            body_sha256(body),
        ]
    )
    return canonical.encode("utf-8")


def sign_request(secret: str, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        signing_base(method, path, timestamp, nonce, body),
        hashlib.sha256,
    ).hexdigest()


def build_auth_headers(secret: str, method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    signature = sign_request(secret, method, path, timestamp, nonce, body)
    return {
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: signature,
    }


def signatures_match(expected: str, provided: str) -> bool:
    return hmac.compare_digest(expected, provided)
