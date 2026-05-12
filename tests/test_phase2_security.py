from __future__ import annotations

import asyncio
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from deskwarden_daemon import DaemonState, create_handler
from deskwarden_protocol import build_auth_headers, sign_request
from deskwarden_rpc import DeskWardenRpcClient, RpcError


class ProtocolTests(unittest.TestCase):
    def test_signature_is_deterministic_for_same_request(self) -> None:
        body = b'{"action":"status"}'
        signature = sign_request("secret", "POST", "/status", "1710000000", "nonce-1", body)

        self.assertEqual(signature, sign_request("secret", "POST", "/status", "1710000000", "nonce-1", body))
        self.assertNotEqual(signature, sign_request("secret", "POST", "/status", "1710000000", "nonce-2", body))


class DaemonSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        state = DaemonState(
            state_path=Path(self.temp_dir.name) / "daemon_state.json",
            max_auth_failures=2,
        )
        self.state = state
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp_dir.cleanup()

    def test_pair_status_rotate_and_replay_rejection(self) -> None:
        client = DeskWardenRpcClient(self.base_url, timeout_seconds=2)

        health = asyncio.run(client.health())
        self.assertFalse(health["paired"])
        self.assertEqual(health["state"], "LOCKED")

        with self.assertRaises(RpcError) as unpaired:
            asyncio.run(client.status())
        self.assertEqual(unpaired.exception.code, "UNPAIRED")

        pairing = asyncio.run(client.pair(self.state.pairing_token, "test-client"))
        self.assertTrue(pairing.paired)
        self.assertTrue(pairing.shared_secret)

        signed_client = DeskWardenRpcClient(self.base_url, pairing.shared_secret, timeout_seconds=2)
        status = asyncio.run(signed_client.status())
        self.assertTrue(status["paired"])
        self.assertEqual(status["state"], "LOCKED")

        replay_headers = build_auth_headers(pairing.shared_secret, "GET", "/status", b"")
        ok, status_code, _ = self.state.verify_request("GET", "/status", replay_headers, b"")
        self.assertTrue(ok)
        ok, status_code, payload = self.state.verify_request("GET", "/status", replay_headers, b"")
        self.assertFalse(ok)
        self.assertEqual(status_code, 401)
        self.assertEqual(payload["error_code"], "REPLAYED_NONCE")

        rotated = asyncio.run(signed_client.rotate_secret())
        self.assertNotEqual(rotated.shared_secret, pairing.shared_secret)

    def test_bad_signatures_lock_daemon(self) -> None:
        client = DeskWardenRpcClient(self.base_url, timeout_seconds=2)
        pairing = asyncio.run(client.pair(self.state.pairing_token, "test-client"))

        bad_client = DeskWardenRpcClient(self.base_url, pairing.shared_secret + "x", timeout_seconds=2)
        for _ in range(2):
            with self.assertRaises(RpcError):
                asyncio.run(bad_client.status())

        health = asyncio.run(client.health())
        self.assertTrue(health["auth_locked"])


if __name__ == "__main__":
    unittest.main()
