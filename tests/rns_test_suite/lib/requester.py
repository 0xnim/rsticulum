"""Utility class for sending test traffic into the test mesh.

Wraps an RnsNode to provide convenience methods for test traffic injection.
Not a standalone RNS instance — uses the node's subprocess protocol.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .orchestrator import RnsNode


class Requester:
    """Convenience wrapper around RnsNode for injecting test traffic."""

    def __init__(self, node: "RnsNode"):
        self._node = node
        self._received: list[bytes] = []

    def announce(self, app_name: str = "test_requester") -> "Requester":
        self._node.announce(app_name)
        return self

    def identity_hash(self) -> bytes:
        return self._node.identity_hash()

    def hexhash(self) -> str:
        return self._node.hexhash()

    def send_data(self, target_hash: bytes, data: bytes) -> None:
        self._node.send_data(target_hash, data)

    def initiate_link(self, target_hash: bytes) -> dict:
        return self._node.initiate_link(target_hash)

    def send_over_link(self, data: bytes) -> None:
        self._node.send_over_link(data)

    def recv_poll(self) -> list[bytes]:
        return self._node.recv_poll()

    def recv_data(self, timeout: float = 5.0) -> Optional[bytes]:
        """Wait for a received packet. Returns None on timeout."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            msgs = self._node.recv_poll()
            if msgs:
                return msgs[0]
            time.sleep(0.1)
        return None

    def stop(self) -> None:
        pass  # Node lifecycle managed by Orchestrator

    def __repr__(self) -> str:
        return f"Requester({self._node.name})"
