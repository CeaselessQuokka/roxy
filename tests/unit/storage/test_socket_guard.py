"""Tests for the autouse socket guard in tests/conftest.py (plan 19.12): no test may leave this machine."""

from __future__ import annotations

import socket
import threading
from typing import Any

import pytest


def test_non_loopback_connect_is_refused_before_any_packet() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # 192.0.2.0/24 is TEST-NET-1 (documentation only); the guard raises before the kernel is asked.
        with pytest.raises(RuntimeError, match="loopback"):
            sock.connect(("192.0.2.1", 443))
        with pytest.raises(RuntimeError, match="loopback"):
            sock.connect_ex(("192.0.2.1", 443))
    finally:
        sock.close()


def test_dns_lookups_of_outside_names_are_refused() -> None:
    with pytest.raises(RuntimeError, match="resolve"):
        socket.getaddrinfo("games.roblox.com", 443)
    with pytest.raises(RuntimeError, match="loopback"):
        socket.create_connection(("api.ipify.org", 443), timeout=1)


def test_loopback_connections_still_work() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted: list[bytes] = []

    def accept() -> None:
        conn, _ = server.accept()
        accepted.append(conn.recv(5))
        conn.close()

    thread = threading.Thread(target=accept)
    thread.start()
    try:
        with socket.create_connection(("localhost", port), timeout=5) as client:
            client.sendall(b"hello")
        thread.join(5)
        assert accepted == [b"hello"]
        assert socket.getaddrinfo("127.0.0.1", port)
    finally:
        server.close()


@pytest.mark.parametrize(
    ("host", "allowed"),
    [
        ("127.0.0.1", True),
        ("127.8.9.10", True),
        ("::1", True),
        ("[::1]", True),
        ("::ffff:127.0.0.1", True),
        ("localhost", True),
        ("app.localhost", True),
        (None, True),
        ("0.0.0.0", False),
        ("192.0.2.1", False),
        ("::ffff:192.0.2.1", False),
        ("games.roblox.com", False),
        ("localhost.example.com", False),
    ],
)
def test_loopback_classification(loopback_check: Any, host: object, allowed: bool) -> None:
    assert loopback_check(host) is allowed
