"""Shared helpers for the abuse tests: settings over catalog defaults, a fake proxy request, rules builders.

Kept in a plainly named module (not conftest) so test files can import the classes directly.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from roxy.config.audit import Actor
from roxy.config.catalog import CATALOG
from roxy.core.reasons import ReasonCode

ADMIN = Actor("admin", "owner")
CLIENT_IP = "203.0.113.7"  # TEST-NET-3 documentation range, never a real system


class FakeSettings:
    """The read side of `RuntimeSettings`: catalog defaults plus overrides (tests change `values` freely)."""

    def __init__(self, overrides: Mapping[str, Any] | None = None) -> None:
        self.values: dict[str, Any] = {key: spec.default for key, spec in CATALOG.items()}
        unknown = set(overrides or {}) - set(self.values)
        assert not unknown, f"unknown settings in test: {sorted(unknown)}"
        self.values.update(overrides or {})

    def snapshot(self) -> Mapping[str, Any]:
        return dict(self.values)

    def get(self, key: str) -> Any:
        return self.values[key]


@dataclass
class FakeReq:
    """The attributes of `proxy/context.py ProxyRequest` the abuse layer reads."""

    client_ip: str = CLIENT_IP
    limit_key: str = CLIENT_IP
    method: str = "GET"
    host: str = "games.roblox.com"
    path: str = "/v1/games"
    query: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=lambda: {"user-agent": "Roblox/Linux", "accept": "*/*"})
    header_names_in_order: list[str] = field(default_factory=lambda: ["user-agent", "accept"])
    user_agent: str = "Roblox/Linux"
    place_id: str | None = None
    is_browser: bool = False
    template: str = "games.roblox.com/v1/games"
    bypass: bool = False
    deadline_at: float = 0.0
    target_problem: ReasonCode | None = None
    fresh_cache_hit: bool = False
    request_id: str = "01TESTREQUEST"
    raw_path: str | None = None
    csp_nonce: str | None = None

    def with_headers(self, pairs: list[tuple[str, str]]) -> FakeReq:
        self.headers = {name.lower(): value for name, value in pairs}
        self.header_names_in_order = [name for name, _ in pairs]
        ua = self.headers.get("user-agent")
        if ua is not None:
            self.user_agent = ua
        return self


def wire(body: str) -> bytes:
    """The v1 wire form of a refusal body: a JSON string plus a newline."""
    import json

    return (json.dumps(body) + "\n").encode()


__all__ = ["ADMIN", "CLIENT_IP", "FakeReq", "FakeSettings", "wire"]
