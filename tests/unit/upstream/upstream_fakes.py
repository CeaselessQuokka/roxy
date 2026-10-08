"""Test doubles for the upstream package (not a test module: pytest collects only test_*.py).

A fake egress that satisfies the DESIGN.md 11.4 contract, a recording metrics recorder, settings at catalog
defaults with overrides, a rules store over hand-made rows, a clock whose sleeps advance fake time, and a
context builder. Integration and multiprocess tests load this file by path (see `load_fakes` there).
"""

from __future__ import annotations

import asyncio
import inspect
import itertools
import random
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from types import MappingProxyType, SimpleNamespace
from typing import Any

import httpx

from roxy.config import catalog
from roxy.core.clock import FakeClock
from roxy.core.reasons import Egress
from roxy.rules.models import CredentialAllowlistRow, RoutingRuleRow, UpstreamLimitRow
from roxy.rules.store import RulesSnapshot
from roxy.upstream.service import UpstreamService


# --- exceptions with the contract's names (status.classify_exception maps them by class name) -----------------------
class CredentialLeakBlocked(Exception):
    pass


class AuthSmugglingBlocked(Exception):
    pass


class EgressDisabled(Exception):
    pass


class UpstreamTimeout(Exception):
    pass


class UpstreamConnectError(Exception):
    pass


class SteppingClock(FakeClock):
    """A FakeClock whose `sleep` advances fake time instead of waiting (the service sleeps through the clock)."""

    def __init__(self, start: float = 1_760_000_000.0) -> None:
        super().__init__(start)
        self.slept: list[float] = []

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.advance(max(0.0, seconds))
        await asyncio.sleep(0)


class FakeSettings:
    """Catalog defaults plus overrides; `set()` bumps `version` like a config reload."""

    def __init__(self, **overrides: Any) -> None:
        self._values: dict[str, Any] = dict(catalog.DEFAULTS)
        self._values.update(overrides)
        self.version = 1

    def set(self, **overrides: Any) -> None:
        self._values.update(overrides)
        self.version += 1

    def get(self, key: str) -> Any:
        return self._values[key]

    def int(self, key: str) -> int:
        return int(self._values[key])

    def float(self, key: str) -> float:
        return float(self._values[key])

    def bool(self, key: str) -> bool:
        return bool(self._values[key])

    def str(self, key: str) -> str:
        return str(self._values[key])

    def list(self, key: str) -> list[Any]:
        return list(self._values[key])


class FakeRules:
    """A rules store over hand-made rows (`snapshot` is a property, like `RulesStore`)."""

    def __init__(self) -> None:
        self.credential_rows: list[CredentialAllowlistRow] = []
        self.routing_rows: list[RoutingRuleRow] = []
        self.limits: dict[str, UpstreamLimitRow] = {}
        self._version = 0
        self._snapshot = self._build()

    def _build(self) -> RulesSnapshot:
        return RulesSnapshot(
            version=self._version,
            loaded_at=0.0,
            routing_rules=tuple(self.routing_rows),
            credential_allowlist=tuple(self.credential_rows),
            upstream_limits=MappingProxyType(dict(self.limits)),
        )

    def rebuild(self) -> None:
        self._version += 1
        self._snapshot = self._build()

    @property
    def snapshot(self) -> RulesSnapshot:
        return self._snapshot

    def allow_credential(
        self, pattern: str, *, cache_private: bool = True, identical_anonymous: bool = False, methods: str = "GET"
    ) -> None:
        self.credential_rows.append(
            CredentialAllowlistRow(
                id=len(self.credential_rows) + 1,
                pattern=pattern,
                type="glob",
                methods=methods,
                cache_private=cache_private,
                identical_anonymous=identical_anonymous,
            )
        )
        self.rebuild()

    def route(self, pattern: str, mode: str) -> None:
        self.routing_rows.append(RoutingRuleRow(id=len(self.routing_rows) + 1, pattern=pattern, type="glob", mode=mode))
        self.rebuild()

    def limit(self, bucket_key: str, per_min: float, burst: int, origin: str = "admin", updated_at: int = 0) -> None:
        self.limits[bucket_key] = UpstreamLimitRow(
            bucket_key=bucket_key, per_min=per_min, burst=burst, origin=origin, updated_at=updated_at
        )
        self.rebuild()


class MemoryLimitsWriter:
    """Records adaptive writes and applies them to a `FakeRules` (as the real audited writer would, via reload)."""

    def __init__(self, rules: FakeRules | None = None, clock: Any = None) -> None:
        self.rules = rules
        self.clock = clock
        self.writes: list[tuple[str, float, int, str]] = []

    async def write_limit(self, bucket_key: str, per_min: float, burst: int, reason: str) -> None:
        self.writes.append((bucket_key, per_min, burst, reason))
        if self.rules is not None:
            now = int(self.clock.now()) if self.clock is not None else 0
            self.rules.limit(bucket_key, per_min, burst, origin="adaptive", updated_at=now)


@dataclass
class FakeResponse:
    status: int
    headers: httpx.Headers
    body: bytes = b""
    elapsed_ms: float = 5.0
    bytes_out: int = 100
    bytes_in: int = 200
    egress: Egress = Egress.DIRECT
    session_id: str | None = None
    http_version: str = "HTTP/2"


def answer(status: int = 200, body: bytes = b'{"ok":true}', headers: dict[str, str] | None = None) -> FakeResponse:
    merged = {"content-type": "application/json"} | dict(headers or {})
    return FakeResponse(status=status, headers=httpx.Headers(merged), body=body)


class FakeCredential:
    """The credential manager side of the contract (no `probe`: the service uses its own fallback probe)."""

    def __init__(self, *, status: str = "active") -> None:
        self.status_value = status
        self.cooldown = 0.0
        self.cooldowns: list[tuple[float, str]] = []
        self.rejections: list[str] = []

    def status(self) -> Any:
        return SimpleNamespace(status=self.status_value)

    def available(self) -> bool:
        return self.status_value == "active" and self.cooldown <= 0

    def cooldown_remaining(self) -> float:
        return self.cooldown

    async def set_cooldown(self, seconds: float, source: str) -> float:
        self.cooldowns.append((seconds, source))
        return seconds

    async def mark_rejected(self, reason: str) -> None:
        self.rejections.append(reason)
        self.status_value = "rejected"


class FakeRotator:
    """Each session id is one exit; `rotate` retires it and the next request gets a new one."""

    def __init__(self, prefix: str = "s") -> None:
        self._prefix = prefix
        self._ids = itertools.count(1)
        self.current = f"{prefix}{next(self._ids)}"
        self.rotations: list[tuple[str, str]] = []

    def session_for(self, req: Any = None) -> str:
        return self.current

    def rotate(self, session_id: str | None, reason: str) -> str:
        self.rotations.append((session_id or "", reason))
        if session_id == self.current:
            self.current = f"{self._prefix}{next(self._ids)}"
        return self.current


Handler = Callable[[Egress, Any], Any]


class FakeEgress:
    """`ctx.egress`: records every call, answers with `handler(egress, out)` (a response, or an exception to raise)."""

    def __init__(self, handler: Handler | None = None, *, disabled: Iterable[Egress] = ()) -> None:
        self.handler: Handler = handler or (lambda egress, out: answer())
        self.disabled = set(disabled)
        self.calls: list[tuple[Egress, Any]] = []
        self.credential = FakeCredential()
        self.rotator = FakeRotator()
        self.headers = None

    def is_enabled(self, egress: Egress) -> tuple[bool, str]:
        if egress in self.disabled:
            return False, "disabled in test"
        return True, ""

    async def send(self, egress: Egress, out: Any) -> Any:
        self.calls.append((egress, out))
        result = self.handler(egress, out)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, BaseException):
            raise result
        if isinstance(result, FakeResponse):
            result.egress = egress
            result.session_id = out.session_id
        return result

    def egresses(self) -> list[Egress]:
        return [egress for egress, _ in self.calls]


class RespxEgress(FakeEgress):
    """Sends through a real `httpx.AsyncClient` (trust_env=False), so a `respx` mock plays Roblox."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.http = httpx.AsyncClient(trust_env=False)

    async def send(self, egress: Egress, out: Any) -> Any:
        self.calls.append((egress, out))
        try:
            response = await self.http.request(out.method, out.url, headers=out.headers, content=out.content)
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout(str(exc)) from exc
        return FakeResponse(
            status=response.status_code,
            headers=response.headers,
            body=response.content,
            egress=egress,
            session_id=out.session_id,
        )


class FakeRecorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, str, dict[str, Any]]] = []
        self.rows_429: list[dict[str, Any]] = []
        self.internal: list[dict[str, Any]] = []

    def record_event(self, event_type: str, severity: str, reason: str, detail: dict[str, Any]) -> None:
        self.events.append((event_type, severity, reason, detail))

    def record_upstream_429(self, **row: Any) -> None:
        self.rows_429.append(row)

    def record_internal_call(self, purpose: str, **row: Any) -> None:
        self.internal.append({"purpose": purpose, **row})


@dataclass
class Req:
    """A ProxyRequest stand-in with the fields upstream reads."""

    host: str = "games.roblox.com"
    path: str = "/v1/games"
    method: str = "GET"
    query: list[tuple[str, str]] = field(default_factory=lambda: [("universeIds", "1")])
    body: bytes = b""
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    template: str = ""
    deadline_at: float = 0.0
    request_id: str = "req-test"


def make_ctx(
    dbs: Any,
    clock: Any,
    egress: Any = None,
    *,
    settings: FakeSettings | None = None,
    rules: FakeRules | None = None,
    recorder: FakeRecorder | None = None,
    worker_id: str = "w1",
) -> SimpleNamespace:
    return SimpleNamespace(
        clock=clock,
        dbs=dbs,
        settings=settings or FakeSettings(),
        rules=rules or FakeRules(),
        egress=egress if egress is not None else FakeEgress(),
        recorder=recorder or FakeRecorder(),
        worker_id=worker_id,
        tasks=None,
    )


def make_service(ctx: SimpleNamespace, *, seed: int = 7, writer: Any = None) -> UpstreamService:
    return UpstreamService(
        ctx,
        rng=random.Random(seed),
        adaptive_writer=writer or MemoryLimitsWriter(ctx.rules, ctx.clock),
        deadline_clock=ctx.clock.monotonic,  # the fake clock steps through sleeps; deadlines follow it
    )


def request(service: UpstreamService, **fields: Any) -> Req:
    """A request whose deadline is 60 s from now on the service's clock."""
    req = Req(**fields)
    if not req.deadline_at:
        req.deadline_at = service.clock.monotonic() + 60
    return req


def read_rows(db: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    return db.read_sync(lambda conn: [tuple(row) for row in conn.execute(sql, params).fetchall()])
