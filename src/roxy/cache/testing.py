"""Test doubles for the cache contract: a fake upstream service, fake settings, static rules, fake requests.

What this is
    Small, dependency-free stand-ins for the objects `CacheService` talks to: `FakeUpstream` (DESIGN 11.3
    `fetch` and `availability`, counting every call), `FakeResult` (an `UpstreamResult` shape), `FakeSettings`
    (catalog defaults plus overrides, with a `version` that moves on every change), `StaticRules` (a fixed
    `RulesSnapshot`) and `FakeRequest` (the `ProxyRequest` fields the cache reads).

Why it exists
    The cache is tested in unit tests, integration tests with real SQLite files, and tests that run several
    worker processes; the upstream and proxy packages are written by other people at the same time. One shared
    set of fakes keeps every one of those tests honest about the same contract, and lets other packages test
    their use of the cache without a network.

How it works
    `FakeUpstream(responder)` calls `responder(req, call_number)` for each fetch (or returns a 200 with a
    numbered body by default), optionally after waiting for `gate` (an asyncio.Event) or `delay_s`, and records
    `(priority, stale_available, purpose)` per call. Like the real upstream it takes the single-flight lease
    passed as `lease=` before "calling" (`take_lease`; a lost lease raises `SingleFlightLost` and is not a call).
    `availability` answers from `cooldown_s`: None means every egress is available. Nothing here opens a socket.

What to read next
    `roxy/cache/service.py` (what these fakes stand in for) and `tests/unit/cache/`.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from roxy.config import catalog
from roxy.core.reasons import AuthClass, Egress, ReasonCode
from roxy.rules.models import CacheIgnoredParamRow, CacheRuleRow, CredentialAllowlistRow
from roxy.rules.store import RulesSnapshot

_FORWARDABLE_ACCEPT = frozenset({"application/json", "*/*"})
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass
class FakeResult:
    """The `UpstreamResult` fields of DESIGN 11.3, with defaults for a plain Roblox 200."""

    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b"{}"
    content_type: str | None = "application/json"
    egress: Egress = Egress.DIRECT
    auth_class: AuthClass = AuthClass.ANON
    upstream_status: int | None = 200
    reason: ReasonCode = ReasonCode.UPSTREAM_OK
    retry_after_s: int | None = None
    cooldown_s: int | None = None
    attempts: int = 1
    calls: int = 1
    bytes_in: int = 0
    bytes_out: int = 0
    queue_wait_ms: float = 0.0
    upstream_ms: float = 1.0
    trace: Any = None
    cacheable: bool = True
    negative_ttl_s: int | None = None
    private: bool = False
    """The upstream fetched it with the credential under a `cache_private` allowlist row (or none): plan 6.9."""


def ok(body: bytes | str = b"{}", *, status: int = 200, **fields: Any) -> FakeResult:
    """A Roblox success."""
    data = body.encode("utf-8") if isinstance(body, str) else body
    return FakeResult(status=status, body=data, upstream_status=status, **fields)


def roblox_error(status: int, body: bytes = b'{"errors":[]}', **fields: Any) -> FakeResult:
    """A definitive Roblox 4xx (reason `upstream_4xx`), with the hints `upstream/service.py` sets: never
    `cacheable` content, and `negative_ttl_s` only for 400, 404, 410 and a 403 that is not a CSRF challenge."""
    headers = {str(k).lower(): v for k, v in dict(fields.get("headers") or {}).items()}
    negative_cacheable = status in (400, 404, 410) or (status == 403 and "x-csrf-token" not in headers)
    fields.setdefault("negative_ttl_s", 60 if negative_cacheable else None)
    fields.setdefault("cacheable", False)
    return FakeResult(status=status, body=body, upstream_status=status, reason=ReasonCode.UPSTREAM_4XX, **fields)


def roblox_429(retry_after_s: int = 30, **fields: Any) -> FakeResult:
    """A Roblox 429 as the upstream layer reports it (7.13 row `upstream_cooldown`)."""
    values: dict[str, Any] = {
        "body": b"All request methods are busy right now; please try again shortly.",
        "content_type": "text/plain; charset=utf-8",
        "retry_after_s": retry_after_s,
        "cooldown_s": retry_after_s,
        "negative_ttl_s": retry_after_s,
        "cacheable": False,
    }
    values.update(fields)
    return FakeResult(status=429, upstream_status=429, reason=ReasonCode.UPSTREAM_COOLDOWN, **values)


def failure(reason: ReasonCode = ReasonCode.UPSTREAM_5XX, status: int = 503, **fields: Any) -> FakeResult:
    """A failure row of plan 7.13 (5xx after retries, timeout, busy...)."""
    defaults: dict[str, Any] = {
        "body": b"Upstream request failed; please try again later.",
        "content_type": "text/plain; charset=utf-8",
        "upstream_status": status if reason is ReasonCode.UPSTREAM_5XX else None,
        "retry_after_s": 5,
        "cacheable": False,
    }
    defaults.update(fields)
    return FakeResult(status=status, reason=reason, **defaults)


@dataclass
class FakeAvailability:
    any_egress_available: bool = True
    cooldown_remaining_s: float | None = None
    soonest_s: float | None = None
    reasons: tuple[str, ...] = ()


@dataclass
class FakeCall:
    priority: int
    stale_available: bool
    purpose: str
    url: str


class FakeUpstream:
    """`UpstreamService.fetch` and `availability`, scripted (module docstring)."""

    def __init__(
        self,
        responder: Callable[[Any, int], FakeResult] | None = None,
        *,
        delay_s: float = 0.0,
        gate: asyncio.Event | None = None,
    ) -> None:
        self.responder = responder
        self.delay_s = delay_s
        self.gate = gate
        self.calls: list[FakeCall] = []
        self.cooldown_s: float | None = None
        self.started = asyncio.Event()
        self.leases_lost = 0

    @property
    def count(self) -> int:
        return len(self.calls)

    async def take_lease(self, lease: Any) -> None:
        """What the real upstream does with `lease=` inside its reservation: take the single-flight lease or
        raise `SingleFlightLost` (nothing is "sent" then). Here the hook runs in a hot.db transaction of its own
        (`FlightLease.claim_alone`), so cross-worker tests coalesce exactly like production."""
        if lease is None:
            return
        claim = getattr(lease, "claim_alone", None)
        if claim is not None and not await claim():
            from roxy.upstream.service import SingleFlightLost  # local: keeps importing the fakes light

            self.leases_lost += 1
            raise SingleFlightLost("fake upstream: the single-flight lease belongs to another flight")

    async def fetch(
        self, req: Any, *, priority: Any, stale_available: bool, purpose: str = "caller", lease: Any = None
    ) -> FakeResult:
        await self.take_lease(lease)
        number = len(self.calls) + 1
        self.calls.append(FakeCall(int(priority), stale_available, purpose, _url_of(req)))
        self.started.set()
        if self.gate is not None:
            await self.gate.wait()
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        if self.responder is None:
            return ok(f'{{"call":{number}}}')
        return self.responder(req, number)

    def availability(self, req: Any) -> FakeAvailability:
        if self.cooldown_s is None:
            return FakeAvailability()
        return FakeAvailability(False, self.cooldown_s, self.cooldown_s, ("cooldown",))


def _url_of(req: Any) -> str:
    query = "&".join(f"{n}={v}" for n, v in getattr(req, "query", ()) or ())
    return f"{getattr(req, 'host', '')}/{str(getattr(req, 'path', '')).lstrip('/')}" + (f"?{query}" if query else "")


class FakeSettings:
    """Catalog defaults plus overrides, read like `RuntimeSettings.get`; `version` moves on every `set`."""

    def __init__(self, overrides: Mapping[str, Any] | None = None) -> None:
        self._values: dict[str, Any] = dict(catalog.DEFAULTS)
        self.version = 1
        if overrides:
            self.set(**overrides)

    def set(self, **changes: Any) -> None:
        for key, value in changes.items():
            if key not in self._values:
                raise KeyError(key)
            self._values[key] = value
        self.version += 1

    def get(self, key: str) -> Any:
        return self._values[key]


class StaticRules:
    """A `RulesStore` stand-in holding one fixed snapshot (replace `snapshot` to "reload")."""

    def __init__(self, snapshot: RulesSnapshot | None = None) -> None:
        self.snapshot = snapshot or RulesSnapshot.empty()


def rules_snapshot(
    *,
    cache_rules: Iterable[Mapping[str, Any]] = (),
    credential_allowlist: Iterable[Mapping[str, Any]] = (),
    ignored_params: Iterable[str] = (),
    version: int = 1,
) -> RulesSnapshot:
    """Build a snapshot from plain dicts (ids are assigned in order when missing)."""
    cache = [
        CacheRuleRow.model_validate({"id": index, "type": "glob", **row}) for index, row in enumerate(cache_rules, 1)
    ]
    credential = [
        CredentialAllowlistRow.model_validate({"id": index, "type": "glob", **row})
        for index, row in enumerate(credential_allowlist, 1)
    ]
    ignored = [CacheIgnoredParamRow(name=name) for name in ignored_params]
    return RulesSnapshot(
        version=version,
        loaded_at=0.0,
        cache_rules=tuple(cache),
        credential_allowlist=tuple(credential),
        cache_ignored_param_rows=tuple(ignored),
    )


@dataclass
class FakeRequest:
    """The `proxy/context.py: ProxyRequest` fields the cache reads (not slotted, so tests can add fields)."""

    method: str
    host: str
    path: str
    query: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    deadline_at: float = field(default_factory=lambda: time.monotonic() + 60.0)
    request_id: str = "req-test"
    template: str = ""
    target: str = ""
    cache_key: Any = None
    fresh_cache_hit: bool = False

    def forwarded_headers(self) -> dict[str, str]:
        """Plan 9.13, like `proxy/scrub.py: forwarded_request_headers`."""
        forwarded: dict[str, str] = {}
        accept = (self.headers.get("accept") or "").strip().lower()
        if accept in _FORWARDABLE_ACCEPT:
            forwarded["accept"] = accept
        if self.method.upper() in _BODY_METHODS:
            content_type = (self.headers.get("content-type") or "").strip()
            if content_type:
                forwarded["content-type"] = content_type
            forwarded["content-length"] = str(len(self.body))
        return forwarded


def make_request(
    target: str,
    *,
    method: str = "GET",
    body: bytes = b"",
    headers: Mapping[str, str] | None = None,
    deadline_s: float = 60.0,
) -> FakeRequest:
    """`make_request("games.roblox.com/v1/games/votes?universeIds=1")` -> a GET FakeRequest."""
    location, _, query_text = target.partition("?")
    host, _, path = location.partition("/")
    query = [(name, value) for name, _, value in (part.partition("=") for part in query_text.split("&") if part)]
    return FakeRequest(
        method=method.upper(),
        host=host.lower(),
        path=path,
        query=query,
        body=body,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        deadline_at=time.monotonic() + deadline_s,
        target=f"{host.lower()}/{path}",
    )


__all__ = [
    "FakeAvailability",
    "FakeCall",
    "FakeRequest",
    "FakeResult",
    "FakeSettings",
    "FakeUpstream",
    "StaticRules",
    "failure",
    "make_request",
    "ok",
    "roblox_429",
    "roblox_error",
    "rules_snapshot",
]
