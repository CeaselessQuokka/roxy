"""Egress clients: the three ways a request leaves Roxy, and `EgressClients`, the one object that sends it.

What this is
    Three client kinds, each an `httpx.AsyncClient` with `trust_env=False` built by its own factory (plan C2 item
    1): `DirectClient` (server IP, no proxy, no cookie, HTTP/2), `CredentialClient` (server IP, no proxy, the
    cookie added per request by `egress/credential.py`, HTTP/2), and `RotatorClient` (one per DataImpulse session,
    through the proxy, no cookie, HTTP/1.1). `EgressClients` (`ctx.egress`, DESIGN.md 11.4) holds them plus the
    credential manager, the rotator pool and the header profiles, and exposes `send(egress, request)`,
    `is_enabled(egress)`, the admin re-enable after a leak guard trip, and the H-CRED-GUARD and H-ENV-PROXY
    self-tests. `build_egress_clients(ctx)` is what the lifespan calls.

Why it exists
    v1 used module-level `requests` calls: a new connection per call, `trust_env=True` (so `HTTPS_PROXY` could
    capture the credential), the cookie in a jar that followed redirects, and nothing stopping the token from
    leaving through the rotation proxy. Plan C2 asks for layered defenses that each hold on their own:
      1. type separation: only the credential client is ever given the cookie, by credential.py, per request;
      2. `trust_env=False` everywhere, so proxy variables and `.netrc` are ignored;
      3. the credential client has no proxy and no mounts, asserted at startup (`assert_no_proxy`);
      4. the direct and rotator clients sit on `GuardTransport`, which refuses any request carrying the
         credential (and disables that egress fleet-wide) or a public auth marker (refused, egress stays on);
      5. every client's cookie jar refuses to store or send cookies, and its jar cannot be swapped;
      6. redirects are followed by hand, at most 3, each hop re-validated (https, allowed Roblox host); the
         cookie is re-checked and re-attached per hop, so it can never follow a redirect off the allowlist;
      7. `Set-Cookie` is stripped from every response; on the credential path a `.ROBLOSECURITY` one raises the
         "Roblox rotated the cookie" alert and is never stored.

How it works
    `send` checks the egress is enabled (admin switch, leak guard trip, rotator configured, parked or over budget;
    the credential path re-reads its shared state right before the cookie is attached), validates the target,
    builds API-shaped headers from the header profile plus the caller-safe extras the upstream layer passes, and
    sends with byte metering scoped to this one call. httpx errors become `UpstreamTimeout` or
    `UpstreamConnectError`; the body is read with a hard size bound. Usage goes to the accountant; rotator
    outcomes feed the rotator's failure streak, and a 429 rotates a `sticky_until_429` session.
    Pools and timeouts (plan 7.11): direct and credential keep up to 50 connections, keep-alive 30 s; timeouts
    connect `upstream_connect_timeout_s` (5), read `request_timeout` (15), write 10, pool 5 unless the
    `OutboundRequest` brings its own. Rotator session clients keep 8 connections; the shared `per_request`
    client disables keep-alive so every request gets a new tunnel and a new exit IP.

    TEST-ONLY upstream override (multi-process tests, never production)
    When `ROXY_ENV=development` and `ROXY_TEST_UPSTREAM_BASE` is set (a loopback origin such as
    `http://127.0.0.1:18080`), the direct and credential clients send every Roblox request to that base instead:
    same path and query, plain http allowed, `Host` set to the original Roblox host, and `X-Roxy-Test-Host`
    naming it too. Rotator requests to Roblox are rewritten the same way, and `ROXY_TEST_ROTATOR_PROXY` (a
    loopback proxy, for example `tests/fixtures/recording_proxy.py`) replaces the rotator's proxy URL. Nothing else
    changes: the target is validated as the real Roblox URL first, the guard, header profiles, metering,
    accounting and the credential checks all stay in place, and the cookie is attached only after
    `authorize` accepted the Roblox URL and saw a loopback destination. With `ROXY_ENV=production`, setting either
    variable is a startup error (`EgressConfigError`), and both must name loopback addresses in any environment.

What to read next
    `roxy/egress/credential.py` (the only reader of the secret), `roxy/egress/guard.py` (the leak guard), then
    `roxy/egress/rotator.py` and `roxy/egress/metering.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sqlite3
import ssl
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from roxy.config import audit
from roxy.config.audit import Actor
from roxy.core.clock import Clock
from roxy.core.reasons import Egress
from roxy.egress.accounting import EgressUsage, UsageAccountant
from roxy.egress.credential import CredentialManager, LeakMatcher
from roxy.egress.crypto import load_encryption_key
from roxy.egress.errors import (
    AuthSmugglingBlocked,
    CredentialLeakBlocked,
    CredentialUnavailable,
    EgressConfigError,
    EgressDisabled,
    TargetNotAllowed,
    UpstreamConnectError,
    UpstreamTimeout,
)
from roxy.egress.events import EventSink
from roxy.egress.guard import GuardStats, GuardTransport, Inspection, LeakTrip, NoStoreCookieJar, guard_context
from roxy.egress.headers import HeaderProfiles, merge_outbound
from roxy.egress.metering import (
    ByteMeter,
    Estimate,
    MeteringMode,
    MeteringSelfTest,
    MeteringTransport,
    RequestUsage,
    attribute_to,
    estimate_exchange,
    run_self_test,
)
from roxy.egress.models import (
    CREDENTIAL_PROBE_PURPOSES,
    PURPOSE_EXIT_IP_PROBE,
    EgressResponse,
    OutboundRequest,
    SelfTestResult,
)
from roxy.egress.rotator import STICKY_UNTIL_429, RotatorPool
from roxy.egress.targets import UpstreamTestOverride, check_echo_target, check_roblox_target, endpoint_label
from roxy.storage.db import Databases, SharedStateUnavailable

log = logging.getLogger("roxy.egress.clients")

DIRECT_LIMITS = httpx.Limits(max_connections=50, max_keepalive_connections=20, keepalive_expiry=30.0)
"""Plan 7.11: one pooled client per path, at most 50 connections, idle connections kept 30 s."""

ROTATOR_SESSION_LIMITS = httpx.Limits(max_connections=8, max_keepalive_connections=4, keepalive_expiry=30.0)
"""One sticky session: a few parallel tunnels through the same exit (bounded: at most 16 sessions per worker)."""

ROTATOR_PER_REQUEST_LIMITS = httpx.Limits(max_connections=50, max_keepalive_connections=0, keepalive_expiry=30.0)
"""`per_request` mode: keep-alive off, because a reused tunnel would reuse the same exit IP (plan 7.11)."""

WRITE_TIMEOUT_S = 10.0
POOL_TIMEOUT_S = 5.0
MAX_REDIRECTS = 3
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
"""Hard safety bound on one upstream body (plan P9); Roblox API answers are far smaller."""

DROPPED_RESPONSE_HEADERS = frozenset(
    {"set-cookie", "content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"}
)
"""Never returned: cookies (C2 item 7, 9.13), and framing headers that no longer describe the decoded body."""

CREDENTIAL_METHODS = frozenset({"GET", "HEAD"})

DISABLED_KEY_PREFIX = "egress_disabled:"
"""control.db `service_state` keys `egress_disabled:direct` and `egress_disabled:rotator`: a leak guard trip."""

PROXY_ENV_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")
REFRESH_INTERVAL_S = 1.0
STALE_REFRESH_S = 2.0
_SEEN_STREAMS_MAX = 512
_LEAK_ACTOR = Actor("system", "leak_guard")


# --- the client kinds -----------------------------------------------------------------------------------------------


class JarLockedAsyncClient(httpx.AsyncClient):
    """An httpx client whose cookie jar cannot be replaced (the no-store jar it was built with stays)."""

    @property
    def cookies(self) -> httpx.Cookies:
        return self._cookies

    @cookies.setter
    def cookies(self, value: Any) -> None:
        raise AttributeError("egress clients never hold cookies (plan C2 item 6)")


class _EgressHttpClient:
    """Common shape of the three client kinds: the httpx client, its transport chain and its meter."""

    egress: Egress

    def __init__(self, http: httpx.AsyncClient, top: httpx.AsyncBaseTransport, metering: MeteringTransport) -> None:
        self.http = http
        self._top = top
        self.metering = metering
        self._seen_streams: OrderedDict[int, None] = OrderedDict()

    @property
    def transport(self) -> httpx.AsyncBaseTransport:
        """The outermost transport this client was built with (the guard on anonymous clients)."""
        return self._top

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Send one request (no redirects, streamed body) and map library errors to egress errors."""
        if getattr(self.http, "_transport", self._top) is not self._top:
            # Someone replaced the transport after construction: refuse rather than send around the guard.
            raise EgressDisabled(self.egress, "client_transport_replaced")
        try:
            return await self.http.send(request, stream=True, follow_redirects=False)
        except (CredentialLeakBlocked, AuthSmugglingBlocked):
            raise
        except httpx.ConnectTimeout as exc:
            raise UpstreamConnectError(self.egress, "connect timeout") from exc
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout(self.egress, type(exc).__name__) from exc
        except httpx.HTTPError as exc:
            raise UpstreamConnectError(self.egress, type(exc).__name__) from exc

    def is_new_connection(self, response: httpx.Response) -> bool:
        """For the fallback estimate: True the first time a connection is seen (bounded memory)."""
        stream = response.extensions.get("network_stream")
        if stream is None:
            return True
        key = id(stream)
        if key in self._seen_streams:
            self._seen_streams.move_to_end(key)
            return False
        self._seen_streams[key] = None
        while len(self._seen_streams) > _SEEN_STREAMS_MAX:
            self._seen_streams.popitem(last=False)
        return True

    async def aclose(self) -> None:
        await self.http.aclose()


class DirectClient(_EgressHttpClient):
    """Server IP, anonymous: no proxy, no cookie, the leak guard underneath."""

    egress = Egress.DIRECT


class CredentialClient(_EgressHttpClient):
    """Server IP with the credential: no proxy, no mounts, no jar; the cookie comes from credential.py per request."""

    egress = Egress.CREDENTIAL


class RotatorClient(_EgressHttpClient):
    """One DataImpulse session: through the proxy, anonymous, the leak guard underneath, HTTP/1.1 only."""

    egress = Egress.ROTATOR

    def __init__(
        self,
        http: httpx.AsyncClient,
        top: httpx.AsyncBaseTransport,
        metering: MeteringTransport,
        *,
        session_id: str,
        keepalive: bool,
    ) -> None:
        super().__init__(http, top, metering)
        self.session_id = session_id
        self.keepalive = keepalive


@dataclass(frozen=True, slots=True)
class GuardHooks:
    """What an anonymous client's guard needs from `EgressClients`."""

    matcher: Callable[[], LeakMatcher]
    max_body_bytes: Callable[[], int]
    on_leak: Callable[[LeakTrip], Any] | None = None
    on_marker: Callable[[Egress, Inspection], None] | None = None
    stats: GuardStats | None = None


def _default_timeout() -> httpx.Timeout:
    return httpx.Timeout(15.0, connect=5.0, write=WRITE_TIMEOUT_S, pool=POOL_TIMEOUT_S)


def make_direct_client(
    *,
    hooks: GuardHooks,
    meter: ByteMeter | None = None,
    verify: ssl.SSLContext | bool = True,
    http2: bool = True,
    socket_metering: bool | None = None,
) -> DirectClient:
    """The direct client: metered transport, guard on top, no proxy, no cookies, `trust_env=False`."""
    metering = MeteringTransport(
        meter=meter or ByteMeter("direct"),
        limits=DIRECT_LIMITS,
        http2=http2,
        verify=verify,
        socket_metering=socket_metering,
    )
    guard = GuardTransport(
        metering,
        egress=Egress.DIRECT,
        matcher=hooks.matcher,
        max_body_bytes=hooks.max_body_bytes,
        on_leak=hooks.on_leak,
        on_marker=hooks.on_marker,
        stats=hooks.stats,
    )
    # trust_env=False: HTTPS_PROXY, ALL_PROXY, NO_PROXY and .netrc are ignored (plan C2 item 2).
    http = JarLockedAsyncClient(
        transport=guard, trust_env=False, cookies=NoStoreCookieJar(), follow_redirects=False, timeout=_default_timeout()
    )
    return DirectClient(http, guard, metering)


def make_credential_client(
    *,
    meter: ByteMeter | None = None,
    verify: ssl.SSLContext | bool = True,
    http2: bool = True,
    socket_metering: bool | None = None,
) -> CredentialClient:
    """The credential client: metered transport, `proxy=None`, `mounts={}`, no jar, `trust_env=False`."""
    metering = MeteringTransport(
        meter=meter or ByteMeter("credential"),
        limits=DIRECT_LIMITS,
        http2=http2,
        verify=verify,
        proxy=None,
        socket_metering=socket_metering,
    )
    http = JarLockedAsyncClient(
        transport=metering,
        trust_env=False,
        proxy=None,
        mounts={},
        cookies=NoStoreCookieJar(),
        follow_redirects=False,
        timeout=_default_timeout(),
    )
    return CredentialClient(http, metering, metering)


def make_rotator_client(
    proxy_url: str,
    *,
    session_id: str,
    keepalive: bool,
    hooks: GuardHooks,
    meter: ByteMeter | None = None,
    verify: ssl.SSLContext | bool = True,
    socket_metering: bool | None = None,
) -> RotatorClient:
    """One rotator session client: metered proxy transport (HTTP/1.1), guard on top, no cookies."""
    metering = MeteringTransport(
        meter=meter or ByteMeter("rotator"),
        limits=ROTATOR_SESSION_LIMITS if keepalive else ROTATOR_PER_REQUEST_LIMITS,
        http2=False,  # HTTP/1.1 keeps one request per connection, so byte attribution is exact (plan 8.3)
        verify=verify,
        proxy=proxy_url,
        socket_metering=socket_metering,
    )
    guard = GuardTransport(
        metering,
        egress=Egress.ROTATOR,
        matcher=hooks.matcher,
        max_body_bytes=hooks.max_body_bytes,
        on_leak=hooks.on_leak,
        on_marker=hooks.on_marker,
        stats=hooks.stats,
    )
    http = JarLockedAsyncClient(
        transport=guard, trust_env=False, cookies=NoStoreCookieJar(), follow_redirects=False, timeout=_default_timeout()
    )
    return RotatorClient(http, guard, metering, session_id=session_id, keepalive=keepalive)


def assert_no_proxy(client: _EgressHttpClient) -> None:
    """Startup assertion (plan C2 item 3): no proxy mount, no env trust, no proxy pool under this client."""
    http = client.http
    label = client.egress.value
    if getattr(http, "_mounts", None):
        raise EgressConfigError(f"the {label} client has transport mounts; it must not route through any proxy")
    if http.trust_env:
        raise EgressConfigError(f"the {label} client trusts the environment (proxy variables, .netrc)")
    layer = getattr(http, "_transport", None)
    while isinstance(layer, GuardTransport):
        layer = layer.inner
    if layer is not client.metering:
        raise EgressConfigError(f"the {label} client's transport chain is not the one it was built with")
    if client.metering.proxy_configured or client.metering.pool_is_proxy():
        raise EgressConfigError(f"the {label} client has a proxy transport")


class _NeverSendTransport(httpx.AsyncBaseTransport):
    """The bottom of the self-test guard: records that it was reached and refuses to send anything."""

    def __init__(self) -> None:
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        raise RuntimeError("the self-test transport never sends")


# --- EgressClients ---------------------------------------------------------------------------------------------------


class EgressClients:
    """`ctx.egress` (DESIGN.md 11.4). Build with `build_egress_clients(ctx)` or construct and `await start()`."""

    def __init__(
        self,
        *,
        env: Any,
        settings: Any,
        dbs: Databases,
        clock: Clock,
        worker_id: str,
        alerts: Callable[[], Any] = lambda: None,
        recorder: Callable[[], Any] = lambda: None,
        environ: Mapping[str, str] | None = None,
        tls_verify: ssl.SSLContext | bool = True,
        socket_metering: bool | None = None,
    ) -> None:
        self._env = env
        self._settings = settings
        self._dbs = dbs
        self._clock = clock
        self._worker_id = worker_id
        self._environ: Mapping[str, str] = os.environ if environ is None else environ
        self._tls_verify = tls_verify
        self._socket_metering = socket_metering
        # Refused in production before anything else is built (see "TEST-ONLY upstream override" above).
        self.override = UpstreamTestOverride.from_environ(str(getattr(env, "env", "production")), self._environ)
        self.events = EventSink(alerts, recorder)
        self.accounting = UsageAccountant(recorder)
        self.headers = HeaderProfiles(settings, str(getattr(env, "site_origin", "")))
        self.guard_stats = {Egress.DIRECT: GuardStats(), Egress.ROTATOR: GuardStats()}
        self.meters = {egress: ByteMeter(egress.value) for egress in (Egress.DIRECT, Egress.CREDENTIAL, Egress.ROTATOR)}
        credentials_dir = getattr(env, "credentials_dir", None)
        key = load_encryption_key(credentials_dir)
        self.credential = CredentialManager(
            credentials_dir=credentials_dir,
            dbs=dbs,
            settings=settings,
            clock=clock,
            worker_id=worker_id,
            encryption_key=key,
            events=self.events,
            allow_loopback_target=self.override is not None and self.override.base is not None,
        )
        self.rotator = RotatorPool(
            credentials_dir=credentials_dir,
            dbs=dbs,
            settings=settings,
            clock=clock,
            echo_url=str(getattr(env, "rotator_ip_echo_url", "https://api.ipify.org?format=json")),
            encryption_key=key,
            client_factory=self._make_rotator_client,
            events=self.events,
            override_proxy=self.override.rotator_proxy if self.override is not None else None,
        )
        self.metering_self_test: MeteringSelfTest | None = None
        self._direct: DirectClient | None = None
        self._credential_client: CredentialClient | None = None
        self._disabled: dict[Egress, dict[str, Any]] = {}
        self._pending_trips: dict[Egress, dict[str, Any]] = {}
        self._last_refresh = float("-inf")
        self._refresh_lock = asyncio.Lock()
        self._started = False
        self.credential.set_sender(lambda out: self.send(Egress.CREDENTIAL, out))
        self.rotator.set_sender(lambda out: self.send(Egress.ROTATOR, out))
        self.accounting.add_listener(self.rotator.on_usage)

    # --- construction helpers ---------------------------------------------------------------------------------------

    def _setting(self, key: str, default: Any) -> Any:
        try:
            return self._settings.get(key)
        except (KeyError, LookupError, AttributeError):
            return default

    def _max_body_bytes(self) -> int:
        return int(self._setting("max_body_bytes", 2 * 1024 * 1024))

    def _hooks(self, egress: Egress) -> GuardHooks:
        return GuardHooks(
            matcher=self.credential.leak_matcher,
            max_body_bytes=self._max_body_bytes,
            on_leak=self._on_leak,
            on_marker=self._on_marker,
            stats=self.guard_stats[egress],
        )

    def _make_rotator_client(self, proxy_url: str, session_id: str, keepalive: bool) -> RotatorClient:
        return make_rotator_client(
            proxy_url,
            session_id=session_id,
            keepalive=keepalive,
            hooks=self._hooks(Egress.ROTATOR),
            meter=self.meters[Egress.ROTATOR],
            verify=self._tls_verify,
            socket_metering=self._socket_metering,
        )

    @property
    def direct_client(self) -> DirectClient:
        if self._direct is None:
            raise RuntimeError("EgressClients.start() has not run")
        return self._direct

    @property
    def credential_client(self) -> CredentialClient:
        if self._credential_client is None:
            raise RuntimeError("EgressClients.start() has not run")
        return self._credential_client

    # --- lifecycle --------------------------------------------------------------------------------------------------

    async def start(self) -> None:
        """Run the metering self-test, build and check the clients, and load credential, rotator and trip state."""
        if self._socket_metering is None:
            self.metering_self_test = await run_self_test()
            log.info(
                "egress_metering",
                extra={
                    "fields": {"mode": self.metering_self_test.mode.value, "detail": self.metering_self_test.detail}
                },
            )
        self._direct = make_direct_client(
            hooks=self._hooks(Egress.DIRECT),
            meter=self.meters[Egress.DIRECT],
            verify=self._tls_verify,
            socket_metering=self._socket_metering,
        )
        self._credential_client = make_credential_client(
            meter=self.meters[Egress.CREDENTIAL], verify=self._tls_verify, socket_metering=self._socket_metering
        )
        assert_no_proxy(self._direct)
        assert_no_proxy(self._credential_client)
        await self.credential.start()
        await self.rotator.start()
        await self._refresh_trips()
        self._last_refresh = self._clock.monotonic()
        self._started = True
        if self.override is not None:
            log.warning("egress_test_override_active", extra={"fields": {"env": str(getattr(self._env, "env", ""))}})

    async def aclose(self) -> None:
        """Close every client and wait briefly for alert sends (shutdown)."""
        for client in (self._direct, self._credential_client):
            if client is not None:
                await client.aclose()
        await self.rotator.aclose()
        await self.events.drain(timeout_s=2.0)

    async def refresh(self) -> None:
        """Re-read credential, rotator and trip state from the shared databases (every second per worker)."""
        await self.credential.refresh()
        await self.rotator.refresh()
        await self._refresh_trips()
        self._last_refresh = self._clock.monotonic()

    async def run(self, stop: asyncio.Event) -> None:
        """The per-worker refresh loop for `lifespan._start_loop(ctx, stack, "egress_refresh", egress.run)`."""
        while not stop.is_set():
            try:
                await self.refresh()
            except Exception:
                log.exception("egress_refresh_failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=REFRESH_INTERVAL_S)

    async def _maybe_refresh(self) -> None:
        if self._clock.monotonic() - self._last_refresh < STALE_REFRESH_S or self._refresh_lock.locked():
            return
        async with self._refresh_lock:
            await self.refresh()

    # --- leak guard trips --------------------------------------------------------------------------------------------

    @staticmethod
    def _read_trips(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
        rows = conn.execute(
            "SELECT key, value_json FROM service_state WHERE key >= ? AND key < ?",
            (DISABLED_KEY_PREFIX, DISABLED_KEY_PREFIX[:-1] + ";"),
        ).fetchall()
        out: dict[str, dict[str, Any]] = {}
        for key, value in rows:
            try:
                parsed = json.loads(value)
            except ValueError:
                parsed = {}
            out[str(key)[len(DISABLED_KEY_PREFIX) :]] = parsed if isinstance(parsed, dict) else {}
        return out

    async def _refresh_trips(self) -> None:
        for egress, row in list(self._pending_trips.items()):
            if await self._write_trip(egress, row):
                self._pending_trips.pop(egress, None)
        try:
            rows = await self._dbs.control.read(self._read_trips)
        except SharedStateUnavailable:
            return  # keep the last known trips; pending local trips stay in force regardless
        self._disabled = {Egress(name): row for name, row in rows.items() if name in ("direct", "rotator")}

    def tripped(self, egress: Egress) -> bool:
        """True while a leak guard trip keeps `egress` disabled (fleet-wide row or a local trip not yet saved)."""
        return egress in self._disabled or egress in self._pending_trips

    async def _write_trip(self, egress: Egress, row: dict[str, Any]) -> bool:
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                (DISABLED_KEY_PREFIX + egress.value, json.dumps(row, sort_keys=True), now),
            )
            audit.record(
                conn,
                _LEAK_ACTOR,
                "egress.leak_guard_trip",
                f"egress:{egress.value}",
                None,
                row,
                "the credential was found in an anonymous request; egress disabled until an admin re-enables it",
                row.get("request_id"),
                at=now,
            )

        try:
            await self._dbs.control.write(write, busy_timeout_ms=2000)
        except SharedStateUnavailable as exc:
            log.critical("leak_trip_not_saved", extra={"fields": {"egress": egress.value, "error": str(exc)[:200]}})
            return False
        return True

    async def _on_leak(self, trip: LeakTrip) -> None:
        row = {
            "reason": "leak_guard",
            "since": int(self._clock.now()),
            "location": trip.location,
            "purpose": trip.purpose,
            "request_id": trip.request_id,
            "worker": self._worker_id,
        }
        # In force in this worker at once, whatever happens to the database write below.
        self._pending_trips[trip.egress] = row
        if await self._write_trip(trip.egress, row):
            self._pending_trips.pop(trip.egress, None)
            self._disabled[trip.egress] = row
        self.events.alert(
            type="leak_guard",
            severity="critical",
            subject="Roxy SECURITY: credential leak blocked",
            summary=(
                f"The leak guard refused a {trip.egress.value} request that carried the Roblox credential. "
                f"The {trip.egress.value} egress is disabled until an admin re-enables it."
            ),
            fields={
                "egress_disabled": trip.egress.value,
                "request_id": trip.request_id or "",
                "code_path": trip.purpose,
                "found_in": trip.location,
                "runbook": "Leak guard",
            },
            always_send=True,
        )
        self.events.event(
            "leak_blocked", "critical", "leak_blocked", {"egress": trip.egress.value, "location": trip.location}
        )

    def _on_marker(self, egress: Egress, inspection: Inspection) -> None:
        self.events.event(
            "auth_smuggling_blocked",
            "warn",
            "auth_smuggling",
            {"egress": egress.value, "marker": inspection.marker, "location": inspection.location},
        )

    async def enable_egress(
        self, egress: Egress, actor: Actor, *, reason: str | None = None, request_id: str | None = None
    ) -> bool:
        """Re-enable an egress after a leak guard trip (the admin action; audited). False when it was not tripped."""
        if egress not in (Egress.DIRECT, Egress.ROTATOR):
            raise ValueError("only the direct and rotator egresses can be tripped")
        key = DISABLED_KEY_PREFIX + egress.value
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> bool:
            row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (key,)).fetchone()
            if row is None:
                return False
            conn.execute("DELETE FROM service_state WHERE key = ?", (key,))
            before = json.loads(row[0]) if row[0] else None
            audit.record(
                conn, actor, "egress.enable", f"egress:{egress.value}", before, None, reason, request_id, at=now
            )
            return True

        changed = await self._dbs.control.write(write)
        self._pending_trips.pop(egress, None)
        self._disabled.pop(egress, None)
        return bool(changed)

    # --- availability -------------------------------------------------------------------------------------------------

    def is_enabled(self, egress: Egress, *, purpose: str = "caller") -> tuple[bool, str]:
        """`(enabled, reason)`: admin switches, leak guard trips, rotator configuration, park and budget, and the
        credential status. Reads the per-worker snapshot (refreshed every second); never touches a database."""
        if egress is Egress.DIRECT:
            if self.tripped(egress):
                return False, "leak_guard_tripped"
            if not self._setting("direct_enabled", 1):
                return False, "direct_disabled"
            return True, ""
        if egress is Egress.ROTATOR:
            if self.tripped(egress):
                return False, "leak_guard_tripped"
            usable, reason, _ = self.rotator.availability(ignore_switch=purpose == PURPOSE_EXIT_IP_PROBE)
            return usable, reason
        if egress is Egress.CREDENTIAL:
            usable = (
                self.credential.probe_allowed() if purpose in CREDENTIAL_PROBE_PURPOSES else self.credential.available()
            )
            return usable, "" if usable else f"credential_{self.credential.status().status}"
        return False, "no_egress"

    # --- sending ------------------------------------------------------------------------------------------------------

    async def send(self, egress: Egress, out: OutboundRequest) -> EgressResponse:
        """Send one upstream call through `egress` (DESIGN.md 11.4). Raises the `egress.errors` exceptions only."""
        if not self._started:
            raise RuntimeError("EgressClients.start() has not run")
        await self._maybe_refresh()
        if egress is Egress.CREDENTIAL:
            # No cached pre-check: `authorize` re-reads the shared state right before the cookie is attached.
            return await self._send_with(self.credential_client, out, egress, None, credential=True)
        usable, why = self.is_enabled(egress, purpose=out.purpose)
        if not usable:
            retry = None
            if egress is Egress.ROTATOR:
                retry = self.rotator.availability(ignore_switch=out.purpose == PURPOSE_EXIT_IP_PROBE)[2]
            raise EgressDisabled(egress, why, retry)
        if egress is Egress.DIRECT:
            return await self._send_with(self.direct_client, out, egress, None)
        if egress is Egress.ROTATOR:
            return await self._send_rotator(out)
        raise ValueError(f"cannot send through egress {egress.value!r}")

    async def _send_rotator(self, out: OutboundRequest) -> EgressResponse:
        lease = await self.rotator.acquire(out.session_id)
        counted = out.purpose != PURPOSE_EXIT_IP_PROBE  # v1: probe failures never park the rotator
        try:
            response = await self._send_with(lease.client, out, Egress.ROTATOR, lease.session_id)
        except (UpstreamTimeout, UpstreamConnectError) as exc:
            if counted:
                await self.rotator.record_result(False, type(exc).__name__)
            raise
        finally:
            await self.rotator.release(lease)
        bad = response.status == 429 or response.status >= 500
        if counted:
            await self.rotator.record_result(not bad, f"http_{response.status}")
        if response.status == 429 and self.rotator.effective_mode() == STICKY_UNTIL_429:
            self.rotator.rotate(lease.session_id, "429")
        return response

    def _check_target(self, egress: Egress, url: str | httpx.URL, purpose: str) -> tuple[httpx.URL, bool]:
        """`(validated url, is_roblox)`; only the rotator's exit IP probe may name the IP echo service."""
        if egress is Egress.ROTATOR and purpose == PURPOSE_EXIT_IP_PROBE:
            echo = str(getattr(self._env, "rotator_ip_echo_url", ""))
            return check_echo_target(url, egress=egress, echo_url=echo), False
        checked = check_roblox_target(
            url,
            egress=egress,
            allowed_hosts=tuple(self._setting("allowed_roblox_hosts", ())),
            strict=bool(self._setting("strict_host_allowlist", 1)),
            require_listed=egress is Egress.CREDENTIAL,
        )
        return checked, True

    def _timeout(self, out: OutboundRequest) -> httpx.Timeout:
        if isinstance(out.timeout, httpx.Timeout):
            return out.timeout
        return httpx.Timeout(
            float(self._setting("request_timeout", 15)),
            connect=float(self._setting("upstream_connect_timeout_s", 5)),
            write=WRITE_TIMEOUT_S,
            pool=POOL_TIMEOUT_S,
        )

    async def _read_body(self, client: _EgressHttpClient, response: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        try:
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise UpstreamConnectError(client.egress, "response larger than the safety bound")
                chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout(client.egress, type(exc).__name__) from exc
        except httpx.HTTPError as exc:
            raise UpstreamConnectError(client.egress, type(exc).__name__) from exc
        finally:
            await response.aclose()
        return b"".join(chunks)

    async def _send_with(
        self,
        client: _EgressHttpClient,
        out: OutboundRequest,
        egress: Egress,
        session_id: str | None,
        *,
        credential: bool = False,
    ) -> EgressResponse:
        logical, is_roblox = self._check_target(egress, out.url, out.purpose)
        method = out.method.upper()
        if credential and method not in CREDENTIAL_METHODS:
            # The allowlist table only admits GET and HEAD (D1, 9.13); a write never carries the account cookie.
            raise TargetNotAllowed(egress, "the credential is used only for GET and HEAD")
        content = out.content
        identity = session_id if egress is Egress.ROTATOR else out.identity
        headers = merge_outbound(self.headers.api_headers(egress, identity), out.headers)
        timeout = self._timeout(out)
        probe = out.purpose in CREDENTIAL_PROBE_PURPOSES
        usage = RequestUsage()
        estimate = Estimate(0, 0, 0)
        socket_mode = client.metering.mode is MeteringMode.SOCKET
        started = self._clock.monotonic()
        redirects = 0
        response: httpx.Response | None = None
        body = b""
        status: int | None = None
        try:
            with attribute_to(usage), guard_context(out.purpose):
                while True:
                    target, extra = (
                        self.override.rewrite(logical) if self.override is not None and is_roblox else (logical, {})
                    )
                    request = client.http.build_request(
                        method, target, headers={**headers, **extra}, content=content, timeout=timeout
                    )
                    if credential:
                        await self.credential.authorize(request, logical_url=logical, probe=probe)
                    hop: httpx.Response | None = None
                    try:
                        hop = await client.send(request)
                        body = await self._read_body(client, hop)
                    finally:
                        if not socket_mode:
                            estimate = self._add_estimate(estimate, client, request, hop, target)
                    response = hop
                    status = hop.status_code
                    set_cookies = hop.headers.get_list("set-cookie")
                    if credential and set_cookies:
                        await self.credential.observe_set_cookie(set_cookies, endpoint=endpoint_label(logical))
                    follow = self._next_hop(out, egress, logical, hop, redirects)
                    if follow is None:
                        break
                    logical, method, content = follow[0], follow[1], follow[2]
                    if content is None:
                        headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
                    redirects += 1
        finally:
            self._account(client, out, egress, session_id, usage, estimate, socket_mode, status)
        if response is None:  # pragma: no cover - the loop always sets it or raises
            raise RuntimeError("no upstream response")
        elapsed_ms = round((self._clock.monotonic() - started) * 1000, 2)
        safe_headers = httpx.Headers(
            [(k, v) for k, v in response.headers.multi_items() if k.lower() not in DROPPED_RESPONSE_HEADERS]
        )
        if socket_mode:
            bytes_out, bytes_in, new_connections = usage.bytes_out, usage.bytes_in, usage.new_connections
        else:
            # The per-connection overhead is mostly the server's certificate chain, so it is shown as bytes in.
            bytes_out, bytes_in, new_connections = estimate.bytes_out, estimate.bytes_in + estimate.overhead, 0
        return EgressResponse(
            status=response.status_code,
            headers=safe_headers,
            body=body,
            elapsed_ms=elapsed_ms,
            bytes_out=bytes_out,
            bytes_in=bytes_in,
            egress=egress,
            session_id=session_id,
            http_version=response.http_version,
            url=str(logical),
            redirects=redirects,
            metering=client.metering.mode.value,
            new_connections=new_connections,
        )

    def _next_hop(
        self, out: OutboundRequest, egress: Egress, logical: httpx.URL, response: httpx.Response, redirects: int
    ) -> tuple[httpx.URL, str, bytes | None] | None:
        """The next URL, method and body when a redirect may be followed (plan 7.9), else None."""
        if not out.follow_redirects or response.status_code not in REDIRECT_STATUSES or redirects >= MAX_REDIRECTS:
            return None
        location = response.headers.get("location")
        if not location:
            return None
        try:
            candidate = logical.join(location)
            next_url, is_roblox = self._check_target(egress, candidate, out.purpose)
        except (TargetNotAllowed, httpx.InvalidURL, ValueError):
            # Not allowed: the 3xx itself is the answer. The cookie never follows a redirect off the allowlist.
            return None
        if not is_roblox:
            return None
        method = response.request.method
        content = out.content if method == out.method.upper() else None
        # Browsers turn a 303 (and a 301 or 302 after a POST) into a GET without a body; so does Roxy.
        see_other = response.status_code == 303 and method != "HEAD"
        moved_post = response.status_code in (301, 302) and method == "POST"
        if see_other or moved_post:
            method, content = "GET", None
        return next_url, method, content

    def _add_estimate(
        self,
        total: Estimate,
        client: _EgressHttpClient,
        request: httpx.Request,
        response: httpx.Response | None,
        target: httpx.URL,
    ) -> Estimate:
        # A rotator CONNECT carries "Proxy-Authorization: Basic <base64 of user:password>", about 60 bytes.
        proxy_auth = 60 if client.metering.proxy_configured else 0
        hop = estimate_exchange(
            request,
            response,
            tls=target.scheme == "https",
            proxied=client.metering.proxy_configured,
            new_connection=client.is_new_connection(response) if response is not None else True,
            tls_overhead_bytes=int(self._setting("rotator_tls_overhead_bytes", 6000)),
            proxy_auth_bytes=proxy_auth,
        )
        return Estimate(total.bytes_out + hop.bytes_out, total.bytes_in + hop.bytes_in, total.overhead + hop.overhead)

    def _account(
        self,
        client: _EgressHttpClient,
        out: OutboundRequest,
        egress: Egress,
        session_id: str | None,
        usage: RequestUsage,
        estimate: Estimate,
        socket_mode: bool,
        status: int | None,
    ) -> None:
        if socket_mode:
            req, resp, overhead, connections = usage.bytes_out, usage.bytes_in, 0, usage.new_connections
        else:
            req, resp, overhead, connections = estimate.bytes_out, estimate.bytes_in, estimate.overhead, 0
        if not (req or resp or overhead):
            return  # refused before anything was sent (guard, target check, credential unavailable)
        self.accounting.record(
            EgressUsage(
                at_ms=self._clock.now_ms(),
                egress=egress,
                purpose=out.purpose,
                session_id=session_id,
                req_bytes=req,
                resp_bytes=resp,
                overhead_bytes=overhead,
                new_connections=connections,
                method=client.metering.mode.value,
                status=status,
            )
        )

    # --- self-tests for the health check (plan 13.2) ------------------------------------------------------------------

    async def self_test_leak_guard(self) -> SelfTestResult:
        """H-CRED-GUARD: synthetic credential-bearing rotator requests must be refused in-process, never sent."""
        kit = self.credential.guard_self_test_kit()
        sentinel = _NeverSendTransport()
        guard = GuardTransport(
            sentinel, egress=Egress.ROTATOR, matcher=lambda: kit.matcher, max_body_bytes=self._max_body_bytes
        )
        blocked = 0
        for request in kit.requests:
            try:
                await guard.handle_async_request(request)
            except CredentialLeakBlocked:
                blocked += 1
            except Exception:  # anything else (including the sentinel's refusal) counts as not blocked
                log.warning("guard_self_test_unexpected")
        sample = self._make_rotator_client("http://127.0.0.1:9", "self-test", False)
        try:
            layered = isinstance(getattr(sample.http, "_transport", None), GuardTransport)
        finally:
            await sample.aclose()
        direct_layered = isinstance(getattr(self.direct_client.http, "_transport", None), GuardTransport)
        ok = blocked == len(kit.requests) and sentinel.calls == 0 and layered and direct_layered
        facts: dict[str, object] = {
            "blocked": blocked,
            "attempts": len(kit.requests),
            "reached_network": sentinel.calls,
            "rotator_guarded": layered,
            "direct_guarded": direct_layered,
            "synthetic_value": kit.synthetic,
        }
        if not ok:
            return SelfTestResult("H-CRED-GUARD", "fail", "not blocked", "the leak guard let a request through", facts)
        if kit.synthetic:
            return SelfTestResult(
                "H-CRED-GUARD", "warn", "n/a", "no credential configured; the guard blocked a synthetic value", facts
            )
        return SelfTestResult("H-CRED-GUARD", "pass", "blocked", "every synthetic leak was refused in-process", facts)

    def self_test_env_proxy(self, environ: Mapping[str, str] | None = None) -> SelfTestResult:
        """H-ENV-PROXY: proxy variables must be unset, or at least ignored by every client."""
        source = os.environ if environ is None else environ  # the real service environment by default
        names = sorted({name.upper() for name in PROXY_ENV_VARS if (source.get(name) or "").strip()})
        honoring: list[str] = []
        for label, client in (("direct", self.direct_client), ("credential", self.credential_client)):
            try:
                assert_no_proxy(client)
            except EgressConfigError:
                honoring.append(label)
        sample = self._make_rotator_client("http://127.0.0.1:9", "self-test", False)
        try:
            if sample.http.trust_env:
                honoring.append("rotator")
        finally:
            self._close_soon(sample)
        facts: dict[str, object] = {"variables_set": names, "clients_honoring": honoring}
        if honoring:
            return SelfTestResult("H-ENV-PROXY", "fail", ", ".join(honoring), "clients honor proxy settings", facts)
        if names:
            return SelfTestResult("H-ENV-PROXY", "warn", ", ".join(names), "set in the environment but ignored", facts)
        return SelfTestResult("H-ENV-PROXY", "pass", "unset", "no proxy variables in the service environment", facts)

    def _close_soon(self, client: _EgressHttpClient) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(client.aclose())
        task.add_done_callback(lambda finished: finished.exception() if not finished.cancelled() else None)

    # --- the Egress page ----------------------------------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Counters for the Egress and System pages (never a secret)."""
        return {
            "metering_mode": (self.metering_self_test.mode.value if self.metering_self_test else "socket"),
            "meters": {egress.value: meter.snapshot() for egress, meter in self.meters.items()},
            "guard": {egress.value: guard_stats_dict(stats) for egress, stats in self.guard_stats.items()},
            "usage": self.accounting.totals(),
            "usage_buffered": self.accounting.buffered,
            "tripped": sorted(egress.value for egress in (Egress.DIRECT, Egress.ROTATOR) if self.tripped(egress)),
            "rotator": {
                "configured": self.rotator.configured(),
                "url": self.rotator.masked_url(),
                "mode": self.rotator.effective_mode(),
                "sessions": self.rotator.session_count(),
            },
            "test_override": self.override is not None,
        }


def guard_stats_dict(stats: GuardStats) -> dict[str, int]:
    """The guard counters as a plain dict."""
    return {
        "inspected": stats.inspected,
        "leak_trips": stats.leak_trips,
        "smuggling_refusals": stats.smuggling_refusals,
        "oversize_refusals": stats.oversize_refusals,
    }


async def build_egress_clients(ctx: Any) -> EgressClients:
    """Build and start `ctx.egress` from an `AppContext` (lifespan step "clients", DESIGN.md section 1).

    Lifespan wiring: `ctx.egress = await build_egress_clients(ctx)`, `stack.push_async_callback(ctx.egress.aclose)`,
    then `_start_loop(ctx, stack, "egress_refresh", ctx.egress.run)`. The notifier and recorder are looked up on
    `ctx` at each use, so they may be attached after this step.
    """
    clients = EgressClients(
        env=ctx.env,
        settings=ctx.settings,
        dbs=ctx.dbs,
        clock=ctx.clock,
        worker_id=ctx.worker_id,
        alerts=lambda: getattr(ctx, "alerts", None),
        recorder=lambda: getattr(ctx, "recorder", None),
    )
    await clients.start()
    return clients


__all__ = [
    "DIRECT_LIMITS",
    "DISABLED_KEY_PREFIX",
    "MAX_REDIRECTS",
    "CredentialClient",
    "CredentialUnavailable",
    "DirectClient",
    "EgressClients",
    "GuardHooks",
    "JarLockedAsyncClient",
    "RotatorClient",
    "assert_no_proxy",
    "build_egress_clients",
    "make_credential_client",
    "make_direct_client",
    "make_rotator_client",
]
