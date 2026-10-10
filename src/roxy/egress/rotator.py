"""The rotator: DataImpulse sessions, the gateway URL, exit IPs, rotator health and the byte budget (plan 8).

What this is
    `RotatorPool` (`ctx.egress.rotator`). It knows the gateway URL, decides which session (and therefore which exit
    IP) a request uses, keeps one httpx client per sticky session in a bounded LRU, checks the exit IP through the
    configured IP echo service, parks the rotator after a failure streak, and stops it at the monthly hard stop or
    the daily cap. It never sees the Roblox credential: the clients it holds are anonymous and guarded (C2).

Why it exists
    DataImpulse picks the exit IP per connection, or per session when the session id is put in the proxy user
    name. Each session therefore needs its own proxy URL and its own connection pool, and every byte costs money.
    v1 had one global proxy, a random User-Agent per request, no session control and no budget (parity rows 30 to
    33, plan 8.2 to 8.4).

How it works
    URL: the value the admin set on the Egress page (control.db `rotator_store`, AES-GCM encrypted) wins over the
    bootstrap systemd credential `rotator_url` (read once at start; there is no environment variable form because
    the URL embeds a password). It is never logged; `masked_url()` shows `scheme://host:port`. A change bumps
    `service_state.rotator_version`; every worker reloads within a second and retires its old clients.
    Every URL and its password are registered with `SecretRegistry` (which keeps 3 values per name) under a pair of
    names per role: offered (`replace_url` and the stored row), bootstrap (once at start) and in use (each time the
    URL changes). A URL that can be used again (the bootstrap one, through `revert_to_bootstrap`) therefore stays
    redacted for the worker's whole life, however many URLs the admin tries (finding W2H-1).
    Sessions (`rotator_session_mode`): `per_request` uses one shared client with keep-alive off, so every request
    opens a new CONNECT tunnel and gets a new exit IP; it is the effective mode while
    `rotator_session_username_template` is empty, because the sticky modes need the template to put a session id
    into the proxy user name (`{user}`, `{session}`, `{country}`; the format is the provider's and must be checked
    by the owner). `sticky` keeps the current session for `rotator_sticky_seconds`; `sticky_until_429` keeps it
    until `rotate()` (a 429 through that session). Sticky clients live in an LRU of `rotator_max_sessions`; an
    evicted or retired client is closed with `aclose()` as soon as no request is using it.
    Health (parity row 31): consecutive failures (timeouts, connect errors, Roblox 429 and 5xx) are counted
    fleet-wide in hot.db; at `rotator_max_failures` the rotator is parked for `rotator_cooldown_s`.
    Budget (plan 8.4): usage for the billing cycle and the day comes from metrics.db `egress_usage` (re-read every
    15 s) plus this worker's bytes not yet in it; at `rotator_hard_stop_pct` of `rotator_quota_gb_per_month`
    (decimal GB, the provider's unit) or `rotator_daily_cap_mb`, the rotator stops until the next cycle or day.
    Cycles and days are UTC.

What to read next
    `roxy/egress/clients.py` (`EgressClients.send` uses `acquire` and `release`), `roxy/egress/metering.py` (the
    byte counts), and `roxy/egress/headers.py` (one coherent header profile per session).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import secrets
import sqlite3
import time
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, unquote, urlsplit

import httpx

from roxy.config import audit
from roxy.config.audit import Actor, secret_summary
from roxy.core.clock import Clock
from roxy.core.reasons import Egress
from roxy.core.redact import SecretRegistry, masked_url
from roxy.egress.accounting import EgressUsage
from roxy.egress.credential import bump_version, read_version
from roxy.egress.crypto import SealError, derive_key, seal, unseal
from roxy.egress.errors import EgressError
from roxy.egress.events import EventSink
from roxy.egress.models import PURPOSE_EXIT_IP_PROBE, EgressResponse, OutboundRequest
from roxy.storage.db import Databases, SharedStateUnavailable

log = logging.getLogger("roxy.egress.rotator")

URL_FILE_NAME = "rotator_url"
ROTATOR_STORE_AAD = b"roxy:rotator_store:v1"
FINGERPRINT_LABEL = b"roxy rotator fingerprint v1"
VERSION_KEY = "rotator_version"
PARK_KEY = "rotator:parked"
"""hot.db `cooldown` row that parks the rotator after a failure streak (its own key, not an upstream one)."""
STREAK_KEY = "rotator:streak"
"""hot.db `breaker` row counting consecutive rotator failures fleet-wide."""

PER_REQUEST = "per_request"
STICKY = "sticky"
STICKY_UNTIL_429 = "sticky_until_429"
SESSION_MODES = (PER_REQUEST, STICKY, STICKY_UNTIL_429)

USAGE_REFRESH_S = 15.0
DECIMAL_GB = 1_000_000_000
DECIMAL_MB = 1_000_000
MAX_URL_LENGTH = 2048
_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")
_MAX_URL_FILE_BYTES = 8192
_SHARED = "__per_request__"

# `SecretRegistry` names, one pair (whole URL, password) per role. The registry keeps 3 values per name, so a value
# that can be used again must not share a name with values the admin can add at will (finding W2H-1).
OFFERED_SECRET_NAMES = ("rotator_url", "rotator_password")
"""URLs offered or stored through the Egress page (`replace_url`, the store row loaded by a refresh)."""
BOOTSTRAP_SECRET_NAMES = ("rotator_url_bootstrap", "rotator_password_bootstrap")
"""The bootstrap file's URL, registered once at start: `revert_to_bootstrap` can make it the URL in use again."""
IN_USE_SECRET_NAMES = ("rotator_url_in_use", "rotator_password_in_use")
"""The URL in use, registered each time it changes, before any client is built with it."""


class RotatorStateError(RuntimeError):
    """The requested rotator action does not apply (no key to store a UI value, nothing to revert)."""


class RotatorUrlError(ValueError):
    """A gateway URL that does not parse. Its message describes the expected shape and never quotes the value (the
    URL carries the provider password), so the admin API can show it as the 422 `invalid_url` field message."""


@dataclass(frozen=True, slots=True)
class ProxyEndpoint:
    """A parsed gateway URL. `render` builds the URL for one session user name."""

    scheme: str
    username: str
    password: str
    host: str
    port: int

    def render(self, username: str | None = None) -> str:
        user = self.username if username is None else username
        host = f"[{self.host}]" if ":" in self.host else self.host
        if not user and not self.password:
            return f"{self.scheme}://{host}:{self.port}"
        return f"{self.scheme}://{quote(user, safe='')}:{quote(self.password, safe='')}@{host}:{self.port}"


def parse_proxy_url(url: str) -> ProxyEndpoint:
    """Parse and validate a gateway URL (scheme, host and port required, no path). Raises `RotatorUrlError`."""
    text = url.strip()
    if not text or len(text) > MAX_URL_LENGTH or any(ch in text for ch in "\r\n\t "):
        raise RotatorUrlError("the rotator URL must be one line without spaces")
    parts = urlsplit(text)
    if parts.scheme not in _PROXY_SCHEMES:
        raise RotatorUrlError("the rotator URL must start with http://, https:// or socks5://")
    try:
        port = parts.port
    except ValueError as exc:
        raise RotatorUrlError("the rotator URL has an invalid port") from exc
    if not parts.hostname or port is None:
        raise RotatorUrlError("the rotator URL needs a host and a port")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise RotatorUrlError("the rotator URL must not have a path or query")
    return ProxyEndpoint(
        scheme=parts.scheme,
        username=unquote(parts.username or ""),
        password=unquote(parts.password or ""),
        host=parts.hostname,
        port=port,
    )


def _read_bootstrap_url(credentials_dir: Path | None) -> str | None:
    if credentials_dir is None:
        return None
    path = Path(credentials_dir) / URL_FILE_NAME
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_URL_FILE_BYTES)
    except FileNotFoundError:
        return None
    except OSError as exc:
        log.error("rotator_bootstrap_unreadable", extra={"fields": {"error": type(exc).__name__}})
        return None
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.strip():
            return line.strip()
    return None


def mask_ip(ip: str) -> str:
    """An exit IP masked for display: IPv4 to its /24, IPv6 to its /48 (plan 4.2 row 32, privacy)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "n/a"
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def parse_exit_ip(body: bytes) -> tuple[str, str]:
    """`(ip, error)` from an IP echo answer: JSON `{"ip": ...}` or the raw text (v1), every shape checked (B11)."""
    text = body.decode("utf-8", "replace").strip()
    try:
        data = json.loads(text)
    except ValueError:
        candidate = text
    else:
        if not isinstance(data, dict):
            return "", "IP-echo returned JSON without an ip field"
        value = data.get("ip")
        if not isinstance(value, str) or not value.strip():
            return "", "IP-echo response had no IP"
        candidate = value.strip()
    if not candidate:
        return "", "IP-echo response had no IP"
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return "", "IP-echo response was not an IP address"
    return candidate[:64], ""


class _Closable(Protocol):
    async def aclose(self) -> None: ...


RotatorClientFactory = Callable[[str, str, bool], Any]
"""`(proxy_url, session_id, keepalive) -> client` with an async `aclose()` (built by `clients.py`)."""

Sender = Callable[[OutboundRequest], Awaitable[EgressResponse]]


@dataclass(slots=True)
class _Session:
    session_id: str
    client: Any
    created: float
    url_version: int
    inflight: int = 0
    retired: bool = False


@dataclass(frozen=True, slots=True)
class RotatorLease:
    """One request's use of a session client; give it back with `release`."""

    session_id: str
    client: Any
    key: str


@dataclass(frozen=True, slots=True)
class ExitIpProbe:
    """The exit IP check result (v1 `probe_rotation` fields plus timing)."""

    configured: bool
    enabled: bool
    exit_ip: str
    error: str
    latency_ms: float | None
    session_id: str | None
    at: int


@dataclass(frozen=True, slots=True)
class RotatorUsage:
    """The rotator budget as of the last refresh (Egress page KPIs, H-ROTATOR-QUOTA)."""

    cycle_start: int
    cycle_bytes: int
    day_bytes: int
    quota_bytes: int
    hard_stop_bytes: int
    daily_cap_bytes: int
    pct_of_quota: float | None
    stopped: bool
    stop_reason: str | None


def _setting(settings: Any, key: str, default: Any) -> Any:
    try:
        return settings.get(key)
    except (KeyError, LookupError, AttributeError):
        return default


def cycle_start_for(now_s: float, billing_day: int) -> int:
    """The UTC start (00:00) of the billing cycle that contains `now_s`."""
    day = min(max(int(billing_day), 1), 28)
    now = dt.datetime.fromtimestamp(now_s, tz=dt.UTC)
    start = now.replace(day=day, hour=0, minute=0, second=0, microsecond=0)
    if now.day < day:
        start = (start.replace(day=1) - dt.timedelta(days=1)).replace(day=day)
    return int(start.timestamp())


def day_start_for(now_s: float) -> int:
    return int(now_s // 86_400) * 86_400


def usage_since(conn: sqlite3.Connection, egress: str, start_s: int) -> int:
    """Bytes in metrics.db `egress_usage` for `egress` since `start_s`, using the finest rows that still exist.

    Minute rows are used where they exist; hour rows only for whole hours before the oldest minute row; day rows
    only for whole days before the oldest hour row. The leader compacts and prunes oldest first, so this counts
    every byte once (to within the one partly covered hour or day at a boundary, which is an estimate anyway).
    """
    total = 0
    boundary: int | None = None
    for granularity, span in (("minute", 60), ("hour", 3600), ("day", 86_400)):
        sql = (
            "SELECT coalesce(sum(req_bytes + resp_bytes + overhead_bytes), 0), min(bucket_start) FROM egress_usage "
            "WHERE egress = ? AND granularity = ? AND bucket_start >= ?"
        )
        params: tuple[Any, ...] = (egress, granularity, start_s)
        if boundary is not None:
            sql += " AND bucket_start + ? <= ?"
            params += (span, boundary)
        row = conn.execute(sql, params).fetchone()
        total += int(row[0] or 0)
        if row[1] is not None:
            boundary = int(row[1]) if boundary is None else min(boundary, int(row[1]))
    return total


class RotatorPool:
    """DataImpulse sessions and budget (see the module docstring)."""

    def __init__(
        self,
        *,
        credentials_dir: Path | None,
        dbs: Databases,
        settings: Any,
        clock: Clock,
        echo_url: str,
        encryption_key: bytes | None,
        client_factory: RotatorClientFactory,
        events: EventSink,
        override_proxy: str | None = None,
    ) -> None:
        self._credentials_dir = credentials_dir
        self._dbs = dbs
        self._settings = settings
        self._clock = clock
        self.echo_url = echo_url
        self._key = encryption_key
        self._fp_key = (
            derive_key(encryption_key, FINGERPRINT_LABEL)
            if encryption_key is not None
            else hashlib.sha256(FINGERPRINT_LABEL + b" without an encryption key").digest()
        )
        self._factory = client_factory
        self._events = events
        self._override_proxy = override_proxy
        self._sender: Sender | None = None
        self._bootstrap_url: str | None = None
        self._ui_url: str | None = None
        self._url: str | None = None
        self._endpoint: ProxyEndpoint | None = None
        self._url_problem: str | None = None
        self._url_version = 0
        self._version = -1
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._retired: dict[int, _Session] = {}  # retired clients still serving a request, by id(client)
        self._shared: _Session | None = None
        self._current: str | None = None
        self._current_created = 0.0
        self._park_until_ms = 0
        self._streak = 0
        self._recent: deque[dict[str, Any]] = deque(maxlen=50)
        self._db_cycle_bytes = 0
        self._db_day_bytes = 0
        self._pending = 0
        self._kept: dict[str, tuple[int, int]] = {"day": (0, 0), "cycle": (0, 0)}
        self._usage_read_at = -1e18
        self._usage_cycle_start = 0
        self._alerted: set[str] = set()
        self._degraded = False
        self._closing: set[asyncio.Task[None]] = set()

    # --- settings -------------------------------------------------------------------------------------------------

    def _get(self, key: str, default: Any) -> Any:
        return _setting(self._settings, key, default)

    def set_sender(self, sender: Sender) -> None:
        """Install the function the exit IP probe sends through (EgressClients' rotator path)."""
        self._sender = sender

    # --- loading --------------------------------------------------------------------------------------------------

    async def start(self) -> None:
        """Read the bootstrap URL once and load the current state."""
        self._bootstrap_url = await asyncio.to_thread(_read_bootstrap_url, self._credentials_dir)
        if self._bootstrap_url:
            self._register(self._bootstrap_url, BOOTSTRAP_SECRET_NAMES)
        await self.refresh(force=True)

    @staticmethod
    def _register(url: str, names: tuple[str, str] = OFFERED_SECRET_NAMES) -> None:
        """Register `url` and its password under `names` (one of the role pairs above)."""
        url_name, password_name = names
        SecretRegistry.register(url_name, url)
        with contextlib.suppress(ValueError):
            endpoint = parse_proxy_url(url)
            if endpoint.password:
                SecretRegistry.register(password_name, endpoint.password)

    def _read_control(self, conn: sqlite3.Connection, known: int, force: bool) -> tuple[int, Any]:
        version = read_version(conn, VERSION_KEY)
        store: Any = None
        if force or version != known:
            row = conn.execute("SELECT ciphertext, nonce FROM rotator_store WHERE id = 1").fetchone()
            store = ("row", bytes(row[0]), bytes(row[1])) if row is not None else ("none",)
        return version, store

    @staticmethod
    def _read_hot(conn: sqlite3.Connection) -> tuple[int, int]:
        park = conn.execute("SELECT until_ms FROM cooldown WHERE key = ?", (PARK_KEY,)).fetchone()
        streak = conn.execute("SELECT failures FROM breaker WHERE key = ?", (STREAK_KEY,)).fetchone()
        return (int(park[0]) if park else 0), (int(streak[0]) if streak else 0)

    async def refresh(self, *, force: bool = False) -> bool:
        """Re-read the URL version (and the URL when it moved), the park state, and every 15 s the usage."""
        known = self._version
        try:
            version, store = await self._dbs.control.read(lambda conn: self._read_control(conn, known, force))
            self._park_until_ms, self._streak = await self._dbs.hot.read(self._read_hot)
        except SharedStateUnavailable as exc:
            if not self._degraded:
                log.warning("rotator_state_unavailable", extra={"fields": {"error": str(exc)[:200]}})
            self._degraded = True
            return False
        self._degraded = False
        if store is not None:
            self._apply_store(store)
        self._version = version
        if force or self._clock.monotonic() - self._usage_read_at >= USAGE_REFRESH_S:
            await self._refresh_usage()
        return True

    def _apply_store(self, store: tuple[Any, ...]) -> None:
        ui_url: str | None = None
        if store[0] == "row":
            if self._key is None:
                self._url_problem = "encryption_key_missing"
            else:
                try:
                    ui_url = unseal(self._key, store[2], store[1], ROTATOR_STORE_AAD).decode("utf-8")
                except (SealError, UnicodeDecodeError):
                    self._url_problem = "ui_value_unreadable"
                else:
                    self._url_problem = None
                    self._register(ui_url)
        else:
            self._url_problem = None
        self._ui_url = ui_url
        chosen = self._override_proxy or ui_url or (None if store[0] == "row" else self._bootstrap_url)
        self._set_url(chosen)

    def _set_url(self, url: str | None) -> None:
        if url == self._url:
            return
        endpoint: ProxyEndpoint | None = None
        if url is not None:
            try:
                endpoint = parse_proxy_url(url)
            except ValueError as exc:
                self._url_problem = "invalid_url"
                log.error("rotator_url_invalid", extra={"fields": {"error": str(exc)[:120]}})
                url = None
            else:
                # Known to every redaction point before any client holds it, whichever source it came from
                # (finding W2H-1: going back to the bootstrap URL left its password unregistered).
                self._register(url, IN_USE_SECRET_NAMES)
        self._url = url
        self._endpoint = endpoint
        self._url_version += 1
        self._current = None
        self._retire_all()

    # --- configuration and availability -------------------------------------------------------------------------

    def configured(self) -> bool:
        """True when a usable gateway URL is loaded."""
        return self._endpoint is not None

    def masked_url(self) -> str:
        """The gateway URL without user name and password (`scheme://host:port`), or empty (parity row 33)."""
        return masked_url(self._url) if self._url else ""

    def url_source(self) -> str | None:
        """`test_override`, `ui`, `bootstrap` or None."""
        if self._url is None:
            return None
        if self._override_proxy and self._url == self._override_proxy:
            return "test_override"
        return "ui" if self._ui_url is not None and self._url == self._ui_url else "bootstrap"

    def effective_mode(self) -> str:
        """The session mode in force: a sticky mode only when a username template is set (plan 8.2)."""
        mode = str(self._get("rotator_session_mode", STICKY_UNTIL_429))
        template = str(self._get("rotator_session_username_template", "") or "")
        if mode not in SESSION_MODES or not template:
            return PER_REQUEST
        return mode

    def park_remaining(self) -> float:
        return max(0.0, (self._park_until_ms - self._clock.now_ms()) / 1000.0)

    def availability(self, *, ignore_switch: bool = False) -> tuple[bool, str, int | None]:
        """`(usable, reason, retry_after_s)`. `ignore_switch` is for admin-triggered probes (plan 8.1): they run
        while the master switch is off, parked or over budget, but never without a URL."""
        if not self.configured():
            return False, self._url_problem or "rotator_not_configured", None
        if ignore_switch:
            return True, "", None
        if not self._get("rotator_enabled", 1):
            return False, "rotator_disabled", None
        parked = self.park_remaining()
        if parked > 0:
            return False, "rotator_parked", max(1, int(parked + 0.999))
        usage = self.usage_snapshot()
        if usage.stopped:
            return False, usage.stop_reason or "rotator_budget", self._seconds_to_reset(usage.stop_reason)
        return True, "", None

    def enabled(self) -> bool:
        """True when the rotator may take traffic now (DESIGN.md 11.4 `enabled()`)."""
        return self.availability()[0]

    def _seconds_to_reset(self, reason: str | None) -> int:
        now = self._clock.now()
        if reason == "rotator_daily_cap":
            return max(1, int(day_start_for(now) + 86_400 - now))
        billing_day = int(self._get("rotator_billing_day", 1))
        start = dt.datetime.fromtimestamp(cycle_start_for(now, billing_day), tz=dt.UTC)
        nxt = (start.replace(day=1) + dt.timedelta(days=32)).replace(day=start.day)
        return max(1, int(nxt.timestamp() - now))

    # --- sessions -----------------------------------------------------------------------------------------------

    @staticmethod
    def new_session_id() -> str:
        """A random session id (10 hex characters; it appears in the proxy user name, never anything secret)."""
        return secrets.token_hex(5)

    def session_for(self, req: object | None = None) -> str:
        """The session a request should use now (a fresh id per request in `per_request` mode)."""
        mode = self.effective_mode()
        if mode == PER_REQUEST:
            return self.new_session_id()
        now = self._clock.monotonic()
        age = now - self._current_created
        if self._current is None or (mode == STICKY and age >= float(self._get("rotator_sticky_seconds", 300))):
            if self._current is not None:
                self._retire(self._current)
            self._current = self.new_session_id()
            self._current_created = now
        return self._current

    def rotate(self, session_id: str | None, reason: str) -> str:
        """Drop `session_id` (for example after a 429 in `sticky_until_429`) and return the next session id."""
        if session_id is not None and session_id == self._current:
            self._current = None
        if session_id is not None:
            self._retire(session_id)
        log.info("rotator_session_rotated", extra={"fields": {"reason": reason[:40]}})
        return self.session_for()

    def proxy_url_for(self, session_id: str) -> str:
        """The proxy URL for one session (the base URL in `per_request` mode)."""
        endpoint = self._endpoint
        if endpoint is None:
            raise RuntimeError("the rotator is not configured")
        if self.effective_mode() == PER_REQUEST:
            return endpoint.render()
        template = str(self._get("rotator_session_username_template", ""))
        country = str(self._get("rotator_country", "") or "")
        username = (
            template.replace("{user}", endpoint.username).replace("{session}", session_id).replace("{country}", country)
        )
        return endpoint.render(username)

    async def acquire(self, session_id: str | None = None) -> RotatorLease:
        """A client for `session_id` (or the current session), created on first use. Pair with `release`."""
        if not self.configured():
            raise RuntimeError("the rotator is not configured")
        if self.effective_mode() == PER_REQUEST:
            shared = self._shared
            if shared is None or shared.url_version != self._url_version or shared.retired:
                shared = _Session(
                    _SHARED, self._factory(self.proxy_url_for(_SHARED), _SHARED, False), 0.0, self._url_version
                )
                self._shared = shared
            shared.inflight += 1
            return RotatorLease(session_id or self.new_session_id(), shared.client, _SHARED)
        sid = session_id or self.session_for()
        entry = self._sessions.get(sid)
        if entry is not None and entry.url_version != self._url_version:
            self._retire(sid)
            entry = None
        if entry is None:
            client = self._factory(self.proxy_url_for(sid), sid, True)
            entry = _Session(sid, client, self._clock.monotonic(), self._url_version)
            self._sessions[sid] = entry
        self._sessions.move_to_end(sid)  # newest last, so the LRU never evicts the session just handed out
        entry.inflight += 1
        limit = max(1, int(self._get("rotator_max_sessions", 16)))
        while len(self._sessions) > limit:
            _, victim = self._sessions.popitem(last=False)
            victim.retired = True
            self._close_if_idle(victim)
        return RotatorLease(sid, entry.client, sid)

    async def release(self, lease: RotatorLease) -> None:
        """Give a session client back; a retired client is closed once its last request is done."""
        entry: _Session | None
        if lease.key == _SHARED:
            entry = self._shared if self._shared is not None and self._shared.client is lease.client else None
        else:
            entry = self._sessions.get(lease.key)
            if entry is not None and entry.client is not lease.client:
                entry = None
        if entry is None:
            entry = self._retired.get(id(lease.client))
        if entry is None:
            return
        entry.inflight = max(0, entry.inflight - 1)
        if entry.retired:
            self._close_if_idle(entry)

    def _retire(self, session_id: str) -> None:
        entry = self._sessions.pop(session_id, None)
        if entry is not None:
            entry.retired = True
            self._close_if_idle(entry)

    def _retire_all(self) -> None:
        for sid in list(self._sessions):
            self._retire(sid)
        if self._shared is not None:
            self._shared.retired = True
            self._close_if_idle(self._shared)
            self._shared = None

    def _close_if_idle(self, entry: _Session) -> None:
        """Close a retired client now, or park it until its in-flight requests finish (then `release` closes it)."""
        if entry.inflight > 0:
            self._retired[id(entry.client)] = entry
            return
        self._retired.pop(id(entry.client), None)
        self._schedule_close(entry.client)

    def _schedule_close(self, client: Any) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no loop (shutdown already over): the client is garbage collected with its sockets
        task = loop.create_task(_close_quietly(client), name="roxy:rotator-client-close")
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    def session_count(self) -> int:
        return len(self._sessions)

    async def aclose(self) -> None:
        """Close every client (shutdown)."""
        clients = [entry.client for entry in self._sessions.values()]
        clients += [entry.client for entry in self._retired.values()]
        if self._shared is not None:
            clients.append(self._shared.client)
        self._sessions.clear()
        self._retired.clear()
        self._shared = None
        for client in clients:
            await _close_quietly(client)
        if self._closing:
            await asyncio.wait(set(self._closing), timeout=5.0)

    # --- health (parity row 31) -----------------------------------------------------------------------------------

    async def record_result(self, ok: bool, kind: str) -> None:
        """Count one rotator outcome: a success resets the fleet-wide streak; a failure extends it and parks the
        rotator for `rotator_cooldown_s` at `rotator_max_failures` (failures: timeout, connect, 429, 5xx)."""
        if ok:
            if self._streak == 0:
                return

            def reset(conn: sqlite3.Connection) -> None:
                conn.execute("UPDATE breaker SET failures = 0 WHERE key = ?", (STREAK_KEY,))

            with contextlib.suppress(SharedStateUnavailable):
                await self._dbs.hot.write(reset)
                self._streak = 0
            return
        limit = max(1, int(self._get("rotator_max_failures", 3)))
        park_s = float(self._get("rotator_cooldown_s", 60))
        now_ms = self._clock.now_ms()

        def fail(conn: sqlite3.Connection) -> tuple[int, int]:
            row = conn.execute("SELECT failures FROM breaker WHERE key = ?", (STREAK_KEY,)).fetchone()
            failures = (int(row[0]) if row else 0) + 1
            until = 0
            if failures >= limit:
                until = now_ms + int(park_s * 1000)
                conn.execute(
                    "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, 'breaker', ?, 1) "
                    "ON CONFLICT(key) DO UPDATE SET until_ms = max(cooldown.until_ms, excluded.until_ms), "
                    "source = 'breaker', set_at = excluded.set_at, hits = cooldown.hits + 1",
                    (PARK_KEY, until, now_ms // 1000),
                )
                failures = 0
            conn.execute(
                "INSERT INTO breaker (key, state, failures, window_start) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET state = excluded.state, failures = excluded.failures, "
                "window_start = excluded.window_start",
                (STREAK_KEY, "open" if until else "closed", failures, now_ms // 1000),
            )
            return failures, until

        try:
            self._streak, until = await self._dbs.hot.write(fail)
        except SharedStateUnavailable:
            self._streak += 1
            until = now_ms + int(park_s * 1000) if self._streak >= limit else 0
            if until:
                self._streak = 0
        if until:
            self._park_until_ms = max(self._park_until_ms, until)
            log.warning("rotator_parked", extra={"fields": {"seconds": park_s, "last_failure": kind[:40]}})
            self._events.event("rotator_parked", "warn", "egress_disabled", {"seconds": park_s, "kind": kind[:40]})

    # --- usage and budget (plan 8.4) -----------------------------------------------------------------------------

    def on_usage(self, usage: EgressUsage, handed_off: bool) -> None:
        """Accounting listener: count rotator bytes at once, so a worker stops at the cap without a flush."""
        if usage.egress is not Egress.ROTATOR:
            return
        size = usage.total_bytes
        if handed_off:
            self._pending += size  # becomes visible in metrics.db after the recorder flushes
            return
        now = self._clock.now()
        for name, start in (("day", day_start_for(now)), ("cycle", self._cycle_start(now))):
            kept_start, kept = self._kept[name]
            self._kept[name] = (start, (kept if kept_start == start else 0) + size)

    def _cycle_start(self, now: float) -> int:
        return cycle_start_for(now, int(self._get("rotator_billing_day", 1)))

    async def _refresh_usage(self) -> None:
        now = self._clock.now()
        cycle = self._cycle_start(now)
        day = day_start_for(now)
        pending = self._pending

        def read(conn: sqlite3.Connection) -> tuple[int, int]:
            return usage_since(conn, Egress.ROTATOR.value, cycle), usage_since(conn, Egress.ROTATOR.value, day)

        try:
            self._db_cycle_bytes, self._db_day_bytes = await self._dbs.metrics.read(read)
        except (SharedStateUnavailable, sqlite3.Error) as exc:
            # Metrics may degrade open (C7): keep the last numbers plus this worker's own count.
            log.warning("rotator_usage_unavailable", extra={"fields": {"error": str(exc)[:200]}})
            return
        self._pending = max(0, self._pending - pending)
        self._usage_read_at = self._clock.monotonic()
        self._usage_cycle_start = cycle
        self._check_budget_alerts()

    def usage_snapshot(self) -> RotatorUsage:
        """The rotator budget now (DESIGN.md 11.4 "usage snapshot")."""
        now = self._clock.now()
        cycle = self._cycle_start(now)
        day = day_start_for(now)
        kept_day = self._kept["day"][1] if self._kept["day"][0] == day else 0
        kept_cycle = self._kept["cycle"][1] if self._kept["cycle"][0] == cycle else 0
        cycle_db = self._db_cycle_bytes if self._usage_cycle_start == cycle else 0
        cycle_bytes = cycle_db + self._pending + kept_cycle
        day_bytes = self._db_day_bytes + self._pending + kept_day
        quota = int(float(self._get("rotator_quota_gb_per_month", 0)) * DECIMAL_GB)
        stop_pct = float(self._get("rotator_hard_stop_pct", 100))
        hard_stop = int(quota * stop_pct / 100) if quota > 0 and stop_pct > 0 else 0
        cap = int(float(self._get("rotator_daily_cap_mb", 0)) * DECIMAL_MB)
        reason: str | None = None
        if hard_stop and cycle_bytes >= hard_stop:
            reason = "rotator_quota_hard_stop"
        elif cap and day_bytes >= cap:
            reason = "rotator_daily_cap"
        return RotatorUsage(
            cycle_start=cycle,
            cycle_bytes=cycle_bytes,
            day_bytes=day_bytes,
            quota_bytes=quota,
            hard_stop_bytes=hard_stop,
            daily_cap_bytes=cap,
            pct_of_quota=round(cycle_bytes * 100.0 / quota, 2) if quota > 0 else None,
            stopped=reason is not None,
            stop_reason=reason,
        )

    def _check_budget_alerts(self) -> None:
        usage = self.usage_snapshot()
        if usage.pct_of_quota is None:
            return
        thresholds = sorted({int(p) for p in self._get("rotator_budget_alert_pcts", (50, 80, 95))})
        for pct in thresholds:
            key = f"quota:{pct}:{usage.cycle_start}"
            if usage.pct_of_quota >= pct and key not in self._alerted:
                self._alerted.add(key)
                self._events.alert(
                    type="rotator_quota",
                    severity="critical" if pct >= 95 else "warn",
                    subject=f"Roxy: rotator at {pct}% of monthly quota",
                    summary=f"Rotator usage this cycle is {usage.pct_of_quota}% of the monthly quota.",
                    fields={"used_bytes": usage.cycle_bytes, "quota_bytes": usage.quota_bytes, "page": "egress#budget"},
                    cooldown_key=key,
                    cooldown_s=40 * 86_400,
                )
        if len(self._alerted) > 64:
            self._alerted = {key for key in self._alerted if key.endswith(f":{usage.cycle_start}")}

    # --- exit IPs (parity row 32) ----------------------------------------------------------------------------------

    async def exit_ip_probe(self, session_id: str | None = None) -> ExitIpProbe:
        """Ask the IP echo service through the rotator which exit IP a session uses (admin probes, health)."""
        now = int(self._clock.now())
        enabled = self.enabled()
        if not self.configured():
            return ExitIpProbe(False, enabled, "", "Rotation proxy is not configured.", None, None, now)
        if self._sender is None:
            return ExitIpProbe(True, enabled, "", "no sender installed", None, None, now)
        sid = session_id or self.session_for()
        timeout_s = float(self._get("rotator_probe_timeout_s", 10))
        out = OutboundRequest(
            method="GET",
            url=self.echo_url,
            headers={"Accept": "application/json"},
            content=None,
            timeout=httpx.Timeout(timeout_s),
            purpose=PURPOSE_EXIT_IP_PROBE,
            session_id=sid,
            follow_redirects=False,
        )
        started = time.monotonic()
        ip, error = "", ""
        try:
            response = await self._sender(out)
        except EgressError as exc:
            error = f"{type(exc).__name__}: {exc.detail}"[:200]
        else:
            if response.status != 200:
                error = f"IP-echo returned HTTP {response.status}"
            else:
                ip, error = parse_exit_ip(response.body)
        latency = round((time.monotonic() - started) * 1000, 1)
        if ip:
            self._remember_ip(ip, sid, now)
        return ExitIpProbe(True, enabled, ip, error, latency, sid, now)

    def _remember_ip(self, ip: str, session_id: str | None, at: int) -> None:
        size = max(0, int(self._get("rotator_recent_ips", 50)))
        if self._recent.maxlen != size:
            self._recent = deque(list(self._recent)[-size:] if size else [], maxlen=size)
        if size:
            self._recent.append({"ip": ip, "at": at, "source": "probe", "session_id": session_id})

    def recent_exit_ips(self, *, masked: bool = True) -> list[dict[str, Any]]:
        """Recent exit IPs, newest first; masked to /24 (IPv6 /48) unless `masked=False` (reveal on click)."""
        items = list(reversed(self._recent))
        if not masked:
            return [dict(item) for item in items]
        return [{**item, "ip": mask_ip(str(item["ip"]))} for item in items]

    # --- admin actions (parity row 30) -----------------------------------------------------------------------------

    def _summary(self, url: str | None) -> dict[str, str] | None:
        return secret_summary(url, self._fp_key, url=True) if url else None

    async def replace_url(
        self, url: str, actor: Actor, *, reason: str | None = None, request_id: str | None = None
    ) -> None:
        """Store a new gateway URL from the Egress page (encrypted; wins over the bootstrap value)."""
        parse_proxy_url(url)
        text = url.strip()
        if self._key is None:
            raise RotatorStateError("credential_encryption_key is not configured, so a UI value cannot be stored")
        nonce, ciphertext = seal(self._key, text.encode("utf-8"), ROTATOR_STORE_AAD)
        before = self._summary(self._ui_url or self._bootstrap_url)
        after = self._summary(text)
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO rotator_store (id, ciphertext, nonce, set_at, set_by, masked_host) "
                "VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET ciphertext = excluded.ciphertext, "
                "nonce = excluded.nonce, set_at = excluded.set_at, set_by = excluded.set_by, "
                "masked_host = excluded.masked_host",
                (ciphertext, nonce, now, actor.label, masked_url(text)[:200]),
            )
            audit.record(conn, actor, "rotator.replace_url", "rotator_url", before, after, reason, request_id, at=now)
            bump_version(conn, VERSION_KEY, now)

        self._register(text)
        await self._dbs.control.write(write)
        await self.refresh(force=True)

    async def revert_to_bootstrap(
        self, actor: Actor, *, reason: str | None = None, request_id: str | None = None
    ) -> None:
        """Delete the UI-set URL so the bootstrap credential is used again (restart needed to re-read the file).

        The bootstrap URL is registered as a secret again BEFORE the audit row is written, so a reason that repeats
        its password is redacted however many URLs were tried since this worker started (finding W2H-1).
        """
        before = self._summary(self._ui_url)
        after = self._summary(self._bootstrap_url)
        now = int(self._clock.now())
        if self._bootstrap_url:
            self._register(self._bootstrap_url, BOOTSTRAP_SECRET_NAMES)

        def write(conn: sqlite3.Connection) -> None:
            if conn.execute("SELECT 1 FROM rotator_store WHERE id = 1").fetchone() is None:
                raise RotatorStateError("there is no UI-set rotator URL to remove")
            conn.execute("DELETE FROM rotator_store WHERE id = 1")
            audit.record(
                conn, actor, "rotator.revert_to_bootstrap", "rotator_url", before, after, reason, request_id, at=now
            )
            bump_version(conn, VERSION_KEY, now)

        await self._dbs.control.write(write)
        await self.refresh(force=True)


async def _close_quietly(client: _Closable) -> None:
    try:
        await client.aclose()
    except Exception:
        log.warning("rotator_client_close_failed")


__all__ = [
    "BOOTSTRAP_SECRET_NAMES",
    "IN_USE_SECRET_NAMES",
    "OFFERED_SECRET_NAMES",
    "PER_REQUEST",
    "STICKY",
    "STICKY_UNTIL_429",
    "ExitIpProbe",
    "ProxyEndpoint",
    "RotatorLease",
    "RotatorPool",
    "RotatorStateError",
    "RotatorUrlError",
    "RotatorUsage",
    "cycle_start_for",
    "mask_ip",
    "parse_exit_ip",
    "parse_proxy_url",
    "usage_since",
]
