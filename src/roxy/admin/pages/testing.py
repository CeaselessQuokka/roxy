"""Test harness for the dashboard pages (P11): hostile caller text, seeding, an HTML reader and a live server.

What this is
    Helpers the page tests share (`tests/integration/pages/conftest.py` and `tests/e2e/conftest.py` import them);
    production code never imports this module.
      * `HOSTILE` and `assert_inert(html)`: the hostile caller text set (XSS payloads, a `javascript:` URL, very long
        values, unicode with a right-to-left override, template braces) and the check that a rendered page shows it
        as inert text only.
      * `parse_html(text)` and `Node.select(css)`: a small HTML reader with CSS selectors (tag, `#id`, `.class`,
        `[attr]`, `[attr=value]`, `[attr~=value]`, descendant combinators), so integration tests can ask "is
        `[data-table=audit_log]` inside `#log`" without a browser.
      * Seeding through the real code paths: `traffic_plan()` (served, cached, refused, probed, Roblox 429, several
        IPs, places and User-Agents, hostile text) for the real proxy; `seed_audit(ctx, clock)` (settings changes
        through `SettingsService` with hostile reasons, plus audit rows with hostile targets and documents);
        `seed_recommendation(ctx, clock)` (the engine's own writer); `seed_health_run(ctx, clock)` (the health
        store's writers; a real run would resolve real DNS names, which tests must never do).
      * `RobloxMock`: a loopback HTTP server playing every Roblox host (the egress test override
        `ROXY_TEST_UPSTREAM_BASE` sends Roxy's calls to it), answering JSON, a 429 on `/too-many` paths and 503 on
        `/fail` paths, with hostile names in its JSON.
      * `DashboardServer.start(...)`: the real app (`create_app` with its lifespan) on a FREE loopback port in a
        thread, its own temporary state, a fast password hasher, an admin signed in through the real password and
        TOTP steps (`login()` returns the session cookie), and the seeded data. Seven page builders run their tests
        at the same time, so nothing here uses a fixed port or a shared directory.

Why it exists
    Plan 19.2 and the P11 test rules: every page is tested against the real app, the real guards and the real read
    models, with data that went through the real proxy, and every page must render caller text as inert text. One
    harness keeps seven builders' tests consistent and short.

How it works
    `DashboardServer` binds a socket to 127.0.0.1:0 first (so the port is known before the app is built: the site
    origin, which the CSRF checks compare, must name it), builds `EnvSettings` with explicit values only (no
    environment variable leaks in), sets the egress override just while the app starts, and runs uvicorn on its own
    event loop in a daemon thread. Coroutines that must run on the app's loop (flushing the recorder, seeding) go
    through `run(coro)`. `OffsetClock` is the real clock plus an offset the harness can advance (each TOTP code
    needs a new 30 second step). A process-wide loopback guard refuses any connection that would leave the machine
    while the server runs (plan 19.12).

What to read next
    `tests/e2e/conftest.py` (the browser fixtures), `tests/integration/pages/conftest.py`, `.remake/P11_CONTRACT.md`.
"""

from __future__ import annotations

import asyncio
import html as html_lib
import ipaddress
import json
import re
import secrets
import socket
import tempfile
import threading
import time
from collections.abc import Callable, Coroutine, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Final, Literal

# ============================================================================================ hostile caller text

HOSTILE: Final[dict[str, str]] = {
    "img": "<img src=x onerror=alert(1)>",
    "script": "<script>alert('roxy')</script>",
    "js_url": "javascript:alert(document.cookie)",
    "attr": '" autofocus onfocus="alert(1)',
    "long": "L" * 5000,
    "unicode": "Unicode üñï ‮evil‬ \U0001f98a 漢字",
    "jinja": "{{ 7*7 }} {% raw %}",
}
"""Text a caller (or an admin) may send: every page must show it as inert text."""

RAW_MARKERS: Final[tuple[str, ...]] = (
    "<img src=x onerror",
    "<script>alert",
    'onfocus="alert(1)',
)
"""What must never appear unescaped in a rendered page."""

_LINK_ATTR = re.compile(r"""\b(?:href|src|action|formaction|xlink:href)\s*=\s*["']?\s*javascript:""", re.IGNORECASE)


def assert_inert(html: str, where: str = "page") -> None:
    """Fail when hostile text reached the page as markup: an unescaped tag, a live handler, a `javascript:` link."""
    for marker in RAW_MARKERS:
        assert marker not in html, f"{where} contains unescaped hostile text {marker!r}"
    assert not _LINK_ATTR.search(html), f"{where} has a javascript: URL in a link or source attribute"


# ============================================================================================ a small HTML reader

_VOID: Final = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
)


@dataclass(eq=False)
class Node:
    """One element of a parsed page: tag, attributes, children and text."""

    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[Node] = field(default_factory=list)
    parent: Node | None = None
    texts: list[str] = field(default_factory=list)
    flow: list[Node | str] = field(default_factory=list)
    """Text and child elements in document order (what `text()` reads)."""

    def iter(self) -> Iterator[Node]:
        for child in self.children:
            yield child
            yield from child.iter()

    def text(self) -> str:
        """All text inside this element, whitespace collapsed."""
        parts: list[str] = []

        def walk(node: Node) -> None:
            for item in node.flow:
                if isinstance(item, str):
                    parts.append(item)
                else:
                    walk(item)

        walk(self)
        return " ".join(" ".join(parts).split())

    def get(self, name: str, default: str | None = None) -> str | None:
        return self.attrs.get(name, default)

    @property
    def id(self) -> str | None:
        return self.attrs.get("id")

    def classes(self) -> set[str]:
        return set((self.attrs.get("class") or "").split())

    def select(self, css: str) -> list[Node]:
        """Elements below this one matching `css` (comma-separated selectors, descendant combinators)."""
        found: list[Node] = []
        for part in css.split(","):
            steps = [_parse_compound(s) for s in part.split()]
            if not steps:
                continue
            for node in self.iter():
                if node not in found and _matches(node, steps[-1]) and _ancestors_match(node, steps[:-1], self):
                    found.append(node)
        return found

    def select_one(self, css: str) -> Node | None:
        found = self.select(css)
        return found[0] if found else None

    def ids(self) -> list[str]:
        return [node.attrs["id"] for node in self.iter() if "id" in node.attrs]


_COMPOUND = re.compile(r"([a-zA-Z][a-zA-Z0-9-]*)|#([\w-]+)|\.([\w-]+)|\[([\w:-]+)(?:([~*^]?=)\"?([^\"\]]*)\"?)?\]")


def _parse_compound(text: str) -> list[tuple[str, str, str, str]]:
    parts: list[tuple[str, str, str, str]] = []
    position = 0
    for match in _COMPOUND.finditer(text):
        if match.start() != position:
            raise ValueError(f"unsupported selector {text!r}")
        position = match.end()
        tag, ident, cls, attr, op, value = match.groups()
        if tag:
            parts.append(("tag", tag.lower(), "", ""))
        elif ident:
            parts.append(("id", ident, "", ""))
        elif cls:
            parts.append(("class", cls, "", ""))
        else:
            parts.append(("attr", attr, op or "", value or ""))
    if position != len(text):
        raise ValueError(f"unsupported selector {text!r}")
    return parts


def _matches(node: Node, compound: list[tuple[str, str, str, str]]) -> bool:
    for kind, name, op, value in compound:
        if kind == "tag" and node.tag != name:
            return False
        if kind == "id" and node.attrs.get("id") != name:
            return False
        if kind == "class" and name not in node.classes():
            return False
        if kind == "attr":
            if name not in node.attrs:
                return False
            actual = node.attrs[name]
            if op == "=" and actual != value:
                return False
            if op == "~=" and value not in actual.split():
                return False
            if op == "*=" and value not in actual:
                return False
            if op == "^=" and not actual.startswith(value):
                return False
    return True


def _ancestors_match(node: Node, steps: list[list[tuple[str, str, str, str]]], root: Node) -> bool:
    current = node.parent
    remaining = list(steps)
    while remaining:
        while current is not None and current is not root.parent and not _matches(current, remaining[-1]):
            current = current.parent
        if current is None or current is root.parent:
            return False
        remaining.pop()
        current = current.parent
    return True


class _Builder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("#document")
        self.current = self.root

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = Node(
            tag.lower(), {name: (value if value is not None else "") for name, value in attrs}, parent=self.current
        )
        self.current.children.append(node)
        self.current.flow.append(node)
        if node.tag not in _VOID:
            self.current = node

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = Node(
            tag.lower(), {name: (value if value is not None else "") for name, value in attrs}, parent=self.current
        )
        self.current.children.append(node)
        self.current.flow.append(node)

    def handle_endtag(self, tag: str) -> None:
        name = tag.lower()
        walker: Node | None = self.current
        while walker is not None and walker.tag != name:
            walker = walker.parent
        if walker is not None and walker.parent is not None:
            self.current = walker.parent

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.current.texts.append(data)
            self.current.flow.append(data)


def parse_html(text: str) -> Node:
    """Parse a page or fragment into a `Node` tree (the document root)."""
    builder = _Builder()
    builder.feed(text)
    builder.close()
    return builder.root


def unescape(text: str) -> str:
    return html_lib.unescape(text)


# ============================================================================================ clocks


class OffsetClock:
    """The real clock plus an offset tests can move forward (a TOTP code needs a new 30 s step each time)."""

    def __init__(self) -> None:
        self.offset = 0.0

    def now(self) -> float:
        return time.time() + self.offset

    def now_ms(self) -> int:
        return int(self.now() * 1000)

    def monotonic(self) -> float:
        return time.monotonic() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


# ============================================================================================ seeding

DOC_NETS: Final[tuple[str, ...]] = ("203.0.113", "198.51.100", "192.0.2")
"""Documentation address ranges (RFC 5737): never real clients."""

PLACES: Final[tuple[str, ...]] = ("1818", "920587237", "606849621")
"""Made-up place ids (Roblox-Id header values)."""

VIEWPORTS: Final[dict[str, tuple[int, int]]] = {"desktop": (1440, 900), "phone": (390, 844)}
"""The sizes every dashboard page is checked at in a browser (plan 14.9): a laptop and a phone."""

THEMES: Final[tuple[str, ...]] = ("dark", "light")
"""The themes every dashboard page is checked in."""

SEED_SETTINGS: Final[dict[str, int]] = {
    "tarpit_enabled": 0,
    "rotator_enabled": 0,
    "global_bucket_burst": 100,
    "direct_bucket_burst": 100,
    "host_bucket_default_burst": 100,
    "endpoint_bucket_default_burst": 100,
}
"""Settings every page test runs with: no tarpit and no rotator (no waits, no other egress), and upstream bursts
big enough that the seeding plan never waits in an upstream queue (its throttled client is refused by the per-IP
limit instead; a queued request waits in real time, up to `queue_wait_interactive_ms`)."""


@dataclass(frozen=True, slots=True)
class PlannedRequest:
    """One proxy request of the seeding plan."""

    path: str
    ip: str
    user_agent: str = "Roblox/WinInet"
    place: str | None = None
    method: str = "GET"
    note: str = ""


def traffic_plan() -> list[PlannedRequest]:
    """The seeding plan: served, cached (repeats), refused, probed, a Roblox 429, a Roblox 503, several IPs, places
    and User-Agents, IPv6, and the hostile text set in paths, User-Agents and Roblox-Id headers."""
    plan: list[PlannedRequest] = []
    for _ in range(6):
        plan.append(
            PlannedRequest(
                "/games.roblox.com/v1/games?universeIds=1",
                f"{DOC_NETS[0]}.10",
                place=PLACES[0],
                note="served then cached",
            )
        )
    for i in range(4):
        plan.append(
            PlannedRequest(
                f"/users.roblox.com/v1/users/{100 + i}",
                f"{DOC_NETS[1]}.{20 + i}",
                user_agent="RobloxGameServer/1.0",
                place=PLACES[1],
                note="served",
            )
        )
    plan += [
        PlannedRequest("/thumbnails.roblox.com/v1/too-many?size=48x48", f"{DOC_NETS[2]}.30", note="Roblox 429"),
        PlannedRequest("/catalog.roblox.com/v1/fail/items", f"{DOC_NETS[2]}.31", note="Roblox 503"),
        PlannedRequest("/wp-login.php", f"{DOC_NETS[2]}.40", user_agent="curl/8.0", note="probe: not Roblox"),
        PlannedRequest("/.env", f"{DOC_NETS[2]}.41", user_agent="python-requests/2.31", note="probe"),
        PlannedRequest("/" + HOSTILE["js_url"], f"{DOC_NETS[2]}.42", note="probe with a javascript: URL"),
        PlannedRequest(
            "/games.roblox.com/v1/games/" + HOSTILE["img"] + "/votes",
            f"{DOC_NETS[0]}.50",
            user_agent=HOSTILE["img"],
            place=PLACES[2],
            note="hostile path and User-Agent",
        ),
        PlannedRequest(
            "/games.roblox.com/v1/games?universeIds=2",
            f"{DOC_NETS[0]}.51",
            user_agent=HOSTILE["script"],
            place=HOSTILE["script"],
            note="hostile place",
        ),
        PlannedRequest(
            "/games.roblox.com/v1/games?universeIds=3",
            f"{DOC_NETS[0]}.52",
            user_agent=HOSTILE["long"],
            note="very long User-Agent",
        ),
        PlannedRequest(
            "/games.roblox.com/v1/games?universeIds=4",
            f"{DOC_NETS[0]}.53",
            user_agent=HOSTILE["unicode"],
            note="unicode User-Agent",
        ),
        PlannedRequest(
            "/games.roblox.com/v1/games?universeIds=5",
            "2001:db8::7",
            user_agent=HOSTILE["attr"],
            note="IPv6 and an attribute break",
        ),
    ]
    for i in range(14):  # one client over the per-IP limit (10 per 50 s): throttle refusals
        plan.append(
            PlannedRequest(
                f"/games.roblox.com/v1/games?universeIds={10 + i}",
                f"{DOC_NETS[1]}.99",
                user_agent="LoopBot/0.1",
                note="throttled",
            )
        )
    return plan


def _header_value(text: str) -> str | bytes:
    """A header value as a client sends it: plain ASCII, or the UTF-8 bytes of anything else."""
    return text if text.isascii() else text.encode("utf-8")


def request_headers(item: PlannedRequest) -> dict[str, str | bytes]:
    headers: dict[str, str | bytes] = {
        "User-Agent": _header_value(item.user_agent[:8000]),
        "X-Forwarded-For": item.ip,
    }
    if item.place is not None:
        headers["Roblox-Id"] = _header_value(item.place)
    return headers


def roblox_answer(host: str, path: str) -> tuple[int, dict[str, str], bytes]:
    """What the Roblox stand-in answers for a host and path (status, headers, JSON body)."""
    if "/too-many" in path:
        body = json.dumps({"errors": [{"code": 0, "message": "Too many requests"}]}).encode()
        return 429, {"Content-Type": "application/json", "Retry-After": "5"}, body
    if "/fail" in path:
        return 503, {"Content-Type": "application/json"}, b'{"errors":[{"code":0,"message":"Service unavailable"}]}'
    payload = {
        "data": [
            {
                "id": 1,
                "rootPlaceId": int(PLACES[0]),
                "name": HOSTILE["img"],
                "creator": {"id": 7, "name": HOSTILE["script"], "type": "User"},
                "description": HOSTILE["js_url"],
            }
        ],
        "universeId": 1,
        "host": host,
    }
    return 200, {"Content-Type": "application/json"}, json.dumps(payload).encode()


async def seed_audit(ctx: Any, clock: Any) -> dict[str, Any]:
    """Audit rows with hostile text: settings changes through the real `SettingsService` (hostile reasons; one
    revertible change), and rows written by `config.audit.record` with hostile targets and documents (the targets
    of a rule or a ban carry caller-chosen patterns in production)."""
    from roxy.config import audit
    from roxy.config.audit import Actor
    from roxy.config.settings_service import SettingsService

    service = SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=clock)
    admin = Actor("admin", "owner", "203.0.113.200")
    await service.update({"cache_ttl_seconds": 150}, admin, "Raise the cache lifetime " + HOSTILE["img"], "admin")
    await service.update({"cache_ttl_seconds": 180}, admin, "Again " + HOSTILE["js_url"], "admin")
    await service.update(
        {"pause_message_default": "Back soon, after maintenance."}, admin, HOSTILE["long"][:400], "admin"
    )
    await ctx.settings.reload()
    now = int(clock.now())

    def write(conn: Any) -> list[int]:
        ids = [
            audit.record(
                conn,
                admin,
                "rule.create",
                "rules_endpoint_block:" + HOSTILE["img"],
                None,
                {"pattern": HOSTILE["img"], "note": HOSTILE["script"], "message": HOSTILE["js_url"]},
                HOSTILE["attr"],
                "SEEDAUDIT0000000000000001",
                at=now - 120,
            ),
            audit.record(
                conn,
                Actor("system", "spam-detector", None),
                "ban.create",
                "bans:" + HOSTILE["js_url"],
                None,
                {"subject": HOSTILE["unicode"], "reason": HOSTILE["jinja"]},
                None,
                None,
                at=now - 60,
            ),
            audit.record(
                conn,
                admin,
                "export.download",
                "table:audit_log",
                None,
                {"format": "csv", "rows": 12, "bytes": 2048, "ip_addresses": "hashed"},
                None,
                None,
                at=now - 30,
            ),
        ]
        return ids

    ids = await ctx.dbs.control.write(write)
    return {"record_ids": ids}


async def seed_recommendation(ctx: Any, clock: Any, *, severity: str = "critical") -> str:
    """One open recommendation with hostile text in its subject, title and explanation (the engine's writer)."""
    from roxy.config.insight_params import INSIGHT_RULES
    from roxy.core.ids import new_id
    from roxy.insights import simulate
    from roxy.insights.engine import write_recommendation
    from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint

    now = clock.now()
    rule_id = "UP-429-ENDPOINT"
    spec = INSIGHT_RULES[rule_id]
    subject = "games.roblox.com/v1/games/" + HOSTILE["img"]
    rec = Recommendation(
        rule_id=rule_id,
        family=spec.family,
        subject=subject,
        title="Roblox refuses " + HOSTILE["script"],
        severity=severity,
        confidence="high",
        explanation="Plain words " + HOSTILE["js_url"],
        evidence=Evidence(window_from=now - 3600, window_to=now, sample_size=50).add("roblox_429", 50, "responses"),
        changes=[ProposedChange("setting", key="cache_ttl_seconds", current=180, proposed=300)],
        expected_impact="Fewer calls " + HOSTILE["unicode"],
        risk="low",
    )
    rec.id = new_id("rec", clock)
    rec.fingerprint = make_fingerprint(rule_id, subject)
    rec.computed_severity = severity
    rec.state = "open"
    rec.created_at = rec.updated_at = now
    rec.expires_at = now + 7 * 86_400
    rec.dry_run_available = simulate.can_simulate(rec)
    await ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    return str(rec.id)


async def seed_health_run(ctx: Any, clock: Any) -> int:
    """One finished health run with a pass, a warn and a fail (the health store's writers; never a real run)."""
    from roxy import __version__
    from roxy.health import store
    from roxy.health.model import CheckResult, Status

    now = int(clock.now())
    results = [
        CheckResult("H-DB-INTEGRITY", Status.PASS, "ok", "ok", "Every database passed its quick check.", ""),
        CheckResult(
            "H-CACHE-HIT", Status.WARN, "41%", "60%", "The hit ratio is low " + HOSTILE["img"], "/admin/cache#settings"
        ),
        CheckResult(
            "H-REACH", Status.FAIL, "timeout", "200", "games.roblox.com did not answer.", "/admin/upstream#health"
        ),
    ]

    def write(conn: Any) -> int:
        run_id = store.insert_run(
            conn,
            started_at=now - 70,
            trigger="manual",
            version=__version__,
            options={"include_credential": False},
            actor="admin:owner",
            at_ms=(now - 70) * 1000,
            planned=len(results),
        )
        for result in results:
            store.insert_result(conn, run_id, result, at_ms=(now - 60) * 1000)
        store.finish_run(
            conn,
            run_id,
            finished_at=now - 10,
            summary=store.summarize(results),
            at_ms=(now - 10) * 1000,
            trigger="manual",
        )
        return run_id

    run_id: int = await ctx.dbs.metrics.write(write)
    return run_id


# ============================================================================================ loopback guard

_GUARD_LOCK = threading.Lock()
_GUARD_DEPTH = 0
_SAVED: dict[str, Any] = {}


def _loopback(host: Any) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    name = str(host).strip("[]").lower().rstrip(".")
    if name in ("localhost", "localhost.localdomain") or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def install_loopback_guard() -> None:
    """Refuse any connection or name lookup that would leave the machine, process-wide, until removed."""
    global _GUARD_DEPTH
    with _GUARD_LOCK:
        _GUARD_DEPTH += 1
        if _GUARD_DEPTH > 1:
            return
        _SAVED.update(connect=socket.socket.connect, getaddrinfo=socket.getaddrinfo)
        real_connect = _SAVED["connect"]
        real_getaddrinfo = _SAVED["getaddrinfo"]

        def connect(self: socket.socket, address: Any) -> None:
            if self.family != getattr(socket, "AF_UNIX", -1):
                host = address[0] if isinstance(address, tuple) else address
                if not _loopback(host):
                    raise ConnectionRefusedError(f"the dashboard harness refuses a connection to {host!r}")
            real_connect(self, address)

        def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
            if not _loopback(host):
                raise OSError(f"the dashboard harness refuses to resolve {host!r}")
            return real_getaddrinfo(host, *args, **kwargs)

        socket.socket.connect = connect  # type: ignore[method-assign,assignment]
        socket.getaddrinfo = getaddrinfo


def remove_loopback_guard() -> None:
    global _GUARD_DEPTH
    with _GUARD_LOCK:
        _GUARD_DEPTH = max(0, _GUARD_DEPTH - 1)
        if _GUARD_DEPTH == 0 and _SAVED:
            socket.socket.connect = _SAVED.pop("connect")  # type: ignore[method-assign]
            socket.getaddrinfo = _SAVED.pop("getaddrinfo")


# ============================================================================================ servers in threads


class _ThreadServer:
    """uvicorn serving an ASGI app on a socket already bound, on its own event loop in a daemon thread."""

    def __init__(
        self, app: Any, sock: socket.socket, *, lifespan: Literal["auto", "on", "off"] = "on", name: str = "roxy-test"
    ) -> None:
        import uvicorn

        self.loop = asyncio.new_event_loop()
        config = uvicorn.Config(app, lifespan=lifespan, log_level="warning", timeout_graceful_shutdown=1)
        self.server = uvicorn.Server(config)
        self.sock = sock
        self.thread = threading.Thread(target=self._run, name=name, daemon=True)
        self.error: BaseException | None = None

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.server.serve(sockets=[self.sock]))
        except BaseException as exc:  # reported by wait_started
            self.error = exc

    def start(self, timeout_s: float = 60.0) -> None:
        self.thread.start()
        deadline = time.monotonic() + timeout_s
        while not self.server.started:
            if self.error is not None or not self.thread.is_alive():
                raise RuntimeError(f"the test server did not start: {self.error!r}")
            if time.monotonic() > deadline:
                raise RuntimeError("the test server did not start in time")
            time.sleep(0.05)

    def run(self, coro: Coroutine[Any, Any, Any], timeout_s: float = 60.0) -> Any:
        """Run a coroutine on the server's event loop and wait for its result."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout_s)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)


def bound_socket() -> socket.socket:
    """A TCP socket bound to a free loopback port (the OS picks it; never a fixed port)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    sock.setblocking(False)
    return sock


def roblox_mock_app() -> Any:
    """A Starlette app playing every Roblox host (`roblox_answer`), and recording what it was asked."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Route

    calls: list[tuple[str, str, str]] = []

    async def answer(request: Request) -> Response:
        host = request.headers.get("x-roxy-test-host", "")
        path = request.url.path
        if len(calls) < 10_000:
            calls.append((request.method, host, path))
        status, headers, body = roblox_answer(host, path)
        return Response(body, status_code=status, headers=headers)

    app = Starlette(routes=[Route("/{path:path}", answer, methods=["GET", "POST", "HEAD"])])
    app.state.calls = calls
    return app


@dataclass
class RobloxMock:
    """The Roblox stand-in on a free loopback port (see `roblox_answer`)."""

    base_url: str
    app: Any
    server: _ThreadServer

    @classmethod
    def start(cls) -> RobloxMock:
        sock = bound_socket()
        port = sock.getsockname()[1]
        app = roblox_mock_app()
        server = _ThreadServer(app, sock, lifespan="off", name="roblox-mock")
        server.start()
        return cls(base_url=f"http://127.0.0.1:{port}", app=app, server=server)

    @property
    def calls(self) -> list[tuple[str, str, str]]:
        calls: list[tuple[str, str, str]] = self.app.state.calls
        return calls

    def stop(self) -> None:
        self.server.stop()


def make_fake_credentials(directory: Path) -> dict[str, str]:
    """Fake values for every credential the app reads (never real; the mail and webhook ones are left out, so the
    notifier only logs)."""
    from roxy.core.redact import TOKEN_PREFIX  # the public warning text every Roblox cookie starts with

    prefix = TOKEN_PREFIX
    values = {
        "roblox_credential": prefix + "FAKEDASHBOARDCREDENTIAL" + secrets.token_hex(160).upper(),
        "rotator_url": f"http://fakeuser:fake{secrets.token_hex(8)}@127.0.0.1:9",
        "credential_encryption_key": secrets.token_hex(32),
        "totp_encryption_key": secrets.token_hex(32),
        "ip_hash_key": secrets.token_hex(32),
    }
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in values.items():
        path = directory / name
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
    directory.chmod(0o700)
    return values


SESSION_COOKIE_NAME: Final = "__Host-roxy_session"


@dataclass
class SignedIn:
    """An admin signed in through the real password and TOTP steps."""

    username: str
    password: str
    totp_secret: str
    cookie: str
    csrf: str


@dataclass
class DashboardServer:
    """The real app on a free loopback port with its own state, a Roblox stand-in and a signed-in admin."""

    base_url: str
    app: Any
    clock: OffsetClock
    server: _ThreadServer
    roblox: RobloxMock
    state_dir: Path
    admin: Any = None
    signed_in: SignedIn | None = None
    seeded: dict[str, Any] = field(default_factory=dict)
    _last_step: int = 0

    SESSION_COOKIE = SESSION_COOKIE_NAME

    @property
    def ctx(self) -> Any:
        return self.app.state.ctx

    @property
    def origin(self) -> str:
        return self.base_url

    @classmethod
    def start(cls, *, seed: bool = True, settings: Mapping[str, Any] | None = None) -> DashboardServer:
        """Start everything (see the module docstring). `settings` are applied before seeding."""
        import os

        from roxy.admin.auth.testing import fast_hasher
        from roxy.config.env import EnvSettings
        from roxy.egress.targets import TEST_UPSTREAM_ENV
        from roxy.main import create_app

        install_loopback_guard()
        roblox = RobloxMock.start()
        state = Path(tempfile.mkdtemp(prefix="roxy-pages-"))
        (state / "state").mkdir(mode=0o750)
        (state / "state").chmod(0o750)  # like systemd's StateDirectory (the app warns about a looser mode)
        credentials = state / "credentials"
        make_fake_credentials(credentials)
        sock = bound_socket()
        port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        data = state / "state"
        env = EnvSettings(
            env="development",
            auto_migrate=True,
            state_dir=data,
            control_db=data / "control.db",
            hot_db=data / "hot.db",
            metrics_db=data / "metrics.db",
            cache_db=data / "cache.db",
            color="dev",
            workers=1,
            bind=f"127.0.0.1:{port}",
            internal_socket=data / "internal.sock",
            trusted_proxy_hops=1,
            trusted_proxy_cidrs=(ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("::1/128")),
            site_origin=base,
            rotator_ip_echo_url="http://127.0.0.1:9/ip",
            credentials_dir=credentials,
            log_level="warning",
        )
        clock = OffsetClock()
        app = create_app(env, clock=clock)
        app.state.auth_hasher = fast_hasher()
        saved = os.environ.get(TEST_UPSTREAM_ENV)
        os.environ[TEST_UPSTREAM_ENV] = roblox.base_url  # read once, while the egress clients are built
        server = _ThreadServer(app, sock, name="roxy-dashboard")
        try:
            server.start()
        finally:
            if saved is None:
                os.environ.pop(TEST_UPSTREAM_ENV, None)
            else:
                os.environ[TEST_UPSTREAM_ENV] = saved
        running = cls(base_url=base, app=app, clock=clock, server=server, roblox=roblox, state_dir=state)
        running.change_settings({**SEED_SETTINGS, **dict(settings or {})})
        running.make_admin()
        running.signed_in = running.login()
        if seed:
            running.seed()
        return running

    # ---- admin and sign-in

    def make_admin(self) -> Any:
        from roxy.admin.auth import totp
        from roxy.admin.auth.testing import make_admin

        cipher = totp.load_cipher(self.ctx.env.credentials_dir)
        assert cipher is not None, "make_fake_credentials writes the TOTP key"
        self.admin = make_admin(
            self.ctx.dbs.control, cipher=cipher, hasher=self.app.state.auth_hasher, now=int(self.clock.now())
        )
        return self.admin

    def next_code(self) -> str:
        """A TOTP code for a step no earlier sign-in used. The server accepts the step before and after the current
        one, and each step once, so up to three codes are ready at any moment; a fourth waits for the next step.
        The clock is never moved: moving it would expire the leader's lease and every session's idle timer."""
        from roxy.admin.auth import totp

        step_s = int(totp.TOTP_STEP_S)
        while True:
            current = int(self.clock.now()) // step_s
            step = max(self._last_step + 1, current - 1)
            if step <= current + 1:
                self._last_step = step
                return str(totp.code_at(self.admin.totp_secret, step * step_s + 1))
            time.sleep(1.0)

    def http(self) -> Any:
        import httpx

        return httpx.Client(base_url=self.base_url, timeout=30, follow_redirects=False)

    def headers(self, *, cookie: str | None = None, csrf: str | None = None) -> dict[str, str]:
        out = {
            "Origin": self.origin,
            "Sec-Fetch-Site": "same-origin",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) RoxyDashboardTest/1.0",
        }
        if cookie:
            out["Cookie"] = f"{self.SESSION_COOKIE}={cookie}"
        if csrf:
            out["X-CSRF-Token"] = csrf
        return out

    def login(self) -> SignedIn:
        """Sign in through `POST /admin/api/v1/auth/login` and `/auth/mfa` (TOTP), as the login page does."""
        with self.http() as client:
            first = client.post(
                "/admin/api/v1/auth/login",
                json={"username": self.admin.username, "password": self.admin.password},
                headers=self.headers(),
            )
            first.raise_for_status()
            body = first.json()
            second = client.post(
                "/admin/api/v1/auth/mfa",
                json={"transaction": body["Transaction"], "method": "totp", "code": self.next_code()},
                headers=self.headers(),
            )
            second.raise_for_status()
            cookie = _cookie_value(second.headers.get_list("set-cookie"), self.SESSION_COOKIE)
            data = second.json()
        assert cookie, "the login answer set no session cookie"
        return SignedIn(self.admin.username, self.admin.password, self.admin.totp_secret, cookie, data["CsrfToken"])

    def csrf(self) -> str:
        """A fresh masked CSRF token for the signed-in session."""
        assert self.signed_in is not None
        with self.http() as client:
            answer = client.get("/admin/api/v1/auth/session", headers=self.headers(cookie=self.signed_in.cookie))
            answer.raise_for_status()
            return str(answer.json()["CsrfToken"])

    def get(self, path: str, **kwargs: Any) -> Any:
        """GET as the signed-in admin (HTML pages and fragments included)."""
        assert self.signed_in is not None
        headers = {**self.headers(cookie=self.signed_in.cookie), "Accept": "text/html", **kwargs.pop("headers", {})}
        with self.http() as client:
            return client.get(path, headers=headers, **kwargs)

    def api(self, method: str, path: str, **kwargs: Any) -> Any:
        """A JSON admin API call as the signed-in admin (CSRF token added for unsafe methods)."""
        assert self.signed_in is not None
        token = self.csrf() if method.upper() in ("POST", "PUT", "PATCH", "DELETE") else None
        headers = {**self.headers(cookie=self.signed_in.cookie, csrf=token), **kwargs.pop("headers", {})}
        url = path if path.startswith("/admin") else f"/admin/api/v1/{path.lstrip('/')}"
        with self.http() as client:
            return client.request(method, url, headers=headers, **kwargs)

    # ---- data

    def run(self, coro: Coroutine[Any, Any, Any]) -> Any:
        return self.server.run(coro)

    def change_settings(self, values: Mapping[str, Any]) -> None:
        from roxy.config.audit import Actor
        from roxy.config.settings_service import SettingsService

        async def apply() -> None:
            service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
            await service.update(dict(values), Actor("cli", "test"), "dashboard test setup")
            await self.ctx.settings.reload()

        self.run(apply())

    def send_traffic(self, plan: Sequence[PlannedRequest] | None = None) -> list[int]:
        """Send the seeding plan through the real proxy; returns the statuses."""
        statuses: list[int] = []
        with self.http() as client:
            for item in plan if plan is not None else traffic_plan():
                response = client.request(item.method, item.path, headers=request_headers(item))
                statuses.append(response.status_code)
        return statuses

    def flush(self) -> None:
        """Write everything the recorder holds to metrics.db (the open minute included)."""

        async def flush() -> None:
            cache = getattr(self.ctx, "cache", None)
            if cache is not None:
                await cache.settle()
            await self.ctx.recorder.flush()

        self.run(flush())

    def seed(self) -> dict[str, Any]:
        """Traffic through the proxy, audit rows, a recommendation and a health run (see the module docstring)."""
        statuses = self.send_traffic()
        self.flush()
        self.seeded["statuses"] = statuses
        self.seeded["audit"] = self.run(seed_audit(self.ctx, self.clock))
        self.seeded["recommendation"] = self.run(seed_recommendation(self.ctx, self.clock))
        self.seeded["health_run"] = self.run(seed_health_run(self.ctx, self.clock))
        self.flush()
        return self.seeded

    def stop(self) -> None:
        try:
            self.server.stop()
        finally:
            self.roblox.stop()
            remove_loopback_guard()


def _cookie_value(set_cookies: Sequence[str], name: str) -> str | None:
    for header in set_cookies:
        first = header.split(";", 1)[0]
        key, _, value = first.partition("=")
        if key.strip() == name and value:
            return value.strip()
    return None


def wait_until(predicate: Callable[[], bool], timeout_s: float = 10.0, step_s: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step_s)
    return predicate()


__all__ = [
    "HOSTILE",
    "PLACES",
    "RAW_MARKERS",
    "SEED_SETTINGS",
    "THEMES",
    "VIEWPORTS",
    "DashboardServer",
    "Node",
    "OffsetClock",
    "PlannedRequest",
    "RobloxMock",
    "SignedIn",
    "assert_inert",
    "bound_socket",
    "install_loopback_guard",
    "make_fake_credentials",
    "parse_html",
    "remove_loopback_guard",
    "request_headers",
    "roblox_answer",
    "seed_audit",
    "seed_health_run",
    "seed_recommendation",
    "traffic_plan",
    "unescape",
    "wait_until",
]
