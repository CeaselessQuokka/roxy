"""SSRF corpus (plan 9.10 and 19.7): hostile targets the proxy must never fetch.

What this is
    Every case of the plan 9.10 corpus plus more: trailing newline and dots, case, look-alike domains, user
    names, IP literals in every spelling, ports, percent-encoded dots and slashes, Unicode homoglyphs and
    case-folding tricks, backslashes, dot segments, double encoding, and the redirect re-validation. Each case is
    checked twice: by `validate.parse_target` directly, and as a raw request through the real proxy route with an
    abuse pipeline that ALLOWS everything and a cache that fails the test if it is ever asked to serve.

Why it exists
    Server-side request forgery turns Roxy into a tool against other hosts or its own machine (the cloud metadata
    address 169.254.169.254 hands out credentials). The host allowlist is the control (plan 9.10); these tests make
    sure no spelling of a hostile target gets past it, and that the router refuses an invalid target even when
    the abuse pipeline (another module, another author) fails to.

How it works
    The app-level check builds the ASGI scope by hand with `raw_path` exactly as a server would pass it, because
    HTTP clients normalize URLs (httpx removes `..`), which would hide the attack. A request counts as safe when
    it gets a 404 and nothing was served.

What to read next
    `roxy/proxy/validate.py`.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from urllib.parse import unquote

import pytest
from starlette.applications import Starlette

from roxy.core.client_ip import parse_cidrs
from roxy.core.clock import FakeClock
from roxy.core.middleware import build_middleware
from roxy.core.reasons import ReasonCode
from roxy.proxy import respond
from roxy.proxy.router import router
from roxy.proxy.validate import parse_redirect, parse_target, parse_upstream_url

NR = ReasonCode.NOT_ROBLOX
HNA = ReasonCode.HOST_NOT_ALLOWED
UNSAFE = ReasonCode.UNSAFE_URL

# (id, raw path as the server passes it, expected problem)
HOSTILE: list[tuple[str, bytes, ReasonCode]] = [
    ("trailing_newline_encoded", b"/games.roblox.com%0A/v1/games", NR),
    ("trailing_newline_raw", b"/games.roblox.com\n/v1/games", NR),
    ("newline_before_slash_regex_trap", b"/games.roblox.com\n", NR),
    ("two_trailing_dots", b"/games.roblox.com../v1/games", NR),
    ("roblox_as_subdomain_of_evil", b"/roblox.com.evil.com/x", NR),
    ("evil_suffix", b"/games.roblox.com.evil.com/x", NR),
    ("lookalike_prefix", b"/evilroblox.com/x", NR),
    ("lookalike_hyphen", b"/evil-roblox.com/x", NR),
    ("lookalike_tld", b"/games.roblox.co/x", NR),
    ("userinfo_after_host", b"/games.roblox.com@evil.com/x", NR),
    ("userinfo_before_host", b"/evil.com@games.roblox.com/x", NR),
    ("userinfo_with_password", b"/user:pass@games.roblox.com/x", NR),
    ("ipv4_loopback", b"/127.0.0.1/x", NR),
    ("ipv4_metadata", b"/169.254.169.254/latest/meta-data/", NR),
    ("ipv4_decimal", b"/2130706433/x", NR),
    ("ipv4_hex", b"/0x7f000001/x", NR),
    ("ipv4_octal", b"/0177.0.0.1/x", NR),
    ("ipv6_loopback", b"/[::1]/x", NR),
    ("ipv6_mapped", b"/[::ffff:127.0.0.1]/x", NR),
    ("localhost", b"/localhost/x", NR),
    ("port_8080", b"/games.roblox.com:8080/x", NR),
    ("port_443_explicit", b"/games.roblox.com:443/x", NR),
    ("encoded_dots", b"/games%2Eroblox%2Ecom/x", NR),
    ("encoded_dot_suffix", b"/evil.com%2E.roblox.com/x", NR),
    ("encoded_slash_in_host", b"/games.roblox.com%2F@evil.com/x", NR),
    ("encoded_slash_before_roblox", b"/evil.com%2F.roblox.com/x", NR),
    ("encoded_at", b"/evil.com%40games.roblox.com/x", NR),
    ("encoded_nul", b"/games.roblox.com%00.evil.com/x", NR),
    ("encoded_tab", b"/games.roblox.com%09/x", NR),
    ("raw_hash_in_host", b"/evil.com#.roblox.com/x", NR),
    ("homoglyph_cyrillic_a_raw", "/gаmes.roblox.com/x".encode(), NR),
    ("homoglyph_cyrillic_a_encoded", b"/g%D0%B0mes.roblox.com/x", NR),
    ("fullwidth_dot", "/games．roblox.com/x".encode(), NR),
    ("ideographic_dot", "/games。roblox.com/x".encode(), NR),
    ("empty_host", b"//evil.com/x", NR),
    ("scheme_in_path", b"/https://evil.com/x", NR),
    ("scheme_roblox_in_path", b"/https://games.roblox.com/x", NR),
    ("no_slash_after_host", b"/games.roblox.com", NR),
    ("overlong_host", b"/" + b"a." * 130 + b"roblox.com/x", NR),
    ("unknown_subdomain", b"/internal.roblox.com/x", HNA),
    ("bare_apex", b"/roblox.com/x", HNA),
    ("www", b"/www.roblox.com/x", HNA),
    ("punycode_lookalike", b"/xn--gmes-roblox-9db.roblox.com/x", HNA),
    ("nested_allowed_name", b"/games.roblox.com.roblox.com/x", HNA),
    ("backslash_raw", b"/games.roblox.com\\@evil.com/x", UNSAFE),
    ("backslash_encoded", b"/games.roblox.com%5C@evil.com/x", UNSAFE),
    ("dot_segments", b"/games.roblox.com/v1/../../evil", UNSAFE),
    ("encoded_dot_segments", b"/games.roblox.com/v1/%2e%2e/%2e%2e/x", UNSAFE),
    ("encoded_slash_traversal", b"/games.roblox.com/v1%2F..%2F..%2Fx", UNSAFE),
    ("double_encoded_slash", b"/games.roblox.com/v1/%252F..", UNSAFE),
    ("crlf_in_path", b"/games.roblox.com/v1/x%0D%0AHost:%20evil.com", UNSAFE),
    ("encoded_query_split", b"/games.roblox.com/v1/a%3F@evil.com", UNSAFE),
    ("html_probe", b"/games.roblox.com/%3Cscript%3E", UNSAFE),
]

ACCEPTED: list[tuple[str, bytes, str]] = [
    ("uppercase", b"/GAMES.ROBLOX.COM/v1/games", "games.roblox.com"),
    ("one_trailing_dot", b"/games.roblox.com./v1/games", "games.roblox.com"),
    ("uppercase_trailing_dot", b"/Games.Roblox.Com./v1/games", "games.roblox.com"),
    ("multi_label_allowed", b"/thumbnails.roblox.com/v1/users/avatar", "thumbnails.roblox.com"),
]


@pytest.mark.parametrize(("case_id", "raw", "problem"), HOSTILE, ids=[case[0] for case in HOSTILE])
def test_hostile_targets_refused(case_id: str, raw: bytes, problem: ReasonCode) -> None:
    result = parse_target(raw, b"", "GET")
    assert result.problem is problem, (case_id, result.detail)
    assert not result.ok


@pytest.mark.parametrize(("case_id", "raw", "host"), ACCEPTED, ids=[case[0] for case in ACCEPTED])
def test_benign_variants_accepted(case_id: str, raw: bytes, host: str) -> None:
    result = parse_target(raw, b"", "GET")
    assert result.ok, (case_id, result.detail)
    assert result.host == host
    assert result.upstream_url.startswith(f"https://{host}/")


def test_kelvin_sign_is_refused_even_without_the_allowlist() -> None:
    """`str.lower()` turns U+212A KELVIN SIGN into ASCII `k`: ASCII is checked before lowercasing."""
    raw = "/K.roblox.com/x".encode()
    assert parse_target(raw, b"", "GET", strict_host_allowlist=False).problem is NR
    assert parse_target(b"/k.roblox.com/x", b"", "GET", strict_host_allowlist=False).ok


def test_non_strict_mode_still_requires_roblox_com() -> None:
    for raw in (b"/evil.com/x", b"/127.0.0.1/x", b"/games.roblox.com:8080/x", b"/games.roblox.com@evil.com/x"):
        assert parse_target(raw, b"", "GET", strict_host_allowlist=False).problem is NR
    assert parse_target(b"/anything.roblox.com/x", b"", "GET", strict_host_allowlist=False).ok


def test_empty_allowlist_refuses_everything() -> None:
    assert parse_target(b"/games.roblox.com/v1/games", b"", "GET", allowed_hosts=frozenset()).problem is HNA


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://games.roblox.com/v1/games?ids=1", True),
        ("https://games.roblox.com:443/v1/games", True),
        ("https://GAMES.roblox.com./v1/games", True),
        ("http://games.roblox.com/v1/games", False),
        ("https://games.roblox.com:8443/v1/games", False),
        ("https://user:pass@games.roblox.com/v1/games", False),
        ("https://games.roblox.com@evil.com/", False),
        ("https://evil.com/", False),
        ("https://[::1]/", False),
        ("https://127.0.0.1/", False),
        ("https://169.254.169.254/latest/meta-data/", False),
        ("https://games.rob\nlox.com/", False),  # urlsplit would delete the newline and join the host
        ("https://games.roblox.com:99999/", False),
        ("ftp://games.roblox.com/", False),
        ("//games.roblox.com/v1", False),
        ("https://games.roblox.com/v1/../x", False),
    ],
)
def test_parse_upstream_url(url: str, ok: bool) -> None:
    assert parse_upstream_url(url).ok is ok


@pytest.mark.parametrize(
    ("location", "ok"),
    [
        ("/v1/games/2", True),
        ("https://games.roblox.com/v1/other", True),
        ("https://thumbnails.roblox.com/v1/x", True),
        ("//evil.example/x", False),
        ("https://evil.example/x", False),
        ("http://games.roblox.com/v1/games", False),
        ("https://www.roblox.com/login", False),  # a roblox.com host outside the allowlist
        ("../../../etc/passwd", True),  # resolved by urljoin against the current host, stays on it
    ],
)
def test_redirects_revalidated(location: str, ok: bool) -> None:
    result = parse_redirect("https://games.roblox.com/v1/games", location)
    assert result.ok is ok, result.detail
    if ok:
        assert result.host in {"games.roblox.com", "thumbnails.roblox.com"}


# --- through the real proxy route -----------------------------------------------------------------------------------


class AllowEverything:
    """A broken abuse pipeline that lets every target through: the router must still refuse."""

    tarpit = None

    async def evaluate(self, req: Any) -> Any:
        return SimpleNamespace(headers={}, serve_throttled_from_cache=False)


class MustNotServe:
    def __init__(self) -> None:
        self.served: list[Any] = []

    async def peek(self, req: Any) -> Any:
        assert req.target_problem is None, "the cache must never be consulted for an invalid target"
        return None

    async def serve(self, req: Any, peek: Any) -> Any:
        self.served.append(req)
        return respond.ProxyResult(reason=ReasonCode.UPSTREAM_OK, status=200, body=b"FETCHED")


@pytest.fixture
def ssrf_app() -> tuple[Starlette, Any]:
    ctx = SimpleNamespace(
        settings=None, clock=FakeClock(), abuse=AllowEverything(), cache=MustNotServe(), upstream=None, recorder=None
    )
    app = Starlette(
        routes=list(router.routes),
        middleware=build_middleware(trusted_cidrs=parse_cidrs("127.0.0.1/32"), hops=1),
    )
    app.state.ctx = ctx
    return app, ctx


async def raw_request(app: Starlette, raw_path: bytes, method: str = "GET") -> tuple[int, dict[bytes, bytes], bytes]:
    """Send one request with an exact raw path, as uvicorn would pass it (no client-side normalization)."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": unquote(raw_path.decode("latin-1")),
        "raw_path": raw_path,
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    messages: list[dict[str, Any]] = []
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(scope, receive, send)
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), body


@pytest.mark.parametrize(("case_id", "raw", "problem"), HOSTILE, ids=[case[0] for case in HOSTILE])
async def test_hostile_targets_never_fetched_through_the_route(
    ssrf_app: tuple[Starlette, Any], case_id: str, raw: bytes, problem: ReasonCode
) -> None:
    app, ctx = ssrf_app
    for method in ("GET", "POST", "HEAD"):
        status, _, body = await raw_request(app, raw, method)
        assert status == 404, (case_id, method, status, body)
        assert b"FETCHED" not in body
    assert ctx.cache.served == []


async def test_benign_variant_is_fetched_through_the_route(ssrf_app: tuple[Starlette, Any]) -> None:
    app, ctx = ssrf_app
    status, _, body = await raw_request(app, b"/GAMES.ROBLOX.COM./v1/games")
    assert status == 200
    assert body == b"FETCHED"
    assert ctx.cache.served[0].host == "games.roblox.com"
    assert ctx.cache.served[0].upstream_url == "https://games.roblox.com/v1/games"
