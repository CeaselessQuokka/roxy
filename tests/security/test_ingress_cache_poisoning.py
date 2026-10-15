"""Ingress review, cache poisoning lens: two requests share a cache entry only when Roblox would see the same request.

What this is
    Probes for `cache/keys.py`, `cache/policy.py`, `cache/service.py` and `proxy/scrub.py` (plan 9.13, 6.9, lead
    decision 9): the key text is one-to-one (it decodes back to exactly the method, host, path, query pairs, body
    hash, forwarded headers and auth class it was built from), query and path encoding ambiguities either share a
    key AND an upstream request or neither, forwarded headers always vary the key and nothing else does, POST
    bodies are hashed in full, and a credential answer never reaches an anonymous caller.

Why it exists
    Cache poisoning needs one thing: two requests with the same key but different upstream requests. Then the
    first caller's answer is served to the second. v1 had that (bug B12, the 12 hex body hash, forwarded
    `Accept-Language`); these probes fail if any of it comes back.

How it works
    The key is built from real `ProxyRequest` objects (`ingress_support.proxy_request`, the router's own
    construction) through the real `CacheService.peek`, so the policy, the ignored set and the vary input are the
    ones production uses. The upstream request is what `upstream/service.py _normalize` sends: host, decoded path,
    `urlencode(query)` in caller order, the scrubbed headers and the body.

What to read next
    `roxy/cache/keys.py`, `roxy/proxy/scrub.py`, then `test_ingress_exhaustion.py`.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any
from urllib.parse import unquote, urlencode

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from ingress_support import proxy_request

from roxy.cache.keys import CRED_SUFFIX, VARY_HEADERS, assert_forward_list, build_key
from roxy.cache.policy import request_policy, store_decision
from roxy.cache.service import CacheService
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, ok, rules_snapshot
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState
from roxy.proxy import scrub
from roxy.proxy.context import ProxyRequest

# --- the key text is one-to-one -------------------------------------------------------------------------------------


def decode_key(text: str) -> dict[str, Any]:
    """Invert `build_key`'s text: the docstring promises every separator starts with a space and no encoded part
    contains one, so the text parses back unambiguously. If this inverse ever fails, two inputs can share a key."""
    parts = text.split(" ")
    method, target = parts[0], parts[1]
    cut = min((i for i in (target.find("/"), target.find("?")) if i >= 0), default=len(target))
    host, rest = target[:cut], target[cut:]
    path_text, has_query, query_text = rest.removeprefix("/").partition("?")
    pairs: list[tuple[str, str]] = []
    if has_query:
        for item in query_text.split("&"):
            name, equals, value = item.partition("=")
            assert equals, item
            pairs.append((unquote(name), unquote(value)))
    decoded: dict[str, Any] = {
        "method": method,
        "host": host,
        "path": unquote(path_text),
        "pairs": pairs,
        "body_hash": None,
        "vary": [],
        "cred": False,
    }
    for extra in parts[2:]:
        if extra.startswith("#"):
            decoded["body_hash"] = extra[1:]
        elif extra.startswith("^"):
            name, _, value = extra[1:].partition("=")
            decoded["vary"].append((name, unquote(value)))
        elif " " + extra == CRED_SUFFIX:
            decoded["cred"] = True
        else:
            raise AssertionError(f"unparsable key part {extra!r} in {text!r}")
    return decoded


_TEXT = st.text(alphabet=st.characters(codec="utf-8"), max_size=8)  # no lone surrogates (never in a parsed URL)
_SEGMENT = st.text(
    alphabet=st.characters(codec="utf-8", exclude_categories=["Cc"], exclude_characters="/%?#"),
    min_size=1,
    max_size=6,
)


@given(
    method=st.sampled_from(["GET", "POST"]),
    host=st.sampled_from(["games.roblox.com", "users.roblox.com"]),
    segments=st.lists(_SEGMENT, max_size=4),
    trailing=st.booleans(),
    pairs=st.lists(st.tuples(_TEXT, _TEXT), max_size=5),
    body=st.binary(max_size=16),
    accept=st.sampled_from([None, "application/json", "*/*"]),
    content_type=st.sampled_from([None, "application/json", "text/plain; charset=utf-8", "a b^c=d #e"]),
    cred=st.booleans(),
)
@settings(max_examples=800, deadline=None)
def test_property_key_text_decodes_to_exactly_its_inputs(
    method: str,
    host: str,
    segments: list[str],
    trailing: bool,
    pairs: list[tuple[str, str]],
    body: bytes,
    accept: str | None,
    content_type: str | None,
    cred: bool,
) -> None:
    path = "/" + "/".join(segments) + ("/" if trailing and segments else "")
    headers: dict[str, str] = {}
    if accept:
        headers["accept"] = accept
    if content_type:
        headers["content-type"] = content_type
    vary = scrub.forwarded_request_headers(method, headers, body)
    key = build_key(method, host, path, pairs, body, auth_class=AuthClass.CRED if cred else AuthClass.ANON, vary=vary)
    decoded = decode_key(key.text)
    assert decoded["method"] == method
    assert decoded["host"] == host
    assert decoded["path"] == path[1:]
    assert decoded["pairs"] == sorted(pairs, key=lambda pair: pair[0])  # stable: repeated names keep their order
    expected_hash = hashlib.sha256(body).hexdigest() if body and method != "GET" else None
    assert decoded["body_hash"] == expected_hash
    assert decoded["vary"] == sorted(vary.items())
    assert decoded["cred"] is cred


def test_forwarded_headers_and_key_vary_list_are_the_same_list() -> None:
    assert_forward_list(scrub.FORWARDED_REQUEST_HEADERS)
    assert set(VARY_HEADERS) == set(scrub.FORWARDED_REQUEST_HEADERS)


# --- encoding ambiguities through the real parse and the real peek -------------------------------------------------


def upstream_request(req: ProxyRequest) -> tuple[str, str, str, tuple[tuple[str, str], ...], bytes, str]:
    """What `upstream/service.py` sends for `req`: method, host, decoded path, query pairs in caller order, the
    body and the scrubbed headers."""
    forwarded = tuple(sorted(scrub.forwarded_request_headers(req.method, req.headers, req.body).items()))
    query = urlencode(req.query)
    return req.method, req.host, req.path, forwarded, req.body, query


def same_upstream(a: ProxyRequest, b: ProxyRequest) -> bool:
    """Equivalent upstream requests: identical, except that distinct parameter names may come in another order
    (the key sorts names with a stable sort, so repeated values must keep their relative order)."""
    ua, ub = upstream_request(a), upstream_request(b)
    if ua[:5] != ub[:5]:
        return False
    return sorted(a.query, key=lambda p: p[0]) == sorted(b.query, key=lambda p: p[0])


@pytest.fixture
def cache(dbs: Any) -> CacheService:
    return CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(rules_snapshot(ignored_params=["_", "t"])),
        clock=FakeClock(),
        upstream=FakeUpstream(),
        worker_id="ingress",
    )


async def key_of(cache: CacheService, req: ProxyRequest) -> str:
    peek = await cache.peek(req)
    assert peek.key is not None, "the probe expects a cacheable request"
    return peek.key.id


DIFFERENT_QUERIES: list[tuple[str, bytes, bytes]] = [
    ("lead_decision_9", b"universeIds=1%26universeIds%3D2", b"universeIds=1&universeIds=2"),
    ("encoded_equals_in_name", b"a%3D1=2", b"a=1%3D2"),
    ("plus_vs_encoded_plus", b"a=%2B", b"a=+"),
    ("repeated_value_order", b"ids=1&ids=2", b"ids=2&ids=1"),
    ("encoded_ampersand", b"a=1%26b%3D2", b"a=1&b=2"),
    ("semicolon_is_data", b"a=1;b=2", b"a=1&b=2"),
    ("unicode_nfc_vs_nfd", b"a=caf%C3%A9", b"a=cafe%CC%81"),
    ("name_case", b"A=1", b"a=1"),
    ("prettyprint_name_case", b"PrettyPrint=true", b""),
    ("ignored_name_case", b"T=1", b""),
    ("empty_name", b"=1", b""),
    ("encoded_percent", b"a=%2541", b"a=A"),
    ("csv_order_without_rule", b"ids=1,2", b"ids=2,1"),
]

SAME_QUERIES: list[tuple[str, bytes, bytes]] = [
    ("name_order", b"b=2&a=1", b"a=1&b=2"),
    ("prettyprint_stripped", b"a=1&prettyprint=true", b"a=1"),
    ("prettyprint_any_value", b"prettyprint=false&a=1", b"a=1&prettyprint=TRUE"),
    ("bare_name", b"a", b"a="),
    ("space_spellings", b"a=%20", b"a=+"),
    ("encoded_letter", b"%61=1", b"a=1"),
    ("interleaved_repeats", b"ids=1&x=5&ids=2", b"x=5&ids=1&ids=2"),
    ("raw_equals_in_value", b"a=1=b", b"a=1%3Db"),
    ("brackets", b"a[]=1", b"a%5B%5D=1"),
    ("ignored_param", b"t=123&a=1", b"a=1"),
]


@pytest.mark.parametrize(("case_id", "left", "right"), DIFFERENT_QUERIES, ids=[c[0] for c in DIFFERENT_QUERIES])
async def test_query_ambiguities_never_share_a_key_when_roblox_sees_different_requests(
    cache: CacheService, case_id: str, left: bytes, right: bytes
) -> None:
    a = proxy_request(b"/games.roblox.com/v1/games", left)
    b = proxy_request(b"/games.roblox.com/v1/games", right)
    assert a.target_problem is None
    assert b.target_problem is None
    assert not same_upstream(a, b), f"{case_id}: the probe pair must reach Roblox differently"
    assert await key_of(cache, a) != await key_of(cache, b), case_id


@pytest.mark.parametrize(("case_id", "left", "right"), SAME_QUERIES, ids=[c[0] for c in SAME_QUERIES])
async def test_equivalent_spellings_share_one_key(cache: CacheService, case_id: str, left: bytes, right: bytes) -> None:
    a = proxy_request(b"/games.roblox.com/v1/games", left)
    b = proxy_request(b"/games.roblox.com/v1/games", right)
    assert await key_of(cache, a) == await key_of(cache, b), case_id
    if case_id != "ignored_param":  # an ignored name is sent upstream but deliberately not keyed (plan 15.5)
        assert same_upstream(a, b), case_id


DIFFERENT_PATHS = [
    ("trailing_slash", b"/games.roblox.com/v1/games", b"/games.roblox.com/v1/games/"),
    ("path_case", b"/games.roblox.com/v1/Games", b"/games.roblox.com/v1/games"),
    ("semicolon_vs_slash", b"/games.roblox.com/v1/a;b", b"/games.roblox.com/v1/a/b"),
    ("unicode_nfc_vs_nfd", b"/games.roblox.com/v1/caf%C3%A9", b"/games.roblox.com/v1/cafe%CC%81"),
    ("space_vs_plus", b"/games.roblox.com/v1/a%20b", b"/games.roblox.com/v1/a+b"),
]
SAME_PATHS = [
    ("double_slash", b"/games.roblox.com/v1//games", b"/games.roblox.com/v1/games"),
    ("encoded_letter", b"/games.roblox.com/v1/g%61mes", b"/games.roblox.com/v1/games"),
    ("encoded_semicolon", b"/games.roblox.com/v1/a%3Bb", b"/games.roblox.com/v1/a;b"),
    ("host_case_and_dot", b"/GAMES.roblox.com./v1/games", b"/games.roblox.com/v1/games"),
]


@pytest.mark.parametrize(("case_id", "left", "right"), DIFFERENT_PATHS, ids=[c[0] for c in DIFFERENT_PATHS])
async def test_path_spellings_reaching_roblox_differently_never_share_a_key(
    cache: CacheService, case_id: str, left: bytes, right: bytes
) -> None:
    a, b = proxy_request(left), proxy_request(right)
    assert a.target_problem is None
    assert b.target_problem is None
    assert not same_upstream(a, b)
    assert await key_of(cache, a) != await key_of(cache, b), case_id


@pytest.mark.parametrize(("case_id", "left", "right"), SAME_PATHS, ids=[c[0] for c in SAME_PATHS])
async def test_path_spellings_reaching_roblox_identically_share_a_key(
    cache: CacheService, case_id: str, left: bytes, right: bytes
) -> None:
    a, b = proxy_request(left), proxy_request(right)
    assert same_upstream(a, b), case_id
    assert await key_of(cache, a) == await key_of(cache, b), case_id


# --- headers: what is forwarded varies the key, and nothing else does ----------------------------------------------

HEADER_SETS: list[list[tuple[str, str]]] = [
    [],
    [("accept", "application/json")],
    [("accept", " APPLICATION/JSON ")],
    [("accept", "*/*")],
    [("accept", "text/html")],
    [("accept", "application/json"), ("accept", "*/*")],
    [("accept-language", "de-DE")],
    [("cookie", "a=b")],
    [("authorization", "Bearer x")],
    [("x-csrf-token", "abc")],
    [("roblox-id", "123")],
    [("user-agent", "Mozilla/5.0 Chrome")],
    [("content-type", "application/json")],
    [("x-forwarded-for", "198.51.100.1")],
    [("cache-control", "max-age=0")],
]


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_key_varies_exactly_with_the_forwarded_headers(cache: CacheService, method: str) -> None:
    target = b"/users.roblox.com/v1/users" if method == "POST" else b"/games.roblox.com/v1/games"
    keys: dict[tuple[tuple[str, str], ...], str] = {}
    for headers in HEADER_SETS:
        req = proxy_request(target, b"a=1", method=method, headers=headers, body=b'{"userIds":[1]}')
        forwarded = tuple(sorted(req.forwarded_headers().items()))
        for name, _ in forwarded:
            assert name in VARY_HEADERS
        key = await key_of(cache, req)
        if forwarded in keys:
            assert keys[forwarded] == key, (headers, "a header that is not forwarded changed the key")
        keys[forwarded] = key
    # Distinct forwarded header sets always give distinct keys.
    assert len(set(keys.values())) == len(keys)


async def test_get_ignores_content_type_and_body(cache: CacheService) -> None:
    plain = proxy_request(b"/games.roblox.com/v1/games", b"a=1")
    typed = proxy_request(
        b"/games.roblox.com/v1/games", b"a=1", headers=[("accept", "*/*"), ("content-type", "text/evil")]
    )
    assert typed.forwarded_headers() == plain.forwarded_headers()
    assert await key_of(cache, plain) == await key_of(cache, typed)


# --- bodies ----------------------------------------------------------------------------------------------------------


async def test_post_body_is_hashed_in_full(cache: CacheService) -> None:
    first = b'{"userIds":[1]}' + b" " * 64 + b"a"
    second = b'{"userIds":[1]}' + b" " * 64 + b"b"
    a = proxy_request(b"/users.roblox.com/v1/users", method="POST", body=first)
    b = proxy_request(b"/users.roblox.com/v1/users", method="POST", body=second)
    peek_a, peek_b = await cache.peek(a), await cache.peek(b)
    assert peek_a.key is not None
    assert peek_b.key is not None
    assert peek_a.key.body_hash == hashlib.sha256(first).hexdigest()
    assert peek_a.key.id != peek_b.key.id


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
async def test_write_methods_never_get_a_key(cache: CacheService, method: str) -> None:
    req = proxy_request(b"/games.roblox.com/v1/games", method=method, body=b"{}")
    assert (await cache.peek(req)).key is None


async def test_post_outside_the_allowlist_never_gets_a_key(cache: CacheService) -> None:
    req = proxy_request(b"/games.roblox.com/v1/games", method="POST", body=b"{}")
    assert (await cache.peek(req)).key is None


async def test_head_shares_get_and_view_options_do_not_split(cache: CacheService) -> None:
    base = await key_of(cache, proxy_request(b"/games.roblox.com/v1/games", b"a=1"))
    head = await key_of(cache, proxy_request(b"/games.roblox.com/v1/games", b"a=1", method="HEAD"))
    pretty = await key_of(cache, proxy_request(b"/games.roblox.com/v1/games", b"a=1&prettyprint=true"))
    browser = await key_of(
        cache,
        proxy_request(
            b"/games.roblox.com/v1/games", b"a=1", headers=[("user-agent", "Mozilla/5.0"), ("accept", "*/*")]
        ),
    )
    assert base == head == pretty == browser


# --- auth classes (plan 6.9) -----------------------------------------------------------------------------------------

CURRENCY = b"/economy.roblox.com/v1/user/currency"


def credential_rules(private: int) -> Any:
    return rules_snapshot(
        credential_allowlist=[
            {"pattern": "economy.roblox.com/v1/user/currency", "methods": ["GET"], "cache_private": private}
        ]
    )


def test_policy_auth_class_follows_the_allowlist_and_private_is_never_keyed() -> None:
    from roxy.cache.policy import CacheSettings

    cs = CacheSettings.read(FakeSettings())
    anon = request_policy("GET", "economy.roblox.com/v1/user/currency", {}, cs, rules_snapshot())
    shared = request_policy("GET", "economy.roblox.com/v1/user/currency", {}, cs, credential_rules(0))
    private = request_policy("GET", "economy.roblox.com/v1/user/currency", {}, cs, credential_rules(1))
    assert (anon.auth_class, shared.auth_class) == (AuthClass.ANON, AuthClass.CRED)
    assert not private.cacheable
    assert private.private
    key_anon = build_key("GET", "economy.roblox.com", "/v1/user/currency", [], b"")
    key_cred = build_key("GET", "economy.roblox.com", "/v1/user/currency", [], b"", auth_class=AuthClass.CRED)
    assert key_anon.id != key_cred.id
    assert key_anon.flight_key != key_cred.flight_key
    leaked = ok('{"robux":1}', auth_class=AuthClass.CRED)
    assert store_decision(leaked, anon, cs).why == "auth_class_mismatch"


async def test_same_worker_follower_never_receives_a_credential_answer_for_an_anonymous_key(dbs: Any) -> None:
    """Defense in depth (cache/service.py docstring: an answer fetched with the credential belongs to its own
    request). The trigger in production is any disagreement between the cache's policy (rules at peek time) and
    the upstream's routing (rules at fetch time): for example a `cache_private` allowlist row added between the two,
    or an allowlist regex cut off by the match timeout in one place and not the other. The follower joined the
    owner's flight in the same worker; when the owner's answer comes back with the credential, the follower makes
    its own call (anonymous here, the rules have settled) instead of receiving it. Fixed ingress finding (F2)."""
    gate = asyncio.Event()

    def respond(req: Any, n: int) -> Any:
        return ok('{"robux":"secret"}', auth_class=AuthClass.CRED) if n == 1 else ok('{"robux":"public"}')

    upstream = FakeUpstream(respond, gate=gate)
    service = CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(rules_snapshot()),
        clock=FakeClock(),
        upstream=upstream,
        worker_id="w1",
    )

    async def call() -> Any:
        req = proxy_request(CURRENCY)
        return await service.serve(req, await service.peek(req))

    owner = asyncio.create_task(call())
    await upstream.started.wait()
    follower = asyncio.create_task(call())
    await asyncio.sleep(0.05)
    gate.set()
    first = await owner
    other = await follower
    await service.settle()
    assert b"secret" in first.body
    assert b"secret" not in other.body
    assert other.cache_state is CacheState.MISS  # its own call, not a coalesced copy
    assert upstream.count == 2
    later = await call()  # and nothing the credential answered is stored or served to a later request
    assert b"secret" not in later.body
    assert later.cache_state is CacheState.HIT
