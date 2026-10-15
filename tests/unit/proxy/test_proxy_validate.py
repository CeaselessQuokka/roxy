"""Unit tests for `roxy/proxy/validate.py`: query parsing, prettyprint, path normalization and the upstream URL.

What this is
    The non-attack behavior of `parse_target` (the SSRF corpus lives in `tests/security/test_ssrf.py`): repeated
    parameters kept in caller order (plan row 2), the v1 prettyprint rules (row 3, v1 notes 5.1), the path
    normalization that makes the matched path the fetched path (v1 B3, B4), and `build_upstream_url`.

Why it exists
    Every later stage (rules, cache key, upstream URL) trusts what this parse returns, so its edge cases are pinned
    here, including property tests that any query survives the parse and re-encoding unchanged.

How it works
    Direct calls with raw bytes as an ASGI server would pass them; Hypothesis generates query pairs.

What to read next
    `tests/security/test_ssrf.py`.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from roxy.core.reasons import ReasonCode
from roxy.proxy.validate import (
    DEFAULT_ALLOWED_HOSTS,
    build_upstream_url,
    encode_query,
    parse_target,
    quote_path,
)


def test_valid_target_fields() -> None:
    result = parse_target(b"/Games.Roblox.com/v1/games/votes", b"universeIds=9967558039", "get")
    assert result.problem is None
    assert result.ok
    assert result.method == "GET"
    assert result.host == "games.roblox.com"
    assert result.path == "/v1/games/votes"  # path case preserved, host lowercased
    assert result.target == "games.roblox.com/v1/games/votes"
    assert result.query == (("universeIds", "9967558039"),)
    assert result.prettyprint is False
    assert result.upstream_url == "https://games.roblox.com/v1/games/votes?universeIds=9967558039"


def test_repeated_params_preserved_in_caller_order() -> None:
    """Plan row 2: `ids=1&ids=2` stays two pairs; caller order is kept (DESIGN 7), not v1's grouping."""
    result = parse_target(b"/games.roblox.com/v1/games", b"a=1&b=2&a=3&c=&d", "GET")
    assert result.query == (("a", "1"), ("b", "2"), ("a", "3"), ("c", ""), ("d", ""))
    assert result.upstream_url.endswith("?a=1&b=2&a=3&c=&d=")  # a bare `d` is sent as `d=` (v1 probe)


@pytest.mark.parametrize(
    ("query", "pretty", "kept"),
    [
        ("universeIds=1&universeIds=2&prettyprint=true&b=%20x&a=1", True, "universeIds=1&universeIds=2&b=+x&a=1"),
        ("prettyprint=TRUE", True, ""),
        ("prettyprint=1", False, ""),
        ("prettyprint=true&prettyprint=false", False, ""),
        ("prettyprint=false&prettyprint=true", True, ""),
        ("PrettyPrint=true", False, "PrettyPrint=true"),
        ("prettyprint", False, ""),
    ],
)
def test_prettyprint_rules(query: str, pretty: bool, kept: str) -> None:
    """v1 notes 5.1: exact case-sensitive name, every copy removed, the LAST value decides."""
    result = parse_target(b"/games.roblox.com/v1/games", query.encode(), "GET")
    assert result.ok
    assert result.prettyprint is pretty
    assert encode_query(result.query) == kept


def test_query_embedded_in_raw_path_is_used() -> None:
    """httpx's test transport puts the query inside raw_path; the parse must find it there too."""
    result = parse_target(b"/games.roblox.com/v1/games?ids=1&ids=2", b"", "GET")
    assert result.query == (("ids", "1"), ("ids", "2"))


def test_percent_decoding_of_query_and_plus() -> None:
    result = parse_target(b"/games.roblox.com/v1/x", b"keyword=caf%C3%A9+au+lait&note=a%3Db%26c", "GET")
    assert result.query == (("keyword", "café au lait"), ("note", "a=b&c"))
    # Re-encoding keeps `=` and `&` inside the value: one value stays one value (LEAD_NOTES decision 9).
    assert parse_qsl(urlsplit(result.upstream_url).query) == [("keyword", "café au lait"), ("note", "a=b&c")]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"/games.roblox.com/", "/"),
        (b"/games.roblox.com//v1//games", "/v1/games"),  # empty segments dropped: no double-slash block bypass
        (b"/games.roblox.com/v1/games/", "/v1/games/"),  # a trailing slash is kept
        (b"/games.roblox.com//", "/"),
        (b"/games.roblox.com/v1/a%20b", "/v1/a b"),
        (b"/games.roblox.com/v1/caf%C3%A9", "/v1/café"),
        (b"/games.roblox.com/v1/it's&more", "/v1/it's&more"),  # v1 refused these (B17); v2 allows them
        (b"/games.roblox.com/v1/%7Euser", "/v1/~user"),
    ],
)
def test_path_normalization(raw: bytes, expected: str) -> None:
    result = parse_target(raw, b"", "GET")
    assert result.ok, result.detail
    assert result.path == expected


@pytest.mark.parametrize(
    ("raw", "detail"),
    [
        (b"/games.roblox.com/v1/a%3Fb%23c", "encoded %, ? or # in the path"),  # v1 B3 path smuggling
        (b"/games.roblox.com/v1/x/../secret", "dot segment in the path"),  # v1 B4
        (b"/games.roblox.com/v1/%2E%2E/secret", "dot segment in the path"),
        (b"/games.roblox.com/v1/./x", "dot segment in the path"),
        (b"/games.roblox.com/v1%2Fgames", "encoded slash in the path"),
        (b"/games.roblox.com/v1/%252F", "encoded %, ? or # in the path"),  # double encoding
        (b"/games.roblox.com/v1/%zz", "encoded %, ? or # in the path"),  # a broken escape stays a literal %
        (b"/games.roblox.com/v1/a%0Db", "control character in the path"),
        (b"/games.roblox.com/v1/a%0Ab", "control character in the path"),
        (b"/games.roblox.com/v1/a%00b", "control character in the path"),
        (b"/games.roblox.com/v1/%FF", "path is not valid UTF-8"),
        (b"/games.roblox.com/v1/a%5Cb", "unsafe characters"),  # an encoded backslash
        (b"/games.roblox.com/v1/%3Cscript%3E", "unsafe characters"),
        (b'/games.roblox.com/v1/"x"', "unsafe characters"),
    ],
)
def test_unsafe_paths(raw: bytes, detail: str) -> None:
    result = parse_target(raw, b"", "GET")
    assert result.problem is ReasonCode.UNSAFE_URL
    assert result.detail == detail


@pytest.mark.parametrize("query", [b"a=%0D%0Ab", b"a=1%00", b"x%0A=1"])
def test_control_characters_in_query_are_unsafe(query: bytes) -> None:
    result = parse_target(b"/games.roblox.com/v1/games", query, "GET")
    assert result.problem is ReasonCode.UNSAFE_URL
    assert result.detail == "control character in the query string"


def test_too_many_query_fields_is_unsafe() -> None:
    query = "&".join(f"a{i}=1" for i in range(1001)).encode()
    result = parse_target(b"/games.roblox.com/v1/games", query, "GET", max_url_length=100_000)
    assert result.problem is ReasonCode.UNSAFE_URL


def test_url_length_limit() -> None:
    path = b"/games.roblox.com/v1/" + b"a" * 100
    assert parse_target(path, b"q=1", "GET", max_url_length=len(path) + 4).ok
    too_long = parse_target(path, b"q=12", "GET", max_url_length=len(path) + 4)
    assert too_long.problem is ReasonCode.UNSAFE_URL
    assert "longer than" in too_long.detail


def test_no_slash_after_host_is_not_roblox() -> None:
    """v1 parity: `^[a-z]+\\.roblox\\.com/` needed a slash after the host."""
    assert parse_target(b"/games.roblox.com", b"", "GET").problem is ReasonCode.NOT_ROBLOX


def test_problem_target_keeps_the_decoded_text_for_ignored_paths() -> None:
    """The abuse pipeline matches ignored paths (`favicon.ico`) against `target` before the URL checks."""
    result = parse_target(b"/.well-known/appspecific/com.chrome.devtools.json", b"", "GET")
    assert result.problem is ReasonCode.NOT_ROBLOX
    assert result.target == ".well-known/appspecific/com.chrome.devtools.json"
    assert parse_target(b"/favicon.ico", b"", "POST").target == "favicon.ico"


def test_parse_never_raises_on_garbage() -> None:
    for raw in (b"", b"/", b"//", b"/%", b"/\xff\xfe", b"\x00", "/\udcff".encode("utf-8", "surrogatepass")):
        result = parse_target(raw, b"\xff=\xfe", "GET")
        assert result.problem is not None


def test_strict_allowlist_and_custom_hosts() -> None:
    assert parse_target(b"/www.roblox.com/x", b"", "GET").problem is ReasonCode.HOST_NOT_ALLOWED
    assert parse_target(b"/www.roblox.com/x", b"", "GET", strict_host_allowlist=False).ok
    custom = parse_target(b"/www.roblox.com/x", b"", "GET", allowed_hosts=frozenset({"www.roblox.com"}))
    assert custom.ok
    assert "games.roblox.com" in DEFAULT_ALLOWED_HOSTS


def test_quote_path_round_trip() -> None:
    assert quote_path("/v1/a b/café/it's") == "/v1/a%20b/caf%C3%A9/it's"
    assert build_upstream_url("games.roblox.com", "/v1/games", [("ids", "1"), ("ids", "2")]) == (
        "https://games.roblox.com/v1/games?ids=1&ids=2"
    )
    assert build_upstream_url("games.roblox.com", "", []) == "https://games.roblox.com/"


_names = st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00\r\n"), min_size=1)
_values = st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00\r\n"))


@settings(max_examples=200, deadline=None)
@given(st.lists(st.tuples(_names, _values), max_size=8))
def test_property_query_round_trip(pairs: list[tuple[str, str]]) -> None:
    """Any caller query (repeats and odd characters included) survives parse and re-encoding in order."""
    pairs = [(name, value) for name, value in pairs if name != "prettyprint"]
    encoded = encode_query(pairs).encode("utf-8")
    result = parse_target(b"/games.roblox.com/v1/games", encoded, "GET", max_url_length=10**6)
    assert result.ok, result.detail
    assert list(result.query) == pairs
    reparsed = parse_qsl(urlsplit(result.upstream_url).query, keep_blank_values=True)
    assert reparsed == list(result.query)


_segment = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters='/%?#<>"`\\'), min_size=1
).filter(lambda s: s not in (".", ".."))


@settings(max_examples=200, deadline=None)
@given(st.lists(_segment, min_size=1, max_size=6))
def test_property_path_round_trip(segments: list[str]) -> None:
    """A decoded path re-encodes to a raw path that parses back to the same decoded path."""
    path = "/" + "/".join(segments)
    raw = b"/games.roblox.com" + quote_path(path).encode("ascii")
    result = parse_target(raw, b"", "GET", max_url_length=10**6)
    assert result.ok, result.detail
    assert result.path == path
