"""Ingress review, SSRF lens: an expanded hostile corpus and properties for the target validator (plan 9.10).

What this is
    Probes for `proxy/validate.py` (`parse_target`, `parse_upstream_url`, `parse_redirect`) and the upstream
    layer's own redirect check (`upstream/service.py is_roblox_https_url`), beyond the plan 9.10 list already in
    `test_ssrf.py`: percent encodings of every host byte, double encoding, overlong and invalid UTF-8, Unicode
    look-alikes and invisible characters, every IPv4 and IPv6 spelling, ports, user info, dots, CR and LF, plus
    property tests (Hypothesis) that tie the parse to what httpx would actually connect to.

Why it exists
    The host allowlist is Roxy's SSRF control. A single spelling that the validator accepts but httpx resolves to
    another host, or a path the rules see differently from the path Roblox receives, would defeat it. Each probe
    fails if that property breaks.

How it works
    Corpus cases call the validator directly with the raw bytes uvicorn would hand over (`scope["raw_path"]`).
    Property tests generate raw paths from a hostile alphabet and assert: an accepted parse names an allowed host,
    its upstream URL re-parses (by the validator and by httpx) to the same host, path and query, and the URL the
    upstream service builds from the decoded path (`f"https://{host}{path}"`, unencoded) means the same thing to
    httpx.

What to read next
    `roxy/proxy/validate.py`, `tests/security/test_ssrf.py`, then `test_ingress_cache_poisoning.py`.
"""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import unquote, unquote_to_bytes, urlencode, urljoin

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from roxy.core.reasons import Egress, ReasonCode
from roxy.proxy.validate import DEFAULT_ALLOWED_HOSTS, parse_redirect, parse_target, parse_upstream_url
from roxy.upstream.service import UpstreamService, is_roblox_https_url

NR = ReasonCode.NOT_ROBLOX
HNA = ReasonCode.HOST_NOT_ALLOWED
UNSAFE = ReasonCode.UNSAFE_URL

# (id, raw path bytes, raw query bytes, expected problem)
EXPANDED: list[tuple[str, bytes, bytes, ReasonCode]] = [
    # --- percent encodings inside the host ------------------------------------------------------------------------
    ("enc_letter_in_host", b"/%67ames.roblox.com/x", b"", NR),
    ("enc_trailing_dot", b"/games.roblox.com%2e/x", b"", NR),
    ("enc_colon_port", b"/games.roblox.com%3A443/x", b"", NR),
    ("enc_hash", b"/games.roblox.com%23/x", b"", NR),
    ("enc_question", b"/games.roblox.com%3F/x", b"", NR),
    ("enc_space_after", b"/games.roblox.com%20/x", b"", NR),
    ("enc_space_before", b"/%20games.roblox.com/x", b"", NR),
    ("enc_crlf_host", b"/games.roblox.com%0d%0a/x", b"", NR),
    ("enc_nul_host", b"/games.roblox.com%00/x", b"", NR),
    ("double_enc_dot_host", b"/games%252eroblox.com/x", b"", NR),
    ("double_enc_slash_host", b"/evil.com%252f.roblox.com/x", b"", NR),
    ("overlong_dot_host", b"/games%C0%AEroblox.com/x", b"", NR),
    ("enc_zero_width", b"/games.roblox.com%E2%80%8B/x", b"", NR),
    # --- raw control and separator bytes in the host -----------------------------------------------------------------
    ("raw_space", b"/games.roblox.com /x", b"", NR),
    ("raw_tab", b"/games.roblox.com\t/x", b"", NR),
    ("raw_crlf", b"/games.roblox.com\r\n/x", b"", NR),
    ("raw_nul", b"/games.roblox.com\x00/x", b"", NR),
    ("raw_del", b"/games.roblox.com\x7f/x", b"", NR),
    ("raw_semicolon", b"/games.roblox.com;evil.com/x", b"", NR),
    ("raw_comma", b"/games.roblox.com,evil.com/x", b"", NR),
    ("raw_underscore", b"/games_x.roblox.com/x", b"", NR),
    # --- Unicode look-alikes and invisible characters (raw UTF-8 and str.lower() traps) ------------------------------
    ("zero_width_space", "/games.roblox.com​/x".encode(), b"", NR),
    ("cyrillic_o", "/games.roblox.cоm/x".encode(), b"", NR),
    ("fullwidth_letters", "/ｇａｍｅｓ.roblox.com/x".encode(), b"", NR),
    ("fullwidth_slash", "/games.roblox.com／evil/x".encode(), b"", NR),
    ("ideographic_trailing_dot", "/games.roblox.com。/x".encode(), b"", NR),
    ("dotless_i", "/ıtems.roblox.com/x".encode(), b"", NR),
    ("dotted_capital_i", "/İnventory.roblox.com/x".encode(), b"", NR),
    ("kelvin_sign", "/Katalog.roblox.com/x".encode(), b"", NR),
    ("long_s", "/ſearch.roblox.com/x".encode(), b"", NR),
    ("right_to_left_override", "/games.roblox.com‮/x".encode(), b"", NR),
    ("combining_dot", "/games.roblox.cȯm/x".encode(), b"", NR),
    ("invalid_utf8_host", b"/games.roblox.com\xff/x", b"", NR),
    # --- IP literals -------------------------------------------------------------------------------------------------
    ("ipv4_short", b"/127.1/x", b"", NR),
    ("ipv4_zero", b"/0/x", b"", NR),
    ("ipv4_all_zero", b"/0.0.0.0/x", b"", NR),
    ("ipv4_wildcard_dns", b"/127.0.0.1.nip.io/x", b"", NR),
    ("ipv6_mapped_hex", b"/[::ffff:7f00:1]/x", b"", NR),
    ("ipv6_long_loopback", b"/[0:0:0:0:0:0:0:1]/x", b"", NR),
    ("ipv6_unspecified", b"/[::]/x", b"", NR),
    ("ipv6_zone", b"/[fe80::1%25eth0]/x", b"", NR),
    ("ipv6_unbracketed", b"/::1/x", b"", NR),
    ("ipv6_with_port", b"/[::1]:443/x", b"", NR),
    ("ipv6_doc", b"/[2001:db8::1]/x", b"", NR),
    ("metadata_label_under_roblox", b"/169.254.169.254.roblox.com/x", b"", HNA),
    ("localhost_under_roblox", b"/localhost.roblox.com/x", b"", HNA),
    # --- ports -------------------------------------------------------------------------------------------------------
    ("empty_port", b"/games.roblox.com:/x", b"", NR),
    ("double_port", b"/games.roblox.com:443:443/x", b"", NR),
    ("port_zero", b"/games.roblox.com:0/x", b"", NR),
    ("port_plus", b"/games.roblox.com:+443/x", b"", NR),
    ("port_encoded_digits", b"/games.roblox.com:%34%34%33/x", b"", NR),
    # --- user info ---------------------------------------------------------------------------------------------------
    ("userinfo_empty_user", b"/@games.roblox.com/x", b"", NR),
    ("userinfo_trailing_at", b"/games.roblox.com@/x", b"", NR),
    ("userinfo_user", b"/user@games.roblox.com/x", b"", NR),
    ("userinfo_password_then_evil", b"/games.roblox.com:pass@evil.com/x", b"", NR),
    # --- dots --------------------------------------------------------------------------------------------------------
    ("three_trailing_dots", b"/games.roblox.com.../x", b"", NR),
    ("leading_dot", b"/.games.roblox.com/x", b"", NR),
    ("empty_label_middle", b"/games..roblox.com/x", b"", NR),
    ("empty_label_before_tld", b"/games.roblox..com/x", b"", NR),
    ("dot_segment_as_host", b"/./games.roblox.com/x", b"", NR),
    ("dotdot_segment_as_host", b"/../games.roblox.com/x", b"", NR),
    ("dot_only_host", b"/./x", b"", NR),
    # --- path: CR LF, overlong and invalid UTF-8, double encoding, dot segments, backslashes -----------------------
    ("path_lf", b"/games.roblox.com/v1/a%0Ab", b"", UNSAFE),
    ("path_cr", b"/games.roblox.com/v1/a%0db", b"", UNSAFE),
    ("path_tab", b"/games.roblox.com/v1/a%09b", b"", UNSAFE),
    ("path_nul", b"/games.roblox.com/v1/a%00", b"", UNSAFE),
    ("path_del", b"/games.roblox.com/v1/a%7F", b"", UNSAFE),
    ("overlong_dotdot", b"/games.roblox.com/v1/%C0%AE%C0%AE/x", b"", UNSAFE),
    ("overlong_slash_2byte", b"/games.roblox.com/v1%C0%AFx", b"", UNSAFE),
    ("overlong_slash_3byte", b"/games.roblox.com/v1%E0%80%AFx", b"", UNSAFE),
    ("overlong_slash_4byte", b"/games.roblox.com/v1%F0%80%80%AFx", b"", UNSAFE),
    ("utf8_surrogate", b"/games.roblox.com/v1/%ED%A0%80", b"", UNSAFE),
    ("utf8_truncated", b"/games.roblox.com/v1/%E2%82", b"", UNSAFE),
    ("double_enc_dotdot", b"/games.roblox.com/v1/%252e%252e/x", b"", UNSAFE),
    ("double_enc_percent_parts", b"/games.roblox.com/v1/%25%32%65", b"", UNSAFE),
    ("double_enc_slash", b"/games.roblox.com/v1%252Fx", b"", UNSAFE),
    ("double_enc_question", b"/games.roblox.com/v1/a%253Fb", b"", UNSAFE),
    ("dot_segment_single", b"/games.roblox.com/v1/./x", b"", UNSAFE),
    ("dot_segment_encoded_single", b"/games.roblox.com/v1/%2E/x", b"", UNSAFE),
    ("dot_segment_mixed", b"/games.roblox.com/v1/.%2e/x", b"", UNSAFE),
    ("dot_segment_mixed_case", b"/games.roblox.com/v1/%2e%2E/x", b"", UNSAFE),
    ("dot_segment_trailing", b"/games.roblox.com/v1/..", b"", UNSAFE),
    ("traversal_with_encoded_slash", b"/games.roblox.com/..%2f..%2fevil.com", b"", UNSAFE),
    ("backslash_traversal", b"/games.roblox.com/v1/..%5c..%5cx", b"", UNSAFE),
    ("encoded_fragment", b"/games.roblox.com/v1/a%23b", b"", UNSAFE),
    # --- query: CR LF and NUL in names or values ----------------------------------------------------------------------
    ("query_crlf_value", b"/games.roblox.com/v1/games", b"a=%0d%0aHost:%20evil.com", UNSAFE),
    ("query_lf_name", b"/games.roblox.com/v1/games", b"a%0A=1", UNSAFE),
    ("query_nul_value", b"/games.roblox.com/v1/games", b"a=%00", UNSAFE),
    ("query_raw_cr", b"/games.roblox.com/v1/games", b"a=\r1", UNSAFE),
    ("query_too_many_fields", b"/games.roblox.com/v1/games", b"&".join(b"a=1" for _ in range(1001)), UNSAFE),
]


@pytest.mark.parametrize(("case_id", "raw", "query", "problem"), EXPANDED, ids=[case[0] for case in EXPANDED])
def test_expanded_hostile_corpus_refused(case_id: str, raw: bytes, query: bytes, problem: ReasonCode) -> None:
    for method in ("GET", "POST", "HEAD", "DELETE"):
        result = parse_target(raw, query, method)
        assert result.problem is problem, (case_id, method, result.problem, result.detail)
        assert not result.ok


def test_non_strict_mode_never_widens_beyond_roblox_com() -> None:
    """With `strict_host_allowlist` off, only roblox.com names pass; no encoding or spelling widens that."""
    for case_id, raw, query, problem in EXPANDED:
        if problem is NR:
            assert parse_target(raw, query, "GET", strict_host_allowlist=False).problem is NR, case_id


def test_query_shapes_that_must_stay_accepted() -> None:
    """Characters with no meaning to Roblox stay data: they are re-encoded, never interpreted."""
    for query in (b"a=%2526", b"a=%3B%23%3F", b"a=%E2%80%A8", b"a=1;b=2", b"%26=%3D"):
        result = parse_target(b"/games.roblox.com/v1/games", query, "GET")
        assert result.ok, (query, result.detail)
        for ch in "\r\n ":
            assert ch not in result.upstream_url, (query, ch)


# --- absolute URLs: parse_upstream_url, parse_redirect and the upstream layer's own check -----------------------------

ABSOLUTE_HOSTILE = [
    "https://games.roblox.com:443@evil.com/",
    "https://games.roblox.com%40evil.com/",
    "https://games.roblox.com\\@evil.com/",
    "https://evil.com\\.games.roblox.com/",
    "https://evil.com#@games.roblox.com/",
    "https://evil.com?@games.roblox.com/",
    "https://games.roblox.com:443:80/",
    "https://games.roblox.com:8443/",
    "https://[::ffff:127.0.0.1]/",
    "https://[::1]:443/",
    "https://127.0.0.1:443/",
    "https://0x7f.1/",
    "https://games。roblox。com/",
    "https://games.roblox.com／evil/",
    "https://gаmes.roblox.com/",
    "https://evil.com%2f.roblox.com/",
    "https://evil.com%23.games.roblox.com/",
    "http://games.roblox.com/",
    "HTTP://games.roblox.com/",
    "javascript:alert(1)//games.roblox.com/",
    "file:///etc/passwd",
    "//evil.com/",
    "https:/evil.com/",
    "https:evil.com/",
    "https://games.roblox.com.evil.com/",
    "https://www.roblox.com/",
    "https://evil.com\n.games.roblox.com/",
    "https://evil.com\t.games.roblox.com/",
    "https://games.roblox.com\r\n.evil.com/",
]


@pytest.mark.parametrize("url", ABSOLUTE_HOSTILE)
def test_absolute_hostile_urls_refused_by_both_validators(url: str) -> None:
    assert not parse_upstream_url(url).ok, url
    assert not is_roblox_https_url(url, DEFAULT_ALLOWED_HOSTS), url


@pytest.mark.parametrize(
    "location",
    [
        "//evil.example/x",
        "\\\\evil.example/x",
        "/\\evil.example/x",
        "https:\\\\evil.example/x",
        "https://evil.example%2f@games.roblox.com/",
        " https://evil.example/x",
        "https://games.roblox.com@evil.example/",
        "\thttps://evil.example/",
    ],
)
def test_redirects_to_another_host_are_refused(location: str) -> None:
    result = parse_redirect("https://games.roblox.com/v1/games", location)
    assert not result.ok or result.host == "games.roblox.com", (location, result.host, result.detail)


# --- properties ------------------------------------------------------------------------------------------------------

_HOST_TOKENS = st.sampled_from(
    [
        "games.roblox.com",
        "GAMES.ROBLOX.COM",
        "games.roblox.com.",
        "evil.com",
        "roblox.com",
        "127.0.0.1",
        "[::1]",
        "games.roblox.com:443",
        "user@games.roblox.com",
        "games.roblox.com@evil.com",
        "%67ames.roblox.com",
        "gаmes.roblox.com",
        "Katalog.roblox.com",
        "thumbnails.roblox.com",
        "",
    ]
)
_PATH_ATOMS = st.sampled_from(
    [
        "v1",
        "games",
        "..",
        ".",
        "",
        "%2e",
        "%2E%2e",
        "%2f",
        "%252f",
        "%5c",
        "%00",
        "%0d%0a",
        "%C0%AE",
        "%E2%80%A8",
        "%3F",
        "%23",
        "%25",
        "%20",
        ";x=1",
        "@",
        ":",
        "café",
        "a b",
        "[x]",
        "{x}",
        "|",
        "^",
        "~",
        "%7e",
        "123",
    ]
)


_ACCEPTED_HOSTS = st.sampled_from(
    ["games.roblox.com", "GAMES.ROBLOX.COM", "Games.Roblox.Com.", "thumbnails.roblox.com", "users.roblox.com."]
)
_ACCEPTED_ATOMS = st.sampled_from(
    [
        "v1",
        "games",
        "",
        "...",
        "..;",
        ";x=1",
        "%3B",
        "@",
        ":",
        "café",
        "caf%C3%A9",
        "%E2%80%A8",
        "%C2%85",
        "a%20b",
        "[x]",
        "{x}",
        "|",
        "^",
        "~",
        "%7e",
        "123",
        "!$&'()*+,=",
    ]
)


@st.composite
def raw_targets(draw: st.DrawFn) -> bytes:
    """Mostly targets the validator accepts (so the property has something to check), some hostile ones."""
    hostile = draw(st.integers(0, 3)) == 0
    host = draw(_HOST_TOKENS if hostile else _ACCEPTED_HOSTS)
    atoms = st.one_of(_PATH_ATOMS, _ACCEPTED_ATOMS) if hostile else _ACCEPTED_ATOMS
    segments = draw(st.lists(atoms, min_size=0, max_size=6))
    return ("/" + host + "/" + "/".join(segments)).encode("utf-8")


_QUERY_ATOMS = st.sampled_from(
    ["a=1", "a=", "a", "ids=1", "ids=2", "%26=%3D", "b=%2B", "b=+", "b=%20", "c=%25", "prettyprint=true", "d=%C3%A9"]
)


@given(raw=raw_targets(), query=st.lists(_QUERY_ATOMS, max_size=5))
@settings(max_examples=600, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_property_accepted_targets_mean_one_thing_everywhere(raw: bytes, query: list[str]) -> None:
    """An accepted target names an allowed host, and the validator, httpx and the upstream service all agree on
    host, path and query: no spelling reaches a different host or a different path than the rules matched."""
    query_bytes = "&".join(query).encode()
    result = parse_target(raw, query_bytes, "GET")
    if not result.ok:
        return
    assert result.host in DEFAULT_ALLOWED_HOSTS
    for ch in "\r\n\x00 \t":
        assert ch not in result.upstream_url
    # The validator's own upstream URL re-parses to the same target (idempotent, nothing re-interpreted).
    again = parse_upstream_url(result.upstream_url)
    assert again.ok, again.detail
    assert (again.host, again.path, again.query) == (result.host, result.path, result.query)
    # httpx connects to exactly this host on 443, and decodes the path to exactly what the rules matched.
    url = httpx.URL(result.upstream_url)
    assert (url.scheme, url.host, url.port) == ("https", result.host, None)
    assert unquote_to_bytes(url.raw_path.split(b"?", 1)[0]).decode("utf-8") == result.path
    # The URL `upstream/service.py _normalize` sends (decoded path, NOT re-encoded) means the same to httpx.
    service_url = f"https://{result.host}{result.path}" + (f"?{urlencode(result.query)}" if result.query else "")
    sent = httpx.URL(service_url)
    assert sent.host == result.host
    assert unquote(sent.raw_path.split(b"?", 1)[0].decode("ascii")) == result.path
    assert sent.query == url.query


@given(
    location=st.lists(
        st.sampled_from([*"/\\@:.%?#[]ae2fG \t", "evil.com", "games.roblox.com", "https:", "//", "443"]),
        max_size=12,
    ).map("".join)
)
@settings(max_examples=600, deadline=None)
def test_property_redirect_check_agrees_with_httpx(location: str) -> None:
    """Whatever the upstream layer's redirect check accepts, httpx would connect to an allowed roblox.com host."""
    try:
        target = urljoin("https://games.roblox.com/v1/games", location)
    except ValueError:
        return  # see test_malformed_redirect_location_is_refused_not_raised
    if not is_roblox_https_url(target, DEFAULT_ALLOWED_HOSTS):
        return
    try:
        url = httpx.URL(target)
    except httpx.InvalidURL:
        return  # httpx refuses it: nothing is sent
    assert url.scheme == "https"
    assert url.host in DEFAULT_ALLOWED_HOSTS
    assert url.port in (None, 443)


# --- the upstream layer's redirect helper on a malformed Location -----------------------------------------------------


@pytest.mark.parametrize("location", ["//[", "https://[x/", "http://[::1", "https://games.roblox.com:99999/x"])
def test_malformed_redirect_location_is_refused_not_raised(location: str) -> None:
    """Ingress finding (fixed): `_redirect_url` used to call urljoin() unguarded, so a Location such as `//[`
    raised after Roblox answered, skipping the call's bookkeeping and answering 500. It is now "do not follow";
    the service relays Roblox's own 3xx (`tests/unit/upstream/test_upstream_service.py`
    `test_malformed_redirect_location_is_answered_not_raised` runs the whole fetch)."""
    service = object.__new__(UpstreamService)  # the helper reads only its arguments
    call = SimpleNamespace(
        method="GET",
        cfg=SimpleNamespace(allowed_hosts=DEFAULT_ALLOWED_HOSTS, strict_hosts=True),
        mode="caller",
        rules=None,
        rules_target="games.roblox.com/v1/games",
    )
    exchange = SimpleNamespace(headers={"location": location})
    current = "https://games.roblox.com/v1/games"
    target = service._redirect_url(call, Egress.DIRECT, current, exchange)  # type: ignore[arg-type]
    assert target is None
