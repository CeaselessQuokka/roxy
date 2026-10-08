"""Cache keys (plan 4.4 row 53, 54; LEAD_NOTES decision 9; plan 9.13 vary rule).

The v1 worked examples come from `.remake/v1notes/cache.md` section 3.4 (computed with the v1 functions), so plain
keys keep their v1 ids. The poisoning case is v1 bug B12, which v2 closes by percent-encoding names and values.
"""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from roxy.cache.keys import (
    CRED_SUFFIX,
    VARY_HEADERS,
    VaryMismatchError,
    assert_forward_list,
    build_key,
    key_id,
    pairs_from_mapping,
    sort_csv,
    split_target,
)
from roxy.core.reasons import AuthClass
from roxy.rules.models import CacheRuleRow


def _v1(
    method: str, dst: str, params: dict[str, list[str]], body: bytes | None = None, ignored: set[str] | None = None
):
    host, path = split_target(dst)
    return build_key(method, host, path, pairs_from_mapping(params), body, ignored=frozenset(ignored or ()))


@pytest.mark.parametrize(
    ("method", "dst", "params", "ignored", "text", "expected_id"),
    [
        (
            "GET",
            "Games.Roblox.com/v1/games/votes",
            {"universeIds": ["9967558039"]},  # prettyprint already removed by the proxy (row 3)
            None,
            "GET games.roblox.com/v1/games/votes?universeIds=9967558039",
            "f9581fd96456d6b88a30dcfd",
        ),
        (
            "GET",
            "games.roblox.com/v1/games/votes",
            {"universeIds": ["1", "2"], "other": ["2"]},
            None,
            "GET games.roblox.com/v1/games/votes?other=2&universeIds=1&universeIds=2",
            "ef8c27b31891de87a32e6a81",
        ),
        (
            "GET",
            "games.roblox.com/v1/games/votes",
            {"other": ["2"], "universeIds": ["1", "2"]},
            None,
            "GET games.roblox.com/v1/games/votes?other=2&universeIds=1&universeIds=2",
            "ef8c27b31891de87a32e6a81",
        ),
        (
            "GET",
            "games.roblox.com/v1/games/9583680112/votes",
            {"t": ["1000"]},
            {"t"},
            "GET games.roblox.com/v1/games/9583680112/votes",
            "13d0ab3fbac51a8babe2c801",
        ),
        (
            "GET",
            "games.roblox.com/v1/games",
            {"a": ["2"], "B": ["1"], "_": ["3"]},
            None,
            "GET games.roblox.com/v1/games?B=1&_=3&a=2",
            "23b0af36ca78c7aab1b4f211",
        ),
        (
            "POST",
            "users.roblox.com/v1/usernames/users",
            {},
            None,
            "POST users.roblox.com/v1/usernames/users",
            "ffd5bfffa49362c14edc86e1",
        ),
    ],
)
def test_v1_worked_examples_keep_their_ids(method, dst, params, ignored, text, expected_id) -> None:
    key = _v1(method, dst, params, b"" if method == "POST" else None, ignored)
    assert key.text == text
    assert key.id == expected_id
    assert key.id == key_id(text) == hashlib.sha256(text.encode()).hexdigest()[:24]


def test_cache_key_poisoning_case_lead_notes_9() -> None:
    """v1 B12: one odd value `1&universeIds=2` and two plain values shared id dab5b8ca1a3c7410d076dfc5."""
    one_odd = build_key("GET", "games.roblox.com", "v1/games/votes", [("universeIds", "1&universeIds=2")], None)
    two_plain = build_key(
        "GET", "games.roblox.com", "v1/games/votes", [("universeIds", "1"), ("universeIds", "2")], None
    )
    assert two_plain.id == "dab5b8ca1a3c7410d076dfc5"  # plain values keep the v1 id
    assert one_odd.text == "GET games.roblox.com/v1/games/votes?universeIds=1%26universeIds%3D2"
    assert one_odd.id != two_plain.id


def test_empty_value_and_missing_equals_share_a_key_only_when_forwarded_the_same() -> None:
    # Both forms reach the key as ("a", ""); the proxy forwards both as `a=` (the key follows what goes upstream).
    assert build_key("GET", "h.roblox.com", "x", [("a", "")], None).text == "GET h.roblox.com/x?a="


def test_percent_and_spaces_cannot_fake_structure() -> None:
    literal = build_key("GET", "h.roblox.com", "x", [("q", "%2C")], None)
    comma = build_key("GET", "h.roblox.com", "x", [("q", ",")], None)
    assert literal.id != comma.id
    spaced = build_key("POST", "h.roblox.com", "x", [("q", "a #b")], b"")
    assert " #" not in spaced.text.split("?", 1)[1]


def test_path_question_mark_is_not_a_query() -> None:
    in_path = build_key("GET", "h.roblox.com", "v1/x?a=1", [], None)
    in_query = build_key("GET", "h.roblox.com", "v1/x", [("a", "1")], None)
    assert in_path.id != in_query.id
    assert in_path.text == "GET h.roblox.com/v1/x%3Fa=1"


def test_host_lowercased_path_case_kept_head_is_get_one_slash_dropped() -> None:
    upper = build_key("head", "GAMES.Roblox.com", "/v1/Games", [], None)
    assert upper.text == "GET games.roblox.com/v1/Games"
    assert upper.method == "GET"
    assert build_key("GET", "games.roblox.com", "//v1/Games", [], None).text == "GET games.roblox.com//v1/Games"
    assert build_key("GET", "games.roblox.com", "", [], None).text == "GET games.roblox.com"


def test_repeated_values_keep_arrival_order() -> None:
    first = build_key("GET", "h.roblox.com", "x", [("ids", "1"), ("ids", "2")], None)
    second = build_key("GET", "h.roblox.com", "x", [("ids", "2"), ("ids", "1")], None)
    assert first.id != second.id


def test_ignored_params_are_exact_case_sensitive_and_remembered() -> None:
    key = build_key("GET", "h.roblox.com", "x", [("t", "1"), ("T", "2"), ("t", "3")], None, ignored=frozenset({"t"}))
    assert key.text == "GET h.roblox.com/x?T=2"
    assert key.params == (("T", "2"),)
    assert key.stripped == ("t",)


def test_body_hash_is_full_sha256_and_get_bodies_are_ignored() -> None:
    body = b'{"usernames": ["a"]}'
    post = build_key("POST", "users.roblox.com", "v1/usernames/users", [], body)
    digest = hashlib.sha256(body).hexdigest()
    assert post.text == f"POST users.roblox.com/v1/usernames/users #{digest}"
    assert post.body_hash == digest
    assert build_key("GET", "users.roblox.com", "x", [], body).body_hash is None
    other = build_key("POST", "users.roblox.com", "v1/usernames/users", [], b'{"usernames": ["b"]}')
    assert other.id != post.id


def test_normalization_flags_sort_csv_and_casefold_path() -> None:
    rule = CacheRuleRow(
        id=7,
        pattern="games.roblox.com/v1/games",
        type="glob",
        ttl=60,
        normalize_flags=("sort_csv:universeIds", "casefold_path"),
    )
    first = build_key("GET", "games.roblox.com", "v1/Games", [("universeIds", "3,1,20,2")], None, rule)
    second = build_key("GET", "games.roblox.com", "v1/games", [("universeIds", "1,2,3,20")], None, rule)
    assert first.id == second.id
    assert first.rule_id == 7
    assert first.path == "v1/Games"  # the resend path is the caller's, not the normalized one
    assert first.params == (("universeIds", "3,1,20,2"),)


def test_sort_csv_numeric_order_and_huge_numbers() -> None:
    assert sort_csv("10,9,1") == "1,9,10"
    assert sort_csv("b,10,a,2") == "2,10,a,b"
    huge = "9" * 5000  # int() of this would raise in Python 3.12; the sort key never converts
    assert sort_csv(f"{huge},1") == f"1,{huge}"
    assert sort_csv("5") == "5"


def test_vary_headers_are_part_of_the_key() -> None:
    plain = build_key("POST", "h.roblox.com", "x", [], b"{}")
    typed = build_key("POST", "h.roblox.com", "x", [], b"{}", vary={"content-type": "application/json"})
    other = build_key("POST", "h.roblox.com", "x", [], b"{}", vary=[("content-type", "text/plain")])
    assert len({plain.id, typed.id, other.id}) == 3
    assert typed.text.endswith(" ^content-type=application%2Fjson")
    accept = build_key("GET", "h.roblox.com", "x", [], None, vary={"Accept": "*/*", "content-type": None})
    assert accept.vary == (("accept", "*/*"),)


def test_header_outside_the_vary_list_is_refused() -> None:
    with pytest.raises(VaryMismatchError):
        build_key("GET", "h.roblox.com", "x", [], None, vary={"accept-language": "fr"})


def test_vary_list_equals_the_forward_list() -> None:
    """Plan 9.13: the forwarded caller headers and the key's vary list are the same list."""
    assert_forward_list(VARY_HEADERS)
    with pytest.raises(VaryMismatchError):
        assert_forward_list(("accept", "content-type"))
    with pytest.raises(VaryMismatchError):
        assert_forward_list((*VARY_HEADERS, "accept-language"))
    scrub = pytest.importorskip("roxy.proxy.scrub")
    assert_forward_list(scrub.FORWARDED_REQUEST_HEADERS)


def test_credential_keys_never_share_an_id_with_anonymous_ones() -> None:
    anon = build_key("GET", "users.roblox.com", "v1/users/authenticated", [], None)
    cred = build_key("GET", "users.roblox.com", "v1/users/authenticated", [], None, auth_class=AuthClass.CRED)
    assert cred.text == anon.text + CRED_SUFFIX
    assert cred.id != anon.id
    assert cred.flight_key != anon.flight_key
    assert anon.marker_id not in {anon.id, cred.id}


def test_handoff_rows_have_their_own_id_per_key_and_auth_class() -> None:
    """A single-flight handoff row never shares an id with an entry or a marker, of either auth class."""
    anon = build_key("GET", "users.roblox.com", "v1/users", [("a", "1")], None)
    cred = build_key("GET", "users.roblox.com", "v1/users", [("a", "1")], None, auth_class=AuthClass.CRED)
    ids = {anon.id, anon.marker_id, anon.handoff_id, cred.id, cred.marker_id, cred.handoff_id}
    assert len(ids) == 6
    assert anon.handoff_id == build_key("GET", "users.roblox.com", "v1/users", [("a", "1")], None).handoff_id


_TEXT = st.text(alphabet="ab=&%#?^@ ,~.-_1é", max_size=4)


def _canonical(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return sorted(pairs, key=lambda pair: pair[0])


@settings(max_examples=300, deadline=None)
@given(
    st.lists(st.tuples(_TEXT, _TEXT), max_size=4),
    st.lists(st.tuples(_TEXT, _TEXT), max_size=4),
    _TEXT,
    _TEXT,
)
def test_key_text_is_one_to_one(q1, q2, p1, p2) -> None:
    """Two requests share a key exactly when they send the same path and the same parameters (in name order)."""
    k1 = build_key("GET", "h.roblox.com", "v1/" + p1, q1, None)
    k2 = build_key("GET", "h.roblox.com", "v1/" + p2, q2, None)
    same_request = p1 == p2 and _canonical(q1) == _canonical(q2)
    assert (k1.text == k2.text) == same_request
