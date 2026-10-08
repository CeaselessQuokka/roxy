"""Tests for `roxy.rules.match`: v1 parity (plan 4.8 rows 111 and 112) and pattern validation (plan 9.9).

The parity tests load the frozen v1 functions from `tests/fixtures/v1/v1_rules.py` by file path (so they do not
depend on how `tests` is laid out as packages) and compare answers over generated patterns and paths.
"""

from __future__ import annotations

import importlib.util
import os
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from roxy.rules import match
from roxy.rules.match import (
    MAX_GLOB_WILDCARDS,
    MAX_PATTERN_LENGTH,
    PatternIndex,
    PatternValidationError,
    best_match,
    compile_pattern,
    has_nested_quantifier,
    header_rule_canonical_key,
    normalize_pattern,
    normalize_target,
    path_matches,
    specificity,
    text_matches,
    validate_pattern,
    validate_regex,
)


def _load_v1() -> ModuleType:
    path = Path(__file__).resolve().parents[2] / "fixtures" / "v1" / "v1_rules.py"
    spec = importlib.util.spec_from_file_location("roxy_v1_rules_frozen", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v1 = _load_v1()

# The frozen v1 code compiles generated patterns such as "[[" with the stdlib `re`, which emits FutureWarning
# ("possible nested set"); that is expected here and says nothing about the code under test.
pytestmark = pytest.mark.filterwarnings("ignore::FutureWarning")


# --- Strategies ------------------------------------------------------------------------------------------------

# Characters seen in real paths plus troublemakers: regex metacharacters (globs must escape them), upper case
# (everything is case-insensitive), whitespace (normalization trims it), Unicode letters whose case folding differs
# between engines (Kelvin sign, long s, dotted capital I, dotless i, sharp s, Greek sigma forms), and characters the
# `regex` module and `re` put in different classes (superscripts, fractions and other numbers, combining marks,
# the separators 0x1C to 0x1F and NEL that `re` calls whitespace, a non-breaking space, a Devanagari digit).
_SEGMENT_CHARS = st.sampled_from(
    list("abcdefgxyzABCXYZ0123456789")
    + list(".-_~?=&%+()[]{}^$|\\")
    + [" ", "\t", "\n"]
    + ["\u00e9", "\u00c9", "\u00df", "\u212a", "\u017f", "\u0130", "\u0131", "\u03c2", "\u03a3"]
    + ["\u00b2", "\u00b9", "\u00bd", "\u2155", "\u0301", "\u0307", "\u0300", "\u1c00", "\u0966"]
    + ["\x1c", "\x1f", "\x85", "\xa0", "\u2028", "\u200b"]
)
_HOSTS = st.sampled_from(
    ["games.roblox.com", "users.roblox.com", "thumbnails.roblox.com", "GROUPS.Roblox.com", "catalog.roblox.com"]
)
_WORDS = st.sampled_from(["v1", "v2", "games", "users", "votes", "servers", "batch", "icons", "123", "Public", ""])


@st.composite
def _segment(draw: st.DrawFn, *, allow_star: bool) -> str:
    kind = draw(st.integers(min_value=0, max_value=3))
    if kind == 0:
        text = draw(_WORDS)
    elif kind == 1:
        text = draw(st.text(_SEGMENT_CHARS, max_size=5))
    elif kind == 2 and allow_star:
        text = draw(st.sampled_from(["*", "**", "a*", "*z", "*1*", "v*s"]))
    else:
        text = draw(_WORDS) + draw(st.text(_SEGMENT_CHARS, max_size=2))
    return text


@st.composite
def glob_patterns(draw: st.DrawFn) -> str:
    """Raw admin input for a glob (before normalization): optional slashes and spaces around a host and path."""
    head = draw(st.one_of(_HOSTS, _segment(allow_star=True)))
    segments = draw(st.lists(_segment(allow_star=True), max_size=4))
    body = "/".join([head, *segments])
    lead = draw(st.sampled_from(["", "/", "//", " ", " /"]))
    tail = draw(st.sampled_from(["", "/", "//", " "]))
    return lead + body + tail


@st.composite
def paths(draw: st.DrawFn, *, near: str | None = None, max_segments: int = 6) -> str:
    """A request path; when `near` is given, often a concrete instance of that pattern plus a subpath."""
    if near is not None and draw(st.booleans()):
        filled = near.replace("*", draw(st.sampled_from(["", "123", "abc", "x/y", "A.B"])))
        extra = draw(st.lists(_segment(allow_star=False), max_size=2))
        return "/".join([filled, *extra]) if extra else filled
    head = draw(st.one_of(_HOSTS, _segment(allow_star=False)))
    segments = draw(st.lists(_segment(allow_star=False), max_size=max_segments))
    lead = draw(st.sampled_from(["", "/", " "]))
    return lead + "/".join([head, *segments])


# Regex building blocks. Some combinations are invalid on purpose (both sides must then never match).
_REGEX_TOKENS = st.sampled_from(
    [
        "games",
        "users",
        "v1",
        "roblox",
        "/",
        r"\.",
        ".",
        r"\d",
        r"\D",
        r"\w",
        r"\W",
        r"\S",
        r"\b",
        "[a-z]",
        "[^/]",
        "[0-9]",
        "^",
        "$",
        "*",
        "+",
        "?",
        "{1,3}",
        "{2}",
        "(",
        ")",
        "(?:",
        "|",
        "\\",
        "[",
        "]",
        "{",
        r"\p{L}",
        "(?i)",
        "(?P<n>",
        r"\Z",
        r"\A",
        "\u212a",
        "\u017f",
        "K",
        "S",
        # Text the `regex` module reads differently from `re` unless match.py escapes it (POSIX classes, fuzzy
        # matching), plus the contexts the escaping must look through (comments, verbose mode, named chars).
        "[[:alpha:]]",
        "[:",
        ":]",
        ":",
        "{e<=1}",
        "{1,",
        "{,2}",
        "{}",
        "(?#[)",
        "(?x)",
        "(?x:",
        "#",
        " ",
        "\n",
        r"\N{LATIN SMALL LETTER A}",
        "[]a]",
        "&&",
        "--",
        "a",
        "p",
        # Classes and anchors whose meaning depends on Unicode tables or flags (spec review finding 1).
        r"\s",
        r"\B",
        "i",
        "I",
        "ı",
        "[²-¹]",
        "[^a-z]",
        "(?a)",
        "(?s)",
        "(?m)",
        "(?-i:",
        # No backreferences here: a case-insensitive backreference is the one documented approximation of
        # rules/re_compat.py (it differs from `re` only for a few letters such as dotted capital I).
        "(?<=a)",
        "(?!b)",
        "*?",
        "++",
    ]
)


@st.composite
def regex_patterns(draw: st.DrawFn) -> str:
    tokens = draw(st.lists(_REGEX_TOKENS, min_size=1, max_size=8))
    lead = draw(st.sampled_from(["", "/", " ", " //"]))
    tail = draw(st.sampled_from(["", " "]))
    return lead + "".join(tokens) + tail


# ROXY_PARITY_EXAMPLES raises the budget for a soak run (for example 20000) without editing the test.
_PARITY_SETTINGS = settings(
    max_examples=int(os.environ.get("ROXY_PARITY_EXAMPLES", "400")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


# --- Parity: the plan's test id --------------------------------------------------------------------------------


@_PARITY_SETTINGS
@given(data=st.data())
def test_v1_rule_match_parity(data: st.DataObject) -> None:
    """Globs: normalization, specificity, matching and cache-purge matching agree with v1 exactly."""
    raw = data.draw(glob_patterns(), label="raw_pattern")
    stored_v1 = v1.normalize_pattern(raw, "glob")
    stored_v2 = normalize_pattern(raw, "glob")
    assert stored_v2 == stored_v1

    assert specificity(stored_v2, "glob") == v1._specificity(stored_v1, "glob")
    assert compile_pattern(stored_v2, "glob").specificity == v1._specificity(stored_v1, "glob")

    path = data.draw(paths(near=stored_v1), label="path")
    target = v1._norm(path)
    assert normalize_target(path) == target
    assert compile_pattern(stored_v2, "glob").matches(target) == v1._matches(stored_v1, target, "glob")
    assert match.matches(stored_v2, target, "glob") == v1._matches(stored_v1, target, "glob")
    assert path_matches(stored_v2, path, "glob") == v1.path_matches(stored_v1, path, "glob")


@_PARITY_SETTINGS
@given(data=st.data())
def test_v1_rule_match_parity_regex(data: st.DataObject) -> None:
    """Regexes: not lowercased, IGNORECASE, search not match, invalid never matches; all as v1."""
    raw = data.draw(regex_patterns(), label="raw_pattern")
    stored_v1 = v1.normalize_pattern(raw, "regex")
    stored_v2 = normalize_pattern(raw, "regex")
    assert stored_v2 == stored_v1
    assert specificity(stored_v2, "regex") == v1._specificity(stored_v1, "regex")
    # Paths stay short so the v1 engine (no timeout) finishes quickly even on a backtracking-prone pattern.
    path = data.draw(paths(max_segments=2).filter(lambda p: len(p) <= 24), label="path")
    target = v1._norm(path)
    assert compile_pattern(stored_v2, "regex").matches(target) == v1._matches(stored_v1, target, "regex")
    assert path_matches(stored_v2, path, "regex") == v1.path_matches(stored_v1, path, "regex")


@dataclass(frozen=True)
class _Rule:
    id: int
    pattern: str
    type: str


@_PARITY_SETTINGS
@given(data=st.data())
def test_v1_best_match_parity(data: st.DataObject) -> None:
    """The winning rule (highest specificity, first inserted on ties) is the one v1 picked."""
    raw_rules = data.draw(
        st.lists(
            st.tuples(st.one_of(glob_patterns(), regex_patterns()), st.sampled_from(["glob", "glob", "regex"])),
            min_size=1,
            max_size=8,
        ),
        label="rules",
    )
    # Build the v1 store the way v1's setters did: keyed by the normalized pattern, so re-adding a pattern
    # keeps its original insertion position and replaces its type.
    v1_store: dict[str, dict[str, str]] = {}
    for raw, kind in raw_rules:
        stored = v1.normalize_pattern(raw, kind)
        if not stored or (kind == "regex" and not v1.valid_regex(stored)):
            continue  # v1 refused these at save time
        v1_store[stored] = {"Type": kind}
    # v2 rows get ascending ids in v1 insertion order (what the migrator does), shuffled to prove order does not
    # matter, only ids do.
    rules = [_Rule(i + 1, pattern, rule["Type"]) for i, (pattern, rule) in enumerate(v1_store.items())]
    shuffled = data.draw(st.permutations(rules), label="row_order")

    candidates = [p for p in v1_store if v1_store[p]["Type"] == "glob"]
    near = data.draw(st.sampled_from(candidates)) if candidates else None
    path = data.draw(paths(near=near, max_segments=3).filter(lambda p: len(p) <= 40), label="path")

    expected = v1.match_best(v1_store, path)
    expected_pattern = None if expected is None else expected["Pattern"]

    winner = best_match(shuffled, path)
    assert (None if winner is None else winner.pattern) == expected_pattern

    index = PatternIndex.from_rules(shuffled)
    indexed = index.best(path)
    assert (None if indexed is None else indexed.pattern) == expected_pattern
    assert index.any_match(path) == (expected is not None)


@_PARITY_SETTINGS
@given(
    mode=st.sampled_from(["contains", "exact", "regex", "other"]),
    needle=st.one_of(regex_patterns(), st.text(_SEGMENT_CHARS, max_size=6)),
    target=st.one_of(st.none(), st.text(_SEGMENT_CHARS, max_size=16)),
)
def test_v1_text_rule_parity(mode: str, needle: str, target: str | None) -> None:
    """User-Agent and header needles match exactly as v1's `_user_agent_matches` and `rule_hit` did."""
    ua_rule = {"Needle": needle, "Mode": mode}
    assert text_matches(mode, needle, target) == v1._user_agent_matches(ua_rule, target)
    v1_header = bool(needle) and v1._header_field_matches(mode, needle, target)  # rule_hit skips empty needles
    assert text_matches(mode, needle, target) == v1_header


@given(
    scope=st.sampled_from(["key", "value", "either"]),
    mode=st.sampled_from(["contains", "exact", "regex"]),
    needle=st.text(_SEGMENT_CHARS, min_size=1, max_size=10),
    header=st.one_of(st.just(""), st.text(_SEGMENT_CHARS, max_size=10)),
)
def test_header_rule_canonical_key_parity(scope: str, mode: str, needle: str, header: str) -> None:
    """Plan 4.8 row 112: the canonical id is byte for byte v1's `header|scope|mode|needle`."""
    assert header_rule_canonical_key(scope, mode, needle, header) == v1._header_rule_id(scope, mode, needle, header)


# --- Corpus parity: realistic rules against realistic paths --------------------------------------------------------

_CORPUS_RULES: list[tuple[str, str]] = [
    ("games.roblox.com", "glob"),
    ("games.roblox.com/v1/games", "glob"),
    ("games.roblox.com/v1/games/*/servers", "glob"),
    ("games.roblox.com/v1/games/*/servers/public", "glob"),
    ("games.roblox.com/v1/games/votes", "glob"),
    ("/Games.Roblox.com/v1/games/votes/", "glob"),
    ("thumbnails.roblox.com/v1/*", "glob"),
    ("thumbnails.roblox.com/v1/batch", "glob"),
    ("users.roblox.com/v1/users/*", "glob"),
    ("users.roblox.com/v1/users/*/username-history", "glob"),
    ("presence.roblox.com", "glob"),
    ("*.roblox.com/v1/*", "glob"),
    ("catalog.roblox.com/v1/search/items/details", "glob"),
    (r"^games\.roblox\.com/v1/games/\d+/favorites$", "regex"),
    (r"/^users\.roblox\.com/v1/users/\D", "regex"),
    (r"badges\.roblox\.com/v1/(universes|users)/\d+/badges", "regex"),
    (r"inventory\.roblox\.com/v\d/users/\d+/(?:items|assets)", "regex"),
    (r"ECONOMY\.ROBLOX\.COM/V2/ASSETS/\d+/DETAILS", "regex"),
    (r"groups\.roblox\.com/v1/groups/\d+$", "regex"),
    (r"\W(votes|favorites)\b", "regex"),
]

_CORPUS_PATHS: list[str] = [
    "games.roblox.com/v1/games?universeIds=1818,2017",
    "games.roblox.com/v1/games/votes?universeIds=1818",
    "games.roblox.com/v1/games/votes",
    "/games.roblox.com/v1/games/694768217/servers/Public?limit=100",
    "games.roblox.com/v1/games/694768217/servers/0",
    "games.roblox.com/v1/games/694768217/favorites",
    "games.roblox.com/v1/games/694768217/favorites/count",
    "games.roblox.com/v2/users/123/games",
    "GAMES.ROBLOX.COM/V1/GAMES",
    "thumbnails.roblox.com/v1/batch",
    "thumbnails.roblox.com/v1/users/avatar-headshot?userIds=1&size=48x48",
    "thumbnails.roblox.com/v1/assets",
    "users.roblox.com/v1/users/156",
    "users.roblox.com/v1/users/156/username-history?limit=10",
    "users.roblox.com/v1/users/authenticated",
    "users.roblox.com/v1/usernames/users",
    "presence.roblox.com/v1/presence/users",
    "badges.roblox.com/v1/universes/1818/badges?limit=100",
    "badges.roblox.com/v1/users/156/badges",
    "inventory.roblox.com/v2/users/156/items/0/1",
    "economy.roblox.com/v2/assets/1818/details",
    "groups.roblox.com/v1/groups/7",
    "groups.roblox.com/v1/groups/7/roles",
    "catalog.roblox.com/v1/search/items/details?Category=1",
    "develop.roblox.com/v1/universes/1818",
    "  /apis.roblox.com/cloud/v2/universes/1",
    "",
    "/",
]


def test_v1_rule_match_corpus_parity() -> None:
    """Every corpus rule against every corpus path agrees with v1, and so does the winner per path."""
    v1_store: dict[str, dict[str, str]] = {}
    for raw, kind in _CORPUS_RULES:
        v1_store[v1.normalize_pattern(raw, kind)] = {"Type": kind}
    rules = [_Rule(i + 1, pattern, rule["Type"]) for i, (pattern, rule) in enumerate(v1_store.items())]
    index = PatternIndex.from_rules(rules)
    for path in _CORPUS_PATHS:
        target = v1._norm(path)
        for rule in rules:
            assert compile_pattern(rule.pattern, rule.type).matches(target) == v1._matches(
                rule.pattern, target, rule.type
            ), (rule, path)
            assert path_matches(rule.pattern, path, rule.type) == v1.path_matches(rule.pattern, path, rule.type)
        expected = v1.match_best(v1_store, path)
        winner = index.best(path)
        assert (None if winner is None else winner.pattern) == (None if expected is None else expected["Pattern"])


# --- The pinned semantics, spelled out ---------------------------------------------------------------------------


def test_glob_subpath_rule_and_host_only() -> None:
    assert match.matches("games.roblox.com/v1/games", "games.roblox.com/v1/games/123/votes")
    assert match.matches("games.roblox.com/v1/games", "games.roblox.com/v1/games")
    assert not match.matches("games.roblox.com/v1/games", "games.roblox.com/v1/gamesx")
    assert match.matches("games.roblox.com", "games.roblox.com/anything/at/all")
    assert not match.matches("games.roblox.com", "games.roblox.com.evil.example/v1")


def test_glob_star_stays_inside_one_segment() -> None:
    pattern = "games.roblox.com/v1/games/*/servers"
    assert match.matches(pattern, "games.roblox.com/v1/games/694768217/servers")
    assert match.matches(pattern, "games.roblox.com/v1/games//servers")
    assert not match.matches(pattern, "games.roblox.com/v1/games/1/2/servers")


def test_glob_is_case_insensitive_and_normalized() -> None:
    assert normalize_pattern("  //Games.Roblox.com/V1/ ", "glob") == "games.roblox.com/v1/"
    assert match.matches("games.roblox.com/v1", "GAMES.roblox.com/V1/Games")


def test_regex_is_not_lowercased_and_uses_search() -> None:
    stored = normalize_pattern(r" /^users\.roblox\.com/v1/users/\D", "regex")
    assert stored == r"^users\.roblox\.com/v1/users/\D"  # \D survived (lowercasing would make it \d)
    assert match.matches(stored, "users.roblox.com/v1/users/authenticated", "regex")
    assert not match.matches(stored, "users.roblox.com/v1/users/156", "regex")
    # search, not match: an unanchored regex matches anywhere; IGNORECASE applies.
    assert match.matches(r"V1/USERS", "users.roblox.com/v1/users/156", "regex")
    # no implied trailing subpath for regexes
    assert not match.matches(r"^users\.roblox\.com$", "users.roblox.com/v1", "regex")


def test_specificity_tuples() -> None:
    assert specificity("games.roblox.com/v1/games/*/servers", "glob") == (4, 34)
    assert specificity("games.roblox.com/v1/games/123/servers", "glob") == (4, 37)
    assert specificity(r"^games\.roblox\.com/v1/\d+$", "regex") == (2, len(r"^games\.roblox\.com/v1/\d+$"))
    assert compile_pattern("a/*", "glob").specificity == (1, 2)


def test_best_match_ties_go_to_the_lowest_id() -> None:
    # Both score (1, 19): the second is one character longer but that character is a `*`.
    first = _Rule(7, "games.roblox.com/v1", "glob")
    second = _Rule(3, "games.roblox.com/*v1", "glob")
    assert specificity(first.pattern) == specificity(second.pattern)
    assert best_match([first, second], "games.roblox.com/v1/x") is second
    assert best_match([second, first], "games.roblox.com/v1/x") is second
    assert PatternIndex.from_rules([first, second]).best("games.roblox.com/v1/x") is second


def test_most_specific_rule_wins() -> None:
    broad = _Rule(1, "games.roblox.com", "glob")
    wildcard = _Rule(2, "games.roblox.com/v1/games/*/servers", "glob")
    concrete = _Rule(3, "games.roblox.com/v1/games/1/servers", "glob")
    rules = [broad, wildcard, concrete]
    assert best_match(rules, "/games.roblox.com/v1/games/1/servers/public") is concrete
    assert best_match(rules, "games.roblox.com/v1/games/2/servers") is wildcard
    assert best_match(rules, "games.roblox.com/v2/x") is broad
    assert best_match(rules, "users.roblox.com/v1") is None
    index = PatternIndex.from_rules(rules)
    assert index.matching("games.roblox.com/v1/games/1/servers") == [concrete, wildcard, broad]
    assert len(index) == 3


def test_empty_and_invalid_patterns_never_match() -> None:
    assert not match.matches("", "anything")
    assert not compile_pattern("", "glob").valid
    assert not match.matches("(", "(", "regex")
    # Valid for the `regex` module but not for Python `re`: v1 never matched it, so v2 does not either.
    assert not compile_pattern(r"\p{L}", "regex").valid
    assert not match.matches(r"\p{L}", "games", "regex")


@pytest.mark.parametrize(
    ("pattern", "targets"),
    [
        (r"[[:alpha:]]", ["a", "a]", ":]", "[]", "1"]),
        (r"a{e<=1}", ["a", "b", "a{e<=1}"]),
        (r"(?#[)a[[:alpha:]]", ["a[]", "aa", "a:]"]),
        ("(?x) a [[:alpha:]] # [ a comment\n b", ["a:]b", "aab", "a b"]),
        (r"\N{LATIN SMALL LETTER A}{e<=1}", ["a{e<=1}", "b", "a"]),
        (r"x{1, 2}", ["x{1, 2}", "xx"]),
        (r"[]a[]+", ["]", "[", "a"]),
    ],
)
def test_regex_dialect_differences_follow_python_re(pattern: str, targets: list[str]) -> None:
    """Text that the `regex` module would read as a POSIX class or fuzzy match keeps its Python `re` meaning."""
    for target in targets:
        assert compile_pattern(pattern, "regex").matches(target) == v1._matches(pattern, target, "regex"), target
        assert text_matches("regex", pattern, target) == v1._header_field_matches("regex", pattern, target)


def test_ambiguous_sets_are_refused_for_new_rules() -> None:
    with pytest.raises(PatternValidationError, match="Ambiguous character set"):
        validate_regex(r"[[:alpha:]]+")
    assert validate_regex(r"[\[:alpha:]]+") == r"[\[:alpha:]]+"


def test_wildcard_runs_collapse_without_changing_answers() -> None:
    source = match.glob_to_regex_source("a/**/b")
    assert source.count("[^/]*") == 1
    for target in ["a/x/b", "a//b", "a/x/y/b", "a/xb/b/c"]:
        assert match.matches("a/**/b", target) == v1._matches("a/**/b", target, "glob")


def test_unknown_type_is_treated_as_glob() -> None:
    assert match.kind_of("Glob") == "glob"
    assert match.matches("games.roblox.com/v1", "games.roblox.com/v1/x", "something-else")


def test_compile_cache_is_bounded() -> None:
    assert compile_pattern.cache_info().maxsize == match.COMPILE_CACHE_SIZE


# --- Timeouts (plan 9.9) -------------------------------------------------------------------------------------------


def test_regex_timeout_stops_a_pathological_pattern() -> None:
    # Validation now refuses (a|aa)+ for new rules, but a stored (imported) rule may still have it: the timeout is
    # the backstop.
    pattern = r"^(a|aa)+$"
    with pytest.raises(PatternValidationError, match="Alternatives"):
        validate_regex(pattern)
    before = match.regex_timeouts_total()
    started = time.monotonic()
    assert not compile_pattern(pattern, "regex").matches("a" * 60 + "b")
    assert time.monotonic() - started < 2.0
    assert match.regex_timeouts_total() == before + 1


def test_text_regex_timeout_counts_as_no_match() -> None:
    before = match.regex_timeouts_total()
    assert not text_matches("regex", r"^(a|aa)+$", "a" * 60 + "b")
    assert match.regex_timeouts_total() == before + 1


# --- Validation (plan 9.9) -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [r"(a+)+", r"(a*)*", r"(?:x|y+)*", r"((ab)+c)+", r"^(\w+\s?)*$", r"(a?)*", r"(?:[a-z]+/)+end", r"(a+){50}"],
)
def test_nested_quantifiers_are_refused(pattern: str) -> None:
    assert has_nested_quantifier(pattern)
    with pytest.raises(PatternValidationError, match="Nested quantifiers"):
        validate_regex(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^games\.roblox\.com/v1/games/\d+$",
        r"(\d{1,3}\.){3}\d{1,3}",
        r"(?:ab)+",
        r"(a{2})+",
        r"(a+){3}",
        r"[a-z]+/[0-9]*",
        r"(?i)roblox(?=\.com)",
    ],
)
def test_reasonable_regexes_are_accepted(pattern: str) -> None:
    assert not has_nested_quantifier(pattern)
    assert validate_regex(pattern) == pattern


def test_regex_length_limit() -> None:
    ok = "a" * MAX_PATTERN_LENGTH
    assert validate_regex(ok) == ok
    with pytest.raises(PatternValidationError, match="longer than 500"):
        validate_regex(ok + "a")
    with pytest.raises(PatternValidationError, match="longer than 500"):
        validate_pattern("a" * (MAX_PATTERN_LENGTH + 1), "glob")


def test_invalid_and_empty_patterns_are_refused_with_v1_messages() -> None:
    with pytest.raises(PatternValidationError, match=r"^Empty endpoint pattern$"):
        validate_pattern("  // ", "glob")
    with pytest.raises(PatternValidationError, match=r"^Empty endpoint pattern$"):
        validate_pattern("", "regex")
    with pytest.raises(PatternValidationError, match=r"^Invalid regular expression$"):
        validate_pattern("games(", "regex")
    with pytest.raises(PatternValidationError, match=r"^Invalid regular expression$"):
        validate_regex(r"\p{L}+")  # the regex module accepts it, Python re (v1) did not


def test_validate_pattern_returns_the_stored_form() -> None:
    assert validate_pattern(" /Games.Roblox.com/V1/Games ", "glob") == "games.roblox.com/v1/games"
    assert validate_pattern(r" /^Games\.roblox\.com/\D", "regex") == r"^Games\.roblox\.com/\D"


def test_glob_wildcard_and_control_character_limits() -> None:
    many = "/".join(["*"] * (MAX_GLOB_WILDCARDS + 1))
    with pytest.raises(PatternValidationError, match="wildcards"):
        validate_pattern(many, "glob")
    assert validate_pattern("/".join(["*"] * MAX_GLOB_WILDCARDS), "glob")
    with pytest.raises(PatternValidationError, match="control character"):
        validate_pattern("games.roblox.com/\x00", "glob")
    with pytest.raises(PatternValidationError, match="control character"):
        validate_regex("games\x07")


# --- fix pass: spec review 1 (v1 answers for non-ASCII text) ------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "kind", "path"),
    [
        ("users.roblox.com/v1/users/authenticated", "glob", "users.roblox.com/v1/users/authent\u0131cated"),
        (r"^games\.roblox\.com/v1/games/\w+/votes$", "regex", "games.roblox.com/v1/games/1\u00b2/votes"),
        (r"\w$", "regex", "\u0130"),
        ("I", "regex", "\u0130"),
        ("i", "regex", "\u0131"),
        (r"\d", "regex", "\u00b2"),
        (r"\s", "regex", "a\x1cb"),
        (r"\B", "regex", ""),
        (r"\b", "regex", ""),
        (r"x\b", "regex", "x\u0301"),
        ("[a-z]+$", "regex", "\u0131"),
        ("k", "regex", "\u212a"),
        ("s", "regex", "\u017f"),
    ],
)
def test_reviewer_cases_give_v1_answers(pattern: str, kind: str, path: str) -> None:
    """The exact cases from spec review finding 1, plus the class and case rules behind them."""
    target = v1._norm(path)
    assert compile_pattern(pattern, kind).matches(target) == v1._matches(pattern, target, kind), (pattern, path)
    if kind == "regex":
        assert text_matches("regex", pattern, path) == v1._header_field_matches("regex", pattern, path)


def test_user_agent_word_boundary_follows_v1() -> None:
    ua = "mybot\u0301/1.0"
    assert text_matches("regex", r"bot\b", ua) == v1._user_agent_matches({"Needle": r"bot\b", "Mode": "regex"}, ua)


_EVERY_CODE_POINT = "".join(map(chr, range(0x110000)))


@pytest.mark.parametrize(
    "piece",
    [
        r"\w",
        r"\W",
        r"\d",
        r"\D",
        r"\s",
        r"\S",
        ".",
        "[a-z]",
        "[^/]",
        "[^a-z0-9]",
        "i",
        "I",
        "k",
        "s",
        "K",
        "\u0131",
        "\u0130",
        "\u03c3",
        "[\u00b2-\u00b9]",
        r"[\w-]",
        r"[^\W\d]",
        r"(?a:\w)",
        r"(?s:.)",
        r"(?-i:k)",
    ],
)
def test_every_code_point_is_classified_like_re(piece: str) -> None:
    """Exhaustive: for every code point, the translated `regex` source and `re` agree (case-insensitive)."""
    import re

    expected = [m.start() for m in re.finditer(piece, _EVERY_CODE_POINT, re.IGNORECASE)]
    compiled = match.compile_like_re(piece)
    assert compiled is not None
    got = [m.start() for m in compiled.finditer(_EVERY_CODE_POINT)]
    assert got == expected


@pytest.mark.parametrize("anchor", [r"\b", r"\B", "^", "$", r"\A", r"\Z", "(?m)^", "(?m)$"])
def test_anchors_find_the_same_positions_as_re(anchor: str) -> None:
    import re

    samples = ["", "a", " a b ", "x\u0301y", "\u00b2\u00b2 ab\n", "\n\nab\n", "\u0130\u0131_9 \u2028"]
    for text in samples:
        expected = [m.start() for m in re.finditer(anchor, text, re.IGNORECASE)]
        compiled = match.compile_like_re(anchor)
        assert compiled is not None
        assert [m.start() for m in compiled.finditer(text)] == expected, (anchor, text)


# --- fix pass: security review M4 (slow shapes, fail closed, budget) ----------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a|aa)+$",
        r"(a{1,10}){1,10}b",
        r"(.*,){5}x",
        r"^games\.roblox\.com/.*.*.*.*.*!",
        r"(?:ab|a)*c",
        r"(x+x+)+y",
    ],
)
def test_slow_regex_shapes_are_refused(pattern: str) -> None:
    with pytest.raises(PatternValidationError):
        validate_regex(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"(GET|POST)+",
        r"^thumbnails\.roblox\.com/v1/users/\d+/\d+/\d+$",
        r"(?:users|groups)/\d+",
        r"(a+){3}",
        r"^(?:[a-z]+\.)?roblox\.com/",
    ],
)
def test_ordinary_regexes_stay_valid(pattern: str) -> None:
    assert validate_regex(pattern) == pattern


def test_glob_wildcards_per_segment_are_capped() -> None:
    with pytest.raises(PatternValidationError, match="one path segment"):
        validate_pattern("games.roblox.com/v1/*-*-*-x", "glob")
    assert validate_pattern("games.roblox.com/v1/*-*/x/*", "glob")


def test_a_timeout_fails_closed_for_blocks() -> None:
    """M4: a timed-out match on a refusing rule must count as a match (v1 `re` would have said True here)."""

    @dataclass(frozen=True)
    class Block:
        id: int
        pattern: str
        type: str

    slow = Block(1, r"(a|aa)+$", "regex")  # an imported v1 rule: stored, never judged again
    target = "a" * 32 + "!a"
    assert PatternIndex.from_rules([slow]).best(target, normalize=False) is None  # the default fails open
    closed = PatternIndex(((r.id, r.pattern, r.type, r) for r in [slow]), on_timeout=True)
    assert closed.best(target, normalize=False) is slow
    assert text_matches("regex", r"(a|aa)+$", target, on_timeout=True)
    assert not text_matches("regex", r"(a|aa)+$", target)


def test_regex_budget_caps_one_request() -> None:
    import time as _time

    target = "a" * 32 + "!a"
    compiled = compile_pattern(r"(a|aa)+$", "regex")
    started = _time.monotonic()
    with match.regex_budget(0.08):
        answers = [compiled.matches(target, on_timeout=True) for _ in range(10)]
    assert _time.monotonic() - started < 0.5  # ten slow rules, but one budget
    assert all(answers)


@pytest.mark.parametrize("pattern", [r"x(?<=\w)", r"(?<!\w)x", r"|(?<=\w)", r"(?<=\d\w)y", r"\w+\b", r"(?<=\W)\w"])
def test_large_sets_inside_lookbehinds_match_like_re(pattern: str) -> None:
    """The `regex` module mishandles subroutine calls inside lookbehinds, so big sets there must stay inline."""
    import re

    for text in ["", "x", "ax", "1x", " x", "²x", "a1y", "-y", "́x"]:
        compiled = match.compile_like_re(pattern)
        assert compiled is not None
        expected = [m.span() for m in re.finditer(pattern, text, re.IGNORECASE)]
        assert [m.span() for m in compiled.finditer(text)] == expected, (pattern, text)
