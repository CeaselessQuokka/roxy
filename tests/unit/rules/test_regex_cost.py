"""Tests for `roxy.rules.regex_cost`: the write-time worst-case budget for new regular expressions (plan 9.9).

What this is
    The model's verdicts on the shapes the ingress reviews found slow, on realistic admin patterns, and on the
    near-budget cases used to calibrate it; then a measured check that every pattern the validator accepts here
    fails an 8192 character worst-case input well inside the 50 ms per-match timeout.

Why it exists
    The first ingress review showed accepted patterns (three trading repeats, a repeat an unanchored search restarts
    in) running into the per-match timeout on one 4 KB path; the re-review (finding INGRESS-2) showed chains of SHORT
    repeats (`\\w{0,10}` four times, `[a-z]?` twenty times) the model never charged, a glob with two wildcards and
    text after them (`*a*b`), and inputs sized at 4096 while header values reach 8 KiB. The cost model is an
    estimate; these tests pin its numbers and check them against the real engine, with wide margins so they do not
    flake on a busy machine.

How it works
    Verdicts go through `validate_regex` and `validate_pattern` (the paths admin writes take). Measurements run the
    compiled pattern the way rules run it (`search` on the `regex` module) on runs of single characters, short
    units and the pattern's own literal pieces, each with and without a killer character, and keep the slowest.

What to read next
    `src/roxy/rules/regex_cost.py`, `src/roxy/rules/match.py`, `tests/security/test_ingress_redos.py`,
    `tests/security/test_rr_ingress_regex_cost.py`.
"""

from __future__ import annotations

import contextlib
import re
import time

import pytest

from roxy.config.catalog import CATALOG
from roxy.rules import regex_cost
from roxy.rules.match import (
    REGEX_MATCH_TIMEOUT_S,
    PatternValidationError,
    compile_pattern,
    validate_pattern,
    validate_regex,
)

N = regex_cost.TARGET_LENGTH

REFUSED = {
    # The six probes of the ingress review (tests/security/test_ingress_redos.py ACCEPTED_BUT_SLOW).
    r"x+x+x+y": "can match the same characters",
    r"\w+\d+\w+x": "can match the same characters",
    r"[a-z]+[0-9]+[a-z]+x": "restart at every position",
    r".*.*.*x": "can match the same characters",
    r"a.*a.*a.*b": "can match the same characters",
    r".*/v1/.*/.*icons": "can match the same characters",
    # Two trading repeats, even anchored, and single repeats an unanchored search restarts inside of.
    r"^.*x.*y": "can match the same characters",
    r"a.*a.*b": "can match the same characters",
    r"x+y": "restart at every position",
    r"x+$": "restart at every position",
    r"\w+\W": "restart at every position",
    r"\d+x": "restart at every position",
    r"(?:ab)+c": "restart at every position",
    r"(?:v1/)+icons": "restart at every position",
    r".*crawler.*": "a leading .* is never needed",
    r"(?=.*x)": "restart at every position",
    r"x{1,1000}y": "restart at every position",
    r"a.{0,100}b.{0,100}c": "can match the same characters",
    # Finding INGRESS-2: chains of short repeats over overlapping characters (seconds on an 8 KiB header).
    r"\w{0,10}\w{0,10}\w{0,10}\w{0,10}\d": "write them as one repeat",
    "[a-z]?" * 20 + "[0-9]": "write them as one repeat",
    "[a-z]{2,12}" * 4 + "[0-9]": "write them as one repeat",
    r"\w{0,5}\w{0,5}\d": "write them as one repeat",
    r"\w{0,10}\d": "restart at every position",
    # Fast enough on a 4096 character path, too slow on the 8192 characters a header (or a raised max_url_length)
    # can hold: 17 to 20 ms measured, more than a third of the timeout.
    r"users/\d+/.*friends": "restart at every position",
    r"catalog.*search": "restart at every position",
    r"^\w+\W": "use a narrower character class",
    r"^Mozilla/5\.0 \(.*\) AppleWebKit/.*Chrome/\d+": "can match the same characters",
}

ACCEPTED = [
    r"^games\.roblox\.com/v1/games/\d+$",
    r"^games\.roblox\.com/v1/games/\d+/servers/.*",
    r"^thumbnails\.roblox\.com/v1/users/\d+/\d+/\d+$",
    r"^users\.roblox\.com/v1/users/\d+/status$",
    r"economy\.roblox\.com/v1/assets/\d+(?:/.*)?",
    r"^users/\d+/.*friends",
    r"^catalog.*search",
    r"(?:users|groups)/\d+",
    r"/\d+/x",
    r"(GET|POST)+",
    r"(a+){3}",
    r"(\d{1,3}\.){3}\d{1,3}",
    r"^(?:[a-z]+\.)?roblox\.com/",
    r"^[a-z]+/[0-9]*",
    r"(?i)roblox(?=\.com)",
    r"^Mozilla/5\.0 \([^)]*\) AppleWebKit/",
    r"python-requests/[\d.]+",
    r"^python-requests/\d+\.\d+(\.\d+)?$",
    r"curl/\d+\.\d+",
    r"\w+\b",
    r"bot\b",
    r"^[A-Fa-f0-9]{32}$",
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    r"x{1,100}y",
    r"https?://",
    r"Synapse|Xeno|KRNL",
    r"^scraper",
    r"^\d+$",
    r"crawler",
    # The controls of finding INGRESS-2: short repeats separated by fixed text, or anchored, are cheap.
    r"Roblox/\w{1,10} \w{1,10}",
    r"^\w{0,10}\w{0,10}\d",
    r"games\.roblox\.com/v1/games/\d{1,20}/media",
]


def test_the_input_length_is_the_largest_path_or_header_the_catalog_admits() -> None:
    """Finding INGRESS-2: the model sizes inputs at the longest text any configuration lets a caller send."""
    assert N == max(CATALOG["max_url_length"].max or 0, CATALOG["max_header_bytes"].max or 0) == 8192


@pytest.mark.parametrize("pattern", list(REFUSED), ids=list(REFUSED))
def test_slow_shapes_are_refused_with_a_specific_message(pattern: str) -> None:
    with pytest.raises(PatternValidationError) as refused:
        validate_regex(pattern)
    message = refused.value.message
    assert REFUSED[pattern] in message
    assert f"path or header of {N} characters" in message
    assert chr(0x2014) not in message
    assert chr(0x2013) not in message


@pytest.mark.parametrize("pattern", ACCEPTED, ids=ACCEPTED)
def test_realistic_patterns_are_accepted(pattern: str) -> None:
    assert validate_regex(pattern) == pattern


def test_the_model_numbers_are_pinned() -> None:
    """The calibration anchors from the module docstring (units, not milliseconds)."""

    def units(pattern: str) -> float:
        charge = regex_cost.estimate(pattern)
        return 0.0 if charge is None else charge.units

    assert units(r"x+y") == pytest.approx((N / 2) * N * 2)  # restarts * reach * (x test + y test)
    assert units(r"^x+y") == pytest.approx(N * 2)  # anchored: one pass
    assert units(r"^\d+/\d+") == pytest.approx(N * (60 + 1))  # `/` pins the split: the two never trade
    assert units(r"\d+/\d+") > regex_cost.STEP_BUDGET  # unanchored, the first one restarts inside a digit run
    assert units(r"x+x") == 0.0  # nothing after the run can fail
    assert units(r"^users/\d+/.*friends") < regex_cost.STEP_BUDGET < units(r"x+y")
    assert units(r"x+x+x+y") > 1e12
    # Short repeats (finding INGRESS-2): each one multiplies by its span + 1, the lengths it can give back.
    assert units(r"^\w{0,10}\w{0,10}\d") == pytest.approx(11 * 10 * (200 + 60))  # splits * reach * (\w + \d)
    assert units("[a-z]?" * 20 + "[0-9]") == pytest.approx((N / 2) * 2**19 * 1 * (2 + 2))
    assert units(r"\w{0,10}\d") == pytest.approx((N / 2) * 10 * (200 + 60))  # one short repeat, restarted
    # A taken optional group keeps its required text between the repeats around it: the two `\d+` never trade.
    assert units(r"^v\d+\.\d+(\.\d+)?$") < regex_cost.STEP_BUDGET


def test_messages_name_the_repeats_and_the_fix() -> None:
    restart = regex_cost.cost_problem(r"[a-z]+[0-9]+[a-z]+x")
    assert restart is not None
    assert "[a-z]+" in restart
    assert "start the pattern with ^" in restart
    assert "a leading .* is never needed" not in restart
    trading = regex_cost.cost_problem(r"^thumbnails\.roblox\.com/.*/.*icons$")
    assert trading is not None
    assert ".* and .*" in trading
    assert "something .* cannot match" in trading
    assert "bounded repeat such as {1,20}" in trading
    short = regex_cost.cost_problem(r"\w{0,10}\w{0,10}\d")
    assert short is not None
    assert r"\w{0,10} and \w{0,10}" in short
    assert "write them as one repeat" in short
    middle = regex_cost.cost_problem(r"users/\d+/.*friends")
    assert middle is not None
    assert "a leading .* is never needed" not in middle  # the .* is not leading here
    assert "a leading .* is never needed" in (regex_cost.cost_problem(r"(?i).*crawler") or "")


def test_the_analysis_itself_is_fast() -> None:
    """The longest pattern an admin may store, with many alternatives and repeats, is judged quickly."""
    pattern = "^" + "(?:ab|cd)x{0,20}" * 24
    assert len(pattern) <= 500
    started = time.perf_counter()
    regex_cost.cost_problem(pattern)
    assert time.perf_counter() - started < 1.0
    too_many = regex_cost.cost_problem("(?:a+|b+)" * 7)  # 128 combinations of alternatives with repeats
    assert too_many is not None
    assert "combinations of alternatives" in too_many
    crowded = regex_cost.cost_problem("^" + "x{0,20}y" * 30)
    assert crowded is not None
    assert "repeats of varying length" in crowded
    optional = "^" + "x?y" * 70  # 70 optional parts: refused outright, and judged quickly
    started = time.perf_counter()
    many = regex_cost.cost_problem(optional)
    assert time.perf_counter() - started < 1.0
    assert many is not None
    assert "optional or repeated parts" in many
    started = time.perf_counter()
    assert regex_cost.estimate("x?" * 250) is not None  # the estimate alone stays bounded too
    assert time.perf_counter() - started < 1.0


GLOBS_ACCEPTED = [
    "games.roblox.com/v1/games/*",
    "games.roblox.com/*/games/*",
    "games.roblox.com/v1/games/*/media",
    "games.roblox.com/v1/games/*-*",  # two wildcards in the last segment, nothing after them that can fail
    "games.roblox.com/v1/a*b*",
    "games.roblox.com/v1/*a*",
]


@pytest.mark.parametrize("glob", GLOBS_ACCEPTED, ids=GLOBS_ACCEPTED)
def test_globs_whose_wildcards_cannot_fail_late_are_accepted(glob: str) -> None:
    assert validate_pattern(glob, "glob") == glob


@pytest.mark.parametrize("glob", ["games.roblox.com/v1/*a*b", "games.roblox.com/v1/*.*json", "*x*y"])
def test_globs_with_text_after_two_wildcards_in_a_segment_are_refused(glob: str) -> None:
    """Finding INGRESS-2: the glob's compiled regex meets the regex budget (`*a*b` took 37 ms on 4 KiB)."""
    with pytest.raises(PatternValidationError) as refused:
        validate_pattern(glob, "glob")
    assert "two wildcards in one segment with more text after the second one" in refused.value.message
    assert chr(0x2014) not in refused.value.message


def _attacks(pattern: str) -> list[str]:
    """Generic worst-case inputs: runs of single characters, short units and the pattern's literal pieces, each
    plain, ending in a killer character, and starting with one."""
    pieces = {"x", "a", "1", "/", ".", "-", " ", "ab", "a/", "v1/", "xy", "a1", "users/1/", "catalog"}
    pieces.update(word for word in re.findall(r"[A-Za-z0-9/.-]{2,}", pattern.replace("\\", " ")))
    out: list[str] = []
    for piece in sorted(pieces):
        run = (piece * (N // len(piece) + 1))[:N]
        out += [run, run[:-1] + "!", "!" + run[1:]]
    return out


@pytest.mark.parametrize("pattern", ACCEPTED, ids=ACCEPTED)
def test_accepted_patterns_fail_long_inputs_well_inside_the_timeout(pattern: str) -> None:
    """Measured: every accepted pattern's slowest generic worst case takes under half the per-match timeout (the
    model aims at a third; the margin keeps a busy test machine from flaking)."""
    rx = compile_pattern(pattern, "regex")._rx
    assert rx is not None
    worst = 0.0
    for target in _attacks(pattern):
        best = 1.0
        for _ in range(2):  # the faster of two runs: a scheduler hiccup is not the pattern's cost
            started = time.perf_counter()
            with contextlib.suppress(TimeoutError):
                rx.search(target, timeout=1.0)
            best = min(best, time.perf_counter() - started)
        worst = max(worst, best)
    assert worst < REGEX_MATCH_TIMEOUT_S / 2, f"{pattern!r} took {worst * 1000:.1f} ms"
