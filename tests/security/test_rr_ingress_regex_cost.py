"""Ingress re-review (rr), write-time regex cost lens: shapes the new validator accepts that still need the timeout.

What this is
    Probes for `rules/match.py validate_pattern` / `validate_regex` and the cost model behind them
    (`rules/regex_cost.py`, fix pass 1): each case is a pattern the validator ACCEPTS for a new rule, paired with
    the slowest caller input found for it, and the probe asserts the promise of the fix pass: either the validator
    refuses the pattern, or a worst-case input finishes well inside the 50 ms per-match timeout.

Why it exists
    The cost model charges only "long" repeats (open-ended, or a count that can vary by more than `LONG_SPAN` 10).
    A chain of SHORT repeats over overlapping characters (`\\w{0,10}` four times, `[a-z]?` twenty times) is never
    charged (estimate 0), yet every start position of an unanchored search tries every way to split the run among
    them: up to 11^4 or 2^20 attempts per position, times 4,000 positions. Separately, globs are judged only by
    their wildcard count, and the two wildcards allowed in a last segment (`*a*b`) trade characters quadratically
    (`MAX_GLOB_WILDCARDS_PER_SEGMENT` says three need 50 ms on 4,000 characters; two need 37 ms at the default
    `max_url_length`, four times that at its catalog maximum of 8,192). The model also sizes inputs at
    `TARGET_LENGTH` 4096 while header values (User-Agent and header rules) may be 8 KiB (`max_header_bytes`).
    Every such rule costs a timed-out match per request, and a timed-out match is answered with a guess
    (finding INGRESS-2).

How it works
    The same measurement as `test_ingress_redos.py test_accepted_patterns_never_need_the_timeout`: run the real
    compiled pattern (`compile_pattern`, `text_matches`) on the input and require less than half the per-match
    timeout and no timeout counted. Regex inputs are a full header value (8 KiB, the default `max_header_bytes`),
    the input a User-Agent or header rule sees; the glob input is a path at the catalog maximum `max_url_length`.
    Fixed in the review round: the model sizes inputs at 8192, charges short repeats by the lengths they can give
    back, and judges globs on their compiled regex, so every slow shape here is refused (asserted), while the
    controls and a two-wildcard glob that cannot fail late (`*-*`) stay accepted and fast.

What to read next
    `roxy/rules/regex_cost.py` (`_is_long`, `LONG_SPAN`, `TARGET_LENGTH`), `roxy/rules/match.py`
    (`MAX_GLOB_WILDCARDS_PER_SEGMENT`, `validate_pattern`), then `tests/security/test_ingress_redos.py`.
"""

from __future__ import annotations

import time

import pytest

from roxy.rules import match
from roxy.rules.match import (
    PatternValidationError,
    compile_pattern,
    normalize_target,
    regex_timeouts_total,
    text_matches,
    validate_pattern,
)

HEADER_VALUE = 8192 - len("user-agent")
"""The longest User-Agent a caller can send under the default `max_header_bytes` (8 KiB per header line)."""
MAX_PATH = 8192 - len("/")
"""The longest path under the catalog maximum of `max_url_length` (8192)."""

SLOW_ACCEPTED_REGEXES: list[tuple[str, str]] = [
    (r"\w{0,10}\w{0,10}\w{0,10}\w{0,10}\d", "a" * HEADER_VALUE),
    ("[a-z]?" * 20 + "[0-9]", "a" * HEADER_VALUE),
    ("[a-z]{2,12}" * 4 + "[0-9]", "a" * HEADER_VALUE),
]
SLOW_ACCEPTED_GLOBS: list[tuple[str, str]] = [
    ("games.roblox.com/v1/*a*b", "games.roblox.com/v1/b" + "a" * (MAX_PATH - len("games.roblox.com/v1/b"))),
]


def _assert_fast(run: object, label: str) -> None:
    before = regex_timeouts_total()
    started = time.perf_counter()
    run()  # type: ignore[operator]
    elapsed = time.perf_counter() - started
    assert regex_timeouts_total() == before, f"{label} hit the per-match timeout"
    assert elapsed < match.REGEX_MATCH_TIMEOUT_S / 2, f"{label} took {elapsed * 1000:.0f} ms"


@pytest.mark.parametrize(("pattern", "target"), SLOW_ACCEPTED_REGEXES, ids=[p for p, _ in SLOW_ACCEPTED_REGEXES])
def test_an_accepted_regex_never_needs_the_timeout_on_a_header_value(pattern: str, target: str) -> None:
    """Finding INGRESS-2 (fixed): the cost model charges chains of short repeats on an 8 KiB input, so each of
    these slow shapes is refused at write time (the only correct answer: each needs the timeout)."""
    assert len(target) == HEADER_VALUE  # the input that made each of them need the timeout
    with pytest.raises(PatternValidationError) as refused:
        validate_pattern(pattern, "regex")
    assert "can match the same characters" in refused.value.message


@pytest.mark.parametrize(("glob", "target"), SLOW_ACCEPTED_GLOBS, ids=[g for g, _ in SLOW_ACCEPTED_GLOBS])
def test_an_accepted_glob_never_needs_the_timeout(glob: str, target: str) -> None:
    """Finding INGRESS-2 (fixed): a glob's compiled regex meets the same budget, so two wildcards with text after
    the second one (`*a*b`) are refused, while `*-*` (nothing after them can fail) stays accepted and fast."""
    try:
        validate_pattern(glob, "glob")
    except PatternValidationError:
        pass
    else:
        pytest.fail(f"{glob!r} was accepted although it needs the per-match timeout on a {len(target)} character path")
    allowed = validate_pattern("games.roblox.com/v1/*-*", "glob")
    compiled = compile_pattern(allowed, "glob")
    slow_shape = "games.roblox.com/v1/" + "-a" * ((MAX_PATH - len("games.roblox.com/v1/")) // 2)
    _assert_fast(lambda: compiled.matches(normalize_target(slow_shape + "/x")), f"{allowed!r} on a long path")
    _assert_fast(lambda: compiled.matches(normalize_target(target)), f"{allowed!r} on a {len(target)} character path")


@pytest.mark.parametrize(
    "pattern",
    [r"Roblox/\w{1,10} \w{1,10}", r"^\w{0,10}\w{0,10}\d", r"games\.roblox\.com/v1/games/\d{1,20}/media"],
)
def test_control_ordinary_short_repeats_stay_accepted_and_fast(pattern: str) -> None:
    """A fix must not refuse ordinary rules: short repeats separated by fixed text, or anchored, are cheap."""
    validate_pattern(pattern, "regex")
    _assert_fast(lambda: text_matches("regex", pattern, "a" * HEADER_VALUE, on_timeout=True), pattern)
