"""Wave 2 high fix INGRESS-1 and public-4, new variants (review round 3, lens w2highs): other hostile text shapes.

What this is
    Timing probes of `roxy.core.redact` (stdlib `re`, run on the event loop for every Live row, log line and
    record) on caller-shaped text other than the `%0A` run of the original findings: repeated secret-pair openers
    (`a="`, `a=`), Python tuple reprs, scheme prefixes, the cookie name repeated with and without `=` and spaces, an
    almost complete public warning repeated, double percent escapes, folded `Cookie:` lines, one-time code shapes,
    64 character words between line breaks, the kill-switch path repeated, and ampersand heavy queries.

Why it exists
    INGRESS-1 and public-4 were one quadratic rule (`_HEADER_LINE_RE` crossing line breaks). The fix made that rule
    linear and its tests compare newline text with plain text. Every other rule of `_redact_once` sees the same
    caller text, and `redact_query` runs `redact_text` once per query part, so a different shape could make the same
    class of bug come back through another rule or another entry point.

How it works
    Each shape is built at 8 KiB (a request line nginx passes) and timed best of three against plain letters of the
    same size through `redact_text`, `redact_query` and `redact_label`; a shape may cost at most three times plain
    text plus 10 ms. A growth check compares 2 KiB with 8 KiB for every shape: linear work grows about four times,
    quadratic work sixteen. Every probe here passes today: the fix holds against these shapes.

What to read next
    `src/roxy/core/redact.py` (`_redact_once`, `redact_query`), `tests/security/test_rr_ingress_redaction_cost.py`
    and `tests/unit/core/test_core_redact_cost.py` (the fix tests).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import pytest

from roxy.core.redact import TOKEN_PREFIX, redact_label, redact_query, redact_text

SIZE = 8190
SHAPES = {
    "dq_pair_openers": 'a="',
    "bare_pair_openers": "a=",
    "tuple_reprs": "('a', 'xx",
    "tuple_backslashes": "('a', '\\",
    "scheme_prefixes": "a://",
    "scheme_plus": "a+",
    "cookie_name": ".ROBLOSECURITY",
    "cookie_name_eq_space": ".ROBLOSECURITY= ",
    "almost_the_warning": TOKEN_PREFIX[:-1],
    "double_escapes": "%25",
    "letter_newline": "a%0A",
    "folded_cookie_lines": "cookie:%0A %0A",
    "code_shapes": "code=aaaa-aa&",
    "long_words_between_breaks": "b" * 64 + "%0A%0A%0A%0A",
    "kill_switch_paths": "/admin/invalidate/",
    "ampersands": "a&",
    "empty_pairs": "&=",
}


def _rep(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def _best_of(runs: int, work: Callable[[], Any]) -> float:
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        work()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("scrub", [redact_text, redact_query, redact_label], ids=lambda f: f.__name__)
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_ingress1_variant_shapes_cost_about_what_plain_text_costs(shape: str, scrub: Callable[[str], str]) -> None:
    plain = "a" * SIZE
    hostile = _rep(SHAPES[shape], SIZE)
    plain_s = _best_of(3, lambda: scrub(plain))
    hostile_s = _best_of(3, lambda: scrub(hostile))
    assert hostile_s < 3 * plain_s + 0.010, (
        f"{scrub.__name__}({shape}): {hostile_s * 1000:.1f} ms against {plain_s * 1000:.1f} ms for plain text"
    )


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_ingress1_variant_shapes_grow_linearly(shape: str) -> None:
    small = _best_of(3, lambda: redact_text(_rep(SHAPES[shape], SIZE // 4)))
    large = _best_of(3, lambda: redact_text(_rep(SHAPES[shape], SIZE)))
    assert large < 8 * small + 0.005, f"{shape}: {small * 1000:.2f} ms for 2 KiB, {large * 1000:.2f} ms for 8 KiB"
