"""Redaction cost: every scrubbing function stays linear on hostile caller text (findings INGRESS-1 and public-4).

What this is
    Timing tests for `roxy.core.redact` on shapes built to make a backtracking regex engine work hard: runs of line
    breaks (raw and as `%0A`, which `redact_text` decodes itself), runs of spaces after a secret header name or
    after a `key=` pair, repeated openers of every pattern (`a://`, `("x", '`, `.ROBLOSECURITY=`, the kill-switch
    path), and so on. Each shape is scrubbed at size n and at 4n; linear work grows about 4 times, quadratic work
    about 16 times.

Why it exists
    `redact_text` runs on the event loop for every log field, error event and metric label, before any rate limit,
    on text a caller chooses (a path, a query, a header, a CSP report). Python's `re` has no timeout, so one rule
    that backtracks quadratically lets one client stall a worker: `_HEADER_LINE_RE` once cost 80 ms for one 8 KiB
    path of `%0A`. These tests keep every rule, present and future, honest.

How it works
    Best of several runs at each size, so a busy machine does not make a linear rule look quadratic; the bound
    (`MAX_GROWTH` for 4x the input) sits between linear (about 4) and quadratic (about 16). Sizes are large enough
    that the work dominates the call overhead. A control checks that the rule still redacts what it must.

What to read next
    `roxy/core/redact.py`, tests/security/test_rr_ingress_redaction_cost.py and
    tests/security/test_rr_public_redaction_cost.py (the same question through the whole app).
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from roxy.core.redact import TOKEN_PREFIX, redact_headers, redact_label, redact_query, redact_text

N = 4000
"""Units of the hostile shape at the small size (the large size is 4 x N)."""

MAX_GROWTH = 8.0
"""Allowed time ratio for 4x the input: linear is about 4, quadratic about 16."""

RUNS = 5

SHAPES: dict[str, Callable[[int], str]] = {
    "raw line breaks": lambda n: "\n" * n,
    "encoded line breaks": lambda n: "%0A" * n,
    "double encoded line breaks": lambda n: "%250A" * n,
    "carriage returns and line breaks": lambda n: "\r\n" * n,
    "secret header name then spaces": lambda n: "Cookie" + " " * n,
    "secret header name then line breaks": lambda n: "Cookie:" + "\n" * n,
    "header lines without a value": lambda n: "Cookie:\n" * n,
    "spaces": lambda n: " " * n,
    "tabs and line breaks": lambda n: "\t\n" * n,
    "pair openers": lambda n: "a=" * n,
    "colon pairs": lambda n: "a:" * n,
    "quoted pair openers": lambda n: '"a": "' * n,
    "unterminated quoted values": lambda n: 'password="' + "x" * n,
    "key then spaces": lambda n: "token" + " " * n + "x",
    "long name": lambda n: "a" * n,
    "url scheme openers": lambda n: "a://" * n,
    "url without at sign": lambda n: "http://" + "a" * n,
    "tuple openers": lambda n: "('a', '" * n,
    "tuple openers mixed quotes": lambda n: "('a', \"" + "('b', '" * n,
    "tuple escapes": lambda n: "('token', '" + "\\" * n,
    "cookie markers": lambda n: ".ROBLOSECURITY=" * n,
    "kill switch paths": lambda n: "/admin/invalidate/" * n,
    "token prefixes": lambda n: TOKEN_PREFIX * max(1, n // 50),
    "percent signs": lambda n: "%" * n,
    "query separators": lambda n: "&" * n,
    "query pairs": lambda n: "a=%0A&" * n,
}

FUNCTIONS: dict[str, Callable[[str], object]] = {
    "redact_text": redact_text,
    "redact_label": redact_label,
    "redact_query": redact_query,
    "redact_headers": lambda text: redact_headers([("X-Note", text), (text[:200] or "x", "1")]),
}


def _best(work: Callable[[], object]) -> float:
    best = float("inf")
    for _ in range(RUNS):
        started = time.perf_counter()
        work()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("function", list(FUNCTIONS), ids=list(FUNCTIONS))
@pytest.mark.parametrize("shape", list(SHAPES), ids=list(SHAPES))
def test_scrubbing_hostile_text_is_linear(shape: str, function: str) -> None:
    make, scrub = SHAPES[shape], FUNCTIONS[function]
    small, large = make(N), make(4 * N)
    scrub(small)  # warm up (label memory, regex caches)
    small_s = _best(lambda: scrub(small))
    large_s = _best(lambda: scrub(large))
    # 2 ms of slack: tiny inputs are dominated by call overhead and timer noise, not by the regex work.
    assert large_s <= MAX_GROWTH * small_s + 0.002, (
        f"{function} on {shape!r}: {small_s * 1000:.2f} ms for {len(small)} chars, "
        f"{large_s * 1000:.2f} ms for {len(large)} chars"
    )


def test_eight_kib_of_encoded_line_breaks_is_cheap() -> None:
    """The INGRESS-1 request: an 8 KiB request line of `%0A` cost about 80 ms; it must now cost a few ms."""
    path = "/" + "%0A" * 2730
    assert _best(lambda: redact_text(path)) < 0.02


def test_header_lines_are_still_redacted() -> None:
    """Control for the linear `_HEADER_LINE_RE`: indented, tabbed, CRLF and folded secret header lines lose their
    values, other header lines keep theirs, and line breaks around them are kept."""
    text = (
        "GET /x HTTP/1.1\r\nHost: a\r\n  Cookie: session=abc123\r\nAuthorization:\tBearer zzz9\r\n"
        "X-Csrf-Token :  t0ken55\r\nProxy-Authorization:\r\n  Basic cGFzczp3b3Jk\r\nAccept: */*\r\n"
    )
    cleaned = redact_text(text)
    for secret in ("abc123", "zzz9", "t0ken55", "cGFzczp3b3Jk"):
        assert secret not in cleaned, secret
    assert "Host: a\r\n" in cleaned
    assert "Accept: */*" in cleaned
    assert cleaned.count("\n") == text.count("\n")  # every line break is kept, the folded one included


def test_line_breaks_alone_are_kept() -> None:
    assert redact_text("\n" * 50) == "\n" * 50
    assert redact_text("a\n\nb") == "a\n\nb"
