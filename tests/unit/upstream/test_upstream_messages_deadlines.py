"""Caller texts and the 7.13 rows; deadline math (plan 5.2) including the owner deadline; backoff; the queue."""

from __future__ import annotations

import asyncio
import random

import pytest
from upstream_fakes import FakeSettings

from roxy.config import catalog
from roxy.core.reasons import ReasonCode
from roxy.upstream import deadlines, messages
from roxy.upstream.backoff import DecorrelatedJitter, decorrelated_jitter_ms
from roxy.upstream.messages import CALLER_ROWS, RetryAfterRule, retry_after_seconds
from roxy.upstream.queue import CANCEL_ORDER, Priority, WaitQueue

# --- messages (parity row 36, plan 7.13) ------------------------------------------------------------------------------


def test_exact_caller_texts() -> None:
    assert messages.BUSY_MESSAGE == "All request methods are busy right now; please try again shortly."
    assert messages.FAILED_MESSAGE == "Upstream request failed; please try again later."
    assert messages.INTERNAL_ERROR_MESSAGE == "Internal Server Error"
    assert messages.AUTH_SMUGGLING_MESSAGE == "Requests requiring authentication are not allowed with this proxy."
    assert messages.MESSAGE_CONTENT_TYPE == "text/plain; charset=utf-8"
    for text in (messages.BUSY_MESSAGE, messages.FAILED_MESSAGE):
        assert chr(0x2014) not in text
        assert chr(0x2013) not in text


B, F = messages.BUSY_MESSAGE, messages.FAILED_MESSAGE
TABLE = [
    # reason, status (None = real upstream), body (None = upstream body), Retry-After rule, fixed, Roxy-Refusal
    (ReasonCode.UPSTREAM_OK, None, None, RetryAfterRule.NONE, None, False),
    (ReasonCode.UPSTREAM_4XX, None, None, RetryAfterRule.NONE, None, False),
    (ReasonCode.UPSTREAM_COOLDOWN, 429, B, RetryAfterRule.COOLDOWN, None, True),
    (ReasonCode.UPSTREAM_BUSY, 429, B, RetryAfterRule.SOONEST, None, True),
    (ReasonCode.QUEUE_OVERFLOW, 429, B, RetryAfterRule.SOONEST_MIN_1, None, True),
    (ReasonCode.UPSTREAM_5XX, None, F, RetryAfterRule.UPSTREAM_OR_DEFAULT, None, False),
    (ReasonCode.UPSTREAM_TIMEOUT, 504, F, RetryAfterRule.FIXED, 5, True),
    (ReasonCode.UPSTREAM_CONNECT, 502, F, RetryAfterRule.FIXED, 5, True),
    (ReasonCode.DEADLINE, 504, F, RetryAfterRule.FIXED, 5, True),
    (ReasonCode.COALESCE_TIMEOUT, 503, B, RetryAfterRule.OWNER_DEADLINE, None, True),
    (ReasonCode.EGRESS_DISABLED, 503, B, RetryAfterRule.FIXED, 60, True),
    (ReasonCode.CREDENTIAL_UNAVAILABLE, 503, B, RetryAfterRule.CREDENTIAL, None, True),
    (ReasonCode.DEGRADED, 503, B, RetryAfterRule.FIXED, 10, True),
    (ReasonCode.INTERNAL_ERROR, 500, "Internal Server Error", RetryAfterRule.FIXED, 5, False),
]


@pytest.mark.parametrize(
    ("reason", "status", "body", "rule", "fixed", "refusal"), TABLE, ids=[r[0].value for r in TABLE]
)
def test_7_13_rows(
    reason: ReasonCode, status: int | None, body: str | None, rule: RetryAfterRule, fixed: int | None, refusal: bool
) -> None:
    row = CALLER_ROWS[reason]
    assert (row.status, row.body, row.retry_after, row.retry_after_fixed, row.refusal_header) == (
        status,
        body,
        rule,
        fixed,
        refusal,
    )


def test_retry_after_values() -> None:
    assert retry_after_seconds(ReasonCode.UPSTREAM_COOLDOWN, cooldown_s=29.2) == 30  # rounded up
    assert retry_after_seconds(ReasonCode.UPSTREAM_COOLDOWN, cooldown_s=0.1) == 1
    assert retry_after_seconds(ReasonCode.UPSTREAM_BUSY, soonest_s=3.5) == 4
    assert retry_after_seconds(ReasonCode.QUEUE_OVERFLOW, soonest_s=0.0) == 1
    assert retry_after_seconds(ReasonCode.UPSTREAM_5XX) == 5
    assert retry_after_seconds(ReasonCode.UPSTREAM_5XX, upstream_retry_after_s=17) == 17
    assert retry_after_seconds(ReasonCode.COALESCE_TIMEOUT, owner_remaining_s=12.2) == 13
    assert retry_after_seconds(ReasonCode.CREDENTIAL_UNAVAILABLE, cooldown_s=44) == 44
    assert retry_after_seconds(ReasonCode.CREDENTIAL_UNAVAILABLE) == 300
    assert retry_after_seconds(ReasonCode.CREDENTIAL_UNAVAILABLE, cooldown_s=44, credential_rejected=True) == 300
    assert retry_after_seconds(ReasonCode.EGRESS_DISABLED) == 60
    assert retry_after_seconds(ReasonCode.DEGRADED) == 10
    assert retry_after_seconds(ReasonCode.UPSTREAM_OK) is None


def test_caller_status() -> None:
    assert messages.caller_status(ReasonCode.UPSTREAM_5XX, 503) == 503
    assert messages.caller_status(ReasonCode.UPSTREAM_TIMEOUT, None) == 504
    with pytest.raises(KeyError):
        messages.caller_row(ReasonCode.THROTTLE)  # abuse refusals are not upstream rows


# --- deadlines (plan 5.2) --------------------------------------------------------------------------------------------


def test_owner_deadline_with_defaults_is_36_seconds() -> None:
    settings = FakeSettings()
    assert deadlines.owner_deadline_s(settings) == 36.0  # 4 s + 15 s x 2 + 2 s
    assert deadlines.owner_deadline_ms(settings) == 36_000


def test_owner_deadline_follows_settings() -> None:
    settings = FakeSettings(
        queue_wait_interactive_ms=1000, request_timeout=10, upstream_max_attempts=3, backoff_cap_ms=500
    )
    assert deadlines.owner_deadline_s(settings) == pytest.approx(31.5)


def test_owner_deadline_cross_rule_matches_the_code() -> None:
    """The catalog rejects settings whose owner deadline exceeds request_deadline_s - 2 (same formula)."""
    good = dict(catalog.DEFAULTS)
    assert not [issue for issue in catalog.validate_cross(good) if "owner" in issue.message.lower()]
    bad = good | {"request_timeout": 30, "upstream_max_attempts": 2, "request_deadline_s": 60}  # 4 + 60 + 2 = 66
    issues = [issue for issue in catalog.validate_cross(bad) if "owner deadline" in issue.message]
    assert issues
    assert deadlines.owner_deadline_s(FakeSettings(request_timeout=30)) == 66


def test_attempt_timeout_is_clipped_to_the_deadline() -> None:
    settings = FakeSettings()
    full = deadlines.attempt_timeout(settings, 60)
    assert (full.connect, full.read, full.write, full.pool) == (5, 15, 10, 5)
    short = deadlines.attempt_timeout(settings, 3.0)
    assert (short.connect, short.read, short.write, short.pool) == (3, 3, 3, 3)
    assert deadlines.attempt_timeout(settings, -1).read == 0.05


def test_can_retry_after() -> None:
    assert deadlines.can_retry_after(10, 2) is True
    assert deadlines.can_retry_after(2.9, 2) is False
    assert deadlines.can_retry_after(3.0, 2) is True


@pytest.mark.parametrize(
    ("priority", "budget"),
    [
        (Priority.INTERACTIVE, 4000),
        (Priority.INTERACTIVE_STALE, 500),
        (Priority.BACKGROUND, 10000),
        (Priority.ADMIN, 10000),
        (Priority.INTERNAL, 30000),
    ],
)
def test_queue_budgets(priority: Priority, budget: float) -> None:
    assert deadlines.queue_budget_ms(FakeSettings(), priority) == budget


def test_internal_deadline_never_exceeds_request_deadline() -> None:
    assert deadlines.internal_deadline_s(FakeSettings(), Priority.ADMIN) == 42  # 10 + 30 + 2
    assert deadlines.internal_deadline_s(FakeSettings(), Priority.INTERNAL) == 60  # 30 + 30 + 2, capped at 60


# --- backoff (plan 2.5 F9) --------------------------------------------------------------------------------------------


def test_decorrelated_jitter_bounds() -> None:
    rng = random.Random(5)
    jitter = DecorrelatedJitter(200, 2000, rng)
    values = [jitter.next_ms() for _ in range(2000)]
    assert all(200 <= value <= 2000 for value in values)
    assert max(values) == 2000  # it reaches the cap
    assert min(values) < 400


def test_decorrelated_jitter_step_and_reset() -> None:
    class Fixed:
        def uniform(self, a: float, b: float) -> float:
            return b

    assert decorrelated_jitter_ms(200, 200, 2000, Fixed()) == 600
    assert decorrelated_jitter_ms(600, 200, 2000, Fixed()) == 1800
    assert decorrelated_jitter_ms(1800, 200, 2000, Fixed()) == 2000
    jitter = DecorrelatedJitter(200, 2000, Fixed())
    assert [jitter.next_ms() for _ in range(3)] == [600, 1800, 2000]
    jitter.reset()
    assert jitter.next_s() == 0.6


# --- the per-worker queue (plan 7.8) ----------------------------------------------------------------------------------


def test_queue_is_bounded() -> None:
    queue = WaitQueue(2)
    assert queue.enter(Priority.INTERACTIVE) is not None
    assert queue.enter(Priority.INTERACTIVE) is not None
    assert queue.enter(Priority.INTERACTIVE) is None
    assert queue.refused == 1
    assert len(queue) == 2


def test_cancellation_order() -> None:
    assert CANCEL_ORDER[0] is Priority.BACKGROUND
    assert CANCEL_ORDER[-1] is Priority.INTERACTIVE
    queue = WaitQueue(3)
    background_old = queue.enter(Priority.BACKGROUND)
    background_new = queue.enter(Priority.BACKGROUND)
    stale = queue.enter(Priority.INTERACTIVE_STALE)
    assert background_old
    assert background_new
    assert stale
    first = queue.enter(Priority.INTERACTIVE)
    assert first is not None
    assert background_new.evicted.is_set()  # the newest background waiter goes first
    assert not background_old.evicted.is_set()
    queue.enter(Priority.INTERACTIVE)
    assert background_old.evicted.is_set()
    queue.enter(Priority.INTERACTIVE)
    assert stale.evicted.is_set()
    assert queue.enter(Priority.INTERACTIVE) is None  # interactive waiters are never evicted
    assert queue.enter(Priority.BACKGROUND) is None
    assert queue.evicted == 3
    assert queue.counts()["interactive"] == 3


def test_newcomer_never_evicts_its_betters() -> None:
    queue = WaitQueue(1)
    admin = queue.enter(Priority.ADMIN)
    assert admin is not None
    assert queue.enter(Priority.INTERNAL) is None  # internal is more expendable than admin
    assert queue.enter(Priority.INTERACTIVE_STALE) is None  # a caller with a stale copy is too
    assert queue.enter(Priority.INTERACTIVE) is not None  # a caller without one is not
    assert admin.evicted.is_set()


async def test_wait_until_slot_and_eviction() -> None:
    queue = WaitQueue(1)
    ticket = queue.enter(Priority.BACKGROUND)
    assert ticket is not None
    assert await queue.wait(ticket, 0.01) is True
    assert len(queue) == 0
    ticket = queue.enter(Priority.BACKGROUND)
    assert ticket is not None
    waiter = asyncio.ensure_future(queue.wait(ticket, 10))
    await asyncio.sleep(0.01)
    assert queue.enter(Priority.INTERACTIVE) is not None
    assert await asyncio.wait_for(waiter, 1) is False


async def test_canceled_wait_leaves_the_queue() -> None:
    queue = WaitQueue(5)
    ticket = queue.enter(Priority.INTERACTIVE)
    assert ticket is not None
    waiter = asyncio.ensure_future(queue.wait(ticket, 10))
    await asyncio.sleep(0.01)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert len(queue) == 0
