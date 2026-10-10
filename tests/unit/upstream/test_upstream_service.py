"""UpstreamService end to end over real temp databases and a fake egress: the 7.9 policy and 7.13 answers."""

from __future__ import annotations

import asyncio
import itertools
from typing import Any

import pytest
from upstream_fakes import (
    AuthSmugglingBlocked,
    CredentialLeakBlocked,
    EgressDisabled,
    FakeEgress,
    UpstreamConnectError,
    UpstreamTimeout,
    answer,
    make_ctx,
    make_service,
    read_rows,
    request,
)

from roxy.core.reasons import AuthClass, Egress, ReasonCode
from roxy.upstream import buckets, messages
from roxy.upstream.queue import Priority
from roxy.upstream.service import SingleFlightLost, UpstreamService

pytestmark = pytest.mark.asyncio

TEMPLATE = "games.roblox.com/v1/games"


async def fetch(service: UpstreamService, **fields: Any) -> Any:
    return await service.fetch(request(service, **fields), priority=Priority.INTERACTIVE, stale_available=False)


# --- 2xx, 3xx, 4xx: Roblox's answer is passed on --------------------------------------------------------------------


@pytest.mark.parametrize("status", [200, 201, 202, 204, 206])
async def test_any_2xx_is_success(service: UpstreamService, egress: FakeEgress, status: int) -> None:
    egress.handler = lambda e, out: answer(status, b"{}")
    result = await fetch(service)
    assert result.status == status
    assert result.reason is ReasonCode.UPSTREAM_OK
    assert result.upstream_status == status
    assert result.cacheable is True
    assert result.calls == 1
    assert result.attempts == 1
    assert result.egress is Egress.DIRECT
    assert result.auth_class is AuthClass.ANON
    assert egress.egresses() == [Egress.DIRECT]


async def test_success_writes_nothing_after_the_call(service: UpstreamService, ctx: Any) -> None:
    await fetch(service)
    assert read_rows(ctx.dbs.hot, "SELECT key FROM cooldown") == []
    assert read_rows(ctx.dbs.hot, "SELECT key FROM breaker") == []


async def test_outbound_request_shape(service: UpstreamService, egress: FakeEgress) -> None:
    await fetch(service, query=[("universeIds", "1"), ("universeIds", "2"), ("x", "a b")])
    _egress, out = egress.calls[0]
    assert out.url == "https://games.roblox.com/v1/games?universeIds=1&universeIds=2&x=a+b"
    assert out.method == "GET"
    assert out.follow_redirects is False
    assert out.purpose == "caller"
    assert out.content is None
    assert out.timeout.read == 15.0
    assert out.timeout.connect == 5.0


async def test_caller_accept_forwarded_only_when_safe(service: UpstreamService, egress: FakeEgress) -> None:
    await fetch(service, headers={"accept": "application/json"})
    await fetch(service, headers={"accept": "text/html"})
    assert egress.calls[0][1].headers.get("Accept") == "application/json"
    assert "Accept" not in egress.calls[1][1].headers


async def test_body_carries_content_type(service: UpstreamService, egress: FakeEgress) -> None:
    await fetch(service, method="POST", body=b'{"userIds":[1]}', content_type="application/json; charset=utf-8")
    out = egress.calls[0][1]
    assert out.content == b'{"userIds":[1]}'
    assert out.headers["Content-Type"] == "application/json; charset=utf-8"


@pytest.mark.parametrize("status", [400, 404, 410])
async def test_definitive_4xx_negative_cached(service: UpstreamService, egress: FakeEgress, status: int) -> None:
    egress.handler = lambda e, out: answer(status, b'{"errors":[]}')
    result = await fetch(service)
    assert result.status == status
    assert result.reason is ReasonCode.UPSTREAM_4XX
    assert result.negative_ttl_s == 60
    assert result.cacheable is False
    assert len(egress.calls) == 1


@pytest.mark.parametrize("status", [401, 405, 409, 422])
async def test_other_4xx_definitive_not_negative(service: UpstreamService, egress: FakeEgress, status: int) -> None:
    egress.handler = lambda e, out: answer(status, b"{}")
    result = await fetch(service)
    assert (result.status, result.reason, result.negative_ttl_s) == (status, ReasonCode.UPSTREAM_4XX, None)
    assert len(egress.calls) == 1


async def test_403_without_csrf_is_negative_cached(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: answer(403, b"{}")
    result = await fetch(service)
    assert result.negative_ttl_s == 60
    assert len(egress.calls) == 1


async def test_304_passed_through(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: answer(304, b"")
    result = await fetch(service)
    assert (result.status, result.reason, result.cacheable) == (304, ReasonCode.UPSTREAM_OK, False)


async def test_redirect_followed_within_allowed_hosts(service: UpstreamService, egress: FakeEgress) -> None:
    def handler(e: Egress, out: Any) -> Any:
        if out.url.startswith("https://games.roblox.com"):
            return answer(302, b"", {"location": "https://users.roblox.com/v1/users/1"})
        return answer(200, b'{"id":1}')

    egress.handler = handler
    result = await fetch(service)
    assert result.status == 200
    assert [out.url for _, out in egress.calls] == [
        "https://games.roblox.com/v1/games?universeIds=1",
        "https://users.roblox.com/v1/users/1",
    ]
    assert result.calls == 2
    assert result.attempts == 1


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/x",
        "http://users.roblox.com/v1",
        "https://roblox.com.evil.com/",
        "https://u:p@users.roblox.com/",
    ],
)
async def test_redirect_off_allowlist_not_followed(service: UpstreamService, egress: FakeEgress, location: str) -> None:
    egress.handler = lambda e, out: answer(302, b"", {"location": location})
    result = await fetch(service)
    assert result.status == 302
    assert len(egress.calls) == 1
    assert "location" not in result.headers  # never relayed toward a caller


@pytest.mark.parametrize(
    "location",
    [
        "/v1/games/%2E%2E/%2E%2E/v2/secret",  # encoded dot segments (v1 bug B4)
        "/v1/%2E%2E%2Fv2%2Fsecret",  # encoded slashes
        "/v1/x%3Fy",  # an encoded `?` inside a segment
        "/v1/x%25y",  # double encoding
        "/v1/a b",  # a space: not a URL any caller could send
    ],
)
async def test_redirect_hop_must_pass_the_caller_path_checks(
    service: UpstreamService, egress: FakeEgress, location: str
) -> None:
    """Finding cred-3: every hop goes through `proxy/validate.py parse_redirect` (then `parse_upstream_url`), the
    checks a caller's own path gets (plan 9.10 "redirects are re-validated"); a hop that fails them is not
    followed, Roblox's 3xx goes back."""
    egress.handler = lambda e, out: answer(302, b"", {"location": location})
    result = await fetch(service)
    assert (result.status, len(egress.calls)) == (302, 1)
    assert "redirect not followed" in result.trace.notes


async def test_a_followed_hop_is_the_url_that_was_checked(service: UpstreamService, egress: FakeEgress) -> None:
    """The URL fetched is rebuilt from the validated parse: dot segments resolved, the query kept in order."""

    def handler(e: Egress, out: Any) -> Any:
        if "/v1/games" in out.url:
            return answer(302, b"", {"location": "../v2/./next?b=2&a=1"})
        return answer(200, b"{}")

    egress.handler = handler
    result = await fetch(service)
    assert result.status == 200
    assert [out.url for _, out in egress.calls][1] == "https://games.roblox.com/v2/next?b=2&a=1"


@pytest.mark.parametrize(
    ("location", "followed"),
    [
        ("/v1/games/next", True),  # granted by the row's single-segment wildcard
        ("/v1/games/%2E%2E%2Fsecret", False),  # the raw text matched `*`; decoded it is not a valid path at all
        ("/v1/games/a/b", False),  # two segments: the exact row does not grant it
    ],
)
async def test_credential_hop_is_matched_on_its_decoded_path(
    service: UpstreamService, egress: FakeEgress, rules: Any, location: str, followed: bool
) -> None:
    """Finding cred-3: the allowlist sees the hop's decoded, normalized target, as it sees a caller path, so the
    cookie never follows a hop its rows do not name (C2 item 7, F3 exact grants)."""
    rules.allow_credential("games.roblox.com/v1/games/*")

    def handler(e: Egress, out: Any) -> Any:
        if out.url.startswith("https://games.roblox.com/v1/games/start"):
            return answer(302, b"", {"location": location})
        return answer(200, b"{}")

    egress.handler = handler
    result = await fetch(service, path="/v1/games/start", query=[])
    assert egress.egresses() == [Egress.CREDENTIAL] * (2 if followed else 1)
    assert result.status == (200 if followed else 302)


@pytest.mark.parametrize("location", ["//[", "https://[x/", "http://[::1", "https://games.roblox.com:99999/x"])
async def test_malformed_redirect_location_is_answered_not_raised(
    service: UpstreamService, egress: FakeEgress, ctx: Any, location: str
) -> None:
    """Ingress review: a Location that does not parse is a redirect not followed. Roblox's own 3xx goes back (the
    "Roblox answered" row of 7.13) after the normal bookkeeping; it is never a 500 internal_error."""
    egress.handler = lambda e, out: answer(302, b"moved", {"location": location})
    result = await fetch(service)
    assert (result.status, result.reason, result.calls, result.attempts) == (302, ReasonCode.UPSTREAM_OK, 1, 1)
    assert result.body == b"moved"
    assert "redirect not followed" in result.trace.notes
    assert len(egress.calls) == 1
    assert "location" not in result.headers


async def test_redirect_hops_capped_at_three(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: answer(302, b"", {"location": "https://games.roblox.com/v1/loop"})
    result = await fetch(service)
    assert result.status == 302
    assert len(egress.calls) == 4  # the call plus 3 hops


async def test_safe_response_headers_only(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: answer(
        200, b"{}", {"set-cookie": "a=b", "x-csrf-token": "tok", "cache-control": "max-age=5", "x-other": "1"}
    )
    result = await fetch(service)
    assert result.headers == {"content-type": "application/json", "cache-control": "max-age=5"}
    assert result.trace.upstream_headers["x-csrf-token"] == "[redacted]"
    assert result.trace.upstream_headers["set-cookie"] == "[redacted]"


# --- 429: cooldown for every worker, no immediate retry ---------------------------------------------------------------


async def test_429_opens_cooldown_and_is_not_retried(
    service: UpstreamService, egress: FakeEgress, ctx: Any, clock: Any
) -> None:
    egress.disabled.add(Egress.ROTATOR)  # otherwise the rotator would serve while direct cools down
    egress.handler = lambda e, out: answer(429, b"slow down", {"retry-after": "30"})
    result = await fetch(service)
    assert result.status == 429
    assert result.reason is ReasonCode.UPSTREAM_COOLDOWN
    assert result.body == messages.BUSY_MESSAGE.encode()
    assert result.content_type == "text/plain; charset=utf-8"
    assert result.retry_after_s == 30
    assert result.cooldown_s == 30
    assert result.upstream_status == 429
    assert result.negative_ttl_s == 30
    assert len(egress.calls) == 1
    rows = read_rows(ctx.dbs.hot, "SELECT key, source FROM cooldown")
    assert (f"endpoint:{TEMPLATE}:direct", "retry_after") in rows
    assert ctx.recorder.rows_429[0]["endpoint_template"] == TEMPLATE
    assert ctx.recorder.rows_429[0]["retry_after_s"] == 30.0
    # The next request makes no call at all and tells the caller how long to wait.
    clock.advance(10)
    again = await fetch(service)
    assert len(egress.calls) == 1
    assert again.reason is ReasonCode.UPSTREAM_COOLDOWN
    assert again.retry_after_s == 20
    assert again.attempts == 0
    assert again.calls == 0


async def test_429_without_header_uses_default_backoff(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: answer(429, b"")
    result = await fetch(service)
    assert 30 <= result.retry_after_s <= 33  # cooldown_default_s plus at most 10 % jitter


def busiest_minute(times_ms: list[float]) -> int:
    """The most calls any closed 60 s span holds (how Roblox would count them)."""
    ordered, best, first = sorted(times_ms), 0, 0
    for index, at in enumerate(ordered):
        while at - ordered[first] > 60_000:
            first += 1
        best = max(best, index - first + 1)
    return best


async def test_429_cuts_below_the_rate_roblox_refused_and_the_bucket_holds_it(
    service: UpstreamService, egress: FakeEgress, ctx: Any, clock: Any
) -> None:
    """Finding LOAD-1 end to end: Roblox allows 60 calls a minute and refuses the 61st. The endpoint runs at the
    default 120 a minute, so the cut must start from the 61 calls the endpoint's meter saw, not from 120 (84 would
    not slow it down at all): one 429 takes it to 42.7 a minute with burst 3, and after the cooldown no minute
    holds more than 42 calls however hard callers push."""
    egress.disabled.add(Egress.ROTATOR)
    sent: list[float] = []
    refused: list[float] = []

    def roblox(e: Egress, out: Any) -> Any:
        sent.append(clock.now_ms())
        if busiest_minute(sent[-61:]) > 60:  # Roblox: at most 60 calls in any minute
            refused.append(sent[-1])
            return answer(429, b"", {"retry-after": "30"})
        return answer(200)

    egress.handler = roblox
    results = [await fetch(service) for _ in range(61)]
    assert [r.status for r in results[:60]] == [200] * 60
    assert (results[-1].upstream_status, results[-1].reason) == (429, ReasonCode.UPSTREAM_COOLDOWN)
    limit = ctx.rules.snapshot.upstream_limit(f"endpoint:{TEMPLATE}")
    assert (limit.per_min, limit.burst, limit.origin) == (42.7, 3, "adaptive")
    decrease = [detail for kind, _s, _r, detail in ctx.recorder.events if kind == "adaptive_rate_decrease"]
    assert decrease[0]["evidence"]["observed_calls"] == 61
    clock.advance(31)  # the cooldown is over
    before = len(sent)
    end = clock.now() + 240
    while clock.now() < end:
        if (await fetch(service)).status != 200:
            clock.advance(0.25)  # a busy answer: the caller comes back a moment later
    after = sent[before:]
    assert len(after) >= 120  # it keeps serving, at the learned pace
    assert busiest_minute(after) <= 42
    # The minutes that began before the cut hold at most 42 new and old calls together (the backlog of the 61 old
    # calls is paced out first), so Roblox never had to say 429 again.
    for at in after:
        assert sum(1 for t in sent if at - 60_000 <= t <= at) <= 42
    assert len(refused) == 1


class FastSleepClock:
    """A stepping clock whose sleeps end early, like asyncio's on WSL 2, where the monotonic clock runs about 10
    percent fast against the wall clock the buckets use: a sleep of `s` moves the wall clock only 0.9 x s."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def now(self) -> float:
        return float(self.inner.now())

    def now_ms(self) -> int:
        return int(self.inner.now_ms())

    def monotonic(self) -> float:
        return float(self.inner.monotonic())

    def advance(self, seconds: float) -> None:
        self.inner.advance(seconds)

    async def sleep(self, seconds: float) -> None:
        self.inner.advance(max(0.0, seconds) * 0.9)
        await asyncio.sleep(0)


async def test_a_call_never_leaves_before_its_slot(dbs: Any, rules: Any) -> None:
    """The queue's sleep is measured on another clock than the slot: a call woken early sleeps the rest, so calls
    keep the bucket's spacing on the buckets' own clock (`_sleep_until_slot`)."""
    from upstream_fakes import SteppingClock

    clock = FastSleepClock(SteppingClock())
    sent: list[int] = []

    def roblox(e: Egress, out: Any) -> Any:
        sent.append(clock.now_ms())
        return answer(200)

    egress = FakeEgress(roblox, disabled={Egress.ROTATOR})
    rules.limit(f"endpoint:{TEMPLATE}", 60, 1)
    service = make_service(make_ctx(dbs, clock, egress, rules=rules))
    for _ in range(4):
        assert (await fetch(service)).status == 200
    spacing = buckets.BucketSpec(f"endpoint:{TEMPLATE}", 60, 1).interval_ms
    gaps = [later - earlier for earlier, later in itertools.pairwise(sent)]
    assert all(gap >= spacing - 2 for gap in gaps), (gaps, spacing)  # never 10 percent early


async def test_429_fallback_on_429_uses_other_anonymous_egress(
    service: UpstreamService, egress: FakeEgress, settings: Any
) -> None:
    settings.set(fallback_on_429=1)
    egress.handler = lambda e, out: answer(429, b"", {"retry-after": "5"}) if e is Egress.DIRECT else answer(200)
    result = await fetch(service)
    assert egress.egresses() == [Egress.DIRECT, Egress.ROTATOR]
    assert result.status == 200
    assert result.egress is Egress.ROTATOR


async def test_429_fallback_never_onto_credential(service: UpstreamService, egress: FakeEgress, settings: Any) -> None:
    settings.set(fallback_on_429=1)
    egress.disabled.add(Egress.ROTATOR)
    egress.handler = lambda e, out: answer(429, b"", {"retry-after": "5"})
    result = await fetch(service)
    assert egress.egresses() == [Egress.DIRECT]
    assert result.reason is ReasonCode.UPSTREAM_COOLDOWN


async def test_x_ratelimit_remaining_zero_cools_down_even_on_200(
    service: UpstreamService, egress: FakeEgress, ctx: Any
) -> None:
    egress.disabled.add(Egress.ROTATOR)
    egress.handler = lambda e, out: answer(200, b"{}", {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "12"})
    first = await fetch(service)
    assert first.status == 200
    rows = read_rows(ctx.dbs.hot, "SELECT key, source FROM cooldown")
    assert rows == [(f"endpoint:{TEMPLATE}:direct", "ratelimit_reset")]
    second = await fetch(service)
    assert second.reason is ReasonCode.UPSTREAM_COOLDOWN
    assert second.retry_after_s == 12
    assert len(egress.calls) == 1


# --- 5xx, timeouts, connect errors: bounded retries with jittered backoff -----------------------------------------


async def test_5xx_retried_with_backoff_then_success(service: UpstreamService, egress: FakeEgress, clock: Any) -> None:
    answers = iter([answer(502, b"bad gateway"), answer(200)])
    egress.handler = lambda e, out: next(answers)
    result = await fetch(service)
    assert result.status == 200
    assert result.attempts == 2
    assert result.calls == 2
    assert len(clock.slept) == 1
    assert 0.2 <= clock.slept[0] <= 2.0  # decorrelated jitter within [backoff_base_ms, backoff_cap_ms]


@pytest.mark.parametrize("status", [500, 502, 503, 504])
async def test_5xx_after_retries_gives_real_status(service: UpstreamService, egress: FakeEgress, status: int) -> None:
    egress.handler = lambda e, out: answer(status, b"oops")
    result = await fetch(service)
    assert result.status == status
    assert result.reason is ReasonCode.UPSTREAM_5XX
    assert result.body == messages.FAILED_MESSAGE.encode()
    assert result.retry_after_s == 5
    assert len(egress.calls) == 2  # upstream_max_attempts = 2


async def test_5xx_relays_roblox_retry_after(service: UpstreamService, egress: FakeEgress, settings: Any) -> None:
    settings.set(upstream_max_attempts=1)
    egress.handler = lambda e, out: answer(503, b"", {"retry-after": "17"})
    result = await fetch(service)
    assert result.retry_after_s == 17


async def test_retry_only_if_deadline_allows(service: UpstreamService, egress: FakeEgress, clock: Any) -> None:
    egress.handler = lambda e, out: answer(500, b"")
    req = request(service)
    req.deadline_at = clock.monotonic() + 1.1  # 1.1 s left: a retry after >= 0.2 s backoff would leave < 1 s
    result = await service.fetch(req, priority=Priority.INTERACTIVE, stale_available=False)
    assert len(egress.calls) == 1
    assert result.reason is ReasonCode.UPSTREAM_5XX


@pytest.mark.parametrize(
    ("error", "status", "reason"),
    [
        (UpstreamTimeout("slow"), 504, ReasonCode.UPSTREAM_TIMEOUT),
        (UpstreamConnectError("refused"), 502, ReasonCode.UPSTREAM_CONNECT),
    ],
)
async def test_timeouts_and_connect_errors(
    service: UpstreamService, egress: FakeEgress, error: Exception, status: int, reason: ReasonCode
) -> None:
    egress.handler = lambda e, out: error
    result = await fetch(service)
    assert (result.status, result.reason, result.retry_after_s) == (status, reason, 5)
    assert result.body == messages.FAILED_MESSAGE.encode()
    assert len(egress.calls) == 2


async def test_deadline_already_passed(service: UpstreamService, egress: FakeEgress, clock: Any) -> None:
    req = request(service)
    req.deadline_at = clock.monotonic() - 1
    result = await service.fetch(req, priority=Priority.INTERACTIVE, stale_available=False)
    assert (result.status, result.reason, result.retry_after_s) == (504, ReasonCode.DEADLINE, 5)
    assert egress.calls == []


# --- the guard, disabled egress ---------------------------------------------------------------------------------------


async def test_leak_guard_trip_is_never_retried(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: CredentialLeakBlocked("found")
    result = await fetch(service)
    assert (result.status, result.reason) == (503, ReasonCode.LEAK_BLOCKED)
    assert len(egress.calls) == 1
    assert result.calls == 0


async def test_public_marker_is_an_auth_smuggling_refusal(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: AuthSmugglingBlocked("marker")
    result = await fetch(service)
    assert (result.status, result.reason) == (400, ReasonCode.AUTH_SMUGGLING)
    assert result.body == messages.AUTH_SMUGGLING_MESSAGE.encode()


async def test_egress_disabled_at_send_reroutes(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: EgressDisabled("switched off") if e is Egress.DIRECT else answer(200)
    result = await fetch(service)
    assert egress.egresses() == [Egress.DIRECT, Egress.ROTATOR]
    assert result.status == 200
    assert result.attempts == 1  # the refused send did not reach Roblox: not an attempt


async def test_every_egress_disabled(service: UpstreamService, egress: FakeEgress) -> None:
    egress.disabled.update({Egress.DIRECT, Egress.ROTATOR})
    result = await fetch(service)
    assert (result.status, result.reason, result.retry_after_s) == (503, ReasonCode.EGRESS_DISABLED, 60)
    assert egress.calls == []


async def test_all_paths_down_alerts_with_the_v1_subject(
    service: UpstreamService, egress: FakeEgress, ctx: Any
) -> None:
    pytest.importorskip("roxy.notify.alerts")
    sent: list[Any] = []
    ctx.alerts = type("Alerts", (), {"notify": staticmethod(sent.append)})()
    egress.disabled.update({Egress.DIRECT, Egress.ROTATOR})
    await fetch(service)
    assert len(sent) == 1
    assert sent[0].subject == "Roxy: all upstream methods unavailable"
    assert sent[0].cooldown_key == "all_unavailable"
    assert sent[0].fields["egresses"] == {"direct": "disabled in test", "rotator": "disabled in test"}


async def test_no_egress_package_means_egress_disabled(dbs: Any, clock: Any) -> None:
    ctx = make_ctx(dbs, clock, egress=None)
    ctx.egress = None
    service = make_service(ctx)
    result = await fetch(service)
    assert result.reason is ReasonCode.EGRESS_DISABLED


async def test_rotator_used_only_when_direct_cannot(service: UpstreamService, egress: FakeEgress, ctx: Any) -> None:
    egress.handler = lambda e, out: answer(429, b"", {"retry-after": "60"}) if e is Egress.DIRECT else answer(200)
    first = await fetch(service)
    assert first.reason is ReasonCode.UPSTREAM_COOLDOWN
    second = await fetch(service)
    assert second.status == 200
    assert egress.egresses() == [Egress.DIRECT, Egress.ROTATOR]


# --- CSRF ------------------------------------------------------------------------------------------------------------


async def test_csrf_handshake_with_cached_token(service: UpstreamService, egress: FakeEgress, ctx: Any) -> None:
    def handler(e: Egress, out: Any) -> Any:
        if out.headers.get("x-csrf-token") == "tok123":
            return answer(200, b"{}")
        return answer(403, b"", {"x-csrf-token": "tok123"})

    egress.handler = handler
    first = await fetch(service, method="POST", body=b"{}", content_type="application/json")
    assert first.status == 200
    assert len(egress.calls) == 2
    assert first.trace.retries == 1
    assert first.calls == 2
    # Row 117: the retry is recorded with v1's reason text (v1 `log_retry(403, "CSRF token refresh")`).
    retries = ctx.recorder.retries
    assert [(r["status"], r["reason"], r["egress"], r["endpoint_template"]) for r in retries] == [
        (403, "CSRF token refresh", "direct", TEMPLATE)
    ]
    # Both calls took a bucket slot: the endpoint bucket advanced by two intervals (120 a minute with burst 10 as a
    # window bucket: 61,000 / 111 ms each) and its meter counted both.
    interval = buckets.BucketSpec(f"endpoint:{TEMPLATE}", 120, 10).interval_ms
    tats = ctx.dbs.hot.read_sync(lambda conn: buckets.read_tats(conn, [f"endpoint:{TEMPLATE}"]))
    assert tats[f"endpoint:{TEMPLATE}"] == pytest.approx(ctx.clock.now_ms() + 2 * interval, abs=5)
    meters = ctx.dbs.hot.read_sync(lambda conn: buckets.read_meters(conn, [f"endpoint:{TEMPLATE}"]))
    assert meters[f"endpoint:{TEMPLATE}"].current == 2
    second = await fetch(service, method="POST", body=b"{}", content_type="application/json")
    assert second.status == 200
    assert len(egress.calls) == 3  # the cached token went out with the first try
    assert egress.calls[2][1].headers["x-csrf-token"] == "tok123"


async def test_csrf_second_challenge_is_definitive(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: answer(403, b"", {"x-csrf-token": "again"})
    result = await fetch(service, method="POST", body=b"{}")
    assert (result.status, result.reason) == (403, ReasonCode.UPSTREAM_4XX)
    assert len(egress.calls) == 2
    assert result.negative_ttl_s is None  # a CSRF challenge is not a permission answer


async def test_get_never_carries_a_csrf_token(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: answer(403, b"", {"x-csrf-token": "t"}) if not out.headers else answer(200)
    await fetch(service, method="POST", body=b"{}")
    egress.calls.clear()
    egress.handler = lambda e, out: answer(200)
    await fetch(service)
    assert "x-csrf-token" not in egress.calls[0][1].headers


# --- buckets, queue, cancellation -------------------------------------------------------------------------------------


async def test_bucket_paces_calls(service: UpstreamService, egress: FakeEgress, rules: Any, clock: Any) -> None:
    rules.limit(f"endpoint:{TEMPLATE}", 60, 1)  # at most 60 in any minute, no burst: one every 61 / 60 s
    start = clock.now()
    for _ in range(3):
        result = await fetch(service)
        assert result.status == 200
    assert clock.now() - start == pytest.approx(2 * 61 / 60, abs=0.01)  # slots at 0, 1.017 and 2.033 s
    assert len(egress.calls) == 3


async def test_bucket_busy_beyond_queue_budget(
    service: UpstreamService, egress: FakeEgress, rules: Any, settings: Any
) -> None:
    rules.limit(f"endpoint:{TEMPLATE}", 6, 1)  # at most 6 in any minute: one per 10.17 s
    settings.set(queue_wait_interactive_ms=4000)
    assert (await fetch(service)).status == 200
    result = await fetch(service)
    assert (result.status, result.reason) == (429, ReasonCode.UPSTREAM_BUSY)
    assert result.retry_after_s == 11  # 10.17 s, rounded up
    assert result.body == messages.BUSY_MESSAGE.encode()
    assert len(egress.calls) == 1


async def test_stale_available_waits_less(service: UpstreamService, egress: FakeEgress, rules: Any) -> None:
    rules.limit(f"endpoint:{TEMPLATE}", 60, 1)
    await fetch(service)
    req = request(service)
    result = await service.fetch(req, priority=Priority.INTERACTIVE, stale_available=True)
    assert result.reason is ReasonCode.UPSTREAM_BUSY  # 1 s wait exceeds queue_wait_stale_ms (500 ms)


async def test_cancel_during_wait_refunds_slot(dbs: Any, rules: Any) -> None:
    from upstream_fakes import FakeEgress as Egr
    from upstream_fakes import FakeRules as Rules

    from roxy.core.clock import FakeClock

    clock = FakeClock()  # real sleeps: the request really waits, so it can be canceled while waiting
    rules = Rules()
    rules.limit(f"endpoint:{TEMPLATE}", 60, 1)
    ctx = make_ctx(dbs, clock, Egr(), rules=rules)
    service = make_service(ctx)
    await fetch(service)
    key = f"endpoint:{TEMPLATE}"
    before = dbs.hot.read_sync(lambda conn: buckets.read_tats(conn, [key]))[key]
    task = asyncio.ensure_future(fetch(service))
    for _ in range(50):
        await asyncio.sleep(0.01)
        if dbs.hot.read_sync(lambda conn: buckets.read_tats(conn, [key]))[key] > before:
            break
    interval = buckets.BucketSpec(key, 60, 1).interval_ms
    assert dbs.hot.read_sync(lambda conn: buckets.read_tats(conn, [key]))[key] == pytest.approx(
        before + interval, abs=1
    )
    assert dbs.hot.read_sync(lambda conn: buckets.read_meters(conn, [key]))[key].current == 2
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(50):
        if dbs.hot.read_sync(lambda conn: buckets.read_tats(conn, [key]))[key] == pytest.approx(before, abs=1):
            break
        await asyncio.sleep(0.01)
    assert dbs.hot.read_sync(lambda conn: buckets.read_tats(conn, [key]))[key] == pytest.approx(before, abs=1)
    assert dbs.hot.read_sync(lambda conn: buckets.read_meters(conn, [key]))[key].current == 1  # the refund uncounted it
    assert len(ctx.egress.calls) == 1
    assert len(service.queue) == 0


async def test_queue_overflow(service: UpstreamService, egress: FakeEgress, rules: Any, settings: Any) -> None:
    rules.limit(f"endpoint:{TEMPLATE}", 60, 1)
    settings.set(queue_max_length=1)
    await fetch(service)
    blocker = service.queue.enter(Priority.INTERACTIVE)  # the only queue place is taken
    assert blocker is not None
    result = await fetch(service)
    assert (result.status, result.reason) == (429, ReasonCode.QUEUE_OVERFLOW)
    assert result.retry_after_s >= 1
    service.queue.leave(blocker)


# --- credential confinement ------------------------------------------------------------------------------------------


async def test_non_allowlisted_never_uses_credential(service: UpstreamService, egress: FakeEgress) -> None:
    for status in (200, 429, 500):
        egress.handler = lambda e, out, s=status: answer(s, b"")
        await fetch(service)
    assert Egress.CREDENTIAL not in egress.egresses()


async def test_allowlisted_get_uses_credential(
    service: UpstreamService, egress: FakeEgress, rules: Any, ctx: Any
) -> None:
    rules.allow_credential("games.roblox.com/v1/games", cache_private=True)
    result = await fetch(service)
    assert egress.egresses() == [Egress.CREDENTIAL]
    assert result.auth_class is AuthClass.CRED
    assert result.cacheable is False  # cache_private: never stored
    assert result.private is True  # and never handed to a single-flight follower (finding cred-4, request U1)
    assert egress.calls[0][1].purpose == "caller"
    tats = dbs_tats(ctx, ["egress:credential", "egress:credential:probe"])
    assert "egress:credential" in tats
    assert "egress:credential:probe" not in tats


def dbs_tats(ctx: Any, keys: list[str]) -> dict[str, float]:
    return ctx.dbs.hot.read_sync(lambda conn: buckets.read_tats(conn, keys))


async def test_allowlisted_not_private_is_cacheable(service: UpstreamService, rules: Any) -> None:
    rules.allow_credential("games.roblox.com/v1/games", cache_private=False)
    result = await fetch(service)
    assert result.cacheable is True
    assert result.auth_class is AuthClass.CRED
    assert result.private is False


async def test_private_follows_the_row_the_answer_was_fetched_under(
    service: UpstreamService, egress: FakeEgress, rules: Any
) -> None:
    """Finding cred-4 (request U1): only the upstream knows the allowlist row it routed under, so it reports a
    credential answer fetched under a `cache_private` row as `private`, failures included (a 429, a 5xx), and the
    cache keeps such an answer to its own request. Anonymous answers are never private."""
    result = await fetch(service)
    assert (result.egress, result.private) == (Egress.DIRECT, False)
    rules.allow_credential("games.roblox.com/v1/games", cache_private=True)
    egress.handler = lambda e, out: answer(503, b"busy")
    failed = await fetch(service)
    assert failed.egress is Egress.CREDENTIAL
    assert failed.reason is ReasonCode.UPSTREAM_5XX
    assert failed.private is True


async def test_allowlisted_post_never_uses_credential(service: UpstreamService, egress: FakeEgress, rules: Any) -> None:
    rules.allow_credential("games.roblox.com/v1/games")
    await fetch(service, method="POST", body=b"{}")
    assert egress.egresses() == [Egress.DIRECT]


async def test_allowlisted_never_falls_back_to_anonymous(
    service: UpstreamService, egress: FakeEgress, rules: Any
) -> None:
    rules.allow_credential("games.roblox.com/v1/games")
    egress.credential.status_value = "rejected"
    result = await fetch(service)
    assert (result.status, result.reason, result.retry_after_s) == (503, ReasonCode.CREDENTIAL_UNAVAILABLE, 300)
    assert egress.calls == []


async def test_allowlisted_identical_anonymous_may_go_anonymous(
    service: UpstreamService, egress: FakeEgress, rules: Any
) -> None:
    rules.allow_credential("games.roblox.com/v1/games", identical_anonymous=True)
    egress.credential.cooldown = 30
    result = await fetch(service)
    assert result.status == 200
    assert egress.egresses() == [Egress.DIRECT]


async def test_credential_429_sets_fleet_cooldown_and_never_cascades(
    service: UpstreamService, egress: FakeEgress, rules: Any, ctx: Any, settings: Any
) -> None:
    settings.set(fallback_on_429=1)
    rules.allow_credential("games.roblox.com/v1/games")
    egress.handler = lambda e, out: answer(429, b"", {"retry-after": "45"})
    result = await fetch(service)
    assert egress.egresses() == [Egress.CREDENTIAL]  # no anonymous retry for an allowlisted endpoint
    assert result.reason is ReasonCode.UPSTREAM_COOLDOWN
    keys = {row[0] for row in read_rows(ctx.dbs.hot, "SELECT key FROM cooldown")}
    assert "credential" in keys
    assert f"endpoint:{TEMPLATE}:credential" in keys
    assert egress.credential.cooldowns == [(45.0, "retry_after")]
    again = await fetch(service)
    assert again.reason is ReasonCode.CREDENTIAL_UNAVAILABLE
    assert len(egress.calls) == 1


async def test_credential_401_confirmed_by_probe_marks_rejected(
    service: UpstreamService, egress: FakeEgress, rules: Any
) -> None:
    rules.allow_credential("games.roblox.com/v1/games")
    egress.handler = lambda e, out: answer(401, b"{}")
    result = await fetch(service)
    assert (result.status, result.reason) == (401, ReasonCode.UPSTREAM_4XX)
    for _ in range(100):
        if egress.credential.rejections:
            break
        await asyncio.sleep(0.01)
    assert len(egress.credential.rejections) == 1
    probe_out = egress.calls[1][1]
    assert probe_out.url == "https://users.roblox.com/v1/users/authenticated"
    assert probe_out.purpose == "credential_probe"
    assert egress.calls[1][0] is Egress.CREDENTIAL


async def test_credential_401_not_confirmed_keeps_credential(
    service: UpstreamService, egress: FakeEgress, rules: Any
) -> None:
    rules.allow_credential("games.roblox.com/v1/games")
    egress.handler = lambda e, out: answer(200, b'{"id":5}') if "authenticated" in out.url else answer(401)
    await fetch(service)
    for _ in range(30):
        await asyncio.sleep(0.01)
    assert egress.credential.rejections == []


async def test_allowlist_and_routing_matches_share_one_regex_budget(
    service: UpstreamService, egress: FakeEgress, rules: Any
) -> None:
    """Ingress review (plan 9.9): stored slow allowlist and routing regexes (imported, never judged again) cost a
    crafted request at most the regex budget, and a cut-off allowlist match never grants the credential."""
    import time

    from roxy.rules.match import REGEX_REQUEST_BUDGET_S, regex_timeouts_total
    from roxy.rules.models import CredentialAllowlistRow, RoutingRuleRow

    slow = r"x+x+x+y"  # refused for new rules (rules/regex_cost.py), but a stored row keeps matching
    rules.credential_rows.extend(
        CredentialAllowlistRow(id=i, pattern=slow + "(?:q)?" * i, type="regex", methods="GET", cache_private=True)
        for i in range(1, 9)
    )
    rules.routing_rows.extend(
        RoutingRuleRow(id=i, pattern=slow + "(?:r)?" * i, type="regex", mode="rotator_only") for i in range(1, 9)
    )
    rules.rebuild()
    before = regex_timeouts_total()
    started = time.perf_counter()
    result = await fetch(service, path="/" + "x" * 3000, query=[])
    elapsed = time.perf_counter() - started
    assert elapsed < REGEX_REQUEST_BUDGET_S + 0.25, f"{elapsed * 1000:.0f} ms of regex time"
    assert regex_timeouts_total() > before  # the slow rows really were tried (the probe is not vacuous)
    assert result.auth_class is AuthClass.ANON
    assert Egress.CREDENTIAL not in egress.egresses()


class CredentialUnavailable(EgressDisabled):
    """The egress package's refusal at send time (mapped by its base class name, like the real one)."""

    def __init__(self, why: str, retry_after_s: int | None) -> None:
        super().__init__(why)
        self.why = why
        self.retry_after_s = retry_after_s


@pytest.mark.parametrize(
    ("why", "hint", "expected"),
    [("cooling_down", 42, 42), ("degraded", 10, 10), ("rejected", 300, 300), ("not_confirmed", None, 300)],
)
async def test_credential_refused_at_send_time_answers_its_own_retry_after(
    service: UpstreamService, egress: FakeEgress, rules: Any, why: str, hint: int | None, expected: int
) -> None:
    """Wire report: the credential manager refused at the last moment (its own authoritative check). The 503 says
    when to come back from what it said (a cooldown's real remaining time), not a fixed 300 s; still never
    anonymous instead (plan 6.9)."""
    rules.allow_credential("games.roblox.com/v1/games")
    egress.handler = lambda e, out: CredentialUnavailable(why, hint)
    result = await fetch(service)
    assert (result.status, result.reason, result.retry_after_s) == (503, ReasonCode.CREDENTIAL_UNAVAILABLE, expected)
    assert egress.egresses() == [Egress.CREDENTIAL]
    assert result.cooldown_s == (expected if why == "cooling_down" else None)


async def test_credential_cooling_down_in_the_manager_only_answers_its_remaining_time(
    service: UpstreamService, egress: FakeEgress, rules: Any
) -> None:
    """The manager may know a cooldown hot.db does not (kept in memory during an outage): routing uses it too."""
    rules.allow_credential("games.roblox.com/v1/games")
    egress.credential.cooldown = 37.2
    result = await fetch(service)
    assert (result.status, result.reason, result.retry_after_s) == (503, ReasonCode.CREDENTIAL_UNAVAILABLE, 38)
    assert egress.calls == []


def break_hot_writes(ctx: Any, monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    """Make hot.db refuse every write while `state["broken"]` is True (reads keep working, like a read-only file)."""
    from roxy.storage.db import SharedStateUnavailable

    state = {"broken": False}
    real_write = ctx.dbs.hot.write

    async def write(fn: Any, **kwargs: Any) -> Any:
        if state["broken"]:
            raise SharedStateUnavailable("hot", "attempt to write a readonly database")
        return await real_write(fn, **kwargs)

    monkeypatch.setattr(ctx.dbs.hot, "write", write)
    return state


@pytest.mark.parametrize("allowlisted", [False, True], ids=["direct", "credential"])
async def test_429_during_a_hot_outage_still_cools_down(
    service: UpstreamService,
    egress: FakeEgress,
    rules: Any,
    ctx: Any,
    clock: Any,
    settings: Any,
    monkeypatch: pytest.MonkeyPatch,
    allowlisted: bool,
) -> None:
    """Finding UP-COOLDOWN-LOST (plan 7.5, C7): Roblox says 429 with Retry-After 60 just as hot.db stops taking
    writes. The caller gets the cooldown answer (not `degraded`), the cooldown is kept in this worker, the next
    request inside the 60 s never reaches Roblox through that path, and the row reaches hot.db (for every worker)
    once it can. The rotator is off, so "that path" is the only one (with it on, it would take over by design)."""
    settings.set(rotator_enabled=0)
    if allowlisted:
        rules.allow_credential("games.roblox.com/v1/games")
    hot = break_hot_writes(ctx, monkeypatch)

    def handler(e: Egress, out: Any) -> Any:
        hot["broken"] = True  # hot.db goes read-only while Roblox is answering
        return answer(429, b"{}", {"retry-after": "60"})

    egress.handler = handler
    first = await fetch(service)
    assert (first.status, first.reason, first.upstream_status) == (429, ReasonCode.UPSTREAM_COOLDOWN, 429)
    assert first.retry_after_s == 60
    egress_used = Egress.CREDENTIAL if allowlisted else Egress.DIRECT
    assert egress.egresses() == [egress_used]
    kept = {row.key for row in service.local_cooldowns.pending(clock.now_ms())}
    assert f"endpoint:{TEMPLATE}:{egress_used.value}" in kept
    if allowlisted:
        assert "credential" in kept
        assert egress.credential.cooldowns == [(60.0, "retry_after")]  # the manager keeps its own copy too
    # Still read-only five seconds later: nothing reaches Roblox, the answer says how long is left.
    clock.advance(5)
    second = await fetch(service)
    assert len(egress.calls) == 1
    assert second.status in (429, 503)
    assert second.retry_after_s == 55
    # hot.db recovers: the next request shares the cooldown fleet-wide first, and still does not call Roblox.
    hot["broken"] = False
    clock.advance(5)
    third = await fetch(service)
    assert len(egress.calls) == 1
    assert third.retry_after_s == 50
    rows = {row[0]: row[1] for row in read_rows(ctx.dbs.hot, "SELECT key, until_ms FROM cooldown")}
    assert rows[f"endpoint:{TEMPLATE}:{egress_used.value}"] == pytest.approx(clock.now_ms() + 50_000, abs=5)
    assert len(service.local_cooldowns) == 0
    # After Retry-After the endpoint is used again.
    egress.handler = lambda e, out: answer(200, b"{}")
    clock.advance(51)
    assert (await fetch(service)).status == 200
    assert len(egress.calls) == 2


async def test_exhausted_rate_limit_during_a_hot_outage_still_pauses_the_endpoint(
    service: UpstreamService, egress: FakeEgress, ctx: Any, clock: Any, settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 7.5: a 200 that says `x-ratelimit-remaining: 0` stops calls until the reset, outage or not."""
    settings.set(rotator_enabled=0)
    hot = break_hot_writes(ctx, monkeypatch)

    def handler(e: Egress, out: Any) -> Any:
        hot["broken"] = True
        return answer(200, b"{}", {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "30"})

    egress.handler = handler
    first = await fetch(service)
    assert (first.status, first.cooldown_s) == (200, 30)
    clock.advance(1)
    second = await fetch(service)
    assert (second.status, second.reason, second.retry_after_s) == (429, ReasonCode.UPSTREAM_COOLDOWN, 29)
    assert len(egress.calls) == 1


async def test_5xx_during_a_hot_outage_answers_robloxs_status_without_a_retry(
    service: UpstreamService, egress: FakeEgress, ctx: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Findings mp-7 and mp-8: Roblox says 503 as hot.db stops taking writes. A retry could not be paced (C7), so
    none is made: the caller gets Roblox's 503 at once, never `degraded` and never after a wait for the lock."""
    hot = break_hot_writes(ctx, monkeypatch)

    def handler(e: Egress, out: Any) -> Any:
        hot["broken"] = True
        return answer(503, b"{}")

    egress.handler = handler
    result = await fetch(service)
    assert (result.status, result.reason, result.upstream_status) == (503, ReasonCode.UPSTREAM_5XX, 503)
    assert len(egress.calls) == 1
    assert any("no retry while hot.db cannot be written" in note for note in result.trace.notes)


async def test_a_retry_that_cannot_reserve_keeps_robloxs_answer(
    service: UpstreamService, egress: FakeEgress, ctx: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding mp-8: the first 503's effects were written, then hot.db stops taking writes during the backoff, so
    the retry's reservation fails: Roblox's own 503 goes back (D4), not the `degraded` row."""
    hot = break_hot_writes(ctx, monkeypatch)
    egress.handler = lambda e, out: answer(503, b"{}")
    real_sleep = service._sleep

    async def sleep_then_break(seconds: float) -> None:
        hot["broken"] = True
        await real_sleep(seconds)

    monkeypatch.setattr(service, "_sleep", sleep_then_break)
    result = await fetch(service)
    assert (result.status, result.reason, result.upstream_status) == (503, ReasonCode.UPSTREAM_5XX, 503)
    assert len(egress.calls) == 1


async def test_every_hot_write_of_a_fetch_has_a_budget(
    service: UpstreamService, egress: FakeEgress, ctx: Any, rules: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding mp-7: no hot.db write on a request path waits out SQLite's 5 s busy timeout. A 429, a 5xx with its
    retry, a CSRF challenge and a credential 429 each take every write with a budget."""
    budgets: list[int | None] = []
    real_write = ctx.dbs.hot.write

    async def write(fn: Any, **kwargs: Any) -> Any:
        budgets.append(kwargs.get("busy_timeout_ms"))
        return await real_write(fn, **kwargs)

    monkeypatch.setattr(ctx.dbs.hot, "write", write)
    answers = iter([answer(429, b"", {"retry-after": "5"}), answer(503, b""), answer(200, b"{}")])
    egress.handler = lambda e, out: next(answers)
    await fetch(service)
    await fetch(service, path="/v1/other")
    tokens = iter([answer(403, b"", {"x-csrf-token": "t1"}), answer(200, b"{}")])
    egress.handler = lambda e, out: next(tokens)
    await fetch(service, method="POST", body=b"{}", path="/v1/write")
    assert budgets
    assert None not in budgets, budgets


async def test_a_reservation_canceled_while_it_is_written_is_refunded(
    service: UpstreamService, egress: FakeEgress, ctx: Any, settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding mp-9 (plan 7.3): the request is canceled while its reservation write is still running (a started
    write always commits). The request gives back what that write granted before the cancellation goes on, so no
    bucket stays reserved for a call that was never made."""
    settings.set(endpoint_bucket_default_per_min=6, endpoint_bucket_default_burst=1)
    gate = asyncio.Event()
    started = asyncio.Event()
    real_write = ctx.dbs.hot.write
    writes = 0

    async def slow_first_write(fn: Any, **kwargs: Any) -> Any:
        nonlocal writes
        writes += 1
        if writes == 1:  # the reservation: as if another process held the lock for a while
            started.set()
            await gate.wait()
        return await real_write(fn, **kwargs)

    monkeypatch.setattr(ctx.dbs.hot, "write", slow_first_write)
    task = asyncio.ensure_future(fetch(service))
    await started.wait()
    task.cancel()
    await asyncio.sleep(0.01)
    assert not task.done()  # it waits for its own reservation before the cancellation goes on
    gate.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert egress.calls == []
    assert writes >= 2  # the reservation, then the refund
    now_ms = service.clock.now_ms()
    tats = read_rows(ctx.dbs.hot, "SELECT bucket_key, tat_ms FROM upstream_bucket")
    assert tats  # the reservation did commit
    assert [key for key, tat in tats if float(tat) > now_ms + 1000] == []


async def test_local_cooldowns_are_shared_by_the_mirror_loop_and_never_shorten_a_row(
    service: UpstreamService, ctx: Any, clock: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = clock.now_ms()
    key = f"endpoint:{TEMPLATE}:direct"
    service.local_cooldowns.remember(key, 30, "retry_after", now)
    hot = break_hot_writes(ctx, monkeypatch)
    hot["broken"] = True
    stop = asyncio.Event()
    loop = asyncio.ensure_future(service.run_mirror(stop, interval_s=0.01))
    await asyncio.sleep(0.05)
    assert len(service.local_cooldowns) == 1  # still unwritable: kept, and visible to `availability`
    assert "direct cooling down" in service.availability(request(service)).reasons
    ctx.dbs.hot.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, 'retry_after', 0, 1)",
            (key, now + 90_000),
        )
    )
    hot["broken"] = False
    for _ in range(100):
        if not len(service.local_cooldowns):
            break
        await asyncio.sleep(0.01)
    stop.set()
    await loop
    assert len(service.local_cooldowns) == 0
    assert read_rows(ctx.dbs.hot, "SELECT until_ms FROM cooldown WHERE key = ?", (key,)) == [(now + 90_000,)]


async def test_reset_state_forgets_local_cooldowns(service: UpstreamService, clock: Any) -> None:
    service.local_cooldowns.remember(f"endpoint:{TEMPLATE}:direct", 30, "retry_after", clock.now_ms())
    await service.reset_state()
    assert len(service.local_cooldowns) == 0


# --- single-flight lease hook, availability, reset ------------------------------------------------------------------


async def test_lease_hook_lost_raises_and_takes_no_tokens(service: UpstreamService, ctx: Any) -> None:
    with pytest.raises(SingleFlightLost):
        await service.fetch(
            request(service), priority=Priority.INTERACTIVE, stale_available=False, lease=lambda conn, now: False
        )
    assert read_rows(ctx.dbs.hot, "SELECT bucket_key FROM upstream_bucket") == []


async def test_lease_hook_runs_inside_the_reservation(service: UpstreamService, ctx: Any) -> None:
    seen: list[int] = []

    def hook(conn: Any, now_ms: int) -> bool:
        conn.execute(
            "INSERT INTO lease (name, holder, expires_ms, epoch) VALUES ('sf:test', 'me', ?, 1)", (now_ms + 36000,)
        )
        seen.append(now_ms)
        return True

    result = await service.fetch(request(service), priority=Priority.INTERACTIVE, stale_available=False, lease=hook)
    assert result.status == 200
    assert len(seen) == 1
    assert read_rows(ctx.dbs.hot, "SELECT holder FROM lease WHERE name = 'sf:test'") == [("me",)]


async def test_availability_reflects_cooldown(service: UpstreamService, egress: FakeEgress) -> None:
    req = request(service)
    assert service.availability(req).any_egress_available is True
    egress.handler = lambda e, out: answer(429, b"", {"retry-after": "30"})
    egress.disabled.add(Egress.ROTATOR)
    await fetch(service)
    egress.disabled.clear()
    egress.disabled.add(Egress.ROTATOR)
    view = service.availability(req)
    assert view.any_egress_available is False
    assert view.cooldown_remaining_s == pytest.approx(30, abs=0.1)
    await service.refresh_mirror()
    assert service.availability(req).any_egress_available is False


async def test_reset_clears_cooldowns_and_breakers_never_buckets(
    service: UpstreamService, egress: FakeEgress, ctx: Any
) -> None:
    egress.handler = lambda e, out: answer(429, b"", {"retry-after": "30"})
    egress.disabled.add(Egress.ROTATOR)
    await fetch(service)
    tats_before = read_rows(ctx.dbs.hot, "SELECT bucket_key, tat_ms FROM upstream_bucket ORDER BY bucket_key")
    counts = await service.reset_state()
    assert counts["cooldowns"] >= 1
    assert counts["breakers"] >= 1
    assert read_rows(ctx.dbs.hot, "SELECT key FROM cooldown") == []
    assert read_rows(ctx.dbs.hot, "SELECT key FROM breaker") == []
    assert read_rows(ctx.dbs.hot, "SELECT bucket_key, tat_ms FROM upstream_bucket ORDER BY bucket_key") == tats_before


async def test_degraded_when_hot_db_unavailable(service: UpstreamService, egress: FakeEgress) -> None:
    from roxy.storage.db import SharedStateUnavailable

    class BrokenDb:
        async def read(self, fn: Any) -> Any:
            raise SharedStateUnavailable("hot", "disk I/O error")

        async def write(self, fn: Any, **kwargs: Any) -> Any:
            raise SharedStateUnavailable("hot", "disk I/O error")

    service.hot = BrokenDb()  # type: ignore[assignment]
    result = await fetch(service)
    assert (result.status, result.reason, result.retry_after_s) == (503, ReasonCode.DEGRADED, 10)
    assert result.body == messages.BUSY_MESSAGE.encode()
    assert egress.calls == []


async def test_unexpected_exception_is_internal_error(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: ZeroDivisionError("bug")
    result = await fetch(service)
    assert (result.status, result.reason, result.retry_after_s) == (500, ReasonCode.INTERNAL_ERROR, 5)
    assert result.body == b"Internal Server Error"


async def test_trace_has_v1_fields(service: UpstreamService, egress: FakeEgress) -> None:
    answers = iter([UpstreamTimeout("slow"), answer(200)])
    egress.handler = lambda e, out: next(answers)
    result = await fetch(service)
    data = result.trace.to_dict()
    assert data["Attempts"] == 2
    assert data["Methods"] == ["direct", "direct"]
    assert data["Method"] == "direct"
    assert data["Outcome"] == "upstream_ok"
    assert data["UpstreamStatus"] == 200
    assert data["UpstreamError"] == ""  # the earlier timeout does not leak into the final call (v1 bug B32)
    assert data["Retries"] == 0
    assert data["EgressIdentity"] == "direct"
