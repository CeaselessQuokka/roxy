"""No cascade onto the credential, ever (plan 2.5 R3, 7.9, C1/D1): a property test over states and outcomes.

Hypothesis draws a sequence of upstream answers (429, 5xx, timeouts, connect errors, egress refusals, successes),
the egress switches, the credential's state, and the retry settings, then runs fetches through the real service
over a real hot.db. Whatever happens, a request that is not allowlisted never reaches the credential path, and an
allowlisted one never reaches an anonymous path unless its row says `identical_anonymous`.
"""

from __future__ import annotations

import asyncio
import itertools
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from upstream_fakes import (
    EgressDisabled,
    FakeEgress,
    FakeRules,
    FakeSettings,
    SteppingClock,
    UpstreamConnectError,
    UpstreamTimeout,
    answer,
    make_ctx,
    make_service,
    request,
)

from roxy.core.reasons import Egress
from roxy.upstream.queue import Priority

OUTCOMES = st.sampled_from(["200", "201", "404", "429", "429ra", "500", "503", "timeout", "connect", "disabled"])


def respond(kind: str) -> Any:
    return {
        "200": lambda: answer(200),
        "201": lambda: answer(201),
        "404": lambda: answer(404),
        "429": lambda: answer(429, b""),
        "429ra": lambda: answer(429, b"", {"retry-after": "3"}),
        "500": lambda: answer(500),
        "503": lambda: answer(503),
        "timeout": lambda: UpstreamTimeout("slow"),
        "connect": lambda: UpstreamConnectError("refused"),
        "disabled": lambda: EgressDisabled("off"),
    }[kind]()


def reset(dbs: Any) -> None:
    def clear(conn: Any) -> None:
        for table in ("cooldown", "breaker", "upstream_bucket", "lease", "csrf_cache"):
            conn.execute(f"DELETE FROM {table}")

    dbs.hot.write_sync(clear)


@given(
    outcomes=st.lists(OUTCOMES, min_size=1, max_size=12),
    allowlisted=st.booleans(),
    identical=st.booleans(),
    method=st.sampled_from(["GET", "HEAD", "POST", "DELETE"]),
    fallback=st.booleans(),
    attempts=st.integers(1, 5),
    rotator_on=st.booleans(),
    direct_on=st.booleans(),
    credential_state=st.sampled_from(["active", "rejected", "unknown", "cooling"]),
    weights=st.tuples(st.integers(0, 100), st.integers(0, 100)),
    requests=st.integers(1, 4),
)
@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_no_cascade_to_the_credential_ever(
    dbs: Any,
    outcomes: list[str],
    allowlisted: bool,
    identical: bool,
    method: str,
    fallback: bool,
    attempts: int,
    rotator_on: bool,
    direct_on: bool,
    credential_state: str,
    weights: tuple[int, int],
    requests: int,
) -> None:
    reset(dbs)
    clock = SteppingClock()
    answers = itertools.cycle(outcomes)
    egress = FakeEgress(lambda e, out: respond(next(answers)))
    if credential_state == "cooling":
        egress.credential.cooldown = 30
    else:
        egress.credential.status_value = credential_state
    rules = FakeRules()
    if allowlisted:
        rules.allow_credential("games.roblox.com/v1/games", identical_anonymous=identical, methods="GET,HEAD")
    knobs = FakeSettings(
        fallback_on_429=int(fallback),
        upstream_max_attempts=attempts,
        rotator_enabled=int(rotator_on),
        direct_enabled=int(direct_on),
        direct_weight=weights[0],
        rotator_weight=weights[1],
    )
    service = make_service(make_ctx(dbs, clock, egress, settings=knobs, rules=rules))

    async def run() -> None:
        for _ in range(requests):
            body = b"{}" if method in ("POST", "DELETE") else b""
            await service.fetch(
                request(service, method=method, body=body), priority=Priority.INTERACTIVE, stale_available=False
            )
            clock.advance(1)

    asyncio.run(run())
    used = set(egress.egresses())
    may_use_credential = allowlisted and method in ("GET", "HEAD")
    if not may_use_credential:
        assert Egress.CREDENTIAL not in used
    elif not identical:
        assert used <= {Egress.CREDENTIAL}  # an allowlisted endpoint never falls back to an anonymous path
    if Egress.CREDENTIAL in used:
        for egress_used, out in egress.calls:
            if egress_used is Egress.CREDENTIAL:
                assert out.method in ("GET", "HEAD")
