"""The per-IP throttle: atomic admit, the strike ladder, decay, strike on retry (plan 10.2, 10.4; rows 39 to 41)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from roxy.abuse.limiter import LimiterRow
from roxy.abuse.throttle import (
    NO_RUNG,
    PerIpPolicy,
    PerIpResult,
    Rung,
    StrikeRow,
    add_strike_in,
    decays_in,
    effective_strikes,
    evaluate_per_ip,
    forgive,
    load_strike_rows,
    peek_per_ip,
    rung_for,
    save_strike_rows,
    strike_board,
    throttle_watch,
)
from roxy.config.defaults import THROTTLE_TIERS

LADDER = tuple(Rung(i, t.multiplier, t.message) for i, t in enumerate(THROTTLE_TIERS, start=1))
T0 = 1_760_000_000_000


def policy(**changes: Any) -> PerIpPolicy:
    base = PerIpPolicy(
        key="203.0.113.7",
        mode="gcra",
        limit=10,
        window_s=50,
        escalation=True,
        decay_s=1800,
        ladder=LADDER,
        strike_on_retry=True,
    )
    return replace(base, **changes)


class Client:
    """Applies `evaluate_per_ip` results the way the pipeline commits them."""

    def __init__(self, pol: PerIpPolicy) -> None:
        self.policy = pol
        self.row = LimiterRow(pol.key)
        self.strikes = StrikeRow(pol.key)

    def send(self, now_ms: int) -> PerIpResult:
        result = evaluate_per_ip(self.policy, self.row, self.strikes, now_ms)
        if result.limiter_row is not None:
            self.row = result.limiter_row
        if result.strike_row is not None:
            self.strikes = result.strike_row
        return result


def test_rung_lookup_repeats_the_last_rung() -> None:
    assert rung_for(LADDER, 0) is NO_RUNG
    assert rung_for((), 3) is NO_RUNG
    assert rung_for(LADDER, 1).message == "Too many requests; please slow down."  # C5 replacement
    assert rung_for(LADDER, 9).index == 4


def test_effective_strikes_decay_from_the_last_strike() -> None:
    assert effective_strikes(3, 1000, 1000 + 1799, 1800) == 3
    assert effective_strikes(3, 1000, 1000 + 1800, 1800) == 2
    assert effective_strikes(3, 1000, 1000 + 3 * 1800, 1800) == 0
    assert effective_strikes(3, 1000, 10**9, 0) == 3  # decay 0: never
    assert effective_strikes(3, 0, 10**9, 1800) == 3  # v1: no last strike time, no decay


def test_decays_in_counts_to_the_next_drop_not_zero() -> None:
    """v1 bug B3: after the first drop v1 showed 0 while strikes remained."""
    assert decays_in(3, 1000, 1000 + 2000, 1800) == 1600  # 2 strikes left, the next drops at 3600
    assert decays_in(3, 1000, 1000 + 100, 1800) == 1700
    assert decays_in(1, 1000, 1000 + 1800, 1800) == 0  # nothing left to decay
    assert decays_in(2, 1000, 1500, 0) == 0


def test_the_crossing_request_is_refused_atomic_admit() -> None:
    """Plan 10.2 fixes v1's allowed + 1 leak: exactly L requests are served."""
    client = Client(policy(mode="fixed"))
    results = [client.send(T0).admitted for _ in range(11)]
    assert results == [True] * 10 + [False]


def test_ladder_penalties_double_per_rung_fixed_mode() -> None:
    client = Client(policy(mode="fixed"))
    now = T0
    penalties = []
    for _ in range(5):
        while client.send(now).admitted:
            pass
        result = client.send(now)  # inside the penalty: refused without a new strike (retry strikes need W)
        penalties.append((client.strikes.strikes, client.strikes.throttled_until - now // 1000))
        now = client.strikes.throttled_until * 1000 + 1000
        assert not result.admitted
    assert [p[1] for p in penalties] == [50, 100, 200, 400, 400]  # rung 1 waits W, 2 2W, 3 4W, then 8W repeats
    assert [p[0] for p in penalties] == [1, 2, 3, 4, 5]


def test_refusal_message_and_headers_use_the_new_strike() -> None:
    client = Client(policy())
    for _ in range(10):
        assert client.send(T0).admitted
    refused = client.send(T0)
    assert not refused.admitted
    assert refused.strikes == 1
    assert refused.rung.index == 1
    assert refused.retry_after_s == 50  # the rung penalty (50 s) is longer than the GCRA wait (5 s)
    assert refused.reset_s == 50
    assert refused.penalty_s == 50
    assert refused.throttled
    assert peek_per_ip(client.policy, client.row, client.strikes, T0 + 10_000) == (0, 40, True)


def test_strike_on_retry_adds_at_most_one_strike_per_window() -> None:
    client = Client(policy(mode="fixed"))
    for _ in range(11):
        client.send(T0)
    assert client.strikes.strikes == 1
    # Retrying inside the penalty: no extra strike until W seconds after the last strike.
    client.send(T0 + 10_000)
    assert client.strikes.strikes == 1
    client.send(T0 + 49_000)
    assert client.strikes.strikes == 1
    # A long penalty (raise the multiplier) so the client is still penalized after W seconds.
    client.strikes = replace(client.strikes, throttled_until=(T0 + 500_000) // 1000)
    result = client.send(T0 + 50_000)
    assert result.new_strike
    assert client.strikes.strikes == 2
    client.send(T0 + 60_000)
    assert client.strikes.strikes == 2  # at most one per window


def test_strike_on_retry_can_be_switched_off() -> None:
    client = Client(policy(mode="fixed", strike_on_retry=False))
    for _ in range(11):
        client.send(T0)
    client.strikes = replace(client.strikes, throttled_until=(T0 + 500_000) // 1000)
    client.send(T0 + 100_000)
    assert client.strikes.strikes == 1


def test_strikes_decay_between_offenses() -> None:
    client = Client(policy(mode="fixed"))
    for _ in range(11):
        client.send(T0)
    later = T0 + 3600_000 + 60_000  # two decay periods after the strike, penalty long over
    while client.send(later).admitted:
        pass
    assert client.strikes.strikes == 1  # decayed to 0, then one new strike: rung 1 again


def test_escalation_off_adds_no_strikes() -> None:
    fixed_client = Client(policy(mode="fixed", escalation=False))
    for _ in range(11):
        fixed_client.send(T0)
    assert fixed_client.strikes.strikes == 0
    assert fixed_client.strikes.throttled_until == T0 // 1000 + 50  # fixed mode keeps the plain duration
    gcra_client = Client(policy(escalation=False))
    for _ in range(10):
        gcra_client.send(T0)
    refused = gcra_client.send(T0)
    assert not refused.admitted
    assert refused.retry_after_s == 5  # gcra: just the pacing wait, no penalty
    assert gcra_client.send(T0 + 5000).admitted


def test_ban_rung_asks_for_a_ban() -> None:
    ladder = (Rung(1, 1.0, "slow down"), Rung(2, 2.0, "", action="ban", ban_minutes=30))
    client = Client(policy(mode="fixed", ladder=ladder))
    for _ in range(11):
        client.send(T0)
    now = client.strikes.throttled_until * 1000 + 1
    result = None
    while True:
        result = client.send(now)
        if not result.admitted:
            break
    assert result.ban_minutes == 30
    assert result.rung.index == 2


def test_empty_ladder_still_counts_strikes_and_uses_plain_duration() -> None:
    client = Client(policy(mode="fixed", ladder=()))
    for _ in range(10):
        client.send(T0)
    refused = client.send(T0)
    assert refused.strikes == 1
    assert refused.rung is NO_RUNG
    assert refused.penalty_s == 50


async def test_strike_board_forgive_and_watch(dbs: Any) -> None:
    now_s = T0 // 1000
    rows = [
        StrikeRow("198.51.100.1", 3, now_s - 100, 3, now_s + 150, True),
        StrikeRow("198.51.100.2", 1, now_s - 4000, 1, 0, True),  # decayed to 0
        StrikeRow("198.51.100.3", 2, now_s - 10, 2, 0, True),
    ]
    await dbs.hot.write(lambda conn: save_strike_rows(conn, rows))
    board = await strike_board(dbs.hot, now_s=now_s, decay_s=1800, ladder=LADDER)
    assert board["total"] == 2
    assert [r["ip"] for r in board["rows"]] == ["198.51.100.1", "198.51.100.3"]
    first = board["rows"][0]
    assert first["strikes"] == 3
    assert first["throttled"] is True
    assert first["reset_in"] == 150
    assert first["decays_in"] == 1700
    watch = await throttle_watch(dbs.hot, now_s=now_s)
    assert watch["total"] == 1
    assert watch["rows"][0] == {"ip": "198.51.100.1", "strikes": 3, "tier": 3, "time_left_s": 150}
    # Forgive counts raw strikes (v1), and does not lift the penalty in progress (v1 B19).
    assert await forgive(dbs.hot, "198.51.100.1") == 1
    assert await forgive(dbs.hot) == 2
    stored = await dbs.hot.read(lambda conn: load_strike_rows(conn, ["198.51.100.1"]))
    assert stored["198.51.100.1"].strikes == 0
    assert stored["198.51.100.1"].throttled_until == now_s + 150


async def test_add_strike_keeps_the_penalty(dbs: Any) -> None:
    now_s = T0 // 1000
    await dbs.hot.write(lambda conn: save_strike_rows(conn, [StrikeRow("k", 1, now_s, 1, now_s + 40, True)]))
    row = await dbs.hot.write(lambda conn: add_strike_in(conn, "k", now_s + 1, 1800))
    assert row.strikes == 2
    assert row.throttled_until == now_s + 40
