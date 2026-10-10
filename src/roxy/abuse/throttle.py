"""The per-IP throttle: an atomic GCRA (or v1 fixed window) limit plus the escalating strike ladder.

What this is
    `evaluate_per_ip` decides one request for one client key inside the abuse transaction and says which rows
    change; `peek_per_ip` gives the `Roxy-Requests-Left` / `Roxy-Throttle-Reset` / `Roxy-Throttled` trio without
    counting. The ladder helpers (`Rung`, `ladder_from`, `rung_for`, `effective_strikes`, `decays_in`) implement
    plan 10.4, and `strike_board`, `forgive` and `throttle_watch` serve the Protection page (rows 41 and 118).
    For plan C7, `refuse_unshared` and `peek_unshared` answer a worker whose degraded share of the limit is 0, and
    `merge_strike_row` adds a strike or penalty earned in memory to hot.db once it can be written again.

Why it exists
    v1 checked "is this IP throttled?" at the top of the request and counted the request at the bottom, in two
    separate steps, so the request that crossed the limit was still served (11 per window instead of 10) and
    concurrent requests raced past the check (v1 bugs B8 and B11). Here the check and the count are one decision
    in one `BEGIN IMMEDIATE` transaction: the request that would cross the limit is the one refused (plan 10.2).

How it works
    - Limit: `allowed_requests_per_minute` (L) per `throttle_reset_duration` (W) seconds, keyed by `limit_key` (the
      IP, IPv6 grouped by `ipv6_limit_prefix`). Mode `gcra` (default) or `fixed` (v1).
    - A refusal by the limit is a strike when escalation is on: strikes = decayed strikes + 1, and the client is
      penalized for `W x rung multiplier` seconds (rung 1 waits W, rung 2 2W, ...; past the last rung the last one
      repeats; v1 `punish`). While penalized every request is refused. With `throttle_strike_on_retry`, retrying
      while penalized adds one more strike at most once per W seconds (it raises the NEXT penalty).
    - Decay (v1, kept): one strike is forgiven per full `throttle_strike_decay_seconds` since the LAST strike;
      0 means never. `decays_in` shows the real time to the next drop (v1 bug B3 showed 0 after the first drop).
    - A rung with action `ban` asks the pipeline to create a temporary IP ban for `ban_minutes` (plan 10.4).
    - Escalation off (v2 decision on v1 bug B2): no strikes are added; `fixed` mode still penalizes for W
      (the "plain duration"); `gcra` mode just refuses until the next request would fit.
    - Strike rows live in hot.db `strikes` (seconds); the limiter row in `limiter` (milliseconds). In fixed mode a
      penalty moves the window end to the penalty end, so a fresh window opens when the penalty is over (v1).

What to read next
    `roxy/abuse/limiter.py` (the GCRA and fixed window math), then `roxy/abuse/pipeline.py` (where this runs).
"""

from __future__ import annotations

import math
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from roxy.abuse.limiter import SAVE_CHUNK, DegradedEntry, LimiterRow, RateDecision, fixed, fixed_peek, gcra, gcra_peek
from roxy.storage.db import Database

# --- the ladder ------------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rung:
    """One ladder rung (1-based `index`; index 0 is "no rung": an empty ladder or no strikes)."""

    index: int
    multiplier: float
    message: str
    action: str = "throttle"
    ban_minutes: int | None = None


NO_RUNG = Rung(0, 1.0, "")


def ladder_from(rows: Iterable[Any]) -> tuple[Rung, ...]:
    """The ladder from `throttle_tiers` rows (anything with position, multiplier, message, action, ban_minutes)."""
    ordered = sorted(rows, key=lambda row: int(row.position))
    return tuple(
        Rung(
            index=i,
            multiplier=float(row.multiplier or 1.0),
            message=str(row.message or ""),
            action=str(getattr(row, "action", "throttle") or "throttle"),
            ban_minutes=getattr(row, "ban_minutes", None),
        )
        for i, row in enumerate(ordered, start=1)
    )


def rung_for(ladder: Sequence[Rung], strikes: int) -> Rung:
    """v1 `throttle_tier_for`: the rung for `strikes`; past the end the last rung repeats; none for 0 strikes."""
    if not ladder or strikes < 1:
        return NO_RUNG
    return ladder[min(int(strikes), len(ladder)) - 1]


def effective_strikes(strikes: int, last_strike_at: float, now_s: float, decay_s: float) -> int:
    """v1 `effective_strikes`: strikes minus one per full `decay_s` since the last strike (0 decay: never)."""
    if strikes <= 0:
        return 0
    if not decay_s or not last_strike_at:
        return int(strikes)
    return max(0, int(strikes) - int(max(0.0, now_s - last_strike_at) // decay_s))


def decays_in(strikes: int, last_strike_at: float, now_s: float, decay_s: float) -> int:
    """Seconds until the next strike drops off (0 when nothing decays). Fixes v1 bug B3."""
    if not decay_s or not last_strike_at or effective_strikes(strikes, last_strike_at, now_s, decay_s) <= 0:
        return 0
    elapsed = max(0.0, now_s - last_strike_at)
    return math.ceil(decay_s - (elapsed % decay_s))


# --- strike rows -----------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class StrikeRow:
    """One hot.db `strikes` row (times in seconds). `key` is the client's limit key."""

    key: str
    strikes: int = 0
    last_strike_at: int = 0
    tier: int = 0
    throttled_until: int = 0
    exists: bool = False


def load_strike_rows(conn: sqlite3.Connection, keys: Iterable[str]) -> dict[str, StrikeRow]:
    """Strike rows for `keys` (missing ones with `exists=False`)."""
    wanted = list(dict.fromkeys(keys))
    rows = {key: StrikeRow(key) for key in wanted}
    if not wanted:
        return rows
    marks = ",".join("?" for _ in wanted)
    sql = f"SELECT ip, strikes, last_strike_at, tier, throttled_until FROM strikes WHERE ip IN ({marks})"  # noqa: S608  # only "?" placeholders are interpolated
    for raw in conn.execute(sql, wanted).fetchall():
        rows[str(raw[0])] = StrikeRow(str(raw[0]), int(raw[1]), int(raw[2]), int(raw[3]), int(raw[4]), True)
    return rows


def save_strike_rows(conn: sqlite3.Connection, rows: Iterable[StrikeRow]) -> None:
    """Upsert strike rows inside the caller's transaction: one multi-row statement per `limiter.SAVE_CHUNK` rows (the
    reason is `limiter.save_rows`'s; rows apply in order)."""
    params = [(r.key, int(r.strikes), int(r.last_strike_at), int(r.tier), int(r.throttled_until)) for r in rows]
    for start in range(0, len(params), SAVE_CHUNK):
        chunk = params[start : start + SAVE_CHUNK]
        values = ",".join("(?, ?, ?, ?, ?)" for _ in chunk)
        conn.execute(
            f"INSERT INTO strikes (ip, strikes, last_strike_at, tier, throttled_until) VALUES {values} "  # noqa: S608  # only "?" placeholders are interpolated
            "ON CONFLICT (ip) DO UPDATE SET strikes = excluded.strikes, last_strike_at = excluded.last_strike_at, "
            "tier = excluded.tier, throttled_until = excluded.throttled_until",
            [value for row in chunk for value in row],
        )


def add_strike_in(conn: sqlite3.Connection, key: str, now_s: int, decay_s: float) -> StrikeRow:
    """Add one strike to `key` (a spam detector's `strike` action), keeping any penalty in progress."""
    current = load_strike_rows(conn, [key])[key]
    strikes = effective_strikes(current.strikes, current.last_strike_at, now_s, decay_s) + 1
    row = replace(current, strikes=strikes, last_strike_at=now_s, exists=True)
    save_strike_rows(conn, [row])
    return row


# --- the decision --------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PerIpPolicy:
    """The per-IP settings for one request (read once from the settings snapshot)."""

    key: str
    mode: str  # "gcra" or "fixed"
    limit: int
    window_s: int
    escalation: bool
    decay_s: int
    ladder: tuple[Rung, ...]
    strike_on_retry: bool


@dataclass(slots=True)
class PerIpResult:
    """What the per-IP throttle decided, plus the rows to write (see `evaluate_per_ip`)."""

    admitted: bool
    remaining: int
    reset_s: int
    retry_after_s: int
    throttled: bool
    strikes: int
    rung: Rung
    penalty_s: int = 0
    new_strike: bool = False
    punished: bool = False  # refused by the limit itself: the client has just become throttled (v1 `punish`)
    ban_minutes: int | None = None
    limiter_row: LimiterRow | None = None  # write when the request is admitted (or for a fixed-mode penalty)
    strike_row: StrikeRow | None = None  # write whenever set (refusals that change strikes or penalties)


def _limit_decision(policy: PerIpPolicy, row: LimiterRow, now_ms: int) -> RateDecision:
    if policy.mode == "fixed":
        return fixed(row, policy.limit, policy.window_s, now_ms)
    return gcra(row, policy.limit, policy.window_s, now_ms)


def evaluate_per_ip(policy: PerIpPolicy, row: LimiterRow, srow: StrikeRow, now_ms: int) -> PerIpResult:
    """Admit or refuse one request (module docstring). Pure: the caller writes the returned rows."""
    now_s = now_ms // 1000
    eff = effective_strikes(srow.strikes, srow.last_strike_at, now_s, policy.decay_s)
    penalty_until_ms = srow.throttled_until * 1000
    if srow.exists and penalty_until_ms > now_ms:
        # Still penalized: refuse without counting. A retry may add one strike per window (plan 10.4).
        strikes = eff
        strike_row: StrikeRow | None = None
        if policy.strike_on_retry and policy.escalation and now_s - srow.last_strike_at >= policy.window_s:
            strikes = eff + 1
            strike_row = replace(
                srow, strikes=strikes, last_strike_at=now_s, tier=rung_for(policy.ladder, strikes).index
            )
        wait_ms = penalty_until_ms - now_ms
        reset = max(1, int(wait_ms // 1000))
        return PerIpResult(
            admitted=False,
            remaining=0,
            reset_s=reset,
            retry_after_s=max(1, math.ceil(wait_ms / 1000)),
            throttled=True,
            strikes=strikes,
            rung=rung_for(policy.ladder, max(1, strikes)),
            penalty_s=math.ceil(wait_ms / 1000),
            new_strike=strike_row is not None,
            strike_row=strike_row,
        )
    decision = _limit_decision(policy, row, now_ms)
    if decision.admitted:
        return PerIpResult(
            admitted=True,
            remaining=decision.remaining,
            reset_s=decision.reset_s,
            retry_after_s=0,
            throttled=False,
            strikes=eff,
            rung=rung_for(policy.ladder, max(1, eff)),
            limiter_row=decision.row,
        )
    # Refused by the limit itself: punish (v1 `punish`, now on the request that crossed the limit).
    window_ms = policy.window_s * 1000
    ban_minutes: int | None = None
    if policy.escalation:
        strikes = eff + 1
        rung = rung_for(policy.ladder, strikes)
        multiplier = rung.multiplier if rung.multiplier > 0 else 1.0
        penalty_ms = int(window_ms * multiplier)
        if rung.action == "ban" and rung.ban_minutes:
            ban_minutes = int(rung.ban_minutes)
        new_srow = replace(
            srow,
            strikes=strikes,
            last_strike_at=now_s,
            tier=rung.index,
            throttled_until=math.ceil((now_ms + penalty_ms) / 1000),
            exists=True,
        )
    else:
        strikes = eff
        rung = rung_for(policy.ladder, max(1, eff))
        penalty_ms = window_ms if policy.mode == "fixed" else 0
        new_srow = replace(srow, throttled_until=math.ceil((now_ms + penalty_ms) / 1000), exists=True)
    limiter_row: LimiterRow | None = None
    if policy.mode == "fixed" and penalty_ms > 0:
        # The window now ends with the penalty, so a fresh allowance starts when the penalty is over (v1). The
        # count stays at least the limit ("full"); a count already above it (a degraded worker's share, C7) is
        # kept, so merging that row into hot.db later still adds everything it counted.
        end = now_ms + penalty_ms
        full = max(row.count, policy.limit)
        limiter_row = replace(row, window_start=end - window_ms, count=full, tat_ms=end, exists=True)
    penalty_s = math.ceil(penalty_ms / 1000)
    return PerIpResult(
        admitted=False,
        remaining=0,
        reset_s=max(decision.reset_s, int(penalty_ms // 1000)),
        retry_after_s=max(decision.retry_after_s, penalty_s, 1),
        throttled=True,
        strikes=strikes,
        rung=rung if rung.index else rung_for(policy.ladder, max(1, strikes)),
        penalty_s=penalty_s,
        new_strike=policy.escalation,
        punished=True,
        ban_minutes=ban_minutes,
        limiter_row=limiter_row,
        strike_row=new_srow,
    )


def peek_per_ip(policy: PerIpPolicy, row: LimiterRow, srow: StrikeRow, now_ms: int) -> tuple[int, int, bool]:
    """`(requests_left, reset_s, throttled)` without counting (v1 `headers_snapshot`)."""
    penalty_until_ms = srow.throttled_until * 1000
    if srow.exists and penalty_until_ms > now_ms:
        return 0, int((penalty_until_ms - now_ms) // 1000), True
    if policy.mode == "fixed":
        remaining, reset = fixed_peek(row, policy.limit, now_ms)
    else:
        remaining, reset = gcra_peek(row, policy.limit, policy.window_s, now_ms)
    return remaining, reset, False


# --- degraded mode (plan C7) -----------------------------------------------------------------------------------------


def unshared_wait_s(policy: PerIpPolicy) -> int:
    """The wait a client is told when this worker's degraded share of the per-IP limit is 0: the configured pace."""
    return max(1, math.ceil(policy.window_s / max(1, policy.limit)))


def refuse_unshared(policy: PerIpPolicy, row: LimiterRow, srow: StrikeRow, now_ms: int) -> PerIpResult:
    """C7 when this worker's share of the limit is 0 (`limiter.degraded_limit`): refuse without counting.

    No strike and no penalty: the refusal comes from Roxy's own outage, not from anything the client did. A client
    that is already penalized gets exactly what `evaluate_per_ip` answers a penalized client.
    """
    if srow.exists and srow.throttled_until * 1000 > now_ms:
        return evaluate_per_ip(policy, row, srow, now_ms)
    strikes = effective_strikes(srow.strikes, srow.last_strike_at, now_ms // 1000, policy.decay_s)
    wait = unshared_wait_s(policy)
    return PerIpResult(
        admitted=False,
        remaining=0,
        reset_s=wait,
        retry_after_s=wait,
        throttled=True,
        strikes=strikes,
        rung=rung_for(policy.ladder, max(1, strikes)),
    )


def peek_unshared(policy: PerIpPolicy, srow: StrikeRow, now_ms: int) -> tuple[int, int, bool]:
    """`peek_per_ip` for a worker whose degraded share is 0: nothing left here (unless a penalty says more)."""
    penalty_until_ms = srow.throttled_until * 1000
    if srow.exists and penalty_until_ms > now_ms:
        return 0, int((penalty_until_ms - now_ms) // 1000), True
    return 0, unshared_wait_s(policy), True


def merge_strike_row(shared: StrikeRow, entry: DegradedEntry[StrikeRow], now_s: int, decay_s: float) -> StrikeRow:
    """The shared strike row once a worker's degraded strike row is added to it (C7 recovery).

    The larger decayed strike count, the later last strike, the higher rung and the later penalty end: a strike or
    penalty earned while hot.db could not be written still counts once it can, and nothing earned elsewhere is lost.
    """
    memory = entry.row
    if not memory.exists:
        return shared
    if not shared.exists:
        return memory
    strikes = max(
        effective_strikes(shared.strikes, shared.last_strike_at, now_s, decay_s),
        effective_strikes(memory.strikes, memory.last_strike_at, now_s, decay_s),
    )
    return replace(
        shared,
        strikes=strikes,
        last_strike_at=max(shared.last_strike_at, memory.last_strike_at),
        tier=max(shared.tier, memory.tier),
        throttled_until=max(shared.throttled_until, memory.throttled_until),
        exists=True,
    )


# --- admin views (rows 41 and 118) -----------------------------------------------------------------------------------


def _effective_sql(decay_s: int) -> tuple[str, tuple[Any, ...]]:
    """SQL for the decayed strike count (v1 `effective_strikes`) and its parameters."""
    if decay_s <= 0:
        return "strikes", ()
    return (
        "CASE WHEN last_strike_at = 0 THEN strikes "
        "ELSE max(0, strikes - CAST(max(0, :now - last_strike_at) / :decay AS INTEGER)) END",
        (),
    )


async def strike_board(
    db: Database, *, now_s: int, decay_s: int, ladder: Sequence[Rung], limit: int = 25, offset: int = 0
) -> dict[str, Any]:
    """Clients with strikes left after decay, most strikes first (v1 `strike_board`, now paged server side)."""
    eff_sql, _ = _effective_sql(decay_s)
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        params = {"now": now_s, "decay": max(1, decay_s), "limit": limit, "offset": offset}
        total = conn.execute(f"SELECT count(*) FROM strikes WHERE ({eff_sql}) > 0", params).fetchone()[0]  # noqa: S608  # eff_sql is a constant expression
        rows = conn.execute(
            f"SELECT ip, strikes, last_strike_at, tier, throttled_until, ({eff_sql}) AS eff FROM strikes "  # noqa: S608  # eff_sql is a constant expression
            "WHERE eff > 0 ORDER BY eff DESC, last_strike_at DESC LIMIT :limit OFFSET :offset",
            params,
        ).fetchall()
        return {"total": int(total), "rows": [tuple(r) for r in rows]}

    data = await db.read(read)
    out = []
    for ip, raw_strikes, last, _tier, until, eff in data["rows"]:
        rung = rung_for(ladder, int(eff))
        out.append(
            {
                "ip": ip,
                "strikes": int(eff),
                "tier": rung.index,
                "multiplier": rung.multiplier,
                "message": rung.message,
                "throttled": int(until) > now_s,
                "reset_in": max(0, int(until) - now_s),
                "last_strike_at": int(last),
                "decays_in": decays_in(int(raw_strikes), int(last), now_s, decay_s),
            }
        )
    return {"total": data["total"], "rows": out}


async def forgive(db: Database, ip: str | None = None) -> int:
    """v1 `clear_strikes`: zero the strikes of one client (or all). A penalty in progress is NOT lifted (v1 B19)."""

    def write(conn: sqlite3.Connection) -> int:
        if ip:
            cur = conn.execute(
                "UPDATE strikes SET strikes = 0, last_strike_at = 0, tier = 0 WHERE strikes > 0 AND ip = ?", (ip,)
            )
        else:
            cur = conn.execute("UPDATE strikes SET strikes = 0, last_strike_at = 0, tier = 0 WHERE strikes > 0")
        return int(cur.rowcount)

    return await db.write(write)


async def throttle_watch(db: Database, *, now_s: int, limit: int = 25, offset: int = 0) -> dict[str, Any]:
    """Row 118: who is being throttled right now, longest remaining penalty first, with time left."""
    limit = max(1, min(int(limit), 500))

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        total = conn.execute("SELECT count(*) FROM strikes WHERE throttled_until > ?", (now_s,)).fetchone()[0]
        rows = conn.execute(
            "SELECT ip, strikes, tier, throttled_until FROM strikes WHERE throttled_until > ? "
            "ORDER BY throttled_until DESC LIMIT ? OFFSET ?",
            (now_s, limit, max(0, int(offset))),
        ).fetchall()
        return {
            "total": int(total),
            "rows": [
                {"ip": r[0], "strikes": int(r[1]), "tier": int(r[2]), "time_left_s": int(r[3]) - now_s} for r in rows
            ],
        }

    return await db.read(read)


__all__ = [
    "NO_RUNG",
    "PerIpPolicy",
    "PerIpResult",
    "Rung",
    "StrikeRow",
    "add_strike_in",
    "decays_in",
    "effective_strikes",
    "evaluate_per_ip",
    "forgive",
    "ladder_from",
    "load_strike_rows",
    "merge_strike_row",
    "peek_per_ip",
    "peek_unshared",
    "refuse_unshared",
    "rung_for",
    "save_strike_rows",
    "strike_board",
    "throttle_watch",
    "unshared_wait_s",
]
