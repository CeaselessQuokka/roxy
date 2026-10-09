"""The abuse pipeline: runs every check in order and decides `Allow` or `Refuse` with ONE hot.db write transaction.

What this is
    `AbusePipeline.evaluate(req) -> Allow | Refuse` (DESIGN.md 7 and 11.5), the object stored at `ctx.abuse`, plus
    `install(ctx, stack)`, the lifespan hook that builds it, loads the admin switches and starts its background loops
    (spam flush every second, switch refresh every second, ban hit flush every 5 s, bot scores every minute). It
    also owns the tarpit (`pipeline.tarpit`), the spam detectors, the bot tracker and the per-worker statistics.

Why it exists
    v1 ran its checks inline in one long handler and touched its throttle file several times per request (and
    separately from the check, so the crossing request leaked through). Plan 6.3 requires every limiter of a request
    (flood, throttle-all, per-IP and strikes, place, User-Agent rule, endpoint rule) to be evaluated and updated in a
    single `BEGIN IMMEDIATE` transaction, committing only what the outcome requires, and plan C7 requires sane limits
    when that transaction cannot run. v1 also refused a throttled caller before it ran any regex; an admin regex can
    cost up to the request's regex budget (plan 9.9), so a flood of refused requests must not pay it each time.

How it works
    0. Bypass is resolved first (`req.bypass`), before any check, so the router knows a caller is on the bypass list
       whichever check refuses it (bans and the deny list come before the bypass marker in the order, and a bypass
       caller is never held by the tarpit, plan 10.6).
    1. Prepare: walk the checks in position order (`checks/__init__.py`). Each returns nothing, a refusal that needs
       no shared state (pause, ban, probe, block, ...), or a `LimitSpec`. Bypass-skipped checks are not prepared for
       a bypass caller. Preparing stops at the first refusal: nothing after it can matter.
    2. Cheap limiters first. While the rules contain admin regexes (User-Agent rules, header filters, endpoint blocks
       or rate rules of type regex), preparing stops before the first check that matches patterns (`uses_patterns`).
       One READ of the cheap limiters' rows predicts their verdict: if they refuse (flood, throttle-all, per-IP,
       place), the write transaction runs for them alone and no pattern is ever matched; if they admit, the pattern
       checks are prepared and the single write transaction below runs as usual. A prediction that the write then
       contradicts (another worker moved a row in between) costs at most one extra transaction: the provisional one
       commits nothing when everything admitted. Without regex rules there is no read and no split.
    3. Transaction: one `hot.write` loads every needed `limiter` row and the client's `strikes` row, evaluates the
       limiters in order, and stops at the first refusal. Commit rule: the flood counter always (it counts every
       request); the refusing limiter's own consequences (a strike, a penalty); and the admitted limiters' counts only
       when nothing refused. A request refused later therefore spends no rate budget (plan 6.3; v1 spent UA and
       throttle-all budgets on requests it then refused). The per-IP header trio comes from the same rows. The write
       has a 500 ms budget counted from when it was queued (`storage/db.py`), so a locked hot.db degrades promptly.
    4. Verdict: ask each prepared check, in order, for its refusal; the first one wins (disguised refusals are
       rendered with the client's real strikes, `checks/base.py redisguise`). Otherwise `Allow` with the trio. A
       throttle refusal that may be answered from a fresh cache entry (`cache_serve_throttled`) keeps that permission
       only when no later check would refuse the request (a header filter, auth smuggling, a block, any static
       refusal): content is never served to a filtered request. The answer stays the throttle refusal (v1's order).
    5. Afterwards (memory only): statistics, spam detector and bot tracker observations, aggregated metrics events
       (`ua_rule_hit`, `throttle_tier`), `record_throttled` for a client that just became throttled, and a ladder ban
       if a rung with action `ban` was reached. Rule hits: every admin rule row the request matched (the checks
       report them with `Facts.note_match`; bypass is resolved in step 0) is copied onto the verdict (`matches`) and
       handed to the metrics recorder, which sums them per rule and minute in memory and writes them with its
       batch flush. No hot.db or metrics.db write is added to the request.
    Bot scores: the tracker marks each client seen; the `abuse_bot_scores` loop scores the marked clients once a
    minute off the request path and records them per client and hour (plan 10.7; ABUSE-BOT, THROTTLE-TUNE).
    C7: if the transaction raises `SharedStateUnavailable`, the same walk runs on per-worker memory with every limit
    divided by the live fleet (`ROXY_WORKERS`, or more when the heartbeats show more workers, as during a blue/green
    deploy), logged once per streak as degraded. The shares add up to at most the limit (C6): `limit // workers`,
    so a limit smaller than the fleet gives this worker a share of 0 and its requests are refused until hot.db works
    again (fail closed, with no strike: the outage is Roxy's, not the client's). A key this worker has no memory
    row for in this streak starts from the shared row as read from hot.db now (readable in WAL mode even while
    another process holds the write lock), so entering degraded mode never refills a client's allowance. Leaving it
    never refills one either: every row decided in memory stays until hot.db has it. The first successful
    transaction that touches a key merges that key's memory rows into the shared rows before it decides (the later
    GCRA time, the fixed-window counts added, the larger strikes and the later penalty, `merge_limiter_row` and
    `merge_strike_row`), and a background task merges the rest in batches. The tarpit fails closed on its own (no
    lease, no hold).

What to read next
    `roxy/abuse/checks/base.py` (the check contract), `roxy/abuse/limiter.py` and `roxy/abuse/throttle.py` (the
    math), and `roxy/abuse/tarpit.py` (what the router does with a refusal).
"""

from __future__ import annotations

import asyncio
import functools
import logging
import random
import sqlite3
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from typing import Any, Final

from roxy.abuse.bans import BanHits, create_ladder_ban
from roxy.abuse.bot import SIGNALS, ClientTracker, has_game_server_signature, query_fingerprint
from roxy.abuse.bypass import bypass_entry
from roxy.abuse.challenge import challenge_key
from roxy.abuse.checks import default_checks
from roxy.abuse.checks.base import (
    TABLE_ACCESS_LIST,
    Check,
    Facts,
    LimitOutcome,
    LimitSpec,
    TxState,
    live_setting,
    trio_headers,
)
from roxy.abuse.checks.probe import probe_signature
from roxy.abuse.limiter import (
    DegradedEntry,
    LimiterRow,
    MemoryRowStore,
    RateDecision,
    cooldown,
    degraded_limit,
    fixed,
    gcra,
    load_rows,
    merge_limiter_row,
    save_rows,
    unshared,
)
from roxy.abuse.spam import SpamDetectors
from roxy.abuse.state import SwitchesCache
from roxy.abuse.tarpit import Tarpit
from roxy.abuse.throttle import (
    PerIpPolicy,
    StrikeRow,
    effective_strikes,
    evaluate_per_ip,
    ladder_from,
    load_strike_rows,
    merge_strike_row,
    peek_per_ip,
    peek_unshared,
    refuse_unshared,
    save_strike_rows,
)
from roxy.abuse.verdict import Allow, Refuse, Verdict, raw_path, request_target
from roxy.core.client_ip import limit_key as compute_limit_key
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.reasons import ReasonCode
from roxy.metrics.recorder import note_client_scores, note_rule_hits
from roxy.rules.match import regex_budget
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot
from roxy.scheduler.heartbeat import HEARTBEAT_INTERVAL_S, fresh_counts
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

TX_BUSY_TIMEOUT_MS: Final = 500
"""The abuse transaction's total budget (queue wait included) before it degrades (C7) instead of waiting longer."""
SPAM_FLUSH_INTERVAL_S: Final = 1.0
SWITCH_REFRESH_INTERVAL_S: Final = 1.0
BAN_HITS_FLUSH_INTERVAL_S: Final = 5.0
MAX_BACKGROUND_BANS: Final = 32
MAX_UA_HIT_RECORDS: Final = 200
MAX_TIER_RECORDS: Final = 32
PROBE_REASONS: Final = frozenset({ReasonCode.UNSAFE_URL, ReasonCode.NOT_ROBLOX, ReasonCode.HOST_NOT_ALLOWED})
UA_RULE_HIT_EVENT: Final = "ua_rule_hit"
"""Aggregated metrics event: one User-Agent rule evaluated (detail `rule_id`, `result` allowed or refused)."""
TIER_EVENT: Final = "throttle_tier"
"""Aggregated metrics event: a new strike put a client on a ladder rung (detail `tier`)."""
MERGE_BATCH: Final = 256
"""Degraded rows merged into hot.db per background transaction after a C7 outage (short transactions, plan 6.3)."""
MERGE_RETRY_S: Final = 1.0
"""After a background merge could not write, the next one waits at least this long."""
MERGE_CLOSE_WAIT_S: Final = 2.0
"""At shutdown, how long the last merge of degraded rows may take (inside the lifespan's 8 s budget)."""
FLEET_REFRESH_INTERVAL_S: Final = HEARTBEAT_INTERVAL_S
"""How often the live fleet size (the C7 divisor) is read back from the heartbeats."""
BOT_SCORE_INTERVAL_S: Final = 60.0
"""How often the bot scores of the clients seen since the last run are recorded (per client and hour in
metrics.db; the readers ask about the last hour or day, so a minute of delay costs nothing)."""
MAX_SCORES_PER_RUN: Final = 5000
"""Clients scored per run at most (plan P9); the rest keep their mark for the next run, newest first."""
SCORE_CHUNK: Final = 250
"""Clients scored between two yields to the event loop (each score is tens of microseconds)."""
CLOSE_SCORE_LIMIT: Final = 1000
"""Scores recorded at shutdown at most (inside the lifespan's shutdown budget)."""

Shared = tuple[dict[str, LimiterRow], dict[str, StrikeRow]]
"""Limiter rows and strike rows as read from hot.db (a seed for degraded mode, an input for the prediction)."""


@dataclass(slots=True)
class AbuseStats:
    """Per-worker counters for the Protection page (bounded); the metrics layer reads `snapshot()`."""

    evaluated: int = 0
    allowed: int = 0
    refusals: dict[str, int] = field(default_factory=dict)  # by check name
    ua_rule_hits: dict[str, list[int]] = field(default_factory=dict)  # rule id -> [allowed, refused]
    tier_hits: dict[int, int] = field(default_factory=dict)  # ladder rung -> new strikes reaching it
    degraded_requests: int = 0
    degraded_merged: int = 0  # memory rows written into hot.db after a C7 outage
    ladder_bans: int = 0
    pattern_checks_skipped: int = 0  # requests a cheap limiter refused before any admin regex ran

    def snapshot(self) -> dict[str, Any]:
        return {
            "evaluated": self.evaluated,
            "allowed": self.allowed,
            "refusals": dict(self.refusals),
            "ua_rule_hits": {k: {"allowed": v[0], "refused": v[1]} for k, v in self.ua_rule_hits.items()},
            "tier_hits": dict(self.tier_hits),
            "degraded_requests": self.degraded_requests,
            "degraded_merged": self.degraded_merged,
            "ladder_bans": self.ladder_bans,
            "pattern_checks_skipped": self.pattern_checks_skipped,
        }


@dataclass(slots=True)
class _Walk:
    state: TxState
    limiter_writes: list[LimiterRow]
    strike_writes: list[StrikeRow]


@dataclass(slots=True)
class _Pending:
    """Degraded rows claimed for one merge into hot.db (C7 recovery): limiter and strike entries by key."""

    rows: dict[str, DegradedEntry[LimiterRow]] = field(default_factory=dict)
    strikes: dict[str, DegradedEntry[StrikeRow]] = field(default_factory=dict)
    decay_s: float = 0.0

    def __len__(self) -> int:
        return len(self.rows) + len(self.strikes)


def merge_pending_rows(
    conn: sqlite3.Connection,
    rows: dict[str, LimiterRow],
    strikes: dict[str, StrikeRow],
    pending: _Pending,
    now_ms: int,
) -> None:
    """Merge claimed degraded entries into the rows just loaded from hot.db, and write what changed (C7 recovery).

    `rows` and `strikes` are updated in place, so a walk that follows decides on the merged rows. A merged row is
    written even when the walk that follows writes nothing (a refusal): what the worker counted while degraded
    must reach hot.db either way.
    """
    changed_rows: list[LimiterRow] = []
    for key, entry in pending.rows.items():
        loaded = rows.get(key) or LimiterRow(key)
        merged = merge_limiter_row(loaded, entry, now_ms)
        if merged != loaded:
            rows[key] = merged
            changed_rows.append(merged)
    save_rows(conn, changed_rows, now_ms // 1000)
    changed_strikes: list[StrikeRow] = []
    for key, sentry in pending.strikes.items():
        loaded_strike = strikes.get(key) or StrikeRow(key)
        merged_strike = merge_strike_row(loaded_strike, sentry, now_ms // 1000, pending.decay_s)
        if merged_strike != loaded_strike:
            strikes[key] = merged_strike
            changed_strikes.append(merged_strike)
    save_strike_rows(conn, changed_strikes)


@dataclass(slots=True)
class _Prep:
    """The prepare walk: what was prepared, the limiter specs, the first static refusal, the checks deferred."""

    prepared: list[Check] = field(default_factory=list)
    specs: list[LimitSpec] = field(default_factory=list)
    static: tuple[str, Refuse] | None = None
    rest: list[Check] = field(default_factory=list)  # pattern checks, prepared only once the cheap limiters admit


def _decide(spec: LimitSpec, row: LimiterRow, limit: int, now_ms: int) -> RateDecision:
    if spec.algo == "gcra":
        return gcra(row, limit, spec.window_s, now_ms)
    if spec.algo == "cooldown":
        return cooldown(row, spec.cooldown_s, now_ms)
    return fixed(row, limit, spec.window_s, now_ms)


def walk_limiters(
    specs: Sequence[LimitSpec],
    rows: Mapping[str, LimiterRow],
    strikes: Mapping[str, StrikeRow],
    trio_policy: PerIpPolicy | None,
    now_ms: int,
    *,
    divisor: int = 1,
    refused_after: bool = False,
    provisional: bool = False,
) -> _Walk:
    """Evaluate the limiters in order and decide what to write (pure; shared by hot.db and degraded mode).

    `divisor` > 1 divides every limit (degraded mode, plan C7): each limiter gets `limit // divisor` on this worker,
    and a share of 0 refuses without counting (`limiter.unshared`, `throttle.refuse_unshared`); a cooldown is one
    request per period, so its share is 0 whenever the divisor is above 1. `refused_after` says a check after these
    limiters refuses the request anyway (a probe, a block): the admitted counts are then not committed either.
    `provisional` says more limiters may follow (the cheap ones run first, step 2 of the module docstring): when
    everything here admits, NOTHING is written, not even the flood count, because the full walk that follows writes
    it. See the module docstring for the commit rule.
    """
    outcomes: dict[str, LimitOutcome] = {}
    pending: list[LimiterRow] = []
    writes: list[LimiterRow] = []
    strike_writes: list[StrikeRow] = []
    refused_at: str | None = None
    per_ip_outcome: LimitOutcome | None = None
    for spec in specs:
        row = rows.get(spec.key) or LimiterRow(spec.key)
        if spec.algo == "per_ip" and spec.per_ip is not None:
            policy = spec.per_ip
            srow = strikes.get(spec.key) or StrikeRow(spec.key)
            share = degraded_limit(policy.limit, divisor) if divisor > 1 else policy.limit
            if share > 0:
                limited = policy if share == policy.limit else replace(policy, limit=share)
                result = evaluate_per_ip(limited, row, srow, now_ms)
            else:
                result = refuse_unshared(policy, row, srow, now_ms)  # fail closed (C7), no strike
            outcome = LimitOutcome(
                spec, result.admitted, result.remaining, result.reset_s, result.retry_after_s, per_ip=result
            )
            per_ip_outcome = outcome
            if result.admitted and result.limiter_row is not None:
                pending.append(result.limiter_row)
            if not result.admitted:
                if result.strike_row is not None:
                    strike_writes.append(result.strike_row)
                if result.limiter_row is not None:
                    writes.append(result.limiter_row)
        else:
            limit = spec.limit
            if divisor > 1:
                limit = degraded_limit(1 if spec.algo == "cooldown" else spec.limit, divisor)
            if limit > 0:
                decision = _decide(spec, row, limit, now_ms)
            elif spec.algo == "cooldown":
                decision = unshared(row, 1, spec.cooldown_s)
            else:
                decision = unshared(row, spec.limit, spec.window_s)
            outcome = LimitOutcome(
                spec, decision.admitted, decision.remaining, decision.reset_s, decision.retry_after_s, row=decision.row
            )
            if decision.admitted:
                (writes if spec.always_commit else pending).append(decision.row)
        outcomes[spec.check] = outcome
        if not outcome.admitted:
            refused_at = spec.check
            break
    if refused_at is None and provisional:
        writes = []  # nothing decided yet: the full walk after the pattern checks writes everything
    elif refused_at is None and not refused_after:
        writes.extend(pending)
    state = TxState(outcomes=outcomes, stopped_at=refused_at)
    if trio_policy is not None:
        share = degraded_limit(trio_policy.limit, divisor) if divisor > 1 else trio_policy.limit
        policy = trio_policy if share in (0, trio_policy.limit) else replace(trio_policy, limit=share)
        srow = strikes.get(policy.key) or StrikeRow(policy.key)
        now_s = now_ms // 1000
        if (
            per_ip_outcome is not None
            and per_ip_outcome.per_ip is not None
            and ((refused_at is None and not refused_after) or not per_ip_outcome.admitted)
        ):
            result = per_ip_outcome.per_ip
            state.trio = (result.remaining, result.reset_s, not result.admitted)
            state.strikes = result.strikes
        else:
            if share > 0:
                state.trio = peek_per_ip(policy, rows.get(policy.key) or LimiterRow(policy.key), srow, now_ms)
            else:
                state.trio = peek_unshared(policy, srow, now_ms)
            state.strikes = effective_strikes(srow.strikes, srow.last_strike_at, now_s, policy.decay_s)
        final = next((row for row in strike_writes if row.key == policy.key), srow)
        if final.exists:
            state.penalty_wait_ms = max(0, final.throttled_until * 1000 - now_ms)
    return _Walk(state, writes, strike_writes)


def slow_patterns(rules: RulesSnapshot) -> bool:
    """Whether the snapshot has admin regexes the pattern checks would run (the costly kind, plan 9.9).

    Globs and plain text needles are validated to stay cheap, so only `regex` rules make the pipeline evaluate the
    cheap limiters first (module docstring, step 2).
    """
    return (
        any(str(rule.mode) == "regex" for rule in rules.enabled_ua_rules)
        or any(str(rule.mode) == "regex" for rule in rules.enabled_header_rules)
        or any(row.enabled and str(row.type) == "regex" for row in rules.endpoint_blocks)
        or any(row.enabled and str(row.type) == "regex" for row in rules.endpoint_limits)
    )


class AbusePipeline:
    """The abuse layer of one worker (see the module docstring)."""

    def __init__(
        self,
        *,
        settings: Any,
        rules: Any,
        hot_db: Database | None,
        control_db: Database | None = None,
        clock: Clock = SYSTEM_CLOCK,
        worker_id: str = "worker",
        workers: int = 1,
        recorder: Any = None,
        rules_service: RulesService | None = None,
        ip_hash_key: bytes | None = None,
        checks: Sequence[Check] | None = None,
        tarpit_sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        rng: random.Random | None = None,
        metrics_db: Database | None = None,
    ) -> None:
        self.settings = settings
        self.rules = rules
        self.hot_db = hot_db
        self.control_db = control_db
        self.metrics_db = metrics_db  # worker heartbeats: the live fleet size, the C7 divisor
        self.clock = clock
        self._last_now_ms = 0  # the newest limiter time this pipeline used (`steady_now_ms`)
        self.worker_id = worker_id
        self.workers = max(1, int(workers))
        self.recorder = recorder
        self.rules_service = rules_service
        self.monotonic = monotonic
        self.checks: list[Check] = sorted(checks or default_checks(), key=lambda check: check.position)
        self.switches = SwitchesCache(control_db)
        self.tarpit = Tarpit(
            settings, hot_db, clock, worker_id, sleep=tarpit_sleep, monotonic=monotonic, rng=rng, recorder=recorder
        )
        self.spam = SpamDetectors(
            settings, hot_db, clock, control_db=control_db, rules_service=rules_service, events=self._event
        )
        self.bot = ClientTracker()
        self.ban_hits = BanHits()
        self.challenge_key = challenge_key(ip_hash_key) if ip_hash_key else None
        self.stats = AbuseStats()
        self.degraded = False
        self.fleet_size: int | None = None  # live workers of both colors, from the heartbeats (None: unknown)
        # C7 memory: what this worker decided while hot.db could not be written, kept until merged into hot.db.
        self._memory_rows: MemoryRowStore[DegradedEntry[LimiterRow]] = MemoryRowStore()
        self._memory_strikes: MemoryRowStore[DegradedEntry[StrikeRow]] = MemoryRowStore()
        self._streak = 0  # counts degraded streaks; an entry from an earlier streak is rebased on hot.db first
        self._merge_task: asyncio.Task[int] | None = None
        self._merge_not_before = 0.0  # monotonic time before which no new background merge starts
        self._background: set[asyncio.Task[Any]] = set()
        self._slow: tuple[RulesSnapshot, bool] | None = None  # `slow_patterns` of the last snapshot seen

    @classmethod
    def from_context(cls, ctx: Any) -> AbusePipeline:
        """Build the pipeline from the worker's `AppContext` (DESIGN.md 1)."""
        dbs = ctx.dbs
        service = RulesService(dbs.control, clock=ctx.clock, store=ctx.rules) if dbs is not None else None
        return cls(
            settings=ctx.settings,
            rules=ctx.rules,
            hot_db=dbs.hot if dbs is not None else None,
            control_db=dbs.control if dbs is not None else None,
            clock=ctx.clock,
            worker_id=ctx.worker_id,
            workers=int(getattr(ctx.env, "workers", 1) or 1),
            recorder=ctx.recorder,
            rules_service=service,
            ip_hash_key=getattr(ctx, "ip_hash_key", None),
            metrics_db=getattr(dbs, "metrics", None) if dbs is not None else None,
        )

    # ---- inputs ----

    def _values(self) -> Mapping[str, Any]:
        snapshot = self.settings.snapshot()
        return snapshot if isinstance(snapshot, Mapping) else {}

    def _rules_snapshot(self) -> RulesSnapshot:
        if isinstance(self.rules, RulesSnapshot):
            return self.rules
        snapshot = getattr(self.rules, "snapshot", None)
        if callable(snapshot):
            snapshot = snapshot()
        return snapshot if isinstance(snapshot, RulesSnapshot) else RulesSnapshot.empty()

    def _facts(self, req: Any, values: Mapping[str, Any], rules: RulesSnapshot, now: float, now_ms: int) -> Facts:
        ip = str(getattr(req, "client_ip", "") or "")

        def value(name: str) -> Any:
            return live_setting(values, name)  # the catalog default when the snapshot lacks it (no inline copy)

        key = str(getattr(req, "limit_key", "") or "") or compute_limit_key(ip, int(value("ipv6_limit_prefix")))
        ladder = ladder_from(rules.throttle_tiers)
        policy = PerIpPolicy(
            key=key,
            mode="fixed" if str(value("throttle_window_mode")) == "fixed" else "gcra",
            limit=max(1, int(value("allowed_requests_per_minute"))),
            window_s=max(1, int(value("throttle_reset_duration"))),
            escalation=bool(value("throttle_escalation_enabled")),
            decay_s=max(0, int(value("throttle_strike_decay_seconds"))),
            ladder=ladder,
            strike_on_retry=bool(value("throttle_strike_on_retry")),
        )
        path = raw_path(req)
        cidrs = value("roblox_egress_cidrs") or ()
        return Facts(
            now=now,
            now_ms=now_ms,
            values=values,
            rules=rules,
            services=self,
            target=request_target(req),
            path=path,
            ip=ip,
            limit_key=key,
            per_ip=policy,
            ladder=ladder,
            game_server=has_game_server_signature(
                place_id=getattr(req, "place_id", None),
                user_agent=str(getattr(req, "user_agent", "") or ""),
                client_ip=ip,
                egress_cidrs=list(cidrs),
            ),
            probe_signature=probe_signature(path),
        )

    def _has_slow_patterns(self, rules: RulesSnapshot) -> bool:
        """`slow_patterns(rules)`, computed once per rules snapshot (snapshots are immutable)."""
        cached = self._slow
        if cached is not None and cached[0] is rules:
            return cached[1]
        value = slow_patterns(rules)
        self._slow = (rules, value)
        return value

    # ---- the request path ----

    def steady_now_ms(self) -> int:
        """The clock's milliseconds, never below the last value this pipeline decided with.

        Limiter rows hold wall-clock times (they are shared through hot.db by every process), and a wall clock can
        step back (an NTP step; WSL steps about 0.9 s back every 31 s). GCRA grants a burst against a theoretical
        arrival time, so a step back between two requests of one burst made the last request of a granted
        allowance look early and refused it. Holding the last time until the clock catches up keeps every decision
        of this worker on one forward timeline; a forward jump is taken at once.
        """
        now_ms = int(self.clock.now_ms())
        if now_ms < self._last_now_ms:
            return self._last_now_ms
        self._last_now_ms = now_ms
        return now_ms

    async def evaluate(self, req: Any) -> Verdict:
        """Decide one request (see the module docstring). Never raises for shared-state trouble (C7)."""
        values = self._values()
        rules = self._rules_snapshot()
        now = self.clock.now()
        now_ms = self.steady_now_ms()  # limiter time never steps back inside this worker
        facts = self._facts(req, values, rules, now, now_ms)
        entry = None if getattr(req, "bypass", False) else bypass_entry(rules, facts.ip, now)
        if entry is not None:
            req.bypass = True  # step 0: known before bans refuse, so a bypass caller is never held (plan 10.6)
            facts.note_match(TABLE_ACCESS_LIST, entry.id)  # the entry's hit, whichever check decides
        bypass = bool(getattr(req, "bypass", False))
        with regex_budget():  # every pattern match of this request shares one time budget (plan 9.9)
            prep = _Prep()
            self._prepare(req, facts, self.checks, prep, defer_patterns=self._has_slow_patterns(rules))
            tx = await self._settle(req, facts, prep, bypass)
            tx.facts = facts
            if prep.static is not None:
                tx.static[prep.static[0]] = prep.static[1]
            refused: Refuse | None = None
            for check in prep.prepared:
                refused = await check.check(req, tx)
                if refused is not None:
                    break
            serve_cached = refused is not None and refused.allow_fresh_cache_serve
            if serve_cached and refused is not None and self._later_check_refuses(req, facts, refused, prep, tx):
                refused.allow_fresh_cache_serve = False  # never serve content to a request a filter refuses
        verdict: Verdict = refused if refused is not None else Allow(headers=trio_headers(tx))
        verdict.matches = dict(facts.matches)  # the rule rows this request matched, whatever the verdict
        self._after(req, facts, tx, verdict)
        return verdict

    @staticmethod
    def _prepare(req: Any, facts: Facts, checks: Sequence[Check], prep: _Prep, *, defer_patterns: bool) -> None:
        """Step 1 (and, for deferred pattern checks, the second half of step 2) of the module docstring."""
        for index, check in enumerate(checks):
            if check.skipped_by_bypass and getattr(req, "bypass", False):
                continue
            if defer_patterns and check.uses_patterns:
                prep.rest = list(checks[index:])
                return
            result = check.prepare(req, facts)
            prep.prepared.append(check)
            if isinstance(result, Refuse):
                prep.static = (check.name, result)
                return
            if isinstance(result, LimitSpec):
                prep.specs.append(result)

    async def _settle(self, req: Any, facts: Facts, prep: _Prep, bypass: bool) -> TxState:
        """Steps 2 and 3: the cheap limiters first when pattern checks were deferred, then the one transaction."""
        if prep.rest:
            refused = await self._cheap_first(prep.specs, facts, bypass)
            if refused is not None:
                self.stats.pattern_checks_skipped += 1
                return refused  # a cheap limiter refused: decided with one write, no admin regex ever ran
            rest, prep.rest = prep.rest, []
            self._prepare(req, facts, rest, prep, defer_patterns=False)
        return await self._transaction(prep.specs, facts, bypass, prep.static is not None)

    async def _cheap_first(self, specs: list[LimitSpec], facts: Facts, bypass: bool) -> TxState | None:
        """The cheap limiters' verdict when one of them refuses (that transaction is final), else None."""
        if not specs:
            return None
        policy = None if bypass else facts.per_ip
        keys = [spec.key for spec in specs] + ([policy.key] if policy is not None else [])
        seed = await self._read_shared(keys, [policy.key] if policy is not None else [])
        if seed is not None:
            rows, strikes = self._overlay(seed, facts.now_ms, policy)  # rows not merged yet count as merged
            predicted = walk_limiters(specs, rows, strikes, policy, facts.now_ms)
            if predicted.state.stopped_at is None:
                return None  # they admit on the shared rows: prepare the pattern checks, then one transaction
        state = await self._transaction(specs, facts, bypass, provisional=True, seed=seed)
        return state if state.stopped_at is not None else None

    async def _transaction(
        self,
        specs: list[LimitSpec],
        facts: Facts,
        bypass: bool,
        refused_after: bool = False,
        *,
        provisional: bool = False,
        seed: Shared | None = None,
    ) -> TxState:
        policy = None if bypass else facts.per_ip
        # v1: a bypass entry is never counted, so its headers always show the full allowance.
        bypass_trio = (facts.per_ip.limit if facts.per_ip is not None else 10, 0, False)
        if bypass and not specs:
            return TxState(trio=bypass_trio)
        if not specs:
            return await self._peek(policy, facts.now_ms)
        # Rows this worker decided while degraded and hot.db does not have yet ride along in this transaction.
        pending = self._claim([spec.key for spec in specs], policy)
        written = False
        try:
            if self.hot_db is None:
                raise SharedStateUnavailable("hot", "no hot.db in this process")
            walk = await self.hot_db.write(
                lambda conn: self._tx(conn, specs, policy, facts.now_ms, refused_after, provisional, pending),
                busy_timeout_ms=TX_BUSY_TIMEOUT_MS,
            )
            written = True
        except SharedStateUnavailable as exc:
            self._release(pending, merged=False)
            state = await self._degraded_walk(specs, policy, facts.now_ms, exc, refused_after, provisional, seed)
        else:
            self._release(pending, merged=True)
            self._recovered()
            self._schedule_merge()
            state = walk.state
        finally:
            if not written:
                self._release(pending, merged=False)  # an unexpected error: the rows stay pending (idempotent)
        if bypass:
            state.trio = bypass_trio
        return state

    @staticmethod
    def _tx(
        conn: sqlite3.Connection,
        specs: list[LimitSpec],
        policy: PerIpPolicy | None,
        now_ms: int,
        refused_after: bool = False,
        provisional: bool = False,
        pending: _Pending | None = None,
    ) -> _Walk:
        keys = [spec.key for spec in specs]
        if policy is not None:
            keys.append(policy.key)
        rows = load_rows(conn, keys)
        strikes = load_strike_rows(conn, [policy.key]) if policy is not None else {}
        if pending is not None:
            merge_pending_rows(conn, rows, strikes, pending, now_ms)  # C7 recovery: decide on the merged rows
        walk = walk_limiters(specs, rows, strikes, policy, now_ms, refused_after=refused_after, provisional=provisional)
        save_rows(conn, walk.limiter_writes, now_ms // 1000)
        save_strike_rows(conn, walk.strike_writes)
        return walk

    # ---- C7: degraded mode and the way back ----

    def _divisor(self) -> int:
        """The C7 divisor: `ROXY_WORKERS`, or the live fleet when the heartbeats show more (both colors in a deploy)."""
        return max(self.workers, self.fleet_size or 0)

    def _decay_s(self, policy: PerIpPolicy | None) -> float:
        if policy is not None:
            return float(policy.decay_s)
        return float(max(0, int(live_setting(self._values(), "throttle_strike_decay_seconds"))))

    def _claim(self, keys: Sequence[str], policy: PerIpPolicy | None) -> _Pending | None:
        """The pending degraded entries of these keys, marked as carried by one merge (None when there are none).

        Called only on the event loop. Entries this worker never changed (seeds) carry nothing and are dropped.
        """
        if not (len(self._memory_rows) or len(self._memory_strikes)):
            return None
        pending = _Pending(decay_s=self._decay_s(policy))
        for key in dict.fromkeys([*keys, *([policy.key] if policy is not None else [])]):
            entry = self._memory_rows.get(key)
            if entry is not None and not entry.claimed:
                if entry.changed:
                    entry.claimed = True
                    pending.rows[key] = entry
                elif not self.degraded:
                    self._memory_rows.discard(key, entry)
        if policy is not None:
            sentry = self._memory_strikes.get(policy.key)
            if sentry is not None and not sentry.claimed:
                if sentry.changed:
                    sentry.claimed = True
                    pending.strikes[policy.key] = sentry
                elif not self.degraded:
                    self._memory_strikes.discard(policy.key, sentry)
        return pending if len(pending) else None

    def _claim_batch(self, limit: int) -> _Pending | None:
        """Up to `limit` pending entries, oldest first, for one background merge transaction."""
        pending = _Pending(decay_s=self._decay_s(None))
        for key, entry in self._memory_rows.items():
            if len(pending) >= limit:
                break
            if entry.claimed:
                continue
            if not entry.changed:
                self._memory_rows.discard(key, entry)
                continue
            entry.claimed = True
            pending.rows[key] = entry
        for key, sentry in self._memory_strikes.items():
            if len(pending) >= limit:
                break
            if sentry.claimed:
                continue
            if not sentry.changed:
                self._memory_strikes.discard(key, sentry)
                continue
            sentry.claimed = True
            pending.strikes[key] = sentry
        return pending if len(pending) else None

    def _release(self, pending: _Pending | None, *, merged: bool) -> None:
        """After a merge transaction: forget the entries hot.db now has, or give them back to be merged later.

        An entry a degraded walk replaced meanwhile (a newer object under the same key) is kept either way; it
        holds everything the old one did, so merging it again can only count more, never less (conservative).
        """
        if pending is None:
            return
        for key, entry in pending.rows.items():
            entry.claimed = False
            if merged:
                self._memory_rows.discard(key, entry)
        for key, sentry in pending.strikes.items():
            sentry.claimed = False
            if merged:
                self._memory_strikes.discard(key, sentry)
        if merged:
            self.stats.degraded_merged += len(pending)
        pending.rows.clear()
        pending.strikes.clear()

    def _recovered(self) -> None:
        """A write worked: leave degraded mode. Unchanged seeds are dropped; changed rows wait for their merge."""
        if not self.degraded:
            return
        self.degraded = False
        for key, entry in self._memory_rows.items():
            if not entry.changed and not entry.claimed:
                self._memory_rows.discard(key, entry)
        for key, sentry in self._memory_strikes.items():
            if not sentry.changed and not sentry.claimed:
                self._memory_strikes.discard(key, sentry)
        pending = len(self._memory_rows) + len(self._memory_strikes)
        log.info("abuse_degraded_recovered", extra={"fields": {"pending_rows": pending}})
        self._event("abuse_degraded_recovered", "info", {"pending_rows": pending})

    def _schedule_merge(self) -> None:
        """Start the background merge of the remaining degraded rows, unless one runs or there is nothing to do."""
        if self.degraded or not (len(self._memory_rows) or len(self._memory_strikes)):
            return
        if self._merge_task is not None and not self._merge_task.done():
            return
        if self.monotonic() < self._merge_not_before:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._merge_task = loop.create_task(self.merge_pending())

    async def merge_pending(self, *, even_if_degraded: bool = False) -> int:
        """Write every pending degraded row into hot.db, `MERGE_BATCH` per transaction. Returns how many were merged.

        Stops at the first write that fails (the pipeline is then degraded again, or will be: the rows stay in
        memory, where the degraded walk keeps using them). Never raises.
        """
        merged = 0
        while self.hot_db is not None and (even_if_degraded or not self.degraded):
            pending = self._claim_batch(MERGE_BATCH)
            if pending is None:
                break
            now_ms = self.steady_now_ms()
            size = len(pending)
            try:
                job = functools.partial(self._merge_job, pending=pending, now_ms=now_ms)
                await self.hot_db.write(job, busy_timeout_ms=TX_BUSY_TIMEOUT_MS)
            except SharedStateUnavailable:
                self._release(pending, merged=False)
                self._merge_not_before = self.monotonic() + MERGE_RETRY_S
                break
            except Exception:
                self._release(pending, merged=False)
                self._merge_not_before = self.monotonic() + MERGE_RETRY_S
                log.exception("abuse_degraded_merge_failed")
                break
            self._release(pending, merged=True)
            merged += size
        if merged:
            log.info("abuse_degraded_merged", extra={"fields": {"rows": merged}})
        return merged

    @staticmethod
    def _merge_job(conn: sqlite3.Connection, pending: _Pending, now_ms: int) -> None:
        rows = load_rows(conn, pending.rows)
        strikes = load_strike_rows(conn, pending.strikes)
        merge_pending_rows(conn, rows, strikes, pending, now_ms)

    def _overlay(self, shared: Shared, now_ms: int, policy: PerIpPolicy | None) -> Shared:
        """`shared` with this worker's pending degraded rows merged in (in memory only, for a read-only view)."""
        rows, strikes = dict(shared[0]), dict(shared[1])
        if not (len(self._memory_rows) or len(self._memory_strikes)):
            return rows, strikes
        for key in list(rows):
            entry = self._memory_rows.get(key)
            if entry is not None and entry.changed:
                rows[key] = merge_limiter_row(rows[key], entry, now_ms)
        decay_s = self._decay_s(policy)
        for key in list(strikes):
            sentry = self._memory_strikes.get(key)
            if sentry is not None and sentry.changed:
                strikes[key] = merge_strike_row(strikes[key], sentry, now_ms // 1000, decay_s)
        return rows, strikes

    async def refresh_fleet_size(self) -> None:
        """Background loop: the live workers of both colors from metrics.db heartbeats (the C7 divisor, plan C6).

        A failed read keeps the last value: a larger divisor is only more conservative.
        """
        if self.metrics_db is None:
            return
        now = self.clock.now()
        try:
            counts = await self.metrics_db.read(lambda conn: fresh_counts(conn, now))
        except (SharedStateUnavailable, sqlite3.Error) as exc:
            log.debug("abuse_fleet_size_unavailable", extra={"fields": {"error": str(exc)[:200]}})
            return
        total = sum(counts.values())
        self.fleet_size = total if total > 0 else None

    async def _read_shared(self, keys: list[str], strike_keys: list[str]) -> Shared | None:
        """Limiter and strike rows from hot.db with a READ (works while another process holds the write lock)."""
        if self.hot_db is None or not (keys or strike_keys):
            return None
        try:
            return await self.hot_db.read(lambda conn: (load_rows(conn, keys), load_strike_rows(conn, strike_keys)))
        except SharedStateUnavailable:
            return None

    @staticmethod
    def _algos(specs: Sequence[LimitSpec], policy: PerIpPolicy | None) -> dict[str, str]:
        """Key to merge rule (`gcra`, `fixed` or `cooldown`) for every limiter row this request touches."""
        algos: dict[str, str] = {}
        for spec in specs:
            if spec.algo == "per_ip":
                algos[spec.key] = spec.per_ip.mode if spec.per_ip is not None else "gcra"
            else:
                algos[spec.key] = spec.algo
        if policy is not None:
            algos.setdefault(policy.key, policy.mode)
        return algos

    def _memory_row(self, key: str, algo: str, shared: LimiterRow | None, now_ms: int) -> LimiterRow:
        """This worker's row for `key` in the current streak, starting from (or rebased on) the shared row."""
        entry = self._memory_rows.get(key)
        if entry is not None and entry.streak == self._streak:
            return entry.row
        base = shared or LimiterRow(key)
        if entry is None:
            entry = DegradedEntry(base, base, algo, self._streak)
        else:
            # Left from an earlier streak and not merged yet: keep what this worker counted then, on top of the
            # shared row as it is now (which may hold what other workers counted since).
            entry = DegradedEntry(merge_limiter_row(base, entry, now_ms), base, entry.algo, self._streak)
        if entry.row.exists or entry.changed:
            self._memory_rows.put(key, entry)
        return entry.row

    def _memory_strike(self, key: str, shared: StrikeRow | None, now_s: int, decay_s: float) -> StrikeRow:
        """`_memory_row` for the client's strike row."""
        entry = self._memory_strikes.get(key)
        if entry is not None and entry.streak == self._streak:
            return entry.row
        base = shared or StrikeRow(key)
        if entry is None:
            entry = DegradedEntry(base, base, "strikes", self._streak)
        else:
            entry = DegradedEntry(merge_strike_row(base, entry, now_s, decay_s), base, "strikes", self._streak)
        if entry.row.exists or entry.changed:
            self._memory_strikes.put(key, entry)
        return entry.row

    async def _degraded_walk(
        self,
        specs: list[LimitSpec],
        policy: PerIpPolicy | None,
        now_ms: int,
        exc: SharedStateUnavailable,
        refused_after: bool = False,
        provisional: bool = False,
        seed: Shared | None = None,
    ) -> TxState:
        """C7: the same decision on this worker's memory at `limit // fleet`, starting from the shared rows."""
        if not self.degraded:
            self.degraded = True
            self._streak += 1
            divisor = self._divisor()
            log.warning(
                "abuse_degraded",
                extra={"fields": {"error": str(exc)[:200], "workers": divisor, "mode": "limit // workers"}},
            )
            self._event("abuse_degraded", "critical", {"error": str(exc)[:200], "workers": divisor})
        self.stats.degraded_requests += 1
        algos = self._algos(specs, policy)
        strike_keys = [policy.key] if policy is not None else []
        decay_s = self._decay_s(policy)

        def stale(entry: DegradedEntry[Any] | None) -> bool:
            return entry is None or entry.streak != self._streak

        missing = [key for key in algos if stale(self._memory_rows.get(key))]
        strike_missing = [key for key in strike_keys if stale(self._memory_strikes.get(key))]
        shared: Shared | None = seed
        if shared is None and (missing or strike_missing):
            # A client already over its allowance in hot.db must not get a fresh one here (C7 is conservative).
            shared = await self._read_shared(missing, strike_missing)
        # No await from here on: reading memory, the walk and writing memory are one step of this worker's event
        # loop, so concurrent requests of one client never all start from the same row (each sees the last write).
        shared_rows, shared_strikes = shared if shared is not None else ({}, {})
        rows = {key: self._memory_row(key, algo, shared_rows.get(key), now_ms) for key, algo in algos.items()}
        strikes = {
            key: self._memory_strike(key, shared_strikes.get(key), now_ms // 1000, decay_s) for key in strike_keys
        }
        walk = walk_limiters(
            specs,
            rows,
            strikes,
            policy,
            now_ms,
            divisor=self._divisor(),
            refused_after=refused_after,
            provisional=provisional,
        )
        for row in walk.limiter_writes:
            entry = self._memory_rows.get(row.key)
            base = entry.seed if entry is not None else LimiterRow(row.key)
            self._memory_rows.put(row.key, DegradedEntry(row, base, algos.get(row.key, "gcra"), self._streak))
        for srow in walk.strike_writes:
            sentry = self._memory_strikes.get(srow.key)
            sbase = sentry.seed if sentry is not None else StrikeRow(srow.key)
            self._memory_strikes.put(srow.key, DegradedEntry(srow, sbase, "strikes", self._streak))
        walk.state.degraded = True
        return walk.state

    async def _peek(self, policy: PerIpPolicy | None, now_ms: int) -> TxState:
        """The trio for a refusal decided before any limiter ran (pause, ban): one read, no write.

        While degraded, this worker's memory rows of the current streak are the truth (they include what it
        admitted since hot.db stopped accepting writes); otherwise hot.db with any rows not merged yet added, and
        memory again if hot.db cannot even be read.
        """
        if policy is None:
            return TxState()
        key = policy.key
        entry, sentry = self._memory_rows.get(key), self._memory_strikes.get(key)
        divisor = self._divisor() if self.degraded else 1
        current = [e for e in (entry, sentry) if e is not None and e.streak == self._streak]
        if self.degraded and current:
            rows = {key: entry.row if entry is not None else LimiterRow(key)}
            strikes = {key: sentry.row if sentry is not None else StrikeRow(key)}
            return walk_limiters([], rows, strikes, policy, now_ms, divisor=divisor).state
        shared = await self._read_shared([key], [key])
        if shared is not None:
            rows, strikes = self._overlay(shared, now_ms, policy)
        else:
            rows = {key: entry.row if entry is not None else LimiterRow(key)}
            strikes = {key: sentry.row if sentry is not None else StrikeRow(key)}
        return walk_limiters([], rows, strikes, policy, now_ms, divisor=divisor).state

    def _later_check_refuses(self, req: Any, facts: Facts, verdict: Refuse, prep: _Prep, tx: TxState) -> bool:
        """Whether a static check after `verdict.check` would refuse this request (step 4 of the module docstring).

        Static checks are the filters (challenge, bot score, ignored path, probes, auth smuggling, header filters,
        blocks); rate limits after the throttle are not consulted, as v1 step 4a skipped them. Preparing is pure
        (no I/O), so this costs at most the pattern matching an admitted request would pay anyway.
        """
        position = next((check.position for check in self.checks if check.name == verdict.check), None)
        if position is None:
            return True  # an unknown refusing check: fail closed, no content
        later = [check for check in self.checks if check.position > position]
        if any(check.name in tx.static for check in later):
            return True
        prepared = {check.name for check in prep.prepared}
        for check in later:
            if check.kind != "static" or check.name in prepared:
                continue
            if check.skipped_by_bypass and getattr(req, "bypass", False):
                continue
            if isinstance(check.prepare(req, facts), Refuse):
                return True
        return False

    def _after(self, req: Any, facts: Facts, tx: TxState, verdict: Verdict) -> None:
        """Statistics and memory-only observations; never raises (metrics never fail a request)."""
        try:
            self._record(req, facts, tx, verdict)
        except Exception:
            log.exception("abuse_after_failed")

    def _record(self, req: Any, facts: Facts, tx: TxState, verdict: Verdict) -> None:
        stats = self.stats
        stats.evaluated += 1
        refused = isinstance(verdict, Refuse)
        if isinstance(verdict, Refuse):
            stats.refusals[verdict.check] = stats.refusals.get(verdict.check, 0) + 1
        else:
            stats.allowed += 1
        ua = tx.outcomes.get("user_agent_rule")
        if ua is not None and ua.spec.payload is not None:
            rule_id = str(ua.spec.payload.id)
            if rule_id in stats.ua_rule_hits or len(stats.ua_rule_hits) < MAX_UA_HIT_RECORDS:
                entry = stats.ua_rule_hits.setdefault(rule_id, [0, 0])
                entry[0 if ua.admitted else 1] += 1
            self._aggregate(
                UA_RULE_HIT_EVENT, {"rule_id": rule_id, "result": "allowed" if ua.admitted else "refused"}, facts
            )
        if facts.matches:
            # Every rule row this request matched (blocks, rate rules, header and User-Agent rules, bypass, deny and
            # ban entries): per rule per minute in memory, flushed by the recorder (FILTER-REMOVE, SEC-BYPASS-FOREVER).
            note_rule_hits(self.recorder, facts.matches, at_s=int(facts.now))
        per_ip = next((o.per_ip for o in tx.outcomes.values() if o.per_ip is not None), None)
        if per_ip is not None and per_ip.new_strike and per_ip.rung.index:
            tier = per_ip.rung.index
            if tier in stats.tier_hits or len(stats.tier_hits) < MAX_TIER_RECORDS:
                stats.tier_hits[tier] = stats.tier_hits.get(tier, 0) + 1
            self._aggregate(TIER_EVENT, {"tier": tier}, facts)
        if per_ip is not None and per_ip.punished:
            self._throttled(facts.ip or facts.limit_key, per_ip.rung.index, per_ip.strikes)
        if per_ip is not None and not per_ip.admitted and per_ip.ban_minutes:
            self._ladder_ban(facts.limit_key, per_ip.ban_minutes, per_ip.rung.index, int(facts.now))
        reason = verdict.reason if isinstance(verdict, Refuse) else None
        probe = reason in PROBE_REASONS or facts.probe_signature is not None
        bypass = bool(getattr(req, "bypass", False))
        query = list(getattr(req, "query", None) or ())
        self.spam.observe(
            limit_key=facts.limit_key,
            place_id=getattr(req, "place_id", None),
            template=str(getattr(req, "template", "") or ""),
            path=str(getattr(req, "path", "") or ""),
            query=query,
            user_agent=str(getattr(req, "user_agent", "") or ""),
            # A paused Roxy refuses everyone; that must never look like a client "sending while refused".
            refused=refused and reason != ReasonCode.PAUSED,
            probe=probe,
            auth=reason == ReasonCode.AUTH_SMUGGLING,
            game_server=facts.game_server,
            bypass=bypass,
        )
        if not bypass:
            self.bot.observe(
                facts.limit_key,
                now=facts.now,
                monotonic=self.monotonic(),
                refused=refused,
                probe=probe,
                query_fp=query_fingerprint(str(getattr(req, "template", "") or ""), query),
                ip=facts.ip,
                user_agent=str(getattr(req, "user_agent", "") or ""),
                game_server=facts.game_server,
                header_names=getattr(req, "header_names_in_order", None) or (),
            )

    def _ladder_ban(self, limit_key: str, minutes: int, rung: int, now: int) -> None:
        """A rung with action `ban` was reached: create the ban in the background (control.db write)."""
        if self.rules_service is None or len(self._background) >= MAX_BACKGROUND_BANS:
            return
        service = self.rules_service

        async def run() -> None:
            try:
                await create_ladder_ban(service, limit_key=limit_key, minutes=minutes, rung=rung, now=now)
                self.stats.ladder_bans += 1
            except Exception:
                log.exception("abuse_ladder_ban_failed", extra={"fields": {"rung": rung}})

        task = asyncio.get_running_loop().create_task(run())
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    def _event(self, kind: str, severity: str, detail: Mapping[str, Any]) -> None:
        """Forward a notable event to the metrics recorder (DESIGN.md 8), if there is one."""
        record = getattr(self.recorder, "record_event", None)
        if record is None:
            return
        try:
            record(kind, severity, ReasonCode.SPAM if kind.startswith("spam") else None, dict(detail))
        except Exception:
            log.exception("abuse_event_failed", extra={"fields": {"kind": kind}})

    def _aggregate(self, kind: str, detail: Mapping[str, Any], facts: Facts) -> None:
        """A counter event summed per minute by the recorder (`record_event(..., aggregate=True)`, DESIGN 11.9)."""
        record = getattr(self.recorder, "record_event", None)
        if record is None:
            return
        try:
            record(kind, "info", None, dict(detail), at_ms=facts.now_ms, aggregate=True)
        except TypeError:
            return  # a recorder without the keyword arguments (tests, older builds): counted in `stats` only
        except Exception:
            log.exception("abuse_event_failed", extra={"fields": {"kind": kind}})

    def _throttled(self, ip: str, tier: int, strikes: int) -> None:
        """`record_throttled`: a client that just became throttled (v1 `throttled_ips`, plan row 80)."""
        record = getattr(self.recorder, "record_throttled", None)
        if record is None:
            return
        try:
            record(ip, tier=tier or None, strikes=strikes)
        except Exception:
            log.exception("abuse_event_failed", extra={"fields": {"kind": "throttled"}})

    # ---- admin and lifecycle ----

    def describe(self) -> list[dict[str, Any]]:
        """The pipeline for the Protection page diagram, in order."""
        return [check.describe() for check in self.checks]

    async def flush_ban_hits(self) -> int:
        if self.control_db is None:
            return 0
        return await self.ban_hits.flush(self.control_db)

    async def record_bot_scores(self, *, limit: int = MAX_SCORES_PER_RUN) -> int:
        """Background loop: score the clients seen since the last run and hand the scores to the metrics recorder.

        Off the request path (plan 10.7 scores, recorded for ABUSE-BOT, THROTTLE-TUNE and ABUSE-DIST): at most
        `limit` clients per run, scored in chunks of `SCORE_CHUNK` with a yield to the event loop between chunks, so
        a busy minute never stalls requests. Each address behind a client key gets the key's score. Returns how many
        scores were recorded (0 without a recorder: the marks are still cleared, so memory stays bounded).
        """
        values = self._values()
        weights = {name: float(live_setting(values, f"bot_weight_{name}")) for name in SIGNALS}
        now = self.clock.now()
        recorded = 0
        left = max(0, int(limit))
        while left > 0:
            batch = self.bot.take_scores(now=now, weights=weights, limit=min(SCORE_CHUNK, left))
            if not batch:
                break
            left -= len(batch)
            recorded += note_client_scores(
                self.recorder, [(ip, item.score) for item in batch for ip in item.ips], at_s=now
            )
            await asyncio.sleep(0)  # let requests run between chunks
        return recorded

    def start(self, tasks: Any) -> None:
        """Start the background loops on the worker's `TaskSupervisor`."""
        tasks.start("abuse_spam_flush", self.spam.flush, interval_s=SPAM_FLUSH_INTERVAL_S)
        tasks.start("abuse_switches", self.switches.refresh_if_changed, interval_s=SWITCH_REFRESH_INTERVAL_S)
        tasks.start("abuse_ban_hits", self.flush_ban_hits, interval_s=BAN_HITS_FLUSH_INTERVAL_S)
        tasks.start("abuse_fleet_size", self.refresh_fleet_size, interval_s=FLEET_REFRESH_INTERVAL_S)
        tasks.start("abuse_bot_scores", self.record_bot_scores, interval_s=BOT_SCORE_INTERVAL_S)

    async def aclose(self) -> None:
        """Shutdown: flush what is buffered and merge degraded rows into hot.db (best effort), wait for bans."""
        for flush in (self.spam.flush, self.flush_ban_hits):
            try:
                await flush()
            except Exception:
                log.exception("abuse_close_flush_failed")
        try:
            # The scores of clients seen since the last run; the recorder's final flush (after this) writes them.
            await self.record_bot_scores(limit=CLOSE_SCORE_LIMIT)
        except Exception:
            log.exception("abuse_close_scores_failed")
        if self._merge_task is not None and not self._merge_task.done():
            await asyncio.wait({self._merge_task}, timeout=MERGE_CLOSE_WAIT_S)
        if len(self._memory_rows) or len(self._memory_strikes):
            # What this worker counted during an outage must outlive it: one more try, even if the last write failed.
            try:
                await asyncio.wait_for(self.merge_pending(even_if_degraded=True), timeout=MERGE_CLOSE_WAIT_S)
            except TimeoutError:
                log.warning("abuse_degraded_merge_unfinished_at_close")
        if self._background:
            await asyncio.wait(set(self._background), timeout=5)


async def install(ctx: Any, stack: AsyncExitStack) -> AbusePipeline:
    """Lifespan hook (after the recorder step): build `ctx.abuse`, load the switches, start the loops."""
    pipeline = AbusePipeline.from_context(ctx)
    try:
        await pipeline.switches.reload()
    except SharedStateUnavailable as exc:
        log.warning("abuse_switches_unavailable_at_start", extra={"fields": {"error": str(exc)[:200]}})
    ctx.abuse = pipeline
    pipeline.start(ctx.tasks)
    stack.push_async_callback(pipeline.aclose)
    return pipeline


__all__ = [
    "MERGE_BATCH",
    "TIER_EVENT",
    "UA_RULE_HIT_EVENT",
    "AbusePipeline",
    "AbuseStats",
    "Allow",
    "Refuse",
    "Verdict",
    "install",
    "merge_pending_rows",
    "slow_patterns",
    "walk_limiters",
]
