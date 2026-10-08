"""The abuse pipeline: runs every check in order and decides `Allow` or `Refuse` with ONE hot.db transaction.

What this is
    `AbusePipeline.evaluate(req) -> Allow | Refuse` (DESIGN.md 7 and 11.5), the object stored at `ctx.abuse`, plus
    `install(ctx, stack)`, the lifespan hook that builds it, loads the admin switches and starts its background loops
    (spam flush every second, switch refresh every second, ban hit flush every 5 s). It also owns the tarpit
    (`pipeline.tarpit`), the spam detectors, the bot tracker and the per-worker statistics.

Why it exists
    v1 ran its checks inline in one long handler and touched its throttle file several times per request (and
    separately from the check, so the crossing request leaked through). Plan 6.3 requires every limiter of a request
    (flood, throttle-all, per-IP and strikes, place, User-Agent rule, endpoint rule) to be evaluated and updated in a
    single `BEGIN IMMEDIATE` transaction, committing only what the outcome requires, and plan C7 requires sane limits
    when that transaction cannot run.

How it works
    1. Prepare: walk the checks in position order (`checks/__init__.py`). Each returns nothing, a refusal that needs
       no shared state (pause, ban, probe, block, ...), or a `LimitSpec`. Bypass-skipped checks are not prepared once
       the bypass marker has set `req.bypass`. Preparing stops at the first refusal: nothing after it can matter.
    2. Transaction: one `hot.write` loads every needed `limiter` row and the client's `strikes` row, evaluates the
       limiters in order, and stops at the first refusal. Commit rule: the flood counter always (it counts every
       request); the refusing limiter's own consequences (a strike, a penalty); and the admitted limiters' counts only
       when nothing refused. A request refused later therefore spends no rate budget (plan 6.3; v1 spent UA and
       throttle-all budgets on requests it then refused). The per-IP header trio comes from the same rows.
    3. Verdict: ask each prepared check, in order, for its refusal; the first one wins. Otherwise `Allow` with the trio.
    4. Afterwards (memory only): statistics, spam detector and bot tracker observations, and a ladder ban if a rung
       with action `ban` was reached.
    C7: if the transaction raises `SharedStateUnavailable`, the same walk runs on per-worker memory with every limit
    divided by the number of workers (`ROXY_WORKERS`), logged once per streak as degraded. The tarpit fails closed on
    its own (no lease, no hold).

What to read next
    `roxy/abuse/checks/base.py` (the check contract), `roxy/abuse/limiter.py` and `roxy/abuse/throttle.py` (the
    math), and `roxy/abuse/tarpit.py` (what the router does with a refusal).
"""

from __future__ import annotations

import asyncio
import logging
import random
import sqlite3
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from typing import Any, Final

from roxy.abuse.bans import BanHits, create_ladder_ban
from roxy.abuse.bot import ClientTracker, has_game_server_signature, query_fingerprint
from roxy.abuse.challenge import challenge_key
from roxy.abuse.checks import default_checks
from roxy.abuse.checks.base import Check, Facts, LimitOutcome, LimitSpec, TxState, trio_headers
from roxy.abuse.checks.probe import probe_signature
from roxy.abuse.limiter import (
    LimiterRow,
    MemoryRowStore,
    RateDecision,
    cooldown,
    degraded_limit,
    fixed,
    gcra,
    load_rows,
    save_rows,
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
    peek_per_ip,
    save_strike_rows,
)
from roxy.abuse.verdict import Allow, Refuse, Verdict, raw_path, request_target
from roxy.core.client_ip import limit_key as compute_limit_key
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.reasons import ReasonCode
from roxy.rules.match import regex_budget
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

TX_BUSY_TIMEOUT_MS: Final = 500
"""How long the abuse transaction waits for another process's write lock before degrading (C7) instead."""
SPAM_FLUSH_INTERVAL_S: Final = 1.0
SWITCH_REFRESH_INTERVAL_S: Final = 1.0
BAN_HITS_FLUSH_INTERVAL_S: Final = 5.0
MAX_BACKGROUND_BANS: Final = 32
MAX_UA_HIT_RECORDS: Final = 200
MAX_TIER_RECORDS: Final = 32
PROBE_REASONS: Final = frozenset({ReasonCode.UNSAFE_URL, ReasonCode.NOT_ROBLOX, ReasonCode.HOST_NOT_ALLOWED})


@dataclass(slots=True)
class AbuseStats:
    """Per-worker counters for the Protection page (bounded); the metrics layer reads `snapshot()`."""

    evaluated: int = 0
    allowed: int = 0
    refusals: dict[str, int] = field(default_factory=dict)  # by check name
    ua_rule_hits: dict[str, list[int]] = field(default_factory=dict)  # rule id -> [allowed, refused]
    tier_hits: dict[int, int] = field(default_factory=dict)  # ladder rung -> new strikes reaching it
    degraded_requests: int = 0
    ladder_bans: int = 0

    def snapshot(self) -> dict[str, Any]:
        return {
            "evaluated": self.evaluated,
            "allowed": self.allowed,
            "refusals": dict(self.refusals),
            "ua_rule_hits": {k: {"allowed": v[0], "refused": v[1]} for k, v in self.ua_rule_hits.items()},
            "tier_hits": dict(self.tier_hits),
            "degraded_requests": self.degraded_requests,
            "ladder_bans": self.ladder_bans,
        }


@dataclass(slots=True)
class _Walk:
    state: TxState
    limiter_writes: list[LimiterRow]
    strike_writes: list[StrikeRow]


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
) -> _Walk:
    """Evaluate the limiters in order and decide what to write (pure; shared by hot.db and degraded mode).

    `divisor` > 1 divides every limit (degraded mode, plan C7). `refused_after` says a check after these limiters
    refuses the request anyway (a probe, a block): the admitted counts are then not committed either. See the
    module docstring for the commit rule.
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
            if divisor > 1:
                policy = replace(policy, limit=degraded_limit(policy.limit, divisor))
            srow = strikes.get(spec.key) or StrikeRow(spec.key)
            result = evaluate_per_ip(policy, row, srow, now_ms)
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
            limit = degraded_limit(spec.limit, divisor) if divisor > 1 else spec.limit
            decision = _decide(spec, row, limit, now_ms)
            outcome = LimitOutcome(
                spec, decision.admitted, decision.remaining, decision.reset_s, decision.retry_after_s, row=decision.row
            )
            if decision.admitted:
                (writes if spec.always_commit else pending).append(decision.row)
        outcomes[spec.check] = outcome
        if not outcome.admitted:
            refused_at = spec.check
            break
    if refused_at is None and not refused_after:
        writes.extend(pending)
    state = TxState(outcomes=outcomes, stopped_at=refused_at)
    if trio_policy is not None:
        policy = trio_policy if divisor <= 1 else replace(trio_policy, limit=degraded_limit(trio_policy.limit, divisor))
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
            state.trio = peek_per_ip(policy, rows.get(policy.key) or LimiterRow(policy.key), srow, now_ms)
            state.strikes = effective_strikes(srow.strikes, srow.last_strike_at, now_s, policy.decay_s)
    return _Walk(state, writes, strike_writes)


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
    ) -> None:
        self.settings = settings
        self.rules = rules
        self.hot_db = hot_db
        self.control_db = control_db
        self.clock = clock
        self.worker_id = worker_id
        self.workers = max(1, int(workers))
        self.recorder = recorder
        self.rules_service = rules_service
        self.monotonic = monotonic
        self.checks: list[Check] = sorted(checks or default_checks(), key=lambda check: check.position)
        self.switches = SwitchesCache(control_db)
        self.tarpit = Tarpit(settings, hot_db, clock, worker_id, sleep=tarpit_sleep, monotonic=monotonic, rng=rng)
        self.spam = SpamDetectors(
            settings, hot_db, clock, control_db=control_db, rules_service=rules_service, events=self._event
        )
        self.bot = ClientTracker()
        self.ban_hits = BanHits()
        self.challenge_key = challenge_key(ip_hash_key) if ip_hash_key else None
        self.stats = AbuseStats()
        self.degraded = False
        self._memory_rows: MemoryRowStore[LimiterRow] = MemoryRowStore()
        self._memory_strikes: MemoryRowStore[StrikeRow] = MemoryRowStore()
        self._background: set[asyncio.Task[Any]] = set()

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
        key = str(getattr(req, "limit_key", "") or "") or compute_limit_key(
            ip, int(values.get("ipv6_limit_prefix", 64))
        )
        ladder = ladder_from(rules.throttle_tiers)
        mode = str(values.get("throttle_window_mode", "gcra"))
        policy = PerIpPolicy(
            key=key,
            mode="fixed" if mode == "fixed" else "gcra",
            limit=max(1, int(values.get("allowed_requests_per_minute", 10))),
            window_s=max(1, int(values.get("throttle_reset_duration", 50))),
            escalation=bool(values.get("throttle_escalation_enabled", 1)),
            decay_s=max(0, int(values.get("throttle_strike_decay_seconds", 1800))),
            ladder=ladder,
            strike_on_retry=bool(values.get("throttle_strike_on_retry", 1)),
        )
        path = raw_path(req)
        cidrs = values.get("roblox_egress_cidrs") or ()
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

    # ---- the request path ----

    async def evaluate(self, req: Any) -> Verdict:
        """Decide one request (see the module docstring). Never raises for shared-state trouble (C7)."""
        values = self._values()
        rules = self._rules_snapshot()
        now = self.clock.now()
        now_ms = self.clock.now_ms()
        facts = self._facts(req, values, rules, now, now_ms)
        prepared: list[Check] = []
        specs: list[LimitSpec] = []
        static: tuple[str, Refuse] | None = None
        with regex_budget():  # every pattern match of this request shares one time budget (plan 9.9)
            for check in self.checks:
                if check.skipped_by_bypass and getattr(req, "bypass", False):
                    continue
                result = check.prepare(req, facts)
                prepared.append(check)
                if isinstance(result, Refuse):
                    static = (check.name, result)
                    break
                if isinstance(result, LimitSpec):
                    specs.append(result)
        tx = await self._transaction(specs, facts, bool(getattr(req, "bypass", False)), static is not None)
        tx.facts = facts
        if static is not None:
            tx.static[static[0]] = static[1]
        verdict: Verdict | None = None
        for check in prepared:
            refusal = await check.check(req, tx)
            if refusal is not None:
                verdict = refusal
                break
        if verdict is None:
            verdict = Allow(headers=trio_headers(tx))
        self._after(req, facts, tx, verdict)
        return verdict

    async def _transaction(
        self, specs: list[LimitSpec], facts: Facts, bypass: bool, refused_after: bool = False
    ) -> TxState:
        policy = None if bypass else facts.per_ip
        # v1: a bypass entry is never counted, so its headers always show the full allowance.
        bypass_trio = (facts.per_ip.limit if facts.per_ip is not None else 10, 0, False)
        if bypass and not specs:
            return TxState(trio=bypass_trio)
        if not specs:
            return await self._peek(policy, facts.now_ms)
        try:
            if self.hot_db is None:
                raise SharedStateUnavailable("hot", "no hot.db in this process")
            walk = await self.hot_db.write(
                lambda conn: self._tx(conn, specs, policy, facts.now_ms, refused_after),
                busy_timeout_ms=TX_BUSY_TIMEOUT_MS,
            )
            if self.degraded:
                self.degraded = False
                log.info("abuse_degraded_recovered")
                self._event("abuse_degraded_recovered", "info", {})
            state = walk.state
        except SharedStateUnavailable as exc:
            state = self._degraded_walk(specs, policy, facts.now_ms, exc, refused_after)
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
    ) -> _Walk:
        keys = [spec.key for spec in specs]
        if policy is not None:
            keys.append(policy.key)
        rows = load_rows(conn, keys)
        strikes = load_strike_rows(conn, [policy.key]) if policy is not None else {}
        walk = walk_limiters(specs, rows, strikes, policy, now_ms, refused_after=refused_after)
        save_rows(conn, walk.limiter_writes, now_ms // 1000)
        save_strike_rows(conn, walk.strike_writes)
        return walk

    def _degraded_walk(
        self,
        specs: list[LimitSpec],
        policy: PerIpPolicy | None,
        now_ms: int,
        exc: SharedStateUnavailable,
        refused_after: bool = False,
    ) -> TxState:
        """C7: the same decision on this worker's memory at `limit / workers`."""
        if not self.degraded:
            self.degraded = True
            log.warning(
                "abuse_degraded",
                extra={"fields": {"error": str(exc)[:200], "workers": self.workers, "mode": "limit / workers"}},
            )
            self._event("abuse_degraded", "critical", {"error": str(exc)[:200], "workers": self.workers})
        self.stats.degraded_requests += 1
        keys = [spec.key for spec in specs] + ([policy.key] if policy is not None else [])
        rows = {key: self._memory_rows.get(key) or LimiterRow(key) for key in keys}
        strikes: dict[str, StrikeRow] = {}
        if policy is not None:
            strikes[policy.key] = self._memory_strikes.get(policy.key) or StrikeRow(policy.key)
        walk = walk_limiters(specs, rows, strikes, policy, now_ms, divisor=self.workers, refused_after=refused_after)
        for row in walk.limiter_writes:
            self._memory_rows.put(row.key, row)
        for srow in walk.strike_writes:
            self._memory_strikes.put(srow.key, srow)
        walk.state.degraded = True
        return walk.state

    async def _peek(self, policy: PerIpPolicy | None, now_ms: int) -> TxState:
        """The trio for a refusal decided before any limiter ran (pause, ban): one read, no write."""
        if policy is None:
            return TxState()
        try:
            if self.hot_db is None:
                raise SharedStateUnavailable("hot", "no hot.db in this process")
            rows, strikes = await self.hot_db.read(
                lambda conn: (load_rows(conn, [policy.key]), load_strike_rows(conn, [policy.key]))
            )
        except SharedStateUnavailable:
            rows = {policy.key: self._memory_rows.get(policy.key) or LimiterRow(policy.key)}
            strikes = {policy.key: self._memory_strikes.get(policy.key) or StrikeRow(policy.key)}
        return walk_limiters([], rows, strikes, policy, now_ms).state

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
        per_ip = next((o.per_ip for o in tx.outcomes.values() if o.per_ip is not None), None)
        if per_ip is not None and per_ip.new_strike and per_ip.rung.index:
            tier = per_ip.rung.index
            if tier in stats.tier_hits or len(stats.tier_hits) < MAX_TIER_RECORDS:
                stats.tier_hits[tier] = stats.tier_hits.get(tier, 0) + 1
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

    # ---- admin and lifecycle ----

    def describe(self) -> list[dict[str, Any]]:
        """The pipeline for the Protection page diagram, in order."""
        return [check.describe() for check in self.checks]

    async def flush_ban_hits(self) -> int:
        if self.control_db is None:
            return 0
        return await self.ban_hits.flush(self.control_db)

    def start(self, tasks: Any) -> None:
        """Start the background loops on the worker's `TaskSupervisor`."""
        tasks.start("abuse_spam_flush", self.spam.flush, interval_s=SPAM_FLUSH_INTERVAL_S)
        tasks.start("abuse_switches", self.switches.refresh_if_changed, interval_s=SWITCH_REFRESH_INTERVAL_S)
        tasks.start("abuse_ban_hits", self.flush_ban_hits, interval_s=BAN_HITS_FLUSH_INTERVAL_S)

    async def aclose(self) -> None:
        """Shutdown: flush what is buffered (best effort) and wait briefly for background bans."""
        for flush in (self.spam.flush, self.flush_ban_hits):
            try:
                await flush()
            except Exception:
                log.exception("abuse_close_flush_failed")
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


__all__ = ["AbusePipeline", "AbuseStats", "Allow", "Refuse", "Verdict", "install", "walk_limiters"]
