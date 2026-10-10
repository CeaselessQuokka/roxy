"""Side effects of one finished upstream call, applied in one hot.db transaction (plan 6.3, 7.5, 7.9, 7.10).

What this is
    `apply_call_outcome(conn, facts, config, now_ms, rng)` updates the shared state after a call: the cooldown rows
    on a 429 (with host escalation and egress attribution), the circuit breakers, the half-open probe lease, the
    rotator's distinct-exit rule, and the AIMD slot. `should_record` says whether a call needs the transaction at
    all.

Why it exists
    Plan 6.3: "Breaker and cooldown updates happen after the response, in the same transaction as the bucket refund
    or adaptive rate update", so a request costs at most one extra write, and a plain success on a healthy endpoint
    costs none. Keeping the composition here, separate from the HTTP loop in `service.py`, lets the 7.9 side
    effects be tested row by row against a real hot.db without any network.

How it works
    - 429 through direct or the credential: cooldown `endpoint:<template>:<egress>` (length from `cooldowns`), the
      endpoint breaker trips for that long, the host breaker counts a failure, attribution (`adaptive.attribute`)
      may add `host:<host>:<egress>` or `egress:<egress>` cooldowns, and a credential 429 also opens the fleet-wide
      `credential` cooldown. The returned `CallEffects` tells the service whether this was the first 429 of the
      episode (the adaptive decrease trigger), how long callers must wait, and how many calls the endpoint and
      host buckets let through in the last minute (`observed`, read from their window meters: the adaptive cut
      starts from that rate).
    - 429 through the rotator: the exit is recorded; only when enough distinct exits failed within the window does
      the endpoint cool down and the breaker count it. The rotator's failure streak and parking (parity row 31:
      429s and 5xx count too) live in `egress/rotator.py` (`RotatorPool.record_result`), which sees every rotator
      call, so they are not counted twice here.
    - 5xx, timeouts, connect errors: breaker failures on the endpoint and host keys.
    - A normal answer: breaker successes (only where a failure window is open), and a cooldown until the reset
      time when `x-ratelimit-remaining` says 0 even on a 200 (plan 7.5).
    - The half-open probe (the call that held `brk:<key>`) closes or reopens its breaker and releases the lease.

What to read next
    `roxy/upstream/service.py` (`_after_call`), `roxy/upstream/cooldowns.py` and `roxy/upstream/breaker.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from roxy.core.reasons import Egress
from roxy.upstream import adaptive, aimd, breaker, buckets, cooldowns
from roxy.upstream.adaptive import Attribution, AttributionKind
from roxy.upstream.backoff import UniformSource
from roxy.upstream.breaker import BreakerPolicy, BreakerRow, Transition
from roxy.upstream.cooldowns import CooldownPolicy, CooldownSource, RateLimitInfo
from roxy.upstream.status import FAILURE_KINDS, SUCCESS_LIKE, AttemptKind

NEUTRAL_KINDS: Final = frozenset(
    {AttemptKind.LEAK_BLOCKED, AttemptKind.SMUGGLING_BLOCKED, AttemptKind.EGRESS_DISABLED, AttemptKind.TARGET_REFUSED}
)
"""Nothing reached Roblox: no breaker, cooldown or streak changes (a held probe lease is just released)."""


@dataclass(frozen=True, slots=True)
class CallFacts:
    """What happened on one call, as the service saw it."""

    egress: Egress
    host: str
    template: str
    kind: AttemptKind
    status: int | None = None
    retry_after_s: float | None = None
    ratelimit: RateLimitInfo | None = None
    exit_id: str | None = None  # the rotator session (one session = one exit IP)
    probe_keys: tuple[str, ...] = ()  # breaker keys whose half-open probe lease this call held
    holder: str = ""
    aimd_key: str | None = None
    aimd_slot: str | None = None


@dataclass(frozen=True, slots=True)
class EffectsConfig:
    cooldown: CooldownPolicy
    breaker: BreakerPolicy
    aimd: aimd.AimdPolicy | None = None


@dataclass(slots=True)
class CallEffects:
    """What `apply_call_outcome` changed, for the caller's answer, the adaptive controller and events."""

    cooldown_s: float | None = None  # how long callers should wait (Retry-After) after a 429
    cooldown_source: str = ""
    cooldown_keys: list[str] = field(default_factory=list)  # cooldown rows opened or extended
    first_in_episode: bool = False  # the endpoint was not cooling down before this 429
    counted_429: bool = False  # the 429 counted (always for direct and credential; rotator: distinct exits)
    distinct_exits: int | None = None
    attribution: Attribution | None = None
    transitions: list[Transition] = field(default_factory=list)
    aimd_limit: float | None = None
    observed: dict[str, float] = field(default_factory=dict)
    """After a direct or credential 429: calls Roxy made through the endpoint and host buckets in the last minute
    (their window meters), the rate Roblox refused, for the adaptive cut (finding LOAD-1)."""


def should_record(facts: CallFacts, breakers_seen: Mapping[str, BreakerRow], now_s: float) -> bool:
    """Whether this call changes shared state. False for a plain success on a healthy endpoint (no write)."""
    if facts.kind in FAILURE_KINDS or facts.probe_keys or facts.aimd_slot is not None:
        return True
    if facts.ratelimit is not None and facts.ratelimit.exhausted and facts.ratelimit.reset_s is not None:
        return True
    if facts.kind in SUCCESS_LIKE:
        for key in breaker.breaker_keys(facts.host, facts.template, facts.egress):
            row = breakers_seen.get(key)
            if row is not None and (row.failures > 0 or breaker.effective_state(row, now_s).value != "closed"):
                return True
    return False


def _open(
    conn: sqlite3.Connection,
    effects: CallEffects,
    key: str,
    seconds: float,
    source: CooldownSource,
    now_ms: int,
    policy: CooldownPolicy,
) -> cooldowns.OpenedCooldown:
    existing = cooldowns.read_rows(conn, [key]).get(key)
    opened = cooldowns.open_cooldown(
        conn, key, seconds, source, now_ms, cooldowns.repeat_count(existing, now_ms, policy)
    )
    effects.cooldown_keys.append(key)
    return opened


def apply_call_outcome(
    conn: sqlite3.Connection,
    facts: CallFacts,
    config: EffectsConfig,
    now_ms: int,
    rng: UniformSource,
) -> CallEffects:
    """Apply every shared-state side effect of one call. Run inside `ctx.dbs.hot.write`."""
    effects = CallEffects()
    now_s = now_ms / 1000
    kind = facts.kind
    egress = facts.egress
    endpoint_bkey, host_bkey = breaker.breaker_keys(facts.host, facts.template, egress)
    rows = breaker.load(conn, (endpoint_bkey, host_bkey))
    handled_probe: set[str] = set()

    def save(row: BreakerRow, transition: Transition | None) -> None:
        breaker.save(conn, row)
        rows[row.key] = row
        if transition is not None:
            effects.transitions.append(transition)

    if kind is AttemptKind.RATE_LIMITED:
        counted = True
        if egress is Egress.ROTATOR:
            exit_id = facts.exit_id or f"unknown:{now_ms}"  # no session id: every call is its own exit
            effects.distinct_exits = cooldowns.record_rotator_exit_429(
                conn, facts.template, exit_id, now_ms, config.cooldown.rotator_window_s
            )
            counted = effects.distinct_exits >= config.cooldown.rotator_distinct_exits
        effects.counted_429 = counted
        endpoint_ckey = cooldowns.endpoint_key(facts.template, egress)
        existing = cooldowns.read_rows(conn, [endpoint_ckey]).get(endpoint_ckey)
        repeat = cooldowns.repeat_count(existing, now_ms, config.cooldown)
        seconds, source = cooldowns.cooldown_duration(
            facts.retry_after_s, facts.ratelimit, repeat, config.cooldown, rng
        )
        effects.cooldown_s, effects.cooldown_source = seconds, source.value
        if counted:
            opened = cooldowns.open_cooldown(conn, endpoint_ckey, seconds, source, now_ms, repeat)
            effects.cooldown_keys.append(endpoint_ckey)
            effects.first_in_episode = not opened.was_active
            effects.cooldown_s = opened.row.remaining_s(now_ms)
            effects.cooldown_source = opened.row.source
            save(*breaker.trip(rows.get(endpoint_bkey), endpoint_bkey, now_s, effects.cooldown_s))
            handled_probe.add(endpoint_bkey)  # a 429 probe reopens through the trip, for the Retry-After duration
            if host_bkey not in facts.probe_keys:
                save(*breaker.record_failure(rows.get(host_bkey), host_bkey, now_s, config.breaker))
            if egress in (Egress.DIRECT, Egress.CREDENTIAL):
                attribution = adaptive.attribute(
                    conn,
                    facts.host,
                    facts.template,
                    egress,
                    now_s,
                    config.cooldown.host_escalation_window_s,
                    config.cooldown.host_escalation_endpoints,
                )
                effects.attribution = attribution
                effects.observed = buckets.observed_calls(
                    conn,
                    (buckets.endpoint_bucket_key(facts.template), buckets.host_bucket_key(facts.host)),
                    now_ms,
                )
                if attribution.kind is AttributionKind.HOST:
                    _open(
                        conn, effects, cooldowns.host_key(facts.host, egress), seconds, source, now_ms, config.cooldown
                    )
                elif attribution.kind is AttributionKind.EGRESS:
                    _open(conn, effects, cooldowns.egress_key(egress), seconds, source, now_ms, config.cooldown)
            if egress is Egress.CREDENTIAL:
                credential_row = cooldowns.read_rows(conn, [cooldowns.CREDENTIAL_KEY]).get(cooldowns.CREDENTIAL_KEY)
                credential_repeat = cooldowns.repeat_count(credential_row, now_ms, config.cooldown)
                credential_s, credential_source = cooldowns.cooldown_duration(
                    facts.retry_after_s, facts.ratelimit, credential_repeat, config.cooldown, rng, credential=True
                )
                cooldowns.open_cooldown(
                    conn, cooldowns.CREDENTIAL_KEY, credential_s, credential_source, now_ms, credential_repeat
                )
                effects.cooldown_keys.append(cooldowns.CREDENTIAL_KEY)
                effects.cooldown_s = max(effects.cooldown_s or 0.0, credential_s)
    elif kind in FAILURE_KINDS:
        for key in (endpoint_bkey, host_bkey):
            if key not in facts.probe_keys:
                save(*breaker.record_failure(rows.get(key), key, now_s, config.breaker))
    elif kind in SUCCESS_LIKE:
        for key in (endpoint_bkey, host_bkey):
            if key not in facts.probe_keys:
                updated = breaker.record_success(rows.get(key), now_s, config.breaker)
                if updated is not None:
                    save(updated, None)
        limit = facts.ratelimit
        if limit is not None and limit.exhausted and limit.reset_s is not None:
            # Roblox says the window is used up even though this call succeeded: stop before it says 429.
            opened = _open(
                conn,
                effects,
                cooldowns.endpoint_key(facts.template, egress),
                config.cooldown.clamp(limit.reset_s),
                CooldownSource.RATELIMIT_RESET,
                now_ms,
                config.cooldown,
            )
            effects.cooldown_s = opened.row.remaining_s(now_ms)
            effects.cooldown_source = opened.row.source

    # The half-open probe: its result closes or reopens the breaker; the lease is released either way.
    for key in facts.probe_keys:
        if kind not in NEUTRAL_KINDS and key not in handled_probe:
            failed = kind in FAILURE_KINDS and (kind is not AttemptKind.RATE_LIMITED or effects.counted_429)
            save(*breaker.probe_result(rows.get(key), key, now_s, failed, config.breaker))
        breaker.release_probe(conn, key, facts.holder)

    if facts.aimd_slot is not None and facts.aimd_key is not None and config.aimd is not None:
        ok: bool | None = None if kind in NEUTRAL_KINDS else kind not in FAILURE_KINDS
        effects.aimd_limit = aimd.release(conn, facts.aimd_key, facts.aimd_slot, facts.holder, ok, config.aimd, now_ms)
    return effects


__all__ = ["NEUTRAL_KINDS", "CallEffects", "CallFacts", "EffectsConfig", "apply_call_outcome", "should_record"]
