"""The shape every abuse check shares: `Check`, the per-request `Facts`, `LimitSpec` and the transaction result.

What this is
    `Check` (name, position, label, whether bypass skips it, its tarpit category, `prepare` and `check`), `Facts`
    (everything about one request computed once: the time, the settings and rules snapshots, the target, the per-IP
    policy), `LimitSpec` (what a limiter check asks the single hot.db transaction to evaluate), `LimitOutcome` and
    `TxState` (what that transaction decided), and the header helpers every refusal uses.

Why it exists
    DESIGN.md 7 asks for checks as objects with `name`, `position` and `async check(req, tx_state)`, and plan 6.3
    for ONE hot.db write per request for every limiter. Splitting each check into `prepare` (no I/O: decide, or say
    which limiter row to evaluate) and `check` (read the transaction's answer) gives both: the pipeline prepares in
    order, runs one transaction for all the limiters it collected, then asks each check in order for its verdict.

How it works
    - `prepare(req, facts)` returns None (nothing to do), a `Refuse` (a decision that needs no shared state: a
      ban, a probe, a block), or a `LimitSpec`. Preparing stops at the first `Refuse`: later checks cannot matter.
      A check that matches admin patterns (`uses_patterns`: User-Agent rules, header filters, endpoint blocks and
      rate rules, where an admin regex can cost up to the request's regex budget) may be prepared only after the
      cheap limiters before it admitted the request (see `roxy/abuse/pipeline.py`).
    - The pipeline evaluates the collected `LimitSpec`s in order inside one transaction and stores a `LimitOutcome`
      per check in `TxState.outcomes`; the static refusal sits in `TxState.static`.
    - `check(req, tx)` turns that into the final `Refuse` (adding the per-IP header trio) or None. The first check
      in position order that refuses decides the verdict. A disguised static refusal (a ban, a spam flag, a header
      filter without a message) is rendered again here with the client's real strikes and penalty, read by the
      transaction, so it carries exactly what a genuine throttle refusal for that client would carry right now.
    - Settings missing from the snapshot fall back to the catalog default (`Facts.setting`), never to a second,
      inline copy of the default.
    - Rule hits: a check whose decision rests on an admin rule row (an endpoint block, an endpoint rate rule, a
      header filter, a User-Agent rule, a bypass, deny list or ban entry) reports that row with
      `facts.note_match(table, row_id)` when it matches, whatever the verdict. The pipeline copies `facts.matches`
      onto the verdict (`Allow.matches`, `Refuse.matches`) and hands it to the metrics recorder in memory, so the
      hits ride on the single abuse transaction's request and cost no I/O of their own (FILTER-REMOVE,
      SEC-BYPASS-FOREVER, plan 10.9 per-rule hit counts). One match per table per request (each table has one
      winning row per request).

What to read next
    `roxy/abuse/checks/__init__.py` (the ordered list), then `roxy/abuse/pipeline.py` (the transaction).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from roxy.abuse.limiter import LimiterRow
from roxy.abuse.messages import throttle_fallback
from roxy.abuse.throttle import PerIpPolicy, PerIpResult, Rung, rung_for
from roxy.abuse.verdict import (
    FALSE,
    H_REFUSAL,
    H_REQUESTS_LEFT,
    H_RETRY_AFTER,
    H_THROTTLE_RESET,
    H_THROTTLED,
    TRUE,
    MessageSource,
    Refuse,
)
from roxy.core.reasons import ReasonCode
from roxy.core.scope import catalog_default
from roxy.rules.store import RulesSnapshot

Algo = Literal["gcra", "fixed", "cooldown", "per_ip"]

TABLE_ENDPOINT_BLOCK = "rules_endpoint_block"
TABLE_ENDPOINT_LIMIT = "rules_endpoint_limit"
TABLE_HEADER_RULE = "rules_header"
TABLE_UA_RULE = "rules_user_agent"
TABLE_ACCESS_LIST = "access_list"
TABLE_BANS = "bans"
MATCH_TABLES = (
    TABLE_ACCESS_LIST,
    TABLE_BANS,
    TABLE_UA_RULE,
    TABLE_HEADER_RULE,
    TABLE_ENDPOINT_BLOCK,
    TABLE_ENDPOINT_LIMIT,
)
"""The control.db tables whose rows the checks report as matched (`Facts.note_match`; `rules/models.py` names)."""


def live_setting(values: Mapping[str, Any], key: str) -> Any:
    """`values[key]`, or the catalog default when the snapshot lacks the key (never an inline second default)."""
    return values[key] if key in values else catalog_default(key)


@dataclass(slots=True)
class Facts:
    """One request's inputs, computed once by the pipeline (no I/O)."""

    now: float
    now_ms: int
    values: Mapping[str, Any]
    rules: RulesSnapshot
    services: Any  # the AbusePipeline (switches, spam, bot, ban hits, challenge key, workers)
    target: str
    path: str
    ip: str
    limit_key: str
    per_ip: PerIpPolicy | None
    ladder: tuple[Rung, ...]
    game_server: bool = False
    probe_signature: str | None = None
    score_cache: int | None = None
    pairs_cache: list[tuple[str, str]] | None = None
    matches: dict[str, str] = field(default_factory=dict)  # control.db table -> the row this request matched

    def note_match(self, table: str, row_id: Any, *, decisive: bool = False) -> None:
        """A rule row of `table` matched this request (module docstring, "Rule hits"). Memory only, no I/O.

        The first row noted for a table stays, unless a later one is `decisive` (it decided the verdict): a deny
        entry that refuses an address a bypass entry also covers is the access list row this request counts for.
        """
        if row_id is not None and (decisive or table not in self.matches):
            self.matches[table] = str(row_id)

    # `setting` and `flag` come first: below them `int`, `bool` and `str` name methods inside the class body.
    def setting(self, key: str) -> Any:
        """The live value, or the catalog default when the snapshot lacks the key (plan 15.1)."""
        return live_setting(self.values, key)

    def flag(self, key: str) -> bool:
        """A 0/1 switch read like `setting` (catalog default when missing)."""
        return bool(self.setting(key))

    def required(self, key: str) -> Any:
        """`setting`, but a key with no value at all (not in the snapshot, not in the catalog) raises KeyError.

        Every tunable lives in `config/catalog.py`, so a missing one is a bug to fix there, never a reason for a
        second, inline default here (plan P3, 15.1).
        """
        value = self.setting(key)
        if value is None:
            raise KeyError(f"{key} has no value: it is not a catalog setting")
        return value

    # The typed readers go through `required`: no call site passes (or can pass) its own default.
    def int(self, key: str) -> int:
        return int(self.required(key))

    def float(self, key: str) -> float:
        return float(self.required(key))

    def bool(self, key: str) -> bool:
        return bool(self.required(key))

    def str(self, key: str) -> str:
        return str(self.required(key))


@dataclass(slots=True)
class LimitSpec:
    """One limiter for the single hot.db transaction (see `roxy/abuse/pipeline.py`)."""

    check: str
    key: str
    algo: Algo
    limit: int = 1
    window_s: float = 60.0
    cooldown_s: float = 0.0
    always_commit: bool = False  # flood: counts every request it sees, even when a later check refuses
    per_ip: PerIpPolicy | None = None
    payload: Any = None  # the matched rule, for the refusal text


@dataclass(slots=True)
class LimitOutcome:
    """What one limiter decided (`per_ip` is set for the per-IP throttle)."""

    spec: LimitSpec
    admitted: bool
    remaining: int
    reset_s: int
    retry_after_s: int
    per_ip: PerIpResult | None = None
    row: LimiterRow | None = None


@dataclass(slots=True)
class TxState:
    """The single transaction's answers, plus the static refusal (if preparing stopped at one)."""

    outcomes: dict[str, LimitOutcome] = field(default_factory=dict)
    static: dict[str, Refuse] = field(default_factory=dict)
    trio: tuple[int, int, bool] = (0, 0, False)  # (requests left, reset seconds, throttled) for headers
    strikes: int = 0  # the client's current (decayed) strikes, for disguised bodies
    penalty_wait_ms: int = 0  # how long the client's current throttle penalty still runs (0: not penalized)
    degraded: bool = False
    stopped_at: str | None = None
    facts: Facts | None = None  # the request facts, for refusals that are rendered after the transaction


class Check:
    """Base class: override `prepare` (and `check` for limiter checks or refusals that need the transaction)."""

    name: str = "check"
    position: int = 0
    label: str = ""
    skipped_by_bypass: bool = False
    tarpit_category: str | None = None
    kind: Literal["static", "limiter", "marker"] = "static"
    uses_patterns: bool = False
    """True when `prepare` matches admin patterns (regex capable): deferred until the cheap limiters admit."""

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        return None

    async def check(self, req: Any, tx: TxState) -> Refuse | None:
        refusal = tx.static.get(self.name)
        if refusal is None:
            return None
        if refusal.disguised:
            return redisguise(refusal, tx)
        return with_trio(refusal, tx)

    def describe(self) -> dict[str, Any]:
        """For the Protection page pipeline diagram (plan 4.1 row 5)."""
        return {
            "name": self.name,
            "position": self.position,
            "label": self.label,
            "kind": self.kind,
            "skipped_by_bypass": self.skipped_by_bypass,
            "tarpit_category": self.tarpit_category,
            "uses_patterns": self.uses_patterns,
        }


# --- header helpers ---------------------------------------------------------------------------------------------------


def trio_headers(tx: TxState) -> dict[str, str]:
    """`Roxy-Requests-Left`, `Roxy-Throttle-Reset`, `Roxy-Throttled` from the transaction (plan 10.2, row 8)."""
    left, reset, throttled = tx.trio
    return {
        H_REQUESTS_LEFT: str(int(left)),
        H_THROTTLE_RESET: str(int(reset)),
        H_THROTTLED: TRUE if throttled else FALSE,
    }


def with_trio(refusal: Refuse, tx: TxState) -> Refuse:
    """v1 `_with_throttle_headers`: the trio first, then the refusal's own headers override it."""
    refusal.headers = {**trio_headers(tx), **refusal.headers}
    return refusal


def throttle_refusal_headers(retry_after_s: int, reset_s: int) -> dict[str, str]:
    """The headers of a per-IP throttle refusal, in the order a genuine one reaches the wire.

    One builder for the genuine refusal (`checks/throttle.py`, which then adds the trio with `with_trio`, whose
    keys come first) and every disguised one (`disguised_throttle`): a client reading raw headers (`curl -i`, any
    HTTP library) sees the order too, so the two must agree on order as well as on values (plan 10.5).
    """
    return {
        H_REQUESTS_LEFT: "0",
        H_THROTTLE_RESET: str(int(reset_s)),
        H_THROTTLED: TRUE,
        H_RETRY_AFTER: str(int(retry_after_s)),
        H_REFUSAL: ReasonCode.THROTTLE.value,
    }


def refusal_headers(reason: ReasonCode, **extra: str | int) -> dict[str, str]:
    """`Roxy-Refusal: <reason>` plus extra headers (keyword names use `_` for `-`, like v1's helper)."""
    headers = {name.replace("_", "-"): str(value) for name, value in extra.items()}
    headers[H_REFUSAL] = reason.value
    return headers


def disguised_throttle(
    facts: Facts,
    *,
    reason: ReasonCode,
    check: str,
    strikes: int = 0,
    penalty_wait_ms: int = 0,
    tarpit_category: str | None,
    detail: str,
) -> Refuse:
    """A refusal that looks exactly like an ordinary per-IP throttle refusal (header filters, bans, spam flags).

    v1's disguised header filter: the rung message for the client's current strikes (rung 1 for a clean client), or
    the plain fallback text, with `Retry-After` and `Roxy-Throttle-Reset` equal to `throttle_reset_duration`.
    v2 also sends `Roxy-Requests-Left: 0` and `Roxy-Refusal: throttle`, exactly what a genuine throttle refusal
    carries, in the same order (`throttle_refusal_headers`), so nothing in the response tells the client which rule
    caught it. A client whose throttle penalty is still running (`penalty_wait_ms`) is told the time left on it, as
    a genuine refusal would tell it right now.
    """
    window = max(1, facts.int("throttle_reset_duration"))
    retry, reset = window, window
    if penalty_wait_ms > 0:
        # The same rounding as `throttle.evaluate_per_ip` uses for a client that is still penalized.
        retry, reset = max(1, math.ceil(penalty_wait_ms / 1000)), max(1, penalty_wait_ms // 1000)
    rung = rung_for(facts.ladder, max(1, strikes))
    text = rung.message.strip()
    source: MessageSource = "custom" if text else "default"
    if not text:
        text = throttle_fallback(reset, facts.int("allowed_requests_per_minute"))
    return Refuse(
        status=429,
        body=text,
        reason=reason,
        check=check,
        headers=throttle_refusal_headers(retry, reset),
        tarpit_category=tarpit_category,
        disguised=True,
        message_source=source,
        detail=detail,
    )


def redisguise(refusal: Refuse, tx: TxState) -> Refuse:
    """A disguised refusal rendered again with the client's real strikes and penalty, read by the transaction.

    Prepared refusals are built before the transaction runs, so they cannot know the client's ladder rung; this
    is the same final step for every disguised refusal (bans, the deny list, spam flags, header filters).
    """
    if tx.facts is None:
        return refusal  # no transaction facts (a test calling `check` directly): the prepared form stands
    return disguised_throttle(
        tx.facts,
        reason=refusal.reason,
        check=refusal.check,
        strikes=tx.strikes,
        penalty_wait_ms=tx.penalty_wait_ms,
        tarpit_category=refusal.tarpit_category,
        detail=refusal.detail,
    )


__all__ = [
    "MATCH_TABLES",
    "TABLE_ACCESS_LIST",
    "TABLE_BANS",
    "TABLE_ENDPOINT_BLOCK",
    "TABLE_ENDPOINT_LIMIT",
    "TABLE_HEADER_RULE",
    "TABLE_UA_RULE",
    "Algo",
    "Check",
    "Facts",
    "LimitOutcome",
    "LimitSpec",
    "TxState",
    "disguised_throttle",
    "live_setting",
    "redisguise",
    "refusal_headers",
    "throttle_refusal_headers",
    "trio_headers",
    "with_trio",
]
