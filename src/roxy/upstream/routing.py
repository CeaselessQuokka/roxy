"""Routing: which egress path one upstream attempt uses (plan 7.2). Pure functions, no I/O.

What this is
    `decide(route, states, rng)` picks `credential`, `direct` or `rotator` for one attempt (or none, with the 7.13
    reason and a `Retry-After`), from a description of the request (`RouteRequest`) and a snapshot of each egress's
    availability (`EgressAvailability`: enabled, cooldown, breaker, bucket wait, bucket fill).

Why it exists
    v1 sent 75 % of all traffic with the operator's cookie to any Roblox URL with any verb (plan 2.4, critical),
    picked a method at random, and fell through to the other method on failures. v2 rules (plan 7.2, D1, D13, C2):
    the credential is used ONLY for an endpoint on the credential allowlist, only for GET or HEAD, and only while it
    is active and not cooling down; everything else is anonymous, from the server IP (`direct`) by default, through
    the rotator only when direct cannot serve or a routing rule prefers it. A property test
    (`test_routing_never_selects_credential_for_non_allowlisted`, plan 19.5 item 6) checks the first rule over
    random inputs.

How it works, in the order of plan 7.2
    1. Credential: eligible when the request matched an allowlist row, the method is GET or HEAD, and the
       credential is not excluded. If it is usable and its buckets can grant in time, use it. If not, an
       allowlisted endpoint is NEVER sent anonymously instead (plan 6.9), unless the row says
       `identical_anonymous=1`; the answer is `credential_unavailable` (503) or `upstream_busy` (429).
       A non-allowlisted request never even considers the credential: it is not among the candidates.
    2. A routing rule (`prefer_direct`, `prefer_rotator`, `direct_only`, `rotator_only`) is honored within
       availability.
    3. An anonymous egress is available when it is enabled, has no active cooldown, its breaker admits a call, and
       its buckets can grant a slot within the queue budget. A cooldown or open breaker is never waited out:
       during a cooldown Roxy does not contact that endpoint through that egress at all (plan 7.5).
    4. Without a rule, draw by `direct_weight` (100) and `rotator_weight` (0). When the direct bucket is fuller
       than `direct_shift_threshold_pct` (80 %), weight moves linearly toward the rotator (the successor of v1's
       "danger zone"). A weight of 0 never wins the draw while the other has weight, but an egress that is the
       only one available is still used (v1 semantics), which is how the rotator takes over when direct cools down.
    5. Nothing available: `egress_disabled` when every candidate is switched off, otherwise the reason of the
       candidate that frees up soonest (`upstream_cooldown` for a cooldown or open breaker, `upstream_busy` for a
       bucket) with `Retry-After` equal to that time.

What to read next
    `roxy/upstream/buckets.py` (the bucket waits fed into this), `roxy/upstream/service.py` (`_route_once`, which
    builds the inputs), and `roxy/rules/store.py` (`credential_rule_for`, `routing_rule_for`).
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from roxy.core.reasons import AuthClass, Egress, ReasonCode

CREDENTIAL_METHODS: Final = frozenset({"GET", "HEAD"})
ANONYMOUS_EGRESSES: Final[tuple[Egress, ...]] = (Egress.DIRECT, Egress.ROTATOR)
ROUTING_MODES: Final = frozenset({"prefer_direct", "prefer_rotator", "direct_only", "rotator_only"})


class ChoiceSource(Protocol):
    """`random.Random` (or the `random` module): only `choices` is used."""

    def choices(self, population: Sequence[Any], weights: Sequence[float], *, k: int = 1) -> list[Any]: ...


@dataclass(frozen=True, slots=True)
class EgressAvailability:
    """What one egress can do for this request right now."""

    egress: Egress
    enabled: bool = True
    disabled_reason: str = ""
    cooldown_s: float = 0.0  # remaining cooldown on any key that blocks this call (0 = none)
    cooldown_source: str = ""
    breaker_wait_s: float = 0.0  # time until an open breaker admits a probe (0 = admits now)
    bucket_wait_s: float = 0.0  # time until every bucket of this egress allows a call
    fill: float = 0.0  # used share of this egress's own bucket (0.0 to 1.0), for the direct shift

    def blocked_by(self, max_wait_s: float) -> str | None:
        """None when usable within `max_wait_s`; else "disabled", "cooldown", "breaker" or "bucket"."""
        if not self.enabled:
            return "disabled"
        if self.cooldown_s > 0:
            return "cooldown"
        if self.breaker_wait_s > 0:
            return "breaker"
        if self.bucket_wait_s > max_wait_s:
            return "bucket"
        return None

    @property
    def wait_s(self) -> float:
        """When this egress could take a call (ignoring the queue budget)."""
        return max(self.cooldown_s, self.breaker_wait_s, self.bucket_wait_s)


@dataclass(frozen=True, slots=True)
class CredentialRule:
    """The parts of a `credential_allowlist` row that routing needs (see `rules/models.py`)."""

    rule_id: int
    cache_private: bool
    identical_anonymous: bool

    @classmethod
    def from_row(cls, row: Any) -> CredentialRule:
        return cls(int(row.id), bool(row.cache_private), bool(row.identical_anonymous))


@dataclass(frozen=True, slots=True)
class RouteRequest:
    """Everything about the request and the settings that routing needs."""

    method: str
    credential_rule: CredentialRule | None = None  # the allowlist row the request matched (None: not allowlisted)
    credential_usable: bool = False  # credential enabled, active, not cooling down (checked by the caller)
    credential_rejected: bool = False
    credential_cooldown_s: float = 0.0  # the credential manager's own cooldown (it may know one hot.db does not)
    routing_mode: str | None = None  # the matching routing rule's mode
    direct_weight: float = 100.0
    rotator_weight: float = 0.0
    shift_threshold_pct: float = 80.0
    max_wait_s: float = 4.0  # what is left of the queue budget for this request's priority class
    exclude: frozenset[Egress] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """The chosen egress (and fallbacks to try if its reservation races), or why there is none."""

    egress: Egress | None
    candidates: tuple[Egress, ...] = ()  # usable egresses in preference order, `egress` first
    reason: ReasonCode | None = None  # set when `egress` is None
    retry_after_s: float | None = None
    cooldown_source: str = ""
    auth_class: AuthClass = AuthClass.ANON
    note: str = ""


def credential_eligible(route: RouteRequest) -> bool:
    """Plan 7.2 step 1: only an allowlisted endpoint, only GET or HEAD, only when not excluded."""
    return (
        route.credential_rule is not None
        and route.method.upper() in CREDENTIAL_METHODS
        and Egress.CREDENTIAL not in route.exclude
    )


def shifted_weights(
    direct_weight: float, rotator_weight: float, direct_fill: float, threshold_pct: float, rotator_ok: bool
) -> tuple[float, float]:
    """Direct and rotator weights after the fill shift (v1 `_weights` with the fill as a percentage)."""
    direct, rotator = max(0.0, direct_weight), max(0.0, rotator_weight)
    fill_pct = direct_fill * 100
    if rotator_ok and fill_pct > threshold_pct and threshold_pct < 100:
        progress = min(1.0, (fill_pct - threshold_pct) / (100 - threshold_pct))  # 0 at the threshold, 1 when full
        freed = direct * progress
        direct, rotator = direct - freed, rotator + freed
    return direct, rotator


def _blocked_answer(states: Sequence[EgressAvailability], max_wait_s: float) -> RouteDecision:
    """Step 5: no candidate is usable. Pick the reason of the one that frees up soonest."""
    enabled = [state for state in states if state.enabled]
    if not enabled:
        return RouteDecision(None, reason=ReasonCode.EGRESS_DISABLED, retry_after_s=60.0, note="all egress disabled")
    soonest = min(enabled, key=lambda state: state.wait_s)
    cause = soonest.blocked_by(max_wait_s)
    if cause in {"cooldown", "breaker"}:
        return RouteDecision(
            None,
            reason=ReasonCode.UPSTREAM_COOLDOWN,
            retry_after_s=soonest.wait_s,
            cooldown_source=soonest.cooldown_source or ("breaker" if cause == "breaker" else ""),
            note=f"{soonest.egress.value} {cause}",
        )
    return RouteDecision(
        None, reason=ReasonCode.UPSTREAM_BUSY, retry_after_s=soonest.wait_s, note=f"{soonest.egress.value} busy"
    )


def _credential_decision(route: RouteRequest, state: EgressAvailability | None) -> RouteDecision | None:
    """Step 1 for an eligible request: the credential, a refusal, or None (fall through to anonymous)."""
    usable = route.credential_usable and state is not None
    if usable and state is not None:
        blocked = state.blocked_by(route.max_wait_s)
        if blocked is None:
            return RouteDecision(Egress.CREDENTIAL, (Egress.CREDENTIAL,), auth_class=AuthClass.CRED, note="allowlisted")
    else:
        blocked = "unavailable"
    rule = route.credential_rule
    if rule is not None and rule.identical_anonymous:
        return None  # CRED-UNUSED evidence: the anonymous answer is identical, so anonymous is allowed
    if blocked == "bucket" and state is not None:
        return RouteDecision(
            None, reason=ReasonCode.UPSTREAM_BUSY, retry_after_s=state.bucket_wait_s, note="credential bucket busy"
        )
    if blocked == "breaker" and state is not None:
        return RouteDecision(
            None,
            reason=ReasonCode.UPSTREAM_COOLDOWN,
            retry_after_s=state.breaker_wait_s,
            cooldown_source="breaker",
            note="credential breaker open",
        )
    cooldown = max(state.cooldown_s if state is not None else 0.0, route.credential_cooldown_s)
    return RouteDecision(
        None,
        reason=ReasonCode.CREDENTIAL_UNAVAILABLE,
        retry_after_s=cooldown if cooldown > 0 else None,
        cooldown_source=state.cooldown_source if state is not None else "",
        note="credential rejected" if route.credential_rejected else "credential unavailable",
    )


def decide(
    route: RouteRequest,
    states: Mapping[Egress, EgressAvailability],
    rng: ChoiceSource | None = None,
) -> RouteDecision:
    """Choose the egress for one attempt (plan 7.2). See the module docstring for the steps."""
    rule = route.credential_rule
    if rule is not None and route.method.upper() in CREDENTIAL_METHODS:
        if Egress.CREDENTIAL in route.exclude:
            # The credential refused this request already (disabled, rejected, cooling down at send time). An
            # allowlisted endpoint still never goes out anonymously instead (plan 6.9), unless identical_anonymous.
            if not rule.identical_anonymous:
                return RouteDecision(
                    None, reason=ReasonCode.CREDENTIAL_UNAVAILABLE, note="credential unavailable at send time"
                )
        else:
            chosen = _credential_decision(route, states.get(Egress.CREDENTIAL))
            if chosen is not None:
                return chosen

    # Anonymous routing. The credential is not a candidate here, whatever the inputs say.
    pool = [egress for egress in ANONYMOUS_EGRESSES if egress not in route.exclude]
    mode = route.routing_mode if route.routing_mode in ROUTING_MODES else None
    if mode == "direct_only":
        pool = [egress for egress in pool if egress is Egress.DIRECT]
    elif mode == "rotator_only":
        pool = [egress for egress in pool if egress is Egress.ROTATOR]
    candidate_states = [states.get(egress, EgressAvailability(egress, enabled=False)) for egress in pool]
    if not candidate_states:
        return RouteDecision(None, reason=ReasonCode.EGRESS_DISABLED, retry_after_s=60.0, note="no candidate egress")
    usable = [state for state in candidate_states if state.blocked_by(route.max_wait_s) is None]
    if not usable:
        return _blocked_answer(candidate_states, route.max_wait_s)

    order: list[Egress]
    if mode == "prefer_rotator":
        order = sorted((s.egress for s in usable), key=lambda e: 0 if e is Egress.ROTATOR else 1)
    elif mode in {"prefer_direct", "direct_only", "rotator_only"} or len(usable) == 1:
        order = sorted((s.egress for s in usable), key=lambda e: 0 if e is Egress.DIRECT else 1)
    else:
        direct_state = next(s for s in usable if s.egress is Egress.DIRECT)
        direct_w, rotator_w = shifted_weights(
            route.direct_weight, route.rotator_weight, direct_state.fill, route.shift_threshold_pct, rotator_ok=True
        )
        weights = [direct_w, rotator_w]
        if sum(weights) <= 0:
            weights = [1.0, 1.0]  # v1: all weights zero means a fair draw
        source: ChoiceSource = rng if rng is not None else random.Random()
        first = source.choices([Egress.DIRECT, Egress.ROTATOR], weights=weights, k=1)[0]
        order = [first, Egress.ROTATOR if first is Egress.DIRECT else Egress.DIRECT]
    note = f"rule {mode}" if mode else ("weighted" if len(order) > 1 else "only available")
    return RouteDecision(order[0], tuple(order), auth_class=AuthClass.ANON, note=note)


__all__ = [
    "ANONYMOUS_EGRESSES",
    "CREDENTIAL_METHODS",
    "ROUTING_MODES",
    "ChoiceSource",
    "CredentialRule",
    "EgressAvailability",
    "RouteDecision",
    "RouteRequest",
    "credential_eligible",
    "decide",
    "shifted_weights",
]
