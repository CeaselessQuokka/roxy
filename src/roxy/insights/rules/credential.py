"""The credential rules of plan 11.5: CRED-EXPIRING, CRED-UNUSED, CRED-ROTATOR-GUARD and CRED-PROBE-COST.

What this is
    Four recommendation rules about the one Roblox credential (plan C1, C2): the credential is rejected, mismatched
    or being rotated by Roblox; an allowlisted endpoint answers the same without it; the leak guard caught the
    credential on an anonymous egress; and Roxy's own credential checks spend too much of the account's budget.

Why it exists
    The credential is the riskiest thing Roxy holds (plan 1, P1). These rules make its trouble visible within a
    run, and they are deliberately conservative: Roxy never replaces, switches or disables the credential by itself
    (C1), so CRED-EXPIRING and CRED-ROTATOR-GUARD only ever propose a manual step, CRED-UNUSED proposes removing an
    allowlist entry (less account exposure, never more), and CRED-PROBE-COST proposes fewer probes, never none.

How it works
    - Probe history is the `credential_probe` events (`egress/credential.py`: `{kind, result, status}` per probe),
      read only after the current credential was set (`credential_meta.set_at`), so a rejection of a replaced
      cookie says nothing about the new one; a rate-limited probe (429) is not a rejection.
    - Leak guard trips are counted from every record the egress module and the proxy leave: `leak_blocked` (and
      the provisional `leak_guard`) events, `leak_blocked` outcomes in the rollups, and the fleet-wide
      `egress_disabled:<egress>` rows of control.db (`egress/read_state.py leak_trips`).
    - Credential comparisons come from `insights/providers_rules_cache_egress.py credential_comparisons`.
    - CRED-PROBE-COST counts `internal_call` events made with the credential in the last hour, by trigger.
    - Thresholds come from `self.param(ctx, ...)`, or for CRED-PROBE-COST from its ordinary setting
      `insight_cred_probe_cost_max_per_hour` (15.3 J); the module constants are fixed choices the plan leaves open.

What to read next
    `roxy/egress/credential.py` (status, probes, rotation), `roxy/egress/clients.py` (the leak guard trip),
    `tests/fixtures/insights/cred_*.yaml`.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any, Final

from roxy.config import catalog
from roxy.insights import providers_rules_cache_egress as extra
from roxy.insights.context import InsightContext
from roxy.insights.models import Evidence, ProposedChange, Recommendation
from roxy.insights.rules.base import Rule, register
from roxy.insights.rules.cache import MAX_EVIDENCE_ROWS

CREDENTIAL_LINK: Final = "/admin/credential#status"
DAY_S: Final = 86_400
HOUR_S: Final = 3600
MINUTES_PER_HOUR: Final = 60

WARNING_LOOKBACK_DAYS: Final = 30
"""CRED-EXPIRING: probes and rotation warnings are read since the credential was set, at most this many days back
(a bound on the read; Roblox cookies live for weeks)."""
REJECTED_STATUSES: Final = frozenset({401, 403})
"""Plan 11.5 CRED-EXPIRING: "Probe 401/403"."""
MISMATCH: Final = "account_mismatch"
"""A probe that saw another account (plan C1: a different account is an account switch)."""
REJECTED: Final = "rejected"
WARNING_EVENTS: Final[tuple[str, ...]] = ("credential_rotated",)
"""Account warnings Roxy detects in a Roblox response: a replacement credential cookie (`egress/credential.py`)."""
COMPARISON_WINDOW_H: Final = 24
"""CRED-UNUSED: comparison events of the last day count (11.5 gives the row no window)."""
TRIP_LOOKBACK_H: Final = 24
"""CRED-ROTATOR-GUARD: trips of the last day, plus every egress still disabled by a trip."""
TRIP_EVENTS: Final[tuple[str, ...]] = ("leak_blocked", "leak_guard")
"""Event types of a leak guard trip: `leak_blocked` as `egress/clients.py` records it, and `leak_guard`, the
provisional name of the fixture README."""
LEAK_REASON: Final = "leak_blocked"
PROBE_COST_WINDOW_S: Final = HOUR_S
"""CRED-PROBE-COST: "in an hour" is the last 60 minutes."""
SCHEDULED: Final = "scheduled"
HEALTH: Final = "health"
ADMIN: Final = "admin"
UNRECORDED: Final = "unrecorded"
"""The trigger of a credential call recorded without one (`upstream/service.py` does not pass it yet)."""


def _probe_rejected(detail: Mapping[str, Any]) -> bool:
    """A probe answer that means the credential no longer works (401 or 403) or belongs to another account."""
    result = str(detail.get("result") or "")
    try:
        status = int(detail.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    return status in REJECTED_STATUSES or result.startswith(REJECTED) or result == MISMATCH


# ------------------------------------------------------------------------------------------------ CRED-EXPIRING


@register
class CredExpiring(Rule):
    """The Roblox credential is rejected, belongs to another account, or Roblox is replacing it.

    Fires when the newest credential probe since the credential was set was answered 401 or 403 (or saw another
    account), when the credential's status is `rejected`, or when Roblox sent a replacement credential cookie
    (which Roxy never stores). A rate-limited probe (429) is not a rejection, and history from before the current
    credential was set is ignored. The only change is manual: renew the credential on the Credential page. Roxy
    never switches or replaces the credential by itself (plan C1).
    """

    id = "CRED-EXPIRING"
    safe_auto = False
    triggers = frozenset({"credential_status"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        meta = await ctx.credential_meta()
        if meta is None:
            return []  # no credential configured (H-CRED-PRESENT reports that)
        set_at = float(meta.get("set_at") or 0)
        since = max(set_at, ctx.now - WARNING_LOOKBACK_DAYS * DAY_S)
        window = ctx.window(seconds=max(1.0, ctx.now - since))
        probes = [p for p in await ctx.events(["credential_probe"], window) if p["at_ms"] >= set_at * 1000]
        warnings = [w for w in await ctx.events(WARNING_EVENTS, window) if w["at_ms"] >= set_at * 1000]
        latest = probes[-1] if probes else None
        latest_rejected = latest is not None and _probe_rejected(latest["detail"])
        status = str(meta.get("status") or "")
        status_rejected = status == REJECTED and float(meta.get("status_at") or 0) >= set_at
        if not (latest_rejected or status_rejected or warnings):
            return []
        rejected = sum(1 for p in probes if _probe_rejected(p["detail"]))
        evidence = Evidence(
            window_from=window.start, window_to=window.end, sample_size=max(1, len(probes) + len(warnings))
        )
        evidence.add("probes_since_set", len(probes), "probes")
        evidence.add("rejected_probes", rejected, "probes")
        evidence.add("rotation_warnings", len(warnings), "events")
        evidence.details["status"] = status
        evidence.details["set_at"] = extra.utc_text(set_at) if set_at else None
        evidence.details["probes"] = [
            {
                "at": extra.utc_text(p["at_ms"] / 1000),
                "kind": p["detail"].get("kind"),
                "status": p["detail"].get("status"),
                "result": p["detail"].get("result"),
            }
            for p in probes[-MAX_EVIDENCE_ROWS:]
        ]
        if warnings:
            evidence.details["last_rotation_warning"] = extra.utc_text(warnings[-1]["at_ms"] / 1000)
        evidence.links.append(CREDENTIAL_LINK)
        if latest_rejected or status_rejected:
            what = latest["detail"] if latest_rejected and latest is not None else (meta.get("last_probe_result") or {})
            result = str((what or {}).get("result") or REJECTED)
            if result == MISMATCH:
                problem = "the last check saw a different Roblox account than the one this credential was set for"
            else:
                problem = f"Roblox rejected it (last check: {result})"
            title = "The Roblox credential is rejected: renew it"
            severity = "critical"
            impact = "Allowlisted credential endpoints and the credential checks work again."
            explanation = (
                f"The credential set on {evidence.details['set_at'] or 'an unknown date'} no longer works: {problem}. "
                f"Of {len(probes)} checks since it was set, {rejected} failed. Roxy has stopped using it and never "
                "switches to another account by itself (plan C1). Paste a fresh credential on the Credential page."
            )
        else:
            title = "Roblox is replacing the credential cookie: renew it"
            severity = "warn"
            impact = "Allowlisted credential endpoints and the credential checks keep working after Roblox retires it."
            explanation = (
                f"Roblox sent a replacement credential cookie {extra.counted(len(warnings), 'time')} since the "
                "credential was set "
                f"(last at {evidence.details['last_rotation_warning']}). Roxy does not store it (plan C1), so the "
                "stored cookie will stop working when Roblox retires it. Paste the new value on the Credential page "
                "when you have checked it is the same account."
            )
        return [
            self.recommendation(
                ctx,
                subject=f"credential set {int(set_at)}",
                title=title,
                severity=severity,
                confidence="high",
                explanation=explanation,
                evidence=evidence,
                changes=[
                    ProposedChange(
                        "manual", text="Renew the Roblox credential on the Credential page (never automatic)."
                    )
                ],
                expected_impact=impact,
                risk="low",
            )
        ]


# ------------------------------------------------------------------------------------------------- CRED-UNUSED


@register
class CredUnused(Rule):
    """An endpoint on the credential allowlist answers the same without the credential.

    For each enabled credential allowlist row, counts the side-by-side comparisons of the same request on the
    anonymous path and on the credential path (the comparison producer's events of the last day, plus what a
    provider supplies). With at least `min_comparisons` comparisons of which at least `identical_pct` percent
    returned the same body, it proposes removing that row: every credential call is account exposure (plan D1),
    and an endpoint that does not need the login should not carry it. Rows whose anonymous answers differ stay.
    """

    id = "CRED-UNUSED"
    safe_auto = False  # the allowlist is a credential setting (plan 11.4: auto-apply never touches the credential)

    def minimum_evidence(self, ctx: InsightContext) -> int:
        return self.int_param(ctx, "min_comparisons")

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        rows = [row for row in ctx.rules.credential_allowlist if row.enabled]
        if not rows:
            return []
        window = ctx.window(hours=COMPARISON_WINDOW_H)
        comparisons = await extra.credential_comparisons(ctx, window)
        per_row: dict[int, list[dict[str, Any]]] = {}
        for item in comparisons:
            template = str(item.get("endpoint_template") or "")
            method = str(item.get("method") or "GET").upper()
            row = ctx.rules.credential_rule_for(template, method) if template else None
            if row is not None and row.enabled:
                per_row.setdefault(int(row.id), []).append(item)
        minimum = self.param(ctx, "min_comparisons")
        needed = self.param(ctx, "identical_pct")
        out: list[Recommendation] = []
        calls: dict[int, int] | None = None
        for row in sorted(rows, key=lambda r: int(r.id)):
            items = per_row.get(int(row.id), [])
            total = sum(int(i.get("count") or 1) for i in items)
            same = sum(int(i.get("count") or 1) for i in items if bool(i.get("identical")))
            if total <= 0 or total < minimum or same * 100.0 < needed * total:
                continue
            if calls is None:
                calls = await self._credential_calls(ctx, window)
            out.append(self._recommend(ctx, window, row, items, total, same, calls.get(int(row.id), 0)))
        return out

    @staticmethod
    async def _credential_calls(ctx: InsightContext, window: Any) -> dict[int, int]:
        """Upstream calls made with the credential in the window, per allowlist row (rollups, `auth_class` cred)."""
        out: dict[int, int] = {}
        for template, row in (await ctx.by_template(window, {"auth_class": "cred"})).items():
            allowed = ctx.rules.credential_rule_for(str(template), "GET")
            if allowed is not None:
                out[int(allowed.id)] = out.get(int(allowed.id), 0) + int(row.get("upstream_calls") or 0)
        return out

    def _recommend(
        self,
        ctx: InsightContext,
        window: Any,
        row: Any,
        items: Sequence[Mapping[str, Any]],
        total: int,
        same: int,
        calls: int,
    ) -> Recommendation:
        statuses: dict[str, int] = {}
        for item in items:
            pair = f"{item.get('anon_status')}/{item.get('cred_status')}"
            statuses[pair] = statuses.get(pair, 0) + int(item.get("count") or 1)
        hours = round((window.end - window.start) / 3600)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=total)
        evidence.add("comparisons", total, "comparisons")
        evidence.add("identical_answers", same, "comparisons")
        evidence.add("identical_pct", round(same * 100.0 / total, 2), "percent")
        evidence.add("credential_calls", calls, "calls")
        evidence.details["anon_cred_status_pairs"] = statuses
        evidence.links.append("/admin/credential#allowlist")
        current = {
            "id": int(row.id),
            "pattern": row.pattern,
            "type": row.type,
            "methods": ",".join(row.methods),
            "cache_private": bool(row.cache_private),
            "identical_anonymous": bool(row.identical_anonymous),
            "note": row.note,
        }
        evidence.details["allowlist_row"] = current
        return self.recommendation(
            ctx,
            subject=row.pattern,
            title=f"{row.pattern} works without the credential: remove it from the allowlist",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In {total:,} side-by-side comparisons, {same:,} anonymous answers for {row.pattern} were identical "
                f"to the credential's ({same * 100.0 / total:.0f}%). Every call that carries the credential is account "
                "exposure (plan D1), so an endpoint that answers the same without it should not be on the allowlist. "
                "Removing the row sends these calls anonymously; the credential itself is untouched."
            ),
            evidence=evidence,
            changes=[
                ProposedChange(
                    "credential_allowlist_remove",
                    table="credential_allowlist",
                    match={"id": int(row.id), "pattern": row.pattern, "type": row.type},
                    current=current,
                    proposed=None,
                )
            ],
            expected_impact=(
                f"Calls to {row.pattern} stop carrying the credential: {calls:,} calls in the last {hours} hours went "
                "out with it."
            ),
            risk="low",
        )


# ------------------------------------------------------------------------------------------ CRED-ROTATOR-GUARD


@register
class CredRotatorGuard(Rule):
    """The credential leak guard blocked a request (the credential nearly left on an anonymous egress).

    Fires on any trip: a `leak_blocked` event or outcome in the last day, or an egress the guard has disabled and
    nobody re-enabled yet. A trip means some code path put the credential on the rotator or the direct client;
    only a code investigation fixes it (plan C2), so the change is manual and the severity critical. Callers who
    send their own cookie are refused by the auth smuggling check and do not count.
    """

    id = "CRED-ROTATOR-GUARD"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(hours=TRIP_LOOKBACK_H)
        events = await ctx.events(TRIP_EVENTS, window)
        totals = await ctx.totals(window, {"reason_code": LEAK_REASON})
        blocked = int(totals.get("requests") or 0)
        disabled = await extra.leak_trips(ctx)
        per: dict[str, dict[str, Any]] = {}
        for event in events:
            detail = event.get("detail") or {}
            egress = str(detail.get("egress") or "unknown")
            slot = per.setdefault(
                egress, {"trips": 0, "last_ms": 0, "requests": [], "locations": set(), "callers": set()}
            )
            slot["trips"] += int(event.get("count") or 1)
            slot["last_ms"] = max(slot["last_ms"], int(event["at_ms"]))
            if detail.get("request_id") and len(slot["requests"]) < MAX_EVIDENCE_ROWS:
                slot["requests"].append(str(detail["request_id"]))
            if detail.get("location"):
                slot["locations"].add(str(detail["location"]))
            if event.get("ip_hash"):
                slot["callers"].add(str(event["ip_hash"]))
        for egress, row in disabled.items():
            slot = per.setdefault(
                egress, {"trips": 0, "last_ms": 0, "requests": [], "locations": set(), "callers": set()}
            )
            slot["disabled_since"] = row.get("since")
            if row.get("request_id") and len(slot["requests"]) < MAX_EVIDENCE_ROWS:
                slot["requests"].append(str(row["request_id"]))
            if row.get("location"):
                slot["locations"].add(str(row["location"]))
        if not per and blocked:
            per["unknown"] = {"trips": blocked, "last_ms": 0, "requests": [], "locations": set(), "callers": set()}
        out: list[Recommendation] = []
        for egress, slot in sorted(per.items()):
            out.append(self._recommend(ctx, window, egress, slot, blocked))
        return out

    def _recommend(
        self, ctx: InsightContext, window: Any, egress: str, slot: Mapping[str, Any], blocked: int
    ) -> Recommendation:
        trips = max(1, int(slot["trips"]))
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=trips)
        evidence.add("trips", int(slot["trips"]), "trips")
        evidence.add("blocked_requests", blocked, "requests")
        evidence.details["egress"] = egress
        evidence.details["request_ids"] = list(slot["requests"])
        evidence.details["found_in"] = sorted(slot["locations"])
        evidence.details["callers_hashed"] = sorted(slot["callers"])[:MAX_EVIDENCE_ROWS]
        if slot.get("last_ms"):
            evidence.details["last_trip"] = extra.utc_text(int(slot["last_ms"]) / 1000)
        if slot.get("disabled_since"):
            evidence.details["egress_disabled_since"] = extra.utc_text(float(slot["disabled_since"]))
        evidence.links.append("/admin/egress#trips")
        for request_id in slot["requests"][:1]:
            evidence.links.append(f"/admin/live/{request_id}")
        where = " and ".join(f"the {place}" for place in sorted(slot["locations"])) or "an outgoing part"
        still = f" The {egress} egress is disabled until an admin re-enables it." if slot.get("disabled_since") else ""
        return self.recommendation(
            ctx,
            subject=f"leak guard {egress}",
            title=f"The credential leak guard blocked a {egress} request",
            severity="critical",
            confidence="high",
            explanation=(
                f"The leak guard found the Roblox credential in {where} of a {egress} request and refused to send it "
                f"({extra.counted(int(slot['trips']), 'trip')} in the last "
                f"{round((window.end - window.start) / 3600)} hours; plan C2: the "
                f"credential never travels through the rotator or the anonymous client).{still} A code path is "
                'putting the credential where it must never be; investigate it with the request ids (runbook "Leak '
                'guard") before re-enabling anything.'
            ),
            evidence=evidence,
            changes=[
                ProposedChange(
                    "manual", text="Investigate the code path that attached the credential (runbook Leak guard)."
                )
            ],
            expected_impact="The account is never exposed through an anonymous egress.",
            risk="low",
        )


# --------------------------------------------------------------------------------------------- CRED-PROBE-COST


@register
class CredProbeCost(Rule):
    """Roxy's own credential checks are spending the account's call budget.

    Counts the calls Roxy itself made with the credential in the last hour (scheduled liveness probes, health
    runs, admin checks) and fires when they exceed `insight_cred_probe_cost_max_per_hour` (plan 13.3). The change
    follows the biggest source: a longer `credential_probe_interval_min` for scheduled probes (back to its default
    when it is shorter, else long enough to fit the budget), and no credential checks in scheduled health runs when
    `health_auto_include_credential` is on. The probe is never switched off and the threshold never raised.
    """

    id = "CRED-PROBE-COST"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        limit = int(ctx.setting("insight_cred_probe_cost_max_per_hour"))
        window = ctx.window(seconds=PROBE_COST_WINDOW_S)
        groups = await extra.credential_calls(ctx, window)
        total = sum(int(g["calls"]) for g in groups)
        if total <= limit:
            return []
        by_trigger: dict[str, int] = {}
        for group in groups:
            trigger = group["trigger"] or UNRECORDED
            by_trigger[trigger] = by_trigger.get(trigger, 0) + int(group["calls"])
        key = "credential_probe_interval_min"
        interval = int(ctx.setting(key))
        # The liveness job runs on the leader only, so an interval of N minutes is 60 / N calls per hour fleet-wide.
        # When the calls carry no trigger (the upstream service does not pass one yet), that is the scheduled share.
        expected = math.ceil(MINUTES_PER_HOUR / interval) if interval > 0 else 0
        recorded = any(trigger != UNRECORDED for trigger in by_trigger)
        scheduled = by_trigger.get(SCHEDULED, 0) if recorded else min(total, expected)
        others = total - scheduled
        changes: list[ProposedChange] = []
        parts: list[str] = []
        if scheduled and interval > 0:
            allowed = limit - others
            highest = int(catalog.CATALOG[key].max or interval)
            default = int(catalog.CATALOG[key].default)
            needed = math.ceil(MINUTES_PER_HOUR / allowed) if allowed > 0 else interval
            # Back to the shipped interval at least when it is shorter; longer only while the scheduled probes are
            # what can still bring the hour under the budget (hand-started checks no setting limits).
            proposed = min(highest, max(needed, default) if interval < default else needed)
            if proposed > interval:
                changes.append(ProposedChange("setting", key=key, current=interval, proposed=proposed))
                parts.append(
                    f"scheduled probes run every {interval} min ({scheduled} in the last hour); every {proposed} min "
                    f"they make about {math.ceil(MINUTES_PER_HOUR / proposed)} per hour"
                )
        if by_trigger.get(HEALTH) and int(ctx.setting("health_auto_include_credential")):
            changes.append(ProposedChange("setting", key="health_auto_include_credential", current=1, proposed=0))
            parts.append("scheduled health runs also check the credential (health_auto_include_credential is 1)")
        if not changes:
            changes.append(
                ProposedChange("manual", text="Most credential calls were admin or health checks: run them less often.")
            )
            parts.append("most calls were started by hand (admin checks and health runs), which no setting limits")
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=total)
        evidence.add("credential_calls", total, "calls")
        evidence.add("budget_per_hour", limit, "calls")
        for trigger in (SCHEDULED, HEALTH, ADMIN):
            evidence.add(f"{trigger}_calls", by_trigger.get(trigger, 0), "calls")
        evidence.details["by_trigger"] = by_trigger
        evidence.details["sources"] = [dict(g) for g in groups[: MAX_EVIDENCE_ROWS * 2]]
        evidence.links.append("/admin/credential#budget")
        after = total
        for change in changes:
            if change.kind == "setting" and change.key == key:
                after = others + math.ceil(MINUTES_PER_HOUR / int(change.proposed))
        sources = ", ".join(f"{name} {calls}" for name, calls in sorted(by_trigger.items()))
        remedy = "; ".join(parts)
        return [
            self.recommendation(
                ctx,
                subject="credential probe budget",
                title=f"Roxy made {total} credential calls in the last hour (budget {limit})",
                severity="warn",
                confidence="high",
                explanation=(
                    f"Roxy's own checks used the Roblox credential {total} times in the last hour, over the budget of "
                    f"{limit} (plan 13.3: every credential call spends the one account's allowance). By source: "
                    f"{sources}. {remedy[:1].upper()}{remedy[1:]}."
                ),
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    f"Roxy's own credential calls fall from {total} to about {after} per hour."
                    if after < total
                    else "Fewer credential calls once the checks run less often."
                ),
                risk="low",
            )
        ]


__all__ = ["CredExpiring", "CredProbeCost", "CredRotatorGuard", "CredUnused"]
