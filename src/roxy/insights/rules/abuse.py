"""The abuse and filter rules of plan 11.5: ABUSE-SPAM, ABUSE-BOT, ABUSE-DIST, FILTER-ADD, FILTER-REMOVE,
FILTER-COLLATERAL, TARPIT-TUNE, THROTTLE-TUNE and PLACE-HEAVY.

What this is
    Nine recommendation rules over what the abuse layer records: spam detector events and automatic bans, client
    activity per IP and per place, refusal events, request samples, bot scores, tarpit totals, rule hits and the
    access list. Each class docstring is the rule's help text on the Recommendations page.

Why it exists
    Plan 10 gives Roxy many protections (per-IP limit, spam detectors, bans, filters, the tarpit); plan 11.5 asks the
    engine to say when one is mis-sized, idle, harmful or not enough, with a change the admin can apply in one click.
    Every change here is scoped to one client or one rule row where the plan allows it; global settings are proposed
    only where the row says so (tarpit and per-IP limit sizes) and are never safe to auto-apply (11.2). Places are
    never banned automatically (place ids are claims anyone can forge, plan 10.3).

How it works
    - Thresholds come from `self.param` (the `insight_<slug>_<param>` settings) and from the catalog settings 11.5
      names (`bot_score_abuse_min`, `bot_score_legit_max`). The fixed numbers below are not 11.5 thresholds but
      readings the plan leaves open (look-back lengths, the "few" and "most" of THROTTLE-TUNE, a ban length); each is a
      module constant with a docstring, and the report asks the integrator to promote the ones that act as
      thresholds to catalog parameters.
    - Client numbers come from the client activity tables (`InsightContext.clients`, exact per minute); refusals by
      reason and place, and upstream use per place or client, from `providers_rules_abuse_system` (the refusal
      events and the request samples). Bot scores and tarpit totals come from the provider seams; a client without
      a score is unknown, never legitimate or abusive.
    - Bans proposed here are temporary and name one address (`ban_subject_for`: an IPv6 network key becomes a CIDR
      ban), exactly what an armed spam detector would write.

What to read next
    `roxy/insights/rules/base.py` (the authoring guide), `roxy/insights/providers_rules_abuse_system.py`,
    `roxy/abuse/spam.py` and `roxy/abuse/bans.py` (what the detectors write), and
    `tests/insights/test_rules_abuse_system.py`.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.abuse.bans import REPEAT_WINDOW_S, ban_subject_for, escalated_minutes, ua_hash
from roxy.abuse.bot import in_networks
from roxy.abuse.spam import DETECTORS
from roxy.config import catalog
from roxy.config.spec import RiskOp
from roxy.insights import providers_rules_abuse_system as facts
from roxy.insights.context import InsightContext
from roxy.insights.models import Evidence, ProposedChange, Recommendation, iso
from roxy.insights.rules.base import Rule, register
from roxy.insights.simulate import names_template, template_match
from roxy.metrics.templating import OTHER
from roxy.rules.match import compile_pattern, specificity

HOUR_S: Final = 3600
DAY_S: Final = 86_400
SPAM_LOOKBACK_S: Final = 3600
"""ABUSE-SPAM and ABUSE-DIST read the detections of the last hour: a detection older than that was acted on or
stopped (the detectors' default windows are 5 to 10 minutes, plan 10.3)."""
REPEATED_AUTO_BANS: Final = 2
"""ABUSE-SPAM "repeated auto-bans": two or more automatic bans of one subject within the 30 day escalation window of
plan 10.3 (`abuse/bans.py REPEAT_WINDOW_S`; README reading of the fixtures)."""
RECENT_AUTO_BAN_S: Final = 86_400
"""A repeat offender counts while its newest automatic ban is at most a day old (older repeats already stopped)."""
DIST_DETECTOR: Final = "SPAM-DIST"
TEMPORARY_BAN_S: Final = 86_400
"""Length of the temporary IP ban ABUSE-BOT and FILTER-ADD propose (11.5 gives none): a day stops the load and
lapses by itself if the address is reassigned to someone else."""
COLLATERAL_WINDOW_MIN: Final = 60
"""FILTER-COLLATERAL compares the last hour of each place's traffic (11.5 names no window; an hour matches the
other per-place rule, PLACE-HEAVY)."""
PLACE_LOOKBACK_S: Final = 86_400
"""FILTER-REMOVE judges a banned place by its traffic in the day before the ban was created."""
TOP_PLACES: Final = 10
"""FILTER-REMOVE "top legitimate place": among the 10 places with the most served requests (the plan's other "top"
list of endpoints, CACHE-LOW-HIT, also defaults to 10)."""
BYPASS_EXPIRY_S: Final = 30 * 86_400
"""Expiry proposed for a bypass entry that has none and is still in use: 30 days from now."""
TIGHT_WINDOW_S: Final = 86_400
"""THROTTLE-TUNE "throttled per day": the last 24 hours."""
LOOSE_WINDOW_MIN: Final = 60
"""THROTTLE-TUNE "too loose" looks at the last hour of upstream use and `upstream_busy` refusals."""
LOOSE_TOP_CLIENTS: Final = 3
"""THROTTLE-TUNE "a few IPs": the three clients that reached Roblox most often (11.5 gives no number)."""
LOOSE_SHARE: Final = 0.5
"""THROTTLE-TUNE "most of the upstream slots": more than half of the sampled requests that reached Roblox."""
LIMIT_STEP: Final = 0.5
"""THROTTLE-TUNE "too tight" raises the per-IP limit by half (the default `auto_apply_max_step_pct` step)."""
GAP_GAIN_MIN: Final = 0.5
"""TARPIT-TUNE "arrival gap unchanged by holding": a held client returns less than 50% later than an unheld one."""
PLACE_RULE_PERIOD_S: Final = 60
"""PLACE-HEAVY's per-place endpoint rule counts per minute, like `place_limit_per_minute`."""
FULL_SAMPLING_PCT: Final = 100
"""`request_sample_pct` at which every proxied request is sampled (below it, sample counts are estimates)."""
FILTER_REASONS: Final[dict[str, str]] = {
    "rules_endpoint_block": "endpoint_blocked",
    "rules_endpoint_limit": "endpoint_rule",
    "rules_user_agent": "user_agent_rule",
    "rules_header": "header_rule",
}
"""The abuse filter tables and the refusal reason each one writes (DESIGN 6)."""
PATTERN_TABLES: Final = frozenset({"rules_endpoint_block", "rules_endpoint_limit"})
CLIENTS_LINK: Final = "/admin/clients"
PROTECTION_LINK: Final = "/admin/protection"


# ------------------------------------------------------------------------------------------------ helpers


def is_active(row: Mapping[str, Any], now: float) -> bool:
    """A ban or access list row in force now (no expiry, or one in the future)."""
    expires = row.get("expires_at")
    return expires is None or float(expires) > now


def bypass_rows(rows: Iterable[Mapping[str, Any]], now: float) -> list[Mapping[str, Any]]:
    """Active bypass entries of the access list."""
    return [row for row in rows if row.get("kind") == "bypass" and is_active(row, now)]


def banned_subjects(rows: Iterable[Mapping[str, Any]], now: float) -> set[tuple[str, str]]:
    """`(subject_type, subject)` of every active ban."""
    return {(str(r["subject_type"]), str(r["subject"])) for r in rows if is_active(r, now)}


def is_banned(ip: str, bans: set[tuple[str, str]]) -> bool:
    """Whether an active IP or CIDR ban covers the address."""
    if ("ip", ip) in bans:
        return True
    cidrs = [subject for kind, subject in bans if kind == "cidr"]
    return bool(cidrs) and in_networks(ip, cidrs)


def is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def access_match(row: Mapping[str, Any]) -> dict[str, Any]:
    """The natural key of an access list row (README "Extensions": `{kind, cidr}`)."""
    return {"kind": row["kind"], "cidr": row["cidr"]}


def filter_match(table: str, row: Mapping[str, Any]) -> dict[str, Any]:
    """The natural key of an abuse filter row (README "Extensions")."""
    if table == "rules_user_agent":
        return {"id": row["id"]}
    if table == "rules_header":
        return {"canonical_key": row["canonical_key"]}
    return {"pattern": row["pattern"], "type": row.get("type") or "glob"}


def filter_label(table: str, row: Mapping[str, Any]) -> str:
    """A short human name of a filter row for titles and subjects."""
    if table == "rules_user_agent":
        return f"User-Agent rule {row['id']} ({row.get('needle')!s})"
    if table == "rules_header":
        return f"header rule {row.get('canonical_key')!s}"
    noun = "endpoint block" if table == "rules_endpoint_block" else "endpoint rule"
    return f"{noun} {row.get('pattern')!s}"


def ban_change(
    subject_type: str, subject: str, *, expires_at: int | None, reason_code: str, text: str
) -> ProposedChange:
    """A `ban_add` change (README shape: `current` null, `proposed` with an `expires_at` always present)."""
    return ProposedChange(
        "ban_add",
        table="bans",
        current=None,
        proposed={
            "subject_type": subject_type,
            "subject": subject,
            "reason_code": reason_code,
            "reason_text": text[:300],
            "expires_at": expires_at,
        },
    )


def setting_change(ctx: InsightContext, key: str, proposed: Any) -> ProposedChange:
    """A `setting` change with the current value from this run's snapshot and the proposal in canonical form."""
    return ProposedChange("setting", key=key, current=ctx.setting(key), proposed=catalog.validate_value(key, proposed))


def highest_safe(key: str, value: float) -> float:
    """`value` capped at the catalog maximum and below the setting's high-risk range (plan 15.1 `high_risk_if`)."""
    spec = catalog.CATALOG[key]
    capped = min(value, spec.max) if spec.max is not None else value
    integral = spec.type.value in ("int", "duration", "bytes")
    for condition in spec.high_risk_if:
        if condition.op is RiskOp.GTE and capped >= condition.value:
            capped = condition.value - 1 if integral else condition.value
        elif condition.op is RiskOp.GT and capped > condition.value:
            capped = condition.value
    return capped


def lowest_allowed(key: str, value: float) -> float:
    """`value` raised to the catalog minimum."""
    spec = catalog.CATALOG[key]
    return max(value, spec.min) if spec.min is not None else value


def per_hour(count: float, seconds: float) -> int:
    return round(count * HOUR_S / seconds) if seconds else 0


def client_index(rows: Iterable[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    """Client table rows by key, without the folded `other` row."""
    return {str(row["key"]): row for row in rows if str(row["key"]) not in ("", "other", OTHER)}


async def scores_of(ctx: InsightContext) -> dict[str, float]:
    """Bot scores by client address (provider seam); a missing address is unknown."""
    return dict(await ctx.providers.client_scores())


# ------------------------------------------------------------------------------------------------ ABUSE-SPAM


@dataclass(slots=True)
class _SpamSubject:
    """What the detectors said about one subject in the look-back window."""

    subject: str
    detections: list[dict[str, Any]] = field(default_factory=list)
    detectors: dict[str, int] = field(default_factory=dict)
    game_server: bool = False
    would_ban: bool = False
    auto_bans: list[Mapping[str, Any]] = field(default_factory=list)


def _detector_id(name: str) -> str | None:
    """`SPAM-RATE` or `spam_rate` -> `rate` (a detector of `abuse/spam.py`), else None."""
    text = name.strip().lower().replace("-", "_")
    for prefix in ("spam_", "auto:spam_"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text if text in DETECTORS else None


def _client_of(subject: str) -> str | None:
    """The client limit key of a detector subject (`ip:<key>` or `ip:<key>|<template>`), else None."""
    if not subject.startswith("ip:"):
        return None
    key = subject[3:].split("|", 1)[0]
    return key or None


@register
class AbuseSpam(Rule):
    """A spam detector found abusive traffic but nothing stopped it.

    Fires for a client that a spam detector would have banned in the last hour while `spam_dry_run` is on, that a
    recommend-only detector flagged, or that was banned automatically at least twice in 30 days and came back within
    the last day (the doubling escalation alone is not stopping it). The change is a temporary ban on that one
    address, as long as the armed detectors would have made it by now (or twice the longest ban so far for a repeat
    offender). A trusted Roblox game server is never banned, and a place flagged by a detector gets a manual review
    instead: place ids are claims anyone can send.
    """

    id = "ABUSE-SPAM"
    triggers = frozenset({"ban_created", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(seconds=SPAM_LOOKBACK_S)
        subjects: dict[str, _SpamSubject] = {}
        for event in await ctx.events(("spam_would_ban", "spam_detected"), window):
            detail = event.get("detail") or {}
            detector = str(detail.get("detector") or event.get("reason_code") or "")
            subject = str(detail.get("subject") or "")
            if detector.upper() == DIST_DETECTOR or not subject:
                continue  # SPAM-DIST is ABUSE-DIST's
            client = _client_of(subject)
            key = f"ip:{client}" if client else subject
            entry = subjects.setdefault(key, _SpamSubject(key))
            entry.detections.append(
                {
                    "at": iso(int(event["at_ms"]) / 1000),
                    "type": event["type"],
                    "detector": detector,
                    "value": detail.get("value"),
                    "threshold": detail.get("threshold"),
                    "subject": subject,
                }
            )
            entry.detectors[detector] = entry.detectors.get(detector, 0) + int(event.get("count") or 1)
            entry.game_server = entry.game_server or bool(detail.get("game_server"))
            entry.would_ban = entry.would_ban or event["type"] == "spam_would_ban"
        bans = await ctx.rule_rows("bans")
        for subject_key, rows in _repeated_auto_bans(bans, ctx.now).items():
            entry = subjects.setdefault(subject_key, _SpamSubject(subject_key))
            entry.auto_bans = rows
        clients = client_index(await ctx.clients(window, "ip"))
        scores = await scores_of(ctx)
        out: list[Recommendation] = []
        for key, entry in sorted(subjects.items()):
            if entry.game_server:
                continue  # collateral protection (plan 10.3): a trusted game server is never banned
            client = _client_of(key)
            if client is None:
                if key.startswith("place:") and entry.detections:
                    out.append(self._place(ctx, window, entry))
                continue
            rec = self._client(ctx, window, entry, client, bans, clients.get(client), scores.get(client))
            if rec is not None:
                out.append(rec)
        return out

    def _ban_minutes(self, ctx: InsightContext, entry: _SpamSubject, previous: int) -> int:
        """How long the armed detectors would ban this client by now, or a longer ban for a repeat offender."""
        minutes = 0
        for name, count in entry.detectors.items():
            detector = _detector_id(name)
            if detector is None:
                continue
            base = int(ctx.setting(f"spam_{detector}_ban_minutes"))
            cap = int(ctx.setting(f"spam_{detector}_ban_max_minutes"))
            minutes = max(minutes, escalated_minutes(base, cap, previous + max(0, count - 1)))
        if entry.auto_bans:
            longest = max(
                ((int(r["expires_at"]) - int(r["created_at"])) // 60 for r in entry.auto_bans if r.get("expires_at")),
                default=0,
            )
            minutes = max(minutes, 2 * longest)
            for row in entry.auto_bans:
                detector = _detector_id(str(row.get("created_by") or ""))
                if detector is not None:
                    minutes = max(minutes, int(ctx.setting(f"spam_{detector}_ban_max_minutes")))
        return minutes

    def _client(
        self,
        ctx: InsightContext,
        window: Any,
        entry: _SpamSubject,
        client: str,
        bans: Sequence[Mapping[str, Any]],
        activity: Mapping[str, Any] | None,
        score: float | None,
    ) -> Recommendation | None:
        subject_type, subject = ban_subject_for(client)
        since = ctx.now - REPEAT_WINDOW_S
        previous = sum(
            1
            for r in bans
            if str(r["subject_type"]) == subject_type
            and str(r["subject"]) == subject
            and str(r.get("created_by") or "").startswith("auto:")
            and float(r["created_at"]) >= since
        )
        minutes = self._ban_minutes(ctx, entry, previous)
        if minutes <= 0:
            return None  # every detector involved has its ban length at 0: bans are switched off for them
        expires_at = int(ctx.now) + minutes * 60
        current_expiry = max(
            (
                float("inf") if r.get("expires_at") is None else float(r["expires_at"])
                for r in bans
                if str(r["subject_type"]) == subject_type and str(r["subject"]) == subject and is_active(r, ctx.now)
            ),
            default=0.0,
        )
        if current_expiry >= expires_at:
            return None  # an active ban already lasts at least that long
        detections = sum(entry.detectors.values())
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=max(1, detections + previous))
        evidence.add("detections_last_hour", detections, "detections")
        evidence.add("automatic_bans_30d", previous, "bans")
        if activity is not None:
            evidence.add("requests_last_hour", int(activity.get("requests") or 0), "requests")
            evidence.add("refused_last_hour", int(activity.get("refused") or 0), "requests")
        if score is not None:
            evidence.add("bot_score", score)
        evidence.details["detectors"] = dict(entry.detectors)
        evidence.details["timeline"] = entry.detections[-20:]
        evidence.details["automatic_bans"] = [
            {
                "created_at": iso(r["created_at"]),
                "expires_at": iso(r.get("expires_at")),
                "created_by": r.get("created_by"),
                "reason": r.get("reason_text"),
            }
            for r in entry.auto_bans[-10:]
        ]
        evidence.links += [f"{CLIENTS_LINK}?ip={client}", f"{PROTECTION_LINK}#spam"]
        length = "as long as the armed detectors would have made it by now"
        if entry.auto_bans:
            why = (
                f"Roxy banned {client} automatically {len(entry.auto_bans)} times in 30 days and it came back every "
                "time; the doubling escalation of plan 10.3 is not stopping it."
            )
            length = "twice its longest automatic ban, and at least the detector's longest ban"
        elif entry.would_ban:
            names = ", ".join(sorted(entry.detectors))
            why = (
                f"{names} would have banned {client} {detections} times in the last hour, but the spam detectors were "
                "in dry run (spam_dry_run on), so nothing happened."
            )
        else:
            names = ", ".join(sorted(entry.detectors))
            why = f"{names} flagged {client} {detections} times in the last hour; that detector only recommends."
        requests = int((activity or {}).get("requests") or 0)
        hours = minutes / 60
        text = f"ABUSE-SPAM: {', '.join(sorted(entry.detectors)) or 'repeated automatic bans'}"
        return self.recommendation(
            ctx,
            subject=f"ip:{client}",
            title=f"Ban {client} for {hours:g} h: spam detectors keep flagging it",
            severity="warn",
            confidence="medium",
            explanation=(
                f"{why} The change bans this one address for {hours:g} hours (until {iso(expires_at)}), {length}. "
                "Other clients are not affected. To let the detectors act on their own instead, preview "
                "FILTER-COLLATERAL and arm them on Protection > Spam."
            ),
            evidence=evidence,
            changes=[ban_change(subject_type, subject, expires_at=expires_at, reason_code="abuse_spam", text=text)],
            expected_impact=(
                f"About {requests:,} requests an hour from {client} (the last hour's volume) stop reaching Roxy's "
                f"cache and Roblox for {hours:g} hours."
            ),
            risk="low",
        )

    def _place(self, ctx: InsightContext, window: Any, entry: _SpamSubject) -> Recommendation:
        place = entry.subject.split(":", 1)[1]
        detections = sum(entry.detectors.values())
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=max(1, detections))
        evidence.add("detections_last_hour", detections, "detections")
        evidence.details["detectors"] = dict(entry.detectors)
        evidence.details["timeline"] = entry.detections[-20:]
        evidence.links.append(f"{CLIENTS_LINK}?place={place}")
        return self.recommendation(
            ctx,
            subject=entry.subject,
            title=f"Spam detectors flagged place {place}",
            severity="warn",
            confidence="medium",
            explanation=(
                f"{', '.join(sorted(entry.detectors))} fired {detections} times in the last hour for place {place}. "
                "Place ids are claims any caller can send, so Roxy never bans a place automatically; review its "
                "clients and use a place limit or a per-place endpoint rule if the traffic is abusive."
            ),
            evidence=evidence,
            changes=[ProposedChange("manual", text=f"Review place {place} on Clients and limit it if it is abusive.")],
            expected_impact="The admin decides; nothing changes until then.",
            risk="low",
        )


def _repeated_auto_bans(rows: Iterable[Mapping[str, Any]], now: float) -> dict[str, list[Mapping[str, Any]]]:
    """`{"ip:<subject>": [auto bans]}` for subjects banned automatically `REPEATED_AUTO_BANS` times or more in the
    escalation window, the newest within `RECENT_AUTO_BAN_S`."""
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        if not str(row.get("created_by") or "").startswith("auto:"):
            continue
        if str(row["subject_type"]) not in ("ip", "cidr") or float(row["created_at"]) < now - REPEAT_WINDOW_S:
            continue
        grouped.setdefault(f"ip:{row['subject']}", []).append(row)
    out: dict[str, list[Mapping[str, Any]]] = {}
    for key, bans in grouped.items():
        bans.sort(key=lambda r: float(r["created_at"]))
        if len(bans) >= REPEATED_AUTO_BANS and float(bans[-1]["created_at"]) >= now - RECENT_AUTO_BAN_S:
            out[key] = bans
    return out


# ------------------------------------------------------------------------------------------------ ABUSE-BOT


@register
class AbuseBot(Rule):
    """A bot-like client is sending heavy traffic.

    Fires for each address whose bot score is at or above `bot_score_abuse_min` and that sent more than
    `min_requests_per_hour` requests in the last hour. Both tests must hold: busy game servers have low scores and
    small scripts send little. The change is a temporary ban (one day) on that address only; a client on the bypass
    list or already banned is left alone, and a client without a bot score is never judged.
    """

    id = "ABUSE-BOT"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        scores = await scores_of(ctx)
        if not scores:
            return []
        window = ctx.window(seconds=HOUR_S)
        abuse_min = float(ctx.setting("bot_score_abuse_min"))
        min_requests = self.param(ctx, "min_requests_per_hour")
        access = await ctx.rule_rows("access_list")
        bypass = [str(r["cidr"]) for r in bypass_rows(access, ctx.now)]
        banned = banned_subjects(await ctx.rule_rows("bans"), ctx.now)
        out: list[Recommendation] = []
        for ip, row in sorted(client_index(await ctx.clients(window, "ip")).items()):
            score = scores.get(ip)
            requests = int(row.get("requests") or 0)
            if score is None or score < abuse_min or requests <= min_requests or not is_address(ip):
                continue
            if (bypass and in_networks(ip, bypass)) or is_banned(ip, banned):
                continue
            out.append(self._recommend(ctx, window, ip, score, row))
        return out

    def _recommend(
        self, ctx: InsightContext, window: Any, ip: str, score: float, row: Mapping[str, Any]
    ) -> Recommendation:
        requests = int(row.get("requests") or 0)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=requests)
        evidence.add("bot_score", score)
        evidence.add("requests_last_hour", requests, "requests")
        evidence.add("refused_last_hour", int(row.get("refused") or 0), "requests")
        evidence.add("served_last_hour", int(row.get("served") or 0), "requests")
        evidence.details["top_endpoint"] = row.get("top_endpoint")
        evidence.links.append(f"{CLIENTS_LINK}?ip={ip}")
        expires_at = int(ctx.now) + TEMPORARY_BAN_S
        subject_type, subject = ban_subject_for(ip)
        return self.recommendation(
            ctx,
            subject=f"ip:{ip}",
            title=f"Bot-like client {ip} sent {requests:,} requests in an hour",
            severity="warn",
            confidence="medium",
            explanation=(
                f"{ip} has a bot score of {score:g} (bot_score_abuse_min is {ctx.setting('bot_score_abuse_min')}) and "
                f"sent {requests:,} requests in the last hour, mostly to {row.get('top_endpoint') or 'one endpoint'}. "
                "The change bans this one address for a day; a User-Agent rule is the alternative when its "
                "User-Agent is distinctive (Clients shows the client's details)."
            ),
            evidence=evidence,
            changes=[
                ban_change(
                    subject_type,
                    subject,
                    expires_at=expires_at,
                    reason_code="abuse_bot",
                    text=f"ABUSE-BOT: bot score {score:g}, {requests} requests in an hour",
                )
            ],
            expected_impact=f"About {requests:,} fewer requests an hour from {ip} for the next 24 hours.",
            risk="low",
        )


# ------------------------------------------------------------------------------------------------ ABUSE-DIST


@register
class AbuseDist(Rule):
    """A distributed attack: many addresses with one User-Agent are hammering one endpoint.

    Fires when SPAM-DIST (more than `spam_dist_threshold` addresses sharing one User-Agent on one endpoint) detected
    a swarm in the last hour. Each address stays under the per-IP limit, so only a rule over all of them helps: a
    User-Agent rule with global scope (one shared allowance for every address sending that User-Agent), or
    throttle-all for a while when the User-Agent text is not known. A detection made only of legitimate game servers
    (every scored client at or under `bot_score_legit_max`) is ignored: its remedy would refuse every game server,
    and a rule never matches a Roblox User-Agent.
    """

    id = "ABUSE-DIST"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(seconds=SPAM_LOOKBACK_S)
        swarms: dict[str, list[dict[str, Any]]] = {}
        for event in await ctx.events(("spam_detected",), window):
            detail = event.get("detail") or {}
            if str(detail.get("detector") or event.get("reason_code") or "").upper() != DIST_DETECTOR:
                continue
            subject = str(detail.get("subject") or "")
            if "|" not in subject:
                continue
            swarms.setdefault(subject, []).append({**detail, "at": int(event["at_ms"]) / 1000})
        if not swarms:
            return []
        scores = await scores_of(ctx)
        legit_max = float(ctx.setting("bot_score_legit_max"))
        agents = await facts.recent_user_agents(ctx)
        out: list[Recommendation] = []
        for subject, detections in sorted(swarms.items()):
            template, digest = subject.rsplit("|", 1)
            if template.startswith("(") or not template:
                continue  # the folded `(other)` pair names no endpoint to act on
            first = min(d["at"] for d in detections) - max(int(d.get("window_s") or 0) for d in detections)
            last = max(d["at"] for d in detections)
            span = ctx.window(seconds=max(60.0, last - first + 60), end=last + 60)
            members = [
                row
                for row in client_index(await ctx.clients(span, "ip")).values()
                if row.get("top_endpoint") == template
            ]
            scored = [scores[str(row["key"])] for row in members if str(row["key"]) in scores]
            if scored and all(score <= legit_max for score in scored):
                continue  # legitimate game servers sharing the Roblox User-Agent (10.3 collateral protection)
            agent = next((ua for ua in agents if ua_hash(ua) == digest), None)
            out.append(self._recommend(ctx, window, subject, template, digest, detections, members, scored, agent))
        return out

    def _recommend(
        self,
        ctx: InsightContext,
        window: Any,
        subject: str,
        template: str,
        digest: str,
        detections: Sequence[Mapping[str, Any]],
        members: Sequence[Mapping[str, Any]],
        scored: Sequence[float],
        agent: str | None,
    ) -> Recommendation:
        addresses = max(int(float(d.get("value") or 0)) for d in detections)
        requests = sum(int(row.get("requests") or 0) for row in members)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=max(1, addresses))
        evidence.add("detections", len(detections), "detections")
        evidence.add("addresses", addresses, "IP addresses")
        evidence.add("requests_from_swarm", requests, "requests")
        if scored:
            evidence.add("median_bot_score", sorted(scored)[len(scored) // 2])
        evidence.details["endpoint_template"] = template
        evidence.details["ua_hash"] = digest
        evidence.details["sample_clients"] = [str(row["key"]) for row in members[:10]]
        evidence.details["detections"] = [
            {"at": iso(d["at"]), "value": d.get("value"), "evidence": d.get("evidence")} for d in detections[-12:]
        ]
        evidence.links += [f"{PROTECTION_LINK}#spam-dist", f"{PROTECTION_LINK}#ua-rules"]
        if agent is not None and "roblox" not in agent.lower():
            limit = int(ctx.setting("allowed_requests_per_minute"))
            period = int(ctx.setting("throttle_reset_duration"))
            changes = [
                ProposedChange(
                    "filter_add",
                    table="rules_user_agent",
                    match=None,
                    current=None,
                    proposed={
                        "mode": "exact",
                        "needle": agent,
                        "kind": "burst",
                        "scope": "global",
                        "limit": limit,
                        "period": period,
                        "note": "ABUSE-DIST: distributed swarm",
                    },
                )
            ]
            remedy = (
                f"a User-Agent rule with global scope for {agent!r}: every address sending it shares one allowance "
                f"of {limit} requests per {period} s"
            )
            impact = (
                f"The swarm's {requests:,} requests in the detection window shrink to one shared allowance; game "
                "servers are unaffected because the rule never matches a Roblox User-Agent."
            )
        else:
            changes = [
                ProposedChange(
                    "manual",
                    text=(
                        "Turn on throttle-all for a while (top bar), and add a global User-Agent rule for the shared "
                        f"User-Agent (hash {digest}) once Live or Clients shows its text."
                    ),
                )
            ]
            remedy = "throttle-all for a while, then a global User-Agent rule once the User-Agent text is known"
            impact = (
                f"Throttle-all slows every caller, game servers included, until it is turned off; the User-Agent rule "
                f"that follows stops only the swarm ({requests:,} requests in the detection window)."
            )
        unknown = (
            "" if scored else " The bot scores of these clients are unknown, so Roxy could not rule out game servers."
        )
        return self.recommendation(
            ctx,
            subject=subject,
            title=f"Distributed attack on {template} from {addresses} addresses",
            severity="critical",
            confidence="medium",
            explanation=(
                f"SPAM-DIST fired {len(detections)} times in the last hour: {addresses} addresses sharing one "
                f"User-Agent (hash {digest}) are calling {template}. Each address stays under the per-IP limit, so "
                f"only a rule over all of them stops it: {remedy}.{unknown}"
            ),
            evidence=evidence,
            changes=changes,
            expected_impact=impact,
            risk="medium",
        )


# ------------------------------------------------------------------------------------------------ FILTER-ADD


@register
class FilterAdd(Rule):
    """A client keeps hitting Roxy's limits hour after hour.

    Fires for each address refused more than `refusals_per_hour` times in each of the last `hours` hours (rolling
    hours ending now). Refusals already cost the client nothing but cost Roxy work; a temporary ban (one day) refuses
    it before any other check runs, and the tarpit holds it if `tarpit_on_ban` is on. Clients on the bypass list or
    already banned are left alone.
    """

    id = "FILTER-ADD"
    triggers = frozenset({"ban_created", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        hours = max(1, self.int_param(ctx, "hours"))
        threshold = self.param(ctx, "refusals_per_hour")
        end = ctx.window(seconds=60).end
        windows = [ctx.window(seconds=HOUR_S, end=end - k * HOUR_S) for k in range(hours)]
        per_hour = [client_index(await ctx.clients(w, "ip")) for w in windows]
        access = await ctx.rule_rows("access_list")
        bypass = [str(r["cidr"]) for r in bypass_rows(access, ctx.now)]
        banned = banned_subjects(await ctx.rule_rows("bans"), ctx.now)
        out: list[Recommendation] = []
        for ip in sorted(per_hour[0]):
            counts = [int((hour.get(ip) or {}).get("refused") or 0) for hour in per_hour]
            if not all(count > threshold for count in counts) or not is_address(ip):
                continue
            if (bypass and in_networks(ip, bypass)) or is_banned(ip, banned):
                continue
            out.append(self._recommend(ctx, windows, ip, counts, per_hour[0][ip]))
        return out

    def _recommend(
        self, ctx: InsightContext, windows: Sequence[Any], ip: str, counts: Sequence[int], latest: Mapping[str, Any]
    ) -> Recommendation:
        total = sum(counts)
        evidence = Evidence(window_from=windows[-1].start, window_to=windows[0].end, sample_size=total)
        evidence.add("refused_per_hour_min", min(counts), "requests")
        evidence.add("refused_total", total, "requests")
        evidence.add("hours_over_threshold", len(counts), "hours")
        evidence.add("requests_last_hour", int(latest.get("requests") or 0), "requests")
        evidence.details["refused_by_hour"] = [
            {"from": iso(w.start), "to": iso(w.end), "refused": n} for w, n in zip(windows, counts, strict=True)
        ]
        evidence.details["top_endpoint"] = latest.get("top_endpoint")
        evidence.links.append(f"{CLIENTS_LINK}?ip={ip}")
        subject_type, subject = ban_subject_for(ip)
        expires_at = int(ctx.now) + TEMPORARY_BAN_S
        hourly = ", ".join(f"{n:,}" for n in counts)
        return self.recommendation(
            ctx,
            subject=f"ip:{ip}",
            title=f"{ip} was refused at least {min(counts):,} times an hour for {len(counts)} hours",
            severity="warn",
            confidence="medium",
            explanation=(
                f"Roxy refused {ip} {total:,} times in the last {len(counts)} hours ({hourly} per hour, newest "
                "first) and it keeps coming back. A temporary ban refuses it before any other check runs; the ban "
                "ends by itself after a day."
            ),
            evidence=evidence,
            changes=[
                ban_change(
                    subject_type,
                    subject,
                    expires_at=expires_at,
                    reason_code="filter_add",
                    text=f"FILTER-ADD: refused {min(counts)} or more times an hour for {len(counts)} hours",
                )
            ],
            expected_impact=(
                f"About {counts[0]:,} refusals an hour (the last hour's count) become one cheap ban lookup each, for "
                "the next 24 hours."
            ),
            risk="low",
        )


# ------------------------------------------------------------------------------------------------ FILTER-REMOVE


@register
class FilterRemove(Rule):
    """A filter, bypass entry or ban looks stale or harmful.

    Fires for an enabled abuse filter (User-Agent, header, endpoint block or endpoint rule) with no hit for
    `idle_rule_days` days (a never-hit rule counts from its creation; endpoint and header filters also count a hit when
    the rollups show a refusal they would have made), for a bypass entry unused for `idle_bypass_days` days (remove
    it) or with no expiry at all (set one), and for an active ban on a place that was one of the busiest legitimate
    places before the ban (its traffic was served, by the FILTER-COLLATERAL measure). One recommendation per object:
    remove it, or for a bypass entry still in use, give it an expiry.
    """

    id = "FILTER-REMOVE"
    triggers = frozenset({"ban_created", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        out: list[Recommendation] = []
        idle_rule_s = self.param(ctx, "idle_rule_days") * DAY_S
        for table in FILTER_REASONS:
            hits = await ctx.rule_hits(table)
            for row in await ctx.rule_rows(table):
                if not row.get("enabled", 1):
                    continue
                rec = await self._idle_rule(ctx, table, row, hits, idle_rule_s)
                if rec is not None:
                    out.append(rec)
        out += await self._bypass(ctx)
        out += await self._place_bans(ctx)
        return out

    async def _idle_rule(
        self,
        ctx: InsightContext,
        table: str,
        row: Mapping[str, Any],
        hits: Mapping[tuple[str, str], Mapping[str, Any]],
        idle_s: float,
    ) -> Recommendation | None:
        created = float(row.get("created_at") or ctx.now)
        last_hit = (hits.get((table, str(row["id"]))) or {}).get("last_hit_at")
        since = float(last_hit) if last_hit is not None else created
        if ctx.now - since <= idle_s:
            return None
        if table != "rules_user_agent" and await self._refused_lately(ctx, table, row, ctx.now - idle_s):
            return None
        days = (ctx.now - since) / DAY_S
        evidence = Evidence(window_from=ctx.now - idle_s, window_to=ctx.now, sample_size=1)
        evidence.add("idle_days", round(days, 1), "days")
        evidence.add("age_days", round((ctx.now - created) / DAY_S, 1), "days")
        evidence.details["last_hit_at"] = iso(last_hit)
        evidence.details["row"] = dict(row)
        evidence.links.append(f"{PROTECTION_LINK}#filters")
        label = filter_label(table, row)
        never = "has never matched a request" if last_hit is None else f"last matched {days:.0f} days ago"
        return self.recommendation(
            ctx,
            subject=f"{table}:{row['id']}",
            title=f"Remove the idle {label}",
            severity="info",
            confidence="high",
            explanation=(
                f"The {label} {never} (created {iso(created)}). A filter that never fires only costs a check on every "
                "request and makes the protection page harder to read; removing it is undone with one click."
            ),
            evidence=evidence,
            changes=[ProposedChange("filter_remove", table=table, match=filter_match(table, row), current=dict(row))],
            expected_impact="One check fewer on every request and a shorter filter list; no traffic changes.",
            risk="low",
        )

    async def _refused_lately(self, ctx: InsightContext, table: str, row: Mapping[str, Any], since: float) -> bool:
        """Whether the rollups show a refusal this filter could have made since `since` (rule hits are recorded for
        User-Agent rules only until the abuse layer records the others; integrator request in the P10 report)."""
        reason = FILTER_REASONS[table]
        refused = await ctx.by(facts.long_window(since, ctx.now), "endpoint_template", {"reason_code": reason})
        templates = [str(t) for t, measures in refused.items() if int(measures.get("requests") or 0) > 0]
        if not templates:
            return False
        if table not in PATTERN_TABLES:
            return True  # a header refusal cannot be tied to one header rule: never call any of them idle
        compiled = compile_pattern(str(row["pattern"]), str(row.get("type") or "glob"))
        return any(compiled.matches(template) for template in templates)

    async def _bypass(self, ctx: InsightContext) -> list[Recommendation]:
        idle_s = self.param(ctx, "idle_bypass_days") * DAY_S
        hits = await ctx.rule_hits("access_list")
        out: list[Recommendation] = []
        for row in bypass_rows(await ctx.rule_rows("access_list"), ctx.now):
            last_hit = (hits.get(("access_list", str(row["id"]))) or {}).get("last_hit_at")
            created = float(row.get("created_at") or ctx.now)
            since = float(last_hit) if last_hit is not None else created
            idle = ctx.now - since > idle_s and not await self._seen_lately(ctx, str(row["cidr"]), ctx.now - idle_s)
            forever = row.get("expires_at") is None
            if not idle and not forever:
                continue
            evidence = Evidence(window_from=ctx.now - idle_s, window_to=ctx.now, sample_size=1)
            evidence.add("unused_days", round((ctx.now - since) / DAY_S, 1), "days")
            evidence.add("age_days", round((ctx.now - created) / DAY_S, 1), "days")
            evidence.details["last_hit_at"] = iso(last_hit)
            evidence.details["expires_at"] = iso(row.get("expires_at"))
            evidence.links.append(f"{PROTECTION_LINK}#bypass")
            cidr = str(row["cidr"])
            if idle:
                change = ProposedChange(
                    "bypass_remove", table="access_list", match=access_match(row), current=dict(row)
                )
                title, what = f"Remove the unused bypass entry {cidr}", "removes it"
                why = f"it has not been used for {(ctx.now - since) / DAY_S:.0f} days"
            else:
                expires_at = int(ctx.now) + BYPASS_EXPIRY_S
                change = ProposedChange(
                    "rule_upsert",
                    table="access_list",
                    match=access_match(row),
                    current=dict(row),
                    proposed={"expires_at": expires_at},
                )
                title, what = f"Give the bypass entry {cidr} an expiry", f"sets it to expire on {iso(expires_at)}"
                why = "it never expires"
            out.append(
                self.recommendation(
                    ctx,
                    subject=f"bypass:{cidr}",
                    title=title,
                    severity="info",
                    confidence="high",
                    explanation=(
                        f"The bypass entry {cidr} ({row.get('note') or 'no note'}) lets every request from it skip the "
                        f"per-IP limit, the place limit and the tarpit, and {why}. The change {what}."
                    ),
                    evidence=evidence,
                    changes=[change],
                    expected_impact="No unlimited client is forgotten on the bypass list.",
                    risk="low",
                )
            )
        return out

    async def _seen_lately(self, ctx: InsightContext, cidr: str, since: float) -> bool:
        """Whether a client inside a bypass entry sent requests since `since` (the client tables are the fallback
        until bypass hits are recorded)."""
        rows = client_index(await ctx.clients(facts.long_window(since, ctx.now), "ip"))
        return any(int(row.get("requests") or 0) > 0 and in_networks(ip, [cidr]) for ip, row in rows.items())

    async def _place_bans(self, ctx: InsightContext) -> list[Recommendation]:
        served_pct = float(ctx.setting("insight_filter_collateral_served_pct"))
        out: list[Recommendation] = []
        for row in await ctx.rule_rows("bans"):
            if str(row["subject_type"]) != "place" or not is_active(row, ctx.now):
                continue
            created = float(row["created_at"])
            window = facts.long_window(max(ctx.now - PLACE_LOOKBACK_S, created - PLACE_LOOKBACK_S), created)
            places = client_index(await ctx.clients(window, "place"))
            place = str(row["subject"])
            mine = places.get(place)
            if mine is None:
                continue
            requests = int(mine.get("requests") or 0)
            served = int(mine.get("served") or 0)
            if not requests or served * 100.0 / requests < served_pct:
                continue  # not legitimate by the FILTER-COLLATERAL measure
            ranking = sorted(places, key=lambda key: -int(places[key].get("served") or 0))
            rank = ranking.index(place) + 1
            if rank > TOP_PLACES:
                continue
            evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=requests)
            evidence.add("requests_before_ban", requests, "requests")
            evidence.add("served_before_ban", served, "requests")
            evidence.add("served_pct_before_ban", round(served * 100.0 / requests, 2), "percent")
            evidence.add("rank_by_served", rank)
            evidence.add("ban_hits", int(row.get("hits") or 0), "requests")
            evidence.links.append(f"{CLIENTS_LINK}?place={place}")
            hours = (window.end - window.start) / 3600
            out.append(
                self.recommendation(
                    ctx,
                    subject=f"place:{place}",
                    title=f"The ban on place {place} blocks one of the busiest legitimate experiences",
                    severity="warn",
                    confidence="high",
                    explanation=(
                        f"In the {hours:g} hours before the ban (created {iso(created)}) place {place} sent "
                        f"{requests:,} requests, {served * 100.0 / requests:.1f}% of them served, the #{rank} place by "
                        "served requests. Since "
                        f"then the ban refused {int(row.get('hits') or 0):,} requests. Place ids are claims, so a "
                        "scraper may have used this id, but the ban now blocks the real game; remove it and limit the "
                        "scraper by address or User-Agent instead."
                    ),
                    evidence=evidence,
                    changes=[
                        ProposedChange(
                            "ban_remove",
                            table="bans",
                            match={"subject_type": "place", "subject": place},
                            current=dict(row),
                        )
                    ],
                    expected_impact=(
                        f"The game's requests (about {per_hour(requests, hours * HOUR_S):,} an hour before the ban) "
                        "are served again."
                    ),
                    risk="medium",
                )
            )
        return out


# ------------------------------------------------------------------------------------------------ FILTER-COLLATERAL


@register
class FilterCollateral(Rule):
    """A filter is refusing legitimate traffic.

    Fires for each enabled abuse filter (User-Agent, header, endpoint block or endpoint rule) that refused requests in
    the last hour from a place whose other traffic (everything the filter did not refuse) was more than `served_pct`
    percent served. Refusals are tied to a filter by their reason and endpoint template (endpoint blocks and rules by
    pattern; a User-Agent or header refusal only when one such filter exists). The change removes the filter; narrow it
    instead if part of it is still needed.
    """

    id = "FILTER-COLLATERAL"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=COLLATERAL_WINDOW_MIN)
        groups = await facts.refusal_groups(ctx, window, reasons=FILTER_REASONS.values())
        if not groups:
            return []
        served_pct = self.param(ctx, "served_pct")
        places = client_index(await ctx.clients(window, "place"))
        out: list[Recommendation] = []
        for table, reason in FILTER_REASONS.items():
            rows = [r for r in await ctx.rule_rows(table) if r.get("enabled", 1)]
            if not rows:
                continue
            refused: dict[Any, dict[str, int]] = {}
            for group in groups:
                if group["reason"] != reason or not group["place"]:
                    continue
                owner = _owner(table, rows, group["endpoint_template"])
                if owner is None:
                    continue
                by_place = refused.setdefault(owner["id"], {})
                by_place[str(group["place"])] = by_place.get(str(group["place"]), 0) + int(group["count"])
            for row in rows:
                harmed = _collateral_places(refused.get(row["id"], {}), places, served_pct)
                if harmed:
                    out.append(self._recommend(ctx, window, table, row, harmed, served_pct))
        return out

    def _recommend(
        self,
        ctx: InsightContext,
        window: Any,
        table: str,
        row: Mapping[str, Any],
        harmed: Sequence[dict[str, Any]],
        served_pct: float,
    ) -> Recommendation:
        refused = sum(item["refused_by_filter"] for item in harmed)
        label = filter_label(table, row)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=refused)
        evidence.add("legitimate_places_refused", len(harmed), "places")
        evidence.add("requests_refused_from_them", refused, "requests")
        evidence.add("best_served_pct", max(item["served_pct"] for item in harmed), "percent")
        evidence.details["places"] = list(harmed[:20])
        evidence.links.append(f"{PROTECTION_LINK}#filters")
        names = ", ".join(str(item["place"]) for item in harmed[:5])
        return self.recommendation(
            ctx,
            subject=f"{table}:{row['id']}",
            title=f"The {label} refuses {len(harmed)} legitimate place(s)",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last hour the {label} refused {refused:,} requests from {len(harmed)} place(s) ({names}) "
                f"whose other traffic was more than {served_pct:g}% served, so they look like real games, not "
                "abusers. The change removes the filter; if it still stops an abuser, replace it with a narrower one "
                "(an address ban or a User-Agent rule for that client)."
            ),
            evidence=evidence,
            changes=[ProposedChange("filter_remove", table=table, match=filter_match(table, row), current=dict(row))],
            expected_impact=(
                f"About {per_hour(refused, window.end - window.start):,} requests an hour from these games are served "
                "again."
            ),
            risk="medium",
        )


def _owner(table: str, rows: Sequence[Mapping[str, Any]], template: str | None) -> Mapping[str, Any] | None:
    """The filter row a refusal of `table`'s reason on `template` belongs to, or None when it cannot be told."""
    if table not in PATTERN_TABLES:
        return rows[0] if len(rows) == 1 else None
    if not template:
        return None
    matching = [r for r in rows if compile_pattern(str(r["pattern"]), str(r.get("type") or "glob")).matches(template)]
    if not matching:
        return None
    # Endpoint rules apply the single most specific match, ties to the lowest id (rules/match.py best_match); every
    # matching block refuses, and the most specific one is the one an admin would narrow.
    matching.sort(key=lambda r: (specificity(str(r["pattern"]), str(r.get("type") or "glob")), -int(r["id"])))
    return matching[-1]


def _collateral_places(
    refused: Mapping[str, int], places: Mapping[str, Mapping[str, Any]], served_pct: float
) -> list[dict[str, Any]]:
    """Places refused by one filter whose other traffic was more than `served_pct` percent served."""
    out = []
    for place, count in sorted(refused.items()):
        row = places.get(place)
        if row is None:
            continue
        other = int(row.get("requests") or 0) - count
        served = int(row.get("served") or 0)
        if other <= 0:
            continue
        share = served * 100.0 / other
        if share > served_pct:
            out.append(
                {"place": place, "refused_by_filter": count, "other_requests": other, "served_pct": round(share, 2)}
            )
    return out


# ------------------------------------------------------------------------------------------------ TARPIT-TUNE


@register
class TarpitTune(Rule):
    """The tarpit is saturated, or holding refused clients does not slow them down.

    Reads the tarpit totals of the last hour. When held clients come back almost as fast as unheld ones (their
    arrival gap is less than 50% longer), holding only costs sockets: the change halves the hold range. Otherwise,
    when more than `skipped_pct` percent of the eligible holds were skipped because every slot was taken, the change
    raises the term that caps the slots (`tarpit_max_concurrent`, or `tarpit_max_capacity_fraction` when it is the
    smaller), staying out of high-risk values. Global settings: never auto-applied.
    """

    id = "TARPIT-TUNE"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        data = await ctx.providers.tarpit()
        if not data or not int(ctx.setting("tarpit_enabled")):
            return []
        eligible = int(data.get("eligible_holds") or 0)
        skipped = int(data.get("skipped") or 0)
        holds = int(data.get("holds") or 0)
        with_hold = None if data.get("gap_with_hold_s") is None else float(data["gap_with_hold_s"])
        without_hold = None if data.get("gap_without_hold_s") is None else float(data["gap_without_hold_s"])
        window = ctx.window(seconds=HOUR_S)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=max(eligible, holds))
        evidence.add("eligible_holds", eligible, "requests")
        evidence.add("holds", holds, "requests")
        evidence.add("skipped", skipped, "requests")
        if eligible:
            evidence.add("skipped_pct", round(skipped * 100.0 / eligible, 2), "percent")
        if with_hold is not None:
            evidence.add("gap_with_hold_s", with_hold, "seconds")
        if without_hold is not None:
            evidence.add("gap_without_hold_s", without_hold, "seconds")
        evidence.links.append(f"{PROTECTION_LINK}#tarpit")
        # Held clients that come back barely later than unheld ones are not slowed down: holding is useless.
        if (
            holds > 0
            and with_hold is not None
            and without_hold is not None
            and with_hold < without_hold * (1 + GAP_GAIN_MIN)
        ):
            rec = self._lower(ctx, evidence, with_hold, without_hold, holds)
            return [rec] if rec is not None else []
        if eligible and skipped * 100.0 / eligible > self.param(ctx, "skipped_pct"):
            rec = self._raise(ctx, evidence, eligible, skipped, holds)
            return [rec] if rec is not None else []
        return []

    def _lower(
        self, ctx: InsightContext, evidence: Evidence, with_hold: float, without_hold: float, holds: int
    ) -> Recommendation | None:
        low, high = int(ctx.setting("tarpit_min_seconds")), int(ctx.setting("tarpit_max_seconds"))
        new_low = int(lowest_allowed("tarpit_min_seconds", low // 2))
        new_high = int(lowest_allowed("tarpit_max_seconds", max(new_low, high // 2)))
        changes: list[ProposedChange] = []
        if new_high < high:
            changes.append(setting_change(ctx, "tarpit_max_seconds", new_high))
        if new_low < low:
            changes.append(setting_change(ctx, "tarpit_min_seconds", new_low))
        if not changes and str(ctx.setting("tarpit_default_type")) == "hold":
            changes.append(setting_change(ctx, "tarpit_default_type", "jitter"))
        if not changes:
            return None
        return self.recommendation(
            ctx,
            subject="tarpit",
            title="Holding refused clients does not slow them down: hold for less time",
            severity="info",
            confidence="medium",
            explanation=(
                f"In the last hour the tarpit held {holds:,} refusals, but a held client came back after "
                f"{with_hold:g} s on average against {without_hold:g} s when not held: it opens new connections "
                f"instead of waiting. Holds of {low} to {high} s only tie up sockets, so the change halves the hold "
                "range."
            ),
            evidence=evidence,
            changes=changes,
            expected_impact=(
                f"About half the socket time the tarpit spends on {holds:,} holds an hour, with no change for callers."
            ),
            risk="low",
        )

    def _raise(
        self, ctx: InsightContext, evidence: Evidence, eligible: int, skipped: int, holds: int
    ) -> Recommendation | None:
        current = int(ctx.setting("tarpit_max_concurrent"))
        fraction = float(ctx.setting("tarpit_max_capacity_fraction"))
        budget = int(ctx.setting("tarpit_connection_budget"))
        by_budget = math.floor(budget * fraction)
        effective = min(current, by_budget)
        needed = math.ceil(effective * eligible / max(1, holds))
        evidence.add("effective_slots", effective, "holds")
        evidence.add("slots_needed", needed, "holds")
        changes: list[ProposedChange] = []
        if needed > current:
            proposed = int(highest_safe("tarpit_max_concurrent", needed))
            if proposed > current:
                changes.append(setting_change(ctx, "tarpit_max_concurrent", proposed))
        if needed > by_budget and budget:
            proposed_fraction = highest_safe("tarpit_max_capacity_fraction", math.ceil(needed * 100 / budget) / 100)
            if proposed_fraction > fraction:
                changes.append(setting_change(ctx, "tarpit_max_capacity_fraction", proposed_fraction))
        if not changes:
            return None
        share = skipped * 100.0 / eligible
        return self.recommendation(
            ctx,
            subject="tarpit",
            title=f"The tarpit skipped {share:.1f}% of its holds: give it more slots",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last hour {skipped:,} of {eligible:,} refusals that should have been held ({share:.1f}%) were "
                f"answered at once because all {effective} slots were taken. Holding works here (held clients come "
                f"back much later), so about {needed} slots would hold them all. A hold is a sleeping task, cheap for "
                "an async worker; the change stays out of the high-risk range."
            ),
            evidence=evidence,
            changes=changes,
            expected_impact=f"About {skipped:,} more abusive requests an hour are held instead of answered at once.",
            risk="medium",
        )


# ------------------------------------------------------------------------------------------------ THROTTLE-TUNE


@register
class ThrottleTune(Rule):
    """The per-IP request limit looks too tight or too loose.

    Too tight: more than `legit_throttled_pct` percent of the legitimate addresses seen in the last 24 hours (bot score
    at or under `bot_score_legit_max`) were refused at least once; the change raises `allowed_requests_per_minute` by
    half, below its high-risk value. Too loose: in the last hour some callers got `upstream_busy` while the three
    clients that reached Roblox most often took more than half of the sampled upstream calls; the change lowers the
    limit so those three together can take at most what everyone else takes. Fairness only: the global and endpoint
    buckets already cap what reaches Roblox, so this does not reduce Roblox 429s.
    """

    id = "THROTTLE-TUNE"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        loose = await self._too_loose(ctx)
        if loose is not None:
            return [loose]
        tight = await self._too_tight(ctx)
        return [tight] if tight is not None else []

    async def _too_tight(self, ctx: InsightContext) -> Recommendation | None:
        scores = await scores_of(ctx)
        if not scores:
            return None
        window = ctx.window(seconds=TIGHT_WINDOW_S)
        legit_max = float(ctx.setting("bot_score_legit_max"))
        clients = client_index(await ctx.clients(window, "ip"))
        legit = {ip: row for ip, row in clients.items() if ip in scores and scores[ip] <= legit_max}
        if not legit:
            return None
        refused = sorted(ip for ip, row in legit.items() if int(row.get("refused") or 0) > 0)
        share = len(refused) * 100.0 / len(legit)
        if share <= self.param(ctx, "legit_throttled_pct"):
            return None
        current = int(ctx.setting("allowed_requests_per_minute"))
        proposed = int(highest_safe("allowed_requests_per_minute", math.ceil(current * (1 + LIMIT_STEP))))
        if proposed > current:
            change = setting_change(ctx, "allowed_requests_per_minute", proposed)
            what = f"raises allowed_requests_per_minute from {current} to {proposed} per window"
        else:
            reset = int(ctx.setting("throttle_reset_duration"))
            shorter = int(lowest_allowed("throttle_reset_duration", math.floor(reset * (1 - LIMIT_STEP))))
            if shorter >= reset:
                return None
            change = setting_change(ctx, "throttle_reset_duration", shorter)
            what = f"shortens throttle_reset_duration from {reset} s to {shorter} s"
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=len(legit))
        evidence.add("legitimate_addresses", len(legit), "addresses")
        evidence.add("legitimate_addresses_refused", len(refused), "addresses")
        evidence.add("legitimate_refused_pct", round(share, 2), "percent")
        evidence.add("refusals_of_legitimate", sum(int(legit[ip].get("refused") or 0) for ip in refused), "requests")
        evidence.details["sample_refused_addresses"] = refused[:20]
        evidence.links.append(f"{PROTECTION_LINK}#throttle")
        return self.recommendation(
            ctx,
            subject="per_ip_limit",
            title=f"The per-IP limit refused {share:.1f}% of legitimate clients today",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last 24 hours {len(refused)} of {len(legit)} legitimate addresses (bot score at or under "
                f"{legit_max:g}) were refused at least once. The change {what}. Bots are not counted, and a place "
                "limit remains the tool for one experience that sends too much."
            ),
            evidence=evidence,
            changes=[change],
            expected_impact=(
                f"Fewer refusals for {len(refused)} legitimate addresses a day. It does not reduce Roblox 429s: the "
                "global and endpoint buckets already cap what reaches Roblox."
            ),
            risk="medium",
        )

    async def _too_loose(self, ctx: InsightContext) -> Recommendation | None:
        window = ctx.window(minutes=LOOSE_WINDOW_MIN)
        busy = int((await ctx.totals(window, {"reason_code": "upstream_busy"})).get("requests") or 0)
        if not busy:
            return None
        sampled = await facts.sampled_upstream(ctx, window, "client_hash")
        total = int(sampled["total"])
        groups = sorted(sampled["groups"].values(), reverse=True)
        if not total or len(groups) <= LOOSE_TOP_CLIENTS:
            return None
        top = groups[:LOOSE_TOP_CLIENTS]
        share = sum(top) / total
        if share <= LOOSE_SHARE:
            return None
        current = int(ctx.setting("allowed_requests_per_minute"))
        reset = int(ctx.setting("throttle_reset_duration"))
        windows = (window.end - window.start) / max(1, reset)
        others_per_window = (total - sum(top)) / windows
        proposed = max(1, math.floor(others_per_window / LOOSE_TOP_CLIENTS))
        if proposed >= current:
            return None
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=total)
        evidence.add("upstream_busy_refusals", busy, "requests")
        evidence.add("sampled_upstream_requests", total, "requests")
        evidence.add("top_clients_share", round(share, 4))
        evidence.add("top_clients_requests", sum(top), "requests")
        evidence.add("clients_reaching_roblox", len(groups), "clients")
        evidence.details["top_clients_requests"] = top
        evidence.links.append(f"{PROTECTION_LINK}#throttle")
        return self.recommendation(
            ctx,
            subject="per_ip_limit",
            title=f"{LOOSE_TOP_CLIENTS} clients took {share:.0%} of the upstream calls while others got upstream_busy",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last hour the {LOOSE_TOP_CLIENTS} busiest clients made {sum(top):,} of the {total:,} sampled "
                f"requests that reached Roblox ({share:.0%}) while {busy:,} requests from others failed with "
                f"upstream_busy. With allowed_requests_per_minute at {current} per {reset} s nothing stops a few "
                f"clients from taking the slots. At {proposed} per window those {LOOSE_TOP_CLIENTS} can take at most "
                "what everyone else takes; give a trusted partner a bypass entry instead of a loose global limit."
            ),
            evidence=evidence,
            changes=[setting_change(ctx, "allowed_requests_per_minute", proposed)],
            expected_impact=(
                f"Fairer sharing of upstream slots: most of the {busy:,} upstream_busy refusals an hour should go. "
                "It does not reduce Roblox 429s: the buckets already cap what reaches Roblox."
            ),
            risk="medium",
        )


# ------------------------------------------------------------------------------------------------ PLACE-HEAVY


@register
class PlaceHeavy(Rule):
    """One experience (place id) takes most of the upstream calls.

    Fires for each place whose share of the requests that reached Roblox (request samples) over the last
    `window_min` minutes is above `share_pct` percent. The change is a per-place endpoint rule on the endpoint that
    place calls most, capping every place at `share_pct` percent of the current upstream rate there (or, when that
    endpoint already has a rule, turning on the place limit). Never a ban: place ids are claims anyone can send. This
    is about fairness between experiences and fewer `upstream_busy` refusals for others, not fewer Roblox 429s.
    """

    id = "PLACE-HEAVY"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        minutes = self.param(ctx, "window_min")
        window = ctx.window(minutes=minutes)
        sampled = await facts.sampled_upstream(ctx, window, "place")
        total = int(sampled["total"])
        if not total:
            return []
        threshold = self.param(ctx, "share_pct")
        out: list[Recommendation] = []
        for place, count in sorted(sampled["groups"].items()):
            if not place or place in ("other", OTHER):
                continue
            share = count * 100.0 / total
            if share > threshold:
                out.append(await self._recommend(ctx, window, place, count, total, share, threshold))
        return out

    async def _recommend(
        self, ctx: InsightContext, window: Any, place: str, count: int, total: int, share: float, threshold: float
    ) -> Recommendation:
        minutes = (window.end - window.start) / 60
        templates = await facts.sampled_place_templates(ctx, window, place)
        template = max(templates, key=lambda t: templates[t]) if templates else ""
        cap = max(1, math.ceil(total / minutes * threshold / 100))
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=count)
        evidence.add("place_upstream_requests", count, "requests")
        evidence.add("all_upstream_requests", total, "requests")
        evidence.add("place_share_pct", round(share, 2), "percent")
        evidence.add("place_rate_per_min", round(count / minutes, 1), "per minute")
        evidence.details["top_endpoints"] = dict(sorted(templates.items(), key=lambda kv: -kv[1])[:5])
        sample_pct = float(ctx.setting("request_sample_pct"))
        if sample_pct < FULL_SAMPLING_PCT:
            evidence.details["note"] = (
                f"Counts come from request samples taken at {sample_pct:g}% (shares stay unbiased)."
            )
        evidence.links.append(f"{CLIENTS_LINK}?place={place}")
        # The template's own endpoint rule (the exact regex a recommendation writes, or the legacy v1 glob), and a
        # new one for exactly this template, so it refuses what `would_be_refused` counts and nothing below it
        # (finding insights-8).
        rows = await ctx.rule_rows("rules_endpoint_limit") if template else []
        existing = next((r for r in rows if names_template(str(r["pattern"]), str(r["type"]), template)), None)
        refused = 0
        if template and existing is None:
            per_minute = await facts.sampled_upstream_minutes(ctx, window, place, template)
            refused = sum(max(0, n - cap) for n in per_minute.values())
            evidence.add("would_be_refused", refused, "requests")
            match = template_match(template)
            changes = [
                ProposedChange(
                    "rule_upsert",
                    table="rules_endpoint_limit",
                    match=dict(match),
                    current=None,
                    proposed={
                        **match,
                        "scope": "place",
                        "limit": cap,
                        "period": PLACE_RULE_PERIOD_S,
                        "note": f"PLACE-HEAVY: place {place} took {share:.0f}% of upstream calls",
                    },
                )
            ]
            what = (
                f"a per-place endpoint rule on {template}: every place may make {cap} requests a minute there "
                f"({threshold:g}% of the current upstream rate); place {place} peaked above that"
            )
            impact = (
                f"About {refused:,} of place {place}'s {count:,} upstream calls in the last {minutes:g} minutes would "
                "have been refused, leaving slots for other experiences."
            )
        elif not int(ctx.setting("place_limit_enabled")):
            changes = [setting_change(ctx, "place_limit_enabled", 1)]
            limit = ctx.setting("place_limit_per_minute")
            what = (
                f"turning on the place limit ({limit} requests a minute per place, keyed the forger-safe way) because "
                "that endpoint already has a rule"
            )
            impact = f"Place {place} is held to the place limit; other experiences get more upstream slots."
        else:
            changes = [ProposedChange("manual", text=f"Lower the endpoint rule on {template} or the place limit.")]
            what = "a manual review: the endpoint already has a rule and the place limit is on"
            impact = "The admin decides; nothing changes until then."
        return self.recommendation(
            ctx,
            subject=f"place:{place}",
            title=f"Place {place} made {share:.1f}% of the upstream calls",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last {minutes:g} minutes place {place} made {count:,} of the {total:,} sampled requests that "
                f"reached Roblox ({share:.1f}%, threshold {threshold:g}%), mostly to "
                f"{template or 'several endpoints'}. The change is {what}. Place ids are claims, so Roxy never bans a "
                "place."
            ),
            evidence=evidence,
            changes=changes,
            expected_impact=impact + " It does not reduce Roblox 429s: the buckets already cap what reaches Roblox.",
            risk="medium",
        )


__all__ = [
    "AbuseBot",
    "AbuseDist",
    "AbuseSpam",
    "FilterAdd",
    "FilterCollateral",
    "FilterRemove",
    "PlaceHeavy",
    "TarpitTune",
    "ThrottleTune",
    "access_match",
    "ban_change",
    "bypass_rows",
    "highest_safe",
    "is_active",
    "setting_change",
]
