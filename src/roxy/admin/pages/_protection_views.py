"""Plain helpers of the Protection page: labels, the pipeline model, the repeat offender timeline, tarpit tiles.

What this is
    Pure functions (no I/O) the Protection page module (`roxy/admin/pages/protection.py`) uses to turn the admin API
    answers into what its templates show:
      * `REASON_LABELS`, `reason_label(code)`, `MESSAGE_SOURCE_LABELS`, `message_split(...)`: the words for refusal
        reason codes and for where a refusal's text came from (parity row 116: custom message or default text).
      * `pipeline_model(answer)`: the pipeline diagram (plan 10.9): every check in order with its refusals in the
        range, the share of the busiest check (drawn as a <meter>), what it refuses, whether bypass skips it, and the
        card that controls it.
      * `offender_timeline(...)`: v1's "What happens to a repeat offender, using your current ladder" (v1 notes 7.2,
        plan 14.7), from the saved ladder and the live settings, in plain words.
      * `span_words(seconds)`: v1's `fmtSpan` ("1 minute 40s", "3 hours 20m"), used by the timeline and the tables.
      * `tarpit_tiles(...)`: the four tarpit tiles of v1 (Requests Held, Average Hold, Time Between Requests, Held In
        Last Hour) from the fleet's hold statistics, with their v1 sub-lines.
      * Small cell builders for the tables (`yes_no`, `limit_text`, `rule_text`, ...).

Why it exists
    The page module stays a list of card renderers that call the admin API's own helpers (one source of truth per
    number, DESIGN.md 13); the wording and arithmetic that only the page needs lives here, where it can be tested
    without a database. Every text follows plan C5 (no dash characters) and keeps v1's meaning (parity row 87).

How it works
    Inputs are the API answers as plain dicts; outputs are dicts and strings for Jinja. Nothing here is caller text
    except what callers sent, which the templates render with `format.html caller_text`.

What to read next
    `roxy/admin/pages/protection.py`, `roxy/admin/api/protection.py`, `.remake/v1notes/dashboard.md` sections 4.3,
    4.11 and 7.2.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

REASON_LABELS: Final[dict[str, str]] = {
    "paused": "Paused",
    "banned": "Banned",
    "deny_list": "Deny list",
    "flood": "Flood limit",
    "spam": "Spam detector",
    "throttle_all": "Emergency limit (throttle-all)",
    "throttle": "Per-IP throttle",
    "place_limit": "Place limit",
    "user_agent_rule": "User-Agent rule",
    "ignored_path": "Ignored path",
    "unsafe_url": "Unsafe URL",
    "not_roblox": "Not a Roblox URL",
    "host_not_allowed": "Host not allowed",
    "auth_smuggling": "Sent a credential (auth smuggling)",
    "header_rule": "Request filter",
    "endpoint_blocked": "Endpoint block",
    "endpoint_rule": "Endpoint rule",
    "body_too_large": "Body too large",
    "headers_too_large": "Headers too large",
    "url_too_long": "URL too long",
    "method_not_allowed": "Method not allowed",
    "challenge": "Browser challenge",
    "bot_score": "Bot score block",
    "upstream_cooldown": "Roblox cooldown",
    "upstream_busy": "Upstream busy",
    "queue_overflow": "Upstream queue full",
    "upstream_5xx": "Roblox server error",
    "upstream_timeout": "Roblox timed out",
    "upstream_connect": "Could not reach Roblox",
    "deadline": "Deadline passed",
    "coalesce_timeout": "Waited too long for a shared answer",
    "egress_disabled": "Egress switched off",
    "credential_unavailable": "Credential unavailable",
    "degraded": "Shared state unavailable",
    "leak_blocked": "Leak guard",
    "internal_error": "Internal error",
}
"""Plain words for the refusal and failure reason codes (`core/reasons.py`); an unknown code shows as itself."""

REASON_CARDS: Final[dict[str, str]] = {
    "banned": "bans",
    "deny_list": "lists",
    "flood": "limits",
    "spam": "spam",
    "throttle_all": "throttle-all",
    "throttle": "throttle",
    "place_limit": "places",
    "user_agent_rule": "ua-rules",
    "ignored_path": "ignored-paths",
    "header_rule": "request-filters",
    "endpoint_blocked": "endpoint-blocks",
    "endpoint_rule": "endpoint-rules",
    "body_too_large": "limits",
    "headers_too_large": "limits",
    "url_too_long": "limits",
    "challenge": "challenge",
    "bot_score": "bot",
}
"""The card of this page that controls each refusal reason (the others are failures or probes, shown elsewhere)."""

CHECK_CARDS: Final[dict[str, str]] = {
    "bans": "bans",
    "bypass": "bypass",
    "flood": "limits",
    "spam": "spam",
    "throttle_all": "throttle-all",
    "throttle": "throttle",
    "place_limit": "places",
    "challenge": "challenge",
    "bot_score": "bot",
    "user_agent_rule": "ua-rules",
    "ignored_path": "ignored-paths",
    "header_rule": "request-filters",
    "endpoint_blocked": "endpoint-blocks",
    "endpoint_rule": "endpoint-rules",
}
"""The card that controls each pipeline check (pause lives in the top bar; probes are on the Security page)."""

CHECK_ELSEWHERE: Final[dict[str, tuple[str, str]]] = {
    "pause": ("The Pause button in the top bar", ""),
    "unsafe_url": ("Security > Probes", "/admin/security#probes"),
    "not_roblox": ("Security > Probes", "/admin/security#probes"),
    "auth_smuggling": ("Security > Probes", "/admin/security#probes"),
}

KIND_LABELS: Final[dict[str, str]] = {
    "static": "Fixed check",
    "limiter": "Rate limit",
    "marker": "Marks the request",
}

MESSAGE_SOURCE_LABELS: Final[dict[str, str]] = {
    "custom": "custom message",
    "default": "default text",
    "roxy": "Roxy's failure text",
    "roblox": "Roblox's own body",
}
"""Where a refusal's body came from (row 116): a message an admin wrote, the built-in text, or Roblox's answer."""

RULE_TABLE_LABELS: Final[dict[str, str]] = {
    "rules_user_agent": "User-Agent rules",
    "rules_header": "Request filters",
    "rules_endpoint_block": "Endpoint blocks",
    "rules_endpoint_limit": "Endpoint rules",
    "access_list": "Deny list and bypass entries",
    "bans": "Bans",
}

SCOPE_LABELS: Final[dict[str, str]] = {"key": "Header name", "value": "Header value", "either": "Name or value"}
"""v1 `HEADER_SCOPE_LABELS`."""
MODE_LABELS: Final[dict[str, str]] = {"contains": "Contains", "exact": "Exact", "regex": "Regex"}
"""v1 `HEADER_MODE_LABELS`."""
TYPE_LABELS: Final[dict[str, str]] = {"glob": "Wildcard", "regex": "Regex"}
"""v1 `typeBadge`: a glob pattern is a "Wildcard"."""
UA_SCOPE_LABELS: Final[dict[str, str]] = {"ip": "Per IP", "global": "Shared by all IPs"}
RULE_SCOPE_LABELS: Final[dict[str, str]] = {"ip": "Per IP", "place": "Per experience", "global": "Shared by everyone"}

DETECTOR_SIGNALS: Final[dict[str, tuple[str, str]]] = {
    "rate": ("Sustained request rate", "More than 5 times the per-IP limit rate for 10 minutes; bans for 1 hour."),
    "refused": ("Keeps sending while refused", "More than 200 refused requests in 10 minutes; bans for 30 minutes."),
    "probe": ("Probe paths", "5 or more probes (non-Roblox or unsafe paths) in 10 minutes; bans for 1 hour."),
    "auth": ("Auth smuggling attempts", "3 or more attempts to send a credential in an hour; bans for 1 hour."),
    "enum": (
        "Sequential id enumeration",
        "More than 500 distinct ids on one endpoint in 10 minutes; recommends an endpoint rule instead of banning.",
    ),
    "bust": (
        "Cache busting",
        "Almost every request has a unique query value (over 90% of 200); recommends ignoring the parameter.",
    ),
    "dist": (
        "Distributed burst",
        "More than 50 addresses with one User-Agent hitting one endpoint over 1,000 times in 5 minutes; recommends "
        "a shared User-Agent rule.",
    ),
}
"""Plan 10.3: what each spam detector watches and its shipped default (the live values are its settings)."""

TARPIT_CATEGORY_NOTES: Final[dict[str, str]] = {
    "header_rule": "Traffic you fingerprinted. Safest to hold.",
    "probe": "Scanners and junk paths. Never a real caller.",
    "throttle": "Careful: also catches ordinary users who went too fast.",
    "throttle_all": "Careful: also catches ordinary users.",
    "endpoint_rule": "Careful: also catches ordinary users.",
    "blocked_endpoint": "Careful: may catch a caller who just wants that endpoint.",
    "auth_attempt": "Never valid here, but sometimes a genuine mistake.",
    "user_agent_rule": "Usually cooperative bots being asked to slow down; holding them punishes a client that would "
    "have obeyed the limit anyway.",
    "ban": "Clients you banned or denied. They already cannot get an answer.",
    "spam": "Clients a spam detector flagged.",
    "upstream_cooldown_retry": "A caller retrying the same request inside the Retry-After it was given; held with a "
    "short jitter.",
}
"""v1's tarpit category descriptions (v1 notes 4.11), with the categories v2 added (plan 10.6)."""

BOT_SIGNAL_NOTES: Final[dict[str, tuple[str, str]]] = {
    "library_ua": ("Library or missing User-Agent", "1 when the User-Agent is python-requests, curl, Go or empty."),
    "no_roblox_signature": (
        "No Roblox game server signature",
        "1 when the Roblox-Id header and a Roblox User-Agent are missing (and, when the Roblox egress list is set, "
        "the address is outside it).",
    ),
    "probes": ("Probe history", "Probes in the last 24 hours divided by 5, at most 1."),
    "refusals": ("Refusal ratio", "Refused requests divided by all requests over the last hour."),
    "timing": ("Timing regularity", "1 when the gaps between requests are almost identical over 50 or more."),
    "header_order": ("Header order", "1 when the header order matches no known client family."),
    "cache_busting": ("Cache busting", "The share of unique query values over 200 requests."),
}
"""Plan 10.7: each bot score signal and how it is measured."""


# ============================================================================================ words and numbers


def reason_label(code: Any) -> str:
    text = str(code or "")
    return REASON_LABELS.get(text, text or "n/a")


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}" + ("" if n == 1 else "s")


def span_words(seconds: Any) -> str:
    """v1 `fmtSpan`: `45 seconds`, `1 minute`, `1 minute 40s`, `3 hours`, `3 hours 20m`, `2 days 4h`."""
    if isinstance(seconds, bool) or not isinstance(seconds, int | float):
        return "n/a"
    s = max(0, round(seconds))
    if s < 60:
        return plural(s, "second")
    if s < 3600:
        minutes, rest = divmod(s, 60)
        return plural(minutes, "minute") + (f" {rest}s" if rest else "")
    if s < 86_400:
        hours, rest = divmod(s, 3600)
        return plural(hours, "hour") + (f" {rest // 60}m" if rest // 60 else "")
    days, rest = divmod(s, 86_400)
    return plural(days, "day") + (f" {rest // 3600}h" if rest // 3600 else "")


def ordinal(n: int) -> str:
    """`1st`, `2nd`, `3rd`, `4th` (v1's rung labels used the first three and then `th`)."""
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def number(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "n/a"
    if float(value).is_integer():
        return f"{int(value):,}"
    return f"{value:,.2f}".rstrip("0").rstrip(".")


def message_split(source: Mapping[str, Any] | None) -> str:
    """`custom message 3, default text 10` (row 116); empty when the reason has no refusal text."""
    if not source:
        return ""
    parts = []
    for key, count in sorted(source.items(), key=lambda item: (-int(item[1] or 0), str(item[0]))):
        if int(count or 0):
            parts.append(f"{MESSAGE_SOURCE_LABELS.get(str(key), str(key))} {int(count):,}")
    return ", ".join(parts)


def limit_text(row: Mapping[str, Any]) -> str:
    """A User-Agent rule's limit in v1's words: `1 per 2 seconds` (cooldown) or `10 per 1 minute` (burst)."""
    if str(row.get("kind") or "burst") == "cooldown":
        cooldown = float(row.get("cooldown") or 0)
        text = f"{number(cooldown)} seconds" if not cooldown.is_integer() else span_words(cooldown)
        return f"1 per {text}"
    return f"{number(row.get('limit'))} per {span_words(row.get('period'))}"


def header_rule_text(row: Mapping[str, Any]) -> str:
    """v1 `describeRule`: `"User-Agent" value contains "curl"`, `Header name is "X-Bot"`."""
    header = str(row.get("header") or "")
    scope = str(row.get("scope") or "either")
    target = f'"{header}" value' if header else SCOPE_LABELS.get(scope, scope)
    verb = {"exact": "is", "regex": "matches"}.get(str(row.get("mode") or "contains"), "contains")
    return f'{target} {verb} "{row.get("needle") or ""}"'


def yes_no(value: Any, *, yes: str = "Yes", no: str = "No") -> dict[str, Any]:
    """A boolean cell that does not rely on color (words plus a tone)."""
    return {"text": yes if value else no, "tone": "ok" if value else "muted"}


# ============================================================================================ pipeline


def pipeline_model(answer: Mapping[str, Any]) -> dict[str, Any]:
    """The pipeline diagram's steps and totals from a `GET /protection/pipeline` answer (see the module docstring)."""
    checks = [dict(item) for item in answer.get("checks") or ()]
    busiest = max((int(item.get("refused") or 0) for item in checks), default=0)
    refused_total = int(answer.get("refused") or 0)
    steps = []
    for item in checks:
        name = str(item.get("name") or "")
        refused = int(item.get("refused") or 0)
        card = CHECK_CARDS.get(name)
        elsewhere = CHECK_ELSEWHERE.get(name)
        steps.append(
            {
                "name": name,
                "label": str(item.get("label") or name),
                "kind": KIND_LABELS.get(str(item.get("kind") or ""), str(item.get("kind") or "")),
                "refused": refused,
                "share_pct": round(refused * 100.0 / refused_total, 1) if refused_total else 0.0,
                "max": max(1, busiest),
                "reasons": [reason_label(code) for code in item.get("reasons") or ()],
                "skipped_by_bypass": bool(item.get("skipped_by_bypass")),
                "uses_patterns": bool(item.get("uses_patterns")),
                "tarpit_category": item.get("tarpit_category"),
                "href": f"/admin/protection#{card}" if card else (elsewhere[1] if elsewhere else ""),
                "where": f"This page: {card.replace('-', ' ')}" if card else (elsewhere[0] if elsewhere else ""),
                "marker": str(item.get("kind") or "") == "marker",
            }
        )
    rule_hits = [
        {"table": RULE_TABLE_LABELS.get(str(table), str(table)), "hits": int(hits or 0)}
        for table, hits in sorted((answer.get("rule_hits") or {}).items())
    ]
    ua = (answer.get("ua_rule_hits") or {}).get("total") or {}
    tiers = [
        {"rung": int(rung), "strikes": int(count or 0)}
        for rung, count in sorted((answer.get("throttle_tiers") or {}).items(), key=lambda item: int(item[0]))
    ]
    worker = answer.get("this_worker") or {}
    return {
        "steps": steps,
        "requests": int(answer.get("requests") or 0),
        "evaluated": int(answer.get("evaluated") or 0),
        "refused": refused_total,
        "other_refusals": int(answer.get("other_refusals") or 0),
        "by_checks": max(0, refused_total - int(answer.get("other_refusals") or 0)),
        "allowed": max(0, int(answer.get("evaluated") or 0) - refused_total),
        "rule_hits": rule_hits,
        "ua_allowed": int(ua.get("allowed") or 0),
        "ua_refused": int(ua.get("refused") or 0),
        "tiers": tiers,
        "worker": {
            "evaluated": int(worker.get("evaluated") or 0),
            "allowed": int(worker.get("allowed") or 0),
            "degraded_requests": int(worker.get("degraded_requests") or 0),
            "pattern_checks_skipped": int(worker.get("pattern_checks_skipped") or 0),
            "ladder_bans": int(worker.get("ladder_bans") or 0),
        },
    }


# ============================================================================================ repeat offender


def offender_timeline(
    rungs: Sequence[Mapping[str, Any]], *, base_s: int, escalation: bool, decay_s: int
) -> list[dict[str, str]]:
    """v1's "What happens to a repeat offender, using your current ladder" (v1 notes 7.2), step by step.

    Each step is `{"at": when, "what": plain text}`; the texts are v1's with the C5 replacements (a semicolon where
    v1 had a dash) and the v2 additions (a rung may ban instead of throttle, plan 10.4)."""
    base = span_words(base_s)
    if not escalation:
        return [
            {
                "at": "always",
                "what": f"Escalation is off, so every throttle lasts {base} no matter how many times the same caller "
                "earns one. The ladder below is kept, just unused.",
            }
        ]
    if not rungs:
        return [
            {
                "at": "always",
                "what": f"The ladder is empty, so every throttle is the plain {base} one. Add a rung below to make a "
                "repeat offender wait longer than a first-timer.",
            }
        ]
    steps = []
    for index, rung in enumerate(rungs, start=1):
        multiplier = float(rung.get("multiplier") or 1.0)
        message = str(rung.get("message") or "")
        told = f"“{message}”" if message else "nothing in particular; this rung has no message."
        if str(rung.get("action") or "throttle") == "ban":
            minutes = int(rung.get("ban_minutes") or 0)
            what = f"Is banned for {span_words(minutes * 60)} (an IP ban, never a place ban) and is told: {told}"
        else:
            what = (
                f"Waits {span_words(base_s * multiplier)} ({number(multiplier)} times the normal {base}) and is "
                f"told: {told}"
            )
        steps.append({"at": f"{ordinal(index)} strike", "what": what})
    tail = "The last rung repeats, so a caller who ignores the final warning keeps getting it. "
    if decay_s > 0:
        tail += f"Behaving for {span_words(decay_s)} drops them back down one rung at a time."
    else:
        tail += "Decay is off, so strikes stay until you forgive them by hand."
    steps.append({"at": "after that", "what": tail})
    return steps


# ============================================================================================ tarpit


def _seconds(value: Any) -> str:
    """v1 `fmtSeconds`: one decimal under 10 seconds, whole seconds under a minute, then words; "n/a" for none."""
    if value is None or isinstance(value, bool) or not isinstance(value, int | float):
        return "n/a"
    if value < 10:
        return f"{value:.1f}s"
    if value < 60:
        return f"{round(value)}s"
    return span_words(value)


def gap_trend(recent: Any, baseline: Any) -> str:
    """v1's trend sentence: is the hour's gap between a held caller's requests longer than usual?"""
    if not isinstance(recent, int | float) or not isinstance(baseline, int | float) or not baseline:
        return "Not enough data yet to compare."
    ratio = float(recent) / float(baseline)
    if ratio >= 1.15:
        return f"Backing off: {round((ratio - 1) * 100)}% longer between requests this hour than over the range."
    if ratio <= 0.85:
        return f"Speeding up: {round((1 - ratio) * 100)}% shorter between requests this hour."
    return "Holding steady; about the same request rate as over the range."


def tarpit_tiles(
    history: Mapping[str, Any], windows: Mapping[str, Mapping[str, Any]], state: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """The four v1 tiles (`Requests Held`, `Average Hold`, `Time Between Requests`, `Held In Last Hour`) from the
    fleet hold statistics of the range (`history`) and of the last 15 minutes, hour and day (`windows`)."""
    holds = int(history.get("holds") or 0)
    skipped = int(history.get("skipped") or 0)
    active = state.get("active_holds")
    cap = int(state.get("max_concurrent") or 0)
    w15, w60, w1440 = (windows.get(key) or {} for key in ("15m", "1h", "24h"))
    gap = history.get("gap_after_hold_s")
    worker_ips = len((state.get("stats") or {}).get("ips") or {})
    return [
        {
            "key": "tarpit_held",
            "label": "Requests held",
            "value": f"{holds:,}",
            "status": "warn" if skipped > holds and holds > 0 else None,
            "status_label": "More skipped than held" if skipped > holds and holds > 0 else None,
            "lines": [
                f"Skipped (at capacity): {skipped:,}",
                f"Holding right now: {'n/a' if active is None else f'{int(active):,}'} of {cap:,}",
            ],
            "help": "How many refused callers were made to WAIT for their error instead of getting it at once. "
            "Skipped is the number to watch: refusals let go at once because no hold slot was free. If it climbs, "
            "the capacity cap is the limit, not the abuser.",
        },
        {
            "key": "tarpit_average",
            "label": "Average hold",
            "value": _seconds(history.get("mean_hold_s")),
            "lines": [
                f"95% under: {_seconds(history.get('p95_hold_s'))}; longest: {_seconds(history.get('max_hold_s'))}",
                f"Total time held: {_seconds((history.get('mean_hold_s') or 0) * holds) if holds else 'n/a'}",
            ],
            "help": "How long a held caller waits, on average. Each hold is a random length inside the range you "
            "set, because a fixed delay is learnable: a caller could set a shorter timeout and stop waiting.",
        },
        {
            "key": "tarpit_gap",
            "label": "Time between requests",
            "value": _seconds(gap),
            "lines": [
                f"Last 15m: {_seconds(w15.get('gap_after_hold_s'))}; last hour: "
                f"{_seconds(w60.get('gap_after_hold_s'))}; last 24h: {_seconds(w1440.get('gap_after_hold_s'))}",
                f"After an instant refusal: {_seconds(history.get('gap_after_instant_s'))}. "
                + gap_trend(w60.get("gap_after_hold_s"), gap),
            ],
            "help": "The average gap before a held caller's next request: the number that says whether holding "
            "them slows them down. Compare it with the gap after an instant refusal; if the tarpit works, the gap "
            "after a hold is LONGER.",
        },
        {
            "key": "tarpit_hour",
            "label": "Held in the last hour",
            "value": f"{int(w60.get('holds') or 0):,}",
            "lines": [
                f"Last 15m: {int(w15.get('holds') or 0):,}; last 24h: {int(w1440.get('holds') or 0):,}",
                f"Distinct callers held (this worker): {worker_ips:,}",
            ],
            "help": "How many requests were held recently, so you can see whether this is happening now or "
            "happened days ago.",
        },
    ]


def tarpit_status(state: Mapping[str, Any]) -> tuple[str, str]:
    """v1's tarpit chip: `Off`, `On, but nothing selected` or `Holding N kinds` (tone, text)."""
    if not state.get("enabled"):
        return "neutral", "Off"
    categories = list(state.get("categories") or ())
    if not categories:
        return "bad", "On, but nothing selected"
    return "ok", f"Holding {plural(len(categories), 'kind')}"


HOLD_BOUND_LABELS: Final = "longer than 55 seconds"


def histogram_rows(histogram: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The hold length histogram as rows `{label, holds, max}` (the last bucket, `le_ms` -1, is the overflow)."""
    rows = []
    biggest = max((int(item.get("holds") or 0) for item in histogram), default=0)
    lower = 0
    for item in histogram:
        bound = int(item.get("le_ms") or 0)
        holds = int(item.get("holds") or 0)
        label = HOLD_BOUND_LABELS if bound < 0 else f"{_seconds(lower / 1000)} to {_seconds(bound / 1000)}"
        rows.append({"label": label, "holds": holds, "max": max(1, biggest)})
        if bound > 0:
            lower = bound
    return rows


__all__ = [
    "BOT_SIGNAL_NOTES",
    "CHECK_CARDS",
    "DETECTOR_SIGNALS",
    "MESSAGE_SOURCE_LABELS",
    "MODE_LABELS",
    "REASON_CARDS",
    "REASON_LABELS",
    "RULE_SCOPE_LABELS",
    "SCOPE_LABELS",
    "TARPIT_CATEGORY_NOTES",
    "TYPE_LABELS",
    "UA_SCOPE_LABELS",
    "gap_trend",
    "header_rule_text",
    "histogram_rows",
    "limit_text",
    "message_split",
    "offender_timeline",
    "ordinal",
    "pipeline_model",
    "plural",
    "reason_label",
    "span_words",
    "tarpit_status",
    "tarpit_tiles",
    "yes_no",
]
