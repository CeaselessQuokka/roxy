"""The Recommendations page (`/admin/recommendations`, plan 14.1, 11.1 to 11.4): review, preview, apply and undo.

What this is
    Every recommendation the insights engine made, and everything that can be done with one:
      * `list` (the page's main table): every recommendation with filter chips for state, severity, family and
        rule, search, paging and CSV or JSON export through the API. A row opens the detail drawer.
      * the detail drawer (`GET /admin/recommendations/detail?rec=<id>`, also opened by `?rec=<id>` on the page):
        severity, confidence and state in words, the explanation, the evidence (its window, numbers, links and
        charts of every timeline the rule recorded, each with a data table), the exact proposed changes as a diff
        (a new single-endpoint rule reads "exactly this endpoint"), the `safe_auto` badge (D7) or why auto-apply
        skips it, the watch window with its rollback state, every action taken on it, earlier recommendations
        with the same fingerprint, and the actions: Preview, Undo, Snooze (1 hour, 1 day, 1 week or a time) and
        Dismiss (the plan 11.3 reasons).
      * the preview panel (`GET /admin/recommendations/preview?rec=<id>&window=1h|6h|24h`, loaded into the drawer):
        the validated diff, what an apply needs (a reason and the high-risk confirmation, a fresh second factor),
        the dry run over sampled requests (scaled counts, the sampling note) and the Apply form, which sends the
        previewed `changes_digest` so nothing but what was shown is applied (409 `changed_since_preview` otherwise).
      * `history`: every apply, undo, snooze, dismiss, automatic apply and rollback (filters, export).
      * `rules`: the rule catalog with each rule's switch, severity override, open count and `safe_auto`; a row opens
        its "Tune this rule" drawer (`rule-<slug>`, fragment-only cards) with the rule's help text, its open
        recommendations and its catalog settings, edited inline.
      * `engine` and `preview-settings`: the engine's state (on or off, auto-apply, its last evaluation) and the
        catalog settings placed on these cards.
    `/admin/recommendations/<rec id>` redirects to `?rec=<id>` (the health report links recommendations that way).

Why it exists
    Plan 11.3 and P4: a recommendation is previewed, applied exactly as previewed, and undone exactly; plan 14.8: the
    owner can do it from a phone. Page routes only read: every action posts JSON to the Recommendations API
    (`static/js/api_forms.js`), which checks the digest, the risk rules, the fresh second factor and writes the audit
    log. Plan P6: the page reads through the API's own functions (`list_answer`, `history_answer`, `rule_rows`,
    `rules_answer`, `rule_summary`, `detail_answer`, `preview_answer`).

How it works
    `page = Page("recommendations", default_range="all")`: the list is not time-ranged, the top bar's range filters
    the History card by when an action happened ("All" shows everything). The drawer and the preview are extra GET
    routes on the page's router rendered through `kit.render_card` (so a failure shows in place, never as a 500).
    Every text a rule built from callers' paths (titles, subjects, explanations, expected impacts, change targets,
    evidence details, rollback reasons) renders through `format.html caller_text`. Sensitive setting values arrive
    redacted from the API helpers.

What to read next
    `roxy/admin/api/recommendations.py`, `roxy/insights/actions.py`, `templates/admin/pages/recommendations/*.html`,
    `static/js/pages/recommendations.js`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from roxy.admin.api import common
from roxy.admin.api import recommendations as rec_api
from roxy.admin.pages import fmt, registry
from roxy.admin.pages.kit import (
    MAX_FRAGMENT_PARAMS,
    CardDef,
    Page,
    PageAdmin,
    PageView,
    filter_chip,
    render_card,
    table_query,
    table_view,
)
from roxy.admin.pages.registry import CardSpec
from roxy.config import catalog
from roxy.config.insight_params import INSIGHT_RULES
from roxy.health import store as health_store
from roxy.insights import read_recommendations as reads
from roxy.insights import simulate
from roxy.insights.models import DISMISS_REASONS, SNOOZE_DURATIONS_S, STATES

page = Page(
    "recommendations",
    stream_events=("settings_changed", "recommendation", "alert"),
    default_range="all",
)
router = page.router

PAGE_PATH: Final = "/admin/recommendations"
LIST_TABLE_ID: Final = "recommendations-list"
HISTORY_TABLE_ID: Final = "recommendations-history"
RULES_TABLE_ID: Final = "recommendations-rules"
DETAIL_TEMPLATE: Final = "admin/pages/recommendations/detail.html"
PREVIEW_TEMPLATE: Final = "admin/pages/recommendations/preview.html"
RULE_TEMPLATE: Final = "admin/pages/recommendations/rule.html"
REC_ID_RE: Final = re.compile(rec_api.REC_ID_PATTERN)
MAX_VALUE_CHARS: Final = 600
MAX_DETAIL_CHARS: Final = 4000
MAX_CHART_POINTS: Final = 120
MAX_CHARTS: Final = 6

SEVERITY_WORDS: Final[dict[str, tuple[str, str]]] = {
    "critical": ("bad", "Critical"),
    "warn": ("warn", "Warning"),
    "info": ("info", "Info"),
}
STATE_WORDS: Final[dict[str, str]] = {
    "open": "Open",
    "snoozed": "Snoozed",
    "applied": "Applied",
    "auto_applied": "Applied automatically",
    "rolled_back": "Rolled back",
    "dismissed": "Dismissed",
    "resolved": "Resolved on its own",
    "expired": "Expired",
}
ACTION_WORDS: Final[dict[str, str]] = {
    "apply": "Applied",
    "undo": "Undone",
    "snooze": "Snoozed",
    "dismiss": "Dismissed",
    "auto_apply": "Applied automatically",
    "auto_rollback": "Rolled back automatically",
}
CHANGE_WORDS: Final[dict[str, str]] = {
    "setting": "Setting",
    "bucket_override": "Upstream bucket for one endpoint or host",
    "rule_upsert": "Add or change a rule",
    "rule_delete": "Remove a rule",
    "filter_add": "Add a request filter",
    "filter_remove": "Remove a request filter",
    "ban_add": "Ban",
    "ban_remove": "Lift a ban",
    "bypass_add": "Add a bypass entry",
    "bypass_remove": "Remove a bypass entry",
    "ignored_param_add": "Ignore a cache key parameter",
    "tarpit_category": "Tarpit category",
    "routing_rule": "Routing rule",
    "credential_allowlist_remove": "Remove from the credential allowlist",
    "host_add": "Allow a Roblox host",
    "manual": "Manual step (cannot be applied by Roxy)",
}
TABLE_WORDS: Final[dict[str, str]] = {
    "rules_cache": "cache rule",
    "rules_endpoint_limit": "endpoint rule",
    "rules_endpoint_block": "endpoint block",
    "rules_user_agent": "User-Agent rule",
    "rules_header": "request filter",
    "rules_routing": "routing rule",
    "upstream_limits": "upstream limit",
    "credential_allowlist": "credential allowlist row",
    "access_list": "access list entry",
    "bans": "ban",
    "cache_ignored_params": "ignored parameter",
}
WATCH_WORDS: Final[dict[str, str]] = {
    "watching": "Watching",
    "kept": "Kept: the guard numbers stayed within bounds",
    "rolled_back": "Rolled back automatically",
    "canceled": "Ended: the change was undone by hand",
}
FAMILY_WORDS: Final[dict[str, str]] = {family: family.capitalize() for family in rec_api.FAMILIES}
TONE_OF_STATE: Final[dict[str, str]] = {
    "open": "info",
    "snoozed": "muted",
    "applied": "ok",
    "auto_applied": "ok",
    "rolled_back": "warn",
    "dismissed": "muted",
    "resolved": "ok",
    "expired": "muted",
}
LIST_COLUMNS: Final = (
    "severity",
    "title",
    "state",
    "rule_id",
    "family",
    "subject",
    "confidence",
    "risk",
    "updated_at",
    "expected_impact",
    "created_at",
    "expires_at",
    "id",
)
LIST_HIDDEN: Final = ("expected_impact", "created_at", "expires_at", "id", "confidence")
HISTORY_COLUMNS: Final = ("at", "action", "title", "rule_id", "actor", "summary", "recommendation_id", "id")
RULE_COLUMNS: Final = ("id", "title", "family", "enabled", "severity_override", "open", "safe_auto", "implemented")
ISO_MINUTE: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z")
_ESCAPED: Final = re.compile(r"\\(.)")


# ============================================================================================ small helpers


def severity_cell(severity: Any) -> dict[str, Any]:
    tone, words = SEVERITY_WORDS.get(str(severity), ("muted", str(severity or "n/a")))
    return {"text": words, "tone": tone}


def detail_url(rec_id: Any) -> str:
    return f"{PAGE_PATH}/detail?{urlencode({'rec': str(rec_id)})}"


def preview_url(rec_id: Any, window: str = "1h") -> str:
    return f"{PAGE_PATH}/preview?{urlencode({'rec': str(rec_id), 'window': window})}"


def _iso_seconds(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def value_text(value: Any) -> str | None:
    """A change or evidence value as text (JSON for rows and lists; None stays None, shown as "not set")."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "on (1)" if value else "off (0)"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.4g}" if abs(value) < 1e15 else str(value)
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def words_of(name: Any) -> str:
    """`roblox_429_by_egress` -> `Roblox 429 by egress` (an evidence name made readable)."""
    text = str(name or "").replace("_", " ").strip()
    return (text[:1].upper() + text[1:]).replace("roblox", "Roblox")


def exact_endpoint(match: Any) -> str | None:
    """The endpoint template an anchored single-endpoint regex names (`^host/path/?$`, plan 11.2 and finding
    insights-8), so the page can say "exactly this endpoint" instead of showing only the regex."""
    if not simulate.covers_exactly_one_template(match if isinstance(match, Mapping) else None):
        return None
    pattern = str(match.get("pattern") or "")
    body = pattern[1:-3].replace(simulate.TEMPLATE_SEGMENT, "\0")
    parts = ["{segment}" if part == "\0" else _ESCAPED.sub(r"\1", part) for part in body.split("/")]
    return "/".join(parts)


def change_row(change: Mapping[str, Any]) -> dict[str, Any]:
    """One proposed change for the diff table: what it touches (in words), before and after."""
    kind = str(change.get("kind") or "")
    label = CHANGE_WORDS.get(kind, words_of(kind))
    target = ""
    note = ""
    pattern = None
    if kind in ("setting", "host_add"):
        key = str(change.get("key") or "")
        spec = catalog.CATALOG.get(key)
        target = key
        if spec is not None:
            label = f"{label}: {spec.label}"
    elif kind == "bucket_override":
        target = str(change.get("bucket_key") or "")
    elif kind == "tarpit_category":
        target = str(change.get("category") or "")
    elif kind == "manual":
        target = ""
        note = str(change.get("text") or "")
    else:
        table = str(change.get("table") or "")
        if table:
            label = f"{label} ({TABLE_WORDS.get(table, table)})"
        match = change.get("match")
        proposed = change.get("proposed")
        if isinstance(match, Mapping):
            pattern = match
        elif isinstance(proposed, Mapping) and proposed.get("pattern"):
            pattern = {"pattern": proposed.get("pattern"), "type": proposed.get("type") or "glob"}
        if pattern is not None:
            target = str(pattern.get("pattern") or pattern.get("cidr") or pattern.get("subject") or "")
            if not target:
                target = value_text(dict(pattern)) or ""
    endpoint = exact_endpoint(pattern) if pattern is not None else None
    return {
        "kind": kind,
        "label": label,
        "target": target,
        "endpoint": endpoint,
        "note": note,
        "before": value_text(change.get("current")),
        "after": value_text(change.get("proposed")),
        "manual": kind == "manual",
    }


def evidence_charts(details: Any) -> list[dict[str, Any]]:
    """Charts of the timelines a rule put in its evidence details (`{"<ISO minute>": n}`, `{"<ISO minute>":
    {"measure": n}}`, or `[[t, v], ...]`), each as one or more series of numbers with a data table."""
    if not isinstance(details, Mapping):
        return []
    charts: list[dict[str, Any]] = []
    for name, value in details.items():
        rows: list[tuple[str, dict[str, float]]] = []
        if isinstance(value, Mapping) and value and all(isinstance(k, str) and ISO_MINUTE.fullmatch(k) for k in value):
            for moment, entry in sorted(value.items()):
                if isinstance(entry, bool):
                    continue
                if isinstance(entry, int | float):
                    rows.append((moment, {"value": float(entry)}))
                elif isinstance(entry, Mapping):
                    numbers = {
                        str(k): float(v) for k, v in entry.items() if isinstance(v, int | float) and not isinstance(v, bool)
                    }
                    if numbers:
                        rows.append((moment, numbers))
        elif isinstance(value, list) and len(value) > 1 and all(
            isinstance(p, list | tuple) and len(p) == 2 and isinstance(p[0], int | float) and isinstance(p[1], int | float)
            for p in value
        ):
            for point in value:
                when = datetime.fromtimestamp(float(point[0]), UTC).strftime("%Y-%m-%dT%H:%MZ")
                rows.append((when, {"value": float(point[1])}))
        if len(rows) < 2:
            continue
        rows = rows[-MAX_CHART_POINTS:]
        measures = sorted({measure for _, numbers in rows for measure in numbers})
        series = [
            {"label": words_of(measure) if measure != "value" else words_of(name), "values": [n.get(measure, 0.0) for _, n in rows]}
            for measure in measures[:4]
        ]
        charts.append(
            {
                "name": str(name),
                "title": words_of(name),
                "series": series,
                "times": [moment.replace("T", " ").replace("Z", " UTC") for moment, _ in rows],
                "measures": [words_of(m) if m != "value" else "Value" for m in measures[:4]],
                "rows": [[n.get(measure) for measure in measures[:4]] for _, n in rows],
            }
        )
        if len(charts) >= MAX_CHARTS:
            break
    return charts


def other_details(details: Any, charted: Sequence[str]) -> str | None:
    """Every evidence detail that is not drawn as a chart, as JSON text (caller text: it can quote paths)."""
    if not isinstance(details, Mapping):
        return None
    rest = {k: v for k, v in details.items() if k not in charted}
    if not rest:
        return None
    text = json.dumps(rest, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    return text[:MAX_DETAIL_CHARS]


def history_row(item: Mapping[str, Any], view: PageView) -> dict[str, Any]:
    action = str(item.get("action") or "")
    return {
        "id": item.get("id"),
        "when": view.time_cell(item.get("at")),
        "action": ACTION_WORDS.get(action, words_of(action)),
        "actor": str(item.get("actor") or ""),
        "summary": str(item.get("summary") or ""),
    }


# ============================================================================================ the list


STATE_FILTER: Final[tuple[tuple[str, str], ...]] = (
    ("", "Open"),
    *((state, STATE_WORDS[state]) for state in STATES if state != "open"),
    (rec_api.ALL_STATES, "Every state"),
)
SEVERITY_FILTER: Final[tuple[tuple[str, str], ...]] = (
    ("", "Any severity"),
    ("critical", "Critical"),
    ("warn", "Warning"),
    ("info", "Info"),
)


def family_filter() -> list[tuple[str, str]]:
    return [("", "Any family"), *((family, FAMILY_WORDS[family]) for family in rec_api.FAMILIES)]


def rule_filter() -> list[tuple[str, str]]:
    return [("", "Any rule"), *((rule_id, rule_id) for rule_id in INSIGHT_RULES)]


async def list_filters_of(view: PageView) -> tuple[rec_api.ListFilters, dict[str, str], str | None]:
    """The list filters from the address (the API's names and values); a bad value falls back with a notice."""
    raw = {name: view.state_param(name, max_chars=rec_api.FILTER_TEXT_MAX) for name in ("state", "severity", "family", "rule")}
    try:
        filters = await rec_api.list_filters(
            state=raw["state"] or None,
            severity=raw["severity"] or None,
            family=raw["family"] or None,
            rule=raw["rule"] or None,
        )
        return filters, raw, None
    except common.ApiError as error:
        details = "; ".join(error.error_fields.values()) or error.error_message
        filters = await rec_api.list_filters(state=None, severity=None, family=None, rule=None)
        notice = f"The filters in the address were not valid ({details}); open recommendations are shown."
        return filters, dict.fromkeys(raw, ""), notice


@page.card("list", refresh_on=("recommendation",), refresh_min_s=10)
async def list_card(view: PageView) -> dict[str, Any]:
    """Every recommendation with its filters (`list_answer`, the API's own function)."""
    tq, table_notice = table_query(view, rec_api.LIST_TABLE)
    filters, raw, filter_notice = await list_filters_of(view)
    answer = await rec_api.list_answer(view.ctx, filters, tq)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        state = str(item.get("state") or "")
        state_sub = None
        if state == "snoozed" and item.get("snoozed_until"):
            state_sub = f"until {fmt.local_time(item['snoozed_until'], view.tz, seconds=False)}"
        elif state == "dismissed" and item.get("dismissed_reason"):
            state_sub = DISMISS_REASONS.get(str(item["dismissed_reason"]), str(item["dismissed_reason"]))
        return {
            "severity": severity_cell(item.get("severity")),
            "title": {
                "text": item.get("title"),
                "caller": True,
                "limit": 160,
                "sub": "Safe to auto-apply" if item.get("safe_auto") else None,
            },
            "state": {"text": STATE_WORDS.get(state, state), "tone": TONE_OF_STATE.get(state, "muted"), "sub": state_sub},
            "rule_id": {"text": item.get("rule_id"), "mono": True},
            "family": FAMILY_WORDS.get(str(item.get("family")), item.get("family")),
            "subject": {"text": item.get("subject"), "caller": True, "limit": 120} if item.get("subject") else None,
            "expected_impact": {"text": item.get("expected_impact"), "caller": True, "limit": 200}
            if item.get("expected_impact")
            else None,
            "confidence": str(item.get("confidence") or "").capitalize() or None,
            "risk": str(item.get("risk") or "").capitalize() or None,
            "id": {"text": item.get("id"), "mono": True},
        }

    counts = answer.get("counts") or {}
    by_severity = counts.get("open_by_severity") or {}
    engine = answer.get("engine") or {}
    notices = [n for n in (table_notice, filter_notice) if n]
    filters_ui = [
        filter_chip("state", "State", raw["state"], STATE_FILTER),
        filter_chip("severity", "Severity", raw["severity"], SEVERITY_FILTER),
        filter_chip("family", "Family", raw["family"], family_filter()),
        filter_chip("rule", "Rule", raw["rule"], rule_filter()),
    ]
    filtered = any(raw.values()) or bool(tq.q)
    table = table_view(
        view,
        LIST_TABLE_ID,
        rec_api.LIST_TABLE,
        answer,
        src=view.fragment_url("list"),
        columns=LIST_COLUMNS,
        key_columns=("severity", "title", "state"),
        hidden=LIST_HIDDEN,
        cells=cells,
        row_id=lambda item: f"rec-{item.get('id')}",
        drawer=lambda item: detail_url(item.get("id")),
        drawer_title=lambda item: "Recommendation",
        filters=filters_ui,
        export_url=view.api_url("recommendations", time=False),
        caption="Recommendations",
        empty={
            "title": "No recommendation matches" if filtered else "Nothing to recommend right now",
            "body": "Clear the search or the filters, or choose Every state to see closed ones."
            if filtered
            else "Roxy checks its own numbers every "
            f"{int(engine.get('interval_s') or 30)} seconds and lists here what it would change, with the evidence. "
            "Nothing is open, which is good news.",
            "icon": "bulb",
            "tone": "neutral" if filtered else "good",
        },
        search_placeholder="Search recommendations",
        notice=" ".join(notices) or None,
    )
    return {
        "table": table,
        "open": int(counts.get("open") or 0),
        "by_severity": {key: int(by_severity.get(key) or 0) for key in ("critical", "warn", "info")},
        "engine": engine,
    }


# ============================================================================================ history


@page.card("history")
async def history_card(view: PageView) -> dict[str, Any]:
    """Every action taken on a recommendation (`history_answer`); the top bar's range filters by time."""
    tq, notice = table_query(view, rec_api.HISTORY_TABLE, address=False)
    action = view.state_param("action", address=False, max_chars=32)
    rule = view.state_param("rule", address=False, max_chars=48)
    notices = [notice] if notice else []
    if action and action not in reads.ACTIONS:
        notices.append("That action filter is not known; every action is shown.")
        action = ""
    if rule and rule not in INSIGHT_RULES:
        notices.append("That rule filter is not known; every rule is shown.")
        rule = ""
    whole = view.time.view.get("range") == "all"
    since = None if whole else int(view.tr.window.start)
    until = None if whole else int(view.tr.window.end)
    wanted = rec_api.HistoryFilters(
        actions=(action,) if action else (), rule_ids=(rule,) if rule else (), since=since, until=until
    )
    answer = await rec_api.history_answer(view.ctx, wanted, tq)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        act = str(item.get("action") or "")
        return {
            "action": {"text": ACTION_WORDS.get(act, act), "tone": "warn" if "rollback" in act else None},
            "title": {"text": item.get("title"), "caller": True, "limit": 120} if item.get("title") else None,
            "rule_id": {"text": item.get("rule_id"), "mono": True} if item.get("rule_id") else None,
            "actor": {"text": item.get("actor"), "caller": True, "limit": 80},
            "summary": {"text": item.get("summary"), "caller": True, "limit": 160} if item.get("summary") else None,
            "recommendation_id": {"text": item.get("recommendation_id"), "mono": True},
            "id": {"text": f"#{item.get('id')}", "mono": True},
        }

    bounds = {} if whole else {"from": since, "to": until}
    table = table_view(
        view,
        HISTORY_TABLE_ID,
        rec_api.HISTORY_TABLE,
        answer,
        src=view.fragment_url("history"),
        columns=HISTORY_COLUMNS,
        key_columns=("at", "action", "title"),
        hidden=("recommendation_id", "id"),
        cells=cells,
        row_id=lambda item: f"action-{item.get('id')}",
        drawer=lambda item: detail_url(item.get("recommendation_id")),
        drawer_title=lambda item: "Recommendation",
        filters=[
            filter_chip("action", "Action", action, [("", "Any action"), *((a, ACTION_WORDS[a]) for a in reads.ACTIONS)]),
            filter_chip("rule", "Rule", rule, rule_filter()),
        ],
        export_url=view.api_url("recommendations/history", time=False, **bounds),
        caption="Recommendation history",
        empty={
            "title": "No action yet" if whole else "No action in this range",
            "body": "Applies, undos, snoozes, dismissals and automatic rollbacks are listed here as they happen."
            + ("" if whole else " Choose All in the time range to see every action."),
            "icon": "history",
        },
        search_placeholder="Search the history",
        notice=" ".join(notices) or None,
        address=False,
    )
    return {"table": table, "whole": whole, "range_label": view.time.view.get("label")}


# ============================================================================================ rules


@page.card("rules")
async def rules_card(view: PageView) -> dict[str, Any]:
    """The rule catalog (`rule_rows`, `rules_answer`); a row opens the rule's tuning drawer."""
    tq, notice = table_query(view, rec_api.RULES_TABLE, address=False)
    family = view.state_param("family", address=False, max_chars=32)
    notices = [notice] if notice else []
    if family and family not in rec_api.FAMILIES:
        notices.append("That family filter is not known; every family is shown.")
        family = ""
    rows = await rec_api.rule_rows(view.request, (family,) if family else ())
    answer = rec_api.rules_answer(view.request, rows, tq)
    card_ids = {card.id for card in registry.cards_for(page.id)}

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        enabled = bool(item.get("enabled"))
        override = str(item.get("severity_override") or "auto")
        return {
            "id": {"text": item.get("id"), "mono": True},
            "family": FAMILY_WORDS.get(str(item.get("family")), item.get("family")),
            "enabled": {"text": "On" if enabled else "Off", "tone": "ok" if enabled else "muted"},
            "severity_override": "Its own" if override == "auto" else SEVERITY_WORDS.get(override, ("", override))[1],
            "safe_auto": "Yes" if item.get("safe_auto") else "No",
            "implemented": {"text": "Yes", "tone": None} if item.get("implemented") else {"text": "No", "tone": "warn"},
        }

    def drawer(item: Mapping[str, Any]) -> str | None:
        card_id = f"rule-{item.get('slug')}"
        return view.fragment_url(card_id) if card_id in card_ids else None

    table = table_view(
        view,
        RULES_TABLE_ID,
        rec_api.RULES_TABLE,
        answer,
        src=view.fragment_url("rules"),
        columns=RULE_COLUMNS,
        key_columns=("id", "enabled", "open"),
        cells=cells,
        row_id=lambda item: f"rule-{item.get('slug')}",
        drawer=drawer,
        drawer_title=lambda item: f"Tune {item.get('id')}",
        filters=[filter_chip("family", "Family", family, family_filter())],
        export_url=view.api_url("recommendations/rules", time=False),
        caption="Recommendation rules",
        empty={"title": "No rule matches", "body": "Clear the search or the family filter.", "icon": "bulb"},
        search_placeholder="Search rules",
        notice=" ".join(notices) or None,
        address=False,
    )
    return {
        "table": table,
        "implemented": int(answer.get("implemented") or 0),
        "total_rules": len(INSIGHT_RULES),
        "engine_on": bool(answer.get("insights_enabled")),
    }


def _rule_renderer(rule_id: str) -> Any:
    async def render(view: PageView) -> dict[str, Any]:
        summary = await rec_api.rule_summary(view.request, rule_id)
        active = summary["active"]
        items = [
            {
                **item,
                "severity_tone": SEVERITY_WORDS.get(str(item.get("severity")), ("muted", ""))[0],
                "severity_words": SEVERITY_WORDS.get(str(item.get("severity")), ("", str(item.get("severity"))))[1],
                "state_words": STATE_WORDS.get(str(item.get("state")), str(item.get("state"))),
                "drawer": detail_url(item.get("id")),
            }
            for item in active["items"]
        ]
        return {"rule": summary["rule"], "active": items, "active_total": int(active.get("total") or 0)}

    render.__name__ = f"rule_card_{INSIGHT_RULES[rule_id].slug}"
    return render


def _register_rule_cards() -> None:
    """One "Tune this rule" drawer per rule of the catalog (`rule-<slug>` cards, fragment-only)."""
    known = {card.id for card in registry.cards_for("recommendations")}
    for rule_id, spec in INSIGHT_RULES.items():
        card_id = f"rule-{spec.slug}"
        if card_id in known:
            page.card(card_id, template=RULE_TEMPLATE)(_rule_renderer(rule_id))


_register_rule_cards()


# ============================================================================================ engine


async def _job_facts(view: PageView, names: Sequence[str]) -> dict[str, Any]:
    now = view.now

    def read(conn: Any) -> list[Any]:
        return health_store.read_job_status(conn, now - 86_400)

    try:
        rows = await view.ctx.dbs.metrics.read(read)
    except Exception:  # the job line is a convenience; the card still shows the settings
        return {}
    return {row.name: row for row in rows if row.name in names}


@page.card("engine", lazy=True)
async def engine_card(view: PageView) -> dict[str, Any]:
    """The engine's state: on or off, auto-apply, how often it looks, and when the leader last evaluated."""
    settings = view.ctx.settings
    jobs = await _job_facts(view, ("insights_evaluate", "insights_auto_apply", "insights_watch"))
    evaluate = jobs.get("insights_evaluate")
    last = None
    if evaluate is not None and evaluate.last_finished_at:
        last = {
            "when": fmt.since_text(evaluate.last_finished_at, view.now, view.tz),
            "ok": evaluate.last_ok,
        }
    return {
        "enabled": bool(settings.bool("insights_enabled")),
        "auto_apply": bool(settings.bool("insights_auto_apply")),
        "interval_s": int(settings.int("insights_interval_s")),
        "max_per_hour": int(settings.int("auto_apply_max_per_hour")),
        "watch_minutes": int(settings.int("auto_apply_watch_minutes")),
        "last": last,
    }


@page.card("preview-settings", lazy=True)
async def preview_settings_card(view: PageView) -> dict[str, Any]:
    """What a dry run replays: the sampled requests these settings keep."""
    settings = view.ctx.settings
    return {
        "sample_pct": float(settings.float("request_sample_pct")),
        "sample_hours": int(settings.int("request_sample_hours")),
    }


# ============================================================================================ the drawer


DETAIL_CARD: Final = CardDef(
    spec=CardSpec("detail", "Recommendation", fragment_only=True),
    render=None,
    template=DETAIL_TEMPLATE,
)
PREVIEW_CARD: Final = CardDef(
    spec=CardSpec("preview", "Preview", fragment_only=True),
    render=None,
    template=PREVIEW_TEMPLATE,
)


def _rec_id(view: PageView) -> str:
    raw = view.param("rec", max_chars=80)
    if not REC_ID_RE.fullmatch(raw):
        raise common.not_found("Choose a recommendation from the list; that id is not valid.")
    return raw


async def detail_context(view: PageView) -> dict[str, Any]:
    """The drawer of one recommendation (`detail_answer`, the API's own function)."""
    rec_id = _rec_id(view)
    answer = await rec_api.detail_answer(view.request, rec_id)
    rec = answer["recommendation"]
    card = answer["card"]
    explanation = str(rec.get("explanation") or "")
    wide = simulate.WIDE_PATTERN_NOTE in explanation
    evidence = rec.get("evidence") or {}
    details = evidence.get("details")
    charts = evidence_charts(details)
    window = evidence.get("window") or {}
    watch = answer.get("watch")
    watch_view = None
    if watch:
        rollback = watch.get("rollback") or None
        watch_view = {
            "state": WATCH_WORDS.get(str(watch.get("state")), words_of(watch.get("state"))),
            "raw_state": str(watch.get("state") or ""),
            "started": fmt.local_time(watch.get("started_at"), view.tz, seconds=False),
            "ends": fmt.local_time(watch.get("ends_at"), view.tz, seconds=False),
            "ends_iso": fmt.iso(watch.get("ends_at")),
            "rollback": rollback,
        }
    rule = answer.get("rule")
    tune = None
    if rule:
        card_id = f"rule-{rule.get('slug')}"
        if card_id in {c.id for c in registry.cards_for(page.id)}:
            tune = view.fragment_url(card_id)
    links = answer["links"]
    allowed = answer["allowed"]
    created = _iso_seconds(rec.get("created_at"))
    updated = _iso_seconds(rec.get("updated_at"))
    expires = _iso_seconds(rec.get("expires_at"))
    severity_tone, severity_words = SEVERITY_WORDS.get(str(rec.get("severity")), ("muted", str(rec.get("severity"))))
    return {
        "rec": rec,
        "card": card,
        "id": rec.get("id"),
        "severity_tone": severity_tone,
        "severity_words": severity_words,
        "state_words": STATE_WORDS.get(str(rec.get("state")), str(rec.get("state"))),
        "state_tone": TONE_OF_STATE.get(str(rec.get("state")), "muted"),
        "explanation": explanation.replace(simulate.WIDE_PATTERN_NOTE, "").strip(),
        "wide_note": simulate.WIDE_PATTERN_NOTE if wide else None,
        "safe_auto": bool(rec.get("safe_auto")),
        "created": fmt.time_cell(created, view.tz, view.now),
        "updated": fmt.time_cell(updated, view.tz, view.now),
        "expires": fmt.local_time(expires, view.tz, seconds=False) if expires else None,
        "evidence": {
            "from": fmt.local_time(_iso_seconds(window.get("from")), view.tz, seconds=False),
            "to": fmt.local_time(_iso_seconds(window.get("to")), view.tz, seconds=False),
            "sample_size": int(evidence.get("sample_size") or 0),
            "metrics": [
                {"name": words_of(m.get("name")), "value": value_text(m.get("value")), "unit": m.get("unit") or ""}
                for m in evidence.get("metrics") or ()
                if isinstance(m, Mapping)
            ],
            "links": [str(link) for link in evidence.get("links") or ()],
            "charts": charts,
            "details": other_details(details, [c["name"] for c in charts]),
        },
        "changes": [change_row(change) for change in rec.get("changes") or () if isinstance(change, Mapping)],
        "allowed": allowed,
        "links": links,
        "history": [history_row(item, view) for item in answer.get("history") or ()],
        "watch": watch_view,
        "earlier": [
            {
                **item,
                "state_words": STATE_WORDS.get(str(item.get("state")), str(item.get("state"))),
                "when": fmt.local_time(item.get("updated_at"), view.tz, seconds=False),
                "drawer": detail_url(item.get("id")),
            }
            for item in answer.get("earlier") or ()
        ],
        "rule": rule,
        "tune": tune,
        "dismiss_reasons": [(value, label) for value, label in DISMISS_REASONS.items()],
        "snooze": [(key, {"1h": "1 hour", "1d": "1 day", "1w": "1 week"}.get(key, key)) for key in SNOOZE_DURATIONS_S],
        "snooze_max_days": rec_api.MAX_SNOOZE_S // 86_400,
        "ui_tz": str(view.ctx.settings.get("ui_timezone") or "UTC"),
        "preview_url": preview_url(rec.get("id")),
        "detail_url": detail_url(rec.get("id")),
        "dry_run_available": bool((rec.get("dry_run") or {}).get("available")),
        "max_value_chars": MAX_VALUE_CHARS,
    }


async def preview_context(view: PageView) -> dict[str, Any]:
    """The preview panel (`preview_answer`, the API's own function): diff, requirements, dry run, Apply."""
    rec_id = _rec_id(view)
    window = view.param("window", "1h", max_chars=8)
    notice = None
    if window not in rec_api.PREVIEW_WINDOWS_S:
        notice = "That replay window is not offered; the last hour is shown."
        window = "1h"
    answer = await rec_api.preview_answer(view.request, rec_id, window)
    report = answer.get("dry_run") or {}
    diff = []
    for item in answer.get("diff") or ():
        kind = str(item.get("kind") or "")
        target = str(item.get("target") or "")
        key = target.split(":", 1)[1] if target.startswith("setting:") else ""
        spec = catalog.CATALOG.get(key) if key else None
        diff.append(
            {
                "label": CHANGE_WORDS.get(kind, words_of(kind)) + (f": {spec.label}" if spec else ""),
                "target": target,
                "before": value_text(item.get("before")),
                "after": value_text(item.get("after")),
                "valid": bool(item.get("valid", True)),
                "message": str(item.get("message") or ""),
            }
        )
    requires = answer.get("requires") or {}
    return {
        "id": answer.get("id"),
        "state": answer.get("state"),
        "digest": answer.get("changes_digest"),
        "diff": diff,
        "ok": bool(answer.get("ok")),
        "requires": requires,
        "high_risk_labels": [
            catalog.CATALOG[key].label for key in requires.get("high_risk_keys") or () if key in catalog.CATALOG
        ],
        "window": window,
        "windows": [(key, {"1h": "Last hour", "6h": "Last 6 hours", "24h": "Last 24 hours"}[key]) for key in rec_api.PREVIEW_WINDOWS_S],
        "window_urls": {key: preview_url(rec_id, key) for key in rec_api.PREVIEW_WINDOWS_S},
        "report": report,
        "computed": fmt.local_time(report.get("computed_at"), view.tz) if report.get("computed_at") else None,
        "apply_url": f"{common.API_PREFIX}/recommendations/{rec_id}/apply",
        "detail_url": detail_url(rec_id),
        "notice": notice,
        "active": answer.get("state") in ("open", "snoozed"),
    }


async def _render_extra(request: Request, principal: Any, cdef: CardDef, build: Any) -> HTMLResponse:
    if len(request.query_params) > MAX_FRAGMENT_PARAMS:
        raise HTTPException(status_code=404, detail="Not Found")
    view = await page.view(request, principal)
    bound = CardDef(spec=cdef.spec, render=build, template=cdef.template)
    return HTMLResponse(await render_card(view, bound))


@router.get("/detail", include_in_schema=False)
async def detail_route(request: Request, principal: PageAdmin) -> HTMLResponse:
    """The detail drawer of one recommendation (`?rec=<id>`)."""
    return await _render_extra(request, principal, DETAIL_CARD, detail_context)


@router.get("/preview", include_in_schema=False)
async def preview_route(request: Request, principal: PageAdmin) -> HTMLResponse:
    """The preview panel of one recommendation (`?rec=<id>&window=1h|6h|24h`), loaded into the drawer."""
    return await _render_extra(request, principal, PREVIEW_CARD, preview_context)


@router.get("/{rec_id}", include_in_schema=False)
async def recommendation_link(rec_id: str, principal: PageAdmin) -> RedirectResponse:
    """`/admin/recommendations/<id>` (the health store's "Apply fix" link) opens that recommendation's drawer."""
    if not REC_ID_RE.fullmatch(rec_id):
        raise HTTPException(status_code=404, detail="Not Found")
    return RedirectResponse(f"{PAGE_PATH}?{urlencode({'rec': rec_id})}", status_code=303)


__all__ = [
    "change_row",
    "evidence_charts",
    "exact_endpoint",
    "page",
    "router",
    "value_text",
]
