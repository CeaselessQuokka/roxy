"""The Endpoint policy page (`/admin/policy`, owner decision D1 revised 2026-10-16): which Roblox endpoints callers
may use, and with which account.

What this is
    One card per registry card of page `policy` (`docs/endpoint_policy/BRIEF.md` section 8):
      * `summary`: the effective verdict counts, overrides and category switches in force, the last 24 hours
        (refused, unknown endpoints and requests, shadow mode, sign-in attempts), the shipped seed's date, whether
        the credential is on and its rate, the old credential allowlist rows with what the policy does for each now,
        and "Reset to shipped defaults". The three `endpoint_policy_*` settings are edited inline (`policy#summary`).
      * `categories`: one row per category with its switch (Defaults, Block all, and for a category with endpoints
        sent with the account, Send without the account), its counts and highest risk, a reason field, and a link
        to the Endpoints card filtered to it.
      * `endpoints`: the page's main table, every documented Roblox operation with filters, search, its verdict in
        words, its default, risk, category, refusals in 24 hours and two links to Roblox's documentation; a row
        opens its drawer; selected rows can be blocked or put back to their default together.
      * `tester`: paste a URL and a method, see the target, the matched row, each precedence step and the verdict.
      * `unknown`, `attempts`, `would-block`: the time range's unknown endpoints (each with "Set verdict"), caller
        sign-in attempts (newest first, real cookies highlighted) and what shadow mode let through.
    Three page partials: `/admin/policy/endpoint?id=` (a row's drawer), `/admin/policy/test?target=&method=` (the
    tester's answer) and `/admin/policy/unknown-row?id=` (set the verdict of an unknown endpoint).

Why it exists
    The owner wants to add or remove whole categories or single endpoints, with sensible defaults and a link to
    Roblox's own documentation for each (2026-10-16). It replaces the Credential page's allowlist card: the policy
    now decides which requests carry Roxy's account.

How it works
    `page = Page("policy")`; every card renders `templates/admin/pages/policy/<card>.html` from the admin API's own
    functions (`roxy/admin/api/policy.py summary_answer`, `categories_answer`, `endpoint_items`, `target_answer`,
    `counted_answer`, `attempts_answer`, `unknown_item`), so the page and the API never disagree (plan P6). Page
    routes stay read-only: every form posts JSON to `/admin/api/v1/policy/...` (`static/js/api_forms.js`), where
    CSRF, the fresh second factor for loosening, the risk 4 typed confirmation and the audit row are judged. The
    Endpoints table is drawn by `policy/_table.html` (the `data_table` shell with its own rows: a select box and two
    links that leave Roxy, which the shared macro does not draw). Caller-chosen text (unknown endpoint templates,
    header names, User-Agents, a tester target) goes through `caller_text`, as plain text.

What to read next
    `roxy/admin/api/policy.py`, `roxy/policy/engine.py`, `templates/admin/pages/policy.html`,
    `static/js/pages/policy.js`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any, Final
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.abuse.checks.endpoint_policy import POLICY_UNKNOWN_EVENT, POLICY_WOULD_BLOCK_EVENT
from roxy.admin.api import common
from roxy.admin.api import policy as policy_api
from roxy.admin.api.common import TableQuery
from roxy.admin.api.routing_rules import MAX_TARGET_CHARS
from roxy.admin.pages._upstream_common import render_partial
from roxy.admin.pages.kit import Page, PageAdmin, PageView, filter_chip, table_query, table_view
from roxy.policy.seed import CATEGORIES, LOOSENING, METHODS, VERDICT_LABELS, Verdict

page = Page("policy")
router = page.router

API: Final = common.API_PREFIX
ENDPOINT_DRAWER: Final = "/admin/policy/endpoint"
UNKNOWN_DRAWER: Final = "/admin/policy/unknown-row"
TESTER: Final = "/admin/policy/test"
MAX_ID_CHARS: Final = 500
VERDICT_TONES: Final[Mapping[str, str]] = {"BLOCK": "bad", "ALLOW_TOKEN": "warn", "ALLOW_ANON": "ok"}
"""Tone of a verdict: sending Roxy's account is the one to watch (warn), refusing is red, sending without it green."""
SHORT_VERDICT: Final[Mapping[str, str]] = {
    "BLOCK": "Blocked",
    "ALLOW_TOKEN": "With account",
    "ALLOW_ANON": "No account",
}
RISK_WORDS: Final[Mapping[int, str]] = {
    1: "1 harmless",
    2: "2 low",
    3: "3 meaningful",
    4: "4 critical",
}
RISK_TONES: Final[Mapping[int, str]] = {1: "ok", 2: "info", 3: "warn", 4: "bad"}
STATE_LABELS: Final[Mapping[str, str]] = {
    "defaults": "Defaults",
    "block_all": "Block all",
    "strip_credential": "Send without the account",
}
SOURCE_WORDS: Final[Mapping[str, str]] = {
    "override": "your override",
    "category": "its category's switch",
    "default": "the shipped default",
    "seed": "the shipped default",
    "host": "the default for its host (Roblox does not document the host)",
    "unknown": "the unknown endpoint rule",
    "guard": "a query guard",
}
METHOD_CHOICES: Final[tuple[str, ...]] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
CHANGED_CHOICES: Final[tuple[tuple[str, str], ...]] = (("", "Any"), ("1", "Changed"), ("0", "At default"))


def verdict_cell(verdict: str) -> dict[str, Any]:
    """A verdict as words with its tone (never color alone)."""
    return {"text": VERDICT_LABELS[Verdict(verdict)], "tone": VERDICT_TONES.get(verdict, "muted")}


def risk_cell(risk: int) -> dict[str, Any]:
    return {"text": RISK_WORDS.get(int(risk), str(risk)), "tone": RISK_TONES.get(int(risk), "muted")}


def drawer_url(endpoint_id: str) -> str:
    return f"{ENDPOINT_DRAWER}?" + urlencode({"id": endpoint_id})


def unknown_url(endpoint_id: str) -> str:
    return f"{UNKNOWN_DRAWER}?" + urlencode({"id": endpoint_id})


def audit_url(table: str, key: str) -> str:
    return "/admin/audit?" + urlencode({"target": f"{table}:{key}"})


def verdict_options(method: str) -> list[dict[str, Any]]:
    """The verdict choices of one operation (ALLOW_TOKEN only where the credential may ever go: GET, HEAD, POST)."""
    allowed = [v for v in Verdict if v is not Verdict.ALLOW_TOKEN or method.upper() in ("GET", "HEAD", "POST")]
    return [{"value": v.value, "label": VERDICT_LABELS[v], "rank": LOOSENING[v]} for v in allowed]


# ============================================================================================ summary


@page.card("summary")
async def summary_card(view: PageView) -> dict[str, Any]:
    """The Summary card: `summary_answer`, the API's own function, put in words."""
    answer = await policy_api.summary_answer(view.ctx)
    verdicts = answer.get("verdicts") or {}
    tiles = [
        {"value": v.value, "label": VERDICT_LABELS[v], "count": int(verdicts.get(v.value) or 0), **verdict_cell(v)}
        for v in Verdict
    ]
    switches = [
        {
            "key": key,
            "label": CATEGORIES[key].label if key in CATEGORIES else key,
            "state": STATE_LABELS.get(str(state), str(state)),
        }
        for key, state in sorted((answer.get("categories") or {}).items())
    ]
    legacy = [
        {
            **row,
            "verdict_cell": verdict_cell(str(row["verdict"])) if row.get("verdict") else None,
            "drawer": drawer_url(str(row["endpoint_id"]))
            if row.get("endpoint_id") and not str(row["endpoint_id"]).startswith("unknown:")
            else None,
        }
        for row in answer.get("legacy_allowlist") or ()
    ]
    settings = answer.get("settings") or {}
    return {
        "answer": answer,
        "tiles": tiles,
        "switches": switches,
        "legacy": legacy,
        "settings_now": settings,
        "enforced": bool(settings.get("endpoint_policy_enforce")),
        "reset_url": f"{API}/policy/reset",
        "changed_href": "/admin/policy?" + urlencode({"changed": "1"}) + "#endpoints",
    }


# ============================================================================================ categories


@page.card("categories")
async def categories_card(view: PageView) -> dict[str, Any]:
    """One row per category (`categories_answer`) with its switch form."""
    answer = policy_api.categories_answer(view.ctx)
    items = []
    for item in answer.get("items") or ():
        key = str(item["key"])
        items.append(
            {
                **item,
                "state_label": STATE_LABELS.get(str(item["state"]), str(item["state"])),
                "choices": [{"value": s, "label": STATE_LABELS.get(s, s)} for s in item.get("states") or ()],
                "url": f"{API}/policy/categories/{key}",
                "endpoints_href": "/admin/policy?" + urlencode({"category": key}) + "#endpoints",
                "risk": risk_cell(int(item.get("max_risk") or 1)),
                "counts": [
                    {
                        "label": SHORT_VERDICT[v.value],
                        "now": int((item.get("verdicts") or {}).get(v.value) or 0),
                        "default": int((item.get("default_verdicts") or {}).get(v.value) or 0),
                    }
                    for v in Verdict
                ],
            }
        )
    return {"items": items, "help": answer.get("help") or {}}


# ============================================================================================ endpoints


def _choice(value: str, allowed: Sequence[str]) -> str:
    return value if value in allowed else ""


def endpoint_filters(view: PageView) -> dict[str, Any]:
    """The Endpoints table's filters from the address (an unknown value is ignored, never an error)."""
    seed = view.ctx.rules.snapshot.endpoint_policy.seed
    hosts = sorted({row.host for row in seed.rows})
    risk = view.param("risk", max_chars=2)
    changed = view.param("changed", max_chars=2)
    return {
        "host": _choice(view.param("host", max_chars=100).lower(), hosts),
        "category": _choice(view.param("category", max_chars=64).lower(), list(CATEGORIES)),
        "verdict": _choice(view.param("verdict", max_chars=16).upper(), [v.value for v in Verdict]),
        "risk": _choice(risk, ["1", "2", "3", "4"]),
        "method": _choice(view.param("method", max_chars=8).upper(), sorted(METHODS)),
        "auth": _choice(view.param("auth", max_chars=32), list(policy_api.AUTH_WORDS)),
        "changed": _choice(changed, ["0", "1"]),
        "hosts": hosts,
    }


def _filter_chips(chosen: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        filter_chip("host", "Host", chosen["host"], [("", "Every host"), *((h, h) for h in chosen["hosts"])]),
        filter_chip(
            "category",
            "Category",
            chosen["category"],
            [("", "Every category"), *((k, c.label) for k, c in CATEGORIES.items())],
        ),
        filter_chip(
            "verdict", "Verdict", chosen["verdict"], [("", "Any"), *((v.value, VERDICT_LABELS[v]) for v in Verdict)]
        ),
        filter_chip("risk", "Risk", chosen["risk"], [("", "Any"), *((str(n), w) for n, w in RISK_WORDS.items())]),
        filter_chip("method", "Method", chosen["method"], [("", "Any"), *((m, m) for m in sorted(METHODS))]),
        filter_chip("auth", "Roblox sign-in", chosen["auth"], [("", "Any"), *policy_api.AUTH_WORDS.items()]),
        filter_chip("changed", "Changed", chosen["changed"], list(CHANGED_CHOICES)),
    ]


def _page_of(tq: TableQuery, total: int) -> TableQuery:
    last = max(1, -(-total // tq.page_size))
    return tq if tq.page <= last else replace(tq, page=last)


@page.card("endpoints")
async def endpoints_card(view: PageView) -> dict[str, Any]:
    """Every documented operation (`endpoint_items`), filtered, searched and paged like `GET /policy/endpoints`."""
    spec = policy_api.ENDPOINT_SPEC
    tq, notice = table_query(view, spec)
    chosen = endpoint_filters(view)
    items = await policy_api.endpoint_items(
        view.ctx,
        host=chosen["host"] or None,
        category=chosen["category"] or None,
        verdict=chosen["verdict"] or None,
        risk=int(chosen["risk"]) if chosen["risk"] else None,
        method=chosen["method"] or None,
        auth=chosen["auth"] or None,
        changed={"1": True, "0": False}.get(chosen["changed"]),
    )
    rows, total = common.page_rows(items, tq, search_keys=policy_api.SEARCH_KEYS)
    if not rows and total:
        tq = _page_of(tq, total)  # a page number kept from another filter: show the last page instead
        rows, total = common.page_rows(items, tq, search_keys=policy_api.SEARCH_KEYS)
    answer = common.table_answer(spec, tq, rows, total)
    filter_values = {name: chosen[name] for name in ("host", "category", "verdict", "risk", "method", "auth")}
    table = table_view(
        view,
        "policy-endpoints",
        spec,
        answer,
        src="/admin/policy/fragment/endpoints",
        columns=(
            "method",
            "host",
            "path",
            "summary",
            "verdict",
            "default_verdict",
            "risk",
            "category",
            "roblox_auth",
            "refused_24h",
        ),
        hidden=("roblox_auth",),
        filters=_filter_chips(chosen),
        keep={},
        export_url=view.api_url("policy/endpoints", time=False),
        caption="Roblox endpoints and their verdicts",
        search_placeholder="Search path, summary or host",
        notice=notice,
    )
    shown = [
        {
            **item,
            "verdict_cell": verdict_cell(str(item["verdict"])),
            "default_cell": verdict_cell(str(item["default_verdict"])),
            "risk_cell": risk_cell(int(item["risk"])),
            "drawer": drawer_url(str(item["id"])),
            "title": f"{item['method']} {item['host']}{item['path']}",
        }
        for item in rows
    ]
    return {
        "table": table,
        "rows": shown,
        "bulk_url": f"{API}/policy/endpoints",
        "filtered": any(filter_values.values()) or bool(chosen["changed"]) or bool(tq.q),
    }


@page.router.get("/endpoint", include_in_schema=False)
async def endpoint_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """One operation in the drawer: what Roblox and the review say about it, its verdict now, the form that sets a
    verdict (PUT, a reason; loosening asks for a fresh second factor, a risk 4 one its typed path), and "Back to
    default" (DELETE) when it has an override."""

    async def build(view: PageView) -> dict[str, Any]:
        endpoint_id = view.param("id", max_chars=MAX_ID_CHARS + 1)
        policy = view.ctx.rules.snapshot.endpoint_policy
        row = policy.seed.by_id.get(endpoint_id) if 0 < len(endpoint_id) <= MAX_ID_CHARS else None
        if row is None:
            raise common.not_found("No Roblox endpoint has that id. Choose a row from the Endpoints table.")
        refused = await policy_api.refused_by_endpoint(view.ctx, int(view.now * 1000))
        item = policy_api.item_of(policy, row, refused)
        return {
            "item": item,
            "verdict": verdict_cell(item["verdict"]),
            "default": verdict_cell(item["default_verdict"]),
            "risk": risk_cell(int(item["risk"])),
            "source_words": SOURCE_WORDS.get(str(item["source"]), str(item["source"])),
            "options": verdict_options(str(item["method"])),
            "current_rank": LOOSENING[Verdict(item["verdict"])],
            "url": f"{API}/policy/endpoints",
            "history_url": audit_url(policy_api.OVERRIDES, str(item["id"])),
            "category_href": "/admin/policy?" + urlencode({"category": item["category"]}) + "#endpoints",
            "help": {"loosen": policy_api.LOOSEN_NOTE},
        }

    return await render_partial(page, request, principal, "admin/pages/policy/_endpoint.html", build)


# ============================================================================================ tester


@page.card("tester")
async def tester_card(view: PageView) -> dict[str, Any]:
    """The tester's form (its answer is the `/admin/policy/test` partial)."""
    return {"methods": METHOD_CHOICES, "max_chars": MAX_TARGET_CHARS, "url": TESTER}


@page.router.get("/test", include_in_schema=False)
async def tester_answer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """The tester's answer (`target_answer`, the API's own function), swapped in under the form."""

    async def build(view: PageView) -> dict[str, Any]:
        target = view.param("target", max_chars=MAX_TARGET_CHARS)
        if not target:
            raise common.validation_error({"target": "Paste a Roblox URL such as users.roblox.com/v1/users/1."})
        method = view.param("method", "GET", max_chars=8).upper() or "GET"
        if method not in METHOD_CHOICES:
            raise common.validation_error({"method": "Pick GET, HEAD, POST, PUT, PATCH or DELETE."})
        answer = policy_api.target_answer(view.ctx, target, method)
        status = view.ctx.settings.get("endpoint_policy_block_status")
        return {
            "answer": answer,
            "verdict": verdict_cell(str(answer["verdict"])),
            "default": verdict_cell(str(answer["default_verdict"])),
            "risk": risk_cell(int(answer.get("risk") or 1)),
            "source_words": SOURCE_WORDS.get(str(answer["source"]), str(answer["source"])),
            "row_drawer": drawer_url(str(answer["endpoint_id"])) if answer.get("known") else None,
            "unknown_drawer": unknown_url(str(answer["endpoint_id"])) if not answer.get("known") else None,
            "block_status": str(status or "403"),
        }

    return await render_partial(page, request, principal, "admin/pages/policy/_test.html", build)


# ============================================================================================ unknown endpoints


@page.card("unknown")
async def unknown_card(view: PageView) -> dict[str, Any]:
    """Operations callers asked for in the range that Roblox does not document (`counted_answer`)."""
    spec = policy_api.UNKNOWN_SPEC
    tq, notice = table_query(view, spec, address=False)
    answer = await policy_api.counted_answer(view.ctx, spec, tq, view.tr, POLICY_UNKNOWN_EVENT)
    policy = view.ctx.rules.snapshot.endpoint_policy
    rows = []
    for item in answer.get("items") or ():
        endpoint_id = str(item.get("endpoint_id") or "")
        try:
            now = policy_api.unknown_item(policy, endpoint_id)
        except common.ApiError:
            now = None
        given = str(item.get("verdict") or "")
        rows.append(
            {
                **item,
                "given": verdict_cell(given) if given in VERDICT_TONES else None,
                "now": verdict_cell(now["verdict"]) if now else None,
                "changed": bool(now and now["changed"]),
                "when": view.time_cell(item["last_ms"] / 1000) if isinstance(item.get("last_ms"), int) else None,
                "drawer": unknown_url(endpoint_id) if now else None,
            }
        )
    table = table_view(
        view,
        "policy-unknown",
        spec,
        answer,
        src=view.fragment_url("unknown"),
        export_url=view.api_url("policy/unknown"),
        caption="Unknown endpoints seen",
        search_placeholder="Search endpoints",
        notice=notice,
        address=False,
    )
    return {"table": table, "rows": rows, "range": view.time.view}


@page.router.get("/unknown-row", include_in_schema=False)
async def unknown_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """Set the verdict of one operation Roblox does not document (`PUT /policy/endpoints` with its `unknown:` id)."""

    async def build(view: PageView) -> dict[str, Any]:
        endpoint_id = view.param("id", max_chars=MAX_ID_CHARS + 1)
        if not 0 < len(endpoint_id) <= MAX_ID_CHARS:
            raise common.not_found("Choose an endpoint from the Unknown endpoints seen table.")
        policy = view.ctx.rules.snapshot.endpoint_policy
        item = policy_api.unknown_item(policy, endpoint_id)
        return {
            "item": item,
            "verdict": verdict_cell(item["verdict"]),
            "default": verdict_cell(item["default_verdict"]),
            "options": verdict_options(str(item["method"])),
            "current_rank": LOOSENING[Verdict(item["verdict"])],
            "url": f"{API}/policy/endpoints",
            "history_url": audit_url(policy_api.OVERRIDES, endpoint_id),
            "help": {"loosen": policy_api.LOOSEN_NOTE},
        }

    return await render_partial(page, request, principal, "admin/pages/policy/_unknown_row.html", build)


# ============================================================================================ sign-in attempts


@page.card("attempts")
async def attempts_card(view: PageView) -> dict[str, Any]:
    """Caller sign-in attempts in the range, newest first (`attempts_answer`); the values are never stored."""
    spec = policy_api.ATTEMPT_SPEC
    tq, notice = table_query(view, spec, address=False)
    if tq.order != "desc":
        tq, notice = replace(tq, order="desc"), "This log is listed newest first only."
    answer = await policy_api.attempts_answer(view.ctx, tq, view.tr)
    real = sum(1 for item in answer.get("items") or () if item.get("looks_real"))

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        at_ms = item.get("at_ms")
        return {
            "at_ms": view.time_cell(at_ms / 1000) if isinstance(at_ms, int | float) else None,
            "ip": {"text": item.get("ip"), "mono": True} if item.get("ip") else None,
            "looks_real": {"text": "Yes: this caller leaked a live cookie", "tone": "bad"}
            if item.get("looks_real")
            else {"text": "No", "tone": "muted"},
            "fingerprint": {"text": item.get("fingerprint"), "mono": True} if item.get("fingerprint") else None,
        }

    table = table_view(
        view,
        "policy-attempts",
        spec,
        answer,
        src=view.fragment_url("attempts"),
        columns=(
            "at_ms",
            "ip",
            "kind",
            "where",
            "name",
            "looks_real",
            "fingerprint",
            "endpoint",
            "user_agent",
            "count",
        ),
        key_columns=("at_ms", "kind", "looks_real"),
        hidden=("user_agent", "count"),
        cells=cells,
        row_id=lambda item: f"attempt-{item.get('id', '')}",
        export_url=view.api_url("policy/attempts"),
        caption="Caller sign-in attempts",
        empty={
            "title": "No caller sent a sign-in in this range",
            "body": "Callers never need to send a Roblox cookie or an API key: Roxy uses its own account. Any that do "
            "are refused and listed here.",
            "icon": "shield",
            "tone": "good",
        },
        search_placeholder="Search",
        notice=notice,
        address=False,
    )
    for column in table["columns"]:
        column["sortable"] = False  # newest first only
    return {"table": table, "real": real, "range": view.time.view}


# ============================================================================================ shadow mode


@page.card("would-block")
async def would_block_card(view: PageView) -> dict[str, Any]:
    """What the policy would have refused while `endpoint_policy_enforce` was off (`counted_answer`)."""
    spec = policy_api.WOULD_BLOCK_SPEC
    tq, notice = table_query(view, spec, address=False)
    answer = await policy_api.counted_answer(view.ctx, spec, tq, view.tr, POLICY_WOULD_BLOCK_EVENT)
    enforced = bool(view.ctx.settings.int("endpoint_policy_enforce"))

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        last = item.get("last_ms")
        return {"last_ms": view.time_cell(last / 1000) if isinstance(last, int | float) else None}

    table = table_view(
        view,
        "policy-would-block",
        spec,
        answer,
        src=view.fragment_url("would-block"),
        cells=cells,
        row_id=lambda item: f"shadow-{item.get('endpoint_id', '')}",
        export_url=view.api_url("policy/would-block"),
        caption="Requests shadow mode let through",
        empty={
            "title": "Nothing in this range",
            "body": "This table fills only while Refuse blocked endpoints (endpoint_policy_enforce) is off: then "
            "Roxy sends a blocked endpoint's request (never with its account) and counts it here.",
            "icon": "eye",
            "tone": "neutral",
        },
        search_placeholder="Search endpoints",
        notice=notice,
        address=False,
    )
    return {"table": table, "enforced": enforced, "range": view.time.view}


__all__ = ["page", "router"]
