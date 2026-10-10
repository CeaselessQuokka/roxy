"""The Audit page (`/admin/audit`, plan 14.1 and 9.7): the full audit log with search, filters, diff view and revert.

What this is
    The reference page of P11: every other page copies its pattern. Two cards from the registry:
      * `log`: the audit log as a server-paged table (search, filter chips for action, actor and target, sorting,
        rows per page, CSV and JSON export through the API), each row opening its entry in the drawer.
      * `entry` (fragment-only, the drawer): one entry with who, when, from where and why, its before and after as a
        field diff and as a line diff of the two documents, the link to the card that manages the target, and a
        one-click revert for a settings change (itself audited).
    `/admin/audit?entry=<id>` opens that entry's drawer on load (chart annotations and recommendation histories link
    there); `/admin/audit?target=setting:<key>` lists one setting's history (the inline settings' History links).

Why it exists
    Plan 9.7: every admin action and every security-relevant automatic action is in `audit_log`, and "the Audit page
    supports search, filters, export, and links from any setting or rule to its history"; plan 14.1 adds the diff
    view and the revert links. Plan P6: the page reads the log through the same functions as `GET /admin/api/v1/
    audit` (`admin/api/audit.py audit_table`, `audit_facets`, `entry_view`), so the page and the API can never show
    different rows, and it changes nothing itself: a revert posts to the settings API.

How it works
    `page = Page("audit")`; `@page.card("log")` and `@page.card("entry")` return the context of
    `templates/admin/pages/audit/log.html` and `entry.html`. The time range of the top bar filters the log by when
    the action happened, except "All" (and a link from elsewhere with no range), which shows the whole log: an
    audit log older than the oldest metrics must not disappear. Every caller-chosen text (targets, previews, reasons,
    diff values) is rendered by `format.html caller_text`, never as markup.

What to read next
    `roxy/admin/pages/kit.py`, `templates/admin/pages/audit.html`, `static/js/pages/audit.js`,
    `roxy/admin/api/audit.py`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Final

from roxy.admin.api import audit as audit_api
from roxy.admin.api import common
from roxy.admin.pages import fmt
from roxy.admin.pages.kit import Page, PageView, filter_chip, table_query, table_view
from roxy.admin.pages.texts import diff_lines
from roxy.config.audit import is_secret_target

page = Page("audit", default_range="all")
router = page.router

TABLE_ID: Final = "audit-log"
SHOWN_COLUMNS: Final = (
    "at",
    "actor",
    "action",
    "target",
    "reason",
    "id",
    "actor_ip",
    "request_id",
    "before_preview",
    "after_preview",
)
KEY_COLUMNS: Final = ("at", "action", "target")
HIDDEN_COLUMNS: Final = ("actor_ip", "request_id", "before_preview", "after_preview")
MAX_FILTER_OPTIONS: Final = 60
MAX_DOC_CHARS: Final = 20_000
"""Most characters of one document the line diff shows (a stored document is at most 64 KiB)."""
MAX_VALUE_CHARS: Final = 600

TARGET_KINDS: Final[tuple[tuple[str, str], ...]] = (
    ("setting:*", "Settings"),
    ("rules_cache:*", "Cache rules"),
    ("rules_endpoint_block:*", "Endpoint blocks"),
    ("rules_endpoint_limit:*", "Endpoint rules"),
    ("rules_user_agent:*", "User-Agent rules"),
    ("rules_header:*", "Request filters"),
    ("rules_routing:*", "Routing rules"),
    ("upstream_limits:*", "Upstream limits"),
    ("credential_allowlist:*", "Credential allowlist"),
    ("access_list:*", "Access lists"),
    ("bans:*", "Bans"),
    ("credential*", "The credential"),
    ("table:*", "Downloads"),
    ("reset:*", "Data resets"),
)
"""Target filter choices (a prefix ending in `*`, as `GET /audit` takes them; `admin/api/audit.py MANAGE_PAGES`)."""


def _bounded(view: PageView, name: str, limit: int) -> str | None:
    value = view.param(name, max_chars=limit)
    return value or None


def _choices(current: str | None, base: list[tuple[str, str]]) -> list[tuple[str, str]]:
    values = [value for value, _ in base]
    if current and current not in values:
        base = [*base[:1], (current, current), *base[1:]]
    return base


def action_options(facets: Mapping[str, Any], current: str | None) -> list[tuple[str, str]]:
    """`("", "Any action")`, then each action family (`setting.*`) and each action seen, with its count."""
    actions = [row for row in facets.get("actions") or () if isinstance(row, Mapping)]
    families: dict[str, int] = {}
    for row in actions:
        name = str(row.get("action") or "")
        if "." in name:
            families[name.split(".", 1)[0] + ".*"] = families.get(name.split(".", 1)[0] + ".*", 0) + int(row["count"])
    options = [("", "Any action")]
    options += [(family, f"{family} ({count:,})") for family, count in sorted(families.items())]
    options += [(str(row["action"]), f"{row['action']} ({int(row['count']):,})") for row in actions]
    return _choices(current, options[:MAX_FILTER_OPTIONS])


def actor_options(facets: Mapping[str, Any], current: str | None) -> list[tuple[str, str]]:
    actors = [row for row in facets.get("actors") or () if isinstance(row, Mapping)]
    kinds = sorted(
        {str(row.get("actor") or "").split(":", 1)[0] + ":*" for row in actors if ":" in str(row.get("actor"))}
    )
    options = [("", "Anyone")] + [(kind, kind) for kind in kinds]
    options += [(str(row["actor"]), f"{row['actor']} ({int(row['count']):,})") for row in actors]
    return _choices(current, options[:MAX_FILTER_OPTIONS])


def target_options(current: str | None) -> list[tuple[str, str]]:
    return _choices(current, [("", "Any target"), *TARGET_KINDS])


def window(view: PageView) -> tuple[int | None, int | None]:
    """The log's time filter: the top bar range, or none at all for "All" (see the module docstring)."""
    if view.time.view.get("range") == "all":
        return None, None
    return int(view.tr.window.start), int(view.tr.window.end)


def export_url(view: PageView, since: int | None, until: int | None) -> str:
    """The API route the export menu downloads from (the window as epoch seconds; custom ranges carry their own)."""
    if since is None or view.time.view.get("range") == "custom":
        return f"{common.API_PREFIX}/audit"
    return f"{common.API_PREFIX}/audit?from={since}&to={until}"


@page.card("log")
async def log_card(view: PageView) -> dict[str, Any]:
    """The audit log table (one page from `audit_table`, the API's own function)."""
    tq, notice = table_query(view, audit_api.AUDIT_TABLE)
    action = _bounded(view, "action", 64)
    actor = _bounded(view, "actor", 80)
    target = _bounded(view, "target", audit_api.MAX_FILTER_CHARS)
    since, until = window(view)
    answer = await audit_api.audit_table(
        view.ctx, tq, action=action, actor=actor, target=target, since=since, until=until
    )
    facets = await audit_api.audit_facets(view.ctx)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        reason = item.get("reason")
        return {
            "id": {"text": f"#{item['id']}", "mono": True},
            "reason": {"text": reason, "caller": True} if reason else None,
            "actor_ip": {"text": item.get("actor_ip"), "mono": True} if item.get("actor_ip") else None,
            "request_id": {"text": item.get("request_id"), "mono": True} if item.get("request_id") else None,
        }

    filters = [
        filter_chip("action", "Action", action or "", action_options(facets, action)),
        filter_chip("actor", "Who", actor or "", actor_options(facets, actor)),
        filter_chip("target", "Target", target or "", target_options(target)),
    ]
    table = table_view(
        view,
        TABLE_ID,
        audit_api.AUDIT_TABLE,
        answer,
        src=view.fragment_url("log"),
        columns=SHOWN_COLUMNS,
        key_columns=KEY_COLUMNS,
        hidden=HIDDEN_COLUMNS,
        cells=cells,
        row_id=lambda item: f"audit-{item['id']}",
        drawer=lambda item: view.fragment_url("entry", entry=item["id"]),
        drawer_title=lambda item: f"Audit entry #{item['id']}",
        filters=filters,
        export_url=export_url(view, since, until),
        caption="Audit log",
        empty={
            "title": "No audit entries match",
            "body": "Every change in Roxy is written here as it happens. Try another range in the top bar, or clear "
            "the search and filters.",
            "icon": "clipboard",
        },
        search_placeholder="Search the audit log",
        notice=notice,
    )
    filtered = any((action, actor, target, tq.q))
    return {
        "table": table,
        "total": answer["total"],
        "filtered": filtered,
        "whole_log": view.time.view.get("range") == "all",
        "whole_log_url": "/admin/audit?range=all",
        "range_description": view.time.view.get("description"),
    }


def _json(value: Any) -> str:
    if value is None:
        return ""
    try:
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _cell_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


@page.card("entry")
async def entry_card(view: PageView) -> dict[str, Any]:
    """One entry for the drawer (`entry_view`, the API's own function)."""
    raw = view.param("entry", max_chars=24)
    if not raw.isdigit() or not 1 <= int(raw) <= common.MAX_ROW_ID:
        raise common.not_found("Choose an entry from the log; that entry number is not valid.")
    found = await audit_api.entry_view(view.ctx, int(raw))
    if found is None:
        raise common.not_found("No audit entry has that id. It may have been pruned by the retention settings.")
    entry = found["entry"]
    before_doc = _json(entry.get("before"))
    after_doc = _json(entry.get("after"))
    lines = (
        diff_lines(before_doc[:MAX_DOC_CHARS], after_doc[:MAX_DOC_CHARS], context=3) if before_doc or after_doc else []
    )
    changes = [
        {
            "path": item["path"],
            "change": item["change"],
            "before": _cell_text(item.get("before")),
            "after": _cell_text(item.get("after")),
        }
        for item in found["diff"]["entries"]
    ]
    revert = dict(found["revert"])
    return {
        "entry": entry,
        "when": fmt.time_cell(entry.get("at"), view.tz, view.now),
        "changes": changes,
        "diff_truncated": bool(found["diff"].get("truncated")),
        "lines": lines,
        "docs_cut": len(before_doc) > MAX_DOC_CHARS or len(after_doc) > MAX_DOC_CHARS,
        "has_docs": bool(before_doc or after_doc),
        "revert": revert,
        "manage": found["manage"],
        "secret_target": bool(found["secret_target"]) or is_secret_target(entry.get("target")),
        "max_value_chars": MAX_VALUE_CHARS,
        "log_url": view.page_url(),
    }


__all__ = ["page", "router"]
