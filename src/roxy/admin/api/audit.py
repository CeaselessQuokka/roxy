"""Audit API (`/admin/api/v1/audit`): the full audit log with search, filters, diff view data and revert links.

What this is
    The routes behind the Audit page (plan 9.7, 14.1):
      * `GET /audit`: the log as a table (newest first; paging, sorting, `q` search over action, target, actor,
        reason and request id), with filters `action`, `actor` and `target` (exact, or a prefix ending in `*`
        such as `setting:*` or `rule.*`) and a time window `from` / `to`. `format=csv|json` downloads it
        (formula guarded, IP addresses hashed unless `export_include_ips` is on, in the previews and targets too,
        read one page at a time within the export caps, the download itself audited).
      * `GET /audit/facets`: the actions and actors in the log with their counts (the filter menus).
      * `GET /audit/{id}`: one entry with `before` and `after` decoded, a flat `diff` (path, change, before,
        after) for the diff viewer, a `revert` block and a `manage` link to the page that owns the target.

Why it exists
    Plan 9.7: every admin action and every security-relevant automatic action is written to `audit_log`, and "the
    Audit page supports search, filters, export, and links from any setting or rule to its history". Plan 14.1
    adds the diff view and the revert links.

How it works
    Reads go through `config/read_audit.py` (the read model next to `config/audit.py`). The diff is computed here
    from the two decoded documents (bounded to `MAX_DIFF_ENTRIES` paths and `MAX_DIFF_DEPTH` levels, plan P9).
    A revert is offered where one is meaningful and safe to perform from history: settings changes (`setting.*`,
    `settings.import`) link to `POST /admin/api/v1/settings/history/{id}/revert`, which writes its own audit row.
    Rule, ban and list changes link to the page and card that manage them (their own APIs make the change, with
    their own validation). Secret targets hold only `{fingerprint, masked}` (plan 6.2), so the diff of a
    credential replace shows fingerprints, never a value.

What to read next
    `roxy/config/read_audit.py`, `roxy/config/audit.py`, `roxy/admin/api/settings.py` (the revert route).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Annotated, Any, Final

from fastapi import Depends, Query, Request

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminSession,
    Column,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    table_params,
)
from roxy.config import catalog, read_audit
from roxy.config.audit import is_secret_target
from roxy.deps import get_ctx

router = common.area_router("audit")

MAX_DIFF_ENTRIES: Final = 500
MAX_DIFF_DEPTH: Final = 8
MAX_FILTER_CHARS: Final = 200

AUDIT_TABLE: Final = TableSpec(
    name="audit_log",
    columns=(
        Column("id", "Entry", "The audit entry number."),
        Column("at", "When", "When the action happened (Unix seconds).", "s"),
        Column("actor", "Who", "Who acted: admin:<name>, system:<what>, recommendation:<rule>, cli, import."),
        Column("actor_ip", "From", "The address the admin acted from.", sortable=False, ip=True),
        Column("action", "Action", "What was done, as a dotted name (setting.update, rule.delete, data.reset)."),
        Column(
            "target", "Target", "What it was done to (setting:<key>, <table>:<id>, credential, ...).", caller_text=True
        ),
        Column("reason", "Reason", "The reason given.", sortable=False),
        Column("request_id", "Request", "The request id, to find the matching log lines.", sortable=False),
        Column(
            "before_preview",
            "Before",
            "The state before (the first 2000 characters).",
            sortable=False,
            caller_text=True,
        ),
        Column(
            "after_preview", "After", "The state after (the first 2000 characters).", sortable=False, caller_text=True
        ),
    ),
    default_sort="id",
)

MANAGE_PAGES: Final[dict[str, tuple[str, str]]] = {
    "rules_endpoint_block": ("/admin/protection#endpoint-blocks", "Protection > Endpoint blocks"),
    "rules_endpoint_limit": ("/admin/protection#endpoint-rules", "Protection > Endpoint rules"),
    "rules_cache": ("/admin/cache#rules", "Cache > Rules"),
    "rules_user_agent": ("/admin/protection#ua-rules", "Protection > UA rules"),
    "rules_header": ("/admin/protection#request-filters", "Protection > Request filters"),
    "rules_routing": ("/admin/upstream#routing", "Upstream > Routing"),
    "upstream_limits": ("/admin/upstream#buckets", "Upstream > Buckets"),
    "credential_allowlist": ("/admin/credential#allowlist", "Credential > Allowlist"),
    "throttle_tiers": ("/admin/protection#throttle", "Protection > Throttle ladder"),
    "cache_ignored_params": ("/admin/cache#ignored-params", "Cache > Ignored parameters"),
    "ignored_value_headers": ("/admin/security#fingerprints", "Security > Fingerprints"),
    "ignored_paths": ("/admin/protection#ignored-paths", "Protection > Ignored paths"),
    "access_list": ("/admin/protection#bypass", "Protection > Bypass and lists"),
    "bans": ("/admin/protection#bans", "Protection > Bans"),
    "credential": ("/admin/credential#status", "Credential > Status"),
    "rotator_url": ("/admin/egress#rotator", "Egress > Rotator"),
    "table": ("/admin/data#exports", "Data > Exports"),
    "reset": ("/admin/data#resets", "Data > Resets"),
}
"""Where each audit target kind is managed (page `/admin/<page>`, card anchor; DESIGN.md section 9 anchors)."""


# ================================================================================================ diff


def _flatten(value: Any, path: str, depth: int, out: dict[str, Any]) -> None:
    if len(out) >= MAX_DIFF_ENTRIES:
        return
    if depth < MAX_DIFF_DEPTH and isinstance(value, Mapping) and value:
        for key, item in value.items():
            _flatten(item, f"{path}.{key}" if path else str(key), depth + 1, out)
        return
    if depth < MAX_DIFF_DEPTH and isinstance(value, list) and value:
        for index, item in enumerate(value):
            _flatten(item, f"{path}[{index}]", depth + 1, out)
        return
    out[path or "$"] = value


def diff(before: Any, after: Any) -> dict[str, Any]:
    """A flat diff of two JSON documents: `{entries: [{path, change, before, after}], truncated}`.

    `change` is `added`, `removed` or `changed`; unchanged paths are left out. Paths look like `value`,
    `rows[0].pattern`, or `$` for a document that is a plain value.
    """
    left: dict[str, Any] = {}
    right: dict[str, Any] = {}
    if before is not None:  # no document (a create or a delete) has no paths at all
        _flatten(before, "", 0, left)
    if after is not None:
        _flatten(after, "", 0, right)
    entries: list[dict[str, Any]] = []
    for path in list(dict.fromkeys([*left, *right])):
        if len(entries) >= MAX_DIFF_ENTRIES:
            break
        if path not in right:
            entries.append({"path": path, "change": "removed", "before": left[path], "after": None})
        elif path not in left:
            entries.append({"path": path, "change": "added", "before": None, "after": right[path]})
        elif left[path] != right[path]:
            entries.append({"path": path, "change": "changed", "before": left[path], "after": right[path]})
    truncated = len(left) >= MAX_DIFF_ENTRIES or len(right) >= MAX_DIFF_ENTRIES
    return {"entries": entries, "truncated": truncated}


# ================================================================================================ revert and links


def target_kind(target: str | None) -> str:
    """The kind part of a target (`setting`, `rules_cache`, `bans`, `credential`, ...)."""
    return (target or "").split(":", 1)[0]


def manage_link(target: str | None) -> dict[str, str] | None:
    """The page and card that manage a target, or None."""
    kind = target_kind(target)
    if kind == "setting":
        key = (target or "").split(":", 1)[1] if ":" in (target or "") else ""
        if key in catalog.CATALOG:
            return {"href": f"/admin/settings?key={key}", "label": f"Settings > {catalog.CATALOG[key].label}"}
        return {"href": "/admin/settings", "label": "Settings"}
    page = MANAGE_PAGES.get(kind)
    return None if page is None else {"href": page[0], "label": page[1]}


def revert_info(entry: Mapping[str, Any], history_id: int | None) -> dict[str, Any]:
    """The revert block of an entry: whether a one-click revert exists, and how to call it."""
    action = str(entry.get("action") or "")
    target = str(entry.get("target") or "")
    if action in read_audit.SETTING_ACTIONS and target.startswith("setting:"):
        key = target.split(":", 1)[1]
        spec = catalog.CATALOG.get(key)
        if spec is None:
            return {"available": False, "reason": "This setting no longer exists."}
        if history_id is None:
            return {"available": False, "reason": "The settings history entry of this change was pruned."}
        if spec.sensitive:
            return {"available": False, "reason": "Sensitive values are not kept in history; enter the value again."}
        return {
            "available": True,
            "method": "POST",
            "url": f"{common.API_PREFIX}/settings/history/{history_id}/revert",
            "history_id": history_id,
            "body": {"reason": ""},
            "history_url": f"{common.API_PREFIX}/settings/{key}/history",
        }
    if action.startswith(("rule.", "throttle_tiers.", "defaults.")):
        return {
            "available": False,
            "reason": "Rules are changed back on the card that manages them, with their own checks.",
        }
    return {"available": False, "reason": "This action has nothing to revert."}


# ================================================================================================ routes


def audit_window(ctx: Any, since: str | None, until: str | None) -> tuple[int | None, int | None]:
    """The `from` and `to` filters as epoch seconds in `ui_timezone` (422 `invalid_range` when unreadable)."""
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    values: dict[str, int | None] = {"from": None, "to": None}
    problems: dict[str, str] = {}
    for name, raw in (("from", since), ("to", until)):
        if raw:
            try:
                values[name] = int(common.parse_instant(raw, tz=tz))
            except ValueError as exc:
                problems[name] = str(exc)
    if problems:
        raise common.validation_error(problems, "The time filter is not valid.", code="invalid_range")
    return values["from"], values["to"]


_window = audit_window  # the name this module used before the Audit page needed it


def audit_reader(
    tq: TableQuery,
    *,
    action: str | None,
    actor: str | None,
    target: str | None,
    since: int | None,
    until: int | None,
) -> Callable[[int, int], Callable[[Any], tuple[list[dict[str, Any]], int]]]:
    """`reader(page, size)` -> a control.db read of one page of the filtered log (the table and its export)."""

    def reader(page: int, size: int) -> Callable[[Any], tuple[list[dict[str, Any]], int]]:
        def run(conn: Any) -> tuple[list[dict[str, Any]], int]:
            return read_audit.audit_page(
                conn,
                action=action,
                actor=actor,
                target=target,
                q=tq.q,
                since=since,
                until=until,
                sort=tq.sort,
                descending=tq.descending,
                limit=size,
                offset=(page - 1) * size,
            )

        return run

    return reader


def list_items(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The table rows as `GET /audit` answers them: each with its `manage` link and `detail_url`."""
    return [
        {**row, "manage": manage_link(row.get("target")), "detail_url": f"{common.API_PREFIX}/audit/{row['id']}"}
        for row in rows
    ]


async def audit_table(
    ctx: Any,
    tq: TableQuery,
    *,
    action: str | None = None,
    actor: str | None = None,
    target: str | None = None,
    since: int | None = None,
    until: int | None = None,
) -> dict[str, Any]:
    """The `GET /audit` table answer for one page (the API route and the Audit page both call this)."""
    reader = audit_reader(tq, action=action, actor=actor, target=target, since=since, until=until)
    rows, total = await ctx.dbs.control.read(reader(tq.page, tq.page_size))
    answer = common.table_answer(AUDIT_TABLE, tq, list_items(rows), total)
    answer["filters"] = {"action": action, "actor": actor, "target": target, "from": since, "to": until}
    return answer


@router.get("", response_model=None)
async def list_audit(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(AUDIT_TABLE))],
    fmt: ExportFormatDep,
    action: Annotated[str | None, Query(max_length=64)] = None,
    actor: Annotated[str | None, Query(max_length=80)] = None,
    target: Annotated[str | None, Query(max_length=MAX_FILTER_CHARS)] = None,
    from_: Annotated[str | None, Query(alias="from", max_length=common.MAX_TIME_TEXT)] = None,
    to: Annotated[str | None, Query(max_length=common.MAX_TIME_TEXT)] = None,
) -> Any:
    """The audit log as a table (plan 9.7): search, filters, server-side paging and sorting, export."""
    ctx = get_ctx(request)
    since, until = audit_window(ctx, from_, to)
    filters = {"action": action, "actor": actor, "target": target, "from": since, "to": until}
    if fmt is not None:
        reader = audit_reader(tq, action=action, actor=actor, target=target, since=since, until=until)

        async def fetch(page: int, size: int) -> tuple[list[dict[str, Any]], int]:
            rows, total = await ctx.dbs.control.read(reader(page, size))
            return list(rows), int(total)

        kept = {name: value for name, value in filters.items() if value is not None}
        # One page at a time: an audit row may carry 4,000 characters of previews (mpjobs-5).
        return await common.export_pages(request, admin, AUDIT_TABLE, fetch, fmt, tq=tq, filters=kept)
    return await audit_table(ctx, tq, action=action, actor=actor, target=target, since=since, until=until)


async def audit_facets(ctx: Any) -> dict[str, Any]:
    """The actions and actors in the log with their counts (`GET /audit/facets`; the page's filter menus)."""
    data: dict[str, Any] = await ctx.dbs.control.read(read_audit.audit_facets)
    return data


@router.get("/facets")
async def facets(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The actions and actors in the log with their counts (the Audit page's filter menus)."""
    return await audit_facets(get_ctx(request))


async def entry_view(ctx: Any, audit_id: int) -> dict[str, Any] | None:
    """One audit entry with its diff, its revert block and the link to what it changed (`GET /audit/{id}`), or
    None when no entry has that id. The API route and the Audit page's entry drawer both call this."""

    def read(conn: Any) -> tuple[dict[str, Any] | None, int | None]:
        found = read_audit.audit_entry(conn, audit_id)
        if found is None:
            return None, None
        target = str(found.get("target") or "")
        history_id = None
        if found["action"] in read_audit.SETTING_ACTIONS and target.startswith("setting:"):
            history_id = read_audit.settings_history_id(conn, target.split(":", 1)[1], found["at"], found["actor"])
        return found, history_id

    found, history_id = await ctx.dbs.control.read(read)
    if found is None:
        return None
    return {
        "entry": found,
        "diff": diff(found.get("before"), found.get("after")),
        "revert": revert_info(found, history_id),
        "manage": manage_link(found.get("target")),
        # A secret-bearing target holds fingerprints only (plan 6.2); the page says so next to the diff.
        "secret_target": is_secret_target(found.get("target")),
    }


@router.get("/{audit_id}")
async def get_entry(request: Request, audit_id: common.RowId, _admin: AdminSession) -> dict[str, Any]:
    """One audit entry with its diff, its revert block and the link to what it changed."""
    view = await entry_view(get_ctx(request), audit_id)
    if view is None:
        raise common.not_found("No audit entry has that id.")
    return view


__all__ = [
    "AUDIT_TABLE",
    "MANAGE_PAGES",
    "audit_facets",
    "audit_reader",
    "audit_table",
    "audit_window",
    "diff",
    "entry_view",
    "list_items",
    "manage_link",
    "revert_info",
    "router",
    "target_kind",
]
