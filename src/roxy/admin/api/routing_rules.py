"""Routing rules API (`/admin/api/v1/routing-rules`): per-endpoint egress preferences (plan 7.2 step 2).

What this is
    CRUD for the `rules_routing` table and a tester:
      * `GET /routing-rules`: the rules as a section 13 table (paging, sorting, search, `format=csv|json` export).
      * `POST /routing-rules`: add a rule (`pattern`, `type` glob or regex, `mode` prefer_direct, prefer_rotator,
        direct_only or rotator_only, `note`, `enabled`, `reason`).
      * `GET`, `PATCH` and `DELETE /routing-rules/{id}`: read, change some fields, remove.
      * `GET /routing-rules/test?target=host/path`: which rule decides that path right now (the live snapshot).
    It also holds the small helpers the other rule areas of this team share (`change_answer`, `DeleteBody`,
    `normalize_target`, `rule_flag`), so the three rule tables answer in one shape.

Why it exists
    Plan 7.2 step 2 lets an admin pin an endpoint to an egress (for example keep a fragile endpoint off the rotator,
    or move one that the server IP keeps getting 429s on to it, EGR-UNDERUSE). Every change goes through
    `rules/service.py`, which validates, writes the row, the audit row and the `config_version` bump in one
    control.db transaction (DESIGN.md section 13), so every worker follows within a second.

How it works
    Bodies are `ApiBody` models (unknown fields refused, strings bounded); the service's refusals (a bad pattern, a
    duplicate pattern, the 200 rule cap) become 422, 409 or 409 `cap_reached` through `common.run_mutation`. The
    tester matches under its own regex budget (plan 9.9), exactly as the upstream router does.

What to read next
    `roxy/rules/service.py`, `roxy/rules/models.py` (`RoutingRuleIn`), `roxy/upstream/routing.py` (how a rule is
    honored "within availability").
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Query, Request
from pydantic import Field

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    table_params,
)
from roxy.config.constants import MAX_REASON_LENGTH, MAX_RULE_NOTE
from roxy.deps import get_ctx
from roxy.rules.match import regex_budget
from roxy.rules.models import MAX_RAW_PATTERN
from roxy.rules.service import RuleChange, RulesService

router = common.area_router("routing-rules")

TABLE: Final = "rules_routing"
MODES: Final = ("prefer_direct", "prefer_rotator", "direct_only", "rotator_only")
MAX_TARGET_CHARS: Final = 2048

SPEC: Final = TableSpec(
    name="routing_rules",
    columns=(
        Column("id", "Id", "The rule's number."),
        Column("pattern", "Pattern", "The endpoint it applies to: host/path, a glob or a regular expression."),
        Column("type", "Type", "glob or regex."),
        Column(
            "mode",
            "Mode",
            "prefer_direct or prefer_rotator choose that egress when it is available; direct_only and rotator_only "
            "never use the other one.",
        ),
        Column("enabled", "Enabled", "Whether the rule is in force."),
        Column("note", "Note", "The admin's note.", sortable=False),
        Column("created_at", "Created", "When the rule was added (Unix seconds).", "s"),
        Column("created_by", "Created by", "Who added it."),
        Column("updated_at", "Updated", "When it last changed (Unix seconds).", "s"),
    ),
    default_sort="id",
    default_order="asc",
)

Pattern = Annotated[str, Field(min_length=1, max_length=MAX_RAW_PATTERN)]
Note = Annotated[str, Field(max_length=MAX_RULE_NOTE)]
Reason = Annotated[str, Field(max_length=MAX_REASON_LENGTH)]


# ---------------------------------------------------------------------------------------- shared helpers


class DeleteBody(ApiBody):
    """The optional body of a DELETE: why (goes in the audit row)."""

    reason: Reason = ""


def rule_flag(value: Any) -> bool:
    """A stored 0/1 column as a JSON boolean."""
    return bool(value)


def change_answer(change: RuleChange, item: Callable[[Mapping[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    """The answer of a rule mutation: the row after it, whether anything changed, the audit id, the version."""
    after = change.after if isinstance(change.after, Mapping) else None
    return {
        "item": item(after) if after is not None else None,
        "changed": change.changed,
        "audit_id": change.audit_id,
        "config_version": change.config_version,
        "warnings": list(change.warnings),
    }


def normalize_target(raw: str) -> str:
    """`host/path` as the upstream router matches rules: no scheme, no query, a lowercase host, a leading slash."""
    text = raw.strip()
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix) :]
    text = text.lstrip("/").split("#", 1)[0].split("?", 1)[0]
    host, sep, path = text.partition("/")
    host = host.strip().lower().rstrip(".")
    if not host:
        raise common.validation_error({"target": "Give a host and path such as games.roblox.com/v1/games."})
    return f"{host}/{path}" if sep else f"{host}/"


def rules_service(request: Request) -> RulesService:
    """The audited rules service bound to this worker's control.db, clock and rules store."""
    return service_for(get_ctx(request))


def service_for(ctx: Any) -> RulesService:
    """`rules_service` for a worker context (the dashboard pages read the rule tables through it too)."""
    return RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules)


def all_rows(rows: list[dict[str, Any]], tq: TableQuery, *, search_keys: tuple[str, ...] = ()) -> tuple[list[Any], int]:
    """Every row of a small table searched and sorted like the page (for an export: no paging, capped)."""
    whole = common.TableQuery(1, common.MAX_EXPORT_ROWS, tq.sort, tq.order, tq.q)
    return common.page_rows(rows, whole, search_keys=search_keys)


def changes_of(body: ApiBody, *, exclude: frozenset[str] = frozenset({"reason"})) -> dict[str, Any]:
    """The fields a PATCH body set (never `{}`: an empty change is a 422)."""
    changes = {key: value for key, value in body.model_dump(exclude_unset=True).items() if key not in exclude}
    if not changes:
        raise common.validation_error({"body": "Name at least one field to change."}, "Nothing to change.")
    return changes


# --------------------------------------------------------------------------------------------- bodies


class RoutingRuleBody(ApiBody):
    """`POST /routing-rules`."""

    pattern: Pattern
    type: Literal["glob", "regex"] = "glob"
    mode: Literal["prefer_direct", "prefer_rotator", "direct_only", "rotator_only"]
    note: Note = ""
    enabled: bool = True
    reason: Reason = ""


class RoutingRulePatch(ApiBody):
    """`PATCH /routing-rules/{id}`: only the fields given change."""

    pattern: Pattern | None = None
    type: Literal["glob", "regex"] | None = None
    mode: Literal["prefer_direct", "prefer_rotator", "direct_only", "rotator_only"] | None = None
    note: Note | None = None
    enabled: bool | None = None
    reason: Reason = ""


def item_of(row: Mapping[str, Any]) -> dict[str, Any]:
    """One routing rule as the API shows it."""
    return {
        "id": row.get("id"),
        "pattern": row.get("pattern"),
        "type": row.get("type"),
        "mode": row.get("mode"),
        "enabled": rule_flag(row.get("enabled")),
        "note": row.get("note") or "",
        "created_at": row.get("created_at"),
        "created_by": row.get("created_by"),
        "updated_at": row.get("updated_at"),
        "updated_by": row.get("updated_by"),
    }


# --------------------------------------------------------------------------------------------- routes


@router.get("")
async def list_rules(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Every routing rule (at most 200, plan 15.4), paged and sorted on the server."""
    rows = await rule_rows(get_ctx(request))
    if fmt is not None:
        items, total = all_rows(rows, tq, search_keys=SEARCH_KEYS)
        return await common.export_table(request, admin, SPEC, items, fmt, total=total, tq=tq)
    return rules_answer(rows, tq)


SEARCH_KEYS: Final = ("pattern", "mode", "note", "created_by")


async def rule_rows(ctx: Any) -> list[dict[str, Any]]:
    """Every routing rule as the API shows it (the Upstream page's Routing card lists them too)."""
    with common.service_errors():
        return [item_of(row) for row in await service_for(ctx).list_rows(TABLE)]


def rules_answer(rows: list[dict[str, Any]], tq: TableQuery) -> dict[str, Any]:
    """One page of `rule_rows` as the `GET /routing-rules` table answer."""
    items, total = common.page_rows(rows, tq, search_keys=SEARCH_KEYS)
    return common.table_answer(SPEC, tq, items, total) | {"modes": list(MODES)}


@router.post("", status_code=201)
async def create_rule(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: RoutingRuleBody) -> Any:
    """Add a routing rule (audited; every worker follows within a second)."""
    row = body.model_dump(exclude={"reason"})
    change = await common.run_mutation(
        rules_service(request).create(
            TABLE, row, common.actor_for(admin), body.reason, request_id=common.request_id_of(request)
        )
    )
    return change_answer(change, item_of)


@router.get("/test")
async def check_target(
    request: Request,
    _admin: AdminSession,
    target: Annotated[str, Query(min_length=1, max_length=MAX_TARGET_CHARS)],
) -> dict[str, Any]:
    """Which routing rule decides `target` (host/path) right now, from this worker's live rules snapshot."""
    return target_answer(get_ctx(request), target)


def target_answer(ctx: Any, target: str) -> dict[str, Any]:
    """The answer of `GET /routing-rules/test` (422 for a target without a host; the page's tester shows it)."""
    clean = normalize_target(target)
    snapshot = ctx.rules.snapshot
    with regex_budget(fresh=True):  # the admin's own budget, as a proxied request would have (plan 9.9)
        row = snapshot.routing_rule_for(clean)
    item = item_of(row.model_dump()) if row is not None else None
    return {"target": clean, "rule": item, "mode": item["mode"] if item else None}


@router.get("/{rule_id}")
async def get_rule(request: Request, _admin: AdminSession, rule_id: common.RowId) -> dict[str, Any]:
    """One routing rule."""
    with common.service_errors():
        row = await rules_service(request).get_row(TABLE, rule_id)
    if row is None:
        raise common.not_found("No routing rule has that id.")
    return item_of(row)


@router.patch("/{rule_id}")
async def update_rule(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: common.RowId, body: RoutingRulePatch
) -> dict[str, Any]:
    """Change some fields of a routing rule (only what differs is written and audited)."""
    changes = changes_of(body)
    change = await common.run_mutation(
        rules_service(request).update(
            TABLE, rule_id, changes, common.actor_for(admin), body.reason, request_id=common.request_id_of(request)
        )
    )
    return change_answer(change, item_of)


@router.delete("/{rule_id}")
async def delete_rule(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: common.RowId, body: DeleteBody | None = None
) -> dict[str, Any]:
    """Remove a routing rule (audited, with the row as it was)."""
    reason = body.reason if body is not None else ""
    change = await common.run_mutation(
        rules_service(request).delete(
            TABLE, rule_id, common.actor_for(admin), reason, request_id=common.request_id_of(request)
        )
    )
    return {"deleted": item_of(change.before) if isinstance(change.before, Mapping) else None} | {
        "audit_id": change.audit_id,
        "config_version": change.config_version,
    }


__all__ = [
    "MODES",
    "SPEC",
    "DeleteBody",
    "all_rows",
    "change_answer",
    "changes_of",
    "item_of",
    "normalize_target",
    "router",
    "rule_flag",
    "rule_rows",
    "rules_answer",
    "rules_service",
    "service_for",
    "target_answer",
]
