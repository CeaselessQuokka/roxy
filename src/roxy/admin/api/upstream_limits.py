"""Upstream bucket overrides API (`/admin/api/v1/upstream-limits`): per-host and per-endpoint rates (plan 7.3).

What this is
    CRUD for the `upstream_limits` table, the rows that replace the default rate and burst of one bucket:
      * `GET /upstream-limits`: every override as a section 13 table with the defaults it replaces (export too).
      * `POST /upstream-limits`: add `bucket_key` (`host:<host>` or `endpoint:<template>`), `per_min`, `burst`.
      * `GET`, `PATCH` and `DELETE /upstream-limits/{bucket_key}`: the key is the rest of the path, so an endpoint
        template with slashes and `{placeholders}` needs no escaping beyond URL encoding.

Why it exists
    Plan 7.3: Roblox limits each endpoint, so each endpoint and host has its own bucket. An admin sets a rate here,
    an applied UP-BUCKET-TUNE recommendation sets one through the same table, and the adaptive controller lowers and
    raises rates with origin `adaptive`. A rate an admin writes gets origin `admin`, which the adaptive controller
    never raises again (it may still lower it on a 429, safety first).

How it works
    `rules/service.py` validates the key and the numbers, writes the row, the audit row and the `config_version`
    bump in one transaction; this module only shapes bodies and answers. Deleting an override returns the bucket to
    the default rate of its kind (`host_bucket_default_per_min`, `endpoint_bucket_default_per_min`).

What to read next
    `roxy/upstream/buckets.py` (`specs_for`), `roxy/upstream/adaptive.py`, `roxy/rules/models.py`
    (`UpstreamLimitIn`).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Final

from fastapi import Depends, Request
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
from roxy.admin.api.routing_rules import (
    DeleteBody,
    Note,
    Reason,
    all_rows,
    change_answer,
    changes_of,
    rules_service,
)
from roxy.config.constants import MAX_RULE_LIMIT
from roxy.deps import get_ctx
from roxy.rules.models import MAX_BUCKET_KEY
from roxy.upstream.buckets import BucketDefaults

router = common.area_router("upstream-limits")

TABLE: Final = "upstream_limits"
MAX_BURST: Final = 10_000

SPEC: Final = TableSpec(
    name="upstream_limits",
    columns=(
        Column("bucket_key", "Bucket", "host:<host> or endpoint:<template>."),
        Column("kind", "Kind", "host or endpoint."),
        Column("per_min", "Rate", "Calls per minute this bucket allows at the steady rate.", "per_min"),
        Column("burst", "Burst", "How many calls may go at once before pacing starts.", "count"),
        Column("default_per_min", "Default rate", "The rate the bucket has without this override.", "per_min"),
        Column(
            "origin",
            "Set by",
            "admin, recommendation (an applied UP-BUCKET-TUNE), adaptive (the rate controller) or default.",
        ),
        Column("note", "Note", "The note on the override.", sortable=False),
        Column("updated_at", "Updated", "When it last changed (Unix seconds).", "s"),
        Column("updated_by", "Updated by", "Who changed it last."),
    ),
    default_sort="bucket_key",
    default_order="asc",
)

BucketKey = Annotated[str, Field(min_length=1, max_length=MAX_BUCKET_KEY)]
Rate = Annotated[float, Field(gt=0, le=MAX_RULE_LIMIT, allow_inf_nan=False)]
Burst = Annotated[int, Field(ge=1, le=MAX_BURST)]


class LimitBody(ApiBody):
    """`POST /upstream-limits`."""

    bucket_key: BucketKey
    per_min: Rate
    burst: Burst
    note: Note = ""
    reason: Reason = ""


class LimitPatch(ApiBody):
    """`PATCH /upstream-limits/{bucket_key}`: only the fields given change."""

    per_min: Rate | None = None
    burst: Burst | None = None
    note: Note | None = None
    reason: Reason = ""


def _defaults(request: Request) -> BucketDefaults:
    return BucketDefaults.from_settings(get_ctx(request).settings)


def item_of(row: Mapping[str, Any], defaults: BucketDefaults) -> dict[str, Any]:
    """One override with the default it replaces."""
    key = str(row.get("bucket_key") or "")
    kind = key.partition(":")[0]
    default = defaults.host if kind == "host" else defaults.endpoint
    return {
        "bucket_key": key,
        "kind": kind,
        "target": key.partition(":")[2],
        "per_min": row.get("per_min"),
        "burst": row.get("burst"),
        "default_per_min": default.per_min,
        "default_burst": default.burst,
        "origin": row.get("origin"),
        "note": row.get("note") or "",
        "updated_at": row.get("updated_at"),
        "updated_by": row.get("updated_by"),
    }


@router.get("")
async def list_limits(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Every override (at most 2,500, plan 15.4) with the defaults it replaces."""
    defaults = _defaults(request)
    with common.service_errors():
        rows = [item_of(row, defaults) for row in await rules_service(request).list_rows(TABLE)]
    keys = ("bucket_key", "origin", "note", "updated_by")
    if fmt is not None:
        items, total = all_rows(rows, tq, search_keys=keys)
        return await common.export_table(request, admin, SPEC, items, fmt, total=total, tq=tq)
    items, total = common.page_rows(rows, tq, search_keys=keys)
    answer = common.table_answer(SPEC, tq, items, total)
    answer["defaults"] = {
        "host": {"per_min": defaults.host.per_min, "burst": defaults.host.burst},
        "endpoint": {"per_min": defaults.endpoint.per_min, "burst": defaults.endpoint.burst},
    }
    answer["adaptive_enabled"] = bool(get_ctx(request).settings.get("adaptive_rate_enabled"))
    return answer


@router.post("", status_code=201)
async def create_limit(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: LimitBody) -> Any:
    """Add an override (origin `admin`; audited; every worker follows within a second)."""
    row = body.model_dump(exclude={"reason"}) | {"origin": "admin"}
    change = await common.run_mutation(
        rules_service(request).create(
            TABLE, row, common.actor_for(admin), body.reason, request_id=common.request_id_of(request)
        )
    )
    defaults = _defaults(request)
    return change_answer(change, lambda after: item_of(after, defaults))


@router.get("/{bucket_key:path}")
async def get_limit(request: Request, _admin: AdminSession, bucket_key: str) -> dict[str, Any]:
    """One override."""
    with common.service_errors():
        row = await rules_service(request).get_row(TABLE, bucket_key[:MAX_BUCKET_KEY])
    if row is None:
        raise common.not_found("No override exists for that bucket; it runs at its default rate.")
    return item_of(row, _defaults(request))


@router.patch("/{bucket_key:path}")
async def update_limit(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, bucket_key: str, body: LimitPatch
) -> dict[str, Any]:
    """Change an override. A new rate or burst makes it an `admin` rate (the adaptive controller never raises it)."""
    changes = changes_of(body)
    if "per_min" in changes or "burst" in changes:
        changes["origin"] = "admin"
    change = await common.run_mutation(
        rules_service(request).update(
            TABLE,
            bucket_key[:MAX_BUCKET_KEY],
            changes,
            common.actor_for(admin),
            body.reason,
            request_id=common.request_id_of(request),
        )
    )
    defaults = _defaults(request)
    return change_answer(change, lambda after: item_of(after, defaults))


@router.delete("/{bucket_key:path}")
async def delete_limit(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, bucket_key: str, body: DeleteBody | None = None
) -> dict[str, Any]:
    """Remove an override: the bucket goes back to the default rate of its kind (audited)."""
    reason = body.reason if body is not None else ""
    change = await common.run_mutation(
        rules_service(request).delete(
            TABLE,
            bucket_key[:MAX_BUCKET_KEY],
            common.actor_for(admin),
            reason,
            request_id=common.request_id_of(request),
        )
    )
    before = change.before if isinstance(change.before, Mapping) else None
    return {
        "deleted": item_of(before, _defaults(request)) if before is not None else None,
        "audit_id": change.audit_id,
        "config_version": change.config_version,
    }


__all__ = ["SPEC", "router"]
