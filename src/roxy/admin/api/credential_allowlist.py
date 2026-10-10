"""Credential allowlist API (`/admin/api/v1/credential-allowlist`): the endpoints that may use the credential.

What this is
    CRUD for the `credential_allowlist` table (plan 6.2, 9.13, D1) and a tester:
      * `GET /credential-allowlist`: the rows as a section 13 table, with the D1 notice and what `cache_private`
        means (export with `format=csv|json`).
      * `POST /credential-allowlist`: add a row. `cache_private` is REQUIRED (true or false, no default): the admin
        must decide whether the account's answers may be cached (plan 9.13). Methods are GET and HEAD only.
      * `GET`, `PATCH` and `DELETE /credential-allowlist/{id}`.
      * `GET /credential-allowlist/test?target=host/path&method=GET`: whether a path is granted right now.

Why it exists
    Owner decision D1: callers never get the credential, so the table ships empty; a row is a deliberate exception
    that sends the owner's one Roblox account (C1) for every matching caller request. So adding or changing a row
    needs a fresh second factor and a reason (plan 9.6 sensitive actions); removing one, which only narrows what
    the account is used for, needs the session and CSRF only, so it is never slowed down in an emergency.
    A row grants exactly what it names: a glob has no implicit subpaths and `*` stays in one segment, a regex
    must match the whole path (CHANGES.md "The credential allowlist grants exactly what a row names"; the tester
    shows it). `identical_anonymous` lets Roxy fetch the endpoint anonymously instead; plan 6.2 and 6.9 allow it
    only from CRED-UNUSED evidence, so this API sets it only when the request names an active CRED-UNUSED
    recommendation about that row (`insights/read_evidence.py`), and records the evidence in the audit reason.

How it works
    Bodies are `ApiBody` models with strict booleans (`"yes"` or `1` is not a choice); `rules/service.py` validates
    the pattern in its exact form, refuses a duplicate pattern (409) or the 51st row (409 `cap_reached`), and
    writes the row, the audit row and the `config_version` bump in one transaction. The upstream router reads the
    snapshot, so a change applies to every worker within a second.

What to read next
    `roxy/rules/models.py` (`CredentialAllowlistIn`), `roxy/upstream/routing.py` (step 1 of plan 7.2),
    `roxy/cache/service.py` (what `cache_private` does), `roxy/admin/api/credential.py`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Query, Request
from pydantic import Field, StrictBool

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminFreshMfa,
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
    MAX_TARGET_CHARS,
    DeleteBody,
    Note,
    Pattern,
    Reason,
    all_rows,
    change_answer,
    changes_of,
    normalize_target,
    rule_flag,
    rules_service,
)
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.deps import get_ctx
from roxy.insights.read_evidence import cred_unused_evidence
from roxy.rules.match import regex_budget

router = common.area_router("credential-allowlist")

TABLE: Final = "credential_allowlist"
MAX_RECOMMENDATION_ID: Final = 80

D1_NOTICE: Final = (
    "Owner decision D1: callers never get the credential. Every row here is an exception that sends the owner's "
    "one Roblox account for every caller request that matches it, from the server IP only (never the rotator)."
)
CACHE_PRIVATE_HELP: Final = (
    "cache_private true: the account's answers are never stored, shared with another request, refreshed in the "
    "background or served stale; every matching request makes its own credential call. cache_private false: an "
    "answer is cached as a credential entry and served only to requests that would also use the credential."
)
EXACT_HELP: Final = (
    "A row grants exactly the path it names: a glob has no implicit subpaths and * stays inside one segment; a "
    "regex must match the whole path. Add an explicit wildcard (for example .../currency/*) to grant paths below."
)
EVIDENCE_REQUIRED: Final = (
    "identical_anonymous is set only from CRED-UNUSED evidence: name an open CRED-UNUSED recommendation about this "
    "row in recommendation_id."
)

SPEC: Final = TableSpec(
    name="credential_allowlist",
    columns=(
        Column("id", "Id", "The row's number."),
        Column("pattern", "Pattern", "host/path it grants, exactly (see the help on exact grants)."),
        Column("type", "Type", "glob or regex."),
        Column("methods", "Methods", "GET, HEAD or both; never anything else.", sortable=False),
        Column("cache_private", "Private", "Whether the account's answers are kept out of the shared cache."),
        Column(
            "identical_anonymous",
            "Anonymous allowed",
            "Set only from CRED-UNUSED evidence: the endpoint answers the same without the account.",
        ),
        Column("enabled", "Enabled", "Whether the row is in force."),
        Column("note", "Note", "The admin's note.", sortable=False),
        Column("created_at", "Created", "When the row was added (Unix seconds).", "s"),
        Column("created_by", "Created by", "Who added it."),
        Column("updated_at", "Updated", "When it last changed (Unix seconds).", "s"),
    ),
    default_sort="id",
    default_order="asc",
)

Method = Literal["GET", "HEAD"]
Methods = Annotated[list[Method], Field(min_length=1, max_length=2)]
RecommendationId = Annotated[str, Field(min_length=1, max_length=MAX_RECOMMENDATION_ID)]


def _default_methods() -> list[Method]:
    return ["GET"]


class AllowlistBody(ApiBody):
    """`POST /credential-allowlist`. `cache_private` has no default on purpose (plan 9.13)."""

    pattern: Pattern
    type: Literal["glob", "regex"] = "glob"
    methods: Methods = Field(default_factory=_default_methods)
    cache_private: StrictBool
    identical_anonymous: StrictBool = False
    note: Note = ""
    enabled: StrictBool = True
    reason: Reason


class AllowlistPatch(ApiBody):
    """`PATCH /credential-allowlist/{id}`: only the fields given change; `reason` is required."""

    pattern: Pattern | None = None
    type: Literal["glob", "regex"] | None = None
    methods: Methods | None = None
    cache_private: StrictBool | None = None
    identical_anonymous: StrictBool | None = None
    note: Note | None = None
    enabled: StrictBool | None = None
    recommendation_id: RecommendationId | None = None
    reason: Reason


def item_of(row: Mapping[str, Any]) -> dict[str, Any]:
    """One allowlist row as the API shows it (methods as a list, flags as booleans)."""
    methods = row.get("methods")
    if isinstance(methods, str):
        listed = [part for part in methods.split(",") if part]
    else:
        listed = [str(part) for part in (methods or ())]
    return {
        "id": row.get("id"),
        "pattern": row.get("pattern"),
        "type": row.get("type"),
        "methods": listed,
        "cache_private": rule_flag(row.get("cache_private")),
        "identical_anonymous": rule_flag(row.get("identical_anonymous")),
        "enabled": rule_flag(row.get("enabled")),
        "note": row.get("note") or "",
        "created_at": row.get("created_at"),
        "created_by": row.get("created_by"),
        "updated_at": row.get("updated_at"),
        "updated_by": row.get("updated_by"),
    }


def _help() -> dict[str, str]:
    return {"d1": D1_NOTICE, "cache_private": CACHE_PRIVATE_HELP, "exact": EXACT_HELP}


@router.get("")
async def list_rows(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Every allowlist row (at most 50, plan 15.4), with the D1 notice and the meaning of each choice."""
    with common.service_errors():
        rows = [item_of(row) for row in await rules_service(request).list_rows(TABLE)]
    keys = ("pattern", "note", "created_by")
    if fmt is not None:
        items, total = all_rows(rows, tq, search_keys=keys)
        return await common.export_table(request, admin, SPEC, items, fmt, total=total, tq=tq)
    items, total = common.page_rows(rows, tq, search_keys=keys)
    return common.table_answer(SPEC, tq, items, total) | {"help": _help()}


@router.post("", status_code=201)
async def create_row(request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, body: AllowlistBody) -> Any:
    """Add an allowlist row (fresh second factor and a reason required; audited)."""
    reason = common.require_reason(body.reason, required=True)
    if body.identical_anonymous:
        raise common.validation_error(
            {"identical_anonymous": EVIDENCE_REQUIRED}, EVIDENCE_REQUIRED, code="evidence_required"
        )
    row = body.model_dump(exclude={"reason"})
    change = await common.run_mutation(
        rules_service(request).create(
            TABLE, row, common.actor_for(admin), reason, request_id=common.request_id_of(request)
        )
    )
    return change_answer(change, item_of) | {"help": _help()}


@router.get("/test")
async def check_target(
    request: Request,
    _admin: AdminSession,
    target: Annotated[str, Query(min_length=1, max_length=MAX_TARGET_CHARS)],
    method: Annotated[str, Query(max_length=8)] = "GET",
) -> dict[str, Any]:
    """Whether `method` on `target` (host/path) may use the credential now, and under which row (exact grants)."""
    clean = normalize_target(target)
    verb = method.strip().upper()
    snapshot = get_ctx(request).rules.snapshot
    with regex_budget(fresh=True):  # the admin's own budget (plan 9.9); a cut-off match never grants (C1)
        row = snapshot.credential_rule_for(clean, verb) if verb in ("GET", "HEAD") else None
    item = item_of(row.model_dump()) if row is not None else None
    return {
        "target": clean,
        "method": verb,
        "granted": item is not None,
        "rule": item,
        "cache_private": item["cache_private"] if item else None,
        "note": None if verb in ("GET", "HEAD") else "The credential is used for GET and HEAD only.",
    }


@router.get("/{row_id}")
async def get_row(request: Request, _admin: AdminSession, row_id: common.RowId) -> dict[str, Any]:
    """One allowlist row."""
    with common.service_errors():
        row = await rules_service(request).get_row(TABLE, row_id)
    if row is None:
        raise common.not_found("No allowlist row has that id.")
    return item_of(row)


@router.patch("/{row_id}")
async def update_row(
    request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, row_id: common.RowId, body: AllowlistPatch
) -> dict[str, Any]:
    """Change an allowlist row (fresh second factor and a reason required; audited).

    `identical_anonymous: true` needs `recommendation_id` naming an open CRED-UNUSED recommendation about this
    row; its evidence numbers are added to the audit reason. Clearing the flag needs no evidence.
    """
    reason = common.require_reason(body.reason, required=True)
    changes = changes_of(body, exclude=frozenset({"reason", "recommendation_id"}))
    service = rules_service(request)
    if changes.get("identical_anonymous") is True:
        if not body.recommendation_id:
            raise common.validation_error(
                {"recommendation_id": EVIDENCE_REQUIRED}, EVIDENCE_REQUIRED, code="evidence_required"
            )
        with common.service_errors():
            current = await service.get_row(TABLE, row_id)
        if current is None:
            raise common.not_found("No allowlist row has that id.")
        recommendation_id = body.recommendation_id
        pattern = str(current.get("pattern") or "")
        ctx = get_ctx(request)
        with common.service_errors():
            evidence = await ctx.dbs.metrics.read(
                lambda conn: cred_unused_evidence(
                    conn, recommendation_id=recommendation_id, row_id=row_id, pattern=pattern
                )
            )
        if evidence is None:
            raise common.validation_error(
                {"recommendation_id": "No open CRED-UNUSED recommendation about this row has that id."},
                EVIDENCE_REQUIRED,
                code="evidence_required",
            )
        note = f" [CRED-UNUSED evidence {evidence['recommendation_id']}, {evidence['sample_size']} samples]"
        reason = reason[: MAX_REASON_LENGTH - len(note)] + note
    elif body.recommendation_id is not None:
        raise common.validation_error(
            {"recommendation_id": "Only setting identical_anonymous to true takes a recommendation id."}
        )
    change = await common.run_mutation(
        service.update(
            TABLE, row_id, changes, common.actor_for(admin), reason, request_id=common.request_id_of(request)
        )
    )
    return change_answer(change, item_of)


@router.delete("/{row_id}")
async def delete_row(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, row_id: common.RowId, body: DeleteBody | None = None
) -> dict[str, Any]:
    """Remove an allowlist row: the endpoint is never fetched with the credential again (audited)."""
    reason = body.reason if body is not None else ""
    change = await common.run_mutation(
        rules_service(request).delete(
            TABLE, row_id, common.actor_for(admin), reason, request_id=common.request_id_of(request)
        )
    )
    before = change.before if isinstance(change.before, Mapping) else None
    return {
        "deleted": item_of(before) if before is not None else None,
        "audit_id": change.audit_id,
        "config_version": change.config_version,
    }


__all__ = ["CACHE_PRIVATE_HELP", "D1_NOTICE", "EVIDENCE_REQUIRED", "EXACT_HELP", "SPEC", "router"]
