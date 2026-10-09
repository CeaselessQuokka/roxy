"""LLM export API (`/admin/api/v1/export/llm`): the plan 12 document for an LLM, and its JSON Schema.

What this is
    `GET /export/llm?window=24h|7d|30d&detail=summary|full` answers the export built by
    `roxy/insights/llm_export.py` (`format=json`, the default, or `format=text`: the plan 12.5 instruction block, a
    blank line, then the JSON, which is what "Copy for LLM" puts on the clipboard; `download=true` adds a file name
    for "Download JSON"). `GET /export/llm/schema` answers the JSON Schema ("Open schema", plan 12.2).

Why it exists
    Plan 12.2: an admin session reads the summary; the full detail (every setting and rule row, evidence details,
    tracebacks, raw client addresses when `export_include_ips` is 1) needs a fresh second factor, like the other
    full data exports (DESIGN.md section 13). The file leaves Roxy, so every download is audited first
    (`export.download`, plan 9.7): if the audit row cannot be written there is no file (503).

How it works
    The route checks the guard (`require_admin("session")`, and `require_admin("fresh_mfa")` itself for `full`),
    picks the IP policy with `common.export_ip_policy` (the summary never shows raw addresses), builds the export,
    writes the audit row (window, detail, format, bytes, IP mode, untrusted entry count) and answers the bytes with
    `Cache-Control: no-store` (the route class). A worker builds at most `MAX_CONCURRENT_BUILDS` exports at once;
    another request gets 429 with `Retry-After`. A database that cannot be read is a 503 (plan C7).

What to read next
    `roxy/insights/llm_export.py` (what the document holds and why strings move to `untrusted`),
    `roxy/admin/api/common.py` (guards, errors, the IP policy), `roxy/admin/api/export.py` (table exports).
"""

from __future__ import annotations

import secrets
from typing import Annotated, Any, Final, Literal

from fastapi import APIRouter, Query, Request
from starlette.responses import Response

from roxy.admin.api import common
from roxy.admin.api.common import AdminSession
from roxy.config import audit
from roxy.deps import get_ctx
from roxy.insights import llm_export

router = APIRouter(prefix="/export/llm", tags=["export_llm"], route_class=common.AdminApiRoute)
"""Built directly (not with `common.area_router`) because the plan's path `/export/llm` holds a slash."""

TEXT_TYPE: Final = "text/plain; charset=utf-8"
BUSY_RETRY_S: Final = 5
AUDIT_TARGET: Final = "llm_export"

Window = Literal["24h", "7d", "30d"]
Detail = Literal["summary", "full"]
Format = Literal["json", "text"]


class _NoRawAddresses:
    """`ctx` as `export_ip_policy` sees it, with `export_include_ips` read as 0 (the summary never shows them)."""

    def __init__(self, ctx: Any) -> None:
        self.ip_hash_key = getattr(ctx, "ip_hash_key", None)
        self.settings = _SettingsWithoutRawIps(ctx.settings)


class _SettingsWithoutRawIps:
    def __init__(self, settings: Any) -> None:
        self._settings = settings

    def bool(self, key: str) -> bool:
        return False if key == "export_include_ips" else bool(self._settings.bool(key))


def _filename(at_s: float, detail: str, fmt: str) -> str:
    return f"roxy_llm_export_{detail}_{int(at_s * 1000)}.{'txt' if fmt == 'text' else 'json'}"


@router.get("", response_model=None)
async def export_llm(
    request: Request,
    admin: AdminSession,
    window: Annotated[Window, Query(description="The time window: 24h, 7d or 30d.")] = "24h",
    detail: Annotated[Detail, Query(description="summary, or full (needs a fresh second factor).")] = "summary",
    fmt: Annotated[Format, Query(alias="format", description="json, or text with the instruction block.")] = "json",
    download: Annotated[bool, Query(description="Answer as a file download.")] = False,
) -> Response:
    """The plan 12.3 document (see the module docstring)."""
    if detail == "full":
        # Plan 12.2: re-authentication is needed for the full detail (403 `reauth_required` when it is stale).
        admin = await common.admin_fresh_mfa(request)
    ctx = get_ctx(request)
    export_id = common.request_id_of(request) or secrets.token_hex(8)
    policy_ctx: Any = ctx if detail == "full" else _NoRawAddresses(ctx)
    hasher, ip_mode = common.export_ip_policy(policy_ctx, export_id)
    try:
        with common.service_errors():
            result = await llm_export.build_export(
                llm_export.ExportSources.from_context(ctx),
                window=window,
                detail=detail,
                ip_hasher=hasher,
                ip_mode=ip_mode,
                generated_by="api",
            )
    except llm_export.ExportBusy:
        raise common.rate_limited(
            "Another LLM export is being built in this worker; try again in a few seconds.", BUSY_RETRY_S
        ) from None
    if fmt == "text":
        content = llm_export.copy_text(result.content).encode("utf-8")
        media_type = TEXT_TYPE
    else:
        content = result.content
        media_type = "application/json"
    at = ctx.clock.now()
    filename = _filename(at, detail, fmt)
    details = {
        "window": window,
        "detail": detail,
        "format": fmt,
        "bytes": len(content),
        "ip_addresses": ip_mode,
        "untrusted": result.untrusted,
        "filename": filename if download else None,
    }
    actor = common.actor_for(admin)
    request_id = common.request_id_of(request)

    def write(conn: Any) -> int:
        target = f"{AUDIT_TARGET}:{detail}"
        return audit.record(
            conn, actor, common.EXPORT_AUDIT_ACTION, target, None, details, None, request_id, at=int(at)
        )

    with common.service_errors():
        await ctx.dbs.control.write(write)  # the audit row is written before the file leaves (plan 9.7)
    response = Response(content=content, media_type=media_type)
    if download:
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Roxy-Export-Untrusted"] = str(result.untrusted)
    return response


@router.get("/schema", response_model=None)
async def export_llm_schema(_admin: AdminSession) -> Response:
    """The JSON Schema (draft 2020-12) every export validates against (plan 12.4), as committed."""
    return Response(content=llm_export.schema_bytes(), media_type="application/json")


__all__ = ["router"]
