"""Credential API (`/admin/api/v1/credential`): the one Roblox account Roxy holds (plan C1, C2, D1, 13.3).

What this is
    The routes behind the Credential page (plan 14.1):
      * `GET /credential`: status (active, unknown, cooling down, rejected, absent), the masked suffix (an ellipsis
        and the last 6 characters, parity row 27), fingerprints, the account fingerprint match, the cooldown, where
        the value came from, and the texts the page shows before a replace or an account switch.
      * `GET /credential/probes`: the last probes (Roxy's own calls with the credential) and the last result.
      * `GET /credential/budget`: the credential bucket and the reserved probe sub-bucket now, and how many
        credential calls were made in the last hour and day (plan 13.3: about 50 to 60 a day with an empty
        allowlist).
      * `POST /credential/check`: probe now ("Check credential"). Fresh second factor (it spends a call on the
        account). One probe at a time fleet-wide; paced by the reserved probe bucket; a 429 means "rate limited",
        never "expired" (parity row 25).
      * `POST /credential/replace` with `{value, confirm, reason}`: the C1 replace. Fresh second factor; `confirm`
        must be `REPLACE_CONFIRMATION` exactly (the page shows `C1_WARNING` first). The old value stops being used
        everywhere at once; the value is never echoed. A probe follows to record the new account's fingerprint.
      * `DELETE /credential/ui-value`: go back to the bootstrap file (the only way, plan C1). Fresh second factor.
        The bootstrap value is probed at once and its account fingerprint compared with the previous one; if they
        differ the credential is not used (status rejected) until `POST /credential/confirm-account` with
        `confirm` = `ACCOUNT_SWITCH_CONFIRMATION`, because a different account is an account switch.
      * `POST /credential/confirm-account`: accept the account the last probe saw (the typed C1 confirmation).

Why it exists
    Plan C1: exactly one credential, replaced only by a deliberate, audited action whose confirmation explains the
    risk; never "the next token". The value never leaves `egress/credential.py` (C2 item 1): this module passes the
    pasted text straight to `CredentialManager.replace`, which registers it as a secret BEFORE its audit row is
    written, so neither an answer, a log line nor an audit row (the reason included) can carry it or any 24
    character piece of it.

How it works
    Every route depends on the session guard; the writes also on CSRF; check, replace, delete and confirm on a
    fresh second factor (403 `reauth_required` otherwise). The credential manager writes the encrypted store row, the
    metadata, the audit row and the `credential_version` bump in one control.db transaction, and every worker
    follows within a second. A refused value is 422 `invalid_credential` (the manager's messages never quote the
    value); a missing encryption key or nothing to delete is 409 `wrong_state`. Probe calls are bounded by the
    request deadline: a probe still waiting for its bucket slot when the deadline nears answers `pending`.

What to read next
    `roxy/egress/credential.py` (`CredentialManager`), `roxy/upstream/service.py` (`credential_probe_fetch`),
    `roxy/admin/api/credential_allowlist.py` (what the credential may be used for).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from typing import Annotated, Any, Final

from fastapi import Request
from pydantic import Field

from roxy.admin.api import common
from roxy.admin.api.common import AdminFreshMfa, AdminSession, ApiBody, CsrfChecked
from roxy.admin.api.routing_rules import DeleteBody, Reason
from roxy.core.reasons import Egress
from roxy.deps import get_ctx
from roxy.egress.credential import MAX_VALUE_LENGTH, ProbeResult
from roxy.metrics import queries, read_upstream
from roxy.metrics.queries import Window
from roxy.upstream import cooldowns
from roxy.upstream.buckets import CREDENTIAL_PROBE_KEY, BucketDefaults

log = logging.getLogger("roxy.admin.api.credential")

router = common.area_router("credential")

PROBE_PURPOSES: Final = ("credential_probe", "credential_check", "credential_confirm")
MAX_PROBES: Final = 50
PROBE_TIMEOUT_S: Final = 40.0
"""Longest an admin request waits for a probe answer; a probe that is still queued for its bucket slot finishes on
its own and the page reads the result later (`pending`)."""

EXPECTED_DAILY_CALLS: Final = "about 50 to 60 credential calls a day with an empty allowlist (plan 13.3)"

C1_WARNING: Final = (
    "Roxy uses exactly one Roblox account. Replacing the credential switches every credential call to the new "
    "cookie at once, and the old value is never used again. Roblox ties rate limits and abuse scoring to the "
    "account and the server IP together, so moving between accounts looks like account farming and can get the "
    "accounts and the server IP throttled or banned. Replace it only to renew the same account's cookie, or when "
    "you deliberately move Roxy to another account. After replacing it, remove the old cookie from the bootstrap "
    "file /etc/roxy/credentials/roblox_credential."
)
REPLACE_CONFIRMATION: Final = "replace the credential"
ACCOUNT_SWITCH_WARNING: Final = (
    "The cookie in the bootstrap file belongs to a different Roblox account than the one Roxy used before. Using "
    "it is an account switch (plan C1): Roblox may see many accounts behind one server IP. Roxy does not use it "
    "until you confirm."
)
ACCOUNT_SWITCH_CONFIRMATION: Final = "switch to the other account"


class ReplaceBody(ApiBody):
    """`POST /credential/replace`: the new value (never echoed), the typed confirmation, and why."""

    value: Annotated[str, Field(min_length=1, max_length=MAX_VALUE_LENGTH + 64)]
    confirm: Annotated[str, Field(max_length=200)]
    reason: Reason = ""


class ConfirmBody(ApiBody):
    """`POST /credential/confirm-account`: the typed account switch confirmation, and why."""

    confirm: Annotated[str, Field(max_length=200)]
    reason: Reason = ""


def _manager(request: Request) -> Any:
    egress = get_ctx(request).egress
    if egress is None:
        raise common.unavailable("The egress layer is not running yet; try again shortly.")
    return egress.credential


def _probe_fetch(request: Request, kind: str) -> Any:
    upstream = get_ctx(request).upstream
    if upstream is None:
        raise common.unavailable("The upstream service is not running yet; try again shortly.")
    return upstream.probe_fetch_for(kind)  # recorded with its trigger (`admin`), for CRED-PROBE-COST


def _confirmed(text: str, expected: str) -> bool:
    return " ".join(text.split()).lower() == expected


def _account(status: Any) -> dict[str, Any]:
    """The account fingerprint the credential was set with, and the one the last probe saw when they differ."""
    result = status.last_probe_result or {}
    pending = result.get("pending_account") if isinstance(result, dict) else None
    recorded = status.account_id_fingerprint
    if result.get("result") == "account_mismatch" and isinstance(pending, str):
        match: bool | None = False
    elif recorded is not None and isinstance(result, dict) and result.get("result") in ("ok", "account_confirmed"):
        match = True
    else:
        match = None
    return {
        "recorded": recorded,
        "last_probe": pending if match is False else (recorded if match else None),
        "match": match,
        "confirmation_required": match is False,
    }


def status_view(manager: Any) -> dict[str, Any]:
    """Everything the page may show about the credential (never the value: `CredentialStatus` has none)."""
    status = manager.status()
    view = asdict(status)
    view["account"] = _account(status)
    return view


def _probe_view(result: ProbeResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {**asdict(result), "ok": result.ok}


_PENDING: set[asyncio.Task[Any]] = set()
"""Probes still running after their admin request stopped waiting (a strong reference, so they finish; at most a
few, because only one probe runs at a time in the whole fleet and the others answer `busy` at once)."""


async def _run_probe(request: Request, kind: str) -> ProbeResult | None:
    """One probe through the reserved probe bucket, bounded by `PROBE_TIMEOUT_S` (None: still running)."""
    manager = _manager(request)
    fetch = _probe_fetch(request, kind)
    task: asyncio.Task[Any] = asyncio.ensure_future(manager.probe(kind, fetch=fetch))
    _PENDING.add(task)
    task.add_done_callback(_PENDING.discard)
    try:
        with common.service_errors():
            result: ProbeResult = await asyncio.wait_for(asyncio.shield(task), timeout=PROBE_TIMEOUT_S)
            return result
    except TimeoutError:
        log.info("credential_probe_pending", extra={"fields": {"kind": kind}})
        return None


def texts() -> dict[str, str]:
    """What the page shows before a replace and before an account switch."""
    return {
        "c1_warning": C1_WARNING,
        "replace_confirmation": REPLACE_CONFIRMATION,
        "account_switch_warning": ACCOUNT_SWITCH_WARNING,
        "account_switch_confirmation": ACCOUNT_SWITCH_CONFIRMATION,
    }


# --------------------------------------------------------------------------------------------------- reads


@router.get("")
async def credential_status(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The credential's status, masked suffix, fingerprints, account match, cooldown and source."""
    ctx = get_ctx(request)
    manager = _manager(request)
    now_ms = int(ctx.clock.now_ms())
    with common.service_errors():
        rows = await ctx.dbs.hot.read(lambda conn: cooldowns.read_rows(conn, (cooldowns.CREDENTIAL_KEY,)))
    row = rows.get(cooldowns.CREDENTIAL_KEY)
    cooldown = None
    if row is not None and row.active(now_ms):
        cooldown = {
            "source": row.source,
            "ends_at_ms": row.until_ms,
            "remaining_s": round(row.remaining_s(now_ms), 1),
            "hits": row.hits,
        }
    return {
        **status_view(manager),
        "cooldown": cooldown,
        "now_ms": now_ms,
        "probe_interval_min": ctx.settings.get("credential_probe_interval_min"),
        "probe_url": ctx.settings.get("credential_probe_url"),
        "texts": texts(),
        "d1": "Owner decision D1: callers never get the credential; only Roxy's own probes use it by default.",
        "settings_card": "credential#status",
    }


@router.get("/probes")
async def probes(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The last probes (newest first, at most 50) and the last result the credential manager recorded."""
    ctx = get_ctx(request)
    manager = _manager(request)
    now_ms = int(ctx.clock.now_ms())
    keep_ms = 90 * 86_400 * 1000
    rows = await ctx.dbs.metrics.read(
        lambda conn: read_upstream.recent_events(
            conn, ("internal_call",), now_ms - keep_ms, now_ms + 1, reasons=PROBE_PURPOSES, limit=MAX_PROBES
        )
    )
    items = [
        {
            "at_ms": row["at_ms"],
            "purpose": row["reason_code"],
            "ok": bool(row["detail"].get("ok")),
            "status": row["detail"].get("status"),
            "duration_ms": row["detail"].get("duration_ms"),
            "error": row["detail"].get("error"),
            "trigger": row["detail"].get("trigger"),
            "count": row["count"],
        }
        for row in rows
    ]
    status = manager.status()
    return {"items": items, "last_probe_at": status.last_probe_at, "last_probe_result": status.last_probe_result}


@router.get("/budget")
async def budget(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The credential bucket and the reserved probe bucket now, and the credential calls of the last hour and day."""
    ctx = get_ctx(request)
    upstream = ctx.upstream
    defaults = BucketDefaults.from_settings(ctx.settings)
    states: dict[str, Any] = {}
    if upstream is not None:
        with common.service_errors():
            states = {state.key: state for state in await upstream.bucket_snapshot(500)}
    now = ctx.clock.now()
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    hour = Window(int(now) - int(now) % 60 - 3540, int(now) - int(now) % 60 + 60, "minute", tz)
    day = Window(int(now) - int(now) % 3600 - 82_800, int(now) - int(now) % 3600 + 3600, "hour", tz)
    filters = {"egress": Egress.CREDENTIAL.value}

    def read(conn: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        return (
            queries.totals_sync(conn, hour, filters=filters),
            queries.totals_sync(conn, day, filters=filters),
            queries.series_sync(conn, day, metrics=["internal_calls", "upstream_calls"], filters=filters),
        )

    last_hour, last_day, hourly = await ctx.dbs.metrics.read(read)
    per_hour = hourly["groups"].get("all", {}).get("internal_calls", [])

    def bucket(key: str, pair: Any) -> dict[str, Any]:
        state = states.get(key)
        return {
            "key": key,
            "per_min": pair.per_min,
            "burst": pair.burst,
            "fill_pct": round(state.fill * 100.0, 1) if state is not None else 0.0,
            "next_free_in_ms": round(state.next_free_in_ms, 1) if state is not None else 0.0,
        }

    return {
        "account_bucket": bucket(f"egress:{Egress.CREDENTIAL.value}", defaults.credential),
        "probe_bucket": bucket(CREDENTIAL_PROBE_KEY, defaults.credential_probe),
        "settings": {
            "credential_bucket_per_min": ctx.settings.get("credential_bucket_per_min"),
            "credential_bucket_burst": ctx.settings.get("credential_bucket_burst"),
            "credential_probe_reserved_per_min": ctx.settings.get("credential_probe_reserved_per_min"),
            "credential_probe_interval_min": ctx.settings.get("credential_probe_interval_min"),
        },
        "last_hour": {
            "caller_calls": int(last_hour["upstream_calls"]),
            "probe_calls": int(last_hour["internal_calls"]),
        },
        "last_24h": {
            "caller_calls": int(last_day["upstream_calls"]),
            "probe_calls": int(last_day["internal_calls"]),
            "busiest_hour_probe_calls": max((int(v or 0) for v in per_hour), default=0),
        },
        "expected": EXPECTED_DAILY_CALLS,
        "settings_card": "credential#budget",
    }


# -------------------------------------------------------------------------------------------------- actions


@router.post("/check")
async def check_now(request: Request, _admin: AdminFreshMfa, _csrf: CsrfChecked) -> dict[str, Any]:
    """Probe the credential now (one probe at a time fleet-wide; `busy` when another is running).

    A fresh second factor is required because every probe spends a call on the owner's account, as for a health
    run that includes the credential check (`admin/api/health.py`): a stolen session cannot make Roblox see a
    stream of authenticated calls.
    """
    result = await _run_probe(request, "admin_check")
    return {"probe": _probe_view(result), "pending": result is None, "status": status_view(_manager(request))}


@router.post("/replace")
async def replace(request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, body: ReplaceBody) -> dict[str, Any]:
    """Replace the credential (plan C1): typed confirmation, fresh second factor, audited, value never echoed."""
    if not _confirmed(body.confirm, REPLACE_CONFIRMATION):
        raise common.validation_error(
            {"confirm": f"Type: {REPLACE_CONFIRMATION}"}, C1_WARNING, code="confirmation_required"
        )
    reason = common.require_reason(body.reason, required=False)
    manager = _manager(request)
    await common.run_mutation(
        manager.replace(
            body.value, common.actor_for(admin), reason=reason or None, request_id=common.request_id_of(request)
        )
    )
    result = await _run_probe(request, "admin_check")
    return {"replaced": True, "probe": _probe_view(result), "pending": result is None, "status": status_view(manager)}


@router.delete("/ui-value")
async def delete_ui_value(
    request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, body: DeleteBody | None = None
) -> dict[str, Any]:
    """Delete the UI value and go back to the bootstrap file; the bootstrap value is probed and its account compared
    with the previous one. A different account is not used until `confirm-account` (plan C1)."""
    manager = _manager(request)
    reason = body.reason if body is not None else ""
    previous = manager.status().account_id_fingerprint
    await common.run_mutation(
        manager.delete_ui_value(
            common.actor_for(admin), reason=reason or None, request_id=common.request_id_of(request)
        )
    )
    result = await _run_probe(request, "admin_check")
    view = status_view(manager)
    account = view["account"]
    return {
        "deleted": True,
        "probe": _probe_view(result),
        "pending": result is None,
        "status": view,
        "account": {
            "previous": previous,
            "probed": account["last_probe"],
            "match": account["match"],
            "confirmation_required": account["confirmation_required"],
        },
        "texts": texts(),
    }


@router.post("/confirm-account")
async def confirm_account(
    request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, body: ConfirmBody
) -> dict[str, Any]:
    """Accept the account the last probe saw after an account mismatch (the typed C1 confirmation; audited)."""
    if not _confirmed(body.confirm, ACCOUNT_SWITCH_CONFIRMATION):
        raise common.validation_error(
            {"confirm": f"Type: {ACCOUNT_SWITCH_CONFIRMATION}"}, ACCOUNT_SWITCH_WARNING, code="confirmation_required"
        )
    reason = common.require_reason(body.reason, required=False)
    manager = _manager(request)
    await common.run_mutation(
        manager.confirm_account(
            common.actor_for(admin), reason=reason or None, request_id=common.request_id_of(request)
        )
    )
    return {"confirmed": True, "status": status_view(manager)}


__all__ = [
    "ACCOUNT_SWITCH_CONFIRMATION",
    "ACCOUNT_SWITCH_WARNING",
    "C1_WARNING",
    "REPLACE_CONFIRMATION",
    "router",
    "status_view",
]
