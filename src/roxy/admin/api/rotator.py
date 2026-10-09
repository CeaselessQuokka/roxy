"""Rotator URL API (`/admin/api/v1/rotator`): show the gateway masked, replace it, revert to the bootstrap value.

What this is
    * `GET /rotator`: whether a gateway URL is loaded, where it came from (`ui`, `bootstrap`, `test_override` or
      none), its masked form (`scheme://host:port`, parity row 33), when and by whom a UI value was set.
    * `PUT /rotator/url` with `{url, reason}`: store a new DataImpulse gateway URL (it embeds a user name and a
      password). Fresh second factor and CSRF required (plan 9.6); audited with `{fingerprint, masked}` only.
    * `DELETE /rotator/url`: delete the UI value, so the bootstrap systemd credential `rotator_url` is used again.

Why it exists
    Parity row 30 and plan 8.2: v1 read the URL from an environment variable or a file; v2 reads the bootstrap value
    from a systemd credential at start, and the admin can replace it from the Egress page without a shell. The URL
    is a secret: it never appears in an answer, a log line or an audit row, and it is registered as a secret (so
    every log line and audit reason is scrubbed of it) BEFORE the audit row is written (`RotatorPool.replace_url`
    registers it, then writes the store row and the audit row in one control.db transaction).

How it works
    `egress/rotator.py RotatorPool` does the work (validation, AES-GCM encryption, the version bump every worker
    follows within a second). A URL that does not parse is 422 `invalid_url` with a message that never quotes it;
    no encryption key is 409 `wrong_state`; nothing to revert is 409 `wrong_state`. Changing the bootstrap file
    itself needs a service restart (`systemctl restart roxy@<color>`), which the answer says.

What to read next
    `roxy/egress/rotator.py` (`replace_url`, `revert_to_bootstrap`), `roxy/config/audit.py` (`secret_summary`),
    `roxy/admin/api/egress.py` (the rest of the Egress page).
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Request
from pydantic import Field

from roxy.admin.api import common
from roxy.admin.api.common import AdminFreshMfa, AdminSession, ApiBody, CsrfChecked
from roxy.admin.api.routing_rules import DeleteBody, Reason
from roxy.deps import get_ctx
from roxy.egress import read_state
from roxy.egress.rotator import MAX_URL_LENGTH, RotatorUrlError

router = common.area_router("rotator")

RESTART_NOTE: Final = (
    "The bootstrap value comes from the systemd credential rotator_url, read when the service starts; after "
    "editing that file run systemctl restart roxy@<color>."
)


class UrlBody(ApiBody):
    """`PUT /rotator/url`: the new gateway URL (never echoed) and why."""

    url: Annotated[str, Field(min_length=1, max_length=MAX_URL_LENGTH)]
    reason: Reason = ""


def _pool(request: Request) -> Any:
    egress = get_ctx(request).egress
    if egress is None:
        raise common.unavailable("The egress layer is not running yet; try again shortly.")
    return egress.rotator


async def describe(request: Request) -> dict[str, Any]:
    """The rotator URL state the page shows: masked URL, source, UI value metadata (never the URL itself)."""
    ctx = get_ctx(request)
    pool = _pool(request)
    with common.service_errors():
        stored = await ctx.dbs.control.read(read_state.rotator_store_meta)
    source = pool.url_source()
    return {
        "configured": bool(pool.configured()),
        "url": pool.masked_url(),
        "source": source,
        "ui_value": stored,
        "can_revert": stored is not None,
        "mode": pool.effective_mode(),
        "restart_note": RESTART_NOTE,
    }


@router.get("")
async def rotator_state(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Whether a gateway URL is loaded, from where, masked (`scheme://host:port`)."""
    return await describe(request)


@router.put("/url")
async def replace_url(request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, body: UrlBody) -> dict[str, Any]:
    """Store a new gateway URL (fresh second factor; audited as `{fingerprint, masked}`; registered as a secret
    before its audit row is written)."""
    pool = _pool(request)
    reason = common.require_reason(body.reason, required=False)
    try:
        await common.run_mutation(
            pool.replace_url(
                body.url, common.actor_for(admin), reason=reason or None, request_id=common.request_id_of(request)
            )
        )
    except RotatorUrlError as exc:  # `parse_proxy_url`: its messages describe the shape, never the value
        raise common.validation_error({"url": str(exc)}, "The rotator URL is not valid.", code="invalid_url") from None
    return await describe(request) | {"replaced": True}


@router.delete("/url")
async def revert_url(
    request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, body: DeleteBody | None = None
) -> dict[str, Any]:
    """Delete the UI value: the bootstrap credential `rotator_url` is used again (fresh second factor; audited)."""
    pool = _pool(request)
    reason = body.reason if body is not None else ""
    await common.run_mutation(
        pool.revert_to_bootstrap(
            common.actor_for(admin), reason=reason or None, request_id=common.request_id_of(request)
        )
    )
    return await describe(request) | {"reverted": True}


__all__ = ["RESTART_NOTE", "router"]
