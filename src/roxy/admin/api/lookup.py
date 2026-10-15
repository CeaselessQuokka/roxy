"""Lookup API (`/admin/api/v1/lookup`): "Identify an experience" from a place or universe id (parity rows 38, 92).

What this is
    `POST /lookup/place` with `{id, kind}` (kind `place` or `universe`) resolves a place to its universe and loads
    the experience's name, creator, visits and links, in v1's result keys (`Name`, `CreatorName`, `Url`, ...),
    plus `cached` (answered from the 10 minute cache) and `notes` (v1's warning about a throwaway place).

Why it exists
    The Clients page shows `Roblox-Id` values (places) callers send; the admin needs to see which experience and
    owner are behind one before blocking or allowing it (v1 "Identify"). v1's lookup spent the token budget and
    fell back to an unbudgeted direct call (bug B25); v2's goes through `UpstreamService.internal_fetch` at admin
    priority (paced by the buckets, honoring cooldowns, never the credential), recorded as an internal call.

How it works
    `upstream/internal.py PlaceLookup` does the work; one instance per worker (kept per `UpstreamService`, so its
    256-entry, 10 minute cache is shared by every admin request of the worker). It is a POST with the CSRF header
    because every lookup spends upstream budget. Its answers map to section 13 errors: an id that is not a number
    is 422, an unknown place or experience 404, and Roblox failing or Roxy unable to pace the call 502 with v1's
    message (Roblox's text is scrubbed and bounded first).

What to read next
    `roxy/upstream/internal.py` (`PlaceLookup`), `roxy/admin/api/upstream.py` (the internal calls table).
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any, Final, Literal

from fastapi import Request
from pydantic import Field

from roxy.admin.api import common
from roxy.admin.api.common import AdminSession, ApiBody, CsrfChecked
from roxy.deps import get_ctx
from roxy.upstream.internal import MAX_ID_LENGTH, PlaceLookup, place_lookup_for

router = common.area_router("lookup")

NEW_PLACE_DAYS: Final = 7
FEW_VISITS: Final = 1000
THROWAWAY_NOTE: Final = (
    "Recently created with very few visits; consistent with a throwaway place made to point traffic at this proxy "
    "rather than a real game using it."
)
"""v1's warning (dashboard.js J2887-2945), with the C5 replacement of its dash."""


class PlaceBody(ApiBody):
    """`POST /lookup/place`."""

    id: Annotated[str, Field(min_length=1, max_length=MAX_ID_LENGTH + 12)]
    kind: Literal["place", "universe"] = "place"


def lookup_for(upstream: Any) -> PlaceLookup:
    """This worker's `PlaceLookup` for `upstream`: the one `upstream/internal.py place_lookup_for` keeps, shared
    with the Clients page (one 10 minute cache per worker)."""
    return place_lookup_for(upstream)


def _created_recently(created: Any, now: float) -> bool:
    if not isinstance(created, str) or not created:
        return False
    try:
        when = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    return now - when.timestamp() < NEW_PLACE_DAYS * 86_400


def notes_for(result: dict[str, Any], now: float) -> list[str]:
    """v1's throwaway-place warning when the experience is less than 7 days old and has under 1,000 visits."""
    visits = result.get("Visits")
    few = isinstance(visits, int | float) and not isinstance(visits, bool) and visits < FEW_VISITS
    return [THROWAWAY_NOTE] if few and _created_recently(result.get("Created"), now) else []


@router.post("/place")
async def lookup_place(request: Request, _admin: AdminSession, _csrf: CsrfChecked, body: PlaceBody) -> dict[str, Any]:
    """Identify the experience behind a place or universe id (paced and recorded as an internal call)."""
    ctx = get_ctx(request)
    if ctx.upstream is None:
        raise common.unavailable("The upstream service is not running yet; try again shortly.")
    answer = await lookup_for(ctx.upstream).lookup(body.id, body.kind)
    message = str(answer.payload.get("Message") or "")
    if answer.http_status == 400:
        raise common.validation_error({"id": message or "Enter a numeric place or universe ID"}, code="invalid_id")
    if answer.http_status == 404:
        raise common.not_found(message or "Roblox returned no experience for that ID")
    if answer.http_status != 200:
        raise common.ApiError(502, "upstream_failed", message or "The lookup failed; try again later.")
    result = dict(answer.payload)
    return {"experience": result, "cached": answer.cached, "notes": notes_for(result, ctx.clock.now())}


__all__ = ["THROWAWAY_NOTE", "lookup_for", "notes_for", "router"]
