"""Roxy's own upstream calls: the credential probe, the admin place lookup, and the list of internal endpoints.

What this is
    - `probe_credential(service)`: one liveness probe of the credential (`credential_probe_url`, by default
      `users.roblox.com/v1/users/authenticated`), at most one at a time in the whole fleet (a hot.db lease), read
      as alive, rate limited, rejected or error.
    - `PlaceLookup`: the admin "Identify an experience" lookup (place -> universe -> game details), with v1's
      messages and a 10 minute per-worker cache of successful answers (parity row 38). `place_lookup_for(service)`
      is the one instance of a worker (both lookup routes and the Clients tables share its cache), and `peek`
      reads a cached answer without any upstream call (names in tables).
    - `internal_endpoints(...)` and `INTERNAL_NOTE`: what the Upstream page lists as Roxy's own calls (row 29).

Why it exists
    Parity rows 28 and 29: Roxy's own calls must pay their way in the buckets (v1 probes appended budget uses
    without checking the limit, bug B20, and the lookup's "direct fallback" bypassed every budget, B25). They go
    through `UpstreamService.internal_fetch`, so they are paced, honor cooldowns and breakers, and are recorded as
    the `internal` source, never as caller traffic. Row 25: a probe 429 means "rate limited", never "expired"
    (v1 bug B7), and concurrent 429s no longer schedule one probe each (exactly one probe at a time, fleet-wide).

How it works
    - The credential probe takes the lease `probe:credential` (TTL = request timeout + 5 s) inside a hot.db write,
      calls `internal_fetch(..., use_credential=True)` (credential path only, reserved probe sub-bucket), reads the
      answer, then releases the lease. A second caller while a probe runs gets the verdict `skipped`.
    - The lookup accepts ASCII digits only (v1's `str.isdigit` also accepted superscript digits), resolves a place
      through `apis.roblox.com`, loads details from `games.roblox.com`, and builds v1's result keys. It runs at
      admin priority and never falls back to an unbudgeted call.

What to read next
    `roxy/upstream/service.py` (`internal_fetch`), `roxy/egress/credential.py` (what happens with the verdict), and
    `roxy/admin/api/lookup.py` (the route that calls `PlaceLookup`).
"""

from __future__ import annotations

import json
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Final

from roxy.core.reasons import ReasonCode
from roxy.storage import leases
from roxy.upstream.queue import Priority

CREDENTIAL_PROBE_LEASE: Final = "probe:credential"
PLACE_UNIVERSE_URL: Final = "https://apis.roblox.com/universes/v1/places/{id}/universe"
UNIVERSE_DETAIL_URL: Final = "https://games.roblox.com/v1/games?universeIds={id}"
LOOKUP_TTL_S: Final = 600.0
LOOKUP_CACHE_MAX: Final = 256
MAX_ID_LENGTH: Final = 20
MAX_DESCRIPTION: Final = 600

INTERNAL_NOTE: Final = (
    "Internal probes never pass through the proxy route, so endpoint blocks, rate rules, request filters, "
    "throttling and pause cannot affect them; they do count against the upstream buckets at internal priority. "
    "Client traffic to a similarly-named endpoint is unrelated."
)
"""v1's note (`GET /admin/internal/endpoints`), updated: v2 probes are paced by the buckets (row 28)."""


def internal_endpoints(credential_probe_url: str, ip_echo_url: str = "") -> list[dict[str, str]]:
    """Roxy's own upstream calls, in v1's shape (`Purpose`, `URL`, `What`), plus the v2 health probes (row 29)."""
    return [
        {"Purpose": "credential_probe", "URL": credential_probe_url, "What": "Is the credential still alive?"},
        {"Purpose": "credential_check", "URL": credential_probe_url, "What": "Admin health check / force revalidate"},
        {
            "Purpose": "credential_confirm",
            "URL": credential_probe_url,
            "What": "Confirm a 401 on an allowlisted endpoint before the credential is marked rejected",
        },
        {
            "Purpose": "rotator_probe",
            "URL": ip_echo_url or "the configured IP echo service",
            "What": "Which exit IP is the rotator giving us?",
        },
        {
            "Purpose": "admin_lookup",
            "URL": "apis.roblox.com + games.roblox.com (public)",
            "What": "Identify an experience (only when the proxy path is unavailable)",
        },
        {
            "Purpose": "health_check",
            "URL": "one public probe URL per allowed host (Health page)",
            "What": "Check Proxy Health reachability probes",
        },
    ]


def _json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class CredentialProbe:
    """What one credential probe found."""

    verdict: str  # "alive", "rate_limited", "rejected", "error" or "skipped" (another probe is running)
    status: int | None = None
    account_id: str | None = None  # the user id the probe returned (for the H-CRED-AUTH account fingerprint)
    reason: str = ""
    retry_after_s: int | None = None


def probe_verdict(status: int | None, reason: ReasonCode) -> str:
    """Plan row 25 and 13.2 H-CRED-AUTH: 200 alive, 429 rate limited (never "expired"), 401 or 403 rejected."""
    if status == 200:
        return "alive"
    if status == 429 or reason in (ReasonCode.UPSTREAM_COOLDOWN, ReasonCode.UPSTREAM_BUSY):
        return "rate_limited"
    if status in (401, 403):
        return "rejected"
    return "error"


async def probe_credential(service: Any, *, purpose: str = "credential_probe") -> CredentialProbe:
    """Probe the credential once, fleet-wide single flight. Never raises for upstream problems."""
    settings = service.settings
    ttl_ms = round((float(settings.get("request_timeout")) + 5.0) * 1000)
    holder = service.new_holder()

    def take(conn: Any) -> bool:
        now_ms = int(service.clock.now_ms())
        return leases.acquire(conn, CREDENTIAL_PROBE_LEASE, holder, ttl_ms, now_ms) is not None

    if not await service.hot.write(take):
        return CredentialProbe("skipped", reason="another credential probe is running")
    try:
        url = str(settings.get("credential_probe_url"))
        result = await service.internal_fetch(purpose, "GET", url, use_credential=True)
    finally:
        await service.hot.write(lambda conn: leases.release(conn, CREDENTIAL_PROBE_LEASE, holder, delete=True))
    status = result.upstream_status
    verdict = probe_verdict(status, result.reason)
    account_id = None
    if verdict == "alive":
        payload = _json(result.body)
        if isinstance(payload, dict) and payload.get("id") is not None:
            account_id = str(payload.get("id"))[:32]
    return CredentialProbe(verdict, status, account_id, result.reason.value, result.retry_after_s)


@dataclass(frozen=True, slots=True)
class LookupResult:
    """An HTTP status and v1's JSON payload for `POST /admin/lookup/place` (row 92)."""

    http_status: int
    payload: dict[str, Any]
    cached: bool = False


def _creator_url(creator: dict[str, Any]) -> str:
    """v1 `_creator_url` (index.py:1040-1047)."""
    creator_id = creator.get("id")
    if not creator_id:
        return ""
    if str(creator.get("type", "")).lower() == "group":
        return f"https://www.roblox.com/groups/{creator_id}"
    return f"https://www.roblox.com/users/{creator_id}/profile"


class PlaceLookup:
    """The admin experience lookup (row 38), budgeted and cached for 10 minutes per worker."""

    def __init__(self, service: Any, *, ttl_s: float = LOOKUP_TTL_S, max_entries: int = LOOKUP_CACHE_MAX) -> None:
        self._service = service
        self._ttl_s = ttl_s
        self._max = max(1, max_entries)
        self._cache: OrderedDict[tuple[str, str], tuple[float, dict[str, Any]]] = OrderedDict()

    def _now(self) -> float:
        clock = getattr(self._service, "clock", None)
        return float(clock.monotonic()) if clock is not None else time.monotonic()

    async def _get_json(self, url: str) -> tuple[Any, str]:
        result = await self._service.internal_fetch("admin_lookup", "GET", url, priority=Priority.ADMIN)
        if result.reason not in (ReasonCode.UPSTREAM_OK, ReasonCode.UPSTREAM_4XX):
            return None, result.body.decode("utf-8", "replace") or result.reason.value
        if result.upstream_status != 200:
            return None, f"Roblox returned HTTP {result.upstream_status}"
        payload = _json(result.body)
        if payload is None:
            return None, "Upstream returned a non-JSON body"
        return payload, ""

    def peek(self, place_id: str, kind: str = "place") -> dict[str, Any] | None:
        """A cached successful answer for `place_id`, or None; never calls upstream (tables show known names)."""
        hit = self._cache.get((kind, place_id))
        if hit is None or self._now() - hit[0] >= self._ttl_s:
            return None
        return dict(hit[1])

    async def lookup(self, raw_id: object, kind: object = "place") -> LookupResult:
        """v1 flow (index.py:983-1037): validate, resolve the universe, load the game, shape the answer."""
        raw = str(raw_id if raw_id is not None else "").strip()
        if not raw or len(raw) > MAX_ID_LENGTH or not (raw.isascii() and raw.isdigit()):
            return LookupResult(400, {"Message": "Enter a numeric place or universe ID"})
        lookup_kind = "universe" if kind == "universe" else "place"
        key = (lookup_kind, raw)
        hit = self._cache.get(key)
        if hit is not None and self._now() - hit[0] < self._ttl_s:
            self._cache.move_to_end(key)
            return LookupResult(200, dict(hit[1]), cached=True)
        result: dict[str, Any] = {
            "Query": raw,
            "Kind": lookup_kind,
            "PlaceId": raw if lookup_kind == "place" else "",
            "UniverseId": "",
        }
        if lookup_kind == "place":
            payload, error = await self._get_json(PLACE_UNIVERSE_URL.format(id=raw))
            if error:
                return LookupResult(502, {"Message": f"Could not resolve that place: {error}", **result})
            universe_id = str((payload or {}).get("universeId", "") or "") if isinstance(payload, dict) else ""
            if not universe_id:
                return LookupResult(404, {"Message": "Roblox did not return a universe for that place", **result})
        else:
            universe_id = raw
        result["UniverseId"] = universe_id
        payload, error = await self._get_json(UNIVERSE_DETAIL_URL.format(id=universe_id))
        if error:
            return LookupResult(502, {"Message": f"Could not load that experience: {error}", **result})
        entries = (payload or {}).get("data") if isinstance(payload, dict) else None
        if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
            return LookupResult(404, {"Message": "Roblox returned no experience for that ID", **result})
        game: dict[str, Any] = entries[0]
        raw_creator = game.get("creator")
        creator: dict[str, Any] = raw_creator if isinstance(raw_creator, dict) else {}
        result.update(
            {
                "Name": game.get("name", ""),
                "Description": str(game.get("description", ""))[:MAX_DESCRIPTION],
                "RootPlaceId": game.get("rootPlaceId", ""),
                "Created": game.get("created", ""),
                "Updated": game.get("updated", ""),
                "Playing": game.get("playing", 0),
                "Visits": game.get("visits", 0),
                "MaxPlayers": game.get("maxPlayers", 0),
                "FavoritedCount": game.get("favoritedCount", 0),
                "CreatorId": creator.get("id", ""),
                "CreatorName": creator.get("name", ""),
                "CreatorType": creator.get("type", ""),
                "CreatorVerified": bool(creator.get("hasVerifiedBadge")),
                "Url": f"https://www.roblox.com/games/{game.get('rootPlaceId', '')}",
                "CreatorUrl": _creator_url(creator),
            }
        )
        self._cache[key] = (self._now(), dict(result))
        self._cache.move_to_end(key)
        while len(self._cache) > self._max:
            self._cache.popitem(last=False)
        return LookupResult(200, result)


_LOOKUPS: weakref.WeakKeyDictionary[Any, PlaceLookup] = weakref.WeakKeyDictionary()
"""One `PlaceLookup` per `UpstreamService` (so per worker, and it goes away with the app's service)."""


def place_lookup_for(service: Any) -> PlaceLookup:
    """This worker's `PlaceLookup` for `service` (created on first use). `/lookup/place`, `/clients/lookup` and the
    Clients tables all use it, so a lookup made on one page names the place on the others too."""
    found = _LOOKUPS.get(service)
    if found is None:
        found = PlaceLookup(service)
        _LOOKUPS[service] = found
    return found


__all__ = [
    "CREDENTIAL_PROBE_LEASE",
    "INTERNAL_NOTE",
    "LOOKUP_TTL_S",
    "PLACE_UNIVERSE_URL",
    "UNIVERSE_DETAIL_URL",
    "CredentialProbe",
    "LookupResult",
    "PlaceLookup",
    "internal_endpoints",
    "place_lookup_for",
    "probe_credential",
    "probe_verdict",
]
