"""Probe URLs per Roblox host (plan 13.4): one stable, cheap, public request per host for H-REACH and friends.

What this is
    `probe_for(host)` returns the `Probe` (method, URL, optional JSON body, the statuses that count as "reachable",
    and the JSON field a 200 answer should carry) for every host 13.4 names, and `HEAD /` for any other allowed
    host. `E2E_PATH` is the public-origin path H-E2E requests twice, and `CLOCK_PROBE_URL` the request H-CLOCK
    reads Roblox's `Date` header from.

Why it exists
    A reachability check needs a request whose answer is known in advance, costs Roblox almost nothing, and never
    involves the owner's own game or account. 13.4 asks the implementer to pick fixed public objects owned by
    Roblox itself and to list them here with a comment.

How it works
    The ids below are public objects of the official Roblox account, the same for every Roxy install:
      * user 1 is the "Roblox" account itself (the first user ever created);
      * group 1200769 is "Official Group of Roblox";
      * place 1818 is "Crossroads", a classic place built and owned by the Roblox account; universe 13058 is the
        universe that holds it. A place is also an asset, so asset 1818 is used for the economy and inventory
        probes (an asset id that is guaranteed to exist and to belong to user 1).
    No id belongs to the owner. These URLs are only ever requested in production through
    `UpstreamService.internal_fetch` at internal priority (every probe goes through the buckets); tests never call
    them, they answer from mocks keyed `probe:<host>`. If Roblox retires one of these objects the probe for that
    host starts failing with a 4xx, which the H-REACH explanation points at; change the id here.

What to read next
    `roxy/health/checks.py` (`check_reach`, `check_e2e`, `check_clock`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final

PUBLIC_USER_ID: Final = 1
"""The official "Roblox" user account."""

PUBLIC_GROUP_ID: Final = 1200769
"""The "Official Group of Roblox"."""

PUBLIC_PLACE_ID: Final = 1818
""""Crossroads", a classic place owned by the Roblox account (user 1)."""

PUBLIC_UNIVERSE_ID: Final = 13058
"""The universe that contains place 1818."""

PUBLIC_ASSET_ID: Final = PUBLIC_PLACE_ID
"""Places are assets too: asset 1818 exists and belongs to user 1, so is-owned and asset details have an answer."""


@dataclass(frozen=True, slots=True)
class Probe:
    """One probe request and what counts as a good answer.

    `expected` are the statuses that mean "reachable" for this host (13.4); `head_only` probes accept any status
    below 500. `json_field` is a field a 200 JSON answer must carry (`data`, `id`), or "" when any JSON answer is
    fine. `rate_limit_warns` marks the probe 13.4 expects to see a 429 now and then (catalog search).
    """

    host: str
    method: str
    path: str
    expected: frozenset[int]
    json_field: str = ""
    body: bytes | None = None
    head_only: bool = False
    rate_limit_warns: bool = True

    @property
    def url(self) -> str:
        return f"https://{self.host}{self.path}"

    def accepts(self, status: int) -> bool:
        """Whether `status` means "reachable" for this probe (before the latency bands are applied)."""
        if self.head_only:
            return status < 500
        return status in self.expected


_OK: Final = frozenset({200})

_NAMED: Final[dict[str, Probe]] = {
    probe.host: probe
    for probe in (
        Probe("games.roblox.com", "GET", f"/v1/games?universeIds={PUBLIC_UNIVERSE_ID}", _OK, json_field="data"),
        Probe("users.roblox.com", "GET", f"/v1/users/{PUBLIC_USER_ID}", _OK, json_field="id"),
        Probe(
            "thumbnails.roblox.com",
            "GET",
            f"/v1/users/avatar-headshot?userIds={PUBLIC_USER_ID}&size=48x48&format=Png",
            _OK,
        ),
        Probe("groups.roblox.com", "GET", f"/v1/groups/{PUBLIC_GROUP_ID}", _OK),
        Probe("catalog.roblox.com", "GET", "/v1/search/items?Keyword=hat&Limit=10", _OK),
        Probe("economy.roblox.com", "GET", f"/v2/assets/{PUBLIC_ASSET_ID}/details", _OK),
        Probe("badges.roblox.com", "GET", f"/v1/universes/{PUBLIC_UNIVERSE_ID}/badges?limit=10", _OK),
        Probe(
            "presence.roblox.com",
            "POST",
            "/v1/presence/users",
            _OK,
            # A read-only batch lookup (13.4 allows this one POST); the body names one public user.
            body=json.dumps({"userIds": [PUBLIC_USER_ID]}, separators=(",", ":")).encode("utf-8"),
        ),
        Probe("friends.roblox.com", "GET", f"/v1/users/{PUBLIC_USER_ID}/friends/count", _OK),
        Probe(
            "inventory.roblox.com",
            "GET",
            f"/v1/users/{PUBLIC_USER_ID}/items/Asset/{PUBLIC_ASSET_ID}/is-owned",
            frozenset({200, 403}),  # a private inventory is a valid answer
        ),
        Probe("avatar.roblox.com", "GET", f"/v1/users/{PUBLIC_USER_ID}/avatar", _OK),
        Probe("apis.roblox.com", "GET", f"/universes/v1/places/{PUBLIC_PLACE_ID}/universe", _OK),
        Probe("develop.roblox.com", "GET", f"/v1/universes/{PUBLIC_UNIVERSE_ID}", frozenset({200, 401})),
        Probe(
            "followings.roblox.com",
            "GET",
            f"/v1/users/{PUBLIC_USER_ID}/universes",
            frozenset({200, 401, 404}),  # reachability only
        ),
    )
}


def probe_for(host: str) -> Probe:
    """The 13.4 probe for `host`; `HEAD /` (any status below 500) for an allowed host 13.4 does not name."""
    name = host.strip().lower().rstrip(".")
    found = _NAMED.get(name)
    if found is not None:
        return found
    return Probe(name, "HEAD", "/", frozenset(), head_only=True)


def named_hosts() -> tuple[str, ...]:
    """The hosts with a named probe (13.4 table order)."""
    return tuple(_NAMED)


CLOCK_PROBE_URL: Final = _NAMED["games.roblox.com"].url
"""H-CLOCK reads Roblox's `Date` header from this anonymous, cheap answer (through the buckets)."""

E2E_PATH: Final = f"/games.roblox.com/v1/games?universeIds={PUBLIC_UNIVERSE_ID}"
"""H-E2E: the public pipeline request (nginx, then Roxy, then Roblox), sent twice to see the cache transition."""

STATIC_ASSET_PATH: Final = "/static/public/site.css"
"""H-NGINX: an asset every release ships, served by nginx's `location /static/` (HSTS must be there too)."""

ADMIN_PATH: Final = "/admin"
INTERNAL_VERSION_PATH: Final = "/internal/version"


__all__ = [
    "ADMIN_PATH",
    "CLOCK_PROBE_URL",
    "E2E_PATH",
    "INTERNAL_VERSION_PATH",
    "PUBLIC_ASSET_ID",
    "PUBLIC_GROUP_ID",
    "PUBLIC_PLACE_ID",
    "PUBLIC_UNIVERSE_ID",
    "PUBLIC_USER_ID",
    "STATIC_ASSET_PATH",
    "Probe",
    "named_hosts",
    "probe_for",
]
