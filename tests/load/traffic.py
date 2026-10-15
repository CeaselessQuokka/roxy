"""Traffic profiles for the load tests: the v1-like endpoint mix, key popularity, client addresses, request plans.

What this is
    - `V1_LIKE_MIX`: thirteen Roblox endpoints with the share of traffic each gets, how many distinct keys it has
      and how skewed their popularity is (Zipf), and how the mock Roblox behaves on it (its 429 threshold, latency
      and body size).
    - `Zipf`, `KeyChooser`: which key (user id, universe id, ...) a request asks for.
    - `documentation_addresses`, `benchmark_addresses`: client addresses that belong to no real system.
    - `PlannedRequest` and the planners (`poisson_plan`, `burst_plan`): what to send, from which address, and when.

Why it exists
    Plan 19.10 row 7 asks for "a synthetic profile shaped like v1's endpoint mix" because no real traffic may be
    used (C4, 19.12). v1 never wrote its per-endpoint counts anywhere a test can read: the `endpoints` store lived
    in the server's data file, which agents never read, and .remake/v1notes describes the stores and the
    templating, not the numbers. So the mix is built from what the notes and the plan do say:
    - plan 2.5: about 50,000 requests, of which v1 called 21,889 "saved" (about 44 percent, stale serves
      included), 579 Roblox 429s, most misses on the operator's account;
    - the endpoints the v1 notes, the v1 home page example and the user guide use: avatar outfits (the v1 home
      page example), user name lookups (a POST batch), game details and votes by universe id, place to universe,
      avatar headshots, game server lists, group roles, badges, catalog and economy details, presence;
    - plan 10 and D11: one experience reaches Roxy from hundreds of game server addresses, each sending a few
      requests a minute; game servers ask again and again about their own universe (a few very hot keys), while
      lookups about players spread over a long tail of user ids (mild Zipf skew).
    The thresholds are per minute from Roxy's single address, between 30 and 150 calls. Roblox does not publish
    them; the plan says many endpoints allow "far less than 95 per 65 s" (2.5, R1), and v1's own budget assumed
    "a 100-per-minute detection threshold". The table was fixed before the first run and is not tuned to make any
    test pass (see test_replay_profile.py).

How it works
    Shares are percentages (they add up to 100). `poisson_plan` draws exponential gaps for the arrival times (an
    open-loop Poisson process at the target rate), picks an endpoint by share, a key from that endpoint's
    `KeyChooser` and a client address uniformly from the pool. Everything is seeded, so a plan is reproducible.

What to read next
    `mock_roblox.py` (how the thresholds are enforced), `scenarios.py` (which plan each scenario sends).
"""

from __future__ import annotations

import bisect
import itertools
import json
import random
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from load.mock_roblox import Endpoint

ROBLOX_UA: Final = "Roblox/Linux"
"""The User-Agent Roblox game servers send with HttpService requests."""

DOCUMENTATION_NETS: Final = ("192.0.2", "198.51.100", "203.0.113")
"""RFC 5737 documentation ranges: 762 usable addresses that belong to no real system."""


@dataclass(frozen=True, slots=True)
class EndpointMix:
    """One endpoint of a traffic profile, and the mock's behavior on it."""

    name: str
    share: float
    """Percent of all requests."""
    method: str
    host: str
    path: str
    """Path with `{id}` where the key goes, for example `/v1/users/{id}`."""
    query: str = ""
    """Query string with an optional `{id}`."""
    body: str | None = None
    """POST body with `{id}` or `{ids}` (a JSON list of ids), or None for GET."""
    keys: int = 1000
    """Distinct keys (ids) in the endpoint's key space."""
    zipf_s: float = 1.0
    """Zipf exponent of key popularity (0 is uniform; larger is more skewed)."""
    ids_per_body: tuple[int, int] = (1, 1)
    """For `{ids}` bodies: how many ids one request lists (inclusive range)."""
    id_base: int = 1_000_000
    limit_per_min: int = 0
    """The mock's threshold: calls per minute from Roxy's address before Roblox answers 429 (0 = none)."""
    latency_ms: int = 60
    body_bytes: int = 600

    def mock_endpoint(self, *, latency_scale: float = 1.0, limits: bool = True) -> Endpoint:
        """The mock's view of this endpoint: its path as a regular expression and its behavior."""
        pattern = "".join(r"\d+" if part == "{id}" else re.escape(part) for part in re.split(r"(\{id\})", self.path))
        return Endpoint(
            name=self.name,
            method=self.method,
            host=self.host,
            path=pattern,
            limit_per_min=self.limit_per_min if limits else 0,
            latency_s=self.latency_ms / 1000 * latency_scale,
            body_bytes=self.body_bytes,
        )


# Shares add up to 100. Keys and skew: universe-scoped endpoints have a few hot keys (every server of a game asks
# about its own universe), player-scoped ones a long tail. Thresholds per minute from one address; latency is
# Roblox's typical answer time for that kind of call. Comments give the default cache rule TTL that applies
# (`config/defaults.py`; endpoints without a rule use `cache_ttl_seconds`, 120 s).
V1_LIKE_MIX: Final[tuple[EndpointMix, ...]] = (
    EndpointMix(  # no rule: 120 s. The v1 home page example.
        "avatar_outfits", 16, "GET", "avatar.roblox.com", "/v2/avatar/users/{id}/outfits",
        "outfitType=Avatar&page=1&itemsPerPage=100&isEditable=true",
        keys=20_000, zipf_s=0.9, limit_per_min=60, latency_ms=120, body_bytes=4000,
    ),
    EndpointMix(  # rule: 300 s
        "games_details", 14, "GET", "games.roblox.com", "/v1/games", "universeIds={id}",
        keys=150, zipf_s=1.1, id_base=4_000_000, limit_per_min=100, latency_ms=80, body_bytes=1500,
    ),
    EndpointMix(  # rule: 600 s, POST keyed by the body hash
        "usernames", 10, "POST", "users.roblox.com", "/v1/usernames/users",
        body='{{"usernames":["player{id}"],"excludeBannedUsers":true}}',
        keys=20_000, zipf_s=0.9, limit_per_min=60, latency_ms=90, body_bytes=200,
    ),
    EndpointMix(  # no rule: 120 s
        "avatar_headshot", 12, "GET", "thumbnails.roblox.com", "/v1/users/avatar-headshot",
        "userIds={id}&size=150x150&format=Png&isCircular=false",
        keys=20_000, zipf_s=0.9, limit_per_min=150, latency_ms=60, body_bytes=250,
    ),
    EndpointMix(  # rule: 600 s
        "user_details", 8, "GET", "users.roblox.com", "/v1/users/{id}",
        keys=20_000, zipf_s=0.9, limit_per_min=60, latency_ms=60, body_bytes=400,
    ),
    EndpointMix(  # no rule: 120 s
        "group_roles", 8, "GET", "groups.roblox.com", "/v2/users/{id}/groups/roles",
        keys=20_000, zipf_s=0.9, limit_per_min=60, latency_ms=90, body_bytes=1200,
    ),
    EndpointMix(  # rule: 300 s
        "games_votes", 6, "GET", "games.roblox.com", "/v1/games/votes", "universeIds={id}",
        keys=150, zipf_s=1.1, id_base=4_000_000, limit_per_min=100, latency_ms=70, body_bytes=150,
    ),
    EndpointMix(  # rule: 86,400 s
        "place_universe", 6, "GET", "apis.roblox.com", "/universes/v1/places/{id}/universe",
        keys=150, zipf_s=1.1, id_base=8_000_000, limit_per_min=100, latency_ms=50, body_bytes=40,
    ),
    EndpointMix(  # no rule: 120 s
        "game_servers", 5, "GET", "games.roblox.com", "/v1/games/{id}/servers/Public", "limit=100",
        keys=150, zipf_s=1.1, id_base=8_000_000, limit_per_min=30, latency_ms=150, body_bytes=6000,
    ),
    EndpointMix(  # rule: 3,600 s
        "badge_details", 4, "GET", "badges.roblox.com", "/v1/badges/{id}",
        keys=2_000, zipf_s=1.0, id_base=2_000_000, limit_per_min=60, latency_ms=60, body_bytes=700,
    ),
    EndpointMix(  # rule: 600 s
        "economy_details", 4, "GET", "economy.roblox.com", "/v2/assets/{id}/details",
        keys=2_000, zipf_s=1.0, id_base=3_000_000, limit_per_min=30, latency_ms=80, body_bytes=900,
    ),
    EndpointMix(  # rule: 600 s
        "catalog_details", 3, "GET", "catalog.roblox.com", "/v1/catalog/items/{id}/details", "itemType=Asset",
        keys=2_000, zipf_s=1.0, id_base=3_000_000, limit_per_min=30, latency_ms=80, body_bytes=900,
    ),
    EndpointMix(  # rule: 15 s plus 15 s SWR, POST keyed by the body hash
        "presence", 4, "POST", "presence.roblox.com", "/v1/presence/users", body='{{"userIds":{ids}}}',
        keys=20_000, zipf_s=0.9, ids_per_body=(1, 6), limit_per_min=30, latency_ms=60, body_bytes=300,
    ),
)  # fmt: skip


def mix_total(mix: Sequence[EndpointMix]) -> float:
    return sum(item.share for item in mix)


# ------------------------------------------------------------------------------------------- key popularity


class Zipf:
    """Ranks 1..n drawn with probability proportional to `1 / rank ** s` (inverse transform on the table)."""

    def __init__(self, n: int, s: float) -> None:
        if n < 1:
            raise ValueError("n must be at least 1")
        self.n = n
        self.s = s
        self._cumulative = list(itertools.accumulate(1.0 / (rank**s) for rank in range(1, n + 1)))

    def draw(self, rng: random.Random) -> int:
        """A rank between 1 and n."""
        point = rng.random() * self._cumulative[-1]
        return min(self.n, bisect.bisect_left(self._cumulative, point) + 1)

    def mass(self, top: int) -> float:
        """The probability that a draw falls in the `top` most popular ranks."""
        top = max(0, min(self.n, top))
        return 0.0 if top == 0 else self._cumulative[top - 1] / self._cumulative[-1]


class KeyChooser:
    """Picks the id for one request: Zipf over the endpoint's key space, or a share of never-repeated ids."""

    def __init__(self, item: EndpointMix, *, unique_share: float = 0.0, hot_keys: int | None = None) -> None:
        self.item = item
        self.unique_share = unique_share
        self._zipf = Zipf(hot_keys or item.keys, item.zipf_s)
        self._fresh = itertools.count(item.id_base + 10 * item.keys)  # ids no Zipf draw can produce

    def draw(self, rng: random.Random) -> int:
        if self.unique_share and rng.random() < self.unique_share:
            return next(self._fresh)
        return self.item.id_base + self._zipf.draw(rng)


# ------------------------------------------------------------------------------------------- client addresses


def documentation_addresses(count: int) -> list[str]:
    """Up to 762 addresses from the RFC 5737 documentation ranges."""
    if not 1 <= count <= 254 * len(DOCUMENTATION_NETS):
        raise ValueError("between 1 and 762 documentation addresses")
    return [f"{DOCUMENTATION_NETS[n // 254]}.{n % 254 + 1}" for n in range(count)]


def benchmark_addresses(count: int) -> list[str]:
    """Up to 130,048 addresses from 198.18.0.0/15, the range RFC 2544 sets aside for benchmark tests."""
    if not 1 <= count <= 512 * 254:
        raise ValueError("between 1 and 130048 benchmark addresses")
    out = []
    for n in range(count):
        block, host = divmod(n, 254)
        out.append(f"198.{18 + block // 256}.{block % 256}.{host + 1}")
    return out


# ------------------------------------------------------------------------------------------- request plans


@dataclass(frozen=True, slots=True)
class PlannedRequest:
    """One request to send: when (seconds after the start), what, and from which client address."""

    at: float
    method: str
    path: str
    """The proxy path: `/<host><path>?<query>`."""
    body: bytes | None
    ip: str
    label: str
    """The endpoint name, for the per-endpoint tables."""


def build_request(item: EndpointMix, key: int, rng: random.Random) -> tuple[str, bytes | None]:
    """The proxy path and body of one request for `key`."""
    path = "/" + item.host + item.path.format(id=key)
    if item.query:
        path += "?" + item.query.format(id=key)
    if item.body is None:
        return path, None
    low, high = item.ids_per_body
    count = rng.randint(low, high)
    ids = [key] + [item.id_base + rng.randint(1, item.keys) for _ in range(count - 1)]
    return path, item.body.format(id=key, ids=json.dumps(ids, separators=(",", ":"))).encode()


class MixPicker:
    """Draws endpoints by share, and keys with each endpoint's chooser."""

    def __init__(self, mix: Sequence[EndpointMix], *, unique_share: float = 0.0, hot_keys: int | None = None) -> None:
        self.mix = list(mix)
        self._cumulative = list(itertools.accumulate(item.share for item in self.mix))
        self._choosers = [KeyChooser(item, unique_share=unique_share, hot_keys=hot_keys) for item in self.mix]

    def draw(self, rng: random.Random) -> tuple[EndpointMix, int]:
        index = bisect.bisect_right(self._cumulative, rng.random() * self._cumulative[-1])
        index = min(index, len(self.mix) - 1)
        return self.mix[index], self._choosers[index].draw(rng)


def poisson_plan(
    picker: MixPicker, *, rate: float, duration_s: float, addresses: Sequence[str], seed: int
) -> list[PlannedRequest]:
    """Open-loop Poisson arrivals at `rate` per second for `duration_s`, each a draw from `picker`."""
    rng = random.Random(seed)
    plan: list[PlannedRequest] = []
    at = rng.expovariate(rate)
    while at < duration_s:
        item, key = picker.draw(rng)
        path, body = build_request(item, key, rng)
        plan.append(PlannedRequest(at, item.method, path, body, rng.choice(addresses), item.name))
        at += rng.expovariate(rate)
    return plan


def burst_plan(
    picker: MixPicker,
    *,
    keys: Sequence[tuple[EndpointMix, int]],
    per_address: int,
    addresses: Sequence[str],
    seed: int,
) -> list[PlannedRequest]:
    """Every address sends `per_address` requests at time 0, each for a key drawn uniformly from `keys`."""
    rng = random.Random(seed)
    plan: list[PlannedRequest] = []
    for ip in addresses:
        for _ in range(per_address):
            item, key = rng.choice(list(keys))
            path, body = build_request(item, key, rng)
            plan.append(PlannedRequest(0.0, item.method, path, body, ip, item.name))
    rng.shuffle(plan)
    return plan


def hot_keys(mix: Sequence[EndpointMix], count: int) -> list[tuple[EndpointMix, int]]:
    """`count` distinct keys spread evenly over the GET endpoints of `mix` (the most popular ids of each)."""
    gets = [item for item in mix if item.method == "GET"]
    out: list[tuple[EndpointMix, int]] = []
    for rank in range(1, count + 1):
        item = gets[(rank - 1) % len(gets)]
        out.append((item, item.id_base + (rank - 1) // len(gets) + 1))
    return out


__all__ = [
    "ROBLOX_UA",
    "V1_LIKE_MIX",
    "EndpointMix",
    "KeyChooser",
    "MixPicker",
    "PlannedRequest",
    "Zipf",
    "benchmark_addresses",
    "build_request",
    "burst_plan",
    "documentation_addresses",
    "hot_keys",
    "mix_total",
    "poisson_plan",
]
