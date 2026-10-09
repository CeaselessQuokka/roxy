"""Bot score: a 0 to 100 estimate of how automated (and abusive) a client looks, from weighted signals.

What this is
    `ClientTracker`, a bounded per-worker memory of recent behavior per client key; `BotSignals`, the seven signals
    of plan 10.7 each normalized to 0..1; and `score`, the weighted average times 100 with weights from the
    `bot_weight_<signal>` settings. Also `is_library_ua`, `has_game_server_signature` and `header_order_family`.

Why it exists
    Most abuse is automated, and most automation leaves traces: a library User-Agent, probe paths, a perfectly
    regular rhythm, cache-busting query strings. No single trace proves anything, so they are combined into one
    explainable number that drill-downs show, detectors and recommendations use, and that can (only when the admin
    sets `bot_score_block_threshold`) block or challenge on its own.

How it works
    score = 100 x sum(weight_i x signal_i) / sum(weight_i), rounded. Signals:
      * library_ua: 1 for an empty UA or a known HTTP library (python-requests, curl, Go-http-client, ...);
      * no_roblox_signature: 1 unless the request carries `Roblox-Id`, a Roblox UA, and comes from
        `roblox_egress_cidrs`. With the list empty a signature earns nothing (plan 15.3 E wins over the 10.3 prose:
        both the header and the UA are trivially forged);
      * probes: min(1, probes in the last 24 h / 5);
      * refusals: refused / total over the last hour;
      * timing: 1 when the coefficient of variation of inter-arrival times is below 0.05 over at least 50 requests;
      * header_order: 1 when the header order fits no known client family;
      * cache_busting: unique query strings / requests with a query, over the last 200 (at least 20 needed).
    The tracker is per worker (a bounded LRU of 10,000 clients): ratios do not depend on how traffic is spread over
    workers, but the probe count does, so with N workers it can read up to N times low. The score never limits
    anything by itself unless the admin sets a block or challenge threshold (both off by default).

    Recorded scores (ABUSE-BOT, THROTTLE-TUNE, ABUSE-DIST, the Clients page): the first request of a client in each
    scoring interval marks it "dirty" and keeps that request's per-request inputs (library User-Agent, game server
    signature, header order anomaly; a few microseconds, once per client per interval, plus up to
    `MAX_IPS_PER_CLIENT` addresses behind the key). `take_scores` then scores the dirty clients off the request
    path (newest first, at most `limit` per call) and clears the mark; the pipeline hands the scores to the metrics
    recorder, which keeps per client and hour the largest score any worker computed and the latest one.

What to read next
    `roxy/abuse/challenge.py` (the browser proof of work that uses the score), then `roxy/abuse/checks/challenge.py`.
"""

from __future__ import annotations

import ipaddress
import itertools
import math
import zlib
from collections import OrderedDict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

MAX_CLIENTS: Final = 10_000
PROBE_WINDOW_S: Final = 86_400
REFUSAL_WINDOW_S: Final = 3600
REFUSAL_BUCKET_S: Final = 300
TIMING_MIN_REQUESTS: Final = 50
TIMING_CV_THRESHOLD: Final = 0.05
BUST_WINDOW: Final = 200
BUST_MIN_REQUESTS: Final = 20
MAX_IPS_PER_CLIENT: Final = 4
"""Addresses remembered per client key (an IPv6 prefix groups several); each gets the key's recorded score."""

SIGNALS: Final[tuple[str, ...]] = (
    "library_ua",
    "no_roblox_signature",
    "probes",
    "refusals",
    "timing",
    "header_order",
    "cache_busting",
)
"""Signal names; each has a `bot_weight_<name>` setting."""

LIBRARY_UA_MARKERS: Final[tuple[str, ...]] = (
    "python-requests",
    "python-urllib",
    "python-httpx",
    "aiohttp",
    "curl/",
    "wget/",
    "go-http-client",
    "okhttp",
    "java/",
    "apache-httpclient",
    "libwww-perl",
    "node-fetch",
    "axios/",
    "undici",
    "scrapy",
    "guzzlehttp",
    "php/",
    "ruby",
    "postmanruntime",
    "insomnia",
)
"""Lowercase substrings of User-Agents sent by HTTP libraries and tools rather than browsers or Roblox."""

KNOWN_HEADER_ORDERS: Final[dict[str, tuple[str, ...]]] = {
    # Relative order of a few common request headers per client family. A request fits a family when the anchors it
    # sends appear in that order; headers not listed (including the ones nginx adds) are ignored.
    "chromium": ("host", "connection", "sec-ch-ua", "user-agent", "accept", "sec-fetch-site", "accept-encoding"),
    "firefox": ("host", "user-agent", "accept", "accept-language", "accept-encoding", "connection"),
    "safari": ("host", "accept", "sec-fetch-site", "accept-language", "user-agent", "accept-encoding"),
    "roblox": ("host", "user-agent", "accept", "roblox-id", "content-type"),
    "library": ("host", "user-agent", "accept-encoding", "accept", "connection"),
    "curl": ("host", "user-agent", "accept"),
}


def is_library_ua(user_agent: str) -> bool:
    """True for an empty User-Agent or one of `LIBRARY_UA_MARKERS`."""
    text = (user_agent or "").strip().lower()
    return not text or any(marker in text for marker in LIBRARY_UA_MARKERS)


def in_networks(ip: str, networks: Iterable[str]) -> bool:
    """Whether `ip` is inside any of the CIDR strings (invalid entries are ignored)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in networks:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def has_game_server_signature(
    *, place_id: str | None, user_agent: str, client_ip: str, egress_cidrs: Sequence[str]
) -> bool:
    """A trusted Roblox game server: `Roblox-Id`, a Roblox UA, AND an address in `roblox_egress_cidrs`.

    An empty list trusts nobody (plan 15.3 E: "empty means signatures alone earn nothing").
    """
    if not place_id or "roblox" not in (user_agent or "").lower() or not egress_cidrs:
        return False
    return in_networks(client_ip, egress_cidrs)


def header_order_family(names: Sequence[str]) -> str | None:
    """The first known family whose anchor order the request's header names fit, or None (an anomaly)."""
    lowered = [name.lower() for name in names]
    for family, anchors in KNOWN_HEADER_ORDERS.items():
        rank = {name: i for i, name in enumerate(anchors)}
        positions = [rank[name] for name in lowered if name in rank]
        if len(positions) <= 1 or positions == sorted(positions):
            return family
    return None


def query_fingerprint(template: str, query: Sequence[tuple[str, str]]) -> int | None:
    """A small hash of (template, sorted query) for cache-busting detection; None without a query."""
    if not query:
        return None
    text = template + "?" + "&".join(f"{k}={v}" for k, v in sorted(query))
    return zlib.crc32(text.encode("utf-8", "surrogateescape"))


@dataclass(slots=True)
class _Client:
    probes: deque[float] = field(default_factory=lambda: deque(maxlen=64))
    refusal_buckets: dict[int, list[int]] = field(default_factory=dict)  # bucket start -> [total, refused]
    arrivals: deque[float] = field(default_factory=lambda: deque(maxlen=TIMING_MIN_REQUESTS + 14))
    queries: deque[int] = field(default_factory=lambda: deque(maxlen=BUST_WINDOW))
    ips: list[str] = field(default_factory=list)  # recent addresses behind this key (bounded)
    # The per-request signals of the first request since the last recorded score: (library UA, game server
    # signature, header order anomaly). None: nothing to record (the client is not "dirty").
    pending: tuple[bool, bool, bool] | None = None


def _coefficient_of_variation(values: Sequence[float]) -> float | None:
    """Population standard deviation over the mean, in plain floats (`statistics.pstdev` uses exact fractions,
    far slower for a value that only needs comparing with 0.05). None for a mean of 0 or no values."""
    if not values:
        return None
    mean = math.fsum(values) / len(values)
    if mean <= 0:
        return None
    variance = math.fsum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance) / mean


@dataclass(frozen=True, slots=True)
class BotSignals:
    """Each signal normalized to 0..1 (see the module docstring)."""

    library_ua: float = 0.0
    no_roblox_signature: float = 0.0
    probes: float = 0.0
    refusals: float = 0.0
    timing: float = 0.0
    header_order: float = 0.0
    cache_busting: float = 0.0

    def as_dict(self) -> dict[str, float]:
        return {name: float(getattr(self, name)) for name in SIGNALS}


@dataclass(frozen=True, slots=True)
class ScoredClient:
    """One recorded bot score: the client key, the addresses behind it, the score and its signals."""

    key: str
    ips: tuple[str, ...]
    score: int
    signals: BotSignals


def score(signals: BotSignals, weights: Mapping[str, float]) -> int:
    """`round(100 x sum(w x s) / sum(w))`, 0 when every weight is 0."""
    total_weight = sum(max(0.0, float(weights.get(name, 0.0))) for name in SIGNALS)
    if total_weight <= 0:
        return 0
    value: float = sum(max(0.0, float(weights.get(name, 0.0))) * float(getattr(signals, name)) for name in SIGNALS)
    return max(0, min(100, round(100 * value / total_weight)))


class ClientTracker:
    """Recent behavior per client key in this worker (bounded LRU, see the module docstring)."""

    def __init__(self, max_clients: int = MAX_CLIENTS) -> None:
        self._clients: OrderedDict[str, _Client] = OrderedDict()
        self.max_clients = max_clients

    def _get(self, key: str, create: bool) -> _Client | None:
        client = self._clients.get(key)
        if client is None and create:
            client = _Client()
            self._clients[key] = client
            while len(self._clients) > self.max_clients:
                self._clients.popitem(last=False)
        if client is not None:
            self._clients.move_to_end(key)
        return client

    def observe(
        self,
        key: str,
        *,
        now: float,
        monotonic: float,
        refused: bool,
        probe: bool,
        query_fp: int | None,
        ip: str | None = None,
        user_agent: str | None = None,
        game_server: bool | None = None,
        header_names: Sequence[str] | None = None,
    ) -> None:
        """Record one finished request of client `key`.

        With `user_agent` given, the client is marked for a recorded score (module docstring): the first request
        since the last recorded score keeps its per-request signals. `ip` adds the address to the key's bounded list.
        """
        client = self._get(key, create=True)
        assert client is not None  # created above
        if probe:
            client.probes.append(now)
        bucket = int(now // REFUSAL_BUCKET_S) * REFUSAL_BUCKET_S
        entry = client.refusal_buckets.setdefault(bucket, [0, 0])
        entry[0] += 1
        entry[1] += 1 if refused else 0
        cutoff = now - REFUSAL_WINDOW_S
        for start in [s for s in client.refusal_buckets if s + REFUSAL_BUCKET_S <= cutoff]:
            del client.refusal_buckets[start]
        client.arrivals.append(monotonic)
        if query_fp is not None:
            client.queries.append(query_fp)
        if ip and ip not in client.ips:
            client.ips.append(ip)
            if len(client.ips) > MAX_IPS_PER_CLIENT:
                del client.ips[0]  # the oldest address behind the key goes first
        if user_agent is not None and client.pending is None:
            client.pending = (
                is_library_ua(user_agent),
                bool(game_server),
                header_order_family(list(header_names or ())) is None,
            )

    def _signals(
        self,
        client: _Client | None,
        *,
        now: float,
        library_ua: bool,
        game_server: bool,
        header_anomaly: bool,
    ) -> BotSignals:
        """The seven signals from a client's history and one request's per-request inputs."""
        probes = refusals = timing = busting = 0.0
        if client is not None:
            recent_probes = sum(1 for at in client.probes if at >= now - PROBE_WINDOW_S)
            probes = min(1.0, recent_probes / 5)
            total = sum(
                v[0] for s, v in client.refusal_buckets.items() if s + REFUSAL_BUCKET_S > now - REFUSAL_WINDOW_S
            )
            refused = sum(
                v[1] for s, v in client.refusal_buckets.items() if s + REFUSAL_BUCKET_S > now - REFUSAL_WINDOW_S
            )
            refusals = refused / total if total else 0.0
            arrivals = list(client.arrivals)
            if len(arrivals) > TIMING_MIN_REQUESTS:
                variation = _coefficient_of_variation([b - a for a, b in itertools.pairwise(arrivals)])
                if variation is not None and variation < TIMING_CV_THRESHOLD:
                    timing = 1.0
            if len(client.queries) >= BUST_MIN_REQUESTS:
                busting = len(set(client.queries)) / len(client.queries)
        return BotSignals(
            library_ua=1.0 if library_ua else 0.0,
            no_roblox_signature=0.0 if game_server else 1.0,
            probes=probes,
            refusals=refusals,
            timing=timing,
            header_order=1.0 if header_anomaly else 0.0,
            cache_busting=busting,
        )

    def signals(
        self,
        key: str,
        *,
        now: float,
        user_agent: str,
        game_server: bool,
        header_names: Sequence[str],
    ) -> BotSignals:
        """The signals for client `key` given its history plus the current request's UA and headers."""
        return self._signals(
            self._get(key, create=False),
            now=now,
            library_ua=is_library_ua(user_agent),
            game_server=game_server,
            header_anomaly=header_order_family(header_names) is None,
        )

    def take_scores(self, *, now: float, weights: Mapping[str, float], limit: int) -> list[ScoredClient]:
        """Score up to `limit` clients marked since the last call (newest first) and clear their mark.

        Runs off the request path (the pipeline's `abuse_bot_scores` loop). A marked client pushed out of the LRU is
        simply forgotten; one left over beyond `limit` keeps its mark for the next call. Never raises for a client.
        """
        out: list[ScoredClient] = []
        for key in reversed(list(self._clients)):  # most recently used first
            if len(out) >= max(0, int(limit)):
                break
            client = self._clients.get(key)
            if client is None or client.pending is None:
                continue
            library_ua, game_server, header_anomaly = client.pending
            client.pending = None
            signals = self._signals(
                client, now=now, library_ua=library_ua, game_server=game_server, header_anomaly=header_anomaly
            )
            out.append(ScoredClient(key, tuple(client.ips) or (key,), score(signals, weights), signals))
        return out

    def pending(self) -> int:
        """Clients waiting for a recorded score."""
        return sum(1 for client in self._clients.values() if client.pending is not None)

    def __len__(self) -> int:
        return len(self._clients)


__all__ = [
    "LIBRARY_UA_MARKERS",
    "MAX_IPS_PER_CLIENT",
    "SIGNALS",
    "BotSignals",
    "ClientTracker",
    "ScoredClient",
    "has_game_server_signature",
    "header_order_family",
    "in_networks",
    "is_library_ua",
    "query_fingerprint",
    "score",
]
