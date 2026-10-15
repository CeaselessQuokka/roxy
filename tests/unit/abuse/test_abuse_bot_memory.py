"""The bot tracker keeps a client small until it needs more (finding LOAD-2).

What this is
    Unit tests for `roxy/abuse/bot.py` `ClientTracker`: a client's probe and query histories are created at its first
    probe and its first request with a query string, and a client without them scores exactly as one with empty ones.

Why it exists
    The tracker holds up to `MAX_CLIENTS` (10,000) clients per worker. Each empty deque costs 760 bytes, and most
    clients never probe, so creating every history up front made a client about 4 KB (up to 39 MiB a worker on the
    909 MB server). The signals must not change for it.

How it works
    Observe clients through the public API, then compare their signals with the module's own formulas.

What to read next
    `roxy/abuse/bot.py` (module docstring), `docs/PERFORMANCE.md` (LOAD-2).
"""

from __future__ import annotations

from roxy.abuse import bot


def _observe(tracker: bot.ClientTracker, key: str, n: int, *, probe: bool = False, query: bool = False) -> None:
    for step in range(n):
        tracker.observe(
            key,
            now=1_760_000_000.0 + step,
            monotonic=float(step),
            refused=False,
            probe=probe,
            query_fp=step % 3 if query else None,
            ip="198.51.100.7",
        )


def test_histories_are_created_only_when_used() -> None:
    tracker = bot.ClientTracker()
    _observe(tracker, "ip:198.51.100.7", 5)
    client = tracker._clients["ip:198.51.100.7"]
    assert client.probes is None
    assert client.queries is None
    _observe(tracker, "ip:198.51.100.7", 3, probe=True, query=True)
    assert client.probes is not None
    assert len(client.probes) == 3
    assert client.probes.maxlen == bot.PROBES_KEPT
    assert client.queries is not None
    assert client.queries.maxlen == bot.BUST_WINDOW


def test_a_client_without_histories_scores_like_one_with_empty_ones() -> None:
    tracker = bot.ClientTracker()
    _observe(tracker, "ip:a", 60)
    quiet = tracker._clients["ip:a"]
    signals = tracker._signals(quiet, now=1_760_000_060.0, library_ua=False, game_server=True, header_anomaly=False)
    assert signals.probes == 0.0
    assert signals.cache_busting == 0.0
    _observe(tracker, "ip:b", bot.BUST_MIN_REQUESTS, probe=True, query=True)
    busy = tracker._clients["ip:b"]
    signals = tracker._signals(busy, now=1_760_000_000.0 + 50, library_ua=False, game_server=True, header_anomaly=False)
    assert signals.probes == 1.0  # five or more probes in the window
    assert signals.cache_busting == 3 / bot.BUST_MIN_REQUESTS  # three distinct query fingerprints
