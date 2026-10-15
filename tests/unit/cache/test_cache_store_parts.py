"""In-memory parts of the cache store: bodies, the memory tier, hit and observation buffers, purge scopes."""

from __future__ import annotations

import pytest

from roxy.cache.store import (
    FORMAT_RAW,
    FORMAT_ZSTD,
    MEMORY_ENTRY_OVERHEAD,
    CacheEntry,
    DiskHealth,
    HitBuffer,
    MemoryTier,
    ObservationBuffer,
    PurgeKind,
    PurgeScope,
    decode_body,
    encode_body,
    target_matches,
)
from roxy.core.reasons import AuthClass
from roxy.rules.match import PatternValidationError


def entry(entry_id: str, body: bytes = b"x", *, generation: int = 0, stored_at: int = 100, ttl: int = 60) -> CacheEntry:
    return CacheEntry(
        id=entry_id,
        key=f"GET h.roblox.com/{entry_id}",
        auth_class=AuthClass.ANON,
        method="GET",
        host="h.roblox.com",
        path=entry_id,
        status=200,
        body=body,
        content_type="application/json",
        stored_at=stored_at,
        expires_at=stored_at + ttl,
        stale_until=stored_at + ttl + 600,
        ttl=ttl,
        generation=generation,
    )


def test_bodies_round_trip_compressed_or_raw() -> None:
    json_body = b'{"data":[' + b'{"id":1,"name":"Roxy"},' * 200 + b"{}]}"
    packed = encode_body(json_body, compress=True)
    assert packed[:1] == FORMAT_ZSTD
    assert len(packed) < len(json_body) / 4
    assert decode_body(packed) == json_body
    raw = encode_body(json_body, compress=False)
    assert raw[:1] == FORMAT_RAW
    assert decode_body(raw) == json_body
    tiny = encode_body(b"{}", compress=True)
    assert tiny == FORMAT_RAW + b"{}"  # too small to gain anything
    assert decode_body(None) == b""
    with pytest.raises(ValueError):
        decode_body(b"?junk")


def test_entry_freshness_and_age() -> None:
    item = entry("a", stored_at=100, ttl=60)
    assert item.is_fresh(159.9)
    assert not item.is_fresh(160)
    assert item.age(171.8) == 71
    assert item.age(50) == 0


def test_memory_tier_lru_and_caps() -> None:
    tier = MemoryTier(max_entries=2, max_bytes=10_000)
    tier.put(entry("a"))
    tier.put(entry("b"))
    assert tier.get("a") is not None  # touch: a is now most recent
    tier.put(entry("c"))
    assert "b" not in tier
    assert "a" in tier
    assert "c" in tier
    assert tier.evictions == 1
    small = MemoryTier(max_entries=10, max_bytes=MEMORY_ENTRY_OVERHEAD * 2 + 100)
    assert not small.put(entry("big", b"x" * 10_000))  # bigger than the whole tier: refused
    off = MemoryTier(max_entries=0, max_bytes=10_000)
    assert not off.put(entry("a"))


def test_memory_tier_configure_trims_and_floor_refuses_old_generations() -> None:
    tier = MemoryTier(max_entries=5, max_bytes=100_000)
    for name in "abcde":
        tier.put(entry(name))
    tier.configure(2, 100_000)
    assert len(tier) == 2
    tier.floor = 3
    assert not tier.put(entry("old", generation=2))
    assert tier.put(entry("new", generation=3))
    tier.put(entry("z", generation=3))
    assert tier.get("new") is None or tier.get("new").generation == 3
    tier.configure(0, 0)
    assert len(tier) == 0
    assert tier.bytes == 0


def test_hit_buffer_is_bounded_and_restorable() -> None:
    hits = HitBuffer(max_ids=2)
    hits.record("a", 10)
    hits.record("a", 12)
    hits.record("b", 11)
    hits.record("c", 13)
    assert hits.dropped == 1
    assert hits.pending("a") == 2
    drained = hits.drain()
    assert sorted(drained) == [("a", 2, 12), ("b", 1, 11)]
    assert len(hits) == 0
    hits.restore(drained)
    assert hits.pending("a") == 2


def test_observation_buffer() -> None:
    observations = ObservationBuffer(max_keys=1)
    observations.observe("games.roblox.com/v1/games", 0, True)
    observations.observe("games.roblox.com/v1/games", 0, False)
    observations.observe("other", 0, True)
    assert observations.dropped == 1
    assert observations.drain() == [("games.roblox.com/v1/games", 0, 2, 1)]


def test_disk_health_recovers_after_a_later_write() -> None:
    health = DiskHealth()
    assert health.ok
    health.failed("disk full", 10.0)
    assert not health.ok
    health.wrote(11.0)
    assert health.ok


def test_purge_scopes_validate() -> None:
    assert PurgeScope.all().validated().kind is PurgeKind.ALL
    assert PurgeScope.host("Games.Roblox.com.").validated().value == "games.roblox.com"
    assert PurgeScope.pattern("/Games.Roblox.com/v1/*").validated().value == "games.roblox.com/v1/*"
    assert PurgeScope.rule(4).validated().value == 4
    assert PurgeScope.expired(include_stale=True).validated().include_stale
    with pytest.raises(ValueError, match="Nothing to purge"):
        PurgeScope.entry("  ").validated()
    with pytest.raises(PatternValidationError):
        PurgeScope.pattern("(unclosed", "regex").validated()
    assert PurgeScope.param("t").label == "param:t"


def test_pattern_targets_follow_v1_path_matches() -> None:
    assert target_matches("games.roblox.com/v1/games/browse", "glob", "games.roblox.com/v1/games/browse/x")
    assert target_matches("games.roblox.com/*/games", "glob", "Games.roblox.com/v1/games")
    assert not target_matches("games.roblox.com/v1", "glob", "users.roblox.com/v1")
    assert target_matches(r"^users\.roblox\.com/v1/users/\d+$", "regex", "users.roblox.com/v1/users/12")
