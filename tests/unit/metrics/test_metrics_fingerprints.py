"""Fingerprints: sensitive value hashing, ignored headers, per-header caps, central auto-ignore (rows 79, 134)."""

from __future__ import annotations

from typing import Any

import pytest

from roxy.core.redact import TOKEN_PREFIX
from roxy.metrics import fingerprints as fp

NOW = 1_760_000_000


@pytest.mark.parametrize(
    ("name", "value", "hashed"),
    [
        ("cookie", "a=b", True),
        ("authorization", "Bearer x", True),
        ("x-csrf-token", "t", True),
        ("x-roblox-token", "t", True),
        ("x-api-key", "k", True),
        ("x-forwarded-for", "203.0.113.5", True),
        ("x-real-ip", "203.0.113.5", True),
        ("user-agent", "Roblox/WinInet", False),
        ("roblox-id", "123", False),
    ],
)
def test_value_for_storage(name: str, value: str, hashed: bool) -> None:
    stored = fp.value_for_storage(name, value)
    assert stored.startswith("fp:") is hashed
    if hashed:
        assert value not in stored
        assert len(stored) == 15
    assert fp.value_for_storage(name, "") == fp.EMPTY_VALUE


def test_v1_hash_without_key_and_keyed_hash_with_key() -> None:
    import hashlib

    assert fp.value_for_storage("cookie", "abc") == "fp:" + hashlib.sha256(b"abc").hexdigest()[:12]
    assert fp.value_for_storage("cookie", "abc", b"k" * 32) != fp.value_for_storage("cookie", "abc")


def test_plain_values_are_cut_at_200() -> None:
    assert len(fp.value_for_storage("x-thing", "v" * 500)) == 200


def _write(dbs: Any, agg: fp.FingerprintAggregator, cap: int = 500) -> None:
    items = agg.drain()
    dbs.metrics.write_sync(lambda conn: fp.write_fingerprints(conn, items, value_cap=cap))


def test_ignored_headers_count_names_but_not_values(dbs: Any) -> None:
    agg = fp.FingerprintAggregator()
    agg.add([("Traceparent", "00-abc"), ("X-Thing", "1")], "UA", NOW, ignored=frozenset({"traceparent"}))
    _write(dbs, agg)
    names = dbs.metrics.read_sync(
        lambda c: [tuple(r) for r in c.execute("SELECT name, count FROM fingerprint_headers ORDER BY 1")]
    )
    assert names == [("traceparent", 1), ("x-thing", 1)]
    values = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT name FROM fingerprint_values")])
    assert values == ["x-thing"]


def test_secret_shaped_plain_values_are_stored_hashed(dbs: Any) -> None:
    agg = fp.FingerprintAggregator()
    agg.add([("X-Custom", TOKEN_PREFIX + "ABCDEF" * 10)], TOKEN_PREFIX + "x", NOW)
    _write(dbs, agg)
    stored = dbs.metrics.read_sync(lambda c: c.execute("SELECT value FROM fingerprint_values").fetchone()[0])
    assert stored.startswith("fp:")
    ua = dbs.metrics.read_sync(lambda c: c.execute("SELECT user_agent FROM fingerprint_user_agents").fetchone()[0])
    assert "WARNING" not in ua


def test_counts_add_up_across_workers_and_values_are_capped_per_header(dbs: Any) -> None:
    worker_a, worker_b = fp.FingerprintAggregator(), fp.FingerprintAggregator()
    for i in range(6):
        worker_a.add([("X-Id", f"v{i}"), ("X-Shared", "same")], "UA", NOW + i)
        worker_b.add([("X-Id", f"v{i}"), ("X-Shared", "same")], "UA", NOW + 100 + i)
    _write(dbs, worker_a, cap=4)
    _write(dbs, worker_b, cap=4)
    shared = dbs.metrics.read_sync(
        lambda c: tuple(
            c.execute("SELECT count, first_seen, last_seen FROM fingerprint_values WHERE name = 'x-shared'").fetchone()
        )
    )
    assert shared == (12, NOW, NOW + 105)
    per_header = dbs.metrics.read_sync(
        lambda c: c.execute("SELECT count(*) FROM fingerprint_values WHERE name = 'x-id'").fetchone()[0]
    )
    assert per_header == 4
    ua = dbs.metrics.read_sync(lambda c: c.execute("SELECT count FROM fingerprint_user_agents").fetchone()[0])
    assert ua == 12


def test_pending_maps_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fp, "MAX_PENDING_VALUES", 3)
    agg = fp.FingerprintAggregator()
    agg.add([("X-Id", str(i)) for i in range(10)], "UA", NOW)
    assert agg.dropped == 7


def test_auto_ignore_is_central_and_not_double_counted(dbs: Any) -> None:
    """v1 bug B22: two workers counted the same values twice. Here distinct values come from the shared table."""
    worker_a, worker_b = fp.FingerprintAggregator(), fp.FingerprintAggregator()
    for i in range(600):
        worker_a.add([("X-Request-Id", f"id-{i}"), ("X-Mode", "fast")], "UA", NOW)
        worker_b.add([("X-Mode", "slow")], "UA", NOW)
    _write(dbs, worker_a, cap=500)
    _write(dbs, worker_b, cap=500)
    found = dbs.metrics.read_sync(lambda c: fp.auto_ignore_candidates(c, value_cap=500))
    assert [c.name for c in found] == ["x-request-id"]
    assert found[0].note == "auto: 500 distinct values in 600 requests"
    assert dbs.metrics.read_sync(lambda c: fp.auto_ignore_candidates(c, value_cap=500, ignored=["X-Request-Id"])) == []
    assert dbs.metrics.write_sync(lambda c: fp.clear_values(c, "X-Request-Id")) == 500


def test_auto_ignore_needs_five_hundred_requests(dbs: Any) -> None:
    agg = fp.FingerprintAggregator()
    for i in range(499):
        agg.add([("X-Rare", f"u{i}")], "UA", NOW)
    _write(dbs, agg, cap=100)
    assert dbs.metrics.read_sync(lambda c: fp.auto_ignore_candidates(c, value_cap=100)) == []


# --- header names (finding cred-7) -------------------------------------------------------------------------------


def _credential_piece() -> str:
    """Register a fake credential and return 40 characters of its secret part (a valid HTTP token)."""
    import secrets

    from roxy.core.redact import SecretRegistry

    credential = TOKEN_PREFIX + "FAKE" + secrets.token_hex(60).upper()
    SecretRegistry.register("roblox_credential", credential)
    return credential[len(TOKEN_PREFIX) + 20 : len(TOKEN_PREFIX) + 60]


def test_a_secret_shaped_header_name_is_stored_as_its_hash(dbs: Any) -> None:
    """A header NAME is caller text: one holding a credential piece is stored as `fp:` plus its keyed hash, and its
    values only as hashes; ordinary names are lowercased and kept."""
    piece = _credential_piece()
    key = b"k" * 32
    agg = fp.FingerprintAggregator(key)
    secret_name = f"X-{piece}"
    agg.add([(secret_name, "plain-value"), ("Accept", "*/*")], "UA", NOW)
    agg.add([(secret_name.lower(), "other")], "UA", NOW)  # the same name in other case: the same hash
    _write(dbs, agg)
    names = dbs.metrics.read_sync(
        lambda c: {str(r[0]): int(r[1]) for r in c.execute("SELECT name, count FROM fingerprint_headers")}
    )
    hidden = fp.value_hash_text(secret_name.lower(), key)
    assert names == {"accept": 1, hidden: 2}
    values = dbs.metrics.read_sync(
        lambda c: [(str(r[0]), str(r[1])) for r in c.execute("SELECT name, value FROM fingerprint_values")]
    )
    assert ("accept", "*/*") in values
    assert {value for name, value in values if name == hidden} == {
        fp.value_hash_text("plain-value", key),
        fp.value_hash_text("other", key),
    }
    assert piece.lower() not in (repr(names) + repr(values)).lower()


def test_a_long_name_is_judged_before_it_is_cut() -> None:
    """A credential piece that starts before character 120 and ends after it is still found (judged whole)."""
    piece = _credential_piece()
    stored, hidden = fp.name_for_storage("x-" + "a" * 100 + piece)
    assert hidden
    assert stored.startswith("fp:")
    plain, hidden_plain = fp.name_for_storage("X-" + "b" * 200)
    assert not hidden_plain
    assert plain == ("x-" + "b" * 200)[: fp.MAX_NAME_CHARS]
