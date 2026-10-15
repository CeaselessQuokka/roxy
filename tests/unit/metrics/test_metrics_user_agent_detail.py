"""The User-Agent drill-down (gap G1), address headers never recorded (gap G5) and faithful header text (gap G12).

What this is
    Unit tests of `metrics/fingerprints.py` and `metrics/read_security.py` for metrics.db schema 8: each User-Agent
    row keeps where its newest request went, who sent it and which header names it carried (v1
    `GET /admin/fingerprints/user_agent`, `.remake/v1notes/dashboard.md` 4.21); headers that carry client addresses
    have their names counted and their values never kept; header text is recorded as the caller wrote it.

Why it exists
    The drill-down is bounded (plan P9), scrubbed (plan 9.15), merges across workers to the newest request, and never
    stores a header value; the privacy rule holds whatever the ignore list says.

What to read next
    `roxy/metrics/fingerprints.py`, `roxy/metrics/read_security.py`, then
    `tests/unit/storage/test_storage_migrate_upgrade.py`.
"""

from __future__ import annotations

import json
from typing import Any

from roxy.core.redact import TOKEN_PREFIX
from roxy.metrics import fingerprints as fp
from roxy.metrics import read_security

NOW = 1_760_000_000
UA = "Roblox/WinInet"


def _write(dbs: Any, agg: fp.FingerprintAggregator, key: bytes | None = None) -> None:
    items = agg.drain()
    dbs.metrics.write_sync(lambda conn: fp.write_fingerprints(conn, items, value_cap=500, hash_key=key))


def _detail(dbs: Any, agent: str = UA) -> dict[str, Any]:
    found = dbs.metrics.read_sync(lambda conn: read_security.user_agent_detail(conn, fp.row_hash(agent)))
    assert found is not None
    return found


def test_the_newest_request_of_each_user_agent_is_kept(dbs: Any) -> None:
    agg = fp.FingerprintAggregator()
    first = fp.RequestDetail("games.roblox.com/v1/games", "203.0.113.1", ["Host", "Accept"])
    newest = fp.RequestDetail("users.roblox.com/v1/users/1", "203.0.113.2", ["Host", "User-Agent", "Roblox-Id"])
    agg.add([("Host", "x")], UA, NOW, detail=first)
    agg.add([("Host", "x")], UA, NOW + 5, detail=newest)
    _write(dbs, agg)
    found = _detail(dbs)
    assert found["count"] == 2
    assert found["has_detail"]
    assert (found["last_path"], found["last_caller"], found["last_detail_at"]) == (
        "users.roblox.com/v1/users/1",
        "203.0.113.2",
        NOW + 5,
    )
    assert found["last_header_names"] == ["host", "user-agent", "roblox-id"]  # in the order sent, lowercased


def test_an_older_flush_never_replaces_a_newer_detail(dbs: Any) -> None:
    """Two workers flush in either order: the row keeps the newest request (the upsert compares the times)."""
    newer = fp.FingerprintAggregator()
    newer.add([], UA, NOW + 60, detail=fp.RequestDetail("a.roblox.com/new", "203.0.113.9", ["Host"]))
    _write(dbs, newer)
    older = fp.FingerprintAggregator()
    older.add([], UA, NOW, detail=fp.RequestDetail("a.roblox.com/old", "203.0.113.8", ["Accept"]))
    _write(dbs, older)
    without = fp.FingerprintAggregator()  # a flush without a detail (a previous release's writer) keeps it too
    without.add([], UA, NOW + 120)
    _write(dbs, without)
    found = _detail(dbs)
    assert found["count"] == 3
    assert found["last_seen"] == NOW + 120
    assert (found["last_path"], found["last_caller"], found["last_detail_at"]) == (
        "a.roblox.com/new",
        "203.0.113.9",
        NOW + 60,
    )


def _credential_piece() -> str:
    """Register a fake credential and return 40 characters of its secret part (a valid HTTP token)."""
    import secrets

    from roxy.core.redact import SecretRegistry

    credential = TOKEN_PREFIX + "FAKE" + secrets.token_hex(60).upper()
    SecretRegistry.register("roblox_credential", credential)
    return credential[len(TOKEN_PREFIX) + 20 : len(TOKEN_PREFIX) + 60]


def test_the_detail_is_bounded_and_scrubbed(dbs: Any) -> None:
    secret_name = "x-" + _credential_piece()  # a name holding a credential piece is stored as its hash
    names = [f"x-h{i}" for i in range(200)]
    path = "games.roblox.com/" + TOKEN_PREFIX + "ABCDEF" * 20 + "/" + "p" * 500
    agg = fp.FingerprintAggregator()
    agg.add([], UA, NOW, detail=fp.RequestDetail(path, "2001:db8::1" + "0" * 100, [secret_name, *names]))
    _write(dbs, agg, key=b"k" * 32)
    found = _detail(dbs)
    assert TOKEN_PREFIX not in (found["last_path"] or "")
    assert "ABCDEF" * 3 not in (found["last_path"] or "")
    assert len(found["last_path"]) <= fp.MAX_LAST_PATH_CHARS
    assert len(found["last_caller"]) == fp.MAX_LAST_CALLER_CHARS
    stored = found["last_header_names"]
    assert len(stored) == fp.MAX_LAST_HEADER_NAMES
    assert stored[0].startswith("fp:")
    assert secret_name[2:].lower() not in json.dumps(found).lower()
    assert stored[1:] == names[: fp.MAX_LAST_HEADER_NAMES - 1]


def test_header_names_only_never_values(dbs: Any) -> None:
    agg = fp.FingerprintAggregator()
    pairs = [("Authorization", "Bearer very-secret-value"), ("X-Thing", "plain-value")]
    agg.add(pairs, UA, NOW, detail=fp.RequestDetail("a.roblox.com/x", "203.0.113.1", [n for n, _v in pairs]))
    _write(dbs, agg)
    found = _detail(dbs)
    text = json.dumps(found)
    assert "very-secret-value" not in text
    assert "plain-value" not in text
    assert found["last_header_names"] == ["authorization", "x-thing"]


def test_a_user_agent_without_a_detail_says_so(dbs: Any) -> None:
    agg = fp.FingerprintAggregator()
    agg.add([], UA, NOW)
    _write(dbs, agg)
    found = _detail(dbs)
    assert not found["has_detail"]
    assert (found["last_path"], found["last_caller"], found["last_header_names"]) == (None, None, [])
    missing = dbs.metrics.read_sync(lambda conn: read_security.user_agent_detail(conn, "0" * 32))
    assert missing is None


def test_the_user_agent_table_rows_carry_their_key_and_detail(dbs: Any) -> None:
    agg = fp.FingerprintAggregator()
    agg.add([], UA, NOW, detail=fp.RequestDetail("a.roblox.com/x", "203.0.113.1", ["Host"]))
    agg.add([], "Other/1", NOW)
    _write(dbs, agg)
    rows = dbs.metrics.read_sync(lambda conn: read_security.user_agents(conn, sort="user_agent", descending=False))
    by_agent = {row["user_agent"]: row for row in rows["rows"]}
    assert by_agent[UA]["ua_hash"] == fp.row_hash(UA)
    assert by_agent[UA]["last_header_names"] == ["host"]
    assert by_agent["Other/1"]["last_detail_at"] is None


def test_the_detail_memory_is_bounded_with_the_user_agents(monkeypatch: Any) -> None:
    monkeypatch.setattr(fp, "MAX_PENDING_USER_AGENTS", 3)
    agg = fp.FingerprintAggregator()
    for i in range(10):
        agg.add([], f"UA{i}", NOW, detail=fp.RequestDetail("a.roblox.com/x", "203.0.113.1", ["Host"]))
    items = agg.drain()
    assert len([item for item in items if item.kind == "u"]) == 3
    assert all(item.detail is not None for item in items if item.kind == "u")
    assert agg.dropped == 7
    assert agg.drain() == []


# ------------------------------------------------------------------------------------------- G5: address headers


def test_address_header_values_are_never_kept_but_their_names_are_counted(dbs: Any) -> None:
    agg = fp.FingerprintAggregator()
    pairs = [(name.upper(), "203.0.113.77") for name in sorted(fp.ADDRESS_HEADERS)] + [("X-Thing", "1")]
    agg.add(pairs, UA, NOW)  # no ignore list at all: the rule holds anyway
    _write(dbs, agg)
    names = dbs.metrics.read_sync(
        lambda c: {r[0]: r[1] for r in c.execute("SELECT name, count FROM fingerprint_headers")}
    )
    assert set(fp.ADDRESS_HEADERS) <= set(names)
    values = dbs.metrics.read_sync(
        lambda c: [tuple(r) for r in c.execute("SELECT name, value FROM fingerprint_values")]
    )
    assert values == [("x-thing", "1")]
    assert {"x-forwarded-for", "x-real-ip", "forwarded", "true-client-ip", "cf-connecting-ip", "x-client-ip",
            "x-cluster-client-ip"} <= fp.ADDRESS_HEADERS  # fmt: skip


def test_the_writer_skips_an_address_value_even_from_an_old_item(dbs: Any) -> None:
    item = fp.FingerprintItem("v", "x-forwarded-for\x00fp:0123456789ab", 1, NOW, NOW)
    dbs.metrics.write_sync(lambda conn: fp.write_fingerprints(conn, [item], value_cap=500))
    count = dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM fingerprint_values").fetchone()[0])
    assert count == 0


def test_clear_address_values_deletes_what_a_previous_release_stored(dbs: Any) -> None:
    def old_rows(conn: Any) -> None:
        for name in ("x-forwarded-for", "x-real-ip", "x-thing"):
            conn.execute(
                "INSERT INTO fingerprint_values (value_hash, name, value, count, first_seen, last_seen) "
                "VALUES (?, ?, 'fp:0123456789ab', 1, 1, 1)",
                (fp.row_hash(name, "v"), name),
            )

    dbs.metrics.write_sync(old_rows)
    removed = dbs.metrics.write_sync(fp.clear_address_values)
    assert removed == 2
    left = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT name FROM fingerprint_values")])
    assert left == ["x-thing"]


# ------------------------------------------------------------------------------------------- G12: header text


def test_header_values_and_user_agents_are_recorded_as_the_caller_wrote_them(dbs: Any) -> None:
    sent = "Röblox/日本"  # UTF-8 on the wire
    as_latin1 = sent.encode("utf-8").decode("latin-1")  # what the server hands over
    broken = (b"Bad\xffAgent").decode("latin-1")  # not UTF-8 at all
    agg = fp.FingerprintAggregator()
    agg.add([("X-Name", as_latin1)], as_latin1, NOW)
    agg.add([], broken, NOW)
    _write(dbs, agg)
    agents = dbs.metrics.read_sync(
        lambda c: {r[0] for r in c.execute("SELECT user_agent FROM fingerprint_user_agents")}
    )
    assert agents == {sent, "Bad\\xffAgent"}
    value = dbs.metrics.read_sync(lambda c: c.execute("SELECT value FROM fingerprint_values").fetchone()[0])
    assert value == sent
