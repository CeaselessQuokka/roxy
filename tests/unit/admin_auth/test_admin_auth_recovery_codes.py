"""Recovery codes (plan 9.5): 10 codes, unique lookup ids, forgiving input, hashed at rest, single use."""

from __future__ import annotations

from typing import Any

from roxy.admin.auth import recovery_codes, users
from roxy.admin.auth.testing import fast_hasher


def test_generate_ten_codes_with_unique_ids() -> None:
    codes = recovery_codes.generate()
    assert len(codes) == 10
    assert len({code[:4] for code in codes}) == 10
    for code in codes:
        assert len(code) == 19
        assert code.count("-") == 3
        assert recovery_codes.normalize(code) == code.replace("-", "")


def test_normalize_is_forgiving_but_strict_about_length() -> None:
    assert recovery_codes.normalize("abcd efgh jkmn pqrs") == "ABCDEFGHJKMNPQRS"
    assert recovery_codes.normalize("0O1I-L000-0000-0000") == "0011100000000000"
    assert recovery_codes.normalize("ABCD-EFGH-JKMN") is None
    assert recovery_codes.normalize("ABCD-EFGH-JKMN-PQRU") is None  # U is not in the alphabet
    assert recovery_codes.normalize("x" * 100) is None


def test_loads_tolerates_damage() -> None:
    assert recovery_codes.loads(None) == []
    assert recovery_codes.loads("not json") == []
    assert recovery_codes.loads('{"a": 1}') == []
    assert recovery_codes.loads('[{"id": 1}]') == []


def test_mark_used_is_compare_and_set(dbs: Any) -> None:
    hasher = fast_hasher()
    codes = recovery_codes.generate()
    entries = recovery_codes.hash_codes_sync(hasher, codes)
    assert all(
        hasher.verify_sync(e.hash, recovery_codes.normalize(c) or "") for e, c in zip(entries, codes, strict=True)
    )

    def setup(conn: Any) -> int:
        user_id = users.insert_user(conn, username="owner", password_hash="x", now=1)
        users.set_recovery_codes(conn, user_id, recovery_codes.dumps(entries))
        return user_id

    user_id = dbs.control.write_sync(setup)
    first = entries[0]
    assert dbs.control.write_sync(lambda c: recovery_codes.mark_used(c, user_id, first.id, first.hash, 10)) == 9
    assert dbs.control.write_sync(lambda c: recovery_codes.mark_used(c, user_id, first.id, first.hash, 11)) is None
    stored = dbs.control.read_sync(lambda c: users.get_by_id(c, user_id))
    loaded = recovery_codes.loads(stored.recovery_codes_hash_json)
    assert recovery_codes.remaining(loaded) == 9
    assert recovery_codes.find_entry(loaded, recovery_codes.normalize(codes[0]) or "") is None
    assert recovery_codes.find_entry(loaded, recovery_codes.normalize(codes[1]) or "") is not None
    # The plain codes are nowhere in the stored JSON.
    assert not any(code.replace("-", "") in (stored.recovery_codes_hash_json or "") for code in codes)
