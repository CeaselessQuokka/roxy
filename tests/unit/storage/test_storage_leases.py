"""Unit tests for roxy.storage.leases (single leases, epochs, counted slot leases)."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any

import pytest

from roxy.storage import leases


@pytest.fixture
def run(dbs) -> Callable[[Callable[[sqlite3.Connection], Any]], Any]:
    """Run a lease function inside one hot.db write transaction, like production callers do."""
    return dbs.hot.write_sync


def test_first_acquire_creates_epoch_one(run) -> None:
    grant = run(lambda c: leases.acquire(c, "leader", "a", 15_000, 1_000))
    assert grant == leases.LeaseGrant("leader", "a", 1, 16_000, True)
    assert run(lambda c: leases.holder_epoch(c, "leader")) == ("a", 1, 16_000)
    assert run(lambda c: leases.holder_epoch(c, "nothing")) is None


def test_valid_lease_is_exclusive_and_reacquire_keeps_epoch(run) -> None:
    run(lambda c: leases.acquire(c, "leader", "a", 15_000, 1_000))
    assert run(lambda c: leases.acquire(c, "leader", "b", 15_000, 5_000)) is None
    again = run(lambda c: leases.acquire(c, "leader", "a", 15_000, 5_000))
    assert again is not None
    assert again.epoch == 1
    assert not again.taken_over
    assert again.expires_ms == 20_000


def test_takeover_after_expiry_increments_epoch(run) -> None:
    run(lambda c: leases.acquire(c, "leader", "a", 15_000, 1_000))
    assert run(lambda c: leases.acquire(c, "leader", "b", 15_000, 15_999)) is None  # still valid
    grant = run(lambda c: leases.acquire(c, "leader", "b", 15_000, 16_000))  # expires_ms <= now: expired
    assert grant is not None
    assert grant.epoch == 2
    assert grant.taken_over
    # The old holder re-acquiring later is also a takeover with a new epoch.
    grant = run(lambda c: leases.acquire(c, "leader", "a", 15_000, 40_000))
    assert grant is not None
    assert grant.epoch == 3


def test_renew_rules(run) -> None:
    run(lambda c: leases.acquire(c, "leader", "a", 15_000, 0))
    assert run(lambda c: leases.renew(c, "leader", "a", 15_000, 5_000))
    assert run(lambda c: leases.holder_epoch(c, "leader")) == ("a", 1, 20_000)
    assert not run(lambda c: leases.renew(c, "leader", "b", 15_000, 6_000))
    assert not run(lambda c: leases.renew(c, "leader", "a", 15_000, 6_000, epoch=2))
    assert not run(lambda c: leases.renew(c, "leader", "a", 15_000, 20_000))  # expired: must acquire again
    with pytest.raises(ValueError):
        run(lambda c: leases.renew(c, "leader", "a", 0, 1))


def test_release_keeps_epoch_counting(run) -> None:
    run(lambda c: leases.acquire(c, "leader", "a", 15_000, 0))
    run(lambda c: leases.release(c, "leader", "b"))  # not the holder: no effect
    assert run(lambda c: leases.holder_epoch(c, "leader")) == ("a", 1, 15_000)
    run(lambda c: leases.release(c, "leader", "a"))
    assert run(lambda c: leases.holder_epoch(c, "leader")) == ("a", 1, 0)
    assert not run(lambda c: leases.is_valid(c, "leader", "a", 1))
    grant = run(lambda c: leases.acquire(c, "leader", "b", 15_000, 1))
    assert grant is not None
    assert grant.epoch == 2
    run(lambda c: leases.release(c, "leader", "b", delete=True))
    assert run(lambda c: leases.holder_epoch(c, "leader")) is None


def test_payload_is_stored(run) -> None:
    run(lambda c: leases.acquire(c, "sf:key", "w1", 1000, 0, payload_json='{"owner": "w1"}'))
    payload = run(lambda c: c.execute("SELECT payload_json FROM lease WHERE name = 'sf:key'").fetchone()[0])
    assert payload == '{"owner": "w1"}'


def test_slots_never_exceed_cap_and_expired_slots_are_reused(run) -> None:
    got = [run(lambda c, h=h: leases.acquire_slot(c, "tarpit:", h, 3, 10_000, 0)) for h in "abcd"]
    assert got == ["tarpit:0", "tarpit:1", "tarpit:2", None]
    assert run(lambda c: leases.count_slots(c, "tarpit:", 1)) == 3
    run(lambda c: leases.release(c, "tarpit:1", "b"))
    assert run(lambda c: leases.acquire_slot(c, "tarpit:", "d", 3, 10_000, 5)) == "tarpit:1"
    # Everyone's slot expires at 10_000 (d's at 10_005): new holders reuse the rows.
    later = [run(lambda c, h=h: leases.acquire_slot(c, "tarpit:", h, 3, 10_000, 10_005)) for h in "xyz"]
    assert sorted(s for s in later if s) == ["tarpit:0", "tarpit:1", "tarpit:2"]
    rows = run(lambda c: c.execute("SELECT count(*) FROM lease WHERE name LIKE 'tarpit:%'").fetchone()[0])
    assert rows == 3  # the number of rows is bounded by the cap


def test_lowering_the_cap_counts_higher_slots(run) -> None:
    for h in "abcd":
        run(lambda c, h=h: leases.acquire_slot(c, "tarpit:", h, 4, 10_000, 0))
    assert run(lambda c: leases.acquire_slot(c, "tarpit:", "e", 2, 10_000, 1)) is None
    assert run(lambda c: leases.acquire_slot(c, "tarpit:", "e", 0, 10_000, 1)) is None


def test_slot_prefixes_do_not_overlap_other_leases(run) -> None:
    run(lambda c: leases.acquire(c, "tarpit", "z", 10_000, 0))  # same text without the separator
    run(lambda c: leases.acquire(c, "tarpix:0", "z", 10_000, 0))
    assert run(lambda c: leases.count_slots(c, "tarpit:", 1)) == 0
    assert run(lambda c: leases.acquire_slot(c, "tarpit:", "a", 1, 10_000, 1)) == "tarpit:0"
