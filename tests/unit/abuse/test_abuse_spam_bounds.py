"""Bounds of the spam detectors' shared table (plan P9): per client, overall, and eviction no client can steer.

What this is
    Tests for the caller-chosen subjects of `roxy/abuse/spam.py` (places, enum templates, distributed
    template and User-Agent pairs): the per-client quota that folds extra values into `(other)`, the
    `MAX_SPAM_ROWS` cap with its eviction order, and the `MAX_ACTIVE_FLAGS` cap.

Why it exists
    Ingress review finding: `spam_windows` rows were keyed by values the caller chooses, for every request
    (refused ones included), with nothing capping the count, so one client added rows at request rate. The fix must
    not open a new hole: a client must not be able to push its own incriminating rows out with decoys.

How it works
    A real `SpamDetectors` over the test's hot.db, driven by `observe` and `flush` with a `FakeClock`; the caps are
    lowered with `monkeypatch` so the tests stay small.

What to read next
    `roxy/abuse/spam.py` (module docstring, "Bounds"), `tests/security/test_ingress_exhaustion.py`.
"""

from __future__ import annotations

from typing import Any

import pytest
from abuse_support import FakeSettings

from roxy.abuse import spam as spam_module
from roxy.abuse.spam import CHOSEN_WINDOW_S, MAX_CHOSEN_PER_CLIENT, OVERFLOW, SpamDetectors
from roxy.core.clock import FakeClock


def observe(spam: SpamDetectors, key: str, **fields: Any) -> None:
    values: dict[str, Any] = {
        "limit_key": key,
        "place_id": None,
        "template": "games.roblox.com/v1/games",
        "path": "/v1/games",
        "query": [],
        "user_agent": "Roblox/Linux",
        "refused": False,
        "probe": False,
        "auth": False,
        "game_server": False,
        "bypass": False,
    }
    values.update(fields)
    spam.observe(**values)


def subjects(dbs: Any) -> set[str]:
    return {str(r[0]) for r in dbs.hot.read_sync(lambda c: c.execute("SELECT subject FROM spam_windows").fetchall())}


async def test_places_beyond_the_quota_fold_into_other(dbs: Any, fake_clock: FakeClock) -> None:
    spam = SpamDetectors(FakeSettings(), dbs.hot, fake_clock)
    for n in range(MAX_CHOSEN_PER_CLIENT + 5):
        observe(spam, "203.0.113.7", place_id=str(1000 + n))
    await spam.flush()
    places = {s for s in subjects(dbs) if s.startswith("req|place:")}
    assert len(places) == MAX_CHOSEN_PER_CLIENT + 1
    assert f"req|place:{OVERFLOW}" in places
    assert spam.folded == 5
    # Another client has its own quota; and after the window a client gets a fresh one.
    observe(spam, "198.51.100.2", place_id="5000")
    fake_clock.advance(CHOSEN_WINDOW_S)
    observe(spam, "203.0.113.7", place_id="6000")
    await spam.flush()
    assert {"req|place:5000", "req|place:6000"} <= subjects(dbs)


async def test_a_known_value_keeps_counting_after_the_quota_is_spent(dbs: Any, fake_clock: FakeClock) -> None:
    spam = SpamDetectors(FakeSettings(), dbs.hot, fake_clock)
    for n in range(MAX_CHOSEN_PER_CLIENT + 3):
        observe(spam, "203.0.113.7", place_id=str(n))
    observe(spam, "203.0.113.7", place_id="0")  # the client's own place: still counted under its own subject
    await spam.flush()

    def count(conn: Any) -> str:
        return str(conn.execute("SELECT buckets_json FROM spam_windows WHERE subject = 'req|place:0'").fetchone()[0])

    assert '":2' in dbs.hot.read_sync(count)


async def test_the_table_is_capped_and_decoys_go_before_signal_rows(
    dbs: Any, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Over `MAX_SPAM_ROWS` the stalest caller-chosen rows go first. A client's incriminating `auth|ip:` row, even
    an older one, survives a flood of decoy rows from many clients (and from itself)."""
    monkeypatch.setattr(spam_module, "MAX_SPAM_ROWS", 40)
    monkeypatch.setattr(spam_module, "EVICT_BATCH", 5)
    spam = SpamDetectors(FakeSettings(), dbs.hot, fake_clock)
    observe(spam, "203.0.113.7", auth=True)  # two auth smuggling attempts: one short of SPAM-AUTH (3 per hour)
    observe(spam, "203.0.113.7", auth=True)
    await spam.flush()
    fake_clock.advance(120)
    for client in range(30):  # decoys: many clients, each with as many place ids as its quota allows
        for n in range(MAX_CHOSEN_PER_CLIENT):
            observe(spam, f"198.51.100.{client}", place_id=f"{client}-{n}")
        observe(spam, "203.0.113.7", place_id=f"self-{client}")  # and the client itself
        await spam.flush()
        fake_clock.advance(1)
    rows = subjects(dbs)
    counters = {s for s in rows if not s.startswith("flag|")}
    assert len(counters) <= 40
    assert spam.evicted > 0
    assert "auth|ip:203.0.113.7" in rows  # the signal row that leads to a ban was never pushed out
    observe(spam, "203.0.113.7", auth=True)  # the third attempt still completes the detection
    detections = await spam.flush()
    assert [d.detector for d in detections if d.subject == "ip:203.0.113.7"] == ["auth"]


async def test_active_flags_are_capped(dbs: Any, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(spam_module, "MAX_ACTIVE_FLAGS", 2)
    spam = SpamDetectors(FakeSettings({"spam_probe_action": "tarpit"}), dbs.hot, fake_clock)
    for client in range(5):
        for _ in range(5):  # SPAM-PROBE fires at 5 probes
            observe(spam, f"198.51.100.{client}", probe=True)
    detections = await spam.flush()
    flags = {s for s in subjects(dbs) if s.startswith("flag|")}
    assert len(flags) == 2
    assert len(detections) == 2
