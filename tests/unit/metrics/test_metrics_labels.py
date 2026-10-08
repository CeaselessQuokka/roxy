"""Caller-supplied labels are scrubbed before they become metrics, Live rows, events or captures (finding F4).

A route word that is not id-shaped stays in the endpoint template as written, and the `Roblox-Id` header becomes the
place id as written; neither passes the log filter on its way to metrics.db, the Live feed or a capture. These
tests register a fake credential (with 24 character window matching, like the real one) and check that a piece of
it in the template, the host or the place id never reaches any stored or shown value, while ordinary labels are
stored exactly as v1 made them.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.core.redact import TOKEN_PREFIX, SecretRegistry
from roxy.metrics.capture import CaptureInput, decode_record
from roxy.metrics.live import live_entry
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent, scrub_labels
from roxy.metrics.templating import template_for

NAME = "test_f4_credential"


@pytest.fixture
def piece() -> Iterator[str]:
    """40 characters from the secret part of a registered fake credential."""
    credential = TOKEN_PREFIX + "F4TEST" + secrets.token_hex(100).upper()
    SecretRegistry.register(NAME, credential, match_substrings=True)
    try:
        yield credential[len(TOKEN_PREFIX) + 30 : len(TOKEN_PREFIX) + 70]
    finally:
        SecretRegistry.unregister(NAME)


def _clean(text: str, piece: str) -> bool:
    folded = text.lower()
    return all(piece[i : i + 24].lower() not in folded for i in range(len(piece) - 23))


def test_template_for_scrubs_a_piece_in_a_route_word(piece: str) -> None:
    template = template_for("games.roblox.com", f"/v1/x.{piece}?a=1")
    assert _clean(template, piece), template
    assert template.startswith("games.roblox.com/v1/")
    # An id-shaped segment was already a placeholder; ordinary templates keep v1's exact text.
    assert (
        template_for("users.roblox.com", "/v1/users/29371917/friends") == "users.roblox.com/v1/users/{userId}/friends"
    )
    assert template_for("games.roblox.com", "/v1/games/list") == "games.roblox.com/v1/games/list"


def test_scrub_labels_keeps_ordinary_events_as_they_are(make_event: Callable[..., OutcomeEvent]) -> None:
    ev = make_event()
    assert scrub_labels(ev) is ev  # nothing to scrub: the same object, so v1 values are stored unchanged


def test_scrub_labels_cleans_template_host_and_place(make_event: Callable[..., OutcomeEvent], piece: str) -> None:
    ev = make_event(endpoint_template=f"games.roblox.com/v1/x.{piece}", host=f"{piece.lower()}.roblox.com",
                    place_id=piece)  # fmt: skip
    clean = scrub_labels(ev)
    assert all(_clean(value, piece) for value in (clean.endpoint_template, clean.host, clean.place_id or ""))
    assert clean.request_id == ev.request_id
    assert clean.status == ev.status


def test_live_entry_scrubs_its_labels(make_event: Callable[..., OutcomeEvent], piece: str) -> None:
    ev = make_event(endpoint_template=f"games.roblox.com/v1/x.{piece}", host=f"{piece.lower()}.roblox.com",
                    place_id=piece, path=f"games.roblox.com/v1/x.{piece}", user_agent=f"Roblox/{piece}")  # fmt: skip
    entry = live_entry(ev)
    assert _clean(json.dumps(entry), piece), entry


async def test_recorder_stores_no_piece_anywhere(
    dbs: Any,
    settings_factory: Callable[..., Any],
    fake_clock: FakeClock,
    make_event: Callable[..., OutcomeEvent],
    presets: dict[str, Any],
    piece: str,
) -> None:
    """Every table the recorder writes (dimensions, rollups, clients, events, samples, 429 rows, captures) and the
    Live ring stay clean, for refused and served requests alike."""
    recorder = MetricsRecorder(dbs, settings_factory(capture_sample_served_pct=100), fake_clock)
    labels = {"endpoint_template": f"games.roblox.com/v1/x.{piece}", "host": "games.roblox.com", "place_id": piece}
    variants: list[dict[str, Any]] = [presets["refused"], {}]
    for fields in variants:
        ev = make_event(request_id=secrets.token_hex(13), **labels, **fields)
        capture = CaptureInput(request_id=ev.request_id, at_ms=ev.at_ms, place_id=piece, url=f"x/{piece}")
        assert recorder.record_outcome(ev, capture=capture) == ev.request_id
    recorder.record_event("custom", "warn", reason=f"r-{piece}", detail={"k": piece}, place=piece,
                          endpoint_template=f"t/{piece}")  # fmt: skip
    recorder.record_event("counter", "info", reason=piece, place=piece, aggregate=True)
    recorder.record_upstream_429(endpoint_template=f"games.roblox.com/v1/x.{piece}", host=f"{piece}.roblox.com",
                                 egress="direct")  # fmt: skip
    recorder.record_internal_call("probe", ok=True, endpoint=f"https://games.roblox.com/v1/x.{piece}?a=1")
    recorder.record_crawl("203.0.113.9", f"/robots.txt/{piece}")
    fake_clock.advance(120)  # close the minute, so aggregated events are written too
    await recorder.flush()

    def everything(conn: Any) -> list[str]:
        out: list[str] = []
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        for table in tables:
            for row in conn.execute(f"SELECT * FROM {table}"):  # table names come from sqlite_master
                for value in tuple(row):
                    if isinstance(value, bytes) and table == "captures":
                        out.append(json.dumps(decode_record(value)))
                    elif value is not None:
                        out.append(str(value))
        return out

    stored = dbs.metrics.read_sync(everything)
    assert any("games.roblox.com/v1/" in value for value in stored)  # not vacuous: the rows are there
    assert dbs.metrics.read_sync(lambda conn: conn.execute("SELECT count(*) FROM captures").fetchone()[0]) == 2
    leaks = [value[:120] for value in stored if not _clean(value, piece)]
    assert leaks == []
    assert _clean(json.dumps(recorder.live.snapshot()), piece)
