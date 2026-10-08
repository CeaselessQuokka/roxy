"""Security events: probe signatures (fix for v1 bug B19), rings, summaries and per-type caps (rows 51, 80, 97)."""

from __future__ import annotations

from typing import Any

import pytest

from roxy.metrics import security_events as se
from roxy.metrics.recorder import EventRecord, MetricsRecorder, write_events


@pytest.mark.parametrize(
    ("reason", "signature", "target"),
    [
        ('Invalid URL: "evil.example/a"', "Invalid URL", "evil.example/a"),
        ('Non-Roblox URL: "x.com/"', "Non-Roblox URL", "x.com/"),
        ("Invalid 2FA code", "Invalid 2FA code", ""),
        ("HTTP 404 via GET " + "/x" * 200, "HTTP 404 via GET", ("/x" * 200)[:200]),
        ("", "Unknown", ""),
    ],
)
def test_probe_signature(reason: str, signature: str, target: str) -> None:
    assert se.probe_signature(reason) == (signature, target)


def test_probe_detail_redacts_attacker_text() -> None:
    signature, detail = se.probe_detail("198.51.100.1", 'Invalid URL: "a/?token=abcdef123"', "curl", "/a?b=1")
    assert signature == "Invalid URL"
    assert "abcdef123" not in detail["target"]
    assert detail["path"] == "/a"
    assert detail["ip"] == "198.51.100.1"


def _events(dbs: Any, event_type: str, n: int, *, ip: str = "198.51.100.1", reason: str = "r") -> None:
    rows = [
        EventRecord(1_760_000_000_000 + i, event_type, "warn", reason, None, None, None, {"ip": ip}) for i in range(n)
    ]
    dbs.metrics.write_sync(lambda c: write_events(c, rows))


def test_caps_are_per_type(dbs: Any) -> None:
    _events(dbs, se.PROBE, 10)
    _events(dbs, se.LOGIN, 3)
    _events(dbs, "ban", 5)
    caps = {"max_exploit_records": 4, "max_login_records": 0, "max_crawl_records": 5, "max_throttle_records": 5}
    deleted = dbs.metrics.write_sync(lambda c: se.enforce_caps(c, caps.__getitem__))
    assert deleted == {se.PROBE: 6, se.LOGIN: 3}
    left = dbs.metrics.read_sync(
        lambda c: dict(c.execute("SELECT type, count(*) FROM events GROUP BY type").fetchall())
    )
    assert left == {"probe": 4, "ban": 5}
    newest = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT at_ms FROM events WHERE type='probe'")])
    assert min(newest) == 1_760_000_000_006  # the oldest went first


def test_ring_pages_newest_first_with_filters(dbs: Any) -> None:
    _events(dbs, se.PROBE, 5, ip="198.51.100.1", reason="A")
    _events(dbs, se.PROBE, 2, ip="198.51.100.2", reason="B")
    page = dbs.metrics.read_sync(lambda c: se.ring(c, se.PROBE, limit=3))
    assert page["total"] == 7
    assert [i["reason"] for i in page["items"]] == ["B", "B", "A"]
    by_ip = dbs.metrics.read_sync(lambda c: se.ring(c, se.PROBE, ip="198.51.100.1", limit=10, offset=4))
    assert by_ip["total"] == 5
    assert len(by_ip["items"]) == 1


def test_summaries(dbs: Any) -> None:
    _events(dbs, se.PROBE, 3, reason="A")
    rows = [EventRecord(1_760_000_100_000, se.PROBE, "warn", "B", None, None, None, {"aggregated": True}, count=9)]
    dbs.metrics.write_sync(lambda c: write_events(c, rows))
    summary = dbs.metrics.read_sync(lambda c: se.summary_by_reason(c, se.PROBE, 0, 2**53))
    assert [(s["reason"], s["count"]) for s in summary] == [("B", 9), ("A", 3)]
    _events(dbs, se.CRAWL, 2, ip="198.51.100.9")
    crawls = dbs.metrics.read_sync(lambda c: se.summary_by_ip(c, se.CRAWL, 0, 2**53))
    assert crawls[0]["ip"] == "198.51.100.9"
    assert crawls[0]["count"] == 2


async def test_login_events_via_recorder(recorder: MetricsRecorder) -> None:
    recorder.record_login("203.0.113.7", True, username="owner", method="totp")
    recorder.record_login("203.0.113.8", False)
    await recorder.flush()
    ring = recorder.dbs.metrics.read_sync(lambda c: se.ring(c, se.LOGIN))
    assert [(i["ip"], i["successful"]) for i in ring["items"]] == [("203.0.113.8", False), ("203.0.113.7", True)]
