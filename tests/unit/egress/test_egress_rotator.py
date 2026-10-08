"""The rotator pool: gateway URL, sessions, exit IPs, health parking and the byte budget (plan 8, rows 30 to 33).

What this is
    Unit tests for `roxy.egress.rotator`: URL parsing and masking, session modes and the username template, the
    bounded LRU of session clients, the exit IP probe (v1 parity plus the B11 fix), the fleet-wide failure streak,
    the quota hard stop and daily cap, and the audited URL replace and revert.

Why it exists
    The rotator costs money per byte and must never hold the credential. These tests pin the bounds (sessions,
    recent IPs), the fleet-wide rules (C6), and that the URL's password never shows.

How it works
    A fake client factory records which proxy URL each session client got and whether it was closed. Usage rows
    are written straight into the test metrics.db.

What to read next
    `src/roxy/egress/rotator.py`.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Any

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.core.clock import SYSTEM_CLOCK, FakeClock
from roxy.core.reasons import Egress
from roxy.core.redact import masked_url, redact_text
from roxy.egress.accounting import EgressUsage
from roxy.egress.crypto import load_encryption_key
from roxy.egress.errors import UpstreamTimeout
from roxy.egress.events import EventSink
from roxy.egress.models import EgressResponse, OutboundRequest
from roxy.egress.rotator import (
    PER_REQUEST,
    STICKY,
    STICKY_UNTIL_429,
    RotatorPool,
    RotatorStateError,
    cycle_start_for,
    mask_ip,
    parse_exit_ip,
    parse_proxy_url,
    usage_since,
)

ADMIN = Actor("admin", "owner", "127.0.0.1")
TEMPLATE = "{user}-sessid-{session}-cr-{country}"


class FakeClient:
    def __init__(self, url: str, session_id: str, keepalive: bool) -> None:
        self.url, self.session_id, self.keepalive = url, session_id, keepalive
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class Notifier:
    def __init__(self) -> None:
        self.alerts: list[Any] = []

    def send(self, alert: Any) -> None:
        self.alerts.append(alert)


def make_pool(
    env: Any,
    dbs: Any,
    settings: Any,
    *,
    clock: Any = SYSTEM_CLOCK,
    notifier: Notifier | None = None,
    override_proxy: str | None = None,
    echo: str = "http://127.0.0.1:9/ip",
) -> tuple[RotatorPool, list[FakeClient]]:
    made: list[FakeClient] = []

    def factory(url: str, session_id: str, keepalive: bool) -> FakeClient:
        client = FakeClient(url, session_id, keepalive)
        made.append(client)
        return client

    pool = RotatorPool(
        credentials_dir=env.credentials_dir,
        dbs=dbs,
        settings=settings,
        clock=clock,
        echo_url=echo,
        encryption_key=load_encryption_key(env.credentials_dir),
        client_factory=factory,
        events=EventSink(lambda: notifier, lambda: None),
        override_proxy=override_proxy,
    )
    return pool, made


def test_proxy_url_parsing_and_masking_parity() -> None:
    assert masked_url("http://user:pass@gw.example.net:823") == "http://gw.example.net:823"
    assert masked_url("http://gw.example.net:823") == "http://gw.example.net:823"
    assert masked_url("socks5://u:p@h.example.net:1080") == "socks5://h.example.net:1080"
    assert "ss@" not in masked_url("http://user:p@ss@gw.example.net:823")  # v1 leaked the tail (B10)
    endpoint = parse_proxy_url("http://us%3Aer:p%40ss@gw.example.net:823")
    assert (endpoint.username, endpoint.password, endpoint.host, endpoint.port) == (
        "us:er",
        "p@ss",
        "gw.example.net",
        823,
    )
    assert endpoint.render("x") == "http://x:p%40ss@gw.example.net:823"
    for bad in ("gw.example.net:823", "ftp://h:1", "http://h", "http://h:1/path", "http://h:1 x", ""):
        with pytest.raises(ValueError):
            parse_proxy_url(bad)


async def test_bootstrap_url_is_masked_and_registered(
    env: Any, dbs: Any, settings: Any, fake_secrets: dict[str, str]
) -> None:
    pool, _ = make_pool(env, dbs, settings)
    await pool.start()
    url = fake_secrets["rotator_url"]
    password = parse_proxy_url(url).password
    assert pool.configured()
    assert pool.url_source() == "bootstrap"
    assert pool.masked_url() == "http://127.0.0.1:9"
    assert password not in pool.masked_url()
    assert password not in redact_text(f"proxy is {url} and password {password}")


async def test_session_modes_and_template(env: Any, dbs: Any, settings: Any) -> None:
    clock = FakeClock(1_760_000_000.0)
    pool, _ = make_pool(env, dbs, settings, clock=clock)
    await pool.start()
    assert pool.effective_mode() == PER_REQUEST  # the default mode needs the template
    assert pool.session_for() != pool.session_for()
    settings.set("rotator_session_username_template", TEMPLATE)
    settings.set("rotator_country", "us")
    assert pool.effective_mode() == STICKY_UNTIL_429
    sid = pool.session_for()
    assert pool.session_for() == sid
    rendered = pool.proxy_url_for(sid)
    endpoint = parse_proxy_url(rendered)
    assert endpoint.username == f"fakeuser-sessid-{sid}-cr-us"
    assert endpoint.host == "127.0.0.1"
    nxt = pool.rotate(sid, "429")
    assert nxt != sid
    assert pool.session_for() == nxt
    settings.set("rotator_session_mode", STICKY)
    settings.set("rotator_sticky_seconds", 300)
    current = pool.session_for()
    clock.advance(299)
    assert pool.session_for() == current
    clock.advance(2)
    assert pool.session_for() != current
    settings.set("rotator_session_mode", "bogus")
    assert pool.effective_mode() == PER_REQUEST


async def test_sticky_clients_live_in_a_bounded_lru(env: Any, dbs: Any, settings: Any) -> None:
    settings.set("rotator_session_username_template", TEMPLATE)
    settings.set("rotator_max_sessions", 2)
    pool, made = make_pool(env, dbs, settings)
    await pool.start()
    busy = await pool.acquire("s1")  # stays in flight
    for sid in ("s2", "s3"):
        lease = await pool.acquire(sid)
        await pool.release(lease)
    await asyncio.sleep(0.01)
    assert pool.session_count() == 2
    first = next(client for client in made if client.session_id == "s1")
    assert not first.closed  # evicted while a request still uses it
    await pool.release(busy)
    await asyncio.sleep(0.01)
    assert first.closed
    again = await pool.acquire("s3")
    assert again.client is next(client for client in made if client.session_id == "s3")
    assert all(client.keepalive for client in made)
    await pool.release(again)
    await pool.aclose()
    assert all(client.closed for client in made)


async def test_per_request_mode_shares_one_client_without_keepalive(env: Any, dbs: Any, settings: Any) -> None:
    pool, made = make_pool(env, dbs, settings)
    await pool.start()
    leases = [await pool.acquire(None) for _ in range(3)]
    assert len(made) == 1
    assert made[0].keepalive is False
    assert len({lease.session_id for lease in leases}) == 3  # each request still gets its own header profile
    for lease in leases:
        await pool.release(lease)
    await pool.replace_url("http://other:secretpw1@127.0.0.1:10", ADMIN)
    await asyncio.sleep(0.01)
    assert made[0].closed
    lease = await pool.acquire(None)
    assert len(made) == 2
    assert "127.0.0.1:10" in made[1].url
    await pool.release(lease)


def echo(status: int, body: bytes) -> EgressResponse:
    return EgressResponse(status, httpx.Headers(), body, 1.0, 10, 10, Egress.ROTATOR, "s", "HTTP/1.1")


@pytest.mark.parametrize(
    ("answer", "ip", "error"),
    [
        (echo(200, b'{"ip": "203.0.113.7"}'), "203.0.113.7", ""),
        (echo(200, b"198.51.100.3\n"), "198.51.100.3", ""),
        (echo(200, b'["203.0.113.7"]'), "", "IP-echo returned JSON without an ip field"),
        (echo(200, b'{"ip": null}'), "", "IP-echo response had no IP"),
        (echo(200, b"<html>not an ip</html>"), "", "IP-echo response was not an IP address"),
        (echo(503, b"busy"), "", "IP-echo returned HTTP 503"),
    ],
)
async def test_exit_ip_probe_parsing(
    env: Any, dbs: Any, settings: Any, answer: EgressResponse, ip: str, error: str
) -> None:
    pool, _ = make_pool(env, dbs, settings)
    await pool.start()
    sent: list[OutboundRequest] = []

    async def sender(out: OutboundRequest) -> EgressResponse:
        sent.append(out)
        return answer

    pool.set_sender(sender)
    result = await pool.exit_ip_probe()
    assert (result.exit_ip, result.error) == (ip, error)
    assert sent[0].url == "http://127.0.0.1:9/ip"
    assert sent[0].purpose == "exit_ip_probe"
    assert sent[0].timeout.read == 10.0


async def test_exit_ip_probe_errors_and_recent_ips(env: Any, dbs: Any, settings: Any) -> None:
    pool, _ = make_pool(env, dbs, settings)
    await pool.start()
    settings.set("rotator_recent_ips", 2)
    answers = iter(["203.0.113.1", "203.0.113.2", "2001:db8::5"])

    async def sender(out: OutboundRequest) -> EgressResponse:
        return echo(200, next(answers).encode())

    pool.set_sender(sender)
    for _ in range(3):
        assert (await pool.exit_ip_probe()).exit_ip
    shown = pool.recent_exit_ips()
    assert [item["ip"] for item in shown] == ["2001:db8::/48", "203.0.113.0/24"]
    assert pool.recent_exit_ips(masked=False)[0]["ip"] == "2001:db8::5"

    async def failing(out: OutboundRequest) -> EgressResponse:
        raise UpstreamTimeout(Egress.ROTATOR, "ReadTimeout")

    pool.set_sender(failing)
    assert (await pool.exit_ip_probe()).error == "UpstreamTimeout: ReadTimeout"
    (env.credentials_dir / "rotator_url").unlink()
    unconfigured, _ = make_pool(env, dbs, settings)
    await unconfigured.start()
    result = await unconfigured.exit_ip_probe()
    assert not result.configured
    assert result.error == "Rotation proxy is not configured."
    assert mask_ip("not-an-ip") == "n/a"
    assert parse_exit_ip(b"") == ("", "IP-echo response had no IP")


async def test_failure_streak_parks_the_rotator_fleet_wide(env: Any, dbs: Any, settings: Any) -> None:
    settings.set("rotator_max_failures", 3)
    settings.set("rotator_cooldown_s", 60)
    clock = FakeClock(1_760_000_000.0)  # shared by both pools; WSL's wall clock may step back (AGENT_BRIEF)
    pool_a, _ = make_pool(env, dbs, settings, clock=clock)
    pool_b, _ = make_pool(env, dbs, settings, clock=clock)
    await pool_a.start()
    await pool_b.start()
    await pool_a.record_result(False, "timeout")
    await pool_a.refresh()
    await pool_a.record_result(True, "http_200")  # a success resets the shared streak
    await pool_a.record_result(False, "timeout")
    await pool_b.refresh()
    await pool_b.record_result(False, "http_429")
    assert pool_b.enabled()
    await pool_b.refresh()
    await pool_b.record_result(False, "http_503")
    assert not pool_b.enabled()
    assert pool_b.availability()[1] == "rotator_parked"
    await pool_a.refresh()
    usable, reason, retry = pool_a.availability()
    assert (usable, reason) == (False, "rotator_parked")
    assert retry == 60
    assert pool_a.availability(ignore_switch=True)[0]  # admin probes still run
    clock.advance(61)
    assert pool_a.enabled()  # the park ends on its own


def _usage_row(conn: Any, bucket: int, granularity: str, size: int) -> None:
    conn.execute(
        "INSERT INTO egress_usage (bucket_start, egress, granularity, requests, req_bytes, resp_bytes, overhead_bytes) "
        "VALUES (?, 'rotator', ?, 1, ?, 0, 0)",
        (bucket, granularity, size),
    )


def test_usage_since_counts_each_byte_once(dbs: Any) -> None:
    day = 86_400
    start = 100 * day

    def fill(conn: Any) -> None:
        _usage_row(conn, start, "day", 1000)  # day 1, compacted
        _usage_row(conn, start + day, "day", 2000)  # day 2: also has hour rows below, must not be double counted
        _usage_row(conn, start + day, "hour", 1500)
        _usage_row(conn, start + day + 3600, "hour", 500)
        _usage_row(conn, start + day + 7200, "minute", 30)
        _usage_row(conn, start + day + 7260, "minute", 20)
        _usage_row(conn, start - day, "day", 99_999)  # before the window

    dbs.metrics.write_sync(fill)
    total = dbs.metrics.read_sync(lambda conn: usage_since(conn, "rotator", start))
    assert total == 1000 + 1500 + 500 + 30 + 20


def test_cycle_start() -> None:
    def ts(text: str) -> float:
        return dt.datetime.fromisoformat(text).replace(tzinfo=dt.UTC).timestamp()

    assert cycle_start_for(ts("2026-10-07T12:00:00"), 15) == int(ts("2026-09-15T00:00:00"))
    assert cycle_start_for(ts("2026-10-20T12:00:00"), 15) == int(ts("2026-10-15T00:00:00"))
    assert cycle_start_for(ts("2026-01-03T00:00:00"), 5) == int(ts("2025-12-05T00:00:00"))
    assert cycle_start_for(ts("2026-03-01T00:00:00"), 1) == int(ts("2026-03-01T00:00:00"))


async def test_quota_hard_stop_daily_cap_and_alerts(env: Any, dbs: Any, settings: Any) -> None:
    notifier = Notifier()
    pool, _ = make_pool(env, dbs, settings, notifier=notifier)
    now = SYSTEM_CLOCK.now()
    today = int(now // 86_400) * 86_400
    dbs.metrics.write_sync(lambda conn: _usage_row(conn, today, "minute", 600_000))
    settings.set("rotator_quota_gb_per_month", 0.001)  # 1,000,000 bytes
    await pool.start()
    usage = pool.usage_snapshot()
    assert usage.cycle_bytes >= 600_000
    assert usage.pct_of_quota is not None
    assert usage.pct_of_quota >= 60
    assert not usage.stopped
    assert [alert.subject for alert in notifier.alerts] == ["Roxy: rotator at 50% of monthly quota"]
    local = EgressUsage(SYSTEM_CLOCK.now_ms(), Egress.ROTATOR, "caller", "s", 300_000, 150_000, 0, 1, "socket", 200)
    pool.on_usage(local, False)
    usage = pool.usage_snapshot()
    assert usage.stopped
    assert usage.stop_reason == "rotator_quota_hard_stop"
    assert pool.availability()[1] == "rotator_quota_hard_stop"
    assert not pool.enabled()
    settings.set("rotator_hard_stop_pct", 0)  # 0 means never stop
    assert pool.enabled()
    settings.set("rotator_daily_cap_mb", 1)  # 1,000,000 bytes per day
    assert pool.availability()[1] == "rotator_daily_cap"
    assert 0 < pool.availability()[2] <= 86_400  # type: ignore[operator]
    await pool.refresh(force=True)
    assert len([a for a in notifier.alerts if "50%" in a.subject]) == 1  # each threshold once per cycle


async def test_url_replace_and_revert_are_audited_and_shared(env: Any, dbs: Any, settings: Any) -> None:
    pool_a, _ = make_pool(env, dbs, settings)
    pool_b, _ = make_pool(env, dbs, settings)
    await pool_a.start()
    await pool_b.start()
    new_url = "http://ui-user:uiSecretPw99@127.0.0.1:12"
    await pool_a.replace_url(new_url, ADMIN, reason="new plan")
    assert pool_a.url_source() == "ui"
    assert pool_a.masked_url() == "http://127.0.0.1:12"
    await pool_b.refresh()
    assert pool_b.masked_url() == "http://127.0.0.1:12"
    rows = dbs.control.read_sync(lambda conn: [dict(r) for r in conn.execute("SELECT * FROM audit_log").fetchall()])
    assert rows[-1]["action"] == "rotator.replace_url"
    assert "uiSecretPw99" not in str(rows)
    stored = dbs.control.read_sync(
        lambda conn: bytes(conn.execute("SELECT ciphertext FROM rotator_store").fetchone()[0])
    )
    assert b"uiSecretPw99" not in stored
    assert "uiSecretPw99" not in redact_text("password uiSecretPw99 here")
    await pool_a.revert_to_bootstrap(ADMIN)
    await pool_b.refresh()
    assert pool_b.url_source() == "bootstrap"
    assert pool_b.masked_url() == "http://127.0.0.1:9"
    with pytest.raises(RotatorStateError):
        await pool_a.revert_to_bootstrap(ADMIN)
    for bad in ("not a url", "http://h:1/path"):
        with pytest.raises(ValueError):
            await pool_a.replace_url(bad, ADMIN)


async def test_test_override_proxy_wins(env: Any, dbs: Any, settings: Any) -> None:
    pool, _ = make_pool(env, dbs, settings, override_proxy="http://127.0.0.1:18081")
    await pool.start()
    assert pool.url_source() == "test_override"
    assert pool.masked_url() == "http://127.0.0.1:18081"
