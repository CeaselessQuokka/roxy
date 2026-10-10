"""The plan 17.7 alerts that watch numbers (`notify/producers.py`): Roblox 429 and caller 5xx rates, storage, database
integrity, backups and the daily digest, each through the real notifier, gate and recorded mail and webhook.

What this is
    Unit tests that seed a migrated temp state through the real metrics recorder (or the files the root tools write),
    run one producer at a fake time, and read what the recorded mail transport and webhook received.

Why it exists
    These seven alert types were defined but never sent (lane_docs request 3). Each test pins one producer's trigger
    (the plan 17.7 threshold, the noise floor), its subject and severity, the fleet-wide dedupe by its cooldown key, and
    that its body carries Roxy's own words and numbers only: never a client address, a caller's path or a secret.

How it works
    `ctx` is a plain namespace with the pieces the producers read (`dbs`, `settings` from catalog defaults, `env`,
    `alerts`). The notifier is the real `Notifier` on hot.db with `RecordingTransport` mail and a list-backed webhook,
    on the test's `FakeClock`, so cooldowns are exact.

What to read next
    `roxy/notify/producers.py`, `roxy/notify/notifier.py`, `tests/unit/notify/test_notify_notifier.py`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr

from roxy.admin.auth.testing import RecordingTransport
from roxy.config import catalog
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.core.redact import SecretRegistry
from roxy.metrics import disk_history
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.notify import producers
from roxy.notify.mail import MailConfig, MailSender
from roxy.notify.notifier import Notifier
from roxy.scheduler.jobs import JobRegistry

CONFIG = MailConfig("owner@example.invalid", "alerts@example.invalid", SecretStr("not-a-real-password"))
CALLER_IP = "203.0.113.99"
CALLER_PATH = "games.roblox.com/v1/games/7/private-looking-words"
TEMPLATE = "games.roblox.com/v1/games/{gameId}"


class Settings:
    def __init__(self, **overrides: Any) -> None:
        self.values: dict[str, Any] = catalog.defaults()
        self.values.update({"alert_webhook_enabled": 1, **overrides})

    def get(self, key: str) -> Any:
        return self.values[key]


class FakeWebhook:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    async def send(self, payload: dict[str, Any]) -> None:
        self.payloads.append(payload)

    async def aclose(self) -> None:
        return None


class World:
    """The context the producers read, the recorder that seeds it, and the recorded channels."""

    def __init__(self, dbs: Any, clock: FakeClock, state_dir: Path, **settings: Any) -> None:
        self.clock = clock
        self.settings = Settings(**settings)
        self.mail = RecordingTransport()
        self.webhook = FakeWebhook()
        notifier = Notifier(
            hot_db=dbs.hot,
            settings=self.settings,
            site_origin="https://roxy.example",
            mail=MailSender(CONFIG, transport=self.mail),
            webhook=self.webhook,
            clock=clock,
        )
        env = SimpleNamespace(site_origin="https://roxy.example", state_dir=state_dir)
        self.ctx = SimpleNamespace(dbs=dbs, settings=self.settings, env=env, alerts=notifier, clock=clock)
        self.recorder = MetricsRecorder(dbs, self.settings, clock, ip_hash_key=b"k" * 32)

    def record(self, count: int, **fields: Any) -> None:
        for index in range(count):
            base: dict[str, Any] = {
                "at_ms": self.clock.now_ms(),
                "request_id": f"01PRODUCERS{index:015d}",
                "endpoint_template": TEMPLATE,
                "host": "games.roblox.com",
                "method": "GET",
                "egress": Egress.DIRECT,
                "outcome": Outcome.SERVED_UPSTREAM,
                "reason": ReasonCode.UPSTREAM_OK,
                "status": 200,
                "source": Source.ROBLOX,
                "cache_state": CacheState.MISS,
                "auth_class": AuthClass.ANON,
                "caller_bytes_in": 100,
                "caller_bytes_out": 500,
                "upstream_calls": 1,
                "upstream_bytes_in": 900,
                "upstream_bytes_out": 300,
                "latency_ms": 40.0,
                "queue_wait_ms": 1.0,
                "upstream_ms": 30.0,
                "client_ip": CALLER_IP,
                "place_id": "12345",
                "user_agent": "Roblox/WinInet",
                "bypass": False,
                "error": False,
                "path": CALLER_PATH,
            }
            base.update(fields)
            self.recorder.record_outcome(OutcomeEvent(**base))

    def roblox_429s(self, count: int, egress: str = "direct") -> None:
        for _ in range(count):
            self.recorder.record_upstream_429(endpoint_template=TEMPLATE, host="games.roblox.com", egress=egress)

    def settle(self) -> None:
        """Write what was recorded, then let the minute close (the rate alerts read complete minutes)."""
        self.recorder.close()
        self.clock.advance(60)

    def bodies(self) -> str:
        return "\n".join(self.mail.bodies()) + json.dumps(self.webhook.payloads)


@pytest.fixture
def world(dbs: Any, fake_clock: FakeClock, tmp_path: Path) -> World:
    return World(dbs, fake_clock, tmp_path)


def assert_no_caller_text(world: World) -> None:
    text = world.bodies()
    assert CALLER_IP not in text
    assert "private-looking-words" not in text


# ------------------------------------------------------------------------------------------ Roblox 429 rate


async def test_roblox_429_rate_over_2_percent_alerts_once_per_cooldown(world: World) -> None:
    world.record(50)
    world.roblox_429s(4, egress="direct")
    world.roblox_429s(2, egress="rotator")
    world.settle()
    report = await producers.check_roblox_429(world.ctx, world.clock.now())
    assert (report["roblox_429"], report["upstream_calls"], report["rate_pct"]) == (6, 50, 12.0)
    assert report["sent"] == ["email", "webhook"]
    assert world.mail.subjects() == ["Roxy: Roblox is rate-limiting us (12%)"]
    body = world.mail.bodies()[0]
    assert f"Top endpoints: {TEMPLATE} (6)" in body
    assert "Egress split: direct (4), rotator (2)" in body
    assert "https://roxy.example/admin/recommendations" in body
    assert world.webhook.payloads[0]["type"] == "roblox_429"
    assert_no_caller_text(world)
    again = await producers.check_roblox_429(world.ctx, world.clock.now())
    assert again["skipped"] == "deduped"  # cooldown key roblox_429, 1800 s, fleet-wide in hot.db
    world.clock.advance(1801 - 60)
    world.record(10)
    world.roblox_429s(5)
    world.settle()
    third = await producers.check_roblox_429(world.ctx, world.clock.now())
    assert third["sent"] == ["email", "webhook"]
    assert world.mail.subjects()[-1] == "Roxy: Roblox is rate-limiting us (50%)"


async def test_roblox_429_needs_the_rate_and_the_noise_floor(world: World) -> None:
    world.record(3)
    world.roblox_429s(1)  # 33 percent, but a single 429 never pages anyone
    world.settle()
    small = await producers.check_roblox_429(world.ctx, world.clock.now())
    assert "alert" not in small
    world.clock.advance(producers.RATE_WINDOW_S)
    world.record(1000)
    world.roblox_429s(producers.MIN_EVENTS + 5)  # 1 percent: below the 2 percent of plan 17.7
    world.settle()
    low = await producers.check_roblox_429(world.ctx, world.clock.now())
    assert (low["roblox_429"], "alert" in low) == (producers.MIN_EVENTS + 5, False)
    world.clock.advance(producers.RATE_WINDOW_S)
    old = await producers.check_roblox_429(world.ctx, world.clock.now())  # nothing in the last 10 minutes
    assert old["roblox_429"] == 0
    assert world.mail.messages == []


# --------------------------------------------------------------------------------------------- caller 5xx


async def test_caller_5xx_over_2_percent_names_statuses_and_reasons(world: World) -> None:
    world.record(20)
    world.record(
        5,
        outcome=Outcome.FAILED,
        reason=ReasonCode.UPSTREAM_5XX,
        status=502,
        source=Source.ROXY,
        upstream_status=502,
    )
    world.record(10, status=500, source=Source.INTERNAL, outcome=Outcome.FAILED, reason=ReasonCode.INTERNAL_ERROR)
    world.settle()
    report = await producers.check_caller_5xx(world.ctx, world.clock.now())
    assert (report["status_5xx"], report["requests"], report["rate_pct"]) == (5, 25, 20.0)  # Roxy's probes left out
    assert world.mail.subjects() == ["Roxy: caller errors at 20%"]
    body = world.mail.bodies()[0]
    assert "Statuses: 502 (5)" in body
    assert "Top reasons: upstream_5xx (5)" in body
    assert_no_caller_text(world)


async def test_a_pause_is_not_a_caller_error(world: World) -> None:
    world.record(5)
    world.record(
        100,
        outcome=Outcome.REFUSED,
        reason=ReasonCode.PAUSED,
        status=503,
        source=Source.ROXY,
        upstream_calls=0,
        egress=Egress.NONE,
        cache_state=CacheState.NA,
    )
    world.settle()
    report = await producers.check_caller_5xx(world.ctx, world.clock.now())
    assert (report["status_5xx"], report["requests"]) == (0, 5)
    assert world.mail.messages == []


# ------------------------------------------------------------------------------------------------ storage


def fake_measure(used: int, free: int = 5 * producers.GIB) -> Any:
    def measure(state_dir: Any, paths: Any) -> disk_history.FilesMeasure:
        return disk_history.FilesMeasure(
            total_bytes=20 * producers.GIB,
            free_bytes=free,
            files={"metrics.db": {"bytes": used - 1000, "wal_bytes": 1000}, "control.db": {"bytes": 0, "wal_bytes": 0}},
        )

    return measure


async def test_storage_alerts_from_90_percent_and_is_critical_over_the_budget(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.settings.values["storage_total_budget_gb"] = 10
    monkeypatch.setattr(disk_history, "measure_files", fake_measure(8 * producers.GIB))
    quiet = await producers.check_storage(world.ctx, world.clock.now())
    assert (quiet["pct"], "alert" in quiet) == (80.0, False)
    now = int(world.clock.now())

    def samples(conn: Any) -> None:
        for days, size in ((6, 8 * producers.GIB), (0, int(9.5 * producers.GIB))):
            conn.execute(
                "INSERT INTO disk_samples (at, total_bytes, free_bytes, storage_bytes, files_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (now - days * 86_400, 20 * producers.GIB, producers.GIB, size, "{}"),
            )

    await world.ctx.dbs.metrics.write(samples)
    monkeypatch.setattr(disk_history, "measure_files", fake_measure(int(9.5 * producers.GIB)))
    warn = await producers.check_storage(world.ctx, world.clock.now())
    assert (warn["pct"], warn["severity"], warn["sent"]) == (95.0, "warn", ["email", "webhook"])
    assert world.mail.subjects() == ["Roxy: storage at 95% of budget"]
    body = world.mail.bodies()[0]
    assert "Largest: metrics.db 9.5 GB" in body
    assert "Growth per day: 256.0 MB" in body  # 1.5 GiB over six days
    monkeypatch.setattr(disk_history, "measure_files", fake_measure(12 * producers.GIB))
    assert (await producers.check_storage(world.ctx, world.clock.now()))["skipped"] == "deduped"  # key disk, 6 h
    world.clock.advance(6 * 3600 + 1)
    over = await producers.check_storage(world.ctx, world.clock.now())
    assert (over["severity"], world.mail.subjects()[-1]) == ("critical", "Roxy: storage at 120% of budget")


# ------------------------------------------------------------------------------------- database integrity


async def test_a_failed_quick_check_sends_the_integrity_alert(world: World) -> None:
    hook = producers.integrity_hook(world.ctx)
    await hook("control", ["*** in database main ***", "Page 12 is never used"])
    assert world.mail.subjects() == ["Roxy: database integrity check failed"]
    body = world.mail.bodies()[0]
    assert "Database: control.db" in body
    assert "Page 12 is never used" in body
    await hook("control", ["again"])
    assert len(world.mail.messages) == 1  # db_integrity, one hour


# ------------------------------------------------------------------------------------------------ backups


def write_backup(state_dir: Path, document: dict[str, Any]) -> None:
    folder = state_dir.joinpath(*producers.BACKUP_STATUS_FILE[:-1])
    folder.mkdir(parents=True, exist_ok=True)
    folder.joinpath(producers.BACKUP_STATUS_FILE[-1]).write_text(json.dumps(document), encoding="utf-8")


def iso(at: float) -> str:
    return datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def test_backup_stale_then_failed_share_one_cooldown(world: World, tmp_path: Path) -> None:
    now = world.clock.now()
    assert (await producers.check_backup(world.ctx, now)) == {"backup": "no record"}  # development: H-BACKUP's case
    write_backup(tmp_path, {"last_success": {"at": iso(now - 3 * 3600), "date": "2025-10-09", "set": {}}})
    assert (await producers.check_backup(world.ctx, now))["backup"] == "ok"
    write_backup(tmp_path, {"last_success": {"at": iso(now - 30 * 3600), "date": "2025-10-08", "set": {}}})
    stale = await producers.check_backup(world.ctx, now)
    assert (stale["backup"], stale["sent"]) == ("stale", ["email", "webhook"])
    assert world.mail.subjects() == ["Roxy: no backup for 30 h"]
    failure = {"at": iso(now - 600), "date": "2025-10-09", "step": "copy", "error": "failed at step copy (exit 1)"}
    write_backup(
        tmp_path,
        {"last_success": {"at": iso(now - 30 * 3600), "date": "2025-10-08", "set": {}}, "last_failure": failure},
    )
    failed = await producers.check_backup(world.ctx, now)
    assert (failed["backup"], failed["skipped"]) == ("failed", "deduped")  # one cooldown key: backup, 6 h
    world.clock.advance(6 * 3600 + 1)
    failed = await producers.check_backup(world.ctx, world.clock.now())
    assert world.mail.subjects()[-1] == "Roxy: backup failed"
    assert "Failed step: copy" in world.mail.bodies()[-1]
    assert failed["sent"] == ["email", "webhook"]


# ------------------------------------------------------------------------------------------------- digest


async def test_daily_digest_once_at_the_digest_hour_by_email_only(world: World) -> None:
    now = world.clock.now()
    hour = datetime.fromtimestamp(now, UTC).hour
    world.settings.values.update(alert_min_severity="info", alert_digest_hour=hour, ui_timezone="UTC")

    def seed(conn: Any) -> None:
        for rec_id, rule, severity, state in (
            ("r1", "UP-429-ENDPOINT", "critical", "open"),
            ("r2", "CACHE-LOW-HIT", "warn", "open"),
            ("r3", "CACHE-LOW-HIT", "warn", "dismissed"),
        ):
            conn.execute(
                "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at, "
                "updated_at) VALUES (?, ?, ?, ?, ?, '{}', ?, ?)",
                (rec_id, rule, f"{rule}:{rec_id}", state, severity, int(now), int(now)),
            )
        cursor = conn.execute(
            "INSERT INTO health_runs (started_at, finished_at, trigger, summary) VALUES (?, ?, 'schedule', '{}')",
            (int(now) - 60, int(now) - 30),
        )
        for check, status in (("H-BACKUP", "fail"), ("H-DISK", "pass")):
            conn.execute(
                "INSERT INTO health_results (run_id, check_id, status) VALUES (?, ?, ?)",
                (cursor.lastrowid, check, status),
            )

    await world.ctx.dbs.metrics.write(seed)
    world.record(20)
    world.roblox_429s(3)
    world.recorder.close()
    claimed: list[str] = []

    async def claim(day: str) -> bool:
        if day in claimed:
            return False
        claimed.append(day)
        return True

    report = await producers.send_digest(world.ctx, now, claim=claim)
    assert report["sent"] == ["email"]  # the digest is email only (plan 17.7), even with the webhook on
    assert world.mail.subjects() == ["Roxy daily digest: 2 open recommendations"]
    body = world.mail.bodies()[0]
    assert "Open recommendations: critical 1, warn 1" in body
    assert "Rules: UP-429-ENDPOINT, CACHE-LOW-HIT" in body
    assert "Failing health checks: H-BACKUP" in body
    assert "Roblox 429s (24 h): 3" in body
    assert world.webhook.payloads == []
    assert (await producers.send_digest(world.ctx, now, claim=claim))["digest"] == "already_sent"
    assert (await producers.send_digest(world.ctx, now + 3600))["digest"] == "not_due"
    world.settings.values["alert_min_severity"] = "warn"
    assert (await producers.send_digest(world.ctx, now))["digest"] == "skipped"  # info is below warn
    world.settings.values["alert_digest_hour"] = -1
    assert (await producers.send_digest(world.ctx, now))["digest"] == "off"
    assert claimed == [datetime.fromtimestamp(now, UTC).date().isoformat()]
    assert_no_caller_text(world)


# ---------------------------------------------------------------------------------------- bodies and jobs


async def test_no_secret_reaches_an_alert_body(world: World) -> None:
    secret = "producer-secret-value-that-must-never-leave"
    SecretRegistry.register("test_producer_secret", secret)
    try:
        await producers.integrity_hook(world.ctx)("hot", [f"bad page near {secret}"])
    finally:
        SecretRegistry.unregister("test_producer_secret")
    assert world.mail.messages
    assert secret not in world.bodies()


def test_the_jobs_are_leader_only_and_never_run_at_start(world: World) -> None:
    registry = JobRegistry()
    producers.register_jobs(registry, world.ctx)
    jobs = {job.name: job for job in registry.all()}
    assert set(jobs) == {"alerts_rates", "alerts_storage", "alerts_backup", "alerts_digest"}
    assert all(job.leader_only and not job.run_at_start for job in jobs.values())
    assert jobs["alerts_rates"].interval() == 60.0
