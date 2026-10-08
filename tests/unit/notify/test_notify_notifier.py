"""The notifier (DESIGN.md 11.6, plan 17.7): severity routing, fleet-wide dedupe, hourly cap, redaction,
the body layout, the webhook payload, and never blocking or raising."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from roxy.admin.auth.testing import RecordingTransport
from roxy.core.clock import FakeClock
from roxy.core.redact import SecretRegistry
from roxy.notify.alerts import make_alert
from roxy.notify.mail import MailConfig, MailError, MailSender
from roxy.notify.notifier import Notifier, build_notifier, get_notifier, render_email, render_webhook


class Settings:
    def __init__(self, **values: Any) -> None:
        self.values = {
            "alert_min_severity": "warn",
            "alert_rate_limit_per_hour": 20,
            "alert_webhook_enabled": 0,
            "ui_timezone": "America/New_York",
            "error_email_cooldown": 300,
            "email_cooldown": 600,
            **values,
        }

    def get(self, key: str) -> Any:
        return self.values[key]


class FakeWebhook:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    async def send(self, payload: dict[str, Any]) -> None:
        self.payloads.append(payload)

    async def aclose(self) -> None:
        return None


CONFIG = MailConfig("owner@example.invalid", "alerts@example.invalid", SecretStr("not-a-real-password"))


def _notifier(
    dbs: Any, clock: FakeClock, *, settings: Settings | None = None, webhook: Any = None
) -> tuple[Notifier, RecordingTransport]:
    mail = RecordingTransport()
    notifier = Notifier(
        hot_db=dbs.hot,
        settings=settings or Settings(),
        site_origin="https://roxy.example",
        mail=MailSender(CONFIG, transport=mail),
        webhook=webhook,
        clock=clock,
    )
    return notifier, mail


async def test_severity_routing(dbs: Any, fake_clock: FakeClock) -> None:
    notifier, mail = _notifier(dbs, fake_clock)
    assert (await notifier.send(make_alert("digest", summary="s", n=1, day="d"))).skipped == "severity"
    assert (await notifier.send(make_alert("roblox_429", summary="s", rate=3))).sent == ("email",)
    # always_send ignores alert_min_severity (new admin login, info level).
    critical_only, mail2 = _notifier(dbs, fake_clock, settings=Settings(alert_min_severity="critical"))
    assert (await critical_only.send(make_alert("admin_login", summary="s"))).sent == ("email",)
    assert (await critical_only.send(make_alert("caller_5xx", summary="s", rate=3))).skipped == "severity"
    assert mail.subjects() == ["Roxy: Roblox is rate-limiting us (3%)"]
    assert mail2.subjects() == ["Roxy Admin Login"]


async def test_two_workers_send_one_alert(dbs: Any, fake_clock: FakeClock) -> None:
    worker_a, mail_a = _notifier(dbs, fake_clock)
    worker_b, mail_b = _notifier(dbs, fake_clock)
    alert = make_alert("error", summary="boom", signature="KeyError at x.py:1")
    results = await asyncio.gather(worker_a.send(alert), worker_b.send(alert), worker_a.send(alert))
    assert sum(1 for r in results if r.sent) == 1
    assert len(mail_a.messages) + len(mail_b.messages) == 1
    fake_clock.advance(301)  # error_email_cooldown
    again = await worker_b.send(alert)
    assert again.sent == ("email",)
    assert again.suppressed == 2
    assert "Suppressed since last alert: 2" in mail_a.bodies()[-1] + "".join(mail_b.bodies())


async def test_cooldown_follows_the_live_setting(dbs: Any, fake_clock: FakeClock) -> None:
    settings = Settings(email_cooldown=60)
    notifier, mail = _notifier(dbs, fake_clock, settings=settings)
    alert = make_alert("credential_rejected", summary="rejected")
    assert (await notifier.send(alert)).sent
    fake_clock.advance(61)
    assert (await notifier.send(alert)).sent
    assert mail.subjects() == ["Token Expired", "Token Expired"]


async def test_hourly_cap_and_storm_summary(dbs: Any, fake_clock: FakeClock) -> None:
    notifier, mail = _notifier(dbs, fake_clock, settings=Settings(alert_rate_limit_per_hour=3))
    results = [await notifier.send(make_alert("error", summary="s", signature=f"E{i}")) for i in range(6)]
    assert [r.skipped for r in results] == [None, None, None, "capped", "capped", "capped"]
    leak = await notifier.send(make_alert("leak_guard", summary="blocked"))
    assert leak.sent == ("email",)  # leak guard alerts are never capped...
    assert leak.suppressed == 3  # ...and the first message out reports the storm
    assert "Suppressed since last alert: 3" in mail.bodies()[-1]
    fake_clock.advance(3600)
    after = await notifier.send(make_alert("error", summary="s", signature="later"))
    assert after.sent
    assert after.suppressed == 0


async def test_body_layout_and_redaction(dbs: Any, fake_clock: FakeClock) -> None:
    SecretRegistry.register("test_secret_value", "s3cr3t-value-that-must-not-leak")
    try:
        alert = make_alert(
            "roblox_429",
            summary="Roblox answered 429 for 3% of requests (key s3cr3t-value-that-must-not-leak)",
            fields={"Rate": 3.2, "Top endpoint": "games.roblox.com/v1/games", "password": "hunter22hunter"},
            link="https://roxy.example/admin/upstream",
            rate="3.2",
        )
        subject, body = render_email(
            alert, suppressed=0, now=fake_clock.now(), tz_name="America/New_York", site_origin="https://roxy.example"
        )
        assert subject == "Roxy: Roblox is rate-limiting us (3.2%)"
        lines = body.splitlines()
        assert lines[0].startswith("Roblox answered 429")
        assert "What happened:" in body
        assert "When: 2025-10-09" in body
        assert "UTC" in body
        assert "America/New_York" in body
        assert "Where: https://roxy.example/admin/upstream" in body
        assert "Evidence:\n  Rate: 3.2" in body
        assert "What to do: https://roxy.example/admin/help#runbook-roblox-429" in body
        assert "Suppressed since last alert" not in body
        assert "s3cr3t-value-that-must-not-leak" not in body
        assert "hunter22hunter" not in body
        payload = render_webhook(
            alert, suppressed=2, now=fake_clock.now(), tz_name="UTC", site_origin="https://roxy.example"
        )
        assert payload["subject"] == subject
        assert payload["suppressed"] == 2
        assert payload["fields"]["Top endpoint"] == "games.roblox.com/v1/games"
        assert "s3cr3t-value-that-must-not-leak" not in str(payload)
        assert "hunter22hunter" not in str(payload)
        assert payload["content"].startswith(subject)
    finally:
        SecretRegistry.unregister("test_secret_value")


def test_login_body_keeps_the_kill_switch_link_and_scrubs_the_rest() -> None:
    link = "https://roxy.example/admin/invalidate/" + "A" * 43
    body = f"Hello\nUser-Agent: x .ROBLOSECURITY=abcdefgh123\n{link}\n/admin/invalidate/OTHERTOKEN123\n"
    alert = make_alert("admin_login", summary="s", link=link, body=body)
    _, rendered = render_email(alert, suppressed=0, now=0, tz_name="UTC", site_origin="https://roxy.example")
    assert link in rendered
    assert "OTHERTOKEN123" not in rendered
    assert "abcdefgh123" not in rendered


async def test_webhook_channel_only_when_enabled(dbs: Any, fake_clock: FakeClock) -> None:
    hook = FakeWebhook()
    off, _ = _notifier(dbs, fake_clock, webhook=hook)
    assert (await off.send(make_alert("disk", summary="s", pct=91))).sent == ("email",)
    on, _ = _notifier(dbs, fake_clock, settings=Settings(alert_webhook_enabled=1), webhook=hook)
    result = await on.send(make_alert("db_integrity", summary="bad"))
    assert result.sent == ("email", "webhook")
    assert hook.payloads[-1]["type"] == "db_integrity"
    login = await on.send(make_alert("admin_login", summary="s"))
    assert login.sent == ("email",)  # the login alert (with its kill-switch link) is email only


async def test_delivery_failures_are_reported_not_raised(dbs: Any, fake_clock: FakeClock) -> None:
    notifier, mail = _notifier(dbs, fake_clock)
    mail.fail = True
    result = await notifier.send(make_alert("disk", summary="s", pct=91))
    assert result.sent == ()
    assert "email" in result.errors
    with pytest.raises(MailError):
        await notifier.send_message("Admin 2FA", "123")


async def test_slow_mail_times_out(dbs: Any, fake_clock: FakeClock) -> None:
    async def hang(message: Any, config: Any) -> None:
        await asyncio.sleep(10)

    notifier = Notifier(
        hot_db=dbs.hot,
        settings=Settings(),
        site_origin="https://roxy.example",
        mail=MailSender(CONFIG, transport=hang),
        webhook=None,
        clock=fake_clock,
        send_timeout_s=0.05,
    )
    result = await notifier.send(make_alert("disk", summary="s", pct=91))
    assert result.errors == {"email": "TimeoutError"}


async def test_notify_is_fire_and_forget_and_bounded(dbs: Any, fake_clock: FakeClock) -> None:
    release = asyncio.Event()

    async def slow(message: Any, config: Any) -> None:
        await release.wait()

    notifier = Notifier(
        hot_db=dbs.hot,
        settings=Settings(),
        site_origin="https://roxy.example",
        mail=MailSender(CONFIG, transport=slow),
        webhook=None,
        clock=fake_clock,
    )
    tasks = [notifier.notify(make_alert("error", summary="s", signature=f"S{i}")) for i in range(20)]
    assert sum(1 for t in tasks if t is not None) == 16
    assert notifier.dropped == 4
    release.set()
    await notifier.drain()
    await notifier.aclose()
    assert notifier.notify(make_alert("disk", summary="s", pct=1)) is None


async def test_gate_failure_degrades_open_but_dedupes_per_worker(fake_clock: FakeClock) -> None:
    class BrokenDb:
        async def write(self, fn: Any, **kwargs: Any) -> Any:
            raise RuntimeError("database is closed")

    mail = RecordingTransport()
    notifier = Notifier(
        hot_db=BrokenDb(),
        settings=Settings(),
        site_origin="https://roxy.example",
        mail=MailSender(CONFIG, transport=mail),
        webhook=None,
        clock=fake_clock,
    )
    alert = make_alert("db_integrity", summary="bad")
    assert (await notifier.send(alert)).sent == ("email",)
    assert (await notifier.send(alert)).skipped == "deduped"


async def test_no_channel_configured(fake_clock: FakeClock) -> None:
    notifier = Notifier(hot_db=None, settings=Settings(), site_origin="x", mail=None, webhook=None, clock=fake_clock)
    assert (await notifier.send(make_alert("disk", summary="s", pct=1))).skipped == "no_channel"


def test_build_notifier_reads_credentials(credentials_dir: Path, tmp_path: Path) -> None:
    class Env:
        def __init__(self, directory: Path) -> None:
            self.credentials_dir = directory
            self.site_origin = "https://roxy.example"

    class Ctx:
        def __init__(self, directory: Path) -> None:
            self.env = Env(directory)
            self.settings = Settings()
            self.dbs = None
            self.alerts = None

    ctx = Ctx(credentials_dir)
    notifier = get_notifier(ctx)
    assert ctx.alerts is notifier
    assert get_notifier(ctx) is notifier
    assert notifier.mail is not None
    assert notifier.mail.config.to_addr == "owner@example.invalid"
    assert notifier.webhook is not None  # the fake URL is http on loopback
    empty = build_notifier(Ctx(tmp_path))
    assert empty.mail is None
    assert empty.webhook is None


async def test_unhandled_errors_raise_the_v1_error_alert(dbs: Any, fake_clock: FakeClock) -> None:
    from types import SimpleNamespace

    from roxy.core.errors import ErrorHooks
    from roxy.notify.notifier import error_alert, install_error_alerts

    def explode() -> None:
        raise KeyError("missing")

    try:
        explode()
    except KeyError as exc:
        event = SimpleNamespace(exc=exc, method="GET", path="/games.roblox.com/v1/x", request_id="r1")
    alert = error_alert(event, "https://roxy.example")
    assert alert is not None
    assert alert.subject.startswith("Roxy Error: KeyError at test_notify_notifier.py:")
    assert alert.cooldown_key == f"error:{alert.subject.removeprefix('Roxy Error: ')}"
    assert alert.link == "https://roxy.example/admin/system#errors"
    assert error_alert(SimpleNamespace(exc=None), "x") is None

    notifier, mail = _notifier(dbs, fake_clock)
    app = SimpleNamespace(state=SimpleNamespace(error_hooks=ErrorHooks()))
    install_error_alerts(app, notifier)
    hook = app.state.error_hooks.server_error[0]
    hook(event)
    hook(event)  # the same signature again: deduped fleet-wide
    await notifier.drain()
    assert len(mail.subjects()) == 1
    assert mail.subjects()[0].startswith("Roxy Error: KeyError at ")
