"""The notifier: turns an `Alert` into a redacted email and webhook call, deduped fleet-wide, never blocking.

What this is
    `Notifier` (DESIGN.md 11.6) with `send(alert) -> SendResult` (await the outcome), `notify(alert)` (fire and
    forget from a request), `send_message(subject, body)` (a direct mail that is not an alert: the emailed login
    code), `drain()` and `aclose()`. `build_notifier(ctx)` makes one from the systemd credentials, and
    `get_notifier(ctx)` returns `ctx.alerts`, building it on first use. `install_error_alerts(app, notifier)`
    registers the `Roxy Error: <signature>` alert as a server error hook (`core/errors.py`).

Why it exists
    An alert is only useful if it arrives once, says what happened in plain words, and never leaks a secret or
    slows Roxy down. Plan 17.7 sets the rules: severity routing (`alert_min_severity`), fleet-wide dedupe by
    cooldown key, a per-channel hourly cap (`alert_rate_limit_per_hour`, leak guard alerts exempt), redaction of
    every field, and a fixed body layout. DESIGN.md 11.6 adds: never block a request.

How it works
    1. Severity: an alert below `alert_min_severity` is dropped unless it is `always_send` (new admin login, leak
       guard trip).
    2. Channels: email when the mail credentials exist; webhook when `alert_webhook_enabled` = 1 and the
       `alert_webhook_url` credential exists; intersected with the alert's own channels.
    3. Gate (`gate.decide`, one hot.db transaction): dedupe by cooldown key, then the hourly cap per channel.
       If hot.db cannot be written, `gate.MemoryGate` applies the same rules in this worker's memory instead
       (plan C7: alerts degrade open rather than go silent). The hourly cap still holds, at this worker's share
       (`alert_rate_limit_per_hour // ROXY_WORKERS`, at least 1), so the fleet stays within the setting; dedupe
       becomes per worker, so each worker may then send its own copy of an alert, at most once per cooldown key
       per gap.
    4. Render: every user-influenced text (summary, field names and values, the subject's parameters, a body
       override) goes through `redact_text`. The kill-switch link of the login alert is the one link that may
       carry a token (plan 17.7), so it is protected from the redaction pass that would otherwise mask it.
       Email body: the summary first, then `What happened`, `When` (UTC and `ui_timezone`), `Where` (the page
       link), `Evidence` (up to 5 numbers), `What to do` (the runbook link) and, when anything was held back,
       `Suppressed since last alert: N`. The webhook gets the same fields as JSON.
    5. Deliver: each channel with its own timeout. `notify` runs all of this in a background task (through the
       worker's `TaskSupervisor` when there is one), bounded to `MAX_IN_FLIGHT` tasks; beyond that an alert is
       logged and dropped rather than queued without limit (plan P9).

What to read next
    `roxy/notify/alerts.py` (the alert catalog), `roxy/notify/gate.py`, then `roxy/admin/auth/flow.py` (the login
    alert and the emailed code, the first producers).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import traceback
from collections.abc import Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from roxy.config.constants import SMTP_TIMEOUT_S
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.redact import MASK, is_secret_field, redact_text
from roxy.core.scope import catalog_default
from roxy.notify import gate
from roxy.notify.alerts import ALERT_SPECS, SEVERITIES, Alert, SendResult, make_alert
from roxy.notify.mail import MailError, MailSender, load_mail_config
from roxy.notify.webhook import WebhookError, WebhookSender, load_webhook_url

log = logging.getLogger("roxy.notify")

SEND_TIMEOUT_S = float(SMTP_TIMEOUT_S + 5)
"""Per channel: aiosmtplib's own 15 s timeout plus a margin for TLS and login."""

TASK_TIMEOUT_S = 2 * SEND_TIMEOUT_S + 5
MAX_IN_FLIGHT = 16
GATE_BUSY_TIMEOUT_MS = 1000
MAX_FIELDS = 12
MAX_EVIDENCE = 5
MAX_VALUE_CHARS = 300
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
_LINK_MARK = "\x00ROXY-LINK\x00"

_SETTING_DEFAULTS: dict[str, Any] = {
    "alert_min_severity": "warn",
    "alert_rate_limit_per_hour": 20,
    "alert_webhook_enabled": 0,
    "ui_timezone": "UTC",
}


def _clean(value: Any, limit: int = MAX_VALUE_CHARS) -> str:
    text = redact_text(str(value))
    text = "".join(ch if ch.isprintable() or ch == " " else " " for ch in text)
    return text[:limit]


def _redact_keep_link(text: str, link: str | None) -> str:
    """Redact `text` but keep `link` intact (the kill-switch link must survive, everything else is scrubbed)."""
    if link and link in text:
        parts = text.split(link)
        return link.join(redact_text(part) for part in parts)
    return redact_text(text)


def format_when(now: float, tz_name: str) -> tuple[str, str]:
    """(`YYYY-MM-DD HH:MM:SS UTC`, the same moment in `tz_name`)."""
    moment = datetime.fromtimestamp(now, tz=UTC)
    utc_text = moment.strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        local = moment.astimezone(ZoneInfo(tz_name))
        local_text = f"{local.strftime('%Y-%m-%d %H:%M:%S %Z')} ({tz_name})"
    except (ZoneInfoNotFoundError, ValueError):
        local_text = utc_text
    return utc_text, local_text


def runbook_link(site_origin: str, runbook: str | None) -> str | None:
    if not runbook:
        return None
    return f"{site_origin.rstrip('/')}/admin/help#runbook-{runbook}"


def _field_value(key: Any, value: Any) -> str:
    """A field value for a message: masked entirely when its NAME says secret (`password`, `token`, ...)."""
    return MASK if is_secret_field(str(key), value) else _clean(value)


def _split_fields(fields: dict[str, Any]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """(details, evidence): numbers go to Evidence (up to 5), everything else to What happened."""
    details: list[tuple[str, str]] = []
    evidence: list[tuple[str, str]] = []
    for key, value in list(fields.items())[: MAX_FIELDS * 2]:
        name = _clean(key, 60)
        if isinstance(value, int | float) and not isinstance(value, bool) and len(evidence) < MAX_EVIDENCE:
            evidence.append((name, _field_value(key, value)))
        elif len(details) < MAX_FIELDS:
            details.append((name, _field_value(key, value)))
    return details, evidence


def render_email(alert: Alert, *, suppressed: int, now: float, tz_name: str, site_origin: str) -> tuple[str, str]:
    """(subject, body) of the email for `alert` (plan 17.7 layout)."""
    subject = _clean(alert.subject, 200)
    if alert.body is not None:
        body = _redact_keep_link(alert.body, alert.link)
        if suppressed > 0:
            body = body.rstrip("\n") + f"\n\nSuppressed since last alert: {suppressed}\n"
        return subject, body
    utc_text, local_text = format_when(now, tz_name)
    details, evidence = _split_fields(alert.fields)
    lines = [_clean(alert.summary, 1000), ""]
    if details:
        lines.append("What happened:")
        lines.extend(f"  {key}: {value}" for key, value in details)
    else:
        lines.append(f"What happened: {_clean(alert.summary, 1000)}")
    lines.append(f"When: {utc_text} ({local_text})")
    lines.append(f"Where: {alert.link or 'n/a'}")
    if evidence:
        lines.append("Evidence:")
        lines.extend(f"  {key}: {value}" for key, value in evidence)
    lines.append(f"What to do: {runbook_link(site_origin, alert.runbook) or 'see the admin guide'}")
    if suppressed > 0:
        lines.append(f"Suppressed since last alert: {suppressed}")
    return subject, "\n".join(lines) + "\n"


def render_webhook(alert: Alert, *, suppressed: int, now: float, tz_name: str, site_origin: str) -> dict[str, Any]:
    """The JSON body for the webhook: the email's fields, structured."""
    subject, _ = render_email(alert, suppressed=suppressed, now=now, tz_name=tz_name, site_origin=site_origin)
    utc_text, local_text = format_when(now, tz_name)
    summary = _clean(alert.summary, 1000)
    text = f"{subject}\n{summary}" + (f"\n{alert.link}" if alert.link else "")
    return {
        "content": text[:1900],  # Discord shows `content` (2000 character limit)
        "text": text,  # Slack-compatible receivers show `text`
        "type": alert.type,
        "severity": alert.severity,
        "subject": subject,
        "summary": summary,
        "fields": {_clean(k, 60): _field_value(k, v) for k, v in list(alert.fields.items())[:MAX_FIELDS]},
        "link": alert.link,
        "when_utc": utc_text,
        "when_local": local_text,
        "runbook": runbook_link(site_origin, alert.runbook),
        "suppressed": suppressed,
    }


class Notifier:
    """Sends alerts through the gate to email and webhook. One per worker (`ctx.alerts`)."""

    def __init__(
        self,
        *,
        hot_db: Any | None,
        settings: Any,
        site_origin: str,
        mail: MailSender | None,
        webhook: WebhookSender | None,
        clock: Clock = SYSTEM_CLOCK,
        tasks: Any | None = None,
        send_timeout_s: float = SEND_TIMEOUT_S,
        workers: int = 1,
    ) -> None:
        self._db = hot_db
        self.workers = max(1, int(workers))  # ROXY_WORKERS: the fallback gate's share of the hourly cap
        self._settings = settings
        self.site_origin = site_origin
        self.mail = mail
        self.webhook = webhook
        self._clock = clock
        self._tasks = tasks
        self._send_timeout_s = send_timeout_s
        self._memory_gate = gate.MemoryGate()
        self._inflight: set[asyncio.Task[Any]] = set()
        self._closed = False
        self.dropped = 0  # fire-and-forget alerts dropped because MAX_IN_FLIGHT were already running

    # ------------------------------------------------------------------------------------------ settings

    def _setting(self, key: str) -> Any:
        """The live setting; without a settings store, the catalog default (the table below only as a last resort,
        for a build where the catalog does not have the key)."""
        try:
            return self._settings.get(key)
        except (KeyError, AttributeError, LookupError):
            found = catalog_default(key)
            return found if found is not None else _SETTING_DEFAULTS.get(key)

    def _cooldown_for(self, alert: Alert) -> int:
        spec = ALERT_SPECS.get(alert.type)
        if spec is not None and spec.cooldown_setting:
            value = self._setting(spec.cooldown_setting)
            if isinstance(value, int | float) and not isinstance(value, bool):
                return int(value)
        return int(alert.cooldown_s or 0)

    def available_channels(self, alert: Alert) -> list[str]:
        channels: list[str] = []
        if "email" in alert.channels and self.mail is not None:
            channels.append("email")
        if "webhook" in alert.channels and self.webhook is not None and bool(self._setting("alert_webhook_enabled")):
            channels.append("webhook")
        return channels

    def passes_severity(self, alert: Alert) -> bool:
        if alert.always_send:
            return True
        minimum = str(self._setting("alert_min_severity") or "warn")
        return _SEVERITY_RANK.get(alert.severity, 0) >= _SEVERITY_RANK.get(minimum, 1)

    # ------------------------------------------------------------------------------------------ sending

    async def _decide(self, alert: Alert, channels: list[str], now: int) -> gate.GateDecision:
        cooldown_s = self._cooldown_for(alert)
        uncapped = alert.always_send or alert.type == "leak_guard"
        cap = int(self._setting("alert_rate_limit_per_hour") or _SETTING_DEFAULTS["alert_rate_limit_per_hour"])
        if self._db is not None:
            try:
                decision: gate.GateDecision = await self._db.write(
                    lambda conn: gate.decide(
                        conn,
                        cooldown_key=alert.cooldown_key,
                        cooldown_s=cooldown_s,
                        channels=channels,
                        cap=cap,
                        uncapped=uncapped,
                        now=now,
                    ),
                    busy_timeout_ms=GATE_BUSY_TIMEOUT_MS,
                )
                return decision
            except Exception as exc:  # SharedStateUnavailable or a closed database: degrade open (plan C7)
                log.warning("alert_gate_unavailable", extra={"fields": {"error": type(exc).__name__}})
        # The same rules in this worker's memory: dedupe per worker (each worker may send its own copy, at most
        # once per cooldown key per gap) and this worker's share of the hourly cap, so the fleet stays within it.
        return self._memory_gate.decide(
            cooldown_key=alert.cooldown_key,
            cooldown_s=cooldown_s,
            channels=channels,
            cap=gate.worker_share(cap, self.workers),
            uncapped=uncapped,
            now=now,
        )

    async def send(self, alert: Alert) -> SendResult:
        """Gate, render and deliver one alert; returns what happened. Never raises for a delivery problem."""
        if self._closed:
            return SendResult(skipped="shutting_down")
        if not self.passes_severity(alert):
            return SendResult(skipped="severity")
        channels = self.available_channels(alert)
        if not channels:
            log.info("alert_no_channel", extra={"fields": {"type": alert.type, "subject": _clean(alert.subject)}})
            return SendResult(skipped="no_channel")
        now = self._clock.now()
        decision = await self._decide(alert, channels, int(now))
        if decision.deduped:
            return SendResult(skipped="deduped")
        if not decision.allowed:
            return SendResult(skipped="capped")
        tz_name = str(self._setting("ui_timezone") or "UTC")
        sent: list[str] = []
        errors: dict[str, str] = {}
        for channel in decision.allowed:
            suppressed = decision.suppressed.get(channel, 0)
            try:
                async with asyncio.timeout(self._send_timeout_s):
                    if channel == "email" and self.mail is not None:
                        subject, body = render_email(
                            alert, suppressed=suppressed, now=now, tz_name=tz_name, site_origin=self.site_origin
                        )
                        await self.mail.send(subject, body)
                    elif channel == "webhook" and self.webhook is not None:
                        payload = render_webhook(
                            alert, suppressed=suppressed, now=now, tz_name=tz_name, site_origin=self.site_origin
                        )
                        await self.webhook.send(payload)
                sent.append(channel)
            except (MailError, WebhookError, TimeoutError) as exc:
                errors[channel] = type(exc).__name__ if not str(exc) else _clean(exc, 100)
        log.info(
            "alert_sent",
            extra={
                "fields": {"type": alert.type, "channels": sent, "errors": sorted(errors), "severity": alert.severity}
            },
        )
        return SendResult(sent=tuple(sent), suppressed=max(decision.suppressed.values(), default=0), errors=errors)

    async def _send_quietly(self, alert: Alert) -> SendResult | None:
        try:
            async with asyncio.timeout(TASK_TIMEOUT_S):
                return await self.send(alert)
        except Exception:
            log.exception("alert_task_failed", extra={"fields": {"type": alert.type}})
            return None

    def notify(self, alert: Alert) -> asyncio.Task[Any] | None:
        """Send `alert` in the background (never blocks the caller). Returns the task, or None when dropped."""
        if self._closed:
            return None
        coro: Coroutine[Any, Any, SendResult | None] = self._send_quietly(alert)
        task: asyncio.Task[Any] | None
        if self._tasks is not None and hasattr(self._tasks, "spawn"):
            task = self._tasks.spawn(f"alert:{alert.type}", coro, group="alerts", limit=MAX_IN_FLIGHT)
        elif len(self._inflight) < MAX_IN_FLIGHT:
            task = asyncio.get_running_loop().create_task(coro, name=f"roxy:alert:{alert.type}")
        else:
            coro.close()
            task = None
        if task is None:
            self.dropped += 1
            log.warning("alert_dropped_busy", extra={"fields": {"type": alert.type}})
            return None
        self._inflight.add(task)  # strong reference: the event loop keeps only weak ones
        task.add_done_callback(self._inflight.discard)
        return task

    async def send_message(self, subject: str, body: str, *, to: str | None = None) -> None:
        """Send one direct email that is not an alert (the emailed login code). Raises `MailError` on failure."""
        if self.mail is None:
            raise MailError("mail is not configured")
        try:
            async with asyncio.timeout(self._send_timeout_s):
                await self.mail.send(subject, body, to=to)
        except TimeoutError as exc:
            raise MailError("timeout") from exc

    async def drain(self, timeout_s: float = 5.0) -> None:
        """Wait (bounded) for the background alerts this notifier started."""
        pending = [task for task in self._inflight if not task.done()]
        if pending:
            await asyncio.wait(pending, timeout=timeout_s)

    async def aclose(self) -> None:
        """Stop accepting alerts, give running ones a moment, and close the webhook client."""
        self._closed = True
        await self.drain()
        for task in list(self._inflight):
            if not task.done():
                task.cancel()
        if self.webhook is not None:
            with contextlib.suppress(Exception):
                await self.webhook.aclose()


# ------------------------------------------------------------------------------------------ unhandled errors

TRACEBACK_FRAMES = 6


def error_signature(exc: BaseException) -> tuple[str, str]:
    """(`<ExceptionType> at <module>:<line>`, `module:line`) for the innermost Roxy frame of `exc` (17.7)."""
    frames = traceback.extract_tb(exc.__traceback__) if exc.__traceback__ is not None else []
    ours = [frame for frame in frames if "roxy" in Path(frame.filename).parts]
    frame = (ours or frames)[-1] if (ours or frames) else None
    where = f"{Path(frame.filename).name}:{frame.lineno}" if frame is not None else "unknown"
    return f"{type(exc).__name__} at {where}", where


def error_alert(event: Any, site_origin: str) -> Alert | None:
    """The `Roxy Error: <signature>` alert for an unhandled exception (`core/errors.py` ErrorEvent), or None."""
    exc = getattr(event, "exc", None)
    if exc is None:
        return None
    signature, where = error_signature(exc)
    excerpt = "".join(traceback.format_exception(exc, limit=-TRACEBACK_FRAMES))[-2000:]
    return make_alert(
        "error",
        summary=f"Unhandled error while serving {getattr(event, 'method', '')} {getattr(event, 'path', '')}",
        fields={
            "Signature": signature,
            "Where": where,
            "Request id": getattr(event, "request_id", None) or "n/a",
            "Traceback (redacted)": excerpt,
        },
        link=f"{site_origin.rstrip('/')}/admin/system#errors",
        signature=signature,
    )


def install_error_alerts(app: Any, notifier: Notifier) -> None:
    """Register the server error hook on `app.state.error_hooks` (the lifespan calls this once per worker)."""
    site_origin = notifier.site_origin

    def hook(event: Any) -> None:
        alert = error_alert(event, site_origin)
        if alert is not None:
            notifier.notify(alert)  # fire and forget: the error answer has already been sent

    hooks = getattr(app.state, "error_hooks", None)
    if hooks is not None:
        hooks.add("server_error", hook)


def build_notifier(ctx: Any) -> Notifier:
    """A notifier for this worker from the systemd credentials (missing credentials leave a channel off)."""
    credentials_dir = getattr(ctx.env, "credentials_dir", None)
    config = load_mail_config(credentials_dir)
    url = load_webhook_url(credentials_dir)
    dbs = getattr(ctx, "dbs", None)
    return Notifier(
        hot_db=getattr(dbs, "hot", None),
        settings=ctx.settings,
        site_origin=str(getattr(ctx.env, "site_origin", "")),
        mail=MailSender(config) if config is not None else None,
        webhook=WebhookSender(url) if url else None,
        clock=getattr(ctx, "clock", SYSTEM_CLOCK),
        tasks=getattr(ctx, "tasks", None),
        workers=int(getattr(ctx.env, "workers", 1) or 1),
    )


def get_notifier(ctx: Any) -> Notifier:
    """`ctx.alerts`, built on first use when the lifespan did not build one."""
    existing = getattr(ctx, "alerts", None)
    if existing is not None:
        return cast(Notifier, existing)
    notifier = build_notifier(ctx)
    ctx.alerts = notifier
    return notifier


__all__ = [
    "Alert",
    "Notifier",
    "SendResult",
    "build_notifier",
    "error_alert",
    "get_notifier",
    "install_error_alerts",
    "render_email",
    "render_webhook",
]
