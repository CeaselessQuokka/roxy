"""Egress events and alerts: how the egress layer tells the admin something happened, without ever blocking.

What this is
    `EventSink`, a small adapter over `ctx.alerts` (the notifier, DESIGN.md 11.6) and `ctx.recorder` (the metrics
    recorder, DESIGN.md 8). `alert(...)` sends one alert in the background; `event(...)` records one notable event.
    `EgressAlert` mirrors the notifier's `Alert` fields for when that class is not importable yet.

Why it exists
    The leak guard, the credential probe and the rotator raise alerts from the request path (plan 17.7: "Roxy
    SECURITY: credential leak blocked", "Token Expired", "Roblox sent a new credential cookie"). Sending email must
    never delay or fail a request, and the egress package is built before the notifier, so it reaches both through
    getters that may return None.

How it works
    The getters are read on every call, so a notifier attached after startup is used from then on. `send` may be
    a plain function or a coroutine; a coroutine runs as a background task with a timeout, kept in a bounded set
    so it is not garbage collected mid-flight. Every alert is also logged (the log filter redacts the fields), so
    a trip leaves a journal line even with no notifier. Fields never contain request content or secrets.

What to read next
    `roxy/egress/guard.py` and `roxy/egress/credential.py` (the main callers).
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("roxy.egress.events")

ALERT_SEND_TIMEOUT_S = 10.0
MAX_PENDING_ALERTS = 64
_ALERT_MODULES = ("roxy.notify.models", "roxy.notify.alerts", "roxy.notify")


@dataclass(frozen=True, slots=True)
class EgressAlert:
    """The DESIGN.md 11.6 `Alert` fields, used when the notifier's own class cannot be imported."""

    type: str
    severity: str
    subject: str
    summary: str
    fields: dict[str, Any] = field(default_factory=dict)
    cooldown_key: str | None = None
    cooldown_s: int | None = None
    link: str | None = None
    always_send: bool = False


def _alert_class() -> Any:
    for name in _ALERT_MODULES:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        found = getattr(module, "Alert", None)
        if isinstance(found, type):
            return found
    return EgressAlert


def build_alert(**fields: Any) -> Any:
    """An `Alert` of the notifier if it accepts these fields, else an `EgressAlert`."""
    cls = _alert_class()
    if cls is not EgressAlert:
        try:
            return cls(**fields)
        except TypeError:
            log.warning("alert_class_mismatch", extra={"fields": {"class": getattr(cls, "__name__", "?")}})
    return EgressAlert(**fields)


class EventSink:
    """Fire-and-forget alerts and events (see the module docstring)."""

    def __init__(self, alerts: Callable[[], Any], recorder: Callable[[], Any]) -> None:
        self._alerts = alerts
        self._recorder = recorder
        self._pending: set[asyncio.Task[Any]] = set()
        self.sent = 0
        self.dropped = 0

    def alert(
        self,
        *,
        type: str,
        severity: str,
        subject: str,
        summary: str,
        fields: dict[str, Any] | None = None,
        cooldown_key: str | None = None,
        cooldown_s: int | None = None,
        link: str | None = None,
        always_send: bool = False,
    ) -> None:
        """Send one alert in the background (never raises, never waits)."""
        payload = dict(fields or {})
        level = logging.CRITICAL if severity == "critical" else logging.WARNING
        log.log(level, "egress_alert", extra={"fields": {"type": type, "subject": subject, **payload}})
        notifier = self._alerts()
        send = getattr(notifier, "send", None)
        if not callable(send):
            return
        alert = build_alert(
            type=type,
            severity=severity,
            subject=subject,
            summary=summary,
            fields=payload,
            cooldown_key=cooldown_key,
            cooldown_s=cooldown_s,
            link=link,
            always_send=always_send,
        )
        try:
            result = send(alert)
        except Exception:
            log.exception("egress_alert_failed", extra={"fields": {"type": type}})
            return
        self.sent += 1
        if inspect.isawaitable(result):
            self._track(result, type)

    def _track(self, awaitable: Any, kind: str) -> None:
        if len(self._pending) >= MAX_PENDING_ALERTS:
            self.dropped += 1
            if inspect.iscoroutine(awaitable):
                awaitable.close()
            log.error("egress_alert_dropped", extra={"fields": {"type": kind, "pending": len(self._pending)}})
            return

        async def run() -> None:
            async with asyncio.timeout(ALERT_SEND_TIMEOUT_S):
                await awaitable

        task = asyncio.get_running_loop().create_task(run(), name=f"roxy:egress-alert:{kind}")
        self._pending.add(task)

        def done(finished: asyncio.Task[Any]) -> None:
            self._pending.discard(finished)
            if not finished.cancelled() and finished.exception() is not None:
                log.error("egress_alert_send_failed", extra={"fields": {"type": kind}})

        task.add_done_callback(done)

    def event(self, type: str, severity: str, reason: str, detail: dict[str, Any]) -> None:
        """Record a notable event through `ctx.recorder.record_event` when the recorder exists."""
        recorder = self._recorder()
        record = getattr(recorder, "record_event", None)
        if not callable(record):
            return
        try:
            record(type, severity, reason, detail)
        except Exception:
            log.exception("egress_event_failed", extra={"fields": {"type": type}})

    async def drain(self, timeout_s: float = 5.0) -> None:
        """Wait for background alert sends (tests and shutdown)."""
        if not self._pending:
            return
        await asyncio.wait(set(self._pending), timeout=timeout_s)


__all__ = ["EgressAlert", "EventSink", "build_alert"]
