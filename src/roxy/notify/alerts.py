"""The alert catalog (plan 17.7): every alert type with its exact subject, severity, cooldown key and channels.

What this is
    `Alert` (what a producer hands the notifier, DESIGN.md 11.6), `SendResult` (what came of it), `AlertSpec`
    (one row of the plan 17.7 table) and `ALERT_SPECS`, plus `make_alert(type, ...)`, which fills an `Alert`
    from its spec so producers cannot get a subject or cooldown key wrong.

Why it exists
    Owners filter mail on subjects, so the subjects v1 used are kept exactly: `Roxy Error: <signature>`,
    `Roxy: all upstream methods unavailable`, `Token Expired`, `Roxy Admin Login`, `Roxy DOWN: <unit> failed on
    <host>` (and `Admin 2FA`, which is not an alert, `roxy/admin/auth/email_codes.py`). Keeping every subject,
    severity and cooldown in one table means a reviewer checks them against the plan in one read, and a test
    pins them.

How it works
    - A spec's `subject` and `cooldown_key` are format strings filled from `make_alert`'s keyword arguments
      (`make_alert("error", signature="KeyError at cache.py:88", ...)`).
    - `cooldown_setting` names the runtime setting that overrides the default gap (`error_email_cooldown`,
      `email_cooldown`); the notifier reads it live on every send.
    - `always_send` alerts (new admin login, leak guard trip) ignore `alert_min_severity` and the hourly cap.
      Leak guard alerts are never capped (plan 17.7).
    - Severity is `info`, `warn` or `critical` (the `alert_min_severity` options).

What to read next
    `roxy/notify/notifier.py` (how an `Alert` becomes an email and a webhook call), then `roxy/notify/gate.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["info", "warn", "critical"]
SEVERITIES: tuple[str, ...] = ("info", "warn", "critical")
CHANNELS: tuple[str, ...] = ("email", "webhook")

HOUR_S = 3600
DAY_S = 86_400


@dataclass(frozen=True, slots=True)
class Alert:
    """One alert (DESIGN.md 11.6). Fields after `always_send` are v2 additions with safe defaults.

    `body`, when set, replaces the generated body (the login alert keeps v1's exact text); it is still redacted,
    except for `link`, which is built by Roxy from `ROXY_SITE_ORIGIN`.
    """

    type: str
    severity: str
    subject: str
    summary: str
    fields: dict[str, Any] = field(default_factory=dict)
    cooldown_key: str | None = None
    cooldown_s: int | None = None
    link: str | None = None
    always_send: bool = False
    channels: tuple[str, ...] = CHANNELS
    body: str | None = None
    runbook: str | None = None


@dataclass(frozen=True, slots=True)
class SendResult:
    """What happened to one alert: the channels it reached, why it was held back, and errors per channel."""

    sent: tuple[str, ...] = ()
    skipped: str | None = None  # "severity", "deduped", "capped", "no_channel", "shutting_down"
    suppressed: int = 0  # alerts of this key or channel held back since the last one that went out
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def delivered(self) -> bool:
        return bool(self.sent)


@dataclass(frozen=True, slots=True)
class AlertSpec:
    """One row of the plan 17.7 table."""

    type: str
    subject: str
    severity: str
    cooldown_key: str | None
    cooldown_s: int | None
    channels: tuple[str, ...] = CHANNELS
    cooldown_setting: str | None = None
    always_send: bool = False
    runbook: str = ""


ALERT_SPECS: dict[str, AlertSpec] = {
    spec.type: spec
    for spec in (
        AlertSpec(
            "error",
            "Roxy Error: {signature}",
            "warn",
            "error:{signature}",
            300,
            cooldown_setting="error_email_cooldown",
            runbook="unhandled-errors",
        ),
        AlertSpec(
            "all_unavailable",
            "Roxy: all upstream methods unavailable",
            "critical",
            "all_unavailable",
            300,
            cooldown_setting="error_email_cooldown",
            runbook="all-upstream-unavailable",
        ),
        AlertSpec(
            "credential_rejected",
            "Token Expired",
            "critical",
            "credential:rejected",
            600,
            cooldown_setting="email_cooldown",
            runbook="credential-rejected",
        ),
        AlertSpec(
            "credential_cooldown",
            "Roxy: credential cooling down",
            "warn",
            "credential:cooldown",
            600,
            cooldown_setting="email_cooldown",
            runbook="credential-cooldown",
        ),
        AlertSpec(
            "credential_rotated",
            "Roxy: Roblox sent a new credential cookie",
            "critical",
            "credential:rotated",
            HOUR_S,
            runbook="credential-rotated",
        ),
        AlertSpec(
            "admin_login",
            "Roxy Admin Login",
            "info",
            None,
            None,
            channels=("email",),
            always_send=True,
            runbook="unexpected-admin-login",
        ),
        AlertSpec(
            "service_down",
            "Roxy DOWN: {unit} failed on {host}",
            "critical",
            "service_down:{unit}",
            600,
            runbook="service-down",
        ),
        AlertSpec(
            "deploy_failed",
            "Roxy: deploy {short_sha} failed at step {step}",
            "critical",
            "deploy:{short_sha}",
            DAY_S,
            runbook="deploy-failed",
        ),
        AlertSpec(
            "leak_guard",
            "Roxy SECURITY: credential leak blocked",
            "critical",
            None,
            None,
            always_send=True,
            runbook="leak-guard",
        ),
        AlertSpec(
            "roblox_429", "Roxy: Roblox is rate-limiting us ({rate}%)", "warn", "roblox_429", 1800, runbook="roblox-429"
        ),
        AlertSpec("caller_5xx", "Roxy: caller errors at {rate}%", "warn", "caller_5xx", 1800, runbook="caller-5xx"),
        AlertSpec(
            "rotator_quota",
            "Roxy: rotator at {pct}% of monthly quota",
            "warn",
            "quota:{pct}",
            31 * DAY_S,
            runbook="rotator-quota",
        ),
        AlertSpec("disk", "Roxy: storage at {pct}% of budget", "warn", "disk", 6 * HOUR_S, runbook="disk"),
        AlertSpec(
            "db_integrity",
            "Roxy: database integrity check failed",
            "critical",
            "db_integrity",
            HOUR_S,
            runbook="db-integrity",
        ),
        AlertSpec("backup_failed", "Roxy: backup failed", "warn", "backup", 6 * HOUR_S, runbook="backup"),
        AlertSpec("backup_stale", "Roxy: no backup for {hours} h", "warn", "backup", 6 * HOUR_S, runbook="backup"),
        AlertSpec(
            "health_failures",
            "Roxy: health check found {n} new failures",
            "warn",
            "health:{fingerprint}",
            DAY_S,
            runbook="health-failures",
        ),
        AlertSpec(
            "auto_apply_rollback",
            "Roxy: auto-applied change rolled back",
            "warn",
            "rollback:{rec_id}",
            DAY_S,
            runbook="auto-apply-rollback",
        ),
        AlertSpec(
            # Plan 11.4 "the admin is notified": the guard metric got worse but the automatic undo was refused (an
            # admin changed the row during the watch window), so the change is still in place (finding insights-5).
            "auto_apply_rollback_failed",
            "Roxy: auto-applied change could not be rolled back",
            "critical",
            "rollback_failed:{rec_id}",
            DAY_S,
            runbook="auto-apply-rollback",
        ),
        AlertSpec(
            "login_global",
            "Roxy: login attempts throttled globally",
            "warn",
            "login_global",
            HOUR_S,
            runbook="login-throttled",
        ),
        AlertSpec(
            "digest",
            "Roxy daily digest: {n} open recommendations",
            "info",
            "digest:{day}",
            DAY_S,
            channels=("email",),
            runbook="daily-digest",
        ),
    )
}
"""Every alert type of plan 17.7, keyed by type."""


def _fill(template: str, params: dict[str, Any]) -> str:
    try:
        return template.format(**params)
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError(f"alert template {template!r} needs {exc}") from exc


def make_alert(
    alert_type: str,
    *,
    summary: str,
    fields: dict[str, Any] | None = None,
    link: str | None = None,
    severity: str | None = None,
    body: str | None = None,
    **params: Any,
) -> Alert:
    """An `Alert` of a catalog type. `params` fill the subject and cooldown key templates."""
    spec = ALERT_SPECS.get(alert_type)
    if spec is None:
        raise KeyError(f"unknown alert type {alert_type!r}")
    chosen = severity or spec.severity
    if chosen not in SEVERITIES:
        raise ValueError(f"unknown severity {chosen!r}")
    clean = {key: str(value).replace("\r", " ").replace("\n", " ")[:120] for key, value in params.items()}
    return Alert(
        type=alert_type,
        severity=chosen,
        subject=_fill(spec.subject, clean),
        summary=summary,
        fields=dict(fields or {}),
        cooldown_key=_fill(spec.cooldown_key, clean)[:200] if spec.cooldown_key else None,
        cooldown_s=spec.cooldown_s,
        link=link,
        always_send=spec.always_send,
        channels=spec.channels,
        body=body,
        runbook=spec.runbook or None,
    )
