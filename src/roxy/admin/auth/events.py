"""Auth events: the audit row for every auth event, and the security events the dashboard's Security page shows.

What this is
    `audit_auth(conn, action, ...)` writes one `audit_log` row inside the caller's control.db transaction.
    `record_probe` and `record_login` hand security events to the metrics recorder (v1's "exploit log" and admin
    login list) and always write a structured log line. `record_admin_visit` and `discount_admin_visit` keep v1's
    Admin Page Visits counter (a visit of the login page by a browser that never signed in, minus the owner's own).

Why it exists
    Plan 9.7: every security-relevant action is audited with actor, IP, target, before and after, reason and
    request id. For logins that means successes, logouts, second factor failures, lockouts, the global guard,
    revocations, the kill switch, trusted devices, enrollment, recovery codes and passkeys. The exploit-log
    reason strings of v1 are kept exactly (plan 9.5): `Login attempts rate-limited`, `Malformed login payload`,
    `Missing challenge`, `IP mismatch on challenge`, `User-Agent mismatch on challenge`, `Invalid or expired
    challenge`, `Invalid 2FA code`.
    The audit log is append-only and kept at least 400 days with no row cap, so attacker-driven events must not
    write unbounded rows there. A wrong password therefore writes an audit row only for the first failure of a
    (username, network) key in its window and when the lockout engages (at most two rows per key per window);
    every attempt still becomes a capped `login` event in metrics.db and a log line.

How it works
    Audit actions are `auth.<event>`; targets are `admin_user:<id>` (or `admin_login:<network>` when no account
    matched). Usernames that do not exist are never written to the audit log (someone may have typed a password
    into the username field). The recorder may not exist yet (built in P7), or may be busy: events are best
    effort, logged and dropped on any error, and never fail a login.

What to read next
    `roxy/config/audit.py` (the writer and its secret rules), then `roxy/metrics/security_events.py`.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from roxy.config.audit import Actor, ActorKind, record
from roxy.metrics.visitors import PAGE_ADMIN

log = logging.getLogger("roxy.admin.auth")

# v1 exploit-log reasons (index.py), kept exactly.
REASON_RATE_LIMITED = "Login attempts rate-limited"
REASON_MALFORMED = "Malformed login payload"
REASON_MISSING_CHALLENGE = "Missing challenge"
REASON_IP_MISMATCH = "IP mismatch on challenge"
REASON_UA_MISMATCH = "User-Agent mismatch on challenge"
REASON_BAD_CHALLENGE = "Invalid or expired challenge"
REASON_BAD_CODE = "Invalid 2FA code"


def _actor(kind: ActorKind, username: str | None, ip: str | None) -> Actor:
    name = (username or "").strip()[:64]
    name = "".join(ch for ch in name if ch.isprintable())
    clean_ip = (ip or "")[:64] or None
    if kind == "admin" and not name:
        return Actor("system", "auth", clean_ip)
    return Actor(kind, name, clean_ip)


def audit_auth(
    conn: sqlite3.Connection,
    action: str,
    *,
    user_id: int | None,
    username: str | None,
    ip: str | None,
    request_id: str | None,
    reason: str | None = None,
    after: Any = None,
    before: Any = None,
    target: str | None = None,
    at: int | None = None,
    actor_kind: ActorKind = "admin",
) -> int:
    """Append one auth audit row inside the caller's control.db write transaction."""
    return record(
        conn,
        _actor(actor_kind, username, ip),
        action,
        target or (f"admin_user:{user_id}" if user_id is not None else None),
        before,
        after,
        reason,
        request_id,
        at=at,
    )


def _recorder(ctx: Any) -> Any | None:
    return getattr(ctx, "recorder", None)


def record_probe(ctx: Any, *, ip: str, reason: str, user_agent: str | None, path: str | None) -> None:
    """A v1-style exploit-log event (probe) for a refused or failed login step. Best effort."""
    log.info(
        "auth_probe",
        extra={"fields": {"reason": reason, "client_ip": ip, "path": path, "user_agent": (user_agent or "")[:200]}},
    )
    recorder = _recorder(ctx)
    method = getattr(recorder, "record_probe", None) if recorder is not None else None
    if method is None:
        return
    try:
        method(ip=ip, reason=reason, user_agent=user_agent, path=path)
    except Exception:  # events are best effort; a recorder problem must never fail a login
        log.debug("auth_probe_record_failed", exc_info=True)


def record_login(ctx: Any, *, ip: str, successful: bool, username: str | None, method: str) -> None:
    """An admin login attempt event (the Security page's login list). Best effort."""
    log.info(
        "auth_login_attempt",
        extra={"fields": {"client_ip": ip, "successful": successful, "method": method}},
    )
    recorder = _recorder(ctx)
    fn = getattr(recorder, "record_login", None) if recorder is not None else None
    if fn is None:
        return
    try:
        fn(ip=ip, successful=successful, username=username, method=method)
    except Exception:
        log.debug("auth_login_record_failed", exc_info=True)


def record_admin_visit(ctx: Any, *, user_agent: str | None) -> None:
    """One Admin Page Visit (the Overview Visitors card, parity rows 19 and 130). Best effort, memory only.

    The caller counts only a browser that has never signed in (no `roxy_admin_seen` cookie), as v1 did, so the
    owner's own visits do not inflate the tile."""
    recorder = _recorder(ctx)
    fn = getattr(recorder, "record_visit", None) if recorder is not None else None
    if fn is None:
        return
    try:
        fn(PAGE_ADMIN, user_agent)
    except Exception:  # a visit counter must never fail the login page
        log.debug("auth_admin_visit_record_failed", exc_info=True)


def discount_admin_visit(ctx: Any) -> None:
    """Take back the visit of a browser that just signed in for the first time (v1 `decrement_admin_visit`): it was
    the owner loading the login page, not a visitor. Best effort, memory only."""
    recorder = _recorder(ctx)
    fn = getattr(recorder, "record_admin_visit_discount", None) if recorder is not None else None
    if fn is None:
        return
    try:
        fn()
    except Exception:
        log.debug("auth_admin_visit_discount_failed", exc_info=True)
