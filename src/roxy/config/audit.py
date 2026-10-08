"""The audit log writer: one function every admin and security-relevant action calls, inside its own transaction.

What this is
    `record(conn, actor, action, target, before, after, reason, request_id)` appends one row to the control.db
    `audit_log` table and returns its id. `Actor` says who acted (an admin, the CLI, the system, auto-apply, a
    recommendation or an import). `secret_summary()` builds the only shape a secret may take in the log.

Why it exists
    Plan 9.7: every admin action (settings, rules, bans, purges, resets, exports, credential replaces) and every
    security-relevant automatic action is written with who, from where, what changed, why, and the request id, so
    the owner can answer "who changed this and when" months later. Plan 6.2 adds the hard rule that a secret never
    reaches the audit log: for secret-bearing targets (the Roblox credential, the rotator URL, an admin password,
    a TOTP secret, recovery codes, the webhook URL, the SMTP password) `before_json` and `after_json` hold only
    `{fingerprint, masked}`. Test `test_secret_replace_leaves_no_trace` scans every database for the values.

How it works
    - `record` takes a `sqlite3.Connection` that is already inside a write transaction (`db.write(fn)`), so the
      audit row commits or rolls back together with the change it describes. It never opens its own transaction.
    - Secret targets are recognized by name (`is_secret_target`). Their before/after values must be `None` or a
      mapping with `fingerprint` and `masked` (build one with `secret_summary`); anything else raises
      `AuditSecretError` BEFORE any row is written, so a programming mistake fails loudly instead of leaking.
    - Every other before/after value is scrubbed defensively: values under secret-looking key names (`password`,
      `token`, `cookie`, ...) become `[redacted]`, and every string passes through `redact_text` (registered
      secrets, the Roblox cookie shape, `user:password@` in URLs). The JSON is bounded to 64 KiB (plan P9).
    - The table is append-only: triggers in the migration refuse UPDATE and refuse DELETE except by the 400-day
      retention job (storage/retention.py).

What to read next
    `roxy/config/settings_service.py` and `roxy/rules/service.py` (the two main callers), then
    `roxy/core/redact.py` (the scrubbing helpers used here).
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal, get_args
from urllib.parse import urlsplit

from roxy.config.constants import MAX_AUDIT_JSON_BYTES, MAX_REASON_LENGTH
from roxy.core.redact import MASK, fingerprint, is_secret_field, mask_token, redact_text

ActorKind = Literal["admin", "cli", "system", "auto_apply", "recommendation", "import"]
ACTOR_KINDS: Final[tuple[str, ...]] = get_args(ActorKind)

# Target kinds whose values are secrets (plan 6.2). A target is written `<kind>` or `<kind>:<qualifier>` (for
# example `credential`, `rotator_url`, `admin_user:3:totp_secret`); it is a secret target when ANY colon separated
# part is one of these names, so a qualifier cannot hide the kind.
SECRET_TARGET_KINDS: Final[frozenset[str]] = frozenset(
    {
        "credential",
        "rotator_url",
        "admin_password",
        "totp_secret",
        "recovery_codes",
        "webhook_url",
        "alert_webhook_url",
        "smtp_password",
    }
)

_ACTION = re.compile(r"[a-z][a-z0-9_.:-]{0,63}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")  # names, IPs and targets are single-line identifiers
MAX_TARGET_LENGTH: Final = 200
MAX_ACTOR_NAME: Final = 64
MAX_REQUEST_ID: Final = 64
MAX_SUMMARY_FIELD: Final = 64  # fingerprint (16 hex) and masked labels are short; anything longer is suspicious
_MAX_DEPTH: Final = 8
_TRUNCATED_PREVIEW: Final = 1000


class AuditSecretError(ValueError):
    """A secret-bearing target was given something other than `{fingerprint, masked}` (plan 6.2)."""


@dataclass(frozen=True, slots=True)
class Actor:
    """Who did something (DESIGN.md section 4): `kind`, a `name` within that kind, and the client IP if any.

    Examples: `Actor("admin", "owner", "203.0.113.7")`, `Actor("system", "auto:spam_rate")`,
    `Actor("recommendation", "UP-429-ENDPOINT")`, `Actor("cli", "ctl")`.
    """

    kind: ActorKind
    name: str = ""
    ip: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in ACTOR_KINDS:
            raise ValueError(f"unknown actor kind {self.kind!r}; expected one of {', '.join(ACTOR_KINDS)}")
        if len(self.name) > MAX_ACTOR_NAME or _CONTROL.search(self.name):
            raise ValueError("actor name must be at most 64 printable characters")
        if self.ip is not None and (len(self.ip) > 64 or _CONTROL.search(self.ip)):
            raise ValueError("actor ip must be at most 64 printable characters")

    @property
    def label(self) -> str:
        """`kind:name` (or just `kind`): what `updated_by`, `changed_by` and `created_by` columns store."""
        return f"{self.kind}:{self.name}" if self.name else self.kind

    @classmethod
    def system(cls, name: str = "roxy") -> Actor:
        """The system itself (seeding defaults, automatic actions without a more specific actor)."""
        return cls("system", name)


SYSTEM_ACTOR: Final[Actor] = Actor("system", "roxy")


def is_secret_target(target: str | None) -> bool:
    """True when `target` names a secret-bearing thing (plan 6.2), whose values may only be summarized."""
    if not target:
        return False
    return any(part.strip().lower() in SECRET_TARGET_KINDS for part in target.split(":"))


def secret_summary(
    value: str | bytes | None, key: bytes, *, url: bool = False, credential: bool = False
) -> dict[str, str] | None:
    """The only shape a secret may take in the audit log: `{fingerprint, masked}` (plan 6.2).

    `fingerprint` is HMAC-SHA256 with `key` (first 16 hex characters), so two summaries of the same value match
    and a guessed value cannot be checked without the key. `masked` shows as little as possible:
      * `credential=True` (the Roblox credential only): the v1 dashboard label, an ellipsis plus the last 6
        characters, which the owner compares with what Roblox shows;
      * `url=True` (the rotator URL, the webhook URL): the scheme and host only. Userinfo, path and query are
        dropped, because a webhook URL carries its secret token in the path;
      * anything else (passwords, TOTP secrets, recovery codes): no characters at all. The last 6 characters of a
        password or a TOTP secret are a sixth of the secret (security review L7).
    """
    if value is None:
        return None
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    if credential:
        masked = mask_token(text)
    elif url:
        masked = _scheme_and_host(text)
    else:
        masked = MASK
    return {"fingerprint": fingerprint(value, key), "masked": masked[:MAX_SUMMARY_FIELD]}


def _scheme_and_host(url: str) -> str:
    """`scheme://host[:port]` of `url`, or `[redacted]` when it does not parse as one."""
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return MASK
    if not parts.scheme or not host:
        return MASK
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}{f':{port}' if port is not None else ''}"


def _secret_side(value: Any, side: str) -> dict[str, str] | None:
    """Validate one side of a secret change; return exactly `{fingerprint, masked}` or None."""
    if value is None:
        return None
    if not isinstance(value, Mapping) or not {"fingerprint", "masked"} <= set(value):
        raise AuditSecretError(
            f"{side} of a secret-bearing target must be None or {{fingerprint, masked}} (use secret_summary); "
            "the value itself is never written to the audit log"
        )
    summary: dict[str, str] = {}
    for field in ("fingerprint", "masked"):
        item = value[field]
        if not isinstance(item, str) or len(item) > MAX_SUMMARY_FIELD:
            raise AuditSecretError(f"{side}.{field} must be a short string (at most {MAX_SUMMARY_FIELD} characters)")
        summary[field] = item
    return summary


def scrub(value: Any, depth: int = 0) -> Any:
    """A copy of `value` safe for the audit log: secret-looking keys masked, strings redacted, depth bounded."""
    if depth > _MAX_DEPTH:
        return "[too deep]"
    if isinstance(value, Mapping):
        return {
            str(key): MASK if is_secret_field(str(key), item) else scrub(item, depth + 1) for key, item in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [scrub(item, depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"  # raw bytes never go to the log (they could be anything)
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(str(value))


def encode(value: Any) -> str | None:
    """JSON text for a before/after column, bounded to `MAX_AUDIT_JSON_BYTES` (None stays NULL)."""
    if value is None:
        return None
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    size = len(text.encode("utf-8"))
    if size <= MAX_AUDIT_JSON_BYTES:
        return text
    # Bounded (plan P9): keep a readable preview instead of an unbounded document.
    return json.dumps({"truncated": True, "bytes": size, "preview": text[:_TRUNCATED_PREVIEW]}, ensure_ascii=False)


def record(
    conn: sqlite3.Connection,
    actor: Actor,
    action: str,
    target: str | None,
    before: Any,
    after: Any,
    reason: str | None,
    request_id: str | None,
    *,
    at: int | None = None,
    secret: bool | None = None,
) -> int:
    """Append one audit row inside the caller's transaction and return its id (DESIGN.md section 5).

    `action` is a short dotted name such as `setting.update`, `rule.create` or `credential.replace`; `target`
    names what changed (`setting:<key>`, `<table>:<id>`, `credential`). `secret=True` forces the secret rule for
    a target whose name does not say so; by default it follows `is_secret_target(target)`.
    """
    if not _ACTION.fullmatch(action):
        raise ValueError(f"audit action {action!r} must be a short lowercase dotted name")
    if target is not None and (len(target) > MAX_TARGET_LENGTH or _CONTROL.search(target)):
        raise ValueError("audit target must be at most 200 printable characters")
    is_secret = is_secret_target(target) if secret is None else secret
    if is_secret:
        before_value: Any = _secret_side(before, "before")
        after_value: Any = _secret_side(after, "after")
    else:
        before_value = scrub(before)
        after_value = scrub(after)
    reason_text = redact_text(reason)[:MAX_REASON_LENGTH] if reason else None
    request = request_id[:MAX_REQUEST_ID] if request_id else None
    cursor = conn.execute(
        "INSERT INTO audit_log (at, actor, actor_ip, action, target, before_json, after_json, reason, request_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            int(time.time()) if at is None else int(at),
            actor.label,
            actor.ip,
            action,
            target,
            encode(before_value),
            encode(after_value),
            reason_text,
            request,
        ),
    )
    row_id = cursor.lastrowid
    if row_id is None:  # pragma: no cover - sqlite3 always sets lastrowid after an INSERT
        raise RuntimeError("audit insert returned no row id")
    return int(row_id)


__all__ = [
    "ACTOR_KINDS",
    "SECRET_TARGET_KINDS",
    "SYSTEM_ACTOR",
    "Actor",
    "ActorKind",
    "AuditSecretError",
    "encode",
    "is_secret_target",
    "record",
    "scrub",
    "secret_summary",
]
