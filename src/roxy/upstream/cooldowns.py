"""Cooldowns: honoring Roblox's "slow down" for every worker at once (Retry-After, x-ratelimit-*, defaults).

What this is
    Parsers for `Retry-After` (delay seconds or an HTTP date, RFC 9110) and the `x-ratelimit-limit`,
    `x-ratelimit-remaining` and `x-ratelimit-reset` headers; the rule that turns them into a cooldown length; and
    functions over a hot.db connection that read and write the shared `cooldown` rows, count the evidence for
    escalating a cooldown to a whole host, and apply the rotator's distinct-exit rule.

Why it exists
    v1 never read Retry-After, and kept its "token cooldown" per worker for 15 s, so after a 429 the very next
    request from any of the 4 workers hit the same limit again (plan 2.5, R4). Plan 7.5: a 429 on the direct or
    credential path opens a cooldown on `endpoint:<template>:<egress>` in hot.db, so every worker stops
    contacting that endpoint through that egress until it ends; callers get the same `Retry-After` (F2).

How it works
    - Length: Retry-After if Roblox sent one, else `x-ratelimit-reset` when `x-ratelimit-remaining` is 0, else
      `cooldown_default_s` (30) doubled for each repeated 429 on the same key (30, 60, 120, ...) plus up to 10 %
      jitter. Everything is clamped to `[cooldown_min_s, cooldown_max_s]` (1 to 600 s). A credential 429 without a
      header uses `credential_cooldown_default_s` (60) instead.
    - "Repeated" means the previous cooldown on the key ended at most `cooldown_max_s` ago; the `hits` column
      counts the streak. A 429 that arrives while the cooldown is still active (a request that was already in
      flight) never shortens it and does not grow the streak.
    - Keys: `endpoint:<template>:<egress>`, `host:<host>:<egress>`, `egress:<egress>` and `credential` (plan 6.2).
      `set_at` holds the wall clock seconds of the latest 429 (a float), which is the evidence used to escalate:
      when `cooldown_host_escalation_endpoints` (3) templates of one host cooled down within
      `cooldown_host_escalation_window_s` (60 s), the host cools down as a whole.
    - Rotator 429s: each rotator session is a different exit IP, so one burned exit must not park the endpoint.
      Each 429 records `(template, exit)` as a short-lived row in the `lease` table under the prefix `r429:`
      (expiring after `rotator_cooldown_window_s`); only when `rotator_cooldown_distinct_exits` (3) different exits
      are recorded for a template does `endpoint:<template>:rotator` cool down. The lease table is reused because
      it already is "a named row that expires" with a counting helper and a pruning job; no new table is needed.

What to read next
    `roxy/upstream/effects.py` (where these are applied after each call), `roxy/upstream/breaker.py`, and
    `roxy/upstream/adaptive.py` (how the same evidence lowers bucket rates).
"""

from __future__ import annotations

import email.utils
import hashlib
import math
import re
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from typing import Any, Final

from roxy.core.reasons import Egress
from roxy.storage import leases
from roxy.upstream.backoff import UniformSource

CREDENTIAL_KEY: Final = "credential"
"""The fleet-wide credential cooldown row (plan 7.5: replaces v1's per-worker token drop)."""

ROTATOR_EXIT_PREFIX: Final = "r429:"
ROTATOR_EXIT_HOLDER: Final = "upstream:rotator-exits"
JITTER_FRACTION: Final = 0.1
"""Default cooldowns get up to 10 % added at random, so workers whose 429s arrived together do not all return
at the same instant."""

_PREFIX_END: Final = "\U0010ffff"
_NUMBER = re.compile(r"\s*(\d+(?:\.\d+)?)")
_DELAY_SECONDS = re.compile(r"\d+(?:\.\d+)?")
_EPOCH_THRESHOLD_S: Final = 1_000_000_000
"""An `x-ratelimit-reset` above this is an absolute Unix time, not a number of seconds (some APIs send either)."""


class CooldownSource(StrEnum):
    """Why a cooldown has the length it has (the `source` column, CHECK-constrained in hot.db)."""

    RETRY_AFTER = "retry_after"
    RATELIMIT_RESET = "ratelimit_reset"
    BREAKER = "breaker"
    DEFAULT = "default"


# --- keys ------------------------------------------------------------------------------------------------------------


def endpoint_key(template: str, egress: Egress | str) -> str:
    return f"endpoint:{template}:{Egress(egress).value}"


def host_key(host: str, egress: Egress | str) -> str:
    return f"host:{host}:{Egress(egress).value}"


def egress_key(egress: Egress | str) -> str:
    return f"egress:{Egress(egress).value}"


def keys_for(host: str, template: str, egress: Egress | str) -> tuple[str, ...]:
    """Every cooldown row that blocks a call to `template` on `host` through `egress`."""
    keys = (endpoint_key(template, egress), host_key(host, egress), egress_key(egress))
    return (*keys, CREDENTIAL_KEY) if Egress(egress) is Egress.CREDENTIAL else keys


# --- header parsing --------------------------------------------------------------------------------------------------


def parse_retry_after(value: str | None, now_s: float) -> float | None:
    """`Retry-After` as seconds from now: delay seconds or an HTTP date (RFC 9110 section 10.2.3).

    Returns None for a missing or unparseable value (garbage is ignored, never trusted as 0). A date in the past
    gives 0. Fractional seconds are accepted even though the RFC uses integers: being lenient costs nothing here.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if _DELAY_SECONDS.fullmatch(text):
        return float(text)
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when is None:  # pragma: no cover - older Pythons returned None instead of raising
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)  # HTTP dates are always GMT
    return max(0.0, when.timestamp() - now_s)


def _first_number(value: str | None) -> float | None:
    if value is None:
        return None
    match = _NUMBER.match(value)
    return float(match.group(1)) if match else None


@dataclass(frozen=True, slots=True)
class RateLimitInfo:
    """The `x-ratelimit-*` headers of one response (plan 7.5). Values are None when absent or unparseable."""

    limit: float | None
    remaining: float | None
    reset_s: float | None  # seconds from now until the window resets

    @property
    def exhausted(self) -> bool:
        """True when Roblox says no requests are left in the current window."""
        return self.remaining is not None and self.remaining <= 0

    def as_dict(self) -> dict[str, float | None]:
        return {"limit": self.limit, "remaining": self.remaining, "reset_s": self.reset_s}


def parse_ratelimit_headers(headers: Mapping[str, str], now_s: float) -> RateLimitInfo | None:
    """Read `x-ratelimit-limit`, `-remaining` and `-reset` (first number of each; any case). None if all absent.

    Values like `30, 30;w=60` (the IETF draft form) use their first number. A reset above 10^9 is an absolute Unix
    time and is converted to seconds from now.
    """
    lower = {name.lower(): value for name, value in headers.items()}
    limit = _first_number(lower.get("x-ratelimit-limit"))
    remaining = _first_number(lower.get("x-ratelimit-remaining"))
    reset_raw = _first_number(lower.get("x-ratelimit-reset"))
    if limit is None and remaining is None and reset_raw is None:
        return None
    reset_s = None
    if reset_raw is not None:
        reset_s = max(0.0, reset_raw - now_s) if reset_raw > _EPOCH_THRESHOLD_S else reset_raw
    return RateLimitInfo(limit, remaining, reset_s)


# --- the length of a cooldown ----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CooldownPolicy:
    """The cooldown settings of plan 15.3 B and C, read once per request."""

    default_s: float = 30.0
    min_s: float = 1.0
    max_s: float = 600.0
    credential_default_s: float = 60.0
    host_escalation_endpoints: int = 3
    host_escalation_window_s: float = 60.0
    rotator_distinct_exits: int = 3
    rotator_window_s: float = 60.0

    @classmethod
    def from_settings(cls, settings: Any) -> CooldownPolicy:
        return cls(
            default_s=float(settings.get("cooldown_default_s")),
            min_s=float(settings.get("cooldown_min_s")),
            max_s=float(settings.get("cooldown_max_s")),
            credential_default_s=float(settings.get("credential_cooldown_default_s")),
            host_escalation_endpoints=int(settings.get("cooldown_host_escalation_endpoints")),
            host_escalation_window_s=float(settings.get("cooldown_host_escalation_window_s")),
            rotator_distinct_exits=int(settings.get("rotator_cooldown_distinct_exits")),
            rotator_window_s=float(settings.get("rotator_cooldown_window_s")),
        )

    def clamp(self, seconds: float) -> float:
        """Clamp to `[cooldown_min_s, cooldown_max_s]` (the max wins if the two were ever set inverted)."""
        return min(self.max_s, max(self.min_s, seconds))


def cooldown_duration(
    retry_after_s: float | None,
    ratelimit: RateLimitInfo | None,
    repeat: int,
    policy: CooldownPolicy,
    rng: UniformSource,
    *,
    credential: bool = False,
) -> tuple[float, CooldownSource]:
    """How long to cool down after a 429, and why (plan 7.5).

    `repeat` is 1 for the first 429 of a streak, 2 for the next, and so on (see `repeat_count`).
    """
    if retry_after_s is not None:
        return policy.clamp(retry_after_s), CooldownSource.RETRY_AFTER
    if ratelimit is not None and ratelimit.exhausted and ratelimit.reset_s is not None:
        return policy.clamp(ratelimit.reset_s), CooldownSource.RATELIMIT_RESET
    base = policy.credential_default_s if credential else policy.default_s
    doublings = min(max(0, repeat - 1), 30)  # 30 doublings already exceed any cap; avoids huge floats
    seconds = min(base * (2**doublings), policy.max_s)
    seconds += rng.uniform(0.0, JITTER_FRACTION * seconds)
    return policy.clamp(seconds), CooldownSource.DEFAULT


# --- rows in hot.db --------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CooldownRow:
    """One `cooldown` row."""

    key: str
    until_ms: int
    source: str
    set_at: float  # wall clock seconds of the latest 429 (or other trigger)
    hits: int

    def active(self, now_ms: int) -> bool:
        return self.until_ms > now_ms

    def remaining_s(self, now_ms: int) -> float:
        return max(0.0, (self.until_ms - now_ms) / 1000)


def _to_row(raw: Any) -> CooldownRow:
    return CooldownRow(str(raw[0]), int(raw[1]), str(raw[2]), float(raw[3]), int(raw[4]))


def read_rows(conn: sqlite3.Connection, keys: Iterable[str]) -> dict[str, CooldownRow]:
    """The stored rows for `keys` (active or not)."""
    wanted = list(dict.fromkeys(keys))
    if not wanted:
        return {}
    marks = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        f"SELECT key, until_ms, source, set_at, hits FROM cooldown WHERE key IN ({marks})",  # noqa: S608 - only placeholders are interpolated
        wanted,
    ).fetchall()
    return {str(row[0]): _to_row(row) for row in rows}


def read_active(conn: sqlite3.Connection, keys: Iterable[str], now_ms: int) -> dict[str, CooldownRow]:
    """The rows among `keys` whose cooldown has not ended at `now_ms`."""
    return {key: row for key, row in read_rows(conn, keys).items() if row.active(now_ms)}


def repeat_count(existing: CooldownRow | None, now_ms: int, policy: CooldownPolicy) -> int:
    """The streak number of a new 429 on a key (1 = first). See the module docstring."""
    if existing is None:
        return 1
    if existing.active(now_ms):
        return max(1, existing.hits)  # an in-flight request's 429 inside the same cooldown: same episode
    if now_ms - existing.until_ms <= policy.max_s * 1000:
        return max(1, existing.hits) + 1
    return 1


@dataclass(frozen=True, slots=True)
class OpenedCooldown:
    """The result of `open_cooldown`."""

    row: CooldownRow
    was_active: bool  # the key was already cooling down (this 429 belongs to the same episode)


def open_cooldown(
    conn: sqlite3.Connection,
    key: str,
    seconds: float,
    source: CooldownSource | str,
    now_ms: int,
    hits: int,
) -> OpenedCooldown:
    """Start or extend the cooldown on `key` for `seconds` from `now_ms`. Never shortens an active one."""
    existing = read_rows(conn, [key]).get(key)
    was_active = existing is not None and existing.active(now_ms)
    until_ms = now_ms + math.ceil(max(0.0, seconds) * 1000)
    source_value = CooldownSource(source).value
    if existing is not None and was_active and existing.until_ms >= until_ms:
        until_ms, source_value = existing.until_ms, existing.source
    set_at = now_ms / 1000
    conn.execute(
        "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET until_ms = excluded.until_ms, source = excluded.source, "
        "set_at = excluded.set_at, hits = excluded.hits",
        (key, until_ms, source_value, set_at, max(1, hits)),
    )
    return OpenedCooldown(CooldownRow(key, until_ms, source_value, set_at, max(1, hits)), was_active)


def _endpoint_rows_since(conn: sqlite3.Connection, prefix: str, since_s: float) -> list[str]:
    rows = conn.execute(
        "SELECT key FROM cooldown WHERE key >= ? AND key < ? AND set_at >= ?",
        (prefix, prefix + _PREFIX_END, since_s),
    ).fetchall()
    return [str(row[0]) for row in rows]


def distinct_templates_cooling(conn: sqlite3.Connection, host: str, egress: Egress | str, since_s: float) -> int:
    """How many endpoint templates of `host` got a 429 through `egress` since `since_s` (host escalation evidence)."""
    suffix = ":" + Egress(egress).value
    return sum(1 for key in _endpoint_rows_since(conn, f"endpoint:{host}/", since_s) if key.endswith(suffix))


def distinct_hosts_cooling(conn: sqlite3.Connection, egress: Egress | str, since_s: float) -> int:
    """How many different hosts got a 429 through `egress` since `since_s` (egress attribution evidence)."""
    suffix = ":" + Egress(egress).value
    hosts = {
        key[len("endpoint:") :].split("/", 1)[0]
        for key in _endpoint_rows_since(conn, "endpoint:", since_s)
        if key.endswith(suffix)
    }
    return len(hosts)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def rotator_exit_prefix(template: str) -> str:
    """The lease name prefix of the exits that returned 429 for `template` (hashed: templates may contain ':')."""
    return f"{ROTATOR_EXIT_PREFIX}{_digest(template)}:"


def record_rotator_exit_429(conn: sqlite3.Connection, template: str, exit_id: str, now_ms: int, window_s: float) -> int:
    """Record that rotator exit `exit_id` got a 429 on `template`; return the distinct exits within the window."""
    prefix = rotator_exit_prefix(template)
    ttl_ms = max(1, round(window_s * 1000))
    leases.acquire(conn, prefix + _digest(exit_id), ROTATOR_EXIT_HOLDER, ttl_ms, now_ms)
    return leases.count_slots(conn, prefix, now_ms)


def active_rows(conn: sqlite3.Connection, now_ms: int, limit: int = 1000) -> list[CooldownRow]:
    """Every active cooldown, soonest end last (the admin Cooldowns card and the per-worker mirror)."""
    rows = conn.execute(
        "SELECT key, until_ms, source, set_at, hits FROM cooldown WHERE until_ms > ? ORDER BY until_ms DESC LIMIT ?",
        (now_ms, max(1, limit)),
    ).fetchall()
    return [_to_row(row) for row in rows]


def clear_all(conn: sqlite3.Connection) -> int:
    """Delete every cooldown and every rotator exit record (the "reset upstream state" action, row 34).

    Buckets are deliberately untouched: refilling them on a reset was v1's burst unlock (bug B21).
    """
    deleted = conn.execute("DELETE FROM cooldown").rowcount
    conn.execute(
        "DELETE FROM lease WHERE name >= ? AND name < ?", (ROTATOR_EXIT_PREFIX, ROTATOR_EXIT_PREFIX + _PREFIX_END)
    )
    return int(deleted)


__all__ = [
    "CREDENTIAL_KEY",
    "JITTER_FRACTION",
    "ROTATOR_EXIT_HOLDER",
    "ROTATOR_EXIT_PREFIX",
    "CooldownPolicy",
    "CooldownRow",
    "CooldownSource",
    "OpenedCooldown",
    "RateLimitInfo",
    "active_rows",
    "clear_all",
    "cooldown_duration",
    "distinct_hosts_cooling",
    "distinct_templates_cooling",
    "egress_key",
    "endpoint_key",
    "host_key",
    "keys_for",
    "open_cooldown",
    "parse_ratelimit_headers",
    "parse_retry_after",
    "read_active",
    "read_rows",
    "record_rotator_exit_429",
    "repeat_count",
    "rotator_exit_prefix",
]
