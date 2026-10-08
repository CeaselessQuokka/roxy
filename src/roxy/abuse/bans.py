"""Bans: temporary and permanent refusals by IP, CIDR, place id or User-Agent hash, plus the deny list.

What this is
    `find_ban` (the per-request lookup in the rules snapshot), `ua_hash` (how a User-Agent is named in a ban),
    `BanHits` (a bounded per-worker buffer of ban hit counts, flushed to control.db), `escalated_minutes` and
    `create_auto_ban` (automatic bans with doubling length for repeat offenders) and `create_ladder_ban` (a ladder rung
    whose action is `ban`). Plan 10.5, 10.3, 10.4.

Why it exists
    v1 had no bans: an abuser was throttled, waited, and came back. v2 lets the admin ban a subject outright and
    lets spam detectors ban an IP for a while, with escalation for repeat offenses (plan 10.3). Bans can be
    disguised as ordinary throttles (`ban_disguise_as_throttle`, default on) so an abuser does not learn to switch
    addresses.

How it works
    - Bans live in control.db `bans`; the rules snapshot indexes the active ones (`BanIndex`: one CIDR index for IP
      and CIDR bans, dictionaries for place ids and UA hashes) and checks expiry at lookup time.
    - Hit counts are not written per request (control.db fsyncs every commit): each worker counts in memory and
      `BanHits.flush` adds them in one transaction every few seconds. The buffer is bounded (plan P9).
    - Automatic bans go through `rules/service.py`, which folds a ban on an already banned subject into the active one
      (the later expiry wins) inside the same transaction, so two workers never create two bans.
    - Escalation: each earlier automatic ban of the same subject within 30 days doubles the length, up to the
      detector's cap (`spam_<id>_ban_max_minutes`).
    - Only IP bans are ever automatic (an IPv6 limit key, which is a network, becomes a CIDR ban); places are never
      banned automatically (place ids are claims anyone can forge).

What to read next
    `roxy/rules/store.py` (`BanIndex`), `roxy/abuse/spam.py` (who creates automatic bans), and
    `roxy/abuse/checks/bans.py` (the refusal).
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from typing import Final

from roxy.config.audit import Actor
from roxy.rules.models import BanRow
from roxy.rules.service import RuleChange, RulesService
from roxy.rules.store import RulesSnapshot
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

REPEAT_WINDOW_S: Final = 30 * 86_400
"""Plan 10.3: repeat offenses within 30 days double the ban."""

MAX_PENDING_HITS: Final = 10_000
"""Bound of the per-worker hit buffer (plan P9); beyond it new ban ids are counted as dropped."""

UA_HASH_LENGTH: Final = 16


def ua_hash(user_agent: str) -> str:
    """The name of a User-Agent in a `ua_hash` ban: SHA-256 of the exact UA text, first 16 hex characters.

    Not keyed: a UA is not secret, and the dashboard must be able to compute the hash of a UA the admin pastes.
    """
    return hashlib.sha256(user_agent.encode("utf-8", "surrogateescape")).hexdigest()[:UA_HASH_LENGTH]


def find_ban(snapshot: RulesSnapshot, *, ip: str, place: str | None, user_agent: str, now: float) -> BanRow | None:
    """The active ban covering this request: IP or CIDR first, then place id, then User-Agent hash."""
    return snapshot.bans.match(ip=ip or None, place=place or None, ua_hash=ua_hash(user_agent), now=now)


def escalated_minutes(base_minutes: int, max_minutes: int, previous_offenses: int) -> int:
    """`base x 2^previous`, capped at `max_minutes` (a cap of 0 means no cap). 0 when the base is 0."""
    if base_minutes <= 0:
        return 0
    minutes = int(base_minutes) * int(2 ** max(0, min(int(previous_offenses), 20)))
    return min(minutes, int(max_minutes)) if max_minutes > 0 else minutes


def ban_subject_for(limit_key: str) -> tuple[str, str]:
    """`(subject_type, subject)` for a client limit key: an address is an `ip` ban, a network a `cidr` ban."""
    return ("cidr", limit_key) if "/" in limit_key else ("ip", limit_key)


async def previous_offenses(control_db: Database, subject_type: str, subject: str, now: int) -> int:
    """Automatic bans of this subject created in the last 30 days (expired ones count; they are kept 30 days)."""

    def read(conn: sqlite3.Connection) -> int:
        row = conn.execute(
            "SELECT count(*) FROM bans WHERE subject_type = ? AND subject = ? AND created_at >= ? "
            "AND created_by LIKE 'auto:%'",
            (subject_type, subject, now - REPEAT_WINDOW_S),
        ).fetchone()
        return int(row[0])

    return await control_db.read(read)


async def create_auto_ban(
    service: RulesService,
    control_db: Database,
    *,
    limit_key: str,
    detector: str,
    reason_text: str,
    base_minutes: int,
    max_minutes: int,
    now: int,
) -> tuple[RuleChange | None, int]:
    """Ban a client for `detector` (for example `spam_rate`), escalating for repeat offenses.

    Returns `(change, minutes)`; `(None, 0)` when the detector's ban length is 0.
    """
    subject_type, subject = ban_subject_for(limit_key)
    offenses = await previous_offenses(control_db, subject_type, subject, now)
    minutes = escalated_minutes(base_minutes, max_minutes, offenses)
    if minutes <= 0:
        return None, 0
    row = {
        "subject_type": subject_type,
        "subject": subject,
        "reason_code": detector,
        "reason_text": reason_text[:400],
        "expires_at": now + minutes * 60,
    }
    change = await service.create("bans", row, Actor("system", f"auto:{detector}"), f"automatic ban by {detector}")
    return change, minutes


async def create_ladder_ban(service: RulesService, *, limit_key: str, minutes: int, rung: int, now: int) -> RuleChange:
    """A ladder rung with action `ban` (plan 10.4): a temporary IP (or IPv6 network) ban, never a place ban."""
    subject_type, subject = ban_subject_for(limit_key)
    row = {
        "subject_type": subject_type,
        "subject": subject,
        "reason_code": "throttle_ladder",
        "reason_text": f"Reached throttle ladder rung {rung}",
        "expires_at": now + int(minutes) * 60,
    }
    return await service.create("bans", row, Actor("system", "auto:throttle_ladder"), "throttle ladder ban rung")


class BanHits:
    """Per-worker ban hit counts waiting to be added to control.db (`hits`, `last_hit_at`)."""

    def __init__(self, max_pending: int = MAX_PENDING_HITS) -> None:
        self._pending: dict[int, list[int]] = {}
        self.max_pending = max_pending
        self.dropped = 0

    def record(self, ban_id: int, now: int) -> None:
        entry = self._pending.get(ban_id)
        if entry is None:
            if len(self._pending) >= self.max_pending:
                self.dropped += 1
                return
            self._pending[ban_id] = [1, now]
            return
        entry[0] += 1
        entry[1] = max(entry[1], now)

    def __len__(self) -> int:
        return len(self._pending)

    async def flush(self, control_db: Database) -> int:
        """Add the buffered hits in one transaction; on failure they are kept for the next flush."""
        if not self._pending:
            return 0
        batch, self._pending = self._pending, {}

        def write(conn: sqlite3.Connection) -> int:
            conn.executemany(
                "UPDATE bans SET hits = hits + ?, last_hit_at = max(coalesce(last_hit_at, 0), ?) WHERE id = ?",
                [(count, last, ban_id) for ban_id, (count, last) in batch.items()],
            )
            return len(batch)

        try:
            return await control_db.write(write)
        except SharedStateUnavailable:
            # Put them back (merging with anything recorded meanwhile); counts are statistics, never decisions.
            for ban_id, (count, last) in batch.items():
                entry = self._pending.setdefault(ban_id, [0, 0])
                entry[0] += count
                entry[1] = max(entry[1], last)
            return 0


__all__ = [
    "REPEAT_WINDOW_S",
    "BanHits",
    "ban_subject_for",
    "create_auto_ban",
    "create_ladder_ban",
    "escalated_minutes",
    "find_ban",
    "previous_offenses",
    "ua_hash",
]
