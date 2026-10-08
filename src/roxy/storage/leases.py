"""Leases: time-limited ownership of a named thing, shared by every worker through hot.db.

What this is
    Pure functions over a hot.db connection: `acquire`, `renew`, `release` and `holder_epoch` for a single
    named lease (the leader, a single-flight key, a probe singleton, cache init), and `acquire_slot` for counted
    leases (at most `cap` holders under one prefix, used for the fleet-wide tarpit cap).

Why it exists
    Several processes need "exactly one of us does this" (one leader runs scheduled jobs, one worker fetches a
    missed cache key) and "at most N of us do this" (tarpit holds). A lock held in memory dies with its process;
    a row with an expiry time does not need its owner to be alive to be released. If the owner crashes, the
    lease simply expires and someone else takes it over (plan 5.6, 6.9, 10.6).

How it works
    - A lease row is `(name, holder, expires_ms, epoch)`. It is valid while `now_ms < expires_ms`.
    - `acquire` inserts the row, or takes over an expired one. Every insert or takeover increments `epoch`, a
      fencing token: work started under epoch 7 can check before writing that the epoch is still 7, so a holder
      that stalled past its expiry (and was replaced) cannot write any more.
    - `release` sets `expires_ms` to 0 but keeps the row, so the epoch keeps counting up after a release.
    - The functions are plain SQL on a connection, so callers compose them inside their own
      `db.write(...)` transaction (BEGIN IMMEDIATE), for example "take the single-flight lease and the upstream
      bucket tokens in one transaction" (plan 6.3). The UPDATE statements are also conditional on the row they
      read, so they stay correct even if someone calls them outside a write transaction.

What to read next
    `roxy/scheduler/leader.py` (the leader election loop built on these), then `roxy/storage/retention.py`
    (`prune_expired_leases`).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

_PREFIX_END = "\U0010ffff"
"""The largest Unicode code point. `name >= prefix AND name < prefix + _PREFIX_END` selects every name that
starts with `prefix` using the primary key index (a range scan) instead of reading the whole table."""


@dataclass(frozen=True, slots=True)
class LeaseGrant:
    """A lease this holder now owns.

    `taken_over` is True when this call created the row or replaced an expired holder (the epoch was
    incremented); False when the same holder re-acquired its own still-valid lease (the epoch is unchanged).
    """

    name: str
    holder: str
    epoch: int
    expires_ms: int
    taken_over: bool


def _check_ttl(ttl_ms: int) -> None:
    if ttl_ms <= 0:
        raise ValueError("ttl_ms must be positive")


def acquire(
    conn: sqlite3.Connection,
    name: str,
    holder: str,
    ttl_ms: int,
    now_ms: int,
    payload_json: str | None = None,
) -> LeaseGrant | None:
    """Take lease `name` for `holder` until `now_ms + ttl_ms`, or return None if someone else holds it.

    - No row yet: insert it with epoch 1.
    - Row expired (whoever held it): take it over and increment the epoch.
    - Row valid and held by `holder`: extend it, same epoch.
    - Row valid and held by someone else: None.
    """
    _check_ttl(ttl_ms)
    expires_ms = now_ms + ttl_ms
    row = conn.execute("SELECT holder, expires_ms, epoch FROM lease WHERE name = ?", (name,)).fetchone()
    if row is None:
        cur = conn.execute(
            "INSERT INTO lease (name, holder, expires_ms, epoch, payload_json) VALUES (?, ?, ?, 1, ?) "
            "ON CONFLICT (name) DO NOTHING",
            (name, holder, expires_ms, payload_json),
        )
        if cur.rowcount == 1:
            return LeaseGrant(name, holder, 1, expires_ms, True)
        return None  # another connection inserted it between our SELECT and INSERT (only possible outside a tx)
    current_holder, current_expires, epoch = str(row[0]), int(row[1]), int(row[2])
    if current_expires > now_ms:
        if current_holder != holder:
            return None
        cur = conn.execute(
            "UPDATE lease SET expires_ms = ?, payload_json = coalesce(?, payload_json) "
            "WHERE name = ? AND holder = ? AND epoch = ?",
            (expires_ms, payload_json, name, holder, epoch),
        )
        return LeaseGrant(name, holder, epoch, expires_ms, False) if cur.rowcount == 1 else None
    # Expired: take it over. The WHERE clause repeats what we read (compare and swap), so two takeovers can never
    # both succeed even without an enclosing transaction.
    new_epoch = epoch + 1
    cur = conn.execute(
        "UPDATE lease SET holder = ?, expires_ms = ?, epoch = ?, payload_json = ? "
        "WHERE name = ? AND epoch = ? AND expires_ms <= ?",
        (holder, expires_ms, new_epoch, payload_json, name, epoch, now_ms),
    )
    return LeaseGrant(name, holder, new_epoch, expires_ms, True) if cur.rowcount == 1 else None


def renew(
    conn: sqlite3.Connection,
    name: str,
    holder: str,
    ttl_ms: int,
    now_ms: int,
    *,
    epoch: int | None = None,
) -> bool:
    """Extend a still-valid lease held by `holder` to `now_ms + ttl_ms`. False if it expired or changed hands.

    An expired lease is not renewed even if nobody took it over: the holder must `acquire` again, which bumps
    the epoch, so anything that ran while it was expired is fenced off. Pass `epoch` to also require that the
    lease is still the one you were granted.
    """
    _check_ttl(ttl_ms)
    sql = "UPDATE lease SET expires_ms = ? WHERE name = ? AND holder = ? AND expires_ms > ?"
    params: tuple[object, ...] = (now_ms + ttl_ms, name, holder, now_ms)
    if epoch is not None:
        sql += " AND epoch = ?"
        params += (epoch,)
    return conn.execute(sql, params).rowcount == 1


def release(conn: sqlite3.Connection, name: str, holder: str, *, delete: bool = False) -> None:
    """Give up lease `name` if `holder` holds it. Someone else's lease is never touched.

    By default the row stays (with `expires_ms = 0`) so the next holder's epoch is higher than every epoch
    before it. Pass `delete=True` for one-off names that do not need fencing (single-flight keys), so their rows
    do not linger until the retention job removes them.
    """
    if delete:
        conn.execute("DELETE FROM lease WHERE name = ? AND holder = ?", (name, holder))
    else:
        conn.execute("UPDATE lease SET expires_ms = 0 WHERE name = ? AND holder = ?", (name, holder))


def holder_epoch(conn: sqlite3.Connection, name: str) -> tuple[str, int, int] | None:
    """Return `(holder, epoch, expires_ms)` for lease `name`, or None if it never existed (or was pruned)."""
    row = conn.execute("SELECT holder, epoch, expires_ms FROM lease WHERE name = ?", (name,)).fetchone()
    if row is None:
        return None
    return str(row[0]), int(row[1]), int(row[2])


def is_valid(conn: sqlite3.Connection, name: str, holder: str, now_ms: int) -> bool:
    """True if `holder` currently holds a non-expired lease `name`."""
    row = conn.execute(
        "SELECT 1 FROM lease WHERE name = ? AND holder = ? AND expires_ms > ?", (name, holder, now_ms)
    ).fetchone()
    return row is not None


def count_slots(conn: sqlite3.Connection, prefix: str, now_ms: int) -> int:
    """How many valid (non-expired) leases exist under `prefix`."""
    row = conn.execute(
        "SELECT count(*) FROM lease WHERE name >= ? AND name < ? AND expires_ms > ?",
        (prefix, prefix + _PREFIX_END, now_ms),
    ).fetchone()
    return int(row[0])


def acquire_slot(
    conn: sqlite3.Connection,
    prefix: str,
    holder: str,
    cap: int,
    ttl_ms: int,
    now_ms: int,
) -> str | None:
    """Take one of at most `cap` counted leases named `<prefix>0` .. `<prefix><cap-1>`. Returns its name or None.

    Run it inside `db.write` (BEGIN IMMEDIATE): counting the valid slots and claiming a free one then happen
    under one write lock, so the number of valid slots can never exceed `cap`, however many workers try at once.
    Expired slots (a holder that crashed) are reused. Every valid row under the prefix counts, including slots
    numbered above a cap that was lowered since, so lowering the cap never lets extra holders in.

    Use a prefix that ends with a separator (for example `"tarpit:"`) and is not the start of another prefix.
    Release a slot with `release(conn, slot_name, holder, delete=False)`.
    """
    _check_ttl(ttl_ms)
    if cap <= 0:
        return None
    rows = conn.execute(
        "SELECT name, expires_ms FROM lease WHERE name >= ? AND name < ?", (prefix, prefix + _PREFIX_END)
    ).fetchall()
    in_use = {str(r[0]) for r in rows if int(r[1]) > now_ms}
    if len(in_use) >= cap:
        return None
    for index in range(cap):
        slot = f"{prefix}{index}"
        if slot in in_use:
            continue
        grant = acquire(conn, slot, holder, ttl_ms, now_ms)
        if grant is not None:
            return slot
    return None
