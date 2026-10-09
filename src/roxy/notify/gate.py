"""The alert gate: fleet-wide dedupe by cooldown key and the per-channel hourly cap, in one hot.db transaction.

What this is
    `decide(conn, ...)`, a pure function over a hot.db connection (run it inside `db.write`), returning which
    channels may send this alert now and how many alerts were held back since the last one that went out. Plus
    `MemoryGate`, the per-worker fallback with the same rules used only while hot.db cannot be written (plan C7),
    `worker_share`, the part of the hourly cap one worker may use while it counts alone, and `merge`, which folds
    what a `MemoryGate` decided (its `GateJournal`) into the shared rows once hot.db can be written again.

Why it exists
    Every worker process sees the same errors. Without a shared gate, two workers send two copies of every alert,
    and a long incident sends one mail per error. Plan 17.7: one alert per cooldown key per gap for the whole
    fleet (plan C6), and at most `alert_rate_limit_per_hour` messages per channel per hour, except leak guard
    trips. What is held back is counted and reported in the next message ("Suppressed since last alert: N").

How it works
    Rows in hot.db `email_gate (key, last_sent_at, suppressed)`:
      * `alert:<cooldown key>`: `last_sent_at` is when this key last went out; `suppressed` counts alerts of the
        key held back since then.
      * `cap:<channel>`: the channel's current one-hour window. `last_sent_at` is the window START and
        `suppressed` holds the number of messages SENT in that window (the column is reused as a counter here).
      * `capdrop:<channel>`: messages the cap held back since the channel last sent one (`suppressed`).
      * `capmem:<channel>`: messages reserved for workers that may still hold unreported sends from an outage
        (below). `last_sent_at` is the `cap:` window START it belongs to, `suppressed` the reserved count; the
        cap counts `sent + reserved`.
    The whole decision (read, compare, update) happens in one BEGIN IMMEDIATE transaction, so two workers can
    never both decide to send. A key held back by the cap is not marked as sent, so it goes out as soon as the
    cap allows. The leader prunes `alert:` rows 45 days after they last went out, longer than any alert cooldown
    (`storage/retention.py ALERT_GATE_KEEP_S`, review finding AUTH-2: the rotator quota alert waits up to 40 days),
    and the `cap:`, `capdrop:` and `capmem:` rows after a day idle; the table also has a row cap.
    While hot.db cannot be written, `MemoryGate.decide` applies the same rules in one worker's memory: the cap
    still holds (each worker gets `worker_share` of it, so the fleet stays within the setting), but dedupe is per
    worker, so each worker may send its own copy of an alert, at most once per cooldown key per gap.
    Coming back (finding mp-10): everything the memory gate decided is kept in its `GateJournal` (the send times
    per channel, the cooldown keys it sent or held back, the cap's held-back counts) and `merge` adds it to the
    shared rows in the same transaction as the worker's next shared decision (or earlier, from the notifier's
    retry): sends count in the current `cap:` window, a key keeps the later of the two sent times and the sum of
    the held-back counts. One worker cannot know what the OTHER workers sent from memory, so the first worker of
    a window to report also reserves their shares, `(workers - 1) x share` in `capmem:`, and every other worker
    that reports for that window releases its own share and adds its real count. The fleet thus never sends more
    than the cap in an hour that contains an outage; the price is that a worker that never reports (it sent and
    held nothing during the outage) keeps its share reserved until the window ends. A second outage in the same
    window is not reserved again (each worker reports once per window).

What to read next
    `roxy/notify/notifier.py` (the caller), then `roxy/storage/migrations/hot/0001_initial.sql` (`email_gate`).
"""

from __future__ import annotations

import sqlite3
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

ALERT_PREFIX = "alert:"
CAP_PREFIX = "cap:"
CAPDROP_PREFIX = "capdrop:"
CAPMEM_PREFIX = "capmem:"
CAP_WINDOW_S = 3600
MAX_JOURNAL_SENDS = 1024
"""Send times one channel's journal keeps at most (plan P9); a worker's share per hour is far below it."""


@dataclass(frozen=True, slots=True)
class GateDecision:
    """`allowed` channels may send now; `suppressed` per allowed channel is the count to report."""

    allowed: tuple[str, ...]
    deduped: bool = False
    capped: tuple[str, ...] = ()
    suppressed: dict[str, int] = field(default_factory=dict)


def _get(conn: sqlite3.Connection, key: str) -> tuple[int, int] | None:
    row = conn.execute("SELECT last_sent_at, suppressed FROM email_gate WHERE key = ?", (key,)).fetchone()
    return None if row is None else (int(row[0]), int(row[1]))


def _set(conn: sqlite3.Connection, key: str, last_sent_at: int, suppressed: int) -> None:
    conn.execute(
        "INSERT INTO email_gate (key, last_sent_at, suppressed) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET "
        "last_sent_at = excluded.last_sent_at, suppressed = excluded.suppressed",
        (key, last_sent_at, suppressed),
    )


def _bump_suppressed(conn: sqlite3.Connection, key: str, now: int) -> None:
    conn.execute(
        "INSERT INTO email_gate (key, last_sent_at, suppressed) VALUES (?, ?, 1) ON CONFLICT (key) DO UPDATE SET "
        "suppressed = suppressed + 1",
        (key, now),
    )


def _reserved(conn: sqlite3.Connection, channel: str, window_start: int) -> int:
    """Messages `capmem:<channel>` reserves in the window that starts at `window_start` (0 for another window)."""
    row = _get(conn, f"{CAPMEM_PREFIX}{channel}")
    return row[1] if row is not None and row[0] == window_start else 0


def _cap_allows(conn: sqlite3.Connection, channel: str, cap: int, now: int) -> bool:
    """Count one message in the channel's hourly window if there is room; return whether there was."""
    key = f"{CAP_PREFIX}{channel}"
    row = _get(conn, key)
    start, sent = (now, 0) if row is None or now - row[0] >= CAP_WINDOW_S else row
    if sent + _reserved(conn, channel, start) >= max(1, cap):
        return False
    _set(conn, key, start, sent + 1)
    return True


def decide(
    conn: sqlite3.Connection,
    *,
    cooldown_key: str | None,
    cooldown_s: int,
    channels: Sequence[str],
    cap: int,
    uncapped: bool,
    now: int,
) -> GateDecision:
    """Decide, atomically for the fleet, which channels send this alert now (see the module docstring)."""
    if not channels:
        return GateDecision(allowed=())
    alert_key = f"{ALERT_PREFIX}{cooldown_key}" if cooldown_key else None
    key_suppressed = 0
    if alert_key is not None:
        row = _get(conn, alert_key)
        # A clock that stepped back a little (now before last_sent_at) still counts as inside the gap.
        if row is not None and row[0] > 0 and now - row[0] < max(0, cooldown_s):
            _bump_suppressed(conn, alert_key, now)
            return GateDecision(allowed=(), deduped=True)
        key_suppressed = row[1] if row is not None else 0
    allowed: list[str] = []
    capped: list[str] = []
    suppressed: dict[str, int] = {}
    for channel in channels:
        if uncapped or _cap_allows(conn, channel, cap, now):
            allowed.append(channel)
            drop_key = f"{CAPDROP_PREFIX}{channel}"
            drops = _get(conn, drop_key)
            if drops is not None and drops[1]:
                _set(conn, drop_key, now, 0)
            suppressed[channel] = key_suppressed + (drops[1] if drops is not None else 0)
        else:
            capped.append(channel)
            _bump_suppressed(conn, f"{CAPDROP_PREFIX}{channel}", now)
    if alert_key is not None:
        if allowed:
            _set(conn, alert_key, now, 0)
        else:
            # Held back by the cap: not marked as sent, so it goes out once the cap allows, with this count.
            conn.execute(
                "INSERT INTO email_gate (key, last_sent_at, suppressed) VALUES (?, 0, 1) ON CONFLICT (key) DO UPDATE "
                "SET suppressed = suppressed + 1",
                (alert_key,),
            )
    return GateDecision(allowed=tuple(allowed), capped=tuple(capped), suppressed=suppressed)


def worker_share(cap: int, workers: int) -> int:
    """This worker's part of a fleet-wide hourly cap while each worker counts alone: `cap // workers`, at least 1.

    The per-IP limiter's degraded mode divides the same way (plan C7: `limit / workers`), so the fleet as a whole
    stays within `alert_rate_limit_per_hour` (C6) unless the cap is smaller than the number of workers. Unlike
    the limiter, whose share may be 0 and then refuses (review finding mp-2: a refused request can retry, a
    multiplied limit cannot be undone), an alert share never drops to 0: a hot.db outage is when the owner most
    needs to hear from Roxy, and after the outage `merge` charges every memory send to the shared hour (mp-10).
    """
    return max(1, int(cap) // max(1, int(workers)))


@dataclass(slots=True)
class GateJournal:
    """What a `MemoryGate` decided that the shared gate has not seen yet (`merge` writes it).

    `sends`: per channel, the times this worker sent through the memory gate (a channel that only held messages
    back has an empty list, it still reports). `keys`: per cooldown key, `(sent_at, held)`: when this worker last
    sent it from memory (0 for not since the last merge) and how many of it were held back since that send (or
    since the last merge). `capdrops`: per channel, messages the memory cap held back that no send reported yet.
    """

    sends: dict[str, list[int]] = field(default_factory=dict)
    keys: OrderedDict[str, tuple[int, int]] = field(default_factory=OrderedDict)
    capdrops: dict[str, int] = field(default_factory=dict)

    def empty(self) -> bool:
        return not (self.sends or self.keys or any(self.capdrops.values()))

    def absorb(self, later: GateJournal, *, max_keys: int) -> GateJournal:
        """This journal followed by `later` (a merge that failed is put back in front of what came since)."""
        for channel, times in later.sends.items():
            self.sends[channel] = [*self.sends.get(channel, []), *times][-MAX_JOURNAL_SENDS:]
        for key, (sent_at, held) in later.keys.items():
            old_sent, old_held = self.keys.get(key, (0, 0))
            # A later send reported everything held back before it (the memory row keeps counting across merges).
            self.keys[key] = (sent_at, held) if sent_at else (old_sent, old_held + held)
            self.keys.move_to_end(key)
        while len(self.keys) > max_keys:
            self.keys.popitem(last=False)
        for channel, count in later.capdrops.items():
            self.capdrops[channel] = self.capdrops.get(channel, 0) + count
        return self


def merge(
    conn: sqlite3.Connection,
    journal: GateJournal,
    *,
    now: int,
    workers: int,
    share: int,
    reported: Mapping[str, int],
) -> dict[str, int]:
    """Fold one worker's `GateJournal` into the shared rows (inside the caller's hot.db write transaction).

    `reported` maps each channel to the `cap:` window this worker already reported for; the updated mapping is
    returned. See the module docstring for the rules (sends, cooldown keys, held-back counts, reservations).
    """
    done = dict(reported)
    for channel, times in journal.sends.items():
        # A clock that stepped back a little (a time after `now`) still counts as recent.
        recent = [t for t in times if now - t < CAP_WINDOW_S]
        key = f"{CAP_PREFIX}{channel}"
        row = _get(conn, key)
        if row is None or now - row[0] >= CAP_WINDOW_S:
            if not recent:
                continue  # nothing of this worker's falls in an open window
            start, sent = min(recent), 0  # the window this worker's sends opened
        else:
            start, sent = row
        _set(conn, key, start, sent + len(recent))
        if done.get(channel) == start:
            continue  # this worker already reported for this window: its share is settled
        reserve_key = f"{CAPMEM_PREFIX}{channel}"
        reserve = _get(conn, reserve_key)
        if reserve is None or reserve[0] != start:
            # The first worker back in this window: hold the other workers' shares until each of them reports.
            _set(conn, reserve_key, start, max(0, int(workers) - 1) * max(0, int(share)))
        else:
            # Another worker reserved this worker's share; it is replaced by the real count just added.
            _set(conn, reserve_key, start, max(0, reserve[1] - max(0, int(share))))
        done[channel] = start
    for cooldown_key, (sent_at, held) in journal.keys.items():
        key = f"{ALERT_PREFIX}{cooldown_key}"
        row = _get(conn, key)
        last, suppressed = row if row is not None else (0, 0)
        _set(conn, key, max(last, sent_at), suppressed + held)
    for channel, count in journal.capdrops.items():
        if count > 0:
            conn.execute(
                "INSERT INTO email_gate (key, last_sent_at, suppressed) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE "
                "SET suppressed = suppressed + excluded.suppressed",
                (f"{CAPDROP_PREFIX}{channel}", now, count),
            )
    return done


class MemoryGate:
    """`decide` for one worker, in memory, used only while hot.db cannot be written (plan C7).

    The same rules as the shared gate, kept in this worker's memory: dedupe by cooldown key, the per-channel hourly
    cap with the count of what it held back, and the "Suppressed since last alert" numbers. What changes while
    shared state is down:
      * dedupe is per worker: each worker may send its own copy of an alert, at most once per cooldown key per
        gap (two workers, at most two copies), instead of one for the fleet;
      * the cap is per worker too, so the notifier passes this worker's share (`worker_share`) and the fleet total
        stays within `alert_rate_limit_per_hour`.
    Leak guard trips stay uncapped. Every decision is also written to a `GateJournal`, which the notifier takes
    (`take_journal`) and merges into hot.db (`merge`) as soon as it can write there again, so the shared gate
    counts what this worker sent during the outage (finding mp-10); a failed merge puts it back
    (`restore_journal`). Everything is bounded (plan P9): at most `max_keys` cooldown keys in memory and in the
    journal (least recently used dropped first; a forgotten key only means its next alert is not deduped), one
    window per channel name, and `MAX_JOURNAL_SENDS` send times per channel.
    """

    def __init__(self, max_keys: int = 256, max_channels: int = 8) -> None:
        self._max = max(1, int(max_keys))
        self._max_channels = max(1, int(max_channels))
        self._alerts: OrderedDict[str, tuple[int, int]] = OrderedDict()  # key -> (last_sent_at, suppressed)
        self._caps: dict[str, tuple[int, int]] = {}  # channel -> (window start, messages sent in the window)
        self._capdrops: dict[str, int] = {}  # channel -> messages the cap held back since the channel last sent
        self._journal = GateJournal()
        self.reported: dict[str, int] = {}  # channel -> the shared `cap:` window this worker already reported for

    def _remember(self, key: str, last_sent_at: int, suppressed: int) -> None:
        self._alerts[key] = (last_sent_at, suppressed)
        self._alerts.move_to_end(key)
        while len(self._alerts) > self._max:
            self._alerts.popitem(last=False)

    # ------------------------------------------------------------------------------------------- journal

    def _journal_send(self, channel: str, now: int) -> None:
        if channel not in self._journal.sends and len(self._journal.sends) >= self._max_channels:
            return
        times = self._journal.sends.setdefault(channel, [])
        times.append(now)
        if len(times) > MAX_JOURNAL_SENDS:
            del times[: len(times) - MAX_JOURNAL_SENDS]

    def _journal_channel(self, channel: str) -> None:
        """A channel this worker decided for (even only held back): it reports for the window too."""
        if channel in self._journal.sends or len(self._journal.sends) < self._max_channels:
            self._journal.sends.setdefault(channel, [])

    def _journal_key(self, key: str, *, sent_at: int = 0, held: int = 0) -> None:
        keys = self._journal.keys
        old_sent, old_held = keys.get(key, (0, 0))
        keys[key] = (sent_at, 0) if sent_at else (old_sent, old_held + held)
        keys.move_to_end(key)
        while len(keys) > self._max:
            keys.popitem(last=False)

    def journal_empty(self) -> bool:
        """True when nothing this worker decided in memory is waiting to reach the shared gate."""
        return self._journal.empty() and not any(self._capdrops.values())

    def take_journal(self) -> GateJournal:
        """Hand over everything not merged yet (the held-back counts move with it); call `restore_journal` if the
        merge fails."""
        journal, self._journal = self._journal, GateJournal()
        journal.capdrops = {channel: count for channel, count in self._capdrops.items() if count}
        self._capdrops.clear()
        return journal

    def restore_journal(self, journal: GateJournal) -> None:
        """Put back a journal whose merge failed, in front of whatever was decided since it was taken."""
        later, self._journal = self._journal, journal
        held = journal.capdrops
        journal.capdrops = {}
        self._journal.absorb(later, max_keys=self._max)
        for channel, count in held.items():
            self._capdrops[channel] = self._capdrops.get(channel, 0) + count

    def merged(self, reported: Mapping[str, int]) -> None:
        """A merge landed: remember which shared windows this worker has reported for."""
        self.reported = dict(reported)

    def _cap_allows(self, channel: str, cap: int, now: int) -> bool:
        """Count one message in the channel's hourly window if there is room (same rule as `_cap_allows`)."""
        start, sent = self._caps.get(channel, (now, 0))
        if now - start >= CAP_WINDOW_S:
            start, sent = now, 0
        if sent >= max(1, cap):
            return False
        if channel not in self._caps and len(self._caps) >= self._max_channels:
            self._caps.pop(next(iter(self._caps)))
        self._caps[channel] = (start, sent + 1)
        return True

    def decide(
        self,
        *,
        cooldown_key: str | None,
        cooldown_s: int,
        channels: Sequence[str],
        cap: int,
        uncapped: bool,
        now: int,
    ) -> GateDecision:
        """Which channels send this alert now, for this worker alone (same contract as `decide`)."""
        if not channels:
            return GateDecision(allowed=())
        key_suppressed = 0
        if cooldown_key:
            row = self._alerts.get(cooldown_key)
            # A clock that stepped back a little (now before last_sent_at) still counts as inside the gap.
            if row is not None and row[0] > 0 and now - row[0] < max(0, cooldown_s):
                self._remember(cooldown_key, row[0], row[1] + 1)
                self._journal_key(cooldown_key, held=1)
                return GateDecision(allowed=(), deduped=True)
            key_suppressed = row[1] if row is not None else 0
        allowed: list[str] = []
        capped: list[str] = []
        suppressed: dict[str, int] = {}
        for channel in channels:
            if uncapped or self._cap_allows(channel, cap, now):
                allowed.append(channel)
                suppressed[channel] = key_suppressed + self._capdrops.pop(channel, 0)
                if not uncapped:
                    self._journal_send(channel, now)  # uncapped sends never count against the shared cap either
            else:
                capped.append(channel)
                self._journal_channel(channel)
                if channel in self._capdrops or len(self._capdrops) < self._max_channels:
                    self._capdrops[channel] = self._capdrops.get(channel, 0) + 1
        if cooldown_key:
            if allowed:
                self._remember(cooldown_key, now, 0)
                self._journal_key(cooldown_key, sent_at=now)
            else:
                # Held back by the cap: not marked as sent, so it goes out once the cap allows, with this count.
                row = self._alerts.get(cooldown_key)
                self._remember(cooldown_key, row[0] if row is not None else 0, (row[1] if row is not None else 0) + 1)
                self._journal_key(cooldown_key, held=1)
        return GateDecision(allowed=tuple(allowed), capped=tuple(capped), suppressed=suppressed)
