"""Spam detectors: sustained abuse over minutes to hours, measured on sliding windows shared by every worker.

What this is
    `SpamDetectors` with `observe(...)` (called once per finished abuse decision, memory only), `flush()` (every
    second: merge this worker's counters into hot.db `spam_windows`, evaluate the seven detectors of plan 10.3 on
    the merged rows, claim and act on new detections) and `flagged(limit_key, now)` (whether the spam check must
    refuse this client right now). Plus `evaluate_row`, the pure detector math the tests drive with fixtures.

Why it exists
    A per-request limit cannot see a client that stays just under it for an hour, keeps hammering after being
    refused, probes for `.env` files, or walks through user ids one by one. These detectors look at longer windows
    and either act (ban, strike, tarpit) or ask the admin (a recommendation).

How it works
    - Signals per subject: requests (`req`) and refusals (`ref`) per IP and per place, probes and auth smuggling
      attempts per IP, distinct numeric ids per IP and endpoint template (`enum`), distinct query strings per IP
      (`bust`), and distinct IPs per template and User-Agent hash (`dist`). Each row of `spam_windows` holds bucketed
      counts (`c`) and capped value sets (`s`): 10 s buckets for windows up to a minute, 1 min up to 10 min, 5 min up
      to an hour, about a twelfth of the window beyond.
    - Counters are never written per request (plan 6.3): each worker accumulates in memory (bounded) and the flush
      merges them in ONE hot.db transaction, evaluates the touched subjects, and claims detections with a `flag|`
      row. Only the worker that inserts the flag acts, so an action happens once fleet-wide; every worker reads the
      active flags back so all of them refuse a flagged client within about a second.
    - Detectors (thresholds in the detector's own unit, windows `spam_<id>_window_s`):
      rate: requests > threshold x (allowed_requests_per_minute / throttle_reset_duration) x window;
      refused: refusals > threshold; probe and auth: count >= threshold; enum: distinct ids > threshold;
      bust: at least 200 requests and distinct queries / requests > threshold; dist: distinct IPs > threshold with
      more than 1000 requests.
    - Actions (`spam_<id>_action`): `ban` (a temporary IP ban, doubled for each repeat within 30 days up to the cap;
      while `spam_dry_run` is on only a "would have banned" event), `strike` (one ladder strike, then the client's
      requests are refused while the condition holds), `tarpit` (refused and held while the condition holds),
      `recommend` (an event the recommendations engine turns into ABUSE-SPAM). Collateral protection: a trusted Roblox
      game server (`roxy/abuse/bot.py`) is never banned (it gets a strike instead), places and the distributed
      detector only ever recommend, and bypass entries are never counted.

What to read next
    `roxy/abuse/bans.py` (automatic bans), then `roxy/abuse/checks/spam.py` (the refusal).
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import sqlite3
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.abuse.bans import create_auto_ban, ua_hash
from roxy.abuse.throttle import add_strike_in
from roxy.core.clock import Clock
from roxy.rules.service import RulesService
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

DETECTORS: Final[tuple[str, ...]] = ("rate", "refused", "probe", "auth", "enum", "bust", "dist")
SIGNAL_OF: Final[dict[str, str]] = {
    "rate": "req",
    "refused": "ref",
    "probe": "probe",
    "auth": "auth",
    "enum": "enum",
    "bust": "bust",
    "dist": "dist",
}
DETECTOR_OF: Final[dict[str, str]] = {signal: detector for detector, signal in SIGNAL_OF.items()}
RECOMMEND_ONLY: Final = frozenset({"enum", "bust", "dist"})  # detectors whose subject is not a single address
FLAG_PREFIX: Final = "flag|"
FLAG_REFUSE_S: Final = 10
"""A refusing flag (strike, tarpit) lasts this long and is refreshed while the detector keeps firing."""
MAX_SUBJECTS: Final = 20_000
"""Bound of one worker's pending subjects between flushes (plan P9); more are counted as dropped."""
MAX_SET_PER_BUCKET: Final = 1024
MAX_ACTIVE_FLAGS: Final = 10_000
BUST_MIN_REQUESTS: Final = 200
DIST_MIN_REQUESTS: Final = 1000
_DIGITS = re.compile(r"^[0-9]{1,20}$")

EventSink = Callable[[str, str, Mapping[str, Any]], None]


def bucket_size(window_s: int) -> int:
    """Sub-bucket length for a window (plan 10.3: 10 s for a minute, 1 min for 10 min, 5 min for an hour)."""
    if window_s <= 60:
        return 10
    if window_s <= 600:
        return 60
    if window_s <= 3600:
        return 300
    return max(300, -(-window_s // 12 // 300) * 300)


def _short_hash(value: str) -> str:
    return format(zlib.crc32(value.encode("utf-8", "surrogateescape")), "08x")


@dataclass(slots=True)
class _Pending:
    counts: dict[int, int] = field(default_factory=dict)
    sets: dict[int, set[str]] = field(default_factory=dict)
    game_server: bool = False


@dataclass(frozen=True, slots=True)
class Detection:
    """A detector that fired for one subject."""

    detector: str
    subject: str  # the row subject without its signal, for example "ip:203.0.113.9" or "place:123"
    value: float
    threshold: float
    window_s: int
    action: str
    game_server: bool
    evidence: str

    @property
    def limit_key(self) -> str | None:
        """The client key for IP subjects, None for places and fleet-wide subjects."""
        return self.subject[3:] if self.subject.startswith("ip:") and self.detector not in RECOMMEND_ONLY else None


@dataclass(frozen=True, slots=True)
class Flag:
    """An active detection as every worker sees it."""

    detector: str
    who: str
    action: str
    until: float
    refuses: bool


def _setting(values: Mapping[str, Any], detector: str, name: str, default: Any) -> Any:
    return values.get(f"spam_{detector}_{name}", default)


def _window(values: Mapping[str, Any], detector: str) -> int:
    return max(10, int(_setting(values, detector, "window_s", 600)))


def _in_window(start: int, size: int, now_s: int, window_s: int) -> bool:
    return start + size > now_s - window_s


def evaluate_row(
    detector: str, data: Mapping[str, Any], values: Mapping[str, Any], now_s: int
) -> tuple[bool, float, float]:
    """`(fired, value, threshold)` of one detector on one merged row (pure; the tests drive it with fixtures)."""
    window = _window(values, detector)
    size = bucket_size(window)
    counts = {int(k): int(v) for k, v in (data.get("c") or {}).items()}
    sets = {int(k): set(v) for k, v in (data.get("s") or {}).items()}
    total = sum(n for start, n in counts.items() if _in_window(start, size, now_s, window))
    distinct: set[str] = set()
    for start, members in sets.items():
        if _in_window(start, size, now_s, window):
            distinct |= members
    threshold = float(_setting(values, detector, "threshold", 0))
    if detector == "rate":
        per_s = int(values.get("allowed_requests_per_minute", 10)) / max(
            1, int(values.get("throttle_reset_duration", 50))
        )
        limit = threshold * per_s * window
        return total > limit, float(total), limit
    if detector == "refused":
        return total > threshold, float(total), threshold
    if detector in ("probe", "auth"):
        return total >= threshold, float(total), threshold
    if detector == "enum":
        return len(distinct) > threshold, float(len(distinct)), threshold
    if detector == "bust":
        if total < BUST_MIN_REQUESTS:
            return False, 0.0, threshold
        ratio = len(distinct) / total
        return ratio > threshold, round(ratio, 3), threshold
    if detector == "dist":
        return len(distinct) > threshold and total > DIST_MIN_REQUESTS, float(len(distinct)), threshold
    return False, 0.0, threshold


def _merge(data: dict[str, Any], pending: _Pending, cap: int, keep_after: int) -> dict[str, Any]:
    counts: dict[str, int] = {k: int(v) for k, v in (data.get("c") or {}).items() if int(k) >= keep_after}
    sets: dict[str, list[str]] = {k: list(v) for k, v in (data.get("s") or {}).items() if int(k) >= keep_after}
    for start, n in pending.counts.items():
        if start >= keep_after:
            counts[str(start)] = counts.get(str(start), 0) + n
    for start, members in pending.sets.items():
        if start < keep_after:
            continue
        merged = set(sets.get(str(start), ()))
        for member in members:
            if len(merged) >= cap:
                break
            merged.add(member)
        sets[str(start)] = sorted(merged)
    out: dict[str, Any] = {"c": counts}
    if sets:
        out["s"] = sets
    if pending.game_server or data.get("gs"):
        out["gs"] = 1
    return out


class SpamDetectors:
    """Per-worker accumulation, the shared flush, and the active flags (see the module docstring)."""

    def __init__(
        self,
        settings: Any,
        hot_db: Database | None,
        clock: Clock,
        *,
        control_db: Database | None = None,
        rules_service: RulesService | None = None,
        events: EventSink | None = None,
    ) -> None:
        self.settings = settings
        self.hot_db = hot_db
        self.control_db = control_db
        self.rules_service = rules_service
        self.clock = clock
        self.events = events
        self._pending: dict[str, _Pending] = {}
        self._flags: dict[str, Flag] = {}
        self.dropped = 0
        self.flushes = 0
        self.detections_total = 0

    # ---- per request (memory only) ----

    def _values(self) -> Mapping[str, Any]:
        snapshot = self.settings.snapshot()
        return snapshot if isinstance(snapshot, Mapping) else {}

    def _bucket(self, values: Mapping[str, Any], detector: str, now_s: int) -> int:
        size = bucket_size(_window(values, detector))
        return now_s // size * size

    def _slot(self, subject: str) -> _Pending | None:
        pending = self._pending.get(subject)
        if pending is None:
            if len(self._pending) >= MAX_SUBJECTS:
                self.dropped += 1
                return None
            pending = _Pending()
            self._pending[subject] = pending
        return pending

    def _count(self, values: Mapping[str, Any], detector: str, who: str, now_s: int, value: str | None = None) -> None:
        if not bool(_setting(values, detector, "enabled", 0)):
            return
        slot = self._slot(f"{SIGNAL_OF[detector]}|{who}")
        if slot is None:
            return
        bucket = self._bucket(values, detector, now_s)
        slot.counts[bucket] = slot.counts.get(bucket, 0) + 1
        if value is not None:
            members = slot.sets.setdefault(bucket, set())
            if len(members) < MAX_SET_PER_BUCKET:
                members.add(value)

    def observe(
        self,
        *,
        limit_key: str,
        place_id: str | None,
        template: str,
        path: str,
        query: Sequence[tuple[str, str]],
        user_agent: str,
        refused: bool,
        probe: bool,
        auth: bool,
        game_server: bool,
        bypass: bool,
    ) -> None:
        """Count one finished request for every enabled detector (memory only; bypass entries are never counted)."""
        values = self._values()
        if bypass or not bool(values.get("spam_enabled", 0)):
            return
        now_s = int(self.clock.now())
        who = f"ip:{limit_key}"
        self._count(values, "rate", who, now_s)
        if game_server:
            slot = self._pending.get(f"req|{who}")
            if slot is not None:
                slot.game_server = True
        if place_id:
            self._count(values, "rate", f"place:{place_id}", now_s)
        if refused:
            self._count(values, "refused", who, now_s)
            if place_id:
                self._count(values, "refused", f"place:{place_id}", now_s)
        if probe:
            self._count(values, "probe", who, now_s)
        if auth:
            self._count(values, "auth", who, now_s)
        ids = [part for part in path.split("/") if _DIGITS.match(part)]
        if ids and template:
            self._count(values, "enum", f"{who}|{template}", now_s, "/".join(ids))
        fingerprint = template + "?" + "&".join(f"{k}={v}" for k, v in sorted(query)) if query else template
        self._count(values, "bust", who, now_s, _short_hash(fingerprint) if query else None)
        if template:
            self._count(values, "dist", f"{template}|{ua_hash(user_agent)}", now_s, _short_hash(limit_key))

    # ---- the flagged clients ----

    def flagged(self, limit_key: str, now: float) -> Flag | None:
        """The active refusing flag of this client, if any (the spam check refuses while it holds)."""
        flag = self._flags.get(f"ip:{limit_key}")
        if flag is None or flag.until <= now or not flag.refuses:
            return None
        return flag

    def pending_subjects(self) -> int:
        return len(self._pending)

    # ---- the flush (every second) ----

    def _flush_tx(
        self, conn: sqlite3.Connection, batch: dict[str, _Pending], values: Mapping[str, Any], now_s: int
    ) -> tuple[list[Detection], list[Flag]]:
        detections: list[Detection] = []
        for subject, pending in batch.items():
            signal, _, who = subject.partition("|")
            detector = DETECTOR_OF.get(signal)
            if detector is None:
                continue
            window = _window(values, detector)
            keep_after = now_s - window - bucket_size(window)
            # A count threshold N only needs N + 1 distinct values per bucket to be decided; the cache-busting ratio
            # compares distinct values with the request count, so it keeps the full (bounded) set.
            cap = (
                MAX_SET_PER_BUCKET
                if detector == "bust"
                else min(MAX_SET_PER_BUCKET, int(float(_setting(values, detector, "threshold", 0))) + 1)
            )
            row = conn.execute("SELECT buckets_json FROM spam_windows WHERE subject = ?", (subject,)).fetchone()
            try:
                data = json.loads(row[0]) if row is not None else {}
            except (TypeError, ValueError):
                data = {}
            merged = _merge(data if isinstance(data, dict) else {}, pending, max(1, cap), keep_after)
            conn.execute(
                "INSERT INTO spam_windows (subject, buckets_json, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT (subject) DO UPDATE SET buckets_json = excluded.buckets_json, "
                "updated_at = excluded.updated_at",
                (subject, json.dumps(merged, separators=(",", ":")), now_s),
            )
            if not bool(_setting(values, detector, "enabled", 0)):
                continue
            fired, value, threshold = evaluate_row(detector, merged, values, now_s)
            if fired:
                action = str(_setting(values, detector, "action", "recommend"))
                if detector in RECOMMEND_ONLY or not who.startswith("ip:"):
                    action = "recommend"  # places and fleet-wide subjects only ever recommend (plan 10.3)
                detections.append(
                    Detection(
                        detector,
                        who,
                        value,
                        threshold,
                        window,
                        action,
                        bool(merged.get("gs")),
                        f"SPAM-{detector.upper()}: {value:g} in {window} s (threshold {threshold:g})",
                    )
                )
        claimed = [d for d in detections if self._claim(conn, d, values, now_s)]
        self._drop_expired_flags(conn, now_s)
        flags = self._read_flags(conn, now_s)
        return claimed, flags

    @staticmethod
    def _drop_expired_flags(conn: sqlite3.Connection, now_s: int) -> None:
        """Delete flags whose time is up, so the bounded flag read only ever sees live ones (plan P9)."""
        # A SQLite without JSON functions raises OperationalError; the retention job then prunes the rows later.
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute(
                "DELETE FROM spam_windows WHERE subject >= ? AND subject < ? "
                "AND json_extract(buckets_json, '$.until') <= ?",
                (FLAG_PREFIX, FLAG_PREFIX + "\U0010ffff", now_s),
            )

    def _effective_action(self, detection: Detection) -> str:
        if detection.action == "ban" and detection.game_server:
            return "strike"  # collateral protection: never ban a trusted game server (plan 10.3)
        return detection.action

    def _claim(self, conn: sqlite3.Connection, detection: Detection, values: Mapping[str, Any], now_s: int) -> bool:
        """Insert or refresh this detection's flag; True only for the worker that created it (acts once)."""
        action = self._effective_action(detection)
        refuses = action in ("strike", "tarpit") and detection.limit_key is not None
        until = now_s + (FLAG_REFUSE_S if refuses else detection.window_s)
        subject = f"{FLAG_PREFIX}{detection.detector}|{detection.subject}"
        row = conn.execute("SELECT buckets_json FROM spam_windows WHERE subject = ?", (subject,)).fetchone()
        active = False
        if row is not None:
            try:
                active = float(json.loads(row[0]).get("until", 0)) > now_s
            except (TypeError, ValueError, AttributeError):
                active = False
        if active and not refuses:
            return False
        payload = json.dumps(
            {"until": until, "action": action, "refuses": int(refuses), "evidence": detection.evidence},
            separators=(",", ":"),
        )
        conn.execute(
            "INSERT INTO spam_windows (subject, buckets_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (subject) DO UPDATE SET buckets_json = excluded.buckets_json, "
            "updated_at = excluded.updated_at",
            (subject, payload, now_s),
        )
        if active:
            return False  # refreshed an active refusing flag; the action already happened
        if action == "strike" and detection.limit_key is not None:
            add_strike_in(conn, detection.limit_key, now_s, float(values.get("throttle_strike_decay_seconds", 1800)))
        return True

    @staticmethod
    def _read_flags(conn: sqlite3.Connection, now_s: int) -> list[Flag]:
        rows = conn.execute(
            "SELECT subject, buckets_json FROM spam_windows WHERE subject >= ? AND subject < ? LIMIT ?",
            (FLAG_PREFIX, FLAG_PREFIX + "\U0010ffff", MAX_ACTIVE_FLAGS),
        ).fetchall()
        flags: list[Flag] = []
        for subject, raw in rows:
            try:
                data = json.loads(raw)
                until = float(data.get("until", 0))
            except (TypeError, ValueError, AttributeError):
                continue
            if until <= now_s:
                continue
            _, detector, who = str(subject).split("|", 2)
            flags.append(Flag(detector, who, str(data.get("action", "")), until, bool(data.get("refuses"))))
        return flags

    async def flush(self) -> list[Detection]:
        """Merge this worker's counters, evaluate, claim and act. Returns the detections this worker acted on."""
        if self.hot_db is None:
            self._pending.clear()
            return []
        values = self._values()
        batch, self._pending = self._pending, {}
        now_s = int(self.clock.now())
        try:
            if batch:
                claimed, flags = await self.hot_db.write(lambda conn: self._flush_tx(conn, batch, values, now_s))
            else:
                # Nothing to merge: only refresh the view of the other workers' flags, without the write lock.
                claimed, flags = [], await self.hot_db.read(lambda conn: self._read_flags(conn, now_s))
        except SharedStateUnavailable as exc:
            # Detector counters are statistics: losing one second of them is acceptable (never a decision input
            # for a single request), so the batch is dropped rather than growing memory while hot.db is down.
            self.dropped += len(batch)
            log.warning("spam_flush_failed", extra={"fields": {"error": str(exc)[:200], "subjects": len(batch)}})
            return []
        self.flushes += 1
        refusing: dict[str, Flag] = {}
        for flag in flags:
            if flag.refuses:
                refusing[flag.who] = flag
        self._flags = refusing
        for detection in claimed:
            self.detections_total += 1
            await self._act(detection, values, now_s)
        return claimed

    async def _act(self, detection: Detection, values: Mapping[str, Any], now_s: int) -> None:
        action = self._effective_action(detection)
        detail = {
            "detector": f"SPAM-{detection.detector.upper()}",
            "subject": detection.subject,
            "value": detection.value,
            "threshold": detection.threshold,
            "window_s": detection.window_s,
            "action": action,
            "configured_action": detection.action,
            "game_server": detection.game_server,
            "evidence": detection.evidence,
        }
        if action == "ban" and detection.limit_key is not None:
            if bool(values.get("spam_dry_run", 1)):
                self._event("spam_would_ban", "warning", detail)
                return
            if self.rules_service is not None and self.control_db is not None:
                try:
                    _change, minutes = await create_auto_ban(
                        self.rules_service,
                        self.control_db,
                        limit_key=detection.limit_key,
                        detector=f"spam_{detection.detector}",
                        reason_text=detection.evidence,
                        base_minutes=int(_setting(values, detection.detector, "ban_minutes", 0)),
                        max_minutes=int(_setting(values, detection.detector, "ban_max_minutes", 0)),
                        now=now_s,
                    )
                except Exception:  # a failed ban must never stop the flush loop; it is logged and retried next time
                    log.exception("spam_ban_failed", extra={"fields": {"subject": detection.subject}})
                    return
                self._event("spam_ban", "warning", {**detail, "ban_minutes": minutes})
                return
        kind = "spam_detected" if action == "recommend" else f"spam_{action}"
        self._event(kind, "warning" if action != "recommend" else "info", detail)

    def _event(self, kind: str, severity: str, detail: Mapping[str, Any]) -> None:
        if self.events is None:
            return
        try:
            self.events(kind, severity, detail)
        except Exception:  # metrics never fail the caller (plan P1)
            log.exception("spam_event_failed")


__all__ = [
    "DETECTORS",
    "FLAG_PREFIX",
    "Detection",
    "Flag",
    "SpamDetectors",
    "bucket_size",
    "evaluate_row",
]
