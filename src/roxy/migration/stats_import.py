"""Importing the v1 statistics into metrics.db: lifetime counters, fingerprints, errors and probe summaries.

What this is
    `import_statistics(db, diagnostics, report, now)` writes the v1 `Diagnostics` stores that v2 can use:
    lifetime counters as one `legacy_totals` snapshot (owner decision D17), header and User-Agent fingerprints,
    error signatures, and the probe (exploit) summary as `events` rows, each with first and last seen times.

Why it exists
    v1 statistics are lifetime counters with no time dimension, so they cannot become v2 trends (D17). Two of
    them matter after cutover: the Roblox 429 count (the "579" of plan 2.5) and the request count, because the
    Overview KPI "Roblox 429s per 10,000 caller requests" shows the v1 baseline next to the v2 value (plan 11.6).
    Fingerprints, errors and probe reasons keep their history, so the owner does not start from an empty Clients
    page. Recent-event rings, per-minute buckets and per-worker coordination files are not useful in v2 and are
    listed as not migrated.

How it works
    - `legacy_totals`: one row per counter, `value_json = {"value", "label", "since", "source"}`, where `since`
      is v1's last clear time for that store (so a "lifetime" label stays honest). A rerun rewrites a row only if
      the v1 value changed.
    - Fingerprints and errors: `INSERT OR IGNORE` by primary key (header name, value hash, User-Agent hash, error
      signature), so a rerun or a row v2 already recorded is never double counted. Row keys and stored forms are
      the metrics package's own (`metrics/fingerprints.py row_hash`), so imported rows and live rows are the same
      rows. Values of headers v2 only ever stores hashed (secrets, client addresses) are not imported, nor is a
      value that redaction would change; every stored string passes through `redact_text` and the known v1
      secrets, and client IP addresses in error details are masked.
    - Probe summaries: `events` rows of type `v1_probe_summary`, found again on a rerun by an `import_key` in
      `detail_json`. v1 kept only the last time per reason; the first time comes from v1's recent probe list when
      that reason is still in it.

What to read next
    `roxy/storage/migrations/metrics/0001_initial.sql` (the tables) and REMAKE_PLAN.md sections 6.2 and 11.6.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any, Final

from roxy.core.redact import redact_text
from roxy.metrics.fingerprints import (
    EMPTY_VALUE,
    MAX_NAME_CHARS,
    MAX_UA_CHARS,
    MAX_VALUE_CHARS,
    NO_USER_AGENT,
    hashes_value,
    row_hash,
)
from roxy.migration.report import MigrationReport
from roxy.storage.db import Database

LEGACY_PREFIX: Final = "v1."
EVENT_TYPE: Final = "v1_probe_summary"
MAX_SIGNATURE: Final = 200
MAX_DETAIL: Final = 2000
MAX_REASON: Final = 500
STATUS_SOURCES: Final[dict[str, str]] = {
    "Roblox": "roblox",
    "Roxy": "roxy",
    "Relay": "relay",
    "Internal": "internal",
    "Cache": "cache",
}

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP_LINE = re.compile(r"(?m)^(IP:\s*).*$")


def _num(value: Any) -> int:
    """A non-negative whole number from a v1 counter (anything else counts as 0)."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float) and math.isfinite(value):
        return max(0, int(value))
    return 0


def _epoch(value: Any) -> int | None:
    if isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value) and value > 0:
        return int(value)
    return None


def _counts(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {redact_text(str(key))[:120]: _num(count) for key, count in value.items() if not isinstance(count, Mapping)}


def _nested_counts(value: Any, fields: tuple[str, ...] | None = None) -> dict[str, dict[str, int]]:
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, dict[str, int]] = {}
    for key, record in value.items():
        if not isinstance(record, Mapping):
            continue
        names = fields or tuple(str(name) for name in record if not isinstance(record[name], Mapping | list))
        out[redact_text(str(key))[:120]] = {name: _num(record.get(name)) for name in names}
    return out


def build_legacy_totals(diagnostics: Mapping[str, Any], source: str) -> dict[str, dict[str, Any]]:
    """The `legacy_totals` rows (key -> value object) for the v1 lifetime counters."""
    epochs_raw = diagnostics.get("ClearEpochs")
    epochs = {str(k): _epoch(v) for k, v in epochs_raw.items()} if isinstance(epochs_raw, Mapping) else {}

    def row(value: Any, label: str, store: str) -> dict[str, Any]:
        return {"value": value, "label": label, "since": epochs.get(store), "source": "roxy v1"}

    request_counts = _nested_counts(diagnostics.get("request_counts"), ("Successful", "Failed"))
    requests_total = sum(sum(item.values()) for item in request_counts.values())
    sources_raw = diagnostics.get("status_sources")
    status_sources = (
        {STATUS_SOURCES.get(str(name), str(name).lower()): _counts(codes) for name, codes in sources_raw.items()}
        if isinstance(sources_raw, Mapping)
        else {}
    )
    roblox_429 = status_sources.get("roblox", {}).get("429")
    if roblox_429 is None:
        roblox_429 = _counts(diagnostics.get("status_codes_detailed")).get("429", 0)
    per_10k = round(roblox_429 / requests_total * 10000, 1) if requests_total else None

    rows: dict[str, dict[str, Any]] = {
        "requests_total": row(
            requests_total,
            "Requests v1 handled since its counters were last cleared (the Total Requests tile: upstream attempts "
            "plus cache serves; refusals were not counted)",
            "request_counts",
        ),
        "roblox_429_total": row(
            roblox_429,
            "Roblox 429 answers to v1's upstream attempts since the counters were last cleared (each attempt counted, "
            "not each caller request)",
            "status_sources",
        ),
        "roblox_429_per_10k_requests": row(
            per_10k,
            "v1 baseline for the Overview KPI 'Roblox 429s per 10,000 caller requests' (plan 11.6), a lifetime figure",
            "status_sources",
        ),
        "request_counts": row(request_counts, "Upstream attempts and cache serves per method", "request_counts"),
        "status_sources": row(status_sources, "Status codes by who produced them", "status_sources"),
        "status_codes_detailed": row(
            _counts(diagnostics.get("status_codes_detailed")), "Roblox status codes", "status_codes_detailed"
        ),
        "status_code_counts": row(
            _counts(diagnostics.get("status_code_counts")), "Roblox 2xx and 4xx answers", "status_code_counts"
        ),
        "cache_stats": row(_counts(diagnostics.get("cache_stats")), "Response cache counters", "cache_stats"),
        "page_visits": row(_counts(diagnostics.get("page_visits")), "Public page visits", "page_visits"),
        "visitor_counts": row(_counts(diagnostics.get("visitor_counts")), "Home page visitors", "visitor_counts"),
        "reason_counts": row(_counts(diagnostics.get("reason_counts")), "Failure reasons", "reason_counts"),
        "refusals": row(
            {key: value.get("Count", 0) for key, value in _nested_counts(diagnostics.get("refusals")).items()},
            "Refusals by v1 reason",
            "refusals",
        ),
        "internal_requests": row(
            _nested_counts(diagnostics.get("internal_requests"), ("Count", "Failed")),
            "Roxy's own calls by purpose",
            "internal_requests",
        ),
        "method_stats": row(
            _nested_counts(diagnostics.get("method_stats"), ("Requests", "Failed", "Timeouts")),
            "Upstream attempts per v1 method (Token is the credential, Rotate the rotator)",
            "method_stats",
        ),
        "drops": row(
            {
                "pause": _num((diagnostics.get("pause_drops") or {}).get("Count"))
                if isinstance(diagnostics.get("pause_drops"), Mapping)
                else 0,
                "throttle_all": _num((diagnostics.get("throttle_drops") or {}).get("Count"))
                if isinstance(diagnostics.get("throttle_drops"), Mapping)
                else 0,
            },
            "Requests refused while paused or while throttle-all was on (since it was last switched on)",
            "pause_drops",
        ),
        "retry_counts": row(
            {
                "total": _num((diagnostics.get("retry_counts") or {}).get("Total"))
                if isinstance(diagnostics.get("retry_counts"), Mapping)
                else 0,
                "by_status": _counts((diagnostics.get("retry_counts") or {}).get("ByStatusCode"))
                if isinstance(diagnostics.get("retry_counts"), Mapping)
                else {},
            },
            "Upstream retries",
            "retry_counts",
        ),
        "tarpit": row(_tarpit(diagnostics.get("tarpit_stats")), "Tarpit holds", "tarpit_stats"),
        "token_budget_rejections": row(
            _num((diagnostics.get("token_budget") or {}).get("Rejections"))
            if isinstance(diagnostics.get("token_budget"), Mapping)
            else 0,
            "Credential budget refusals (never counted in v1, bug B1)",
            "token_budget",
        ),
        "snapshot": row(
            {"data_file": source, "clear_epochs": {k: v for k, v in sorted(epochs.items()) if v is not None}},
            "Where these counters came from",
            "",
        ),
    }
    return {f"{LEGACY_PREFIX}{key}": value for key, value in rows.items()}


def _tarpit(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    categories = value.get("Categories")
    return {
        "held": _num(value.get("Count")),
        "skipped": _num(value.get("Skipped")),
        "seconds_held": _num(value.get("TotalHeld")),
        "categories": {
            str(name): {"held": _num(item.get("Count")), "skipped": _num(item.get("Skipped"))}
            for name, item in (categories.items() if isinstance(categories, Mapping) else ())
            if isinstance(item, Mapping)
        },
    }


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def value_hash(name: str, shown: str) -> str:
    """The `fingerprint_values` key of one stored value: the metrics package's own `row_hash(name, value)`."""
    return row_hash(name, shown)


def ua_hash(shown: str) -> str:
    """The `fingerprint_user_agents` key of one stored User-Agent: `row_hash(user_agent)`."""
    return row_hash(shown)


def _times(record: Mapping[str, Any], now: int) -> tuple[int, int]:
    first = _epoch(record.get("FirstSeen"))
    last = _epoch(record.get("LastSeen")) or first or now
    return (first or last), last


def _merge(target: dict[Any, list[int]], key: Any, count: int, first: int, last: int) -> None:
    current = target.get(key)
    if current is None:
        target[key] = [count, first, last]
    else:
        current[0] += count
        current[1] = min(current[1], first)
        current[2] = max(current[2], last)


def _fingerprints(diagnostics: Mapping[str, Any], now: int) -> tuple[Any, Any, Any, int]:
    """(header names, values, User-Agents, values left out). Values are keyed by (name, raw value) here; the
    stored form and its row hash are decided in `import_statistics`, after secrets are removed."""
    headers: dict[str, list[int]] = {}
    values: dict[tuple[str, str], list[int]] = {}
    agents: dict[str, list[int]] = {}
    skipped_values = 0
    for store in ("header_names", "blocked_header_names"):
        records = diagnostics.get(store)
        if not isinstance(records, Mapping):
            continue
        for raw_name, record in records.items():
            if not isinstance(record, Mapping):
                continue
            name = str(raw_name).lower()[:MAX_NAME_CHARS]
            if not name:
                continue
            first, last = _times(record, now)
            _merge(headers, name, _num(record.get("Count")), first, last)
            stored_values = record.get("Values")
            if not isinstance(stored_values, Mapping):
                continue
            if hashes_value(name):
                # v2 keeps only a keyed hash for secret and address headers (metrics/fingerprints.py); v1 kept
                # client IPs in clear text and an unkeyed hash of cookies. Neither is imported.
                skipped_values += len(stored_values)
                continue
            for raw_value, value_record in stored_values.items():
                if not isinstance(value_record, Mapping):
                    continue
                v_first, v_last = _times(value_record, now)
                key = (name, str(raw_value)[:MAX_VALUE_CHARS])
                _merge(values, key, _num(value_record.get("Count")), v_first, v_last)
    for store in ("user_agents", "blocked_user_agents"):
        records = diagnostics.get(store)
        if not isinstance(records, Mapping):
            continue
        for raw_agent, record in records.items():
            if isinstance(record, Mapping):
                first, last = _times(record, now)
                _merge(agents, str(raw_agent)[:MAX_UA_CHARS], _num(record.get("Count")), first, last)
    return headers, values, agents, skipped_values


def _redact_detail(detail: str) -> str:
    text = _IP_LINE.sub(r"\1[ip]", detail)
    text = _IPV4.sub("[ip]", text)
    return redact_text(text)[:MAX_DETAIL]


def _errors(diagnostics: Mapping[str, Any], now: int) -> list[tuple[Any, ...]]:
    records = diagnostics.get("errors")
    rows: list[tuple[Any, ...]] = []
    if not isinstance(records, Mapping):
        return rows
    for raw_signature, record in records.items():
        if not isinstance(record, Mapping):
            continue
        signature = _redact_detail(str(raw_signature))[:MAX_SIGNATURE]
        first, last = _times(record, now)
        source = STATUS_SOURCES.get(str(record.get("Source", "Roxy")), "roxy")
        detail = _redact_detail(str(record.get("LastDetail") or ""))
        rows.append((signature, _num(record.get("Count")) or 1, first, last, source, detail or None))
    return rows


def _reason_code(reason: str) -> str | None:
    if reason.startswith("Invalid URL"):
        return "unsafe_url"
    if reason.startswith("Non-Roblox URL"):
        return "not_roblox"
    if reason.startswith("Sent a ROBLOSECURITY token"):
        return "auth_smuggling"
    return None


def _probe_events(diagnostics: Mapping[str, Any], now: int) -> list[dict[str, Any]]:
    summary = diagnostics.get("exploit_summary")
    if not isinstance(summary, Mapping):
        return []
    firsts: dict[str, int] = {}
    attempts = diagnostics.get("exploit_attempts")
    for attempt in attempts if isinstance(attempts, list) else ():
        if isinstance(attempt, Mapping):
            when = _epoch(attempt.get("Date"))
            reason = str(attempt.get("Reason", ""))
            if when is not None and (reason not in firsts or when < firsts[reason]):
                firsts[reason] = when
    events = []
    for raw_reason, record in summary.items():
        if not isinstance(record, Mapping):
            continue
        reason = str(raw_reason)
        last = _epoch(record.get("LastSeen")) or now
        events.append(
            {
                "at_ms": last * 1000,
                "reason_code": _reason_code(reason),
                "detail": {
                    "source": "roxy v1",
                    "import_key": _short_hash(reason),
                    "reason": redact_text(reason)[:MAX_REASON],
                    "count": _num(record.get("Count")),
                    "first_seen": firsts.get(reason),
                    "last_seen": last,
                },
            }
        )
    return events


def _deep(value: Any, clean: Callable[[str], str]) -> Any:
    """`value` with `clean` applied to every string in it, keys included."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, Mapping):
        return {clean(str(key)): _deep(item, clean) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_deep(item, clean) for item in value]
    return value


async def import_statistics(
    db: Database,
    diagnostics: Mapping[str, Any],
    report: MigrationReport,
    *,
    now: int,
    source: str,
    clean: Callable[[str], str] = redact_text,
) -> int:
    """Write the v1 statistics into metrics.db (one transaction). Returns the rows written.

    `clean` removes secrets from every stored string; the runner passes one that knows every secret value read
    from the v1 tree (on top of `redact_text`'s shape rules), so a token that ended up in an error message or a
    refusal reason in v1 never reaches metrics.db.
    """
    totals = _deep(build_legacy_totals(diagnostics, source), clean)
    raw_headers, raw_values, raw_agents, skipped_values = _fingerprints(diagnostics, now)
    headers = {clean(name): numbers for name, numbers in raw_headers.items()}
    values: dict[str, tuple[str, str, list[int]]] = {}
    for (name, raw_value), numbers in raw_values.items():
        shown = raw_value or EMPTY_VALUE
        if raw_value.startswith("fp:") or clean(shown) != shown:
            # v2 stores a value that redaction would change as a keyed hash; without the key, leave it out.
            skipped_values += 1
            continue
        values[value_hash(name, shown)] = (name, shown, numbers)
    agents: dict[str, tuple[str, list[int]]] = {}
    for raw_agent, numbers in raw_agents.items():
        shown_agent = raw_agent if raw_agent == NO_USER_AGENT else clean(raw_agent)[:MAX_UA_CHARS]
        current = agents.get(ua_hash(shown_agent))
        if current is None:
            agents[ua_hash(shown_agent)] = (shown_agent, numbers)
        else:
            _merge({0: current[1]}, 0, *numbers)
    if skipped_values:
        report.statistics["fingerprint_values_not_imported"] = {
            "count": skipped_values,
            "why": "values of secret or IP address headers, and values that hold a secret, are never imported",
        }
    errors = [
        (clean(signature), count, first, last, source_name, clean(detail) if detail else detail)
        for signature, count, first, last, source_name, detail in _errors(diagnostics, now)
    ]
    events = [{**event, "detail": _deep(event["detail"], clean)} for event in _probe_events(diagnostics, now)]
    outcome: dict[str, dict[str, int]] = {}

    def tally(name: str, inserted: bool) -> None:
        bucket = outcome.setdefault(name, {"imported": 0, "already_present": 0})
        bucket["imported" if inserted else "already_present"] += 1

    def write(conn: sqlite3.Connection) -> int:
        outcome.clear()
        written = 0
        for key, value in totals.items():
            text = json.dumps(value, sort_keys=True)
            row = conn.execute("SELECT value_json FROM legacy_totals WHERE key = ?", (key,)).fetchone()
            if row is not None and row[0] == text:
                tally("legacy_totals", False)
                continue
            conn.execute(
                "INSERT INTO legacy_totals (key, value_json) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
                (key, text),
            )
            tally("legacy_totals", True)
            written += 1
        for name, (count, first, last) in headers.items():
            cursor = conn.execute(
                "INSERT OR IGNORE INTO fingerprint_headers (name, count, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                (name, count, first, last),
            )
            tally("fingerprint_headers", cursor.rowcount > 0)
            written += max(0, cursor.rowcount)
        for key, (name, shown, (count, first, last)) in values.items():
            cursor = conn.execute(
                "INSERT OR IGNORE INTO fingerprint_values (value_hash, name, value, count, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key, name, shown, count, first, last),
            )
            tally("fingerprint_values", cursor.rowcount > 0)
            written += max(0, cursor.rowcount)
        for agent_hash, (shown_agent, (count, first, last)) in agents.items():
            cursor = conn.execute(
                "INSERT OR IGNORE INTO fingerprint_user_agents (ua_hash, user_agent, count, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (agent_hash, shown_agent, count, first, last),
            )
            tally("fingerprint_user_agents", cursor.rowcount > 0)
            written += max(0, cursor.rowcount)
        for signature, count, first, last, source_name, detail in errors:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO errors (signature, count, first_seen, last_seen, source, last_detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (signature, count, first, last, source_name, detail),
            )
            tally("errors", cursor.rowcount > 0)
            written += max(0, cursor.rowcount)
        for event in events:
            detail = event["detail"]
            exists = conn.execute(
                "SELECT 1 FROM events WHERE type = ? AND json_extract(detail_json, '$.import_key') = ? LIMIT 1",
                (EVENT_TYPE, detail["import_key"]),
            ).fetchone()
            if exists is not None:
                tally("exploit_summaries", False)
                continue
            conn.execute(
                "INSERT INTO events (at_ms, type, severity, reason_code, detail_json) VALUES (?, ?, ?, ?, ?)",
                (event["at_ms"], EVENT_TYPE, "info", event["reason_code"], json.dumps(detail, sort_keys=True)),
            )
            tally("exploit_summaries", True)
            written += 1
        return written

    written = await db.write(write)
    report.statistics.update(outcome)
    kpi = {
        "roblox_429_total": totals[f"{LEGACY_PREFIX}roblox_429_total"]["value"],
        "requests_total": totals[f"{LEGACY_PREFIX}requests_total"]["value"],
        "roblox_429_per_10k_requests": totals[f"{LEGACY_PREFIX}roblox_429_per_10k_requests"]["value"],
    }
    report.statistics["kpi"] = kpi
    report.changed(written)
    return written


__all__ = [
    "EVENT_TYPE",
    "LEGACY_PREFIX",
    "build_legacy_totals",
    "import_statistics",
    "ua_hash",
    "value_hash",
]
