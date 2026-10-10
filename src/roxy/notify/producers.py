"""The alert producers that watch numbers: Roblox 429s, caller 5xx, storage, database integrity, backups, the digest.

What this is
    The plan 17.7 alerts no single event raises, each a function that reads the shared numbers, decides, and hands
    an `Alert` to the notifier: `check_roblox_429`, `check_caller_5xx`, `check_storage`, `check_backup`,
    `send_digest`, plus `integrity_alert` (called by the daily `quick_check` of `scheduler/jobs.py` through
    `integrity_hook`). `register_jobs(registry, ctx)` adds the leader jobs that run them: `alerts_rates` (both rate
    alerts, every minute), `alerts_storage` and `alerts_backup` (every 30 minutes) and `alerts_digest` (polls every
    5 minutes, sends once a day at `alert_digest_hour`).

Why it exists
    The alert catalog (`notify/alerts.py`) defined `roblox_429`, `caller_5xx`, `disk`, `db_integrity`,
    `backup_failed`, `backup_stale` and `digest`, but nothing sent them (lane_docs request 3): an owner would learn
    about Roblox rate limiting, failing callers, a filling disk, a corrupt database or a dead backup only by opening
    the dashboard. Each of these needs a fleet-wide view (the rollups every worker writes, the files every worker
    shares), so each runs on the leader alone; the gate (`notify/gate.py`) still dedupes every alert fleet-wide by
    its cooldown key, so a leadership change cannot send one twice inside its gap (C6).

How it works
    - Thresholds come from plan 17.7 and the catalog: "Roblox 429 rate over 2% for 10 min" and "Caller 5xx over 2%
      for 10 min" are the rate over the last 10 complete minutes (`RATE_WINDOW_S`) above `RATE_THRESHOLD_PCT`, with at
      least `MIN_EVENTS` 429s or 5xx answers in the window, so one failed call out of three never pages anyone. The
      429 rate is Roblox 429s (the `upstream_429` log, once per attempt) per upstream call made for callers; the
      caller 5xx rate is 5xx answers per caller request, a deliberate pause (`paused`, 503) left out of both sides.
      Storage alerts from 90 percent of `storage_total_budget_gb` (the catalog: "an alert at 90 percent"), warn
      below the budget and critical over it. A backup is stale after `BACKUP_STALE_H` hours without a good one (the
      H-BACKUP pass band), and failed when the newest record of `backup.sh` is a failure. The digest goes out once
      per local day at `alert_digest_hour` (`-1`: off; `ui_timezone`), claimed in hot.db `job_runs` first.
    - Alert bodies hold Roxy's own words and numbers only: reason codes, status codes, rule and check ids, egress
      names, the normalized endpoint templates the dashboard shows, file names, sizes. Never a caller's raw text, a
      client address or a secret; the notifier redacts every field again on top.
    - Every check reads on the database reader threads or a worker thread (files), never on the event loop, and
      returns a short report (the job's `last_result`).

What to read next
    `roxy/notify/alerts.py` (subjects, severities, cooldown keys), `roxy/notify/notifier.py` (gate, render, send),
    `roxy/scheduler/jobs.py` (`Job`, `register_storage_jobs`), `deploy/tools/backup.sh` (the backup status file).
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from roxy.metrics import queries
from roxy.metrics.rollups import zone
from roxy.notify.alerts import Alert, SendResult, make_alert
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger("roxy.notify")

RATE_WINDOW_S: Final = 600
"""Plan 17.7 "for 10 min": the rate alerts read the last 10 complete minutes."""
RATE_THRESHOLD_PCT: Final = 2.0
"""Plan 17.7 "over 2%" (Roblox 429s per upstream call; caller 5xx per caller request)."""
MIN_EVENTS: Final = 5
"""A noise floor: fewer 429s or 5xx answers than this in the window never alert, whatever the rate."""
RATES_INTERVAL_S: Final = 60.0
STORAGE_INTERVAL_S: Final = 1800.0
BACKUP_INTERVAL_S: Final = 1800.0
DIGEST_INTERVAL_S: Final = 300.0
STORAGE_ALERT_PCT: Final = 90.0
"""`storage_total_budget_gb`: "Roxy ... raises a SYS-DISK recommendation at 70 percent and an alert at 90 percent"."""
STORAGE_CRITICAL_PCT: Final = 100.0
"""Over the budget itself the storage alert is critical (plan 17.7 "Disk over budget")."""
GIB: Final = 1024**3
"""The catalog's GB is 1,073,741,824 bytes (the unit df -h shows)."""
GROWTH_DAYS: Final = 7
"""The storage alert's growth figure: bytes per day over the disk samples of the last week."""
BACKUP_STALE_H: Final = 26.0
"""Hours without a good backup before `backup_stale` (H-BACKUP's pass band: a nightly run plus two hours)."""
BACKUP_STATUS_FILE: Final = ("audit", "backup.json")
"""Where `deploy/tools/backup.sh` records its last success and failure, under the state directory."""
CALLER_SOURCES: Final[tuple[str, ...]] = ("roblox", "relay", "roxy", "cache")
"""Rollup sources of caller answers (Roxy's own probes, `internal`, are not caller traffic)."""
TOP_ROWS: Final = 3
"""Endpoints, egresses, statuses and reasons listed in a rate alert."""
MAX_DIGEST_RULES: Final = 10
MAX_PROBLEMS: Final = 5
"""Lines of `quick_check` output an integrity alert carries."""
SEND_TIMEOUT_S: Final = 60.0
"""A producer waits this long for the notifier (it has its own per channel timeouts)."""

JOB_RATES: Final = "alerts_rates"
JOB_STORAGE: Final = "alerts_storage"
JOB_BACKUP: Final = "alerts_backup"
JOB_DIGEST: Final = "alerts_digest"


# ------------------------------------------------------------------------------------------------- helpers


def _setting(ctx: Any, key: str) -> Any:
    return ctx.settings.get(key)


def _origin(ctx: Any) -> str:
    return str(getattr(getattr(ctx, "env", None), "site_origin", "") or "").rstrip("/")


def _pct(part: float, whole: float) -> float:
    return round(part * 100.0 / whole, 2) if whole else 0.0


def _rate_text(value: float) -> str:
    """A percentage for a subject: one decimal, no trailing `.0`."""
    text = f"{value:.1f}"
    return text[:-2] if text.endswith(".0") else text


def _size(n: float) -> str:
    """Bytes in the units `df -h` uses (binary), e.g. `1.2 GB`."""
    value = float(n)
    for unit in ("bytes", "KB", "MB", "GB"):
        if abs(value) < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "bytes" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def _listing(pairs: Sequence[tuple[Any, Any]]) -> str:
    return ", ".join(f"{name} ({count})" for name, count in pairs) or "none"


async def _send(ctx: Any, alert: Alert) -> dict[str, Any]:
    """Hand `alert` to the notifier and report what came of it (the notifier never raises for delivery)."""
    notifier = getattr(ctx, "alerts", None)
    if notifier is None:
        return {"alert": alert.type, "skipped": "no_notifier"}
    try:
        async with asyncio.timeout(SEND_TIMEOUT_S):
            result: SendResult = await notifier.send(alert)
    except Exception as exc:  # an alerting problem must not fail the job that noticed the problem
        log.warning("alert_producer_send_failed", extra={"fields": {"type": alert.type, "error": type(exc).__name__}})
        return {"alert": alert.type, "skipped": "error"}
    return {"alert": alert.type, "sent": list(result.sent), "skipped": result.skipped, "severity": alert.severity}


def rate_window(now: float, tz: str = "UTC") -> queries.Window:
    """The last `RATE_WINDOW_S` seconds of complete minutes before `now`."""
    end = int(now) // 60 * 60
    return queries.Window(end - RATE_WINDOW_S, end, "minute", tz)


# ------------------------------------------------------------------------------------------ Roblox 429 rate


def roblox_429_facts(conn: sqlite3.Connection, window: queries.Window) -> dict[str, Any]:
    """Roblox 429s and upstream calls in `window`, with the busiest endpoints and the egress split of the 429s."""
    totals = queries.totals_sync(conn, window)
    span = (window.start * 1000, window.end * 1000)
    endpoints = conn.execute(
        "SELECT endpoint_template, count(*) FROM upstream_429 WHERE at_ms >= ? AND at_ms < ? "
        "GROUP BY endpoint_template ORDER BY 2 DESC, 1 LIMIT ?",
        (*span, TOP_ROWS),
    ).fetchall()
    egresses = conn.execute(
        "SELECT egress, count(*) FROM upstream_429 WHERE at_ms >= ? AND at_ms < ? GROUP BY egress ORDER BY 2 DESC, 1",
        span,
    ).fetchall()
    return {
        "roblox_429": int(totals.get("roblox_429") or 0),
        "upstream_calls": int(totals.get("upstream_calls") or 0),
        "endpoints": [(str(r[0])[:120], int(r[1])) for r in endpoints],
        "egress": [(str(r[0])[:16], int(r[1])) for r in egresses],
    }


async def check_roblox_429(ctx: Any, now: float) -> dict[str, Any]:
    """Plan 17.7 "Roblox 429 rate over 2% for 10 min": `Roxy: Roblox is rate-limiting us (<rate>%)`."""
    window = rate_window(now)
    facts = await ctx.dbs.metrics.read(lambda conn: roblox_429_facts(conn, window))
    n429, calls = facts["roblox_429"], facts["upstream_calls"]
    rate = _pct(n429, calls)
    report: dict[str, Any] = {"roblox_429": n429, "upstream_calls": calls, "rate_pct": rate}
    if n429 < MIN_EVENTS or calls <= 0 or rate <= RATE_THRESHOLD_PCT:
        return report
    alert = make_alert(
        "roblox_429",
        summary=f"Roblox answered {n429} of Roxy's last {calls} upstream calls with 429 Too Many Requests in the last "
        f"{RATE_WINDOW_S // 60} minutes ({_rate_text(rate)}%). Roblox is rate limiting Roxy's address or account.",
        fields={
            "Top endpoints": _listing(facts["endpoints"]),
            "Egress split": _listing(facts["egress"]),
            "Roblox 429s": n429,
            "Upstream calls": calls,
            "Rate (percent)": rate,
        },
        link=f"{_origin(ctx)}/admin/recommendations",
        rate=_rate_text(rate),
    )
    report.update(await _send(ctx, alert))
    return report


# --------------------------------------------------------------------------------------------- caller 5xx


def caller_5xx_facts(conn: sqlite3.Connection, window: queries.Window) -> dict[str, Any]:
    """Caller requests and 5xx answers in `window` (a pause left out), by status and by reason."""
    callers = {"source": list(CALLER_SOURCES)}
    totals = queries.totals_sync(conn, window, filters=callers)
    paused = int(totals.get("paused") or 0)  # a pause answers 503 on purpose: not an error to alert about
    failing = {**callers, "status_class": "5xx"}

    def counts(filters: Mapping[str, Any], group_by: str) -> dict[str, int]:
        data = queries.collect(conn, window, filters=filters, group_by=group_by, bucketed=False)
        return {str(group): int(found.values["requests"]) for (_bucket, group), found in data.items()}

    def top(found: Mapping[str, int]) -> list[tuple[str, int]]:
        return sorted(((k, n) for k, n in found.items() if n > 0), key=lambda item: (-item[1], item[0]))[:TOP_ROWS]

    paused_statuses = counts({**failing, "reason_code": "paused"}, "status")
    statuses = {status: n - paused_statuses.get(status, 0) for status, n in counts(failing, "status").items()}
    reasons = counts(failing, "reason_code")
    reasons.pop("paused", None)
    return {
        "requests": max(0, int(totals.get("requests") or 0) - paused),
        "status_5xx": max(0, int(totals.get("status_5xx") or 0) - paused),
        "statuses": top(statuses),
        "reasons": top(reasons),
    }


async def check_caller_5xx(ctx: Any, now: float) -> dict[str, Any]:
    """Plan 17.7 "Caller 5xx over 2% for 10 min": `Roxy: caller errors at <rate>%`."""
    window = rate_window(now)
    facts = await ctx.dbs.metrics.read(lambda conn: caller_5xx_facts(conn, window))
    errors, requests = facts["status_5xx"], facts["requests"]
    rate = _pct(errors, requests)
    report: dict[str, Any] = {"status_5xx": errors, "requests": requests, "rate_pct": rate}
    if errors < MIN_EVENTS or requests <= 0 or rate <= RATE_THRESHOLD_PCT:
        return report
    alert = make_alert(
        "caller_5xx",
        summary=f"{errors} of the last {requests} caller requests got a 5xx answer in the last {RATE_WINDOW_S // 60} "
        f"minutes ({_rate_text(rate)}%).",
        fields={
            "Statuses": _listing(facts["statuses"]),
            "Top reasons": _listing(facts["reasons"]),
            "5xx answers": errors,
            "Caller requests": requests,
            "Rate (percent)": rate,
        },
        link=f"{_origin(ctx)}/admin/traffic",
        rate=_rate_text(rate),
    )
    report.update(await _send(ctx, alert))
    return report


# ------------------------------------------------------------------------------------------------- storage


def _growth_per_day(samples: Sequence[Mapping[str, Any]]) -> float | None:
    """Bytes per day between the oldest and newest sample (None under a day of samples)."""
    if len(samples) < 2:
        return None
    first, last = samples[0], samples[-1]
    span = int(last["at"]) - int(first["at"])
    if span < 86_400:
        return None
    return (int(last["total_bytes"]) - int(first["total_bytes"])) * 86_400.0 / span


async def check_storage(ctx: Any, now: float) -> dict[str, Any]:
    """Plan 17.7 "Disk over budget": `Roxy: storage at <pct>% of budget` from 90 percent of the budget."""
    from roxy.metrics import disk_history, read_producers

    paths = {db.name: Path(db.path) for db in ctx.dbs.all()}
    state_dir = getattr(ctx.env, "state_dir", None)
    folder = Path(state_dir) if state_dir else Path(ctx.dbs.metrics.path).parent
    measure = await asyncio.to_thread(disk_history.measure_files, folder, paths)
    budget = int(_setting(ctx, "storage_total_budget_gb")) * GIB
    used = int(measure.storage_bytes)
    pct = _pct(used, budget)
    report: dict[str, Any] = {"storage_bytes": used, "budget_bytes": budget, "pct": pct}
    if pct < STORAGE_ALERT_PCT:
        return report
    since = int(now) - GROWTH_DAYS * 86_400
    try:
        samples = await ctx.dbs.metrics.read(lambda conn: read_producers.disk_growth(conn, since))
    except (sqlite3.Error, SharedStateUnavailable):  # no history table yet, or a busy file: no growth figure
        samples = []
    growth = _growth_per_day(samples)
    largest = sorted(
        ((name, int(v.get("bytes") or 0) + int(v.get("wal_bytes") or 0)) for name, v in measure.files.items()),
        key=lambda item: -item[1],
    )[:TOP_ROWS]
    fields: dict[str, Any] = {
        "Largest": ", ".join(f"{name} {_size(size)}" for name, size in largest) or "none",
        "Growth per day": _size(growth) if growth is not None else "not enough history yet",
        "Storage bytes": used,
        "Budget bytes": budget,
        "Free bytes on the volume": int(measure.free_bytes),
        "Percent of budget": pct,
    }
    alert = make_alert(
        "disk",
        summary=f"Roxy's data uses {_size(used)}, {_rate_text(pct)}% of the {_size(budget)} storage budget "
        "(storage_total_budget_gb). Lower retention, purge the cache or raise the budget if the disk allows it.",
        fields=fields,
        link=f"{_origin(ctx)}/admin/data",
        severity="critical" if pct >= STORAGE_CRITICAL_PCT else "warn",
        pct=int(pct),
    )
    report.update(await _send(ctx, alert))
    return report


# ---------------------------------------------------------------------------------------- database integrity


def integrity_alert(ctx: Any, db_name: str, problems: Sequence[str]) -> Alert:
    """Plan 17.7 "DB integrity failure": `Roxy: database integrity check failed` (SQLite's own words only)."""
    lines = [str(line)[:200] for line in list(problems)[:MAX_PROBLEMS]]
    return make_alert(
        "db_integrity",
        summary=f"PRAGMA quick_check found damage in {db_name}.db. Stop writes and restore that file from the last "
        "backup (runbook).",
        fields={
            "Database": f"{db_name}.db",
            "Check output": " | ".join(lines) or "no detail",
            "Problems": len(problems),
        },
        link=f"{_origin(ctx)}/admin/data",
    )


def integrity_hook(ctx: Any) -> Callable[[str, list[str]], Awaitable[None]]:
    """The `on_integrity_failure` callback of `scheduler.jobs.register_storage_jobs` (the daily quick_check)."""

    async def hook(db_name: str, problems: list[str]) -> None:
        await _send(ctx, integrity_alert(ctx, db_name, problems))

    return hook


# ------------------------------------------------------------------------------------------------- backups


def _when(at: float | None, tz: str) -> str:
    if at is None:
        return "never"
    return datetime.fromtimestamp(at, zone(tz)).strftime("%Y-%m-%d %H:%M %Z")


async def check_backup(ctx: Any, now: float) -> dict[str, Any]:
    """Plan 17.7 "Backup failed or stale": `Roxy: backup failed` / `Roxy: no backup for <hours> h`.

    Reads `backup.json` (`deploy/tools/backup.sh`, the file H-BACKUP reads). No record at all (development, or a
    server whose first nightly backup has not run) sends nothing: H-BACKUP reports that case.
    """
    from roxy.health.facts import backup_facts_from, read_json_file

    state_dir = getattr(ctx.env, "state_dir", None)
    if not state_dir:
        return {"backup": "no state directory"}
    path = Path(state_dir).joinpath(*BACKUP_STATUS_FILE)
    document = await asyncio.to_thread(read_json_file, path)
    facts = backup_facts_from(document) if document is not None else None
    if facts is None or not facts.known:
        return {"backup": "no record"}
    tz = str(_setting(ctx, "ui_timezone") or "UTC")
    good = facts.last_success_at
    hours = int((now - good) // 3600) if good is not None else None
    link = f"{_origin(ctx)}/admin/data"
    failed = facts.last_failure_at is not None and (good is None or facts.last_failure_at > good)
    if failed:
        alert = make_alert(
            "backup_failed",
            summary=f"The backup failed at step {facts.last_failure_step or 'unknown'}.",
            fields={
                "Failed at": _when(facts.last_failure_at, tz),
                "Failed step": facts.last_failure_step or "unknown",
                "Last good backup": _when(good, tz),
                "Hours since the last good backup": hours if hours is not None else "never",
            },
            link=link,
        )
        return {"backup": "failed", **(await _send(ctx, alert))}
    if good is not None and now - good > BACKUP_STALE_H * 3600:
        alert = make_alert(
            "backup_stale",
            summary=f"No backup has completed for {hours} hours (the nightly backup should run every day).",
            fields={"Last good backup": _when(good, tz), "Hours since the last good backup": hours},
            link=link,
            hours=hours,
        )
        return {"backup": "stale", **(await _send(ctx, alert))}
    return {"backup": "ok", "hours_since_good": hours}


# -------------------------------------------------------------------------------------------------- digest


def digest_facts(conn: sqlite3.Connection, now: float, tz: str) -> dict[str, Any]:
    """Open recommendations by severity and rule, the latest health run's failures, the last day's 429 numbers."""
    from roxy.health import store
    from roxy.insights import read_recommendations

    by_severity: dict[str, int] = {}
    by_rule: dict[str, tuple[int, int]] = {}
    rank = {"critical": 2, "warn": 1}
    for row in read_recommendations.facets(conn):
        if row["state"] != "open":
            continue
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + int(row["count"])
        worst, count = by_rule.get(row["rule_id"], (0, 0))
        by_rule[row["rule_id"]] = (max(worst, rank.get(row["severity"], 0)), count + int(row["count"]))
    rules = sorted(by_rule, key=lambda rule: (-by_rule[rule][0], -by_rule[rule][1], rule))[:MAX_DIGEST_RULES]
    run_id = store.latest_run_id(conn)
    failing: list[str] = []
    if run_id is not None:
        failing = [str(r["check_id"]) for r in store.run_results(conn, run_id) if r.get("status") == "fail"]
    totals = queries.totals_sync(conn, queries.resolve_window("24h", now=now, tz=tz))  # the open minute included
    return {
        "open": sum(by_severity.values()),
        "by_severity": by_severity,
        "rules": rules,
        "health_run": run_id,
        "failing_checks": failing,
        "roblox_429": int(totals.get("roblox_429") or 0),
        "roblox_429_per_10k": totals.get("roblox_429_per_10k"),
        "requests": int(totals.get("requests") or 0),
    }


async def send_digest(ctx: Any, now: float, *, claim: Callable[[str], Awaitable[bool]] | None = None) -> dict[str, Any]:
    """Plan 17.7 "Daily digest": `Roxy daily digest: <n> open recommendations`, once per local day at
    `alert_digest_hour` (`-1` turns it off). `claim(day)` records the day in hot.db `job_runs` first (at most once
    per day across leadership changes); the gate's `digest:<day>` key dedupes as well."""
    hour = int(_setting(ctx, "alert_digest_hour"))
    if hour < 0:
        return {"digest": "off"}
    tz = str(_setting(ctx, "ui_timezone") or "UTC")
    local = datetime.fromtimestamp(now, zone(tz))
    if local.hour != hour:
        return {"digest": "not_due", "local_hour": local.hour}
    day = local.date().isoformat()
    notifier = getattr(ctx, "alerts", None)
    probe = make_alert("digest", summary="", n=0, day=day)
    if notifier is None or not notifier.passes_severity(probe):
        return {"digest": "skipped", "reason": "alert_min_severity" if notifier is not None else "no_notifier"}
    if claim is not None and not await claim(day):
        return {"digest": "already_sent", "day": day}
    facts = await ctx.dbs.metrics.read(lambda conn: digest_facts(conn, now, tz))
    severities = ", ".join(f"{name} {facts['by_severity'][name]}" for name in sorted(facts["by_severity"]))
    per_10k = facts["roblox_429_per_10k"]
    alert = make_alert(
        "digest",
        summary=f"{facts['open']} open recommendation(s); {len(facts['failing_checks'])} failing health check(s) in "
        f"the latest run; {facts['roblox_429']} Roblox 429s in the last 24 hours.",
        fields={
            "Open recommendations": severities or "none",
            "Rules": ", ".join(facts["rules"]) or "none",
            "Failing health checks": ", ".join(facts["failing_checks"][:20]) or "none",
            "Open recommendation count": facts["open"],
            "Roblox 429s (24 h)": facts["roblox_429"],
            "Roblox 429s per 10,000 requests (24 h)": per_10k if per_10k is not None else 0,
            "Requests (24 h)": facts["requests"],
        },
        link=f"{_origin(ctx)}/admin/recommendations",
        n=facts["open"],
        day=day,
    )
    return {"digest": "built", "day": day, **(await _send(ctx, alert))}


# ---------------------------------------------------------------------------------------------------- jobs


def register_jobs(registry: Any, ctx: Any) -> None:
    """Add the leader jobs `alerts_rates`, `alerts_storage`, `alerts_backup` and `alerts_digest` (none at start:
    a boot or a deploy never alerts on what it just did)."""
    from roxy.scheduler.jobs import Job

    async def rates(job: Any) -> dict[str, Any]:
        return {"roblox_429": await check_roblox_429(ctx, job.now), "caller_5xx": await check_caller_5xx(ctx, job.now)}

    async def storage(job: Any) -> dict[str, Any]:
        return await check_storage(ctx, job.now)

    async def backup(job: Any) -> dict[str, Any]:
        return await check_backup(ctx, job.now)

    async def digest(job: Any) -> dict[str, Any]:
        return await send_digest(ctx, job.now, claim=job.claim)

    for name, interval, fn, description in (
        (JOB_RATES, RATES_INTERVAL_S, rates, "Roblox 429 and caller 5xx rates over the last 10 minutes (17.7)."),
        (JOB_STORAGE, STORAGE_INTERVAL_S, storage, "Roxy's storage against storage_total_budget_gb (17.7)."),
        (JOB_BACKUP, BACKUP_INTERVAL_S, backup, "The backup status file: a failed or stale backup (17.7)."),
        (JOB_DIGEST, DIGEST_INTERVAL_S, digest, "The daily digest at alert_digest_hour (17.7)."),
    ):
        registry.add(Job(name, interval, fn, leader_only=True, run_at_start=False, description=description))


__all__ = [
    "BACKUP_STALE_H",
    "MIN_EVENTS",
    "RATE_THRESHOLD_PCT",
    "RATE_WINDOW_S",
    "STORAGE_ALERT_PCT",
    "check_backup",
    "check_caller_5xx",
    "check_roblox_429",
    "check_storage",
    "integrity_alert",
    "integrity_hook",
    "register_jobs",
    "send_digest",
]
