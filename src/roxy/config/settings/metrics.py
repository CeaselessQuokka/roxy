"""Metrics settings: the catalog entries for group I of the settings catalog (plan 15.3 I).

What this is
    The `SettingSpec` declarations for every runtime setting that decides what Roxy remembers about its own
    traffic and for how long: the metrics pipeline (how often each worker writes its counters and how many
    items it may queue), retention for every table and file in plan 6.10, row caps, the disk budget, the daily
    maintenance hour, the live tail, the record caps carried over from v1, request and response body capture,
    and the privacy switches for logs and exports. The module exports `SETTINGS: list[SettingSpec]`.

Why it exists
    Every store Roxy keeps must be bounded (plan principle P9), and every bound must be visible and tunable
    from one place (P3). Statistics are what the dashboard, the recommendations engine and the LLM export are
    built from, so these knobs trade disk, memory and privacy against how much history an admin can look at.
    Declaring them once here generates validation, the settings editor, docs/SETTINGS.md and the export.

How it works
    Plain data, no logic. `roxy/config/catalog.py` imports `SETTINGS`, merges it with the other groups and
    checks it at import time. Conventions used here:
    - Defaults are the v2 defaults of plan 15.3 I and 6.10 (DESIGN.md section 0 overrides none of them).
    - Byte values are integers (64 MiB is 67108864); `_KIB`, `_MIB` and `_GIB` only make them readable.
    - Retention is in whole days (type int, unit "days"). 0 means "keep forever" only where plan 6.10 allows
      it: `retention_day_days` and `retention_settings_history_days`. Everywhere else a cap of 0 means "keep
      nothing", never "unlimited", so every store stays bounded. That includes `capture_max_body` and
      `capture_ttl_seconds`, where v1 used 0 for "no limit" (the notes say so for the migrator).
    - `high_risk_if` marks values that lose security evidence, leak client addresses, or can exhaust memory or
      disk. The default value is never high risk. SEC-DEFAULTS appears in `related_recommendations` on every
      key that has a high-risk value, because that rule proposes restoring a safer one.
    - `auto_apply_bounds` exists only on the two pipeline knobs that SYS-METRICS-DROP proposes; retention is
      never auto-applied because deleted history cannot be rolled back, and privacy keys never are.
    - `related_rules` names rule tables by their `RulesSnapshot` field names (DESIGN.md section 5).

What to read next
    `roxy/config/spec.py` (the field meanings), `roxy/config/catalog.py` (assembly and validation), then the
    code that reads these values: `roxy/storage/batch.py` (the batch writer), `roxy/metrics/recorder.py`,
    `roxy/metrics/capture.py`, `roxy/metrics/live.py` and the leader's retention job.
"""

from __future__ import annotations

from roxy.config.spec import (
    Apply,
    Group,
    Risk,
    RiskCondition,
    RiskOp,
    SettingSpec,
    SettingType,
)

# Readability helpers for byte sizes. The values stay plain integers.
_KIB = 1024
_MIB = 1024 * _KIB
_GIB = 1024 * _MIB

# Dashboard anchors (plan 15.6, DESIGN.md section 9).
_PIPELINE = "system#metrics-pipeline"
_LIVE_TAIL = "live#tail"
_RETENTION = "data#retention"
_RECORD_CAPS = "data#record-caps"
_CAPTURE = "live#capture"
_EXPORTS = "data#exports"

# Shared notes about the v1 migration (plan 18.3).
_IMPORT_IF_DIFFERENT = "Migration from v1 imports this value only when it differs from the v1 default (plan 18.3)."
_IMPORT_IF_LARGER = (
    "Migration from v1 imports this value only when it differs from the v1 default and is larger than the v2 "
    "default, because v1 caps were sized for in-memory lists and JSON files (plan 18.3)."
)
_NEVER_IMPORTED_RING = (
    "Never imported from v1: the v1 value (20) sized a small in-memory list, while v2 keeps these records on "
    "disk (plan 18.3)."
)

# Day values that would delete day rollups before the leader has compacted them into their month.
_DAY_RETENTION_TOO_SHORT = tuple(range(1, 30))


SETTINGS: list[SettingSpec] = [
    # --- Metrics pipeline (System > Metrics pipeline) ------------------------------------------------
    SettingSpec(
        key="metrics_flush_interval_ms",
        group=Group.METRICS,
        label="Metrics flush interval",
        type=SettingType.DURATION,
        default=2000,
        unit="ms",
        min=250,
        max=60000,
        step=50,
        description=(
            "How often each worker (one of the Roxy server processes that handle requests) writes the counters "
            "and events it has collected in memory to the statistics database. Charts only show what has been "
            "written, so this is also how far the dashboard lags behind real time."
        ),
        pages=(_PIPELINE,),
        if_raised=(
            "Fewer, larger database writes, but the dashboard lags further behind, a worker that crashes loses "
            "up to this much unsaved statistics, and the pending queue must hold more items between writes, so "
            "drops during bursts become more likely."
        ),
        if_lowered=(
            "A fresher dashboard and less lost on a crash, but every worker opens more write transactions per "
            "minute, which compete with other writers for the statistics database. Below about 500 ms the "
            "extra writes rarely help."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("metrics_queue_max",),
        related_recommendations=("SYS-METRICS-DROP",),
        auto_apply_bounds=(1000, 5000),
        renamed_from="autosave_interval",
        v1_default=30,
        notes=(
            "Replaces two v1 settings: autosave_interval (30 seconds) and diagnostics_flush_interval (10 "
            "seconds). Their values are never imported, because both the meaning and the unit changed (v1 "
            "counted seconds, v2 counts milliseconds; plan 18.3)."
        ),
    ),
    SettingSpec(
        key="metrics_queue_max",
        group=Group.METRICS,
        label="Metrics queue size per worker",
        type=SettingType.INT,
        default=50000,
        unit="items",
        min=1000,
        max=1000000,
        step=1000,
        description=(
            "The most events, Roblox 429 records, body captures and fingerprints one worker may hold in memory "
            "while waiting for its next write to the statistics database. When the queue is full the oldest "
            "low-priority items are dropped and counted on the System page, so a burst of traffic can never "
            "grow the queue without limit."
        ),
        pages=(_PIPELINE,),
        if_raised=(
            "Fewer items are dropped during traffic bursts or slow disk moments, but each worker can use more "
            "memory. On a server with about 1 GB of RAM a very large queue can push a worker past its memory "
            "limit."
        ),
        if_lowered=(
            "Each worker uses less memory, but items are dropped sooner during bursts, statistics get gaps, and "
            "the SYS-METRICS-DROP recommendation fires."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                200000,
                "Each worker may hold this many pending items in memory. On the production server (under 1 GB "
                "of RAM shared by every worker) a full queue this large can push a worker over its systemd "
                "memory limit, which kills it and loses everything it had not written yet.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("metrics_flush_interval_ms", "capture_max_body", "capture_sample_served_pct"),
        related_recommendations=("SYS-METRICS-DROP", "SEC-DEFAULTS"),
        auto_apply_bounds=(25000, 100000),
        notes="The queue is per worker, so total memory use grows with the number of workers.",
    ),
    # --- Rollup retention (Data > Retention) ---------------------------------------------------------
    SettingSpec(
        key="retention_minute_days",
        group=Group.METRICS,
        label="Minute statistics retention",
        type=SettingType.INT,
        default=14,
        unit="days",
        min=1,
        max=90,
        step=1,
        description=(
            "How many days of per-minute statistics to keep. Roxy stores traffic as rollups (one row of "
            "pre-summed counters per minute, hour and day), and the minute rows feed the live charts, the last "
            "hour and last day views, and anomaly detection. Hour and day totals are kept separately, so "
            "deleting old minutes does not change totals."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Minute-by-minute detail stays available for longer, at up to about 140 MB of disk per extra day "
            "at ten times today's traffic (usually far less)."
        ),
        if_lowered=(
            "Less disk is used, but minute detail disappears sooner: older periods show only hourly points, and "
            "anomaly detection has less minute history to compare against."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                30,
                "At ten times today's traffic each day of minute rows can take about 140 MB, so more than 30 "
                "days can use over 4 GB, a third of the default disk budget.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("retention_hour_days", "retention_client_minute_days", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK", "SEC-DEFAULTS"),
        notes=(
            "Replaces the v1 constants TRAFFIC_HISTORY_MINUTES, CACHE_HISTORY_MINUTES, TARPIT_HISTORY_MINUTES, "
            "ACTIVITY_HISTORY_MINUTES and MAX_BUDGET_MINUTES, which kept 2 to 25 hours of minute buckets in "
            "memory. Egress byte accounting at minute granularity follows this setting too."
        ),
    ),
    SettingSpec(
        key="retention_hour_days",
        group=Group.METRICS,
        label="Hour statistics retention",
        type=SettingType.INT,
        default=400,
        unit="days",
        min=7,
        max=3650,
        step=1,
        description=(
            "How many days of per-hour statistics to keep. Hour rows are built from closed minutes by the leader "
            "(the one worker that runs scheduled jobs) and power the week and month charts and the hour-of-day "
            "heatmap; the 400 day default keeps a little over a year so a week can be compared with the same "
            "week last year."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Hourly detail and hour-of-day patterns stay available for longer, at up to about 2.4 MB of disk per "
            "extra day at ten times today's traffic."
        ),
        if_lowered=(
            "Less disk is used; older periods show only daily points, and comparing an hour with the same hour "
            "last year stops working below 365 days."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_minute_days", "retention_day_days", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK",),
        notes="Egress byte accounting at hour granularity follows this setting too.",
    ),
    SettingSpec(
        key="retention_day_days",
        group=Group.METRICS,
        label="Day and month statistics retention",
        type=SettingType.INT,
        default=0,
        unit="days",
        min=0,
        max=36500,
        step=1,
        description=(
            "How many days of daily and monthly totals to keep; 0 keeps them forever. These rows are tiny (about "
            "37 MB per year at ten times today's traffic) and are what week over week, month over month and "
            "year over year comparisons use, so forever is the recommended setting."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Daily and monthly history is kept for longer. Any value above 0 eventually deletes old history; 0 "
            "never does."
        ),
        if_lowered=(
            "Old year over year and month over month comparisons become impossible once their days are deleted. "
            "Use 0 or at least 30: a value from 1 to 29 deletes days before they are rolled into their month, "
            "which leaves holes in month and year charts."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.IN,
                _DAY_RETENTION_TOO_SHORT,
                "Days younger than a month would be deleted before Roxy rolls them up into month totals, leaving "
                "permanent holes in month and year charts.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("retention_hour_days", "ui_timezone", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK", "SEC-DEFAULTS"),
        notes=(
            "Allowed values are 0 (forever) or 30 to 36500 days. Days and months are computed in the dashboard "
            "timezone (ui_timezone). Egress byte accounting at day and month granularity follows this setting "
            "too."
        ),
    ),
    SettingSpec(
        key="retention_client_minute_days",
        group=Group.METRICS,
        label="Per-client minute retention",
        type=SettingType.INT,
        default=3,
        unit="days",
        min=1,
        max=30,
        step=1,
        description=(
            "How many days of per-minute activity per client to keep. A client is one IP address or one Roblox "
            "experience (identified by the place id its game servers send); these rows show exactly what one "
            "client did minute by minute, for example during an attack."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Minute-level client history reaches further back, at up to about 115 MB of disk per extra day at "
            "ten times today's traffic."
        ),
        if_lowered=(
            "Less disk is used; minute-by-minute client drill-downs only cover the last few days, though hourly "
            "client history remains."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=(
            "retention_client_hour_days",
            "retention_client_day_days",
            "max_ip_activity_records",
            "max_caller_records",
            "activity_tracking",
        ),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_client_hour_days",
        group=Group.METRICS,
        label="Per-client hour retention",
        type=SettingType.INT,
        default=90,
        unit="days",
        min=7,
        max=400,
        step=1,
        description=(
            "How many days of per-hour activity per client (one IP address or one Roblox experience) to keep. "
            "Hourly client rows answer questions such as when one game started calling Roxy much more than "
            "usual, over the past weeks."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Hourly client history reaches further back, at up to about 1.9 MB of disk per extra day at ten "
            "times today's traffic."
        ),
        if_lowered="Less disk is used; client drill-downs older than the limit show only daily totals.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_client_minute_days", "retention_client_day_days", "activity_tracking"),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_client_day_days",
        group=Group.METRICS,
        label="Per-client day retention",
        type=SettingType.INT,
        default=730,
        unit="days",
        min=30,
        max=3650,
        step=1,
        description=(
            "How many days of daily totals per client (one IP address or one Roblox experience) to keep. Daily "
            "client rows show long-term trends, such as which experiences have used Roxy most over the past two "
            "years."
        ),
        pages=(_RETENTION,),
        if_raised="Long-term client history reaches further back, at up to about 80 KB of disk per extra day.",
        if_lowered="Less disk is used; long-term client history becomes shorter.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_client_hour_days", "activity_tracking"),
        related_recommendations=("SYS-DISK",),
    ),
    # --- Table and file retention (Data > Retention) -------------------------------------------------
    SettingSpec(
        key="retention_events_days",
        group=Group.METRICS,
        label="Event log retention",
        type=SettingType.INT,
        default=90,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days of the event log to keep. The event log has one row per notable thing that happened, "
            "such as a refusal, a ban, a circuit breaker opening, a credential status change or a data reset; "
            "it is also capped by row count (events_max_rows)."
        ),
        pages=(_RETENTION,),
        if_raised="Longer history of individual events for investigations, at about 300 bytes of disk per event.",
        if_lowered="Less disk is used; individual events older than the limit are gone (totals in the charts remain).",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("events_max_rows", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_upstream_429_days",
        group=Group.METRICS,
        label="Roblox 429 log retention",
        type=SettingType.INT,
        default=90,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days of the Roblox 429 log to keep. Each row is one 'too many requests' answer from "
            "Roblox, with the endpoint, the egress path (how the call left the server) and the Retry-After "
            "value; it is the main evidence behind upstream rate-limit recommendations."
        ),
        pages=(_RETENTION,),
        if_raised="Longer history of when and where Roblox rate limited Roxy, at about 200 bytes per row.",
        if_lowered=(
            "Less disk is used; long-term 429 patterns per endpoint become harder to see, and recommendations "
            "that look back further than the limit have less evidence."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("upstream_429_max_rows",),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_recommendations_days",
        group=Group.METRICS,
        label="Closed recommendation retention",
        type=SettingType.INT,
        default=365,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days closed recommendations (applied, dismissed, expired, resolved or rolled back) and "
            "their action history are kept. Open recommendations are never deleted by age, and at most 50,000 "
            "are kept in total. A dismissed or rolled back item is kept at least until its quiet period "
            "(dismiss_cooldown_days) ends, an applied one through its watch window."
        ),
        pages=(_RETENTION,),
        if_raised="A longer record of what Roxy suggested and what was done about it, at a small disk cost.",
        if_lowered="Less disk is used; the Recommendations history tab covers a shorter period.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("recommendation_expiry_days",),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_health_days",
        group=Group.METRICS,
        label="Health check history retention",
        type=SettingType.INT,
        default=180,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days of Check Proxy Health results to keep, whether the run was started by hand or by the "
            "schedule. The number of runs is also capped (health_runs_max)."
        ),
        pages=(_RETENTION,),
        if_raised="Longer health history, useful for spotting slow trends, at a small disk cost.",
        if_lowered="Less disk is used; the Health page history covers a shorter period.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("health_runs_max", "health_auto_interval_h"),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_fingerprints_days",
        group=Group.METRICS,
        label="Fingerprint retention",
        type=SettingType.INT,
        default=90,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days a fingerprint (a request header name, header value or User-Agent seen from callers) "
            "is kept after it was last seen. Fingerprints that keep appearing are never deleted by age."
        ),
        pages=(_RETENTION,),
        if_raised="Clients and tools that stopped calling stay recognizable for longer, at a small disk cost.",
        if_lowered="Less disk is used; fingerprints of clients that went quiet are forgotten sooner.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_header_name_records", "max_header_value_records", "max_user_agent_records"),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_errors_days",
        group=Group.METRICS,
        label="Error signature retention",
        type=SettingType.INT,
        default=180,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days an error signature (one kind of internal Roxy error, grouped by where in the code it "
            "happened) is kept after it last occurred. Errors that keep happening are never deleted by age."
        ),
        pages=(_RETENTION,),
        if_raised="Old, fixed errors stay in the Errors view for longer, which helps notice when one returns.",
        if_lowered="Less disk is used; an error that comes back after the limit looks brand new.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_error_records",),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_anomalies_days",
        group=Group.METRICS,
        label="Anomaly retention",
        type=SettingType.INT,
        default=90,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days detected anomalies are kept. An anomaly is a moment when a metric (for example "
            "requests, errors or Roblox 429s) moved far outside its usual range; anomalies are marked on charts "
            "and used as evidence by recommendations."
        ),
        pages=(_RETENTION,),
        if_raised="Older anomalies stay marked on charts and available as evidence, at a small disk cost.",
        if_lowered="Less disk is used; older anomaly markers disappear from charts.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_minute_days",),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_audit_days",
        group=Group.METRICS,
        label="Audit log retention",
        type=SettingType.INT,
        default=730,
        unit="days",
        min=400,
        max=3650,
        step=1,
        description=(
            "How many days of the admin audit log to keep. The audit log records every admin action (logins, "
            "setting and rule changes, bans, purges, resets, exports, credential replacement) with who, when "
            "and why; it can never be set below 400 days, so at least a full year can always be reviewed."
        ),
        pages=(_RETENTION,),
        if_raised="A longer trail of admin actions for security reviews; audit rows are small, so disk cost is minor.",
        if_lowered=(
            "Older admin actions are deleted sooner (never younger than 400 days), so a slow-moving compromise "
            "or an old mistake becomes harder to trace."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=("retention_settings_history_days",),
        notes=(
            "The audit table is append-only: database triggers block edits and deletes, except for this "
            "retention job, which never removes rows younger than 400 days. Recommendations never propose "
            "lowering it, and auto-apply never touches it."
        ),
    ),
    SettingSpec(
        key="retention_settings_history_days",
        group=Group.METRICS,
        label="Settings history retention",
        type=SettingType.INT,
        default=0,
        unit="days",
        min=0,
        max=3650,
        step=1,
        description=(
            "How many days of setting change history to keep; 0 keeps it forever. Each row records who changed "
            "which setting, from what, to what, and why, and powers one-click revert."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Older changes stay visible and revertible for longer; 0 keeps them all. Rows are small, so the "
            "disk cost is minor."
        ),
        if_lowered=(
            "Older changes disappear from the history and can no longer be reverted with one click; the audit "
            "log still records them for retention_audit_days."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_audit_days",),
        related_recommendations=("SYS-DISK",),
        notes=(
            "Independently of age, at most 100,000 rows are kept (oldest first), and the latest change of every "
            "setting is never deleted."
        ),
    ),
    SettingSpec(
        key="retention_expired_bans_days",
        group=Group.METRICS,
        label="Expired ban retention",
        type=SettingType.INT,
        default=30,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days a ban is kept as evidence after it has expired. An expired ban no longer blocks "
            "anyone; keeping it shows who was banned before, why, and how often."
        ),
        pages=(_RETENTION,),
        if_raised="A longer evidence trail of past bans, so repeat offenders are easier to recognize.",
        if_lowered="Expired bans disappear sooner, and a returning attacker looks like a new one.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_audit_days",),
        related_rules=("bans",),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_exports_days",
        group=Group.METRICS,
        label="Export file retention",
        type=SettingType.INT,
        default=14,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days generated export files (such as the LLM export and data exports) stay on the server "
            "for download before they are deleted. At most 400 export files are kept regardless of age."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Old exports stay downloadable for longer and use more disk; they contain client data (hashed, or "
            "raw if export_include_ips is on)."
        ),
        if_lowered="Export files are deleted sooner, which is more private; download what you need promptly.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("export_include_ips", "export_stable_ip_hash"),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="retention_snapshots_days",
        group=Group.METRICS,
        label="Safety snapshot retention",
        type=SettingType.INT,
        default=7,
        unit="days",
        min=1,
        max=3650,
        step=1,
        description=(
            "How many days safety snapshots are kept. Before a destructive data reset or a database migration, "
            "Roxy copies the affected database to a snapshot file so the change can be undone; total size is "
            "also capped (snapshots_max_bytes)."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Resets stay undoable for longer, at the cost of disk: each snapshot is a full copy of one database "
            "and can be hundreds of MB."
        ),
        if_lowered="Snapshots are deleted sooner, freeing disk; after that, a reset can no longer be undone.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("snapshots_max_bytes", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK",),
    ),
    # --- Row caps, disk budget and maintenance (Data > Retention) ------------------------------------
    SettingSpec(
        key="events_max_rows",
        group=Group.METRICS,
        label="Event log row cap",
        type=SettingType.INT,
        default=2000000,
        unit="rows",
        min=10000,
        max=50000000,
        step=10000,
        description=(
            "The most rows the event log may hold. When it is full, the oldest events are deleted first, even if "
            "they are younger than retention_events_days."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "More raw event history survives busy periods such as attacks, at about 300 bytes of disk per row "
            "(the default is about 600 MB when full)."
        ),
        if_lowered="Less disk is used; during an attack, older events are pushed out sooner.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                10000000,
                "More than 10 million events can use over 3 GB of disk at about 300 bytes per row, a quarter of "
                "the default disk budget, and slow down event queries.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("retention_events_days", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK", "SEC-DEFAULTS"),
    ),
    SettingSpec(
        key="upstream_429_max_rows",
        group=Group.METRICS,
        label="Roblox 429 log row cap",
        type=SettingType.INT,
        default=200000,
        unit="rows",
        min=10000,
        max=50000000,
        step=10000,
        description=(
            "The most rows the Roblox 429 log may hold. When it is full, the oldest rows are deleted first, even "
            "if they are younger than retention_upstream_429_days."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "More 429 history survives a bad rate-limit episode, at about 200 bytes of disk per row (the default "
            "is about 40 MB when full)."
        ),
        if_lowered="Less disk is used; after a long 429 episode, its earliest rows are pruned sooner.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                10000000,
                "More than 10 million rows can use over 2 GB of disk at about 200 bytes per row, and slow down "
                "the queries behind upstream recommendations.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("retention_upstream_429_days", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK", "SEC-DEFAULTS"),
    ),
    SettingSpec(
        key="health_runs_max",
        group=Group.METRICS,
        label="Health check history cap",
        type=SettingType.INT,
        default=2000,
        unit="runs",
        min=100,
        max=100000,
        step=100,
        description=(
            "The most Check Proxy Health runs kept in history, each with one result per check. The oldest runs "
            "are deleted first; runs older than retention_health_days are deleted even below this cap."
        ),
        pages=(_RETENTION,),
        if_raised="Longer health history, useful when checks run often, at a small disk cost.",
        if_lowered="Less history; with frequent runs, old results disappear within days.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_health_days", "health_auto_interval_h"),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="snapshots_max_bytes",
        group=Group.METRICS,
        label="Safety snapshot disk cap",
        type=SettingType.BYTES,
        default=2 * _GIB,  # 2147483648
        unit="bytes",
        min=0,
        max=100 * _GIB,  # 107374182400
        step=_MIB,
        description=(
            "Total disk space all safety snapshots may use together. Snapshots are copies of a database taken "
            "before a destructive reset or a migration so it can be undone; when the cap is reached, the oldest "
            "snapshots are deleted first."
        ),
        pages=(_RETENTION,),
        if_raised="More resets stay undoable, at the cost of more disk.",
        if_lowered=(
            "Less disk is used, but older snapshots are deleted sooner, so older resets can no longer be undone. "
            "0 takes no snapshots at all."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "No snapshot is taken before a destructive reset, so a mistaken reset of statistics, rules or "
                "settings cannot be undone.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("retention_snapshots_days", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK", "SEC-DEFAULTS"),
    ),
    SettingSpec(
        key="storage_total_budget_gb",
        group=Group.METRICS,
        label="Disk budget",
        type=SettingType.INT,
        default=12,
        unit="GB",
        min=1,
        max=1000,
        step=1,
        description=(
            "How much disk all of Roxy's data together (databases, captures, snapshots and exports) is expected "
            "to use. Roxy shows usage against this budget, raises a SYS-DISK recommendation at 70 percent and an "
            "alert at 90 percent; reaching it deletes nothing, because the retention settings do that."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Warnings come later. Never set it higher than the free disk you can really spare, or the disk can "
            "fill up before Roxy warns you."
        ),
        if_lowered=(
            "Warnings come earlier, giving more time to lower retention or clean up, but they may fire while "
            "plenty of disk is still free."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=(
            "retention_minute_days",
            "retention_hour_days",
            "events_max_rows",
            "capture_max_bytes",
            "snapshots_max_bytes",
            "cache_max_bytes",
        ),
        related_recommendations=("SYS-DISK",),
        notes=(
            "1 GB here means 1,073,741,824 bytes (the unit df -h shows). The default comes from the worst case "
            "estimate in plan 6.6 (about 7.5 GB) plus headroom; the H-DB-SIZE health check uses the same budget. "
            "Replaces the v1 24 MiB size limit of the JSON statistics file."
        ),
    ),
    SettingSpec(
        key="maintenance_hour",
        group=Group.METRICS,
        label="Daily maintenance hour",
        type=SettingType.INT,
        default=4,
        unit="hour",
        min=0,
        max=23,
        step=1,
        description=(
            "The local hour (in the dashboard timezone) when Roxy runs daily database maintenance: shrinking the "
            "write-ahead log files (journals of recent writes) of the cache and statistics databases, and "
            "refreshing the statistics SQLite uses to plan queries. It only starts when traffic is below its "
            "usual 24 hour median, so pick your quietest hour."
        ),
        pages=(_RETENTION,),
        if_raised=(
            "Maintenance moves later in the day. Choose the hour with the least traffic (the hour-of-day heatmap "
            "on the Traffic page shows it); during maintenance some requests can be slightly slower for a moment."
        ),
        if_lowered=(
            "Maintenance moves earlier in the day. Choose the hour with the least traffic (the hour-of-day "
            "heatmap on the Traffic page shows it); during maintenance some requests can be slightly slower for "
            "a moment."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("ui_timezone",),
        notes="Each maintenance run's duration is recorded on the System page.",
    ),
    # --- Live tail (System > Metrics pipeline, Live) -------------------------------------------------
    SettingSpec(
        key="live_tail_buffer",
        group=Group.METRICS,
        label="Live view history per worker",
        type=SettingType.INT,
        default=500,
        unit="requests",
        min=0,
        max=5000,
        step=1,
        description=(
            "How many recent requests each worker keeps in memory for the Live view, so opening the page shows "
            "recent history at once instead of an empty list. New requests stream in live regardless of this "
            "setting."
        ),
        pages=(_PIPELINE, _LIVE_TAIL),
        if_raised=(
            "You can scroll further back in the Live view, at the cost of a little more memory per worker (each "
            "row holds the request summary and up to 2,000 characters of body)."
        ),
        if_lowered=(
            "Less memory is used and the Live view opens with less history. 0 keeps none, so only requests that "
            "arrive while the page is open appear."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("capture_enabled", "metrics_queue_max"),
        renamed_from="max_live_requests",
        v1_default=150,
        notes=_IMPORT_IF_DIFFERENT + " The buffer is per worker, so memory use grows with the number of workers.",
    ),
    # --- Record caps (Data > Record caps) ------------------------------------------------------------
    SettingSpec(
        key="max_exploit_records",
        group=Group.METRICS,
        label="Probe records kept",
        type=SettingType.INT,
        default=5000,
        unit="records",
        min=0,
        max=1000000,
        step=1,
        description=(
            "How many records of probe attempts are kept. A probe is a request that looks like someone scanning "
            "for weaknesses, such as paths that belong to other software, oversized requests or smuggled login "
            "headers; when the cap is reached the oldest records are deleted first."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="A longer history of who probed Roxy and how, at a few hundred bytes of disk per record.",
        if_lowered="Less disk is used; older probes are forgotten sooner. 0 keeps none.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Probe attempts leave no record, so you cannot see who has been scanning Roxy for weaknesses.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("max_login_records", "max_crawl_records", "max_throttle_records"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=20,
        notes=_NEVER_IMPORTED_RING,
    ),
    SettingSpec(
        key="max_login_records",
        group=Group.METRICS,
        label="Admin login records kept",
        type=SettingType.INT,
        default=5000,
        unit="records",
        min=0,
        max=1000000,
        step=1,
        description=(
            "How many admin login attempts (successful and failed, with address and time) are kept for the "
            "Security page. When the cap is reached the oldest records are deleted first."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="A longer history of admin logins for security reviews, at a small disk cost.",
        if_lowered="Less disk is used; older login attempts are forgotten sooner. 0 keeps none.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Admin login attempts leave no record, so password guessing or the use of a stolen password "
                "would be invisible.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("max_exploit_records", "retention_audit_days"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=20,
        notes=_NEVER_IMPORTED_RING,
    ),
    SettingSpec(
        key="max_crawl_records",
        group=Group.METRICS,
        label="Crawler records kept",
        type=SettingType.INT,
        default=5000,
        unit="records",
        min=0,
        max=1000000,
        step=1,
        description=(
            "How many records of crawler visits are kept. Crawlers are search engines and other bots that read "
            "Roxy's public pages, recognized by their User-Agent (the text a client sends to say what software "
            "it is); each record has the address, visit count and last visit time."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="More crawler history, at a small disk cost.",
        if_lowered="Less disk is used; older crawler visits are forgotten sooner. 0 keeps none.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_exploit_records", "max_user_agent_records"),
        v1_default=20,
        notes=_NEVER_IMPORTED_RING,
    ),
    SettingSpec(
        key="max_throttle_records",
        group=Group.METRICS,
        label="Throttled client records kept",
        type=SettingType.INT,
        default=5000,
        unit="records",
        min=0,
        max=1000000,
        step=1,
        description=(
            "How many records of throttled clients are kept. A record is an IP address that went over the "
            "per-IP request limit, with how often it happened and when it last did."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="A longer history of who keeps hitting the limits, at a small disk cost.",
        if_lowered="Less disk is used; older throttle records are forgotten sooner. 0 keeps none.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Throttled clients leave no record, so you cannot see who keeps hitting the rate limits or "
                "decide whom to ban.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("max_exploit_records", "allowed_requests_per_minute"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=20,
        notes=_NEVER_IMPORTED_RING,
    ),
    SettingSpec(
        key="max_endpoint_records",
        group=Group.METRICS,
        label="Endpoints tracked in detail",
        type=SettingType.INT,
        default=5000,
        unit="endpoints",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many endpoints Roxy tracks in detail, with example paths and a list of recent requests for "
            "each. An endpoint here is a Roblox API path with its ids replaced by placeholders (a template, for "
            "example games.roblox.com/v1/games/{universeId}/votes); the busiest are kept and rare ones are "
            "folded into one 'other' entry."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="Rarely used endpoints keep their own detail, at the cost of disk and a longer Endpoints page.",
        if_lowered="Less disk is used; rarely used endpoints fall into 'other' sooner and lose their detail.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("endpoint_recent_requests",),
        v1_default=200,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="max_header_name_records",
        group=Group.METRICS,
        label="Header names tracked",
        type=SettingType.INT,
        default=1000,
        unit="headers",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many distinct request header names seen from callers are tracked with counts. Unusual header "
            "names are often the easiest way to recognize a particular client or exploit tool."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="More header detail, including rare headers, at a small disk cost.",
        if_lowered="Less disk is used; rare header names stop being tracked once the cap is reached.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_header_value_records", "retention_fingerprints_days"),
        v1_default=300,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="max_header_value_records",
        group=Group.METRICS,
        label="Values tracked per header",
        type=SettingType.INT,
        default=500,
        unit="values",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many distinct values are kept per request header name, for the header drill-down. Values of "
            "sensitive headers are stored as hashes (one-way fingerprints), never as text."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="More values per header, which helps tell clients apart, at the cost of more disk.",
        if_lowered="Less disk is used; fewer values are listed per header.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_header_name_records", "auto_ignore_high_cardinality", "retention_fingerprints_days"),
        related_rules=("ignored_value_headers",),
        v1_default=200,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="max_user_agent_records",
        group=Group.METRICS,
        label="User-Agents tracked",
        type=SettingType.INT,
        default=5000,
        unit="user agents",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many distinct User-Agent strings (the text a client sends to say what software it is) are "
            "tracked with counts. User-Agents are the main input for User-Agent rules and bot detection."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="More User-Agent detail, including rare clients, at a small disk cost.",
        if_lowered="Less disk is used; rare User-Agents stop being tracked once the cap is reached.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_fingerprints_days", "user_agent_rules_enabled"),
        v1_default=1000,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="max_error_records",
        group=Group.METRICS,
        label="Error signatures kept",
        type=SettingType.INT,
        default=2000,
        unit="signatures",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many distinct error signatures are kept in the Errors view. A signature is one kind of internal "
            "Roxy error, grouped by where in the code it happened, with a count and a redacted traceback (the "
            "list of code lines that led to it)."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="More error signatures are kept, at a small disk cost.",
        if_lowered="Less disk is used; the least recent signatures are pruned sooner.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("retention_errors_days",),
        v1_default=1000,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="endpoint_recent_requests",
        group=Group.METRICS,
        label="Recent requests per endpoint",
        type=SettingType.INT,
        default=10,
        unit="requests",
        min=0,
        max=50,
        step=1,
        description=(
            "How many recent requests each tracked endpoint remembers for its detail page: method, client, and "
            "up to 600 characters of query or body. 0 keeps only the details of the very last request."
        ),
        pages=(_RECORD_CAPS,),
        if_raised=(
            "More examples per endpoint, which helps debug what callers send, but more caller-supplied text is "
            "stored (up to 600 characters per example, for every tracked endpoint)."
        ),
        if_lowered="Fewer examples per endpoint and less stored caller data.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_endpoint_records",),
        v1_default=5,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="activity_tracking",
        group=Group.METRICS,
        label="Per-client activity tracking",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Whether Roxy records activity per client: how many requests each IP address and each Roblox "
            "experience (place id) made, how many were refused, and their busiest endpoint. This fills the "
            "Clients page and every client drill-down."
        ),
        pages=(_RECORD_CAPS,),
        if_enabled=(
            "Per-client and per-experience history is recorded (the default), at a small cost per request and "
            "some disk (see the retention_client_*_days settings)."
        ),
        if_disabled=(
            "No per-client activity is recorded: the Clients page and client drill-downs go empty, there is no "
            "record of which IPs or experiences caused a traffic spike, and recommendations that need per-client "
            "evidence may not fire. Limits and bans keep working."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "After an attack there is no record of which IP addresses or experiences caused it, which makes "
                "bans and follow-up much harder.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "max_ip_activity_records",
            "max_caller_records",
            "retention_client_minute_days",
            "retention_client_hour_days",
            "retention_client_day_days",
        ),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=1,
        notes=_IMPORT_IF_DIFFERENT,
    ),
    SettingSpec(
        key="max_ip_activity_records",
        group=Group.METRICS,
        label="IP addresses kept per period",
        type=SettingType.INT,
        default=500,
        unit="clients",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many IP addresses are kept individually in each minute, hour and day of client activity. When "
            "a period closes, the busiest addresses are kept and the rest are summed into one 'other' row."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="More clients are kept individually, at the cost of more disk for the client tables.",
        if_lowered="Less disk is used; more of the quieter clients fall into 'other'.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_caller_records", "activity_tracking", "retention_client_minute_days"),
        v1_default=400,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="max_caller_records",
        group=Group.METRICS,
        label="Experiences kept per period",
        type=SettingType.INT,
        default=500,
        unit="clients",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many Roblox experiences (place ids sent by game servers) are kept individually in each minute, "
            "hour and day of client activity. When a period closes, the busiest are kept and the rest are summed "
            "into one 'other' row."
        ),
        pages=(_RECORD_CAPS,),
        if_raised="More experiences are kept individually, at the cost of more disk for the client tables.",
        if_lowered="Less disk is used; more of the quieter experiences fall into 'other'.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_ip_activity_records", "activity_tracking", "retention_client_minute_days"),
        v1_default=200,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="auto_ignore_high_cardinality",
        group=Group.METRICS,
        label="Auto-ignore unique header values",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Whether Roxy automatically stops listing the values of a request header once its values turn out "
            "to be unique on almost every request (for example a request id or a timestamp). The header is "
            "added to the ignored value headers list, where you can see and undo the decision; its name is "
            "still counted."
        ),
        pages=(_RECORD_CAPS,),
        if_enabled=(
            "Headers whose values never repeat stop filling the fingerprint tables (the default), which keeps "
            "the header drill-down useful."
        ),
        if_disabled=(
            "Every unique value is stored until max_header_value_records is reached, which wastes disk and "
            "buries the useful values in noise."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("max_header_value_records",),
        related_rules=("ignored_value_headers",),
        v1_default=1,
        notes=(
            "A header is ignored automatically once it has been seen on at least 500 requests, its stored "
            "values have reached max_header_value_records, and at least 90 percent of the values seen were "
            "distinct. " + _IMPORT_IF_DIFFERENT
        ),
    ),
    # --- Body capture (Live > Capture) ---------------------------------------------------------------
    SettingSpec(
        key="capture_enabled",
        group=Group.METRICS,
        label="Request and response capture",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Whether Roxy stores the request and response bodies of some requests, with secrets removed, so you "
            "can click a row in the Live view and see exactly what a caller sent and what came back. Captures "
            "are kept only briefly (capture_ttl_seconds) and within strict size limits."
        ),
        pages=(_CAPTURE,),
        if_enabled=(
            "Every refused request and a sample of served requests (capture_sample_served_pct) are captured. "
            "This stores caller data, such as player names and ids in request bodies, on disk for up to "
            "capture_ttl_seconds."
        ),
        if_disabled=(
            "No caller payloads are stored at all. The Live view still shows each request's method, path, "
            "status and timing, but not the bodies, which makes debugging a game's failing requests much harder."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=(
            "capture_sample_served_pct",
            "capture_ttl_seconds",
            "capture_max_bytes",
            "capture_max_body",
            "live_tail_buffer",
        ),
        v1_default=1,
        notes=(
            "Owner decision D8 (recommended default, still pending owner confirmation): capture on, with "
            "stronger redaction than v1, a 15 minute lifetime, a 64 MiB cap and 20 percent of served requests "
            "sampled. " + _IMPORT_IF_DIFFERENT
        ),
    ),
    SettingSpec(
        key="capture_max_records",
        group=Group.METRICS,
        label="Captures kept",
        type=SettingType.INT,
        default=2000,
        unit="captures",
        min=0,
        max=100000,
        step=1,
        description=(
            "The most captures kept at once. One capture is the stored request and response of one request; "
            "when a new one would go over the cap, the oldest are removed first."
        ),
        pages=(_CAPTURE, _RETENTION),
        if_raised="More requests can be inspected in detail, and more caller data is kept on disk.",
        if_lowered=(
            "Fewer captures are kept, so older rows in the Live view show their capture as expired. 0 keeps "
            "none, which works like turning capture off."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("capture_max_bytes", "capture_ttl_seconds", "capture_enabled"),
        v1_default=250,
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="capture_max_bytes",
        group=Group.METRICS,
        label="Capture disk cap",
        type=SettingType.BYTES,
        default=64 * _MIB,  # 67108864
        unit="bytes",
        min=0,
        max=1 * _GIB,  # 1073741824
        step=1,
        description=(
            "Total disk space all captures together may use. When captures go over it, the oldest are removed "
            "first, so a few large bodies push out many small ones."
        ),
        pages=(_CAPTURE, _RETENTION),
        if_raised="More and larger captures fit, at the cost of more disk and more caller data stored.",
        if_lowered="Less disk is used; large bodies push out older captures sooner. 0 stores none.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("capture_max_records", "capture_max_body", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK",),
        v1_default=4 * _MIB,  # 4194304
        notes=_IMPORT_IF_LARGER,
    ),
    SettingSpec(
        key="capture_max_body",
        group=Group.METRICS,
        label="Captured body size limit",
        type=SettingType.BYTES,
        default=16 * _KIB,  # 16384
        unit="bytes",
        min=0,
        max=512 * _KIB,  # 524288
        step=1,
        description=(
            "The largest part of each request body and each response body kept in a capture; anything longer is "
            "cut off at this size. 0 stores no body text, only the request summary."
        ),
        pages=(_CAPTURE,),
        if_raised=(
            "Large payloads, such as big batch requests, are kept whole, but each capture uses more disk and "
            "removing secrets from bigger bodies costs more CPU per request."
        ),
        if_lowered=(
            "Captures are smaller and cheaper to make, but long bodies are cut short, which can hide the part "
            "you needed."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("capture_max_bytes", "max_body_bytes", "metrics_queue_max"),
        related_recommendations=("SYS-LOOP-LAG",),
        v1_default=16 * _KIB,  # 16384
        notes=(
            "In v1 this counted characters and 0 meant no limit; in v2 it counts bytes and 0 means no body is "
            "kept, so a v1 value of 0 is imported as the maximum (512 KiB). " + _IMPORT_IF_DIFFERENT
        ),
    ),
    SettingSpec(
        key="capture_ttl_seconds",
        group=Group.METRICS,
        label="Capture lifetime",
        type=SettingType.DURATION,
        default=900,
        unit="seconds",
        min=0,
        max=86400,
        step=1,
        description=(
            "How long a capture is kept before it is deleted, whatever the count and size caps allow. The short "
            "default limits how long caller payloads sit on disk."
        ),
        pages=(_CAPTURE, _RETENTION),
        if_raised=(
            "Captures stay available for longer, so a problem can be investigated after the fact, but caller "
            "payloads stay on disk longer."
        ),
        if_lowered=(
            "Caller data is deleted sooner; inspect a request soon after it happens or its capture shows as "
            "expired. 0 deletes captures at once, which works like turning capture off."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                3600,
                "Caller payloads (which can include player names, ids and anything else a game sends) stay on "
                "disk for more than an hour, far longer than debugging usually needs.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("capture_enabled", "capture_max_records", "capture_max_bytes"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=900,
        notes=(
            "In v1, 0 meant no age limit; in v2 0 means captures expire at once, so a v1 value of 0 is imported "
            "as the maximum (86400 seconds). " + _IMPORT_IF_DIFFERENT
        ),
    ),
    SettingSpec(
        key="capture_sample_served_pct",
        group=Group.METRICS,
        label="Served requests captured",
        type=SettingType.PERCENT,
        default=20,
        unit="percent",
        min=0,
        max=100,
        step=1,
        description=(
            "What share of successfully served requests (answered from Roblox or from the cache) are captured. "
            "Refused requests are always captured while capture is on, because those are usually the ones you "
            "need to investigate."
        ),
        pages=(_CAPTURE,),
        if_raised=(
            "More examples of normal traffic are captured, at the cost of more caller data stored, more disk and "
            "a little more CPU per request. At 100 every request is captured, as in v1."
        ),
        if_lowered="Fewer normal requests are captured; refusals still are. 0 captures refusals only.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("capture_enabled", "capture_max_records", "metrics_queue_max"),
        notes="New in v2 (owner decision D8); v1 captured every request while capture was on.",
    ),
    # --- Privacy of logs and exports (Data > Exports) ------------------------------------------------
    SettingSpec(
        key="log_hash_client_ips",
        group=Group.METRICS,
        label="Hash client IPs in logs",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether Roxy writes client IP addresses into its server logs as keyed hashes instead of plain "
            "addresses. The hash is an HMAC (a one-way fingerprint made with a secret key), so the same address "
            "always gives the same hash, but nobody without the key can work out the address by guessing."
        ),
        pages=(_EXPORTS,),
        if_enabled=(
            "Logs no longer show caller IP addresses, which is more private, but during an attack you cannot "
            "copy an address from the logs into a ban; you have to find the client in the dashboard instead."
        ),
        if_disabled=(
            "Logs show plain caller IP addresses (the default), which is what you need to respond to abuse "
            "quickly. Logs stay on the server, and alert emails only ever contain redacted log lines."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("export_include_ips", "export_stable_ip_hash"),
        notes=(
            "The hash key is the ip_hash_key service credential. It is rotated yearly, after which old and new "
            "hashes of the same address no longer match, by design."
        ),
    ),
    SettingSpec(
        key="export_include_ips",
        group=Group.METRICS,
        label="Raw IP addresses in exports",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether export files (such as the LLM export and data exports) contain real client IP addresses. "
            "When off, every address is replaced by a keyed hash (HMAC), so clients can still be told apart "
            "within an export but not identified."
        ),
        pages=(_EXPORTS,),
        if_enabled=(
            "Exports contain the raw IP addresses of callers (mostly Roblox game servers, sometimes people's own "
            "computers). Export files are meant to leave the server, for example to be shared with a helper or "
            "pasted into an AI assistant, so anyone who gets a file gets those addresses."
        ),
        if_disabled=(
            "Exports show hashes instead of addresses (the default). You can still see that two rows came from "
            "the same client, which is enough for most investigations."
        ),
        risk=Risk.HIGH,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                1,
                "Raw IP addresses end up in files designed to be copied off the server, where Roxy can no longer "
                "protect or delete them.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("export_stable_ip_hash", "retention_exports_days", "log_hash_client_ips"),
        related_recommendations=("SEC-DEFAULTS",),
    ),
    SettingSpec(
        key="export_stable_ip_hash",
        group=Group.METRICS,
        label="Same IP hashes across exports",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether exports hash IP addresses with Roxy's long-lived key instead of a fresh key made for each "
            "export. With the long-lived key the same client has the same hash in every export, so it can be "
            "followed from one export to the next."
        ),
        pages=(_EXPORTS,),
        if_enabled=(
            "The same client has the same hash in every export (until the yearly key rotation), so you can "
            "track a repeat offender across files, but anyone holding two exports can also link a client's "
            "activity across them."
        ),
        if_disabled=(
            "Each export uses its own key, so hashes only match within one file (the default). To follow one "
            "client across two exports, look it up in the dashboard."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                1,
                "Anyone who obtains two or more exports can match the same clients across them and build a "
                "longer activity history than any single file reveals.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("export_include_ips", "log_hash_client_ips", "retention_exports_days"),
        related_recommendations=("SEC-DEFAULTS",),
        notes="Has no effect while export_include_ips is on, because exports then contain raw addresses.",
    ),
]
