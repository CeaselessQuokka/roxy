-- kind: expand
--
-- metrics.db, schema version 5 (wave 3b producers; plan 10.6, 10.7, 10.9, 11.5, 6.6, parity row 78). History that
-- the schema version 2 tables could not hold, so the recommendation rules that waited on it (FILTER-REMOVE,
-- SEC-BYPASS-FOREVER, TARPIT-TUNE, ABUSE-BOT, THROTTLE-TUNE, SYS-METRICS-DROP, SYS-DISK) read real data. Every table
-- except the two disk tables is written by the per-worker metrics recorder (`roxy/metrics/producers.py`, batch kind
-- `metrics.producers`) with upserts that add up across workers (C6); the disk tables are written by one leader job
-- (`roxy/metrics/jobs.py register_producer_jobs`). The leader job `metrics_producer_prune` bounds every table here.
-- Read models: `roxy/metrics/read_producers.py`. Conventions are explained at the top of control/0001_initial.sql.

-- Rule hits per rule and minute (plan 10.9 "per-check hit counts for the selected range", FILTER-REMOVE "hit
-- history"). `rule_hits` (schema 2) keeps one lifetime row per rule with its last hit; this keeps when the hits came.
-- `table_name` is the control.db table (`rules_endpoint_block`, `rules_endpoint_limit`, `rules_header`,
-- `rules_user_agent`, `access_list`, `bans`) and `rule_key` its primary key as text.
CREATE TABLE rule_hit_minute (
    bucket_start  INTEGER NOT NULL,
    table_name    TEXT NOT NULL,
    rule_key      TEXT NOT NULL,
    hits          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, table_name, rule_key)
) WITHOUT ROWID;
CREATE INDEX rule_hit_minute_rule ON rule_hit_minute (table_name, rule_key, bucket_start);

-- Tarpit holds per category, hold type and minute (plan 10.6, parity row 78, TARPIT-TUNE). A tarpit-eligible
-- refusal is either held (it took a fleet slot) or skipped (every slot was taken, or hot.db could not count it).
-- The arrival gap of a client is the time since its previous eligible refusal, split by whether that previous
-- refusal was held or answered at once: a hold that works makes the gap after it longer.
CREATE TABLE tarpit_minute (
    bucket_start             INTEGER NOT NULL,
    category                 TEXT NOT NULL,
    kind                     TEXT NOT NULL,              -- hold, drip or jitter (the planned type)
    holds                    INTEGER NOT NULL DEFAULT 0,
    skipped                  INTEGER NOT NULL DEFAULT 0,
    held_s_sum               REAL NOT NULL DEFAULT 0,    -- mean hold = held_s_sum / holds
    held_s_max               REAL NOT NULL DEFAULT 0,
    gaps_after_hold          INTEGER NOT NULL DEFAULT 0,
    gap_after_hold_s_sum     REAL NOT NULL DEFAULT 0,
    gaps_after_instant       INTEGER NOT NULL DEFAULT 0,
    gap_after_instant_s_sum  REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, category, kind)
) WITHOUT ROWID;

-- How long holds lasted, as a histogram per category and minute (fixed buckets, `producers.HOLD_BOUNDS_MS`), so a
-- p95 hold can be read for any range: percentiles cannot be averaged, bucket counts can be added.
CREATE TABLE tarpit_hold_minute (
    bucket_start  INTEGER NOT NULL,
    category      TEXT NOT NULL,
    bound_ms      INTEGER NOT NULL,                      -- the bucket's upper bound; -1 for the overflow bucket
    holds         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, category, bound_ms)
) WITHOUT ROWID;

-- Bot scores (plan 10.7) per client address and hour: the largest score any worker computed in the hour and the
-- most recent one. `client_key` is the same normalized address as the client tables (`metrics/activity.ip_key`).
CREATE TABLE client_score_hour (
    bucket_start  INTEGER NOT NULL,
    client_key    TEXT NOT NULL,
    score_max     INTEGER NOT NULL,
    score_last    INTEGER NOT NULL,
    last_at       INTEGER NOT NULL,
    samples       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, client_key)
) WITHOUT ROWID;
CREATE INDEX client_score_hour_client ON client_score_hour (client_key, bucket_start);

-- Metrics items each worker dropped per minute (SYS-METRICS-DROP, System > Metrics pipeline): `dropped` is the
-- batch writer's queue overflow (`metrics_queue_max`), `history_dropped` the recorder's bounded history maps,
-- `capture_dropped` the capture encoder's full queue. A row exists only for a minute that dropped something.
CREATE TABLE metrics_pipeline_minute (
    bucket_start     INTEGER NOT NULL,
    worker_id        TEXT NOT NULL,
    dropped          INTEGER NOT NULL DEFAULT 0,
    history_dropped  INTEGER NOT NULL DEFAULT 0,
    capture_dropped  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, worker_id)
) WITHOUT ROWID;

-- Disk use over time (SYS-DISK growth and projection, the Data page): one row per leader sample (hourly). The
-- state volume's size and free space, Roxy's storage (database files plus WAL plus exports and snapshots, the figure
-- SYS-DISK compares with `storage_total_budget_gb`), the per-file sizes, and the minute rollup rows written per
-- minute in the hour before the sample (the "distinct metric rows written per minute" of SYS-DISK).
CREATE TABLE disk_samples (
    at                   INTEGER PRIMARY KEY,
    total_bytes          INTEGER NOT NULL DEFAULT 0,
    free_bytes           INTEGER NOT NULL DEFAULT 0,
    storage_bytes        INTEGER NOT NULL DEFAULT 0,
    files_json           TEXT,
    rollup_rows_per_min  REAL
);

-- Table sizes over time, from SQLite's `dbstat` catalog (bytes of a table plus its indexes), sampled less often
-- than `disk_samples` because a full page walk costs I/O. cache.db is not walked (its file size is its one table).
CREATE TABLE table_size_samples (
    at          INTEGER NOT NULL,
    db          TEXT NOT NULL,
    table_name  TEXT NOT NULL,
    bytes       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (at, db, table_name)
) WITHOUT ROWID;
CREATE INDEX table_size_samples_table ON table_size_samples (db, table_name, at);
