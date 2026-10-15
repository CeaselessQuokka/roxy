-- kind: expand
--
-- metrics.db, schema version 2 (plan 11.1, 11.5; LEAD_NOTES "Fixture gaps for P10"). History the recommendation
-- rules need that schema version 1 did not record. Every table here is written by the per-worker metrics recorder
-- (`roxy/metrics/recorder.py`, batch kind `metrics.insight_history`), summed per minute with upserts so two workers
-- writing the same minute add up (C6), and pruned by the insights retention job (`roxy/insights/__init__.py`
-- `register_jobs`, job `insights_history_prune`). Read models: `roxy/metrics/read_history.py`.
-- Conventions are explained at the top of control/0001_initial.sql.

-- Upstream bucket fill history and rejections (plan 7.3, parity row 77, UP-BUCKET-TUNE): per bucket key and minute,
-- how many reservations asked for a slot, how many were refused because the wait was too long, and the fullest the
-- bucket was seen (0 to 100 percent of its burst).
CREATE TABLE bucket_minute (
    bucket_start   INTEGER NOT NULL,
    bucket_key     TEXT NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    rejections     INTEGER NOT NULL DEFAULT 0,
    fill_pct_peak  REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, bucket_key)
) WITHOUT ROWID;
CREATE INDEX bucket_minute_key ON bucket_minute (bucket_key, bucket_start);

-- Worker process samples (SYS-WORKER-SAT, SYS-LOOP-LAG): CPU use (cgroup cpu.stat, plan 17.1), event loop lag and
-- open connections per worker and minute. The heartbeat row only holds the latest value; this keeps the history.
CREATE TABLE worker_minute (
    bucket_start     INTEGER NOT NULL,
    worker_id        TEXT NOT NULL,
    samples          INTEGER NOT NULL DEFAULT 0,
    cpu_pct_sum      REAL NOT NULL DEFAULT 0,      -- mean = cpu_pct_sum / samples
    cpu_pct_max      REAL,
    loop_lag_ms_p99  REAL,                          -- the largest p99 reported in the minute
    open_conns       INTEGER,                       -- the largest count reported in the minute
    rss              INTEGER,
    PRIMARY KEY (bucket_start, worker_id)
) WITHOUT ROWID;

-- Shared cache tier stores and evictions per minute (CACHE-PRESSURE). An eviction is "young" when the entry was
-- evicted before its lifetime ran out (age below its TTL): the cache was too small for it.
CREATE TABLE cache_minute (
    bucket_start       INTEGER PRIMARY KEY,
    stores             INTEGER NOT NULL DEFAULT 0,
    evictions          INTEGER NOT NULL DEFAULT 0,
    young_evictions    INTEGER NOT NULL DEFAULT 0,
    evicted_age_s_sum  REAL NOT NULL DEFAULT 0,
    young_age_s_sum    REAL NOT NULL DEFAULT 0
);

-- One row per eviction pass (`cache/store.py EvictionReport`), so a rule can tell which cap forced the evictions.
CREATE TABLE cache_eviction_passes (
    id              INTEGER PRIMARY KEY,
    at              INTEGER NOT NULL,
    entries_before  INTEGER NOT NULL DEFAULT 0,
    bytes_before    INTEGER NOT NULL DEFAULT 0,
    evicted         INTEGER NOT NULL DEFAULT 0,
    freed_bytes     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX cache_eviction_passes_at ON cache_eviction_passes (at);

-- When each rule row last matched a request (FILTER-REMOVE, SEC-BYPASS-FOREVER): `table_name` is the control.db
-- table (`rules_endpoint_block`, `rules_user_agent`, `access_list`, ...) and `rule_key` its primary key as text.
CREATE TABLE rule_hits (
    table_name    TEXT NOT NULL,
    rule_key      TEXT NOT NULL,
    hits          INTEGER NOT NULL DEFAULT 0,
    first_hit_at  INTEGER,
    last_hit_at   INTEGER,
    PRIMARY KEY (table_name, rule_key)
) WITHOUT ROWID;
CREATE INDEX rule_hits_last ON rule_hits (last_hit_at);

-- Error occurrences per signature and minute (SYS-ERRORS: hourly counts against a 7-day baseline). The `errors`
-- table keeps one summary row per signature; this keeps when they happened.
CREATE TABLE error_minute (
    signature     TEXT NOT NULL,
    bucket_start  INTEGER NOT NULL,
    count         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (signature, bucket_start)
) WITHOUT ROWID;
CREATE INDEX error_minute_bucket ON error_minute (bucket_start);

-- Upstream calls by attempt (UP-429-AMPLIFY, UP-CSRF-LOOP, UP-CHALLENGE, EGR-POOL-BURNED), summed per minute.
-- `kind` is first, csrf_retry, fallback_429, retry_5xx or redirect; `status` is -1 when no answer came (a timeout);
-- `exit_id` is a short hash of the rotator session ('' for other egresses).
CREATE TABLE upstream_attempt_minute (
    bucket_start       INTEGER NOT NULL,
    endpoint_template  TEXT NOT NULL,
    egress             TEXT NOT NULL,
    attempt            INTEGER NOT NULL,
    kind               TEXT NOT NULL,
    status             INTEGER NOT NULL,
    challenge          INTEGER NOT NULL DEFAULT 0 CHECK (challenge IN (0, 1)),
    html_body          INTEGER NOT NULL DEFAULT 0 CHECK (html_body IN (0, 1)),
    exit_id            TEXT NOT NULL DEFAULT '',
    count              INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, endpoint_template, egress, attempt, kind, status, challenge, html_body, exit_id)
) WITHOUT ROWID;
CREATE INDEX upstream_attempt_minute_template ON upstream_attempt_minute (endpoint_template, bucket_start);

-- The rotator provider's own byte figure for the current billing cycle, typed in by the admin from the provider's
-- dashboard (EGR-CALIBRATE compares it with Roxy's metered bytes).
CREATE TABLE egress_provider_reports (
    id              INTEGER PRIMARY KEY,
    at              INTEGER NOT NULL,
    reported_bytes  INTEGER NOT NULL,
    entered_by      TEXT
);
CREATE INDEX egress_provider_reports_at ON egress_provider_reports (at);

-- The watch window after an applied or auto-applied recommendation (plan 11.3, 11.4): the guard metrics measured
-- before the change, and what the watch decided (kept or rolled back).
CREATE TABLE recommendation_watches (
    recommendation_id  TEXT PRIMARY KEY,
    action_id          INTEGER,
    started_at         INTEGER NOT NULL,
    ends_at            INTEGER NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('watching', 'kept', 'rolled_back', 'canceled')),
    baseline_json      TEXT,
    result_json        TEXT
);
CREATE INDEX recommendation_watches_state ON recommendation_watches (state, ends_at);
