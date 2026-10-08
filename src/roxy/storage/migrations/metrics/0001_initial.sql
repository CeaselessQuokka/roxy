-- kind: expand
--
-- metrics.db, schema version 1 (plan 6.2). Rollups, raw events and diagnostics. Written in batches by each
-- worker (storage/batch.py) and compacted by the leader. Disposable: losing it loses history, not
-- configuration. Conventions are explained at the top of control/0001_initial.sql.

-- Each combination of dimensions is stored once; rollup rows point at it with an 8 byte dim_hash.
-- dim_hash INTEGER PRIMARY KEY makes the hash the rowid itself (no separate index).
CREATE TABLE dims (
    dim_hash           INTEGER PRIMARY KEY,
    endpoint_template  TEXT NOT NULL,
    template_version   INTEGER NOT NULL,
    host               TEXT NOT NULL,
    method             TEXT NOT NULL,
    egress             TEXT NOT NULL,
    outcome            TEXT NOT NULL,
    reason_code        TEXT NOT NULL,
    status             INTEGER NOT NULL,   -- exact status; 0 means "other" (rare codes, plan 6.2)
    source             TEXT NOT NULL,
    cache_state        TEXT NOT NULL,
    auth_class         TEXT NOT NULL
);
CREATE INDEX dims_endpoint_template ON dims (endpoint_template);
CREATE INDEX dims_host ON dims (host);

-- The core time series: one row per minute per active dimension combination. WITHOUT ROWID (plan 6.2, 6.6):
-- rows live inside the (bucket_start, dim_hash) index. Histograms are varint-packed sparse blobs.
CREATE TABLE rollup_minute (
    bucket_start        INTEGER NOT NULL,
    dim_hash            INTEGER NOT NULL,
    requests            INTEGER NOT NULL DEFAULT 0,
    caller_bytes_in     INTEGER NOT NULL DEFAULT 0,
    caller_bytes_out    INTEGER NOT NULL DEFAULT 0,
    upstream_calls      INTEGER NOT NULL DEFAULT 0,
    upstream_bytes_in   INTEGER NOT NULL DEFAULT 0,
    upstream_bytes_out  INTEGER NOT NULL DEFAULT 0,
    errors              INTEGER NOT NULL DEFAULT 0,
    latency_hist        BLOB,
    queue_wait_hist     BLOB,
    PRIMARY KEY (bucket_start, dim_hash)
) WITHOUT ROWID;
CREATE INDEX rollup_minute_dim ON rollup_minute (dim_hash, bucket_start);

CREATE TABLE rollup_hour (
    bucket_start        INTEGER NOT NULL,
    dim_hash            INTEGER NOT NULL,
    requests            INTEGER NOT NULL DEFAULT 0,
    caller_bytes_in     INTEGER NOT NULL DEFAULT 0,
    caller_bytes_out    INTEGER NOT NULL DEFAULT 0,
    upstream_calls      INTEGER NOT NULL DEFAULT 0,
    upstream_bytes_in   INTEGER NOT NULL DEFAULT 0,
    upstream_bytes_out  INTEGER NOT NULL DEFAULT 0,
    errors              INTEGER NOT NULL DEFAULT 0,
    latency_hist        BLOB,
    queue_wait_hist     BLOB,
    PRIMARY KEY (bucket_start, dim_hash)
) WITHOUT ROWID;
CREATE INDEX rollup_hour_dim ON rollup_hour (dim_hash, bucket_start);

-- Day and month buckets are local days and months in ui_timezone; each row records the zone it was computed
-- in (plan 6.4), so a later timezone change never silently re-labels old days.
CREATE TABLE rollup_day (
    bucket_start        INTEGER NOT NULL,
    dim_hash            INTEGER NOT NULL,
    requests            INTEGER NOT NULL DEFAULT 0,
    caller_bytes_in     INTEGER NOT NULL DEFAULT 0,
    caller_bytes_out    INTEGER NOT NULL DEFAULT 0,
    upstream_calls      INTEGER NOT NULL DEFAULT 0,
    upstream_bytes_in   INTEGER NOT NULL DEFAULT 0,
    upstream_bytes_out  INTEGER NOT NULL DEFAULT 0,
    errors              INTEGER NOT NULL DEFAULT 0,
    latency_hist        BLOB,
    queue_wait_hist     BLOB,
    tz                  TEXT NOT NULL DEFAULT 'UTC',
    PRIMARY KEY (bucket_start, dim_hash)
) WITHOUT ROWID;
CREATE INDEX rollup_day_dim ON rollup_day (dim_hash, bucket_start);

CREATE TABLE rollup_month (
    bucket_start        INTEGER NOT NULL,
    dim_hash            INTEGER NOT NULL,
    requests            INTEGER NOT NULL DEFAULT 0,
    caller_bytes_in     INTEGER NOT NULL DEFAULT 0,
    caller_bytes_out    INTEGER NOT NULL DEFAULT 0,
    upstream_calls      INTEGER NOT NULL DEFAULT 0,
    upstream_bytes_in   INTEGER NOT NULL DEFAULT 0,
    upstream_bytes_out  INTEGER NOT NULL DEFAULT 0,
    errors              INTEGER NOT NULL DEFAULT 0,
    latency_hist        BLOB,
    queue_wait_hist     BLOB,
    tz                  TEXT NOT NULL DEFAULT 'UTC',
    PRIMARY KEY (bucket_start, dim_hash)
) WITHOUT ROWID;
CREATE INDEX rollup_month_dim ON rollup_month (dim_hash, bucket_start);

-- Per-client activity (client_type is 'ip' or 'place'). The leader keeps the top 500 per type per bucket plus
-- one 'other' row (plan 6.4).
CREATE TABLE client_minute (
    bucket_start  INTEGER NOT NULL,
    client_type   TEXT NOT NULL,
    client_key    TEXT NOT NULL,
    requests      INTEGER NOT NULL DEFAULT 0,
    refused       INTEGER NOT NULL DEFAULT 0,
    served        INTEGER NOT NULL DEFAULT 0,
    bytes         INTEGER NOT NULL DEFAULT 0,
    top_endpoint  TEXT,
    PRIMARY KEY (bucket_start, client_type, client_key)
) WITHOUT ROWID;
CREATE INDEX client_minute_client ON client_minute (client_type, client_key, bucket_start);

CREATE TABLE client_hour (
    bucket_start  INTEGER NOT NULL,
    client_type   TEXT NOT NULL,
    client_key    TEXT NOT NULL,
    requests      INTEGER NOT NULL DEFAULT 0,
    refused       INTEGER NOT NULL DEFAULT 0,
    served        INTEGER NOT NULL DEFAULT 0,
    bytes         INTEGER NOT NULL DEFAULT 0,
    top_endpoint  TEXT,
    PRIMARY KEY (bucket_start, client_type, client_key)
) WITHOUT ROWID;
CREATE INDEX client_hour_client ON client_hour (client_type, client_key, bucket_start);

CREATE TABLE client_day (
    bucket_start  INTEGER NOT NULL,
    client_type   TEXT NOT NULL,
    client_key    TEXT NOT NULL,
    requests      INTEGER NOT NULL DEFAULT 0,
    refused       INTEGER NOT NULL DEFAULT 0,
    served        INTEGER NOT NULL DEFAULT 0,
    bytes         INTEGER NOT NULL DEFAULT 0,
    top_endpoint  TEXT,
    PRIMARY KEY (bucket_start, client_type, client_key)
) WITHOUT ROWID;
CREATE INDEX client_day_client ON client_day (client_type, client_key, bucket_start);

-- Every Roblox 429 (capped).
CREATE TABLE upstream_429 (
    id                      INTEGER PRIMARY KEY,
    at_ms                   INTEGER NOT NULL,
    endpoint_template       TEXT NOT NULL,
    host                    TEXT NOT NULL,
    egress                  TEXT NOT NULL,
    retry_after_s           REAL,
    ratelimit_headers_json  TEXT,
    request_id              TEXT
);
CREATE INDEX upstream_429_at_ms ON upstream_429 (at_ms);
CREATE INDEX upstream_429_endpoint ON upstream_429 (endpoint_template, at_ms);

-- Raw notable events. AUTOINCREMENT: the live SSE tail reads "events after id N" (plan 14.11), so an id must
-- never be reused, even after every row was deleted by a reset.
CREATE TABLE events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms              INTEGER NOT NULL,
    type               TEXT NOT NULL,
    severity           TEXT NOT NULL,
    reason_code        TEXT,
    ip_hash            TEXT,
    place              TEXT,
    endpoint_template  TEXT,
    detail_json        TEXT
);
CREATE INDEX events_at_ms ON events (at_ms);
CREATE INDEX events_type_at ON events (type, at_ms);
CREATE INDEX events_ip_hash_at ON events (ip_hash, at_ms) WHERE ip_hash IS NOT NULL;

-- One row per proxied request (sampled), input for dry-run replay and TTL tuning (plan 11.3).
CREATE TABLE request_samples (
    id                 INTEGER PRIMARY KEY,
    at_ms              INTEGER NOT NULL,
    key_id             TEXT,
    endpoint_template  TEXT NOT NULL,
    method             TEXT NOT NULL,
    client_hash        TEXT,
    place              TEXT,
    cache_state        TEXT,
    upstream_status    INTEGER,
    egress             TEXT,
    body_hash          TEXT,
    bytes              INTEGER,
    auth_class         TEXT
);
CREATE INDEX request_samples_at_ms ON request_samples (at_ms);
CREATE INDEX request_samples_endpoint ON request_samples (endpoint_template, at_ms);
CREATE INDEX request_samples_key_id ON request_samples (key_id);

-- Vertical markers on every chart.
CREATE TABLE annotations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    kind      TEXT NOT NULL CHECK (kind IN ('config_change', 'reset', 'deploy', 'incident')),
    label     TEXT NOT NULL,
    audit_id  INTEGER
);
CREATE INDEX annotations_at ON annotations (at);

-- Byte accounting per egress (plan 8.3) at minute, hour, day and month granularity.
CREATE TABLE egress_usage (
    bucket_start    INTEGER NOT NULL,
    egress          TEXT NOT NULL,
    granularity     TEXT NOT NULL CHECK (granularity IN ('minute', 'hour', 'day', 'month')),
    requests        INTEGER NOT NULL DEFAULT 0,
    req_bytes       INTEGER NOT NULL DEFAULT 0,
    resp_bytes      INTEGER NOT NULL DEFAULT 0,
    overhead_bytes  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, egress, granularity)
) WITHOUT ROWID;
CREATE INDEX egress_usage_granularity ON egress_usage (granularity, bucket_start);

-- Recommendation lifecycle (plan 11.2). Ids are `rec_<ulid>` (core/ids.py).
CREATE TABLE recommendations (
    id                TEXT PRIMARY KEY,
    rule_id           TEXT NOT NULL,
    fingerprint       TEXT NOT NULL,
    state             TEXT NOT NULL,
    severity          TEXT NOT NULL,
    payload_json      TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    expires_at        INTEGER,
    snoozed_until     INTEGER,
    dismissed_reason  TEXT
);
CREATE INDEX recommendations_state ON recommendations (state, updated_at);
CREATE INDEX recommendations_rule ON recommendations (rule_id, fingerprint);
CREATE INDEX recommendations_updated_at ON recommendations (updated_at);

CREATE TABLE recommendation_actions (
    id                 INTEGER PRIMARY KEY,
    recommendation_id  TEXT NOT NULL,
    action             TEXT NOT NULL
                       CHECK (action IN ('apply', 'undo', 'snooze', 'dismiss', 'auto_apply', 'auto_rollback')),
    at                 INTEGER NOT NULL,
    actor              TEXT NOT NULL,
    details_json       TEXT
);
CREATE INDEX recommendation_actions_rec ON recommendation_actions (recommendation_id, at);
CREATE INDEX recommendation_actions_at ON recommendation_actions (at);

-- Check Proxy Health history (plan 13).
CREATE TABLE health_runs (
    id           INTEGER PRIMARY KEY,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    trigger      TEXT NOT NULL,           -- manual, schedule, deploy, cli
    summary      TEXT,                    -- JSON {"pass": n, "warn": n, "fail": n}
    version      TEXT
);
CREATE INDEX health_runs_started_at ON health_runs (started_at);

CREATE TABLE health_results (
    run_id       INTEGER NOT NULL,
    check_id     TEXT NOT NULL,
    status       TEXT NOT NULL,           -- pass, warn, fail, n/a
    value        TEXT,
    threshold    TEXT,
    explanation  TEXT,
    fix_link     TEXT,
    duration_ms  REAL,
    PRIMARY KEY (run_id, check_id)
);

-- Body capture ring (byte capped).
CREATE TABLE captures (
    id               INTEGER PRIMARY KEY,
    at               INTEGER NOT NULL,
    request_id       TEXT,
    outcome          TEXT,
    status           INTEGER,
    compressed_blob  BLOB,
    bytes            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX captures_at ON captures (at);

-- Fingerprints (capped like v1).
CREATE TABLE fingerprint_headers (
    name        TEXT PRIMARY KEY,         -- lower case header name
    count       INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX fingerprint_headers_last_seen ON fingerprint_headers (last_seen);

CREATE TABLE fingerprint_values (
    value_hash  TEXT PRIMARY KEY,         -- hash of (header name, value)
    name        TEXT NOT NULL,
    value       TEXT,                     -- redacted display value
    count       INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);
CREATE INDEX fingerprint_values_last_seen ON fingerprint_values (last_seen);
CREATE INDEX fingerprint_values_name ON fingerprint_values (name);

CREATE TABLE fingerprint_user_agents (
    ua_hash     TEXT PRIMARY KEY,
    user_agent  TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);
CREATE INDEX fingerprint_user_agents_last_seen ON fingerprint_user_agents (last_seen);

-- Error log by signature (plan 4.5).
CREATE TABLE errors (
    signature           TEXT PRIMARY KEY,
    count               INTEGER NOT NULL DEFAULT 0,
    first_seen          INTEGER NOT NULL,
    last_seen           INTEGER NOT NULL,
    source              TEXT,
    last_detail         TEXT,
    module_line         TEXT,
    traceback_redacted  TEXT
);
CREATE INDEX errors_last_seen ON errors (last_seen);

-- Detected anomalies (input for recommendations).
CREATE TABLE anomalies (
    id        INTEGER PRIMARY KEY,
    at        INTEGER NOT NULL,
    metric    TEXT NOT NULL,
    baseline  REAL,
    observed  REAL,
    zscore    REAL,
    window    TEXT
);
CREATE INDEX anomalies_at ON anomalies (at);

-- Fleet view (parity row 84), one row per live worker process, written every 5 s by scheduler/heartbeat.py.
-- A row is stale when last_seen is more than 20 s old.
CREATE TABLE worker_heartbeat (
    pid                INTEGER PRIMARY KEY,
    started_at         INTEGER NOT NULL,
    last_seen          INTEGER NOT NULL,
    rss                INTEGER,
    requests           INTEGER NOT NULL DEFAULT 0,
    proxied            INTEGER NOT NULL DEFAULT 0,
    loop_lag_ms_p99    REAL,
    open_conns         INTEGER,
    inflight_upstream  INTEGER,
    worker_id          TEXT,
    hostname           TEXT,
    color              TEXT,
    master_pid         INTEGER,
    max_requests       INTEGER,
    counters_reset_at  INTEGER,
    version            TEXT,
    is_leader          INTEGER NOT NULL DEFAULT 0 CHECK (is_leader IN (0, 1)),
    cache_generation   INTEGER
);
CREATE INDEX worker_heartbeat_last_seen ON worker_heartbeat (last_seen);

-- Imported v1 lifetime counters (D17).
CREATE TABLE legacy_totals (
    key         TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL
) WITHOUT ROWID;
