-- kind: expand
--
-- hot.db, schema version 1 (plan 6.2). Small, fast-changing shared state written on the request path:
-- limiters, upstream buckets, cooldowns, breakers, leases. Every row is cheap to rebuild, so the file uses
-- synchronous=NORMAL. Conventions are explained at the top of control/0001_initial.sql.
--
-- Every table here is keyed by text and has small rows, so every table is WITHOUT ROWID (one B-tree search
-- per lookup). Each table has an index on the column its pruning job filters on (storage/retention.py).

-- Per-IP, per-place, per-UA-rule, per-endpoint-rule and throttle-all limiters (GCRA or fixed window).
CREATE TABLE limiter (
    bucket_key    TEXT PRIMARY KEY,
    tat_ms        INTEGER NOT NULL DEFAULT 0,     -- GCRA theoretical arrival time
    window_start  INTEGER NOT NULL DEFAULT 0,
    count         INTEGER NOT NULL DEFAULT 0,
    updated_at    INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX limiter_updated_at ON limiter (updated_at);

-- Escalation ladder state per IP (plan 10.4).
CREATE TABLE strikes (
    ip               TEXT PRIMARY KEY,
    strikes          INTEGER NOT NULL DEFAULT 0,
    last_strike_at   INTEGER NOT NULL,
    tier             INTEGER NOT NULL DEFAULT 0,
    throttled_until  INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX strikes_last_strike_at ON strikes (last_strike_at);
CREATE INDEX strikes_throttled_until ON strikes (throttled_until);

-- Upstream GCRA buckets (global, egress, host, endpoint; plan 7.3).
CREATE TABLE upstream_bucket (
    bucket_key  TEXT PRIMARY KEY,
    tat_ms      INTEGER NOT NULL DEFAULT 0,
    burst       INTEGER NOT NULL,
    rate_per_s  REAL NOT NULL,
    updated_at  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX upstream_bucket_updated_at ON upstream_bucket (updated_at);

-- Adaptive concurrency (Tier 3, off by default). In-flight slots themselves are leases with expiry, so a
-- crashed worker cannot leak them.
CREATE TABLE aimd (
    key             TEXT PRIMARY KEY,
    "limit"         REAL NOT NULL,
    inflight        INTEGER NOT NULL DEFAULT 0,
    last_change_at  INTEGER NOT NULL
) WITHOUT ROWID;

-- Shared cooldowns (credential, endpoint, host, egress).
CREATE TABLE cooldown (
    key      TEXT PRIMARY KEY,
    until_ms INTEGER NOT NULL,
    source   TEXT NOT NULL CHECK (source IN ('retry_after', 'ratelimit_reset', 'breaker', 'default')),
    set_at   INTEGER NOT NULL,
    hits     INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX cooldown_until_ms ON cooldown (until_ms);

-- Circuit breakers (plan 7.10).
CREATE TABLE breaker (
    key           TEXT PRIMARY KEY,
    state         TEXT NOT NULL DEFAULT 'closed',   -- closed, open, half_open
    opened_at     INTEGER,
    half_open_at  INTEGER,
    failures      INTEGER NOT NULL DEFAULT 0,
    successes     INTEGER NOT NULL DEFAULT 0,
    window_start  INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX breaker_window_start ON breaker (window_start);

-- Leases: leader, single-flight (sf:<key>), tarpit slots (<prefix><n>), probe singletons, cache init.
-- epoch is a fencing token, incremented on every takeover (storage/leases.py, plan 5.6). Released leases keep
-- their row (expires_ms = 0) so the epoch keeps counting up across releases.
CREATE TABLE lease (
    name          TEXT PRIMARY KEY,
    holder        TEXT NOT NULL,
    expires_ms    INTEGER NOT NULL,
    epoch         INTEGER NOT NULL DEFAULT 0,
    payload_json  TEXT
) WITHOUT ROWID;
CREATE INDEX lease_expires_ms ON lease (expires_ms);

-- Idempotency keys for non-idempotent leader jobs: job:<name>:<bucket> (plan 5.6). Pruned after 7 days.
CREATE TABLE job_runs (
    idem_key     TEXT PRIMARY KEY,
    epoch        INTEGER NOT NULL,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER
) WITHOUT ROWID;
CREATE INDEX job_runs_started_at ON job_runs (started_at);

-- Fleet-wide alert dedupe (parity row 35).
CREATE TABLE email_gate (
    key           TEXT PRIMARY KEY,
    last_sent_at  INTEGER NOT NULL,
    suppressed    INTEGER NOT NULL DEFAULT 0   -- alerts skipped since last_sent_at, reported in the next one
) WITHOUT ROWID;
CREATE INDEX email_gate_last_sent_at ON email_gate (last_sent_at);

-- Login lockout counters: ip:<address> or global.
CREATE TABLE login_failures (
    subject       TEXT PRIMARY KEY,
    count         INTEGER NOT NULL DEFAULT 0,
    window_start  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX login_failures_window_start ON login_failures (window_start);

-- Sliding window counters for the spam detectors (plan 10.3), flushed by the batch writer every second.
CREATE TABLE spam_windows (
    subject       TEXT PRIMARY KEY,
    buckets_json  TEXT NOT NULL,
    updated_at    INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX spam_windows_updated_at ON spam_windows (updated_at);

-- Cached Roblox CSRF tokens per egress identity.
CREATE TABLE csrf_cache (
    egress_identity  TEXT PRIMARY KEY,
    token            TEXT NOT NULL,
    expires_at       INTEGER NOT NULL
) WITHOUT ROWID;
