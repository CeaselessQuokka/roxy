-- kind: expand
--
-- cache.db, schema version 1 (plan 6.2). The shared response cache tier. Disposable: if it is ever damaged,
-- a worker renames it aside at startup and builds a fresh one (plan 5.5). Conventions are explained at the top
-- of control/0001_initial.sql.

-- Cache entries. id is sha256(key)[:24] (v1 format, so entry ids stay stable). auth_class is part of the key:
-- a credential response is never served to an anonymous request (plan 6.9).
-- This is a rowid table on purpose: Purge All deletes in batches with
-- `DELETE FROM entries WHERE rowid IN (SELECT rowid FROM entries LIMIT 5000)` (plan 6.5).
CREATE TABLE entries (
    id            TEXT PRIMARY KEY,
    key           TEXT NOT NULL,
    auth_class    TEXT NOT NULL DEFAULT 'anon' CHECK (auth_class IN ('anon', 'cred')),
    method        TEXT NOT NULL,
    host          TEXT NOT NULL,
    path          TEXT NOT NULL,
    params_json   TEXT,
    req_body      BLOB,                   -- compressed, only for allowlisted POST refresh
    status        INTEGER NOT NULL,
    content_type  TEXT,
    headers_json  TEXT,                   -- safe subset only
    body          BLOB,                   -- zstd
    body_len      INTEGER NOT NULL DEFAULT 0,
    stored_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    stale_until   INTEGER NOT NULL,
    ttl           INTEGER NOT NULL,
    rule_id       INTEGER,
    egress        TEXT,
    hits          INTEGER NOT NULL DEFAULT 0,
    last_hit_at   INTEGER,
    bytes         INTEGER NOT NULL DEFAULT 0,
    negative      INTEGER NOT NULL DEFAULT 0 CHECK (negative IN (0, 1)),
    generation    INTEGER NOT NULL DEFAULT 0   -- entries older than generation.value are misses (plan 6.5)
);
CREATE INDEX entries_expires_at ON entries (expires_at);
CREATE INDEX entries_last_hit_at ON entries (last_hit_at);
CREATE INDEX entries_host ON entries (host);
CREATE INDEX entries_rule_id ON entries (rule_id);
CREATE INDEX entries_stale_until ON entries (stale_until);

-- Singleton purge generation. Bumped first on every purge; each worker drops its memory tier when it sees a
-- new value and treats older entries as misses immediately.
CREATE TABLE generation (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    value       INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL DEFAULT 0
);
INSERT INTO generation (id, value, updated_at) VALUES (1, 0, 0);

-- Feeds TTL tuning (plan 11.5 F10): refetches that keep returning an identical body mean the TTL can rise.
-- day is the UTC day start in Unix seconds.
CREATE TABLE change_observations (
    endpoint_template  TEXT NOT NULL,
    day                INTEGER NOT NULL,
    refetches          INTEGER NOT NULL DEFAULT 0,
    identical_bodies   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (endpoint_template, day)
) WITHOUT ROWID;
CREATE INDEX change_observations_day ON change_observations (day);
