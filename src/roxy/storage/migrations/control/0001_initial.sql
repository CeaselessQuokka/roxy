-- kind: expand
--
-- control.db, schema version 1 (plan 6.2). Durable configuration: settings, rules, bans, admin accounts, the
-- audit log and metadata about the one Roblox credential (never the secret itself in clear text).
--
-- Conventions used in every migration file:
--   * Times are integer Unix seconds (UTC) unless the column name ends in _ms (milliseconds).
--   * Booleans are INTEGER 0 or 1 with a CHECK, because SQLite has no boolean type.
--   * *_json columns hold JSON text written by the application.
--   * `methods` columns hold comma separated upper case verbs, for example 'GET,HEAD'.
--   * `limit` is an SQL keyword, so columns named limit must be written as "limit" in queries.
--   * WITHOUT ROWID is used for small tables keyed by text: the row is stored inside the primary key index,
--     so a lookup is one B-tree search instead of two.
-- The runner (roxy/storage/migrate.py) wraps this whole file in one transaction and records it in
-- schema_version. auto_vacuum=INCREMENTAL was already set when the file was created (plan 6.5).

-- Current runtime setting values. Only overrides live here; defaults come from config/catalog.py.
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT NOT NULL
) WITHOUT ROWID;

-- Every settings change, for history and one-click revert. AUTOINCREMENT so an id is never reused, because
-- revert links and audit entries point at these ids.
CREATE TABLE settings_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT NOT NULL,
    old_json    TEXT,
    new_json    TEXT,
    changed_at  INTEGER NOT NULL,
    changed_by  TEXT NOT NULL,
    reason      TEXT,
    source      TEXT NOT NULL   -- admin, recommendation:<id>, auto_apply, import, revert, cli, system
);
CREATE INDEX settings_history_key_id ON settings_history (key, id);
CREATE INDEX settings_history_changed_at ON settings_history (changed_at);

-- Every admin action. Append-only: the triggers below refuse UPDATE always, and refuse DELETE unless the
-- retention job opened the prune gate in the same transaction for rows older than 400 days (plan 6.2, 6.10).
CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    at           INTEGER NOT NULL,
    actor        TEXT NOT NULL,
    actor_ip     TEXT,
    action       TEXT NOT NULL,
    target       TEXT,
    before_json  TEXT,   -- secret targets hold only {fingerprint, masked}
    after_json   TEXT,
    reason       TEXT,
    request_id   TEXT
);
CREATE INDEX audit_log_at ON audit_log (at);
CREATE INDEX audit_log_action_at ON audit_log (action, at);
CREATE INDEX audit_log_actor_at ON audit_log (actor, at);
CREATE INDEX audit_log_target_at ON audit_log (target, at);

-- The prune gate: holds a row only inside the retention transaction (storage/retention.py prune_audit_log).
-- Its cutoff can never be newer than 400 days before SQLite's own clock, whatever time the caller passes.
CREATE TABLE audit_prune_gate (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    cutoff_at  INTEGER NOT NULL
);

CREATE TRIGGER audit_prune_gate_minimum_age
BEFORE INSERT ON audit_prune_gate
WHEN NEW.cutoff_at > CAST(strftime('%s', 'now') AS INTEGER) - 400 * 86400
BEGIN
    SELECT RAISE(ABORT, 'audit_log retention must keep at least 400 days');
END;

CREATE TRIGGER audit_prune_gate_no_update
BEFORE UPDATE ON audit_prune_gate
BEGIN
    SELECT RAISE(ABORT, 'audit_prune_gate rows cannot be changed; delete and insert inside one transaction');
END;

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: rows cannot be changed');
END;

CREATE TRIGGER audit_log_retention_only_delete
BEFORE DELETE ON audit_log
WHEN NOT EXISTS (
    SELECT 1 FROM audit_prune_gate AS g
    WHERE g.id = 1
      AND OLD.at < g.cutoff_at
      AND g.cutoff_at <= CAST(strftime('%s', 'now') AS INTEGER) - 400 * 86400
)
BEGIN
    SELECT RAISE(ABORT, 'audit_log rows can only be deleted by the retention job, and only after 400 days');
END;

-- Endpoint blocks (403 "This endpoint is currently blocked.").
CREATE TABLE rules_endpoint_block (
    id          INTEGER PRIMARY KEY,
    pattern     TEXT NOT NULL,
    type        TEXT NOT NULL,          -- matcher type, rules/match.py (v1 semantics)
    note        TEXT,
    message     TEXT,
    created_at  INTEGER NOT NULL,
    created_by  TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    updated_at  INTEGER,
    updated_by  TEXT
);
CREATE INDEX rules_endpoint_block_enabled ON rules_endpoint_block (enabled);

-- Endpoint rate rules.
CREATE TABLE rules_endpoint_limit (
    id          INTEGER PRIMARY KEY,
    pattern     TEXT NOT NULL,
    type        TEXT NOT NULL,
    scope       TEXT NOT NULL CHECK (scope IN ('ip', 'place', 'global')),
    "limit"     INTEGER NOT NULL CHECK ("limit" >= 0),
    period      INTEGER NOT NULL CHECK (period > 0),   -- seconds
    message     TEXT,
    note        TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at  INTEGER,
    created_by  TEXT,
    updated_at  INTEGER,
    updated_by  TEXT
);
CREATE INDEX rules_endpoint_limit_enabled ON rules_endpoint_limit (enabled);

-- Cache rules.
CREATE TABLE rules_cache (
    id               INTEGER PRIMARY KEY,
    pattern          TEXT NOT NULL,
    type             TEXT NOT NULL,
    ttl              INTEGER NOT NULL CHECK (ttl >= 0),            -- seconds
    stale_ttl        INTEGER NOT NULL DEFAULT 0 CHECK (stale_ttl >= 0),
    negative_ttl     INTEGER NOT NULL DEFAULT 0 CHECK (negative_ttl >= 0),
    methods          TEXT NOT NULL DEFAULT 'GET',                  -- comma separated verbs
    normalize_flags  TEXT,                                         -- JSON list of normalization rules
    note             TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    origin           TEXT NOT NULL DEFAULT 'admin' CHECK (origin IN ('default', 'admin', 'recommendation')),
    created_at       INTEGER,
    created_by       TEXT,
    updated_at       INTEGER,
    updated_by       TEXT
);
CREATE INDEX rules_cache_enabled ON rules_cache (enabled);

-- User-Agent rules, evaluated in `position` order. The id is the 8 hex character v1 id, kept on import.
CREATE TABLE rules_user_agent (
    id          TEXT PRIMARY KEY CHECK (length(id) = 8),
    needle      TEXT NOT NULL,
    mode        TEXT NOT NULL,          -- contains, exact, regex (v1)
    kind        TEXT NOT NULL,          -- what the rule does (block, limit, tarpit, ...), abuse/checks/ua_rules.py
    scope       TEXT,
    "limit"     INTEGER,
    period      INTEGER,
    cooldown    INTEGER,
    message     TEXT,
    note        TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    position    INTEGER NOT NULL,
    created_at  INTEGER,
    created_by  TEXT,
    updated_at  INTEGER,
    updated_by  TEXT
) WITHOUT ROWID;
CREATE INDEX rules_user_agent_position ON rules_user_agent (position);

-- Request header filters. canonical_key is the v1 id (`header|scope|mode|needle`), unique so the same filter
-- can never be created twice.
CREATE TABLE rules_header (
    id             INTEGER PRIMARY KEY,
    canonical_key  TEXT NOT NULL UNIQUE,
    scope          TEXT NOT NULL,
    mode           TEXT NOT NULL,
    needle         TEXT NOT NULL,
    header         TEXT NOT NULL,
    message        TEXT,
    note           TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at     INTEGER,
    created_by     TEXT,
    updated_at     INTEGER,
    updated_by     TEXT
);

-- Per-endpoint routing rules (plan 7.2 step 2).
CREATE TABLE rules_routing (
    id          INTEGER PRIMARY KEY,
    pattern     TEXT NOT NULL,
    type        TEXT NOT NULL CHECK (type IN ('glob', 'regex')),
    mode        TEXT NOT NULL CHECK (mode IN ('prefer_direct', 'prefer_rotator', 'direct_only', 'rotator_only')),
    note        TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at  INTEGER NOT NULL,
    created_by  TEXT NOT NULL,
    updated_at  INTEGER,
    updated_by  TEXT
);

-- Per-host and per-endpoint upstream bucket overrides (plan 7.3).
CREATE TABLE upstream_limits (
    bucket_key  TEXT PRIMARY KEY,       -- host:<host> or endpoint:<template>
    per_min     REAL NOT NULL CHECK (per_min >= 0),
    burst       INTEGER NOT NULL CHECK (burst >= 0),
    origin      TEXT NOT NULL CHECK (origin IN ('default', 'admin', 'recommendation', 'adaptive')),
    note        TEXT,
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT NOT NULL
) WITHOUT ROWID;

-- Endpoints that may use the credential (D1: empty by default). The CHECK on methods makes "GET and HEAD
-- only" a property of the file, not just of the API that writes it. cache_private has no default on purpose:
-- whoever adds a row must decide it (plan 9.13).
CREATE TABLE credential_allowlist (
    id                   INTEGER PRIMARY KEY,
    pattern              TEXT NOT NULL,
    type                 TEXT NOT NULL,
    methods              TEXT NOT NULL DEFAULT 'GET' CHECK (methods IN ('GET', 'HEAD', 'GET,HEAD')),
    cache_private        INTEGER NOT NULL CHECK (cache_private IN (0, 1)),
    identical_anonymous  INTEGER NOT NULL DEFAULT 0 CHECK (identical_anonymous IN (0, 1)),
    note                 TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at           INTEGER NOT NULL,
    created_by           TEXT NOT NULL,
    updated_at           INTEGER,
    updated_by           TEXT
);

-- The escalation ladder (plan 10.4). A rung with action 'ban' creates a temporary ban for ban_minutes.
CREATE TABLE throttle_tiers (
    position     INTEGER PRIMARY KEY CHECK (position >= 0),
    multiplier   REAL NOT NULL CHECK (multiplier > 0),
    message      TEXT,
    note         TEXT,
    action       TEXT NOT NULL DEFAULT 'throttle' CHECK (action IN ('throttle', 'ban')),
    ban_minutes  INTEGER CHECK (ban_minutes IS NULL OR ban_minutes > 0)
);

CREATE TABLE cache_ignored_params (
    name    TEXT PRIMARY KEY,
    note    TEXT,
    origin  TEXT NOT NULL DEFAULT 'admin'   -- default, admin, recommendation, import
) WITHOUT ROWID;

CREATE TABLE ignored_value_headers (
    name  TEXT PRIMARY KEY,
    note  TEXT,
    auto  INTEGER NOT NULL DEFAULT 0 CHECK (auto IN (0, 1))
) WITHOUT ROWID;

CREATE TABLE ignored_paths (
    pattern  TEXT PRIMARY KEY,
    note     TEXT
) WITHOUT ROWID;

-- Bypass list, admin allowlist and deny list, CIDR aware.
CREATE TABLE access_list (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('bypass', 'allow_admin', 'deny')),
    cidr        TEXT NOT NULL,
    note        TEXT,
    expires_at  INTEGER,                -- NULL = never
    created_by  TEXT NOT NULL,
    created_at  INTEGER,
    UNIQUE (kind, cidr)
);
CREATE INDEX access_list_expires_at ON access_list (expires_at) WHERE expires_at IS NOT NULL;

-- Temporary and permanent bans.
CREATE TABLE bans (
    id            INTEGER PRIMARY KEY,
    subject_type  TEXT NOT NULL CHECK (subject_type IN ('ip', 'cidr', 'place', 'ua_hash')),
    subject       TEXT NOT NULL,
    reason_code   TEXT NOT NULL,
    reason_text   TEXT,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,              -- NULL = permanent
    created_by    TEXT NOT NULL,        -- admin, auto:<detector>, cli, import
    hits          INTEGER NOT NULL DEFAULT 0,
    last_hit_at   INTEGER
);
CREATE INDEX bans_subject ON bans (subject_type, subject);
CREATE INDEX bans_expires_at ON bans (expires_at) WHERE expires_at IS NOT NULL;

-- Small named state: pause, throttle-all, session epoch, credential/rotator/config versions, flush requests.
CREATE TABLE service_state (
    key         TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    updated_at  INTEGER
) WITHOUT ROWID;
-- Counters start at zero so writers can always `UPDATE ... SET value_json = value_json + 1` (plan 5.7).
INSERT INTO service_state (key, value_json, updated_at) VALUES
    ('config_version', '0', 0),
    ('session_epoch', '0', 0),
    ('credential_version', '0', 0),
    ('rotator_version', '0', 0);

-- Admin accounts (all full admins, D22). mfa_bootstrap_pending and email support DESIGN.md D5: the migrator
-- sets the flag for the imported account, whose first login uses the emailed code once before TOTP enrollment.
CREATE TABLE admin_users (
    id                        INTEGER PRIMARY KEY,
    username                  TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash             TEXT NOT NULL,      -- argon2id encoded hash
    totp_secret_enc           BLOB,               -- AES-GCM ciphertext (totp_encryption_key)
    recovery_codes_hash_json  TEXT,
    created_at                INTEGER NOT NULL,
    last_login_at             INTEGER,
    mfa_bootstrap_pending     INTEGER NOT NULL DEFAULT 0 CHECK (mfa_bootstrap_pending IN (0, 1)),
    email                     TEXT
);

CREATE TABLE admin_prefs (
    user_id     INTEGER NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value_json  TEXT NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, key)
) WITHOUT ROWID;

CREATE TABLE admin_passkeys (
    id             INTEGER PRIMARY KEY,
    user_id        INTEGER NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    credential_id  BLOB NOT NULL UNIQUE,
    public_key     BLOB NOT NULL,
    sign_count     INTEGER NOT NULL DEFAULT 0,
    transports     TEXT,                -- JSON list
    name           TEXT,
    created_at     INTEGER NOT NULL,
    last_used_at   INTEGER
);
CREATE INDEX admin_passkeys_user ON admin_passkeys (user_id);

-- Server-side sessions. Only a hash of the session id is stored, so a stolen database cannot be replayed.
CREATE TABLE admin_sessions (
    id_hash           TEXT PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    created_at        INTEGER NOT NULL,
    last_seen_at      INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    ip                TEXT,
    ua                TEXT,
    epoch             INTEGER NOT NULL,
    csrf_secret_hash  TEXT NOT NULL,
    mfa_level         TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX admin_sessions_user ON admin_sessions (user_id);
CREATE INDEX admin_sessions_expires_at ON admin_sessions (expires_at);

CREATE TABLE trusted_devices (
    id            INTEGER PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,
    user_id       INTEGER NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    name          TEXT,
    ua_family     TEXT,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX trusted_devices_user ON trusted_devices (user_id);
CREATE INDEX trusted_devices_expires_at ON trusted_devices (expires_at);

-- Emailed kill-switch links (hashed at rest).
CREATE TABLE invalidation_tokens (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
) WITHOUT ROWID;
CREATE INDEX invalidation_tokens_expires_at ON invalidation_tokens (expires_at);

-- The UI-replaced credential, AES-GCM encrypted (plan 9.8). CHECK (id = 1) makes it a single slot: there is
-- no way to store a second credential in this table (plan C1).
CREATE TABLE credential_store (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    ciphertext  BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    set_at      INTEGER NOT NULL,
    set_by      TEXT NOT NULL
);

-- Metadata about the one credential. Never the secret.
CREATE TABLE credential_meta (
    id                            INTEGER PRIMARY KEY CHECK (id = 1),
    fingerprint                   TEXT,     -- HMAC-SHA256[:16]
    masked                        TEXT,
    account_id_fingerprint        TEXT,
    superseded_fingerprints_json  TEXT NOT NULL DEFAULT '[]',
    set_at                        INTEGER,
    set_by                        TEXT,
    status                        TEXT NOT NULL DEFAULT 'unknown'
                                  CHECK (status IN ('unknown', 'active', 'cooling_down', 'rejected')),
    status_at                     INTEGER,
    last_probe_at                 INTEGER,
    last_probe_result             TEXT
);

-- The UI-set DataImpulse URL, AES-GCM encrypted (parity row 30). Single slot.
CREATE TABLE rotator_store (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    ciphertext   BLOB NOT NULL,
    nonce        BLOB NOT NULL,
    set_at       INTEGER NOT NULL,
    set_by       TEXT NOT NULL,
    masked_host  TEXT
);
