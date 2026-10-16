-- kind: expand
-- The endpoint policy (owner decision D1 revised on 2026-10-16; docs/endpoint_policy/BRIEF.md section 9.1, read by
-- roxy/rules/store.py and written by roxy/rules/service.py through the Endpoint policy page).
--
-- The policy itself ships with the code (roxy/policy/endpoint_policy_seed.json, one reviewed verdict per documented
-- Roblox operation). These two tables hold only the admin's changes to it, so a release that improves the shipped
-- verdicts never undoes a choice an admin made, and an empty table means "the shipped defaults".
--
-- The old credential_allowlist table stays (expand only: the previous release reads it during a blue and green
-- deploy). This release no longer reads it; a later contract migration drops it.

-- One row per operation an admin changed. endpoint_id is the seed id (`users:GET:/v1/users/{userId}`) or, for an
-- operation Roblox does not document, `unknown:<METHOD>:<template>`.
CREATE TABLE endpoint_policy_override (
    endpoint_id    TEXT PRIMARY KEY,
    verdict        TEXT NOT NULL CHECK (verdict IN ('BLOCK', 'ALLOW_TOKEN', 'ALLOW_ANON')),
    cache_private  INTEGER NOT NULL DEFAULT 0 CHECK (cache_private IN (0, 1)),
    note           TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at     INTEGER NOT NULL,
    created_by     TEXT NOT NULL,
    updated_at     INTEGER,
    updated_by     TEXT
) WITHOUT ROWID;

-- One row per category whose switch is not "defaults" (a missing row means defaults).
CREATE TABLE endpoint_policy_category (
    category    TEXT PRIMARY KEY,
    state       TEXT NOT NULL CHECK (state IN ('defaults', 'block_all', 'strip_credential')),
    note        TEXT,
    updated_at  INTEGER,
    updated_by  TEXT
) WITHOUT ROWID;
