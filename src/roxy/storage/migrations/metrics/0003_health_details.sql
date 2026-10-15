-- kind: expand
-- Check Proxy Health details beyond the plan 6.2 columns (plan 13.1, 13.2; owned by roxy/health/store.py).
--
-- health_runs gains what a run was asked to do (`options_json`: the check list and whether credential checks
-- were included; never the admin's address) and who started it (`actor`, `admin:<name>` or `system:schedule`).
-- health_results gains `critical` (13.2 flags an account switch and a leak guard that did not block as
-- critical), the measured number and its unit (charts and comparisons without parsing text), a small bounded
-- detail document without secrets, and when the result was written (the order the live checklist filled in).
-- health_job_status holds the leader's job runner status, published every 30 s by the leader, so H-LEADER can
-- see late jobs from any worker (job status otherwise lives only in the leader's memory). One row per job;
-- rows not published for a day are deleted by the publisher itself.
-- Every column is added with a default (or nullable), so the previous release keeps working on this schema.

ALTER TABLE health_runs ADD COLUMN options_json TEXT;
ALTER TABLE health_runs ADD COLUMN actor TEXT;

ALTER TABLE health_results ADD COLUMN critical INTEGER NOT NULL DEFAULT 0;
ALTER TABLE health_results ADD COLUMN measured REAL;
ALTER TABLE health_results ADD COLUMN unit TEXT;
ALTER TABLE health_results ADD COLUMN detail_json TEXT;
ALTER TABLE health_results ADD COLUMN finished_ms INTEGER;

CREATE INDEX health_runs_trigger_started ON health_runs (trigger, started_at);
CREATE INDEX health_results_check ON health_results (check_id, run_id);

CREATE TABLE health_job_status (
    name              TEXT PRIMARY KEY,
    interval_s        REAL,
    last_started_at   REAL,
    last_finished_at  REAL,
    last_ok           INTEGER,
    holder            TEXT,
    published_at      INTEGER NOT NULL
) WITHOUT ROWID;
