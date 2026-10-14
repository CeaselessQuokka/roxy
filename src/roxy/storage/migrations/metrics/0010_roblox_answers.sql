-- kind: expand
-- Roblox's answers per attempt (lead decision 11 of the final review, findings v1parity-1 and data-3; written by
-- roxy/metrics/recorder.py `record_attempts`, compacted by roxy/metrics/rollups.py, read by roxy/metrics/queries.py).
--
-- v1 counted every answer Roblox gave Roxy's calls in its 2xx, 4xx and "5xx from Roblox" totals (app/diagnostics.py
-- `log_status_code`, once per upstream answer): a 503 that Roxy's retry turned into a 200 for the caller counted as
-- one 5xx and one 2xx, and Roxy's own refusals and cache serves counted as nothing. v2's tiles read the caller's final
-- status from the rollups instead, and the only per-attempt record (`upstream_attempt_minute`) keeps 14 days and mixes
-- in Roxy's own probes. These four tables keep the answers Roblox gave the calls made for callers (their requests,
-- the background refreshes and the retries of both; never Roxy's own internal calls), by status class, at the same
-- levels as the rollups: minute rows written by every worker (upserts that add up, exact with any number of workers),
-- hour, local day and local month rows computed by the leader's compaction (day and month rows keep the zone they
-- were computed in, plan 6.4).
--
-- Separate tables, never new rollup columns: during a blue and green deploy the previous release's leader recomputes
-- `rollup_hour` and `rollup_day` buckets with DELETE plus INSERT of the columns it knows, which would wipe a new column
-- for every bucket it compacts. The previous release never names these tables, so it keeps working on this schema.
-- No backfill: v2 has no traffic from before this migration (the release ships with it; the v1 migrator writes no
-- rollups), and the read models say since when the counting runs when a range starts earlier.
--
-- Keys: the bucket, the endpoint template and host (bounded like the rollup dimensions, `metrics/templating.py`
-- vocabulary gates) and the egress (four values). Bounded like the rollups: minutes `retention_minute_days`, hours
-- `retention_hour_days`, days and months `retention_day_days` (`storage/retention.py`).

CREATE TABLE roblox_answer_minute (
    bucket_start       INTEGER NOT NULL,
    endpoint_template  TEXT NOT NULL,
    host               TEXT NOT NULL,
    egress             TEXT NOT NULL,
    answers_2xx        INTEGER NOT NULL DEFAULT 0,
    answers_3xx        INTEGER NOT NULL DEFAULT 0,
    answers_4xx        INTEGER NOT NULL DEFAULT 0,
    answers_5xx        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, endpoint_template, host, egress)
) WITHOUT ROWID;

CREATE TABLE roblox_answer_hour (
    bucket_start       INTEGER NOT NULL,
    endpoint_template  TEXT NOT NULL,
    host               TEXT NOT NULL,
    egress             TEXT NOT NULL,
    answers_2xx        INTEGER NOT NULL DEFAULT 0,
    answers_3xx        INTEGER NOT NULL DEFAULT 0,
    answers_4xx        INTEGER NOT NULL DEFAULT 0,
    answers_5xx        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, endpoint_template, host, egress)
) WITHOUT ROWID;

CREATE TABLE roblox_answer_day (
    bucket_start       INTEGER NOT NULL,
    endpoint_template  TEXT NOT NULL,
    host               TEXT NOT NULL,
    egress             TEXT NOT NULL,
    answers_2xx        INTEGER NOT NULL DEFAULT 0,
    answers_3xx        INTEGER NOT NULL DEFAULT 0,
    answers_4xx        INTEGER NOT NULL DEFAULT 0,
    answers_5xx        INTEGER NOT NULL DEFAULT 0,
    tz                 TEXT NOT NULL DEFAULT 'UTC',
    PRIMARY KEY (bucket_start, endpoint_template, host, egress)
) WITHOUT ROWID;

CREATE TABLE roblox_answer_month (
    bucket_start       INTEGER NOT NULL,
    endpoint_template  TEXT NOT NULL,
    host               TEXT NOT NULL,
    egress             TEXT NOT NULL,
    answers_2xx        INTEGER NOT NULL DEFAULT 0,
    answers_3xx        INTEGER NOT NULL DEFAULT 0,
    answers_4xx        INTEGER NOT NULL DEFAULT 0,
    answers_5xx        INTEGER NOT NULL DEFAULT 0,
    tz                 TEXT NOT NULL DEFAULT 'UTC',
    PRIMARY KEY (bucket_start, endpoint_template, host, egress)
) WITHOUT ROWID;
