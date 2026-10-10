-- kind: expand
-- What the dry run needs to replay limits and to scale samples (review round 4, findings LOGICFIX-5 and LOGICFIX-6;
-- written by roxy/metrics/samples.py through the recorder, read by roxy/insights/simulate.py).
--
-- `request_samples.sample_pct`: the `request_sample_pct` in force when the row was taken, so a dry run counts each
-- sample for 100 / its own rate instead of the live rate (after the rate changed inside the replay window, samples
-- taken at the old rate were counted at the new one). NULL on rows written before this column existed; the dry run
-- then reads the rate in force at the row's time from control.db `settings_history`.
--
-- `refusal_samples`: requests a limiter refused, sampled at the same rate as `request_samples`. Production never
-- sampled a refused request, so a limit dry run (THROTTLE-TUNE, the place limit, an endpoint rule) replayed a stream
-- without exactly the requests the limit refused and previewed about zero refusals. Only refusals by the per-IP
-- throttle and the checks after it in the abuse pipeline are kept (`samples.LIMIT_STREAM_REASONS`): those requests
-- reached the per-IP limiter. Pruned like `request_samples` (`request_sample_hours`, `request_sample_max_rows`); a
-- worker keeps at most `samples.MAX_REFUSAL_SAMPLES_PER_MINUTE` a minute (a flood never multiplies writes).
--
-- The previous release never names either, so it keeps working on this schema during a deploy.

ALTER TABLE request_samples ADD COLUMN sample_pct REAL;

CREATE TABLE refusal_samples (
    id                 INTEGER PRIMARY KEY,
    at_ms              INTEGER NOT NULL,
    reason             TEXT NOT NULL,
    endpoint_template  TEXT NOT NULL,
    method             TEXT NOT NULL,
    client_hash        TEXT,
    place              TEXT,
    sample_pct         REAL
);
CREATE INDEX refusal_samples_at_ms ON refusal_samples (at_ms);
