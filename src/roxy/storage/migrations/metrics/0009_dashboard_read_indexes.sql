-- kind: expand
-- Indexes for the dashboard reads that missed plan 6.7 (a page under 300 ms, a 90 day read under 500 ms) at plan
-- 6.6's volume (the P11 latency lanes, `.remake/p11_reports/latency.md` and `gaps_latency.md`; docs/PERFORMANCE.md
-- "Dashboard pages"). No table is rebuilt and no row is rewritten: the previous release keeps reading and writing
-- this file during a deploy, and every row it writes is indexed like this release's (an index belongs to the file,
-- not to the code), so the numbers read through these indexes are the same whoever wrote the rows.
--
-- Events (`events`, written by roxy/metrics/recorder.py): the refusal and failure cards counted reasons, message
-- sources, clients and failure groups from `detail_json` of every event in the range, which over 90 days parsed up to
-- 2 million JSON documents per card. Five VIRTUAL generated columns name the detail fields those reads use. A
-- VIRTUAL column is computed when it is read (or when an index stores it), never stored in the row, so adding one
-- rewrites nothing; the previous release never names them (its INSERTs list their columns). Each is exactly the
-- expression the reads used before, guarded by `json_valid` so a detail that is not JSON (Roxy never writes one)
-- reads as an absent field instead of failing the write that indexes it:
--   `detail_count`: `coalesce($.count, 1)`, how many occurrences the row stands for (a folded row carries a count);
--   `detail_message_source`: `coalesce($.message_source, '')`, whose words the caller got (row 116);
--   `detail_egress`, `detail_upstream_status`, `detail_aggregated`: the failure log's group and folded marker;
--   `detail_ip`: the caller address of a live row (live rows keep the raw address only in the detail).
--
-- Partial indexes cover only the rows those reads ask for, and a read uses one only when it repeats the index's WHERE
-- term exactly (roxy/metrics/queries.py `REFUSAL_EVENT_TYPES`):
--   `events_refusal_sources`: refusal and failure counts per reason and message source in a time range
--     (`queries.refusal_reasons`, `message_source_split`, `returned_reasons`);
--   `events_refusal_clients`: distinct clients and unattributed counts per reason (`queries.refusal_reasons`);
--   `events_failure_groups`: the Upstream failure log grouped by egress, reason and Roblox's status, walked in group
--     order without a sort (`read_upstream.failure_log`);
--   `events_refusal_places`: one place's refusals by reason (`read_clients.client_refusals`);
--   `events_live_places`, `events_live_ips`: one client's newest live rows (`read_clients.recent_live`), which
--     walked every live row (or the whole table when the client had none).
-- Bounded like the table (`events_max_rows`, `retention_events_days`); live rows are kept 15 minutes.
--
-- Client activity (`client_minute`, `client_hour`, `client_day`, written by roxy/metrics/rollups.py):
--   `*_pair_place`: the place part of a pair key (`<ip>|<place>`, `rollups.PAIR_SEPARATOR`), so the peers of a place
--     (the distinct addresses that called as it, `read_client_extras.peer_counts` and `peer_list`) are an index range
--     instead of a scan of every pair row of the window;
--   `client_minute_ip_rows`: every column the address table sums, in key order (`queries.client_table_sync`), so a
--     window of many hours is summed per address without sorting the window's rows (the numbers stay the exact sums
--     of the minute rows; reading the hourly rows instead would fold the addresses beyond each hour's top 500).
-- Bounded like their tables (the per-bucket caps and `retention_client_*_days`).

ALTER TABLE events ADD COLUMN detail_count
    GENERATED ALWAYS AS (CASE WHEN json_valid(detail_json) THEN coalesce(json_extract(detail_json, '$.count'), 1)
                              ELSE 1 END) VIRTUAL;
ALTER TABLE events ADD COLUMN detail_message_source
    GENERATED ALWAYS AS (CASE WHEN json_valid(detail_json)
                              THEN coalesce(json_extract(detail_json, '$.message_source'), '') ELSE '' END) VIRTUAL;
ALTER TABLE events ADD COLUMN detail_egress
    GENERATED ALWAYS AS (CASE WHEN json_valid(detail_json) THEN json_extract(detail_json, '$.egress') END) VIRTUAL;
ALTER TABLE events ADD COLUMN detail_upstream_status
    GENERATED ALWAYS AS (CASE WHEN json_valid(detail_json) THEN json_extract(detail_json, '$.upstream_status') END)
    VIRTUAL;
ALTER TABLE events ADD COLUMN detail_aggregated
    GENERATED ALWAYS AS (CASE WHEN json_valid(detail_json) THEN json_extract(detail_json, '$.aggregated') END) VIRTUAL;
ALTER TABLE events ADD COLUMN detail_ip
    GENERATED ALWAYS AS (CASE WHEN json_valid(detail_json) THEN json_extract(detail_json, '$.ip') END) VIRTUAL;

CREATE INDEX events_refusal_sources ON events (reason_code, detail_message_source, at_ms, detail_count)
    WHERE type IN ('refusal', 'failure');
CREATE INDEX events_refusal_clients ON events (reason_code, ip_hash, at_ms, detail_count)
    WHERE type IN ('refusal', 'failure');
CREATE INDEX events_failure_groups
    ON events (detail_egress, reason_code, detail_upstream_status, at_ms, detail_count, detail_aggregated)
    WHERE type = 'failure';
CREATE INDEX events_refusal_places ON events (place, at_ms, reason_code, detail_count)
    WHERE type = 'refusal' AND place IS NOT NULL;
CREATE INDEX events_live_places ON events (place, id) WHERE type = 'live' AND place IS NOT NULL;
CREATE INDEX events_live_ips ON events (detail_ip, id) WHERE type = 'live';

CREATE INDEX client_minute_pair_place ON client_minute (substr(client_key, instr(client_key, '|') + 1), bucket_start)
    WHERE client_type = 'pair';
CREATE INDEX client_hour_pair_place ON client_hour (substr(client_key, instr(client_key, '|') + 1), bucket_start)
    WHERE client_type = 'pair';
CREATE INDEX client_day_pair_place ON client_day (substr(client_key, instr(client_key, '|') + 1), bucket_start)
    WHERE client_type = 'pair';
CREATE INDEX client_minute_ip_rows
    ON client_minute (client_key, bucket_start, requests, refused, served, bytes, top_endpoint)
    WHERE client_type = 'ip';
