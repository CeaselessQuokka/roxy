-- kind: expand
-- The v1 User-Agent drill-down (plan 14.1 row 29, parity row 79, `.remake/v1notes/dashboard.md` 4.21; v1
-- `GET /admin/fingerprints/user_agent`): where the newest request of each User-Agent went, who sent it and which
-- header names it carried. Written by roxy/metrics/fingerprints.py through the recorder from the request it already
-- fingerprints (no extra read or write per request: the newest detail per User-Agent rides in the same flush), read
-- by roxy/metrics/read_security.py `user_agent_detail`.
--
-- `last_path`: the target (host and path, no query) of that request, scrubbed with `redact_text`, at most 300
-- characters (v1 kept 300). Caller text: pages show it as plain text, never as markup.
-- `last_caller`: the client address of that request, stored and shown as the Endpoints page's "Last caller" is (the
-- address as Live shows it, at most 64 characters); exports hash it (`Column(ip=True)`).
-- `last_header_names`: a JSON array of the header names that request carried, in the order sent, lowercased, a
-- secret-shaped name as `fp:<keyed hash>` (`fingerprints.name_for_storage`), at most 64 names. Names only: v1 also
-- kept the values, v2 never stores a value here (values live in `fingerprint_values`, scrubbed and capped).
-- `last_detail_at`: when that request arrived (Unix seconds). It can be older than `last_seen` while a previous
-- release, which never writes these columns, runs beside this one during a deploy.
--
-- Bounded like the table itself (`max_user_agent_records`, `retention_fingerprints_days`): one row per User-Agent,
-- each new column bounded above. NULL on rows written before this migration (and on v1 imports): the drill-down then
-- says no request detail was recorded. The previous release never names these columns, so it keeps working on this
-- schema during a deploy.

ALTER TABLE fingerprint_user_agents ADD COLUMN last_path TEXT;
ALTER TABLE fingerprint_user_agents ADD COLUMN last_caller TEXT;
ALTER TABLE fingerprint_user_agents ADD COLUMN last_header_names TEXT;
ALTER TABLE fingerprint_user_agents ADD COLUMN last_detail_at INTEGER;
