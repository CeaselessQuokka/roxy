# Roxy v2 changes

This file records what v2 changes on purpose, and every place where the build had to choose between two rules of
REMAKE_PLAN.md or depart from it (plan 18.1). Each entry says what changed, why, and where the code is. The
per-phase progress notes and the full parity list are added as the phases land.

## Plan conflicts and deviations

### Decided by the lead (DESIGN.md section 0 and .remake/LEAD_NOTES.md)

- **Memory sizing for the 1 GB server.** The production box has 909 MB of RAM and no swap; plan 6.1 and 17.1
  assume 2 GB. SQLite page caches are scaled down per DESIGN.md section 0 (control 2048/1024 KiB, hot 4096/1024,
  metrics 8192/2048, cache 4096/2048 for the writer and reader connections), `mmap_size` is 0 except 32 MiB on
  cache.db, `cache_memory_bytes` defaults to 16 MiB and `cache_memory_entries` to 1000, systemd uses
  `MemoryHigh=320M` and `MemoryMax=420M` per color, and `ROXY_WORKERS=2`. The deploy switches to low-memory mode
  (the idle color starts with one worker) when less than 700 MB is available.
- **Owner decisions.** D1: the credential is never sent for callers (the allowlist starts empty; only Roxy's own
  probes use it). D4: callers see Roblox's real status (`compat_collapse_upstream_errors=0`). D5: TOTP is
  mandatory; the first login bootstraps with the imported password and an emailed code, then forces TOTP enrollment.
- **Auto-migrate only in development.** `ROXY_AUTO_MIGRATE=1` is honored only with `ROXY_ENV=development`;
  production workers never migrate (plan 5.5).
- **Refusal body wire form.** Refusal bodies keep v1's form (a JSON string and a trailing newline, sent as
  `application/json`). Upstream failure messages (plan 7.13 bodies) were raw text labeled `application/json` in
  v1; v2 sends the same text with `text/plain; charset=utf-8`.
- **Duplicate header rules (plan 4.8 row 112).** v1 silently overwrote a header rule with the same canonical id;
  the plan says refuse it, and the plan wins: v2 answers 409 `RuleConflict`.
- **Regex header rule ids.** v1 lowercased regex needles in the canonical id, so `^\d+$` and `^\D+$` (opposite
  rules) collided. New regex rules keep the case of each escape in their id (literal letters are still lowercased,
  because matching is case-insensitive); imported v1 rows keep the id they arrived with, also when edited, unless
  the filter itself changes (`rules/match.py header_rule_canonical_key`, `rules/service.py`).
- **Ignored paths use the shared matcher (row 111).** v1 compared ignored paths as exact strings; v2 matches them
  as globs, so an entry also covers every path below it (`favicon.ico` covers `favicon.ico/x`). The bypass list
  became CIDR based (`access_list`).
- **Per-IP limit off by one.** v1 allowed `limit + 1` requests per window; v2 allows exactly `limit` (plan 10.2).
- **Dashboard section count.** v1 has 35 dashboard sections, not the count in the plan 14.1 map; see
  `.remake/v1notes/dashboard.md` section 2.
- **Hotfix shadow mode.** The Tier 0 hotfix replays in the opposite direction (anonymous primary, credential
  replay), because the hotfix removes credential traffic; the comparison is equivalent.
- **Cache key encoding (plan row 53 against sections 3 and 9).** v1 built cache key text from decoded names and
  values, so `?universeIds=1%26universeIds%3D2` and `?universeIds=1&universeIds=2` shared a key while sending
  different upstream URLs (a cache poisoning path). v2 percent-encodes names and values in the key text; ids for
  plain values are unchanged and ambiguous ones become distinct.
- **POST cache allowlist.** Plan 15.5 lists `games.roblox.com/v1/games/multiget-place-details` as a POST lookup;
  it is a GET that needs a signed-in account, so it is left out (`config/defaults.py`).
- **Settings history sources.** Besides the plan's sources, settings history records `cli` and `system` changes
  (`config/settings_service.py FIXED_SOURCES`).

### Fix pass after the P0 to P2 reviews

- **The credential allowlist and the ignored paths are tables, not settings.** Plan 15.3 B and E list the
  settings `credential_endpoint_allowlist` and `ignored_paths`, while plan 6.2, 6.9 and 9.13 keep the same data in
  the `credential_allowlist` and `ignored_paths` tables. The tables are what the rules store reads, and only the
  table can hold the required `cache_private` choice for each credential endpoint, so the two settings were
  removed: a setting next to its table was a second, disconnected list. An ignored path naming a roblox.com host is
  refused (it would be a silent 404 for every caller; an endpoint block does that with a message).
- **One rule per pattern for single-winner tables.** Endpoint rules, cache rules, routing rules and the credential
  allowlist apply one winning rule per path (most specific, ties to the lowest id). A second rule with the same
  pattern text, whatever its scope or type, could never win where both match, so it is refused, as v1 refused it
  (v1 kept these rules in a dict keyed by the pattern). Endpoint blocks still allow a glob and a regex with the same
  text, because every matching block refuses.
- **One active ban per subject.** Creating a ban for a subject with an active ban extends that ban (the later end
  wins; a permanent ban is never shortened) inside the same transaction, so two detectors banning one IP at once
  leave one ban. `RulesService.unban(subject_type, subject)` lifts every ban of a subject.
- **Exact `re` answers on the `regex` engine (plan 4.8 row 111 with DESIGN.md section 5).** v1 matched with `re`;
  v2 must use the `regex` module for its timeout. The two engines read `\w`, `\d`, `\s`, `\b`, `\B` and
  case-insensitive letters (dotless i, dotted capital I) differently for many non-ASCII characters, so every
  pattern is now rewritten from `re`'s own parse tree into explicit character sets (`rules/re_compat.py`). One
  approximation remains: a case-insensitive backreference uses the `regex` module's case folding.
- **Stricter regex validation (plan 9.9).** New patterns are also refused for a variable repeat inside a group
  that repeats a variable number of times (`(a{1,10}){1,10}`), alternatives inside a repeat that can start with the
  same character (`(a|aa)+`), more than 3 open-ended repeats counted by how often their group repeats
  (`(.*,){5}`), and more than 2 glob wildcards in one path segment. Stored v1 patterns are not judged again.
- **Regex timeouts fail closed for refusing rules.** A pattern match cut off by the 50 ms timeout counts as "no
  match" for rules that grant something (cache, routing, the credential allowlist) and as a match for endpoint
  blocks and endpoint rate rules; User-Agent and header rule callers pass `on_timeout=True`. `regex_budget()`
  caps the regex time of one request.
- **Audit summaries of secrets show no characters.** Only the Roblox credential keeps v1's tail label (an ellipsis
  plus the last 6 characters). Other secrets are stored as a keyed fingerprint and `[redacted]`; URLs keep only
  the scheme and host (a webhook URL carries its token in the path).
- **uvicorn's access log is off.** It printed raw paths, queries and client addresses, bypassing redaction and
  `log_hash_client_ips`; Roxy's own `http_request` log line covers every request.
- **A startup that fails only on a busy database does not stop gunicorn.** uvicorn-worker exits with gunicorn's
  "failed to boot" status for any startup failure, and gunicorn then stops the whole master. Startup steps now
  retry a busy or unreachable database for up to 20 s, the cache.db check is skipped when hot.db stays busy, and a
  worker that still cannot start exits with status 1 (`roxy/worker.py`), so gunicorn starts a new one. A schema
  that is too old still stops the master, as plan 17.4 requires.
- **cache.db is checked before anything reads it.** A damaged cache.db is rebuilt at startup (plan 5.5) instead of
  being reported as a schema problem; the schema check of cache.db runs after its quick check.
- **Fenced leader writes outside hot.db need lease time in hand.** A fenced write to control.db, metrics.db or
  cache.db checks the hot.db lease right before COMMIT and now also requires 5 s of lease left
  (`scheduler/leader.py FENCE_MARGIN_S`). Such a write can only land after a takeover if the process stalls for
  longer than the margin inside that one transaction, and even then it lands before the new leader's first write
  to that file (which waits for the same file lock), so a deposed leader never overwrites newer data.
- **Workers follow `config_version` down as well as up.** A restored control.db can lower the counter; workers now
  reload whenever the version differs. Restore and undo code calls `raise_config_version` to move the counter
  above every value a worker may have seen.
- **Busy circuit on each database writer.** After a write gives up on a lock held by another process, writes to
  that database fail at once for 2 s and the next one probes again, so no caller waits much longer than one
  `busy_timeout`; `write(..., busy_timeout_ms=...)` gives a hot path a shorter wait.
- **Redaction.** One-time code fields under their bare names (`TwoFA`, `mfa`, `passcode`, `recovery`, and `code`
  when its value is shaped like a one-time code, so Roblox's `"code": 0` error codes stay readable) and
  `X-Api-Key` style headers are secret; percent-encoded markers are decoded before judging; the credential's
  24 character windows ignore ASCII case and no longer include the public `TOKEN_PREFIX`; the kill-switch token
  in `/admin/invalidate/<token>` is masked in every log line and error event.
- **Duration text is bounded.** Duration settings accept at most 64 characters of text, matched by an expression
  that cannot backtrack.
- **Spam ban lengths.** While a detector's action is `ban`, its first ban and its ban cap must be at least 1
  minute (plan 15.3 E2); `insight_up_latency_p95_ms <= insight_up_latency_p99_ms` and the CACHE-TTL-TUNE
  "shorter" threshold at or below the "longer" one are enforced, as their help text says.
- **Place clients have their own cap.** Client compaction keeps `max_caller_records` place rows per bucket and
  `max_ip_activity_records` IP rows (plan 6.10, 15.3 I).

## Writing style (plan C5)

- The v1 test suites kept under `tests/` (`smoke_test.py`, `deploy_test.sh`, `boot_check.sh`) are scanned by
  `scripts/check_style.py` like every other file; the dashes they had were all in comments and were rewritten.
