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

### Wave 2 (P3 to P8)

Collected from the seven builder reports, the wiring report, the spec review (finding F5) and fix pass 1 of
2026-10-08. Module paths are under `src/roxy/`; DESIGN.md 11.9 holds the exact contracts.

#### Owner and lead decisions

- **D10 reversed by the owner (2026-10-07).** `throttle_count_cache_hits` defaults to 1: fresh cache hits count
  toward the per-IP limit, because an answer from the cache still costs Roxy CPU, memory and bandwidth, and one
  shared allowance per caller keeps Roxy fair. Plan 0.3 D10 and 15.3 E said 0; a decision the owner changed is
  binding (0.2 item 6), and both plan rows now carry the owner's value. The flood limit still counts every
  request. The setting's help text, `docs/SETTINGS.md`, the public site and the tests say cache hits count
  (`config/settings/throttling.py`, `abuse/checks/throttle.py`). With this default the router reads the cache only
  after an Allow (`proxy/router.py peek_before_verdict`), so a refused caller costs no cache read and its outcome
  record carries no `cache_key_id`; the early peek comes back when the setting is 0 or `cache_serve_throttled` is 1.
- **`/internal` on the public port is an instant 404.** Every method on `/internal` and `/internal/<anything>`
  answers 404 with v1's `"Not Found"` plus a newline (`application/json`); it is never a probe, never held by the
  tarpit and not counted as proxied. Before, it was a `not_roblox` refusal ("Not a Roblox URL") after an 8 to 20 s
  tarpit hold. Plan 5.8 and the nginx `location /internal/` 404 are the basis (`internal_app.PublicInternalNotFound`,
  the public app's first route; the proxy endpoint repeats the check as defense in depth). The deploy smoke check
  `internal_hidden` now fails after 5 s or on any `Roxy-Refusal` header (`scripts/smoke_remote.py`).
- **Compat collapse restores v1's bytes (spec F8 and review round finding spec-6; D4 against the plan 7.13 note).**
  With `compat_collapse_upstream_errors=1`, a Roblox 4xx, live or cached, keeps Roblox's own body and content type
  under status 500; with `?prettyprint=true` it is pretty printed only when it is answered from the cache
  (`Roxy-Cache` HIT, REVALIDATING, STALE or COALESCED), as v1's `_serve_from_cache` did, while a live 4xx stays raw as
  v1's live path left it; the browser `<pre>` view is kept. A Roblox 5xx and the 502 and 504 rows keep the 7.13
  failure text (the request deadline row included, see the review round below). The 7.13 compat note gave every
  collapsed answer the failure text, but v1 sent Roblox's body (`.remake/v1notes/pipeline.md` section 7 step 4), and
  D4 defines the setting as restoring v1's behavior (`proxy/respond.py`). The default (0, the real status) is
  unchanged.
- **The credential allowlist grants exactly what a row names (confinement finding F3; C1, D1).** A glob
  row compiles to `^<pattern>/?$` (no implicit subpaths, `*` stays inside one segment, one trailing slash still
  matches) and a regex row must match the whole target; subpaths need an explicit wildcard such as
  `.../currency/*`. Plan 4.8 row 111 lists the tables that keep v1's subpath rule, and the allowlist, which v1 did
  not have, is not among them; every other table keeps the shared semantics (`rules/match.py
  compile_pattern(exact=True)`, `rules/store.py credential_index`).
- **Disguised refusals are byte-identical to a genuine throttle (spec F7 and review round finding spec-1; plan
  10.5).** A ban, the deny list, a spam flag or a disguised header filter renders the client's real rung and, while
  the client is penalized, the remaining penalty in `Retry-After` and `Roxy-Throttle-Reset`; v1's header-filter
  disguise always sent `throttle_reset_duration` (`abuse/checks/base.py redisguise`). The headers also go out in the
  genuine refusal's order, because one builder makes both (`checks/base.py throttle_refusal_headers`).
- **Bypass callers are never held by the tarpit (plan 10.6).** The pipeline marks `req.bypass` before any check
  runs, so a bypass caller refused by a ban, the deny list or a filter gets its refusal at once; a ban still
  refuses it and the order of checks is unchanged (`abuse/pipeline.py`).
- **Internal safety bounds stay module constants (principle P3 against P9).** The spam detector caps, the tarpit
  retry slots, the capture encoder queue, the label memory and the health size memory are `MAX_*` style constants
  with their reasons, not catalog settings: they cap memory and are not tuning knobs.
- **`net.ipv4.tcp_migrate_req` is not set.** The kernel default stays. Without it, connections queued on a
  recycling worker are reset, which is rare with `ROXY_WORKERS=2` and jittered recycling. It is a production kernel
  setting, so it goes on the `DECISIONS_REVIEW.md` list for the owner (P14).
- **Bandit rules B610 and B704 are owned by ruff.** Like B608, they are skipped in `pyproject.toml` because ruff's
  S610 and S704 run on every commit: B610 only matches anyio's `stream.extra()` in `egress/metering.py`, and every
  `Markup(...)` call in `public/` wraps text that was escaped first, each with a reviewed `noqa` reason.
- **Vendored third-party files skip the style walk (C5).** See "Design system (P11a)" under Wave 3a.

#### Proxy surface, errors and public endpoints

- **OPTIONS is answered before the abuse check.** DESIGN 11.1 placed it after the verdict, but plan 4.1 row 1 says
  OPTIONS is never logged as a probe, and the URL checks would log an OPTIONS for an odd path as one. It answers
  204 with `Allow` (v1 parity) and is recorded with outcome `served_upstream` and reason `options_local`, the
  closest value of the closed enum (`proxy/router.py`).
- **`Roxy-Paused: True` is kept (row 8 against plan 7.13).** Plan 7.13 shows `1`; row 8 keeps v1's header values,
  and v1 sent `True`. Section 4 is the contract (LEAD_NOTES decision 3); `Retry-After` is added per 7.13
  (`abuse/checks/pause.py`).
- **Target validation (plan 9.10; v1 bugs B3, B4, B17).** `&` and `'` are allowed (ordinary path characters v1
  refused by mistake); `<`, `>`, `"`, the backtick and the backslash are refused as `unsafe_url`; an encoded `/`,
  `?`, `#` or `%` inside a path segment and `.` or `..` segments are refused; empty segments are dropped (`//v1`
  becomes `/v1`) and a trailing slash is kept; any port in the host is refused, even `:443`; the host is checked for
  ASCII before lowercasing, stricter than the 9.10 order (the Kelvin sign lowercases to `k`). The upstream query
  keeps the caller's order, where v1 grouped repeated names (`.remake/v1notes/pipeline.md` 5.1) (`proxy/validate.py`).
- **Answer shapes.** Prettyprint applies to every Roblox body (2xx and 4xx, live or cached; with compat collapse on,
  a live 4xx stays raw, as in v1), never to Roxy's own texts; failure texts go to browsers as `text/plain` without
  the `<pre>` wrapper; every proxy answer carries `Cache-Control: no-store`; the CORS header (when
  `public_cors_allow_any_origin` is on) goes only on GET and HEAD; the catch-all route never matches `/admin` paths
  (`proxy/respond.py`, `proxy/router.py`).
- **Rows outside plan 7.13.** A leak guard trip answers 503 with the busy text and `Retry-After: 60`
  (`leak_blocked`); a public marker that reaches the guard answers 400 with v1's smuggling text; an egress host
  refusal answers 404 "Not a Roblox URL" (`upstream/messages.py`). The `cooldown_no_stale` answer also carries
  `Roxy-Upstream-Status: 429` when that request reached Roblox.
- **New refusal texts for checks v1 did not have (`abuse/messages.py`).** An undisguised ban or deny list entry:
  `Access denied.`; the flood limit: `You are sending requests too fast; try again in {retry} seconds.`; the place
  limit: `This experience is over its request limit; try again in {retry} seconds.`
- **The unhandled 500 is v1's `jsonify` form (spec F5).** Both the middleware and respond's `internal_error` row
  send `"Internal Server Error"` plus a newline as `application/json` with `Retry-After: 5` (it was `text/plain`).
  Plan 7.13 asks for the text "as v1", v1 used `jsonify`, and LEAD_NOTES decision 2 keeps every `jsonify` answer in
  that form (`core/errors.py send_response`, `proxy/respond.py FailureRow.json_string`).
- **Unknown admin paths (row 15, spec F2).** Under `/admin` they answer v1's 404 `"Not Found"` plus a newline and
  are never recorded as probes; under `/admin/api/v1` they answer the DESIGN.md section 13 error object (code
  `not_found`). Every plain admin 404 (the D6 network allowlist, the fail-closed guards, the gallery outside
  development) has the same bytes as a missing path, so the allowlist stays undetectable; those 404s still reach the
  probe hook. Admin URLs with a trailing slash (`/admin/`, `/admin/enroll/`) now get that 404 instead of FastAPI's
  307 redirect, as Flask answered (`admin/router.py AdminNotFoundRoute`, `core/errors.py not_found_response`).
- **`/health` (row 14).** `DataBytes` is the total size of the SQLite files and may be up to 10 s old: it is
  measured on a thread, and on a stalled disk `/health` answers within 0.25 s with the last known value (0 before
  the first measurement). `DataLimitBytes` is `storage_total_budget_gb`. POST, PUT, PATCH and DELETE `/health`
  answer 404 "Not a Roblox URL" with `Roxy-Refusal: not_roblox`, without the proxy pipeline or the tarpit (v1 B18)
  (`public/health.py`).
- **Outcome records on exceptions.** DESIGN 7 expected the middleware to record a fallback outcome, but only the
  proxy flow knows the request's endpoint and cache facts, so `ProxyFlow` records the 7.13 `internal_error` (500) or
  `deadline` (504, or 500 in compat mode, the status the caller gets) row exactly once before re-raising.
- **`Roblox-Id` is scrubbed (C1, plan 9.15).** The place id passes `core.redact.redact_label` before any check,
  record or limiter key uses it.
- **Message source for failures (row 116, spec F9 and review round finding spec-4).** Refusals keep `custom` or
  `default`, and a refusal the upstream layer returns (a public marker at the guard, an egress host refusal) is
  `default`, because its text is always Roxy's built-in v1 text; a 7.13 failure text is `roxy`; an error answer
  carrying Roblox's body (a relayed or cached 4xx, a compat-collapsed 500) is `roblox` (`proxy/router.py
  message_source`).

#### Abuse protection

- **An empty `roblox_egress_cidrs` earns nothing (15.3 E against 10.3).** Plan 10.3 implies a game-server signature
  alone protects a client; 15.3 E says an empty list earns nothing, and the catalog wins by the precedence rule, so
  there is no ban immunity and no bot-score credit without the list.
- **`Roxy-Refusal` on disguised refusals (row 7).** Row 7 sends the header "unless the rule is disguised"; v2 sends
  the genuine throttle header set, `Roxy-Refusal: throttle` included, because a missing header would give the
  disguise away.
- **Commit rule (plan 6.3).** A request refused by a later check spends no rate budget (v1 spent the UA-rule and
  throttle-all budgets); the flood counter always counts.
- **Retry-After on more refusals (v1 B8, B16).** Throttle-all, endpoint rule, custom header filter, flood and place
  refusals carry `Retry-After`; retry values use a true ceiling of at least 1 (the scheduled pause's time to its
  window end too, review round finding spec-9), while `Roxy-Throttle-Reset` keeps v1's rounded-down value in fixed
  windows.
- **Escalation off (v1 B2).** With escalation off, strikes no longer climb: fixed mode keeps a plain W-second
  penalty and GCRA mode only paces.
- **Bypass scope.** Bypass also skips the new flood, spam, challenge and bot-score checks.
- **Disguise defaults.** The deny list follows `ban_disguise_as_throttle`, and spam refusals are disguised as
  throttles.
- **Endpoint rules.** Only the `ip` scope is clamped to the per-IP allowance.
- **Strike on retry.** It raises the next penalty but does not extend the current one, at most once per window.
  SPAM-REFUSED does not count refusals caused by pause.
- **v1 abuse bugs (`.remake/v1notes/abuse.md`).** Fixed: B1 (the UA-rule tarpit switch works), B3 (`decays_in`),
  B13 (the UA tester respects the master switch). Kept for parity: B6 (throttle-all without a reason uses the pause
  text), B7 (throttle-all shows the per-IP headers), B9 (refusal headers are computed before the tarpit hold), B19
  (forgive does not lift a running penalty), B31 (header rules see headers nginx adds).
- **Pause and throttle-all default text (spec F3).** The pause default is the live setting `pause_message_default`
  (plan 7.13, 15.3 K), and throttle-all without a reason sends the same text, as v1 did (C3) (`abuse/pause.py`,
  `abuse/throttle_all.py`, `abuse/messages.py downtime_default`).
- **`upstream_cooldown_retry` has a producer (spec F4; plan 10.6, 15.3 F).** A retry of the same key by the same
  client inside the `Retry-After` it was given (after `upstream_cooldown`, `upstream_busy` or `queue_overflow`) is
  held with jitter. One hot.db write per answer records the `Retry-After` (`ucr:` limiter rows, 8 slots per client,
  a collision forgets the older key and fails open); nothing is read or written while the category is off, which is
  the default, and bypass callers are never held (`abuse/tarpit.py plan_cooldown_retry`, `proxy/router.py
  cooldown_retry_plan`).
- **Throttled cache serve (row 60 against sections 3 and 9).** With `cache_serve_throttled` on, a throttled caller
  is served from a fresh entry only when no later static check (challenge, bot score, ignored path, probes, auth
  smuggling, header filters, blocks) would refuse the request; otherwise it gets the throttle refusal. v1 step 4a
  served it before the filters ran (`abuse/pipeline.py`).
- **A refused caller runs no admin regex (plan 6.3, 9.9).** Still one hot.db write per request; while the rules
  contain regex rules, one extra hot.db read predicts the cheap limiters first, so a caller refused by the flood or
  per-IP limit never reaches a pattern (v1 also refused throttled callers before any regex). A wrong prediction (a
  race between workers) costs one more write (`abuse/pipeline.py walk_limiters`).
- **Spam detector bounds (P9).** Caller-chosen values (places, enum templates, dist subjects) are capped at 8 per
  client, family and hour per worker, the rest folded into one `(other)` subject; `spam_windows` holds at most
  50,000 counter rows, evicted oldest first in three tiers (recommend-only rows, then rate and refusal rows, then
  probe and auth rows); at most 10,000 flags are active. Place detectors therefore undercount the 9th and later
  places behind one address; they only recommend. The quota is per worker (N workers allow N x 8 values) while the
  row cap is fleet-wide (`abuse/spam.py`).
- **C7 degraded mode starts from the shared rows and ends in them (C6, C7; review round findings mp-1 and mp-2).**
  While hot.db cannot be written, a client's memory row is seeded from a hot.db read, so entering degraded mode never
  refills an allowance, and leaving it does not either: every admit, strike and penalty decided in memory is merged
  into hot.db by the first successful transaction that touches the key, before it decides, and a background task
  merges the rest (256 rows per write, one last attempt at shutdown). Each worker's share is `limit // workers`,
  never rounded up; details under "Review round" below (`abuse/pipeline.py`, `abuse/limiter.py`).
- **Recorder calls.** Abuse calls `record_throttled` once per penalty and records the aggregated events
  `ua_rule_hit` and `throttle_tier`; the Protection page read models that count them come with P9 and P11.

#### Rules and the regex budget

- **Stricter validation of new regex and glob rules (plan 9.9).** A write-time cost model (`rules/regex_cost.py`)
  refuses any new pattern whose worst case on an 8192-character path or header (4096 before the review round, see
  below) exceeds 3,000,000 units (about 5 to 25 ms, under half the 50 ms timeout): two repeats that trade
  characters (`a.*a.*b`), an unanchored repeat that a search can restart inside of and that can still fail after it
  (`x+y`, `[a-z]+/[0-9]*`, `.*crawler.*`), and since the review round a chain of short repeats.
  The fix is to anchor with `^`, start with fixed text the repeat cannot match, or drop a leading `.*`. Globs may
  have two wildcards only in their last segment, allowlist globs one per segment, which replaces the "more than 2
  glob wildcards in one path segment" limit of the earlier fix-pass entry. Stored v1 patterns are still not judged
  again, and `RulesService.create` validates on a worker thread. The model is conservative: it can refuse a pattern
  the engine would run fast through its literal prefilter.
- **One regex budget per request.** The cache peek's policy lookup, the availability check, the abuse checks and
  every upstream call share one `regex_budget()`; a nested budget keeps the outer one, and the stale-while-revalidate
  refresh starts its own (`regex_budget(fresh=True)`), so a background task never inherits a spent budget
  (`rules/match.py`, `proxy/router.py`).

#### Upstream and egress

- **Credential status lives in control.db.** The builder's task placed it in hot.db, which has no table for it;
  `credential_meta.status` already exists and a rejection should survive restarts. The fleet-wide cooldown is in
  hot.db, and `cooling_down` is computed from that row (`egress/credential.py`).
- **No-store cookie jar on the credential client (C2 item 7).** In httpx, `cookies=None` gives a jar that stores
  and resends Set-Cookie, so the credential client uses a jar that refuses every cookie; no egress client's jar or
  transport can be replaced.
- **Credential use is narrower.** Ordinary credential traffic needs status `active` (`unknown` allows probes
  only), and the credential client refuses every method but GET and HEAD.
- **Egress responses drop framing headers.** Set-Cookie, Content-Encoding, Content-Length, Transfer-Encoding,
  Connection and Keep-Alive never come back from the egress; the body is already decoded.
- **Rotator URL source fails closed.** A UI-set URL that cannot be decrypted leaves the rotator unconfigured
  instead of falling back to the bootstrap file. An empty optional credential file (`rotator_url`,
  `alert_webhook_url`) means "not configured", because systemd's LoadCredential refuses a missing file
  (`egress/rotator.py`, `notify/webhook.py`).
- **Pasted cookie pair (C2 item 5; confinement F1).** A bootstrap file or a replacement of the form
  `.ROBLOSECURITY=<value>` is stored as the bare value; a value that names the cookie anywhere else is refused
  ("paste only the text after the equals sign"). The leak matcher ignores any run of 12 or more characters of
  public text wherever it sits in the stored value (`egress/credential.py secret_spans`).
- **Rotator parking is counted once (row 31).** The egress `RotatorPool` counts the failure streak and parks the
  rotator; upstream keeps only the three-distinct-exits rule for rotator cooldowns and breakers.
- **Upstream follows redirects itself.** The egress gets `follow_redirects=False`, so every hop takes a bucket
  slot. A malformed `Location` (`//[`, an out-of-range port) is not followed: Roblox's own 3xx is relayed instead of
  a 500 (`upstream/service.py`).
- **Egress-wide cooldown on two hosts.** 429s on 2 different hosts within 60 s cool down the whole egress; 2 is a
  constant, since "across hosts" means more than one.
- **Adaptive rate.** Increases never raise a rate set by an admin or an applied recommendation and only undo host
  cuts the controller made; decreases on a 429 always apply.
- **Refunds and queue order.** A canceled reservation restores the bucket exactly when nobody reserved after it,
  otherwise it gives back one interval. The queue evicts background requests first, then interactive ones with a
  stale copy, then internal, then admin; an interactive request without a stale copy is never evicted.
- **Breakers** count successes only while a failure window is open, so a healthy endpoint costs no extra write.
- **"All upstream methods unavailable" alert.** It keeps v1's subject and is sent only when every egress is
  disabled, not for one endpoint's cooldown.
- **No schema change in P4.** Distinct-exit records for rotator 429s are short-lived hot.db `lease` rows (hashed
  `r429:` names); breaker and cooldown times are stored as fractional seconds and bucket TATs as fractional
  milliseconds.
- **A 429 during a hot.db outage (plan 7.5 with C7).** The caller gets the 429 cooldown answer with Roblox's
  `Retry-After` instead of 503 `degraded`. The cooldown (also for `x-ratelimit-remaining: 0`) is kept per worker
  (at most 1000 entries), honored by every routing decision there and written to hot.db for every worker as soon as
  a write works; it never shortens an existing row. Breaker counts, host escalation and the adaptive decrease of
  that one call are lost. The credential manager likewise keeps a cooldown it could not write
  (`upstream/cooldowns.py LocalCooldowns`, `egress/credential.py`). Other hot.db failures still answer 503
  `degraded` rather than sending unpaced calls.
- **Retry-After for a credential refused at send time** comes from the credential manager: the cooldown's
  remaining time, 10 s while shared state is unreadable, 300 s when rejected or not confirmed (it was always 300).
- **CSRF retries are recorded** with v1's reason "CSRF token refresh" (row 117).
- **Development-only upstream overrides.** `ROXY_TEST_UPSTREAM_BASE` and `ROXY_TEST_ROTATOR_PROXY` send Roblox
  traffic to loopback mocks and are refused at startup in production (`egress/targets.py`, `egress/clients.py`).
- **Startup metering self-test.** Each worker measures bytes on a short loopback test at startup and uses the
  calibrated estimate when the test fails (for example under a sandbox that blocks loopback TCP)
  (`egress/metering.py`).
- **Credential reader scan.** The 19.5 test that only one module reads the secret allows the offline v1 migrator
  (`migration/secrets_out.py`), which writes the bootstrap file; the test also checks that the service never
  imports it.
- **Admin lookup label.** The internal endpoint label keeps its C5 replacement text verbatim, although v2 lookups
  have no direct fallback.

#### Cache and single-flight

- **Key additions (plan 9.13).** A credential key ends in ` @cred`; the forwarded caller headers (Accept,
  Content-Type, Content-Length) are part of the key as ` ^name=value`, so GET callers that send
  `Accept: application/json` or `*/*` get a separate entry from callers that send none, at some cost in hit ratio.
  `proxy/scrub.py FORWARDED_REQUEST_HEADERS` and the key's vary list are one list, checked at start
  (`cache/keys.py`).
- **Full SHA-256 body hash (row 53).** POST keys carry the whole SHA-256 of the body instead of v1's 12 hex
  characters: 48 bits can be matched in hours of GPU time to poison another caller's batch lookup. Only POST ids
  change.
- **The owner's outcome lives in its hot.db lease row (plan 6.9).** Followers already poll that row, which saves a
  read per poll; the outcome stays readable for 1 s after the answer.
- **Generation (plan 6.5).** The `generation` value moves only on Purge All (older rows become misses at once);
  every purge moves its `updated_at` stamp, and each worker drops its memory tier within 250 ms. Moving the value
  on every scoped purge would invalidate the whole disk tier.
- **Stale windows.** A rule's `stale_ttl` is its stale-while-revalidate window; stale-if-error stays
  `cache_stale_seconds`.
- **Upstream hints.** `cacheable` applies to 2xx only; a 4xx is stored only when the upstream set
  `negative_ttl_s`.
- **`coalesce_timeout` only across workers.** A follower in the owner's own worker waits for the owner, whose
  fetch has its own deadline; followers in other workers answer `coalesce_timeout` after `cache_coalesce_wait_ms`
  (or the owner deadline).
- **Answer before store (plan 6.9 step 3 against C7).** The owner and its same-worker followers are answered as
  soon as Roblox answers; the cache.db store and the outcome publish follow in a bounded background tail (1024 tails
  per worker; at most 32 cache.db writes waiting, skips and failures counted). The publish is retried with backoff
  until it lands or the lease would expire, a worker takes over its own finished but unpublished lease at once, and
  the outcome lingers 1 s from the answer. Answers never wait for cache.db or hot.db after Roblox answered; code
  that reads cache.db right after a request awaits `ctx.cache.settle()`. Trade-off: an owner killed right after
  answering, before its cache.db store, leaves followers on the crash path (lease expiry, then one takeover); one
  killed after the store but before the publish leaves them the stored answer, which they now look for in cache.db
  (review round finding mp-12, below) (`upstream/singleflight.py`, `cache/service.py`).
- **The lease rides in the bucket reservation (plan 6.3, 7.3).** A miss makes 2 hot.db writes: the reservation
  with the lease, then the small outcome publish, which is one write beyond the two per request plan 6.3 lists.
- **Handoff rows (C6 and plan 19.2, 19.3 over the setting's help text).** An answer too big to share inline that
  is not stored reaches followers in other workers through a cache.db handoff row (key suffix ` !flight`, 10 s life,
  up to 8 MiB, never answers a lookup, left out of the key spread), so they answer `COALESCED` instead of each making
  a call. Handoff rows are written even while `cache_disk_enabled` is 0, as the setting's help now says, and the
  maintenance pass deletes dead rows with the disk tier off.
- **Private credential answers (plan 6.9, C2).** A credential answer for a key that is not a credential key is
  private to its request: never stored, never handed to a follower. Same-worker followers that used to get it as
  `COALESCED` now make their own call (`MISS`).
- **v1 cache bugs fixed (`.remake/v1notes/cache.md`):** B3 to B9, B11, B12, B15, B18, B23, B24, B26 and B29.

#### Metrics and alerts

- **Honest demand (principle P6).** Demand excludes refusals, local OPTIONS answers and internal calls; "avoided" is
  demand minus caller upstream calls, background refreshes and retries included, so an attack cannot inflate the
  headline.
- **No new tables in P7.** Low-volume counters (visits, retries, UA rule hits, blocked fingerprints, capture
  errors) are `events` rows summed per minute with a `count`. Individual events are capped at 30 per type and
  reason per worker, refilling at 0.5 per second, and beyond that summed per minute, so totals stay exact.
- **Live tail.** Rows are `events` of type `live`, kept 15 minutes and written at most 50 per second per worker;
  requests beyond that rate stay in the worker's ring.
- **Templates and probes.** Each worker keeps its own 2,000-template bound, refreshed hourly from the last 24 h of
  rollups, instead of a leader-computed table. Besides the v1 bug B19 fix for URL reasons, `HTTP 404 via GET
  <path>` is reduced to a stable signature with the path as the target. Header auto-ignore is decided centrally
  from the shared tables (v1 B22). An empty User-Agent counts as unknown, and the docs and status pages are counted
  apart from the v1 visitor tiles.
- **Labels are scrubbed (plan 9.15, C1 over row 74).** Endpoint templates, hosts, place ids and event label columns
  pass `core.redact.redact_label` like log lines: a secret-shaped piece is stored as `[redacted]`, ordinary values
  are unchanged and `TEMPLATE_VERSION` stays 1 (`metrics/templating.py`, `metrics/recorder.py scrub_labels`).
- **Captures are encoded off the loop (plan 6.3, P9, row 127).** A bounded queue (256 captures or 16 MiB) feeds one
  thread; a full queue drops the capture and counts it as `capture_dropped`, never delaying the request.
  `record_capture` returns the id once queued; if encoding fails later, `GET /live/{id}` answers v1's expired
  message (`metrics/capture.py CaptureEncoder`).
- **Alerts while hot.db is down (17.7, C6, C7).** Each worker caps at its share,
  `alert_rate_limit_per_hour // ROXY_WORKERS` (at least 1), so the fleet stays within the setting; dedupe is per
  worker, so each worker may send its own copy at most once per cooldown key per gap; leak guard alerts stay
  uncapped (`notify/gate.py MemoryGate.decide`, `worker_share`). What the workers sent from memory is merged into the
  shared gate once hot.db can be written, so the hour that contains the outage still stays within the cap (review
  round finding mp-10, below). Unlike the per-IP limiter's degraded share, an alert share never drops to 0: a cap
  smaller than the number of workers can be exceeded during an outage, because the owner most needs alerts then.
- **Row size (plan 6.6).** A `rollup_minute` row measured 71.4 bytes (table 51.0, index 20.4) against the plan's
  250-byte estimate; one day of minute rows at 400 combinations per minute is 41 MB. The plan asks to revisit the
  table and `storage_total_budget_gb` when the measure is more than 20% off: open for the lead and the owner.

#### Admin auth (P8)

- **No schema migration.** Login transactions (`auth_tx:`), the last used TOTP step (`auth_totp:`), pending
  enrollment secrets (`auth_enroll:`) and WebAuthn challenges (`auth_webauthn:`) are hot.db `lease` rows;
  `login_failures` holds one row per failure plus a `global` row; the alert hourly caps are `email_gate` rows
  `cap:<channel>` and `capdrop:<channel>`. A dedicated `auth_tx` table and an `admin_users.totp_last_step` column
  are a later option.
- **Sessions.** `mfa_at` is the session's `created_at`; re-auth rotates the session and keeps its absolute expiry;
  the CSRF secret is HMAC(session id), with its SHA-256 stored in `csrf_secret_hash`.
- **Guard answers.** A missing session gets 401 `{"detail":"Session expired"}` on an API path and a 302 to `/admin`
  on a page; missing fresh MFA gets 403 with `Roxy-Reauth: required`; a bootstrap session used outside enrollment
  gets 403 with `Roxy-Enroll: required` or a 302 to `/admin/enroll`. DESIGN.md section 13 names the JSON code
  `reauth_required`; the dashboard client accepts both until the lead picks one.
- **Kill-switch link from outside the allowlist (plan 9.5).** A valid invalidation link works from a network
  outside the admin allowlist (an invalid one gets the same plain 404); otherwise the owner could not stop an
  attacker while on mobile data.
- **Bounded audit of wrong passwords.** Only the first failure per username and network in a window, and the one
  that locks the key, get an `audit_log` row (which has no row cap and keeps 400 days); every attempt still goes to
  the event log.
- **Login alert by email only (17.7 table over 9.5).** The webhook would carry the kill-switch token.
- **Smaller choices.** Lockout 429s add `Retry-After` (the body text is v1's); recovery codes look like
  `XXXX-XXXX-XXXX-XXXX` and their first group is a public lookup id, so an attempt costs one argon2 check instead of
  ten; emailed codes are stored as a salted SHA-256 inside the login transaction; each login transaction allows 3
  second-factor attempts; v1's `sendBeacon` heartbeat is dropped because it cannot send the CSRF header; the common
  password list is a generated 27,912-entry file loaded only when a password is set. The argon2 parameters and the
  hashing queue (2 running, 4 queued) are module constants with reasons.

#### Storage, shutdown and gunicorn

- **Busy budgets are deadlines from enqueue time (C7).** `Database.write(..., busy_timeout_ms=N)` counts N from the
  call, queue wait included; a job still queued at the deadline is canceled and raises `SharedStateUnavailable`,
  and a job that started is waited for, so "unavailable" always means "did not happen" (`storage/db.py`). Abuse
  decisions under a locked hot.db stay prompt: the slowest of 16 went from 8.56 s to 0.51 s.
- **Shutdown (plan 5.2, 17.1).** uvicorn waits at most 20 s for open requests (gunicorn's 30 s graceful timeout
  minus the 8 s lifespan budget and a 2 s margin); tarpit holds and drips end at once with their refusal when
  draining starts; readiness drops at drain start; the lifespan shutdown shares one 8 s budget, so a stuck loop
  cannot push the final flush past the kill; upstream calls still running after 20 s are canceled, as gunicorn's
  kill did before (`worker.py`, `lifespan.py begin_drain`).
- **One TCP listener per worker (the plan 5.2 `bind` row against 5.8 and C6).** With one shared listening socket,
  epoll gave nearly every connection to the worker that went idle last (69/10/1/0 requests over 4 workers).
  `deploy/gunicorn.conf.py` sets `reuse_port = True` (measured 24/20/19/17); `bind` holds only the TCP address, and
  the internal Unix socket is created once by the master hook (SO_REUSEPORT fails on AF_UNIX), mode 0660, handed to
  each worker and unlinked on exit. Trade-offs: connections queued on a stopping worker are reset (see
  `tcp_migrate_req` above), and a single-worker color briefly refuses connections while its worker recycles. A
  second master on a port another listener holds no longer shares it silently: it exits 1 before READY (review
  round finding mp-3, below).

#### Review round (2026-10-08)

Six adversarial lenses (credential confinement, ingress, multi-process and failure modes, spec and parity, admin
auth and alerts, public site) reviewed the tree after fix pass 1; one fixer per area and the integrator closed every
finding. Ids are the review ids; DESIGN.md 11.9 "Review round" holds the contracts.

Credential and egress:
- **Credential values are stored canonical (cred-1; C2 items 4 and 5, plan 9.8).** A bootstrap file or a pasted
  replacement that is percent-encoded (an `encodeURIComponent` copy) is stored, fingerprinted, sent and watched
  decoded; Roblox unescapes cookie values, so it is the same cookie, in the form Roblox itself issues. A value still
  encoded after 4 rounds, or with fewer than 24 characters of its own besides the public warning, is refused. Rotated
  cookies are decoded the same way before the leak matcher watches them, and the matcher never watches a secret
  fragment shorter than 24 characters on its own (C2 item 4's unit of a leak is a 24 character run). Before, a
  caller could send `?note=_|WARNING:` and switch off direct and then the rotator for everyone
  (`egress/credential.py canonical_bytes`).
- **The credential path refuses a smuggled credential piece (cred-5; C2 item 7 against sections 3 and 9.15).** A
  request to an allowlisted endpoint whose URL, headers or body hold a 24 character run of the credential, or a
  public marker, is refused with 400 auth smuggling before the cookie is attached: nothing is sent or cached and no
  egress is tripped. C2 item 7 gives the credential client no guard; it still has none, `authorize` runs the guard's
  inspection as a refusal only (`egress/credential.py authorize`).
- **Credential replace registers the new value before its audit row (cred-2; plan 19.5 item 11, 9.8),** so a value
  pasted into the reason box is redacted in `audit_log`.
- **Redirect hops are re-validated like caller paths (cred-3; plan 9.10, 7.9).** Every hop passes
  `proxy/validate.py parse_redirect` (which now never raises and takes the live `max_url_length`); the credential
  allowlist is matched on the hop's decoded target; the URL followed is rebuilt from the validated parse, so its
  query is re-encoded and a `prettyprint` parameter in a Location is dropped. A hop that fails is not followed and
  Roblox's 3xx is relayed (`upstream/service.py _redirect_url`).
- **TLS key logging is always off (cred-6; C2 item 2 over the plan 13.2 H-ENV-PROXY row).** CPython copies
  `SSLKEYLOGFILE` into every default TLS context whatever `trust_env` says, so the three egress clients
  (`egress/metering.py tls_context`), the SMTP channel (`notify/mail.py smtp_tls_context`) and the webhook client
  build their contexts with the key log off, and H-ENV-PROXY fails while the variable is set. Plan 13.2's row names
  only the proxy variables (open for the lead).
- **Answers never wait out a locked hot.db after Roblox answered (mp-7, mp-8; C7, D4).** The writes after the call
  (effects, CSRF token, refunds, releases, the credential cooldown, sharing kept cooldowns on a request path) wait at
  most 0.5 s. When the effects cannot be written no retry or fallback is made and the caller gets Roblox's own 5xx,
  timeout or connect answer; a retry whose reservation fails also answers Roblox's last answer, never `degraded`.
  Measured: a 429 reached the caller 0.51 s after Roblox answered (was 5.03 s). Trade-off: a retry a short lock
  wait would have allowed is skipped, and that call's breaker counts are lost (`upstream/service.py`).
- **A reservation canceled mid-write is refunded (mp-9; plan 7.3).** The canceled request waits for its own write
  (at most the 2 s reservation budget, only while hot.db is locked) and gives back its slots, the half-open probe
  lease and the AIMD slot; the single-flight lease is abandoned too. A deadline 504 can therefore come up to 2 s late
  while another process holds hot.db (`upstream/service.py _reserve_shielded`).

Rules:
- **New rules are judged on 8 KiB inputs, short-repeat chains included (INGRESS-2; plan 9.9, sections 3 and 9 over
  convenience).** The cost model sizes inputs at the catalog maximum of `max_url_length` and `max_header_bytes`
  (8192), costs every element whose length varies (a chain of short repeats multiplies), and judges a glob by the
  regex it compiles to (`*a*b` is refused, `*-*` stays accepted). Four realistic patterns fix pass 1 accepted take 10
  to 20 ms on 8 KiB and are now refused with a fix-it message: `users/\d+/.*friends`, `catalog.*search`, `^\w+\W`
  and `^Mozilla/5\.0 \(.*\) AppleWebKit/.*Chrome/\d+`. Stored v1 patterns are still not judged again
  (`rules/regex_cost.py`, `rules/match.py`).

Cache and single-flight:
- **A peeked fresh entry is served even if it expired during the abuse verdict (INGRESS-3; plan 10.2 and row 60
  with C6, C7, over a literal freshness re-check).** When the verdict depended on the peek (`cache_serve_throttled`
  on, or cache hits not counted), the request is answered `HIT` from that entry; its `Roxy-Cache-Age` can reach the
  TTL plus the verdict's time (one hot.db write, 500 ms budget). Before, an over-limit caller could reach Roblox
  through an entry that expired in between (`cache/service.py serve`).
- **Followers in other workers read cache.db when the owner's outcome is late (mp-12; plan 6.9 step 4).** After 1 s
  on a live lease, every 0.5 s and once before a timeout, so an owner that stored its answer but could not publish
  it (hot.db busy, then its worker stopped or was killed) answers its followers `COALESCED` instead of 503
  `coalesce_timeout`. Cost: at most two cache.db reads per second per waiting key and worker, only for flights longer
  than 1 s. A canceled publish no longer logs "Task exception was never retrieved" at shutdown
  (`upstream/singleflight.py`, `cache/service.py _stored_answer`).
- **A credential answer under a `cache_private` row stays with its request even when the row changes during the
  flight (cred-4; plan 6.9, 9.13, C2).** The upstream reports the row it routed under (`UpstreamResult.private`) and
  the cache re-reads the row when the answer arrives; followers make their own credential call (`MISS`) instead of
  getting `COALESCED`.

Abuse protection:
- **Degraded shares never round up (mp-2; C6 over the plain reading of C7's `limit / workers`).** Each worker gets
  `limit // workers`; a limit smaller than the fleet gives a share of 0, and those requests are refused while hot.db
  cannot be written (fail closed) with a throttle refusal whose Retry-After is the configured pace, and no strike.
  Examples: `allowed_requests_per_minute` 1 with 2 workers, throttle-all at its default of 1 per 60 s, a global rule
  of 1 per period, any User-Agent cooldown rule with 2 or more workers. The divisor is the live fleet when the
  heartbeats show more workers than `ROXY_WORKERS` (both colors during a deploy). Caller-visible: during a hot.db
  outage these clients get 429s they did not get before (`abuse/limiter.py`).
- **Leaving degraded mode merges what memory decided (mp-1; C6, C7).** Merge rules: the later GCRA time, fixed-window
  counts added, the larger strikes and the later penalty; conservative, so a fixed-window count can be added twice
  when a worker flaps in and out of degraded mode. An unmerged row from an earlier outage is rebased on hot.db first.
  A pending row pushed out by the 50,000-row memory bound is never merged (P9 over completeness)
  (`abuse/pipeline.py merge_pending`).
- **Pause and throttle-all reasons are checked for C5 (spec-2).** A reason with an em or en dash or a control
  character is refused with the C5 message before anything is written, like rule messages; length is still cut to
  300 as in v1 (`abuse/messages.py checked_state_reason`). The future top-bar API answers it with 400 or 422.
- **Inline setting defaults are gone (spec-8; P3, F10).** Every abuse setting read falls back to the catalog default
  only, and a key the catalog lacks raises KeyError (`abuse/checks/base.py Facts`).

Proxy surface, errors and redaction:
- **Compat collapse covers the request deadline (spec-5; plan 7.13 compat note).** With
  `compat_collapse_upstream_errors=1` a proxied request that outlives `request_deadline_s` gets 500 with the 7.13
  text, `Retry-After: 5` and `Roxy-Refusal: deadline`, and its outcome record says 500; the flow's own choice is
  used, so a setting changed mid-request cannot split wire and record. Admin and public pages keep 504
  (`core/deadline.py deadline_status`).
- **Compat prettyprint of a cached 4xx (spec-6).** See "Compat collapse restores v1's bytes" above. One deviation:
  v2 can answer `COALESCED` for a 4xx that was never stored (the single-flight outcome), and in compat mode that
  answer is pretty printed because it is labeled as a cache serve; in v1 that follower made its own call and got a
  raw live 4xx labeled `MISS`.
- **Redaction is linear on any text (INGRESS-1, public-4; plan 9.15, 5.2).** The secret header line rule no longer
  crosses line breaks (one folded line still counts): scrubbing an 8 KiB path of `%0A` costs 0.6 ms instead of about
  80 ms, and an 8 KiB CSP report 1.9 ms instead of 77 ms. Log fields keep at most 8192 characters
  (`...[cut N chars]`), error events scrub at most 2048 characters of a path, and a CSP report's page path at most
  512, each cut before redaction (`core/redact.py`, `core/logging.py`, `core/errors.py`, `public/csp_report.py`).
- **Header names are scrubbed (cred-7, cred-8; plan 9.15 and C1 over rows 79 and 82).** A capture shows a header
  whose name holds secret-shaped text as `[redacted-header-N]: [redacted]`; fingerprints store such a name as `fp:`
  plus its keyed hash and its values as hashes. Ordinary names are unchanged; v1 stored every name as sent.

Metrics, alerts, logs and shutdown:
- **Logs are written by a thread (mp-11; plan 17.6, 9.15, 5.2).** A paused journald no longer freezes the worker;
  while it stays paused the worker queues at most 10,000 lines or 4 MiB, then drops lines and reports them as
  `log_lines_dropped` with a count (logs degrade open, like metrics in C7). uvicorn's and gunicorn's own loggers
  still write synchronously (`core/logging.py BackgroundLogWriter`).
- **The shutdown flush is budgeted (mp-6; DESIGN 11.9, C7).** The final metrics flush gets at most 4 s of the 8 s
  budget and never blocks the event loop, the heartbeat row delete waits at most 1 s, and the database close is
  budgeted; numbers a locked metrics.db cannot take in time are lost and logged (`metrics_final_flush_incomplete`)
  (`metrics/recorder.py aclose`, `scheduler/heartbeat.py`, `lifespan.py`).
- **Alert cap across a hot.db outage (mp-10; plan 17.7, C6, C7).** Memory sends are merged into `email_gate`, and
  `capmem:` reservations make the first worker back hold the other workers' shares until they report. Trade-offs: a
  worker that sent and held nothing from memory never reports, so its share stays reserved until the hourly window
  ends; a second outage in the same window is not reserved again (`notify/gate.py merge`).
- **"Served from Roblox" leaves out local OPTIONS answers (spec-7; principle P6).** They stay recorded as
  `served_upstream` with reason `options_local` (the closest enum value) and are not request samples
  (`metrics/queries.py`).

Storage and gunicorn:
- **Rows that enforce a limit outlive its longest period (AUTH-1, AUTH-2; plan 9.5, 17.7, P9).** Login failure
  slots are kept a day, the largest `admin_login_window_s` the catalog accepts, and never less than the live window
  (an hour before, which reset longer lockout windows early); alert dedupe rows (`email_gate alert:`) are kept 45
  days, longer than any alert cooldown (the rotator quota alert waits 40 days), while the hourly cap rows keep the
  one day idle; `email_gate` gets a 10,000 row cap (`storage/retention.py`).
- **A taken port fails loudly (mp-3; plan 5.2, 17.1).** The master checks its TCP port before READY (a bind without
  SO_REUSEPORT, 5 tries 1 s apart) and exits 1 when any listener holds it; a `pre_fork` hook stops the master
  instead of starting a worker that would crash-loop when a foreign listener took the port later. Residual race: a
  second master started while every worker of the first is down at once passes the check.
- **Each color defaults to its own port (mp-4; plan 5.2 `bind` row).** Without ROXY_BIND, blue binds
  127.0.0.1:8001 and green 127.0.0.1:8002 (the nginx upstream files) with a warning; before, both took 8001
  (`deploy/gunicorn.conf.py`).

Public site and design system:
- **No file system call on the event loop for public pages (mp-5, public-1, public-2; AGENT_BRIEF, plan 5.2).**
  Jinja runs without `auto_reload`, asset hashes are computed once at startup, and the guide, the home snippets,
  robots.txt and the sitemap date are loaded at startup on a thread, which costs a worker's startup about 10 ms.
  Caller-visible: `/docs` keeps serving the guide loaded at startup even if the file disappears later (it answered
  503 before, see the P12a entry), and a template or asset edit shows after a worker restart, also in development.
  Dashboard templates are read once, on their first render in each worker (`core/templating.py`, `public/pages.py`).
- **Other spellings of the page paths redirect (public-5; plan 16.1 with 10.3 and 10.6).** GET and HEAD of `/docs/`,
  `/status/` and case variants such as `/Docs` answer 308 to the page with the query string kept. They were
  `not_roblox` refusals (a JSON 404 "Not a Roblox URL" after an 8 to 20 s tarpit hold) that counted toward a spam
  probe ban. Other single-segment paths stay probes (`public/pages.py PageAliasRoute`).
- **`/status` while throttle-all is on (public-3; plan 16.1).** The banner says Degraded (unless paused or in
  maintenance), and "Your limit right now" states the emergency limit, names `Roxy-Global-Throttled` and says the
  usual limit still applies.
- **Live texts (public-7, public-8, public-9; plan 16.1, 16.2 chapters 2, 4, 7, 8 and 10).** The strike and retry
  sentences on `/` and `/docs` follow `throttle_escalation_enabled` and `throttle_strike_on_retry`; the privacy
  chapter opens with what body capture keeps while it is on (the D8 default) and says bodies are not kept only while
  it is off; chapter 2 states the live `max_url_length` and chapter 7 has a 414 row and says the size refusals (413,
  414, 431) have plain text bodies.
- **Luau examples keep the guide's conventions (public-6; owner request, plan 16.2 chapter 3).** Every function, the
  anonymous `pcall` wrappers included, has a return type (`type HttpResponse` per example), and the POST example
  encodes its body inside the `pcall`.
- **The dashboard quotes what callers really get (spec-3; plan P3, 15.6, 7.13).** The pause and emergency-limit
  banners and both dialog message fields take their text from the live `pause_message_default` through
  `admin/gallery.py caller_texts`, which asks the same message code as the refusals; the emergency-limit banner now
  says what callers get without a reason (the pause default, v1 B6), and the dialog's made-up placeholder `High load;
  please slow down.` is replaced by the default an empty message really sends.

### Migrator (P14 part)

From the migrator's build, review and fix reports (`src/roxy/migration/`, wrapper `scripts/migrate_from_v1.py`,
plan 18.3).

- **Rules are imported per table, not through `RulesService.create`.** `create` gives every new UA rule a fresh id
  and judges stored regexes again, which 18.3 ("UA rules (ids kept)") and the rule that stored v1 patterns are not
  judged again rule out. Each table is written in one control.db transaction with the service's own helpers: a
  `rule.import` audit row per rule and one `config_version` bump per table. The ladder goes through
  `RulesService.replace_throttle_tiers`; settings go through `SettingsService.update` with source `import` and
  actor `import:v1` (`migration/rules_import.py`).
- **Defaults are seeded first.** `seed_defaults` runs before the import, so a v1 cache rule with the same pattern
  as a shipped default replaces it, and a deliberately empty v1 ladder stays empty.
- **Existing v2 rows are never overwritten.** A matching row is reported "already imported" and a different one
  "kept existing"; the one exception is a shipped default cache rule (origin `default`).
- **Reruns (18.3 "idempotent"; marker version 2).** `service_state["v1_import"]` records what each finished step
  placed (setting keys, hosts, a 16-character hash of each rule's v1 key but never its text, the ladder, the pause
  and throttle-all state, admin usernames, credential file names per directory) and whether the import is
  complete. A rerun adds only v1 items no earlier run placed; anything the owner deleted or reset in v2 since is
  reported as `removed_in_v2` and not put back, a deleted admin account included. Pause and throttle-all are
  imported by the first run only, with no flag to import them again: after cutover the top-bar switch does the same
  with an audit row. A first run with errors is stored as incomplete, so the next run finishes it
  (`migration/ledger.py`, `migration/runner.py`).
- **Bypass entries only as single addresses.** v1 compared bypass entries as exact strings, so a range such as
  `198.51.100.0/24` never matched anyone; such entries are reported as invalid ("never matched in v1") instead of
  becoming an active network bypass. A single IP becomes a /32 or /128 entry whose expiry is the earlier of the v1
  expiry and now plus `bypass_default_expiry_h`.
- **Dash rewrite (C5).** Only an en dash with no spaces between two digits becomes a plain hyphen (a range such as
  10-20); every other em or en dash becomes a semicolon, colon, comma or parentheses, so "Error 429 <em dash> 2
  retries left" no longer reads as a range, and a spaced en dash between numbers becomes a comma. Plan C5 names only
  those four marks; the agent brief allows the hyphen for ranges. Every rewrite is listed in the report
  (`migration/text.py`).
- **Refusals exit with status 2 and write nothing.** A v1 root with no state, data or secret file; `--state-dir` or
  `--credentials-out` equal to the v1 root; a `--report` path inside the v1 root (`migration/cli.py`,
  `migration/v1_tree.py`).
- **v1 environment variables (plan 15.3 L).** `ROXY_ROTATE_PROXY` and `ROXY_ROTATE_PROXY_FILE` are read from the
  environment as v1 did; the v1 state and data file names come from the new `--v1-state-file` and `--v1-data-file`
  flags; a path outside the v1 root is read by its file name inside the root, with a warning. The other v1 path
  variables name disposable files and are ignored.
- **files.txt never leaves the root.** Lines outside `--v1-root` (absolute or `../`) are not followed; an absolute
  path is read again by its file name inside the root, so a copied tree cannot make the migrator read the live
  `/etc/roxy`.
- **Secrets in admin text and statistics.** Text is scrubbed before it is cut to its length limit, and pieces of
  every long secret are masked, case ignored (the rotator URL is matched whole, so its host stays readable); a rule
  whose match text holds a secret is refused; a ladder rung whose text held one is kept with `[redacted]` and a
  warning, because dropping it would shift every later multiplier. The 6-character masking minimum stays; the
  report warns when the v1 admin password is shorter.
- **Fingerprint values left out.** Values of headers v2 stores only hashed (secrets, client addresses) and values
  redaction would change are not imported: v2 hashes them with a key the migrator does not have.
- **Endpoint rules import with scope `ip`.** v1 capped each rule at `allowed_requests_per_minute`; nothing is lost,
  because the v2 runtime clamps `ip` rules to the per-IP allowance (`abuse/endpoint_rules.py`; the review's
  correction of the build report).
- **`cache_post_requests = 1`** maps to `all` with a high-risk warning in the report's warnings; imported cache rules
  are GET only.
- **Credential files.** Leftover `.<name>.<8 hex>.tmp` files are deleted at the start of a run and reported; an
  existing credential file readable by others is set to 0600 with a warning; discarded extra token lines are logged
  as `v1_credentials_discarded` with the count and the last 6 characters only (C1); the report is written under a
  random temporary name opened with `O_EXCL` and `O_NOFOLLOW`.
- **Admin import (D5).** Only with `--import-admin-password`: an argon2id hash, the admin email from the v1 emails
  file and `mfa_bootstrap_pending = 1`; without an email the report warns that the emailed bootstrap code cannot be
  sent (`migration/admin_import.py`).
- **Statistics (D17).** Lifetime counters go to `legacy_totals` as `v1.roblox_429_total`, `v1.requests_total` and
  `v1.roblox_429_per_10k_requests` (`{value, label, since, source}`, the plan 11.6 baseline); probe summaries become
  `events` of type `v1_probe_summary`; fingerprint rows use `metrics.fingerprints.row_hash`, so they merge with live
  rows.
- **A v1 paused at copy time starts v2 paused.** The report warns; MIGRATION.md must say to switch it off after
  cutover.

### Wave 3a (P13 ops, P12a public site, P11a design system)

From the build, review and fix reports of each part (all done 2026-10-07), the C5 decision of fix pass 1 and the
Luau follow-up of 2026-10-08.

#### Operations (P13; `deploy/`)

- **Migrations run as `roxy` in ExecStartPre (17.4 step 3 against 17.1, 17.3 and 9.14).** The databases belong to
  `roxy` and the deploy user may not run anything extra with sudo, so the snapshot, the expand migration and the
  defaults seed run in `deploy/prestart.py` inside the restart of 17.4 step 4: the same order, no new privilege, and
  no `-wal` or `-shm` files the service could not open.
- **Root tools live in `/usr/local/lib/roxy` (9.14 over the 17.3 table).** 17.3 put root-owned `/opt/roxy/tools`
  inside the deploy-owned `/opt/roxy`, where the deploy user could swap a tool that root runs.
- **`roxy-nginx-apply` verifies from its own git mirror (section 9 prose over the 17.3 table).** Releases stay
  deploy-owned (the deploy user builds the venv), so the wrapper fetches into a root-only mirror from the repository
  URL in the root-owned `roxy.env`, checks that the commit is on `main`, installs the bytes from git objects and
  refuses any mismatch with the deploy's manifest or the release files, read without following links.
- **Actions the deploy user cannot take (9.14).** SIGTTIN is replaced by the gunicorn control socket's
  `worker add` (the same code as the SIGTTIN handler, with `systemctl reload` as fallback); `roxy-audit.path` runs
  the audit when `deployed_version` changes; `deploy.sh` writes `last_failure.json` and `roxy-deploy-alert.path`
  starts `roxy-alert@deploy-failure`; `deployed_version` lives in `/var/lib/roxy-deploy/`.
- **System call filter (17.1).** gunicorn chowns its Unix socket and `~@privileged` killed the master at first
  start, so the unit allows `@chown` again and sets `SystemCallErrorNumber=EPERM`, which turns a blocked call into a
  Python error instead of a silent kill.
- **Static files from the active release (17.2).** Each color file holds the whole upstream block plus a
  `$roxy_active_color` variable, included at http level, so one symlink switch changes both.
- **nginx beside v1.** The template `roxy.conf.template` is installed as `roxy-v2.conf` next to v1's `roxy` site;
  the SSL session cache is `roxy_ssl` instead of `SSL`; nginx 1.18 has no `ssl_reject_handshake`, so there the
  default 443 server presents the site certificate and closes the connection; `ROXY_NGINX_*` hints go to
  `/etc/roxy/nginx-hints.env`.
- **Boot, accounts and credentials.** `roxy@.service` has no `[Install]` section; `roxy-boot.service` starts
  whichever color nginx points at, because the deploy user cannot enable a color. The deploy account is
  `roxy-deploy`, never `ubuntu` (which has unrestricted sudo on Lightsail). Optional credential files must exist for
  LoadCredential, so an empty file means "not configured". The low-memory threshold is 700 MB (the plan said 900
  MB; DESIGN.md section 0).
- **Additions.** `deploy/install-system.sh`, `scripts/build_static.py`, a second smoke run through nginx after the
  switch (HSTS on a static asset), and a refusal to run `deploy.sh` as root.
- **`/etc/roxy` while v1 runs (review finding 1; the brief and C3 over the 17.3 table by 0.2 item 7).**
  `install-system.sh` leaves a v1-owned `/etc/roxy` (owner, group and mode) alone and only adds an ACL entry so the
  deploy user can pass through (`setfacl -m u:roxy-deploy:x`); the `acl` package is required, and without it the
  script stops and changes nothing. `chmod 0711` was rejected because it would expose v1 files created with a looser
  mode (9.8, 9.14). `--take-over-etc` at cutover sets root:roxy 0750 and removes the ACL entry.
- **Report and backup status files (findings 2 and 5; 9.14 prose).** `backup.sh` and `roxy-audit.py` write through
  a root-owned `audit/` directory opened with `O_NOFOLLOW` (anything else found there is moved aside), under a
  random name opened with `O_EXCL|O_NOFOLLOW`, with mode and group set on the open file; the directory is 0750
  root:roxy and the files 0640, even under `UMask=0077`. The paths stay `/var/lib/roxy/audit/perms.json` and
  `backup.json`, as plan 13.2, 17.1 and 17.3 and the health fixtures expect.
- **A failed deploy restores the previous nginx config (finding 3; the 17.4 rollback goal).** The failure record
  says whether the restore worked and prints the command when it did not.
- **Every location that reaches the app is rate limited (finding 4; the 17.2 "Why" column).** `/health` and the
  static fallback gained `limit_req zone=perip burst=100 nodelay`; only the event stream (`/admin/api/v1/stream`)
  is exempt.
- **Deploys before the cutover (finding 6).** The public check requires the `Degraded` key that only v2's
  `/health` sends; until v1's site is disabled, deploys run with `ROXY_DEPLOY_PUBLIC_CHECK=0` (`deploy/README.md`).
- **The kill-switch token never reaches a log (finding 7, plan 17.2).** The invalidate location sets
  `error_log /dev/null;` as well as turning the access log off.
- **Missing state directory (finding 8).** The audit and backup units mark `/var/lib/roxy` optional and
  `install-system.sh` creates it (roxy, 0750); `backup.sh` exits 0 before the first deploy.
- **Sudo rules are checked as installed (finding 9).** The deploy user name must be a plain account name, and
  `visudo` checks the rendered file before it is moved into place.
- **Releases ship compiled bytecode (finding 10)** (`uv sync --compile-bytecode`).
- **Contract migrations stay manual (finding 11; 17.4 step 3 against rollback to any kept release, 0.2 item 3).**
  Running them automatically would break an older kept release that `deploy_rollback.sh <sha>` can start;
  `prestart.py` names pending contract migrations in the journal and `deploy/README.md` gives the manual
  `--contract` command.
- **Redaction (findings 12 and 13).** The failure alert redacts JSON and Python dict forms of secret headers;
  `user:password@` is removed from repository URLs in log lines and failure records.
- **Symlinked directories are refused.** `install-system.sh` no longer changes owner or mode through a link (the
  deploy user owns `/opt/roxy` and could point `releases` at `/etc/sudoers.d`); a narrow race remains while the
  owner runs the script.
- **Test-only overrides.** `ROXY_INSTALL_UID` and `ROXY_SETFACL` are honored only with `--prefix`; `backup.sh`
  reads `ROXY_DEPLOYED_VERSION_FILE`.

#### Public site and user guide (P12a; `public/`, `templates/public/`, `docs/USER_GUIDE.md`)

- **Quick start examples (16.1 against v1's page; 0.2 item 1).** The plan says v1's GET examples included a
  RequestAsync snippet, but v1's only RequestAsync snippet was in the POST section; the quick start has one
  GetAsync and one RequestAsync GET example from 16.2, and the POST snippet stays.
- **JSON-LD (row 12 against 9.2).** It stays exactly as v1, in a `<script type="application/ld+json">` data block
  that never runs and carries the nonce; every executable script is a nonced module.
- **Visits.** HEAD requests are not counted as visits (v1 counted `HEAD /`); a sitemap fetch counts as a visit.
  Pages call `record_visit(page, user_agent)`, the recorder's page-first form, and visitors are classified only in
  `metrics/visitors.py`.
- **Assets and links.** The favicon link says `image/png` (v1 said `image/x-icon`) and `/favicon.ico` gets a
  one-day browser cache; `og:image` names the content-hashed file (row 18); the icons are smaller copies of the v1
  art (favicon 64 px, 3,403 bytes; og image 512 px, 43,832 bytes; metadata removed) instead of two PNGs of about
  1 MB each; v1 section ids are kept, so `/#tokenSafetyHeading` still works.
- **The user guide ships with the release (review finding 1).** `pages.find_user_guide()` looks for
  `docs/USER_GUIDE.md` in the package folder and up to 5 levels above it, which finds the repository copy in
  development and `<release>/docs` after `uv sync --no-editable`; a copy packaged in the wheel would win. A worker
  refuses to start without the guide (`UserGuideMissing`, so a bad release fails the health gate). Since the wave 2
  review round the guide is rendered once at startup, so a file that disappears later changes nothing until the next
  restart (it answered 503 before); `/docs` answers 503 only in an app whose startup never loaded the guide.
- **CSP reports (finding 2; plan 9.2 against the recorder API).** One stored report per request; one hot.db write
  checks three hourly limits (100 for the fleet, 5 per client by IP or IPv6 network, 10 per identical report) and
  writes nothing unless a report is stored (`others_in_body` counts the rest). The 9.2 "low priority" is met through
  the recorder's aggregated events (priority 55, below every individual event at 60, with identical reports in a
  minute sharing a row), since the recorder has no low-priority single-event path (`public/csp_report.py`).
- **Status page.** The "Roblox is asking Roxy to slow down" note counts only active direct or rotator cooldowns that
  Roblox caused (`retry_after`, `ratelimit_reset`, `default`), built with `upstream.cooldowns`' own key functions,
  so credential and breaker rows no longer show it (finding 3); the minute scan starts after the newest compacted
  hour (finding 7); a manual pause shows as paused even inside a scheduled window, read through
  `abuse.pause.PauseState`.
- **Texts follow live settings (findings 4, 11 and 12).** CORS, the place limit key, a strike decay of 0, an IPv6
  prefix of 128 and the cache-bust parameter list ("by default") follow their settings; refusal bodies are described
  as JSON strings; counts of one read as singular; `/status` links appear only while the page is on. The guide's
  `{{ }}` markers were renamed, and four values are built-in HTML snippets made from constant text.
- **Accessibility (findings 8 to 10).** Heading anchors sit beside the heading at full-opacity muted color; each
  status state has its own pattern and height besides its color; the copy result is announced through one polite
  `role="status"` region.
- **Rejected: a separate 404 body for a disabled `/status` (finding 13).** Whether the page is on is already public
  (navigation, home page, sitemap), plan 15.3 K asks for a 404, and copying the proxy's refusal body would duplicate
  another package's format.
- **Module constants (principle P3).** The status thresholds (10 s view cache, 10 minute window, 10% failure share,
  at least 20 answered requests, 50% paused share) and the CSP report numbers (8 KiB, then 100, 5 and 10 per hour)
  are documented module constants, not catalog settings; the lead may move them.

#### Design system (P11a; `templates/admin/`, `templates/components/`, `static/`)

- **C5 exception for vendored third-party files (C5 against 14.10 and 9.2).** htmx 2.0.11, Alpine CSP 3.17.4 and
  uPlot 1.6.32 are served byte for byte with SRI hashes pinned in `src/roxy/static/vendor/VERSIONS.md`, and
  axe-core 4.13.0 is copied unchanged for the accessibility tests. Editing them to remove one em dash in a comment
  and a few British spellings would fork the libraries and break the SRI hashes, so `scripts/check_style.py` skips
  `src/roxy/static/vendor` and `tests/e2e/vendor` when it walks the tree (a file named on the command line is still
  checked). Plan 20.3's "zero dashes in the repo" therefore excludes those copies; everything Roxy writes is still
  checked (`test_check_style.py::test_directory_walk_skips_only_the_vendored_third_party_libraries`).
- **Vendored versions.** Each is the newest stable release at least two weeks old: htmx stays on 2.x (4.0.0 is a
  rewrite on the `next` tag) and axe-core stays on 4.13.0 (4.14.0 was two days old).
- **CSP spike (the P0 gate item, done here).** The exact 9.2 policy with a fresh nonce runs htmx, Alpine CSP and
  uPlot with zero violations, and a wrong SRI hash blocks the module. Two rules follow: htmx is imported statically
  and configured before it starts (otherwise it injects an indicator `<style>` without a nonce), and Alpine's CSP
  build refuses property assignments on DOM objects in expressions. No `style-src-attr` hashes are needed.
- **Heartbeat and logout (plan 9.6).** The heartbeat is `POST /admin/api/v1/auth/heartbeat` with JSON `{idle_ms}`
  and the CSRF header, sent only after real input, at the shorter of `admin_heartbeat_interval_s` and
  `admin_activity_window_s`; logout is a POST with the CSRF header (a plain form cannot send it) and leaves the page
  only on a 2xx or 401 answer.
- **Theme tokens use CSS `light-dark()`** (Chrome 123, Firefox 120, Safari 17.5 and later), with a fallback block
  that gives older browsers, older iOS Safari included (plan 14.8), both themes; a test fails if the fallback
  drifts from the main tokens.
- **Development-only gallery.** The component gallery is not behind the admin login: every route answers 404
  outside development and `include_gallery` adds nothing in production; `gallery_routes()` lists its paths for the
  19.7 route discovery test.
- **Glossary location.** `docs/glossary.yml` (104 terms, every plan section 21 term included) is found by searching
  upward from the package, like the user guide, instead of being shipped as package data; a missing file raises a
  `FileNotFoundError` that names it.
- **Shortcuts (14.6 against 14.9, WCAG 2.1.4).** Single-key shortcuts are kept with an on and off switch (in the
  `?` overlay and the account menu, remembered per browser); Ctrl+K always works; `t`, `c` and `g` plus a letter
  refuse with a toast while a setting is unsaved, and a "Leave site?" guard covers other navigation.
- **Re-auth signal (DESIGN.md 13 against the auth code as built).** DESIGN.md 13 signals re-auth with the JSON code
  `reauth_required`, while the auth routes send `Roxy-Reauth: required` with a text body; the client accepts both
  and raises a cancelable `roxy:reauth` event. The lead decides the contract (open).
- **Contracts for P11 part two.** Page URLs are `/admin/<page id>`; setting forms post `key`, `value`, `reason` and
  `confirm_high_risk` and mark unsaved state with `data-dirty`; the server may refresh the CSRF token with an
  `HX-Trigger` event `roxy:csrf`; links taken from data render only for local paths through the `local_href` macro.
  The shell's `status` context carries `pause_message`, `pause_default` and `throttle_message`, built with
  `admin/gallery.py caller_texts` from the live `pause_message_default`, plus `paused = PauseState.active(now)`
  (wave 2 review round, finding spec-3).
- **Review fixes.** Tooltips, toasts and live regions move into the topmost open modal; keyboard focus never hides
  under the phone bottom bar; charts and live tails removed from the page release their memory and streams; live
  tail text filters are debounced; the palette follows only same-origin `/admin` paths; a failed drawer load says
  so in the drawer; the session overlay keeps other dialogs open; Escape on a tooltip closes only the tooltip; the
  spinner stands still with reduced motion; shadows render again.

#### Luau follow-up (owner request of 2026-10-07; `public/`, `templates/public/examples/`, `docs/USER_GUIDE.md`)

- **`const` exists in Luau since release 0.711.** The RFC "Const Keyword" is implemented and release 0.711 added
  `const` bindings that can never be reassigned; luau-analyze 0.741 parses and type checks `const` and
  `const function` and reports a reassignment as an error. The guide and the home quick start say to write `local`
  (and `local function`) where a Studio build refuses `const`. Studio support itself was not checked, because
  roblox.com is off limits for this run (open).
- **Every example is strict and fully typed (plan 16.2 chapter 3 example replaced on owner request).** The six
  examples (three home files, each repeated in the guide, plus the headers example, the `RoxyClient` module and the
  script that uses it) start with `--!strict`, use `const` for every binding that is never reassigned and `local`
  only where a name changes, check decoded JSON before use, comment every `any`, call `GetService` once at the top,
  wait with `task.wait` only, handle status codes from `RequestAsync`, and honor `Retry-After` with a fallback,
  jitter and a cap (a 5xx `Retry-After` included). The plan's example used `local`, `wait_seconds` and no
  annotations. Each example passes `luau-analyze --mode=strict` under both `--solver=new` and `--solver=old` with
  zero errors and zero warnings (`tests/unit/public/test_luau_examples.py`, which skips when the binary is missing).
- **Server-side highlighting (plan 9.2).** `public/luau_highlight.py` turns every Luau block on `/` and `/docs` into
  spans with one-letter classes: no script and no inline style, every text piece escaped, it never raises, runs in
  linear time and bounds nesting at 16. The highlight colors pass WCAG AA in both themes (the lowest is 5.49:1),
  checked by `scripts/check_contrast.py --public`.
- **Code blocks are keyboard tab stops (plan 14.9, 19.8; WCAG 2.1.1).** Every `<pre>` scrolls sideways, so it opens
  as `<pre tabindex="0">`.
- **Cache hits count, said everywhere (the owner's D10 reversal over 16.2 chapter 4).** Plan 16.2 chapter 4 said
  cache hits do not count. The home page, guide chapter 4 and its FAQ ("Why do I get 429 when I barely send
  anything?"), the status page and the glossary say every request counts toward the limit, cached or not, because
  an answer from Roxy's cache spares Roblox but still costs Roxy CPU, memory and bandwidth, and one shared allowance
  per caller keeps Roxy fair for everyone. If an admin turns counting off, the texts follow the live setting.

### Wave 3b (P9 admin API, P10 insights and health)

Collected from the twelve builder reports and the integration report of 2026-10-08 and 2026-10-09
(`.remake/wave3b_reports/`; the long tables named here are in those reports). Module paths are under `src/roxy/`;
DESIGN.md 13.1 and 14 hold the exact contracts. The review round of 2026-10-09 and the lanes are recorded in the
"Review round 3" and "Lanes" subsections at the end (DESIGN.md 14.9); where they differ from the entries before
them, they win.

#### Plan conflicts resolved by the integration

- **One error format for the whole admin API, guard answers included (DESIGN 13 against 11.9 and the P8 entry "Guard
  answers").** DESIGN 13 wins. On `/admin/api/v1` the guards now answer section 13 objects: 401 `unauthorized`
  ("Session expired", the session cookie still cleared), 403 `forbidden` (CSRF or origin), 403 `enrollment_required`
  with `Roxy-Enroll: required` and 503 `unavailable`. Any `HTTPException` that carries an `error_code` on an `/admin`
  path gets its own code, so the auth routes' fresh second factor refusal, enrollment included, is 403
  `reauth_required` with `Roxy-Reauth: required`, the same as the area routes. This closes the re-auth contract left
  open under "Admin auth (P8)" and "Re-auth signal" (P11a): every refusal sends the header and the code, and the
  dashboard client reads both. The admin allowlist 404 stays byte for byte the answer for a missing path (D6; on the
  API that is 404 `not_found` "Not found."), and signed-out page requests keep the 302 to `/admin`
  (`core/errors.py section13_exception_body`, `admin/auth/deps.py ReauthRequired`, `admin/auth/routes.py`,
  `static/js/auth.js`).
- **Worker CPU is measured per process (SYS-WORKER-SAT "a worker's CPU" against the engine author's request for the
  cgroup `cpu.stat` delta).** The cgroup covers a whole color and cannot tell workers apart; every heartbeat takes
  the growth of the worker's own `time.process_time()` per monotonic second, as a percent of one core
  (`scheduler/heartbeat.py CpuMeter`).
- **No scheduled health run at boot (the health author's run at start against 17.4 deploy safety and test
  isolation).** A run at start probed every allowed host while a worker booted, during a deploy's health gate too,
  and polluted tests that count upstream calls. The first scheduled poll now comes 5 minutes after a worker starts
  leading; `health_auto_interval_h` is unchanged (`health/runner.py`).

#### Admin API conventions (P9 shared layer; `admin/api/common.py`, `admin/api/__init__.py`)

- **Body errors come after the guards (plan 9.6 against FastAPI's order, with D6 and 9.5; section 9 first).** FastAPI
  parses a body before the dependencies run, so `AdminApiRoute` runs the guards again before it answers a body error:
  a signed-out caller gets 401, a cross-site caller 403 and a caller outside the admin allowlist 404 before any 400
  or 422, and none of them learns anything about the body. Malformed or missing bodies are 400 (`invalid_json`,
  `missing_body`, `invalid_body`), never `{}`.
- **Mount checks refuse to start the app.** A route under `/admin/api/v1` without `require_admin`, an unsafe one
  without `require_csrf`, an area route that is not an `AdminApiRoute`, or two areas on one prefix raises
  `ApiMountError`. The router is built on first use, so `roxy.admin.sse` may be imported first, and a nested prefix
  mounts before its parent: `export_llm` (`/export/llm`) before `export`, whose `/export/{dataset}` would otherwise
  shadow it.
- **Exports (plan 9.16; 9.15 and 12.3; 9.7 with C7; parity row 88).** Files are named `roxy_<table>_<epoch ms>.<ext>`
  as in v1; the CSV header is the column labels, every cell is quoted and the formula guard applies to every cell,
  numbers included, so `-5` exports as `'-5`, as v1's `toCSVRow` did; JSON is
  `{table, exported_at, columns, items, total, truncated}`; at most 50,000 rows, with `Roxy-Export-Rows` and
  `Roxy-Export-Truncated`. IP columns are hashed unless `export_include_ips` is on (9.15 and 12.3 say the setting
  covers "the LLM export and data exports"), with a stable key only under `export_stable_ip_hash`. The
  `export.download` audit row is written first, and no file leaves when it cannot be written (503).
- **Time ranges and tiles (DESIGN 13 over `metrics/queries.py GRANULARITIES`; 14.1).** Granularity `year` is not
  offered; `from` and `to` only with `range=custom`, as ISO 8601 (a time without an offset is read in `ui_timezone`)
  or epoch seconds between 1970 and 2100; more than `MAX_POINTS` buckets is 422. KPI deltas use the previous period
  when no `compare` is given (14.1 tiles show deltas while `compare` is optional), and sparklines have 61 points and
  name their `sparkline_range`, so a sparkline always sums to its tile.
- **Resets that delete no counters write a `config_change` marker (6.8 "every reset writes an annotations row"
  against P6).** A `reset` marker makes KPI tiles report partial data, so the limiter, bans and upstream state
  resets, which delete no counters, write a `config_change` marker instead; charts still show it, linked to the audit
  row. Only a reset that deleted counters writes kind `reset` (`metrics/annotate.py`, the one writer of `annotations`
  since the integration).
- **The API schema is for signed-in admins only.** `GET /admin/api/v1/openapi.json` (no-store) lists every area and
  the stream (220 paths, 26 tags) and never the login routes; there is still no public schema. The component gallery
  is mounted by the admin router's lifespan in development apps only, so production never imports it
  (`admin/router.py admin_lifespan`).
- **Bounds are module constants (the lead's decision on safety bounds, P3 against P9).** In `common.py`:
  `MAX_EXPORT_ROWS` 50,000, `MAX_PAGE` 1,000,000, `MAX_SEARCH_CHARS` 200, `MAX_FIELDS` 50, `MAX_MESSAGE_CHARS` 500,
  `MAX_BODY_STRING_CHARS` 8192 and `MAX_TIME_TEXT` 40; each area module and read model documents its own.

#### Settings, audit, preferences, data, export and system (P9; `admin/api/`)

Code: `admin/api/settings.py`, `audit.py`, `prefs.py`, `data.py`, `export.py` and `system.py`, with their read
models.

Plan conflicts:
- **Metric families share rollup rows (6.8 against the v2 schema; P6).** The `traffic` and `internal_calls` (rows
  with `source = 'internal'`) families delete their rows, and the preview says that Traffic totals drop with them;
  `latency` empties the histogram columns and keeps the counts; upstream call counts are never zeroed on their own,
  which would inflate "avoided calls". Since review round 3 the `cache_stats` family deletes no rollup rows: it
  moves every cache lookup (hits, misses, stale, revalidating, coalesced) to the cache state `cleared` and keeps
  the requests in every total, as v1's "Clear stats" did (finding parity-8; C3 and 6.8 "headline KPIs honest"
  over the 6.8 table's "rows of that family").
- **"Everything" keeps live state (6.8 "all of metrics.db" against C6).** `dims` (the recorder relies on its rows),
  `worker_heartbeat` and `health_job_status` are kept.
- **The factory reset keeps admin access and history (6.8 against D6, 9.5 and 9.7).** `access_list` entries of kind
  `allow_admin` are kept, so a reset never widens admin access; the audit log, settings history and the pause and
  throttle-all switches are kept too. It refuses to run without a control.db snapshot (409 `not_feasible`), and it
  has its own `fresh_mfa` route so the mount check sees the guard (9.6).
- **"Back up now" makes on-server snapshots (14.1 against the unprivileged service, 9.14 and 17.1).** The service
  cannot start the root backup unit, so the button takes `VACUUM INTO` snapshots in `<state dir>/snapshots`
  (`manual-*`, pruned by `file_retention`); the nightly backups are listed from `audit/backup.json`. Since review
  round 3 it also asks the root backup to run (`<state dir>/backup-request`, watched by
  `roxy-backup-request.path`; the Data page shows the last answered and any pending request); its copies count
  against `snapshots_max_bytes` together with what the folder holds, it replaces only its own oldest copies (409
  `not_feasible` when that is not enough), and one backup or reset runs at a time fleet-wide (409
  `run_in_progress`; finding apisec-5).
- **VACUUM lives on the Data page (6.5 System page against 14.1 Data page, C7).** It needs a typed phrase, and hot.db
  is never offered: its write lock would stall every proxied request.
- **Snapshots "where feasible" (6.8 against 17.5).** Only databases that lose rows are copied, within
  `snapshots_max_bytes` and the free disk; cache.db and hot.db never are.
- **Audit before action (9.7 with C7).** The intent row of a reset is written first; if it cannot be written, nothing
  is deleted.
- **`POST /prefs` takes JSON and form posts (DESIGN 13 against `theme.js`, which posts form fields).** Both go
  through one validation.
- **An import always needs a reason (15.2 "applies atomically with a reason" over the settings service, which asks
  for one only for risky values).**
- **Ranged reset markers (6.8 "every chart covering that time").** The marker of a ranged reset sits at the range
  start and, since the integration, stores the range end (`annotations.until`, metrics.db schema 4): a KPI window
  inside the deleted range gets the partial-data notice, and the notice names the range
  (`metrics/queries.py reset_annotations`, `admin/api/common.py reset_notices`).

Deviations:
- **Reset flow.** The preview returns the exact rows per table, the oldest and newest dates, what stays, the snapshot
  plan, the typed phrase and a digest of the normalized scope; a run without that digest is 409 `preview_required`.
  Typed phrases: `reset <family>`, `reset N families` (no range), `purge cache`, `delete all bans`, `reset limiters`,
  `delete recommendations`, `delete health history`, `everything` and `factory reset`; a phrase scope also needs a
  reason. Operations run in the background (200 within 5 s, else 202 and `GET /data/operations/{id}`), one reset at a
  time fleet-wide (hot.db lease, 409 `reset_in_progress`), with intent, done and failed audit rows (`data.reset`,
  `data.reset.done` with the exact rows per table, `data.reset.failed`) and batches of 5,000 rows followed by
  `incremental_vacuum`.
- **Families map to tables.** Rollup rows: traffic, latency, cache_stats, internal_calls. Event types: throttle
  (`throttle_tier`, `ua_rule_hit`, `throttled`), probes (`probe`, `v1_probe_summary`), logins, crawls, visits,
  refusals, live (also `captures`), internal_calls (`internal_call`). Tables: upstream (`upstream_429`,
  `upstream_attempt_minute`, `bucket_minute`, events `failure` and `upstream_retry`), cache_stats (`cache_minute`,
  `cache_eviction_passes`, `change_observations`), egress_usage, fingerprints (the `fingerprint_*` tables and the
  blocked events), activity (`client_*`), errors (`errors`, `error_minute`). Tarpit: the hot.db `tarpit_arrival:`
  rows and every worker's in-memory counters.
- **Client and endpoint scopes.** A client reset covers the client rows, strikes, its limiter rows (per-IP, `flood:`,
  `tall:`, `ucr:`, `tarpit_arrival:`, and `ua:` and `ep:` suffixes) and its events (by `ip_hash` or by place). An
  endpoint reset covers its rollups, its 429 rows, its `endpoint:<template>:<egress>` cooldown and breaker rows and
  its cache entries (an anchored regex, one segment per placeholder).
- **Settings.** Every change of a high-risk setting needs `confirm_high_risk` and a reason, turning it off included
  (422 `confirmation_required`, one field per key); `GET /settings/values` was added; sensitive settings show
  `[redacted]` everywhere, and their fingerprints are keyed from `ip_hash_key`, so they match across workers. Audit
  entries carry a flat diff; one-click revert exists for settings only, and rule entries link to their card.
- **Preferences.** Keys `theme`, `density`, `shortcuts`, `sidebar`, `timezone`, `default_range`, `compare`,
  `live_filters`, `tables` and `panels`, one `admin_prefs` row each; at most 100 tables, 200 panels and 50 hidden
  columns per table, the least recently changed forgotten first; defaults from `ui_default_theme`, `24h` and `none`.
  Preferences are not audited.
- **System.** Jobs and checkpoint data are labeled by source (this worker or the leader's published status); the
  metrics pipeline is labeled "this worker"; the forced flush (row 121) writes `service_state.flush_requested_at`
  with its audit row, flushes this worker at once and reaches the others through the per-worker job
  `admin_requests_watch` (a 1 s poll), which also clears per-worker memory counters named in `memory_reset_at`. The
  environment summary lists which optional credentials exist by name, never a value.
- **Storage projection.** Rows added per day over 7 days times 30, added to today's rows and bounded by the maximum
  age and the row cap; bytes follow the current bytes per row. It is labeled an estimate; `refresh=true` is honored
  at most every 10 s and results are cached 60 s per worker.
- **Export datasets.** 16 datasets (`endpoints`, `hosts`, `clients_ip`, `clients_place`, `refusal_reasons`,
  `internal_calls`, `upstream_429`, `probes`, `logins`, `crawls`, `throttled`, `errors`, `audit`, `settings`,
  `settings_history`, `workers`) plus a link to the LLM export.
- **Bounds as module constants.** `MAX_CHANGES` 1000, `MAX_OPERATIONS` 32, `STORAGE_CACHE_S` 60, `RESET_LEASE_TTL_MS`
  30 minutes, `VACUUM_BYTES_PER_S` 40 MiB/s (an estimate rate), prefs `MAX_TABLES` 100 and `MAX_PANELS` 200, audit
  `PREVIEW_CHARS` 2000 and diffs of 500 paths, `read_purge_counts.MAX_SCAN` 200,000.

The v1 clear targets map onto the 6.8 scopes as follows (plan 6.8 asks for this table here; constant
`admin/api/data.py V1_CLEAR_TARGETS`, checked by `test_api_data.py::test_reset_listing_maps_every_v1_clear_target`):

| v1 target | v2 scope | Note |
|---|---|---|
| probes | family probes | |
| requests | family traffic | counters, statuses, retries and the traffic chart are traffic rows |
| refusals | family refusals | |
| ip_activity | family activity | covers places too |
| callers | family activity | covers IP addresses too (v1 B12 fixed) |
| internal_requests | family internal_calls | |
| proxy_timings | family latency | |
| request_failures | family upstream | failures are upstream events |
| rotate_ips | family egress_usage | v2 never stores exit IPs; egress usage is the stored rotator data |
| endpoints | family traffic | the endpoint scope resets one template |
| blocked_attempts | family endpoint_block_attempts | endpoint block refusals only |
| rate_limited_attempts | family endpoint_rule_attempts | endpoint rule refusals only |
| header_blocked_attempts | family header_rule_attempts | request filter refusals only |
| pause_drops | none | nothing to reset: the banner counts from the pause start |
| throttle_drops | none | nothing to reset: enabling throttle-all starts a new count |
| tarpit | family tarpit | |
| cache | family cache_stats | hits, misses, stale and coalesced together; requests and entries stay |
| throttle_rules | family throttle_rule_hits | ladder rung and UA rule hit counts |
| live | family live | captured bodies too |
| logins | family logins | |
| crawls | family crawls | |
| throttled | family throttled_clients | the throttled clients list |
| visits | family visits | |
| errors | family errors | |
| fingerprints | family fingerprints | |
| blocked_fingerprints | family fingerprints | one family in v2 |
| all | everything | plus System > Reset counts for the worker counters |

The five narrower families (`endpoint_block_attempts`, `endpoint_rule_attempts`, `header_rule_attempts`,
`throttle_rule_hits`, `throttled_clients`) are parts of the plan 6.8 `refusals` and `throttle` families and name
their `parent` (finding parity-9, C3).

#### Protection, clients and security (P9; `admin/api/`)

Code: `admin/api/protection.py`, `clients.py` and `security.py`; read models in `abuse/read_bans.py`,
`abuse/read_spam.py`, `metrics/read_protection.py`, `metrics/read_clients.py` and `metrics/read_security.py`.

Plan conflicts:
- **The spam arming preview (10.3 FILTER-COLLATERAL "against the last 7 days of `request_samples`" against what
  samples hold; P6, C3).** Samples hold only served and failed requests, sampled and keyed by a client hash, so the
  collateral preview is built from the detectors' own dry-run decisions (`spam_would_ban` events of the last 7 days)
  judged against the exact client activity tables: a client looks legitimate when its served share is at least
  `insight_filter_collateral_served_pct` or a detector saw the game server signature, and a key with no activity rows
  (an IPv6 network) is listed for review. `POST /protection/spam/arm` needs the preview's token, a digest of the
  legitimate-looking list (`abuse/read_spam.py`).
- **A fresh second factor for admin allowlist changes and spam arming (9.6 list against D6 and 10.3; stricter, never
  looser).** The allowlist decides who can reach `/admin` at all, and arming starts automatic bans that can hit
  shared game server addresses. Removing the admin allowlist entry that covers the caller's own address while the
  allowlist is on also needs `confirm_lockout=true`.
- **Attempts tabs count clients (row 75 against 9.15).** Refusal events keep only a keyed client hash, so the
  blocked, rate-limited and header-blocked tabs show distinct clients (a lower bound, plus an `unattributed` count
  for folded rows) instead of v1's last IP, and the rule shown is the one that matches the path now (`current_rule`),
  because refusal events do not record the rule (deferred, see P9 below).
- **Bot score (10.7) needs the User-Agent,** which only the 15-minute live rows keep; without one the score is null
  with a note (P6 over a guess). Header order is not stored, so that signal reads as a known client.
- **Tester samples (row 45).** v1 sampled live requests with all their headers; v2 samples hold the User-Agent and
  `Roblox-Id` lines only (with the capture id when there is one), and the v1 example lines are kept verbatim.

Deviations:
- **Protection settings.** `PATCH /protection/settings` accepts only settings whose catalog `pages` name a Protection
  card; `spam_dry_run` is switched off only through `POST /protection/spam/arm` (switching it on, `/spam/disarm`, is
  always allowed).
- **Pause and throttle-all.** A reason or message with a dash or a control character, and an invalid schedule window,
  are 422 (the "future top-bar API" of the spec-2 entry above); throttle-all checks the message before the limit or
  period changes, so nothing is half applied, and a bad limit or period is 422 (v1 bug B16 fixed).
- **The limiter reset (6.8) deletes strike rows too,** so it ends running penalties; forgive still does not (v1 B19
  kept). Tarpit bookkeeping rows (`tarpit_arrival:`, `ucr:`) survive a limiter reset.
- **Bans.** Reset scopes are all (typed confirmation `all bans`), automatic only, expired only and one detector, each
  previewed first; a ban on a subject with an active ban extends it, and the answer says `extended_existing`.
- **Client actions.** "Rule" on an IP adds a deny list entry; on a place it adds an exact request filter on
  `Roblox-Id` (v1's Block button).
- **Lookup errors are section 13 objects.** 422 for an id that is not ASCII digits, 404, and 502 `upstream_failed`
  when Roblox could not answer (v1 answered 502); the result is snake_case and carries v1's "recently created with
  very few visits" warning as `recently_created_warning`.
- **Security area.** Passkeys can be renamed (plan 14.1 lists it); sessions, trusted devices, passkeys and recovery
  codes are also served in section 13 shapes next to the v1-shaped `/auth/*` routes;
  `POST /security/recovery-codes/regenerate` returns the new codes once, the only secret this API returns, as the
  auth route does.
- **Pipeline counts** come from the rollups by reason code (`metrics/read_protection.py CHECK_REASONS`, pinned by a
  test against `PIPELINE_ORDER`); `other_refusals` counts refusals no abuse check produced. Tarpit statistics, the
  bot tracker and the spam and pipeline blocks that one worker holds are labeled `this_worker`.

#### Overview, traffic, endpoints, live, cache and the event stream (P9; `admin/api/`, `admin/sse.py`)

Code: `admin/api/overview.py`, `traffic.py`, `endpoints.py`, `live.py` and `cache.py`, the stream `admin/sse.py`;
read models in `metrics/read_dashboard.py` and `cache/read_browser.py`.

Plan conflicts:
- **Cache purges are audited first (9.7 "every mutation audited" against C7 "metrics degrade open").** A purge is a
  mutation: its `cache.purge` audit row is written before it acts, and the purge is refused with 503 when control.db
  cannot take the row; refreshes write `cache.refresh` first.
- **No dashboard refresh of credential entries (C1, P1).** Entries fetched with the credential are purged, never
  refreshed from the dashboard; other entries refresh through the real cache path (peek, then serve), so they pay
  their way in the buckets and join fetches in flight, as internal purpose `admin_cache_refresh`, never counted as
  caller demand.
- **Event stream bounds (P9, C6).** They are module constants (`MAX_STREAMS_PER_SESSION` 6, `HEARTBEAT_S` 15,
  `BACKFILL_MAX` 500, `KPI_INTERVAL_S` 2 and others), and the per-session cap is counted fleet-wide through
  self-expiring hot.db slot leases, with a per-worker count while hot.db cannot be written.
- **Rows 116 and 117** are served by `GET /protection/refusals` and `GET /upstream/retries`; Traffic has no duplicate
  routes.
- **The Live `before` cursor stays exact (the per-worker ring against the shared table).** This worker's ring rows
  are merged only when the shared scan is exhausted and the page has room.
- **Overview recommendations are read only** and degrade open when the engine or its table is unavailable; the
  hour-granularity heatmap is bounded to the last `MAX_POINTS - 1` hours with a notice (P9).

Deviations:
- **Live updates over Server-Sent Events (rows 81 and 90).** `GET /admin/api/v1/stream` replaces v1's polled JSON,
  and a stream on any worker sees every worker's requests and events (v1 bugs B16 and B17). A session that expires
  mid-stream gets an `unauthorized` event and the end of the stream (a status line cannot change once streaming
  began), the reconnect gets a real 401, and since the integration the browser client stops for good and shows the
  sign-in overlay. A resume by `Last-Event-ID` replays at most 500 rows and then sends `gap`, which the live tail
  shows as "some missed while reconnecting". Above 50 live rows a second a stream samples, and the `kpi` frame
  reports how many rows were sampled out or lost. nginx already has `proxy_buffering off` and a 100 s read timeout on
  the stream location.
- **Capture detail** tells "never captured" (404 `not_captured`, v1's capture-off text) from "expired" (404
  `capture_expired`, v1's exact text; row 128).
- **Cache.** Adding or removing an ignored parameter purges only the entries keyed with it (v1 emptied the whole
  cache); adding or changing a cache rule purges the entries it now covers unless `purge: false`; the browser sorts
  both ways, and a pattern purge honors the glob or regex type chosen (v1 cache bugs 3 to 5); POST entries can be
  inspected and refreshed, because v2 stores the request body; handoff rows (` !flight`) are never shown. Refreshing
  a 429 marker, a credential entry, an entry caching no longer applies to or an entry whose key would change is 409
  `wrong_state`; purge all needs `confirm: true`.
- **Overview.** Tiles are windowed with deltas; v1's lifetime Roblox 429 figure (from `legacy_totals`) appears only
  as a baseline on the 429 rate tile; the status strip reports the credential's state, never its value, fingerprint
  or mask. The Visitors card counts a minute once it has closed, so it can be up to about 60 s behind.

#### Upstream, egress and credential (P9; `admin/api/`)

Code: `admin/api/upstream.py`, `upstream_limits.py`, `routing_rules.py`, `egress.py`, `rotator.py`, `credential.py`,
`credential_allowlist.py` and `lookup.py`; read models in `metrics/read_upstream.py`, `egress/read_state.py`,
`upstream/read_state.py`, `upstream/read_trace.py` and `insights/read_evidence.py`.

Plan conflicts:
- **The upstream state reset (6.8 "exact counts in the audit entry" against one transaction).** The reset lives in
  hot.db and the audit row in control.db: the reset runs first and the audit row records the exact counts; if
  control.db stays busy the reset stands (reversible state, not data) and the answer says so in `warnings`. A reason
  is required.
- **`identical_anonymous` only from CRED-UNUSED evidence (6.2 and 6.9 against 11.5, whose action is a removal).** The
  API sets the flag only with a `recommendation_id` naming an open or snoozed CRED-UNUSED recommendation whose change
  names the row (id or pattern); the evidence id and sample size go into the audit reason. Clearing needs no
  evidence, and create never sets it.
- **The credential allowlist (D1 and C1 against the DESIGN 13 sensitive list).** Creating or changing a row sends the
  owner's account for callers, so it needs a fresh second factor and a reason; deleting a row only narrows the grant,
  so session and CSRF are enough (never slowed in an emergency).
- **"Check credential" needs a fresh second factor (9.6 list against the account budget, 13.3).** It spends a call on
  the account, as a health run with H-CRED-AUTH does.
- **Bytes per request (8.5) from aggregates.** Per-call sizes are not kept, so the histogram counts calls by the
  average bytes per call of each rollup row (one minute or hour of one endpoint) and says so.
- **"Why did this request wait" (7.12) is inferred.** The trace object is not kept per request; the explainer works
  from the Live row (15 minutes), the 429 log (90 days) and the minute bucket history, and labels the binding bucket
  as inferred (`upstream/read_trace.py`).
- **Rotator projection (8.4 names no formula).** 0.7 x the trailing 7 complete UTC days' mean plus 0.3 x this cycle's
  average, with a 90 percent band of `1.6449 x s x sqrt(r + r^2/n)`, no band under 2 complete days and a low end
  never below what is used; cycles and days are UTC, as for the rotator's hard stop (`egress/read_state.py`).
- **Exit IP reveal (row 32 privacy with 9.7).** Revealing exit IPs is audited (`egress.exit_ips_reveal`) and fails
  closed (503) when the audit row cannot be written, like an export; the probe answer shows the exit IP masked.
- **The provider byte figure (C7 across two databases).** It is stored in metrics.db, then audited; when the audit
  row cannot be written the figure is deleted again and the answer is 503, so no unaudited figure feeds
  EGR-CALIBRATE.

Deviations:
- **Typed C1 phrases.** A credential replace needs `replace the credential`; an account switch after deleting the
  dashboard value needs `switch to the other account` (case and spacing ignored); the warning texts come with
  `GET /credential`.
- **A probe right after a replace or a dashboard value delete** (one call on the reserved probe bucket), so the
  account fingerprint is recorded or compared at once; the request waits at most 40 s and answers `pending` while the
  probe finishes in the background.
- **Re-enabling an egress the leak guard tripped** needs a fresh second factor and a reason (409 when it is not
  tripped).
- **The place lookup is a POST with CSRF,** because it spends upstream budget: a non-numeric id is 422 `invalid_id`,
  a Roblox failure 502 `upstream_failed`, and v1's throwaway place warning is computed on the server (`notes`).
- **An invalid rotator URL is 422 `invalid_url` without quoting it;** since the integration the API catches only
  `egress/rotator.py RotatorUrlError`, never any `ValueError` whose message could hold the URL.
- **Bounds are module constants** (`MAX_SERIES` 20, `MAX_EVENTS` 500, `MAX_EXITS` 100, `MAX_BUCKETS` 500,
  `MAX_COOLDOWNS` 1000, `PROBE_TIMEOUT_S` 40, `TRAILING_WEIGHT` 0.7 and the others listed in each module).

#### Recommendations API and route security (P9 assembly)

Code: `admin/api/recommendations.py`, `insights/read_recommendations.py`, `admin/api/__init__.py`, `admin/router.py`;
test `tests/security/test_admin_routes.py`.

Plan conflicts:
- **Apply only what was previewed (11.3 "applies atomically" and P4 "exactly as previewed").** Apply needs the
  previewed `changes_digest` (409 `changed_since_preview` otherwise); the engine's compensation stays the atomicity
  mechanism (see the insights engine below).
- **A fresh second factor for security changes (9.6 list against recommendations; stricter, never looser).** Applying
  or undoing a change to an `admin_security`, `credential` or sensitive setting, an `allow_admin` row, or a
  credential allowlist row that exists after the write needs it. The direction matters: undoing an allowlist removal
  recreates the row.
- **"Export of full data" and "factory or full data reset" (9.6).** The first is the LLM export's `detail=full`
  (12.2), and per-dataset exports stay at session level (row 88); the second is the factory route, while the
  `everything` scope deletes statistics only and stays at session level with its typed phrase and preview digest.
- **Public exceptions are listed by name (19.7 "/csp-report the single exception" against the login surface).** The
  route security test lists 8 unguarded routes with reasons (`/csp-report`, the login page, the 4 login steps, the
  kill-switch GET and POST) plus the enrollment routes, and exactly 20 fresh second factor routes; a new unguarded or
  fresh second factor route fails the test until it is listed.
- **Dry runs (11.3 "last 1 h, or 24 h up to `request_sample_hours`"; P9 and the loop rule against a pure-Python
  simulator).** Windows are `1h`, `6h` and `24h`, capped by the simulator; a replay runs on a worker thread with its
  own event loop, one per worker with 4 waiting (a fifth gets 429), and a result is reused for 60 s, 32 at most.

Deviations:
- A high-risk value in a recommendation needs `confirm_high_risk` and a reason, as in the settings editor; a
  recommendation without changes is 422 `nothing_to_apply`; undo after a later change of the same key is 409
  `superseded`; snooze takes `1h`, `1d`, `1w` or an `until` at most 90 days ahead; dismiss takes a reason
  (`not_accurate`, `intended_behavior`, `will_handle_manually`, or `other` with a text). Every setting value shown
  passes through the settings API's redaction.

#### Insights engine (P10; `insights/`)

Plan conflicts:
- **The users batch card has a fourth change (11.6 against 15.3 D, where `cache_post_requests` is an enum).** It
  moves `cache_post_requests` from off to `allowlist`, never `all`; the fixture states it and the lead accepted it
  (LEAD_NOTES).
- **CACHE-TTL-TUNE when lowering (11.5 "set TTL to the median observed change interval").** Samples fetched at the
  TTL spacing cannot show a shorter interval, so the rule proposes the lifetime at which, with random (Poisson) body
  changes, the identical share reaches `identical_lower_pct`: `ttl x ln(1/q) / ln(1/p)`. At the default 50% this is
  the Poisson median the plan names, always below the current TTL.
- **SYS-ERRORS (11.5 "7-day hourly baseline" against the catalog's "usual count for that hour of the day").** The
  baseline is the hourly mean over the 7 days before the last hour (from `first_seen` when younger); a known
  signature silent for the whole baseline that comes back fires; "caller-facing 500s" are `internal_error` only.
- **Atomic apply by compensation (11.3 against DESIGN 4 and 5).** Each service write is its own control.db
  transaction and duplicating their write logic is forbidden, so apply validates everything first, applies change by
  change through the audited services and reverts the applied ones in reverse order on any failure; a single
  transaction needs the deferred `*_in(conn, ...)` service variants.
- **The auto-apply step limit also bounds rule values (11.4).** `auto_apply_max_step_pct` applies to numeric rule
  values too (bucket `per_min`, cache rule `ttl`, endpoint rule `limit` and `period`); bypass entries, the credential
  allowlist and bans wider than one address are never auto-applied.
- **Error occurrences go to the new `error_minute` table,** not to `events` rows of type `error` (the fixture README
  allows an owning module to add a table).
- **The 7.3 "highest 429-free sustained rate"** is the highest per-minute call count held for 5 consecutive minutes
  without a Roblox 429 (`insights/rules/core.py SUSTAIN_MINUTES`), then 80% of it.

Deviations:
- **metrics.db schema 2 (`0002_insight_history.sql`).** Nine tables: `bucket_minute`, `worker_minute`,
  `cache_minute`, `cache_eviction_passes`, `rule_hits`, `error_minute`, `upstream_attempt_minute`,
  `egress_provider_reports` and `recommendation_watches`, pruned by the leader job `insights_history_prune` (minute
  tables by `retention_minute_days`, idle `rule_hits` rows after `retention_hour_days`, `error_minute` 8 days,
  eviction passes 14 days, provider reports 400 days).
- **Lifecycle.** A rule switched off leaves its open recommendations until they expire; a dismissed or rolled back
  fingerprint stays quiet for `dismiss_cooldown_days` unless its severity rises; an applied one stays quiet during
  its watch window; an expired one re-opens if it is still true. Every state change is an `events` row of type
  `recommendation` in the same transaction (the stream's `recommendation` kind); a burst over 500 per run becomes one
  `bulk` event.
- **UP-429-ENDPOINT** is critical when callers saw failures and warn when stale serves hid every 429 (11.5 gives no
  severity); a proposed SWR window is `max(cache_swr_seconds, 20% of the TTL)` (11.6: 600 s with 120 s); a rule's own
  TTL 0 ("never cache") is never changed by CACHE-TTL-TUNE or UP-429-ENDPOINT.
- **Anomaly constants** (15-minute blocks against the previous 24 h, z of at least 4) are module constants; no rule
  fires on them directly.
- **Events.** A new `credential_probe` event per credential probe; `internal_call` events carry `trigger` and the
  credential `egress`.
- **Fixture harness.** The recorder's own request sampling is off except for the PLACE-HEAVY and THROTTLE-TUNE
  fixtures (`tests/insights/harness.py RECORDER_SAMPLED_RULES`), no Live rows are written while loading, and day and
  month egress usage buckets are floored in UTC.

#### Recommendation rules (P10; `insights/rules/`)

Every threshold is read through `self.param` from `config/insight_params.py` (an AST test refuses any other number in
a rule comparison); look-backs and remedy arithmetic the plan does not give are module constants with docstrings.
Where the 11.5 table and the 15.3 J2 catalog disagree, the catalog wins (0.2 item 7).

UP-* rules (`rules/upstream.py`, `providers_rules_upstream.py`):
- **Thresholds and windows.** Every `min_*` parameter is an inclusive minimum (11.5 says "> 20" and "> 5", the
  catalog says "how many fire the rule"), while rates, percentages, `calls_per_request` and `openings_per_hour` must
  be exceeded. Rows without a window parameter look back 24 h (UP-429-CREDENTIAL) or 1 h (UP-429-AMPLIFY,
  UP-QUEUE-SAT, a too-loose UP-BUCKET-TUNE, UP-BREAKER-FLAP). UP-UA-EXPERIMENT gives no card below its minimum
  sample, compares the arms with a two-proportion z of at least 1.96, does not use `ua_experiment_days` as a gate and
  stays quiet when the current User-Agent already wins.
- **Signal readings.** UP-RETRYAFTER-IGNORED's advertised time is each Roblox 429 plus its Retry-After clamped to the
  cooldown bounds, plus every active endpoint cooldown, counted per client and cache key on samples that made no call
  and served nothing (a lower bound below 100% sampling; the evidence shows `request_sample_pct`). UP-429-AMPLIFY
  divides upstream calls by the caller requests that went upstream in the 429 minutes of the last hour. UP-LATENCY
  reads the latency of caller requests that went to Roblox, queue wait included; "queue wait dominates" means the
  queue p95 is at least half the latency p95. UP-4XX-SPIKE subtracts failed CSRF second 403s and reads a 7-day hourly
  baseline.
- **Remedies.** UP-429-HOST lowers the host bucket to
  `min(80% of the server-IP call rate in the 429 minutes, the adaptive_decrease_pct cut)`, floored at
  `adaptive_min_per_min`, and shifts load only through per-template `prefer_rotator` routing rules, when the rotator
  is available and its 429 rate is lower. UP-429-CREDENTIAL lowers `credential_bucket_per_min` by
  `adaptive_decrease_pct`, above the probe reservation, and reads "works anonymously" as the row's
  `identical_anonymous`. UP-4XX-SPIKE blocks the endpoint when rejections are mostly 401 or not GET (7.7
  negative-caches only 400, 403, 404 and 410). UP-5XX doubles the effective SWR window, because a `stale_ttl` of 0
  already serves `cache_swr_seconds`. UP-CSRF-LOOP lowers `csrf_token_cache_s` (back to its default, else halved), or
  blocks an endpoint whose retries never succeed. UP-CHALLENGE's change is the routing rule, manual when no other
  anonymous egress is available. UP-TIMEOUT raises `request_timeout` 1.5 times inside the plan 5.2 owner deadline,
  and for the rotator halves `rotator_weight`, then steps `rotator_session_mode` toward `per_request`. UP-BUCKET-TUNE
  applies the 7.3 attribution thresholds over the 429 log. UP-BREAKER-FLAP doubles the global `breaker_open_s` (there
  is no per-key open time) up to `breaker.MAX_OPEN_S`. UP-LATENCY and UP-QUEUE-SAT raise a bucket only through
  UP-BUCKET-TUNE's clean-hours test, never as a latency fix alone.
- **Severities and limits.** Critical: UP-429-CREDENTIAL; info: UP-RETRYAFTER-IGNORED, UP-UA-EXPERIMENT and a
  too-tight UP-BUCKET-TUNE; warn: the rest (11.5 gives none). Only UP-BUCKET-TUNE is `safe_auto`, and while
  `adaptive_rate_enabled` is 1 the buckets the controller manages are left alone. At most 5 endpoints change per
  UP-LATENCY or UP-QUEUE-SAT card and at most 20 UP-5XX cards are made; cache rule changes cover the endpoint's
  dominant method, POST only when `cache_post_requests` is not off. UP-UA-EXPERIMENT arms are estimated from request
  samples (`source: request_samples`) until a per-arm counter exists. Parity row 77: UP-BUCKET-TUNE cards show the
  hourly fill history (attempts, rejections, peak fill).

Cache, egress and credential rules (`rules/cache.py`, `egress.py`, `credential.py`,
`providers_rules_cache_egress.py`):
- **Cache.** CACHE-LOW-HIT's ratio is `served_cache / demand` (a request served while the cache is off is a miss).
  HOT-ENDPOINT means "in the top N now with no rule", GET only. CACHE-KEYSPLIT proposes `ignored_param_add` only for
  buster-shaped parameters that are not ids, sorts id lists through a rule flag, and never proposes ignoring a text
  or id parameter (a manual card instead); it covers parity row 65. CACHE-NEG counts only keys sampled more than once
  (P6). CACHE-PRESSURE doubles the binding cap, bytes bounded by half the free disk.
- **Egress.** EGR-BURN aims at the `projected_pct` line (the rotator weight first, the daily cap when the weight is
  0). EGR-UNDERUSE looks at 60 minutes and needs a quota (D12). EGR-CALIBRATE measures the gap as a percent of the
  provider's figure and gives a manual card in socket metering mode. HOST-ADD's distinct callers come from refusal
  events, so its text says "at least".
- **Credential.** CRED-EXPIRING reads the account warning from `credential_rotated` events and counts
  `account_mismatch` as rejected. CRED-PROBE-COST raises `credential_probe_interval_min` and switches
  `health_auto_include_credential` off, instead of the plan's "lower `health_auto_interval_h`", which would add
  calls. CRED-UNUSED reads the new event type `credential_comparison`
  (`{endpoint_template, method, anon_status, cred_status, identical}`), which nothing writes yet, so it stays quiet
  in production. No rule bans anything, and no egress rule moves, lists or routes the credential.

Abuse, filter, system and security rules (`rules/abuse.py`, `system.py`, `security.py`,
`providers_rules_abuse_system.py`, `metrics/read_caller_facts.py`):
- **ABUSE-SPAM proposes a temporary ban, never arming (11.5 "enable detector action" against SEC-DEFAULTS and
  10.3).** Arming means `spam_dry_run` 1 to 0, a value SEC-DEFAULTS flags as high risk; the rule proposes a scoped
  temporary ban on the one address and points at arming through the collateral preview. A place subject gets a manual
  card, never a ban.
- **Readings.** Bot score bounds are inclusive (`bot_score_abuse_min` "at or above", `bot_score_legit_max` "at or
  below"), while the request count keeps 11.5's strict ">". FILTER-COLLATERAL removes the filter and names the
  narrower replacement in its text, because Roxy cannot know a narrower pattern. SYS-WORKER-SAT shows open
  connections as evidence only (11.5 names no limit). SYS-DISK uses `dims_per_minute` as a fourth condition.
  ABUSE-DIST skips swarms whose scored clients are all at or below `bot_score_legit_max`, and says so when it cannot
  rule out game servers.
- **Fixed readings (module constants).** ABUSE-SPAM and ABUSE-DIST look back one hour; "repeated auto-bans" is 2
  within 30 days with the newest under a day old; ABUSE-BOT and FILTER-ADD bans last one day; FILTER-COLLATERAL
  measures the last hour; FILTER-REMOVE's "top legitimate place" is the top 10 by served requests in the day before
  the ban; the bypass expiry the rules propose is 30 days; TARPIT-TUNE's "unchanged gap" is less than 50% longer;
  THROTTLE-TUNE's "a few" is 3 clients and "most" more than half, over one hour for too loose and 24 h for too tight,
  loosening by 50%; PLACE-HEAVY's endpoint rule counts per 60 s; SYS-DISK halves the retention of the largest table
  and projects 30 days; SYS-METRICS-DROP doubles the queue or halves the flush interval; SEC-ADMIN-ALLOWLIST networks
  are IPv4 /24 and IPv6 /64.
- **Data.** Upstream use per place and per client comes from `request_samples` (requests that reached Roblox, retries
  not counted), because no rollup has a place or client dimension; FILTER-ADD evidence shows refusals per hour and
  the top endpoint, not refusal reasons per client; THROTTLE-TUNE counts any refusal of a legitimate client as
  throttled. Every rule of this group has `safe_auto` false.

#### Check Proxy Health (P10; `health/`, `admin/api/health.py`)

Plan conflicts:
- **A private H-DNS answer fails (13.2 over 9.10, which calls it a warning).** 13.2 defines the check; the fixture
  author made the same reading.
- **A manual run that includes H-CRED-AUTH needs a fresh second factor (13.1 "manual runs include credential checks"
  against 9.6 and 13.3).** A run without the credential check does not; scheduled runs include it only with
  `health_auto_include_credential` 1.

Deviations:
- **Thresholds are plan constants** in `health/checks.py` (the catalog has no health keys); every result stores the
  threshold it was judged against.
- **Readings** (full list in `.remake/wave3b_reports/health.md`): H-REACH fails a 2xx after 2000 ms or more, warns
  when the probe gets no bucket slot in time and when a 200 lacks the 13.4 JSON field; H-E2E reads "no Server header"
  as no header naming a version or the app server (nginx with `server_tokens off` always sends `Server: nginx`);
  H-NGINX requires HSTS on `/`, `/static/public/site.css` and `/admin`, no version in Server and a 404 for
  `/internal/version`; H-LEADER calls a last start more than 2 intervals ago late; H-WORKERS counts fresh heartbeats
  of the checking worker's color; H-LOOP-LAG reads the heartbeat's p99 (there is no 5-minute history);
  H-ROTATOR-REACH has a 2000 ms slow edge; H-ROTATOR-QUOTA works in decimal GB and is n/a with quota 0;
  H-ROTATOR-SESSION warns when a session id changes exit; H-CLOCK compares with Roblox's Date header; H-CONFIG fails
  on errors and warns on unknown stored keys; H-BANS names bans by id, never an address; H-BACKUP without a record
  fails in production; H-SECRETS-PERMS reads both the plan shape and the file `deploy/tools/roxy-audit.py` writes;
  H-VERSION reads `/var/lib/roxy-deploy/deployed_version`.
- **n/a in development:** H-SYSTEMD, H-E2E, H-NGINX and H-TLS-PUBLIC. A check that times out fails; a check that
  raises warns.
- **Runs.** One run at a time fleet-wide (lease `health:run`, 409 `run_in_progress` with `Roxy-Health-Run`);
  scheduled-run alerts compare with the previous scheduled run, so a manual run in between never hides a new failure
  (alert `health_failures`, one cooldown key per failing set); the run events use the keys `passed`, `warned` and
  `failed`, because a key named `pass` read as a secret field; reports are JSON, printable HTML (escaped, nonced) and
  an LLM copy, each audited before it leaves.
- **metrics.db schema 3 (`0003_health_details.sql`):** new `health_runs` and `health_results` columns, two indexes
  and the `health_job_status` table, where the leader publishes job status every 30 s.

#### LLM export (P10; `insights/llm_export.py`, `admin/api/export_llm.py`)

Plan conflicts:
- **Long texts span entries (12.3 "truncated to 200 characters" against "full objects (11.2)").** Explanations,
  expected impacts and health findings span up to 20 consecutive 200-character entries, each obeying the rule, so the
  object stays complete.
- **All admin free text is untrusted (12.3's list of caller strings against section 9 and 12.5 rule 0).**
  Recommendation texts embed endpoint templates, and admins paste attacker text into rule patterns and notes, so
  those become references too.
- **One dated copy per UTC day (12.2 "dated copies kept 14 days").** Kept `retention_exports_days`, instead of 336
  hourly files on the 909 MB server; the hourly file covers 7d at full detail (summary above 32 MiB).
- **Raw IP addresses always need a fresh second factor (9.15 and 12.4 against 12.2).** Only the full detail shows
  them, and only with `export_include_ips`.
- **C4.** The rotator appears as its host name only (an IP literal host is null), workers by pid and color, and admin
  allowlist entries are counted, never listed.
- **Missing sources (P6).** `capacity.metrics_pipeline` is the building worker's counters, labeled
  `this_worker`. (The `top_clients` bot score was null until the producers lane recorded scores; since review
  round 3 it is the recorded plan 10.7 score, 0 to 100.) The code map lists public
  classes and methods too, with a `kind` (12.3 says "public functions"). The schema is committed as
  `insights/schema/llm_export.v1.schema.json`, and a test checks it equals the models.

Deviations:
- **Two details.** The summary lists overridden settings, changed rule configuration, open and snoozed
  recommendations without evidence details, non-passing health results and non-covered parity rows, with shorter
  lists, no error samples and no code symbols; the full detail needs a fresh second factor. `format=text` is the 12.5
  block, a blank line and the JSON; `download=true` adds an attachment name; `GET /export/llm/schema` serves the
  committed schema. Every answer writes `export.download` (target `llm_export:<detail>`) before it leaves (503
  otherwise); more than 2 builds in a worker is 429.
- **Trust rule.** Outside `untrusted` a string is one of Roxy's own words or a token that cannot carry words;
  anything else becomes `{"untrusted_ref": "uN"}` with an entry `{id, kind, untrusted_text, length, truncated}`
  (redacted, IPs hashed, controls escaped), and equal texts share one entry.
- **Additions.** `top_clients.ips[].user_agent` (the newest User-Agent of the address in the last 15 minutes);
  `potential_issues.rule_zero_hits` only for tables that record hits (today `rules_user_agent`). "Copy run for LLM"
  stays in `health/report.py`, and the export imports its instruction block and escaping, so there is one copy of
  each.

#### Wiring, storage and the request path (integration; `lifespan.py`, `proxy/router.py`, `metrics/`)

- **Fingerprints are recorded in production (parity rows 79 and 134).** Every request that passed every check is
  fingerprinted, and a request filter's refusal counts as a blocked fingerprint; before, nothing called the recorder
  (`proxy/router.py note_fingerprint`).
- **Request samples carry the hash of the body fetched from Roblox** (served upstream, at least one call, 2xx; the
  first 16 hex characters of its SHA-256), not the POST request body's hash, so the TTL tuner sees real body changes
  (`proxy/router.py fetched_body_hash`).
- **`spam_dry_run` is switched off only through `POST /protection/spam/arm` (plan 10.3).** The settings editor,
  `PUT`, revert and import refuse it with 422 `confirmation_required` (`admin/api/settings.py ARM_ONLY_SETTINGS`);
  turning it on and resetting it to its default stay allowed.
- **One action at a time per recommendation.** Apply, undo, snooze and dismiss hold the fleet-wide hot.db lease
  `insights:action:<id>`; a second request gets 409 `wrong_state` (`insights/actions.py`).
- **One place lookup cache per worker,** shared by `/lookup/place`, `/clients/lookup` and the Clients tables
  (`upstream/internal.py place_lookup_for`).
- **The environment summary no longer names the credential file (C1, plan 19.5 item 7).** It reports
  `credential: {bootstrap_file, dashboard_value, in_use}` from the credential manager (`admin/api/system.py`).
- **Credential probes record their trigger** (`scheduled`, `health`, `admin`, `upstream`) on the `internal_call`
  event, so CRED-PROBE-COST can tell them apart (`upstream/service.py PROBE_TRIGGERS`).
- **Worker and cache history are recorded in production.** Each heartbeat records the worker minute (CPU share of one
  core, loop lag p99, RSS), and each cache maintenance pass records its young evictions and their ages
  (`scheduler/heartbeat.py`, `cache/store.py`, `metrics/recorder.py record_eviction_ages`).
- **Event details are always valid JSON.** When redacting the serialized text would break it, the detail is scrubbed
  value by value, and a value under a secret-shaped key becomes `[redacted]` (`metrics/recorder.py _scrub_detail`).
- **The per-IP limiter holds its time across a wall clock step back** (`abuse/pipeline.py steady_now_ms`): a step
  back (NTP, WSL's 0.9 s steps) inside a burst no longer refuses the rest of an allowance GCRA granted; a forward
  move is taken at once.
- **The `settings_reloaded` log line carries `monotonic_s`** (CLOCK_MONOTONIC, one clock for every process of a
  host), so the time a change takes to reach each worker can be measured while the wall clock steps
  (`config/runtime.py`).
- **Job status shows a bounded last result** (`scheduler/jobs.py MAX_RESULT_CHARS` 2000, else
  `{"truncated": true, "chars": n}`).
- **Leader jobs.** `insights_evaluate` (every `insights_interval_s`, off while `insights_enabled` is 0),
  `insights_triggers` (5 s), `insights_history_prune` (600 s), `insights_anomalies` (300 s), `insights_watch` (60 s),
  `insights_auto_apply` (a no-op while `insights_auto_apply` is 0), `health_scheduled_run` (a 300 s poll while
  `health_auto_interval_h` is above 0), `health_publish_jobs` (30 s) and `llm_export_file` (3600 s); every worker
  runs `admin_requests_watch` (1 s). Intervals are read before every scheduling decision, so a settings change
  applies without a restart.

#### Review round 3: admin API security and bounds (2026-10-09; findings apisec-1 to 9, mpjobs-5)

The review of wave 3b filed 54 findings; the entries of this and the next five subsections are the fixes, the lane
work and the deviations they brought. Reports: `.remake/wave3b_reports/r3_fix_*.md`, `lane_*.md` and
`r3_integrate.md`. Where they differ from the entries above, these win.

- **Settings that guard the admin need a fresh second factor (apisec-1; plan 9.6, stricter, never looser).**
  Changing any `admin_security` or `credential` setting, a sensitive one, or `export_include_ips` through the
  settings editor, PUT, reset, revert or import needs a second factor entered within `admin_reauth_window_s` (403
  `reauth_required`), as applying a recommendation did; a stale session can no longer raise the window or switch
  the admin allowlist off. Previews and editor entries say which keys need it, and recommendations use the same rule
  (`admin/api/settings.py needs_fresh_mfa`).
- **Exports never carry a client address while `export_include_ips` is off (apisec-2; plan 9.15, 12.3).** Every cell,
  not only IP columns: an address in free text (spam subjects, event details, audit targets and previews) becomes
  `ip:<keyed hash>`, the same hash its IP column gets. A version after a product name (`Chrome/120.0.0.0`) is left
  alone; any other quad or colon form that parses as an address is replaced (privacy first).
- **A wrong method on an admin path no longer reveals it (apisec-3; D6, plan 9.5).** Anyone without a signed-in admin
  session gets the missing path's 404; a signed-in admin gets 405 `method_not_allowed` with `Allow` (a section 13
  object; it was FastAPI's `{"detail": "Method Not Allowed"}` for everyone). `/admin` itself is covered too
  (`admin/router.py`).
- **High-risk Protection settings need the confirmation (apisec-4).** `PATCH /protection/settings` and the
  throttle-all limit and period need `confirm_high_risk` and a reason, as in Settings (422
  `confirmation_required`).
- **Table downloads are bounded (apisec-6, mpjobs-5; plan P9, DESIGN.md section 0).** At most 2 downloads build at once
  per worker (429 `rate_limited`, `Retry-After: 5`); a file is at most 16 MiB as well as 50,000 rows (the rest is left
  out and `Roxy-Export-Truncated: true` and JSON `truncated` say so); every table and dataset download reads one page
  at a time and streams the file (one 50,000-row audit download peaked at 17.7 MiB instead of about 270 MiB).
  Deviation: before, a download could be as large as its rows made it; the cap is a module constant (lead decision on
  safety bounds), and a filter or a narrower range exports the rest.
- **Huge ids are 422, not 500 (apisec-7).** Integer path ids above 2**62 (routing rules, credential allowlist rows,
  cache rules, health runs and their `with`, passkeys, trusted devices) and the Live `before` cursor are 422
  `validation_failed`; no error alert fires.
- **An open event stream ends when the admin allowlist shuts its network out (apisec-8; D6),** within a quarter
  second of the change reaching the worker, without a further frame.
- **The mount checks refuse the enrollment guard outside enrollment (apisec-9).** A route guarded by
  `require_admin("session", allow_bootstrap=True)` refuses to start the app unless it is an enrollment path; the
  route security test lists such routes (`bootstrap`).

#### Review round 3: numbers, pages and resets (parity lens and the parity table; findings parity-1 to 15)

- **Who returned a Roblox 5xx (parity-1).** A Roblox 5xx passed on after the retries counts as "5xx from Roblox"
  (Overview, Traffic, upstream cards); "5xx from Roxy" counts only Roxy's own failures (new measure `roxy_5xx`). In
  the "Who returned it?" table and the source chart such answers are "Roblox to caller (relayed)". The reading is in
  the read model (`metrics/queries.py ANSWER_SOURCE_SQL`), so rows recorded earlier are read correctly too.
- **Overview: "Failures (last hour)" (parity-2, v1 tile 11),** right after "Requests (last hour)", with the hour
  before as its delta; the live stream carries it too. Deviation: it counts failed outcomes (Roxy could not answer),
  not refusals and not Roblox's own 4xx answers; v1 counted any non-200 Roblox answer as failed, v2 relays a Roblox
  4xx as an answer (it is in the 4xx tile).
- **KPI deltas over a reset (parity-12, plan 6.8).** A tile whose own data was reset in its window or comparison window
  shows the reset notice and `partial: true` and no delta (the two last-hour tiles included); resets of other
  families leave tiles alone, because reset markers now name what they deleted (metrics.db schema 6,
  `annotations.reset_tables`); a marker without that list still blanks every delta in its window (the safe
  reading).
- **Protection > Refusals has v1's columns (parity-3).** Status (newest), Last path, Unique clients (distinct hashes,
  a lower bound with an unattributed count), First and Last seen; it is a paged, sortable, exportable table (a shape
  change from `{range, items}`). v1's "Last IP" is replaced by the client count (plan 9.15).
- **Throttle-all watch has v1's columns (parity-4, row 135):** Requests, Refused, Rate 1/5/60, Top endpoint and Last
  seen, counted from the minute throttle-all was switched on (the drops-since rule); an IPv6 network key shows them
  empty (activity is per address).
- **Upstream: v1's Request Failures log (parity-5, rows 24 and 72)** at `GET /upstream/failures`. Rows folded over the
  recorder's event budget keep their reason, count and (since the integration) egress, but not path or error.
- **Upstream: method health per egress (parity-6, ptable-5, row 71).** Cards and host rows show Failed, last success,
  last error time and the last error. Deviation: the times have minute (or hour, said so) precision and cover
  everything kept, not only the range; the exact time is in `last_error.at_ms`.
- **Clients (parity-7, row 73).** Tables show Last seen (to the minute, coarser for compacted data) and the peer
  count ("Places" for an IP, "IPs" for a place); client pages list the peers. A new `pair` client row type is
  stored and capped like IPs (at most `max_ip_activity_records` extra rows per bucket); peer counts are lower
  bounds under a flood.
- **Endpoints (parity-13, row 74).** Rows show Methods, Last request (exact while its Live row is kept, else the
  minute), Last status, Last caller and Last place; status and caller are known only while the newest request's Live
  row is kept (15 minutes).
- **Security (parity-11, parity-14, rows 79 and 134).** v1's "Clear values" and "Remove" per header, and "Remove" on
  the Blocked tab, are routes again, audited first; the Blocked tab is exportable. "Clear values" does not exist on
  the Blocked tab (blocked requests keep no values). This supersedes the parity table's "no per-header fingerprint
  clear" reading.
- **Cache: "Purge matching" purges exactly what the browser search lists (parity-15, v1 bug 4)**, with one shared
  condition (`scope: search`).
- **The cache statistics reset keeps the requests (parity-8)**; see "Settings, audit, preferences, data, export and
  system" above. After it the hit ratio reads null until new lookups, and the cleared lookups show as cache state
  `cleared`.
- **Clearing one v1 attempts tab keeps the others (parity-9)**: the five narrower families and the two "nothing to
  reset" targets of the clear-target table above.
- **Retention view (parity-10).** Every setting of the Data page's retention and record cap cards is listed with its
  card, and every bounded table appears with the limits the code sets (fixed ages and caps, the audit log's 400 day
  minimum) and hot.db idle limits (never reported as pruning due).
- **Reset fences (parity-4 of the parity table, v1 `ClearEpochs`).** A counter that was reset is never refilled by
  numbers a worker gathered before the reset but had not flushed yet: each worker drops (or, for latency and cache
  statistics, rewrites) its unflushed items of the reset family in its next two flushes. At most two flush intervals
  (4 s by default) of other workers' counts of that family are lost around a reset; the control.db key
  `metrics_reset_fences` holds the latest 16 resets.
- **Reset flow (mpjobs-4).** The chart marker is written before anything is deleted; a reset that fails after
  deleting keeps it, labeled "Data reset (incomplete)" and linked to `data.reset.failed`; one that deleted nothing
  leaves none. Only resets that delete counters mark `reset`; state resets (bans, cache entries, limiter, upstream,
  recommendations, health history) mark `config_change` (P6). Families also cover the producer tables: tarpit
  `tarpit_minute` and `tarpit_hold_minute`, activity `client_score_hour`, "everything" the rest; a single client
  reset covers its bot scores and its `pair` rows; rule hit history is in no family (deleting it would make
  FILTER-REMOVE read a filter as never hit).
- **Security > Probes lists probes through the proxy route (ptable parity-2, rows 51 and 80).** Signatures `Non-Roblox
  URL` and `Invalid URL` (the probed URL in the target column), `Host not allowed` (new in v2, the URL in the path
  column) and `Sent a ROBLOSECURITY token (<where>)`. Deviation: when the marker was in a header value, v1 named the
  header (`"<Name>" header carried ...`); v2 logs `a header carried a ROBLOSECURITY-shaped value`, because a header
  name is caller text and as a signature it would give every name its own summary row and event budget (v1 B19).
- **`POST /` is v1's instant 405 again (ptable parity-1).** `POST /` (and PUT, PATCH, DELETE and any other method
  except GET, HEAD and OPTIONS) answers 405 with `Allow: GET, HEAD, OPTIONS` and a JSON body; it is no longer a
  `not_roblox` proxy refusal (never tarpitted, not counted as proxied, no `Roxy-Refusal`, no spam probe count), and
  the probe log shows `HTTP 405 via POST` with target `/`. Deviation: the body is FastAPI's standard `{"detail":"Method
  Not Allowed"}`, as every other v2 405, where v1 sent the JSON string `"The method is not allowed for the requested
  URL."`.
- **Admin Page Visits counts again (ptable parity-3, rows 19 and 130).** A GET of `/admin` by a browser that never
  signed in counts one visit. New cookie `roxy_admin_counted` (1 day, `Path=/admin`, `Secure; HttpOnly;
  SameSite=Strict`, a visitor count marker). Deviation: a login takes back only a visit that browser made (v1
  decremented on every first login and clamped at zero), because v2 sums visits per minute and an unmatched
  decrement would cancel a real visitor.

#### Review round 3: recommendations, dry runs and the LLM export (findings insights-1 to 14, mpjobs-1 to 8)

- **Auto-apply (D7) respects a rule's off switch** and applies only proposals an evaluation refreshed within two
  evaluation intervals (insights-3); it never overwrites a value an admin changed after the evaluation: the apply is
  refused and the next evaluation proposes from the new value, so the 50% step limit is always measured from the
  live value (insights-4).
- **D7 rollbacks (insights-5, mpjobs-8).** A rollback that only has to wait (another action holding the
  recommendation, or a busy hot.db) is retried every watch pass and the window shows "rollback pending"; a rollback
  refused for good (for example an admin changed the row during the window) closes the window as kept with the
  reason and sends one critical alert, "Roxy: auto-applied change could not be rolled back". Deviation: a new row in
  the plan 17.7 alert table (type `auto_apply_rollback_failed`, runbook `auto-apply-rollback`), and no new watch state
  (the table's CHECK constraint allows only `watching`, `kept`, `rolled_back` and `canceled`).
- **Auto-apply and its watch are fenced by the leader lease (mpjobs-1, plan 5.6)**, and the auto-apply pass records an
  idempotency key per interval; a leader that stalled past its lease writes nothing, and a partial apply is put back.
- **Applying compares the previewed digest again inside the action lease (mpjobs-2)**: an evaluation that rewrote the
  proposal in between gives 409 `changed_since_preview`, and nothing is applied without its own confirmation or
  second factor. A busy hot.db during apply, undo, snooze or dismiss is 503 `unavailable` with `Retry-After: 5`
  (mpjobs-3; it was 409 `wrong_state`, which now means only that another action holds the recommendation). If an
  apply cannot be recorded, it is undone.
- **A host suggestion adds its host to the live list (insights-13)**: `host_add`, and every list setting a
  recommendation changes, is applied and previewed as a delta, so a host the admin removed after the evaluation is
  never put back.
- **The engine's early run after a Roblox 429 burst counts rows by arrival (insights-10)**, so a burst flushed late
  still triggers; **a recommendation left out by the 50 per rule cap stays open (insights-11)** while its rule still
  reports it.
- **Dry run (insights-6, 9, 14; plan 11.3, 19.10 row 11).** Answers the cache would not keep (5xx, 429, other statuses)
  are not stored in the replay, and 400, 403, 404 and 410 are kept for the error lifetime (the 11.6 card's dry run is
  2,455 avoided calls, not 2,485); below 100% sampling counts are scaled to all requests (`scale` in the preview;
  limits and buckets are thinned to the sample's share first, `parts` stay sample counts with `not_stored`); the
  per-IP limit replays `allowed_requests_per_minute` per `throttle_reset_duration`, as production does, and a
  THROTTLE-TUNE window change and a CACHE-NEG error lifetime change are dry-runnable. The per-IP replay keys by
  address while the limiter groups IPv6 by prefix, so it is a lower bound (open).
- **Request samples of POSTs the cache has off by `cache_post_requests` carry the key id the cache would use
  (insights-7)**, so the 11.6 dry run and the TTL tuner see repeats. Such a POST is treated like a cached POST for
  everything but caching: the User-Agent experiment assigns its arm per key (was per endpoint template), and a retry
  inside `Retry-After` is recognized per key, so per body (was per method, target and query; accepted by the
  integrator). Requests with the cache switched off, other methods and `cache_private` credential endpoints keep no
  key; CACHE-NEG leaves samples the cache had off out of its count.
- **Exact new rules (insights-8; plan 11.2 "scoped to one endpoint").** A new rule a recommendation proposes for one
  endpoint is an anchored regex (`^users\.roblox\.com/v1/users/?$`, placeholders `[^/]{1,512}`), not a v1 glob, which
  also covers every endpoint below it; this holds for every rule (cache, routing, endpoint block, endpoint limit), and
  a change that creates a pattern rule is `safe_auto` only when it names exactly one endpoint. Admin and older glob
  rules for a template are still recognized as its own rule. Deviation from v1's glob-only rules.
- **LLM export, stricter trust rule (insights-1, insights-2).** Text with free letters is referenced whatever its
  shape, a parameter name shaped like a rule fingerprint or a ULID included; only fingerprints of Roxy's rules stand
  inline, and Roxy's own ids only in their id fields; setting values in `potential_issues` are references like in
  `config`.
- **LLM export, bot scores and the event loop (producers lane, mpjobs-6).** `top_clients.ips[].bot_score` carries the
  recorded score (0 to 100 in the schema); a build cleans and splits all outside text on a worker thread and yields
  between recommendation batches (the event loop is no longer held 0.1 to 0.3 s by a full export).
- **H-CLOCK no longer counts the probe's bucket wait as clock skew (insights-12)**; a busy hour no longer reads as a
  broken clock, and the detail shows `queue_wait_ms` and `call_ms`.

#### Review round 3: storage, jobs, credential and the deploy (findings W2H-1 to 3, mpjobs-7)

- **Security fix (W2H-1; C2 item 8, plan 9.15).** The bootstrap Roblox credential and the bootstrap rotator gateway URL
  and password stay redacted everywhere for the whole life of a worker, however many values are pasted or tried from
  the dashboard; going back to the bootstrap value (Delete UI value, Use bootstrap URL) no longer stores a reason that
  repeats it in clear. The value in use is always registered, also after refused pastes.
- **Strikes are no longer forgiven by retention (W2H-2, plan 10.4, v1 `_prune_once`):** a strike row stays until every
  strike faded and the penalty ended (decay 0: until an admin forgives). The strikes table is capped at 200,000 rows
  (plan 15.4 `MAX_TRACKED_THROTTLE_IPS`); rows still penalized are never dropped by the cap.
- **Quiet recommendations outlive a shorter retention (W2H-3).** A dismissed or rolled back recommendation is kept
  until its `dismiss_cooldown_days` quiet period ends (an applied one through its watch window), even when
  `retention_recommendations_days` is shorter; the 50,000 closed-item cap removes such rows last.
- **Leader jobs run on a fleet-wide schedule (mpjobs-7):** a leader change (deploy, recycle, crash) no longer reruns
  them, and the hourly LLM export file is written once per hour across blue and green.
- **Workers need metrics.db schema 6** (`--expand` adds `0005_producer_history` and `0006_annotation_scope`, both
  expand only; the previous release keeps working on the new file).
- **Refusal events name the rule rows the abuse verdict matched (`detail.rules`)**, and the Protection attempts tabs
  show them as "Refused by" next to "Matching rule now" (closes the deferred P9 item "the rule that refused at the
  time"; refusals recorded before this change name none).
- **C7 admin login is now proven (docs lane request):** a test locks hot.db or control.db during a login and gets the
  503 with its clear message within one busy timeout (then at once), never a 500 and never a session from a failed
  step (`tests/security/test_auth_c7_unavailable.py`).
- **Deploy: kept releases are the newest five by deploy order** (a sequence number per release), never by file time,
  so a clock step can no longer remove a newer release; a rollback makes its release the newest. **The watch makes a
  fixed number of checks** (60 s / 5 s = 12): on a slow machine it may take longer than 60 s, but it is never cut
  short. **`perms.json` reports a wrong owner or mode on `/var/lib/roxy/ctl-proofs`** (roxy's 0700 directory).

#### Lanes: producers, docs, parity table, tooling and CI, load (2026-10-09)

Producers (`.remake/wave3b_reports/lane_producers.md`):
- **Six production data gaps are closed:** rule hits for every rule table (not only User-Agent rules), fleet-wide
  tarpit hold statistics, recorded bot scores, challenge and HTML-body flags per upstream attempt (with the rotator
  exit each call used), a windowed fleet-wide metrics drop counter and disk growth history (metrics.db schema 5, seven
  tables). Everything is summed in memory and written by the recorder's batch flush; the only request path change is
  the tarpit's held flag in the arrival row its transaction already writes. The Protection, Clients, System and
  Upstream areas show the new data.
- **What counts as a rule hit (plan 10.9, FILTER-REMOVE).** A request the rule's row matched, whatever the verdict
  (a User-Agent or endpoint rate rule counts even when its budget admitted the request, or an earlier limiter refused
  it first); while admin regex rules exist, a request a cheap limiter refused runs no pattern and records no pattern
  hit (9.9); one row per table per request; a deny entry that refuses an address also covered by a bypass entry
  gets the `access_list` hit; header rules are keyed by row id. The User-Agent rule hit is now recorded on the match
  (the aggregated `ua_rule_hit` event keeps its meaning).
- **TARPIT-TUNE readings.** The arrival gap is the time since the same client's previous tarpit-eligible refusal,
  filed under "after a hold" or "after an instant refusal"; "instant" covers only eligible refusals that were skipped
  (tracking refusals in categories that are off would add a hot.db write). Holds are a fixed-bucket histogram per
  category and minute (0.25 s to 55 s, then overflow; p95 interpolated); a planned hold that never waited counts as 0
  s; a hot.db outage is a skip with no gap (C7).
- **Recorded bot scores (plan 10.7).** A client's per-request inputs come from its first request in each 60 s scoring
  interval; scores are kept per address and hour (largest and latest), at most 5,000 clients per worker per minute,
  at least 2 days and 300,000 rows; an IPv6 key gives each of its last 4 addresses the key's score; bypass callers are
  never scored.
- **Challenge and HTML body (UP-CHALLENGE).** A challenge header (`rblx-challenge-*`, `cf-mitigated: challenge`), or
  HTML where a JSON endpoint was asked (by the content type or the first 256 bytes); 3xx, 204 and 304 are never
  flagged; a CDN's HTML 403 or 503 counts as a block page.
- **SYS-METRICS-DROP** counts every worker's queue overflow and bad items over the last hour and goes quiet an hour
  after the drops stop. **SYS-DISK `dims_per_minute` (plan conflict: the fixture README against the catalog help).**
  The catalog wins (P3): minute rollup rows of the last full hour divided by 60, averaged over 7 days. Disk history is
  one leader sample an hour plus table sizes every 6 hours (from `dbstat`), kept 90 days, first sample one interval
  after a worker starts leading; a growth line shorter than a day is not used.
- **Bounds are module constants** (`MAX_PRODUCER_KEYS` 20,000 and the others in `metrics/producers.py`,
  `metrics/disk_history.py`, `abuse/pipeline.py`); providers remember each answer 10 s.

Docs (`lane_docs.md`): `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/RUNBOOKS.md` and `docs/LEARNING_PATH.md`,
checked by `tests/unit/test_docs_references.py`; `README.md` now links the guides and `deploy/README.md` the runbooks.
- **Runbook headings use plan 13.2's short names**, so the health checks' links work with no mapping; each heading
  names its plan 17.8 title. **38 runbooks instead of 14** (one per alert and per health check link), each with a
  "Roll back" part.
- **The "Credential rejected" runbook empties the bootstrap file instead of deleting it** (systemd refuses to start a
  unit whose `LoadCredential=` file is missing; an empty file reads as "no bootstrap value"); plan C1 says "remove".
  **Changed credential files are picked up by redeploying the running commit** (no downtime).
- **Learning path exercises adapted to what exists** (chapter 1 runs the end-to-end test with `-s`, chapter 2 adds a
  practice route and watches the mount check refuse it, chapter 11 compares two recommendation fixtures, chapter 12
  runs the deploy sandbox tests). **The vulnerability report section names no contact address** (none exists; the
  owner should add one). **Memory sizing states only configured bounds**, and now links `docs/PERFORMANCE.md`.

Parity table (`lane_parity_table.md`, plan 19.11): `tests/V1_PARITY.md` has a row for every v1 smoke and deploy check
(781 rows: 365 covered by existing v2 tests, 233 by a new `tests/parity/` test, 183 intentionally changed, 0 empty,
0 pinned by an open finding since this round), generated and checked by `scripts/gen_v1_parity.py` (CI runs
`--check`).
- Readings recorded as intentional changes: blocked User-Agent drill-down and per-endpoint last headers come from the
  Live feed and its capture; per-place addresses, User-Agents and statuses come from the place's recent requests (15
  minute Live rows), per-client endpoint counts are the busiest endpoint of each minute (`top_endpoints_basis`); pause
  and throttle-all drop counters count from the minute the state began; a stale worker is listed as not fresh
  instead of hidden; the deploy keeps the newest five releases, builds an environment for every new release and has
  no home-directory alert script. (The per-header fingerprint clear and the tarpit history readings are superseded by
  parity-11 and the producers lane above.)

Tooling and CI (`lane_tooling.md`):
- **`scripts/ctl.py`, the operator CLI.** The plan 5.4 commands (`settings show|set` covers show-setting and
  set-setting) plus `status`, `reset`, `backup-now`, `leader`, `jobs` and `bans`; `--json` everywhere; every change is
  audited as `cli:<login name behind sudo>` and every line goes through `redact_text`. Deviation (plan 5.8 "ctl talks
  to the socket"): control-plane commands write the databases directly through the same services, so they work with
  every color stopped, and refuse any user but the databases' owner; only `export-llm`, `health-run` and `reset` use
  the socket.
- **A one-use proof for the dangerous socket actions (stricter than 5.8's group-only socket).** A reset, a
  full-detail LLM export and a health run with H-CRED-AUTH need a `Roxy-Ctl-Proof` file that only the state
  directory's owner can write, so the deploy user can never do them; in the shell it stands in for the dashboard's
  fresh second factor. The factory reset stays dashboard-only; a CLI health run leaves the credential check out
  unless `--include-credential` is given; a CLI LLM export says `generated_by: "cli"`, is audited before the bytes
  leave and is written 0600; `flush-metrics` sets the fleet-wide `flush_requested_at` like the System page.
- **"Back up now" reaches the root backup** (the earlier plan conflict "makes on-server snapshots" is resolved for the
  CLI and the dashboard): the roxy user writes `/var/lib/roxy/backup-request`, `roxy-backup-request.path` starts
  `roxy-backup.service`, and `backup.sh` consumes it, skips within 10 minutes of a good backup and records
  `last_request`. New state directory entries: `backup-request` and `ctl-proofs/`.
- **`advisories.json` at deploy (H-VERSION).** Counts come from CI's pip-audit of the production requirements only
  (`uv export --no-dev`), so a dev-only advisory never makes H-VERSION warn; CI still fails on fixable advisories in
  the whole environment; a hand deploy records "not recorded", never zero.
- **CI** (`ci.yml`): the unit job is the catch-all for suites without a job; `systemd-analyze verify` runs in the
  24.04 container only; container images are pinned by tag, not digest (a digest needs a network lookup); the runner
  allows unprivileged user namespaces, so the namespaced deploy tests run instead of skipping; CI now runs
  `tests/deploy` (parity row 102) and `gen_v1_parity.py --check`. CI has not run on GitHub yet. **Shadow week:** not
  run (D1 = never); `scripts/shadow_report.py` describes what the report would contain.

Load harness (`lane_load.md`, `docs/PERFORMANCE.md`, plan 19.4, 6.7, 19.10 row 7):
- **A Python harness instead of locust or k6** (plan 19.4): neither can start gunicorn, the mock and temporary state in
  one private network namespace, read metrics.db or sample worker memory; no new dependency.
- **Numbers from the WSL 2 development machine, not a staging VM of the production size** (6.7, 19.10): latency
  figures are indicative; the quiet-machine rerun in `docs/PERFORMANCE.md` is the reference before release. **The
  flood runs on the app limits only** (no nginx in the harness).
- **One steady wall clock for client, mock and Roxy** (`tests/load/clock.py`), because WSL 2's CLOCK_MONOTONIC runs
  about 9.5% fast and Roxy paces by the wall clock; the old harness made the mock 9.5% more lenient, which is why the
  replay test passed on one run and failed on the next.
- **Plan 19.10 row 7 test split:** `test_replay_profile.py` is two tests over one harness run; the clean-run and
  avoided-share checks are strict (49.5 to 49.8% avoided against 40%), and the unchanged 0.1% Roblox 429 assertion is
  a non-strict xfail for finding LOAD-1: at production defaults v2 gets 2 Roblox 429s in about 1,020 calls (0.196%)
  in 10 of 10 runs (avatar outfits, busiest 60 s 61 calls against 60), from the adaptive controller cutting the
  configured rate rather than the measured one and never cutting the burst; over 30 minutes it is 0.095%. A lead
  decision (LEAD_NOTES). The replay warms up 5 s instead of 20 s to fit the 5 minute budget.

#### Review round 3: integration (2026-10-09)

- **Producer history jobs wired** (`metrics_disk_history` hourly, `metrics_producer_prune` every 600 s, leader only,
  never at start); until now no disk samples were taken and the schema 5 tables were never pruned.
- **Every area's table download reads one page at a time** (Traffic, Endpoints, Clients, Security, Protection,
  Health, System errors, Recommendations and its history, Cache endpoints, and the `upstream_429` dataset), and the
  `refusal_reasons` and client datasets carry the new columns.
- **Chart notices for cache numbers** react to a cache statistics reset (hit ratio and the cache state counts), not
  to resets of other data.
- **The flaky health API test was a test isolation bug, not a product defect:** moving the fake clock past the
  re-auth window also made the leader's scheduled health run due, and that run rightly held the one-run lease.
- See `.remake/wave3b_reports/r3_integrate.md` for every request applied, deferred or rejected.

#### Review round 4: verification of the round 3 fixes (2026-10-09; findings secfix-1 to 7, LOGICFIX-1 to 6)

Two lenses checked the round 3 fixes and filed 13 findings (1 high, 7 medium, 5 low); all are fixed. Report:
`.remake/wave3b_reports/r4_refix.md`. Where these differ from the entries above, these win.

- **A lagging worker can no longer let a stale session undo a security change (secfix-1, high; plan 9.6, C6).** The
  fresh second factor, the spam detector arming rule and the high-risk confirmation are judged again inside the
  settings write, on the keys control.db is about to change; before, a worker whose settings copy was up to a second
  behind another worker's change judged a request "unchanged" and the write put the old value back (switching the
  admin allowlist off again, the credential back on, deleting a shortened re-auth window, or arming the spam
  detectors without the collateral preview). A save can therefore answer 403 `reauth_required` or 422
  `confirmation_required` for a key the page still showed at its old value.
- **Scheduled credential health checks need the fresh second factor (secfix-6, DESIGN 14.4)**, like a manual credential
  run: `health_auto_include_credential` joins `export_include_ips` in the settings that need it.
- **Exports hide IPv6 clients written after a word (secfix-2, secfix-3; plan 9.15, 12.3).** `ip:2001:db8:1:2::/64`
  (the spam and abuse subjects, a client's /64 limit key), `bypass:<network>` and `ban:<address>` are masked in every
  download and in the LLM export (the summary export kept the raw network); one masker serves both now
  (`core/ipmask.py`). Deviation from round 3: a version after a product name (`Chrome/120.0.0.0`) is kept only in
  User-Agent columns and fields; anywhere else `<word>/<address>` may be a path and is masked (privacy first).
- **Back up now always asks the root backup (secfix-4).** The request is written right after the audited intent,
  whatever the on-server snapshots can do; a copy that does not fit `snapshots_max_bytes` or the free disk is skipped
  with its reason (`skipped`), and 409 `not_feasible` remains only when neither the request nor any copy could be made.
- **Every table names its caller-text columns (secfix-5, DESIGN 13.1).** The probe log, admin logins, the Protection
  attempts tabs, CSP reports, fingerprints, events, audit, recommendations and the rest list `caller_text` from their
  columns (a discovery test checks every table), so the pages render them as plain text.
- **A probe flood with a new HTTP method per request is folded (secfix-7, v1 B19).** A client error's signature names
  one of ten method classes (the standard methods, else `OTHER`); the caller's own method token goes to the redacted
  target column. Deviation: v1 wrote the raw method in the reason.
- **KPI deltas over a reset are honest everywhere (LOGICFIX-1, plan 6.8).** The Cache page tiles, the endpoint
  drill-down totals, the Overview's "rotator bytes today" and the Traffic trends rows show the reset notice and no
  delta when a reset emptied either window (they computed their own deltas before), and their pages list the reset.
- **Updating an older glob rule is never auto-applied (LOGICFIX-2, plan 11.2).** A glob also covers every endpoint
  below it, so a recommendation that changes a template's own v1 glob rule (every rule the migrator imports) is not
  "scoped to one endpoint": it is not `safe_auto`, and its card says why. Deviation: the independent insights fixture
  `up_429_endpoint__get_raise_ttl` expected `safe_auto: true` for exactly that update; its expectation was changed (the
  one edit to that file, with a comment).
- **The early evaluation after a Roblox 429 burst survives a data reset (LOGICFIX-3).** The trigger poll remembers its
  cursor row; when a reset removed it (SQLite then reuses the ids), that poll counts by time.
- **Dry runs (LOGICFIX-4, 5, 6; plan 11.3, 19.10 row 11).** A request Roblox never answered (a connect error or a
  timeout) is not replayed as a stored answer; limit previews (THROTTLE-TUNE, the place limit, endpoint rules) replay
  the refused requests too, which production now samples (`refusal_samples`, metrics.db schema 7: refusals by the
  per-IP throttle and every later check, at `request_sample_pct`, at most 6,000 a minute per worker); each sample
  counts for 100 / the rate it was taken at (stored on each row since schema 7, else read from the settings history),
  so lowering `request_sample_pct` no longer inflates the next hour's previews.
- **Workers need metrics.db schema 7** (`--expand` adds `0007_limit_samples`, expand only; the previous release keeps
  working on the new file).
- **Found while gating: the batch writer's loop could leave its last items behind.** When the stop request arrived
  while a flush ran, an item added after that flush took its batch was never written (`storage/batch.py
  BatchWriter.run` promised one more flush); it now flushes once more (seen as an intermittent
  `test_run_loop_flushes_periodically_and_on_stop` under load, now pinned by a deterministic test).

#### P11 lane: upstream pacing, finding LOAD-1 fixed (2026-10-10; `upstream/buckets.py`, `adaptive.py`)

Plan 19.10 row 7's replay now keeps Roblox 429s under 0.1% of upstream calls at the plan's defaults (1 in about 1,030
calls, the one 429 that discovers the busiest endpoint's limit after a cold start; a 30 minute replay gets 2 in 8,593,
0.023%, one per endpoint whose demand exceeds its limit, against 8 in 8,442 before); the thresholds (0.1% and 40%) and
every default are unchanged, and `test_replay_keeps_roblox_429s_below_a_tenth_of_a_percent` is no longer an xfail.
Report: `.remake/p11_reports/pacing.md`.

- **Host and endpoint buckets cap every rolling minute (plan 7.3 formula changed for these two kinds).** Plain GCRA
  lets `per_min + burst - 1` calls into one minute (129 for 120 a minute with burst 10), which a Roblox limit of
  `per_min` refuses. For `host:` and `endpoint:` buckets (Roblox's own limits, configured or learned), `per_min` is
  now the most calls any minute holds, burst included: with N = `per_min` rounded down and B = min(burst, N) the
  spacing is `(60 s + 1 s margin) / (N - B + 1)` instead of `60 s / per_min`, so B calls still leave at once and the
  steady pace is a little lower (120 with burst 10: about 109 a minute; 240 with 15: about 222). The 1 s margin
  covers jitter between Roxy's slot time and Roblox's arrival time. The global and egress buckets are Roxy's own
  ceilings and keep the plan formula. A bucket's fill on the Upstream page is relative to the new spacing.
- **A Roblox 429 cuts from the rate Roblox refused, rate and burst together (plan 7.3 "drops 30%").** Each host and
  endpoint bucket counts the calls it grants in a small sliding window counter (a `meter:<key>` row in hot.db's
  `upstream_bucket`, written in the same reservation transaction, pruned like an idle bucket, never shown as a
  bucket). After a direct or credential 429, the cut of `adaptive_decrease_pct` starts from the lower of the
  current limit and the calls the bucket let through in the last minute, so it always lands below what Roblox refused
  (the root cause of LOAD-1: 120 cut to 84 never slowed an endpoint running at 61 against 60; now 61 becomes about 43,
  burst 10 becomes 3). A count at or below `adaptive_min_per_min` is not used (Roblox refusing that few calls is not
  a per-minute limit Roxy could keep, for example a refusal of the first call of a quiet minute): the plan's cut of
  the current limit applies. The burst always shrinks by the same ratio as the rate. The change event and the audited
  `upstream_limits` write carry `old_burst`, `new_burst` and the evidence (`observed_calls`, `cut_from`).
- **A lowered limit also holds for the minute that began before it.** The first reservation under a lower host or
  endpoint limit (an adaptive cut or an admin's edit) starts from the backlog the last minute's calls make at the new
  pace, so Roblox's window, which still holds those calls, never sees more than the new limit; routing reads the
  same paced state.
- **Careful recovery.** The hourly raise (plan 7.3 bounded probing, unchanged: 24 clean hours and rejections over
  1%) also gives the burst back, at most one call per raise and never beyond the default burst's share of the new
  rate or the default burst itself.
- **A call never leaves before its slot.** The queue sleeps a duration measured on the monotonic clock while slots are
  wall clock times (the clock the buckets share); on WSL 2 the monotonic clock runs about 10% fast and the wall clock
  is stepped back every half minute, so calls left early and squeezed extra calls into a minute. The rest of the wait
  is now slept (at most three rounds, never past the time the call needs before its deadline); on a server whose
  clocks agree nothing changes.
- **Settings texts and `docs/SETTINGS.md`:** the host and endpoint rate and burst, `adaptive_rate_enabled`,
  `adaptive_decrease_pct` and `adaptive_increase_pct` describe the rolling minute, the measured cut and the burst. No
  default changed: the catalog matches plan 7.3 and 15.3 C (600/30, 300/20, 300/20, 240/15, 120/10, credential 20/3
  with 2 reserved, adaptive 30%, 10%, 24 h, 6 to 600); there are no built-in `upstream_limits` rows.
- **Tests:** the upstream fleet test now also checks the plan's cut after a first-call 429; the multiprocess 429 test
  checks the window guarantee (at most the limit, never limit plus burst) and the learned limit across two processes;
  one admin API expectation follows the new spacing (an endpoint bucket 3 s ahead is 54.6% full, not 60%).

## Progress notes per phase

### Phase -1 (Tier 0): v1 hotfix, 2026-10-07

- Built on branch `hotfix/v1-phase-minus-1` (commit 3453d66), kept apart from v2 and not merged: a push to `main`
  deploys v1, so the owner reviews `HOTFIX_NOTES.md` on that branch first.
- What it does: the credential goes only with GET requests whose exact outbound host and path are on a new allowlist
  (empty by default) and with Roxy's own probes, carrying only Roxy's fixed header set; every requests session has
  `trust_env = False`; no fallback to the other method on a 429; `Retry-After` opens a cooldown shared by all workers;
  cookie responses are never cached; shadow mode (off) for the D1 measurement.
- Gate: v1 smoke suite 1018 checks, including 135 wire-level credential invariant checks, all passing; the remaining
  intermittent failures are older timing checks (the WSL clock steps back about 0.9 s every 31 s) and one random-weight
  check, both pre-existing.
- Reviews: a correctness reviewer found an allowlist bypass through `%3F` and `%23` in paths and unnormalized cooldown
  keys (fixed); a defensive verification pass found forwarded caller headers on cookie calls, non-exact allowlist
  matching and two exposure paths (fixed).

### P0 to P2: skeleton, storage, control plane, 2026-10-07

- Built: the app factory, worker class, internal Unix socket app, lifespan, middleware, logging with redaction, the
  style checker and word list, CI and a disabled deploy workflow (P0); four WAL databases with writer threads and read
  pools, the full 6.2 schema, leases with fencing, leader election, heartbeat, batch writer and retention (P1); the
  settings catalog (495 settings, 50 insight rules, generated `docs/SETTINGS.md`), runtime store with hot reload,
  audited settings service, rules store and CRUD, and the shared matcher with v1 parity tests (P2).
- Gate: 3054 tests pass (unit and multi-process with real processes); ruff, ruff format, mypy (strict on core,
  storage, config, rules) and the style check are clean; `check_style.py REMAKE_PLAN.md` passes; the app boots under
  gunicorn with `RoxyUvicornWorker` and serves the internal socket while `/internal/version` is 404 on TCP.
- Reviews: three adversarial reviewers (multi-process, security, spec) filed 33 findings; all were fixed with tests
  (see "Fix pass after the P0 to P2 reviews" above).
- Deviations: `roxy.asgi:app` is a small dispatcher that sends requests arriving on the internal Unix socket to the
  internal app and everything else to `create_app()` (the public app has no `/internal` routes). Bandit's B608 is
  owned by ruff's identical S608 rule, with every interpolated identifier annotated inline.
- Open: the CSP Playwright spike (P0 gate item) moves to P11, where the vendored scripts exist.

### P3 to P8: egress, upstream, cache, proxy and abuse, metrics, admin auth (wave 2), 2026-10-07 to 2026-10-08

- Built (2026-10-07, seven builders in parallel on the DESIGN.md section 11 contracts):
  - P3 egress (`egress/`): the single credential slot, the three clients on the guard transport, header profiles,
    rotator sessions and parking, byte metering and accounting. 159 tests (112 unit, 47 in the 19.5 credential
    suite); metering matched a recording proxy's raw byte count exactly on loopback (2150, 13811 and 13700 bytes
    for forwarding, a CONNECT tunnel and TLS interception).
  - P4 upstream (`upstream/`): routing, GCRA reservations, adaptive rate, cooldowns, breakers, backoff, the
    priority queue, the CSRF cache, the 7.9 policy and 7.13 statuses, internal calls. 398 tests (382 unit, 15
    integration, 1 two-process test: no call during a `Retry-After: 30` cooldown, then 43 calls in the next 60 s
    against a limit of 60 per minute plus a burst of 2).
  - P5 cache (`cache/`, `upstream/singleflight.py`): keys, policy, both tiers with generation invalidation, SWR,
    negative entries, key spread. 118 tests (96 unit, 15 integration, 6 multiprocess where 2 and 4 processes make
    exactly 1 upstream call, 1 contract test).
  - P6 proxy surface (`proxy/`): 368 tests (76 golden, 138 in the SSRF corpus of 53 hostile cases). P6 abuse
    (`abuse/`): the ordered pipeline with every check, the ladder, bans, spam, bot score, challenge and the three
    tarpit types; 148 tests (6 multiprocess: GCRA at the exact limit is never refused across two processes over 10
    simulated minutes).
  - P7 metrics (`metrics/`): recorder, rollups, histograms, templating, activity, fingerprints, live tail, capture,
    samples and the query layer. 200 tests (193 unit, 4 integration, 3 multiprocess with 1, 2 and 4 workers x 3,000
    events, totals exact); `record_outcome` costs about 28 microseconds.
  - P8 admin auth and alerts (`admin/auth/`, `notify/`): argon2id, TOTP, passkeys, recovery codes, the email
    bootstrap, sessions, CSRF, lockout, trusted devices, the kill switch, the allowlist, `scripts/create_admin.py`
    and the notifier. 167 tests (82 auth unit, 55 notify, 30 security); two app instances sharing hot.db split 14
    parallel guesses and exactly 5 passwords are checked.
- Wire (2026-10-07): `lifespan.py` fills every AppContext field in the order of DESIGN.md 11.9, `public/health.py`
  and the admin router are added, and the proxy flow records outcomes on exceptions and counts proxied requests.
  New tests: 55 end-to-end (`test_pipeline_e2e.py`: every refusal, every 7.13 row, every cache state) and 5 against
  real gunicorn masters (`test_gunicorn_mp.py`). With 4 workers, one client got exactly 10 of 30 requests, 20
  callers on one key made 1 upstream call, a settings change reached all 4 workers within 0.44 s, there was exactly
  1 leader, and 80 requests gave 80 records; with two masters, the other color took over leadership 4.9 s after the
  leader stopped. 19.10 row 7 with 2 workers: 0 upstream calls during the cooldown, 112 caller answers all 429 with
  `Retry-After`, 43 calls in the 60 s after it (limit 65), 0 calls with the credential, 368 recorded of 368 sent.
  The full suite was then 6011 passed and 60 failed: 37 deploy and 21 design system tests that other agents were
  editing at that moment, and 2 timing tests that passed on rerun.
- Review round 1 (2026-10-07, cut short when the run was stopped at the owner's request): four lenses (credential
  confinement, ingress security, multi-process, spec and parity). The spec and parity review finished with 10
  findings (1 high: the D10 reversal had stopped halfway; 6 medium; 3 low) and 5 repro tests; the other three
  lenses left 22 findings in the tree as strict xfail tests. The WIP checkpoint 680f52a (2026-10-08) stood at 5997
  passed, 3 failed (tests that still expected the old D10 default) and 36 xfailed.
- Fix pass 1 (2026-10-08): six fixers (abuse and storage 13 findings, cache and single-flight 6, upstream, egress
  and rules 8, metrics and ops 6, surface and gates 9 items, Luau 6 items) and an integrator fixed all 22 xfail
  findings and spec findings F1 to F4 and F6 to F10, with the repros R1 to R5 moved into the suite; F5's code item
  (the 500 body) is fixed and its CHANGES.md part is this catch-up. Every strict xfail became a passing test, most of
  them strengthened (abuse decisions under a locked hot.db: the slowest of 16 went from 8.56 s to 0.51 s).
- Gate (2026-10-08): `lead_gate.sh` 6853 passed (pytest -x, 949 s); the full run without -x gave 6853 passed, 0
  failed, 0 skipped, 0 xfailed in 1008 s (unit 5545, security 510, deploy 356, integration 216, migration 99, e2e
  with Playwright 76, multiprocess 51). ruff check, ruff format --check (450 files), mypy (228 files),
  `check_style.py` and `check_style.py REMAKE_PLAN.md` pass, and `docs/SETTINGS.md` is up to date. Bandit at the CI
  level reported 13 medium findings (B610 x6, B704 x7, the same as at 680f52a), now owned by ruff as recorded above.
  Committed as c128a1c.
- Review round 2 (2026-10-08, on c128a1c): six adversarial lenses filed 43 findings, each pinned by a strict xfail
  test that failed for the stated reason: credential confinement 8 (1 high, 4 medium, 3 low), ingress 3 (1 high, 2
  medium), multi-process and failure modes 12 (6 medium, 6 low), spec and parity 9 (2 medium, 7 low), admin auth and
  alerts 2 (1 high, 1 medium), public site 9 (1 high, 3 medium, 5 low): 4 high, 18 medium, 21 low, 40 distinct
  defects (INGRESS-1 and public-4 are one regex; mp-5, public-1 and public-2 one templating cause). The high ones:
  an encoded credential paste let any caller switch off direct and the rotator (cred-1); the secret header line
  regex was quadratic on line breaks any anonymous caller can send (INGRESS-1, public-4); login failure retention
  reset lockout windows longer than an hour (AUTH-1). Most fix pass 1 fixes held against new variants (33 passing
  variant tests stay in `test_rr_ingress_fix_variants.py`); the ones that did not hold on a variant, mostly the exit
  side of a failure mode, were filed: credential F1 to F4, the regex validator, DEGRADED-REFILL, UP-COOLDOWN-LOST,
  SF-ORPHAN, ALERT-CAP, spec F7 to F10 and the template stat item left open.
- Fix (2026-10-08): seven fixers (upstream, egress and rules 9 findings; metrics and ops 11; abuse and storage 9;
  public site 9; cache and single-flight 3; design system 1; surface and gates 1) and the integrator fixed all 43;
  none was rejected, and every strict xfail became a passing test, most of them strengthened. Measured: an 8 KiB
  `%0A` path costs 0.6 ms of scrubbing (was about 80 ms); a 429 reaches the caller 0.51 s after Roblox answered
  while another process holds hot.db (was 5.03 s); with metrics.db locked the shutdown took 5.04 s (was 10.2 s,
  over its 8 s budget) with no loop stall over 0.02 s (was 5.0 s), and the rest of that wait, the heartbeat row
  delete, is now capped at 1 s; a paused journald stalls the loop 0.03 s (was 2.49 s); leaving degraded mode
  admits nothing extra (was 20 against a limit of 10). The integrator applied the cross-owner requests (notify TLS
  key log, the never-raising `parse_redirect` that upstream now uses for every hop, `UpstreamResult.private`,
  bounded scrubbing in error events and CSP reports, the flow's compat choice for the deadline answer, a budgeted
  heartbeat delete) and fixed one flake at its root: the fleet breaker test's mock egress inserted every call into
  a shared SQLite file on the event loop, so a call reserved before the breaker opened could be sent a tenth of a
  second later and read as a call through an open breaker; the mock now keeps calls in memory and anchors on the
  time the breaker really opened (`test_review_failure_modes_mp.py`, 15 of 15 and 6 of 6 under fsync load after).
- Gate (review round, 2026-10-08): `lead_gate.sh` 7283 passed (pytest -x, 1232 s, Playwright with
  `LD_LIBRARY_PATH`); the full run without -x gave 7283 passed, 0 failed, 0 skipped, 0 xfailed in 1295 s (unit
  5849, security 585, deploy 356, integration 234, migration 99, multiprocess 84, e2e with Playwright 76). ruff
  check, ruff format --check (492 files), mypy (228 files), `check_style.py`, `check_style.py REMAKE_PLAN.md` and
  `gen_settings_docs.py --check` pass; bandit at the CI level (`-ll`) reports nothing (29 low findings below it).
- Deviations: see "Wave 2 (P3 to P8)" above.
- Open:
  - Upstream still builds its own outbound URL and headers instead of using `req.upstream_url` and
    `req.forwarded_headers()`: safe, because a validated path cannot hold `%`, `?` or `#`, but a second source of
    truth (it sends `Content-Type: application/json` when the caller sent none).
  - The single-flight outcome publish is a third small hot.db write per miss; lease-row outcomes are not
    compressed; handoff rows show in the cache browser for about a minute.
  - Retention: `prune_fingerprint_values` caps the whole table at `max_header_value_records` while the writer and v1
    cap it per header; an alert held back by the hourly cap is stored with `last_sent_at = 0`, so the next prune
    drops it with its suppressed count (as before the review round).
  - From the review round: plan 13.2's H-ENV-PROXY row should name `SSLKEYLOGFILE` (REMAKE_PLAN.md is the lead's);
    the regex cost model means 5 to 25 ms on 8 KiB (the slowest accepted shape measured 20 ms) and still refuses some
    patterns the engine's literal prefilter runs fast; a rotated cookie whose only secret text is shorter than 24
    characters is not watched; handoff rows are read only on a follower's last look; a recycling worker's unpublished
    lease stays live until the owner deadline (followers find the stored answer meanwhile); an hour that contains a
    hot.db outage can send the alert cap plus what went out before the outage; when only some workers are degraded
    the fleet can admit `limit + k x share`, the degraded divisor lags the heartbeats by up to 5 s, and a pending row
    evicted by the memory bound is never merged; a second master started while every worker of the first is down
    passes the port check (a per-port lock file would close it); uvicorn's and gunicorn's own loggers still write
    synchronously.
  - For P11 part two: build the shell `status` with `caller_texts`, answer the switch writers' `ValueError` as 400
    or 422, add the inline editor for `pause_message_default` and refresh open dashboards when it changes, and
    decide whether to warm the dashboard templates at startup (about 155 ms per worker; today each is read once, on
    its first render). The home page's "Limits at a glance" does not mention throttle-all, and the examples' `type
    HttpResponse` stands in for Studio's own type name, which could not be checked.
  - Passkeys are tested with a software authenticator only (no browser test); the cross-worker lockout is tested
    with two app instances in one process.
  - Per-worker views: the bot score's probe count and the recent exit IPs. A worker that cannot read control.db at
    start does not know an existing leak trip until a read succeeds (the guard still blocks the request).
  - The measured row size means plan 6.6 and `storage_total_budget_gb` should be revisited; there is no table for
    concrete example paths per template (the Endpoints page gets them only from the 15-minute live rows).
  - `DECISIONS_REVIEW.md` needs entries for `rotator_session_username_template` and `net.ipv4.tcp_migrate_req`.
  - Commit from WSL git: Windows git cannot see the 0755 bits of `deploy/*.sh` and `deploy/tools/*`.
  - `test_caller_traffic_never_carries_the_credential` failed once during concurrent edits and did not recur in the
    baseline, gate or final runs.

### Migrator (P14 part), 2026-10-07

- Built: `roxy.migration` with the thin wrapper `scripts/migrate_from_v1.py`: reading the v1 tree (with the `.bak`
  and legacy `Runtime` fallbacks), settings per the 18.3 table, every rule table, the ladder, bypass entries, pause
  and throttle-all, hosts, the credential files, the admin account, statistics and a JSON and Markdown report. 70
  tests in 13 files (the plan 19.6 cases), stable over three runs. Committed with wave 2 in 680f52a, because it
  imports `roxy.abuse` and `roxy.metrics`.
- Reviews: one adversarial reviewer filed 15 findings (1 high: a rerun after cutover paused production again; 4
  medium: a rerun undid deliberate v2 changes, ladder text was not checked for secrets, a v1 bypass range became an
  active network bypass, a wrong `--v1-root` reported success; 10 low), each with a probe test outside `tests/` (15
  failing, 13 passing checks). It confirmed every row of the 18.3 settings table (71 keys), C1, untouched v1 files,
  a byte-identical second run and clean convergence after an interrupt at 4 steps and a SIGKILL inside a rule
  transaction.
- Fix: all 15 fixed (five differently from the suggestion, recorded above); `tests/migration` 99 passed (29 new
  cases); the review suite 27 of 28 (the remaining one reads `control.db` in its setup, which a refused run no
  longer creates); the credential suite 47 passed; ruff, ruff format, mypy (strict on `migration/`) and the style
  check clean. In the wave 2 gate of 2026-10-08: 99 passed.
- Deviations: see "Migrator (P14 part)" above.
- Open: the `config/env.py` docstring still says the migrator reads every removed v1 variable; statistics are
  outside the rerun rules (a rerun can insert again v1 fingerprint, error or probe-summary rows that retention or a
  clear removed since); MIGRATION.md must say that a v1 paused at copy time starts v2 paused.

### P13: operations, 2026-10-07

- Built: `deploy/` (gunicorn config, `prestart.py`, `deploy.sh`, `deploy_rollback.sh`, `install-system.sh`, env
  examples, the nginx template, upstream files and security snippet, systemd units, timers and path units, root
  tools, sudoers), `scripts/smoke_remote.py` and `scripts/build_static.py`.
- Gate (build): `tests/deploy` 307 passed, nothing skipped. All 9 v1 `deploy_test.sh` scenarios and the plan 19.9
  list run the real `deploy.sh` against stubbed tools; real gunicorn masters in a loopback-only namespace show one
  leader across blue and green, a low-memory start growing from 1 to 2 workers and both sockets at 0660; real
  `nginx -t` passes on nginx 1.18, 1.24 and 1.30; `systemd-analyze verify` is clean and `security --offline` scores
  roxy@blue at 1.2 (target 2.0); the app boots under the unit's system call filter.
- Reviews: one adversarial reviewer filed 14 findings (1 high: `install-system.sh` took `/etc/roxy` away from the
  running v1; 6 medium; 7 low) with eight verification scripts and a live nginx 1.24 flood test.
- Fix: all 14 fixed, plus symlinked directories in `install-system.sh`; `tests/deploy` 353 passed (45 new cases, 39
  of them shown to fail on the builder's files); `test_stop_flushes_metrics` now compares rows with answers (7151
  served, 7151 recorded). Fix pass 1 of wave 2 then made the `internal_hidden` smoke check fail fast, added
  `reuse_port` to the gunicorn config and a test of the 0755 bits in the git index; the wave 2 gate ran 356 deploy
  tests, all passing.
- Deviations: see "Operations (P13)" above.
- Open: CI (`ci.yml`) does not run `tests/deploy` yet; `scripts/smoke_remote.py` should also check `GET /docs`, and
  the deploy's required paths should name `docs/USER_GUIDE.md` and `docs/glossary.yml`. MIGRATION.md (P14) must
  list: create the `roxy-deploy` account and set `LIGHTSAIL_USER` to it; set `ROXY_DEPLOY_REPO_URL` in
  `/etc/roxy/roxy.env`; `worker_processes 2;` and `worker_connections 4096;` in `nginx.conf`; remove
  `sites-enabled/default`; install `acl`; deploy with `ROXY_DEPLOY_PUBLIC_CHECK=0` until the cutover; at the cutover
  stop v1, import its data, disable v1's nginx site and run `install-system.sh --take-over-etc`; the manual contract
  migration step. The swap note is in `deploy/README.md`.

### P12 part one: public site and user guide, 2026-10-07

- Built: `public/pages.py` (`/`, `/docs`, `/status`, `/robots.txt`, `/sitemap.xml`, `/favicon.ico`, each for GET
  and HEAD), `public/csp_report.py`, the public templates, `site.css` (light and dark), `site.js` (copy buttons,
  opening `<details>` on hash links) and `docs/USER_GUIDE.md` with live values filled from settings. 108 tests (86
  unit, 22 integration), stable over three runs; page weights then: home 25.7 KB, docs 42.3 KB, status 17.1 KB.
- Reviews: one adversarial reviewer filed 15 findings (1 high: `/docs` was a 404 in the non-editable production
  install; 1 medium: one client could spend the hour's CSP report budget; 10 low; 3 informational), backed by 49
  probe tests; XSS through the `site_*` settings, raw HTML in the guide and the CSP all held.
- Fix: 12 fixed, 2 informational cleanups done, 1 rejected; 143 tests (116 unit, 27 integration), stable over
  three runs (36 of the 91 new tests that could import failed on the old code). Page weights: home 27.5 KB, docs
  45.4 KB, status 18.8 KB; no CSP violation, console error or sideways scroll in Chromium at 1280 and 375 px in both
  themes.
- Deviations: see "Public site and user guide (P12a)" above.
- Open: the deploy smoke check should request `GET /docs`; `config/catalog.py` (for `scripts/style_words.txt`,
  which silently skips the word check when missing) and `core/style_guard.py` still build paths with `parents[3]`,
  which resolve inside `.venv` in a non-editable release; the hatch `force-include` for the guide is optional now;
  Chromium warns that the Permissions-Policy features `ambient-light-sensor` and `bluetooth` are unrecognized
  (`core/security_headers.py`).

### P11 part one: design system, 2026-10-07

- Built: the admin base layout and its parts (navigation, sidebar, top bar, banners, phone bar, palette, shortcuts,
  control dialogs, overlays), 16 Jinja component files (icons, KPI tile, charts, heatmap, table, live tail, the
  setting control for every catalog setting, recommendation card, diff, dialog, glossary term and more), the token,
  layout, component and print stylesheets, 16 JS modules, the vendored htmx, Alpine CSP and uPlot,
  `admin/gallery.py`, `docs/glossary.yml`, `scripts/check_contrast.py` and four review screenshots. 669 tests (102
  static, 23 gallery, 508 template, 7 CSP spike, 29 browser), the browser suite stable over three runs.
- Gate (build): axe finds nothing serious or critical in dark and light at 390x844 and 1440x900, also with the
  palette, a dialog and the drawer open; 164 contrast pairs, none failing; the CSP spike has zero violations.
- Reviews: one adversarial reviewer filed 17 findings (1 high: the glossary path broke in a non-editable install;
  1 CI blocker: the style check failed on vendored files; 6 medium accessibility and robustness defects; 9 low),
  each verified with a browser probe or a command; no CSP violation and no XSS path.
- Fix: 15 fixed in the design system files and the vendored-file skip applied by the lead in fix pass 1 of wave 2;
  705 tests (36 new, including the new `test_design_system_robustness.py`, whose 23 browser tests all failed before
  the fix), the browser suite stable over three runs; screenshots regenerated.
- Deviations: see "Design system (P11a)" above.
- Open: the catalog cross rule `admin_heartbeat_interval_s <= admin_activity_window_s` (config owner; the client
  already uses the shorter of the two); the re-auth contract (JSON code or header); P11 part two should load the
  glossary at startup so a missing file fails the health gate.

### Luau follow-up (public site), 2026-10-08

- Built: the server-side Luau highlighter `public/luau_highlight.py`, rewritten after the interrupted first attempt
  (its generic-parameter path called a missing method and brackets inside types recursed without a bound); the six
  strict typed examples; the cache-hit wording on every public page; keyboard-focusable code blocks; and
  `scripts/check_contrast.py --public` for the public palette.
- Gate: `tests/unit/public` 278 passed (the highlighter 112, including Hypothesis properties and a coverage test
  that requires all 328 scanner lines to run; the examples 39, with luau-analyze 0.741 under both solvers),
  `test_public_pages.py` 28, the new Playwright file `test_public_site.py` 17 (no CSP violation or console error on
  `/`, `/docs` and `/status` in both themes, browser-computed highlight colors at 4.5:1 or better, axe clean, the
  Copy button copies each home example byte for byte) and `test_ui_static.py` 104: 323 passed, all of them inside
  the wave 2 gate of 6853.
- Reviews: done as part of wave 2 fix pass 1; review round 2 covers it.
- Deviations: see "Luau follow-up" under Wave 3a above.
- Open: Studio support for `const` is not verified; `tests/unit/public/roblox_api.luau` declares only the Roblox API
  the examples use (Studio's own definitions may differ slightly); the highlighter is a lexer with a little context,
  so rare spellings (a method named `typeof`, `obj : Method()` with spaces) may get another color, while the text
  itself is never lost or changed.

### P9: admin API (wave 3b), 2026-10-08 to 2026-10-09

- Built (2026-10-08 on the DESIGN.md section 13 conventions: the shared layer first, then four area builders in
  parallel, then the assembly):
  - The shared layer (`admin/api/__init__.py`, `admin/api/common.py`): area routers, the guards, the error format,
    bodies, time ranges, series, KPI tiles, tables, exports and the mount checks. 109 unit and 13 integration tests.
  - Settings, Audit, Preferences, Data, Export and System: 55 tests, with every data reset plan part checked against
    the real schema.
  - Protection, Clients and Security (106 routes): 32 tests; a mutation check of the `spam_dry_run` refusal, the
    allowlist self-lockout guard, the collateral token and the tarpit bookkeeping exemption caught all 4.
  - Overview, Traffic, Endpoints, Live, Cache and the event stream (`admin/sse.py`): 58 tests, one of them across two
    processes (a stream on one worker receives what another worker recorded, exactly once).
  - Upstream, Upstream limits, Routing rules, Egress, Rotator, Credential, Credential allowlist and Lookup: 79 tests;
    the leak scans look for the whole credential and every 24-character window of it, and for the rotator URL, in
    every answer, audit row and log record.
  - Assembly: the Recommendations API (16 tests), lazy mounting with nested prefixes first, the admin-only OpenAPI
    document, the P11 page include point and `tests/security/test_admin_routes.py` (15 tests). It discovers every
    admin route of the app (316 method and path pairs in a development app, 295 of them checked; the rest are the
    development gallery and the catch-all) and checks that the unguarded and fresh second factor routes are exactly
    the listed ones, that every guarded route answers 401 or the login redirect when signed out, that more than 100
    unsafe routes refuse a missing, garbage or foreign CSRF token, and that every sensitive route answers
    `reauth_required` with a stale second factor.
  - In all, 25 areas plus the stream: 220 paths and 265 method and path pairs, with read models next to their data
    (DESIGN.md 14.6).
- Integration (2026-10-08 to 2026-10-09): 41 integrator requests applied or verified and three problems found while
  integrating fixed (see "Wiring, storage and the request path" above). For P9 that meant the section 13 guard
  answers (the 2 strict xfails of the route security test now pass), the per-recommendation lease, the shared place
  lookup, the arm-only `spam_dry_run`, the bounded `last_result` of `GET /system/jobs`, `RotatorUrlError`, the
  credential file name out of `/system/environment` (it failed `test_only_credential_module_reads_secret`), the
  forced flush watcher on every worker, one annotation writer, and the stream's `unauthorized` and `gap` events in
  the browser (`static/js/sse.js`, `static/js/live_tail.js`). 26 new tests, among them
  `tests/integration/admin_api/test_api_w3b_wiring.py` (15). Two intermittent failures of the final runs were fixed
  at their root: `test_gunicorn_fleet_limits_hold[1]` measured a reload delay of -1.5 s across a wall clock step (now
  measured with `monotonic_s`; 12 of 12 reruns pass), and the 4-worker GCRA case of `test_rr_mp_degraded.py` lost an
  admit across a step back (now `steady_now_ms`; 60 of 60 reruns pass, 2 failures in 36 before).
- Gate (2026-10-09, the whole wave 3b tree): the full run without -x gave 8823 passed, 0 failed, 0 errors, 0 skipped,
  0 xfailed in 1760 s (unit 6056, insights 840, security 600, integration 522, deploy 356, health 187, migration 99,
  multiprocess 86, e2e with Playwright 77), against 7283 at the wave 2 gate. `lead_gate.sh` (pytest -x plus the
  static checks) gave 8821 passed in 1807 s before the two flake fixes, with ruff check, ruff format (627 files),
  mypy (318 files), `check_style.py` for the tree and REMAKE_PLAN.md, `gen_settings_docs.py --check` and bandit `-ll`
  (0 findings; 32 low below it) green; the static checks were rerun clean after the fixes. Admin API tests:
  `tests/integration/admin_api` 288 (the P10 health and LLM export files and the wiring tests included),
  `tests/unit/admin_api` 109, `tests/security/test_admin_routes.py` 15. Under real gunicorn (2 workers), an admin
  signed in through the password and TOTP steps gets the OpenAPI document (26 tags, more than 200 paths) and an
  anonymous caller gets 401 `unauthorized`.
- Reviews (2026-10-09): six lenses reviewed the whole of wave 3b and filed 54 findings, each pinned by a strict
  xfail test: apisec 9 (1 high, 4 medium, 4 low), insights 14 (1 high, 9 medium, 4 low), mpjobs 8 (1 high, 6
  medium, 1 low), parity 15 (9 medium, 6 low), the parity table lane 5 (1 medium, 4 low) and the wave 2 highs 3 (2
  high, 1 medium): 5 high, 30 medium, 19 low. The P9 share: apisec-1 to 9 (fresh second factor for the settings that
  guard the admin, addresses masked in every exported cell, wrong methods no longer reveal admin paths, the
  Protection confirmation, bounded Back up now, bounded table downloads, huge ids, the stream's allowlist check, the
  bootstrap guard mount check), mpjobs-4 and 5 (the reset marker, download memory) and parity-1 to 15 (v1 columns and
  numbers of the Overview, Traffic, Upstream, Protection, Clients, Endpoints, Security, Cache and Data areas).
- Fix pass (2026-10-09, nine fixers in parallel, then the integration): all 54 findings fixed, none rejected (two pairs
  were one defect each: insights-5 with mpjobs-8, parity-6 with the parity table's parity-5); every strict xfail is
  gone and each test pins the fixed behavior, most of them strengthened; the lanes ran beside it (see "Lanes of wave
  3b" below). The integration applied or verified every fixer and lane request (46 from the fixers), rejected none,
  deferred three optional ones and left the load lane's three decisions to the lead (reasons in
  `.remake/wave3b_reports/r3_integrate.md`); it also wired the producer history jobs, moved every area's download to
  the page-by-page builder, added metrics.db schema 6 (`annotations.reset_tables`), and found the root cause of the
  "flaky" health API test (a test isolation bug: the fake clock jump made the scheduled health run due).
- Gate (2026-10-09, after the fix pass and the integration): the final full run without -x gave 9479 passed, 0
  failed, 0 errors, 0 skipped and 1 xfailed (the non-strict LOAD-1 marker) in 2305 s (deploy 422, e2e with Playwright
  77, health 194, insights 883, integration 602, load 23 and 1 xfailed, migration 99, multiprocess 87, parity 49,
  security 726, unit 6317), against 8823 at the wave 3b gate. `lead_gate.sh` (pytest -x plus the static checks):
  9479 passed and 1 xfailed in 2319 s; ruff check and format (720 files), mypy (324 files), `check_style.py` for the
  tree and REMAKE_PLAN.md, `gen_settings_docs.py --check`, `gen_v1_parity.py --check` (781 rows, 0 empty, 0
  problems) and bandit `-ll` (0 findings; 34 low below it) green. The replay test alone: 1,018 upstream calls, 49.6%
  avoided, 2 Roblox 429s (0.196%, LOAD-1, at 50.4 s and 157.0 s, avatar outfits 61 calls against 60). The admin API
  schema lists 225 paths, 271 method and path pairs and 26 tags.
- Review round 4 (2026-10-09, `.remake/wave3b_reports/r4_refix.md`): two lenses verified the round 3 fixes and filed
  13 findings, each pinned by a strict xfail; all fixed, none rejected. The P9 share: secfix-1 (high: the fresh
  factor, arming and confirmation judged inside the settings write, `settings.WriteRules`), secfix-2 (IPv6 subjects
  masked in every download, one masker `core/ipmask.py`), secfix-4 (Back up now always asks the root backup),
  secfix-5 (`caller_text` from every table's columns, a discovery test), secfix-6 (`health_auto_include_credential`
  needs the fresh factor), secfix-7 (probe signatures by method class) and LOGICFIX-1 (reset notices on the Cache
  tiles, endpoint drill-down, rotator tile and Traffic trends). Found while gating: `BatchWriter.run` could leave the
  items added during its last flush behind (fixed, deterministic test).
- Gate (2026-10-09, after review round 4): the full run without -x gave 9539 passed, 0 failed, 0 errors, 0 skipped
  and 1 xfailed (LOAD-1, non-strict) in 2388 s (deploy 422, e2e with Playwright 77, health 194, insights 890,
  integration 631, load 23 and 1 xfailed, migration 99, multiprocess 87, parity 57, security 730, unit 6329), against
  9231 passed, 5 failed and 60 xfailed on 3861e65. `lead_gate.sh` right after: 9539 passed and 1 xfailed with -x in
  2386 s; ruff check and format (740 files), mypy (325 files), `check_style.py` for the tree and REMAKE_PLAN.md,
  `gen_settings_docs.py --check`, `gen_v1_parity.py --check` (781 rows, 0 problems) and bandit `-ll` (0 findings; 34
  low below it) green; all 517 insights fixture cases pass.
- Deviations: see "Wave 3b (P9 admin API, P10 insights and health)" above.
- Deferred (each with its reason in `.remake/wave3b_reports/integrate.md`):
  - Service helpers for what the routes compose today in one control.db transaction with `audit.record` and
    `bump_config_version`: `RulesService.delete_where` and `delete_bans`, `throttle.reset_limiter_state`,
    `passkey_rename` and one shared `revoke_sessions`.
  - (Done in review round 3: refusal events carry the rule rows that refused, and the attempts tabs show them.)
  - Trace fields on the Live row (`bucket_key`, `cooldown_source`, `egress_identity`), `RotatorPool.session_ages`
    (`GET /egress/sessions` answers `session_lifetimes: null`) and an AIMD history table (`GET /upstream/aimd` has no
    `history`); the routes label what is inferred or missing.
  - A metrics export mode (exports page through 250 rows today).
  - (Done by the tooling lane: `roxy-backup-request.path`; "Back up now" asks the root backup since review round
    3.)
  - For P11: every page item is collected in `.remake/P11_INPUTS.md` (the shell's `u.prefs` URL, the table macro's
    `size` and `dir`, the LLM export buttons, the Help page's runbook URLs and the rest).
- Open:
  - `UpstreamService.reset_state` clears only this worker's unshared cooldowns; another worker that kept one through
    a hot.db outage writes it back later (a reset epoch honored by the mirror loop would close it).
  - A reset canceled by shutdown leaves only its intent row (status "started") and holds the reset lease for up to 30
    minutes; two VACUUMs started in two workers at once are not prevented (the second waits on SQLite's lock);
    without `ip_hash_key` a client reset cannot match events; the bans and limiter resets keep exact counts in the
    audit row but no snapshot of the deleted rows.
  - Each worker's stream hub reads metrics.db and hot.db every 2 s while a stream is open on it; rows another worker
    sampled out are missing from the Live first page (the KPIs stay exact); a cache refresh is a real upstream call
    that can itself get a 429.
  - Tarpit statistics, the bot tracker, exit IPs and open rotator sessions are per worker and labeled `this_worker`;
    the fleet header's Expected count uses the answering worker's `ROXY_WORKERS` for both colors.
  - Plan 9.6 lists "change password" as a fresh second factor action, but no route changes the admin password yet;
    when one is added, the route security test fails until it is listed as sensitive.
  - A canceled dry run keeps its worker's single dry-run slot until its thread ends; a ban `subject` column is hashed
    in exports for place and User-Agent subjects too (conservative).
  - `test_gunicorn_wave3_jobs_run_on_one_leader` signs in over plain HTTP and sends the Secure session cookie by hand
    (nginx provides HTTPS in production).

### P10: insights engine, rules, LLM export and Check Proxy Health (wave 3b), 2026-10-08 to 2026-10-09

- Built (2026-10-08, six builders):
  - The engine core (`insights/`): the engine and its lifecycle, actions with compensation, auto-apply with watch
    windows and automatic rollback, the simulator, anomalies, the three core rules (UP-429-ENDPOINT, CACHE-TTL-TUNE,
    SYS-ERRORS), metrics.db schema 2 with nine history tables and the recorder hooks that fill them, and the fixture
    loader and harness. 287 tests; the plan 11.6 card comes out exactly (critical, 412 x 429, 71%, TTL 600 with SWR
    120 on a new GET,POST rule, `fallback_on_429` 1 to 0, `cache_post_requests` off to allowlist, endpoint bucket 120
    to 89 per minute, dry run 2,485 avoided calls of 2,845 samples, not safe_auto; 2,455 since review round 3,
    when the replay stopped storing answers the cache would not keep, finding insights-6).
  - The rules: 14 UP-* rules (173 tests), 15 cache, egress and credential rules (165 tests) and 18 abuse, filter,
    system and security rules (176 tests); with the 3 core rules, all 50 rules of the catalog. Every proposed change
    of the last group is also previewed through the actions module, so the apply path accepts it.
  - Check Proxy Health (`health/`, `admin/api/health.py`): the 34 checks of 13.2 (H-REACH per allowed host), the
    runner with one run at a time fleet-wide, the store, JSON, printable HTML and LLM reports, and the metrics.db
    schema 3 migration; 197 tests.
  - The LLM export (`insights/llm_export.py`, `admin/api/export_llm.py`, the committed
    `insights/schema/llm_export.v1.schema.json`): 38 tests, including the plan 12.5 injection fixture (the attacker
    text appears only under `untrusted`) and leak checks for the credential's 24-character windows, the rotator, SMTP
    and webhook secrets, the encryption keys and the admin's TOTP secret and session cookie.
- Fixtures: all 162 insights fixture files pass (517 cases with variants through
  `.remake/scripts/insights_core_smoke.py --all`, 0 skipped, 0 failed) and all 120 health fixture files (156 cases,
  36 of them variants). The P10 authors added 14 insights fixtures for branches the committed set did not reach and
  edited none; one committed file (`up_5xx__just_under_rate`) has header numbers that disagree with its rows, and
  every expectation holds under both readings.
- Integration and gate: see the P9 note; the 8823 run included `tests/insights` 840 and `tests/health` 187, plus
  `test_api_health.py` 10 and `test_api_export_llm.py` 11. Under real gunicorn with 2 workers and a state migrated as
  the deploy does it, one leader holds all 9 wave 3 leader jobs, `insights_evaluate`, `llm_export_file` and
  `health_publish_jobs` finish OK, the export file is written and no job fails or times out
  (`test_gunicorn_wave3_jobs_run_on_one_leader`). At start `insights_evaluate` took 0.53 s and `llm_export_file`
  0.86 s, later runs 0.02 s and 0.08 s, with a worst event loop lag of 84 ms during boot. A state at the previous
  release's schema upgrades with only the three new metrics.db expand migrations, and the previous release's
  statements still work on it (`test_storage_migrate_upgrade.py`).
- Reviews and fixes (2026-10-09): see the P9 note for the whole review. The P10 share: insights-1 to 14 (the
  LLM export trust rule, auto-apply guardrails and rollbacks, the dry run's store policy, sampling and windows, exact
  single-endpoint rules, trigger and cap bookkeeping, H-CLOCK, host deltas) and mpjobs-1, 2, 3, 6, 7 and 8 (fenced
  auto-apply, the digest checked inside the lease, 503 on a busy hot.db, the export off the event loop, the fleet-wide
  leader schedule, waiting rollbacks); all fixed. The plan 11.6 dry run is now 2,455 avoided calls (the fixture range
  is 2,230 to 2,800), and every one of the 162 insights fixture files still passes.
- Review round 4 (2026-10-09): see the P9 note. The P10 share: secfix-3 (the LLM export masks IPv6 subjects with the
  shared masker), LOGICFIX-2 (an update of a template's own legacy glob rule is not `safe_auto`, and the card says
  why; the independent fixture `up_429_endpoint__get_raise_ttl` now expects `safe_auto: false`, its one edit),
  LOGICFIX-3 (the 429 burst trigger survives a reset that reused ids), LOGICFIX-4 (a request Roblox never answered is
  not replayed as a stored answer), LOGICFIX-5 (limit dry runs replay the refused requests: metrics.db schema 7
  `refusal_samples`) and LOGICFIX-6 (each sample counts for the rate it was taken at: `request_samples.sample_pct`,
  else the settings history); all fixed. `tests/insights` 890 passed; the plan 11.6 dry run is still 2,455 avoided
  calls.
- Deviations: see "Wave 3b (P9 admin API, P10 insights and health)" above.
- Deferred (reasons in `.remake/wave3b_reports/integrate.md`):
  - Transaction-composable service variants (`update_in(conn, ...)` and the like), so apply and undo write in one
    control.db transaction instead of compensating.
  - (Done by the producers lane: rule hits for every rule table and challenge and HTML-body detection.) Still
    deferred: a per-arm User-Agent experiment counter and the 18.4 `credential_comparison` producer (CRED-UNUSED
    stays quiet).
  - Catalog additions are lead decisions: `insight_up_timeout_min_calls` (UP-TIMEOUT has no minimum sample) and
    promoting fixed readings to `insight_params`; memoized providers and de-duplicated queries are optional (parity
    tests guard the copies).
  - One owner for the 12.5 block. (`scripts/ctl.py export-llm` with its internal socket route and `advisories.json`
    at deploy were built by the tooling lane.)
- Open:
  - Production data still missing, so the rules that need it stay quiet or say so and never guess:
    `credential_comparison` events and a per-arm User-Agent counter (UP-UA-EXPERIMENT reads at most 50,000
    samples). The producers lane closed the other six gaps (rule hits, challenge and HTML-body flags, bot scores,
    tarpit hold statistics, a windowed fleet-wide drop counter, disk growth history).
  - The dry run's per-IP replay keys by address while the limiter groups IPv6 by prefix (a lower bound until the
    samples record the limiter key; since review round 4 it does see the refused requests, up to 6,000 refusal
    samples a minute per worker); requests while the cache is switched off carry no key id until the dry run models
    `cache_enabled`; CACHE-NEG still scales its refetch count by the live `request_sample_pct` (its evidence, not the
    dry run).
  - Every in-process test app's leader runs `insights_evaluate` and `llm_export_file` at start (the suite took about
    3 minutes longer); health checks in in-process tests log `health_check_failed` with a traceback when the socket
    guard refuses their DNS lookups (noise, not failures).
  - The 13.4 probe ids (universe 13058, group 1200769) come from knowledge of Roblox's public objects and were not
    checked against the live API; `LiveFacts` network paths run only through the fixture seam; H-E2E and H-NGINX fail
    when the host cannot reach its own public name (hairpin).
  - On the 11.6 fixture the full 7d LLM export is about 460 KB (the summary about 100 KB); while two API builds run,
    the hourly job's build is refused and the file waits an hour.
  - HOT-ENDPOINT and CACHE-LOW-HIT manual cards may be frequent on a server with no cache rules; FILTER-REMOVE's
    rollup fallback counts any header refusal as a hit for every header rule; under a spam storm some detections lose
    their subject to the recorder's event budget; the `x-csrf-token` age is not tracked (UP-CSRF-LOOP shows the
    setting).

### Lanes of wave 3b: producers, docs, parity table, tooling and CI, load harness, 2026-10-09

- Producers (`.remake/wave3b_reports/lane_producers.md`): six production data gaps closed (rule hits for every rule
  table, fleet-wide tarpit hold statistics, recorded bot scores, challenge and HTML-body flags per attempt with the
  rotator exit each call used, a windowed fleet-wide drop counter, disk growth history), metrics.db schema 5 with
  seven tables, all summed in memory and written by the batch flush; 61 new tests; the jobs were wired by the
  integration. Deviations: see "Lanes" under Wave 3b above.
- Docs (`lane_docs.md`): `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/RUNBOOKS.md` (38 runbooks and a
  machine-readable link index) and `docs/LEARNING_PATH.md` (the 12 chapters of plan 18.5), checked by
  `tests/unit/test_docs_references.py` (19 tests: every file, dotted name, test id, route, setting, script flag and
  anchor the guides name, the link index against the alert catalog and the health checks, and drift against the
  code). The integration linked the guides from `README.md` and `deploy/README.md` and added the new alert to the
  runbooks.
- Parity table (`lane_parity_table.md`, plan 19.11): `tests/V1_PARITY.md` has 781 rows, every v1 smoke check (735
  call sites) and deploy check (46): 365 covered by existing v2 tests, 233 by 37 new `tests/parity/` tests, 183
  intentionally changed, 0 empty; the 5 findings it pinned (17 rows) are fixed, so 0 rows are pinned by an open
  finding. `scripts/gen_v1_parity.py --check` runs in CI.
- Tooling and CI (`lane_tooling.md`): `scripts/ctl.py` (the operator CLI, 40 tests), `scripts/shadow_report.py` (14),
  the four operator routes of the internal socket with the one-use state directory proof, `roxy-backup-request.path`
  (12), `advisories.json` at deploy (14), and a rewritten `ci.yml` (32 workflow tests) whose jobs cover every test
  directory, `tests/deploy` included (parity row 102). CI has not run on GitHub yet: apt nginx and setup-uv in the
  containers, `playwright install --with-deps`, pip-audit's flags on the hashed export and the AppArmor sysctl are
  unproven until the first push.
- Load harness (`lane_load.md`, `docs/PERFORMANCE.md`): the harness puts client, mock and Roxy on one steady wall
  clock (the old one ran the mock about 9.5% lenient on WSL, which is why the replay test passed on one run and failed
  on the next); `pytest tests/load` 23 passed and 1 xfailed. The v1-like replay (10 requests a second, 200 s, cold
  cache, production defaults): about 1,020 upstream calls, 49.5 to 49.8% of calls avoided (row 7 asks 40%), and 2
  Roblox 429s (0.196%, against 0.1%) in 10 of 10 runs, all on avatar outfits whose busiest 60 s reached 61 calls
  against the mock's 60 (finding LOAD-1: the adaptive cut is taken from the configured rate, the burst is never cut;
  over 20 minutes 0.160% and 0.142%, over 30 minutes 0.095%). A lead decision; the assertion is a non-strict xfail and
  was not tuned. Also measured on the dev box (indicative): hit p99 26.9 ms and miss overhead p99 78 ms at 200 req/s,
  a throughput ceiling near 205 req/s from hot.db write lock waits (LOAD-3), and the leader worker growing from 157 to
  230 MiB over 33 minutes, past `MemoryHigh` under sustained load (LOAD-2). The quiet-machine rerun in
  `docs/PERFORMANCE.md` is the reference before release.

## Parity checklist (plan section 4)

Every row of plan section 4 (C3, plan 18.1 item 5) with its status and the tests that prove it. **covered**: the
row is built and tested. **partial**: names the phase that completes it; the listed tests cover the part that
exists. **changed**: what differs from the row, with the plan rule that allows it. Test ids are `file::test` under
`tests/` (parametrized tests are named without their parameters); every id was checked against
`pytest --collect-only` of the review round tree (7283 tests) on 2026-10-08. The base is the table of the wave 2 spec
review; after fix pass 1, rows 15, 47, 49 and 116 are covered, the rows it had as missing are filled in, and rows
that are an admin control or a live dashboard table (34, 41, 114, 118, 122, 125, 135) or an admin route (128) are
partial until their route (P9) and page (P11) exist, although the service helper each one needs is tested. The
review round changed no listed test id; it added its tests to rows 3, 7, 9, 26, 35, 39, 48, 49, 59, 60, 79, 82 and
116, and row 60's change now also says that a peeked entry is never fetched for a throttled caller.

Wave 3b (2026-10-09) added the admin API, insights, health and LLM export ids; each new id was checked against
`pytest --collect-only` of `tests/integration/admin_api`, `tests/insights`, `tests/health` and
`tests/security/test_admin_routes.py` (1330 tests), plus `tests/multiprocess/test_sse_mp.py` and
`tests/e2e/test_design_system_robustness.py`, on the wave 3b tree (8823 tests). Rows 38, 65, 88, 121 and 128 are
covered now. Every other row that waited for P9 or P10 has its API part and its tests and stays partial until its P11
page exists, so it now names only P11; row 78 also waits for a fleet-wide tarpit statistics history, which P10 did
not store. Wave 3b also added API tests to the covered rows 15, 25, 29, 32, 45, 116, 117 and 119 and to the P11 rows
114, 131, 132 and 134, and rows 45 and 75 now say what the admin side changed.

| # | Row | Status | Tests |
|---|---|---|---|
| 1 | Catch-all proxy, plus HEAD and OPTIONS | covered | `test_pipeline_e2e.py::test_options_and_head`, `test_proxy_router.py::test_options_answered_locally`, `test_proxy_router.py::test_head_runs_as_get`, `test_proxy_router.py::test_methods_outside_the_list_are_405`, `test_proxy_golden.py::test_head_and_options` |
| 2 | Repeated query params preserved | covered (the upstream query keeps the caller's order; see Wave 2) | `test_proxy_validate.py::test_repeated_params_preserved_in_caller_order`, `test_proxy_validate.py::test_property_query_round_trip`, `test_cache_keys.py::test_repeated_values_keep_arrival_order` |
| 3 | `?prettyprint=true` applied at serve time | covered | `test_proxy_respond.py::test_pretty_json_v1`, `test_proxy_golden.py::test_repeated_params_and_prettyprint`, `test_proxy_validate.py::test_prettyprint_rules`, `test_proxy_respond.py::test_prettyprint_applies_to_cached_and_error_bodies`, `test_rr_spec_compat_pretty.py::test_spec_6_cached_4xx_is_pretty_printed_in_compat_mode_like_v1`, `test_pipeline_e2e.py::test_compat_prettyprint_follows_v1_for_live_and_cached_4xx` |
| 4 | Browser `<pre>` view, raw JSON for others | covered | `test_proxy_context.py::test_is_browser_v1_heuristic`, `test_proxy_golden.py::test_non_json_upstream_type_replayed`, `test_proxy_golden.py::test_browser_gets_escaped_html_with_sandbox_csp` |
| 5 | Ordered refusal pipeline | covered | `test_abuse_pipeline_order.py::test_pipeline_order_is_the_design_order`, `test_abuse_pipeline_order.py::test_a_request_refused_later_spends_no_rate_budget`, `test_abuse_golden.py::test_throttled_client_probing_gets_429_not_404`, `test_ingress_refusal_order.py::test_pause_beats_a_ban`, `test_ingress_refusal_order.py::test_endpoint_block_beats_an_endpoint_rule` |
| 6 | Bypass allowlist semantics | covered | `test_abuse_golden.py::test_bypass_skips_limits_and_is_never_counted`, `test_abuse_golden.py::test_bypass_does_not_skip_filters`, `test_proxy_router.py::test_bypass_is_never_held`, `test_ingress_refusal_order.py::test_bypass_caller_refused_by_a_ban_is_never_held`, `test_abuse_switches_rules.py::test_bypass_expiry_defaults` |
| 7 | Refusal codes and bodies | covered | `test_proxy_golden.py::test_refusal_golden`, `test_pipeline_e2e.py::test_refusal_paused`, `test_pipeline_e2e.py::test_refusal_endpoint_block`, `test_abuse_review_fixes.py::test_r1_pause_message_default_setting_is_used`, `test_proxy_respond.py::test_refusal_body_is_v1_jsonify`, `test_rr_spec_disguise.py::test_spec_1_disguised_refusal_is_byte_identical_to_a_genuine_throttle` |
| 8 | `Roxy-*` response headers | covered | `test_proxy_golden.py::test_refusal_header_names_keep_v1_casing`, `test_proxy_respond.py::test_header_value_forms`, `test_proxy_respond.py::test_header_casing_preserved`, `test_abuse_golden.py::test_allow_carries_the_per_ip_trio` |
| 9 | Caller auth rejected (smuggling) | covered | `test_abuse_golden.py::test_auth_smuggling`, `test_abuse_switches_rules.py::test_auth_smuggling_detection`, `test_pipeline_e2e.py::test_refusal_auth_smuggling`, `test_credential_suite.py::test_public_markers_do_not_disable_egress`, `test_rr_cred_encoded_paste.py::test_encoded_credential_paste_never_lets_a_caller_disable_an_egress` |
| 10 | Header scrubbing (allowlist) | covered | `test_proxy_golden.py::test_header_allowlist_both_ways`, `test_proxy_scrub.py::test_forward_list_is_exactly_the_plan`, `test_proxy_scrub.py::test_leaky_v1_headers_never_forwarded`, `test_proxy_scrub.py::test_forward_list_equals_cache_key_vary_list` |
| 11 | API-shaped upstream headers | covered | `test_egress_headers.py::test_direct_and_credential_headers_are_api_shaped`, `test_egress_headers.py::test_rotator_profile_is_stable_and_coherent_per_session` |
| 12 | Home page with SEO data | covered | `test_public_pages.py::test_home_seo_parity_with_v1`, `test_public_pages.py::test_v1_home_links_survive`, `test_public_pages.py::test_live_limits_render_from_settings`, `test_public_pages.py::test_home_uses_details_for_collapsibles_and_site_text`, `test_public_pages.py::test_home_luau_examples_are_highlighted_and_copy_exactly` |
| 13 | robots.txt, sitemap.xml, favicon.ico | covered | `test_public_crawler_files.py::test_robots_txt_is_v1_byte_for_byte`, `test_public_crawler_files.py::test_sitemap_keeps_v1_bytes_and_adds_docs_and_status`, `test_public_pages.py::test_robots_sitemap_favicon`, `test_public_pages.py::test_visits_and_crawls_are_recorded` |
| 14 | `GET /health` | covered | `test_pipeline_e2e.py::test_public_health_and_post_health`, `test_review_loop_blocking.py::test_review_health_answers_at_once_while_the_disk_stalls` |
| 15 | Unknown `/admin` path is a 404, not a probe | covered | `test_pipeline_e2e.py::test_r2_unknown_admin_path_is_v1_not_found_and_not_a_probe`, `test_app_skeleton.py::test_unknown_admin_paths_get_the_v1_not_found`, `test_admin_auth_pages.py::test_allowlist_hides_admin_with_a_plain_404`, `test_api_common.py::test_unknown_api_paths_get_the_section13_404` |
| 16 | Client errors as probes, 5xx emailed | covered | `test_core_middleware.py::test_client_errors_reach_the_probe_hook`, `test_notify_notifier.py::test_unhandled_errors_raise_the_v1_error_alert`, `test_metrics_recorder.py::test_core_error_hooks_record_probes_and_errors` |
| 17 | Security headers | covered | `test_core_security_headers.py::test_page_csp_is_exactly_the_plan_policy`, `test_core_security_headers.py::test_other_security_headers_on_every_response`, `test_core_security_headers.py::test_hsts_only_when_enabled`, `test_core_security_headers.py::test_proxied_response_gets_sandbox_csp` |
| 18 | Static asset cache busting | covered | `test_core_templating.py::test_static_url_uses_content_hash`, `test_core_templating.py::test_hashed_static_files_cache_headers`, `test_public_pages.py::test_static_assets_are_hashed_and_immutable` |
| 19 | Visitor classification | covered | `test_metrics_visitors_catalog.py::test_classify`, `test_metrics_visitors_catalog.py::test_crawler_markers_equal_v1`, `test_metrics_recorder.py::test_visits_and_security_helpers`, `test_v1_visitors.py::test_v1_anonymous_admin_page_visits_are_counted_and_known_admins_are_not`, `test_v1_visitors.py::test_v1_the_owners_first_login_takes_back_its_own_admin_page_visit` |
| 20 | Egress paths: direct, credential, rotator | covered | `test_upstream_routing.py::test_default_is_direct_and_rotator_weight_zero_never_wins`, `test_upstream_routing.py::test_routing_never_selects_credential_for_non_allowlisted`, `test_credential_suite.py::test_credential_path_has_no_proxy`, `test_confinement_routing.py::test_caller_traffic_never_carries_the_credential` |
| 21 | Weighted egress choice and shift | covered | `test_upstream_routing.py::test_weights_split_traffic`, `test_upstream_routing.py::test_direct_shift_toward_rotator`, `test_upstream_routing.py::test_shift_uses_direct_fill` |
| 22 | Fallback policy, never onto the credential | covered | `test_upstream_no_cascade.py::test_no_cascade_to_the_credential_ever`, `test_upstream_service.py::test_429_fallback_never_onto_credential`, `test_upstream_status_policy.py::test_no_rule_retries_onto_another_egress_immediately_on_429` |
| 23 | CSRF retry with a cached token | covered | `test_upstream_service.py::test_csrf_handshake_with_cached_token`, `test_upstream_fleet.py::test_csrf_token_cached_for_every_worker` |
| 24 | Upstream status semantics | covered | `test_upstream_status_policy.py::test_classify_response`, `test_upstream_service.py::test_any_2xx_is_success`, `test_upstream_service.py::test_redirect_followed_within_allowed_hosts`, `test_upstream_service.py::test_5xx_retried_with_backoff_then_success`, `test_upstream_service.py::test_malformed_redirect_location_is_answered_not_raised` |
| 25 | Credential 429 cooldown and probes | covered | `test_upstream_service.py::test_credential_429_sets_fleet_cooldown_and_never_cascades`, `test_egress_credential.py::test_one_probe_at_a_time_fleet_wide`, `test_egress_credential.py::test_cooldown_is_fleet_wide_and_never_shortened`, `test_egress_credential.py::test_probe_outcomes`, `test_api_credential.py::test_a_probe_429_is_rate_limited_never_expired` |
| 26 | Credential replace, check, revalidate | partial: P11 (Credential page) | `test_credential_suite.py::test_single_credential_slot`, `test_credential_suite.py::test_superseded_bootstrap_never_reused`, `test_egress_credential.py::test_replace_is_encrypted_audited_and_reaches_other_workers`, `test_egress_credential.py::test_delete_ui_value_goes_back_to_the_bootstrap_value`, `test_rr_cred_audit_reason.py::test_replace_reason_never_stores_the_new_credential`, `test_api_credential.py::test_replace_and_return_to_the_bootstrap_account_with_typed_confirmations`, `test_api_credential.py::test_status_check_probes_and_budget` |
| 27 | `mask_token` | covered | `test_core_redact.py::test_mask_token_matches_v1_format` |
| 28 | Internal probes count against budgets | covered | `test_upstream_internal.py::test_internal_anonymous_call_is_paced_and_recorded`, `test_upstream_internal.py::test_internal_credential_call_uses_the_probe_sub_bucket`, `test_upstream_egress_contract.py::test_credential_probe_hook_is_paced_by_the_probe_bucket` |
| 29 | Internal endpoints list | covered | `test_upstream_internal.py::test_internal_endpoints_list`, `test_upstream_internal.py::test_probe_is_single_flight_fleet_wide`, `test_api_upstream.py::test_retries_and_internal_calls` |
| 30 | Rotation proxy URL | partial: P11 (Egress page) | `test_egress_rotator.py::test_url_replace_and_revert_are_audited_and_shared`, `test_egress_rotator.py::test_bootstrap_url_is_masked_and_registered`, `test_egress_rotator.py::test_an_empty_rotator_url_file_means_not_configured`, `test_api_egress.py::test_rotator_url_is_masked_replaced_and_reverted_without_leaking` |
| 31 | Rotator failure cooldown | covered | `test_egress_rotator.py::test_failure_streak_parks_the_rotator_fleet_wide`, `test_upstream_effects.py::test_rotator_429_counts_only_with_distinct_exits`, `test_upstream_fleet.py::test_rotator_429s_count_by_distinct_exits` |
| 32 | Exit IP probe and recent exits | covered | `test_egress_rotator.py::test_exit_ip_probe_parsing`, `test_egress_rotator.py::test_exit_ip_probe_errors_and_recent_ips`, `test_api_egress.py::test_exit_ips_are_masked_unless_revealed_and_the_reveal_is_audited` |
| 33 | `masked_url` | covered | `test_core_redact.py::test_masked_url_matches_v1`, `test_egress_rotator.py::test_proxy_url_parsing_and_masking_parity` |
| 34 | Routing state view and reset | partial: P11 (Upstream page) | `test_upstream_buckets.py::test_bucket_states_for_the_dashboard`, `test_upstream_breaker.py::test_reset_and_snapshot`, `test_upstream_service.py::test_reset_clears_cooldowns_and_breakers_never_buckets`, `test_api_upstream.py::test_buckets_show_fill_rates_and_history_and_a_reset_never_refills_them` |
| 35 | Fleet email dedupe | covered | `test_notify_gate.py::test_dedupe_within_the_cooldown_and_report_what_was_held_back`, `test_notify_notifier.py::test_two_workers_send_one_alert`, `test_review_c7_failure_modes.py::test_review_readonly_hot_alert_cap_still_holds`, `test_rr_mp_alerts.py::test_rr_mp_alert_cap_holds_for_the_hour_across_a_hot_db_outage`, `test_rr_auth_alert_dedupe_retention.py::test_long_cooldown_alert_stays_deduped_through_retention` |
| 36 | Busy and failed caller messages | covered | `test_upstream_messages_deadlines.py::test_exact_caller_texts`, `test_proxy_golden.py::test_7_13_row_golden` |
| 37 | Trace fields | covered | `test_upstream_service.py::test_trace_has_v1_fields`, `test_upstream_csrf_trace_aimd.py::test_trace_v1_fields_and_redaction` |
| 38 | Admin place lookup | covered | `test_upstream_internal.py::test_lookup_place_chain`, `test_upstream_internal.py::test_lookup_cache_expires`, `test_upstream_internal.py::test_lookup_runs_at_admin_priority`, `test_api_upstream.py::test_identify_an_experience_is_budgeted_cached_and_mapped`, `test_api_w3b_wiring.py::test_the_place_lookup_cache_is_shared_by_every_route` |
| 39 | Per-IP limit, fixed or GCRA | covered (cache hits count by default, owner D10) | `test_abuse_limiter.py::test_gcra_burst`, `test_abuse_limiter.py::test_fixed_window_v1_semantics`, `test_abuse_mp.py::test_gcra_at_exact_limit_never_refused`, `test_abuse_golden.py::test_fresh_cache_hits_count_by_default`, `test_abuse_golden.py::test_fresh_cache_hits_are_not_counted_with_the_setting_off`, `test_rr_mp_degraded.py::test_rr_mp_leaving_degraded_mode_never_refills_the_allowance`, `test_rr_mp_degraded.py::test_rr_mp_degraded_share_never_multiplies_a_small_limit` |
| 40 | Escalating ladder | covered | `test_abuse_throttle.py::test_ladder_penalties_double_per_rung_fixed_mode`, `test_abuse_throttle.py::test_decays_in_counts_to_the_next_drop_not_zero`, `test_abuse_throttle.py::test_strike_on_retry_adds_at_most_one_strike_per_window`, `test_defaults.py::test_throttle_ladder_is_v1_with_the_c5_message`, `test_service.py::test_ladder_validation_uses_v1_wording` |
| 41 | Strike board and forgive | partial: P11 (Protection page) | `test_abuse_throttle.py::test_strike_board_forgive_and_watch`, `test_api_protection.py::test_strike_board_forgive_watch_and_export` |
| 42 | Throttle-all (emergency per-IP limit) | covered | `test_abuse_golden.py::test_throttle_all_default_text_and_headers`, `test_abuse_review_fixes.py::test_r1_throttle_all_without_a_reason_shares_the_pause_default`, `test_pipeline_e2e.py::test_refusal_throttle_all`, `test_ingress_refusal_order.py::test_throttle_all_beats_the_per_ip_throttle` |
| 43 | Endpoint rate rules | covered | `test_abuse_golden.py::test_endpoint_rule`, `test_abuse_golden.py::test_endpoint_rule_is_clamped_to_the_per_ip_allowance`, `test_abuse_golden.py::test_global_endpoint_rule_is_shared`, `test_service.py::test_a_second_rate_rule_on_the_same_pattern_is_refused` |
| 44 | User-Agent rules and tester | covered | `test_abuse_golden.py::test_ua_burst_rule`, `test_abuse_golden.py::test_ua_cooldown_rule_and_custom_message`, `test_abuse_golden.py::test_ua_rules_master_switch`, `test_abuse_switches_rules.py::test_ua_rules_first_match_and_tester_reflects_the_switch`, `test_ingress_redos.py::test_timed_out_header_and_ua_regexes_refuse` |
| 45 | Header filter rules and tester | covered (tester samples hold only the User-Agent and Roblox-Id lines; see Wave 3b) | `test_abuse_golden.py::test_header_filter_disguised`, `test_abuse_golden.py::test_header_filter_custom_message`, `test_abuse_switches_rules.py::test_header_rule_semantics_and_tester`, `test_api_protection.py::test_header_rules_crud_tester_and_presets` |
| 46 | Endpoint blocks | covered | `test_abuse_golden.py::test_endpoint_block`, `test_ingress_redos.py::test_timed_out_block_regex_refuses` |
| 47 | Tarpit | covered | `test_abuse_tarpit.py::test_effective_cap_formula_defaults`, `test_abuse_tarpit.py::test_fails_closed_without_shared_state`, `test_abuse_tarpit.py::test_arrival_gap_is_measured_across_refusals`, `test_abuse_cooldown_retry.py::test_r3_retry_inside_retry_after_is_jitter_tarpitted`, `test_proxy_router.py::test_tarpit_hold`, `test_proxy_router.py::test_tarpit_drip`, `test_abuse_mp.py::test_tarpit_cap_holds_under_contention_across_processes` |
| 48 | Login lockout | covered | `test_admin_auth_lockout.py::test_reserve_counts_before_checking_and_refuses_at_the_limit`, `test_auth_lockout.py::test_two_workers_share_one_count`, `test_auth_lockout.py::test_window_slides`, `test_auth_global_guard.py::test_guard_slows_but_never_refuses`, `test_rr_auth_lockout_retention.py::test_lockout_window_longer_than_an_hour_survives_retention` |
| 49 | Pause with reason and schedule | covered | `test_abuse_golden.py::test_pause_default`, `test_abuse_golden.py::test_pause_reason_and_scheduled_window`, `test_abuse_review_fixes.py::test_r1_pause_message_default_setting_is_used`, `test_abuse_switches_rules.py::test_schedule_and_clear`, `test_migration_service_state.py::test_migration_paused_v1_starts_paused`, `test_rr_spec_pause_retry_after.py::test_spec_9_scheduled_retry_after_covers_the_rest_of_the_window`, `test_rr_spec_state_reasons.py::test_spec_2_switch_reasons_never_store_a_dash` |
| 50 | Ignored paths | covered | `test_abuse_golden.py::test_ignored_path`, `test_service.py::test_ignored_paths_refuse_roblox_endpoints` |
| 51 | Probe logging | covered | `test_abuse_golden.py::test_unsafe_url`, `test_abuse_golden.py::test_not_roblox`, `test_metrics_security_events.py::test_probe_signature`, `test_v1_public.py::test_v1_proxy_probes_reach_the_probe_log`, `test_abuse_security_records.py::test_proxy_probes_reach_the_security_probe_log`, `test_v1_public.py::test_v1_post_to_the_home_page_is_a_json_405_with_allow` |
| 52 | Two cache tiers | covered | `test_cache_store_parts.py::test_memory_tier_lru_and_caps`, `test_cache_purge.py::test_purge_invalidates_memory_tier_in_another_process`, `test_cache_workers.py::test_a_store_in_one_worker_is_a_hit_in_another` |
| 53 | Cache key format and ids | changed: ambiguous names and values are percent-encoded, POST keys carry the full SHA-256 of the body and forwarded caller headers are part of the key, so those ids differ from v1; plain GET ids are unchanged (sections 3 and 9 over row 53; LEAD_NOTES 9, plan 9.13) | `test_cache_keys.py::test_v1_worked_examples_keep_their_ids`, `test_cache_keys.py::test_cache_key_poisoning_case_lead_notes_9`, `test_cache_keys.py::test_body_hash_is_full_sha256_and_get_bodies_are_ignored`, `test_cache_keys.py::test_key_text_is_one_to_one` |
| 54 | Ignored cache params | covered | `test_cache_keys.py::test_ignored_params_are_exact_case_sensitive_and_remembered`, `test_cache_service.py::test_ignored_params_share_one_entry`, `test_defaults.py::test_ignored_params_are_the_v1_suggestions_without_v` |
| 55 | Cache rules | covered | `test_cache_policy.py::test_rule_selection_respects_methods_and_default_switch`, `test_cache_policy.py::test_rule_lifetimes`, `test_defaults.py::test_every_default_cache_rule_validates_and_has_a_note` |
| 56 | Cache TTL policy and negative entries | covered | `test_cache_policy.py::test_definitive_errors_are_negative_entries`, `test_cache_policy.py::test_429_becomes_a_marker_until_the_cooldown_ends`, `test_cache_policy.py::test_store_2xx_all_cacheable_v1_b4_fixed`, `test_cache_service.py::test_negative_entries_replay_their_status` |
| 57 | Cached methods: GET, POST allowlist | covered | `test_cache_policy.py::test_post_modes`, `test_pipeline_e2e.py::test_cache_post_allowlist`, `test_defaults.py::test_post_allowlist_is_read_only_lookups` |
| 58 | Stale on error, SWR, stale during cooldown | covered | `test_cache_service.py::test_stale_after_failure`, `test_cache_service.py::test_revalidating_serves_at_once_and_refreshes_once`, `test_cache_service.py::test_stale_during_upstream_cooldown_without_contacting_roblox`, `test_pipeline_e2e.py::test_cache_revalidating` |
| 59 | Coalescing (fleet-wide single-flight) | covered | `test_singleflight.py::test_followers_in_another_worker_get_the_outcome_not_a_call`, `test_singleflight_mp.py::test_concurrent_requests_in_many_processes_make_one_upstream_call`, `test_singleflight_mp.py::test_owner_failure_costs_one_upstream_call_not_n`, `test_review_failure_modes_mp.py::test_review_unstored_large_answer_costs_one_upstream_call`, `test_rr_mp_singleflight.py::test_rr_mp_followers_get_the_stored_answer_when_the_owner_goes_before_publishing` |
| 60 | Serve throttled callers from cache | changed: served only when no later static check would refuse; v1 step 4a served before the filters (sections 3 and 9 over row 60); the peeked entry is served even if it expired during the verdict, never fetched for the throttled caller (review round INGRESS-3) | `test_proxy_router.py::test_throttled_caller_served_from_fresh_cache`, `test_abuse_review_fixes.py::test_throttled_cache_serve_only_without_a_later_refusal`, `test_ingress_refusal_order.py::test_a_throttled_request_a_filter_refuses_is_never_served_from_cache`, `test_abuse_golden.py::test_throttled_cache_serve_flag`, `test_rr_ingress_peek_race.py::test_an_over_limit_caller_never_reaches_roblox_through_an_entry_that_expires_during_the_verdict` |
| 61 | Respect `Cache-Control: no-cache` | covered | `test_cache_policy.py::test_caller_no_cache_only_when_respected`, `test_cache_service.py::test_bypass_with_respected_no_cache` |
| 62 | Bounded disk tier and eviction | covered | `test_cache_purge.py::test_maintenance_removes_dead_rows_first_then_evicts_cold_entries`, `test_cache_purge.py::test_byte_budget_counts_stored_size`, `test_cache_policy.py::test_store_skips_zero_lifetime_and_oversize` |
| 63 | Buffered hit counting | covered | `test_cache_service.py::test_hits_and_change_observations_are_flushed`, `test_cache_store_parts.py::test_hit_buffer_is_bounded_and_restorable` |
| 64 | Cache disk health | covered | `test_cache_store_parts.py::test_disk_health_recovers_after_a_later_write`, `test_cache_service.py::test_disk_write_failure_keeps_serving_from_memory`, `test_cache_flights.py::test_failed_cache_db_write_is_counted_and_the_answer_unaffected` |
| 65 | Key spread diagnostic | covered (the apply route is built, the P11 Recommendations page draws the button; CACHE-KEYSPLIT never proposes ignoring a text or id parameter, see Wave 3b) | `test_cache_spread.py::test_cache_buster_is_suspect_like_v1_smoke`, `test_cache_spread.py::test_large_groups_can_still_be_suspect_b9_fixed`, `test_cache_purge.py::test_admin_views_and_key_spread`, `test_rules_cache_egress.py::test_rule_fixture`, `test_rules_cache_egress.py::test_text_and_id_parameters_are_never_ignored`, `test_rules_cache_egress.py::test_spread_rows_match_the_shared_tier`, `test_api_cache.py::test_key_spread_finds_the_splitting_parameter`, `test_api_recommendations.py::test_apply_then_undo_through_the_audited_services` |
| 66 | Cache browser, inspect, purge, refresh | partial: P11 (Cache page) | `test_cache_purge.py::test_purge_scopes_report_true_counts`, `test_cache_purge.py::test_purge_host_regex_expired_and_all`, `test_cache_workers.py::test_purge_reaches_the_other_workers_memory_tier`, `test_cache_purge.py::test_admin_views_and_key_spread`, `test_api_cache.py::test_browser_search_sort_page_and_hidden_handoff_rows`, `test_api_cache.py::test_inspect_and_refresh_a_get_entry`, `test_api_cache.py::test_refresh_a_post_entry_resends_its_body`, `test_api_cache.py::test_purge_every_scope_is_audited_first`, `test_r3_parity_cache.py::test_parity_15_purge_matching_purges_exactly_what_the_search_lists`, `test_r3_parity_cache.py::test_parity_15_search_purge_removes_exactly_the_listed_entries_and_nothing_else` |
| 67 | Cache stats and honest avoided calls | partial: P11 (Cache page) | `test_metrics_queries.py::test_avoided_calls_are_honest`, `test_metrics_recorder.py::test_upstream_429_internal_background_and_egress`, `test_cache_service.py::test_hits_and_change_observations_are_flushed`, `test_api_cache.py::test_stats_are_honest`, `test_api_overview.py::test_kpi_tiles_are_honest_and_carry_sparklines_and_deltas` |
| 68 | Status codes by source | partial: P11 (Traffic page) | `test_metrics_recorder.py::test_dims_row_holds_every_dimension`, `test_metrics_recorder.py::test_cache_state_and_source_strings`, `test_metrics_queries.py::test_series_reads_compacted_levels_plus_the_tail`, `test_api_traffic.py::test_status_sources_and_the_429_verdict`, `test_r3_parity_overview.py::test_parity_1_a_roblox_5xx_counts_as_5xx_from_roblox` |
| 69 | Request counts and traffic over time | partial: P11 (Overview and Traffic pages) | `test_metrics_rollups.py::test_minutes_compact_into_hours_exactly`, `test_metrics_rollups.py::test_days_and_months_in_ui_timezone`, `test_metrics_queries.py::test_comparison_windows`, `test_metrics_pipeline.py::test_flush_loop_compaction_and_queries`, `test_metrics_mp.py::test_metric_totals_equal_requests_sent`, `test_api_traffic.py::test_requests_stacked_by_outcome_with_compare`, `test_api_traffic.py::test_verbs_series_and_table_with_export`, `test_api_traffic.py::test_trend_tables`, `test_r3_parity_overview.py::test_parity_2_overview_has_the_v1_failures_last_hour_tile` |
| 70 | Latency percentiles | partial: P11 (Traffic and Upstream pages) | `test_metrics_histograms.py::test_merge_is_element_wise_addition`, `test_metrics_histograms.py::test_percentile_interpolates_inside_the_bucket`, `test_metrics_histograms.py::test_percentile_error_is_bounded_by_the_bucket_width`, `test_metrics_histograms.py::test_sql_functions_merge_and_sum`, `test_api_traffic.py::test_latency_series_and_splits`, `test_api_upstream.py::test_latency_series_are_percentiles_of_upstream_requests` |
| 71 | Method health per egress and host | partial: P11 (Upstream page) | `test_metrics_queries.py::test_filters_are_whitelisted`, `test_metrics_queries.py::test_misc_read_models`, `test_metrics_recorder.py::test_errors_are_upserted_and_redacted`, `test_api_upstream.py::test_egress_cards_and_host_table_report_honest_rates`, `test_r3_parity_upstream.py::test_parity_6_egress_cards_carry_v1_method_health`, `test_v1_upstream.py::test_v1_egress_health_says_when_it_last_worked_and_what_failed_last` |
| 72 | Failure, refusal, internal and error logs | partial: P11 (Upstream, Protection and System pages) | `test_metrics_recorder.py::test_refusal_events_are_budgeted_but_counts_stay_exact`, `test_metrics_recorder.py::test_upstream_429_internal_background_and_egress`, `test_metrics_recorder.py::test_errors_are_upserted_and_redacted`, `test_metrics_recorder.py::test_aggregated_events_wait_for_their_minute_to_close`, `test_api_upstream.py::test_retries_and_internal_calls`, `test_api_system.py::test_errors_are_searchable_and_tracebacks_redacted`, `test_api_protection.py::test_bot_pipeline_and_refusals_for_the_range`, `test_r3_parity_upstream.py::test_parity_5_upstream_failures_log_exists`, `test_r3_parity_protection.py::test_parity_3_refusal_reasons_keep_the_v1_columns` |
| 73 | Top talkers and callers with rates | partial: P11 (Clients page) | `test_metrics_clients.py::test_minute_keeps_top_n_and_folds_the_rest`, `test_metrics_clients.py::test_trailing_rate_has_no_minute_boundary_flap`, `test_metrics_queries.py::test_client_table_with_rates`, `test_storage_retention.py::test_place_clients_follow_max_caller_records`, `test_api_clients.py::test_ip_table_rates_flags_bot_score_sort_search_and_export`, `test_api_clients.py::test_place_table_page_actions_and_lookup_cache`, `test_r3_parity_clients.py::test_parity_7_client_tables_keep_last_seen_and_peers`, `test_metrics_client_extras.py::test_peer_counts_across_levels_count_each_peer_once`, `test_api_clients.py::test_recorded_fleet_scores_answer_when_no_live_row_exists` |
| 74 | Endpoint popularity with templating | partial: P11 (Endpoints page; labels scrubbed, C1 over row 74) | `test_metrics_templating.py::test_v1_worked_examples`, `test_metrics_templating.py::test_templatize_equals_v1_on_generated_paths`, `test_metrics_templating.py::test_vocabulary_gate_bounds_distinct_values`, `test_metrics_labels.py::test_template_for_scrubs_a_piece_in_a_route_word`, `test_metrics_queries.py::test_top_n_pages_and_sorts_on_the_server`, `test_api_endpoints.py::test_table_sorts_pages_and_trends`, `test_api_endpoints.py::test_drill_down`, `test_r3_parity_endpoints.py::test_parity_13_endpoint_rows_keep_methods_and_last_request`, `test_r3_parity_endpoints.py::test_parity_13_last_request_falls_back_to_the_rollup_minute` |
| 75 | Blocked and rate-limited attempt logs | partial: P11 (Protection page); the attempts tabs count distinct clients instead of showing the last IP (plan 9.15 over row 75) and, since review round 3, name the rule that refused (`refused_by`; see Wave 3b) | `test_abuse_pipeline_order.py::test_stats_count_refusals_by_check`, `test_metrics_recorder.py::test_refusal_events_are_budgeted_but_counts_stay_exact`, `test_api_protection.py::test_endpoint_blocks_rules_and_attempts`, `test_abuse_security_records.py::test_a_refusal_event_names_the_rule_that_refused` |
| 76 | Throttle tier and UA rule hits | partial: P11 (Protection page) | `test_abuse_review_fixes.py::test_record_throttled_and_aggregated_tier_and_ua_rule_events`, `test_api_protection.py::test_ladder_replace_reset_and_tier_hits`, `test_api_protection.py::test_ua_rules_crud_order_hits_and_tester`, `test_producers_rule_hits.py::test_every_matched_rule_row_is_on_the_verdict_and_recorded`, `test_r3_fix_pages_lane.py::test_rule_tables_carry_hits_and_one_rule_has_a_hit_history` |
| 77 | Budget rejections and peaks | partial: P11 (Upstream page; the bucket fill history is stored since P10) | `test_upstream_buckets.py::test_bucket_states_for_the_dashboard`, `test_upstream_buckets.py::test_fill_levels`, `test_engine.py::test_recorder_history_hooks_and_read_models`, `test_rules_upstream.py::test_up_bucket_tune_numbers_and_safe_auto`, `test_api_upstream.py::test_buckets_show_fill_rates_and_history_and_a_reset_never_refills_them` |
| 78 | Tarpit stats | partial: P11 (Protection page); the fleet-wide hold statistics history is stored and served since the producers lane (`GET /protection/tarpit` `history`) | `test_abuse_tarpit.py::test_arrival_gap_is_measured_across_refusals`, `test_abuse_tarpit.py::test_over_the_cap_is_instant_and_counted_as_skipped`, `test_ingress_exhaustion.py::test_tarpit_stats_tables_are_bounded`, `test_api_protection.py::test_tarpit_state_has_the_effective_cap_fields`, `test_producers_tarpit_stats.py::test_holds_are_recorded_with_category_kind_and_hold_time`, `test_producers_tarpit_stats.py::test_skips_and_the_gaps_after_a_hold_and_after_an_instant_refusal`, `test_r3_fix_pages_lane.py::test_tarpit_card_has_the_fleet_hold_statistics_of_the_range` |
| 79 | Header and User-Agent fingerprints | partial: P11 (Security page) | `test_metrics_fingerprints.py::test_secret_shaped_plain_values_are_stored_hashed`, `test_metrics_fingerprints.py::test_counts_add_up_across_workers_and_values_are_capped_per_header`, `test_metrics_fingerprints.py::test_auto_ignore_is_central_and_not_double_counted`, `test_metrics_jobs.py::test_rules_ignore_header_writes_an_audited_auto_entry`, `test_rr_cred_fingerprint_names.py::test_fingerprint_header_names_never_store_a_credential_piece`, `test_api_security.py::test_fingerprints_values_user_agents_blocked_and_ignored_headers`, `test_api_w3b_wiring.py::test_passing_requests_are_fingerprinted_and_filtered_ones_count_as_blocked`, `test_r3_parity_security.py::test_parity_11_one_headers_values_can_be_cleared_and_the_header_removed` |
| 80 | Probe, login, crawl and throttled rings | partial: P11 (Security page) | `test_metrics_security_events.py::test_probe_signature`, `test_metrics_security_events.py::test_ring_pages_newest_first_with_filters`, `test_metrics_security_events.py::test_summaries`, `test_metrics_security_events.py::test_login_events_via_recorder`, `test_public_pages.py::test_visits_and_crawls_are_recorded`, `test_api_security.py::test_probes_ring_summary_and_crawls`, `test_api_security.py::test_logins_and_failed_logins`, `test_api_protection.py::test_throttled_history_from_the_throttled_events`, `test_v1_public.py::test_v1_proxy_probes_reach_the_probe_log` |
| 81 | Live request feed | partial: P11 (Live page) | `test_metrics_live.py::test_tail_delivers_rows_from_any_writer`, `test_metrics_live.py::test_backfill_for_last_event_id`, `test_metrics_live.py::test_filter_covers_every_field`, `test_metrics_pipeline.py::test_live_tail_sees_every_worker`, `test_design_system.py::test_live_tail_streams_pauses_and_resumes_after_last_event_id`, `test_api_live.py::test_rows_newest_first_with_filters`, `test_api_live.py::test_cursor_pages_back_without_gaps`, `test_sse.py::test_kpi_then_filtered_live_rows`, `test_sse_mp.py::test_a_stream_on_worker_a_delivers_what_worker_b_recorded` |
| 82 | Capture with redaction, TTL and caps | covered | `test_metrics_capture.py::test_headers_query_url_and_bodies_are_redacted`, `test_metrics_capture.py::test_write_enforces_count_bytes_and_ttl`, `test_metrics_capture.py::test_refusals_always_served_sampled`, `test_metrics_capture_encoder.py::test_queue_is_bounded_by_count_and_drops_without_waiting`, `test_review_loop_blocking.py::test_review_large_capture_is_not_encoded_on_the_loop`, `test_rr_cred_capture_header_names.py::test_captured_header_names_never_hold_a_credential_piece` |
| 83 | Section clears (granular resets) | partial: P11 (Data page and the inline reset menus) | `test_metrics_queries.py::test_kpis_compare_and_reset_notice`, `test_api_data.py::test_family_reset_preview_phrase_snapshot_audit_and_annotation`, `test_api_data.py::test_reset_listing_maps_every_v1_clear_target`, `test_api_data.py::test_date_range_reset_deletes_only_inside_the_range`, `test_r3_parity_data.py::test_parity_8_clearing_cache_stats_keeps_ratios_honest_and_requests`, `test_r3_parity_data.py::test_parity_9_clearing_one_attempts_tab_keeps_the_others`, `test_r3_parity_data.py::test_parity_12_kpi_delta_over_a_reset_window_is_replaced_by_a_notice`, `test_metrics_reset_scope.py::test_a_reset_of_another_family_leaves_the_tiles_and_the_page_alone`, `test_v1_metrics.py::test_v1_a_reset_counter_resumes_from_zero_and_nothing_comes_back` |
| 84 | Worker fleet registry | partial: P11 (System page) | `test_scheduler_heartbeat.py::test_beat_writes_the_parity_row_84_fields`, `test_scheduler_heartbeat.py::test_fleet_view_marks_fresh_stale_and_this_worker`, `test_scheduler_heartbeat.py::test_loop_lag_monitor_measures_a_blocked_loop`, `test_scheduler_heartbeat.py::test_beat_sync_and_rss`, `test_api_system.py::test_fleet_has_the_parity_row_84_fields_and_both_colors`, `test_api_w3b_wiring.py::test_the_heartbeat_feeds_the_worker_minute_history` |
| 85 | Persistence and store sizes | partial: P11 (System and Data pages) | `test_review_loop_blocking.py::test_review_health_answers_at_once_while_the_disk_stalls`, `test_storage_retention.py::test_run_retention_works_in_batches_and_vacuums`, `test_api_system.py::test_metrics_pipeline_and_persistence`, `test_api_data.py::test_storage_has_every_database_and_table_with_a_projection`, `test_api_data.py::test_retention_view_lists_the_settings_and_each_tables_state`, `test_r3_fix_pages_lane.py::test_system_shows_fleet_drops_and_the_disk_growth_history`, `test_r3_parity_data.py::test_parity_10_retention_view_lists_every_data_retention_setting` |
| 86 | Threat banner, now recommendations | partial: P11 (Overview card and Recommendations page) | `test_engine.py::test_lifecycle_open_update_resolve_reopen`, `test_rules_core.py::test_before_after_11_6_card`, `test_api_recommendations.py::test_list_filters_counts_paging_and_export`, `test_api_recommendations.py::test_apply_then_undo_through_the_audited_services`, `test_api_overview.py::test_top_recommendations_most_severe_first` |
| 87 | Glossary, help dots, setting help, simulations | partial: P11 (pages and simulations) | `test_ui_static.py::test_glossary_has_every_plan_section_21_term`, `test_ui_static.py::test_glossary_includes_the_v1_dashboard_terms`, `test_ui_templates.py::test_setting_control_renders_every_catalog_setting`, `test_design_system.py::test_tooltips_for_help_dots_and_glossary_terms` |
| 88 | CSV and JSON exports | covered (IP columns are hashed unless `export_include_ips`; see Wave 3b) | `test_ui_gallery.py::test_export_guards_spreadsheet_formulas`, `test_api_common.py::test_csv_and_json_exports_are_guarded_named_and_audited`, `test_api_common.py::test_exports_follow_the_ip_privacy_settings`, `test_api_data.py::test_dataset_exports`, `test_llm_export.py::test_export_of_a_fixture_database_validates_against_the_schema`, `test_llm_export.py::test_injection_fixture_appears_only_under_untrusted`, `test_llm_export.py::test_no_secret_appears_in_the_export`, `test_api_export_llm.py::test_summary_validates_and_every_download_is_audited`, `test_api_export_llm.py::test_the_leader_job_writes_the_hourly_file` |
| 89 | Server-side sorting and paging | partial: P11 | `test_metrics_queries.py::test_top_n_pages_and_sorts_on_the_server`, `test_ui_gallery.py::test_table_fragment_sorts_filters_and_pages_on_the_server`, `test_design_system.py::test_table_paging_sorting_search_and_columns`, `test_api_common.py::test_table_paging_sorting_and_search`, `test_api_settings.py::test_prefs_json_and_form_updates_are_validated_and_stored_per_admin` |
| 90 | Live updates over SSE | partial: P11 | `test_ui_gallery.py::test_stream_resumes_after_last_event_id`, `test_design_system.py::test_live_tail_streams_pauses_and_resumes_after_last_event_id`, `test_sse.py::test_kpi_then_filtered_live_rows`, `test_sse.py::test_last_event_id_resumes_exactly`, `test_sse.py::test_a_resume_that_cannot_catch_up_says_so`, `test_sse.py::test_a_revoked_session_ends_the_stream_with_401` |
| 91 | Section jump, now the command palette | partial: P11 (palette search over the real pages) | `test_design_system.py::test_command_palette_and_shortcuts`, `test_ui_gallery.py::test_palette_search_is_bounded`, `test_design_system_robustness.py::test_single_key_shortcuts_can_be_turned_off_and_stay_off` |
| 92 | Identify an experience | partial: P11 (Clients page) | `test_upstream_internal.py::test_lookup_place_chain`, `test_upstream_internal.py::test_lookup_rejects_non_numeric`, `test_api_clients.py::test_place_table_page_actions_and_lookup_cache`, `test_api_clients.py::test_lookup_errors_are_section13` |
| 93 | Health check button | partial: P11 (Health page) | `test_upstream_internal.py::test_probe_credential_verdicts`, `test_egress_rotator.py::test_exit_ip_probe_errors_and_recent_ips`, `test_health_fixtures.py::test_health_fixture`, `test_runner.py::test_catalog_covers_every_13_2_check_once`, `test_api_health.py::test_a_run_starts_streams_and_reads_back`, `test_api_health.py::test_the_credential_check_needs_a_fresh_second_factor` |
| 94 | Admin login with password (argon2id) | covered | `test_admin_auth_passwords.py::test_production_parameters_are_the_plan_values`, `test_admin_auth_passwords.py::test_unknown_user_verifies_against_a_dummy_hash_and_fails`, `test_admin_auth_flow.py::test_wrong_password_is_403_invalid_credentials_and_unknown_user_looks_the_same`, `test_auth_argon2_thread.py::test_argon2_runs_off_the_loop_thread` |
| 95 | Login bound to IP and UA | covered | `test_admin_auth_flow.py::test_transaction_is_bound_to_ip_and_user_agent_and_expires` |
| 96 | Second factor: TOTP, passkeys, email fallback | covered | `test_admin_auth_flow.py::test_password_then_totp_logs_in_and_sends_the_login_alert`, `test_admin_auth_flow.py::test_bootstrap_login_uses_email_then_forces_enrollment`, `test_admin_auth_flow.py::test_email_resend_replaces_the_code_and_is_rate_limited`, `test_admin_auth_flow.py::test_passkey_registration_and_login`, `test_admin_auth_flow.py::test_recovery_code_works_once`, `test_auth_uniform_404.py::test_every_second_factor_failure_looks_identical` |
| 97 | Lockout with exploit-log reasons | covered | `test_admin_auth_lockout.py::test_reserve_counts_before_checking_and_refuses_at_the_limit`, `test_auth_lockout.py::test_parallel_guesses_cannot_pass_the_limit`, `test_auth_lockout.py::test_two_workers_share_one_count`, `test_metrics_security_events.py::test_login_events_via_recorder` |
| 98 | Sessions | covered | `test_auth_cookies.py::test_session_and_trusted_cookie_flags`, `test_auth_sessions.py::test_login_never_adopts_a_planted_session_id`, `test_auth_sessions.py::test_only_hashes_are_stored`, `test_admin_auth_flow.py::test_heartbeat_extends_only_with_recent_input`, `test_admin_auth_flow.py::test_session_absolute_lifetime`, `test_auth_sessions.py::test_sign_out_everywhere_bumps_the_epoch` |
| 99 | Login alert with the kill-switch link | covered | `test_admin_auth_pages.py::test_kill_switch_get_confirms_post_consumes_once`, `test_admin_auth_pages.py::test_kill_switch_can_spare_passkey_sessions`, `test_auth_sessions.py::test_kill_switch_also_revokes_trusted_devices`, `test_notify_notifier.py::test_login_body_keeps_the_kill_switch_link_and_scrubs_the_rest` |
| 100 | Trusted devices | covered | `test_admin_auth_flow.py::test_trusted_device_skips_only_the_second_factor`, `test_admin_auth_pages.py::test_trusted_devices_list_and_revoke`, `test_admin_auth_parts.py::test_ua_family_ignores_versions_but_not_browsers` |
| 101 | Logout | covered | `test_admin_auth_pages.py::test_logout_deletes_the_server_side_session`, `test_auth_cookies.py::test_logout_and_dead_sessions_clear_the_cookie` |
| 102 | Deploy on push, blue/green, gated | partial: P14 (`deploy.yml` stays disabled until the cutover); CI runs `tests/deploy` since the tooling lane | `test_deploy_sh.py::test_v1_1_clean_deploy`, `test_deploy_sh.py::test_failed_health_gate_rolls_back`, `test_deploy_sh.py::test_failure_after_the_switch_switches_back`, `test_deploy_sh.py::test_commit_not_on_main_is_refused`, `test_deploy_sh.py::test_workflow_bootstrap_installs_a_missing_deploy_script`, `test_deploy_ci_workflow.py::test_every_test_directory_runs_in_ci`, `test_deploy_ci_workflow.py::test_deploy_stays_disabled_until_the_cutover` |
| 103 | Per-release venv | covered | `test_deploy_sh.py::test_v1_7_redeploy_of_a_built_release_reuses_it`, `test_deploy_sh.py::test_v1_8_failed_build_leaves_a_usable_environment`, `test_deploy_sh.py::test_keeps_the_newest_five_releases`, `test_deploy_sh.py::test_release_ships_compiled_bytecode` |
| 104 | systemd unit hardening | covered | `test_deploy_units.py::test_roxy_unit_has_the_plan_17_1_directive`, `test_deploy_units.py::test_memory_numbers_fit_the_909_mb_server`, `test_deploy_units.py::test_systemd_analyze_verify`, `test_deploy_units.py::test_exposure_score_is_ok`, `test_deploy_units.py::test_app_boots_under_the_unit_sandbox` |
| 105 | OnFailure alert | covered | `test_deploy_alert.py::test_one_alert_per_unit_per_ten_minutes`, `test_deploy_alert.py::test_redact_removes_secrets`, `test_deploy_alert.py::test_webhook_failure_is_a_failure_too`, `test_deploy_alert.py::test_end_to_end_with_system_python`, `test_deploy_units.py::test_alert_unit` |
| 106 | nginx config | covered | `test_deploy_nginx.py::test_nginx_t_accepts_the_rendered_site`, `test_deploy_nginx.py::test_every_location_that_reaches_the_app_is_rate_limited`, `test_deploy_nginx.py::test_internal_is_404_and_never_proxied`, `test_deploy_nginx.py::test_kill_switch_token_is_never_logged`, `test_deploy_nginx.py::test_live_floods_never_reach_the_app_unlimited`, `test_deploy_wrappers.py::test_apply_installs_the_verified_files` |
| 107 | Deploy runbook | partial: P12 part two (`docs/RUNBOOKS.md`) | none yet |
| 108 | v1 smoke suite, deploy test, boot check | partial: P14 (the boot check); the smoke suite and deploy test parts are covered by `tests/V1_PARITY.md` (781 rows, 0 empty, checked by `gen_v1_parity.py --check` in CI) | `test_deploy_sh.py::test_v1_1_clean_deploy`, `test_deploy_sh.py::test_v1_3_fetch_failure_must_not_brick_the_server`, `test_deploy_smoke_remote.py::test_each_check_fails_when_its_condition_breaks`, `test_check_style.py::test_v1_test_suites_are_scanned_and_clean`, `test_gen_v1_parity.py::test_the_committed_table_is_complete_current_and_cites_real_tests` |
| 109 | Secrets as systemd credentials | covered | `test_core_env.py::test_systemd_credentials_directory_wins`, `test_core_env.py::test_no_accessor_for_the_roblox_credential`, `test_migration_credentials.py::test_migration_credential_files_and_modes`, `test_migration_v1_files.py::test_files_listing_outside_root_is_never_followed`, `test_deploy_units.py::test_roxy_unit_lists_and_order` |
| 110 | Worker recycling | covered | `test_deploy_gunicorn.py::test_settings_follow_plan_5_2`, `test_deploy_gunicorn.py::test_max_requests_zero_disables_recycling` |
| 111 | Shared matcher semantics | covered (the credential allowlist is exact; see Wave 2) | `test_match.py::test_v1_rule_match_parity`, `test_match.py::test_v1_rule_match_corpus_parity`, `test_match.py::test_v1_best_match_parity`, `test_match.py::test_exact_patterns_grant_no_implicit_subpath` |
| 112 | Canonical header rule id | covered | `test_match.py::test_header_rule_canonical_key_parity`, `test_service.py::test_header_rule_duplicates_are_rejected`, `test_service.py::test_imported_header_rule_keeps_its_v1_key_on_edit`, `test_service.py::test_opposite_regex_header_rules_are_two_rules` |
| 113 | "Bypass my IP" | partial: P11 | `test_abuse_switches_rules.py::test_bypass_my_ip_and_never_needs_confirmation`, `test_api_protection.py::test_bypass_deny_and_bypass_my_ip` |
| 114 | Pause and throttle-all drop counters and banners | partial: P11 (top bar banners) | `test_metrics_queries.py::test_drops_since_refusal_reasons_retries_visitors`, `test_api_protection.py::test_pause_message_schedule_and_drops_since`, `test_api_protection.py::test_throttle_all_limit_since_marker_and_watch` |
| 115 | Enabling throttle-all starts a new count | covered | `test_abuse_switches_rules.py::test_enabling_throttle_all_records_a_new_since_marker` |
| 116 | Custom message vs Roblox body split | covered | `test_proxy_router.py::test_message_source_tells_roxy_text_from_roblox_body`, `test_metrics_queries.py::test_drops_since_refusal_reasons_retries_visitors`, `test_rr_spec_message_source.py::test_spec_4_upstream_refusal_records_its_message_source`, `test_api_protection.py::test_bot_pipeline_and_refusals_for_the_range` |
| 117 | Retry counts by status and reason | covered | `test_metrics_queries.py::test_drops_since_refusal_reasons_retries_visitors`, `test_upstream_service.py::test_csrf_handshake_with_cached_token`, `test_api_upstream.py::test_retries_and_internal_calls` |
| 118 | Throttle watch table | partial: P11 (Protection page) | `test_abuse_throttle.py::test_strike_board_forgive_and_watch`, `test_api_protection.py::test_strike_board_forgive_watch_and_export` |
| 119 | Session-expired overlay | covered | `test_design_system.py::test_session_expired_overlay_on_any_401_and_stay`, `test_design_system.py::test_session_expired_overlay_redirects_to_login`, `test_design_system_robustness.py::test_session_overlay_keeps_other_dialogs_and_ignores_the_palette`, `test_design_system_robustness.py::test_live_tail_marks_a_gap_and_stops_for_good_on_unauthorized` |
| 120 | `GET /admin` sends a signed-in admin to the dashboard | partial: P11 (the dashboard page it redirects to) | `test_admin_auth_flow.py::test_login_page_and_logged_in_redirect` |
| 121 | Forced metrics flush | covered | `test_api_system.py::test_forced_flush_writes_this_workers_metrics_and_asks_every_worker`, `test_api_system.py::test_watcher_flushes_and_clears_memory_when_another_worker_asks`, `test_ctl.py::test_flush_metrics_asks_every_worker` |
| 122 | Workers "reset counts" | partial: P11 (System page) | `test_scheduler_heartbeat.py::test_reset_counts_is_adopted_by_every_worker`, `test_api_system.py::test_reset_counts_zeroes_every_worker_and_is_audited` |
| 123 | Tarpit state fields and reasons | covered | `test_abuse_tarpit.py::test_state_fields`, `test_abuse_tarpit.py::test_effective_cap_formula_defaults`, `test_proxy_router.py::test_tarpit_gets_the_v1_reason_string` |
| 124 | Per-setting "Reset to default" | partial: P11 (settings pages) | `test_settings_service.py::test_reset_to_default`, `test_ui_templates.py::test_setting_control_renders_every_catalog_setting`, `test_api_settings.py::test_put_one_key_and_reset_it_to_default`, `test_api_protection.py::test_protection_settings_patch_reset_and_refusals` |
| 125 | Ladder "reset to defaults" | partial: P11 (Protection page) | `test_service.py::test_replace_and_reset_the_ladder`, `test_api_protection.py::test_ladder_replace_reset_and_tier_hits` |
| 126 | Live feed entry fields | covered | `test_metrics_live.py::test_live_entry_has_every_row_126_field`, `test_proxy_router.py::test_event_carries_the_optional_recorder_fields` |
| 127 | Capture never fails a request | covered | `test_metrics_recorder.py::test_record_outcome_never_raises`, `test_metrics_recorder.py::test_capture_errors_never_fail_the_request`, `test_metrics_capture_encoder.py::test_a_failing_capture_is_counted_and_the_thread_goes_on`, `test_proxy_router.py::test_recorder_failure_never_fails_the_request` |
| 128 | Expired capture message | covered | `test_metrics_capture.py::test_v1_expired_message_is_exact`, `test_metrics_capture.py::test_get_capture_and_expiry`, `test_api_live.py::test_capture_detail_expired_and_not_captured` |
| 129 | `POST /health` is 404 | covered | `test_pipeline_e2e.py::test_public_health_and_post_health` |
| 130 | Overview visitor KPIs | partial: P11 | `test_metrics_queries.py::test_drops_since_refusal_reasons_retries_visitors`, `test_metrics_visitors_catalog.py::test_classify`, `test_metrics_recorder.py::test_visits_and_security_helpers`, `test_api_overview.py::test_visitors_card`, `test_api_security.py::test_probes_ring_summary_and_crawls`, `test_v1_visitors.py::test_v1_anonymous_admin_page_visits_are_counted_and_known_admins_are_not`, `test_v1_visitors.py::test_v1_the_owners_first_login_takes_back_its_own_admin_page_visit` |
| 131 | Proxy timings split toggle | partial: P11 (Traffic page) | `test_metrics_recorder.py::test_dims_row_holds_every_dimension`, `test_api_traffic.py::test_latency_series_and_splits` |
| 132 | Status codes source split | partial: P11 (Traffic page) | `test_metrics_recorder.py::test_cache_state_and_source_strings`, `test_api_traffic.py::test_status_sources_and_the_429_verdict`, `test_r3_parity_overview.py::test_parity_1_a_roblox_5xx_counts_as_5xx_from_roblox` |
| 133 | "What's Being Stored" | partial: P11 (Data page) | `test_api_data.py::test_storage_has_every_database_and_table_with_a_projection` |
| 134 | Blocked fingerprints | partial: P11 (Security page) | `test_metrics_recorder.py::test_fingerprints_flow_and_blocked_variant`, `test_api_security.py::test_fingerprints_values_user_agents_blocked_and_ignored_headers`, `test_api_w3b_wiring.py::test_passing_requests_are_fingerprinted_and_filtered_ones_count_as_blocked`, `test_r3_parity_security.py::test_parity_14_blocked_fingerprints_export_as_csv` |
| 135 | Throttle-all watch | partial: P11 (Protection page) | `test_abuse_switches_rules.py::test_throttle_all_watch`, `test_api_protection.py::test_throttle_all_limit_since_marker_and_watch`, `test_r3_parity_protection.py::test_parity_4_throttle_all_watch_keeps_the_v1_columns` |

Plan sections 7 and 10, which the rows above lean on: every 7.9 policy row
(`test_upstream_status_policy.py::test_outcome_policy_row`) and every 7.13 row
(`test_proxy_golden.py::test_7_13_row_golden`, `test_pipeline_e2e.py::test_row_roblox_4xx`) is tested, the 7.8
queue horizon too (`test_upstream_buckets.py::test_priority_horizon_is_the_max_wait`), and the 10.6 cap formula and
the 10.7 bot weights match the plan (`test_abuse_tarpit.py::test_effective_cap_formula_defaults`,
`test_abuse_bot_challenge.py::test_default_weights_match_the_plan`).

Counts: 135 rows; 87 covered, 2 changed, 46 partial.

## Writing style (plan C5)

- The v1 test suites kept under `tests/` (`smoke_test.py`, `deploy_test.sh`, `boot_check.sh`) are scanned by
  `scripts/check_style.py` like every other file; the dashes they had were all in comments and were rewritten.
- **C5 replacement in the admin login script (P8).** v1's `admin.js` said "This code has expired", a dash, then
  "send a new one."; v2 says `This code has expired; send a new one.` (LEAD_NOTES decision 5).
- **Vendored libraries.** The style walk skips `src/roxy/static/vendor` and `tests/e2e/vendor`; the reason is under
  "Design system (P11a)" above.
