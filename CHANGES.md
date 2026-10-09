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
| 15 | Unknown `/admin` path is a 404, not a probe | covered | `test_pipeline_e2e.py::test_r2_unknown_admin_path_is_v1_not_found_and_not_a_probe`, `test_app_skeleton.py::test_unknown_admin_paths_get_the_v1_not_found`, `test_admin_auth_pages.py::test_allowlist_hides_admin_with_a_plain_404` |
| 16 | Client errors as probes, 5xx emailed | covered | `test_core_middleware.py::test_client_errors_reach_the_probe_hook`, `test_notify_notifier.py::test_unhandled_errors_raise_the_v1_error_alert`, `test_metrics_recorder.py::test_core_error_hooks_record_probes_and_errors` |
| 17 | Security headers | covered | `test_core_security_headers.py::test_page_csp_is_exactly_the_plan_policy`, `test_core_security_headers.py::test_other_security_headers_on_every_response`, `test_core_security_headers.py::test_hsts_only_when_enabled`, `test_core_security_headers.py::test_proxied_response_gets_sandbox_csp` |
| 18 | Static asset cache busting | covered | `test_core_templating.py::test_static_url_uses_content_hash`, `test_core_templating.py::test_hashed_static_files_cache_headers`, `test_public_pages.py::test_static_assets_are_hashed_and_immutable` |
| 19 | Visitor classification | covered | `test_metrics_visitors_catalog.py::test_classify`, `test_metrics_visitors_catalog.py::test_crawler_markers_equal_v1`, `test_metrics_recorder.py::test_visits_and_security_helpers` |
| 20 | Egress paths: direct, credential, rotator | covered | `test_upstream_routing.py::test_default_is_direct_and_rotator_weight_zero_never_wins`, `test_upstream_routing.py::test_routing_never_selects_credential_for_non_allowlisted`, `test_credential_suite.py::test_credential_path_has_no_proxy`, `test_confinement_routing.py::test_caller_traffic_never_carries_the_credential` |
| 21 | Weighted egress choice and shift | covered | `test_upstream_routing.py::test_weights_split_traffic`, `test_upstream_routing.py::test_direct_shift_toward_rotator`, `test_upstream_routing.py::test_shift_uses_direct_fill` |
| 22 | Fallback policy, never onto the credential | covered | `test_upstream_no_cascade.py::test_no_cascade_to_the_credential_ever`, `test_upstream_service.py::test_429_fallback_never_onto_credential`, `test_upstream_status_policy.py::test_no_rule_retries_onto_another_egress_immediately_on_429` |
| 23 | CSRF retry with a cached token | covered | `test_upstream_service.py::test_csrf_handshake_with_cached_token`, `test_upstream_fleet.py::test_csrf_token_cached_for_every_worker` |
| 24 | Upstream status semantics | covered | `test_upstream_status_policy.py::test_classify_response`, `test_upstream_service.py::test_any_2xx_is_success`, `test_upstream_service.py::test_redirect_followed_within_allowed_hosts`, `test_upstream_service.py::test_5xx_retried_with_backoff_then_success`, `test_upstream_service.py::test_malformed_redirect_location_is_answered_not_raised` |
| 25 | Credential 429 cooldown and probes | covered | `test_upstream_service.py::test_credential_429_sets_fleet_cooldown_and_never_cascades`, `test_egress_credential.py::test_one_probe_at_a_time_fleet_wide`, `test_egress_credential.py::test_cooldown_is_fleet_wide_and_never_shortened`, `test_egress_credential.py::test_probe_outcomes` |
| 26 | Credential replace, check, revalidate | partial: P9 (credential API), P11 (Credential page) | `test_credential_suite.py::test_single_credential_slot`, `test_credential_suite.py::test_superseded_bootstrap_never_reused`, `test_egress_credential.py::test_replace_is_encrypted_audited_and_reaches_other_workers`, `test_egress_credential.py::test_delete_ui_value_goes_back_to_the_bootstrap_value`, `test_rr_cred_audit_reason.py::test_replace_reason_never_stores_the_new_credential` |
| 27 | `mask_token` | covered | `test_core_redact.py::test_mask_token_matches_v1_format` |
| 28 | Internal probes count against budgets | covered | `test_upstream_internal.py::test_internal_anonymous_call_is_paced_and_recorded`, `test_upstream_internal.py::test_internal_credential_call_uses_the_probe_sub_bucket`, `test_upstream_egress_contract.py::test_credential_probe_hook_is_paced_by_the_probe_bucket` |
| 29 | Internal endpoints list | covered | `test_upstream_internal.py::test_internal_endpoints_list`, `test_upstream_internal.py::test_probe_is_single_flight_fleet_wide` |
| 30 | Rotation proxy URL | partial: P9 (replace and revert routes), P11 (Egress page) | `test_egress_rotator.py::test_url_replace_and_revert_are_audited_and_shared`, `test_egress_rotator.py::test_bootstrap_url_is_masked_and_registered`, `test_egress_rotator.py::test_an_empty_rotator_url_file_means_not_configured` |
| 31 | Rotator failure cooldown | covered | `test_egress_rotator.py::test_failure_streak_parks_the_rotator_fleet_wide`, `test_upstream_effects.py::test_rotator_429_counts_only_with_distinct_exits`, `test_upstream_fleet.py::test_rotator_429s_count_by_distinct_exits` |
| 32 | Exit IP probe and recent exits | covered | `test_egress_rotator.py::test_exit_ip_probe_parsing`, `test_egress_rotator.py::test_exit_ip_probe_errors_and_recent_ips` |
| 33 | `masked_url` | covered | `test_core_redact.py::test_masked_url_matches_v1`, `test_egress_rotator.py::test_proxy_url_parsing_and_masking_parity` |
| 34 | Routing state view and reset | partial: P9, P11 (Upstream page) | `test_upstream_buckets.py::test_bucket_states_for_the_dashboard`, `test_upstream_breaker.py::test_reset_and_snapshot`, `test_upstream_service.py::test_reset_clears_cooldowns_and_breakers_never_buckets` |
| 35 | Fleet email dedupe | covered | `test_notify_gate.py::test_dedupe_within_the_cooldown_and_report_what_was_held_back`, `test_notify_notifier.py::test_two_workers_send_one_alert`, `test_review_c7_failure_modes.py::test_review_readonly_hot_alert_cap_still_holds`, `test_rr_mp_alerts.py::test_rr_mp_alert_cap_holds_for_the_hour_across_a_hot_db_outage`, `test_rr_auth_alert_dedupe_retention.py::test_long_cooldown_alert_stays_deduped_through_retention` |
| 36 | Busy and failed caller messages | covered | `test_upstream_messages_deadlines.py::test_exact_caller_texts`, `test_proxy_golden.py::test_7_13_row_golden` |
| 37 | Trace fields | covered | `test_upstream_service.py::test_trace_has_v1_fields`, `test_upstream_csrf_trace_aimd.py::test_trace_v1_fields_and_redaction` |
| 38 | Admin place lookup | partial: P9 (`admin/api/lookup.py`) | `test_upstream_internal.py::test_lookup_place_chain`, `test_upstream_internal.py::test_lookup_cache_expires`, `test_upstream_internal.py::test_lookup_runs_at_admin_priority` |
| 39 | Per-IP limit, fixed or GCRA | covered (cache hits count by default, owner D10) | `test_abuse_limiter.py::test_gcra_burst`, `test_abuse_limiter.py::test_fixed_window_v1_semantics`, `test_abuse_mp.py::test_gcra_at_exact_limit_never_refused`, `test_abuse_golden.py::test_fresh_cache_hits_count_by_default`, `test_abuse_golden.py::test_fresh_cache_hits_are_not_counted_with_the_setting_off`, `test_rr_mp_degraded.py::test_rr_mp_leaving_degraded_mode_never_refills_the_allowance`, `test_rr_mp_degraded.py::test_rr_mp_degraded_share_never_multiplies_a_small_limit` |
| 40 | Escalating ladder | covered | `test_abuse_throttle.py::test_ladder_penalties_double_per_rung_fixed_mode`, `test_abuse_throttle.py::test_decays_in_counts_to_the_next_drop_not_zero`, `test_abuse_throttle.py::test_strike_on_retry_adds_at_most_one_strike_per_window`, `test_defaults.py::test_throttle_ladder_is_v1_with_the_c5_message`, `test_service.py::test_ladder_validation_uses_v1_wording` |
| 41 | Strike board and forgive | partial: P9, P11 (Protection page) | `test_abuse_throttle.py::test_strike_board_forgive_and_watch` |
| 42 | Throttle-all (emergency per-IP limit) | covered | `test_abuse_golden.py::test_throttle_all_default_text_and_headers`, `test_abuse_review_fixes.py::test_r1_throttle_all_without_a_reason_shares_the_pause_default`, `test_pipeline_e2e.py::test_refusal_throttle_all`, `test_ingress_refusal_order.py::test_throttle_all_beats_the_per_ip_throttle` |
| 43 | Endpoint rate rules | covered | `test_abuse_golden.py::test_endpoint_rule`, `test_abuse_golden.py::test_endpoint_rule_is_clamped_to_the_per_ip_allowance`, `test_abuse_golden.py::test_global_endpoint_rule_is_shared`, `test_service.py::test_a_second_rate_rule_on_the_same_pattern_is_refused` |
| 44 | User-Agent rules and tester | covered | `test_abuse_golden.py::test_ua_burst_rule`, `test_abuse_golden.py::test_ua_cooldown_rule_and_custom_message`, `test_abuse_golden.py::test_ua_rules_master_switch`, `test_abuse_switches_rules.py::test_ua_rules_first_match_and_tester_reflects_the_switch`, `test_ingress_redos.py::test_timed_out_header_and_ua_regexes_refuse` |
| 45 | Header filter rules and tester | covered | `test_abuse_golden.py::test_header_filter_disguised`, `test_abuse_golden.py::test_header_filter_custom_message`, `test_abuse_switches_rules.py::test_header_rule_semantics_and_tester` |
| 46 | Endpoint blocks | covered | `test_abuse_golden.py::test_endpoint_block`, `test_ingress_redos.py::test_timed_out_block_regex_refuses` |
| 47 | Tarpit | covered | `test_abuse_tarpit.py::test_effective_cap_formula_defaults`, `test_abuse_tarpit.py::test_fails_closed_without_shared_state`, `test_abuse_tarpit.py::test_arrival_gap_is_measured_across_refusals`, `test_abuse_cooldown_retry.py::test_r3_retry_inside_retry_after_is_jitter_tarpitted`, `test_proxy_router.py::test_tarpit_hold`, `test_proxy_router.py::test_tarpit_drip`, `test_abuse_mp.py::test_tarpit_cap_holds_under_contention_across_processes` |
| 48 | Login lockout | covered | `test_admin_auth_lockout.py::test_reserve_counts_before_checking_and_refuses_at_the_limit`, `test_auth_lockout.py::test_two_workers_share_one_count`, `test_auth_lockout.py::test_window_slides`, `test_auth_global_guard.py::test_guard_slows_but_never_refuses`, `test_rr_auth_lockout_retention.py::test_lockout_window_longer_than_an_hour_survives_retention` |
| 49 | Pause with reason and schedule | covered | `test_abuse_golden.py::test_pause_default`, `test_abuse_golden.py::test_pause_reason_and_scheduled_window`, `test_abuse_review_fixes.py::test_r1_pause_message_default_setting_is_used`, `test_abuse_switches_rules.py::test_schedule_and_clear`, `test_migration_service_state.py::test_migration_paused_v1_starts_paused`, `test_rr_spec_pause_retry_after.py::test_spec_9_scheduled_retry_after_covers_the_rest_of_the_window`, `test_rr_spec_state_reasons.py::test_spec_2_switch_reasons_never_store_a_dash` |
| 50 | Ignored paths | covered | `test_abuse_golden.py::test_ignored_path`, `test_service.py::test_ignored_paths_refuse_roblox_endpoints` |
| 51 | Probe logging | covered | `test_abuse_golden.py::test_unsafe_url`, `test_abuse_golden.py::test_not_roblox`, `test_metrics_security_events.py::test_probe_signature` |
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
| 65 | Key spread diagnostic | partial: P10 (rule CACHE-KEYSPLIT with its apply button) | `test_cache_spread.py::test_cache_buster_is_suspect_like_v1_smoke`, `test_cache_spread.py::test_large_groups_can_still_be_suspect_b9_fixed`, `test_cache_purge.py::test_admin_views_and_key_spread` |
| 66 | Cache browser, inspect, purge, refresh | partial: P9 (cache API, POST refresh), P11 (Cache page) | `test_cache_purge.py::test_purge_scopes_report_true_counts`, `test_cache_purge.py::test_purge_host_regex_expired_and_all`, `test_cache_workers.py::test_purge_reaches_the_other_workers_memory_tier`, `test_cache_purge.py::test_admin_views_and_key_spread` |
| 67 | Cache stats and honest avoided calls | partial: P9, P11 (Cache page) | `test_metrics_queries.py::test_avoided_calls_are_honest`, `test_metrics_recorder.py::test_upstream_429_internal_background_and_egress`, `test_cache_service.py::test_hits_and_change_observations_are_flushed` |
| 68 | Status codes by source | partial: P9, P11 (Traffic page) | `test_metrics_recorder.py::test_dims_row_holds_every_dimension`, `test_metrics_recorder.py::test_cache_state_and_source_strings`, `test_metrics_queries.py::test_series_reads_compacted_levels_plus_the_tail` |
| 69 | Request counts and traffic over time | partial: P9, P11 | `test_metrics_rollups.py::test_minutes_compact_into_hours_exactly`, `test_metrics_rollups.py::test_days_and_months_in_ui_timezone`, `test_metrics_queries.py::test_comparison_windows`, `test_metrics_pipeline.py::test_flush_loop_compaction_and_queries`, `test_metrics_mp.py::test_metric_totals_equal_requests_sent` |
| 70 | Latency percentiles | partial: P9, P11 | `test_metrics_histograms.py::test_merge_is_element_wise_addition`, `test_metrics_histograms.py::test_percentile_interpolates_inside_the_bucket`, `test_metrics_histograms.py::test_percentile_error_is_bounded_by_the_bucket_width`, `test_metrics_histograms.py::test_sql_functions_merge_and_sum` |
| 71 | Method health per egress and host | partial: P9, P11 | `test_metrics_queries.py::test_filters_are_whitelisted`, `test_metrics_queries.py::test_misc_read_models`, `test_metrics_recorder.py::test_errors_are_upserted_and_redacted` |
| 72 | Failure, refusal, internal and error logs | partial: P9, P11 | `test_metrics_recorder.py::test_refusal_events_are_budgeted_but_counts_stay_exact`, `test_metrics_recorder.py::test_upstream_429_internal_background_and_egress`, `test_metrics_recorder.py::test_errors_are_upserted_and_redacted`, `test_metrics_recorder.py::test_aggregated_events_wait_for_their_minute_to_close` |
| 73 | Top talkers and callers with rates | partial: P9 (place names through the lookup), P11 | `test_metrics_clients.py::test_minute_keeps_top_n_and_folds_the_rest`, `test_metrics_clients.py::test_trailing_rate_has_no_minute_boundary_flap`, `test_metrics_queries.py::test_client_table_with_rates`, `test_storage_retention.py::test_place_clients_follow_max_caller_records` |
| 74 | Endpoint popularity with templating | partial: P9, P11 (labels scrubbed, C1 over row 74) | `test_metrics_templating.py::test_v1_worked_examples`, `test_metrics_templating.py::test_templatize_equals_v1_on_generated_paths`, `test_metrics_templating.py::test_vocabulary_gate_bounds_distinct_values`, `test_metrics_labels.py::test_template_for_scrubs_a_piece_in_a_route_word`, `test_metrics_queries.py::test_top_n_pages_and_sorts_on_the_server` |
| 75 | Blocked and rate-limited attempt logs | partial: P9, P11 | `test_abuse_pipeline_order.py::test_stats_count_refusals_by_check`, `test_metrics_recorder.py::test_refusal_events_are_budgeted_but_counts_stay_exact` |
| 76 | Throttle tier and UA rule hits | partial: P9, P11 (read models of the Protection page) | `test_abuse_review_fixes.py::test_record_throttled_and_aggregated_tier_and_ua_rule_events` |
| 77 | Budget rejections and peaks | partial: P10 (bucket fill history storage), P11 | `test_upstream_buckets.py::test_bucket_states_for_the_dashboard`, `test_upstream_buckets.py::test_fill_levels` |
| 78 | Tarpit stats | partial: P10 (stats history storage), P11 | `test_abuse_tarpit.py::test_arrival_gap_is_measured_across_refusals`, `test_abuse_tarpit.py::test_over_the_cap_is_instant_and_counted_as_skipped`, `test_ingress_exhaustion.py::test_tarpit_stats_tables_are_bounded` |
| 79 | Header and User-Agent fingerprints | partial: P9, P11 | `test_metrics_fingerprints.py::test_secret_shaped_plain_values_are_stored_hashed`, `test_metrics_fingerprints.py::test_counts_add_up_across_workers_and_values_are_capped_per_header`, `test_metrics_fingerprints.py::test_auto_ignore_is_central_and_not_double_counted`, `test_metrics_jobs.py::test_rules_ignore_header_writes_an_audited_auto_entry`, `test_rr_cred_fingerprint_names.py::test_fingerprint_header_names_never_store_a_credential_piece` |
| 80 | Probe, login, crawl and throttled rings | partial: P9, P11 (Security page) | `test_metrics_security_events.py::test_probe_signature`, `test_metrics_security_events.py::test_ring_pages_newest_first_with_filters`, `test_metrics_security_events.py::test_summaries`, `test_metrics_security_events.py::test_login_events_via_recorder`, `test_public_pages.py::test_visits_and_crawls_are_recorded` |
| 81 | Live request feed | partial: P9 (stream route), P11 (Live page) | `test_metrics_live.py::test_tail_delivers_rows_from_any_writer`, `test_metrics_live.py::test_backfill_for_last_event_id`, `test_metrics_live.py::test_filter_covers_every_field`, `test_metrics_pipeline.py::test_live_tail_sees_every_worker`, `test_design_system.py::test_live_tail_streams_pauses_and_resumes_after_last_event_id` |
| 82 | Capture with redaction, TTL and caps | covered | `test_metrics_capture.py::test_headers_query_url_and_bodies_are_redacted`, `test_metrics_capture.py::test_write_enforces_count_bytes_and_ttl`, `test_metrics_capture.py::test_refusals_always_served_sampled`, `test_metrics_capture_encoder.py::test_queue_is_bounded_by_count_and_drops_without_waiting`, `test_review_loop_blocking.py::test_review_large_capture_is_not_encoded_on_the_loop`, `test_rr_cred_capture_header_names.py::test_captured_header_names_never_hold_a_credential_piece` |
| 83 | Section clears (granular resets) | partial: P9 (reset routes), P11 (Data page) | `test_metrics_queries.py::test_kpis_compare_and_reset_notice` |
| 84 | Worker fleet registry | partial: P9, P11 (System page) | `test_scheduler_heartbeat.py::test_beat_writes_the_parity_row_84_fields`, `test_scheduler_heartbeat.py::test_fleet_view_marks_fresh_stale_and_this_worker`, `test_scheduler_heartbeat.py::test_loop_lag_monitor_measures_a_blocked_loop`, `test_scheduler_heartbeat.py::test_beat_sync_and_rss` |
| 85 | Persistence and store sizes | partial: P9, P11 (System page) | `test_review_loop_blocking.py::test_review_health_answers_at_once_while_the_disk_stalls`, `test_storage_retention.py::test_run_retention_works_in_batches_and_vacuums` |
| 86 | Threat banner, now recommendations | partial: P10 (recommendation engine), P11 | none yet (the rule fixtures wait in `tests/fixtures/insights/`) |
| 87 | Glossary, help dots, setting help, simulations | partial: P11 (pages and simulations) | `test_ui_static.py::test_glossary_has_every_plan_section_21_term`, `test_ui_static.py::test_glossary_includes_the_v1_dashboard_terms`, `test_ui_templates.py::test_setting_control_renders_every_catalog_setting`, `test_design_system.py::test_tooltips_for_help_dots_and_glossary_terms` |
| 88 | CSV and JSON exports | partial: P9 (export routes), P10 (LLM export) | `test_ui_gallery.py::test_export_guards_spreadsheet_formulas` |
| 89 | Server-side sorting and paging | partial: P9, P11 | `test_metrics_queries.py::test_top_n_pages_and_sorts_on_the_server`, `test_ui_gallery.py::test_table_fragment_sorts_filters_and_pages_on_the_server`, `test_design_system.py::test_table_paging_sorting_search_and_columns` |
| 90 | Live updates over SSE | partial: P9, P11 | `test_ui_gallery.py::test_stream_resumes_after_last_event_id`, `test_design_system.py::test_live_tail_streams_pauses_and_resumes_after_last_event_id` |
| 91 | Section jump, now the command palette | partial: P11 (palette search over the real pages) | `test_design_system.py::test_command_palette_and_shortcuts`, `test_ui_gallery.py::test_palette_search_is_bounded`, `test_design_system_robustness.py::test_single_key_shortcuts_can_be_turned_off_and_stay_off` |
| 92 | Identify an experience | partial: P9, P11 (Clients page) | `test_upstream_internal.py::test_lookup_place_chain`, `test_upstream_internal.py::test_lookup_rejects_non_numeric` |
| 93 | Health check button | partial: P10 (health suite), P11 | `test_upstream_internal.py::test_probe_credential_verdicts`, `test_egress_rotator.py::test_exit_ip_probe_errors_and_recent_ips` |
| 94 | Admin login with password (argon2id) | covered | `test_admin_auth_passwords.py::test_production_parameters_are_the_plan_values`, `test_admin_auth_passwords.py::test_unknown_user_verifies_against_a_dummy_hash_and_fails`, `test_admin_auth_flow.py::test_wrong_password_is_403_invalid_credentials_and_unknown_user_looks_the_same`, `test_auth_argon2_thread.py::test_argon2_runs_off_the_loop_thread` |
| 95 | Login bound to IP and UA | covered | `test_admin_auth_flow.py::test_transaction_is_bound_to_ip_and_user_agent_and_expires` |
| 96 | Second factor: TOTP, passkeys, email fallback | covered | `test_admin_auth_flow.py::test_password_then_totp_logs_in_and_sends_the_login_alert`, `test_admin_auth_flow.py::test_bootstrap_login_uses_email_then_forces_enrollment`, `test_admin_auth_flow.py::test_email_resend_replaces_the_code_and_is_rate_limited`, `test_admin_auth_flow.py::test_passkey_registration_and_login`, `test_admin_auth_flow.py::test_recovery_code_works_once`, `test_auth_uniform_404.py::test_every_second_factor_failure_looks_identical` |
| 97 | Lockout with exploit-log reasons | covered | `test_admin_auth_lockout.py::test_reserve_counts_before_checking_and_refuses_at_the_limit`, `test_auth_lockout.py::test_parallel_guesses_cannot_pass_the_limit`, `test_auth_lockout.py::test_two_workers_share_one_count`, `test_metrics_security_events.py::test_login_events_via_recorder` |
| 98 | Sessions | covered | `test_auth_cookies.py::test_session_and_trusted_cookie_flags`, `test_auth_sessions.py::test_login_never_adopts_a_planted_session_id`, `test_auth_sessions.py::test_only_hashes_are_stored`, `test_admin_auth_flow.py::test_heartbeat_extends_only_with_recent_input`, `test_admin_auth_flow.py::test_session_absolute_lifetime`, `test_auth_sessions.py::test_sign_out_everywhere_bumps_the_epoch` |
| 99 | Login alert with the kill-switch link | covered | `test_admin_auth_pages.py::test_kill_switch_get_confirms_post_consumes_once`, `test_admin_auth_pages.py::test_kill_switch_can_spare_passkey_sessions`, `test_auth_sessions.py::test_kill_switch_also_revokes_trusted_devices`, `test_notify_notifier.py::test_login_body_keeps_the_kill_switch_link_and_scrubs_the_rest` |
| 100 | Trusted devices | covered | `test_admin_auth_flow.py::test_trusted_device_skips_only_the_second_factor`, `test_admin_auth_pages.py::test_trusted_devices_list_and_revoke`, `test_admin_auth_parts.py::test_ua_family_ignores_versions_but_not_browsers` |
| 101 | Logout | covered | `test_admin_auth_pages.py::test_logout_deletes_the_server_side_session`, `test_auth_cookies.py::test_logout_and_dead_sessions_clear_the_cookie` |
| 102 | Deploy on push, blue/green, gated | partial: P14 (`deploy.yml` stays disabled until the cutover; CI does not run `tests/deploy` yet) | `test_deploy_sh.py::test_v1_1_clean_deploy`, `test_deploy_sh.py::test_failed_health_gate_rolls_back`, `test_deploy_sh.py::test_failure_after_the_switch_switches_back`, `test_deploy_sh.py::test_commit_not_on_main_is_refused`, `test_deploy_sh.py::test_workflow_bootstrap_installs_a_missing_deploy_script` |
| 103 | Per-release venv | covered | `test_deploy_sh.py::test_v1_7_redeploy_of_a_built_release_reuses_it`, `test_deploy_sh.py::test_v1_8_failed_build_leaves_a_usable_environment`, `test_deploy_sh.py::test_keeps_the_newest_five_releases`, `test_deploy_sh.py::test_release_ships_compiled_bytecode` |
| 104 | systemd unit hardening | covered | `test_deploy_units.py::test_roxy_unit_has_the_plan_17_1_directive`, `test_deploy_units.py::test_memory_numbers_fit_the_909_mb_server`, `test_deploy_units.py::test_systemd_analyze_verify`, `test_deploy_units.py::test_exposure_score_is_ok`, `test_deploy_units.py::test_app_boots_under_the_unit_sandbox` |
| 105 | OnFailure alert | covered | `test_deploy_alert.py::test_one_alert_per_unit_per_ten_minutes`, `test_deploy_alert.py::test_redact_removes_secrets`, `test_deploy_alert.py::test_webhook_failure_is_a_failure_too`, `test_deploy_alert.py::test_end_to_end_with_system_python`, `test_deploy_units.py::test_alert_unit` |
| 106 | nginx config | covered | `test_deploy_nginx.py::test_nginx_t_accepts_the_rendered_site`, `test_deploy_nginx.py::test_every_location_that_reaches_the_app_is_rate_limited`, `test_deploy_nginx.py::test_internal_is_404_and_never_proxied`, `test_deploy_nginx.py::test_kill_switch_token_is_never_logged`, `test_deploy_nginx.py::test_live_floods_never_reach_the_app_unlimited`, `test_deploy_wrappers.py::test_apply_installs_the_verified_files` |
| 107 | Deploy runbook | partial: P12 part two (`docs/RUNBOOKS.md`) | none yet |
| 108 | v1 smoke suite, deploy test, boot check | partial: P14 (`tests/V1_PARITY.md`) | `test_deploy_sh.py::test_v1_1_clean_deploy`, `test_deploy_sh.py::test_v1_3_fetch_failure_must_not_brick_the_server`, `test_deploy_smoke_remote.py::test_each_check_fails_when_its_condition_breaks`, `test_check_style.py::test_v1_test_suites_are_scanned_and_clean` |
| 109 | Secrets as systemd credentials | covered | `test_core_env.py::test_systemd_credentials_directory_wins`, `test_core_env.py::test_no_accessor_for_the_roblox_credential`, `test_migration_credentials.py::test_migration_credential_files_and_modes`, `test_migration_v1_files.py::test_files_listing_outside_root_is_never_followed`, `test_deploy_units.py::test_roxy_unit_lists_and_order` |
| 110 | Worker recycling | covered | `test_deploy_gunicorn.py::test_settings_follow_plan_5_2`, `test_deploy_gunicorn.py::test_max_requests_zero_disables_recycling` |
| 111 | Shared matcher semantics | covered (the credential allowlist is exact; see Wave 2) | `test_match.py::test_v1_rule_match_parity`, `test_match.py::test_v1_rule_match_corpus_parity`, `test_match.py::test_v1_best_match_parity`, `test_match.py::test_exact_patterns_grant_no_implicit_subpath` |
| 112 | Canonical header rule id | covered | `test_match.py::test_header_rule_canonical_key_parity`, `test_service.py::test_header_rule_duplicates_are_rejected`, `test_service.py::test_imported_header_rule_keeps_its_v1_key_on_edit`, `test_service.py::test_opposite_regex_header_rules_are_two_rules` |
| 113 | "Bypass my IP" | partial: P9, P11 | `test_abuse_switches_rules.py::test_bypass_my_ip_and_never_needs_confirmation` |
| 114 | Pause and throttle-all drop counters and banners | partial: P11 (top bar banners) | `test_metrics_queries.py::test_drops_since_refusal_reasons_retries_visitors` |
| 115 | Enabling throttle-all starts a new count | covered | `test_abuse_switches_rules.py::test_enabling_throttle_all_records_a_new_since_marker` |
| 116 | Custom message vs Roblox body split | covered | `test_proxy_router.py::test_message_source_tells_roxy_text_from_roblox_body`, `test_metrics_queries.py::test_drops_since_refusal_reasons_retries_visitors`, `test_rr_spec_message_source.py::test_spec_4_upstream_refusal_records_its_message_source` |
| 117 | Retry counts by status and reason | covered | `test_metrics_queries.py::test_drops_since_refusal_reasons_retries_visitors`, `test_upstream_service.py::test_csrf_handshake_with_cached_token` |
| 118 | Throttle watch table | partial: P9, P11 (Protection page) | `test_abuse_throttle.py::test_strike_board_forgive_and_watch` |
| 119 | Session-expired overlay | covered | `test_design_system.py::test_session_expired_overlay_on_any_401_and_stay`, `test_design_system.py::test_session_expired_overlay_redirects_to_login`, `test_design_system_robustness.py::test_session_overlay_keeps_other_dialogs_and_ignores_the_palette` |
| 120 | `GET /admin` sends a signed-in admin to the dashboard | partial: P11 (the dashboard page it redirects to) | `test_admin_auth_flow.py::test_login_page_and_logged_in_redirect` |
| 121 | Forced metrics flush | partial: P9 (`POST /admin/api/v1/system/flush`) | none yet |
| 122 | Workers "reset counts" | partial: P9, P11 (System page) | `test_scheduler_heartbeat.py::test_reset_counts_is_adopted_by_every_worker` |
| 123 | Tarpit state fields and reasons | covered | `test_abuse_tarpit.py::test_state_fields`, `test_abuse_tarpit.py::test_effective_cap_formula_defaults`, `test_proxy_router.py::test_tarpit_gets_the_v1_reason_string` |
| 124 | Per-setting "Reset to default" | partial: P9 (settings API), P11 (settings pages) | `test_settings_service.py::test_reset_to_default`, `test_ui_templates.py::test_setting_control_renders_every_catalog_setting` |
| 125 | Ladder "reset to defaults" | partial: P9, P11 (Protection page) | `test_service.py::test_replace_and_reset_the_ladder` |
| 126 | Live feed entry fields | covered | `test_metrics_live.py::test_live_entry_has_every_row_126_field`, `test_proxy_router.py::test_event_carries_the_optional_recorder_fields` |
| 127 | Capture never fails a request | covered | `test_metrics_recorder.py::test_record_outcome_never_raises`, `test_metrics_recorder.py::test_capture_errors_never_fail_the_request`, `test_metrics_capture_encoder.py::test_a_failing_capture_is_counted_and_the_thread_goes_on`, `test_proxy_router.py::test_recorder_failure_never_fails_the_request` |
| 128 | Expired capture message | partial: P9 (`GET /admin/api/v1/live/{request_id}`) | `test_metrics_capture.py::test_v1_expired_message_is_exact`, `test_metrics_capture.py::test_get_capture_and_expiry` |
| 129 | `POST /health` is 404 | covered | `test_pipeline_e2e.py::test_public_health_and_post_health` |
| 130 | Overview visitor KPIs | partial: P9, P11 | `test_metrics_queries.py::test_drops_since_refusal_reasons_retries_visitors`, `test_metrics_visitors_catalog.py::test_classify`, `test_metrics_recorder.py::test_visits_and_security_helpers` |
| 131 | Proxy timings split toggle | partial: P11 (Traffic page) | `test_metrics_recorder.py::test_dims_row_holds_every_dimension` |
| 132 | Status codes source split | partial: P11 (Traffic page) | `test_metrics_recorder.py::test_cache_state_and_source_strings` |
| 133 | "What's Being Stored" | partial: P9, P11 (Data page) | none yet |
| 134 | Blocked fingerprints | partial: P11 (Security page) | `test_metrics_recorder.py::test_fingerprints_flow_and_blocked_variant` |
| 135 | Throttle-all watch | partial: P9, P11 (Protection page) | `test_abuse_switches_rules.py::test_throttle_all_watch` |

Plan sections 7 and 10, which the rows above lean on: every 7.9 policy row
(`test_upstream_status_policy.py::test_outcome_policy_row`) and every 7.13 row
(`test_proxy_golden.py::test_7_13_row_golden`, `test_pipeline_e2e.py::test_row_roblox_4xx`) is tested, the 7.8
queue horizon too (`test_upstream_buckets.py::test_priority_horizon_is_the_max_wait`), and the 10.6 cap formula and
the 10.7 bot weights match the plan (`test_abuse_tarpit.py::test_effective_cap_formula_defaults`,
`test_abuse_bot_challenge.py::test_default_weights_match_the_plan`).

Counts: 135 rows; 82 covered, 2 changed, 51 partial.

## Writing style (plan C5)

- The v1 test suites kept under `tests/` (`smoke_test.py`, `deploy_test.sh`, `boot_check.sh`) are scanned by
  `scripts/check_style.py` like every other file; the dashes they had were all in comments and were rewritten.
- **C5 replacement in the admin login script (P8).** v1's `admin.js` said "This code has expired", a dash, then
  "send a new one."; v2 says `This code has expired; send a new one.` (LEAD_NOTES decision 5).
- **Vendored libraries.** The style walk skips `src/roxy/static/vendor` and `tests/e2e/vendor`; the reason is under
  "Design system (P11a)" above.
