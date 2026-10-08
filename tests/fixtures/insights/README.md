# Insight rule fixtures (plan 11.5, acceptance 19.10)

Each file here is one scenario for one recommendation rule from plan 11.5 (the rule ids in
`roxy.config.insight_params.INSIGHT_RULES`). A loader turns the scenario into database rows and recorder events,
the harness runs that one rule at a fixed time, and the result is compared with `expect`.

Ground rules (plan 19.10):

- These fixtures were written from the 11.5 table before any rule existed. A rule author may ADD fixture files
  (and add variants in new files) but must never edit or delete an existing one. If you think a fixture is wrong,
  say so in your report to the lead; do not change it to make a rule pass.
- 19.10 asks for, per rule: a scenario that fires, one that does not, the `insight_<slug>_enabled` switch, and
  each threshold. Variants (below) make the last three cheap.
- No real systems: client and server addresses only from the documentation ranges `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`; no secrets, tokens, cookies or credential values (the
  credential is described by status and a fake account id only; the loader computes fingerprints with test
  keys); invented hosts use `.test`; place, user and group ids are synthetic. No em or en dashes, US spelling.

## File names and the top level

`<rule_slug>__<case>.yaml`, where `rule_slug` is `InsightRuleSpec.slug` (`UP-429-ENDPOINT` becomes
`up_429_endpoint`) and `case` is the file's `case` value. The first fixture is
`up_429_endpoint__before_after_11_6.yaml`, a full worked example of everything below.

| Key | Required | Meaning |
|---|---|---|
| `format` | yes | `roxy.insight_fixture/1`. A breaking change to this document bumps the number. |
| `rule` | yes | The rule under test, an id from `INSIGHT_RULES`. |
| `case` | yes | Snake case name, equal to the part of the file name after `__`. |
| `description` | yes | What the scenario is and why the expectation follows from the 11.5 row. |
| `now` | yes | Evaluation time, ISO 8601 UTC with `Z`, on a whole minute (`"2026-10-07T15:00:00Z"`). |
| `seed_defaults` | no | `true` runs `roxy.config.defaults.seed_defaults` before `tables`. Default `false`: rule tables start empty, so the file states everything it depends on. |
| `settings` | no | Setting overrides by catalog key. |
| `tables` | no | control.db rows by table name. |
| `traffic_defaults`, `profiles`, `traffic` | no | Generators that expand into `OutcomeEvent`s. |
| `events` | no | Non-request rows: 429 rows, security events, errors, samples, change observations, and so on. |
| `state` | no | Shared state and system facts: cooldowns, breakers, buckets, credential, workers, disk, health, history. |
| `expect` | yes | What the rule must return, plus `data_checks` on the loaded data itself. |
| `variants` | no | Settings-only reruns of the same data with their own `expect`. |

The loader rejects unknown keys at every level, so a typo fails loudly instead of silently testing nothing. The
one exception is keys that start with `x_`: they carry data that has no table in schema version 1 and go to a
provider (see "Provider seams" at the end).

## Shared conventions

**Times.** Anywhere a time is expected you may write:

- `"now"`, or a relative offset `"<sign><integer><unit>"` with unit `s`, `m`, `h` or `d` (`"-60m"`, `"+12s"`,
  `"-7d"`, and `"0m"` for now). One unit per value; write `"-90s"`, not `"-1m30s"`.
- An absolute ISO time `"2026-10-07T14:00:00Z"`, or a date `"2026-10-06"` (UTC midnight; used for day columns
  such as `change_observations.day`).
- A bare integer, written to the column unchanged (escape hatch).

The loader converts to the destination column's unit: columns ending in `_ms` get milliseconds, every other time
column gets Unix seconds (the convention in `storage/migrations/control/0001_initial.sql`).

**Windows** are two-item lists `[start, end]`, half open (start included, end excluded). Traffic windows must
start and end on whole minutes relative to `now`.

**YAML traps.** PyYAML reads `OFF`, `ON`, `yes`, `no` as booleans. Always quote enum strings that look like those
(`cache_state: "OFF"`, `cache_post_requests: "off"`), quote `{placeholder}` templates
(`"groups.roblox.com/v1/groups/{groupId}"`) and numeric-looking ids (`"1000000001"`). The loader rejects a
boolean where an enum string is expected.

**Enums** are the values in `roxy.core.reasons` (DESIGN.md section 6): `ReasonCode`, `Outcome`, `Egress`,
`Source`, `CacheState` (upper case, `"NA"` for n/a), `AuthClass`. Unknown values fail the load.

## settings

A map from catalog key (`roxy.config.catalog.CATALOG`, which includes the generated `insight_<slug>_enabled`,
`insight_<slug>_severity` and `insight_<slug>_<param>` keys) to a value. Each value goes through
`catalog.validate_value`, and the merged set through `catalog.validate_cross`; a failure fails the load. Values
are written as control.db `settings` rows (`updated_by` = `fixture`, `updated_at` = the time of the last
`state.settings_history` entry for that key, else `now - 1d`). Every key not listed keeps its catalog default.

```yaml
settings:
  fallback_on_429: 1
  cache_post_requests: "off"
  insight_up_429_endpoint_min_429s: 20
```

## tables

control.db rows keyed by table name, with column names exactly as in `storage/migrations/control/*.sql`. The
loader checks every key against `PRAGMA table_info`.

Allowed tables: `rules_endpoint_block`, `rules_endpoint_limit`, `rules_cache`, `rules_user_agent`, `rules_header`,
`rules_routing`, `upstream_limits`, `credential_allowlist`, `throttle_tiers`, `cache_ignored_params`,
`ignored_value_headers`, `ignored_paths`, `access_list` (bypass, admin allowlist and deny entries: `kind`,
`cidr`, `expires_at` null for never) and `bans` (with `hits` and `last_hit_at`). Not allowed here, because they
have their own section or hold secrets: `settings` (use `settings`), `settings_history` and `audit_log` (use
`state.settings_history`), `service_state`, `credential_meta` (use `state`), `credential_store`, `rotator_store`,
`admin_*`, `trusted_devices`, `invalidation_tokens`, `audit_prune_gate`, `schema_version`.

Filling rules: an omitted column gets its SQL default; NOT NULL columns without a default get `now - 1d` for
`*_at`, `fixture` for `*_by`, and the next integer for `id`. Time columns accept the time grammar. Rows are
inserted directly (not through `rules/service.py`), and the loader bumps `config_version` once at the end.

```yaml
tables:
  rules_cache:
    - {id: 1, pattern: "games.roblox.com/v1/games", type: glob, ttl: 300, methods: "GET", origin: admin}
  access_list:
    - {kind: bypass, cidr: "198.51.100.7/32", expires_at: null, created_by: admin, x_last_hit_at: "-9d"}
```

## traffic

Each generator expands into one `OutcomeEvent` (DESIGN.md section 8) per request. The loader sets the fake clock
to each event's time, calls `MetricsRecorder.record_outcome`, and calls `flush_now()` at the end, so the rule
reads exactly what production would have written (rollups, client tables, histograms).

**Field resolution.** For each generator: `traffic_defaults`, then each profile named in `profile` (a string or
a list, applied left to right), then the generator's own fields; later wins. A profile may hold any generator
field except `name`, `window` and the count.

| Field | OutcomeEvent field | Default | Notes |
|---|---|---|---|
| `name` | none | required | Unique in the file; used in error messages and request ids. |
| `window` | `at_ms` range | required | `[start, end]` relative to `now`, whole minutes. |
| `per_minute` / `total` / `series` | count | exactly one | See "Counts and placement". |
| `endpoint_template` | `endpoint_template` | required | The `metrics/templating.py` form `host/path` with `{userId}` style placeholders. |
| `host` | `host` | text before the first `/` | |
| `method` | `method` | `GET` | |
| `egress` | `egress` | required | Egress of the final attempt; `none` when no upstream call was made. |
| `outcome` | `outcome` | required | |
| `reason` | `reason` | required | |
| `status` | `status` | required | Status sent to the caller. |
| `source` | `source` | required | `relay` for a relayed Roblox answer, `roxy` for Roxy's own refusal or failure text, `cache` for cache serves. |
| `cache_state` | `cache_state` | required | |
| `auth_class` | `auth_class` | `anon` | |
| `upstream_calls` | `upstream_calls` | 0 when `egress` is `none`, else 1 | Calls made for this request, retries included. |
| `latency_ms` | `latency_ms` | 0 | A number or a distribution. |
| `queue_wait_ms` | `queue_wait_ms` | 0 | A number or a distribution. |
| `upstream_ms` | `upstream_ms` | `latency_ms - queue_wait_ms` (floor 0) when calls > 0, else 0 | A number or a distribution. |
| `bytes` | `caller_bytes_in`, `caller_bytes_out`, `upstream_bytes_in`, `upstream_bytes_out` | all 0 | `{caller_in, caller_out}` per request; `{upstream_in, upstream_out}` PER CALL, multiplied by `upstream_calls`. |
| `client_ip` or `clients` | `client_ip` | required (usually in `traffic_defaults`) | See "Pools". |
| `place_id` or `places` | `place_id` | null | |
| `user_agent` or `user_agents` | `user_agent` | `""` | |
| `bypass` | `bypass` | false | |
| `error` | `error` | false | Set it the way the recorder contract defines it; the 11.6 fixture marks caller-facing failures and stale-after-failure serves. |
| `request_id` | `request_id` | `<case>-<name>-<n>` | |
| `upstream_status` | none (samples only) | `status` when `source` is `relay`, else null | Roblox's status when it differs from the caller's (429 served stale, for example). |
| `upstream_429` | side output | none | One `upstream_429` row per request, see below. |
| `samples` | side output | none | One `request_samples` row per request, see below. |

**Counts and placement.** `per_minute: N` gives N events in every minute of the window. `total: N` spreads N
evenly: with `m` minutes, minute `i` (0 based) gets `N // m`, plus one when `i < N % m`. `series: [..]` lists
the count for each minute and must have exactly one entry per minute. Inside a minute that starts at `t0` (ms)
with `k` events, event `j` is at `t0 + (2j + 1) * 30000 // k`. Events with equal times are recorded in file
order. `n` below is the event's index within its generator, counted from 0 across the whole window.

**Distributions.** A number is a constant. A map of percentile points such as `{p50: 180, p95: 450, p99: 900}`
(keys `p0` to `p100`; a missing `p0` or `p100` takes the nearest given value) is a piecewise linear quantile
function. Event `n` takes the value at quantile `q = frac((n + 1) * 0.6180339887498949)`, rounded to 0.1 ms. The
golden ratio sequence spreads values evenly with no random seed, so every run produces the same numbers and the
stated percentiles come out close to exact.

**Pools.** `client_ip: "203.0.113.7"` is fixed. `clients: {cidr: "203.0.113.0/26", count: 40}` uses the first
`count` host addresses of the CIDR (network address skipped); `clients: {list: [..]}` uses the list. Event `n`
takes entry `n mod size`. `places: [..]` and `user_agents: [..]` work the same way.

**Side output `upstream_429`.** `{egress, retry_after_s, ratelimit_headers: {..}, offset_ms: 0}` writes one
metrics.db `upstream_429` row per generated request (through `record_upstream_429` when it exists), with the
request's `endpoint_template`, `host` and `request_id`, at the event time plus `offset_ms`. `egress` is the egress
of the attempt that received the 429, which can differ from the event's final egress (a 429 on direct followed
by a rotator retry).

**Side output `samples`.** `{key_space, keys, body_change_interval_s, every: 1}` writes metrics.db
`request_samples` rows, the input of the TTL tuner and dry run (plan 11.3):

1. Collect every event, from any generator, whose `samples.key_space` is the same; keep every `every`-th event of
   each generator (`n mod every == 0`). Sort by `(at_ms, file order, n)`.
2. Position `p` in that order gets key index `i = p mod keys`; `key_id = sha256("<key_space>:<i>")` hex, first 24
   characters (the cache key id format).
3. With `C = body_change_interval_s * 1000` and `phase_i = (i * C) // keys`, the body epoch is
   `(at_ms - phase_i) // C` (always 0 when the interval is 0 or null: the body never changes).
   `body_hash = sha256("<key_space>:<i>:<epoch>")` hex, first 16 characters, set only when the event fetched a
   body from Roblox (`upstream_calls >= 1`, `source` = `relay`, 2xx status); otherwise null.
4. Other columns: `at_ms`, `endpoint_template`, `method`, `client_hash` = `roxy.core.iphash.ip_hash(client_ip,
   test key)`, `place` = `place_id`, `cache_state`, `upstream_status`, `egress`, `bytes` = `caller_bytes_out`,
   `auth_class`.

**Consistency checks** (load fails otherwise): `egress: none` if and only if `upstream_calls: 0`; `auth_class:
cred` only with `egress: credential`; refusal reasons only with `outcome: refused`, upstream and failure reasons
only with `failed`, served reasons only with `served_upstream` or `served_cache` (the three groups of DESIGN.md
section 6). A file may expand to at most 250,000 events, which keeps a fixture under a few seconds; for long
baselines (7 days) use a small `per_minute`, since rules work with rates and shares.

```yaml
traffic_defaults:
  clients: {cidr: "203.0.113.0/26", count: 40}
  user_agent: "Roblox/Linux"
profiles:
  hit: {egress: none, outcome: served_cache, reason: cache_hit, status: 200, source: cache, cache_state: "HIT"}
traffic:
  - {name: games_hit, profile: hit, endpoint_template: games.roblox.com/v1/games, window: ["-60m", "0m"], total: 3000}
```

## events

Every list under `events` (and the list-shaped keys under `state`) accepts two item forms: a single row with
`at`, or a row generator with `window` and one count key (`per_minute`, `total`, `series`). A row generator
places its rows exactly like traffic and copies every other field into each row.

| Key | Destination | Fields |
|---|---|---|
| `upstream_429` | metrics `upstream_429` | `endpoint_template`, `host` (default from template), `egress`, `retry_after_s`, `ratelimit_headers` (map, stored as `ratelimit_headers_json`), `request_id`. For 429s that belong to no generated request. |
| `security` | metrics `events` | `type`, `severity`, `reason_code`, `ip` (stored as `ip_hash` with the test key; also in the detail for the types that keep it), `place`, `endpoint_template`, `detail` (map). `type` must be a type the recorder defines (`probe`, `login`, `crawl`, `throttled` in `metrics/security_events.py`, and the abuse, egress and credential event types their modules define: detector dry-run fires, auto bans, leak guard trips). |
| `errors` | metrics `errors` | `signature`, `count`, `first_seen`, `last_seen`, `source`, `last_detail`, `module_line`, `traceback_redacted`, plus `occurrences`: a list of row generators, each occurrence stored as an `events` row of type `error` with detail `{signature}`, so hourly counts and 7-day baselines (SYS-ERRORS) can be computed. |
| `request_samples` | metrics `request_samples` | Raw columns (`key_id`, `body_hash` given explicitly), for samples that traffic `samples` cannot express. |
| `change_observations` | cache.db `change_observations` | `endpoint_template`, `day` (a date), `refetches`, `identical_bodies`. |
| `anomalies` | metrics `anomalies` | Raw columns. |
| `annotations` | metrics `annotations` | Raw columns (`kind`, `label`). Settings changes add their own; see `state.settings_history`. |
| `internal_calls` | `record_internal_call` | `purpose` (`credential_probe`, `health`, `admin_lookup`, ...), `trigger` (`scheduled`, `health`, `admin`), `egress`, `endpoint_template`, `status`. Roxy's own calls, kept out of caller traffic (P6). Used by CRED-PROBE-COST. |
| `upstream_attempts` | provider (attempt trace) | Per attempt: `endpoint_template`, `egress`, `attempt` (1, 2, ...), `status`, `kind` (`first`, `csrf_retry`, `fallback_429`, `retry_5xx`), `challenge` (bool), `html_body` (bool), `exit_id` (rotator exit, synthetic). For UP-CSRF-LOOP, UP-CHALLENGE, UP-429-AMPLIFY (attempts histogram) and EGR-POOL-BURNED (per exit). |

## state

| Key | Destination | Shape |
|---|---|---|
| `cooldowns` | hot `cooldown` | `{key, until, source, set_at, hits}`; `until` becomes `until_ms`. Keys as in plan 7.5 (`endpoint:<template>:<egress>`, `host:<host>:<egress>`, `credential`). |
| `breakers` | hot `breaker`, plus provider | Columns of `breaker`, plus `openings`: a list of times (or row generators) when it opened, for UP-BREAKER-FLAP. |
| `buckets` | hot `upstream_bucket`, plus provider | `{bucket_key, per_min, burst, fill_pct, history}`. The row gets `rate_per_s = per_min / 60` and `tat_ms = now_ms + fill_pct / 100 * burst * (60000 / per_min)`. `history` is a list of `{window, fill_pct_peak, attempts, rejections}` for the fill history and rejection counts (plan 7.3, parity row 77). |
| `credential` | control `credential_meta`, plus provider | `{present, status, status_at, set_at, account_id, probes}`. `present: false` writes no row and no fake credential file. `account_id` is a synthetic user id; the loader stores its fingerprint with the test key, so a probe answer can be compared. `probes` is a list of `{at, kind, status, result}`; the latest sets `last_probe_at` and `last_probe_result`. |
| `egress` | metrics `egress_usage`, plus provider | `usage`: rows or row generators of `{egress, granularity, at, requests, req_bytes, resp_bytes, overhead_bytes}`; `provider_reported_bytes` (the admin-entered provider figure, EGR-CALIBRATE). Quota, billing day and daily cap are settings (`rotator_quota_gb_per_month`, `rotator_billing_day`, `rotator_daily_cap_mb`). |
| `workers` | metrics `worker_heartbeat`, plus provider | Columns of `worker_heartbeat` (`loop_lag_ms_p99`, `open_conns`, `is_leader`, ...) plus `x_cpu_pct` and `history`: `{window, cpu_pct, loop_lag_ms_p99, open_conns}` per stretch, for SYS-WORKER-SAT and SYS-LOOP-LAG. |
| `leader` | hot `lease` (name `leader`) | `{holder, expires, epoch}`; `job_runs` rows go to hot `job_runs`. |
| `disk` | provider | `{total_bytes, free_bytes, files: {"control.db": {bytes, wal_bytes}, ...}, tables: {"metrics.rollup_minute": bytes, ...}, growth: [{at, total_bytes}], dims_per_minute_7d_avg}` for SYS-DISK. |
| `dns` | provider | `{<host>: {answers: [..], latency_ms, error}}`. Documentation range answers count as public in tests (the address classifier seam); private ranges stay private. For HOST-ADD. |
| `health` | metrics `health_runs`, `health_results` | `runs: [{started_at, trigger, results: [{check_id, status, value, threshold, explanation, fix_link}]}]`. |
| `settings_history` | control `settings_history`, `audit_log`, metrics `annotations` | `[{at, key, old, new, source, changed_by, reason}]`. Each entry also writes an audit row (`setting.update` through `config/audit.record`) and a `config_change` annotation. The last `new` of each key must equal its `settings` value (or the catalog default when the key is not in `settings`); the loader checks. For SYS-CHANGE-REGRESSION and "Undo". |
| `admin_logins` | metrics `events` type `login` | Rows or row generators of `{at, ip, username, successful, method}`, stored with `security_events.login_detail`. For SEC-ADMIN-ALLOWLIST. |
| `service_state` | control `service_state` | `{paused: {..}, throttle_all: {..}, ...}` merged over the migration's rows. |
| `cache` | cache.db `entries`, plus provider | `entries`: columns of `entries` (`x_body_size` makes the loader generate a body of that size); `stores` and `evictions: [{age_s, ttl_s, count}]` for CACHE-PRESSURE. |
| `client_scores` | provider | `[{ip, bot_score}]` for ABUSE-BOT and THROTTLE-TUNE. |
| `tarpit` | provider | `{eligible_holds, skipped, holds, gap_with_hold_s, gap_without_hold_s}` for TARPIT-TUNE. |
| `ua_experiment` | provider | `{arms: [{user_agent, calls, roblox_429}]}` for UP-UA-EXPERIMENT. |
| `metrics_pipeline` | provider | `{dropped}` for SYS-METRICS-DROP. |
| `raw` | any table | `{hot: {<table>: [rows]}, metrics: {..}, cache: {..}}`: escape hatch, columns checked like `tables`. |

## expect

```yaml
expect:
  data_checks: [...]
  fires: true
  others: forbid
  recommendations: [...]
```

**`data_checks`** test the loaded data, not the rule: they keep a fixture honest about its own story. Each item has
a `window`, an optional `where` (OutcomeEvent fields: `endpoint_template`, `host`, `method`, `egress`,
`outcome`, `reason`, `status`, `source`, `cache_state`, `auth_class`) and any of these measures:

| Measure | Definition |
|---|---|
| `requests` | Number of OutcomeEvents. |
| `upstream_calls` | Sum of `upstream_calls`. |
| `avoided_calls` | `requests - upstream_calls` (plan P6). |
| `roblox_429` | `upstream_429` rows; only the `where` keys that exist on those rows apply (`endpoint_template`, `host`, `egress`, where `egress` is the attempt's egress). |
| `served_upstream`, `served_cache`, `refused`, `failed` | Counts by outcome. |
| `stale_after_failure` | Events with reason `cache_stale_error`. |
| `errors` | Events with `error: true`. |
| `by_reason` | `{<reason>: count}`. |

The harness checks them against the expanded events before the rule runs, and again through the metrics query
read models once those exist (proving the recorder and rollups agree with the fixture).

**`fires`**: `true` means the rule returned at least one recommendation, `false` means none (then
`recommendations` must be absent or empty).

**`others`**: `allow` (default) or `forbid`. With `forbid`, every returned recommendation must be matched by an
entry of `recommendations`.

**`recommendations`**: a list of matchers. For each matcher in order, the harness takes the first returned
recommendation not yet matched that satisfies every field; give matchers distinguishable subjects. A matcher has:

| Field | Meaning |
|---|---|
| `rule_id` | Default: the file's `rule`. |
| `subject`, `subject_contains`, `title_contains` | The fingerprint subject (11.1, for example an endpoint template) exactly, or as a substring; a substring of the title. |
| `severity` | `critical`, `warn`, `info` or `any` (default `any`). |
| `confidence`, `risk`, `family` | A value or a constraint. |
| `safe_auto` | `true` or `false`. |
| `change_kinds_required` | Kinds (11.2) that must each appear at least once. |
| `change_kinds_forbidden` | Kinds that must not appear. |
| `changes_required` | Change matchers; each must match a different change of the recommendation. |
| `changes_forbidden` | Change matchers; no change may match any of them. |
| `exact_changes` | `true`: no changes beyond those matched by `changes_required` (default `false`). |
| `evidence` | `metrics: {<name>: constraint}`: each named metric must exist in `evidence.metrics` (names as in 11.2). Optional `window: {from, to}` in the time grammar. |
| `dry_run` | `available: true or false`, and constraints on the simulator's report for this recommendation's changes over the default window: `avoided_calls`, `simulated_hit_ratio`, `staleness_risk`, `refused_requests`, `sample_size`. |

A **change matcher** is a partial match on the 11.2 change object: `kind` is required, any other field listed
must match (`table`, `match`, `key`, `bucket_key`, `current`, `proposed`, ...), fields not listed are ignored.

```yaml
changes_required:
  - {kind: setting, key: fallback_on_429, current: 1, proposed: 0}
  - kind: bucket_override
    bucket_key: "endpoint:users.roblox.com/v1/users"
    proposed: {per_min: {between: [45, 90]}, burst: {lte: 10}}
  - kind: rule_upsert
    table: rules_cache
    match: {pattern: {matches_targets: ["users.roblox.com/v1/users"]}}
    current: null
changes_forbidden:
  - kind: setting
    key: {in: [endpoint_bucket_default_per_min, global_bucket_per_min]}
```

**Constraint grammar** (also used by `tests/fixtures/health`):

- A scalar means equality. Numbers compare numerically (`1 == 1.0 == true`, tolerance 1e-9); strings exactly.
- `null` means the value is null or absent.
- A list means an equal list.
- A map whose keys are ALL operators is a constraint; several operators must all hold. Any other map is a nested
  partial match (only the listed keys are checked).
- Operators: `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `between: [lo, hi]` (inclusive), `in: [..]`, `not_in: [..]`,
  `contains` (substring, or list element), `contains_all: [..]` (list elements, or comma separated items of a
  string such as `methods: "GET,POST"`, compared case-insensitively), `regex` (Python `re.search`), `present`
  (`true` or `false`), `matches_targets: [..]` and `not_matches_targets: [..]` (the value is a rule pattern:
  compiled with `roxy.rules.match.compile_pattern` using the `type` field next to it, default `glob`, and tested
  against each target).

## variants

```yaml
variants:
  - case: disabled
    description: The per-rule switch silences the rule.
    settings: {insight_up_429_endpoint_enabled: 0}
    expect: {fires: false}
```

A variant reruns the same data with its `settings` merged over the file's settings, and its `expect` REPLACES the
file's expect (`data_checks` are not repeated). Only `case`, `description`, `settings` and `expect` are allowed;
a scenario that needs different data is a new file. Pytest ids are `<file stem>` and `<file stem>[<case>]`.

## How the loader and harness run a file

1. Parse with `yaml.safe_load`; validate keys, enums, settings (catalog), table columns (`PRAGMA table_info`),
   traffic consistency and the 250,000 event cap.
2. Create a temporary state directory and migrate the four databases; run `seed_defaults` when asked.
3. Set a `FakeClock` to `now`. Apply `settings`, `tables`, `state`, `events`, then `traffic` (through the
   recorder, clock moved to each event's time, `flush_now()` at the end). Bump `config_version` once.
4. Run `expect.data_checks`.
5. Evaluate ONLY the rule under test, at `now`, through the engine's per-rule entry point: the same path the
   leader uses, which applies `insight_<slug>_enabled`, `insight_<slug>_severity`, evidence minimums and
   fingerprints. Calling a rule's `evaluate` directly would skip the switch and the severity override and is
   not allowed.
6. Compare with `expect`. On failure, print each returned recommendation (id, subject, severity, changes) and the
   first constraint that did not hold.
7. Run each variant the same way. A variant changes settings only, so an implementation may reuse the loaded
   databases and just apply the settings and reload the snapshot.

## Provider seams (data with no table in schema version 1)

Some facts the 11.5 rules need are not stored in any table yet. Fixtures describe them anyway, and the insights
context must read them through an interface the harness can fill (a provider object or replaceable functions;
naming is the rule author's choice, but every field must reach the rule): bucket fill history and rejections,
worker CPU and per-stretch history (production reads the cgroup `cpu.stat`, plan 17.1), disk and table sizes,
DNS answers and the address classifier, cache eviction ages, tarpit statistics, client bot scores, UA experiment
arms, the metrics drop counter, the rotator provider's byte figure, per-attempt upstream traces, breaker opening
history, credential probe history, error occurrences, and `x_` columns on table rows (for example rule hit
history for FILTER-REMOVE and bypass last use, which `rules_*` and `access_list` do not record). When an owning
module later adds a table or event type for one of these, the loader maps the same fixture field to it; the
fixture format does not change.

## Extensions (added by the UP-* fixture author)

Added after the sections above, as the ground rules ask; no existing field changes meaning.

**`any_of` change matcher.** An item of `changes_required` or `changes_forbidden` may be
`{any_of: [<change matcher>, ...]}` instead of a single change matcher. In `changes_required` it is satisfied by
one change (not already used by another required matcher) that matches at least one alternative; in
`changes_forbidden` it means the same as listing each alternative separately. 11.5 often offers alternatives
("enable X or Y", "block the endpoint or add a negative cache rule"), and a fixture must not choose one for the
rule author.

**Change shapes that the 11.2 example does not show.** The UP-* fixtures match these shapes (fields not listed
are ignored, as for every change matcher):

| Kind | Fields the matchers use |
|---|---|
| `setting` | `key`, `current`, `proposed`, values in the catalog's canonical form (`validate_value`). |
| `bucket_override` | As in the example above: `bucket_key`, `current: {per_min, burst}`, `proposed: {per_min, burst}`. When no `upstream_limits` row exists, `current` holds the default the bucket runs at. |
| `rule_upsert`, `rule_delete` | `table` (`rules_cache`, `rules_endpoint_block`, ...), `match: {pattern, type}`, `current` (null for a new row, else the row's columns), `proposed` (columns). |
| `routing_rule` | Like `rule_upsert` on `rules_routing`: `match: {pattern, type}`, `current`, `proposed: {mode}` with a `rules_routing.mode` value. |
| `credential_allowlist_remove` | `match: {pattern, type}` of the allowlist row to remove. |
| `tarpit_category` | `category` (a name from `roxy.config.constants.TARPIT_CATEGORIES`, for example `upstream_cooldown_retry`), `current` and `proposed` (0 or 1, the category's switch). |
| `manual` | `kind` only. |

**Data the UP-* fixtures put in `events.upstream_attempts`.** One row per HTTP call that a caller request made
beyond what its OutcomeEvent shows: retries after a 429 (`kind: fallback_429`), 5xx or timeout retries
(`retry_5xx`; a timeout row has `status: null`), and CSRF handshakes (`csrf_retry`, sharing the attempt number
of the call it repeats, as `upstream/trace.py` numbers them), plus the first call (`kind: first`) whenever the
row is needed to show what that call returned (a 403 CSRF challenge, a 429, a challenge page). Each such row is
consistent with the `upstream_calls` of the traffic generator it describes, and the fixture's header comment
names that generator.

## Extensions (added by the CACHE-*, HOT-ENDPOINT, HOST-ADD, EGR-* and CRED-* fixture author)

Added after the sections above, as the ground rules ask; no existing field changes meaning. These fixtures also
use the `any_of` matcher and the change shapes of the UP-* extensions above.

**Traffic field `path`, pool `paths`.** The optional `OutcomeEvent.path` (concrete `host/path` without the query,
`metrics/recorder.py`), fixed or as a pool used in turn like `places`. Default: empty. HOST-ADD fixtures use it
for the "sample paths" evidence.

**`state.cache.entries`.** Rows give `id` (the first 24 hex characters of the SHA-256 of `key`, built with
`cache/keys.py build_key`) and `params_json` exactly as `cache/store.py` writes it
(`{"params": [[name, value], ...], "stripped": [...]}`). The `entries` table has no integer id, so the "next
integer" fill rule never applies to it.

**`state.cache` for CACHE-PRESSURE.**

- `stores`: rows `{at, count}`: `count` entries written to the shared tier (cache.db) at that time. A row generator
  form gives one store per row.
- `evictions`: rows `{at, age_s, ttl_s, count}`: `count` entries evicted at that time that were `age_s` old and
  had lifetime `ttl_s` (young means `age_s < ttl_s`). A row generator form gives one eviction per row.
- `passes`: rows `{at, entries_before, bytes_before, evicted, freed_bytes}`, one maintenance pass each, the
  `EvictionReport` of `cache/store.py`, so a rule can tell which cap (`cache_max_entries` or `cache_max_bytes`)
  forced the evictions.

**`state.egress` for EGR-*.**

- In `usage` rows, `at` is floored to the start of the row's granularity bucket; a date such as `"2026-10-01"` is
  that day's bucket.
- `metering_mode`: `socket` (default: the stream wrapper is active and `overhead_bytes` is 0) or `estimate` (the
  fallback: `overhead_bytes` holds `rotator_tls_overhead_bytes` per new connection), plan 8.3.
- `provider_reported_at`: when the admin read `provider_reported_bytes` off the provider's dashboard. The figure
  covers the current billing cycle from its start up to that time. Default `now`.

**`state.x_credential_comparisons`** (CRED-UNUSED; an `x_` key, so it goes to a provider): answers to the same
request on the anonymous path and on the credential path, the "Comparison" evidence of 11.5 (the 18.4 shadow
comparison kept running for allowlisted templates). Single rows or row generators of
`{endpoint_template, method, anon_status, cred_status, identical}`; `identical` means both answered 2xx with the
same body hash. No module records these yet; the CRED-UNUSED author decides how production produces them.

**Event types used in `events.security`.** `spam_detected` and `spam_would_ban` with detail `{detector, subject,
value, threshold, window_s, action, configured_action, game_server, evidence}` (`abuse/spam.py`); `credential_rotated`
(`egress/credential.py`: Roblox sent a replacement credential cookie, which Roxy never stores); `leak_guard`
(provisional until the egress module names its leak-trip event; it is the alert type in `notify/alerts.py`) with
`reason_code: leak_blocked` and detail `{egress, location, purpose, request_id}`.

**`events.internal_calls`.** `trigger` is `scheduled` (the credential liveness job), `health` (a health run) or
`admin` (a button); `egress: credential` marks a call made with the credential. `status` defaults to 200.

**Credential probe `result` values** are those of `egress/credential.py` (`ok`, `rejected_401`, `rejected_403`,
`rate_limited`, `account_mismatch`, `http_<code>`).

**More change shapes.**

| Kind | Fields the matchers use |
|---|---|
| `ignored_param_add` | `table: cache_ignored_params`, `proposed: {name}`. |
| `host_add` | `key: allowed_roblox_hosts`, `current` (the list) and `proposed` (the list with the host added). Matchers test `proposed` with `contains`, which also works if an implementation puts the bare host there. |
| `rule_upsert` on `rules_cache` adding normalization | `proposed.normalize_flags` holds `sort_csv:<param>` (`cache/keys.py`). Matchers use `contains`, which works on a list and on its JSON text. |

## Extensions (added by the ABUSE-*, FILTER-*, TARPIT-TUNE, THROTTLE-TUNE, PLACE-HEAVY, SYS-* and SEC-* fixture author)

Added after the sections above, as the ground rules ask; no existing field changes meaning. These fixtures also use
the `any_of` matcher and the change shapes of the extensions above.

**Changes to rows of tables without a `pattern` column, and to bans and access list entries.** The `rule_upsert`
and `rule_delete` shape above (`table`, `match`, `current`, `proposed`) applies to every control.db table a
recommendation edits. Where a table has no `pattern`, `match` holds the row's natural key instead:

| Table | `match` |
|---|---|
| `rules_user_agent` | `{id}` (the 8 hex character rule id) |
| `rules_header` | `{canonical_key}` |
| `access_list` | `{kind, cidr}` (its unique key) |
| `bans` | `{subject_type, subject}` |

| Kind | Fields the matchers use |
|---|---|
| `filter_add`, `filter_remove` | Same fields as `rule_upsert` and `rule_delete`, for the abuse filter tables (`rules_user_agent`, `rules_header`, `rules_endpoint_block`, `rules_endpoint_limit`). 11.2 does not say when a filter change is `filter_*` rather than `rule_*`, so these fixtures accept either through `any_of`. |
| `ban_add` | `table: bans`, `current: null`, `proposed: {subject_type, subject, expires_at}` with `expires_at` in Unix seconds, or null for a permanent ban (present either way, so a matcher can tell a temporary ban from a permanent one). |
| `ban_remove` | `table: bans`, `match: {subject_type, subject}`, `current` (the row). |
| `bypass_add`, `bypass_remove` | `table: access_list`, rows of kind `bypass`: `match: {kind, cidr}` for an existing row, `proposed: {kind, cidr, expires_at}`. |
| Setting an expiry on an existing access list row | `rule_upsert` on `access_list` with `match: {kind, cidr}` and `proposed: {expires_at}`, or `bypass_add` of the same CIDR with an expiry (fixtures accept both). |
| Admin allowlist entries | `rule_upsert` (or `filter_add`) on `access_list` with `proposed: {kind: allow_admin, cidr}`. |

**One recommendation per object, and what the subject contains.** Rules that judge independent objects (clients,
places, rule rows, access list entries, bans, settings, error signatures, health checks) return one recommendation
per object, as the fingerprint (`rule_id` plus subject, 11.1) implies. The subject contains the object's natural
key, which `subject_contains` tests: a client's address (or IPv6 prefix), a place id, an access list CIDR address, a
setting key, an error signature (`<ExceptionType> at <file>:<line>`, `notify/notifier.py error_signature`), a health
check id. Fixtures give objects keys that are not substrings of one another.

**`where` keys `client_ip` and `place_id`** in `data_checks`: the OutcomeEvent fields of those names, compared as
text, so a fixture can prove per-client and per-place numbers (refusals per hour, upstream calls of one place).

**Row generator count `every`.** Besides `per_minute`, `total` and `series`, a row generator in `events` or
`state` (never a traffic generator) may give `every: "<duration>"` (time grammar without a sign, `"30m"`, `"1d"`,
`"200s"`): one row at `start + k * every` for k = 0, 1, ... while the time is before `end`. `total` puts sparse rows
in the first minutes of a window; `every` spreads them evenly, which a 7-day error baseline (SYS-ERRORS) or a month
of daily admin logins (SEC-ADMIN-ALLOWLIST) needs.

**`state.client_scores` pools.** An item may give `clients` (the traffic pool grammar, `{cidr, count}` or
`{list}`) instead of `ip`, giving every address of the pool that `bot_score`. In these fixtures every client that
appears in traffic has a score; a rule must treat an unscored client as unknown, neither legitimate nor abusive.

**`x_last_hit_at`** on `rules_*` and `access_list` rows: the last time that row matched a request (time grammar);
null means never since `created_at`. FILTER-REMOVE reads idle time from it (a row never hit is idle since it was
created) and SEC-BYPASS-FOREVER shows it as "last hit".

**Meaning of the provider sections these fixtures use.**

- `state.disk`: `total_bytes` and `free_bytes` describe the state volume. Roxy's storage (the figure compared with
  `storage_total_budget_gb`) is the sum of `bytes` plus `wal_bytes` over `files` (databases, `exports`,
  `snapshots`). `growth[].total_bytes` is that storage at each time, and a `growth` point at `now` equals the sum.
  `tables` are per-table sizes for the evidence. `dims_per_minute_7d_avg` is the average number of new `dims` rows
  per minute over 7 days, compared with `insight_sys_disk_dims_per_minute`; 11.5 does not say how it enters the
  rule, so every fixture keeps it under that threshold. `storage_total_budget_gb` may be read as GB or GiB:
  fixtures stay clear of the 7% gap between the two.
- `state.tarpit`: totals for the hour before `now`. `gap_with_hold_s` and `gap_without_hold_s` are the mean time
  between a client's consecutive refused attempts when the previous attempt was held and when it was not (null when
  there were no holds). Traffic in these fixtures shows the same holds (latency 8 to 20 s) and skips (instant).
- `state.metrics_pipeline.dropped`: items dropped by the batch writers of all workers in the hour before `now`.
- `state.workers[].history`: each stretch's `cpu_pct`, `loop_lag_ms_p99` and `open_conns` hold for every minute of
  its window; `x_cpu_pct` is the latest CPU figure.

**Event types in `events.security`** (as `abuse/spam.py` writes them, `severity: warning`): `spam_would_ban` (a
detector with action `ban` fired while `spam_dry_run` = 1), `spam_ban` (an automatic ban was created; detail adds
`ban_minutes`) and `spam_detected` (a `recommend` detector fired). Detail is `{detector, subject, value, threshold,
window_s, action, configured_action, game_server, evidence}`; `subject` is `ip:<address>` for per-address detectors
and `<template>|<ua_hash>` for SPAM-DIST (`abuse/bans.py ua_hash`).

**Readings these fixtures use where 11.5 is not precise** (each fixture's header says which applies, and the data
avoids the boundary wherever two readings could differ):

- "for N min" and "for N h" (SYS-WORKER-SAT, SYS-LOOP-LAG, FILTER-ADD): the condition holds through the whole
  window: every minute above the threshold, or more refusals than the threshold in each of the last N clock hours.
- Comparisons where the plan says `>` and the catalog text says "at or above" (`bot_score_abuse_min`,
  `bot_score_legit_max`): fixtures never use the boundary value.
- "Repeated auto-bans" (ABUSE-SPAM): two or more automatic bans of one subject within the 30 day escalation window
  of 10.3.
- A SPAM-DIST detection made only of legitimate game-server clients (Roblox UA with place ids, bot score at most
  `bot_score_legit_max`) does not produce ABUSE-DIST: its remedy would refuse every game server (10.3 collateral
  protection).
- "Caller-facing 500s" (SYS-ERRORS) are Roxy's own (`reason: internal_error`); Roblox 5xx answers relayed to the
  caller (`upstream_5xx`, `source: relay`) are UP-5XX's concern.
- Admin "logins" (SEC-ADMIN-ALLOWLIST) are successful logins; failed attempts never define the admin's networks.
- A rule (FILTER-COLLATERAL) is a row of a filter table; the per-IP throttle and bans are not rules there.
