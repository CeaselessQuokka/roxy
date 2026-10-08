# Health check fixtures (plan 13.2, acceptance 19.10)

Each file here is one scenario for one Check Proxy Health check from the plan 13.2 table. The harness builds the
inputs (mocked Roblox and public origin responses, settings, tables, recent traffic, files, systemd output, DNS
answers, TLS facts, clock skew), runs that single check through the health runner, reads the stored result row
back, and compares it with `expect`.

Ground rules (plan 19.10, same as `tests/fixtures/insights/README.md`):

- Written from the 13.2 table before the checks exist. Check authors may ADD files, never edit or delete one; raise
  disagreements with the lead.
- 19.10 asks for pass, warn and fail fixtures for every check (only `n/a` where 13.2 lists none, for example
  H-CRED-PRESENT has no warn and H-CACHE-HIT only warns).
- No real network and no real systems: every outbound call is a mock (respx plus the socket guard), addresses come
  from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), the
  public origin is `https://roxy.test`, and no file holds a secret. The credential exists only as a fake value the
  conftest writes at runtime. No em or en dashes, US spelling.

## File names and the top level

`<check_slug>__<case>__<name>.yaml`, where `check_slug` is the 13.2 id in lower case with dashes turned into
underscores and any `<placeholder>` part dropped (`H-CRED-AUTH` gives `h_cred_auth`, `H-REACH-<host>` gives
`h_reach`), `case` is the expected status and `name` is a short snake case label. Example:
`h_cred_auth__fail__other_account.yaml`.

| Key | Required | Meaning |
|---|---|---|
| `format` | yes | `roxy.health_fixture/1`. |
| `check` | yes | The 13.2 id exactly, placeholders kept: `H-CRED-AUTH`, `H-REACH-<host>`. |
| `params` | when the id has placeholders | Values for them: `{host: games.roblox.com}`. The result row's `check_id` must be the id with the placeholders filled in (`H-REACH-games.roblox.com`). |
| `case` | yes | `pass`, `warn`, `fail` or `n/a`: the status the check must report. |
| `name` | yes | Snake case label; the last part of the file name. |
| `description` | yes | The situation, and which 13.2 threshold puts it in `case`. |
| `now` | yes | ISO 8601 UTC with `Z` (`"2026-10-07T15:00:00Z"`). |
| `run` | no | `{trigger: manual}` (default) or `schedule`, `deploy`, `cli`. Scheduled runs skip the credential checks that call Roblox unless `health_auto_include_credential` = 1 (13.1). |
| `inputs` | yes | Everything the check may observe; sections below. |
| `expect` | yes | The result row and the calls made. |
| `variants` | no | Reruns with merged inputs; see the end. |

Unknown keys fail the load at every level. Times use the insights time grammar (`"now"`, `"-3h"`, `"+12s"`, ISO
times, dates, raw integers), and values compared in `expect` use the insights constraint grammar (scalars mean
equality; operator maps with `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `between`, `in`, `not_in`, `contains`,
`contains_all`, `regex`, `present`).

## inputs

### Data the check reads from Roxy itself

`settings`, `tables`, `state`, `traffic_defaults`, `profiles`, `traffic` and `events` have exactly the shapes
defined in `tests/fixtures/insights/README.md` and are loaded the same way. They cover the checks that read
recent metrics (H-LATENCY, H-429-RATE, H-ERR-RATE, H-CACHE-HIT), configuration (H-CONFIG, H-BANS through `tables`
with `bans` and `access_list`), the credential (`state.credential` with `present`, `status` and a synthetic
`account_id`), workers and the leader (`state.workers`, `state.leader` with `job_runs`), sizes
(`state.disk`), and the rotator (`state.egress`, plus settings such as `rotator_weight` and
`rotator_session_username_template`).

### upstream: mocked HTTP responses

A map from a URL key to a response, or to a list of responses served in order (the last one repeats). Keys:

- A full URL, `https://users.roblox.com/v1/users/authenticated`. Query parameters match as a set, in any order.
  `*` stands for one path segment, and a trailing `?*` accepts any query.
- `probe:<host>`: whatever probe URL `health/probes.py` defines for that host (13.4). Fixtures cannot know the
  implementer's public ids, so H-REACH and the probe-based checks use this form.
- `origin:<path>`: a request to the public origin (`https://roxy.test<path>`), for H-E2E and H-NGINX.
- `ip_echo`: the rotator's IP echo service, for H-ROTATOR-REACH and H-ROTATOR-SESSION.

A response has:

| Field | Meaning |
|---|---|
| `status` | HTTP status. |
| `headers` | Map. A `date` value in the time grammar (`"now"`, `"-12s"`) is rendered as an HTTP date, which is how H-CLOCK skew is set. |
| `body` or `json` | Text, or an object sent as JSON. |
| `latency_ms` | The mock advances the fake clock's monotonic time by this much before answering, so the check measures exactly this latency. The check must time itself with `ctx.clock.monotonic()`. |
| `error` | Instead of a response: `timeout`, `connect`, `tls` or `reset` (raised as the matching httpx exception). |
| `exit_ip` | For `ip_echo`: the address the echo reports (documentation ranges only). |
| `expect_request` | Optional checks on what the check sent: `via` (`direct`, `credential`, `rotator`; recorded by the harness at `EgressClients.send`), `method`, `headers_present`, `headers_absent`. |

Any request without a mock fails the test.

### files

Logical paths under the harness roots `{state_dir}`, `{exports_dir}` and `{backup_dir}`, each a temporary directory:

```yaml
files:
  "{state_dir}/audit/perms.json":
    json: {checked_at: "-2h", results: [{path: "/etc/roxy/credentials", mode: "0700", expected: "0700", secret: true}]}
    mode: "0640"
    age: "-2h"        # file mtime relative to now
```

Fields: `content` (text) or `json`, `mode`, `age`, `size_bytes` (a sparse file of that size), `missing: true`.
Time strings inside `json` are converted to Unix seconds. H-SECRETS-PERMS reads `perms.json` and its age; the
file holds only the audit result (paths, modes, verdicts), never the contents of the audited files.

### Operating system facts

| Key | Shape | Used by |
|---|---|---|
| `systemd` | `{show: {"roxy@blue": {ActiveState: active, NRestarts: "0", ExecMainStartTimestamp: "-2d"}, ...}}`, or `{error: {returncode: 1, stderr: "..."}}`. Rendered as `systemctl show` output (`Key=Value` lines). | H-SYSTEMD |
| `timedatectl` | `{show: {NTPSynchronized: "yes"}}` or `{error: {..}}`. | H-CLOCK |
| `dns` | `{<host>: {answers: ["192.0.2.10"], latency_ms: 20}}`, or `{error: nxdomain}` (`timeout`, `servfail`). | H-DNS |
| `tls` | `{<host>: {days_left: 40, handshake_ms: 60}}`, or `{error: handshake_failed}` (`expired`, `hostname_mismatch`); key `origin` for the public certificate. | H-TLS, H-TLS-PUBLIC |
| `env` | Process environment the check sees (`{HTTPS_PROXY: "http://proxy.test:3128"}`) plus `clients_trust_env: false` (true models a client built with `trust_env=True`). | H-ENV-PROXY |
| `alerts` | `{smtp: {connect: ok, login: ok, noop: ok}, webhooks: [{provider: discord, get_status: 200}, {provider: other}]}`; values `ok`, `refused`, `timeout`, `failed`. The harness builds fake channel URLs itself, so none appear in fixtures. | H-ALERTS |
| `backup` | `{last_backup_at: "-20h", restore_test: pass}` (`fail`, `never`). | H-BACKUP |
| `version` | `{running_sha: "abc1234", deployed_sha: "abc1234", advisories: 0}`. | H-VERSION |
| `databases` | `{quick_check: {control: "ok", hot: "row 3 missing from index i1"}}`. Sizes and WAL sizes come from `state.disk`. | H-DB-INTEGRITY, H-DB-SIZE, H-WAL, H-DISK |

Documentation range addresses count as public in these tests: the harness replaces the check's address
classifier so that `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32` are public, while
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `fc00::/7` and `::1` stay private (Python's
`ipaddress` marks the documentation ranges private, so without the seam no pass fixture could exist).

### faults

Named failures the harness injects into Roxy's own code, for checks that test Roxy rather than the outside
world, written as a map (`faults: {leak_guard_bypassed: true, cache_rw_latency_ms: 150}`). The first set:

| Fault | Effect | Used by |
|---|---|---|
| `leak_guard_bypassed` | The guard's matcher never matches, so the synthetic credential-bearing rotator request is not blocked (it is still never sent). | H-CRED-GUARD fail |
| `cache_db_readonly` | cache.db writes raise. | H-CACHE-RW fail |
| `cache_rw_latency_ms: <n>` | Each cache round trip step takes that long on the fake clock. | H-CACHE-RW warn |
| `rules_compile_error: {table, id}` | That rule row fails to compile. | H-CONFIG fail |

New faults are added together with the harness code that injects them; a fault name the harness does not know
fails the load.

## expect

```yaml
expect:
  status: fail                 # must equal `case`
  value: {contains: "different account"}
  threshold: {contains: "same account"}
  critical: true
  fix_link: {contains: "credential"}
  explanation: {present: true}
  calls:
    "https://users.roblox.com/v1/users/authenticated": {count: 1, via: credential}
  credential_calls: {lte: 1}
  no_calls_to: ["probe:games.roblox.com"]
```

| Field | Meaning |
|---|---|
| `status` | `pass`, `warn`, `fail` or `n/a`; must equal `case`. Compared with the stored `health_results.status`. |
| `value`, `threshold` | Constraints on the stored text columns. Numeric operators read the first number in the text (`"312 ms"` is 312). |
| `critical` | The check flagged the result as critical (H-CRED-AUTH with a different account, H-CRED-GUARD not blocked). |
| `fix_link`, `explanation` | Constraints on those columns. `explanation` must at least be present for every warn and fail. |
| `calls` | Per URL key: `count` (constraint) and `via` (egress) of the requests the check made. |
| `credential_calls` | Constraint on calls made through the credential path (13.3 budget). |
| `no_calls_to` | URL keys that must not be requested (for example a scheduled run skipping credential checks). |

## variants

```yaml
variants:
  - case: warn
    name: rate_limited
    inputs:
      upstream:
        "https://users.roblox.com/v1/users/authenticated": {status: 429, headers: {retry-after: "30"}}
    expect: {status: warn, critical: false}
```

A variant deep merges its `inputs` over the file's inputs (maps merge, lists and scalars replace), REPLACES
`expect`, and has its own `case` and `name`. Pytest ids are `<file stem>` and `<file stem>[<case>-<name>]`.

## How the harness runs a file

1. Parse and validate (keys, check id known to the health registry, fault names, insights sections).
2. Temporary state directory, migrated databases, `FakeClock` at `now`; load the insights-shaped sections.
3. Install the mocks: respx for every URL key plus egress recording, files under the temporary roots, the
   environment, subprocess output for `systemctl` and `timedatectl`, DNS and TLS answers, the address classifier,
   database facts and faults. Each of these is a seam the check author must provide (one replaceable function or
   object per kind); the names are theirs.
4. Run the one check through the health runner's per-check entry point, with the run trigger, per-check timeout
   and internal probe priority (13.1), exactly as a real run would.
5. Read the stored `health_results` row back and compare with `expect`; then verify the call assertions.

## Example

```yaml
format: roxy.health_fixture/1
check: H-CRED-AUTH
case: fail
name: other_account
description: >
  The credential authenticates, but the account id it returns is not the one recorded when the credential was
  set. 13.2 makes that a critical fail (plan C1: exactly one account).
now: "2026-10-07T15:00:00Z"
inputs:
  state:
    credential: {present: true, status: active, set_at: "-20d", account_id: "1000001"}
  upstream:
    "https://users.roblox.com/v1/users/authenticated":
      status: 200
      json: {id: 1000002, name: "fixture_user"}
      latency_ms: 140
      expect_request: {via: credential, method: GET}
expect:
  status: fail
  critical: true
  fix_link: {contains: "credential"}
  credential_calls: {eq: 1}
```

## Extensions

Added by the independent fixture author while writing one fixture set per 13.2 check. Nothing above changes;
these are new keys and rules the first fixture set needs, and the loader and harness accept them like the rest.

| Extension | Meaning | Used by |
|---|---|---|
| URL key `any_roblox` | Fallback for any request to an allowed Roblox host that no other key matches. A more specific key always wins. For checks whose Roblox URL is the implementer's choice. | H-CLOCK |
| `**` in a URL key path | Matches one or more path segments (`*` still matches exactly one). The `*`, `**` and `?*` rules apply to `origin:` keys too. | H-NGINX (`origin:/static/**`), H-E2E (`origin:/games.roblox.com/v1/games?*`) |
| `exit_ip_by_session: [..]` on an `ip_echo` response | Instead of `exit_ip`: the n-th distinct `session_id` the harness sees at `EgressClients.send` (`OutboundRequest.session_id`) gets the n-th address, whatever order the requests arrive in. A request without a session id, or more distinct ids than entries, fails the test. | H-ROTATOR-SESSION |
| `inputs.env` keys starting with `ROXY_` | Also applied to the `EnvSettings` the check reads (as if set before startup), not only to the process environment. | H-NGINX (`ROXY_NGINX_WORKER_PROCESSES`, `ROXY_NGINX_WORKER_CONNECTIONS`), H-WORKERS, H-LEADER and H-LOOP-LAG (`ROXY_WORKERS`), H-SYSTEMD (`ROXY_COLOR`) |
| `x_self: true` on a `state.workers` row | That row is the heartbeat of the worker running the check: the harness gives the checking worker the row's `pid` and `worker_id`. At most one row per file. | H-WORKERS |
| `state.leader.x_jobs` | The leader's job status as `JobRunner.status()` reports it: `[{name, interval_s, last_started_at, last_finished_at, last_ok}]` (times in the time grammar). Read through a provider, because job status lives in the leader's memory. | H-LEADER |
| `state.raw.control` | Only `{settings: [{key, value_json, updated_at, updated_by}]}`: control.db `settings` rows written exactly as given, with no `validate_value` or `validate_cross`, the way an older release or a hand edit can leave them. A key here must not also appear in `inputs.settings`. | H-CONFIG |
| `backup.last_backup_at: null` | No backup has ever completed. | H-BACKUP |
| Unmocked DNS or TLS host | A lookup or handshake for a host with no entry in `inputs.dns` or `inputs.tls` fails the test, like an unmocked HTTP request. The H-DNS and H-TLS fixtures set `allowed_roblox_hosts` to a short list so the inputs can name every host. | H-DNS, H-TLS |
| `case: "n/a"` | Appears only in variants, so no file name needs a slash. A variant keeps the file's `run` trigger. | H-CRED-AUTH, H-ROTATOR-SESSION, H-ROTATOR-QUOTA |
| Replacing a whole response in a variant | Write the variant's response as a one-item list (`"probe:games.roblox.com": [{error: timeout}]`): a list replaces the file's value instead of merging into it, so no field of the old response (`status`, `body`) survives next to the new `error`. Other maps that would need replacing rather than merging (a `dns` or `tls` answer turning into an `error`, `timedatectl` turning from `show` into `error`) get their own file instead of a variant. | H-REACH, H-ROTATOR-REACH |
| `expect.data_checks` | Exactly the insights `data_checks` (same measures and `where` keys), run on the loaded data before the check, so a traffic-based fixture proves its own numbers. Variants do not repeat them. | H-LATENCY, H-429-RATE, H-ERR-RATE, H-CACHE-HIT |

Conventions the fixtures follow (no format change, written down so check authors know what to expect):

- `value` constraints with numeric operators assume the first number in the stored `value` text is the measured
  value in the unit 13.2 names (`"875 ms"`, `"0.4%"`, `"45 s"`, `"22 days"`, `"30 h"`). Checks whose value starts
  with something else (H-REACH starts with the status) are only checked with `present` or `regex`.
- `fix_link` constraints use a case-insensitive `regex` on the page or runbook named in 13.2's "Fix link" column,
  or only `present: true` where the column names something generic ("Ops docs", an unnamed "Runbook"). Checks
  with an empty "Fix link" cell are not constrained.
- Probe answers carry placeholder ids: fixtures cannot know the public ids in `health/probes.py`, so a check
  verifies the shape 13.4 names (`data` present, `id` present), never a specific id.
