# Roxy runbooks

What to do when something goes wrong. Each runbook has the same parts:

- **Symptoms**: what you notice (an alert, a failing health check, a page that looks wrong).
- **Confirm**: where to look to be sure, on the dashboard and from the server shell.
- **Likely causes**: what usually explains it.
- **Fix**: the steps, safest first.
- **Verify**: how to tell it worked.
- **Roll back**: how to undo the fix if it made things worse.
- **Prevent**: how to make it less likely next time.

Alert emails and failing health checks link straight to the right runbook; the [link index](#link-index) and the
[health check table](#health-checks-and-their-runbooks) list every link. Background on how the pieces fit together
is in `docs/ARCHITECTURE.md`, and the security side in `docs/SECURITY.md`.

## How to use these runbooks

Three rules first:

1. **Never paste a secret into a ticket, chat, reason box or log.** Roxy redacts what it can, but the safest
   secret is one that was never typed anywhere else.
2. **Prefer the dashboard.** Every dashboard change is validated, audited and reaches every worker within a second.
   The shell tool `scripts/ctl.py` uses the same services, for when the dashboard is out of reach.
3. **One credential, always** (plan C1). No fix in this book ever adds a second Roblox account.

Dashboard pages live at `/admin/<page>` (for example `/admin/upstream`). Each step also names the admin API route
the page uses (for example `GET /admin/api/v1/upstream/cooldowns`), which is handy when a page is still being built
or when you want the raw numbers.

Two colors exist on the server, `roxy@blue` and `roxy@green`. Normally one serves and the other is stopped. In the
commands below, replace `blue` with the color that is live.

## Everyday commands

```sh
# Which color is live? (prints roxy-upstream-blue.conf or roxy-upstream-green.conf)
readlink /etc/nginx/roxy-active-upstream.conf

# Are the colors running, and why did one stop?
systemctl status roxy@blue roxy@green
systemctl show roxy@blue -p ActiveState,NRestarts
journalctl -u roxy@blue --since "1 hour ago"

# Ask one worker of a color directly, on its internal socket (root or the roxy group only)
sudo curl -sS --unix-socket /run/roxy-blue/internal.sock http://localhost/internal/ready
sudo curl -sS --unix-socket /run/roxy-blue/internal.sock http://localhost/internal/version

# What monitors see (Status, Paused, PersistenceOK, Degraded, DataBytes)
curl -sS https://<your site>/health

# The deploy's own records
cat /var/lib/roxy-deploy/deployed_version
cat /var/lib/roxy-deploy/last_failure.json
```

The operator CLI runs as the `roxy` user: its database commands refuse to run as anyone else, because SQLite files
created by root would lock the service out. A short alias saves typing:

```sh
alias roxyctl='sudo -u roxy /opt/roxy/releases/current-blue/.venv/bin/python /opt/roxy/releases/current-blue/scripts/ctl.py'
roxyctl status
roxyctl leader
roxyctl jobs
roxyctl settings show allowed_requests_per_minute
```

The CLI finds the databases and the sockets from `/etc/roxy/roxy.env` and the color env files, and falls back to
`/var/lib/roxy` and `/run/roxy-<color>/internal.sock` when it cannot read them. Commands that change something are
audited as `cli:<your login name>`.

Roxy's own logs are JSON lines in the journal under `roxy-blue` and `roxy-green`; nginx writes its structured
access log to `/var/log/nginx/roxy.access.log`.

## Link index

Alert emails link to `/admin/help#runbook-<name>`; health checks link to `/admin/help/runbooks#<name>` or
`/admin/help/operations#<name>`. This table resolves every one of those names.

| Link name | Used by | Runbook |
|---|---|---|
| `unhandled-errors` | alert "Roxy Error: <signature>" | [Unhandled errors](#unhandled-errors) |
| `all-upstream-unavailable` | alert "Roxy: all upstream methods unavailable" | [All upstream paths unavailable](#all-upstream-paths-unavailable) |
| `credential-rejected` | alert "Token Expired", health checks H-CRED-AUTH and H-CRED-PRESENT | [Credential rejected](#credential-rejected) |
| `credential-cooldown` | alert "Roxy: credential cooling down", health check H-CRED-COOLDOWN | [Credential cooling down](#credential-cooling-down) |
| `credential-rotated` | alert "Roxy: Roblox sent a new credential cookie" | [Credential rotated by Roblox](#credential-rotated-by-roblox) |
| `unexpected-admin-login` | alert "Roxy Admin Login" | [Unexpected admin login](#unexpected-admin-login) |
| `service-down` | alert "Roxy DOWN: <unit> failed on <host>", health check H-SYSTEMD | [Service down](#service-down) |
| `deploy-failed` | alert "Roxy: deploy <short sha> failed at step <n>" | [Deploy failed](#deploy-failed) |
| `leak-guard` | alert "Roxy SECURITY: credential leak blocked", health check H-CRED-GUARD | [Leak guard](#leak-guard) |
| `roblox-429` | alert "Roxy: Roblox is rate-limiting us (<rate>%)", health check H-429-RATE | [Roblox is rate-limiting us](#roblox-is-rate-limiting-us) |
| `caller-5xx` | alert "Roxy: caller errors at <rate>%", health check H-ERR-RATE | [Caller errors](#caller-errors) |
| `rotator-quota` | alert "Roxy: rotator at <pct>% of monthly quota" | [Rotator down or quota exhausted](#rotator-down-or-quota-exhausted) |
| `disk` | alert "Roxy: storage at <pct>% of budget" | [Disk full or database large](#disk-full-or-database-large) |
| `db-integrity` | alert "Roxy: database integrity check failed" | [Database corrupt](#database-corrupt) |
| `backup` | alerts "Roxy: backup failed" and "Roxy: no backup for <hours> h" | [Backups](#backups) |
| `health-failures` | alert "Roxy: health check found <n> new failures" | [Health check found new failures](#health-check-found-new-failures) |
| `auto-apply-rollback` | alerts "Roxy: auto-applied change rolled back" and "Roxy: auto-applied change could not be rolled back" | [Auto-applied change rolled back](#auto-applied-change-rolled-back) |
| `login-throttled` | alert "Roxy: login attempts throttled globally" | [Login attempts throttled](#login-attempts-throttled) |
| `daily-digest` | alert "Roxy daily digest: <n> open recommendations" | [Daily digest](#daily-digest) |
| `dns` | health check H-DNS | [DNS](#dns) |
| `tls` | health check H-TLS | [TLS](#tls) |
| `database-corrupt` | health check H-DB-INTEGRITY | [Database corrupt](#database-corrupt) |
| `certificate` | health check H-TLS-PUBLIC | [Certificate](#certificate) |
| `clock` | health check H-CLOCK | [Clock](#clock) |
| `file-permissions` | health check H-SECRETS-PERMS | [File permissions](#file-permissions) |
| `backups` | health check H-BACKUP | [Backups](#backups) |
| `operations#environment` | health check H-ENV-PROXY | [Proxy variables in the environment](#proxy-variables-in-the-environment) |
| `operations#end-to-end` | health check H-E2E | [End to end check](#end-to-end-check) |
| `operations#nginx` | health check H-NGINX | [nginx](#nginx) |
| `operations#deploy` | health check H-VERSION | [Version mismatch](#version-mismatch) |

## Health checks and their runbooks

Check Proxy Health (the button on the Overview and Health pages, `POST /admin/api/v1/health/runs`, or
`roxyctl health-run`) runs every check below. When one warns or fails, start here.

| Check | What it looks at | Runbook |
|---|---|---|
| H-CRED-PRESENT | A credential is configured | [Credential rejected](#credential-rejected) |
| H-CRED-AUTH | The credential still signs in, as the same account | [Credential rejected](#credential-rejected) |
| H-CRED-COOLDOWN | The credential is not cooling down | [Credential cooling down](#credential-cooling-down) |
| H-CRED-GUARD | The leak guard self-test blocks a synthetic leak | [Leak guard](#leak-guard) |
| H-ENV-PROXY | No proxy or key log variables reach the clients | [Proxy variables in the environment](#proxy-variables-in-the-environment) |
| H-DNS | Every allowed Roblox host resolves quickly to public addresses | [DNS](#dns) |
| H-TLS | A TLS handshake to every allowed Roblox host works | [TLS](#tls) |
| H-REACH-<host> | Each Roblox host answers its probe | [Upstream slow or unreachable](#upstream-slow-or-unreachable) |
| H-E2E | Two requests through nginx and the whole pipeline | [End to end check](#end-to-end-check) |
| H-LATENCY | Upstream p95 latency, last 15 minutes | [Upstream slow or unreachable](#upstream-slow-or-unreachable) |
| H-429-RATE | Roblox 429 share, last 15 minutes | [Roblox is rate-limiting us](#roblox-is-rate-limiting-us) |
| H-ERR-RATE | Caller-facing 5xx share, last 15 minutes | [Caller errors](#caller-errors) |
| H-CACHE-RW | A cache.db write, read and delete round trip | [Cache not working](#cache-not-working) |
| H-CACHE-HIT | Share of requests the cache answered, last hour | [Cache not working](#cache-not-working) |
| H-DB-INTEGRITY | `PRAGMA quick_check` on control.db and hot.db | [Database corrupt](#database-corrupt) |
| H-DB-SIZE | Database sizes against the budget | [Disk full or database large](#disk-full-or-database-large) |
| H-WAL | WAL file sizes | [Disk full or database large](#disk-full-or-database-large) |
| H-DISK | Free space on the state volume | [Disk full or database large](#disk-full-or-database-large) |
| H-WORKERS | Fresh heartbeats from every worker | [Workers or leader missing](#workers-or-leader-missing) |
| H-LEADER | One leader, jobs on time | [Workers or leader missing](#workers-or-leader-missing) |
| H-LOOP-LAG | Event loop lag p99, last 5 minutes | [Slow event loop](#slow-event-loop) |
| H-ROTATOR-REACH | The rotator answers an IP echo | [Rotator down or quota exhausted](#rotator-down-or-quota-exhausted) |
| H-ROTATOR-SESSION | Sticky rotator sessions keep and change exits | [Rotator down or quota exhausted](#rotator-down-or-quota-exhausted) |
| H-ROTATOR-QUOTA | Rotator quota left and the cycle projection | [Rotator down or quota exhausted](#rotator-down-or-quota-exhausted) |
| H-SYSTEMD | Both color units, restarts in 24 h | [Service down](#service-down) |
| H-NGINX | HSTS, hidden version, `/internal` hidden, tarpit budget | [nginx](#nginx) |
| H-TLS-PUBLIC | Days left on the public certificate | [Certificate](#certificate) |
| H-CLOCK | Clock skew against Roblox and NTP status | [Clock](#clock) |
| H-CONFIG | Settings and rules validate | [Config or ban list problems](#config-or-ban-list-problems) |
| H-BANS | No ban covers the admin, a bypass entry or a top place | [Config or ban list problems](#config-or-ban-list-problems) |
| H-SECRETS-PERMS | Credential, env, backup and database file modes | [File permissions](#file-permissions) |
| H-ALERTS | The alert channels log in without sending | [Alert channels down](#alert-channels-down) |
| H-BACKUP | Age of the last backup and its restore test | [Backups](#backups) |
| H-VERSION | The running version is the deployed one | [Version mismatch](#version-mismatch) |

## Emergency stop

Plan 17.8: "Emergency: stop all upstream traffic".

**Symptoms.** You need Roxy to stop calling Roblox right now: Roblox is complaining, the account is at risk, the
rotator bill is running away, or you suspect a compromise.

**Confirm.** Decide how far to go. Pausing stops every caller request at once and keeps the dashboard working;
switching the egresses off also stops Roxy's own calls; stopping the service stops everything, the dashboard too.

**Likely causes.** Not applicable: this is the big red button.

**Fix.**

1. Pause the proxy: the Pause switch in the dashboard's top bar (`POST /admin/api/v1/protection/pause`), or
   `roxyctl pause --reason "Back soon."`. Every proxied request gets 503 with `Roxy-Paused: True` and a
   `Retry-After`. Nothing skips a pause, not even bypass entries.
2. While paused, Roxy still makes its own calls: the credential liveness probe every `credential_probe_interval_min`
   minutes, scheduled health runs every `health_auto_interval_h` hours, and anything an admin starts. To stop those
   too, switch the egresses off: set `direct_enabled`, `rotator_enabled` and `credential_enabled` to 0 on the
   Settings page (`PATCH /admin/api/v1/settings`), or
   `roxyctl settings set direct_enabled=0 rotator_enabled=0 credential_enabled=0 --reason "emergency stop" --confirm-high-risk`.
   With every egress off, no request of any kind leaves for Roblox.
3. If the dashboard and the CLI are both out of reach, stop the service:
   `sudo systemctl stop roxy@blue roxy@green`. nginx then answers 502 and nothing runs.

**Verify.** `curl -sS https://<your site>/health` shows `"Paused":true`; the Upstream page shows no new calls
(`GET /admin/api/v1/upstream/internal-calls` for Roxy's own calls, `GET /admin/api/v1/traffic/requests` for
callers).

**Roll back.** Resume (the same switch, or `roxyctl resume`), set the egress settings back (the Settings page
history has one-click revert, `POST /admin/api/v1/settings/history/{history_id}/revert`), and if you stopped the
service, start the color nginx points at with `sudo /usr/local/sbin/roxy-switch-color --boot`.

**Prevent.** For planned work, schedule a maintenance window instead (`PUT /admin/api/v1/protection/pause/schedule`):
callers get the window's end as their `Retry-After`.

## Roblox is rate-limiting us

**Symptoms.** The alert "Roxy: Roblox is rate-limiting us (<rate>%)"; health check H-429-RATE warns (0.5% of
upstream calls or more) or fails (2% or more); callers get 429 answers carrying `Roxy-Upstream-Cooldown` or
`Roxy-Upstream-Status: 429`; recommendations UP-429-ENDPOINT or UP-429-HOST are open.

**Confirm.** On the Upstream page: the 429 timeline (`GET /admin/api/v1/upstream/429-timeline`), which endpoints
and hosts get them (`GET /admin/api/v1/upstream/hosts`), the active cooldowns
(`GET /admin/api/v1/upstream/cooldowns`) and the split by egress (`GET /admin/api/v1/upstream/egress`).

**Likely causes.**

- One popular endpoint is fetched from Roblox too often: its cache lifetime is short, or callers add a changing
  parameter (a cache buster) so every request is a miss.
- An endpoint or host bucket allows more than Roblox accepts.
- Traffic is going out with the credential (the credential allowlist is not empty).
- Through the rotator: individual exit addresses were limited (Roxy only cools down an endpoint on the rotator after
  three different exits got 429s).

**Fix.**

1. Open Recommendations (`GET /admin/api/v1/recommendations`). The rules UP-429-ENDPOINT, UP-429-HOST,
   UP-BUCKET-TUNE, CACHE-TTL-TUNE and CACHE-KEYSPLIT look at exactly this. Preview a recommendation
   (`GET /admin/api/v1/recommendations/{rec_id}/preview`), read the evidence, and apply it
   (`POST /admin/api/v1/recommendations/{rec_id}/apply`).
2. Raise the lifetime of the hot endpoint with a cache rule on the Cache page (`POST /admin/api/v1/cache/rules`).
3. If a parameter splits the cache, add it to the ignored parameters (`POST /admin/api/v1/cache/ignored-params`);
   the key spread view (`GET /admin/api/v1/cache/spread`) names the varying parameter.
4. Lower the endpoint or host bucket on the Upstream page (`POST /admin/api/v1/upstream-limits` for a new
   override, `PATCH /admin/api/v1/upstream-limits/{bucket_key}` for an existing one; keys look like
   `endpoint:<template>` or `host:<host>`). Adaptive rate control already lowers a bucket after a 429 while
   `adaptive_rate_enabled` is on.
5. Check the credential allowlist (`GET /admin/api/v1/credential-allowlist`). It should be empty unless you decided
   otherwise (owner decision D1).
6. Do not clear the cooldowns to make the 429s go away. A cooldown is Roblox telling Roxy to wait; Roxy already
   serves stale data during a cooldown when it has some.

**Verify.** Run Check Proxy Health 15 minutes later: H-429-RATE passes. The 429 timeline flattens.

**Roll back.** Undo an applied recommendation (`POST /admin/api/v1/recommendations/{rec_id}/undo`), revert a
setting from the Settings history, or delete the rule or bucket override you added.

**Prevent.** Look at the Recommendations page daily, keep `adaptive_rate_enabled` on, and give popular endpoints
cache rules before traffic grows.

## All upstream paths unavailable

**Symptoms.** The alert "Roxy: all upstream methods unavailable" (sent only when every egress is off, not for one
endpoint's cooldown); callers get 503 `egress_disabled`, or stale answers.

**Confirm.** The Upstream page egress card (`GET /admin/api/v1/upstream/egress`) gives each egress's state and
why; leak guard trips are listed by `GET /admin/api/v1/egress/trips`; the rotator's state by
`GET /admin/api/v1/rotator`. `/health` lists `egress_direct_disabled` or `egress_rotator_disabled` in `Degraded`
after a leak guard trip.

**Likely causes.** `direct_enabled` was switched off while the rotator is unconfigured, parked after failures, or
over its budget; or the leak guard disabled the direct path.

**Fix.**

1. A leak guard trip: follow [Leak guard](#leak-guard). Do not re-enable before you know why it tripped.
2. A setting: turn `direct_enabled` back on (the Settings page, or `roxyctl settings set direct_enabled=1`).
3. The rotator: follow [Rotator down or quota exhausted](#rotator-down-or-quota-exhausted).

**Verify.** The egress card shows at least one egress enabled; the Traffic page shows answers served from Roblox
again.

**Roll back.** Revert the setting from the Settings history.

**Prevent.** Keep the direct path on; it is the normal path for public traffic and costs nothing.

## Credential rejected

Plan 17.8: "Credential rejected or expired".

**Symptoms.** The alert "Token Expired"; the Credential page says rejected; health check H-CRED-AUTH fails (Roblox
answered 401 or 403, or the cookie now belongs to a different account); H-CRED-PRESENT fails when no credential is
configured at all.

**Confirm.** The Credential page (`GET /admin/api/v1/credential`) and its probe history
(`GET /admin/api/v1/credential/probes`). "Check credential" (`POST /admin/api/v1/credential/check`) probes once more;
it needs a fresh second factor and spends one call on the account. A 429 from that probe means "rate limited", not
"expired".

**Likely causes.** The cookie expired, the account was signed out everywhere, its password changed, or Roblox reset
its session.

**Fix.** Follow the C1 rules: one account, replaced deliberately, never a second account.

1. Sign in to the same Roblox account in a private browser window and copy its `.ROBLOSECURITY` cookie value.
2. On the Credential page choose Replace (`POST /admin/api/v1/credential/replace`). It asks for a fresh second
   factor, a reason, and the typed phrase `replace the credential`. The old value stops being used everywhere at
   once, and Roxy probes the new one right away to record the account.
3. After a replacement from the dashboard, empty the bootstrap file so the old cookie is not kept on disk:
   `sudo truncate -s 0 /etc/roxy/credentials/roblox_credential`. Keep the file itself: systemd expects it, and an
   empty file means "no bootstrap value".
4. If H-CRED-AUTH reports a different account than the one recorded, the cookie belongs to another Roblox account,
   and using it would be an account switch (C1). After going back to the bootstrap file (see "Roll back" below),
   Roxy probes that cookie and does not use one of a different account until you confirm the switch
   (`POST /admin/api/v1/credential/confirm-account` with the typed phrase `switch to the other account`). Confirm
   only if you meant it.

**Verify.** H-CRED-AUTH passes with the same account; the Credential page shows active.

**Roll back.** There is no automatic way back to an older value, on purpose. Deleting the dashboard value
(`DELETE /admin/api/v1/credential/ui-value`) returns to the bootstrap file, which is only useful when that file holds
a valid cookie of the same account.

**Prevent.** Do not sign the account out everywhere or change its password without planning a replacement. Keep
`credential_probe_interval_min` at its default, so an expired cookie is noticed within half an hour.

## Credential cooling down

**Symptoms.** The alert "Roxy: credential cooling down" (a cooldown longer than 10 minutes); health check
H-CRED-COOLDOWN warns or fails.

**Confirm.** The Credential page (`GET /admin/api/v1/credential`) shows the remaining cooldown and where it came
from; the cooldown row `credential` is on the Upstream page (`GET /admin/api/v1/upstream/cooldowns`); recent
credential calls are on `GET /admin/api/v1/credential/budget`.

**Likely causes.** Roblox answered 429 on a credential call: allowlisted traffic was too fast, probes ran too often,
or the account hit a limit of its own.

**Fix.**

1. Wait. During the cooldown no worker uses the credential, which is exactly what Roblox asked for.
2. Lower `credential_bucket_per_min` if allowlisted traffic caused it, and review the credential allowlist.
3. Raise `credential_probe_interval_min` if probes caused it (recommendation CRED-PROBE-COST says so when it applies).
4. Avoid "Reset upstream state" (`POST /admin/api/v1/upstream/reset`): it clears every cooldown, the credential's
   included, and the next call may be refused again with a longer wait.

**Verify.** H-CRED-COOLDOWN passes once the cooldown ends; no new credential 429s.

**Roll back.** Revert the settings from the Settings history.

**Prevent.** Keep the allowlist small and the credential bucket modest; plan 13.3 expects about 50 to 60 credential
calls a day with an empty allowlist.

## Credential rotated by Roblox

**Symptoms.** The alert "Roxy: Roblox sent a new credential cookie".

**Confirm.** The audit log (`GET /admin/api/v1/audit`) has the rotation entry; the Credential page shows the current
status.

**Likely causes.** Roblox refreshed the account's session and sent a new `.ROBLOSECURITY` cookie. Roxy never stores
it (plan C1): the value Roxy holds may stop working soon.

**Fix.**

1. Sign in to the same account in a private browser window and copy the cookie it has now.
2. Replace the credential as in [Credential rejected](#credential-rejected), steps 2 and 3.

**Verify.** H-CRED-AUTH passes with the same account.

**Roll back.** Not applicable; the old value is what Roblox is retiring.

**Prevent.** Nothing to do: Roblox decides when to rotate. The alert exists so a rotation never turns into a
surprise expiry.

## Leak guard

Plan 17.8: "Leak guard tripped". Treat it as a security incident.

**Symptoms.** The alert "Roxy SECURITY: credential leak blocked" (never capped, never deduplicated away); `/health`
lists `egress_direct_disabled` or `egress_rotator_disabled` in `Degraded`; health check H-CRED-GUARD fails if the
guard itself is broken.

**Confirm.** The trips list (`GET /admin/api/v1/egress/trips`) gives the egress, the request id, where the value was
found (a header, the URL or the body) and the code path that built the request; the audit log has the trip. The
request itself: `GET /admin/api/v1/live/{request_id}` and `GET /admin/api/v1/upstream/trace/{request_id}`.

**Likely causes.** A code path put the credential into an anonymous request: a bug, a bad change, or a compromise. A
caller typing the public cookie name or warning text never trips the guard (that is refused as auth smuggling
instead), so a trip always deserves an explanation.

**Fix.**

1. Leave the tripped egress off; Roxy already switched it off for every worker. If the rotator tripped, also set
   `rotator_weight` to 0 or `rotator_enabled` to 0 so nothing is routed there.
2. Collect the evidence: the alert, the trips list, the audit rows, the deployed commit
   (`cat /var/lib/roxy-deploy/deployed_version`) and recent setting and rule changes (the Audit page).
3. Find the code path. Only `src/roxy/egress/credential.py` may read the credential; the request named in the trip
   shows which purpose built it.
4. If there is any doubt that the value stayed private, replace the credential once, with the same account
   ([Credential rejected](#credential-rejected), steps 1 to 3). One replacement, never a second account.
5. Fix and deploy the code, then re-enable the egress: `POST /admin/api/v1/egress/{name}/enable` with a reason (a
   fresh second factor is required; the reason goes into the audit log).

**Verify.** H-CRED-GUARD passes; `/health` shows no `egress_*_disabled` entry; requests are served through the
re-enabled egress.

**Roll back.** If the cause is not fixed, a new trip switches the egress off again. Re-enabling is itself the undo
of a trip, so only re-enable once the cause is understood.

**Prevent.** Keep every read of the credential inside `src/roxy/egress/credential.py`; the test
`tests/security/test_credential_suite.py::test_only_credential_module_reads_secret` fails the build otherwise.

## Rotator down or quota exhausted

**Symptoms.** The alert "Roxy: rotator at <pct>% of monthly quota"; health checks H-ROTATOR-REACH,
H-ROTATOR-SESSION or H-ROTATOR-QUOTA warn or fail; the Egress page shows the rotator parked or stopped.

**Confirm.** The Egress page: the rotator's state (`GET /admin/api/v1/rotator`), the budget and projection
(`GET /admin/api/v1/egress/rotator/budget`), usage (`GET /admin/api/v1/egress/usage`), and an IP echo through it
(`POST /admin/api/v1/egress/rotator/probe`).

**Likely causes.** The provider is down or the URL's password changed; the monthly quota or the daily cap is spent
(`rotator_hard_stop_pct` of `rotator_quota_gb_per_month`, or `rotator_daily_cap_mb`); a failure streak parked it for
`rotator_cooldown_s` after `rotator_max_failures` failures.

**Fix.**

1. Run direct only. The direct path is the default (`rotator_weight` is 0), so with the rotator off Roxy keeps
   serving from the server's own address. Set `rotator_enabled` to 0 if it should not be used at all for now.
2. Quota: buy more and raise `rotator_quota_gb_per_month`, or lower what goes through the rotator (weight, routing
   rules).
3. A wrong or changed URL: replace it on the Egress page (`PUT /admin/api/v1/rotator/url`, fresh second factor). The
   value is stored encrypted and never shown again.

**Verify.** H-ROTATOR-REACH passes (or the rotator is off with weight 0); the budget projection stays under the
quota.

**Roll back.** Turn `rotator_enabled` back on; `DELETE /admin/api/v1/rotator/url` goes back to the bootstrap URL in
`/etc/roxy/credentials/rotator_url`.

**Prevent.** Set the quota and the alert percentages (`rotator_budget_alert_pcts`) to what you pay for, and read the
EGR recommendations.

## Service down

Plan 17.8: "Site down / crash loop".

**Symptoms.** The alert "Roxy DOWN: <unit> failed on <host>" (sent by systemd's `OnFailure=`, even when the app
itself cannot send mail); the site answers 502 from nginx; health check H-SYSTEMD warns (restarts) or fails.

**Confirm.**

```sh
readlink /etc/nginx/roxy-active-upstream.conf
systemctl status roxy@blue roxy@green
systemctl show roxy@blue -p ActiveState,NRestarts
journalctl -u roxy@blue --since "1 hour ago"
sudo curl -sS --unix-socket /run/roxy-blue/internal.sock http://localhost/internal/ready
```

**Likely causes.** Read the journal for one of these:

- A failed pre-start step (`deploy/prestart.py`, which migrates the databases before every start), or
  `schema_too_old`: the databases are older than this release needs, which happens when a release is started by
  hand without that step.
- The port is taken: the master exits before it is ready when another program holds 127.0.0.1:8001 or 8002.
- Out of memory: the color passed `MemoryMax` and was killed.
- A missing credential file: systemd refuses to start the unit when a `LoadCredential=` file does not exist.
- A full disk, or a database that cannot be opened.
- A crash loop: five failed starts within 300 s put the unit in `failed`.

**Fix.**

1. If a deploy just happened, roll back first and investigate after: `/opt/roxy/deploy_rollback.sh` as the deploy
   user.
2. Fix the cause from the journal (free disk space, recreate a missing optional credential file as an empty file,
   lower `cache_memory_bytes` after an out-of-memory kill).
3. Start the color nginx points at: `sudo systemctl reset-failed roxy@blue`, then
   `sudo /usr/local/sbin/roxy-switch-color --boot`.

**Verify.** `/internal/ready` answers `"Ready":true` on the live color; `/health` answers; H-SYSTEMD passes after
24 hours without restarts.

**Roll back.** `/opt/roxy/deploy_rollback.sh <sha>` starts any of the five kept releases.

**Prevent.** Watch worker memory on the System page (`GET /admin/api/v1/system/workers`) and let deploys go through
`deploy.sh`, which never leaves the site without a healthy color.

## Deploy failed

**Symptoms.** The alert "Roxy: deploy <short sha> failed at step <n>"; the GitHub Action is red; health check
H-VERSION may report a mismatch.

**Confirm.** The Action log, and on the server `cat /var/lib/roxy-deploy/last_failure.json` (the step, the failing
command and whether the rollback worked). The steps are:

| Step | What it does | Usual causes |
|---|---|---|
| 1 | Fetch the commit | Not on `main`; the repository URL in `/etc/roxy/roxy.env` |
| 2 | Build the release | uv or the network; a lock file that does not match |
| 3, 4 | Migrations and the restart of the idle color | A failing migration (see the idle color's journal) |
| 5 | Health gate and smoke test | The new code does not start or a page fails (`scripts/smoke_remote.py` output) |
| 6 | nginx config and the switch | `nginx -t` refused the new config |
| 7 | Watch the new color for 60 s | Errors after the switch; before the cutover, the public check reaching v1 |
| 8 | Stop the old color | The old color did not stop in time |

**Likely causes.** See the table.

**Fix.**

1. Nothing is usually broken for callers: a failure before step 8 switches nginx back, restores the previous nginx
   config and stops the new color.
2. If `last_failure.json` says the rollback itself failed, put nginx back on the old color by hand:
   `sudo /usr/local/sbin/roxy-switch-color blue` (the old color) as the deploy user.
3. Fix the cause and deploy again: push a fixed commit, or run `/opt/roxy/deploy.sh <sha>` as the deploy user.
   Before the cutover, while v1 still answers the public host name, deploy with `ROXY_DEPLOY_PUBLIC_CHECK=0`.

**Verify.** `sudo curl -sS --unix-socket /run/roxy-blue/internal.sock http://localhost/internal/version` reports the
new commit; H-VERSION passes.

**Roll back.** `/opt/roxy/deploy_rollback.sh` returns to the previous release with the same health gate.

**Prevent.** Run `tests/deploy` before merging changes to `deploy/`; keep CI green.

## Caller errors

**Symptoms.** The alert "Roxy: caller errors at <rate>%"; health check H-ERR-RATE warns (0.5% or more of callers got
a 5xx in the last 15 minutes) or fails (2% or more).

**Confirm.** The Traffic page: status codes (`GET /admin/api/v1/traffic/status`) and who produced them
(`GET /admin/api/v1/traffic/status/sources`: Roblox, Roxy, the cache); the Live page filtered to 5xx
(`GET /admin/api/v1/live`); the errors table (`GET /admin/api/v1/system/errors`).

**Likely causes.**

- Roblox itself answers 5xx or times out (source Roblox): an outage on their side.
- Roxy answers 503 `degraded` because shared state is unavailable (a locked or full disk).
- Roxy answers 504 `deadline` because requests wait too long (queue, slow upstream).
- Roxy answers 500 `internal_error`: a bug.

**Fix.**

1. A Roblox outage: nothing to fix; the cache serves stale answers where it can. Check
   [Upstream slow or unreachable](#upstream-slow-or-unreachable).
2. `degraded`: check the disk and the databases ([Disk full or database large](#disk-full-or-database-large)).
3. `internal_error`: follow [Unhandled errors](#unhandled-errors).

**Verify.** H-ERR-RATE passes on the next run.

**Roll back.** Depends on the fix; a deploy can be rolled back with `/opt/roxy/deploy_rollback.sh`.

**Prevent.** Cache rules with a stale window on popular endpoints let Roxy answer through short Roblox outages.

## Unhandled errors

**Symptoms.** The alert "Roxy Error: <signature>"; the System page errors card grows.

**Confirm.** `GET /admin/api/v1/system/errors` lists each signature with its count and `module:line`;
`GET /admin/api/v1/system/errors/detail` shows the redacted traceback. The journal has the same error with its
request id: `journalctl -u roxy@blue --since "1 hour ago"`.

**Likely causes.** A bug, often in a newly deployed release; or a failing dependency underneath (a full disk, a
database that cannot be written) that surfaces as an unexpected exception.

**Fix.**

1. If the signature appeared right after a deploy, roll back: `/opt/roxy/deploy_rollback.sh`.
2. Rule out the disk and the databases first (`/health` `Degraded`, H-DISK, H-DB-INTEGRITY).
3. Otherwise record the signature, `module:line` and a request id, write a failing test, fix and deploy.

**Verify.** The error's count stops growing.

**Roll back.** `/opt/roxy/deploy_rollback.sh` to the previous release.

**Prevent.** Tests first; a deploy runs the health gate and smoke test before callers see a release.

## Disk full or database large

Plan 17.8: "Disk full or DB large".

**Symptoms.** The alert "Roxy: storage at <pct>% of budget"; health checks H-DB-SIZE, H-WAL or H-DISK warn or
fail; `/health` lists `storage_budget` in `Degraded`; in the worst case writes fail and Roxy runs degraded.

**Confirm.** The Data page: bytes per database and table with a 30-day projection
(`GET /admin/api/v1/data/storage`). On the server:

```sh
df -h /var/lib/roxy
sudo du -sh /var/lib/roxy/* /var/backups/roxy /opt/roxy/releases
```

**Likely causes.** Retention set longer than the disk allows; a flood of events; the cache at its byte cap
(`cache_max_bytes`); a WAL that does not shrink because a reader held it open; old snapshots, exports or releases;
the journal.

**Fix.**

1. Shorten retention on the Data page (for example `retention_minute_days`, `retention_events_days`,
   `events_max_rows`); the leader prunes within 10 minutes.
2. Purge the cache, all or only expired entries (`POST /admin/api/v1/cache/purge`, or
   `roxyctl purge-cache --expired`).
3. Reset a metric family you do not need (preview first: `POST /admin/api/v1/data/resets/preview`, then
   `POST /admin/api/v1/data/resets`).
4. Give the space back with VACUUM on the Data page (`POST /admin/api/v1/data/vacuum`; control, metrics or cache,
   never hot.db). VACUUM needs free space about the size of the database while it runs.
5. Lower `retention_snapshots_days` or `snapshots_max_bytes` when snapshots are large.
6. When the volume is completely full, free space first (an old backup set, the journal with
   `sudo journalctl --vacuum-size=500M`), then do the steps above.

**Verify.** H-DB-SIZE, H-WAL and H-DISK pass; `/health` no longer lists `storage_budget`.

**Roll back.** A reset takes a snapshot of the database it deletes from first (kept `retention_snapshots_days`);
putting one back is a restore ([Restore from backup](#restore-from-backup)).

**Prevent.** Keep `storage_total_budget_gb` below the real free space and read the SYS-DISK recommendation.

## Database corrupt

**Symptoms.** The alert "Roxy: database integrity check failed"; health check H-DB-INTEGRITY fails; errors that
mention a malformed database.

**Confirm.** The health check's detail names the file. Check by hand, read-only, as the `roxy` user (the `sqlite3`
command line tool is not installed by default, so use Python):

```sh
sudo -u roxy python3 -c "import sqlite3; print(sqlite3.connect('file:/var/lib/roxy/control.db?mode=ro', uri=True).execute('PRAGMA quick_check').fetchall())"
```

`[('ok',)]` means the file is fine.

**Likely causes.** A disk or file system problem, a full disk at the wrong moment, or a file copied while it was
being written.

**Fix.** It depends on the file:

1. **cache.db**: disposable. Restart the colors; each worker runs `quick_check` on cache.db at startup and rebuilds
   a damaged file.
2. **hot.db**: holds only short-lived state (limits, cooldowns, leases). Stop both colors
   (`sudo systemctl stop roxy@blue roxy@green`), move `hot.db` and its `-wal` and `-shm` files aside, and start the
   live color (`sudo /usr/local/sbin/roxy-switch-color --boot`): its pre-start step creates a fresh hot.db.
   Limits and cooldowns start from zero, so consider pausing for a few minutes to let Roblox's own limits reset.
3. **control.db** (settings, rules, admin accounts, the audit log): restore it from the last backup
   ([Restore from backup](#restore-from-backup)).
4. **metrics.db**: restore it, or move it aside and start fresh (losing the history).

**Verify.** `quick_check` answers `ok`; H-DB-INTEGRITY passes.

**Roll back.** Keep the moved-aside files until everything works again.

**Prevent.** Nightly backups with a monthly restore test; watch disk space.

## Backups

**Symptoms.** The alerts "Roxy: backup failed" or "Roxy: no backup for <hours> h", or "Roxy DOWN:
roxy-backup.service failed on <host>"; health check H-BACKUP warns (26 hours or older) or fails (72 hours or older,
never, or a failed restore test).

**Confirm.**

```sh
systemctl status roxy-backup.service roxy-backup.timer
journalctl -u roxy-backup.service --since "2 days ago"
sudo cat /var/lib/roxy/audit/backup.json
sudo ls -l /var/backups/roxy
```

The Data page lists the backups too (`GET /admin/api/v1/data/backups`).

**Likely causes.** A missing tool (`zstd`, `age`), a full disk, a damaged database (the copy failed its
`integrity_check`), an off-box copy (rclone) that failed, or the timer not running.

**Fix.**

1. Fix the cause from the journal.
2. Run the backup now: `sudo systemctl start roxy-backup.service` (or `roxyctl backup-now`).

**Verify.** `backup.json` records the success; a new dated directory appears in `/var/backups/roxy`; H-BACKUP passes.

**Roll back.** Not applicable.

**Prevent.** The backup runs nightly at 03:30 and tests a restore every 28 days on its own. Also practice the restore
below once a quarter (plan 17.5).

## Restore from backup

**Symptoms.** A database is damaged or lost, or a bad change has to be undone as a whole.

**Confirm.** Pick the backup set: `sudo ls /var/backups/roxy` lists one directory per day, each with
`control.db.zst` and `metrics.db.zst` (with `.age` appended when encrypted) and a `SHA256SUMS` file. Check it:
`cd /var/backups/roxy/<date> && sudo sha256sum -c SHA256SUMS`.

**Likely causes.** Not applicable.

**Fix.**

1. Stop both colors: `sudo systemctl stop roxy@blue roxy@green`.
2. Move the damaged files aside, for example `sudo mv /var/lib/roxy/control.db /var/lib/roxy/control.db.bad`, and
   the same for its `-wal` and `-shm` files.
3. Decrypt when the set is encrypted: `age -d -i <your identity file> control.db.zst.age > control.db.zst`.
4. Decompress into place: `sudo zstd -d control.db.zst -o /var/lib/roxy/control.db`.
5. Check it: run the `PRAGMA integrity_check` the same way as the quick check in
   [Database corrupt](#database-corrupt).
6. Give it back to the service: `sudo chown roxy:roxy /var/lib/roxy/control.db` and
   `sudo chmod 0640 /var/lib/roxy/control.db`.
7. If the disk was lost, restore `/etc/roxy/credentials/` from your offline copy first (below): backups never hold
   the encryption keys, and without `totp_encryption_key` nobody can sign in.
8. Start the live color: `sudo /usr/local/sbin/roxy-switch-color --boot`.
9. Run Check Proxy Health.

hot.db does not need restoring (a fresh one is created at start) and cache.db is never backed up.

The offline copy of the credentials (key escrow, plan 9.8) is made once, and again after any key changes, with
[age](https://age-encryption.org) and a key that does not live on the server:

```sh
# make the copy on the server, then move the file somewhere offline
sudo tar -C /etc/roxy -cf - credentials | age -r <your age public key> > roxy-credentials.tar.age
# restore it on a new server
age -d -i <your identity file> roxy-credentials.tar.age | sudo tar -C /etc/roxy -xf -
```

**Verify.** The dashboard loads, you can sign in, settings and rules are as expected, health checks pass.

**Roll back.** The moved-aside files are still there; stop the colors and move them back.

**Prevent.** Keep the offline copy current and practice this once a quarter.

## Under attack

Plan 17.8: "Under attack (flood)".

**Symptoms.** A sudden jump in requests and refusals; slower answers; ABUSE recommendations; spam detector events;
nginx answering 429 for the busiest addresses.

**Confirm.** The Protection page: refusals by reason (`GET /admin/api/v1/protection/refusals`) and the pipeline
counts (`GET /admin/api/v1/protection/pipeline`); the Clients page: top addresses (`GET /admin/api/v1/clients/ips`);
spam events (`GET /admin/api/v1/protection/spam/events`); the Live page. On the server, the nginx access log
`/var/log/nginx/roxy.access.log`.

**Likely causes.** A script or botnet hammering one endpoint; scanners probing paths; someone trying to exhaust
other callers' limits with fake `Roblox-Id` headers.

**Fix.** From the narrowest to the widest:

1. Ban the worst addresses or networks (`POST /admin/api/v1/clients/ips/{ip}/ban`, or the Bans card,
   `POST /admin/api/v1/protection/bans`). Bans look like ordinary throttles to the caller by default
   (`ban_disguise_as_throttle`), so they do not learn to switch addresses.
2. Put persistent offenders on the deny list (`POST /admin/api/v1/protection/access/{kind}` with kind `deny`).
3. Tighten the per-address limits: `allowed_requests_per_minute` and `flood_limit_per_minute`.
4. Arm the spam auto-ban after reading its collateral preview (`GET /admin/api/v1/protection/spam/collateral`, then
   `POST /admin/api/v1/protection/spam/arm`, fresh second factor). Places are never banned automatically.
5. Hold refused callers longer with the tarpit (the `tarpit_on_*` switches). Each hold costs Roxy one coroutine and
   one socket, and the fleet-wide cap (`tarpit_max_concurrent`) keeps it bounded.
6. Switch on throttle-all from the top bar (`POST /admin/api/v1/protection/throttle-all`, or
   `roxyctl throttle-all on --reason "Heavy load; please slow down."`): every client gets `global_throttle_limit`
   requests per `global_throttle_period` seconds. Legitimate callers feel it too; bypass entries skip it.
7. Pause as the last resort ([Emergency stop](#emergency-stop)).

The nginx limits (20 requests a second per address with a burst of 100, 50 connections per address) come from
`deploy/nginx/roxy.conf.template`; changing them is a code change and a deploy.

**Verify.** Refusals fall back, upstream calls look normal on the Upstream page, H-ERR-RATE passes.

**Roll back.** Switch throttle-all off (`roxyctl throttle-all off`), lift bans (`POST /admin/api/v1/protection/bans/lift`,
or `roxyctl bans lift ip <address>`), disarm the spam detectors (`POST /admin/api/v1/protection/spam/disarm`), and
revert settings from the Settings history.

**Prevent.** Arm the spam detectors once their collateral preview has been clean for a while, and read the ABUSE
and FILTER recommendations.

## Login attempts throttled

**Symptoms.** The alert "Roxy: login attempts throttled globally": more than `admin_login_global_max_per_min`
sign-in attempts in a minute, fleet-wide.

**Confirm.** The Security page logins (`GET /admin/api/v1/security/logins`) and the alert's top network prefixes.

**Likely causes.** Password guessing spread over many networks.

**Fix.**

1. Nothing urgent: beyond the cap each attempt waits `admin_login_global_delay_s` before it is checked, and every
   username and network still has its own lockout. Attempts are slowed, never refused, so you are not locked out.
2. Make sure your password is long and unique and TOTP is enrolled.
3. Consider the admin network allowlist (`admin_allowlist_enabled`): first add your own networks as `allow_admin`
   entries (`POST /admin/api/v1/protection/access/allow_admin`, fresh second factor), then switch it on. Every other
   network then gets a plain 404 for `/admin`.

**Verify.** The attempts per minute fall below the cap.

**Roll back.** Switch the allowlist off on the Security page, or from the server:
`roxyctl settings set admin_allowlist_enabled=0 --reason "allowlist off"`.

**Prevent.** The allowlist, when your networks are stable; passkeys as the second factor.

## Unexpected admin login

**Symptoms.** A "Roxy Admin Login" email you did not cause.

**Confirm.** The email names the address, browser and time. The Security page lists sessions
(`GET /admin/api/v1/security/sessions`) and recent logins.

**Likely causes.** Someone has the password and a second factor (a recovery code, a trusted device, or a stolen
authenticator).

**Fix.**

1. Open the kill-switch link in that email right away and confirm: it ends the sessions and, by default, revokes
   every trusted device. It works even from a network outside the admin allowlist.
2. On the server, set a new password: run `scripts/create_admin.py --reset-password` the way
   [Admin locked out](#admin-locked-out) shows. If the second factor may be compromised, use `--reset-mfa` too.
3. Sign in, regenerate the recovery codes (`POST /admin/api/v1/security/recovery-codes/regenerate`) and review
   passkeys (`GET /admin/api/v1/security/passkeys`).
4. Read the Audit page (`GET /admin/api/v1/audit`) for anything the session changed, and revert it: settings from
   their history, rules and bans by hand, the credential allowlist (`GET /admin/api/v1/credential-allowlist`), the
   rotator URL. The credential value is never shown on any page, but check whether it was replaced.
5. If the server itself (not only the dashboard) may be compromised, treat every file in `/etc/roxy/credentials/`
   as exposed: replace the Roblox credential once ([Credential rejected](#credential-rejected)) and change the
   rotator and mail passwords at their providers.

**Verify.** Only your session is listed; the audit log shows no further unexpected actions.

**Roll back.** Not applicable.

**Prevent.** Passkeys, the admin allowlist, and never reusing the admin password elsewhere.

## Admin locked out

**Symptoms.** You cannot sign in: a lost phone, a forgotten password, the allowlist hides `/admin` from your current
network, or the lockout answers 429.

**Confirm.** Which case it is: a 404 on the login page from a new network means the allowlist; "Too many attempts;
try again in N seconds." means the lockout; a wrong code with a lost phone means the second factor.

**Likely causes.** As above.

**Fix.**

1. **Lockout (429):** wait the seconds it says (at most `admin_login_window_s`), or sign in from another network.
2. **Lost phone, recovery codes at hand:** enter a recovery code instead of the authenticator code; each works once.
   Then enroll the new phone and regenerate the codes.
3. **The allowlist hides /admin:** from the server, `roxyctl settings set admin_allowlist_enabled=0 --reason "locked out"`.
4. **No authenticator and no recovery codes, or a forgotten password:** reset from the server console. The script
   needs the TOTP key, which only root can read, and must write the database as the `roxy` user, so run it through
   systemd:

```sh
sudo systemd-run --wait --pty --uid=roxy --gid=roxy -p UMask=0027 \
  -p LoadCredential=totp_encryption_key:/etc/roxy/credentials/totp_encryption_key \
  /opt/roxy/releases/current-blue/.venv/bin/python /opt/roxy/releases/current-blue/scripts/create_admin.py \
  --username <your admin name> --reset-mfa --state-dir /var/lib/roxy
```

   `--reset-mfa` makes a new authenticator secret (shown as a QR code in the terminal) and new recovery codes, and
   removes passkeys, trusted devices and sessions. Use `--reset-password` instead (or as well) for a forgotten
   password.

**Verify.** You can sign in with the new factor.

**Roll back.** Not applicable.

**Prevent.** Keep the recovery codes somewhere safe and offline, and enroll a passkey as a second way in.

## Certificate

Plan 17.8: "Certificate expiring".

**Symptoms.** Health check H-TLS-PUBLIC warns (21 days or fewer left) or fails (7 days or fewer, or a failed
handshake); browsers warn about the site.

**Confirm.** `sudo certbot certificates` lists the certificates and their expiry dates.

**Likely causes.** Automatic renewal stopped (its timer, a changed DNS record, a blocked port 80).

**Fix.**

1. Test renewal: `sudo certbot renew --dry-run`.
2. Fix what the dry run reports, then renew for real: `sudo certbot renew`.
3. Let nginx pick up the new certificate: `sudo nginx -t && sudo systemctl reload nginx`.

**Verify.** H-TLS-PUBLIC passes; `sudo certbot certificates` shows the new expiry.

**Roll back.** Not applicable; certbot keeps the previous certificate files.

**Prevent.** Certbot renews 30 days before expiry when its timer runs; H-TLS-PUBLIC warns three weeks ahead.

## Clock

Plan 17.8: "Clock skew".

**Symptoms.** Health check H-CLOCK warns (2 s or more off) or fails (10 s or more); authenticator codes are refused
although they are right; cooldowns and cache ages look odd.

**Confirm.** `timedatectl status` (look for "System clock synchronized: yes") and `timedatectl timesync-status`.

**Likely causes.** Time synchronization stopped or cannot reach its servers.

**Fix.** Restart it: `sudo systemctl restart systemd-timesyncd` (or chrony, if that is what the server uses), then
check again.

**Verify.** H-CLOCK passes; `timedatectl status` says synchronized.

**Roll back.** Not applicable.

**Prevent.** Keep one time service enabled.

## DNS

**Symptoms.** Health check H-DNS warns (slow) or fails (a lookup failed, or an allowed Roblox host resolved to a
private, loopback or link-local address).

**Confirm.** `resolvectl query games.roblox.com` and `resolvectl status`.

**Likely causes.** The resolver is down or slow; a private answer means a misconfigured or poisoned resolver. Roxy
does not trust DNS for safety (the host allowlist is the SSRF control), but a wrong answer still sends traffic to
the wrong place.

**Fix.** Check the resolver configuration and restart it: `sudo systemctl restart systemd-resolved`.

**Verify.** H-DNS passes.

**Roll back.** Not applicable.

**Prevent.** Use the provider's default resolvers unless you have a reason not to.

## TLS

**Symptoms.** Health check H-TLS warns (a Roblox certificate with 14 days or fewer left) or fails (a handshake to a
Roblox host failed).

**Confirm.** `openssl s_client -connect games.roblox.com:443 -servername games.roblox.com -brief </dev/null`.

**Likely causes.** A network path problem; the server's clock far off (certificates look not yet valid or expired);
an outdated CA bundle in the release (Roxy's clients use the `certifi` package).

**Fix.** Check [Clock](#clock) first. A failing handshake from the server's network is a provider or Roblox issue.
An outdated CA bundle is fixed by updating the dependency and deploying.

**Verify.** H-TLS passes.

**Roll back.** Not applicable.

**Prevent.** Keep dependencies current; CI's pip-audit step reports known vulnerabilities.

## File permissions

**Symptoms.** Health check H-SECRETS-PERMS warns (looser modes on non-secret files, or a report older than 7 hours)
or fails (looser modes on secret files).

**Confirm.** `sudo cat /var/lib/roxy/audit/perms.json` names every finding. Refresh it with
`sudo systemctl start roxy-audit.service`; check its timer with `systemctl status roxy-audit.timer`.

**Likely causes.** A file copied in with the wrong mode; a manual edit; the audit timer stopped.

**Fix.** Put the expected modes back, for example
`sudo chmod 0700 /etc/roxy/credentials && sudo chmod 0600 /etc/roxy/credentials/*`, env files 0640 root:roxy,
database files 0640 owned by `roxy`, and `/var/backups/roxy` 0700 root. Then run the audit again.

**Verify.** H-SECRETS-PERMS passes.

**Roll back.** Not applicable.

**Prevent.** Copy secrets with `sudo install -m 0600` rather than `cp`.

## Health check found new failures

**Symptoms.** The alert "Roxy: health check found <n> new failures" from a scheduled run.

**Confirm.** The Health page: the latest run (`GET /admin/api/v1/health/runs/latest`) and what changed since the
previous one (`GET /admin/api/v1/health/runs/{run_id}/compare`).

**Likely causes.** See each failing check in the [health check table](#health-checks-and-their-runbooks).

**Fix.** Open the runbook of each failing check. A failing check with a linked recommendation has an "Apply fix"
button on the Health page.

**Verify.** Run Check Proxy Health again (`POST /admin/api/v1/health/runs`, or `roxyctl health-run`).

**Roll back.** Not applicable.

**Prevent.** Scheduled runs (`health_auto_interval_h`) catch problems between visits; keep them on.

## Auto-applied change rolled back

**Symptoms.** The alert "Roxy: auto-applied change rolled back", or the critical alert "Roxy: auto-applied change
could not be rolled back".

The alert "Roxy: auto-applied change could not be rolled back" means a guard metric got worse but the automatic undo
was refused (usually because an admin changed the same row during the watch window), so the change is still in
place. Open the recommendation, review the watch result (`rollback.reason`), and undo or adjust the row by hand. A
rollback that only has to wait (another action holds the recommendation, or hot.db is busy) sends no alert: the
watch shows "rollback pending" and tries again every pass.

**Confirm.** The Recommendations history (`GET /admin/api/v1/recommendations/history`) and the recommendation's own
history (`GET /admin/api/v1/recommendations/{rec_id}/history`): the change, the guard metric and its before and
after.

**Likely causes.** With `insights_auto_apply` on, Roxy applied a small, safe recommendation, and during its watch
window (`auto_apply_watch_minutes`) the error rate, Roblox 429 rate, p95 latency or refused rate got worse by more
than `auto_apply_rollback_threshold_pct`, so Roxy undid it.

**Fix.** Usually nothing: the change is already undone. Check whether something else moved the metric at the same
time (a deploy, an attack, a Roblox outage). If the rule keeps proposing changes that do not help, dismiss the
recommendation or switch auto-apply off (`insights_auto_apply`).

**Verify.** The recommendation shows as rolled back and the setting or rule is back to its earlier value.

**Roll back.** Apply it again by hand after review (`POST /admin/api/v1/recommendations/{rec_id}/apply`).

**Prevent.** Auto-apply is off by default; keep it that way until the recommendations have proved themselves.

## Daily digest

**Symptoms.** The email "Roxy daily digest: <n> open recommendations". It is a summary, not an incident.

**Confirm.** The Recommendations page (`GET /admin/api/v1/recommendations`) and the Health page.

**Likely causes.** Not applicable.

**Fix.** Read the open recommendations; preview and apply, snooze or dismiss each one.

**Verify.** The count goes down over the following days.

**Roll back.** Undo an applied recommendation from its page.

**Prevent.** Not applicable.

## Upstream slow or unreachable

**Symptoms.** Health checks H-REACH-<host> or H-LATENCY warn or fail; answers are slow; circuit breakers open.

**Confirm.** The Upstream page: per-host answers and latency (`GET /admin/api/v1/upstream/hosts`,
`GET /admin/api/v1/upstream/latency`), breakers (`GET /admin/api/v1/upstream/breakers`) and the wait queue.

**Likely causes.** A Roblox service is down or slow; the server's network; requests queueing behind tight buckets
(recommendation UP-QUEUE-SAT).

**Fix.** A Roblox outage needs no action: breakers stop calls to a failing endpoint and the cache serves stale data.
Queueing: raise the bucket that binds, if Roblox accepts it (the UP-BUCKET-TUNE recommendation). Do not reset the
breakers repeatedly; each one probes on its own.

**Verify.** The checks pass on the next run.

**Roll back.** Revert bucket changes from the Upstream page.

**Prevent.** Cache rules with stale windows on the endpoints that matter most.

## Workers or leader missing

**Symptoms.** Health check H-WORKERS (stale heartbeats) or H-LEADER (no leader, or late or failing jobs) warns or
fails.

**Confirm.** The System page: workers and their heartbeats (`GET /admin/api/v1/system/workers`), the leader
(`GET /admin/api/v1/system/leader`) and the jobs (`GET /admin/api/v1/system/jobs`); from the server, `roxyctl leader`
and `roxyctl jobs`.

**Likely causes.** A worker crashed or its event loop froze (gunicorn restarts it); hot.db is locked so leases cannot
be renewed; a job keeps failing.

**Fix.**

1. Read the journal of the color for tracebacks.
2. Reload the color's workers gracefully: `sudo systemctl reload roxy@blue` (gunicorn starts new workers and lets the
   old ones finish).
3. A failing job names its error on the jobs card; fix the cause it names.

**Verify.** H-WORKERS and H-LEADER pass.

**Roll back.** Not applicable.

**Prevent.** Watch [Slow event loop](#slow-event-loop) and the disk.

## Slow event loop

**Symptoms.** Health check H-LOOP-LAG warns (p99 of 50 ms or more) or fails (200 ms or more); every request of a
worker gets slower.

**Confirm.** The System page workers card (`GET /admin/api/v1/system/workers`) shows each worker's loop lag; the
SYS-LOOP-LAG recommendation names likely causes.

**Likely causes.** Something blocking runs on the event loop (a new release), or the CPU is saturated.

**Fix.** Roll back a recent deploy (`/opt/roxy/deploy_rollback.sh`); otherwise read SYS-WORKER-SAT and SYS-LOOP-LAG.

**Verify.** H-LOOP-LAG passes.

**Roll back.** Not applicable.

**Prevent.** Blocking work (SQLite, argon2, compression) always goes to a thread; the loop-blocking tests check it.

## Cache not working

**Symptoms.** Health check H-CACHE-RW fails (a cache.db write, read or delete failed or was slow) or H-CACHE-HIT
warns (the cache answers 30% of requests or fewer).

**Confirm.** The Cache page: hit ratios and states (`GET /admin/api/v1/cache/stats`), the key spread
(`GET /admin/api/v1/cache/spread`).

**Likely causes.** For H-CACHE-RW: the disk or cache.db ([Disk full or database large](#disk-full-or-database-large),
[Database corrupt](#database-corrupt)). For H-CACHE-HIT: short lifetimes, cache busters, or traffic that is mostly
unique.

**Fix.** Apply the CACHE recommendations (CACHE-LOW-HIT, CACHE-TTL-TUNE, CACHE-KEYSPLIT, CACHE-OFF); check that
`cache_enabled` is on.

**Verify.** The checks pass on the next run.

**Roll back.** Undo the recommendation or delete the rule.

**Prevent.** Review the Cache page after traffic patterns change.

## Config or ban list problems

**Symptoms.** Health check H-CONFIG (a stored setting or rule no longer validates) or H-BANS (a ban covers the
admin's address, a bypass entry or a top place, or a very wide range without a note) warns or fails.

**Confirm.** The check's detail names the setting, rule or ban.

**Likely causes.** A setting stored before a release tightened its range; a ban that is wider than intended.

**Fix.** Correct the setting on the Settings page; lift or narrow the ban (`POST /admin/api/v1/protection/bans/lift`,
or `roxyctl bans lift cidr <range>`).

**Verify.** The checks pass on the next run.

**Roll back.** Settings history revert; recreate a ban if it was right after all.

**Prevent.** Give wide bans a note; check H-BANS after adding one.

## Alert channels down

**Symptoms.** Health check H-ALERTS warns (one channel down or not testable) or fails (every channel down). Alerts
may be failing silently.

**Confirm.** The check's detail says which step failed (connect, login, NOOP, the webhook).

**Likely causes.** The mail app password was revoked or changed; the webhook was deleted.

**Fix.**

1. Put the new value in its file: `/etc/roxy/credentials/smtp_password`, `/etc/roxy/credentials/alert_emails` or
   `/etc/roxy/credentials/alert_webhook_url` (root, 0600).
2. Credentials are read when a color starts. To pick them up without downtime, deploy the commit that is already
   running: `/opt/roxy/deploy.sh <the commit in /var/lib/roxy-deploy/deployed_version>`.

**Verify.** H-ALERTS passes on the next health run.

**Roll back.** Put the previous value back the same way.

**Prevent.** Note where each app password was made, so a change at the provider is not forgotten here.

## Proxy variables in the environment

**Symptoms.** Health check H-ENV-PROXY warns (`HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` is set in the service's
environment but ignored) or fails (a client would honor it, or `SSLKEYLOGFILE` is set).

**Confirm.** The check's detail names the variable; the environment files are `/etc/roxy/roxy.env` and
`/etc/roxy/blue.env` (or `green.env`).

**Likely causes.** A variable added to an env file, or inherited from a systemd drop-in.

**Fix.** Remove the variable, then deploy the running commit again to restart the colors without downtime (as in
[Alert channels down](#alert-channels-down)). `SSLKEYLOGFILE` must never be set on the server: it would record TLS
session keys.

**Verify.** H-ENV-PROXY passes.

**Roll back.** Not applicable.

**Prevent.** Keep the env files to the variables `deploy/env/roxy.env.example` lists.

## End to end check

**Symptoms.** Health check H-E2E warns (the cache did not answer the second request) or fails (an error status,
or a missing `Roxy-Request-Id` or security header) for a request sent through nginx to the public address.

**Confirm.** The check's detail; then the same request by hand, twice:
`curl -sS -D - -o /dev/null "https://<your site>/games.roblox.com/v1/games?universeIds=1"`.

**Likely causes.** nginx sends traffic to a color that is not running; the cache is off; a security header snippet
is missing from an nginx location.

**Fix.** Check [Service down](#service-down) and [nginx](#nginx); for the cache, [Cache not working](#cache-not-working).

**Verify.** H-E2E passes.

**Roll back.** Not applicable.

**Prevent.** The deploy's smoke test runs the same kind of request before every switch.

## nginx

**Symptoms.** Health check H-NGINX warns or fails: HSTS missing on a page or static file, nginx showing its version,
`/internal/version` reachable, or the tarpit connection budget out of line with nginx's settings.

**Confirm.** `sudo nginx -t` and `curl -sS -D - -o /dev/null https://<your site>/health`.

**Likely causes.** An nginx config that did not come from the release (edited by hand), or the default site still
enabled next to Roxy's.

**Fix.** nginx config is installed only from the verified release: `sudo /usr/local/sbin/roxy-nginx-apply <sha>` (as
the deploy user, with the full commit). Remove `/etc/nginx/sites-enabled/default` if it is still there.

**Verify.** H-NGINX passes.

**Roll back.** The wrapper keeps the previous config when `nginx -t` fails.

**Prevent.** Never edit the installed nginx files by hand; change `deploy/nginx/` in the repository and deploy.

## Version mismatch

**Symptoms.** Health check H-VERSION fails (the running release is not the one the last deploy recorded) or warns
(the last audit of dependencies found advisories).

**Confirm.** `cat /var/lib/roxy-deploy/deployed_version` against
`sudo curl -sS --unix-socket /run/roxy-blue/internal.sock http://localhost/internal/version`.

**Likely causes.** A release started by hand; a deploy that failed halfway ([Deploy failed](#deploy-failed)).

**Fix.** Deploy the commit you want live with `/opt/roxy/deploy.sh <sha>`; for advisories, update the dependency and
deploy.

**Verify.** H-VERSION passes.

**Roll back.** `/opt/roxy/deploy_rollback.sh`.

**Prevent.** Only deploy through `deploy.sh`.
