# Roxy v2 decisions review

Written on 2026-10-13 and completed on 2026-10-14 from branch `remake/v2` at commit 686fe46 (the final review round,
gated green: section 6), plan 0.1, 5.4 and 20.2, phase P14. One value is still to come: the quiet-machine performance
numbers in section 5, added when those runs finish (the owner chose to start reading before them). Nothing on the
server changes before they are in and this document is signed.

## 1. How to use this document

The plan asked the owner to confirm 23 decisions (plan 0.3, D1 to D23) and marked a few more values "PENDING" or
"owner verification". This document lists every one of them with the value Roxy v2 uses today, plus the decisions the
lead took where the plan was silent or contradicted itself, and what is still known to be imperfect.

What the words in the Status column mean:

- **Decided by the owner on (date):** you answered; the build follows your answer.
- **PENDING, default used:** you did not answer; the build used the plan's recommended default and nothing else.

What to do:

1. Read section 2. In the **Decision** column of each row, write **Agreed**, or the value you want instead.
2. Section 3 lists values only you can give or check. Fill them in.
3. Sections 4 and 5 are for reading. Write a note next to anything you disagree with, or anything that must be fixed
   before Roxy v2 goes live.
4. Sign in section 6.

**Nothing on the server changes before your signature.** No install, no data migration, no cutover step. The lead
stops here and waits. After you sign, the changes you wrote are made first, then the cutover follows `MIGRATION.md`.

Everything you must act on is marked **OWNER:**.

A few words used throughout:

- **The credential:** the `.ROBLOSECURITY` cookie of the one Roblox account Roxy holds. There is exactly one, and it
  never goes through the rotator (plan C1 and C2).
- **The rotator:** the paid DataImpulse proxy service, a pool of other IP addresses Roxy can send anonymous calls
  through.
- **Setting key:** the name of a setting on the Settings page (for example `rotator_weight`). Unless the table says
  otherwise, a setting is "live": a change takes effect at once, without a restart, and is recorded in the audit log
  with its history. A place such as `egress#budget` means the Egress page, Budget card, where the setting is also
  edited.
- **Color:** v2 runs as two copies of itself, blue and green. A deploy starts the idle color and switches nginx to it.
- **Worker:** one of the server processes inside a color (two by default).
- **Fresh second factor:** a second factor (an authenticator code or a passkey) entered in the last 10 minutes
  (`admin_reauth_window_s` 600). Risky actions ask for it again.

Owner instructions still in force during this run (from the handoff notes):

- Server changes only at the very end, once everything works. Read-only checks on the server only with your
  permission, and never anything under `/etc/roxy` that holds a secret.
- D1: never send the credential for callers. D4: callers see Roblox's real status. D5: authenticator app mandatory,
  with the emailed code once at the first sign-in. D10 reversed: cache hits count.
- `ROXY_WORKERS=2` on the 909 MB server, with no race between workers. Luau examples on the public site are strictly
  typed (`--!strict`) and highlighted (done).

## 2. Owner decisions D1 to D23

| ID | Question | Value used | Where it lives (default) | Status | What changing it later costs | Decision |
|---|---|---|---|---|---|---|
| D1 | Should caller (public) traffic ever carry the credential? | Never. The credential allowlist ships empty, so all caller traffic goes out anonymous. Only Roxy's own checks use the credential: the account probe and the health checks you start yourself. | Table `credential_allowlist`, no rows shipped (Credential page, Allowlist card; GET and HEAD only, at most 50 rows). `credential_enabled` 1, `credential_probe_interval_min` 30, `health_auto_include_credential` 0. | Decided by the owner on 2026-10-07 (was ASK) | A row takes a minute to add (fresh second factor, a reason and a `cache_private` choice: whether the account's answers may be kept in the shared cache), but each row puts your account back on caller traffic, the risk plan section 2 describes. | OWNER: |
| D2 | Process model | gunicorn with uvicorn workers, 2 workers per color, each recycled after 20,000 requests plus a random extra of up to 10 percent, so the two never restart at the same moment. | `ROXY_WORKERS=2` and `ROXY_MAX_REQUESTS=20000` in `/etc/roxy/roxy.env` (`deploy/env/roxy.env.example`, `deploy/gunicorn.conf.py`). | PENDING, default used (2 workers is also your instruction) | A restart of the colors. More workers need memory the 909 MB server does not have (section 5). | OWNER: |
| D3 | Shared store | SQLite in WAL mode (a database mode where readers and one writer work at the same time), four files (`control.db`, `hot.db`, `metrics.db`, `cache.db`) in `/var/lib/roxy`. No Redis. | Code (`src/roxy/storage/`); `ROXY_STATE_DIR`. | PENDING, default used | A different store is a code project. | OWNER: |
| D4 | What status do callers see when Roblox fails? | Roblox's real status (404 stays 404, 429 stays 429 with `Retry-After`), plus a `Roxy-Upstream-Status` header. | `compat_collapse_upstream_errors` 0 (`settings#public-site`). | Decided by the owner on 2026-10-07 (was ASK) | Live. Setting 1 brings back v1's "everything is 500", with Roblox's own body as v1 sent it. | OWNER: |
| D5 | Admin second factor | Authenticator app (TOTP) mandatory; passkeys optional; 10 single-use recovery codes. When the migrator imports your v1 password, the first sign-in uses it plus a 16-digit code emailed for that sign-in only, then forces authenticator enrollment and shows the recovery codes; the email code is not used again (section 3, item 11). | Code (`src/roxy/admin/auth/`). `admin_email_code_enabled` 0 (high risk), `email_code_digits` 16; the one-time bootstrap is a flag on the imported account (`mfa_bootstrap_pending`), set by the migrator's `--import-admin-password`, not a setting. | Decided by the owner on 2026-10-07 (was ASK) | The mandatory authenticator is code. Turning the email code on as a permanent fallback is a live setting marked high risk (it needs a fresh second factor): the mailbox becomes a second way in. | OWNER: |
| D6 | Admin IP allowlist | Off. The dashboard recommends it if your sign-ins always come from the same networks. | `admin_allowlist_enabled` 0 (`security#admin-access`). | PENDING, default used | Live, with a fresh second factor. A wrong list locks you out (every `/admin` address answers 404), so removing the entry that covers your own address asks for an extra confirmation. | OWNER: |
| D7 | Auto-apply safe recommendations | Off. | `insights_auto_apply` 0 (`recommendations#engine`); guardrails `auto_apply_max_per_hour` 3, `auto_apply_max_step_pct` 50, `auto_apply_watch_minutes` 30, `auto_apply_rollback_threshold_pct` 20. The catalog marks the switch for owner verification. | PENDING, default used | Live. When on, only rules marked safe apply, never to security settings, the credential, the rotator quota or bans wider than one address, and a change is rolled back if the watched numbers get worse. | OWNER: |
| D8 | Request and response body capture | On. Refused and failed requests always captured, 20% of served ones; kept 15 minutes, 64 MiB in all, 16 KiB per body, redacted. | `capture_enabled` 1, `capture_sample_served_pct` 20, `capture_ttl_seconds` 900, `capture_max_bytes` 64 MiB, `capture_max_body` 16 KiB (`live#capture`). | PENDING, default used | Live. Off loses the evidence for refused requests; more keeps more of the callers' data. | OWNER: |
| D9 | Keep the old admin API paths? | No. The dashboard uses the new `/admin/api/v1`. Public addresses are unchanged: `/`, `/health`, `/robots.txt`, `/sitemap.xml`, `/favicon.ico`, `/<sub>.roblox.com/...`, `/admin`, `/admin/invalidate/<token>`. New beside them: `/docs` (the user guide) and `/status` (a coarse public status page). | Code (`src/roxy/admin/`, `src/roxy/public/`). | PENDING, default used | A code project. It matters only if you have your own scripts that call v1's admin pages. | OWNER: |
| D10 | Do cache hits count toward a caller's per-IP limit? | Yes. Every request counts, cached or not, because an answer from the cache still costs Roxy CPU, memory and bandwidth. The flood limit also counts every request. | `throttle_count_cache_hits` 1 (`protection#throttle`). | Decided by the owner on 2026-10-07, changing the plan's recommendation (0) | Live; the public site texts follow the setting. | OWNER: |
| D11 | Per-experience (place) limits | Observe and recommend only; a limit of 600 requests a minute per place is ready. | `place_limit_enabled` 0, `place_limit_per_minute` 600, `place_limit_key` `place_prefix` (`protection#places`, `clients#places`). | PENDING, default used | Live. Turning it on can refuse a large, legitimate game; watch the places cards first. | OWNER: |
| D12 | DataImpulse plan details | Unknown (0). Bytes are still metered, but no percentage alert, no hard stop and no cost projection can work. | `rotator_quota_gb_per_month` 0, `rotator_price_per_gb_usd` 0, `rotator_billing_day` 1 (`egress#budget`); the first two are marked for owner verification in the catalog ("PENDING owner verification" on the Settings page and in `docs/SETTINGS.md`). | PENDING; your values are needed (section 3) | Live, any time. | OWNER: |
| D13 | When may the rotator be used? | Anonymous calls only, and only when the direct path is cooling down, its rate bucket is more than 80% full (traffic then moves over gradually, within the rotator budget), or a routing rule asks for the rotator. Share when everything is healthy: 0%. | `rotator_weight` 0 (v1 used 25), `direct_weight` 100, `direct_shift_threshold_pct` 80, `fallback_on_429` 0 (`upstream#routing`). | PENDING, default used | Live. A higher weight spends rotator money on ordinary traffic. | OWNER: |
| D14 | Alert channels | Email through Gmail with an app password. A webhook (for example Discord) is possible but off. | Server credentials `smtp_password`, `alert_emails`, optional `alert_webhook_url`; `alert_webhook_enabled` 0, `alert_min_severity` `warn`, `alert_rate_limit_per_hour` 20 (`settings#alerts`). | PENDING, default used | The addresses and the webhook are files on the server (root, then a restart); the switches are live. | OWNER: |
| D15 | Off-box backups | Nightly backups on the server, always (03:30 server time; 14 daily and 8 weekly sets kept in `/var/backups/roxy`). No off-box copy until an rclone remote is named. Backups are encrypted with `age` when a recipients file exists. | `ROXY_BACKUP_REMOTE` unset, credential `rclone_config`, `ROXY_BACKUP_AGE_RECIPIENTS` `/etc/roxy/backup-age-recipients` (`/etc/roxy/roxy.env`). | PENDING, default used | Root on the server; it applies from the next nightly backup. | OWNER: |
| D16 | Retention | Minute statistics 14 days, hour statistics 400 days, day and month totals forever, event log at most 2,000,000 rows, captures 15 minutes. Every other table has its own cap and age. | `retention_minute_days` 14, `retention_hour_days` 400, `retention_day_days` 0 (forever), `events_max_rows` 2,000,000, `capture_ttl_seconds` 900 (`data#retention`). | PENDING, default used | Live. Shortening deletes older rows at the next prune and cannot be undone; lengthening keeps more only from then on. | OWNER: |
| D17 | Migrate the old statistics? | Every rule is imported, and every setting you changed from v1's defaults (a setting whose meaning changed is only shown in the report, beside the v2 default). v1's lifetime counters become one "legacy totals" snapshot (the v1 baseline shown next to the Overview's "Roblox 429s per 10,000 caller requests"). | `scripts/migrate_from_v1.py`; keys `v1.roblox_429_total`, `v1.requests_total`, `v1.roblox_429_per_10k_requests`. | PENDING, default used | Migration time only. A second run adds only new v1 items and never brings back what you deleted in v2. | OWNER: |
| D18 | Home page text that names people or prices | Kept, and moved into editable settings so it can be kept current. | Six `site_*` keys (`settings#public-site`), all marked for owner verification (section 3). | PENDING, default used | Live. | OWNER: |
| D19 | Open Cloud API key support | Not built. | Nothing in the code. | PENDING, default used | A code project. A key would count as "the credential" and fall under every rule of plan section 3. | OWNER: |
| D20 | CORS on the public proxy | No CORS headers: web pages on other sites cannot call Roxy from a browser. | `public_cors_allow_any_origin` 0, high risk (`settings#public-site`); marked for owner verification. | PENDING, default used | Live. Turning it on lets any website use Roxy from its visitors' browsers (GET and HEAD only, never with cookies). | OWNER: |
| D21 | HSTS preload | No preload. HSTS is the header that tells browsers to use only HTTPS for your domain; preload would build that into the browsers themselves. nginx sends `Strict-Transport-Security: max-age=63072000; includeSubDomains`, and the domain is not submitted to the preload list. | `deploy/nginx/snippets/roxy-security-headers.conf`; the app does not repeat it (`ROXY_SEND_HSTS=0`). | PENDING, default used | Adding preload is one line plus a submission. Removing it later takes months and covers every subdomain of your domain. | OWNER: |
| D22 | Multi-admin roles | One role: every admin account is a full admin. Sensitive actions need a fresh second factor. | Code: `require_admin` accepts only the scopes `session` and `fresh_mfa` (`src/roxy/admin/auth/deps.py`). | PENDING, default used | A code project (roles are a planned follow-up). | OWNER: |
| D23 | Upstream User-Agent | A browser-like User-Agent (Chrome 141 on Windows). The A/B experiment against `Roxy/2 (+your site)` is built but off. | `direct_user_agent`; `ua_experiment_enabled` 0, `ua_experiment_days` 7, `ua_experiment_alt_user_agent` `Roxy/2 (+{site_origin})` (`upstream#routing`). A run splits direct traffic for `ua_experiment_days` from when it was switched on, then ends by itself. The UP-UA-EXPERIMENT recommendation compares only calls made during the run and needs 10,000 calls per side (`insight_up_ua_experiment_min_calls_per_arm`; section 3, item 10). | PENDING, default used | Live. See section 3 for whether to start the experiment. | OWNER: |

## 3. Items the owner must fill in or verify

1. **OWNER: DataImpulse quota and price (D12).** Give the plan's data allowance per billing cycle in GB, the price per
   GB in US dollars and the day of the month the plan resets. Set them on the Egress page (`egress#budget`):
   `rotator_quota_gb_per_month`, `rotator_price_per_gb_usd`, `rotator_billing_day` (default 1). Until the quota is
   set, the budget alerts (50, 80 and 95 percent, `rotator_budget_alert_pcts`) and the hard stop at 100 percent
   (`rotator_hard_stop_pct`) cannot fire. The catalog marks the quota and the price "PENDING owner verification", so
   the Settings page lists them for you. The hard stop and the daily cap count from a billing record Roxy keeps apart
   from the statistics, so resetting the Egress usage statistics never lifts them.
2. **OWNER: rotator session username template (plan 8.2 and 15.3 A, "PENDING owner verification").** DataImpulse
   chooses a "sticky" session (the same exit IP for a while) from text inside the proxy username. The exact text is
   the provider's, so it is a setting: `rotator_session_username_template`, default empty, with the placeholders
   `{user}`, `{session}` and `{country}`. The plan's example shape `{user}__sessid-{session}` was never checked.
   While the template is empty, every rotator call gets a new IP, even though `rotator_session_mode` says
   `sticky_until_429`. Check the DataImpulse documentation and enter the template on the Egress page
   (`egress#rotator`), or leave it empty. Always use the `{user}` placeholder, never your real username or password.
   A wrong template makes the gateway refuse rotator calls, which parks the rotator; the H-ROTATOR-SESSION health
   check confirms a new template works.
3. **OWNER: vulnerability contact for `docs/SECURITY.md`.** "Reporting a vulnerability" names no contact; it says to
   use GitHub's private vulnerability reporting "if it is turned on" or a private message. The home page's bug bounty
   text promises rewards, so reporters need a real channel. Name one (an email address, or turn on private reporting
   on GitHub).
4. **For your information (done): the v1 dashboard fix is on GitHub (commit 12616fd).** On 2026-10-09 the live v1
   dashboard was blank (a `NaN` in `/admin/diagnostics`). With your permission it was fixed by patching two files on
   the server (backup in `~/roxy-hotfix-backup-20261009`) and a graceful reload. You pushed the commit to `main` on
   2026-10-10 at 01:57 (US Eastern), and `git ls-remote` of the repository showed `main` at 12616fd on 2026-10-12,
   so a v1 deploy from `main` keeps the fix. Nothing is owed here; the merge of v2 into `main` (`MIGRATION.md` step
   1.4) must keep it (a merge, never a force push).
5. **OWNER: the v1 safety hotfix (Tier 0, commit 3453d66).** The plan's first step, a small v1 change that keeps the
   credential off caller traffic, stops the retries that multiply Roblox 429s and adds the (off) shadow mode, is built
   and tested (1,018 v1 smoke checks) on branch `hotfix/v1-phase-minus-1`, with notes in its `HOTFIX_NOTES.md`. It
   was never merged, so live v1 still sends the credential with most caller traffic until v2 replaces it. Merging is
   a push to `main`, which deploys v1; it was built before 12616fd, so it must be merged on top of it. Decide: merge
   it before the cutover, or leave v1 as it is until the cutover.
6. **OWNER: alert channels (D14).** Confirm the address that receives alerts and the sender address (the
   `alert_emails` credential, `to:` and `from:` lines) and that the Gmail app password (`smtp_password`) is current.
   Say whether you want a webhook (then `alert_webhook_url` and `alert_webhook_enabled` 1). Note: the daily digest
   (at `alert_digest_hour` 9, in the dashboard time zone `ui_timezone`) is an "info" alert, so it is not sent while
   `alert_min_severity` is `warn`. Say whether you want it (that means `info`, which also sends every other info
   alert).
7. **OWNER: the public site texts (D18).** The catalog marks six texts for your check (`settings#public-site`):
   `site_contact_name` ("CeaselessQuokka"), `site_bug_bounty_text` (rewards of $10 to $250),
   `site_hosting_note` ("the second tier option of Lightsail", 2 TB of transfer a month, 7 USD a month plus 15 USD a
   year for the domain), `site_footer_text` ("Roxy Proxy 2025-Present"), `site_support_links` and
   `site_white_hats_text`. Confirm each is still true or give the new text. These texts are shown to every caller, so
   a value that holds the credential or another secret Roxy keeps is refused when you save it.
8. **OWNER: time zone (plan 6.4 and 15.3 K, "PENDING owner preference").** `ui_timezone` is `America/New_York`. It
   sets the time zone of the charts and time windows, when a "day" and a "month" begin in long-term charts, and the
   digest hour. Times are shown in it too, unless an admin picks a personal zone ("Show times in this time zone").
   A change affects only days compacted afterwards. It is set from the user menu's Preferences, in the part that
   applies to every admin (`user-menu#preferences`).
9. **OWNER: auto-apply and CORS (D7 and D20).** The catalog also marks `insights_auto_apply` and
   `public_cors_allow_any_origin` for your check; your answer in section 2 settles both.
10. **OWNER: the UA experiment (D23).** Say whether to switch `ua_experiment_enabled` on after the cutover. A run
    splits direct traffic between the two User-Agents for `ua_experiment_days` (7) from when you switch it on (or
    change either User-Agent), then every direct call uses `direct_user_agent` again; switch it off and on to start a
    new run. The recommendation compares only calls made during the run and needs 10,000 calls on each side before
    it is confident. Until a per-side counter exists (deferred) it counts the request samples, which are kept
    `request_sample_hours` (24 hours), so each side needs those calls within one day.
11. **OWNER: your admin account at the cutover (D5).** Choose one: the migrator imports your v1 password
    (`--import-admin-password`; the emailed code needs your address in v1's emails file, or the report warns that it
    cannot be sent), or a new admin is made on the server console with `scripts/create_admin.py`. The first sign-in
    after an import can only enroll the authenticator, for at most 30 minutes. Either way, have an authenticator app
    ready and keep the 10 recovery codes somewhere safe.
12. **OWNER: offline copy of the keys (plan 9.8).** Backups never contain the encryption keys
    (`credential_encryption_key`, `totp_encryption_key`, `ip_hash_key`). After a disk loss, a restore without them
    means nobody can sign in. Keep an `age`-encrypted copy of `/etc/roxy/credentials/` offline (`docs/RUNBOOKS.md`,
    "Restore from backup", gives the commands) and say where it is kept. If you want encrypted backups, provide the
    `age` public key for `/etc/roxy/backup-age-recipients`, and an rclone remote if you want an off-box copy (D15).
13. **OWNER: server memory check.** The memory plan assumes nginx and the operating system use about 200 MB (section
    5). Confirming it needs one read-only look at the server (`free -m`). Either allow that check over SSH, or run it
    yourself and send the numbers. `deploy/README.md` also recommends a small swap file as a safety net (not as
    capacity); say whether you want one.
14. **OWNER: the deploy repository.** `ROXY_DEPLOY_REPO_URL` in `/etc/roxy/roxy.env` must name your GitHub repository
    (the example file holds the placeholder `https://github.com/OWNER/REPO.git`, and both the nginx wrapper and
    `deploy.sh` refuse to run while it is there).
15. **OWNER (optional): the Roblox host list.** The plan asked that each of the 33 hosts in `allowed_roblox_hosts` be
    checked against Roblox's documentation. This run could not reach roblox.com, so the list ships as the plan wrote
    it; the migrator adds every host seen in v1's data, and the HOST-ADD recommendation proposes hosts callers keep
    asking for (`upstream#hosts`). Two more network facts were assumed for the same reason: Roblox's web API paths
    ignore the case of their letters (Roxy now paces an endpoint as one, in every letter case; if a Roblox host were
    case sensitive the cost is slower pacing, never extra calls), and the addresses Roblox's game servers call from
    are not filled in (item 18).
16. **OWNER (optional): the Luau examples in Studio.** The examples use `const` (in Luau since release 0.711) and the
    guide says to write `local` where Studio refuses it; the type name `HttpResponse` stands in for Studio's own. Both
    were checked with the Luau analyzer, not in Roblox Studio. Paste one home page example into Studio once.
17. **OWNER (development machine only): scratch space.** A WSL restart on 2026-10-14 already emptied most of the old
    work folders in `/tmp` (about 5 GB of test runs remain there); `~/Projects/RoxyGate-wip94` (876 MB) is left.
    Nothing in them is needed; they are not deleted without your word.
18. **OWNER: Roblox game server addresses (`roblox_egress_cidrs`, plan 9 threat 6).** Empty by default, and marked
    "PENDING owner verification" in the catalog. While it is empty the bot score never credits a caller as a Roblox
    game server (its signal needs an address inside these ranges besides the `Roblox-Id` and User-Agent), so every
    caller, game servers included, scores the same on that signal. Fill it in from Roblox's published ranges if you
    want game servers recognized, or leave it empty (the safe default: a forged `Roblox-Id` or User-Agent alone never
    earns trust).

## 4. Decisions the lead took where the plan was silent or conflicted

Each was needed to finish the build. Most are recorded in `CHANGES.md` under "Plan conflicts and deviations" (the
heading or entry named after each item; the final review's are under "Final review"). The lead's working notes are
not part of the repository: `CHANGES.md` carries every decision. **OWNER:** mark any item you disagree with.

### Memory and processes (the 909 MB server)

- **Memory sized for 1 GB, not 2 GB.** Plan 6.1 and 17.1 assume 2 GB; the server has 909 MB and no swap. SQLite
  caches are smaller, the cache's memory tier is 16 MiB and 1,000 entries (`cache_memory_bytes`,
  `cache_memory_entries`). CHANGES.md "Decided by the lead".
- **Memory per color: `MemoryHigh=420M`, `MemoryMax=500M`, plus three glibc allocator lines** in
  `deploy/systemd/roxy@.service` (was 320M and 420M). Measured: a busy color settles at about 365 to 405 MiB; 320M
  would have throttled a healthy color within 20 minutes. CHANGES.md "P11 lane: memory and the hot.db write lock".
- **Two warm colors never run at once.** A deploy starts the new color fresh, with one worker when less than 700 MB
  is available (the plan said 900 MB); `deploy/README.md` says never to start the idle color by hand. Same section.
- **2 workers per color** (`ROXY_WORKERS=2`, D2 and your instruction), each recycled after 20,000 requests plus up to
  10 percent (`ROXY_MAX_REQUESTS` must stay at 20,000 or lower).
- **Dashboard templates are prepared when a worker starts** (about 270 ms and 4.3 MB a worker), so no page request
  pays for it; a missing glossary file stops the start. CHANGES.md "P11 dashboard pages".
- **Password hashing sized for the server, not the plan** (final review finding sec-2). Plan 9.5's argon2id (64 MiB,
  two hashes at a time) let anyone push a warm color past its 500 MiB limit with a burst of login attempts (95 to
  129 MiB a worker). Roxy now hashes with 19 MiB, one hash at a time per worker (about 40 MiB a color under a burst),
  keeps two places in the queue for the admin allowlist, trusted devices and signed-in admins, and rehashes an old
  hash at the next sign-in. The time per hash on the server is estimated at about 100 ms, not measured.
- **An out-of-memory kill ends one worker, not the color** (`OOMPolicy=continue`, finding ops-9): gunicorn starts a
  replacement while the other worker serves. The degraded-mode limiter rows (used only while hot.db cannot be
  written) are bounded at 6,000 entries a store, about 4.4 MiB a worker (finding abuse-14; it was 50,000, about 37
  MiB).
- **The master process keeps its own listener on the color's port** (finding memory-4): before, when both workers
  recycled at once the port refused connections for 4 to 6 seconds; now new connections wait for the next worker
  (measured: at most 0.05 s with no listener answering).
- **`net.ipv4.tcp_migrate_req` is not set** (kernel default kept; section 5). CHANGES.md "Owner and lead decisions".

### What callers notice

- **Refusal bodies keep v1's form** (a JSON string and a newline). Roblox failure messages keep their v1 text but are
  sent as `text/plain` (v1 labeled plain text as JSON). CHANGES.md "Refusal body wire form".
- **The per-IP limit allows exactly the limit.** v1 let one extra request through per window (plan 10.2).
- **Cache keys percent-encode names and values.** v1's keys let two different upstream addresses share one cached
  answer (a cache poisoning path); security (plan sections 3 and 9) wins over plan row 53's "same format".
- **`/internal` on the public site is an instant 404,** never held by the tarpit (the delay Roxy holds suspicious
  requests in; plan 5.8).
- **Ignored paths match like other rules,** so an entry also covers the paths below it; the bypass list is by address
  range (plan row 111).
- **A duplicate header rule is refused** (409); v1 silently overwrote it (plan row 112: the plan wins).
- **POST caching allowlist:** `multiget-place-details` was left out; it is a GET that needs a signed-in account
  (plan 15.5).
- **Pacing (finding LOAD-1):** host and endpoint rate buckets now cap every rolling minute, burst included, and a
  Roblox 429 cuts the rate from what Roblox actually refused, rate and burst together (plan 7.3's formula changed for
  these two). The plan's replay test now stays under 0.1% Roblox 429s at the shipped defaults. CHANGES.md "P11 lane:
  upstream pacing".
- **D4 compatibility mode returns v1's bytes:** with `compat_collapse_upstream_errors` 1, a Roblox 4xx keeps Roblox's
  own body under status 500, as v1 did (D4 over the plan 7.13 note). A Roblox 429 that Roxy's own call received is
  treated the same (500 with Roblox's body, `Retry-After` still sent); Roxy's own busy and cooldown answers that made
  no call stay 429 (finding pipe-4).
- **Per-experience endpoint rate rules count per place and caller network** while "Place limit counts by"
  (`place_limit_key`) is `place_prefix`, the default, like the place limit (finding abuse-15): a forged `Roblox-Id`
  from another network never uses up a real game's budget. A game spread over several networks gets one budget per
  network.
- **One endpoint, one pace, in every letter case** (finding pipe-2): Roxy paced `/v1/Users/1` and `/v1/users/1` as
  two endpoints, so a caller could double the calls Roblox saw. Buckets, cooldowns, breakers and learned rates now
  key on the template with its letters lowercased; the dashboard still shows templates as callers wrote them.

### The credential and admin security

- **Credential allowlist rows grant exactly what they name** (no automatic sub-paths). The allowlist and the ignored
  paths are tables, not settings, because only a table can hold each row's `cache_private` choice.
- **More actions ask for a fresh second factor than plan 9.6 lists:** adding or changing a credential allowlist row
  (deleting one only narrows it), admin allowlist changes, arming spam bans, "Check credential", and applying or
  undoing a recommendation that touches a security setting. Stricter, never looser.
- **Shortcuts never spend the credential's budget:** the Overview's Check Proxy Health and the command palette's
  health run leave the credential check out (the Health page offers it); scheduled runs leave it out by default
  (`health_auto_include_credential` 0), and the first scheduled check for a due run comes 5 minutes after a worker
  starts leading, so a start or a deploy never begins a run.
- **Cache entries fetched with the credential are purged, never refreshed,** from the dashboard (C1).
- **A probe verdict belongs to the cookie it checked** (findings constraints-2 to 4, docs_a-1): a check that was in
  flight during a replace never rejects or activates the new cookie; a rejection the database cannot record right
  away is held in memory and still stops the cookie; an answer that names no account never clears a rejection. After
  a replace, the Credential page says "Same account as before" or "A different account than before the replace"
  (the replace itself is the deliberate C1 change, so the new cookie is used either way).
- **The account burst is shared with Roxy's own checks** (finding constraints-6): allowlisted traffic gets
  `credential_bucket_burst` minus 1 and the checks 1, so no more than that many account calls ever leave back to back.
- **The D5 email bootstrap closes for good at enrollment** (finding sec-3): enrolling the authenticator deletes the
  account's other pending emailed-code logins and ends its other bootstrap sessions.
- **A setting never holds a secret** (finding constraints-1): a setting value that holds the credential (or another
  secret Roxy keeps, or the cookie's marker) is refused from every writer, a stored one is dropped at the next reload,
  and the settings history, its downloads and the settings export scrub secrets. Pause and throttle-all reasons and
  rule texts are refused when written.
- **Client address headers keep no values.** `X-Forwarded-For` and seven others (`X-Real-IP`, `Forwarded`,
  `True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `Via`) are counted by name, but their
  values are never stored in the request fingerprint tables, not even hashed. CHANGES.md "P11 gaps lane: the
  metrics-side gaps", item G5.
- **The page test helper lives in `tests/`, not in the shipped package;** it named the credential file and broke the
  credential scan of plan C1.
- **Fixed safety bounds stay in the code, not in Settings** (the spam detector caps, the tarpit retry slots, the
  capture encoder queue, export caps): they cap memory and are not tuning knobs (principle P3 against
  P9).
- **Tooling:** two bandit rules are owned by ruff's identical checks; the vendored browser libraries (htmx, Alpine,
  uPlot) are skipped by the style check, because editing them would break their integrity hashes.

### Numbers on the dashboard (plan P6, honest numbers)

- **A negative "avoided share" is shown as it is,** with its reason (retries and refreshes made more upstream calls
  than requests), never clamped to zero.
- **Caller bytes are the bytes on the wire** between nginx and Roxy; the chunk framing of a streamed answer and what
  nginx adds are not counted (plan 14.3).
- **The Clients address table stays exact** (indexes, no folding into "other").
- **v1's User-Agent drill-down is built, not dropped** (metrics migration 0008); it shows the newest request only.
- **Resets keep what must stay:** clearing cache statistics moves lookups to "cleared" but keeps every request in the
  totals (as v1's "Clear stats" did); "everything" (all statistics) keeps settings, rules, bans, users, the audit log,
  the limiter state and the rows the running workers need; the factory reset keeps admin accounts, the credential
  and rotator address, the admin allowlist, the audit log and the pause and throttle-all switches; rule hit history
  is in no reset family (plan 6.8 against C3, C6, D6, 9.5 and 9.7).
- **The disk alert follows the catalog** (warning from 90% of the budget, critical from 100%) over plan 17.7's
  wording; the digest is an info alert (section 3, item 6).
- **"2xx, 4xx and 5xx from Roblox" count Roblox's answers again, per call, as v1 did** (the dashboard review's
  deferred item, decided in this round). The Overview tiles (and the Upstream hosts table's 5xx) count every answer
  Roblox gave Roxy's calls for callers, retries included, Roxy's own internal calls left out, from new tables kept
  like the other statistics (metrics migration 0010). There is no backfill: the tiles count from the upgrade on and
  say so for a range that starts earlier (in practice never, since v2 has no traffic before it). What callers got
  stays on the Traffic page's Status codes card, now labeled "answers to callers". `CHANGES.md` records both
  definitions.
- **Size and method limit refusals are counted** (finding abuse-4): a 413, 414, 431 or 405 Roxy answers before any
  route now counts as a refused request on the Overview and on Protection > Request limits (they read 0 before).
- **Resetting the Egress usage statistics keeps the rotator's billing count** (finding data-4): the monthly hard
  stop, the daily cap and the budget alerts count from a record kept apart, so a reset never lifts them.

### The dashboard

- **One setting, one editor per page.** A setting shown on two cards of one page is edited on one; the other shows
  the value with a link (settles plan 15.6's double coalescing editors).
- **The Settings editor shows 10 settings a page** by default (25, 50 and 100 one click away), for page weight.
- **v1's "clear" buttons became resets** with a preview, a reason and, for a whole family, a typed phrase (v1 cleared
  at once).
- **"Back up now" makes on-server snapshots and asks the root backup to run** (the service has no right to start it
  itself; plan 14.1 against 9.14 and 17.1). VACUUM lives on the Data page and is never offered for `hot.db`.
- **Screenshots in `docs/screenshots/` are left out of every release** (`.gitattributes`); the admin guide cannot show
  them yet (the Help page allows images from Roxy itself only, and no route serves them).
- **Smaller records** (CHANGES.md "Decided by the lead"): new regex header rules keep the case of each escape in
  their id (v1 made the opposite rules `^\d+$` and `^\D+$` collide); settings history also records changes made from
  the shell tool (`cli`) and by Roxy itself (`system`).

### Operations and deploy

- **Database migrations run as the `roxy` user at service start** (`deploy/prestart.py`), not by the deploy user
  (plan 17.4 against 17.1, 17.3 and 9.14). Contract (destructive) migrations stay manual, so an older kept release can
  still be rolled back to.
- **Root-run tools live in `/usr/local/lib/roxy`,** and the nginx wrapper verifies files from its own root-owned copy
  of the repository (plan 9.14 over the 17.3 table).
- **The deploy account is `roxy-deploy`,** never `ubuntu` (which has unrestricted sudo on Lightsail); adding a worker
  uses gunicorn's control socket instead of a signal the deploy user may not send.
- **v2 installs beside v1:** nginx site `roxy-v2.conf` next to v1's `roxy`; `/etc/roxy` stays v1's until the cutover
  (`install-system.sh --take-over-etc`), with only an access entry added for the deploy user.
- **`ROXY_AUTO_MIGRATE=1` works only in development;** production workers never migrate (plan 5.5).
- **`deploy.sh --build-only <sha>`** fetches and builds a release without starting anything, so the cutover's outage
  does not include the several minutes of the environment build (`MIGRATION.md` 3.4). A first deploy that failed
  after its switch is retried on blue again, as a first deploy.
- **An off-box backup is always encrypted** (finding sec-5): with `ROXY_BACKUP_REMOTE` set and no age recipient, the
  backup keeps its local set, sends nothing and fails, so its alert names what is missing.
- **The install script never follows a planted link** (finding sec-1): it changes modes and owners only through
  files it opened without following links, so the deploy account cannot make root write through a link.
- **The test helpers left the shipped package** (`tests/auth_harness.py`, like `tests/pages_harness.py`): they wrote
  fake credential files and were never imported by production code.

### The data migration (`scripts/migrate_from_v1.py`)

- **Rules are imported table by table, keeping v1's User-Agent rule ids,** with an audit row each; shipped defaults are
  put in first; an existing v2 row is never overwritten (except a shipped default cache rule with the same pattern);
  a second run never restores what you deleted (plan 18.3).
- **v1 is stopped, not paused, at the cutover** (plan 18.2 paused it): v1 uses about 345 MB and does not fit beside a
  v2 color on the 909 MB server, and stopping it freezes its files for the copy.
- **If v1 is paused when its files are copied, v2 starts paused** (throttle-all too; the first run imports both
  switches), as v1 would have after a restart. The deploy's smoke test accepts exactly Roxy's own pause or
  throttle-all answer on a color that reports the switch, and says so, so the first deploy (and any later deploy you
  make while paused on purpose) still goes through. `MIGRATION.md` 3.3 explains it.
- **The migrator hands the databases to the service itself:** run as root, it gives every database file it made to
  the state directory's owner and group, mode 0640, so the cutover has no manual `chown` step. It also fills an empty
  optional credential file (the empty `rotator_url` the install script creates means "not configured").
- **Bypass entries are imported only as single addresses;** a v1 range never matched anyone, so it is reported, not
  turned into a network-wide bypass. Each one gets the earlier of its v1 expiry and 24 hours after the import (v2
  treats a bypass that never ends as a risk; plan 15.3 and 18.3), and the report and `MIGRATION.md` say so: renew any
  address that must stay exempt.
- **Dashes in your v1 texts are rewritten** (plan C5): an unspaced en dash between digits becomes a hyphen, every other
  em or en dash a semicolon, colon, comma or parentheses; the report lists each one.
- **v1's damaged numbers:** the v1 files can hold NaN and infinity (the cause of the 2026-10-09 blank dashboard).
  The migrator reads such a count as 0 (and caps a huge one at 2**53), and reads a time that is not finite, zero,
  negative or more than a day in the future as missing; its JSON report never holds a NaN.
- **A v1 capture limit of 0 means "no limit"** in v1 but "nothing" in v2, so it is imported as the v2 maximum, and a
  capture lifetime imported that way (a day) carries a HIGH RISK warning in the report.

### The shadow comparison (plan 18.4)

- **No shadow week ran, on purpose.** The plan's 7-day comparison exists to choose which endpoints keep the
  credential. You answered D1 = never, so no endpoint waits on it. The hotfix's shadow mode replays in the opposite
  direction (anonymous first, then the credential), which gives the same pairs.
- **What the report needs:** `scripts/shadow_report.py` reads either the JSON of the v1 hotfix's `GET /admin/shadow`
  after 7 days with `shadow_enabled` 1 (`--hotfix-report`), or v2 events of type `credential_comparison`
  (`--state-dir`). Neither exists: the hotfix was never deployed, and no v2 module writes those events yet.
- **Its output today** (run on 2026-10-13, US Eastern, with no input; exit status 0; lines wrapped here) is attached below. It says
  that you decided D1 ahead of time and describes the table a later run would print, and the cutover gate (Roblox
  429s per 1,000 calls on the anonymous sample no more than 50% above the credential path's), which cannot be judged
  without a comparison.

```text
# Shadow comparison report (plan 18.4, decision D1)

Generated 2026-10-14T03:54:33Z.

No shadow week ran. Plan 18.4 asks for a 7-day comparison before the cutover so that the owner can decide which
endpoints, if any, should keep the credential (decision D1). The owner decided that ahead of time: D1 = never send
the credential for callers. The credential allowlist ships empty and only Roxy's own probes use the credential, so
no endpoint waited on this measurement (DECISIONS_REVIEW.md, decision D1; CHANGES.md, "Hotfix shadow mode").

If a comparison is run later (the v1 hotfix's shadow mode with `shadow_enabled` = 1 for 7 days, then
`--hotfix-report` with the saved `GET /admin/shadow` JSON; or a v2 producer of `credential_comparison` events, then
`--state-dir`), this report shows one row per endpoint template with: pairs sampled, identical answers, differing
answers, anonymous failures (401, 403, an empty body), anonymous 429s, credential failures and credential 429s; the
class of plan 18.4 (identical, differs, anonymous fails, anonymous rate-limited); and what the owner decides for it
(templates that differ or fail are the allowlist decision, each with its cache_private choice). Below the table: the
cutover gate, Roblox 429s per 1,000 upstream calls on the anonymous sample against the credential path, which must
not be more than 50% higher.
```

## 5. Known limitations and open items going live

**OWNER:** accept these as known limitations for the cutover, or name the ones that must be fixed first.

### Memory headroom on the 909 MB server

- During a deploy the worst case is about 855 of 909 MB: a busy color at its 500M cap, a fresh one-worker color
  (about 155 MiB) and about 200 MB for nginx and the operating system. That 200 MB is an assumption until `free -m`
  confirms it (section 3, item 13).
- Two warm colors (about 1,010 to 1,040 MB) do not fit. Never start the idle color by hand.
- `ROXY_MAX_REQUESTS` must stay at 20,000 or lower: the limits assume workers recycle.
- v1 used about 345 MB when it was measured at the start of the run, so v1 and a v2 color do not fit together:
  `MIGRATION.md` stops v1 (step 4.1) before the first v2 color starts, and builds the release beforehand (step 3.4),
  while v1 still serves, so the outage holds only the import and the start.
- A login burst holds one 19 MiB password hash per worker (about 40 MiB a color), measured; the time per hash on the
  server (an estimated 100 ms) is not measured.
- Per-client memory (the bot tracker, up to 10,000 clients and 32 MiB a worker; spam state, 20,000 subjects) still
  grows under heavy traffic until a worker recycles.

### Performance

- Every figure so far comes from the shared development machine (WSL 2, under load from other work), not from a
  quiet machine or a VM the size of the server. "p99" below is the time 99 of every 100 requests stay under. On that
  machine, plan 6.7's proxy overhead targets (p99 under 8 ms on a cache hit, 15 ms on a miss), the 3 ms p99 of the
  abuse transaction and the 50 ms worst case of a metrics flush were not met under contention, and the upstream
  transaction was not measured on its own; the dashboard targets (pages under 300 ms, 90-day charts under 500 ms)
  were met with the exceptions below.
- Quiet-machine numbers: (being measured on commit 686fe46; added here when the release measurements finish)
- Known slow spots: the Protection attempts tabs at 90 days (Request filters 0.53 to 0.65 s, over the 500 ms target);
  the Overview at 90 days under load (up to about 0.53 s; quiet it is about 0.27 s); pages above about 150 KiB
  (Overview 185, Security 192, Cache and Clients 159); hourly points over 90 days on four API routes (up to 0.76 s;
  the dashboard never asks for them); the endpoint drill-down at 90 days was twice as slow in one quiet run for no
  reason found; the cache-lifetime tuner sorts a day of samples in one read.
- Under a flood, while a database is degraded, one address can get one request past its rate limit (plan C7).

### Keys with no rotation procedure

- There is no written procedure to replace `ip_hash_key`, `credential_encryption_key` or `totp_encryption_key`
  (plan 9.15 says the IP hash key is rotated yearly). Replacing one today has costs: old address hashes stop matching
  new ones; the credential and rotator address set from the dashboard become unreadable; the stored authenticator
  secrets become unreadable. Until a procedure exists, keep the keys and their offline copy (section 3, item 12).

### Kernel setting not set

- **OWNER:** `net.ipv4.tcp_migrate_req` is left at the kernel default. The port itself never goes without a listener
  now (the master keeps one, finding memory-4), but when a worker recycles, connections already waiting in its own
  queue are reset instead of handed over: in the reproduction 4 to 8 percent of fresh connections made around a
  recycle. nginx keeps its connections to Roxy open between requests, so production sees far fewer fresh ones.
  Setting it is a change to the server's kernel settings, so it is yours to decide: keep the default, or set it to 1.

### Behavior items

- A rule refused for a conflict or a validation error inside a database write counts as a write error on the System
  page.
- A read-only copy of a setting (and the Settings page's second control of a key) refreshes with its card, not at the
  moment the editor saves.
- The User-Agent drill-down keeps the newest request only (as v1 did).
- Keys typed into a table's search box while an earlier search is still loading can be lost (rare).
- Touch-screen sizes are tested in the three phone flows only; other page tests use a mouse pointer.
- The pause dialog's extra text renders after its buttons (cosmetic).
- The docs screenshots show the test data's hostile sample text; they are taken again with clean data after this
  review, with the quiet-machine reruns.
- No v2 module records anonymous against credential comparisons, so the CRED-UNUSED recommendation and the shadow
  report's v2 input stay empty (harmless while the allowlist is empty).
- The User-Agent experiment (D23) has no per-side counter yet (deferred): UP-UA-EXPERIMENT estimates each side from
  the request samples of at most the last 24 hours (section 3, item 10). Resetting a User-Agent to its default during
  a run restarts the run for the recommendation but not for the traffic split.
- Passkeys are tested with a software authenticator only.
- One multi-process test (`test_gunicorn_mock_429_retry_after_30`) has no allowance for a call already on the wire;
  it passed in every gate so far.
- Seen by the final review's fixers, not fixed (rare, each needs a fresh second factor or an unusual sequence): a
  kill switch or revoke racing a re-authentication in the same moment can leave the rotated session alive; the first
  unknown username a worker sees costs two hashes (that one answer is slower than a wrong password); two changes of
  one setting by one admin in the same second share one revert on the Audit page; a pause reason or rule message
  saved with a secret before Roxy learned that secret is still served until rewritten; in compatibility mode a
  follower request in another worker gets Roxy's busy text, not Roblox's body, under the 500.

### Final review

- Findings of the final review and what was done about each: 101 confirmed (6 high, 31 medium, 64 low), every one
  fixed at its root, and each reproduction now passes as a regression test; 18 refuted (11 because the plan or a
  recorded decision sets the behavior, 7 that were duplicates of each other in three groups, which were real and are
  fixed too). The table with every finding, its severity and its fix in a few words, plus each refuted one with its
  reason, is in `CHANGES.md`, "Final review: findings table". The six high ones: Roblox endpoints written in another
  letter case dodged the shared pacing (pipe-2); a planted link could make the install script change a file it should
  not (sec-1); a login burst could take more memory than a warm color has left (sec-2: password hashing now 19 MiB,
  one at a time); trusted Roblox game servers could be auto-banned by the spam detectors (abuse-1); both workers of a
  color recycling together left the port refusing connections for 4 to 6 s (memory-4: the master keeps a listener);
  forged `Roblox-Id` values made some dashboard reads hold hundreds of MiB (memory-2). Left open on purpose: one
  optional recommendation refinement (SYS-METRICS-DROP during failed metrics flushes, which needs a new data field)
  and a public `/health` field for the emergency limit (declined: it would tell every caller when the limit is on).

## 6. What sign-off allows next

Your signature allows the cutover, and nothing before it. The steps follow `MIGRATION.md` and plan 18.2:

1. Make the changes you wrote in sections 2 and 3.
2. Prepare the server: `deploy/install-system.sh` (the `roxy` and `roxy-deploy` accounts, directories, units with
   the memory lines of section 4, the backup request watcher), the credential files and their offline copy.
3. Run the migrator in dry-run mode (`--dry-run`), read its report together, build the release ahead
   (`deploy.sh --build-only`), then schedule a short maintenance window. v1 is stopped, not paused (section 4, "The
   data migration"); if it was paused, v2 starts paused too and you resume it when you are ready.
4. Run the migration for real; start v2 beside v1's files (the first color is blue, on 127.0.0.1:8001); pass the
   health gate; switch nginx to v2; watch.
5. Remove the `if: false` guard from `.github/workflows/deploy.yml`, so pushes to `main` deploy v2 from then on.
6. Keep v1's files for 30 days. The rollback to v1 is written in `MIGRATION.md`.

Build status at sign-off:

- Last gated commit before the final review: 84ab636 (the dashboard review round, 2026-10-13), one pytest process
  over the whole suite: 11,796 passed, 0 failed, 2 skipped (no systemd user manager on the development machine at
  that moment), 1 expected failure (the deferred item v1parity-1, fixed in the final review); ruff, mypy, the style
  check and bandit clean. Before it, 65d4bd5 (the dashboard pages, 2026-10-11): 11,701 passed, 0 failed, 0 skipped.
- Final gate numbers (2026-10-14, the final review fixes on top of 84ab636): the whole suite, every test file once,
  as ten parallel pytest processes plus the multi-process and load suites each alone: 12,173 passed, 0 failed, 2
  skipped (the two `systemd-run --user` deploy tests: no systemd user manager on the development machine that day),
  0 expected failures; no xfail marker is left in the tests. ruff, ruff format, mypy and the style check clean;
  `docs/SETTINGS.md` and the parity map up to date; bandit 0 high, 0 medium (30 low, all older). The lead's one
  single-process run on a quiet machine follows with the performance reruns.
- Final review findings summary: 101 findings confirmed (6 high, 31 medium, 64 low) and all fixed; 18 refuted (the
  three duplicate groups among them were real and are fixed too). See section 5, "Final review", and `CHANGES.md`,
  "Final review: findings table".

### Signature

I have read sections 1 to 6. Every row of section 2 carries my decision, and section 3 carries my values.

- Owner name:
- Date:
- Choose one: approved as written / approved with the changes written above
- Signature:

Prepared by the lead, from commit: 686fe46 (the final review round, 2026-10-14). The quiet-machine numbers of section
5 come from the release measurements on that commit.
