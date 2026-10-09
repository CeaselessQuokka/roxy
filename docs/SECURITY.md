# Roxy security

This page explains what Roxy protects, who it protects it from, and how. Each section names the code that does
the work and the tests that prove it, so a claim here can always be checked. The plan behind it is
`REMAKE_PLAN.md` section 9 (hardening) and section 3 (the hard constraints C1 to C7); the places where the build
chose between two rules are in `CHANGES.md`.

If you found a security problem, go straight to [Reporting a vulnerability](#reporting-a-vulnerability).

## What Roxy protects

1. **The Roblox account.** Roxy holds exactly one Roblox credential (a `.ROBLOSECURITY` cookie). If it leaked,
   someone could act as that account; if it were used carelessly (many accounts, the wrong network), Roblox could
   throttle or ban the account and the server's IP address.
2. **The server's standing with Roblox.** Roxy is a shared relay. If it sends too much, too fast, Roblox rate-limits
   everyone who uses it.
3. **The admin dashboard.** It can pause the proxy, change limits, replace the credential and export data.
4. **The rotator account.** The optional rotating proxy (DataImpulse) is paid per byte, and its URL carries a
   password.
5. **Callers.** Roxy must never serve one caller's answer to another when the answers differ, and must keep what it
   records about callers small, hashed where possible, and free of secrets.

## Threat model

Plan section 9 names seven threats. For each: what the attacker wants, and what stands in the way.

### 1. Internet attackers abusing the public proxy

They want to use Roxy against Roblox or against Roxy itself: floods, requests to hosts that are not Roblox (SSRF),
smuggling a login through the proxy, or poisoning the shared cache.

- **Floods** meet nginx first (per-IP request and connection limits, `deploy/nginx/roxy.conf.template`), then the
  abuse pipeline (`src/roxy/abuse/pipeline.py`): a flood limit that counts every request, the per-IP GCRA limit
  with escalating strikes, spam detectors over longer windows, bans, and the tarpit, which makes a refused abuser
  wait while costing Roxy one coroutine. The emergency switch throttle-all limits everyone at once.
- **SSRF.** `roxy.proxy.validate.parse_target` parses the raw path once and only accepts an https target on an
  allowed `*.roblox.com` host: no IP literals, no ports, no user names, no encoded slashes or dot segments, no
  control characters, and the host is checked for ASCII before it is lowercased. Redirects are followed by Roxy
  itself and each hop goes through `roxy.proxy.validate.parse_redirect`. Tests:
  `tests/security/test_ssrf.py::test_hostile_targets_refused`,
  `tests/security/test_ssrf.py::test_redirects_revalidated`,
  `tests/security/test_ssrf.py::test_hostile_targets_never_fetched_through_the_route`.
- **Auth smuggling.** `roxy.abuse.checks.auth_smuggling.AuthSmugglingCheck` refuses any request that carries the
  public markers of a Roblox login (the `TOKEN_PREFIX` warning text or the `.ROBLOSECURITY` cookie name) in a
  header, the query, a cookie name or the body, with 400. Roxy only proxies anonymous requests.
- **Cache poisoning.** The cache key is a one-to-one function of everything that reaches Roblox
  (`roxy.cache.keys.build_key`): names and values are percent-encoded so `&` or `=` inside a value can never look
  like structure, a POST body adds its full SHA-256, and every caller header Roxy forwards is part of the key. Tests:
  `tests/security/test_ingress_cache_poisoning.py::test_property_key_text_decodes_to_exactly_its_inputs`,
  `tests/security/test_ingress_cache_poisoning.py::test_forwarded_headers_and_key_vary_list_are_the_same_list`.
- **Resource exhaustion.** Size limits are enforced while the request is read (`max_url_length`, `max_header_count`,
  `max_header_bytes`, `max_body_bytes`), every map, queue and table has a bound (plan principle P9), and admin
  regular expressions run with a timeout inside a per-request budget. Tests:
  `tests/security/test_ingress_exhaustion.py::test_streamed_oversized_body_stops_being_read_at_the_limit`,
  `tests/security/test_ingress_redos.py::test_validator_refuses_catastrophic_shapes`,
  `tests/security/test_ingress_redos.py::test_abuse_pipeline_regex_time_is_capped_by_the_budget`.
- **A spoofed client address.** `roxy.core.client_ip.resolve_client_ip` trusts `X-Forwarded-For` only when the
  socket peer is a trusted proxy and reads it from the right. Test:
  `tests/unit/core/test_core_client_ip.py::test_spoofed_leftmost_xff_ignored`.

### 2. Attackers targeting the admin panel

They want a session: by guessing passwords, stealing a session, forging a request from another site (CSRF), or
injecting script into a page (XSS). See [Admin authentication and sessions](#admin-authentication-and-sessions)
and [Browser security](#browser-security).

### 3. A compromised worker process

If an attacker ever ran code inside Roxy, the damage should stay small. The service runs as the unprivileged
`roxy` user inside a tight systemd sandbox, can write only `/var/lib/roxy`, and cannot read
`/etc/roxy/credentials` (systemd hands it copies of its credentials). See
[Process and host hardening](#process-and-host-hardening).

### 4. Leaking the credential or the rotator password

Through logs, captures, exports, error emails, the dashboard, or the rotator itself. See
[C2](#c2-the-credential-never-travels-through-the-rotator), [Secrets handling](#secrets-handling) and
[The leak guard](#the-leak-guard).

### 5. Supply chain

A malicious or vulnerable dependency, or a tampered deploy. See [Supply chain and CI](#supply-chain-and-ci).

### 6. Spoofed claims

`Roblox-Id` and `User-Agent` are headers the caller writes, so a non-Roblox client can claim any place id, to frame
an experience, exhaust its place limit, or look like a game server. Roxy treats them as claims: places are never
banned automatically (the spam detectors only recommend, `roxy.abuse.bans`), the place limit keys on the place and
the caller's network (`place_limit_key` = `place_prefix`), and the bot score credits a Roblox game server only when
the caller's address is also in `roblox_egress_cidrs`, which is empty by default. `ProxyRequest.place_id` is
scrubbed with `roxy.core.redact.redact_label` before it becomes a key anywhere.

### 7. Prompt injection through the LLM export

The owner can hand Roxy's LLM export to a language model. A caller can put text such as "ignore your instructions"
in a User-Agent or a path. `roxy.insights.llm_export.build_export` keeps every string that did not come from Roxy
itself out of the main document: such text is stored once under `untrusted` (redacted, at most 200 characters per
entry, control characters escaped) and referenced by id, and the export starts with the plan 12.5 instruction block
that tells the model to treat that section as data. Tests:
`tests/insights/test_llm_export.py::test_injection_fixture_appears_only_under_untrusted`,
`tests/insights/test_llm_export.py::test_no_secret_appears_in_the_export`.

## The hard constraints (C1 to C7)

### C1. Exactly one Roblox credential, never rotated, never auto-switched

Roblox ties rate limits and abuse scoring to account and IP together, so several accounts cycling from one server
looks like account farming.

- **One slot.** `roxy.egress.credential.CredentialSlot` holds one optional value, never a list. A bootstrap file
  with several lines uses the first and logs (masked) that the rest were discarded.
- **Replacing is deliberate.** `POST /admin/api/v1/credential/replace` needs a fresh second factor, a reason and the
  typed phrase `replace the credential`; the old value stops being used everywhere at once
  (`roxy.egress.credential.CredentialManager.replace`).
- **No silent way back.** A UI replacement records the bootstrap value's fingerprint as superseded, and Roxy never
  loads that value again on its own. Going back is `DELETE /admin/api/v1/credential/ui-value`; if the probe then
  sees a different account, the credential stays unused until `POST /admin/api/v1/credential/confirm-account` with
  the typed phrase `switch to the other account`.
- **Rotation by Roblox is not followed.** A `Set-Cookie: .ROBLOSECURITY=...` on a credential response is never
  stored; it writes an audit row and sends the "Roxy: Roblox sent a new credential cookie" alert
  (`roxy.egress.credential.CredentialManager.observe_set_cookie`).
- **Rejected means stopped.** A rejected credential is not used and Roxy never looks for another one.

Tests: `tests/security/test_credential_suite.py::test_single_credential_slot`,
`tests/security/test_credential_suite.py::test_superseded_bootstrap_never_reused`,
`tests/security/test_credential_suite.py::test_credential_client_ignores_set_cookie`,
`tests/unit/egress/test_egress_credential.py::test_multiline_bootstrap_keeps_only_the_first_line`,
`tests/unit/egress/test_egress_credential.py::test_replace_accepts_one_string_only`,
`tests/unit/egress/test_egress_credential.py::test_rotated_cookie_is_never_stored`.

### C2. The credential never travels through the rotator

Requests that carry the credential always go direct from the server's own address. The defenses are layered, so
each holds even if another fails (`src/roxy/egress/clients.py`):

1. **Type separation.** Three client kinds: `roxy.egress.clients.DirectClient` (no proxy, no cookie),
   `roxy.egress.clients.CredentialClient` (no proxy, the cookie per request) and
   `roxy.egress.clients.RotatorClient` (through the proxy, no cookie). Only `src/roxy/egress/credential.py` reads
   the secret, and only `roxy.egress.credential.CredentialManager.authorize` attaches it, after checking that the
   target is https on an allowed Roblox host, the method is GET or HEAD, and the endpoint is on the credential
   allowlist (empty by default, owner decision D1).
2. **No environment proxies.** Every client is built with `trust_env=False`, so `HTTPS_PROXY`, `ALL_PROXY` and
   `.netrc` are ignored, and every TLS context has key logging off (`roxy.egress.metering.tls_context`), so
   `SSLKEYLOGFILE` cannot record session keys.
3. **No proxy on the credential client,** asserted when it is built.
4. **The leak guard** (`roxy.egress.guard.GuardTransport`) sits under the direct and rotator clients and refuses any
   request that carries the credential or a 24 character piece of it. See [The leak guard](#the-leak-guard).
5. **Public markers are refusals, not trips.** Anyone can type the `TOKEN_PREFIX` text or the cookie name, so they
   are refused at ingress (auth smuggling, 400) and never switch an egress off.
6. **Cookie jars that refuse cookies** (`roxy.egress.guard.NoStoreCookieJar`) on every client.
7. **Redirects are followed by hand,** at most three, each hop validated again; the cookie is checked again for every
   hop and never follows a redirect off the allowlist.
8. **Noisy HTTP libraries are pinned to WARNING** (`roxy.core.logging.configure_logging`), so DEBUG logging never
   prints request headers, and the redaction filter runs on the root handler.

Tests (plan 19.5, all must pass):
`tests/security/test_credential_suite.py::test_rotator_guard_blocks_cookie`,
`tests/security/test_credential_suite.py::test_rotator_guard_blocks_header_query_body`,
`tests/security/test_credential_suite.py::test_direct_guard_blocks_credential`,
`tests/security/test_credential_suite.py::test_public_markers_do_not_disable_egress`,
`tests/security/test_credential_suite.py::test_guard_is_a_transport`,
`tests/security/test_credential_suite.py::test_clients_ignore_env_proxies`,
`tests/security/test_credential_suite.py::test_end_to_end_recording_proxy`,
`tests/security/test_credential_suite.py::test_credential_path_has_no_proxy`,
`tests/unit/upstream/test_upstream_routing.py::test_routing_never_selects_credential_for_non_allowlisted`,
`tests/security/test_credential_suite.py::test_only_credential_module_reads_secret`,
`tests/integration/test_cache_workers.py::test_cred_response_never_served_to_other_auth_class`,
`tests/security/test_credential_suite.py::test_secret_replace_leaves_no_trace`,
`tests/security/test_credential_suite.py::test_debug_logging_never_leaks`,
`tests/security/test_rr_cred_tls_keylog.py::test_credential_client_never_logs_tls_keys_from_the_environment`.

A credential answer is also kept apart in the cache: credential keys end in ` @cred`, so they never share an id
with an anonymous key, and an allowlist row marked `cache_private` is never stored, coalesced or served stale.

### C3. Feature parity

Nothing v1 did may be lost unless the plan says it is replaced by something better. The parity checklist is the
"Parity checklist" section of `CHANGES.md`; caller-visible bytes are pinned by golden tests such as
`tests/integration/test_proxy_golden.py::test_refusal_golden` and
`tests/integration/test_proxy_golden.py::test_7_13_row_golden`.

### C4. No secrets in the repository

No credential, password, key, proxy URL with a password, server address or host fingerprint is committed.

- Secrets are only ever referenced by name (the systemd credentials below).
- CI runs gitleaks over every push (`.github/workflows/ci.yml`).
- Tests use fake values made at run time, and a socket guard fails any test that tries to reach a non-loopback
  address (`tests/unit/storage/test_socket_guard.py::test_non_loopback_connect_is_refused_before_any_packet`).
- The System page's environment summary names no credential file (`src/roxy/admin/api/system.py`).

### C5. Writing style

No em or en dash characters and US spelling everywhere. `scripts/check_style.py` reads its word list from
`scripts/style_words.txt` and runs in CI; the settings catalog checks its own help texts at import
(`roxy.config.catalog.catalog_self_check`), and `src/roxy/core/style_guard.py` applies the same rules to rendered
pages in tests. Tests: `tests/unit/test_check_style.py::test_em_and_en_dash_fail`,
`tests/unit/core/test_core_style_guard.py::test_assert_style_clean`. A security angle exists too: rule texts and
pause reasons with dashes are refused before they are stored, so stored text always passes the same checks.

### C6. Multi-process safety

Every limit, budget, counter, lock and schedule holds with any number of workers. The means: shared state in
SQLite, decided inside `BEGIN IMMEDIATE` transactions (`roxy.storage.db.Database.write`), leases for "only one of
us", one leader for scheduled work (`roxy.scheduler.leader.LeaderElector`), and metrics that add up across workers.
Tests run real processes: `tests/multiprocess/test_storage_mp.py::test_no_lost_updates_across_processes`,
`tests/multiprocess/test_storage_mp.py::test_one_leader_across_blue_and_green_and_fast_takeover`,
`tests/multiprocess/test_abuse_mp.py::test_gcra_burst_across_processes_admits_exactly_the_limit`,
`tests/multiprocess/test_singleflight_mp.py::test_concurrent_requests_in_many_processes_make_one_upstream_call`,
`tests/multiprocess/test_control_mp.py::test_cross_process_rule_edit`,
`tests/multiprocess/test_gunicorn_mp.py::test_gunicorn_fleet_limits_hold`.

### C7. Fail closed where it matters

When shared state cannot be read or written (`roxy.storage.db.SharedStateUnavailable`):

| Area | Behavior | Code | Test |
|---|---|---|---|
| Credential | Not used; an allowlisted request gets 503 with `Retry-After` (it goes anonymous only when its allowlist row says `identical_anonymous`) | `roxy.egress.credential.CredentialManager.authorize` | `tests/unit/egress/test_egress_credential.py::test_unreadable_shared_state_means_no_credential`, `tests/security/test_confinement_routing.py::test_shared_state_unavailable_never_uses_the_credential` |
| Tarpit | Never holds; the refusal is instant | `roxy.abuse.tarpit.Tarpit.plan` | `tests/unit/abuse/test_abuse_tarpit.py::test_fails_closed_without_shared_state` |
| Per-IP limit | Each worker enforces `limit // workers` in memory, merged back into hot.db later | `src/roxy/abuse/pipeline.py`, `roxy.abuse.limiter.degraded_limit` | `tests/integration/test_review_c7_failure_modes.py::test_review_readonly_hot_per_ip_limit_is_limit_over_workers`, `tests/multiprocess/test_rr_mp_degraded.py::test_rr_mp_leaving_degraded_mode_never_refills_the_allowance` |
| Admin login | Refused with 503 and a clear message | `roxy.admin.auth.flow.UNAVAILABLE_TEXT`, `src/roxy/admin/auth/deps.py` | No dedicated test yet (a known gap) |
| Upstream pacing | No unpaced call: 503 `degraded`, or stale data | `src/roxy/upstream/service.py` | `tests/integration/test_pipeline_e2e.py::test_row_degraded_shared_state` |
| Metrics | Degrade open: keep serving, flag the gap | `src/roxy/metrics/recorder.py` | `tests/integration/test_review_c7_failure_modes.py::test_review_readonly_metrics_degrade_open` |

## Browser security

### Content Security Policy with nonces

Every page response gets a new random nonce (`roxy.core.security_headers.new_nonce`) and this exact policy from
`roxy.core.security_headers.page_csp`:

```text
default-src 'none'; script-src 'nonce-<random>' 'strict-dynamic'; style-src 'self' 'nonce-<random>';
img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none';
base-uri 'none'; object-src 'none'; manifest-src 'self'; upgrade-insecure-requests;
report-to csp-endpoint; report-uri /csp-report
```

Only `<script>` and `<style>` tags that carry the response's nonce run, so markup an attacker managed to inject
cannot. There is no `unsafe-inline` and no `unsafe-eval`. The vendored libraries (htmx, Alpine's CSP build,
uPlot) run under exactly this policy with zero violations, and their files are pinned by SRI hashes
(`src/roxy/static/vendor/VERSIONS.md`). Proxied Roblox content gets `default-src 'none'; sandbox`
(`roxy.core.security_headers.PROXIED_CSP`), so nothing Roblox returns can run script on Roxy's origin.

Browsers report violations to `POST /csp-report` (`src/roxy/public/csp_report.py`). It is public by design
(browsers send reports without cookies), accepts only the two report content types, at most 8 KiB, and stores at
most 100 reports an hour fleet-wide with small shares per client and per report, so a flood cannot fill the event
table. nginx limits it to one request a second per address.

Tests: `tests/unit/core/test_core_security_headers.py::test_page_csp_is_exactly_the_plan_policy`,
`tests/unit/core/test_core_security_headers.py::test_nonce_is_new_for_every_response`,
`tests/unit/core/test_core_security_headers.py::test_proxied_response_gets_sandbox_csp`,
`tests/e2e/test_csp_spike.py::test_the_whole_gallery_runs_without_violations`.

### Other headers

`roxy.core.security_headers.SecurityHeadersMiddleware` sets these on every response (and replaces any copy a
route set, so a route cannot weaken them):

| Header | Value | Why |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | No MIME sniffing. |
| `X-Frame-Options` | `DENY` | Old browsers' clickjacking defense; CSP `frame-ancestors` is the main one. |
| `Referrer-Policy` | `no-referrer` | URLs never leak to other sites. |
| `Permissions-Policy` | every powerful feature off | Least privilege. Passkey features keep their default, which the login needs. |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates the browsing context. |
| `Cross-Origin-Resource-Policy` | `same-origin` on pages | Other sites cannot embed Roxy's pages. |
| `Cross-Origin-Embedder-Policy` | `require-corp` under `/admin` | Stronger isolation; every admin asset is self-hosted. |
| `Cache-Control` | `no-store` under `/admin` | Admin data never sits in a browser or proxy cache. |
| `Server` | removed | Less fingerprinting (nginx also has `server_tokens off`). |

HSTS (`max-age=63072000; includeSubDomains`, no `preload`) is sent by nginx on every location, static files
included; the app sends it only when `ROXY_SEND_HSTS=1`. nginx terminates TLS 1.2 and 1.3 only.

### CORS

The admin area sends no CORS headers, and the admin API refuses a request whose `Origin` is not the site's own
origin. The public proxy sends none by default; `public_cors_allow_any_origin` turns on a wildcard for GET and HEAD
answers only.

### Output encoding

Jinja2 autoescape is on everywhere (`src/roxy/core/templating.py`), dashboard fragments never contain `<script>`,
JSON is shown as text, and CSV exports guard every cell against spreadsheet formulas
(`roxy.admin.api.common.csv_safe`; test `tests/unit/admin_api/test_api_common_export.py::test_formula_guard_covers_every_rule_and_nothing_else`).

## Admin authentication and sessions

### Signing in

- **Passwords** are hashed with argon2id (`time_cost=3`, `memory_cost=65536` KiB, `parallelism=2`) on a worker
  thread, at most two at a time per worker, with at most four more waiting; beyond that a login gets the
  lockout-style 429 at once (`roxy.admin.auth.passwords.PasswordHasher`). An unknown username is checked against a
  dummy hash, so both answers take the same time. The policy asks for at least 14 characters, not on the bundled
  list of common passwords and not containing the username. Tests:
  `tests/unit/admin_auth/test_admin_auth_passwords.py::test_production_parameters_are_the_plan_values`,
  `tests/security/test_auth_argon2_thread.py::test_argon2_runs_off_the_loop_thread`.
- **The second factor is mandatory** (owner decision D5). TOTP accepts one 30 s step of drift either way and each
  step once per user (`roxy.admin.auth.totp.match_step`); its secret is stored encrypted with
  `totp_encryption_key`. Passkeys (WebAuthn, user verification required) are optional. Ten single-use recovery
  codes are hashed with argon2id. An emailed code is off by default (`admin_email_code_enabled`); it is used once,
  for the bootstrap login of an account imported from v1, which must then enroll TOTP. Tests:
  `tests/unit/admin_auth/test_admin_auth_flow.py::test_totp_code_is_single_use_per_step`,
  `tests/unit/admin_auth/test_admin_auth_flow.py::test_totp_accepts_one_step_of_drift_but_not_two`,
  `tests/unit/admin_auth/test_admin_auth_flow.py::test_recovery_code_works_once`,
  `tests/unit/admin_auth/test_admin_auth_flow.py::test_bootstrap_login_uses_email_then_forces_enrollment`.
- **Every second-factor failure looks the same:** the same 404 `Not Found` body, so an attacker learns nothing
  about which part failed. Test:
  `tests/security/test_auth_uniform_404.py::test_every_second_factor_failure_looks_identical`.
- **Lockout** counts an attempt before the password is checked, in one hot.db transaction, per username and network
  (IPv4 /24, IPv6 /64): `admin_login_max_failures` (5) per `admin_login_window_s` (600 s, sliding). A global guard
  (`admin_login_global_max_per_min`, 30) slows attempts beyond the cap by `admin_login_global_delay_s` and alerts,
  but never refuses, so an attacker cannot lock the owner out; the admin allowlist and trusted devices are exempt.
  Tests: `tests/security/test_auth_lockout.py::test_parallel_guesses_cannot_pass_the_limit`,
  `tests/security/test_auth_lockout.py::test_two_workers_share_one_count`,
  `tests/security/test_auth_global_guard.py::test_guard_slows_but_never_refuses`.
- **The first admin is created on the server console** with `scripts/create_admin.py`, so there is never a "first
  visitor becomes admin" moment. The same script resets a lost authenticator (`--reset-mfa`) or password
  (`--reset-password`).

### The admin network allowlist (D6)

With `admin_allowlist_enabled` on, only networks listed as `allow_admin` access-list entries can reach `/admin`;
everyone else gets the same plain 404 as a path that does not exist, so a scanner cannot tell the dashboard is
there (`src/roxy/admin/auth/allowlist.py`). It is off by default because a changing network would lock the owner
out until the console turns it off. Changing the list needs a fresh second factor, and removing the entry that
covers your own address needs an explicit confirmation.

### Sessions

- The session cookie is `__Host-roxy_session` (Secure, HttpOnly, SameSite=Strict, Path=/, no Domain). Its value is a
  256-bit random id; control.db stores only its SHA-256, so a copied database cannot be replayed as a login
  (`src/roxy/admin/auth/sessions.py`).
- A session ends after `admin_session_idle_timeout_s` (900 s) without real use, and in any case after
  `admin_session_max_age_s` (12 hours). Polling, the live stream and an unattended tab do not count as use; the
  dashboard's heartbeat counts only when there was keyboard or pointer input.
- Sensitive actions need a second factor entered within `admin_reauth_window_s` (600 s): replacing or checking the
  credential, changing the credential allowlist, replacing the rotator URL, re-enabling an egress after a leak guard
  trip, managing passkeys and recovery codes, the admin allowlist, arming the spam auto-ban, the factory reset, the
  full LLM export, and a health run that spends a credential call. The list is pinned by
  `tests/security/test_admin_routes.py::test_fresh_mfa_routes_are_exactly_the_documented_sensitive_ones`.
- The session id rotates at login, enrollment and re-authentication; a planted session id is never adopted. Signing
  out everywhere bumps a session epoch that ends every session at once.
- Every login sends a "Roxy Admin Login" email with a one-time kill-switch link (`/admin/invalidate/<token>`,
  valid 24 hours, stored hashed). Opening the link only shows a confirmation page; confirming ends sessions and, by
  default, revokes trusted devices. nginx never logs that path.
- Trusted devices skip only the second factor, never the password, and are bound to the browser and operating
  system they were issued to.

Tests: `tests/security/test_auth_cookies.py::test_session_and_trusted_cookie_flags`,
`tests/security/test_auth_sessions.py::test_login_never_adopts_a_planted_session_id`,
`tests/security/test_auth_sessions.py::test_only_hashes_are_stored`,
`tests/security/test_auth_sessions.py::test_sign_out_everywhere_bumps_the_epoch`,
`tests/security/test_auth_sessions.py::test_kill_switch_also_revokes_trusted_devices`,
`tests/unit/admin_auth/test_admin_auth_flow.py::test_heartbeat_extends_only_with_recent_input`,
`tests/unit/admin_auth/test_admin_auth_flow.py::test_session_absolute_lifetime`.

### CSRF and BREACH

Every state-changing admin request must carry the session's CSRF token in the `X-CSRF-Token` header and come from
Roxy's own origin (`Origin` and `Sec-Fetch-Site` are checked; at least one must be present). The token is never sent
twice in the same bytes: each response embeds it XOR-masked with a fresh random pad, so a compressed page cannot
leak it one character at a time (the BREACH attack), and nginx also turns gzip off under `/admin`
(`src/roxy/admin/auth/csrf.py`). A malformed or missing body is a 400, never treated as an empty object. Tests:
`tests/security/test_auth_csrf.py::test_every_state_changing_route_rejects_bad_csrf`,
`tests/security/test_auth_csrf.py::test_tokens_are_masked_differently_in_every_response`,
`tests/security/test_auth_csrf.py::test_malformed_bodies_are_400_never_empty_objects`.

### Every admin route is guarded, and the app checks it

The admin API refuses to start when any route lacks `require_admin` or, for POST, PUT, PATCH and DELETE, lacks
`require_csrf` (`roxy.admin.api.ApiMountError`). The security tests discover every route of the running app and
check the guards, the CSRF refusal, the 401 for a signed-out caller and the documented exceptions (the login steps,
the kill-switch link, `/csp-report`): `tests/security/test_admin_routes.py::test_unguarded_routes_are_exactly_the_documented_exceptions`,
`tests/security/test_admin_routes.py::test_state_changing_routes_reject_missing_wrong_and_foreign_csrf_tokens`,
`tests/security/test_admin_routes.py::test_signed_out_requests_get_401_or_the_login_redirect`. Admin API bodies
refuse unknown fields and bound every string; errors never echo a secret or a stack trace; every table export
writes its audit row before the file leaves, and hashes client addresses unless `export_include_ips` is on.

## Secrets handling

### Where secrets live

Every secret is a systemd credential: a file under `/etc/roxy/credentials/` (root, mode 0600, directory 0700),
handed to the service through `LoadCredential=` in `deploy/systemd/roxy@.service` and read from
`$CREDENTIALS_DIRECTORY`, a private directory only the service can read. None is ever an environment variable.

| Credential | Contents | Read by |
|---|---|---|
| `roblox_credential` | The bootstrap `.ROBLOSECURITY` value | `src/roxy/egress/credential.py` only |
| `rotator_url` | The bootstrap rotator URL with its user name and password (optional) | `src/roxy/egress/rotator.py` |
| `smtp_password` | The mail password | `src/roxy/notify/mail.py`, `deploy/tools/alert_on_failure.py` |
| `alert_emails` | Recipient and sender addresses (`to:` and `from:` lines) | the same two |
| `alert_webhook_url` | The webhook URL, which is itself a secret (optional) | `src/roxy/notify/webhook.py`, `deploy/tools/alert_on_failure.py` |
| `credential_encryption_key` | 32-byte key for the UI-set credential and rotator URL | `src/roxy/egress/crypto.py` |
| `totp_encryption_key` | 32-byte key for TOTP secrets | `src/roxy/admin/auth/totp.py` |
| `ip_hash_key` | 32-byte HMAC key for client address hashes | `src/roxy/core/iphash.py` |

An empty optional file means "not configured" (systemd refuses a missing file). The service cannot write
`/etc/roxy`, so a credential or rotator URL set from the dashboard is stored in control.db, encrypted with AES-256-GCM
(`roxy.egress.crypto.seal`), with associated data naming its table so a ciphertext copied to the other table does
not decrypt. The dashboard value wins over the bootstrap file.

**What the encryption protects, plainly:** a stolen database file or backup. It does not protect against someone
who controls the running server, because the keys and the process memory are there. Backups never contain the
keys, so the owner must keep an offline copy of `/etc/roxy/credentials/` (see `docs/RUNBOOKS.md`, "Restore from
backup").

### Redaction

Redaction is the last line of defense and is deliberately blunt (`src/roxy/core/redact.py`):

- Code that loads a secret registers it (`roxy.core.redact.SecretRegistry`); every log line, alert field, capture,
  audit value and export string has every registered value removed, and for the Roblox credential also every run of
  24 or more of its characters.
- Patterns that look like secrets are removed whatever their value: the `TOKEN_PREFIX` text and what follows it,
  `.ROBLOSECURITY=...`, `user:password@` in URLs, `Cookie` and `Authorization` header lines, fields named like
  passwords, tokens, sessions and codes, and the kill-switch token in its path. Percent-encoded text is decoded and
  checked again.
- The filter is attached to the root log handler (`roxy.core.logging.RedactionFilter`), so it covers third-party
  loggers too.
- Caller-supplied labels that never pass a log filter (endpoint templates, place ids, event columns, hot.db keys)
  are scrubbed where they are made (`roxy.core.redact.redact_label`).
- Client addresses can be hashed in logs (`log_hash_client_ips`) with a keyed HMAC, never a plain hash, which could
  be reversed by hashing all four billion IPv4 addresses (`src/roxy/core/iphash.py`). Exports use a derived key per
  export unless `export_stable_ip_hash` is on.
- Audit rows for secret targets hold only `{fingerprint, masked}`; anything else raises before a row is written
  (`roxy.config.audit.record`). The audit log is append-only: database triggers refuse updates and deletes except
  the 400-day retention job.

Tests: `tests/unit/core/test_core_redact.py::test_credential_substring_of_24_chars_is_redacted`,
`tests/unit/core/test_core_logging.py::test_debug_logging_redacts_secrets_from_every_logger`,
`tests/unit/core/test_core_logging.py::test_third_party_loggers_pinned_to_warning`,
`tests/unit/config/test_audit.py::test_secret_target_refuses_raw_values_before_writing`,
`tests/unit/config/test_audit.py::test_audit_log_is_append_only`.

## The leak guard

`roxy.egress.guard.GuardTransport` wraps the transport of the direct client and of every rotator client. It is a
transport, not an httpx event hook, because hooks are a list that later code could clear; a transport is fixed when
the client is built and sees the request after every hook ran.

Before a request is handed to the network, the guard inspects the final request (every header name and value,
`Cookie` and `Authorization` included, the whole URL and the body) as sent and again after percent-decoding:

- **The credential, or any run of 24 or more of its characters:** `CredentialLeakBlocked`. The request is not sent,
  that egress (direct or rotator) is disabled for the whole fleet (a control.db `service_state` row
  `egress_disabled:<egress>`), a critical audit entry is written, and the "Roxy SECURITY: credential leak blocked"
  alert is sent, never capped. The caller gets 503 with `Retry-After: 60`.
- **A public marker, or a body larger than `max_body_bytes`:** `AuthSmugglingBlocked`. That one request is refused
  and counted; the egress stays on, so typing a public string can never switch an egress off.

The guard never holds the secret. The credential module gives it an opaque `roxy.egress.credential.LeakMatcher`
with keyed hashes of short pieces of the secret parts of each value (the current one, the bootstrap one, recently
replaced ones and cookies Roblox rotated), and text any caller could type is left out of what it watches.

Re-enabling a tripped egress is a deliberate admin action: `POST /admin/api/v1/egress/{name}/enable`, with a fresh
second factor and a reason that goes into the audit row (`roxy.egress.clients.EgressClients.enable_egress`). Health
check H-CRED-GUARD runs a self-test of the guard in-process (nothing is sent). The runbook is
`docs/RUNBOOKS.md`, "Leak guard".

Tests: `tests/unit/egress/test_egress_guard.py::test_guard_transport_refuses_and_never_reaches_the_network`,
`tests/unit/egress/test_egress_guard.py::test_matcher_ignores_23_char_pieces_and_public_prefix`,
`tests/unit/egress/test_egress_guard.py::test_no_store_cookie_jar_never_stores_or_sends`,
`tests/integration/test_pipeline_e2e.py::test_direct_guard_trip_through_the_app`,
`tests/security/test_confinement_markers.py::test_public_fragments_from_a_caller_never_disable_an_egress`.

## Process and host hardening

- **Accounts.** The service runs as `roxy`, which owns only the databases. The deploy logs in as `roxy-deploy`,
  whose only sudo rights are starting, stopping, restarting and reloading the two colors and running two root-owned
  wrappers (`deploy/sudoers/roxy-deploy`). A deploy user that could install nginx config would effectively be root,
  so the wrappers install only the files of the verified commit and only repoint one symlink
  (`deploy/tools/roxy-nginx-apply`, `deploy/tools/roxy-switch-color`). Tests:
  `tests/deploy/test_deploy_wrappers.py::test_sudoers_allows_only_the_wrappers_and_the_color_units`,
  `tests/deploy/test_deploy_wrappers.py::test_apply_refuses_a_tampered_release_file`.
- **The systemd sandbox** (`deploy/systemd/roxy@.service`, every directive commented): `NoNewPrivileges`,
  `ProtectSystem=strict` with only `/var/lib/roxy` writable (the code directory is read-only), `ProtectHome`,
  `PrivateTmp`, `PrivateDevices`, the kernel, clock, hostname and control group protections, `ProtectProc=invisible`,
  only IPv4, IPv6 and Unix sockets, a system call filter, `MemoryDenyWriteExecute`, no capabilities at all, memory
  and task limits. Tests: `tests/deploy/test_deploy_units.py::test_every_directive_has_its_reason`,
  `tests/deploy/test_deploy_units.py::test_exposure_score_is_ok`,
  `tests/deploy/test_deploy_units.py::test_app_boots_under_the_unit_sandbox`.
- **Internal endpoints** exist only on the color's Unix socket (mode 0660, group `roxy`); the public port answers
  404 for `/internal`, and so does nginx (`tests/deploy/test_deploy_nginx.py::test_internal_is_404_and_never_proxied`).
  The operator routes there that delete data or export raw addresses also need a one-use proof that the caller can
  write the state directory (the `roxy.internal_app.PROOF_HEADER` header, sent by `scripts/ctl.py`), so the deploy
  user, which may open the socket, cannot use them.
- **File permissions.** `/etc/roxy/credentials` is root 0700 with 0600 files, the state directory 0750 and database
  files 0640. The service cannot see the credential directory, so a root timer (`roxy-audit.service`, every 6 hours
  and after each deploy) checks modes and owners, reading metadata only, and health check H-SECRETS-PERMS reads its
  report (`deploy/tools/roxy-audit.py`).
- **nginx** terminates TLS, hides its version, limits requests and connections per address (separate zones so the
  login guard never throttles the dashboard), times out slow clients, and never logs the kill-switch path
  (`tests/deploy/test_deploy_nginx.py::test_kill_switch_token_is_never_logged`).

## Supply chain and CI

- Dependencies are locked with hashes in `uv.lock`; the deploy installs exactly that (`uv sync --frozen`).
- `.github/workflows/ci.yml` runs ruff, mypy, the tests, `scripts/check_style.py`, the settings reference check,
  bandit, pip-audit (failing on a known vulnerability that has a fix) and gitleaks.
- The deploy workflow ships disabled until the cutover, and the server only ever deploys a commit that is on
  `main`; the nginx wrapper verifies every file it installs against the commit.
- Vendored browser libraries are byte-for-byte copies with SRI hashes; a modified file is refused by the browser
  (`tests/e2e/test_csp_spike.py::test_a_modified_vendor_file_is_refused_by_its_sri_hash`).

## Reporting a vulnerability

Thank you for taking the time. Please:

1. **Do not open a public issue** and do not post details anywhere public. Contact the maintainer privately, for
   example through the repository's private vulnerability reporting on GitHub if it is turned on, or through a
   private message to the maintainer.
2. Describe what you found, how to reproduce it, and what an attacker could do with it. A request (with any real
   secret removed) and the `Roxy-Request-Id` of a response help a lot.
3. **Never include a real credential, cookie, password or key,** yours or anyone else's. If you saw one, say where,
   not what.
4. Test only against your own copy of Roxy. Do not flood the public service, try other people's accounts, or try to
   reach the Roblox account Roxy holds.

What happens next, for the maintainer: confirm the report, check the audit log and the events for signs it was
used, fix it with a test that fails before the fix, and follow the runbook that matches the impact (for a
credential exposure, `docs/RUNBOOKS.md`, "Leak guard", and the one-time replacement rules of C1; for an admin
compromise, "Unexpected admin login"). Credit the reporter if they want it.
