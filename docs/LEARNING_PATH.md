# Roxy learning path

Roxy was rebuilt partly so it could be learned from. This page is the reading order: twelve stops that start with
one request and widen out to the web framework, the server processes, shared state, rate limiting, caching, abuse
protection, web security, the admin tools and operations.

Every stop has the same three parts:

- **Read**: the files to open, in order, and what to look for. Every module starts with a docstring in four parts
  (What this is, Why it exists, How it works, What to read next), so the first screen of each file is the lesson.
- **See it in the tests**: tests that show the idea working. Reading a test is often the fastest way to see what
  code promises.
- **Try this**: a small exercise. Some only run code; some ask you to change something and watch a test fail.

Background for the whole tour is in `docs/ARCHITECTURE.md`; the security reasoning is in `docs/SECURITY.md`.

## Before you start

Everything runs from the repository root, inside the project's virtual environment (`.venv`), on Linux or WSL.
Check that the tools work:

```sh
.venv/bin/python -m pytest tests/unit/abuse/test_abuse_limiter.py -q
```

Some exercises change code on purpose. Do that on a branch of your own, and put a file back afterwards with
`git checkout -- <file>`. The tests never touch the network: a socket guard refuses any connection that is not to
the local machine, so it is safe to run any of them.

Start with the package docstring in `src/roxy/__init__.py`: it is the map of every package.

## 1. One request, end to end

A game server sends `GET /games.roblox.com/v1/games?universeIds=1`. Follow it.

**Read.**

1. `src/roxy/asgi.py`: the object gunicorn loads, and `roxy.main.create_app`, which assembles the app.
2. `src/roxy/core/middleware.py`: the stack every request passes. Look at `roxy.core.middleware.build_middleware`
   for the order, then three of its layers in their own files: `src/roxy/core/client_ip.py` (who is calling),
   `src/roxy/core/deadline.py` (how long the request may take) and `src/roxy/core/security_headers.py` (the
   headers every answer gets).
3. `src/roxy/proxy/router.py`: `roxy.proxy.router.ProxyFlow` runs the steps in their binding order. Read its
   docstring twice; it is the outline of everything below.
4. `src/roxy/proxy/validate.py`: `roxy.proxy.validate.parse_target` turns the raw path into a safe target.
5. `src/roxy/abuse/pipeline.py`: `roxy.abuse.pipeline.AbusePipeline.evaluate` decides allow or refuse.
6. `src/roxy/cache/keys.py` and `src/roxy/cache/store.py`: how the request becomes a cache key, and where cached
   answers live.
7. `src/roxy/upstream/singleflight.py`: why concurrent misses of one key make one call.
8. `src/roxy/upstream/buckets.py`: the pacing every upstream call goes through.
9. `src/roxy/egress/clients.py`: how the request finally leaves the server.
10. `src/roxy/proxy/respond.py`: the exact bytes and headers the caller gets.
11. `src/roxy/metrics/recorder.py`: the one outcome record every request leaves behind.

**See it in the tests.** `tests/integration/test_pipeline_e2e.py` drives the fully wired app with a fake Roblox.
Start with `tests/integration/test_pipeline_e2e.py::test_cache_miss_then_hit`: the first request is a `MISS`
that calls Roblox once, the second a `HIT` that does not, and both count toward the caller's limit
(`Roxy-Requests-Left` goes from 9 to 8). Then `tests/integration/test_pipeline_e2e.py::test_row_429_with_stale_entry`
shows a Roblox 429 answered from a stale copy.

**Try this.** Run the first test with its output shown:

```sh
.venv/bin/python -m pytest "tests/integration/test_pipeline_e2e.py::test_cache_miss_then_hit" -q -s
```

Each JSON line is one log event. The `startup_step` lines are the worker starting, step by step; the `worker_ready`
line lists every step in order. Compare that list with the startup order in the docstring of
`src/roxy/lifespan.py`. Then read the test and predict the `Roxy-Requests-Left` value of a third request before the
test turns `throttle_count_cache_hits` off.

## 2. FastAPI basics: routers, models, dependency injection, lifespan

**Read.**

1. `src/roxy/main.py`: `roxy.main.create_app` and `roxy.main.ROUTER_MODULES`. A factory instead of a global app
   means every test gets a fresh app.
2. `src/roxy/deps.py`: dependencies are functions FastAPI calls before a route runs. A route declares what it needs
   (the context, a database, an admin) in its signature, and a test can swap any of them.
3. `src/roxy/admin/auth/deps.py`: `roxy.admin.auth.deps.require_admin` and `roxy.admin.auth.deps.require_csrf`, the
   two guards every admin route declares.
4. `src/roxy/admin/api/common.py`: `roxy.admin.api.common.ApiBody`, the base of every request body (unknown fields
   refused, strings bounded), and `roxy.admin.api.common.AdminSession`, the guard as a ready-made dependency.
5. `src/roxy/admin/api/system.py`: a typical API area. Find `GET /admin/api/v1/system/versions` and read it top to
   bottom.
6. `src/roxy/lifespan.py`: the lifespan, the code FastAPI runs once when a worker starts and once when it stops.
   `roxy.lifespan.AppContext` is everything one worker keeps.

**See it in the tests.** `tests/unit/test_app_skeleton.py::test_app_starts_with_lifespan`,
`tests/unit/test_lifespan_wiring.py::test_setting_written_elsewhere_reaches_this_worker` and
`tests/security/test_admin_routes.py::test_unguarded_routes_are_exactly_the_documented_exceptions`, which finds
every admin route of the running app and checks its guards.

**Try this.** Add a read-only endpoint to `src/roxy/admin/api/system.py`, below the versions route:

```python
@router.get("/hello")
async def hello(_admin: AdminSession) -> dict[str, str]:
    """A practice route: it only says hello to a signed-in admin."""
    return {"hello": "admin"}
```

Run `.venv/bin/python -m pytest tests/security/test_admin_routes.py -q`: the new route is discovered and passes,
because it declares its guard. Now delete the `_admin: AdminSession` parameter and run the tests again: the app now
refuses to start (`roxy.admin.api.ApiMountError`), because an admin route without a guard is a bug the code will
not let through. Put the file back with `git checkout -- src/roxy/admin/api/system.py`.

## 3. Uvicorn and gunicorn

**Read.**

1. `deploy/gunicorn.conf.py`: every setting with its reason. Notice that `timeout` is a watchdog for a frozen event
   loop, not a limit on slow requests.
2. `src/roxy/worker.py`: `roxy.worker.RoxyUvicornWorker`, and why some uvicorn options can only be set in code.
3. `src/roxy/core/deadline.py`: the per-request limit that gunicorn's `timeout` cannot be.
4. `src/roxy/internal_app.py`: the second listener on a Unix socket, and why the peer address proves nothing behind
   nginx.

**See it in the tests.** `tests/unit/test_worker_shutdown.py::test_graceful_shutdown_fits_inside_gunicorns_limits`,
`tests/unit/core/test_core_deadline.py::test_deadline_returns_504_with_7_13_body_and_headers`, and the real
gunicorn runs in `tests/multiprocess/test_gunicorn_mp.py::test_gunicorn_fleet_limits_hold`.

**Try this.** Work out how long uvicorn waits for open requests when gunicorn stops a worker, then check it:

```sh
.venv/bin/python -c "from roxy.worker import graceful_shutdown_s; print(graceful_shutdown_s(30, 30))"
```

It prints 20.0: gunicorn's 30 s, minus the 8 s the lifespan needs for its final flush
(`roxy.lifespan.SHUTDOWN_BUDGET_S`), minus a 2 s margin (`roxy.worker.SHUTDOWN_MARGIN_S`).

## 4. Async correctness

The event loop is one thread that serves every request of a worker. Anything that blocks it (a synchronous database
call, a CPU-heavy hash) freezes every request in that worker.

**Read.**

1. `src/roxy/admin/auth/passwords.py`: argon2id takes about 250 ms by design, so
   `roxy.admin.auth.passwords.PasswordHasher` runs it on a worker thread with a small capacity limit.
2. `src/roxy/storage/db.py`: every SQLite call runs on a thread of its own (`roxy.storage.db.Database.write` and
   `roxy.storage.db.Database.read`).
3. `src/roxy/core/tasks.py`: `roxy.core.tasks.TaskSupervisor` gives every background loop logging, restarts,
   bounds and a clean cancel.
4. `src/roxy/core/logging.py`: even writing a log line can block when journald pauses, so lines are written by a
   thread with a bounded queue.
5. `src/roxy/scheduler/heartbeat.py`: `roxy.scheduler.heartbeat.LoopLagMonitor` measures how late the loop wakes up.

**See it in the tests.** `tests/security/test_auth_argon2_thread.py::test_argon2_runs_off_the_loop_thread`,
`tests/integration/test_review_loop_blocking.py::test_review_no_sqlite_or_argon2_on_the_loop_thread`,
`tests/unit/scheduler/test_scheduler_heartbeat.py::test_loop_lag_monitor_measures_a_blocked_loop`,
`tests/unit/core/test_core_tasks.py::test_failing_loop_is_logged_and_restarted`.

**Try this.** Measure the loop lag with and without blocking:

```sh
.venv/bin/python - <<'EOF'
import asyncio
import time

from roxy.scheduler.heartbeat import LoopLagMonitor


async def main(blocking: bool) -> None:
    monitor = LoopLagMonitor(interval_s=0.01, window=200)
    stop = asyncio.Event()
    task = asyncio.create_task(monitor.run(stop))
    for _ in range(10):
        if blocking:
            time.sleep(0.05)  # blocks the event loop: nothing else can run meanwhile
        else:
            await asyncio.to_thread(time.sleep, 0.05)  # waits on a thread: the loop stays free
        await asyncio.sleep(0.02)  # let the monitor take its samples
    stop.set()
    await task
    print("blocking:" if blocking else "on a thread:", round(monitor.p99() or 0.0), "ms")


asyncio.run(main(True))
asyncio.run(main(False))
EOF
```

The blocking version shows about 50 ms of lag, the threaded one a couple of milliseconds: the same wait, but only
one of them stops everyone else.

## 5. SQLite in WAL mode across processes

**Read.**

1. `src/roxy/storage/db.py`: one writer thread and two reader threads per database, `BEGIN IMMEDIATE` for writes,
   the busy circuit, and `roxy.storage.db.SharedStateUnavailable`, the signal to fail closed.
2. `src/roxy/storage/leases.py`: ownership with an expiry, and the epoch as a fencing token.
3. `src/roxy/scheduler/leader.py`: one leader for the whole fleet, and how a stalled leader is kept from writing.
4. `src/roxy/storage/migrate.py`: numbered migrations, expand now and contract later.
5. `src/roxy/storage/batch.py`: why metrics are written every two seconds instead of once per request.

**See it in the tests.** `tests/unit/storage/test_storage_db.py::test_readers_not_blocked_by_long_write_in_process`,
`tests/unit/storage/test_storage_leases.py::test_takeover_after_expiry_increments_epoch`,
`tests/unit/scheduler/test_scheduler_leader.py::test_stalled_leader_cannot_write_after_takeover`, and with real
processes `tests/multiprocess/test_storage_mp.py::test_no_lost_updates_across_processes` and
`tests/multiprocess/test_storage_mp.py::test_exactly_one_leader_among_four_processes`.

**Try this.** Create the four databases in a temporary directory and look at them:

```sh
mkdir -p /tmp/roxy-learn
.venv/bin/python -m roxy.storage.migrate --status --state-dir /tmp/roxy-learn
.venv/bin/python -m roxy.storage.migrate --expand --state-dir /tmp/roxy-learn
.venv/bin/python -c "import sqlite3; c = sqlite3.connect('/tmp/roxy-learn/hot.db'); print(c.execute('PRAGMA journal_mode').fetchone()[0], [r[0] for r in c.execute('SELECT name FROM sqlite_master WHERE type = ?', ('table',))])"
```

The journal mode is `wal`, and the tables are the shared state every worker uses. Then run the multi-process tests
(`.venv/bin/python -m pytest tests/multiprocess/test_storage_mp.py -q`) and read how they start real processes.
Remove `/tmp/roxy-learn` when you are done.

## 6. Rate limiting with GCRA

GCRA (the generic cell rate algorithm) keeps one number per client: the time its next request would be due if it
sent at exactly the allowed pace. It allows a burst, then one request per interval, with no window edge where twice
the limit fits.

**Read.**

1. `src/roxy/abuse/limiter.py`: `roxy.abuse.limiter.gcra` and the fixed window v1 used, side by side.
2. `src/roxy/abuse/throttle.py`: the per-IP limit with escalating strikes.
3. `src/roxy/upstream/buckets.py`: the same algorithm pacing calls to Roblox, with a worked example in its docstring,
   and `roxy.upstream.buckets.reserve`, which takes a slot in several buckets in one transaction.

**See it in the tests.** `tests/unit/abuse/test_abuse_limiter.py::test_gcra_burst`,
`tests/unit/abuse/test_abuse_limiter.py::test_gcra_exact_rate_for_ten_minutes_is_never_refused`,
`tests/unit/upstream/test_upstream_buckets.py::test_gcra_teaching_example` (the docstring's example, step by step),
`tests/unit/upstream/test_upstream_buckets.py::test_reservation_never_leaks_tokens_when_one_bucket_denies`, and
across processes `tests/multiprocess/test_abuse_mp.py::test_gcra_burst_across_processes_admits_exactly_the_limit`.

**Try this.** Send twelve requests at the same instant to a limit of 10 per 50 seconds (the defaults of
`allowed_requests_per_minute` and `throttle_reset_duration`):

```sh
.venv/bin/python - <<'EOF'
from roxy.abuse.limiter import LimiterRow, gcra

row = LimiterRow("demo")
for i in range(12):
    decision = gcra(row, 10, 50, 1_000_000)
    print(i, decision.admitted, decision.remaining, decision.retry_after_s)
    if decision.admitted:
        row = decision.row
EOF
```

Ten are admitted, then the eleventh is told to retry in 5 s: one interval, 50 s divided by 10. Change the time of
the later requests (the last argument, in milliseconds) and predict when they are admitted again.

## 7. Being kind to Roblox

**Read.**

1. `src/roxy/upstream/cooldowns.py`: `Retry-After` and the `x-ratelimit-*` headers become a cooldown every worker
   honors.
2. `src/roxy/upstream/breaker.py`: circuit breakers that stop calling a failing endpoint and send one probe later.
3. `src/roxy/upstream/adaptive.py`: lowering a bucket's rate on a 429, raising it slowly when demand proves it low.
4. `src/roxy/cache/swr.py`: stale-while-revalidate, which answers at once and refreshes once.
5. `src/roxy/cache/policy.py`: which errors are cached briefly (negative caching) so a bad request does not reach
   Roblox again and again.
6. `src/roxy/upstream/routing.py`: why a 429 never makes Roxy jump to another path, and never onto the credential.

**See it in the tests.** `tests/integration/test_upstream_fleet.py::test_429_retry_after_cools_down_every_worker`,
`tests/multiprocess/test_upstream_mp.py::test_429_retry_after_30_holds_across_two_processes`,
`tests/unit/upstream/test_upstream_breaker.py::test_half_open_admits_one_probe`,
`tests/integration/test_pipeline_e2e.py::test_cache_stale_during_cooldown_without_a_call`.

**Try this.** Read how Roxy understands a `Retry-After` header, then run the fleet test:

```sh
.venv/bin/python -c "from roxy.upstream.cooldowns import parse_retry_after; print(parse_retry_after('30', 0.0), parse_retry_after('soon', 0.0))"
.venv/bin/python -m pytest "tests/integration/test_upstream_fleet.py::test_429_retry_after_cools_down_every_worker" -q
```

The first line prints `30.0 None`: a number of seconds is understood, garbage is ignored (and the default cooldown
applies instead). Read the test to see the second worker refuse to call Roblox without ever being told about the
429 directly.

## 8. Caching

**Read.**

1. `src/roxy/cache/keys.py`: `roxy.cache.keys.build_key`. Two requests may share an answer only when Roblox would
   answer them the same way.
2. `src/roxy/cache/policy.py`: what is cacheable, under which rule, for how long.
3. `src/roxy/cache/service.py`: `roxy.cache.service.CacheService.serve`, the table of cache states (HIT,
   REVALIDATING, STALE, COALESCED, MISS).
4. `src/roxy/cache/store.py`: the memory tier in front of cache.db, and how a purge reaches every worker.
5. `src/roxy/metrics/catalog.py`: the honest definition of "avoided upstream calls" (plan principle P6).

**See it in the tests.** `tests/unit/cache/test_cache_keys.py::test_cache_key_poisoning_case_lead_notes_9`,
`tests/unit/cache/test_cache_service.py::test_revalidating_serves_at_once_and_refreshes_once`,
`tests/integration/test_cache_workers.py::test_one_upstream_call_for_concurrent_requests_in_two_workers`,
`tests/multiprocess/test_singleflight_mp.py::test_owner_failure_costs_one_upstream_call_not_n`.

**Try this.** Compare two requests that v1 would have cached under the same key:

```sh
.venv/bin/python - <<'EOF'
from roxy.cache.keys import build_key

odd = build_key("GET", "games.roblox.com", "/v1/games", [("universeIds", "1&universeIds=2")], None)
two = build_key("GET", "games.roblox.com", "/v1/games", [("universeIds", "1"), ("universeIds", "2")], None)
print(odd.text, odd.id)
print(two.text, two.id)
EOF
```

The first request has one odd value, the second has two values; Roblox sees different URLs. v1 joined the decoded
values and gave both one key, so one caller could choose what another got (cache poisoning). Here the `&` and `=`
inside the value are encoded, so the keys and ids differ.

## 9. Abuse protection and tarpits

**Read.**

1. `src/roxy/abuse/checks/__init__.py`: the checks in their binding order (`roxy.abuse.checks.PIPELINE_ORDER`).
2. `src/roxy/abuse/checks/base.py`: every check prepares without I/O, then reads the one transaction's answer.
3. `src/roxy/abuse/pipeline.py`: one hot.db transaction for every limiter of a request, and what happens when hot.db
   is unavailable.
4. `src/roxy/abuse/bans.py` and `src/roxy/abuse/spam.py`: bans, and detectors over longer windows that only log what
   they would do while `spam_dry_run` is on.
5. `src/roxy/abuse/tarpit.py`: making a refused abuser wait, and why that costs Roxy only a coroutine and a socket.

**See it in the tests.** `tests/unit/abuse/test_abuse_pipeline_order.py::test_pipeline_order_is_the_design_order`,
`tests/unit/abuse/test_abuse_pipeline_order.py::test_a_request_refused_later_spends_no_rate_budget`,
`tests/security/test_ingress_refusal_order.py::test_bypass_never_skips_filters`,
`tests/unit/abuse/test_abuse_spam.py::test_dry_run_ban_only_logs`,
`tests/unit/abuse/test_abuse_tarpit.py::test_over_the_cap_is_instant_and_counted_as_skipped`,
`tests/integration/test_pipeline_e2e.py::test_tarpit_hold_then_refusal`.

**Try this.** Print the order, then the tarpit's fleet-wide cap with the default settings:

```sh
.venv/bin/python -c "from roxy.abuse.checks import PIPELINE_ORDER; print(PIPELINE_ORDER)"
.venv/bin/python -c "from roxy.abuse.tarpit import capacity; print(capacity({'tarpit_max_concurrent': 50, 'tarpit_connection_budget': 4000, 'tarpit_max_capacity_fraction': 0.25}))"
```

Explain to yourself why pause comes first and the endpoint rules last, and why a throttled caller probing a
non-Roblox URL gets a 429 rather than a 404. Then change `tarpit_connection_budget` in the second line to 100 and
see which limit binds.

## 10. Web security habits

**Read.**

1. `src/roxy/core/security_headers.py`: a fresh CSP nonce for every response and the exact policy
   (`roxy.core.security_headers.page_csp`); proxied content gets a sandbox.
2. `src/roxy/core/templating.py`: autoescape everywhere, the nonce on every tag.
3. `src/roxy/admin/auth/sessions.py`: server-side sessions; the `__Host-` cookie prefix; only a hash is stored.
4. `src/roxy/admin/auth/csrf.py`: the synchronizer token, masked so it never repeats (the BREACH attack), plus the
   same-origin headers.
5. `src/roxy/admin/auth/passwords.py`, `src/roxy/admin/auth/totp.py`, `src/roxy/admin/auth/webauthn.py`: argon2id,
   TOTP with replay protection, and passkeys.
6. `src/roxy/proxy/validate.py` and `src/roxy/proxy/scrub.py`: SSRF protection and header allowlists in both
   directions.
7. `src/roxy/config/env.py` and `src/roxy/egress/credential.py`: secrets arrive as systemd credentials, never as
   environment variables, and exactly one module reads the Roblox credential.

**See it in the tests.** `tests/unit/core/test_core_security_headers.py::test_nonce_is_new_for_every_response`,
`tests/security/test_auth_csrf.py::test_tokens_are_masked_differently_in_every_response`,
`tests/security/test_auth_cookies.py::test_session_and_trusted_cookie_flags`,
`tests/security/test_auth_sessions.py::test_login_never_adopts_a_planted_session_id`,
`tests/security/test_ssrf.py::test_hostile_targets_refused`, and the whole credential suite in
`tests/security/test_credential_suite.py`.

**Try this.** Three short experiments:

```sh
.venv/bin/python - <<'EOF'
import secrets

from roxy.admin.auth.csrf import mask, unmask
from roxy.proxy.validate import parse_target

secret = secrets.token_bytes(32)
first, second = mask(secret), mask(secret)
print("masked forms differ:", first != second, "and hide the same secret:", unmask(first) == unmask(second) == secret)

for raw in ("/games.roblox.com/v1/games", "/games.roblox.com.evil.com/x", "/127.0.0.1/x", "/games.roblox.com/v1/%2e%2e/x"):
    print(raw, "->", parse_target(raw, "universeIds=1", "GET", allowed_hosts={"games.roblox.com"}).problem)
EOF
```

Then introduce a failure on purpose: in `src/roxy/core/security_headers.py`, make `new_nonce` return a constant
string, and run `.venv/bin/python -m pytest tests/unit/core/test_core_security_headers.py -q`. Read which test
fails and why a nonce that repeats protects nothing. Put the file back with
`git checkout -- src/roxy/core/security_headers.py`.

## 11. Admin controls and diagnostics

**Read.**

1. `src/roxy/config/catalog.py` and one group module such as `src/roxy/config/settings/cache.py`: every setting is
   declared once, with its type, range, help text and risk, and everything else is generated from it.
2. `src/roxy/config/settings_service.py` and `src/roxy/config/runtime.py`: a change is validated, audited and
   published in one transaction, and every worker reloads within a second.
3. `src/roxy/metrics/recorder.py` and `src/roxy/metrics/live.py`: the numbers, and the live tail that shows requests
   from every worker.
4. `src/roxy/insights/engine.py`, `src/roxy/insights/rules/base.py` and one rule family such as
   `src/roxy/insights/rules/upstream.py`: how recommendations are found, kept and applied
   (`src/roxy/insights/actions.py`), and the guarded auto-apply mode (`src/roxy/insights/autoapply.py`).
5. `src/roxy/health/checks.py` and `src/roxy/health/runner.py`: Check Proxy Health, 34 checks run four at a time.
6. `src/roxy/insights/llm_export.py`: one document an LLM can review, with outside text fenced off under
   `untrusted`.

**See it in the tests.** `tests/unit/config/test_catalog.py::test_catalog_self_check_passes`,
`tests/unit/config/test_settings_service.py::test_update_is_all_or_nothing`,
`tests/insights/test_engine.py::test_lifecycle_open_update_resolve_reopen`,
`tests/insights/test_engine.py::test_auto_apply_watch_and_rollback`,
`tests/health/test_runner.py::test_concurrency_is_bounded_to_four`,
`tests/insights/test_llm_export.py::test_injection_fixture_appears_only_under_untrusted`. The recommendation rules
and health checks are also tested against fixture files written before the code: `tests/fixtures/insights/README.md`
and `tests/fixtures/health/README.md` explain the format.

**Try this.** Read one setting the way the editor shows it, then run the fixtures of one rule family:

```sh
.venv/bin/python -c "from roxy.config.catalog import CATALOG; spec = CATALOG['allowed_requests_per_minute']; print(spec.default, spec.risk); print(spec.description)"
.venv/bin/python -m pytest tests/insights -q -k up_429
```

Then open two fixtures of the same rule side by side:
`tests/fixtures/insights/up_429_endpoint__get_raise_ttl.yaml` (the rule fires) and
`tests/fixtures/insights/up_429_endpoint__just_under_thresholds.yaml` (it stays quiet). The comment at the top of
each explains every number. Find the threshold that separates them, then edit the quiet one so it crosses the
threshold and run the command again: the case that expected silence now fails, because the rule speaks up. Put the
fixture back with `git checkout -- tests/fixtures/insights/`.

## 12. Operations

**Read.**

1. `deploy/README.md`: the map of everything on the server, and where each file is installed.
2. `deploy/systemd/roxy@.service`: the unit, with a reason next to every hardening directive.
3. `deploy/nginx/roxy.conf.template`: TLS, rate limits per address, the blue/green upstream and the security
   headers snippet.
4. `deploy/deploy.sh` and `deploy/deploy_rollback.sh`: the zero-downtime deploy and its safety net.
5. `deploy/prestart.py`: migrations as the service user, before gunicorn starts.
6. `deploy/tools/backup.sh` and `deploy/tools/roxy-audit.py`: the nightly backup and the permission audit.
7. `scripts/ctl.py`: the operator CLI for the server shell, which changes things through the same audited services
   as the dashboard.
8. `docs/RUNBOOKS.md`: what to do when things go wrong.

**See it in the tests.** `tests/deploy/test_deploy_sh.py::test_failed_health_gate_rolls_back`,
`tests/deploy/test_deploy_sh.py::test_rollback_script_returns_to_the_previous_release`,
`tests/deploy/test_deploy_units.py::test_memory_numbers_fit_the_909_mb_server`,
`tests/deploy/test_deploy_nginx.py::test_every_location_with_add_header_includes_the_security_snippet`,
`tests/deploy/test_deploy_backup.py::test_retention_keeps_14_daily_and_8_weekly`.

**Try this.** Run the deploy sandbox tests about rolling back:

```sh
.venv/bin/python -m pytest tests/deploy/test_deploy_sh.py -q -k rollback
```

They run the real `deploy/deploy.sh` against a fake server (stub `systemctl`, `sudo`, `curl` and nginx). Pick one,
read how it makes a step fail, and follow in `deploy/deploy.sh` what the script undoes.

## Where to go next

- `docs/ARCHITECTURE.md` for the design decisions and their reasons.
- `docs/SECURITY.md` for the threat model and the hard constraints.
- `docs/SETTINGS.md` for every setting.
- `CHANGES.md` for every place where the build departed from the plan, and why.
