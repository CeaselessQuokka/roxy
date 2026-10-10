# Roxy architecture

This page explains how Roxy v2 is put together: which processes run, what happens to one request, where state
lives, which work runs in the background, how a release reaches the server without downtime, and why the big
choices were made the way they were. It is written for the owner and for anyone who wants to learn from the code,
so every section names the real modules and points at the code to read next.

Three other documents go with this one:

- `docs/LEARNING_PATH.md` is a guided reading order through the code, with exercises.
- `docs/SECURITY.md` is the threat model and how each hard constraint (C1 to C7) is enforced and tested.
- `docs/RUNBOOKS.md` says what to do when something goes wrong.

The plan the code was built from is `REMAKE_PLAN.md`; the decisions made while building it are in `CHANGES.md`.

## The big picture

Roxy is a proxy for public Roblox web APIs. A Roblox game server calls
`https://<site>/games.roblox.com/v1/games?universeIds=1`; Roxy checks the request, answers it from its cache when
it can, and otherwise asks Roblox and passes the answer back. Around that core sit an admin dashboard, a public
site with a user guide, and a set of background jobs that keep the numbers, the caches and the databases healthy.

```text
           internet
              |
           nginx  (TLS, HSTS, rate limits per IP, the blue/green switch)
              |
   127.0.0.1:8001 (blue) or 127.0.0.1:8002 (green)
              |
   gunicorn master of one color
     |-- worker 1: uvicorn event loop running the Roxy app
     |-- worker 2: the same, in its own process
              |
   four SQLite files in /var/lib/roxy, shared by every worker of both colors
     control.db   settings, rules, bans, admin accounts, audit log
     hot.db       rate limits, upstream buckets, cooldowns, breakers, leases
     metrics.db   rollups, events, recommendations, health runs, captures
     cache.db     cached Roblox answers
              |
   egress clients -> Roblox (direct from the server IP; optionally through the rotating proxy)
```

The important idea: every worker is a separate process with its own memory, so anything that must hold for the
whole service (a rate limit, a cooldown after a Roblox 429, "only one of us refreshes this key") lives in SQLite,
and every decision about it is one short transaction. That is what plan constraint C6 asks for: no limit may
quietly become "N times the setting" because there are N workers.

## Process model

### gunicorn, uvicorn and the worker class

Roxy runs under gunicorn with uvicorn workers. gunicorn is the process manager: it starts the workers, tells
systemd when the service is ready (`Type=notify`), restarts a worker that dies, recycles workers after
`max_requests`, reloads gracefully, and kills a worker whose event loop has frozen. Each worker runs one asyncio
event loop with uvicorn, and that loop serves thousands of concurrent connections: a request that waits for
Roblox, or a tarpit hold that waits on purpose, costs a coroutine, not a thread.

- `deploy/gunicorn.conf.py` holds every gunicorn setting with its reason. The ones that shape the design:
  `workers` from `ROXY_WORKERS` (2 on the 2 vCPU server), `timeout = 30` (a watchdog for a frozen event loop, not
  a request limit), `graceful_timeout = 30`, `keepalive = 75` (longer than nginx's 60 s upstream keep-alive, so
  nginx never reuses a socket the app already closed), `max_requests` from `ROXY_MAX_REQUESTS` (20000) with 10%
  jitter, `preload_app = False` (each worker builds its own clients and loop after the fork), and
  `reuse_port = True`.
- `src/roxy/worker.py` defines `roxy.worker.RoxyUvicornWorker`. It exists because some uvicorn options can only be
  set in code: proxy header rewriting off (only `src/roxy/core/client_ip.py` reads `X-Forwarded-For`), no
  `Server` header, uvicorn's access log off (Roxy logs every request itself, redacted), and a bounded graceful
  shutdown (`roxy.worker.graceful_shutdown_s`, 20 s with the production values).
- `src/roxy/asgi.py` is what gunicorn imports (`roxy.asgi:app`). It builds the public app with
  `roxy.main.create_app` and wraps it in `roxy.internal_app.ListenerDispatcher`.

### Two listeners per worker

Every worker serves two sockets:

1. The TCP port nginx proxies to (`ROXY_BIND`, 8001 for blue and 8002 for green). With `reuse_port` each worker
   opens its own listener, so the kernel spreads connections evenly instead of handing almost all of them to the
   worker that went idle last.
2. The internal Unix socket `/run/roxy-<color>/internal.sock` (mode 0660, group `roxy`). The master creates it
   once and hands it to every worker. It serves `GET /internal/version`, `GET /internal/ready` and
   `POST /internal/flush` from `src/roxy/internal_app.py`, plus the few routes the operator CLI `scripts/ctl.py`
   needs a running worker for (an LLM export, a health run, a data reset). The deploy uses it as its health gate.

Why a second socket? nginx connects from 127.0.0.1, so "the caller is local" is true for every internet request
that nginx forwards. No endpoint may be authorized by the peer address (plan 5.8). The public app therefore has
no internal routes at all: `roxy.internal_app.PublicInternalNotFound` answers 404 for every `/internal` path on
the public port, and nginx refuses `/internal/` too.

### Colors

There are two copies of the service, `roxy@blue` and `roxy@green` (one systemd template unit,
`deploy/systemd/roxy@.service`). Normally one color serves and the other is stopped. During a deploy both run for
a few minutes (see "Blue/green deploy" below). Both colors use the same databases, so they share every limit and
elect one leader between them.

### Startup and shutdown of one worker

`src/roxy/lifespan.py` is the one place that builds and tears down a worker. At startup it creates one
`roxy.lifespan.AppContext` (stored at `app.state.ctx`) and fills it in a fixed order:

```text
env -> logging -> databases -> schema -> cache_db_check -> settings -> rules -> alerts -> clients
-> recorder -> upstream -> cache -> abuse -> error_hooks -> insights -> heartbeat -> leader -> jobs
-> config_watcher -> sse_tail
```

Each step that opens something registers its cleanup, so shutdown runs the cleanups in exactly the reverse order,
and a failure halfway through still closes what was opened. A few details matter in practice:

- A database whose schema is older than `roxy.storage.migrate.REQUIRED_SCHEMA` stops the worker with a
  `schema_too_old` log line, and gunicorn then stops the whole color. That is how a broken deploy fails cleanly.
  Workers never migrate in production; `deploy/prestart.py` does that before gunicorn starts.
- A database that is only busy (another process holds a lock) is retried for a while; a worker that still cannot
  start exits with an ordinary error status (`roxy.worker.TRANSIENT_BOOT_EXIT_CODE`), so gunicorn simply starts
  another worker instead of stopping the color.
- The proxy route answers 503 until the abuse pipeline exists, so a half-built worker never serves callers.
- When gunicorn asks a worker to stop, `roxy.lifespan.begin_drain` drops readiness and wakes every tarpit hold at
  once, uvicorn waits at most 20 s for open requests, and the cleanups share one 8 s budget
  (`roxy.lifespan.SHUTDOWN_BUDGET_S`), so the final metrics flush runs before gunicorn's 30 s kill.

The background loops of a worker (`metrics_flush`, `heartbeat`, `loop_lag`, `leader`, `jobs`, `config_watcher`,
`sse_tail`, `egress_refresh`, `upstream_mirror`, and the cache and abuse loops) all run through
`roxy.core.tasks.TaskSupervisor`, which logs a failure, restarts the loop after a backoff, bounds one-shot tasks,
and cancels everything cleanly at shutdown.

## Request flow

### The middleware stack

`roxy.main.create_app` installs the middleware from `roxy.core.middleware.build_middleware`, outermost first:

| Order | Middleware | What it does |
|---|---|---|
| 1 | `roxy.core.middleware.RequestIdMiddleware` | Gives every request a `Roxy-Request-Id` (also on error answers) and counts it for the fleet view. |
| 2 | `roxy.core.errors.UnhandledErrorMiddleware` | Turns an escaped exception into the plan 7.13 500, then runs the error hooks (probe log, error table, alert email). |
| 3 | `roxy.core.middleware.ClientIPMiddleware` | Resolves the real client IP once, from the right end of `X-Forwarded-For`, only when the peer is a trusted proxy. |
| 4 | `roxy.core.deadline.DeadlineMiddleware` | Runs the rest inside `asyncio.timeout(request_deadline_s)` and answers 504 with `Retry-After` when time runs out. |
| 5 | `roxy.core.security_headers.SecurityHeadersMiddleware` | A fresh CSP nonce per response, the CSP itself and the other security headers. |
| 6 | `roxy.core.middleware.SizeLimitMiddleware` | Refuses long URLs (414), big headers (431) and big bodies (413) while reading, never after buffering. |
| 7 | `roxy.core.middleware.TimingMiddleware` | Records how long the app took and writes the `http_request` log line. |

These are pure ASGI classes, not Starlette's `BaseHTTPMiddleware`, because that helper runs the app in a separate
task and buffers responses, which costs time on every request and breaks streaming.

### The routers

After the middleware, routes are tried in this order (`roxy.main.ROUTER_MODULES`):

1. `roxy.internal_app.PublicInternalNotFound`: an instant 404 for `/internal` on the public port.
2. `roxy.public.health`: `GET /health` for monitors.
3. `roxy.public.csp_report`: `POST /csp-report`, where browsers send CSP violation reports.
4. `roxy.public.pages`: the home page, `/docs` (the user guide), `/status`, robots, sitemap, favicon.
5. `roxy.admin.router`: the login surface, the admin API under `/admin/api/v1`, and a final catch-all that
   answers an unknown admin path with a plain 404 (never a probe record).
6. `roxy.proxy.router`: the catch-all proxy route, always last so it never shadows a real page.

### One proxied request

`src/roxy/proxy/router.py` runs one request through `roxy.proxy.router.ProxyFlow`. It is a plain Starlette
endpoint that reads `request.app.state.ctx` itself: the hot path skips FastAPI's dependency injection and Pydantic
models because both cost work per request that this route does not need. The steps, in their binding order:

1. **OPTIONS** is answered at once (204 with `Allow`), never checked, never counted as a probe.
2. **Parse the target.** `roxy.proxy.validate.parse_target` reads the raw, still encoded path and query and returns
   the host, the normalized path and the query pairs in caller order, or a problem (`unsafe_url`, `not_roblox`,
   `host_not_allowed`). This is the SSRF defense. A `roxy.proxy.context.ProxyRequest` is built; HEAD becomes GET.
3. **Peek the cache** (`roxy.cache.service.CacheService.peek`), memory and cache.db only, never Roblox. By default
   cache hits count toward the per-IP limit (`throttle_count_cache_hits` = 1), so the peek runs after the abuse
   verdict; `roxy.proxy.router.peek_before_verdict` moves it earlier only when a check needs the answer.
4. **Abuse verdict.** `roxy.abuse.pipeline.AbusePipeline.evaluate` walks the checks in a fixed order (pause, bans and
   deny list, bypass, flood, spam, throttle-all, per-IP throttle, place limit, challenge, bot score, User-Agent
   rules, ignored paths, unsafe URL, not Roblox, auth smuggling, header filters, endpoint blocks, endpoint rate
   rules) and updates every limiter of the request in one hot.db write transaction.
5. **Refused:** the tarpit (`roxy.abuse.tarpit.Tarpit.plan`) may hold the answer for a while (hold, drip or jitter),
   never for a bypass caller, then the refusal is sent.
6. **Allowed:** the request is fingerprinted, then `roxy.cache.service.CacheService.serve` answers from the cache
   (HIT, REVALIDATING with one background refresh, STALE during a cooldown) or fetches. A fetch goes through
   fleet-wide single-flight (`roxy.upstream.singleflight.SingleFlight.run`), so concurrent misses of one key in any
   worker make one upstream call.
7. **Upstream.** `roxy.upstream.service.UpstreamService.fetch` picks the egress (`roxy.upstream.routing.decide`),
   reserves a slot in every GCRA bucket the call needs in one hot.db transaction (`roxy.upstream.buckets.reserve`,
   together with the single-flight lease), waits for that slot in a bounded queue, sends through
   `roxy.egress.clients.EgressClients.send`, classifies the answer, records cooldowns and breaker results, and
   retries only what the outcome policy allows. It never raises for an upstream problem: every failure becomes a
   row of the plan 7.13 table.
8. **Respond.** `roxy.proxy.respond.render` builds the exact bytes the caller gets: the real Roblox status, the
   safe response headers only (`roxy.proxy.scrub.safe_response_headers`), the `Roxy-*` headers, pretty printing
   when asked, and the sandbox CSP for proxied content.
9. **Record.** `roxy.metrics.recorder.MetricsRecorder.record_outcome` runs exactly once per request, also when an
   exception escapes. It only updates in-memory counters; the batch writer stores them every 2 s.

The caller's headers never reach Roblox, with three exceptions: `Accept` (only `application/json` or `*/*`) and,
for bodies, `Content-Type` and `Content-Length` (`roxy.proxy.scrub.forwarded_request_headers`). Every forwarded
header is also part of the cache key, so one caller's header can never change the answer another caller gets.

### The admin and public surfaces

- `src/roxy/admin/auth/` is the login surface and the guards: `roxy.admin.auth.deps.require_admin` (a session, or
  a session with a fresh second factor) and `roxy.admin.auth.deps.require_csrf`.
- `src/roxy/admin/api/` is the JSON API under `/admin/api/v1`: one module per area (`roxy.admin.api.API_MODULES`,
  25 areas) plus the event stream `GET /admin/api/v1/stream` (`src/roxy/admin/sse.py`). The mount checks in
  `src/roxy/admin/api/__init__.py` refuse to start the app if any route lacks its guard or its CSRF check.
- The dashboard pages (plan phase P11) call the same read models as the API, so every number has one source.
- `src/roxy/public/` serves the public site; `GET /health` answers monitors with v1's keys plus a `Degraded` list.

## Storage: four SQLite databases

### Why SQLite in WAL mode

v1 rewrote whole JSON files under a lock: every update cost the size of the file, every worker waited for every
other, and a damaged file failed open. SQLite in WAL (write-ahead log) mode gives readers that never wait for the
writer, indexed point updates, atomic commits, `PRAGMA quick_check` and online copies (`VACUUM INTO`), with no
extra daemon to run and secure. Redis and PostgreSQL were rejected as more moving parts than one small server
needs (plan 6.1).

### Why four files

SQLite allows one writer per file at a time. Splitting by write pattern keeps the hot path (rate limit admits,
bucket reservations) from waiting behind a metrics flush or a large cache body:

| File | Holds | Durability | Notes |
|---|---|---|---|
| control.db | Settings and their history, the audit log, every rule table, bans, access lists, admin users, sessions, passkeys, trusted devices, the encrypted UI-set credential and rotator URL, `service_state` | `synchronous=FULL` | Rare writes that must survive a power cut. The audit log is append-only (triggers). |
| hot.db | `limiter`, `strikes`, `upstream_bucket`, `cooldown`, `breaker`, `lease`, `job_runs`, `email_gate`, `login_failures`, `spam_windows`, `csrf_cache` | `synchronous=NORMAL` | Small, hot and prunable. Every shared limit lives here. |
| metrics.db | Rollups per minute, hour, day and month, `events`, `upstream_429`, `request_samples`, recommendations, health runs, captures, fingerprints, worker heartbeats and the insight history tables | `synchronous=NORMAL` | Written in batches. Metrics may degrade open (C7). |
| cache.db | `entries`, `generation`, `change_observations` | `synchronous=NORMAL` | Disposable: checked at startup and rebuilt if damaged, never backed up. |

The exact tables are in the migration files under `src/roxy/storage/migrations/`, one folder per database.

### How code talks to a database

`src/roxy/storage/db.py` gives each database one writer thread and two reader threads per worker
(`roxy.storage.db.Database`). Async code calls `await db.write(fn)` or `await db.read(fn)` with a small function
that receives a `sqlite3.Connection`; the function runs on the thread, never on the event loop. Writes run inside
`BEGIN IMMEDIATE`, which takes the write lock at the start, so a read-decide-update function can never interleave
with another process's write: that is what makes limits exact across workers. Reads run inside a deferred
transaction, so several queries see one snapshot.

When a database stays locked past its busy timeout, or the disk fails, the caller gets
`roxy.storage.db.SharedStateUnavailable`. Callers use it to fail closed where it matters (plan C7): no credential
use, no tarpit hold, no admin login, and a conservative per-worker rate limit of `limit // workers`. A hot path
passes a shorter budget (`busy_timeout_ms`), measured from the moment the job was queued, so a locked hot.db costs
a request half a second, not five.

### Migrations

`roxy.storage.migrate` runs numbered SQL files. Expand migrations only add (tables, columns, indexes), so the
previous release keeps working on the new schema while both colors run. They run in each color's pre-start step
(`deploy/prestart.py`, as the `roxy` user, after a `VACUUM INTO` snapshot of control.db). Contract migrations
(drops, renames) only ever run by hand, one release later; `deploy/README.md` has the command.

### Shared state and hot reload

Settings, rules, bans and access lists live in control.db, and one counter, `service_state.config_version`, is
bumped in the same transaction as any change. Each worker polls that counter every second
(`roxy.config.runtime.RuntimeSettings.refresh_if_changed` and `roxy.rules.store.RulesStore`) and, when it moved,
builds a new immutable snapshot in one read transaction. Requests only ever read the snapshot in memory, never the
database, and a request that grabbed a snapshot sees one consistent set of rules even if a reload happens halfway
through. A change made on one worker is live on every worker within about a second.

### Leases

`src/roxy/storage/leases.py` provides time-limited ownership stored in hot.db: a row `(name, holder, expires_ms,
epoch)`. If the holder dies, the lease simply expires and someone else takes it over; every takeover increments
`epoch`, a fencing token. Leases are used for the leader, single-flight keys (`sf:<key>`), the tarpit's fleet-wide
slot cap (`roxy.storage.leases.acquire_slot`), the cache.db startup check, one health run at a time, one action
per recommendation at a time, and the event stream slots.

### Metrics without a write per request

`roxy.metrics.recorder.MetricsRecorder` adds numbers to in-memory dictionaries keyed by minute and a hash of the
dimensions; `roxy.storage.batch.BatchWriter` upserts them every `metrics_flush_interval_ms` (2 s). Two workers that
write the same minute simply add up, so totals are exact with any number of workers. Every queue is bounded
(`metrics_queue_max`); when it overflows, the oldest low-priority items are dropped and counted.

### Retention

Every table has a maximum age, a row cap, or both (plan 6.10, the `retention_*` settings). The leader prunes in
small batches and follows with `incremental_vacuum`, so files shrink and the hot path never waits behind one big
delete (`src/roxy/storage/retention.py`).

## Leader jobs

Some work must run once for the whole fleet: rollups, retention, probes, recommendation evaluation.
`roxy.scheduler.leader.LeaderElector` keeps trying to hold the `leader` lease in hot.db (15 s lifetime, renewed
every 5 s). Whoever holds it leads; when it dies the lease expires and another worker takes over within 15 s.
Because hot.db is shared by both colors, there is exactly one leader across blue and green during a deploy.

A leader that stalls (a long pause, a frozen VM) still believes it leads when it wakes up, so every leader write
is fenced: inside the writing transaction it checks that the lease still names this holder and epoch, and rolls
back with `roxy.scheduler.leader.LostLeadership` otherwise. Writes to databases other than hot.db also require
`roxy.scheduler.leader.FENCE_MARGIN_S` of lease time left. Jobs that must not run twice (an alert, a scheduled
health run slot) first claim an idempotency key in hot.db `job_runs`.

`roxy.scheduler.jobs.JobRunner` runs the registered jobs. The main ones:

| Job | Runs on | What it does |
|---|---|---|
| `metrics_compaction` | leader | Folds closed minutes into hours, days and months; keeps the top clients. |
| `metrics_live_prune`, `metrics_security_caps`, `fingerprint_auto_ignore` | leader | Delete live rows older than 15 minutes, keep the probe, login and crawl events within their caps, and stop listing header values that are unique per request. |
| `retention`, `hot_prune`, `file_retention` | leader | Plan 6.10 retention for tables, hot.db rows, exports and snapshots. |
| `wal_checkpoint_passive`, `daily_maintenance` | leader | PASSIVE checkpoints every few minutes; the daily TRUNCATE checkpoint, `quick_check` and `optimize` at `maintenance_hour`. |
| `adaptive_rate_increase` | leader | Slowly raises a bucket rate that demand proves too low (never one an admin set). |
| `credential_liveness` | leader | Probes the credential every `credential_probe_interval_min` minutes. |
| `insights_evaluate`, `insights_triggers`, `insights_anomalies`, `insights_watch`, `insights_auto_apply`, `insights_history_prune` | leader | The recommendations engine and its watch windows. |
| `health_scheduled_run`, `health_publish_jobs` | leader | Scheduled Check Proxy Health runs and the job status H-LEADER reads. |
| `llm_export_file` | leader | Writes the hourly LLM export file. |
| `admin_requests_watch` | every worker | Applies a forced metrics flush or counter reset asked for in another worker. |

Every interval that comes from a setting is read again before each scheduling decision, so a settings change
applies without a restart. The status of every job is published for the System page.

## Blue/green deploy

A deploy replaces the running code without dropping a request. `deploy/deploy.sh <sha>` runs on the server as the
unprivileged deploy user `roxy-deploy`:

1. Fetch exactly that commit into `/opt/roxy/releases/<sha>` (it must be on `main`) and record a manifest of the
   nginx files.
2. Build the release's own virtual environment with uv while the live color keeps serving.
3. Migrations: the idle color's pre-start step (`deploy/prestart.py`) snapshots control.db and applies the expand
   migrations as the `roxy` user.
4. Point `current-<idle>` at the release and restart `roxy@<idle>`.
5. Health gate: the idle color's internal socket must report Ready, PersistenceOK and the new version within 60 s,
   then `scripts/smoke_remote.py` checks the pages, the proxy and that `/internal` is hidden.
6. Install the nginx config through the root wrapper when it changed, then switch nginx to the idle color
   (`/usr/local/sbin/roxy-switch-color`, an atomic symlink swap and a reload).
7. Watch the new color for 60 s.
8. Stop the old color; its shutdown flushes metrics and releases its leases. Keep the newest five releases.
9. Record the deployed commit in `/var/lib/roxy-deploy/deployed_version`.

Any failure before step 8 switches nginx back, restores the previous nginx config, stops the new color and exits
non-zero, which fails the GitHub Action and sends the "deploy failed" alert. `deploy/deploy_rollback.sh` goes back
to the previous release (or a named one) with the same steps in the other direction.

While both colors run, nothing doubles: they share the same databases, so limits, buckets and cooldowns are the
same rows, and one leader runs the jobs. The deploy user can only run the commands in `deploy/sudoers/roxy-deploy`:
start, stop, restart and reload of the two colors, and the two root wrappers. `deploy/README.md` has the full
picture, including the first setup.

## Memory sizing for the 1 GB server

The production server has 909 MB of RAM and no swap, while the plan was sized for 2 GB. Everything that can grow
is bounded by a setting or a constant, and the sizes were scaled down (DESIGN.md section 0, `CHANGES.md`
"Memory sizing for the 1 GB server").

### What one worker may hold

| Item | Bound | Where it is set |
|---|---|---|
| SQLite page cache, control.db | 2 MiB writer + 2 x 1 MiB readers | `src/roxy/storage/db.py` (`roxy.storage.db.PROFILES`) |
| SQLite page cache, hot.db | 4 MiB writer + 2 x 1 MiB readers | same |
| SQLite page cache, metrics.db | 8 MiB writer + 2 x 2 MiB readers | same |
| SQLite page cache, cache.db | 4 MiB writer + 2 x 2 MiB readers | same |
| Memory-mapped cache.db | up to 32 MiB, file-backed and reclaimable | same (`mmap_size` is 0 for the other files) |
| Cache memory tier | `cache_memory_bytes` (16 MiB) and `cache_memory_entries` (1000) | settings catalog |
| Metrics queue | `metrics_queue_max` items (50,000) | settings catalog |
| Background log queue | 10,000 lines or 4 MiB | `roxy.core.logging.LOG_QUEUE_MAX_LINES`, `roxy.core.logging.LOG_QUEUE_MAX_BYTES` |
| Upstream wait queue | `queue_max_length` (500) waiters | settings catalog |

The page caches add up to at most 30 MiB per worker, and only fill as pages are read. The Python heap, the
libraries, the HTTP connection pools and the recorder's counters are the remaining part; they have not been
measured on the server yet. Each worker reports its resident memory in its heartbeat every 5 s (the `rss` field of
`worker_heartbeat`, shown on the System page through `GET /admin/api/v1/system/workers`), so the real figure is
visible from the first day. The load harness measured a development machine, not the production box: the leader
worker kept growing over a long replay (finding LOAD-2) because each recommendations evaluation read a day of request
samples as dicts; reads are now compact and bounded, the units tune glibc's allocator, and a color measured 332 MiB
of PSS after a 35 minute soak. `docs/PERFORMANCE.md` has the figures and the quiet-machine commands to measure again
before release.

### What one color may hold

systemd caps each color (`deploy/systemd/roxy@.service`):

- `MemoryHigh=350M`: above this the kernel reclaims the color's memory aggressively and slows it down.
- `MemoryMax=450M`: the hard limit; above it the color's processes are killed and systemd restarts the color.

During a deploy both colors run for a few minutes. Two colors at `MemoryHigh` (700 MB) plus nginx and the
operating system (about 200 MB) fit the 909 MB; `tests/deploy/test_deploy_units.py::test_memory_numbers_fit_the_909_mb_server`
checks that arithmetic. When less than 700 MB is available before the restart, `deploy/deploy.sh` switches to
low-memory mode: the idle color starts with one worker and grows to `ROXY_WORKERS` after the old color stopped,
through the gunicorn control socket (`--low-memory` forces it, `--no-low-memory` turns it off).

### If memory runs short

The first knob is `cache_memory_bytes`: the memory tier is a copy of what cache.db already holds, so a smaller
tier only costs a disk read on a hit. `deploy/README.md` also explains how to add a small swap file as a safety
net, not as capacity.

## Design decisions and their reasons

| Decision | Reason | Where |
|---|---|---|
| gunicorn with uvicorn workers, 2 per color | Async workers hold thousands of waiting connections cheaply; gunicorn adds readiness, graceful reloads, recycling and a frozen-loop watchdog that plain uvicorn lacks (plan 5.2). | `deploy/gunicorn.conf.py`, `src/roxy/worker.py` |
| A per-request deadline inside the app | gunicorn's `timeout` only notices a frozen loop, never a slow upstream; the app must answer first with a status the caller can act on. Every inner budget is derived from `request_deadline_s`. | `src/roxy/core/deadline.py` |
| The proxy route skips FastAPI dependency injection | It is the busiest route and its inputs are raw bytes that the validators check more strictly than a model would. | `src/roxy/proxy/router.py` |
| SQLite in WAL mode, four files | Shared state without another daemon; one writer per file, so hot limits never queue behind metrics or cache writes. | `src/roxy/storage/db.py` |
| `BEGIN IMMEDIATE` for every shared decision | Read, decide and update happen under the write lock, so N workers enforce exactly one limit (C6). | `src/roxy/storage/db.py`, `src/roxy/abuse/pipeline.py` |
| GCRA instead of fixed windows | One number per bucket, a smooth pace with a small burst, and no window edge where twice the limit fits. | `src/roxy/abuse/limiter.py`, `src/roxy/upstream/buckets.py` |
| One abuse transaction per request | Every limiter of a request is decided and counted together; a request refused later spends no rate budget. | `src/roxy/abuse/pipeline.py` |
| Leases with an epoch instead of locks | A lock dies with its process; a lease expires on its own, and the epoch fences a holder that woke up late. | `src/roxy/storage/leases.py`, `src/roxy/scheduler/leader.py` |
| Fleet-wide single-flight | With several workers a popular key that expired would otherwise cost one call per worker, at the worst moment. | `src/roxy/upstream/singleflight.py` |
| Answer before storing | The caller gets Roblox's answer as soon as it arrives; the cache.db write and the outcome publish follow in a bounded background tail, so a locked cache.db never delays anyone. | `src/roxy/cache/service.py` |
| Batched metrics | A row per request would make every request wait for the disk; counters in memory, flushed every 2 s, add up exactly across workers. | `src/roxy/metrics/recorder.py`, `src/roxy/storage/batch.py` |
| Fail closed where it matters, open where it does not | Shared state that cannot be read must never unlock the credential, the tarpit or an admin login; metrics may have a gap instead (C7). | `docs/SECURITY.md` section on C7 |
| Immutable snapshots of settings and rules | Requests never touch the database for configuration and never see a half-applied change. | `src/roxy/config/runtime.py`, `src/roxy/rules/store.py` |
| One settings catalog | Every setting is declared once with its type, range, help and risk; validation, the editor, `docs/SETTINGS.md` and the LLM export come from it (plan principle P3). | `src/roxy/config/catalog.py` |
| Internal endpoints on a Unix socket | The peer address proves nothing behind nginx; a socket that only the `roxy` group can open does. | `src/roxy/internal_app.py` |
| Credential confinement in layers | Each layer (separate clients, `trust_env=False`, the leak guard transport, cookie jars that refuse cookies) holds on its own (C2). | `src/roxy/egress/` |
| CPU-heavy work off the event loop | One 250 ms argon2 hash on the loop would freeze every request of the worker. | `src/roxy/admin/auth/passwords.py` |
| Logs written by a thread | A paused journald must never freeze a worker; the queue is bounded and drops are counted. | `src/roxy/core/logging.py` |
| One TCP listener per worker (`reuse_port`) | With one shared socket nearly all connections went to one worker; the kernel now spreads them. | `deploy/gunicorn.conf.py` |
| Server-side admin sessions | Logout, revocation and the kill switch delete rows; a copied database holds only hashes. | `src/roxy/admin/auth/sessions.py` |

## Where to go next

- `docs/LEARNING_PATH.md` walks through these pieces in reading order, with exercises.
- `docs/SECURITY.md` covers the threat model and the constraints.
- `docs/RUNBOOKS.md` turns this knowledge into steps for incidents.
- `docs/SETTINGS.md` lists every runtime setting, generated from the catalog.
