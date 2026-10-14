# Roxy performance and load tests

This page records how Roxy v2 was load tested (plan 19.4), what the tests measured against the performance targets
of plan 6.7, the replay of a v1-like traffic profile that plan 19.10 row 7 accepts on, how much memory each worker
used against the 1 GB server, and how many bytes one metrics rollup row takes (plan 6.6). It also says how to run
every measurement again.

Every figure below was measured on 2026-10-09 and 2026-10-10 on a development machine (WSL 2), not on the production
plan size, and while other agents ran test suites and their own load runs on the same machine (load average mostly
between 1 and 8). Counts (calls, 429s, avoided shares) and memory are reliable; **latency and throughput figures are
indicative only**, and every before and after comparison below was measured at the same time on the same machine
(interleaved runs, or soaks side by side). The lead reruns the numbers on a quiet machine before release with the
commands in "Running it again". The section "LOAD-2 and LOAD-3: what grew, what contended, what changed" records the
perf lane's findings and fixes; the older sections keep the figures of the code before them (commit 3861e65).

## Running it again

All commands run inside WSL from the repository root. The harness needs unprivileged user and network namespaces
(`unshare -rn`); on Ubuntu 24.04 that means `kernel.apparmor_restrict_unprivileged_userns=0`.

The harness's own checks (no gunicorn, about 2 s):

```sh
.venv/bin/python -m pytest -q tests/load -m "not load"
```

The acceptance test of plan 19.10 row 7 (one gunicorn run, about 4 minutes):

```sh
.venv/bin/python -m pytest -q -rA -m load tests/load
```

Every scenario with its results table (about 10 minutes; `--json` keeps every number):

```sh
cd tests && env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.harness --json /tmp/roxy-load.json
```

**The quiet machine rerun before release** (the lead). Stop every other test run first and check that `uptime`
shows a load average under 1. Then measure the release commit exactly, from a clean export of it, five replays and
one run of everything else:

```sh
cd ~/Projects/RobloxProxyServer
rel=$(git rev-parse --short HEAD); out=/tmp/roxy-perf-$rel; rm -rf "$out"; mkdir -p "$out/tree"
git archive HEAD | tar -x -C "$out/tree"
cd tests
for n in 1 2 3 4 5; do
  env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.harness replay --tree "$out/tree" \
    --json "$out/replay$n.json" | tee "$out/replay$n.txt"
done
env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.harness steady cold_burst cooldown_429 flood \
  --tree "$out/tree" --json "$out/scenarios.json" | tee "$out/scenarios.txt"
cd .. && .venv/bin/python -m pytest -q -s tests/integration/test_metrics_rowsize.py
```

**The memory soak and the write lock ceiling (LOAD-2, LOAD-3)**, before and after side by side: `$base` is the
commit before the perf lane (3f2ad1c), the release is HEAD. The replay soaks run together (about 37 minutes), then
the aged soaks together (30 minutes at 200 a second, about a day of samples); the steady runs alternate between
the two trees, three of each, so the machine's mood hits both alike (about 25 minutes):

```sh
cd ~/Projects/RobloxProxyServer
base=3f2ad1c; rel=$(git rev-parse --short HEAD); out=/tmp/roxy-perf-$rel; rm -rf "$out"
mkdir -p "$out/base" "$out/tree"; git archive $base | tar -x -C "$out/base"; git archive HEAD | tar -x -C "$out/tree"
cd tests
for t in base tree; do
  env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.harness replay --scale 10 --tree "$out/$t" \
    --work "$out/soak-$t" --json "$out/soak-$t.json" > "$out/soak-$t.txt" 2>&1 &
done; wait
for t in base tree; do
  env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.harness steady --scale 30 --tree "$out/$t" \
    --work "$out/aged-$t" --json "$out/aged-$t.json" > "$out/aged-$t.txt" 2>&1 &
done; wait
for n in 1 2 3; do for t in base tree; do
  env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.harness steady --tree "$out/$t" \
    --json "$out/steady200-$t-$n.json" > "$out/steady200-$t-$n.txt" 2>&1
  env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.harness steady --tree "$out/$t" --steady-rate 450 \
    --steady-connections 400 --json "$out/steady450-$t-$n.json" > "$out/steady450-$t-$n.txt" 2>&1
done; done
for t in base tree; do
  env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.harness flood --tree "$out/$t" \
    --json "$out/flood-$t.json" > "$out/flood-$t.txt" 2>&1
done
cd .. && .venv/bin/python -m pytest -q -s tests/multiprocess/test_storage_mp.py -k "group_commit or latency"
```

Read in each soak table the rows "peak RSS per worker", "peak memory of the color" and "memory over the run" (the
JSON's `memory.timeline` has a point every 30 s); in each steady table "offered and achieved rate", "cache hit
latency", "miss overhead", "hot.db write lock, every transaction" and "hot.db budget overruns". The harness applies
the `Environment=` lines of the measured tree's `roxy@.service` (the allocator tuning) the way systemd does, and its
table lists them.

Useful options: `--scale 6` runs every duration six times longer (a 20 minute replay), `--keep` keeps each
scenario's state, gunicorn log and the mock's call log (`<work>/replay/mock_calls.csv`), `--set KEY=VALUE` changes
a setting and `--worker-env KEY=VALUE` the workers' environment for a "what if" run (marked in the table as not a
reference run), and `--steady-connections N` gives the steady scenario's client more connections, so at a rate the
server cannot keep up with, the server (not the client's pool) sets the answered rate.

## LOAD-2 and LOAD-3: what grew, what contended, what changed

Measured on 2026-10-10 by the perf lane (two agents: the first stopped before it reported, its successor reviewed,
reworked and measured everything again) with the harness above, diagnostics that are not shipped (a
`sitecustomize` hook in the measured copy writing each worker's RSS, glibc `mallinfo2`, SQLite's memory counter, full
garbage collection pauses and tracemalloc snapshots every 30 s), and offline runs of one recommendations evaluation
against a kept state. "Before" is commit 3f2ad1c (the code the findings were filed against); "after" is commit
94ca1c3 with the reworked `storage/db.py` of this section, which also carries the P11 pages code (about 9 MiB more
per process at start); the lighter bot tracker (below) came after the soaks and only lowers their figures. Every before and after pair below ran at the same time on the same machine (load average 5
to 12 from other agents), so latency and throughput are comparable within a table, not across tables.

### LOAD-2: what grew

Two different growths, both on the leader worker.

**The recommendations evaluation (every 30 s) held a day of request samples as dicts.** Each sample read returned up
to 50,000 rows, the evaluation memoized every read until it ended, and the rules read per template, so one
evaluation held several overlapping copies. Its high water mark rose with the traffic: a tracemalloc snapshot of the
leader at minute 33 of the 10 a second replay caught an evaluation holding 27.9 MiB in `metrics/read_history.py`
(rows and the dicts made of them); offline, one evaluation over the request samples plan 6.6 expects in a day
(293,304) peaked at **251.5 MiB** above its start. In the harness at 200 requests a second (360,000 requests in 30
minutes, about a day of samples), the leader reached **660 MiB** and the color 864 MiB of PSS, and the leader spent
97 percent of a core in evaluations: cache hit p99 43 s, 1,125 HTTP 503.

**glibc kept freed memory in many arenas.** glibc allows 8 malloc arenas per CPU (256 on the 32 CPU development
machine, 16 on the 2 vCPU server) and raises its mmap threshold after the first large free, so the transient reads
above left holes in the heaps of the worker's 20 or so threads (`mallinfo2` free space: 22 MiB on the leader after 35
minutes).

What did not grow: live Python objects stay flat at the replay's rate (tracemalloc snapshots of the leader at minute
15 and 25 differ by 0.2 MiB after the fix, 0.4 MiB between minute 10 and 20 before, besides an evaluation in flight),
and SQLite's page caches fill toward their bound (`docs/ARCHITECTURE.md`, "What one worker may hold": about 30 MiB
per worker; 22 MiB on the leader after 35 minutes, 7 MiB on the other worker).

### LOAD-2: what changed

- `metrics/read_history.py`: the two sample reads return `SampleRecord`, a read-only mapping over one tuple with a
  column index shared by every row of the read, repeated values (templates, methods, states, hot keys) sharing one
  string; same `[]`, `get`, `in`, iteration and equality with a dict, a third of the memory. The snapshot that held
  27.9 MiB now holds 12.3 MiB for the same evaluation.
- `insights/context.py`: one evaluation keeps at most `MAX_MEMO_SAMPLE_ROWS` (50,000) sample rows memoized; past it
  the oldest reads are forgotten and read again when a rule asks. Offline at a day's volume, same 17
  recommendations: peak 251.5 MiB before, **35.6 MiB** after (92.6 MiB with compact rows but no bound). The cost is
  time: 1.7 s per evaluation before, 3.5 s after (1.6 s compact without the bound), because the rules ask for the
  same per-template reads again in turn (since resolved: "The recommendations evaluation: one read per window").
- `abuse/bot.py`: a tracked client's probe and query histories are created when first used (an empty deque
  costs 760 bytes and most clients never probe): 3.3 KB instead of 4.1 KB a client after 20 requests with a query
  string, 1.5 KB less without one; at the tracker's bound of 10,000 clients, up to 32 MiB a worker instead of 39.
- `deploy/systemd/roxy@.service`: `MALLOC_ARENA_MAX=2`, `MALLOC_MMAP_THRESHOLD_=131072`, `MALLOC_TRIM_THRESHOLD_=131072`
  (two arenas; blocks of 128 KiB and more always mmapped and returned when freed). The same code with and without
  them, side by side: color PSS 354.0 against 374.3 MiB after 35 minutes, leader 218 against 234 MiB, other worker
  166 against 173 MiB. The load harness applies a measured tree's `Environment=` lines the way systemd does.
- `worker.py`: `gc.freeze()` once a worker started, so full collections skip the startup heap. Leader at 10 a
  second: worst full collection 156 ms before, 108 ms after (they run twice as often, each shorter); other worker 151
  against 124 ms. A modest gain; it changes no memory figure.

**Soak: 35 minutes of the replay (10 requests a second, 2 workers, no worker recycling), three trees side by side**
(PSS of the whole color, master included; worker RSS leader / other, MiB):

| Minute | Color before | Color after | After without the allocator lines | Workers before | Workers after |
|---|---|---|---|---|---|
| 0 | 243.7 | 270.8 | 279.9 | 135 / 135 | 153 / 147 |
| 5 | 292.9 | 305.4 | 322.0 | 172 / 153 | 176 / 161 |
| 10 | 317.7 | 325.0 | 340.7 | 186 / 155 | 185 / 163 |
| 20 | 341.2 | 341.5 | 358.6 | 216 / 157 | 204 / 165 |
| 30 | 357.9 | 348.8 | 369.4 | 231 / 158 | 215 / 166 |
| 35 (end) | 364.7 | 354.0 | 374.3 | 239 / 159 | 218 / 166 |

Growth over the last 15 minutes: leader 1.48 MiB a minute before, 0.62 after (0.92 without the allocator lines);
the other worker 0.12 and 0.09. The color grew 121 MiB before and 83 after; the after tree starts 27 MiB higher
because it carries the P11 pages. The replay outcome is the same in every tree (9,4xx calls, 52.5 to 53.4 percent
avoided), so the fixes change no behavior.

**Aged soak: 30 minutes at 200 requests a second (360,000 requests, about a day of samples), before and after side
by side** (no worker recycling):

| Minute | Color before | Color after | Leader before | Leader after | Other before | Other after |
|---|---|---|---|---|---|---|
| 0 | 242 | 260 | 135 | 145 | 135 | 145 |
| 3.5 (about 20,000 requests a worker) | 403 | 405 | 257 | 241 | 177 | 194 |
| 10 | 516 | 441 | 364 | 267 | 185 | 207 |
| 20 | 683 | 465 | 516 | 283 | 199 | 214 |
| 30 | 819 | 477 | 638 | 290 | 214 | 219 |

After: cache hit p99 113 ms, no HTTP 503, 200.1 answered a second, 23 `abuse_degraded` and 1 publish failure.
Before: cache hit p99 42.9 s, 1,125 HTTP 503, 190.4 answered a second, 1,960 and 5,252. The after color still grows
slowly at this rate (about 0.4 MiB a minute at the end): per-client structures with large bounds keep filling
(the bot tracker and the spam detectors; open issue below). Production recycles each worker
after about 20,000 requests (`max_requests`, with 10 percent jitter), which is where every per-request structure
starts over.

### The recommendations evaluation: one read per window (finding G7)

The leader evaluates every rule every 30 s (`insights_interval_s`). At a day's volume that cost 3 to 5.5 s of CPU an
evaluation, almost all of it on the databases' reader threads (Python building rows, which holds the GIL the event
loop needs): every rule that tunes a cache lifetime read up to 50,000 samples of its template for the whole day (the
OLDEST 50,000: a busy template's day was silently cut), and the memo bound made the rules read them again in turn;
the address table was read 250 rows a page, each page re-running the whole aggregate and a rates read (3.2 s for
2,000 addresses over 24 hours). Now (`CHANGES.md`, "P11 gaps lane: the recommendations evaluation", finding G7):

- each window is read once for every rule of a run: `by` and `clients` are one aggregate (`queries.top_rows_sync`,
  `queries.client_rows_sync`), and the TTL tuner is SQL over every sample of the window
  (`read_history.change_estimates`, one small row per template; a parity test pins it to the Python tuner float for
  float), as are the User-Agent experiment's arm counts;
- raw sample rows are read only where a rule needs rows, filtered in SQL (`read_history.SampleFilter`), and a read its
  bound cut says so in the recommendation's evidence (`sample_bound`);
- a dry run replays the newest part of its window that fits 50,000 samples and says so (`bounded`, `note`; before,
  a day window replayed its oldest few hours and called them the day), and the replay, pure Python over up to 50,000
  samples, runs on a worker thread, one at a time per event loop (`simulate.offload`), as do the key spread grouping
  and CACHE-NEG's error replay.

Offline, one evaluation (`InsightsEngine.evaluate`, every rule) at the time of the last sample, the process pinned to
one CPU with `taskset` (the leader's share of the 2 vCPU server under load), two runs each, before and after
interleaved, on copies of the seeded databases (a one-off measurement script of the lane, not part of the
repository; to measure again, time one `InsightsEngine.evaluate` call the same way on a copy of the dashboard
scenario's template). "Day" is the dashboard scenario's seeded day (`tests/load/pages.py`:
500,000 requests, 477,330 request samples, 2,000 addresses); "replay" is the perf lane's copy of a replay state
(293,304 samples over 22 hours, 13 templates). The loop stall is how late a 2 ms sleep on the same event loop woke up.

| | Day before | Day after | Replay before | Replay after |
|---|---|---|---|---|
| Wall time | 5.6 to 5.9 s | 0.57 to 0.62 s | 3.0 to 3.3 s | 0.54 to 0.58 s |
| CPU of the process (every thread) | 5.4 to 5.7 s | 0.56 to 0.60 s | 2.9 to 3.2 s | 0.52 to 0.56 s |
| CPU of the event loop's thread | 0.29 to 0.31 s | 0.03 to 0.05 s | 0.52 to 0.71 s | 0.02 to 0.04 s |
| Longest loop stall | 33 to 38 ms | 5 to 17 ms | 40 to 60 ms | 14 to 17 ms |
| Peak traced memory of one evaluation | 39.3 MiB | 15.3 MiB | 35.9 MiB | 11.3 MiB |

The first evaluation after a start costs about 1.1 s (cold page caches). The largest read left is the tuner's SQL
over a day of samples (0.18 s on the day, 0.3 s on the replay, outside the GIL).

### Memory per color and the systemd decision

The units now hold each color at `MemoryHigh=420M` and `MemoryMax=500M` (were 320M and 420M; the first perf agent's
350M and 450M were measured before the P11 code and without a high-rate soak), with the allocator lines above.

| Case | Measured or derived | Against |
|---|---|---|
| A color at 10 a second, workers recycling every 20,000 requests (about every 67 minutes) | 354 MiB at 35 minutes, 0.3 MiB a minute at the end: about 365 MiB | under `MemoryHigh` 420 |
| A color at 200 a second, workers recycling every 20,000 requests (about every 3.5 minutes) | 405 MiB at 3.5 minutes | under `MemoryHigh` 420 |
| Short peaks on top (one evaluation at a day's volume, two 16 MiB table downloads) | up to about 70 MiB | under `MemoryMax` 500 |
| A login burst (anyone can send one; no password is needed to make Roxy hash): one argon2id hash of 19 MiB at a time per worker (`HASH_CONCURRENCY` 1, final review finding sec-2) | +20 MiB a worker, measured over 5 runs with the unit's allocator lines: 40 MiB a color (plan 9.5's 64 MiB, two at a time, measured 95 to 129 MiB a worker) | the 95 MiB a warm color has left under `MemoryMax` 500 |
| The C7 degraded-mode stores while hot.db cannot be written (`limiter.MEMORY_ROWS_MAX` 6,000 entries each, least recently used evicted; final review finding abuse-14) | about 4.4 MiB a worker when both are full (tracemalloc, about 380 bytes an entry): 8.8 MiB a color (50,000 entries, the bound before, took about 37 MiB a worker) | under `MemoryMax` 500 |
| One color at its hard limit, plus nginx and the OS (about 200 MB, the lead's estimate) | 500 + 200 = 700 | 909 |
| A deploy on this server (low-memory mode: below 700 MB available, which a warm color always causes): a warm color at `MemoryMax` plus a new color with one worker (155 MiB at start) plus 200 | 855 | 909 |
| A deploy in normal mode (only when 700 MB or more is available): two fresh workers, 275 MiB at start | fits in the 700 available | 909 |
| Two warm colors at once (never made by deploy.sh or the rollback) | 2 x 405 + 200 = 1,010 | does not fit |

`MemoryHigh` 350M would have throttled a healthy color within the hour (355 MiB after 35 minutes at 10 a second);
320M within 20 minutes. Two warm colors cannot both fit the 909 MB server at any setting that leaves one color room
to work, so the rule is in the deploy instead: the new color always starts fresh and the old one stops after the
60 s watch (`deploy/README.md` "Never run two warm colors at once"). `test_memory_numbers_fit_the_909_mb_server`
checks the rows above. The swap file of `deploy/README.md` stays recommended as a safety net.

### LOAD-3: what contends

The steady scenario at 200 requests a second with call site counters (the time inside each job's function, where the
write lock is held; both trees side by side, 12,133 requests):

| hot.db write | Per request | Inside, mean (max) before | Inside, mean (max) after |
|---|---|---|---|
| The abuse transaction (`abuse/pipeline.py _transaction`, plan 6.3) | 0.88 | 0.38 ms (130) | 0.47 ms (35) |
| Bucket reservation with the single-flight lease (`upstream/buckets.py reserve`) | 0.16 | 1.03 ms (125) | 0.82 ms (30) |
| Single-flight outcome publish (`upstream/singleflight.py`) | 0.16 | 0.14 ms (4) | 0.20 ms (11) |
| Spam detector flush (`abuse/spam.py`), once a second per worker | 0.009 | 8.0 ms (39) | 6.9 ms (32) |

About 1.2 hot.db write transactions per request. The lock is held a small share of the time, yet before the fix
writes waited 30 to 135 ms at p99 and the fleet answered about 180 to 205 requests a second at most, because:
1. SQLite's busy handler sleeps 1, 2, 5, 10 ... 100 ms between tries, so a worker that found the lock taken a few
   times slept through the moments it was free while the other worker took it again; its queue grew and its 500 ms
   budgets ran out (`abuse_degraded`, `singleflight_publish_failed`, HTTP 503 `degraded`).
2. Inside a transaction every SQLite statement gives the GIL away and may wait for the event loop to hand it back
   (up to 5 ms while the loop is busy), so a transaction holds the lock far longer than its SQL takes (after the
   fix, at 200 a second and load average 10 to 12: hold p50 0.25 to 1 ms, p99 in the 50 ms bucket, once 100; wait
   p99 in the 10 ms bucket). The spam flush ran two statements per subject.
3. Full garbage collections stopped the event loop for about 150 ms.

### LOAD-3: what changed

- `storage/db.py`: a writer thread waits for the lock in short polls (`LOCK_POLL_MS`, 2 ms a try, until the job's
  budget or the profile's 5 s), so no worker falls into SQLite's long sleeps.
- `storage/db.py`: group commit on hot.db in a backlog: when at least `GROUP_MIN_QUEUE` (8) writes wait, the writer
  runs the queued hot-path writes (the budgeted ones) in one `BEGIN IMMEDIATE ... COMMIT`, at most `GROUP_MAX_JOBS`
  (64) while the transaction has held the lock less than `GROUP_MAX_MS` (10 ms). Below the backlog every write keeps a
  transaction of its own (the shortest lock holds). The contract and its proof are below.
- `abuse/spam.py`: the flush reads every subject with one statement per 500 and writes them with one multi-row upsert
  per 300 (was a read and a write per subject); `abuse/limiter.py save_rows` and `abuse/throttle.py
  save_strike_rows` write their rows with one statement per 150 (was one per row; a key given twice still ends with
  its last values).
- `worker.py`: `gc.freeze()` (above).
- `storage/db.py DbStats`: lock wait and lock hold histograms of every write transaction and the group counts, on the
  System page's metrics pipeline card (`GET /admin/api/v1/system/metrics-pipeline`: `lock_wait_ms`, `hold_ms`,
  `groups`, `grouped_writes`, `largest_group`) and in the harness's steady table.

**Group commit, why it is correct.** Each property is a test in `tests/unit/storage/test_storage_db_group.py`,
`test_storage_db_group_faults.py`, `test_storage_txn_contract.py` or `tests/multiprocess/test_storage_mp.py`:
- A caller gets its value only after COMMIT returned (results are handed out by one function called after it; if a
  bug interrupts the bookkeeping after COMMIT, the committed results are still delivered). Every other ending (COMMIT
  fails, an I/O, corruption or out-of-memory error, a savepoint that cannot be rolled back or released, a job that
  ended the transaction, a bug before COMMIT) rolls the transaction back and answers every job that ran
  `SharedStateUnavailable` or its own exception; the jobs not reached run in a new transaction.
- A job that raises undoes only its own changes (every job after the first runs in a savepoint; the first needs none)
  and its caller gets exactly the exception a transaction of its own would give (`SharedStateUnavailable` chained to
  an unavailable SQLite error, anything else unchanged; a test runs the same jobs grouped and ungrouped and compares
  type, message and cause). A savepoint that cannot open fails only its own job, which never ran; the jobs before it
  commit.
- One job's mistake can never fail the COMMIT or end the transaction: grouping needs foreign keys off
  (`group_safe`; SQLite defers no other constraint), no function passed to `write` runs COMMIT, ROLLBACK, END,
  `commit()` or `executescript()` and no SQL uses the ROLLBACK conflict resolution (a scan of `src/roxy`), and a job
  that did end its transaction anyway is detected and its whole group reported "unavailable", never done.
- Jobs run one at a time in queue order inside one `BEGIN IMMEDIATE`, so each sees every earlier job's rows and no
  other process writes in between: the same history as separate transactions in that order. Limits stay exact
  (counters, a fleet cap, leases and epoch fences, with 1, 2 and 4 processes), ordinary writes keep their place in the
  queue, and a caller that reads after its write returned sees it.
- A job starts only through the `Future` handshake (a caller that gave up first wins, a running job is never
  canceled) and only before its deadline, so budgets and the busy circuit behave as before, grouped or not.
- A process that dies between two grouped jobs answered nobody, and SQLite discards the uncommitted transaction.
- Every hot.db multiprocess test (abuse, degraded mode, single-flight, upstream, alerts, the event stream, storage)
  also passed with grouping forced on every budgeted write (47 tests).

**Results, interleaved on the same machine** (three runs of each, medians and ranges; load average 6 to 12):

| Steady scenario | Answered a second | Cache hit p99 | Miss overhead p99 | Roxy's own p95 / p99 | HTTP 503 | `abuse_degraded`, publish failures |
|---|---|---|---|---|---|---|
| 200 offered, before | 202 (202 to 208) | 226 ms (47 to 976) | 468 ms | 293 / 771 ms | 0 | 5, 1 (up to 30, 54) |
| 200 offered, after | 202 (202 to 203) | 220 ms (70 to 267) | 348 ms | 149 / 445 ms | 0 | 2, 0 |
| 450 offered, 400 connections, before | **179 (165 to 186)** | 44 s | 44 s | 1,411 / 2,870 ms | 192 | 261, 232 |
| 450 offered, after | **286 (267 to 319)** | 31 s | 31 s | 497 / 2,692 ms | 110 | 11, 373 |
| 450 offered, after without group commit | 263 (218 to 280) | 37 s | 35 s | 763 / 2,874 ms | 168 | 51, 286 |

**The ceiling** (answered a second when far more is offered): **about 179 before, 286 after on this busy machine
(+60 percent)**; group commit is about 23 of the 107. Before, the workers sat at 43 percent of a core each while
requests queued behind the lock; after, they use 50 to 75 percent. The flood (1,000 a second offered from 50
addresses, tarpit on): 347 answers a second after against 203 to 208 before, `abuse_degraded` 50 against 144 to 352,
and the most any address was served above its GCRA bound 1 against 4 (both from the C7 degraded mode while budgets
ran out, open issue below). Two processes doing only hot.db writes
(`test_group_commit_throughput_under_two_process_contention`): about 4,500 writes a second one transaction each,
18,000 to 19,800 grouped.

### Open (LOAD-2 and LOAD-3)

- Resolved since (finding G7, "The recommendations evaluation: one read per window" above): the rules re-read the
  same per-template samples (3.5 s an evaluation at a day's volume), and the all-template read stopped at the oldest
  50,000 rows of a busy day.
- Per-client structures with large bounds keep a color growing at high rates until its workers recycle: a
  tracemalloc run at 60 requests a second (4,000 client addresses) shows the bot tracker (`abuse/bot.py`, 10,000
  clients, up to 32 MiB a worker) and the spam detectors' per-client state (`abuse/spam.py`, 20,000 subjects) as
  the only lines still growing after 5 minutes. The units are sized with recycling counted; smaller bounds (for
  example 4,000 tracked clients, 13 MiB) would score and watch fewer clients, so they are the abuse owners' call.
- The ceiling is now set by CPU and GIL handoffs in the request path, and plan 6.7's 3 ms p99 for the abuse
  transaction is still not met under contention (lock hold p99 in the 50 ms bucket).
- Under a flood the C7 degraded mode still lets an address exceed its GCRA bound by one request when a worker's
  budget runs out (the abuse owners' merge rules; it happened 4 times per address before).

## Method

**The system under test** is started the way production starts it: `gunicorn -c deploy/gunicorn.conf.py
roxy.asgi:app` with `roxy.worker.RoxyUvicornWorker` and 2 workers (`ROXY_WORKERS`, `deploy/env/roxy.env.example`), `reuse_port`, the
production keep-alive and timeouts. The four databases live in a fresh temporary state directory, migrated and
seeded before the start as the deploy's prestart step does. Settings are the built-in defaults, with three
exceptions that every scenario shares (`tests/load/fleet.py`): the scheduled health run and the rotator are off
(both would add calls to the counts; with the rotator off all traffic leaves from one address, the hardest case for
Roblox's per-address limits), `ROXY_ENV=development` (the only environment that accepts the loopback upstream
override) and `ROXY_MAX_REQUESTS=0` (no worker recycling in the middle of a memory measurement). A scenario that
changes a setting lists the change in its table.

**Isolation (plan 19.12).** The harness re-executes itself inside `unshare -rn`, a user and network namespace whose
only interface is loopback. Roblox traffic goes to a local mock through the development-only
`ROXY_TEST_UPSTREAM_BASE` override, so no name is ever resolved by real DNS. Client addresses come from the
RFC 5737 documentation ranges and the RFC 2544 benchmark range; credentials are fakes generated per run.

**The client** (`tests/load/client.py`) is open loop: a request leaves at its planned instant whatever happened to
the earlier ones, so a slow server shows up as latency and queueing instead of quietly lowering the offered rate
(coordinated omission). Arrivals are Poisson. The plan is split over spawned client processes that check in at a
barrier before one common start instant is set, so a slow start on a busy machine delays the start instead of
sending the first seconds of the plan in one bunch. Each request carries `X-Forwarded-For` with its planned
address (trusted from loopback, as Roxy trusts nginx) and Roblox's game server User-Agent.

**One clock for everyone** (`tests/load/clock.py`). Callers send N requests a minute, Roxy paces M calls a minute,
and the mock refuses above L calls a minute; if one of them measures a minute differently, the test measures the
clocks. On WSL 2 they do differ: `CLOCK_MONOTONIC` runs about 9.5 percent fast against the host (90 s of
`time.monotonic()` took 82.2 s on a Windows stopwatch; the wall clock moved 81.5 s), and the wall clock, which Roxy's
GCRA buckets, cache TTLs and cooldowns read, is stepped back about 2.8 s every 32 s to stay on the host's time
(the step was 0.9 s per 31 s on other days). The client's schedule and the mock's windows therefore run on the
wall clock, made steady (never stepping back, like Roxy's own `max(TAT, now)`), and every duration (latency,
timeouts) on `time.monotonic()`. Latency figures measured on WSL are about 9.5 percent too high for that reason.

**The mock Roblox** (`tests/load/mock_roblox.py`) answers every Roblox host on one loopback port with deterministic
JSON bodies, a per-endpoint latency, and per-endpoint limits: an endpoint refuses (429 with Roblox's usual body and
no `Retry-After`) when Roxy's single address made more calls to it in the last 60 s than its threshold, refused
calls included. Every call is logged with its time, so the harness counts upstream calls and Roblox 429s from the
mock's side (ground truth), and replays each endpoint's window afterwards: `peak_60s` is the most calls an endpoint
ever had in one 60 s window, so `limit - peak_60s` is how close Roxy came to the threshold.

**The v1-like profile** (`tests/load/traffic.py`, `V1_LIKE_MIX`) is synthetic: no real traffic may be used (C4,
19.12), and v1 never stored its per-endpoint counts anywhere the agents may read. Thirteen endpoints with shares,
key spaces and popularity skew taken from the v1 notes, the plan (2.5, 10, D11) and the user guide: avatar outfits
16 percent (20,000 user ids), game details 14 percent (150 universes), user name lookups 10 percent (POST), avatar
headshots 12 percent, user details 8 percent, group roles 8 percent, votes, place to universe, server lists, badges,
economy and catalog details, presence (POST, 15 s TTL). The thresholds are 30 to 150 calls a minute per endpoint
(plan 2.5: many endpoints allow far less than 95 per 65 s); they were fixed before the first run and are never
tuned to make a test pass.

**What the numbers mean.** Demand is every caller request Roxy tried to serve (abuse refusals are not demand, plan
P6). Upstream calls are the mock's count of calls for caller traffic (Roxy's own credential probes carry the cookie
and are counted apart). The avoided-call share is plan P6's: demand minus upstream calls, over demand. It counts a
caller that Roxy told to come back later (a pacing answer, `upstream_busy` or `upstream_cooldown`, 429 with
`Retry-After`) as avoided, because Roblox was spared the call; the tables therefore also show the share served
from the cache or a shared fetch and the share deferred by pacing.

**Deviations from the plan** (for CHANGES.md):

- Plan 19.4 says "locust or k6". The harness is Python with httpx and asyncio instead: both tools are new
  dependencies (k6 is not Python), and neither can start gunicorn, the mock and the temporary state in one private
  network namespace, read Roxy's metrics database afterwards, or sample each worker's memory. httpx is already a
  dependency, so the lock file is unchanged.
- Plan 6.7 and 19.10 want the numbers from a staging VM of the production plan size. These were measured on the
  development machine below; the quiet rerun (above) is still not the production plan size.
- The flood scenario measures the app's limits only: there is no nginx in front of it (nginx's own limits are
  checked by the deploy tests).

## The machine

| Item | Value |
|---|---|
| CPU | AMD Ryzen 9 9950X3D, 16 cores, 32 logical CPUs |
| Memory | 31.2 GiB (no limit on the workers; production is 909 MB, no swap) |
| OS | Ubuntu 24.04 under WSL 2, kernel 6.18.40.1-microsoft-standard-WSL2 |
| Python and packages | Python 3.12.3, gunicorn 26.2.0, uvicorn 0.54.0, uvloop 0.23.0, httptools 0.8.0, httpx 0.28.1 |
| Load | load average 0.6 to 8 from other agents' test runs, 34 for the two deliberate busy-machine replays |
| Roxy measured | `git archive` of commit 3861e65 (`--tree`), except where a row says "working tree" |

Production is a 2 vCPU burstable Lightsail instance with 909 MB of memory and no swap (`docs/ARCHITECTURE.md`,
"Memory sizing for the 1 GB server"). Throughput and latency on it will differ; per-process memory figures transfer
better (see the memory section for the one caveat).

## Results of the plan 19.4 scenarios (indicative)

One run of each scenario, 2026-10-09 15:46 to 15:55, Roxy 3861e65, while a 20 minute replay and other agents'
test suites ran (load average 7 to 8). The steady scenario was run again at 16:07, when the machine was quieter
(load average 0.6 at the start; two slow replays still ran beside it); both are shown. An earlier run of all four at
15:31 gave the same picture.

### Steady mixed cacheable traffic, 200 requests a second, 60 s

90 percent of requests ask for one of 50 hot keys per endpoint, 10 percent for a key never seen before; every
endpoint answers in 30 ms; the upstream buckets are raised to 10,000 a minute so 20 or more misses a second can
flow (6.7 states its miss targets at 20 misses a second, above the default direct bucket).

| Metric | Busy machine (15:46) | Quieter machine (16:07) | Target (6.7) |
|---|---|---|---|
| Offered and answered a second | 200 and 202.9, all 12,133 answers 200 | 200 and 202.1, all 200 | 200 |
| Cache hit latency (client side) | p50 4.2, p95 50, p99 278 ms | p50 3.0, p95 11.1, p99 26.9 ms | p99 under 8 ms |
| Miss latency minus the 30 ms upstream | p50 10.7, p99 538 ms | p50 7.7, p99 78 ms | p99 under 15 ms |
| Upstream calls a second | 35.5 | 35.5 | about 20 misses |
| CPU per worker (percent of one core) | 38.5 and 33.2 | 30.4 and 22.3 | |
| hot.db write time (sampled) | p50 0.24, p99 135 ms | p50 0.14, p99 29.5 ms | abuse transaction p50 under 0.5, p99 under 3 ms |
| hot.db writes a second per worker; most waiting | 127 and 120; 114 | 140 and 111; 92 | |
| Metrics flush (sampled) | p50 30.7, max 475 ms | p50 20.7, max 80 ms | under 50 ms per 2 s of traffic |
| `abuse_degraded` log lines (500 ms hot.db budget ran out) | 28 | 2 | 0 |
| Event loop lag p99, worst heartbeat | 90 and 45 ms | 29 and 10 ms | |
| Requests recorded by Roxy | 12,133 of 12,133 | 12,133 of 12,133 | equal |

The median request is fast; the tail is not, and the tail moves with the machine's load by a factor of ten. Both
workers sat at a quarter to a third of one core while up to 92 to 114 writes waited in one worker's hot.db writer
queue, and single writes took up to 30 to 135 ms: the time goes to waiting for hot.db's write lock, not to
computing. Every request makes at least one hot.db write transaction (the abuse transaction, plan 6.3), the two
worker processes share the file, and SQLite's busy handler waits by sleeping (1, 2, 5, 10, up to 100 ms) whenever
the other process holds the lock. That lock also sets the ceiling the busy runs reached, about 205 requests a second
for the steady mix and 205 answers a second for the flood. Whether a quiet machine and the production disk meet
the 3 ms target is the first question for the quiet rerun; if they do not, the per-request abuse transaction is the
design point to revisit (plan 6.3).

### Cold cache burst: 100 hot keys from 500 addresses

2,500 requests at one instant (5 per address) for 100 keys on 11 GET endpoints, empty cache, production pacing.

| Metric | Measured | Expected |
|---|---|---|
| Upstream calls | 100, none answered 429 | at most 100, one per key (single-flight) |
| First answers | 1,993 served, 507 paced (429 `upstream_busy`) | production pacing |
| Cache state of the first answers | 1,423 HIT, 481 COALESCED, 596 MISS (the paced ones included) | |
| Retry-After | on every 429, at most 7 s | never missing |
| After one retry | 2,391 of 2,500 served | |
| Every answer in | 37.3 s (client side; the client queues on 512 connections) | |
| Roxy's own latency | p50 116 ms, p95 3,985 ms, p99 4,951 ms | |

Single-flight holds across both workers: exactly one upstream call per key. The callers that were paced received
429 with `Retry-After`, never a silent wait past the 4 s queue budget.

### Roblox answers 429 with Retry-After: 30 on one endpoint, 90 s

20 requests a second for badge details (each a new badge id, so no cache entry can answer), plus 10 a second of
background traffic on the other endpoints.

| Metric | Measured | Expected |
|---|---|---|
| Upstream calls to the 429 endpoint | 4 in 90 s: 2 in flight before the first 429 came back, then 1 at 30.4 s and 1 at 60.5 s | about 1 per Retry-After |
| Caller answers there | 1,821 of 1,821 were 429 `upstream_cooldown` with `Retry-After` | 429 with Retry-After |
| Caller latency there | p50 5.1 ms, p99 90.5 ms | bounded, no wait for Roblox |
| Other endpoints | 915 of 915 served (200), p50 4.3 ms | unaffected |

The cooldown works as plan 7.5 and 19.10 row 7 (first half) want: one probe call per Retry-After, every caller told
when to come back, no cascade to the other endpoints.

### Flood: 50 addresses at 1,000 requests a second, 20 s

`tarpit_on_throttle` is on so the tarpit's fleet cap is exercised.

| Metric | Measured | Expected |
|---|---|---|
| Offered | 921 a second (20,312 planned) | 1,000 a second |
| Answers | 1,039 served, 19,273 refused `throttle` | |
| Served per address | at most 24; at most 2 above what the per-IP GCRA (10 per 50 s, burst 10) allows over the time that address was being answered | 0 above |
| Tarpit holds at once (hot.db slot leases) | peak 50 | fleet cap 50 |
| Answered | all 20,312 within 99 s, 205 answers a second overall | |
| CPU per worker | 35.0 and 26.4 percent of one core | |
| Upstream calls | 22 | few (hot keys are cached) |
| 500 ms hot.db budget overruns | 202 `abuse_degraded` lines | 0 |

The fleet cap held at exactly 50 holds. Roxy answered the flood at about 205 requests a second, the same hot.db
ceiling as the steady scenario, so the flood took 99 s to drain. The two requests above the per-IP bound for one
address most likely come from the 202 degraded transactions: while hot.db cannot be written within its budget, each
worker limits from memory at `limit / workers` (C7) and merges afterwards. Two extra over a 90 s span is within
what a degraded mode can promise, but worth a look by the abuse owner, and the quiet rerun shows whether the budget
runs out at all without other load.

### Plan 6.7 targets at a glance

| Target (6.7) | Measured here (indicative; quieter run, busy run in brackets) | Status |
|---|---|---|
| Proxy overhead p99 under 8 ms on a hit at 200 rps, 2 workers | p99 26.9 ms (278), p50 3.0 ms | not met on this machine; rerun quietly |
| Proxy overhead p99 under 15 ms on a miss | p99 78 ms (538), p50 7.7 ms | not met on this machine; rerun quietly |
| Abuse transaction p50 under 0.5 ms, p99 under 3 ms at 200 rps | hot.db writes p50 0.14 ms, p99 29.5 ms (135), sampled | p50 met, p99 not met |
| Upstream transaction p99 under 3 ms at 20 misses a second | not separated from the abuse writes | not measured |
| Metrics flush of 2 s of traffic under 50 ms | p50 20.7 ms, max 80 ms (475), sampled | p50 met, max not met |
| Dashboard first render under 300 ms; 90 day chart query under 500 ms | measured in "Dashboard pages" below (the P11 pages): every page at its default range and every fragment under 300 ms at p95, quiet, on 2 CPUs and with load; every 90 day chart route at the UI's granularity under 500 ms | met on this machine, with the exceptions listed there; rerun quietly |

The client measures latency from the moment it sends to the end of the body, so it includes the client's own
Python overhead (a few hundred microseconds) and, on WSL, the 9.5 percent fast monotonic clock.

## Plan 19.10 row 7: the replay of a v1-like profile

10 requests a second for 200 s from 300 game server addresses, Poisson arrivals, from an empty cache, against the
mock's per-endpoint thresholds, production defaults. Accepted when Roblox 429s stay below 0.1 percent of upstream
calls and the avoided-call share is at least 40 percent.

### Every run

"Monotonic clock" runs used the harness as committed in 3861e65, whose client and mock ran on `time.monotonic()`;
"shared clock" runs used the harness after this lane's fix (`clock.py`). "Busiest minute" is avatar outfits' most
calls in one 60 s window against its threshold of 60.

| Run | Harness clock | Roxy | Upstream calls | Roblox 429s | 429 share | Avoided | Served from cache | Deferred | Busiest minute |
|---|---|---|---|---|---|---|---|---|---|
| 1 | monotonic | working tree | 947 | 0 | 0.000 % | 53.1 % | 30.5 % | 22.5 % | not recorded |
| 2 | monotonic | working tree | 951 | 1 (at 50.7 s) | **0.105 %** | 52.9 % | 31.3 % | 21.7 % | 61 / 60 |
| 3 | monotonic | working tree | 949 | 0 | 0.000 % | 53.0 % | 30.4 % | 22.5 % | 58 / 60 |
| 4 | monotonic | working tree | 948 | 0 | 0.000 % | 53.0 % | 31.3 % | 21.7 % | 59 / 60 |
| 5 | monotonic | working tree | 948 | 0 | 0.000 % | 53.0 % | 30.7 % | 22.3 % | 59 / 60 |
| 6 | shared | 3861e65 | 1,020 | 2 (55.5, 165.5 s) | **0.196 %** | 49.5 % | 31.8 % | 18.0 % | 61 / 60 |
| 7 | shared | 3861e65 | 1,019 | 2 (60.9, 167.1 s) | **0.196 %** | 49.5 % | 32.1 % | 18.0 % | 61 / 60 |
| 8 | shared | 3861e65 | 1,020 | 2 (50.7, 156.5 s) | **0.196 %** | 49.5 % | 31.6 % | 18.4 % | 61 / 60 |
| 9 | shared | 3861e65 | 1,020 | 2 (50.5, 152.5 s) | **0.196 %** | 49.5 % | 31.6 % | 18.3 % | 61 / 60 |
| 10 | shared | 3861e65 | 1,019 | 2 (47.6, 157.5 s) | **0.196 %** | 49.5 % | 31.6 % | 18.3 % | 61 / 60 |
| 11 | shared | 3861e65 | 1,019 | 2 (50.5, 155.7 s) | **0.196 %** | 49.5 % | 31.8 % | 18.2 % | 61 / 60 |
| 12, all CPUs busy | shared | 3861e65 | 1,014 | 2 (50.5, 156.5 s) | **0.197 %** | 49.8 % | 31.3 % | 19.0 % | 61 / 60 |
| 13, all CPUs busy | shared | 3861e65 | 1,018 | 2 (50.5, 155.7 s) | **0.196 %** | 49.6 % | 31.9 % | 18.3 % | 61 / 60 |
| pytest 1 | shared | working tree | not printed | 2 or more (xfail) | 0.1 % or more | 40 % or more (passed) | n/a | n/a | n/a |
| pytest 2 | shared | working tree | 1,020 | 2 (61.0, 167.2 s) | **0.196 %** | 49.5 % (passed) | n/a | n/a | 61 / 60 |
| 20 min, first | shared | 3861e65 | 5,609 | 9 | **0.160 %** | 54.1 % | 44.4 % | 10.5 % | 61 / 60 |
| 20 min, second | shared | 3861e65 | 5,616 | 8 | **0.142 %** | 54.0 % | 44.5 % | 10.3 % | 61 / 60 |
| 30 min | shared | 3861e65 | 8,442 | 8 | 0.095 % | 53.6 % | 45.9 % | 8.4 % | 61 / 60 |
| 30 min, `MALLOC_ARENA_MAX=2` | shared | 3861e65 | 8,441 | 8 | 0.095 % | 53.6 % | 46.1 % | 8.3 % | 61 / 60 |

Runs 1 to 11 ran while other agents' suites kept the load average between 1 and 8; runs 12 and 13 ran beside 32
busy-looping processes (load average 34, every logical CPU taken), and the result did not move. "pytest" rows are
`pytest -m load tests/load` itself, which measures the working tree. Every run had zero transport errors, zero calls
with the credential on caller traffic, a `Retry-After` on every 429 and 503 Roxy sent, a clean graceful stop and no
traceback in the log. Runs on the shared clock took 227 to 234 s (monotonic) with 0.5 to 1.5 s to prepare the state
and 2.3 to 5.4 s to start gunicorn.

### Finding LOAD-1: v2 does not meet the 0.1 percent bar at its defaults

**Resolved in P11 (2026-10-10, the pacing lane; CHANGES.md "P11 lane: upstream pacing, finding LOAD-1 fixed").** Host
and endpoint buckets now cap every rolling minute, and a Roblox 429 cuts from the rate Roblox refused, rate and burst
together. At the same defaults the 200 s replay gets one discovery 429 in about 1,030 calls (0.097 percent, 6 of 6
pytest runs) and a 30 minute replay 2 in 8,593 (0.023 percent, against 8 in 8,442 before); the assertion is a plain
assertion again (no xfail). The rest of this section is the finding as measured before the fix.

The avoided-call share passes comfortably (49.5 to 54.1 percent against 40). The Roblox 429 share does not: 0.196
percent in every 200 s run on the shared clock, 0.142 to 0.160 percent over 20 minutes, and 0.095 percent over 30
minutes. The 429s are the same in every long run, eight or nine at the same moments (50, 156, 292, 341, 341, 559,
745 and 989 s), and none after 989 s: Roxy pays them while it learns the limits after a cold start, then stops. So
v2 does meet the bar on a replay long enough to dilute that cost (30 minutes, about 8,400 calls, just under), and
does not on the 200 s replay the 5 minute test budget allows (2 of about 1,020 calls), nor on 20 minutes.

Where the 429s come from: the endpoints whose Roblox threshold is below Roxy's default endpoint rate (120 a minute)
and whose cache cannot absorb the demand. In the first 20 minute run: avatar outfits 3 (threshold 60), presence 5
(threshold 30), group roles 1 (threshold 60); in the second, avatar outfits 3 and presence 5. Avatar outfits gets
16 percent of the traffic over 20,000 user ids (18 percent served from the cache); presence bodies list up to six
random user ids, so nearly every request is a miss.

Why Roxy does not stop at the threshold, from the mock's call log and the `adaptive_rate_decrease` log lines:

1. **The first cuts do not bind.** At the start nothing paces avatar outfits at 60 a minute; only its share of the
   direct egress bucket (300 a minute, shared by every endpoint) holds it near 60, and the busiest minute reaches
   61: Roblox answers 429. The adaptive controller (plan 7.3) lowers the endpoint's configured rate by 30 percent,
   from 120 to 84 a minute, which is still above what the endpoint actually ran at, so nothing changes. About 100 s
   later the same minute reaches 61 again: a second 429, the rate goes to 58.8. In the long run a third 429 took it
   to 41.16. The cut is a percentage of the configured rate, not of the rate the endpoint was really making.
2. **The burst is never cut.** GCRA allows `rate + burst - 1` calls in a 60 s window that starts with a full
   bucket. At 58.8 a minute with the default burst of 10 that is up to 67 calls, above a 60 a minute threshold; at
   41.16 it is 50. For presence (threshold 30) the cuts went 120, 84, 58.8, 41.16 and the burst of 10 is a third of
   its whole limit; presence earned five 429s, the last at 989 s, before its own demand (about 24 a minute) stayed
   under the threshold.
3. **The steps are slow.** From 120 a minute, 30 percent steps need four cuts (four 429s and four cooldowns) to get
   below 30.

This is the design at its plan defaults (15.3 C: `endpoint_bucket_default_per_min` 120, burst 10,
`adaptive_decrease_pct` 30), not a timing problem of the harness: on the shared clock every run gives the same two
429s at the same moments, on a quiet machine and with every CPU busy. Changing it is a plan decision, so this lane
only measured options ("what if" runs, not reference runs):

| What if | Roblox 429s | Avoided | Note |
|---|---|---|---|
| `endpoint_bucket_default_per_min` 50, 200 s | 0 of 1,033 (0.000 %) | 48.8 % | avatar outfits' busiest minute 58 of 60; presence 25 of 30 |
| `adaptive_decrease_pct` 50, 200 s | 2 of 1,019 (0.196 %) | 49.5 % | 120, 60, then 30: the first cut still does not bind |
| `endpoint_bucket_default_per_min` 50, 20 minutes | 3 of 5,852 (0.051 %) | 52.1 % | all three on presence (50, 35, 24.5, then 17.15 a minute); deferred 7.0 % against 10.3 % at the default |

A lower starting rate is the only option measured here that meets the bar, over 200 s and over 20 minutes. It
does not remove the mechanism: presence, whose threshold (30) is below the new default, still paid three 429s to
find its rate.

Directions for the lead, each a change to plan 7.3, 15.3 C or 19.10 row 7: cut from the measured rate of the last
60 s (at the first 429 avatar outfits ran at 61, so a 30 percent cut lands at 43 and binds at once); cut the burst
with the rate (or size it from the rate, for example `ceil(rate / 12)`); start endpoints lower (50 a minute in the
table above) and let the existing upward probing (24 clean hours with real demand, plus 10 percent) raise the
endpoints that need more; or decide that row 7 is judged on a replay long enough to dilute the cold start (30
minutes or more, a nightly job rather than the 5 minute test), where v2 at its defaults measured 0.095 percent.

### Why the lead's gate failed once and passed when rerun

The harness as committed ran its client and its mock on `time.monotonic()`, while Roxy's buckets, TTLs and
cooldowns run on the wall clock. On WSL 2 the monotonic clock runs 9.5 percent fast, so the mock's "minute" was 55
real seconds. Counted in the mock's minutes, Roxy's buckets let through 9.5 percent less than their rate and its
cache entries lived 9.5 percent longer, so the mock was about 9.5 percent more generous to Roxy than a machine with
honest clocks would be. That held avatar outfits' busiest minute at 58 to 61 against 60: a coin toss between no 429
(passes) and one 429 out of about 950 calls (0.105 percent, fails). The gate run was a 61; the rerun was a 58 or
59. On the shared clock the busiest minute is 61 in every run and the result is two 429s, every time.

The test is now built so that timing cannot decide it: one clock for client, mock and Roxy; a start barrier
instead of a fixed start delay; the mock's window replayed per endpoint so a failure says how close every endpoint
came; a 5 s warm-up instead of 20 s, so a run takes about 230 s (monotonic) and stays inside the 5 minute budget
on a busy machine. The thresholds (0.1 and 40 percent) are unchanged. Because of LOAD-1 the 429 assertion was
marked `xfail` (not strict: a run whose busiest minute stays at 60 passed) until the pacing fix above; it is a plain
assertion now, and the avoided share and the soundness checks stay strict.

## Memory against the 1 GB server

This section keeps the load lane's figures of 2026-10-09 (commit 3861e65, before the LOAD-2 fixes, when the units
said `MemoryHigh=320M` and `MemoryMax=420M`). The current figures, the cause of the leader's growth and the limits
the units now set (420M and 500M) are in "LOAD-2 and LOAD-3" above, "Memory per color and the systemd decision".

Production has 909 MB and no swap; each color ran with `MemoryHigh=320M` and `MemoryMax=420M` (MiB), and during a
deploy two colors overlap (`deploy/systemd/roxy@.service`). The sampler reads RSS, USS and PSS
from `/proc` every 0.5 s; PSS summed over the master and both workers is the best per-process estimate of the
color's charge (the cgroup also charges page cache, which no per-process figure shows).

| Scenario | Worker RSS peak (MiB) | Worker USS peak (MiB) | Master RSS (MiB) | Color PSS peak (MiB) |
|---|---|---|---|---|
| Idle after boot (every scenario's first point) | 132 to 141 | | 39 | 235 to 257 |
| Replay, 200 s, 10 a second | 164 to 169, 147 to 152 | 134 to 139, 116 to 122 | 39 to 40 | 281 to 295 |
| Replay, 20 min (two runs) | 217 to 220, 156 to 157 | 183 to 187, 124 to 125 | 39 | **339 to 353** |
| Replay, 30 min | 230, 163 | 202, 129 | 40 | **364** |
| Replay, 30 min, `MALLOC_ARENA_MAX=2` | 222, 158 | 189, 126 | 40 | **348** |
| Steady, 200 a second, 60 s (busy, quieter) | 197, 169 to 171 | 166, 138 to 139 | 40 | **336 to 338** |
| Steady, `MALLOC_ARENA_MAX=2` | 193, 159 | 163, 128 | 40 | **322** |
| Cold burst | 165, 159 | 135, 128 | 39 | 294 |
| 429 cooldown, 90 s | 167, 151 | 137, 120 | 39 | 286 |
| Flood, 1,000 a second offered | 176, 170 | 146, 140 | 39 | 316 |

**Finding LOAD-2: the leader worker keeps growing.** The memory timeline of the 30 minute replay (one point every
30 s) shows the two workers part ways. The worker that is not the leader goes from 148 MiB at 30 s to 155 MiB at
10 minutes and stays there (158 MiB at 33 minutes). The leader goes from 157 MiB at 30 s to 183 MiB at 9.5
minutes, 191 MiB just after a step at 10 minutes, 208 MiB at 17 minutes, 226 MiB at 30 minutes and 230 MiB at 33
minutes: about 2.9 MiB a minute in the first nine minutes and 1.5 MiB a minute in the last twelve, slowing but not
level when the run ended. Every long run has the same shape, including the step of about 7 MiB at 10 minutes. The
color's PSS crossed `MemoryHigh` (320 MiB) after about 12 minutes of 10 requests a second and was 364 MiB at the
end. `MALLOC_ARENA_MAX=2` lowers every figure by about 10 MiB and changes neither the growth nor its shape, so this
is not allocator fragmentation across threads. The cause is not known: the leader is the worker that runs the
leader jobs (insights every 30 s, history pruning every 10 minutes, rollups and compaction, health publishing, the
LLM export file at start and hourly). The page caches of a worker's usual SQLite connections and the cache.db
memory map add up to about 60 MiB (`docs/ARCHITECTURE.md`, "What one worker may hold"), less than the leader's 73 MiB of growth, and the other
worker, which reads the same files for the same requests, did not grow. Someone who owns those jobs should take two
`tracemalloc` snapshots of the leader ten minutes apart, and the quiet rerun should include a soak of a few hours
(`--scale 60` is a 200 minute replay) to see where it levels off.

What it means for the 1 GB box:

- A color at rest is about 235 to 257 MiB of PSS. Under the steady 200 a second load (within a minute) and in
  every replay of 20 minutes or more it went above `MemoryHigh` (320 MiB), to 336 to 364 MiB: the kernel would
  reclaim this color's memory hard, and throttle it, before page cache is even counted. `MemoryMax` (420 MiB) was
  not reached in 33 minutes, but at the leader's growth rate it would be within a few hours unless it levels off.
- During a deploy two colors overlap. Two colors at rest are about 500 MiB, and an old color under load plus a new
  one starting is 600 MiB or more, on a box that also runs nginx and the operating system in 909 MB. The deploy's
  low-memory mode (the idle color starts with 1 worker below 700 MB available) is needed, not optional.
- Figures from this 32 CPU machine transfer to the 2 vCPU server reasonably well. glibc allows up to 8 malloc
  arenas per CPU (256 here, 16 on the server), yet limiting them to 2 saved only about 10 MiB per worker. Setting
  `MALLOC_ARENA_MAX=2` in `roxy@.service` is a cheap 3 to 4 percent; it does not fix LOAD-2.

## Bytes per rollup row (plan 6.6)

From `tests/integration/test_metrics_rowsize.py`, which writes 24 hours of minute rollups at the plan's worst case
(400 active dimension combinations a minute, 576,000 rows) through the real write path, compacts the day into
hours, and reads page usage from SQLite's `dbstat`:

| Table | Rows | Bytes per row | Plan 6.6 estimate |
|---|---|---|---|
| `rollup_minute` | 576,000 | 71.4 (table 51.0 plus index 20.4) | 250 (71 percent less) |
| `rollup_hour` | 9,600 | 105.4 | |
| Histogram blobs (in the rows above) | | latency 8.7, queue wait 2.0 on average | |

One day at 400 combinations a minute is 41 MB of minute rows; 14 days of minute retention is 0.58 GB. The dimension
table for 400 combinations is 112 KiB. Run with `-s` to print the figures:
`.venv/bin/python -m pytest -q -s tests/integration/test_metrics_rowsize.py`.

## Dashboard pages (plan 6.7: first render under 300 ms, a 90 day chart under 500 ms)

Measured on 2026-10-10 by the latency lane (P11) with `tests/load/pages.py`, on the development machine of "The
machine" above (WSL 2, load average about 1 to 1.8 at the start of the final runs), not on the production plan size. The
Roxy measured is the working tree on top of 94ca1c3 with this lane's changes. This section replaces the "Dashboard
first render" row of "Plan 6.7 targets at a glance", which was written before the pages existed. Production is a 2
vCPU burstable instance whose cores are slower than this machine's: read the pinned columns (`@0-1`: gunicorn held to
2 CPUs with `taskset`) as the closer estimate, and expect the server itself to be slower still.

A second pass on 2026-10-11 (the P11 gaps lane) fixed the misses the first one left; "Second pass" below has its
before and after numbers on a freshly seeded template, and "Against the targets" and "Still open" are the state after
it. "Results", "Before and after" and "What was slow" are the first pass.

### Running it again (quiet machine)

From a clean export of the release commit, all four runs (about 20 minutes on this machine: the seeding takes about 3
minutes, then each run 3 to 4 minutes, most of it copying the 1.4 GB metrics database and the 20 rounds):

```sh
cd ~/Projects/RobloxProxyServer
rel=$(git rev-parse --short HEAD); out=/tmp/roxy-pages-$rel; rm -rf "$out"; mkdir -p "$out/tree"
git archive HEAD | tar -x -C "$out/tree"
cd tests
env -u ROXY_ENV PYTHONPATH="$PWD" ../.venv/bin/python -m load.pages --tree "$out/tree" --work "$out/work" --keep \
  --rounds 20 --rounds-90d 3 --runs quiet,quiet@0-1,load@0-1,load --json "$out/pages.json" | tee "$out/pages.txt"
```

`--keep` keeps the seeded template in `$out/work/template`; `--reuse-template` measures again on it without seeding
(for example after a code change, with `--runs quiet@0-1`). Every run migrates its copy with `python -m
roxy.storage.migrate --expand` first, as a deploy's prestart does, so a template seeded by an older release still
starts; the time is printed ("expand migrations of the copy"). The harness's own checks run in seconds:
`.venv/bin/python -m pytest -q tests/load/test_pages_units.py tests/unit/metrics/test_metrics_dashboard_latency.py`.

### What the scenario does

**The data.** One day of 500,000 requests (the answer mix of the steady scenario on a day and night curve, 2,000
game server addresses, 150 places) goes through the real `MetricsRecorder` on a fake clock, so the minute rollups,
client tables, events, samples and 429 rows are what the recorder writes. SQL copies then stretch that day over each
retention: 14 days of minute rollups (3 days of client minutes), hours, days and months over 90 days of history,
compacted by the real `rollups.compact_all` and pruned by the real retention tasks. The events table stops near 2
million rows, plan 6.6's cap. The control data goes through the real writers: 80,000 audit rows over 400 days (240 of
them settings changes made through `SettingsService`), 30 health runs with every check, and 22 recommendations. A 60 s
warm phase at 100 requests a second through the proxy leaves live rows and cache entries; before each run the 3,000
cache entries are moved to the run's time.

| Table or file | Rows or size |
|---|---|
| `rollup_minute`, `rollup_hour` | 1,724,548 and 618,390 |
| `rollup_day`, `rollup_month`, `dims` | 28,250, 942 and 314 |
| `client_minute`, `client_hour`, `client_day` | 3,048,777, 2,476,373 and 103,230 |
| `events` | 1,972,675 |
| `request_samples`, `refusal_samples`, `upstream_429` | 471,330, 28,164 and 20,970 |
| `audit_log` | 80,011 |
| Files | metrics.db 1,391 MiB, control.db 19.6 MiB, hot.db 2.3 MiB, cache.db 0.7 MiB |

The seeded day: 224,021 answers from the cache, 226,842 from Roblox, 28,670 refused, 20,467 failed, 233 Roblox 429s,
5,978 credential probes and 34 sign-ins.

**The server** is started as in "Method": gunicorn with `RoxyUvicornWorker`, 2 workers, `ROXY_WORKERS=2`, inside
`unshare -rn`, plus `ROXY_LOG_LEVEL=debug`, so that each request's `http_request` log line (server time, time to first
byte, bytes, worker pid) can be joined to the client's request by `Roxy-Request-Id`. The `@0-1` runs start gunicorn
under `taskset -c 0,1`. The `load` runs add the steady scenario's mixed proxy traffic at 200 requests a second from
spawned client processes while the pages are read (201.1 answered a second in both, every answer a 200).

**The browser.** An admin signs in through the real steps (password, then TOTP), then each round loads every page
in turn and, for each page, every card fragment the page names (`data-card-src`, eager and lazy, with `HX-Request`
and `HX-Target` as htmx sends them), one request after another. Connections are not kept alive, so both workers
answer (the leader answered 1,211 to 1,256 of the 2,466 requests of each run). 20 rounds at each page's default
range, then 3 rounds at `range=90d` of every page and of 20 chart series routes, at the granularity the UI asks for
(automatic) and at `granularity=hour`.

**What is reported.** Server time per page and per fragment (p50 and p95 over the rounds), the first load after the
start, the whole view (the page plus every fragment, server time summed: what one visit costs the server), HTML bytes
as sent (pages are not compressed, because of BREACH) and first-paint bytes (the HTML plus the gzipped render-blocking
stylesheets). "First render" is read as the server time of the page request: each page renders its eager cards
inline and fetches the lazy ones after first paint.

### Results

Page server time, p50 / p95 in ms, 20 rounds per run:

| Page | quiet | quiet@0-1 | load@0-1 | load | First load (quiet) | HTML | First paint |
|---|---|---|---|---|---|---|---|
| Overview | 126 / 172 | 121 / 169 | 158 / 215 | 152 / 390 | 374 | 185 KiB | 218 KiB |
| Traffic | 84 / 93 | 84 / 93 | 118 / 136 | 110 / 354 | 97 | 194 KiB | 226 KiB |
| Upstream | 60 / 62 | 59 / 75 | 77 / 118 | 64 / 139 | 60 | 395 KiB | 426 KiB |
| Cache | 53 / 57 | 53 / 62 | 69 / 94 | 72 / 2,584 | 55 | 159 KiB | 191 KiB |
| Clients | 261 / 268 | 261 / 269 | 281 / 313 | 270 / 407 | 264 | 159 KiB | 191 KiB |
| Protection | 21 / 34 | 21 / 22 | 28 / 32 | 26 / 31 | 21 | 118 KiB | 153 KiB |
| Live | 5 / 6 | 5 / 6 | 7 / 12 | 7 / 10 | 5 | 126 KiB | 157 KiB |
| Security | 20 / 23 | 19 / 24 | 23 / 29 | 26 / 66 | 21 | 192 KiB | 224 KiB |
| Settings | 11 / 12 | 11 / 18 | 13 / 27 | 13 / 16 | 12 | 243 KiB | 276 KiB |
| Audit | 13 / 14 | 12 / 13 | 14 / 18 | 15 / 19 | 14 | 128 KiB | 159 KiB |

The stylesheets every page loads before first paint are 122,702 bytes (33,431 gzipped); the module scripts load
after it, 593,633 bytes (209,096 gzipped) in 27 files.

Whole view, page plus every fragment, server time summed, p50 / p95 in ms:

| Page | quiet | quiet@0-1 | load@0-1 | load | Slowest fragment (load@0-1) |
|---|---|---|---|---|---|
| Overview (9 fragments) | 489 / 542 | 480 / 540 | 578 / 764 | 562 / 904 | top endpoints 111 / 158 |
| Traffic (7) | 686 / 713 | 685 / 715 | 837 / 1,164 | 872 / 1,875 | trends 179 / 280 |
| Upstream (15) | 404 / 420 | 400 / 431 | 461 / 614 | 462 / 835 | latency 88 / 126 |
| Cache (10) | 301 / 317 | 294 / 310 | 392 / 466 | 428 / 5,512 | ratios 89 / 105 |
| Clients (5) | 736 / 820 | 738 / 749 | 804 / 967 | 805 / 2,340 | places 268 / 334 |
| Protection (27) | 700 / 747 | 697 / 740 | 683 / 890 | 692 / 1,196 | refusals 441 / 584 |
| Live (2) | 10 / 11 | 10 / 15 | 15 / 27 | 16 / 22 | capture 3 / 8 |
| Security (11) | 66 / 74 | 64 / 81 | 76 / 102 | 83 / 199 | probes 13 / 17 |
| Settings (5) | 33 / 36 | 32 / 43 | 43 / 55 | 41 / 78 | editor 9 / 15 |
| Audit (1) | 24 / 25 | 23 / 24 | 27 / 33 | 28 / 49 | log 12 / 14 |

Fragments over 300 ms at p95: quiet, the Clients places card (303) and the Protection refusals card (430);
quiet@0-1, the refusals card (402); load@0-1, places (334) and refusals (584); load, refusals (766), the Clients
addresses table (1,313), places (352), Traffic trends (490) and three Cache cards (324 to 426).

Chart series routes over 90 days, p50 / p95 in ms, 3 rounds; "hourly" is `granularity=hour`:

| Route | quiet | quiet@0-1 | load@0-1 | load | quiet, hourly | load, hourly |
|---|---|---|---|---|---|---|
| Overview KPI tiles and sparklines | 110 / 110 | 108 / 109 | 139 / 146 | 118 / 126 | 121 / 126 | 131 / 150 |
| Overview chart | 23 / 24 | 21 / 22 | 26 / 32 | 28 / 32 | 307 / 308 | 381 / 675 |
| Traffic requests | 16 / 16 | 16 / 24 | 27 / 29 | 17 / 19 | 292 / 298 | 364 / 384 |
| Traffic status classes | 21 / 21 | 20 / 21 | 24 / 26 | 24 / 27 | 243 / 252 | 292 / 350 |
| Traffic status by source | 19 / 20 | 18 / 19 | 21 / 27 | 25 / 32 | 339 / 340 | 404 / 421 |
| Traffic verbs | 14 / 15 | 14 / 14 | 15 / 19 | 15 / 15 | 230 / 233 | 251 / 270 |
| Traffic latency | 44 / 44 | 42 / 44 | 48 / 54 | 69 / 70 | 592 / 594 | 683 / 744 |
| Traffic latency by egress | 45 / 46 | 44 / 44 | 64 / 65 | 76 / 278 | 536 / 545 | 713 / 740 |
| Traffic bytes | 85 / 87 | 81 / 85 | 91 / 98 | 109 / 110 | 354 / 365 | 413 / 446 |
| Traffic heatmap | 165 / 174 | 170 / 171 | 198 / 199 | 194 / 197 | 166 / 167 | 215 / 226 |
| Endpoint drill-down | 208 / 210 | 210 / 213 | 107 / 119 | 108 / 132 | 413 / 424 | 415 / 508 |
| Egress call share | 29 / 30 | 29 / 29 | 35 / 38 | 40 / 54 | 320 / 328 | 382 / 390 |
| Upstream latency | 26 / 26 | 25 / 26 | 32 / 33 | 32 / 33 | 377 / 382 | 503 / 517 |
| Upstream 429 timeline | 34 / 34 | 33 / 33 | 38 / 46 | 55 / 69 | 23 / 27 | 65 / 73 |
| Upstream bucket history | 4 / 4 | 4 / 4 | 5 / 16 | 9 / 25 | 5 / 12 | 14 / 24 |
| Cache KPI tiles and sparklines | 79 / 80 | 78 / 78 | 101 / 102 | 93 / 102 | 86 / 89 | 106 / 113 |
| Cache hit and avoided ratios | 25 / 25 | 25 / 26 | 33 / 44 | 34 / 37 | 352 / 356 | 435 / 461 |
| Cache states | 20 / 20 | 21 / 22 | 24 / 28 | 29 / 30 | 256 / 256 | 280 / 310 |
| One address's timeline | 132 / 132 | 134 / 151 | 142 / 148 | 169 / 186 | 140 / 140 | 160 / 167 |
| One place's timeline | 426 / 432 | 431 / 433 | 435 / 442 | 458 / 460 | 948 / 949 | 994 / 1,005 |

Pages at `range=90d`, p50 / p95 in ms, 3 rounds:

| Page | quiet | quiet@0-1 | load@0-1 | load | Slowest card (quiet@0-1) |
|---|---|---|---|---|---|
| Overview | 263 / 265 | 267 / 271 | 352 / 383 | 354 / 363 | visitors 174 / 175 |
| Traffic | 18 / 19 | 19 / 19 | 21 / 22 | 34 / 49 | heatmap 173 / 181 |
| Upstream | 1,093 / 1,294 | 1,096 / 1,160 | 1,181 / 1,403 | 1,208 / 1,653 | retries 1,932 / 1,944 |
| Cache | 85 / 86 | 81 / 83 | 159 / 186 | 100 / 102 | stats 80 / 82 |
| Clients | 46 / 46 | 44 / 46 | 59 / 59 | 57 / 459 | addresses 103 / 104 |
| Protection | 82 / 87 | 84 / 85 | 151 / 174 | 104 / 112 | refusals 7,343 / 7,348 |
| Live, Security, Settings, Audit (p50) | 6 to 21 | 6 to 19 | 8 to 23 | 9 to 25 | 17 ms or less |

Peak worker memory (RSS): 204 and 198 MiB quiet, 267 and 235 MiB on 2 CPUs with load, 274 and 231 MiB with load.
Every run: all 2,466 requests answered 200 and joined to their log lines, a clean stop, no traceback.

### Against the targets

After the second pass (below):

| Target (6.7) | Measured | Status |
|---|---|---|
| Dashboard page first render under 300 ms | every page at its default range 211 ms or less at p95 in all four runs (Overview the slowest: 140 ms p50 quiet, 192 / 210 on 2 CPUs with load); no fragment over 300 ms at p95 in any run; at `range=90d` every page 265 ms or less at p95 in both quiet runs and 246 ms or less with load, except Overview with load (341 / 493 on 2 CPUs, 302 / 526 unpinned); the first load after a start is 381 ms (Overview) | met on this machine at the default ranges; Overview at 90 days under load is over |
| Any chart query over 90 days under 500 ms | every route at the granularity the UI asks for: 223 ms or less at p95 in every run; every 90 day card 497 ms or less at p95 (Protection > Endpoint blocks 469 to 497, Endpoint rules 368 to 391, Refusal reasons 272 to 343) except Protection > Request filters (532 to 649 ms; the attempts tabs were not changed by the second pass, see "Still open"); at `granularity=hour`, which the UI never sends, at p95: the two Traffic latency charts in every run (573 to 759 ms), Upstream latency on 2 CPUs and with load (533 to 546 ms), the endpoint drill-down on 2 CPUs with load (714 ms) and Traffic bytes unpinned with load (523 ms) | met at the UI's granularity except one card; not met at hourly points |

The first pass (2026-10-10) measured: every page 269 ms or less at p95 quiet, Clients 313 ms with load on 2 CPUs; 90
day cards over: the Upstream page 1.1 to 1.2 s, its retries card 1.9 s, the Protection refusals card 7.3 s.

### Before and after

The first full measurement, on the same data before this lane changed anything (quiet, 5 rounds; its client kept one
connection alive, so one worker answered every request), against the quiet run above, server time p50 / p95 in ms:

| Page | Page before | Page after | Whole view before | Whole view after |
|---|---|---|---|---|
| Overview | 6,452 / 6,949 | 126 / 172 | 9,765 / 10,194 | 489 / 542 |
| Traffic | 500 / 508 | 84 / 93 | 5,998 / 6,109 | 686 / 713 |
| Upstream | 1,063 / 1,081 | 60 / 62 | 3,952 / 3,984 | 404 / 420 |
| Cache | 1,067 / 1,087 | 53 / 57 | 3,987 / 4,018 | 301 / 317 |
| Clients | 270 / 274 | 261 / 268 | 983 / 1,015 | 736 / 820 |
| Protection | 419 / 423 | 21 / 34 | 3,098 / 3,162 | 700 / 747 |
| Live, Security, Settings, Audit (p50) | 6 to 20 | 5 to 20 | 10 to 61 | 10 to 66 |

24 fragments were over 300 ms at p95 before (Traffic trends 1.9 s; most Overview, Traffic, Cache and Upstream cards
0.8 to 1.1 s); 2 are now. The 90 day chart routes were up to 486 ms at the UI's granularity (most about 130 ms; the
heatmap 2.0 s) and mostly 2.0 to 2.4 s at hourly points (Traffic bytes 3.9 s); the Upstream page at `range=90d` was
2.2 s, its retries card 9.4 s, and the refusals card 9.2 s.

The reads themselves, in one process on one connection over the seeded data, ms:

| Read | Before | After |
|---|---|---|
| Totals over 24 hours, 7, 30 and 90 days | 348, 143, 627 and 114 | 17, 16, 29 and 58 |
| A 24 hour chart by outcome, a 24 hour latency chart | 464 and 416 | 74 and 74 |
| A 90 day chart, hourly and daily points | 2,071 and 124 | 263 and 14 |
| Overview KPIs, top endpoints, outcomes | 690, 362 and 343 | 39, 16 and 14 |
| Last failure per egress, per host | 743 and 825 | 34 and 33 |
| Limit cards' reason counts, 24 hours and 90 days | 247 and 9,813 | 3.4 and 10.6 |
| Notable events, recent upstream events, 90 days | 395 and 322 | 0.3 and less than 0.1 |
| Failure log, 90 days | about 1,900 | 1,005 |
| Live tail with no live row | 112 | 0.1 |
| Peers of 25 addresses | 218 | 1.4 |
| Traffic trends (four periods) | 380 | 262 |
| Two reader threads against one, the same reads | 401 against 152 | 104 against 131 |

### What was slow, and what changed

1. **Sums read minute rows for whole hours and days.** A total over 24 hours read 1,440 minute rows per dimension
   combination. `queries.total_pieces` now reads a total (not a chart's buckets) from whole days in `rollup_day` where
   the window covers them (each row's own zone, stopping at a gap), whole hours in `rollup_hour` up to its
   watermark, and minutes only at the two ends. The sums are equal (the tests compare 15 windows); charts still read
   each level at their own granularity. Client tables still read minutes: their hourly rows keep only the top 500
   clients, so folding would change a client's sums.
2. **Every chart summed every measure.** `queries.measures_for` picks the columns a request's metrics need
   (`series` and `totals_sync(metrics=...)`), and the Traffic trends card sums only its own metrics for its four
   periods. The answers keep their shape.
3. **Histograms were merged by a Python aggregate.** `roxy_hist_sum` was called once per row. A page's reads run
   in two reader threads, and each call handed the GIL to the other thread, so two threads were 2 to 2.7 times slower
   than one. The reads now concatenate the blobs in SQLite (`group_concat(hex(...))`) and decode them once in
   `histograms.add_blob_into`. Compaction, one thread on the leader, still uses the aggregate.
4. **Event reads walked the table.** For several event types ordered by time SQLite chose the `events_at_ms` index
   and filtered up to 2 million rows; `ORDER BY +at_ms` makes it use `events_type_at` (notable events, recent
   upstream events). The newest event of each refusal reason and of each failure group is now one index lookup each
   instead of a second grouped scan (`refusal_reasons`, `failure_log`). The last failure per egress or host is read
   newest first in windows that double until every key with a failure in the rollups is found. The Protection limit
   cards count their reasons from the rollups (`queries.reason_counts`), and the Upstream retries card reads its
   returned reasons alone (`queries.returned_reasons`). The Live tail asks the type index whether any live row
   exists before it walks the table.
5. **Peers of 200 addresses were one statement.** An OR of 200 ranges cannot use the index; one indexed statement per
   address is cheaper.

The changes are in `src/roxy/metrics/queries.py`, `histograms.py`, `read_upstream.py`, `read_dashboard.py` and
`read_client_extras.py`, `src/roxy/admin/pages/upstream.py` and `protection.py`, and
`src/roxy/admin/api/traffic.py`. `tests/unit/metrics/test_metrics_dashboard_latency.py` checks that each faster read
answers what the old one did.

### Second pass: the misses fixed (gaps lane, 2026-10-11)

How it was measured: one freshly seeded template (the same volume, 1,409 MiB metrics.db), then the four runs exactly
as above (20 rounds, 3 rounds at 90 days) twice, back to back: "before" with the working tree as it was when the
lane started (metrics schema 8), "after" with the working tree at the end of the lane (schema 9; each run's copy took
8.7 to 9.8 s to migrate). The "after" tree also holds the other lanes' changes made in between (the recommendations
evaluation got cheaper in the insights lane), and the machine was busier than for the first pass (load average 3 to
7 from other work): read the before and after columns against each other, not against the first pass. The changes
are recorded in `CHANGES.md`, "P11 gaps lane: dashboard latency L1 to L5"; the raw output of the runs stayed with the
lane's working notes, outside the repository.

Pages at their default range, server time p50 / p95 in ms, before -> after:

| Page | quiet | quiet@0-1 | load@0-1 | load | HTML |
|---|---|---|---|---|---|
| Overview | 149 / 182 -> 140 / 174 | 159 / 293 -> 144 / 182 | 222 / 380 -> 192 / 210 | 215 / 297 -> 168 / 211 | 184 -> 185 KiB |
| Traffic | 98 / 128 -> 97 / 115 | 103 / 126 -> 93 / 98 | 150 / 188 -> 116 / 127 | 132 / 390 -> 120 / 147 | 194 -> 91 KiB |
| Upstream | 71 / 114 -> 62 / 73 | 79 / 116 -> 66 / 76 | 103 / 185 -> 88 / 108 | 86 / 119 -> 77 / 115 | 395 -> 130 KiB |
| Cache | 76 / 144 -> 69 / 75 | 80 / 104 -> 69 / 84 | 105 / 131 -> 90 / 108 | 106 / 744 -> 75 / 126 | 159 KiB |
| Clients | 302 / 351 -> 141 / 145 | 319 / 394 -> 140 / 172 | 361 / 484 -> 157 / 188 | 325 / 366 -> 151 / 162 | 160 KiB |
| Protection | 29 / 40 -> 26 / 29 | 32 / 39 -> 25 / 32 | 35 / 63 -> 30 / 45 | 38 / 69 -> 32 / 37 | 118 KiB |
| Settings | 13 / 17 -> 10 / 11 | 12 / 16 -> 10 / 17 | 18 / 24 -> 12 / 16 | 18 / 45 -> 13 / 24 | 243 -> 156 KiB |
| Live, Security, Audit | 6 to 21 / 8 to 32 -> 6 to 21 / 7 to 24 | 6 to 23 / 11 to 36 -> 6 to 21 / 8 to 27 | 7 to 31 / 24 to 44 -> 7 to 26 / 11 to 32 | 9 to 33 / 20 to 62 -> 7 to 29 / 18 to 45 | 126 to 192 KiB |

Pages over 300 ms at p95: 1 to 3 per run before (Clients in every run, Overview and Traffic and Cache with load), none
after. Fragments over 300 ms at p95: 2 to 5 per run before (the Protection refusals card in every run, Clients places
and addresses, Traffic cards with load), none after. Page and fragment requests over 500 ms at the default range:
before 1 / 2, 4 / 0, 8 / 12, 11 / 13 (leader / other worker in the four runs), after 0 / 0, 0 / 0, 0 / 0, 2 / 0.

The cards and routes that missed, p50 / p95 in ms (quiet, then unpinned with load), before -> after:

| Card or route | quiet | load |
|---|---|---|
| Protection > Refusal reasons, default range | 445 / 507 -> 123 / 132 | 536 / 595 -> 182 / 218 |
| Protection > Refusal reasons, 90 days | 7,647 / 8,811 -> 271 / 272 | 8,384 / 8,417 -> 327 / 329 |
| Upstream page at 90 days (eager failures card) | 1,169 / 1,335 -> 144 / 153 | 1,361 / 1,855 -> 161 / 246 |
| Upstream > Retries, 90 days | 2,042 / 2,260 -> 153 / 155 | 2,366 / 2,413 -> 161 / 165 |
| Clients > Places (the eager card, its refresh) | 297 / 345 -> 139 / 147 | 316 / 350 -> 148 / 175 |
| Clients > IP addresses, default range | 239 / 280 -> 92 / 98 | 311 / 365 -> 143 / 188 |
| One place's timeline (`/clients/places/{id}`), 90 days | 324 / 336 -> 61 / 62 | 573 / 616 -> 62 / 64 |
| The same, hourly points | 338 / 340 -> 62 / 62 | 507 / 598 -> 66 / 82 |
| One address's timeline, 90 days | 138 / 140 -> 14 / 14 | 166 / 216 -> 14 / 25 |

Whole views (a page plus every fragment, summed) after: Clients 384 / 394 ms quiet (846 / 971 before), Protection 359
/ 469 (684 / 805), Upstream 388 / 396 (460 / 635). First paint (HTML plus the gzipped stylesheets): Upstream 426 to
161 KiB, Traffic 227 to 124, Settings 276 to 189. Peak worker RSS after: 207 and 205 MiB quiet, 239 and 231 MiB with
load (241 and 196, 283 and 230 before).

The reads in one process on one connection (the reader page cache of `roxy.storage.db.PROFILES`), on the seeded data, ms (24
hours, 7 days, 90 days):

| Read | Before | After |
|---|---|---|
| Refusal reasons (Protection > Refusal reasons) | 199, 1,341, 7,406 | 31, 57, 194 |
| Returned reasons (Upstream > Retries) | 49, 351, 1,962 | 6, 29, 146 |
| Failure log (Upstream > Failures) | 26, 189, 1,097 | 26, 38, 98 |
| One place's refusals | 5.6, 37, 203 | 0.2, 1.2, 6.7 |
| IP address table, 25 rows with last seen and peers | 205, 116, 98 | 76, 107, 99 |
| Place table, 25 rows with last seen and peers | 277, 64, 41 | 127, 73, 45 |
| Live rows of an address with none left | 118 | less than 0.1 |

What was slow, and what changed:

1. **Refusal and failure cards parsed JSON of every event in the range.** Metrics migration
   `0009_dashboard_read_indexes` adds VIRTUAL generated columns on `events` (`detail_count`,
   `detail_message_source`, `detail_egress`, `detail_upstream_status`, `detail_aggregated`, `detail_ip`: the JSON
   expressions the reads used, computed when indexed, never stored, so no row is rewritten and the previous release
   keeps working) and partial indexes on the refusal and failure events. The refusal reasons, returned reasons,
   limit cards and failure log read them by index ranges and loose index scans; no JSON is parsed and no window is
   sorted. The newest status and path of a reason walked every refusal of the window when the reason was a failure
   reason (2 s per field over 90 days); it now walks only that reason's rows. Tests compare every number with the old
   reads (`tests/unit/metrics/test_metrics_event_facts.py`).
2. **Clients.** The peers of a place are an index range on the place part of a pair key (`*_pair_place`); the address
   table sums each address while walking `client_minute_ip_rows` in key order when the window holds 6 hours of minutes
   or more, instead of sorting 720,000 rows (the sums stay exact; reading hourly rows would have folded addresses
   beyond each hour's top 500, which the lead ruled out); one place's refusals and one client's live rows are index
   lookups.
3. **The leader's slow window, traced.** A DEBUG line per job run (`job_finished`) and per loop lag spike over 50 ms
   (`loop_lag_spike`), with the slow requests of an unpinned load run: the event loop was never blocked for more than
   59 ms; the recommendations evaluation took 5 to 30 s of every 30 s (timing out at 30 s three times in a row) and
   the compaction 12 to 20 s of every minute (0.5 s alone on the same data); retention (every 10 minutes) and hot.db
   pruning (0.25 to 0.9 s a minute) did not line up with the slow requests. With the evaluation switched off the
   compaction took 1.1 to 2.4 s and the leader and the other worker were alike (48 and 35 requests over 300 ms against
   112 and 15). So the leader's own Python work in its jobs (CPU and the GIL) was the cause, not long transactions,
   deletes or checkpoints. Changed: a job whose run takes longer than half its interval rests as long as it ran before
   its next start (`scheduler/jobs.py JOB_REST_FACTOR`), and the compaction no longer caps a whole day of client
   minutes every minute. In the "after" load run (with the insights lane's cheaper evaluation) the evaluation took 0.6
   to 3.2 s and the compaction 1.2 to 3.1 s, and both workers had 24 requests over 300 ms.
4. **HTML weight.** The Upstream 429 timeline and the Traffic requests chart read their series by URL after the first
   paint (their totals and tables stay rendered on the server); the Settings editor shows 10 settings a page by
   default (25, 50 and 100 one choice away).
5. **A ranged reset at every granularity.** A reset of part of an hour or a day deleted whole coarse rows that started
   in the range and kept those that started before it, so totals read from days and hours disagreed with the minutes
   (an hour of 601 requests against 305 left in its minutes in a test). The partly covered buckets are now recomputed
   from the trimmed level below (`rollups.rebuild_partial_buckets`).

The cost: the indexes take 405 MiB at this volume (metrics.db 1,391 to 1,796 MiB; `events_refusal_sources` 60,
`events_refusal_clients` 82, `events_failure_groups` 32, `events_refusal_places` 34, `client_minute_pair_place` 54,
`client_hour_pair_place` 44, `client_day_pair_place` 2, `client_minute_ip_rows` 96 MiB); `--expand` takes about 9 s
holding the metrics.db write lock (the old color's flushes wait and requeue); a metrics flush of 2 s at 200 requests a
second (160 events, 1,200 client upserts) takes 6.3 ms instead of 3.4 ms with the writer's 8 MiB cache.

### Still open

After the second pass:

- **The attempts tabs of Protection at 90 days** (Request filters 532 to 649 ms at p95, Endpoint blocks 469 to 497,
  Endpoint rules 368 to 391): `read_protection.refusal_attempts` groups one reason's refusal events by the JSON path
  (and methods and rule ids) and runs that grouping twice (a count and a page). One materialized grouping, or
  indexed `detail_path` and `detail_method` columns, would halve it or better (the metrics read model owners).
- **Overview at 90 days under load:** 341 / 493 ms with load on 2 CPUs, 302 / 526 unpinned (the visitors card and the
  KPI sparklines); quiet it is 263 / 265.
- **Hourly points over 90 days** (API only): the two Traffic latency charts 573 to 759 ms at p95, Upstream latency
  and the endpoint drill-down up to 546 and 714 ms with load. The UI never asks for them.
- **HTML weight above about 150 KiB:** Overview 185, Security 192, Cache and Clients 159 KiB (their eager KPI tiles,
  event lists and tables; the shell itself is about 80 KiB of every page). Making more cards lazy changes the
  registry and every page's tests (the page owners).
- **The recommendations evaluation's CPU** (the insights lane, its G7): 3 to 9 times its quiet cost under load before
  that lane's change; the job rest rule bounds what it can take from the leader, it does not make it cheaper.
  Resolved by that lane: one evaluation at a day's volume now takes about 0.6 s of CPU (see "The recommendations
  evaluation: one read per window" above); under load in the after run it took 0.6 to 3.2 s.
- **The harness's limits:** the seed is one day copied back, so every day has the same shape; the cache holds 3,000
  entries, not a full cache.db; the request samples cover one day. Both passes ran on the development machine, not
  the production plan size: rerun on a quiet machine (and the plan size) before release.
