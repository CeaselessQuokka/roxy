"""Load tests for Roxy v2 (plan 19.4, 6.7 and 19.10 row 7): a harness that drives real gunicorn workers.

What this is
    A small load harness written in Python with httpx and asyncio, plus one acceptance test that CI can run:
    - `mock_roblox.py`: a local asyncio server that plays every Roblox host, with per-endpoint rate limits that
      answer 429 like Roblox does, configurable latency, and a log of every call.
    - `traffic.py`: traffic profiles. The v1-like endpoint mix (synthetic, shaped like v1's traffic; no real data),
      Zipf key popularity, client address pools, and the request plans the scenarios send.
    - `fleet.py`: fake credentials, the temporary state, a gunicorn master started exactly like production
      (`deploy/gunicorn.conf.py`, `roxy.worker.RoxyUvicornWorker`, 2 workers), resource sampling (RSS and CPU per
      worker) and reading Roxy's own metrics after the stop.
    - `client.py`: an open-loop load generator (requests leave on schedule whatever the answers do), spread over
      several processes when one process cannot keep the rate, started together at a barrier.
    - `clock.py`: the harness clock, the one time line the client, the mock and Roxy's own buckets share (the
      wall clock, never stepping back; on WSL 2 CLOCK_MONOTONIC runs 9.5 percent fast, so it cannot be that).
    - `scenarios.py`: the five scenarios (steady mixed traffic, cold cache burst, a 429ing endpoint, a flood, and
      the replay of the v1-like profile) and the numbers each one reports.
    - `harness.py`: the command line (`python -m load.harness`, run from `tests/`), which runs scenarios inside a
      private network namespace and prints a results table.
    - `test_replay_profile.py`: plan 19.10 row 7 (second half) as a normal pytest test, marked `load`; the only
      test here that starts gunicorn (about 4 minutes). `test_load_units.py` checks the harness's own parts in a
      couple of seconds. The other scenarios are run by the command, never by pytest.

Why it exists
    Plan 19.4 asks for load tests "with locust or k6". This harness uses neither, on purpose: both are new
    dependencies (k6 is not even Python), and neither can start gunicorn, the mock Roblox and the temporary state in
    one private network namespace, read Roxy's own metrics database afterwards, or sample each worker's memory.
    httpx and asyncio are already dependencies, so the harness adds nothing to the lock file. The cost: one Python
    process makes a few hundred requests a second at most, so the harness fans out over several client processes,
    and its latency figures include the client's own scheduling delay (see `client.py`). Recorded in CHANGES.md as
    a deviation.

How it works
    Every run happens inside `unshare -rn` (a user and network namespace with nothing but loopback), so nothing
    the app does can reach a real system (plan 19.12): Roblox requests go to the mock through the
    development-only `ROXY_TEST_UPSTREAM_BASE` override, and no name is ever resolved by real DNS.

What to read next
    `harness.py` (how a run is put together), then `scenarios.py`, then docs/PERFORMANCE.md (the method and the
    results).
"""
