"""Scheduler: leader election, the job registry, and worker heartbeats.

What this is
    `leader.py` elects exactly one leader across every worker of both colors, `jobs.py` runs registered jobs on
    their intervals (leader-only or on every worker), and `heartbeat.py` publishes each worker's vital signs for
    the fleet view.

Why it exists
    Plan 5.6 and C6: scheduled work (rollups, retention, probes, digests) must run once for the whole fleet, not
    once per worker, and must survive any worker dying.

How it works
    See each module. Everything shared goes through hot.db (leases, job idempotency keys) or metrics.db
    (heartbeats), never through process memory.

What to read next
    `roxy/scheduler/leader.py`.
"""
