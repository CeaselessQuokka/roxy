"""Roxy v2: a Roblox web API proxy that is safe for its operator, kind to Roblox, and fully observable.

What this is
    The top-level package. Everything Roxy runs lives below it: `core` (clocks, ids, logging, redaction, the HTTP
    middleware), `config` (environment, the settings catalog and the live settings store), `storage` (the four
    SQLite databases, migrations, leases, the batch writer, retention), `rules` (admin rules and the shared
    matcher), `scheduler` (heartbeats, leader election, scheduled jobs), and the feature packages added phase by
    phase (egress, upstream, cache, abuse, metrics, admin, public pages).

Why it exists
    v1 was a handful of large Flask modules that created their state at import time. v2 splits the same features
    into small modules with one job each, every one opening with a docstring like this one, so the code can be
    read in order and each piece tested alone (plan principle P7).

How it works
    gunicorn imports `roxy.asgi:app`, which `roxy.main.create_app` builds; `roxy.lifespan` then opens the
    databases, loads settings and rules, and starts the background loops, once per worker process. Nothing heavy
    happens at import time.

What to read next
    `roxy/main.py` (how a request travels through the app), `roxy/lifespan.py` (what a worker does at startup),
    then `roxy/core/__init__.py`. The full guided reading order (plan 18.5) is written in the last phase.
"""

__version__ = "2.0.0"
