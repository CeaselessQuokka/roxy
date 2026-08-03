"""Gunicorn configuration for Roxy.

Lives with the app (move_files/UpdateBuild deploy this directory), so the
worker count and timeouts are versioned alongside the code that assumes them.

Referenced by Tooling/roxy.service.
"""

import multiprocessing
import os

bind = os.environ.get("ROXY_BIND", "127.0.0.1:8000")

# Sized to RAM, not to CPU. Every worker holds its own copy of the diagnostics
# state, so the CPU-count default (2*cores+1) can multiply memory use well past
# what a small instance has. Four is plenty for a proxy that spends its time
# waiting on Roblox; raise it only alongside MemoryMax in the unit file.
workers = int(os.environ.get("ROXY_WORKERS", "4"))

# Threads, not more processes, for the extra concurrency: the work is almost
# entirely waiting on an upstream socket, and threads share one copy of the
# state rather than adding another.
threads = int(os.environ.get("ROXY_THREADS", "4"))
worker_class = "gthread"

# Longer than the upstream request timeout plus its retries, so a slow Roblox
# response can never look like a hung worker and get the worker killed
# mid-request. Keep this above config.REQUEST_TIMEOUT * MAX_METHOD_ATTEMPTS.
timeout = 90
graceful_timeout = 30
keepalive = 5

# Recycle workers periodically. Every store is capped now, but this bounds the
# blast radius of any slow leak that has not been found yet -- including ones in
# dependencies. The jitter stops all four workers recycling at the same moment.
max_requests = 2000
max_requests_jitter = 200

# Do NOT preload. Each worker starts its own autosave thread and its own shared
# -file handles at import; preloading would fork them from the master and give
# every worker a copy of the parent's timers.
preload_app = False

accesslog = os.environ.get("ROXY_ACCESS_LOG", "-")
errorlog = "-"
loglevel = os.environ.get("ROXY_LOG_LEVEL", "info")
# Log the real client IP that ProxyFix resolved, not nginx's loopback address.
access_log_format = '%({x-forwarded-for}i)s %(h)s "%(r)s" %(s)s %(b)s %(M)sms "%(a)s"'

proc_name = "roxy"
