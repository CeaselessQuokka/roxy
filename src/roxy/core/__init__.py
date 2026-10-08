"""Core helpers shared by every other package: clocks, ids, logging, redaction, client IPs and the HTTP middleware.

What this is
    The bottom layer of Roxy: `clock.py` (real and fake time), `ids.py` (request ids), `redact.py` and
    `logging.py` (secrets never reach a log line), `client_ip.py` and `iphash.py` (who is calling), `reasons.py`
    (the closed set of refusal and outcome codes), `tasks.py` (supervised background tasks), and the middleware
    stack (`middleware.py`, `errors.py`, `deadline.py`, `security_headers.py`).

Why it exists
    Every feature needs these, and they must behave the same everywhere: one redaction rule set, one way to find
    the real client IP, one request deadline. Keeping them in one package with no upward imports means they can be
    read first and tested alone.

How it works
    Nothing in `roxy.core` imports from the feature packages (storage, egress, upstream, cache, abuse, admin). The
    middleware reads live settings through `scope.py`, which only needs an object with `settings.get(key)`, so
    the stack works in tests without databases.

What to read next
    `clock.py` and `ids.py`, then `redact.py` and `logging.py`, then `middleware.py` to see how one request travels
    through the app before it reaches a router.
"""
