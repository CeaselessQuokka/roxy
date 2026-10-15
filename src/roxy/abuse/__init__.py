"""Abuse protection: every check that can refuse a proxy request before Roxy spends anything on it.

What this is
    The package behind plan section 10: an ordered pipeline of checks (pause, bans and the deny list, bypass, the
    flood limit, spam detectors, throttle-all, the per-IP throttle with its strike ladder, the per-place limit,
    challenge and bot score, User-Agent rules, ignored paths, probes, auth smuggling, header filters, endpoint
    blocks and endpoint rate rules), plus the tarpit that slows refused abusers down.

Why it exists
    v1 spread these checks through one 300-line request handler, counted the per-IP limit in a separate step after
    the check (so one extra request always slipped through) and kept every counter in JSON files that failed open
    on disk trouble. Here each check is a small object with a name and a position, every limiter is evaluated in ONE
    hot.db transaction per request (plan 6.3), and losing shared state degrades to conservative per-worker limits
    instead of no limits at all (plan C7).

How it works
    `pipeline.py` builds the ordered list of `checks/*` objects and runs them for each request, returning `Allow` or
    `Refuse` (`verdict.py`). Pure decision logic lives in the modules beside it: `limiter.py` (GCRA and fixed window
    math), `throttle.py` (strikes and the ladder), `throttle_all.py` and `pause.py` (admin switches kept in
    control.db), `bans.py`, `bypass.py`, `spam.py`, `bot.py`, `challenge.py`, `tarpit.py`, and the rule families
    (`blocks.py`, `endpoint_rules.py`, `ua_rules.py`, `header_rules.py`). `messages.py` holds every caller-facing
    text.

What to read next
    `roxy/abuse/verdict.py` (what a check returns), then `roxy/abuse/pipeline.py` (the order and the single
    transaction), then `roxy/abuse/limiter.py` (the rate limiting math).
"""
