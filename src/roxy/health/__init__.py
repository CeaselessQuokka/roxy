"""Check Proxy Health (plan 13): one button that checks every part of Roxy and says what to fix.

What this is
    The package behind the Check Proxy Health button and the scheduled health runs: the 13.2 checks
    (`checks.py`), the 13.4 probe URLs (`probes.py`), the run engine (`runner.py`), run history and comparisons
    (`store.py`), the JSON, printable HTML and "Copy run for LLM" reports (`report.py`), and the replaceable
    seams to the outside world (`facts.py`: DNS, TLS, subprocesses, the public origin, alert channels, files).

Why it exists
    v1 had a single "health" endpoint that said up or down. Plan 13 asks for a checklist an owner can act on:
    every result has a status, the measured value, the threshold it was judged against, a paragraph that explains
    what the check means, and a link to the page or runbook that fixes it. Runs are stored, compared with the run
    before, exported, and repeated on a schedule that alerts on new failures.

How it works
    `runner.HealthRunner` expands the check catalog (one H-REACH check per allowed Roblox host), runs the checks
    with bounded concurrency (4) and a timeout each, writes each result to metrics.db `health_results` together
    with an `events` row (the SSE stream picks it up), and finishes the run with a summary. Upstream checks call
    Roblox through `UpstreamService.internal_fetch` at internal priority, so they pay their way in the buckets;
    the credential check uses only the credential path and is skipped in scheduled runs unless
    `health_auto_include_credential` is 1.

What to read next
    `roxy/health/model.py`, then `roxy/health/checks.py` and `roxy/health/runner.py`.
"""
