"""Admin rules: blocks, endpoint and cache rules, User-Agent and header rules, routing, bans and access lists.

What this is
    The package that owns every admin-authored rule table in `control.db` and the code that matches requests
    against them.

Why it exists
    v1 kept each rule family in its own dict inside `runtime.py`, each with a slightly different copy of the same
    matching loop. v2 has one shared matcher (`match.py`, plan 4.8 row 111), one immutable snapshot of every rule
    table per worker (`store.py`, reloaded when `config_version` changes), and one audited write path
    (`service.py`), so a rule cannot behave differently in the request path and in the dashboard's tester.

How it works
    Writes go through `service.py`, which validates patterns with `match.validate_pattern`, writes the row and an
    audit entry, and bumps `config_version` in one transaction. Every worker notices the new version within a
    second and rebuilds its `RulesSnapshot`, compiling patterns into `match.PatternIndex` objects once, so the hot
    path only runs precompiled regexes.

What to read next
    `roxy/rules/match.py` (the matching semantics), then `roxy/rules/store.py` and `roxy/rules/service.py`.
"""
