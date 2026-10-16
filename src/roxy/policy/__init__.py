"""The endpoint policy: which Roblox endpoints callers may use, and which of them carry Roxy's credential.

What this is
    A package of three modules. `seed` loads the reviewed list of every documented Roblox operation that ships with
    Roxy (`endpoint_policy_seed.json`, 992 rows from Roblox's own API reference, each with a verdict). `matcher`
    turns a request's host, method and path into the one seed row it belongs to. `engine` combines the seed with
    the admin's overrides and category switches (control.db, loaded into the rules snapshot) into one
    `PolicyDecision` per request: `BLOCK` (refused before Roblox), `ALLOW_TOKEN` (sent with the credential) or
    `ALLOW_ANON` (sent, never with the credential).

Why it exists
    Owner decision D1, revised on 2026-10-16: Roxy sends its own Roblox account with every request except
    endpoints that act on an account, read its private data, or touch sign-in and security flows. Those are
    refused entirely, so no caller can use Roxy's account against itself. `docs/endpoint_policy/BRIEF.md` is the
    design; `docs/endpoint_policy/DOMAIN_ANALYSIS.md` explains the verdicts.

How it works
    `RulesSnapshot.endpoint_policy` (built when the rules reload) answers `decide(host, method, path, query)`. The
    abuse check `endpoint_policy` refuses BLOCK verdicts; `RulesSnapshot.credential_rule_for` gives the upstream
    and the cache a credential grant only for ALLOW_TOKEN verdicts.

What to read next
    `roxy/policy/seed.py`, `roxy/policy/matcher.py`, then `roxy/policy/engine.py`.
"""

from __future__ import annotations

from roxy.policy.engine import CREDENTIAL_METHODS, EndpointPolicy, PolicyDecision
from roxy.policy.seed import CATEGORIES, Verdict, load_seed

__all__ = ["CATEGORIES", "CREDENTIAL_METHODS", "EndpointPolicy", "PolicyDecision", "Verdict", "load_seed"]
