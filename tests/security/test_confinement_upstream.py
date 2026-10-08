"""The upstream service under random states never routes a caller to the credential off the allowlist.

What this is
    A seeded randomized probe of `UpstreamService.fetch` (plan 19.5 item 6, at the service level rather than the
    pure `routing.decide` level): random methods, targets, allowlist rows (methods, `cache_private`,
    `identical_anonymous`), routing rules, weights, `fallback_on_429`, retry counts, credential states (active,
    unknown, rejected, cooling down), and a random answer for every attempt (2xx, a redirect to an allowlisted or
    other URL, a CSRF challenge, 429, 5xx, timeouts, connect errors, egress refusals, leak guard and smuggling
    refusals). After each fetch, every call the service handed to the egress is checked.

Why it exists
    `decide` is proven in isolation by the unit property test. The service adds retries, reroutes after an egress
    refusal, `fallback_on_429`, CSRF retries, redirect hops and probes; each of those builds a new outbound request,
    and each is a place where the credential could be chosen, or a header added, without passing `decide` again.

How it works
    Uses the upstream unit fakes (`tests/unit/upstream/upstream_fakes.py`, loaded by path): `FakeEgress` records
    `(egress, OutboundRequest)` for every send. Invariants per fetch:
      1. a credential send is a GET or HEAD whose URL matches an allowlist row for the caller's method;
      2. a credential send never uses Roxy's probe purpose (which would skip the "active" requirement);
      3. no send of any egress carries a `Cookie` header added by the upstream layer;
      4. an allowlisted request (credential-eligible, without `identical_anonymous`) never goes out anonymously.
    Each case has its own fake clock far from the previous one and clears cooldowns and breakers first, so the
    shared buckets never starve later cases.

What to read next
    `src/roxy/upstream/service.py` (`_run`, `_route`, `_exchange_and_record`, `_redirect_url`),
    `src/roxy/upstream/routing.py`, and `tests/unit/upstream/test_upstream_routing.py`.
"""

from __future__ import annotations

import random
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from confinement_harness import load_fixture

from roxy.core.reasons import Egress
from roxy.upstream.egress_port import PURPOSE_CREDENTIAL_PROBE
from roxy.upstream.queue import Priority
from roxy.upstream.routing import CREDENTIAL_METHODS

fakes = load_fixture("upstream_fakes", "unit/upstream")

ALLOWLISTED = "economy.roblox.com/v1/user/currency"
TARGETS = (
    ("economy.roblox.com", "/v1/user/currency"),
    ("economy.roblox.com", "/V1/User/Currency"),
    ("economy.roblox.com", "/v1/user/currency/"),
    ("economy.roblox.com", "/v1/user/currencies"),
    ("economy.roblox.com", "/v2/user/currency"),
    ("games.roblox.com", "/v1/user/currency"),
    ("games.roblox.com", "/v1/games"),
)
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
LOCATIONS = (
    "https://economy.roblox.com/v1/user/currency",
    "https://economy.roblox.com/v2/elsewhere",
    "https://games.roblox.com/v1/games",
    "/v1/user/currency",
    "/v1/other",
    "https://evil.example.com/x",
)
ROUTING_PATTERNS = ("economy.roblox.com", ALLOWLISTED, "games.roblox.com/v1/games")
ROUTING_MODES = ("prefer_direct", "prefer_rotator", "direct_only", "rotator_only")
CASES = 400


def answer_for(rng: random.Random) -> Any:
    """One random attempt outcome: a response or an exception named like the egress contract's."""
    roll = rng.random()
    if roll < 0.30:
        return fakes.answer(200)
    if roll < 0.42:
        return fakes.answer(302, b"", {"location": rng.choice(LOCATIONS)})
    if roll < 0.50:
        return fakes.answer(403, b"{}", {"x-csrf-token": "tok-probe"})
    if roll < 0.60:
        return fakes.answer(429, b"{}", {"retry-after": str(rng.choice([1, 5, 30]))})
    if roll < 0.70:
        return fakes.answer(rng.choice([500, 502, 503]))
    if roll < 0.76:
        return fakes.UpstreamTimeout("probe")
    if roll < 0.82:
        return fakes.UpstreamConnectError("probe")
    if roll < 0.88:
        return fakes.EgressDisabled("probe")
    if roll < 0.92:
        return fakes.AuthSmugglingBlocked("probe")
    if roll < 0.95:
        return fakes.CredentialLeakBlocked("probe")
    return fakes.answer(404, b"{}")


async def test_random_states_never_route_a_caller_to_the_credential_off_the_allowlist(dbs: Any) -> None:
    rng = random.Random(20261007)
    tally: Counter[str] = Counter()
    for case in range(CASES):
        clock = fakes.SteppingClock(start=1_760_000_000.0 + case * 7200)
        settings = fakes.FakeSettings(
            fallback_on_429=rng.choice([0, 1]),
            direct_weight=rng.choice([0, 100]),
            rotator_weight=rng.choice([0, 50, 100]),
            upstream_max_attempts=rng.choice([1, 2, 3]),
            backoff_base_ms=1,
            backoff_cap_ms=2,
        )
        rules = fakes.FakeRules()
        listed = rng.random() < 0.7
        identical = listed and rng.random() < 0.3
        if listed:
            rules.allow_credential(
                ALLOWLISTED,
                cache_private=rng.random() < 0.5,
                identical_anonymous=identical,
                methods=rng.choice(["GET", "HEAD", "GET,HEAD"]),
            )
        for _ in range(rng.randint(0, 2)):
            pattern = rng.choice(ROUTING_PATTERNS)
            if all(row.pattern != pattern for row in rules.routing_rows):
                rules.route(pattern, rng.choice(ROUTING_MODES))
        egress = fakes.FakeEgress(lambda kind, out: answer_for(rng))
        egress.credential.status_value = rng.choice(["active", "active", "active", "unknown", "rejected"])
        egress.credential.cooldown = rng.choice([0.0, 0.0, 0.0, 30.0])
        egress.disabled = set(rng.sample([Egress.DIRECT, Egress.ROTATOR, Egress.CREDENTIAL], rng.randint(0, 1)))
        ctx = fakes.make_ctx(dbs, clock, egress, settings=settings, rules=rules, worker_id=f"case-{case}")
        service = fakes.make_service(ctx, seed=case)
        await service.reset_state()
        # Biased toward GET and HEAD on the allowlisted endpoint's spellings, so the credential path is exercised
        # often enough for invariants 1, 2 and 4 to mean something.
        method = rng.choice((*METHODS, "GET", "GET", "HEAD", "HEAD"))
        host, path = rng.choice((*TARGETS, *TARGETS[:3], *TARGETS[:3]))
        body = b'{"a":1}' if method in ("POST", "PUT", "PATCH", "DELETE") else b""
        req = fakes.request(service, method=method, host=host, path=path, body=body, query=[])
        result = await service.fetch(req, priority=Priority.INTERACTIVE, stale_available=rng.random() < 0.3)
        tally[result.reason.value] += 1
        snapshot = rules.snapshot
        eligible = method in CREDENTIAL_METHODS and snapshot.credential_rule_for(f"{host}{path}", method) is not None
        for used, out in egress.calls:
            tally[f"sent:{used.value}"] += 1
            assert "cookie" not in {name.lower() for name in out.headers}, (case, used, out.headers)
            if used is not Egress.CREDENTIAL:
                continue
            parts = urlsplit(out.url)
            target = f"{(parts.hostname or '').lower()}{parts.path or '/'}"
            assert out.method in CREDENTIAL_METHODS, (case, out.method)
            assert snapshot.credential_rule_for(target, method) is not None, (case, out.url)
            assert out.purpose != PURPOSE_CREDENTIAL_PROBE, (case, out.purpose)
        if eligible and not identical:
            anonymous = [used for used, _ in egress.calls if used is not Egress.CREDENTIAL]
            assert anonymous == [], (case, method, host, path, anonymous)
        if not eligible:
            assert Egress.CREDENTIAL not in egress.egresses(), (case, method, host, path)
    # The battery reached the interesting places (otherwise the invariants above are vacuous).
    assert tally["sent:credential"] > 20
    assert tally["sent:direct"] > 50
    assert tally["sent:rotator"] > 20
    assert tally["upstream_ok"] > 20
