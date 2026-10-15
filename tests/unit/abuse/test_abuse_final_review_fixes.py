"""Final review fixes of the abuse layer (findings abuse-1, abuse-2, abuse-3, abuse-5, abuse-15, abuse-16).

What this is
    Unit tests around the fixed behavior, next to the strict-xfail reproductions in `tests/review_final/test_abuse.py`
    (which stay as regression tests): the trusted game server mark per client, dry run applied before the game server
    conversion, the actions of SPAM-ENUM and SPAM-BUST, a client's own folded subject, the User-Agent hash a ban
    accepts, and the per-experience endpoint budget keyed by caller network.

Why it exists
    The reproductions pin the reported failure; these pin the edges of each fix (a game server whose offending request
    lacked the signature, the rate detector switched off, a ban made from the "no User-Agent" fingerprint key, the
    `place_limit_key` opt-out) so a later change cannot quietly undo them.

How it works
    `SpamDetectors` over the root conftest's temporary databases with catalog defaults plus overrides
    (`abuse_support.FakeSettings`), a real `RulesService` so a wrong ban would really be created, and `AbusePipeline`
    from the abuse conftest for the endpoint rules.

What to read next
    `roxy/abuse/spam.py`, `roxy/rules/models.py normalize_ua_hash`, `roxy/abuse/endpoint_rules.py`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import pytest
from abuse_support import ADMIN, FakeReq, FakeSettings

from roxy.abuse.bans import ua_hash
from roxy.abuse.endpoint_rules import endpoint_limit
from roxy.abuse.pipeline import AbusePipeline, Allow
from roxy.abuse.spam import SpamDetectors
from roxy.abuse.throttle import load_strike_rows
from roxy.abuse.verdict import Refuse
from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.metrics.fingerprints import NO_USER_AGENT, row_hash
from roxy.rules.models import EndpointLimitRow, normalize_ua_hash
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot

CLIENT = "203.0.113.7"  # TEST-NET-3 documentation range, never a real system


def detectors(dbs: Any, clock: FakeClock, events: list[Any], service: RulesService, **overrides: Any) -> SpamDetectors:
    return SpamDetectors(
        FakeSettings(overrides),
        dbs.hot,
        clock,
        control_db=dbs.control,
        rules_service=service,
        events=lambda kind, severity, detail: events.append((kind, dict(detail))),
    )


def observe(spam: SpamDetectors, n: int, *, ip: str = CLIENT, **kwargs: Any) -> None:
    base: dict[str, Any] = {
        "limit_key": ip,
        "place_id": None,
        "template": "games.roblox.com/v1/games",
        "path": "/v1/games",
        "query": [],
        "user_agent": "Roblox/Linux",
        "refused": False,
        "probe": False,
        "auth": False,
        "game_server": False,
        "bypass": False,
    }
    base.update(kwargs)
    for _ in range(n):
        spam.observe(**base)


def ban_rows(dbs: Any) -> list[tuple[Any, ...]]:
    return dbs.control.read_sync(
        lambda conn: [tuple(r) for r in conn.execute("SELECT subject_type, subject, created_by FROM bans")]
    )


# ============================================================================================ abuse-1


async def test_a_known_game_server_is_not_banned_for_a_request_without_the_signature(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService
) -> None:
    """The mark is per client: the address showed the game server signature earlier (its SPAM-RATE row carries it),
    so probes it sends later without the signature still lead to a strike, never a ban of the shared address."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_dry_run=0)
    observe(spam, 1, game_server=True)
    await spam.flush()
    fake_clock.advance(5)
    observe(spam, 5, probe=True)  # no signature on these
    acted = await spam.flush()
    assert [d.detector for d in acted] == ["probe"]
    assert ban_rows(dbs) == []
    assert [kind for kind, _ in events] == ["spam_strike"]
    assert events[0][1]["configured_action"] == "ban"
    assert events[0][1]["game_server"] is True


async def test_the_game_server_mark_holds_with_the_rate_detector_off(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService
) -> None:
    """The mark used to live on the SPAM-RATE row only, so switching that detector off removed the protection."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_dry_run=0, spam_rate_enabled=0)
    observe(spam, 3, auth=True, game_server=True)
    await spam.flush()
    assert ban_rows(dbs) == []
    assert [kind for kind, _ in events] == ["spam_strike"]
    assert spam.flagged(CLIENT, fake_clock.now()) is not None  # the offending requests are refused instead


async def test_another_client_is_still_banned(dbs: Any, fake_clock: FakeClock, rules_service: RulesService) -> None:
    """The per-client mark never spreads: a client that never showed the signature is banned as before."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_dry_run=0)
    observe(spam, 1, ip="203.0.113.8", game_server=True)
    observe(spam, 5, probe=True)
    await spam.flush()
    assert ban_rows(dbs) == [("ip", CLIENT, "auto:spam_probe")]


# ============================================================================================ abuse-2


async def test_dry_run_logs_what_arming_would_do_to_a_game_server(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService
) -> None:
    """Dry run applies to the configured action first: a configured ban is only logged, for a game server too, and
    the event says arming would strike it (so the FILTER-COLLATERAL preview can list it)."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_rate_threshold=1.0)
    observe(spam, 121, game_server=True)
    await spam.flush()
    assert [kind for kind, _ in events] == ["spam_would_ban"]
    detail = events[0][1]
    assert (detail["game_server"], detail["when_armed"], detail["configured_action"]) == (True, "strike", "ban")
    strikes = await dbs.hot.read(lambda conn: load_strike_rows(conn, [CLIENT]))
    assert not strikes[CLIENT].exists
    assert spam.flagged(CLIENT, fake_clock.now()) is None


async def test_dry_run_leaves_a_configured_strike_working(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService
) -> None:
    """The `spam_dry_run` text: only `ban` is held back; strike, tarpit and recommend work normally."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_probe_action="strike")
    observe(spam, 5, probe=True)
    await spam.flush()
    assert [kind for kind, _ in events] == ["spam_strike"]
    assert spam.flagged(CLIENT, fake_clock.now()) is not None


# ============================================================================================ abuse-5


async def test_enum_strike_refuses_the_enumerating_client(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService
) -> None:
    """SPAM-ENUM's subject is `ip:<key>|<template>`: a strike goes to the client, and its flag refuses the client."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_dry_run=0, spam_enum_action="strike")
    for i in range(501):
        observe(spam, 1, path=f"/v1/users/{1000 + i}", template="users.roblox.com/v1/users/{id}")
    await spam.flush()
    assert [kind for kind, _ in events] == ["spam_strike"]
    assert events[0][1]["subject"] == f"ip:{CLIENT}|users.roblox.com/v1/users/{{id}}"
    strikes = await dbs.hot.read(lambda conn: load_strike_rows(conn, [CLIENT]))
    assert strikes[CLIENT].strikes == 1
    flag = spam.flagged(CLIENT, fake_clock.now())
    assert flag is not None
    assert flag.detector == "enum"


async def test_bust_ban_bans_the_client_address(dbs: Any, fake_clock: FakeClock, rules_service: RulesService) -> None:
    events: list[Any] = []
    spam = detectors(
        dbs,
        fake_clock,
        events,
        rules_service,
        spam_dry_run=0,
        spam_bust_action="ban",
        spam_bust_ban_minutes=30,
        spam_bust_ban_max_minutes=60,
    )
    for i in range(200):
        observe(spam, 1, query=[("t", str(i))])
    await spam.flush()
    assert ban_rows(dbs) == [("ip", CLIENT, "auto:spam_bust")]
    assert [kind for kind, _ in events] == ["spam_ban"]


async def test_dist_only_ever_recommends(dbs: Any, fake_clock: FakeClock, rules_service: RulesService) -> None:
    """SPAM-DIST's subject is a swarm of addresses with one User-Agent (Roblox game servers share theirs)."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_dry_run=0, spam_dist_action="ban")
    for i in range(60):
        observe(spam, 17, ip=f"198.51.100.{i + 1}", user_agent="DistBot/1.0")
    await spam.flush()
    assert [kind for kind, _ in events] == ["spam_detected"]
    assert ban_rows(dbs) == []


# ============================================================================================ abuse-16


async def test_a_clients_own_folded_enum_subject_is_still_evaluated(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService
) -> None:
    """Only folded subjects every client feeds are skipped; a client's own `(other)` enum subject is still one
    client, so spreading an enumeration over many templates does not hide it."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service)
    for i in range(8):  # the client's quota of distinct templates
        observe(spam, 1, path=f"/v1/items/{i}", template=f"catalog.roblox.com/v1/t{i}/{{id}}")
    for i in range(501):  # 501 more templates, folded into `(other)`, 501 distinct ids
        observe(spam, 1, path=f"/v1/items/{5000 + i}", template=f"catalog.roblox.com/v1/x{i}/{{id}}")
    await spam.flush()
    subjects = [detail["subject"] for kind, detail in events if detail["detector"] == "SPAM-ENUM"]
    assert subjects == [f"ip:{CLIENT}|(other)"]


# ============================================================================================ abuse-3


@pytest.mark.parametrize("agent", ["python-requests/2.31.0", "Roblox/Linux", "Mozilla/5.0 (X11; Linux x86_64)"])
def test_every_hash_form_names_the_same_user_agent(agent: str) -> None:
    full = hashlib.sha256(agent.encode()).hexdigest()
    assert normalize_ua_hash(ua_hash(agent)) == ua_hash(agent)
    assert normalize_ua_hash(row_hash(agent)) == ua_hash(agent)  # the Security page's fingerprint key
    assert normalize_ua_hash(full) == ua_hash(agent)
    assert normalize_ua_hash(f"  {full.upper()} ") == ua_hash(agent)


def test_the_no_user_agent_fingerprint_key_bans_requests_without_one() -> None:
    assert normalize_ua_hash(row_hash(NO_USER_AGENT)) == ua_hash("")


@pytest.mark.parametrize(
    "text", ["ab" * 7 + "a", "ab" * 8 + "a", "ab" * 15 + "a", "ab" * 20, "ab" * 32 + "a", "g" * 16]
)
def test_a_hash_that_could_never_match_is_refused(text: str) -> None:
    with pytest.raises(ValueError, match="User-Agent hash"):
        normalize_ua_hash(text)


async def test_a_ban_made_from_the_fingerprint_key_matches_the_user_agent(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService, snapshot_of: Callable[[], RulesSnapshot]
) -> None:
    agent = "python-requests/2.31.0"
    await rules_service.create("bans", {"subject_type": "ua_hash", "subject": row_hash(agent)}, ADMIN)
    snapshot = snapshot_of()
    assert snapshot.bans.match(ip=None, place=None, ua_hash=ua_hash(agent), now=fake_clock.now()) is not None
    assert snapshot.bans.match(ip=None, place=None, ua_hash=ua_hash("Roblox/Linux"), now=fake_clock.now()) is None


# ============================================================================================ abuse-15


def _rule(scope: str) -> EndpointLimitRow:
    return EndpointLimitRow(id=7, pattern="games.roblox.com/v1/games", type="glob", scope=scope, limit=2, period=60)


def test_a_place_budget_is_keyed_by_caller_network_when_given() -> None:
    keyed = endpoint_limit(
        _rule("place"), limit_key=CLIENT, place_id="1818", allowed_per_ip=10, place_network="203.0.113.0/24"
    )
    assert keyed == ("ep:7|place:1818|203.0.113.0/24", 2, 60)
    assert endpoint_limit(_rule("place"), limit_key=CLIENT, place_id="1818", allowed_per_ip=10)[0] == "ep:7|place:1818"
    per_ip = endpoint_limit(_rule("ip"), limit_key=CLIENT, place_id="1818", allowed_per_ip=10, place_network="x")
    assert per_ip[0] == f"ep:7|{CLIENT}"  # the network only ever keys the place scope


async def _place_rule_pipeline(
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
    overrides: dict[str, Any],
) -> AbusePipeline:
    await rules_service.create(
        "rules_endpoint_limit",
        {"pattern": "games.roblox.com/v1/games", "limit": 2, "period": 60, "scope": "place"},
        ADMIN,
        "per experience budget",
    )
    return make_pipeline(overrides, rules=snapshot_of())


async def test_one_network_shares_its_place_budget(
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    pipeline = await _place_rule_pipeline(rules_service, snapshot_of, make_pipeline, {})
    for last in (9, 10):
        ip = f"198.51.100.{last}"
        assert isinstance(await pipeline.evaluate(FakeReq(ip, ip, place_id="1818")), Allow)
    third = await pipeline.evaluate(FakeReq("198.51.100.11", "198.51.100.11", place_id="1818"))
    assert isinstance(third, Refuse)
    assert third.reason == ReasonCode.ENDPOINT_RULE
    other = await pipeline.evaluate(FakeReq("203.0.113.50", "203.0.113.50", place_id="1818"))
    assert isinstance(other, Allow)  # another network keeps its own share


async def test_place_limit_key_place_keys_on_the_claim_alone(
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    """The owner's opt-out (`place_limit_key = place`, marked high risk) shares one budget per place id."""
    pipeline = await _place_rule_pipeline(rules_service, snapshot_of, make_pipeline, {"place_limit_key": "place"})
    for _ in range(2):
        assert isinstance(await pipeline.evaluate(FakeReq("198.51.100.9", "198.51.100.9", place_id="1818")), Allow)
    verdict = await pipeline.evaluate(FakeReq("203.0.113.50", "203.0.113.50", place_id="1818"))
    assert isinstance(verdict, Refuse)
    assert verdict.reason == ReasonCode.ENDPOINT_RULE
