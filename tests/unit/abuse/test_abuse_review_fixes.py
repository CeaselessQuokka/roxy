"""The wave 2 review fixes in the abuse pipeline: what each finding demanded, pinned with the real pipeline.

What this is
    Tests for the pause and throttle-all default text (spec R1), disguised refusals that carry the client's real
    rung and penalty (spec R5), bypass known before bans refuse, the throttled cache serve that never reaches a
    filtered request, the cheap limiters running before admin regexes (with the single write transaction kept), the
    degraded walk starting from the shared rows, the metrics events (`record_throttled`, `ua_rule_hit`,
    `throttle_tier`) and the catalog defaults behind settings missing from a snapshot (spec F10).

Why it exists
    R1 and R5 lived in `.remake/scripts/review_repro/test_spec_repro.py` outside the suite; the other findings are
    proven end to end in `tests/security` and `tests/multiprocess`. These tests pin each mechanism at the unit level,
    including the race paths that are hard to provoke from outside.

How it works
    `make_pipeline` builds a real `AbusePipeline` over the test's temporary databases (`tests/unit/abuse/conftest.py`);
    rules are created through the real `RulesService` or as snapshots built from row models.

What to read next
    `roxy/abuse/pipeline.py` (module docstring steps 0 to 5), `roxy/abuse/checks/base.py` (`redisguise`).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import pytest
from abuse_support import ADMIN, CLIENT_IP, FakeReq, FakeSettings

from roxy.abuse import pause, throttle_all
from roxy.abuse.pipeline import TIER_EVENT, UA_RULE_HIT_EVENT, AbusePipeline, slow_patterns
from roxy.abuse.spam import SpamDetectors
from roxy.abuse.tarpit import Tarpit
from roxy.abuse.throttle import StrikeRow, save_strike_rows
from roxy.abuse.verdict import Allow, Refuse
from roxy.config.defaults import THROTTLE_TIERS
from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.rules.models import HeaderRuleRow, UserAgentRuleRow
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot
from roxy.storage.db import SharedStateUnavailable


async def refuse(pipeline: AbusePipeline, req: FakeReq | None = None) -> Refuse:
    verdict = await pipeline.evaluate(req or FakeReq())
    assert isinstance(verdict, Refuse), verdict
    return verdict


async def allow(pipeline: AbusePipeline, req: FakeReq | None = None) -> Allow:
    verdict = await pipeline.evaluate(req or FakeReq())
    assert isinstance(verdict, Allow), verdict
    return verdict


def snapshot(**families: Any) -> RulesSnapshot:
    return RulesSnapshot(version=1, loaded_at=0.0, **families)


REGEX_FILTER = HeaderRuleRow(id=7, canonical_key="|value|regex|tool", scope="value", mode="regex", needle="^tool.*")
"""A header filter of type regex: the kind that makes the pipeline run the cheap limiters first."""


# --- R1: the pause default is the live `pause_message_default` setting (plan 7.13, 15.3 K) ----------------------------


async def test_r1_pause_message_default_setting_is_used(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock
) -> None:
    """Plan 7.13 Paused row and 15.3 K: the pause body defaults to the live `pause_message_default` setting."""
    await pause.set_pause(dbs.control, fake_clock, ADMIN, paused=True)
    pipeline = make_pipeline({"pause_message_default": "Back at 5 pm."})
    pipeline.switches.reload_sync()
    refusal = await refuse(pipeline)
    assert refusal.status == 503
    assert refusal.body == "Back at 5 pm."
    assert refusal.message_source == "default"
    pipeline.settings.values["pause_message_default"] = "   "  # an empty setting never sends an empty body
    assert (await refuse(pipeline)).body == "Service down for maintenance."


async def test_r1_throttle_all_without_a_reason_shares_the_pause_default(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock
) -> None:
    """v1 used one downtime constant for both (v1 notes B6/B13); the live setting replaces that constant."""
    await throttle_all.set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True)
    pipeline = make_pipeline({"pause_message_default": "Back at 5 pm."})
    pipeline.switches.reload_sync()
    await allow(pipeline)
    refusal = await refuse(pipeline)
    assert refusal.reason is ReasonCode.THROTTLE_ALL
    assert refusal.body == "Back at 5 pm."
    assert refusal.message_source == "default"


# --- R5: disguised refusals carry exactly what a genuine throttle refusal would, right now ----------------------------


async def test_r5_disguised_ban_uses_the_clients_real_rung(
    make_pipeline: Callable[..., AbusePipeline],
    snapshot_of: Callable[[], Any],
    rules_service: RulesService,
    dbs: Any,
    fake_clock: FakeClock,
    seeded: Any,
) -> None:
    """Plan 10.5 and DESIGN 11.9: a client already on rung 3 gets the rung 3 text from a genuine throttle (and from a
    disguised header filter), so a disguised ban must say the same."""
    now = int(fake_clock.now())
    dbs.hot.write_sync(lambda conn: save_strike_rows(conn, [StrikeRow(CLIENT_IP, 3, now, 3, 0, True)]))
    ban = {"subject_type": "ip", "subject": CLIENT_IP, "reason_text": "t"}
    await rules_service.create("bans", ban, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of())
    refusal = await refuse(pipeline)
    assert refusal.headers["Roxy-Refusal"] == "throttle"
    assert refusal.body == THROTTLE_TIERS[2].message
    assert refusal.reason is ReasonCode.BANNED


@pytest.mark.parametrize("subject", ["ban", "spam"])
async def test_disguise_matches_a_genuine_refusal_of_a_penalized_client(
    make_pipeline: Callable[..., AbusePipeline],
    snapshot_of: Callable[[], Any],
    rules_service: RulesService,
    dbs: Any,
    fake_clock: FakeClock,
    seeded: Any,
    subject: str,
) -> None:
    """A client 2 strikes deep and still penalized for 77 s: the genuine throttle refusal and the disguised ban or
    spam refusal it gets right after are byte for byte the same (body, every header)."""
    now = int(fake_clock.now())
    dbs.hot.write_sync(lambda conn: save_strike_rows(conn, [StrikeRow(CLIENT_IP, 2, now, 2, now + 77, True)]))
    genuine = await refuse(make_pipeline(rules=snapshot_of()))
    assert genuine.reason is ReasonCode.THROTTLE
    if subject == "ban":
        await rules_service.create("bans", {"subject_type": "ip", "subject": CLIENT_IP}, ADMIN)
        pipeline = make_pipeline(rules=snapshot_of())
    else:
        from roxy.abuse.spam import Flag

        pipeline = make_pipeline(rules=snapshot_of())
        pipeline.spam._flags[f"ip:{CLIENT_IP}"] = Flag("refused", f"ip:{CLIENT_IP}", "tarpit", now + 10, True)
    disguised = await refuse(pipeline)
    assert disguised.reason in (ReasonCode.BANNED, ReasonCode.SPAM)
    assert disguised.disguised
    assert disguised.body == genuine.body == THROTTLE_TIERS[1].message
    # Same headers, same values AND the same order (finding spec-1: a client reading raw headers sees the order).
    assert list(disguised.headers.items()) == list(genuine.headers.items())
    assert disguised.headers["Retry-After"] == "77"


# --- bypass is known before any check refuses (plan 10.6, DESIGN 11.1) -----------------------------------------------


async def test_bypass_is_marked_before_a_ban_refuses(
    make_pipeline: Callable[..., AbusePipeline], snapshot_of: Callable[[], Any], rules_service: RulesService
) -> None:
    await rules_service.create("access_list", {"kind": "bypass", "cidr": CLIENT_IP}, ADMIN)
    await rules_service.create("bans", {"subject_type": "ip", "subject": CLIENT_IP}, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of())
    req = FakeReq()
    refusal = await refuse(pipeline, req)
    assert refusal.reason is ReasonCode.BANNED  # the ban still wins over the bypass entry
    assert req.bypass  # but the router knows the caller is on the bypass list: never held
    assert await pipeline.tarpit.plan(refusal.tarpit_category or "ban", req, reason=refusal.detail) is None


# --- cache_serve_throttled never serves a request a later check refuses ----------------------------------------------


@pytest.mark.parametrize("regex", [False, True])
async def test_throttled_cache_serve_only_without_a_later_refusal(
    make_pipeline: Callable[..., AbusePipeline], regex: bool
) -> None:
    rule = (
        REGEX_FILTER
        if regex
        else HeaderRuleRow(id=7, canonical_key="|value|contains|tool", scope="value", mode="contains", needle="tool")
    )
    pipeline = make_pipeline(
        {"cache_serve_throttled": 1, "allowed_requests_per_minute": 1}, rules=snapshot(header_rules=(rule,))
    )
    await allow(pipeline, FakeReq(fresh_cache_hit=True))
    filtered = await refuse(pipeline, FakeReq(fresh_cache_hit=True).with_headers([("X-Client", "tool/1")]))
    assert filtered.reason is ReasonCode.THROTTLE  # v1's order: the throttle refusal is the answer
    assert filtered.allow_fresh_cache_serve is False  # but no cached content for a request the filter refuses
    clean = await refuse(pipeline, FakeReq(fresh_cache_hit=True))
    assert clean.allow_fresh_cache_serve is True  # an unfiltered throttled caller is still served from the cache


# --- cheap limiters before admin regexes, one write transaction kept ------------------------------------------------


def test_slow_patterns_are_only_regex_rules() -> None:
    contains = HeaderRuleRow(id=1, canonical_key="k", scope="value", mode="contains", needle="tool")
    ua_regex = UserAgentRuleRow(id="u", needle="^bot", mode="regex", kind="burst", limit=1, period=60)
    assert not slow_patterns(snapshot(header_rules=(contains,)))
    assert slow_patterns(snapshot(header_rules=(REGEX_FILTER,)))
    assert slow_patterns(snapshot(ua_rules=(ua_regex,)))


async def test_a_refused_caller_never_reaches_a_regex_and_each_request_writes_once(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from roxy.abuse.header_rules import match_header_rule

    matched: list[str] = []

    def spy(rules: Any, pairs: Any) -> Any:
        matched.append("x")
        return match_header_rule(rules, pairs)

    monkeypatch.setattr("roxy.abuse.checks.header_rules.match_header_rule", spy)  # the check's own reference
    pipeline = make_pipeline({"flood_limit_per_minute": 10}, rules=snapshot(header_rules=(REGEX_FILTER,)))
    writes = dbs.hot.stats.writes
    await allow(pipeline)  # admitted: the filter runs, one write
    assert (matched, dbs.hot.stats.writes - writes) == (["x"], 1)
    for _ in range(9):
        await pipeline.evaluate(FakeReq())
    matched.clear()
    writes = dbs.hot.stats.writes
    refusal = await refuse(pipeline, FakeReq().with_headers([("X-Client", "tool/1")]))
    assert refusal.reason is ReasonCode.FLOOD  # over the flood limit (10 per minute)
    assert matched == []  # the filter (an admin regex) never ran for a refused caller
    assert dbs.hot.stats.writes - writes == 1  # still one write transaction (plan 6.3)
    assert pipeline.stats.pattern_checks_skipped >= 1


async def test_without_regex_rules_there_is_no_extra_read(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any
) -> None:
    pipeline = make_pipeline()
    reads = dbs.hot.stats.reads
    await allow(pipeline)
    assert dbs.hot.stats.reads == reads


async def test_a_wrong_prediction_still_runs_every_filter(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The READ predicts a flood refusal, but the write admits (another worker moved the row): the pattern checks
    must still run before the request is let through, and the flood count is taken exactly once."""
    from roxy.abuse.limiter import LimiterRow

    pipeline = make_pipeline({"flood_limit_per_minute": 10}, rules=snapshot(header_rules=(REGEX_FILTER,)))
    real_read = pipeline._read_shared

    async def stale_read(keys: list[str], strike_keys: list[str]) -> Any:
        shared = await real_read(keys, strike_keys)
        assert shared is not None
        rows, strikes = shared
        far = pipeline.clock.now_ms() + 3_600_000
        rows = {
            key: LimiterRow(key, tat_ms=far, exists=True) if key.startswith("flood:") else row
            for key, row in rows.items()
        }
        return rows, strikes

    monkeypatch.setattr(pipeline, "_read_shared", stale_read)
    refusal = await refuse(pipeline, FakeReq().with_headers([("X-Client", "tool/1")]))
    assert refusal.reason is ReasonCode.HEADER_RULE  # the filter ran: never admitted without it
    assert isinstance(await pipeline.evaluate(FakeReq()), Allow)

    def flood_tat(conn: Any) -> int:
        return int(
            conn.execute("SELECT tat_ms FROM limiter WHERE bucket_key = ?", (f"flood:{CLIENT_IP}",)).fetchone()[0]
        )

    # Two requests counted once each: TAT is two flood intervals (6 s at 10 per 60 s) ahead of the clock.
    assert dbs.hot.read_sync(flood_tat) - pipeline.clock.now_ms() == 12_000


# --- degraded mode starts from the shared rows (C7, DEGRADED-REFILL) -------------------------------------------------


async def test_degraded_walk_starts_from_the_shared_row_and_merges_memory_on_recovery(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any
) -> None:
    pipeline = make_pipeline(workers=2)
    for _ in range(10):
        await allow(pipeline)
    real_write = dbs.hot.write

    async def locked(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "database is locked")

    dbs.hot.write = locked
    try:
        refusal = await refuse(pipeline)  # hot.db readable: the client's spent allowance carries over
        assert refusal.reason is ReasonCode.THROTTLE
        assert pipeline.degraded
    finally:
        dbs.hot.write = real_write
    assert len(pipeline._memory_strikes) == 1  # the strike earned while degraded waits for hot.db (finding mp-1)
    other = FakeReq(client_ip="198.51.100.4", limit_key="198.51.100.4")
    await allow(pipeline, other)  # a working write: degraded mode ends; the background merge writes the rest
    assert not pipeline.degraded
    assert pipeline._merge_task is not None
    await pipeline._merge_task
    await pipeline.merge_pending()  # nothing left: the background merge took every row
    assert len(pipeline._memory_rows) == 0
    assert len(pipeline._memory_strikes) == 0
    strikes = dbs.hot.read_sync(
        lambda conn: conn.execute("SELECT strikes FROM strikes WHERE ip = ?", (CLIENT_IP,)).fetchone()
    )
    assert strikes is not None
    assert int(strikes[0]) == 1  # hot.db now has the strike earned during the outage


# --- metrics events (wire report open issue) --------------------------------------------------------------------------


class EventSpy:
    def __init__(self) -> None:
        self.events: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.throttled: list[tuple[str, dict[str, Any]]] = []

    def record_event(self, *args: Any, **kwargs: Any) -> bool:
        self.events.append((args, kwargs))
        return True

    def record_throttled(self, ip: str, **kwargs: Any) -> None:
        self.throttled.append((ip, kwargs))


async def test_record_throttled_and_aggregated_tier_and_ua_rule_events(
    make_pipeline: Callable[..., AbusePipeline],
    snapshot_of: Callable[[], Any],
    rules_service: RulesService,
    seeded: Any,
) -> None:
    await rules_service.create("rules_user_agent", {"needle": "tool", "kind": "burst", "limit": 1, "period": 60}, ADMIN)
    spy = EventSpy()
    pipeline = make_pipeline({"allowed_requests_per_minute": 2}, rules=snapshot_of(), recorder=spy)
    tool = FakeReq(client_ip="198.51.100.9", limit_key="198.51.100.9").with_headers([("User-Agent", "tool/1")])
    await allow(pipeline, tool)
    await pipeline.evaluate(
        FakeReq(client_ip="198.51.100.9", limit_key="198.51.100.9").with_headers([("User-Agent", "tool/1")])
    )
    for _ in range(2):
        await allow(pipeline)
    await refuse(pipeline)  # the limit itself refuses: a new strike, rung 1, the client just became throttled
    await refuse(pipeline)  # still penalized: not "just became throttled" again
    aggregated = [(args[0], args[3], kwargs) for args, kwargs in spy.events if kwargs.get("aggregate")]
    ua_hits = [detail for kind, detail, _ in aggregated if kind == UA_RULE_HIT_EVENT]
    assert [hit["result"] for hit in ua_hits] == ["allowed", "refused"]
    assert [detail for kind, detail, _ in aggregated if kind == TIER_EVENT] == [{"tier": 1}]
    assert spy.throttled == [(CLIENT_IP, {"tier": 1, "strikes": 1})]


# --- spec F10: a setting missing from the snapshot falls back to the catalog default --------------------------------


class PartialSettings(FakeSettings):
    """A snapshot without some keys (a stale or partial snapshot): the catalog default must apply, not 0."""

    def __init__(self, missing: tuple[str, ...], overrides: Mapping[str, Any] | None = None) -> None:
        super().__init__(overrides)
        for key in missing:
            self.values.pop(key)


async def test_missing_settings_fall_back_to_the_catalog_defaults(dbs: Any, fake_clock: FakeClock) -> None:
    settings = PartialSettings(("throttle_count_cache_hits",))
    pipeline = AbusePipeline(settings=settings, rules=RulesSnapshot.empty(), hot_db=dbs.hot, clock=fake_clock)
    first = await allow(pipeline, FakeReq(fresh_cache_hit=True))
    assert first.headers["Roxy-Requests-Left"] == "9"  # the catalog default 1: cache hits count
    spam = SpamDetectors(PartialSettings(("spam_enabled",)), None, fake_clock)
    spam.observe(
        limit_key=CLIENT_IP,
        place_id=None,
        template="games.roblox.com/v1/games",
        path="/v1/games",
        query=[],
        user_agent="Roblox/Linux",
        refused=False,
        probe=False,
        auth=False,
        game_server=False,
        bypass=False,
    )
    assert spam.pending_subjects() > 0  # the catalog default 1: detectors on
    pit = Tarpit(PartialSettings(("tarpit_enabled",)), dbs.hot, fake_clock, "w1")
    assert (await pit.state())["enabled"] is True  # the catalog default 1
