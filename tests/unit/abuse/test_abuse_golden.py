"""Golden refusals: every check's exact status, body bytes and headers (plan 4.1 rows 7 and 8, 19.2).

Texts are v1's byte for byte (`.remake/v1notes/pipeline.md` section 18), except the C5 dash replacement of the
default rung 1 message. Every refusal carries `Roxy-Refusal`, except that disguised refusals carry exactly what a
genuine throttle refusal carries (`Roxy-Refusal: throttle`).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from abuse_support import ADMIN, CLIENT_IP, FakeReq, wire

from roxy.abuse import pause, throttle_all
from roxy.abuse.bans import ua_hash
from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.verdict import Allow, Refuse
from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.rules.service import RulesService

RUNG1 = "Too many requests; please slow down."
RUNG2 = "You are about to be severely throttled. Please respect the proxy's limits."
TRIO_FRESH = {"Roxy-Requests-Left": "10", "Roxy-Throttle-Reset": "0", "Roxy-Throttled": "False"}

pytestmark = pytest.mark.usefixtures("seeded")


async def refuse(pipeline: AbusePipeline, req: FakeReq | None = None) -> Refuse:
    verdict = await pipeline.evaluate(req or FakeReq())
    assert isinstance(verdict, Refuse), verdict
    return verdict


async def allow(pipeline: AbusePipeline, req: FakeReq | None = None) -> Allow:
    verdict = await pipeline.evaluate(req or FakeReq())
    assert isinstance(verdict, Allow), verdict
    return verdict


@pytest.fixture
def pipeline_with(
    make_pipeline: Callable[..., AbusePipeline], snapshot_of: Callable[[], Any]
) -> Callable[..., AbusePipeline]:
    """A pipeline over the seeded rules (default ladder) plus whatever the test created."""

    def build(overrides: dict[str, Any] | None = None, **kwargs: Any) -> AbusePipeline:
        return make_pipeline(overrides, rules=snapshot_of(), **kwargs)

    return build


# --- allow ------------------------------------------------------------------------------------------------------------


async def test_allow_carries_the_per_ip_trio(pipeline_with: Callable[..., AbusePipeline]) -> None:
    pipeline = pipeline_with()
    first = await allow(pipeline)
    assert first.headers == {"Roxy-Requests-Left": "9", "Roxy-Throttle-Reset": "5", "Roxy-Throttled": "False"}
    assert first.serve_throttled_from_cache is False


# --- 1 pause ----------------------------------------------------------------------------------------------------------


async def test_pause_default(pipeline_with: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock) -> None:
    await pause.set_pause(dbs.control, fake_clock, ADMIN, paused=True)
    pipeline = pipeline_with()
    pipeline.switches.reload_sync()
    refusal = await refuse(pipeline)
    assert refusal.status == 503
    assert refusal.encoded_body() == wire("Service down for maintenance.")
    assert refusal.encoded_body() == b'"Service down for maintenance."\n'
    assert refusal.headers == {
        **TRIO_FRESH,
        "Roxy-Paused": "True",
        "Retry-After": "60",
        "Roxy-Refusal": "paused",
    }
    assert refusal.reason is ReasonCode.PAUSED
    assert refusal.tarpit_category is None
    assert refusal.message_source == "default"


async def test_pause_reason_and_scheduled_window(
    pipeline_with: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock
) -> None:
    now = int(fake_clock.now())
    await pause.schedule_pause(dbs.control, fake_clock, ADMIN, start=now - 10, end=now + 300, reason="Upgrading")
    pipeline = pipeline_with()
    pipeline.switches.reload_sync()
    refusal = await refuse(pipeline)
    assert refusal.body == "Upgrading"
    assert refusal.message_source == "custom"
    assert refusal.headers["Retry-After"] == "300"


async def test_pause_skips_shared_state_entirely(
    pipeline_with: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock
) -> None:
    await pause.set_pause(dbs.control, fake_clock, ADMIN, paused=True, reason="Back soon")
    pipeline = pipeline_with()
    pipeline.switches.reload_sync()
    for _ in range(30):
        assert (await refuse(pipeline)).body == "Back soon"
    rows = dbs.hot.read_sync(lambda conn: conn.execute("SELECT count(*) FROM limiter").fetchone()[0])
    assert rows == 0  # a paused request never takes the write lock


# --- 2 bans and deny list ---------------------------------------------------------------------------------------------


async def test_ban_disguised_as_throttle(
    pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService, fake_clock: FakeClock
) -> None:
    await rules_service.create("bans", {"subject_type": "ip", "subject": CLIENT_IP, "reason_text": "test"}, ADMIN)
    pipeline = pipeline_with()
    refusal = await refuse(pipeline)
    assert refusal.status == 429
    assert refusal.body == RUNG1
    assert refusal.headers == {
        "Retry-After": "50",
        "Roxy-Requests-Left": "0",
        "Roxy-Throttle-Reset": "50",
        "Roxy-Throttled": "True",
        "Roxy-Refusal": "throttle",
    }
    assert refusal.reason is ReasonCode.BANNED
    assert refusal.disguised
    assert refusal.tarpit_category == "ban"
    assert len(pipeline.ban_hits) == 1


async def test_ban_not_disguised(pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService) -> None:
    await rules_service.create("bans", {"subject_type": "ua_hash", "subject": ua_hash("BadBot/1.0")}, ADMIN)
    pipeline = pipeline_with({"ban_disguise_as_throttle": 0})
    req = FakeReq().with_headers([("User-Agent", "BadBot/1.0")])
    refusal = await refuse(pipeline, req)
    assert refusal.status == 403
    assert refusal.encoded_body() == b'"Access denied."\n'
    assert refusal.headers == {**TRIO_FRESH, "Roxy-Refusal": "banned"}
    assert not refusal.disguised


async def test_deny_list(pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService) -> None:
    await rules_service.create("access_list", {"kind": "deny", "cidr": "203.0.113.0/24"}, ADMIN)
    pipeline = pipeline_with({"ban_disguise_as_throttle": 0})
    refusal = await refuse(pipeline)
    assert refusal.reason is ReasonCode.DENY_LIST
    assert refusal.headers["Roxy-Refusal"] == "deny_list"
    assert refusal.detail == "Deny list 203.0.113.0/24"


async def test_ban_beats_bypass(pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService) -> None:
    await rules_service.create("access_list", {"kind": "bypass", "cidr": CLIENT_IP}, ADMIN)
    await rules_service.create("bans", {"subject_type": "ip", "subject": CLIENT_IP}, ADMIN)
    assert (await refuse(pipeline_with())).reason is ReasonCode.BANNED


# --- 3 bypass ---------------------------------------------------------------------------------------------------------


async def test_bypass_skips_limits_and_is_never_counted(
    pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService, dbs: Any
) -> None:
    await rules_service.create("access_list", {"kind": "bypass", "cidr": "203.0.113.0/24"}, ADMIN)
    pipeline = pipeline_with()
    for _ in range(50):
        req = FakeReq()
        verdict = await allow(pipeline, req)
        assert req.bypass
        assert verdict.headers == TRIO_FRESH  # v1: allowed, 0, False for bypass entries
    rows = dbs.hot.read_sync(lambda conn: conn.execute("SELECT count(*) FROM limiter").fetchone()[0])
    assert rows == 0


async def test_bypass_does_not_skip_filters(
    pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService
) -> None:
    await rules_service.create("access_list", {"kind": "bypass", "cidr": CLIENT_IP}, ADMIN)
    pipeline = pipeline_with()
    refusal = await refuse(pipeline, FakeReq(target_problem=ReasonCode.NOT_ROBLOX, raw_path="example.com/x"))
    assert refusal.reason is ReasonCode.NOT_ROBLOX
    assert refusal.headers["Roxy-Requests-Left"] == "10"


# --- 4 flood ----------------------------------------------------------------------------------------------------------


async def test_flood(pipeline_with: Callable[..., AbusePipeline]) -> None:
    pipeline = pipeline_with({"flood_limit_per_minute": 10, "allowed_requests_per_minute": 1000})
    for _ in range(10):
        await allow(pipeline)
    refusal = await refuse(pipeline)
    assert refusal.status == 429
    assert refusal.body == "You are sending requests too fast; try again in 6 seconds."
    assert refusal.headers["Retry-After"] == "6"
    assert refusal.headers["Roxy-Refusal"] == "flood"
    assert refusal.reason is ReasonCode.FLOOD


# --- 5 spam -----------------------------------------------------------------------------------------------------------


async def test_spam_flag_refuses_disguised(pipeline_with: Callable[..., AbusePipeline], fake_clock: FakeClock) -> None:
    from roxy.abuse.spam import Flag

    pipeline = pipeline_with()
    pipeline.spam._flags[f"ip:{CLIENT_IP}"] = Flag("refused", f"ip:{CLIENT_IP}", "tarpit", fake_clock.now() + 10, True)
    refusal = await refuse(pipeline)
    assert refusal.reason is ReasonCode.SPAM
    assert refusal.body == RUNG1
    assert refusal.headers["Roxy-Refusal"] == "throttle"
    assert refusal.tarpit_category == "spam"
    assert refusal.detail == "Spam detector SPAM-REFUSED"


# --- 6 throttle-all ---------------------------------------------------------------------------------------------------


async def test_throttle_all_default_text_and_headers(
    pipeline_with: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock
) -> None:
    state = await throttle_all.set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True)
    assert state.since == fake_clock.now()
    pipeline = pipeline_with()
    pipeline.switches.reload_sync()
    await allow(pipeline)
    refusal = await refuse(pipeline)
    assert refusal.status == 429
    assert refusal.encoded_body() == b'"Service down for maintenance."\n'  # v1 B6, kept
    assert refusal.headers == {
        "Roxy-Requests-Left": "9",  # the per-IP value (v1 B7)
        "Roxy-Throttle-Reset": "60",
        "Roxy-Throttled": "False",
        "Roxy-Global-Throttled": "True",
        "Retry-After": "60",
        "Roxy-Refusal": "throttle_all",
    }
    assert refusal.tarpit_category == "throttle_all"
    assert refusal.detail == "Global limit 1 per 60s"


# --- 7 per-IP throttle ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["gcra", "fixed"])
async def test_per_ip_throttle(pipeline_with: Callable[..., AbusePipeline], mode: str) -> None:
    pipeline = pipeline_with({"throttle_window_mode": mode})
    for _ in range(10):
        await allow(pipeline)
    refusal = await refuse(pipeline)
    assert refusal.status == 429
    assert refusal.encoded_body() == b'"Too many requests; please slow down."\n'
    assert refusal.headers == {
        "Roxy-Requests-Left": "0",
        "Roxy-Throttle-Reset": "50",
        "Roxy-Throttled": "True",
        "Retry-After": "50",
        "Roxy-Refusal": "throttle",
    }
    assert refusal.tarpit_category == "throttle"
    assert refusal.detail == "Per-IP limit 10 per 50s"
    assert refusal.penalty_retry_after_s == 50
    assert refusal.message_source == "custom"


async def test_per_ip_throttle_second_rung(pipeline_with: Callable[..., AbusePipeline], fake_clock: FakeClock) -> None:
    pipeline = pipeline_with({"throttle_window_mode": "fixed"})
    for _ in range(11):
        await pipeline.evaluate(FakeReq())
    fake_clock.advance(51)
    for _ in range(10):
        await allow(pipeline)
    refusal = await refuse(pipeline)
    assert refusal.body == RUNG2
    assert refusal.headers["Retry-After"] == "100"


async def test_per_ip_fallback_text_without_a_ladder(make_pipeline: Callable[..., AbusePipeline]) -> None:
    pipeline = make_pipeline()  # empty rules: no ladder
    for _ in range(10):
        await allow(pipeline)
    refusal = await refuse(pipeline)
    assert refusal.body == "You have been throttled; try again in 50 seconds (you get ~10 requests per ~minute)."
    assert refusal.message_source == "default"


async def test_throttled_cache_serve_flag(pipeline_with: Callable[..., AbusePipeline]) -> None:
    pipeline = pipeline_with({"cache_serve_throttled": 1, "throttle_count_cache_hits": 1})
    for _ in range(10):
        await allow(pipeline, FakeReq(fresh_cache_hit=True))
    refusal = await refuse(pipeline, FakeReq(fresh_cache_hit=True))
    assert refusal.allow_fresh_cache_serve


async def test_fresh_cache_hits_are_not_counted_by_default(pipeline_with: Callable[..., AbusePipeline]) -> None:
    pipeline = pipeline_with()
    for _ in range(40):
        await allow(pipeline, FakeReq(fresh_cache_hit=True))  # D10
    first = await allow(pipeline)
    assert first.headers["Roxy-Requests-Left"] == "9"


# --- 8 place limit ----------------------------------------------------------------------------------------------------


async def test_place_limit(pipeline_with: Callable[..., AbusePipeline]) -> None:
    pipeline = pipeline_with(
        {"place_limit_enabled": 1, "place_limit_per_minute": 2, "allowed_requests_per_minute": 1000}
    )
    for _ in range(2):
        await allow(pipeline, FakeReq(place_id="1818"))
    refusal = await refuse(pipeline, FakeReq(place_id="1818"))
    assert refusal.status == 429
    assert refusal.body == "This experience is over its request limit; try again in 30 seconds."
    assert refusal.headers["Roxy-Refusal"] == "place_limit"
    # place_prefix (default): another network has its own budget for the same claimed place.
    other = FakeReq(place_id="1818", client_ip="198.51.100.9", limit_key="198.51.100.9")
    await allow(pipeline, other)


# --- 9 and 10 challenge and bot score ---------------------------------------------------------------------------------


async def test_bot_score_block(pipeline_with: Callable[..., AbusePipeline]) -> None:
    pipeline = pipeline_with({"bot_score_block_threshold": 30})
    req = FakeReq().with_headers([("User-Agent", "python-requests/2.31")])
    refusal = await refuse(pipeline, req)
    assert refusal.status == 403
    assert refusal.body == "Access denied."
    assert refusal.headers["Roxy-Refusal"] == "bot_score"


async def test_challenge_page_for_browsers(pipeline_with: Callable[..., AbusePipeline]) -> None:
    pipeline = pipeline_with({"challenge_enabled": 1, "challenge_trigger_score": 10}, ip_hash_key=b"k" * 32)
    req = FakeReq(is_browser=True, csp_nonce="n0nce").with_headers([("User-Agent", "Mozilla/5.0 curl/8")])
    refusal = await refuse(pipeline, req)
    assert refusal.status == 403
    assert refusal.reason is ReasonCode.CHALLENGE
    assert refusal.content_type.startswith("text/html")
    assert 'nonce="n0nce"' in refusal.body
    assert refusal.encoded_body().startswith(b"<!doctype html>")
    # Not a browser: never challenged.
    await allow(pipeline, FakeReq(is_browser=False).with_headers([("User-Agent", "Mozilla/5.0 curl/8")]))


# --- 11 User-Agent rules ----------------------------------------------------------------------------------------------


async def test_ua_burst_rule(pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService) -> None:
    await rules_service.create(
        "rules_user_agent", {"needle": "scraper", "kind": "burst", "limit": 2, "period": 60}, ADMIN
    )
    pipeline = pipeline_with()

    def req() -> FakeReq:
        return FakeReq().with_headers([("User-Agent", "MyScraper/1")])

    await allow(pipeline, req())
    await allow(pipeline, req())
    refusal = await refuse(pipeline, req())
    assert refusal.status == 429
    assert refusal.body == "This client is limited to 2 requests per 60s. Try again in 60 seconds."
    assert refusal.headers == {
        "Roxy-Requests-Left": "8",
        "Roxy-Throttle-Reset": "60",
        "Roxy-Throttled": "True",
        "Retry-After": "60",
        "Roxy-Client-Limited": "True",
        "Roxy-Refusal": "user_agent_rule",
    }
    assert refusal.tarpit_category == "user_agent_rule"
    assert refusal.detail == "User-Agent rule: scraper"
    assert pipeline.stats.snapshot()["ua_rule_hits"]


async def test_ua_cooldown_rule_and_custom_message(
    pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService
) -> None:
    await rules_service.create("rules_user_agent", {"needle": "slowbot", "kind": "cooldown", "cooldown": 2}, ADMIN)
    pipeline = pipeline_with()

    def req() -> FakeReq:
        return FakeReq().with_headers([("User-Agent", "SlowBot")])

    await allow(pipeline, req())
    refusal = await refuse(pipeline, req())
    assert refusal.body == "This client is limited to one request every 2.0s. Try again in 2 seconds."
    await rules_service.create(
        "rules_user_agent", {"needle": "loud", "kind": "cooldown", "cooldown": 5, "message": "Go away"}, ADMIN
    )
    pipeline = pipeline_with()

    def loud() -> FakeReq:
        return FakeReq().with_headers([("User-Agent", "LoudClient")])

    await allow(pipeline, loud())
    custom = await refuse(pipeline, loud())
    assert custom.body == "Go away"
    assert custom.message_source == "custom"


async def test_ua_rules_master_switch(pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService) -> None:
    await rules_service.create("rules_user_agent", {"needle": "x", "kind": "cooldown", "cooldown": 60}, ADMIN)
    pipeline = pipeline_with({"user_agent_rules_enabled": 0})
    for _ in range(3):
        await allow(pipeline, FakeReq().with_headers([("User-Agent", "x")]))


# --- 12 to 14 ignored path, probes ------------------------------------------------------------------------------------


async def test_ignored_path(pipeline_with: Callable[..., AbusePipeline]) -> None:
    refusal = await refuse(pipeline_with(), FakeReq(raw_path=".well-known/appspecific/com.chrome.devtools.json"))
    assert refusal.status == 404
    assert refusal.encoded_body() == b'"Not Found"\n'
    assert refusal.headers == {**{**TRIO_FRESH, "Roxy-Requests-Left": "10"}, "Roxy-Refusal": "ignored_path"}
    assert refusal.tarpit_category is None


async def test_unsafe_url(pipeline_with: Callable[..., AbusePipeline]) -> None:
    refusal = await refuse(pipeline_with(), FakeReq(target_problem=ReasonCode.UNSAFE_URL))
    assert (refusal.status, refusal.encoded_body()) == (404, b'"Invalid URL"\n')
    assert refusal.tarpit_category == "probe"
    assert refusal.detail == "Invalid URL (unsafe characters)"
    assert refusal.headers["Roxy-Refusal"] == "unsafe_url"


@pytest.mark.parametrize("problem", [ReasonCode.NOT_ROBLOX, ReasonCode.HOST_NOT_ALLOWED])
async def test_not_roblox(pipeline_with: Callable[..., AbusePipeline], problem: ReasonCode) -> None:
    req = FakeReq(target_problem=problem, raw_path="evil.example.com/wp-login.php")
    refusal = await refuse(pipeline_with(), req)
    assert (refusal.status, refusal.encoded_body()) == (404, b'"Not a Roblox URL"\n')
    assert refusal.reason is problem
    assert refusal.tarpit_category == "probe"
    assert refusal.detail.endswith("evil.example.com")


async def test_throttled_client_probing_gets_429_not_404(pipeline_with: Callable[..., AbusePipeline]) -> None:
    pipeline = pipeline_with()
    for _ in range(11):
        await pipeline.evaluate(FakeReq())
    refusal = await refuse(pipeline, FakeReq(target_problem=ReasonCode.NOT_ROBLOX))
    assert refusal.status == 429
    assert refusal.reason is ReasonCode.THROTTLE


# --- 15 auth smuggling ------------------------------------------------------------------------------------------------


async def test_auth_smuggling(pipeline_with: Callable[..., AbusePipeline]) -> None:
    req = FakeReq().with_headers([("User-Agent", "Roblox/Linux"), ("X-Roblox-Token", "")])
    refusal = await refuse(pipeline_with(), req)
    assert refusal.status == 400
    assert refusal.encoded_body() == b'"Requests requiring authentication are not allowed with this proxy."\n'
    assert refusal.detail == "X-Roblox-Token header"
    assert refusal.tarpit_category == "auth_attempt"
    assert refusal.headers["Roxy-Refusal"] == "auth_smuggling"


# --- 16 header filters ------------------------------------------------------------------------------------------------


async def test_header_filter_disguised(
    pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService
) -> None:
    await rules_service.create("rules_header", {"needle": "xeno", "scope": "either"}, ADMIN)
    pipeline = pipeline_with()
    req = FakeReq().with_headers([("User-Agent", "Roblox/WinInet"), ("Xeno-Fingerprint", "4f3a91c0")])
    refusal = await refuse(pipeline, req)
    assert refusal.status == 429
    assert refusal.body == RUNG1  # byte identical to a genuine throttle refusal for a clean client
    assert refusal.headers == {
        "Retry-After": "50",
        "Roxy-Requests-Left": "0",
        "Roxy-Throttle-Reset": "50",
        "Roxy-Throttled": "True",
        "Roxy-Refusal": "throttle",
    }
    assert "xeno" not in str(refusal.headers).lower()
    assert refusal.reason is ReasonCode.HEADER_RULE
    assert refusal.disguised
    assert refusal.detail == "Filter |either|contains|xeno (matched Xeno-Fingerprint)"


async def test_header_filter_custom_message(
    pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService
) -> None:
    await rules_service.create(
        "rules_header", {"needle": "badtool", "header": "User-Agent", "message": "Not with that tool"}, ADMIN
    )
    pipeline = pipeline_with()
    refusal = await refuse(pipeline, FakeReq().with_headers([("User-Agent", "BadTool/2")]))
    assert refusal.body == "Not with that tool"
    assert refusal.headers["Roxy-Refusal"] == "header_rule"
    assert refusal.headers["Roxy-Throttle-Reset"] == "50"
    assert refusal.headers["Roxy-Throttled"] == "True"
    assert not refusal.disguised


# --- 17 endpoint blocks -----------------------------------------------------------------------------------------------


async def test_endpoint_block(pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService) -> None:
    await rules_service.create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/games"}, ADMIN)
    refusal = await refuse(pipeline_with())
    assert refusal.status == 403
    assert refusal.encoded_body() == b'"This endpoint is currently blocked."\n'
    assert refusal.headers == {**TRIO_FRESH, "Roxy-Blocked": "True", "Roxy-Refusal": "endpoint_blocked"}
    assert refusal.detail == "Block rule: games.roblox.com/v1/games"
    assert refusal.tarpit_category == "blocked_endpoint"


# --- 18 endpoint rules ------------------------------------------------------------------------------------------------


async def test_endpoint_rule(pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService) -> None:
    await rules_service.create(
        "rules_endpoint_limit", {"pattern": "games.roblox.com/v1/*", "limit": 1, "period": 60}, ADMIN
    )
    pipeline = pipeline_with()
    await allow(pipeline)
    refusal = await refuse(pipeline)
    assert refusal.status == 429
    assert refusal.body == "This endpoint is rate-limited for you; try again in 60 seconds."
    assert refusal.headers == {
        "Roxy-Requests-Left": "9",
        "Roxy-Throttle-Reset": "60",
        "Roxy-Throttled": "True",
        "Retry-After": "60",
        "Roxy-Endpoint-Limited": "True",
        "Roxy-Refusal": "endpoint_rule",
    }
    assert refusal.detail == "Rate rule: games.roblox.com/v1/*"


async def test_endpoint_rule_is_clamped_to_the_per_ip_allowance(
    pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService, fake_clock: FakeClock
) -> None:
    await rules_service.create(
        "rules_endpoint_limit", {"pattern": "games.roblox.com", "limit": 50, "period": 60}, ADMIN
    )
    pipeline = pipeline_with({"allowed_requests_per_minute": 3, "throttle_reset_duration": 1})
    for _ in range(3):
        await allow(pipeline)
        fake_clock.advance(1)  # the per-IP allowance (3 per second) refills; the rule's 60 s window does not
    assert (await refuse(pipeline)).reason is ReasonCode.ENDPOINT_RULE  # v1: limit 50 clamped to 3


async def test_global_endpoint_rule_is_shared(
    pipeline_with: Callable[..., AbusePipeline], rules_service: RulesService
) -> None:
    await rules_service.create(
        "rules_endpoint_limit", {"pattern": "games.roblox.com", "limit": 2, "period": 60, "scope": "global"}, ADMIN
    )
    pipeline = pipeline_with()
    await allow(pipeline, FakeReq(client_ip="198.51.100.1", limit_key="198.51.100.1"))
    await allow(pipeline, FakeReq(client_ip="198.51.100.2", limit_key="198.51.100.2"))
    refusal = await refuse(pipeline, FakeReq(client_ip="198.51.100.3", limit_key="198.51.100.3"))
    assert refusal.reason is ReasonCode.ENDPOINT_RULE
