"""Unit tests for `roxy/proxy/router.py`: the DESIGN.md 11.1 flow with fake abuse, cache, upstream and recorder.

What this is
    One test per branch of the request flow: served, refused, tarpit hold and drip, bypass, OPTIONS, HEAD, the
    throttled cache serve, fail-closed paths (no context, no pipeline, shared state unavailable), defense in
    depth against an invalid target the pipeline let through, and exactly one outcome record per request.

Why it exists
    The order of these steps is a security property (the SSRF guard, the tarpit never holding bypass callers, the
    cache never consulted for invalid targets) and a metrics property (one record per request, never zero, never
    two). Both are easy to break when the flow is edited.

How it works
    `proxy_app` is a Starlette app with the real middleware stack and the real proxy route, and a fake context
    whose services record every call (`tests/unit/proxy/conftest.py`). Requests go through httpx's ASGI transport.

What to read next
    `tests/integration/test_proxy_golden.py` (the same router inside the real application).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode
from roxy.proxy import respond
from roxy.storage.db import SharedStateUnavailable

GAMES = "/games.roblox.com/v1/games?universeIds=1"


async def test_served_flow(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    response = await proxy_client.get(GAMES, headers={"Roblox-Id": " 12345 ", "User-Agent": "Roblox/Linux"})
    assert response.status_code == 200
    assert response.content == b'{"data":[]}'
    assert response.headers["content-type"] == "application/json"
    assert response.headers["Roxy-Cache"] == "MISS"
    assert response.headers["Roxy-Requests-Left"] == "9"
    assert response.headers["Roxy-Throttled"] == "False"
    assert response.headers["Roxy-Upstream-Status"] == "200"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["content-security-policy"] == "default-src 'none'; sandbox"
    req = ctx.abuse.seen[0]
    assert ctx.cache.peeked == [req]
    assert ctx.cache.served == [req]
    assert req.cache_key == "key-1"
    assert req.host == "games.roblox.com"
    assert req.path == "/v1/games"
    assert req.query == [("universeIds", "1")]
    assert req.place_id == "12345"
    assert req.request_id == response.headers["Roxy-Request-Id"]
    assert req.client_ip == "127.0.0.1"
    [event] = ctx.recorder.events
    assert event.request_id == req.request_id
    assert event.outcome is Outcome.SERVED_UPSTREAM
    assert event.reason is ReasonCode.UPSTREAM_OK
    assert event.status == 200
    assert event.egress is Egress.DIRECT
    assert event.cache_state is CacheState.MISS
    assert event.method == "GET"
    assert event.place_id == "12345"
    assert event.caller_bytes_out == len(b'{"data":[]}')
    assert event.endpoint_template == "games.roblox.com/v1/games"
    assert event.latency_ms >= 0


async def test_client_ip_and_limit_key_from_trusted_forwarded_for(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    await proxy_client.get(GAMES, headers={"X-Forwarded-For": "6.6.6.6, 2001:db8:1:2:3:4:5:6"})
    req = ctx.abuse.seen[0]
    assert req.client_ip == "2001:db8:1:2:3:4:5:6"  # the rightmost hop nginx appended (plan 9.11)
    assert req.limit_key == "2001:db8:1:2::/64"


async def test_invalid_target_refused_without_cache(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    ctx.abuse.tarpit = fakes.FakeTarpit(None)
    response = await proxy_client.get("/evil.example/x")
    assert response.status_code == 404
    assert response.content == b'"Not a Roblox URL"\n'
    assert response.headers["Roxy-Refusal"] == "not_roblox"
    assert ctx.cache.peeked == []
    assert ctx.cache.served == []
    assert [category for category, _ in ctx.abuse.tarpit.asked] == ["probe"]
    [event] = ctx.recorder.events
    assert event.outcome is Outcome.REFUSED
    assert event.reason is ReasonCode.NOT_ROBLOX
    assert event.endpoint_template == "(not_roblox)"


async def test_invalid_target_allowed_by_pipeline_is_still_refused(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    """Defense in depth: the SSRF guard never depends on the pipeline's check order."""
    ctx.abuse = fakes.FakeAbuse(refuse_targets=False)
    response = await proxy_client.get("/169.254.169.254/latest/meta-data")
    assert response.status_code == 404
    assert response.content == b'"Not a Roblox URL"\n'
    assert ctx.cache.served == []
    assert len(ctx.recorder.events) == 1


async def test_no_pipeline_fails_closed(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    ctx.abuse = None
    valid = await proxy_client.get(GAMES)
    assert valid.status_code == 503
    assert valid.content == respond.UPSTREAM_BUSY_TEXT.encode()
    assert valid.headers["Retry-After"] == "10"
    assert valid.headers["Roxy-Refusal"] == "degraded"
    invalid = await proxy_client.get("/games.roblox.com/v1/%3Cscript%3E")
    assert invalid.status_code == 404
    assert invalid.content == b'"Invalid URL"\n'
    assert ctx.cache.served == []
    assert len(ctx.recorder.events) == 2


async def test_no_context_fails_closed(proxy_app: Any) -> None:
    proxy_app.state.ctx = None
    transport = httpx.ASGITransport(app=proxy_app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get(GAMES)).status_code == 503
        assert (await client.get("/not-roblox/x")).status_code == 404


async def test_shared_state_unavailable_is_degraded(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    async def broken(req: Any) -> Any:
        raise SharedStateUnavailable("hot", "database is locked")

    ctx.abuse.evaluate = broken
    response = await proxy_client.get(GAMES)
    assert response.status_code == 503
    assert response.headers["Roxy-Refusal"] == "degraded"
    assert response.headers["Retry-After"] == "10"
    [event] = ctx.recorder.events
    assert event.reason is ReasonCode.DEGRADED
    assert event.outcome is Outcome.FAILED


async def test_cache_peek_errors_are_misses(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    ctx.cache = fakes.FakeCache(peek_error=SharedStateUnavailable("cache", "disk I/O error"))
    response = await proxy_client.get(GAMES)
    assert response.status_code == 200
    assert ctx.abuse.seen[0].cache_key is None


async def test_fresh_peek_marks_request(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    ctx.cache = fakes.FakeCache(peek_result=fakes.FakePeek(key="k", fresh=object()))
    await proxy_client.get(GAMES)
    assert ctx.abuse.seen[0].fresh_cache_hit is True


async def test_tarpit_hold(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    plan = fakes.FakePlan("hold")
    ctx.abuse.tarpit = fakes.FakeTarpit(plan)
    response = await proxy_client.get("/wp-login.php")
    assert response.status_code == 404
    assert response.content == b'"Not a Roblox URL"\n'
    assert plan.waited == 1
    assert plan.released == 1
    assert len(ctx.recorder.events) == 1


async def test_tarpit_drip(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    plan = fakes.FakePlan("drip", ticks=4)
    ctx.abuse.tarpit = fakes.FakeTarpit(plan)
    response = await proxy_client.get("/wp-login.php")
    assert response.status_code == 404
    assert response.content == b'    "Not a Roblox URL"\n'
    assert response.headers["X-Accel-Buffering"] == "no"
    assert response.headers["Content-Encoding"] == "identity"
    assert plan.released == 1
    assert plan.waited == 0
    [event] = ctx.recorder.events
    assert event.caller_bytes_out == len(b'"Not a Roblox URL"\n')


async def test_bypass_is_never_held(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    plan = fakes.FakePlan("hold")
    ctx.abuse.tarpit = fakes.FakeTarpit(plan)
    original = ctx.abuse.evaluate

    async def bypassing(req: Any) -> Any:
        req.bypass = True
        return await original(req)

    ctx.abuse.evaluate = bypassing
    response = await proxy_client.get("/evil.example/x")
    assert response.status_code == 404
    assert ctx.abuse.tarpit.asked == []
    assert plan.waited == 0
    assert ctx.recorder.events[0].bypass is True


async def test_tarpit_without_shared_state_never_holds(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    class BrokenTarpit:
        async def plan(self, category: str, req: Any) -> Any:
            raise SharedStateUnavailable("hot", "locked")

    ctx.abuse.tarpit = BrokenTarpit()
    response = await proxy_client.get("/evil.example/x")
    assert response.status_code == 404  # C7: the refusal still works, the tarpit does not hold


async def test_throttled_caller_served_from_fresh_cache(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    # The pipeline grants `allow_fresh_cache_serve` only with `cache_serve_throttled` on, which also makes the
    # router peek before the verdict (it needs `fresh_cache_hit`).
    ctx.settings = fakes.FakeSettings(cache_serve_throttled=1)
    refusal = respond.Refusal(
        429,
        "Too many requests; please slow down.",
        ReasonCode.THROTTLE,
        headers={"Retry-After": 50, "Roxy-Requests-Left": 0, "Roxy-Throttle-Reset": 50, "Roxy-Throttled": True},
        tarpit_category="throttle",
        allow_fresh_cache_serve=True,
    )
    ctx.abuse = fakes.FakeAbuse(refusal, tarpit=fakes.FakeTarpit(fakes.FakePlan("hold")))
    hit = fakes.served(cache_state=CacheState.HIT, outcome=Outcome.SERVED_CACHE, cache_age_s=5, cache_ttl_s=60)
    ctx.cache = fakes.FakeCache(hit, peek_result=fakes.FakePeek(key="k", fresh=object()))
    response = await proxy_client.get(GAMES)
    assert response.status_code == 200
    assert response.headers["Roxy-Cache"] == "HIT"
    assert response.headers["Roxy-Throttled"] == "True"
    assert "Retry-After" not in response.headers
    assert "Roxy-Refusal" not in response.headers
    assert ctx.abuse.tarpit.asked == []
    [event] = ctx.recorder.events
    assert event.reason is ReasonCode.THROTTLED_CACHE


def _track_order(ctx: Any) -> list[str]:
    """Wrap the fake pipeline's `evaluate` and the fake cache's `peek` so the test sees their order."""
    order: list[str] = []
    evaluate, peek = ctx.abuse.evaluate, ctx.cache.peek

    async def tracked_evaluate(req: Any) -> Any:
        order.append("verdict")
        return await evaluate(req)

    async def tracked_peek(req: Any) -> Any:
        order.append("peek")
        return await peek(req)

    ctx.abuse.evaluate = tracked_evaluate
    ctx.cache.peek = tracked_peek
    return order


async def test_by_default_the_cache_is_peeked_only_after_an_allow(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    """With the catalog defaults (cache hits count, no throttled cache serve) no abuse check reads the cache, so the
    peek waits for the verdict: a refused caller costs no cache read and no cache rule match (plan 9.9)."""
    order = _track_order(ctx)
    response = await proxy_client.get(GAMES)
    assert response.status_code == 200
    assert order == ["verdict", "peek"]
    assert ctx.cache.served == ctx.abuse.seen
    assert ctx.abuse.seen[0].cache_key == "key-1"  # the late peek still marks the request for the outcome record

    ctx.abuse = fakes.FakeAbuse(respond.Refusal(429, "Too many requests; please slow down.", ReasonCode.THROTTLE))
    ctx.cache = fakes.FakeCache()
    order = _track_order(ctx)
    assert (await proxy_client.get(GAMES)).status_code == 429
    assert order == ["verdict"]
    assert ctx.cache.peeked == []
    assert ctx.cache.served == []


@pytest.mark.parametrize(
    "overrides", [{"throttle_count_cache_hits": 0}, {"cache_serve_throttled": 1}], ids=["hits_not_counted", "serve"]
)
async def test_the_cache_is_peeked_before_the_verdict_when_a_check_reads_it(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any, overrides: dict[str, int]
) -> None:
    """`fresh_cache_hit` matters to the per-IP throttle (hits not counted) and to the throttled cache serve: then
    the peek runs first, once, and the allowed request is served from that same peek."""
    ctx.settings = fakes.FakeSettings(**overrides)
    ctx.cache = fakes.FakeCache(peek_result=fakes.FakePeek(key="k", fresh=object()))
    order = _track_order(ctx)
    assert (await proxy_client.get(GAMES)).status_code == 200
    assert order == ["peek", "verdict"]
    assert ctx.abuse.seen[0].fresh_cache_hit is True


async def test_throttled_without_fresh_entry_is_refused(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    refusal = respond.Refusal(
        429, "Too many requests; please slow down.", ReasonCode.THROTTLE, allow_fresh_cache_serve=True
    )
    ctx.abuse = fakes.FakeAbuse(refusal)
    response = await proxy_client.get(GAMES)
    assert response.status_code == 429
    assert ctx.cache.served == []


async def test_options_answered_locally(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    response = await proxy_client.options("/games.roblox.com/v1/games")
    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["Allow"] == "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
    assert "Roxy-Request-Id" in response.headers
    assert "Roxy-Cache" not in response.headers
    assert ctx.abuse.seen == []
    assert ctx.cache.peeked == []
    odd = await proxy_client.options("/not-roblox/anything")  # never a probe, whatever the path
    assert odd.status_code == 204
    assert [event.reason for event in ctx.recorder.events] == [ReasonCode.OPTIONS_LOCAL] * 2


async def test_head_runs_as_get(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    response = await proxy_client.head(GAMES)
    assert response.status_code == 200
    assert response.content == b""
    assert response.headers["content-length"] == str(len(b'{"data":[]}'))
    req = ctx.abuse.seen[0]
    assert req.method == "GET"
    assert req.is_head is True
    [event] = ctx.recorder.events
    assert event.method == "HEAD"
    assert event.caller_bytes_out == 0


async def test_post_body_is_read(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    await proxy_client.post(
        "/users.roblox.com/v1/usernames/users",
        content=b'{"usernames":["a"]}',
        headers={"content-type": "application/json"},
    )
    req = ctx.abuse.seen[0]
    assert req.method == "POST"
    assert req.body == b'{"usernames":["a"]}'
    assert req.content_type == "application/json"
    # httpx sends `Accept: */*` by default, which is one of the two forwardable values.
    assert req.forwarded_headers() == {"accept": "*/*", "content-type": "application/json", "content-length": "19"}
    assert ctx.recorder.events[0].caller_bytes_in == 19


async def test_unhandled_error_is_recorded_once_by_the_router(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    async def broken(req: Any, peek: Any) -> Any:
        raise RuntimeError("bug")

    ctx.cache.serve = broken
    response = await proxy_client.get(GAMES)
    assert response.status_code == 500
    # The middleware owns the body (core/errors.py): v1's `jsonify("Internal Server Error")` form.
    assert response.content == b'"Internal Server Error"\n'
    assert response.headers["content-type"].split(";")[0] == "application/json"
    # The middleware answers 500; the flow writes the fallback outcome itself, exactly once (DESIGN 7).
    assert len(ctx.recorder.events) == 1
    event = ctx.recorder.events[0]
    assert (event.status, str(event.reason), str(event.outcome)) == (500, "internal_error", "failed")


async def test_recorder_failure_never_fails_the_request(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    def broken(event: Any) -> None:
        raise RuntimeError("metrics down")

    ctx.recorder.record_outcome = broken
    assert (await proxy_client.get(GAMES)).status_code == 200


async def test_upstream_used_only_without_cache(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    ctx.cache = None
    ctx.upstream = fakes.FakeUpstream()
    response = await proxy_client.get(GAMES)
    assert response.status_code == 200
    assert response.content == b'{"ok":true}'
    assert response.headers["Roxy-Cache"] == "OFF"
    [(_, kwargs)] = ctx.upstream.calls
    assert kwargs["stale_available"] is False
    assert int(kwargs["priority"]) == 0
    ctx.upstream = None
    assert (await proxy_client.get(GAMES)).status_code == 503


async def test_admin_paths_never_reach_the_proxy(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    for path in ("/admin", "/admin/", "/admin/anything"):
        response = await proxy_client.post(path)
        assert response.status_code == 404
        assert "Roxy-Refusal" not in response.headers
    assert ctx.abuse.seen == []
    assert ctx.recorder.events == []


async def test_settings_are_live(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    ctx.settings.overrides["strict_host_allowlist"] = 0
    assert (await proxy_client.get("/www.roblox.com/home")).status_code == 200
    ctx.settings.overrides["strict_host_allowlist"] = 1
    assert (await proxy_client.get("/www.roblox.com/home")).status_code == 404
    ctx.settings.overrides["allowed_roblox_hosts"] = ["www.roblox.com."]
    assert (await proxy_client.get("/www.roblox.com/home")).status_code == 200
    assert (await proxy_client.get(GAMES)).status_code == 404
    ctx.settings.overrides["compat_collapse_upstream_errors"] = 1
    ctx.cache.result = fakes.served(b'{"errors":[]}', status=404, reason=ReasonCode.UPSTREAM_4XX)
    collapsed = await proxy_client.get("/www.roblox.com/home")
    assert collapsed.status_code == 500  # the live setting reached respond: v1's collapse (lead decision on F8)
    assert collapsed.content == b'{"errors":[]}'  # with Roblox's own body, exactly as v1 sent it


async def test_methods_outside_the_list_are_405(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    response = await proxy_client.request("TRACE", GAMES)
    assert response.status_code == 405
    assert ctx.abuse.seen == []


async def test_request_extras_for_the_abuse_layer(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    """`abuse/verdict.py` reads `raw_path` (v1 dst as received), `query_string` and `csp_nonce` when present."""
    await proxy_client.get("/Games.Roblox.com//v1/games?universeIds=1&prettyprint=true")
    req = ctx.abuse.seen[0]
    assert req.raw_path == "Games.Roblox.com//v1/games"
    assert req.target == "games.roblox.com/v1/games"
    assert req.query_string == "universeIds=1&prettyprint=true"
    assert req.csp_nonce


async def test_tarpit_gets_the_v1_reason_string(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    refusal = respond.Refusal(
        403,
        "This endpoint is currently blocked.",
        ReasonCode.ENDPOINT_BLOCKED,
        tarpit_category="blocked_endpoint",
        detail="Block rule: games.roblox.com/v1/*",
    )
    ctx.abuse = fakes.FakeAbuse(refusal, tarpit=fakes.FakeTarpit(None))
    await proxy_client.get(GAMES)
    assert ctx.abuse.tarpit.reasons == ["Block rule: games.roblox.com/v1/*"]


async def test_challenge_page_gets_the_page_csp(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    seen: dict[str, Any] = {}

    async def evaluate(req: Any) -> Any:
        seen["nonce"] = req.csp_nonce
        body = f'<script nonce="{req.csp_nonce}">solve()</script>'
        return respond.Refusal(403, body, ReasonCode.CHALLENGE, content_type="text/html; charset=utf-8")

    ctx.abuse.evaluate = evaluate
    response = await proxy_client.get(GAMES, headers={"User-Agent": "Mozilla/5.0"})
    assert response.status_code == 403
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    csp = response.headers["content-security-policy"]
    assert "sandbox" not in csp
    assert f"'nonce-{seen['nonce']}'" in csp  # the nonce the page's script carries is this response's nonce


async def test_event_carries_the_optional_recorder_fields(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    """With the P7 `OutcomeEvent`, the optional fields (Live view, samples, refusal split) are filled in."""
    from roxy.metrics.recorder import OutcomeEvent

    refusal = respond.Refusal(429, "Custom.", ReasonCode.ENDPOINT_RULE, check="endpoint_rule", message_source="custom")
    ctx.abuse = fakes.FakeAbuse(refusal)
    await proxy_client.get(GAMES)
    [event] = ctx.recorder.events
    assert isinstance(event, OutcomeEvent)
    assert event.check == "endpoint_rule"
    assert event.message_source == "custom"
    assert event.path == "games.roblox.com/v1/games"
    assert event.query == "universeIds=1"


async def test_stale_after_failure_counts_as_an_error(proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any) -> None:
    ctx.cache.result = fakes.served(
        reason=ReasonCode.CACHE_STALE_ERROR,
        cache_state=CacheState.STALE,
        outcome=Outcome.SERVED_CACHE,
        cache_age_s=90.7,
        cache_ttl_s=60,
        stale_after_failure=True,
    )
    response = await proxy_client.get(GAMES)
    assert response.status_code == 200
    [event] = ctx.recorder.events
    assert event.error is True
    assert event.cache_age_s == 90


async def test_capture_input_handed_to_a_capturing_recorder(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    class CapturingRecorder:
        def __init__(self) -> None:
            self.calls: list[tuple[Any, Any]] = []

        def record_outcome(self, event: Any, capture: Any = None) -> str:
            self.calls.append((event, capture))
            return ""

    ctx.recorder = CapturingRecorder()
    await proxy_client.post("/users.roblox.com/v1/usernames/users", content=b'{"usernames":["a"]}')
    [(event, capture)] = ctx.recorder.calls
    assert capture.request_id == event.request_id
    assert capture.request_body == b'{"usernames":["a"]}'
    assert capture.response_body == b'{"data":[]}'
    assert capture.url == "users.roblox.com/v1/usernames/users"


# --- /internal on the public app (lead decision: v1's JSON 404, no pipeline, no tarpit) -------------------------------


async def test_internal_paths_on_the_public_app_are_a_plain_404(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    ctx.abuse.tarpit = fakes.FakeTarpit(fakes.FakePlan("hold"))
    for method, path in (("GET", "/internal"), ("GET", "/internal/version"), ("POST", "/internal/flush")):
        response = await proxy_client.request(method, path)
        assert response.status_code == 404
        assert response.content == b'"Not Found"\n'
        assert response.headers["content-type"] == "application/json"
        assert "Roxy-Refusal" not in response.headers
    assert ctx.abuse.seen == []  # never the proxy pipeline
    assert ctx.abuse.tarpit.asked == []  # never held
    assert ctx.recorder.events == []
    # A path that only starts with the same letters is an ordinary (refused) proxy path.
    assert (await proxy_client.get("/internals/x")).status_code == 404
    assert len(ctx.abuse.seen) == 1


# --- message_source for failures (parity row 116) ---------------------------------------------------------------------


async def test_message_source_tells_roxy_text_from_roblox_body(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    ctx.cache.result = respond.failure_result(ReasonCode.UPSTREAM_TIMEOUT)
    assert (await proxy_client.get(GAMES)).status_code == 504
    ctx.cache.result = fakes.served(b'{"errors":[{"code":0}]}', status=404, reason=ReasonCode.UPSTREAM_4XX)
    assert (await proxy_client.get(GAMES)).status_code == 404
    ctx.cache.result = fakes.served()
    assert (await proxy_client.get(GAMES)).status_code == 200
    timeout, relayed, ok = ctx.recorder.events
    assert timeout.message_source == "roxy"  # a plan 7.13 text Roxy wrote
    assert relayed.message_source == "roblox"  # Roblox's own error body
    assert ok.message_source == ""


# --- upstream_cooldown_retry: the router hands pacing failures to the tarpit (plan 10.6) ------------------------------


class RetryTarpit:
    """`tarpit.plan_cooldown_retry` stand-in: records every call and returns `plan` (None: no hold)."""

    def __init__(self, plan: Any) -> None:
        self.plan_value = plan
        self.calls: list[dict[str, Any]] = []
        self.asked: list[Any] = []

    async def plan(self, category: str, req: Any, *, reason: str = "") -> Any:
        self.asked.append(category)
        return None

    async def plan_cooldown_retry(self, req: Any, *, key: str, retry_after_s: float, reason: str = "") -> Any:
        self.calls.append({"key": key, "retry_after_s": retry_after_s, "reason": reason, "bypass": req.bypass})
        return self.plan_value


def cooldown_result(retry_after_s: int = 30) -> Any:
    return respond.failure_result(
        ReasonCode.UPSTREAM_COOLDOWN, retry_after_s=retry_after_s, cooldown_s=retry_after_s, upstream_status=429
    )


async def test_a_pacing_failure_is_offered_to_the_cooldown_retry_tarpit(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    plan = fakes.FakePlan("jitter")
    ctx.abuse.tarpit = RetryTarpit(plan)
    ctx.cache.result = cooldown_result(30)
    response = await proxy_client.get(GAMES)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "30"
    [call] = ctx.abuse.tarpit.calls
    assert call["key"] == "key-1"  # the cache key id: "the same key"
    assert call["retry_after_s"] == 30
    assert call["reason"] == "Retry inside Retry-After (upstream_cooldown)"
    assert plan.waited == 1
    assert plan.released == 1
    assert len(ctx.recorder.events) == 1


async def test_cooldown_retry_is_never_asked_for_served_answers_or_bypass_callers(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    ctx.abuse.tarpit = RetryTarpit(fakes.FakePlan("jitter"))
    assert (await proxy_client.get(GAMES)).status_code == 200  # served: never tarpitted
    ctx.cache.result = respond.failure_result(ReasonCode.UPSTREAM_TIMEOUT)
    assert (await proxy_client.get(GAMES)).status_code == 504  # a failure that paces nobody
    ctx.cache.result = cooldown_result()
    original = ctx.abuse.evaluate

    async def bypassing(req: Any) -> Any:
        req.bypass = True
        return await original(req)

    ctx.abuse.evaluate = bypassing
    assert (await proxy_client.get(GAMES)).status_code == 429
    assert ctx.abuse.tarpit.calls == []


async def test_cooldown_retry_without_shared_state_never_holds(proxy_client: httpx.AsyncClient, ctx: Any) -> None:
    class Broken(RetryTarpit):
        async def plan_cooldown_retry(self, req: Any, **kwargs: Any) -> Any:
            raise SharedStateUnavailable("hot", "locked")

    ctx.abuse.tarpit = Broken(None)
    ctx.cache.result = cooldown_result()
    assert (await proxy_client.get(GAMES)).status_code == 429  # C7: the answer still goes out, unheld


# --- the Roblox-Id place claim is scrubbed before it can become a hot.db key (plan C1, 9.15) -------------------------


async def test_a_credential_piece_in_roblox_id_never_reaches_the_request(
    proxy_client: httpx.AsyncClient, ctx: Any
) -> None:
    import secrets

    from roxy.core.redact import SecretRegistry

    secret = secrets.token_hex(40)  # a fake credential made at runtime
    SecretRegistry.register("router_test_credential", secret, match_substrings=True)  # like the credential
    try:
        await proxy_client.get(GAMES, headers={"Roblox-Id": secret[:40]})
        await proxy_client.get(GAMES, headers={"Roblox-Id": " 4483381587 "})
    finally:
        SecretRegistry.unregister("router_test_credential")
    scrubbed, plain = ctx.abuse.seen
    assert scrubbed.place_id
    assert secret[:24] not in scrubbed.place_id
    assert plain.place_id == "4483381587"  # an ordinary place id is unchanged


# --- a refusal's record names the rule rows the verdict matched (lane producers request) ------------------------------


async def test_a_refusal_record_names_the_rule_rows_the_verdict_matched(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    """`Refuse.matches` reaches the outcome event (the refusal event's `rules`), so the Protection attempts tabs know
    which rule refused without matching the patterns again. Allowed requests and the proxy's own refusals carry none."""
    from roxy.abuse.verdict import Allow, Refuse
    from roxy.metrics.recorder import OutcomeEvent

    matched = {"rules_endpoint_block": "7", "access_list": "3"}
    ctx.abuse = fakes.FakeAbuse(
        Refuse(
            status=403,
            body="This endpoint is currently blocked.",
            reason=ReasonCode.ENDPOINT_BLOCKED,
            check="endpoint_block",
            matches=dict(matched),
        )
    )
    assert (await proxy_client.get(GAMES)).status_code == 403
    ctx.abuse = fakes.FakeAbuse(Allow(headers={}, matches={"rules_endpoint_limit": "4"}))
    assert (await proxy_client.get(GAMES)).status_code == 200
    assert (await proxy_client.get("/this-is-not-roblox")).status_code == 404  # `respond.Refusal`: no matches
    refused, allowed, probe = ctx.recorder.events
    assert all(isinstance(event, OutcomeEvent) for event in ctx.recorder.events)
    assert refused.matches == matched
    assert allowed.matches is None  # a served answer is no refusal (its hits went to the rule hit counters)
    assert probe.matches is None


def test_refusal_matches_are_bounded_and_plain_strings() -> None:
    from types import SimpleNamespace

    from roxy.proxy.router import MAX_EVENT_MATCHES, refusal_matches

    assert refusal_matches(None) is None
    assert refusal_matches(SimpleNamespace(matches={})) is None
    assert refusal_matches(SimpleNamespace()) is None
    many = SimpleNamespace(matches={f"table_{i}": i for i in range(20)})
    out = refusal_matches(many)
    assert out is not None
    assert len(out) == MAX_EVENT_MATCHES
    assert all(isinstance(key, str) and isinstance(value, str) for key, value in out.items())
