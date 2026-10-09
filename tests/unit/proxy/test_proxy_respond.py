"""Unit tests for `roxy/proxy/respond.py`: value forms, body transforms, content types, HEAD and the drip tarpit.

What this is
    The building blocks of every caller answer: v1 header value forms, the `jsonify` refusal body, prettyprint
    with indent 4 and ASCII escapes, markupsafe-exact HTML escaping, the content type rules of plan row 4, no-body
    statuses, header casing, CORS, and the drip response (plan 10.6). The full golden table (every refusal and
    every 7.13 row, compat 0 and 1) is `tests/integration/test_proxy_golden.py`.

Why it exists
    Callers compare bytes. A changed escape, a missing newline or a lowercased header name is a breaking change
    for somebody's game script.

How it works
    Calls the pure render functions with `fakes.make_req` and `ProxyResult` values; the drip response is driven
    through a tiny ASGI harness that collects what is sent.

What to read next
    `tests/integration/test_proxy_golden.py`.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import markupsafe
import pytest

from roxy.core.reasons import CacheState, Outcome, ReasonCode, Source
from roxy.proxy import respond


def test_header_value_forms() -> None:
    assert respond.header_value(True) == "True"
    assert respond.header_value(False) == "False"
    assert respond.header_value(49) == "49"
    assert respond.header_value(50.0) == "50"
    assert respond.header_value(2.5) == "2.5"
    assert respond.header_value("x") == "x"
    assert respond.header_value(None) is None


def test_seconds_header_rounds_up_with_minimum() -> None:
    assert respond.seconds_header(0.2, minimum=1) == "1"
    assert respond.seconds_header(4.01, minimum=1) == "5"
    assert respond.seconds_header(0, minimum=0) == "0"
    assert respond.seconds_header(None) is None
    assert respond.seconds_header(float("nan")) is None


@pytest.mark.parametrize(
    ("text", "body"),
    [
        ("Not a Roblox URL", b'"Not a Roblox URL"\n'),
        ("Too many requests; please slow down.", b'"Too many requests; please slow down."\n'),
        ('Say "hi" \\ bye', b'"Say \\"hi\\" \\\\ bye"\n'),
        ("café \U0001f600", b'"caf\\u00e9 \\ud83d\\ude00"\n'),  # Flask jsonify: ensure_ascii
        ("<b>&</b>", b'"<b>&</b>"\n'),  # jsonify does not HTML-escape
    ],
)
def test_refusal_body_is_v1_jsonify(text: str, body: bytes) -> None:
    assert respond.refusal_body(text) == body


def test_pretty_json_v1() -> None:
    assert respond.pretty_json(b'{"b":1,"a":[1,{"c":"caf\xc3\xa9"}]}') == (
        b'{\n    "b": 1,\n    "a": [\n        1,\n        {\n            "c": "caf\\u00e9"\n        }\n    ]\n}'
    )
    assert respond.pretty_json(b"not json") == b"not json"
    assert respond.pretty_json(b"") == b""
    deep = b"[" * 100_000 + b"]" * 100_000
    assert respond.pretty_json(deep) == deep  # RecursionError is caught, the body is unchanged


@pytest.mark.parametrize("text", ["<script>alert('x')</script>", 'a & b "c"', "plain", "é &amp;"])
def test_markup_escape_matches_markupsafe(text: str) -> None:
    assert respond.markup_escape(text) == str(markupsafe.escape(text))


def test_html_pre() -> None:
    assert respond.html_pre(b'{"a":"<b>"}') == b"<pre>{&#34;a&#34;:&#34;&lt;b&gt;&#34;}</pre>"


@pytest.mark.parametrize(
    ("content_type", "json_type", "textual"),
    [
        (None, True, True),
        ("application/json", True, True),
        ("application/json; charset=utf-8", True, True),
        ("application/problem+json", True, True),
        ("text/html", False, True),
        ("application/xml", False, True),
        ("image/png", False, False),
        ("application/octet-stream", False, False),
    ],
)
def test_media_type_classes(content_type: str | None, json_type: bool, textual: bool) -> None:
    assert respond.is_json_type(content_type) is json_type
    assert respond.is_textual_type(content_type) is textual


def test_served_content_types(fakes: Any) -> None:
    json_result = fakes.served(content_type="application/json; charset=utf-8")
    raw = respond.render(fakes.make_req(), json_result)
    assert raw.content_type == "application/json"  # v1's exact type, no charset
    html = respond.render(fakes.make_req(is_browser=True), json_result)
    assert html.content_type == "text/html; charset=utf-8"
    assert html.body == b"<pre>{&#34;data&#34;:[]}</pre>"
    image = fakes.served(body=b"\x89PNG\r\n", content_type="image/png")
    assert respond.render(fakes.make_req(), image).content_type == "image/png"  # row 4: real type replayed
    browser_image = respond.render(fakes.make_req(is_browser=True), image)
    assert browser_image.content_type == "image/png"
    assert browser_image.body == b"\x89PNG\r\n"  # binary is never wrapped in <pre>
    text_html = fakes.served(body=b"<h1>x</h1>", content_type="text/html; charset=utf-8")
    assert respond.render(fakes.make_req(), text_html).content_type == "text/html; charset=utf-8"
    assert respond.render(fakes.make_req(is_browser=True), text_html).body == b"<pre>&lt;h1&gt;x&lt;/h1&gt;</pre>"
    odd = fakes.served(body=b"x", content_type="text/plain\x01")
    assert respond.render(fakes.make_req(), odd).content_type == respond.FALLBACK_BINARY_TYPE


def test_prettyprint_then_browser_escape(fakes: Any) -> None:
    result = fakes.served(body=b'{"a":"<b>"}')
    rendered = respond.render(fakes.make_req(prettyprint=True, is_browser=True), result)
    assert rendered.body == b"<pre>{\n    &#34;a&#34;: &#34;&lt;b&gt;&#34;\n}</pre>"
    assert rendered.source is Source.RELAY  # Roblox's answer reshaped by Roxy
    plain = respond.render(fakes.make_req(), result)
    assert plain.source is Source.ROBLOX


def test_prettyprint_applies_to_cached_and_error_bodies(fakes: Any) -> None:
    """Live and cached bodies look the same (fixes the v1 B19 inconsistency): every Roblox body is prettified."""
    result = fakes.served(body=b'{"errors":[{"code":0}]}', status=404, reason=ReasonCode.UPSTREAM_4XX)
    rendered = respond.render(fakes.make_req(prettyprint=True), result)
    assert rendered.status == 404
    assert rendered.body == json.dumps({"errors": [{"code": 0}]}, indent=4).encode()


def test_failure_text_is_never_prettified_or_wrapped(fakes: Any) -> None:
    result = respond.failure_result(ReasonCode.UPSTREAM_BUSY)
    rendered = respond.render(fakes.make_req(prettyprint=True, is_browser=True), result)
    assert rendered.body == respond.UPSTREAM_BUSY_TEXT.encode()
    assert rendered.content_type == "text/plain; charset=utf-8"


@pytest.mark.parametrize("compat", [False, True])
def test_internal_error_row_is_v1_jsonify(fakes: Any, compat: bool) -> None:
    """v1 answered every unhandled error with `jsonify("Internal Server Error")` (plan 7.13 "as v1"): the same
    bytes the unhandled error middleware sends, whatever compat says (the row is not collapsible)."""
    rendered = respond.render(
        fakes.make_req(prettyprint=True, is_browser=True),
        respond.failure_result(ReasonCode.INTERNAL_ERROR),
        compat_collapse=compat,
    )
    assert (rendered.status, rendered.body, rendered.content_type) == (
        500,
        b'"Internal Server Error"\n',
        "application/json",
    )
    assert rendered.header("Retry-After") == "5"
    assert rendered.header("Roxy-Refusal") is None


ROBLOX_404_BODY = json.dumps({"errors": [{"code": 0, "message": "NotFound"}]}, separators=(",", ":")).encode()


def test_r4_compat_collapse_keeps_robloxs_body_like_v1(fakes: Any) -> None:
    """Spec review R4 (F8) and the lead decision: v1 (pipeline.md section 7 step 4, bug B1) sent a Roblox 404 to
    the caller as 500 WITH Roblox's body, labeled application/json; compat mode reproduces exactly that."""
    result = fakes.served(ROBLOX_404_BODY, status=404, reason=ReasonCode.UPSTREAM_4XX, content_type="application/json")
    rendered = respond.render(fakes.make_req(), result, compat_collapse=True)
    assert rendered.status == 500
    assert rendered.body == ROBLOX_404_BODY
    assert rendered.content_type == "application/json"
    assert rendered.collapsed is True
    assert rendered.header("Roxy-Upstream-Status") == "404"
    assert rendered.header("Roxy-Refusal") is None
    off = respond.render(fakes.make_req(), result, compat_collapse=False)  # D4, the default: the real status
    assert (off.status, off.body, off.collapsed) == (404, ROBLOX_404_BODY, False)


def test_compat_collapse_of_a_live_4xx_is_not_prettified_but_keeps_the_browser_view(fakes: Any) -> None:
    """v1's live path pretty printed only a successful call, and showed every body (errors too) to a browser as
    escaped `<pre>`. A cached 4xx is pretty printed: `test_rr_spec_compat_pretty.py` (finding spec-6)."""
    result = fakes.served(ROBLOX_404_BODY, status=404, reason=ReasonCode.UPSTREAM_4XX)
    pretty = respond.render(fakes.make_req(prettyprint=True), result, compat_collapse=True)
    assert (pretty.status, pretty.body) == (500, ROBLOX_404_BODY)
    browser = respond.render(fakes.make_req(is_browser=True), result, compat_collapse=True)
    assert browser.status == 500
    assert browser.content_type == "text/html; charset=utf-8"
    assert browser.body == respond.html_pre(ROBLOX_404_BODY)
    text = fakes.served(b"gone", status=410, reason=ReasonCode.UPSTREAM_4XX, content_type="text/plain")
    replayed = respond.render(fakes.make_req(), text, compat_collapse=True)
    assert (replayed.status, replayed.body, replayed.content_type) == (500, b"gone", "text/plain")  # row 4


def test_compat_collapse_of_a_5xx_uses_the_failure_text(fakes: Any) -> None:
    """Plan 7.13 compat note: a Roblox 5xx, 502 and 504 become 500 with `Upstream request failed; ...`."""
    served_5xx = fakes.served(b'{"errors":[]}', status=503, reason=ReasonCode.UPSTREAM_4XX)
    rendered = respond.render(fakes.make_req(), served_5xx, compat_collapse=True)
    assert (rendered.status, rendered.body, rendered.content_type) == (
        500,
        respond.UPSTREAM_FAILED_TEXT.encode(),
        "text/plain; charset=utf-8",
    )
    timeout = respond.render(
        fakes.make_req(), respond.failure_result(ReasonCode.UPSTREAM_TIMEOUT), compat_collapse=True
    )
    assert (timeout.status, timeout.body) == (500, respond.UPSTREAM_FAILED_TEXT.encode())


@pytest.mark.parametrize("status", [204, 304])
def test_no_body_statuses(fakes: Any, status: int) -> None:
    rendered = respond.render(fakes.make_req(prettyprint=True, is_browser=True), fakes.served(body=b"", status=status))
    assert rendered.body == b""
    assert rendered.content_type is None
    response = rendered.to_response()
    assert response.body == b""
    assert b"content-length" not in [name for name, _ in response.raw_headers]


def test_head_keeps_length_drops_body(fakes: Any) -> None:
    rendered = respond.render(fakes.make_req(is_head=True), fakes.served(body=b'{"data":[1]}'))
    response = rendered.to_response(head=True)
    assert response.body == b""
    assert (b"content-length", b"12") in response.raw_headers


def test_header_casing_preserved(fakes: Any) -> None:
    rendered = respond.render(fakes.make_req(), fakes.served(cache_state=CacheState.HIT, cache_age_s=3, cache_ttl_s=60))
    names = [name for name, _ in rendered.to_response().raw_headers]
    for expected in (b"Roxy-Cache", b"Roxy-Cache-Age", b"Roxy-Cache-TTL", b"Roxy-Upstream-Status", b"Roxy-Request-Id"):
        assert expected in names


def test_header_values_cannot_split_the_response(fakes: Any) -> None:
    refusal = respond.Refusal(429, "x", ReasonCode.THROTTLE, headers={"X-Evil": "a\r\nSet-Cookie: b", "Ok": "1"})
    rendered = respond.render(fakes.make_req(), refusal)
    assert rendered.header("X-Evil") is None
    assert rendered.header("Ok") == "1"


def test_cors_only_when_enabled_and_only_for_get(fakes: Any) -> None:
    result = fakes.served()
    assert respond.render(fakes.make_req(), result).header("Access-Control-Allow-Origin") is None
    assert respond.render(fakes.make_req(), result, cors_any_origin=True).header("Access-Control-Allow-Origin") == "*"
    post = fakes.make_req(method="POST")
    assert respond.render(post, result, cors_any_origin=True).header("Access-Control-Allow-Origin") is None


def test_upstream_guard_refusal_renders_as_v1_refusal(fakes: Any) -> None:
    """The egress guard saw a public credential marker: 400 with the v1 text, never a leak-guard trip (C2 item 5)."""
    result = respond.ProxyResult(reason=ReasonCode.AUTH_SMUGGLING, status=400)
    rendered = respond.render(fakes.make_req(), result)
    assert rendered.status == 400
    assert rendered.body == b'"Requests requiring authentication are not allowed with this proxy."\n'
    assert rendered.outcome is Outcome.REFUSED


def test_result_from_upstream(fakes: Any) -> None:
    upstream = fakes.FakeUpstreamResult(headers={"Set-Cookie": "x=y", "Retry-After": "3"})
    result = respond.result_from_upstream(upstream)
    assert result.outcome is Outcome.SERVED_UPSTREAM
    assert result.upstream_headers == {"Retry-After": "3"}
    assert result.upstream_calls == 1
    failed = respond.result_from_upstream(fakes.FakeUpstreamResult(reason=ReasonCode.UPSTREAM_TIMEOUT, status=504))
    assert failed.outcome is Outcome.FAILED


# --- drip -----------------------------------------------------------------------------------------------------------


async def _collect(response: Any) -> tuple[dict[str, Any], list[bytes]]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "asgi": {"spec_version": "2.4"}, "method": "GET"}
    await response(scope, receive, send)
    start = sent[0]
    chunks = [m["body"] for m in sent[1:] if m.get("body")]
    return start, chunks


async def test_drip_response_streams_filler_then_body(fakes: Any) -> None:
    refusal = respond.target_refusal(ReasonCode.NOT_ROBLOX)
    closed: list[int] = []
    plan = fakes.FakePlan("drip", ticks=3)
    response = respond.drip_response(refusal, plan, req=fakes.make_req(), on_close=lambda: closed.append(1))
    start, chunks = await _collect(response)
    headers = dict(start["headers"])
    assert start["status"] == 404
    assert headers[b"X-Accel-Buffering"] == b"no"
    assert headers[b"Content-Encoding"] == b"identity"
    assert b"content-length" not in headers
    assert headers[b"Roxy-Refusal"] == b"not_roblox"
    assert chunks == [b" ", b" ", b" ", b'"Not a Roblox URL"\n']
    assert json.loads(b"".join(chunks)) == "Not a Roblox URL"  # leading whitespace keeps it valid JSON
    assert closed == [1]
    await response.close()
    assert closed == [1]  # exactly once


async def test_drip_chunks_that_take_the_body(fakes: Any) -> None:
    class BodyPlan:
        kind = "drip"

        async def drip_chunks(self, body: bytes) -> Any:
            for index in range(len(body)):
                yield body[index : index + 1]

    rendered = respond.render(fakes.make_req(), respond.target_refusal(ReasonCode.UNSAFE_URL))
    _, chunks = await _collect(respond.drip_response(rendered, BodyPlan()))
    assert b"".join(chunks) == b'"Invalid URL"\n'  # the body is sent once, by the plan


async def test_drip_on_close_runs_when_stream_is_canceled(fakes: Any) -> None:
    closed: list[int] = []
    plan = fakes.FakePlan("drip", ticks=1000, interval_s=0.01)
    rendered = respond.render(fakes.make_req(), respond.target_refusal(ReasonCode.NOT_ROBLOX))

    async def on_close() -> None:
        closed.append(1)

    task = asyncio.create_task(_collect(respond.drip_response(rendered, plan, on_close=on_close)))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed == [1]


def test_drip_response_needs_req_for_a_raw_refusal() -> None:
    with pytest.raises(ValueError):
        respond.drip_response(respond.target_refusal(ReasonCode.NOT_ROBLOX), object())


async def test_drip_plan_headers_sent_once(fakes: Any) -> None:
    class HeaderPlan:
        kind = "drip"
        response_headers = {"X-Accel-Buffering": "no", "Content-Encoding": "identity"}

        async def drip_chunks(self) -> Any:
            yield b" "

    rendered = respond.render(fakes.make_req(), respond.target_refusal(ReasonCode.NOT_ROBLOX))
    start, _ = await _collect(respond.drip_response(rendered, HeaderPlan()))
    names = [name.lower() for name, _ in start["headers"]]
    assert names.count(b"x-accel-buffering") == 1
    assert names.count(b"content-encoding") == 1


# --- refusals as the abuse pipeline builds them (abuse/verdict.py) ---------------------------------------------------


def test_refusal_headers_are_copied_as_given(fakes: Any) -> None:
    """`Refuse.headers` is complete: it already names the refusal, so nothing is added or replaced."""
    refusal = respond.Refusal(
        403,
        "This endpoint is currently blocked.",
        ReasonCode.ENDPOINT_BLOCKED,
        headers={"Roxy-Refusal": "endpoint_blocked"},
    )
    rendered = respond.render(fakes.make_req(), refusal)
    assert [value for name, value in rendered.headers if name == "Roxy-Refusal"] == ["endpoint_blocked"]


def test_disguised_refusal_keeps_its_throttle_disguise(fakes: Any) -> None:
    """A disguised header filter carries exactly a throttle refusal's headers, `Roxy-Refusal: throttle` included."""
    disguised = respond.Refusal(
        429,
        "Too many requests; please slow down.",
        ReasonCode.HEADER_RULE,
        headers={"Retry-After": "50", "Roxy-Refusal": "throttle"},
        disguised=True,
    )
    rendered = respond.render(fakes.make_req(), disguised)
    assert rendered.header("Roxy-Refusal") == "throttle"  # never unmasked to header_rule
    assert rendered.reason is ReasonCode.HEADER_RULE  # the true reason still reaches the metrics
    bare = respond.Refusal(429, "x", ReasonCode.HEADER_RULE, disguised=True)
    assert respond.render(fakes.make_req(), bare).header("Roxy-Refusal") is None


def test_html_refusal_is_a_page(fakes: Any) -> None:
    """The challenge page (plan 10.8) is the one refusal with an HTML body: sent as is, marked as a page."""

    page = respond.Refusal(
        403,
        "<!doctype html><p>Checking your browser</p>",
        ReasonCode.CHALLENGE,
        content_type="text/html; charset=utf-8",
    )
    rendered = respond.render(fakes.make_req(), page)
    assert rendered.body == b"<!doctype html><p>Checking your browser</p>"
    assert rendered.content_type == "text/html; charset=utf-8"
    assert rendered.page is True
    assert respond.render(fakes.make_req(), respond.target_refusal(ReasonCode.NOT_ROBLOX)).page is False
