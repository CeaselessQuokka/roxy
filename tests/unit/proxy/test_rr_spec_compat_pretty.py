"""Reviewer finding spec-6: compat mode pretty prints a CACHED Roblox error with `?prettyprint=true`, as v1 did.

What this is
    `respond.render` tests for `compat_collapse_upstream_errors` (v1 mode) with `?prettyprint=true`, for a Roblox 4xx
    answered live and the same 4xx answered from the cache (a negative entry, and every other cache serve state).

Why it exists
    Fix pass 1 (spec F8) made compat mode keep Roblox's body under status 500 and "never pretty printed (v1 pretty
    printed only successes)". That holds for a LIVE answer: v1 `index.py` pretty printed the live body only when
    the upstream call succeeded (pipeline.md section 7 step 2). It did not hold for a cache serve: v1
    `_serve_from_cache` (index.py:1770) calls `_pretty(entry["Body"], pretty_print)` for every entry, successful or
    not, then answers 500 for an unsuccessful one (pipeline.md section 7.2 and section 8, "Serve"). v1 served HIT,
    STALE and COALESCED answers through that one function, so every answer labeled as a cache serve was pretty
    printed. The setting promises "every Roblox 4xx, live or cached ... exactly as in v1".

How it works
    Builds cached and live 4xx results with the proxy test fakes and renders them with compat on. A cache serve
    (`respond.CACHE_SERVE_STATES`: HIT, REVALIDATING, STALE, COALESCED) is pretty printed and then wrapped for a
    browser; a live answer (MISS, OFF) stays raw; without `?prettyprint=true` nothing is pretty printed (stored
    bodies never are). The end-to-end version through the real cache is
    `tests/integration/test_pipeline_e2e.py::test_compat_prettyprint_follows_v1_for_live_and_cached_4xx`.

What to read next
    `roxy/proxy/respond.py` (`render_served`), `.remake/v1notes/pipeline.md` sections 7 and 8, `app/index.py`
    `_serve_from_cache`.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.core.reasons import CacheState, Outcome, ReasonCode, Source
from roxy.proxy import respond

ROBLOX_404 = b'{"errors":[{"code":0,"message":"NotFound"}]}'


def _cached(fakes: Any, state: CacheState = CacheState.HIT, **fields: Any) -> respond.ProxyResult:
    """A Roblox 404 answered from the cache in `state` (a negative entry for HIT)."""
    reasons = {
        CacheState.HIT: ReasonCode.CACHE_NEGATIVE,
        CacheState.REVALIDATING: ReasonCode.CACHE_REVALIDATING,
        CacheState.STALE: ReasonCode.CACHE_STALE_COOLDOWN,
        CacheState.COALESCED: ReasonCode.CACHE_COALESCED,
    }
    fields.setdefault("content_type", "application/json")
    return fakes.served(
        fields.pop("body", ROBLOX_404),
        status=404,
        reason=reasons[state],
        cache_state=state,
        outcome=Outcome.SERVED_CACHE,
        source=Source.CACHE,
        cache_age_s=3,
        cache_ttl_s=60,
        **fields,
    )


@pytest.mark.parametrize("state", [CacheState.MISS, CacheState.OFF], ids=["miss", "cache_off"])
def test_spec_6_control_live_4xx_is_not_pretty_printed(fakes: Any, state: CacheState) -> None:
    """v1 pretty printed a live answer only when the call succeeded: compat leaves a live 4xx raw."""
    live = fakes.served(
        ROBLOX_404, status=404, reason=ReasonCode.UPSTREAM_4XX, content_type="application/json", cache_state=state
    )
    rendered = respond.render(fakes.make_req(prettyprint=True), live, compat_collapse=True)
    assert (rendered.status, rendered.body, rendered.content_type) == (500, ROBLOX_404, "application/json")
    assert rendered.source is Source.ROBLOX  # nothing reshaped it


def test_spec_6_cached_4xx_is_pretty_printed_in_compat_mode_like_v1(fakes: Any) -> None:
    rendered = respond.render(fakes.make_req(prettyprint=True), _cached(fakes), compat_collapse=True)
    assert rendered.status == 500
    assert rendered.body == respond.pretty_json(ROBLOX_404)  # v1 `_serve_from_cache`: `_pretty` on every entry
    assert rendered.body != ROBLOX_404
    assert rendered.content_type == "application/json"
    assert rendered.collapsed is True
    assert (rendered.header("Roxy-Cache"), rendered.header("Roxy-Cache-Age")) == ("HIT", "3")
    assert rendered.source is Source.CACHE
    assert rendered.reason is ReasonCode.CACHE_NEGATIVE


@pytest.mark.parametrize(
    "state",
    sorted(respond.CACHE_SERVE_STATES, key=lambda state: state.value),
    ids=lambda state: state.value.lower(),
)
def test_spec_6_every_cache_serve_state_is_pretty_printed_in_compat_mode(fakes: Any, state: CacheState) -> None:
    """v1 answered HIT, STALE and COALESCED through `_serve_from_cache`; REVALIDATING is v2's HIT inside the SWR
    window. Every answer labeled as a cache serve gets the same body v1's cache path gave."""
    rendered = respond.render(fakes.make_req(prettyprint=True), _cached(fakes, state), compat_collapse=True)
    assert (rendered.status, rendered.body) == (500, respond.pretty_json(ROBLOX_404))
    assert rendered.header("Roxy-Cache") == state.value


def test_spec_6_cached_4xx_is_pretty_printed_then_wrapped_for_a_browser(fakes: Any) -> None:
    """v1 order: `_pretty` first, then `_proxy_response` wrapped the result as escaped `<pre>` for a browser."""
    rendered = respond.render(fakes.make_req(prettyprint=True, is_browser=True), _cached(fakes), compat_collapse=True)
    assert rendered.status == 500
    assert rendered.content_type == "text/html; charset=utf-8"
    assert rendered.body == respond.html_pre(respond.pretty_json(ROBLOX_404))


def test_spec_6_cached_4xx_without_prettyprint_stays_raw(fakes: Any) -> None:
    """Stored bodies are never pretty (v1 stored before `_pretty`): only `?prettyprint=true` changes them."""
    rendered = respond.render(fakes.make_req(), _cached(fakes), compat_collapse=True)
    assert (rendered.status, rendered.body) == (500, ROBLOX_404)


def test_spec_6_cached_non_json_4xx_is_unchanged_by_prettyprint(fakes: Any) -> None:
    """v1 `_pretty` returned a body that is not JSON unchanged; the content type is replayed (row 4)."""
    cached = _cached(fakes, body=b"gone", content_type="text/plain")
    rendered = respond.render(fakes.make_req(prettyprint=True), cached, compat_collapse=True)
    assert (rendered.status, rendered.body, rendered.content_type) == (500, b"gone", "text/plain")


def test_spec_6_compat_off_pretty_prints_live_and_cached_4xx(fakes: Any) -> None:
    """D4 (the default) is unchanged: the real status, and every Roblox body pretty printed, live or cached."""
    live = fakes.served(ROBLOX_404, status=404, reason=ReasonCode.UPSTREAM_4XX, content_type="application/json")
    for result in (live, _cached(fakes)):
        rendered = respond.render(fakes.make_req(prettyprint=True), result, compat_collapse=False)
        assert (rendered.status, rendered.body, rendered.collapsed) == (404, respond.pretty_json(ROBLOX_404), False)
