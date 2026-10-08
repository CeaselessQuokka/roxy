"""Unit tests for `roxy/proxy/context.py`: the browser heuristic, endpoint templates and `ProxyRequest`.

What this is
    The v1 `is_browser` substring list (plan row 4, v1 note B24 false positives pinned on purpose), the fallback
    endpoint template, and the small helpers on `ProxyRequest`.

Why it exists
    Whether a caller gets raw JSON or escaped HTML depends only on `is_browser`; changing it silently would break
    scripts that send browser-like User-Agents today.

How it works
    Direct calls; `fakes.make_req` builds a request.

What to read next
    `tests/unit/proxy/test_proxy_respond.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.core.reasons import ReasonCode
from roxy.proxy.context import BROWSER_UA_MARKERS, _fallback_template, is_browser, problem_template


@pytest.mark.parametrize(
    ("user_agent", "browser"),
    [
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36", True),
        ("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0", True),
        ("Roblox/Linux", False),
        ("RobloxStudio/WinInet", False),
        ("curl/8.5.0", False),
        ("python-httpx/0.28.1", False),
        ("", False),
        (None, False),
        ("knowledge-bot/1.0", True),  # v1 B24: `edge` matches `knowledge`; kept for parity
        ("coprocessor-agent", True),  # v1 B24: `opr` matches `coprocessor`
        ("SAFARI", True),  # case-insensitive
    ],
)
def test_is_browser_v1_heuristic(user_agent: str | None, browser: bool) -> None:
    assert is_browser(user_agent) is browser


def test_browser_markers_are_v1s() -> None:
    assert len(BROWSER_UA_MARKERS) == 18
    assert BROWSER_UA_MARKERS[0] == "gecko"
    assert BROWSER_UA_MARKERS[-1] == "mozilla"


def test_fallback_template() -> None:
    assert (
        _fallback_template("users.roblox.com", "/v1/users/29371917/outfits")
        == "users.roblox.com/v1/users/{userId}/outfits"
    )
    assert _fallback_template("games.roblox.com", "/v1/games") == "games.roblox.com/v1/games"
    assert _fallback_template("games.roblox.com", "/v1/x/42") == "games.roblox.com/v1/x/{id}"
    assert _fallback_template("games.roblox.com", "/") == "games.roblox.com"
    assert problem_template(ReasonCode.NOT_ROBLOX) == "(not_roblox)"


def test_proxy_request_helpers(fakes: Any) -> None:
    req = fakes.make_req(
        query=[("ids", "1"), ("ids", "2")],
        headers={"accept": "*/*", "cookie": "a=b", "authorization": "x"},
        is_head=True,
    )
    assert req.caller_method == "HEAD"
    assert req.method == "GET"
    assert req.upstream_url == "https://games.roblox.com/v1/games?ids=1&ids=2"
    assert req.forwarded_headers() == {"accept": "*/*"}
    assert req.deadline_remaining() > 0


def test_proxy_request_has_slots(fakes: Any) -> None:
    """`slots=True`: a typo such as `req.bypas = True` fails instead of silently adding an attribute."""
    req = fakes.make_req()
    with pytest.raises(AttributeError):
        req.bypas = True  # type: ignore[attr-defined]
    req.bypass = True
    assert req.bypass is True
