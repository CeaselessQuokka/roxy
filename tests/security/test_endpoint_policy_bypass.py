"""The endpoint policy cannot be dodged: every spelling of a blocked endpoint the URL parser lets through is blocked.

Requests go through `proxy/validate.py parse_target` (what the proxy route runs) and then the policy, so a trick that
the parser normalizes away and a trick the policy must catch are both covered (BRIEF.md section 4).
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from roxy.policy.engine import EndpointPolicy
from roxy.policy.seed import Verdict, load_seed
from roxy.proxy.validate import parse_target

POLICY = EndpointPolicy(load_seed())
HOSTS = sorted(load_seed().hosts)
BLOCKED = [row for row in load_seed().rows if row.verdict is Verdict.BLOCK]
_PARAM = re.compile(r"\{[^{}/]+\}")


def through_the_proxy(raw_path: str, method: str = "POST", query: str = "") -> Verdict | None:
    """The verdict for a raw proxy path, or None when the URL parser itself refuses it."""
    parsed = parse_target(raw_path, query, method, allowed_hosts=HOSTS)
    if not parsed.ok:
        return None
    return POLICY.decide(parsed.host, method, parsed.path, parsed.query).verdict


@pytest.mark.parametrize(
    "raw",
    [
        "/auth.roblox.com/v1/logout",
        "/AUTH.ROBLOX.COM/v1/logout",
        "/auth.roblox.com/V1/LogOut",
        "/auth.roblox.com/v1/logout/",
        "/auth.roblox.com//v1//logout",
        "/auth.roblox.com/v1/%6Cogout",
        "/auth.roblox.com/v1/logout;jsessionid=1",
        "/auth.roblox.com/v1/logout.json",
        "/auth.roblox.com/v1/logout%20",
        "/auth.roblox.com/v1/logout/extra",
    ],
)
def test_logout_spellings_never_pass(raw: str) -> None:
    verdict = through_the_proxy(raw)
    assert verdict in (None, Verdict.BLOCK), (raw, verdict)


@pytest.mark.parametrize(
    "raw",
    [
        "/auth.roblox.com/v1/logout%2F",
        "/auth.roblox.com/v1/x/..%2Flogout",
        "/auth.roblox.com/v1/x/../logout",
        "/auth.roblox.com/v1/logout%00",
    ],
)
def test_the_parser_refuses_path_tricks(raw: str) -> None:
    assert through_the_proxy(raw) is None


def test_head_and_get_share_a_verdict() -> None:
    assert through_the_proxy("/users.roblox.com/v1/users/authenticated", "GET") is Verdict.BLOCK
    assert through_the_proxy("/users.roblox.com/v1/users/authenticated", "HEAD") is Verdict.BLOCK


def test_friend_servers_through_the_proxy() -> None:
    assert through_the_proxy("/games.roblox.com/v1/games/1/servers/Friend", "GET") is Verdict.BLOCK
    assert through_the_proxy("/games.roblox.com/v1/games/1/servers/Public", "GET") is Verdict.ALLOW_TOKEN


def _fill(path: str, value: str) -> str:
    return _PARAM.sub(value, path)


@settings(max_examples=300, deadline=None)
@given(
    index=st.integers(min_value=0, max_value=len(BLOCKED) - 1),
    value=st.text(alphabet=st.characters(categories=("L", "N"), include_characters="-_.:~"), min_size=1, max_size=40),
    upper=st.booleans(),
    slash=st.booleans(),
)
def test_every_blocked_row_stays_blocked_whatever_its_parameters(
    index: int, value: str, upper: bool, slash: bool
) -> None:
    row = BLOCKED[index]
    if value in (".", ".."):
        return
    path = _fill(row.path, value)
    if upper:
        path = path.upper()
    if slash:
        path += "/"
    decision = POLICY.decide(row.host, row.method, path)
    assert decision.verdict is Verdict.BLOCK, (row.id, path, decision)
    assert POLICY.credential_grant(row.host + path, row.method) is None
