"""What a request filter's refusal records about its hit (finding v1parity-5, parity row 75).

What this is
    Unit tests of `abuse/header_rules.py match_detail`, of the header filter check carrying it on both refusal forms
    (disguised as a throttle and with a message of its own), and of `proxy/router.py refusal_match_detail`, which
    hands it to the refusal's outcome record.

Why it exists
    v1's Header-Blocked Attempts showed which header a filter caught, whether its name or its value matched, and the
    matched text: the way an admin spots a broad filter's false positives. The record keeps exactly that, never a
    caller's header value (wave 3b: refused requests keep no header values), and none of it reaches the caller (the
    disguised refusal stays byte for byte a throttle refusal).

How it works
    Rules are created through the real rules service over temporary databases (the abuse conftest); the pipeline
    evaluates `FakeReq`s like `test_abuse_golden.py` does.

What to read next
    `roxy/abuse/header_rules.py`, `roxy/abuse/checks/header_rules.py`, `roxy/proxy/router.py refusal_match_detail`,
    then tests/review_p11/test_v1parity.py (v1parity-5 through the real app and the attempts tab).
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from abuse_support import ADMIN, FakeReq

from roxy.abuse.header_rules import MAX_MATCH_TEXT, match_detail, rule_hit
from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.verdict import Refuse
from roxy.proxy.router import MAX_MATCH_DETAIL_CHARS, refusal_match_detail
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot

pytestmark = pytest.mark.usefixtures("seeded")

CALLER_VALUE = "4f3a91c0-private"
"""A header value a caller sent: it must never be what a refusal records."""


async def _filters(rules_service: RulesService, snapshot_of: Callable[[], RulesSnapshot]) -> RulesSnapshot:
    await rules_service.create("rules_header", {"needle": "xeno", "scope": "key"}, ADMIN)
    await rules_service.create("rules_header", {"needle": "WinInet", "header": "User-Agent"}, ADMIN)
    await rules_service.create("rules_header", {"needle": "^4f3a", "scope": "value", "mode": "regex"}, ADMIN)
    await rules_service.create("rules_header", {"needle": "exactly-this", "scope": "value", "mode": "exact"}, ADMIN)
    return snapshot_of()


async def test_the_detail_names_the_header_the_side_that_matched_and_the_text(
    rules_service: RulesService, snapshot_of: Callable[[], RulesSnapshot]
) -> None:
    by_name, user_agent, regex, exact = (await _filters(rules_service, snapshot_of)).header_rules
    # ASGI hands header names over lowercased; v1 showed them Title-Cased (Werkzeug), as the tarpit reason does.
    name_hit = rule_hit(by_name, [("x-xeno-fingerprint", CALLER_VALUE)])
    assert name_hit is not None
    assert match_detail(name_hit) == {"header": "X-Xeno-Fingerprint", "field": "key", "text": "X-Xeno-Fingerprint"}
    value_hit = rule_hit(user_agent, [("user-agent", "Roblox/WinInet")])
    assert value_hit is not None
    assert match_detail(value_hit) == {"header": "User-Agent", "field": "value", "text": user_agent.needle}
    exact_hit = rule_hit(exact, [("x-tool", "Exactly-This")])
    assert exact_hit is not None
    assert match_detail(exact_hit) == {"header": "X-Tool", "field": "value", "text": exact.needle}
    # A regex on a value: what it matched is the caller's value, which a refusal never keeps.
    regex_hit = rule_hit(regex, [("x-xeno-fingerprint", CALLER_VALUE)])
    assert regex_hit is not None
    detail = match_detail(regex_hit)
    assert detail == {"header": "X-Xeno-Fingerprint", "field": "value"}
    assert CALLER_VALUE not in str(detail)


async def test_a_long_or_non_ascii_header_name_is_kept_bounded_and_readable(
    rules_service: RulesService, snapshot_of: Callable[[], RulesSnapshot]
) -> None:
    by_name = (await _filters(rules_service, snapshot_of)).header_rules[0]
    hit = rule_hit(by_name, [("x-xeno-" + "a" * 500, "1")])
    assert hit is not None
    detail = match_detail(hit)
    assert len(detail["header"]) == MAX_MATCH_TEXT
    assert detail["text"] == detail["header"]
    # Header bytes reach Python as Latin-1 text; the record reads them as the UTF-8 the caller wrote.
    utf8 = "x-xeno-ö".encode().decode("latin-1")
    hit = rule_hit(by_name, [(utf8, "1")])
    assert hit is not None
    assert match_detail(hit)["header"] == "X-Xeno-Ö"  # read as UTF-8, then Title-Cased like every name


async def test_both_refusal_forms_carry_it_and_the_caller_never_sees_it(
    make_pipeline: Callable[..., AbusePipeline],
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
) -> None:
    await rules_service.create("rules_header", {"needle": "xeno", "scope": "either"}, ADMIN)
    await rules_service.create("rules_header", {"needle": "badtool", "header": "User-Agent", "message": "No."}, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of())
    disguised = await pipeline.evaluate(
        FakeReq().with_headers([("User-Agent", "Roblox/WinInet"), ("X-Xeno-Fingerprint", CALLER_VALUE)])
    )
    assert isinstance(disguised, Refuse)
    assert disguised.disguised
    assert disguised.match_detail == {"header": "X-Xeno-Fingerprint", "field": "key", "text": "X-Xeno-Fingerprint"}
    wire = (disguised.encoded_body() + str(disguised.headers).encode()).lower()
    assert b"xeno" not in wire  # the disguise names no header (v1 smoke test)
    custom = await pipeline.evaluate(FakeReq(client_ip="198.51.100.20", limit_key="198.51.100.20").with_headers(
        [("User-Agent", "BadTool/2")]
    ))  # fmt: skip
    assert isinstance(custom, Refuse)
    assert not custom.disguised
    assert custom.match_detail == {"header": "User-Agent", "field": "value", "text": "badtool"}
    assert b"user-agent" not in (custom.encoded_body() + str(custom.headers).encode()).lower()


def test_the_outcome_record_takes_the_three_keys_bounded_and_nothing_else() -> None:
    long = "x" * 500
    refusal: Any = SimpleNamespace(match_detail={"header": long, "field": "key", "text": long, "value": CALLER_VALUE})
    kept = refusal_match_detail(refusal)
    assert kept == {"header": long[:MAX_MATCH_DETAIL_CHARS], "field": "key", "text": long[:MAX_MATCH_DETAIL_CHARS]}
    assert refusal_match_detail(SimpleNamespace(match_detail={})) is None
    assert refusal_match_detail(SimpleNamespace(match_detail="header")) is None
    assert refusal_match_detail(SimpleNamespace()) is None  # an Allow, a cache serve, the proxy's own refusals
    assert refusal_match_detail(None) is None
