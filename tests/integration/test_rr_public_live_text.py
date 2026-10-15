"""Adversarial review (public site lens): public text that contradicts the live settings.

What this is
    Integration tests on the fully wired app. One switches the strike ladder off (`throttle_escalation_enabled` 0)
    and retry strikes off (`throttle_strike_on_retry` 0) through the real settings service, then reads `/` and
    `/docs`. One reads the privacy chapter of `/docs` with the shipped capture defaults.

Why it exists
    The public pages promise that every limit a visitor reads follows the live settings (plan 16.1 "rendered live
    from settings", 16.2 chapter 4), and they already follow `throttle_count_cache_hits`, the window mode, the place
    limit, the IPv6 grouping and the strike decay. The strike ladder is the exception. With escalation off, v2 adds
    no strikes and every throttle lasts one window (`abuse/throttle.py`, catalog text of
    `throttle_escalation_enabled`), and with retry strikes off a retry while throttled costs nothing extra. Yet the
    guide still tells callers "each repeated violation is a strike, and each strike makes the next wait longer" and
    "Retrying while you are throttled can add a strike", and the home page says "retrying sooner makes the wait
    longer". A caller reading them gets the rules of a different configuration.
    - Finding public-7: the strike and retry sentences of `/` and `/docs` ignore `throttle_escalation_enabled` and
      `throttle_strike_on_retry`.
    The privacy chapter (plan 16.2 chapter 10, D8) opens its body paragraph with "Bodies are not normally kept",
    while body capture is ON by default (`capture_enabled` 1): every refusal's request and answer bodies and 20% of
    served ones are kept for 15 minutes. The live sentence right after it even says "body capture is currently on".
    - Finding public-8: the privacy text states the opposite of the shipped capture default.
    Chapter 2 gives the live body limit and deadline, but never the live URL limit (`max_url_length`, 4,096
    characters by default), and chapter 7, which the status page calls the place that "explains every status
    code", has no row for 414, the refusal Roxy's middleware sends for a longer URL (plan 9.12). Long id lists in a
    GET query are exactly how callers reach it (plan 15.3: "More 414 refusals").
    - Finding public-9: the guide never states the URL length limit and omits Roxy's own 414.
    All three are fixed: the sentences are built from the live settings (`pages.escalation_rule`, `retry_tip`,
    `LiveLimits.retry_rule`, `capture_rule`, and the `max_url_length` value with a 414 row in chapter 7).

How it works
    The visible text of each page (tags removed, entities decoded, whitespace collapsed, lower case) must not
    contain the stale sentences in the stated configuration, and must contain the missing facts and the sentences
    that replace the stale ones.

What to read next
    `docs/USER_GUIDE.md` chapters 4 and 10, `roxy/templates/public/home.html` ("Limits at a glance"),
    `roxy/public/pages.py` (`GUIDE_VALUES`, `escalation_rule`, `capture_rule`), `roxy/abuse/throttle.py`.
"""

from __future__ import annotations

import html
import re

import httpx
from fastapi import FastAPI

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService

ESCALATION_CLAIMS = {
    "/docs": (
        "each strike makes the next wait longer",
        "retrying while you are throttled can add a strike",
        "retrying sooner only makes the wait longer",  # the good citizen checklist (chapter 8)
    ),
    "/": ("retrying sooner makes the wait longer",),
}
RETRY_CLAIMS = {  # only the retry part: true while escalation stays on
    "/docs": ("retrying while you are throttled can add a strike", "retrying sooner only makes the wait longer"),
    "/": ("retrying sooner makes the wait longer",),
}


def visible_text(page: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", page)).split()).lower()


async def test_rr_public_escalation_sentences_are_there_by_default(client: httpx.AsyncClient) -> None:
    """The premise: with the defaults (ladder and retry strikes on) the sentences are on the pages, and true."""
    for path, claims in ESCALATION_CLAIMS.items():
        text = visible_text((await client.get(path)).text)
        for claim in claims:
            assert claim in text, (path, claim)


async def _change(app: FastAPI, changes: dict[str, object]) -> None:
    ctx = app.state.ctx
    service = SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=ctx.clock)
    await service.update(changes, Actor("cli", "public-review"), "review test")
    await ctx.settings.refresh_if_changed()


async def test_rr_public_escalation_text_follows_the_live_settings(app: FastAPI, client: httpx.AsyncClient) -> None:
    await _change(app, {"throttle_escalation_enabled": 0, "throttle_strike_on_retry": 0})
    stale = []
    for path, claims in ESCALATION_CLAIMS.items():
        text = visible_text((await client.get(path)).text)
        stale += [(path, claim) for claim in claims if claim in text]
    print("\nstale sentences with the ladder off:", stale)
    assert stale == []
    docs = visible_text((await client.get("/docs")).text)
    assert "right now repeated violations do not make the wait longer" in docs
    assert "requests sent sooner are only refused" in docs  # the checklist
    assert "requests sent sooner are refused" in visible_text((await client.get("/")).text)


async def test_rr_public_retry_text_follows_the_retry_strike_setting(app: FastAPI, client: httpx.AsyncClient) -> None:
    """Escalation on, retry strikes off: the ladder sentence stays (it is true), the retry promises go."""
    await _change(app, {"throttle_strike_on_retry": 0})
    for path, claims in RETRY_CLAIMS.items():
        text = visible_text((await client.get(path)).text)
        assert [claim for claim in claims if claim in text] == [], path
    docs = visible_text((await client.get("/docs")).text)
    assert "each strike makes the next wait longer" in docs
    assert "retrying while you are throttled adds no strike right now" in docs
    home = visible_text((await client.get("/")).text)
    assert "going over the limit again makes the next wait longer" in home


async def test_rr_public_privacy_text_matches_the_default_capture(app: FastAPI, client: httpx.AsyncClient) -> None:
    """Plan 16.2 chapter 10 and D8: capture is ON by default (`capture_enabled` 1, refusals always captured,
    `capture_sample_served_pct` 20, 15 minute TTL). A privacy notice must not open with the opposite."""
    settings = app.state.ctx.settings
    assert settings.bool("capture_enabled") is True  # the shipped default: bodies are kept, briefly
    assert settings.float("capture_sample_served_pct") > 0
    text = visible_text((await client.get("/docs")).text)
    start = text.find("for each request roxy records")  # chapter 10's first words (the contents list comes first)
    assert start > 0
    chapter = text[start : text.find("11. security reports", start)]
    print("\nprivacy chapter:", chapter[:600])
    assert "body capture is currently on" in chapter  # the live part of the paragraph says it is on
    assert "bodies are not normally kept" not in chapter
    assert "roxy also keeps the bodies of some requests and answers" in chapter
    assert "refused requests and about 20% of served requests" in chapter
    assert "deleted after 15 minutes" in chapter

    await _change(app, {"capture_enabled": 0})
    text = visible_text((await client.get("/docs")).text)
    start = text.find("for each request roxy records")
    off = text[start : text.find("11. security reports", start)]
    assert "request and answer bodies are not kept: body capture is currently off" in off
    assert "roxy also keeps the bodies" not in off


async def test_rr_public_guide_states_the_url_limit_and_its_414(app: FastAPI, client: httpx.AsyncClient) -> None:
    long_url = "/games.roblox.com/v1/games?universeIds=" + ",".join(str(n) for n in range(1_000_000, 1_000_700))
    refused = await client.get(long_url, headers={"X-Forwarded-For": "203.0.113.120"})
    assert refused.status_code == 414  # the premise: a long id list is refused by Roxy itself, before any upstream call
    limit = f"{app.state.ctx.settings.int('max_url_length'):,}"
    text = visible_text((await client.get("/docs")).text)
    end = text.find("8. good citizen checklist", text.find("roxy's own refusals"))  # the chapter's last paragraph
    chapter_7 = text[text.rfind("7. status codes and what to do", 0, end) : end]  # the heading, not the contents
    assert "413, 431" in chapter_7  # the slice really is the status code table
    print("\nmax_url_length:", limit, "| '414' in chapter 7:", "414" in chapter_7, "| limit in guide:", limit in text)
    assert "414" in chapter_7
    assert limit in text
    assert f"may be up to {limit} characters long; a longer one is answered with 414" in text
    await _change(app, {"max_url_length": 2048})  # the number follows the live setting
    assert "may be up to 2,048 characters long" in visible_text((await client.get("/docs")).text)
