"""robots.txt, sitemap.xml, the build date, the recorder calls and the live limit texts (plan 4.1 rows 13, 19).

What this is
    Unit tests for `robots_bytes`, `build_sitemap`, `build_date`, `live_limits` and the number wording helpers in
    `roxy.public.pages`, plus a check that every recorder call the public site makes binds to the real
    `MetricsRecorder`.

Why it exists
    robots.txt must stay byte for byte v1's, and sitemap.xml must keep v1's bytes for `/` while adding `/docs`
    and `/status` with a build-time `lastmod` (row 13). Visits feed the Overview visitor tiles (rows 19 and 130);
    the recorder classifies the visitor itself (`metrics/visitors.py`), so the pages pass only the page and the
    User-Agent. Limits read "1 request", never "1 requests".

How it works
    Compares with the v1 files copied into tests/fixtures/v1/ and calls the helpers with crafted values.

What to read next
    `roxy/public/pages.py`, `.remake/v1notes/public_ops.md` section 6.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from roxy.public import pages

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "v1"


def test_robots_txt_is_v1_byte_for_byte() -> None:
    assert pages.robots_bytes() == (FIXTURES / "robots.txt").read_bytes()
    assert len(pages.robots_bytes()) == 120


def test_sitemap_keeps_v1_bytes_and_adds_docs_and_status() -> None:
    v1 = (FIXTURES / "sitemap.xml").read_text(encoding="utf-8")
    v2 = pages.build_sitemap("2026-07-08").decode("utf-8")
    # v1's whole document, with the two new entries inserted before the closing tag.
    head, _, _ = v1.rpartition("</urlset>")
    assert v2.startswith(head)
    assert v2.endswith("</urlset>\n")
    extra = v2[len(head) :]
    assert "\t\t<loc>https://roxytheproxy.com/docs</loc>\n" in extra
    assert "\t\t<loc>https://roxytheproxy.com/status</loc>\n" in extra
    assert extra.count("<lastmod>2026-07-08</lastmod>") == 2
    without_status = pages.build_sitemap("2026-07-08", include_status=False).decode("utf-8")
    assert "/status" not in without_status
    assert "/docs" in without_status


def test_build_date_is_a_w3c_date_from_the_newest_public_file() -> None:
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", pages.build_date())
    newest = max(path.stat().st_mtime for path in [pages.USER_GUIDE_PATH, Path(pages.__file__)])
    assert pages.build_time() >= newest


def test_calls_fit_the_metrics_recorder() -> None:
    """The arguments the public pages and /csp-report pass must bind to the real recorder's methods (P7)."""
    import inspect

    from roxy.metrics import visitors
    from roxy.metrics.recorder import MetricsRecorder

    recorder = MetricsRecorder.__new__(MetricsRecorder)  # bound methods, no databases needed
    inspect.signature(recorder.record_visit).bind(pages.PAGE_DOCS, "Mozilla/5.0")
    inspect.signature(recorder.record_crawl).bind("127.0.0.1", "/robots.txt", "curl/8.5.0")
    inspect.signature(recorder.record_event).bind("csp_report", "info", None, {"document": "/"}, aggregate=True)
    # Every page name the site sends is one the recorder counts on its own (not lumped into "other").
    for page in (pages.PAGE_HOME, pages.PAGE_DOCS, pages.PAGE_STATUS, pages.PAGE_ROBOTS, pages.PAGE_SITEMAP):
        assert page in visitors.PAGES


@pytest.mark.parametrize(
    ("value", "singular", "expected"),
    [(1, "request", "1 request"), (0, "request", "0 requests"), (2500, "second", "2,500 seconds")],
)
def test_count_text(value: int, singular: str, expected: str) -> None:
    assert pages.count_text(value, singular) == expected


def test_live_limits_read_as_singular_for_one(catalog_get: Callable[..., Callable[[str], Any]]) -> None:
    one = pages.live_limits(catalog_get(allowed_requests_per_minute=1, throttle_reset_duration=1))
    assert (one.requests_text, one.window_text) == ("1 request", "1 second")
    assert "every 1 second." in one.pacing_rule
    fixed = pages.live_limits(catalog_get(throttle_reset_duration=1, throttle_window_mode="fixed"))
    assert "closes 1 second later" in fixed.pacing_rule
    place = pages.live_limits(catalog_get(place_limit_enabled=1, place_limit_per_minute=1))
    assert "at most 1 request per minute" in place.place_limit_rule


def test_live_limits_texts(catalog_get: Callable[..., Callable[[str], Any]]) -> None:
    limits = pages.live_limits(catalog_get())
    assert (limits.requests_per_window, limits.window_seconds, limits.flood_per_minute) == (10, 50, 300)
    assert limits.pace_seconds == "5"
    assert "every 5 seconds" in limits.pacing_rule
    # Owner change 2026-10-07 (D10 reversed): every request counts by default, cached or not, and the page says
    # why: a cache hit still costs Roxy CPU, memory and bandwidth, and one allowance per caller keeps Roxy fair.
    assert limits.cache_hits_count is True
    assert limits.cache_hits_rule.startswith("Every request counts toward this limit, cached or not.")
    assert pages.CACHE_HITS_WHY in limits.cache_hits_rule
    for reason in ("CPU, memory and bandwidth", "one shared allowance per caller", "fair for everyone"):
        assert reason in pages.CACHE_HITS_WHY
    assert limits.cache_hits_faq.startswith("Every request counts toward your per-IP limit, cached or not")
    assert pages.CACHE_HITS_WHY in limits.cache_hits_faq
    assert "do not count" not in limits.cache_hits_rule + limits.cache_hits_faq
    assert "currently off" in limits.place_limit_rule

    other = pages.live_limits(
        catalog_get(
            allowed_requests_per_minute=4,
            throttle_reset_duration=10,
            throttle_window_mode="fixed",
            throttle_count_cache_hits=0,
            place_limit_enabled=1,
            place_limit_per_minute=1500,
        )
    )
    assert other.pace_seconds == "2.5"
    assert "closes 10 seconds later" in other.pacing_rule
    # An admin may still switch counting off; the sentences then say so, and that the flood limit still counts.
    assert "Right now, requests Roxy answers from its cache do not count toward this limit" in other.cache_hits_rule
    assert "flood limit" in other.cache_hits_rule
    assert "do not count toward your per-IP limit right now" in other.cache_hits_faq
    assert "Every request counts" not in other.cache_hits_rule + other.cache_hits_faq
    assert pages.CACHE_HITS_WHY not in other.cache_hits_rule + other.cache_hits_faq
    assert "1,500 requests per minute" in other.place_limit_rule
    assert "counted for each network its servers use" in other.place_limit_rule  # place_limit_key=place_prefix
    shared = pages.live_limits(catalog_get(place_limit_enabled=1, place_limit_key="place"))
    assert "shared by all of its servers" in shared.place_limit_rule
    assert "network" not in shared.place_limit_scope


def test_number_formatting() -> None:
    assert pages.fmt_int(1234567) == "1,234,567"
    assert pages.fmt_number(5.0) == "5"
    assert pages.fmt_number(0.25) == "0.25"
    assert pages.fmt_number(1 / 3) == "0.33"
