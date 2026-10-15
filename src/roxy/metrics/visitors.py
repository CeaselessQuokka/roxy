"""Visitor classification and page visit counting for the public pages (parity rows 19 and 130).

What this is
    `classify(user_agent)` sorts a visitor of Roxy's own public pages into human, crawler or unknown, and
    `visit_event(...)` turns a page visit into the event the recorder stores, so the Overview "Visitors" card
    can show Human Visitors, Crawler Visitors, Unknown Visitors, Home Page Visits, Admin Page Visits and
    robots.txt Crawls for any time range.

Why it exists
    v1 kept five lifetime counters in memory (`visitor_counts`, `page_visits`); v2 keeps them time-bucketed
    (row 130) so "how many people looked at the site this week" has an answer. v1 counted a request with no
    User-Agent as a crawler; plan row 19 changes that to "unknown", because an empty header says nothing about
    who sent it.

How it works
    - `classify` lowercases the User-Agent and checks v1's crawler markers (`config.CRAWLER_USER_AGENT_MARKERS`,
      same list, same order) as substrings. Empty or whitespace-only is `unknown`.
    - A visit is an aggregated event (`type = "visit"`, detail `{page, visitor}`): the recorder sums visits per
      minute in memory and writes one row per page, class and minute, so a crawler hammering `/` costs one row a
      minute, not one per request.
    - v1 subtracted one admin visit after a successful login without the `roxy_admin_seen` cookie (the owner's
      own visit). `admin_visit_discount()` records the same correction as a visit with count -1; the visitor
      query clamps the admin total at zero like v1 did.

What to read next
    `roxy/metrics/recorder.py` (`record_visit`), `roxy/metrics/queries.py` (`visitor_kpis`), and
    `roxy/metrics/security_events.py` (robots.txt and sitemap crawls per IP).
"""

from __future__ import annotations

from typing import Final

CRAWLER_USER_AGENT_MARKERS: Final[tuple[str, ...]] = (
    "bot",
    "crawl",
    "spider",
    "slurp",
    "curl",
    "wget",
    "python",
    "go-http",
    "java",
    "okhttp",
    "headless",
    "scrapy",
    "httpclient",
    "libwww",
    "feedfetcher",
    "facebookexternalhit",
    "ahrefs",
    "semrush",
    "bingpreview",
    "node-fetch",
    "axios",
    "postman",
    "insomnia",
)
"""v1 `config.CRAWLER_USER_AGENT_MARKERS`, same order (the order does not change the result)."""

HUMAN = "human"
CRAWLER = "crawler"
UNKNOWN = "unknown"
VISITOR_CLASSES: Final[tuple[str, ...]] = (HUMAN, CRAWLER, UNKNOWN)

PAGE_HOME = "home"
PAGE_ADMIN = "admin"
PAGE_ROBOTS = "robots"
PAGE_SITEMAP = "sitemap"
PAGE_DOCS = "docs"
PAGE_STATUS = "status"
PAGES: Final[tuple[str, ...]] = (PAGE_HOME, PAGE_ADMIN, PAGE_ROBOTS, PAGE_SITEMAP, PAGE_DOCS, PAGE_STATUS)
"""Pages whose visits are counted (v1 counted home, admin and robots; the others are new v2 pages, counted apart
so the v1 tiles keep their meaning)."""

VISIT_EVENT = "visit"


def classify(user_agent: str | None) -> str:
    """`human`, `crawler` or `unknown` (empty User-Agent; v1 said crawler, plan row 19 says unknown)."""
    ua = (user_agent or "").strip().lower()
    if not ua:
        return UNKNOWN
    return CRAWLER if any(marker in ua for marker in CRAWLER_USER_AGENT_MARKERS) else HUMAN


def visit_detail(page: str, user_agent: str | None) -> dict[str, str]:
    """The event detail for one visit. Only the home page classifies visitors (v1 `index.py:145`); other pages
    record `visitor = ""` so the class totals stay comparable with v1's."""
    page = page if page in PAGES else "other"
    return {"page": page, "visitor": classify(user_agent) if page == PAGE_HOME else ""}


def admin_visit_discount() -> dict[str, str]:
    """Detail of the -1 correction recorded after the owner's own login (v1 `decrement_admin_visit`)."""
    return {"page": PAGE_ADMIN, "visitor": ""}
