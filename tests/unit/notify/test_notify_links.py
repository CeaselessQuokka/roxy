"""Alert links a mail client can open (plan 17.7 "Links use ROXY_SITE_ORIGIN"; final review brain-13).

What this is
    Tests of `notify.notifier.page_link` (a dashboard path in an alert becomes absolute with the site origin, in the
    email's "Where:" line and in the webhook payload) and of `AlertSpec.page` (the default page of an alert type
    whose producer passes no link: `all_unavailable` links the Upstream page).

Why it exists
    The auto-apply rollback alerts linked a bare `/admin/recommendations` path and "all upstream methods
    unavailable" linked nothing, so the owner could not open the page from the mail.

How it works
    `make_alert` and the pure renderers; no database, no network.

What to read next
    `roxy/notify/notifier.py` (`render_email`, `render_webhook`, `page_link`), `roxy/notify/alerts.py`.
"""

from __future__ import annotations

from roxy.notify.alerts import ALERT_SPECS, make_alert
from roxy.notify.notifier import page_link, render_email, render_webhook

ORIGIN = "https://roxy.example"
NOW = 1_791_385_200.0


def _where(body: str) -> str:
    return next(line for line in body.splitlines() if line.startswith("Where: "))


def test_page_link_makes_a_dashboard_path_absolute() -> None:
    assert page_link(ORIGIN, "/admin/upstream") == f"{ORIGIN}/admin/upstream"
    assert page_link(ORIGIN + "/", "/admin/upstream#buckets") == f"{ORIGIN}/admin/upstream#buckets"
    assert page_link(ORIGIN, f"{ORIGIN}/admin/system#errors") == f"{ORIGIN}/admin/system#errors"  # kept as it is
    assert page_link("", "/admin/upstream") == "/admin/upstream"  # no origin configured: the path is all there is
    assert page_link(ORIGIN, "//elsewhere.example/x") == "//elsewhere.example/x"  # never glued to the origin
    assert page_link(ORIGIN, None) is None
    assert page_link(ORIGIN, "") is None


def test_an_alert_without_a_link_gets_its_types_page() -> None:
    assert ALERT_SPECS["all_unavailable"].page == "/admin/upstream"
    alert = make_alert("all_unavailable", summary="No egress path can reach Roblox.")
    assert alert.link == "/admin/upstream"
    _subject, body = render_email(alert, suppressed=0, now=NOW, tz_name="UTC", site_origin=ORIGIN)
    assert _where(body) == f"Where: {ORIGIN}/admin/upstream"
    payload = render_webhook(alert, suppressed=0, now=NOW, tz_name="UTC", site_origin=ORIGIN)
    assert payload["link"] == f"{ORIGIN}/admin/upstream"
    assert payload["text"].endswith(f"\n{ORIGIN}/admin/upstream")
    # A producer's own link wins over the type's page.
    own = make_alert("all_unavailable", summary="s", link=f"{ORIGIN}/admin/egress")
    assert own.link == f"{ORIGIN}/admin/egress"


def test_an_alert_type_without_a_page_keeps_where_n_a() -> None:
    alert = make_alert("digest", summary="s", n=0, day="2026-10-13")
    assert alert.link is None
    _subject, body = render_email(alert, suppressed=0, now=NOW, tz_name="UTC", site_origin=ORIGIN)
    assert _where(body) == "Where: n/a"
