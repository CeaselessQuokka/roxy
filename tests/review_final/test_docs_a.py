"""Final review, lens docs_a: the product's own texts against the code, guide part A (regression tests).

What this is
    One test per finding of `.remake/final_review/find_docs_a.md`: the places where a page, a card help, an empty
    state, a dialog, a catalog text or a runbook says something the code does not do, or where the admin guide's
    chapters (Getting started, Daily routine, the Upstream model chapter, Overview, Recommendations, Health,
    Traffic, Endpoints, Live, Upstream, Egress, Credential) had to work around the product. Each test was a strict
    xfail naming its finding until the final review fixed it; each is a regression test now. The browser half is
    `test_docs_a_e2e.py`.

Why it exists
    The final review rule: a finding without a reproduction is not a finding. For a wrong text the test asserts the
    right text; where a fix could land on either side (the code or the text), the test accepts both.

How it works
    The fixtures of `tests/integration/pages/conftest.py` (the real app in process, a signed-in admin, Roblox played
    by `respx` through `pages_harness.roblox_answer`, a `FakeClock`). Texts are read from the rendered pages and
    fragments where the owner reads them, or from the catalog and docs files they come from. No network.

What to read next
    `.remake/final_review/find_docs_a.md`, `.remake/drafts/open_items.md` (sections g1, g2, g3 and the editor's),
    `.remake/drafts/ADMIN_GUIDE.md`.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from typing import Any

import pytest

import pages_harness
from integration.pages.conftest import anon, page, page_admin, pages_app  # noqa: F401  (the page fixtures)
from pages_harness import parse_html

REPO = Path(__file__).resolve().parents[2]
AUTHENTICATED = "/v1/users/authenticated"


def _account_answer(account: dict[str, Any]) -> Any:
    """A Roblox stand-in whose credential check answers like users.roblox.com: 200 with the account id, or a status."""
    real = pages_harness.roblox_answer

    def answer(host: str, path: str) -> tuple[int, dict[str, str], bytes]:
        if path.endswith(AUTHENTICATED):
            status = int(account.get("status", 200))
            if status != 200:
                return status, {"Content-Type": "application/json"}, b'{"errors":[{"code":0,"message":"Unauthorized"}]}'
            body = {"id": account["id"], "name": "owner_account", "displayName": "owner_account"}
            return 200, {"Content-Type": "application/json"}, json.dumps(body).encode()
        return real(host, path)

    return answer


# ===================================================================================================== docs_a-1


async def test_after_a_replace_the_status_card_never_calls_another_account_the_same(
    page: Any, pages_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`CredentialManager.replace` writes `account_id_fingerprint = NULL`; the probe the replace runs then finds no
    recorded account (`_interpret_probe`: `recorded is None`), records the new account as if it were the old one,
    and `admin/api/credential._account` answers `match: True`, so `credential/status.html` prints the green badge
    "Same account as before". The guide had to tell the owner to write the Account fingerprint down before a renewal
    and compare it by hand (Credential > Replace, step 4), because the badge compares nothing. Plan C1: moving
    between accounts is the account farming pattern Roblox punishes."""
    account: dict[str, Any] = {"id": 11111111}
    monkeypatch.setattr(pages_harness, "roblox_answer", _account_answer(account))
    checked = await page.api("POST", "credential/check")
    assert checked.status_code == 200, checked.text
    before = (await page.doc("/admin/credential/fragment/status")).text()
    assert "Same account as before" in before  # the badge works while nothing changes

    # The account's probe sub-bucket allows one probe at a time (burst 1, finding constraints-6): the replace's own
    # probe gets its slot once the paced interval has passed on the fake clock.
    pages_app.clock.advance(60)
    account["id"] = 22222222  # the cookie pasted below belongs to another Roblox account
    new_value = "DOCSATESTVALUE" + secrets.token_hex(96).upper()
    from roxy.admin.api.credential import REPLACE_CONFIRMATION

    replaced = await page.api(
        "POST", "credential/replace", json={"value": new_value, "confirm": REPLACE_CONFIRMATION, "reason": "renewal"}
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["probe"] is not None  # the replace checked the new cookie at once
    after = (await page.doc("/admin/credential/fragment/status")).text()
    assert "Same account as before" not in after, "another account's cookie is shown as the same account"


# ===================================================================================================== docs_a-2


async def test_an_account_mismatch_is_never_alerted_as_an_expired_token(
    page: Any, pages_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`egress/credential.py _interpret_probe`: a 200 naming another account sets the status REJECTED with
    `account_mismatch` and calls `_alert_rejected("account_mismatch")`, whose summary (the body's first line) is
    always 'An auth token has expired: "<masked>"'. The cookie is valid; the account changed (plan C1: an account
    switch). The subject stays "Token Expired": plan 17.7 keeps v1's subjects exactly (owners filter mail on them)
    and routes "Credential expired or rejected", a different account included (13.2 H-CRED-AUTH), to that alert, so
    only the summary is checked here (skeptic's correction: the first version also asserted on the subject)."""
    account: dict[str, Any] = {"id": 33333333}
    monkeypatch.setattr(pages_harness, "roblox_answer", _account_answer(account))
    manager = pages_app.ctx.egress.credential
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(manager._events, "alert", lambda **fields: sent.append(fields))
    assert (await page.api("POST", "credential/check")).status_code == 200  # the account is recorded
    pages_app.clock.advance(60)  # the next probe's slot in the account's paced probe sub-bucket (constraints-6)
    account["id"] = 44444444  # the same cookie slot now answers for another account
    checked = await page.api("POST", "credential/check")
    assert checked.status_code == 200, checked.text
    assert checked.json()["probe"]["outcome"] == "account_mismatch", checked.text
    mismatch = [item for item in sent if (item.get("fields") or {}).get("result") == "account_mismatch"]
    assert mismatch, sent  # the owner is alerted (critical): good
    assert all(item["subject"] == "Token Expired" for item in mismatch)  # plan 17.7: the v1 subject is kept
    summaries = [str(item["summary"]) for item in mismatch]
    assert not any("xpired" in text for text in summaries), summaries


# ===================================================================================================== docs_a-5


def test_the_texts_never_promise_recommendation_emails_the_defaults_do_not_send() -> None:
    """`config/catalog.py SEVERITY_OPTIONS` (every `insight_<rule>_severity` control, 50 rules): Warn "with the default
    alert settings each new finding is also sent as an alert", Critical "they are alerted at every
    alert_min_severity level". `notify/alerts.py ALERT_SPECS` has no per-recommendation alert at all. The only
    recommendation email is the daily digest, which `alert_digest_hour`'s description promises ("Roxy emails a daily
    digest"), but its spec is `info` without `always_send`, and `Notifier.passes_severity` drops it under the default
    `alert_min_severity` (warn). An owner who forces a rule to Critical "so I never miss it" gets no email at all."""
    from roxy.config import catalog
    from roxy.config.settings.alerts import SETTINGS as ALERT_SETTINGS
    from roxy.notify.alerts import ALERT_SPECS

    per_finding = any("recommend" in kind for kind in ALERT_SPECS if kind != "digest")
    options = {option.value: option.description for option in catalog.SEVERITY_OPTIONS}
    problems = []
    if not per_finding:
        if "sent as an alert" in options["warn"]:
            problems.append("Warn: " + options["warn"])
        if "alerted" in options["critical"]:
            problems.append("Critical: " + options["critical"])
    digest = ALERT_SPECS["digest"]
    default_min = str(catalog.defaults()["alert_min_severity"])
    rank = {"info": 0, "warn": 1, "critical": 2}
    digest_sent = digest.always_send or rank[digest.severity] >= rank[default_min]
    hour = next(spec for spec in ALERT_SETTINGS if spec.key == "alert_digest_hour")
    if not digest_sent and "alert_min_severity" not in hour.description:
        problems.append("alert_digest_hour: " + hour.description)
    assert problems == []


# ===================================================================================================== docs_a-7


async def test_the_reset_drawer_promises_no_undo_the_dashboard_cannot_do(page: Any, pages_app: Any) -> None:
    """`templates/admin/pages/_reset.html` (the inline resets of Overview, Traffic, Live and Endpoints): "A copy of
    metrics.db is taken first, so this can be undone from Data > Backups." `templates/admin/pages/data/backups.html`
    only lists backups and snapshots (no restore action, no route), and docs/RUNBOOKS.md "Restore from backup" covers
    the nightly .zst sets, not `snapshots/reset-<time>-metrics.db`. Undoing really means a whole-file restore on the
    server that also loses everything recorded after the reset; the guide had to say so (Statistics resets).
    Skeptic's correction: `static/js/pages/data.js` ("A snapshot of metrics.db is taken first, so this can be
    undone.") is plan 6.8's own wording and names no place to undo it from, so only the drawer's "from Data >
    Backups" is checked (the first version also required the data.js sentence to go)."""
    await pages_app.seed_traffic()
    drawer = await page.get("/admin/traffic/reset", params={"which": "traffic"}, htmx=True)
    assert drawer.status_code == 200, drawer.text[:300]
    lines = [item.text() for item in parse_html(drawer.text).select(".inline-reset__snapshots li")]
    assert any("metrics.db" in line and not line.startswith("No copy") for line in lines), lines  # a copy is taken
    backups = (await page.fragment("data", "backups")).text
    restorable = "restore" in backups.lower() and "data-api-url" in backups and "/restore" in backups
    promises = [line for line in lines if "undone from Data" in line]
    assert restorable or promises == [], promises


# ===================================================================================================== docs_a-8


async def test_no_text_names_a_send_test_alert_button_that_is_not_there(page: Any, pages_app: Any) -> None:
    """`health/checks.py` H-ALERTS (warn for a non-Discord webhook): "use Send test alert on Settings > Alerts.";
    `config/settings/alerts.py` alert_webhook_enabled notes ("What happens if I change this?"): "The 'Send test
    alert' button on the Settings > Alerts card posts one real low-severity message". No route, template or script
    has such a button (Settings > Alerts holds only settings). The guide had to say "this release has no such button"
    (Getting started, Step 10)."""
    from roxy.config.settings.alerts import SETTINGS as ALERT_SETTINGS

    card = parse_html((await page.fragment("settings", "alerts")).text)
    controls = [node.text() for node in card.select("button")] + [node.text() for node in card.select("a.btn")]
    has_button = any("Send test alert" in text for text in controls)  # the notes' own words are not a button
    checks = (REPO / "src" / "roxy" / "health" / "checks.py").read_text(encoding="utf-8")
    notes = next(spec for spec in ALERT_SETTINGS if spec.key == "alert_webhook_enabled").notes or ""
    mentions = [
        where
        for where, text in (("H-ALERTS", checks), ("alert_webhook_enabled notes", notes))
        if "Send test alert" in text
    ]
    assert has_button or mentions == [], f"named but missing: {mentions}"


# ===================================================================================================== docs_a-10


async def test_a_rotator_park_leaves_no_half_open_breaker_behind(page: Any, pages_app: Any) -> None:
    """`egress/rotator.py record_result` parks the rotator at `rotator_max_failures` and writes the `rotator:streak`
    breaker row with state `open`, failures 0 and no `half_open_at`; `breaker.effective_state` reads such a row as
    HALF_OPEN ("a row without a reopening time can only come from a hand edit"). A later success returns early
    (`self._streak == 0`), so the row stays `open`: the Upstream Breakers card lists "Half-open: one test call
    decides" for the rotator long after the park ended and the rotator works again, and its subtitle counts it. The
    guide had to send the owner to Egress > Sessions instead."""
    pool = pages_app.ctx.egress.rotator
    limit = int(pages_app.ctx.settings.int("rotator_max_failures"))
    for _ in range(limit):
        await pool.record_result(False, "timeout")
    pages_app.clock.advance(float(pages_app.ctx.settings.int("rotator_cooldown_s")) + 600)  # the park ended long ago
    await pool.record_result(True, "ok")  # and the rotator works again
    card = await page.doc("/admin/upstream/fragment/breakers")
    rows = [row.text() for row in card.select("tr") if "rotator" in row.text().lower()]
    assert not any("Half-open" in row for row in rows), rows


# ===================================================================================================== docs_a-11


async def test_the_credential_buckets_are_described_where_and_as_they_are(page: Any, pages_app: Any) -> None:
    """`pages/upstream.py BUCKET_SETTINGS` gives `egress:credential` and `egress:credential:probe` a drawer line
    "change them under 'Settings for this card' on the Buckets card", but `credential_bucket_per_min`,
    `credential_bucket_burst` and `credential_probe_reserved_per_min` are anchored on `credential#budget` only. And
    `pages/credential.py budget_card` labels the `egress:credential` gauge "The account (callers on the allowlist
    and probes)", while `upstream/buckets.py specs_for` sends every probe to `egress:credential:probe`: with D1's
    empty allowlist that gauge never moves although probes run every 30 minutes."""
    drawer = await page.get("/admin/upstream/bucket", params={"key": "egress:credential"}, htmx=True)
    assert drawer.status_code == 200, drawer.text[:300]
    pointer = parse_html(drawer.text).text()
    budget = (await page.doc("/admin/credential/fragment/budget")).text()
    problems = []
    if "on the Buckets card" in pointer:
        problems.append("the drawer sends the credential bucket settings to the Buckets card")
    if "callers on the allowlist and probes" in budget:
        problems.append("the account gauge says probes use it")
    assert problems == []


# ===================================================================================================== docs_a-12


async def test_the_credential_page_names_its_checks_in_words(
    page: Any, pages_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`egress/credential.py _interpret_probe` stores `rejected_401` or `rejected_403` as the last probe's result;
    `pages/credential.py PROBE_WORDS` has only `rejected`, so `_probe_words` prints "rejected 401" where the owner
    should read "Rejected: the cookie expired or was revoked" (the moment the Token Expired alert sends them here).
    And `templates/admin/pages/credential.html` links `term("probe", "probes")`, whose glossary meaning is "A request
    that looks like scanning or attacking"."""
    monkeypatch.setattr(pages_harness, "roblox_answer", _account_answer({"status": 401}))
    checked = await page.api("POST", "credential/check")
    assert checked.status_code == 200, checked.text
    status = (await page.doc("/admin/credential/fragment/status")).text()
    assert "rejected 401" in status or "Rejected: the cookie expired or was revoked" in status, status[:2000]
    doc = await page.doc("/admin/credential")
    attack = [link.text() for link in doc.select("a.gloss") if "scanning or attacking" in (link.get("data-def") or "")]
    problems = []
    if "Rejected: the cookie expired or was revoked" not in status:
        problems.append("the Last probe line reads 'rejected 401'")
    if attack:
        problems.append(f"credential checks link the attack probe term: {attack}")
    assert problems == []


# ===================================================================================================== docs_a-13


async def test_the_overview_says_what_its_cards_do(page: Any, pages_app: Any) -> None:
    """`metrics/read_dashboard.py NOTABLE_EVENT_TYPES` lists no alert, no settings or rule change and no manual ban,
    yet the registry help of `overview#events` ("Bans, cooldowns, breakers, alerts and configuration changes.") and
    its empty state ("Bans, Roblox cooldowns, open breakers, alerts and configuration changes are listed here")
    promise them: an empty list does not mean no alert was sent or no setting changed. `overview.html`'s How to read
    says "The page keeps itself current from the live event stream", but Visitors, Top endpoints, Top places and
    Recent notable events have no `refresh_on` and no live refresh. The Workers item says "a heartbeat in the last
    30 seconds" while `scheduler/heartbeat.py HEARTBEAT_STALE_S` is 20."""
    from roxy.admin.pages import overview, registry
    from roxy.metrics.read_dashboard import NOTABLE_EVENT_TYPES
    from roxy.scheduler.heartbeat import HEARTBEAT_STALE_S

    problems = []
    lists_alerts = any("alert" in kind for kind in NOTABLE_EVENT_TYPES)
    lists_config = any(word in kind for kind in NOTABLE_EVENT_TYPES for word in ("setting", "config", "rule_change"))
    help_text = registry.card("overview", "events").help
    events = (await page.fragment("overview", "events")).text  # an empty range: the empty state
    for where, text in (("registry help", help_text), ("empty state", events)):
        if "alerts" in text and not lists_alerts:
            problems.append(f"{where} promises alerts")
        if "configuration changes" in text and not lists_config:
            problems.append(f"{where} promises configuration changes")
    still = [
        card.spec.id
        for card in overview.page.cards()
        if not card.refresh_on and card.live_refresh_s is None and not card.spec.fragment_only
    ]
    how_to_read = (await page.get("/admin/overview")).text
    if "keeps itself current" in how_to_read and still:
        problems.append(f"'keeps itself current' but these cards never refresh: {still}")
    status = (await page.fragment("overview", "status")).text
    if f"in the last {int(HEARTBEAT_STALE_S)} seconds" not in status:
        problems.append(f"Workers does not say {int(HEARTBEAT_STALE_S)} seconds")
    assert problems == []


# ===================================================================================================== docs_a-14


def test_the_latency_card_helps_say_what_the_cards_measure() -> None:
    """`registry.py` traffic#latency: "How long requests took, Roxy's own time and Roblox's separately." The card
    shows one total per caller request, Roblox's time included (`traffic_api.LATENCY_NOTE`), plus queue wait p95;
    nothing is split into Roxy's and Roblox's time. upstream#latency: "How long Roblox took to answer.", while
    `upstream_api.latency_answer` measures "caller latency of requests that went to Roblox: queue wait plus every
    attempt", so a slow Roxy queue reads as a slow Roblox in the card's help."""
    from roxy.admin.pages import registry

    traffic = registry.card("traffic", "latency").help
    upstream = registry.card("upstream", "latency").help
    problems = []
    if "separately" in traffic:
        problems.append("traffic#latency: " + traffic)
    if upstream.strip() == "How long Roblox took to answer.":
        problems.append("upstream#latency: " + upstream)
    assert problems == []


# ===================================================================================================== docs_a-15


def test_the_live_setting_texts_say_what_capture_and_the_ring_do() -> None:
    """`metrics/capture.py CapturePolicy.wants`: "Refusals and failures always; served requests at
    sample_served_pct". The catalog says refusals only: capture_enabled if_enabled ("Every refused request and a
    sample of served requests"), capture_sample_served_pct (description "Refused requests are always captured",
    if_lowered "0 captures refusals only"); failed requests' bodies, with caller data, are stored too. And
    live_tail_buffer: "so opening the page shows recent history at once instead of an empty list", "0 keeps none,
    so only requests that arrive while the page is open appear", but the Live page replays the newest `SEED_ROWS`
    (40) live rows of the shared metrics.db (`pages/live.py seed_after`) whatever this setting says; the ring only
    serves the API's this-worker fallback, the drawer lookup and the capture card's This worker line."""
    from roxy.config.settings.metrics import SETTINGS as METRIC_SETTINGS

    specs = {spec.key: spec for spec in METRIC_SETTINGS}
    problems = []
    enabled = specs["capture_enabled"].if_enabled or ""
    sample = specs["capture_sample_served_pct"]
    for where, text in (
        ("capture_enabled if_enabled", enabled),
        ("capture_sample_served_pct description", sample.description),
        ("capture_sample_served_pct if_lowered", sample.if_lowered or ""),
    ):
        if re.search(r"refus", text, re.I) and not re.search(r"fail", text, re.I):
            problems.append(f"{where}: {text}")
    ring = specs["live_tail_buffer"]
    if "instead of an empty list" in ring.description or "only requests that arrive" in (ring.if_lowered or ""):
        problems.append("live_tail_buffer: " + ring.description)
    assert problems == []


# ===================================================================================================== docs_a-17


async def test_the_health_credential_setting_says_which_runs_include_the_check(page: Any, pages_app: Any) -> None:
    """`config/settings/alerts.py` health_auto_include_credential: "Runs you start yourself always include them".
    The Overview's Check Proxy Health posts `include_credential=false` (`overview.html`), the palette's health run
    does the same (DESIGN 15.5), and the Health page's Run card has an "Include the credential check" box. The
    guide had to describe the three cases itself."""
    from roxy.config.settings.alerts import SETTINGS as ALERT_SETTINGS

    spec = next(spec for spec in ALERT_SETTINGS if spec.key == "health_auto_include_credential")
    overview = parse_html((await page.get("/admin/overview")).text)
    hidden = overview.select_one('input[name="include_credential"]')
    assert hidden is not None
    assert hidden.get("value") == "false"  # the Overview's run leaves the check out
    assert "always include them" not in spec.description, spec.description


# ===================================================================================================== docs_a-18


def test_the_emailed_code_lifetime_text_matches_the_real_lifetime() -> None:
    """`admin/auth/flow.py _send_email_code`: the code's expiry is `two_fa_expiration`, but the sign-in transaction
    that holds it lives `challenge_expiration` and the countdown is `min(lifetime, challenge_expiration)`: 2 minutes
    at the defaults. The setting's description ("How long an emailed login code stays valid after it is sent") reads
    as 5 minutes, at the D5 bootstrap sign-in of the cutover too. The guide had to explain the shorter-of rule
    (Getting started, Step 2)."""
    from roxy.config import catalog
    from roxy.config.settings.admin_security import SETTINGS as SECURITY_SETTINGS

    spec = next(spec for spec in SECURITY_SETTINGS if spec.key == "two_fa_expiration")
    defaults = catalog.defaults()
    shorter = int(defaults["challenge_expiration"]) < int(defaults["two_fa_expiration"])
    assert not shorter or "challenge_expiration" in spec.description, spec.description
