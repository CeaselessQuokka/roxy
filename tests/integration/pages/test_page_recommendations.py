"""The Recommendations page (`/admin/recommendations`, plan 14.1, 11.2 to 11.4): integration tests.

What this is
    Tests against the real app: recommendations written by the engine's own writer (`write_recommendation`, as the
    harness's `seed_recommendation` does) with hostile text in every field a rule builds from callers' paths, and
    actions taken through the Recommendations API the page's forms post to. They prove: every page, fragment, drawer
    and preview route answers 200 for an admin and redirects otherwise; every registry card (the 50 rule drawers too)
    and every inline setting of its anchors is there; the list's numbers and rows equal the API's for the same
    filters; the drawer shows the evidence with charts and data tables, the exact diff ("exactly this endpoint" for an
    anchored single-endpoint rule), the D7 badge or why auto-apply skips it, the watch window and its rollback state;
    the preview's Apply form carries the API's own digest; apply, undo, snooze and dismiss work through the API with
    CSRF, a changed recommendation is refused until previewed again, and a security change needs a fresh second
    factor; hostile text stays inert; no filter or bad value fails the page; an empty database explains itself.

Why it exists
    The P11 page rules for the Recommendations page; `tests/e2e/test_page_recommendations.py` proves the flows in
    Chromium, at phone size too.

What to read next
    `roxy/admin/pages/recommendations.py`, `roxy/admin/api/recommendations.py`, `tests/integration/pages/
    test_page_audit.py`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.recommendations import change_row, evidence_charts, exact_endpoint
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.ids import new_id
from roxy.core.style_guard import find_style_issues
from roxy.insights import simulate
from roxy.insights.engine import write_recommendation
from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint

PAGE = "/admin/recommendations"
VISIBLE = [card.id for card in registry.cards_for("recommendations") if not card.fragment_only]
RULE_CARDS = [card.id for card in registry.cards_for("recommendations") if card.id.startswith("rule-")]
TEMPLATE = "games.roblox.com/v1/games/{universeId}/votes"


async def seed(
    pages_app: Any,
    *,
    rule_id: str = "UP-429-ENDPOINT",
    severity: str = "warn",
    changes: list[ProposedChange] | None = None,
    subject: str = "",
    details: dict[str, Any] | None = None,
    explanation: str = "",
    safe_auto: bool = False,
) -> str:
    """One open recommendation written by the engine's own writer (hostile text where rules quote callers)."""
    clock = pages_app.clock
    now = clock.now()
    spec = INSIGHT_RULES[rule_id]
    subject = subject or f"games.roblox.com/v1/games/{HOSTILE['img']}"
    evidence = Evidence(window_from=now - 3600, window_to=now, sample_size=120).add("roblox_429", 120, "responses")
    evidence.add("share_of_all_roblox_429", 0.71)
    evidence.links.append("/admin/upstream#429-timeline")
    evidence.links.append(HOSTILE["js_url"])
    evidence.details.update(details or {})
    rec = Recommendation(
        rule_id=rule_id,
        family=spec.family,
        subject=subject,
        title="Roblox refuses " + HOSTILE["script"],
        severity=severity,
        confidence="high",
        explanation=explanation or ("Plain words " + HOSTILE["js_url"]),
        evidence=evidence,
        changes=changes if changes is not None else [ProposedChange("setting", key="cache_ttl_seconds", current=180, proposed=300)],
        expected_impact="Fewer calls " + HOSTILE["img"],
        risk="low",
        safe_auto=safe_auto,
    )
    rec.id = new_id("rec", clock)
    rec.fingerprint = make_fingerprint(rule_id, subject)
    rec.computed_severity = severity
    rec.state = "open"
    rec.created_at = rec.updated_at = now
    rec.expires_at = now + 7 * 86_400
    rec.dry_run_available = simulate.can_simulate(rec)
    await pages_app.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    return str(rec.id)


async def test_every_route_needs_a_signed_in_admin(anon: Any, pages_app: Any) -> None:
    rec_id = await seed(pages_app)
    paths = [
        PAGE,
        *(f"{PAGE}/fragment/{card}" for card in [*VISIBLE, RULE_CARDS[0]]),
        f"{PAGE}/detail?rec={rec_id}",
        f"{PAGE}/preview?rec={rec_id}",
        f"{PAGE}/{rec_id}",
    ]
    for path in paths:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_registry_card_and_inline_setting_is_there(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    doc = await page.doc(PAGE)
    for card in VISIBLE:
        assert doc.select_one(f"section#{card}[data-card]") is not None, card
    assert doc.select_one('#list [data-table="recommendations"]') is not None
    assert not doc.select("[data-card-error]")
    assert len(doc.select("h1")) == 1
    for card in VISIBLE:
        fragment = await page.fragment("recommendations", card)
        assert fragment.status_code == 200, card
        assert "data-card-error" not in fragment.text, (card, fragment.text[:400])
        anchor = registry.anchor("recommendations", card)
        fdoc = parse_html(fragment.text)
        for spec in registry.settings_for(anchor):
            assert fdoc.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card, spec.key)
    assert len(RULE_CARDS) == len(INSIGHT_RULES)
    for card in RULE_CARDS:
        fragment = await page.fragment("recommendations", card)
        assert fragment.status_code == 200, card
        fdoc = parse_html(fragment.text)
        assert fdoc.select_one(f"#{card}[data-rule]") is not None, card
        for spec in registry.settings_for(registry.anchor("recommendations", card)):
            assert fdoc.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card, spec.key)
    tables = {
        "history": "recommendation_actions",
        "rules": "recommendation_rules",
    }
    for card, name in tables.items():
        fdoc = parse_html((await page.fragment("recommendations", card)).text)
        assert fdoc.select_one(f'[data-table="{name}"]') is not None, card


async def test_the_list_equals_the_api_for_the_same_filters(page: Any, pages_app: Any) -> None:
    await seed(pages_app, severity="critical")
    await seed(pages_app, severity="info", rule_id="CACHE-LOW-HIT", subject="users.roblox.com/v1/users")
    for params in (
        {},
        {"severity": "critical"},
        {"family": "cache"},
        {"rule": "CACHE-LOW-HIT"},
        {"state": "all"},
        {"q": "users.roblox"},
    ):
        api = (await page.api("GET", "recommendations", params=params)).json()
        doc = await page.doc(f"{PAGE}/fragment/list", params=params)
        rows = [row.get("data-row-id") for row in doc.select("tbody tr[data-row-id]")]
        assert rows == [f"rec-{item['id']}" for item in api["items"]], params
    full = await page.doc(PAGE)
    assert "2 open: 1 critical, 0 warnings, 1 info" in full.select_one("#list").text()


async def test_the_drawer_shows_evidence_diff_actions_and_stays_inert(page: Any, pages_app: Any, inert: Any) -> None:
    timeline = {"2026-10-10T12:00:00Z": 3, "2026-10-10T12:01:00Z": 9, "2026-10-10T12:02:00Z": 4}
    rec_id = await seed(
        pages_app,
        details={"timeline": timeline, "sample_paths": [HOSTILE["img"], HOSTILE["js_url"]]},
        changes=[
            ProposedChange(
                "rule_upsert",
                table="rules_cache",
                match=simulate.template_match(TEMPLATE),
                proposed={"ttl": 300, "pattern": HOSTILE["img"]},
            )
        ],
    )
    response = await page.get(f"{PAGE}/detail", params={"rec": rec_id})
    assert response.status_code == 200
    inert(response.text, "recommendation drawer")
    assert find_style_issues(response.text, "drawer") == []
    doc = parse_html(response.text)
    root = doc.select_one(f'[data-rec-detail="{rec_id}"]')
    assert root is not None
    assert HOSTILE["script"] in root.select_one(".rec-detail__title").text()
    assert "Exactly this endpoint" in root.text()
    assert TEMPLATE.replace("{universeId}", "{segment}") in root.text()
    chart = root.select_one(".rec-chart")
    assert chart is not None
    assert chart.select_one("svg.spark") is not None
    assert len(chart.select("tbody tr")) == len(timeline)
    links = [a.get("href") for a in root.select(".rec-links a")]
    assert links == ["/admin/upstream#429-timeline"]  # the javascript: link is dropped, never a link
    assert root.select_one('[data-action="recommendation-preview"]').get("hx-get").startswith(f"{PAGE}/preview?rec=")
    forms = {form.get("data-api-url") for form in root.select("form[data-api-form]")}
    base = f"/admin/api/v1/recommendations/{rec_id}"
    assert {f"{base}/snooze", f"{base}/dismiss"} <= forms
    assert root.select_one(f'form[data-api-url="{base}/undo"]') is None  # not applied: no undo
    assert "Undo" not in [n.text() for n in root.select(".rec-form__title")]
    reasons = [o.get("value") for o in root.select('select[name="reason"] option')]
    assert reasons == ["not_accurate", "intended_behavior", "will_handle_manually", "other"]


async def test_the_preview_carries_the_api_digest_and_the_requirements(page: Any, pages_app: Any) -> None:
    rec_id = await seed(pages_app)
    api = (await page.api("GET", f"recommendations/{rec_id}/preview")).json()
    response = await page.get(f"{PAGE}/preview", params={"rec": rec_id, "window": "6h"})
    assert response.status_code == 200
    doc = parse_html(response.text)
    form = doc.select_one("form.rec-apply")
    assert form.get("data-api-url") == f"/admin/api/v1/recommendations/{rec_id}/apply"
    assert form.select_one('input[name="changes_digest"]').get("value") == api["changes_digest"]
    assert doc.select_one('[data-preview-window="6h"]') is not None
    assert form.select_one('[data-confirm-field][hidden] input[name="confirm_high_risk"]') is not None
    bad = await page.get(f"{PAGE}/preview", params={"rec": rec_id, "window": "forever"})
    assert "not offered" in bad.text


async def test_apply_undo_snooze_and_dismiss_through_the_api(page: Any, pages_app: Any) -> None:
    rec_id = await seed(pages_app)
    digest = (await page.api("GET", f"recommendations/{rec_id}/preview")).json()["changes_digest"]
    refused = await page.api("POST", f"recommendations/{rec_id}/apply", json={"changes_digest": digest}, csrf=False)
    assert refused.status_code == 403
    stale = await page.api("POST", f"recommendations/{rec_id}/apply", json={"changes_digest": "0" * 16})
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "changed_since_preview"
    applied = await page.api(
        "POST", f"recommendations/{rec_id}/apply", json={"changes_digest": digest, "reason": "From the page test"}
    )
    assert applied.status_code == 200, applied.text
    assert pages_app.ctx.settings.int("cache_ttl_seconds") == 300
    doc = parse_html((await page.get(f"{PAGE}/detail", params={"rec": rec_id})).text)
    assert "Applied" in doc.select_one(".rec-detail__lead").text()
    assert doc.select_one(f'form[data-api-url="/admin/api/v1/recommendations/{rec_id}/undo"]') is not None
    assert doc.select_one('[data-why-not="apply"]') is not None
    assert "Applied" in doc.select_one(".rec-history").text()
    undone = await page.api("POST", f"recommendations/{rec_id}/undo", json={"reason": "Back"})
    assert undone.status_code == 200, undone.text
    other = await seed(pages_app, subject="users.roblox.com/v1/users")
    snoozed = await page.api("POST", f"recommendations/{other}/snooze", json={"duration": "1h"})
    assert snoozed.status_code == 200, snoozed.text
    third = await seed(pages_app, subject="thumbnails.roblox.com/v1/x")
    dismissed = await page.api(
        "POST", f"recommendations/{third}/dismiss", json={"reason": "other", "text": "Handled " + HOSTILE["img"]}
    )
    assert dismissed.status_code == 200, dismissed.text
    history = await page.doc(f"{PAGE}/fragment/history")
    words = history.text()
    for action in ("Applied", "Undone", "Snoozed", "Dismissed"):
        assert action in words, action
    listed = await page.doc(f"{PAGE}/fragment/list", params={"state": "dismissed"})
    assert listed.select_one(f'tr[data-row-id="rec-{third}"]') is not None


async def test_a_security_change_needs_a_fresh_second_factor(page: Any, pages_app: Any) -> None:
    rec_id = await seed(
        pages_app,
        rule_id="SEC-DEFAULTS",
        changes=[ProposedChange("setting", key="admin_session_idle_timeout_s", current=900, proposed=600)],
    )
    preview = await page.get(f"{PAGE}/preview", params={"rec": rec_id})
    assert "asks for your second factor" in preview.text
    digest = (await page.api("GET", f"recommendations/{rec_id}/preview")).json()["changes_digest"]
    page.make_mfa_stale()
    assert (await pages_app.harness.login(page.admin)).status_code == 200  # the clock jump ended the old session
    page.make_mfa_stale()
    refused = await page.api("POST", f"recommendations/{rec_id}/apply", json={"changes_digest": digest})
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "reauth_required"
    await page.fresh_mfa()
    done = await page.api("POST", f"recommendations/{rec_id}/apply", json={"changes_digest": digest})
    assert done.status_code == 200, done.text


async def test_the_watch_window_shows_its_rollback_reason_as_text(page: Any, pages_app: Any, inert: Any) -> None:
    rec_id = await seed(pages_app)
    digest = (await page.api("GET", f"recommendations/{rec_id}/preview")).json()["changes_digest"]
    assert (await page.api("POST", f"recommendations/{rec_id}/apply", json={"changes_digest": digest})).status_code == 200
    result = json.dumps({"rollback_refused": "Refused for " + HOSTILE["img"]})
    await pages_app.ctx.dbs.metrics.write(
        lambda conn: conn.execute(
            "UPDATE recommendation_watches SET state = 'watching', result_json = ? WHERE recommendation_id = ?",
            (result, rec_id),
        )
    )
    response = await page.get(f"{PAGE}/detail", params={"rec": rec_id})
    inert(response.text, "watch window")
    doc = parse_html(response.text)
    rollback = doc.select_one('[data-rollback="refused"]')
    assert rollback is not None
    assert "The change is still in place" in rollback.text()
    assert HOSTILE["img"] in rollback.text()


async def test_auto_apply_badges_say_why(page: Any, pages_app: Any) -> None:
    safe = await seed(pages_app, safe_auto=True, subject="a")
    wide = await seed(pages_app, explanation="It is busy. " + simulate.WIDE_PATTERN_NOTE, subject="b")
    safe_doc = parse_html((await page.get(f"{PAGE}/detail", params={"rec": safe})).text)
    assert "Safe to auto-apply" in safe_doc.select_one(".rec-detail__auto").text()
    wide_doc = parse_html((await page.get(f"{PAGE}/detail", params={"rec": wide})).text)
    note = wide_doc.select_one(".rec-detail__auto").text()
    assert "Not auto-applied" in note
    assert "older glob rule" in note
    assert simulate.WIDE_PATTERN_NOTE not in wide_doc.select_one(".rec-detail__why").text()
    listed = await page.doc(f"{PAGE}/fragment/list")
    assert "Safe to auto-apply" in listed.select_one(f'tr[data-row-id="rec-{safe}"]').text()


async def test_links_into_the_page_keep_working(page: Any, pages_app: Any) -> None:
    rec_id = await seed(pages_app)
    redirect = await page.get(f"{PAGE}/{rec_id}")
    assert redirect.status_code == 303
    assert redirect.headers["location"] == f"{PAGE}?rec={rec_id}"
    assert (await page.get(f"{PAGE}/not-a-rec")).status_code == 404
    deep = await page.get(PAGE, params={"rec": rec_id})
    assert deep.status_code == 200
    for bad in ("", "abc", "rec_" + "x" * 100):
        drawer = await page.get(f"{PAGE}/detail", params={"rec": bad})
        assert drawer.status_code == 200
        assert "not valid" in drawer.text
    missing = await page.get(f"{PAGE}/detail", params={"rec": "rec_01NOPE"})
    assert "No recommendation has that id" in missing.text


@pytest.mark.parametrize(
    "params",
    [
        {"state": "bogus"},
        {"severity": "loud"},
        {"family": "x"},
        {"rule": "NOPE"},
        {"page": "abc"},
        {"page_size": "7"},
        {"sort": "bogus"},
        {"order": "sideways"},
        {"q": "x" * 500},
        {"range": "forever"},
        {"action": "explode"},
        {"page": "99999999"},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_filter_or_value_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await seed(pages_app)
    for path in (PAGE, *(f"{PAGE}/fragment/{card}" for card in VISIBLE)):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)


async def test_an_empty_database_explains_itself(page: Any) -> None:
    doc = await page.doc(PAGE)
    assert "Nothing to recommend right now" in doc.select_one("#list").text()
    history = await page.doc(f"{PAGE}/fragment/history")
    assert "No action yet" in history.text()


def test_change_rows_and_charts_read_every_shape() -> None:
    exact = simulate.template_match(TEMPLATE)
    assert exact_endpoint(exact) == "games.roblox.com/v1/games/{segment}/votes"
    assert exact_endpoint({"pattern": "games.roblox.com/*", "type": "glob"}) is None
    row = change_row({"kind": "setting", "key": "cache_ttl_seconds", "current": 180, "proposed": 300})
    assert row["label"].startswith("Setting: ")
    assert (row["before"], row["after"]) == ("180", "300")
    manual = change_row({"kind": "manual", "text": "Renew the credential"})
    assert manual["manual"] and manual["note"] == "Renew the credential"
    charts = evidence_charts(
        {
            "timeline": {"2026-10-10T12:00:00Z": {"a": 1, "b": 2}, "2026-10-10T12:01:00Z": {"a": 3, "b": 4}},
            "series": [[1_760_000_000, 1.0], [1_760_000_060, 2.0]],
            "words": "not a chart",
        }
    )
    assert [chart["name"] for chart in charts] == ["timeline", "series"]
    assert len(charts[0]["series"]) == 2
