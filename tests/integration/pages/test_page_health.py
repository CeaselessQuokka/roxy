"""The Health page (`/admin/health`, plan 14.1, 13.1 to 13.3): integration tests.

What this is
    Tests against the real app: runs written by the health store's own writers (the harness's `seed_health_run`, and
    runs left running or compared here), and runs started through the Health API the page's button posts to (local
    checks only: a test never resolves a real name). They prove: the page and every card answer 200 for an admin and
    redirect otherwise; every registry card, the v1 Run button and the schedule settings are there; the run view lists
    the checks in plan 13.2 order with their status in words, "Apply fix" when a recommendation is linked, "Copy for
    LLM" and the fix link; a running run shows the checks still to come; two runs compare check by check; the history
    equals the API's list and exports through it; starting a run needs CSRF and, with the credential check, a fresh
    second factor; hostile text stays inert; no bad value fails the page; an empty database explains itself.

Why it exists
    The P11 page rules for the Health page; `tests/e2e/test_page_health.py` runs a check from the page in Chromium,
    at phone size too.

What to read next
    `roxy/admin/pages/health.py`, `roxy/admin/api/health.py`, `roxy/health/store.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.ids import new_id
from roxy.core.style_guard import find_style_issues
from roxy.health import checks, store
from roxy.health.model import CheckResult, Status
from roxy.health.runner import runner_for
from roxy.insights.engine import write_recommendation
from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint

PAGE = "/admin/health"
CARDS = [card.id for card in registry.cards_for("health")]
LOCAL_CHECKS = ["H-DISK", "H-CONFIG", "H-CACHE-RW", "H-WORKERS"]


async def store_run(
    pages_app: Any,
    results: list[CheckResult],
    *,
    trigger: str = "manual",
    finished: bool = True,
    checks: list[str] | None = None,
    started_ago: int = 60,
) -> int:
    now = int(pages_app.clock.now())

    def write(conn: Any) -> int:
        run_id = store.insert_run(
            conn,
            started_at=now - started_ago,
            trigger=trigger,
            version="test",
            options={"checks": checks or [], "include_credential": False},
            actor="admin:" + HOSTILE["img"],
            at_ms=(now - started_ago) * 1000,
            planned=len(results),
        )
        for result in results:
            store.insert_result(conn, run_id, result, at_ms=now * 1000)
        if finished:
            store.finish_run(conn, run_id, finished_at=now, summary=store.summarize(results), at_ms=now * 1000)
        return run_id

    run_id: int = await pages_app.ctx.dbs.metrics.write(write)
    return run_id


async def open_rec(pages_app: Any, rule_id: str) -> str:
    now = pages_app.clock.now()
    rec = Recommendation(
        rule_id=rule_id,
        family=INSIGHT_RULES[rule_id].family,
        subject="games.roblox.com/v1/games",
        title="Raise the cache lifetime",
        severity="warn",
        evidence=Evidence(window_from=now - 3600, window_to=now, sample_size=10),
        changes=[ProposedChange("setting", key="cache_ttl_seconds", current=120, proposed=300)],
    )
    rec.id = new_id("rec", pages_app.clock)
    rec.fingerprint = make_fingerprint(rule_id, rec.subject)
    rec.state = "open"
    rec.created_at = rec.updated_at = now
    await pages_app.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    return str(rec.id)


async def test_every_route_needs_a_signed_in_admin(anon: Any) -> None:
    for path in (PAGE, *(f"{PAGE}/fragment/{card}" for card in CARDS)):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_the_run_button_and_the_schedule_settings_are_there(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    doc = await page.doc(PAGE)
    for card in CARDS:
        assert doc.select_one(f"section#{card}[data-card]") is not None, card
    assert not doc.select("[data-card-error]")
    assert len(doc.select("h1")) == 1
    button = doc.select_one('#run form[data-health-start] [data-action="health-run"]')
    assert button is not None
    assert doc.select_one("#run form[data-health-start]").get("data-run-url") == "/admin/api/v1/health/runs"
    assert doc.select_one('#run input[name="include_credential"][checked]') is not None
    assert doc.select_one('#history [data-table="health_runs"]') is not None
    for card in CARDS:
        response = await page.fragment("health", card)
        assert response.status_code == 200
        assert "data-card-error" not in response.text, (card, response.text[:400])
        fdoc = parse_html(response.text)
        for spec in registry.settings_for(registry.anchor("health", card)):
            assert fdoc.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card, spec.key)
    checks = parse_html((await page.fragment("health", "checks")).text)
    assert len(checks.select("tr[data-check-id]")) == 34
    assert doc.select_one('link[href*="css/pages/health"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/health"]') is not None


async def test_the_run_view_lists_checks_in_order_with_words_fixes_and_copies(
    page: Any, pages_app: Any, inert: Any
) -> None:
    await pages_app.seed_all()
    rec_id = await open_rec(pages_app, "CACHE-LOW-HIT")
    run_id = pages_app.seeded["health_run"]
    response = await page.get(PAGE)
    inert(response.text, "health page")
    assert find_style_issues(response.text, "health") == []
    doc = parse_html(response.text)
    run = doc.select_one(f'#run [data-run-id="{run_id}"]')
    assert run is not None
    assert run.get("data-run-state") == "finished"
    order = [node.get("data-check") for node in run.select("[data-check]")]
    assert sorted(order) == ["H-CACHE-HIT", "H-DB-INTEGRITY", "H-REACH"]
    assert order == sorted(order, key=checks.sort_key)  # the 13.2 order
    statuses = {node.get("data-check"): node.select_one(".badge").text() for node in run.select("[data-check]")}
    assert statuses == {"H-REACH": "Fail", "H-CACHE-HIT": "Warn", "H-DB-INTEGRITY": "Pass"}
    warn = run.select_one('[data-check="H-CACHE-HIT"]')
    assert HOSTILE["img"] in warn.text()  # the explanation, as text
    apply = warn.select_one('[data-action="health-apply-fix"]')
    assert apply is not None
    assert apply.get("href") == f"/admin/recommendations?rec={rec_id}"
    copy = warn.select_one("[data-copy-llm]")
    assert copy.get("data-copy-llm") == f"/admin/api/v1/health/runs/{run_id}/export?format=llm&focus=H-CACHE-HIT"
    assert warn.select_one('a[href="/admin/cache#settings"]') is not None
    assert run.select_one('[data-check="H-DB-INTEGRITY"] [data-copy-llm]') is None  # a pass has nothing to fix
    whole = run.select_one('[data-action="health-copy-llm"]')
    text = await page.api("GET", whole.get("data-copy-llm"))
    assert text.status_code == 200
    assert text.headers["content-type"].startswith("text/plain")
    for button in run.select("[data-download]"):
        assert (await page.api("GET", button.get("data-download"))).status_code == 200


async def test_a_running_run_shows_the_checks_still_to_come(page: Any, pages_app: Any) -> None:
    result = CheckResult("H-DISK", Status.PASS, "40% free", "25%", "Free disk space is fine.", "")
    run_id = await store_run(pages_app, [result], finished=False, checks=["H-DISK", "H-CONFIG"], started_ago=5)
    doc = await page.doc(f"{PAGE}/fragment/run", params={"run": run_id})
    run = doc.select_one(f'[data-run-id="{run_id}"]')
    assert run.get("data-run-state") == "running"
    assert run.get("data-run-pinned") == "true"
    assert run.select_one('[data-check="H-DISK"]').get("data-check-status") == "pass"
    assert run.select_one('[data-check="H-CONFIG"]').get("data-check-status") == "pending"
    assert "1 of 2 checks done" in run.text()
    src = doc.select_one("section#run").get("data-card-src")
    assert src.startswith("/admin/health/fragment/run?")
    assert f"run={run_id}" in src.split("?", 1)[1].split("&")  # a refresh keeps showing this run


async def test_two_runs_compare_check_by_check(page: Any, pages_app: Any) -> None:
    first = await store_run(
        pages_app,
        [
            CheckResult("H-DISK", Status.PASS, "40%", "25%", "ok", ""),
            CheckResult("H-CONFIG", Status.FAIL, "2 errors", "0", "bad", "/admin/settings"),
        ],
        started_ago=600,
    )
    second = await store_run(
        pages_app,
        [
            CheckResult("H-DISK", Status.FAIL, "5%", "25%", "low", ""),
            CheckResult("H-CONFIG", Status.PASS, "0", "0", "ok", ""),
            CheckResult(
                "H-CLOCK", Status.PASS, "0.2 s", "2 s", "fine", "", detail={"queue_wait_ms": 12, "call_ms": 80}
            ),
        ],
    )
    doc = await page.doc(PAGE, params={"run": second})
    run = doc.select_one(f'[data-run-id="{second}"]')
    sentence = run.select_one(".hl-compare").text()
    assert f"Since run {first}" in sentence
    assert "H-DISK" in sentence and "H-CONFIG" in sentence  # newly failing and fixed
    clock = run.select_one('[data-check="H-CLOCK"]').text()
    assert "Queue wait ms" in clock and "Call ms" in clock  # H-CLOCK's detail (insights-12)
    options = [o.get("value") for o in run.select('select[name="with"] option')]
    assert str(first) in options
    compared = await page.doc(PAGE, params={"run": second, "with": first})
    table = compared.select_one(f'[data-compare-with="{first}"]')
    changes = {row.select_one("code").text(): row.get("data-change") for row in table.select("tbody tr")}
    assert changes["H-DISK"] == "worse"
    assert changes["H-CONFIG"] == "better"
    assert changes["H-CLOCK"] == "new"
    api = (await page.api("GET", f"health/runs/{second}/compare", params={"with": first})).json()
    assert {c["check_id"]: c["change"] for c in api["changes"]} == changes


async def test_the_history_equals_the_api_and_exports_through_it(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    await store_run(pages_app, [CheckResult("H-DISK", Status.PASS, "1", "2", "ok", "")], trigger="schedule")
    for params in ({}, {"trigger": "schedule"}, {"worst": "fail"}, {"sort": "started_at", "order": "asc"}):
        api = (await page.api("GET", "health/runs", params=params)).json()
        doc = await page.doc(f"{PAGE}/fragment/history", params=params)
        rows = [row.get("data-row-id") for row in doc.select("tbody tr[data-row-id]")]
        assert rows == [f"run-{item['id']}" for item in api["items"]], params
    doc = await page.doc(PAGE)
    link = doc.select_one("#history tbody tr a")
    assert link.get("href").startswith("/admin/health?run=")
    export = doc.select_one('#history a[data-export][href*="format=csv"]')
    assert export.get("href").startswith("/admin/api/v1/health/runs?")
    download = await page.api("GET", export.get("href"))
    assert download.status_code == 200


async def test_starting_a_run_needs_csrf_and_a_fresh_factor_for_the_credential(page: Any, pages_app: Any) -> None:
    await pages_app.settings(health_auto_interval_h=0)
    body = {"checks": LOCAL_CHECKS, "include_credential": False}
    assert (await page.api("POST", "health/runs", json=body, csrf=False)).status_code == 403
    page.make_mfa_stale()
    assert (await pages_app.harness.login(page.admin)).status_code == 200
    page.make_mfa_stale()
    refused = await page.api("POST", "health/runs", json={"checks": ["H-CRED-AUTH"], "include_credential": True})
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "reauth_required"
    started = await page.api("POST", "health/runs", json=body)
    assert started.status_code == 202, started.text
    run_id = started.json()["run_id"]
    await runner_for(pages_app.ctx).wait(run_id)
    doc = await page.doc(PAGE)
    run = doc.select_one(f'#run [data-run-id="{run_id}"]')
    assert run is not None  # the newest run is the one the card shows
    assert run.get("data-run-pinned") == "false"
    assert len(run.select("[data-check]")) == len(LOCAL_CHECKS)


@pytest.mark.parametrize(
    "params",
    [
        {"run": "abc"},
        {"run": "999999"},
        {"run": "0"},
        {"run": "1", "with": "abc"},
        {"run": "1", "with": "999999"},
        {"trigger": "explode"},
        {"worst": "terrible"},
        {"page": "abc"},
        {"page_size": "7"},
        {"sort": "bogus"},
        {"range": "forever"},
        {"q": "x" * 500},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_bad_value_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_all()
    for path in (PAGE, *(f"{PAGE}/fragment/{card}" for card in CARDS)):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)


async def test_an_empty_database_explains_itself(page: Any, pages_app: Any) -> None:
    await pages_app.settings(health_auto_interval_h=0)
    doc = await page.doc(PAGE)
    assert "No health run yet" in doc.select_one("#run").text()
    assert "No health run yet" in doc.select_one("#history").text()
    schedule = await page.doc(f"{PAGE}/fragment/schedule")
    assert "Runs happen only when you press Run" in schedule.text()
