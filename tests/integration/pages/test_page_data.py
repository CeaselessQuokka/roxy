"""The Data page (`/admin/data`, plan 14.1, 6.6, 6.8, 6.10, 17.5): storage, retention, record caps, resets, backups,
VACUUM and exports.

What this is
    Integration tests against the real app (`pages_app`: real databases, real proxy traffic, the real admin API).
    They prove: the page and every fragment answer 200 for an admin and redirect otherwise; every registry card and
    every inline setting its anchors name is there; the storage table equals `GET /data/storage`, the retention
    table `GET /data/retention`, the reset form `GET /data/resets` (every scope, every family with the narrower ones
    under their parent, every v1 clear target with "Nothing to reset" where its scope is None), the exports card
    `GET /export/datasets`; a reset, Back up now and VACUUM go through the API the page's forms name (CSRF, the
    preview digest, the typed phrases); text the backup script wrote is inert; no parameter ever fails the page;
    and an empty server explains itself.

Why it exists
    P11 page rules and the v1 rows of plan 14.1 row 37 (Tools: what's being stored, clears, exports).

What to read next
    `roxy/admin/pages/data.py`, `tests/e2e/test_page_data.py`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/data"
CARDS = [c.id for c in registry.cards_for("data")]


def _top_level(html: str) -> list[Any]:
    return list(parse_html(html).children)


def _write_backup_record(state_dir: Path) -> None:
    """What `backup.sh` writes (`audit/backup.json`), with hostile text where the script copies outside text."""
    folder = state_dir / "audit"
    folder.mkdir(parents=True, exist_ok=True)
    record = {
        "last_success": {
            "at": "2026-10-09T03:00:00Z",
            "date": "2026-10-09",
            "set": {"files": {"control.db.zst": 1024, "metrics.db.zst": 2048}, "encrypted": True, "remote": False},
        },
        "last_failure": {"at": "2026-10-08T03:00:00Z", "date": "2026-10-08", "step": "copy", "error": HOSTILE["img"]},
        "restore_test": {"ok": True, "detail": HOSTILE["script"], "at": "2026-10-07T03:00:00Z"},
        "last_request": {
            "requested_at": "2026-10-09T02:00:00Z",
            "by": "admin:" + HOSTILE["attr"],
            "at": "2026-10-09T02:01:00Z",
            "outcome": "skipped_recent",
        },
    }
    (folder / "backup.json").write_text(json.dumps(record), encoding="utf-8")


async def test_the_page_and_its_fragments_need_a_signed_in_admin(anon: Any) -> None:
    paths = [PAGE, *(f"{PAGE}/fragment/{card}" for card in CARDS)]
    paths += [f"{PAGE}/fragment/storage?part=list", f"{PAGE}/fragment/storage?part=detail&db=metrics&table=events"]
    for path in paths:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_renders_and_every_fragment_answers(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE)
    assert len(doc.select("h1")) == 1
    for card in registry.cards_for("data"):
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        response = await page.fragment("data", card.id)
        assert response.status_code == 200, card.id
        assert "data-card-error" not in response.text, (card.id, response.text[:500])
        assert parse_html(response.text).select_one(f"section#{card.id}[data-card]") is not None
    assert doc.select_one('link[href*="css/pages/data"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/data"]') is not None
    assert doc.select_one('[data-action="backup-now"][data-dialog-open="dlg-backup"]') is not None
    assert doc.select_one("dialog#dlg-backup form[data-api-form]").get("data-api-url") == "/admin/api/v1/data/backups"
    assert doc.select_one("dialog#dlg-reset-run form[data-reset-run]") is not None
    assert find_style_issues(doc.text(), "data") == []


async def test_the_v1_tools_are_in_their_cards(page: Any) -> None:
    storage = parse_html((await page.fragment("data", "storage")).text)
    assert storage.select_one('section#storage [data-table="storage_tables"]') is not None
    resets = parse_html((await page.fragment("data", "resets")).text)
    assert resets.select_one("section#resets form[data-reset-form]") is not None
    exports = parse_html((await page.fragment("data", "exports")).text)
    assert exports.select('section#exports a[data-export][href*="format=csv"]')
    assert exports.select_one('section#exports [data-action="llm-download"]') is not None
    assert exports.select_one('section#exports [data-action="llm-copy"]') is not None


@pytest.mark.parametrize("card", ["retention", "record-caps", "exports"])
async def test_every_inline_setting_of_the_cards_anchors_is_there(page: Any, card: str) -> None:
    doc = parse_html((await page.fragment("data", card)).text)
    keys = {node.get("data-setting-key") for node in doc.select(f"section#{card} [data-setting-key]")}
    expected = {spec.key for spec in registry.settings_for(f"data#{card}")}
    assert expected
    assert keys == expected


# ============================================================================================ storage


async def test_the_storage_table_equals_the_api_and_answers_alone(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    api = (await page.api("GET", "data/storage")).json()
    tables = sum(len(db.get("tables", [])) for db in api["databases"])
    alone = await page.fragment("data", "storage", part="list", page_size=250)
    roots = _top_level(alone.text)
    assert len(roots) == 1
    assert roots[0].get("data-table") == "storage_tables"
    assert f"of {tables:,}" in parse_html(alone.text).select_one(".dt__count").text()
    rows = parse_html(alone.text).select("tbody tr[data-row-id]")
    assert len(rows) == tables
    events = [row for row in rows if row.get("data-row-id") == "table-metrics-events"]
    assert events
    assert "part=detail" in events[0].get("data-drawer-src")
    searched = parse_html((await page.fragment("data", "storage", part="list", q="rollup")).text)
    assert all("rollup" in row.text() for row in searched.select("tbody tr[data-row-id]"))
    card = parse_html((await page.fragment("data", "storage")).text)
    kpis = {node.get("data-kpi") for node in card.select("[data-kpi]")}
    assert {"storage_total", "storage_budget_used", "storage_growth_per_day", "storage_projected_30d"} <= kpis
    assert "No disk samples yet" in card.text() or "Traffic rows written" in card.text()


async def test_a_table_opens_with_its_limits_and_links_to_their_settings(page: Any) -> None:
    doc = parse_html((await page.fragment("data", "storage", part="detail", db="metrics", table="events")).text)
    assert doc.select_one("[data-storage-detail]") is not None
    text = doc.text()
    assert "metrics.events" in text
    links = {a.get("href") for a in doc.select("a.data-setting-ref")}
    assert "/admin/settings?key=retention_events_days" in links
    assert "/admin/settings?key=events_max_rows" in links
    bad = await page.fragment("data", "storage", part="detail", db="metrics", table="no_such_table")
    assert "data-card-error" in bad.text
    assert "not measured" in bad.text


async def test_the_retention_table_equals_the_api(page: Any) -> None:
    api = (await page.api("GET", "data/retention")).json()
    doc = parse_html((await page.fragment("data", "retention")).text)
    rows = doc.select("section#retention .data-limits tbody tr")
    assert len(rows) == len(api["tables"])
    assert f"{len(api['tables'])} tables with a limit" in doc.select_one("#retention .card__sub").text()
    assert f"at least {api['audit_min_days']} days" in doc.text()


# ============================================================================================ resets


async def test_the_reset_form_is_built_from_the_api(page: Any) -> None:
    api = (await page.api("GET", "data/resets")).json()
    doc = parse_html((await page.fragment("data", "resets")).text)
    scopes = [o.get("value") for o in doc.select('select[name="scope"] option')]
    assert scopes == [s["scope"] for s in api["scopes"]]
    boxes = [box.get("value") for box in doc.select('input[name="families"]')]
    assert sorted(boxes) == sorted(f["name"] for f in api["families"])
    for family in api["families"]:
        if family["parent"]:
            nested = doc.select(f'ul.data-families--narrow input[value="{family["name"]}"]')
            assert nested, family["name"]
            parent_item = nested[0].parent.parent.parent.parent
            assert parent_item.select_one(f'input[value="{family["parent"]}"]') is not None, family["name"]
    targets = doc.select(".data-v1 tbody tr")
    assert len(targets) == len(api["v1_clear_targets"]) == 27
    nothing = [row for row in targets if row.select_one("td").text() in ("pause_drops", "throttle_drops")]
    assert len(nothing) == 2
    assert all("Nothing to reset" in row.text() for row in nothing)
    form = doc.select_one("form[data-reset-form]")
    assert form.get("data-preview-url") == "/admin/api/v1/data/resets/preview"
    assert form.get("data-run-url") == "/admin/api/v1/data/resets"
    assert form.get("data-factory-url") == "/admin/api/v1/data/resets/factory"


async def test_a_link_preselects_the_families_and_the_scope(page: Any) -> None:
    doc = await page.doc(PAGE, params={"families": "probes,logins,bogus"})
    checked = {box.get("value") for box in doc.select('#resets input[name="families"][checked]')}
    assert checked == {"probes", "logins"}
    scoped = await page.doc(PAGE, params={"scope": "bans"})
    chosen = scoped.select_one('#resets select[name="scope"] option[selected]')
    assert chosen.get("value") == "bans"
    bans = scoped.select_one('#resets fieldset[data-scope-fields="bans"]')
    assert bans.get("hidden") is None
    families = scoped.select_one('#resets fieldset[data-scope-fields^="family"]')
    assert families.get("hidden") is not None


async def test_a_reset_runs_only_through_the_preview_the_form_shows(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    body = {"scope": "family", "families": ["probes"]}
    assert (await page.api("POST", "data/resets/preview", json=body, csrf=False)).status_code == 403
    preview = await page.api("POST", "data/resets/preview", json=body)
    assert preview.status_code == 200, preview.text
    answer = preview.json()
    assert answer["confirm_phrase"] == "reset probes"
    assert answer["total_rows"] >= 1
    wrong = await page.api("POST", "data/resets", json={**body, "preview": "0" * 64, "reason": "x", "confirm": "x"})
    assert wrong.status_code == 409
    unconfirmed = await page.api("POST", "data/resets", json={**body, "preview": answer["preview"], "reason": "test"})
    assert unconfirmed.status_code == 422
    assert unconfirmed.json()["error"]["code"] == "confirmation_required"
    done = await page.api(
        "POST",
        "data/resets",
        json={
            **body,
            "preview": answer["preview"],
            "reason": "Clear the probes " + HOSTILE["img"],
            "confirm": "reset probes",
        },
    )
    assert done.status_code in (200, 202), done.text
    probes = (await page.api("GET", "security/probes")).json()
    assert probes["total"] == 0
    doc = parse_html((await page.fragment("data", "resets")).text)
    recent = [a.text() for a in doc.select(".data-recent__list a")]
    assert "data.reset.done" in recent
    assert "data.reset" in recent


# ============================================================================================ backups and VACUUM


async def test_the_backups_card_reads_the_backup_record_as_text(page: Any, pages_app: Any, inert: Any) -> None:
    state_dir = Path(pages_app.ctx.env.state_dir)
    empty = parse_html((await page.fragment("data", "backups")).text)
    assert "No nightly backup has been recorded" in empty.text()
    assert "Nothing waiting" in empty.text()
    _write_backup_record(state_dir)
    response = await page.fragment("data", "backups")
    inert(response.text, "backups card")
    doc = parse_html(response.text)
    text = doc.text()
    assert "Succeeded" in text
    assert "2 files, encrypted, kept on this server only" in text
    assert HOSTILE["img"] in text  # the failure's error, as text
    assert "Skipped: a good backup was less than 10 minutes old" in text


async def test_back_up_now_goes_through_the_dialogs_api_url(page: Any, pages_app: Any) -> None:
    doc = await page.doc(PAGE)
    url = doc.select_one("dialog#dlg-backup form").get("data-api-url")
    assert (await page.api("POST", url, json={}, csrf=False)).status_code == 403
    answer = await page.api("POST", url, json={"reason": "before an upgrade"})
    assert answer.status_code in (200, 202), answer.text
    request = Path(pages_app.ctx.env.state_dir) / "backup-request"
    assert request.exists()
    card = parse_html((await page.fragment("data", "backups")).text)
    assert "Asked" in card.select_one(".data-backups__facts").text()
    assert "Nothing waiting" not in card.text()


async def test_vacuum_needs_the_phrase_typed_in_its_dialog(page: Any) -> None:
    doc = parse_html((await page.fragment("data", "vacuum")).text)
    dialog = doc.select_one("dialog#dlg-vacuum-control")
    assert dialog is not None
    form = dialog.select_one("form[data-api-form]")
    assert form.get("data-api-url") == "/admin/api/v1/data/vacuum"
    assert form.get("data-expected") == "vacuum control"
    typed = form.select_one('input[name="confirm"]')
    assert typed.get("data-json") == "string"
    assert form.select_one('input[name="database"]').get("value") == "control"
    assert doc.select_one('[data-action="vacuum-hot"]') is None  # hot.db never
    refused = await page.api("POST", "data/vacuum", json={"database": "control", "confirm": "nope"})
    assert refused.status_code == 422
    done = await page.api("POST", "data/vacuum", json={"database": "control", "confirm": "vacuum control"})
    assert done.status_code in (200, 202), done.text


# ============================================================================================ exports


async def test_the_exports_card_lists_every_dataset_with_this_range(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    api = (await page.api("GET", "export/datasets")).json()
    doc = parse_html((await page.fragment("data", "exports", range="7d")).text)
    links = [a.get("href") for a in doc.select('a[data-export][href*="format=csv"]')]
    assert len(links) == len(api["datasets"])
    for item in api["datasets"]:
        href = next(link for link in links if link.startswith(f"/admin/api/v1/export/{item['name']}?"))
        assert ("range=7d" in href) == bool(item["ranged"]), href
    probes = next(link for link in links if "/export/probes?" in link)
    download = await page.api("GET", probes)
    assert download.status_code == 200, download.text
    assert download.headers["content-type"].startswith("text/csv")
    llm = doc.select_one("[data-llm-export]")
    assert llm.get("data-llm-url") == "/admin/api/v1/export/llm"
    assert [o.get("value") for o in llm.select("[data-llm-window] option")] == ["24h", "7d", "30d"]
    assert doc.select_one('a[href="/admin/api/v1/export/llm/schema"]') is not None
    assert "keyed hashes" in doc.text()


# ============================================================================================ robustness


BAD_PARAMS = [
    {"page": "abc"},
    {"page_size": "7"},
    {"sort": "bogus"},
    {"order": "sideways"},
    {"q": "x" * 500},
    {"families": "<img src=x onerror=alert(1)>," * 30},
    {"scope": "<script>"},
    {"range": "forever"},
    {"range": "custom", "from": "yesterday"},
    {"part": "bogus"},
    {"refresh": "1"},
    {"db": "../../etc", "table": "x"},
]


@pytest.mark.parametrize("params", BAD_PARAMS, ids=lambda p: "-".join(p))
async def test_no_parameter_ever_fails_the_page(page: Any, pages_app: Any, inert: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    requests: list[tuple[str, dict[str, str]]] = [(PAGE, {}), *((f"{PAGE}/fragment/{card}", {}) for card in CARDS)]
    requests.append((f"{PAGE}/fragment/storage", {"part": "list"}))
    for path, base in requests:
        sent = {**base, **params}
        response = await page.get(path, params=sent)
        assert response.status_code == 200, (path, sent, response.text[:300])
        assert "data-card-error" not in response.text, (path, sent)
        inert(response.text, f"{path} {sent}")


async def test_an_empty_server_explains_itself(page: Any) -> None:
    doc = await page.doc(PAGE)
    assert doc.select_one("#storage.page-card--lazy") is not None  # measured after the first paint
    resets = parse_html((await page.fragment("data", "resets")).text).text()
    assert "No reset, backup or VACUUM has been run yet" in resets
    backups = parse_html((await page.fragment("data", "backups")).text).text()
    assert "No snapshot is kept on this server right now" in backups
    storage = parse_html((await page.fragment("data", "storage")).text).text()
    assert re.search(r"No disk samples yet|samples so far", storage)
