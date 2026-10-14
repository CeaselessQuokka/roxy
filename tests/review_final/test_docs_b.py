"""Final review, lens docs_b: the product's own texts against the code, guide part B (regression tests).

What this is
    One test per finding of `.remake/final_review/find_docs_b.md`: the places where a page, a card help, an empty
    state, a dialog, a catalog text or a filter of the Cache, Clients, Security, Data, Audit, Settings and System
    pages says something the code does not do, or where the admin guide's chapters (Cache, Clients, Protection,
    Security, Data, Audit, Settings, System, Help, Alerts, Backups and resets, the operator CLI) had to work around
    the product. Each test was a strict xfail naming its finding until the final review fixed it; each is a
    regression test now.

Why it exists
    The final review rule: a finding without a reproduction is not a finding. For a wrong text the test asserts the
    right text; where a fix could land on either side (the code or the text), the test accepts both.

How it works
    The fixtures of `tests/integration/pages/conftest.py` (the real app in process, a signed-in admin, Roblox played
    by `respx` through `pages_harness.roblox_answer`, a `FakeClock`), or the root conftest's `dbs` and `fake_clock`
    for the one test that needs no app. Texts are read from the rendered pages and fragments where the owner reads
    them, or from the catalog and the static files they come from. No network.

What to read next
    `.remake/final_review/find_docs_b.md`, `.remake/drafts/open_items.md` (sections g4, g5, g6, g7, x and the
    editor's), `.remake/drafts/ADMIN_GUIDE.md`.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from integration.pages.conftest import anon, page, page_admin, pages_app  # noqa: F401  (the page fixtures)
from pages_harness import PlannedRequest, parse_html

REPO = Path(__file__).resolve().parents[2]
TEMPLATES = REPO / "src" / "roxy" / "templates"
GAME_PATH = "/games.roblox.com/v1/games?universeIds=1"


def _text(html: str) -> str:
    """The visible text of an HTML answer, whitespace folded (what the owner reads)."""
    return " ".join(parse_html(html).text().split())


def _cell(row: Any, css: str) -> str:
    """The folded text of the one element of `row` that `css` selects (it must exist)."""
    node = row.select_one(css)
    assert node is not None, (css, row.text()[:200])
    return " ".join(node.text().split())


# ===================================================================================================== docs_b-1


async def test_the_audit_target_choices_find_what_they_name(page: Any, pages_app: Any) -> None:
    """`admin/pages/audit.py TARGET_KINDS` offers `("reset:*", "Data resets")` and `("credential*", "The
    credential")`. `admin/api/data.py` audits every reset, backup and VACUUM with the target `operation:<id>`
    (`execute_reset`, `_run_reset`, `back_up_now`, `run_vacuum`), so no row ever starts with `reset:`, and
    `admin/api/audit.py MANAGE_PAGES["reset"]` never applies either. Filters match by prefix, so `credential*` also
    matches `credential_allowlist:<id>`, which has a choice of its own. The guide tells the owner to use the Action
    filter `data.*` instead."""
    from roxy.config import audit
    from roxy.config.audit import Actor

    await pages_app.seed_traffic()
    body: dict[str, Any] = {"scope": "family", "families": ["probes"]}
    preview = await page.api("POST", "data/resets/preview", json=body)
    assert preview.status_code == 200, preview.text
    done = await page.api(
        "POST",
        "data/resets",
        json={**body, "preview": preview.json()["preview"], "reason": "review docs_b-1", "confirm": "reset probes"},
    )
    assert done.status_code in (200, 202), done.text

    def allowlisted(conn: Any) -> int:
        actor = Actor("admin", "owner", None)
        return audit.record(conn, actor, "rule.create", "credential_allowlist:7", None, {"pattern": "x"}, None, None)

    await pages_app.ctx.dbs.control.write(allowlisted)
    every = (await page.api("GET", "audit", params={"page_size": 100})).json()["items"]
    resets = [item for item in every if str(item.get("action", "")).startswith("data.reset")]
    assert resets, [(item.get("action"), item.get("target")) for item in every][:20]  # the reset was audited
    doc = await page.doc("/admin/audit")
    choices = {" ".join(opt.text().split()): opt.get("value") for opt in doc.select('select[name="target"] option')}
    reset_choice = next(value for label, value in choices.items() if label.startswith("Data resets"))
    credential_choice = next(value for label, value in choices.items() if label.startswith("The credential"))
    found = (await page.api("GET", "audit", params={"target": reset_choice})).json()["items"]
    credential = (await page.api("GET", "audit", params={"target": credential_choice})).json()["items"]
    problems = []
    if not any(str(item.get("action", "")).startswith("data.reset") for item in found):
        problems.append(f"Data resets ({reset_choice}) lists none of the resets: {[r.get('target') for r in resets]}")
    stray = [item.get("target") for item in credential if str(item.get("target", "")).startswith("credential_")]
    if stray:
        problems.append(f"The credential ({credential_choice}) also lists {stray}")
    assert problems == [], problems


# ===================================================================================================== docs_b-2


async def test_a_zero_in_a_cache_rule_is_described_as_the_setting_it_falls_back_to(page: Any, pages_app: Any) -> None:
    """`cache/policy.py request_policy`: a rule's `negative_ttl` of 0 uses `cache_error_ttl_seconds` (60 s by default)
    and a `stale_ttl` of 0 uses `cache_swr_seconds` (60 s); only a rule whose `ttl` is 0 keeps no refusals. The add
    form's hint (`templates/admin/pages/cache/rules.html`) says "0 keeps none", and `admin/pages/cache.py rules_card`
    prints "none" in the Revalidate window and Negative TTL cells. An owner who writes a rule with "Keep refusals
    for" 0 to stop negative caching for an endpoint still gets Roblox's 404s replayed for a minute."""
    pattern = "games.roblox.com/v1/review-docs-b-zero"
    made = await page.api(
        "POST", "cache/rules", json={"pattern": pattern, "ttl": 300, "stale_ttl": 0, "negative_ttl": 0}
    )
    assert made.status_code in (200, 201), made.text
    assert int(pages_app.ctx.settings.int("cache_error_ttl_seconds")) == 60  # what a 0 really means
    response = await page.fragment("cache", "rules")
    assert response.status_code == 200, response.text[:300]
    doc = parse_html(response.text)
    hint = doc.select_one("#cache-rule-new-negative-hint")
    assert hint is not None
    row = next(tr for tr in doc.select("tbody tr[data-row-id]") if pattern in tr.text())
    cells = {name: _cell(row, f'td[data-col="{name}"]') for name in ("stale_ttl", "negative_ttl")}
    problems = []
    if "keeps none" in hint.text():
        problems.append(f"hint: {hint.text()!r}")
    problems += [f"{name} cell reads {text!r}" for name, text in cells.items() if text.lower() in ("none", "")]
    assert problems == [], problems


# ===================================================================================================== docs_b-3


async def test_the_clear_stats_dialog_names_everything_it_deletes(page: Any, pages_app: Any) -> None:
    """`admin/api/data.py FAMILIES["cache_stats"]` deletes `metrics.cache_minute` (the "Stored answers" box's
    eviction and store counts), `metrics.cache_eviction_passes` and `cache.change_observations` (what the TTL tuner
    measures lifetimes from). cache.db is never snapshotted (`SNAPSHOT_DBS`), so the observations cannot come back.
    The dialog (`admin/pages/cache.py stats_reset`) lists only the hit, miss, stale and coalesced counts, the stored
    answers staying and the chart marker; the guide had to add the rest.

    The fix may also take `change_observations` out of the family (the finding's other option): the tuner then
    needs no word in the dialog (skeptic note)."""
    preview = await page.api("POST", "data/resets/preview", json={"scope": "family", "families": ["cache_stats"]})
    assert preview.status_code == 200, preview.text
    tables = {(t["db"], t["table"]) for t in preview.json()["tables"]}
    assert ("metrics", "cache_minute") in tables, tables
    wanted = ["evict"]
    if ("cache", "change_observations") in tables:
        wanted.append("tuner")
    response = await page.fragment("cache", "stats")
    assert response.status_code == 200, response.text[:300]
    dialog = parse_html(response.text).select_one("#dlg-cache-reset-stats")
    assert dialog is not None
    words = " ".join(dialog.text().split()).lower()
    missing = [what for what in wanted if what not in words]
    assert missing == [], words[:1200]


# ===================================================================================================== docs_b-4


async def test_the_revert_drawer_warns_when_the_setting_changed_again(page: Any, pages_app: Any) -> None:
    """`SettingsService.revert` adds the warning "<key> was changed again after history entry N" and the API answers
    it in `warnings`, but `templates/admin/pages/settings/history.html` shows a fixed text ("Puts X back to the value
    it had right before this change") and `api_forms.js` shows the fixed `data-success` text, never `warnings`. An
    owner who reverts last week's change to undo just that one also throws away today's change, without a word. The
    guide had to warn about it; the Audit page's revert form has the same gap."""
    await pages_app.settings(alert_rate_limit_per_hour=30)
    await pages_app.settings(alert_rate_limit_per_hour=40)
    history = (await page.api("GET", "settings/history", params={"key": "alert_rate_limit_per_hour"})).json()
    first = min(int(item["id"]) for item in history["items"])  # 20 -> 30, changed again since (30 -> 40)
    drawer = await page.fragment("settings", "history", change=first)
    assert drawer.status_code == 200, drawer.text[:300]
    words = _text(drawer.text).lower()
    assert "revert this change" in words  # the revert form is offered
    reverted = await page.api("POST", f"settings/history/{first}/revert", json={"reason": "review docs_b-4"})
    assert reverted.status_code == 200, reverted.text
    assert reverted.json()["warnings"], reverted.json()  # the server knew
    assert any(phrase in words for phrase in ("changed again", "later change", "changed since", "newer change")), words[
        :1500
    ]


# ===================================================================================================== docs_b-5


async def test_the_client_bypass_dialog_works_with_a_default_expiry_of_zero(page: Any, pages_app: Any) -> None:
    """`admin/pages/clients.py client_context` passes `bypass_hours = float(bypass_default_expiry_h)` and
    `templates/admin/pages/clients/client.html` prefills `name="expires_in_h"` with it; `admin/api/clients.py
    BypassBody.expires_in_h` is `gt=0`. The catalog allows 0 ("new entries never expire"), so with that value the
    dialog's own Bypass button is always refused until the owner types some other number; the guide had to tell the
    owner to type hours or use Protection > Bypass."""
    await pages_app.settings(bypass_default_expiry_h=0)
    ip = "203.0.113.61"
    await pages_app.seed_traffic([PlannedRequest(GAME_PATH, ip, user_agent="Roblox/WinInet")])
    doc = await page.doc(f"/admin/clients/ip/{ip}")
    field = doc.select_one("#dlg-client-bypass-hours")
    assert field is not None
    value = (field.get("value") or "").strip()
    body: dict[str, Any] = {"note": "", "reason": "review docs_b-5"}
    if value:
        body["expires_in_h"] = float(value)  # what api_forms.js sends for data-json="float"
    sent = await page.api("POST", f"clients/ips/{ip}/bypass", json=body)
    assert sent.status_code == 200, (value, sent.status_code, sent.text[:400])


# ===================================================================================================== docs_b-6


async def test_every_import_preview_status_has_words_on_the_page(page: Any, pages_app: Any) -> None:
    """`config/settings_service.py preview_import` marks a value already in force `same` (`ImportStatus`), and
    `admin/api/settings.py import_preview` marks a change it must refuse `refused` (functional-9). `static/js/pages/
    settings.js IMPORT_STATUS` maps `unchanged` (never sent) and has no `same` or `refused`, so `showImport` prints
    the raw status. The guide describes the column as the page means it ("Already set")."""
    current = pages_app.ctx.settings.get("alert_rate_limit_per_hour")
    document = {"alert_rate_limit_per_hour": current, "spam_dry_run": 0, "cache_ttl_seconds": 150}
    preview = await page.api("POST", "settings/import/preview", json={"document": document})
    assert preview.status_code == 200, preview.text
    statuses = {str(item["status"]) for item in preview.json()["items"]}
    script = (REPO / "src" / "roxy" / "static" / "js" / "pages" / "settings.js").read_text(encoding="utf-8")
    block = re.search(r"const IMPORT_STATUS = \{(.*?)\};", script, re.S)
    assert block is not None
    known = set(re.findall(r"^\s*([a-z_]+):", block.group(1), re.M))
    assert "change" in statuses, statuses
    assert "change" in known, known
    assert sorted(statuses - known) == [], (sorted(statuses), sorted(known))


# ===================================================================================================== docs_b-7


async def test_the_clients_how_to_read_describes_the_rates_as_counts(page: Any, pages_app: Any) -> None:
    """`admin/pages/registry.py` (page `clients`, `how_to_read`): "Rates are requests per minute over the last minute,
    five minutes and hour". `metrics/queries.py trailing_rate` returns the requests in the trailing window, and the
    API's column help says so ("Requests in the trailing 5 minutes"). truth-4 fixed the same words on Overview > Top
    places; this paragraph (also on Help > What each page does) was left. An owner sizing a per-place limit from
    Rate60 read as a per-minute figure sets it 60 times too high."""
    from roxy.admin.api import clients as clients_api

    helps = {c.key: c.help for c in clients_api.PLACE_SPEC.columns if c.key in ("rate5", "rate60")}
    assert all("trailing" in text for text in helps.values()), helps  # the column help says counts
    doc = await page.doc("/admin/clients")
    words = " ".join(doc.text().split())
    assert "requests per minute over the last minute, five minutes and hour" not in words


# ===================================================================================================== docs_b-8


async def test_the_places_table_does_not_call_the_other_row_forged(page: Any, pages_app: Any) -> None:
    """The leader trims each closed minute to the top `max_caller_records` places plus one `other` row
    (`metrics/activity.py OTHER_KEY`, `rollups.py`). `admin/pages/clients.py places_card` notes every key that is not
    digits as "not a number: a forged header", so under a busy hour the biggest row of the table tells the owner a
    forgery is going on when it is Roxy's own total. The guide had to explain the row."""
    await pages_app.seed_traffic([PlannedRequest(GAME_PATH, "203.0.113.62", place="606849621")])
    minute = int(pages_app.clock.now()) // 60 * 60

    def fold(conn: Any) -> None:
        conn.execute(
            "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes) "
            "VALUES (?, 'place', 'other', 900, 0, 900, 90000)",
            (minute,),
        )

    await pages_app.ctx.dbs.metrics.write(fold)
    response = await page.fragment("clients", "places")
    assert response.status_code == 200, response.text[:300]
    rows = parse_html(response.text).select("tbody tr[data-row-id]")
    other = [row for row in rows if _cell(row, 'td[data-col="key"]').startswith("other")]
    assert other, [" ".join(row.text().split())[:80] for row in rows]
    assert "forged" not in other[0].text()


# ===================================================================================================== docs_b-9


async def test_a_pre_migration_snapshot_reads_before_a_migration(page: Any, pages_app: Any) -> None:
    """`deploy/prestart.py` names its copies `pre-migrate-<time>-<release>.db`; `admin/api/data.py _snapshot_files`
    takes the kind as `name.split("-", 1)[0]` (`pre`), and `templates/admin/pages/data/backups.html` maps only
    `premigrate` to "Before a migration". The guide had to explain the raw word."""
    folder = Path(pages_app.ctx.env.state_dir) / "snapshots"
    folder.mkdir(parents=True, exist_ok=True)
    name = "pre-migrate-20261013T120000Z-65d4bd5abcde.db"
    (folder / name).write_bytes(b"SQLite format 3\x00" + bytes(4080))
    response = await page.fragment("data", "backups")
    assert response.status_code == 200, response.text[:300]
    row = next((tr for tr in parse_html(response.text).select("tr") if name in tr.text()), None)
    assert row is not None, _text(response.text)[:600]
    kind = _cell(row, 'td[data-label="Kind"]')
    assert kind == "Before a migration", kind


# ===================================================================================================== docs_b-10


async def test_the_error_log_states_how_long_errors_are_kept(page: Any, pages_app: Any) -> None:
    """`templates/admin/pages/system/errors.html` and the empty state in `admin/pages/system.py` both say "Nothing is
    dropped as more come in". `storage/retention.py prune_errors` deletes a signature `retention_errors_days` (180)
    after it was last seen and keeps at most `max_error_records` (2,000), and `MetricsRecorder.record_error` drops new
    signatures beyond `MAX_ERROR_SIGNATURES` between flushes. The column help is stale too (`ERRORS_TABLE`: a
    signature of "type, place and message shape" and a source of "request, job, startup", while the hook records
    "<Type>: <message>" with source `roxy`), and so is the drawer's "No traceback was kept for this error (Roblox's
    answers and probes have none)": in v2 only the rows brought over from v1 have no traceback."""
    from roxy.admin.api import system as system_api

    response = await page.fragment("system", "errors")
    assert response.status_code == 200, response.text[:300]
    words = _text(response.text)
    source_help = next(c.help for c in system_api.ERRORS_TABLE.columns if c.key == "source")
    drawer = (TEMPLATES / "admin" / "pages" / "system" / "errors.html").read_text(encoding="utf-8")
    problems = []
    if "Nothing is dropped" in words:
        problems.append("the card says nothing is dropped")
    if "startup" in source_help and "job" in source_help:
        problems.append(f"source help promises sources nothing records: {source_help!r}")
    if "probes have none" in drawer:
        problems.append("the drawer blames Roblox's answers and probes for a missing traceback")
    assert problems == [], problems


# ===================================================================================================== docs_b-12


async def test_texts_name_the_buttons_as_they_are_labeled(anon: Any, pages_app: Any) -> None:
    """The kill-switch link's failure page (`templates/auth/invalidate.html`, state `failed`) tells the owner to use
    "Sign out everywhere" and "Revoke all trusted devices" on the Security page; the Trusted devices card's button and
    dialog say "Revoke all". `admin/api/data.py V1_CLEAR_TARGETS["all"]` (the Data page's v1 map) says "System >
    Reset counts" and the Workers column help (`admin/api/system.py WORKERS_TABLE`, `counters_reset_at`) says "Reset
    counts"; the button on System > Workers is "Reset request counts". (The failure page also uses curly quotation
    marks, unlike every other product text.)"""
    from roxy.admin.api import data as data_api
    from roxy.admin.api import system as system_api

    response = await anon.http.post(
        "/admin/invalidate/" + "Zz9" * 11, data={"all_sessions": "1"}, headers=pages_app.harness.headers()
    )
    assert response.status_code == 404, response.text[:300]
    words = _text(response.text)
    assert "no longer valid" in words  # the failure state
    named = re.findall('[\u201c"]([^\u201d"]+)[\u201d"]', words)
    security = "".join(path.read_text(encoding="utf-8") for path in (TEMPLATES / "admin/pages/security").glob("*.html"))
    system = "".join(path.read_text(encoding="utf-8") for path in (TEMPLATES / "admin/pages/system").glob("*.html"))
    problems = [f"invalidate.html names {name!r}" for name in named if f"<span>{name}</span>" not in security]
    note = str(data_api.V1_CLEAR_TARGETS["all"].get("note") or "")
    column = next(c.help for c in system_api.WORKERS_TABLE.columns if c.key == "counters_reset_at")
    assert "<span>Reset request counts</span>" in system
    problems += [f"{where} says {text!r}" for where, text in (("V1_CLEAR_TARGETS", note), ("column help", column))
                 if "Reset counts" in text]  # fmt: skip
    assert named, words
    assert problems == [], (named, problems)


# ===================================================================================================== docs_b-13


async def test_the_audit_how_to_read_names_the_actors_the_log_holds(page: Any, pages_app: Any) -> None:
    """`templates/admin/pages/audit.html` says who acted reads `recommendation:<rule>` for an applied recommendation
    and `cli` for the server's command line. `insights/actions.py` applies a recommendation as the admin who pressed
    Apply (its reason starts with `recommendation:<id>`; automatic apply is `auto_apply:...`), `scripts/ctl.py`
    writes `Actor("cli", <login name>)` (`cli:<name>`), and the v1 import is `import:v1`. A Who filter of
    `recommendation:*` finds nothing. The guide lists the forms the log really holds."""
    doc = await page.doc("/admin/audit")
    panel = doc.select_one("#how-to-read .how-to-read__body")
    assert panel is not None
    words = " ".join(panel.text().split())
    assert "Who acted reads" in words
    problems = []
    if "recommendation:<rule>" in words:
        problems.append("names recommendation:<rule> as an actor")
    if "cli:" not in words:
        problems.append("names the command line as `cli` (the log writes cli:<login name>)")
    assert problems == [], problems


# ===================================================================================================== docs_b-14


def test_the_catalog_texts_name_the_real_page_action_and_rules() -> None:
    """`config/settings/admin_security.py`: `admin_allowlist_enabled` says the list "is edited on the Security page";
    its entries live on Protection > Deny and allow lists (Security > Admin access only links there).
    `admin_reauth_window_s` lists "changing your password" among the sensitive actions; the dashboard has no
    password change at all (only `scripts/create_admin.py --reset-password` on the console).
    `config/settings/throttling.py bot_score_legit_max` says THROTTLE-TUNE and FILTER-COLLATERAL use it (and links
    FILTER-COLLATERAL); `insights/rules/abuse.py` reads it in THROTTLE-TUNE and ABUSE-DIST only. The owner reads all
    three under "What happens if I change this?".

    Plan 15.3's catalog row for `bot_score_legit_max` names FILTER-COLLATERAL too (plan 11.5's rule table does not),
    so by lead decision (9) that part may be fixed on either side: the text, or FILTER-COLLATERAL reading the
    setting. A dashboard password change, if one is ever added, likewise makes the reauth text right (skeptic note)."""
    from roxy.config.catalog import CATALOG

    rules = (REPO / "src" / "roxy" / "insights" / "rules" / "abuse.py").read_text(encoding="utf-8")
    collateral = rules.split("class FilterCollateral", 1)[1].split("\nclass ", 1)[0]
    assert "bot_score_legit_max" in rules
    collateral_reads_it = "bot_score_legit_max" in collateral
    pages = list((TEMPLATES / "admin/pages").rglob("*.html"))
    password_change = any("change your password" in p.read_text(encoding="utf-8").lower() for p in pages)
    problems = []
    if "edited on the Security page" in CATALOG["admin_allowlist_enabled"].description:
        problems.append("admin_allowlist_enabled: the list is on Protection > Deny and allow lists")
    if not password_change and "changing your password" in CATALOG["admin_reauth_window_s"].description:
        problems.append("admin_reauth_window_s: no dashboard action changes a password")
    legit = CATALOG["bot_score_legit_max"]
    names_collateral = "FILTER-COLLATERAL" in legit.description or "FILTER-COLLATERAL" in legit.related_recommendations
    if names_collateral and not collateral_reads_it:
        problems.append("bot_score_legit_max: FILTER-COLLATERAL never reads it (ABUSE-DIST does)")
    assert problems == [], problems


# ===================================================================================================== docs_b-15


async def test_cards_that_compare_nothing_do_not_say_compared_with(page: Any, pages_app: Any) -> None:
    """`admin/pages/shell.py page_time` builds `view["description"]` as "<range>, compared with <comparison>"
    whenever a comparison is chosen, and these cards use it as their subtitle (`range.description`,
    `range_description`): "Last 24 hours, compared with the same period last week: 6 attempts, 2 failed", "For last
    24 hours, compared with ..." on Exports. Nothing on those cards is compared, and the number reads as a
    comparison. The guide had to tell the owner the comparison changes nothing there."""
    params = {"range": "24h", "compare": "week"}
    cards = [
        ("security", "logins"),
        ("security", "probes"),
        ("security", "probe-summary"),
        ("security", "crawls"),
        ("data", "exports"),
        ("audit", "log"),
        ("settings", "history"),
    ]
    subtitles: dict[str, str] = {}
    for page_id, card in cards:
        response = await page.fragment(page_id, card, **params)
        assert response.status_code == 200, (page_id, card, response.text[:300])
        sub = parse_html(response.text).select_one(".card__sub")
        subtitles[f"{page_id}#{card}"] = " ".join(sub.text().split()) if sub is not None else ""
    assert any(text.startswith("Last 24 hours") or "last 24 hours" in text for text in subtitles.values()), subtitles
    compared = {where: text for where, text in subtitles.items() if "compared with" in text}
    assert compared == {}, compared


# ===================================================================================================== docs_b-16


async def test_the_disk_full_runbook_states_the_vacuum_space_the_dashboard_asks(page: Any, pages_app: Any) -> None:
    """`admin/api/data.py _vacuum_estimates`: `enough_disk = free > bytes * 2`, and `POST /data/vacuum` refuses
    otherwise ("it needs about twice the file"); the Vacuum card says the same. docs/RUNBOOKS.md, read in the middle
    of a disk-full incident, says "about the size of the database", so an owner who frees that much is still refused.
    The guide follows the code."""
    estimate = await page.api("GET", "data/vacuum")
    assert estimate.status_code == 200, estimate.text
    vacuum_card = (await page.fragment("data", "vacuum")).text
    assert "twice the file" in vacuum_card
    runbooks = (REPO / "docs" / "RUNBOOKS.md").read_text(encoding="utf-8")
    section = runbooks.split("## Disk full or database large", 1)[1].split("\n## ", 1)[0]
    step = next(line for line in section.splitlines() if "VACUUM" in line and "free" in line)
    assert "twice" in step, step
