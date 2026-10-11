"""The Credential page (`/admin/credential`, plan 14.1, C1, C2, D1): integration tests against the real app.

What this is
    Tests with the real credential manager (a fake value written at runtime) and data written by the real services:
    the page and every card fragment answer 200 for an admin and redirect otherwise, every registry card and every
    inline setting of the `credential#*` anchors is there, the value is never in any HTML (only its masked suffix,
    before and after a replace), the numbers equal the admin API's, the allowlist forms post to the API with CSRF and
    a fresh second factor (a delete needs neither the factor nor more than CSRF), the replace needs the typed C1
    confirmation and a fresh factor, a check shows its probe, hostile text stays inert in the cards, the drawer and
    the tester, no filter or bad value ever fails the page, and an empty database explains owner decision D1.

Why it exists
    The P11 contract, and plan C1, C2 and 9.8: the credential is the most sensitive value Roxy holds.

What to read next
    `roxy/admin/pages/credential.py`, `tests/e2e/test_page_credential.py`.
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest

from pages_harness import HOSTILE, parse_html
from roxy.admin.api.credential import REPLACE_CONFIRMATION
from roxy.admin.pages import registry
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/credential"
PAGE_ID = "credential"
ROW = "/admin/credential/allowlist-row"
TESTER = "/admin/credential/allowlist-test"
PATTERN = "economy.roblox.com/v1/user/currency"
WINDOW = 24


def _cards() -> list[registry.CardSpec]:
    return list(registry.cards_for(PAGE_ID))


def _leaks(html: str, value: str) -> list[str]:
    """Where `value` shows in `html`: whole, or any 24 character window of it (case ignored)."""
    folded = html.lower()
    secret = value.lower()
    found = ["whole value"] if secret in folded else []
    for start in range(len(secret) - WINDOW + 1):
        if secret[start : start + WINDOW] in folded:
            found.append(f"window at {start}")
            break
    return found


async def _all_html(page: Any, *extra: tuple[str, dict[str, Any]]) -> list[tuple[str, str]]:
    out = [("page", (await page.get(PAGE)).text)]
    for card in _cards():
        out.append((card.id, (await page.fragment(PAGE_ID, card.id)).text))
    for path, params in extra:
        out.append((path, (await page.get(path, params=params, htmx=True)).text))
    return out


async def _add_row(page: Any, **fields: Any) -> int:
    body = {"pattern": PATTERN, "cache_private": True, "reason": "page test", **fields}
    created = await page.api("POST", "credential-allowlist", json=body)
    assert created.status_code == 201, created.text
    return int(created.json()["item"]["id"])


# ============================================================================================ guards and structure


async def test_the_page_its_fragments_and_partials_need_a_signed_in_admin(anon: Any) -> None:
    extra = (f"{ROW}?id=1", f"{TESTER}?target=x")
    for path in [PAGE, *(f"{PAGE}/fragment/{card.id}" for card in _cards()), *extra]:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_renders_without_an_error_and_holds_its_settings(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    response = await page.get(PAGE)
    doc = parse_html(response.text)
    for card in _cards():
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        fragment = await page.doc(f"{PAGE}/fragment/{card.id}")
        section = fragment.select_one(f"section#{card.id}[data-card]")
        assert section is not None, card.id
        assert fragment.select_one("[data-card-error]") is None, (card.id, section.text()[:300])
        for spec in registry.settings_for(registry.anchor(PAGE_ID, card.id)):
            assert section.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card.id, spec.key)
    assert not doc.select("[data-card-error]")
    assert doc.select_one('link[href*="css/pages/credential"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/credential"]') is not None
    assert find_style_issues(response.text, "credential page") == []
    for card in _cards():
        assert find_style_issues((await page.fragment(PAGE_ID, card.id)).text, card.id) == []


# ============================================================================================ the value (C2, 9.8)


async def test_the_value_never_reaches_any_html_before_or_after_a_replace(
    page: Any, pages_app: Any, fake_secrets: dict[str, str]
) -> None:
    bootstrap = fake_secrets["roblox_credential"]
    row_id = await _add_row(page)
    extra = ((ROW, {"id": row_id}), (TESTER, {"target": PATTERN}))
    for where, html in await _all_html(page, *extra):
        assert _leaks(html, bootstrap) == [], where
    status = await page.doc(f"{PAGE}/fragment/status")
    assert "…" + bootstrap[-6:] in status.text()  # the masked suffix only (parity row 27)
    new_value = "PAGETESTVALUE" + secrets.token_hex(96).upper()
    replaced = await page.api(
        "POST", "credential/replace", json={"value": new_value, "confirm": REPLACE_CONFIRMATION, "reason": "page"}
    )
    assert replaced.status_code == 200, replaced.text
    for where, html in await _all_html(page, *extra):
        assert _leaks(html, new_value) == [], where
        assert _leaks(html, bootstrap) == [], where
    after = await page.doc(f"{PAGE}/fragment/status")
    assert "…" + new_value[-6:] in after.text()
    assert "set from this page" in after.text()
    replace = await page.doc(f"{PAGE}/fragment/replace")
    delete = replace.select_one("#dlg-credential-delete form[data-api-form]")
    assert delete is not None  # a dashboard value is in use: going back to the bootstrap file is offered
    assert delete.get("data-api-url") == "/admin/api/v1/credential/ui-value"
    assert delete.get("data-api-method") == "DELETE"


# ============================================================================================ caller text


async def test_hostile_text_is_inert_in_cards_the_drawer_and_the_tester(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_traffic()
    row_id = await _add_row(page, note=HOSTILE["img"] + HOSTILE["attr"])
    extra = (
        (ROW, {"id": row_id}),
        (TESTER, {"target": "economy.roblox.com/v1/" + HOSTILE["img"]}),
        (TESTER, {"target": HOSTILE["js_url"], "method": HOSTILE["attr"][:8]}),
    )
    for where, html in await _all_html(page, *extra):
        inert(html, f"credential {where}")
    table = await page.doc(f"{PAGE}/fragment/allowlist")
    assert HOSTILE["img"] in table.text()  # shown, as text
    drawer = await page.doc(ROW, params={"id": row_id})
    note = drawer.select_one("#allow-edit-note")
    assert note is not None
    assert HOSTILE["img"] in (note.get("value") or "")  # a form value, never markup


# ============================================================================================ one source of truth


async def test_the_numbers_equal_the_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    await _add_row(page)
    checked = await page.api("POST", "credential/check")
    assert checked.status_code == 200, checked.text
    await pages_app.flush()
    status = (await page.api("GET", "credential")).json()
    status_doc = await page.doc(f"{PAGE}/fragment/status")
    assert status["masked"] in status_doc.text()
    assert status["fingerprint"] in status_doc.text()
    budget = (await page.api("GET", "credential/budget")).json()
    budget_doc = await page.doc(f"{PAGE}/fragment/budget")
    hour = budget["last_hour"]
    assert f"{hour['caller_calls'] + hour['probe_calls']:,}" in budget_doc.select_one(".g3-stats").text()
    assert f"{hour['probe_calls']:,} probes" in budget_doc.text()
    probes = (await page.api("GET", "credential/probes")).json()
    probes_doc = await page.doc(f"{PAGE}/fragment/probes")
    assert len(probes_doc.select("#probes tbody tr")) == len(probes["items"]) >= 1
    allowlist = (await page.api("GET", "credential-allowlist")).json()
    allowlist_doc = await page.doc(f"{PAGE}/fragment/allowlist")
    rows = allowlist_doc.select('[data-table="credential_allowlist"] tbody tr[data-row-id]')
    assert len(rows) == allowlist["total"] == 1
    tested = (await page.api("GET", "credential-allowlist/test", params={"target": PATTERN})).json()
    tester = await page.doc(TESTER, params={"target": PATTERN})
    assert tested["granted"] is True
    assert f"row #{tested['rule']['id']}" in tester.text()
    assert "kept private" in tester.text()


# ============================================================================================ actions go to the API


async def test_the_allowlist_forms_need_csrf_and_a_fresh_factor_and_the_delete_only_csrf(page: Any) -> None:
    doc = await page.doc(f"{PAGE}/fragment/allowlist")
    form = doc.select_one('form[data-api-url="/admin/api/v1/credential-allowlist"]')
    assert form is not None
    assert form.get("data-api-method") == "POST"
    radios = form.select('input[type="radio"][name="cache_private"]')
    assert len(radios) == 2
    assert not any(radio.get("checked") is not None for radio in radios)  # the choice is never made for you
    assert form.select_one('textarea[name="reason"][required]') is not None
    body = {"pattern": PATTERN, "cache_private": False, "reason": "page test"}
    assert (await page.api("POST", "credential-allowlist", json=body, csrf=False)).status_code == 403
    page.make_mfa_stale()
    stale = await page.api("POST", "credential-allowlist", json=body)
    assert stale.status_code == 403
    assert stale.json()["error"]["code"] == "reauth_required"
    await page.fresh_mfa()
    created = await page.api("POST", "credential-allowlist", json=body)
    assert created.status_code == 201, created.text
    row_id = created.json()["item"]["id"]
    listed = await page.doc(f"{PAGE}/fragment/allowlist")
    row = listed.select_one(f'tr[data-row-id="allow-{row_id}"]')
    assert row is not None
    assert row.get("data-drawer-src") == f"{ROW}?id={row_id}"
    drawer = await page.doc(ROW, params={"id": row_id})
    edit = drawer.select_one("form[data-api-method=PATCH]")
    assert edit.get("data-api-url") == f"/admin/api/v1/credential-allowlist/{row_id}"
    remove = drawer.select_one("#dlg-allow-delete form")
    assert remove.get("data-api-url") == f"/admin/api/v1/credential-allowlist/{row_id}"
    assert remove.get("data-api-method") == "DELETE"
    page.make_mfa_stale()
    patch = await page.api("PATCH", f"credential-allowlist/{row_id}", json={"note": "x", "reason": "page"})
    assert patch.status_code == 403
    assert (await page.api("DELETE", f"credential-allowlist/{row_id}", json={}, csrf=False)).status_code == 403
    gone = await page.api("DELETE", f"credential-allowlist/{row_id}", json={"reason": "page test"})
    assert gone.status_code == 200, gone.text  # narrowing what the account is used for needs no fresh factor
    missing = await page.doc(ROW, params={"id": row_id})
    assert "No allowlist row has that id" in missing.text()


async def test_the_replace_needs_the_typed_confirmation_and_a_fresh_factor(page: Any) -> None:
    doc = await page.doc(f"{PAGE}/fragment/replace")
    form = doc.select_one("#dlg-credential-replace form[data-api-form]")
    assert form is not None
    assert form.get("data-api-url") == "/admin/api/v1/credential/replace"
    assert form.get("data-api-method") == "POST"
    assert form.select_one('input[name="value"][type="password"]') is not None
    assert form.select_one('input[name="confirm"][required]') is not None
    assert REPLACE_CONFIRMATION in form.text()
    assert "account farming" in doc.text()  # the C1 warning, the API's own words
    value = "PAGETESTVALUE" + secrets.token_hex(96).upper()
    body = {"value": value, "confirm": REPLACE_CONFIRMATION}
    assert (await page.api("POST", "credential/replace", json=body, csrf=False)).status_code == 403
    page.make_mfa_stale()
    stale = await page.api("POST", "credential/replace", json=body)
    assert stale.status_code == 403
    assert stale.json()["error"]["code"] == "reauth_required"
    await page.fresh_mfa()
    wrong = await page.api("POST", "credential/replace", json={**body, "confirm": "yes"})
    assert wrong.status_code == 422
    assert wrong.json()["error"]["code"] == "confirmation_required"
    assert "confirm" in wrong.json()["error"]["fields"]  # shown under the typed field of the dialog
    check = doc.select_one('#status form[data-api-url="/admin/api/v1/credential/check"]')
    assert check is None  # the check button lives on the Status card, not here
    status = await page.doc(f"{PAGE}/fragment/status")
    check = status.select_one('form[data-api-url="/admin/api/v1/credential/check"]')
    assert check is not None
    page.make_mfa_stale()
    assert (await page.api("POST", "credential/check")).status_code == 403


async def test_a_check_shows_its_probe_and_a_429_reads_rate_limited_never_expired(page: Any, pages_app: Any) -> None:
    checked = await page.api("POST", "credential/check")
    assert checked.status_code == 200, checked.text
    await pages_app.flush()
    probes = await page.doc(f"{PAGE}/fragment/probes")
    rows = probes.select("#probes tbody tr")
    assert len(rows) == 1
    assert "Check credential (admin)" in rows[0].text()  # the probe's trigger, in words
    assert "OK" in rows[0].select_one('td[data-label="Outcome"]').text()
    status = await page.doc(f"{PAGE}/fragment/status")
    assert "No probe yet" not in status.text()
    # Roblox answers the next probe 429 (the stand-in does on `/too-many` paths): slow down, never "expired".
    await pages_app.settings(credential_probe_url="https://users.roblox.com/v1/too-many")
    limited = await page.api("POST", "credential/check")
    assert limited.status_code == 200, limited.text
    assert limited.json()["probe"]["outcome"] == "rate_limited"
    await pages_app.flush()
    newest = (await page.doc(f"{PAGE}/fragment/probes")).select("#probes tbody tr")[0]
    assert "Rate limited" in newest.select_one('td[data-label="Outcome"]').text()
    after = (await page.doc(f"{PAGE}/fragment/status")).text()
    assert "Cooling down" in after
    assert "Rate limited (a 429 means slow down, never expired)" in after
    assert "expired or was revoked" not in after


@pytest.mark.parametrize(
    ("path", "params"),
    [
        (PAGE, {"page": "abc", "page_size": "7", "sort": "bogus", "order": "sideways"}),
        (PAGE, {"q": "x" * 600}),
        (PAGE, {"range": "forever"}),
        (PAGE, {"range": "custom", "from": "yesterday"}),
        (PAGE, {"page": "99999999"}),
        (f"{PAGE}/fragment/allowlist", {"page": "0", "sort": "nope"}),
        (f"{PAGE}/fragment/budget", {"range": "all"}),
        (ROW, {"id": "abc"}),
        (ROW, {"id": "0"}),
        (ROW, {"id": "99999999999999999999999"}),
        (TESTER, {"target": ""}),
        (TESTER, {"target": "/"}),
        (TESTER, {"target": PATTERN, "method": "DELETE"}),
    ],
    ids=lambda value: value if isinstance(value, str) else "-".join(value),
)
async def test_no_filter_range_or_bad_value_ever_fails_the_page(page: Any, path: str, params: dict[str, str]) -> None:
    response = await page.get(path, params=params, htmx=path != PAGE)
    assert response.status_code == 200, (path, params, response.text[:300])
    if path == PAGE:
        assert "data-card-error" not in response.text, params


# ============================================================================================ empty database


async def test_an_empty_database_explains_itself(page: Any) -> None:
    allowlist = (await page.doc(f"{PAGE}/fragment/allowlist")).text()
    assert "No endpoint may use the credential" in allowlist
    assert "owner decision D1" in allowlist
    probes = (await page.doc(f"{PAGE}/fragment/probes")).text()
    assert "No probes yet" in probes
    status = (await page.doc(f"{PAGE}/fragment/status")).text()
    assert "Not checked yet" in status
    assert "No probe yet" in status
    tester = await page.doc(TESTER, params={"target": PATTERN})
    assert "never uses the credential" in tester.text()
