"""P11 review, functional lens: reproductions against the real app in process (regression tests since the fixes).

What this is
    Each test reproduces one finding of `.remake/p11_review/find_functional.md` with the integration fixtures of
    `tests/integration/pages/conftest.py` (the real app, the real login, data sent through the real proxy). A test
    reads the form a page renders (its API URL, method and fields, as `static/js/api_forms.js` would send them) and
    sends that body to the admin API, so it fails for the reason the finding names and passes once the page or the
    API is fixed, whichever side the fix lands on.

Why it exists
    The review rule: a finding without a reproduction is not a finding. Every test was
    `@pytest.mark.xfail(strict=True)` until the P11 review round fixed its finding (functional-1 through its
    duplicate authz-2); each is a regression test now, with a comment above it naming the fix.

How it works
    `form_body(form, overrides)` mirrors `api_forms.js formBody`: every named field except `data-json="never"` ones
    and those inside a hidden `[data-confirm-field]`, typed by `data-json` (`bool`, `int`, `float`, `list`, `string`,
    and skip-empty text by default), a checkbox as its checked state, a select as its selected option.

What to read next
    `tests/review_p11/test_functional_e2e.py` (the browser half), `static/js/api_forms.js`,
    `.remake/p11_review/find_functional.md`.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)

from __future__ import annotations

from typing import Any

import pytest

from integration.pages.conftest import anon, page, page_admin, pages_app  # noqa: F401  (the page fixtures)
from pages_harness import Node, parse_html

DASH = chr(0x2014)
"""An em dash built at run time: the admin API refuses it in caller-visible text (plan C5), and C5 also means the
source of this file never holds one."""


def _inside_hidden_confirm(node: Node) -> bool:
    parent = node.parent
    while parent is not None:
        if "data-confirm-field" in parent.attrs and "hidden" in parent.attrs:
            return True
        parent = parent.parent
    return False


def _raw_value(node: Node) -> Any:
    if node.tag == "select":
        options = node.select("option")
        chosen = next((option for option in options if "selected" in option.attrs), options[0] if options else None)
        return chosen.get("value", "") if chosen is not None else ""
    if node.tag == "textarea":
        return node.text()
    if node.get("type") == "checkbox":
        return "checked" in node.attrs
    return node.get("value", "") or ""


def form_body(form: Node, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """The JSON body `api_forms.js formBody` builds from `form`, with `overrides` typed into its fields first."""
    overrides = overrides or {}
    body: dict[str, Any] = {}
    for node in form.select("input[name], select[name], textarea[name]"):
        name = node.get("name") or ""
        kind = node.get("data-json") or ("bool" if node.get("type") == "checkbox" else "skip-empty")
        if "disabled" in node.attrs or kind == "never" or _inside_hidden_confirm(node):
            continue
        if node.get("type") == "radio" and "checked" not in node.attrs:
            continue
        raw = overrides.get(name, _raw_value(node))
        if kind == "bool":
            value: Any = raw if isinstance(raw, bool) else str(raw).strip().lower() in ("true", "1", "on", "yes")
        elif kind in ("int", "float"):
            text = str(raw).strip().replace(",", "")
            if text == "":
                continue
            try:
                value = int(text) if kind == "int" else float(text)
            except ValueError:
                value = text
        elif kind == "list":
            value = [line.strip() for line in str(raw).splitlines() if line.strip()]
        elif kind == "string":
            value = str(raw)
        else:
            if str(raw).strip() == "":
                continue
            value = str(raw)
        body[name] = value
    return body


async def submit(page: Any, form: Node, overrides: dict[str, Any] | None = None) -> Any:
    """Send `form` the way the dashboard does (its URL, its method, its fields)."""
    method = form.get("data-api-method") or "POST"
    return await page.api(method, form.get("data-api-url") or "", json=form_body(form, overrides))


# ============================================================================================ functional-1


# Refuted as a duplicate of authz-2 (same root cause in settings.write_rules); fixed there in the P11 review round
# (shared fixer: an empty allowlist switched on is refused, a lockout needs confirm_lockout): a regression test now.
async def test_switching_the_admin_allowlist_on_never_locks_out_the_admin_doing_it(page: Any, pages_app: Any) -> None:
    rows = (await page.api("GET", "protection/access/allow_admin")).json()
    assert rows["total"] == 0, "no network is on the admin allowlist yet"
    card = await page.get("/admin/security/fragment/admin-access", htmx=True)
    assert card.status_code == 200, card.text[:300]
    control = parse_html(card.text).select_one('form[data-setting-key="admin_allowlist_enabled"]')
    assert control is not None, "Security > Admin access holds the switch"
    await page.fresh_mfa()  # the control asks "Confirm it is you" first (data-fresh-mfa)
    # What settings_api.js sends when the admin flips the switch, reviews it and presses Save:
    saved = await page.api(
        "PUT",
        control.get("data-setting-api") or "",
        json={"value": "1", "reason": "hide /admin", "confirm_high_risk": False},
    )
    after = await page.get("/admin/security")
    assert after.status_code == 200, (
        f"the save answered {saved.status_code} and the dashboard is now a plain 404 for the admin who saved it "
        f"(and for every other network: the list is empty); only the server console can undo it"
    )


# ============================================================================================ functional-2


# Fixed in the P11 review round (functional-2, shared fixer): a regression test now.
async def test_the_top_bar_resume_ends_a_scheduled_maintenance_window(page: Any, pages_app: Any) -> None:
    now = int(pages_app.clock.now())
    scheduled = await page.api(
        "PUT",
        "protection/pause/schedule",
        json={"start": now - 60, "end": now + 3600, "message": "Planned maintenance"},
    )
    assert scheduled.status_code == 200, scheduled.text
    doc = await page.doc("/admin/overview")
    assert doc.select_one("#banner-pause-title") is not None, "the page says the proxy is paused"
    form = doc.select_one("dialog#dlg-pause form[data-api-form]")
    assert form is not None, "the top bar's pause control opens its dialog"
    answer = await submit(page, form)
    assert answer.status_code == 200, answer.text  # the dialog then says "The proxy is running again."
    state = (await page.api("GET", "protection/pause")).json()
    assert state["active"] is False, f"callers still get 503 after Resume: {state}"


# ============================================================================================ functional-4


DIALOG_CASES = [
    pytest.param("/admin/overview", "dlg-throttle-all", {"limit": "0"}, False, id="emergency-limit-requests"),
    pytest.param("/admin/overview", "dlg-throttle-all", {"period": "0"}, False, id="emergency-limit-period"),
    pytest.param(
        "/admin/protection/fragment/bans",
        "dlg-prot-ban-add",
        {"subject": "203.0.113.77", "message": f"Go away {DASH} now"},
        False,
        id="protection-ban-message",
    ),
    pytest.param(
        "/admin/clients/client?kind=place&key=1818",
        "dlg-client-ban",
        {"message": f"Go away {DASH} now"},
        True,
        id="client-ban-message",
    ),
]


@pytest.mark.parametrize(("path", "dialog", "typed", "seed"), DIALOG_CASES)
# Fixed in the P11 review round (functional-4, shared fixer): a regression test now.
async def test_a_refused_value_is_reported_on_the_field_that_holds_it(
    page: Any, pages_app: Any, path: str, dialog: str, typed: dict[str, Any], seed: bool
) -> None:
    if seed:
        await pages_app.seed_traffic()
    response = await page.get(path, htmx="/fragment/" in path)
    assert response.status_code == 200, response.text[:300]
    form = parse_html(response.text).select_one(f"dialog#{dialog} form[data-api-form]")
    assert form is not None, dialog
    answer = await submit(page, form, typed)
    assert answer.status_code == 422, answer.text
    fields = answer.json()["error"]["fields"]
    assert fields, answer.text
    # api_forms.js puts a field's message under `[name=<key>]` or into `[data-field-error=<key>]`; any other key
    # leaves only the general line ("The change was refused; nothing was saved.") with no reason at all.
    unplaced = {
        key: message
        for key, message in fields.items()
        if form.select_one(f'[name="{key}"]') is None and form.select_one(f'[data-field-error="{key}"]') is None
    }
    assert unplaced == {}, f"{dialog}: messages with no field to show them: {unplaced}"


# ============================================================================================ functional-7


PAGE_CASES = [
    pytest.param("/admin/audit", {"range": "all"}, id="audit"),
    pytest.param("/admin/endpoints", {"range": "24h"}, id="endpoints"),
]


# Fixed in the P11 review round (functional-7, shared fixer): a regression test now.
@pytest.mark.parametrize(("path", "params"), PAGE_CASES)
async def test_a_page_number_past_the_end_still_shows_rows(
    page: Any, pages_app: Any, path: str, params: dict[str, str]
) -> None:
    await pages_app.seed_all()
    doc = await page.doc(path, params={**params, "page_size": "10", "page": "99"})
    table = doc.select_one("[data-dt-address]")
    assert table is not None
    count = table.select_one(".dt__count").text()
    assert "of" in count, f"{path}: the range holds rows ({count})"
    rows = table.select("tbody tr[data-row-id]")
    assert rows, f"{path}: the table says {count!r} and shows no row (the empty state instead)"


# ============================================================================================ functional-9


async def _arm_then_disarm(page: Any) -> None:
    token = (await page.api("GET", "protection/spam/collateral")).json()["token"]
    armed = await page.api("POST", "protection/spam/arm", json={"confirm_collateral": token, "reason": "arm"})
    assert armed.status_code == 200, armed.text
    disarmed = await page.api(
        "PUT", "settings/spam_dry_run", json={"value": "1", "reason": "back to dry run", "confirm_high_risk": True}
    )
    assert disarmed.status_code == 200, disarmed.text


# Fixed in the P11 review round (functional-9, shared fixer): a regression test now.
async def test_the_audit_drawer_offers_no_revert_the_api_must_refuse(page: Any, pages_app: Any) -> None:
    await _arm_then_disarm(page)
    log = (await page.api("GET", "audit", params={"target": "setting:spam_dry_run"})).json()
    entry = log["items"][0]
    assert entry["action"] == "setting.update", entry
    drawer = await page.fragment("audit", "entry", entry=entry["id"])
    form = parse_html(drawer.text).select_one("form.audit-revert[data-api-form]")
    if form is None:
        return  # not offered: the Settings history drawer's behavior for an arming revert
    first = await submit(page, form, {"reason": "undo the disarm"})
    assert first.status_code == 422, first.text
    assert first.json()["error"]["code"] == "confirmation_required", first.text
    # api_forms.js reveals the form's only confirmation ("I understand: the old value is high risk"); ticked:
    again = await page.api(
        form.get("data-api-method") or "POST",
        form.get("data-api-url") or "",
        json={"reason": "undo the disarm", "confirm_high_risk": True},
    )
    assert not (again.status_code == 422 and again.json()["error"]["code"] == "confirmation_required"), (
        f"the form asks for a confirmation that can never satisfy the API: {again.text}"
    )


# Fixed in the P11 review round (functional-9, shared fixer): a regression test now.
async def test_the_import_preview_says_when_the_import_will_be_refused(page: Any, pages_app: Any) -> None:
    exported = await page.api("GET", "settings/export")
    assert exported.status_code == 200, exported.text
    document = {**exported.json(), "overrides": {"spam_dry_run": 0}}
    preview = (await page.api("POST", "settings/import/preview", json={"document": document, "replace": False})).json()
    imported = await page.api(
        "POST",
        "settings/import",
        json={"document": document, "replace": False, "reason": "restore a backup", "confirm_high_risk": True},
    )
    assert not (preview["ok"] and preview["changes"] and imported.status_code == 422), (
        f"the preview enabled Import ({preview['ok']=}, {preview['confirm_required']=}) but the import was refused: "
        f"{imported.text}"
    )
