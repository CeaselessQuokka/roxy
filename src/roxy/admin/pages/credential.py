"""The Credential page (`/admin/credential`, plan 14.1, C1, C2, D1): the one Roblox account Roxy may use.

What this is
    One card per registry card of page `credential` (DESIGN.md section 9 anchors):
      * `status`: whether the credential works (in words, never color alone), its masked suffix (an ellipsis and the
        last 6 characters, parity row 27; the value itself is never shown), its fingerprints and the account
        fingerprint match, where it was loaded from (v1's "Tokens Loaded"), its cooldown with a countdown, the last
        probe, v1's "Token" health (calls, rejections, timeouts, last success and error), and "Check credential"
        (a probe; a fresh second factor).
      * `budget`: v1's "Token Safety Budget": the account bucket and the reserved probe bucket (fill gauges, rate,
        refusals and peak fill in the range) and the credential calls of the last hour and day (plan 13.3).
      * `probes`: the latest probes (Roxy's own calls with the credential) with their outcome.
      * `allowlist`: the endpoints the credential may be used for (owner decision D1: none by default), the page's
        main table, with the required `cache_private` choice, an add form, a tester and a drawer per row (edit,
        delete). Adding or changing a row needs a fresh second factor and a reason; deleting one does not.
      * `replace`: the plan C1 replace (the warning, the typed confirmation `replace the credential`, a fresh second
        factor), deleting the dashboard value to go back to the bootstrap file, and the typed account switch
        confirmation when the bootstrap value belongs to another account.
    The `credential#status` and `credential#budget` settings are edited inline by the kit's settings block (they
    need a fresh second factor, the settings API's rule for the credential group).

Why it exists
    Plan C1: exactly one credential, replaced only by a deliberate, audited act whose confirmation explains the risk;
    plan C2 and 9.8: the value never leaves `egress/credential.py`. This page shows only what the API answers
    (`roxy/admin/api/credential.py status_answer`, `budget_answer`, `probes_answer`; `credential_allowlist.py
    allowlist_rows`, `target_answer`), which never holds the value (plan P6: the same functions, the same numbers).
    Every change goes to the admin API (CSRF, the fresh second factor, the typed confirmations and the audit log
    are judged there).

How it works
    `page = Page("credential")`; each card renderer returns the context of
    `templates/admin/pages/credential/<card>.html`. Two small page routes serve partials: `/admin/credential/allowlist-row?id=` (a row's drawer) and
    `/admin/credential/allowlist-test?target=&method=` (the tester's answer). Allowlist patterns and notes are
    caller text (an admin typed them, but they are shown as text everywhere, like every other rule).

What to read next
    `templates/admin/pages/credential.html`, `roxy/admin/api/credential.py`, `roxy/egress/credential.py`,
    `static/js/pages/credential.js`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.admin.api import common
from roxy.admin.api import credential as credential_api
from roxy.admin.api import credential_allowlist as allowlist_api
from roxy.admin.api import upstream as upstream_api
from roxy.admin.api.routing_rules import MAX_TARGET_CHARS
from roxy.admin.pages._upstream_common import gauge, ms_text, per_min_text, precision_words, render_partial
from roxy.admin.pages.kit import Page, PageAdmin, PageView, table_query, table_view

page = Page("credential")
router = page.router

API: Final = common.API_PREFIX
STATUS_WORDS: Final[dict[str, tuple[str, str, str]]] = {
    "active": ("ok", "Working", "Roblox accepted the credential at its last check."),
    "unknown": (
        "info",
        "Not checked yet",
        "A credential is loaded; the next probe (or Check credential) tells whether it works.",
    ),
    "cooling_down": (
        "warn",
        "Cooling down",
        "Roblox answered a credential call with 429; it rests until the cooldown ends.",
    ),
    "rejected": ("bad", "Rejected", "Roblox refused the credential (expired or revoked), so Roxy no longer uses it."),
    "absent": ("bad", "None loaded", "No credential is loaded: only anonymous paths are used."),
}
SOURCE_WORDS: Final[dict[str, str]] = {
    "ui": "set from this page",
    "bootstrap": "the bootstrap file (systemd credential roblox_credential)",
}
PROBE_WORDS: Final[dict[str, str]] = {
    "ok": "OK: Roblox accepted it",
    "ok_no_account_id": "OK, but the answer named no account",
    "account_confirmed": "OK: the account switch was confirmed",
    "account_mismatch": "A different account than before: not used until you confirm",
    "rejected": "Rejected: the cookie expired or was revoked",
    "rate_limited": "Rate limited (a 429 means slow down, never expired)",
    "cooling_down": "Skipped: the credential was cooling down",
    "busy": "Skipped: another probe was running",
    "skipped_rejected": "Skipped: the credential is rejected",
    "absent": "Skipped: no credential is loaded",
    "disabled": "Skipped: the credential is switched off",
    "degraded": "Skipped: Roxy's shared state could not be used",
    "timeout": "Failed: Roblox did not answer in time",
    "connect_error": "Failed: Roblox could not be reached",
}
PURPOSE_WORDS: Final[dict[str, str]] = {
    "credential_probe": "Scheduled liveness probe",
    "credential_check": "Check credential (admin)",
    "credential_confirm": "Confirm a 401 before marking it rejected",
}
METHOD_CHOICES: Final[tuple[tuple[str, str], ...]] = (
    ("GET", "GET only"),
    ("GET\nHEAD", "GET and HEAD"),
    ("HEAD", "HEAD only"),
)
"""The methods select: a value holds one method per line (`data-json="list"`), the API's list body."""


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _seconds_from_ms(value: Any) -> float | None:
    number = _number(value)
    return number / 1000 if number is not None else None


def _probe_words(result: Any) -> str:
    if not isinstance(result, Mapping):
        return "No probe yet"
    code = str(result.get("result") or result.get("outcome") or "")
    return PROBE_WORDS.get(code, code.replace("_", " ") or "n/a")


# ============================================================================================ status


@page.card("status")
async def status_card(view: PageView) -> dict[str, Any]:
    """The credential's state (`status_answer`) and v1's Token health (`upstream.egress_cards_answer`)."""
    answer = await credential_api.status_answer(view.ctx)
    cards = await upstream_api.egress_cards_answer(view.ctx, view.tr)
    health: dict[str, Any] = next((item for item in cards["items"] if item.get("egress") == "credential"), {})
    status = str(answer.get("status") or "")
    tone, words, detail = STATUS_WORDS.get(status, ("neutral", status or "n/a", ""))
    if not answer.get("enabled"):
        tone, words, detail = "neutral", "Switched off", "credential_enabled is 0: no call uses the credential."
    cooldown = answer.get("cooldown") or None
    countdown = None
    if isinstance(cooldown, Mapping) and _number(cooldown.get("ends_at_ms")) is not None:
        countdown = {
            "ends_at_ms": int(cooldown["ends_at_ms"]),
            "now_ms": int(answer.get("now_ms") or 0),
            "remaining_s": round(float(cooldown.get("remaining_s") or 0), 1),
        }
    account = answer.get("account") or {}
    return {
        "answer": answer,
        "tone": tone,
        "words": words,
        "state_detail": detail,
        "source_words": SOURCE_WORDS.get(str(answer.get("source") or ""), "none"),
        "set_when": view.time_cell(answer.get("set_at")),
        "probe_when": view.time_cell(answer.get("last_probe_at")),
        "probe_words": _probe_words(answer.get("last_probe_result")),
        "cooldown": cooldown,
        "countdown": countdown,
        "account": account,
        "health": health,
        "last_success": view.time_cell(health.get("last_success_at")),
        "last_success_precision": precision_words(health.get("last_success_precision")),
        "last_error_at": view.time_cell(health.get("last_error_at")),
        "check_url": f"{API}/credential/check",
    }


# ============================================================================================ budget


@page.card("budget")
async def budget_card(view: PageView) -> dict[str, Any]:
    """v1's Token Safety Budget: `budget_answer` (buckets now, calls of the last hour and day) and the range's
    reservations, refusals and peak fill of the two credential buckets (`upstream.bucket_rows`)."""
    answer = await credential_api.budget_answer(view.ctx)
    rows = {str(row["key"]): row for row in await upstream_api.bucket_rows(view.ctx, view.tr)}
    buckets = []
    for name, label in (
        ("account_bucket", "The account (callers on the allowlist and probes)"),
        ("probe_bucket", "Reserved for Roxy's probes"),
    ):
        bucket = answer.get(name) or {}
        history = rows.get(str(bucket.get("key"))) or {}
        detail = f"{per_min_text(bucket.get('per_min'))}, burst {bucket.get('burst', 'n/a')}"
        if _number(bucket.get("next_free_in_ms")):
            detail += f"; the next call would wait {ms_text(bucket.get('next_free_in_ms'))}"
        buckets.append(
            {
                "gauge": gauge(label, bucket.get("fill_pct"), detail=detail, key=str(bucket.get("key") or "")),
                "attempts": int(history.get("attempts") or 0),
                "rejections": int(history.get("rejections") or 0),
                "peak": history.get("fill_pct_peak"),
            }
        )
    return {"answer": answer, "buckets": buckets}


# ============================================================================================ probes


@page.card("probes")
async def probes_card(view: PageView) -> dict[str, Any]:
    """The latest probes, newest first (`probes_answer`, the API's own function)."""
    answer = await credential_api.probes_answer(view.ctx)
    items = [
        {
            **item,
            "when": view.time_cell(_seconds_from_ms(item.get("at_ms"))),
            "purpose_words": PURPOSE_WORDS.get(str(item.get("purpose")), str(item.get("purpose"))),
            "duration": ms_text(item.get("duration_ms")),
        }
        for item in answer.get("items") or ()
    ]
    return {"items": items, "last_words": _probe_words(answer.get("last_probe_result"))}


# ============================================================================================ allowlist


def _allowlist_cells(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": {"text": f"#{item['id']}", "mono": True},
        "pattern": {"text": item.get("pattern"), "caller": True, "mono": True},
        "methods": ", ".join(item.get("methods") or ()),
        "cache_private": {"text": "Private", "tone": "ok"}
        if item.get("cache_private")
        else "Shared with credential calls",
        "identical_anonymous": "Yes" if item.get("identical_anonymous") else "No",
        "enabled": {"text": "On", "tone": "ok"} if item.get("enabled") else {"text": "Off", "tone": "muted"},
        "note": {"text": item.get("note"), "caller": True} if item.get("note") else None,
        "created_by": {"text": item.get("created_by"), "caller": True} if item.get("created_by") else None,
    }


@page.card("allowlist")
async def allowlist_card(view: PageView) -> dict[str, Any]:
    """The allowlist rows (`allowlist_rows`, the page's main table), the D1 notice, the add form and the tester."""
    tq, notice = table_query(view, allowlist_api.SPEC)
    rows = await allowlist_api.allowlist_rows(view.ctx)
    answer = allowlist_api.allowlist_answer(rows, tq)
    table = table_view(
        view,
        "credential-allowlist",
        allowlist_api.SPEC,
        answer,
        src=view.fragment_url("allowlist"),
        columns=(
            "id",
            "pattern",
            "type",
            "methods",
            "cache_private",
            "identical_anonymous",
            "enabled",
            "note",
            "created_at",
            "created_by",
        ),
        key_columns=("id", "pattern", "cache_private"),
        hidden=("type", "identical_anonymous", "created_at", "created_by"),
        cells=_allowlist_cells,
        row_id=lambda item: f"allow-{item['id']}",
        drawer=lambda item: "/admin/credential/allowlist-row?" + urlencode({"id": item["id"]}),
        drawer_title=lambda item: f"Allowlist row #{item['id']}",
        export_url=f"{API}/credential-allowlist",
        caption="Credential allowlist",
        empty={
            "title": "No endpoint may use the credential",
            "body": "This is the default (owner decision D1): callers never get the account; only Roxy's own probes "
            "use it. Add a row only for an endpoint that answers nothing useful without the account.",
            "tone": "good",
            "icon": "key",
        },
        search_placeholder="Search the allowlist",
        notice=notice,
    )
    help_texts = answer.get("help") or {}
    return {
        "table": table,
        "help": help_texts,
        "create_url": f"{API}/credential-allowlist",
        "methods": METHOD_CHOICES,
    }


@page.router.get("/allowlist-row", include_in_schema=False)
async def allowlist_row_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """One allowlist row in the drawer: its fields, the edit form (PATCH, fresh second factor, reason) and the
    delete dialog (DELETE)."""

    async def build(view: PageView) -> dict[str, Any]:
        raw = view.param("id", max_chars=24)
        if not raw.isdigit() or not 1 <= int(raw) <= common.MAX_ROW_ID:
            raise common.not_found("Choose a row from the table; that row number is not valid.")
        row_id = int(raw)
        found = next((item for item in await allowlist_api.allowlist_rows(view.ctx) if item["id"] == row_id), None)
        if found is None:
            raise common.not_found("No allowlist row has that id. It may have been deleted.")
        methods = "\n".join(found.get("methods") or ())
        return {
            "row": found,
            "url": f"{API}/credential-allowlist/{row_id}",
            "methods": METHOD_CHOICES,
            "methods_value": methods,
            "created": view.time_cell(found.get("created_at")),
            "updated": view.time_cell(found.get("updated_at")),
            "help": {"cache_private": allowlist_api.CACHE_PRIVATE_HELP, "exact": allowlist_api.EXACT_HELP},
        }

    return await render_partial(page, request, principal, "admin/pages/credential/_allowlist_row.html", build)


@page.router.get("/allowlist-test", include_in_schema=False)
async def allowlist_test(request: Request, principal: PageAdmin) -> HTMLResponse:
    """The allowlist tester's answer (`credential_allowlist.target_answer`, the API's own function)."""

    async def build(view: PageView) -> dict[str, Any]:
        target = view.param("target", max_chars=MAX_TARGET_CHARS)
        if not target:
            raise common.validation_error(
                {"target": "Give a host and path such as users.roblox.com/v1/users/authenticated."}
            )
        method = view.param("method", "GET", max_chars=8)
        return {"answer": allowlist_api.target_answer(view.ctx, target, method)}

    return await render_partial(page, request, principal, "admin/pages/credential/_allowlist_test.html", build)


# ============================================================================================ replace


@page.card("replace")
async def replace_card(view: PageView) -> dict[str, Any]:
    """The C1 replace, the dashboard value delete and the account switch confirmation (texts from `status_answer`,
    the API's own function, so the page warns with the words the API checks)."""
    answer = await credential_api.status_answer(view.ctx)
    return {
        "answer": answer,
        "texts": answer.get("texts") or credential_api.texts(),
        "account": answer.get("account") or {},
        "replace_url": f"{API}/credential/replace",
        "delete_url": f"{API}/credential/ui-value",
        "confirm_url": f"{API}/credential/confirm-account",
    }


__all__ = ["page", "router"]
