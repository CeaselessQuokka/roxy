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
      * `replace`: the plan C1 replace (the warning, the typed confirmation `replace the credential`, a fresh second
        factor), deleting the dashboard value to go back to the bootstrap file, and the typed account switch
        confirmation when the bootstrap value belongs to another account.
    The `credential#status` and `credential#budget` settings are edited inline by the kit's settings block (they
    need a fresh second factor, the settings API's rule for the credential group). Which caller requests carry the
    credential is the Endpoint policy page's (`roxy/admin/pages/policy.py`, D1 revised 2026-10-16); the old
    allowlist card is gone.

Why it exists
    Plan C1: exactly one credential, replaced only by a deliberate, audited act whose confirmation explains the risk;
    plan C2 and 9.8: the value never leaves `egress/credential.py`. This page shows only what the API answers
    (`roxy/admin/api/credential.py status_answer`, `budget_answer`, `probes_answer`), which never holds the value
    (plan P6: the same functions, the same numbers).
    Every change goes to the admin API (CSRF, the fresh second factor, the typed confirmations and the audit log
    are judged there).

How it works
    `page = Page("credential")`; each card renderer returns the context of
    `templates/admin/pages/credential/<card>.html`. A probe's "why" comes from its recorded trigger (`TRIGGER_WORDS`);
    its outcome says "Rate limited" for a 429, never "expired" (parity row 25).

What to read next
    `templates/admin/pages/credential.html`, `roxy/admin/api/credential.py`, `roxy/egress/credential.py`,
    `static/js/pages/credential.js`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from roxy.admin.api import common
from roxy.admin.api import credential as credential_api
from roxy.admin.api import upstream as upstream_api
from roxy.admin.pages._upstream_common import gauge, ms_text, per_min_text, precision_words
from roxy.admin.pages.kit import Page, PageView

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
    "replaced": "Not checked yet since the replace",
    "account_changed": "OK: a different account than before the replace (replaced on purpose)",
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
    "not_confirmed": "Skipped: the account switch waits for your confirmation",
    "TargetNotAllowed": "Failed: the probe address is not an allowed Roblox host",
    "EgressDisabled": "Failed: the credential path is switched off",
}
"""A probe's stored result in words (`egress/credential.py _run_probe` and `_interpret_probe`). Two families carry the
status Roblox answered in the code and are worded by `_probe_words`: `rejected_401` and `rejected_403` (Rejected),
`http_<status>` (an answer that says nothing about the credential; its state is left as it was). Finding docs_a-12:
the Status card printed "rejected 401"."""
TRIGGER_WORDS: Final[dict[str, str]] = {
    "scheduled": "Scheduled liveness probe",
    "admin": "Check credential (admin)",
    "health": "Check Proxy Health (H-CRED-AUTH)",
    "upstream": "Confirm a Roblox 401 before marking it rejected",
}
"""Why a probe ran: the `trigger` every probe records (`upstream/service.py PROBE_TRIGGERS`)."""
PURPOSE_WORDS: Final[dict[str, str]] = {
    "credential_probe": "A probe of the credential",
    "credential_check": "Check credential (admin)",
    "credential_confirm": "Confirm a 401 before marking it rejected",
}
"""The call site, for a probe recorded without a trigger (older rows)."""


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _seconds_from_ms(value: Any) -> float | None:
    number = _number(value)
    return number / 1000 if number is not None else None


def _probe_outcome(item: Mapping[str, Any]) -> tuple[str, str]:
    """`(tone, word)` of one probe row: a 429 is "Rate limited", never "expired" (parity row 25); a 401 or 403 is
    "Rejected" (the cookie expired or was revoked); any other failure is "Failed"."""
    if item.get("ok"):
        return "ok", "OK"
    status = item.get("status")
    if status == 429:
        return "warn", "Rate limited"
    if status in (401, 403):
        return "bad", "Rejected"
    return "bad", "Failed"


def _probe_words(result: Any) -> str:
    if not isinstance(result, Mapping):
        return "No probe yet"
    code = str(result.get("result") or result.get("outcome") or "")
    if code in PROBE_WORDS:
        return PROBE_WORDS[code]
    family, _, status = code.rpartition("_")
    if family == "rejected" and status.isdigit():  # rejected_401, rejected_403: the status Roblox refused it with
        return f"{PROBE_WORDS['rejected']} (Roblox answered {status})"
    if family == "http" and status.isdigit():  # any other answer: no verdict, the state is left as it was
        return f"Unexpected answer: Roblox answered {status}, which says nothing about the credential"
    return code.replace("_", " ") or "n/a"


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
    # Probes take only the reserved sub-bucket (`upstream/buckets.py specs_for`), so the account bucket moves only
    # with caller requests the endpoint policy sends with the account (D1 revised 2026-10-16; finding docs_a-11).
    for name, label in (
        ("account_bucket", "Callers sent with the account (the credential rate limit minus the reserve)"),
        ("probe_bucket", "Reserved for Roxy's credential checks"),
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
            "purpose_words": TRIGGER_WORDS.get(str(item.get("trigger") or ""))
            or PURPOSE_WORDS.get(str(item.get("purpose")), str(item.get("purpose"))),
            "duration": ms_text(item.get("duration_ms")),
            "outcome": _probe_outcome(item),
        }
        for item in answer.get("items") or ()
    ]
    return {"items": items, "last_words": _probe_words(answer.get("last_probe_result"))}


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
