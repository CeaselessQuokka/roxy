"""The Credential page API and the credential allowlist, in the real app (plan C1, C2, D1, 6.9, 9.13, 13.3, parity rows
25 to 27).

Roblox's `users/authenticated` probe is played by `respx` and answers a different account id for each cookie, so the
account fingerprint comparison of plan C1 is real. Every test that handles a credential value also checks that
neither the value nor any 24 character window of its secret part appears in an answer, an audit row or a log record.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any

import httpx
import pytest

from roxy.admin.api.credential import ACCOUNT_SWITCH_CONFIRMATION, REPLACE_CONFIRMATION
from roxy.core.redact import TOKEN_PREFIX

PROBE_URL = "https://users.roblox.com/v1/users/authenticated"
WINDOW = 24


def _secret_part(value: str) -> str:
    return value[len(TOKEN_PREFIX) :] if value.startswith(TOKEN_PREFIX) else value


def _leaks(blob: str, value: str) -> list[str]:
    """Where `value` shows in `blob`: whole, or any 24 character window of its secret part (case ignored)."""
    folded = blob.lower()
    secret = _secret_part(value).lower()
    found = ["whole value"] if value.lower() in folded else []
    for start in range(len(secret) - WINDOW + 1):
        if secret[start : start + WINDOW] in folded:
            found.append(f"window at {start}")
            break
    return found


def _audit(api_app: Any, action: str | None = None) -> list[dict[str, Any]]:
    def read(conn: Any) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_log" + (" WHERE action = ?" if action else "") + " ORDER BY id"
        return [dict(row) for row in conn.execute(sql, (action,) if action else ()).fetchall()]

    rows: list[dict[str, Any]] = api_app.ctx.dbs.control.read_sync(read)
    return rows


def _accounts(api_app: Any, by_cookie: dict[str, int]) -> Any:
    """Roblox's `users/authenticated`: the account id of whichever known cookie the request carries."""

    def answer(request: httpx.Request) -> httpx.Response:
        cookie = request.headers.get("cookie", "")
        for value, account in by_cookie.items():
            if cookie == f".ROBLOSECURITY={value}":
                return httpx.Response(200, json={"id": account, "name": f"user{account}"})
        return httpx.Response(401, json={"errors": [{"message": "Authorization has been denied"}]})

    return api_app.roblox.get(PROBE_URL).mock(side_effect=answer)


def _no_leaks(api: Any, api_app: Any, caplog: pytest.LogCaptureFixture, values: dict[str, str]) -> None:
    assert caplog.records, "the log check would be vacuous"
    answers = " ".join(response.text + json.dumps(dict(response.headers)) for response in api.sent)
    rows = json.dumps(_audit(api_app))
    logs = " ".join(f"{record.getMessage()} {record.__dict__!r}" for record in caplog.records)
    found = {
        (where, name, hit)
        for name, value in values.items()
        for where, blob in (("answers", answers), ("audit", rows), ("logs", logs))
        for hit in _leaks(blob, value)
    }
    assert found == set()


def test_leak_scan_finds_every_window_and_ignores_public_text() -> None:
    value = TOKEN_PREFIX + secrets.token_hex(64).upper()
    part = _secret_part(value)
    for start in (0, 7, 13, len(part) - WINDOW):
        assert _leaks("x " + part[start : start + WINDOW].lower() + " y", value), start
    assert _leaks(part[: WINDOW - 1], value) == []
    assert _leaks(TOKEN_PREFIX, value) == []


# ================================================================================================= guards


@pytest.mark.parametrize(
    "path", ["credential", "credential/probes", "credential/budget", "credential-allowlist", "credential-allowlist/1"]
)
async def test_every_credential_read_needs_a_session(anon_api: Any, path: str) -> None:
    response = await anon_api.get(path)
    assert response.status_code == 401, (path, response.text)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "credential/check"),
        ("POST", "credential/replace"),
        ("DELETE", "credential/ui-value"),
        ("POST", "credential/confirm-account"),
        ("POST", "credential-allowlist"),
        ("PATCH", "credential-allowlist/1"),
        ("DELETE", "credential-allowlist/1"),
    ],
)
async def test_every_credential_write_needs_the_csrf_header(api: Any, method: str, path: str) -> None:
    response = await api.request(method, path, json={"reason": "x"}, csrf=False)
    assert response.status_code == 403, (method, path, response.text)


# ======================================================================================== status and probes


async def test_status_check_probes_and_budget(
    api_app: Any,
    api: Any,
    api_json: Any,
    metrics_seed: Any,
    fake_secrets: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    bootstrap = fake_secrets["roblox_credential"]
    _accounts(api_app, {bootstrap: 1})
    before = api_json(await api.get("credential"))
    assert before["status"] == "unknown"  # never probed yet: probes only
    assert before["source"] == "bootstrap"
    assert before["masked"] == "…" + bootstrap[-6:]  # v1's label: an ellipsis and the last 6 (row 27)
    assert before["account"]["match"] is None
    assert before["texts"]["replace_confirmation"] == REPLACE_CONFIRMATION
    assert "account farming" in before["texts"]["c1_warning"]
    assert before["cooldown"] is None

    checked = api_json(await api.post("credential/check"))
    assert checked["pending"] is False
    assert (checked["probe"]["outcome"], checked["probe"]["ok"], checked["probe"]["status_code"]) == ("ok", True, 200)
    assert checked["status"]["status"] == "active"
    assert checked["status"]["account"]["match"] is True
    await metrics_seed.flush()
    probes = api_json(await api.get("credential/probes"))
    assert probes["items"][0]["purpose"] == "credential_probe"
    assert probes["items"][0]["ok"] is True
    assert probes["last_probe_result"]["result"] == "ok"
    budget = api_json(await api.get("credential/budget"))
    assert budget["probe_bucket"]["key"] == "egress:credential:probe"
    assert budget["probe_bucket"]["per_min"] == api_app.ctx.settings.get("credential_probe_reserved_per_min")
    assert budget["last_hour"]["probe_calls"] == 1
    assert budget["last_hour"]["caller_calls"] == 0  # D1: the allowlist is empty
    assert "50 to 60" in budget["expected"]
    _no_leaks(api, api_app, caplog, {"bootstrap": bootstrap})


async def test_a_probe_429_is_rate_limited_never_expired(api_app: Any, api: Any, api_json: Any, section13: Any) -> None:
    route = api_app.roblox.get(PROBE_URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "120"}))
    api.make_mfa_stale()
    section13(await api.post("credential/check"), 403, "reauth_required")  # a probe spends a call on the account
    assert route.call_count == 0
    await api.fresh_mfa()
    checked = api_json(await api.post("credential/check"))
    assert checked["probe"]["outcome"] == "rate_limited"
    assert checked["status"]["status"] == "cooling_down"
    state = api_json(await api.get("credential"))
    assert state["cooldown"]["remaining_s"] == 120.0
    assert state["cooldown"]["source"] in ("retry_after", "default")
    busy = api_json(await api.post("credential/check"))
    assert busy["probe"]["outcome"] == "cooling_down"  # no probe inside Roblox's Retry-After


# ================================================================================================ replace


async def test_replace_and_return_to_the_bootstrap_account_with_typed_confirmations(
    api_app: Any,
    api: Any,
    api_json: Any,
    section13: Any,
    fake_secrets: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    bootstrap = fake_secrets["roblox_credential"]
    new_value = "NEWBAREVALUE" + secrets.token_hex(96).upper()  # copied without the public warning
    _accounts(api_app, {bootstrap: 2, new_value: 1})
    assert api_json(await api.post("credential/check"))["status"]["status"] == "active"
    confirm = REPLACE_CONFIRMATION

    api.make_mfa_stale()
    stale = await api.post("credential/replace", json={"value": new_value, "confirm": confirm})
    section13(stale, 403, "reauth_required")
    await api.fresh_mfa()
    wrong = await api.post("credential/replace", json={"value": new_value, "confirm": "yes"})
    assert section13(wrong, 422, "confirmation_required") == {"confirm": f"Type: {confirm}"}
    assert "account farming" in wrong.json()["error"]["message"]
    short = await api.post("credential/replace", json={"value": "tooshort", "confirm": confirm})
    section13(short, 422, "invalid_credential")
    listed = await api.post("credential/replace", json={"value": [new_value], "confirm": confirm})
    section13(listed, 422, "validation_failed")  # one value, never a list (C1)
    extra = await api.post("credential/replace", json={"value": new_value, "confirm": confirm, "values": [1]})
    section13(extra, 422, "validation_failed")

    replaced = api_json(
        await api.post(
            "credential/replace",
            json={"value": new_value, "confirm": "  Replace THE credential ", "reason": f"x {new_value}"},
        )
    )
    assert replaced["replaced"] is True
    assert replaced["probe"]["outcome"] == "ok"
    status = replaced["status"]
    assert (status["source"], status["status"], status["ui_value_present"]) == ("ui", "active", True)
    assert status["masked"] == "…" + new_value[-6:]
    assert status["bootstrap_superseded"] is True
    (audit_row,) = _audit(api_app, "credential.replace")
    assert json.loads(audit_row["after_json"])["masked"] == "…" + new_value[-6:]
    assert set(json.loads(audit_row["after_json"])) == {"fingerprint", "masked"}

    # Back to the bootstrap file: it holds another account's cookie, so it is not used until confirmed (C1).
    api.make_mfa_stale()
    section13(await api.delete("credential/ui-value"), 403, "reauth_required")
    await api.fresh_mfa()
    previous = status["account_id_fingerprint"]
    deleted = api_json(await api.delete("credential/ui-value", json={"reason": "renewed the file"}))
    assert deleted["deleted"] is True
    assert deleted["account"]["previous"] == previous
    assert deleted["account"]["match"] is False
    assert deleted["account"]["confirmation_required"] is True
    assert deleted["account"]["probed"] not in (None, previous)
    assert deleted["status"]["status"] == "rejected"
    assert deleted["status"]["source"] == "bootstrap"
    assert deleted["texts"]["account_switch_confirmation"] == ACCOUNT_SWITCH_CONFIRMATION
    section13(await api.delete("credential/ui-value"), 409, "wrong_state")

    no = await api.post("credential/confirm-account", json={"confirm": "ok"})
    section13(no, 422, "confirmation_required")
    confirmed = api_json(
        await api.post("credential/confirm-account", json={"confirm": ACCOUNT_SWITCH_CONFIRMATION, "reason": "mine"})
    )
    assert confirmed["status"]["status"] == "active"
    assert confirmed["status"]["account_id_fingerprint"] == deleted["account"]["probed"]
    (deleted_row,) = _audit(api_app, "credential.delete_ui_value")
    assert deleted_row["reason"] == "renewed the file"
    (confirm_row,) = _audit(api_app, "credential.confirm_account")
    assert json.loads(confirm_row["after_json"]) == {"account_id_fingerprint": deleted["account"]["probed"]}
    _no_leaks(api, api_app, caplog, {"bootstrap": bootstrap, "new value": new_value})


# ================================================================================================ allowlist


async def test_allowlist_requires_the_cache_private_choice_and_grants_exactly(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    base = {"pattern": "economy.roblox.com/v1/user/currency", "reason": "currency for the shop"}
    fields = section13(await api.post("credential-allowlist", json=base), 422, "validation_failed")
    assert "cache_private" in fields  # required, no default (plan 9.13)
    section13(await api.post("credential-allowlist", json=base | {"cache_private": "yes"}), 422, "validation_failed")
    section13(
        await api.post("credential-allowlist", json=base | {"cache_private": True, "methods": ["POST"]}),
        422,
        "validation_failed",
    )
    section13(
        await api.post("credential-allowlist", json=base | {"cache_private": True, "reason": ""}),
        422,
        "validation_failed",
    )
    evidence = await api.post("credential-allowlist", json=base | {"cache_private": True, "identical_anonymous": True})
    section13(evidence, 422, "evidence_required")
    api.make_mfa_stale()
    section13(await api.post("credential-allowlist", json=base | {"cache_private": True}), 403, "reauth_required")
    await api.fresh_mfa()

    created = await api.post("credential-allowlist", json=base | {"cache_private": True, "methods": ["HEAD", "GET"]})
    assert created.status_code == 201, created.text
    row = created.json()["item"]
    assert (row["pattern"], row["methods"], row["cache_private"], row["identical_anonymous"]) == (
        base["pattern"],
        ["GET", "HEAD"],
        True,
        False,
    )
    assert "Owner decision D1" in created.json()["help"]["d1"]
    section13(await api.post("credential-allowlist", json=base | {"cache_private": False}), 409, "conflict")

    granted = api_json(await api.get("credential-allowlist/test", params={"target": base["pattern"]}))
    assert (granted["granted"], granted["cache_private"], granted["rule"]["id"]) == (True, True, row["id"])
    below = api_json(await api.get("credential-allowlist/test", params={"target": base["pattern"] + "/more"}))
    assert below["granted"] is False  # exact grants: no implicit subpaths (CHANGES.md, finding F3)
    post = api_json(await api.get("credential-allowlist/test", params={"target": base["pattern"], "method": "POST"}))
    assert post["granted"] is False

    listed = api_json(await api.get("credential-allowlist"))
    assert listed["total"] == 1
    assert "never stored" in listed["help"]["cache_private"]
    (audit_row,) = _audit(api_app, "rule.create")
    assert audit_row["target"] == f"credential_allowlist:{row['id']}"
    assert audit_row["reason"] == "currency for the shop"


async def test_identical_anonymous_needs_cred_unused_evidence(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    pattern = "economy.roblox.com/v1/user/currency"
    created = await api.post(
        "credential-allowlist", json={"pattern": pattern, "cache_private": False, "reason": "shop"}
    )
    row_id = created.json()["item"]["id"]
    path = f"credential-allowlist/{row_id}"
    section13(await api.patch(path, json={"identical_anonymous": True, "reason": "same"}), 422, "evidence_required")
    unknown = await api.patch(path, json={"identical_anonymous": True, "recommendation_id": "rec_NONE", "reason": "x"})
    section13(unknown, 422, "evidence_required")
    section13(
        await api.patch(path, json={"note": "n", "recommendation_id": "rec_X", "reason": "x"}), 422, "validation_failed"
    )
    section13(await api.patch(path, json={"note": "n"}), 422, "validation_failed")  # the reason is required

    now = int(time.time())
    payload = {
        "rule_id": "CRED-UNUSED",
        "changes": [{"kind": "credential_allowlist_remove", "table": "credential_allowlist", "match": {"id": row_id}}],
        "evidence": {"sample_size": 25, "metrics": [{"name": "identical_pct", "value": 100, "unit": "percent"}]},
    }
    for rec_id, state in (("rec_DISMISSED", "dismissed"), ("rec_OPEN", "open")):
        await api_app.ctx.dbs.metrics.write(
            lambda conn, rec_id=rec_id, state=state: conn.execute(
                "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at, "
                "updated_at) VALUES (?, 'CRED-UNUSED', 'fp', ?, 'warn', ?, ?, ?)",
                (rec_id, state, json.dumps(payload), now, now),
            )
        )
    dismissed = await api.patch(
        path, json={"identical_anonymous": True, "recommendation_id": "rec_DISMISSED", "reason": "same"}
    )
    section13(dismissed, 422, "evidence_required")
    patched = api_json(
        await api.patch(
            path, json={"identical_anonymous": True, "recommendation_id": "rec_OPEN", "reason": "same body"}
        )
    )
    assert patched["item"]["identical_anonymous"] is True
    (update,) = _audit(api_app, "rule.update")
    assert update["reason"] == "same body [CRED-UNUSED evidence rec_OPEN, 25 samples]"
    cleared = api_json(await api.patch(path, json={"identical_anonymous": False, "reason": "not any more"}))
    assert cleared["item"]["identical_anonymous"] is False

    # Removing a row narrows what the account is used for: the session is enough, even with a stale factor.
    api.make_mfa_stale()
    deleted = api_json(await api.delete(path, json={"reason": "not needed"}))
    assert deleted["deleted"]["id"] == row_id
    section13(await api.get(path), 404, "not_found")
    assert api_app.ctx.rules.snapshot.credential_rule_for(pattern, "GET") is None
