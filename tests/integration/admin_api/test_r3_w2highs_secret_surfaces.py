"""Wave 2 credential fixes through the wave 3b surfaces (review round 3, lens w2highs): cred-2 on the admin API.

What this is
    Variants of finding cred-2 ("the audit reason is redacted only against registered secrets, so a value must be
    registered before its audit row") through the entry points wave 3b added: `POST /credential/replace`,
    `PUT /rotator/url` and `DELETE /rotator/url`, and the surfaces that later show what was stored: the audit API
    and its export, the credential answers, the `events` rows the SSE stream reads, a health run of the credential
    checks with its three exports, and the full LLM export.

Why it exists
    The fix tests call `CredentialManager.replace` directly with a bare value. An admin uses the dashboard: the
    paste may be percent-encoded, carry the cookie pair, be lowercased in the reason, or be repeated %XX encoded,
    and a rotator URL embeds its password percent-encoded. The registry keeps three values per name and registers
    the bootstrap rotator URL only at start (`RotatorPool.start`), so after three UI replaces the bootstrap value is
    evicted, and `revert_to_bootstrap` (the Egress page's "use the bootstrap file again") does not register it again:
    the reason of that revert, and every later redaction, no longer know the gateway password in use.

How it works
    The shared admin API fixtures (`conftest.py` here): the real app, a signed-in admin (the login gives a fresh
    second factor), respx playing Roblox's `users/authenticated` with an account per cookie. Each test collects every
    answer, the raw `audit_log` and `events` tables and the log records, and scans them for the whole value and every
    24 character window of the credential's secret part (ASCII case ignored, also after percent-decoding).

What to read next
    `src/roxy/admin/api/credential.py`, `src/roxy/admin/api/rotator.py`, `src/roxy/egress/rotator.py`
    (`replace_url`, `revert_to_bootstrap`, `_apply_store`), `tests/security/test_r3_w2highs_cred_variants.py`.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any
from urllib.parse import quote, unquote_to_bytes

import httpx
import pytest

from roxy.admin.api.credential import REPLACE_CONFIRMATION
from roxy.core.redact import TOKEN_PREFIX, redact_text
from roxy.health.runner import runner_for

PROBE_URL = "https://users.roblox.com/v1/users/authenticated"
WINDOW = 24
CREDENTIAL_CHECKS = ["H-CRED-PRESENT", "H-CRED-AUTH", "H-CRED-COOLDOWN", "H-CRED-GUARD", "H-ENV-PROXY"]


def _variants(text: str) -> list[str]:
    out = [text]
    for _ in range(2):
        if "%" not in out[-1]:
            break
        out.append(unquote_to_bytes(out[-1]).decode("utf-8", "replace"))
    return out


def _leaks(blob: str, value: str, *, secret: str | None = None) -> list[str]:
    """Where `value` shows in `blob`: whole, or any 24 character window of `secret` (default: the value without the
    public warning), ASCII case ignored, as stored and after up to two rounds of percent-decoding."""
    part = (secret if secret is not None else value.removeprefix(TOKEN_PREFIX)).lower()
    found: list[str] = []
    for variant in _variants(blob):
        folded = variant.lower()
        if value.lower() in folded:
            found.append("whole value")
        for start in range(len(part) - WINDOW + 1):
            if part[start : start + WINDOW] in folded:
                found.append(f"window at {start}")
                break
    return found


def _accounts(api_app: Any, by_cookie: dict[str, int]) -> Any:
    def answer(request: httpx.Request) -> httpx.Response:
        cookie = request.headers.get("cookie", "")
        for value, account in by_cookie.items():
            if cookie == f".ROBLOSECURITY={value}":
                return httpx.Response(200, json={"id": account, "name": f"user{account}"})
        return httpx.Response(401, json={"errors": [{"message": "Authorization has been denied"}]})

    return api_app.roblox.get(PROBE_URL).mock(side_effect=answer)


def _table(api_app: Any, db: str, sql: str) -> str:
    rows = getattr(api_app.ctx.dbs, db).read_sync(lambda conn: [dict(row) for row in conn.execute(sql).fetchall()])
    return json.dumps(rows, default=str)


def _logs(caplog: pytest.LogCaptureFixture) -> str:
    return " ".join(f"{record.getMessage()} {record.__dict__!r}" for record in caplog.records)


def _encode_uri_component(value: str) -> str:
    return quote(value, safe="-_.!~*'()")


async def test_cred2_api_replace_paste_spellings_never_reach_a_record_or_an_export(
    api_app: Any, api: Any, api_json: Any, fake_secrets: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    """cred-2 variant (holds): the dashboard replace with an encoded paste, and a reason that repeats the value in
    four spellings; then every surface that shows stored text is scanned."""
    caplog.set_level(logging.DEBUG)
    bootstrap = fake_secrets["roblox_credential"]
    secret = "APIPASTE" + secrets.token_hex(80).upper()
    new_value = TOKEN_PREFIX + secret
    _accounts(api_app, {bootstrap: 7, new_value: 7})
    pasted = _encode_uri_component(new_value)
    reason = (
        f"pasted {pasted} | pair .ROBLOSECURITY={new_value} | lower {secret.lower()} | "
        + "escaped "
        + "".join(f"%{ord(ch):02X}" for ch in secret[:40])
    )
    replaced = await api.post(
        "credential/replace", json={"value": pasted, "confirm": REPLACE_CONFIRMATION, "reason": reason}
    )
    assert replaced.status_code == 200, replaced.text
    assert api_json(replaced)["status"]["source"] == "ui"
    run = api_json(await api.post("health/runs", json={"checks": CREDENTIAL_CHECKS, "include_credential": True}))
    await runner_for(api_app.ctx).wait(run["run_id"])
    surfaces = [response.text for response in api.sent]
    for path, params in (
        ("audit", {"page_size": 250}),
        ("audit", {"format": "csv"}),
        ("audit", {"format": "json"}),
        ("credential", None),
        ("credential/probes", None),
        (f"health/runs/{run['run_id']}", None),
        (f"health/runs/{run['run_id']}/export", {"format": "json"}),
        (f"health/runs/{run['run_id']}/export", {"format": "html"}),
        (f"health/runs/{run['run_id']}/export", {"format": "llm"}),
        ("export/llm", {"detail": "full", "window": "24h"}),
        ("export/llm", {"detail": "summary", "window": "24h", "format": "text"}),
    ):
        response = await api.get(path, params=params)
        assert response.status_code == 200, (path, response.text[:300])
        surfaces.append(response.text)
    await api_app.ctx.recorder.flush()
    surfaces.append(_table(api_app, "control", "SELECT * FROM audit_log"))
    surfaces.append(_table(api_app, "metrics", "SELECT * FROM events"))
    surfaces.append(_logs(caplog))
    blob = "\n".join(surfaces)
    assert "credential.replace" in blob  # not vacuous: the audit row is among the surfaces
    found = {name: _leaks(blob, value) for name, value in (("new value", new_value), ("bootstrap", bootstrap))}
    assert found == {"new value": [], "bootstrap": []}


async def test_cred2_api_rotator_url_password_spellings_never_reach_a_record(
    api_app: Any, api: Any, api_json: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """cred-2 variant (holds): a gateway URL whose password needs percent-encoding, and a reason that repeats the
    password raw, encoded and as the whole URL."""
    caplog.set_level(logging.DEBUG)
    password = "p@ss/" + secrets.token_hex(10) + "+x"
    url = f"http://gwuser:{quote(password, safe='')}@127.0.0.1:9"
    reason = f"new gateway {url} | raw {password} | encoded {quote(password, safe='')}"
    replaced = await api.put("rotator/url", json={"url": url, "reason": reason})
    assert replaced.status_code == 200, replaced.text
    assert api_json(replaced)["url"] == "http://127.0.0.1:9"
    for path, params in (("audit", {"page_size": 250}), ("audit", {"format": "csv"}), ("rotator", None)):
        assert (await api.get(path, params=params)).status_code == 200
    blob = "\n".join(
        [response.text for response in api.sent]
        + [_table(api_app, "control", "SELECT * FROM audit_log"), _logs(caplog)]
    )
    assert "rotator.replace_url" in blob
    assert [variant for variant in _variants(blob) if password in variant] == []


@pytest.mark.xfail(
    strict=True,
    reason="finding W2H-1: after three rotator URL replaces the bootstrap URL is evicted from SecretRegistry and "
    "revert_to_bootstrap does not register it again, so its gateway password is stored in clear",
)
async def test_cred2_reverting_to_the_bootstrap_gateway_keeps_its_password_redacted(
    api_app: Any, api: Any, api_json: Any, fake_secrets: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    """Three gateway URLs are tried from the Egress page, then the bootstrap file is used again with a reason that
    repeats its password (a paste into the wrong box). The password in use must stay redacted everywhere."""
    caplog.set_level(logging.DEBUG)
    bootstrap_url = fake_secrets["rotator_url"]
    bootstrap_password = bootstrap_url.split("://", 1)[1].rsplit("@", 1)[0].split(":", 1)[1]
    assert redact_text(f"x {bootstrap_password} y") == "x [redacted] y"  # control: known while the worker is fresh
    for attempt in range(3):
        url = f"http://try{attempt}:fake{secrets.token_hex(10)}@127.0.0.1:9"
        response = await api.put("rotator/url", json={"url": url, "reason": f"attempt {attempt}"})
        assert response.status_code == 200, response.text
    reason = f"back to the file gateway, password {bootstrap_password}"
    reverted = await api.delete("rotator/url", json={"reason": reason})
    assert reverted.status_code == 200, reverted.text
    assert api_json(reverted)["source"] == "bootstrap"
    audit_answer = await api.get("audit", params={"page_size": 250})
    assert audit_answer.status_code == 200
    blob = "\n".join([audit_answer.text, _table(api_app, "control", "SELECT * FROM audit_log"), _logs(caplog)])
    assert "rotator.revert_to_bootstrap" in blob
    found = ["password in a stored or shown text" for variant in _variants(blob) if bootstrap_password in variant]
    still_known = redact_text(f"x {bootstrap_password} y") == "x [redacted] y"
    assert {"found": found, "redaction knows it": still_known} == {"found": [], "redaction knows it": True}
