"""Review round 3, parity lens: the fingerprint actions of v1 "Request Fingerprints" (plan 14.1 row 29; row 79).

What this is
    Tests for v1's per-header "Clear values" and "Remove" buttons on the header-name tables (finding parity-11) and
    for the blocked fingerprints export (finding parity-14), both fixed; they were strict xfails. v2 had kept only
    "Ignore values" (which also deletes the stored values) and "Record values" (un-ignore), so an admin could not
    drop one header's recorded values while it keeps being recorded, nor remove one stray header row.

Why it exists
    `.remake/v1notes/dashboard.md` 4.21: "Clear values" (`POST /admin/fingerprints/clear_header` with `values_only`
    true) dropped one header's values and kept the header and its count; "Remove" (`values_only` false) removed the
    header from the table entirely. The lens checks that every v1 clear survives with its semantics (plan C3, 6.8).

How it works
    Fingerprints are recorded through the real recorder (`record_fingerprint`), flushed, and the route candidates for
    the two actions are tried in turn (a fix may pick any of them); the header tables are then read back, and the
    audit rows and 404s of the chosen routes are pinned.

What to read next
    `roxy/admin/api/security.py` (the fingerprint routes), `roxy/metrics/fingerprints.py` (`clear_values`),
    `roxy/metrics/read_security.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.asyncio

Candidate = tuple[str, str, Any]
CLEAR_VALUES: tuple[Candidate, ...] = (
    ("DELETE", "security/fingerprints/headers/x-test/values", None),
    ("POST", "security/fingerprints/headers/x-test/clear-values", {}),
    ("POST", "security/fingerprints/headers/x-test/clear", {"values_only": True}),
)
REMOVE_HEADER: tuple[Candidate, ...] = (
    ("DELETE", "security/fingerprints/headers/x-test", None),
    ("POST", "security/fingerprints/headers/x-test/clear", {"values_only": False}),
    ("POST", "security/fingerprints/headers/x-test/remove", {}),
)


async def _first_ok(api: Any, candidates: tuple[tuple[str, str, Any], ...]) -> list[tuple[str, int]]:
    tried = []
    for method, path, body in candidates:
        kwargs = {} if body is None else {"json": body}
        response = await api.request(method, path, **kwargs)
        tried.append((f"{method} {path}", response.status_code))
        if 200 <= response.status_code < 300:
            return []
    return tried


async def test_parity_11_one_headers_values_can_be_cleared_and_the_header_removed(
    api: Any, api_app: Any, api_json: Any
) -> None:
    """Finding parity-11 (fixed): `DELETE .../headers/{name}/values` and `DELETE .../headers/{name}`."""
    recorder = api_app.ctx.recorder
    recorder.record_fingerprint([("X-Test", "one"), ("Accept", "*/*")], "Roblox/WinInet")
    recorder.record_fingerprint([("X-Test", "two"), ("Accept", "*/*")], "Roblox/WinInet")
    api_app.clock.advance(61)  # aggregated rows are written once their minute closes
    await recorder.flush()
    rows = {row["name"]: row for row in api_json(await api.get("security/fingerprints/headers"))["items"]}
    assert rows["x-test"]["value_count"] == 2
    failures = await _first_ok(api, CLEAR_VALUES)
    assert not failures, failures
    rows = {row["name"]: row for row in api_json(await api.get("security/fingerprints/headers"))["items"]}
    kept = rows.get("x-test", {})
    assert (kept.get("count"), kept.get("value_count"), kept.get("values_ignored")) == (2, 0, False), kept
    failures = await _first_ok(api, REMOVE_HEADER)
    assert not failures, failures
    rows = {row["name"]: row for row in api_json(await api.get("security/fingerprints/headers"))["items"]}
    assert "x-test" not in rows, sorted(rows)
    assert "accept" in rows, sorted(rows)


async def test_parity_11_clears_are_audited_first_and_unknown_headers_are_404(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    """Each clear writes its audit row (with the counts) before it deletes; a header never recorded is 404 and a
    clear needs the CSRF token like every change. The Blocked tab's "Remove" drops one blocked header name."""
    recorder = api_app.ctx.recorder
    recorder.record_fingerprint([("X-Test", "one")], "Roblox/WinInet")
    recorder.record_fingerprint([("Xeno-Fingerprint", "4f3a"), ("X-Other", "1")], "Xeno/1.0", blocked=True)
    api_app.clock.advance(61)
    await recorder.flush()
    section13(await api.delete("security/fingerprints/headers/never-seen/values"), 404, "not_found")
    section13(await api.delete("security/fingerprints/headers/never-seen"), 404, "not_found")
    cleared = api_json(await api.delete("security/fingerprints/headers/X-Test/values", params={"reason": "noise"}))
    assert (cleared["name"], cleared["values_removed"], cleared["header_kept"]) == ("x-test", 1, True)

    def audit_rows(conn: Any) -> list[tuple[str, str, str | None]]:
        rows = conn.execute(
            "SELECT action, target, reason FROM audit_log WHERE action LIKE 'fingerprints.%' ORDER BY id"
        ).fetchall()
        return [(str(r[0]), str(r[1]), r[2]) for r in rows]

    assert await api_app.ctx.dbs.control.read(audit_rows) == [
        ("fingerprints.clear_values", "fingerprint_header:x-test", "noise")
    ]
    removed = api_json(await api.delete("security/fingerprints/blocked/headers/xeno-fingerprint"))
    assert (removed["name"], removed["requests_removed"]) == ("xeno-fingerprint", 1)
    blocked = api_json(await api.get("security/fingerprints/blocked", params={"kind": "header"}))
    assert [item["name"] for item in blocked["items"]] == ["x-other"]
    section13(await api.delete("security/fingerprints/blocked/headers/xeno-fingerprint"), 404, "not_found")


async def test_parity_14_blocked_fingerprints_export_as_csv(api: Any, api_app: Any, api_json: Any) -> None:
    """v1's Blocked Request Fingerprints section had `Export` (`Type,Header,Value,Count,LastSeen`,
    `roxy_blocked_fingerprints_<ms>.csv`); DESIGN 13 says every table route accepts `format=csv|json` and parity row 88
    says every table is exportable. Finding parity-14 (fixed): `GET /security/fingerprints/blocked` is a section 13
    table (headers and User-Agents, `kind` picks one) that exports as CSV or JSON."""
    recorder = api_app.ctx.recorder
    recorder.record_fingerprint([("Xeno-Fingerprint", "4f3a")], "Xeno/1.0", blocked=True)
    api_app.clock.advance(61)
    await recorder.flush()
    response = await api.get("security/fingerprints/blocked", params={"format": "csv"})
    assert response.status_code == 200, response.text
    assert response.headers.get("content-type", "").startswith("text/csv"), response.headers
    assert "xeno-fingerprint" in response.text, response.text
    assert "Xeno/1.0" in response.text, response.text
    assert "roxy_blocked_fingerprints_" in response.headers["content-disposition"]
    table = api_json(await api.get("security/fingerprints/blocked"))
    assert {"items", "total", "page", "columns"} <= set(table)
    assert sorted((item["kind"], item["count"]) for item in table["items"]) == [("header", 1), ("user_agent", 1)]
    agents = api_json(await api.get("security/fingerprints/blocked", params={"kind": "user_agent"}))
    assert [item["user_agent"] for item in agents["items"]] == ["Xeno/1.0"]
    assert set(table["caller_text"]) == {"name", "user_agent"}
