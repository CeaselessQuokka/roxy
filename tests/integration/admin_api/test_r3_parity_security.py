"""Review round 3, parity lens: the fingerprint actions of v1 "Request Fingerprints" (plan 14.1 row 29; row 79).

What this is
    A strict xfail test for v1's per-header "Clear values" and "Remove" buttons on the header-name tables, which have
    no v2 route. v2 keeps "Ignore values" (which also deletes the stored values) and "Record values" (un-ignore), but
    an admin can no longer drop one header's recorded values while it keeps being recorded, nor remove one stray
    header row; the only way left is the whole `fingerprints` family reset.

Why it exists
    `.remake/v1notes/dashboard.md` 4.21: "Clear values" (`POST /admin/fingerprints/clear_header` with `values_only`
    true) dropped one header's values and kept the header and its count; "Remove" (`values_only` false) removed the
    header from the table entirely. The lens checks that every v1 clear survives with its semantics (plan C3, 6.8).

How it works
    Fingerprints are recorded through the real recorder (`record_fingerprint`), flushed, and the route candidates for
    the two actions are tried in turn (a fix may pick any of them); the header tables are then read back. The test is
    `xfail(strict=True)` with its finding id.

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


@pytest.mark.xfail(
    strict=True,
    reason="finding parity-11: v1's per-header fingerprint 'Clear values' and 'Remove' actions have no v2 route",
)
async def test_parity_11_one_headers_values_can_be_cleared_and_the_header_removed(
    api: Any, api_app: Any, api_json: Any
) -> None:
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


@pytest.mark.xfail(
    strict=True,
    reason="finding parity-14: Blocked fingerprints cannot be exported (v1 exportBlockedFingerprints; DESIGN 13)",
)
async def test_parity_14_blocked_fingerprints_export_as_csv(api: Any, api_app: Any) -> None:
    """v1's Blocked Request Fingerprints section had `Export` (`Type,Header,Value,Count,LastSeen`,
    `roxy_blocked_fingerprints_<ms>.csv`); DESIGN 13 says every table route accepts `format=csv|json` and parity row 88
    says every table is exportable. `GET /security/fingerprints/blocked` takes no `format` and no dataset covers it."""
    recorder = api_app.ctx.recorder
    recorder.record_fingerprint([("Xeno-Fingerprint", "4f3a")], "Xeno/1.0", blocked=True)
    api_app.clock.advance(61)
    await recorder.flush()
    response = await api.get("security/fingerprints/blocked", params={"format": "csv"})
    assert response.status_code == 200, response.text
    assert response.headers.get("content-type", "").startswith("text/csv"), response.headers
    assert "xeno-fingerprint" in response.text, response.text
    assert "Xeno/1.0" in response.text, response.text
