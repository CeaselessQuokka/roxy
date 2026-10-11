"""The User-Agent drill-down (gap G1) and the address headers that are never recorded (gap G5), through the API.

What this is
    Integration tests in the real app (`api_app`): fingerprints recorded through the real recorder, flushed to
    metrics.db, read through `GET /admin/api/v1/security/fingerprints/user-agents/{ua_hash}` (v1
    `GET /admin/fingerprints/user_agent`, `.remake/v1notes/dashboard.md` 4.21) and the User-Agent table and its
    export; the shipped ignored address headers, their refusal to be recorded again, and the leader job that clears
    what a previous release stored.

Why it exists
    The drill-down shows a client address like the Endpoints page's last caller, so exports must hash it unless the
    owner allows addresses (plan 9.15); the path and header names are caller text (DESIGN 13.1 `caller_text`); and a
    header that carries client addresses must never have a value kept, whatever an admin does with the ignore list.

What to read next
    `roxy/admin/api/security.py` (`user_agent_detail_answer`, `ignored_rows`, `fingerprint_unignore`),
    `roxy/metrics/read_security.py` (`user_agent_detail`), `roxy/metrics/fingerprints.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.metrics import fingerprints as fp

pytestmark = pytest.mark.asyncio

CLIENT_IP = "198.51.100.41"
"""A documentation address (RFC 5737) standing in for a caller."""
UA = "Roblox/WinInet <b>hostile</b>"


def ok(response: Any, api_json: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return api_json(response)


async def _record(api_app: Any) -> None:
    recorder = api_app.ctx.recorder
    names = ["Host", "User-Agent", "X-Forwarded-For", "Roblox-Id"]
    pairs = [("Host", "games.roblox.com"), ("User-Agent", UA), ("X-Forwarded-For", CLIENT_IP), ("Roblox-Id", "1")]
    recorder.record_fingerprint(pairs, UA, path="games.roblox.com/v1/games", client_ip=CLIENT_IP, header_names=names)
    await recorder.flush()


async def test_the_user_agent_drill_down_answers_v1s_question(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    await _record(api_app)
    table = ok(await api.get("security/fingerprints/user-agents", params={"q": "roblox/wininet"}), api_json)
    row = table["items"][0]
    assert row["ua_hash"] == fp.row_hash(UA)
    assert {"last_path", "last_caller", "last_header_names", "last_detail_at"} <= {c["key"] for c in table["columns"]}
    assert {"user_agent", "last_path", "last_header_names"} <= set(table["caller_text"])
    detail = ok(await api.get(f"security/fingerprints/user-agents/{row['ua_hash']}"), api_json)
    assert detail["user_agent"] == UA
    assert detail["has_detail"] is True
    assert detail["last_path"] == "games.roblox.com/v1/games"
    assert detail["last_caller"] == CLIENT_IP  # shown as the Endpoints page's last caller is
    assert detail["last_header_names"] == ["host", "user-agent", "x-forwarded-for", "roblox-id"]
    assert set(detail["caller_text"]) == {"user_agent", "last_path", "last_header_names"}
    assert CLIENT_IP not in str(detail["last_header_names"])  # names only, never a value
    section13(await api.get(f"security/fingerprints/user-agents/{'0' * 32}"), 404, "not_found")
    bad = await api.get("security/fingerprints/user-agents/not-a-key")
    assert bad.status_code == 422


async def test_the_user_agent_export_hashes_the_last_caller(api: Any, api_app: Any) -> None:
    await _record(api_app)
    assert int(api_app.ctx.settings.int("export_include_ips")) == 0
    for fmt in ("csv", "json"):
        response = await api.get("security/fingerprints/user-agents", params={"format": fmt})
        assert response.status_code == 200, response.text
        assert CLIENT_IP not in response.text
        assert "games.roblox.com/v1/games" in response.text
    await api_app.settings(export_include_ips=1)  # the owner's choice: raw addresses in the file
    raw = await api.get("security/fingerprints/user-agents", params={"format": "csv"})
    assert CLIENT_IP in raw.text


async def test_address_headers_are_listed_as_never_recorded_and_cannot_be_recorded_again(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    await _record(api_app)
    ignored = ok(await api.get("security/fingerprints/ignored", params={"page_size": 100}), api_json)
    rows = {item["name"]: item for item in ignored["items"]}
    for name in fp.ADDRESS_HEADERS:
        assert rows[name]["why"] == "Default", name
        assert rows[name]["never_recorded"] is True, name
    assert rows["traceparent"]["never_recorded"] is False
    refused = section13(await api.delete("security/fingerprints/ignored/X-Forwarded-For"), 422, "validation_failed")
    assert "client addresses" in refused["name"]
    headers = ok(await api.get("security/fingerprints/headers", params={"q": "x-forwarded-for"}), api_json)
    assert headers["items"][0]["count"] == 1  # the name is counted
    assert headers["items"][0]["values_ignored"] is True
    values = ok(await api.get("security/fingerprints/headers/x-forwarded-for/values"), api_json)
    assert values["total"] == 0  # its value is never kept


async def test_the_leader_job_clears_address_values_an_older_release_stored(api_app: Any) -> None:
    """A previous release kept address values hashed; the fingerprint job deletes them (and only them)."""

    def old_rows(conn: Any) -> None:
        for name in ("x-real-ip", "x-thing"):
            conn.execute(
                "INSERT INTO fingerprint_values (value_hash, name, value, count, first_seen, last_seen) "
                "VALUES (?, ?, 'fp:0123456789ab', 1, 1, 1)",
                (fp.row_hash(name, "fp:0123456789ab"), name),
            )

    await api_app.ctx.dbs.metrics.write(old_rows)
    status = await api_app.ctx.jobs.run_job_now("fingerprint_auto_ignore")
    assert status.last_ok, status.last_error
    left = await api_app.ctx.dbs.metrics.read(
        lambda conn: sorted(r[0] for r in conn.execute("SELECT name FROM fingerprint_values"))
    )
    assert left == ["x-thing"]
