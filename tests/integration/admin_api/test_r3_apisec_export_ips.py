"""Review round 3 (lens apisec): client IP addresses in admin API exports while `export_include_ips` is off.

What this is
    Tests for finding apisec-2 (fixed; it was a strict xfail). With `export_include_ips` at its default (0) the
    catalog promises that "every address is replaced by a keyed hash (HMAC)" in export files (plan 9.15, 12.3; the
    setting's own help text). The shared export path hashed only the columns a `TableSpec` marks `ip=True`, while
    client addresses also travel in other columns: the spam detector `subject` (`ip:<client>`), the Overview events
    `detail`, and the audit log's `target`, `before_preview` and `after_preview` (a ban or an access list row holds
    the address). Now every exported cell has its addresses replaced by `ip:<keyed hash>`
    (`common.ExportBuilder`, `common.mask_ip_text`), and `export_include_ips` 1 still exports them raw.

Why it exists
    Export files are designed to be copied off the server (shared with a helper, pasted into an AI assistant); the
    setting is the owner's privacy control for exactly that, and it is a high-risk setting to turn on. A control
    that hashes the IP column of one table but leaves the same address in the next column is not a control.

How it works
    One client address is seeded the way production writes it: a manual ban through the API (its audit row holds
    the subject) and a spam detector dry-run decision (`spam_would_ban`, detail `subject` = `ip:<address>`, as
    `abuse/spam.py` records it). A control check proves the hashing itself works where a column is marked
    (`/protection/bans` hashes `subject`). Then every download that carries those rows is fetched in CSV and JSON
    and searched for the raw address.

What to read next
    `roxy/admin/api/common.py` (`ExportBuilder`, `mask_ip_text`, `export_ip_policy`),
    `roxy/admin/api/protection.py` (`SPAM_EVENTS_SPEC`), `roxy/admin/api/overview.py` (`EVENTS_SPEC`),
    `roxy/admin/api/audit.py` (`AUDIT_TABLE`), `roxy/admin/api/export.py` (`DATASETS`).
"""

from __future__ import annotations

from typing import Any

CLIENT_IP = "198.51.100.77"
"""A documentation address (RFC 5737) standing in for a caller."""


async def _seed(api: Any, api_app: Any, metrics_seed: Any) -> None:
    assert int(api_app.ctx.settings.int("export_include_ips")) == 0  # the default: exports must hash addresses
    created = await api.post(
        "protection/bans",
        json={"subject_type": "ip", "subject": CLIENT_IP, "minutes": 30, "message": "", "reason": "r3 apisec seed"},
    )
    assert created.status_code == 200, created.text
    metrics_seed.event(
        "spam_would_ban",
        "warning",
        "",
        {
            "detector": "SPAM-RATE",
            "subject": f"ip:{CLIENT_IP}",
            "value": 9.0,
            "threshold": 5.0,
            "window_s": 600,
            "action": "ban",
            "configured_action": "ban",
            "game_server": False,
            "evidence": "9 requests a second over 600 s",
        },
    )
    await metrics_seed.flush()


async def test_marked_ip_columns_are_hashed(api: Any, api_app: Any, metrics_seed: Any) -> None:
    """Control (passes today): a column marked `ip=True` is hashed, so the policy itself works."""
    await _seed(api, api_app, metrics_seed)
    for fmt in ("csv", "json"):
        response = await api.get("protection/bans", params={"format": fmt})
        assert response.status_code == 200, response.text
        assert CLIENT_IP not in response.text


async def test_no_export_carries_a_raw_client_address_while_export_include_ips_is_off(
    api: Any, api_app: Any, metrics_seed: Any
) -> None:
    await _seed(api, api_app, metrics_seed)
    downloads = {
        "spam detector decisions": ("protection/spam/events", {"range": "24h"}),
        "overview events": ("overview/events", {"range": "24h"}),
        "audit log table": ("audit", {}),
        "audit log dataset": ("export/audit", {"range": "24h"}),
    }
    leaks: list[str] = []
    for label, (path, params) in downloads.items():
        for fmt in ("csv", "json"):
            response = await api.get(path, params={**params, "format": fmt})
            assert response.status_code == 200, (label, fmt, response.text[:200])
            assert response.headers.get("content-disposition", "").startswith("attachment"), (label, fmt)
            if CLIENT_IP in response.text:
                leaks.append(f"{label} ({fmt})")
    assert leaks == [], f"raw client address {CLIENT_IP} in: {', '.join(leaks)}"
    await api_app.settings(export_include_ips=1)  # the owner's choice: raw addresses in every file
    raw = await api.get("audit", params={"format": "csv"})
    assert raw.status_code == 200
    assert CLIENT_IP in raw.text
