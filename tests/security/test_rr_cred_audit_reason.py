"""The new credential can land in its own audit row: `replace` redacts the reason before it knows the value
(review lens cred, finding cred-2).

What this is
    A probe for plan 19.5 item 11 (`test_secret_replace_leaves_no_trace`, 6.2 `audit_log`), 9.8 and DESIGN.md 5
    ("secret targets pass `{fingerprint, masked}` only"). The admin replaces the credential and the free-text reason
    holds the new value's secret part (a paste into the wrong box, or "new cookie <value>"). `audit.record` redacts
    the reason with `redact_text`, which only knows the secrets in `SecretRegistry`; `CredentialManager.replace`
    writes the audit row inside its control.db transaction and registers the new value only AFTER that write.

Why it exists
    The value is bare (Roblox cookies are often copied without the public warning, and `_clean_value` accepts that),
    so neither the `TOKEN_PREFIX` pattern nor the `.ROBLOSECURITY=` pattern of the redactor can find it. At the
    moment the reason is redacted, the only registered credential is the previous one, so the new credential is
    stored in clear in `audit_log.reason`, which is shown on the Audit page and included in exports and backups.

How it works
    The real app (`confinement_harness.running_app`) runs; the audited `replace` stores a fresh bare value with the
    same text in the reason; then every `audit_log` row and the raw bytes of control.db are scanned with
    `leak_scan`. A control check shows the same reason IS scrubbed once the value is registered (a second replace
    reusing the same reason text), so the failure was about ordering, not about the scanner. Fixed in the review
    round: `replace` registers the new value before its control.db transaction writes the audit row.

What to read next
    `src/roxy/egress/credential.py` (`replace`: `SecretRegistry.register` after `control.write`),
    `src/roxy/config/audit.py` (`record` redacts the reason), `tests/security/test_confinement_records.py`.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

import pytest
from confinement_harness import ADMIN, leak_scan, running_app


def audit_reasons(run: Any) -> list[str]:
    rows = run.ctx.dbs.control.read_sync(
        lambda conn: conn.execute("SELECT reason FROM audit_log WHERE action = 'credential.replace'").fetchall()
    )
    return [str(row[0] or "") for row in rows]


async def test_replace_reason_never_stores_the_new_credential(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    new_value = "NEWBAREVALUE" + secrets.token_hex(96).upper()  # copied without the public warning
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        await run.ctx.egress.credential.replace(new_value, ADMIN, reason=f"new cookie {new_value}")
        reasons = audit_reasons(run)
        assert len(reasons) == 1  # the row was really written
        control_bytes = b"".join(
            path.read_bytes() for path in sorted(env.state_dir.iterdir()) if path.name.startswith("control.db")
        )
    found = {"audit reason": leak_scan(reasons[0], new_value), "control.db bytes": leak_scan(control_bytes, new_value)}
    assert found == {"audit reason": [], "control.db bytes": []}


async def test_a_registered_value_in_the_reason_is_scrubbed(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: once the value is registered (a second replace with the same value), the same reason is clean."""
    new_value = "NEWBAREVALUE" + secrets.token_hex(96).upper()
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        await run.ctx.egress.credential.replace(new_value, ADMIN, reason="first")
        await run.ctx.egress.credential.replace(new_value, ADMIN, reason=f"again {new_value}")
        reasons = audit_reasons(run)
    assert len(reasons) == 2
    assert leak_scan(reasons[1], new_value) == []
