"""Captures keep caller header NAMES verbatim (review lens cred, finding cred-8).

What this is
    A variant of finding F4 on a path that is wired today. A capture stores the caller's request headers through
    `metrics/capture.py: _headers`, which calls `core/redact.py: redact_headers`: a header whose NAME says secret loses
    its value, every other value is scrubbed with `redact_text`, but the NAME itself is kept as sent. A header name is
    any HTTP token, so 40 hex characters of the credential's secret part are a valid name, and Roxy never forwards
    caller headers upstream, so the leak guard never sees it and the request is served (and captured) normally.

Why it exists
    Plan 9.15 and 19.7 ("inject secrets into requests and assert logs, captures, exports are clean"); the F4 probe
    injects a header VALUE only. The capture is shown on the Live page (`GET /live/{id}`) and lives in metrics.db for
    15 minutes, so a caller can make Roxy keep and display a credential piece it was told never to store.

How it works
    The real app runs (`confinement_harness.running_app`) with every served request captured. The caller sends one
    ordinary GET with an extra header named `X-<piece>`; the recorder is flushed, and every decoded capture is scanned
    with `leak_scan`. A control check shows the request was served and captured. Fixed: `redact_headers` replaces a
    name that `redact_label` changes with `[redacted-header-N]` and its value with `[redacted]`, so the capture says
    a header was hidden without holding any of it, and ordinary headers stay as sent.

What to read next
    `src/roxy/core/redact.py` (`redact_headers`), `src/roxy/metrics/capture.py` (`build_record`, `_headers`),
    `tests/security/test_confinement_records.py`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from confinement_harness import leak_scan, running_app, secret_part

from roxy.core.redact import TOKEN_PREFIX
from roxy.metrics.capture import decode_record


async def test_captured_header_names_never_hold_a_credential_piece(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    piece = secret_part(fake_secrets["roblox_credential"])[30:70]
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        await run.settings(capture_sample_served_pct=100, request_sample_pct=100)
        run.clock.advance(5)
        response = await run.get("/games.roblox.com/v1/games?universeIds=1", headers={f"X-{piece}": "1"})
        await run.ctx.recorder.flush()
        rows = run.ctx.dbs.metrics.read_sync(
            lambda conn: conn.execute("SELECT compressed_blob FROM captures").fetchall()
        )
    assert response.status_code == 200  # served: header names never go upstream, so the guard never saw it
    decoded = [decode_record(row[0]) for row in rows if row[0] is not None]
    assert decoded  # the request was really captured
    assert leak_scan(json.dumps(decoded, default=str), TOKEN_PREFIX + piece) == []
    headers = decoded[-1]["request_headers"]
    assert headers.get("[redacted-header-1]") == "[redacted]", headers  # the capture shows one header was hidden
    assert headers.get("user-agent") or headers.get("User-Agent"), headers  # ordinary headers are kept
