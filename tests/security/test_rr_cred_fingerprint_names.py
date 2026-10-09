"""Header NAMES recorded by `record_fingerprint` are stored unscrubbed (review lens cred, finding cred-7).

What this is
    A variant of finding F4 ("credential piece in labels"). The F4 fix scrubs every caller-supplied label the
    recorder stores (templates, hosts, place ids, event label columns) with `redact_label`, and fingerprint VALUES
    with `redact_text` at flush time. Fingerprint header NAMES (`metrics/fingerprints.py: FingerprintAggregator.add`,
    `write_fingerprints`) are only lowercased and cut to 120 characters, then written to `fingerprint_headers.name`
    and inside `fingerprint_values` rows. Header names are caller text (any HTTP token, so 40 hex characters of the
    credential's secret part are a valid name), they are never forwarded upstream, so the leak guard never sees them.

Why it exists
    Plan 9.15 and 19.7 require every record to be free of the credential, and the F4 probe asserts it for metrics.db.
    Today the proxy pipeline does not call `record_fingerprint` yet (parity row 79 is not wired in wave 2), so this is
    latent: the first wiring of the recorder API stores a caller's header name verbatim. The blocked-request branch
    of the same method already scrubs names (they go through `_event`), which shows the intent.

How it works
    The real app runs (`confinement_harness.running_app`); the recorder's public `record_fingerprint` is called with
    a header name holding a 40 character run of the credential's secret part and an ordinary value, the recorder is
    flushed, and metrics.db is scanned with `leak_scan`. A control check shows the rows were written. Fixed:
    `fingerprints.name_for_storage` stores a name that `redact_label` changes as `fp:` plus its keyed hash, and that
    name's values only as hashes; the ordinary name next to it is kept as sent.

What to read next
    `src/roxy/metrics/fingerprints.py`, `src/roxy/metrics/recorder.py` (`record_fingerprint`),
    `tests/security/test_confinement_records.py::test_injected_credential_piece_is_scrubbed_everywhere`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from confinement_harness import leak_scan, running_app, secret_part

from roxy.core.redact import TOKEN_PREFIX


async def test_fingerprint_header_names_never_store_a_credential_piece(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    piece = secret_part(fake_secrets["roblox_credential"])[30:70]
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        run.ctx.recorder.record_fingerprint([(f"X-{piece}", "1"), ("Accept", "*/*")], "Roblox/Linux")
        await run.ctx.recorder.flush()
        names = run.ctx.dbs.metrics.read_sync(
            lambda conn: conn.execute("SELECT count(*) FROM fingerprint_headers").fetchone()[0]
        )
        assert names >= 2  # the rows were really written
        rows = run.ctx.dbs.metrics.read_sync(
            lambda conn: (
                conn.execute("SELECT name FROM fingerprint_headers").fetchall()
                + conn.execute("SELECT name FROM fingerprint_values").fetchall()
            )
        )
        values = run.ctx.dbs.metrics.read_sync(
            lambda conn: dict(conn.execute("SELECT name, value FROM fingerprint_values").fetchall())
        )
    text = "\n".join(str(row[0]) for row in rows)
    assert leak_scan(text, TOKEN_PREFIX + piece) == []
    assert values["accept"] == "*/*"  # an ordinary header keeps its name and value
    hidden = [name for name in values if name.startswith("fp:")]
    assert len(hidden) == 1, values  # the secret-shaped name is stored as its keyed hash...
    assert values[hidden[0]].startswith("fp:")  # ...and so is its value
