"""`SSLKEYLOGFILE` still reaches the credential client's TLS context (review lens cred, finding cred-6).

What this is
    A probe of plan C2 item 2 ("all clients are built with `trust_env=False` so `HTTPS_PROXY`, `ALL_PROXY`, `.netrc`
    and similar environment settings are ignored") and 19.5 item 3. `egress/metering.py: MeteringTransport` says
    "trust_env=False: SSL_CERT_FILE, SSLKEYLOGFILE and friends from the environment are ignored". The first is true;
    the second is not: httpx builds its context with `ssl.create_default_context(cafile=certifi.where())`, and
    CPython's `create_default_context` itself copies `SSLKEYLOGFILE` into `context.keylog_filename` (unless Python
    runs with `-E`), whatever httpx's `trust_env` says.

Why it exists
    With `SSLKEYLOGFILE` in the service environment (a debugging leftover in `/etc/roxy/roxy.env`, or a drop-in), every
    TLS session of the credential client writes its secrets to that file, so anyone who can read it and capture
    traffic recovers the `Cookie: .ROBLOSECURITY=<value>` header in clear. The environment, not the code, decides
    whether the credential is confidential on the wire, which is exactly what C2 item 2 forbids, and the H-ENV-PROXY
    self-test does not look at this variable.

How it works
    The variable is set (to a file under the test's temporary directory) before the real app starts through
    `confinement_harness.running_app`; the credential client the app built is then inspected: its TLS context must
    have no key log file. The same is checked for a client built directly by `make_credential_client`. Fixed in
    the review round: `metering.tls_context` builds every egress TLS context with its key log switched off, and the
    H-ENV-PROXY self-test fails while the variable is set.

What to read next
    `src/roxy/egress/metering.py` (`MeteringTransport.__init__`), `src/roxy/egress/clients.py`
    (`make_credential_client`, `self_test_env_proxy`), and CPython's `ssl.create_default_context`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from confinement_harness import running_app

from roxy.egress.clients import make_credential_client


def keylog_of(client: Any) -> Any:
    """The key log file name of a client's TLS context (None when keys are not logged)."""
    pool = getattr(client.http._transport, "_pool", None)
    context = getattr(pool, "_ssl_context", None)
    assert context is not None  # the pool really has a TLS context to inspect
    return getattr(context, "keylog_filename", None)


async def test_credential_client_never_logs_tls_keys_from_the_environment(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    keylog = tmp_path / "tls-keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        wired = keylog_of(run.ctx.egress.credential_client)
        # The health self-test names the variable: other TLS connections of the process would still log keys.
        check = run.ctx.egress.self_test_env_proxy()
        assert (check.status, check.value) == ("fail", "SSLKEYLOGFILE")
        assert check.facts["clients_honoring"] == []  # every egress client ignores it
    direct = make_credential_client()
    try:
        built = keylog_of(direct)
    finally:
        await direct.aclose()
    assert (wired, built) == (None, None)
