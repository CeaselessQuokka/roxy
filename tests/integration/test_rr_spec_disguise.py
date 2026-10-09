"""Reviewer finding spec-1: a disguised refusal must be byte for byte a genuine per-IP throttle refusal.

What this is
    An end-to-end check through the fully wired app: a clean client's genuine throttle refusal (its eleventh
    request in the window) is compared with the disguised refusals a clean client gets for a ban and for a header
    filter without a message, on the wire: status, body, and every response header in order, except the ones that
    differ for every request (the request id).

Why it exists
    Plan 10.5 disguises bans as throttles "so abusers do not learn they are banned", and DESIGN.md 11.9 (fix pass 1)
    promises the disguise is "byte-identical to a genuine throttle refusal at that moment". The fix pass compared
    the header values only (the e2e goldens compare dictionaries). A client that reads raw headers (any HTTP
    library, `curl -i`) sees the order, so a different order told a banned client it is banned. Fixed: the genuine
    throttle refusal and every disguised one build their headers with one function
    (`checks/base.py throttle_refusal_headers`).

How it works
    The e2e harness of `tests/integration/test_pipeline_e2e.py`, loaded by path under its own module name (so its
    tests are not collected twice), runs the real app with respx playing Roblox and the tarpit off. Each client gets
    its own address.

What to read next
    `roxy/abuse/checks/base.py` (`throttle_refusal_headers`, `disguised_throttle`, `redisguise`, `with_trio`),
    `roxy/abuse/checks/throttle.py`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest


def _load(name: str, path: Path) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


E2E = _load("rr_spec_disguise_e2e_harness", Path(__file__).with_name("test_pipeline_e2e.py"))

VARYING = {"roxy-request-id", "date"}
"""Headers whose value differs for every request whatever the outcome."""


@pytest.fixture
async def app(env: Any, credentials_dir: Path, fake_secrets: dict[str, str], respx_mock: Any) -> Any:
    async with E2E.running_app(env, credentials_dir, fake_secrets, respx_mock) as harness:
        yield harness


def wire(response: httpx.Response) -> tuple[int, bytes, list[tuple[str, str]]]:
    """Status, body and the raw header list in order, without the per-request values."""
    headers = [
        (name.decode("latin-1"), value.decode("latin-1"))
        for name, value in response.headers.raw
        if name.decode("latin-1").lower() not in VARYING
    ]
    return response.status_code, response.content, headers


async def genuine_throttle(app: Any) -> tuple[int, bytes, list[tuple[str, str]]]:
    """A clean client's first throttle refusal (10 per 50 s by default, so the eleventh request)."""
    app.route(E2E.GAMES, E2E.GAMES_PATH).mock(return_value=httpx.Response(200, json={"data": []}))
    ip = app.ip()
    response = None
    for n in range(11):
        response = await app.get(E2E.games(n + 1), ip=ip)
    assert response is not None
    assert response.status_code == 429
    assert response.headers["Roxy-Refusal"] == "throttle"
    return wire(response)


async def test_spec_1_value_level_disguise_still_matches(app: Any) -> None:
    """Control: the values of a disguised ban match a genuine throttle refusal (they did before the fix too)."""
    genuine = await genuine_throttle(app)
    ip = app.ip()
    await app.rule("bans", {"subject_type": "ip", "subject": ip, "reason_text": "rr spec"})
    banned = wire(await app.get(E2E.games(1), ip=ip))
    assert banned[0] == genuine[0]
    assert banned[1] == genuine[1]
    assert dict(banned[2]) == dict(genuine[2])


@pytest.mark.parametrize("kind", ["ban", "header_filter"])
async def test_spec_1_disguised_refusal_is_byte_identical_to_a_genuine_throttle(app: Any, kind: str) -> None:
    genuine = await genuine_throttle(app)
    ip = app.ip()
    if kind == "ban":
        await app.rule("bans", {"subject_type": "ip", "subject": ip, "reason_text": "rr spec"})
        response = await app.get(E2E.games(1), ip=ip)
    else:
        await app.rule("rules_header", {"needle": "xeno", "scope": "either"})
        response = await app.get(E2E.games(1), ip=ip, headers={"Xeno-Fingerprint": "4f3a91c0"})
    disguised = wire(response)
    assert disguised[0] == genuine[0]
    assert disguised[1] == genuine[1]
    assert disguised[2] == genuine[2]  # same headers, same values, same order on the wire
