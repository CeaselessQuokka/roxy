"""The app's HTTPException handler speaks the DESIGN.md section 13 error format on the admin API (wave 3b).

What this is
    Unit tests of `core/errors.py section13_exception_body`: which exceptions on which paths get the section 13
    error object, and which keep their old answers (the uniform 404, page paths, other statuses).

Why it exists
    Plan D9 and DESIGN.md 13: one admin API, one error format, whoever raises the error (an area route, an auth
    route or a guard). The allowlist 404 must stay byte for byte the answer for a missing path (D6), so it is not
    touched here.

How it works
    Plain `HTTPException` objects are fed to the function with admin API, auth and page paths.

What to read next
    `roxy/core/errors.py`, `roxy/admin/auth/deps.py` (the guards), `tests/security/test_admin_routes.py`.
"""

from __future__ import annotations

import json

from starlette.exceptions import HTTPException

from roxy.admin.auth.deps import ReauthRequired
from roxy.core.errors import ENROLL_CODE, ENROLL_HEADER, section13_exception_body

API = "/admin/api/v1"


def _body(exc: HTTPException, path: str) -> dict[str, object] | None:
    raw = section13_exception_body(exc, path)
    return None if raw is None else json.loads(raw)


def test_guard_answers_on_the_api_get_section13_codes() -> None:
    assert _body(HTTPException(401, "Session expired"), f"{API}/settings") == {
        "error": {"code": "unauthorized", "message": "Session expired", "fields": {}}
    }
    assert _body(HTTPException(403, "Forbidden"), f"{API}/auth/logout") == {
        "error": {"code": "forbidden", "message": "Forbidden", "fields": {}}
    }
    enroll = HTTPException(403, "Finish enrolling", headers={ENROLL_HEADER: "required"})
    assert _body(enroll, f"{API}/settings")["error"]["code"] == ENROLL_CODE  # type: ignore[index]
    assert _body(HTTPException(503, "Busy"), f"{API}/audit")["error"]["code"] == "unavailable"  # type: ignore[index]


def test_an_exception_with_an_error_code_gets_its_own_code_on_any_admin_path() -> None:
    body = _body(ReauthRequired(), f"{API}/auth/recovery-codes/regenerate")
    assert body is not None
    assert body["error"]["code"] == "reauth_required"  # type: ignore[index]
    assert _body(ReauthRequired(), "/admin/settings") is not None


def test_other_answers_are_left_alone() -> None:
    assert _body(HTTPException(404, "Not Found"), f"{API}/nothing") is None  # the uniform 404 has its own writer
    assert _body(HTTPException(401, "Session expired"), "/admin/settings") is None  # pages redirect instead
    assert _body(HTTPException(405, "Method Not Allowed"), f"{API}/settings") is None
    assert _body(HTTPException(401, "Session expired"), "/games.roblox.com/v1/games") is None
