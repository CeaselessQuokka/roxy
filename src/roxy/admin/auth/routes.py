"""The auth HTTP surface: the login page, `/admin/api/v1/auth/*`, logout, enrollment, and the kill-switch link.

What this is
    `router`, an `APIRouter` the admin router includes (`roxy/admin/router.py`). Pages: `GET /admin` (login),
    `GET /admin/enroll` (authenticator enrollment), `GET|POST /admin/invalidate/<token>` (kill switch). JSON API
    under `/admin/api/v1/auth`: `login`, `mfa`, `mfa/email`, `mfa/passkey/options`, `session`, `heartbeat`,
    `logout`, `reauth`, `reauth/passkey/options`, `totp/enroll/start|confirm`, `recovery-codes`,
    `recovery-codes/regenerate`, `passkeys` (list, `register/options`, `register/verify`, `<id>/delete`),
    `trusted-devices` (list, `<id>/revoke`, `revoke-all`) and `sessions` (list, `<id>/revoke`, `revoke-others`,
    `revoke-all`).

Why it exists
    Routes stay thin: parse and validate the request, call the flow (`flow.py`, `enrollment.py`), turn the result
    into the exact response. The pre-session endpoints (login, second factor, email resend, passkey options)
    cannot carry a CSRF token yet, so they check what they can: the admin allowlist, the same-origin headers
    when present, a strict JSON body, and the login transaction's IP and User-Agent binding. Everything after
    login uses `require_admin` and, when it changes state, `require_csrf`.

How it works
    - Bodies are Pydantic models with `extra="forbid"` and bounded lengths (plan 9.9); a malformed body is 400
      `Invalid request`, and for the login step it is also logged with v1's reason `Malformed login payload`.
    - Every response that creates or rotates a session sets the new cookie and returns a fresh masked
      `CsrfToken`, because the CSRF secret is derived from the session id and changes with it.
    - Pages render templates from `templates/auth/` with no inline script or style: one nonce'd module script
      (`static/js/auth.js`) and one stylesheet, so the strict CSP of plan 9.2 holds.

What to read next
    `roxy/admin/auth/flow.py`, `roxy/admin/auth/deps.py`, then `roxy/templates/auth/login.html`.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import RedirectResponse, Response

from roxy.admin.auth import enrollment, invalidation, sessions, trusted_devices
from roxy.admin.auth.allowlist import admin_ip_allowed, not_found
from roxy.admin.auth.csrf import foreign_origin
from roxy.admin.auth.deps import (
    STATE_COOKIE,
    STATE_SESSION,
    AdminPrincipal,
    client_ip,
    get_auth,
    get_ctx_or_none,
    load_request_session,
    masked_csrf,
    masked_csrf_for_token,
    request_info,
    require_admin,
    require_csrf,
)
from roxy.admin.auth.events import REASON_MALFORMED, audit_auth, record_probe
from roxy.admin.auth.flow import AuthError, LoginOutcome
from roxy.admin.auth.responses import (
    clear_session_cookie,
    error_response,
    read_json_body,
    set_admin_seen_cookie,
    set_session_cookie,
    set_trusted_cookie,
    v1_json,
)
from roxy.core.templating import Templates

log = logging.getLogger("roxy.admin.auth.routes")

API = "/admin/api/v1/auth"
DASHBOARD_PATH = "/admin/dashboard"
ENROLL_PATH = "/admin/enroll"
LOGGED_OUT_TEXT = "Logged out"
NOT_FOUND_TEXT = "Not Found"

router = APIRouter(include_in_schema=False)


# Dependency aliases (module level, so every route reads the same guard and no call sits in a default argument).
AdminSession = Annotated[AdminPrincipal, Depends(require_admin("session"))]
AdminPassive = Annotated[AdminPrincipal, Depends(require_admin("session", activity="never"))]
AdminEnroll = Annotated[AdminPrincipal, Depends(require_admin("session", allow_bootstrap=True))]
AdminEnrollPassive = Annotated[
    AdminPrincipal, Depends(require_admin("session", allow_bootstrap=True, activity="never"))
]
AdminFresh = Annotated[AdminPrincipal, Depends(require_admin("fresh_mfa"))]
CsrfChecked = Annotated[None, Depends(require_csrf)]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class LoginBody(_Body):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    trust_device: bool = False


class MfaBody(_Body):
    transaction: str = Field(min_length=16, max_length=128)
    method: Literal["totp", "recovery", "email", "passkey"]
    code: str | None = Field(default=None, max_length=64)
    credential: dict[str, Any] | None = None


class TransactionBody(_Body):
    transaction: str = Field(min_length=16, max_length=128)


class ReauthBody(_Body):
    method: Literal["totp", "recovery", "passkey"]
    code: str | None = Field(default=None, max_length=64)
    credential: dict[str, Any] | None = None


class HeartbeatBody(_Body):
    idle_ms: int = Field(ge=0, le=10**10)


class CodeBody(_Body):
    code: str = Field(min_length=1, max_length=16)


class PasskeyRegisterBody(_Body):
    credential: dict[str, Any]
    name: str = Field(default="Passkey", max_length=64)


# ------------------------------------------------------------------------------------------------ helpers


def _pre_session_guard(request: Request) -> None:
    """Allowlist and same-origin checks for the endpoints that run before a session exists."""
    ctx = get_ctx_or_none(request)
    if ctx is None or not admin_ip_allowed(ctx, client_ip(request)):
        raise not_found()
    site = str(ctx.env.site_origin)
    fetch_site = request.headers.get("sec-fetch-site")
    if foreign_origin(request, site) or (fetch_site is not None and fetch_site.lower() != "same-origin"):
        raise AuthError(403, "Forbidden")


def _login_success(request: Request, outcome: LoginOutcome) -> Response:
    """Set the session (and trusted device) cookies; tell the page where to go next."""
    assert outcome.session_token is not None
    redirect = ENROLL_PATH if outcome.enrollment_required else DASHBOARD_PATH
    response = v1_json(
        {
            "CsrfToken": masked_csrf_for_token(outcome.session_token),
            "EnrollmentRequired": outcome.enrollment_required,
            "LoggedIn": True,
            "MfaLevel": outcome.mfa_level,
            "Redirect": redirect,
            "Status": "Success",
        }
    )
    set_session_cookie(response, outcome.session_token)
    if outcome.trusted_token:
        set_trusted_cookie(response, outcome.trusted_token, get_auth(request).settings.int("trusted_device_days"))
    set_admin_seen_cookie(response)
    return response


def _login_response(request: Request, outcome: LoginOutcome) -> Response:
    if outcome.kind == "session":
        return _login_success(request, outcome)
    body: dict[str, Any] = {
        "Bootstrap": outcome.bootstrap,
        "ExpiresIn": outcome.expires_in,
        "Methods": list(outcome.methods),
        "Status": "Success",
        "Transaction": outcome.transaction,
        "TwoFA": True,
    }
    if outcome.email_expires_in is not None:
        body["EmailExpiresIn"] = outcome.email_expires_in
    return v1_json(body)


def _session_of(request: Request) -> tuple[sessions.SessionRecord, str]:
    record = getattr(request.state, STATE_SESSION, None)
    token = getattr(request.state, STATE_COOKIE, None)
    if not isinstance(record, sessions.SessionRecord) or not isinstance(token, str):
        raise not_found()  # pragma: no cover - require_admin always ran first
    return record, token


def _rotated(token: str, body: dict[str, Any]) -> Response:
    response = v1_json({**body, "CsrfToken": masked_csrf_for_token(token)})
    set_session_cookie(response, token)
    return response


def _templates(request: Request) -> Templates:
    templates: Templates = request.app.state.templates
    return templates


# ------------------------------------------------------------------------------------------------ pages


@router.get("/admin")
async def login_page(request: Request) -> Response:
    """The login page, or a redirect when this browser already has a live session (v1 bug 15 fixed)."""
    ctx = get_ctx_or_none(request)
    if ctx is None or not admin_ip_allowed(ctx, client_ip(request)):
        raise not_found()
    try:
        found = await load_request_session(request)
    except Exception:  # shared state trouble: show the login page; the login itself will explain
        found = None
    if found is not None:
        target = ENROLL_PATH if found[0].mfa_level == "bootstrap" else DASHBOARD_PATH
        return RedirectResponse(target, status_code=302)
    settings = ctx.settings
    return _templates(request).render(
        request,
        "auth/login.html",
        {
            "trusted_devices_enabled": bool(settings.bool("admin_trusted_devices_enabled")),
            "trusted_device_days": int(settings.int("trusted_device_days")),
            "email_code_enabled": bool(settings.bool("admin_email_code_enabled")),
        },
    )


@router.get(ENROLL_PATH)
async def enroll_page(request: Request, principal: AdminEnroll) -> Response:
    record, _ = _session_of(request)
    return _templates(request).render(
        request,
        "auth/enroll.html",
        {
            "csrf_token": masked_csrf(request),
            "bootstrap": record.mfa_level == "bootstrap",
            "username": principal.username,
        },
    )


@router.get("/admin/invalidate/{token}")
async def invalidate_confirm(request: Request, token: str) -> Response:
    """The kill-switch confirmation page. Never uses (or, normally, even reads) the token: mail scanners open links."""
    await _invalidate_visible(request, token)
    return _templates(request).render(request, "auth/invalidate.html", {"state": "confirm", "token": token})


async def _invalidate_visible(request: Request, token: str) -> None:
    """404 unless this caller may see the page: allowlisted network, or a valid link (allowlist on, D6)."""
    ctx = get_ctx_or_none(request)
    if ctx is None or not 0 < len(token) <= 100 or not all(c.isascii() and (c.isalnum() or c in "-_") for c in token):
        raise not_found()
    if admin_ip_allowed(ctx, client_ip(request)):
        return
    now = int(ctx.clock.now())
    try:
        valid = await get_auth(request).control_read(lambda conn: invalidation.is_valid(conn, token, now))
    except AuthError:
        valid = False
    if not valid:
        raise not_found()


@router.post("/admin/invalidate/{token}")
async def invalidate_apply(request: Request, token: str) -> Response:
    """Use the kill-switch link: end sessions and (by default) revoke trusted devices. Single use."""
    await _invalidate_visible(request, token)
    form = await request.form()
    revoke_trusted = form.get("revoke_trusted") == "1"
    all_sessions = form.get("all_sessions") == "1"
    auth = get_auth(request)
    info = request_info(request)
    now = int(auth.clock.now())
    try:
        result = await auth.control_write(
            lambda conn: invalidation.kill_switch(
                conn,
                token=token,
                now=now,
                revoke_trusted=revoke_trusted,
                all_sessions=all_sessions,
                ip=info.ip,
                request_id=info.request_id,
            )
        )
    except AuthError as error:
        return error_response(error)
    if result is None:
        return _templates(request).render(request, "auth/invalidate.html", {"state": "failed"}, status_code=404)
    response = _templates(request).render(
        request,
        "auth/invalidate.html",
        {
            "state": "done",
            "all_sessions": result.all_sessions,
            "sessions_ended": result.sessions_ended,
            "trusted_revoked": result.trusted_devices_revoked,
            "revoke_trusted": revoke_trusted,
        },
    )
    clear_session_cookie(response)
    return response


# ------------------------------------------------------------------------------------------------ login API


@router.post(f"{API}/login")
async def api_login(request: Request) -> Response:
    try:
        _pre_session_guard(request)
        info = request_info(request)
        try:
            body = await read_json_body(request, LoginBody)
        except AuthError:
            record_probe(get_auth(request).ctx, ip=info.ip, reason=REASON_MALFORMED, user_agent=info.ua, path=info.path)
            raise
        outcome = await get_auth(request).login(info, body.username, body.password, body.trust_device)
    except AuthError as error:
        return error_response(error)
    return _login_response(request, outcome)


@router.post(f"{API}/mfa")
async def api_mfa(request: Request) -> Response:
    try:
        _pre_session_guard(request)
        body = await read_json_body(request, MfaBody)
        outcome = await get_auth(request).mfa(
            request_info(request), body.transaction, body.method, body.code, body.credential
        )
    except AuthError as error:
        return error_response(error)
    return _login_response(request, outcome)


@router.post(f"{API}/mfa/email")
async def api_mfa_email(request: Request) -> Response:
    """Send (or resend) the emailed code of a login transaction; the previous code stops working."""
    try:
        _pre_session_guard(request)
        body = await read_json_body(request, TransactionBody)
        expires_in = await get_auth(request).resend_email(request_info(request), body.transaction)
    except AuthError as error:
        return error_response(error)
    return v1_json({"ExpiresIn": expires_in, "Status": "Success", "TwoFA": True})


@router.post(f"{API}/mfa/passkey/options")
async def api_mfa_passkey_options(request: Request) -> Response:
    try:
        _pre_session_guard(request)
        body = await read_json_body(request, TransactionBody)
        options = await get_auth(request).passkey_options(request_info(request), body.transaction)
    except AuthError as error:
        return error_response(error)
    return v1_json({"Options": options})


# ------------------------------------------------------------------------------------------------ session API


@router.get(f"{API}/session")
async def api_session(
    request: Request,
    principal: AdminEnrollPassive,
) -> Response:
    """Who is signed in, how long the session lasts, and a fresh masked CSRF token. Does not extend the session."""
    record, _ = _session_of(request)
    auth = get_auth(request)
    settings = auth.settings
    idle = int(settings.int("admin_session_idle_timeout_s"))
    window = int(settings.int("admin_reauth_window_s"))
    now = auth.clock.now()
    return v1_json(
        {
            "ActivityWindow": int(settings.int("admin_activity_window_s")),
            "CsrfToken": masked_csrf(request),
            "EnrollmentRequired": record.mfa_level == "bootstrap",
            "ExpiresAt": record.expires_at,
            "Fresh": record.is_fresh(now, window),
            "FreshUntil": record.created_at + window if record.mfa_level in sessions.FULL_MFA_LEVELS else None,
            "HeartbeatInterval": int(settings.int("admin_heartbeat_interval_s")),
            "IdleExpiresAt": record.idle_expires_at(idle),
            "IdleTimeout": idle,
            "MfaLevel": record.mfa_level,
            "ReauthWindow": window,
            "Username": principal.username,
        }
    )


@router.post(f"{API}/heartbeat")
async def api_heartbeat(
    request: Request,
    _principal: AdminEnrollPassive,
    _csrf: CsrfChecked,
) -> Response:
    """Keepalive: extends the session only when the page reports input within `admin_activity_window_s`."""
    try:
        body = await read_json_body(request, HeartbeatBody)
    except AuthError as error:
        return error_response(error)
    record, _ = _session_of(request)
    auth = get_auth(request)
    settings = auth.settings
    window_s = int(settings.int("admin_activity_window_s"))
    idle = int(settings.int("admin_session_idle_timeout_s"))
    extended = body.idle_ms <= window_s * 1000
    if extended:
        try:
            await auth.touch_session(record)
        except AuthError as error:
            return error_response(error)
    last_seen = max(record.last_seen_at, int(auth.clock.now())) if extended else record.last_seen_at
    expires_in = max(0, min(last_seen + idle, record.expires_at) - int(auth.clock.now()))
    return v1_json(
        {
            "ActivityWindow": window_s,
            "ExpiresIn": expires_in,
            "Extended": extended,
            "HeartbeatInterval": int(settings.int("admin_heartbeat_interval_s")),
            "IdleTimeout": idle,
            "OK": True,
        }
    )


@router.post(f"{API}/logout")
async def api_logout(
    request: Request,
    _principal: AdminEnrollPassive,
    _csrf: CsrfChecked,
) -> Response:
    """Deletes the server-side session (a copied cookie stops working too, unlike v1)."""
    record, _ = _session_of(request)
    try:
        await get_auth(request).logout(request_info(request), record)
    except AuthError as error:
        return error_response(error)
    response = v1_json(LOGGED_OUT_TEXT)
    clear_session_cookie(response)
    return response


@router.post(f"{API}/reauth")
async def api_reauth(
    request: Request,
    _principal: AdminPassive,
    _csrf: CsrfChecked,
) -> Response:
    """A fresh second factor for sensitive actions; rotates the session (new cookie, new CSRF token)."""
    record, _ = _session_of(request)
    try:
        body = await read_json_body(request, ReauthBody)
        token = await get_auth(request).reauth(request_info(request), record, body.method, body.code, body.credential)
    except AuthError as error:
        return error_response(error)
    return _rotated(token, {"Fresh": True, "Status": "Success"})


@router.post(f"{API}/reauth/passkey/options")
async def api_reauth_passkey_options(
    request: Request,
    _principal: AdminPassive,
    _csrf: CsrfChecked,
) -> Response:
    record, _ = _session_of(request)
    try:
        options = await get_auth(request).reauth_passkey_options(record)
    except AuthError as error:
        return error_response(error)
    return v1_json({"Options": options})


# ------------------------------------------------------------------------------------------------ enrollment


def _require_enroll_rights(request: Request, record: sessions.SessionRecord) -> None:
    """A bootstrap session may enroll; anyone else replacing their authenticator needs a fresh second factor."""
    if record.mfa_level == "bootstrap":
        return
    auth = get_auth(request)
    if not record.is_fresh(auth.clock.now(), int(auth.settings.int("admin_reauth_window_s"))):
        raise AuthError(403, "Re-authentication required", headers={"Roxy-Reauth": "required"})


@router.post(f"{API}/totp/enroll/start")
async def api_totp_start(
    request: Request,
    _principal: AdminEnroll,
    _csrf: CsrfChecked,
) -> Response:
    record, _ = _session_of(request)
    try:
        _require_enroll_rights(request, record)
        data = await enrollment.start_totp(get_auth(request), record)
    except AuthError as error:
        return error_response(error)
    return v1_json(data)


@router.post(f"{API}/totp/enroll/confirm")
async def api_totp_confirm(
    request: Request,
    _principal: AdminEnroll,
    _csrf: CsrfChecked,
) -> Response:
    record, _ = _session_of(request)
    try:
        _require_enroll_rights(request, record)
        body = await read_json_body(request, CodeBody)
        token, codes = await enrollment.confirm_totp(get_auth(request), request_info(request), record, body.code)
    except AuthError as error:
        return error_response(error)
    return _rotated(token, {"RecoveryCodes": codes, "Redirect": DASHBOARD_PATH, "Status": "Success"})


@router.get(f"{API}/recovery-codes")
async def api_recovery_status(request: Request, _principal: AdminPassive) -> Response:
    record, _ = _session_of(request)
    try:
        status = await enrollment.recovery_status(get_auth(request), record)
    except AuthError as error:
        return error_response(error)
    return v1_json(status)


@router.post(f"{API}/recovery-codes/regenerate")
async def api_recovery_regenerate(
    request: Request,
    _principal: AdminFresh,
    _csrf: CsrfChecked,
) -> Response:
    record, _ = _session_of(request)
    try:
        codes = await enrollment.regenerate_recovery(get_auth(request), request_info(request), record)
    except AuthError as error:
        return error_response(error)
    return v1_json({"RecoveryCodes": codes, "Status": "Success"})


# ------------------------------------------------------------------------------------------------ passkeys


@router.get(f"{API}/passkeys")
async def api_passkeys(request: Request, _principal: AdminPassive) -> Response:
    record, _ = _session_of(request)
    try:
        items = await enrollment.passkey_list(get_auth(request), record)
    except AuthError as error:
        return error_response(error)
    return v1_json({"Passkeys": items})


@router.post(f"{API}/passkeys/register/options")
async def api_passkey_register_options(
    request: Request,
    _principal: AdminFresh,
    _csrf: CsrfChecked,
) -> Response:
    record, _ = _session_of(request)
    try:
        options = await enrollment.passkey_register_options(get_auth(request), record)
    except AuthError as error:
        return error_response(error)
    return v1_json({"Options": options})


@router.post(f"{API}/passkeys/register/verify")
async def api_passkey_register_verify(
    request: Request,
    _principal: AdminFresh,
    _csrf: CsrfChecked,
) -> Response:
    record, _ = _session_of(request)
    try:
        body = await read_json_body(request, PasskeyRegisterBody)
        item = await enrollment.passkey_register_verify(
            get_auth(request), request_info(request), record, body.credential, body.name
        )
    except AuthError as error:
        return error_response(error)
    return v1_json({"Passkey": item, "Status": "Success"})


@router.post(f"{API}/passkeys/{{passkey_id}}/delete")
async def api_passkey_delete(
    request: Request,
    passkey_id: Annotated[int, Path(ge=1)],
    _principal: AdminFresh,
    _csrf: CsrfChecked,
) -> Response:
    record, _ = _session_of(request)
    try:
        removed = await enrollment.passkey_delete(get_auth(request), request_info(request), record, passkey_id)
    except AuthError as error:
        return error_response(error)
    if not removed:
        return v1_json(NOT_FOUND_TEXT, 404)
    return v1_json({"Removed": True, "Status": "Success"})


# ------------------------------------------------------------------------------------------------ trusted devices


@router.get(f"{API}/trusted-devices")
async def api_trusted_list(request: Request, principal: AdminPassive) -> Response:
    auth = get_auth(request)
    now = int(auth.clock.now())
    try:
        devices = await auth.control_read(lambda conn: trusted_devices.list_for_user(conn, principal.user_id, now))
    except AuthError as error:
        return error_response(error)
    current = request.cookies.get(trusted_devices.TRUSTED_COOKIE)
    this_device = None
    if current:
        try:
            found = await auth.control_read(lambda conn: trusted_devices.find_valid(conn, current, principal.ua, now))
            this_device = found.id if found is not None and found.user_id == principal.user_id else None
        except AuthError:
            this_device = None
    return v1_json(
        {
            "Devices": devices,
            "Enabled": bool(auth.settings.bool("admin_trusted_devices_enabled")),
            "ThisDevice": this_device,
        }
    )


async def _revoke_trusted(request: Request, principal: AdminPrincipal, device_id: int | None) -> Response:
    auth = get_auth(request)
    info = request_info(request)
    now = int(auth.clock.now())

    def write(conn: Any) -> int:
        if device_id is None:
            count = trusted_devices.revoke_all(conn, principal.user_id)
        else:
            count = 1 if trusted_devices.revoke(conn, principal.user_id, device_id) else 0
        if count:
            audit_auth(
                conn,
                "auth.trusted_devices_revoked_all" if device_id is None else "auth.trusted_device_revoked",
                user_id=principal.user_id,
                username=principal.username,
                ip=info.ip,
                request_id=info.request_id,
                after={"revoked": count, "device_id": device_id},
                at=now,
            )
        return count

    try:
        count = await auth.control_write(write)
    except AuthError as error:
        return error_response(error)
    if device_id is not None and count == 0:
        return v1_json(NOT_FOUND_TEXT, 404)
    return v1_json({"Revoked": count})


@router.post(f"{API}/trusted-devices/{{device_id}}/revoke")
async def api_trusted_revoke(
    request: Request,
    device_id: Annotated[int, Path(ge=1)],
    principal: AdminSession,
    _csrf: CsrfChecked,
) -> Response:
    return await _revoke_trusted(request, principal, device_id)


@router.post(f"{API}/trusted-devices/revoke-all")
async def api_trusted_revoke_all(
    request: Request,
    principal: AdminSession,
    _csrf: CsrfChecked,
) -> Response:
    response = await _revoke_trusted(request, principal, None)
    response.delete_cookie(trusted_devices.TRUSTED_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return response


# ------------------------------------------------------------------------------------------------ sessions


@router.get(f"{API}/sessions")
async def api_sessions(request: Request, principal: AdminPassive) -> Response:
    auth = get_auth(request)
    now = int(auth.clock.now())
    try:
        items = await auth.control_read(lambda conn: sessions.list_for_user(conn, principal.user_id, now))
    except AuthError as error:
        return error_response(error)
    return v1_json({"Current": sessions.public_id(principal.session_id), "Sessions": items})


async def _revoke_sessions(request: Request, principal: AdminPrincipal, mode: str, short_id: str | None) -> Response:
    auth = get_auth(request)
    info = request_info(request)
    now = int(auth.clock.now())

    def write(conn: Any) -> int:
        if mode == "one":
            count = 1 if sessions.revoke_public(conn, principal.user_id, short_id or "") else 0
        elif mode == "others":
            count = sessions.revoke_user(conn, principal.user_id, keep=principal.session_id)
        else:
            count, _epoch = sessions.revoke_all(conn, now)
        audit_auth(
            conn,
            {"one": "auth.session_revoked", "others": "auth.sessions_revoked_others"}.get(
                mode, "auth.sessions_revoked_all"
            ),
            user_id=principal.user_id,
            username=principal.username,
            ip=info.ip,
            request_id=info.request_id,
            after={"sessions_ended": count, "session": short_id},
            at=now,
        )
        return count

    try:
        count = await auth.control_write(write)
    except AuthError as error:
        return error_response(error)
    if mode == "one" and count == 0:
        return v1_json(NOT_FOUND_TEXT, 404)
    response = v1_json({"Revoked": count})
    if mode == "all" or (mode == "one" and short_id == sessions.public_id(principal.session_id)):
        clear_session_cookie(response)
    return response


@router.post(f"{API}/sessions/revoke-others")
async def api_sessions_revoke_others(
    request: Request,
    principal: AdminSession,
    _csrf: CsrfChecked,
) -> Response:
    return await _revoke_sessions(request, principal, "others", None)


@router.post(f"{API}/sessions/revoke-all")
async def api_sessions_revoke_all(
    request: Request,
    principal: AdminSession,
    _csrf: CsrfChecked,
) -> Response:
    """Sign out everywhere (the epoch kill switch from inside the dashboard), this browser included."""
    return await _revoke_sessions(request, principal, "all", None)


@router.post(f"{API}/sessions/{{session_id}}/revoke")
async def api_session_revoke(
    request: Request,
    session_id: Annotated[str, Path(min_length=16, max_length=16, pattern=r"^[0-9a-f]{16}$")],
    principal: AdminSession,
    _csrf: CsrfChecked,
) -> Response:
    return await _revoke_sessions(request, principal, "one", session_id)
