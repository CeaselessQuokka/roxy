"""The shared layer of the admin API (`/admin/api/v1`): guards, errors, time ranges, tables, exports, KPI tiles.

What this is
    Everything the API modules (`admin/api/<area>.py`, P9) have in common, with stable names:
      * Routing: `area_router(area)` builds a module's `router` on `AdminApiRoute`, the route class that answers
        errors in the DESIGN.md section 13 shape. `AdminSession`, `AdminFreshMfa` and `CsrfChecked` are the guard
        dependencies every route declares (`admin_session`, `admin_fresh_mfa` and `require_csrf` underneath).
      * Errors: `ApiError` and its helpers (`bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
        `validation_error`, `rate_limited`, `unavailable`), `error_response`, `validation_answer` (FastAPI's
        validation errors as 400 or 422), `service_error` and `run_mutation` / `service_errors` (the services'
        refusals as 422, 409, 404 or 503).
      * Who and what: `actor_for(principal)` (the audit `Actor`), `request_id_of(request)`, `ApiBody` (the base of
        every request body: unknown fields refused) and `require_reason`.
      * Time: `RangeParams`, `range_params`, `build_time_range`, `time_range` and `TimeRangeDep`, all built on
        `metrics.queries.resolve_window`, `comparison_window` and `bucket_starts` (one implementation of windows).
      * Answers: `range_info`, `series_entry`, `series_from_read_model`, `series_answer`, `annotation_entries`,
        `reset_notices`, `kpi_tile`, `kpi_from_read_model`.
      * Tables: `Column`, `TableSpec`, `TableQuery`, `table_params(spec)`, `page_rows`, `table_answer`,
        `table_from_read_model`, `collect_pages`.
      * Exports: `export_format`, `ExportFormatDep`, `csv_safe`, `csv_bytes`, `render_export`, `export_ip_policy`,
        `export_table` (CSV or JSON download of any table, formula guarded, IP addresses hashed, audited).

Why it exists
    DESIGN.md section 13 and plan 14.2, 15.2, 9.6, 9.7, 9.9 and 9.16 set one convention for some twenty API areas:
    the same query parameters, the same answer shapes, the same error object, the same guards. Writing them once
    keeps the areas consistent (the dashboard reads every table and chart the same way) and keeps the API modules
    thin: they parse, call a read model or a service, and shape the answer. The rules here are security rules too:
    a malformed body is a 400 and never `{}` (9.6), bodies refuse unknown fields (9.9), a CSV cell can never start a
    spreadsheet formula (9.16), every download leaves an audit row (9.7), and nothing a service refuses turns into
    a 500 with a stack trace or a secret in it.

How it works
    * `AdminApiRoute` wraps FastAPI's handler for its route. An `ApiError` (or any `HTTPException` carrying
      `error_code`, such as the guard's `ReauthRequired`) becomes `{"error": {"code", "message", "fields"}}` with
      its status and headers. A request validation error is checked against the guards first (an unauthenticated
      or cross-site caller gets the guard's answer, never a hint about the body), then becomes 400 when the body
      itself is missing, not JSON or not an object, and 422 with one message per field otherwise. The services'
      known refusals are mapped as a safety net. Every other `HTTPException` (the guards' 401, 403, 404, 503) is
      re-raised unchanged, so the app's handler answers it exactly as it answers every other admin path (the
      allowlist 404 stays byte for byte a missing path's 404). Every answer of the route carries
      `Cache-Control: no-store` (the security headers middleware does the same for all of `/admin`).
    * FastAPI caches a dependency once per request by its function, so the module-level guard instances
      (`admin_session`) run once even when a route and its `time_range` dependency both ask for them.
    * Time ranges: `range` (`live`, `1h`, `6h`, `24h`, `7d`, `30d`, `90d`, `1y`, `all`, `custom`), `from` and `to`
      (ISO 8601, a time without an offset read in `ui_timezone`, or epoch seconds) for `custom` only,
      `granularity` (`auto`, `minute`, `hour`, `day`, `week`, `month`) and `compare` (`none`, `previous`, `week`,
      `month`, `year`). A window that would need more than `queries.MAX_POINTS` buckets is refused up front.
    * Tables: `page` is 1-based, `page_size` one of 10, 25, 50, 100, 250, `sort` one of the table's sortable
      column keys, `order` `asc` or `desc`, `q` at most 200 characters. Missing values sort last in both orders.
    * Exports: at most `MAX_EXPORT_ROWS` rows, built on a worker thread; columns marked `ip=True` hold keyed hashes
      unless `export_include_ips` is on (`export_ip_policy`); the audit row (`export.download`) is written before
      the file is sent, and a failed audit write refuses the download (503) instead of sending an unaudited file.

What to read next
    `roxy/admin/api/__init__.py` (how area modules are mounted and checked), `roxy/metrics/queries.py` (the read
    models behind the charts and tables), `roxy/admin/auth/deps.py` (the guards), `roxy/core/errors.py`.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import re
import secrets
from collections.abc import Awaitable, Callable, Coroutine, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Final, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException
from starlette.responses import Response

from roxy.abuse.bypass import BypassNeedsConfirmation
from roxy.admin.auth.deps import SAFE_METHODS, AdminPrincipal, require_admin, require_csrf
from roxy.config import audit
from roxy.config.audit import Actor
from roxy.config.catalog import SettingValidationError
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.config.settings_service import HistoryNotFound, SettingsUpdateError
from roxy.core.errors import JSON_TYPE, admin_api_error_body
from roxy.core.iphash import derived_key, ip_hash
from roxy.core.redact import redact_text
from roxy.deps import get_ctx
from roxy.egress.credential import CredentialStateError, CredentialValueError
from roxy.egress.rotator import RotatorStateError
from roxy.metrics import queries
from roxy.metrics.catalog import METRICS
from roxy.metrics.queries import Window, bucket_starts, comparison_window, resolve_window
from roxy.metrics.rollups import zone
from roxy.rules.match import PatternValidationError
from roxy.rules.service import RuleCapReached, RuleConflict, RuleNotFound, RulesError, RuleValidationError
from roxy.storage.db import SharedStateUnavailable

API_PREFIX: Final = "/admin/api/v1"
"""Where the admin API lives (DESIGN.md section 13); `admin/api/__init__.py` mounts the areas under it."""

RESERVED_PREFIXES: Final[frozenset[str]] = frozenset({"/auth"})
"""Area prefixes owned elsewhere: `/admin/api/v1/auth/*` is the login surface (`admin/auth/routes.py`)."""

NO_STORE: Final = "no-store"
_DASHES: Final = (chr(0x2014), chr(0x2013))  # built at runtime so this file never holds the characters C5 bans
_CODE_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")
_AREA_RE: Final = re.compile(r"[a-z][a-z0-9_-]{0,39}")
_CONTROL_RE: Final = re.compile(r"[\x00-\x1f\x7f]")

MAX_MESSAGE_CHARS: Final = 500
MAX_FIELD_MESSAGE_CHARS: Final = 300
MAX_FIELD_NAME_CHARS: Final = 100
MAX_FIELDS: Final = 50
"""Bounds of one error object (plan P9): a body with a thousand bad fields still gets a small answer."""

MAX_BODY_STRING_CHARS: Final = 8192
"""Longest string any API body field may hold unless its model sets a tighter bound (plan 9.9)."""


# ================================================================================================= errors


class ApiError(HTTPException):
    """An admin API refusal in the DESIGN.md section 13 shape. Raise it (or a helper below) from a route.

    `error_code` is snake_case, `error_message` plain English for the admin, `error_fields` maps a field name to
    its own message. `detail` holds the message too, so a handler that only knows `HTTPException` still answers
    something sensible.
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        fields: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if not 400 <= status <= 599:
            raise ValueError(f"an API error status must be 4xx or 5xx, not {status}")
        if not _CODE_RE.fullmatch(code):
            raise ValueError(f"an API error code must be snake_case, not {code!r}")
        clean = clean_message(message, MAX_MESSAGE_CHARS)
        super().__init__(status_code=status, detail=clean, headers=dict(headers) if headers else None)
        self.error_code = code
        self.error_message = clean
        self.error_fields = clean_fields(fields)

    def body(self) -> bytes:
        return admin_api_error_body(self.error_code, self.error_message, self.error_fields)


def clean_message(text: Any, limit: int) -> str:
    """A message safe to send: secrets scrubbed, dash characters replaced (C5), control characters removed.

    The text is cut to a few times `limit` BEFORE it is scrubbed, so the work per message is bounded (an unknown
    body field may be named by a megabyte of text); a secret cut short of its 24 character window is not a leak.
    """
    value = redact_text(str(text)[: limit * 4])
    for dash in _DASHES:
        value = value.replace(dash, "-")
    return _CONTROL_RE.sub(" ", value).strip()[:limit]


def clean_fields(fields: Mapping[str, Any] | None) -> dict[str, str]:
    """At most `MAX_FIELDS` entries, each name and message bounded and cleaned."""
    out: dict[str, str] = {}
    for name, message in (fields or {}).items():
        if len(out) >= MAX_FIELDS:
            break
        key = clean_message(name, MAX_FIELD_NAME_CHARS) or "body"
        out.setdefault(key, clean_message(message, MAX_FIELD_MESSAGE_CHARS))
    return out


def bad_request(message: str, *, code: str = "bad_request", fields: Mapping[str, str] | None = None) -> ApiError:
    return ApiError(400, code, message, fields=fields)


def unauthorized(message: str = "Sign in first.", *, code: str = "unauthorized") -> ApiError:
    return ApiError(401, code, message)


def forbidden(message: str, *, code: str = "forbidden") -> ApiError:
    return ApiError(403, code, message)


def not_found(message: str = "Not found.", *, code: str = "not_found") -> ApiError:
    return ApiError(404, code, message)


def conflict(message: str, *, code: str = "conflict", fields: Mapping[str, str] | None = None) -> ApiError:
    return ApiError(409, code, message, fields=fields)


def validation_error(
    fields: Mapping[str, str], message: str = "Some fields are not valid.", *, code: str = "validation_failed"
) -> ApiError:
    return ApiError(422, code, message, fields=fields)


def rate_limited(message: str, retry_after_s: int, *, code: str = "rate_limited") -> ApiError:
    return ApiError(429, code, message, headers={"Retry-After": str(max(1, int(retry_after_s)))})


def unavailable(message: str, *, retry_after_s: int = 5, code: str = "unavailable") -> ApiError:
    """503: shared state cannot be read or written right now (plan C7). Not one of the section 13 statuses, but the
    honest answer; the body keeps the section 13 shape."""
    return ApiError(503, code, message, headers={"Retry-After": str(max(1, int(retry_after_s)))})


def section13_parts(exc: BaseException) -> tuple[str, str, dict[str, str]] | None:
    """`(code, message, fields)` when `exc` is an `HTTPException` carrying a section 13 error, else None."""
    if not isinstance(exc, HTTPException):
        return None
    code = getattr(exc, "error_code", None)
    if not isinstance(code, str) or not _CODE_RE.fullmatch(code):
        return None
    message = clean_message(getattr(exc, "error_message", exc.detail), MAX_MESSAGE_CHARS)
    return code, message, clean_fields(getattr(exc, "error_fields", None))


def error_response(
    status: int,
    code: str,
    message: str,
    fields: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
) -> Response:
    """The section 13 error answer: `{"error": {"code", "message", "fields"}}`, `application/json`, no-store."""
    body = admin_api_error_body(code, clean_message(message, MAX_MESSAGE_CHARS), clean_fields(fields))
    response = Response(content=body, status_code=status, media_type=JSON_TYPE, headers=dict(headers or {}))
    response.headers["Cache-Control"] = NO_STORE
    return response


def exception_response(exc: HTTPException) -> Response | None:
    """The section 13 answer for an exception that carries one (an `ApiError`, the guard's `ReauthRequired`)."""
    parts = section13_parts(exc)
    if parts is None:
        return None
    code, message, fields = parts
    return error_response(exc.status_code, code, message, fields, exc.headers)


# --- validation errors (400 for the body itself, 422 per field) -----------------------------------------------

_SOURCES: Final = frozenset({"body", "query", "path", "header", "cookie"})


def _field_name(loc: Sequence[Any]) -> str:
    parts = [str(part) for part in loc]
    if parts and parts[0] in _SOURCES:
        parts = parts[1:]
    return ".".join(parts) or "body"


def _field_message(error: Mapping[str, Any]) -> str:
    message = str(error.get("msg") or "Not valid.")
    if message.startswith("Value error, "):  # pydantic's prefix for a validator's own message
        message = message[len("Value error, ") :]
    return message


def validation_answer(errors: Sequence[Mapping[str, Any]]) -> ApiError:
    """FastAPI's request validation errors as a section 13 error (plan 9.6 and 9.9).

    The body as a whole is a 400: not JSON (`invalid_json`), absent (`missing_body`), or not an object
    (`invalid_body`, for example a list, a string, or form data). Never treated as `{}`. Anything else is one
    message per field (422 `validation_failed`): unknown fields, wrong types, values out of range, in the body or
    in the query string.
    """
    for error in errors:
        if error.get("type") == "json_invalid":
            return bad_request("The request body is not valid JSON.", code="invalid_json")
    for error in errors:
        loc = tuple(error.get("loc") or ())
        if loc == ("body",):
            if error.get("type") == "missing":
                return bad_request("This request needs a JSON object as its body.", code="missing_body")
            return bad_request("The request body must be a JSON object.", code="invalid_body")
    fields: dict[str, str] = {}
    for error in errors:
        fields.setdefault(_field_name(tuple(error.get("loc") or ())), _field_message(error))
    return validation_error(fields)


# --- service refusals --------------------------------------------------------------------------------------------

ErrorMap = Mapping[type[BaseException], tuple[int, str]]
"""Extra mappings for `service_error`: exception class -> (status, code); the exception's text is the message."""


def _rule_fields(exc: RuleValidationError) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in exc.errors:
        fields.setdefault(str(item.get("field") or "body"), str(item.get("message") or "Not valid."))
    return fields


def _settings_fields(exc: SettingsUpdateError) -> dict[str, str]:
    fields = dict(exc.errors)
    for issue in exc.cross:
        for key in issue.keys:
            fields.setdefault(key, issue.message)
    return fields


def service_error(exc: BaseException, extra: ErrorMap | None = None) -> ApiError | None:
    """The section 13 error for a refusal from a service, or None when `exc` is not one (a real bug stays a 500).

    Validation refusals are 422 with per-field messages, duplicates and wrong states 409, missing rows 404, and
    shared state that cannot be reached 503 with `Retry-After` (C7). The services write their messages for the
    admin; they are still scrubbed (`clean_message`) because a message may quote what the admin typed.
    """
    for kind, (status, code) in (extra or {}).items():
        if isinstance(exc, kind):
            return ApiError(status, code, str(exc) or "The request was refused.")
    if isinstance(exc, ApiError):
        return exc
    if isinstance(exc, SettingsUpdateError):
        return validation_error(
            _settings_fields(exc), "The change was refused; nothing was saved.", code="invalid_settings"
        )
    if isinstance(exc, SettingValidationError):
        return validation_error({exc.key: exc.message}, exc.message, code="invalid_setting")
    if isinstance(exc, HistoryNotFound):
        return not_found("No settings history entry has that id.")
    if isinstance(exc, RuleValidationError):
        return validation_error(_rule_fields(exc), "The rule was refused; nothing was saved.", code="invalid_rule")
    if isinstance(exc, RuleConflict):
        return conflict(exc.message)
    if isinstance(exc, RuleCapReached):
        return conflict(exc.message, code="cap_reached")
    if isinstance(exc, RuleNotFound):
        return not_found(exc.message)
    if isinstance(exc, RulesError):
        return validation_error({}, exc.message, code="invalid_rule")
    if isinstance(exc, PatternValidationError):
        return validation_error({"pattern": exc.message}, exc.message, code="invalid_pattern")
    if isinstance(exc, BypassNeedsConfirmation):
        return validation_error({"confirm": str(exc)}, str(exc), code="confirmation_required")
    if isinstance(exc, CredentialValueError):
        return validation_error({"value": str(exc)}, str(exc), code="invalid_credential")
    if isinstance(exc, CredentialStateError | RotatorStateError):
        return conflict(str(exc), code="wrong_state")
    if isinstance(exc, SharedStateUnavailable):
        return unavailable(f"The {exc.db_name} database is busy or unavailable right now; try again shortly.")
    return None


@contextmanager
def service_errors(extra: ErrorMap | None = None) -> Iterator[None]:
    """`with service_errors(): await service.update(...)`: a known refusal becomes its `ApiError` (see
    `service_error`); anything else propagates unchanged."""
    try:
        yield
    except Exception as exc:
        mapped = service_error(exc, extra)
        if mapped is None or mapped is exc:
            raise
        raise mapped from exc


async def run_mutation[T](call: Awaitable[T], *, extra: ErrorMap | None = None) -> T:
    """Await a service mutation (`settings_service.update`, `rules_service.create`, a purge, ...) and map its
    refusals to section 13 errors. The service writes its audit row and bumps `config_version` in the same
    transaction as the change; this helper only translates what it refuses."""
    with service_errors(extra):
        return await call


# ============================================================================================ guards and route


admin_session = require_admin("session")
"""The `session` guard instance shared by every API route (one instance, so FastAPI runs it once per request)."""

admin_fresh_mfa = require_admin("fresh_mfa")
"""The `fresh_mfa` guard for sensitive actions (plan 9.6): answers `ReauthRequired` when the factor is stale."""

_passive_session = require_admin("session", activity="never")
"""Used only to put the guard's answer before a body error; it never counts as activity."""

AdminSession = Annotated[AdminPrincipal, Depends(admin_session)]
AdminFreshMfa = Annotated[AdminPrincipal, Depends(admin_fresh_mfa)]
CsrfChecked = Annotated[None, Depends(require_csrf)]


async def _check_guards(request: Request) -> None:
    """Raise the guard's own answer (401, 403, 404, 503) for a caller who would not pass the route's guards."""
    await _passive_session(request)
    if request.method not in SAFE_METHODS:
        await require_csrf(request)


FASTAPI_BODY_ERROR: Final = "There was an error parsing the body"
"""The `detail` of the 400 FastAPI raises when it cannot read a body at all (before the route's guards run)."""


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = NO_STORE
    return response


class AdminApiRoute(APIRoute):
    """The route class of every admin API route: section 13 errors, guard-first body errors, no-store answers."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def api_handler(request: Request) -> Response:
            try:
                return _no_store(await handler(request))
            except RequestValidationError as exc:
                await _check_guards(request)
                return _no_store(_render(validation_answer(exc.errors())))
            except HTTPException as exc:
                answer = exception_response(exc)
                if answer is not None:
                    return answer
                if exc.status_code == 400 and exc.detail == FASTAPI_BODY_ERROR:  # unreadable body, no guard ran yet
                    await _check_guards(request)
                    return _render(bad_request("The request body could not be read.", code="invalid_body"))
                raise  # the guards' own answers: the app's handler sends them as for every admin path
            except Exception as exc:
                mapped = service_error(exc)
                if mapped is None:
                    raise
                return _render(mapped)

        return api_handler


def _render(error: ApiError) -> Response:
    return error_response(error.status_code, error.error_code, error.error_message, error.error_fields, error.headers)


def area_router(area: str, *, tags: Sequence[str] | None = None) -> APIRouter:
    """`router = area_router("settings")`: the router of one API module (prefix `/<area>`, `AdminApiRoute`)."""
    if not _AREA_RE.fullmatch(area):
        raise ValueError(f"an API area name is lowercase letters, digits, '_' or '-', not {area!r}")
    prefix = f"/{area}"
    if prefix in RESERVED_PREFIXES:
        raise ValueError(f"the API prefix {prefix!r} is reserved")
    return APIRouter(prefix=prefix, tags=list(tags or [area]), route_class=AdminApiRoute)


# ================================================================================================ who and what


def actor_for(principal: AdminPrincipal) -> Actor:
    """`Actor("admin", username, ip)` for the audit log and the services (DESIGN.md section 13)."""
    name = _CONTROL_RE.sub("", principal.username)[:64]
    ip = _CONTROL_RE.sub("", principal.ip)[:64] or None
    return Actor("admin", name, ip)


def request_id_of(request: Request) -> str | None:
    """This request's id (`Roxy-Request-Id`), for audit rows."""
    value = getattr(request.state, "request_id", None)
    return str(value) if value else None


class ApiBody(BaseModel):
    """Base of every request body (plan 9.9): unknown fields refused, every string bounded."""

    model_config = ConfigDict(extra="forbid", str_max_length=MAX_BODY_STRING_CHARS)


def require_reason(reason: str | None, *, required: bool, field: str = "reason") -> str:
    """The trimmed reason; a 422 on `field` when `required` (a high-risk change) and it is empty or too long."""
    text = (reason or "").strip()
    if len(text) > MAX_REASON_LENGTH:
        raise validation_error({field: f"A reason is at most {MAX_REASON_LENGTH} characters."})
    if required and not text:
        raise validation_error({field: "Give a reason for this change; it is high risk and goes in the audit log."})
    return text


# ================================================================================================ time ranges

RANGE_KEYS: Final[tuple[str, ...]] = (*queries.RANGES, "all", "custom")
GRANULARITY_KEYS: Final[tuple[str, ...]] = ("auto", "minute", "hour", "day", "week", "month")
COMPARE_KEYS: Final[tuple[str, ...]] = ("none", *queries.COMPARISONS)
DEFAULT_RANGE: Final = "24h"
MAX_TIME_TEXT: Final = 40
MAX_EPOCH_S: Final = 4_102_444_800
"""2100-01-01T00:00:00Z: the latest instant `from` or `to` may name."""

_EPOCH_RE: Final = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,6})?")

if not set(GRANULARITY_KEYS[1:]) <= set(queries.GRANULARITIES):  # pragma: no cover - import-time contract check
    raise RuntimeError("GRANULARITY_KEYS names a granularity metrics.queries does not know")


@dataclass(frozen=True, slots=True)
class RangeParams:
    """The raw time query parameters of a request (validated by `build_time_range`)."""

    range: str = DEFAULT_RANGE
    start: str | None = None  # `from`
    end: str | None = None  # `to`
    granularity: str = "auto"
    compare: str = "none"


@dataclass(frozen=True, slots=True)
class TimeRange:
    """A resolved time range: the window to read, and the window to compare with (None for `compare=none`)."""

    key: str
    window: Window
    compare: str | None = None
    compare_window: Window | None = None

    def info(self) -> dict[str, Any]:
        return range_info(self.window)


def parse_instant(text: str, *, tz: str) -> float:
    """Epoch seconds from ISO 8601 (an offset or `Z`; without one, the time is read in `tz`) or epoch seconds.

    Raises ValueError with a message for the admin. Bounded: at most `MAX_TIME_TEXT` characters, between 1970 and
    2100.
    """
    value = text.strip()
    if not value or len(value) > MAX_TIME_TEXT:
        raise ValueError(f"Use an ISO 8601 time or epoch seconds (at most {MAX_TIME_TEXT} characters).")
    if _EPOCH_RE.fullmatch(value):
        seconds = float(value)
    else:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            raise ValueError("Use an ISO 8601 time such as 2026-10-08T14:30:00Z, or epoch seconds.") from None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=zone(tz))
        seconds = parsed.timestamp()
    if not 0 <= seconds <= MAX_EPOCH_S:
        raise ValueError("Use a time between 1970 and 2100.")
    return seconds


def build_time_range(params: RangeParams, *, now: float, tz: str, earliest: float | None = None) -> TimeRange:
    """Validate the parameters and resolve them with `metrics.queries` (422 with per-field messages if invalid)."""
    fields: dict[str, str] = {}
    if params.range not in RANGE_KEYS:
        fields["range"] = f"Choose one of: {', '.join(RANGE_KEYS)}."
    if params.granularity not in GRANULARITY_KEYS:
        fields["granularity"] = f"Choose one of: {', '.join(GRANULARITY_KEYS)}."
    if params.compare not in COMPARE_KEYS:
        fields["compare"] = f"Choose one of: {', '.join(COMPARE_KEYS)}."
    start = end = None
    if params.range == "custom":
        for name, raw in (("from", params.start), ("to", params.end)):
            if raw is None or not raw.strip():
                fields[name] = "A custom range needs both from and to."
                continue
            try:
                value = parse_instant(raw, tz=tz)
            except ValueError as exc:
                fields[name] = str(exc)
                continue
            if name == "from":
                start = value
            else:
                end = value
        if start is not None and end is not None and end <= start:
            fields["to"] = "The end of the range must be after its start."
    else:
        for name, raw in (("from", params.start), ("to", params.end)):
            if raw is not None:
                fields[name] = "Only a custom range takes from and to; add range=custom."
    if fields:
        raise validation_error(fields, "The time range is not valid.", code="invalid_range")
    granularity = None if params.granularity == "auto" else params.granularity
    if earliest is not None:
        earliest = min(earliest, now - 60)  # data stamped ahead of this worker's clock still gives a real window
    try:
        window = resolve_window(
            None if params.range == "custom" else params.range,
            now=now,
            tz=tz,
            start=start,
            end=end,
            granularity=granularity,
            earliest=earliest,
        )
    except ValueError as exc:
        text = str(exc)
        message = f"{text[:1].upper()}{text[1:]}."
        raise validation_error({"range": message}, "The time range is not valid.", code="invalid_range") from None
    try:
        bucket_starts(window)  # refuses a window of more than queries.MAX_POINTS buckets
    except ValueError:
        message = f"This range has more than {queries.MAX_POINTS} points at that granularity; choose a coarser one."
        raise validation_error({"granularity": message}, "The time range is not valid.", code="invalid_range") from None
    compare = None if params.compare == "none" else params.compare
    other = comparison_window(window, compare) if compare else None
    return TimeRange(params.range, window, compare, other)


async def range_params(
    range_: Annotated[str, Query(alias="range", max_length=16)] = DEFAULT_RANGE,
    from_: Annotated[str | None, Query(alias="from", max_length=MAX_TIME_TEXT)] = None,
    to: Annotated[str | None, Query(max_length=MAX_TIME_TEXT)] = None,
    granularity: Annotated[str, Query(max_length=16)] = "auto",
    compare: Annotated[str, Query(max_length=16)] = "none",
) -> RangeParams:
    """The time query parameters (DESIGN.md section 13) as a dependency."""
    return RangeParams(range=range_, start=from_, end=to, granularity=granularity, compare=compare)


async def time_range(
    request: Request,
    _admin: AdminSession,
    params: Annotated[RangeParams, Depends(range_params)],
) -> TimeRange:
    """The resolved `TimeRange` of a request, in `ui_timezone` (the guard runs first; `all` reads the oldest data)."""
    ctx = get_ctx(request)
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    earliest = await ctx.dbs.metrics.read(queries.earliest_data) if params.range == "all" else None
    return build_time_range(params, now=ctx.clock.now(), tz=tz, earliest=earliest)


TimeRangeDep = Annotated[TimeRange, Depends(time_range)]


# ============================================================================================== chart answers


def range_info(window: Window) -> dict[str, Any]:
    """`{from, to, granularity, tz}` of a window (epoch seconds, `to` exclusive)."""
    return {"from": window.start, "to": window.end, "granularity": window.granularity, "tz": window.tz}


def series_entry(key: str, label: str, unit: str, points: Sequence[Sequence[Any]]) -> dict[str, Any]:
    """One chart line: `{key, label, unit, points: [[t, v], ...]}`."""
    return {"key": key, "label": label, "unit": unit, "points": [[point[0], point[1]] for point in points]}


def series_from_read_model(
    data: Mapping[str, Any],
    metric: str,
    *,
    label: str | None = None,
    unit: str | None = None,
) -> list[dict[str, Any]]:
    """Chart lines from a `queries.series` answer: one per group (just one, key `metric`, when ungrouped).

    Label and unit default to the metric catalog (`metrics/catalog.py`), so help and units have one source.
    """
    spec = METRICS.get(metric)
    base_label = label or (spec.label if spec else metric)
    base_unit = unit if unit is not None else (spec.unit if spec else "")
    buckets = list(data.get("buckets") or [])
    groups: Mapping[str, Mapping[str, Sequence[Any]]] = data.get("groups") or {}
    out: list[dict[str, Any]] = []
    for group, values in groups.items():
        points = list(zip(buckets, values.get(metric, []), strict=False))
        if group == "all" and len(groups) == 1:
            out.append(series_entry(metric, base_label, base_unit, points))
        else:
            out.append(series_entry(f"{metric}:{group}", f"{base_label}: {group}", base_unit, points))
    return out


def annotation_entries(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Chart markers (`queries.chart_annotations` rows) as `{at, kind, label, audit_id}`."""
    return [
        {
            "at": row.get("at"),
            "kind": row.get("kind", "reset"),
            "label": row.get("label"),
            "audit_id": row.get("audit_id"),
        }
        for row in rows
    ]


def reset_notices(rows: Sequence[Mapping[str, Any]], *, tz: str) -> list[str]:
    """Plan 6.8 partial data warnings for `queries.reset_annotations` rows inside the window."""
    notices: list[str] = []
    for row in rows:
        at = datetime.fromtimestamp(int(row.get("at") or 0), zone(tz)).strftime("%Y-%m-%d %H:%M %Z")
        label = clean_message(row.get("label") or "a reset", 200)
        until = row.get("until")
        if until is not None:
            end = datetime.fromtimestamp(int(until), zone(tz)).strftime("%Y-%m-%d %H:%M %Z")
            notices.append(f"Partial data: counters from {at} to {end} were reset ({label}).")
        else:
            notices.append(f"Partial data: counters were reset at {at} ({label}).")
    return notices


def series_answer(
    tr: TimeRange,
    series: Sequence[Mapping[str, Any]],
    *,
    compare_series: Sequence[Mapping[str, Any]] | None = None,
    annotations: Sequence[Mapping[str, Any]] = (),
    notices: Sequence[str] = (),
) -> dict[str, Any]:
    """The series answer: `{range, series, compare, annotations, notices}` (DESIGN.md section 13).

    `compare` is None without a comparison, else `{mode, range, series}`; its points keep their own times, and a
    chart overlays them bucket by bucket.
    """
    compare: dict[str, Any] | None = None
    if tr.compare and tr.compare_window is not None:
        compare = {"mode": tr.compare, "range": range_info(tr.compare_window), "series": list(compare_series or [])}
    return {
        "range": tr.info(),
        "series": list(series),
        "compare": compare,
        "annotations": list(annotations),
        "notices": [str(notice) for notice in notices],
    }


# ================================================================================================= KPI tiles

GoodDirection = Literal["up", "down", "neutral"]
_BETTER_TO_DIRECTION: Final[dict[str, GoodDirection]] = {"higher": "up", "lower": "down", "neutral": "neutral"}


def kpi_tile(
    key: str,
    *,
    label: str,
    value: Any,
    unit: str = "",
    delta: float | None = None,
    delta_pct: float | None = None,
    good_direction: GoodDirection = "neutral",
    sparkline: Sequence[Sequence[Any]] = (),
    help: str = "",
    notice: str | None = None,
) -> dict[str, Any]:
    """`{key, label, value, unit, delta, delta_pct, good_direction, sparkline, help, notice}` (section 13).

    This only shapes the tile: deltas come from the read model that computed the value (`queries.kpis`), so
    there is one definition of each number (P6).
    """
    return {
        "key": key,
        "label": label,
        "value": value,
        "unit": unit,
        "delta": delta,
        "delta_pct": delta_pct,
        "good_direction": good_direction,
        "sparkline": [[point[0], point[1]] for point in sparkline],
        "help": help,
        "notice": notice,
    }


def kpi_from_read_model(
    key: str,
    tile: Mapping[str, Any],
    *,
    sparkline: Sequence[Sequence[Any]] = (),
    notice: str | None = None,
    label: str | None = None,
    unit: str | None = None,
) -> dict[str, Any]:
    """A tile from one `queries.kpis` tile (`value`, and `delta`/`delta_pct` with a comparison); label, unit,
    help and good direction come from the metric catalog."""
    spec = METRICS.get(key)
    return kpi_tile(
        key,
        label=label or (spec.label if spec else key),
        value=tile.get("value"),
        unit=unit if unit is not None else (spec.unit if spec else ""),
        delta=tile.get("delta"),
        delta_pct=tile.get("delta_pct"),
        good_direction=_BETTER_TO_DIRECTION.get(spec.better if spec else "neutral", "neutral"),
        sparkline=sparkline,
        help=spec.description if spec else "",
        notice=notice,
    )


# ==================================================================================================== tables

PAGE_SIZES: Final[tuple[int, ...]] = queries.PAGE_SIZES
DEFAULT_PAGE_SIZE: Final = 25
MAX_PAGE: Final = 1_000_000
MAX_SEARCH_CHARS: Final = 200
Order = Literal["asc", "desc"]
_TABLE_NAME_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,47}")


@dataclass(frozen=True, slots=True)
class Column:
    """One table column: `key` in each item, a `label`, `help` text and a `unit` (`""` for plain text).

    `ip=True` marks a column of client IP addresses: an export replaces them with keyed hashes unless
    `export_include_ips` is on (see `export_ip_policy`). The dashboard's own answers show them as they are.
    """

    key: str
    label: str
    help: str = ""
    unit: str = ""
    sortable: bool = True
    ip: bool = False

    def info(self) -> dict[str, str]:
        return {"key": self.key, "label": self.label, "help": self.help, "unit": self.unit}


@dataclass(frozen=True, slots=True)
class TableSpec:
    """A table's columns and sorting allowlist. `name` names exports and their audit rows (`table:<name>`)."""

    name: str
    columns: tuple[Column, ...]
    default_sort: str
    default_order: Order = "desc"
    extra_sort_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _TABLE_NAME_RE.fullmatch(self.name):
            raise ValueError(f"a table name is lowercase snake_case, not {self.name!r}")
        keys = [column.key for column in self.columns]
        if len(set(keys)) != len(keys):
            raise ValueError(f"table {self.name}: column keys repeat")
        if self.default_sort not in self.sortable:
            raise ValueError(f"table {self.name}: default sort {self.default_sort!r} is not sortable")

    @property
    def sortable(self) -> frozenset[str]:
        return frozenset(c.key for c in self.columns if c.sortable) | frozenset(self.extra_sort_keys)

    def columns_info(self) -> list[dict[str, str]]:
        return [column.info() for column in self.columns]


@dataclass(frozen=True, slots=True)
class TableQuery:
    """Validated paging, sorting and search of one table request."""

    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE
    sort: str = ""
    order: Order = "desc"
    q: str = ""

    @property
    def descending(self) -> bool:
        return self.order == "desc"

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    def metrics_page(self) -> queries.Page:
        """The same request as a `metrics.queries.Page` (for `top_n`, `endpoint_table`, `client_table`)."""
        return queries.Page(
            page=self.page, size=self.page_size, sort=self.sort, descending=self.descending, search=self.q
        )


def check_table_query(
    spec: TableSpec, *, page: int, page_size: int, sort: str | None, order: str | None, q: str | None
) -> TableQuery:
    """Validate table parameters against `spec` (422 with per-field messages)."""
    fields: dict[str, str] = {}
    if not 1 <= page <= MAX_PAGE:
        fields["page"] = f"A page number is between 1 and {MAX_PAGE}."
    if page_size not in PAGE_SIZES:
        fields["page_size"] = f"Choose one of: {', '.join(str(size) for size in PAGE_SIZES)}."
    chosen_sort = sort or spec.default_sort
    if chosen_sort not in spec.sortable:
        fields["sort"] = f"This table sorts by: {', '.join(sorted(spec.sortable))}."
    chosen_order = order or spec.default_order
    if chosen_order not in ("asc", "desc"):
        fields["order"] = "Choose asc or desc."
    search = (q or "").strip()
    if len(search) > MAX_SEARCH_CHARS:
        fields["q"] = f"A search is at most {MAX_SEARCH_CHARS} characters."
    if fields:
        raise validation_error(fields, "The table request is not valid.", code="invalid_table_query")
    return TableQuery(page, page_size, chosen_sort, "asc" if chosen_order == "asc" else "desc", search)


def table_params(spec: TableSpec) -> Callable[..., Awaitable[TableQuery]]:
    """A dependency for one table: `tq: Annotated[TableQuery, Depends(table_params(SPEC))]`."""

    async def dependency(
        page: Annotated[int, Query()] = 1,
        page_size: Annotated[int, Query()] = DEFAULT_PAGE_SIZE,
        sort: Annotated[str | None, Query(max_length=64)] = None,
        order: Annotated[str | None, Query(max_length=8)] = None,
        q: Annotated[str | None, Query(max_length=MAX_SEARCH_CHARS)] = None,
    ) -> TableQuery:
        return check_table_query(spec, page=page, page_size=page_size, sort=sort, order=order, q=q)

    dependency.__name__ = f"table_params_{spec.name}"
    return dependency


def _sort_key(item: Mapping[str, Any], key: str) -> Any:
    value = item.get(key)
    if isinstance(value, bool):
        return (0, int(value))
    if isinstance(value, int | float):
        return (0, value)
    return (1, str(value).lower())


def page_rows(
    rows: Sequence[Mapping[str, Any]], tq: TableQuery, *, search_keys: Sequence[str] = ()
) -> tuple[list[Mapping[str, Any]], int]:
    """Search, sort and page an in-memory list (small tables: rules, sessions). Returns `(items, total)`.

    `q` matches case-insensitively in any of `search_keys` (every value of the row when none are given). Rows
    without a value for the sort key come last in both orders (as `metrics.queries` does); ties keep their
    original order. Read models that page in SQL return their own page instead (see `table_from_read_model`).
    """
    needle = tq.q.lower()

    def matches(row: Mapping[str, Any]) -> bool:
        keys = search_keys or tuple(row.keys())
        return any(needle in str(row.get(key, "")).lower() for key in keys)

    found = [row for row in rows if not needle or matches(row)]
    present = [r for r in found if r.get(tq.sort) is not None]
    missing = [r for r in found if r.get(tq.sort) is None]
    present.sort(key=lambda r: _sort_key(r, tq.sort), reverse=tq.descending)
    ordered = present + missing
    return ordered[tq.offset : tq.offset + tq.page_size], len(ordered)


def table_answer(spec: TableSpec, tq: TableQuery, items: Sequence[Any], total: int) -> dict[str, Any]:
    """`{items, total, page, page_size, sort, order, columns}` (DESIGN.md section 13)."""
    return {
        "items": list(items),
        "total": int(total),
        "page": tq.page,
        "page_size": tq.page_size,
        "sort": tq.sort,
        "order": tq.order,
        "columns": spec.columns_info(),
    }


def table_from_read_model(spec: TableSpec, tq: TableQuery, data: Mapping[str, Any]) -> dict[str, Any]:
    """The table answer for a `metrics.queries` page (`{total, rows, ...}` from `top_n`, `client_table`, ...)."""
    return table_answer(spec, tq, list(data.get("rows") or []), int(data.get("total") or 0))


async def collect_pages(
    fetch: Callable[[int, int], Awaitable[tuple[Sequence[Any], int]]],
    *,
    page_size: int = max(PAGE_SIZES),
    max_rows: int | None = None,
) -> tuple[list[Any], int]:
    """Read every page of a paged read model for an export: `fetch(page, page_size) -> (items, total)`.

    Stops at `max_rows` (default `MAX_EXPORT_ROWS`), at an empty page, or at the total. Returns `(rows, total)`.
    """
    limit = MAX_EXPORT_ROWS if max_rows is None else max_rows
    rows: list[Any] = []
    total = 0
    page = 1
    while len(rows) < limit:
        items, total = await fetch(page, page_size)
        if not items:
            break
        rows.extend(items)
        if len(rows) >= total:
            break
        page += 1
    return rows[:limit], max(total, len(rows))


# =================================================================================================== exports

ExportFormat = Literal["csv", "json"]
EXPORT_FORMATS: Final[tuple[str, ...]] = ("csv", "json")
MAX_EXPORT_ROWS: Final = 50_000
"""Most rows one download carries (plan P9: the 1 GB server builds the file in memory)."""

FORMULA_PREFIXES: Final = ("=", "+", "-", "@", "\t", "\r")
"""Characters that make a spreadsheet read a cell as a formula (plan 9.16, parity row 88, v1 `toCSVRow`)."""

CSV_TYPE: Final = "text/csv; charset=utf-8"
EXPORT_AUDIT_ACTION: Final = "export.download"


async def export_format(
    format_: Annotated[str | None, Query(alias="format", max_length=8)] = None,
) -> ExportFormat | None:
    """`format=csv` or `format=json` turns a table request into a download; absent means the normal answer."""
    if format_ is None:
        return None
    if format_ == "csv":
        return "csv"
    if format_ == "json":
        return "json"
    raise validation_error({"format": "Choose csv or json."}, "The export format is not valid.", code="invalid_format")


ExportFormatDep = Annotated[ExportFormat | None, Depends(export_format)]


def _cell_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Mapping | list | tuple):
        return json.dumps(jsonable_encoder(value), separators=(",", ":"), ensure_ascii=False)
    return str(value).replace("\x00", "")


def csv_safe(value: Any) -> str:
    """One CSV cell: text form of `value`, with a leading apostrophe when it starts with `=`, `+`, `-`, `@`, a tab
    or a carriage return, so a spreadsheet shows it as text instead of running it (every column, headers too)."""
    text = _cell_text(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def csv_bytes(columns: Sequence[Column], items: Sequence[Mapping[str, Any]]) -> bytes:
    """A CSV file: a header row of column labels, then one row per item; every cell quoted and formula guarded."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow([csv_safe(column.label) for column in columns])
    for item in items:
        writer.writerow([csv_safe(item.get(column.key)) for column in columns])
    return buffer.getvalue().encode("utf-8")


def export_filename(name: str, fmt: ExportFormat, at_ms: int) -> str:
    """`roxy_<table>_<epoch ms>.<csv|json>` (v1's export file names)."""
    safe = re.sub(r"[^a-z0-9_]", "_", name.lower())[:48] or "table"
    return f"roxy_{safe}_{int(at_ms)}.{fmt}"


@dataclass(frozen=True, slots=True)
class ExportFile:
    """A rendered export: bytes, media type, file name, row count and whether rows were cut at the cap."""

    content: bytes
    media_type: str
    filename: str
    rows: int
    truncated: bool


IpHasher = Callable[[str], str]
IpMode = Literal["raw", "hashed_stable", "hashed_one_time"]


def export_ip_policy(ctx: Any, export_id: str) -> tuple[IpHasher | None, IpMode]:
    """How an export shows client IP addresses (plan 9.15 and 12.3, settings `export_include_ips` and
    `export_stable_ip_hash`): raw when `export_include_ips` is on; otherwise a keyed hash (`core/iphash.py`) with
    Roxy's long-lived key when `export_stable_ip_hash` is on, else with a key derived for this one export, so two
    files cannot be matched against each other. Without the `ip_hash_key` credential every export gets a random
    one-time key (stable hashes need the credential)."""
    settings = ctx.settings
    if settings.bool("export_include_ips"):
        return None, "raw"
    key: bytes | None = getattr(ctx, "ip_hash_key", None)
    if key and settings.bool("export_stable_ip_hash"):
        stable = key
        return (lambda ip: ip_hash(ip, stable)), "hashed_stable"
    one_time = derived_key(key or secrets.token_bytes(32), f"export:{export_id}")
    return (lambda ip: ip_hash(ip, one_time)), "hashed_one_time"


def _private_items(
    columns: Sequence[Column], items: Sequence[Mapping[str, Any]], hasher: IpHasher | None
) -> list[Mapping[str, Any]]:
    """`items` with every non-empty value of an `ip` column hashed (unchanged when `hasher` is None)."""
    ip_keys = [column.key for column in columns if column.ip]
    if hasher is None or not ip_keys:
        return list(items)
    out: list[Mapping[str, Any]] = []
    for item in items:
        copy = dict(item)
        for key in ip_keys:
            value = copy.get(key)
            if isinstance(value, str) and value:
                copy[key] = hasher(value)
        out.append(copy)
    return out


def render_export(
    spec: TableSpec,
    items: Sequence[Mapping[str, Any]],
    fmt: ExportFormat,
    *,
    at_ms: int,
    total: int | None = None,
    max_rows: int = MAX_EXPORT_ROWS,
    ip_hasher: IpHasher | None = None,
) -> ExportFile:
    """Build the file (pure: no I/O). JSON carries `{table, exported_at, columns, items, total, truncated}`.

    Values of `ip` columns pass through `ip_hasher` when one is given (see `export_ip_policy`).
    """
    kept = _private_items(spec.columns, items[:max_rows], ip_hasher)
    truncated = len(items) > max_rows or (total is not None and total > len(kept))
    if fmt == "csv":
        content = csv_bytes(spec.columns, kept)
        media_type = CSV_TYPE
    else:
        payload = {
            "table": spec.name,
            "exported_at": int(at_ms) // 1000,
            "columns": spec.columns_info(),
            "items": [{column.key: item.get(column.key) for column in spec.columns} for item in kept],
            "total": len(items) if total is None else int(total),
            "truncated": truncated,
        }
        content = json.dumps(jsonable_encoder(payload), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        media_type = JSON_TYPE
    return ExportFile(content, media_type, export_filename(spec.name, fmt, at_ms), len(kept), truncated)


async def export_table(
    request: Request,
    principal: AdminPrincipal,
    spec: TableSpec,
    items: Sequence[Mapping[str, Any]],
    fmt: ExportFormat,
    *,
    total: int | None = None,
    tq: TableQuery | None = None,
    filters: Mapping[str, Any] | None = None,
    tr: TimeRange | None = None,
) -> Response:
    """The download answer for a table: the file, `Content-Disposition`, no-store, and an audit row (plan 9.7).

    The file is built on a worker thread (50,000 rows of CSV would hold the event loop for a noticeable time),
    with IP columns hashed per `export_ip_policy`. The audit row (`export.download`, target `table:<name>`, with
    the format, row count, IP mode, sort, search, filters and range) is written before the file leaves; if
    control.db cannot take it, the answer is 503 and no file.
    """
    ctx = get_ctx(request)
    at_ms = int(ctx.clock.now() * 1000)
    request_id = request_id_of(request)
    hasher, ip_mode = export_ip_policy(ctx, request_id or secrets.token_hex(8))
    file = await asyncio.to_thread(render_export, spec, items, fmt, at_ms=at_ms, total=total, ip_hasher=hasher)
    details: dict[str, Any] = {"format": fmt, "rows": file.rows, "truncated": file.truncated, "filename": file.filename}
    if any(column.ip for column in spec.columns):
        details["ip_addresses"] = ip_mode
    if tq is not None:
        details.update(sort=tq.sort, order=tq.order, q=tq.q)
    if filters:
        details["filters"] = dict(filters)
    if tr is not None:
        details["range"] = {"key": tr.key, **tr.info()}
    actor = actor_for(principal)
    target = f"table:{spec.name}"

    def write(conn: Any) -> int:
        return audit.record(conn, actor, EXPORT_AUDIT_ACTION, target, None, details, None, request_id, at=at_ms // 1000)

    with service_errors():
        await ctx.dbs.control.write(write)
    response = Response(content=file.content, media_type=file.media_type)
    response.headers["Content-Disposition"] = f'attachment; filename="{file.filename}"'
    response.headers["Roxy-Export-Rows"] = str(file.rows)
    response.headers["Roxy-Export-Truncated"] = "true" if file.truncated else "false"
    return _no_store(response)


__all__ = [
    "API_PREFIX",
    "COMPARE_KEYS",
    "CSV_TYPE",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_RANGE",
    "EXPORT_AUDIT_ACTION",
    "EXPORT_FORMATS",
    "FORMULA_PREFIXES",
    "GRANULARITY_KEYS",
    "MAX_EXPORT_ROWS",
    "MAX_SEARCH_CHARS",
    "PAGE_SIZES",
    "RANGE_KEYS",
    "RESERVED_PREFIXES",
    "AdminApiRoute",
    "AdminFreshMfa",
    "AdminSession",
    "ApiBody",
    "ApiError",
    "Column",
    "CsrfChecked",
    "ErrorMap",
    "ExportFile",
    "ExportFormat",
    "ExportFormatDep",
    "GoodDirection",
    "IpHasher",
    "IpMode",
    "Order",
    "RangeParams",
    "TableQuery",
    "TableSpec",
    "TimeRange",
    "TimeRangeDep",
    "actor_for",
    "admin_fresh_mfa",
    "admin_session",
    "annotation_entries",
    "area_router",
    "bad_request",
    "build_time_range",
    "check_table_query",
    "clean_fields",
    "clean_message",
    "collect_pages",
    "conflict",
    "csv_bytes",
    "csv_safe",
    "error_response",
    "exception_response",
    "export_filename",
    "export_format",
    "export_ip_policy",
    "export_table",
    "forbidden",
    "kpi_from_read_model",
    "kpi_tile",
    "not_found",
    "page_rows",
    "parse_instant",
    "range_info",
    "range_params",
    "rate_limited",
    "render_export",
    "request_id_of",
    "require_reason",
    "reset_notices",
    "run_mutation",
    "section13_parts",
    "series_answer",
    "series_entry",
    "series_from_read_model",
    "service_error",
    "service_errors",
    "table_answer",
    "table_from_read_model",
    "table_params",
    "time_range",
    "unauthorized",
    "unavailable",
    "validation_answer",
    "validation_error",
]
