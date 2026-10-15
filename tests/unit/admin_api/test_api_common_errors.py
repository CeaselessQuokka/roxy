"""The admin API error layer (DESIGN.md section 13): the error object, the helpers, validation answers, the
mapping of the services' refusals, the route class, and who acted."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.exceptions import HTTPException as FastApiHTTPException
from pydantic import ValidationError

from roxy.abuse.bypass import BypassNeedsConfirmation
from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminApiRoute,
    ApiBody,
    ApiError,
    actor_for,
    area_router,
    clean_fields,
    clean_message,
    exception_response,
    require_reason,
    run_mutation,
    section13_parts,
    service_error,
    service_errors,
    validation_answer,
)
from roxy.admin.auth.deps import REAUTH_CODE, REAUTH_MESSAGE, AdminPrincipal, ReauthRequired
from roxy.config.catalog import CrossIssue, SettingValidationError
from roxy.config.settings_service import HistoryNotFound, SettingsUpdateError
from roxy.core.redact import TOKEN_PREFIX
from roxy.egress.credential import CredentialStateError, CredentialValueError
from roxy.egress.rotator import RotatorStateError
from roxy.rules.match import PatternValidationError
from roxy.rules.service import RuleCapReached, RuleConflict, RuleNotFound, RulesError, RuleValidationError
from roxy.storage.db import SharedStateUnavailable

EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)


def parts(error: ApiError) -> tuple[int, str, dict[str, str]]:
    return error.status_code, error.error_code, error.error_fields


# ============================================================================================ error object


def test_api_error_body_is_the_section13_object() -> None:
    error = ApiError(409, "conflict", "That rule already exists.", fields={"pattern": "Already used."})
    assert json.loads(error.body()) == {
        "error": {"code": "conflict", "message": "That rule already exists.", "fields": {"pattern": "Already used."}}
    }
    assert error.detail == "That rule already exists."
    assert error.status_code == 409
    empty = ApiError(404, "not_found", "Not found.")
    assert empty.body() == b'{"error":{"code":"not_found","message":"Not found.","fields":{}}}'


@pytest.mark.parametrize("status", [200, 302, 399, 600])
def test_api_error_status_must_be_an_error(status: int) -> None:
    with pytest.raises(ValueError):
        ApiError(status, "bad_request", "x")


@pytest.mark.parametrize("code", ["BadRequest", "bad-request", "", "1code", "a" * 65, "bad request"])
def test_api_error_code_must_be_snake_case(code: str) -> None:
    with pytest.raises(ValueError):
        ApiError(400, code, "x")


def test_messages_never_carry_secrets_dashes_or_control_characters() -> None:
    secret = TOKEN_PREFIX + "FAKE" + "AB12" * 40
    message = clean_message(f"refused {secret} here{EM_DASH}there{EN_DASH}x\nnext\x00", 500)
    assert "AB12AB12" not in message
    assert EM_DASH not in message
    assert EN_DASH not in message
    assert "\n" not in message
    assert "\x00" not in message
    assert len(clean_message("y" * 5000, 300)) == 300
    error = ApiError(422, "validation_failed", f"bad {secret}", fields={"value": f"saw {secret}"})
    assert "AB12AB12" not in error.body().decode()


def test_fields_are_bounded() -> None:
    fields = clean_fields({f"field{n}": "x" * 1000 for n in range(80)})
    assert len(fields) == common.MAX_FIELDS
    assert all(len(message) <= common.MAX_FIELD_MESSAGE_CHARS for message in fields.values())
    long_name = clean_fields({"n" * 1000: "x"})
    assert [len(name) for name in long_name] == [common.MAX_FIELD_NAME_CHARS]
    assert clean_fields(None) == {}


def test_helpers_have_their_status_and_code() -> None:
    assert parts(common.bad_request("x")) == (400, "bad_request", {})
    assert parts(common.unauthorized()) == (401, "unauthorized", {})
    assert parts(common.forbidden("x")) == (403, "forbidden", {})
    assert parts(common.not_found()) == (404, "not_found", {})
    assert parts(common.conflict("x", fields={"name": "taken"})) == (409, "conflict", {"name": "taken"})
    assert parts(common.validation_error({"a": "b"})) == (422, "validation_failed", {"a": "b"})
    limited = common.rate_limited("slow down", 0)
    assert parts(limited) == (429, "rate_limited", {})
    assert limited.headers == {"Retry-After": "1"}
    down = common.unavailable("later")
    assert parts(down) == (503, "unavailable", {})
    assert down.headers == {"Retry-After": "5"}


def test_section13_parts_reads_api_errors_and_the_reauth_guard() -> None:
    assert section13_parts(common.conflict("dup")) == ("conflict", "dup", {})
    assert section13_parts(ReauthRequired()) == (REAUTH_CODE, REAUTH_MESSAGE, {})
    assert section13_parts(FastApiHTTPException(403, "Forbidden")) is None
    assert section13_parts(ValueError("x")) is None


def test_reauth_answer_has_the_header_and_the_code() -> None:
    response = exception_response(ReauthRequired())
    assert response is not None
    assert response.status_code == 403
    assert response.headers["roxy-reauth"] == "required"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"] == "application/json"
    body = json.loads(bytes(response.body))
    assert body["error"]["code"] == "reauth_required"
    assert body["error"]["fields"] == {}
    assert exception_response(FastApiHTTPException(401, "Session expired")) is None


# ======================================================================================== validation errors


def test_unreadable_bodies_are_400() -> None:
    invalid = validation_answer([{"type": "json_invalid", "loc": ("body", 7), "msg": "JSON decode error"}])
    assert parts(invalid) == (400, "invalid_json", {})
    missing = validation_answer([{"type": "missing", "loc": ("body",), "msg": "Field required"}])
    assert parts(missing) == (400, "missing_body", {})
    not_object = validation_answer([{"type": "model_attributes_type", "loc": ("body",), "msg": "Input should be"}])
    assert parts(not_object) == (400, "invalid_body", {})


def test_field_errors_are_422_one_message_per_field() -> None:
    errors: list[dict[str, Any]] = [
        {"type": "extra_forbidden", "loc": ("body", "extra"), "msg": "Extra inputs are not permitted"},
        {"type": "int_parsing", "loc": ("query", "page_size"), "msg": "Input should be a valid integer"},
        {"type": "value_error", "loc": ("body", "items", 0, "name"), "msg": "Value error, Use letters only."},
        {"type": "string_too_long", "loc": ("body", "items", 0, "name"), "msg": "a second message"},
        {"type": "missing", "loc": ("body", "reason"), "msg": "Field required"},
    ]
    error = validation_answer(errors)
    assert error.status_code == 422
    assert error.error_code == "validation_failed"
    assert error.error_fields == {
        "extra": "Extra inputs are not permitted",
        "page_size": "Input should be a valid integer",
        "items.0.name": "Use letters only.",
        "reason": "Field required",
    }


# ========================================================================================= service refusals


@pytest.mark.parametrize(
    ("exc", "status", "code", "fields"),
    [
        (
            SettingValidationError("cache_ttl_seconds", "Enter a duration"),
            422,
            "invalid_setting",
            {"cache_ttl_seconds"},
        ),
        (HistoryNotFound(5), 404, "not_found", set()),
        (
            RuleValidationError("bans", [{"field": "subject", "message": "Enter an IP"}]),
            422,
            "invalid_rule",
            {"subject"},
        ),
        (RuleConflict("access_list", "That CIDR is already listed."), 409, "conflict", set()),
        (RuleCapReached("bans", "The table is full.", 10), 409, "cap_reached", set()),
        (RuleNotFound("bans", "No such ban."), 404, "not_found", set()),
        (RulesError("bans", "Refused."), 422, "invalid_rule", set()),
        (PatternValidationError("Too many wildcards."), 422, "invalid_pattern", {"pattern"}),
        (
            BypassNeedsConfirmation("A bypass that never expires needs confirmation"),
            422,
            "confirmation_required",
            {"confirm"},
        ),
        (
            CredentialValueError("the value has characters a cookie value cannot hold"),
            422,
            "invalid_credential",
            {"value"},
        ),
        (CredentialStateError("there is no UI-set credential to delete"), 409, "wrong_state", set()),
        (RotatorStateError("there is no UI-set rotator URL to remove"), 409, "wrong_state", set()),
    ],
)
def test_known_service_refusals_are_mapped(exc: BaseException, status: int, code: str, fields: set[str]) -> None:
    mapped = service_error(exc)
    assert mapped is not None
    assert (mapped.status_code, mapped.error_code, set(mapped.error_fields)) == (status, code, fields)


def test_settings_refusal_lists_every_key_including_cross_rules() -> None:
    issue = CrossIssue(("tarpit_min_seconds", "tarpit_max_seconds"), "The minimum must not exceed the maximum.", "r1")
    mapped = service_error(SettingsUpdateError({"cache_ttl_seconds": "Enter a duration"}, [issue]))
    assert mapped is not None
    assert parts(mapped) == (
        422,
        "invalid_settings",
        {
            "cache_ttl_seconds": "Enter a duration",
            "tarpit_min_seconds": "The minimum must not exceed the maximum.",
            "tarpit_max_seconds": "The minimum must not exceed the maximum.",
        },
    )


def test_shared_state_unavailable_is_503_without_the_cause() -> None:
    mapped = service_error(SharedStateUnavailable("hot", "database is locked at /secret/path"))
    assert mapped is not None
    assert parts(mapped) == (503, "unavailable", {})
    assert mapped.headers == {"Retry-After": "5"}
    assert "hot" in mapped.error_message
    assert "/secret/path" not in mapped.error_message


def test_unknown_exceptions_are_not_mapped_and_extra_rules_come_first() -> None:
    assert service_error(ValueError("bug")) is None
    assert service_error(KeyError("bug")) is None
    mapped = service_error(ValueError("Reasons cannot contain dashes."), {ValueError: (422, "invalid_reason")})
    assert mapped is not None
    assert parts(mapped) == (422, "invalid_reason", {})
    assert mapped.error_message == "Reasons cannot contain dashes."
    same = common.conflict("x")
    assert service_error(same) is same


def test_service_errors_context_maps_or_reraises() -> None:
    with pytest.raises(ApiError) as caught, service_errors():
        raise RuleConflict("bans", "duplicate")
    assert caught.value.status_code == 409
    assert isinstance(caught.value.__cause__, RuleConflict)
    with pytest.raises(KeyError), service_errors():
        raise KeyError("a real bug stays a 500")


async def test_run_mutation_returns_the_result_or_the_mapped_error() -> None:
    async def ok() -> int:
        return 7

    async def refused() -> int:
        raise RuleNotFound("bans", "No such ban.")

    assert await run_mutation(ok()) == 7
    with pytest.raises(ApiError) as caught:
        await run_mutation(refused())
    assert caught.value.status_code == 404


# ==================================================================================================== route


def _bare_app() -> FastAPI:
    app = FastAPI()
    router = area_router("unit")

    @router.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    @router.get("/refused")
    async def refused() -> dict[str, bool]:
        raise common.conflict("Already there.", fields={"name": "taken"})

    @router.get("/service")
    async def service() -> dict[str, bool]:
        raise RuleConflict("bans", "duplicate ban")

    @router.get("/plain")
    async def plain() -> dict[str, bool]:
        raise FastApiHTTPException(418, "teapot")

    @router.get("/plain-400")
    async def plain_400() -> dict[str, bool]:
        raise FastApiHTTPException(400, "route's own text")

    @router.get("/bug")
    async def bug() -> dict[str, bool]:
        raise KeyError("bug")

    app.include_router(router)
    return app


async def test_route_class_shapes_errors_and_marks_answers_no_store() -> None:
    transport = httpx.ASGITransport(app=_bare_app(), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        ok = await client.get("/unit/ok")
        assert ok.status_code == 200
        assert ok.headers["cache-control"] == "no-store"
        refused = await client.get("/unit/refused")
        assert refused.status_code == 409
        assert refused.json() == {
            "error": {"code": "conflict", "message": "Already there.", "fields": {"name": "taken"}}
        }
        assert refused.headers["cache-control"] == "no-store"
        service = await client.get("/unit/service")
        assert service.status_code == 409
        assert service.json()["error"]["message"] == "duplicate ban"
        plain = await client.get("/unit/plain")
        assert plain.status_code == 418
        assert plain.json() == {"detail": "teapot"}  # other HTTPExceptions go to the app's own handler
        plain_400 = await client.get("/unit/plain-400")
        assert plain_400.json() == {"detail": "route's own text"}  # only FastAPI's body parse 400 is reshaped
        assert (await client.get("/unit/bug")).status_code == 500


def test_area_router_builds_on_the_api_route_class() -> None:
    router = area_router("upstream_limits")
    assert router.prefix == "/upstream_limits"
    assert router.tags == ["upstream_limits"]
    assert router.route_class is AdminApiRoute
    for bad in ("", "Settings", "a b", "x" * 41, "/settings"):
        with pytest.raises(ValueError):
            area_router(bad)
    with pytest.raises(ValueError):
        area_router("auth")  # the login surface owns /admin/api/v1/auth


# ============================================================================================= who and what


def test_actor_for_principal() -> None:
    principal = AdminPrincipal(1, "owner\x07", "hash", "totp", 0, "203.0.113.9", "ua")
    actor = actor_for(principal)
    assert (actor.kind, actor.name, actor.ip) == ("admin", "owner", "203.0.113.9")
    assert actor.label == "admin:owner"
    no_ip = actor_for(AdminPrincipal(1, "o" * 100, "hash", "totp", 0, "", "ua"))
    assert len(no_ip.name) == 64
    assert no_ip.ip is None


def test_require_reason() -> None:
    assert require_reason("  because  ", required=True) == "because"
    assert require_reason(None, required=False) == ""
    with pytest.raises(ApiError) as missing:
        require_reason("   ", required=True)
    assert parts(missing.value) == (422, "validation_failed", {"reason": missing.value.error_fields["reason"]})
    with pytest.raises(ApiError) as long:
        require_reason("x" * (common.MAX_REASON_LENGTH + 1), required=False, field="why")
    assert set(long.value.error_fields) == {"why"}


def test_api_body_refuses_unknown_fields_and_huge_strings() -> None:
    class Body(ApiBody):
        name: str

    assert Body.model_validate({"name": "x"}).name == "x"
    with pytest.raises(ValidationError):
        Body.model_validate({"name": "x", "extra": 1})
    with pytest.raises(ValidationError):
        Body.model_validate({"name": "x" * (common.MAX_BODY_STRING_CHARS + 1)})
