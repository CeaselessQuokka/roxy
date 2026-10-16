"""The endpoint policy check in the pipeline: refusals, shadow mode, overrides, counters and sign-in attempts."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from abuse_support import ADMIN, CLIENT_IP, FakeReq

from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.verdict import Allow, Refuse
from roxy.core.reasons import ReasonCode
from roxy.core.redact import TOKEN_PREFIX
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot

LOGOUT = FakeReq(method="POST", host="auth.roblox.com", path="/v1/logout", template="auth.roblox.com/v1/logout")
SECRET = "A" * 120  # stands in for the private part of a cookie; never a real value


class Recorder:
    """Keeps the pipeline's counter events and sign-in attempts (the other recorder hooks are absent)."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.attempts: list[tuple[str, Any, dict[str, Any]]] = []

    def record_event(self, kind: str, _severity: str, _reason: Any, detail: dict[str, Any], **_kw: Any) -> None:
        self.events.append((kind, detail))

    def record_auth_attempt(self, ip: str, attempt: Any, **kwargs: Any) -> None:
        self.attempts.append((ip, attempt, kwargs))

    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.events]


def req_for(method: str, host: str, path: str, **kw: Any) -> FakeReq:
    return FakeReq(method=method, host=host, path=path, template=f"{host}{path}", **kw)


async def test_a_blocked_endpoint_is_refused_before_roblox(make_pipeline: Callable[..., AbusePipeline]) -> None:
    recorder = Recorder()
    verdict = await make_pipeline(recorder=recorder).evaluate(req_for("POST", "auth.roblox.com", "/v1/logout"))
    assert isinstance(verdict, Refuse)
    assert verdict.status == 403
    assert verdict.reason is ReasonCode.ENDPOINT_POLICY
    assert verdict.headers["Roxy-Blocked"] == "policy"
    assert verdict.headers["Roxy-Refusal"] == "endpoint_policy"
    assert "signed-in account" in verdict.body
    assert verdict.tarpit_category is None
    assert verdict.detail.startswith("auth:POST:/v1/logout (seed, login-session-security)")
    assert ("policy_blocked", {"endpoint_id": "auth:POST:/v1/logout", "verdict": "BLOCK"}) in recorder.events


async def test_status_and_message_are_settings(make_pipeline: Callable[..., AbusePipeline]) -> None:
    pipeline = make_pipeline(
        {"endpoint_policy_block_status": "500", "endpoint_policy_block_message": "No account endpoints."}
    )
    verdict = await pipeline.evaluate(req_for("GET", "users.roblox.com", "/v1/users/authenticated"))
    assert isinstance(verdict, Refuse)
    assert verdict.status == 500
    assert verdict.body == "No account endpoints."


async def test_public_reads_pass(make_pipeline: Callable[..., AbusePipeline]) -> None:
    recorder = Recorder()
    verdict = await make_pipeline(recorder=recorder).evaluate(req_for("GET", "users.roblox.com", "/v1/users/1"))
    assert isinstance(verdict, Allow)
    assert "policy_blocked" not in recorder.kinds()
    assert "policy_unknown" not in recorder.kinds()


async def test_shadow_mode_lets_it_through_and_counts_it(make_pipeline: Callable[..., AbusePipeline]) -> None:
    recorder = Recorder()
    pipeline = make_pipeline({"endpoint_policy_enforce": 0}, recorder=recorder)
    verdict = await pipeline.evaluate(req_for("POST", "auth.roblox.com", "/v1/logout"))
    assert isinstance(verdict, Allow)
    assert ("policy_would_block", {"endpoint_id": "auth:POST:/v1/logout", "verdict": "BLOCK"}) in recorder.events


async def test_unknown_endpoints_are_counted(make_pipeline: Callable[..., AbusePipeline]) -> None:
    recorder = Recorder()
    pipeline = make_pipeline(recorder=recorder)
    verdict = await pipeline.evaluate(req_for("GET", "users.roblox.com", "/v9/brand-new/5"))
    assert isinstance(verdict, Allow)
    kinds = recorder.kinds()
    assert "policy_unknown" in kinds
    write = await pipeline.evaluate(req_for("POST", "users.roblox.com", "/v9/brand-new"))
    assert isinstance(write, Refuse)
    assert write.reason is ReasonCode.ENDPOINT_POLICY


async def test_an_override_opens_a_blocked_endpoint(
    make_pipeline: Callable[..., AbusePipeline],
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
) -> None:
    row = {"endpoint_id": "users:GET:/v1/users/authenticated", "verdict": "ALLOW_ANON"}
    await rules_service.upsert("endpoint_policy_override", row, ADMIN, "test")
    verdict = await make_pipeline(rules=snapshot_of()).evaluate(
        req_for("GET", "users.roblox.com", "/v1/users/authenticated")
    )
    assert isinstance(verdict, Allow)


async def test_a_caller_sign_in_is_refused_and_recorded_without_its_value(
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    recorder = Recorder()
    cookie = TOKEN_PREFIX + SECRET
    req = req_for("GET", "users.roblox.com", "/v1/users/1").with_headers(
        [("User-Agent", "Roblox/Linux"), ("Cookie", f".ROBLOSECURITY={cookie}")]
    )
    verdict = await make_pipeline(recorder=recorder).evaluate(req)
    assert isinstance(verdict, Refuse)
    assert verdict.reason is ReasonCode.AUTH_SMUGGLING
    assert len(recorder.attempts) == 1
    ip, attempt, kwargs = recorder.attempts[0]
    assert ip == CLIENT_IP
    assert attempt.kind == "roblosecurity"
    assert attempt.where == "cookie"
    assert attempt.looks_real
    assert kwargs["endpoint_id"] == "users:GET:/v1/users/{userId}"
    assert SECRET not in repr(attempt)  # the value is kept for the fingerprint only, never shown


async def test_api_keys_and_bearer_tokens_are_refused(make_pipeline: Callable[..., AbusePipeline]) -> None:
    for name, value in (("Authorization", "Bearer abc"), ("X-Api-Key", "k"), ("Proxy-Authorization", "Basic x")):
        recorder = Recorder()
        req = req_for("GET", "users.roblox.com", "/v1/users/1").with_headers([("User-Agent", "Roblox"), (name, value)])
        verdict = await make_pipeline(recorder=recorder).evaluate(req)
        assert isinstance(verdict, Refuse), name
        assert verdict.reason is ReasonCode.AUTH_SMUGGLING
        assert verdict.status == 400
        kind = recorder.attempts[0][1].kind
        assert kind == ("bearer" if value.startswith("Bearer") else "api_key")


async def test_logout_constant_is_blocked(make_pipeline: Callable[..., AbusePipeline]) -> None:
    verdict = await make_pipeline().evaluate(LOGOUT)
    assert isinstance(verdict, Refuse)
    assert verdict.reason is ReasonCode.ENDPOINT_POLICY
