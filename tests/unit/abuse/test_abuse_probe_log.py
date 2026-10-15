"""Proxy probes reach the Security probe log (finding parity-2; v1 `log_exploit_attempt`, parity rows 51 and 80).

What this is
    Unit tests for `AbusePipeline._probe` and `probe_log_reason`: a refusal by the unsafe URL, not Roblox, host
    allowlist or auth smuggling check hands one probe to the metrics recorder with v1's text, Roxy's own words as the
    signature (the probed URL quoted, so `metrics/security_events.py` moves it to the target column), and nothing
    else (an allowed request, a refusal by an earlier check, any other refusal) does.

Why it exists
    v1 logged every probe through the proxy route in its exploit log; v2 fed those refusals only to the spam and bot
    detectors, so `GET /admin/api/v1/security/probes` stayed empty for a scanner. Caller text never becomes a
    signature: that would give every scanner request its own summary row and event budget (v1 bug B19).

How it works
    The pipeline runs over temporary databases (`make_pipeline`) with a recorder that keeps the `record_probe` calls.

What to read next
    `roxy/abuse/pipeline.py` (`_record`, `_probe`), `roxy/metrics/security_events.py` (`probe_signature`),
    `tests/parity/test_v1_public.py::test_v1_proxy_probes_reach_the_probe_log` (the same through the real app).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from abuse_support import CLIENT_IP, FakeReq

from roxy.abuse.messages import (
    REASON_AUTH_BODY,
    REASON_AUTH_COOKIE_NAME,
    REASON_AUTH_QUERY,
    REASON_AUTH_TOKEN_HEADER,
)
from roxy.abuse.pipeline import PROBE_TEXT_CHARS, AbusePipeline, probe_log_reason
from roxy.abuse.verdict import Allow, Refuse
from roxy.core.reasons import ReasonCode
from roxy.core.redact import TOKEN_PREFIX
from roxy.metrics.security_events import probe_signature


class ProbeRecorder:
    """Keeps every `record_probe(ip, reason, user_agent, path)` call (the other recorder hooks are absent)."""

    def __init__(self) -> None:
        self.probes: list[tuple[str, str, str | None, str | None]] = []

    def record_probe(self, ip: str, reason: str, user_agent: str | None = None, path: str | None = None) -> None:
        self.probes.append((ip, reason, user_agent, path))


def _refusal(reason: ReasonCode, detail: str = "") -> Refuse:
    return Refuse(status=404, body="x", reason=reason, check="c", detail=detail)


def test_probe_reasons_are_v1_texts_with_roxys_own_signatures() -> None:
    assert probe_log_reason(_refusal(ReasonCode.UNSAFE_URL), "a<b") == 'Invalid URL: "a<b"'
    assert probe_log_reason(_refusal(ReasonCode.NOT_ROBLOX), "wp-login.php") == 'Non-Roblox URL: "wp-login.php"'
    assert probe_log_reason(_refusal(ReasonCode.HOST_NOT_ALLOWED), "x.roblox.com/v1") == "Host not allowed"
    for where in (REASON_AUTH_TOKEN_HEADER, REASON_AUTH_COOKIE_NAME, REASON_AUTH_QUERY, REASON_AUTH_BODY):
        assert (
            probe_log_reason(_refusal(ReasonCode.AUTH_SMUGGLING, where), "") == f"Sent a ROBLOSECURITY token ({where})"
        )
    # A header name is caller text: the probe log says only that a header carried the marker.
    header = probe_log_reason(_refusal(ReasonCode.AUTH_SMUGGLING, '"X-Anything-Goes" header carried a ...'), "")
    assert header == "Sent a ROBLOSECURITY token (a header carried a ROBLOSECURITY-shaped value)"
    for other in (ReasonCode.THROTTLE, ReasonCode.BANNED, ReasonCode.ENDPOINT_BLOCKED, ReasonCode.HEADER_RULE):
        assert probe_log_reason(_refusal(other), "games.roblox.com/v1") is None
    # The signatures the Security page groups by are fixed words; the probed URL goes to the target column.
    assert probe_signature('Non-Roblox URL: "any/thing"') == ("Non-Roblox URL", "any/thing")
    assert probe_signature('Invalid URL: "a"b"') == ("Invalid URL", 'a"b')


@pytest.mark.parametrize(
    ("problem", "raw", "reason"),
    [
        (ReasonCode.NOT_ROBLOX, "this-is-not-roblox", 'Non-Roblox URL: "this-is-not-roblox"'),
        (ReasonCode.UNSAFE_URL, "games.roblox.com/<script>", 'Invalid URL: "games.roblox.com/<script>"'),
        (ReasonCode.HOST_NOT_ALLOWED, "other.roblox.com/v1/x", "Host not allowed"),
    ],
)
async def test_a_url_probe_refusal_reaches_the_probe_log(
    make_pipeline: Callable[..., AbusePipeline], problem: ReasonCode, raw: str, reason: str
) -> None:
    recorder = ProbeRecorder()
    pipeline = make_pipeline(recorder=recorder)
    verdict = await pipeline.evaluate(FakeReq(target_problem=problem, raw_path="/" + raw))
    assert isinstance(verdict, Refuse)
    assert verdict.reason is problem
    assert recorder.probes == [(CLIENT_IP, reason, "Roblox/Linux", "/" + raw)]


async def test_auth_smuggling_reaches_the_probe_log_without_the_header_name(
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    recorder = ProbeRecorder()
    pipeline = make_pipeline(recorder=recorder)
    req = FakeReq().with_headers([("User-Agent", "Roblox/Linux"), ("X-Custom-Auth", TOKEN_PREFIX + "SECRET")])
    verdict = await pipeline.evaluate(req)
    assert isinstance(verdict, Refuse)
    assert verdict.reason is ReasonCode.AUTH_SMUGGLING
    [(ip, reason, _ua, path)] = recorder.probes
    assert ip == CLIENT_IP
    assert reason == "Sent a ROBLOSECURITY token (a header carried a ROBLOSECURITY-shaped value)"
    assert "X-Custom-Auth" not in reason
    assert "SECRET" not in reason
    assert path == "/games.roblox.com/v1/games"
    token = FakeReq(query=[("x", "1")]).with_headers([("User-Agent", "Roblox/Linux"), ("X-Roblox-Token", "a")])
    await pipeline.evaluate(token)
    assert recorder.probes[-1][1] == "Sent a ROBLOSECURITY token (X-Roblox-Token header)"


async def test_only_the_refusing_probe_check_logs_and_long_urls_are_cut(
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    """An allowed request logs nothing; a probe refused first by an earlier check (here the flood limit) is that
    check's refusal, not a probe (v1's order); the probed URL handed over is at most `PROBE_TEXT_CHARS` long."""
    recorder = ProbeRecorder()
    pipeline = make_pipeline({"flood_limit_per_minute": 2}, recorder=recorder)
    assert isinstance(await pipeline.evaluate(FakeReq()), Allow)
    assert recorder.probes == []
    long_raw = "x" * 5000
    verdict = await pipeline.evaluate(FakeReq(target_problem=ReasonCode.NOT_ROBLOX, raw_path="/" + long_raw))
    assert isinstance(verdict, Refuse)
    assert verdict.reason is ReasonCode.NOT_ROBLOX
    [(_ip, reason, _ua, path)] = recorder.probes
    assert reason == f'Non-Roblox URL: "{"x" * PROBE_TEXT_CHARS}"'
    assert path is not None
    assert len(path) == PROBE_TEXT_CHARS
    flooded = await pipeline.evaluate(FakeReq(target_problem=ReasonCode.NOT_ROBLOX, raw_path="/again"))
    assert isinstance(flooded, Refuse)
    assert flooded.reason is ReasonCode.FLOOD
    assert len(recorder.probes) == 1


async def test_a_failing_probe_recorder_never_fails_the_request(make_pipeline: Callable[..., AbusePipeline]) -> None:
    class Broken:
        def record_probe(self, *_args: Any) -> None:
            raise RuntimeError("recorder down")

    pipeline = make_pipeline(recorder=Broken())
    verdict = await pipeline.evaluate(FakeReq(target_problem=ReasonCode.NOT_ROBLOX, raw_path="/nope"))
    assert isinstance(verdict, Refuse)
    assert verdict.reason is ReasonCode.NOT_ROBLOX
