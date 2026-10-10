"""Roxy's own calls: internal_fetch, the credential probe, the place lookup chain, the internal endpoint list."""

from __future__ import annotations

import json
from typing import Any

import pytest
from upstream_fakes import FakeEgress, answer, read_rows

from roxy.core.reasons import Egress, ReasonCode
from roxy.upstream import internal
from roxy.upstream.queue import Priority
from roxy.upstream.service import ProbeResponse, UpstreamService, probe_response


def test_internal_endpoints_list() -> None:
    rows = internal.internal_endpoints("https://users.roblox.com/v1/users/authenticated", "http://127.0.0.1:9/ip")
    assert [row["Purpose"] for row in rows] == [
        "credential_probe",
        "credential_check",
        "credential_confirm",
        "rotator_probe",
        "admin_lookup",
        "health_check",
    ]
    lookup = next(row for row in rows if row["Purpose"] == "admin_lookup")
    assert lookup["What"] == "Identify an experience (only when the proxy path is unavailable)"  # C5 replacement
    for row in rows:
        assert set(row) == {"Purpose", "URL", "What"}
        for text in row.values():
            assert chr(0x2014) not in text
            assert chr(0x2013) not in text
    assert "count against the upstream buckets" in internal.INTERNAL_NOTE


async def test_internal_fetch_rejects_non_roblox_urls(service: UpstreamService) -> None:
    for url in (
        "https://evil.example/x",
        "http://users.roblox.com/v1",
        "https://users.roblox.com:8443/v1",
        "https://a:b@users.roblox.com/v1",
        "https://notallowed.roblox.com/v1",
    ):
        with pytest.raises(ValueError, match="https URL"):
            await service.internal_fetch("health_check", "GET", url)


async def test_internal_credential_only_for_reads(service: UpstreamService) -> None:
    with pytest.raises(ValueError, match="GET or HEAD"):
        await service.internal_fetch("x", "POST", "https://users.roblox.com/v1/x", use_credential=True)


async def test_internal_anonymous_call_is_paced_and_recorded(
    service: UpstreamService, egress: FakeEgress, rules: Any, ctx: Any
) -> None:
    rules.allow_credential("games.roblox.com/v1/games")  # allowlisted, but an anonymous internal call stays anonymous
    result = await service.internal_fetch("health_check", "GET", "https://games.roblox.com/v1/games?universeIds=1")
    assert result.status == 200
    assert egress.egresses() == [Egress.DIRECT]
    assert egress.calls[0][1].url == "https://games.roblox.com/v1/games?universeIds=1"
    keys = {row[0] for row in read_rows(ctx.dbs.hot, "SELECT bucket_key FROM upstream_bucket")}
    # It paid in every bucket, and the host and endpoint (window) buckets counted the call in their meters.
    assert keys == {
        "global",
        "egress:direct",
        "host:games.roblox.com",
        "endpoint:games.roblox.com/v1/games",
        "meter:host:games.roblox.com",
        "meter:endpoint:games.roblox.com/v1/games",
    }
    assert ctx.recorder.internal[0]["purpose"] == "health_check"
    assert ctx.recorder.internal[0]["ok"] is True


async def test_internal_credential_call_uses_the_probe_sub_bucket(
    service: UpstreamService, egress: FakeEgress, ctx: Any
) -> None:
    egress.credential.status_value = "unknown"  # a probe is how an unknown credential becomes active
    result = await service.internal_fetch(
        "credential_probe", "GET", "https://users.roblox.com/v1/users/authenticated", use_credential=True
    )
    assert result.status == 200
    assert egress.egresses() == [Egress.CREDENTIAL]
    assert egress.calls[0][1].purpose == "credential_probe"
    keys = {row[0] for row in read_rows(ctx.dbs.hot, "SELECT bucket_key FROM upstream_bucket")}
    assert "egress:credential:probe" in keys
    assert "egress:credential" not in keys


async def test_internal_credential_call_never_goes_anonymous(service: UpstreamService, egress: FakeEgress) -> None:
    egress.disabled.add(Egress.CREDENTIAL)
    result = await service.internal_fetch(
        "credential_probe", "GET", "https://users.roblox.com/v1/users/authenticated", use_credential=True
    )
    assert result.reason is ReasonCode.CREDENTIAL_UNAVAILABLE
    assert egress.calls == []


# --- the credential probe -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "body", "verdict", "account"),
    [
        (200, b'{"id": 123, "name": "x"}', "alive", "123"),
        (200, b"not json", "alive", None),
        (429, b"", "rate_limited", None),
        (401, b"", "rejected", None),
        (403, b"", "rejected", None),
        (500, b"", "error", None),
    ],
)
async def test_probe_credential_verdicts(
    service: UpstreamService, egress: FakeEgress, status: int, body: bytes, verdict: str, account: str | None
) -> None:
    egress.handler = lambda e, out: answer(status, body)
    result = await internal.probe_credential(service)
    assert (result.verdict, result.account_id) == (verdict, account)
    assert egress.egresses()[0] is Egress.CREDENTIAL


async def test_probe_is_single_flight_fleet_wide(service: UpstreamService, egress: FakeEgress, ctx: Any) -> None:
    now_ms = ctx.clock.now_ms()
    ctx.dbs.hot.write_sync(
        lambda c: c.execute(
            "INSERT INTO lease (name, holder, expires_ms, epoch) VALUES ('probe:credential', 'other', ?, 1)",
            (now_ms + 10_000,),
        )
    )
    result = await internal.probe_credential(service)
    assert result.verdict == "skipped"
    assert egress.calls == []


async def test_probe_releases_its_lease(service: UpstreamService, ctx: Any) -> None:
    await internal.probe_credential(service)
    assert read_rows(ctx.dbs.hot, "SELECT name FROM lease WHERE name = 'probe:credential'") == []


async def test_probe_fetch_for_the_credential_manager(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lambda e, out: answer(200, b'{"id":5}')
    response = await service.credential_probe_fetch("https://users.roblox.com/v1/users/authenticated")
    assert isinstance(response, ProbeResponse)
    assert (response.status, response.body) == (200, b'{"id":5}')


def test_probe_response_conversion() -> None:
    from roxy.upstream.trace import Trace

    def result(reason: ReasonCode, upstream: int | None, retry: int | None = None) -> Any:
        from roxy.core.reasons import AuthClass
        from roxy.upstream.service import UpstreamResult

        return UpstreamResult(
            status=upstream or 503,
            headers={},
            body=b"",
            content_type=None,
            egress=Egress.CREDENTIAL,
            auth_class=AuthClass.CRED,
            upstream_status=upstream,
            reason=reason,
            retry_after_s=retry,
            cooldown_s=retry,
            attempts=1,
            calls=1,
            bytes_in=0,
            bytes_out=0,
            queue_wait_ms=0,
            upstream_ms=1,
            trace=Trace(),
        )

    limited = probe_response(result(ReasonCode.UPSTREAM_COOLDOWN, 429, 31))
    assert (limited.status, limited.headers["retry-after"]) == (429, "31")
    assert probe_response(result(ReasonCode.UPSTREAM_4XX, 401)).status == 401
    errors = pytest.importorskip("roxy.egress.errors")
    with pytest.raises(errors.CredentialUnavailable) as caught:
        probe_response(result(ReasonCode.UPSTREAM_BUSY, None, 7))
    assert caught.value.retry_after_s == 7
    with pytest.raises(errors.UpstreamTimeout):
        probe_response(result(ReasonCode.UPSTREAM_TIMEOUT, None))
    with pytest.raises(errors.CredentialUnavailable) as degraded:
        probe_response(result(ReasonCode.DEGRADED, None, 10))
    assert degraded.value.why == "degraded"


async def test_confirm_uses_the_managers_probe_when_it_has_one(service: UpstreamService, egress: FakeEgress) -> None:
    seen: list[str] = []

    async def probe(kind: str, *, fetch: Any) -> Any:
        seen.append(kind)
        response = await fetch("https://users.roblox.com/v1/users/authenticated")
        seen.append(str(response.status))
        return None

    egress.credential.probe = probe  # type: ignore[attr-defined]
    egress.handler = lambda e, out: answer(401, b"")
    await service._confirm_credential("games.roblox.com/v1/games")
    assert seen == ["confirm_401", "401"]
    assert egress.credential.rejections == []  # the manager decides, not the fallback


# --- the place lookup (rows 38, 92) ---------------------------------------------------------------------------------

GAME = {
    "data": [
        {
            "name": "Example Place",
            "description": "d" * 700,
            "rootPlaceId": 1818,
            "created": "2010-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
            "playing": 5,
            "visits": 100,
            "maxPlayers": 30,
            "favoritedCount": 7,
            "creator": {"id": 1, "name": "Roblox", "type": "User", "hasVerifiedBadge": True},
        }
    ]
}


def lookup_handler(egress: Egress, out: Any) -> Any:
    if "/universes/v1/places/" in out.url:
        return answer(200, json.dumps({"universeId": 13058}).encode())
    if "games.roblox.com/v1/games" in out.url:
        return answer(200, json.dumps(GAME).encode())
    return answer(404, b"{}")


async def test_lookup_place_chain(service: UpstreamService, egress: FakeEgress) -> None:
    egress.handler = lookup_handler
    lookup = internal.PlaceLookup(service)
    result = await lookup.lookup("1818", "place")
    assert result.http_status == 200
    payload = result.payload
    assert (payload["Query"], payload["Kind"], payload["PlaceId"], payload["UniverseId"]) == (
        "1818",
        "place",
        "1818",
        "13058",
    )
    assert payload["Name"] == "Example Place"
    assert len(payload["Description"]) == 600
    assert payload["Url"] == "https://www.roblox.com/games/1818"
    assert payload["CreatorUrl"] == "https://www.roblox.com/users/1/profile"
    assert payload["CreatorVerified"] is True
    assert [out.url for _, out in egress.calls] == [
        "https://apis.roblox.com/universes/v1/places/1818/universe",
        "https://games.roblox.com/v1/games?universeIds=13058",
    ]
    again = await lookup.lookup("1818", "place")
    assert again.cached is True
    assert len(egress.calls) == 2  # cached for 10 minutes: no new calls


async def test_lookup_cache_expires(service: UpstreamService, egress: FakeEgress, clock: Any) -> None:
    egress.handler = lookup_handler
    lookup = internal.PlaceLookup(service)
    await lookup.lookup("13058", "universe")
    clock.advance(601)
    await lookup.lookup("13058", "universe")
    assert len(egress.calls) == 2


@pytest.mark.parametrize("raw", ["", "abc", "12a", "²³", "1" * 21, None])
async def test_lookup_rejects_non_numeric(service: UpstreamService, raw: Any) -> None:
    result = await internal.PlaceLookup(service).lookup(raw)
    assert (result.http_status, result.payload) == (400, {"Message": "Enter a numeric place or universe ID"})


async def test_lookup_messages(service: UpstreamService, egress: FakeEgress) -> None:
    lookup = internal.PlaceLookup(service)
    egress.handler = lambda e, out: answer(200, b"{}")
    missing_universe = await lookup.lookup("5")
    assert (missing_universe.http_status, missing_universe.payload["Message"]) == (
        404,
        "Roblox did not return a universe for that place",
    )
    egress.handler = lambda e, out: answer(200, b'{"data": []}')
    none = await lookup.lookup("5", "universe")
    assert (none.http_status, none.payload["Message"]) == (404, "Roblox returned no experience for that ID")
    egress.handler = lambda e, out: answer(404, b"{}")
    failed = await lookup.lookup("6")
    assert (failed.http_status, failed.payload["Message"]) == (
        502,
        "Could not resolve that place: Roblox returned HTTP 404",
    )
    egress.handler = lambda e, out: answer(200, b"<html>")
    garbled = await lookup.lookup("7", "universe")
    assert garbled.payload["Message"] == "Could not load that experience: Upstream returned a non-JSON body"


async def test_lookup_runs_at_admin_priority(service: UpstreamService, egress: FakeEgress, monkeypatch: Any) -> None:
    seen: list[Priority] = []
    original = service.internal_fetch

    async def spy(purpose: str, method: str, url: str, **kwargs: Any) -> Any:
        seen.append(kwargs.get("priority", Priority.INTERNAL))
        return await original(purpose, method, url, **kwargs)

    monkeypatch.setattr(service, "internal_fetch", spy)
    egress.handler = lookup_handler
    await internal.PlaceLookup(service).lookup("1818")
    assert seen == [Priority.ADMIN, Priority.ADMIN]
