"""The admin API shared layer in the real app: mounting, guards before body errors, 400 and 422, the re-auth
answer, no-store, the section 13 404, exports with their audit rows, time ranges over seeded metrics, and the
services' refusals (DESIGN.md section 13, plan 9.6, 9.7, 9.9, 9.16, 14.2).

A probe area (`area_router("probe")`) is mounted through `build_api_router` from a module placed in
`sys.modules`, exactly as a specialist's `roxy.admin.api.<area>` module is mounted, and added to the running app.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sys
import types
from collections.abc import Iterator
from typing import Annotated, Any

import pytest
from fastapi import Depends, Request
from fastapi.routing import iter_route_contexts
from pydantic import Field

from roxy.admin import router as admin_router_module
from roxy.admin.api import api_router, build_api_router
from roxy.admin.api.common import (
    AdminFreshMfa,
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRangeDep,
    actor_for,
    annotation_entries,
    area_router,
    export_table,
    kpi_from_read_model,
    page_rows,
    request_id_of,
    reset_notices,
    run_mutation,
    series_answer,
    series_from_read_model,
    table_answer,
    table_params,
)
from roxy.config.settings_service import SettingsService
from roxy.core.iphash import ip_hash
from roxy.core.reasons import Outcome, ReasonCode, Source
from roxy.deps import get_ctx
from roxy.metrics import queries
from roxy.rules.service import RulesService
from roxy.storage.db import SharedStateUnavailable

NOT_FOUND_BODY = b'{"error":{"code":"not_found","message":"Not found.","fields":{}}}'

ITEMS_SPEC = TableSpec(
    name="probe_items",
    columns=(
        Column("name", "Name", "The item name."),
        Column("count", "Count", "How many.", "count"),
        Column("note", "Note", "Free text.", sortable=False),
        Column("client", "Client", "The caller.", sortable=False, ip=True),
    ),
    default_sort="count",
)
ITEMS: list[dict[str, Any]] = [
    {"name": f"item{n:02d}", "count": n if n % 7 else None, "note": "plain", "client": f"203.0.113.{n}"}
    for n in range(1, 31)
] + [
    {"name": '=HYPERLINK("http://example.invalid")', "count": 99, "note": "+1", "client": "198.51.100.1"},
    {"name": "@SUM(A1)", "count": -5, "note": "\tTabbed", "client": None},
]


class ItemBody(ApiBody):
    name: str = Field(max_length=40)
    count: int = Field(ge=0, le=1000)


PROBE = area_router("probe")


@PROBE.get("/items")
async def probe_items(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(ITEMS_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    if fmt is not None:
        return await export_table(request, admin, ITEMS_SPEC, ITEMS, fmt, tq=tq, filters={"kind": "probe"})
    items, total = page_rows(ITEMS, tq, search_keys=("name", "note"))
    return table_answer(ITEMS_SPEC, tq, items, total)


@PROBE.post("/items")
async def probe_create(admin: AdminSession, _csrf: CsrfChecked, body: ItemBody) -> dict[str, Any]:
    return {"created": body.name, "count": body.count, "by": actor_for(admin).label}


@PROBE.post("/sensitive")
async def probe_sensitive(admin: AdminFreshMfa, _csrf: CsrfChecked) -> dict[str, bool]:
    return {"done": True}


@PROBE.get("/series")
async def probe_series(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    ctx = get_ctx(request)
    data = await queries.series(ctx.dbs.metrics, tr.window, metrics=["requests"])
    compare = None
    if tr.compare_window is not None:
        other = await queries.series(ctx.dbs.metrics, tr.compare_window, metrics=["requests"])
        compare = series_from_read_model(other, "requests")
    start, end = tr.window.start, tr.window.end
    resets = await ctx.dbs.metrics.read(lambda conn: queries.reset_annotations(conn, start, end))
    marks = await ctx.dbs.metrics.read(lambda conn: queries.chart_annotations(conn, start, end))
    return series_answer(
        tr,
        series_from_read_model(data, "requests"),
        compare_series=compare,
        annotations=annotation_entries(marks),
        notices=reset_notices(resets, tz=tr.window.tz),
    )


@PROBE.get("/kpis")
async def probe_kpis(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> list[dict[str, Any]]:
    ctx = get_ctx(request)
    data = await queries.kpis(ctx.dbs.metrics, tr.window, now=ctx.clock.now(), compare=tr.compare)
    return [kpi_from_read_model(key, data["tiles"][key]) for key in ("requests", "roblox_429")]


@PROBE.post("/rules")
async def probe_rule(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    ctx = get_ctx(request)
    service = RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules)
    row = {"kind": "deny", "cidr": "198.51.100.0/24"}
    rid = request_id_of(request)
    change = await run_mutation(service.create("access_list", row, actor_for(admin), "probe", request_id=rid))
    return {"id": change.key}


@PROBE.post("/settings")
async def probe_settings(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    ctx = get_ctx(request)
    service = SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=ctx.clock)
    result = await run_mutation(service.update({"cache_ttl_seconds": "banana"}, actor_for(admin), "probe"))
    return {"changed": list(result.changed_keys)}


@PROBE.get("/busy")
async def probe_busy(_admin: AdminSession) -> dict[str, Any]:
    raise SharedStateUnavailable("control", "simulated lock")


@pytest.fixture
def probe_module() -> Iterator[str]:
    """A fake `roxy.admin.api.<area>` module exposing PROBE, found by the real mount code."""
    name = "zz_probe_area"
    module = types.ModuleType(f"roxy.admin.api.{name}")
    module.router = PROBE  # type: ignore[attr-defined]
    sys.modules[module.__name__] = module
    try:
        yield name
    finally:
        sys.modules.pop(module.__name__, None)


@pytest.fixture
def probe(api_app: Any, probe_module: str) -> str:
    """Mount the probe area into the running app; returns its URL prefix."""
    router, mounted = build_api_router((probe_module,), sse=None)
    assert mounted == (f"roxy.admin.api.{probe_module}",)
    api_app.include(router)
    return "/admin/api/v1/probe"


# ============================================================================================== mounting


def test_admin_router_includes_the_api_router_before_the_catch_all() -> None:
    routes = admin_router_module.router.routes
    positions = [i for i, route in enumerate(routes) if getattr(route, "original_router", None) is api_router]
    assert len(positions) == 1
    catch_all = [i for i, route in enumerate(routes) if getattr(route, "name", "") == "admin_not_found"]
    assert catch_all == [len(routes) - 1]
    assert positions[0] < catch_all[0]
    assert api_router.prefix == "/admin/api/v1"


async def test_mounted_area_routes_are_live_behind_the_real_guards(api: Any, anon_api: Any, probe: str) -> None:
    paths = {context.path for context in iter_route_contexts(api.owner.app.routes)}
    assert f"{probe}/items" in paths
    assert (await anon_api.get(f"{probe}/items")).status_code == 401
    ok = await api.get(f"{probe}/items")
    assert ok.status_code == 200, ok.text
    assert ok.json()["total"] == len(ITEMS)


async def test_unknown_api_paths_get_the_section13_404(api: Any, anon_api: Any, probe: str) -> None:
    for client in (api, anon_api):
        for method, path in (("GET", "/admin/api/v1/nope"), ("POST", f"{probe}/nope"), ("GET", f"{probe}/items/x")):
            response = await client.request(method, path, csrf=False)
            assert response.status_code == 404, (method, path)
            assert response.content == NOT_FOUND_BODY
            assert response.headers["content-type"] == "application/json"
            assert response.headers["cache-control"] == "no-store"
    wrong_method = await api.delete(f"{probe}/items")
    assert wrong_method.status_code == 405  # a real route with another method keeps its 405


# =============================================================================================== bodies


async def test_malformed_or_missing_bodies_are_400_never_empty_objects(api: Any, probe: str, section13: Any) -> None:
    url = f"{probe}/items"
    json_type = {"Content-Type": "application/json"}
    section13(await api.post(url, content=b'{"name": "x",', headers=json_type), 400, "invalid_json")
    section13(await api.post(url, content=b"", headers=json_type), 400, "missing_body")
    section13(await api.post(url, content=b"null", headers=json_type), 400, "missing_body")
    section13(await api.post(url, json=[{"name": "x", "count": 1}]), 400, "invalid_body")
    section13(await api.post(url, json="text"), 400, "invalid_body")
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    section13(await api.post(url, content=b"name=x&count=1", headers=form), 400, "invalid_body")
    no_type = await api.post(url, content=json.dumps({"name": "x", "count": 1}).encode())
    section13(no_type, 400, "invalid_body")
    not_utf8 = b'{"name": "\xff", "count": 1}'  # FastAPI cannot decode it at all: its own "error parsing the body"
    section13(await api.post(url, content=not_utf8, headers=json_type), 400, "invalid_body")
    created = await api.post(url, json={"name": "x", "count": 1})
    assert created.status_code == 200, created.text
    assert created.json() == {"created": "x", "count": 1, "by": f"admin:{api.admin.username}"}


async def test_validation_errors_are_422_with_one_message_per_field(api: Any, probe: str, section13: Any) -> None:
    url = f"{probe}/items"
    fields = section13(await api.post(url, json={"name": "x", "count": 1, "extra": True}), 422, "validation_failed")
    assert set(fields) == {"extra"}
    fields = section13(await api.post(url, json={"name": "y" * 41, "count": "many"}), 422, "validation_failed")
    assert set(fields) == {"name", "count"}
    fields = section13(await api.post(url, json={}), 422, "validation_failed")
    assert set(fields) == {"name", "count"}
    fields = section13(await api.get(url, params={"page_size": 7, "sort": "note"}), 422, "invalid_table_query")
    assert set(fields) == {"page_size", "sort"}
    fields = section13(await api.get(url, params={"page": "two"}), 422, "validation_failed")
    assert set(fields) == {"page"}
    fields = section13(await api.get(url, params={"q": "x" * 201}), 422, "validation_failed")
    assert set(fields) == {"q"}
    fields = section13(await api.get(f"{probe}/series", params={"range": "2d"}), 422, "invalid_range")
    assert set(fields) == {"range"}


async def test_guards_answer_before_any_body_error(
    api_app: Any, api: Any, anon_api: Any, probe: str, section13: Any
) -> None:
    url = f"{probe}/items"
    broken = b'{"name": '
    json_type = {"Content-Type": "application/json"}
    unauthenticated = await anon_api.post(url, content=broken, headers=json_type)
    assert unauthenticated.status_code == 401
    undecodable = await anon_api.post(url, content=b'{"name": "\xff"}', headers=json_type)
    assert undecodable.status_code == 401
    no_csrf = await api.post(url, content=broken, headers=json_type, csrf=False)
    assert no_csrf.status_code == 403
    cross_site = await api.post(url, content=broken, headers={**json_type, "Sec-Fetch-Site": "cross-site"})
    assert cross_site.status_code == 403
    # The admin network allowlist (D6) hides real routes: even a broken body gets the missing path's exact 404.
    await api_app.settings(admin_allowlist_enabled=1)
    hidden = await api.post(url, content=broken, headers=json_type, csrf=False)
    missing = await api.get("/admin/api/v1/nope")
    assert hidden.status_code == missing.status_code == 404
    assert hidden.content == missing.content == NOT_FOUND_BODY


# ============================================================================================== re-auth


async def test_missing_fresh_mfa_is_403_with_header_and_reauth_code(api: Any, probe: str, section13: Any) -> None:
    url = f"{probe}/sensitive"
    first = await api.post(url, json={})
    assert first.status_code == 200, first.text  # the login itself is a fresh second factor
    api.make_mfa_stale()
    stale = await api.post(url, json={})
    fields = section13(stale, 403, "reauth_required")
    assert fields == {}
    assert stale.headers["roxy-reauth"] == "required"
    assert "authenticator" in stale.json()["error"]["message"]
    await api.fresh_mfa()
    again = await api.post(url, json={})
    assert again.status_code == 200, again.text
    # The auth routes use the same guard: the header is there too (their body is the handler's, see the report).
    api.make_mfa_stale()
    auth_route = await api.post("/admin/api/v1/auth/recovery-codes/regenerate", json={})
    assert auth_route.status_code == 403
    assert auth_route.headers["roxy-reauth"] == "required"


# ================================================================================================ answers


async def test_every_api_answer_is_no_store(api: Any, anon_api: Any, probe: str, api_json: Any) -> None:
    answers = [
        await api.get(f"{probe}/items"),
        await api.get(f"{probe}/items", params={"page_size": 7}),
        await api.get(f"{probe}/items", params={"format": "csv"}),
        await api.post(f"{probe}/items", json=[]),
        await api.get(f"{probe}/busy"),
        await anon_api.get(f"{probe}/items"),
        await api.get("/admin/api/v1/nope"),
    ]
    for response in answers:
        assert response.headers["cache-control"] == "no-store", (response.request.url, response.status_code)
    api_json(answers[0])


async def test_table_paging_sorting_and_search(api: Any, probe: str, api_json: Any) -> None:
    url = f"{probe}/items"
    body = api_json(await api.get(url, params={"page": 2, "page_size": 10, "sort": "count", "order": "asc"}))
    assert body["total"] == len(ITEMS)
    assert (body["page"], body["page_size"], body["sort"], body["order"]) == (2, 10, "count", "asc")
    assert [c["key"] for c in body["columns"]] == ["name", "count", "note", "client"]
    assert set(body["columns"][1]) == {"key", "label", "help", "unit"}
    counts = [item["count"] for item in body["items"]]
    assert counts == sorted(counts)
    last = api_json(await api.get(url, params={"page": 4, "page_size": 10, "sort": "count", "order": "desc"}))
    assert [item["count"] for item in last["items"]] == [None, None]  # missing values come last in both orders
    found = api_json(await api.get(url, params={"q": "ITEM0"}))
    assert found["total"] == 9
    beyond = api_json(await api.get(url, params={"page": 50}))
    assert beyond["items"] == []
    assert beyond["total"] == len(ITEMS)


async def test_csv_and_json_exports_are_guarded_named_and_audited(api_app: Any, api: Any, probe: str) -> None:
    url = f"{probe}/items"
    exported = await api.get(url, params={"format": "csv", "q": "ignored for exports", "sort": "name"})
    assert exported.status_code == 200, exported.text
    assert exported.headers["content-type"] == "text/csv; charset=utf-8"
    disposition = exported.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="roxy_probe_items_')
    assert disposition.endswith('.csv"')
    assert exported.headers["roxy-export-rows"] == str(len(ITEMS))
    rows = list(csv.reader(io.StringIO(exported.text)))
    assert rows[0] == ["Name", "Count", "Note", "Client"]
    assert rows[1][:3] == ["item01", "1", "plain"]
    assert re.fullmatch(r"[0-9a-f]{16}", rows[1][3])  # a keyed hash, never the address (export_include_ips=0)
    assert "203.0.113." not in exported.text
    assert rows[31][:3] == ['\'=HYPERLINK("http://example.invalid")', "99", "'+1"]
    assert rows[32] == ["'@SUM(A1)", "'-5", "'\tTabbed", ""]
    assert rows[7][:3] == ["item07", "", "plain"]
    as_json = await api.get(url, params={"format": "json"})
    assert as_json.status_code == 200
    assert as_json.headers["content-disposition"].endswith('.json"')
    document = as_json.json()
    assert document["table"] == "probe_items"
    last = {"name": "@SUM(A1)", "count": -5, "note": "\tTabbed", "client": None}
    assert document["items"][-1] == last  # JSON is not formula guarded
    assert document["items"][0]["client"] != rows[1][3]  # a fresh key for each export: files do not correlate
    assert document["truncated"] is False
    bad = await api.get(url, params={"format": "xml"})
    assert bad.status_code == 422
    assert set(bad.json()["error"]["fields"]) == {"format"}

    def audit_rows(conn: Any) -> list[Any]:
        sql = "SELECT actor, actor_ip, target, after_json, request_id FROM audit_log WHERE action = 'export.download'"
        return conn.execute(sql + " ORDER BY id").fetchall()

    rows_written = api_app.ctx.dbs.control.read_sync(audit_rows)
    assert len(rows_written) == 2
    first = rows_written[0]
    assert first["actor"] == f"admin:{api.admin.username}"
    assert first["actor_ip"] == "127.0.0.1"
    assert first["target"] == "table:probe_items"
    assert first["request_id"] == exported.headers["roxy-request-id"]
    details = json.loads(first["after_json"])
    assert details["format"] == "csv"
    assert details["rows"] == len(ITEMS)
    assert details["filters"] == {"kind": "probe"}
    assert details["sort"] == "name"
    assert details["ip_addresses"] == "hashed_one_time"


async def test_exports_follow_the_ip_privacy_settings(api_app: Any, api: Any, probe: str) -> None:
    url = f"{probe}/items"
    await api_app.settings(export_stable_ip_hash=1)
    stable = [row[3] for row in csv.reader(io.StringIO((await api.get(url, params={"format": "csv"})).text))]
    again = [row[3] for row in csv.reader(io.StringIO((await api.get(url, params={"format": "csv"})).text))]
    assert stable == again  # the long-lived key: the same client has the same hash in every export
    assert stable[1] == ip_hash("203.0.113.1", api_app.ctx.ip_hash_key)
    await api_app.settings(export_include_ips=1)
    raw = [row[3] for row in csv.reader(io.StringIO((await api.get(url, params={"format": "csv"})).text))]
    assert raw[1:3] == ["203.0.113.1", "203.0.113.2"]

    def modes(conn: Any) -> list[str]:
        rows = conn.execute("SELECT after_json FROM audit_log WHERE action = 'export.download' ORDER BY id").fetchall()
        return [json.loads(row["after_json"])["ip_addresses"] for row in rows]

    assert api_app.ctx.dbs.control.read_sync(modes) == ["hashed_stable", "hashed_stable", "raw"]


async def test_time_ranges_and_series_read_seeded_metrics(
    api: Any, metrics_seed: Any, probe: str, api_json: Any
) -> None:
    metrics_seed.record(5)
    refused = {"outcome": Outcome.REFUSED, "reason": ReasonCode.THROTTLE, "source": Source.ROXY}
    metrics_seed.record(2, status=429, upstream_calls=0, **refused)
    await metrics_seed.flush()
    body = api_json(await api.get(f"{probe}/series", params={"range": "1h", "compare": "previous"}))
    assert set(body) == {"range", "series", "compare", "annotations", "notices"}
    assert set(body["range"]) == {"from", "to", "granularity", "tz"}
    assert body["range"]["granularity"] == "minute"
    (line,) = body["series"]
    assert (line["key"], line["label"], line["unit"]) == ("requests", "Requests", "requests")
    assert sum(point[1] for point in line["points"]) == 7
    assert body["compare"]["mode"] == "previous"
    assert body["compare"]["range"]["to"] == body["range"]["from"]
    assert sum(point[1] for point in body["compare"]["series"][0]["points"]) == 0
    assert body["notices"] == []
    everything = api_json(await api.get(f"{probe}/series", params={"range": "all"}))
    assert sum(point[1] for point in everything["series"][0]["points"]) == 7
    assert everything["compare"] is None
    start = body["range"]["from"]
    custom = api_json(
        await api.get(f"{probe}/series", params={"range": "custom", "from": str(start), "to": str(start + 7200)})
    )
    assert custom["range"]["from"] == start
    assert custom["range"]["granularity"] == "minute"
    tiles = api_json(await api.get(f"{probe}/kpis", params={"range": "24h", "compare": "week"}))
    requests_tile = tiles[0]
    assert set(requests_tile) == {
        "key", "label", "value", "unit", "delta", "delta_pct", "good_direction", "sparkline", "help", "notice"
    }  # fmt: skip
    assert requests_tile["value"] == 7
    assert requests_tile["delta"] == 7
    assert requests_tile["delta_pct"] is None  # nothing to compare with: no percentage invented (P6)


async def test_service_refusals_become_409_422_and_503(api: Any, probe: str, section13: Any) -> None:
    first = await api.post(f"{probe}/rules", json={})
    assert first.status_code == 200, first.text
    section13(await api.post(f"{probe}/rules", json={}), 409, "conflict")
    fields = section13(await api.post(f"{probe}/settings", json={}), 422, "invalid_settings")
    assert set(fields) == {"cache_ttl_seconds"}
    busy = await api.get(f"{probe}/busy")
    section13(busy, 503, "unavailable")
    assert busy.headers["retry-after"] == "5"
    assert "simulated" not in busy.text  # the cause stays in the log, never in the answer
