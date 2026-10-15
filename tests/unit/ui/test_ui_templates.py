"""Rendering the base layout and every component macro with Roxy's real Jinja environment.

What this is
    Tests that render templates/admin/base.html with an empty context and each macro in templates/components with
    small inputs, and check the markup they promise: accessible names and states, escaping, the CSP rules (no
    inline styles), links from data limited to paths on this site, and the plan's writing style. The setting
    control is rendered for EVERY setting in the catalog.

Why it exists
    Pages built in P11 part two call these macros with real data. A macro that breaks on an unusual setting (an
    enum without options, a percent unit, a list type) or that drops an ARIA state would show up on one page
    among eighteen; rendering every catalog spec here catches it at once (plan principle P3: the editor is
    generated from the catalog, so it must handle all of it).

How it works
    `Templates` from roxy/core/templating.py (autoescape on, `static_url` global) renders a small template string
    that imports the macro under test. A minimal ASGI scope stands in for the request.

What to read next
    templates/components/*.html, templates/admin/base.html.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from starlette.requests import Request

from roxy.config.catalog import CATALOG, PAGES
from roxy.config.spec import SettingSpec
from roxy.core.style_guard import find_style_issues
from roxy.core.templating import Templates

TEMPLATES = Templates()


def _request(path: str = "/admin/overview") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [],
            "query_string": b"",
            "state": {"csp_nonce": "testnonce"},
        }
    )


def render_string(source: str, **context: Any) -> str:
    template = TEMPLATES.env.from_string(source)
    html: str = template.render({"request": _request(), "csp_nonce": "testnonce", **context})
    return html


def _clean(html: str) -> None:
    assert not re.search(r"\sstyle\s*=", html), "inline style attribute"
    assert find_style_issues(html, "render") == []


# ------------------------------------------------------------------------------------------- base layout


def test_base_layout_renders_with_an_empty_context() -> None:
    html = TEMPLATES.render_to_string(_request(), "admin/base.html", {})
    _clean(html)
    assert html.lstrip().startswith("<!doctype html>")
    assert '<a class="skip-link" href="#main">' in html
    assert 'id="how-to-read"' in html
    assert '<main class="main" id="main" tabindex="-1">' in html
    assert 'data-theme="dark"' in html  # dark is the default theme (plan 14.4)
    assert '<meta name="csrf-token" content="">' in html
    assert html.count('nonce="testnonce"') == 2
    importmap = re.search(r'<script type="importmap" nonce="testnonce">(.*?)</script>', html, re.DOTALL)
    assert importmap is not None
    integrity = re.findall(r"sha384-[A-Za-z0-9+/=]+", importmap.group(1))
    assert len(integrity) == 3  # htmx, Alpine and uPlot are pinned
    for landmark in ('role="banner"', '<nav class="sidebar"', "<main", 'aria-label="Quick navigation"'):
        assert landmark in html


def test_base_layout_carries_session_settings_and_marks_the_current_page() -> None:
    context = {
        "page": {"id": "cache", "title": "Cache", "purpose": "What the cache saves.", "how_to_read": "Read it."},
        "session": {"heartbeat_s": 45, "activity_window_s": 90, "heartbeat_url": "/hb", "login_url": "/admin"},
        "csrf_token": "masked-token",
        "theme": "system",
        "recs": {"open": 4, "critical": 2},
        "status": {"paused": True, "pause_drops": 12, "throttle_all": True, "throttle_limit": 5, "throttle_period": 60},
        "admin": {"username": "<owner>"},
    }
    html = TEMPLATES.render_to_string(_request("/admin/cache"), "admin/base.html", context)
    _clean(html)
    assert 'data-heartbeat-s="45"' in html
    assert 'data-activity-window-s="90"' in html
    assert '<meta name="csrf-token" content="masked-token">' in html
    assert re.search(r'<a class="nav-link" href="/admin/cache"[^>]*aria-current="page"', html)
    assert "The proxy is paused." in html
    assert "Resume proxy" in html
    assert "each IP may make 5 requests per 60 seconds" in html
    assert "&lt;owner&gt;" in html
    assert "<owner>" not in html
    assert "Recommendations: 4 open, 2 critical" in html


def test_navigation_lists_exactly_the_dashboard_pages() -> None:
    html = render_string('{% from "admin/_layout/nav.html" import PAGES %}{{ PAGES|map(attribute="id")|join(",") }}')
    assert set(html.split(",")) == set(PAGES)


# ------------------------------------------------------------------------------------------- components


def test_kpi_tile_delta_reads_as_improvement_or_regression() -> None:
    source = (
        '{% from "components/kpi.html" import kpi_tile %}'
        '{{ kpi_tile("Roblox 429s", "38", delta=-72.0, good="down", status="ok", status_label="Low", '
        'spark=[3, 5, 2], href="/admin/upstream", help="Responses where Roblox said too many requests.") }}'
    )
    html = render_string(source)
    _clean(html)
    assert "delta--ok" in html
    assert "an improvement" in html
    assert "-72.0%" in html
    assert 'aria-label="Help: Roblox 429s"' in html
    assert '<a class="kpi__link" href="/admin/upstream">' in html
    worse = render_string(
        '{% from "components/kpi.html" import kpi_tile %}{{ kpi_tile("p95", "182", delta=12.4, good="down") }}'
    )
    assert "delta--bad" in worse
    assert "getting worse" in worse


def test_sparkline_scales_points_into_its_box() -> None:
    html = render_string('{% from "components/chart.html" import sparkline %}{{ sparkline([0, 5, 10], label="T") }}')
    points = re.search(r'class="spark__line" points="([^"]+)"', html)
    assert points is not None
    assert points.group(1) == "0.00,30.00 60.00,16.00 120.00,2.00"
    assert 'aria-label="T: from 0 to 10, lowest 0, highest 10"' in html
    assert "spark--empty" in render_string('{% from "components/chart.html" import sparkline %}{{ sparkline([4]) }}')


def test_timeseries_carries_its_spec_safely_in_an_attribute() -> None:
    spec = {
        "x": [1, 2],
        "series": [{"label": "A'</script>", "values": [1, 2]}],
        "annotations": [{"t": 1, "iso": "2026-10-07T14:02:00Z", "when": "14:02", "label": "changed", "kind": "config"}],
    }
    html = render_string(
        '{% from "components/chart.html" import timeseries %}'
        '{{ timeseries("c1", "Requests", spec=spec, summary="S") }}',
        spec=spec,
    )
    _clean(html)
    attribute = re.search(r"data-spec='([^']*)'", html)
    assert attribute is not None
    assert "</script>" not in attribute.group(1)
    assert 'role="img" aria-label="S"' in html
    assert '<time datetime="2026-10-07T14:02:00Z">14:02</time>' in html
    assert 'data-chart-zoom="in"' in html
    assert "Show the data as a table" in html


def test_heatmap_levels_and_table_semantics() -> None:
    html = render_string(
        '{% from "components/heatmap.html" import heatmap %}'
        '{{ heatmap("h", "Load", ["Mon", "Tue"], ["00", "01"], [[0, 10], [5, 1]], summary="S") }}'
    )
    _clean(html)
    assert 'class="heat heat-0"' in html
    assert 'class="heat heat-8"' in html
    assert 'class="heat heat-4"' in html
    assert html.count('scope="row"') == 2
    assert html.count('scope="col"') == 2
    assert 'aria-pressed="false"' in html


def test_data_table_marks_sorting_paging_and_hidden_columns() -> None:
    columns = [
        {"key": "endpoint", "label": "Endpoint", "key_col": True},
        {"key": "requests", "label": "Requests", "num": True},
        {"key": "host", "label": "Host", "hidden": True, "sortable": False},
    ]
    rows = [{"id": "a", "cells": {"endpoint": "games.roblox.com/v1", "requests": 1234, "host": "games"}}]
    html = render_string(
        '{% from "components/table.html" import data_table %}'
        '{{ data_table("t", columns, rows, src="/x", total=60, page=1, size=25, sort="requests", dir="asc") }}',
        columns=columns,
        rows=rows,
    )
    _clean(html)
    assert re.search(r'<th scope="col" data-col="requests" class="num" aria-sort="ascending">', html)
    assert re.search(r'data-col="host" class="" hidden>', html)
    assert 'aria-label="First page" disabled' in html
    assert 'aria-label="Last page" disabled' not in html
    assert "Page 1 of 3" in html
    assert "1,234" in html
    assert '<button type="button" class="link-btn" data-dt-open>' in html
    empty = render_string(
        '{% from "components/table.html" import data_table %}{{ data_table("t", columns, []) }}', columns=columns
    )
    assert "Nothing to show" in empty
    assert 'colspan="3"' in empty


@pytest.mark.parametrize(
    "href",
    [
        "https://example.invalid/x",
        "javascript:alert(1)",
        "//example.invalid/x",
        "/\\example.invalid/x",
        "data:text/html,x",
        " /admin/x",
        "",
    ],
)
def test_table_cells_and_chart_notes_link_only_to_local_paths(href: str) -> None:
    """Cell and annotation links come from data; only a path on this site may become a link (the text stays)."""
    columns = [{"key": "endpoint", "label": "Endpoint"}]
    rows = [{"id": "a", "cells": {"endpoint": {"text": "games.roblox.com/v1", "href": href}}}]
    table = render_string(
        '{% from "components/table.html" import data_table %}{{ data_table("t", columns, rows) }}',
        columns=columns,
        rows=rows,
    )
    spec = {"x": [1, 2], "series": [{"label": "A", "values": [1, 2]}]}
    notes = [{"t": 1, "when": "14:02", "label": "changed", "kind": "config", "href": href}]
    chart = render_string(
        '{% from "components/chart.html" import timeseries %}{{ timeseries("c1", "Requests", spec=spec, '
        "annotations=notes) }}",
        spec=spec,
        notes=notes,
    )
    for html in (table, chart):
        assert "example.invalid" not in html
        assert "javascript:" not in html
        assert "data:text" not in html
    assert "games.roblox.com/v1" in table
    assert "changed" in chart


def test_table_cells_and_chart_notes_keep_local_links() -> None:
    columns = [{"key": "endpoint", "label": "Endpoint"}]
    rows = [{"id": "a", "cells": {"endpoint": {"text": "E", "href": "/admin/endpoints?template=a&x=1"}}}]
    table = render_string(
        '{% from "components/table.html" import data_table %}{{ data_table("t", columns, rows) }}',
        columns=columns,
        rows=rows,
    )
    assert '<a href="/admin/endpoints?template=a&amp;x=1"' in table
    spec = {"x": [1, 2], "series": [{"label": "A", "values": [1, 2]}]}
    notes = [{"t": 1, "when": "14:02", "label": "changed", "kind": "config", "href": "/admin/audit#entry-4"}]
    chart = render_string(
        '{% from "components/chart.html" import timeseries %}{{ timeseries("c1", "R", spec=spec, annotations=notes) }}',
        spec=spec,
        notes=notes,
    )
    assert '<a href="/admin/audit#entry-4">changed</a>' in chart


def test_confirm_dialog_type_to_confirm_and_reason() -> None:
    html = render_string(
        '{% from "components/dialog.html" import confirm_dialog %}'
        '{{ confirm_dialog("d", "Purge?", "/purge", danger=True, consequences=["All gone."], '
        'type_to_confirm="purge", reason=True, reason_required=True, hidden={"scope": "all"}) }}'
    )
    _clean(html)
    assert '<dialog class="dialog dialog--danger" id="d" aria-labelledby="d-title" aria-describedby="d-desc">' in html
    assert 'hx-post="/purge"' in html
    assert 'data-expected="purge"' in html
    assert 'x-bind:disabled="blocked"' in html
    assert 'name="reason" rows="2" maxlength="500" required aria-required="true"' in html
    assert '<input type="hidden" name="scope" value="all">' in html


def test_recommendation_card_shows_evidence_diff_and_actions() -> None:
    rec = {
        "id": "r1",
        "rule_id": "UP-429-ENDPOINT",
        "family": "upstream",
        "severity": "critical",
        "confidence": "high",
        "title": "T",
        "explanation": "E",
        "evidence": {"label": "L", "values": [1, 2, 3], "note": None},
        "changes": [{"label": "TTL", "key": "k", "before": None, "after": "300 s"}],
        "expected_impact": "Less.",
        "age": "now",
        "safe_auto": True,
        "urls": {"apply": "/a", "preview": "/p", "snooze": "/s", "dismiss": "/d"},
    }
    html = render_string(
        '{% from "components/recommendation.html" import recommendation_card %}{{ recommendation_card(rec) }}', rec=rec
    )
    _clean(html)
    assert "Critical" in html
    assert "UP-429-ENDPOINT" in html
    assert 'data-dialog-open="rec-r1-apply"' in html
    assert 'id="rec-r1-dismiss"' in html
    assert "not set" in html
    assert "<ins>300 s</ins>" in html
    assert 'data-drawer-src="/p"' in html


def test_glossary_term_links_known_terms_and_degrades_for_unknown_ones() -> None:
    entries = {"ttl": {"term": "TTL", "definition": "Time to live."}}
    html = render_string(
        '{% from "components/glossary.html" import term %}{{ term("ttl", entries=entries) }} '
        '{{ term("nope", "Nope", entries=entries) }}',
        entries=entries,
    )
    assert '<a class="gloss" href="/admin/help#term-ttl" data-def="Time to live.">TTL</a>' in html
    assert '<span class="gloss gloss--unknown">Nope</span>' in html


def test_empty_state_alert_and_diff_lines_render() -> None:
    html = render_string(
        '{% from "components/empty.html" import empty_state %}{% from "components/alert.html" import inline_alert %}'
        '{% from "components/diff.html" import diff_lines %}'
        '{{ empty_state("No 429s from Roblox in this range. Good.", tone="good", doc_href="/d") }}'
        '{{ inline_alert("warn", "Quota", "85%", dismissible=True) }}'
        '{{ diff_lines([{"op": "delete", "old": 1, "new": None, "text": "a"},'
        ' {"op": "insert", "old": None, "new": 1, "text": "b"}]) }}'
    )
    _clean(html)
    assert "empty--good" in html
    assert "#i-check-circle" in html
    assert 'aria-label="Dismiss: Quota"' in html
    assert "+1 added" in html
    assert "-1 removed" in html
    assert '<span class="sr-only">removed</span>' in html


def test_live_tail_shell_has_controls_but_no_live_region_on_the_list() -> None:
    html = render_string('{% from "components/live_tail.html" import live_tail %}{{ live_tail("t", "/stream") }}')
    _clean(html)
    assert 'data-stream-url="/stream"' in html
    assert 'aria-pressed="false"' in html
    viewport = re.search(r'<div class="tail__viewport"[^>]*>', html)
    assert viewport is not None
    assert "aria-live" not in viewport.group(0)
    assert html.count('aria-live="polite"') == 1


# ------------------------------------------------------------------------------------------- setting control


def _render_setting(spec: SettingSpec, value: Any, **options: Any) -> str:
    return render_string(
        '{% from "components/setting.html" import setting_control %}'
        '{{ setting_control(spec, value, "/save", **options) }}',
        spec=spec,
        value=value,
        options=options,
    )


@pytest.mark.parametrize("key", sorted(CATALOG), ids=str)
def test_setting_control_renders_every_catalog_setting(key: str) -> None:
    spec = CATALOG[key]
    html = _render_setting(spec, spec.default)
    assert not re.search(r"\sstyle\s*=", html)
    assert f'<label class="setting__label" for="set-{key}-value">' in html
    assert f'id="set-{key}-value"' in html
    assert 'x-data="settingControl"' in html
    assert 'hx-post="/save"' in html
    assert "Default" in html


def test_setting_control_types_pick_the_right_input() -> None:
    by_key = {
        k: CATALOG[k]
        for k in (
            "cache_enabled",
            "cache_eviction_policy",
            "cache_ttl_seconds",
            "cache_memory_bytes",
            "direct_weight",
            "roblox_egress_cidrs",
            "ui_timezone",
        )
    }
    switch = _render_setting(by_key["cache_enabled"], 1)
    assert 'role="switch"' in switch
    assert 'name="value" value="0"' in switch
    assert "checked" in switch
    select = _render_setting(by_key["cache_eviction_policy"], by_key["cache_eviction_policy"].default)
    assert "<select" in select
    assert "setting__option" in select
    duration = _render_setting(by_key["cache_ttl_seconds"], 300)
    assert "Accepts 90, 90s, 15m or 2h." in duration
    assert 'data-unit-ms="1000"' in duration
    assert "Changed (default 120 seconds)" in duration
    size = _render_setting(by_key["cache_memory_bytes"], by_key["cache_memory_bytes"].default)
    assert "Accepts 65536, 64 KiB or 1 GiB." in size
    slider = _render_setting(by_key["direct_weight"], 100)
    assert 'type="range"' in slider
    assert "data-setting-slider" in slider
    listing = _render_setting(by_key["roblox_egress_cidrs"], ["203.0.113.0/24", "198.51.100.0/24"])
    assert "203.0.113.0/24\n198.51.100.0/24</textarea>" in listing
    text = _render_setting(by_key["ui_timezone"], "UTC")
    assert 'type="text"' in text
    assert 'maxlength="64"' in text


def test_setting_control_shows_high_risk_values_and_server_errors() -> None:
    spec = CATALOG["strict_host_allowlist"]
    risky = _render_setting(spec, 0)
    assert "setting--risky" in risky
    assert "High risk" in risky
    assert re.search(r'<div class="setting__risk" role="alert" x-bind:hidden', risky)  # visible from the start
    error = _render_setting(CATALOG["cache_ttl_seconds"], 120, error="Enter a duration", submitted="banana")
    assert 'value="banana"' in error
    assert 'data-server-error="Enter a duration"' in error
    assert 'data-initial="120"' in error  # Cancel goes back to the saved value, not the refused text
    saved = _render_setting(
        CATALOG["cache_ttl_seconds"],
        900,
        saved=True,
        meta={"changed_at": "now", "changed_by": "owner", "reason": "<b>why</b>"},
    )
    assert "setting__saved" in saved
    assert "&lt;b&gt;why&lt;/b&gt;" in saved
