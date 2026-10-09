"""Table exports (plan 9.16, parity row 88): the spreadsheet formula guard on every cell, the CSV and JSON files,
their names, the row cap, the IP address privacy settings (plan 9.15, 12.3) and the `format` parameter."""

from __future__ import annotations

import csv
import io
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

import pytest

from roxy.admin.api.common import (
    CSV_TYPE,
    FORMULA_PREFIXES,
    MAX_EXPORT_ROWS,
    ApiError,
    Column,
    TableSpec,
    csv_bytes,
    csv_safe,
    export_filename,
    export_format,
    export_ip_policy,
    render_export,
)
from roxy.core.iphash import ip_hash

SPEC = TableSpec(
    name="probe_rows",
    columns=(Column("name", "Name"), Column("count", "Count", unit="count"), Column("meta", "=Meta")),
    default_sort="count",
)


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_formula_prefixes_get_an_apostrophe(prefix: str) -> None:
    assert csv_safe(prefix + "cmd|' /C calc'!A0") == "'" + prefix + "cmd|' /C calc'!A0"


def test_formula_guard_covers_every_rule_and_nothing_else() -> None:
    assert FORMULA_PREFIXES == ("=", "+", "-", "@", "\t", "\r")
    assert csv_safe("games.roblox.com/v1/games") == "games.roblox.com/v1/games"
    assert csv_safe("a=b") == "a=b"  # only the first character matters
    assert csv_safe(" =1") == " =1"
    assert csv_safe("'quoted") == "'quoted"
    assert csv_safe(-5) == "'-5"  # every cell, numbers included (v1 toCSVRow)
    assert csv_safe(12.5) == "12.5"
    assert csv_safe(None) == ""
    assert csv_safe(True) == "true"
    assert csv_safe(False) == "false"
    assert csv_safe({"b": 1, "a": "x"}) == '{"b":1,"a":"x"}'
    assert csv_safe(["=x"]) == '["=x"]'
    assert csv_safe("nul\x00here") == "nulhere"


def test_csv_file_quotes_every_cell_and_guards_headers() -> None:
    items = [
        {"name": '=HYPERLINK("http://example.invalid")', "count": 3, "meta": None},
        {"name": "plain, with comma", "count": None, "meta": {"k": "v"}},
        {"name": "new\nline", "count": 0},
    ]
    content = csv_bytes(SPEC.columns, items).decode("utf-8")
    lines = content.split("\r\n")
    assert lines[0] == '"Name","Count","\'=Meta"'
    assert lines[1] == '"\'=HYPERLINK(""http://example.invalid"")","3",""'
    rows = list(csv.reader(io.StringIO(content)))
    assert rows[2] == ["plain, with comma", "", '{"k":"v"}']
    assert rows[3] == ["new\nline", "0", ""]
    assert len(rows) == 4


def test_export_filenames() -> None:
    assert export_filename("endpoints", "csv", 1_760_000_000_123) == "roxy_endpoints_1760000000123.csv"
    assert export_filename("Weird Name!/..", "json", 5) == "roxy_weird_name_____5.json"
    assert export_filename("", "csv", 1) == "roxy_table_1.csv"


def test_render_csv_and_json() -> None:
    items: list[dict[str, Any]] = [{"name": "@x", "count": n, "meta": "", "hidden": "not a column"} for n in range(3)]
    csv_file = render_export(SPEC, items, "csv", at_ms=1_760_000_000_000)
    assert csv_file.media_type == CSV_TYPE
    assert csv_file.filename == "roxy_probe_rows_1760000000000.csv"
    assert (csv_file.rows, csv_file.truncated) == (3, False)
    assert b"not a column" not in csv_file.content
    json_file = render_export(SPEC, items, "json", at_ms=1_760_000_000_000)
    assert json_file.media_type == "application/json"
    document = json.loads(json_file.content)
    assert document == {
        "table": "probe_rows",
        "exported_at": 1_760_000_000,
        "columns": SPEC.columns_info(),
        "items": [{"name": "@x", "count": n, "meta": ""} for n in range(3)],
        "total": 3,
        "truncated": False,
    }


def test_exports_are_capped_and_say_so() -> None:
    items = [{"name": "x", "count": n} for n in range(12)]
    capped = render_export(SPEC, items, "json", at_ms=0, max_rows=5)
    assert (capped.rows, capped.truncated) == (5, True)
    assert json.loads(capped.content)["truncated"] is True
    partial = render_export(SPEC, items, "csv", at_ms=0, total=40)
    assert (partial.rows, partial.truncated) == (12, True)  # the caller had more rows than it passed
    assert MAX_EXPORT_ROWS == 50_000


@dataclass
class FakeSettings:
    values: dict[str, Any] = field(default_factory=dict)

    def bool(self, key: str) -> bool:
        return bool(self.values.get(key, 0))


@dataclass
class FakeCtx:
    settings: FakeSettings
    ip_hash_key: bytes | None


def test_ip_policy_follows_the_export_settings() -> None:
    key = secrets.token_bytes(32)
    raw, mode = export_ip_policy(FakeCtx(FakeSettings({"export_include_ips": 1}), key), "r1")
    assert (raw, mode) == (None, "raw")
    stable, mode = export_ip_policy(FakeCtx(FakeSettings({"export_stable_ip_hash": 1}), key), "r1")
    assert mode == "hashed_stable"
    assert stable is not None
    assert stable("203.0.113.9") == ip_hash("203.0.113.9", key)
    first, mode = export_ip_policy(FakeCtx(FakeSettings(), key), "r1")
    second, _ = export_ip_policy(FakeCtx(FakeSettings(), key), "r2")
    assert mode == "hashed_one_time"
    assert first is not None
    assert second is not None
    assert first("203.0.113.9") != second("203.0.113.9") != ip_hash("203.0.113.9", key)
    assert first("203.0.113.9") == first("203.0.113.9")  # stable within one file
    no_key, mode = export_ip_policy(FakeCtx(FakeSettings({"export_stable_ip_hash": 1}), None), "r1")
    assert mode == "hashed_one_time"  # a stable hash needs the ip_hash_key credential
    assert no_key is not None
    assert len(no_key("203.0.113.9")) == 16


def test_render_hashes_only_ip_columns() -> None:
    spec = TableSpec(
        name="clients",
        columns=(Column("ip", "Client", ip=True), Column("note", "Note")),
        default_sort="ip",
    )
    items: list[dict[str, Any]] = [
        {"ip": "203.0.113.9", "note": "203.0.113.9"},
        {"ip": None, "note": "x"},
        {"ip": "", "note": "y"},
    ]
    hashed = render_export(spec, items, "json", at_ms=0, ip_hasher=lambda ip: "H:" + ip[-1])
    document = json.loads(hashed.content)
    assert [item["ip"] for item in document["items"]] == ["H:9", None, ""]
    assert document["items"][0]["note"] == "203.0.113.9"  # only columns marked ip=True are hashed
    assert items[0]["ip"] == "203.0.113.9"  # the caller's rows are not changed
    plain = render_export(spec, items, "csv", at_ms=0)
    assert b'"203.0.113.9","203.0.113.9"' in plain.content


async def test_format_parameter() -> None:
    assert await export_format() is None
    assert await export_format("csv") == "csv"
    assert await export_format("json") == "json"
    for bad in ("xml", "CSV", ""):
        with pytest.raises(ApiError) as caught:
            await export_format(bad)
        assert caught.value.status_code == 422
        assert set(caught.value.error_fields) == {"format"}
