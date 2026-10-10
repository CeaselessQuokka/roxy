"""Table exports (plan 9.16, parity row 88): the spreadsheet formula guard on every cell, the CSV and JSON files,
their names, the row and byte caps (plan P9), the IP address privacy settings (plan 9.15, 12.3) in `ip` columns and
in free text (review finding apisec-2), the per-worker download slots (apisec-6) and the `format` parameter."""

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
    JSON_TRAILER_RESERVE,
    MAX_CONCURRENT_EXPORTS,
    MAX_EXPORT_BYTES,
    MAX_EXPORT_ROWS,
    MAX_MASK_DEPTH,
    ApiError,
    Column,
    ExportBuilder,
    ExportSlots,
    TableSpec,
    csv_bytes,
    csv_safe,
    estimated_bytes,
    export_filename,
    export_ip_policy,
    mask_ip_text,
    mask_ip_value,
    parse_export_format,
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


def _tag(ip: str) -> str:
    return "H" + ip.replace(".", "").replace(":", "")[-4:]


def test_render_hashes_ip_columns_and_masks_addresses_in_every_other_cell() -> None:
    """apisec-2: with export_include_ips off, no address leaves in any cell, not only in `ip` columns.

    Review round 4 (secfix-2): a product version (`Chrome/120.0.0.0`) is kept only in a User-Agent column or under a
    User-Agent key; in any other cell `<letter>/<quad>` may be a path holding an address and is masked."""
    spec = TableSpec(
        name="clients",
        columns=(
            Column("ip", "Client", ip=True),
            Column("note", "Note"),
            Column("detail", "Detail"),
            Column("user_agent", "User-Agent"),
        ),
        default_sort="ip",
    )
    items: list[dict[str, Any]] = [
        {
            "ip": "203.0.113.9",
            "note": "ban ip:203.0.113.9 and 2001:db8::7",
            "detail": {"203.0.113.9": ["2001:db8::7"]},
            "user_agent": "Bot/1.0 (from 203.0.113.9)",
        },
        {"ip": None, "note": "x", "detail": None, "user_agent": None},
        {
            "ip": "",
            "note": "/v1/lookup/203.0.113.9",
            "detail": {"at": "12:30:45 Chrome/120.0.0.0", "user_agent": "Mozilla/5.0 Chrome/120.0.0.0"},
            "user_agent": "Mozilla/5.0 Chrome/120.0.0.0",
        },
    ]
    hashed = render_export(spec, items, "json", at_ms=0, ip_hasher=_tag)
    document = json.loads(hashed.content)
    assert [item["ip"] for item in document["items"]] == ["H1139", None, ""]  # the bare keyed hash, as before
    assert document["items"][0]["note"] == "ban ip:H1139 and ip:Hdb87"  # an `ip:` already there is kept once
    assert document["items"][0]["detail"] == {"ip:H1139": ["ip:Hdb87"]}  # nested values and keys too
    assert document["items"][0]["user_agent"] == "Bot/1.0 (from ip:H1139)"  # an address in a User-Agent too
    assert document["items"][2]["note"] == "/v1/lookup/ip:H1139"  # an address in a path after `<letter>/`
    assert document["items"][2]["detail"] == {  # a time is not an address; a version outside a User-Agent is masked
        "at": "12:30:45 Chrome/ip:H0000",
        "user_agent": "Mozilla/5.0 Chrome/120.0.0.0",
    }
    assert document["items"][2]["user_agent"] == "Mozilla/5.0 Chrome/120.0.0.0"  # a browser version is kept
    assert items[0]["ip"] == "203.0.113.9"  # the caller's rows are not changed
    as_csv = render_export(spec, items, "csv", at_ms=0, ip_hasher=_tag).content.decode()
    assert "203.0.113" not in as_csv
    assert "2001:db8" not in as_csv
    assert '"ban ip:H1139 and ip:Hdb87"' in as_csv
    plain = render_export(spec, items, "csv", at_ms=0)  # export_include_ips on: no hasher, every value as it is
    assert b'"203.0.113.9","ban ip:203.0.113.9 and 2001:db8::7"' in plain.content


def test_mask_ip_text_replaces_only_real_addresses() -> None:
    assert mask_ip_text("from 198.51.100.77 (subject ip:198.51.100.77)", _tag) == "from ip:H0077 (subject ip:H0077)"
    assert mask_ip_text("cidr 198.51.100.0/24", _tag) == "cidr ip:H1000/24"
    assert mask_ip_text("[2001:db8::1]:443 and ::1", _tag) == "[ip:Hdb81]:443 and ip:H1"
    assert mask_ip_text("2001:0db8:0000::0001", _tag) == "ip:Hdb81"  # hashed in its normal form, as a column is
    # Review round 4 (secfix-2): an IPv6 client after a word and a colon, as Roxy writes its /64 limit key.
    assert mask_ip_text("ip:2001:db8:1:2::/64", _tag) == "ip:Hb812/64"
    assert mask_ip_text("bypass:2001:db8:1:2::/64 ban:2001:db8::7.", _tag) == "bypass:ip:Hb812/64 ban:ip:Hdb87."
    assert mask_ip_text("Edg/120.0.0.0", _tag) == "Edg/ip:H0000"  # outside a User-Agent: maybe a path, masked
    assert mask_ip_text("Edg/120.0.0.0 at 198.51.100.77", _tag, keep_versions=True) == "Edg/120.0.0.0 at ip:H0077"
    for unchanged in ("999.1.1.1", "1.2.3", "v1.2.3.4.5", "12:30:45", "a::b::c", "Type::fmt", "a :: b", "", "no"):
        assert mask_ip_text(unchanged, _tag) == unchanged, unchanged
    deep: Any = "198.51.100.1"
    for _ in range(MAX_MASK_DEPTH + 3):
        deep = [deep]
    assert "198.51.100.1" not in json.dumps(mask_ip_value(deep, _tag))  # past the depth bound: masked as text


def test_files_stop_at_the_byte_cap_and_stay_valid() -> None:
    items = [{"name": "x" * 90, "count": n, "meta": ""} for n in range(200)]
    limit = 4096
    for fmt in ("csv", "json"):
        capped = render_export(SPEC, items, fmt, at_ms=0, max_bytes=limit)
        assert capped.truncated is True
        assert 0 < capped.rows < 200
        assert capped.size == len(capped.content) <= limit
        if fmt == "json":
            document = json.loads(capped.content)
            assert (document["total"], document["truncated"], len(document["items"])) == (200, True, capped.rows)
            assert capped.size > limit - JSON_TRAILER_RESERVE - 200  # filled up to the cap, minus one row at most
        else:
            assert len(list(csv.reader(io.StringIO(capped.content.decode())))) == capped.rows + 1
    assert MAX_EXPORT_BYTES == 16 * 1024 * 1024


def test_a_file_built_page_by_page_equals_the_one_shot_file() -> None:
    items = [{"name": f"=n{n}", "count": n, "meta": {"k": n}} for n in range(23)]
    for fmt in ("csv", "json"):
        whole = render_export(SPEC, items, fmt, at_ms=5_000, total=40)
        builder = ExportBuilder(SPEC, fmt, at_ms=5_000)
        for start in range(0, len(items), 5):
            assert builder.add(items[start : start + 5]) is True
        paged = builder.finish(40)
        assert paged.content == whole.content
        assert (paged.rows, paged.truncated, paged.size) == (23, True, len(whole.content))
        assert len(paged.chunks) == 1 + 5 + (1 if fmt == "json" else 0)  # the head, one chunk per page, the trailer
    full = ExportBuilder(SPEC, "json", at_ms=0, max_rows=3)
    assert full.add(items[:3]) is True  # exactly the cap is not a cut
    assert full.add(items[3:4]) is False  # one more row is
    assert full.full is True
    assert full.add(items[4:]) is False


def test_export_slots_bound_one_worker() -> None:
    slots = ExportSlots()
    assert slots.limit == MAX_CONCURRENT_EXPORTS == 2
    assert [slots.take() for _ in range(3)] == [True, True, False]
    slots.give()
    assert slots.take() is True
    for _ in range(3):
        slots.give()  # never below zero
    assert slots.busy == 0


def test_row_size_estimate() -> None:
    assert estimated_bytes({"a": "xyz", "b": 5, "c": None}) == 3 + 8 + 8 + 12
    assert estimated_bytes("abcd") == 4
    assert estimated_bytes({"nested": {"k": [1, 2]}}) >= len("{'k': [1, 2]}")


def test_format_parameter() -> None:
    assert parse_export_format(None) is None
    assert parse_export_format("csv") == "csv"
    assert parse_export_format("json") == "json"
    for bad in ("xml", "CSV", ""):
        with pytest.raises(ApiError) as caught:
            parse_export_format(bad)
        assert caught.value.status_code == 422
        assert set(caught.value.error_fields) == {"format"}
