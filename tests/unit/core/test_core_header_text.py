"""`core/header_text.py`: header text recorded as the caller wrote it (gap G12, faithful non-Latin-1 User-Agents)."""

from __future__ import annotations

import pytest

from roxy.core.header_text import header_text


def _as_server(raw: bytes) -> str:
    """What an ASGI server and Starlette hand over for header bytes: Latin-1 text, one character per byte."""
    return raw.decode("latin-1")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"Roblox/WinInet", "Roblox/WinInet"),
        ("Roblöx/1.0".encode(), "Roblöx/1.0"),
        ("日本語-Agent".encode(), "日本語-Agent"),
        ("emoji \U0001f600".encode(), "emoji \U0001f600"),
        (b"bad \xff\xfe byte", "bad \\xff\\xfe byte"),  # invalid UTF-8 stays visible as escapes
        (b"cut \xe6\x97", "cut \\xe6\\x97"),  # a cut multi-byte character too
        (b"latin1 caf\xe9", "latin1 caf\\xe9"),
        (b"", ""),
    ],
)
def test_header_text_reads_the_callers_bytes_as_utf8(raw: bytes, expected: str) -> None:
    assert header_text(_as_server(raw)) == expected


def test_ascii_comes_back_as_the_same_object_and_none_is_empty() -> None:
    value = "Mozilla/5.0"
    assert header_text(value) is value
    assert header_text(None) == ""


def test_text_that_is_already_decoded_is_left_alone() -> None:
    already = "日本"  # characters above U+00FF cannot be Latin-1 bytes
    assert header_text(already) == already


def test_hostile_text_stays_text() -> None:
    """Markup and bidi controls are kept as characters (pages escape them); nothing is interpreted here."""
    hostile = "<script>alert(1)</script> ‮evil‬".encode()
    out = header_text(_as_server(hostile))
    assert out == "<script>alert(1)</script> ‮evil‬"
    escaped = header_text(_as_server(b"\x1b[31m<b>"))
    assert escaped == "\x1b[31m<b>"
