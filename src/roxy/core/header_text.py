"""Header text as the caller sent it: the readable form of a header value for records and pages.

What this is
    `header_text(value)`: the text of one request header value (a User-Agent, a header Roxy fingerprints) as Roxy
    records and shows it. The bytes are read as UTF-8, the encoding every current client and the rest of Roxy's
    caller text use (the path and the query are decoded as UTF-8 in `proxy/validate.py`); a byte that is not part of
    valid UTF-8 stays visible as a `\\xNN` escape instead of becoming a wrong letter or disappearing.

Why it exists
    HTTP header bytes reach Python as Latin-1 text (one character per byte: what ASGI servers, Starlette and v1's
    WSGI stack hand over, PEP 3333), and that is what the abuse checks match against, unchanged since v1. But a
    User-Agent written in UTF-8, such as `Robl\\u00f6xApp`, then reads as `Robl\\u00c3\\u00b6xApp` (mojibake) on
    the Live tail, the Endpoints page and the fingerprint tables. Recording the caller's own text keeps those views
    faithful; matching stays on the Latin-1 form, so no rule changes meaning.

How it works
    A value is first turned back into the bytes it came from (`encode("latin-1")` is lossless for text that came
    from bytes), then decoded as UTF-8 with `backslashreplace`: invalid bytes become `\\xNN`. ASCII text, almost
    every value, is returned as it is without any work. Text that cannot be bytes read as Latin-1 (a character above
    U+00FF: it was already decoded by someone else) is returned unchanged. The result is still caller text: pages
    render it with `format.html caller_text` (plain text, never markup) and recorders still scrub it
    (`redact_text`) and cut it to their bounds.

What to read next
    `roxy/metrics/recorder.py` (`scrub_labels`, `record_fingerprint`, `record_probe`), `roxy/metrics/live.py`
    (`live_entry`) and `roxy/proxy/router.py` (`caller_headers`, where the Latin-1 text is made).
"""

from __future__ import annotations


def header_text(value: str | None) -> str:
    """`value` (a header value decoded as Latin-1) as the caller wrote it: UTF-8, invalid bytes as `\\xNN`."""
    if not value:
        return ""
    if value.isascii():
        return value  # nearly every value: nothing to do
    try:
        raw = value.encode("latin-1")
    except UnicodeEncodeError:
        return value  # already real text (a character above U+00FF), not bytes read as Latin-1
    return raw.decode("utf-8", "backslashreplace")


def text_lines(text: str | None) -> list[str]:
    """`text` split at line breaks only: `\\r\\n`, `\\n` and `\\r` (no empty last line after a final break).

    `str.splitlines()` also breaks at U+2028, U+2029, U+0085, U+000B, U+000C and U+001C to U+001E, which a caller
    can put inside a header value or a path (header values are read as UTF-8, paths are percent-decoded). Text a
    caller chose must never become extra lines: the request filter tester would read a forged header, and an audit
    diff would cut a line in two (review finding esc-4).
    """
    if not text:
        return []
    parts = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if parts[-1] == "":
        parts.pop()
    return parts


__all__ = ["header_text", "text_lines"]
