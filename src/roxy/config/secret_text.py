"""Secret screening for admin-typed text: is this the Roblox credential (or another secret Roxy keeps) pasted in?

What this is
    `holds_secret(text)` answers whether a text an admin typed carries a secret: a value in the process-wide
    `SecretRegistry` (the Roblox credential, the rotator URL and password, the SMTP password, the webhook URL, the
    keys), a run of `SUBSTRING_WINDOW` (24) or more characters of the credential, or the Roblox cookie's own shape
    (the public `TOKEN_PREFIX` warning, or `.ROBLOSECURITY=<value>`). `value_holds_secret(value)` does the same for
    a setting value (text or a list of texts), `scrub_secrets(value)` returns a copy safe to show or export, and
    `PASTE_REFUSED_MESSAGE` is the refusal every writer answers with (it never repeats the value).

Why it exists
    Review finding constraints-1 (plan C4, 9.15 and 19.5): an owner who pastes the cookie into the wrong box (the
    downtime message, a pause reason, a public site text) would have Roxy serve it to every caller and write it to
    the settings export and the settings history, although the audit row of the same change is already redacted.
    Admin text is therefore refused when it holds a secret, before it is stored, and read models scrub what they
    show as a second line. Only real secrets count here: `redact_text`'s shape rules (`session: 5`, `token=x`) are
    right for log lines but would refuse or mangle ordinary help texts, so they are applied only to a text that
    already holds a secret.

How it works
    The registry snapshot gives the registered values and the ASCII lowercased 24 character windows of every
    substring-matched secret (`core/redact.py`); a text holds a secret when it contains a value, when one of its own
    24 character windows (ASCII lowercased) is in that set, or when it carries the token marker or a cookie
    assignment. Like `redact_text`, the text is also checked after percent-decoding (up to twice), so an encoded
    paste is caught too. Pure functions over the current snapshot: no lock, no I/O, cost linear in the text.

What to read next
    `roxy/core/redact.py` (the registry and the log-side redaction), `roxy/config/catalog.py validate_spec_value`
    (where every setting value is screened), `roxy/config/read_settings.py` (the history read model that scrubs).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import unquote

from roxy.core.redact import ROBLOX_COOKIE_NAME, SUBSTRING_WINDOW, TOKEN_PREFIX, SecretRegistry, redact_text

PASTE_REFUSED_MESSAGE: Final = (
    "Holds a secret Roxy keeps (part of the Roblox credential, a key or a password) or a Roblox cookie. Never paste "
    "a secret here: callers, exports and the change history would show it."
)
"""What a writer answers when admin text holds a secret. It names no part of the value."""

COOKIE_VALUE_MIN_CHARS: Final = 16
"""`.ROBLOSECURITY=` counts as a pasted cookie only with at least this many value characters after it, so a help
text that names the cookie (`.ROBLOSECURITY=...`) is not refused; a real cookie value is hundreds of characters."""

_MAX_DECODE_ROUNDS: Final = 2  # the same as `redact_text`: double encoding is still caught
_ASCII_LOWER: Final = {code: code + 32 for code in range(ord("A"), ord("Z") + 1)}  # keeps the length (windows)
_TOKEN_MARKER: Final = TOKEN_PREFIX[2:40].translate(_ASCII_LOWER)  # "warning:-do-not-share-this.--sharing-th"
_COOKIE_ASSIGNMENT: Final = re.compile(
    re.escape(ROBLOX_COOKIE_NAME) + r"\s*=\s*[^\s;,&\"'<>]{" + str(COOKIE_VALUE_MIN_CHARS) + ",}", re.IGNORECASE
)


def _holds_once(text: str) -> bool:
    snapshot = SecretRegistry.snapshot()
    if any(value in text for value in snapshot.values):
        return True
    folded = text.translate(_ASCII_LOWER)  # the windows are ASCII lowercased (the credential is hex)
    if _TOKEN_MARKER in folded or _COOKIE_ASSIGNMENT.search(text):
        return True
    windows = snapshot.windows
    if not windows or len(folded) < SUBSTRING_WINDOW:
        return False
    return any(
        folded[start : start + SUBSTRING_WINDOW] in windows for start in range(len(folded) - SUBSTRING_WINDOW + 1)
    )


def holds_secret(text: str) -> bool:
    """True when `text` carries a secret Roxy keeps or a Roblox cookie (see the module docstring)."""
    if not text:
        return False
    current = text
    for _ in range(_MAX_DECODE_ROUNDS + 1):
        if _holds_once(current):
            return True
        if "%" not in current:
            return False
        decoded = unquote(current)
        if decoded == current:
            return False
        current = decoded
    return False


def value_holds_secret(value: Any) -> bool:
    """`holds_secret` for a setting value: a text, or any text inside a list, tuple or mapping (numbers never)."""
    if isinstance(value, str):
        return holds_secret(value)
    if isinstance(value, list | tuple):
        return any(value_holds_secret(item) for item in value)
    if isinstance(value, Mapping):
        return any(value_holds_secret(item) for item in value.values())
    return False


def scrub_secrets(value: Any) -> Any:
    """`value` with every text that holds a secret passed through `redact_text` (lists and mappings walked).

    Text without a secret is returned unchanged, so what a read model shows stays exactly what was stored unless
    the stored text carries a secret (one written before the screening existed, or before the registry knew it).
    """
    if isinstance(value, str):
        return redact_text(value) if holds_secret(value) else value
    if isinstance(value, list | tuple):
        return [scrub_secrets(item) for item in value]
    if isinstance(value, Mapping):
        return {key: scrub_secrets(item) for key, item in value.items()}
    return value


__all__ = [
    "COOKIE_VALUE_MIN_CHARS",
    "PASTE_REFUSED_MESSAGE",
    "holds_secret",
    "scrub_secrets",
    "value_holds_secret",
]
