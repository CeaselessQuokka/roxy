"""Redaction: the helpers that keep secrets out of logs, captures, exports and the dashboard.

What this is
    Small pure functions that turn text which might contain a secret into text that cannot: `mask_token` and
    `masked_url` (the short labels v1 showed for tokens and proxy URLs), `redact_headers`, `redact_query`,
    `redact_text`, `redact_label` (the same scrub for short caller-supplied texts that repeat, such as endpoint
    templates and place ids, with a bounded memory of answers), and `fingerprint` (a keyed hash that identifies a
    secret without revealing it). Plus `SecretRegistry`, the process-wide list of secret values that must never be
    printed anywhere.

Why it exists
    Plan 9.15 and C2 item 8: the Roblox credential, the rotator password, session ids, CSRF tokens, TOTP and
    recovery codes must never reach a log line, an alert email, a capture or the LLM export, even at DEBUG level
    and even when a third-party library logs a whole request. Redaction is the last line of defense, so it is
    deliberately blunt: it would rather hide a harmless value than print a secret.

How it works
    Two complementary layers.
    1. Known values: code that loads a secret calls `SecretRegistry.register(name, value)`. `redact_text` replaces
       every registered value, and for the Roblox credential also every run of 24 or more characters that appears
       inside it (so a log line holding half of the cookie is still clean). Lookups use a precomputed set of all
       24 character windows, so scanning a line costs one set lookup per character. The windows ignore ASCII
       case (the credential is hex, and hex case is trivially reversible) and are built only from the part after
       the public `TOKEN_PREFIX`: the prefix is text anyone can type, and treating it as secret would let the
       window pass eat the prefix and hide a caller's own cookie from the shape rules below.
    2. Known shapes: patterns that look like secrets whatever their value: the Roblox `TOKEN_PREFIX` warning and
       the value after it, `.ROBLOSECURITY=...`, `user:password@` in URLs, `Cookie:`/`Authorization:` header lines,
       `key=value`, `"key": "value"` and `(b'key', b'value')` pairs whose key names a secret (password, token,
       session, csrf, codes, API keys), and the token segment of the `/admin/invalidate/<token>` kill-switch path.
       The shape rules run first, then the windows.
    Text that contains `%` is also checked after percent-decoding (twice, for double encoding): a query such as
    `x=.ROBLOSECURITY%3D<value>` or an encoded `TOKEN_PREFIX` would otherwise pass every rule untouched. When the
    decoded text holds something secret, the decoded text is what gets redacted and returned.
    The registry is copy on write: writers build a new immutable snapshot under a lock, readers (the logging filter,
    on any thread) just read the current snapshot, so logging never waits on a lock.
    Text that never passes through the log filter (metric dimensions, Live rows, event columns, hot.db keys) is
    scrubbed where it is made: `redact_label` for short repeated values, `redact_text` for the rest.

What to read next
    `roxy/core/logging.py` (the filter that applies `redact_text` to every log record), then
    `roxy/egress/credential.py` (the only module that reads and registers the credential).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus

MASK = "[redacted]"
"""What every redacted value is replaced with."""

TOKEN_PREFIX = (
    "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-"  # noqa: S105 (public text)
    "and-to-steal-your-ROBUX-and-items.|_"
)
"""The public warning text Roblox puts at the start of every `.ROBLOSECURITY` value (v1 `config.TOKEN_PREFIX`).

It is not a secret (anyone can type it), but whatever follows it is, so the text and the value after it are always
redacted, and `abuse/checks/auth_smuggling.py` refuses callers who send it (plan C2 item 5).
"""

ROBLOX_COOKIE_NAME = ".ROBLOSECURITY"

CREDENTIAL_SECRET_NAME = "roblox_credential"  # noqa: S105 (a registry key name, not a value)
"""Registry name the credential module uses. Secrets registered under it are also matched by 24+ char substrings."""

SUBSTRING_WINDOW = 24
"""Shortest run of characters from the credential that counts as a leak (plan 9.15 and C2 item 4)."""

MIN_SECRET_LENGTH = 8
"""Shorter values are not registered: replacing every "abc" in every log line would destroy the logs."""

_MAX_REGISTERED_NAMES = 64
_MAX_VALUES_PER_NAME = 3  # the current value plus the two before it, so a just-replaced secret stays hidden

# Header names whose values are always secret, whatever they contain (v1 `_SENSITIVE_HEADERS` plus Set-Cookie
# and Proxy-Authorization).
SENSITIVE_HEADER_NAMES = frozenset(
    {
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-csrf-token",
        "x-roblox-token",
    }
)

# Key names (lowercase) that are secret wherever they appear: form fields, JSON keys, query parameters, dict reprs.
_SENSITIVE_EXACT = frozenset(
    {
        "pass",
        "pwd",
        "otp",
        "session",
        "sid",
        "code_verifier",
        "client_secret",
        "roblosecurity",
        ".roblosecurity",
        # One-time codes under their bare names: v1's MFA field `TwoFA`, recovery codes. (A bare `code` is judged by
        # its value too, see `is_secret_field`: Roblox error bodies say `"code": 0` and that must stay readable.)
        "twofa",
        "2fa",
        "mfa",
        "passcode",
        "recovery",
    }
)

# Names whose value is a secret only when it is shaped like a one-time code (an emailed or TOTP code, a recovery
# code): at least 4 letters or digits, optionally in dash separated groups. Roblox's own error codes are small
# numbers (`{"errors": [{"code": 0, ...}]}`), which stay visible in captures and logs.
_CODE_NAMES = frozenset({"code"})
_ONE_TIME_CODE = re.compile(r"[A-Za-z0-9]{4,}(?:-[A-Za-z0-9]{2,})*")
# ...and key names that END with one of these (so `new_password`, `x-csrf-token` and `admin_session_id` match,
# while `bypass`, `cache_key` and `credential_status` do not).
_SENSITIVE_SUFFIXES = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "cookie",
    "authorization",
    "_session",
    "-session",
    "session_id",
    "sessionid",
    "csrf",
    "totp",
    "totp_code",
    "otp_code",
    "mfa_code",
    "email_code",
    "recovery_code",
    "recovery_codes",
    "verification_code",
    "api_key",
    "api-key",  # X-Api-Key: the header Roblox Open Cloud API keys travel in
    "apikey",
    "access_key",
    "access-key",
    "private_key",
    "private-key",
    "secret_key",
    "secret-key",
    "encryption_key",
    "hash_key",
    "_pass",
    "-pass",
    "roblosecurity",
)


def is_sensitive_key(name: str) -> bool:
    """True when a header, field or parameter NAME says its value is a secret."""
    lowered = name.strip().strip("\"'").lower()
    if not lowered:
        return False
    if lowered in SENSITIVE_HEADER_NAMES or lowered in _SENSITIVE_EXACT:
        return True
    return lowered.endswith(_SENSITIVE_SUFFIXES)


def is_secret_field(name: str, value: object) -> bool:
    """True when a field must be masked: its name says secret (`is_sensitive_key`), or it is a bare `code` whose
    value looks like a one-time code (`{"code": "123456"}`, not Roblox's `{"code": 0}`)."""
    if is_sensitive_key(name):
        return True
    if name.strip().strip("\"'").lower() not in _CODE_NAMES or isinstance(value, bool):
        return False
    return isinstance(value, str | int) and _ONE_TIME_CODE.fullmatch(str(value).strip()) is not None


@dataclass(frozen=True, slots=True)
class _Snapshot:
    """An immutable view of the registry: what `redact_text` replaces right now."""

    values: tuple[str, ...]  # every registered value, longest first (so a long value wins over its own prefix)
    windows: frozenset[str]  # every 24 character window of substring-matched secrets, ASCII lowercased


_EMPTY_SNAPSHOT = _Snapshot(values=(), windows=frozenset())


class SecretRegistry:
    """Process-wide list of secret values that must never be printed (DESIGN section 3).

    Use the class directly: `SecretRegistry.register("smtp_password", value)`. Values shorter than
    `MIN_SECRET_LENGTH` are ignored. The credential (registered as `CREDENTIAL_SECRET_NAME`, or any name with
    `match_substrings=True`) is also matched by every substring of 24 or more characters.
    """

    _lock = threading.Lock()
    _entries: dict[str, tuple[tuple[str, ...], bool]] = {}  # name -> (values newest first, match_substrings)
    _snapshot: _Snapshot = _EMPTY_SNAPSHOT

    @classmethod
    def register(cls, name: str, value: str | None, *, match_substrings: bool | None = None) -> None:
        """Remember `value` as a secret under `name`. Re-registering a name keeps the previous values too."""
        if not value or len(value) < MIN_SECRET_LENGTH:
            return
        substrings = (name == CREDENTIAL_SECRET_NAME) if match_substrings is None else match_substrings
        with cls._lock:
            previous, previous_substrings = cls._entries.get(name, ((), False))
            if name not in cls._entries and len(cls._entries) >= _MAX_REGISTERED_NAMES:
                # Bounded (plan P9). Dropping a secret silently would be worse than refusing loudly.
                raise RuntimeError("SecretRegistry is full; too many distinct secret names")
            values = (value, *(v for v in previous if v != value))[:_MAX_VALUES_PER_NAME]
            cls._entries[name] = (values, substrings or previous_substrings)
            cls._rebuild_locked()

    @classmethod
    def unregister(cls, name: str) -> None:
        """Forget every value registered under `name` (tests; production keeps old values hidden)."""
        with cls._lock:
            cls._entries.pop(name, None)
            cls._rebuild_locked()

    @classmethod
    def clear(cls) -> None:
        """Forget everything (tests only)."""
        with cls._lock:
            cls._entries.clear()
            cls._snapshot = _EMPTY_SNAPSHOT

    @classmethod
    def names(cls) -> list[str]:
        """Registered secret names (never the values), for the System page."""
        with cls._lock:
            return sorted(cls._entries)

    @classmethod
    def snapshot(cls) -> _Snapshot:
        # Reading a class attribute is atomic in CPython, so readers never need the lock.
        return cls._snapshot

    @classmethod
    def _rebuild_locked(cls) -> None:
        values: set[str] = set()
        windows: set[str] = set()
        for entry_values, substrings in cls._entries.values():
            values.update(entry_values)
            if substrings:
                for value in entry_values:
                    # Only the secret part: the public TOKEN_PREFIX in front of every cookie is not a secret.
                    secret = _ascii_lower(value.removeprefix(TOKEN_PREFIX))
                    for start in range(len(secret) - SUBSTRING_WINDOW + 1):
                        windows.add(secret[start : start + SUBSTRING_WINDOW])
        cls._snapshot = _Snapshot(
            values=tuple(sorted(values, key=len, reverse=True)),
            windows=frozenset(windows),
        )


# --- v1 compatible labels ------------------------------------------------------------------------------------------


def mask_token(value: str | None) -> str:
    """A short, non-reversible label for a token: an ellipsis plus the last 6 characters (v1 `proxy.mask_token`).

    The format is exactly v1's (`"…" + value[-6:]`), because it is shown on the dashboard and lands in exports
    that people compare across versions.
    """
    return f"…{(value or '')[-6:]}"


def masked_url(url: str | None) -> str:
    """A proxy URL with any `user:password@` removed, safe to show on the dashboard (v1 `rotate.masked_url`).

    Same output as v1 for every normal URL (`http://user:pass@host:port` becomes `http://host:port`, a URL
    without credentials is returned unchanged, and a credentialed value with no `scheme://` becomes empty). One
    deliberate difference: when the password itself contains "@", v1 kept everything after the FIRST "@", which
    printed the end of the password; this splits at the LAST "@", so only the host part survives.
    """
    if not url:
        return ""
    if "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    host = rest.rsplit("@", 1)[-1]
    return f"{scheme}://{host}" if scheme and scheme != url else host


def fingerprint(value: str | bytes, key: bytes) -> str:
    """A keyed fingerprint (HMAC-SHA256, first 16 hex characters) that identifies a secret without revealing it.

    Used in the audit log for secret changes (plan 6.2) and to compare credentials. Keyed, so the fingerprint of a
    guessed value cannot be computed by someone who only has the database.
    """
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hmac.new(key, data, hashlib.sha256).hexdigest()[:16]


# --- text redaction ------------------------------------------------------------------------------------------------

# str.translate table that lowercases A-Z only, so the text keeps its length (and every index stays valid).
_ASCII_LOWER = {code: code + 32 for code in range(ord("A"), ord("Z") + 1)}


def _ascii_lower(text: str) -> str:
    return text.translate(_ASCII_LOWER)


# The Roblox warning prefix and the cookie value that follows it (up to a delimiter). Case-insensitive: changing
# the case of a public marker must not be a way around it.
_TOKEN_RE = re.compile(re.escape(TOKEN_PREFIX) + r"[^\s;,&\"'<>]*", re.IGNORECASE)
_TOKEN_MARKER = _ascii_lower(TOKEN_PREFIX[2:40])  # "warning:-do-not-share-this..." for a cheap first test
# `.ROBLOSECURITY=<value>` in a cookie header, a Set-Cookie line or a dict repr.
_COOKIE_RE = re.compile(r"(\.ROBLOSECURITY\s*=\s*)[^\s;,&\"'<>]+", re.IGNORECASE)
# The kill-switch link `/admin/invalidate/<token>` (plan D9) keeps its token in the path; mask the token.
_INVALIDATE_PATH_RE = re.compile(r"(/admin/invalidate/)[^/?#\s\"'<>]+", re.IGNORECASE)
# `(b'x-csrf-token', b'...')` and `('authorization', 'Bearer ...')`: header pairs printed as a Python repr (an
# ASGI scope or httpcore's debug output). The callback decides by the name.
_TUPLE_PAIR_RE = re.compile(
    r"""(?P<prefix>\(\s*b?(?P<nq>['"])(?P<name>[^'"\\]{1,64})(?P=nq)\s*,\s*b?(?P<vq>['"]))"""
    # An escape pair, or one character that is neither the closing quote nor a backslash: the two alternatives can
    # never match the same text, so a long run of backslashes cannot make the engine backtrack.
    r"""(?P<value>(?:\\.|(?!(?P=vq))[^\\\n])*)(?P=vq)"""
)
_MAX_DECODE_ROUNDS = 2
# `scheme://user:password@` in any URL (the rotator URL embeds its password this way). Greedy up to the LAST "@"
# before the path, so a password that itself contains "@" is removed whole.
_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{0,15}://)[^\s/\"'<>]+@")
# Whole header lines whose value is secret, for logged raw requests. Linear time on any text (findings INGRESS-1
# and public-4): with MULTILINE, `^` matches after every line break, so the spaces around the name and the colon
# are `[^\S\n]*` (any whitespace except a line break) and can never run on into the following lines. With `\s*`
# there, text made of n line breaks (a caller's `%0A` run, decoded) cost about n * n / 2 steps on the event loop.
# One folded continuation line (`Cookie:` then a line starting with a space) is still covered by the bounded
# `(?:\n[^\S\n]+)?`.
_HEADER_LINE_RE = re.compile(
    r"(?im)^([^\S\n]*(?:cookie|set-cookie|authorization|proxy-authorization|x-csrf-token|x-roblox-token)"
    r"[^\S\n]*:[^\S\n]*(?:\n[^\S\n]+)?)(\S.*)$"
)
# `key=value`, `key: value`, `"key": "value"` and `'key': 'value'` pairs. The callback decides by the key name.
_PAIR_RE = re.compile(
    r"""(?P<prefix>(?P<kq>["']?)(?P<name>[A-Za-z_.][A-Za-z0-9_.\-]{0,63})(?P=kq)\s*[:=]\s*)"""
    r"""(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<bare>[^"'&\s,;}{\]\)]+))"""
)


def _redact_pair(match: re.Match[str]) -> str:
    value = match.group("dq") if match.group("dq") is not None else match.group("sq") or match.group("bare") or ""
    if not is_secret_field(match.group("name"), value):
        return match.group(0)
    prefix = match.group("prefix")
    if match.group("dq") is not None:
        return f'{prefix}"{MASK}"'
    if match.group("sq") is not None:
        return f"{prefix}'{MASK}'"
    bare = match.group("bare") or ""
    if bare.startswith("[redacted"):
        return match.group(0)  # already redacted by an earlier pass
    return prefix + MASK


def _redact_windows(text: str, windows: frozenset[str]) -> str:
    """Replace every run of text whose 24 character windows all come from the credential (ignoring ASCII case)."""
    n = len(text)
    if not windows or n < SUBSTRING_WINDOW:
        return text
    folded = _ascii_lower(text)  # same length as `text`, so positions found here are positions in `text`
    out: list[str] = []
    last = 0
    i = 0
    width = SUBSTRING_WINDOW
    while i <= n - width:
        if folded[i : i + width] in windows:
            end = i + width
            # Extend the match one character at a time while the trailing window is still part of a secret.
            while end < n and folded[end - width + 1 : end + 1] in windows:
                end += 1
            out.append(text[last:i])
            out.append(MASK)
            last = i = end
        else:
            i += 1
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def _redact_tuple_pair(match: re.Match[str]) -> str:
    if not is_secret_field(match.group("name"), match.group("value")):
        return match.group(0)
    return match.group("prefix") + MASK + match.group("vq")


def _redact_once(text: str) -> str:
    snap = SecretRegistry.snapshot()
    for value in snap.values:
        if value in text:
            text = text.replace(value, MASK)
    # The public markers first: a caller's own cookie after TOKEN_PREFIX (or after `.ROBLOSECURITY=`) is a secret
    # even though it is not Roxy's credential, and the marker is what finds it.
    if _TOKEN_MARKER in _ascii_lower(text):
        text = _TOKEN_RE.sub(MASK, text)
    text = _COOKIE_RE.sub(lambda m: m.group(1) + MASK, text)
    text = _redact_windows(text, snap.windows)
    text = _USERINFO_RE.sub(lambda m: m.group(1) + MASK + "@", text)
    text = _HEADER_LINE_RE.sub(lambda m: m.group(1) + MASK, text)
    text = _INVALIDATE_PATH_RE.sub(lambda m: m.group(1) + MASK, text)
    text = _TUPLE_PAIR_RE.sub(_redact_tuple_pair, text)
    return _PAIR_RE.sub(_redact_pair, text)


def redact_text(text: str) -> str:
    """Return `text` with every registered secret and every secret-shaped value replaced by `[redacted]`.

    Percent-encoded text is checked too: if decoding it (up to twice) reveals anything secret, the decoded text
    is redacted and returned instead, so an encoded marker or credential never survives (see the module
    docstring).
    """
    if not text:
        return text
    cleaned = _redact_once(text)
    current = cleaned
    for _ in range(_MAX_DECODE_ROUNDS):
        if "%" not in current:
            break
        decoded = unquote(current)
        if decoded == current:
            break
        redacted = _redact_once(decoded)
        if redacted != decoded:
            return redacted
        current = decoded
    return cleaned


def redact_path(path: str) -> str:
    """A request path safe to log or store: secret path segments (the kill-switch token) masked, secrets
    scrubbed."""
    return redact_text(path)


LABEL_CACHE_ENTRIES = 4096
"""Distinct labels `redact_label` remembers (plan P9); the whole memory is dropped when it is full."""

LABEL_CACHE_MAX_CHARS = 512
"""Longer texts are redacted every time and never remembered (they are not labels, and they would cost memory)."""


class _LabelCache:
    """`redact_text` answers for short texts that repeat, valid for one registry snapshot.

    The memory is a pair (snapshot, answers) swapped as one object, so a thread that sees a new snapshot starts an
    empty memory and can never read an answer computed before a secret was registered (that answer could miss the
    new secret). Lookups and inserts are single dict operations, atomic under the GIL, so no lock is needed.
    """

    def __init__(self, entries: int) -> None:
        self._entries = max(1, entries)
        self._state: tuple[_Snapshot, dict[str, str]] = (_EMPTY_SNAPSHOT, {})

    def redact(self, text: str) -> str:
        if len(text) > LABEL_CACHE_MAX_CHARS:
            return redact_text(text)
        snapshot = SecretRegistry.snapshot()
        state = self._state
        if state[0] is not snapshot:
            state = (snapshot, {})
            self._state = state
        answers = state[1]
        cleaned = answers.get(text)
        if cleaned is None:
            cleaned = redact_text(text)
            if len(answers) >= self._entries:
                answers.clear()  # bounded: forgetting only costs a recomputation
            answers[text] = cleaned
        return cleaned


_LABELS = _LabelCache(LABEL_CACHE_ENTRIES)


def redact_label(text: str) -> str:
    """`redact_text` for caller-supplied labels that repeat: endpoint templates, hosts, place ids, reason names.

    Such a text becomes a metric dimension, a Live row field, an event column or part of a hot.db key, where the
    log filter never sees it, so it must be scrubbed exactly like a log line (plan C1, 9.15): a credential piece a
    caller put in a path segment or in the `Roblox-Id` header must never be stored. The answer for an ordinary
    label is the label itself, unchanged. Answers are remembered per registry snapshot (`_LabelCache`), so the
    request path pays one dict lookup for a label it has seen before.
    """
    if not text:
        return text
    return _LABELS.redact(text)


def redact_query(query: str) -> str:
    """Redact a raw query string: secret-named parameters lose their value, and every value is scrubbed.

    The structure (order, separators, encoding of harmless values) is kept, so a redacted query is still useful
    for debugging: `user=1&password=x&token=y` becomes `user=1&password=[redacted]&token=[redacted]`. A value is
    judged after percent-decoding, so `x=.ROBLOSECURITY%3D...` or an encoded `TOKEN_PREFIX` loses its value too.
    """
    if not query:
        return query
    parts: list[str] = []
    for part in query.split("&"):
        name, sep, value = part.partition("=")
        plain_name = unquote_plus(name)
        if sep and is_secret_field(plain_name, unquote_plus(value)):
            parts.append(f"{name}={MASK}")
            continue
        if redact_text(plain_name) != plain_name:
            parts.append(MASK)  # the name itself carries the secret
            continue
        if sep:
            plain_value = unquote_plus(value)
            if redact_text(plain_value) != plain_value:
                parts.append(f"{name}={MASK}")
                continue
        parts.append(part)
    return redact_text("&".join(parts))


def _as_text(value: str | bytes) -> str:
    # ASGI headers are bytes in latin-1 (the HTTP header encoding); everything else is already text.
    return value.decode("latin-1") if isinstance(value, bytes) else str(value)


REDACTED_HEADER_NAME = "[redacted-header-{n}]"
"""What `redact_headers` stores in place of a header NAME that holds a secret (numbered, so two stay apart)."""


def redact_headers(
    headers: Mapping[str, str] | Mapping[bytes, bytes] | Iterable[tuple[str | bytes, str | bytes]],
    *,
    max_value_length: int | None = None,
) -> dict[str, str]:
    """A plain dict copy of `headers` with secret values replaced (v1 `capture.redact_headers` names and more).

    Accepts a mapping or (name, value) pairs, with str or ASGI bytes. Secret header names lose their whole value;
    every other value is scrubbed with `redact_text`. `max_value_length` clips long values (captures use 2000).
    A header NAME is caller text too (any HTTP token, so 40 characters of the credential make a valid name, and
    caller headers are never forwarded, so the leak guard never sees them): a name that `redact_label` changes is
    replaced by `[redacted-header-N]` and its value by `[redacted]` (finding cred-8, plan 9.15).
    """
    pairs: Iterable[tuple[str | bytes, str | bytes]]
    if isinstance(headers, Mapping):
        pairs = headers.items()
    else:
        pairs = headers
    out: dict[str, str] = {}
    hidden = 0
    for raw_name, raw_value in pairs:
        name = _as_text(raw_name)
        if redact_label(name) != name:
            hidden += 1
            out[REDACTED_HEADER_NAME.format(n=hidden)] = MASK
            continue
        if is_sensitive_key(name):
            out[name] = MASK
            continue
        value = redact_text(_as_text(raw_value))
        if max_value_length is not None and len(value) > max_value_length:
            value = value[:max_value_length]
        out[name] = value
    return out
