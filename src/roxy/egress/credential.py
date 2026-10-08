"""The Roblox credential: the one module that reads it, stores it, checks it, and puts it on a request.

What this is
    `CredentialManager` (`ctx.egress.credential`) owns the single Roblox `.ROBLOSECURITY` value (plan C1): where it
    comes from, whether it may be used right now, the fleet-wide cooldown, the one-at-a-time probe, the audited
    replace and delete actions, rotation detection, and the opaque `LeakMatcher` the leak guard uses.
    `CredentialSlot` is the store type: one optional value, never a list.

Why it exists
    Roblox ties rate limits and abuse scoring to account and IP together, so Roxy uses exactly one account, from
    the server IP only, never through the rotator, and never "the next token" (C1, C2). Keeping every read of
    the secret in this module makes that auditable: an AST test (19.5 item 7) fails the build if any other module
    references the loader. Every other module sees only fingerprints, masked labels and statuses.

How it works
    Sources and precedence (plan 9.8):
      1. A value set from the dashboard, stored AES-GCM encrypted in control.db `credential_store`. It wins.
      2. Otherwise the bootstrap systemd credential file `<credentials_dir>/roblox_credential`, read once at
         start (first non-empty line; extra lines are discarded and logged, masked: one slot, never a list).
         A bootstrap value whose fingerprint is in `credential_meta.superseded_fingerprints_json` is never used
         again: a UI replacement supersedes it, and only the audited "delete UI value" action un-supersedes it.
    Both sources go through `_validate_value`, which also removes a leading `.ROBLOSECURITY=`: browser tools copy
    the cookie as that pair, and the pair is unambiguous (a cookie value never starts with its own name), so Roxy
    stores, fingerprints and sends the bare value instead of refusing it. A value that still names the cookie after
    that is refused. The removal is logged without the value.
    Fingerprints are HMAC-SHA256 with a key derived from `credential_encryption_key`, so they identify a value
    without revealing it and cannot be checked offline.
    Status is `unknown` (never probed), `active`, `rejected`, or (computed) `cooling_down` while the fleet-wide
    cooldown row `credential` in hot.db is in the future. Ordinary allowlisted traffic needs `active`; probes may
    run while `unknown` or `rejected` (that is how a status is established) but never during a cooldown.
    Changes bump `service_state.credential_version`; every worker refreshes once a second and, before every
    credential request, re-reads the version, status and cooldown, so a replacement or a 429 cooldown applies
    fleet-wide at once. If control.db or hot.db cannot be read the credential is not used (C7). A cooldown that
    hot.db could not record (the 429 arrived during an outage) is kept in this worker's memory, merged with hot.db's
    row on every refresh, and written to hot.db by the first refresh that can write.
    `authorize(request)` is the only place the cookie is attached: after those checks, after validating that the
    target is https on an allowed Roblox host, as a per-request `Cookie` header (no cookie jar anywhere).
    `observe_set_cookie` sees `Set-Cookie` headers the credential client dropped; a `.ROBLOSECURITY` one means
    Roblox rotated the cookie: Roxy does not store it, it writes an audit row and raises the critical alert.
    `LeakMatcher` holds keyed hashes of 12 and 24 character pieces of the secret parts of each value, never the
    pieces, and finds any 24+ character run of a secret part in a byte string by sampling every 13th position (see
    `matches`). The secret parts are what is left after removing public text wherever it sits in the value (any
    run of 12 or more characters that the public `TOKEN_PREFIX` warning or `.ROBLOSECURITY=<warning>` contains,
    see `secret_spans`), so whatever was stored, text any caller can type never trips the leak guard (plan C2
    item 5). It covers the current value, the bootstrap value, recently replaced values and rotated cookies
    Roblox sent.

What to read next
    `roxy/egress/guard.py` (how the matcher is used), `roxy/egress/clients.py` (the credential client), and
    `roxy/config/audit.py` (why audit rows only ever hold `{fingerprint, masked}`).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import math
import re
import secrets
import sqlite3
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol

import httpx

from roxy.config import audit
from roxy.config.audit import Actor, secret_summary
from roxy.core.clock import Clock
from roxy.core.reasons import Egress
from roxy.core.redact import (
    CREDENTIAL_SECRET_NAME,
    ROBLOX_COOKIE_NAME,
    TOKEN_PREFIX,
    SecretRegistry,
    fingerprint,
    mask_token,
)
from roxy.egress.crypto import SealError, derive_key, seal, unseal
from roxy.egress.errors import (
    CredentialUnavailable,
    EgressDisabled,
    EgressError,
    TargetNotAllowed,
    UpstreamConnectError,
    UpstreamTimeout,
)
from roxy.egress.events import EventSink
from roxy.egress.models import PURPOSE_CREDENTIAL_PROBE, EgressResponse, OutboundRequest
from roxy.egress.targets import check_roblox_target, endpoint_label, is_loopback_host
from roxy.storage import leases
from roxy.storage.db import Databases, SharedStateUnavailable

log = logging.getLogger("roxy.egress.credential")

BOOTSTRAP_FILE_NAME = "roblox_credential"
"""The systemd credential with the bootstrap value (plan 9.8). Read here and nowhere else (test 19.5 item 7)."""

STORE_AAD = b"roxy:credential_store:v1"
FINGERPRINT_LABEL = b"roxy credential fingerprint v1"
VERSION_KEY = "credential_version"
COOLDOWN_KEY = "credential"
PROBE_LEASE = "probe:credential"
ROTATED_SECRET_NAME = "roblox_credential_rotated"  # noqa: S105 (a registry name, not a value)

MIN_VALUE_LENGTH = 32
MAX_VALUE_LENGTH = 4096
MAX_SUPERSEDED = 20
MAX_EXTRA_VALUES = 3
_MAX_BOOTSTRAP_FILE_BYTES = 64 * 1024
_FORBIDDEN_VALUE_CHARS = frozenset(';,"\\')
_KIND = re.compile(r"[a-z][a-z0-9_]{0,31}")

COOLDOWN_SOURCES = ("retry_after", "ratelimit_reset", "breaker", "default")
"""Allowed `cooldown.source` values (the hot.db CHECK constraint)."""

SCHEDULED_PROBE_KINDS = frozenset({"liveness"})
"""Probe kinds that are skipped while the credential is rejected (only an admin check re-tests a dead cookie)."""

ACTIVE = "active"
UNKNOWN = "unknown"
REJECTED = "rejected"
COOLING_DOWN = "cooling_down"
ABSENT = "absent"
UNAVAILABLE = "unavailable"
DISABLED = "disabled"

_EGRESS_ACTOR = Actor("system", "egress")


class CredentialValueError(ValueError):
    """A value offered as the credential is not a single, plausible cookie value."""


class CredentialStateError(RuntimeError):
    """The requested credential action does not apply to the current state (for example no UI value to delete)."""


_COOKIE_PAIR_PREFIX = ROBLOX_COOKIE_NAME.lower() + "="


def _clean_value(value: object) -> tuple[str, bool]:
    """The cleaned credential text and whether a leading `.ROBLOSECURITY=` was removed, or an error.

    Lists, tuples and multi-line text are refused (C1: one slot). The cookie pair form browser tools copy
    (`.ROBLOSECURITY=<value>`) is normalized to the bare value: the stored value is what Roxy puts after
    `.ROBLOSECURITY=` in the Cookie header, so keeping the name would send it twice and Roblox would reject it.
    """
    if not isinstance(value, str):
        raise TypeError("the credential is exactly one string; no API accepts a list of credentials (plan C1)")
    text = value.strip()
    if "\n" in text or "\r" in text:
        raise CredentialValueError("one credential only: the value must be a single line (plan C1)")
    named = text[: len(_COOKIE_PAIR_PREFIX)].lower() == _COOKIE_PAIR_PREFIX
    if named:
        text = text[len(_COOKIE_PAIR_PREFIX) :].strip()
    if ROBLOX_COOKIE_NAME.lower() in text.lower():
        raise CredentialValueError(
            "the value still contains the cookie name .ROBLOSECURITY; paste only the text after the equals sign"
        )
    if len(text) < MIN_VALUE_LENGTH or len(text) > MAX_VALUE_LENGTH:
        raise CredentialValueError(f"a credential is between {MIN_VALUE_LENGTH} and {MAX_VALUE_LENGTH} characters")
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E or ch in _FORBIDDEN_VALUE_CHARS for ch in text):
        raise CredentialValueError("the value has characters a cookie value cannot hold")
    return text, named


def _validate_value(value: object) -> str:
    """The cleaned credential text (see `_clean_value`), or an error."""
    return _clean_value(value)[0]


def _read_bootstrap_file(credentials_dir: Path | None) -> tuple[str | None, int]:
    """The first non-empty line of the bootstrap file and how many further lines were discarded (C1)."""
    if credentials_dir is None:
        return None, 0
    path = Path(credentials_dir) / BOOTSTRAP_FILE_NAME
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_BOOTSTRAP_FILE_BYTES)
    except FileNotFoundError:
        return None, 0
    except OSError as exc:
        log.error("credential_bootstrap_unreadable", extra={"fields": {"error": type(exc).__name__}})
        return None, 0
    lines = [line.strip() for line in raw.decode("utf-8", "replace").splitlines()]
    values = [line for line in lines if line]
    if not values:
        return None, 0
    return values[0], len(values) - 1


# --- the slot -----------------------------------------------------------------------------------------------------


class CredentialSlot:
    """Exactly one optional credential (plan C1). Setting a value replaces the previous one; there is no list."""

    __slots__ = ("_fingerprint", "_source", "_value")

    def __init__(self) -> None:
        self._value: str | None = None
        self._source: str | None = None
        self._fingerprint: str | None = None

    def set(self, value: str, *, source: str, value_fingerprint: str) -> None:
        """Put `value` in the slot, replacing whatever was there."""
        if not isinstance(value, str):
            raise TypeError("the credential slot holds one string, never a list (plan C1)")
        self._value = value
        self._source = source
        self._fingerprint = value_fingerprint

    def clear(self) -> None:
        self._value = None
        self._source = None
        self._fingerprint = None

    @property
    def is_set(self) -> bool:
        return self._value is not None

    @property
    def source(self) -> str | None:
        return self._source

    @property
    def fingerprint(self) -> str | None:
        return self._fingerprint

    def _reveal_credential(self) -> str | None:
        """The secret itself. Called only inside this module."""
        return self._value

    def __repr__(self) -> str:
        return f"CredentialSlot(set={self.is_set}, source={self._source!r})"

    def __reduce__(self) -> Any:
        raise TypeError("the credential slot cannot be pickled")


# --- the leak matcher ---------------------------------------------------------------------------------------------

PUBLIC_TEXTS: tuple[bytes, ...] = tuple(
    text.lower().encode("ascii") for text in (TOKEN_PREFIX, f"{ROBLOX_COOKIE_NAME}={TOKEN_PREFIX}")
)
"""Text any caller can type: the public warning Roblox puts in front of every cookie, and the cookie pair form.
Lowercased, because the matcher folds ASCII case."""

PUBLIC_RUN = 12
"""A run of at least this many characters of a stored value that public text contains is public, wherever it sits
in the value. Shorter runs are ignored: any 1 to 11 characters of a random secret can appear in the warning by
chance, and treating them as public would cut the real secret into pieces too small to watch."""


def _is_public(piece: bytes) -> bool:
    return any(piece in text for text in PUBLIC_TEXTS)


def secret_spans(value: str) -> list[tuple[int, int]]:
    """The `(start, end)` byte spans of `value` (UTF-8) that are secret: everything outside public runs.

    Finds, for each position, the longest run starting there that public text contains (at least `PUBLIC_RUN`
    long) and marks it public. A suffix of a public run is itself public, so each new run only has to be extended
    past the end of the previous one: the scan does about one substring test per byte. A span that public text
    contains as a whole (a short leftover such as `items.|_`) is dropped too.
    """
    data = value.encode("utf-8", "replace").lower()
    size = len(data)
    public = bytearray(size)
    end = 0  # the end of the last public run found
    for start in range(size - PUBLIC_RUN + 1):
        stop = max(end, start + PUBLIC_RUN)
        if not _is_public(data[start:stop]):
            continue
        while stop < size and _is_public(data[start : stop + 1]):
            stop += 1
        public[start:stop] = b"\x01" * (stop - start)
        end = stop
    spans: list[tuple[int, int]] = []
    start = 0
    while start < size:
        if public[start]:
            start += 1
            continue
        stop = start
        while stop < size and not public[stop]:
            stop += 1
        if not _is_public(data[start:stop]):
            spans.append((start, stop))
        start = stop
    return spans


class LeakMatcher:
    """Finds the credential, or any run of 24+ of its characters, in bytes, without holding the secret.

    Only the secret parts of each value are watched (`secret_spans`): public text is never "secret", whatever was
    stored, so a caller who types the public warning can never trip the guard (plan C2 item 5, finding F1).

    Correctness of the sampling: if the data holds a run of a secret part of length >= 24 starting at offset `s`,
    then some multiple `p` of 13 lies in `[s, s + 12]`, so `data[p:p+12]` lies inside the run and is a 12
    character piece of the secret (a "probe" hit). The 24 character windows starting at `p-12 .. p` include the
    one starting at `s`, which is a 24 character piece of the secret (a "window" hit). Both sets hold keyed
    BLAKE2b hashes with a random per-process key, so the matcher cannot be turned back into the secret.
    """

    WINDOW = 24
    PROBE = 12
    STEP = WINDOW - PROBE + 1  # 13
    MIN_SECRET = 8

    __slots__ = ("_count", "_key", "_long", "_short", "_whole")

    def __init__(self, values: Iterable[str]) -> None:
        self._key = secrets.token_bytes(16)
        self._short: set[bytes] = set()
        self._long: set[bytes] = set()
        self._whole: dict[int, set[bytes]] = {}
        self._count = 0
        for value in values:
            data = value.encode("utf-8", "replace").lower()
            for start, end in secret_spans(value):
                self._watch(data[start:end])

    def _watch(self, secret: bytes) -> None:
        """Add the hashes of one secret part (already ASCII lowercased)."""
        if len(secret) < self.MIN_SECRET:
            return
        self._count += 1
        if len(secret) < self.WINDOW:
            self._whole.setdefault(len(secret), set()).add(self._hash(secret))
            return
        for start in range(len(secret) - self.PROBE + 1):
            self._short.add(self._hash(secret[start : start + self.PROBE]))
        for start in range(len(secret) - self.WINDOW + 1):
            self._long.add(self._hash(secret[start : start + self.WINDOW]))

    def _hash(self, data: bytes) -> bytes:
        return hashlib.blake2b(data, key=self._key, digest_size=8).digest()

    @property
    def active(self) -> bool:
        """True when at least one secret is being watched for."""
        return self._count > 0

    def matches(self, data: bytes | str) -> bool:
        """True when `data` contains a watched secret or a 24+ character run of one (ASCII case ignored)."""
        if not self._count:
            return False
        folded = (data.encode("utf-8", "replace") if isinstance(data, str) else bytes(data)).lower()
        size = len(folded)
        if self._long:
            for probe in range(0, size - self.PROBE + 1, self.STEP):
                if self._hash(folded[probe : probe + self.PROBE]) not in self._short:
                    continue
                first = max(0, probe - (self.WINDOW - self.PROBE))
                last = min(probe, size - self.WINDOW)
                for start in range(first, last + 1):
                    if self._hash(folded[start : start + self.WINDOW]) in self._long:
                        return True
        for length, hashes in self._whole.items():
            for start in range(size - length + 1):
                if self._hash(folded[start : start + length]) in hashes:
                    return True
        return False

    def __repr__(self) -> str:
        return f"LeakMatcher(values={self._count})"

    def __reduce__(self) -> Any:
        raise TypeError("a leak matcher cannot be pickled")


# --- results ------------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CredentialStatus:
    """Everything the dashboard and the health check may know about the credential. Never the value."""

    enabled: bool
    present: bool
    source: str | None
    status: str
    masked: str | None
    fingerprint: str | None
    account_id_fingerprint: str | None
    cooldown_remaining_s: float
    set_at: int | None
    set_by: str | None
    last_probe_at: int | None
    last_probe_result: dict[str, Any] | None
    problem: str | None
    version: int
    bootstrap_present: bool
    bootstrap_superseded: bool
    ui_value_present: bool


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The outcome of one credential probe (H-CRED-AUTH, the liveness job, the Check credential button)."""

    kind: str
    outcome: str
    status_code: int | None = None
    retry_after_s: int | None = None
    account_match: bool | None = None
    latency_ms: float | None = None
    at: int = 0

    @property
    def ok(self) -> bool:
        return self.outcome in ("ok", "ok_no_account_id")


@dataclass(frozen=True, slots=True)
class GuardSelfTestKit:
    """Synthetic credential-bearing requests for the H-CRED-GUARD self-test (plan 13.2).

    They exist only to be refused by a guard in-process; they are never sent. `synthetic` is True when no
    credential is configured and a random stand-in was used to test the mechanism.
    """

    requests: tuple[httpx.Request, ...]
    matcher: LeakMatcher
    synthetic: bool


class ProbeAnswer(Protocol):
    """What a probe fetch returns: an `EgressResponse`, or the upstream layer's `ProbeResponse` (the same fields),
    which is what `UpstreamService.credential_probe_fetch` hands back after pacing the probe through its buckets."""

    @property
    def status(self) -> int: ...

    @property
    def headers(self) -> httpx.Headers: ...

    @property
    def body(self) -> bytes: ...


ProbeFetch = Callable[[str], Awaitable[ProbeAnswer]]
Sender = Callable[[OutboundRequest], Awaitable[EgressResponse]]


def _row_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()} if row is not None else {}  # noqa: SIM118 (sqlite3.Row)


def _json_list(text: Any) -> list[str]:
    try:
        value = json.loads(text) if isinstance(text, str) else []
    except ValueError:
        return []
    return [str(item) for item in value] if isinstance(value, list) else []


def _json_obj(text: Any) -> dict[str, Any] | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        return {"result": text[:64]}
    return value if isinstance(value, dict) else None


def bump_version(conn: sqlite3.Connection, key: str, now_s: int) -> int:
    """Increment the `service_state` counter `key` (creating it at 1) and return the new value."""
    conn.execute(
        "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, '1', ?) "
        "ON CONFLICT(key) DO UPDATE SET value_json = CAST(CAST(service_state.value_json AS INTEGER) + 1 AS TEXT), "
        "updated_at = excluded.updated_at",
        (key, now_s),
    )
    row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (key,)).fetchone()
    return int(json.loads(row[0])) if row is not None else 0


def read_version(conn: sqlite3.Connection, key: str) -> int:
    """The `service_state` counter `key` (0 when missing)."""
    row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (key,)).fetchone()
    if row is None:
        return 0
    try:
        return int(json.loads(row[0]))
    except (TypeError, ValueError):
        return 0


def retry_after_seconds(value: str | None, now_s: float) -> float | None:
    """`Retry-After` as seconds: delta seconds or an HTTP date (RFC 9110). None when missing or unparsable."""
    if not value:
        return None
    text = value.strip()
    if text.isdigit():
        return float(int(text))
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if moment is None:
        return None
    return max(0.0, moment.timestamp() - now_s)


def _account_id(body: bytes) -> str | None:
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("id")
    if isinstance(value, bool) or not isinstance(value, int | str):
        return None
    text = str(value).strip()
    return text if text.isdigit() else None


_UNCHANGED = object()


class CredentialManager:
    """The one credential (see the module docstring). Built and started by `EgressClients`."""

    def __init__(
        self,
        *,
        credentials_dir: Path | None,
        dbs: Databases,
        settings: Any,
        clock: Clock,
        worker_id: str,
        encryption_key: bytes | None,
        events: EventSink,
        allow_loopback_target: bool = False,
    ) -> None:
        self._credentials_dir = credentials_dir
        self._dbs = dbs
        self._settings = settings
        self._clock = clock
        self._worker_id = worker_id
        self._key = encryption_key
        # A key per job: the fingerprint key is derived, never the encryption key itself.
        self._fp_key = (
            derive_key(encryption_key, FINGERPRINT_LABEL)
            if encryption_key is not None
            else hashlib.sha256(FINGERPRINT_LABEL + b" without an encryption key").digest()
        )
        self._events = events
        self._allow_loopback_target = allow_loopback_target
        self._sender: Sender | None = None
        self._slot = CredentialSlot()
        self._bootstrap: str | None = None
        self._bootstrap_fp: str | None = None
        self._bootstrap_problem: str | None = None
        self._extra_values: deque[str] = deque(maxlen=MAX_EXTRA_VALUES)
        self._matcher = LeakMatcher(())
        self._matcher_values: tuple[str, ...] = ()
        self._version = -1
        self._meta: dict[str, Any] = {}
        self._ui_present = False
        self._cooldown_until_ms = 0
        # A cooldown opened while hot.db could not be written: (until_ms, source). Honored here until hot.db takes
        # it, so a refresh that reads hot.db's (older) row never forgets it (C7, finding UP-COOLDOWN-LOST).
        self._pending_cooldown: tuple[int, str] | None = None
        self._problem: str | None = None
        self._degraded = False
        self._started = False

    # --- settings -------------------------------------------------------------------------------------------------

    def _setting(self, key: str, default: Any) -> Any:
        try:
            return self._settings.get(key)
        except (KeyError, LookupError, AttributeError):
            return default

    @property
    def enabled(self) -> bool:
        """The `credential_enabled` switch."""
        return bool(self._setting("credential_enabled", 1))

    def set_sender(self, sender: Sender) -> None:
        """Install the function probes use to send (EgressClients wires the credential client here)."""
        self._sender = sender

    def fingerprint_of(self, value: str) -> str:
        """The keyed fingerprint Roxy would record for `value` (to compare a pasted value; never stored)."""
        return fingerprint(value, self._fp_key)

    # --- startup and refresh --------------------------------------------------------------------------------------

    async def start(self) -> None:
        """Read the bootstrap file once, reconcile `credential_meta` with it, and load the current state."""
        value, discarded = await asyncio.to_thread(_read_bootstrap_file, self._credentials_dir)
        if discarded:
            # C1: a multi-line file is not a list of credentials. Only the first line counts.
            log.warning(
                "credential_bootstrap_extra_lines_discarded",
                extra={"fields": {"discarded": discarded, "kept": mask_token(value)}},
            )
        if value is not None:
            try:
                self._bootstrap, named = _clean_value(value)
            except (TypeError, CredentialValueError) as exc:
                self._bootstrap_problem = "bootstrap_invalid"
                log.error("credential_bootstrap_invalid", extra={"fields": {"error": str(exc)[:120]}})
            else:
                if named:
                    # The file holds the pair browser tools copy; the bare value is used. Never log the value.
                    log.warning("credential_cookie_name_removed", extra={"fields": {"source": "bootstrap"}})
                self._bootstrap_fp = fingerprint(self._bootstrap, self._fp_key)
                SecretRegistry.register(CREDENTIAL_SECRET_NAME, self._bootstrap)
        try:
            await self._dbs.control.write(self._sync_bootstrap_meta)
        except SharedStateUnavailable as exc:
            log.warning("credential_meta_sync_skipped", extra={"fields": {"error": str(exc)[:200]}})
        self._started = True
        await self.refresh(force=True)

    def _sync_bootstrap_meta(self, conn: sqlite3.Connection) -> bool:
        """Keep `credential_meta` describing the bootstrap value while no UI value exists (one transaction)."""
        if conn.execute("SELECT 1 FROM credential_store WHERE id = 1").fetchone() is not None:
            return False
        meta = _row_dict(conn.execute("SELECT * FROM credential_meta WHERE id = 1").fetchone())
        superseded = _json_list(meta.get("superseded_fingerprints_json"))
        now = int(self._clock.now())
        current_fp = meta.get("fingerprint")
        if self._bootstrap is None or self._bootstrap_fp is None:
            if current_fp is None or meta.get("set_by") != "bootstrap":
                return False
            conn.execute(
                "UPDATE credential_meta SET fingerprint = NULL, masked = NULL, status = 'unknown', status_at = ? "
                "WHERE id = 1",
                (now,),
            )
            audit.record(
                conn,
                _EGRESS_ACTOR,
                "credential.bootstrap_removed",
                "credential",
                {"fingerprint": current_fp, "masked": meta.get("masked") or ""},
                None,
                "the bootstrap credential file is gone",
                None,
                at=now,
            )
            bump_version(conn, VERSION_KEY, now)
            return True
        if self._bootstrap_fp in superseded or self._bootstrap_fp == current_fp:
            return False
        after = {"fingerprint": self._bootstrap_fp, "masked": mask_token(self._bootstrap)}
        if not meta:
            conn.execute(
                "INSERT INTO credential_meta (id, fingerprint, masked, superseded_fingerprints_json, set_at, set_by, "
                "status, status_at) VALUES (1, ?, ?, '[]', ?, 'bootstrap', 'unknown', ?)",
                (self._bootstrap_fp, after["masked"], now, now),
            )
            action, before = "credential.bootstrap_loaded", None
        else:
            # The file changed while no UI value exists. The account fingerprint is kept on purpose: the next probe
            # compares accounts, so a file holding another account's cookie is caught (an account switch, C1).
            conn.execute(
                "UPDATE credential_meta SET fingerprint = ?, masked = ?, set_at = ?, set_by = 'bootstrap', "
                "status = 'unknown', status_at = ?, last_probe_result = NULL WHERE id = 1",
                (self._bootstrap_fp, after["masked"], now, now),
            )
            action = "credential.bootstrap_changed"
            before = {"fingerprint": current_fp, "masked": meta.get("masked") or ""} if current_fp else None
        audit.record(conn, _EGRESS_ACTOR, action, "credential", before, after, "read at service start", None, at=now)
        bump_version(conn, VERSION_KEY, now)
        return True

    def _read_control(
        self, conn: sqlite3.Connection, known_version: int, force: bool
    ) -> tuple[int, dict[str, Any], Any]:
        version = read_version(conn, VERSION_KEY)
        meta = _row_dict(conn.execute("SELECT * FROM credential_meta WHERE id = 1").fetchone())
        store: Any = _UNCHANGED
        if force or version != known_version:
            row = conn.execute("SELECT ciphertext, nonce FROM credential_store WHERE id = 1").fetchone()
            store = (bytes(row[0]), bytes(row[1])) if row is not None else None
        return version, meta, store

    @staticmethod
    def _read_cooldown(conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT until_ms FROM cooldown WHERE key = ?", (COOLDOWN_KEY,)).fetchone()
        return int(row[0]) if row is not None else 0

    async def _load(self, *, force: bool) -> None:
        known = self._version
        version, meta, store = await self._dbs.control.read(lambda conn: self._read_control(conn, known, force))
        cooldown = await self._dbs.hot.read(self._read_cooldown)
        self._apply(version, meta, store, cooldown)

    async def refresh(self, *, force: bool = False) -> bool:
        """Re-read version, metadata and cooldown (and the stored value when the version moved). False when shared
        state was unreadable: the credential is then unusable until a read succeeds (C7)."""
        await self._share_pending_cooldown()
        try:
            await self._load(force=force)
        except SharedStateUnavailable as exc:
            if not self._degraded:
                log.warning("credential_state_unavailable", extra={"fields": {"error": str(exc)[:200]}})
            self._degraded = True
            return False
        self._degraded = False
        return True

    async def _share_pending_cooldown(self) -> None:
        """Write a cooldown kept in memory during a hot.db outage into hot.db, once hot.db takes writes again."""
        pending = self._pending_cooldown
        if pending is None:
            return
        until_ms, source = pending
        now_ms = self._clock.now_ms()
        if until_ms <= now_ms:
            self._pending_cooldown = None
            return
        try:
            await self._dbs.hot.write(lambda conn: self._write_cooldown(conn, until_ms, source, now_ms))
        except SharedStateUnavailable:
            return  # still unwritable: it stays in memory and keeps blocking the credential in this worker
        if self._pending_cooldown == pending:
            self._pending_cooldown = None
        log.info("credential_cooldown_shared", extra={"fields": {"remaining_s": round((until_ms - now_ms) / 1000)}})

    def _apply(self, version: int, meta: dict[str, Any], store: Any, cooldown_until_ms: int) -> None:
        self._meta = meta
        pending = self._pending_cooldown[0] if self._pending_cooldown is not None else 0
        self._cooldown_until_ms = max(cooldown_until_ms, pending)
        if store is not _UNCHANGED:
            self._resolve_slot(store, meta)
        self._version = version

    def _resolve_slot(self, store: tuple[bytes, bytes] | None, meta: dict[str, Any]) -> None:
        previous = self._slot._reveal_credential()
        self._problem = None
        self._ui_present = store is not None
        if store is not None:
            if self._key is None:
                self._problem = "encryption_key_missing"
                self._slot.clear()
            else:
                try:
                    value = unseal(self._key, store[1], store[0], STORE_AAD).decode("utf-8")
                except (SealError, UnicodeDecodeError):
                    self._problem = "ui_value_unreadable"
                    self._slot.clear()
                else:
                    SecretRegistry.register(CREDENTIAL_SECRET_NAME, value)
                    self._slot.set(value, source="ui", value_fingerprint=fingerprint(value, self._fp_key))
        elif self._bootstrap is not None and self._bootstrap_fp is not None:
            superseded = _json_list(meta.get("superseded_fingerprints_json"))
            if self._key is None and superseded:
                # Superseded fingerprints were made with the keyed fingerprint; without the key Roxy cannot prove
                # this bootstrap value is not one of them, so it is not used (fail closed, C1).
                self._problem = "cannot_verify_bootstrap"
                self._slot.clear()
            elif self._bootstrap_fp in superseded:
                self._problem = "bootstrap_superseded"
                self._slot.clear()
            else:
                self._slot.set(self._bootstrap, source="bootstrap", value_fingerprint=self._bootstrap_fp)
        else:
            self._problem = self._bootstrap_problem
            self._slot.clear()
        current = self._slot._reveal_credential()
        if previous is not None and previous != current:
            self._extra_values.append(previous)
        self._rebuild_matcher()
        if self._problem in ("bootstrap_superseded", "cannot_verify_bootstrap", "encryption_key_missing"):
            log.error("credential_not_loaded", extra={"fields": {"problem": self._problem}})

    def _rebuild_matcher(self) -> None:
        values = tuple(
            dict.fromkeys(
                v for v in (self._slot._reveal_credential(), self._bootstrap, *self._extra_values) if v is not None
            )
        )
        if values != self._matcher_values:
            self._matcher_values = values
            self._matcher = LeakMatcher(values)

    def leak_matcher(self) -> LeakMatcher:
        """The opaque matcher for the guard: current, bootstrap, recently replaced and rotated values."""
        return self._matcher

    # --- status ---------------------------------------------------------------------------------------------------

    def cooldown_remaining(self) -> float:
        """Seconds until the fleet-wide credential cooldown ends (0 when none), from the last refresh."""
        return max(0.0, (self._cooldown_until_ms - self._clock.now_ms()) / 1000.0)

    def _effective_status(self) -> str:
        if not self.enabled:
            return DISABLED
        if self._degraded:
            return UNAVAILABLE
        if not self._slot.is_set:
            return UNAVAILABLE if self._problem else ABSENT
        stored = str(self._meta.get("status") or UNKNOWN)
        if stored == REJECTED:
            return REJECTED
        if self.cooldown_remaining() > 0:
            return COOLING_DOWN
        if stored in (ACTIVE, COOLING_DOWN):
            return ACTIVE
        return UNKNOWN

    def available(self) -> bool:
        """True when allowlisted traffic may use the credential now (active, not cooling down, state readable)."""
        return self._effective_status() == ACTIVE

    def probe_allowed(self) -> bool:
        """True when a probe may use the credential now (present, enabled, not cooling down, state readable)."""
        return self._effective_status() in (ACTIVE, UNKNOWN, REJECTED)

    def status(self) -> CredentialStatus:
        """The current status, from the last refresh (DESIGN.md 11.4 `status()`)."""
        superseded = _json_list(self._meta.get("superseded_fingerprints_json"))
        return CredentialStatus(
            enabled=self.enabled,
            present=self._slot.is_set,
            source=self._slot.source,
            status=self._effective_status(),
            masked=self._meta.get("masked") if self._slot.is_set else None,
            fingerprint=self._slot.fingerprint,
            account_id_fingerprint=self._meta.get("account_id_fingerprint"),
            cooldown_remaining_s=round(self.cooldown_remaining(), 3),
            set_at=self._meta.get("set_at"),
            set_by=self._meta.get("set_by"),
            last_probe_at=self._meta.get("last_probe_at"),
            last_probe_result=_json_obj(self._meta.get("last_probe_result")),
            problem="degraded" if self._degraded else self._problem,
            version=self._version,
            bootstrap_present=self._bootstrap is not None,
            bootstrap_superseded=self._bootstrap_fp is not None and self._bootstrap_fp in superseded,
            ui_value_present=self._ui_present,
        )

    # --- using the credential ---------------------------------------------------------------------------------------

    async def _authoritative_check(self, *, probe: bool) -> None:
        """Re-read shared state and raise `CredentialUnavailable` unless the credential may be used right now."""
        await self._share_pending_cooldown()
        try:
            await self._load(force=False)
        except SharedStateUnavailable as exc:
            self._degraded = True
            raise CredentialUnavailable("degraded", 10) from exc
        self._degraded = False
        status = self._effective_status()
        if status == DISABLED:
            raise CredentialUnavailable("disabled", 300)
        if status in (ABSENT, UNAVAILABLE):
            raise CredentialUnavailable(self._problem or "absent", 300)
        if status == COOLING_DOWN:
            raise CredentialUnavailable("cooling_down", max(1, math.ceil(self.cooldown_remaining())))
        if status == REJECTED and not probe:
            raise CredentialUnavailable("rejected", 300)
        if status == UNKNOWN and not probe:
            raise CredentialUnavailable("not_confirmed", 300)

    async def authorize(self, request: httpx.Request, *, logical_url: httpx.URL, probe: bool) -> None:
        """Attach the cookie to `request` (the ONLY place that does), after every check (module docstring).

        `logical_url` is the Roblox URL being called; `request.url` is where the bytes actually go, which differs
        only under the development test override (then it must be a loopback address).
        """
        await self._authoritative_check(probe=probe)
        checked = check_roblox_target(
            logical_url,
            egress=Egress.CREDENTIAL,
            allowed_hosts=tuple(self._setting("allowed_roblox_hosts", ())),
            strict=True,
            require_listed=True,
        )
        actual = request.url
        same_target = actual.scheme == "https" and actual.host == checked.host and actual.port in (None, 443)
        test_target = self._allow_loopback_target and is_loopback_host(actual.host)
        if not (same_target or test_target):
            raise TargetNotAllowed(Egress.CREDENTIAL, "the request does not go to the checked Roblox host")
        value = self._slot._reveal_credential()
        if value is None:
            raise CredentialUnavailable("absent", 300)
        # One header per request from the slot: every worker uses exactly the current value (C2 item 7).
        request.headers["Cookie"] = f"{ROBLOX_COOKIE_NAME}={value}"

    async def observe_set_cookie(self, set_cookie_values: list[str], *, endpoint: str) -> None:
        """React to `Set-Cookie` headers the credential client dropped (plan C1: rotation is never stored)."""
        rotated: str | None = None
        for raw in set_cookie_values:
            name, sep, rest = raw.partition("=")
            if sep and name.strip().lower() == ROBLOX_COOKIE_NAME.lower():
                candidate = rest.split(";", 1)[0].strip().strip('"')
                if candidate:
                    rotated = candidate
        if rotated is None:
            return
        rotated_fp = fingerprint(rotated, self._fp_key)
        if rotated_fp == self._slot.fingerprint:
            return  # Roblox re-sent the same cookie: nothing changed
        SecretRegistry.register(ROTATED_SECRET_NAME, rotated, match_substrings=True)
        self._extra_values.append(rotated)
        self._rebuild_matcher()
        summary = secret_summary(rotated, self._fp_key, credential=True)
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> int:
            return audit.record(
                conn,
                _EGRESS_ACTOR,
                "credential.rotation_seen",
                "credential",
                None,
                summary,
                f"Roblox sent a new credential cookie on {endpoint}; not stored (C1)",
                None,
                at=now,
            )

        try:
            await self._dbs.control.write(write)
        except SharedStateUnavailable as exc:
            log.error("credential_rotation_audit_failed", extra={"fields": {"error": str(exc)[:200]}})
        self._events.alert(
            type="credential_rotated",
            severity="critical",
            subject="Roxy: Roblox sent a new credential cookie",
            summary="Roblox answered a credential request with a new login cookie. Roxy did not store it.",
            fields={
                "endpoint": endpoint,
                "new_cookie_fingerprint": summary["fingerprint"] if summary else "",
                "what_to_do": "If you want to use the new cookie, paste it on the Credential page (Replace).",
            },
            cooldown_key="credential:rotated",
            cooldown_s=3600,
        )
        self._events.event("credential_rotated", "critical", "credential", {"endpoint": endpoint})

    # --- cooldown, rejection --------------------------------------------------------------------------------------

    async def set_cooldown(self, seconds: float, source: str) -> float:
        """Open (or extend) the fleet-wide credential cooldown; returns the seconds remaining.

        Never shortens an existing cooldown. If hot.db cannot be written the cooldown is kept in this worker's
        memory, blocks the credential here (every refresh merges it with hot.db's row), and is written to hot.db
        by the next refresh that can write (C7: the credential is not used inside Roblox's Retry-After).
        """
        if source not in COOLDOWN_SOURCES:
            raise ValueError(f"cooldown source must be one of {', '.join(COOLDOWN_SOURCES)}")
        span_ms = int(max(1.0, float(seconds)) * 1000)
        now_ms = self._clock.now_ms()
        until_ms = now_ms + span_ms

        try:
            until_ms = await self._dbs.hot.write(lambda conn: self._write_cooldown(conn, until_ms, source, now_ms))
        except SharedStateUnavailable as exc:
            self._degraded = True
            kept = self._pending_cooldown
            if kept is None or kept[0] < until_ms:
                self._pending_cooldown = (until_ms, source)
            log.error("credential_cooldown_not_shared", extra={"fields": {"error": str(exc)[:200]}})
        self._cooldown_until_ms = max(self._cooldown_until_ms, until_ms)
        remaining = self.cooldown_remaining()
        self._events.event(
            "credential_cooldown", "warn", "upstream_cooldown", {"seconds": round(remaining, 1), "source": source}
        )
        if remaining >= 600:
            self._events.alert(
                type="credential_cooldown",
                severity="warn",
                subject="Roxy: credential cooling down",
                summary=f"The Roblox credential is resting for {int(remaining)} s after a rate limit.",
                fields={"remaining_s": int(remaining), "source": source},
                cooldown_key="credential:cooldown",
                cooldown_s=600,
            )
        return remaining

    @staticmethod
    def _write_cooldown(conn: sqlite3.Connection, until_ms: int, source: str, now_ms: int) -> int:
        """Open or extend the fleet-wide `credential` cooldown row (never shortened); returns its end."""
        row = conn.execute("SELECT until_ms FROM cooldown WHERE key = ?", (COOLDOWN_KEY,)).fetchone()
        target = max(until_ms, int(row[0]) if row is not None else 0)
        conn.execute(
            "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, ?, ?, 1) "
            "ON CONFLICT(key) DO UPDATE SET until_ms = excluded.until_ms, source = excluded.source, "
            "set_at = excluded.set_at, hits = cooldown.hits + 1",
            (COOLDOWN_KEY, target, source, now_ms // 1000),
        )
        return target

    async def mark_rejected(self, reason: str, *, request_id: str | None = None) -> None:
        """Mark the credential rejected (after the upstream layer's confirming probe, plan 7.9) and alert."""
        await self._set_status(REJECTED, {"result": "rejected", "reason": reason[:80]}, request_id=request_id)
        self._alert_rejected(reason[:80])

    def _alert_rejected(self, outcome: str) -> None:
        self._events.alert(
            type="credential_rejected",
            severity="critical",
            subject="Token Expired",
            summary=f'An auth token has expired: "{self._meta.get("masked") or mask_token(None)}".',
            fields={"status": REJECTED, "result": outcome, "page": "credential#status"},
            cooldown_key="credential:rejected",
            cooldown_s=int(self._setting("email_cooldown", 600)),
        )

    async def _set_status(
        self,
        status: str,
        result: dict[str, Any] | None,
        *,
        request_id: str | None = None,
        account_fp: str | None = None,
        probed_at: int | None = None,
    ) -> None:
        now = int(self._clock.now())
        result_text = json.dumps(result, sort_keys=True)[:400] if result is not None else None

        def write(conn: sqlite3.Connection) -> None:
            meta = _row_dict(
                conn.execute("SELECT status, account_id_fingerprint FROM credential_meta WHERE id = 1").fetchone()
            )
            if not meta:
                return
            before = str(meta.get("status") or UNKNOWN)
            account_changed = account_fp is not None and account_fp != meta.get("account_id_fingerprint")
            conn.execute(
                "UPDATE credential_meta SET status = ?, status_at = CASE WHEN status = ? THEN status_at ELSE ? END, "
                "last_probe_result = coalesce(?, last_probe_result), "
                "last_probe_at = coalesce(?, last_probe_at), "
                "account_id_fingerprint = coalesce(?, account_id_fingerprint) WHERE id = 1",
                (status, status, now, result_text, probed_at, account_fp),
            )
            if before != status or account_changed:
                audit.record(
                    conn,
                    _EGRESS_ACTOR,
                    "credential.status",
                    "credential_status",
                    {"status": before},
                    {"status": status, "result": (result or {}).get("result")},
                    None,
                    request_id,
                    at=now,
                )
                bump_version(conn, VERSION_KEY, now)

        try:
            await self._dbs.control.write(write)
        except SharedStateUnavailable as exc:
            log.error("credential_status_not_saved", extra={"fields": {"error": str(exc)[:200], "status": status}})
        await self.refresh()

    # --- probes -----------------------------------------------------------------------------------------------------

    async def _default_fetch(self, url: str) -> EgressResponse:
        if self._sender is None:
            raise EgressDisabled(Egress.CREDENTIAL, "no sender installed")
        timeout = httpx.Timeout(
            connect=float(self._setting("upstream_connect_timeout_s", 5)),
            read=float(self._setting("request_timeout", 15)),
            write=10.0,
            pool=5.0,
        )
        out = OutboundRequest(
            method="GET",
            url=url,
            headers={},
            content=None,
            timeout=timeout,
            purpose=PURPOSE_CREDENTIAL_PROBE,
            follow_redirects=False,
        )
        return await self._sender(out)

    async def probe(self, kind: str = "admin_check", *, fetch: ProbeFetch | None = None) -> ProbeResult:
        """Check the credential against `credential_probe_url`, one probe at a time fleet-wide (lease).

        `fetch` lets the upstream layer route the probe through its buckets (the reserved probe sub-bucket,
        plan 7.3); the default sends it straight through the credential client. A 429 is "rate limited" and
        opens the cooldown, never "expired" (parity row 25); 401 or 403 is rejected; a 200 whose account id
        differs from the recorded one is an account switch (C1) and needs `confirm_account`.
        """
        if not _KIND.fullmatch(kind):
            raise ValueError("probe kind must be a short lowercase name")
        now = int(self._clock.now())
        if not self.enabled:
            return ProbeResult(kind, "disabled", at=now)
        if not await self.refresh():
            return ProbeResult(kind, "degraded", at=now)
        status = self._effective_status()
        if status in (ABSENT, UNAVAILABLE):
            return ProbeResult(kind, self._problem or "absent", at=now)
        if status == COOLING_DOWN:
            return ProbeResult(kind, "cooling_down", retry_after_s=math.ceil(self.cooldown_remaining()), at=now)
        if status == REJECTED and kind in SCHEDULED_PROBE_KINDS:
            return ProbeResult(kind, "skipped_rejected", at=now)
        holder = f"{self._worker_id}#{secrets.token_hex(4)}"
        # Long enough for the slowest legitimate probe: the internal queue wait (the upstream layer's buckets), the
        # connect and read timeouts, and a margin. A crashed holder's lease expires on its own after this.
        ttl_s = (
            float(self._setting("queue_wait_internal_ms", 30_000)) / 1000.0
            + float(self._setting("upstream_connect_timeout_s", 5))
            + float(self._setting("request_timeout", 15))
            + 10.0
        )
        ttl_ms = int(ttl_s * 1000)
        try:
            grant = await self._dbs.hot.write(
                lambda conn: leases.acquire(conn, PROBE_LEASE, holder, ttl_ms, self._clock.now_ms())
            )
        except SharedStateUnavailable:
            return ProbeResult(kind, "degraded", at=now)
        if grant is None:
            return ProbeResult(kind, "busy", at=now)
        started = self._clock.monotonic()
        try:
            result = await self._run_probe(kind, fetch or self._default_fetch, now, started)
        finally:
            # If hot.db is busy now, the lease simply expires on its own after ttl_ms.
            with contextlib.suppress(SharedStateUnavailable):
                await self._dbs.hot.write(lambda conn: leases.release(conn, PROBE_LEASE, holder, delete=True))
        return result

    async def _run_probe(self, kind: str, fetch: ProbeFetch, now: int, started: float) -> ProbeResult:
        url = str(self._setting("credential_probe_url", "https://users.roblox.com/v1/users/authenticated"))
        try:
            response = await fetch(url)
        except CredentialUnavailable as exc:
            return ProbeResult(kind, exc.why, retry_after_s=exc.retry_after_s, at=now)
        except UpstreamTimeout:
            outcome = "timeout"
        except UpstreamConnectError:
            outcome = "connect_error"
        except EgressError as exc:
            outcome = type(exc).__name__
        else:
            return await self._interpret_probe(kind, response, now, started)
        latency = round((self._clock.monotonic() - started) * 1000, 1)
        await self._set_status(self._stored_status(), {"result": outcome, "kind": kind}, probed_at=now)
        return ProbeResult(kind, outcome, latency_ms=latency, at=now)

    def _stored_status(self) -> str:
        return str(self._meta.get("status") or UNKNOWN)

    async def _interpret_probe(self, kind: str, response: ProbeAnswer, now: int, started: float) -> ProbeResult:
        latency = round((self._clock.monotonic() - started) * 1000, 1)
        code = response.status
        if code == 200:
            account = _account_id(response.body)
            if account is None:
                await self._set_status(
                    ACTIVE, {"result": "ok_no_account_id", "kind": kind, "status": code}, probed_at=now
                )
                return ProbeResult(kind, "ok_no_account_id", code, latency_ms=latency, at=now)
            account_fp = fingerprint(account, self._fp_key)
            recorded = self._meta.get("account_id_fingerprint")
            if recorded is None or recorded == account_fp:
                await self._set_status(
                    ACTIVE, {"result": "ok", "kind": kind, "status": code}, account_fp=account_fp, probed_at=now
                )
                return ProbeResult(kind, "ok", code, account_match=True, latency_ms=latency, at=now)
            await self._set_status(
                REJECTED,
                {"result": "account_mismatch", "kind": kind, "status": code, "pending_account": account_fp},
                probed_at=now,
            )
            self._alert_rejected("account_mismatch")
            return ProbeResult(kind, "account_mismatch", code, account_match=False, latency_ms=latency, at=now)
        if code == 429:
            retry = retry_after_seconds(response.headers.get("retry-after"), self._clock.now())
            source = "retry_after" if retry is not None else "default"
            low = float(self._setting("cooldown_min_s", 1))
            high = float(self._setting("cooldown_max_s", 600))
            seconds = retry if retry is not None else float(self._setting("credential_cooldown_default_s", 60))
            seconds = min(max(seconds, low), high)
            await self.set_cooldown(seconds, source)
            await self._set_status(
                self._stored_status(), {"result": "rate_limited", "kind": kind, "status": code}, probed_at=now
            )
            return ProbeResult(kind, "rate_limited", code, retry_after_s=math.ceil(seconds), latency_ms=latency, at=now)
        if code in (401, 403):
            await self._set_status(
                REJECTED, {"result": f"rejected_{code}", "kind": kind, "status": code}, probed_at=now
            )
            self._alert_rejected(f"rejected_{code}")
            return ProbeResult(kind, "rejected", code, latency_ms=latency, at=now)
        await self._set_status(
            self._stored_status(), {"result": f"http_{code}", "kind": kind, "status": code}, probed_at=now
        )
        return ProbeResult(kind, f"http_{code}", code, latency_ms=latency, at=now)

    # --- admin actions ------------------------------------------------------------------------------------------------

    async def replace(
        self, value: str, actor: Actor, *, reason: str | None = None, request_id: str | None = None
    ) -> CredentialStatus:
        """Replace the credential with `value` (the audited admin action of plan C1). The old value stops being
        used everywhere at once (version bump), and the bootstrap value is superseded for good. A pasted
        `.ROBLOSECURITY=<value>` pair is stored as the bare value (`_clean_value`)."""
        text, named = _clean_value(value)
        if named:
            log.info("credential_cookie_name_removed", extra={"fields": {"source": "ui", "by": actor.label}})
        if self._key is None:
            raise CredentialStateError("credential_encryption_key is not configured, so a UI value cannot be stored")
        new_fp = fingerprint(text, self._fp_key)
        nonce, ciphertext = seal(self._key, text.encode("utf-8"), STORE_AAD)
        after = {"fingerprint": new_fp, "masked": mask_token(text)}
        now = int(self._clock.now())
        bootstrap_fp = self._bootstrap_fp

        def write(conn: sqlite3.Connection) -> int:
            meta = _row_dict(conn.execute("SELECT * FROM credential_meta WHERE id = 1").fetchone())
            old_fp = meta.get("fingerprint")
            superseded = _json_list(meta.get("superseded_fingerprints_json"))
            for item in (old_fp, bootstrap_fp):
                if item and item != new_fp and item not in superseded:
                    superseded.append(item)
            superseded = [item for item in superseded if item != new_fp][-MAX_SUPERSEDED:]
            conn.execute(
                "INSERT INTO credential_store (id, ciphertext, nonce, set_at, set_by) VALUES (1, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET ciphertext = excluded.ciphertext, nonce = excluded.nonce, "
                "set_at = excluded.set_at, set_by = excluded.set_by",
                (ciphertext, nonce, now, actor.label),
            )
            conn.execute(
                "INSERT INTO credential_meta (id, fingerprint, masked, account_id_fingerprint, "
                "superseded_fingerprints_json, set_at, set_by, status, status_at, last_probe_at, last_probe_result) "
                "VALUES (1, ?, ?, NULL, ?, ?, ?, 'unknown', ?, NULL, NULL) "
                "ON CONFLICT(id) DO UPDATE SET fingerprint = excluded.fingerprint, masked = excluded.masked, "
                "account_id_fingerprint = NULL, superseded_fingerprints_json = excluded.superseded_fingerprints_json, "
                "set_at = excluded.set_at, set_by = excluded.set_by, status = 'unknown', "
                "status_at = excluded.status_at, "
                "last_probe_result = NULL",
                (new_fp, after["masked"], json.dumps(superseded), now, actor.label, now),
            )
            before = {"fingerprint": old_fp, "masked": meta.get("masked") or ""} if old_fp else None
            audit.record(conn, actor, "credential.replace", "credential", before, after, reason, request_id, at=now)
            return bump_version(conn, VERSION_KEY, now)

        await self._dbs.control.write(write)
        SecretRegistry.register(CREDENTIAL_SECRET_NAME, text)
        await self.refresh(force=True)
        self._events.event("credential_replaced", "info", "credential", {"fingerprint": new_fp, "by": actor.label})
        return self.status()

    async def delete_ui_value(
        self, actor: Actor, *, reason: str | None = None, request_id: str | None = None
    ) -> CredentialStatus:
        """Delete the UI-set value and go back to the bootstrap file (the only way to un-supersede it, plan C1).

        The status becomes `unknown`: the bootstrap value is not used for traffic until a probe confirms the same
        account (or `confirm_account` accepts a different one after the typed C1 warning in the dashboard).
        """
        now = int(self._clock.now())
        bootstrap_fp = self._bootstrap_fp
        bootstrap_masked = mask_token(self._bootstrap) if self._bootstrap is not None else None

        def write(conn: sqlite3.Connection) -> int:
            if conn.execute("SELECT 1 FROM credential_store WHERE id = 1").fetchone() is None:
                raise CredentialStateError("there is no UI-set credential to delete")
            meta = _row_dict(conn.execute("SELECT * FROM credential_meta WHERE id = 1").fetchone())
            superseded = [item for item in _json_list(meta.get("superseded_fingerprints_json")) if item != bootstrap_fp]
            conn.execute("DELETE FROM credential_store WHERE id = 1")
            conn.execute(
                "UPDATE credential_meta SET fingerprint = ?, masked = ?, superseded_fingerprints_json = ?, set_at = ?, "
                "set_by = ?, status = 'unknown', status_at = ?, last_probe_result = NULL WHERE id = 1",
                (bootstrap_fp, bootstrap_masked, json.dumps(superseded), now, "bootstrap", now),
            )
            before = {"fingerprint": meta.get("fingerprint"), "masked": meta.get("masked") or ""}
            after = {"fingerprint": bootstrap_fp, "masked": bootstrap_masked or ""} if bootstrap_fp else None
            audit.record(
                conn,
                actor,
                "credential.delete_ui_value",
                "credential",
                before if before["fingerprint"] else None,
                after,
                reason,
                request_id,
                at=now,
            )
            return bump_version(conn, VERSION_KEY, now)

        await self._dbs.control.write(write)
        await self.refresh(force=True)
        return self.status()

    async def confirm_account(
        self, actor: Actor, *, reason: str | None = None, request_id: str | None = None
    ) -> CredentialStatus:
        """Accept the account the last probe saw after an `account_mismatch` (the typed C1 confirmation)."""
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> int:
            meta = _row_dict(conn.execute("SELECT * FROM credential_meta WHERE id = 1").fetchone())
            result = _json_obj(meta.get("last_probe_result")) or {}
            pending = result.get("pending_account")
            if result.get("result") != "account_mismatch" or not isinstance(pending, str):
                raise CredentialStateError("the last probe did not report a different account to confirm")
            conn.execute(
                "UPDATE credential_meta SET account_id_fingerprint = ?, status = 'active', status_at = ?, "
                "last_probe_result = ? WHERE id = 1",
                (pending, now, json.dumps({"result": "account_confirmed"})),
            )
            audit.record(
                conn,
                actor,
                "credential.confirm_account",
                "credential_account",
                {"account_id_fingerprint": meta.get("account_id_fingerprint")},
                {"account_id_fingerprint": pending},
                reason,
                request_id,
                at=now,
            )
            return bump_version(conn, VERSION_KEY, now)

        await self._dbs.control.write(write)
        await self.refresh(force=True)
        return self.status()

    # --- the H-CRED-GUARD self-test --------------------------------------------------------------------------------

    def guard_self_test_kit(self, url: str = "https://games.roblox.com/v1/roxy-guard-self-test") -> GuardSelfTestKit:
        """Requests that carry the credential three ways (cookie, a 30 character piece in a header, a lowercased
        piece in a body), for a guard to refuse in-process. With no credential, a random stand-in is used."""
        value = self._slot._reveal_credential()
        matcher = self._matcher
        synthetic = value is None
        if value is None:
            value = TOKEN_PREFIX + secrets.token_hex(64).upper()
            matcher = LeakMatcher((value,))
        # The piece comes from the longest secret part, the text the matcher really watches (never public text).
        raw = value.encode("utf-8", "replace")
        first, last = max(secret_spans(value), key=lambda span: span[1] - span[0], default=(0, len(raw)))
        secret = raw[first:last].decode("utf-8", "replace")
        start = max(0, len(secret) // 3)
        piece = secret[start : start + 30]
        requests = (
            httpx.Request("GET", url, headers={"Cookie": f"{ROBLOX_COOKIE_NAME}={value}"}),
            httpx.Request("GET", url, headers={"X-Roxy-Self-Test": piece}),
            httpx.Request("POST", url, content=b"note=" + piece.lower().encode("utf-8")),
        )
        return GuardSelfTestKit(requests=requests, matcher=matcher, synthetic=synthetic)

    # --- helpers for other modules ------------------------------------------------------------------------------

    @staticmethod
    def endpoint_of(url: httpx.URL) -> str:
        """`host/path` of a URL, for alerts (no query string)."""
        return endpoint_label(url)


__all__ = [
    "BOOTSTRAP_FILE_NAME",
    "COOLDOWN_KEY",
    "COOLDOWN_SOURCES",
    "PROBE_LEASE",
    "VERSION_KEY",
    "CredentialManager",
    "CredentialSlot",
    "CredentialStateError",
    "CredentialStatus",
    "CredentialValueError",
    "GuardSelfTestKit",
    "LeakMatcher",
    "ProbeResult",
    "bump_version",
    "read_version",
    "retry_after_seconds",
    "secret_spans",
]
