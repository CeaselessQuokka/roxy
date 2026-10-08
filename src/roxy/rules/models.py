"""Rule models: the validated shape of every rule table in control.db, for input and for the loaded snapshot.

What this is
    For each rule table of plan 6.2 two Pydantic models: an input model (`EndpointBlockIn`, `HeaderRuleIn`, ...)
    that an admin API body, a recommendation or the v1 migrator must pass before anything is stored, and a row
    model (`EndpointBlockRow`, ...) that holds one stored row inside the immutable rules snapshot. Plus
    `RULE_TABLES`, the registry that tells `rules/service.py` and `rules/store.py` each table's primary key, cap,
    duplicate rule and columns, and `to_columns` / `row_to_input` that convert between models and SQL columns.

Why it exists
    Plan 9.9: every admin body is a Pydantic model with `extra="forbid"` (unknown fields are refused, so a typo
    never silently does nothing), bounded string lengths, numeric ranges and regex validation with complexity
    limits. The bounds come from `config/constants.py` (plan 15.4) and the messages keep v1's wording where v1
    had one ("Empty endpoint pattern", "Invalid regular expression", "Enter the User-Agent text to match").
    Admin text that callers can see (refusal messages) and private notes refuse em and en dashes (plan C5).

How it works
    - Input models normalize as they validate: patterns go through `rules/match.py validate_pattern` (globs
      lowercased, regexes length and nested-quantifier checked), enum-like fields are lowercased and trimmed like
      v1 did, CIDRs are normalized to their network form, method lists become a canonical tuple.
    - Updating a row validates the whole merged row, but fields the update does not touch are passed as
      "unchanged" in the validation context: their stored text is normalized, not re-judged. So an imported v1
      regex that today's complexity rule would refuse can still be disabled or have its note edited.
    - Row models only check types (the write path already enforced the bounds); they are frozen so a snapshot
      can be shared by every request in the worker.

What to read next
    `roxy/rules/service.py` (create, update and delete with audit and `config_version`), then
    `roxy/rules/store.py` (the compiled snapshot built from the row models).
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from roxy.config.catalog import DASH_MESSAGE, EM_DASH, EN_DASH
from roxy.config.constants import (
    DEFAULT_CACHE_RULE_TTL,
    DEFAULT_ENDPOINT_RULE_PERIOD,
    DEFAULT_USER_AGENT_RULE_COOLDOWN,
    DEFAULT_USER_AGENT_RULE_LIMIT,
    DEFAULT_USER_AGENT_RULE_PERIOD,
    MAX_ACTIVE_BANS,
    MAX_ADMIN_ALLOW_ENTRIES,
    MAX_CACHE_IGNORED_PARAMS,
    MAX_CACHE_RULE_FLAGS,
    MAX_CACHE_RULE_STALE_TTL_S,
    MAX_CACHE_RULE_TTL_S,
    MAX_CACHE_RULES,
    MAX_CREDENTIAL_ALLOWLIST_RULES,
    MAX_DENY_ENTRIES,
    MAX_ENDPOINT_BLOCKS,
    MAX_ENDPOINT_RULES,
    MAX_HEADER_RULES,
    MAX_IGNORED_PATHS,
    MAX_IGNORED_VALUE_HEADERS,
    MAX_ROUTING_RULES,
    MAX_RULE_LIMIT,
    MAX_RULE_MESSAGE,
    MAX_RULE_NOTE,
    MAX_RULE_PERIOD_S,
    MAX_THROTTLE_BYPASS_IPS,
    MAX_THROTTLE_MULTIPLIER,
    MAX_THROTTLE_TIERS,
    MAX_TIER_BAN_MINUTES,
    MAX_UPSTREAM_LIMITS,
    MAX_USER_AGENT_NEEDLE,
    MAX_USER_AGENT_RULE_COOLDOWN,
    MAX_USER_AGENT_RULES,
    MIN_ACCESS_PREFIX_V4,
    MIN_ACCESS_PREFIX_V6,
)
from roxy.rules.match import (
    MAX_PATTERN_LENGTH,
    PatternValidationError,
    header_rule_canonical_key,
    normalize_pattern,
    validate_pattern,
    validate_regex,
)

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # newline and tab are allowed in messages
_CONTROL_ALL = re.compile(r"[\x00-\x1f\x7f]")
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")  # RFC 9110 token: what a header name may contain
_ROBLOX_HOST = re.compile(r"(?:[a-z0-9-]+\.)*roblox\.com")
_REASON_CODE = re.compile(r"[a-z0-9_:.-]{1,64}")
_FLAG = re.compile(r"sort_csv:[A-Za-z0-9_.-]{1,64}|casefold_path")
MAX_RAW_PATTERN: Final = 2 * MAX_PATTERN_LENGTH  # raw input bound before normalization trims it
MAX_HEADER_NAME: Final = 128
MAX_PARAM_NAME: Final = 80  # v1 `name.strip()[:80]`
MAX_VALUE_HEADER_NAME: Final = 120  # v1 `name.strip().lower()[:120]`
MAX_BUCKET_KEY: Final = 300
MAX_BAN_SUBJECT: Final = 128
MAX_POSITION: Final = 1_000_000
METHOD_ORDER: Final[tuple[str, ...]] = ("GET", "HEAD", "POST")

PatternType = Literal["glob", "regex"]


# --- small shared validators -----------------------------------------------------------------------------------------


def _lower(value: Any) -> Any:
    """v1 lowercased and trimmed every enum-like field (`scope`, `mode`, `kind`) before checking it."""
    return value.strip().lower() if isinstance(value, str) else value


def _none_to_empty(value: Any) -> Any:
    return "" if value is None else value


def check_admin_text(value: str, limit: int, what: str) -> str:
    """Trim, bound and check admin-written text: no dash characters (plan C5), no control characters."""
    text = value.replace("\r\n", "\n").strip()
    if len(text) > limit:
        raise ValueError(f"{what} is longer than {limit} characters")
    if EM_DASH in text or EN_DASH in text:
        raise ValueError(DASH_MESSAGE)
    if _CONTROL.search(text):
        raise ValueError(f"{what} contains a control character")
    return text


def _text(limit: int, what: str) -> Callable[[str], str]:
    def check(value: str) -> str:
        return check_admin_text(value, limit, what)

    return check


Lower = BeforeValidator(_lower)
Message = Annotated[str, BeforeValidator(_none_to_empty), AfterValidator(_text(MAX_RULE_MESSAGE, "The message"))]
Note = Annotated[str, BeforeValidator(_none_to_empty), AfterValidator(_text(MAX_RULE_NOTE, "The note"))]
Kind = Annotated[PatternType, Lower]


def _unchanged(info: ValidationInfo, *fields: str) -> bool:
    """Whether every one of `fields` is listed as unchanged in the validation context (see module docstring)."""
    context = info.context if isinstance(info.context, Mapping) else {}
    unchanged = context.get("unchanged", ())
    return all(name in unchanged for name in fields)


def _checked_pattern(value: str, info: ValidationInfo) -> str:
    kind: str = info.data.get("type", "glob")
    if _unchanged(info, "pattern", "type"):
        return normalize_pattern(value, kind)  # stored earlier (maybe imported from v1): normalize, never re-judge
    try:
        return validate_pattern(value, kind)
    except PatternValidationError as exc:
        raise ValueError(exc.message) from None


def _methods(value: Any, allowed: tuple[str, ...]) -> tuple[str, ...]:
    """A method list from a JSON list or v1-style text ("GET,HEAD"): uppercased, deduplicated, canonical order."""
    items = value.split(",") if isinstance(value, str) else value
    if not isinstance(items, list | tuple):
        raise ValueError("Methods must be a list such as GET, HEAD")
    methods = {str(item).strip().upper() for item in items if str(item).strip()}
    unknown = sorted(methods - set(allowed))
    if unknown:
        raise ValueError(f"Method {unknown[0][:10]!r} is not allowed here; use {', '.join(allowed)}")
    if not methods:
        raise ValueError("Choose at least one method")
    return tuple(method for method in METHOD_ORDER if method in methods)


class _Model(BaseModel):
    """Shared configuration of every input model (plan 9.9)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False, validate_default=True)


class _PatternModel(_Model):
    """Rules keyed by an endpoint pattern. `type` is declared first so the pattern validator can read it."""

    type: Kind = "glob"
    pattern: str = Field(max_length=MAX_RAW_PATTERN)

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, value: str, info: ValidationInfo) -> str:
        return _checked_pattern(value, info)


# --- input models -----------------------------------------------------------------------------------------------------


class EndpointBlockIn(_PatternModel):
    """An endpoint block (parity row 46): requests matching `pattern` get 403 with `message` or the default."""

    note: Note = ""
    message: Message = ""
    enabled: bool = True


class EndpointLimitIn(_PatternModel):
    """An endpoint rate rule (row 43): `limit` requests per `period` seconds per IP, place, or globally."""

    scope: Annotated[Literal["ip", "place", "global"], Lower] = "ip"
    limit: int = Field(ge=1, le=MAX_RULE_LIMIT)
    period: int = Field(DEFAULT_ENDPOINT_RULE_PERIOD, ge=1, le=MAX_RULE_PERIOD_S)
    message: Message = ""
    note: Note = ""
    enabled: bool = True


class CacheRuleIn(_PatternModel):
    """A cache rule (row 55): TTL 0 means "never cache this endpoint".

    `normalize_flags` (applied by `cache/keys.py` when the key is built): `sort_csv:<param>` sorts the
    comma separated values of query parameter `<param>` (id lists where order does not change the answer,
    plan 15.5), `casefold_path` lowercases the path.
    """

    ttl: int = Field(DEFAULT_CACHE_RULE_TTL, ge=0, le=MAX_CACHE_RULE_TTL_S)
    stale_ttl: int = Field(0, ge=0, le=MAX_CACHE_RULE_STALE_TTL_S)
    negative_ttl: int = Field(0, ge=0, le=MAX_CACHE_RULE_TTL_S)
    methods: tuple[str, ...] = ("GET",)
    normalize_flags: tuple[str, ...] = ()
    note: Note = ""
    enabled: bool = True
    origin: Annotated[Literal["default", "admin", "recommendation"], Lower] = "admin"

    @field_validator("methods", mode="before")
    @classmethod
    def _check_methods(cls, value: Any) -> tuple[str, ...]:
        return _methods(value, METHOD_ORDER)

    @field_validator("normalize_flags", mode="before")
    @classmethod
    def _check_flags(cls, value: Any) -> tuple[str, ...]:
        if value is None or value == "":
            return ()
        items = json.loads(value) if isinstance(value, str) else value
        if not isinstance(items, list | tuple):
            raise ValueError("Normalization flags must be a list")
        flags: list[str] = []
        for item in items:
            flag = str(item).strip()
            if not _FLAG.fullmatch(flag):
                raise ValueError(f"Unknown normalization flag {flag[:40]!r}; use sort_csv:<param> or casefold_path")
            if flag not in flags:
                flags.append(flag)
        if len(flags) > MAX_CACHE_RULE_FLAGS:
            raise ValueError(f"At most {MAX_CACHE_RULE_FLAGS} normalization flags")
        return tuple(flags)


class UserAgentRuleIn(_Model):
    """A per-User-Agent rule (row 44): a burst allowance or a minimum gap, per IP or shared by every IP.

    Field order matters: `mode` before `needle` and `kind` before the numbers, so each validator can read them.
    """

    mode: Annotated[Literal["contains", "exact", "regex"], Lower] = "contains"
    needle: str = Field(max_length=4 * MAX_USER_AGENT_NEEDLE)
    kind: Annotated[Literal["burst", "cooldown"], Lower] = "burst"
    scope: Annotated[Literal["ip", "global"], Lower] = "ip"
    limit: int = DEFAULT_USER_AGENT_RULE_LIMIT
    period: int = DEFAULT_USER_AGENT_RULE_PERIOD
    cooldown: float = DEFAULT_USER_AGENT_RULE_COOLDOWN
    message: Message = ""
    note: Note = ""
    enabled: bool = True
    position: int | None = Field(None, ge=0, le=MAX_POSITION)

    @field_validator("needle")
    @classmethod
    def _needle(cls, value: str, info: ValidationInfo) -> str:
        needle = value.strip()
        if not needle:
            raise ValueError("Enter the User-Agent text to match")
        if len(needle) > MAX_USER_AGENT_NEEDLE:
            raise ValueError(f"The User-Agent text is longer than {MAX_USER_AGENT_NEEDLE} characters")
        if _CONTROL_ALL.search(needle):
            raise ValueError("The User-Agent text contains a control character")
        if info.data.get("mode") == "regex" and not _unchanged(info, "needle", "mode"):
            try:
                validate_regex(needle, max_length=MAX_USER_AGENT_NEEDLE)
            except PatternValidationError as exc:
                raise ValueError(exc.message) from None
        return needle

    @field_validator("limit")
    @classmethod
    def _limit(cls, value: int, info: ValidationInfo) -> int:
        if info.data.get("kind") == "burst" and not 1 <= value <= MAX_RULE_LIMIT:
            raise ValueError(f"Burst allowance must be between 1 and {MAX_RULE_LIMIT}")
        return value

    @field_validator("period")
    @classmethod
    def _period(cls, value: int, info: ValidationInfo) -> int:
        if info.data.get("kind") == "burst" and not 1 <= value <= MAX_RULE_PERIOD_S:
            raise ValueError(f"Burst window must be between 1 and {MAX_RULE_PERIOD_S} seconds")
        return value

    @field_validator("cooldown")
    @classmethod
    def _cooldown(cls, value: float, info: ValidationInfo) -> float:
        if not math.isfinite(value):
            raise ValueError("Cooldown must be a number")
        if info.data.get("kind") == "cooldown" and not 0 < value <= MAX_USER_AGENT_RULE_COOLDOWN:
            raise ValueError(f"Cooldown must be between 0 and {MAX_USER_AGENT_RULE_COOLDOWN:g} seconds")
        return round(value, 3)  # v1 kept millisecond precision


class HeaderRuleIn(_Model):
    """A request header filter (rows 45, 112). Naming a `header` forces `scope` to `value`, as in v1."""

    header: str = Field("", max_length=4 * MAX_HEADER_NAME)
    scope: Annotated[Literal["key", "value", "either"], Lower] = "either"
    mode: Annotated[Literal["contains", "exact", "regex"], Lower] = "contains"
    needle: str = Field(max_length=MAX_RAW_PATTERN)
    message: Message = ""
    note: Note = ""
    enabled: bool = True

    @field_validator("header", mode="before")
    @classmethod
    def _header(cls, value: Any) -> Any:
        if value is None:
            return ""
        if not isinstance(value, str):
            return value
        header = value.strip()
        if len(header) > MAX_HEADER_NAME:
            raise ValueError(f"The header name is longer than {MAX_HEADER_NAME} characters")
        if header and not _HEADER_TOKEN.fullmatch(header):
            raise ValueError("A header name may contain letters, digits and !#$%&'*+.^_`|~- only")
        return header

    @field_validator("needle")
    @classmethod
    def _needle(cls, value: str, info: ValidationInfo) -> str:
        needle = value.strip()
        if not needle:
            raise ValueError("Empty match text")
        if len(needle) > MAX_PATTERN_LENGTH:
            raise ValueError(f"The match text is longer than {MAX_PATTERN_LENGTH} characters")
        if _CONTROL_ALL.search(needle):
            raise ValueError("The match text contains a control character")
        if info.data.get("mode") == "regex" and not _unchanged(info, "needle", "mode"):
            try:
                validate_regex(needle)
            except PatternValidationError as exc:
                raise ValueError(exc.message) from None
        return needle

    @model_validator(mode="after")
    def _header_forces_value_scope(self) -> HeaderRuleIn:
        if self.header:
            self.scope = "value"  # v1 normalize_header_rule: a named header is always matched on its value
        return self

    @property
    def canonical_key(self) -> str:
        """The rule id `header|scope|mode|needle` (row 112), stored under a unique index.

        v1's form, except that a regex needle keeps the case of its escapes (lead decision 3), so `^\\d+$` and
        `^\\D+$` are two rules. Imported v1 rows keep the key they arrived with (`rules/service.py`).
        """
        return header_rule_canonical_key(self.scope, self.mode, self.needle, self.header, keep_regex_escapes=True)


class RoutingRuleIn(_PatternModel):
    """A per-endpoint routing rule (plan 7.2 step 2)."""

    mode: Annotated[Literal["prefer_direct", "prefer_rotator", "direct_only", "rotator_only"], Lower]
    note: Note = ""
    enabled: bool = True


class UpstreamLimitIn(_Model):
    """A per-host or per-endpoint upstream bucket override (plan 7.3): `host:<host>` or `endpoint:<template>`."""

    bucket_key: str = Field(max_length=MAX_BUCKET_KEY)
    per_min: float = Field(gt=0, le=MAX_RULE_LIMIT, allow_inf_nan=False)
    burst: int = Field(ge=1, le=10_000)
    origin: Annotated[Literal["default", "admin", "recommendation", "adaptive"], Lower] = "admin"
    note: Note = ""

    @field_validator("bucket_key")
    @classmethod
    def _bucket_key(cls, value: str) -> str:
        kind, _, rest = value.strip().partition(":")
        if kind == "host":
            host = rest.strip().lower().removesuffix(".")
            if not _ROBLOX_HOST.fullmatch(host):
                raise ValueError("A host bucket is host:<name>.roblox.com")
            return f"host:{host}"
        if kind == "endpoint":
            template = rest.strip()
            host = template.split("/", 1)[0].lower()
            if not template or _CONTROL_ALL.search(template) or " " in template or not _ROBLOX_HOST.fullmatch(host):
                raise ValueError("An endpoint bucket is endpoint:<host>/<path template>, on a roblox.com host")
            return f"endpoint:{host}{template[len(host) :]}"
        raise ValueError("A bucket key starts with host: or endpoint:")


class CredentialAllowlistIn(_PatternModel):
    """An endpoint that may use the credential (D1, 9.13). GET and HEAD only; `cache_private` has no default."""

    methods: tuple[str, ...] = ("GET",)
    cache_private: bool
    identical_anonymous: bool = False
    note: Note = ""
    enabled: bool = True

    @field_validator("methods", mode="before")
    @classmethod
    def _check_methods(cls, value: Any) -> tuple[str, ...]:
        return _methods(value, ("GET", "HEAD"))


class ThrottleTierIn(_Model):
    """One rung of the escalation ladder (rows 40, 125; plan 10.4). Rung `position` 1 is the first strike."""

    position: int = Field(ge=1, le=MAX_THROTTLE_TIERS)
    multiplier: float = Field(gt=0, le=MAX_THROTTLE_MULTIPLIER, allow_inf_nan=False)
    message: Message = ""
    note: Note = ""
    action: Annotated[Literal["throttle", "ban"], Lower] = "throttle"
    ban_minutes: int | None = Field(None, ge=1, le=MAX_TIER_BAN_MINUTES)

    @model_validator(mode="after")
    def _ban_needs_minutes(self) -> ThrottleTierIn:
        if self.action == "ban" and self.ban_minutes is None:
            raise ValueError("A ban rung needs ban_minutes (how long the temporary IP ban lasts)")
        if self.action == "throttle":
            self.ban_minutes = None
        return self


class CacheIgnoredParamIn(_Model):
    """A query parameter left out of cache keys (row 54). Case is kept and matching is case-sensitive (v1)."""

    name: str = Field(max_length=4 * MAX_PARAM_NAME)
    note: Note = ""
    origin: Annotated[Literal["default", "admin", "recommendation", "import"], Lower] = "admin"

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        name = value.strip()
        if not name:
            raise ValueError("Enter a query parameter name")
        if len(name) > MAX_PARAM_NAME or _CONTROL_ALL.search(name):
            raise ValueError(f"A parameter name is at most {MAX_PARAM_NAME} printable characters")
        return name


class IgnoredValueHeaderIn(_Model):
    """A header whose values are not fingerprinted (row 79). Stored lowercase, like v1."""

    name: str = Field(max_length=4 * MAX_VALUE_HEADER_NAME)
    note: Note = ""
    auto: bool = False

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        name = value.strip().lower()
        if not name:
            raise ValueError("Enter a header name")
        if len(name) > MAX_VALUE_HEADER_NAME or not _HEADER_TOKEN.fullmatch(name):
            raise ValueError("Enter a valid header name")
        return name


class IgnoredPathIn(_Model):
    """A path answered 404 without logging (row 50), matched with the shared glob matcher (lead decision 4).

    The entry is a glob written without the leading slash: `*` matches within one path segment, and every path
    UNDER the entry matches too (`favicon.ico` also covers `favicon.ico/x`; v1 compared exact strings, so this is
    a widening, recorded in CHANGES.md). A Roblox endpoint (anything on a roblox.com host) is refused: the proxy
    would then answer that endpoint with a silent 404 for every caller, which is what an endpoint block is for,
    with a message and a log line (spec review 4). This table is the only list of ignored paths; there is no
    setting for it.
    """

    pattern: str = Field(max_length=MAX_RAW_PATTERN)
    note: Note = ""

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, value: str, info: ValidationInfo) -> str:
        if _unchanged(info, "pattern"):
            return normalize_pattern(value, "glob")
        try:
            pattern = validate_pattern(value, "glob")
        except PatternValidationError as exc:
            message = exc.message.replace("endpoint pattern", "path").replace("Endpoint pattern", "Path")
            raise ValueError(message) from None
        if "roblox.com" in pattern.split("/", 1)[0]:
            raise ValueError(
                "That is a Roblox endpoint, which every caller would get as a silent 404; use an endpoint block "
                "to refuse a Roblox endpoint"
            )
        return pattern


def normalize_network(value: str) -> str:
    """A CIDR or bare address in its canonical network form, refusing very wide ranges (likely typos)."""
    text = value.strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"{text[:60]!r} is not a valid IP address or CIDR range") from None
    if isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped is not None:
        mapped = network.network_address.ipv4_mapped
        network = ipaddress.ip_network(f"{mapped}/{max(0, network.prefixlen - 96)}", strict=False)
    minimum = MIN_ACCESS_PREFIX_V4 if network.version == 4 else MIN_ACCESS_PREFIX_V6
    if network.prefixlen < minimum:
        raise ValueError(f"/{network.prefixlen} is too wide; the widest range allowed is /{minimum}")
    return str(network)


class AccessListIn(_Model):
    """A bypass, admin allow or deny entry (rows 6, 113; plan 10.5), CIDR aware, optionally expiring."""

    kind: Annotated[Literal["bypass", "allow_admin", "deny"], Lower]
    cidr: str = Field(max_length=100)
    note: Note = ""
    expires_at: int | None = Field(None, ge=0)

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, value: str) -> str:
        return normalize_network(value)


class BanIn(_Model):
    """A temporary (`expires_at`) or permanent ban by IP, CIDR, place id or User-Agent hash (plan 10.5)."""

    subject_type: Annotated[Literal["ip", "cidr", "place", "ua_hash"], Lower]
    subject: str = Field(max_length=MAX_BAN_SUBJECT)
    reason_code: str = "banned"
    reason_text: Message = ""
    expires_at: int | None = Field(None, ge=0)

    @field_validator("subject")
    @classmethod
    def _subject(cls, value: str, info: ValidationInfo) -> str:
        text = value.strip()
        kind = info.data.get("subject_type")
        if kind == "ip":
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                raise ValueError(f"{text[:60]!r} is not a valid IP address") from None
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                return str(address.ipv4_mapped)
            return str(address)
        if kind == "cidr":
            return normalize_network(text)
        if kind == "place":
            if not re.fullmatch(r"[0-9]{1,20}", text):
                raise ValueError("A place ban needs the numeric place id (the Roblox-Id header)")
            return text
        if kind == "ua_hash":
            lowered = text.lower()
            if not re.fullmatch(r"[0-9a-f]{16,64}", lowered):
                raise ValueError("A User-Agent ban needs the User-Agent hash (16 to 64 hex characters)")
            return lowered
        return text

    @field_validator("reason_code")
    @classmethod
    def _reason_code(cls, value: str) -> str:
        code = value.strip().lower()
        if not _REASON_CODE.fullmatch(code):
            raise ValueError("A reason code is 1 to 64 lowercase letters, digits and _ : . -")
        return code


# --- row models (what the snapshot holds) -----------------------------------------------------------------------------


def _flag(value: Any) -> Any:
    return bool(value) if isinstance(value, int) else value


def _split(value: Any) -> Any:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip().upper() for part in value.split(",") if part.strip())
    return value


def _json_tuple(value: Any) -> Any:
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        try:
            loaded = json.loads(value)
        except ValueError:
            return ()
        return tuple(str(item) for item in loaded) if isinstance(loaded, list) else ()
    return value


Flag = Annotated[bool, BeforeValidator(_flag)]
Text = Annotated[str, BeforeValidator(_none_to_empty)]
MethodsColumn = Annotated[tuple[str, ...], BeforeValidator(_split)]
JsonList = Annotated[tuple[str, ...], BeforeValidator(_json_tuple)]


class _Row(BaseModel):
    """Shared configuration of the frozen row models."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class EndpointBlockRow(_Row):
    id: int
    pattern: str
    type: str
    note: Text = ""
    message: Text = ""
    enabled: Flag = True
    created_at: int | None = None
    created_by: str | None = None
    updated_at: int | None = None
    updated_by: str | None = None


class EndpointLimitRow(_Row):
    id: int
    pattern: str
    type: str
    scope: str
    limit: int
    period: int
    message: Text = ""
    note: Text = ""
    enabled: Flag = True
    created_at: int | None = None
    created_by: str | None = None
    updated_at: int | None = None
    updated_by: str | None = None


class CacheRuleRow(_Row):
    id: int
    pattern: str
    type: str
    ttl: int
    stale_ttl: int = 0
    negative_ttl: int = 0
    methods: MethodsColumn = ("GET",)
    normalize_flags: JsonList = ()
    note: Text = ""
    enabled: Flag = True
    origin: str = "admin"
    created_at: int | None = None
    created_by: str | None = None
    updated_at: int | None = None
    updated_by: str | None = None


class UserAgentRuleRow(_Row):
    id: str
    needle: str
    mode: str
    kind: str
    scope: Annotated[str, BeforeValidator(lambda v: "ip" if v is None else v)] = "ip"
    limit: int | None = None
    period: int | None = None
    cooldown: float | None = None
    message: Text = ""
    note: Text = ""
    enabled: Flag = True
    position: int = 0
    created_at: int | None = None
    created_by: str | None = None
    updated_at: int | None = None
    updated_by: str | None = None


class HeaderRuleRow(_Row):
    id: int
    canonical_key: str
    scope: str
    mode: str
    needle: str
    header: Text = ""
    message: Text = ""
    note: Text = ""
    enabled: Flag = True
    created_at: int | None = None
    created_by: str | None = None
    updated_at: int | None = None
    updated_by: str | None = None


class RoutingRuleRow(_Row):
    id: int
    pattern: str
    type: str
    mode: str
    note: Text = ""
    enabled: Flag = True
    created_at: int | None = None
    created_by: str | None = None
    updated_at: int | None = None
    updated_by: str | None = None


class UpstreamLimitRow(_Row):
    bucket_key: str
    per_min: float
    burst: int
    origin: str
    note: Text = ""
    updated_at: int | None = None
    updated_by: str | None = None


class CredentialAllowlistRow(_Row):
    id: int
    pattern: str
    type: str
    methods: MethodsColumn = ("GET",)
    cache_private: Flag
    identical_anonymous: Flag = False
    note: Text = ""
    enabled: Flag = True
    created_at: int | None = None
    created_by: str | None = None
    updated_at: int | None = None
    updated_by: str | None = None


class ThrottleTierRow(_Row):
    position: int
    multiplier: float
    message: Text = ""
    note: Text = ""
    action: str = "throttle"
    ban_minutes: int | None = None


class CacheIgnoredParamRow(_Row):
    name: str
    note: Text = ""
    origin: str = "admin"


class IgnoredValueHeaderRow(_Row):
    name: str
    note: Text = ""
    auto: Flag = False


class IgnoredPathRow(_Row):
    pattern: str
    note: Text = ""


class AccessListRow(_Row):
    id: int
    kind: str
    cidr: str
    note: Text = ""
    expires_at: int | None = None
    created_by: str = ""
    created_at: int | None = None


class BanRow(_Row):
    id: int
    subject_type: str
    subject: str
    reason_code: str
    reason_text: Text = ""
    created_at: int
    expires_at: int | None = None
    created_by: str
    hits: int = 0
    last_hit_at: int | None = None


# --- the table registry -----------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleTable:
    """How the service and the store treat one rule table.

    `pk_auto`: the primary key is an INTEGER assigned by SQLite (otherwise it is a field of the input model, or
    generated by the service for UA rules). `duplicate_of`: columns that identify "the same rule" (checked
    inside the write transaction, so two workers can never both add it). `created`/`updated`: whether the table
    has `created_at, created_by` and `updated_at, updated_by` columns.
    """

    name: str
    label: str
    pk: str
    input_model: type[_Model]
    row_model: type[_Row]
    cap: int
    order_by: str
    pk_auto: bool = True
    duplicate_of: tuple[str, ...] = ()
    created: bool = True
    updated: bool = True

    @property
    def columns(self) -> tuple[str, ...]:
        """Every column the row model reads, in declaration order (the store SELECTs exactly these)."""
        return tuple(self.row_model.model_fields)

    @property
    def input_fields(self) -> tuple[str, ...]:
        return tuple(self.input_model.model_fields)


RULE_TABLES: Final[dict[str, RuleTable]] = {
    table.name: table
    for table in (
        RuleTable(
            "rules_endpoint_block",
            "blocked endpoints",
            "id",
            EndpointBlockIn,
            EndpointBlockRow,
            MAX_ENDPOINT_BLOCKS,
            "id",
            duplicate_of=("pattern", "type"),
        ),
        # Endpoint rules, cache rules, routing rules and the credential allowlist apply ONE winning rule per path
        # (the most specific, ties to the lowest id). A second rule with the same pattern text, whatever its scope
        # or type, would tie with the first and could never win where both match, so it is refused, exactly as v1
        # refused it (v1 kept these rules in a dict keyed by the pattern). Endpoint blocks differ: every matching
        # block refuses, so a glob and a regex with the same text are both useful.
        RuleTable(
            "rules_endpoint_limit",
            "endpoint rules",
            "id",
            EndpointLimitIn,
            EndpointLimitRow,
            MAX_ENDPOINT_RULES,
            "id",
            duplicate_of=("pattern",),
        ),
        RuleTable(
            "rules_cache",
            "cache rules",
            "id",
            CacheRuleIn,
            CacheRuleRow,
            MAX_CACHE_RULES,
            "id",
            duplicate_of=("pattern",),
        ),
        RuleTable(
            "rules_user_agent",
            "User-Agent rules",
            "id",
            UserAgentRuleIn,
            UserAgentRuleRow,
            MAX_USER_AGENT_RULES,
            "position, created_at, id",
            pk_auto=False,
        ),
        RuleTable(
            "rules_header",
            "header rules",
            "id",
            HeaderRuleIn,
            HeaderRuleRow,
            MAX_HEADER_RULES,
            "id",
            duplicate_of=("canonical_key",),  # also a UNIQUE index in the schema (row 112)
        ),
        RuleTable(
            "rules_routing",
            "routing rules",
            "id",
            RoutingRuleIn,
            RoutingRuleRow,
            MAX_ROUTING_RULES,
            "id",
            duplicate_of=("pattern",),
        ),
        RuleTable(
            "upstream_limits",
            "upstream limits",
            "bucket_key",
            UpstreamLimitIn,
            UpstreamLimitRow,
            MAX_UPSTREAM_LIMITS,
            "bucket_key",
            pk_auto=False,
            created=False,
        ),
        RuleTable(
            "credential_allowlist",
            "credential allowlist entries",
            "id",
            CredentialAllowlistIn,
            CredentialAllowlistRow,
            MAX_CREDENTIAL_ALLOWLIST_RULES,
            "id",
            duplicate_of=("pattern",),
        ),
        RuleTable(
            "throttle_tiers",
            "throttle rungs",
            "position",
            ThrottleTierIn,
            ThrottleTierRow,
            MAX_THROTTLE_TIERS,
            "position",
            pk_auto=False,
            created=False,
            updated=False,
        ),
        RuleTable(
            "cache_ignored_params",
            "ignored parameters",
            "name",
            CacheIgnoredParamIn,
            CacheIgnoredParamRow,
            MAX_CACHE_IGNORED_PARAMS,
            "name",
            pk_auto=False,
            created=False,
            updated=False,
        ),
        RuleTable(
            "ignored_value_headers",
            "ignored headers",
            "name",
            IgnoredValueHeaderIn,
            IgnoredValueHeaderRow,
            MAX_IGNORED_VALUE_HEADERS,
            "name",
            pk_auto=False,
            created=False,
            updated=False,
        ),
        RuleTable(
            "ignored_paths",
            "ignored paths",
            "pattern",
            IgnoredPathIn,
            IgnoredPathRow,
            MAX_IGNORED_PATHS,
            "pattern",
            pk_auto=False,
            created=False,
            updated=False,
        ),
        RuleTable(
            "access_list",
            "access list entries",
            "id",
            AccessListIn,
            AccessListRow,
            0,  # per kind, see ACCESS_LIST_CAPS
            "id",
            duplicate_of=("kind", "cidr"),
            updated=False,
        ),
        RuleTable(
            "bans",
            "active bans",
            "id",
            BanIn,
            BanRow,
            MAX_ACTIVE_BANS,
            "id",
            updated=False,
        ),
    )
}

# Caps of the access list are per kind (constants.py explains each).
ACCESS_LIST_CAPS: Final[dict[str, int]] = {
    "bypass": MAX_THROTTLE_BYPASS_IPS,
    "allow_admin": MAX_ADMIN_ALLOW_ENTRIES,
    "deny": MAX_DENY_ENTRIES,
}


def to_columns(table: RuleTable, model: _Model) -> dict[str, Any]:
    """The SQL column values for a validated input model (booleans as 0/1, lists in their stored text form)."""
    columns: dict[str, Any] = {}
    for name in table.input_fields:
        value = getattr(model, name)
        if isinstance(value, bool):
            value = int(value)
        elif name == "methods":
            value = ",".join(value)
        elif name == "normalize_flags":
            value = json.dumps(list(value)) if value else None
        columns[name] = value
    if isinstance(model, HeaderRuleIn):
        columns["canonical_key"] = model.canonical_key
    if isinstance(model, UserAgentRuleIn) and columns.get("position") is None:
        columns.pop("position", None)  # the service appends the rule at the end
    return columns


def row_to_input(table: RuleTable, row: Mapping[str, Any]) -> dict[str, Any]:
    """The input-model fields of a stored row (the starting point of an update)."""
    data: dict[str, Any] = {}
    fields = table.input_model.model_fields
    for name in table.input_fields:
        if name not in row:
            continue
        value = row[name]
        if value is None and not fields[name].is_required():
            continue  # a NULL in a nullable column (an imported row) takes the field's default
        if name == "methods" and isinstance(value, str):
            value = [part for part in value.split(",") if part]
        elif name == "normalize_flags":
            value = list(_json_tuple(value))
        elif name in ("message", "note", "reason_text", "header") and value is None:
            value = ""
        elif name == "scope" and value is None and table.name == "rules_user_agent":
            value = "ip"
        data[name] = value
    return data


__all__ = [
    "ACCESS_LIST_CAPS",
    "RULE_TABLES",
    "AccessListIn",
    "AccessListRow",
    "BanIn",
    "BanRow",
    "CacheIgnoredParamIn",
    "CacheIgnoredParamRow",
    "CacheRuleIn",
    "CacheRuleRow",
    "CredentialAllowlistIn",
    "CredentialAllowlistRow",
    "EndpointBlockIn",
    "EndpointBlockRow",
    "EndpointLimitIn",
    "EndpointLimitRow",
    "HeaderRuleIn",
    "HeaderRuleRow",
    "IgnoredPathIn",
    "IgnoredPathRow",
    "IgnoredValueHeaderIn",
    "IgnoredValueHeaderRow",
    "RoutingRuleIn",
    "RoutingRuleRow",
    "RuleTable",
    "ThrottleTierIn",
    "ThrottleTierRow",
    "UpstreamLimitIn",
    "UpstreamLimitRow",
    "UserAgentRuleIn",
    "UserAgentRuleRow",
    "check_admin_text",
    "normalize_network",
    "row_to_input",
    "to_columns",
]
