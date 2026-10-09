"""Rule pattern matching: the one matcher every rule family uses.

What this is
    The functions that decide whether an admin-written pattern covers a request path (endpoint blocks, endpoint
    rate rules, cache rules, the credential allowlist, cache purges), which of several matching rules wins, and
    whether a User-Agent or header rule's needle matches a piece of text. Also the validation an admin pattern
    must pass before it is stored (plan 9.9) and the canonical header-rule id (plan 4.8 row 112).

Why it exists
    v1 spread this logic over `runtime.py` (`_compile_pattern`, `_matches`, `_specificity`) and every rule
    family reused it. Callers and stored rules depend on its exact behavior, so plan 4.8 row 111 pins the v1
    semantics bit for bit, and `tests/unit/rules/test_match.py` replays generated patterns through a frozen copy
    of the v1 functions (`tests/fixtures/v1/v1_rules.py`) to prove nothing drifted. Some things are deliberately
    stronger than v1:
      * regular expressions run on the `regex` module with a per-match timeout, so one pathological admin regex
        cannot freeze a worker's event loop (regular expression denial of service, "ReDoS"). v1 used `re`, which
        reads `\\w`, `\\d`, `\\s`, `\\b` and case-insensitive letters differently from `regex` for many non-ASCII
        characters, so every pattern is first rewritten by `rules/re_compat.py` into `regex` source that matches
        exactly what `re` matched (the one approximation, a case-insensitive backreference, is documented there);
      * new admin patterns are refused when they are longer than 500 characters or have a shape that can take
        exponential or polynomial time to fail (plan 9.9): a variable repeat inside a repeated group
        (`(a+)+`, `(a{1,10}){1,10}`), alternatives that can start with the same character inside a repeat
        (`(a|aa)+`), more than `MAX_UNBOUNDED_REPEATS` unbounded repeats counting how often an enclosing group
        repeats them (`(.*,){5}`), any regex whose worst case on an 8192 character caller input is over the
        `rules/regex_cost.py` budget (two repeats that trade characters, such as `a.*a.*b` or a chain of short
        ones such as `\\w{0,10}\\w{0,10}\\d`, or a repeat that an unanchored search can restart inside of, such as
        `x+y`), or a glob with more than `MAX_GLOB_WILDCARDS_PER_SEGMENT` wildcards in one path segment, two in a
        segment that is not the last, or a glob whose compiled regex is over the same budget (`*a*b`).
        Stored v1 patterns are not judged again (they keep matching), so the timeout stays the backstop. A match
        that times out counts as "no match" by default; rules that refuse or limit traffic pass `on_timeout=True`
        so a slow pattern cannot be used to slip past them (fail closed), and `regex_budget()` caps the total
        regex time one request may spend.

How it works
    Glob patterns (the default `type`):
      * normalized at write time: trimmed, leading slashes dropped, lowercased (`normalize_glob`);
      * `*` matches a run of characters inside ONE path segment (it never crosses `/`);
      * a trailing subpath is always allowed: the compiled form is `^<escaped pattern>(?:/.*)?$`, so
        `games.roblox.com/v1/games` also matches `games.roblox.com/v1/games/123/votes`, and a host-only pattern
        (no slash) matches the whole service.
    Regex patterns (`type == "regex"`):
      * trimmed and leading slashes dropped but NOT lowercased, because lowercasing turns escapes such as `\\D`
        (not a digit) into `\\d` (a digit);
      * compiled with IGNORECASE and matched with `search`, not `match`, so the admin anchors them with `^`/`$`.
      * The pattern must be valid Python `re` syntax: v1 compiled with `re`, so a pattern only the more
        permissive `regex` module understands (for example `\\p{L}`) never matched in v1 and never matches here.
        The source handed to the `regex` module is generated from `re`'s own parse tree (`rules/re_compat.py`),
        so text the two engines read differently (POSIX classes such as `[[:alpha:]]`, fuzzy matching such as
        `a{e<=1}`, Unicode `\\w` and case rules) keeps exactly its `re` meaning. Globs go through the same
        translation (v1 compiled them with `re` too).
    The credential allowlist is the one exception (lead decision on finding F3, plan C1 and D1: least privilege,
    fail closed): its rows are compiled `exact`, so a glob grants only the path it spells out (plus the same path
    with one trailing slash; `*` still covers one segment) and a regex must match the whole target (`fullmatch`).
    A row that should cover the paths below it says so with an explicit wildcard (`.../currency/*`) or regex.
    Both kinds are case-insensitive. When several rules match, the highest `specificity` wins: for globs the
    tuple (number of `/`, length minus number of `*`), for regexes (number of `/`, length). On a tie the rule
    inserted first wins (v1 compared with a strict greater-than in insertion order), which v2 reproduces by
    ordering ties by ascending row `id`.
    Request paths are normalized with `normalize_target` (v1 `_norm`: trim, drop leading slashes, lowercase)
    before matching, for both kinds, exactly as v1's `match_*` functions did.

What to read next
    `roxy/rules/store.py` (the compiled, immutable rules snapshot that uses `PatternIndex`), then
    `roxy/rules/service.py` (where `validate_pattern` guards every write) and `roxy/rules/regex_cost.py` (the
    worst-case cost model for new regexes).
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import re
import threading
import time
import warnings
from collections.abc import Iterable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal, Protocol

import regex

from roxy.rules import regex_cost
from roxy.rules.re_compat import UnsupportedPattern, re_compatible_source

log = logging.getLogger(__name__)

PatternKind = Literal["glob", "regex"]

# Per-match time limit for every regular expression run on a request (plan 9.9). A sane pattern on a path capped
# at `max_url_length` (8192) characters finishes in microseconds, so 50 ms only ever cuts off a pathological
# pattern. A timed-out match counts as "no match" (see `CompiledPattern.matches`).
REGEX_MATCH_TIMEOUT_S = 0.05

# Longest pattern or regex an admin may store (plan 9.9). Also applied to globs: a pattern is matched on every
# request, so its cost is bounded the same way for both kinds.
MAX_PATTERN_LENGTH = 500

# Most `*` wildcard runs one glob may contain. Each run compiles to `[^/]*`, and k runs separated by literals can
# backtrack in O(n^k) on a failing match, so k is kept small (no real endpoint pattern needs more than a few).
MAX_GLOB_WILDCARDS = 16

# Most `*` wildcard runs inside ONE path segment. Runs in different segments are separated by `/`, which `[^/]*`
# cannot cross, so they cannot trade characters; runs inside one segment can, and three already need 50 ms to fail
# on a 4000 character segment (security review M4).
MAX_GLOB_WILDCARDS_PER_SEGMENT = 2

# A repeated group that may repeat more than this many times counts as "unbounded" for the nested quantifier
# check. `(\d{1,3}\.){3}` (an IPv4 shape) stays legal; `(a+)+` and `(a+){50}` do not.
NESTED_QUANTIFIER_OUTER_LIMIT = 10

# Most unbounded repeats (`*`, `+`, `{n,}`) a new regex may have, each counted as often as an enclosing group
# repeats it: `(.*,){5}` counts 5. Every one of them can trade characters with the others on a failing match, so
# the cost grows like the target length to this power.
MAX_UNBOUNDED_REPEATS = 3

# Total regex time one request may spend when the caller sets a budget with `regex_budget()`.
REGEX_REQUEST_BUDGET_S = 0.2

# Compiled patterns are cached per process. Rules are few (hundreds) and change rarely, so this bound is generous
# while still keeping memory finite (plan P9).
COMPILE_CACHE_SIZE = 4096

# The compiled form of one glob `*`. Consecutive `*` collapse to one copy, which matches exactly the same strings
# (`[^/]*[^/]*` and `[^/]*` accept the same text) and leaves `specificity` untouched (it is computed from the
# pattern text, not the compiled form), but removes needless backtracking.
_WILDCARD = r"[^/]*"
_WILDCARD_RUN = re.compile(r"(?:\[\^/\]\*){2,}")
_GLOB_WILDCARD_RUN = re.compile(r"\*+")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# The standard library's regex parser (the module behind `re.compile`). It is private API, so it is loaded
# dynamically and typed as Any; it has shipped as `re._parser` since Python 3.11. Parsing gives an exact tree of
# the pattern, which is far more reliable for spotting nested quantifiers than scanning the text ourselves.
_sre_parser: Any = importlib.import_module("re._parser")
_sre_constants: Any = importlib.import_module("re._constants")
_REPEAT_OPCODES = frozenset(
    {
        _sre_constants.MAX_REPEAT,
        _sre_constants.MIN_REPEAT,
        getattr(_sre_constants, "POSSESSIVE_REPEAT", _sre_constants.MAX_REPEAT),
    }
)
_UNBOUNDED_REPEAT: int = _sre_constants.MAXREPEAT


class PatternValidationError(ValueError):
    """An admin pattern or regex was refused. `message` is safe to show the admin as is."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# --- Normalization (v1 `_norm`, `_norm_regex`, `normalize_pattern`) -------------------------------------------


def kind_of(rule_type: str | None) -> PatternKind:
    """Map a stored rule type to a pattern kind. Like v1, anything other than "regex" is a glob."""
    return "regex" if rule_type == "regex" else "glob"


def normalize_glob(pattern: str | None) -> str:
    """v1 `_norm`: trim, drop leading slashes, lowercase."""
    return (pattern or "").strip().lstrip("/").lower()


def normalize_regex(pattern: str | None) -> str:
    """v1 `_norm_regex`: trim and drop leading slashes only (never lowercase a regex, see the module docstring)."""
    return (pattern or "").strip().lstrip("/")


def normalize_pattern(pattern: str | None, type: str = "glob") -> str:
    """v1 `normalize_pattern`: the stored form of a pattern of the given type."""
    return normalize_regex(pattern) if kind_of(type) == "regex" else normalize_glob(pattern)


def normalize_target(path: str | None) -> str:
    """The form of a request path that rules are matched against.

    v1's `match_endpoint_block`, `match_endpoint_rule` and `match_cache_rule` all ran the path through `_norm`
    before matching, for glob and regex rules alike, so this does the same.
    """
    return normalize_glob(path)


def specificity(pattern: str, type: str = "glob") -> tuple[int, int]:
    """v1 `_specificity`: the sort key for "most specific match wins" (higher wins).

    Globs: (number of `/`, length minus number of `*`), so a concrete rule beats a wildcard one covering the
    same path. Regexes: (number of `/`, length), because a regex has no clean notion of segments.
    """
    if kind_of(type) == "regex":
        return (pattern.count("/"), len(pattern))
    return (pattern.count("/"), len(pattern) - pattern.count("*"))


def glob_to_regex_source(pattern: str, *, subpaths: bool = True) -> str:
    """The regular expression text a glob compiles to (v1 `_compile_pattern`, plus wildcard-run collapsing).

    `subpaths=False` is the exact form used by the credential allowlist (lead decision F3): the glob names only
    the paths it spells out (and the same path with one trailing slash); a `*` still covers one segment.
    """
    base = pattern.rstrip("/")
    # Escape everything literally, then turn each escaped `*` (re.escape writes it as `\*`) back into a
    # single-segment wildcard. The stdlib `re.escape` is used on purpose: it is what v1 used, and its output is
    # valid for the `regex` module too.
    escaped = re.escape(base).replace(r"\*", _WILDCARD)
    escaped = _WILDCARD_RUN.sub(lambda _m: _WILDCARD, escaped)
    return rf"^{escaped}(?:/.*)?$" if subpaths else rf"^{escaped}/?$"


def _python_re_compile(pattern: str) -> re.Pattern[str] | None:
    """Compile with the stdlib `re` and v1's flags (what v1 ran); None when `re` refuses the pattern.

    FutureWarnings ("possible nested set") are silenced here: they describe what a future Python might do, and
    v1 parity is defined by what this Python's `re` does today. (validate_regex refuses such patterns for new
    rules instead.)
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        try:
            return re.compile(pattern, re.IGNORECASE)
        except (re.error, RecursionError, OverflowError):
            return None


# --- Reading a Python `re` pattern with the `regex` module ------------------------------------------------------
#
# The `regex` module (VERSION0, its default) is meant to be compatible with `re`, but it understands two
# extensions that `re` reads as plain characters, so the same text would match different strings:
#   * POSIX classes inside a set: `[[:alpha:]]` is "a letter" to `regex`, but to `re` it is the set of the
#     characters `[`, `:`, `a`, `l`, `p`, `h` followed by a literal `]`;
#   * fuzzy matching: `a{e<=1}` is "a, with up to one error" to `regex`, but literal text to `re`, because `re`
#     only reads `{` as a quantifier when it has the form `{m}`, `{m,}`, `{,n}` or `{m,n}`.
# `regex_dialect_source` escapes exactly those characters (a `[` inside a set, a `{` that `re` would not read as
# a quantifier). Escaping a character `re` already treats as a literal cannot change what `re` matches, and
# `_re_fingerprint` proves it for every pattern: the rewrite is used only when `re` parses it to the identical
# tree. Comments `(?#...)`, `\N{...}` escapes and verbose mode (`(?x)`, where `#` starts a comment) are skipped
# over so that a bracket inside them is never mistaken for a set.

_RE_QUANTIFIER_BRACE = re.compile(r"\{\d*(?:,\d*)?\}")
_SCOPED_FLAGS = re.compile(r"\(\?([aiLmsux]*)(?:-([imsx]*))?:")


def _copy_set(pattern: str, start: int, out: list[str]) -> int:
    """Copy the character set opening at `start`, escaping any `[` inside it; return the index after it."""
    index = start + 1
    if index < len(pattern) and pattern[index] == "^":
        index += 1
    out.append(pattern[start:index])
    members = 0  # like `re`, a `]` closes the set only after at least one member (so `[]a]` contains `]`)
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            out.append(pattern[index : index + 2])
            index += 2
        elif char == "]" and members:
            out.append(char)
            return index + 1
        else:
            out.append("\\[" if char == "[" else char)
            index += 1
        members += 1
    return index


def _regex_dialect_rewrite(pattern: str, verbose: bool) -> str:
    out: list[str] = []
    verbose_stack: list[bool] = []
    index, length = 0, len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            if pattern.startswith("N{", index + 1):  # a named character, \N{LATIN SMALL LETTER A}
                end = pattern.find("}", index)
                end = length - 1 if end < 0 else end
                out.append(pattern[index : end + 1])
                index = end + 1
            else:
                out.append(pattern[index : index + 2])
                index += 2
        elif char == "[":
            index = _copy_set(pattern, index, out)
        elif char == "#" and verbose:
            end = pattern.find("\n", index)
            end = length if end < 0 else end + 1
            out.append(pattern[index:end])
            index = end
        elif char == "(" and pattern.startswith("(?#", index):
            end = index + 3
            while end < length and pattern[end] != ")":
                end += 2 if pattern[end] == "\\" else 1
            out.append(pattern[index : end + 1])
            index = end + 1
        elif char == "(":
            verbose_stack.append(verbose)
            scoped = _SCOPED_FLAGS.match(pattern, index)
            if scoped:
                if "x" in scoped.group(1):
                    verbose = True
                if scoped.group(2) and "x" in scoped.group(2):
                    verbose = False
                out.append(scoped.group(0))
                index = scoped.end()
            else:
                out.append(char)
                index += 1
        elif char == ")":
            if verbose_stack:
                verbose = verbose_stack.pop()
            out.append(char)
            index += 1
        elif char == "{" and not _RE_QUANTIFIER_BRACE.match(pattern, index):
            out.append("\\{")
            index += 1
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _re_fingerprint(pattern: str) -> str | None:
    """How the stdlib `re` understands `pattern`: its parse tree, flags and group names, as comparable text."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        try:
            tree = _sre_parser.parse(pattern, re.IGNORECASE)
        except Exception:  # any parse failure means "not comparable"
            return None
    return repr((tree.data, tree.state.flags, sorted(tree.state.groupdict.items())))


def regex_dialect_source(pattern: str) -> str | None:
    """`pattern` rewritten so the `regex` module reads it exactly as Python `re` does; None if `re` refuses it."""
    compiled = _python_re_compile(pattern)
    if compiled is None:
        return None
    rewritten = _regex_dialect_rewrite(pattern, verbose=bool(compiled.flags & re.VERBOSE))
    if rewritten == pattern:
        return pattern
    if _re_fingerprint(rewritten) != _re_fingerprint(pattern):
        # Cannot happen for well-formed input (only literals were escaped); keep the original as a safe fallback.
        log.warning("rule_regex_dialect_mismatch", extra={"fields": {"pattern": pattern[:120]}})
        return pattern
    return rewritten


# --- Timeout accounting ---------------------------------------------------------------------------------------


class _TimeoutCounter:
    """Process-wide count of regex matches cut off by the timeout (exported for the System page)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0

    def add(self) -> int:
        with self._lock:
            self._count += 1
            return self._count

    @property
    def value(self) -> int:
        with self._lock:
            return self._count


_TIMEOUTS = _TimeoutCounter()


def regex_timeouts_total() -> int:
    """How many pattern matches in this process were stopped by `REGEX_MATCH_TIMEOUT_S` (or the request budget)."""
    return _TIMEOUTS.value


class _Budget:
    """Regex time left for the current request (see `regex_budget`)."""

    __slots__ = ("remaining_s",)

    def __init__(self, seconds: float) -> None:
        self.remaining_s = seconds


_BUDGET: ContextVar[_Budget | None] = ContextVar("roxy_regex_budget", default=None)


@contextlib.contextmanager
def regex_budget(seconds: float = REGEX_REQUEST_BUDGET_S, *, fresh: bool = False) -> Iterator[None]:
    """Cap the total time every pattern match inside this block may take together (per request, plan 9.9).

    Each match still has its own `REGEX_MATCH_TIMEOUT_S`; once the budget is spent, further matches are not run
    and are answered as timeouts (each caller's `on_timeout` decides what that means). A context variable, so
    concurrent requests on one event loop each have their own budget. Inside a block that already has a budget,
    a nested `regex_budget()` keeps that one: every phase of one request (cache peek, abuse checks, upstream
    routing) shares a single budget instead of each starting a fresh one.
    `fresh=True` always starts a new budget, for work that is not the current request's: a background task
    copies the context of the request that started it, and must not inherit (or spend) that request's budget.
    """
    if _BUDGET.get() is not None and not fresh:
        yield
        return
    token = _BUDGET.set(_Budget(seconds))
    try:
        yield
    finally:
        _BUDGET.reset(token)


def _run_with_timeout(run: Any, target: str) -> Any:
    """`run(target, timeout=...)` within the per-match timeout and the request budget; raises TimeoutError."""
    budget = _BUDGET.get()
    if budget is None:
        return run(target, timeout=REGEX_MATCH_TIMEOUT_S)
    if budget.remaining_s <= 0:
        raise TimeoutError("regex budget of this request is spent")
    started = time.perf_counter()
    try:
        return run(target, timeout=min(REGEX_MATCH_TIMEOUT_S, budget.remaining_s))
    finally:
        budget.remaining_s -= time.perf_counter() - started


def _record_timeout(source: str, pattern: str, target_length: int) -> None:
    total = _TIMEOUTS.add()
    # Log the first timeout and then every 100th, so a hot pathological rule cannot flood the log.
    if total == 1 or total % 100 == 0:
        log.warning(
            "rule_regex_timeout",
            extra={
                "fields": {
                    "source": source,
                    "pattern": pattern[:120],
                    "target_length": target_length,
                    "timeouts_total": total,
                }
            },
        )


# --- Compiled patterns ----------------------------------------------------------------------------------------


class CompiledPattern:
    """One stored pattern, compiled once and reused for every request.

    `matches(target)` takes an already normalized target (see `normalize_target`). A pattern that is empty or
    does not compile never matches, exactly like v1 (which caught `re.error` and returned False). An `exact`
    pattern (the credential allowlist only) must cover the WHOLE target: a glob gets no implicit subpaths and a
    regex is matched with `fullmatch` instead of `search`.
    """

    __slots__ = ("_rx", "exact", "kind", "pattern", "specificity")

    def __init__(self, pattern: str, kind: PatternKind, rx: regex.Pattern[str] | None, *, exact: bool = False) -> None:
        self.pattern = pattern
        self.kind: PatternKind = kind
        self.specificity: tuple[int, int] = specificity(pattern, kind)
        self._rx = rx
        self.exact = exact

    @property
    def valid(self) -> bool:
        """False for an empty or uncompilable pattern (it never matches)."""
        return self._rx is not None

    def matches(self, target: str, *, on_timeout: bool = False) -> bool:
        """Whether this pattern covers `target` (v1 `_matches`).

        A match cut off by the timeout (or by a spent `regex_budget`) answers `on_timeout`: False keeps traffic
        flowing for rules that grant something (cache, routing, the credential allowlist); rules that refuse or
        limit pass True, so a slow pattern can never be used to get past them (security review M4).
        """
        rx = self._rx
        if rx is None:
            return False
        if self.kind == "regex":
            # v1: regexes use search (the admin anchors them); an exact (allowlist) regex must cover the whole path.
            run = rx.fullmatch if self.exact else rx.search
        else:
            run = rx.match  # globs carry their own ^...$
        try:
            found = _run_with_timeout(run, target)
        except TimeoutError:
            # The counter and log make the bad rule visible on the System page.
            _record_timeout(f"pattern:{self.kind}", self.pattern, len(target))
            return on_timeout
        return found is not None

    def __repr__(self) -> str:
        return f"CompiledPattern({self.pattern!r}, {self.kind!r}{', exact' if self.exact else ''})"


@lru_cache(maxsize=COMPILE_CACHE_SIZE)
def compile_pattern(pattern: str, type: str = "glob", *, exact: bool = False) -> CompiledPattern:
    """Compile a stored pattern of the given rule type (v1 `_compile_pattern` plus the `_matches` guards).

    The pattern is used as stored; normalize it with `normalize_pattern` (or `validate_pattern`) at write time.
    `exact=True` is the credential allowlist's least-privilege form (see `CompiledPattern`); every other rule
    family keeps the v1 semantics.
    """
    kind = kind_of(type)
    if not pattern:
        return CompiledPattern(pattern, kind, None, exact=exact)
    re_source = pattern if kind == "regex" else glob_to_regex_source(pattern, subpaths=not exact)
    return CompiledPattern(pattern, kind, compile_like_re(re_source), exact=exact)


def compile_like_re(pattern: str) -> regex.Pattern[str] | None:
    """Compile `pattern` (Python `re` syntax, matched case-insensitively as v1 did) on the `regex` module so it
    matches exactly what `re.compile(pattern, re.IGNORECASE)` matches. None when `re` refuses it (v1 never
    matched such a pattern)."""
    try:
        source = re_compatible_source(pattern, re.IGNORECASE)
        flags = 0  # the translation spells out every case rule itself
    except UnsupportedPattern:
        # A parse tree the translator does not know (a newer Python): the older, less exact reading.
        log.warning("rule_regex_untranslated", extra={"fields": {"pattern": pattern[:120]}})
        source, flags = regex_dialect_source(pattern), regex.IGNORECASE
    if source is None:
        return None
    try:
        return regex.compile(source, flags)
    except (regex.error, RecursionError, OverflowError):
        return None


def matches(pattern: str, target: str, type: str = "glob") -> bool:
    """v1 `_matches`: whether a stored pattern covers an already normalized target."""
    return compile_pattern(pattern, type).matches(target)


def path_matches(pattern: str, path: str, type: str = "glob") -> bool:
    """v1 `path_matches` (used by cache purges): normalizes the path by kind, then matches.

    Note the difference from `normalize_target`: here a regex rule sees the path trimmed but NOT lowercased.
    """
    kind = kind_of(type)
    target = normalize_regex(path) if kind == "regex" else normalize_glob(path)
    return compile_pattern(pattern, type).matches(target)


# --- Choosing the winning rule ----------------------------------------------------------------------------------


class PatternRule(Protocol):
    """Anything with a row id, a stored pattern and a rule type (Pydantic rule models satisfy this)."""

    @property
    def id(self) -> int: ...

    @property
    def pattern(self) -> str: ...

    @property
    def type(self) -> str: ...


def best_match[R: PatternRule](rules: Iterable[R], target: str, *, normalize: bool = True) -> R | None:
    """The matching rule with the highest specificity; ties go to the lowest id (v1: first inserted wins).

    `target` is a request path; it is normalized with `normalize_target` unless `normalize=False`.
    For a hot path, build a `PatternIndex` once per rules snapshot instead of calling this per request.
    """
    path = normalize_target(target) if normalize else target
    best: R | None = None
    best_score: tuple[int, int] = (0, 0)
    for rule in rules:
        compiled = compile_pattern(rule.pattern, rule.type)
        if not compiled.matches(path):
            continue
        score = compiled.specificity
        if best is None or score > best_score or (score == best_score and rule.id < best.id):
            best = rule
            best_score = score
    return best


@dataclass(frozen=True, slots=True)
class IndexEntry[T]:
    """One rule inside a `PatternIndex`: its id, its compiled pattern and the caller's payload."""

    id: int
    compiled: CompiledPattern
    value: T


class PatternIndex[T]:
    """An immutable, pre-sorted list of compiled rules for one rules snapshot.

    Entries are sorted by (specificity descending, id ascending), so the FIRST entry that matches is exactly
    the rule v1 would have chosen. Build it once when the snapshot loads; matching then costs one compiled
    regex per rule until the first hit. `on_timeout` is what a timed-out match counts as (see
    `CompiledPattern.matches`): True for rules that refuse or limit traffic, so they fail closed. `exact=True`
    compiles every pattern in its exact form (the credential allowlist, lead decision F3).
    """

    __slots__ = ("_entries", "on_timeout")

    def __init__(
        self, entries: Iterable[tuple[int, str, str, T]], *, on_timeout: bool = False, exact: bool = False
    ) -> None:
        built = [
            IndexEntry(rule_id, compile_pattern(pattern, rule_type, exact=exact), value)
            for rule_id, pattern, rule_type, value in entries
        ]
        built.sort(key=lambda entry: (-entry.compiled.specificity[0], -entry.compiled.specificity[1], entry.id))
        self._entries: tuple[IndexEntry[T], ...] = tuple(built)
        self.on_timeout = on_timeout

    @classmethod
    def from_rules[R: PatternRule](cls, rules: Iterable[R]) -> PatternIndex[R]:
        """Index rule objects that carry `id`, `pattern` and `type` (the payload is the rule itself)."""
        return PatternIndex((rule.id, rule.pattern, rule.type, rule) for rule in rules)

    def best_entry(self, target: str, *, normalize: bool = True) -> IndexEntry[T] | None:
        """The winning entry for `target`, or None."""
        path = normalize_target(target) if normalize else target
        for entry in self._entries:
            if entry.compiled.matches(path, on_timeout=self.on_timeout):
                return entry
        return None

    def best(self, target: str, *, normalize: bool = True) -> T | None:
        """The winning payload for `target`, or None."""
        entry = self.best_entry(target, normalize=normalize)
        return None if entry is None else entry.value

    def any_match(self, target: str, *, normalize: bool = True) -> bool:
        """Whether any rule covers `target` (v1 `is_endpoint_blocked`)."""
        return self.best_entry(target, normalize=normalize) is not None

    def matching(self, target: str, *, normalize: bool = True) -> list[T]:
        """Every payload whose pattern covers `target`, winner first (used by rule testers in the UI)."""
        path = normalize_target(target) if normalize else target
        return [entry.value for entry in self._entries if entry.compiled.matches(path, on_timeout=self.on_timeout)]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[IndexEntry[T]]:
        return iter(self._entries)


# --- Text needles: User-Agent and header rules ------------------------------------------------------------------


@lru_cache(maxsize=COMPILE_CACHE_SIZE)
def _compile_text_regex(needle: str) -> regex.Pattern[str] | None:
    """v1 `_compile_header_regex`, on the `regex` module; None when the needle is not valid Python `re` syntax."""
    return compile_like_re(needle)


def precompile_text_regex(needle: str) -> None:
    """Compile a regex needle now (rules snapshot build, on a reader thread) instead of on the first request."""
    _compile_text_regex(needle)


def text_matches(mode: str, needle: str, target: str | None, *, on_timeout: bool = False) -> bool:
    """Whether a User-Agent or header rule needle matches `target` (v1 `_header_field_matches` and
    `_user_agent_matches`, which behave identically).

    * `regex`: search, case-insensitive, on the target as given (not lowercased);
    * `exact`: case-insensitive equality;
    * anything else (`contains`): case-insensitive substring.
    An empty needle never matches: v1 checked this in `rule_hit` and `_user_agent_matches` before matching.
    A regex cut off by the timeout answers `on_timeout`: header filters and User-Agent rules refuse or limit, so
    their callers pass True (fail closed, security review M4).
    """
    if not needle:
        return False
    text = target or ""
    if mode == "regex":
        rx = _compile_text_regex(needle)
        if rx is None:
            return False
        try:
            return _run_with_timeout(rx.search, text) is not None
        except TimeoutError:
            _record_timeout("text:regex", needle, len(text))
            return on_timeout
    text_lower = text.lower()
    needle_lower = needle.lower()
    if mode == "exact":
        return text_lower == needle_lower
    return needle_lower in text_lower


def header_rule_canonical_key(
    scope: str, mode: str, needle: str, header: str = "", *, keep_regex_escapes: bool = False
) -> str:
    """v1 `_header_rule_id` (plan 4.8 row 112): `header|scope|mode|needle`, header and needle lowercased.

    Stored in `rules_header.canonical_key` under a unique index, so imported rules keep their identity and a
    duplicate is refused exactly as in v1. Pass the values as normalized for storage (scope and mode lowercased
    and trimmed, needle and header trimmed, scope forced to "value" when a header is named), as v1 did.

    v1 lowercased regex needles too, so `^\\d+$` and `^\\D+$` (opposite rules) got the same id. New rules pass
    `keep_regex_escapes=True` (lead decision 3): a regex needle is lowercased except for the character after
    each backslash. Matching is case-insensitive, so lowercasing literals never changes what a regex matches,
    while the case of an escape (`\\d` against `\\D`) does.
    """
    if keep_regex_escapes and mode == "regex":
        return f"{header.lower()}|{scope}|{mode}|{_lower_keeping_escapes(needle)}"
    return f"{header.lower()}|{scope}|{mode}|{needle.lower()}"


def _lower_keeping_escapes(text: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            out.append(text[index : index + 2])  # the escape exactly as written
            index += 2
        else:
            out.append(char.lower())
            index += 1
    return "".join(out)


# --- Write-time validation (plan 9.9) ---------------------------------------------------------------------------


def _subpatterns(value: Any) -> Iterator[Any]:
    """Every parser SubPattern nested anywhere inside one opcode's argument."""
    if isinstance(value, _sre_parser.SubPattern):
        yield value
    elif isinstance(value, tuple | list):
        for item in value:
            yield from _subpatterns(item)


def _nested_quantifier(items: Any, inside_repeat: bool) -> bool:
    """Walk a parsed pattern; True when a variable-length repeat sits inside a group that repeats a variable
    number of times, or more than `NESTED_QUANTIFIER_OUTER_LIMIT` times (`(a+)+`, `(a{1,10}){1,10}`)."""
    for opcode, argument in items:
        if opcode in _REPEAT_OPCODES:
            low, high, body = argument
            variable = high == _UNBOUNDED_REPEAT or high > low
            if inside_repeat and variable:
                return True
            multiplies = high == _UNBOUNDED_REPEAT or high > 1
            repeats_a_lot = high == _UNBOUNDED_REPEAT or high > NESTED_QUANTIFIER_OUTER_LIMIT
            if _nested_quantifier(body, inside_repeat or (multiplies and (variable or repeats_a_lot))):
                return True
            continue
        for child in _subpatterns(argument):
            if _nested_quantifier(child, inside_repeat):
                return True
    return False


def _first_chars(items: Any) -> set[str] | None:
    """The (lowercased) characters a parsed piece can start with; None when unknown, very broad, or when it can
    match the empty string."""
    for opcode, argument in items:
        if opcode in (_sre_constants.AT, _sre_constants.ASSERT, _sre_constants.ASSERT_NOT):
            continue  # zero width: the next item decides
        if opcode == _sre_constants.LITERAL:
            return {chr(argument).lower()}
        if opcode == _sre_constants.IN:
            chars: set[str] = set()
            for item_op, item_av in argument:
                if item_op == _sre_constants.LITERAL:
                    chars.add(chr(item_av).lower())
                elif item_op == _sre_constants.RANGE and item_av[1] - item_av[0] < 256:
                    chars.update(chr(code).lower() for code in range(item_av[0], item_av[1] + 1))
                else:
                    return None  # a negated set, a category or a huge range: too broad to tell apart
            return chars
        if opcode == _sre_constants.SUBPATTERN:
            return _first_chars(argument[3])
        if opcode in _REPEAT_OPCODES:
            low, _high, body = argument
            return _first_chars(body) if low > 0 else None
        if opcode == _sre_constants.BRANCH:
            union: set[str] = set()
            for alternative in argument[1]:
                first = _first_chars(alternative)
                if first is None:
                    return None
                union |= first
            return union
        return None  # any character, a negated literal, a backreference...
    return None  # empty: matches the empty string


def _ambiguous_alternation(items: Any, in_repeat: bool) -> bool:
    """True when, inside a repeat, two alternatives can start with the same character (`(a|aa)+`): each
    repetition can then be split between the alternatives in many ways, and a failing match tries them all."""
    for opcode, argument in items:
        if opcode in _REPEAT_OPCODES:
            _low, high, body = argument
            if _ambiguous_alternation(body, in_repeat or high == _UNBOUNDED_REPEAT or high > 1):
                return True
            continue
        if opcode == _sre_constants.BRANCH and in_repeat:
            seen: set[str] = set()
            for alternative in argument[1]:
                first = _first_chars(alternative)
                if first is None or first & seen:
                    return True
                seen |= first
        for child in _subpatterns(argument):
            if _ambiguous_alternation(child, in_repeat):
                return True
    return False


def _unbounded_weight(items: Any, multiplier: int = 1) -> int:
    """How many unbounded repeats a match may have to juggle: each counts as often as enclosing groups repeat it
    (`(.*,){5}` weighs 5); of several alternatives only the heaviest counts."""
    total = 0
    for opcode, argument in items:
        if opcode in _REPEAT_OPCODES:
            _low, high, body = argument
            if high == _UNBOUNDED_REPEAT:
                total += multiplier
                total += _unbounded_weight(body, multiplier)
            else:
                total += _unbounded_weight(body, multiplier * max(1, high))
        elif opcode == _sre_constants.BRANCH:
            total += max((_unbounded_weight(alternative, multiplier) for alternative in argument[1]), default=0)
        else:
            total += sum(_unbounded_weight(child, multiplier) for child in _subpatterns(argument))
    return total


def _parse_for_checks(pattern: str) -> Any:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        try:
            return _sre_parser.parse(pattern, re.IGNORECASE)
        except Exception:  # the caller has already checked that the pattern compiles; be defensive anyway
            return None


def has_nested_quantifier(pattern: str) -> bool:
    """True for shapes like `(a+)+`, `(a*)*`, `(?:x|y+)*`, `((ab)+c)+`, `(a{1,10}){1,10}` that can backtrack
    exponentially."""
    tree = _parse_for_checks(pattern)
    return tree is not None and _nested_quantifier(tree, inside_repeat=False)


def slow_shape(pattern: str) -> str | None:
    """Why `pattern` could take exponential or high polynomial time to fail, in words for the admin; None if not
    (security review M4). Checked after `has_nested_quantifier`."""
    tree = _parse_for_checks(pattern)
    if tree is None:
        return None
    if _ambiguous_alternation(tree, in_repeat=False):
        return (
            "Alternatives inside a repeated group that can start with the same character, such as (a|aa)+, can "
            "take exponential time to fail; make each alternative start differently or move the repeat"
        )
    weight = _unbounded_weight(tree)
    if weight > MAX_UNBOUNDED_REPEATS:
        return (
            f"The pattern has {weight} open-ended repeats (*, + or {{n,}}, counted as often as their group "
            f"repeats); at most {MAX_UNBOUNDED_REPEATS} are allowed, because each one multiplies the time a "
            "failing match can take"
        )
    return None


def validate_regex(pattern: str, *, max_length: int = MAX_PATTERN_LENGTH) -> str:
    """Refuse a regular expression an admin may not store (plan 9.9); return it unchanged when it is fine.

    Used for regex endpoint patterns (after `normalize_regex`) and for User-Agent and header rule needles.
    """
    if not pattern:
        raise PatternValidationError("Empty regular expression")
    if len(pattern) > max_length:
        raise PatternValidationError(f"Regular expression is longer than {max_length} characters")
    if _CONTROL_CHARS.search(pattern):
        raise PatternValidationError("Regular expression contains a control character")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", FutureWarning)
        try:
            re.compile(pattern, re.IGNORECASE)
        except (re.error, RecursionError, OverflowError) as exc:
            raise PatternValidationError("Invalid regular expression") from exc
    if any(issubclass(warning.category, FutureWarning) for warning in caught):
        # For example "[[" or "--" inside a set: Python warns these may change meaning in a future version.
        raise PatternValidationError(
            "Ambiguous character set (such as [[ or -- inside [...]); escape the character with a backslash"
        )
    if compile_like_re(pattern) is None:
        raise PatternValidationError("Invalid regular expression")
    if has_nested_quantifier(pattern):
        raise PatternValidationError(
            "Nested quantifiers such as (a+)+ can take exponential time to fail; "
            "rewrite the pattern so a repeated group does not itself contain a repeat"
        )
    why = slow_shape(pattern)
    if why is not None:
        raise PatternValidationError(why)
    # Polynomial shapes (two repeats that trade characters, a chain of short ones, a repeat a search can restart
    # inside of): the cost model must finish an 8192 character worst case well inside the per-match timeout
    # (ingress review, finding INGRESS-2).
    why = regex_cost.cost_problem(pattern)
    if why is not None:
        raise PatternValidationError(why)
    return pattern


def validate_pattern(pattern: str | None, type: str = "glob", *, exact: bool = False) -> str:
    """Normalize and validate an endpoint pattern for storage; return the stored form.

    Error texts for the cases v1 also refused are v1's ("Empty endpoint pattern", "Invalid regular expression").
    `exact=True` validates for the exact form the credential allowlist compiles to (see `CompiledPattern`).
    """
    kind = kind_of(type)
    normalized = normalize_pattern(pattern, kind)
    if not normalized:
        raise PatternValidationError("Empty endpoint pattern")
    if kind == "regex":
        return validate_regex(normalized)
    if len(normalized) > MAX_PATTERN_LENGTH:
        raise PatternValidationError(f"Endpoint pattern is longer than {MAX_PATTERN_LENGTH} characters")
    if _CONTROL_CHARS.search(normalized):
        raise PatternValidationError("Endpoint pattern contains a control character")
    if len(_GLOB_WILDCARD_RUN.findall(normalized)) > MAX_GLOB_WILDCARDS:
        raise PatternValidationError(f"Endpoint pattern has more than {MAX_GLOB_WILDCARDS} wildcards")
    segments = normalized.rstrip("/").split("/")
    if any(len(_GLOB_WILDCARD_RUN.findall(part)) > MAX_GLOB_WILDCARDS_PER_SEGMENT for part in segments):
        raise PatternValidationError(
            f"Endpoint pattern has more than {MAX_GLOB_WILDCARDS_PER_SEGMENT} wildcards in one path segment; "
            "wildcards in the same segment can take a very long time to fail on a long path"
        )
    # Two wildcards in one segment trade characters: where more text must still match after that segment, a
    # failing match tries every split of a long segment between them (about 30 ms on 4096 characters). In the last
    # segment only text after the second one can fail (checked by the cost model below), except in the exact
    # form, which must end there.
    crowded = segments if exact else segments[:-1]
    if any(len(_GLOB_WILDCARD_RUN.findall(part)) > 1 for part in crowded):
        where = "one path segment" if exact else "one path segment before the last one"
        raise PatternValidationError(
            f"Endpoint pattern has two wildcards in {where}; a failing match can try every way to split a long "
            "segment between them, so use one wildcard per segment (or a regular expression)"
        )
    # Then the regex budget every new regex meets, on the regex the glob compiles to (finding INGRESS-2): two
    # wildcards in the last segment are fine when nothing after them can fail (`*-*`), but text after the second
    # one (`*a*b`) makes a failing match try every split of the segment between them.
    if regex_cost.cost_problem(glob_to_regex_source(normalized, subpaths=not exact)) is not None:
        raise PatternValidationError(
            "Endpoint pattern has two wildcards in one segment with more text after the second one; a failing match "
            f"can try every way to split a long segment between them (too long on a path of {regex_cost.TARGET_LENGTH} "
            "characters), so use one wildcard per segment (or a regular expression)"
        )
    return normalized


__all__ = [
    "COMPILE_CACHE_SIZE",
    "MAX_GLOB_WILDCARDS",
    "MAX_GLOB_WILDCARDS_PER_SEGMENT",
    "MAX_PATTERN_LENGTH",
    "MAX_UNBOUNDED_REPEATS",
    "REGEX_MATCH_TIMEOUT_S",
    "REGEX_REQUEST_BUDGET_S",
    "CompiledPattern",
    "IndexEntry",
    "PatternIndex",
    "PatternKind",
    "PatternRule",
    "PatternValidationError",
    "best_match",
    "compile_like_re",
    "compile_pattern",
    "glob_to_regex_source",
    "has_nested_quantifier",
    "header_rule_canonical_key",
    "kind_of",
    "matches",
    "normalize_glob",
    "normalize_pattern",
    "normalize_regex",
    "normalize_target",
    "path_matches",
    "precompile_text_regex",
    "regex_budget",
    "regex_dialect_source",
    "regex_timeouts_total",
    "slow_shape",
    "specificity",
    "text_matches",
    "validate_pattern",
    "validate_regex",
]
