"""Python `re` answers on the `regex` engine: rewrite a pattern so the `regex` module matches exactly what `re` would.

What this is
    `re_compatible_source(pattern, flags)` returns source text for the third-party `regex` module that matches
    exactly the strings the standard library's `re.compile(pattern, flags)` matches, case-insensitivity included.
    Compile the result WITHOUT `regex.IGNORECASE`: every case rule is already written out in it. It returns None
    when `re` refuses the pattern.

Why it exists
    Two binding rules meet here. Plan 4.8 row 111 says every rule pattern gives v1's answers, and v1 matched with
    `re`. DESIGN.md section 5 says patterns run on the `regex` module, because it has a per-match timeout and `re`
    cannot be interrupted (a bad pattern would freeze a worker). The two engines read some things differently:
      * `\\w`, `\\W`, `\\b` and `\\B`: `regex` follows the Unicode standard's word definition, `re` uses Python's
        `str.isalnum()` plus `_`. They disagree on 26,120 code points (superscript digits, combining marks...);
      * `\\d` (90 code points) and `\\s` (for example the control characters 0x1C to 0x1F);
      * case-insensitive matching: `re` treats dotless i and dotted capital I as forms of i, `regex` does not;
      * `\\B` on an empty string (never matches in `re` before Python 3.14).
    So a rule could match a request in v1 and not in v2, or the other way round.

How it works
    The pattern is parsed with the standard library's own parser (`re._parser`, what `re.compile` runs), and new
    source is generated from that tree node by node, using only constructs both engines read identically:
      * every character set (`[...]`, `\\w`, `\\d`, `\\s`, `.`, a negated literal) becomes an explicit list of
        code point ranges. The list is computed by asking `re` itself which code points the set matches, so it
        is right by construction for the Python this runs on (the same 3.12 as v1);
      * a literal under IGNORECASE becomes the explicit set of characters `re` accepts for it, except that runs of
        ASCII characters whose case variants both engines agree on (most letters, but not `i`) stay a plain
        `(?i:text)` string, which `regex` matches much faster;
      * anchors and word boundaries become lookarounds over those explicit sets;
      * a large set (the word set has about 750 ranges) is written once, in a `(?(DEFINE)...)` block at the end,
        and used through subroutine calls, which keeps compiling fast;
      * groups keep their numbers, so backreferences and conditionals still point at the right group.
    Computing a set costs a few milliseconds the first time (results are cached), and happens when a rules
    snapshot is built, on a reader thread. One approximation remains: a backreference under IGNORECASE uses the
    `regex` module's case folding (identical to `re` for everything but a handful of exotic letters). If the
    parser ever returns a node this module does not know, `re_compatible_source` raises `UnsupportedPattern` and
    the caller falls back to its older, less exact path.

What to read next
    `roxy/rules/match.py` (the only caller), then `tests/unit/rules/test_match.py`, which compares this module
    with `re` over every code point and replays generated patterns through a frozen copy of v1's matcher.
"""

from __future__ import annotations

import importlib
import re
import threading
import warnings
from collections.abc import Iterable, Sequence
from functools import lru_cache
from typing import Any

import regex

_parser: Any = importlib.import_module("re._parser")
_constants: Any = importlib.import_module("re._constants")
_casefix: Any = importlib.import_module("re._casefix")
_sre: Any = importlib.import_module("_sre")

MAX_CODE_POINT = 0x10FFFF

Ranges = tuple[tuple[int, int], ...]
"""A set of code points as sorted, disjoint, inclusive (low, high) ranges."""

_I = re.IGNORECASE
_M = re.MULTILINE
_S = re.DOTALL
_A = re.ASCII
_U = re.UNICODE
_TYPE_FLAGS = re.ASCII | re.UNICODE | getattr(re, "LOCALE", 0)

# Any one character, and "no character here" (the start or the end of the string), in both engines.
_ANY = r"[\s\S]"
_AT_START = r"(?<![\s\S])"
_AT_END = r"(?![\s\S])"


class UnsupportedPattern(ValueError):
    """The stdlib parser produced a node this translator does not handle (a future Python, most likely)."""


# --- code point sets ------------------------------------------------------------------------------------------------


def _merge(points: Iterable[tuple[int, int]]) -> Ranges:
    merged: list[list[int]] = []
    for low, high in sorted(points):
        if merged and low <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    return tuple((low, high) for low, high in merged)


def _complement(ranges: Ranges) -> Ranges:
    out: list[tuple[int, int]] = []
    start = 0
    for low, high in ranges:
        if low > start:
            out.append((start, low - 1))
        start = high + 1
    if start <= MAX_CODE_POINT:
        out.append((start, MAX_CODE_POINT))
    return tuple(out)


def _intersect(left: Ranges, right: Ranges) -> Ranges:
    out: list[tuple[int, int]] = []
    i = j = 0
    while i < len(left) and j < len(right):
        low = max(left[i][0], right[j][0])
        high = min(left[i][1], right[j][1])
        if low <= high:
            out.append((low, high))
        if left[i][1] < right[j][1]:
            i += 1
        else:
            j += 1
    return tuple(out)


def _points(points: Iterable[int]) -> Ranges:
    return _merge((point, point) for point in points)


_all_lock = threading.Lock()


@lru_cache(maxsize=1)
def _categories() -> dict[tuple[str, bool], Ranges]:
    """The code points of each `re` category (`\\d`, `\\s`, `\\w`; Unicode and ASCII), as `re` defines them.

    Runs `re` over strings that hold every code point in order, so each run of matches is one range. The strings
    are built and scanned in chunks of 64Ki code points: one C call over all 1.1 million would hold the GIL for
    about 50 ms and stall the event loop thread even though this runs on another thread. About 0.15 s in all,
    once per process; `warm_up` does it on a reader thread at the first rules load.
    """
    chunk = 0x10000
    with _all_lock:
        pieces: dict[tuple[str, bool], list[tuple[int, int]]] = {}
        compiled = {
            (code, ascii_only): re.compile(f"{escape}+", _A if ascii_only else _U)
            for code, escape in (("digit", r"\d"), ("space", r"\s"), ("word", r"\w"))
            for ascii_only in (False, True)
        }
        for start in range(0, MAX_CODE_POINT + 1, chunk):
            text = "".join(map(chr, range(start, min(start + chunk, MAX_CODE_POINT + 1))))
            for key, pattern in compiled.items():
                pieces.setdefault(key, []).extend(
                    (start + m.start(), start + m.end() - 1) for m in pattern.finditer(text)
                )
        return {key: _merge(found) for key, found in pieces.items()}


def _category(code: str, ascii_only: bool) -> Ranges:
    """The code points of one `re` category (`\\d`, `\\s` or `\\w`)."""
    return _categories()[(code, ascii_only)]


def warm_up() -> None:
    """Build the one-time tables (categories and case mappings, about 0.15 s) now.

    Call it off the event loop (the rules snapshot build does, on a reader thread), so the first admin pattern
    validated on the event loop does not pay for them.
    """
    _categories()
    _cased()


@lru_cache(maxsize=1)
def _cased() -> tuple[frozenset[int], dict[int, tuple[int, ...]]]:
    """Code points that take part in any case mapping, and the inverse of `re`'s simple lowercase mapping.

    A code point outside this set is matched by a character set under IGNORECASE exactly as without it, which is
    what lets `_set_for` test only these one by one (a few thousand instead of 1.1 million).
    """
    cased: set[int] = set()
    for point in range(MAX_CODE_POINT + 1):
        if _sre.unicode_iscased(point) or _sre.unicode_tolower(point) != point:
            cased.add(point)
    extra: dict[int, tuple[int, ...]] = _casefix._EXTRA_CASES
    for low, others in extra.items():
        cased.add(low)
        cased.update(others)
    cased.update({_sre.unicode_tolower(point) for point in list(cased)})
    inverse: dict[int, list[int]] = {}
    for point in cased:
        inverse.setdefault(_sre.unicode_tolower(point), []).append(point)
    return frozenset(cased), {low: tuple(sorted(points)) for low, points in inverse.items()}


_CATEGORY_ESCAPES: dict[Any, tuple[str, str, bool]] = {
    _constants.CATEGORY_DIGIT: (r"\d", "digit", False),
    _constants.CATEGORY_NOT_DIGIT: (r"\D", "digit", True),
    _constants.CATEGORY_SPACE: (r"\s", "space", False),
    _constants.CATEGORY_NOT_SPACE: (r"\S", "space", True),
    _constants.CATEGORY_WORD: (r"\w", "word", False),
    _constants.CATEGORY_NOT_WORD: (r"\W", "word", True),
}


def _escape_point(point: int) -> str:
    """One code point as `regex` (and `re`) source: ASCII letters and digits as themselves (shorter source compiles
    faster), everything else as a `\\U` escape, which means the same character in a set and outside one."""
    if point < 128 and chr(point).isalnum():
        return chr(point)
    return f"\\U{point:08x}"


def _class_text(items: Sequence[tuple[Any, Any]]) -> str:
    """`re` source for one parsed character set (so `re` can be asked what it matches)."""
    parts: list[str] = []
    negate = False
    for op, av in items:
        if op is _constants.NEGATE:
            negate = True
        elif op is _constants.LITERAL:
            parts.append(_escape_point(av))
        elif op is _constants.RANGE:
            parts.append(f"{_escape_point(av[0])}-{_escape_point(av[1])}")
        elif op is _constants.CATEGORY and av in _CATEGORY_ESCAPES:
            parts.append(_CATEGORY_ESCAPES[av][0])
        else:
            raise UnsupportedPattern(f"set item {op}")
    return "[" + ("^" if negate else "") + "".join(parts) + "]"


def _relevant(flags: int) -> int:
    return flags & (_I | _A | _U)


@lru_cache(maxsize=4096)
def _set_for(class_text: str, items: tuple[tuple[Any, Any], ...], flags: int) -> Ranges:
    """Exactly the code points `re.compile(class_text, flags)` matches (one character each)."""
    ascii_only = not flags & _U
    pieces: list[tuple[int, int]] = []
    negate = False
    for op, av in items:
        if op is _constants.NEGATE:
            negate = True
        elif op is _constants.LITERAL:
            pieces.append((av, av))
        elif op is _constants.RANGE:
            pieces.append((av[0], av[1]))
        else:
            _escape, code, negated = _CATEGORY_ESCAPES[av]
            ranges = _category(code, ascii_only)
            pieces.extend(_complement(ranges) if negated else ranges)
    base = _merge(pieces)
    if negate:
        base = _complement(base)
    if not flags & _I:
        return base
    # Under IGNORECASE only characters that take part in a case mapping can change their answer: test those one by
    # one against `re` itself, and keep the case-sensitive answer for everything else.
    cased, _inverse = _cased()
    compiled = re.compile(class_text, flags)
    uncased = _intersect(base, _complement(_points(cased)))
    matched = [point for point in cased if compiled.fullmatch(chr(point))]
    return _merge((*uncased, *((point, point) for point in matched)))


@lru_cache(maxsize=4096)
def _literal_set(point: int, flags: int) -> Ranges:
    """The characters `re` accepts for the literal `point` under `flags`."""
    if not flags & _I:
        return ((point, point),)
    compiled = re.compile(_escape_point(point), flags)
    if flags & _U:
        _cased_points, inverse = _cased()
        low = _sre.unicode_tolower(point)
        candidates = {point, *inverse.get(low, ())}
        for extra in _casefix._EXTRA_CASES.get(low, ()):
            candidates.add(extra)
            candidates.update(inverse.get(extra, ()))
    else:
        candidates = {point, _sre.ascii_tolower(point)}
        candidates.update(other for other in range(128) if _sre.ascii_tolower(other) == _sre.ascii_tolower(point))
    return _points(candidate for candidate in candidates if compiled.fullmatch(chr(candidate)))


def class_source(ranges: Ranges) -> str:
    """`regex` source for a set of code points: one escaped character, a `[...]` set, or "never" for empty."""
    if not ranges:
        return "(?!)"
    if len(ranges) == 1 and ranges[0][0] == ranges[0][1]:
        return _escape_point(ranges[0][0])
    parts = [
        _escape_point(low) if low == high else f"{_escape_point(low)}-{_escape_point(high)}" for low, high in ranges
    ]
    return "[" + "".join(parts) + "]"


@lru_cache(maxsize=256)
def _regex_ignorecase_agrees(point: int, flags: int) -> bool:
    """True when the `regex` module's own case-insensitive match of the ASCII character `point` accepts exactly
    the characters `re` accepts for it under `flags`.

    Then a run of such literals can be emitted as `(?i:text)`, which `regex` matches as one fast literal string
    instead of a chain of sets. It holds for most ASCII letters, not for `i` (re also accepts dotted capital I and
    dotless i). Unicode case folding is stable, so no newer Unicode version adds a variant of an ASCII letter
    outside the code points already checked here.
    """
    if point >= 128:
        return False
    expected = _literal_set(point, flags)
    cased, _inverse = _cased()
    compiled = regex.compile("(?i:" + _escape_point(point) + ")")
    accepted = _points(candidate for candidate in {point, *cased} if compiled.fullmatch(chr(candidate)))
    return accepted == expected


def _word_ranges(ascii_only: bool) -> Ranges:
    return _category("word", ascii_only)


# --- the tree walk --------------------------------------------------------------------------------------------------


def _combine(flags: int, add: int, delete: int) -> int:
    """Flags inside a scoped group `(?a-b:...)`, as the stdlib compiler combines them."""
    if add & _TYPE_FLAGS:
        flags &= ~_TYPE_FLAGS
    return (flags | add) & ~delete


BIG_SET_RANGES = 24
"""A set with more ranges than this (`\\w` has about 750) is written once per pattern, inside `(?(DEFINE)...)`,
and used through a subroutine call `(?&name)`: a word boundary needs the word set four times, and repeating 15 KB
of ranges made compiling one such pattern take 40 ms instead of 6. Never inside a lookbehind: the `regex` module
(2026.9) gets a subroutine call inside a lookbehind wrong (`x(?<=(?&d))` misses "x"), so sets there are inlined."""


class _Emitter:
    def __init__(self, names: dict[int, str]) -> None:
        self._names = names
        self._defined: dict[str, str] = {}  # set source -> subroutine group name
        self._behind = 0  # > 0 while emitting the body of a lookbehind
        prefix = "roxyset"
        while any(name.startswith(prefix) for name in names.values()):
            prefix += "x"  # never collide with a group name of the pattern itself
        self._prefix = prefix

    def finish(self, body: str) -> str:
        """The whole pattern: `body` plus the shared big sets. The DEFINE groups come last, so the pattern's own
        groups keep their numbers (backreferences and conditionals refer to them by number)."""
        if not self._defined:
            return body
        groups = "".join(f"(?P<{name}>{source})" for source, name in self._defined.items())
        return f"{body}(?(DEFINE){groups})"

    def set(self, ranges: Ranges) -> str:
        source = class_source(ranges)
        if len(ranges) <= BIG_SET_RANGES or self._behind:
            return source
        name = self._defined.setdefault(source, f"{self._prefix}{len(self._defined)}")
        return f"(?&{name})"

    def items(self, items: Iterable[tuple[Any, Any]], flags: int) -> str:
        out: list[str] = []
        run: list[int] = []  # ASCII literals the `regex` module can match case-insensitively by itself
        for op, av in items:
            if op is _constants.LITERAL and flags & _I and _regex_ignorecase_agrees(av, _relevant(flags)):
                run.append(av)
                continue
            if run:
                out.append("(?i:" + "".join(map(_escape_point, run)) + ")")
                run = []
            out.append(self.node(op, av, flags))
        if run:
            out.append("(?i:" + "".join(map(_escape_point, run)) + ")")
        return "".join(out)

    def node(self, op: Any, av: Any, flags: int) -> str:
        c = _constants
        if op is c.LITERAL:
            return self.set(_literal_set(av, _relevant(flags)))
        if op is c.NOT_LITERAL:
            return self.set(_complement(_literal_set(av, _relevant(flags))))
        if op is c.ANY:
            return _ANY if flags & _S else self.set(_complement(((10, 10),)))
        if op is c.IN:
            items = tuple(av)
            return self.set(_set_for(_class_text(items), items, _relevant(flags)))
        if op is c.AT:
            return self._at(av, flags)
        if op is c.BRANCH:
            return "(?:" + "|".join(self.items(branch, flags) for branch in av[1]) + ")"
        if op is c.SUBPATTERN:
            group, add, delete, body = av
            inner = self.items(body, _combine(flags, add, delete))
            if group is None:
                return f"(?:{inner})"
            name = self._names.get(group)
            return f"(?P<{name}>{inner})" if name else f"({inner})"
        if op in (c.MAX_REPEAT, c.MIN_REPEAT) or op is getattr(c, "POSSESSIVE_REPEAT", None):
            low, high, body = av
            suffix = "?" if op is c.MIN_REPEAT else "+" if op is not c.MAX_REPEAT else ""
            return f"(?:{self.items(body, flags)}){_quantifier(low, high)}{suffix}"
        if op is getattr(c, "ATOMIC_GROUP", None):
            return f"(?>{self.items(av, flags)})"
        if op is c.ASSERT or op is c.ASSERT_NOT:
            direction, body = av
            kind = ("=" if op is c.ASSERT else "!") if direction == 1 else ("<=" if op is c.ASSERT else "<!")
            if direction == 1:
                return f"(?{kind}{self.items(body, flags)})"
            self._behind += 1
            try:
                return f"(?{kind}{self.items(body, flags)})"
            finally:
                self._behind -= 1
        if op is c.GROUPREF:
            # The one approximation (module docstring): `regex`'s own case folding for a case-insensitive backref.
            return f"(?i:\\g<{av}>)" if flags & _I else f"(?:\\g<{av}>)"
        if op is c.GROUPREF_EXISTS:
            group, yes, no = av
            otherwise = "" if no is None else "|" + self.items(no, flags)
            return f"(?({group}){self.items(yes, flags)}{otherwise})"
        if op is c.FAILURE:
            return "(?!)"
        if op is c.SUCCESS:
            return ""
        raise UnsupportedPattern(f"opcode {op}")

    def _at(self, code: Any, flags: int) -> str:
        c = _constants
        if code is c.AT_BEGINNING_STRING:
            return _AT_START
        if code is c.AT_END_STRING:
            return _AT_END
        if code is c.AT_BEGINNING:
            # `^`: the start of the string; with MULTILINE also right after every "\n".
            return f"(?:{_AT_START}|(?<=\\n))" if flags & _M else _AT_START
        if code is c.AT_END:
            # `$`: the end, or just before a final "\n"; with MULTILINE also before every "\n".
            return f"(?=\\n|{_AT_END})" if flags & _M else f"(?=\\n?{_AT_END})"
        if code is c.AT_BOUNDARY or code is c.AT_NON_BOUNDARY:
            ranges = _word_ranges(not flags & _U)
            behind = class_source(ranges)  # always inline in a lookbehind (see BIG_SET_RANGES)
            ahead = self.set(ranges)
            # One lookbehind (a conditional on it) instead of two: the inlined word set is the bulk of the source.
            if code is c.AT_BOUNDARY:
                return f"(?(?<={behind})(?!{ahead})|(?={ahead}))"
            # `re` never finds \B in an empty string (Python 3.12), hence the "some character is near" condition.
            return f"(?(?<={behind})(?={ahead})|(?!{ahead})(?:(?<={_ANY})|(?={_ANY})))"
        raise UnsupportedPattern(f"anchor {code}")


def _quantifier(low: int, high: int) -> str:
    unbounded = high == _constants.MAXREPEAT
    if unbounded:
        return "*" if low == 0 else "+" if low == 1 else f"{{{low},}}"
    if low == high:
        return f"{{{low}}}"
    if (low, high) == (0, 1):
        return "?"
    return f"{{{low},{high}}}"


def parse(pattern: str, flags: int) -> Any:
    """The stdlib parse tree of `pattern` (FutureWarnings about possible future syntax silenced)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        return _parser.parse(pattern, flags)


@lru_cache(maxsize=4096)
def re_compatible_source(pattern: str, flags: int = re.IGNORECASE) -> str | None:
    """`regex` source matching exactly what `re.compile(pattern, flags)` matches; None if `re` refuses it.

    Compile the result with no flags. Raises `UnsupportedPattern` for a parse tree it does not know.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        try:
            re.compile(pattern, flags)  # some errors (look-behind width, bad group refs) only show up here
            tree = _parser.parse(pattern, flags)
        except (re.error, RecursionError, OverflowError):
            return None
    names = {number: name for name, number in tree.state.groupdict.items()}
    emitter = _Emitter(names)
    return emitter.finish(emitter.items(tree, tree.state.flags))


__all__ = ["UnsupportedPattern", "class_source", "parse", "re_compatible_source", "warm_up"]
