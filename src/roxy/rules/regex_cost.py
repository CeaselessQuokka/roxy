"""Worst-case cost of a new regular expression on a long caller input: the write-time ReDoS budget (plan 9.9).

What this is
    `cost_problem(pattern)` estimates how much work the matcher may do to FAIL a search of `pattern` over a
    caller-chosen text of `TARGET_LENGTH` characters (an 8 KiB path or header value: the catalog's largest
    `max_url_length` and `max_header_bytes`), and returns a plain refusal message naming the repeats responsible
    when the estimate is over `STEP_BUDGET`, or None. `estimate` returns the costliest charge itself.
    `rules/match.py validate_regex` calls `cost_problem` for every NEW regex, and `validate_pattern` for every new
    glob (on the regex the glob compiles to); stored patterns (imported from v1) are never judged again, and the
    per-match timeout stays their backstop.

Why it exists
    The 50 ms per-match timeout and the per-request budget stop one slow pattern from freezing a worker, but a
    pattern that needs the timeout on every request still costs 50 ms of a worker per request, and a cut-off
    match is answered with a guess. New patterns should finish well inside the timeout. The structural checks in
    `match.py` (nested quantifiers, ambiguous alternatives, too many open-ended repeats) stop exponential shapes;
    polynomial shapes need a cost model, because `x+x+y` takes seconds on 4096 characters while `\\d+/\\d+` (two
    repeats that can never trade characters) takes microseconds. The model was calibrated against the `regex`
    module running the translated patterns Roxy really runs (`.remake/scripts/fix1u_redos_shapes*.py`,
    `rr_ue_cost_measure*.py`): one unit below costs 1.5 to 5 ns there for long repeats and up to about 9 ns for
    chains of optional characters, so the 3 million unit budget is about 5 to 25 ms on an 8 KiB input, under half
    of the timeout (the slowest accepted shapes measured 20 ms).

How it works
    1. Parse with Python's own `re` parser (the language v1 rules are written in) and flatten the tree into
       paths of elements: single characters, repeats, zero-width assertions. Alternatives that contain a long
       repeat split the path (at most `MAX_PATHS` paths); other alternatives become one element (variable when
       its alternatives differ in length). A small fixed repeat of a group with a variable repeat inside
       (`(a+){3}`, `(\\d{1,3}\\.){3}`) is unrolled. Lookaround bodies are inlined as optional text followed by a
       zero-width test.
    2. An element is "variable" when the length of text it consumes can vary (any repeat whose count can vary, an
       optional character, alternatives of different lengths), and "long" when that variation is open-ended or
       more than `LONG_SPAN`. Character sets are bit masks over a finite alphabet: printable ASCII, every character
       the pattern names (in both cases), and a few non-ASCII stand-ins, so `\\w` and `[a-z]` overlap and `\\d` and
       `/` do not.
    3. An unanchored pattern (no leading `^` or `\\A`) is searched: the engine retries it from every start. That is
       modeled as an invisible leading repeat that matches anything.
    4. Two variable elements "trade" when some character is accepted by both and every required element between
       them accepts one of those characters too: the engine can then split a run of such characters between the
       two in many ways, and a failing match tries them all. For each variable element, the costliest chain of
       trading elements ending at it gives a count of splits: per link `n / (2 * (gap + 1))` after a long element
       (`gap` being the minimum length of the text between the two), or exactly its `span + 1` lengths after a
       short one, so a chain of short repeats (`\\w{0,10}` four times, `[a-z]?` twenty times) multiplies like the
       combinations the engine really tries (finding INGRESS-2; such chains used to be free in the model). An
       element is charged `splits * reach * step` only when something after it can still fail once it has eaten a
       run (a required element that rejects one of its characters, or an assertion such as `$` that no `.*`
       before it can always satisfy). `step` weighs the repeated element and the test that follows it: a Unicode
       class such as `\\d` costs about 60 single characters, `\\w` 200, `$` 25, `\\b` 100, because
       `rules/re_compat.py` spells them out exactly as Python `re` defines them.
    The estimate is an upper bound in this model, not a promise about every engine optimization: it can refuse a
    pattern the engine happens to run fast. Each refusal says what to change (anchor with `^`, start with fixed
    text, or make the text between two repeats something the first cannot match).

What to read next
    `roxy/rules/match.py` (`validate_regex`, the structural checks, the timeout and the request budget) and
    `tests/unit/rules/test_regex_cost.py` (calibration cases and measured worst-case inputs).
"""

from __future__ import annotations

import importlib
import math
import re
import warnings
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Final

from roxy.config.catalog import CATALOG

_sre_parser: Any = importlib.import_module("re._parser")
_c: Any = importlib.import_module("re._constants")

INPUT_BOUND_SETTINGS: Final = ("max_url_length", "max_header_bytes")
"""The settings that bound the text a rule pattern runs on: a path (endpoint, cache, routing and allowlist rules)
or a header value (User-Agent and header rules)."""

TARGET_LENGTH: Final = max(int(CATALOG[key].max or 0) for key in INPUT_BOUND_SETTINGS)
"""The caller input the budget is computed for: the longest path or header value any configuration admits (the
catalog maximum of both settings, 8192). Sizing it at the default 4096 let a pattern that is fast on a 4 KiB path
need the timeout on an 8 KiB User-Agent (finding INGRESS-2)."""

STEP_BUDGET: Final = 3_000_000
"""Most cost units a failing match may need on `TARGET_LENGTH` characters (about 5 to 25 ms, see the docstring)."""

LONG_SPAN: Final = 10
"""A repeat whose count can vary by more than this (or is open-ended) can trade characters with another one."""

MAX_PATHS: Final = 64
"""Most alternative paths through one pattern that are costed one by one."""

MAX_LONG_REPEATS: Final = 24
"""Most long repeats on one path. More are refused outright: no realistic endpoint or header rule needs them."""

MAX_VARIABLE: Final = 64
"""Most variable elements (repeats, optional parts) on one path. More are refused outright: no realistic rule needs
them, and it keeps the analysis itself quick (it compares every pair of them)."""

MAX_UNROLL: Final = 10
"""A fixed repeat of a group that holds a long repeat is unrolled up to this many times (`(a+){3}`)."""

GROUP_OVERHEAD: Final = 10
"""Cost of one iteration of a repeated group, on top of its characters (entering and leaving the group)."""

_SMALL_SET_SPAN: Final = 256
"""A character set covering fewer code points than this (and no class like `\\w`) is cheap to test."""

_WEIGHT_LITERAL: Final = 1.0
_WEIGHT_SMALL_SET: Final = 2.0
_WEIGHT_NEGATED_SET: Final = 3.0
_WEIGHT_BIG_SET: Final = 60.0  # \d, \s, a wide range: re_compat spells out the exact Unicode set (about 150 ns)
_WEIGHT_WORD_SET: Final = 200.0  # \w and \W: the largest of those sets (about 500 ns per test)
_WEIGHT_END: Final = 25.0  # $ (the end, or before a final newline)
_WEIGHT_END_STRING: Final = 15.0  # \Z
_WEIGHT_BOUNDARY: Final = 100.0  # \b and \B: a lookbehind on the whole word set
_WEIGHT_LOOKAROUND: Final = 15.0
_WEIGHT_BACKREF: Final = 10.0

_NON_ASCII_STAND_INS: Final = "éßıİKſа中٣  ²́"
_BASE_ALPHABET: Final = frozenset(chr(code) for code in range(0x20, 0x7F)) | {"\t"} | frozenset(_NON_ASCII_STAND_INS)
_WORD: Final = re.compile(r"\w")

_CATEGORY_SOURCE: Final = {
    _c.CATEGORY_DIGIT: r"\d",
    _c.CATEGORY_NOT_DIGIT: r"\D",
    _c.CATEGORY_SPACE: r"\s",
    _c.CATEGORY_NOT_SPACE: r"\S",
    _c.CATEGORY_WORD: r"\w",
    _c.CATEGORY_NOT_WORD: r"\W",
}
_REPEATS: Final = frozenset({_c.MAX_REPEAT, _c.MIN_REPEAT, getattr(_c, "POSSESSIVE_REPEAT", _c.MAX_REPEAT)})
_ATOMS: Final = frozenset({_c.LITERAL, _c.NOT_LITERAL, _c.ANY, _c.IN})
_RANGES: Final = frozenset({_c.RANGE, getattr(_c, "RANGE_UNI_IGNORE", _c.RANGE)})
_ATOMIC_GROUP: Final = getattr(_c, "ATOMIC_GROUP", None)


@dataclass(frozen=True, slots=True)
class Element:
    """One step of a flattened path (see the module docstring). `mask` is a set of alphabet positions."""

    kind: str  # "atom", "repeat", "assert" or "start" (the invisible search loop)
    mask: int  # characters it can consume (0 for an assertion)
    min_len: int  # characters it must consume (0 for an assertion or an optional element)
    weight: float  # cost of testing it once (an atom, an assertion) or of one iteration (a repeat)
    text: str  # roughly how the admin wrote it, for messages
    long: bool = False
    unit: int = 1  # characters per iteration (repeats)
    max_iter: float = 1.0  # most iterations (repeats; math.inf when open-ended)
    anchor: str = ""  # assertions: "begin", "end", "end_string", "boundary", "non_boundary", "other"
    span: float = 0.0  # by how many characters the text it consumes can vary (math.inf when open-ended)
    groups: tuple[int, ...] = ()  # the optional groups (`(...)?`) it sits in, outermost first
    taken_len: int = 0  # characters it must consume once every group in `groups` is taken

    @property
    def variable(self) -> bool:
        """Whether the engine can try this element with several lengths (a repeat whose count varies, `x?`)."""
        return self.long or self.span > 0


def _required_between(element: Element, i: Element, j: Element) -> bool:
    """Whether `element`, between `i` and `j`, must consume text whenever both are used.

    An element is optional (`min_len` 0) when an optional group around it may be skipped; but a group that holds
    `i` or `j` is taken whenever they are used, so its required text stays between them (`\\d+\\.\\d+(\\.\\d+)?$`:
    the second `\\.` always separates the last two `\\d+`).
    """
    if element.min_len > 0:
        return True
    taken = set(i.groups) | set(j.groups)
    return element.taken_len > 0 and bool(element.groups) and set(element.groups) <= taken


@dataclass(frozen=True, slots=True)
class Charge:
    """The cost charged to one long repeat, and the chain of trading repeats that leads to it."""

    units: float
    chain: tuple[Element, ...]


@dataclass(slots=True)
class _Alphabet:
    chars: tuple[str, ...]
    all: int
    base: int
    word: int

    @classmethod
    def build(cls, extra: set[str]) -> _Alphabet:
        chars = tuple(sorted(_BASE_ALPHABET | extra))
        everything = (1 << len(chars)) - 1
        base = sum(1 << index for index, char in enumerate(chars) if char in _BASE_ALPHABET)
        word = sum(1 << index for index, char in enumerate(chars) if _WORD.fullmatch(char))
        return cls(chars, everything, base, word)


@dataclass(slots=True)
class _Walk:
    """State of one flattening pass."""

    alphabet: _Alphabet
    multiline: bool
    paths: list[list[Element]] = field(default_factory=lambda: [[]])
    too_many: bool = False
    groups: int = 0  # optional groups numbered so far


@dataclass(frozen=True, slots=True)
class _Scope:
    """Where the items being flattened sit: optional or not, inside which optional groups, and whether they are
    optional for any reason besides those groups (a lookaround body, an optional alternative)."""

    optional: bool = False
    groups: tuple[int, ...] = ()
    loose: bool = False  # optional even when every group in `groups` is taken

    def required(self, length: int) -> int:
        return 0 if self.optional else length

    def taken(self, length: int) -> int:
        return 0 if self.loose else length


# --- character sets -----------------------------------------------------------------------------------------------


def _in_set_char(code: int) -> str:
    char = chr(code)
    return "\\" + char if char in "\\]^-[" else char


def _atom_source(op: Any, av: Any) -> str:
    """Python `re` source for one single-character item of the parse tree."""
    if op is _c.LITERAL:
        return re.escape(chr(av))
    if op is _c.NOT_LITERAL:
        return f"[^{_in_set_char(av)}]"
    if op is _c.ANY:
        return "."
    parts: list[str] = []
    negate = False
    for item_op, item_av in av:
        if item_op is _c.NEGATE:
            negate = True
        elif item_op is _c.LITERAL:
            parts.append(_in_set_char(item_av))
        elif item_op in _RANGES:
            parts.append(f"{_in_set_char(item_av[0])}-{_in_set_char(item_av[1])}")
        elif item_op is _c.CATEGORY:
            parts.append(_CATEGORY_SOURCE.get(item_av, r"\w"))
        else:  # pragma: no cover - a set item this Python's parser does not produce
            return "."
    if not negate and len(parts) == 1 and parts[0] in _CATEGORY_SOURCE.values():
        return parts[0]
    return "[" + ("^" if negate else "") + "".join(parts) + "]"


def _atom_weight(op: Any, av: Any) -> float:
    if op is _c.LITERAL or op is _c.ANY:
        return _WEIGHT_LITERAL
    if op is _c.NOT_LITERAL:
        return _WEIGHT_SMALL_SET
    negate = False
    span = 0
    category = 0.0
    for item_op, item_av in av:
        if item_op is _c.NEGATE:
            negate = True
        elif item_op is _c.CATEGORY:
            word = item_av in (_c.CATEGORY_WORD, _c.CATEGORY_NOT_WORD)
            category = max(category, _WEIGHT_WORD_SET if word else _WEIGHT_BIG_SET)
        elif item_op in _RANGES:
            span += item_av[1] - item_av[0] + 1
        else:
            span += 1
    if category:
        return category
    if span >= _SMALL_SET_SPAN:
        return _WEIGHT_BIG_SET
    return _WEIGHT_NEGATED_SET if negate else _WEIGHT_SMALL_SET


@lru_cache(maxsize=4096)
def _mask_of(source: str, chars: tuple[str, ...]) -> int:
    """The alphabet positions the one-character pattern `source` accepts (case-insensitive, like v1)."""
    try:
        compiled = re.compile(source, re.IGNORECASE)
    except re.error:  # pragma: no cover - the whole pattern compiled, so its pieces do
        return (1 << len(chars)) - 1
    return sum(1 << index for index, char in enumerate(chars) if compiled.fullmatch(char))


def _cases(code: int) -> set[str]:
    char = chr(code)
    return {char, char.lower(), char.upper(), char.swapcase()}


def _children(op: Any, av: Any) -> Iterator[Any]:
    """The nested parse trees of one item."""
    if op is _c.SUBPATTERN:
        yield av[3]
    elif op in _REPEATS:
        yield av[2]
    elif op is _c.BRANCH:
        yield from av[1]
    elif op in (_c.ASSERT, _c.ASSERT_NOT):
        yield av[1]
    elif op is _c.GROUPREF_EXISTS:
        yield av[1]
        if av[2] is not None:
            yield av[2]
    elif _ATOMIC_GROUP is not None and op is _ATOMIC_GROUP:
        yield av


def _named_chars(tree: Any) -> set[str]:
    """Every character the pattern names (literals and range ends), in both cases."""
    found: set[str] = set()

    def visit(items: Any) -> None:
        for op, av in items:
            if op in (_c.LITERAL, _c.NOT_LITERAL):
                found.update(_cases(av))
            elif op is _c.IN:
                for item_op, item_av in av:
                    if item_op is _c.LITERAL:
                        found.update(_cases(item_av))
                    elif item_op in _RANGES:
                        found.update(_cases(item_av[0]) | _cases(item_av[1]))
            for child in _children(op, av):
                visit(child)

    visit(tree)
    return {char for char in found if char not in "\r\n"}  # caller paths and header values never hold these


# --- reading the parse tree -------------------------------------------------------------------------------------------


def _is_long(low: int, high: int) -> bool:
    return bool(high == _c.MAXREPEAT or high - low > LONG_SPAN)


def _has_long_repeat(items: Any) -> bool:
    for op, av in items:
        if op is _c.GROUPREF or (op in _REPEATS and _is_long(av[0], av[1])):
            return True
        if any(_has_long_repeat(child) for child in _children(op, av)):
            return True
    return False


def _has_variable_repeat(items: Any) -> bool:
    """Whether `items` holds a repeat whose count can vary (`a?`, `\\d{1,3}`, `x+`) or a backreference."""
    for op, av in items:
        if op is _c.GROUPREF or (op in _REPEATS and av[1] != av[0]):
            return True
        if any(_has_variable_repeat(child) for child in _children(op, av)):
            return True
    return False


def _max_length(items: Any) -> float:
    """The most characters `items` can consume (math.inf when open-ended; lookaround bodies consume none)."""
    total = 0.0
    for op, av in items:
        if op in _ATOMS:
            total += 1
        elif op is _c.GROUPREF:
            return math.inf
        elif op is _c.SUBPATTERN:
            total += _max_length(av[3])
        elif op in _REPEATS:
            body = _max_length(av[2])
            if av[1] == _c.MAXREPEAT and body > 0:
                return math.inf
            total += av[1] * body
        elif op is _c.BRANCH:
            total += max((_max_length(alt) for alt in av[1]), default=0.0)
        elif op is _c.GROUPREF_EXISTS:
            total += max(_max_length(av[1]), _max_length(av[2]) if av[2] is not None else 0.0)
        elif _ATOMIC_GROUP is not None and op is _ATOMIC_GROUP:
            total += _max_length(av)
    return total


def _min_length(items: Any) -> int:
    total = 0
    for op, av in items:
        if op in _ATOMS:
            total += 1
        elif op is _c.SUBPATTERN:
            total += _min_length(av[3])
        elif op in _REPEATS:
            total += av[0] * _min_length(av[2])
        elif op is _c.BRANCH:
            total += min((_min_length(alt) for alt in av[1]), default=0)
        elif _ATOMIC_GROUP is not None and op is _ATOMIC_GROUP:
            total += _min_length(av)
    return total


def _all_mask(items: Any, alphabet: _Alphabet) -> int:
    """Every character any part of `items` can consume (lookaround bodies excluded: they consume nothing)."""
    found = 0
    for op, av in items:
        if op in _ATOMS:
            found |= _mask_of(_atom_source(op, av), alphabet.chars)
        elif op is _c.GROUPREF:
            return alphabet.all
        elif op not in (_c.ASSERT, _c.ASSERT_NOT):
            for child in _children(op, av):
                found |= _all_mask(child, alphabet)
    return found


def _anchor_kind(code: Any) -> str:
    if code in (_c.AT_BEGINNING, _c.AT_BEGINNING_STRING):
        return "begin"
    return {
        _c.AT_END: "end",
        _c.AT_END_STRING: "end_string",
        _c.AT_BOUNDARY: "boundary",
        _c.AT_NON_BOUNDARY: "non_boundary",
    }.get(code, "other")


_ANCHOR_WEIGHT: Final = {
    "end": _WEIGHT_END,
    "end_string": _WEIGHT_END_STRING,
    "boundary": _WEIGHT_BOUNDARY,
    "non_boundary": _WEIGHT_BOUNDARY,
}
_ANCHOR_TEXT: Final = {"begin": "^", "end": "$", "end_string": r"\Z", "boundary": r"\b", "non_boundary": r"\B"}


def _weight_of(items: Any) -> float:
    """The cost of testing every element of `items` once (one iteration of a repeated group)."""
    total = 0.0
    for op, av in items:
        if op in _ATOMS:
            total += _atom_weight(op, av)
        elif op is _c.AT:
            total += _ANCHOR_WEIGHT.get(_anchor_kind(av), _WEIGHT_LITERAL)
        elif op in (_c.ASSERT, _c.ASSERT_NOT):
            total += _WEIGHT_LOOKAROUND + _weight_of(av[1])
        elif op is _c.GROUPREF:
            total += _WEIGHT_BACKREF
        else:
            total += sum(_weight_of(child) for child in _children(op, av))
    return total


def _render(items: Any, limit: int = 40) -> str:
    """Roughly how the admin wrote `items` (for messages only)."""
    out: list[str] = []
    for op, av in items:
        if op in _ATOMS:
            out.append(_atom_source(op, av))
        elif op in _REPEATS:
            out.append(_render_repeat(av[0], av[1], av[2]))
        elif op is _c.SUBPATTERN:
            out.append("(" + _render(av[3], limit) + ")")
        elif op is _c.BRANCH:
            out.append("(" + "|".join(_render(alt, limit) for alt in av[1]) + ")")
        elif op is _c.AT:
            out.append(_ANCHOR_TEXT.get(_anchor_kind(av), ""))
        else:
            out.append("(...)")
    text = "".join(out)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _render_repeat(low: int, high: int, body: Any) -> str:
    inner = _render(body)
    if not (len(body) == 1 and body[0][0] in _ATOMS) and not (inner.startswith("(") and inner.endswith(")")):
        inner = f"({inner})"
    if high == _c.MAXREPEAT:
        quantifier = {0: "*", 1: "+"}.get(low, f"{{{low},}}")
    elif low == 0 and high == 1:
        quantifier = "?"
    else:
        quantifier = f"{{{low},{high}}}" if low != high else f"{{{low}}}"
    return inner + quantifier


# --- flattening into paths --------------------------------------------------------------------------------------------


def _extend(walk: _Walk, element: Element) -> None:
    for path in walk.paths:
        path.append(element)


def _flatten(walk: _Walk, items: Any, scope: _Scope) -> None:
    """Append the elements of `items` to every current path (splitting paths at costly alternatives)."""
    for op, av in items:
        if walk.too_many:
            return
        if op in _ATOMS:
            mask = _mask_of(_atom_source(op, av), walk.alphabet.chars)
            text = _render([(op, av)])
            atom = Element(
                "atom",
                mask,
                scope.required(1),
                _atom_weight(op, av),
                text,
                groups=scope.groups,
                taken_len=scope.taken(1),
            )
            _extend(walk, atom)
        elif op is _c.AT:
            kind = _anchor_kind(av)
            if kind == "begin" and av is _c.AT_BEGINNING and walk.multiline:
                kind = "other"  # (?m)^ matches after every newline: not an anchor for the search
            weight = _ANCHOR_WEIGHT.get(kind, _WEIGHT_LITERAL)
            _extend(walk, Element("assert", 0, 0, weight, _ANCHOR_TEXT.get(kind, "?"), anchor=kind))
        elif op is _c.SUBPATTERN:
            _flatten(walk, av[3], scope)
        elif _ATOMIC_GROUP is not None and op is _ATOMIC_GROUP:
            _flatten(walk, av, scope)
        elif op in (_c.ASSERT, _c.ASSERT_NOT):
            # A lookaround body runs where it stands without consuming text: its repeats are costed like optional
            # text there, then the lookaround itself is a zero-width test that can fail.
            _flatten(walk, av[1], _Scope(True, scope.groups, True))
            _extend(walk, Element("assert", 0, 0, _WEIGHT_LOOKAROUND, "(?=...)", anchor="other"))
        elif op is _c.GROUPREF:
            backref = Element("repeat", walk.alphabet.all, 0, _WEIGHT_BACKREF, f"\\{av}", long=True, max_iter=math.inf)
            _extend(walk, backref)
        elif op in _REPEATS:
            _flatten_repeat(walk, av[0], av[1], av[2], scope)
        elif op is _c.BRANCH:
            _flatten_branch(walk, list(av[1]), scope)
        elif op is _c.GROUPREF_EXISTS:
            alternatives = [av[1]] if av[2] is None else [av[1], av[2]]
            _flatten_branch(walk, alternatives, _Scope(True, scope.groups, True))
        else:  # an opcode this model does not know: assume the worst kind of single character
            unknown = Element("atom", walk.alphabet.all, scope.required(1), _WEIGHT_BIG_SET, "?", groups=scope.groups)
            _extend(walk, unknown)


def _flatten_repeat(walk: _Walk, low: int, high: int, body: Any, scope: _Scope) -> None:
    long = _is_long(low, high)
    if not long and high <= MAX_UNROLL and _has_variable_repeat(body):
        # `(a+){3}` holds three trading repeats, `(\d{1,3}\.){3}` three short ones: unroll small counts so each copy
        # is costed. A copy beyond `low` is an optional group (a wider range around a variable body is refused
        # earlier, as a nested quantifier): its text is optional, but once the group is taken its required text
        # stays required (`_required_between`), so `\d+\.\d+(\.\d+)?$` never lets two `\d+` trade.
        for index in range(high):
            if index < low:
                _flatten(walk, body, scope)
            else:
                walk.groups += 1
                _flatten(walk, body, _Scope(True, (*scope.groups, walk.groups), scope.loose))
        return
    single = len(body) == 1 and body[0][0] in _ATOMS
    body_min = _min_length(body)
    body_max = _max_length(body)
    required = scope.required(low * body_min)
    span = (math.inf if body_max > 0 else 0.0) if high == _c.MAXREPEAT else high * body_max - required
    element = Element(
        "repeat",
        _all_mask(body, walk.alphabet),
        required,
        _weight_of(body) + (0.0 if single else GROUP_OVERHEAD),
        _render_repeat(low, high, body),
        long=long,
        unit=max(1, body_min),
        max_iter=math.inf if high == _c.MAXREPEAT else float(high),
        span=span,
        groups=scope.groups,
        taken_len=scope.taken(low * body_min),
    )
    _extend(walk, element)


def _flatten_branch(walk: _Walk, alternatives: list[Any], scope: _Scope) -> None:
    if not any(_has_long_repeat(alt) for alt in alternatives):
        mask = 0
        for alt in alternatives:
            mask |= _all_mask(alt, walk.alphabet)
        minimum = min((_min_length(alt) for alt in alternatives), default=0)
        maximum = max((_max_length(alt) for alt in alternatives), default=0.0)
        weight = sum(_weight_of(list(alt)[:1]) for alt in alternatives)
        text = "(" + "|".join(_render(alt) for alt in alternatives) + ")"
        required = scope.required(minimum)
        # Alternatives of different lengths (`(a?|b)`, `(x|xy)`) let the engine try the next element at several
        # offsets, like a short repeat: that variation is the element's span.
        atom = Element(
            "atom",
            mask,
            required,
            weight,
            text,
            span=maximum - required,
            groups=scope.groups,
            taken_len=scope.taken(minimum),
        )
        _extend(walk, atom)
        return
    base = walk.paths
    if len(base) * len(alternatives) > MAX_PATHS:
        walk.too_many = True
        return
    split: list[list[Element]] = []
    for alt in alternatives:
        walk.paths = [list(path) for path in base]
        _flatten(walk, alt, scope)
        split.extend(walk.paths)
    walk.paths = split


# --- the cost model ------------------------------------------------------------------------------------------------


def _trades(path: list[Element], i: int, j: int) -> bool:
    """Whether variable elements `i` and `j` can trade characters (see the module docstring)."""
    shared = path[i].mask & path[j].mask
    if not shared:
        return False
    # A required element that accepts none of the shared characters pins the split between them.
    return all(not _required_between(element, path[i], path[j]) or element.mask & shared for element in path[i + 1 : j])


def _absorbs_everything(element: Element, alphabet: _Alphabet) -> bool:
    """An open-ended repeat that accepts every character caller text can hold (`.*`): it can always run to the end."""
    return element.kind == "repeat" and element.max_iter == math.inf and alphabet.base & ~element.mask == 0


def _can_fail_after(path: list[Element], j: int, alphabet: _Alphabet) -> bool:
    """Whether something after element `j` can still fail once `j` has eaten a run of its characters."""
    eaten = path[j].mask
    runs_to_the_end = False  # an optional `.*` after `j` with nothing required after it (a glob's `(?:/.*)?$`)
    for later in path[j + 1 :]:
        if later.kind == "assert":
            if later.anchor in ("end", "end_string") and (runs_to_the_end or alphabet.base & ~eaten == 0):
                continue  # `.*$`: what `.` cannot eat is a newline, which caller text never holds
            if later.anchor == "boundary" and eaten & ~alphabet.word == 0:
                continue  # a run of word characters always ends at a word boundary
            return True
        if _required_between(later, path[j], path[j]):  # required, or in an optional group `j` is in
            if eaten & ~later.mask:
                return True  # a required element that rejects one of the eaten characters
            runs_to_the_end = False  # something required comes after any `.*` seen so far
        if _absorbs_everything(later, alphabet):
            runs_to_the_end = True
    return False


def _follower_weight(path: list[Element], j: int) -> float:
    """The cost of the test that follows element `j` (optional elements before the next required one included)."""
    total = 0.0
    for later in path[j + 1 :]:
        total += later.weight
        if later.kind == "assert" or _required_between(later, path[j], path[j]):
            break
    return total


def _gap(path: list[Element], i: int, j: int) -> int:
    """The fewest characters the text between elements `i` and `j` holds when both are used."""
    return sum(
        max(element.min_len, element.taken_len)
        for element in path[i + 1 : j]
        if _required_between(element, path[i], path[j])
    )


def _splits(element: Element, gap: int, n: int) -> float:
    """How many ways a run can be split between `element` and a later variable element it trades with."""
    if element.long:
        reach = min(float(n), element.max_iter * element.unit)
        return max(1.0, min(reach, n / (gap + 1)) / 2)
    # A short element gives back each of its `span + 1` lengths in turn: `[a-z]?` twenty times is 2 ** 20 splits.
    return max(1.0, min(element.span + 1, n / (gap + 1)))


def _path_charges(path: list[Element], n: int, alphabet: _Alphabet) -> list[Charge]:
    movers = [index for index, element in enumerate(path) if element.variable]
    if len(movers) > MAX_VARIABLE + 1:  # the search loop is one of them; `cost_problem` refuses these outright
        return [Charge(math.inf, (path[movers[-1]],))]
    best: dict[int, tuple[float, tuple[Element, ...]]] = {}
    charges: list[Charge] = []
    for position, j in enumerate(movers):
        value: float = 1.0
        chain: tuple[Element, ...] = (path[j],)
        for i in movers[:position]:
            if not _trades(path, i, j):
                continue
            splits = _splits(path[i], _gap(path, i, j), n)
            prior_value, prior_chain = best[i]
            if prior_value * splits > value:
                value, chain = prior_value * splits, (*prior_chain, path[j])
        best[j] = (value, chain)
        element = path[j]
        if element.kind == "start" or not _can_fail_after(path, j, alphabet):
            continue
        reach = min(element.max_iter, n / element.unit)
        charges.append(Charge(value * reach * (element.weight + _follower_weight(path, j)), chain))
    return charges


@dataclass(frozen=True, slots=True)
class _Flat:
    paths: list[list[Element]]
    alphabet: _Alphabet
    too_many: bool


def _flatten_pattern(pattern: str) -> _Flat | None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        try:
            tree = _sre_parser.parse(pattern, re.IGNORECASE)
        except Exception:  # the caller checked that the pattern compiles; anything else is "unknown"
            return None
    alphabet = _Alphabet.build(_named_chars(tree))
    walk = _Walk(alphabet=alphabet, multiline=bool(tree.state.flags & re.MULTILINE))
    _flatten(walk, tree, _Scope())
    paths: list[list[Element]] = []
    for path in walk.paths:
        anchored = bool(path) and path[0].kind == "assert" and path[0].anchor == "begin"
        if not anchored:
            start = Element("start", alphabet.all, 0, 0.0, "(search)", long=True, max_iter=math.inf)
            path = [start, *path]
        paths.append(path)
    return _Flat(paths, alphabet, walk.too_many)


def _worst(flat: _Flat, n: int) -> Charge | None:
    worst: Charge | None = None
    for path in flat.paths:
        for charge in _path_charges(path, n, flat.alphabet):
            if worst is None or charge.units > worst.units:
                worst = charge
    return worst


def estimate(pattern: str, *, n: int = TARGET_LENGTH) -> Charge | None:
    """The costliest charge of `pattern` on an `n` character input, or None when nothing is charged."""
    flat = _flatten_pattern(pattern)
    return None if flat is None else _worst(flat, n)


def _amount(units: float) -> str:
    if units >= 1e9:
        return "more than a billion"
    return f"about {max(1, round(units / 1e6))} million"


def cost_problem(pattern: str, *, n: int = TARGET_LENGTH, budget: float = STEP_BUDGET) -> str | None:
    """Why `pattern` could take too long to fail on a long caller input, in words for the admin; None if fine."""
    flat = _flatten_pattern(pattern)
    if flat is None:
        return None
    if flat.too_many:
        return (
            f"The pattern has more than {MAX_PATHS} combinations of alternatives that contain repeats, too many to "
            "check how long a match can take; simplify the alternatives"
        )
    if any(
        sum(1 for element in path if element.long and element.kind != "start") > MAX_LONG_REPEATS for path in flat.paths
    ):
        return f"The pattern has more than {MAX_LONG_REPEATS} repeats of varying length; use fewer"
    variable_parts = (sum(1 for e in path if e.variable and e.kind != "start") for path in flat.paths)
    if any(count > MAX_VARIABLE for count in variable_parts):
        return f"The pattern has more than {MAX_VARIABLE} optional or repeated parts of varying length; use fewer"
    worst = _worst(flat, n)
    if worst is None or worst.units <= budget:
        return None
    where = (
        f"{_amount(worst.units)} steps on a path or header of {n} characters, the limit is {budget / 1e6:.0f} million"
    )
    real = [element for element in worst.chain if element.kind != "start"]
    if len(real) >= 2:
        first, second = real[-2], real[-1]
        # Two short repeats (`\w{0,10}\w{0,10}`, `[a-z]?[a-z]?`) are better written as one; a long one gets a bound.
        fix = "use a bounded repeat such as {1,20}" if first.long or second.long else "write them as one repeat"
        return (
            f"{first.text} and {second.text} can match the same characters, so a failing match tries every way to "
            f"split a long run between them ({where}); make the text between them something {first.text} cannot "
            f"match, or {fix}"
        )
    target = real[-1] if real else worst.chain[-1]
    if worst.chain[0].kind == "start":
        leading = _LEADING_FLAGS.sub("", pattern).startswith(".*")
        hint = " (a leading .* is never needed: rules already match anywhere)" if leading else ""
        return (
            f"Rules match anywhere in the text they check, so a caller can make {target.text} restart at every "
            f"position of a long run it matches and rescan the run each time ({where}); start the pattern with ^, "
            f"or with fixed text that {target.text} cannot match{hint}"
        )
    return (
        f"A failing match of {target.text} can take too long ({where}); use a narrower character class or a "
        "bounded repeat"
    )


_LEADING_FLAGS: Final = re.compile(r"^(?:\(\?[aiLmsux]+\))+")
"""Inline flags such as `(?i)` at the start of a pattern (skipped when deciding whether it starts with `.*`)."""


__all__ = [
    "GROUP_OVERHEAD",
    "INPUT_BOUND_SETTINGS",
    "LONG_SPAN",
    "MAX_LONG_REPEATS",
    "MAX_PATHS",
    "MAX_VARIABLE",
    "STEP_BUDGET",
    "TARGET_LENGTH",
    "Charge",
    "Element",
    "cost_problem",
    "estimate",
]
