"""Worst-case cost of a new regular expression on a long caller input: the write-time ReDoS budget (plan 9.9).

What this is
    `cost_problem(pattern)` estimates how much work the matcher may do to FAIL a search of `pattern` over a
    caller-chosen text of `TARGET_LENGTH` characters (a 4 KB path or header value), and returns a plain refusal
    message naming the repeats responsible when the estimate is over `STEP_BUDGET`, or None. `estimate` returns
    the costliest charge itself. `rules/match.py validate_regex` calls `cost_problem` for every NEW pattern; stored
    patterns (imported from v1) are never judged again, and the per-match timeout stays their backstop.

Why it exists
    The 50 ms per-match timeout and the per-request budget stop one slow pattern from freezing a worker, but a
    pattern that needs the timeout on every request still costs 50 ms of a worker per request, and a cut-off
    match is answered with a guess. New patterns should finish well inside the timeout. The structural checks in
    `match.py` (nested quantifiers, ambiguous alternatives, too many open-ended repeats) stop exponential shapes;
    polynomial shapes need a cost model, because `x+x+y` takes seconds on 4096 characters while `\\d+/\\d+` (two
    repeats that can never trade characters) takes microseconds. The model was calibrated against the `regex`
    module running the translated patterns Roxy really runs (`.remake/scripts/fix1u_redos_shapes*.py`): one
    unit below costs 1.5 to 5 ns there, so the 3 million unit budget is about 5 to 15 ms, under a third of the
    timeout.

How it works
    1. Parse with Python's own `re` parser (the language v1 rules are written in) and flatten the tree into
       paths of elements: single characters, repeats, zero-width assertions. Alternatives that contain a long
       repeat split the path (at most `MAX_PATHS` paths); other alternatives become one element. A small fixed
       repeat of a group with a long repeat inside (`(a+){3}`) is unrolled. Lookaround bodies are inlined as
       optional text followed by a zero-width test.
    2. A repeat is "long" when it is open-ended or its count can vary by more than `LONG_SPAN`. Character sets are
       bit masks over a finite alphabet: printable ASCII, every character the pattern names (in both cases), and a
       few non-ASCII stand-ins, so `\\w` and `[a-z]` overlap and `\\d` and `/` do not.
    3. An unanchored pattern (no leading `^` or `\\A`) is searched: the engine retries it from every start. That is
       modeled as an invisible leading repeat that matches anything.
    4. Two long repeats "trade" when some character is accepted by both and every required element between them
       accepts one of those characters too: the engine can then split a run of such characters between the two in
       many ways, and a failing match tries them all. For each long repeat, the costliest chain of trading repeats
       ending at it gives a count of splits (`n / (2 * (gap + 1))` per link, `gap` being the minimum length of the
       text between the two), and it is charged `splits * reach * step` only when something after it can still
       fail once it has eaten a run (a required element that rejects one of its characters, or an assertion such
       as `$`). `step` weighs the repeated element and the test that follows it: a Unicode class such as `\\d`
       costs about 60 single characters, `\\w` 200, `$` 25, `\\b` 100, because `rules/re_compat.py` spells them
       out exactly as Python `re` defines them.
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

_sre_parser: Any = importlib.import_module("re._parser")
_c: Any = importlib.import_module("re._constants")

TARGET_LENGTH: Final = 4096
"""The caller input the budget is computed for: the default `max_url_length`, and a long header value."""

STEP_BUDGET: Final = 3_000_000
"""Most cost units a failing match may need on `TARGET_LENGTH` characters (about 5 to 15 ms, see the docstring)."""

LONG_SPAN: Final = 10
"""A repeat whose count can vary by more than this (or is open-ended) can trade characters with another one."""

MAX_PATHS: Final = 64
"""Most alternative paths through one pattern that are costed one by one."""

MAX_LONG_REPEATS: Final = 24
"""Most long repeats on one path. More are refused outright: no realistic endpoint or header rule needs them."""

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


def _flatten(walk: _Walk, items: Any, optional: bool) -> None:
    """Append the elements of `items` to every current path (splitting paths at costly alternatives)."""
    for op, av in items:
        if walk.too_many:
            return
        if op in _ATOMS:
            mask = _mask_of(_atom_source(op, av), walk.alphabet.chars)
            _extend(walk, Element("atom", mask, 0 if optional else 1, _atom_weight(op, av), _render([(op, av)])))
        elif op is _c.AT:
            kind = _anchor_kind(av)
            if kind == "begin" and av is _c.AT_BEGINNING and walk.multiline:
                kind = "other"  # (?m)^ matches after every newline: not an anchor for the search
            weight = _ANCHOR_WEIGHT.get(kind, _WEIGHT_LITERAL)
            _extend(walk, Element("assert", 0, 0, weight, _ANCHOR_TEXT.get(kind, "?"), anchor=kind))
        elif op is _c.SUBPATTERN:
            _flatten(walk, av[3], optional)
        elif _ATOMIC_GROUP is not None and op is _ATOMIC_GROUP:
            _flatten(walk, av, optional)
        elif op in (_c.ASSERT, _c.ASSERT_NOT):
            # A lookaround body runs where it stands without consuming text: its repeats are costed like optional
            # text there, then the lookaround itself is a zero-width test that can fail.
            _flatten(walk, av[1], True)
            _extend(walk, Element("assert", 0, 0, _WEIGHT_LOOKAROUND, "(?=...)", anchor="other"))
        elif op is _c.GROUPREF:
            backref = Element("repeat", walk.alphabet.all, 0, _WEIGHT_BACKREF, f"\\{av}", long=True, max_iter=math.inf)
            _extend(walk, backref)
        elif op in _REPEATS:
            _flatten_repeat(walk, av[0], av[1], av[2], optional)
        elif op is _c.BRANCH:
            _flatten_branch(walk, list(av[1]), optional)
        elif op is _c.GROUPREF_EXISTS:
            alternatives = [av[1]] if av[2] is None else [av[1], av[2]]
            _flatten_branch(walk, alternatives, True)
        else:  # an opcode this model does not know: assume the worst kind of single character
            _extend(walk, Element("atom", walk.alphabet.all, 0 if optional else 1, _WEIGHT_BIG_SET, "?"))


def _flatten_repeat(walk: _Walk, low: int, high: int, body: Any, optional: bool) -> None:
    long = _is_long(low, high)
    if not long and high <= MAX_UNROLL and _has_long_repeat(body):
        # `(a+){3}` holds three trading repeats: unroll small fixed counts so each copy is costed.
        for index in range(high):
            _flatten(walk, body, optional or index >= low)
        return
    single = len(body) == 1 and body[0][0] in _ATOMS
    body_min = _min_length(body)
    element = Element(
        "repeat",
        _all_mask(body, walk.alphabet),
        0 if optional else low * body_min,
        _weight_of(body) + (0.0 if single else GROUP_OVERHEAD),
        _render_repeat(low, high, body),
        long=long,
        unit=max(1, body_min),
        max_iter=math.inf if high == _c.MAXREPEAT else float(high),
    )
    _extend(walk, element)


def _flatten_branch(walk: _Walk, alternatives: list[Any], optional: bool) -> None:
    if not any(_has_long_repeat(alt) for alt in alternatives):
        mask = 0
        for alt in alternatives:
            mask |= _all_mask(alt, walk.alphabet)
        minimum = min((_min_length(alt) for alt in alternatives), default=0)
        weight = sum(_weight_of(list(alt)[:1]) for alt in alternatives)
        text = "(" + "|".join(_render(alt) for alt in alternatives) + ")"
        _extend(walk, Element("atom", mask, 0 if optional else minimum, weight, text))
        return
    base = walk.paths
    if len(base) * len(alternatives) > MAX_PATHS:
        walk.too_many = True
        return
    split: list[list[Element]] = []
    for alt in alternatives:
        walk.paths = [list(path) for path in base]
        _flatten(walk, alt, optional)
        split.extend(walk.paths)
    walk.paths = split


# --- the cost model ------------------------------------------------------------------------------------------------


def _trades(path: list[Element], i: int, j: int) -> bool:
    """Whether long elements `i` and `j` can trade characters (see the module docstring)."""
    shared = path[i].mask & path[j].mask
    if not shared:
        return False
    # A required element that accepts none of the shared characters pins the split between them.
    return all(element.min_len == 0 or element.mask & shared for element in path[i + 1 : j])


def _can_fail_after(path: list[Element], j: int, alphabet: _Alphabet) -> bool:
    """Whether something after element `j` can still fail once `j` has eaten a run of its characters."""
    eaten = path[j].mask
    for later in path[j + 1 :]:
        if later.kind == "assert":
            if later.anchor in ("end", "end_string") and alphabet.base & ~eaten == 0:
                continue  # `.*$`: what `.` cannot eat is a newline, which caller text never holds
            if later.anchor == "boundary" and eaten & ~alphabet.word == 0:
                continue  # a run of word characters always ends at a word boundary
            return True
        if later.min_len > 0 and eaten & ~later.mask:
            return True  # a required element that rejects one of the eaten characters
    return False


def _follower_weight(path: list[Element], j: int) -> float:
    """The cost of the test that follows element `j` (optional elements before the next required one included)."""
    total = 0.0
    for later in path[j + 1 :]:
        total += later.weight
        if later.min_len > 0 or later.kind == "assert":
            break
    return total


def _path_charges(path: list[Element], n: int, alphabet: _Alphabet) -> list[Charge]:
    longs = [index for index, element in enumerate(path) if element.long]
    best: dict[int, tuple[float, tuple[Element, ...]]] = {}
    charges: list[Charge] = []
    for position, j in enumerate(longs):
        value: float = 1.0
        chain: tuple[Element, ...] = (path[j],)
        for i in longs[:position]:
            if not _trades(path, i, j):
                continue
            gap = sum(element.min_len for element in path[i + 1 : j])
            reach_i = min(float(n), path[i].max_iter * path[i].unit)
            splits = max(1.0, min(reach_i, n / (gap + 1)) / 2)
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
    _flatten(walk, tree, False)
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
    worst = _worst(flat, n)
    if worst is None or worst.units <= budget:
        return None
    steps = _amount(worst.units)
    real = [element for element in worst.chain if element.kind != "start"]
    if len(real) >= 2:
        first, second = real[-2], real[-1]
        return (
            f"{first.text} and {second.text} can match the same characters, so a failing match tries every way to "
            f"split a long run between them ({steps} steps on a {n} character path or header, the limit is "
            f"{budget / 1e6:.0f} million); make the text between them something {first.text} cannot match, or "
            "use a bounded repeat such as {1,20}"
        )
    target = real[-1] if real else worst.chain[-1]
    if worst.chain[0].kind == "start":
        hint = " (a leading .* is never needed: rules already match anywhere)" if target.text == ".*" else ""
        return (
            f"Rules match anywhere in the text they check, so a caller can make {target.text} restart at every "
            f"position of a long run it matches and rescan the run each time ({steps} steps on a {n} character path "
            f"or header, the limit is {budget / 1e6:.0f} million); start the pattern with ^, or with fixed text that "
            f"{target.text} cannot match{hint}"
        )
    return (
        f"A failing match of {target.text} can take {steps} steps on a {n} character path or header (the limit is "
        f"{budget / 1e6:.0f} million); use a narrower character class or a bounded repeat"
    )


__all__ = [
    "GROUP_OVERHEAD",
    "LONG_SPAN",
    "MAX_LONG_REPEATS",
    "MAX_PATHS",
    "STEP_BUDGET",
    "TARGET_LENGTH",
    "Charge",
    "Element",
    "cost_problem",
    "estimate",
]
