"""Plan C5 rewrite of imported admin text: every em and en dash becomes a semicolon, colon, comma or parentheses.

What this is
    `rewrite_dashes(text)` returns the text with each em dash (U+2014) and en dash (U+2013) replaced by the
    punctuation that keeps the meaning, and `clean_admin_text(text, limit)` adds the other repairs an imported
    message or note needs before the v2 models accept it (control characters removed, length bounded).

Why it exists
    Plan C5 bans both dash characters everywhere in v2, and the v2 rule models refuse admin text that contains
    one. v1 stored whatever the admin typed, and its own default ladder message had an em dash. Plan 18.3 says the
    migrator rewrites every admin-authored text (tier, block, rule, UA and header messages, pause and throttle-all
    reasons, notes) and lists each rewrite, so the owner can adjust the wording afterwards.

How it works
    A small set of readable rules, applied line by line, in this order:
      1. A run of dashes counts as one dash.
      2. An en dash with no space on either side, between two digits, is a range: `10<en dash>20` becomes
         `10-20` (a plain hyphen). A spaced dash or an em dash between numbers is not: it is often a clause break
         (`Error 429 <dash> 2 retries left`), where a hyphen would read as the range `429-2`; rule 6 handles it.
      3. An en dash with no space on either side, between two letters, joins words: it becomes a hyphen.
      4. A dash with nothing before it on the line is dropped; one with nothing after it is dropped too.
      5. Two dashes in one sentence enclose an aside: `A <dash> b <dash> c` becomes `A (b) c`.
      6. A single dash becomes a comma before a joining word (and, but, which, ...), a colon after a one-word
         label or a label word such as "Note" or "Maintenance", a comma before a short closing phrase of at most
         two words, and a semicolon otherwise. This matches the plan's own example: `Too many requests <dash>
         please slow down.` becomes `Too many requests; please slow down.`
    The characters are built with `chr()`, so this file contains neither of them (the style check scans it).

What to read next
    `roxy/migration/rules_import.py` (where rewrites are applied and recorded) and REMAKE_PLAN.md section 3, C5.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

EM_DASH: Final = chr(0x2014)
EN_DASH: Final = chr(0x2013)
DASHES: Final[tuple[str, str]] = (EM_DASH, EN_DASH)

# Patterns use \u escapes, so the source holds only ASCII.
_DASH_CLASS: Final = "[\\u2013\\u2014]"
_DASH_RUN = re.compile(f"{_DASH_CLASS}{{2,}}")
_NUMBER_RANGE = re.compile("(?<=\\d)\\u2013(?=\\d)")  # an unspaced en dash only (rule 2)
_JOINED_WORDS = re.compile("(?<=[A-Za-z])\\u2013(?=[A-Za-z])")
_SPLIT_ON_DASH = re.compile(f"[ \\t]*{_DASH_CLASS}[ \\t]*")
_SENTENCE_END = re.compile(r"[.!?]")
_LEFT_SENTENCE = re.compile(r"(?:^|[.!?]\s+)([^.!?]*)$")
_WORDS = re.compile(r"[A-Za-z0-9']+")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # newline and tab stay (v2 messages allow them)
_SPACES = re.compile(r"[ \t]{2,}")

JOINING_WORDS: Final[frozenset[str]] = frozenset(
    {"and", "but", "or", "so", "yet", "nor", "which", "who", "though", "although", "while", "because", "since"}
)
"""A dash right before one of these reads as a comma: `Cached briefly <dash> but not for long`."""

LABEL_WORDS: Final[frozenset[str]] = frozenset(
    {
        "note",
        "warning",
        "tip",
        "reminder",
        "important",
        "update",
        "reason",
        "example",
        "notice",
        "caution",
        "maintenance",
        "status",
    }
)
"""A dash right after one of these introduces what follows, so it becomes a colon: `Maintenance <dash> back at 5`."""


def has_dash(text: str | None) -> bool:
    """True when `text` contains an em or en dash."""
    if not text:
        return False
    return any(dash in text for dash in DASHES)


def _first_word(text: str) -> str:
    match = _WORDS.search(text)
    return match.group(0).lower() if match else ""


def _left_sentence(text: str) -> str:
    """The part of `text` after its last sentence end (the clause a following dash belongs to)."""
    match = _LEFT_SENTENCE.search(text)
    return match.group(1) if match else text


def _separator(left: str, right: str) -> str:
    """The punctuation (with its spacing) that replaces a single dash between `left` and `right`."""
    if _first_word(right) in JOINING_WORDS:
        return ", "
    left_words = _WORDS.findall(_left_sentence(left))
    if len(left_words) == 1 or (left_words and left_words[-1].lower() in LABEL_WORDS):
        return ": "
    right_words = _WORDS.findall(right)
    if len(right_words) <= 2 and not _SENTENCE_END.search(right.rstrip(".!? \t")):
        return ", "
    return "; "


def _join_after(text: str, rest: str) -> str:
    """Append `rest` after a closing parenthesis: no space before punctuation, one space before a word."""
    rest = rest.lstrip()
    if not rest:
        return text
    if rest[0] in ",.;:!?)":
        return text + rest
    return f"{text} {rest}"


def _rewrite_line(line: str) -> str:
    parts = _SPLIT_ON_DASH.split(line)
    if len(parts) == 1:
        return line
    out = parts[0].rstrip()
    index = 1
    while index < len(parts):
        segment = parts[index]
        last = index == len(parts) - 1
        if not out.strip():
            # Rule 4: a dash at the start of the line (nothing before it) is dropped.
            out = segment.lstrip()
            index += 1
            continue
        if not segment.strip() and last:
            # Rule 4: a dash at the end of the line is dropped.
            out = out.rstrip()
            index += 1
            continue
        if not last and segment.strip() and not _SENTENCE_END.search(segment):
            # Rule 5: two dashes inside one sentence enclose an aside.
            out = _join_after(f"{out.rstrip()} ({segment.strip()})", parts[index + 1])
            index += 2
            continue
        # Rule 6: a single dash.
        out = out.rstrip() + _separator(out, segment) + segment.lstrip()
        index += 1
    return _SPACES.sub(" ", out)


def rewrite_dashes(text: str) -> str:
    """Return `text` with every em and en dash replaced per plan C5 (see the module docstring for the rules)."""
    if not has_dash(text):
        return text
    result = _DASH_RUN.sub(EM_DASH, text)  # rule 1
    result = _NUMBER_RANGE.sub("-", result)  # rule 2
    result = _JOINED_WORDS.sub("-", result)  # rule 3
    lines = result.split("\n")
    result = "\n".join(_rewrite_line(line) if has_dash(line) else line for line in lines)
    for dash in DASHES:  # defensive: the rules above leave none, but the output must never hold one
        result = result.replace(dash, ";")
    return result


@dataclass(frozen=True, slots=True)
class CleanText:
    """The repaired text and what was done to it (each flag becomes a report line)."""

    text: str
    original: str
    dashes_rewritten: bool
    control_removed: bool
    truncated: bool

    @property
    def changed(self) -> bool:
        return self.text != self.original


def clean_admin_text(value: object, limit: int, *, strip: bool = True) -> CleanText:
    """Turn a v1 message, note or reason into text the v2 models accept.

    `None` becomes "", other non-strings their `str()`. Dashes are rewritten (C5), control characters other than
    newline and tab are removed, `\\r\\n` becomes `\\n`, and the text is cut to `limit` characters (v2 bounds,
    plan 15.4). The flags say which repairs happened so the report can list them.
    """
    original = "" if value is None else str(value)
    text = original.replace("\r\n", "\n")
    rewritten = rewrite_dashes(text)
    dashes = rewritten != text
    without_control = _CONTROL.sub("", rewritten)
    control = without_control != rewritten
    text = without_control.strip() if strip else without_control
    truncated = len(text) > limit
    if truncated:
        text = text[:limit].rstrip() if strip else text[:limit]
    return CleanText(text, original, dashes, control, truncated)


__all__ = [
    "DASHES",
    "EM_DASH",
    "EN_DASH",
    "JOINING_WORDS",
    "LABEL_WORDS",
    "CleanText",
    "clean_admin_text",
    "has_dash",
    "rewrite_dashes",
]
