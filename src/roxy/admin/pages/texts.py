"""Shared text helpers of the dashboard: the glossary, the caller texts of the shell, and the line diff.

What this is
    `load_glossary()` reads `docs/glossary.yml` (term id -> `GlossaryEntry`), `find_glossary()` locates it,
    `glossary_terms()` sorts it; `caller_texts(pause, throttle_all, now=, pause_message_default=)` builds the caller
    texts of the shell's `status` context (what a paused or emergency-limited caller gets right now);
    `diff_lines(before, after)` builds the input of the line diff viewer (`components/diff.html`).

Why it exists
    The development gallery (`admin/gallery.py`, P11 part one) introduced these helpers; every dashboard page needs
    them too, in production, where the gallery module must never be imported. They live here, next to the pages,
    and the gallery re-exports them, so there is one implementation of each.
    `caller_texts` asks `PauseState.message`, `ThrottleAllState.message` and `abuse.messages.downtime_default`,
    the very code that writes the 503 and 429 bodies, so the banners and dialogs cannot drift from what callers
    get when an admin changes `pause_message_default` (plan P3: one source of truth, no copy in a template).

How it works
    The glossary is not inside the package: it is `docs/glossary.yml` at the top of the tree (plan 14.7 keeps it
    with the other docs). `find_glossary` looks for `docs/glossary.yml` in the nearest directory at or above the
    roxy package: `<repo>/docs` for a checkout or editable install, `<release>/docs` for a release that
    deploy/deploy.sh installed into `<release>/.venv/lib/python3.12/site-packages` (5 levels up), and a copy
    packaged inside roxy itself wins if a build ever adds one. `load_glossary` caches per (path, mtime) and raises
    `FileNotFoundError` naming the file when it is missing; the pages router's lifespan loads it at startup, so a
    release without its glossary fails the deploy health gate instead of failing on first use.

What to read next
    `roxy/admin/pages/shell.py` (the shell context that uses all three), `templates/components/glossary.html`.
"""

from __future__ import annotations

import difflib
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import yaml

from roxy.abuse.messages import downtime_default
from roxy.abuse.pause import PauseState
from roxy.abuse.throttle_all import ThrottleAllState

PACKAGE_DIR: Final = Path(__file__).resolve().parents[2]
"""The installed `roxy` package: `<repo>/src/roxy` in a checkout, `.../site-packages/roxy` in a release."""
GLOSSARY_RELATIVE_PATH: Final = Path("docs") / "glossary.yml"
GLOSSARY_SEARCH_PARENTS: Final = 5
"""How far above the package `find_glossary` looks: far enough for `<release>/.venv/lib/python3.12/site-packages/
roxy` (the release is the 5th parent) and no further, so an unrelated file higher up is never used."""


def find_glossary(package_dir: Path = PACKAGE_DIR) -> Path | None:
    """`docs/glossary.yml` in the nearest directory at or above the roxy package, or None when there is none."""
    for directory in (package_dir, *package_dir.parents[:GLOSSARY_SEARCH_PARENTS]):
        candidate = directory / GLOSSARY_RELATIVE_PATH
        if candidate.is_file():
            return candidate
    return None


GLOSSARY_PATH: Final = find_glossary() or PACKAGE_DIR.parents[1] / GLOSSARY_RELATIVE_PATH
"""The glossary this process reads. When no copy exists it names where a checkout keeps it, and `load_glossary`
raises FileNotFoundError naming that path (a release without docs/ fails loudly, never with silent blanks)."""


@dataclass(frozen=True, slots=True)
class GlossaryEntry:
    """One glossary term: shown text, plain definition, and where it came from (plan, dashboard, roxy)."""

    id: str
    term: str
    definition: str
    source: str


@lru_cache(maxsize=4)
def _load_glossary_cached(path: str, mtime_ns: int) -> dict[str, GlossaryEntry]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries: dict[str, GlossaryEntry] = {}
    for item in raw.get("terms", []):
        entry = GlossaryEntry(
            id=str(item["id"]),
            term=str(item["term"]),
            definition=" ".join(str(item["definition"]).split()),
            source=str(item.get("source", "roxy")),
        )
        if entry.id in entries:
            raise ValueError(f"{path}: duplicate glossary id {entry.id!r}")
        entries[entry.id] = entry
    return entries


def load_glossary(path: Path = GLOSSARY_PATH) -> dict[str, GlossaryEntry]:
    """docs/glossary.yml as id -> entry, cached until the file changes (yaml.safe_load: data, never code)."""
    try:
        mtime_ns = path.stat().st_mtime_ns
    except FileNotFoundError:
        raise FileNotFoundError(
            f"the dashboard glossary {path} does not exist; docs/glossary.yml must ship next to the roxy package "
            f"(searched {GLOSSARY_SEARCH_PARENTS} levels above {PACKAGE_DIR})"
        ) from None
    return _load_glossary_cached(str(path), mtime_ns)


def glossary_terms(entries: Mapping[str, GlossaryEntry]) -> list[GlossaryEntry]:
    """Entries sorted by term, case-insensitive (the order of the Help page glossary)."""
    return sorted(entries.values(), key=lambda entry: entry.term.lower())


def diff_lines(before: str, after: str, context: int = 3) -> list[dict[str, Any]]:
    """A line diff for components/diff.html `diff_lines`: equal runs longer than 2 x context fold into one row."""
    old, new = before.splitlines(), after.splitlines()
    rows: list[dict[str, Any]] = []
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            span = i2 - i1
            hidden = span - 2 * context
            if hidden >= 2:  # folding a single line would hide nothing worth hiding
                head = range(i1, i1 + context)
                tail = range(i2 - context, i2)
                rows += [{"op": "equal", "old": i + 1, "new": j1 + (i - i1) + 1, "text": old[i]} for i in head]
                rows.append({"op": "skip", "old": None, "new": None, "text": f"{hidden} unchanged lines"})
                rows += [{"op": "equal", "old": i + 1, "new": j1 + (i - i1) + 1, "text": old[i]} for i in tail]
            else:
                rows += [{"op": "equal", "old": i + 1, "new": j1 + (i - i1) + 1, "text": old[i]} for i in range(i1, i2)]
            continue
        rows += [{"op": "delete", "old": i + 1, "new": None, "text": old[i]} for i in range(i1, i2)]
        rows += [{"op": "insert", "old": None, "new": j + 1, "text": new[j]} for j in range(j1, j2)]
    return rows


def caller_texts(
    pause: PauseState, throttle_all: ThrottleAllState, *, now: float, pause_message_default: object
) -> dict[str, str]:
    """The caller texts of the shell's `status` context (admin/_layout/banners.html, control_dialogs.html).

    `pause_message_default` is the LIVE setting value (`ctx.settings.get("pause_message_default")`). The result:
    `pause_message`, the 503 text a paused caller gets at `now` (the reason, the scheduled reason inside a scheduled
    window, else the default); `throttle_message`, the 429 text of the emergency limit (its reason, else the same
    default, v1 B6); and `pause_default`, the default exactly as it is sent when a message is left empty.
    """
    default = downtime_default(pause_message_default)  # cleaned like the refusal path; empty means the catalog's
    return {
        "pause_message": pause.message(now, default)[0],
        "pause_default": default,
        "throttle_message": throttle_all.message(default)[0],
    }


__all__ = [
    "GLOSSARY_PATH",
    "GLOSSARY_RELATIVE_PATH",
    "GLOSSARY_SEARCH_PARENTS",
    "PACKAGE_DIR",
    "GlossaryEntry",
    "caller_texts",
    "diff_lines",
    "find_glossary",
    "glossary_terms",
    "load_glossary",
]
