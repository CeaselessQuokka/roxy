"""The migration report: what was imported, skipped, clamped, rewritten or kept, as JSON and as Markdown.

What this is
    `MigrationReport`, the object every step of the migrator writes its results into, plus `render_markdown`,
    `write_report` and `SecretScrubber` (the last line of defense that keeps secrets out of both files).

Why it exists
    Plan 18.3 asks for a JSON and a Markdown report the owner reviews after the dry run and again after the real
    run: every imported, skipped and clamped setting, every rule, every C5 text rewrite (table, id, before, after),
    the hosts added to `allowed_roblox_hosts`, how many extra credential lines were discarded (masked, plan C1).
    The report must never contain a secret: values are masked where they are recorded, and the scrubber removes
    any secret that slipped through anyway before a byte is written.

How it works
    Steps append plain dicts to the lists of `MigrationReport` (statuses are the constants below). At the end the
    runner calls `scrub()` with every secret value it read; strings are cleaned recursively (exact values, every
    24 character window of a Roblox credential, shorter pieces of every other secret long enough to tell apart
    from ordinary text, then `core.redact.redact_text` shape rules). JSON is written with `ensure_ascii=True`, so
    the "before" side of a C5 rewrite holds the dash only as a `\\u2014` escape; the Markdown file names it in
    words (`[em dash]`), so neither file contains the character. Both files are mode 0600, written through a
    temporary file with a random name that is never a link (the report may go to a shared directory).

What to read next
    `roxy/migration/runner.py` (who fills the report) and `roxy/core/redact.py` (the shape rules).
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import time
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from roxy.core.redact import MASK, TOKEN_PREFIX, redact_text
from roxy.migration.text import EM_DASH, EN_DASH, CleanText

REPORT_SCHEMA: Final = "roxy.v1_migration_report/1"

# Item statuses (one vocabulary for every section).
IMPORTED: Final = "imported"
ALREADY: Final = "already_imported"
KEPT: Final = "kept_existing"
REPLACED_DEFAULT: Final = "replaced_default"
SKIPPED: Final = "skipped"
INVALID: Final = "invalid"
DUPLICATE: Final = "duplicate"
REMOVED: Final = "removed_in_v2"  # an earlier run placed it, v2 deleted or reset it since; never placed again
NOT_IMPORTED: Final = "not_imported"  # a dry run reports IMPORTED too: the header says nothing was written
REFUSED: Final = "refused"  # the run status when the arguments were refused and nothing was written

WINDOW: Final = 24  # same window as core.redact SUBSTRING_WINDOW: any 24 characters of the credential are secret
MIN_PIECE: Final = 8
MIN_SECRET: Final = 6
"""Shorter values are not masked: masking a 5 character value would hide ordinary words in every text and refuse
unrelated rule patterns. The runner warns when a v1 secret is that short instead (only a password can be)."""

_STATUS_WORDS: Final[dict[str, str]] = {
    IMPORTED: "imported",
    ALREADY: "already imported",
    KEPT: "kept the existing v2 value",
    REPLACED_DEFAULT: "replaced a built-in default",
    SKIPPED: "skipped",
    INVALID: "invalid (skipped)",
    DUPLICATE: "duplicate (skipped)",
    REMOVED: "removed in v2 after the import (not placed again)",
    NOT_IMPORTED: "not imported",
}


def piece_length(secret: str) -> int | None:
    """How many characters of `secret` are secret on their own (half of it, 8 to 24), or None when the value is
    too short for a piece to stand out from ordinary text (it is then matched whole only)."""
    if len(secret) < 2 * MIN_PIECE:
        return None
    return min(WINDOW, max(MIN_PIECE, len(secret) // 2))


@dataclass
class MigrationReport:
    """Everything the owner needs to review one migrator run. Every value is plain JSON data."""

    dry_run: bool
    started_at: int
    v1_root: str
    state_dir: str
    credentials_out: str | None
    import_admin_password: bool = False
    schema: str = REPORT_SCHEMA
    status: str = "running"
    already_imported: bool = False
    resumed_incomplete_import: bool = False  # an earlier run stopped with errors; this one finishes its work
    first_imported_at: int | None = None
    finished_at: int | None = None
    changes: int = 0
    inputs: list[dict[str, Any]] = field(default_factory=list)
    sources: dict[str, Any] = field(default_factory=dict)
    defaults_seed: dict[str, Any] = field(default_factory=dict)
    settings: list[dict[str, Any]] = field(default_factory=list)
    hosts: dict[str, Any] = field(default_factory=dict)
    rules: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    ladder: dict[str, Any] = field(default_factory=dict)
    service_state: list[dict[str, Any]] = field(default_factory=list)
    text_rewrites: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    admin: dict[str, Any] = field(default_factory=dict)
    statistics: dict[str, Any] = field(default_factory=dict)
    not_migrated: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # ---- helpers for the steps ------------------------------------------------------------------------------------

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def error(self, message: str) -> None:
        if message not in self.errors:
            self.errors.append(message)

    def changed(self, count: int = 1) -> None:
        """Count rows or files this run wrote (0 on a second run: that is what "already imported" means)."""
        self.changes += count

    def rule_item(self, table: str, item: dict[str, Any]) -> None:
        self.rules.setdefault(table, []).append(item)

    def note_rewrite(self, table: str, row_id: Any, field_name: str, clean: CleanText) -> None:
        """Record a C5 rewrite (and any other repair) of one admin-written text (plan 18.3)."""
        if not clean.changed:
            return
        repairs = [
            name
            for name, done in (
                ("dashes rewritten", clean.dashes_rewritten),
                ("control characters removed", clean.control_removed),
                ("shortened to the v2 limit", clean.truncated),
            )
            if done
        ]
        if not clean.dashes_rewritten and not clean.control_removed and not clean.truncated:
            return  # only whitespace was trimmed, as v1 itself did
        self.text_rewrites.append(
            {
                "table": table,
                "id": str(row_id),
                "field": field_name,
                "before": clean.original,
                "after": clean.text,
                "repairs": repairs,
            }
        )

    # ---- results ----------------------------------------------------------------------------------------------------

    def counts(self) -> dict[str, int]:
        """How many items ended in each status, over settings, rules and service state."""
        counter: Counter[str] = Counter()
        for item in self.settings:
            counter[str(item.get("status"))] += 1
        for items in self.rules.values():
            for item in items:
                counter[str(item.get("status"))] += 1
        for item in self.service_state:
            counter[str(item.get("status"))] += 1
        return dict(sorted(counter.items()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "dry_run": self.dry_run,
            "status": self.status,
            "already_imported": self.already_imported,
            "resumed_incomplete_import": self.resumed_incomplete_import,
            "first_imported_at": self.first_imported_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "changes": self.changes,
            "counts": self.counts(),
            "v1_root": self.v1_root,
            "state_dir": self.state_dir,
            "credentials_out": self.credentials_out,
            "import_admin_password": self.import_admin_password,
            "inputs": self.inputs,
            "sources": self.sources,
            "defaults_seed": self.defaults_seed,
            "settings": self.settings,
            "hosts": self.hosts,
            "rules": self.rules,
            "ladder": self.ladder,
            "service_state": self.service_state,
            "text_rewrites": self.text_rewrites,
            "credentials": self.credentials,
            "admin": self.admin,
            "statistics": self.statistics,
            "not_migrated": self.not_migrated,
            "warnings": self.warnings,
            "errors": self.errors,
        }

    def scrub(self, scrubber: SecretScrubber) -> int:
        """Remove every secret from every string of the report, in place. Returns how many strings changed."""
        changed = 0
        for name in (
            "inputs",
            "sources",
            "defaults_seed",
            "settings",
            "hosts",
            "rules",
            "ladder",
            "service_state",
            "text_rewrites",
            "credentials",
            "admin",
            "statistics",
            "not_migrated",
            "warnings",
            "errors",
        ):
            cleaned, count = scrubber.clean(getattr(self, name))
            setattr(self, name, cleaned)
            changed += count
        for name in ("v1_root", "state_dir", "credentials_out"):
            value = getattr(self, name)
            if isinstance(value, str):
                cleaned_value, count = scrubber.clean(value)
                setattr(self, name, cleaned_value)
                changed += count
        if changed:
            self.warn(f"{changed} value(s) that looked secret were removed from this report")
        return changed


# --- the scrubber ----------------------------------------------------------------------------------------------------


def _add_windows(windows: dict[int, set[str]], text: str, size: int) -> None:
    for start in range(max(0, len(text) - size + 1)):
        windows.setdefault(size, set()).add(text[start : start + size])


def _lower_same_length(text: str) -> str:
    """`text.lower()` with one character per character, so positions match `text` (a few letters, such as the
    dotted capital I, lowercase to two characters)."""
    lowered = text.lower()
    if len(lowered) == len(text):
        return lowered
    return "".join(char.lower()[:1] for char in text)


class SecretScrubber:
    """Removes known secret values, every 24 character window of each credential, and pieces of every other
    secret long enough to have them (`piece_length`), from report strings and imported text.

    Pieces matter because text is often cut: v1 cut notes at 200 characters and v2 cuts at its own limits, so a
    stored text can end with the first part of a secret that no longer matches the whole value (review finding 9).
    """

    def __init__(self, secrets: Iterable[str], credentials: Iterable[str] = (), pieces: Iterable[str] = ()) -> None:
        values = {value for value in secrets if value and len(value) >= MIN_SECRET}
        windows: dict[int, set[str]] = {}
        for credential in credentials:
            if not credential:
                continue
            values.add(credential)
            _add_windows(windows, credential.removeprefix(TOKEN_PREFIX).lower(), WINDOW)
        for secret in pieces:
            size = piece_length(secret) if secret else None
            if size is not None:
                values.add(secret)
                _add_windows(windows, secret.lower(), size)
        self._values = sorted(values, key=len, reverse=True)
        self._windows = {size: frozenset(found) for size, found in sorted(windows.items()) if found}

    def clean_text(self, text: str) -> str:
        """`clean_known`, then `redact_text`'s shape rules (cookie values, `user:password@`, secret-named pairs)."""
        return redact_text(self.clean_known(text))

    def clean_known(self, text: str) -> str:
        """Replace the known secret values, and any secret piece (case ignored), with `[redacted]`."""
        result = text
        for value in self._values:
            if value in result:
                result = result.replace(value, MASK)
        hidden_at: list[bool] | None = None
        lowered = ""
        for size, windows in self._windows.items():
            if len(result) < size:
                continue
            if not lowered:
                lowered = _lower_same_length(result)
            for start in range(len(lowered) - size + 1):
                if lowered[start : start + size] in windows:
                    if hidden_at is None:
                        hidden_at = [False] * len(result)
                    hidden_at[start : start + size] = [True] * size
        if hidden_at is None:
            return result
        pieces: list[str] = []
        previous_hidden = False
        for char, hidden in zip(result, hidden_at, strict=True):
            if not hidden:
                pieces.append(char)
            elif not previous_hidden:
                pieces.append(MASK)  # one mask per hidden run
            previous_hidden = hidden
        return "".join(pieces)

    def clean(self, value: Any) -> tuple[Any, int]:
        """A scrubbed copy of `value` (dicts, lists and strings, recursively) and the number of strings changed."""
        if isinstance(value, str):
            cleaned = self.clean_text(value)
            return cleaned, int(cleaned != value)
        if isinstance(value, Mapping):
            total = 0
            out: dict[str, Any] = {}
            for key, item in value.items():
                cleaned_key, key_count = self.clean(str(key))
                cleaned_item, count = self.clean(item)
                out[cleaned_key] = cleaned_item
                total += count + key_count
            return out, total
        if isinstance(value, list | tuple):
            total = 0
            items: list[Any] = []
            for item in value:
                cleaned_item, count = self.clean(item)
                items.append(cleaned_item)
                total += count
            return items, total
        return value, 0


# --- rendering -------------------------------------------------------------------------------------------------------


def _visible(text: str) -> str:
    """Name the dash characters in words, so the Markdown file never contains them (plan C5)."""
    return text.replace(EM_DASH, "[em dash]").replace(EN_DASH, "[en dash]")


def _cell(value: Any) -> str:
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, list | tuple):
        text = ", ".join(str(item) for item in value)
    elif isinstance(value, dict):
        text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    else:
        text = str(value)
    text = _visible(text).replace("\r\n", "\n").replace("|", "\\|").replace("\n", "<br>")
    return text if text.strip() else " "


def _table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    count = 0
    for row in rows:
        lines.append("| " + " | ".join(_cell(cell) for cell in row) + " |")
        count += 1
    if count == 0:
        return ["(none)"]
    return lines


def _when(epoch: int | None) -> str:
    if not epoch:
        return "n/a"
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(epoch))


def _status(value: Any) -> str:
    return _STATUS_WORDS.get(str(value), str(value))


def render_markdown(report: MigrationReport) -> str:
    """The report as Markdown for people (the JSON file holds the same data for tools)."""
    out: list[str] = ["# Roxy v1 to v2 migration report", ""]
    mode = "dry run (nothing was written to the state or credentials directory)" if report.dry_run else "real run"
    out += [
        f"- Mode: {mode}",
        f"- Result: {report.status}",
        f"- Started: {_when(report.started_at)}; finished: {_when(report.finished_at)}",
        f"- v1 root: `{report.v1_root}`",
        f"- v2 state directory: `{report.state_dir}`",
        f"- Credentials directory: `{report.credentials_out or 'not given (no credential files written)'}`",
        f"- Rows and files written by this run: {report.changes}",
    ]
    if report.already_imported:
        out.append(
            f"- Already imported on {_when(report.first_imported_at)}. A rerun adds only v1 items that are new since "
            "then; what an earlier run placed is never placed again, so anything changed or deleted in v2 since "
            "stays as it is."
        )
    elif report.resumed_incomplete_import:
        out.append(
            f"- A previous run on {_when(report.first_imported_at)} stopped with errors; this run imported what it "
            "left out and left what it had placed as it is."
        )
    counts = report.counts()
    if counts:
        out.append("- Items by result: " + ", ".join(f"{_status(key)} {value}" for key, value in counts.items()))
    out.append("")

    if report.errors or report.warnings:
        out += ["## Problems", ""]
        out += [f"- Error: {_visible(message)}" for message in report.errors]
        out += [f"- Warning: {_visible(message)}" for message in report.warnings]
        out.append("")

    out += ["## Inputs", ""]
    out += _table(
        ("Role", "Path", "Found", "Details"),
        ((i.get("role"), i.get("path"), i.get("found"), i.get("detail", "")) for i in report.inputs),
    )
    sources = report.sources
    if sources:
        out += ["", f"Control plane read from: {sources.get('control_plane', 'n/a')}."]
        out.append(f"Statistics read from: {sources.get('statistics', 'n/a')}.")
    out.append("")

    if report.defaults_seed:
        seed = report.defaults_seed
        out += ["## Built-in defaults", ""]
        if seed.get("already_seeded"):
            out.append("The v2 built-in defaults were already in place.")
        else:
            out.append(f"Seeded the v2 built-in defaults first: {_cell(seed.get('inserted'))}.")
        out.append("")

    out += ["## Settings", ""]
    out.append(
        "Only values the owner changed in v1 are imported (plan 18.3); keys whose meaning changed are never imported "
        "and are shown next to the v2 default so you can decide by hand."
    )
    out.append("")
    out += _table(
        ("v1 key", "v2 key", "v1 value", "v1 default", "v2 default", "Result", "Notes"),
        (
            (
                s.get("v1_key"),
                s.get("v2_key") or "",
                s.get("v1_value"),
                s.get("v1_default"),
                s.get("v2_default"),
                _status(s.get("status")),
                "; ".join(s.get("notes", [])),
            )
            for s in report.settings
        ),
    )
    out.append("")

    hosts = report.hosts
    if hosts:
        out += ["## Allowed Roblox hosts", ""]
        out.append(
            f"Result: {_status(hosts.get('status'))}. Shipped list: {hosts.get('default_count', 0)} hosts; "
            f"hosts seen in v1 data: {hosts.get('seen_count', 0)}; added: {len(hosts.get('added', []))}."
        )
        out.append("")
        out += _table(
            ("Added host", "Seen in", "Requests", "Successful answer seen"),
            ((h.get("host"), h.get("seen_in"), h.get("requests"), h.get("successful")) for h in hosts.get("added", [])),
        )
        if hosts.get("not_added"):
            out += ["", "Not added: " + ", ".join(f"`{_visible(str(h))}`" for h in hosts["not_added"])]
        if hosts.get("removed_in_v2"):
            out += [
                "",
                "Removed in v2 after the import (not added again): "
                + ", ".join(f"`{_visible(str(h))}`" for h in hosts["removed_in_v2"]),
            ]
        out.append("")

    out += ["## Rules", ""]
    for table, items in report.rules.items():
        out += [f"### {table}", ""]
        out += _table(
            ("v1 key", "v2 id", "Result", "Notes"),
            (
                (i.get("v1_key"), i.get("id", ""), _status(i.get("status")), "; ".join(i.get("notes", [])))
                for i in items
            ),
        )
        out.append("")
    if report.ladder:
        out += ["### throttle_tiers (the escalation ladder)", ""]
        out.append(f"Result: {_status(report.ladder.get('status'))}. {_visible(str(report.ladder.get('detail', '')))}")
        out.append("")

    out += ["## Pause and throttle-all", ""]
    out += _table(
        ("State", "v1 value", "Result", "Notes"),
        (
            (s.get("key"), s.get("v1"), _status(s.get("status")), "; ".join(s.get("notes", [])))
            for s in report.service_state
        ),
    )
    out.append("")

    out += ["## Text rewrites (plan C5)", ""]
    out.append(
        "Every em and en dash in admin-written text was replaced. Review the wording and change it in the dashboard "
        "if a rewrite reads badly."
    )
    out.append("")
    out += _table(
        ("Table", "Id", "Field", "Before", "After", "Repairs"),
        (
            (r.get("table"), r.get("id"), r.get("field"), r.get("before"), r.get("after"), r.get("repairs"))
            for r in report.text_rewrites
        ),
    )
    out.append("")

    out += ["## Credential files", ""]
    out += _table(
        ("Name", "Result", "Details"),
        ((c.get("name"), c.get("status"), c.get("detail", "")) for c in report.credentials),
    )
    out.append("")

    out += ["## Admin account", ""]
    admin = report.admin or {}
    out.append(f"Result: {_status(admin.get('status', 'n/a'))}. {_visible(str(admin.get('detail', '')))}")
    out.append("")

    out += ["## Statistics (metrics.db)", ""]
    stats = report.statistics or {}
    labels = {"exploit_summaries": "exploit summaries (events table)", "kpi": "Baseline KPI (plan 11.6)"}
    out += [f"- {labels.get(name, name)}: {_cell(value)}" for name, value in stats.items()] or ["(none)"]
    out.append("")

    out += ["## Not migrated", ""]
    out += _table(
        ("What", "Count", "Why"),
        ((n.get("what"), n.get("count", ""), n.get("why")) for n in report.not_migrated),
    )
    out.append("")
    return "\n".join(out)


def report_paths(path: Path) -> tuple[Path, Path]:
    """(json path, markdown path) for `--report PATH`: `x.json` pairs with `x.md`, anything else gets both suffixes."""
    if path.suffix.lower() == ".json":
        return path, path.with_suffix(".md")
    if path.suffix.lower() == ".md":
        return path.with_suffix(".json"), path
    return path.with_name(path.name + ".json"), path.with_name(path.name + ".md")


def _write_private(path: Path, text: str) -> None:
    """Write `text` to `path` with mode 0600 (the report names files, hosts and admin text; keep it private).

    The owner may point `--report` at a shared directory such as /tmp while running as root. A fixed temporary
    name there lets another user plant a link that the write would follow (review finding 7), so the temporary
    file gets a random name and is created with O_EXCL and O_NOFOLLOW, which never open an existing entry or a
    link. `os.replace` then swaps the directory entry itself: a link planted at the final name is replaced, not
    followed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)  # the umask can only remove bits; set the mode exactly anyway
            data = memoryview(text.encode("utf-8"))
            while data:  # os.write may write less than asked
                data = data[os.write(fd, data) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise


def write_report(report: MigrationReport, path: Path) -> tuple[Path, Path]:
    """Write the JSON and Markdown files for `report`; returns their paths."""
    json_path, markdown_path = report_paths(path)
    # ensure_ascii=True: non-ASCII (the dashes in C5 "before" texts included) is written as \\u escapes.
    _write_private(json_path, json.dumps(report.as_dict(), indent=2, sort_keys=False, ensure_ascii=True) + "\n")
    _write_private(markdown_path, render_markdown(report))
    return json_path, markdown_path


__all__ = [
    "ALREADY",
    "DUPLICATE",
    "IMPORTED",
    "INVALID",
    "KEPT",
    "NOT_IMPORTED",
    "REFUSED",
    "REMOVED",
    "REPLACED_DEFAULT",
    "REPORT_SCHEMA",
    "SKIPPED",
    "MigrationReport",
    "SecretScrubber",
    "piece_length",
    "render_markdown",
    "report_paths",
    "write_report",
]
