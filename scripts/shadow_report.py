#!/usr/bin/env python3
"""shadow_report.py: the pre-cutover shadow comparison report for decision D1 (plan 18.4).

What this is
    `python scripts/shadow_report.py [--hotfix-report FILE] [--state-dir DIR]` reads the records of a shadow
    comparison (the same Roblox GET answered once anonymously and once with the credential, from the server's own
    address) and prints, per endpoint template: how many pairs were sampled, how many answers were identical, how
    many differed, how often the anonymous call failed (401, 403, an empty body) or was rate-limited, and the
    class the plan names (identical, differs, anonymous fails, anonymous rate-limited). Below the table it
    evaluates the cutover gate: "Roblox 429s per 1,000 upstream calls" on the anonymous sample must not exceed the
    credential path's rate by more than 50%. Markdown by default, JSON with `--json`.
    With no records at all it says so plainly: no shadow week ran, why, and what the report would contain.

Why it exists
    Plan 18.4: D1 moves the credential off caller traffic, so before the cutover the owner should see which
    endpoints behave the same without it. Templates that differ or fail are the D1 allowlist decision (each with
    its `cache_private` choice). The owner has decided D1 = never send the credential for callers (empty
    allowlist; only Roxy's own probes use it), so the 7-day shadow week was not run before the cutover (LEAD_NOTES
    decision 8, DECISIONS_REVIEW.md). The script stays so the comparison can be made at any time later, from either
    producer, and so the cutover documents say exactly what was and was not measured.

How it works
    Two producers, both optional:
      * The v1 hotfix (branch hotfix/v1-phase-minus-1, item 6): `GET /admin/shadow` answers per-template counters
        (`Sampled`, `AnonOk`, `AnonFailed`, `Anon429`, `Replayed`, `Identical`, `Differs`, `CredFailed`,
        `Cred429`, `SkippedBudget`, `SkippedRedirect`); save that JSON and pass it as `--hotfix-report`. The v1
        coordination file, which keeps the same object under `Shadow`, works too. The hotfix replays in the opposite
        direction (anonymous first, credential replay), which gives the same pairs (CHANGES.md, "Hotfix shadow mode").
      * Roxy v2: `credential_comparison` events in metrics.db (type, detail `{endpoint_template, method, anon_status,
        cred_status, identical}`), the event `insights/providers_rules_cache_egress.py` defines for a comparison
        producer. `--state-dir` reads them over the last `--days` days, read only (SQLite `mode=ro`).
    Records from both are added per template. A template needs `--min-samples` pairs before it is called identical.
    The gate compares 429s per 1,000 anonymous samples with 429s per 1,000 credential replays; it cannot be judged
    without replays. Exit status: 0 report written; 1 an input could not be read; with `--strict`, also 1 when the
    gate fails. Only the standard library is used, so the system Python can run it.

What to read next
    REMAKE_PLAN.md section 18.4, the hotfix's `app/shadow.py`, `src/roxy/insights/rules/credential.py`
    (CRED-UNUSED, the rule that reads the v2 events), then MIGRATION.md.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final, TextIO

GATE_MAX_RATIO: Final = 1.5
"""Plan 18.4: the anonymous 429 rate may exceed the credential path's by at most 50%."""

DEFAULT_MIN_SAMPLES: Final = 5
DEFAULT_DAYS: Final = 7
COMPARISON_EVENT: Final = "credential_comparison"
MAX_TEMPLATES: Final = 2000
"""Templates kept in one report (the hotfix keeps at most 200; v2 events are bounded the same way, plan P9)."""
MAX_EVENTS: Final = 500_000
MAX_INPUT_BYTES: Final = 64 * 1024 * 1024
MAX_TEMPLATE_CHARS: Final = 300

CLASS_IDENTICAL: Final = "identical"
CLASS_DIFFERS: Final = "differs"
CLASS_ANON_FAILS: Final = "anonymous fails"
CLASS_ANON_LIMITED: Final = "anonymous rate-limited"
CLASS_THIN: Final = "not enough data"

D1_DECISION: Final = (
    "The owner chose D1 = never send the credential for callers: the credential allowlist stays empty and only "
    "Roxy's own probes use the credential."
)

HOTFIX_COUNTERS: Final = {
    "Sampled": "sampled",
    "AnonOk": "anon_ok",
    "AnonFailed": "anon_failed",
    "Anon429": "anon_429",
    "Replayed": "replayed",
    "Identical": "identical",
    "Differs": "differs",
    "CredFailed": "cred_failed",
    "Cred429": "cred_429",
    "SkippedBudget": "skipped_budget",
    "SkippedRedirect": "skipped_redirect",
}


class ReportError(Exception):
    """An input could not be read; printed without a traceback (exit 1)."""


@dataclass
class Tally:
    """The counts of one endpoint template (every field a plain integer, so tallies add up across sources)."""

    template: str
    sampled: int = 0
    anon_ok: int = 0
    anon_failed: int = 0
    anon_429: int = 0
    replayed: int = 0
    identical: int = 0
    differs: int = 0
    cred_failed: int = 0
    cred_429: int = 0
    skipped_budget: int = 0
    skipped_redirect: int = 0

    def add(self, other: Tally) -> None:
        for name in HOTFIX_COUNTERS.values():
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def classify(self, min_samples: int) -> str:
        """The plan 18.4 class; the most consequential one wins when several apply."""
        if self.anon_failed > 0:
            return CLASS_ANON_FAILS
        if self.differs > 0:
            return CLASS_DIFFERS
        if self.anon_429 > 0:
            return CLASS_ANON_LIMITED
        if self.identical >= max(1, min_samples):
            return CLASS_IDENTICAL
        return CLASS_THIN


@dataclass
class Report:
    """Everything the output shows."""

    sources: list[str] = field(default_factory=list)
    tallies: dict[str, Tally] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def tally(self, template: str) -> Tally | None:
        key = str(template or "").strip()[:MAX_TEMPLATE_CHARS]
        if not key:
            return None
        found = self.tallies.get(key)
        if found is None:
            if len(self.tallies) >= MAX_TEMPLATES:
                self.notes.append(f"More than {MAX_TEMPLATES} templates; the rest were left out.")
                return None
            found = self.tallies[key] = Tally(key)
        return found

    @property
    def empty(self) -> bool:
        return not any(t.sampled or t.replayed for t in self.tallies.values())


# ================================================================================================ inputs


def _int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _read_json(path: Path) -> Any:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise ReportError(f"cannot read {path}: {type(exc).__name__}") from None
    if len(data) > MAX_INPUT_BYTES:
        raise ReportError(f"{path} is larger than {MAX_INPUT_BYTES} bytes")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ReportError(f"{path} is not a JSON document") from None


def load_hotfix(report: Report, document: Any, label: str) -> int:
    """Add the hotfix's per-template counters (`GET /admin/shadow`, or the coordination file's `Shadow`)."""
    if isinstance(document, Mapping) and isinstance(document.get("Shadow"), Mapping):
        document = document["Shadow"]
    templates = document.get("Templates") if isinstance(document, Mapping) else None
    if not isinstance(templates, Mapping):
        raise ReportError(f"{label} has no shadow report (a Templates object, as GET /admin/shadow answers)")
    added = 0
    for template, counters in templates.items():
        if not isinstance(counters, Mapping):
            continue
        tally = report.tally(str(template))
        if tally is None:
            continue
        part = Tally(tally.template, **{name: _int(counters.get(key)) for key, name in HOTFIX_COUNTERS.items()})
        tally.add(part)
        added += 1
    since = document.get("Since") if isinstance(document, Mapping) else None
    when = time.strftime("%Y-%m-%d", time.gmtime(float(since))) if isinstance(since, int | float) and since else "?"
    report.sources.append(f"v1 hotfix shadow report {label} ({added} templates, measured since {when})")
    return added


def add_comparison(
    report: Report, template: str, anon_status: Any, cred_status: Any, identical: Any, count: int
) -> None:
    """One v2 `credential_comparison` record (counted `count` times)."""
    tally = report.tally(template)
    if tally is None or count <= 0:
        return
    tally.sampled += count
    anon = _int(anon_status) if anon_status is not None else 0
    if anon == 429:
        tally.anon_429 += count
        return
    if not 200 <= anon < 300:
        tally.anon_failed += count
        return
    tally.anon_ok += count
    if cred_status is None:
        tally.skipped_budget += count
        return
    tally.replayed += count
    cred = _int(cred_status)
    if cred == 429:
        tally.cred_429 += count
    elif not 200 <= cred < 300:
        tally.cred_failed += count
    elif identical:
        tally.identical += count
    else:
        tally.differs += count


def load_events(report: Report, state_dir: Path, *, days: float, now: float | None = None) -> int:
    """Add v2 `credential_comparison` events from metrics.db (read only) over the last `days` days."""
    path = state_dir / "metrics.db"
    if not path.is_file():
        raise ReportError(f"no metrics.db in {state_dir}")
    since_ms = int(((time.time() if now is None else now) - days * 86400) * 1000)
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise ReportError(f"cannot open {path}: {exc}") from None
    try:
        rows = conn.execute(
            "SELECT endpoint_template, detail_json FROM events WHERE type = ? AND at_ms >= ? ORDER BY id LIMIT ?",
            (COMPARISON_EVENT, since_ms, MAX_EVENTS),
        ).fetchall()
    except sqlite3.Error as exc:
        raise ReportError(f"cannot read the events of {path}: {exc}") from None
    finally:
        conn.close()
    for template_column, detail_text in rows:
        try:
            detail = json.loads(detail_text) if detail_text else {}
        except ValueError:
            continue
        if not isinstance(detail, Mapping):
            continue
        template = str(detail.get("endpoint_template") or template_column or "")
        add_comparison(
            report,
            template,
            detail.get("anon_status"),
            detail.get("cred_status"),
            detail.get("identical"),
            _int(detail.get("count", 1)) or 1,
        )
    report.sources.append(f"Roxy v2 metrics.db: {len(rows)} {COMPARISON_EVENT} events over {days:g} days")
    return len(rows)


# ================================================================================================ the gate


@dataclass(frozen=True)
class Gate:
    """The plan 18.4 cutover gate."""

    anon_samples: int
    anon_429: int
    cred_replays: int
    cred_429: int
    anon_per_1000: float | None
    cred_per_1000: float | None
    verdict: str  # "pass", "review" or "no data"
    explanation: str


def gate(tallies: Iterable[Tally]) -> Gate:
    rows = list(tallies)
    anon_samples = sum(t.sampled for t in rows)
    anon_429 = sum(t.anon_429 for t in rows)
    replays = sum(t.replayed for t in rows)
    cred_429 = sum(t.cred_429 for t in rows)
    anon_rate = 1000.0 * anon_429 / anon_samples if anon_samples else None
    cred_rate = 1000.0 * cred_429 / replays if replays else None
    if anon_rate is None or cred_rate is None:
        why = "The gate needs both anonymous samples and credential replays; there are none to compare."
        return Gate(anon_samples, anon_429, replays, cred_429, anon_rate, cred_rate, "no data", why)
    limit = cred_rate * GATE_MAX_RATIO
    if anon_rate <= limit + 1e-9:
        verdict = "pass"
        text = (
            f"Anonymous 429s are {anon_rate:.2f} per 1,000 calls against {cred_rate:.2f} on the credential path "
            f"(the limit is {limit:.2f}, 50% above it)."
        )
    else:
        verdict = "review"
        text = (
            f"Anonymous 429s are {anon_rate:.2f} per 1,000 calls, more than 50% above the credential path's "
            f"{cred_rate:.2f}: the owner reviews before the cutover (plan 18.4)."
        )
    return Gate(anon_samples, anon_429, replays, cred_429, anon_rate, cred_rate, verdict, text)


# ================================================================================================ output


def decision_for(kind: str) -> str:
    """What the plan asks of the owner for one class (and what D1 = never means for it)."""
    if kind in (CLASS_DIFFERS, CLASS_ANON_FAILS):
        return "D1 allowlist decision (with its cache_private choice); with D1 = never it stays anonymous"
    if kind == CLASS_ANON_LIMITED:
        return "anonymous only; watch its 429 rate (the gate below)"
    if kind == CLASS_IDENTICAL:
        return "none: the credential changes nothing here"
    return "measure longer before deciding"


def as_document(report: Report, min_samples: int) -> dict[str, Any]:
    rows = sorted(report.tallies.values(), key=lambda t: (-t.sampled, t.template))
    result = gate(rows)
    return {
        "schema": "roxy.shadow_report/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ran": not report.empty,
        "decision_d1": D1_DECISION,
        "sources": report.sources,
        "min_samples": min_samples,
        "templates": [
            {**asdict(t), "class": t.classify(min_samples), "decision": decision_for(t.classify(min_samples))}
            for t in rows
        ],
        "gate": asdict(result),
        "notes": report.notes,
    }


NO_SHADOW_WEEK: Final = (
    "No shadow week ran. Plan 18.4 asks for a 7-day comparison before the cutover so that the owner can decide "
    "which endpoints, if any, should keep the credential (decision D1). The owner decided that ahead of time: "
    "D1 = never send the credential for callers. The credential allowlist ships empty and only Roxy's own probes "
    "use the credential, so no endpoint waited on this measurement (LEAD_NOTES decision 8, DECISIONS_REVIEW.md)."
)

WOULD_CONTAIN: Final = (
    "If a comparison is run later (the v1 hotfix's shadow mode with `shadow_enabled` = 1 for 7 days, then "
    "`--hotfix-report` with the saved `GET /admin/shadow` JSON; or a v2 producer of `credential_comparison` "
    "events, then `--state-dir`), this report shows one row per endpoint template with: pairs sampled, identical "
    "answers, differing answers, anonymous failures (401, 403, an empty body), anonymous 429s, credential failures "
    "and credential 429s; the class of plan 18.4 (identical, differs, anonymous fails, anonymous rate-limited); "
    "and what the owner decides for it (templates that differ or fail are the allowlist decision, each with its "
    "cache_private choice). Below the table: the cutover gate, Roblox 429s per 1,000 upstream calls on the "
    "anonymous sample against the credential path, which must not be more than 50% higher."
)


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(document: Mapping[str, Any]) -> str:
    lines = ["# Shadow comparison report (plan 18.4, decision D1)", ""]
    lines.append(f"Generated {document['generated_at']}.")
    lines.append("")
    if not document["ran"]:
        lines += [NO_SHADOW_WEEK, "", WOULD_CONTAIN, ""]
        if document["sources"]:
            lines += ["Inputs read (no comparison records in them):", ""]
            lines += [f"- {_cell(source)}" for source in document["sources"]]
            lines.append("")
        return "\n".join(lines)
    lines += [document["decision_d1"], "", "Inputs:", ""]
    lines += [f"- {_cell(source)}" for source in document["sources"]]
    lines += [
        "",
        "| Endpoint template | Sampled | Identical | Differs | Anonymous fails | Anonymous 429 | Credential fails | "
        "Credential 429 | Class | Decision |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in document["templates"]:
        lines.append(
            f"| `{_cell(row['template'])}` | {row['sampled']} | {row['identical']} | {row['differs']} | "
            f"{row['anon_failed']} | {row['anon_429']} | {row['cred_failed']} | {row['cred_429']} | {row['class']} | "
            f"{_cell(row['decision'])} |"
        )
    result = document["gate"]
    lines += [
        "",
        "## Cutover gate",
        "",
        f"Verdict: **{result['verdict']}**. {result['explanation']}",
        "",
        f"Anonymous: {result['anon_429']} 429s in {result['anon_samples']} samples. "
        f"Credential: {result['cred_429']} 429s in {result['cred_replays']} replays.",
        "",
        f"A template needs {document['min_samples']} identical pairs before it is called identical.",
    ]
    for note in document["notes"]:
        lines.append(f"Note: {_cell(note)}")
    return "\n".join(lines) + "\n"


# ================================================================================================ main


def build_report(
    *, hotfix_reports: Sequence[Path] = (), state_dir: Path | None = None, days: float = DEFAULT_DAYS
) -> Report:
    report = Report()
    for path in hotfix_reports:
        load_hotfix(report, _read_json(path), str(path))
    if state_dir is not None:
        load_events(report, state_dir, days=days)
    return report


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    output = out or sys.stdout
    parser = argparse.ArgumentParser(description="The plan 18.4 shadow comparison report (decision D1).")
    parser.add_argument(
        "--hotfix-report",
        action="append",
        type=Path,
        default=[],
        help="JSON saved from the v1 hotfix's GET /admin/shadow (or its coordination file); repeatable",
    )
    parser.add_argument("--state-dir", type=Path, help="Roxy v2 state directory: read credential_comparison events")
    parser.add_argument("--days", type=float, default=DEFAULT_DAYS, help="look-back for v2 events (default 7)")
    parser.add_argument("--min-samples", type=int, default=DEFAULT_MIN_SAMPLES, help="pairs before 'identical'")
    parser.add_argument("--json", action="store_true", help="JSON instead of Markdown")
    parser.add_argument("--strict", action="store_true", help="exit 1 when the cutover gate asks for a review")
    args = parser.parse_args(argv)
    try:
        report = build_report(hotfix_reports=args.hotfix_report, state_dir=args.state_dir, days=args.days)
    except ReportError as exc:
        output.write(f"shadow_report: {exc}\n")
        return 1
    document = as_document(report, max(1, args.min_samples))
    if args.json:
        output.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    else:
        output.write(render_markdown(document))
    if args.strict and document["gate"]["verdict"] == "review":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
