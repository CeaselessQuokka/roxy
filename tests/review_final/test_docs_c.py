"""Final review, lens docs_c: the owner-facing documents and the promises they make, against the code.

What this is
    One reproduction per finding of `.remake/final_review/find_docs_c.md` (ids `docs_c-<n>`). Each was a strict
    xfail until the final review fixed its finding (in the text or in the code); each is a regression test now.

Why it exists
    The owner follows the runbooks in an incident and MIGRATION.md at the cutover, callers read the public user
    guide, and the owner signs DECISIONS_REVIEW.md after reading CHANGES.md. A step that cannot work as written, a
    promise the proxy does not keep, or a record that points at a file the owner does not have, costs the most at
    the worst moment.

How it works
    Documents are read as text and split into their sections the way tests/unit/test_docs_references.py does
    (headings, code spans and code block lines). Behavior comes from the real code: the migrator through the
    tests/migration fixtures, the public `/docs` page through the root conftest's in-process `client`, the
    shadow report as a subprocess, the settings catalog as imported. Nothing leaves the machine.

What to read next
    `.remake/final_review/find_docs_c.md`, then the documents and modules each test names.
"""

from __future__ import annotations

import html
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from migration.conftest import _no_v1_environment, migrate, v1, ws  # noqa: F401  (the migration fixtures)
from roxy.config.catalog import CATALOG

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
INLINE_CODE = re.compile(r"`([^`\n]+)`")


def sections(text: str, level: int) -> dict[str, str]:
    """Every section of exactly `level` (`##` is 2) by its heading text, with its body up to the next one."""
    out: dict[str, str] = {}
    current: str | None = None
    body: list[str] = []
    in_block = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_block = not in_block
        match = None if in_block else HEADING.match(line)
        if match and len(match.group(1)) <= level:
            if current is not None:
                out[current] = "\n".join(body)
            current = match.group(2).strip() if len(match.group(1)) == level else None
            body = []
            continue
        if current is not None:
            body.append(line)
    if current is not None:
        out[current] = "\n".join(body)
    return out


def code_lines(text: str) -> list[str]:
    """Inline code spans and code block lines (a line ending in a backslash is joined with the next)."""
    found: list[str] = []
    in_block = False
    pending = ""
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            if line.rstrip().endswith("\\"):
                pending += line.rstrip()[:-1] + " "
                continue
            found.append((pending + line).strip())
            pending = ""
            continue
        found.extend(span.strip() for span in INLINE_CODE.findall(line))
    return [item for item in found if item and not item.startswith("#")]


def migration_doc() -> Path:
    """MIGRATION.md at the repository root once the docs step installs it, else the draft it is made from."""
    installed = ROOT / "MIGRATION.md"
    return installed if installed.is_file() else ROOT / ".remake" / "drafts" / "MIGRATION.md"


# ============================================================================================ docs_c-1


def test_the_restore_runbook_works_from_an_operator_shell() -> None:
    """docs/RUNBOOKS.md "Restore from backup", followed from the operator's shell (`ubuntu` with per-command sudo,
    as every other runbook command is written):

    - `cd /var/backups/roxy/<date> && sudo sha256sum -c SHA256SUMS` fails: backup.sh makes `/var/backups/roxy` and
      every set directory 0700 root, so the `cd` (run by the shell, not by sudo) is refused;
    - `age -d -i <id> control.db.zst.age > control.db.zst` has no sudo: it can neither read the root 0600 file nor
      write next to it, and `sudo zstd -d control.db.zst ...` only works from inside that directory;
    - step 5 runs `PRAGMA integrity_check` "the same way as the quick check" (`sudo -u roxy python3 ...`) BEFORE
      step 6 hands the file to roxy: zstd keeps the mode of the 0600 root copy, so roxy cannot open it;
    - "If the disk was lost" restores the keys, but the sets lived on that disk: nothing says how to fetch the
      off-box copy (D15, `rclone`) the runbook then needs.
    """
    backup_sh = (ROOT / "deploy" / "tools" / "backup.sh").read_text(encoding="utf-8")
    # The facts the runbook has to live with (pinned by tests/deploy/test_deploy_backup.py::test_nightly_set).
    assert 'chmod 0700 "$BACKUP_DIR"' in backup_sh
    assert 'chmod 0700 "$final"' in backup_sh
    assert "umask 0077" in backup_sh

    section = sections((DOCS / "RUNBOOKS.md").read_text(encoding="utf-8"), 2)["Restore from backup"]
    commands = [line for line in code_lines(section) if " " in line]
    problems: list[str] = []
    # A runbook may instead open a root shell first (`sudo -i`); then plain commands and a `cd` work as written.
    root_shell = any(re.match(r"sudo (-i|-s|su)\b", line) for line in commands)
    for line in [] if root_shell else commands:
        if re.match(r"cd\s+/var/backups/roxy", line):
            problems.append(f"the operator's shell cannot cd into a root-only directory: {line!r}")
        # A file of a backup set (the key escrow archive lives in the owner's own directory and needs no sudo).
        names_backup_file = re.search(r"\.zst\b|SHA256SUMS", line)
        if names_backup_file and not line.startswith("sudo"):
            problems.append(f"a command on a root-only backup file runs without sudo: {line!r}")
        for token in re.findall(r"\S*\.zst(?:\.age)?\b", line):
            if "/" not in token and "cd " not in line:
                problems.append(f"{token} is named relative to a directory the shell cannot enter: {line!r}")
    chown = section.find("chown roxy:roxy /var/lib/roxy/control.db")
    check = section.find("integrity_check")
    if chown == -1 or (check != -1 and check < chown and "sudo python3" not in section):
        problems.append("the integrity check runs as roxy before the restored root 0600 file is given to roxy")
    if "rclone" not in section:
        problems.append("after a lost disk the runbook never says how to fetch the off-box set (rclone, D15)")
    assert problems == []


# ============================================================================================ docs_c-2


async def test_the_public_privacy_chapter_says_what_roxy_records(client: Any) -> None:
    """`/docs` chapter 10 (docs/USER_GUIDE.md and `roxy.public.pages.capture_rule`) is what callers are told about
    their data. At the shipped defaults it says Roxy keeps "a small sample of individual requests", but
    `request_sample_pct` is 100 (plan 6.2: one row per proxied request, with `client_hash` and `place`, for 24 h,
    used for every dry run of limits and detectors, not only to tune caching). It says capture "covers refused
    requests and about 20% of served requests", but `roxy.metrics.capture.CapturePolicy.wants` captures every
    outcome that is not served: failed requests (timeouts, deadlines, no upstream path) too.

    Lead decision (9) lets the capture half be fixed either way: the text names failed requests (the code is
    right), or the code samples failures like served requests (plan D8 read as "served (non-refused) requests at
    20%"), so the test accepts both (skeptic edit)."""
    from roxy.metrics.capture import CapturePolicy

    assert CATALOG["request_sample_pct"].default == 100
    response = await client.get("/docs")
    assert response.status_code == 200
    page = response.text
    start = page.find('id="10-privacy"')
    end = page.find('id="11-reporting-a-security-problem"')
    assert 0 <= start < end
    chapter = html.unescape(re.sub(r"<[^>]+>", " ", page[start:end]))
    chapter = re.sub(r"\s+", " ", chapter)
    problems: list[str] = []
    if "small sample" in chapter:
        problems.append("says 'a small sample of individual requests' while request_sample_pct is 100")
    capture = chapter[chapter.find("body capture") :] if "body capture" in chapter else chapter
    # At the default 20% share, a draw of 0.999 skips a served request; a failure still captured is "always".
    failures_always = CapturePolicy().wants("failed", rnd=lambda: 0.999)
    if failures_always and not re.search(r"\bfail", capture):
        problems.append("says capture covers refused and some served requests; failed requests are always captured")
    assert problems == [], chapter


# ============================================================================================ docs_c-4

PLAN_18_1 = {
    "summary": "1. Summary of the rewrite",
    "files removed": "2. Files removed",
    "files added": "3. Files added",
    "files changed": "4. Files changed",
    "parity checklist": "5. Feature parity checklist",
    "settings decisions": "6. Settings decisions",
    "owner decisions applied": "7. Owner decisions applied",
    "ops changes": "8. Ops changes",
    "behavior changes callers may notice": "9. Behavior changes callers may notice",
    "plan conflicts": "10. Plan conflicts",
    "progress notes": "11. Progress notes per phase",
    "section map": "12. v1 section map and parity checklists",
    "known limitations": "13. Known limitations and follow-ups",
}


def test_changes_md_has_every_plan_18_1_section() -> None:
    """Plan 18.1 lists the 13 parts CHANGES.md must contain. MIGRATION.md 5.5 tells the owner to "tell your users
    what changed for callers (decision D4 and the other caller-visible changes in CHANGES.md)", DECISIONS_REVIEW.md
    cites CHANGES.md headings, and plan 0.1 says every PENDING decision used is noted there. Today CHANGES.md has the
    plan conflicts, the progress notes, the parity checklist and the v1 section map, and none of the others."""
    text = (ROOT / "CHANGES.md").read_text(encoding="utf-8")
    headings = [match.group(2).lower() for line in text.splitlines() if (match := HEADING.match(line))]
    missing = [title for key, title in PLAN_18_1.items() if not any(key in heading for heading in headings)]
    assert missing == []
    owner = next(
        (
            body
            for title, body in {**sections(text, 2), **sections(text, 3)}.items()
            if "owner decisions" in title.lower()
        ),
        "",
    )
    absent = [f"D{n}" for n in range(1, 21) if not re.search(rf"\bD{n}\b", owner)]
    assert absent == [], "plan 18.1 item 7: D1 to D20 with the value used"


# ============================================================================================ docs_c-6

WORKING_NOTES = re.compile(r"\.remake/|\bLEAD_NOTES\b|\bDESIGN\.md\b|\bHANDOFF\.md\b|\bP11_INPUTS\b|\bv1notes\b")


def _shadow_report_output() -> str:
    result = subprocess.run(  # the repository's own script, no shell
        [sys.executable, "-I", str(ROOT / "scripts" / "shadow_report.py")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=str(ROOT / "tests"),
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.mark.parametrize(
    "source",
    ["scripts/shadow_report.py output", "deploy/README.md", "docs/ARCHITECTURE.md", "docs/PERFORMANCE.md"],
)
def test_owner_facing_texts_cite_only_files_in_the_repository(source: str) -> None:
    """`.remake/` is in .gitignore: a clone, a release and the owner's checkout have none of it. Yet the shadow
    report, whose output DECISIONS_REVIEW.md attaches for the owner's signature, says "(LEAD_NOTES decision 8,
    DECISIONS_REVIEW.md)"; deploy/README.md twice sends the reader to "DESIGN.md section 0" for the memory sizing;
    docs/ARCHITECTURE.md does too; and docs/PERFORMANCE.md, which the dashboard's Help page serves, cites
    `.remake/p11_reports/...` results and tells the reader to rerun `.remake/scripts/gaps_insights_pinned.sh`, a
    script no checkout contains. (CHANGES.md carries 65 more such citations of `.remake/` reports.)"""
    if source.endswith("output"):
        text = _shadow_report_output()
    else:
        text = (ROOT / source).read_text(encoding="utf-8")
    cited = sorted({match.group(0) for match in WORKING_NOTES.finditer(text)})
    assert cited == [], f"{source} cites {cited}"


# ============================================================================================ docs_c-7


@pytest.mark.parametrize("key", ["rotator_quota_gb_per_month", "rotator_price_per_gb_usd"])
def test_owner_filled_settings_are_marked_for_the_owner(key: str) -> None:
    """Plan 0.3 D12: "Owner fills in `rotator_quota_gb_per_month` and `rotator_price_per_gb_usd`. Placeholders: 0".
    The catalog flag is what docs/SETTINGS.md ("Pending owner verification") and the settings API show; the ten
    keys flagged today include six `site_*` texts, but not these two, so nothing in the product asks for the values
    the quota alerts, the hard stop and the cost projection need (DECISIONS_REVIEW.md works around it by hand:
    "The catalog does not mark these keys for your check"). The fix also updates
    tests/unit/config/test_settings_routing.py::test_only_the_session_template_is_pending_owner_verification,
    which pins today's list."""
    assert CATALOG[key].default == 0
    assert CATALOG[key].pending_owner_verification is True


# ============================================================================================ docs_c-8


def test_the_readme_is_final_and_points_at_the_cutover() -> None:
    """README.md is the repository's front page and the first thing the owner opens before signing off. It still
    says "The full README is written in P12; until then, these are the guides", calls docs/ADMIN_GUIDE.md "being
    written" (the docs step installs the 26-chapter guide), and lists neither MIGRATION.md (plan 18.2, the cutover
    the owner runs; deploy.yml's guard comment sends the owner there) nor DECISIONS_REVIEW.md (the sign-off)."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    stale = [phrase for phrase in ("written in P12", "until then", "being written") if phrase in text]
    assert stale == [], f"placeholder text left: {stale}"
    assert "MIGRATION.md" in text, "README.md does not point at the cutover document"
