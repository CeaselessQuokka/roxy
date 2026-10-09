"""Documentation references (plan 18.5): every file, symbol, test, route and command the guides name exists.

What this is
    Tests over the four hand-written guides: `docs/LEARNING_PATH.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`
    and `docs/RUNBOOKS.md`. Every reference inside a code span or a code block is checked against the repository
    and the application:
      * repository paths (`src/roxy/...`, `tests/...`, `deploy/...`) exist;
      * dotted Python names (`roxy.abuse.limiter.gcra`) are defined in their module, read with `ast`;
      * test ids (`tests/....py::test_name`) name a test function that exists;
      * HTTP routes (`GET /admin/api/v1/...`, `/internal/ready`, `/health`) are routes of the public or internal
        app, with that method; dashboard pages (`/admin/<page>`) use a page id of the DESIGN.md section 9
        vocabulary (`roxy.config.catalog.PAGES`);
      * snake_case, UPPER_SNAKE and CamelCase names, and `Roxy-*` header names, appear in the settings catalog or the
        source, so no setting, table, event or constant is made up;
      * server paths (`/etc/roxy/...`, `/var/lib/roxy/...`) appear in the deploy files or the source;
      * every `--flag` given to a repository script (or to the `roxyctl` alias the runbooks define) is a flag that
        script handles;
      * every link inside a guide (`[text](#anchor)`) reaches a heading of that guide.
    For the runbooks: the link index resolves every runbook name the alerts (`roxy.notify.alerts.ALERT_SPECS`) and the
    health checks (`roxy.health.checks.SPECS`) link to, every health check has a row, every runbook of plan 17.8
    exists, and every runbook has its seven parts. The architecture page's startup order is compared with a real
    worker's, and the counts and memory sizes the guides quote with the code that sets them. Finally the four files
    pass the C5 style check.

Why it exists
    The owner learns from these guides and follows the runbooks during incidents. A path that moved, a test that was
    renamed or a flag that never existed sends the reader nowhere at the worst moment, and a made-up name teaches
    something false. Plan 18.5 asks for `test_learning_path_references_exist`; the same rules hold for the other three
    guides, so each gets its own test.

How it works
    A small line parser splits each guide into inline code spans, code block lines (a line ending in a backslash is
    joined with the next) and headings; no Markdown library is needed. Each span is classified by its shape (a whole
    span that is a path, a name, a test id or a route), and everything else is read as a command: its words are
    checked one by one, and once a word names a repository script, the `--flags` after it must appear in that
    script's text (or the text of the script it hands over to). Python files are read with `ast` and never imported,
    except the application, which is built once (with temporary state) to list its routes. Heading anchors are
    made with `roxy.public.pages.slugify`, the function that renders the guides, so a link that passes here works on
    the page. Each problem is reported with the guide and the reference, all at once.

What to read next
    `docs/LEARNING_PATH.md`, `docs/RUNBOOKS.md` (its link index), `src/roxy/notify/alerts.py` and
    `src/roxy/health/checks.py` (the runbook links they send), then `tests/unit/test_docstrings.py` (the same idea for
    module docstrings).
"""

from __future__ import annotations

import ast
import functools
import importlib.util
import itertools
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from roxy.config.catalog import CATALOG, PAGES
from roxy.health.checks import CATALOG as HEALTH_CHECKS
from roxy.health.checks import SPECS as HEALTH_SPECS
from roxy.notify.alerts import ALERT_SPECS
from roxy.public.pages import slugify

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
DOCS = ROOT / "docs"
GUIDES = ("LEARNING_PATH.md", "ARCHITECTURE.md", "SECURITY.md", "RUNBOOKS.md")

REPO_DIRS = ("src/", "tests/", "scripts/", "deploy/", "docs/", ".github/")
"""A reference that starts with one of these is a repository path and must exist."""

ROOT_FILES = frozenset({"CHANGES.md", "REMAKE_PLAN.md", "README.md", "pyproject.toml", "uv.lock"})

SERVER_DIRS = ("/etc/", "/var/", "/opt/", "/run/", "/usr/")
"""A reference that starts with one of these is a path on the server and must appear in the deploy files or code."""

SCRATCH_DIRS = ("/tmp/",)
"""Temporary directories an exercise creates; nothing there is part of Roxy."""

CORPUS_DIRS = ("src", "scripts", "deploy", ".github")
"""Where names and server paths must appear (tests are left out: a name only a test uses is not a real one)."""

CORPUS_SUFFIXES = frozenset(
    {
        ".py",
        ".sql",
        ".sh",
        ".md",
        ".conf",
        ".service",
        ".timer",
        ".path",
        ".example",
        ".yml",
        ".template",
        ".txt",
        ".json",
        ".html",
        ".js",
        ".toml",
        "",
    }
)

SCRIPT_ALIASES = {"roxyctl": "scripts/ctl.py"}
"""Shell aliases the guides define (`docs/RUNBOOKS.md`, "Everyday commands")."""

SERVER_SCRIPTS = {
    "/opt/roxy/deploy.sh": "deploy/deploy.sh",
    "/opt/roxy/deploy_rollback.sh": "deploy/deploy_rollback.sh",
    "/usr/local/sbin/roxy-switch-color": "deploy/tools/roxy-switch-color",
    "/usr/local/sbin/roxy-nginx-apply": "deploy/tools/roxy-nginx-apply",
}
"""Where `deploy/README.md` installs each script on the server."""

SCRIPT_DELEGATES = {
    "deploy/deploy_rollback.sh": ("deploy/deploy.sh",),
    "scripts/migrate_from_v1.py": ("src/roxy/migration/cli.py",),
}
"""Scripts that hand their arguments to another file, which then defines the flags."""

CREATED_BY_THE_READER = frozenset({"/var/lib/roxy/control.db.bad"})
"""Server paths a runbook tells the reader to create (a damaged file moved aside), so no deploy file names them."""

RELEASE_PATH = re.compile(r"^/opt/roxy/releases/[^/]+/(.+)$")
TEST_ID = re.compile(r"^(tests/[\w./-]+\.py)::([\w:]+?)(\[[^\]]*\])?$")
ROUTE = re.compile(r"^(?:(GET|HEAD|POST|PUT|PATCH|DELETE) )?(/\S*)$")
SYMBOL = re.compile(r"^roxy(?:\.\w+)+$")
SNAKE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
UPPER_SNAKE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
CAMEL = re.compile(r"^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+$")
HEADER = re.compile(r"^Roxy-[A-Z][A-Za-z-]+$")
FLAG = re.compile(r"^--[a-z][a-z0-9-]*")
IMPORT = re.compile(r"from (roxy(?:\.\w+)+) import ([\w, ]+)")
PLACEHOLDER = re.compile(r"\{[^}]*\}|<[^>]*>")
INLINE_CODE = re.compile(r"`([^`\n]+)`")
LOCAL_LINK = re.compile(r"\]\(#([^)\s]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")

RUNBOOK_PARTS = (
    "**Symptoms.**",
    "**Confirm.**",
    "**Likely causes.**",
    "**Fix.**",
    "**Verify.**",
    "**Roll back.**",
    "**Prevent.**",
)

PLAN_RUNBOOKS = {
    "roblox-is-rate-limiting-us": "Roblox is rate-limiting us",
    "credential-rejected": "Credential rejected or expired",
    "leak-guard": "Leak guard tripped",
    "rotator-down-or-quota-exhausted": "Rotator down or quota exhausted",
    "service-down": "Site down / crash loop",
    "deploy-failed": "Deploy failed",
    "disk-full-or-database-large": "Disk full or DB large",
    "database-corrupt": "Database corrupt",
    "under-attack": "Under attack (flood)",
    "admin-locked-out": "Admin locked out",
    "certificate": "Certificate expiring",
    "clock": "Clock skew",
    "restore-from-backup": "Restore from backup",
    "emergency-stop": "Emergency: stop all upstream traffic",
}
"""Every runbook plan 17.8 names, by the anchor its heading gets here."""


# ============================================================================================== reading the guides


@dataclass(frozen=True)
class Heading:
    level: int
    text: str
    anchor: str
    line: int


@dataclass
class Guide:
    """One guide split into what the checks need."""

    name: str
    text: str
    spans: list[str] = field(default_factory=list)
    block_lines: list[str] = field(default_factory=list)
    headings: list[Heading] = field(default_factory=list)


def parse_guide(name: str) -> Guide:
    """Code spans, code block lines and headings (with the anchors the guide renderer gives them)."""
    text = (DOCS / name).read_text(encoding="utf-8")
    guide = Guide(name, text)
    used: dict[str, int] = {}
    in_block = False
    pending = ""
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            if line.rstrip().endswith("\\"):
                pending += line.rstrip()[:-1] + " "
                continue
            guide.block_lines.append(pending + line)
            pending = ""
            continue
        heading = HEADING.match(line)
        if heading:
            plain = heading.group(2).replace("`", "")
            base = slugify(plain)
            used[base] = used.get(base, 0) + 1
            anchor = base if used[base] == 1 else f"{base}-{used[base]}"
            guide.headings.append(Heading(len(heading.group(1)), plain, anchor, number))
        guide.spans.extend(INLINE_CODE.findall(line))
    return guide


@functools.cache
def guide(name: str) -> Guide:
    return parse_guide(name)


# ============================================================================================== what exists


def _corpus_files() -> Iterator[Path]:
    for top in CORPUS_DIRS:
        for path in sorted((ROOT / top).rglob("*")):
            if "__pycache__" in path.parts or "vendor" in path.parts or not path.is_file():
                continue
            if path.suffix in CORPUS_SUFFIXES:
                yield path


@functools.cache
def corpus() -> str:
    """The text of every source, script, deploy and CI file."""
    return "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in _corpus_files())


@functools.cache
def corpus_words() -> frozenset[str]:
    return frozenset(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", corpus())) | frozenset(CATALOG)


@functools.cache
def module_names(path: Path) -> dict[str, ast.AST]:
    """Names a module defines at the top level (also inside `if` and `try` blocks), including imported ones."""
    names: dict[str, ast.AST] = {}

    def visit(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                names[node.name] = node
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name):
                            names[name.id] = node
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names[node.target.id] = node
            elif isinstance(node, ast.Import | ast.ImportFrom):
                for alias in node.names:
                    names[(alias.asname or alias.name).split(".")[0]] = node
            elif isinstance(node, ast.If | ast.Try):
                visit(node.body)
                visit(node.orelse)
                for handler in getattr(node, "handlers", []):
                    visit(handler.body)
                visit(getattr(node, "finalbody", []))

    visit(ast.parse(path.read_text(encoding="utf-8")).body)
    return names


def class_members(node: ast.ClassDef) -> set[str]:
    """Methods, class attributes, dataclass fields and `self.x` attributes of a class."""
    members: set[str] = set()
    for item in node.body:
        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            members.add(item.name)
        elif isinstance(item, ast.Assign):
            members.update(target.id for target in item.targets if isinstance(target, ast.Name))
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            members.add(item.target.id)
    for found in ast.walk(node):
        if (
            isinstance(found, ast.Attribute)
            and isinstance(found.ctx, ast.Store)
            and isinstance(found.value, ast.Name)
            and found.value.id == "self"
        ):
            members.add(found.attr)  # an attribute set in a method: `self.name = ...`
    return members


def module_file(parts: list[str]) -> Path | None:
    """The file of module `parts` under `src/` (a module file or a package `__init__.py`)."""
    base = SRC.joinpath(*parts)
    if base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return None


def symbol_problem(dotted: str) -> str | None:
    """None when `roxy.package.module.Name[.member]` is defined, else what is missing."""
    parts = dotted.split(".")
    for cut in range(len(parts), 0, -1):
        path = module_file(parts[:cut])
        if path is not None:
            rest = parts[cut:]
            break
    else:
        return "no such module"
    if not rest:
        return None
    names = module_names(path)
    if rest[0] not in names:
        return f"{rest[0]} is not defined in {path.relative_to(ROOT)}"
    if len(rest) == 1:
        return None
    node = names[rest[0]]
    if not isinstance(node, ast.ClassDef) or len(rest) > 2:
        return f"{'.'.join(rest)} cannot be resolved in {path.relative_to(ROOT)}"
    if rest[1] not in class_members(node):
        return f"{rest[0]} has no member {rest[1]}"
    return None


def problem_of_test_id(path_text: str, name: str) -> str | None:
    path = ROOT / path_text
    if not path.is_file():
        return "no such test file"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parts = name.split("::")
    scope: list[ast.stmt] = tree.body
    for depth, part in enumerate(parts):
        found = None
        for node in scope:
            is_def = isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            if node_name(node) == part and (is_def or (isinstance(node, ast.ClassDef) and depth < len(parts) - 1)):
                found = node
        if found is None:
            return f"{part} is not a test in {path_text}"
        scope = found.body if isinstance(found, ast.ClassDef) else []
    return None


def node_name(node: ast.stmt) -> str:
    return getattr(node, "name", "")


def repo_path_problem(text: str) -> str | None:
    return None if (ROOT / text.rstrip("/")).exists() else "no such file or directory in the repository"


def server_path_problem(text: str) -> str | None:
    """None when a server path appears in the deploy files or the source (a color name may stand for either)."""
    path = text.rstrip("/.,")
    if path in CREATED_BY_THE_READER:
        return None
    if path in SERVER_SCRIPTS:
        return None
    release = RELEASE_PATH.match(path)
    if release:
        inside = release.group(1)
        if inside.startswith(".venv/") or (ROOT / inside).exists():
            return None
        return f"{inside} is not part of a release"
    text_of_everything = corpus()
    variants = {path}
    for color in ("blue", "green"):
        for stand_in in ("%i", "<color>", "{color}", "${color}", "blue", "green"):
            variants.add(path.replace(color, stand_in))
    if any(variant in text_of_everything for variant in variants):
        return None
    parent, _, base = path.rpartition("/")
    parents = {parent} | {parent.replace(color, "%i") for color in ("blue", "green")}
    if any(item in text_of_everything for item in parents) and base in text_of_everything:
        return None
    return "not named by any deploy file or source file"


# ============================================================================================== routes


@dataclass(frozen=True)
class Routes:
    """Every (path template, methods) of the public app and the internal socket app."""

    templates: dict[str, frozenset[str]]

    def problem(self, method: str | None, path: str) -> str | None:
        wanted = normalize_route(path)
        if wanted.endswith("/") or wanted in ("/internal", "/admin/api/v1"):
            prefix = wanted if wanted.endswith("/") else wanted + "/"
            return None if any(t.startswith(prefix) for t in self.templates) else "no route under this prefix"
        methods = self.templates.get(wanted)
        if methods is None:
            return "no such route"
        if method is not None and method not in methods:
            return f"the route does not answer {method}"
        return None


def normalize_route(path: str) -> str:
    """`/a/{x:path}/b` and `/a/<x>/b` both become `/a/{}/b`; query strings and anchors are dropped."""
    path = path.split("?", 1)[0].split("#", 1)[0]
    return PLACEHOLDER.sub("{}", path)


@pytest.fixture(scope="module")
def routes(tmp_path_factory: pytest.TempPathFactory) -> Routes:
    from fastapi.routing import iter_route_contexts

    from roxy.config.env import EnvSettings
    from roxy.internal_app import create_internal_app
    from roxy.main import create_app

    state = tmp_path_factory.mktemp("docs_routes")
    env = EnvSettings(env="development", state_dir=state, site_origin="https://testserver")
    app = create_app(env)
    templates: dict[str, set[str]] = {}
    for context in iter_route_contexts(app.router.routes):
        path = normalize_route(str(context.path or ""))
        templates.setdefault(path, set()).update(context.methods or ())
    for route in create_internal_app(app).routes:
        path = normalize_route(str(getattr(route, "path", "")))
        templates.setdefault(path, set()).update(getattr(route, "methods", None) or ())
    return Routes({path: frozenset(methods) for path, methods in templates.items()})


def page_problem(path: str) -> str | None:
    """`/admin/<page>[...]`: the page id must be in the DESIGN.md section 9 vocabulary."""
    segments = normalize_route(path).split("/")
    page = segments[2] if len(segments) > 2 else ""
    if page in ("", "{}") or page in PAGES:
        return None
    return f"{page} is not a dashboard page"


# ============================================================================================== checking references


@dataclass
class Checker:
    routes: Routes
    problems: list[str] = field(default_factory=list)

    def report(self, where: str, reference: str, problem: str | None) -> None:
        if problem:
            self.problems.append(f"{where}: `{reference}`: {problem}")

    def http_path(self, where: str, method: str | None, path: str) -> None:
        first = path.split("/")[1] if path.count("/") >= 1 and len(path) > 1 else ""
        if ".roblox.com" in first:
            return  # a proxied Roblox target, not a route of Roxy
        if path.startswith("/admin") and not path.startswith("/admin/api/") and path not in ("/admin", "/admin/"):
            routed = self.routes.problem(method, path)
            self.report(where, path, None if routed is None else page_problem(path))
            return
        self.report(where, path, self.routes.problem(method, path))

    def span(self, where: str, span: str) -> None:
        """A whole inline code span."""
        text = span.strip()
        test_id = TEST_ID.match(text)
        if test_id:
            self.report(where, text, problem_of_test_id(test_id.group(1), test_id.group(2)))
            return
        if SYMBOL.match(text):
            self.report(where, text, symbol_problem(text))
            return
        if text.startswith(SCRATCH_DIRS):
            return  # a scratch directory the reader makes for an exercise
        route = ROUTE.match(text)
        if route and not text.startswith(SERVER_DIRS) and not PLACEHOLDER.fullmatch(text):
            self.http_path(where, route.group(1), route.group(2))
            return
        if SNAKE.match(text) or UPPER_SNAKE.match(text) or CAMEL.match(text):
            self.report(where, text, None if text in corpus_words() else "not a setting or a name in the source")
            return
        if HEADER.match(text):
            self.report(where, text, None if text in corpus() else "no such header in the source")
            return
        self.command(where, text)

    def command(self, where: str, line: str) -> None:
        """A command or a phrase: check each word; flags after a repository script must be that script's."""
        for match in IMPORT.finditer(line):
            module = match.group(1)
            for name in (item.strip() for item in match.group(2).split(",")):
                if name:
                    self.report(where, f"{module}.{name}", symbol_problem(f"{module}.{name}"))
        scripts: list[str] = []
        # A placeholder such as `<the commit in /var/lib/x>` may hold spaces: blank it before splitting into words.
        words = PLACEHOLDER.sub("{}", line).split()
        for index, raw in enumerate(words):
            word = raw.strip("'\"`,;()")
            if not word or PLACEHOLDER.search(word) or "*" in word:
                continue
            if word.startswith("http://localhost/"):
                self.http_path(where, None, word[len("http://localhost") :])
                continue
            if word.startswith(("http://", "https://", "file:")):
                continue
            if word == "-m" and index + 1 < len(words) and words[index + 1].startswith("roxy."):
                parts = words[index + 1].split(".")
                path = module_file(parts)
                self.report(where, words[index + 1], None if path else "no such module")
                if path:
                    scripts = [str(path.relative_to(ROOT))]
                continue
            if word in SCRIPT_ALIASES:
                scripts = [SCRIPT_ALIASES[word]]
                continue
            test_id = TEST_ID.match(word)
            if test_id:
                self.report(where, word, problem_of_test_id(test_id.group(1), test_id.group(2)))
                continue
            if word.startswith(REPO_DIRS) or word in ROOT_FILES:
                self.report(where, word, repo_path_problem(word))
                if word.endswith((".py", ".sh")) or word.startswith("deploy/tools/"):
                    scripts = [word]
                continue
            if word.startswith(SERVER_DIRS):
                self.report(where, word, server_path_problem(word))
                release = RELEASE_PATH.match(word)
                if word in SERVER_SCRIPTS:
                    scripts = [SERVER_SCRIPTS[word]]
                elif release and release.group(1).endswith((".py", ".sh")):
                    scripts = [release.group(1)]
                continue
            flag = FLAG.match(word)
            if flag and scripts:
                texts = [(ROOT / name).read_text(encoding="utf-8") for name in scripts]
                texts += [(ROOT / extra).read_text(encoding="utf-8") for extra in SCRIPT_DELEGATES.get(scripts[0], ())]
                found = any(flag.group(0) in text for text in texts)
                self.report(where, f"{scripts[0]} {flag.group(0)}", None if found else "the script has no such flag")

    def links(self, doc: Guide) -> None:
        anchors = {heading.anchor for heading in doc.headings}
        for anchor in LOCAL_LINK.findall(doc.text):
            self.report(doc.name, f"#{anchor}", None if anchor in anchors else "no heading with this anchor")

    def guide(self, doc: Guide) -> None:
        for span in doc.spans:
            self.span(doc.name, span)
        for line in doc.block_lines:
            self.command(f"{doc.name} (code block)", line)
        self.links(doc)


def check_guide(name: str, routes: Routes) -> list[str]:
    checker = Checker(routes)
    checker.guide(guide(name))
    return checker.problems


# ============================================================================================== the tests


def test_learning_path_references_exist(routes: Routes) -> None:
    """Plan 18.5: every file path, symbol, test id, route and command flag in the learning path exists."""
    assert check_guide("LEARNING_PATH.md", routes) == []


def test_learning_path_has_the_plan_chapters_with_their_three_parts() -> None:
    """Plan 18.5: twelve chapters, each with file pointers, the tests that show the idea, and an exercise."""
    doc = guide("LEARNING_PATH.md")
    chapters = [h for h in doc.headings if h.level == 2 and re.match(r"\d+\. ", h.text)]
    assert [int(h.text.split(".")[0]) for h in chapters] == list(range(1, 13))
    sections = doc.text.split("\n## ")
    for chapter in chapters:
        body = next(part for part in sections if part.startswith(chapter.text))
        for part in ("**Read.**", "**See it in the tests.**", "**Try this.**"):
            assert part in body, f"{chapter.text} lacks {part}"
        assert any(TEST_ID.match(span) for span in INLINE_CODE.findall(body)), f"{chapter.text} names no test"


def test_architecture_references_exist(routes: Routes) -> None:
    assert check_guide("ARCHITECTURE.md", routes) == []


async def test_architecture_startup_order_is_the_lifespan_order(app: Any, client: Any) -> None:
    """The startup order the architecture page draws is the order a real worker runs its steps in."""
    lines = guide("ARCHITECTURE.md").block_lines
    start = next(index for index, line in enumerate(lines) if line.startswith("env -> "))
    drawn = [lines[start], *itertools.takewhile(lambda line: line.startswith("-> "), lines[start + 1 :])]
    steps = [step.strip() for step in " ".join(drawn).split("->") if step.strip()]
    assert steps == list(app.state.ctx.startup_steps)


def test_numbers_the_guides_state_match_the_code() -> None:
    """Counts and sizes the guides quote, against the code that sets them (so the guides cannot drift)."""
    from roxy.admin.api import API_MODULES
    from roxy.storage.db import PROFILES

    architecture = guide("ARCHITECTURE.md").text
    assert f"{len(API_MODULES)} areas" in architecture
    assert f"{len(HEALTH_CHECKS)} checks" in guide("LEARNING_PATH.md").text
    for name, profile in PROFILES.items():
        writer, reader = profile.writer_cache_kib // 1024, profile.reader_cache_kib // 1024
        row = f"SQLite page cache, {name}.db | {writer} MiB writer + 2 x {reader} MiB readers"
        assert row in architecture, row
    total = sum((p.writer_cache_kib + 2 * p.reader_cache_kib) // 1024 for p in PROFILES.values())
    assert f"add up to at most {total} MiB per worker" in architecture
    assert f"up to {PROFILES['cache'].mmap_bytes // (1024 * 1024)} MiB" in architecture
    assert f"`cache_memory_bytes` ({CATALOG['cache_memory_bytes'].default // (1024 * 1024)} MiB)" in architecture
    unit = (ROOT / "deploy" / "systemd" / "roxy@.service").read_text(encoding="utf-8")
    for directive in ("MemoryHigh", "MemoryMax"):
        value = re.search(rf"^{directive}=(\S+)$", unit, re.MULTILINE)
        assert value is not None
        assert f"`{directive}={value.group(1)}`" in architecture, directive


def test_security_references_exist(routes: Routes) -> None:
    assert check_guide("SECURITY.md", routes) == []


def test_runbook_references_exist(routes: Routes) -> None:
    assert check_guide("RUNBOOKS.md", routes) == []


def runbook_sections() -> dict[str, str]:
    """Each level 2 section of the runbooks by its anchor, with its body."""
    doc = guide("RUNBOOKS.md")
    lines = doc.text.splitlines()
    level2 = [h for h in doc.headings if h.level == 2]
    sections: dict[str, str] = {}
    for index, heading in enumerate(level2):
        end = level2[index + 1].line - 1 if index + 1 < len(level2) else len(lines)
        sections[heading.anchor] = "\n".join(lines[heading.line : end])
    return sections


def table_links(section: str) -> dict[str, str]:
    """First-cell code span -> the `#anchor` of the row's last markdown link, for every row of the table."""
    rows: dict[str, str] = {}
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2 or not line.lstrip().startswith("|"):
            continue
        anchors = LOCAL_LINK.findall(cells[-1])
        if anchors:
            rows[cells[0].strip("`")] = anchors[-1]
    return rows


def test_every_runbook_has_its_parts() -> None:
    """Plan 17.8 and the docs lane task: symptoms, how to confirm, causes, the fix, verify, roll back, prevent."""
    runbooks = {anchor: body for anchor, body in runbook_sections().items() if RUNBOOK_PARTS[0] in body}
    assert len(runbooks) >= len(PLAN_RUNBOOKS)
    for anchor, body in runbooks.items():
        missing = [part for part in RUNBOOK_PARTS if part not in body]
        assert missing == [], f"runbook #{anchor} lacks {missing}"


def test_every_plan_17_8_runbook_exists() -> None:
    sections = runbook_sections()
    missing = [title for anchor, title in PLAN_RUNBOOKS.items() if RUNBOOK_PARTS[0] not in sections.get(anchor, "")]
    assert missing == []


def test_link_index_resolves_every_alert_runbook() -> None:
    """Alert emails link to `/admin/help#runbook-<name>` (`roxy.notify.notifier.runbook_link`)."""
    sections = runbook_sections()
    index = table_links(sections["link-index"])
    names = {spec.runbook for spec in ALERT_SPECS.values() if spec.runbook}
    assert names, "the alert catalog names no runbooks any more: update this test"
    missing = sorted(name for name in names if name not in index)
    assert missing == []
    for name in names:
        assert RUNBOOK_PARTS[0] in sections.get(index[name], ""), f"{name} -> #{index[name]} is not a runbook"


def test_health_check_fix_links_reach_a_runbook() -> None:
    """Health checks link to `/admin/help/runbooks#<anchor>` (a heading here) or `/admin/help/operations#<name>`."""
    sections = runbook_sections()
    index = table_links(sections["link-index"])
    seen = 0
    for spec in HEALTH_SPECS:
        link = spec.fix_link
        if link.startswith("/admin/help/runbooks#"):
            anchor = link.split("#", 1)[1]
            assert RUNBOOK_PARTS[0] in sections.get(anchor, ""), f"{spec.id}: {link} is not a runbook heading"
            assert index.get(anchor) == anchor, f"{spec.id}: {anchor} is missing from the link index"
            seen += 1
        elif link.startswith("/admin/help/operations#"):
            name = "operations#" + link.split("#", 1)[1]
            assert name in index, f"{spec.id}: {name} is missing from the link index"
            assert RUNBOOK_PARTS[0] in sections.get(index[name], ""), f"{spec.id}: {name} is not a runbook"
            seen += 1
    assert seen >= 9, "fewer runbook links than plan 13.2 names: update this test"


def test_every_health_check_has_a_row_in_the_runbooks() -> None:
    sections = runbook_sections()
    table = table_links(sections["health-checks-and-their-runbooks"])
    missing = sorted(check for check in HEALTH_CHECKS if check not in table)
    assert missing == []
    for check, anchor in table.items():
        assert RUNBOOK_PARTS[0] in sections.get(anchor, ""), f"{check} -> #{anchor} is not a runbook"


def test_every_link_index_target_is_a_runbook() -> None:
    sections = runbook_sections()
    for name, anchor in table_links(sections["link-index"]).items():
        assert RUNBOOK_PARTS[0] in sections.get(anchor, ""), f"{name} -> #{anchor} is not a runbook"


@pytest.fixture(scope="module")
def style() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_style_for_docs", ROOT / "scripts" / "check_style.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", GUIDES)
def test_guides_pass_the_style_check(style: ModuleType, name: str) -> None:
    """Plan C5: no em or en dash and US spelling (the same rules CI applies to the whole tree)."""
    rules = style.load_rules()
    issues = style.check_text((DOCS / name).read_text(encoding="utf-8"), rules, f"docs/{name}")
    assert [f"{issue.line}: {issue.message}" for issue in issues] == []


# ============================================================================================== the checker itself


def test_the_checker_catches_made_up_references(routes: Routes) -> None:
    """A guard that never fails proves nothing: each kind of mistake is reported."""
    checker = Checker(routes)
    mistakes = [
        "src/roxy/no_such_module.py",
        "roxy.abuse.limiter.no_such_function",
        "roxy.storage.db.Database.no_such_method",
        "tests/unit/abuse/test_abuse_limiter.py::test_no_such_test",
        "GET /admin/api/v1/no-such-area",
        "DELETE /admin/api/v1/system/versions",
        "/admin/no-such-page",
        "no_such_setting_anywhere",
        "/etc/roxy/no-such-file.conf",
        "roxyctl status --no-such-flag",
        ".venv/bin/python -m roxy.storage.migrate --no-such-flag",
        "Roxy-No-Such-Header",
    ]
    for mistake in mistakes:
        checker.span("example", mistake)
    reported = {problem.split("`")[1].split(" ")[0] for problem in checker.problems}
    assert len(checker.problems) == len(mistakes), checker.problems
    assert "scripts/ctl.py" in reported


def test_the_checker_accepts_real_references(routes: Routes) -> None:
    checker = Checker(routes)
    for real in (
        "src/roxy/abuse/limiter.py",
        "roxy.abuse.limiter.gcra",
        "roxy.storage.db.Database.write",
        "roxy.lifespan.AppContext.dbs",
        "tests/unit/abuse/test_abuse_limiter.py::test_gcra_burst",
        "POST /admin/api/v1/protection/pause",
        "PATCH /admin/api/v1/upstream-limits/{bucket_key}",
        "/admin/upstream#cooldowns",
        "GET /internal/ready",
        "allowed_requests_per_minute",
        "/etc/roxy/credentials/roblox_credential",
        "roxyctl pause --reason now",
        "Roxy-Request-Id",
    ):
        checker.span("example", real)
    assert checker.problems == []
