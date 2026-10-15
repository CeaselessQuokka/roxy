"""Templating: the Jinja2 environment (autoescape always on), the CSP nonce in every page, and hashed asset URLs.

What this is
    `Templates.render(request, name, context)` renders a page into an `HTMLResponse`, with `request`, `csp_nonce`
    and `static_url()` available inside every template. `AssetHasher` turns `static_url("css/app.css")` into
    `/static/css/app.<hash>.css`, and `HashedStaticFiles` serves those names back with a one-year immutable cache.

Why it exists
    Three security and correctness rules meet here. Autoescape on everywhere (plan 9.16): the dashboard shows
    attacker-controlled text, and an unescaped `<` is a script injection. The nonce (plan 9.2): a page's `<script>`
    and `<style>` tags only run if they carry this response's nonce, so every template needs it. Cache busting
    (parity row 18): v1 appended `?v=<mtime>`, which changes on every deploy even when the file did not, and can
    collide when two files change in the same second. A hash of the file CONTENT changes exactly when the content
    does, so browsers can cache an asset forever (`immutable`) and still never run stale code after a deploy.

How it works
    - Hashes: the first 10 hex characters of the file's SHA-256. `HashedStaticFiles` strips the hash from the
      requested name, serves the real file, and marks it `immutable` only when the hash matches the current
      content; an old hash (a page from the previous release during a blue/green switch) still gets the file, but
      with `no-cache`. In production nginx serves `/static/` directly (plan 17.2); this mount is the same contract
      for development and tests, and the fallback nginx uses for a name a release does not have.
    - Nothing touches the disk while a page renders. A request is answered on the event loop, and one blocking
      `stat` or `open` there stalls every request of the worker (the proxy's included) for as long as the disk
      does, which on a stalled disk is the whole worker (the `/health` finding LOOP-2, same rule). So:
      `Templates.warm(names)` (run on a thread at startup by the public pages' lifespan, `public/pages.py`, for
      the public and sign-in templates anyone on the internet can reach) compiles those templates and calls
      `AssetHasher.freeze()`, which hashes every file under the static directory once; after that, rendering
      them, `static_url()` and resolving a hashed name read memory only. The Jinja environment runs with
      `auto_reload=False`: its default checks each template's modification time (a `stat`) on every render, for a
      file that only changes with a release, and a release starts new workers. Any other template (the admin
      dashboard, behind its login) is read once, on its first render in a worker, and never checked again.
    - Until `freeze()` runs (scripts, unit tests, an app whose lifespan did not run) `AssetHasher` hashes on use
      and caches per (path, modification time, size), so an edited file gets a new hash at once.
    - Development: a template or asset edit shows after a restart (for example `uvicorn --reload` with
      `--reload-include "*.html"`, `"*.css"` and `"*.js"`), the same as in a release.

What to read next
    `roxy/core/security_headers.py` (where the nonce comes from), then `roxy/templates/public/base.html` and
    `roxy/public/pages.py` (`load_public_content`, which warms all of this at startup).
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

import jinja2
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from roxy.core.security_headers import get_nonce

log = logging.getLogger("roxy.core.templating")

PACKAGE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"
STATIC_URL_PREFIX = "/static"

HASH_LENGTH = 10
IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
REVALIDATE_CACHE = "no-cache"
_MAX_CACHED_ASSETS = 5000
"""Most asset hashes kept in memory (plan P9). A static directory with more files than this is not frozen: its
hashes stay computed on use (the shipped directory holds a few dozen files)."""
_HASHED_NAME = re.compile(rf"^(?P<base>.+)\.(?P<hash>[0-9a-f]{{{HASH_LENGTH}}})(?P<ext>\.[A-Za-z0-9]+)?$")


def _clean_logical(path: str) -> str | None:
    """Normalize an asset path like `css/app.css`; None when it tries to leave the static directory."""
    parts = PurePosixPath(path.replace("\\", "/").lstrip("/")).parts
    if not parts or any(part in ("..", ".") for part in parts):
        return None
    return "/".join(parts)


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()[:HASH_LENGTH]


class AssetHasher:
    """Content hashes for files under one static directory, cached and bounded.

    Two modes. Live (the start): each lookup checks the file and re-hashes it when it changed, which suits
    scripts and tests. Frozen (after `freeze()`, which a served app runs once at startup on a thread): every hash
    was computed up front and lookups read memory only, so a page render never touches the disk.
    """

    def __init__(self, static_dir: Path, *, url_prefix: str = STATIC_URL_PREFIX) -> None:
        self.static_dir = static_dir
        self.url_prefix = url_prefix.rstrip("/")
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[int, int, str]] = {}  # logical path -> (mtime_ns, size, hash)
        self._frozen: Mapping[str, str] | None = None  # logical path -> hash, once frozen

    @property
    def frozen(self) -> bool:
        """True once `freeze()` has hashed every asset (lookups no longer touch the disk)."""
        return self._frozen is not None

    def freeze(self) -> int:
        """Hash every file under the static directory now and answer every later lookup from memory.

        Reads every asset, so it blocks: call it on a thread (`asyncio.to_thread`), once per process, before the
        first request. A file added or changed afterwards is not seen until the next process, which is how a
        release behaves anyway (its files never change). Returns how many files were hashed; 0 and a warning when
        the directory holds more than `_MAX_CACHED_ASSETS` files, in which case lookups stay live.
        """
        hashes: dict[str, str] = {}
        if self.static_dir.is_dir():
            for path in sorted(self.static_dir.rglob("*")):
                if not path.is_file():
                    continue
                if len(hashes) >= _MAX_CACHED_ASSETS:
                    log.warning("static_assets_not_frozen", extra={"fields": {"limit": _MAX_CACHED_ASSETS}})
                    return 0
                hashes[path.relative_to(self.static_dir).as_posix()] = _digest(path.read_bytes())
        self._frozen = MappingProxyType(hashes)  # one reference swap: a reader sees the old mode or the new one
        return len(hashes)

    def file_hash(self, logical: str) -> str | None:
        """The content hash of an asset, or None when the file does not exist."""
        clean = _clean_logical(logical)
        if clean is None:
            return None
        frozen = self._frozen
        if frozen is not None:
            return frozen.get(clean)  # memory only: no stat, no read
        path = self.static_dir / clean
        try:
            stat = path.stat()
        except OSError:
            return None
        cached = self._cache.get(clean)
        if cached is not None and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
            return cached[2]
        digest = _digest(path.read_bytes())
        with self._lock:
            if len(self._cache) >= _MAX_CACHED_ASSETS and clean not in self._cache:
                self._cache.clear()  # bounded (plan P9): a reset only costs re-hashing on next use
            self._cache[clean] = (stat.st_mtime_ns, stat.st_size, digest)
        return digest

    def hashed_name(self, logical: str) -> str:
        """`css/app.css` -> `css/app.<hash>.css` (or the name unchanged when the file is missing)."""
        clean = _clean_logical(logical) or logical
        digest = self.file_hash(clean)
        if digest is None:
            return clean
        directory, _, filename = clean.rpartition("/")
        stem, dot, ext = filename.rpartition(".")
        hashed = f"{stem}.{digest}.{ext}" if dot and stem else f"{filename}.{digest}"
        return f"{directory}/{hashed}" if directory else hashed

    def url(self, logical: str) -> str:
        """The URL a template should use for an asset: `/static/<dir>/<name>.<hash>.<ext>`."""
        return f"{self.url_prefix}/{self.hashed_name(logical)}"

    def resolve(self, requested: str) -> tuple[str, bool]:
        """Map a requested (maybe hashed) name back to the real file: (logical path, hash matches content)."""
        clean = _clean_logical(requested)
        if clean is None:
            return requested, False
        directory, _, filename = clean.rpartition("/")
        match = _HASHED_NAME.match(filename)
        if match is None:
            return clean, False
        original = match.group("base") + (match.group("ext") or "")
        logical = f"{directory}/{original}" if directory else original
        current = self.file_hash(logical)
        if current is None:
            return clean, False  # not a hashed name after all (a real file can contain a dot and hex)
        return logical, current == match.group("hash")


class HashedStaticFiles(StaticFiles):
    """`StaticFiles` that understands content-hashed names and sets the matching cache headers."""

    def __init__(self, *, directory: Path, hasher: AssetHasher) -> None:
        super().__init__(directory=directory, check_dir=False)
        self.hasher = hasher

    async def get_response(self, path: str, scope: Scope) -> Response:
        # Memory only once the hasher is frozen; Starlette then finds and sends the file on worker threads.
        logical, immutable = self.hasher.resolve(path)
        response = await super().get_response(logical, scope)
        if response.status_code in (200, 304):
            response.headers["cache-control"] = IMMUTABLE_CACHE if immutable else REVALIDATE_CACHE
        return response


TEMPLATE_SUFFIXES = (".html",)
"""What `Templates.warm()` compiles when no names are given: the page templates (not the `.txt` and `.luau` data
files kept next to them)."""


def admin_nav() -> Any:
    """The dashboard navigation (pages, groups, icons, shortcuts) from the page registry, for the admin layout.

    A Jinja global, so the sidebar, the phone menu, the palette and the shortcut overlay read the one registry
    (`roxy/admin/pages/registry.py`) whatever context a page passes. Imported on first use: the registry is plain
    data (no routes, no database), and only admin templates call it.
    """
    from roxy.admin.pages.registry import nav_model

    return nav_model()


class Templates:
    """The Jinja2 environment with Roxy's rules: autoescape everywhere, nonce and `static_url` in every page."""

    def __init__(
        self,
        directories: Sequence[Path] = (TEMPLATES_DIR,),
        *,
        hasher: AssetHasher | None = None,
        extra_globals: Mapping[str, Any] | None = None,
        loader: jinja2.BaseLoader | None = None,
    ) -> None:
        self.hasher = hasher or AssetHasher(STATIC_DIR)
        self.env = jinja2.Environment(
            loader=loader or jinja2.FileSystemLoader([str(d) for d in directories]),
            # Always on, for every extension: there is no template in Roxy where raw HTML from data is wanted.
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
            # A compiled template is reused without asking the disk whether its file changed. The default (True)
            # costs a stat per template (and per `extends` parent) on every render, on the event loop, for files
            # that only change with a release. The cache holds 400 templates (Jinja's bound); Roxy has about 40.
            auto_reload=False,
        )
        self.env.globals["static_url"] = self.hasher.url
        self.env.globals["admin_nav"] = admin_nav
        if extra_globals:
            self.env.globals.update(extra_globals)

    def page_templates(self, prefixes: Sequence[str] = ("",)) -> list[str]:
        """The page templates (`TEMPLATE_SUFFIXES`) the loader lists under any of `prefixes` (`"public/"`...).

        Blocking (a loader lists files): call it on a thread. Empty for a loader that cannot list its templates.
        """
        try:
            listed = self.env.list_templates()
        except TypeError:  # a loader that cannot list its templates (Jinja raises TypeError)
            return []
        return [name for name in listed if name.endswith(TEMPLATE_SUFFIXES) and name.startswith(tuple(prefixes))]

    def warm(self, names: Iterable[str] | None = None) -> int:
        """Compile templates into the cache and freeze the asset hashes, so later renders never touch the disk.

        Blocking (it reads files): call it on a thread at startup (`asyncio.to_thread(templates.warm, names)`).
        Without `names` it compiles every page template (`page_templates()`). A template that does not compile is
        logged and skipped, never raised: rendering it raises the same error on the page that uses it, where that
        page's own tests see it, instead of stopping every worker. Returns how many templates compiled. Compiling
        is the costly part (about 4 ms a template, 160 ms for all of them); hashing every asset takes about 2 ms.
        """
        wanted = self.page_templates() if names is None else list(names)
        compiled = 0
        for name in wanted:
            try:
                self.env.get_template(name)
            except jinja2.TemplateError as exc:
                log.warning("template_warm_failed", extra={"fields": {"template": name, "error": type(exc).__name__}})
                continue
            compiled += 1
        self.hasher.freeze()
        return compiled

    def render_to_string(self, request: Request, name: str, context: Mapping[str, Any] | None = None) -> str:
        """Render a template to text with `request` and `csp_nonce` in its context."""
        values: dict[str, Any] = {"request": request, "csp_nonce": get_nonce(request.scope)}
        if context:
            values.update(context)
        return self.env.get_template(name).render(values)

    def render(
        self,
        request: Request,
        name: str,
        context: Mapping[str, Any] | None = None,
        *,
        status_code: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> HTMLResponse:
        """Render a page into an `HTMLResponse` (the security headers middleware adds the matching CSP)."""
        return HTMLResponse(self.render_to_string(request, name, context), status_code=status_code, headers=headers)
