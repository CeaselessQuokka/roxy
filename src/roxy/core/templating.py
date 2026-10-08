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
    The hash is the first 10 hex characters of the file's SHA-256, computed on first use and cached per
    (path, modification time, size), so a release (whose files never change) hashes each asset once per worker,
    and development edits are picked up immediately. `HashedStaticFiles` strips the hash from the requested name,
    serves the real file, and marks it `immutable` only when the hash matches the current content; an old hash
    (a page from the previous release during a blue/green switch) still gets the file, but with `no-cache`.
    In production nginx serves `/static/` directly (plan 17.2); this mount is the same contract for development
    and tests.

What to read next
    `roxy/core/security_headers.py` (where the nonce comes from), then `roxy/templates/base.html`.
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import jinja2
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from roxy.core.security_headers import get_nonce

PACKAGE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"
STATIC_URL_PREFIX = "/static"

HASH_LENGTH = 10
IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
REVALIDATE_CACHE = "no-cache"
_MAX_CACHED_ASSETS = 5000
_HASHED_NAME = re.compile(rf"^(?P<base>.+)\.(?P<hash>[0-9a-f]{{{HASH_LENGTH}}})(?P<ext>\.[A-Za-z0-9]+)?$")


def _clean_logical(path: str) -> str | None:
    """Normalize an asset path like `css/app.css`; None when it tries to leave the static directory."""
    parts = PurePosixPath(path.replace("\\", "/").lstrip("/")).parts
    if not parts or any(part in ("..", ".") for part in parts):
        return None
    return "/".join(parts)


class AssetHasher:
    """Content hashes for files under one static directory, cached and bounded."""

    def __init__(self, static_dir: Path, *, url_prefix: str = STATIC_URL_PREFIX) -> None:
        self.static_dir = static_dir
        self.url_prefix = url_prefix.rstrip("/")
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[int, int, str]] = {}  # logical path -> (mtime_ns, size, hash)

    def file_hash(self, logical: str) -> str | None:
        """The content hash of an asset, or None when the file does not exist."""
        clean = _clean_logical(logical)
        if clean is None:
            return None
        path = self.static_dir / clean
        try:
            stat = path.stat()
        except OSError:
            return None
        cached = self._cache.get(clean)
        if cached is not None and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
            return cached[2]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:HASH_LENGTH]
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
        logical, immutable = self.hasher.resolve(path)
        response = await super().get_response(logical, scope)
        if response.status_code in (200, 304):
            response.headers["cache-control"] = IMMUTABLE_CACHE if immutable else REVALIDATE_CACHE
        return response


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
        )
        self.env.globals["static_url"] = self.hasher.url
        if extra_globals:
            self.env.globals.update(extra_globals)

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
