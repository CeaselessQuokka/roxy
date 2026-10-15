"""Build the content-hashed copies of Roxy's static files that nginx serves in production.

What this is
    `python scripts/build_static.py --out <release>/build/public` copies every file under `src/roxy/static/` to
    `<out>/static/<dir>/<name>.<hash>.<ext>` (the exact names `static_url()` puts into pages) and writes
    `<out>/static-manifest.json` mapping each logical name to its URL. deploy.sh runs it in step 2 with the
    release's own Python, right after `uv sync`.

Why it exists
    Plan 17.2 has nginx serve `/static/` from the active release with a one-year `immutable` cache. The app's
    templates link assets by content hash (`roxy/core/templating.py`, parity row 18), so the hashed names must
    exist as files for nginx. Using the app's own `AssetHasher` means the names here can never drift from the
    names in the pages. A name that is missing (a page from the previous release asking for an old hash during a
    switch) falls back to the app through nginx's `try_files`, and the app answers with `no-cache`, so an old
    hash is never cached forever with new content.

How it works
    Walk the static directory (skipping hidden files and symlinks), ask the hasher for each file's hashed name,
    copy the bytes with mode 0644, and replace the output's `static/` directory as a whole so a rebuild never
    leaves stale files behind. An empty or missing static directory produces an empty manifest (the dashboard
    assets arrive in phase P11). The manifest also tells scripts/smoke_remote.py which asset to fetch.

What to read next
    `src/roxy/core/templating.py` (the hash rule), `deploy/nginx/roxy.conf.template` (the /static/ location), then
    `scripts/smoke_remote.py`.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from roxy.core.templating import STATIC_DIR, STATIC_URL_PREFIX, AssetHasher

MANIFEST_NAME = "static-manifest.json"


def build(static_dir: Path, out_dir: Path) -> dict[str, str]:
    """Copy every static file to its hashed name under `out_dir/static`. Returns {logical name: URL}."""
    hasher = AssetHasher(static_dir, url_prefix=STATIC_URL_PREFIX)
    target_root = out_dir / "static"
    staging = out_dir / ".static.tmp"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    manifest: dict[str, str] = {}
    if static_dir.is_dir():
        for path in sorted(static_dir.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            logical = path.relative_to(static_dir).as_posix()
            if any(part.startswith(".") for part in logical.split("/")):
                continue  # editor and OS leftovers are never published
            hashed = hasher.hashed_name(logical)
            destination = staging / hashed
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            destination.chmod(0o644)
            manifest[logical] = hasher.url(logical)
    if target_root.exists():
        shutil.rmtree(target_root)
    staging.rename(target_root)
    (out_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write content-hashed static files for nginx (plan 17.2).")
    parser.add_argument("--out", required=True, type=Path, help="output directory (the release's build/public)")
    parser.add_argument("--static-dir", type=Path, default=STATIC_DIR, help="source directory (default: the app's)")
    args = parser.parse_args(argv)
    manifest = build(args.static_dir, args.out)
    print(f"build_static: {len(manifest)} file(s) written to {args.out / 'static'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
