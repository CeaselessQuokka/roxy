"""Templating tests: autoescape, the nonce in templates, content-hashed static URLs and their cache headers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import jinja2
from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.core.templating import IMMUTABLE_CACHE, REVALIDATE_CACHE, AssetHasher, HashedStaticFiles, Templates


def make_static(tmp_path: Path) -> Path:
    static = tmp_path / "static"
    (static / "css").mkdir(parents=True)
    (static / "css" / "app.css").write_text("body { color: black; }\n", encoding="utf-8")
    (static / "LICENSE").write_text("no extension\n", encoding="utf-8")
    return static


def test_static_url_uses_content_hash(tmp_path: Path) -> None:
    static = make_static(tmp_path)
    hasher = AssetHasher(static)
    digest = hashlib.sha256((static / "css" / "app.css").read_bytes()).hexdigest()[:10]
    assert hasher.url("css/app.css") == f"/static/css/app.{digest}.css"
    assert hasher.url("/css/app.css") == f"/static/css/app.{digest}.css"
    assert hasher.url("LICENSE").startswith("/static/LICENSE.")
    assert hasher.url("missing.js") == "/static/missing.js"


def test_hash_changes_with_content_not_with_time(tmp_path: Path) -> None:
    static = make_static(tmp_path)
    hasher = AssetHasher(static)
    first = hasher.url("css/app.css")
    (static / "css" / "app.css").write_text("body { color: black; }\n", encoding="utf-8")  # same bytes
    assert hasher.url("css/app.css") == first
    (static / "css" / "app.css").write_text("body { color: navy; }\n", encoding="utf-8")
    assert hasher.url("css/app.css") != first


def test_resolve_maps_hashed_names_back(tmp_path: Path) -> None:
    static = make_static(tmp_path)
    hasher = AssetHasher(static)
    hashed = hasher.hashed_name("css/app.css")
    assert hasher.resolve(hashed) == ("css/app.css", True)
    assert hasher.resolve("css/app.0123456789.css") == ("css/app.css", False)  # stale hash, same file
    assert hasher.resolve("css/app.css") == ("css/app.css", False)
    assert hasher.resolve("../secrets.txt") == ("../secrets.txt", False)


async def test_hashed_static_files_cache_headers(tmp_path: Path, client_for: Any) -> None:
    from fastapi import FastAPI

    static = make_static(tmp_path)
    hasher = AssetHasher(static)
    app = FastAPI()
    app.mount("/static", HashedStaticFiles(directory=static, hasher=hasher))
    async with client_for(app) as client:
        fresh = await client.get(hasher.url("css/app.css"))
        stale = await client.get("/static/css/app.0123456789.css")
        plain = await client.get("/static/css/app.css")
        missing = await client.get("/static/css/none.css")
    assert fresh.status_code == 200
    assert fresh.text == "body { color: black; }\n"
    assert fresh.headers["cache-control"] == IMMUTABLE_CACHE
    assert stale.status_code == 200
    assert stale.headers["cache-control"] == REVALIDATE_CACHE
    assert plain.headers["cache-control"] == REVALIDATE_CACHE
    assert missing.status_code == 404


async def test_templates_autoescape_and_nonce(tmp_path: Path, make_app: Any, client_for: Any) -> None:
    static = make_static(tmp_path)
    loader = jinja2.DictLoader(
        {
            "page.html": (
                '<style nonce="{{ csp_nonce }}">p{}</style><link href="{{ static_url(\'css/app.css\') }}">'
                "<p>{{ user_agent }}</p>"
            )
        }
    )
    templates = Templates(hasher=AssetHasher(static), loader=loader)
    app = make_app()

    @app.get("/page", response_class=HTMLResponse)
    async def page(request: Request) -> HTMLResponse:
        return templates.render(request, "page.html", {"user_agent": "<script>alert(1)</script>"})

    async with client_for(app) as client:
        response = await client.get("/page")
    assert "<script>" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    csp = response.headers["content-security-policy"]
    nonce = response.text.split('nonce="', 1)[1].split('"', 1)[0]
    assert f"'nonce-{nonce}'" in csp
    assert "/static/css/app." in response.text
