"""Temporary probe (deleted after use): prints public page weights, raw and gzip."""

import gzip
import re

import httpx


async def test_probe(client: httpx.AsyncClient) -> None:
    for path in ("/", "/docs", "/status"):
        response = await client.get(path)
        html = response.content
        assets = re.findall(r'(?:href|src)="(/static/public/site\.[0-9a-f]+\.(?:css|js))"', response.text)
        total = len(html)
        total_gz = len(gzip.compress(html, 6))
        for asset in assets:
            body = (await client.get(asset)).content
            total += len(body)
            total_gz += len(gzip.compress(body, 6))
        print(f"WEIGHT {path}: html={len(html)} total={total} gzip_total={total_gz}")
        if path == "/docs" or path == "/":
            name = "docs" if path == "/docs" else "home"
            with open(f"/tmp/roxy_{name}.html", "wb") as handle:
                handle.write(html)
