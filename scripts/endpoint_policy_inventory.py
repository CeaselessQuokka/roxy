"""Build or refresh the Roblox endpoint inventory behind the endpoint policy (docs/endpoint_policy/BRIEF.md).

What this is
    A standalone tool, not part of the running service. It reads Roblox's published OpenAPI document (the file the
    Creator Hub "Cloud API reference" pages are rendered from, `content/en-us/reference/cloud/openapi.json` in the
    public GitHub repository Roblox/creator-docs) and prints, for every operation, the host, method, path, summary,
    which sign-in kinds Roblox accepts, and the two documentation links.

Why it exists
    The endpoint policy seed (`docs/endpoint_policy/endpoint_policy_seed.json`) holds one reviewed verdict per
    operation. Roblox adds, renames and retires endpoints; this tool finds the drift so a human (or an LLM following
    BRIEF.md section 9) reviews only what changed instead of all 992 rows again.

How it works
    `python3 -I scripts/endpoint_policy_inventory.py <openapi.json> --seed <seed>` (the seed is
    `docs/endpoint_policy/endpoint_policy_seed.json`) prints three lists: operations in the spec and missing from
    the seed (review these), seed rows the spec no longer has (retire these), and rows whose Roblox sign-in kind
    changed (re-check these). `--out <file>` also writes the
    full inventory as JSON. Run with `-I` and keep the downloaded spec in its own folder: it is untrusted data.
    `roblox_auth` values: `cookie-required` (only a .ROBLOSECURITY cookie works), `cookie-optional` (works without a
    sign-in, a cookie changes the answer), `none` (no sign-in listed), `apikey/oauth-only` (Open Cloud key or OAuth
    only, so Roxy can never serve it).

What to read next
    docs/endpoint_policy/BRIEF.md, then scripts/gen_endpoint_catalog.py.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

METHODS = ("get", "post", "put", "patch", "delete")
DOCS_DOMAIN = "https://create.roblox.com/docs/cloud/reference/domains/"


def auth_mode(security: list[dict] | None) -> tuple[str, list[str]]:
    schemes: set[str] = set()
    anon = not security
    for entry in security or []:
        if not entry:
            anon = True
        schemes |= set(entry)
    cookie = "roblox-legacy-cookie" in schemes
    if cookie:
        return ("cookie-optional" if anon else "cookie-required"), sorted(schemes)
    if not schemes:
        return "none", []
    return ("apikey-optional" if anon else "apikey/oauth-only"), sorted(schemes)


def endpoint_id(host: str, method: str, path: str) -> str:
    return f"{host.split('.')[0]}:{method}:{path}"


def inventory(spec: dict) -> list[dict]:
    rows = []
    default_server = spec["servers"][0]["url"]
    for spec_key, ops in spec["paths"].items():
        # Roblox's merged document disambiguates paths that several hosts share with a "#<host>" suffix
        # (for example "/v1/metadata#auth.roblox.com"); the real path is the part before "#".
        path = spec_key.split("#", 1)[0]
        for method, op in ops.items():
            if method not in METHODS or not isinstance(op, dict):
                continue
            server = (op.get("servers") or ops.get("servers") or [{"url": default_server}])[0]["url"]
            host = server.replace("https://", "").rstrip("/")
            mode, schemes = auth_mode(op.get("security", spec.get("security")))
            feature_doc = (op.get("externalDocs") or {}).get("url")
            anchor = feature_doc.split("#", 1)[1] if feature_doc and "#" in feature_doc else ""
            rows.append(
                {
                    "id": endpoint_id(host, method.upper(), path),
                    "host": host,
                    "method": method.upper(),
                    "path": path,
                    "spec_key": spec_key,
                    "summary": (op.get("summary") or "").strip(),
                    "description": re.sub(r"\s+", " ", op.get("description") or "")[:600],
                    "roblox_auth": mode,
                    "schemes": schemes,
                    "scopes": [s.get("name") for s in op.get("x-roblox-scopes", [])],
                    "stability": op.get("x-roblox-stability"),
                    "deprecated": bool(op.get("deprecated") or op.get("x-roblox-deprecated")),
                    "feature_doc": feature_doc,
                    "domain_doc": DOCS_DOMAIN + host.split(".")[0] + (f"#{anchor}" if anchor else ""),
                }
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("spec", type=Path)
    parser.add_argument("--seed", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    rows = inventory(json.loads(args.spec.read_text(encoding="utf-8")))
    print(f"{len(rows)} operations on {len({r['host'] for r in rows})} hosts")
    if args.out:
        args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    if args.seed:
        seed = {r["id"]: r for r in json.loads(args.seed.read_text(encoding="utf-8"))["endpoints"]}
        spec_ids = {r["id"]: r for r in rows}
        added = sorted(set(spec_ids) - set(seed))
        removed = sorted(set(seed) - set(spec_ids))
        changed = sorted(i for i in set(seed) & set(spec_ids) if seed[i]["roblox_auth"] != spec_ids[i]["roblox_auth"])
        for title, ids in (
            ("New in the spec (review)", added),
            ("Gone from the spec (retire)", removed),
            ("Sign-in kind changed (re-check)", changed),
        ):
            print(f"\n{title}: {len(ids)}")
            for i in ids:
                print("  " + i)
    return 0


if __name__ == "__main__":
    sys.exit(main())
