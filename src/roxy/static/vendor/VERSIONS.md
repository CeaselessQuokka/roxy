# Vendored front-end libraries

The dashboard loads no script or style from another origin (plan 9.2 `default-src 'none'`, plan 14.10 "all
libraries vendored into `static/vendor/` with recorded versions and SRI hashes"). Every file below is byte for byte
the file inside the npm registry tarball of that exact version: the tarball was downloaded over HTTPS, its SHA-512
was checked against the registry's own `dist.integrity` before unpacking, and the file was copied unchanged.

The SRI column is what the browser checks: `templates/admin/base.html` puts each module's hash in the import map's
`integrity` section (and the stylesheet's on its `<link>`), so a file changed on the server is refused by the browser
(tests/e2e/test_csp_spike.py proves a wrong hash blocks the module). `tests/unit/ui/test_ui_static.py` recomputes
every hash in this file from the files on disk and checks the templates carry the same values.

## Production (served from `/static/vendor/`)

| Library | Version | Published | License | File | Bytes | SRI (SHA-384, base64) |
|---|---|---|---|---|---|---|
| htmx | 2.0.11 | 2026-09-22 | 0BSD | `htmx-2.0.11/htmx.esm.js` | 171382 | `sha384-MGpLJI+YdNF+gTEwPJkKrb2WL70Ce3qnYw+YP2Hy3U+AX6oRl45HdZa9/W/7ROZr` |
| Alpine.js, CSP build (`@alpinejs/csp`) | 3.17.4 | 2026-09-21 | MIT | `alpine-csp-3.17.4/module.esm.min.js` | 72182 | `sha384-1iUT5Gr1H+nzOhvZHzMtH1F8+Hn/P6+jPCmpGGd++NA0IS5o7zN7GzlQsckdJqMa` |
| uPlot | 1.6.32 | 2025-03-14 | MIT | `uplot-1.6.32/uPlot.esm.js` | 145423 | `sha384-iUdBlEO5qc07+gOz+3rq/Besyud+KVIxM+xJEuUBObxLG3C/Dlkz8OYuPUcPrCGP` |
| uPlot stylesheet | 1.6.32 | 2025-03-14 | MIT | `uplot-1.6.32/uPlot.min.css` | 1857 | `sha384-IfV0B7MIOYuO95kO9G5ySKPz/85zqFNOAs8iy4tkK5zd9izhJAB8b7lHrwYqqmYE` |

## Test only (`tests/e2e/vendor/`, never served)

| Library | Version | Published | License | File | Bytes | SRI (SHA-384, base64) |
|---|---|---|---|---|---|---|
| axe-core | 4.13.0 | 2026-08-05 | MPL-2.0 | `axe-core-4.13.0/axe.min.js` | 580491 | `sha384-jzJDdyy7z7+/I7TeoAg0Gc8k9hD8b1xRN0W18hMptWJ0cdoiebywhPpCyP9eBOgn` |

## Registry tarballs (checked before unpacking)

| Package | Tarball | `dist.integrity` from registry.npmjs.org |
|---|---|---|
| `htmx.org@2.0.11` | `https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.11.tgz` | `sha512-Thx/WtpeOQqSrqBCw/A1cwGJGg4UrVa3+sW0GmrM3p4gJgO89ecH4qtbnyzDDWFvBTqjnIMCgELTNt636dtamA==` |
| `@alpinejs/csp@3.17.4` | `https://registry.npmjs.org/@alpinejs/csp/-/csp-3.17.4.tgz` | `sha512-SlRXmqO6kYhnxlg+99etmuzJtE9Lk4QbKjBHqerXzaMflJqoJXdz/SI3IvHJGZ/vRVyC3bR0SSBz40oY7goBeg==` |
| `uplot@1.6.32` | `https://registry.npmjs.org/uplot/-/uplot-1.6.32.tgz` | `sha512-KIMVnG68zvu5XXUbC4LQEPnhwOxBuLyW1AHtpm6IKTXImkbLgkMy+jabjLgSLMasNuGGzQm/ep3tOkyTxpiQIw==` |
| `axe-core@4.13.0` | `https://registry.npmjs.org/axe-core/-/axe-core-4.13.0.tgz` | `sha512-UzGt8zg7Ny8djbYMhxl2zuEevVa7r2gJjYY5Lwr1xM7+XU2nd6CkIWFTVcCIbAP63vSz71NaVyyuSk9lHKcy0A==` |

## Choices

- **Versions.** The newest stable release at least two weeks old on 2026-10-07. htmx 4.0.0 is published under the
  registry's `next` tag (a rewrite), so the 2.x line stays; axe-core 4.14.0 was two days old, so 4.13.0.
- **Module builds.** Every library is an ES module so the dashboard needs exactly one `<script type="module">` with
  the response nonce; modules it imports are trusted through `'strict-dynamic'` and pinned by the import map. htmx
  ships its module build unminified (`htmx.esm.js`; its minified file is a classic script that sets a global, which
  a module cannot do); nginx compresses it on the wire.
- **License texts.** `htmx-2.0.11/LICENSE` and `uplot-1.6.32/LICENSE` are the files from the tarballs. The
  `@alpinejs/csp` tarball has no license file; its `package.json` declares MIT (Copyright Caleb Porzio). axe-core's
  MPL-2.0 text is in `tests/e2e/vendor/axe-core-4.13.0/LICENSE`.
- **Writing style.** These files are third-party code kept byte-identical (their hashes are pinned), so they are
  not rewritten to the plan C5 style rules. htmx uses the British spelling of "canceled" (double l) as a property
  name and has one em dash in a comment; axe-core has a few dashes and British spellings in its rule texts. The
  style checker therefore has to skip `src/roxy/static/vendor/` and `tests/e2e/vendor/`, like `tests/fixtures/v1`.

## Upgrading

1. Pick the version, then download the tarball and compare its SHA-512 with `dist.integrity` from
   `https://registry.npmjs.org/<package>` (the `.remake/scripts/p11_vendor_fetch.sh` steps).
2. Copy the files into a new versioned directory, delete the old one, and update this file, the hashes in
   `templates/admin/base.html` (and `tests/e2e/spike/spike.html`), then run the unit and e2e tests: the CSP spike
   must still show zero violations.
