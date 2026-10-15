"""The public site: everything a visitor or a crawler can open without signing in, apart from the proxy itself.

What this is
    The package behind Roxy's public pages (plan 16.1). `pages.py` serves the home page `/`, the user guide at
    `/docs` (rendered from `docs/USER_GUIDE.md`), the coarse status page `/status`, and the crawler files
    `/robots.txt`, `/sitemap.xml` and `/favicon.ico`. `csp_report.py` receives browser Content Security Policy
    reports at `POST /csp-report` (plan 9.2). `health.py` answers the monitor JSON at `/health` (parity row 14).

Why it exists
    v1 served its home page and crawler files from the same 2,000 line module as the proxy, with hard-coded limits
    ("10 requests every 50 seconds") and hosting facts that had gone stale. Keeping the public site in its own
    package makes three promises easy to check: every number a visitor reads comes from the live settings, the
    pages run under the strict nonce CSP with no third-party script or font, and nothing on them (status
    included) reveals internals such as counts or IP addresses.

How it works
    Each module exposes `router`; `roxy/main.py` includes them in a fixed order before the proxy catch-all, so a
    public path is never mistaken for a Roblox URL. Templates live in `roxy/templates/public/`, the stylesheet,
    script and icons in `roxy/static/public/`, and the guide text in `docs/USER_GUIDE.md` (found next to the
    installed package; a worker refuses to start without it). Visits are counted through the metrics recorder
    when it exists (the recorder classifies visitors and decides how to store them).

What to read next
    `roxy/public/pages.py` (the routes), then `roxy/templates/public/base.html` and `roxy/core/templating.py`
    (how the nonce and hashed asset URLs reach the pages), and `docs/USER_GUIDE.md`.
"""
