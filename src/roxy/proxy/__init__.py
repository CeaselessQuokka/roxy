"""The proxy surface: the public `/<host>.roblox.com/<path>` route callers use.

What this is
    The package that receives every caller request to Roxy's proxy route and sends back the answer:
    `validate.py` (is this a safe Roblox URL?), `context.py` (the `ProxyRequest` every stage shares),
    `scrub.py` (which headers may cross in each direction), `respond.py` (the exact bytes and headers a caller
    receives) and `router.py` (the route and the request flow).

Why it exists
    v1 did all of this inside one 300-line view function, mixed with abuse checks, caching and upstream calls, so
    the safety rules (which host, which path, which headers) were hard to see and easy to bypass (v1 bugs B3, B4,
    B5, B17). Here each rule lives in one small module with its own tests, and the flow that strings them
    together is short enough to read in one sitting.

How it works
    The router builds a `ProxyRequest` from the raw request, asks the abuse pipeline for a verdict, asks the cache
    (which asks the upstream service on a miss) for a result, and hands either one to `respond.py`. The abuse,
    cache, upstream and metrics services are separate packages reached through `request.app.state.ctx`.

What to read next
    `roxy/proxy/router.py`, then `roxy/proxy/validate.py`.
"""
