"""Egress: every network path a Roblox request can leave this server by, and the guards around them.

What this is
    The package that owns Roxy's outgoing HTTP: three client kinds (`direct` from the server IP without the
    credential, `credential` from the server IP with the one Roblox cookie, `rotator` through DataImpulse without
    it), the leak guard that sits under the anonymous clients, the header profiles, byte metering, usage
    accounting, and `EgressClients`, the one object the upstream layer talks to (`ctx.egress`, DESIGN.md 11.4).

Why it exists
    Plan C1 and C2 are the two rules that may never break: exactly one credential, and the credential never goes
    through the rotator (nor out of the direct path). Putting every outgoing byte behind one package means the
    rules can be enforced in layers in one place (type separation, `trust_env=False`, no proxy on the credential
    client, a guard transport that inspects the final request) and tested in one place (tests 19.5).

How it works
    `clients.py` builds the three clients and `EgressClients.send(egress, request)`. `credential.py` is the only
    module that reads the Roblox credential; it hands the guard an opaque `LeakMatcher` and puts the cookie on a
    request itself. `guard.py` refuses any anonymous request that carries the credential (and disables that egress
    fleet-wide) or a public auth marker (refused, counted, egress stays on). `rotator.py` manages DataImpulse
    sessions, the rotator URL, exit IPs and the byte budget; `metering.py` counts wire bytes below TLS;
    `accounting.py` hands per-request usage to the metrics recorder; `headers.py` builds API-shaped headers.
    The package `__init__` imports nothing, so importing one submodule never drags in the others.

What to read next
    `roxy/egress/clients.py` (the entry point and the test-only upstream override), then
    `roxy/egress/credential.py` and `roxy/egress/guard.py`.
"""
