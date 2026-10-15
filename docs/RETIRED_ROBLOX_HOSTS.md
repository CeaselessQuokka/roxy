# Retired Roblox hosts

Roblox web API hosts that Roxy once allowed and that Roblox has since shut down, kept here in memory of the services
they ran and so nobody adds them back by mistake. A host on this list is removed from Roxy's allowed host list
(`allowed_roblox_hosts`, the Upstream page) and from the list Roxy ships with
(`DEFAULT_ALLOWED_ROBLOX_HOSTS` in `src/roxy/config/settings/routing.py`).

How a host lands here: Check Proxy Health resolves every allowed host (H-DNS) and opens a TLS connection to it
(H-TLS). A host whose name no longer resolves fails both checks every time, and callers asking for it get errors
anyway. Confirm it from the server (`getent hosts <host>` prints nothing), remove it from the setting with a reason,
then add a row below.

| Host | What it served | Evidence it is gone | Removed from Roxy |
|---|---|---|---|
| `points.roblox.com` | Player Points: the points experiences could award to players (the Points API behind `PointsService`), which Roblox retired | The name no longer resolves (`getent hosts points.roblox.com` printed nothing on the production server, 2026-10-15); H-DNS and H-TLS failed on it in the first health run after the v2 cutover | 2026-10-15: the live setting (audited, reason recorded) and the shipped list |

Rest in peace.
