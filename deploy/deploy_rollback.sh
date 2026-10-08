#!/bin/bash
# deploy_rollback.sh [<sha>]: switch Roxy back to the previous release (or to the named release) on demand.
#
# What this is
#   The on-demand rollback of plan 17.4, run on the server as the deploy user: `/opt/roxy/deploy_rollback.sh`.
#   Without an argument it goes back to the release the idle color last ran (the one the previous deploy
#   replaced); with a commit it goes to that release, which must still be in /opt/roxy/releases (the newest 5 are
#   kept).
#
# Why it exists
#   A deploy can pass every gate and still be wrong (a behavior change noticed an hour later). The previous
#   release is still built and its color is only stopped, so going back is a blue/green switch in the other
#   direction: no fetch, no build, no downtime.
#
# How it works
#   It runs deploy.sh in rollback mode, which reuses the same steps and the same safety net: the lock, start the
#   idle color on the target release, the health gate and smoke test, switch nginx, watch, stop the other color,
#   record the result. Migrations are not undone: expand migrations are backward compatible, so the older code
#   runs on the newer schema (its pre-start step finds nothing to apply). Low-memory options are passed through.
#
# What to read next
#   deploy/deploy.sh (the steps), then deploy/README.md (restoring a backup, if a schema change itself must go).

if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -Eeuo pipefail

# deploy.sh sits next to this file both in the repository (deploy/) and on the server (/opt/roxy/).
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/deploy.sh" --rollback "$@"
