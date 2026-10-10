#!/bin/bash
# deploy.sh <sha>: zero downtime blue/green deploy of one exact commit, health gated, with automatic rollback.
#
# What this is
#   The server-side deploy (plan 17.4). GitHub Actions runs it over SSH as the unprivileged deploy user
#   (`/opt/roxy/deploy.sh <sha>`, see .github/workflows/deploy.yml); an operator can run it by hand the same way.
#   `deploy_rollback.sh` runs this file with --rollback to switch back to the previous release.
#
# Why it exists
#   v1's UpdateBuild.sh stopped the only copy of the site, rebuilt it in place, and when the new build did not come
#   up it left the site down (v1 notes, section 13.5). v2 builds the new release while the old one keeps serving,
#   starts it as the idle color, proves it healthy, switches nginx, watches it, and only then stops the old color.
#   Any failure before the old color stops puts everything back: nginx returns to the old color, the idle color
#   is stopped, and the run exits non-zero so the Action goes red and an alert goes out.
#
# How it works (the steps of plan 17.4; the step number is in every log line and in the failure alert)
#   1. Fetch exactly <sha> into /opt/roxy/releases/<sha>: a local mirror fetches the branch, the commit must be on
#      it, `git archive` exports the tree, required paths are checked, and a SHA-256 manifest of deploy/nginx/ is
#      recorded for the nginx wrapper (plan 9.14).
#   2. Build the release's own .venv with `uv python install 3.12` and `uv sync --frozen` (uv-managed Python under
#      /opt/roxy/python, never the system Python), and the content-hashed static files nginx serves.
#   3. Migrations: the expand migrations and the pre-migration snapshot of control.db run as the roxy user in
#      the idle color's pre-start step (deploy/prestart.py explains why the deploy user cannot run them itself).
#   4. Point current-<idle> at the release and restart roxy@<idle>. Below 700 MB of available memory (DESIGN.md
#      section 0) the idle color starts with one worker (low-memory mode).
#   5. Health gate: the idle color's internal socket must report Ready, PersistenceOK and Version=<sha> within
#      60 s, then scripts/smoke_remote.py checks the public pages on its port.
#   6. Install the nginx config through the root wrapper if it changed, then switch nginx to the idle color.
#   7. Watch the new color for 60 s: 12 checks 5 s apart, counted rather than timed by the wall clock (internal
#      readiness, and the public /health through nginx, which must be answered by Roxy v2 itself: during the
#      cutover v1's nginx site can still own the host name).
#   8. Drain, stop the old color and wait until it is inactive (its shutdown flushes metrics). In low-memory mode,
#      add workers to the new color through its gunicorn control socket. Keep the newest 5 releases by deploy order
#      (a sequence number each deploy or rollback writes into the release it starts, never file times).
#   9. Record the dependency audit of this commit in /var/lib/roxy-deploy/advisories.json (health check H-VERSION:
#      the count CI's pip-audit found, passed by the workflow as ROXY_ADVISORY_COUNT; "not recorded" when the deploy
#      was started by hand), record the commit in /var/lib/roxy-deploy/deployed_version (roxy-audit.path then runs
#      the permission audit) and install this release's deploy scripts as the new /opt/roxy/deploy.sh. A rollback
#      puts back the audit record its release was deployed with.
#   Safety: `set -Eeuo pipefail`; an ERR trap (inherited by functions and subshells through -E) records the
#   failing command, and an EXIT trap runs the rollback for ANY non-zero exit, including `set -u` errors and
#   signals, which an ERR trap alone misses (v1 bug: a failing command inside a function skipped its trap). The
#   rollback puts back everything this run changed before the old color stopped: nginx's color, the nginx config
#   (when this run installed a new one), the idle color and its release link. One flock means two deploys never
#   overlap; the second one exits at once without touching anything. Repository URLs are logged without any
#   user:password@ part, because the log reaches the Action log, last_failure.json and the alert email.
#   Privilege: the deploy user can only run `sudo systemctl start|stop|restart|reload roxy@<color>.service` and
#   the two root wrappers (deploy/sudoers/roxy-deploy). Every path and program can be overridden through ROXY_*
#   environment variables, which is how tests/deploy runs this file in a sandbox with stub commands.
#
# What to read next
#   deploy/prestart.py, scripts/smoke_remote.py, deploy/tools/roxy-switch-color, deploy/tools/roxy-nginx-apply, and
#   tests/deploy/test_deploy_sh.py (every scenario this script must survive).

# Re-run under bash when started as `sh deploy.sh` (dash knows no pipefail or arrays). This must come before
# any bash-only line, which is why it is the first command (v1 parity, deploy_test.sh scenario 6).
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

set -Eeuo pipefail
# Command substitutions inherit errexit too, so `x=$(failing)` stops the deploy.
shopt -s inherit_errexit
# Release files must be readable by the roxy user (0644 files, 0755 directories), and nothing group-writable.
umask 0022

# ------------------------------------------------------------------------------------------------ settings

ROXY_ROOT="${ROXY_ROOT:-/opt/roxy}"
RELEASES_DIR="${ROXY_RELEASES_DIR:-$ROXY_ROOT/releases}"
MIRROR_DIR="${ROXY_MIRROR_DIR:-$ROXY_ROOT/repo.git}"
DEPLOY_STATE_DIR="${ROXY_DEPLOY_STATE_DIR:-/var/lib/roxy-deploy}"
LOCK_FILE="$DEPLOY_STATE_DIR/lock"
ETC_DIR="${ROXY_ETC_DIR:-/etc/roxy}"
NGINX_DIR="${ROXY_NGINX_DIR:-/etc/nginx}"
ACTIVE_LINK="$NGINX_DIR/roxy-active-upstream.conf"
RUN_DIR_PREFIX="${ROXY_RUN_DIR_PREFIX:-/run/roxy-}"
NGINX_APPLIED="${ROXY_NGINX_APPLIED:-/var/lib/roxy-nginx-apply/applied.json}"
SYSTEMCTL="${ROXY_SYSTEMCTL:-/usr/bin/systemctl}"
NGINX_APPLY="${ROXY_NGINX_APPLY:-/usr/local/sbin/roxy-nginx-apply}"
SWITCH_COLOR="${ROXY_SWITCH_COLOR:-/usr/local/sbin/roxy-switch-color}"
CURL="${ROXY_CURL:-curl}"
PYTHON3="${ROXY_PYTHON3:-/usr/bin/python3}"
UV="${ROXY_UV:-$(command -v uv || echo "$HOME/.local/bin/uv")}"
PYTHON_VERSION="${ROXY_PYTHON_VERSION:-3.12}"
KEEP_RELEASES="${ROXY_KEEP_RELEASES:-5}"
HEALTH_TIMEOUT_S="${ROXY_HEALTH_TIMEOUT_S:-60}"
POLL_INTERVAL_S="${ROXY_POLL_INTERVAL_S:-1}"
WATCH_S="${ROXY_WATCH_S:-60}"
WATCH_INTERVAL_S="${ROXY_WATCH_INTERVAL_S:-5}"
WATCH_MAX_FAILURES="${ROXY_WATCH_MAX_FAILURES:-1}"
DRAIN_S="${ROXY_DRAIN_S:-5}"
STOP_TIMEOUT_S="${ROXY_STOP_TIMEOUT_S:-60}"
SCALE_TIMEOUT_S="${ROXY_SCALE_TIMEOUT_S:-60}"
LOW_MEMORY_MB="${ROXY_LOW_MEMORY_MB:-700}"
MEMINFO="${ROXY_MEMINFO:-/proc/meminfo}"
PUBLIC_CHECK="${ROXY_DEPLOY_PUBLIC_CHECK:-1}"
LOCK_WAIT_S="${ROXY_LOCK_WAIT_S:-0}"
# The dependency audit of this commit, from CI's pip-audit job (deploy.yml passes them; empty when run by hand):
# how many known advisories the locked dependencies have, how many of those have a fixed version, and their ids.
ADVISORY_COUNT="${ROXY_ADVISORY_COUNT:-}"
ADVISORY_FIXABLE="${ROXY_ADVISORY_FIXABLE:-}"
ADVISORY_IDS="${ROXY_ADVISORY_IDS:-}"

# uv: interpreters under /opt/roxy/python (the service cannot see /home, ProtectHome=yes), copies instead of
# links into the user cache, and never a system Python (plan 5.1).
export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-$ROXY_ROOT/python}"
export UV_LINK_MODE=copy
export UV_MANAGED_PYTHON=1
export UV_NO_PROGRESS=1

REQUIRED_PATHS=(pyproject.toml uv.lock src/roxy deploy/deploy.sh deploy/deploy_rollback.sh deploy/gunicorn.conf.py
  deploy/prestart.py deploy/nginx/roxy.conf.template scripts/smoke_remote.py scripts/build_static.py)
RELEASE_STAMP=".roxy-release-complete"
# The deploy order of a release: written by every deploy or rollback that starts it (mark_release_used).
RELEASE_SEQUENCE=".roxy-release-sequence"
NGINX_MANIFEST=".roxy-nginx-manifest"
# The audit record a release was deployed with, kept in the release so a rollback can put it back.
RELEASE_ADVISORIES=".roxy-advisories.json"

# ----------------------------------------------------------------------------------------------- run state

MODE=deploy
LOW_MEMORY=auto
FORCE_NGINX=0
SHA=""
STEP=0
LAST_ERROR=""
HANDLED=0
RELEASE=""
BUILT_NEW=0
ACTIVE_COLOR=""
IDLE_COLOR=""
PREV_IDLE_TARGET=""
IDLE_TOUCHED=0
SWITCHED=0
COMMITTED=0
LOW_MEMORY_MODE=0
# Set when this run installed its own nginx config, and the release whose config to put back on a failure.
NGINX_INSTALLED_NEW=0
NGINX_RESTORE_SHA=""
# Why the last public /health check failed, for the watch's log line and the failure record.
PUBLIC_PROBLEM=""

# --------------------------------------------------------------------------------------------- small tools

log() { printf '==> %s\n' "$*"; }
fail() { printf '!!! %s\n' "$*" >&2; }
step() {
  STEP="$1"
  shift
  log "Step $STEP: $*"
}
# Stop the deploy with a message. The EXIT trap does the rollback, so every failure takes the same path.
die() {
  LAST_ERROR="$*"
  fail "$*"
  exit 1
}

usage() {
  cat <<'EOF'
usage: deploy.sh [--low-memory | --no-low-memory] [--force-nginx] <40 character commit sha>
       deploy.sh --rollback [<sha of an existing release>]   (what deploy_rollback.sh runs)
EOF
}

# The last value of KEY in the given env files (later files win, like systemd's EnvironmentFile order).
env_value() {
  local key="$1" file value=""
  shift
  for file in "$@"; do
    [ -r "$file" ] || continue
    local found
    found="$(sed -n "s/^[[:space:]]*${key}=//p" "$file" | tail -n 1)"
    if [ -n "$found" ]; then value="$found"; fi
  done
  value="${value%\"}"
  value="${value#\"}"
  printf '%s' "$value"
}

# Read one field from a JSON document on stdin (system python3; jq is not installed by default).
json_field() {
  "$PYTHON3" -I -c '
import json, sys
try:
    value = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for key in sys.argv[1:]:
    value = value.get(key) if isinstance(value, dict) else None
if isinstance(value, bool):
    print("true" if value else "false")
elif value is not None:
    print(value)
' "$@"
}

# True when the JSON document on stdin is an object with the given key (whatever its value).
json_has_key() {
  "$PYTHON3" -I -c '
import json, sys
try:
    value = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(value, dict) and sys.argv[1] in value else 1)
' "$1"
}

# A URL as it may appear in a log line or a failure record: any user:password@ part is removed (a token in the
# repository URL must never reach the Action log, last_failure.json or the alert email). Greedy up to the last "@"
# before the first "/", so a password containing "@" goes too.
display_url() {
  printf '%s' "$1" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^/]*@#\1#'
}

# Write a file atomically (temporary file, then rename), readable by the roxy user and the alert unit.
write_file() {
  local target="$1" content="$2" tmp
  tmp="$(mktemp "$target.XXXXXX")"
  printf '%s\n' "$content" >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$target"
}

# Point a symlink at a target atomically (a new link renamed over the old one).
relink() {
  local link="$1" target="$2"
  ln -sfn "$target" "$link.new"
  mv -T -f "$link.new" "$link"
}

other_color() { if [ "$1" = blue ]; then echo green; else echo blue; fi; }

# The color the active upstream symlink points at, or nothing before the first deploy.
active_color() {
  local target
  target="$(readlink "$ACTIVE_LINK" 2>/dev/null || true)"
  case "$(basename "${target:-none}")" in
    roxy-upstream-blue.conf) echo blue ;;
    roxy-upstream-green.conf) echo green ;;
    *) echo "" ;;
  esac
}

internal_socket() {
  local color="$1" sock
  sock="$(env_value ROXY_INTERNAL_SOCKET "$ETC_DIR/roxy.env" "$ETC_DIR/$color.env")"
  printf '%s' "${sock:-${RUN_DIR_PREFIX}${color}/internal.sock}"
}

unit() { printf 'roxy@%s.service' "$1"; }

is_active() { "$SYSTEMCTL" is-active --quiet "$(unit "$1")"; }

# True when the color's internal socket answers Ready, PersistenceOK and the expected Version.
ready_ok() {
  local color="$1" want="$2" body
  body="$("$CURL" -sS --max-time 3 --unix-socket "$(internal_socket "$color")" http://localhost/internal/ready \
    2>/dev/null)" || return 1
  [ "$(printf '%s' "$body" | json_field Ready)" = true ] || return 1
  [ "$(printf '%s' "$body" | json_field PersistenceOK)" = true ] || return 1
  [ "$(printf '%s' "$body" | json_field Version)" = "$want" ] || return 1
}

# The public /health through nginx on this machine (TLS to 127.0.0.1 with the real host name, so no hairpin NAT).
# A 200 is not enough: the answer must come from Roxy v2, whose /health carries a "Degraded" list that v1's lacks.
# During the cutover v1's nginx site `roxy` names the same host and wins (it sorts before roxy-v2.conf), so a
# status-only check would pass on v1 and prove nothing about the new color. Sets PUBLIC_PROBLEM on failure.
public_health_ok() {
  [ "$PUBLIC_CHECK" = 1 ] || return 0
  local origin host body
  origin="$(env_value ROXY_SITE_ORIGIN "$ETC_DIR/roxy.env")"
  host="${origin#https://}"
  host="${host%%/*}"
  [ -n "$host" ] || host=roxytheproxy.com
  # --fail: an error status makes curl exit non-zero instead of printing the error page as the body.
  if ! body="$("$CURL" -sS --fail --max-time 10 --resolve "$host:443:127.0.0.1" "https://$host/health" 2>/dev/null)"
  then
    PUBLIC_PROBLEM="https://$host/health through nginx gave no 200 answer"
    return 1
  fi
  if ! printf '%s' "$body" | json_has_key Degraded; then
    PUBLIC_PROBLEM="https://$host/health through nginx was answered, but not by Roxy v2 (another nginx site, such as v1's roxy, serves $host: disable it, or set ROXY_DEPLOY_PUBLIC_CHECK=0 for a deploy before the cutover)"
    return 1
  fi
}

# ------------------------------------------------------------------------------------------ failure handling

record_result() {
  local status="$1" detail="$2" now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local json
  json="$("$PYTHON3" -I -c '
import json, socket, sys
status, sha, step, error, detail, now, mode = sys.argv[1:8]
print(json.dumps({"status": status, "sha": sha, "short": sha[:12], "step": int(step), "error": error,
                  "rollback": detail, "mode": mode, "at": now, "host": socket.gethostname()}, indent=2))
' "$status" "${SHA:-unknown}" "$STEP" "$LAST_ERROR" "$detail" "$now" "$MODE")" || return 0
  write_file "$DEPLOY_STATE_DIR/last_deploy.json" "$json" || true
  if [ "$status" = failed ]; then
    # roxy-deploy-alert.path watches this file and sends "Roxy: deploy <short sha> failed at step <n>".
    write_file "$DEPLOY_STATE_DIR/last_failure.json" "$json" || true
  fi
}

handle_failure() {
  local code="$1" detail="nothing was switched"
  [ "$HANDLED" = 0 ] || return 0
  HANDLED=1
  trap - ERR
  set +e
  fail "Deploy failed (exit $code) at step $STEP${LAST_ERROR:+: ${LAST_ERROR%.}}. Rolling back."
  if [ "$COMMITTED" = 1 ]; then
    detail="the new color stays live (the old color was already stopped)"
  else
    if [ "$SWITCHED" = 1 ] && [ -n "$ACTIVE_COLOR" ]; then
      if sudo "$SWITCH_COLOR" "$ACTIVE_COLOR"; then
        detail="nginx switched back to $ACTIVE_COLOR"
      else
        detail="COULD NOT switch nginx back to $ACTIVE_COLOR"
        fail "Could not switch nginx back to $ACTIVE_COLOR; run: sudo $SWITCH_COLOR $ACTIVE_COLOR"
      fi
    fi
    # The old color must get its own nginx config back too, not stay behind the config of the failed release.
    # The same wrapper and sudo rule as step 6, with the commit of the config that was installed before.
    if [ "$NGINX_INSTALLED_NEW" = 1 ]; then
      if [ -z "$NGINX_RESTORE_SHA" ]; then
        detail="$detail; the nginx config of ${SHA:0:12} stays installed (there was no earlier Roxy config to restore)"
      elif sudo "$NGINX_APPLY" "$NGINX_RESTORE_SHA"; then
        detail="$detail; nginx config restored to ${NGINX_RESTORE_SHA:0:12}"
      else
        detail="$detail; COULD NOT restore the nginx config of ${NGINX_RESTORE_SHA:0:12}"
        fail "Could not restore the previous nginx config; run: sudo $NGINX_APPLY $NGINX_RESTORE_SHA"
      fi
    fi
    if [ "$IDLE_TOUCHED" = 1 ] && [ -n "$IDLE_COLOR" ]; then
      sudo "$SYSTEMCTL" stop "$(unit "$IDLE_COLOR")" || fail "Could not stop $(unit "$IDLE_COLOR")."
      rm -f "$DEPLOY_STATE_DIR/start-workers-$IDLE_COLOR"
      if [ -n "$PREV_IDLE_TARGET" ]; then
        relink "$RELEASES_DIR/current-$IDLE_COLOR" "$PREV_IDLE_TARGET" || true
      else
        rm -f "$RELEASES_DIR/current-$IDLE_COLOR"
      fi
      detail="$detail; stopped $(unit "$IDLE_COLOR")"
    fi
    if [ "$BUILT_NEW" = 1 ] && [ -n "$RELEASE" ] && [ ! -e "$RELEASE/$RELEASE_STAMP" ]; then
      rm -rf "$RELEASE"
    fi
  fi
  record_result failed "$detail"
  if [ "$COMMITTED" = 1 ]; then
    fail "The new release is serving; only the bookkeeping after step 8 failed."
  else
    fail "Previous build restored. The site should be back up; nothing was upgraded."
    if [ -n "$ACTIVE_COLOR" ] && ! is_active "$ACTIVE_COLOR"; then
      fail "Note: $(unit "$ACTIVE_COLOR") is not running either; see systemctl status $(unit "$ACTIVE_COLOR")."
    fi
  fi
}

on_exit() {
  local code=$?
  if [ "$code" -ne 0 ]; then
    handle_failure "$code"
  fi
  exit "$code"
}

on_err() {
  local code="$1" line="$2" command="$3"
  LAST_ERROR="line $line: $command (exit $code)"
  exit "$code"
}

# ------------------------------------------------------------------------------------------------- steps

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --low-memory) LOW_MEMORY=on ;;
      --no-low-memory) LOW_MEMORY=off ;;
      --force-nginx) FORCE_NGINX=1 ;;
      --rollback) MODE=rollback ;;
      -h | --help)
        usage
        exit 0
        ;;
      -*)
        usage >&2
        exit 2
        ;;
      *)
        if [ -n "$SHA" ]; then
          usage >&2
          exit 2
        fi
        SHA="$1"
        ;;
    esac
    shift
  done
  if [ "$MODE" = deploy ] && [ -z "$SHA" ]; then
    usage >&2
    exit 2
  fi
  if [ -n "$SHA" ] && ! [[ "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
    fail "The commit must be the full 40 character lowercase sha, got '$SHA'."
    exit 2
  fi
}

repo_url() {
  local url="${ROXY_DEPLOY_REPO_URL:-}"
  [ -n "$url" ] || url="$(env_value ROXY_DEPLOY_REPO_URL "$ETC_DIR/roxy.env")"
  if [ -z "$url" ] || [[ "$url" == *OWNER/REPO* ]]; then
    url="${ROXY_REPO:+https://github.com/$ROXY_REPO.git}"
  fi
  [ -n "$url" ] || return 1
  printf '%s' "$url"
}

branch_name() {
  local branch="${ROXY_DEPLOY_BRANCH:-}"
  [ -n "$branch" ] || branch="$(env_value ROXY_DEPLOY_BRANCH "$ETC_DIR/roxy.env")"
  printf '%s' "${branch:-main}"
}

release_in_use() {
  local dir="$1" color target
  for color in blue green; do
    target="$(readlink "$RELEASES_DIR/current-$color" 2>/dev/null || true)"
    if [ -n "$target" ] && [ "$(basename "$target")" = "$(basename "$dir")" ]; then return 0; fi
  done
  return 1
}

# The deploy sequence number of a release directory: 0 when it has none (a release only an older deploy.sh used).
release_sequence() {
  local seq=""
  if [ -r "$1/$RELEASE_SEQUENCE" ]; then
    IFS= read -r seq <"$1/$RELEASE_SEQUENCE" || true
  fi
  [[ "$seq" =~ ^[0-9]{1,18}$ ]] || seq=0
  printf '%s' "$((10#$seq))"
}

# Give $RELEASE the next deploy sequence number: one more than the highest any release on disk carries (the
# newest release is always kept, so the numbers only grow). keep_releases orders by it, never by file times: a
# wall clock that steps back (NTP; WSL steps about 0.9 s) could make a newer release look older and get it
# removed. The deploy lock makes the read and the write one step.
mark_release_used() {
  local dir seq highest=0
  for dir in "$RELEASES_DIR"/*; do
    # The current-<color> links name releases that are counted under their own names.
    if [ ! -d "$dir" ] || [ -L "$dir" ]; then continue; fi
    seq="$(release_sequence "$dir")"
    if [ "$seq" -gt "$highest" ]; then highest="$seq"; fi
  done
  write_file "$RELEASE/$RELEASE_SEQUENCE" "$((highest + 1))"
}

fetch_release() {
  local url shown branch required
  # repo_url runs in a subshell, so the message is given here, where die can record it for the alert.
  url="$(repo_url)" || die "No repository to fetch from: set ROXY_DEPLOY_REPO_URL in $ETC_DIR/roxy.env."
  shown="$(display_url "$url")"
  branch="$(branch_name)"
  step 1 "fetching ${SHA:0:12} from $shown ($branch)"
  mkdir -p "$RELEASES_DIR"
  if [ ! -f "$MIRROR_DIR/HEAD" ]; then
    git init --quiet --bare "$MIRROR_DIR"
  fi
  git --git-dir="$MIRROR_DIR" fetch --quiet --no-tags --prune "$url" "+refs/heads/$branch:refs/heads/$branch"
  git --git-dir="$MIRROR_DIR" cat-file -e "$SHA^{commit}" 2>/dev/null ||
    die "Commit $SHA is not on $branch in $shown; refusing to deploy it."
  git --git-dir="$MIRROR_DIR" merge-base --is-ancestor "$SHA" "refs/heads/$branch" ||
    die "Commit $SHA is not on $branch; refusing to deploy it."
  RELEASE="$RELEASES_DIR/$SHA"
  if [ -e "$RELEASE/$RELEASE_STAMP" ] && [ -x "$RELEASE/.venv/bin/python" ]; then
    log "Release ${SHA:0:12} is already built."
    return 0
  fi
  if [ -e "$RELEASE" ]; then
    release_in_use "$RELEASE" && die "Release $RELEASE is incomplete but in use; refusing to rebuild it in place."
    rm -rf "$RELEASE"
  fi
  BUILT_NEW=1
  mkdir -p "$RELEASE"
  git --git-dir="$MIRROR_DIR" archive --format=tar "$SHA" | tar -x -C "$RELEASE"
  for required in "${REQUIRED_PATHS[@]}"; do
    [ -e "$RELEASE/$required" ] || die "Clone is missing $required; refusing to deploy it."
  done
  (cd "$RELEASE" && find deploy/nginx -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) \
    >"$RELEASE/$NGINX_MANIFEST"
  log "Build verified."
}

build_release() {
  step 2 "building the release environment"
  if [ "$BUILT_NEW" = 0 ]; then
    log "Dependencies unchanged; keeping the existing environment."
    touch "$RELEASE/$RELEASE_STAMP"
    mark_release_used
    return 0
  fi
  log "Dependencies changed (or no usable environment); rebuilding."
  [ -x "$UV" ] || command -v "$UV" >/dev/null || die "uv is not installed (expected at $UV)."
  "$UV" python install --quiet "$PYTHON_VERSION"
  # --compile-bytecode: the release is read-only to the service (ProtectSystem=strict), so Python could never
  # cache bytecode there itself; without this every worker start and max_requests recycle compiles from source.
  (cd "$RELEASE" && "$UV" sync --quiet --frozen --no-dev --no-editable --compile-bytecode --python "$PYTHON_VERSION")
  "$RELEASE/.venv/bin/python" "$RELEASE/scripts/build_static.py" --out "$RELEASE/build/public"
  chmod -R go-w "$RELEASE"
  printf '%s\n' "$SHA" >"$RELEASE/$RELEASE_STAMP"
  mark_release_used
}

choose_colors() {
  ACTIVE_COLOR="$(active_color)"
  if [ -z "$ACTIVE_COLOR" ]; then
    IDLE_COLOR=blue
    log "No active color yet: this is the first deploy; starting blue."
  else
    IDLE_COLOR="$(other_color "$ACTIVE_COLOR")"
    log "Active color: $ACTIVE_COLOR; deploying to $IDLE_COLOR."
  fi
}

decide_low_memory() {
  local avail_kb avail_mb
  avail_kb="$(awk '/^MemAvailable:/ {print $2}' "$MEMINFO" 2>/dev/null || true)"
  avail_mb=$(( ${avail_kb:-0} / 1024 ))
  case "$LOW_MEMORY" in
    on) LOW_MEMORY_MODE=1 ;;
    off) LOW_MEMORY_MODE=0 ;;
    *)
      if [ -n "$ACTIVE_COLOR" ] && [ -n "$avail_kb" ] && [ "$avail_mb" -lt "$LOW_MEMORY_MB" ]; then
        LOW_MEMORY_MODE=1
      else
        LOW_MEMORY_MODE=0
      fi
      ;;
  esac
  if [ "$LOW_MEMORY_MODE" = 1 ]; then
    log "Low-memory mode: ${avail_mb} MB available (threshold ${LOW_MEMORY_MB} MB); $IDLE_COLOR starts with 1 worker."
  else
    log "Normal mode: ${avail_mb} MB available (threshold ${LOW_MEMORY_MB} MB)."
  fi
}

start_idle() {
  step 4 "starting $(unit "$IDLE_COLOR") on release ${RELEASE##*/}"
  PREV_IDLE_TARGET="$(readlink "$RELEASES_DIR/current-$IDLE_COLOR" 2>/dev/null || true)"
  IDLE_TOUCHED=1
  relink "$RELEASES_DIR/current-$IDLE_COLOR" "$RELEASE"
  if [ "$LOW_MEMORY_MODE" = 1 ]; then
    write_file "$DEPLOY_STATE_DIR/start-workers-$IDLE_COLOR" 1
  else
    rm -f "$DEPLOY_STATE_DIR/start-workers-$IDLE_COLOR"
  fi
  # Type=notify: this returns once the pre-start migrations ran and gunicorn's master is up, or fails.
  sudo "$SYSTEMCTL" restart "$(unit "$IDLE_COLOR")" ||
    die "$(unit "$IDLE_COLOR") did not start (journalctl -u $(unit "$IDLE_COLOR") shows why; a failed migration stops it here)."
}

health_gate() {
  local want="${RELEASE##*/}" deadline
  step 5 "health gate on $IDLE_COLOR (internal socket, then smoke test)"
  deadline=$((SECONDS + HEALTH_TIMEOUT_S))
  until ready_ok "$IDLE_COLOR" "$want"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      die "Health gate failed: $IDLE_COLOR did not report Ready with version ${want:0:12} within ${HEALTH_TIMEOUT_S} s."
    fi
    sleep "$POLL_INTERVAL_S"
  done
  log "$IDLE_COLOR is ready on version ${want:0:12}."
  "$RELEASE/.venv/bin/python" "$RELEASE/scripts/smoke_remote.py" --color "$IDLE_COLOR" --expect-version "$want" \
    --env-dir "$ETC_DIR" || die "Smoke test failed on $IDLE_COLOR."
}

nginx_changed() {
  local mine applied
  [ "$FORCE_NGINX" = 0 ] || return 0
  [ -n "$ACTIVE_COLOR" ] || return 0
  mine="$(sha256sum <"$RELEASE/$NGINX_MANIFEST" | cut -d' ' -f1)"
  applied="$(json_field manifest_sha256 <"$NGINX_APPLIED" 2>/dev/null || true)"
  [ "$mine" != "$applied" ]
}

# The release whose nginx config is installed now, so a failed deploy can put it back: the release applied.json
# names while it is still on disk (the wrapper verifies a release against its files), else the release the active
# color runs (every successful run leaves the active release's config installed). Empty on a first deploy.
nginx_restore_target() {
  local sha
  sha="$(json_field sha <"$NGINX_APPLIED" 2>/dev/null || true)"
  if [[ "$sha" =~ ^[0-9a-f]{40}$ ]] && [ -e "$RELEASES_DIR/$sha/$NGINX_MANIFEST" ]; then
    printf '%s' "$sha"
    return 0
  fi
  [ -n "$ACTIVE_COLOR" ] || return 0
  sha="$(readlink "$RELEASES_DIR/current-$ACTIVE_COLOR" 2>/dev/null || true)"
  sha="${sha##*/}"
  if [[ "$sha" =~ ^[0-9a-f]{40}$ ]] && [ -e "$RELEASES_DIR/$sha/$NGINX_MANIFEST" ]; then
    printf '%s' "$sha"
  fi
}

switch_traffic() {
  step 6 "switching nginx to $IDLE_COLOR"
  if nginx_changed; then
    log "nginx config changed in this release; installing it through the root wrapper."
    NGINX_RESTORE_SHA="$(nginx_restore_target)"
    if [ -L "$ACTIVE_LINK" ]; then
      sudo "$NGINX_APPLY" "${RELEASE##*/}"
    else
      sudo "$NGINX_APPLY" "${RELEASE##*/}" --initial-color "$IDLE_COLOR"
    fi
    # Only a completed apply needs undoing: a failed one has already put its own files back (nginx -t failed) or
    # changed nothing (the commit or the release did not verify).
    NGINX_INSTALLED_NEW=1
  else
    log "nginx config unchanged."
  fi
  SWITCHED=1
  sudo "$SWITCH_COLOR" "$IDLE_COLOR"
}

# How many watch checks span WATCH_S at one every WATCH_INTERVAL_S (rounded up, at least 1). awk, because bash
# arithmetic has no fractions and the tests watch in tenths of a second; the margin absorbs float rounding.
watch_checks() {
  awk -v span="$WATCH_S" -v every="$WATCH_INTERVAL_S" 'BEGIN {
    rounds = (every > 0) ? span / every : 1
    whole = int(rounds)
    if (whole < rounds - 1e-9) whole += 1
    if (whole < 1) whole = 1
    print whole
  }'
}

watch_new_color() {
  local want="${RELEASE##*/}" checks check failures=0
  # A fixed number of checks, WATCH_INTERVAL_S apart, that together span WATCH_S (60 s / 5 s: 12 checks). Counting
  # checks rather than comparing whole seconds of the wall clock ($SECONDS) means a busy machine or a clock step
  # never cuts the watch down to one check (or none), which would let a failing new color through.
  checks="$(watch_checks)"
  step 7 "watching $IDLE_COLOR for ${WATCH_S} s ($checks checks, ${WATCH_INTERVAL_S} s apart)"
  for ((check = 1; check <= checks; check++)); do
    sleep "$WATCH_INTERVAL_S"
    if ! ready_ok "$IDLE_COLOR" "$want"; then
      failures=$((failures + 1))
      fail "Watch: $IDLE_COLOR internal readiness check failed ($failures)."
    fi
    if ! public_health_ok; then
      failures=$((failures + 1))
      fail "Watch: $PUBLIC_PROBLEM ($failures)."
    fi
    if [ "$failures" -gt "$WATCH_MAX_FAILURES" ]; then
      die "Watch failed: $failures failed checks on $IDLE_COLOR${PUBLIC_PROBLEM:+; last public check: $PUBLIC_PROBLEM}."
    fi
  done
  if [ "$PUBLIC_CHECK" = 1 ]; then
    # Now that nginx serves the new color: the same smoke test once more, plus a static asset through the local
    # nginx with HSTS (step 5 could not check that: nginx still pointed at the old color then).
    "$RELEASE/.venv/bin/python" "$RELEASE/scripts/smoke_remote.py" --color "$IDLE_COLOR" --expect-version "$want" \
      --env-dir "$ETC_DIR" --skip-proxy --nginx 127.0.0.1:443 || die "Smoke test through nginx failed on $IDLE_COLOR."
  fi
  log "$IDLE_COLOR stayed healthy."
}

wait_inactive() {
  local color="$1" deadline=$((SECONDS + STOP_TIMEOUT_S))
  while is_active "$color"; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep "$POLL_INTERVAL_S"
  done
}

full_workers() {
  local color="$1" workers
  workers="$(env_value ROXY_WORKERS "$ETC_DIR/roxy.env" "$ETC_DIR/$color.env")"
  [[ "$workers" =~ ^[0-9]+$ ]] && [ "$workers" -ge 1 ] || workers=2
  printf '%s' "$workers"
}

# Low-memory mode: add workers through the gunicorn control socket (`worker add` runs gunicorn's SIGTTIN handler
# code; the deploy user cannot signal the roxy user's processes). Falls back to a graceful reload, which re-reads
# gunicorn.conf.py with the marker gone. Never fatal: the new color already serves with one worker.
scale_up() {
  local color="$1" target ctl gunicornc current deadline
  target="$(full_workers "$color")"
  rm -f "$DEPLOY_STATE_DIR/start-workers-$color"
  [ "$target" -gt 1 ] || return 0
  ctl="$(dirname "$(internal_socket "$color")")/gunicorn.ctl"
  gunicornc="$RELEASE/.venv/bin/gunicornc"
  log "Low-memory mode: adding $((target - 1)) worker(s) to $color (target $target)."
  if "$gunicornc" -s "$ctl" -c "worker add $((target - 1))" -j >/dev/null 2>&1; then
    deadline=$((SECONDS + SCALE_TIMEOUT_S))
    while :; do
      current="$("$gunicornc" -s "$ctl" -c "show stats" -j 2>/dev/null | json_field workers_current || true)"
      if [[ "$current" =~ ^[0-9]+$ ]] && [ "$current" -ge "$target" ]; then
        log "$color now runs $current workers."
        return 0
      fi
      [ "$SECONDS" -lt "$deadline" ] || break
      sleep "$POLL_INTERVAL_S"
    done
  fi
  fail "Could not add workers through the control socket; reloading $(unit "$color") instead."
  sudo "$SYSTEMCTL" reload "$(unit "$color")" || fail "Reload failed too; $color keeps running with 1 worker."
}

keep_releases() {
  local dir kept=0
  # Newest first by the deploy sequence number (mark_release_used: every deploy or rollback that starts a release
  # gives it the next number), never by file times, which a clock stepping back can reorder. The newest
  # KEEP_RELEASES stay; a release a color points at is never removed, however old.
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    kept=$((kept + 1))
    if [ "$kept" -le "$KEEP_RELEASES" ] || release_in_use "$dir"; then continue; fi
    log "Removing old release ${dir##*/}."
    rm -rf "$dir"
  done < <(
    # Only complete builds count. find does not follow symlinks, so the current-<color> links are never listed
    # (or removed) themselves. Releases without a sequence number (used only by an older deploy.sh) sort after
    # every numbered one, newest stamp first among themselves.
    find "$RELEASES_DIR" -mindepth 2 -maxdepth 2 -type f -name "$RELEASE_STAMP" -printf '%T@ %h\n' |
      grep -E '/[0-9a-f]{40}$' |
      while IFS=' ' read -r stamped dir; do
        printf '%s %s %s\n' "$(release_sequence "$dir")" "$stamped" "$dir"
      done |
      LC_ALL=C sort -k1,1nr -k2,2nr | cut -d' ' -f3- || true
  )
}

stop_old() {
  step 8 "stopping the old color"
  if [ -n "$ACTIVE_COLOR" ]; then
    log "Draining $ACTIVE_COLOR for ${DRAIN_S} s."
    sleep "$DRAIN_S"
    # The point of no return: once the old color is told to stop, switching nginx back to it could only make
    # things worse, so from here a failure keeps the (healthy, watched) new color live.
    COMMITTED=1
    sudo "$SYSTEMCTL" stop "$(unit "$ACTIVE_COLOR")"
    wait_inactive "$ACTIVE_COLOR" || die "$(unit "$ACTIVE_COLOR") did not stop within ${STOP_TIMEOUT_S} s."
    log "Stopped $(unit "$ACTIVE_COLOR"); its release stays for an instant rollback."
  fi
  COMMITTED=1
  if [ "$LOW_MEMORY_MODE" = 1 ]; then
    scale_up "$IDLE_COLOR"
  fi
  log "Cleaning up."
  keep_releases
}

install_scripts() {
  local name
  for name in deploy.sh deploy_rollback.sh; do
    if ! cmp -s "$RELEASE/deploy/$name" "$ROXY_ROOT/$name" 2>/dev/null; then
      install -m 0755 "$RELEASE/deploy/$name" "$ROXY_ROOT/.$name.new"
      mv -f "$ROXY_ROOT/.$name.new" "$ROXY_ROOT/$name"
      log "Updated $ROXY_ROOT/$name."
    fi
  done
}

# The dependency audit record of this release for health check H-VERSION, printed as JSON (`{"count": n, ...}`;
# `"count": null` reads as "not recorded"). The workflow passes CI's pip-audit result; a rollback reuses the record
# its release was deployed with; anything else is honestly "not recorded", never a guessed zero.
advisories_json() {
  local saved="$RELEASE/$RELEASE_ADVISORIES"
  "$PYTHON3" -I - "${RELEASE##*/}" "$ADVISORY_COUNT" "$ADVISORY_FIXABLE" "$ADVISORY_IDS" "$MODE" "$saved" <<'PY'
import json, os, re, sys, time

sha, count, fixable, ids, mode, saved = sys.argv[1:7]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
number = re.compile(r"[0-9]{1,6}")


def known_ids(text):
    # Advisory ids only (PYSEC-2024-1, GHSA-xxxx-xxxx-xxxx, CVE-2024-1234): letters, digits, dots and hyphens.
    found = [part.strip() for part in text.split(",") if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", part.strip())]
    return found[:50]


if number.fullmatch(count.strip()):
    record = {
        "count": int(count),
        "fixable": int(fixable) if number.fullmatch(fixable.strip()) else None,
        "ids": known_ids(ids),
        "source": "ci",
    }
else:
    record = None
    if mode == "rollback":
        try:
            with open(saved, "rb") as handle:
                earlier = json.loads(handle.read(65536))
        except (OSError, ValueError):
            earlier = None
        if isinstance(earlier, dict) and earlier.get("commit") == sha and isinstance(earlier.get("count"), int):
            record = {key: earlier.get(key) for key in ("count", "fixable", "ids", "source", "recorded_at")}
            record["restored_by"] = "rollback"
    if record is None:
        why = "the deploy was started by hand" if not count.strip() else "the value given was not a count"
        record = {"count": None, "fixable": None, "ids": [], "source": "not_recorded", "note": why}
record["commit"] = sha
record.setdefault("recorded_at", now)
if record.get("recorded_at") is None:
    record["recorded_at"] = now
print(json.dumps(record, indent=2, sort_keys=True))
PY
}

record_advisories() {
  local json count source
  json="$(advisories_json)" || return 1
  count="$(printf '%s' "$json" | json_field count || true)"
  source="$(printf '%s' "$json" | json_field source || true)"
  if [ "$source" = ci ] && [ "$MODE" = deploy ]; then
    write_file "$RELEASE/$RELEASE_ADVISORIES" "$json"
  fi
  # 0644 in the 0755 deploy state directory: the roxy user (H-VERSION) reads it.
  write_file "$DEPLOY_STATE_DIR/advisories.json" "$json"
  if [ -n "$count" ]; then
    log "Dependency audit recorded: $count known advisories ($source)."
  else
    log "Dependency audit not recorded (no CI result was passed to this deploy); H-VERSION will say so."
  fi
}

record_deploy() {
  step 9 "recording ${RELEASE##*/}"
  # Bookkeeping after the switch must never undo a healthy deploy; a missing record shows as "not recorded".
  record_advisories || fail "Could not record the dependency audit; H-VERSION reports it as not recorded."
  # roxy-audit.path watches this file and runs the permission audit (plan 17.4 step 9).
  write_file "$DEPLOY_STATE_DIR/deployed_version" "${RELEASE##*/}"
  record_result succeeded "none needed"
  if [ "$MODE" = deploy ]; then
    install_scripts
  fi
  log "Site successfully deployed."
}

rollback_target() {
  step 1 "choosing the release to roll back to"
  local target
  if [ -n "$SHA" ]; then
    target="$RELEASES_DIR/$SHA"
  else
    target="$(readlink "$RELEASES_DIR/current-$IDLE_COLOR" 2>/dev/null || true)"
    [ -n "$target" ] || die "Nothing to roll back to: $IDLE_COLOR has never run a release."
  fi
  [ -e "$target/$RELEASE_STAMP" ] || die "Release $target is not a complete build; refusing to roll back to it."
  if [ -n "$ACTIVE_COLOR" ] &&
    [ "$(basename "$(readlink "$RELEASES_DIR/current-$ACTIVE_COLOR" 2>/dev/null || true)")" = "$(basename "$target")" ]; then
    die "Release $(basename "$target") is already live on $ACTIVE_COLOR; nothing to roll back."
  fi
  RELEASE="$target"
  SHA="$(basename "$target")"
  log "Rolling back to ${SHA:0:12} on $IDLE_COLOR."
  touch "$RELEASE/$RELEASE_STAMP"
  mark_release_used
}

main() {
  parse_args "$@"
  if [ "$(id -u)" -eq 0 ] && [ "${ROXY_ALLOW_ROOT:-0}" != 1 ]; then
    # As root every release file would be root-owned and the next normal deploy could not replace it; root also
    # does not need the sudo rules this script is built around.
    fail "Run deploy.sh as the deploy user (roxy-deploy), not as root."
    exit 2
  fi
  mkdir -p "$DEPLOY_STATE_DIR"
  chmod 0755 "$DEPLOY_STATE_DIR" 2>/dev/null || true
  # One deploy at a time. This runs BEFORE the traps, so a refused second deploy touches nothing.
  exec 9>>"$LOCK_FILE"
  if ! flock -w "$LOCK_WAIT_S" 9; then
    fail "Another deploy is running (lock $LOCK_FILE); nothing was changed. Try again when it finishes."
    exit 75
  fi
  trap 'on_err $? $LINENO "$BASH_COMMAND"' ERR
  trap on_exit EXIT
  trap 'LAST_ERROR="interrupted by a signal"; exit 130' INT TERM HUP

  if [ "$MODE" = rollback ]; then
    log "Rollback started."
    choose_colors
    rollback_target
  else
    log "Deploy of $SHA started."
    fetch_release
    build_release
    step 3 "database migrations run as the roxy user in the pre-start step of $(active_color_or_first) (snapshot first)"
    choose_colors
  fi
  decide_low_memory
  start_idle
  health_gate
  switch_traffic
  watch_new_color
  stop_old
  record_deploy
  log "Done."
}

# The idle color name for the step 3 log line, before choose_colors has run.
active_color_or_first() {
  local active
  active="$(active_color)"
  if [ -z "$active" ]; then echo blue; else other_color "$active"; fi
}

main "$@"
