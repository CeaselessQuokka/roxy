#!/bin/bash
#
# Deploys the newest build from GitHub. Run by .github/workflows/deploy.yml as
# `bash ~/UpdateBuild.sh` on every push to main.
#
# This script updates ITSELF, and that is the part worth being careful about:
# the previous version moved the running script out of the way
# (`mv ~/UpdateBuild.sh ~/UpdateBuildOld.sh`) before it had the replacement in
# hand, deleted its own backup unconditionally at the end, and ran with no
# `set -e`. So one failed `git clone` was enough to leave the home directory
# with no UpdateBuild.sh, no backup, no ~/Tooling and no ~/Roxy — after which
# every future deploy failed at "bash: ~/UpdateBuild.sh: No such file or
# directory" and the one script that could have repaired it was the thing that
# had been deleted. Recovery needed a manual SSH session.
#
# The rules that keep that from happening again:
#
#   Fetch before destroying.  Everything is cloned, verified and staged while
#       the live site is still running. Nothing that is currently serving is
#       touched until there is a complete, checked replacement on disk.
#
#   Replace, never vacate.  The self-update writes the new script to a temp file
#       and renames it ONTO ~/UpdateBuild.sh. rename(2) is atomic, so the path
#       is never empty even for an instant, and bash keeps executing from the
#       inode it already has open. The backup is kept until the run succeeds.
#
#   Fail loudly and roll back.  set -euo pipefail plus an ERR trap that puts the
#       previous build and venv back and restarts the service, then exits
#       non-zero so the GitHub Action goes red instead of reporting success over
#       a site that is down.
#
# The workflow can also reinstall this script from the repo if it goes missing,
# so a broken deploy is recoverable by pushing rather than by hand.

set -euo pipefail

DEPLOY_TO=~/Roxy
ENV_NAME=SiteEnv
SERVICE_NAME="roxy.service"
SITE_NAME="Roxy"
GITHUB_REPO_NAME="roxy"
GITHUB_REPO_URL="https://github.com/CeaselessQuokka/$GITHUB_REPO_NAME"
SITE_CODE_ROOT="app"

VENV=~/"$ENV_NAME"
SCRIPT_PATH=~/UpdateBuild.sh
BUILD_DIR=~/Build
# Retired copies, kept until the very end so a late failure can still roll back.
OLD_SITE="$DEPLOY_TO.old"
OLD_VENV="$VENV.old"
NEW_VENV="$VENV.new"

log() { echo "==> $*"; }
fail() { echo "!!! $*" >&2; }

service_exists() {
	systemctl list-unit-files "$SERVICE_NAME" 2>/dev/null | grep -q "^$SERVICE_NAME"
}

start_service() {
	service_exists || return 0
	sudo systemctl start "$SERVICE_NAME" || true
}

stop_service() {
	if systemctl is-active --quiet "$SERVICE_NAME"; then
		log "Stopping $SITE_NAME service."
		sudo systemctl stop "$SERVICE_NAME"
	fi
}

# Put back whatever was live before this run and get the site up again. Called
# from the ERR trap, so it must not itself be able to fail the script.
rollback() {
	local code=$?
	trap - ERR EXIT
	fail "Deploy failed (exit $code). Rolling back."
	if [ -d "$OLD_SITE" ]; then
		sudo rm -rf "$DEPLOY_TO" 2>/dev/null || true
		mv "$OLD_SITE" "$DEPLOY_TO" 2>/dev/null || fail "Could not restore $DEPLOY_TO."
	fi
	if [ -d "$OLD_VENV" ]; then
		sudo rm -rf "$VENV" 2>/dev/null || true
		mv "$OLD_VENV" "$VENV" 2>/dev/null || fail "Could not restore $VENV."
	fi
	# The backup only exists if the self-update had already replaced the script.
	if [ -f "$SCRIPT_PATH.bak" ] && [ ! -f "$SCRIPT_PATH" ]; then
		mv "$SCRIPT_PATH.bak" "$SCRIPT_PATH" 2>/dev/null || true
	fi
	rm -rf "$NEW_VENV" "$BUILD_DIR" 2>/dev/null || true
	start_service
	fail "Previous build restored. The site should be back up; nothing was upgraded."
	exit "$code"
}
trap rollback ERR

# --- 1. Fetch and verify, while the live site keeps serving ------------------
log "Retrieving newest build."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
git clone --quiet --depth 1 "$GITHUB_REPO_URL" "$BUILD_DIR/$GITHUB_REPO_NAME"

SRC="$BUILD_DIR/$GITHUB_REPO_NAME"
# Check the payload BEFORE anything live is touched. A clone that "succeeded"
# but produced the wrong shape (bad branch, partial fetch) must stop here, while
# stopping costs nothing.
for required in "$SITE_CODE_ROOT" "requirements.txt" "Tooling/UpdateBuild.sh" "Tooling/alert_on_failure.py"; do
	if [ ! -e "$SRC/$required" ]; then
		fail "Clone is missing $required — refusing to deploy it."
		exit 1
	fi
done
log "Build verified."

# --- 2. Build the new virtualenv alongside the old one -----------------------
# Alongside, not in place: a pip failure used to leave the site with no
# interpreter at all, because the old venv had already been deleted.
log "Creating fresh environment."
rm -rf "$NEW_VENV"
python3 -m venv "$NEW_VENV"
"$NEW_VENV"/bin/pip install --quiet --upgrade pip
"$NEW_VENV"/bin/pip install --quiet -r "$SRC/requirements.txt"

# --- 3. Update the tooling that lives outside the app ------------------------
# ~/Build is deleted at the end, so without this the systemd and nginx configs
# are only reachable by pulling them from GitHub again -- exactly when you least
# want to be hunting for them.
log "Updating tooling."
rm -rf ~/Tooling.new
cp -r "$SRC/Tooling" ~/Tooling.new
rm -rf ~/Tooling
mv ~/Tooling.new ~/Tooling

# The failure-alert script lives directly in the home directory: it has to
# survive the window where ~/Roxy has been torn down, and it is what emails you
# if the service will not come back up.
cp "$SRC/Tooling/alert_on_failure.py" ~/alert_on_failure.py
chmod +x ~/alert_on_failure.py

# --- 4. Replace this script, atomically --------------------------------------
# Written to a temp path and renamed ONTO the live path, so ~/UpdateBuild.sh is
# never absent. bash carries on from the inode it already has open, so the rest
# of this run executes the old version — which is what we want: a half-applied
# mix of two versions is exactly the state that is impossible to reason about.
log "Updating deploy script."
cp "$SRC/Tooling/UpdateBuild.sh" "$SCRIPT_PATH.new"
chmod +x "$SCRIPT_PATH.new"
if [ -f "$SCRIPT_PATH" ]; then
	cp "$SCRIPT_PATH" "$SCRIPT_PATH.bak"
fi
mv "$SCRIPT_PATH.new" "$SCRIPT_PATH"

# --- 5. Swap in the new build ------------------------------------------------
# Only now is anything that is currently serving touched. The old build and venv
# are moved aside rather than deleted, so the ERR trap above can still put them
# back if the service refuses to come up.
stop_service

log "Deploying newest build."
sudo rm -rf "$OLD_SITE" "$OLD_VENV"
# Written as `if` rather than `[ -d x ] && mv`: under `set -e` a bare test that
# comes back false is a footgun waiting for someone to move the line, and a
# first-ever deploy (no ~/Roxy yet) is exactly when it would fire.
if [ -d "$DEPLOY_TO" ]; then
	mv "$DEPLOY_TO" "$OLD_SITE"
fi
if [ -d "$VENV" ]; then
	mv "$VENV" "$OLD_VENV"
fi
mv "$SRC/$SITE_CODE_ROOT" "$DEPLOY_TO"
mv "$NEW_VENV" "$VENV"
# Past deploys used `sudo mv`, which could leave a root-owned tree behind for a
# service that runs as this user. Normalise it either way.
sudo chown -R "$(id -un):$(id -gn)" "$DEPLOY_TO" 2>/dev/null || true

if service_exists; then
	log "Starting $SITE_NAME service."
	sudo systemctl start "$SERVICE_NAME"
	# Confirm it actually came up. Reporting success on a dead service is how a
	# broken deploy stays unnoticed until the 502s are noticed by someone else.
	sleep 3
	if ! systemctl is-active --quiet "$SERVICE_NAME"; then
		fail "$SERVICE_NAME did not come up."
		systemctl status "$SERVICE_NAME" --no-pager --lines=20 || true
		exit 1
	fi
	log "Site successfully deployed."
else
	fail "Service $SERVICE_NAME not found. Create a systemd service to run the site."
fi

# --- 6. Success: clear the safety net ----------------------------------------
trap - ERR
log "Cleaning up."
sudo rm -rf "$OLD_SITE" "$OLD_VENV"
rm -rf "$BUILD_DIR"
rm -f "$SCRIPT_PATH.bak"
log "Done."
