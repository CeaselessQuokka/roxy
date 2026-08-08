#!/bin/bash
# Exercises Tooling/UpdateBuild.sh against a fake home, a fake git remote, and
# stubbed sudo/systemctl/python3. Nothing real is touched.
#
# It proves the two properties that actually matter:
#   1. a successful run leaves ~/UpdateBuild.sh in place and the site updated
#   2. a FAILED run leaves ~/UpdateBuild.sh in place and the OLD site running
#
# The second is the one the previous version got wrong, and getting it wrong
# cost the server its deploy script, its virtualenv, its ~/Tooling and its
# running app — while reporting success. Every failure path here exists because
# that actually happened.
#
# Run:  bash tests/deploy_test.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC_SCRIPT="${1:-$REPO/Tooling/UpdateBuild.sh}"   # the UpdateBuild.sh under test

if [ ! -f "$SRC_SCRIPT" ]; then
	echo "No such script: $SRC_SCRIPT" >&2
	exit 1
fi
if ! bash -n "$SRC_SCRIPT"; then
	echo "$SRC_SCRIPT is not valid bash" >&2
	exit 1
fi

pass=0
fail=0
check() {
	if [ "$2" = "1" ]; then
		echo "  PASS  $1"
		pass=$((pass + 1))
	else
		echo "  FAIL  $1   ${3:-}"
		fail=$((fail + 1))
	fi
}

SANDBOX=$(mktemp -d)
trap 'rm -rf "$SANDBOX"' EXIT

# --- A fake "GitHub" repo the script can clone -------------------------------
build_remote() {
	local remote="$1" marker="$2"
	rm -rf "$remote"
	mkdir -p "$remote/app" "$remote/Tooling"
	echo "$marker" > "$remote/app/index.py"
	echo "gunicorn" > "$remote/requirements.txt"
	cp "$SRC_SCRIPT" "$remote/Tooling/UpdateBuild.sh"
	echo "print('alert')" > "$remote/Tooling/alert_on_failure.py"
	echo "unit" > "$remote/Tooling/roxy.service"
	(cd "$remote" && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm x)
}

# --- Stub sudo, systemctl, python3 venv so nothing real is touched -----------
setup_home() {
	HOME_DIR="$SANDBOX/home"
	rm -rf "$HOME_DIR"
	mkdir -p "$HOME_DIR/bin"

	cat > "$HOME_DIR/bin/sudo" <<'EOF'
#!/bin/bash
exec "$@"
EOF
	cat > "$HOME_DIR/bin/systemctl" <<'EOF'
#!/bin/bash
case "${1:-}" in
  is-active) [ -f "$HOME/.service_running" ] && exit 0 || exit 3 ;;
  list-unit-files) echo "roxy.service enabled" ;;
  start) touch "$HOME/.service_running" ;;
  stop) rm -f "$HOME/.service_running" ;;
  status) echo "stubbed status" ;;
esac
exit 0
EOF
	# A venv that is cheap to make; pip is a no-op unless we ask it to fail.
	cat > "$HOME_DIR/bin/python3" <<'EOF'
#!/bin/bash
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "venv" ]; then
  mkdir -p "$3/bin"
  cat > "$3/bin/pip" <<'PIP'
#!/bin/bash
[ -f "$HOME/.pip_should_fail" ] && { echo "pip exploded" >&2; exit 1; }
exit 0
PIP
  chmod +x "$3/bin/pip"
  exit 0
fi
exec /usr/bin/python3 "$@"
EOF
	chmod +x "$HOME_DIR/bin/"*
}

run_deploy() {
	env -i \
		HOME="$HOME_DIR" \
		PATH="$HOME_DIR/bin:/usr/local/bin:/usr/bin:/bin" \
		bash "$HOME_DIR/UpdateBuild.sh" > "$SANDBOX/out.log" 2>&1
	echo $?
}

echo "== A successful deploy =="
setup_home
REMOTE="$SANDBOX/remote"
build_remote "$REMOTE" "VERSION_ONE"
# Point the script at the local fake remote.
sed "s|GITHUB_REPO_URL=.*|GITHUB_REPO_URL=\"$REMOTE\"|" "$SRC_SCRIPT" > "$HOME_DIR/UpdateBuild.sh"
chmod +x "$HOME_DIR/UpdateBuild.sh"
# A live site + venv already deployed.
mkdir -p "$HOME_DIR/Roxy" "$HOME_DIR/SiteEnv/bin"
echo "VERSION_ZERO" > "$HOME_DIR/Roxy/index.py"
touch "$HOME_DIR/.service_running"

code=$(run_deploy)
check "exits 0" "$([ "$code" = "0" ] && echo 1 || echo 0)" "exit=$code $(tail -3 "$SANDBOX/out.log")"
check "UpdateBuild.sh is still in home" "$([ -f "$HOME_DIR/UpdateBuild.sh" ] && echo 1 || echo 0)"
check "the new build is deployed" "$(grep -q VERSION_ONE "$HOME_DIR/Roxy/index.py" 2>/dev/null && echo 1 || echo 0)"
check "~/Tooling is refreshed" "$([ -f "$HOME_DIR/Tooling/roxy.service" ] && echo 1 || echo 0)"
check "the alert script is in home" "$([ -f "$HOME_DIR/alert_on_failure.py" ] && echo 1 || echo 0)"
check "the venv is in place" "$([ -d "$HOME_DIR/SiteEnv/bin" ] && echo 1 || echo 0)"
check "the service is running" "$([ -f "$HOME_DIR/.service_running" ] && echo 1 || echo 0)"
check "the build dir is cleaned up" "$([ ! -d "$HOME_DIR/Build" ] && echo 1 || echo 0)"
check "no leftovers" "$([ ! -e "$HOME_DIR/Roxy.old" ] && [ ! -e "$HOME_DIR/SiteEnv.old" ] && [ ! -e "$HOME_DIR/UpdateBuild.sh.bak" ] && echo 1 || echo 0)"

echo ""
echo "== The script updates itself =="
setup_home
build_remote "$REMOTE" "VERSION_TWO"
# Mark the copy in the remote so we can tell the two apart.
echo "# NEWER VERSION MARKER" >> "$REMOTE/Tooling/UpdateBuild.sh"
(cd "$REMOTE" && git add -A && git -c user.email=t@t -c user.name=t commit -qm y)
sed "s|GITHUB_REPO_URL=.*|GITHUB_REPO_URL=\"$REMOTE\"|" "$SRC_SCRIPT" > "$HOME_DIR/UpdateBuild.sh"
chmod +x "$HOME_DIR/UpdateBuild.sh"
mkdir -p "$HOME_DIR/Roxy"; touch "$HOME_DIR/.service_running"
code=$(run_deploy)
check "exits 0" "$([ "$code" = "0" ] && echo 1 || echo 0)" "exit=$code"
check "home now has the NEWER script" "$(grep -q 'NEWER VERSION MARKER' "$HOME_DIR/UpdateBuild.sh" && echo 1 || echo 0)"
check "the backup is gone on success" "$([ ! -f "$HOME_DIR/UpdateBuild.sh.bak" ] && echo 1 || echo 0)"

echo ""
echo "== A clone failure must not brick the server =="
# This is the exact scenario that broke the real box: the remote is unreachable.
setup_home
sed "s|GITHUB_REPO_URL=.*|GITHUB_REPO_URL=\"$SANDBOX/does-not-exist\"|" "$SRC_SCRIPT" > "$HOME_DIR/UpdateBuild.sh"
chmod +x "$HOME_DIR/UpdateBuild.sh"
mkdir -p "$HOME_DIR/Roxy" "$HOME_DIR/SiteEnv/bin" "$HOME_DIR/Tooling"
echo "VERSION_ZERO" > "$HOME_DIR/Roxy/index.py"
echo "unit" > "$HOME_DIR/Tooling/roxy.service"
touch "$HOME_DIR/.service_running"

code=$(run_deploy)
check "exits NON-zero so the Action goes red" "$([ "$code" != "0" ] && echo 1 || echo 0)" "exit=$code"
check "UpdateBuild.sh SURVIVES in home" "$([ -f "$HOME_DIR/UpdateBuild.sh" ] && echo 1 || echo 0)"
check "...and is still runnable" "$(bash -n "$HOME_DIR/UpdateBuild.sh" 2>/dev/null && echo 1 || echo 0)"
check "the old site is untouched" "$(grep -q VERSION_ZERO "$HOME_DIR/Roxy/index.py" 2>/dev/null && echo 1 || echo 0)"
check "the venv is untouched" "$([ -d "$HOME_DIR/SiteEnv/bin" ] && echo 1 || echo 0)"
check "~/Tooling is untouched" "$([ -f "$HOME_DIR/Tooling/roxy.service" ] && echo 1 || echo 0)"
check "the service is still running" "$([ -f "$HOME_DIR/.service_running" ] && echo 1 || echo 0)"

echo ""
echo "== A pip failure rolls back to the working venv =="
setup_home
build_remote "$REMOTE" "VERSION_THREE"
sed "s|GITHUB_REPO_URL=.*|GITHUB_REPO_URL=\"$REMOTE\"|" "$SRC_SCRIPT" > "$HOME_DIR/UpdateBuild.sh"
chmod +x "$HOME_DIR/UpdateBuild.sh"
mkdir -p "$HOME_DIR/Roxy" "$HOME_DIR/SiteEnv/bin"
echo "VERSION_ZERO" > "$HOME_DIR/Roxy/index.py"
echo "old-venv" > "$HOME_DIR/SiteEnv/bin/marker"
touch "$HOME_DIR/.service_running" "$HOME_DIR/.pip_should_fail"

code=$(run_deploy)
check "exits non-zero" "$([ "$code" != "0" ] && echo 1 || echo 0)" "exit=$code"
check "UpdateBuild.sh survives" "$([ -f "$HOME_DIR/UpdateBuild.sh" ] && echo 1 || echo 0)"
check "the WORKING venv is still there" "$([ -f "$HOME_DIR/SiteEnv/bin/marker" ] && echo 1 || echo 0)"
check "the old site still serves" "$(grep -q VERSION_ZERO "$HOME_DIR/Roxy/index.py" 2>/dev/null && echo 1 || echo 0)"
check "the service is still running" "$([ -f "$HOME_DIR/.service_running" ] && echo 1 || echo 0)"
check "no half-built venv left behind" "$([ ! -e "$HOME_DIR/SiteEnv.new" ] && echo 1 || echo 0)"
rm -f "$HOME_DIR/.pip_should_fail"

echo ""
echo "== A clone that is missing app/ is refused =="
setup_home
BAD="$SANDBOX/badremote"
rm -rf "$BAD"; mkdir -p "$BAD/Tooling"
cp "$SRC_SCRIPT" "$BAD/Tooling/UpdateBuild.sh"
echo "x" > "$BAD/Tooling/alert_on_failure.py"
echo "gunicorn" > "$BAD/requirements.txt"
(cd "$BAD" && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm x)
sed "s|GITHUB_REPO_URL=.*|GITHUB_REPO_URL=\"$BAD\"|" "$SRC_SCRIPT" > "$HOME_DIR/UpdateBuild.sh"
chmod +x "$HOME_DIR/UpdateBuild.sh"
mkdir -p "$HOME_DIR/Roxy"; echo "VERSION_ZERO" > "$HOME_DIR/Roxy/index.py"
touch "$HOME_DIR/.service_running"
code=$(run_deploy)
check "exits non-zero" "$([ "$code" != "0" ] && echo 1 || echo 0)" "exit=$code"
check "says what was missing" "$(grep -q 'missing app' "$SANDBOX/out.log" && echo 1 || echo 0)" "$(tail -2 "$SANDBOX/out.log")"
check "the live site is untouched" "$(grep -q VERSION_ZERO "$HOME_DIR/Roxy/index.py" && echo 1 || echo 0)"
check "the service was never even stopped" "$([ -f "$HOME_DIR/.service_running" ] && echo 1 || echo 0)"

echo ""
echo "== A first-ever deploy onto a bare home works =="
setup_home
build_remote "$REMOTE" "VERSION_FOUR"
sed "s|GITHUB_REPO_URL=.*|GITHUB_REPO_URL=\"$REMOTE\"|" "$SRC_SCRIPT" > "$HOME_DIR/UpdateBuild.sh"
chmod +x "$HOME_DIR/UpdateBuild.sh"
# No ~/Roxy, no ~/SiteEnv, no ~/Tooling, service not running.
code=$(run_deploy)
check "exits 0" "$([ "$code" = "0" ] && echo 1 || echo 0)" "exit=$code $(tail -3 "$SANDBOX/out.log")"
check "the site is deployed" "$(grep -q VERSION_FOUR "$HOME_DIR/Roxy/index.py" 2>/dev/null && echo 1 || echo 0)"
check "UpdateBuild.sh is in home" "$([ -f "$HOME_DIR/UpdateBuild.sh" ] && echo 1 || echo 0)"

echo ""
echo "========================================"
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = "0" ] || exit 1
