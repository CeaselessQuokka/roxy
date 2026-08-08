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

# The script under test, rewritten to clone from a local path instead of GitHub.
local_variant() {
	sed "s|GITHUB_REPO_URL=.*|GITHUB_REPO_URL=\"$1\"|" "$SRC_SCRIPT"
}

# --- A fake "GitHub" repo the script can clone -------------------------------
# The copy inside the remote is ALSO pointed at the local remote. It has to be:
# the script replaces itself from the clone on every run, so a remote carrying
# the stock GitHub URL would make the *second* deploy in a test go and fetch the
# real repository over the network.
build_remote() {
	local remote="$1" marker="$2"
	rm -rf "$remote"
	mkdir -p "$remote/app" "$remote/Tooling"
	echo "$marker" > "$remote/app/index.py"
	echo "gunicorn" > "$remote/requirements.txt"
	local_variant "$remote" > "$remote/Tooling/UpdateBuild.sh"
	echo "print('alert')" > "$remote/Tooling/alert_on_failure.py"
	echo "unit" > "$remote/Tooling/roxy.service"
	(cd "$remote" && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm x)
}

# Install the script into the fake home, pointed at the fake remote.
install_script() {
	local_variant "$1" > "$HOME_DIR/UpdateBuild.sh"
	chmod +x "$HOME_DIR/UpdateBuild.sh"
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
	# A venv that is cheap to make. It records the path it was built at and bakes
	# that path into its console scripts' shebangs, exactly as a real venv does —
	# which is what makes the "built elsewhere then moved" bug detectable here.
	cat > "$HOME_DIR/bin/python3" <<'EOF'
#!/bin/bash
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "venv" ]; then
  echo "$3" >> "$HOME/.venv_created_at"
  mkdir -p "$3/bin"
  printf '#!/bin/bash\nexit 0\n' > "$3/bin/python"
  # pip stays a plain bash script so it is directly runnable as a test double.
  cat > "$3/bin/pip" <<'PIP'
#!/bin/bash
[ -f "$HOME/.pip_should_fail" ] && { echo "pip exploded" >&2; exit 1; }
exit 0
PIP
  # gunicorn is what the systemd unit actually execs, so ITS shebang is the one
  # that breaks if the venv is relocated after creation — that is what
  # venv_is_usable inspects.
  printf '#!%s/bin/python\nexit 0\n' "$3" > "$3/bin/gunicorn"
  chmod +x "$3/bin/python" "$3/bin/pip" "$3/bin/gunicorn"
  exit 0
fi
exec /usr/bin/python3 "$@"
EOF
	chmod +x "$HOME_DIR/bin/"*
}

# A venv is only usable where it was built: every console script carries an
# absolute shebang. Returns 0 if ~/SiteEnv's scripts point at ~/SiteEnv.
venv_is_usable() {
	local shebang
	[ -f "$HOME_DIR/SiteEnv/bin/gunicorn" ] || return 1
	shebang=$(head -1 "$HOME_DIR/SiteEnv/bin/gunicorn")
	case "$shebang" in
	"#!$HOME_DIR/SiteEnv/bin/"*) return 0 ;;
	*) return 1 ;;
	esac
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
install_script "$REMOTE"
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
# The regression that made every deploy fail: a venv built at SiteEnv.new and
# then renamed keeps shebangs pointing at SiteEnv.new, so systemd's
# ExecStart=.../SiteEnv/bin/gunicorn dies with "bad interpreter".
check "the venv is USABLE where it landed (shebangs match)" "$(venv_is_usable && echo 1 || echo 0)" \
	"gunicorn shebang: $(head -1 "$HOME_DIR/SiteEnv/bin/gunicorn" 2>/dev/null)"
check "...because it was built at its final path" \
	"$([ "$(cat "$HOME_DIR/.venv_created_at" 2>/dev/null)" = "$HOME_DIR/SiteEnv" ] && echo 1 || echo 0)" \
	"built at: $(cat "$HOME_DIR/.venv_created_at" 2>/dev/null)"
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
install_script "$REMOTE"
mkdir -p "$HOME_DIR/Roxy"; touch "$HOME_DIR/.service_running"
code=$(run_deploy)
check "exits 0" "$([ "$code" = "0" ] && echo 1 || echo 0)" "exit=$code"
check "home now has the NEWER script" "$(grep -q 'NEWER VERSION MARKER' "$HOME_DIR/UpdateBuild.sh" && echo 1 || echo 0)"
check "the backup is gone on success" "$([ ! -f "$HOME_DIR/UpdateBuild.sh.bak" ] && echo 1 || echo 0)"

echo ""
echo "== A clone failure must not brick the server =="
# This is the exact scenario that broke the real box: the remote is unreachable.
setup_home
install_script "$SANDBOX/does-not-exist"
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
install_script "$REMOTE"
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
install_script "$BAD"
mkdir -p "$HOME_DIR/Roxy"; echo "VERSION_ZERO" > "$HOME_DIR/Roxy/index.py"
touch "$HOME_DIR/.service_running"
code=$(run_deploy)
check "exits non-zero" "$([ "$code" != "0" ] && echo 1 || echo 0)" "exit=$code"
check "says what was missing" "$(grep -q 'missing app' "$SANDBOX/out.log" && echo 1 || echo 0)" "$(tail -2 "$SANDBOX/out.log")"
check "the live site is untouched" "$(grep -q VERSION_ZERO "$HOME_DIR/Roxy/index.py" && echo 1 || echo 0)"
check "the service was never even stopped" "$([ -f "$HOME_DIR/.service_running" ] && echo 1 || echo 0)"

echo ""
echo "== Running it with `sh` still works =="
# Ubuntu's /bin/sh is dash, which has no `set -o pipefail`. Typing
# `sh UpdateBuild.sh` is a natural thing to do while poking at a broken deploy,
# and it used to abort immediately on the script's own safety setup.
setup_home
build_remote "$REMOTE" "VERSION_SH"
install_script "$REMOTE"
mkdir -p "$HOME_DIR/Roxy"; touch "$HOME_DIR/.service_running"
env -i HOME="$HOME_DIR" PATH="$HOME_DIR/bin:/usr/local/bin:/usr/bin:/bin" \
	sh "$HOME_DIR/UpdateBuild.sh" > "$SANDBOX/sh.log" 2>&1
code=$?
check "sh UpdateBuild.sh exits 0" "$([ "$code" = "0" ] && echo 1 || echo 0)" "exit=$code $(tail -2 "$SANDBOX/sh.log")"
check "...without an 'Illegal option' error" "$(grep -qi 'illegal option' "$SANDBOX/sh.log" && echo 0 || echo 1)"
check "...and actually deploys" "$(grep -q VERSION_SH "$HOME_DIR/Roxy/index.py" 2>/dev/null && echo 1 || echo 0)"

echo ""
echo "== An unchanged requirements.txt skips the venv rebuild =="
setup_home
build_remote "$REMOTE" "VERSION_A"
install_script "$REMOTE"
touch "$HOME_DIR/.service_running"
code=$(run_deploy)   # first deploy: builds the venv
check "the first deploy builds a venv" "$([ "$(wc -l < "$HOME_DIR/.venv_created_at")" = "1" ] && echo 1 || echo 0)"
build_remote "$REMOTE" "VERSION_B"   # same requirements.txt, new app code
code=$(run_deploy)
check "the second deploy exits 0" "$([ "$code" = "0" ] && echo 1 || echo 0)" "exit=$code"
check "...ships the new code" "$(grep -q VERSION_B "$HOME_DIR/Roxy/index.py" 2>/dev/null && echo 1 || echo 0)"
check "...and does NOT rebuild the venv" "$([ "$(wc -l < "$HOME_DIR/.venv_created_at")" = "1" ] && echo 1 || echo 0)" \
	"builds: $(wc -l < "$HOME_DIR/.venv_created_at")"
echo "flask==3.1.2" >> "$REMOTE/requirements.txt"
(cd "$REMOTE" && git add -A && git -c user.email=t@t -c user.name=t commit -qm reqs)
code=$(run_deploy)
check "changing requirements DOES rebuild it" "$([ "$(wc -l < "$HOME_DIR/.venv_created_at")" = "2" ] && echo 1 || echo 0)" \
	"builds: $(wc -l < "$HOME_DIR/.venv_created_at")"
check "...and it is still usable" "$(venv_is_usable && echo 1 || echo 0)"

echo ""
echo "== A pip failure leaves a USABLE venv behind =="
# Rolling back has to restore the old venv to its ORIGINAL path, or its
# shebangs stop matching and the site cannot start even though the files exist.
setup_home
build_remote "$REMOTE" "VERSION_C"
install_script "$REMOTE"
touch "$HOME_DIR/.service_running"
run_deploy > /dev/null                       # establish a good venv
echo "extra==1.0" >> "$REMOTE/requirements.txt"   # force a rebuild...
(cd "$REMOTE" && git add -A && git -c user.email=t@t -c user.name=t commit -qm reqs2)
touch "$HOME_DIR/.pip_should_fail"           # ...that fails
code=$(run_deploy)
check "exits non-zero" "$([ "$code" != "0" ] && echo 1 || echo 0)" "exit=$code"
check "the restored venv is usable" "$(venv_is_usable && echo 1 || echo 0)" \
	"gunicorn shebang: $(head -1 "$HOME_DIR/SiteEnv/bin/gunicorn" 2>/dev/null)"
check "the service is running" "$([ -f "$HOME_DIR/.service_running" ] && echo 1 || echo 0)"
rm -f "$HOME_DIR/.pip_should_fail"

echo ""
echo "== A first-ever deploy onto a bare home works =="
setup_home
build_remote "$REMOTE" "VERSION_FOUR"
install_script "$REMOTE"
# No ~/Roxy, no ~/SiteEnv, no ~/Tooling, service not running.
code=$(run_deploy)
check "exits 0" "$([ "$code" = "0" ] && echo 1 || echo 0)" "exit=$code $(tail -3 "$SANDBOX/out.log")"
check "the site is deployed" "$(grep -q VERSION_FOUR "$HOME_DIR/Roxy/index.py" 2>/dev/null && echo 1 || echo 0)"
check "UpdateBuild.sh is in home" "$([ -f "$HOME_DIR/UpdateBuild.sh" ] && echo 1 || echo 0)"

echo ""
echo "========================================"
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = "0" ] || exit 1
