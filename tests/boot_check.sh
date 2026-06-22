#!/bin/bash
# Boots the real Flask server against a sandbox /etc/roxy and curls key routes.
set -u
cd "$(dirname "$0")/.."

SANDBOX=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$SANDBOX"' EXIT

printf 'admin_credentials.txt\napp_password.txt\nauth_tokens.txt\nemails.txt\n' > "$SANDBOX/files.txt"
printf 'user\npass\nhmackey\nsecret\n' > "$SANDBOX/admin_credentials.txt"
printf 'apppw\n' > "$SANDBOX/app_password.txt"
printf 'FAKETOKEN\n' > "$SANDBOX/auth_tokens.txt"
printf 'a@x.com\nb@x.com\n' > "$SANDBOX/emails.txt"

cd app
ROXY_FILE_ROOT="$SANDBOX" ROXY_DATA_FILE="$SANDBOX/data.json" \
	ROXY_ROUTING_FILE="$SANDBOX/routing.json" ROXY_THROTTLE_FILE="$SANDBOX/throttle.json" \
	ROXY_COORD_FILE="$SANDBOX/coord.json" \
	../env2/bin/python -c "import index; index.app.run(port=5099)" > /tmp/roxy_boot.log 2>&1 &
SERVER_PID=$!
sleep 3

echo "home:               $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5099/)"
echo "admin login page:   $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5099/admin)"
echo "static css:         $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5099/static/dashboard.css)"
echo "static js:          $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5099/static/dashboard.js)"
echo "favicon:            $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5099/favicon.ico)"
echo "POST / (bot probe): $(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:5099/)"
echo "POST / body:        $(curl -s -X POST http://127.0.0.1:5099/ | head -c 120)"
echo "health:             $(curl -s http://127.0.0.1:5099/health)"
echo "dashboard (no session): $(curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}' http://127.0.0.1:5099/admin/dashboard)"

echo "boot log errors:"
grep -iE 'error|traceback|exception' /tmp/roxy_boot.log | grep -v "POST / HTTP" | head -5 || echo "  none"
