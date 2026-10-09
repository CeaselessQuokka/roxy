#!/bin/bash
# backup.sh: the nightly backup of Roxy's databases (roxy-backup.service, plan 17.1 and 17.5).
#
# What this is
#   Installed as /usr/local/lib/roxy/backup.sh (root, 0755) and run as root by roxy-backup.service every night,
#   and on request ("back up now" from the dashboard or `scripts/ctl.py backup-now`): the roxy user writes
#   /var/lib/roxy/backup-request and roxy-backup-request.path starts the same service.
#   For control.db and metrics.db (and hot.db when ROXY_BACKUP_HOT=1) it makes a consistent copy with SQLite's
#   VACUUM INTO, checks the copy with PRAGMA integrity_check, compresses it with zstd and tests the compressed
#   file, encrypts it with age when a recipients file exists, and stores the set in /var/backups/roxy/<date>/
#   with a SHA256SUMS file. Then it prunes old sets (14 daily and 8 weekly are kept), once every 28 days restores
#   the newest set into a temporary directory and checks it again, optionally copies the set off the box with
#   rclone (D15), and writes /var/lib/roxy/audit/backup.json (0640 root:roxy) for health check H-BACKUP.
#
# Why it exists
#   v1 had no backups. One Lightsail disk is a single point of failure, and a bad migration or a mistaken bulk
#   edit needs a way back. cache.db is never copied (it is disposable and rebuilt on demand), and the encryption
#   keys are never copied either (plan 9.8 key escrow: the owner keeps them offline), so a stolen backup does not
#   reveal the encrypted credential or TOTP secrets.
#
# How it works
#   VACUUM INTO writes a compact copy from one read transaction, so it is consistent while both colors keep
#   writing (no need to stop the service). The work happens in a hidden temporary directory that is renamed into
#   place only when every file passed its checks, so a half-made backup is never mistaken for a good one.
#   Any failure exits non-zero, which fails the unit and sends the "Roxy DOWN: roxy-backup.service failed" email
#   (OnFailure=), and records the failure in backup.json for the app's own "Roxy: backup failed" alert. Before the
#   first deploy has started a color there is no database at all; that is not a failure (no false alert), and the
#   run ends at once. Once /var/lib/roxy-deploy/deployed_version exists, a missing database is a failure again.
#   Python 3 from the system does the SQLite work (the sqlite3 command line tool is not installed by default).
#   The status file is the one place this root job writes into a tree another account controls: /var/lib/roxy
#   belongs to the roxy user, who could plant a link where root is about to write (a link to a backup would make
#   root overwrite it). status_tool therefore never follows a link: the directory audit/ is root's own (root:roxy
#   0750), opened with O_NOFOLLOW and accepted only when root owns it and nobody else can write to it (anything
#   else there is renamed aside, which moves a link, never its target), and the file is written to a new random
#   name with O_EXCL and O_NOFOLLOW, given its mode and group through the open file, then renamed into place.
#   A request is consumed first thing (whatever happens next, one request is one run, so the path unit cannot
#   loop): the file is read without following a link (at most 4 KiB; only a sanitized "by" and "requested_at" are
#   kept, since the roxy user wrote it) and removed (unlink, or a descriptor-based tree removal for a directory,
#   neither of which follows a link). A requested run within ROXY_BACKUP_MIN_GAP_S (10 minutes) of the last good
#   backup is skipped, so a flood of requests costs one short check each, never a backup each. backup.json records
#   every answered request under last_request (at, by, requested_at, outcome: ran, skipped_recent or
#   skipped_no_database).
#
# What to read next
#   deploy/systemd/roxy-backup.service (its sandbox), deploy/systemd/roxy-backup-request.path (the request),
#   deploy/README.md (restoring a backup), deploy/prestart.py (the pre-migration snapshots a deploy takes).

if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -Eeuo pipefail
# Backups are root's alone; the status file gets its own mode below.
umask 0077

STATE_DIR="${ROXY_STATE_DIR:-/var/lib/roxy}"
BACKUP_DIR="${ROXY_BACKUP_DIR:-/var/backups/roxy}"
STATUS_FILE="${ROXY_BACKUP_STATUS:-$STATE_DIR/audit/backup.json}"
STATUS_GROUP="${ROXY_BACKUP_STATUS_GROUP:-roxy}"
PYTHON3="${ROXY_PYTHON3:-/usr/bin/python3}"
ZSTD="${ROXY_ZSTD:-zstd}"
AGE="${ROXY_AGE:-age}"
RCLONE="${ROXY_RCLONE:-rclone}"
KEEP_DAILY="${ROXY_BACKUP_KEEP_DAILY:-14}"
KEEP_WEEKLY="${ROXY_BACKUP_KEEP_WEEKLY:-8}"
RECIPIENTS="${ROXY_BACKUP_AGE_RECIPIENTS:-/etc/roxy/backup-age-recipients}"
REMOTE="${ROXY_BACKUP_REMOTE:-}"
INCLUDE_HOT="${ROXY_BACKUP_HOT:-0}"
RESTORE_TEST_DAYS="${ROXY_BACKUP_RESTORE_TEST_DAYS:-28}"
# Written by the first successful deploy; until then an empty state directory is expected, not a failure.
DEPLOYED_VERSION="${ROXY_DEPLOYED_VERSION_FILE:-/var/lib/roxy-deploy/deployed_version}"
# The date of this set (UTC). Overridable so tests can make a month of backups in a second.
DATE="${ROXY_BACKUP_DATE:-$(date -u +%Y-%m-%d)}"
# "Back up now": the file roxy-backup-request.path watches, and the shortest gap between a good backup and a
# requested one (seconds).
REQUEST_FILE="${ROXY_BACKUP_REQUEST:-$STATE_DIR/backup-request}"
MIN_GAP_S="${ROXY_BACKUP_MIN_GAP_S:-600}"

STEP="start"
WORK=""

log() { printf 'backup: %s\n' "$*"; }

# Read or update the status file the app reads (H-BACKUP), never through a link (see the header).
#   status_tool due <days>                          prints yes when the monthly restore test is due
#   status_tool age                                 prints the seconds since the last good backup (-1: none)
#   status_tool update <kind> <detail> <date> <step> records success, failure, restore_test or request (the
#                                                   outcome goes in <step>); other fields stay
status_tool() {
  "$PYTHON3" -I - "$STATUS_FILE" "$STATUS_GROUP" "$@" <<'PY'
import calendar, contextlib, grp, json, os, secrets, stat, sys, time

path, group, op, args = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
directory, name = os.path.split(path)
parent, dir_name = os.path.split(directory)


def give_group(fd):
    # Unprivileged tests have no such group or no right to chown; production runs as root with CAP_CHOWN.
    with contextlib.suppress(KeyError, PermissionError):
        os.fchown(fd, -1, grp.getgrnam(group).gr_gid)


def trusted(fd):
    info = os.fstat(fd)
    return stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022


def open_dir(repair):
    """The status directory's descriptor, or None. With repair, make it (or replace an untrusted one)."""
    try:
        parent_fd = os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        for _ in range(3):
            try:
                fd = os.open(dir_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            except FileNotFoundError:
                if not repair:
                    return None
                os.mkdir(dir_name, 0o700, dir_fd=parent_fd)
                continue
            except OSError:  # a link (ELOOP) or not a directory (ENOTDIR): never followed
                fd = -1
            if fd >= 0 and trusted(fd):
                if repair:
                    os.fchmod(fd, 0o750)
                    give_group(fd)
                return fd
            if fd >= 0:
                os.close(fd)
            if not repair:
                return None
            aside = f"{dir_name}.untrusted-{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"
            os.rename(dir_name, aside, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            sys.stderr.write(f"backup: {directory} was not a directory only root controls; moved it to {aside}\n")
        sys.exit(f"backup: cannot make a trusted status directory at {directory}")
    finally:
        os.close(parent_fd)


def read_status(dir_fd):
    if dir_fd is None:
        return {}
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        return {}
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return {}
        try:
            value = json.loads(handle.read(1_000_000))
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def read_at(field):
    """The Unix time of `<field>.at` in the status file, 0 when there is none."""
    dir_fd = open_dir(repair=False)
    try:
        entry = read_status(dir_fd).get(field)
        last = entry.get("at", "") if isinstance(entry, dict) else ""
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    try:
        return calendar.timegm(time.strptime(last, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return 0


if op == "due":
    then = read_at("restore_test")
    print("yes" if time.time() - then >= int(args[0]) * 86400 else "no")
    sys.exit(0)

if op == "age":
    then = read_at("last_success")
    print(max(0, int(time.time() - then)) if then else -1)
    sys.exit(0)

kind, detail, date, step = args
dir_fd = open_dir(repair=True)
if dir_fd is None:
    sys.exit(f"backup: {parent} does not exist; status not written")
try:
    status = read_status(dir_fd)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if kind == "success":
        status["last_success"] = {"at": now, "date": date, "set": json.loads(detail)}
        status.pop("last_failure", None)
    elif kind == "failure":
        status["last_failure"] = {"at": now, "date": date, "step": step, "error": detail[-500:]}
    elif kind == "restore_test":
        status["restore_test"] = dict(json.loads(detail), at=now)
    elif kind == "request":
        # A "back up now" request this run answered; for this kind the step argument carries the outcome.
        status["last_request"] = dict(json.loads(detail), at=now, outcome=step)
    tmp = f".{name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write((json.dumps(status, indent=2) + "\n").encode("utf-8"))
            handle.flush()
            os.fchmod(handle.fileno(), 0o640)
            give_group(handle.fileno())
            os.fsync(handle.fileno())
        # rename() replaces whatever is at the status name (a planted link included) without following it.
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise
finally:
    os.close(dir_fd)
PY
}

# The status file the app reads (H-BACKUP). Fields not given keep their previous value.
write_status() {
  status_tool update "$1" "${2:-}" "$DATE" "$STEP"
}

on_exit() {
  local code=$?
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then rm -rf "$WORK"; fi
  if [ "$code" -ne 0 ]; then
    log "FAILED at step $STEP (exit $code)"
    write_status failure "failed at step $STEP (exit $code)" || true
  fi
  exit "$code"
}
trap on_exit EXIT

# Copy one database with VACUUM INTO and check the copy. Prints nothing on success.
copy_and_check() {
  local src="$1" dst="$2"
  "$PYTHON3" -I - "$src" "$dst" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1:3]
conn = sqlite3.connect(src, timeout=30)  # waits up to 30 s for a writer to finish (busy timeout)
try:
    conn.execute("VACUUM INTO ?", (dst,))
finally:
    conn.close()
copy = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
try:
    rows = [row[0] for row in copy.execute("PRAGMA integrity_check")]
finally:
    copy.close()
if rows != ["ok"]:
    sys.exit("integrity_check on the copy of " + src + " failed: " + "; ".join(map(str, rows[:5])))
PY
}

integrity_of() {
  "$PYTHON3" -I - "$1" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
try:
    rows = [row[0] for row in conn.execute("PRAGMA integrity_check")]
finally:
    conn.close()
sys.exit(0 if rows == ["ok"] else 1)
PY
}

make_set() {
  local db src encrypted=0
  local dbs=(control metrics)
  if [ "$INCLUDE_HOT" = 1 ]; then dbs=(control hot metrics); fi
  STEP="prepare"
  command -v "$ZSTD" >/dev/null || { log "zstd is not installed (apt install zstd)"; return 1; }
  mkdir -p "$BACKUP_DIR"
  chmod 0700 "$BACKUP_DIR"
  WORK="$(mktemp -d "$BACKUP_DIR/.tmp-$DATE.XXXXXX")"
  if [ -s "$RECIPIENTS" ]; then
    command -v "$AGE" >/dev/null || { log "$RECIPIENTS exists but age is not installed (apt install age)"; return 1; }
    encrypted=1
  fi
  for db in "${dbs[@]}"; do
    src="$STATE_DIR/$db.db"
    STEP="copy $db.db"
    [ -f "$src" ] || { log "$src does not exist"; return 1; }
    copy_and_check "$src" "$WORK/$db.db"
    STEP="compress $db.db"
    "$ZSTD" -q -T1 -6 --rm "$WORK/$db.db" -o "$WORK/$db.db.zst"
    "$ZSTD" -q -t "$WORK/$db.db.zst"
    if [ "$encrypted" = 1 ]; then
      STEP="encrypt $db.db"
      "$AGE" -R "$RECIPIENTS" -o "$WORK/$db.db.zst.age" "$WORK/$db.db.zst"
      rm -f "$WORK/$db.db.zst"
    fi
  done
  STEP="checksums"
  (cd "$WORK" && sha256sum -- * >SHA256SUMS)
  STEP="publish"
  local final="$BACKUP_DIR/$DATE" old=""
  if [ -e "$final" ]; then
    old="$BACKUP_DIR/.old-$DATE.$$"
    mv "$final" "$old"
  fi
  mv "$WORK" "$final"
  WORK=""
  if [ -n "$old" ]; then rm -rf "$old"; fi
  chmod 0700 "$final"
  log "wrote $final ($(find "$final" -mindepth 1 -maxdepth 1 -printf '%f '))"
  SET_DIR="$final"
  SET_ENCRYPTED="$encrypted"
}

# Keep the newest KEEP_DAILY sets, plus the newest set of each of the last KEEP_WEEKLY ISO weeks.
prune() {
  STEP="prune"
  local name
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    log "removing old set $name"
    rm -rf "${BACKUP_DIR:?}/$name"
  done < <(
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' \
      -printf '%f\n' | "$PYTHON3" -I -c '
import datetime, sys
keep_daily, keep_weekly = int(sys.argv[1]), int(sys.argv[2])
names = sorted({line.strip() for line in sys.stdin if line.strip()}, reverse=True)
keep = set(names[:keep_daily])
weeks = {}
for name in names:
    week = datetime.date.fromisoformat(name).isocalendar()[:2]
    weeks.setdefault(week, name)  # names are newest first, so the first one seen is the newest of its week
for week in sorted(weeks, reverse=True)[:keep_weekly]:
    keep.add(weeks[week])
for name in names:
    if name not in keep:
        print(name)
' "$KEEP_DAILY" "$KEEP_WEEKLY"
  )
}

# Every RESTORE_TEST_DAYS days: decompress the new set into a temporary directory and check each database again.
restore_test() {
  STEP="restore test"
  local due
  due="$(status_tool due "$RESTORE_TEST_DAYS")"
  [ "$due" = yes ] || return 0
  if [ "$SET_ENCRYPTED" = 1 ]; then
    write_status restore_test '{"ok": null, "detail": "the set is encrypted; the restore drill with the escrowed key is manual (plan 17.5)"}'
    log "restore test skipped: encrypted set (manual drill)"
    return 0
  fi
  local tmp file ok=true detail="restored and checked"
  tmp="$(mktemp -d)"
  for file in "$SET_DIR"/*.db.zst; do
    "$ZSTD" -q -d "$file" -o "$tmp/$(basename "$file" .zst)"
    if ! integrity_of "$tmp/$(basename "$file" .zst)"; then
      ok=false
      detail="integrity_check failed on $(basename "$file" .zst)"
    fi
  done
  rm -rf "$tmp"
  write_status restore_test "{\"ok\": $ok, \"detail\": \"$detail\", \"set\": \"$DATE\"}"
  log "restore test: $detail"
  [ "$ok" = true ]
}

push_remote() {
  [ -n "$REMOTE" ] || return 0
  STEP="rclone push"
  local config="${CREDENTIALS_DIRECTORY:-/nonexistent}/rclone_config"
  [ -s "$config" ] || { log "ROXY_BACKUP_REMOTE is set but the rclone_config credential is empty"; return 1; }
  [[ "$REMOTE" =~ ^[A-Za-z0-9_-]+$ ]] || { log "ROXY_BACKUP_REMOTE must be a remote name only"; return 1; }
  "$RCLONE" --config "$config" copy "$SET_DIR" "$REMOTE:roxy-backups/$DATE"
  log "copied the set to $REMOTE:roxy-backups/$DATE"
}

# True before the first deploy: no database exists yet and no deploy has been recorded. The timer runs from the
# moment install-system.sh enables it, so this window is normal and must not end in a "backup failed" alert.
nothing_to_back_up_yet() {
  local db
  [ ! -e "$DEPLOYED_VERSION" ] || return 1
  for db in control hot metrics; do
    [ ! -e "$STATE_DIR/$db.db" ] || return 1
  done
}

# "Back up now": take the request file away first thing (see the header). Sets REQUESTED (1 when this run answers
# a request) and REQUEST_INFO (the sanitized {"by", "requested_at"} of the request, as JSON).
REQUESTED=0
REQUEST_INFO='{}'
consume_request() {
  local info
  info="$("$PYTHON3" -I - "$REQUEST_FILE" <<'PY'
import json, os, re, shutil, stat, sys

path = sys.argv[1]
try:
    info = os.lstat(path)  # lstat: a link is looked at, never followed
except FileNotFoundError:
    sys.exit(0)
by, requested_at = "unknown", ""
if stat.S_ISREG(info.st_mode):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as handle:
            document = json.loads(handle.read(4096).decode("utf-8", "replace") or "{}")
    except (OSError, ValueError):
        document = {}
    if isinstance(document, dict):
        # The roxy user wrote this file: keep only short, plain words from it.
        by = re.sub(r"[^A-Za-z0-9:_.@-]", "", str(document.get("by", "")))[:80] or "unknown"
        requested_at = re.sub(r"[^0-9TZ:-]", "", str(document.get("requested_at", "")))[:20]
if stat.S_ISDIR(info.st_mode):
    shutil.rmtree(path)  # descriptor based on Linux: a link inside is removed, never followed
else:
    os.unlink(path)
print(json.dumps({"by": by, "requested_at": requested_at}))
PY
)"
  if [ -n "$info" ]; then
    REQUESTED=1
    REQUEST_INFO="$info"
  fi
}

# Record how this run answered the request (best effort: the status directory may not exist yet).
answer_request() {
  [ "$REQUESTED" = 1 ] || return 0
  status_tool update request "$REQUEST_INFO" "$DATE" "$1" || true
}

STEP="request"
consume_request

if nothing_to_back_up_yet; then
  log "no Roxy v2 database in $STATE_DIR and no deploy recorded yet; nothing to back up yet"
  answer_request skipped_no_database
  exit 0
fi

if [ "$REQUESTED" = 1 ]; then
  last_good_age="$(status_tool age)"
  if [ "$last_good_age" -ge 0 ] && [ "$last_good_age" -lt "$MIN_GAP_S" ]; then
    log "a backup finished ${last_good_age} s ago (less than ${MIN_GAP_S} s); this request is answered by it"
    answer_request skipped_recent
    exit 0
  fi
  log "running a requested backup ($REQUEST_INFO)"
  answer_request ran
fi

SET_DIR=""
SET_ENCRYPTED=0
make_set
prune
restore_test
push_remote
STEP="status"
write_status success "$("$PYTHON3" -I - "$SET_DIR" "$SET_ENCRYPTED" "$REMOTE" <<'PY'
import json, os, sys
path, encrypted, remote = sys.argv[1:4]
files = {name: os.path.getsize(os.path.join(path, name)) for name in sorted(os.listdir(path))}
print(json.dumps({"dir": path, "files": files, "encrypted": encrypted == "1", "remote": remote or None}))
PY
)"
log "done"
