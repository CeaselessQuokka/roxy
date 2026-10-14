#!/bin/bash
# install-system.sh: one-time (and re-runnable) root setup of the server pieces deploy.sh cannot install itself.
#
# What this is
#   Run as root from a checkout of the repository: `sudo deploy/install-system.sh`. It creates the accounts
#   (`roxy` for the service, `roxy-deploy` for GitHub Actions), the directories of plan 17.3 with their owners and
#   modes, and installs everything that must be root-owned: the systemd units and the journald drop-in, the
#   root-run tools in /usr/local/lib/roxy, the two wrappers in /usr/local/sbin, and the sudo rules (after `visudo`
#   accepts them in the form they are installed). It also installs the env examples and the deploy scripts when
#   they are missing, and enables the timers, the path watchers and roxy-boot.service.
#
# Why it exists
#   deploy.sh runs as the unprivileged deploy user and may only restart the two colors and call two wrappers (plan
#   9.14), so it can never install a unit, a root tool or a sudo rule. Those change rarely, and when they do, the
#   owner runs this script again from the new commit. Doing it with one reviewed script instead of a list of
#   commands means the modes and owners are always the ones roxy-audit.py checks.
#   It also runs on the live v1 server during the cutover. v1 (user ubuntu) keeps its state in /etc/roxy (mode
#   0700) and rewrites files there all the time, so taking that directory over (root:roxy 0750) would stop v1 at
#   its next save. While /etc/roxy belongs to another account, this script leaves its owner and mode alone and
#   only lets the deploy user pass through it with an ACL entry (`setfacl -m u:roxy-deploy:x`), which is what the
#   deploy needs to read the v2 env files (0640 root:roxy) by name. Nobody else gains anything, unlike a chmod
#   o+x, which would let every local account reach any v1 file a person ever created with a looser mode. After v1
#   is retired, `--take-over-etc` gives the directory to root:roxy 0750 and removes the ACL.
#
# How it works
#   Every step is idempotent: directories get their mode and owner set every time, files are installed with
#   `install -m` (replacing older copies), and files that hold local configuration (the env files, the
#   credential files) are only created when missing, never overwritten. Directories and those local files are
#   handled by descriptor (a small system Python helper, `SECURE_FS`), never by path, because some of them sit in
#   directories another account can change (the deploy user's /opt/roxy, v1's /etc/roxy). `--prefix DIR` installs under DIR without
#   creating accounts, changing owners or calling systemctl, which is how tests/deploy checks it (there,
#   ROXY_INSTALL_UID and ROXY_SETFACL stand in for root and setfacl; they are ignored on the real system). The
#   sudo rules are rendered for the deploy user into a temporary file, checked with `visudo -c`, and only then
#   renamed into /etc/sudoers.d (a rule file sudo cannot parse would stop sudo for everyone). Secrets are never
#   written by this script: it creates the optional credential files empty and lists the required ones missing.
#
# What to read next
#   deploy/README.md (the whole server setup and the cutover notes), then deploy/deploy.sh.

if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -Eeuo pipefail

SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX=""
DEPLOY_USER="roxy-deploy"
SERVICE_USER="roxy"
SYSTEM=1
TAKE_OVER_ETC=0

usage() {
  echo "usage: install-system.sh [--prefix DIR] [--deploy-user NAME] [--take-over-etc]" >&2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)
      PREFIX="${2:?}"
      SYSTEM=0
      shift
      ;;
    --deploy-user)
      DEPLOY_USER="${2:?}"
      shift
      ;;
    --take-over-etc)
      TAKE_OVER_ETC=1
      ;;
    *)
      usage
      exit 2
      ;;
  esac
  shift
done

# The name goes into useradd, the sudo rules (through sed) and an ACL entry: only a plain account name is safe in
# all three (a space or sudoers syntax would install rules visudo rejects, or rules for someone else).
if ! [[ "$DEPLOY_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "install-system.sh: --deploy-user must be a plain account name (lowercase letters, digits, _ and -)" >&2
  exit 2
fi

if [ "$SYSTEM" = 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "install-system.sh: run as root (sudo), or with --prefix for a test install" >&2
  exit 1
fi

# Who owns the root-owned pieces, and the ACL tool. On the server: root, and setfacl from the acl package. A
# --prefix test install runs as a normal user and may stand in its own values (never read on the server).
if [ "$SYSTEM" = 1 ]; then
  INSTALL_UID=0
  SETFACL="$(command -v setfacl || true)"
else
  INSTALL_UID="${ROXY_INSTALL_UID:-$(id -u)}"
  SETFACL="${ROXY_SETFACL:-}"
fi
VISUDO="$(command -v visudo || true)"

log() { printf 'install-system: %s\n' "$*"; }

# The system Python runs the descriptor-based helper below (it has os.fchmod, os.fchown and dir_fd; bash has not).
PYTHON3=/usr/bin/python3
[ -x "$PYTHON3" ] || PYTHON3="$(command -v python3 || true)"
# Where the helper's directory walk starts: / on the server, the real path of --prefix in a test install (set
# after the checks below, which must change nothing).
BASE=/

# Directories and local configuration files are made by descriptor, never by path. Some of them live in
# directories another account owns (/opt/roxy and so /opt/roxy/releases, deploy.sh and deploy_rollback.sh belong to
# the deploy user; /etc/roxy to v1's account until the cutover), and that account may rename entries there at any
# moment. chmod, chown and install by path follow a link swapped in after any check (finding sec-1: a link to
# /etc/systemd/system in place of /opt/roxy/releases, or to /etc/shadow in place of a deploy.sh this script is
# about to chown, would hand a root file to the deploy user, plan 9.14). So the helper walks the path one
# component at a time with O_NOFOLLOW (a link is followed only inside a directory no other account can write),
# opens the final directory with O_NOFOLLOW and changes its mode and owner through that descriptor (fchmod,
# fchown), and creates a file with O_CREAT|O_EXCL|O_NOFOLLOW under a temporary name, then links it into place
# (never over an existing name), so whatever stands at a name, root never writes or chowns through it.
SECURE_FS='
import errno, grp, os, pwd, shutil, stat, sys

PREFIX = "install-system.sh: "


def die(message):
    sys.stderr.write(PREFIX + message + "\n")
    sys.exit(1)


def ids(owner):
    """(uid, gid) of "user:group", or None in a --prefix install (no owner changes)."""
    if not owner:
        return None
    user, _, group = owner.partition(":")
    return pwd.getpwnam(user).pw_uid, grp.getgrnam(group or user).gr_gid


def trusted(fd):
    """A directory only this account (root on the server) can change, so a link in it was made by root."""
    st = os.fstat(fd)
    return st.st_uid == os.geteuid() and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def is_link(name, fd):
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def parent_of(base, shown):
    """A descriptor of the directory that holds the last component of the path, made as needed, and that name."""
    parts = [part for part in shown.split("/") if part]
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    for name in parts[:-1]:
        try:
            os.mkdir(name, 0o755, dir_fd=fd)
        except FileExistsError:
            pass
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if not (is_link(name, fd) and trusted(fd)):
            flags |= os.O_NOFOLLOW
        try:
            inner = os.open(name, flags, dir_fd=fd)
        except OSError as exc:
            if is_link(name, fd):
                die(f"{shown}: {name} is a symlink in a directory another account can change; refusing to follow it")
            die(f"{shown}: cannot open {name} ({exc.strerror})")
        os.close(fd)
        fd = inner
    return fd, parts[-1]


def directory(base, shown, mode, owner):
    fd, name = parent_of(base, shown)
    try:
        os.mkdir(name, 0o700, dir_fd=fd)  # opened up below, through the descriptor
    except FileExistsError:
        pass
    try:
        target = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except OSError as exc:
        if is_link(name, fd):
            die(f"{shown} is a symlink; refusing to change its target (remove the link and run this again)")
        die(f"{shown} is not a directory ({exc.strerror})")
    os.fchmod(target, int(mode, 8))
    wanted = ids(owner)
    if wanted is not None:
        os.fchown(target, *wanted)


def file_once(base, source, shown, mode, owner):
    fd, name = parent_of(base, shown)
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        print(f"install-system: keeping the existing {shown}")
        return
    temporary = f".{name}.install-{os.getpid()}"
    out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        with open(source, "rb") as data, os.fdopen(out, "wb", closefd=False) as handle:
            shutil.copyfileobj(data, handle)
        os.fchmod(out, int(mode, 8))
        wanted = ids(owner)
        if wanted is not None:
            os.fchown(out, *wanted)
        try:
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        except FileExistsError:
            print(f"install-system: keeping the existing {shown}")
    finally:
        os.close(out)
        try:
            os.unlink(temporary, dir_fd=fd)  # unlink never follows a link, whatever now stands at the name
        except FileNotFoundError:
            pass


command, base = sys.argv[1], sys.argv[2]
if command == "dir":
    directory(base, *sys.argv[3:6])
elif command == "file-once":
    file_once(base, *sys.argv[3:7])
else:
    die(f"unknown helper command {command}")
'

# Run the helper; the owner is only passed on the real system (a --prefix install changes no owner).
secure_fs() {
  "$PYTHON3" -I -c "$SECURE_FS" "$@"
}

# A directory with an exact mode, and (on the real system) an owner and group, never through a symlink (above).
directory() {
  local owner=""
  if [ "$SYSTEM" = 1 ]; then owner="$3"; fi
  secure_fs dir "$BASE" "$1" "$2" "$owner"
}

# Install one file into a root-owned directory (replacing an older copy). No other account can rename entries in
# these directories (/etc/systemd/system, /usr/local/lib/roxy, /usr/local/sbin, /etc/sudoers.d), so by path is safe.
file() {
  local source="$1" target="$PREFIX$2" mode="$3" owner="$4"
  install -D -m "$mode" "$source" "$target"
  if [ "$SYSTEM" = 1 ]; then chown "$owner" "$target"; fi
}

# Install a file only when nothing stands at its name yet (local configuration is never overwritten), through the
# descriptor helper: these files live in directories another account may own (/opt/roxy, a v1 /etc/roxy).
file_once() {
  local owner=""
  if [ "$SYSTEM" = 1 ]; then owner="$4"; fi
  secure_fs file-once "$BASE" "$1" "$2" "$3" "$owner"
}

# Checks that can refuse the whole run come first, so a refusal changes nothing.
ETC="$PREFIX/etc/roxy"
ETC_SHARED=0
if [ "$TAKE_OVER_ETC" = 0 ] && [ -d "$ETC" ] && [ "$(stat -c %u "$ETC")" != "$INSTALL_UID" ]; then
  # Roxy v1 still lives here (its account owns the directory): share it, never take it.
  ETC_SHARED=1
  if [ -z "$SETFACL" ]; then
    echo "install-system.sh: /etc/roxy belongs to $(stat -c %U "$ETC") (Roxy v1 keeps its state there), so this" \
      "script must not change its owner or mode. The deploy user is let through it with an ACL entry, which needs" \
      "setfacl: sudo apt install acl, then run this again. Nothing was changed." >&2
    exit 1
  fi
fi
if [ "$SYSTEM" = 1 ] && [ -z "$VISUDO" ]; then
  echo "install-system.sh: visudo is missing; sudo rules are never installed unchecked. Nothing was changed." >&2
  exit 1
fi
if [ -z "$PYTHON3" ]; then
  echo "install-system.sh: python3 is missing (Ubuntu ships it); directories are never set up by path. Nothing" \
    "was changed." >&2
  exit 1
fi
if [ "$SYSTEM" = 0 ]; then
  mkdir -p "$PREFIX"
  BASE="$(cd "$PREFIX" && pwd -P)"
fi

if [ "$SYSTEM" = 1 ]; then
  getent group "$SERVICE_USER" >/dev/null || groupadd --system "$SERVICE_USER"
  getent passwd "$SERVICE_USER" >/dev/null ||
    useradd --system --gid "$SERVICE_USER" --home-dir /var/lib/roxy --no-create-home --shell /usr/sbin/nologin \
      "$SERVICE_USER"
  getent passwd "$DEPLOY_USER" >/dev/null || useradd --create-home --shell /bin/bash "$DEPLOY_USER"
  usermod -a -G "$SERVICE_USER" "$DEPLOY_USER" # the internal sockets are 0660 roxy:roxy
fi

log "directories (plan 17.3)"
directory /opt/roxy 0755 "$DEPLOY_USER:$DEPLOY_USER"
directory /opt/roxy/releases 0755 "$DEPLOY_USER:$DEPLOY_USER"
directory /var/lib/roxy-deploy 0755 "$DEPLOY_USER:$DEPLOY_USER"
if [ "$ETC_SHARED" = 1 ]; then
  log "WARNING: /etc/roxy belongs to $(stat -c %U "$ETC"), not root: Roxy v1 still keeps its state there. Its owner," \
    "group and mode stay as they are; $DEPLOY_USER may only pass through it (ACL u:$DEPLOY_USER:x) to read the v2" \
    "env files. After v1 is retired run: sudo deploy/install-system.sh --take-over-etc"
  "$SETFACL" -m "u:$DEPLOY_USER:x" "$ETC"
else
  if [ "$TAKE_OVER_ETC" = 1 ] && [ -d "$ETC" ] && [ -n "$SETFACL" ]; then
    # The cutover's ACL entry is no longer needed; root:roxy 0750 below is the whole rule again (plan 17.3).
    "$SETFACL" -b "$ETC"
  fi
  directory /etc/roxy 0750 "root:$SERVICE_USER"
fi
directory /etc/roxy/credentials 0700 root:root
# The state directory exists before any color starts, so the audit and backup sandboxes (ReadWritePaths) can be
# set up from their first timer run. Its audit/ subdirectory (root:roxy 0750, for perms.json and backup.json) is
# made by those root jobs themselves, without following links, because the roxy user owns this directory.
directory /var/lib/roxy 0750 "$SERVICE_USER:$SERVICE_USER"
directory /var/backups/roxy 0700 root:root
directory /usr/local/lib/roxy 0755 root:root
directory /var/www/letsencrypt 0755 root:root

log "systemd units and the journald drop-in"
for unit in "$SOURCE"/deploy/systemd/*.service "$SOURCE"/deploy/systemd/*.timer "$SOURCE"/deploy/systemd/*.path; do
  file "$unit" "/etc/systemd/system/$(basename "$unit")" 0644 root:root
done
file "$SOURCE/deploy/systemd/journald-roxy.conf" /etc/systemd/journald.conf.d/roxy.conf 0644 root:root

log "root tools and wrappers"
for tool in alert_on_failure.py backup.sh roxy-audit.py; do
  file "$SOURCE/deploy/tools/$tool" "/usr/local/lib/roxy/$tool" 0755 root:root
done
for wrapper in roxy-nginx-apply roxy-switch-color; do
  file "$SOURCE/deploy/tools/$wrapper" "/usr/local/sbin/$wrapper" 0755 root:root
done

log "sudo rules"
RENDERED="$(mktemp)"
trap 'rm -f "$RENDERED"' EXIT
sed "s/^User_Alias ROXY_DEPLOYERS = .*/User_Alias ROXY_DEPLOYERS = $DEPLOY_USER/" "$SOURCE/deploy/sudoers/roxy-deploy" \
  >"$RENDERED"
if ! grep -qx "User_Alias ROXY_DEPLOYERS = $DEPLOY_USER" "$RENDERED"; then
  echo "install-system.sh: the sudo rules could not be written for $DEPLOY_USER; nothing was installed there" >&2
  exit 1
fi
# The exact file that will be installed is what visudo checks (a test install without visudo skips this).
if [ -n "$VISUDO" ] && ! "$VISUDO" -c -q -f "$RENDERED" >/dev/null; then
  echo "install-system.sh: visudo rejected the sudo rules for $DEPLOY_USER; /etc/sudoers.d was not changed" >&2
  exit 1
fi
# Into place by rename: sudo skips file names containing a dot, so it never reads the half-copied temporary file.
file "$RENDERED" /etc/sudoers.d/.roxy-deploy.new 0440 root:root
mv -f "$PREFIX/etc/sudoers.d/.roxy-deploy.new" "$PREFIX/etc/sudoers.d/roxy-deploy"

log "configuration (only when missing)"
file_once "$SOURCE/deploy/env/roxy.env.example" /etc/roxy/roxy.env 0640 "root:$SERVICE_USER"
file_once "$SOURCE/deploy/env/blue.env.example" /etc/roxy/blue.env 0640 "root:$SERVICE_USER"
file_once "$SOURCE/deploy/env/green.env.example" /etc/roxy/green.env 0640 "root:$SERVICE_USER"
file_once "$SOURCE/deploy/deploy.sh" /opt/roxy/deploy.sh 0755 "$DEPLOY_USER:$DEPLOY_USER"
file_once "$SOURCE/deploy/deploy_rollback.sh" /opt/roxy/deploy_rollback.sh 0755 "$DEPLOY_USER:$DEPLOY_USER"

log "credentials (names only; this script never writes a secret)"
for optional in alert_webhook_url rotator_url rclone_config; do
  target="$PREFIX/etc/roxy/credentials/$optional"
  if [ ! -e "$target" ]; then
    install -m 0600 /dev/null "$target"
    log "created an empty $optional (empty means not configured)"
  fi
done
missing=()
for required in roblox_credential smtp_password alert_emails credential_encryption_key totp_encryption_key ip_hash_key; do
  [ -s "$PREFIX/etc/roxy/credentials/$required" ] || missing+=("$required")
done
if [ "${#missing[@]}" -gt 0 ]; then
  log "still missing in /etc/roxy/credentials (root, 0600 each): ${missing[*]}"
fi

if [ "$SYSTEM" = 1 ]; then
  systemctl daemon-reload
  systemctl restart systemd-journald
  systemctl enable --now roxy-backup.timer roxy-audit.timer roxy-audit.path roxy-deploy-alert.path \
    roxy-backup-request.path
  systemctl enable roxy-boot.service
fi
log "done"
