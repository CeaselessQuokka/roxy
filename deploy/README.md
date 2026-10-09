# Roxy v2 operations files (`deploy/`)

Everything that runs Roxy on the server lives here: the gunicorn config, the systemd units, the nginx site, the
blue/green deploy and its rollback, the root wrappers the deploy may call through sudo, backups, alerts and the
permission audit (plan section 17). Every file explains each setting next to the setting itself. This page is the
map; `MIGRATION.md` (phase P14) walks through the cutover from v1 step by step.

## What is here, and where it goes on the server

| Repository file | Installed as | Owner, mode | Installed by |
|---|---|---|---|
| `gunicorn.conf.py`, `prestart.py` | inside each release, `/opt/roxy/releases/<sha>/deploy/` | deploy user, 0644 | `deploy.sh` |
| `deploy.sh`, `deploy_rollback.sh` | `/opt/roxy/deploy.sh`, `/opt/roxy/deploy_rollback.sh` | deploy user, 0755 | the workflow bootstrap, then each successful deploy |
| `systemd/roxy@.service` and the other units | `/etc/systemd/system/` | root, 0644 | `install-system.sh` |
| `systemd/journald-roxy.conf` | `/etc/systemd/journald.conf.d/roxy.conf` | root, 0644 | `install-system.sh` |
| `tools/alert_on_failure.py`, `tools/backup.sh`, `tools/roxy-audit.py` | `/usr/local/lib/roxy/` | root, 0755 | `install-system.sh` |
| `tools/roxy-nginx-apply`, `tools/roxy-switch-color` | `/usr/local/sbin/` | root, 0755 | `install-system.sh` |
| `sudoers/roxy-deploy` | `/etc/sudoers.d/roxy-deploy` | root, 0440 | `install-system.sh` (after `visudo -c`) |
| `env/*.env.example` | `/etc/roxy/roxy.env`, `blue.env`, `green.env` | root:roxy, 0640 | `install-system.sh` (only when missing) |
| `nginx/*` | `/etc/nginx/sites-available/roxy-v2.conf` (rendered), `/etc/nginx/roxy-upstream-{blue,green}.conf`, `/etc/nginx/snippets/roxy-security-headers.conf` | root, 0644 | `roxy-nginx-apply`, from the verified commit only |

## Server layout (plan 17.3, with two corrections)

| Path | Owner, mode | Purpose |
|---|---|---|
| `/opt/roxy/releases/<sha>/` | deploy user, 0755 | One release with its own `.venv` and `build/public/static/` |
| `/opt/roxy/releases/current-blue`, `current-green` | symlinks | The release each color runs |
| `/opt/roxy/python/` | deploy user, 0755 | uv-managed Python 3.12 (the service cannot see `/home`, so not under the deploy user's home) |
| `/opt/roxy/repo.git` | deploy user | Mirror the deploy fetches exact commits from |
| `/usr/local/lib/roxy/` | root, 0755 | Root-run tools (correction: the plan had `/opt/roxy/tools`; inside a directory the deploy user owns, the deploy user could swap the tools that root runs) |
| `/usr/local/sbin/roxy-nginx-apply`, `roxy-switch-color` | root, 0755 | The only commands the deploy user may run with sudo |
| `/etc/roxy/` | root:roxy, 0750 | `roxy.env`, `blue.env`, `green.env`, `nginx-hints.env`, `credentials/` (root, 0700; files 0600). While v1 still lives here the directory stays v1's (see "Running beside v1") |
| `/var/lib/roxy/` | roxy, 0750 | Databases and `snapshots/` (pre-migration copies); created by `install-system.sh` so the root jobs can start before the first deploy |
| `/var/lib/roxy/audit/` | root:roxy, 0750 | `perms.json` (roxy-audit) and `backup.json` (backup.sh). Root's own directory inside the roxy user's: the root jobs create it and write it without ever following a link the roxy user could plant |
| `/var/lib/roxy-deploy/` | deploy user, 0755 | Deploy lock, `deployed_version`, `last_deploy.json`, `last_failure.json`, low-memory markers (correction: the plan put `deployed_version` in `/var/lib/roxy`, which the deploy user cannot write) |
| `/var/lib/roxy-nginx-apply/` | root, 0755 | The wrapper's own git mirror (0700) and `applied.json` |
| `/run/roxy-blue/`, `/run/roxy-green/` | roxy, 0750 | `internal.sock` and `gunicorn.ctl`, both 0660 |
| `/var/backups/roxy/` | root, 0700 | Nightly backups |

## Accounts

- `roxy` runs the service. It owns the databases and nothing else; the code it runs is read-only to it.
- `roxy-deploy` is the account GitHub Actions logs in as (`LIGHTSAIL_USER`). It is a member of group `roxy` so it can
  reach the internal sockets, and its only sudo rights are in `sudoers/roxy-deploy`. Do not deploy as `ubuntu`: on
  Lightsail that account has unrestricted sudo, which would make the sudo rules pointless.

## First setup (summary)

1. `sudo apt install nginx zstd acl` (and `age` for encrypted backups, `rclone` for off-box copies). Let's Encrypt
   certificates for the site come from certbot as today. `acl` is needed while v1 still owns `/etc/roxy`.
2. From a checkout of the commit you will deploy: `sudo deploy/install-system.sh`. On the v1 server it leaves
   v1's `/etc/roxy` as it is (see "Running beside v1").
3. Edit `/etc/roxy/roxy.env`: set `ROXY_DEPLOY_REPO_URL` to the GitHub repository and check `ROXY_SITE_ORIGIN`.
4. Put the secrets in `/etc/roxy/credentials/`, one file each, root 0600: `roblox_credential`, `smtp_password`,
   `alert_emails` (`to:` and `from:` lines), `credential_encryption_key`, `totp_encryption_key`, `ip_hash_key`, and
   when used `rotator_url`, `alert_webhook_url`, `rclone_config`. Empty means "not configured". The install script
   lists the required ones that are still missing.
5. In `/etc/nginx/nginx.conf` set `worker_processes 2;` and, in `events`, `worker_connections 4096;` (plan 17.2; a
   site file cannot set them). Remove `/etc/nginx/sites-enabled/default`: its `default_server` collides with Roxy's.
6. As `roxy-deploy`, install uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`), then run the first deploy by
   hand: `/opt/roxy/deploy.sh <full commit sha>`. It starts blue and points nginx at it. While v1's nginx site is
   still enabled, v1 answers the public host name, so run this first deploy as
   `ROXY_DEPLOY_PUBLIC_CHECK=0 /opt/roxy/deploy.sh <full commit sha>` (see "Running beside v1").

## How a deploy runs

`deploy.sh <sha>` (see its header for every step): fetch exactly that commit (it must be on `main`), build the
release and its venv while the live color serves, restart the idle color (its pre-start step snapshots control.db and
applies the expand migrations as the `roxy` user), wait until its internal socket reports the new version, run
`scripts/smoke_remote.py`, install the nginx config through `roxy-nginx-apply` if it changed, switch nginx with
`roxy-switch-color`, watch for 60 s, then stop the old color. The watch checks the new color's internal socket and
the public `/health` through nginx, which must be Roxy v2's own answer (it has a `Degraded` key; v1's has not). Any
failure before the old color stops switches nginx back, re-installs the nginx config the old color ran with (when
this release had installed its own), and stops the new color; the run exits non-zero and `roxy-deploy-alert.path`
sends "Roxy: deploy <short sha> failed at step <n>". The repository URL is logged without any `user:password@`
part. Releases are built with compiled bytecode (`uv sync --compile-bytecode`), because the service cannot write
bytecode into its read-only release.

Low-memory mode (DESIGN.md section 0): when less than 700 MB is available before the restart, the idle color starts
with one worker and grows to `ROXY_WORKERS` after the old color stopped, through the gunicorn control socket (the
same code as gunicorn's SIGTTIN handler; the deploy user may not signal the `roxy` user's processes). Force it with
`--low-memory`, or turn it off with `--no-low-memory`.

Rollback: `/opt/roxy/deploy_rollback.sh` goes back to the release the other color last ran, with the same health gate;
`/opt/roxy/deploy_rollback.sh <sha>` goes to any release still in `/opt/roxy/releases` (the newest five are kept).

## Contract migrations (by hand, never automatic)

Expand migrations (new tables, columns, indexes) run automatically in each color's pre-start step. Contract
migrations (drops and renames, `-- kind: contract`) run "one release later" (plan 17.4 step 3), and only by hand:
run automatically they would break every kept release older than the one that shipped them, and
`deploy_rollback.sh <sha>` can start any of the five kept releases. The pre-start step names pending contract
migrations in the journal (`journalctl -u roxy@blue -u roxy@green | grep "contract migrations pending"`).
When the release that shipped a contract migration is live and you will not roll back past it, run it as the `roxy`
user with the live release (here blue; use the color nginx points at):

```
sudo systemd-run --wait --pipe --uid=roxy --gid=roxy -p UMask=0027 \
  /opt/roxy/releases/current-blue/.venv/bin/python -m roxy.storage.migrate --expand --contract \
  --state-dir /var/lib/roxy
```

Running it as `roxy` keeps every database file (and SQLite's `-wal` and `-shm` files) owned by the service. After
that, roll back only to releases that contain the same migration file.

## Dependency audit at deploy (health check H-VERSION)

CI's `dependency-audit` job runs pip-audit on the locked dependencies; its counts (all known advisories, the ones with
a fixed version, and their ids) are outputs of `ci.yml`, and `deploy.yml` passes them to `deploy.sh` as
`ROXY_ADVISORY_COUNT`, `ROXY_ADVISORY_FIXABLE` and `ROXY_ADVISORY_IDS`. Step 9 writes them, with the commit, to
`/var/lib/roxy-deploy/advisories.json` (0644, read by the service for H-VERSION) and keeps a copy in the release as
`.roxy-advisories.json`, which a rollback puts back. A deploy started by hand has no CI result, so the record says
`"count": null, "source": "not_recorded"` and H-VERSION shows "advisories not recorded"; it never guesses a zero. To
record an audit for a hand deploy, pass the variables yourself (`ROXY_ADVISORY_COUNT=0 /opt/roxy/deploy.sh <sha>`).

## Operator CLI (`scripts/ctl.py`)

For when the dashboard cannot be reached (nginx down, locked out, under attack). Run it as the `roxy` user with the
live release, for example on blue:

```
sudo -u roxy /opt/roxy/releases/current-blue/.venv/bin/python /opt/roxy/releases/current-blue/scripts/ctl.py status
```

| Command | What it does | Door |
|---|---|---|
| `status` | Both colors' internal sockets, pause and throttle-all, config version, leader, active bans, last backup | both |
| `pause [--reason]`, `resume` | The maintenance switch (503 for every proxy request) | databases |
| `throttle-all on\|off [--reason]` | The emergency per-IP limit | databases |
| `purge-cache --all --yes \| --host H \| --pattern P [--regex] \| --id ID \| --rule N \| --expired [--preview]` | A fleet-wide cache purge | databases |
| `reset preview --scope S ...`, then `reset run ... --digest D --reason R [--confirm PHRASE]` | A Data page reset scope (plan 6.8); the run must match the preview | socket |
| `export-llm --window 7d --detail full --out FILE` | The plan 12 LLM export, written 0600 | socket |
| `health-run [--check ID ...] [--include-credential]` | Check Proxy Health (exit 1 when a check fails) | socket |
| `backup-now [--wait SECONDS]` | Writes `/var/lib/roxy/backup-request`; `roxy-backup-request.path` starts `backup.sh` | databases |
| `leader`, `jobs` | The leader lease and heartbeats, and the leader's published job status | databases |
| `bans list`, `bans lift ip 192.0.2.1 --reason R` | The ban list; lift every ban of one subject | databases |
| `flush-metrics` | Every worker flushes its buffered metrics within about a second | databases |
| `settings show [KEY ...]`, `settings set KEY=VALUE --reason R [--confirm-high-risk]` | Runtime settings, through the settings service | databases |

- Every change is audited as `cli:<your login name>` (the name behind `sudo`), with the reason you give.
- The database commands refuse to run as anyone but the databases' owner, because SQLite would create `-wal` and
  `-shm` files the service cannot open.
- The socket commands need a running color: nginx's color first, then the other one.
- A reset, a full-detail export and a health run with the credential check also prove they run as `roxy`, through a
  one-use file in `/var/lib/roxy/ctl-proofs/`. The deploy user can open the socket, but it can never use those three.
- A factory reset stays dashboard-only (it needs a fresh second factor). Nothing the CLI prints contains a secret.
- `--json` prints JSON; exit status 0 done, 1 refused or failed, 2 bad arguments, 3 no database or no color answering.

## Backups and restore

`roxy-backup.timer` runs `backup.sh` nightly at 03:30 (plus up to 15 minutes): control.db and metrics.db (hot.db with
`ROXY_BACKUP_HOT=1`) are copied with `VACUUM INTO`, checked, compressed, optionally encrypted with `age`, and kept 14
daily and 8 weekly. To restore: stop both colors, decompress (`zstd -d control.db.zst`, after `age -d` when
encrypted) into `/var/lib/roxy/`, run `PRAGMA integrity_check`, fix owners (`chown roxy:roxy`, mode 0640), start the
color nginx points at (`sudo /usr/local/sbin/roxy-switch-color --boot`), and run the health check. The encryption keys are
never in a backup (plan 9.8): restore `/etc/roxy/credentials/` from the owner's offline copy if the disk was lost.

"Back up now" runs the same full backup on request: the service or `scripts/ctl.py backup-now` (both the `roxy`
user, which may not start units) writes `/var/lib/roxy/backup-request`, and `roxy-backup-request.path` starts
`roxy-backup.service`. `backup.sh` removes the request first thing (without following a link the roxy user could
plant), skips a requested run within 10 minutes of the last good backup (`ROXY_BACKUP_MIN_GAP_S`), and records how it
answered under `last_request` in `audit/backup.json`. `install-system.sh` enables the path unit with the timers.

## Running beside v1 during the cutover

v1 (unit `roxy`, user `ubuntu`, port 8000, nginx site `roxy`, state in `/etc/roxy`) and v2 (units `roxy@blue` and
`roxy@green`, user `roxy`, ports 8001 and 8002, nginx site `roxy-v2.conf`) use different names and ports, so both can
be installed at once. Things to know:

- `/etc/roxy` belongs to v1 (user `ubuntu`, mode 0700) and v1 rewrites its state files there all the time.
  `install-system.sh` sees that the directory is not root's and leaves its owner, group and mode exactly as they
  are; it only adds an ACL entry that lets `roxy-deploy` pass through the directory (`setfacl -m u:roxy-deploy:x`),
  so the deploy can read the v2 env files (0640 root:roxy) by name. Nobody else gains anything (a `chmod o+x`
  would let every local account reach any v1 file that was ever created with a looser mode). systemd reads the env
  files and credentials as root, so the service needs no access to the directory. Without the `acl` package the
  script stops and changes nothing.
- Both nginx sites name the same host, and nginx uses the first one it loads (`roxy` sorts before
  `roxy-v2.conf`), so v1 keeps serving the public name until its site is disabled. The deploy's public checks
  (the watch's `/health` and the smoke test through nginx) would then reach v1; the watch notices (no `Degraded`
  key) and fails the deploy. Deploy with `ROXY_DEPLOY_PUBLIC_CHECK=0` until the cutover; the health gate on the
  new color's own socket and port still runs.
- At the cutover, after v1 is stopped and its data imported (MIGRATION.md): disable v1's site
  (`sudo rm /etc/nginx/sites-enabled/roxy && sudo nginx -t && sudo systemctl reload nginx`), then
  `sudo deploy/install-system.sh --take-over-etc`, which makes `/etc/roxy` root:roxy 0750 and removes the ACL
  entry. Later deploys run with the public checks on (the default).
- roxy-audit reports `/etc/roxy` (owned by `ubuntu`) as a finding until the cutover.

## Memory and swap on the 909 MB server

The server has 909 MB of RAM and no swap. DESIGN.md section 0 sizes everything to fit without swap: each color is
capped at `MemoryHigh=320M` and `MemoryMax=420M`, two workers per color, and low-memory mode during a deploy. Adding a
small swap file is still recommended as a safety net, not as capacity:

```
sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/90-roxy-swap.conf && sudo sysctl --system
```

Why: without swap, a short spike (both colors at their soft limit during a deploy, plus certbot or apt) goes straight
to the kernel's OOM killer, which may pick nginx. With a low swappiness the kernel only swaps under real pressure,
and `MemoryMax` still bounds each color's RAM (cgroup memory limits do not count swap), so a runaway color is
throttled and swapped, then restarted by systemd, instead of taking the box down. Watch `free -m` on the System page;
steady swap use means the budget is wrong and `cache_memory_bytes` is the first knob to lower.

## Testing these files

`.venv/bin/pytest tests/deploy` runs the real `deploy.sh` in a sandbox with stub `systemctl`, `sudo`, `curl`, `uv` and
wrappers (every v1 `deploy_test.sh` scenario and the plan 19.9 list), `nginx -t` against nginx 1.18, 1.24 and a
current release, `systemd-analyze verify` and `security`, the app under the unit's system call filter, live gunicorn
masters (one leader across colors, low-memory scaling), and the tools. Optional binaries are found on `PATH` or where
they can be unpacked without root (`apt-get download <package>` then `dpkg -x <deb> ~/.local/<dir>`): nginx in
`~/.local/nginxroot`, `~/.local/nginx118root` (Ubuntu 22.04 package) and `~/.local/nginxnewroot` (nginx.org
package); shellcheck, zstd and age in `~/.local/p13tools`. A test whose tool is missing is skipped with the reason.
Live tests run inside `unshare -rn`, a private network namespace with only loopback, so they can never reach a real
system.
