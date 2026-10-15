# Moving Roxy from v1 to v2

This is the step by step cutover from Roxy v1 (the Flask app in `app/`) to Roxy v2 (the FastAPI app in `src/roxy/`)
on the production server. Follow it in order and do not skip the checks: each one tells you what you should see,
and [section 6](#6-rollback-to-v1) says how to go back to v1 from any step.

- Commands run on the server, in an SSH session as `ubuntu`, unless a step says otherwise.
- `<sha>` is the full 40 character commit id you deploy (section 1.4). `<your site>` is the public host name, for
  example the host in `ROXY_SITE_ORIGIN`.
- **OWNER:** marks something only you can decide or fill in.
- Every command below exists in the repository (or is a standard Ubuntu command) with the flags shown. The time
  estimates are estimates: nothing has been timed on the real server yet.

## 0. What this does and how long it takes

### 0.1 What changes

| | v1 today | v2 after the cutover |
|---|---|---|
| Code | `/home/ubuntu/Roxy`, Python environment `~/SiteEnv` | `/opt/roxy/releases/<sha>`, each release with its own `.venv` |
| Runs as | `ubuntu` | `roxy` (the service) and `roxy-deploy` (deploys only) |
| systemd unit | `roxy` | `roxy@blue` and `roxy@green` (one runs at a time) |
| Port on 127.0.0.1 | 8000 | 8001 (blue) and 8002 (green) |
| nginx site | `roxy` | `roxy-v2.conf` |
| State | JSON files in `/etc/roxy` | four SQLite databases in `/var/lib/roxy` |
| Secrets | files in `/etc/roxy` named by `files.txt` | `/etc/roxy/credentials`, one root-only file per secret |
| Deploys | GitHub Actions runs `~/UpdateBuild.sh` as `ubuntu` | GitHub Actions runs `/opt/roxy/deploy.sh` as `roxy-deploy` |

The two versions use different names, ports, users and directories, so both can be installed at once. The cutover
stops v1, imports its settings, rules, credential and lifetime numbers into v2, starts v2, and moves the public host
name from v1's nginx site to v2's. v1 stays on disk, stopped, so you can start it again (section 6) until you remove
it after 30 days (section 5.6).

### 0.2 Words used in this document

| Word | Meaning |
|---|---|
| Color | One of two copies of v2, blue or green. A deploy starts the idle color, checks it, points nginx at it, then stops the old one. |
| Release | One deployed commit: `/opt/roxy/releases/<sha>`. The newest five are kept. |
| Migrator | `scripts/migrate_from_v1.py`: reads v1's files (never changes them) and writes the v2 databases and credential files. |
| Expand migration | A database change that only adds (tables, columns, indexes), so the code already running keeps working. |
| Credential files | The secrets v2 reads, one file each in `/etc/roxy/credentials` (systemd hands them to the service privately). |
| Key escrow | An encrypted copy of those files kept off the server, because backups never contain the encryption keys. |
| Health gate | The deploy's check that the new color answers "ready" on its private socket before nginx sends it traffic. |
| Smoke test | `scripts/smoke_remote.py`: a few real requests to the new color (pages, a proxy request, a static file). |
| Low-memory mode | When another color is running and less than 700 MB of memory is available, the deploy starts the new color with one worker, then adds the second after the old color stopped. |
| Toolbox | A checkout of the release in your home directory, used by root to install the system pieces and run the migrator. |

### 0.3 How long it takes

| Part | When | Your time | What callers notice |
|---|---|---|---|
| Prerequisites (section 1) | any days before | depends on GitHub | nothing |
| Preparation (section 2) | any day before | 2 to 3 hours | nothing (one graceful nginx reload) |
| Dry run (section 3) | after section 2 | 15 to 30 minutes, mostly reading | nothing |
| Build the release (step 3.4) | the day of the window, before it | 5 to 10 minutes, unattended | nothing (v1 keeps serving) |
| Maintenance window (section 4) | **OWNER:** your quietest hour | book 60 minutes | errors from step 4.1 to step 4.8, about 10 to 15 minutes |
| Watch (step 4.10) | right after the switch | 60 minutes | nothing |
| Follow-up (section 5) | the next days | about an hour | nothing |
| Decommission (section 5.6) | after 30 days | 30 minutes | nothing |

During the outage nginx answers 502 (v1 is stopped and v2 does not hold the name yet). The release and its Python
environment are built before the window (step 3.4, while v1 still serves), so the first deploy in step 4.6 only
starts blue, checks it and points nginx at it.

## 1. Prerequisites and owner decisions

### 1.1 Sign-offs

- **OWNER:** `DECISIONS_REVIEW.md` is signed off. Do not start section 2 before it is.
- Read this document once from top to bottom, and section 6 twice.

### 1.2 The shadow comparison (plan 18.4): not done

Plan 18.4 asked for a 7-day "shadow week" before the cutover: a sample of v1's credential calls replayed without the
credential, to see which endpoints answer the same to anonymous callers and whether anonymous calls get more Roblox
429s. Its purpose was to choose which endpoints, if any, keep using the credential (decision D1).

- **What it needs:** records from a producer. `scripts/shadow_report.py` reads either the JSON of the v1 Tier 0
  hotfix's `GET /admin/shadow` (`--hotfix-report`, from branch `hotfix/v1-phase-minus-1`, commit 3453d66) or
  `credential_comparison` events in a v2 `metrics.db` (`--state-dir`).
- **What was done:** nothing. The Tier 0 hotfix was never merged or deployed, so v1 never ran the shadow mode, and
  no part of v2 writes `credential_comparison` events.
- **Why:** you decided D1 = never send the credential for callers. The credential allowlist ships empty and only
  Roxy's own probes use the credential, so there is no allowlist decision for the week to inform.
- **What it means:** nobody measured how Roblox treats this server's anonymous traffic before the switch. Step 4.10
  watches for exactly that (Roblox 429s, and 401 or 403 answers from Roblox).
- **For the record:** the report states all of this when it has no input. Attach its output to `DECISIONS_REVIEW.md`
  before you sign it (section 1.1). With no input it needs neither the server nor Roxy's Python environment (only
  the standard library), so run it from any checkout of the repository, for example on your own computer:

```sh
python3 scripts/shadow_report.py > shadow_report.md
```

### 1.3 The v1 fix is on GitHub

On 2026-10-09 the live v1 dashboard was fixed by patching two files on the server (the NaN in `/admin/diagnostics`).
That fix is commit 12616fd (branch `fix/v1-diagnostics-nan`), and you pushed it to GitHub `main` on 2026-10-10;
`git ls-remote` of the repository showed `main` at 12616fd on 2026-10-12. A v1 deploy from `main` keeps the fix, so
nothing is owed here. Step 1.4's merge must keep it: a merge, never a force push.

The other v1 change, the Tier 0 safety hotfix (commit 3453d66, branch `hotfix/v1-phase-minus-1`, which stops v1
sending the credential with caller traffic), was never merged. You decided on 2026-10-14 to keep v1 as it is (answer
A2 in `DECISIONS_REVIEW.md`), so it stays unmerged; the cutover does not need it.

### 1.4 v2 on the main branch, after a backup of v1

`deploy.sh` deploys only commits that are on `main`, so v2 must be merged into `main` before the cutover. Back up v1
on GitHub first (your answer B16), then merge.

**First, OWNER: tag and branch v1.** On your own computer, in a clone of the repository (the one v1 deploys from,
`https://github.com/CeaselessQuokka/roxy`; `git clone` it if you have no copy), with your own GitHub account:

```sh
git fetch origin
git rev-parse origin/main
git merge-base --is-ancestor 12616fd origin/main && echo "main has the v1 dashboard fix"
git tag -a v1-final -m "Roxy v1 as it ran before v2 was merged" origin/main
git branch --no-track v1-backup origin/main
git push origin v1-final v1-backup
git ls-remote origin refs/tags/v1-final refs/heads/v1-backup
```

- `rev-parse` should print `12616fd8c8e85b4ae2d2488e2fd0e9bdb36a5590` (commit 12616fd, where `main` was on
  2026-10-12). If it prints something else, `git log --oneline 12616fd..origin/main` lists what was added since: tag
  `main` as it is only if those are v1 changes you know.
- The `merge-base` line must print its sentence, and the last command must list the tag and the branch.
- The tag `v1-final` never moves: it is v1 exactly as it ran. The branch `v1-backup` is where a v1 fix would go if you
  ever need one. Pushing either deploys nothing: v1's workflow runs only for pushes to `main`.
- Optional: in the repository's GitHub settings, add a rule that forbids deleting or force-pushing `v1-final` and
  `v1-backup`.

**Getting v1 back from the backup.**

- To run v1 again on the server you need neither: v1's own files stay on the server, stopped, for 30 days after the
  switch, and [section 6](#6-rollback-to-v1) starts v1 again from them.
- v1's code as it ran is the tag: `git clone --branch v1-final https://github.com/CeaselessQuokka/roxy roxy-v1` makes
  a copy of it anywhere (GitHub asks you to sign in if the repository is private). On the server it is also inside
  the archive `/root/roxy-v1-backup.tar.gz` of step 2.1.
- A v1 fix goes on the branch `v1-backup`, never on `main`.
- Never move `main` back to v1, and never force-push it: after the merge `main` holds v2 and v1's fix 12616fd, and
  every push to it deploys v2 once section 5.2 is done. Never run v1's `~/UpdateBuild.sh` again either: it clones
  `main`, which is v2 from now on (section 5.3).

**Then, OWNER: merge.**

- **OWNER:** merge `remake/v2` into `main` (a merge, never a force push: it must keep 12616fd). Before you push,
  check that the merged workflow is v2's guarded one:

```sh
git show HEAD:.github/workflows/deploy.yml | grep -n "^    if: false$"
```

  It must print the deploy job's line (`37:    if: false` at the time of writing). v2's `.github/workflows/deploy.yml`
  replaces v1's file of the same name, and its deploy job carries `if: false`, so pushing the merge runs CI and skips
  the deploy. v1 keeps running untouched.
- From this push on, v1 can no longer be deployed from GitHub. That is intended: v1's workflow must never run
  against the v2 tree.
- Write down the full commit id of the merge on `main` (`git rev-parse origin/main` after a fetch). That is `<sha>`
  everywhere below. CI must be green on it.

### 1.5 Owner decisions in force

| Decision | Value | What it means at the cutover |
|---|---|---|
| D1 | Never send the credential for callers | The credential allowlist (Credential page, Allowlist card) is empty; only Roxy's own probes use the credential. |
| D4 | Real upstream status | Callers get Roblox's real status (a 404 stays 404, a 429 stays 429 with `Retry-After`) instead of v1's 500. Tell your users. |
| D5 | Authenticator app mandatory | Your first sign-in uses v1's password plus a code emailed to you, then forces you to set up an authenticator app and save 10 recovery codes (section 5.1). |
| D10 | Reversed by you: cache hits count | `throttle_count_cache_hits` is 1: answers from the cache count toward a caller's per-IP limit. |
| Workers | `ROXY_WORKERS=2` | Two workers per color, sized for the 909 MB server. |

The memory plan behind the last row: each color is held at `MemoryHigh=420M` (the kernel starts reclaiming above it)
and `MemoryMax=500M` (the hard limit). A warm color settles at about 365 to 405 MiB. A deploy never runs two warm
colors: the new color starts fresh, with one worker when less than 700 MB is available. The worst case during a
deploy is a warm color at its 500 MiB limit, plus a new one-worker color (about 155 MiB at start), plus about 200 MB
for the operating system and nginx: 855 of 909 MB. Step 4.2 checks the 200 MB on the real server.

Your answers of 2026-10-14 (`DECISIONS_REVIEW.md`, "Owner answers of 2026-10-14") agree to every other decision as
built. What they add to the cutover: the v1 backup on GitHub (step 1.4), a swap file and two kernel settings (step
2.10), the DataImpulse balance written down when v1 stops (step 4.1), and your choices after the first sign-in (step
5.1: a test alert, the User-Agent experiment on, a guard for the prepaid DataImpulse pool). The larger requests come
as v2.x updates after the cutover; `ROADMAP.md` tracks every one of them.

### 1.6 What to have at hand

- An SSH session to the server as `ubuntu` (two are handy during the window).
- The mailbox of v1's admin address (the first line of v1's emails file): the first sign-in emails a code there.
- An authenticator app on your phone or in your password manager.
- An `age` key pair made on your own computer (step 2.9).
- A clone of the repository on your own computer and your GitHub account, to back up v1 and merge v2 (step 1.4).
- Rights to change the repository's GitHub secrets and workflow files (section 5.2).
- Your DataImpulse dashboard, to read the balance left when v1 stops (step 4.1).

## 2. Prepare the server

Nothing in this section stops v1 or changes what callers see. Do it on any day before the window, in this order.

### 2.1 Save v1's configuration and record its directory

```sh
systemctl cat roxy
stat -c '%U:%G %a' /etc/roxy
sudo tar -C / -czf /root/roxy-v1-backup.tar.gz etc/roxy etc/nginx etc/systemd/system home/ubuntu/Roxy
df -h /
```

- `systemctl cat roxy` shows v1's unit. Look for `Environment=` lines that set `ROXY_FILE_ROOT`, `ROXY_STATE_FILE`,
  `ROXY_DATA_FILE`, `ROXY_ROTATE_PROXY` or `ROXY_ROTATE_PROXY_FILE`. The repository's copy of v1's unit sets none of
  them. **OWNER:** if the live one does, read the note at the end of step 2.4.
- **OWNER:** write down what `stat` prints (for example `ubuntu:ubuntu 700`; the repository's copy of v1's unit
  runs v1 with `Group=www-data`, so `ubuntu:www-data` is possible too). Section 6.5 needs it.
- The archive holds v1's secrets. It stays in `/root`, which only root can read.
- **OWNER:** note the free disk space. v2 keeps five releases, each with its own Python environment; the journal may
  use up to 2 GB (`deploy/systemd/journald-roxy.conf`, which also keeps 1 GB free); nightly backups go to
  `/var/backups/roxy`.

### 2.2 Packages

```sh
sudo apt install acl zstd age
```

nginx is already installed. `acl` is required: while v1 owns `/etc/roxy`, the install script lets the deploy account
through that directory with an ACL entry and changes nothing else (without `acl` it stops and changes nothing).
`zstd` compresses backups and `age` encrypts the key escrow. Add `rclone` only if you want off-box backups (D15).

### 2.3 The toolbox: a checkout of the release

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/OWNER/REPO.git ~/roxy-v2-src
cd ~/roxy-v2-src
git checkout --detach <sha>
~/.local/bin/uv sync --frozen --no-dev
git rev-parse HEAD
```

- **OWNER:** replace `OWNER/REPO` with the repository (v1's `Tooling/UpdateBuild.sh` deploys from
  `CeaselessQuokka/roxy`, and you confirmed v2 deploys from the same repository's `main`: answer B16), and `<sha>`
  with the commit of step 1.4. The last command must print that commit.
- Root runs the install script and the migrator from this checkout. It belongs to `ubuntu`, which already has full
  sudo, so running it as root gives no one new power. Never run them as root from `/opt/roxy`: the deploy account
  owns that directory.

### 2.4 The credential files, from v1's files (rule C1)

v2 reads its secrets as systemd credentials: root-only files in `/etc/roxy/credentials` (directory 0700, files 0600).
The migrator writes them from v1's files:

- `roblox_credential`: the **first non-empty line** of v1's token file and nothing else. Rule C1 allows exactly one
  Roblox credential, so any other lines are discarded, and the report lists each one masked (the last 6 characters).
- `rotator_url` (from `rotate_proxy.txt`), `smtp_password` (the Gmail app password) and `alert_emails` (`to:` and
  `from:` lines from v1's emails file).
- Three new random keys (32 bytes each): `credential_encryption_key`, `totp_encryption_key` and `ip_hash_key`.
- An existing file is never overwritten, and a key is never made again. One exception: an existing EMPTY optional
  file (`rotator_url`, `alert_webhook_url`, `rclone_config`; empty means "not configured", and `install-system.sh`
  creates them that way) counts as missing, so the migrator fills `rotator_url` from v1 whichever of steps 2.4 and
  2.5 ran first. A file a previous migrator run already handled stays as it is, even when you emptied it on purpose.

The migrator writes the credential files in the same run as the databases. Right now you only want the files, so
point its databases at a scratch directory and delete that afterwards (the real import happens in the window):

```sh
sudo ~/roxy-v2-src/.venv/bin/python ~/roxy-v2-src/scripts/migrate_from_v1.py \
  --v1-root /etc/roxy --state-dir /root/roxy-scratch-state \
  --credentials-out /etc/roxy/credentials --report /root/roxy-credentials-report
sudo rm -rf /root/roxy-scratch-state
sudo grep -A 12 "## Credential files" /root/roxy-credentials-report.md
sudo ls -l /etc/roxy/credentials
```

- It reads `/etc/roxy` and never changes a v1 file.
- The table should show `roblox_credential`, `smtp_password` and `alert_emails` as `written`, the three keys as
  `generated`, and `rotator_url` as `written` (or `no_source` when v1 had no rotator).
- **OWNER:** if a warning says the token file had more than one credential, check that the kept one (its last 6
  characters are shown) is the cookie you mean to keep.
- The scratch databases were made by root and are deleted with their directory; the real ones (step 4.4) are handed
  to the `roxy` user by the migrator itself.

**Note for an unusual v1 unit (step 2.1):** the migrator's `--help` covers four of the variables.
`ROXY_STATE_FILE` and `ROXY_DATA_FILE` become `--v1-state-file` and `--v1-data-file`. For `ROXY_ROTATE_PROXY_FILE`,
start the command with `sudo env ROXY_ROTATE_PROXY_FILE=<the same value>` instead of `sudo` (the file is read by its
name inside the v1 directory). `ROXY_ROTATE_PROXY` holds the rotator URL with its password: never type it on a
command line. If v1 got the URL that way and no `rotate_proxy.txt` holds it, set it after the cutover on the Egress
page (Rotator card, "Replace the gateway URL"; it asks for a current authenticator code and a reason). The migrator
has no option for `ROXY_FILE_ROOT` (where v1 reads `files.txt` and the secret files it names), and it reads only
inside `--v1-root`: if v1's unit set it to another directory, make a copy of `/etc/roxy` (as in step 4.3), copy
`files.txt` and the files it names into that copy, and use the copy as `--v1-root`. Use the same additions in
sections 3 and 4.

### 2.5 Install the system pieces

```sh
sudo ~/roxy-v2-src/deploy/install-system.sh
```

What it does (it is safe to run again; files that hold local settings are only created when missing):

- Creates the accounts `roxy` (runs the service, no login) and `roxy-deploy` (deploys; member of group `roxy`).
- Creates `/opt/roxy`, `/opt/roxy/releases` and `/var/lib/roxy-deploy` (deploy account), `/var/lib/roxy` (roxy,
  0750), `/etc/roxy/credentials` (root, 0700), `/var/backups/roxy` (root, 0700), `/usr/local/lib/roxy` and
  `/var/www/letsencrypt` (where v2's nginx site answers certificate renewal challenges).
- Installs the units. `roxy@.service` holds each color at `MemoryHigh=420M` and `MemoryMax=500M` and tunes the memory
  allocator (`MALLOC_ARENA_MAX=2`, `MALLOC_MMAP_THRESHOLD_=131072`, `MALLOC_TRIM_THRESHOLD_=131072`).
- Enables and starts `roxy-backup.timer`, `roxy-audit.timer`, `roxy-audit.path`, `roxy-deploy-alert.path` and
  `roxy-backup-request.path` (the "Back up now" button and `roxyctl backup-now` work through it), and enables
  `roxy-boot.service` (starts the active color after a reboot).
- Installs the journald limits (and restarts `systemd-journald` to apply them), the root tools in
  `/usr/local/lib/roxy`, the two wrappers in `/usr/local/sbin`, and the deploy account's sudo rules (only after
  `visudo` accepts them).
- Installs `/etc/roxy/roxy.env`, `blue.env` and `green.env` (root:roxy 0640) and `/opt/roxy/deploy.sh` and
  `/opt/roxy/deploy_rollback.sh` when they are missing.
- Creates the optional credential files that do not exist as empty files (`alert_webhook_url`, `rotator_url`,
  `rclone_config`: empty means "not configured") and lists any required one still missing.

What you should see: a `WARNING` that `/etc/roxy` belongs to `ubuntu` (expected: v1 lives there, so the script only
adds the ACL entry for `roxy-deploy`), **no** "still missing in /etc/roxy/credentials" line, and the last line
`install-system: done`.

v1's failure alert unit has the same name as v2's (`roxy-alert@.service`), and v2 keeps that name on purpose. If v1's
copy lives in `/etc/systemd/system`, it is replaced now, and that is fine: v1's unit `roxy` (not touched) still names
`OnFailure=roxy-alert@%n.service`, and v2's alert script reports any unit it is started for. From now on a v1 crash
is mailed by v2's script ("Roxy DOWN: roxy.service failed on <host>"), with the `smtp_password` and `alert_emails`
files of step 2.4 (it also reads v1's two-line address file format), instead of v1's script, which read v1's own
files. Step 2.4 comes first for that reason too.

Check the units:

```sh
systemctl cat roxy@blue.service | grep -E 'MemoryHigh|MemoryMax|MALLOC'
systemctl is-enabled roxy-backup-request.path roxy-boot.service
id roxy-deploy
```

You should see `MemoryHigh=420M`, `MemoryMax=500M` and the three `MALLOC` lines; `enabled` twice; and `roxy` among
the groups of `roxy-deploy`. If you ever ran `install-system.sh` from an older commit, this run updated the units.

### 2.6 Shared settings in `/etc/roxy/roxy.env`

```sh
sudo nano /etc/roxy/roxy.env
```

- `ROXY_DEPLOY_REPO_URL`: replace `OWNER/REPO` with the repository (`CeaselessQuokka/roxy`, answer B16). The nginx
  wrapper refuses to run while the placeholder is there, and a deploy started by hand has no repository to fetch
  from.
- `ROXY_SITE_ORIGIN`: your public origin. Its certificate must be in `/etc/letsencrypt/live/<host>/`
  (`sudo ls /etc/letsencrypt/live/` lists the hosts; v1 uses the same certificate).
- `ROXY_WORKERS=2`: keep it (section 1.5).
- `ROXY_MAX_REQUESTS=20000`: keep it at 20,000 or lower. A worker restarts after that many requests, and the memory
  figures above assume it does.
- **OWNER, optional:** encrypted backups. Put your `age` public key in `/etc/roxy/backup-age-recipients` (the file
  `ROXY_BACKUP_AGE_RECIPIENTS` names); backups are encrypted when that file exists.
- **OWNER, optional:** an off-box copy (D15). Set `ROXY_BACKUP_REMOTE` to an rclone remote name and put the rclone
  configuration in `/etc/roxy/credentials/rclone_config` (root, 0600). An off-box copy needs the age recipient file
  above: only an encrypted set ever leaves the server, and with a remote but no recipient the backup keeps its local
  set, copies nothing and fails at the step "rclone push", so its alert tells you what is missing.

### 2.7 nginx

```sh
sudo nano /etc/nginx/nginx.conf
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

- In `nginx.conf` set `worker_processes 2;` and, inside `events { }`, `worker_connections 4096;`. A site file cannot
  set these, and Roxy's tarpit budget is computed from them.
- The default site's `default_server` collides with v2's site; removing the link keeps the file in `sites-available`.
- The reload is graceful; v1 keeps serving. Do not enable v2's site by hand: the first deploy installs it through
  the root wrapper `roxy-nginx-apply`, from the verified commit only.

### 2.8 The deploy account

```sh
sudo -iu roxy-deploy
curl -LsSf https://astral.sh/uv/install.sh | sh
mkdir -p -m 700 ~/.ssh
nano ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
sudo -n -l
exit
```

- **OWNER:** make a key pair for GitHub Actions on your own computer (for example
  `ssh-keygen -t ed25519 -f roxy-deploy-actions -C roxy-deploy-actions`) and paste the one line of
  `roxy-deploy-actions.pub` into `authorized_keys`. The private key goes into GitHub in section 5.2, not now.
- `sudo -n -l` must list only `roxy-switch-color`, `roxy-nginx-apply` and `systemctl` start, stop, restart and reload
  of `roxy@blue.service` and `roxy@green.service`. Never deploy as `ubuntu`: on Lightsail it has unrestricted sudo,
  which would make these rules pointless.
- From your computer, `ssh -i roxy-deploy-actions roxy-deploy@<server>` should log in.

### 2.9 Offline copy of the keys (key escrow)

Backups never contain the keys of step 2.4. If the disk is lost without a copy of them, every secret v2 encrypted
(authenticator secrets, a cookie or rotator URL set from the dashboard) is lost too. Make the copy now.

Where you run it and how it works (your question C19): `age` is a small, free encryption tool. You make a lock and
key pair on your own computer, never on the server. The public key (it starts with `age1`) is the lock: the server
uses it to lock a copy of Roxy's secret keys, and anyone may see it. The file `roxy-escrow-key.txt` is the only key
that opens the copy: keep it off the server, for example on a USB stick or in your password manager. If the server's
disk ever dies, the locked copy plus that file is how you get back in.

- **OWNER:** on your own computer, install `age` (on Windows, in PowerShell: `winget install FiloSottile.age`), then
  run `age-keygen -o roxy-escrow-key.txt`. It prints the public key (`age1...`). Keep `roxy-escrow-key.txt` offline;
  it never goes to the server.
- On the server:

```sh
sudo tar -C /etc/roxy -cf - credentials | age -r <your age public key> > ~/roxy-credentials.tar.age
```

- Copy `~/roxy-credentials.tar.age` to your computer, then delete it from the server
  (`rm ~/roxy-credentials.tar.age`).
- Test it on your computer: `age -d -i roxy-escrow-key.txt roxy-credentials.tar.age | tar -tf -` lists the files.
- Make a new copy whenever a file in `/etc/roxy/credentials` changes. The keys never change by themselves.

### 2.10 Memory: measure, then add swap and two kernel settings

```sh
free -m
systemctl show roxy -p MemoryCurrent
```

The `used` column minus v1's `MemoryCurrent` (in bytes) is roughly what the operating system and nginx use. The
memory plan assumes about 200 MB; step 4.2 measures it exactly with v1 stopped.

**Swap and two kernel settings (your answers A7 and A8).** Do this now, on any day before the window, never during
it. `install-system.sh` does not do it yet (`ROADMAP.md`, item 12), so it is the commands below, by hand. What each
part is, in plain words:

- **Swap** is disk space Linux may borrow when memory is completely full. Without it, a full memory makes Linux kill
  a process to free some, and it may pick nginx. With a small swap file the system slows down for a moment instead.
  The 1 GiB file is a safety net for the operating system, apt, certbot and the migrator, never extra room for Roxy.
- **`vm.swappiness` 10** tells Linux to use that disk only under real memory pressure (Ubuntu's default is 60). The
  disk is network storage on Lightsail, so swapping is slow and should stay rare.
- **Roxy's colors never swap (`MemorySwapMax=0`).** Each color keeps its limits (`MemoryHigh=420M`,
  `MemoryMax=500M`), and those limits count memory only, not swap. Without this line a color at its limit would be
  pushed into the slow swap and slow every caller down, instead of losing one worker that gunicorn replaces at once
  (`OOMPolicy=continue`), which is what every memory test measured. The line goes into a small extra file next to the
  unit (a drop-in), so the colors behave exactly as tested.
- **`net.ipv4.tcp_migrate_req` 1** (the lead's recommendation, which you asked for). Each worker of a color has its
  own queue of new connections. When a worker restarts (about every 20,000 requests), the connections still waiting in
  its queue are reset today: 4 to 8 percent of new connections at that moment in the test, each one a 502 for a
  caller. With the setting, Linux hands them to the other worker instead. It costs no memory or CPU and needs Linux
  5.14 or newer (Ubuntu 24.04 runs 6.8 or newer).

Check first:

```sh
swapon --show
ls -l /swapfile
df -h /
cat /proc/sys/net/ipv4/tcp_migrate_req
```

`swapon --show` must print nothing (no swap yet), `ls` must say there is no such file, `df` must show at least 5 GB
available (the file takes 1 GiB), and the last line prints `0` (the kernel knows the setting; it is off). If swap is
already active, skip the four swap commands below and do the rest.

Add them:

```sh
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
grep -qs '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
printf 'vm.swappiness = 10\nnet.ipv4.tcp_migrate_req = 1\n' | sudo tee /etc/sysctl.d/90-roxy.conf
sudo sysctl -p /etc/sysctl.d/90-roxy.conf
sudo mkdir -p /etc/systemd/system/roxy@.service.d
printf '[Service]\nMemorySwapMax=0\n' | sudo tee /etc/systemd/system/roxy@.service.d/90-no-swap.conf
sudo systemctl daemon-reload
```

- The `fstab` line makes the swap file come back after a reboot, `/etc/sysctl.d/90-roxy.conf` does the same for the
  two settings, and the drop-in applies to both colors. `install-system.sh` replaces only `roxy@.service` itself, so
  the drop-in stays when it runs again (step 5.4).
- If `fallocate` fails, or `swapon` says the file has holes, make the file the slow way and go on from `chmod`:
  `sudo rm /swapfile` and `sudo dd if=/dev/zero of=/swapfile bs=1M count=1024`.
- v1 is not affected: its unit has no swap limit, which only helps it.

Check them:

```sh
swapon --show
free -m
sysctl vm.swappiness net.ipv4.tcp_migrate_req
systemctl cat roxy@blue.service | grep MemorySwapMax
```

You should see a line starting `/swapfile file 1024M`; a `Swap:` line in `free -m` with about 1023 total;
`vm.swappiness = 10` and `net.ipv4.tcp_migrate_req = 1`; and `MemorySwapMax=0`. After any reboot the same checks
show the same.

Undo, if you ever want to (v1 and v2 both work without them):

```sh
sudo swapoff /swapfile
sudo rm /swapfile
sudo sed -i '\|^/swapfile |d' /etc/fstab
sudo rm /etc/sysctl.d/90-roxy.conf
sudo sysctl -w vm.swappiness=60 net.ipv4.tcp_migrate_req=0
```

`swapoff` moves what is in swap back into memory, so run it when the `Swap:` used in `free -m` is smaller than the
memory available. The drop-in can stay: without swap it changes nothing.

## 3. Dry run of the migrator

### 3.1 Run it

```sh
sudo ~/roxy-v2-src/.venv/bin/python ~/roxy-v2-src/scripts/migrate_from_v1.py \
  --v1-root /etc/roxy --state-dir /var/lib/roxy --credentials-out /etc/roxy/credentials \
  --import-admin-password --report /root/roxy-migration-dry-run --dry-run
echo "exit $?"
sudo less /root/roxy-migration-dry-run.md
```

- `--dry-run` runs every step against private copies in a temporary directory and writes only the report
  (`/root/roxy-migration-dry-run.md` for you, `.json` for tools, both 0600). v1's files are only read.
- `--import-admin-password` follows D5: v1's admin password is hashed (argon2id) into a v2 admin account that must use
  the emailed code once and then set up an authenticator. Without the flag no admin is created, and you would make
  one on the console with `scripts/create_admin.py` instead.
- The first lines printed are a summary: `Roxy v1 migration: dry_run_would_change`, the item counts, how many rows
  and files a real run would write, the warnings and errors, and the report's paths.
- Exit status: 0 done; 1 a step reported an error (the report says which); 2 refused, nothing written (a wrong
  `--v1-root`, a report path inside the v1 directory, or a state or credentials directory that is the v1 directory
  itself; a subdirectory such as `/etc/roxy/credentials` is fine).
- Run it as often as you like; it changes nothing.

### 3.2 How to read the report

The sections come in this order. Each item says what to look for and what to do.

- **Top lines.** `Mode: dry run` and `Result: dry_run_would_change`, with counts per result (imported, skipped,
  invalid and so on). Nothing to do.
- **Problems.** Every `Error:` must be understood and fixed before the window. Each `Warning:` names something to
  check; the items below say which ones matter.
- **Inputs.** Each v1 file the migrator found, and where it read the control plane (settings, rules, switches) and
  the statistics from. If the data file did not parse, it was read from v1's own `roxy_data.json.bak`, as v1 itself
  would have done, and the line says so. The unreadable data file is also an `Error:` under Problems, so the result
  is `completed_with_errors` (exit 1) on every run: decide before the window whether the `.bak` numbers will do.
- **Built-in defaults.** The rows v2 ships with, seeded before the import. On a new install every seed version goes
  in at once. Version 2 adds 8 client address headers as ignored value headers, so their values are never stored:
  `x-forwarded-for`, `x-real-ip`, `forwarded`, `true-client-ip`, `cf-connecting-ip`, `x-client-ip`,
  `x-cluster-client-ip` and `via`.
- **Settings.** One row per v1 setting: its v2 key, the values, the result and notes.
  - Only values you changed in v1 are imported; a value left at v1's default gives way to v2's default.
  - A value outside the v2 range is **clamped** into it, and the note says so.
  - Keys whose meaning changed are never imported. They are shown next to the v2 default: decide those by hand on the
    Settings page after the cutover.
  - `cache_post_requests` = 1 becomes `all`, with a high-risk warning under Problems.
  - A v1 `capture_max_body` or `capture_ttl_seconds` of 0 meant "no limit" in v1, while v2 reads 0 as "nothing". Such
    a value is imported as the v2 maximum (524,288 bytes; 86,400 seconds, that is a day), with a note, and the long
    capture lifetime also gets a `HIGH RISK` warning under Problems: captured request and answer bodies would be kept
    a whole day. Lower it on the Live page's capture card after the cutover unless you need it.
- **Allowed Roblox hosts.** The `*.roblox.com` hosts seen in v1's data that are **added** to v2's shipped list, with
  their request counts. Check none looks wrong. At most 200 hosts fit; any left out are listed.
- **Rules.** One table per rule type: v1 key, v2 id, result, notes. User-Agent rule ids are kept. A bypass entry that
  is a range is `invalid` ("never matched in v1": v1 compared bypass entries as exact strings, so it never worked).
  A single-address bypass entry is imported with an expiry: the earlier of its v1 expiry and 24 hours after the
  import (`bypass_default_expiry_h`; its note says "expires after 24 h (the v2 default; v1 entries never expired)"),
  because v2 treats a bypass that never ends as a risk. An address you still want exempt after the cutover day must
  be bypassed again on the Protection page (Bypass card) with the expiry you choose. A rule whose text holds a
  secret is refused. Under it, `throttle_tiers` is the escalation ladder; a rung whose text held a secret is kept
  with `[redacted]` and a warning. v1 saves its ladder even when nobody edited it; a v1 ladder equal to v1's built-in
  one counts as v1's default, so v2's own ladder stays (its rungs 3 and 4 already say "on the DevForums or Twitter",
  your answers B13 and B15) and the report says `already_imported`. Only if you had edited v1's ladder and an imported
  rung tells callers just to "contact CeaselessQuokka", add "on the DevForums or Twitter" on the Protection page
  after the switch.
- **Pause and throttle-all.** v1's pause and emergency limit, and what v2 will start with. If v1 is paused when the
  window's copy is taken, v2 starts paused; with throttle-all on, v2 starts with the emergency limit (section 3.3).
- **Text rewrites (plan C5).** Every admin-written text (messages, reasons, notes) whose em or en dash was replaced;
  the file names the dash in words. An en dash with no spaces between two digits (a range such as 10-20) or between
  two letters became a plain hyphen; a dash at the start or end of a line was dropped; two dashes around an aside
  became parentheses; every other dash became a comma, colon or semicolon. Fix any wording you dislike in the
  dashboard later.
- **Credential files.** Every row should say `already_present` (step 2.4 wrote them), or `no_source` where step 2.4
  said so too. A token line that was **discarded** (rule C1) is listed here, masked. Anything else: see step 4.4.
- **Admin account.** `imported`, the username, and any password policy problem. v2 wants 14 or more characters; a
  shorter password is still imported so you can sign in, and you change it after (section 5.5). A warning that no
  email address was found means the emailed code cannot be sent: the account is still created, so after the switch
  give it an authenticator from the console with `scripts/create_admin.py` and `--reset-mfa` (section 5.1; the
  script refuses to create an account whose name already exists).
- **Statistics (metrics.db).** v1's lifetime totals become one snapshot (`v1.requests_total`, `v1.roblox_429_total`,
  `v1.roblox_429_per_10k_requests`), plus the fingerprint, error and probe rows. The Overview's Key numbers card
  shows the last of the three under its "Roblox 429s per 10,000 requests" tile, as "v1 lifetime baseline: ... per
  10,000 requests".
- **Not migrated.** Sessions, emailed codes, login challenges, trusted devices, invalidation links, v1's HMAC key and
  session secret, cache files, per-worker files and recent-event lists. Expected: a security reset, and data v2
  rebuilds by itself.

About damaged numbers in v1's two files, `roxy_data.json` and `roxy_state.json` (the NaN that blanked v1's dashboard
came from the data file): the migrator never stops on them. A time that is not a finite number, is zero or negative,
or lies more than one day after the moment of the run is read as missing (a bypass expiry may lie further ahead). A
count that is not a finite number (NaN or infinity) is read as 0, and a count larger than 2**53 (the largest whole
number a float holds exactly) is capped there. The JSON report writes any such value as `null`, so tools can always
read it. The patched v1 already cleans these values when it loads the file, so the copy you take in step 4.3 should
have none.

### 3.3 Before the window

- Anything you want different in the import, change it in v1 now (the migrator only reads v1). Run the dry run
  again to confirm.
- Pause and throttle-all carry over. The migrator imports both switches on its first real run, so if v1 is paused
  (or under throttle-all) when you stop it in step 4.1, v2 starts paused (or under throttle-all) too, as v1 would
  have after a restart. The first deploy still goes through: its smoke test sends a real proxy request, and when the
  new color reports the switch it accepts exactly Roxy's own answer to it (503 with `Roxy-Refusal: paused`, or 429
  with `Roxy-Refusal: throttle_all`) and says so on its `proxy` line. Callers then get that answer from the switch
  in step 4.8 until you turn it off. If you do not want v2 to start that way, switch it off in v1 before step 4.1. (In
  v1's dashboard, the top bar has the "Pause Proxy" and "Throttle All" buttons; while a switch is on its button reads
  "Resume Proxy" or "Stop Throttle All", and a banner shows.)

### 3.4 Build the release ahead of the window

The first deploy fetches the commit and builds its Python environment, which takes several minutes on this server.
Do that part now, while v1 still serves, so it is not part of the outage:

```sh
sudo -iu roxy-deploy /opt/roxy/deploy.sh --build-only <sha>
```

- It runs steps 1 and 2 of a deploy only (fetch the commit, build `/opt/roxy/releases/<sha>` with its `.venv` and
  static files) and starts, switches and records nothing: no color, no nginx, no sudo.
- Expect `Build-only run of <sha> started: fetch and build; nothing is started or switched.`, then
  `Release <first 12 characters> is built; deploy it with: /opt/roxy/deploy.sh <sha>` and `Done.`
- If it fails, it removes the half-built release and sends no deploy alert; read the error, fix it and run it again.
  Nothing else changed.
- Build the same `<sha>` you deploy in step 4.6. If `main` moves in between, build the new commit too.

## 4. The maintenance window

### 4.0 Before you start

- Sections 1 to 3 are done, including the build of step 3.4; you have `<sha>`, the dry run report, your mailbox and
  your phone.
- Open two SSH sessions as `ubuntu`. In each, run `cd /`, so commands you run as other users never start in a
  directory they cannot read.
- Write down the time of each step below. `DECISIONS_REVIEW.md` and the next cutover will thank you.

### 4.1 Stop v1 (do not pause it)

```sh
curl -sS --resolve <your site>:443:127.0.0.1 https://<your site>/health
sudo systemctl stop roxy
systemctl is-active roxy
```

- The first command asks the live site on this machine. Note whether it shows `"Paused":true`, and whether v1's
  dashboard shows the "Throttle-All is active" banner: v2 will start the same way (section 3.3).
- v1 is stopped, not paused. Stopping it freezes its files, so the copy in step 4.3 is consistent, and frees its
  memory (about 345 MB): v1 and a v2 color do not fit the 909 MB server together. The plan's window paused v1
  instead; a pause would also be carried into v2.
- `is-active` must print `inactive`. From now until step 4.8, callers get 502 from nginx.
- **OWNER:** open your DataImpulse dashboard and write down the traffic balance it shows (for example 4,775.43 MB,
  the figure of 2026-10-14) and the time. Neither v1 nor v2 uses the rotator now, so this figure is exact. Step 5.1
  ("Owner choices after the first sign-in") turns it into the guard for the prepaid pool.

### 4.2 Memory with Roxy stopped

```sh
free -m
```

Read the `used` value on the `Mem:` line: that is the operating system and nginx alone (the `Swap:` line of step
2.10 should show little or nothing used). The plan assumes about 200 MB; at 200 MB or less it holds as written. It
must be **at most about 250 MB**: 909 MB minus a color at its 500 MiB limit minus a new one-worker color (155 MiB)
leaves 254 MB for everything else, which is the deploy worst case of section 1.5. Between 200 and 250 MB it still
fits, with less room to spare. Write the number down for `DECISIONS_REVIEW.md`.

If it is higher, something else uses the memory (`ps aux --sort=-rss | head` shows the largest processes).
**OWNER:** go on only if you understand why; otherwise start v1 again (section 6.3) and sort it out first.

### 4.3 Take the final copy of v1's files

```sh
sudo cp -a /etc/roxy /root/roxy-v1-final
sudo rm -rf /root/roxy-v1-final/credentials
```

The migrator reads this frozen copy. It is a record of v1 at the cutover, and a rerun reads exactly the same input.
v2's own credential directory is removed from the copy, so no second copy of the keys lies around.

### 4.4 Migrate for real

```sh
sudo ~/roxy-v2-src/.venv/bin/python ~/roxy-v2-src/scripts/migrate_from_v1.py \
  --v1-root /root/roxy-v1-final --state-dir /var/lib/roxy --credentials-out /etc/roxy/credentials \
  --import-admin-password --report /root/roxy-migration-final
echo "exit $?"
sudo less /root/roxy-migration-final.md
```

(Add the extra flags of step 2.4 if you needed them.) This takes about a minute. It creates the four databases in
`/var/lib/roxy`, applies every expand migration, seeds the built-in defaults (every seed version at once on a new
install; version 2 adds the 8 client address headers as ignored value headers), imports everything the dry run
showed, finds the credential files already in place, records the import in `control.db`, and finally gives every
database file it made (and SQLite's `-wal`, `-shm` and `-journal` files) to the owner and group of `/var/lib/roxy`
(`roxy`), mode 0640, also after a failed step. It runs as root, and the service, which runs as `roxy`, must own them.

Check the report:

- `Result: imported`, exit 0, and no `Error:` line (a database file it could not hand over is an `Error:` line).
- Pause and throttle-all: what step 4.1 showed (section 3.3).
- Credential files: every row `already_present` (or `no_source`, as before). If `roblox_credential` says
  `kept_existing_different`, v1's token changed since step 2.4: v2 keeps the older one. After the switch, put the
  current cookie in on the Credential page (Replace card, "Replace the credential": it asks for a current
  authenticator code, the typed confirmation `replace the credential` and a reason), which is the deliberate
  replacement rule C1 asks for. (Until then callers are not affected: D1 keeps the credential off their requests.)
- Admin account: `imported`.
- The rest as in the dry run. One difference is expected: if `files.txt` names its files with full paths
  (`/etc/roxy/...`), each gets a warning that it was read by its file name inside the copy. That is the copy doing
  its job (the migrator never reads outside `--v1-root`).

If the exit status is 1, read the errors, fix the cause, and run the same command again: the migrator finishes what
the failed step left out and never imports anything twice. If it is 2, nothing was written: read the error line.

**The expand migrations, and why they matter before any switch.** v2 workers refuse to start on a database older
than the release needs, and this release needs `metrics.db` at version 10 (`REQUIRED_SCHEMA`). The migrator applied
them all just now, with the same runner the deploy uses. The four newest are:

- `0007_limit_samples`: a column on the request samples (the sampling rate in force) and a table of sampled refused
  requests, so the dry runs of limit changes count what a limit refused.
- `0008_user_agent_detail`: four empty columns for the User-Agent drill-down. Instant on any size.
- `0009_dashboard_read_indexes`: computed columns and 10 partial indexes that make the dashboard's 90-day cards fast.
  On a `metrics.db` of plan 6.6's size it holds the database's write lock for about 8 to 10 seconds and adds about
  405 MiB. Here the file holds only the imported v1 rows, so it took a moment.
- `0010_roblox_answers`: four new, empty tables (minute, hour, day and month) that count every answer Roblox gives
  Roxy's calls for callers, by status class, retries included, as v1 counted them. The Overview's "2xx from
  Roblox", "4xx from Roblox" and "5xx from Roblox" tiles read them. Instant. Nothing is filled in for the past (there
  is no v2 traffic before it), so those tiles count from the upgrade on and say so for a range that starts earlier.

On later deploys, new expand migrations run in the new color's start-up step, before nginx switches; the running
color keeps serving, and its metrics wait and retry while a migration holds the lock. Step 4.7 checks the versions.

### 4.5 Check who owns the databases

```sh
sudo ls -l /var/lib/roxy
```

Nothing to change by hand: the migrator handed every file over at the end of step 4.4. You should see `control.db`,
`hot.db`, `metrics.db` and `cache.db` (and any `-wal` or `-shm` file beside them) owned by `roxy roxy` with
`-rw-r-----`. If one is not, the report of step 4.4 has an `Error:` line that names it and why (for example a link
or a special file where a database should be, which the migrator never follows): fix the cause and run step 4.4
again, which also hands the files over again.

### 4.6 Start v2 beside v1: the first deploy

```sh
sudo -iu roxy-deploy
ROXY_DEPLOY_PUBLIC_CHECK=0 /opt/roxy/deploy.sh <sha>
exit
```

- No color has run yet, so the deploy starts **blue** on 127.0.0.1:8001 (the plan said green on 8002; green is
  simply the next deploy's color). v1's files and its stopped unit stay where they are.
- `ROXY_DEPLOY_PUBLIC_CHECK=0` is needed because v1's nginx site still holds the public name until step 4.8: the
  deploy's checks through nginx would reach v1's site instead of v2. The checks on blue's own port and socket still
  run.
- No color is active yet, so the deploy uses normal mode: blue starts with two workers (about 275 MiB at start),
  which fits in the roughly 700 MB free with v1 stopped.
- Expect 2 to 4 minutes (the release was built in step 3.4). The log goes through steps 1 to 9. The lines to look
  for: `Release <first 12 characters> is already built.` and `Dependencies unchanged; keeping the existing
  environment.` (step 3.4 did that work), `No active color yet: this is the first deploy; starting blue.`, `blue is
  ready on version ...`, the smoke test ending in `smoke_remote: 7 of 7 checks passed on blue`, `nginx config
  changed in this release; installing it through the root wrapper.`, `blue stayed healthy.`, `Dependency audit not
  recorded ...` (normal for a deploy started by hand) and `Site successfully deployed.`
- If v2 starts paused or under throttle-all (section 3.3), the smoke test's `proxy` line reads, for example,
  `PASS  proxy  the color is paused (/health says Paused): Roxy's own paused refusal, status 503 with Roxy-Refusal:
  paused; the proxy route is mounted`, and the run still ends `7 of 7 checks passed on blue`. Any other refusal is a
  failure.
- Step 6 installs v2's nginx site and points it at blue, but v1's site still answers the public name, so callers
  still get 502 until step 4.8.

If it fails, the deploy puts things back itself: it stops blue and leaves v1's site as it was. (If it got past step
6, v2's nginx site stays installed, because there was no earlier v2 config to put back; v1's site still answers the
public name.) Read why:

```sh
cat /var/lib/roxy-deploy/last_failure.json
journalctl -u roxy@blue -n 100 --no-pager
```

Then fix the cause and run the same deploy command again (the built release is reused), or go back to v1 (section
6.3). A deploy failure also sends the alert "Roxy: deploy <short sha> failed at step <n>". A first deploy that
failed after its switch leaves nginx's link to blue in place while blue is stopped and has no release link; the
retry sees that nothing serves, logs `nginx points at blue, but roxy@blue.service is not running and has no release
(a first deploy that failed after its switch); treating this as the first deploy.` and starts blue again, so the
`blue` commands of steps 4.7 to 4.9 and section 6.3 still hold.

### 4.7 Health gate before the switch

The deploy already checked that blue reports ready on its private socket (`Ready`, `PersistenceOK` and the right
`Version`) and ran the smoke test. Look for yourself:

```sh
cat /var/lib/roxy-deploy/deployed_version
sudo curl -sS --unix-socket /run/roxy-blue/internal.sock http://localhost/internal/ready
sudo -u roxy /opt/roxy/releases/current-blue/.venv/bin/python -m roxy.storage.migrate --status --state-dir /var/lib/roxy
```

- The first prints `<sha>`.
- The second prints JSON with `"Ready":true` and `"PersistenceOK":true`.
- The third prints `metrics: version 10 (this release requires 10)`, and `control: version 1 (this release requires
  1)` and the same for `hot` and `cache`.

Anything else: do not switch. Read `journalctl -u roxy@blue`, or go back to v1
([section 6.3](#63-during-the-window-before-the-switch-steps-41-to-47)).

### 4.8 Switch nginx to v2

```sh
sudo rm /etc/nginx/sites-enabled/roxy
sudo nginx -t && sudo systemctl reload nginx
curl -sS --resolve <your site>:443:127.0.0.1 https://<your site>/health
sudo -u roxy-deploy /opt/roxy/releases/current-blue/.venv/bin/python \
  /opt/roxy/releases/current-blue/scripts/smoke_remote.py --color blue --env-dir /etc/roxy --nginx 127.0.0.1:443
sudo systemctl disable roxy
```

- Removing v1's link leaves v2's site as the only one for the public name; the file stays in `sites-available`. If
  `nginx -t` fails, nothing was reloaded: put the link back with
  `sudo ln -s /etc/nginx/sites-available/roxy /etc/nginx/sites-enabled/roxy` and read the error.
- After the reload, callers reach v2. Write down the time: the outage is over.
- `/health` must now be v2's answer: JSON with a `"Degraded"` key (v1's answer has none), and `"Degraded":[]`,
  `"PersistenceOK":true` and `"Status":"ok"`. `"Paused"` is what v1 had at step 4.1: if it says `"Paused":true`
  (or v1 was under throttle-all), callers get Roxy's pause (or emergency limit) answer until you switch it off with
  the "Resume proxy" (or emergency limit) control in the dashboard's top bar, or `roxyctl resume` (and
  `roxyctl throttle-all off`; step 4.9 defines the alias).
- A normal deploy runs this smoke test through nginx after its switch (with `--skip-proxy`); step 4.6 skipped it.
  Here it also repeats the proxy request. It must end in `7 of 7 checks passed on blue`, with the static file served
  through nginx with `Strict-Transport-Security` (a paused color passes with its `proxy` line saying so, as in step
  4.6).
- `systemctl disable roxy` keeps v1 from starting at the next boot beside v2. Its files stay.
- From your own computer, `curl -sS https://<your site>/health` should show the same.

### 4.9 Check Proxy Health and the first backup

The operator CLI runs as the `roxy` user. The runbooks call it `roxyctl`:

```sh
alias roxyctl='sudo -u roxy /opt/roxy/releases/current-blue/.venv/bin/python /opt/roxy/releases/current-blue/scripts/ctl.py'
roxyctl status
sudo systemctl start roxy-backup.service
roxyctl health-run --include-credential
```

- `status` shows blue's socket answering, pause and throttle-all off, the leader and the last backup.
- The backup runs now instead of tonight at 03:30, so the backup check has something to look at.
- `health-run` is Check Proxy Health from the shell (the same as the Health page). `--include-credential` adds the
  credential check, which spends one call on the Roblox account. The exit status is 1 when a check fails.
- Expected: H-SECRETS-PERMS reports that `/etc/roxy` belongs to `ubuntu` (until section 5.4). H-VERSION passes, and
  its value says "advisories not recorded" (normal after a deploy started by hand). Anything else that fails or
  warns: open its runbook in `docs/RUNBOOKS.md` (the check's fix link on the Health page goes there too).
- The health run only logs in to the alert channels. A real test email follows after your first sign-in (step 5.1,
  "Owner choices after the first sign-in", item 1): you kept v1's alert email setup as it is (answer B14), and the
  test proves it still works.

The alias names blue. After a later deploy the live color may be green: `readlink /etc/nginx/roxy-active-upstream.conf`
tells you which.

### 4.10 Watch

Sign in now (section 5.1) so you can watch the dashboard as well as the shell. Watch closely for the first hour;
run Check Proxy Health again after 15 minutes and after the hour.

What to watch, where, what good looks like, and when to act (the runbooks named are in `docs/RUNBOOKS.md`):

- **The public health answer.** `curl -sS https://<your site>/health` from your own computer, every few minutes.
  Good: `"Status":"ok"`, `"Degraded":[]`, `"Paused":false`, `"PersistenceOK":true`. Any change: read
  `journalctl -u roxy@blue`.
- **Errors in the log.** `journalctl -u roxy@blue -f` (Ctrl+C to stop). Good: no tracebacks. Repeated errors: the
  System page, Error log card, and the "Unhandled errors" runbook.
- **Restarts and memory.** `systemctl show roxy@blue -p MemoryCurrent,NRestarts`. Good: `NRestarts=0`, and memory
  that grows for a while and settles at about 365 to 405 MiB, under `MemoryHigh` (420 MiB is 440,401,920 bytes).
  `MemoryCurrent` also counts file cache the kernel can drop, so it may sit close to 420 MiB without harm; the
  per-worker memory on the System page, Workers card, is the closer measure. Restarts, or memory pressing 500 MiB:
  the "Service down" runbook (after an out-of-memory kill, lower `cache_memory_bytes` first). An out-of-memory kill
  ends only one worker (the unit sets `OOMPolicy=continue`; gunicorn starts another and the color keeps serving), so
  look for it in the journal (`journalctl -u roxy@blue | grep -i "out of memory"`) as well as in `NRestarts`.
- **Free memory.** `free -m`. Good: `available` stays above about 200 MB (909 minus a color at its 500 MiB limit
  minus about 200 for the system), and the `Swap:` line shows little or nothing used. Below that: the System page,
  Workers card, shows which worker grew. Steady swap use means something outside Roxy grew (the colors cannot swap,
  step 2.10): `ps aux --sort=-rss | head` shows what.
- **Roblox 429s.** The Overview tile "Roblox 429s per 10,000 requests" (with "v1 lifetime baseline" under it) and the
  Upstream page, Roblox 429s card. Good: below the v1 baseline. H-429-RATE warns at 0.5% of upstream calls and fails
  at 2%; the alert "Roxy: Roblox is rate-limiting us" fires at 2% for 10 minutes. Then follow the "Roblox is
  rate-limiting us" runbook.
- **Caller errors.** The Traffic page, Status codes card ("answers to callers"), which also shows who answered
  (Roblox, Roxy or the cache). Good: few 5xx, and those from Roblox. H-ERR-RATE warns when 0.5% of callers got a 5xx
  in 15 minutes and fails at 2% (a deliberate pause is left out of it): the "Caller errors" runbook.
- **Anonymous answers (there was no shadow week, section 1.2).** The Overview's "4xx from Roblox" tile (every answer
  Roblox gave Roxy's calls, retries included) and the Endpoints page. Good: no rise in 401 or 403. A rise means some
  endpoint answers only signed-in callers: note which (Endpoints page) for the private endpoint guard (D1,
  `ROADMAP.md` item 1). Do not add it to the credential allowlist: your D1 answer keeps your account off callers'
  requests.
- **Workers and leader.** The System page, Workers and Leader cards, or `roxyctl leader`. Good: two workers, one
  leader, fresh heartbeats. Otherwise: the "Workers or leader missing" runbook.

Roll back ([section 6.4](#64-after-the-switch-step-48-or-later)) if the site is down and you cannot fix it within
about 15 minutes, or if v2 itself (not Roblox) keeps answering callers with 5xx. A Roblox 429 rate that does not fall
is a tuning matter first (the Recommendations page), not a reason to roll back.

The next day: the nightly backup ran (`sudo cat /var/lib/roxy/audit/backup.json`), H-SYSTEMD passes after 24 hours
without restarts, and the daily digest email arrived. The digest is on by default (`alert_digest_enabled`, your
answer A4), goes out at `alert_digest_hour` (9:00, New York time), and is sent whatever `alert_min_severity` says;
both are on the Settings page, Alerts card.

## 5. After the switch

### 5.1 First sign-in (D5)

1. Open `https://<your site>/admin` and sign in with v1's admin username and password ("Login").
2. Roxy emails a code to v1's admin address, with the subject `Admin 2FA`, as v1 did. The second step asks for it
   ("Emailed code"): type it and press "Verify". "Send a new code" sends another (at most every 30 seconds, 5 in
   all).
3. You land on "Set up your authenticator app". Press "Show the QR code", scan it with your authenticator app (or
   type the key shown under it), type the 6-digit code and press "Confirm".
4. "Save your recovery codes": 10 codes, shown **only now**. Each lets you sign in once without the phone. Store them
   offline or in a password manager ("Copy the codes"). "Also add a passkey (optional)" is a good second way in.
5. "Continue to the dashboard". From now on, every sign-in asks for the authenticator code (or a passkey or a
   recovery code); the emailed code is off (`admin_email_code_enabled` stays 0) and the one-time bootstrap is used up.

If the email never arrives, check `smtp_password` and `alert_emails` (step 2.4), then test the mail login from the
shell with `roxyctl health-run --check H-ALERTS` (it logs in to the alert channels without sending) and read
`journalctl -u roxy@blue -n 200 --no-pager`.

If you cannot get in at all, or the report said no admin was imported, use the console. The script needs the
authenticator key (root only) and must write the database as `roxy`, so it runs through systemd, as in the "Admin
locked out" runbook:

```sh
sudo systemd-run --wait --pty --uid=roxy --gid=roxy -p UMask=0027 \
  -p LoadCredential=totp_encryption_key:/etc/roxy/credentials/totp_encryption_key \
  /opt/roxy/releases/current-blue/.venv/bin/python /opt/roxy/releases/current-blue/scripts/create_admin.py \
  --username <your admin name> --email <your address> --state-dir /var/lib/roxy
```

It asks for a password twice, shows the authenticator QR code in the terminal, asks for a first code, and prints the
10 recovery codes once. For an existing account use `--reset-mfa` (new authenticator) or `--reset-password` instead
of `--email`.

#### Your admin account until the account page ships

Your v1 admin name and password come over at the cutover (`--import-admin-password`, steps 3.1 and 4.4; your answer
A9), and the first sign-in above adds your authenticator. Changing your name, password or email in the dashboard
comes later (`ROADMAP.md`, item 4). Until then the console script `scripts/create_admin.py`, run through
`systemd-run` exactly as above, is the only way, and this is all it can do:

| You want | Options after `--username <your admin name>` | What else happens |
|---|---|---|
| A new password | `--reset-password` | It asks for the new password twice and checks it: 14 to 1,024 characters, not a common password, not containing the username, not just one or two repeated characters. Every session of the account ends; your authenticator and trusted devices stay. |
| A new email address (where emailed codes go) | `--email <address>` together with `--reset-password` or `--reset-mfa` | The email cannot change on its own. With `--reset-password` you may type your current password twice as the new one, if it meets the rules. |
| A new authenticator (a lost phone) | `--reset-mfa` | A new QR code in the terminal, a first code to confirm it, and 10 new recovery codes; your passkeys, trusted devices and sessions are removed. |
| A second admin | `--username <new name> --email <address>` with no reset option | A password, an authenticator and 10 recovery codes for the new account. The script refuses a name that already exists. |

What it cannot do: change the sign-in name of an account (a second admin under the new name is the only way, and
neither the console nor the dashboard can delete the old one), list the accounts, or delete one. Every change it
makes is written to the audit log.

#### Owner choices after the first sign-in

Once you are in, apply your answers of 2026-10-14 that are settings. Each change is written to the audit log, and
the Settings page's search finds every setting named below.

1. **A test alert (answer B14).** Settings page, Alerts card: press "Send test alert"
   (`POST /admin/api/v1/system/alerts/test`). The email must reach v1's alert address within a minute or two. If it
   does not, follow the "Alert channels down" runbook in `docs/RUNBOOKS.md`.
2. **The User-Agent experiment: on (answers D23 and A6).** Upstream page, Routing card: switch
   `ua_experiment_enabled` on. A run starts at the moment you switch it on (that is why it is not on by default),
   splits direct traffic between the browser-like User-Agent and `ua_experiment_alt_user_agent` for
   `ua_experiment_days` (7 days), then ends by itself. The UP-UA-EXPERIMENT recommendation compares the two sides.
   Until each side has its own counter (`ROADMAP.md`, item 6) it estimates them from the last 24 hours of request
   samples, so the week may end without a clear answer; switching it off and on again starts a new run.
3. **The public site texts (answers B13 and B15): check them.** This release ships your answers as the defaults: no
   bug bounty paragraph, no support section, and the contact "CeaselessQuokka on the DevForums or Twitter" on the home
   page, in the user guide and in rungs 3 and 4 of v2's own throttle ladder. Open your site's home page and look. If a
   text is not as you want it, change it on the Settings page, Public site card: an empty `site_bug_bounty_text` or
   `site_support_links` hides its section, and `site_contact_name` holds the contact. The footer stays.
4. **The time zone (answer A3): nothing to do.** `ui_timezone` stays `America/New_York`. Times in each device's own
   zone come later (`ROADMAP.md`, item 9); meanwhile, on a device that is not on New York time, pick a zone in the
   user menu's Preferences.
5. **The rotator session template (answer B12): nothing to do.** `rotator_session_username_template` stays empty, so
   every rotator call gets a new IP address, as you prefer.
6. **A guard for the prepaid DataImpulse pool (answers D12 and B11), until the prepaid mode ships.** Egress page,
   Budget card:
   - `rotator_quota_gb_per_month`: the balance you wrote down in step 4.1, in GB, rounded down to one decimal. Roxy
     counts 1 GB as 1,000 MB, so 4,775.43 MB becomes 4.7. Rounding down leaves a small reserve (about 75 MB here) for
     the difference between Roxy's count and DataImpulse's.
   - `rotator_billing_day`: the day of the month of the cutover (1 to 28; on the 29th to the 31st use 28). Roxy's
     count starts at 00:00 UTC that day (the evening before, New York time), and nothing used the rotator through v2
     before the cutover, so it starts right.
   - Leave `rotator_budget_alert_pcts` (50, 80 and 95) and `rotator_hard_stop_pct` (100) as they are: Roxy emails you
     when half, 80 and 95 percent of the balance are used, and stops using the rotator at 100 percent. Callers are
     then served direct only, never refused for it.
   - Optional, a second guard: `rotator_daily_cap_mb` 100 keeps any one day under 100 MB.

   Why this is only a stand-in: you bought a prepaid pool (5 GB, no monthly allowance), but Roxy's budget today is
   monthly. On each billing day it starts counting from zero again, as if the balance had refilled. So once a month,
   on that day, read the balance on DataImpulse and enter it again in `rotator_quota_gb_per_month` (the alerts start
   over with it). The prepaid mode (`ROADMAP.md`, item 2) replaces all of this with the balance you enter, a stop at
   a small reserve and a "lasts until" date.

   How much it matters: little, at the defaults. With `rotator_weight` 0 (D13) the rotator carries traffic only while
   the direct path cools down after Roblox 429s, while its rate bucket is more than 80 percent full, or when a routing
   rule asks for it. v1 sent a quarter of its traffic through the rotator (its weight was 25) and used about 225 MB in
   at least 3 months; v2 should use far less. The guard is there for a runaway (a long cooldown under heavy traffic),
   not for normal use.
7. **Optional: refuse sign-in endpoints now.** Protection page, Endpoint blocks: add `auth.roblox.com` (the whole
   service) with the message "This endpoint needs a signed-in Roblox account, and Roxy never signs in for callers, so
   it is not available through this proxy." That stops login and password reset attempts through your server's
   address until the private endpoint guard ships (`ROADMAP.md`, item 1). It refuses every address of that service,
   including its few public ones (such as checking whether a username is valid): leave it out if a game you know
   uses them.

### 5.2 Enable the deploy workflow

Until now `.github/workflows/deploy.yml` has `if: false` on its deploy job, so pushes to `main` only run CI. Turn it
on once the first day went well:

1. **OWNER:** in the repository's GitHub settings, set the secrets: `LIGHTSAIL_USER` = `roxy-deploy`;
   `LIGHTSAIL_SSH_KEY` = the private key of step 2.8; `LIGHTSAIL_HOST_FINGERPRINT` = the server's host key
   fingerprint (on the server, `ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub` prints it; check which form
   `appleboy/ssh-action` expects). `LIGHTSAIL_HOST` stays as it is. Overwriting `LIGHTSAIL_SSH_KEY` also means GitHub
   no longer holds the key v1 used to log in as `ubuntu`.
2. **OWNER:** edit `.github/workflows/deploy.yml` and delete the line `if: false` of the `deploy` job (and the comment
   line above it). Commit and push to `main`.
3. That push runs CI and then the deploy over SSH. Watch it in the Actions tab. This deploy goes to **green**
   (127.0.0.1:8002), in low-memory mode (a warm blue leaves less than 700 MB free), then stops blue.
4. Check on the server: `readlink /etc/nginx/roxy-active-upstream.conf` names `roxy-upstream-green.conf`, and
   `cat /var/lib/roxy-deploy/deployed_version` names the new commit. Change the `roxyctl` alias to `current-green`.

From then on every push to `main` deploys. A failed deploy switches back by itself and emails "Roxy: deploy <short
sha> failed at step <n>"; see the "Deploy failed" runbook.

### 5.3 The v1 deploy workflow

There is nothing to disable: v2's `.github/workflows/deploy.yml` replaced v1's file at the merge (step 1.4), so v1's
"Deploy to Lightsail" workflow no longer exists on `main`. Do not disable the workflow in GitHub's settings: it is the
same file, now v2's. On the server, `~/UpdateBuild.sh` stays until section 5.6; nothing runs it any more.

**Never run `~/UpdateBuild.sh` again:** it clones `main`, which is v2 now, and would lay v2's tree out as if it were
v1. v1 comes back from its own files on the server (section 6), and its code is the tag `v1-final` (step 1.4).

**OWNER:** if v1's Actions key had its own line in `/home/ubuntu/.ssh/authorized_keys` (a key used only by GitHub),
remove that line, so no automation can log in as `ubuntu` again. Keep your own key.

### 5.4 Give `/etc/roxy` to v2

While v1 might run again, `/etc/roxy` stays v1's (owned by `ubuntu`, with one ACL entry for the deploy account).
Once you no longer expect to go back to v1 at short notice (a day or a few), hand it to v2:

```sh
cd ~/roxy-v2-src && git fetch && git checkout --detach <sha>
sudo ~/roxy-v2-src/deploy/install-system.sh --take-over-etc
stat -c '%U:%G %a' /etc/roxy
sudo systemctl start roxy-audit.service
```

- Use the commit that is live now as `<sha>` (`cat /var/lib/roxy-deploy/deployed_version`).
- `--take-over-etc` makes `/etc/roxy` `root:roxy` with mode 0750 and removes the ACL entry. `stat` must print
  `root:roxy 750`.
- v1 can no longer save its files there after this; section 6.5 says how to undo it if you ever roll back.
- The audit runs again; H-SECRETS-PERMS should pass on the next health run.

### 5.5 The first week

- Tell your users what changed for callers: decision D4 and the other changes in `CHANGES.md`, "Behavior changes
  callers may notice".
- Bypass entries imported from v1 expire 24 hours after the import (section 3.2, Rules). Renew on the Protection page
  (Bypass card) any address that must stay exempt, with an expiry you choose.
- Credential page: the Status card says "Working" ("Not checked yet" until the first probe) and the Allowlist card
  is empty (D1).
- Recommendations page: read what the engine suggests after the first days of traffic.
- Settings page: decide by hand the keys the report showed as never imported (section 3.2), and reword any text the
  report's "Text rewrites" table changed badly.
- If the report said your password is under the v2 policy (14 or more characters), set a new one with the command of
  section 5.1 and `--reset-password` instead of `--email` (there is no password change page yet: section 5.1, "Your
  admin account until the account page ships").
- Run `sudo certbot renew --dry-run` once: certificate renewal must still work with v2's nginx site. v2's site
  answers renewal challenges (`/.well-known/acme-challenge/`) from `/var/www/letsencrypt`, the webroot of
  `certbot renew --webroot -w /var/www/letsencrypt`. If the dry run fails, see the "Certificate" runbook.
- Contract migrations (database changes that drop or rename) never run by themselves, and this release has none.
  When a later release ships one, the color's start-up step names it in the journal
  (`journalctl -u roxy@blue -u roxy@green | grep "contract migrations pending"`), and `deploy/README.md`
  ("Contract migrations (by hand, never automatic)") gives the command to run once you will not roll back past it.
- **OWNER:** decide on encrypted and off-box backups (step 2.6, D15) if you have not. An off-box copy needs the age
  recipient file: without it the backup refuses to send the set and fails, on purpose.
- Add the measured numbers (step 4.2, the outage length, anything that surprised you) to `DECISIONS_REVIEW.md`.

### 5.6 Decommission v1 after 30 days

Keep everything of v1 for 30 days after the switch, stopped, so section 6 stays possible. **OWNER:** set the date.
Then:

1. Look before you delete: `sudo ls -la /etc/roxy` and `sudo cat /etc/roxy/files.txt` (the names of v1's secret
   files).
2. Keep everything v2 put in `/etc/roxy`: `roxy.env`, `blue.env`, `green.env`, `nginx-hints.env`, `credentials/`,
   and `backup-age-recipients` if you made it.
3. Remove v1's files from `/etc/roxy`: the files `files.txt` names (they include v1's admin password in plain
   text), `files.txt` itself, `roxy_state.json`, `roxy_data.json` and its `.bak`, `rotate_proxy.txt`, v1's cache
   directory `cache/`, and its per-worker files (`roxy_routing.json`, `roxy_throttle.json`, `roxy_coord.json`,
   `roxy_tarpit.json`, `roxy_workers.json`, `roxy_capture.json`).
4. Remove v1's unit (`systemctl cat roxy` shows its path on the first line), then `sudo systemctl daemon-reload`, and
   v1's site file `/etc/nginx/sites-available/roxy`. Leave `roxy@.service` and `roxy-alert@.service` alone: they
   are v2's now (step 2.5).
5. Remove v1's code and helpers from your home: `~/Roxy`, `~/SiteEnv`, `~/Tooling`, `~/UpdateBuild.sh`,
   `~/alert_on_failure.py` and `~/roxy-hotfix-backup-20261009`.
6. Remove the copies that hold v1's secrets: `/root/roxy-v1-final` and `/root/roxy-v1-backup.tar.gz`. **OWNER:** keep
   an offline copy of the archive first if you want one, and keep `/root/roxy-v1-final` until the private endpoint
   guard's report of what callers read through v1 with your cookie has run (`ROADMAP.md` item 1) AND the v1 snapshot
   work of D17 has shipped (`ROADMAP.md` item 8): v2 adds its own counts on top of the fingerprint and error counts it
   imported from v1, so v1's share can be told apart later only from v1's own `roxy_data.json` in that copy.

Keep the migration reports in `/root` (`roxy-credentials-report`, `roxy-migration-dry-run` and
`roxy-migration-final`; secrets are masked in them) and the toolbox `~/roxy-v2-src` (move it to the live commit before
running `install-system.sh` again). Keep your offline key escrow for as long as v2 runs.

## 6. Rollback to v1

### 6.1 What a rollback keeps and loses

The migrator never changes v1's files, so v1 starts again exactly as it was when you stopped it in step 4.1. Nothing
v2 wrote ever reaches v1. Going back loses, from v1's point of view:

- **Traffic, metrics, the Live tail, captures, health runs and recommendations** stay in v2's databases. v1 never
  sees them, and its own counters have a gap for the time v2 served.
- **Settings, rules, bans and allowlist changes made on v2's dashboard** are not in v1. Make them again in v1 if you
  need them.
- **The audit log** of everything done in v2 stays in v2's `control.db`.
- **Your authenticator, recovery codes and passkeys** exist in v2 only. v1 signs you in with its own password and
  emailed code, as before.
- **A cookie set on v2's Credential page** is not in v1, which still uses the token in its own file. If you replaced
  the cookie because the old one stopped working, put the new one into v1's token file (the third file `files.txt`
  names) before starting v1. Still only one credential (rule C1).
- **The cache** is gone; v1 has its own.

v2's databases and credential files stay on disk, unused, so you can try again later (section 6.7).

v1 comes back from its own files on the server, never from GitHub: do not run `~/UpdateBuild.sh` (it clones `main`,
which is v2 now). If v1's files on the server were ever lost, its code is the tag `v1-final` (step 1.4) and its
configuration and code are in `/root/roxy-v1-backup.tar.gz` (step 2.1).

### 6.2 During preparation (sections 1 to 3)

v1 kept running through all of it. To undo the parts that touched shared files:

- The default nginx site: `sudo ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default`, then
  `sudo nginx -t && sudo systemctl reload nginx`.
- `nginx.conf` and v1's alert unit: both are in `/root/roxy-v1-backup.tar.gz` (step 2.1).
- Everything else v2 added (accounts, `/opt/roxy`, `/var/lib/roxy`, `/etc/roxy/credentials`, the env files, the
  timers) is ignored by v1 and can stay.
- GitHub: once v2 is on `main` (step 1.4), v1 can no longer be deployed from GitHub; the running v1 is not affected.

### 6.3 During the window, before the switch (steps 4.1 to 4.7)

v1's nginx site still holds the public name, so starting v1 is enough. If blue was started (step 4.6 or later), stop
it first, so the two never run together on this small server:

```sh
sudo systemctl stop roxy@blue
sudo systemctl disable roxy-boot.service
sudo systemctl start roxy
curl -sS --resolve <your site>:443:127.0.0.1 https://<your site>/health
```

- Disabling `roxy-boot.service` keeps blue from starting at the next boot (it starts whatever color nginx points
  at).
- `/health` must be v1's answer: no `"Degraded"` key.
- Nothing is lost: v2 never served a caller.

### 6.4 After the switch (step 4.8 or later)

Stop v2 first, then give the name back to v1 and start it:

```sh
sudo systemctl stop roxy@blue roxy@green
sudo systemctl disable roxy-boot.service
sudo ln -s /etc/nginx/sites-available/roxy /etc/nginx/sites-enabled/roxy
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl enable --now roxy
curl -sS --resolve <your site>:443:127.0.0.1 https://<your site>/health
```

- Callers get 502 for the minute between the first and the fifth command.
- v2's site stays installed, but v1's site sorts first and answers the public name.
- `/health` must be v1's answer (no `"Degraded"` key) with `"Paused":false`.
- Section 6.1 lists what v2 wrote that v1 does not have.

### 6.5 After section 5.2 or 5.4

Do these first, then follow section 6.4:

- **Deploy workflow enabled (5.2):** put `if: false` back on the `deploy` job of `.github/workflows/deploy.yml` and
  push to `main` before anything else is pushed. Otherwise the next push deploys v2 colors beside v1.
- **`/etc/roxy` taken over (5.4):** give it back to v1 before starting it, with the owner and mode you wrote down in
  step 2.1, for example:

```sh
sudo chown ubuntu:ubuntu /etc/roxy && sudo chmod 700 /etc/roxy
```

  Without this v1 cannot save its state there.

### 6.6 Going back to an earlier v2 release instead

To undo a bad v2 deploy (not the cutover), stay on v2: `/opt/roxy/deploy_rollback.sh`, run as `roxy-deploy`,
switches back to the release the other color last ran, with the same health gate, and
`/opt/roxy/deploy_rollback.sh <sha>` goes to any of the five kept releases. This is possible from the second v2 deploy
on (section 5.2). See the "Deploy failed" runbook in `docs/RUNBOOKS.md` and `deploy/README.md` ("How a deploy runs").

### 6.7 Trying the cutover again

A second migrator run on the same `/var/lib/roxy` adds only v1 items that are new since the first run: settings
changed in v1 meanwhile are not updated, and pause and throttle-all are never imported again. For a clean second try,
set v2's databases aside and repeat section 4 from step 4.1:

```sh
sudo systemctl stop roxy@blue roxy@green
sudo mkdir /root/roxy-v2-attempt-1
sudo sh -c 'mv /var/lib/roxy/*.db* /root/roxy-v2-attempt-1/'
```

The credential files and the key escrow stay valid (they are not in the databases). On the second try:

- In step 4.3 copy to a new name (for example `/root/roxy-v1-final-2`), use it as `--v1-root` in step 4.4, and give
  the report a new name too.
- If the first try's deploy succeeded, nginx still remembers blue as the active color
  (`readlink /etc/nginx/roxy-active-upstream.conf` names `roxy-upstream-blue.conf`) and blue's release link
  `/opt/roxy/releases/current-blue` is still there, so the deploy of step 4.6 starts **green**: then use `green` and
  `current-green` instead of `blue` and `current-blue` in steps 4.7 to 4.9. (A first try whose deploy failed left no
  release link, and the retry starts blue again, as step 4.6 says.)
- After the switch, run `sudo systemctl enable roxy-boot.service` again (section 6.3 or 6.4 disabled it).
- If you gave `/etc/roxy` back to v1 (section 6.5), run `sudo ~/roxy-v2-src/deploy/install-system.sh` again before
  step 4.6, without `--take-over-etc`: it puts back the ACL entry that lets the deploy account read the env files.
