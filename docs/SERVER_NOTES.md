# Server notes: what was changed on the server, and why

A plain-words log of every change made to the production server (Ubuntu 24.04 on Lightsail, 2 vCPU, 909 MB of
memory) for Roxy v2, in the order it happened, with the reason and how to undo it. It is meant to teach as much as
to record: each entry says what the thing is before saying what was done to it. `MIGRATION.md` is the step by step
procedure; this file is the story of what actually ran.

Words used below:

- **root**: the all-powerful account on a Linux server. `sudo` runs one command as root.
- **systemd**: the program that starts, stops and watches the server's long-running programs ("services" or
  "units"). `systemctl` talks to it.
- **nginx**: the web server in front of Roxy. It holds the HTTPS certificate, receives every request from the
  internet and passes it to Roxy on a private port.
- **reload**: telling a program to read its configuration again without stopping; requests in flight finish
  normally, so callers notice nothing. A **restart** stops and starts the program.

## 2026-10-14: preparing the server for v2 (v1 kept serving the whole time)

### 1. A backup of v1's setup

- What: `sudo tar ... -czf /root/roxy-v1-backup.tar.gz etc/roxy etc/nginx etc/systemd/system home/ubuntu/Roxy`
  packed v1's settings, secrets, nginx configuration, service definitions and code into one compressed file in
  root's home folder (only root can read it).
- Why: before changing anything on a server, keep a copy of how it was. If anything goes wrong, this file brings v1
  back exactly as it ran.
- Undo: nothing to undo; delete the file once v1 is retired (`MIGRATION.md` section 5.6).

### 2. Two small packages: `acl` and `age`

- What: `sudo apt-get install acl age`. `apt` is Ubuntu's package manager (like an app store for the command line).
- Why: `acl` lets a folder give one extra account a narrow permission without changing its owner: v1 still owns
  `/etc/roxy`, and the deploy account only needs to pass through it to read v2's settings. `age` is a small
  encryption tool for the offline copy of Roxy's keys (the "key escrow").
- Undo: `sudo apt-get remove acl age` (v2 needs both).

### 3. A swap file and two kernel settings

- **Swap** is disk space Linux may borrow when memory is completely full. Without it, a full memory makes Linux
  kill a program to free some (the "out of memory killer"). With a small swap file, idle programs are moved to disk
  instead and the server slows down for a moment rather than losing a program. Commands: `fallocate -l 1G /swapfile`
  (make a 1 GiB file), `chmod 600` (only root may read it), `mkswap` and `swapon` (turn it into swap and use it), and
  a line in `/etc/fstab` (the list of disks to set up at boot) so it comes back after a reboot.
- **`vm.swappiness = 10`**: how eager Linux is to use swap (Ubuntu's default is 60). 10 means "only under real
  memory pressure"; Lightsail's disk is network storage, so swapping is slow and should stay rare. Within minutes,
  about 17 MB of programs that sit idle all day moved to swap, which is exactly the intended use.
- **`net.ipv4.tcp_migrate_req = 1`**: each of Roxy's two worker processes has its own queue of new connections.
  When a worker restarts (about every 20,000 requests, on purpose, to keep memory in check), connections still
  waiting in its queue used to be dropped; with this setting Linux hands them to the other worker instead. Both
  settings live in `/etc/sysctl.d/90-roxy.conf` ("sysctl" settings are the kernel's knobs; files in that folder are
  applied at every boot).
- **Roxy's own services never swap** (`MemorySwapMax=0` in `/etc/systemd/system/roxy@.service.d/90-no-swap.conf`, a
  "drop-in", a small file that adds lines to a service's definition). Roxy has its own memory limits per color
  (`MemoryHigh=420M`, `MemoryMax=500M`); if Roxy could swap, a color at its limit would slow every caller down
  instead of quickly replacing one worker, which is what all the memory tests measured.
- Undo: `MIGRATION.md` step 2.10 lists the commands.

### 4. nginx: more connections per worker

- What: in `/etc/nginx/nginx.conf`, `worker_processes 2` (was `auto`, which is also 2 on this server) and
  `worker_connections 4096` (was 768), then `nginx -t` (check the configuration is valid) and a graceful reload.
  The old file is kept as `/etc/nginx/nginx.conf.before-roxy-v2`.
- Why: each nginx worker can hold that many open connections at once. v2's tarpit (it holds suspicious requests
  open for a few seconds instead of answering at once) and long-lived dashboard streams need more room than 768,
  and Roxy computes how many requests it may hold from this number.
- Undo: copy the `.before-roxy-v2` file back, then `sudo nginx -t && sudo systemctl reload nginx`.

### 5. The toolbox: a copy of v2 in the `ubuntu` home folder

- What: v2's code went to the server as a git "bundle" (one file holding the history; checked with a SHA-256
  checksum on both ends), was unpacked into `~/roxy-v2-src` at the release commit, and `uv` (a fast Python package
  installer) built its Python environment there.
- Why: root runs the installer and the data migrator from this copy. It is separate from the releases v2 runs from
  (`/opt/roxy/releases/...`), which the deploy account builds itself.
- Undo: `rm -rf ~/roxy-v2-src ~/roxy-v2.bundle` (keep it while v2 runs: `MIGRATION.md` uses it again).

### 6. v2's secret files, written from v1's

- What: the migrator read v1's secret files (never changing them) and wrote one file per secret into
  `/etc/roxy/credentials` (folder `0700`, files `0600`, owned by root: nobody but root can read them): the Roblox
  cookie (only the first one, rule C1), the DataImpulse address, the Gmail app password, the alert addresses, and
  three new random 32-byte keys (`credential_encryption_key`, `totp_encryption_key`, `ip_hash_key`).
- Why: v2 never reads secrets from its settings or environment. systemd hands each file to the service privately
  when it starts (systemd "credentials"), so no other program and no log ever sees them.
- Undo: `sudo rm -rf /etc/roxy/credentials` (v2 then cannot start).

### 7. v2's system pieces (`install-system.sh`)

- What it created: the accounts `roxy` (runs v2; cannot log in) and `roxy-deploy` (only deploys; member of the
  `roxy` group); the folders `/opt/roxy` (releases), `/var/lib/roxy` (the four databases), `/var/backups/roxy`; the
  services `roxy@blue` and `roxy@green` (two copies of v2, one running at a time) with their memory limits; the
  nightly backup timer (03:30), a security audit timer and a few watchers ("path" units that react to a file
  appearing, for example the dashboard's "Back up now"); a cap on how much disk the system journal (the log) may
  use; root-owned helper tools in `/usr/local/lib/roxy` and `/usr/local/sbin`; and the deploy account's sudo rules.
- Why separate accounts: if something ever broke into Roxy, it would get only the `roxy` account, which can touch
  nothing but Roxy's own files. The deploy account can run exactly eleven root commands (start, stop, restart or
  reload blue or green, switch the active color, and apply nginx configuration from a verified commit), nothing
  else; `sudo -n -l` as `roxy-deploy` lists them. Never deploy as `ubuntu`: on Lightsail it may do anything as root.
- The expected warning: `/etc/roxy` belongs to `ubuntu` because v1 still keeps its state there; the script only
  added a narrow pass-through permission (an ACL) for the deploy account. After v1 is retired,
  `install-system.sh --take-over-etc` makes root the owner (`MIGRATION.md` section 5.4).
- Note: v1's failure-alert unit has the same name as v2's (`roxy-alert@.service`) and was replaced; v2's alert
  script reports a v1 crash too, using the secret files of entry 6.

### 8. v2's settings file

- What: in `/etc/roxy/roxy.env` (root and group `roxy` may read it, mode `0640`), `ROXY_DEPLOY_REPO_URL` now names
  `https://github.com/CeaselessQuokka/roxy.git` (it held a placeholder). `ROXY_SITE_ORIGIN` was already
  `https://roxytheproxy.com`. The original is kept as `/etc/roxy/roxy.env.orig`.
- Why: deploys fetch the code from that repository, and the nginx tool refuses to run while the placeholder is
  there. A private repository needs a read-only deploy key first (see "Making the repository private" below).

### 9. The deploy account's own tools

- What: `uv` installed for `roxy-deploy`, and an empty `~/.ssh/authorized_keys` (mode `0600`) ready for the GitHub
  Actions key (`MIGRATION.md` section 5.2).

### 10. Four services a cloud server does not use, turned off

- What: `sudo systemctl disable --now ModemManager fwupd udisks2 multipathd` (and `multipathd.socket`).
- Why: they serve physical computers (cellular modems, motherboard firmware updates, plugging in USB drives,
  storage with several cables to one disk). On a 909 MB server every megabyte counts: available memory went from
  234 to 256 MB at once.
- Undo: `sudo systemctl enable --now <name>` for any of them.

### 11. The migration dry run

- What: the migrator ran the whole import against private copies and wrote only a report
  (`/root/roxy-migration-dry-run.md`): result `dry_run_would_change`, 0 errors, 2 harmless warnings (an old copy of
  v1's settings v1 itself ignored; one secret-looking value hidden from the report). Your v1 admin account will be
  imported (password as an argon2id hash; first sign-in with the emailed code, then the authenticator app), the
  throttle ladder (5 rungs, one dash rewritten), 1 added Roblox host (`www.roblox.com`), settings you changed in v1
  (for example the cache lifetime of 180 s), and v1's lifetime numbers (394,753 requests, 1,670 Roblox 429s: 42.3 per
  10,000 requests, the baseline v2 is compared with).

## Making the repository private (later)

Today the server downloads the code anonymously, which works only while the repository is public. Before you make
it private, the server gets a read-only **deploy key** (an SSH key GitHub accepts only for reading this one
repository), the deploy tools learn to fetch with it, and both the deploy account and root's nginx tool use it. Do
not switch the repository to private before that is done and a deploy has worked through the key.
