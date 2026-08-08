# Deploying these changes

`UpdateBuild.sh` handles the application itself — push to `main`, the GitHub
Action runs it, and `app/` (including the new `gunicorn.conf.py`) lands in
`~/Roxy`. Nothing below is needed for a normal deploy.

---

## If `~/UpdateBuild.sh` has gone missing

**You should not need to do anything — just push.** The workflow now reinstalls
the script from the repo when it is absent, so the next push to `main` repairs
itself.

### Why it went missing

The old `UpdateBuild.sh` moved itself out of the way before it had a
replacement:

```bash
mv ~/UpdateBuild.sh ~/UpdateBuildOld.sh          # line 31: home now has no script
mv roxy/Tooling/UpdateBuild.sh ~                 # line 32: fails if the clone failed
...
rm ~/UpdateBuildOld.sh                           # line 56: runs anyway — backup destroyed
```

It ran without `set -e`, so a single failed `git clone` carried straight on
through all three. It also deleted `~/Roxy` and `~/SiteEnv` at the *top* of the
script, before fetching anything. Replaying that exact scenario against the two
versions:

```
        exit  ~/UpdateBuild.sh  backup  ~/Roxy  ~/SiteEnv  ~/Tooling
OLD     0     gone              gone    gone    gone       gone
NEW     128   intact            n/a     intact  intact     intact
```

`exit 0` is the worst part: the Action reported a green tick while the server
had been emptied.

### Manual recovery, if you would rather not wait for a push

```bash
git clone --depth 1 https://github.com/CeaselessQuokka/roxy /tmp/roxy-fix
cp /tmp/roxy-fix/Tooling/UpdateBuild.sh ~/UpdateBuild.sh
chmod +x ~/UpdateBuild.sh
rm -rf /tmp/roxy-fix
bash ~/UpdateBuild.sh          # rebuilds ~/Roxy, ~/SiteEnv and ~/Tooling
```

Run it with `bash`, not `sh`. Ubuntu's `/bin/sh` is dash, which has no
`set -o pipefail` — the script now re-execs itself under bash if you forget, but
older copies sitting on the server will just fail with
`set: Illegal option -o pipefail`.

That one command restores everything: the script re-clones, rebuilds the
virtualenv, redeploys `app/`, and restarts the service.

### What stops it recurring

- `set -euo pipefail` and an `ERR` trap that rolls `~/Roxy` and `~/SiteEnv` back
  and restarts the service.
- Nothing live is touched until the clone has been fetched **and verified**
  (`app/`, `requirements.txt` and both `Tooling/` scripts must be present).
- The virtualenv is rebuilt **only when `requirements.txt` changes**, and always
  directly at `~/SiteEnv` — never built elsewhere and moved. A venv bakes its own
  absolute path into the shebang of every console script, so a relocated one
  leaves `~/SiteEnv/bin/gunicorn` pointing at a directory that no longer exists
  and systemd fails with "bad interpreter". On a rebuild the *old* venv is moved
  aside instead, so rolling back puts it back at the path its shebangs expect.
- The self-update renames the new script *onto* `~/UpdateBuild.sh`. `rename(2)`
  is atomic, so the path is never empty — not even for an instant.
- A deploy that ends with the service down exits non-zero, so the Action goes
  red instead of hiding it.

All of the above is covered by `tests/deploy_test.sh`, which runs the real
script against a fake home and a fake remote with `sudo`/`systemctl`/`python3`
stubbed, so nothing on your machine is touched:

```bash
bash tests/deploy_test.sh
```

It checks a clean deploy, the self-update, a first-ever deploy onto a bare home,
and three failure paths (clone fails, `pip` fails, clone is malformed) — each
asserting that `~/UpdateBuild.sh` survives and the previous build keeps serving.

The steps here are **one-time**, because `UpdateBuild.sh` cannot write to
`/etc/systemd` or `/etc/nginx`. Do them once and every future push is unchanged.

---

## 0. First, the emergency stop (do this before anything else)

The stats file is what has been taking the server down. Truncate it now; the
code changes stop it coming back. Settings, rules, tokens and trusted devices
live in `Runtime` and are preserved — and after step 2 they move to their own
file entirely.

```bash
ls -lh /etc/roxy/roxy_data.json          # how bad is it?
sudo systemctl stop roxy.service
sudo cp /etc/roxy/roxy_data.json /etc/roxy/roxy_data.json.keep
sudo python3 -c "import json;d=json.load(open('/etc/roxy/roxy_data.json'));json.dump({'Runtime':d.get('Runtime',{})},open('/etc/roxy/roxy_data.json','w'),separators=(',',':'))"
sudo rm -f /etc/roxy/roxy_data.json.bak
sudo systemctl start roxy.service
```

If the file is already over 24 MB you can skip the surgery — the app now
quarantines an oversized stats file on load instead of parsing it, so it will
start cleanly either way. Configuration is unaffected.

While you are there, confirm the diagnosis:

```bash
sudo dmesg -T | grep -i -B2 -A4 "out of memory"
journalctl -u roxy.service --since "7 days ago" | grep -iE "killed|signal|failed"
```

---

## 1. Deploy the code

Push to `main` as usual. `UpdateBuild.sh` now also copies
`Tooling/alert_on_failure.py` to `~`, where the alert unit expects it.

---

## 2. Install the service units

`roxy.service` is a **replacement** for the existing one. The important
difference is `Restart=always`: the old unit had no `Restart=` directive at all,
which defaults to `Restart=no`. When the gunicorn master was killed, systemd
marked the unit dead and left it there — which is why the site stayed down
rather than flapping for a second.

`UpdateBuild.sh` now keeps the whole `Tooling/` directory at `~/Tooling`, so the
files are already on the server after the deploy in step 1:

```bash
sudo cp ~/Tooling/roxy.service /etc/systemd/system/roxy.service
sudo cp ~/Tooling/'roxy-alert@.service' /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart roxy.service
systemctl status roxy.service
```

### Check it took

```bash
systemctl show roxy.service -p Restart -p Type -p OnFailure -p MemoryMax
```

Expect `Restart=always`, `Type=notify`, `OnFailure=roxy-alert@roxy.service.service`.

`MemoryMax` is set for a 2 GB instance. Check what you actually have with
`free -m` and adjust `MemoryHigh`/`MemoryMax` to roughly 60% / 70% of it.

### Prove the restart works

Worth doing once, because this is the whole point:

```bash
sudo kill -9 $(systemctl show roxy.service -p MainPID --value)
sleep 5 && systemctl show roxy.service -p ActiveState -p NRestarts
```

`ActiveState=active` and `NRestarts=1` means an OOM kill now self-heals in
about three seconds instead of taking the site down until you notice.

You should also get the failure email once the alert unit is installed. If it
does not arrive, run it by hand to see why:

```bash
~/SiteEnv/bin/python ~/alert_on_failure.py roxy.service
```

---

## 3. Update nginx

`Tooling/nginx-roxy.conf` is the current config plus the marked changes.
The two that matter:

- **`client_max_body_size 2m`** — nginx's 1 MB default was rejecting bodies the
  app was configured to accept, with a bare nginx 413 the app never saw.
- **`proxy_read_timeout 100s`** — the 60s default could cut off a slow upstream
  request that was still working. gunicorn's own 90s timeout now fires first,
  so the app gets to log what happened.

```bash
sudo cp /etc/nginx/sites-available/roxy /etc/nginx/sites-available/roxy.bak
sudo cp ~/Tooling/nginx-roxy.conf /etc/nginx/sites-available/roxy
sudo nginx -t && sudo systemctl reload nginx
```

`nginx -t` before reloading, always.

---

## 4. About `X-Forwarded-For`

Your nginx uses `$proxy_add_x_forwarded_for`, which **appends**: if a caller
sends their own `X-Forwarded-For`, nginx keeps it and adds the real address on
the end. So the last entry is the only trustworthy one.

The app used to read the **first** entry, which meant anyone could set that
header to anything and get a fresh identity — bypassing per-IP rate limiting and
the admin login lockout. It now reads from the right, using
`ROXY_TRUSTED_PROXY_HOPS=1` (set in the unit file) to say how many hops are ours.

**If you ever put Cloudflare or another CDN in front of nginx, change that to
`2`.** Otherwise every client will be recorded as a CDN edge IP and rate
limiting will apply to the CDN rather than to callers.

To sanity-check after deploying, log in and look at "Your IP" in the Throttle
Bypass section — it should be your real address, not `127.0.0.1` and not
something you can change by sending your own header.

---

## 5. Optional: watch the file size

The dashboard now shows the stats file against its ceiling, and `/health`
reports it without needing a session, so an external monitor can alert on the
one number that predicts trouble:

```bash
curl -s https://roxytheproxy.com/health
# {"Status":"ok","DataBytes":123456,"DataLimitBytes":25165824,"PersistenceOK":true,...}
```

Every record store is capped now, so `DataBytes` should level off and stay
there. If it climbs steadily, something new is unbounded — the dashboard's
Tools → "What's Being Stored" panel will show which store is growing.
