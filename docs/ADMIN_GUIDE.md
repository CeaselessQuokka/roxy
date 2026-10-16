# Roxy admin guide

This guide explains how to run Roxy day to day. It is written for an owner who runs one server: it says what every
part of the dashboard shows, what normal and worrying values look like, and what to do about them.

How the guide is organized:

- [Getting started](#getting-started) walks through your first hour: the first admin, your second factors, the
  Roblox credential, the rotator, where alerts go and a first health check. It ends with the controls every dashboard
  page shares, so the page chapters do not repeat them.
- [Daily routine](#daily-routine) is the five minute check to do once a day.
- [How Roxy stays under Roblox's limits](#how-roxy-stays-under-robloxs-limits) explains the cache, the pacing and the
  cooldowns that keep Roblox happy, with a worked example.
- Then one chapter per dashboard page, in the order of the sidebar, from [Overview](#overview) to [Help](#help). Each
  says when to use the page, what every card shows, and what to do when a number looks wrong.
- [Alerts](#alerts), [Backups and resets](#backups-and-resets), [The operator CLI](#the-operator-cli),
  [Incident runbooks](#incident-runbooks) and the [Glossary](#glossary) close the guide.

Every dashboard page also explains itself. Its first line says what it is for, and its "How to read this page" panel,
under the page title, explains its words and numbers in a few lines. Terms with a dotted underline show their meaning
when you hover over or focus them, and link to the glossary on the Help page.

## Getting started

This chapter walks through your first hour with Roxy v2, in the order you do it. Each step ends with what it
protects against, so you know why it matters. Do steps 1 to 4 before anything else: until they are done, your admin
account is only as safe as one password.

You need a shell on the server (with sudo), a phone or password manager with an authenticator app (Google
Authenticator, Microsoft Authenticator, 1Password, Bitwarden or similar), and the mailbox that receives Roxy's email.
In the commands below, replace `blue` with the color that is live (the runbooks' "Everyday commands" show how to
tell).

### Step 1: create the first admin

There are two ways; you use one of them.

**Upgrading from v1.** The cutover runs the migrator, `scripts/migrate_from_v1.py`. With `--import-admin-password`
it brings your v1 admin over: it keeps the username and the admin email address, turns the v1 password (which v1
kept as plain text) into an argon2id hash, and marks the account for a one-time first sign-in with an emailed code.
v2 never stores a password, only its hash. If the v1 password breaks the v2 rules (at least 14 characters, not a
common password, not containing the username), the migration report says so; the password is still imported so you
can sign in, and you change it afterwards from the server (below). Without `--import-admin-password` no admin is
imported, and you use the second way.

**A new admin from the server console.** `scripts/create_admin.py` creates an admin on the server itself. It asks
for the password twice, draws a QR code for your authenticator app in the terminal, asks for the first 6-digit code
to prove the app has it, and prints 10 recovery codes once. It never creates or upgrades the database, so run it
after the first deploy has started a color (it refuses a database older than its release). It needs the
authenticator encryption key, which only root can read, and must write the database as the `roxy` user, so run it
through systemd:

```sh
sudo systemd-run --wait --pty --uid=roxy --gid=roxy -p UMask=0027 \
  -p LoadCredential=totp_encryption_key:/etc/roxy/credentials/totp_encryption_key \
  /opt/roxy/releases/current-blue/.venv/bin/python /opt/roxy/releases/current-blue/scripts/create_admin.py \
  --username <your admin name> --state-dir /var/lib/roxy
```

`--email <address>` (optional) gives the account its own address for emailed login codes, which matter only if you
ever turn on `admin_email_code_enabled` (off by default); without it, such codes go to the alert address. The same
script fixes an account later: `--reset-password` sets a new password and ends every session of that admin;
`--reset-mfa` makes a new authenticator and new recovery codes and removes the admin's passkeys, trusted devices and
sessions. The dashboard has no password form, so `--reset-password` is also how you change your password. The
[Admin locked out](/admin/help/runbooks#admin-locked-out) runbook shows both.

What it protects against: the first admin is made on the console, so a new site never has a moment when its first
visitor could make themselves admin.

### Step 2: sign in for the first time

Open `https://<your site>/admin`, enter the username and password, and press Login. The second step asks for a second
factor.

- An account the migrator imported has no authenticator yet, so this one time Roxy emails a code instead. The email
  has the subject `Admin 2FA` and the code as its whole body (16 digits by default, setting `email_code_digits`). It
  goes to the admin's own email address, or to the alert address when the account has none. Enter it before the
  countdown on the page runs out: 2 minutes by default, because a code lives the shorter of `two_fa_expiration`
  (300 seconds) and `challenge_expiration` (120 seconds, the time allowed between the password and the second
  factor). Send a new code mails a fresh one, restarts the countdown, and the old code stops working (at least 30
  seconds apart, at most 5 codes per sign-in, the first one included). If the page says "Could not send the 2FA
  email; please try again shortly." more than once, the mail credentials are usually missing or wrong
  ([Step 9](#step-9-choose-where-alerts-go)); fix them, or give the account an authenticator from the console with
  `create_admin.py --reset-mfa`.
- An account made with `create_admin.py` already has its authenticator: enter the 6-digit code from the app.

The emailed code opens exactly one page: the authenticator setup page (`/admin/enroll`). Every other page sends you
back to it, and that limited session ends after 30 minutes.

The box "Trust this device for 30 days (skip the second factor)" under the password lets this browser skip the
second step for `trusted_device_days` days (30 by default); the password is still asked every time. It is shown
while `admin_trusted_devices_enabled` is on (the default), and it has no effect on the one-time emailed-code sign-in:
only a sign-in with a real second factor marks a browser as trusted. Leave it unticked on a computer you share.

Every successful sign-in sends a `Roxy Admin Login` email with the address, the browser, the time and a one-time
link that ends admin sessions. If you ever get one you did not cause, use that link
([The kill-switch link](#the-kill-switch-link) in the Security chapter) and follow the
[Unexpected admin login](/admin/help/runbooks#unexpected-admin-login) runbook.

What it protects against: an emailed code is only as safe as the mailbox, so it opens one door, once.

### Step 3: enroll your authenticator app

On the setup page press Show the QR code, scan it with the app (or type the key shown under it), enter the 6-digit
code the app shows, and press Confirm. A QR code waits 10 minutes for its first code; after that, start again with
Show the QR code. Roxy stores the authenticator secret encrypted, closes the email path for good (the setting
`admin_email_code_enabled` stays off; any other sign-in still waiting for an emailed code, and any other emailed-code
session, ends at that moment), and turns your session into a normal one.

What it protects against: someone who learns your password, or reads your mailbox, still cannot sign in without your
phone.

### Step 4: save the recovery codes

Right after Confirm, the page shows 10 recovery codes, once. Press Copy the codes and keep them in a password manager,
or print them and store the paper somewhere safe and offline. Each code signs you in once instead of the
authenticator app. (With `create_admin.py` the terminal printed them instead.)

Later, the Recovery codes card on the Security page shows how many are left and has Make new codes: every old code
stops working at once, and the new ones are shown once on that card.

Make new codes is a sensitive action, like replacing the credential or the rotator URL, adding a passkey, a factory
reset or a full export. Such an action needs a fresh second factor: if you last entered one more than 10 minutes ago
(the "Fresh second factor window", `admin_reauth_window_s`, on the Security page), a "Confirm it is you" dialog asks
for a code from your authenticator app or a recovery code, then finishes the action by itself. Within those 10
minutes Roxy does not ask again. This guide calls this "asks you to confirm it is you", and each chapter says which
actions do.

What it protects against: a lost or broken phone locking you out of your own proxy.

### Step 5: add a passkey

A passkey signs you in with your device's fingerprint, face or PIN instead of a code. The setup page offers Also add
a passkey (optional); later, the Passkeys card on the Security page has Add a passkey (up to 10 per admin; it asks
you to confirm it is you). Your authenticator app keeps working either way.

What it protects against: phishing, because a passkey only works on Roxy's real address, and it gives you a second way
in if the phone is lost.

### Step 6: check the Roblox credential

Open the Credential page. The Status card says whether the credential works, shows only its last characters (never
the value), and says where it was loaded from. After an upgrade it is the first cookie of v1's token file, which the
migrator wrote to the server file `/etc/roxy/credentials/roblox_credential`, a
[systemd credential](/admin/help#term-systemd-credential). Press Check credential to have Roxy try it once with
Roblox (it spends one call on the account, so it may ask you to confirm it is you).

To set or change it, use the Replace card: press Replace the credential, paste the `.ROBLOSECURITY` cookie value,
type `replace the credential` to confirm, and add a reason if you like. It asks you to confirm it is you. Every
worker switches to the new value within a second, and Roxy checks it once, right away. The [Replace](#replace)
section of the Credential chapter has the step by step renewal and what to do when a check finds a different
account.

Caller requests carry it only for the endpoints the [Endpoint policy](#endpoint-policy) page sends with Roxy's
account (owner decision D1, revised on 2026-10-16); every other endpoint goes out anonymously or is refused. Roxy also
uses it for its own checks, about 50 to 60 calls a day: the scheduled check every `credential_probe_interval_min`
minutes (30 by default) and the checks you start.

What it protects against: Roxy holds exactly one Roblox account and never sends it through the rotator. Many accounts
behind one server address look like account farming to Roblox, so a replacement is always a deliberate, audited act.

### Step 7: set the rotator URL

The [rotator](/admin/help#term-rotator) (DataImpulse) is a paid proxy service that sends anonymous requests from other
addresses. Its gateway URL contains a user name and a password, so Roxy treats the whole URL as a secret. It comes
from the systemd credential `rotator_url` (the file `/etc/roxy/credentials/rotator_url`), read when the service
starts (there is deliberately no environment variable for it), or from a value you set on the Egress page; the
dashboard value wins. After an upgrade, the migrator copied v1's rotator URL into that file (from v1's
`rotate_proxy.txt`, or from the `ROXY_ROTATE_PROXY` variable when you ran the migrator with it set, as v1 had it). An
empty file means no rotator is configured.

On the Egress page, Rotator card: Replace the gateway URL takes the URL in the form `http://user:password@host:port`
and, like the credential, asks you to confirm it is you. Every worker uses the new URL within a second, and the page
only ever shows it as `scheme://host:port` (see [Rotator](#rotator) in the Egress chapter). If you edit the server
file instead, the service reads it only when a color starts: `systemctl restart roxy@<color>` does that with a short
interruption, and redeploying the running commit (as the
[Alert channels down](/admin/help/runbooks#alert-channels-down) runbook shows) does it without one.

With the default `rotator_weight` of 0 the rotator is a spillover path only: Roxy uses it when the direct path is
cooling down or nearly full, or when a routing rule prefers it. `rotator_enabled` switches it off entirely. The
rotator's session username template is yours to fill in from DataImpulse's documentation; until it is set, every
rotator call gets a new exit address (see [Rotator](#rotator)).

What it protects against: the password inside the URL never appears on a page, in a log line, in the audit log or in
the process environment.

### Step 8: enter the DataImpulse quota and price

Every byte through the rotator costs money. On the Egress page, Budget card, enter your plan (owner decision D12):

- `rotator_quota_gb_per_month`: the plan's monthly allowance in GB (decimal gigabytes, the provider's unit). It
  ships as 0, which means unknown: bytes are still counted, but no quota alert and no hard stop can fire until you
  set it.
- `rotator_price_per_gb_usd`: the price per GB. It only feeds the cost so far and the projected cost on the Egress
  page; 0 shows bytes only.
- `rotator_billing_day`: the day of the month your plan resets (default 1, at most 28; cycles are counted in UTC).

The alert thresholds (50, 80 and 95 percent of the quota), the hard stop (100 percent: the rotator stops for the rest
of the cycle) and an optional daily cap sit on the same card; the [Budget](#budget) section of the Egress chapter
explains them all.

What it protects against: a surprise bill. With the quota set you get an alert at each threshold, and the rotator
stops at the hard stop.

### Step 9: choose where alerts go

Alerts go by email and, if you want, to a webhook (for example a Discord channel; owner decision D14). Both are
systemd credentials on the server, never settings, because they are secrets:

- Email uses Gmail with an app password: `/etc/roxy/credentials/smtp_password` holds the app password and
  `/etc/roxy/credentials/alert_emails` the addresses, one per line with `to:` and `from:` in front (v1's two-line file,
  recipient first, also works). The migrator copies both from v1.
- The webhook address goes in `/etc/roxy/credentials/alert_webhook_url` (owned by root, mode 0600; an empty file means
  no webhook). Then switch `alert_webhook_enabled` (labeled "Send alerts to webhook") on in the Alerts card of the
  Settings page.

Roxy reads these files when a color starts; the [Alert channels down](/admin/help/runbooks#alert-channels-down)
runbook shows how to pick up a change without downtime. The Alerts card of the System page says which channels are
configured. The [Alerts](#alerts) chapter lists every alert and the settings that shape them.

What it protects against: learning about a problem only when you happen to open the dashboard.

### Step 10: run Check Proxy Health

On the Health page, Run a health check runs every check in about a minute. Leave Include the credential check ticked
the first time: it spends one call on the Roblox account and asks you to confirm it is you (Step 4). (The Check Proxy
Health button on the Overview runs everything except the credential check.) Each check passes, warns, fails or does
not apply, and each warning or failure says how to fix it and links to its runbook.

On a new server, expect three things:

- H-BACKUP fails ("never") until the first backup has run. Press Back up now on the Data page, wait until the Backups
  card shows the backup succeeded, and run the checks again.
- H-ROTATOR-QUOTA says not applicable while the quota is 0 (Step 8).
- H-ALERTS warns when a webhook other than a Discord one is switched on, because other providers cannot be tested
  without posting a message: press **Send test alert** on the Settings page's Alerts card to post one (see
  [Testing that alerts arrive](#testing-that-alerts-arrive)).

From now on Roxy runs the checks by itself every 6 hours (`health_auto_interval_h`) and alerts you about new
failures. Scheduled runs leave the credential check out unless you turn on `health_auto_include_credential`; the
credential has its own scheduled check (Step 6).

What it protects against: a setup mistake that would otherwise show up only when something breaks.

### How every dashboard page works

The pages share one set of controls. This section explains them once; the page chapters only say what differs.

#### The top bar

From left to right: the logo (it opens the Overview), the time range button, the search (it opens the command
palette; Ctrl K or `/` does the same), the bell, **Health**, **Pause proxy** (or **Resume proxy** while paused),
**Emergency limit**, and the user menu. The bell counts the open recommendations and opens the Recommendations page;
its dot turns red when one is critical. The user menu holds the theme, Dense tables, Single-key shortcuts,
Preferences, Keyboard shortcuts, Help and glossary, and Log out.

#### The time range and the comparison

The range button shows the range in words, for example "Last 24 hours", and opens the time range panel:

- **Time range**: **Live** (the last 15 minutes), **1h**, **6h**, **24h**, **7d**, **30d**, **90d**, **1y**,
  **All** (all time), or **Custom** with a From and a To.
- **Compare with**: No comparison, Previous period, Same period last week, Same period last month or Same period
  last year. Charts draw the earlier period as dashed lines.

Picking a preset range or a comparison applies it at once; for Custom, fill in From and To and press **Apply**. The
`T` key moves to the next range (it skips Custom), and the `C` key switches between no comparison and the previous
period. Both are single-key shortcuts: they never fire while you type in a field, and "Single-key shortcuts" in the
user menu turns them off.

The range and the comparison are part of the page address, so a link you copy opens the same view. A page opens on
the range and comparison you chose in Preferences ("Time range pages open with" and "Comparison pages open with");
without them, on the last 24 hours with no comparison. A few pages whose lists are history (Recommendations, Health,
Settings and Audit) open on All when the address names no range. Each page chapter says which cards follow the range
and which always show the present moment.

Times are shown in the dashboard time zone (the setting "Dashboard timezone", `ui_timezone`) unless you chose
another one in Preferences ("Show times in this time zone").

Most numbers are read when the page loads, and heavier cards load a moment later, or when you scroll to them. A few
cards keep themselves current from the live event stream, and each chapter names them; for the rest, reload the
page.

#### Charts

- Drag across a chart to zoom in, or use its zoom in, zoom out and "Show the whole range" buttons.
- Press a legend entry to hide or show that line.
- **Show the data as a table**, under the chart, gives the same numbers as a table.
- Vertical markers ([annotations](/admin/help#term-annotation)) are configuration changes, data resets, deploys and
  incidents. They are listed under the chart as marked events, and one with an audit entry links to it on the
  [Audit](#audit) page.
- When a reset deleted part of the data in the range, a note above the plot says the numbers are partial.

#### Tables and drawers

Most cards hold a table with the same controls: a search box, sorting by pressing a column heading, a **Columns**
menu that shows the hidden columns, **Rows** per page (10, 25, 50, 100 or 250), a pager, and an **Export** menu with
"CSV (spreadsheet safe)" and "JSON". The rows per page and the columns you show or hide are remembered per table in
this browser. An export holds the current search, filters and sort; client addresses in it are replaced by keyed
hashes unless "Raw IP addresses in exports" (`export_include_ips`) is on, and every download is written to the audit
log. On most pages one main table also keeps its search, filters, sort and page in the page address, so a view can
be bookmarked; the chapters say which.

In most tables, pressing a row (or Enter on it) opens its details in a drawer at the side; Up and Down move between
rows. Most numbers and column headings have a **?** button with their exact definition.

Text that callers sent (paths, User-Agents, place ids, headers) is always shown as plain text, never as a link or
markup. Treat an odd value as text a stranger typed.

#### Changing a setting on a card

Most cards end with a **Settings for this card** list, with a count; it starts open on the cards that exist mostly
for their settings and folded on the others. Each setting there is the same setting as on the [Settings](#settings)
page: a change made in one place shows in the other. When one page shows a setting on two of its cards, the second
shows only "Now <value>. Edit it on this page's <card> card." with a link. To change one:

1. Edit the value and press **Review**. Roxy shows the value before and after, what happens, and the risk.
2. Press **Save** (the same button). A reason is optional and goes to the audit log; a high-risk value needs a reason
   and a tick in "I understand the risk described above".

Every worker uses the new value within about a second. **Reset to default** only fills in the default (nothing
changes until you save), and **History** opens the setting's entries on the Audit page. The settings that decide who
may sign in and what the credential is used for also ask you to confirm it is you. The [Settings](#settings) chapter
explains every part of a setting, the risk levels and how to revert a change.

#### Resets next to the numbers

Some cards have a button that deletes their own statistics (Reset, Clear stats, Delete the records and similar).
Each opens a drawer or a dialog that says what it would delete before anything happens; most show the rows and the
dates they cover, what stays, and whether a snapshot of the database is taken first. Some ask for a typed phrase and
a reason. Nothing is deleted before you confirm, and a marker goes on every chart that covers the deleted time.
These are the same resets as the Data page's Resets card; [Statistics resets](#statistics-resets) explains them, and
how a snapshot can put one back.

#### On a phone

- The bar at the bottom of the screen has **Overview**, **Advice** (the Recommendations page, with the open count and
  the red dot), **Health** and **Menu**. The top bar keeps the logo, the range, search and **Pause** (or **Resume**);
  the bell is hidden (Advice shows its count), and **Emergency limit** moves into Menu.
- On a narrow screen (below 640 pixels), a big table shows each row as a small card with its key columns only; press
  the row for the rest. The drawer then slides up from the bottom of the screen.
- Many small tables become blocks of labeled lines, cards that sit side by side stack, and buttons and fields are
  large enough for a thumb.

Each page chapter ends with what is special about that page on a phone.

## Daily routine

A five minute check, once a day, in this order: the Overview, the Recommendations, the Health page. All three
are one tap away on a phone: the bar at the bottom of the screen has Overview, Advice (the Recommendations page) and
Health, so you can do the whole routine from your phone.

### Step 1: the Overview page (about two minutes)

1. Open the [Overview](/admin/overview). It shows the last 24 hours unless you chose another opening range in
   Preferences.
2. Read the status strip at the top. A healthy Roxy says: Proxy **Running**, Credential **Working**, Rotator
   **Working** (or **Not configured** if you do not use DataImpulse), Leader **Worker** followed by a number, and
   Workers **2 of 2**. Anything else: press its **Details** link.
3. Look at **Top recommendations**. A critical one goes first in step 2.
4. Scan the key number tiles, mainly **Roblox 429s**, **Failures (last hour)**, **Caller 5xx**, **Avoided upstream
   calls (percent)** and **Rotator bytes today**. A red arrow means "worse than the period before".
5. Glance at **Recent notable events** for breakers, credential cooldowns, leak guard blocks and spam bans.

### Step 2: the Recommendations page (about two minutes)

1. The bell in the top bar shows how many recommendations are open; its dot turns red when one is critical. On a
   phone the bell is hidden and **Advice** in the bottom bar shows the same count and the same red dot.
2. Open the [Recommendations](/admin/recommendations) page. The list shows the open ones, most severe first.
3. Open each critical or warning item, read its evidence, press **Preview and apply**, then decide: **Apply**,
   **Snooze** or **Dismiss**. Info items can wait; they close by themselves after a week if nobody acts.
4. If you switched auto-apply on, look at the **History** card for "Applied automatically" and "Rolled back
   automatically".

### Step 3: the Health page (about one minute)

1. Open [Health](/admin/health). The Run card shows the newest run; by default Roxy runs one by itself every 6
   hours.
2. "Nothing needs attention" means you are done. Otherwise open each check under **Needs attention** and follow
   its fix link, or press **Apply fix** when it has one.
3. If the newest run is old, or something on the Overview looked wrong, press **Run a health check**.

### When something looks wrong

- Roblox is answering 429 or the account is at risk: [Emergency stop](/admin/help/runbooks#emergency-stop) and
  [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us).
- The credential is cooling down or rejected: [Credential cooling down](/admin/help/runbooks#credential-cooling-down)
  and [Credential rejected](/admin/help/runbooks#credential-rejected).
- Callers get errors: [Caller errors](/admin/help/runbooks#caller-errors).
- Refusals or bans jump: [Under attack](/admin/help/runbooks#under-attack).
- The rotator stopped: [Rotator down or quota exhausted](/admin/help/runbooks#rotator-down-or-quota-exhausted).

Once a week, set the range to **7d** (the last 7 days) and the comparison to **Same period last week** on the
Overview: the arrows then tell you whether this week was better or worse than the last.

## How Roxy stays under Roblox's limits

Roblox limits how often one address, and one account, may call each of its web APIs. A caller that goes over gets
**429 Too Many Requests**, and a caller that keeps going gets limited harder and for longer. v1 kept running into
this. Roxy v2 follows three rules to stay clear of it: call Roblox as rarely as possible, spread the calls it must
make evenly over time, and stop at once when Roblox says "slow down". This chapter explains the parts that do that,
in the order a request meets them, and then follows one burst of requests to one endpoint through all of them with
the default numbers. The [Upstream](#upstream) page shows every part at work.

A few words first:

- An **upstream call** is one request Roxy sends to Roblox. One caller request needs no upstream call (the cache
  answered it), one call, or a few (a retry).
- An [endpoint template](/admin/help#term-endpoint-template) is a Roblox path with its ids replaced by
  placeholders, for example `users.roblox.com/v1/users/{id}`. Roxy counts and paces calls per template. For pacing,
  the letters of a template count in lower case, so `/v1/Users/{id}` and `/v1/users/{id}` share one rate, one
  cooldown and one breaker (a caller cannot double what Roblox sees by changing the case); the pages show templates
  as callers wrote them.
- An [egress](/admin/help#term-egress) is the path a call leaves by: **direct** (the server's own address, free),
  **rotator** (DataImpulse, many exit addresses, paid per byte) or **credential** (direct, carrying the one Roblox
  account).
- Everything below is shared by all worker processes through one small database (`hot.db`), so every limit is the
  same with 1, 2 or 4 workers. Production runs 2 (`ROXY_WORKERS=2`).

### The parts, in the order a request meets them

1. **The cache.** A request whose answer Roxy holds and is still fresh is answered at once (a
   [hit](/admin/help#term-hit)); Roblox never sees it. An answer stays fresh for `cache_ttl_seconds` (120 s) unless a
   cache rule for its endpoint says otherwise. This is the strongest protection there is; the [Cache](#cache)
   chapter covers it.
2. **Stale-while-revalidate.** For `cache_swr_seconds` (60 s) after an answer expires, Roxy still serves it at once
   (header `Roxy-Cache: REVALIDATING`) and starts exactly one background refresh for it, shared by every worker
   ([stale-while-revalidate](/admin/help#term-stale-while-revalidate)). A refresh is the first thing dropped when the
   queue is full, and it may take a pacing slot only while the global bucket is less than half booked, so it never
   takes a slot a caller needs. Each worker runs at most `swr_max_inflight` (50) refreshes at once.
3. **Single-flight.** When several callers ask for the same uncached URL at the same moment, one of them (the owner)
   makes the call and the others (followers) wait for its answer (`Roxy-Cache: COALESCED`), across every worker.
   This is also called [coalescing](/admin/help#term-coalescing). Followers never call Roblox themselves, not even
   when the owner fails. They wait at most `cache_coalesce_wait_ms`; the default 0 means as long as the owner may
   take, about 36 s.
4. **Routing.** Roxy picks the egress. Ordinary traffic goes direct (`direct_weight` 100 against `rotator_weight`
   0). The rotator only takes spillover: while direct is cooling down, when the direct bucket is more than 80
   percent booked (`direct_shift_threshold_pct`), or when a routing rule asks for it (owner decision D13). The
   credential is used only for the endpoints the [Endpoint policy](#endpoint-policy) sends with Roxy's account. The
   Routing card of the [Upstream](#upstream) page shows the rules.
5. **Buckets.** Before a call leaves, it books one slot in four buckets at once: the global bucket, its egress's
   bucket, its Roblox host's bucket and its endpoint's bucket. See "How a bucket paces calls" below.
6. **The queue.** A call whose slot lies in the future sleeps in its worker's queue until then. How long a request
   may wait depends on who is waiting (see "Waiting for a slot" below). When the slot is further away than that,
   nothing is booked and the caller is answered at once: with an older cached copy when Roxy has one, otherwise with
   429 and a `Retry-After` header saying when to come back.
7. **The call, and retries.** Roblox answers. A 5xx error, a timeout or a connection error may be retried once (two
   attempts in all), after a short random wait, on a new bucket slot. A 429 is never retried.
8. **After a 429: cooldown, breaker, adaptive rate.** Roxy stops calling that endpoint through that egress for a
   while (a cooldown), opens its circuit breaker for the same time, and lowers the endpoint's bucket rate below what
   Roblox just refused (the adaptive rate). Each is described below.

### How a bucket paces calls

Each [bucket](/admin/help#term-bucket) has a **rate** (calls a minute) and a **burst** (calls that may leave back to
back). Roxy runs every bucket with [GCRA](/admin/help#term-gcra), the Generic Cell Rate Algorithm. Think of a
timetable: at the steady rate, calls leave evenly spaced, and after a quiet spell up to "burst" calls may leave at
once. Each call books the earliest time that all four of its buckets allow, in one database transaction shared by
every worker. Two workers can never both take the last slot, and a bucket never fills back up just because a new
minute started (v1's token budget worked that way, so its whole budget could leave in about one second).

There are two kinds of bucket:

- **Roxy's own ceilings** (the global bucket and the three egress buckets) use the plain rule: once the burst is
  spent, one call every 60,000 ms divided by the rate. At 600 a minute that is one call every 100 ms.
- **Roblox's limits** (each host and each endpoint template) are a hard cap on any rolling minute: the burst counts
  inside the minute, not on top of it. At 120 a minute with a burst of 10, 10 calls may leave at once and then one
  about every 549.5 ms (61,000 ms divided by the 111 calls left), about 109 a minute, so no 60 second span ever
  holds more than 120 calls. Roxy paces over 61 s instead of 60 to leave a 1 second margin for network delays.

The defaults:

| Bucket | Key on the Buckets card | Rate | Burst | Once the burst is spent |
|---|---|---|---|---|
| Every upstream call | `global` | 600 a minute | 30 | one call every 100 ms |
| Direct path | `egress:direct` | 300 a minute | 20 | one every 200 ms |
| Rotator | `egress:rotator` | 300 a minute | 20 | one every 200 ms |
| Credential, caller requests sent with the account | `egress:credential` | 18 a minute (20 minus the 2 reserved) | 2 (the credential burst of 3 minus 1) | one every 3.3 s |
| Credential, Roxy's own checks | `egress:credential:probe` | 2 a minute | 1 | one every 30 s |
| Each Roblox host | `host:<host>` | 240 a minute | 15 | one about every 270 ms; never more than 240 in a minute |
| Each endpoint template | `endpoint:<template>` | 120 a minute | 10 | one about every 550 ms; never more than 120 in a minute |

The settings behind them: Global upstream rate and burst (`global_bucket_per_min`, `global_bucket_burst`), Direct
path rate and burst (`direct_bucket_per_min`, `direct_bucket_burst`), Rotator rate and burst
(`rotator_bucket_per_min`, `rotator_bucket_burst`), Default rate and burst per Roblox host
(`host_bucket_default_per_min`, `host_bucket_default_burst`) and Default rate and burst per endpoint
(`endpoint_bucket_default_per_min`, `endpoint_bucket_default_burst`), all on the Upstream page's Buckets card; and
Credential rate limit, Credential burst and Reserved rate for credential checks (`credential_bucket_per_min`,
`credential_bucket_burst`, `credential_probe_reserved_per_min`) on the Credential page's Budget card. The credential
burst is shared by the two credential buckets: caller traffic gets it minus 1 and Roxy's checks 1 (at a burst of
1, a check also takes the traffic's slot), so no more than the burst ever leaves on the account back to back. One
host or one endpoint can get a rate and burst of its own (an override) on the Buckets card.

The host and endpoint buckets do not depend on the egress: a call through the rotator takes the same host and
endpoint slots as a direct call, so moving traffic from one egress to another never doubles what one endpoint
receives.

A bucket's **fill** is how much of its burst is booked ahead. At 0 percent a whole burst may leave now; at 100
percent the next call waits for its slot. The Upstream page says "room to spare" below 70 percent, "busy" from 70
and "full: the next call waits" from 95.

### Waiting for a slot: the queue

| Who is waiting | Longest wait | Setting |
|---|---|---|
| A caller's request with no cached copy to fall back on | 4 s | Queue wait for callers with no cached copy (`queue_wait_interactive_ms`) |
| A caller's request Roxy could answer from an older cached copy | 0.5 s, then the older copy is served | Queue wait when a cached copy exists (`queue_wait_stale_ms`) |
| A background refresh | 10 s | Queue wait for background refreshes (`queue_wait_background_ms`) |
| An admin action (a lookup, a cache refresh) | 10 s | Queue wait for admin actions (`queue_wait_admin_ms`) |
| Roxy's own checks | 30 s | Queue wait for internal checks (`queue_wait_internal_ms`) |

Each worker holds at most `queue_max_length` (500) waiting requests. When its queue is full, a newcomer may push
out a more expendable waiter: background refreshes go first, then callers who have an older copy to fall back on,
then Roxy's own checks, then admin actions; a caller with no fallback is never pushed out. Whatever happens, one
request ends within `request_deadline_s` (60 s).

A caller turned away for lack of a slot gets status 429 with the body "All request methods are busy right now;
please try again shortly." and a `Retry-After` header that says, in whole seconds, when the soonest slot frees up.
Well-behaved game scripts wait that long before they try again.

### After Roblox answers

**Retries.** Only a 5xx answer, a timeout or a connection error is retried, up to `upstream_max_attempts` calls in
all (2: the first call and one retry). Before the retry Roxy waits a random time between `backoff_base_ms` (200 ms)
and three times the previous wait, never more than `backoff_cap_ms` (2 s). The retry books a new bucket slot, may
use the other anonymous path, and only happens if the request deadline allows it. A write request (POST and the
like) that Roblox refuses with 403 and a fresh CSRF token is repeated once with that token, and Roxy reuses the
token for `csrf_token_cache_s` (600 s). A 429 is never retried. The setting Retry elsewhere after a 429
(`fallback_on_429`, off) would allow one retry on the other anonymous path; v1 always did that, and it is part of
why v1's limits kept getting worse.

**Cooldowns.** When Roblox answers 429, Roxy stops calling that endpoint through that egress, on every worker, for a
while (a [cooldown](/admin/help#term-cooldown)). How long:

1. Roblox's `Retry-After` header, when it sends one ([Retry-After](/admin/help#term-retry-after));
2. else the `x-ratelimit-reset` time, when `x-ratelimit-remaining` says 0;
3. else `cooldown_default_s` (30 s) plus up to 10 percent at random, doubled for each repeated 429 on the same
   endpoint (30, 60, 120 s and so on). A 429 counts as repeated when the endpoint's previous cooldown ended at most
   `cooldown_max_s` ago.

Every length is kept between `cooldown_min_s` (1 s) and `cooldown_max_s` (600 s). Roxy also starts a cooldown
before any 429 when an ordinary answer says `x-ratelimit-remaining` is 0.

A cooldown can grow wider. When 3 different endpoints of one host get 429s within 60 s
(`cooldown_host_escalation_endpoints`, `cooldown_host_escalation_window_s`), the whole host cools down on that
egress; when 2 different hosts do, the whole egress does. A 429 on a credential call also rests the credential
itself, for `credential_cooldown_default_s` (60 s) when Roblox names no time. On the rotator a single 429 only
swaps that exit address (no cooldown, and the request is not remembered as refused); the endpoint cools down on the
rotator once 3 different exits got a 429 within 60 s (`rotator_cooldown_distinct_exits`,
`rotator_cooldown_window_s`).

A cooldown is never waited out: while it lasts, Roxy does not contact that endpoint through that egress at all.
Callers get, in this order:

- a fresh cached copy, as usual;
- for the exact request that got the 429: an older copy, or 429 with `Retry-After`, without any call (the setting
  Remember Roblox 429s per request, `cache_negative_429`, on by default);
- a copy that expired less than 60 s ago, served at once while one background refresh runs;
- an answer through another egress that can take the call: in practice the rotator, when it is set up, switched
  on and within its budget, and the endpoint's own bucket has a free slot (after an adaptive cut it often has none
  for a while; see the example below);
- an older copy, up to `cache_stale_seconds` (600 s) after it expired (`Roxy-Cache: STALE`,
  [stale during cooldown](/admin/help#term-stale-during-cooldown));
- otherwise 429 with `Retry-After` equal to the time left.

**Breakers.** A circuit [breaker](/admin/help#term-breaker) watches each endpoint, and each host, on each egress. It
opens when, within `breaker_window_s` (30 s), at least `breaker_failure_threshold` (5) calls failed and the failed
share is above `breaker_failure_ratio` (0.5, so more than half). A failure is a 5xx answer, a timeout or a
connection error; a 429 opens the endpoint's breaker at once, for as long as the cooldown. While it is open no call
goes out and callers are answered as during a cooldown. After `breaker_open_s` (30 s) it turns
[half-open](/admin/help#term-half-open): exactly one test call goes, from one worker in the whole fleet. If it works
the breaker closes; if it fails the breaker opens again for twice as long, up to 600 s.

**The adaptive rate.** With Adaptive per-endpoint rate (`adaptive_rate_enabled`) on, the default, Roxy tunes each
endpoint's rate by itself ([adaptive rate](/admin/help#term-adaptive-rate)):

- **Down, on the first 429 of a cooldown.** The rate drops by `adaptive_decrease_pct` (30 percent), counted from the
  lower of its current rate and the calls Roxy really made to it in the last minute (that number is what Roblox just
  refused), and never below `adaptive_min_per_min` (6 a minute). The burst shrinks in the same ratio. The lower
  limit also covers the calls already made: the bucket counts this minute's calls again at the new, slower pace, so
  the endpoint's next free slot can be a minute or more away, for every egress. When 3 endpoints of one host got
  429s together, the host's rate is lowered instead; when 2 hosts did, no rate is lowered (the whole egress cools
  down instead). A rate is not cut twice within 60 s, and only 429s through direct or the credential count (rotator
  exits differ from call to call).
- **Up, slowly.** Once an hour the leader worker looks for endpoints that went `adaptive_probe_after_h` (24) hours
  without a single 429 while more than 1 percent of their calls were turned away by their own bucket. Those rise by
  `adaptive_increase_pct` (10 percent), never above `adaptive_max_per_min` (600). The burst grows by at most one call
  per raise. An endpoint whose limit is never reached is never raised: there is no evidence it needs more. A
  statistics reset that deleted the record of Roblox 429s also restarts the 24 hours: quiet hours after a reset are
  no proof that Roblox was happy.
- **Your rates win.** A rate you set, or an applied recommendation set, is never raised automatically (it can still
  be lowered after a 429: safety first). Every change the controller makes is a rate override marked "adaptive" on
  the Buckets card and an entry in the audit log.

### A worked example: a burst on one endpoint

Defaults throughout, the cache is cold, and the endpoint `users.roblox.com/v1/users/{id}` has no cache rule and no
override of its own. Suppose Roblox's real limit for it is 60 calls a minute from one address (Roblox does not
publish its limits; 60 is only for the example).

**Second 0: 60 requests arrive at once.** A game's servers start and ask about players: 20 requests are for the
same player, 40 are for 40 other players.

1. Cache: all 60 miss.
2. Single-flight: the 20 identical requests become one call and 19 followers. Roxy needs 41 calls.
3. Routing: direct, since the rotator's weight is 0. Near the end of the burst the direct bucket is more than 80
   percent booked, so a few calls may spill to the rotator if it is set up; they take the same endpoint slots either
   way.
4. Buckets: the endpoint bucket binds. 10 calls leave at once; the next free slots are at 0.55, 1.10, 1.65, 2.20,
   2.75, 3.30 and 3.85 s. The host bucket (15 at once, then one every 270 ms), the direct bucket (20, then one every
   200 ms) and the global bucket (30, then one every 100 ms) all have room.
5. Queue: these callers have no cached copy, so they may wait up to 4 s. The 7 slots up to 3.85 s are booked and
   their requests sleep until then. The next slot would be 4.40 s, past the limit, so the other 24 requests are
   answered at once with 429, "All request methods are busy right now; please try again shortly." and
   `Retry-After: 5`.
6. Answers: say the popular player's call was among the first 10. Then within 4 s, 36 of the 60 callers have their
   answer (17 owners and 19 followers), Roblox saw 17 calls, and each answer is cached for 120 s: the next request
   for any of those 17 players in the next two minutes is a hit.

| Time | Calls to Roblox | What callers get |
|---|---|---|
| 0 s | 10 calls | 24 callers: 429 with `Retry-After: 5`, at once |
| 0.55 to 3.85 s | 7 calls, one every 0.55 s | the 7 waiting callers get their answers |
| when the popular player's answer arrives | none | its 19 followers get the same answer |

**Seconds 5 to 28: the game keeps asking.** The servers come back after 5 s and keep asking about more players.
Roxy keeps to one call about every 0.55 s, so the endpoint never gets more than 120 calls in any minute. Requests
that cannot get a slot within 4 s keep getting 429 with a `Retry-After`.

**About 28 s: Roblox answers 429.** That was the 61st call in the minute (10 at once, then 51 more at 0.55 s
apart), one more than Roblox allows. Roblox sent no `Retry-After`. At once, for every worker:

- a cooldown opens on this endpoint through direct for 30 s plus up to 10 percent (30 to 33 s);
- the endpoint's breaker opens for the same time, and the host's breaker counts one failure;
- only one endpoint of `users.roblox.com` got a 429 in the last 60 s, so neither the host (3 endpoints) nor the
  egress (2 hosts) cools down as a whole;
- the endpoint's call counter says about 61 calls went out in the last minute, fewer than the bucket's 120, so the
  cut starts from 61: 61 x 0.7 = 42.7 a minute, and the burst shrinks in the same ratio, from 10 to 3. The Buckets
  card lists the change ("Lowered", 120 a minute to 42.7 a minute, "61 calls went out in the minute before the 429")
  and a rate override marked "adaptive" appears;
- the new limit also covers the 61 calls already made: paced at 42.7 a minute (one every 1.525 s) from the first
  one at 0 s, they reach to about 93 s, so the endpoint's next free slot, through any egress, is at about 90 s. This
  is on purpose: the lower limit must hold for every minute, including the one that began before the cut;
- the caller whose request got the 429 receives an older copy if Roxy has one, otherwise 429 with `Retry-After`
  set to the cooldown left. Calls already on their way that also get a 429 neither lengthen the cooldown nor cut the
  rate again.

**Seconds 28 to about 61: the cooldown.** Direct may not call this endpoint at all, and no egress has a free slot
for it before about 90 s, so the rotator cannot take these calls either. Fresh copies, and copies that expired less
than 60 s ago, are served from the cache; the request that got the 429 is not sent again; every other request gets
an older copy if one expired less than 600 s ago, otherwise 429 with a `Retry-After`.

**About 61 to 90 s: waiting for the slot.** The cooldown is over and the breaker is half-open, but the next slot is
at about 90 s. A caller with no copy may wait 4 s, so from about 86 s a request can book that slot; until then
callers keep getting older copies, or 429 with a `Retry-After` that points at the free slot.

**About 90 s: the test call.** The first call after the 429 is the breaker's test call, made by one worker. Roblox
answers 200 and the breaker closes. From then on the endpoint gets one call every 1.525 s (61,000 ms divided by 40),
never more than 42 in any minute, safely under Roblox's 60; after a quiet spell a burst of 3 may leave at once.

**If Roblox says 429 again later.** The cooldown doubles each time (60, 120, 240 s, up to 600 s) as long as the
previous one ended less than 600 s before. The rate is cut again from what was really sent, but not within 60 s of
the last cut and never below 6 a minute.

**The next days: the slow climb back.** If for 24 hours in a row the endpoint gets no 429 while more than 1 percent
of its calls are turned away by its bucket, the hourly job raises it by 10 percent: 42.7 to about 47 a minute (burst
still 3), then about 51.7 (burst 4), and so on. Getting back to 120 takes many quiet days, on purpose. If you know
the real limit, set the rate yourself on the Buckets card: the adaptive controller never raises a rate you set.

**A different failure: Roblox errors.** Had Roblox answered 503 instead, Roxy would wait 200 to 600 ms at random and
try once more on a new slot, possibly through the other anonymous path. If that failed too, the caller would get an
older copy if Roxy had one, otherwise Roblox's own status with the body "Upstream request failed; please try again
later." and a `Retry-After` (Roblox's own, else 5 s). Five such failures within 30 s, more than half of the calls,
open the endpoint's breaker for 30 s.

### Where to see and tune each part

| Part | Where you see it | Main settings |
|---|---|---|
| Cache, stale-while-revalidate, coalescing | the [Cache](#cache) page | `cache_ttl_seconds`, `cache_swr_seconds`, `cache_stale_seconds`, `cache_coalesce`, `cache_coalesce_wait_ms`, `swr_max_inflight` |
| Routing | Upstream > Routing; the [Egress](#egress) page | `direct_weight`, `rotator_weight`, `direct_shift_threshold_pct`, routing rules |
| Buckets | Upstream > Buckets; Credential > Budget | the bucket settings in the table above, rate overrides |
| Queue | Upstream > Queue; the queue wait line of Latency percentiles | `queue_wait_*_ms`, `queue_max_length`, `request_deadline_s` |
| Cooldowns | Upstream > Cooldowns | `cooldown_*`, `credential_cooldown_default_s`, `rotator_cooldown_*` |
| Breakers | Upstream > Breakers | `breaker_*` |
| Adaptive rate | Upstream > Buckets, "Adaptive rate controller" | `adaptive_*` |
| Retries | Upstream > Retries | `upstream_max_attempts`, `backoff_base_ms`, `backoff_cap_ms`, `fallback_on_429`, `csrf_token_cache_s` |

Every setting is explained, with its range and risk, next to its control and in `docs/SETTINGS.md`; the
[Settings](#settings) chapter says how to read one.

## Overview

The Overview (`/admin/overview`, keys `g` then `o`) answers three questions at a glance: is Roxy healthy, is
Roblox still happy with it, and what needs your attention first. The logo in the top bar opens it.

**When to use this page**

- Every day, as the first step of the [daily routine](#daily-routine).
- Right after a deploy or a settings change, to see whether the numbers moved.
- When an alert email arrives, to see the whole picture before you open the page the alert names.
- When a game developer says "the proxy is slow" or "the proxy is down".

### Time range on this page

The time range and the comparison work as on every page (see
[The time range and the comparison](#the-time-range-and-the-comparison)). What follows the range here:

- **Key numbers**, **Visitors**, **Requests in and calls out**, **Outcomes**, **Top endpoints**, **Top places** and
  **Recent notable events** cover the chosen range.
- Five tiles do not: **Requests (last hour)** and **Failures (last hour)** always cover the last 60 minutes, and
  **Rotator bytes today**, **Active bans** and **Service uptime** are about right now.
- The status strip and the top recommendations are always about right now, and so are the per minute rates of
  **Top places**.

No setting is edited on the Overview. Its only actions are the two header buttons and the Visitors card's
**Reset**; everything else opens the page that holds the controls.

The tiles always show a change: with No comparison chosen, they compare with the previous period of the same length.
The chart draws the comparison (as dashed lines) only when you choose one.

The status strip, the top recommendations and the key numbers update themselves from the live event stream (the
strip at most every 20 seconds, the recommendations every 10, the tiles every 60), and on the Live range the requests
chart and Outcomes do too, so the page has no refresh button. Visitors, Top endpoints, Top places and Recent notable
events show the moment the page was loaded: reload the page to bring them up to date.

### Header buttons

- **Export data** opens the Data page's Exports card, where every table downloads as CSV or JSON.
- **Check Proxy Health** starts a health run of every check except the credential check, then opens the run on the
  [Health](#health) page. Because it leaves the credential check out, it never spends a call on the Roblox account
  and never asks for your second factor. If a run is already going anywhere, it opens that run instead of starting a
  second one.

### Status

One item per part of Roxy. Each item says its state in words, has a colored edge, and has a **Details** link to the
page that manages it (all except Proxy).

- **Proxy**
  - Normal: **Running** ("Serving callers normally").
  - **Paused**: every proxy request gets the pause message. The detail says since when, and how many requests were
    refused so far. If you did not pause it, find out who did on the Audit page; resume with **Resume proxy** in the
    top bar. See [Emergency stop](/admin/help/runbooks#emergency-stop).
  - **Emergency limit on**: a strict per-address limit applies to every caller (see the
    [emergency limit](/admin/help#term-emergency-limit)). The detail counts the refusals. Turn it off with the
    **Emergency limit** button in the top bar when the attack is over.
  - **Starting**: this worker is still starting; refresh in a moment.
- **Credential** (the one Roblox account; its value is never shown here)
  - Normal: **Working**. By default the credential is used only for Roxy's own checks, never for callers.
  - **Not checked yet**: no check of the credential has finished yet; the Credential page shows its last check.
  - **Cooling down**: Roblox rate-limited the account; the detail says when calls resume. See
    [Credential cooling down](/admin/help/runbooks#credential-cooling-down).
  - **Rejected by Roblox** or **Unavailable**: see [Credential rejected](/admin/help/runbooks#credential-rejected)
    and the Credential page.
  - **Not configured** ("anonymous paths serve every caller") or **Switched off**: no credential is in use.
  - **Not started**: this worker is still starting.
- **Rotator** (the DataImpulse [rotator](/admin/help#term-rotator))
  - Normal: **Working**, or **Not configured** when you do not use one (every call then goes direct).
  - **Switched off**, **Resting after errors**, **Stopped by its budget**, **Stopped by its quota**, **Daily cap
    reached** or **Usage unknown**: the rotator is not used for now and the direct path serves every call. The
    detail says when it may be usable again.
  - **URL not valid**, **Key missing** or **Stored URL unreadable**: a configuration problem; open the Egress page.
  - **Not started**: this worker is still starting.
  - For any of these, see [Rotator down or quota exhausted](/admin/help/runbooks#rotator-down-or-quota-exhausted).
- **Leader** (the one worker that runs scheduled jobs; see [leader](/admin/help#term-leader))
  - Normal: **Worker** followed by its process number, with its epoch (a number that goes up each time leadership
    changes hands).
  - **No leader**: scheduled jobs wait until a worker takes over, which takes about 15 seconds. If it stays, see
    [Workers or leader missing](/admin/help/runbooks#workers-or-leader-missing).
  - **Unknown**: the shared lease could not be read right now; look again in a minute.
- **Workers**
  - Normal: **2 of 2** (Roxy runs two worker processes): both sent a heartbeat in the last 20 seconds. Only the
    color serving this page is counted.
  - Fewer than expected (amber), or none (red): open System > Workers and see
    [Workers or leader missing](/admin/help/runbooks#workers-or-leader-missing).
- **Version**
  - The release that is running (or "Development build"), and the configuration version, a counter that goes up
    with every settings or rule change. After a deploy, check that the release changed.

### Top recommendations

The three most severe open [recommendations](/admin/help#term-recommendation), newest first among equals. Each one
shows its severity, the rule that made it, how long ago it changed, its title, the expected impact, and its
confidence, risk and family. The title opens it on the [Recommendations](#recommendations) page, where it can be
previewed and applied; this card only reads. When more than three are open, **All N open** opens the full list
(a "+" after the number means 50 or more).

- Normal: "Nothing needs your attention", or a few warning and info items.
- Worrying: anything critical, or "The recommendations engine is switched off" (its button opens the engine
  settings; switch the engine back on unless you turned it off on purpose).
- "Recommendations are not available right now" means the list could not be read; the card tries again shortly.

### Key numbers

Each tile has a name, a **?** button with its exact definition, the value, an arrow with the percent change against
the comparison, and a small trend line. The whole tile is a link to the page that explains the number, with your
time range kept. A green arrow means better and a red one worse; numbers where neither direction is good or bad (for
example Requests) get a plain arrow. Screen readers also hear "an improvement" or "getting worse".

When part of a tile's data was deleted by a statistics reset, the tile shows a notice ("Part of this data was reset;
no comparison is shown.") instead of an arrow, because a comparison over partial data would mislead. The card lists
the resets of the range above the tiles.

The tiles, in the order the page shows them:

- **Requests**: every proxy request callers sent, whatever happened to it. Neither up nor down is good by itself;
  a sudden jump with no new game behind it can be an attack (look at Refused in **Outcomes**). Opens Traffic.
- **Requests (last hour)**: the same for the last 60 minutes, compared with the hour before. It says whether Roxy is
  busy right now.
- **Failures (last hour)**: requests Roxy could not answer in the last 60 minutes: Roblox kept failing (5xx,
  timeouts, connection errors), every route was unavailable, or Roxy failed itself. Refusals and Roblox's own 4xx
  answers are not failures. Normal: zero or close to it. A steady number: open the Upstream page (the tile goes to
  Request failures) and see [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable) or
  [All upstream paths unavailable](/admin/help/runbooks#all-upstream-paths-unavailable).
- **Avoided upstream calls (percent)**: the share of caller demand that never reached Roblox, because the cache
  answered or several callers shared one fetch (an [avoided upstream call](/admin/help#term-avoided-upstream-call)).
  The line under it says how many of how many caller requests needed no call. Higher is better; the health check
  H-CACHE-HIT passes above 30% over the last hour and warns at 30% or lower. It can be below 0%: then retries and
  background refreshes made more calls to Roblox than callers sent, and the line under it says how many calls per
  request. Low or negative: open the Cache page and look for CACHE-LOW-HIT, HOT-ENDPOINT or CACHE-TTL-TUNE
  recommendations; see [Cache not working](/admin/help/runbooks#cache-not-working).
- **Avoided upstream calls**: the same as a count of calls. Higher is better.
- **Upstream calls for callers**: requests Roxy sent to Roblox for callers, retries and background refreshes
  included. Lower is better for the same traffic.
- **Roblox 429s**: times Roblox answered 429 Too Many Requests, which means Roblox is rate limiting Roxy's address or
  account. This is the number to keep near zero. The line under it gives the share of upstream calls. The health
  check H-429-RATE passes under 0.5% over 15 minutes and fails at 2% or more, and Roxy sends the alert "Roxy: Roblox
  is rate-limiting us (N%)" when the share is above 2% over the last 10 minutes (with at least 5 such answers).
  Rising: open the Upstream page (the tile goes to Roblox 429s), check the UP-429 recommendations, and see
  [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us).
- **Roblox 429s per 10,000 requests**: the same relative to traffic, so a quiet day and a busy day compare. When v1's
  numbers were imported, the line under it shows v1's lifetime figure as a baseline. Lower is better.
- **429s from Roxy**: times Roxy itself answered 429 (its own throttles and limits). This is Roxy protecting
  Roblox, not Roblox limiting Roxy. By default cache hits count toward each caller's per-address limit
  (`throttle_count_cache_hits` is on), so a caller that repeats cached requests fast is throttled too. A sudden jump
  means a caller hit its limits or an attack is going on: the tile opens Protection > Refusal reasons; see
  [Under attack](/admin/help/runbooks#under-attack).
- **Caller 5xx**: server error answers (500 to 599) sent to callers, whoever produced them. The health check
  H-ERR-RATE passes under 0.5% of requests over 15 minutes and fails at 2% or more; Roxy sends the alert "Roxy:
  caller errors at N%" when the share is above 2% over the last 10 minutes (with at least 5 such answers). Both
  leave the pause message's own 503 answers out (a pause you chose is not an error; while only the pause answered,
  the check says "Roxy is paused"). See [Caller errors](/admin/help/runbooks#caller-errors).
- **5xx from Roblox**: Roblox's own server errors, counted the way v1 counted them: every answer Roblox gave a call
  Roxy made for callers (their requests, background refreshes and the retries of both), once per call. A 5xx that a
  retry or an older cached copy hid from the caller still counts here; Roxy's own checks and lookups do not. A rise
  usually means trouble at Roblox, not at Roxy; see
  [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).
- **2xx from Roblox**: Roblox's successful answers, counted the same way (per call, retries included). Higher is
  better for the same traffic.
- **4xx from Roblox**: Roblox's client error answers (for example 404, or 401 and 403 for an endpoint that wants a
  signed-in account), counted the same way. Roxy's own refusals are not in it (they are in **429s from Roxy** and on
  Protection). Neither direction is good by itself, but a sudden rise of 401 or 403 means an endpoint stopped
  answering anonymous callers.

These three count from the upgrade that added Roblox's answers to the statistics (metrics migration 0010); a range
that starts earlier shows a notice instead of an arrow. What callers themselves got (Roxy's refusals and cache answers
included) is on the Traffic page's **Status codes** card, "answers to callers".
- **Latency p95**: 95 of 100 caller requests took at most this long (see
  [percentile](/admin/help#term-percentile)). Cache hits are fast, so this is usually well below Roblox's own time.
  The health check H-LATENCY judges Roblox's p95 over 15 minutes: under 1,000 ms passes, under 2,500 ms warns.
  Rising: the tile opens Traffic > Latency; see
  [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).
- **Rotator bytes today**: bytes sent and received through DataImpulse since local midnight, an estimate of what the
  provider bills, compared with the same part of yesterday. Lower is better (it costs money). A day far above the
  usual: open Egress > Usage and Budget, and look for an EGR-BURN recommendation.
- **Active bans**: address, network, place and User-Agent bans in force right now (no arrow). A jump usually means
  the spam detectors are banning: open Protection > Bans; see [Under attack](/admin/help/runbooks#under-attack).
- **Service uptime**: how long the oldest running worker of this color has been up (no arrow). Workers are recycled
  on purpose, so this restarts only when every worker of the color was replaced: a deploy or a restart. A short
  uptime you cannot explain: open System > Workers and see [Service down](/admin/help/runbooks#service-down).
- **Served from cache**: requests answered from Roxy's cache, fresh or stale, including callers that shared another
  caller's fetch. Higher is better.
- **Errors hidden from callers**: Roblox (or the way to it) failed, but Roxy still answered with an older cached
  copy. The caller got data; the failure is counted here so it is never mistaken for a success. A few during a
  Roblox outage is the cache doing its job; a steady number means Roblox keeps failing (the tile opens Cache
  statistics; the Upstream page shows what Roblox is doing).

### Visitors

Visits to Roxy's public web pages (not proxy traffic; see [visitor](/admin/help#term-visitor)), compared like the
key numbers. Visits are counted per closed minute, so the card can be up to a minute behind.

- **Human visitors**, **Crawler visitors** and **Unknown visitors** (no User-Agent at all): visits to the home page,
  split by who seems to be visiting.
- **Home page visits**: every load of the public home page.
- **Admin page visits**: loads of the admin login page. Your own visits stop counting once this browser has signed
  in.
- **robots.txt crawls** and **Sitemap crawls**: fetches by search engines. These two and Crawler visitors open
  Security > Crawler activity.

None of these is good or bad by itself. Many Admin page visits that are not yours mean someone is looking for the
login page: check Security > Admin logins and Probes, and see
[Unexpected admin login](/admin/help/runbooks#unexpected-admin-login) if any sign-in is not yours.

**Reset** (v1's "Clear data") deletes the visit counts behind this card and nothing else. Its drawer first shows
what will be deleted, what stays (requests, refusals and every other number) and whether a snapshot of metrics.db is
taken first. To go ahead you type a reason (saved in the audit log) and the phrase `reset visits`; no second factor is
asked. Afterwards the page reloads and every chart shows a marker at the moment of the reset. The dashboard cannot
undo it; only a snapshot taken first can bring the counts back, by a restore on the server (see
[Statistics resets](#statistics-resets)).

### Requests in and calls out

A chart of four lines over the range:

- **Requests**: everything callers sent.
- **Caller demand**: the requests Roxy actually tried to answer (refused requests are left out, so an attack Roxy
  turned away never makes the cache look better).
- **Upstream calls for callers**: the calls Roxy made to Roblox, retries and background refreshes included.
- **Served from cache**: the requests the cache answered.

The gap between Caller demand and Upstream calls is what the cache and [coalescing](/admin/help#term-coalescing)
saved. Normal: the upstream line runs well below the demand line. Worrying: the upstream line close to or above the
demand line (retries or refreshes are multiplying the calls; open Upstream > Retries), or Requests climbing while
Caller demand stays flat (Roxy is refusing a lot; open the Protection page).

The chart's zoom, legend, markers and data table work as on every chart (see [Charts](#charts)).

### Outcomes

How the requests of the range ended, as a table: **Outcome**, **Requests** and **Share** (a bar and a percent). The
outcomes are **Served by Roblox**, **Served from cache**, **Refused by Roxy** and **Failed**; the subtitle gives the
total. Refused includes the requests turned away for their size or method before any check ran (a body, header or
address too long, or a method Roxy does not take; Protection > Request limits counts them). When some of the "Served
by Roblox" requests were OPTIONS requests that Roxy answered itself, a note under the table says how many (they never
reached Roblox).

- Normal: Failed close to zero; Served from cache a large share; Refused small.
- Worrying: Failed growing (open the Upstream page), or Refused taking a large share (open Protection > Pipeline to
  see which check refuses).

### Top endpoints

The ten [endpoint templates](/admin/help#term-endpoint-template) callers asked for most in the range. Columns:

- **Endpoint**: the template; it opens the Endpoints page filtered to it.
- **Requests**: caller requests for it.
- **Upstream calls**: calls Roxy made to Roblox for it.
- **Avoided**: the share of its demand that needed no call to Roblox (the **?** explains it). A negative share is
  shown as it is, with the reason under it.
- **Roblox 429s**: how often Roblox rate-limited calls to it.
- **p95**: 95 of 100 requests for it took at most this long ("n/a" when there is no measurement).

**Every endpoint** opens the full Endpoints table. Worrying: a busy endpoint with Roblox 429s, or with a low or
negative Avoided share. Look on the Recommendations page for UP-429-ENDPOINT, CACHE-LOW-HIT or HOT-ENDPOINT about it.

### Top places

The ten experiences that sent the most requests in the range, by the Roblox-Id header their servers send (see
[place](/admin/help#term-place)). A place id is what the caller claims, so it is shown as plain text, never as a
link. Columns:

- **Place**: the place id.
- **Requests**: its requests in the range.
- **Refused**: how many Roxy refused, with the share in parentheses.
- **Per minute (1, 5, 60 min)**: its request rate over the last 1, 5 and 60 minutes (these are about right now, not
  the range).
- **Top endpoint**: the template it calls most.

**Every place** opens Clients > Places. Worrying: one place taking most of the traffic (the PLACE-HEAVY rule
watches for one experience taking most of the upstream calls), or a high refused share for a real game (its limits
may be too tight; see the Clients page and Protection > Place limits).

### Recent notable events

The page's main table: the notable events of the range, newest first. Columns: **Time**, **Event** (the event
type), **Severity** (Info, Warning, Critical, Error), **Reason** (the reason code recorded with it), **Endpoint**
(when it concerns one) and **Detail** (everything recorded with it, as `name: value` pairs; secrets are never
recorded). Search, sort by time, event or severity, page through it, and download it as CSV or JSON; a row opens
the whole event in a drawer. The search, sort and page stay in the page address.

The events listed are: breakers opening, half-open and closing; Roblox 429 attributions; credential cooldowns,
rotations, replacements, rejections and checks; leak guard blocks; the rotator resting after errors; the abuse
checks degrading and recovering; spam detector bans and "would have banned" findings; cache purges and evictions;
recommendation changes; and finished health runs. High-volume events (live requests, refusals, visits, probes) have
their own pages. At most the newest 250 events of the range are listed; when there are more, a notice says so and
the Data page exports every one.

- Normal: a quiet list ("No notable events in this range" is good news), or a few info events.
- Worrying: a breaker that keeps opening (see the UP-BREAKER-FLAP recommendation and the Upstream page), a
  credential rejection ([Credential rejected](/admin/help/runbooks#credential-rejected)), a leak guard block
  ([Leak guard](/admin/help/runbooks#leak-guard)), or a run of spam bans
  ([Under attack](/admin/help/runbooks#under-attack)).

### On a phone

- The status items and the tiles sit two per row, and every card takes the full width.
- **Top endpoints** and **Top places** turn into one block per row, each value with its column name, so the page
  never scrolls sideways.
- On a touch screen each top recommendation's title is a full-width target you can tap with a thumb.
- The events table shows each row as a card with its time, event and severity; tap it for the rest.

## Recommendations

The Recommendations page (`/admin/recommendations`, keys `g` then `r`) lists what Roxy found in its own
numbers, each finding with its evidence and the exact change it suggests. You preview a change, apply it, and undo it
if you change your mind; or you snooze or dismiss it. Nothing changes until you press Apply, unless you switch on
auto-apply.

**When to use this page**

- Every day, as step 2 of the [daily routine](#daily-routine).
- When the bell in the top bar shows a red dot (a critical recommendation is open).
- When a failing health check offers **Apply fix**, or an alert email links here.
- When you want to tune a rule that makes too many (or too few) recommendations.

### How the rules work

A rule is a small piece of code that looks at one kind of problem. Roxy has 50 of them in nine families:

- **upstream** (15 rules): Roblox 429s per endpoint, host or credential, retries that multiply 429s, callers that
  ignore Retry-After, Roblox rejecting Roxy (403, 401, 400), the token handshake Roblox asks for on some calls
  (CSRF), challenge pages, which User-Agent gets fewer 429s, Roblox 5xx, timeouts and slow answers, the upstream
  queue, the pacing buckets and breakers.
- **cache** (7): low hit ratios, cache times that can rise or must fall, cache busting parameters, a cache that is
  too small or switched off, repeated Roblox 404 or 400 answers, and busy endpoints without a cache rule.
- **egress** (4): the rotator quota, rotator use, burned exit addresses and the provider's byte count.
- **credential** (4): a credential that is rejected or expiring, endpoints sent with it that work as well without it,
  leak guard blocks, and Roxy's own credential checks spending the account's calls.
- **abuse** (6): spam detector findings, bot-like heavy clients, distributed attacks, the tarpit, the per-address
  throttle and one experience taking most of the upstream calls.
- **filter** (3): clients that keep hitting limits, stale or harmful rules, bans and bypass entries, and filters that
  block real traffic.
- **system** (7): disk growth, busy workers, a slow event loop, Roxy's own errors, dropped metrics, a settings change
  that made things worse, and failing health checks.
- **security** (3): an admin allowlist that would help, bypass entries that never expire, and settings at a
  high-risk value.
- **host** (1): a real Roblox host missing from the host allowlist.

How a rule turns into a recommendation:

1. The leader (the one worker that runs scheduled jobs) runs every switched-on rule every 30 seconds
   (`insights_interval_s`), and also right after a trigger: a burst of Roblox 429s, a breaker opening, a change of
   the credential's status (a leak guard block included), a settings or rule change, a spam detector ban, or a failed
   health check. Triggered runs happen at most once every 5 seconds.
2. Each finding names its **subject** (an endpoint, a client, a rule row or a setting). A rule plus a subject is
   one recommendation: while the problem lasts, the same recommendation is updated with fresh evidence instead of a
   new one appearing every 30 seconds.
3. A finding below the rule's evidence minimum (too few observations to be sure) is never shown.
4. The rule sets the severity (**Critical**, **Warning** or **Info**), its confidence (low, medium or high: how sure
   the rule is; some rules raise it when they saw more evidence) and the risk of its change (low, medium or high).
   You can force one severity per rule in the rule's tuning drawer.
5. When every change touches only one row (for example one endpoint's cache rule or pacing bucket, or one client),
   a new or changed rule pattern covers exactly one endpoint, and the rule is one of the five that allow it, the
   recommendation is marked **Safe to auto-apply**. A global setting is never marked safe.
6. Rules read only evidence that is still there. A rule that would suggest raising a pacing bucket (UP-BUCKET-TUNE,
   UP-LATENCY, UP-QUEUE-SAT) does so only when that bucket's rate has not changed for its clean period, and the "too
   loose" side ignores 429s from before the bucket's last change, so one burst of 429s lowers a bucket once. A rule
   that suggests removing a filter that never matched (FILTER-REMOVE) waits a whole idle period again after a
   statistics reset deleted its hit record, and names an older reset instead of saying "never matched".

What happens to a recommendation over time (its **state**):

| State | What it means |
|---|---|
| Open | Waiting for you. Updated while the problem lasts. |
| Snoozed | Hidden until the time you chose; it comes back as Open if the problem is still there. |
| Applied | You applied it. |
| Applied automatically | Auto-apply applied it. |
| Rolled back | Its changes were undone, by you (Undo) or automatically after it made things worse. |
| Dismissed | You closed it with a reason. |
| Resolved on its own | The problem went away before anyone acted. |
| Expired | Nobody acted on it for a week (`recommendation_expiry_days`). A fresh one opens if the problem remains. |

After you dismiss a recommendation, or after it was rolled back, the same rule stays quiet about the same subject
for `dismiss_cooldown_days` (7 days by default), unless the problem becomes more severe. After an apply, the same
finding stays quiet during the watch window (30 minutes by default); if the problem is still there after that, a new
recommendation opens.

Switching the engine off (`insights_enabled`) stops new recommendations and stops auto-apply; the ones already
listed stay but are no longer updated. Health checks and alerts run either way.

### Time range on this page

The list is not limited by time. The range in the top bar filters only the **History** card, by when an action
happened. This page opens on **All** when its address names no range. The comparison is not used here.

The **Tune the rules** button at the top jumps to the **Rules** card.

### Recommendations (the list)

The page's main table. Its subtitle counts the open ones by severity ("3 open: 1 critical, 2 warnings, 0 info").
A notice above it says when the engine is switched off (the list then shows only what was found before) and when
auto-apply is on.

Filters, at the top of the table:

- **State**: Open (the default), Applied, Applied automatically, Rolled back, Snoozed, Dismissed, Resolved on its
  own, Expired, or Every state.
- **Severity**: Any severity, Critical, Warning or Info.
- **Family**: Any family, or one of the nine families.
- **Rule**: Any rule, or one rule by its id.

Plus a search box. The filters, search, sort and page stay in the page address, so you can bookmark a view.

Columns shown: **Recommendation** (the title, with "Safe to auto-apply" under it when it is), **Severity**,
**State** (with "until" and the time for a snoozed one, or the reason for a dismissed one), **Rule**, **Family**,
**Subject**, **Risk** and **Updated**. More columns are one click away in the column chooser: **Expected impact**,
**Created**, **Expires**, **Id** and **Confidence**. The list is sorted most severe first. The export menu downloads
it as CSV or JSON. The list updates itself when a recommendation changes (at most every 10 seconds), and the list
and the History card update after every action you take in the drawer.

- Normal: an empty list ("Nothing to recommend right now", which is good news) or a few info items.
- Worrying: any critical item, or warnings that pile up for days. Open them.

A row opens its **detail drawer**. A link of the form `/admin/recommendations?rec=<id>` (the Overview and the
Health page use it) opens the same drawer directly.

#### The detail drawer: how to read the evidence

From top to bottom:

- **Badges**: the severity, the state, the rule id, and "Medium confidence, low risk" in words. Then
  **Safe to auto-apply** ("Every change touches one endpoint, rule row or client") when it is marked safe. When its
  rule allowed auto-apply but the row it changes is an older pattern that also covers the endpoints below this one,
  the drawer shows **Not auto-applied** with that reason instead. Otherwise neither badge appears.
- **Title and explanation**: what the rule noticed, in sentences, and **Expected:** what the change should do, with
  numbers.
- **First raised**, **Last updated**, **Expires** (if nobody acts on it) and **Subject**.
- **Evidence**:
  - "From ... to ...": the time window the rule looked at, and "based on N observations": how much data the decision
    rests on. More observations make the numbers more trustworthy.
  - A table of the numbers the recommendation rests on (**What** and **Value**, with units).
  - A small chart for each timeline the rule recorded (for example 429s per minute), each with **Show the data as a
    table** (times in UTC).
  - Links to the dashboard pages that show the same data, so you can check it yourself.
  - **Everything else the rule recorded**: the rest of its details as text.
- **Proposed changes**: a table with **What** (the kind of change and its target, for example "Setting: Error answer
  lifetime" with its key, or a cache rule with its pattern), **Now** and **After**. "not set" means the row does not
  exist yet; "removed" means the change deletes it. "Exactly this endpoint:" names the one endpoint a new rule
  covers. A manual step says "Roxy cannot make this change; it is a step for you" and cannot be applied.
- **Watch window** (after an apply): what it found, from and until, and for an automatic change its rollback:
  **Rolled back**, **Rollback pending** (with the number of attempts) or **Rollback refused** (with the reason). The
  verdicts: "Watching"; "Kept: the guard numbers stayed within bounds" (none of the four got worse); "Kept, but the
  guard numbers got worse: a change applied by hand is never rolled back automatically; review it and undo it if it
  hurts" (Roxy rolls back only automatic changes, so for a change you applied this is your cue); "Kept: the guard
  numbers got worse and the automatic rollback was refused"; "Ended with worse guard numbers; the change was no
  longer applied by this recommendation"; "Rolled back automatically"; or "Ended: the change was undone by hand".
  When numbers got worse, a line per number says by how much, for example "Got worse: Error rate 0.00% before, 50.00%
  after".
- **What you can do**: the buttons below, or a line that says why one is not possible now (for example "It is
  applied; only open or snoozed recommendations can be changed").
- **What happened to it**: every action taken on it, with who and when; and **Earlier recommendations with the same
  finding**, each of which opens its own drawer.
- **The rule**: what the rule detects, and **Tune this rule**, which opens the rule's tuning drawer.

How to judge one: check that the evidence window is recent, that the numbers match what you see on the linked
pages, and that the change touches what the title says. High confidence with a low risk change is an easy yes; low
confidence or a high risk change deserves a preview over a longer window first.

#### Preview and the dry run

**Preview and apply** opens the preview panel under the button. It never changes anything. It shows:

- **Replay**: Last hour (the default), Last 6 hours or Last 24 hours. A longer window gives a steadier picture; it
  cannot go beyond the sample history (`request_sample_hours`, 24 hours by default).
- **What Apply will write**: each change as Apply would write it now, with **Now** and **After**. A change that is no
  longer valid shows **Not valid** with the reason, and Apply is then not offered ("the rule will propose again on its
  next run"). A list setting (for example the allowed Roblox hosts) is applied as a difference: only the items the
  rule added or removed change, so an edit you made since is kept.
- **What it would have done** over the replay window: a [dry run](/admin/help#term-dry-run) that replays sampled
  real requests through the same cache, limit and bucket code the proxy runs:
  - **Requests replayed**: how many samples were replayed. When sampling is below 100%, the counts below are scaled
    up from the samples, and it says by how much.
  - **Requests in that time**, and how many of them called Roblox.
  - **Calls to Roblox avoided** and **Cache hit ratio** under the change (for a cache change).
  - **Served-old-data risk**: the share of simulated cache hits that would have served an answer Roblox had already
    changed. Lower is better; a high value means the cache time is too long for this endpoint.
  - **Requests it would have refused** (for a limit change) and **Queue wait p95** (for a pacing bucket change).
  - A note when the replay covered less than the window you asked for (at most 50,000 samples are replayed), and
    "Computed" with the time (a preview less than a minute old is reused).
  - When no change of the recommendation can be replayed (for example a setting the samples cannot show), it says
    so; the diff above it is then the whole preview.

Below it sits the Apply form, and **Preview again** to refresh the numbers. If several previews run at the same
moment, Roxy may ask you to try again in a few seconds.

#### Apply

The Apply form says what will happen: the changes above are written together, each through the same audited
settings and rules services as the editors, and every worker uses them within a second. If one change fails, the
ones already written are put back, so a recommendation is applied completely or not at all.

- **Reason**: optional and saved in the audit log, except when a change gives a setting a high-risk value: then the
  reason is required and you also tick "I understand: ... will take a high-risk value".
- **Second factor**: when a change touches an admin security or credential setting (or one of the two settings
  that need it on their own, `health_auto_include_credential` and `export_include_ips`) or an admin allowlist
  entry, the form says so, and Roxy asks you to confirm it is you ([Step 4](#step-4-save-the-recovery-codes)) before
  it finishes the apply by itself.
- **Exactly as previewed**: the form sends a fingerprint of the changes you saw. If the rule rewrote the proposal in
  the meantime, nothing is applied and Roxy says "This recommendation changed since you previewed it"; preview again.
- After the apply, the drawer reloads showing **Applied** and a **Watch window** of `auto_apply_watch_minutes`
  (30 minutes by default). Each change also appears on the Audit page, marked as made by this recommendation.

#### Undo

**Undo the changes** appears on an applied recommendation (by you or automatically). It puts back exactly what the
apply changed, on every worker within a second, with an optional reason for the audit log. An undo writes settings
like the settings editor does, under the same rules:

- When what it puts back is a high-risk value, the reason is required and you tick the confirmation that names the
  settings, as in the editor.
- It never arms the spam detectors (puts `spam_dry_run` back to 0): arming is done only on the Protection page, which
  first shows who would be banned. The undo form says so and the undo is refused while that is the case; arm them
  there, then undo again if you still need to.
- Like Apply, it asks for your second factor when what it writes back touches admin security or the credential.

Undo is refused when someone changed the same setting or rule since the apply (the message names it): Roxy never
overwrites a later edit. Change that value by hand on its page instead.

After an undo the state is **Rolled back**. If its watch window was still open, it ends ("the change was undone by
hand"); a window that had already closed keeps its verdict, and the undo shows in the history. The same finding then
stays quiet for the quiet period unless it becomes more severe. A rolled back recommendation cannot be
applied again; if the problem is still there after the quiet period, the rule opens a fresh one.

#### Snooze and dismiss

- **Snooze** hides an open recommendation: **For 1 hour**, **For 1 day**, **For 1 week**, or **Or until** a date and
  time (in the dashboard time zone, at most 90 days ahead). When the time comes it is Open again if the problem is
  still there, or Resolved if it went away. Use it for "not now". To bring one back early, find it with the State
  filter (Snoozed): a snoozed recommendation can still be previewed and applied, dismissed, or snoozed again for a
  shorter time.
- **Dismiss** closes it with a reason: **Not accurate**, **Intended behavior**, **Will handle manually** or **Other**
  (Other needs a few words in **Say more**, which is saved in the audit log). Use it for "no". The same rule then
  stays quiet about the same subject for `dismiss_cooldown_days` (7 days by default), unless the problem becomes more
  severe. A dismissal cannot be taken back; find dismissed ones with the State filter.

Neither one changes any setting or rule, and neither asks for a second factor.

### History

Every action taken on any recommendation, newest first: applies, undos, snoozes, dismissals, automatic applies and
automatic rollbacks. The range in the top bar filters it by when the action happened (choose **All** to see every
one; the subtitle says which range is shown).

Columns: **When**, **What** (Applied, Undone, Snoozed, Dismissed, Applied automatically, or Rolled back
automatically, shown in amber), **Title**, **Rule**, **Who** (`admin:` and your name, or `auto_apply:insights` for
auto-apply) and **Details** (for example "2 changes" and the reason, or the snooze end). **Recommendation** (the
recommendation's id) and **Action** (the action's own number) are in the column chooser. Filters: **Action** and
**Rule**; a search box; CSV or JSON export. Unlike the list, this card's filters and search are not kept in the page
address. A row opens the recommendation's drawer.

Worrying: "Rolled back automatically" entries (see
[Auto-applied change rolled back](/admin/help/runbooks#auto-applied-change-rolled-back)), or the same finding
dismissed again and again (tune or switch off its rule instead).

### Rules

Every rule, with its switch. The subtitle says how many of the 50 rules are in this build. Columns: **Rule** (the
id), **Detects** (what it looks for), **Family**, **On** (On or Off), **Severity** ("Its own", or the level you
forced), **Open** (its open recommendations right now), **Safe to auto-apply** (Yes for UP-429-ENDPOINT,
UP-BUCKET-TUNE, CACHE-LOW-HIT, CACHE-TTL-TUNE and HOT-ENDPOINT) and **Implemented**. Filter by **Family**, search,
and export.

A row opens the rule's **Tune** drawer:

- **What it detects**: the rule's own description, its family, its severity, and **Runs early after** (the trigger
  events that start an early run of this rule).
- Badges: On or Switched off; "Auto-apply may use it" or "Never auto-applied".
- **Open recommendations of this rule**, each opening its drawer.
- **Tune this rule**: the rule's settings, each an ordinary setting with its description, default, allowed range,
  risk and history. Every rule has **rule enabled** (`insight_<rule>_enabled`, on by default) and **severity**
  (`insight_<rule>_severity`: Automatic, the recommended default, keeps the rule's own severity; Info, Warn or
  Critical force one level). The severity orders the Recommendations page and the bell; Roxy sends no alert for a
  recommendation, so a rule you must never miss needs the page checked (the daily digest, on by default, also counts
  the open ones). Most rules also have thresholds, for example
  **UP-429-ENDPOINT: Roblox 429s on one
  endpoint** (`insight_up_429_endpoint_min_429s`, 20 by default). Change a value, press **Review**, check the
  before and after, add a reason if you like, and save; it is in force on every worker within a second and written
  to the audit log. The Settings page's history can put an old value back. One threshold is edited on the Engine
  settings card instead (CRED-PROBE-COST's **Credential self-checks per hour before warning**); its drawer shows the
  value with a link to that card.

Switch a rule off when its findings never help you. Switching it off also withdraws its proposals from auto-apply.

### Engine settings

The card first says in words:

- **Engine**: On ("Looks at Roxy's numbers every 30 seconds and right after a trigger") or Off.
- **Last evaluation**: when the leader last ran the rules, and "failed" if that run failed. "Not published yet" just
  after a start is normal (the leader reports its jobs every 30 seconds).
- **Auto-apply**: Off ("Nothing is applied without you"), or On with its limits.

Below that, the engine's settings (each one also on the [Settings](#settings) page; the full list of what each
setting does is in `docs/SETTINGS.md`):

- **Recommendation engine** (`insights_enabled`, on): turns rule evaluation on or off.
- **Auto-apply safe recommendations** (`insights_auto_apply`, off): lets Roxy apply some recommendations by itself;
  see the guardrails below.
- **Evaluation interval** (`insights_interval_s`, 30 seconds, 5 to 3,600): how often the rules run on a schedule.
- **Auto-applied changes per hour** (`auto_apply_max_per_hour`, 3, 0 to 20).
- **Largest automatic step** (`auto_apply_max_step_pct`, 50%, 5 to 200; above 100 is a high-risk value).
- **Rollback threshold** (`auto_apply_rollback_threshold_pct`, 20%, 5 to 100; above 50 is a high-risk value).
- **Watch window after an automatic change** (`auto_apply_watch_minutes`, 30 minutes, 5 to 240).
- **Quiet period after dismissing** (`dismiss_cooldown_days`, 7 days, 0 to 365).
- **Recommendation expiry** (`recommendation_expiry_days`, 7 days, 1 to 90).
- **Credential self-checks per hour before warning** (`insight_cred_probe_cost_max_per_hour`, 6, 1 to 60): the
  threshold of the CRED-PROBE-COST rule. At default settings Roxy makes 2 or 3 such calls an hour.

#### Auto-apply and its guardrails

Auto-apply is **off by default**, and the runbook's advice is to keep it off until the recommendations have proved
themselves to you. When you switch it on (`insights_auto_apply`), the leader looks at the open recommendations
every evaluation interval and applies one by itself only when every guardrail holds:

- Its rule allows auto-apply (one of the five rules above) and is switched on.
- It is marked **Safe to auto-apply**: every change touches one row only (one endpoint's cache rule or pacing
  bucket, one client), and a new rule covers exactly one endpoint. A global setting is never applied automatically.
- Its risk is **low**, and the rules evaluated it within the last two evaluation intervals (a stale card waits).
- It never touches the endpoint policy, a bypass entry, a manual step, an admin security or credential setting,
  the rotator quota, or the engine's own settings, and never bans more than one address.
- No number moves by more than the **Largest automatic step** (50% by default) in one change: a cache time of 300
  seconds can move to at most 450 or down to 150. A change that creates a new rule is measured from the value the
  endpoint has today (the cache rule that covers it now, or `cache_ttl_seconds`; 0 while the cache is off); when Roxy
  cannot tell that value, the change is not applied automatically.
- The live value is still the one the rule judged; if you edited it since, nothing is applied and the next
  evaluation proposes from your value.
- At most **Auto-applied changes per hour** (3 by default) changes in any rolling hour, across all workers.

Every automatic change is watched for **Watch window after an automatic change** (30 minutes by default). Roxy
compares four guard numbers after the change with the same length of time just before it: the error rate, the
Roblox 429 rate, the p95 latency and the refused rate. If any of them gets worse by more than the **Rollback
threshold** (20% by default), or a rate that was zero is not any more, Roxy puts the old values back by itself
(state **Rolled back**, History "Rolled back automatically") and sends the alert "Roxy: auto-applied change rolled
back". If that rollback has to wait (another action holds the recommendation), the drawer shows "Rollback pending"
and Roxy tries again every minute. If it is refused for good, usually because someone changed the same row during
the window, the change stays in place, the drawer shows "Rollback refused", and Roxy sends the critical alert "Roxy:
auto-applied change could not be rolled back": open the recommendation and undo or adjust it by hand. See
[Auto-applied change rolled back](/admin/help/runbooks#auto-applied-change-rolled-back).

A change you apply yourself is watched for the same time, but Roxy never rolls it back on its own.

### Dry-run samples

The samples a preview replays. The card says in words how much is kept ("Roxy keeps 100% of requests as samples for
24 hours"), and holds three settings:

- **Request sampling rate** (`request_sample_pct`, 100%, 0 to 100): the share of proxied requests recorded as one
  small row each. Lower saves disk; previews then scale their counts up and say so. At 0 nothing is recorded, so
  previews have nothing to replay and the cache time tuner (CACHE-TTL-TUNE) has nothing to measure.
- **Request sample history** (`request_sample_hours`, 24 hours, 1 to 168): how far back a preview can replay.
- **Request sample row limit** (`request_sample_max_rows`, 3,000,000, 10,000 to 50,000,000): a hard cap; the oldest
  rows go first. Above 20,000,000 is a high-risk value (more than 3 GB of disk).

The same three settings also appear on the Data page's Retention card.

### On a phone

- The tables show each row as a card with its key columns (the list: title, severity and state; the rules: rule,
  detects, on and open); tap a row for its drawer.
- The drawer takes the whole screen; the Preview, Apply, Undo, Snooze and Dismiss buttons stretch across their row
  and are tall enough for a thumb, and the change tables keep half the width for what changes so a setting key fits
  on one line.
- The facts in the drawer (times, evidence window, dry run numbers) and the Engine card's Engine, Last evaluation
  and Auto-apply lines sit in one column.

## Traffic

The Traffic page (`/admin/traffic`) shows how much traffic Roxy handles, how each request ended, how fast it was
answered and how all of that changes from week to week. Its numbers come from the same functions as the admin API
routes under `/admin/api/v1/traffic` (for example `GET /admin/api/v1/traffic/requests`), so the page, the API and an
export always agree.

Words this chapter uses often (upstream calls and the three egress paths are explained in
[How Roxy stays under Roblox's limits](#how-roxy-stays-under-robloxs-limits)):

- A [caller](/admin/help#term-caller) is whoever sends a request to Roxy, usually one of your game servers.
- Every request ends with one **outcome**. **Served by Roblox**: Roxy called Roblox and passed the answer on.
  **Served from the cache**: Roblox never saw the request (a [hit](/admin/help#term-hit), or a fetch shared with
  other callers, called [coalescing](/admin/help#term-coalescing)). **Refused**: Roxy's own protection turned the
  caller away (a [refusal](/admin/help#term-refusal)). **Failed**: Roxy tried and could not answer (a Roblox error, a
  timeout, a [cooldown](/admin/help#term-cooldown)).

**When to use this page**

- You want to know whether traffic is growing, shrinking or behaving oddly (a spike, or a quiet hour that should be
  busy).
- An alert or a health check says Roblox is rate limiting Roxy, or that callers get server errors: the Status codes
  card shows who returned those codes.
- Answers feel slow: the Latency card shows how slow, and for which method, outcome, egress or Roblox host.
- You plan a maintenance window or a deploy: the Busiest hours card shows your quiet hours.
- You want the big picture: Trends compares the last week, month and year with the one before.

### Time range on this page

The time range, the comparison, the charts and the tables work as on every page (see
[How every dashboard page works](#how-every-dashboard-page-works)). On this page:

- Every card except Trends covers the time range. With a comparison chosen, the charts draw the earlier period as
  dashed lines; the tables and the busiest hours grid do not compare.
- The numbers are read when the page loads; they do not update by themselves, not even in the Live range. Reload the
  page to see newer ones. The Requests over time card comes with the page; each other card loads when you scroll
  down to it ("Loading ..." shows until then).
- This page has no settings of its own.

### Requests over time

Every request callers sent in the range, stacked by outcome. Use it first: it tells you whether there is traffic, and
how it ended.

Above the chart, the totals of the range:

| Number | What it counts |
|---|---|
| Requests | Every proxy request a caller sent to Roxy, whatever happened to it. |
| Served by Roblox | Requests answered with a fresh response from Roblox. |
| Served from the cache | Requests answered from Roxy's cache, fresh or [stale](/admin/help#term-stale), including callers that shared another caller's fetch. |
| Refused by Roxy | Requests Roxy turned away on purpose: limits, bans, filters, blocks, a pause. |
| Failed | Requests Roxy tried to serve but could not: Roblox errors, timeouts, cooldowns, a used-up deadline. |

Each outcome also shows its share of all requests. The totals are added up from the chart's own points, so they
always match the chart. In the chart each band is one outcome and the top edge is every request.

Two buttons sit in the card's header:

- **Last 60 minutes** switches the page to the 1 hour range (v1's traffic chart).
- **Reset** deletes the traffic numbers (see [Resetting the traffic or latency
  numbers](#resetting-the-traffic-or-latency-numbers)).

What normal looks like: most requests are served from the cache or by Roblox, refusals are few and steady, failures
stay near zero, and the shape follows your players' day.

What to do when it looks wrong:

- **Failed grows.** Read the Status codes card below to see who returned the errors, then the [Upstream](#upstream)
  page for cooldowns and breakers. Runbooks: [Caller errors](/admin/help/runbooks#caller-errors) and
  [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).
- **Refused jumps.** Someone may be flooding Roxy, or a limit may be too tight for a real game. Open the
  [Protection](#protection) page's refusals by reason (`/admin/protection#refusals`) and the [Clients](#clients)
  page. Runbook: [Under attack](/admin/help/runbooks#under-attack).
- **Served from the cache shrinks while requests stay the same.** The cache stopped helping. Open the [Cache](#cache)
  page. Runbook: [Cache not working](/admin/help/runbooks#cache-not-working).
- **Everything drops to zero.** Callers stopped, Roxy is paused (the top bar shows it), or the service is down.
  Runbook: [Service down](/admin/help/runbooks#service-down).

### Bytes in and out

How many bytes moved between callers and Roxy, and between Roxy and Roblox. The chart draws five lines over time;
beside it (under it on a narrow screen) are two small tables.

| Line or row | What it counts |
|---|---|
| Bytes from callers | Request bytes Roxy received for proxy requests. |
| Bytes to callers | Response bytes Roxy sent back to callers, from Roblox or from the cache. |
| Bytes from Roblox | Bytes Roxy read from Roblox for caller traffic. |
| Bytes to Roblox | Bytes Roxy wrote to Roblox for caller traffic. |
| Bytes served from cache | Response bytes delivered to callers from the cache. |

"Totals in this range" sums those five. "On the wire, per egress path" counts every byte that crossed the wire for
each egress, connection overhead included, so it does not match the Roblox lines exactly:

- **Direct (the server's own address)**: anonymous calls from the server.
- **Credential (direct, with the Roblox account)**: calls that carried the [credential](/admin/help#term-credential).
- **Rotator (DataImpulse, paid per byte)**: calls through the [rotator](/admin/help#term-rotator).

"No calls to Roblox in this range." means no egress was used.

What normal looks like: bytes to callers are usually larger than bytes from Roblox, because the cache hands out one
copy many times. The credential row carries the endpoints the [Endpoint policy](#endpoint-policy) sends with Roxy's
account, plus Roxy's own checks; it is paced by the credential bucket, so it never grows faster than that.

What to do when it looks wrong:

- **Rotator bytes grow.** They cost money. Check the budget on the [Egress](#egress) page (`/admin/egress#budget`).
  Runbook: [Rotator down or quota exhausted](/admin/help/runbooks#rotator-down-or-quota-exhausted).
- **Credential bytes grow.** More caller traffic goes out with the Roblox account. Check which endpoints the
  [Endpoint policy](#endpoint-policy) page (`/admin/policy#endpoints`) sends with it, and the account's pace on the
  [Credential](#credential) page.
- **Bytes from callers jump while requests do not.** Callers send large bodies. The By verb card and the [Live](#live)
  page show which requests.

### By verb

Requests per HTTP method (GET, POST and so on), the "verb" of a request. HEAD requests are counted as GET, because
Roxy runs them as GET.

- **Requests per method**: one line per method over time (at most ten).
- **Method mix**: each method's share of all requests, with its count.
- **Answered, refused and failed**: the share of requests answered (served by Roblox or from the cache), refused and
  failed. It is shown only when the whole table below fits on one page and no search is typed.
- **Counts by method** (the table): Method, Requests, Served by Roblox, Served from cache, Refused, Failed and p95
  (the Latency card below explains p95). The 2xx, 4xx and 5xx columns are hidden; the Columns menu shows them.

What normal looks like: GET for most read APIs, and POST for the batch endpoints your games call.

What to do when it looks wrong: a method your games never send (PUT, PATCH or DELETE, for example) with many requests
means someone else uses your proxy. Open the [Endpoints](#endpoints) page with its Method filter to find the
endpoint, then decide on the [Protection](#protection) page. A method with many failures or refusals: the same
filter shows which endpoints.

### Status codes

Which HTTP status codes callers received, and who produced them. This is where you tell **Roblox is rate limiting
Roxy** (act on it: the server's address and the account behind Roxy are at risk) from **Roxy is rate limiting
callers** (the system working). A 429 status means "too many requests".

Four tiles come first:

| Tile | Its line | What it counts | Its mark |
|---|---|---|---|
| Roblox 429s | Roblox rate limiting Roxy | Times Roblox answered one of Roxy's calls with 429, counted once per call. The number to keep near zero. | "Needs a look" (red) above 0, "None in this range" (green) at 0 |
| 429s from Roxy | Roxy turning callers away | Times Roxy itself answered 429: its own throttles and limits. | none |
| 5xx from Roblox | Roblox's own server errors, every attempt (retries included) | Every 5xx answer Roblox gave a call Roxy made for callers, once per call, as v1 counted them: a 5xx a retry or an older cached copy then hid from the caller still counts. Roxy's own checks are not counted. | "Seen in this range" (amber) above 0 |
| 5xx from Roxy | Roxy's own failures | Server errors Roxy produced: timeouts, connection errors, a used-up deadline, every route unavailable, internal errors, and 503 answers such as a pause. | "Needs a look" (red) above 0, "None in this range" (green) at 0 |

Under the tiles, a verdict sums them up:

- **Roblox is rate limiting Roxy**: it says how many times, and that this is the one to act on.
- **Only Roxy's own limits answered 429**: nothing to do upstream.
- **No rate limiting in this range.**

The **Chart** control switches the chart between:

- **By status class**: the answers callers got: "2xx answers to callers" (success), "4xx answers to callers"
  (client errors, from Roblox such as a 404 or from Roxy's refusals), "5xx answers to callers" (server errors), and
  the lines 429s from Roxy and 429s from Roblox. These count each caller request once, by the status it ended with;
  the Overview's "2xx, 4xx and 5xx from Roblox" tiles count Roblox's own answers per call instead, so the two can
  differ (a refusal is a 4xx answer to a caller but no answer from Roblox; a 503 a retry fixed is a 5xx from Roblox
  but a 2xx answer to the caller).
- **By who returned it**: every answer stacked by its source.

"Who returned it?" names the five sources:

| Source | Meaning |
|---|---|
| Roblox to caller | Roblox's own answer, passed to the caller as it came. |
| Roblox to caller (relayed) | Roblox's answer after Roxy reformatted it, or a Roblox server error passed on with Roxy's retry text after the allowed retries. |
| Roxy (its own answers) | Statuses Roxy produced: refusals, its own errors, pause, limits. |
| Cache to caller | Answers from Roxy's cache: Roblox never saw these requests. |
| Roxy's own calls | Roxy's own probes and lookups, not caller traffic. |

The table under it lists every pair of source and status code with its number of requests (columns Who returned it,
Status code, Requests; the raw Source name is a hidden column). Search it with "Search sources".

What normal looks like: Roblox 429s at 0, 5xx from Roxy at 0 (or only during a pause you started), a few 429s from
Roxy when some caller goes too fast.

What to do when it looks wrong:

- **Roblox 429s above 0.** Follow [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us). The
  [Endpoints](#endpoints) page shows which endpoint gets them, and the [Upstream](#upstream) page shows the 429
  timeline and the cooldowns. The H-429-RATE health check warns when Roblox 429s reach 0.5% of upstream calls in 15
  minutes, and fails at 2%; the alert "Roxy: Roblox is rate-limiting us" links to the same runbook.
- **5xx from Roxy above 0 (not a pause).** Open the [Live](#live) page filtered to 5xx and open a request: it says
  why. Runbooks: [Caller errors](/admin/help/runbooks#caller-errors), and
  [Unhandled errors](/admin/help/runbooks#unhandled-errors) when the reason is an internal error. The H-ERR-RATE
  check warns when 0.5% of caller requests were answered with a 5xx in 15 minutes (whoever produced it), and fails
  at 2%.
- **5xx from Roblox above 0.** Usually a Roblox outage: nothing to fix on Roxy, and the cache serves stale answers
  where it can. Runbook: [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).
- **Many 429s from Roxy.** Fine when they hit abusive callers; worrying when a real game is refused. The
  [Clients](#clients) and [Protection](#protection) pages show who and why.

### Latency

How long callers waited for their answers. [Latency](/admin/help#term-latency) here is the time Roxy took to answer,
Roblox's time and the queue wait included. It is measured per caller request, so Roxy's own probes are not part of it
(the note under the chart says the same).

It is shown as [percentiles](/admin/help#term-percentile):

- **p50**: half of the requests took at most this long.
- **p95**: 95 out of 100 requests took at most this long.
- **p99**: 99 out of 100 requests took at most this long: the slow tail.
- **Queue wait p95**: how long requests waited for a free slot before being sent to Roblox
  ([queue wait](/admin/help#term-queue-wait)). This is Roxy's own pacing, which keeps it under Roblox's limits.

The **Split** control:

| Choice | The chart shows |
|---|---|
| No split: p50, p95 and p99 | The three percentiles and the queue wait p95 over time. |
| By verb (HTTP method) | The p95 of each method. |
| By outcome (successes and failures) | The p95 of each outcome (v1's "successes and failures" toggle). |
| By egress path | The p95 of each egress. |
| By Roblox host | The p95 of each Roblox host. |

A split draws at most ten lines. The table under the chart follows the split (by verb when there is none), with
Requests, p50, p95, p99, Queue wait p95 and Failed per group. Group names are shown as Roxy records them, for
example `served_upstream` for "served by Roblox".

The card's **Reset** button empties only the latency numbers; the request counts stay (see below).

What normal looks like: answers from the cache are much faster than calls to Roblox, so p50 stays low while most
requests are hits; p95 and p99 follow Roblox. For requests that went to Roblox, the H-LATENCY health check passes
while their p95 over 15 minutes stays under 1,000 ms, and warns up to 2,500 ms. On this page, split by outcome and
read the `served_upstream` row for the closest number.

What to do when it looks wrong:

- **p95 of the `served_upstream` row is high.** Roblox is slow. Split by host to see which one, then open the
  [Upstream](#upstream) page. Runbook:
  [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).
- **Queue wait p95 rises.** Roxy's own speed limits (buckets) are holding requests back. The [Upstream](#upstream)
  page's Buckets and Queue cards, and the UP-QUEUE-SAT recommendation, say whether a limit can be raised safely.
- **One egress is much slower than the others.** Split by egress path to confirm, then watch those requests on the
  [Live](#live) page with its Egress filter.

### Busiest hours

A grid of the week: one row per weekday (Monday to Sunday) and one column per hour of the day (00 to 23). Darker
cells hold more. The sentence above the grid names the busiest hour, and the line under it says how many of each
weekday the range covered: each cell adds up that hour over all of them.

- **Measure** chooses what the cells count: Requests (the default), Caller demand (requests Roxy tried to answer,
  refusals left out), Upstream calls for callers, Served from cache, Refused or Failed.
- **Show numbers** turns the colors into the numbers (and **Show colors** back). Resting the pointer on a cell shows
  its exact value. The legend runs from Fewer to More and names the highest cell.
- The hours are in the dashboard time zone (the setting "Dashboard timezone", `ui_timezone`, under "For every admin"
  in the user menu's Preferences). Your own "Show times in this time zone" preference does not move them.
- A very long range uses only its most recent 4,999 hours, and a note says so.

Use it to plan: pause, deploy or test in the quiet hours. Refusals or failures that peak at hours when your players
are asleep point to scripts rather than games.

### Trends

The last 7, 30 and 365 days, each compared with the same length of time just before it. The top bar's range does not
apply here.

Three tables: **Week over week** (open), **Month over month** and **Year over year** (press a heading to open it).
Each heading names both stretches of time, for example "Oct 5, 2026 to Oct 12, 2026, compared with Sep 28, 2026 to
Oct 5, 2026".

Columns: Measure, This period, Before, Change and Trend (a small line of the measure over the period). The Change
column shows an arrow and the change in percent: green means better, red means worse, gray means the measure is
neither better nor worse when it moves (requests, for example). Instead of a change it can say "New in this period",
"No change (none in either)", "No earlier data", or a note that a reset touched the data (the period then lists the
resets it read).

The measures: Requests, Caller demand, Avoided upstream calls, Avoided upstream calls (percent), Upstream calls for
callers, Roblox 429s, Roblox 429s per 10,000 requests, 429s from Roxy, Caller 5xx, Errors hidden from callers,
Latency p95, Bytes to callers and Bytes from Roblox. Three need a word:

- **Avoided upstream calls** are caller requests Roblox never had to answer
  ([avoided upstream call](/admin/help#term-avoided-upstream-call)). The percent can be below 0%: then retries and
  background refreshes made more calls than callers sent, and the cell says how many calls per request.
- **Roblox 429s per 10,000 requests** lets a quiet week and a busy week be compared.
- **Errors hidden from callers** are requests where Roblox failed but Roxy still answered with an older cached copy.

What to watch: the avoided percent falling, and Roblox 429s, Caller 5xx or Latency p95 rising, week over week. Each
has its card above and its runbook. Errors hidden from callers rising means Roblox is failing more often and the
cache is covering for it.

### Resetting the traffic or latency numbers

Two buttons delete recorded numbers from this page:

| Button | Drawer title | What it deletes | Phrase to type |
|---|---|---|---|
| Reset (Requests over time) | Reset the traffic numbers | The request counters behind every Traffic chart and table, the endpoint, cache, upstream and latency numbers recorded with the same requests, and the counts of Roblox's answers behind the Overview's "2xx, 4xx and 5xx from Roblox" tiles (so the Overview and Endpoints pages lose them too). | `reset traffic` |
| Reset (Latency) | Reset the latency numbers | Only the latency and queue wait numbers. Request counts stay. | `reset latency` |

The traffic reset keeps Roxy's log of Roblox 429s, so the Roblox 429s tile of the Status codes card, the Roblox 429s
row of Trends and the Endpoints page's Roblox 429s column keep their numbers. That log belongs to the Upstream
family of numbers, which the Data page resets (see [Resets](#resets)).

The button opens a drawer that previews the reset before anything is deleted: how many rows of each table go and the
dates they cover, what is not affected (settings, rules, bans, users and the other families of numbers), and whether
a snapshot of metrics.db is taken first. To run it, write a reason (it is required and goes to the audit log) and
type the phrase; the button stays off until the text matches. No fresh second factor is asked for. Only one reset or
backup runs at a time: if another one is running, Roxy refuses and asks you to wait for it to finish. If nothing of
that kind is stored, the drawer says "Nothing to reset".

Afterwards the page reloads with the new numbers, every chart shows a marker at the moment of the reset, and the
Audit page has the entry with your reason. Undoing it is not a dashboard action: only the snapshot taken first can
bring the numbers back, by a restore on the server that also loses everything recorded after the reset (see
[Statistics resets](#statistics-resets)).

Reset rarely: for example after a load test you do not want in your history. Narrower resets, such as one date range,
are on the Data page (see [Resets](#resets)).

### On a phone

- The request totals sit two to a row, with Requests across the top.
- Each chart's side tables and meters move under the chart (below 1,100 pixels wide). Card controls fill the width
  and are large enough to tap.
- The tables keep these key columns: Method, Requests and Failed for Counts by method; Who returned it, Status code
  and Requests for the sources; the group, p95 and Requests for latency. Press the first value of a row to see every
  column in a panel.
- Trends hide the Before and Trend columns.
- The busiest hours grid scrolls sideways inside its own box; "Show numbers" works the same.

## Live

The Live page (`/admin/live`, keys `g` then `l`) shows requests as Roxy finishes them, from every
worker, within a second. You can filter the list, pause it, and open any request for its full record, its
[trace](/admin/help#term-trace) and, when it was captured, a redacted copy of what was sent and received.

Live records are kept for 15 minutes, and the top bar's time range does not change this page. For numbers over
longer periods use the [Traffic](#traffic) and [Endpoints](#endpoints) pages. For an older request, the Upstream
page's Request trace card (`/admin/upstream#trace`) can still find the Roblox 429s it met.

**When to use this page**

- You want to see what is happening right now: during a deploy, an incident or a game launch.
- A game developer sends you a [request id](/admin/help#term-request-id) (the `Roxy-Request-Id` header of an
  answer): open `/admin/live?request=<id>` within 15 minutes to see that request.
- You want to know why a request was refused or failed: the drawer says it in plain words.
- You need to see what a caller really sent and what came back (a capture).
- You want to watch one endpoint or one client for a while.

### Live requests (the list)

The list is titled "Requests as they finish". Next to the title, its state:

| State | Meaning |
|---|---|
| Connecting | The page is opening its live connection. |
| Live | New requests arrive on top. |
| Reconnecting | The connection dropped; it comes back by itself. |
| Signed out | Your session ended. Sign in again. |
| Paused | You pressed Pause (or P). |
| Paused while the pointer is over the list | The list holds still so a row does not move under the pointer. |

When the page opens, the newest recorded requests appear at once (up to 40), then new ones arrive on top. Your
browser keeps at most 1,000 rows; older ones drop off the bottom.

The note above the list says what to expect on a busy proxy: when more than 50 requests a second match your filters,
the list shows a sample of them, and each worker records at most 50 a second. The count next to the buttons adds what
it knows: "N rows", then "waiting" (held while paused), "dropped" (more than 1,000 waited), "left out (more than 50 a
second)", and "some missed while reconnecting".

Columns:

| Column | What it shows |
|---|---|
| Time | When the request finished. |
| Status | The status code the caller received, colored by class. |
| Outcome | Served by Roblox, Served from cache, Refused or Failed. Rest the pointer on it for the reason code. |
| Egress | direct, credential, rotator, or none when Roblox was not called. |
| Cache | The cache state (below). |
| Latency | How long Roxy took to answer, in milliseconds. |
| Client | The caller's address, with its place (Roblox-Id) in parentheses. |
| Endpoint | The method and the path. |

Cache states (the `Roxy-Cache` header callers receive):

| State | Meaning |
|---|---|
| HIT | Served from Roxy's saved copy; Roblox never heard about it. |
| MISS | Roxy asked Roblox, passed the answer on and kept a copy. |
| STALE | An expired copy, served because asking Roblox failed or was not allowed yet. |
| REVALIDATING | A saved copy served at once while a fresh one is fetched in the background. |
| COALESCED | Others asked for the same thing at the same moment; one call to Roblox answered them all. |
| OFF | Not cacheable, for example a write request, or caching is off. |
| n/a | The cache did not apply, for example a refusal. |

**Pause** (or the P key while the focus is inside the Live requests list, but not in a filter field) holds the list
still; new rows wait and the count says how many. The button then reads **Resume**, which adds them on top. Resting
the pointer on the list pauses it too, until the pointer leaves.

**Clear** empties the list in your browser only. Nothing is deleted on the server; for that, see
[Deleting the live records and captures](#deleting-the-live-records-and-captures).

Filters:

- **Outcome**: Any outcome, Served by Roblox, Served from cache, Refused by Roxy or Failed.
- **Reason**: Any reason, or one refusal or failure kind in words (v1's outcome filter).
- **Status**: Any status, 2xx, 3xx, 4xx, 429 only or 5xx.
- **Egress**: Any egress, Direct, Rotator, Credential or None.
- **Cache**: Any cache state, Hit, Miss, Stale, Revalidating, Coalesced or Off.
- **Client IP or place**: any part of the caller's address or place id.
- **Endpoint contains**: any part of the request's path or of its endpoint template, for example `/votes`,
  `games.roblox.com` or a whole template such as `games.roblox.com/v1/games/{universeId}/votes` (which the Endpoints
  page's **Watch it live** puts there).
- **User-Agent, query or path**: a text searched in those fields (and in the address, method, place, status and
  outcome), the same way the server searches.

Filters apply to the list at once and are also sent to the server (typed text after a short pause); your browser and
the server match a row the same way, so a row the server sends is never hidden by the page. The server's limit of 50
rows a second counts only rows that match, so on a busy proxy a narrow filter shows every matching request the
workers recorded, as long as fewer than 50 a second match. The workers' own limit of 50 a second each applies before
any filter, so some requests are never recorded at all.

Keyboard: move the focus into the list with Tab, then Up and Down move between rows, Page Up and Page Down jump ten,
Home and End go to the first and the last, Enter opens the row, and P pauses. Screen readers hear a short summary
such as "12 new requests" at most every 10 seconds, never every row.

The page address can carry filters, which is how other pages link here: `/admin/live?outcome=refused&status=4xx`
shows refused 4xx answers. The names are `outcome` (`served_upstream`, `served_cache`, `refused` or `failed`),
`reason` (a reason code), `status` (a class such as `4xx`, or one code such as `404`), `egress` (`direct`, `rotator`,
`credential` or `none`), `cache` (`HIT`, `MISS`, `STALE`, `REVALIDATING`, `COALESCED` or `OFF`, in either case),
`client`, `endpoint` and `q` (any text). A single value the select does not list (a status code such as `404`) is
applied and added to the select as "404 (from the address)". A select holds one value, so a comma list in the address
(`status=429,503`) is left out and a note says so; if a filter is not valid at all, none of them is applied and a
note says every request is shown. `?request=<id>` opens that request's drawer.

What normal looks like: a steady flow of 200 answers, mostly HIT or MISS, with an occasional refused 429 for a caller
that goes too fast.

What to do when it looks wrong:

- **Many Failed rows with 5xx.** Open a few: the drawer gives the reason. Runbook:
  [Caller errors](/admin/help/runbooks#caller-errors).
- **429 answers whose reason is `upstream_cooldown`.** Roblox asked Roxy to wait and Roxy is passing that on. Runbook:
  [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us).
- **Many refusals from one client.** Filter by that client, then act from the [Clients](#clients) or
  [Protection](#protection) page. Runbook: [Under attack](/admin/help/runbooks#under-attack).
- **Caller requests with the egress `credential`.** Normal for endpoints the [Endpoint policy](#endpoint-policy)
  sends with Roxy's account. One you did not expect: find it with that page's Tester.
- **The state stays on Reconnecting.** Reload the page. If the dashboard itself does not load, see
  [Service down](/admin/help/runbooks#service-down).

### The request drawer

Pressing a row (or Enter) opens one request in a drawer. The Endpoints page's request tables open the same drawer.

At the top, the method and the path, then its record:

| Field | What it shows |
|---|---|
| When | When it finished, and how long ago. |
| Request id | The `Roxy-Request-Id`, with **Copy**. |
| Status | What the caller received; "(Roblox answered 503)" when Roblox's status was different. |
| Outcome | The outcome and its reason code. |
| Refused because, or What happened | The reason code in plain words, for example "A cooldown was open for this endpoint (or its host or egress), so Roxy did not call Roblox and answered 429 with Retry-After." |
| Answered by | Roblox (its answer, passed on as it came); Roblox (relayed: reshaped by Roxy); Roxy (its own answer); Roxy's cache (Roblox never saw it); or Roxy's own call. |
| Egress | Direct, Credential, Rotator, or None (Roblox was not called). |
| Cache | The cache state and the age of the copy, or "not cacheable". |
| Attempts | Calls made to Roblox, with "+1 CSRF retry" when Roxy had to refresh a token. |
| Took | Total time, with "(waited ... ms for a slot)" when it queued. |
| Client | The caller's address, with a "Throttle bypass" badge when the address is on the bypass list ([bypass](/admin/help#term-bypass)). |
| Place (Roblox-Id), User-Agent, Query | As the caller sent them, with secrets removed (Query only when there was one). |
| Upstream error | What went wrong on the call to Roblox, when something did. |

**Open its endpoint** opens the template's detail page on the Endpoints page.

**Why did this request wait?** lists, in sentences, what Roxy can tell from what it keeps: the Roblox 429s it met,
the earlier 429 that opened a cooldown it ran into, how long it waited for a bucket slot, which of its buckets was
fullest that minute (inferred from that minute's history, and labeled so), retries after Roblox errors, and answers
that looked like a bot check or a web page. Full buckets are listed with their peak fill and how many requests they
refused. When no explanation is available, it says why; the trace needs the 26 character `Roxy-Request-Id`.

**Captured request and answer** shows the request headers, the request body, the answer headers and the answer body
as they were captured. Secrets and keys were removed when the copy was made. Bodies that are JSON are laid out to be
readable, and the drawer shows at most 20,000 characters of each. "Cut: only the first part ... was kept
(capture_max_body)" means the body was longer than the size limit.
Without a copy, it says which case it is:

- **Never captured**: capture was off, or the request was a served request outside the sample.
- **Capture expired**: the copy aged out (after "Capture lifetime") or was pushed out by the caps; the current
  capture window is shown. Once the request's live record is gone too (after 15 minutes), Roxy can no longer tell
  the two cases apart and always says "Capture expired".

When Roxy no longer has the request's live record (it is older than 15 minutes, or was left out while a worker was
busy), the drawer says "This request is no longer in the live records", and its trace may still find the Roblox 429s
it met.

The drawer shows client addresses and captured bodies, which can hold player names and ids. Secrets are removed;
player data is not.

### Capture

A [capture](/admin/help#term-capture) is a short-lived, redacted copy of a request and its answer, kept so you can
see exactly what a caller sent and what came back. This card says what capture keeps right now and holds its
settings.

The first line is either **Capture off**, or **Capturing** followed by how many captures exist out of the
"Captures kept" cap, their size out of the "Capture disk cap", and how long bodies are kept ("or until the caps are
reached, whichever comes first"). It also says Capture off when capture is on but "Captures kept", "Capture disk
cap" or "Capture lifetime" is 0, because then nothing can be kept. Under it:

| Line | What it shows |
|---|---|
| Captured now | How many captures exist and their size. |
| Window | When the oldest one was made, or "nothing captured yet". |
| What is captured | "Every refusal and failure", the share of served requests, and the body size limit. |
| Live records | Kept 15 minutes, at most 50 a second per worker. |
| This worker | How many recent requests this worker keeps in memory, and how many it left out of the records while busy. Each worker has its own count; this is the one that drew the card. |

The card refreshes itself now and then while the page is open (at most every 30 seconds).

Its settings sit in "Settings for this card", open on this card, in this order. One more, "Live view history per
worker", sits folded in the Live requests card's own "Settings for this card".

| Setting | Key | Default | What it changes |
|---|---|---|---|
| Request and response capture | `capture_enabled` | On | Whether captures are made at all. Off stores no caller payloads; the list still shows each request's summary. Medium risk. |
| Captured body size limit | `capture_max_body` | 16 KiB | The largest part of each body kept (up to 512 KiB); longer bodies are cut. 0 keeps no body text. |
| Capture disk cap | `capture_max_bytes` | 64 MiB | The disk space all captures may use together (up to 1 GiB); the oldest go first. 0 stores none. |
| Captures kept | `capture_max_records` | 2,000 | The most captures kept (up to 100,000); the oldest go first. 0 keeps none. |
| Served requests captured | `capture_sample_served_pct` | 20% | The share of served requests captured. Refusals and failures are always captured while capture is on. 0 captures only those. |
| Capture lifetime | `capture_ttl_seconds` | 15 minutes | How long a capture is kept (up to 24 hours), whatever the caps allow. 0 deletes captures at once. Medium risk; high risk above 1 hour. |
| Live view history per worker | `live_tail_buffer` | 500 | How many recent requests each worker keeps in memory (up to 5,000; 0 keeps none). |

They are changed like any setting on a card (see
[Changing a setting on a card](#changing-a-setting-on-a-card)). None of them asks for a fresh second factor or a
typed confirmation. A Capture lifetime above 1 hour is a high-risk value, so that save needs a reason and the tick.

`capture_max_records`, `capture_max_bytes` and `capture_ttl_seconds` are also on the [Data](#data) page's
Retention card, and `live_tail_buffer` is also on the [System](#system) page's Metrics pipeline card; every place
edits the same value.

What normal looks like: "Capturing", with the counts under the caps and a window close to the capture lifetime.

What to do:

- **The count sits at a cap and the window is much shorter than the lifetime.** Captures are pushed out early, and
  older rows show "Capture expired". Raise "Captures kept" or "Capture disk cap", or capture fewer served requests.
- **You do not want caller payloads on disk at all.** Turn capture off. The list and the drawer still work, without
  bodies.
- **You are chasing one rare problem.** Raise "Served requests captured" (100 captures every request) or the lifetime
  for a while, and set them back afterwards (History or Settings can revert the change). More captures mean more
  caller data on disk, and a lifetime above 1 hour counts as high risk.

### Deleting the live records and captures

**Delete the records**, on the Live requests card, opens "Clear the live feed and the captures". It deletes the live
records of the last 15 minutes and every captured request and answer. Requests keep arriving, so the list fills
again at once.

The drawer previews the rows first and says whether a snapshot of metrics.db is taken. Write a reason (required) and
type `reset live`; no fresh second factor is asked for. It is written to the audit log. Undoing it works as for any
statistics reset (see [Statistics resets](#statistics-resets)), and a restored snapshot brings the deleted captures
back too.

Use it when captures hold data you want gone now, for example after debugging a game with player data in its
requests. Keep in mind that the snapshot taken first (when the drawer says one is taken) still holds those captures
on the server until it ages out after "Safety snapshot retention" (7 days by default). To clear only your screen,
use **Clear** instead.

### On a phone

- The filters sit two to a row with their labels hidden (the first choice names the filter, such as "Any outcome"),
  and the text fields take the full width. Every control is large enough to tap.
- Each row shows the time, the status and the endpoint. Tap a row for the rest (outcome, egress, cache, latency and
  client) in the drawer.
- Use the Pause button to hold the list; there is no pointer to rest on it.
- The drawer's fields stack in one column.

## Upstream

The Upstream page (`/admin/upstream`, keys `g` then `u`) shows how Roblox is answering Roxy and the pacing that keeps
Roxy under Roblox's limits. Its numbers come from the same functions as the admin API routes under
`/admin/api/v1/upstream`, so the page, the API and an export always agree. The chapter
[How Roxy stays under Roblox's limits](#how-roxy-stays-under-robloxs-limits) explains the parts this page shows;
read it once before you change anything here.

Two buttons sit at the top of the page: **Look up a request** jumps to the Request trace card, and **Egress** opens
the Egress page. The "How to read this page" panel names the key words, each linked to the glossary. Most cards end
with their settings, changed as on every card (see
[Changing a setting on a card](#changing-a-setting-on-a-card)); each section below names them.

**When to use this page**

- The alert "Roxy: Roblox is rate-limiting us (<rate>%)" arrived (it fires when more than 2 percent of upstream
  calls, and at least 5, got a 429 in the last 10 minutes), or the health check H-429-RATE warns. Start with the
  Roblox 429s card and follow the runbook
  [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us).
- Callers get 429 "All request methods are busy right now; please try again shortly." or slow answers: the Buckets,
  Queue and Latency percentiles cards tell Roxy's own pacing apart from a slow Roblox.
- One request was slow or failed and you have its `Roxy-Request-Id`: paste it into the Request trace.
- The health checks H-LATENCY or H-REACH-<host> warn, or callers get 5xx answers: Latency percentiles, Hosts and
  Request failures, then the runbook
  [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).
- You want to change pacing or routing: rate overrides on Buckets, routing rules on Routing, the host allowlist on
  Hosts.

### Time range on this page

The time range, the comparison and the charts work as on every page (see
[How every dashboard page works](#how-every-dashboard-page-works)). On this page:

- **Follow the time range:** the numbers of Egress and host health, Roblox 429s, Latency percentiles, the
  Reservations, Refused and Peak fill columns of Buckets and its list of adaptive changes, Request failures, Hosts,
  Retries, Internal calls, and Challenges and HTML answers.
- **Always "now":** the fill gauges and the Fill and Next free slot columns of Buckets, the rate overrides,
  Cooldowns, Breakers, Routing, Queue and Concurrency. "Last success" and "Last error" look at everything Roxy
  still keeps, not only the range.
- **Comparison:** the Latency percentiles chart draws the comparison period as dashed lines, and the Roblox 429s
  chart draws the earlier period's total as one dashed line over its stacked bars.

Most cards load a moment after the page (they show a placeholder first). Egress and host health refreshes itself
when a breaker or cooldown changes (at most every 15 s); Cooldowns and Breakers refresh on those events too (at most
every 5 s).

### Egress and host health

One panel per egress, in this order: **Direct**, **Rotator**, **Credential**. Each starts with a short state badge
and a sentence:

| Badge | Meaning |
|---|---|
| Working | Calls go out and Roblox answers. |
| Idle | Ready, but no call went out this way in this range (normal for the rotator at weight 0). |
| Off | Not in use, with the reason: switched off by a setting, no rotator URL set (or the stored one cannot be read or is not valid), the rotator parked after a failure streak, its monthly budget stop or daily cap reached, no credential loaded, the credential not checked yet, rejected or cooling down. |
| Cooling down | Roblox asked Roxy to slow down on some endpoints; they rest until the cooldown ends. |
| Partly paused | Some endpoints are paused because their circuit breaker is open. |
| Stopped | The leak guard stopped it: an anonymous call would have carried the credential. |

Then the numbers for the range:

- **Calls to Roblox**, with calls a minute and how many Roxy made for itself (checks and lookups).
- **Roblox 429s**, with their share of the calls.
- **Roblox 5xx**, with their share of the calls ("of calls, every attempt": each 5xx Roblox answered, retries
  included).
- **Failed requests**, with their share and how many were timeouts.
- **Latency p50 / p95 / p99**: half, 95 percent and 99 percent of requests were answered within these times
  ([percentile](/admin/help#term-percentile)); the queue wait is included.
- **Queue wait p95**: how long requests waited for a bucket slot ([queue wait](/admin/help#term-queue-wait)).
- **Challenge or HTML answers**: answers that were a bot check, then answers that were a web page instead of data.
- **Paused now**: cooldowns and open breakers on this egress right now.
- A **fill gauge** for the egress's own bucket, with its rate, its burst and how long the next call would wait.
- **Last success** and **Last error**: the start of the newest minute (or hour, or day, as noted: older history is
  kept at a coarser grain) with a request Roblox answered, or one that failed. "The last recorded failure" opens
  the newest failure: when, why, the statuses, the endpoint, the request and the error text.

What normal looks like: Direct "Working" with no 429s or well under 0.5 percent of its calls, almost no 5xx or
failures, p95 under one second, a queue wait p95 near 0, no challenge or HTML answers, nothing paused, and the gauge
at "room to spare". The rotator "Idle" (or "Off" because no URL is set). The credential "Working", with every one of
its calls made by Roxy itself, because callers never get the credential (owner decision D1).

What is worrying, and what to do:

- **Stopped** on any panel: treat it as a security incident and follow the runbook
  [Leak guard](/admin/help/runbooks#leak-guard). The Leak guard card of the Egress page has the details.
- **Roblox 429s at 0.5 percent of calls or more** (the health check H-429-RATE warns from 0.5 and fails from 2
  percent): read the Roblox 429s card, then the runbook
  [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us).
- **Direct "Off"** and the rotator off too: nothing can reach Roblox; follow
  [All upstream paths unavailable](/admin/help/runbooks#all-upstream-paths-unavailable).
- **Failures, timeouts or a p95 above one second** (H-LATENCY warns from 1,000 ms and fails from 2,500 ms): Request
  failures and Hosts say where; then [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).
- **Credential calls growing fast**: more caller traffic to endpoints sent with Roxy's account; check the
  Endpoint policy page and the Credential page's Budget.
- **Challenge or HTML answers above 0**: see the Challenges and HTML answers card.
- **The gauge at "busy" or "full" most of the time**: callers wait for slots; see Buckets and Queue.

### Roblox 429s

When and where Roblox said "too many requests" in the range. The subtitle gives the total. The chart stacks the 429s
of each time step by endpoint, one color for each of the 10 endpoints with the most 429s and one for "Other
endpoints". With a comparison chosen, the earlier period's total is drawn as a dashed line of its own (the earlier
period's top endpoints differ, so it is not split by endpoint); its legend entry shows and hides it, and the data
table lists it. Below it, **Endpoints with the most 429s** lists those endpoints with their counts. Every Roblox 429
is logged, so these numbers are exact.

- **Normal:** "No 429s from Roblox in this range. Good." or a few isolated bars.
- **Worrying:** a steady stream on one endpoint (the recommendation UP-429-ENDPOINT looks for this), 429s spread over
  many endpoints of one host (UP-429-HOST), or 429s that keep coming back right after each cooldown.
- **What to do:** open [Recommendations](#recommendations) and preview what they propose; give a hot endpoint a longer
  cache lifetime on the Cache page; lower its rate on the Buckets card if the adaptive controller has not already.
  Do not clear the cooldowns to make 429s go away: a cooldown is Roblox telling Roxy to wait. The runbook
  [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us) has the full list.

### Latency percentiles

How long requests that went to Roblox took (served or failed), per time step: lines for p50, p95 and p99, and one for
the p95 **queue wait**, the part spent waiting for a bucket slot. The times are what the caller felt: the queue wait
plus every attempt. With a comparison chosen, the earlier period is drawn dashed.

- **Normal:** p95 under one second; the queue wait line near 0.
- **Worrying:** p95 above one second for a while. Look at the queue wait line first. If it makes up most of the
  time, Roxy's own pacing is the cause (the Buckets card shows which bucket is full; the recommendation UP-QUEUE-SAT
  looks at this). If it stays near 0, Roblox itself is slow (UP-LATENCY; the Hosts card says which host); follow
  [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).

### Request trace

"Why did this request wait?" for one request. Paste a **Request id** (the `Roxy-Request-Id` header of the answer the
game received, 26 characters; the [Live](#live) page shows it too) and press **Explain**. The answer:

- **What happened:** a numbered list of plain sentences, for example a cooldown opened by an earlier 429, a full
  bucket, a retry after a Roblox error, a CSRF round trip, a single flight it followed, or a cached answer. Roxy does
  not store a step by step record of every request, so this is inferred from what it keeps, and the card says so.
- **The facts**, when the request is still in the live records: when, the method and URL, the answer (and what
  Roblox answered), the outcome and its reason, the egress and the cache state, the time taken and how much of it
  was spent waiting for a slot, and the attempts.
- **Buckets that were full in that minute (inferred)**, with their peak fill and refused reservations.
- **Roblox 429s this request met**, and **The 429s that opened the cooldown** it ran into, each with its endpoint,
  egress and `Retry-After`.
- While a capture of the request is still kept, a note that sends you to the Live page to open it; and a link to
  this explanation to share.

Live records last 15 minutes (sampled above 50 requests a second per worker) and Roblox 429s are kept for 90 days.
For an older request, or one that never reached Roxy, the card says "Nothing is kept for this request"; when only the
429 log still has it, the card says the Live record is gone and how many 429s Roblox gave it. A value that is not a
request id is refused with "A request id is the 26 character Roxy-Request-Id value."

### Buckets

Roxy's own speed limits and how full they are. The subtitle is a reminder: buckets are never refilled by hand; the
reset on the Cooldowns card clears cooldowns and breakers only.

**Gauges.** One fill gauge each for **Global (every call)**, **Direct**, **Rotator**, **Credential** and
**Credential probes (reserved)**, with the rate, the burst and, when there were any, the reservations refused in the
range. A gauge appears once its bucket has been used.

**The bucket table.** Every bucket used now or in the range. By default it shows:

- **Bucket**: the key, `global`, `egress:<egress>`, `host:<host>` or `endpoint:<template>` (an endpoint's key holds
  its template in lower case: one bucket for every letter case of the endpoint).
- **Kind**: global, egress, host or endpoint.
- **Fill**: how much of the burst is booked now (100 means the next call waits).
- **Rate**: the configured rate.
- **Rate from**: `setting`, or who set the override (`admin`, `recommendation`, `adaptive`).
- **Refused**: reservations refused in the range because the wait would have been too long. Each one is a request
  that could not wait for its slot (a caller then got a "busy" 429 or an older copy).
- **Peak fill**: the fullest the bucket was in any minute of the range.

The column chooser adds **Next free slot**, **Burst** and **Reservations**. The table can be searched, sorted, paged
and exported (CSV or JSON). It is sorted by Fill, fullest first.

**A bucket's drawer.** Press a row. The drawer shows the kind, what it applies to, its rate, burst and where the rate
comes from, its reservations and refusals in the range, a "Fill now" gauge, and a chart of the bucket over time
(reservations, refused, peak fill). For a host or endpoint bucket it has a form: **Give it its own rate** (or
**Change its override** when it has one) with Rate (calls a minute), Burst, Note and an optional Reason, saved with
**Save the rate**; and **Back to the default rate** when an override exists. Saving a new rate or burst makes the
override yours ("Set by" admin), even when the adaptive controller had set it, so the controller never raises it
again. For the global and egress buckets the drawer names the settings their rate and burst come from, by label and
key, and links the card that edits them: the Buckets card for global, direct and the rotator, the Credential page's
Budget card for the two credential buckets. It also says how each credential bucket is made: the bucket of the
caller requests sent with the account runs at the credential rate limit minus the reserve, with the credential burst
minus 1; Roxy's own checks run at the reserve, with a burst of 1.

**Adaptive rate controller.** An On or Off badge (`adaptive_rate_enabled`), one sentence on how it works, how many
rates it holds now, and its changes in the range, newest first: When, Change (**Lowered** or **Raised**), Bucket, Rate
(old to new) and Why (for example "61 calls went out in the minute before the 429, cut from the rate Roxy really
sent at"). Only the newest changes are listed.

**Rate overrides.** The hosts and endpoints with a rate of their own. The sentence above the table gives the
defaults (240 a minute, burst 15 for a host; 120 a minute, burst 10 for an endpoint). Columns: Bucket, Rate, Burst,
Default rate, **Set by** (admin, recommendation, adaptive or default) and Updated; the column chooser adds Note and
Updated by. A rate you set is never raised by the adaptive controller; it may still lower it after a 429. Press a
row for the bucket's drawer.

**Add a rate override** opens a form: Bucket (`host:<host>` for a whole Roblox service, or `endpoint:<template>` for
one endpoint; copy a key from the table), Rate (calls a minute), Burst (calls at once), Note and an optional Reason.
**Add override** saves it; every worker uses it within a second. An endpoint override is stored under the template in
lower case, so it applies to the endpoint whatever letter case callers use.

Actions and how to undo them:

| Action | Second factor | Undo |
|---|---|---|
| Add override, Save the rate | not needed; audited | edit it again, or Back to the default rate |
| Back to the default rate (dialog "Remove this rate override?", optional reason) | not needed; audited | add the override again (the audit log keeps the old values) |

Removing an override that the adaptive controller set after a 429 may earn another 429 until Roxy learns the limit
again; the dialog says so.

What to look for:

- **Normal:** Refused 0 or close to it; Peak fill under 70 percent most of the time; few overrides.
- **An endpoint or host bucket with many refusals and no 429s:** callers want more than its limit and Roblox has not
  complained. Prefer a longer cache lifetime for it (the Cache page); otherwise give it a higher rate a little at a
  time. The recommendation UP-BUCKET-TUNE suggests such changes with evidence.
- **The global or direct gauge "full" often:** the whole server is busy. Look at the cache hit ratio first; raising
  `global_bucket_per_min` or `direct_bucket_per_min` sends more calls from one address and risks 429s on many
  endpoints at once (both are high risk above 1,200 and 600).
- **A bucket with 429s:** keep its rate low; the adaptive controller already lowered it.

Settings for this card: Adaptive per-endpoint rate, Adaptive cut after a 429, Adaptive raise after a clean period,
Clean hours before a raise, Adaptive floor and Adaptive ceiling (`adaptive_rate_enabled`, `adaptive_decrease_pct`,
`adaptive_increase_pct`, `adaptive_probe_after_h`, `adaptive_min_per_min`, `adaptive_max_per_min`); Global upstream
rate and burst, Direct path rate and burst, Rotator rate and burst, Default rate and burst per Roblox host, Default
rate and burst per endpoint (the `*_bucket_*` keys in the
[table of defaults](#how-roxy-stays-under-robloxs-limits)). The credential's buckets are set on the Credential page.

### Cooldowns

What is resting now after Roblox said "too many requests". The subtitle counts the open cooldowns. Columns:

- **Paused**: what rests, its kind (endpoint, host, egress, credential) and its endpoint or host. A cooldown covers
  every letter case of its endpoint (the key is the template in lower case). The rotator's pause after a failure
  streak is listed here too (kind `rotator_park`, "the rotator (failure streak)", why "the rotator's failure streak
  (parked after rotator_max_failures failures in a row)").
- **Egress**: which path (a cooldown covers one egress).
- **Why**: what set its length: "Roblox's Retry-After", "Roblox's rate limit headers", "a circuit breaker", or "no
  Retry-After (the default)".
- **Ends**: a countdown until calls go out again.
- **429s**: the Roblox 429 answers that fed it.

**Held by this worker only** appears when the shared database could not be written for a moment: those cooldowns
are kept in one worker's memory, honored there, and shared once the database can be written again.

- **Normal:** "No cooldowns are open", or a few short ones that end on their own.
- **Worrying:** many at once, cooldowns near 600 s (the 429s keep repeating), a host or egress cooldown (Roblox is
  limiting the whole service or the address), or a `credential` cooldown.
- **What to do:** usually wait; Roxy already answers from the cache where it can. Then find why Roblox complained
  (the Roblox 429s card and [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us)). For the
  credential, see [Credential cooling down](/admin/help/runbooks#credential-cooling-down).

Settings for this card: Default cooldown after a 429 (`cooldown_default_s`, 30 s), Shortest cooldown
(`cooldown_min_s`, 1 s), Longest cooldown (`cooldown_max_s`, 600 s), Endpoints that escalate to a host cooldown
(`cooldown_host_escalation_endpoints`, 3), Host escalation window (`cooldown_host_escalation_window_s`, 60 s) and
Credential rest after a 429 (`credential_cooldown_default_s`, 60 s; it needs a fresh second factor, like every
credential setting). Retry wait, starting value and longest value are shown here but edited on the Retries card.

### Breakers

Endpoints and hosts Roxy stopped calling, or is watching, because calls failed. The subtitle counts them by state.
Columns: **Covers** (the kind and the endpoint or host), **Egress**, **State**, **Failures** (counted in the current
window) and **Test call in** (a countdown for an open breaker).

| State | Meaning |
|---|---|
| Counting | Calls flow; failures are being counted. |
| Open | No calls until the test call. |
| Half-open | One test call decides whether it closes or opens again. |

The rotator's failure streak is stored the same way, so it can also appear here as a row of kind `rotator_streak`
on the Rotator egress. It always reads "Counting": it only counts failures in a row, and the pause it causes is the
`rotator_park` row of the Cooldowns card. The Egress page's Sessions card explains it in words.

- **Normal:** "Every breaker is closed", or a few "Counting" rows with low failure counts.
- **Worrying:** breakers that open again and again (the recommendation UP-BREAKER-FLAP looks for this), or many open
  breakers on one host. Check Request failures and Hosts for the cause, and
  [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).

Settings for this card: Breaker failure count (`breaker_failure_threshold`, 5), Breaker failure share
(`breaker_failure_ratio`, 0.5), Breaker window (`breaker_window_s`, 30 s) and Breaker open time (`breaker_open_s`,
30 s).

### Clearing cooldowns and breakers

Both cards above carry the same button, **Clear cooldowns and breakers**. Its dialog, "Clear every cooldown and
breaker?", lists the consequences: every open cooldown and breaker ends at once on every worker, so Roxy may call
endpoints Roblox recently refused; the cache's per-request 429 memory ends with them (`cache_negative_429`), so a
request Roblox refused with a 429 can reach Roblox again; the credential's rest after a 429 and the rotator's park
are cooldowns too and end as well, so the next credential check may call Roblox with the account at once; buckets are
not refilled, so Roxy keeps its normal pace; if Roblox still limits an endpoint, the next 429 opens its cooldown
again. A reason is required. It needs no second factor. The reset and the exact counts cleared (cooldowns, breakers
and 429 markers) go to the audit log, with a marker on the charts.

The rotator's failure streak and its record of rate-limited exits are stored the same way, so this ends them too.
There is no undo: a cooldown comes back only with Roblox's next 429.

Use it rarely: after you fixed what made calls fail (a wrong setting, a network problem on the server), not to make
429s go away. The runbooks advise against it for 429s.

### Request failures

v1's "Request Failures" log, the page's main table: calls to Roblox that failed in the range. The line above it gives
the total, through every egress or the one chosen with the **Egress** filter (Every egress, Direct, Rotator,
Credential). The filter, the search, the sort and the page are kept in the address bar, so a copied link opens the
same view.

One row per group of failures with the same egress, reason and Roblox status. By default it shows **Egress**,
**Reason** (for example `upstream_5xx`, `upstream_timeout`, `upstream_connect`), **Roblox status** (empty when Roblox
never answered), **Count**, **Last seen**, **Last status** (what the caller got), **Last path** and **Last detail**
(Roblox's status line or the connection error). The column chooser adds **Folded** (failures counted while Roxy was
too busy to record each one; they keep no egress, path or error and show as "Folded"), **First seen**, **Last
method** and **Last endpoint**. Press a row to see all of its columns. Export downloads CSV or JSON. Only the 1,000
largest groups are listed; the card says so when the range holds more.

- **Normal:** "No failed requests in this range", or a handful.
- **Worrying:** a group that keeps growing, many timeouts or connection errors (the network or Roblox is down), or
  5xx on one endpoint. Follow [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable) or,
  when callers are the ones seeing errors, [Caller errors](/admin/help/runbooks#caller-errors).

### Hosts

The same health per Roblox host, and which hosts Roxy may call at all.

The line above the table says whether the host allowlist is **Strict** (Roxy calls only the hosts in
`allowed_roblox_hosts`, 33 by default; a request for any other host is answered 404 "Not a Roblox URL") or **Open**
(any `*.roblox.com` host, which widens what a caller can reach).

The table shows by default **Host**, **Calls** (Roxy's own calls included), **Roblox 429s**, **429 rate**, **5xx
rate** (Roblox's 5xx answers per 100 calls to the host, every attempt counted), **p95**, **Bucket fill** and **Last
success**. The column chooser adds Calls per minute, Roblox 5xx (the 5xx answers Roblox gave calls to this host for
callers, retries included), Timeouts, Failed, p50, p99, Rate limit (the host bucket's rate), Last error and Last error
detail. It is sorted by Calls; search, sort, page and export work as on every table.

- **Normal:** a 429 rate of 0 percent, little 5xx, a low bucket fill.
- **Worrying:** a 429 rate above 0.5 percent on one host, or a host whose Last success is old while callers still ask
  for it. A real host your callers need but the list lacks shows up as the recommendation HOST-ADD.

Settings for this card: Strict Roblox host allowlist (`strict_host_allowlist`, on; high risk: turning it off makes
every roblox.com subdomain reachable, a wider attack surface) and Allowed Roblox hosts (`allowed_roblox_hosts`; only
roblox.com subdomains; callers of a removed host get 404 "Not a Roblox URL"). Whatever the switch says, Roxy always
refuses hosts outside roblox.com.

### Routing

Which egress each call takes. The card starts with the decision in four steps, filled in with the current values:

1. An endpoint the endpoint policy sends with Roxy's account uses the credential (GET, HEAD and POST only, never
   through the rotator).
2. A routing rule below may pin an endpoint to an egress, within what is available.
3. Otherwise direct and the rotator are drawn by weight (direct 100, rotator 0 by default), and above 80 percent
   direct bucket fill the weight shifts toward the rotator when it is on.
4. Each request makes at most 2 attempts (5xx and timeouts only), and a Roblox 429 is never retried (or retried once
   on another anonymous egress when `fallback_on_429` is on).

A weight of 0 never wins the draw, but an egress that is the only one available is still used: that is how the
rotator takes over while direct cools down (as long as the endpoint's own bucket has a free slot).

**Routing rules.** Columns: Id, **Pattern** (the endpoint, as host and path, a glob or a regular expression),
**Mode**, **Enabled** and Note; the column chooser adds Type, Updated and Created by. The modes:

| Mode | Meaning |
|---|---|
| Prefer direct | Direct when it is available, the rotator otherwise. |
| Prefer the rotator | The rotator when it is available, direct otherwise. |
| Direct only | Never the rotator for this endpoint. |
| Rotator only | Never direct for this endpoint. |

**Add a routing rule**: Endpoint pattern (for example `games.roblox.com/v1/games/*`), Pattern type (Glob, with `*`
and `?`, or Regular expression), Egress (the mode), Note, "In force at once" and an optional Reason. **Add rule**
saves it; every worker follows it within a second. Press a row to see the rule in a drawer, change it (**Save the
rule**) or delete it (**Delete the rule**, a dialog with an optional reason: the endpoint follows the weights again,
and the audit log keeps the rule so it can be added back by hand). None of these needs a second factor. At most 200
rules.

**Test a path**: type a host and path without the query and press **Which rule decides it?**. The answer names the
rule that decides it and its mode (and says "It is switched off, so the weights decide." when it is off), or shows
"No rule" with "No routing rule matches <path>: the weights decide."

When to add a rule: keep a fragile endpoint off the rotator (Direct only), or send an endpoint the server address
keeps getting 429s on through the rotator (Prefer the rotator; the recommendation EGR-UNDERUSE suggests such
endpoints). Every rotator byte costs money, so see the [Egress](#egress) chapter first.

Settings for this card: Direct path enabled (`direct_enabled`, on), Direct path weight (`direct_weight`, 100), Rotator
weight (`rotator_weight`, 0; owner decision D13), Direct spillover threshold (`direct_shift_threshold_pct`, 80),
Retry elsewhere after a 429 (`fallback_on_429`, off; high risk when on), Upstream attempts per request
(`upstream_max_attempts`, 2; high risk from 4), Upstream read timeout (`request_timeout`, 15 s), Upstream connect
timeout (`upstream_connect_timeout_s`, 5 s), Upstream User-Agent (`direct_user_agent`) and the User-Agent experiment
(`ua_experiment_enabled`, off; `ua_experiment_days`, 7; `ua_experiment_alt_user_agent`). The experiment splits direct
traffic between two User-Agents for `ua_experiment_days` from when it was switched on (or either User-Agent changed),
then every direct call uses `direct_user_agent` again until you switch it off and on; the recommendation
UP-UA-EXPERIMENT compares only the calls made during the run and reports which User-Agent gets fewer 429s. Prefer it
to changing the User-Agent by hand. Turning `direct_enabled` off forces every anonymous call onto the paid rotator
(high risk).

### Retries

v1's Retries section. Three numbers at the top for the range:

- **Retries after an error**: retries after a 5xx, a timeout or a connection error, made after a backoff.
- **CSRF token refreshes**: Roblox asked for a token and the call was repeated once.
- **Retries after a 429**: retries on another anonymous egress; 0 unless `fallback_on_429` is on.

**Retries logged one by one** (v1's retry log) counts the CSRF repeats by Roblox status, by reason and by egress.
**Upstream calls by attempt kind** splits every call: first calls, retries after a 5xx, a timeout or a connection
error, repeats with a fresh CSRF token, retries on another egress after a 429, and redirect hops followed (each hop
takes a bucket slot too). **Returned reasons** says whose words refused or failed callers got: Roxy's own failure
text, Roblox's own answer passed on, a refusal with your custom message or with the default message.

- **Normal:** almost every call is a first call; retries after an error are rare; CSRF refreshes are a small share
  of write requests.
- **Worrying:** many retries after errors (Roblox is failing; each failing request costs it two calls), or CSRF
  refreshes on a large share of write requests (the recommendation UP-CSRF-LOOP speaks up above 20 percent of the
  write requests of the last 30 minutes, and proposes a shorter `csrf_token_cache_s`).

Settings for this card: Retry wait, starting value (`backoff_base_ms`, 200 ms), Retry wait, longest value
(`backoff_cap_ms`, 2,000 ms) and Roblox CSRF token reuse (`csrf_token_cache_s`, 600 s).

### Internal calls

v1's Internal Requests: the calls Roxy makes for itself. One row per call site: the credential's scheduled check
(`credential_probe`), Check credential by an admin (`credential_check`), the confirmation of a Roblox 401 before the
credential is marked rejected (`credential_confirm`), the rotator's exit address check (`rotator_probe`), Identify an
experience when the proxy path is unavailable (`admin_lookup`) and the reachability probes of Check Proxy Health
(`health_check`). Columns: **Call site** (with what it is for and its URL), **Health** ("Not called yet", "OK" when
its last call worked, "Failing" when it did not), **Calls**, **Failed**, **Average** (the mean time of one call) and
**Last call**, with the last error. Call sites not called in the range come first, then the failing ones, then the
ones that are OK.

These calls never pass through the proxy route, so endpoint blocks, rate rules, filters, throttling and pause do not
touch them; they do take bucket slots, at internal priority (see Queue).

- **Normal:** `credential_probe` OK about every 30 minutes; the others OK or not called yet.
- **Worrying:** `credential_probe` or `credential_check` Failing (see the [Credential](#credential) page), or
  `rotator_probe` Failing while the rotator should work (the Egress page's Rotator card).

### Challenges and HTML answers

Answers that were a bot check (a challenge header) or an HTML page where Roblox should have sent data (a block or
error page), by egress and endpoint. The subtitle counts the endpoints with flagged answers. Columns: Egress,
Endpoint, Calls, **Challenges**, **HTML pages** and Last flagged; the flagged rows come first.

- **Normal:** 0 challenges and 0 HTML pages.
- **Worrying:** challenges or HTML pages on direct: Roblox may be treating the server address as a bot. Open the
  recommendation UP-CHALLENGE, slow the endpoint down (a rate override on Buckets), and consider the User-Agent
  experiment on the Routing card.

### Queue

How long each kind of request may wait for a bucket slot, with the value of the setting that bounds it: priority 0,
a caller's request with no cached copy (`queue_wait_interactive_ms`, 4,000 ms); 1, a caller's request that can be
answered from a stale cached copy instead (`queue_wait_stale_ms`, 500 ms); 2, a background refresh, dropped first
under pressure (`queue_wait_background_ms`, 10,000 ms); 3, an admin action (`queue_wait_admin_ms`, 10,000 ms); 4,
Roxy's own probes and health checks (`queue_wait_internal_ms`, 30,000 ms). The sentence above the table gives the
queue length per worker and the request deadline.

What to watch: the queue wait line of Latency percentiles and the Refused column of Buckets. Raising a wait means
fewer "busy" answers but longer waits, each holding a connection open; lowering it answers "busy, retry after N
seconds" sooner.

Settings for this card: the five queue waits above, Queue length per worker (`queue_max_length`, 500) and Request
deadline (`request_deadline_s`, 60 s). Saving is refused when `queue_wait_interactive_ms` plus `request_timeout`
times `upstream_max_attempts` plus `backoff_cap_ms` (36 s at the defaults) would not stay at least 2 s below the
deadline.

### Concurrency

An optional extra limit on how many calls may be in flight at once to each Roblox host on each egress (AIMD:
additive increase, multiplicative decrease; [AIMD](/admin/help#term-aimd)). It is **Off** by default because Roblox
limits the rate of calls, not how many run at once, and the buckets already handle rate. While it is off, its
settings do nothing.

When on, the card says the rule (the limit grows by one for every `aimd_increase_after` successes, 50 by default,
and is multiplied by the cut factor on a 429, a timeout or a 5xx) and lists each host and egress with its **Limit**
(whole calls at once), the calls **In flight** now and the **Last change**. Only current values are kept; there is
no history.

Settings for this card: Adaptive concurrency (AIMD) (`aimd_enabled`, off), AIMD starting limit (`aimd_initial`, 8),
AIMD lowest limit (`aimd_min`, 1), AIMD highest limit (`aimd_max`, 32), AIMD successes before a raise
(`aimd_increase_after`, 50) and AIMD cut factor (`aimd_decrease_factor`, 0.5). The switch covers every host and
egress at once; turn it on only when a host's answers slow down badly under many parallel calls.

### On a phone

Below 900 px wide the two side-by-side pairs (Roblox 429s with Latency percentiles, Cooldowns with Breakers) stack
into one column. Below 640 px the large tables turn each row into a small card with its key columns only: Buckets
(Bucket, Fill, Rate), Rate overrides (Bucket, Rate, Set by), Request failures (Reason, Count, Last seen), Hosts
(Host, Calls, 429 rate), Routing rules (Id, Pattern, Mode) and Challenges (Endpoint, Challenges, HTML pages).
Pressing a row opens the rest in the drawer. Below 600 px the
small tables (Cooldowns, Breakers, the adaptive changes, Queue, Concurrency, Internal calls) turn each row into a
block of labeled lines, so nothing scrolls sideways; the other small tables (the 429 endpoints, the Retries counts)
scroll inside their own box. The lists of numbers in the egress panels, the drawers and the request trace become one
column below 480 px.

## Egress

The Egress page (`/admin/egress`) shows how many bytes leave through each path, how much of the rotator's monthly
quota is used and what it will cost, and whether the rotator is healthy. The three paths:

- **Direct**: anonymous calls from the server's own address ([direct path](/admin/help#term-direct-path)). Most
  traffic leaves this way, and it costs nothing.
- **Rotator**: anonymous calls through the DataImpulse [rotator](/admin/help#term-rotator), from changing exit
  addresses. Every byte is billed against a monthly [quota](/admin/help#term-quota).
- **Credential**: calls that carry the one Roblox account. They always leave direct, never through the rotator: the
  endpoints the [Endpoint policy](#endpoint-policy) sends with Roxy's account, and Roxy's own checks.

Two buttons sit at the top: **Upstream** and **Credential** open those pages. Bytes on this page are decimal (1 GB is
1,000,000,000 bytes), the unit DataImpulse bills in. Exit addresses are masked to their network unless you reveal
them, and every reveal is written to the audit log.

**When to use this page**

- Once a month, or when the alert "Roxy: rotator at <pct>% of monthly quota" arrives: read the Budget card.
- The health checks H-ROTATOR-REACH, H-ROTATOR-SESSION or H-ROTATOR-QUOTA warn: the Rotator, Sessions and Exit IPs
  cards, then the runbook [Rotator down or quota exhausted](/admin/help/runbooks#rotator-down-or-quota-exhausted).
- The alert "Roxy SECURITY: credential leak blocked" arrived: the Leak guard card and the runbook
  [Leak guard](/admin/help/runbooks#leak-guard).
- You set up Roxy, or DataImpulse changed its URL, price or plan: the Rotator and Budget cards.
- You consider sending more or less traffic through the rotator: see "Running the rotator" at the end of this
  chapter.

### Time range on this page

Usage and Top endpoints by bytes cover the time range in the top bar; their charts and tables do not draw a
comparison. The Budget card always covers the current billing cycle, counted in UTC days. Rotator, Sessions and Leak
guard show the state now (Rotator also counts its calls in the range, and Sessions its calls per exit). Exit IPs
lists the addresses this worker saw most recently.

### Usage

One panel per egress (Direct, Rotator, Credential) with an **On** or **Off** badge (with the reason when off), the
**bytes** that left that way in the range, **Calls** (with their share of all calls) and **Bytes per call**. The
subtitle says how bytes are counted: "counted on the wire, below TLS" (exact, the normal case) or "estimated from
request and answer sizes plus a TLS allowance per connection" (a fallback; the card then shows a notice). Below, the
chart **Upstream calls per egress** stacks each egress's calls over time.

- **Normal:** almost every call direct; the rotator near 0 (its weight is 0, so it only takes spillover); the
  credential a steady share, never above its bucket's pace (its checks, plus the endpoints sent with the account).
- **Worrying:** a large rotator share you did not plan (direct was cooling down a lot, or a routing rule sends traffic
  there; see Upstream > Cooldowns and Routing), or credential calls growing fast (see the Endpoint policy page).

### Budget

The rotator's billing cycle (plan 8.4). Four number tiles:

- **Used this cycle**: metered rotator bytes since the cycle began, all workers.
- **Projected**: what the cycle will end at if use continues at the current pace.
- **Remaining**: the quota minus what is used. It says "Set rotator_quota_gb_per_month to see what is left" while the
  quota is 0.
- **Cost so far**: bytes used times the price, in USD. It says "Set rotator_price_per_gb_usd to see the cost" while the
  price is 0.

Then the projection as a sentence, for example "At this rate you will use 14.2 GB of 20.0 GB this cycle (71.0%),
about 42.60 USD." (without a quota it gives only the GB, without a price no cost, and with no rotator use yet it
says "Not enough rotator usage yet to project this cycle."), with its 90 percent band ("The 90 percent band is ...
to ..."), or the reason there is none yet (a band needs at least 2 complete days of usage). The projection is what is
used so far plus a daily rate times the days left; the daily rate blends the average of the last 7 complete UTC days
(weighted 70 percent) with this cycle's average so far (30 percent).

The list below gives **This cycle** (its first and last UTC day, and the days left), **Used today**, **Quota** ("not
set" while it is 0), **Hard stop** (the bytes at which the rotator stops; "none" while the quota or the hard stop is
0) and **Daily cap** ("none" while it is 0).
When the rotator is stopped, a notice at the top says why: the monthly hard stop was reached (only direct is used
until the next cycle), or the daily byte cap was reached (the rotator rests until midnight UTC). The hard stop, the
daily cap, the budget alerts and the health check H-ROTATOR-QUOTA count from a billing record Roxy keeps apart from
the statistics, so a reset of the Egress usage statistics on the Data page never lifts them: every byte the rotator
sent this cycle still counts.

The chart **Rotator bytes per day this cycle** has one bar per UTC day ("Bytes that day"), a line for the running
total ("Used so far") and, once the quota is set, a line for an even pace that reaches the quota on the last day
("Even pace to the quota"). While the running total stays under the even pace line, the cycle will end within quota.
Until the rotator has used any bytes this cycle, the card says "No rotator bytes yet this cycle, so there are no
daily bars." instead.

**The provider's own figure.** Type the figure DataImpulse's dashboard shows for this cycle, in GB, with an optional
note, and press **Record the figure**. It is written to the audit log (when the audit log cannot be written, the
figure is not kept). The card always shows Roxy's metered count for the cycle, and once a figure is recorded, the
newest one, who entered it and how far apart the two are; the recommendation EGR-CALIBRATE compares them (by default
it speaks up when they differ by more than 10 percent). Recording a figure changes nothing else; a newer figure
replaces it in the comparison.

- **Normal:** used and projected well under the quota; daily bars low and steady.
- **Worrying:** a projection near or over the quota (the recommendation EGR-BURN speaks up when it goes above 90
  percent), a sudden tall bar, or a rotator stopped by the hard stop or the daily cap.
- **What to do:** see which endpoints spend the bytes (Top endpoints by bytes), then send less through the rotator
  ("Running the rotator" below), or buy more and raise the quota. The runbook
  [Rotator down or quota exhausted](/admin/help/runbooks#rotator-down-or-quota-exhausted) has the steps.

Settings for this card (owner decision D12: fill these in from your DataImpulse plan):

- Rotator monthly quota (`rotator_quota_gb_per_month`, 0 = unknown): your plan's allowance per cycle, in GB. Until
  it is set, bytes are still metered but no percentage alert or hard stop can fire.
- Rotator price per GB (`rotator_price_per_gb_usd`, 0 = unknown): used only for the cost figures; it never changes
  routing.
- Billing cycle start day (`rotator_billing_day`, 1): the day of the month your plan resets (1 to 28).
- Budget alert thresholds (`rotator_budget_alert_pcts`, 50, 80 and 95 percent of the quota): each sends the alert
  "Roxy: rotator at <pct>% of monthly quota" once per billing cycle (from 95 percent as a critical alert).
- Rotator hard stop (`rotator_hard_stop_pct`, 100 percent of the quota): the rotator stops for the rest of the cycle;
  0 never stops it and above 100 lets it run into overage (both high risk).
- Rotator daily cap (`rotator_daily_cap_mb`, 0 = none): the most MB a day; reached, the rotator rests until the next
  UTC day.
- Handshake bytes per new rotator connection (`rotator_tls_overhead_bytes`, 6,000): used only by the fallback
  estimate; EGR-CALIBRATE suggests a new value when your recorded figure differs.

### Top endpoints by bytes

The page's main table: which endpoints use the most bytes on one egress, the rotator by default (those bytes cost
money). Choose another egress with the **Egress** filter (Rotator, Direct, Credential). The line above it gives that
egress's total in the range. By default it shows **Endpoint**, **Bytes** (wire bytes: request, answer, TLS and the
proxy's own exchange), **Calls**, **Bytes per call** and **Share** (this endpoint's part of the egress's bytes); the
column chooser adds Bytes in and Bytes out. The filter, search, sort and page are kept in the address bar; export
downloads CSV or JSON.

**Bytes per call on this egress** (press to open) counts the calls in each size slot. It is built from per-minute
averages, as the card says.

- **Normal:** for the rotator, an empty list ("No rotator bytes in this range") or a few endpoints with small
  answers.
- **Worrying:** one endpoint with big answers taking most of the rotator's bytes. Keep it off the rotator with a
  Direct only routing rule, or cache it longer.

### Rotator

v1's "Rotate (IP rotation)" tile. A badge and a sentence give the state: "Working", "Idle", "Not configured" (no
rotator URL is set, so every call goes direct), "Parked" (after a failure streak; it is tried again when the park
ends), "Cooling down", "Partly paused", "Off" with its reason, or "Stopped" by the leak guard (the badges are
explained under Egress and host health in the [Upstream](#upstream) chapter). Then:

- **Gateway**: the DataImpulse gateway as `scheme://host:port` only, and where the URL comes from ("set from this
  page", or "the systemd credential rotator_url"). The full URL holds a user name and a password: it is never shown.
- **Set from this page**: when and by whom, if it was.
- **Session mode in force** (see the Sessions card).
- **Calls in this range**, with failed calls, timeouts and Roblox 429s; **Last success** and **Last error**.

Actions:

| Action | What it changes | Second factor | Undo |
|---|---|---|---|
| **Replace the gateway URL** | Every worker sends rotator traffic through the new gateway within a second. The URL is stored encrypted and never shown again; the audit log keeps only its fingerprint and host. Enter it as `http://user:password@host:port`, with an optional reason. | yes | replace it again, or Go back to the bootstrap URL |
| **Go back to the bootstrap URL** (only after a URL was set here) | Deletes the URL set from this page; every worker uses the systemd credential `rotator_url` again within a second. If that file is empty, the rotator stops and direct carries everything. | yes | replace the URL again |

Both actions ask you to confirm it is you ([Step 4](#step-4-save-the-recovery-codes)). The bootstrap value is read
when the service starts: after editing the file `/etc/roxy/credentials/rotator_url` on the server, restart the
service (the card says `systemctl restart roxy@<color>`).

Settings for this card: Rotator enabled (`rotator_enabled`, on; it only works once a gateway URL is configured),
Rotator weight (`rotator_weight`, 0; owner decision D13), Rotator rate and burst (`rotator_bucket_per_min`, 300;
`rotator_bucket_burst`, 20), Rotator session mode (`rotator_session_mode`, "Sticky until rate-limited"), Rotator
session username template (`rotator_session_username_template`, empty), Sticky session length
(`rotator_sticky_seconds`, 300 s), Warm rotator sessions per worker (`rotator_max_sessions`, 16), Rotator exit country
(`rotator_country`, empty for any country), Rotator failures before pause (`rotator_max_failures`, 3), Rotator pause
after failures (`rotator_cooldown_s`, 60 s), Rate-limited exits before endpoint pause
(`rotator_cooldown_distinct_exits`, 3), Rate-limited exits window (`rotator_cooldown_window_s`, 60 s), Exit IP check
timeout (`rotator_probe_timeout_s`, 10 s) and Recent exit IPs kept (`rotator_recent_ips`, 50). The seven budget
settings (quota, price, billing day, alert thresholds, hard stop, daily cap and handshake bytes) show here too, as
their current value with a link to the Budget card, where they are edited. The rotator's rate and burst can be edited
here or on the Upstream page's Buckets card; both change the same setting.

The session username template is the one rotator setting you must check yourself: its syntax is DataImpulse's, so
Roxy ships none. Read the provider's documentation and fill it in with the `{user}` and `{session}` placeholders
(and `{country}` to use `rotator_country`); never type the real user name or password there. Until it is set, the
sticky modes are unavailable and every rotator call gets a new exit. A wrong template makes the gateway refuse
rotator calls, which parks the rotator; the health check H-ROTATOR-SESSION confirms a new template works.

### Exit IPs

v1's Rotation Exit IPs: the exit addresses this worker saw most recently, newest first. Columns: **Exit address**
(masked to its network, /24 for IPv4, /48 for IPv6), **From** (the check that saw the address) and **When**; the
subtitle counts them. The list is kept per worker (the last `rotator_recent_ips` checks) and never goes into the LLM
export.

- **Verify rotation now** asks the IP echo service through the rotator and says the result in a message: "Rotation
  working: exit IP ..." (masked), "Rotation FAILED: ..." or "Rotation is not configured". It changes nothing; the
  address then appears in the list (From "probe"). The button is disabled while no rotator URL is set; with a URL it
  works even while the rotator is switched off, parked or stopped by the budget. It needs no second factor.
- **Show full addresses** replaces the masked addresses with the full ones. The reveal is written to the audit log
  first (no audit row, no reveal). It needs no second factor.

Normal: the checks work. With "a new exit for every call" (the mode in force until the session username template is
set) each check shows a different address; with a sticky mode the address changes when the session does. Worrying:
checks that fail (see [Rotator down or quota exhausted](/admin/help/runbooks#rotator-down-or-quota-exhausted)), or
one address for a long time in a mode that should change it.

### Sessions

How the rotator uses its exits. A badge says whether it is **Usable now**, **Parked** (after a failure streak) or
**Not in use** (with the reason). Then:

- **Mode set** and **Mode in force**: "a new exit for every call" (`per_request`), "one exit per session for a
  while" (`sticky`) or "one exit per session until it gets a 429" (`sticky_until_429`, the default). The mode in force
  is "a new exit for every call" until the session username template is set; the card says so.
- **Open sessions** on this worker, and the most it keeps.
- **Failure streak**: consecutive rotator failures (connection errors, timeouts, Roblox 429s and 5xx) across every
  worker, with the time of the last one. At `rotator_max_failures` (3) the rotator is parked for `rotator_cooldown_s`
  (60 s).
- **Parked**: until when, and how many times so far.

**Calls per exit** (in the range): **Exit** (a short hash of one session, never its address), Calls, 429s, **429 rate**,
Failures and Last seen. How long each session lasted is not recorded yet.

- **Normal:** "Usable now"; a failure streak of 0 or 1; low 429 rates per exit.
- **Worrying:** parked again and again, or high 429 rates on most exits: the pool's addresses are already limited by
  Roblox (the recommendation EGR-POOL-BURNED speaks up when more than 20 percent of the rotator's calls in the last
  30 minutes got a 429). Send less through the rotator, or try another `rotator_country`.

### Leak guard

The [leak guard](/admin/help#term-leak-guard) checks every anonymous call for the credential before it leaves. If one
ever carried it, the guard stops the call, switches that egress off for every worker, and sends the alert "Roxy
SECURITY: credential leak blocked".

- **Normal:** "The leak guard has not stopped anything."
- **When it tripped:** a red notice per disabled egress ("Direct is disabled by the leak guard" or the rotator), with
  **Since**, **Where** (where in the call the credential was found), **Purpose** (which part of Roxy built the call)
  and **Request** (its request id). A trip means a bug or an attack. Follow the runbook
  [Leak guard](/admin/help/runbooks#leak-guard) before anything else.
- **Turn it back on:** the form under the notice asks **Why it is safe again** (required, saved in the audit log)
  and asks you to confirm it is you; **Turn direct back on** (or **Turn rotator back on**) re-enables
  it on every worker. There is no undo button: a new trip switches it off again, so do this only once the cause is
  understood. To keep it off by choice, use `direct_enabled` or `rotator_enabled` instead.

**Guard counters on this worker**: per egress, the **Calls checked**, the **Trips** and **Smuggling refused** (callers
who tried to send a Roblox login cookie through Roxy; they are refused with 400 before anything leaves, see
[auth smuggling](/admin/help#term-auth-smuggling)).

### Running the rotator: usage, quota and when to rotate more or less

Owner decision D13: the rotator carries anonymous traffic only, and only when it helps. By default its weight is 0,
so it is a spillover path: it takes calls while direct is cooling down after a 429, when the direct bucket is more
than 80 percent booked, or when a routing rule prefers it. It never carries the credential.

**Fill in your plan (owner decision D12).** On the Budget card set the monthly quota, the price per GB and the day
your plan resets. Until the quota is set, the budget alerts, the projection's percentage and the hard stop cannot
work; until the price is set, the cost figures stay empty. Leave the hard stop at 100 percent unless you knowingly
accept overage.

**Read the usage once a month.** On Usage, the rotator's share of calls and bytes; on Budget, the projection against
the quota; on Top endpoints by bytes (Rotator), which endpoints spend the bytes; on Sessions, the 429 rate per exit.
Record DataImpulse's own figure on the Budget card now and then so Roxy's count stays calibrated.

**Send more through the rotator when** the server address keeps getting 429s on specific endpoints (Upstream >
Roblox 429s and Cooldowns), the rotator's own 429 rate is low, and plenty of quota is left. The recommendation
EGR-UNDERUSE looks for exactly this over the last hour (by default: a direct 429 rate above 2 percent on an endpoint
that the rotator has also served with a 429 rate under 5 percent, while the rotator is on and has used under 30
percent of a set quota; it stays silent until the quota is filled in). Prefer a routing rule (Prefer the rotator) for
those endpoints over raising `rotator_weight`, which moves ordinary traffic too and spends quota on calls the free
direct path could make. Remember that the endpoint's own bucket is shared by every path: right after a Roblox 429 the
adaptive cut can leave no free slot for that endpoint on any path for a minute or more (see the worked example in
[How Roxy stays under Roblox's limits](#how-roxy-stays-under-robloxs-limits)), so the rotator helps most with
endpoints the server address keeps getting 429s on, not with a single burst.

**Send less through the rotator when** the projection nears the quota (EGR-BURN), the exits are already limited by
Roblox (EGR-POOL-BURNED), or one endpoint with big answers takes most of the bytes. Use a Direct only routing rule for
that endpoint, a daily cap (`rotator_daily_cap_mb`) to spread spending over the cycle, or set the weight back to 0.
To stop using it entirely, turn Rotator enabled off: no rotator use and no spending; when direct is cooling down,
callers then get an older cached copy or a 429 with `Retry-After` instead.

### On a phone

Below 900 px wide the Exit IPs and Sessions cards stack into one column. Below 640 px Top endpoints by bytes turns
each row into a small card with its key columns (Endpoint, Bytes, Share) and opens the rest of a row in the drawer.
Below 600 px the tables of Exit IPs and Sessions and the guard
counters turn each row into a block of labeled lines. The number tiles of the Budget card wrap to fit the width, and
the lists of the Usage, Budget, Rotator, Sessions and Leak guard cards become one column below 480 px.

## Cache

The Cache page (`/admin/cache`, keys `g` then `c`) shows how many requests Roxy answers from its own stored copies
instead of asking Roblox. It is also where you decide how long answers are kept, and where you look at, refresh and
delete stored answers.

The cache is Roxy's strongest protection against Roblox rate limits. Roblox sees about one call per distinct question
per lifetime, however many callers ask that question. Per-address limits cannot do that: one Roblox game reaches Roxy
from hundreds of rotating server addresses, while Roblox sees one proxy asking the same thing again and again.

The words this chapter uses:

- An **answer** (also called an entry) is one stored Roblox reply to one exact question: the method, the endpoint and
  every query parameter that matters. `?universeIds=123` and `?universeIds=456` are two questions, so two answers.
- The **cache key** is that identity. An **ignored parameter** is a query parameter left out of the key.
- A **hit** is a request answered from a fresh stored copy: Roblox never hears about it. A **miss** went to Roblox.
- The **lifetime**, also called the TTL (time to live), is how long an answer counts as current. After it, the answer
  is **expired**.
- A **stale** answer is an expired one handed over anyway, because Roblox could not be asked or failed.
- **Coalescing** means that callers asking the same missing question at the same moment share one Roblox call.
- A **purge** deletes stored answers on purpose, right now. The next caller who asks goes to Roblox.

**When to use this page**

- Roblox is rate-limiting Roxy (the alert "Roxy: Roblox is rate-limiting us (<rate>%)", health check H-429-RATE,
  429 answers on the Upstream page). The cache is the first thing to check.
- Health check H-CACHE-HIT warns, or a cache recommendation is open (CACHE-LOW-HIT, CACHE-TTL-TUNE, CACHE-KEYSPLIT,
  CACHE-PRESSURE, CACHE-OFF, CACHE-NEG, HOT-ENDPOINT).
- A caller says the data looks old, or that something changed on Roblox but not through Roxy. Find the stored
  answer, check its age, then fetch it again or purge it.
- You want one endpoint kept longer, or never cached: write a cache rule.
- You just changed a cache setting or rule and want to know whether it worked: watch "Hit ratio right now".
- Roblox changed something you cache for a long time and callers must see it now: purge it.

### How the page is laid out

Ten cards, top to bottom: Cache statistics, Hit ratio over time, Cache settings, Coalescing, Per endpoint, Cache
rules, Ignored parameters, Key spread, Cache browser and Purge. The page header has a Recommendations button (it opens
the Recommendations page) and the "How to read this page" panel.

The numbers are read when the page loads. The heavier cards load right after the first paint, one at a time. Nothing
moves on its own after that: reload the page, or change the time range, to see newer numbers. A card refreshes
itself after an action you take on it (a purge, a new rule).

Some numbers carry a **this worker** label. Roxy runs two worker processes, and each keeps a few things in its own
memory: the memory tier and the single-flight counters. The page shows the worker that happened to answer your
request, so these numbers can switch between two sets of values when you reload. Every other number covers the whole
server.

### Time range on this page

The time range in the top bar applies to:

- the tiles, the "By cache state" line, and the eviction and store counts of the "Stored answers (shared)" box of
  Cache statistics;
- the three charts of Hit ratio over time;
- the "Shared answers in range" count of Coalescing;
- the Per endpoint table and its drawer.

Everything else shows the cache as it is now: the "Hit ratio right now" box always covers the last 5 minutes, hour
and 24 hours, and the stored answers and their size, the memory tier, the rules, the ignored parameters, the key
spread, the browser and the purge do not depend on the range.

A comparison draws a dashed second line on the charts. The statistics tiles always show a change in percent:
against the comparison you chose, or against the previous period of the same length when you chose none. (A screen
reader hears "vs the previous period" whatever you picked; the number itself follows your choice.) When a reset
cleared part of a tile's data, in the range or in the period it is compared with, the tile shows a note instead of a
change, because a change over partly cleared data would mislead, and a note under the card's title names the reset.

### Cache statistics

The first card answers "is the cache doing its job right now".

**The top line.** A green "Caching on, answers kept 2 minutes by default" (the default lifetime in words) or a red
"Caching off". Next to it, "N requests Roblox never saw": the requests the cache answered in the range. When there
were any, a line under it splits them by cache state: fresh hits, answers served while one refresh ran, stale rescues
while Roblox failed, and requests that shared another caller's fetch.

**The shared store alert.** A red "The shared cache store is not working." appears when the shared disk cache is on
but Roxy cannot write to its cache directory, or writing to it fails. Answers are then kept only in each worker's
memory: they are not shared between the two workers, they are lost on a restart, the hit ratio drops, and the browser
looks incomplete. Fix the directory's permissions (the [File permissions](/admin/help/runbooks#file-permissions)
runbook; the System page shows the environment), or check the disk and the database with the
[Cache not working](/admin/help/runbooks#cache-not-working) and
[Disk full or database large](/admin/help/runbooks#disk-full-or-database-large) runbooks. Turning "Shared disk cache"
off in the settings runs memory only on purpose; do that only while the store is broken.

**The tiles.** Each tile has a help button with the full definition.

| Tile | What it counts | How to read it |
|---|---|---|
| Cache hit ratio | Of the requests that looked in the cache, the share answered from it. | Higher is better. See "What normal looks like" below. |
| Avoided upstream calls (percent) | The share of caller demand that never reached Roblox. | Higher is better. Health check H-CACHE-HIT passes above 30% (last hour) and warns at 30% or lower. |
| Avoided upstream calls | Calls Roblox did not have to answer, because the cache served the caller or callers shared one fetch. | Grows with traffic; higher is better. |
| Served from cache | Requests answered from the cache, fresh or stale, including callers that shared another caller's fetch. | Higher is better. |
| Errors hidden from callers | Requests where Roblox (or the path to it) failed, but Roxy answered with an older copy. | The caller got data, so this is the cache saving the day. A rising count means Roblox is failing or cooling Roxy down: look at the Upstream page. |
| Bytes served from cache | Response bytes delivered to callers from the cache. | For information. |
| Caller demand | Requests Roxy tried to answer for callers. Refused requests are left out, so a flood Roxy turned away cannot make the cache look better. | For information. |
| Upstream calls for callers | Calls Roxy sent to Roblox for callers, including retries and background refreshes. | Lower is better. |

The avoided share can be below 0%. That happens when retries and background refreshes made more calls to Roblox than
callers sent requests: -100% means two upstream calls per request. Roxy shows it as it is instead of rounding it up,
and the two avoided tiles then say why instead of showing a change. Right after Clear stats, the hit ratio tile can
read "cleared by a reset": no lookup is left in the range to divide by.

**Hit ratio right now.** The hit ratio of the last 5 minutes, the last hour and the last 24 hours, each with "N served
here, M went to Roblox" ("no lookups" when nothing looked in the cache). These windows do not follow the top bar. Use
the 5 minute row after a change: it tells you within minutes whether the change works, long before the range moves.

**Stored answers (shared).** The shared store on disk, which both workers use:

- Answers: how many are stored, out of the "Shared cache entry limit".
- Size: their size on disk, out of the "Shared cache size limit".
- Evicted in range: answers thrown out early to stay inside those limits. The part "before their lifetime ran out"
  counts answers that were still useful.
- Mean age when evicted, and Stored in range: how old evicted answers were, and how many new answers were stored.

When the shared store is turned off, the box says so.

**Memory tier (this worker).** Each worker keeps a small copy of the hottest answers in its own memory, in front of the
shared store: answers (out of "Memory cache entries per worker"), size (out of "Memory cache size per worker") and
evictions since that worker started. The real memory cost is this times the number of workers, and it doubles during
a deploy while the old and new release run side by side. That is why the memory limits are small. Evictions here are
normal: an answer pushed out of memory is still in the shared store.

**What normal looks like.** The page's own thresholds are on the Per endpoint card: a hit ratio of 50% or more is
"working well", and under 10% on a busy endpoint is "low". For the whole server, the health check's line is an avoided
share above 30% over the last hour. Stored answers well under both limits with few evictions is healthy.

**What a worrying value looks like, and what to do.**

- A low or falling hit ratio, or an avoided share at 30% or lower:
  1. Check the top line says "Caching on".
  2. On Per endpoint, sort by Requests and find busy endpoints with a red hit ratio.
  3. On Key spread, look for a row marked "splitting for nothing": a caller adds a changing value to every request.
     Ignore that parameter.
  4. Give a busy endpoint a longer lifetime with a cache rule, if its data does not change that often.
  5. Read the open cache recommendations (the Recommendations button); they measure all of this for you.

  The runbooks: [Cache not working](/admin/help/runbooks#cache-not-working) and
  [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us).
- Evictions that climb steadily, especially "before their lifetime ran out", or answers or size near their limit: the
  shared store is too small for the traffic. Raise "Shared cache entry limit" or "Shared cache size limit" (the
  CACHE-PRESSURE recommendation proposes values), and keep an eye on the disk budget on the Data page.
- A rising "Errors hidden from callers": Roblox is failing or Roxy is in a cooldown. Callers are fine for now, but only
  as long as the stale window lasts. Look at the [Upstream](#upstream) chapter and the
  [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable) runbook.

**Clear stats.** The button at the top right of the card resets the cache statistics (the reset family named
`cache_stats`, v1's "Clear stats"). The dialog "Clear the cache statistics?" counts the rows it would touch when it
opens and lists what happens:

- the hit, miss, stale, revalidating and coalesced counts start again from zero; the requests stay in every Traffic
  total (their cache state reads "cleared");
- the stored answers stay (use Purge for those);
- the "Evicted in range" and "Stored in range" counts of the "Stored answers" box go too, with the log of eviction
  passes;
- the TTL tuner's refetch observations go too (they live in cache.db, which no snapshot keeps), so the tuner starts
  measuring lifetimes again;
- every chart gets a "data reset" marker, and tiles over that time say their data was reset.

You must type `reset cache_stats` and give a reason (the reason is written to the audit log); the button is
"Reset". It does not ask for your second factor. A reset cannot be undone from the dashboard: Roxy copies metrics.db
to a snapshot first when there is room for it, and putting a snapshot back is a restore on the server (see
[Statistics resets](#statistics-resets)). The TTL tuner's observations live in cache.db, which is never
snapshotted, so they cannot come back. Clear stats is rarely needed: a time range that starts after a change shows
the same thing without deleting anything.

### Hit ratio over time

Three charts for the selected range:

- **Hit ratio**: the share of cache lookups answered from the cache, per time bucket.
- **Avoided upstream calls**: the share of caller demand that never reached Roblox. It can dip below 0% (see the tile
  above); the chart then lists a note explaining why.
- **Answers by cache state**: requests per state, stacked: Hit (fresh copy), Revalidating (copy served, refresh
  running), Stale (old copy, Roblox unavailable), Coalesced (shared another caller's fetch) and Miss (fetched from
  Roblox).

Each chart has a help button, a data table and markers, as on every chart (see [Charts](#charts)).

How to read them:

- A step down in the hit ratio right at a configuration marker: that change did it. Open the marker's audit entry to
  see what changed, and change it back if needed.
- A growing Stale band: Roblox is failing or Roxy is cooling down. The cache is hiding it from callers for now.
- A growing Miss band while traffic is steady: lifetimes are too short, or callers started sending cache busters.
- A large Coalesced band during bursts: coalescing is doing its job.

### Cache settings

The card opens with "What happens to one request, using your current settings": a timeline built from the saved
settings, following one caller who keeps asking for the same thing. It changes after you save a setting. Endpoint
rules can change it per endpoint. With the shipped settings (lifetime 120 seconds, revalidate window 60 seconds,
stale window 600 seconds, coalescing on) it reads like this:

| When | What happens |
|---|---|
| 0s | Nobody asked before: a MISS. Roxy asks Roblox once, passes the answer on and keeps a copy. Callers asking while that call is on its way wait for it and share it (COALESCED). |
| up to 2 minutes | Everyone asking gets the copy: a HIT. Roblox hears nothing, whether one caller asks or ten thousand. |
| 2 minutes | The copy is expired. Roxy stops treating it as current but keeps it. |
| 2 to 3 minutes | The next caller still gets the copy at once (REVALIDATING) while Roxy asks Roblox for a fresh one in the background, one refresh for everyone. |
| just after 3 minutes | The next caller sends Roxy back to Roblox. If Roblox answers, a MISS and a new copy. If Roblox refuses (rate limited or down), the old copy anyway: STALE. |
| 12 minutes | The copy is older than the lifetime plus the stale window, so it is no longer used even as a fallback. A refusal from Roblox now reaches the caller as an error. |

When caching is off, or the default lifetime is 0, the timeline says so instead. Under the timeline, "The words used
on this page" folds out the definitions of hit, miss, TTL, expired, stale, entry, evicted and purge.

Then come the settings, under "Settings for this card" (open on this card). They are listed by key, as on the page.
The full description, every allowed value and what happens when you raise or lower each one are in the control
itself ("What happens if I change this?") and on the [Settings](#settings) page.

| Setting (key) | Default | What it does |
|---|---|---|
| Request coalescing (`cache_coalesce`) | on | Shown here read-only; edit it on the Coalescing card. |
| Coalescing wait limit (`cache_coalesce_wait_ms`) | 0 | Shown here read-only; edit it on the Coalescing card. |
| Compress cached bodies (`cache_compress`) | on | Stores bodies compressed, so the same disk budget holds several times more answers. |
| Built-in cache rules (`cache_default_rules_enabled`) | on | Uses the lifetimes Roxy ships for Roblox data with known change rates (game details and votes, universe from place, thumbnails, profiles, groups, catalog items, badges, presence). |
| Shared disk cache (`cache_disk_enabled`) | on | The shared store both workers use, which survives restarts. Off means memory only. |
| Response cache (`cache_enabled`) | on | The master switch. Off sends every request to Roblox. |
| Error answer lifetime (`cache_error_ttl_seconds`) | 60 seconds | How long a Roblox 400, 403 (permission denied only), 404 or 410 is remembered and replayed. 429 and 5xx answers are never stored as content. |
| Eviction policy (`cache_eviction_policy`) | Hybrid | Which still-useful answers go first when the shared store is full: least recently used, least frequently used, or hybrid (hits that fade over time). |
| Largest cacheable response (`cache_max_body`) | 1 MiB | Bigger answers are passed on but never stored. |
| Shared cache size limit (`cache_max_bytes`) | 512 MiB | The disk budget of the shared store. |
| Shared cache entry limit (`cache_max_entries`) | 200,000 | The most answers the shared store holds. |
| Memory cache size per worker (`cache_memory_bytes`) | 16 MiB | Each worker's memory budget. This is the cache setting that can run the server out of memory. |
| Memory cache entries per worker (`cache_memory_entries`) | 1,000 | The most answers each worker keeps in memory. |
| Remember Roblox 429s per request (`cache_negative_429`) | on | After Roblox answers 429, repeats of that exact request do not reach Roblox until the cooldown ends. |
| POST caching (`cache_post_requests`) | Allowlisted lookups | Which POST requests may be cached: off, the built-in read-only batch lookups (plus rules that allow POST), or all (risky). |
| Honor caller no-cache headers (`cache_respect_no_cache`) | off | On lets any caller skip the cache with one header. Keep it off. |
| Serve throttled callers from cache (`cache_serve_throttled`) | off | When a caller is over its rate limit, answer from a fresh copy instead of refusing. |
| Stale serving window (`cache_stale_seconds`) | 600 seconds | How long after expiry an answer may still be served when Roblox cannot be asked. |
| Stale-while-revalidate window (`cache_swr_seconds`) | 60 seconds | How long after expiry an answer is served at once while one background refresh runs. |
| Default cache lifetime (`cache_ttl_seconds`) | 120 seconds | The lifetime of a successful answer when no cache rule covers its endpoint. |
| Background refreshes per worker (`swr_max_inflight`) | 50 | The most background refreshes one worker runs at once. |
| TTL tuner (`ttl_tuner_enabled`) | on | Measures how often each endpoint's answers really change and proposes lifetimes as recommendations. It only proposes. |
| Longest tuned lifetime (`ttl_tuner_max_s`) | 3,600 seconds | The longest lifetime the tuner may propose. You can still set longer ones by hand. |

Cache hits count toward each caller's per-address limit by default ("Count cache hits toward the per-IP limit",
`throttle_count_cache_hits`, on; it lives on the Protection page's Throttle card), so a caller over its limit is
refused even for cached answers unless "Serve throttled callers from cache" is on.

**Changing a setting.** These settings are changed like any setting on a card (see
[Changing a setting on a card](#changing-a-setting-on-a-card)); none needs a restart, and none asks for your second
factor. These values are **high risk**, so they need a reason and the tick:

- Response cache, Shared disk cache, Request coalescing or Remember Roblox 429s turned off;
- Largest cacheable response, Shared cache size limit or Shared cache entry limit set to 0;
- Shared cache size limit above 4 GiB (more than a third of the default storage budget);
- Memory cache size per worker above 32 MiB (two workers can push the service past its memory cap, and the system
  then kills workers mid-request);
- POST caching set to all requests, or Honor caller no-cache headers turned on;
- Default cache lifetime set to 0, or above one hour.

### Coalescing

When many callers ask for the same missing answer at the same moment, Roxy sends one request to Roblox and gives its
answer to all of them. Without it, a popular answer expiring produces a burst of identical calls, exactly the pattern
that earns Roblox 429s, at the worst moment.

- **Coalescing**: "on, fleet-wide" (both workers share one fetch), or an amber "off".
- **Shared answers in range**: requests that got another caller's fetch in the selected range.
- **Single-flight (this worker)**: the counters of the worker that answered the page since it started. "Fetches it
  led" (it made the call others waited for), "Followed here" (waited for a call on the same worker), "Followed another
  worker", "Waits that timed out" and "In flight now".

Normal: "Waits that timed out" stays at or near 0. When it climbs, Roblox is answering slowly (or "Coalescing wait
limit" is set shorter than Roblox takes): waiting callers gave up and got a stale copy, or a 503 with Retry-After
(reason `coalesce_timeout`). They never call Roblox themselves, so this never adds upstream calls. Look at the
Upstream page.

The two settings are edited here (the settings list is open on this card):

| Setting (key) | Default | What it does |
|---|---|---|
| Request coalescing (`cache_coalesce`) | on | Fleet-wide single-flight. Turning it off is a high-risk value. |
| Coalescing wait limit (`cache_coalesce_wait_ms`) | 0 | The longest a waiting caller waits for the call already on its way. 0 means as long as that call may take (about 36 seconds with the shipped settings), not zero. |

### Per endpoint

"Where the cache is working": one row per endpoint template in the range. An **endpoint template** is a Roblox path
with its ids replaced by placeholders, such as `games.roblox.com/v1/games/{universeId}/votes`, so every request of one
kind is counted together. The card's note sums it up: a busy endpoint with a hit ratio near zero is the one to act
on, because every caller asks a slightly different question.

| Column | Meaning |
|---|---|
| Endpoint | The endpoint template. |
| Requests | Every request for it in the range. |
| Hit ratio | Of its lookups, the share answered from the cache. With 20 requests or more, under 10% shows red with "low for a busy endpoint", 50% or more green with "working well". |
| Hits | Answered from a fresh copy; Roblox never saw these. |
| Stale serves | An expired copy handed over because Roblox failed or was cooling down. |
| Revalidations | An expired copy served while one refresh ran. Hidden by default. |
| Coalesced | Requests that shared another caller's fetch. Hidden by default. |
| Misses | Fetched from Roblox because there was no usable copy. |
| Negative hits | Stored refusals (404 and similar) replayed without asking Roblox. |
| Served bytes | Bytes delivered from the cache. Hidden by default. |
| Upstream calls | Calls Roxy made to Roblox for it. Hidden by default. |
| TTL | The lifetime that applies now: the matching rule's, else the default. "never cached" in amber means a lifetime of 0 (a rule's, or the default lifetime when it is set to 0). |
| Rule | The matching cache rule's number, or "default". |

Use "Columns" to show the hidden ones. Click a column header to sort (all but Negative hits, TTL and Rule); the
busiest endpoints come first by default. The search box filters by endpoint, and Export downloads the table as CSV or
JSON.

**The endpoint drawer.** Click a row. The drawer repeats its numbers for the range and says where its lifetime comes
from (a rule, with its number and pattern, or the default). It offers:

- **Give this endpoint its own lifetime.** The pattern is filled in with the wildcard form of the template (each
  placeholder becomes a `*`, and the pattern also covers the paths under it); "Keep answers for (seconds)" starts at
  300, and 0 means never cache it. "Write the rule" adds the rule at once, without a dialog, and drops the stored
  answers it covers so it applies right away. To undo it, remove the rule on the Cache rules card.
- **Purge its stored answers** opens the purge dialog for that pattern (see Purge below).
- **Open this endpoint on the Endpoints page**, for its trend, callers and recent requests ([Endpoints](#endpoints)).

What to do with a worrying row: a busy endpoint with a red hit ratio usually has a cache buster (check Key spread) or
a lifetime that is too short for how often callers ask (write a rule, or apply the TTL tuner's suggestion). "never
cached" on a busy endpoint is fine when it is on purpose, for example a live server list; otherwise check its rule.

### Cache rules

A cache rule gives the endpoints its pattern covers their own lifetime instead of the default. The card's subtitle
shows the default lifetime without a rule. The most specific pattern wins, so a broad `games.roblox.com` rule can set
a house default while one exact path overrides it. A lifetime of **0 means never cache** those endpoints: that is how
you exclude one endpoint without switching the whole cache off. Examples from the card:
`games.roblox.com/v1/games/votes` at 600 (vote counts barely move, so one call every ten minutes is plenty), and
`games.roblox.com/v1/games/*/servers` at 0 (a live server list is worthless when even slightly old).

**TTL tuner suggestions.** The open cache recommendations, most severe first (up to ten; "N more on the
Recommendations page" when there are more). Each one links to its card on the Recommendations page, where you can see
the evidence, preview it, apply it and undo it. Nothing changes until you apply it there
([Recommendations](#recommendations)).
An amber "tuner off" badge means the "TTL tuner" setting is off.

**Add a cache rule.** Fold out the form:

| Field | Meaning |
|---|---|
| Endpoint pattern | Without `https://`. A `*` stands for one part of the path, and a wildcard pattern covers everything nested under it. |
| Pattern type | Wildcard (almost always what you want) or Regex (for a pattern a wildcard cannot express). |
| Keep answers for (seconds) | The lifetime. Starts at 300; 0 means never cache. At most one day (86,400). |
| Revalidate window (seconds) | How long after expiry the copy is still served while one refresh runs. 0 uses the "Stale-while-revalidate window" setting (60 seconds by default). |
| Keep refusals for (seconds) | How long a definite refusal from Roblox (404 and similar) is kept. 0 uses the "Error answer lifetime" setting (60 seconds by default). A rule with a lifetime of 0 keeps no refusals at all. |
| Methods | GET only, or GET and POST. Allow POST only for batch lookups that read and never change anything. A rule's POST counts only while "POST caching" is "Allowlisted lookups" (or all); with POST caching off, no POST is cached. |
| Normalization | Optional, one per line: `sort_csv:<param>` sorts a comma separated id list so its order does not split answers; `casefold_path` lowercases the path. |
| Note | Optional and private: your reminder of why the rule exists. |
| Drop the stored answers this rule now covers | Checked by default, so the rule applies at once. |
| Reason | Optional, saved in the audit log. |

"Add rule" saves it at once (no dialog). Roxy keeps at most 500 cache rules.

**The rules table.** Shown by default: Pattern, TTL ("never cache" in amber for 0), Type, Methods, Note, Enabled and
Id. Hidden by default: Revalidate window, Negative TTL, Normalization, Origin (shipped, admin or recommendation),
Added and Updated. A 0 in the Revalidate window or Negative TTL column reads "default (1 minute)", with the setting it
falls back to under it ("Stale-while-revalidate window" or "Error answer lifetime") and its current value ("default
(none)" when that setting is 0 itself); a rule whose lifetime is 0 reads "none (never cached)", because it keeps
nothing at all. The add form and the edit drawer say the same next to the fields. The rules Roxy ships have the
origin "shipped"; they work like any other rule, and the "Built-in cache rules" setting turns them all off at once.
Search covers patterns and notes, and Export downloads the rules as CSV or JSON.

**The rule drawer.** Click a rule. It shows who added it and when, and the whole rule as a form:

- Change any field and press "Save the rule". By default the answers stored under the rule (and under its new
  pattern, when you change it) are dropped, so the change applies at once.
- Untick "The rule is in force" to switch the rule off without losing it. This is the easy way to try the default
  lifetime for a while.
- "Remove this rule" opens a dialog ("Remove this cache rule?") with an optional reason. Its endpoints fall back to
  the default lifetime or another matching rule, and the answers stored under it are purged.
- "Every change of this rule in the audit log" lists its history with the values before and after.

None of these asks for your second factor or a typed confirmation. There is no one-click undo for a rule: change it
back in its drawer, or add a removed rule again by hand, using its audit entry for the old values.

### Ignored parameters

An ignored parameter is left out of the cache key, so requests that differ only in that parameter share one stored
answer. Only ignore a parameter you know does not change the answer, such as a timestamp a caller adds to defeat
caching. The subtitle shows how many are ignored, out of at most 100.

- **The list**: each parameter, its note and who added it (shipped, admin or recommendation). "Stop ignoring" opens a
  dialog ("Put this parameter back into the cache key?") with an optional reason: requests that differ in it become
  different questions again, and the answers stored without it are purged, because callers with different values
  shared them.
- **The form**: "Parameter name" (exactly as in the query string, case-sensitive), an optional private note, and
  "Drop the answers stored with this parameter" (checked by default, so it takes effect at once). "Ignore it" saves it
  without a dialog. Only the answers keyed with that parameter are dropped, not the whole cache.
- **Splitting answers right now**: the parameters the key spread suspects (below), each with its path, its stored
  answers and how often they were reused. Press one to fill the form, then decide.
- **Commonly used as cache busters**: `t`, `_`, `ts`, `cb`, `cachebust`, `cache_bust`, `rand`, `random`, `nocache`
  and `v` (those not ignored yet). Press one to fill the form. Roxy ships the first nine already ignored (origin
  "shipped"), so on a new install only `v` is offered: it stays a suggestion because some Roblox APIs use `v` as a
  real version number. Check that a parameter really carries no meaning for your callers before you ignore it.

To undo an ignore, use "Stop ignoring". To undo "Stop ignoring", ignore the parameter again.

### Key spread

The key spread answers "why isn't something being reused?". A caller that adds a changing value to every request (a
timestamp, a random number) makes each request a different question. Answers pile up and are never reused, while
every other number looks fine. This card finds it.

The check reads the newest stored answers within a fixed memory budget (about 8 MiB: some 10,000 answers whose
questions are long id lists, more when they are short), so on a very large cache the oldest answers are left out of
it; a very long parameter value is compared by its first 40 characters and a fingerprint of the rest. Each row is one
endpoint path (up to 25, suspects first, then by stored answers):

- **Endpoint**: the method and path. A red "splitting for nothing" badge marks a suspect.
- **Stored answers**: how many answers sit behind the path, and their size.
- **Times reused**: how often those answers were handed out again. An amber 0 means none ever was.
- **Parameter splitting them**: up to four parameters with the number of distinct values each took. A suspect says
  "splitting these apart for nothing"; a row whose answers are being reused says that this is fine.

A row is a **suspect** when all three hold: at least 5 stored answers, its most varied parameter takes a different
value in at least 80% of them, and the answers were reused at most 10% as often as there are answers. These
thresholds are the CACHE-KEYSPLIT recommendation's settings, on the Recommendations page.

Actions:

- **Ignore** (suspects only) adds the splitting parameter to the ignored parameters at once, without a dialog, with
  the note "Ignored from the key spread", and drops the answers it split apart. Undo it with "Stop ignoring".
- **Purge** opens the purge dialog for every stored answer of that path.
- **Check now** (top right) checks again. The subtitle says when it last checked.

Under the list, "Already ignored" names the parameters that are left out of the key now.

A spread that is fine: an endpoint asked for many different ids (many answers, each reused). A spread that is a
problem: many answers, no reuse, and one parameter that is different every time. Ignoring it is safe only when that
parameter does not change the answer.

### Cache browser

Everything the cache holds, one row per distinct question, a page at a time. The subtitle says how many answers are
stored, how many are still fresh, and when the list was loaded.

| Column | Meaning |
|---|---|
| Question | The exact question: method, endpoint and every parameter. |
| Status | The status Roblox answered with: green for a 2xx, amber for a stored refusal such as a 404. |
| Size | Bytes this answer counts against the disk budget. |
| Times reused | How many times it was handed to a caller. The default sort, most first. |
| Stored | When it was fetched from Roblox. |
| Fresh until | When it stops counting as current, with "in N minutes" or "expired" under it. |
| Last reused | When it was last handed out. Hidden by default. |
| State | fresh (green), stale (still usable while Roblox fails; amber), expired (gray), or 429 marker (red). |
| Rule | The rule that decided its lifetime, or "default". Hidden by default. |

A **429 marker** is not an answer: it remembers that Roblox answered 429 to that exact request, so repeats wait for
the cooldown instead of reaching Roblox. It ends by itself, or with **Clear cooldowns and breakers** on the Upstream
page. A 429 that only burned one rotator exit leaves no marker.

The search box matches any part of the question (the endpoint or any parameter). Sort by any column but Status, State
and Rule, in either direction, and choose 10, 25, 50, 100 or 250 rows a page. This is the page's main table: its
search, sort and page live in the address bar (`/admin/cache?q=...`), so you can bookmark or share a view.

The buttons at the top of the card:

- **Purge matching** (enabled while there is a search) purges exactly the answers the search lists, through the purge
  dialog.
- **Purge expired** removes answers past their lifetime and their stale window at once, without a dialog. It is
  harmless: those answers were kept only in case Roblox failed, and their time for that is over.
- **Purge all** opens "Empty the whole cache?" (see Purge below).

**The inspector drawer.** Click a row to see one stored answer: its state and status (and a "fetched with the
credential" badge for an answer fetched with the Roblox credential, for an endpoint the Endpoint policy sends with
Roxy's account), when it was stored, until when it is fresh, until when it is usable if Roblox
fails, its lifetime, age, reuse count, size, which egress path fetched it ("Fetched via"), what Roblox said, its
rule, the parameters left out of its key, the request body of a POST, and the stored body itself (pretty printed when
it is JSON; very long bodies are cut). Anything in a body that looks like a secret is shown as `[redacted]`.

- **Fetch it again from Roblox** asks Roblox for this answer now and replaces the stored copy. It makes one call
  through the same pacing as callers' requests, counted as Roxy's own call (it does not count as caller demand), and
  it is written to the audit log. There is no dialog. Roxy refuses, and says why, for a 429 marker, for an answer
  fetched with the credential (purge it instead; the next caller fetches it again), when caching no longer applies to
  it, or when the rules or ignored parameters changed since it was stored. When Roblox does not give a usable answer,
  the stored copy is left alone.
- **Purge this answer** opens the purge dialog for this one answer.

### Purge

Use a purge after Roblox changed something you cache for a long time, or to test a rule. The form:

- **What to purge**: an endpoint pattern, a host, a cache rule id, search text (matched exactly as the browser
  matches it), or expired answers.
- **Value**: a pattern like a cache rule's, a host such as `games.roblox.com` (the field suggests your allowed hosts),
  a rule number, or search text. Leave it empty for expired answers.
- **Pattern type**: Wildcard or Regex, for an endpoint pattern only.
- **Expired answers**: "Also those still inside their stale window" also removes expired answers that could still be
  served while Roblox fails.

"Review the purge" opens the dialog "Purge these stored answers?": it names what will be purged and asks for an
optional reason. Every matching answer is deleted on both workers within a second, and the next caller asking for one
goes to Roblox again, so expect a few more upstream calls for a while. The purge is written to the audit log before
anything is deleted.

"Empty the whole cache" opens "Empty the whole cache?". You must type `purge all` before "Purge everything" works;
the reason is optional. Every stored answer is deleted at once, and a burst of upstream calls follows as callers ask
again. Settings, rules and statistics stay. Do this only when you must: on a busy server, an empty cache is exactly
the burst that earns Roblox 429s. "Purge all" on the Cache browser card opens the same dialog.

No purge asks for your second factor, and no purge can be undone: the answers come back as callers ask for them.

### On a phone

- The tiles show two per row; the three boxes under them and the two ratio charts stack.
- The request timeline of Cache settings becomes one column.
- The big tables keep these key columns: Per endpoint shows Endpoint, Requests and Hit ratio; Cache rules shows
  Pattern and TTL; the browser shows Question, Times reused and State. Tap a card for the rest.
- The small lists (Ignored parameters, Key spread) stack each row into labeled lines with its buttons underneath.
- Dialogs fill the width of the screen.

## Endpoints

The Endpoints page (`/admin/endpoints`) lists every endpoint template callers used in the range, with its volume,
cache hit ratio, Roblox 429s and latency, and opens any one of them in detail.

An [endpoint template](/admin/help#term-endpoint-template) is a Roblox path with its ids replaced by placeholders,
for example `games.roblox.com/v1/games/{universeId}/votes`, so every request of one kind is counted together.
Templates, paths, places and User-Agents come from what callers sent. The page always shows them as plain text,
never as links, so treat an odd one as text a stranger typed.

**When to use this page**

- You want to know which endpoints your games use most, and which ones grew or appeared recently.
- Roblox is rate limiting Roxy: find the endpoint that gets the 429s, and see its cache lifetime and its rules.
- One kind of request fails or is slow: its row shows its failures and p95, and its detail shows when it started.
- Before you add a cache rule, an endpoint rule or a block: see which rules already apply to the template.
- You want to see exactly what callers sent to one endpoint in the last 15 minutes.

### Time range on this page

- The main table and the drill-down follow the top bar's range (see
  [The time range and the comparison](#the-time-range-and-the-comparison)).
- The trend compares with the comparison chosen in the top bar, or with the previous period when none is chosen.
  The table's subtitle says which, for example "Last 24 hours: 42 endpoint templates; the trend compares with the
  previous period."
- Recent requests, concrete paths and the callers of the last 15 minutes come from the live records, which are kept
  15 minutes. Those parts always show the last 15 minutes, whatever the range.
- This page has no settings of its own.

### Endpoints (the main table)

One row per endpoint template seen in the range, busiest first.

Besides the usual table controls: **Search endpoint templates** (any part of a template), a **Host** filter (Any
host, or one of the allowed Roblox hosts) and a **Method** filter (Any method, GET, POST, PUT, PATCH, DELETE or
OPTIONS). This is the page's main table: the search, filters, sort, page and rows per page are kept in the page
address. A link such as `/admin/endpoints?q=games.roblox.com` opens the table already searched; other pages link here
that way.

Columns shown at first:

| Column | What it shows |
|---|---|
| Endpoint | The template. Press it, or anywhere on the row, to open its detail in a drawer. |
| Requests | Every caller request for it in the range. Under the number, the trend: for example "+12.0% vs before", or "new in this range". |
| Methods | Requests per HTTP method, busiest first, for example `GET:3 POST:1`. |
| Last request | When the newest request in the range arrived, with "2 minutes ago" under it. Exact while its live record is kept (15 minutes); later it is the start of its minute, hour, day or month, and says so ("to the hour"). |
| Last status | What Roxy answered that newest request with. Known only while its live record is kept; otherwise n/a. |
| Last caller | The client address of that newest request, with the same limit. |
| Hit ratio | Of the requests that looked in the cache, the share answered from it. |
| Roblox 429s | Times Roblox answered Roxy's calls for this endpoint with 429. |
| p95 | 95 out of 100 requests took at most this long. |

Hidden columns (the Columns menu shows them): **Trend** (the change in requests against the comparison, "New" when
there were none before), **Upstream calls** (calls Roxy sent to Roblox for callers, retries and background refreshes
included), **Failed**, **Last place** (the Roblox-Id of the newest request, see [place](/admin/help#term-place)),
**Previous** (requests in the comparison period), **Demand** (requests Roxy tried to answer, refusals left out),
**Avoided** (the share of demand that never reached Roblox; below 0% it says why), **p50** and **p99**.

Previous, Trend, Methods, Last request, Last status, Last caller and Last place cannot be sorted.

In an export, Previous and Trend stay empty, Last caller is hashed like every client address, and a very large
export is cut and says so.

What normal looks like: a handful of busy templates (the ones your games call) with a good hit ratio, Roblox 429s at
0 and few failures.

What to do when it looks wrong:

- **Roblox 429s above 0.** Open the row. Its Cache section shows the lifetime, and Rules that apply shows its bucket
  and rules. Follow [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us): a longer lifetime
  with a cache rule on the [Cache](#cache) page, or a lower bucket on the [Upstream](#upstream) page. The
  [Recommendations](#recommendations) page may already propose one.
- **A low hit ratio on a busy GET endpoint.** A short lifetime, or a parameter that changes on every request, splits
  the cache. The Cache page's key spread (`/admin/cache#spread`) names that parameter. Runbook:
  [Cache not working](/admin/help/runbooks#cache-not-working).
- **Failures or a high p95.** Open the row to see when it started, then the Upstream page's failures and breakers.
  Runbook: [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable).
- **A busy template you do not recognize, often marked "new".** Open it and read "Who calls it". When the callers are
  not your games, block it or limit it on the [Protection](#protection) page, or act on the caller from the
  [Clients](#clients) page.

### Recent requests

The newest requests of one endpoint, from every worker, in the last 15 minutes (at most 25).

- **Endpoint** chooses which one: the ten busiest templates of the range, the busiest first.
- **Open its drill-down** opens the template's own detail page.
- **Watch it live** opens the [Live](#live) page with this template in its "Endpoint contains" filter, which matches
  the requests of the template whatever ids they carry (see [Live requests (the list)](#live-requests-the-list)).

The table:

| Column | What it shows |
|---|---|
| When | When the request finished. Press it to open the request in the drawer (see [The request drawer](#the-request-drawer)). |
| Request | The method and the path, with the query under it. |
| Status | What the caller received; "Roblox said 503" under it when Roblox's own status was different. |
| Outcome | Served by Roblox, Served from the cache, Refused or Failed, with the [reason code](/admin/help#term-reason-code) under it. |
| Cache | The cache state (HIT, MISS, STALE and so on; see the Live chapter). |
| Took | How long Roxy took to answer. |
| Client | The caller's address, with its place under it. |
| User-Agent | The User-Agent header the caller sent. |

"No recent requests for this endpoint" means none arrived in the last 15 minutes. Each worker records at most 50
requests a second, so on a very busy proxy this list is a sample.

### Endpoint detail (the drill-down)

Everything about one template over the range. It opens in a drawer when you press a row of the main table. In the
drawer, **Open as a page** gives it a page of its own (`/admin/endpoints/template?template=...`, the range kept), with
an **All endpoints** button that goes back to the table searched for this template. Both have **Watch it live** and
**Reset its numbers**.

Two notes at the top say where the data comes from: concrete paths, recent requests and the callers of the last 15
minutes come from the live records; the callers over the range come from request samples, with addresses hashed.

1. **Totals in this range.** Eight tiles: Requests, Upstream calls for callers, Avoided upstream calls (percent),
   Cache hit ratio, Roblox 429s, Failed, Latency p95 and Caller 5xx. Each shows its change against the comparison
   (or the previous period) as an arrow and a percent: green when better, red when worse, gray for a measure with no
   better direction (Requests). A tile whose data was partly reset shows a note instead of a change, and an avoided
   share below 0% says why (how many upstream calls each request cost).
2. **Over time.** Two charts: Requests by outcome, and Latency percentiles (p50, p95, p99). With a comparison chosen,
   the earlier period is dashed.
3. **Roblox 429s.** How many in the range, split by egress, then the latest ones: when, through which egress, the
   [Retry-After](/admin/help#term-retry-after) Roblox asked for, and "the request", which opens that request. With
   none it says "None in this range. Good: Roblox did not ask Roxy to slow down for this endpoint."
4. **Cache.** The hit ratio ("n/a (no cache lookups)" when nothing looked in the cache), the lifetime
   ([TTL](/admin/help#term-ttl); "not cached" at 0), and the cache rule that sets it, linked to the Cache page's
   rules. "No rule: the default lifetime (cache_ttl_seconds) applies." means the Default cache lifetime setting
   decides.
5. **Who calls it.** Over the range: the places and the clients (as hashes of their addresses) among the sampled
   requests, with how many were sampled. Served and failed requests are sampled; refusals are not, so a caller Roxy
   only refused does not show here. In the last 15 minutes: the ten busiest addresses and the ten busiest places
   among the endpoint's newest 200 live records, with their counts.
6. **Concrete paths.** The real paths behind the template among the same newest 200 live records (up to 50 paths),
   with requests and when each was last seen. Useful to see which ids are asked for most.
7. **Recent requests.** The same table as the Recent requests card.
8. **Rules that apply.** Rules match real paths, so each is checked against the template (placeholders stand for any
   value) and against up to five concrete paths. For each one it lists what applies, each linked to the card that
   manages it:
   - an [endpoint block](/admin/help#term-endpoint-block) ("refused"), on the Protection page;
   - an [endpoint rule](/admin/help#term-endpoint-rule), a rate limit ("N per period per scope"), on the Protection
     page;
   - a cache rule ("kept" for how long), on the Cache page;
   - a routing rule (its mode), on the Upstream page;
   - the endpoint policy sending it with Roxy's account ("the credential may be used"), on the Endpoint policy
     page;
   - an [ignored path](/admin/help#term-ignored-path): "Roxy answers it without calling Roblox.", on the
     Protection page.

   A rule that is switched off says so. "No rule applies: the defaults are used." is common and fine. Under the list,
   a bucket override for the endpoint's host ("Its host's bucket") or for the endpoint itself ("Its own bucket")
   shows its rate per minute and its burst, linked to the Upstream page's buckets.

The endpoint policy's line shows for endpoints sent with Roxy's account. To see why, or to change it, open the
endpoint on the [Endpoint policy](#endpoint-policy) page.

### Resetting one endpoint's numbers

**Reset its numbers** (in the drawer or on the detail page) opens "Reset this endpoint's numbers". It deletes this
template's counters (its counts of Roblox's answers included), its Roblox 429 log rows, its
[cooldowns](/admin/help#term-cooldown) and
[breakers](/admin/help#term-breaker), and the cached answers it matches. Rules (blocks, limits, cache rules) and every
other endpoint stay.

The drawer previews the rows first and says whether a snapshot of metrics.db is taken. The reason is optional here,
no phrase has to be typed, and no fresh second factor is asked for. It is written to the audit log, and the charts
get a marker. Only the counters and the 429 log rows can come back, from that snapshot (see
[Statistics resets](#statistics-resets)). The cooldowns, the breakers and the cached answers live in other databases,
which are never copied; they do not come back, and the cache fills again as callers ask.

Think twice while Roblox is rate limiting this endpoint. Clearing its cooldowns lets Roxy call Roblox again at once,
and removing its cached answers turns the next requests into calls to Roblox. The runbook
[Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us) says not to clear cooldowns to make 429s
go away.

### On a phone

- The main table turns into one card per endpoint with Endpoint, Requests and Roblox 429s. Press the endpoint to open
  its detail.
- The request tables (in the Recent requests card and in the detail) turn into small cards: when, the request, its
  status and outcome, and the client. The cache state, the time taken and the User-Agent are in the request drawer:
  press the time. The same small cards appear inside the drawer on a wide screen.
- In the detail, the tiles sit two to a row, and the charts and the paired sections stack.
- The Endpoint selector of the Recent requests card fills the width; it and the card's buttons (and the drill-down's
  buttons) are large enough to tap.

## Clients

The Clients page (`/admin/clients`) shows who calls Roxy: by experience (place) and by address, how fast, how often
Roxy refuses them, and how bot-like each address looks. It is also where you act on one caller: ban it, let it
bypass the limits, block it, or start its counts over.

The words this chapter uses:

- A **place** is a Roblox experience. Roblox game servers send its place id in the `Roblox-Id` header on every
  HttpService call. It is a claim, not proof: any caller can send any number. It is still the one identifier that
  stays the same while a game's servers come and go.
- A **client** is one place or one IP address.
- **Rate1**, **Rate5** and **Rate60** count a client's requests in the last minute, the last five minutes and the
  last hour, counted back from now. Rate1 is the number an incident is judged on.
- **Refused** counts every request Roxy turned away, for any reason: limits, filters, bans.
- The **bot score** (0 to 100) adds up signals that a caller is a script rather than a game server.

Places are usually the view you want: one game reaches Roxy from hundreds of rotating server addresses, so the same
caller is one row under Places and a hundred rows under IP addresses. Use the addresses for anything that is not a
game: scripts, scrapers, your own testing.

**When to use this page**

- Traffic or refusals jumped (on the Overview or the Traffic page) and you want to know who is behind it.
- The [Under attack](/admin/help/runbooks#under-attack) runbook sends you here for the top addresses.
- A recommendation names a place or an address (PLACE-HEAVY, ABUSE-BOT and others).
- You want to know which game a place id belongs to: Identify an experience.
- You are about to turn on per-experience limits or a bot score block, and want to see who they would catch.
- You want to ban, bypass or block one caller, or give one caller a fresh start.

### How the page is laid out

Places first, then IP addresses, then "Identify an experience" and "Activity" side by side, then the bot score. The
page header has a Protection button (it opens the Protection page, where every ban, list and filter lives) and the
"How to read this page" panel. The numbers are read when the page loads; reload it or change the range to update
them.

### Time range on this page

The top bar's time range sets what the Places and IP addresses tables total (requests, refused, served, bytes, last
seen, peers) and what a client's view shows for "the range" (its totals, chart, refusals, peers and probes). Some
things ignore the range: Rate1, Rate5 and Rate60 (always counted back from now), a client's "last hour" and recent
requests, the bot score card (always the last 25 hours) and the Activity card. The comparison setting has no effect
on this page.

### Places

One row per place id seen in the range, busiest first. This is the page's main table: its search, sort and page live
in the address bar (`/admin/clients?q=...`), so you can share a view.

| Column | Meaning |
|---|---|
| Roblox-Id | The place id callers sent. Under it, in words: "banned" when a ban covers it, and "not a number: a forged header" when it is not digits (Roblox servers always send digits). |
| Experience | Its name, when the worker that answered the page looked it up in the last 10 minutes; otherwise "not looked up". Use Identify to look it up. |
| Requests | Its requests in the range. |
| Refused | Requests Roxy refused. |
| Refused % | The refused share. Hidden by default. |
| Rate1, Rate5, Rate60 | Requests in the last minute, 5 minutes and hour. Rate5 and Rate60 are hidden by default. |
| Top endpoint | The busiest endpoint of its busiest minute. |
| IPs | How many different addresses sent this place id in the range. |
| Last seen | Its newest request in the range, to the minute (to the hour or day for older, compacted data). |
| Served, Bytes | Requests answered (from Roblox or the cache) and bytes sent for it. Hidden by default. |
| Banned | Whether an active ban covers it. Hidden by default (the "banned" note under the id says it too). |

Every column sorts except Experience, Top endpoint, IPs and Banned, and the search looks for a place id. The note
under the table explains that IPs counts the address and place pairs Roxy keeps per minute, hour and day: under a
flood with more pairs than that, it is a lower bound.

A row named `other` is not a place: the note under it reads "Roxy's own sum of the quieter experiences beyond
'Experiences kept per period' (Data > Record caps)". When a period closes, Roxy keeps the busiest places one by one and
sums the rest into this row, so in a busy hour it can be the biggest row of the table. It has no drawer and no
actions.

**How to read it.** A real game shows many IPs (its servers), a steady Rate1 and few refusals. Worrying signs:

- One place takes most of the requests, or its Rate1 jumps far above its usual level. Identify it, open it, and look
  at its busiest endpoints and refusals. If one experience is crowding out the others, consider per-experience
  limits (below); the PLACE-HEAVY recommendation measures this.
- A place id that is not a number: a forged header, from a script rather than a game. To find who sent it, open the
  addresses with a high Places count under IP addresses: their "Places it called as" list shows the ids they sent.
- A high refused count: open it and read "Refusals by reason" to see which limit or filter is hitting it.

**Settings for this card** (folded; the same settings are also on the Protection page's Place limits card, and the
IP ranges on its Bot heuristics card too):

| Setting (key) | Default | What it does |
|---|---|---|
| Enforce per-experience limits (`place_limit_enabled`) | off | Refuses requests over the per-experience limit with 429 (reason `place_limit`). Off, places are only measured. |
| Place limit counts by (`place_limit_key`) | Place id and caller network | What one budget belongs to, for the per-experience limit and every Per experience endpoint rate rule: by default one budget per place id and caller network (a /24 for IPv4, a /48 for IPv6), so a forger only spends the share of their own network. "Claimed place id only" is a high-risk value: anyone can forge a game's id and use up its whole budget. |
| Per-experience limit (`place_limit_per_minute`) | 600 requests per minute | The budget per experience while the limit is on. |
| Roblox game server IP ranges (`roblox_egress_cidrs`) | empty | Address ranges known to belong to Roblox game servers, one per line ("PENDING owner verification": fill it in from Roblox's published ranges). Only callers inside them that also carry the game server signature get bot score credit, and the spam detectors give such a client a strike instead of a ban. |

Before turning per-experience limits on, sort Places by Rate1 at a busy hour and compare the biggest games with the
limit: a large legitimate game can be refused at its peak.

### IP addresses

One row per client address seen in the range, busiest first. The subtitle sums it up: precise but noisy for games, so
use it for scripts, scrapers and your own tests.

| Column | Meaning |
|---|---|
| IP | The address as Roxy saw it behind nginx. Under it: "banned" and "bypasses the limits" when they apply. |
| Requests, Refused | In the range. |
| Refused % | Hidden by default. |
| Rate1, Rate5, Rate60 | Requests in the last minute, 5 minutes and hour. Rate5 and Rate60 are hidden by default. |
| Top endpoint | The busiest endpoint of its busiest minute. |
| Places | How many different place ids it sent in the range. |
| Bot score | 0 to 100, with words: "looks legitimate" at or below the "Legitimate client score ceiling" (30), "in between" (amber), and "looks automated" (red) at or above the "Abusive client score floor" (80). |
| Last seen | Its newest request in the range. |
| Served, Bytes | Hidden by default. |
| Banned, Bypassed | Hidden by default (the notes under the address say it too). |

The bot score shows where it comes from. "this worker": the score of the worker that answered the page, from its own
memory of the address plus the address's newest request of the last 15 minutes. "recorded": with no request in the
last 15 minutes, the largest score any worker computed for it in its latest scored hour, within the last 25 hours. A
dash with "no recent request" means neither exists. The search looks for an address, and every column sorts except
Top endpoint, Places, Bot score, Banned and Bypassed.

A deep link `/admin/clients?ip=<address>` opens this table on that search (other pages link here that way).

As under Places, a row named `other` is "Roxy's own sum of the quieter addresses beyond 'IP addresses kept per
period' (Data > Record caps)". It is not an address, so it has no drawer.

**How to read it.** Worrying signs, and what to do:

- One address with a Rate1 far above the rest, a high refused count and a high bot score: a script or a flood. Open
  it, check its User-Agent and probes, then ban it or put it on the deny list. The
  [Under attack](/admin/help/runbooks#under-attack) runbook goes from the narrowest fix to the widest.
- One address with many Places: one machine sending many different place ids looks like a scraper cycling ids.
- A game's server addresses that never score below 15: with an empty "Roblox game server IP ranges" list, every
  caller gets the 15 points of "no Roblox game server signature" (see Bot score below). That is expected, not a
  problem.

### One client

Click a row in either table to open the client in a drawer; "Open as a page" gives it a page of its own
(`/admin/clients/ip/<address>` or `/admin/clients/place/<place id>`), a link you can keep or share. A place id that is
not a number cannot be opened: its row has no drawer and no actions (the table marks it "not a number: a forged
header"), and its own page address answers Not Found.

**The head** names the client (a place shows its looked-up name when there is one) and its state: "Banned until ..."
or "Banned permanently" or "Not banned"; for an address also "Bypasses the limits", "On the deny list", "Penalized for
Ns more" (a throttle penalty in progress) and its strikes with the rung of the throttle ladder it is on.

**The range** (titled with the range's name): requests, refused (with the share), served, bytes sent, and the busiest
endpoints (up to five), with a "Requests over time" chart of everything it sent, what was served and what was
refused.

**The last hour**: requests (and how many were refused), requests in the last minute, 5 minutes and hour (Rate1,
Rate5, Rate60), and the busiest endpoint.

**Refusals by reason**: each reason code, how many, and when it last happened. This is where you see which limit,
filter or ban turned the client away (the [Protection](#protection) chapter explains every reason).

**Bot score** (addresses only, this worker): the score out of 100, whether it carries a Roblox game server's
signature, and a table of the seven signals, each with its value (0 to 1) and its weight. Header order is not stored,
so that signal always reads 0 here. With no request from the address in the last 15 minutes there is no live score:
the section says its User-Agent is unknown. Under it: the score the fleet recorded in its latest scored hour (or "no
score in the last 25 hours"), the recorded hours in the range (the last twelve), and a link to how the score works.

**Places it called as** (an address) or **Addresses it came from** (a place): the busiest 50, each with requests,
refused and last seen, each a link to that client. One game normally comes from many addresses. One address calling
as many places is suspicious.

**Recent probes** (addresses only): up to ten requests in the range that looked for weaknesses, such as `.env` or
`wp-login` paths, with the reason, the path and the User-Agent.

**Recent requests**: up to ten requests of the last 15 minutes, with the method, the target, the status and how it
ended (from the cache, from Roblox, refused or failed), the address (for a place) and the User-Agent. Older single
requests are not kept; only the counts are.

At the bottom, "Audit entries that name this client" opens the audit log searched for it.

**The actions.** Ban, Bypass the limits, Add to the deny list, Block its Roblox-Id and Reset this client each open a
confirm dialog that lists what will happen, with an optional reason saved in the audit log; Identify runs at once and
Show in Live is a link. None asks for your second factor or a typed confirmation. After an action succeeds, the
drawer reloads to show the new state (the page of its own reloads).

| Action | For | What it does | How to undo it |
|---|---|---|---|
| Ban | address or place | Refuses every request from the address (before any limit is checked), or every request carrying this `Roblox-Id` from any address. Length: 1 hour, 1 day (preselected), 1 week, 30 days, or "Ban permanently". The field "Message kept with the ban (optional, shown on Protection > Bans as evidence; the caller never sees it)" is saved with the ban as its reason text. A banned caller gets the same 429 a throttled caller gets while "Disguise bans as throttles" is on (the default), otherwise a 403 "Access denied.". Banning an address that is already banned extends the ban. | "Lift this ban" on the Protection page's Bans card. |
| Bypass the limits | address | For the hours you give, the address skips the flood limit, the spam detectors, the emergency limit, the per-IP limit, place limits, the browser challenge, the bot score block, User-Agent rules, endpoint rules and the tarpit; a pause, bans, the deny list, ignored paths, request filters, endpoint blocks and Roxy's URL, host and credential smuggling checks still apply (the dialog lists both). For your own testing. The hours start at the "Default bypass expiry" (24). When that setting is 0, the hours start empty and the dialog says that an entry left empty never expires; type hours to make it end by itself. | It expires by itself; remove it earlier on Protection > Bypass. |
| Add to the deny list | address | Refuses every request from the address before any limit, like a ban without hit counts. Leave the hours empty to keep it until you remove it. | Remove it on Protection > Deny and allow lists. |
| Block its Roblox-Id | place | Adds a request filter that refuses every request whose `Roblox-Id` is exactly this place id. Without a message the caller sees an ordinary slow-down answer, so a scraper cannot tell it was singled out. It does not expire. | Remove it on Protection > Request filters. |
| Identify | place | Looks the place up (see Identify an experience) and shows the answer in the view. | Nothing to undo. |
| Reset this client | address or place | Deletes its activity rows, strikes, limiter state and events, so it starts again with a full allowance. Bans, rules and settings stay. The dialog counts the rows first; no phrase to type, and the reason is optional. | Cannot be undone from the dashboard (Roxy snapshots metrics.db first when there is room; see [Statistics resets](#statistics-resets)). |
| Show in Live | address or place | Opens the Live page filtered to this client ([Live](#live)). | |

Place ids are claims. A real game's servers keep sending the same id; a forger can change it. Roxy never bans a
place by itself; a place ban or block is always your decision.

### Identify an experience

Paste a place id from a `Roblox-Id` header to find out which experience it is and who owns it. Choose whether the
number is a place id or a universe id, and press Identify. This uses Roblox's public endpoints through Roxy's own
upstream pacing, so it needs no extra credentials and never uses the Roblox credential. Answers are kept for 10
minutes on the worker that fetched them (the answer says when it came from that cache).

The answer shows the experience's name and universe, the owner (name, type and id), the place id, when it was
created, visits, players now, the maximum players, favorites, the start of its description, and the experience's and
owner's Roblox addresses as text with a Copy button (the dashboard never links to another site from data). An amber
warning appears when the experience was created less than 7 days ago with fewer than 1,000 visits: that is
consistent with a throwaway place made to point traffic at this proxy rather than a real game using it.

Errors say what went wrong in plain words: the id is not a number, Roblox returned no experience (or no universe) for
it, or Roblox could not be reached or answered with an error (try again shortly). A deep link
`/admin/clients?lookup=<place id>` fills the form.

### Activity

What Roxy keeps per place and per address: every request is counted under its place and its address a minute at a
time, and old minutes are compacted into hours and days. The tables above read these rows for any range. The card
lists the six settings that govern them, each a link to the Data page card where it is changed:

- Per-client minute retention (3 days), Per-client hour retention (90 days) and Per-client day retention (730 days):
  how long each level is kept.
- Per-client activity tracking (on): whether these rows are written at all. When it is off, no new rows are written
  and the tables stop filling.
- IP addresses kept per period and Experiences kept per period (500 each): how many clients are kept individually in
  each minute, hour and day; the rest are summed into the `other` row.

**Clear client activity** opens "Clear every client's activity?". It deletes the per-place and per-address activity
rows (requests, refusals, rates, peers) and the recorded bot scores. Bans, bypass entries, rules and strikes stay,
Traffic totals are not touched, and the tables start filling again with the next request. The dialog counts the rows
first; you must type `reset activity` and give a reason. It does not ask for your second factor and cannot be undone
from the dashboard: Roxy snapshots metrics.db first when there is room, and putting it back is a restore (see
[Statistics resets](#statistics-resets)). To start one client over instead, use "Reset this client" in its view.

### Bot score

The bot score adds up seven signals that a client is a script rather than a game server. Each signal is between 0 and
1; the score is 100 times their weighted average, so it runs from 0 (looks like a game server) to 100 (looks like a
script). No single signal proves anything, which is why they are combined. The score blocks nothing unless you set a
block threshold.

**The signals and their weights now**, with each one's share of the score:

| Signal | Default weight | It is 1 (or close to it) when |
|---|---|---|
| Library or missing User-Agent | 25 | The User-Agent is a programming library (python-requests, curl, Go-http-client) or empty. |
| No Roblox game server signature | 15 | The request lacks a `Roblox-Id` header plus a Roblox User-Agent, or comes from outside the Roblox game server IP ranges. |
| Probe history | 25 | The client sent probe requests in the last 24 hours (five or more makes it 1). |
| Refusal ratio | 15 | Roxy refused a large share of its requests in the last hour. |
| Timing regularity | 10 | The gaps between its requests are almost identical, like a script on a timer (over at least 50 requests). |
| Unusual header order | 5 | Its header order matches no known client family. |
| Cache busting | 5 | Its query values are different on almost every request (measured over its last 200 requests with a query, once it has sent at least 20). |

The default weights add up to 100, so each weight is also its share. Two examples with them: a well-behaved script
using python-requests from an ordinary address scores 40 (library 25, no signature 15): "in between". With the Roblox
game server IP ranges list empty, every caller gets the no-signature signal, so even a real game server starts at 15.

**Recorded scores, last 25 hours (every worker)**: how many clients were scored, how many "look legitimate" (at or
below the ceiling), how many are "in between", how many "look abusive" (at or above the floor), and "Blocking": off,
or how many are at or above the block threshold.

**Settings for this card** (open on this card):

| Setting (key) | Default | What it does |
|---|---|---|
| Abusive client score floor (`bot_score_abuse_min`) | 80 | The ABUSE-BOT recommendation looks at clients at or above this score that send more than 500 requests an hour (that rule's own setting). It also sets the "looks automated" words on this page. It blocks nothing. |
| Block clients at or above bot score (`bot_score_block_threshold`) | 0 (off) | Refuses requests from clients whose score is at or above this value with a 403 and reason `bot_score`. Addresses on the bypass list are never blocked this way. 0 turns blocking off. |
| Legitimate client score ceiling (`bot_score_legit_max`) | 30 | Clients at or below this count as legitimate: the THROTTLE-TUNE recommendation uses it to judge whether the per-IP limit hurts real users, and ABUSE-DIST ignores a swarm made only of such clients. It also sets the "looks legitimate" words on this page. It blocks nothing. |
| Bot score weight: cache busting (`bot_weight_cache_busting`) | 5 | The weight of that signal. |
| Bot score weight: unusual header order (`bot_weight_header_order`) | 5 | The weight of that signal. |
| Bot score weight: library or missing User-Agent (`bot_weight_library_ua`) | 25 | The weight of that signal. |
| Bot score weight: no Roblox game server signature (`bot_weight_no_roblox_signature`) | 15 | The weight of that signal. |
| Bot score weight: probe history (`bot_weight_probes`) | 25 | The weight of that signal. |
| Bot score weight: refusal ratio (`bot_weight_refusals`) | 15 | The weight of that signal. |
| Bot score weight: timing regularity (`bot_weight_timing`) | 10 | The weight of that signal. |

A weight only matters relative to the other six; 0 ignores a signal. The ceiling must stay below the floor: Roxy
refuses to save a "Legitimate client score ceiling" at or above the "Abusive client score floor". The same settings
are also on the Protection page's Bot heuristics card. These settings apply at once and none asks for your second
factor.

**Before setting a block threshold**, read the "Recorded scores" box: everyone at or above the value you are about to
choose would be refused. Low values catch ordinary game servers. After turning it on, watch the refusals with reason
`bot_score` (the Protection page's Refusal reasons card, or "Refusals by reason" in a client's view), and fill in the
Roblox game server IP ranges first if you can, so real game servers lose their 15 points.

### On a phone

- The Places and IP addresses tables show each row as a card with three columns: the place id or address, Requests
  and Rate1. Tap a card to open the client. A row that cannot be opened (a forged place id, the `other` row) shows
  only those three.
- "Identify an experience" and "Activity", side by side on a wide screen, stack one above the other.
- In the bot score card, the signal table and the recorded scores stack.
- In a client's view, the facts become one column; the dialogs fill the width of the screen.

## Protection

The Protection page (`/admin/protection`, keys `g` then `p`, in the Defense group of the sidebar) decides which callers
Roxy turns away and how: limits, bans, lists, rules, filters, spam detectors and the tarpit. Almost every refusal
Roxy makes before a request reaches the cache or Roblox comes from a check this page shows, and the settings of
those checks are edited here.

**When to use this page**

- An alert, the Overview or the Traffic page shows a jump in refused requests, and you want to know which check
  refused them and who sent them.
- A caller (a script, a game, a scanner) misbehaves and you want to slow it down, limit it or ban it.
- Someone reports endless 429 answers and you want to know why (a throttle, a disguised ban, a request filter).
- A recommendation such as ABUSE-SPAM, ABUSE-DIST, FILTER-REMOVE, THROTTLE-TUNE or TARPIT-TUNE points here.
- You load-test Roxy from your own address and need it to skip the limits for a while.
- You are under attack. Follow the [Under attack](/admin/help/runbooks#under-attack) runbook; it uses this page.

### How the page is laid out

The page is long, so it opens with an **On this page** list (fold it away with its arrow; the browser remembers your
choice) that links the cards in six groups: Overview, Limits, Bans and lists, Rules and filters, Detectors, and
Tarpit. The seven detector cards have no link of their own; they sit right under Spam detectors. This chapter
follows the same order. Only the Pipeline card loads with the page; every other card loads when you scroll to it,
which keeps the page quick on the small server.

Tables, drawers and settings work as on every page (see
[How every dashboard page works](#how-every-dashboard-page-works)); in most tables a row's drawer is where you change
or remove it. Admin text (patterns, notes, messages) is shown as plain text too, exactly as stored. Besides:

- **Reasons.** Most dialogs have a Reason box. It is optional when its label says "optional, saved in the audit
  log" and required when it says only "saved in the audit log"; whatever you type goes to the [Audit](#audit) page.
  A change reaches every worker within about a second.
- **Settings.** The "Settings for this card" list starts open on Throttle, Request limits, Place limits, Spam
  detectors, Bot heuristics, Challenge and Tarpit, and folded on the other cards.
- **Fresh second factor.** Three actions on this page ask you to confirm it is you: adding a network to the admin
  allowlist, removing one, and arming the spam detectors.
- **Clear buttons** on seven cards (Refusal reasons, Throttle, Ladder, the Attempts tabs of Request filters,
  Endpoint blocks and Endpoint rules, Tarpit) delete statistics only, never rules, bans or settings. Each asks for
  a reason and a typed phrase such as `reset refusals`, leaves a marker on the charts, and cannot be undone from
  this page. Like every statistics reset it first takes a snapshot where it can (see
  [Statistics resets](#statistics-resets)).

### Time range on this page

The time range in the top bar sets every count on the page: the Pipeline, Refusal reasons, "Throttled in this
range", new strikes per rung, the Hits columns of the rule tables and lists, the attempts tabs, detector decisions
and the first three tarpit tiles. These show the present moment instead: Throttled
now, the Strike board, the emergency limit list (since it was switched on), bans in force and the tarpit's slots in
use. A ban's Requests refused counts since the ban was made, the tarpit's "Held in the last hour" tile looks back
from now, and "This worker since it started" on the Pipeline card and "Who is held" on the Tarpit card cover one
worker since it started. The comparison (Compare with, or the C key) only affects the Detector decisions over
time chart; the other cards on this page have no comparison.

### The order of the checks

Every proxy request walks through the same steps, in this order. The first check that refuses decides the answer;
the checks after it never see that request. So a throttled client that also asks for a non-Roblox URL gets the
throttle's 429, not a 404, and each refusal is counted once, at the check that stopped it.

1. **nginx**, the web server in front of Roxy, applies its own generous limits per address (20 requests a second
   with a burst of 100, and 50 connections). Changing them is a code change and a deploy.
2. **Size and method limits.** A URL, a header, too many headers or a body over the Request limits settings is
   refused at once (414, 431 or 413), and so is a method Roxy does not take (405). Each is logged as a probe and
   counted as a refused request (the Request limits card and the Pipeline's "Refused elsewhere" count them).
3. **OPTIONS** requests are answered at once (204) and never checked or logged as probes.
4. **The checks** below, in the order the Pipeline card draws them.
5. **After a refusal**, the tarpit may hold the answer for a while (see [Tarpit](#tarpit)). A per-IP throttle refusal
   can instead be answered from a fresh cached copy when "Serve throttled callers from cache"
   (`cache_serve_throttled`, Cache page, off by default) is on and no later check would refuse the request.
6. **After an allow**, the cache or Roblox answers. When the answer tells the caller to wait (a Retry-After on a
   Roblox cooldown, an "upstream busy" or a "queue full" answer), a caller that retries the same request before
   that time can get a short random delay (the tarpit's "Jitter early retries during a Roblox cooldown" switch, off
   by default).

| Step | Check | Refuses with | Bypass skips it | Tarpit category | Managed on |
|---|---|---|---|---|---|
| 1 | Pause | 503 and the pause message | No | never held | Pause button in the top bar |
| 2 | Bans and deny list | 403 "Access denied.", or a normal-looking 429 while bans are disguised | No | Banned or denied client | Bans; Deny and allow lists |
| 3 | Bypass | nothing: it only marks bypass addresses | | | Bypass |
| 4 | Flood limit | 429 | Yes | Per-IP rate limit | Request limits |
| 5 | Spam detectors | a normal-looking 429, for clients a detector flagged with the strike or tarpit action | Yes | Flagged by a spam detector | Spam detectors |
| 6 | Throttle-all (emergency limit) | 429 with the emergency message | Yes | Global throttle-all | Emergency limit |
| 7 | Per-IP throttle | 429 with the ladder rung's message | Yes | Per-IP rate limit | Throttle, Ladder |
| 8 | Place limit | 429 | Yes | Per-IP rate limit | Place limits |
| 9 | Browser challenge | a 403 puzzle page, browsers only | Yes | never held | Challenge |
| 10 | Bot score block | 403 "Access denied." | Yes | Banned or denied client | Bot heuristics |
| 11 | User-Agent rules | 429 with the rule's message | Yes | Hit a client (User-Agent) rule | User-Agent rules |
| 12 | Ignored paths | 404, not logged | No | never held | Ignored paths |
| 13 | Unsafe URL | 404, logged as a probe | No | Not a Roblox URL | Security page, Probes |
| 14 | Not a Roblox URL / host allowlist | 404 "Not a Roblox URL", logged as a probe | No | Not a Roblox URL | Security page, Probes |
| 15 | Auth smuggling (a Roblox login cookie sent through Roxy) | 400, logged as a probe | No | Sent a ROBLOSECURITY cookie | Security page, Probes |
| 16 | Request filters (header rules) | a normal-looking 429, or the filter's own reply | No | Caught by a Request Filter | Request filters |
| 17 | Endpoint blocks | 403 with the block's reply | No | Blocked endpoint | Endpoint blocks |
| 18 | Endpoint rate rules | 429 with the rule's reply | Yes | Per-endpoint rate rule | Endpoint rules |

Three details explain numbers you will see:

- **Rate limits only spend what they keep.** Flood, throttle-all, per-IP, place, User-Agent and endpoint limits are
  decided together. A request that one check refuses does not use up the allowance of the others, except the flood
  limit, which counts every request.
- **Cheap limits first.** The four checks marked "Uses patterns" (User-Agent rules, request filters, endpoint
  blocks, endpoint rules) can match regexes you wrote. While any of their rules is a regex, a request the cheap
  limits refuse is never matched against them. The Pipeline card counts these, for one worker, as "Pattern checks
  skipped (a cheap limit refused first)".
- **Degraded mode.** If the shared database that holds the limits cannot be used, each worker keeps limiting on its
  own with its share of every limit, and the tarpit holds nothing. The Pipeline card counts these requests, for one
  worker, as "Checked while shared state was unavailable".

### Which tool for which problem

Start narrow and widen only when the narrow tool is not enough. Every tool here can be undone.

| Problem | How you notice it | First tool | If that is not enough | Avoid |
|---|---|---|---|---|
| One abusive address | It tops "Clients refused most", sits on the last rung of the Strike board, or its Rate is high on Clients | A ban on the address (Bans, Type Address), a few hours to a day | The deny list with an expiry, for a network you never want; arm the spam detectors, so SPAM-RATE and SPAM-REFUSED ban such addresses on their own | A permanent ban: addresses change hands |
| A bot spread over many addresses | SPAM-DIST decisions and an ABUSE-DIST recommendation; on Live, many addresses with one User-Agent on one endpoint | A User-Agent rule with Scope "Shared" (one allowance for every address using that User-Agent) | A request filter if it sends a telltale header; a ban on its network (Type Network) if it comes from one range; the emergency limit for a while | Raising the IPv6 grouping prefix above 64; per-address bans one by one |
| One game hammering one endpoint | Clients > Places shows one place far ahead; a PLACE-HEAVY recommendation | An endpoint rule on that endpoint with Scope "Per experience" | Place limits for the whole game (counted by place and caller network) | Banning the place: anyone can send a game's Roblox-Id, and a place ban refuses that game's real servers too |
| A scraper of one path | SPAM-ENUM decisions; one client, one endpoint, many different ids | An endpoint rule with Scope "Per IP" on that path | An endpoint block with a reply, if nobody legitimate needs it; the browser challenge if it scrapes from a browser | Banning on SPAM-BUST alone: for cache busting, ignore the busting parameter on the Cache page instead |
| A header signature | Security > Fingerprints shows a header or value only the bad client sends | A request filter, tried in its Tester first (the tarpit holds filter refusals by default) | A ban on the addresses that keep coming back | A filter that also matches Roblox game servers: test it with a real game server's headers |
| A flood | A sudden jump in requests; Flood limit and SPAM-RATE counts climb | Nothing at first: the flood limit refuses any address over 300 requests a minute. Ban the worst addresses | Lower "Requests per window" or the flood limit; arm the detectors; the emergency limit; pause as the last resort | Leaving the emergency limit on after the flood ends |
| Scanners probing paths | Unsafe URL and Not a Roblox URL counts; Security > Probes | Nothing: they get 404 and the tarpit holds them by default; SPAM-PROBE bans them once armed | Add harmless paths every browser asks for to Ignored paths | Switching off "Hold probe refusals": scanners then try thousands of paths quickly |

### Pipeline and refusal reasons

#### Pipeline

What every request went through in the selected time range, check by check. Open it first when refusals jump.

At the top, four totals: **Requests checked** (OPTIONS answers are left out), **Passed every check**, **Refused by a
check below** (one of the 18 checks), and **Refused elsewhere**: refusals no check in the list made, that is the
request size and method limits (a body, headers or URL too long, a method Roxy does not take; see Request limits). A
request the guard in front of Roblox refused for a credential marker counts under Auth smuggling, and a host the
egress refused under Not a Roblox URL. Refused elsewhere normally stays small: scanners send the odd oversized or
odd-method request.

Then one row per check, numbered in order. Each row shows the check's name (a link to the card that controls it;
the three probe checks link to Security > Probes, and Pause names the top bar button instead), a badge for its
kind ("Fixed check", "Rate limit" or "Marks the request"), "Bypass skips it" where that applies, "Uses patterns" for
the four rule checks, the reasons it refuses as, how many requests it refused with its share of
all refusals, and a bar scaled to the busiest check. "How the pipeline works" repeats the rules above.

Below the list, **Rule rows matched** counts how often rows of each list (User-Agent rules, request filters,
endpoint blocks, endpoint rules, deny list and bypass entries, bans) matched a request, whatever the verdict.
**User-Agent rules and the ladder** counts what the User-Agent rules allowed and refused and the new strikes per
rung (these arrive once their minute has closed). **This worker since it started** gives one worker's own counters:
Checked, Allowed, "Checked while shared state was unavailable", "Pattern checks skipped (a cheap limit refused
first)" and "Bans made by the ladder"; everything above it covers every worker. The card refreshes itself at most
once a minute.

**Normal**: most refusals sit at Per-IP throttle; a steady trickle at Unsafe URL and Not a Roblox URL (scanners);
Refused elsewhere small; "Checked while shared state was unavailable" at zero.

**Worrying, and what to do**:

- Flood limit refusals climbing: one address sends over 300 requests a minute. Find it under Refusal reasons >
  Clients refused most and ban it; see [Under attack](/admin/help/runbooks#under-attack).
- Bans and deny list climbing fast: banned clients keep retrying. That is harmless while the tarpit holds them.
- Refused elsewhere growing: someone sends oversized or odd-method requests; the Request limits card says which
  limit, and Refusal reasons lists them.
- The leak guard never shows here: a leak guard trip is a failure, not a refusal. It appears as "Leak guard" on
  Refusal reasons; follow [Leak guard](/admin/help/runbooks#leak-guard).
- "Checked while shared state was unavailable" above zero: the shared database was locked or the disk was full.
  Follow [Caller errors](/admin/help/runbooks#caller-errors) and
  [Disk full or database large](/admin/help/runbooks#disk-full-or-database-large).

#### Refusal reasons

Every reason Roxy refused or failed a request in the range, with where the text the caller got came from. Several
checks answer with the same 429; the reason says which one fired. Two tabs:

**By reason**, most frequent first: Reason (plain words, with the code below), Count, Status (of the newest one),
Last path, Unique clients, Last seen, and Message. Message says whose words the callers got, with counts: a custom
message an admin wrote, the default text, Roxy's own failure text, or Roblox's own body passed on. Unique clients
is a lower bound: under heavy load some refusals are recorded without their client (the hidden Unattributed
column counts them). First seen is hidden too; the column menu shows it.

This tab lists failures as well as refusals, so it doubles as a map to the runbooks:

| Reason you see | Means | Go to |
|---|---|---|
| Roblox cooldown | Roblox asked Roxy to wait, and no stored answer could be served meanwhile | [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us) |
| Upstream busy, Upstream queue full | Roxy's own limits on calls to Roblox were full, so the request could not wait its turn | [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable) |
| Roblox server error, Roblox timed out, Could not reach Roblox | Roblox is slow or down | [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable) |
| Deadline passed | The request waited longer than its time limit | [Caller errors](/admin/help/runbooks#caller-errors) |
| Egress switched off | No path to Roblox is enabled | [All upstream paths unavailable](/admin/help/runbooks#all-upstream-paths-unavailable) |
| Credential unavailable | The one Roblox credential cannot be used now | [Credential cooling down](/admin/help/runbooks#credential-cooling-down) |
| Leak guard | A request tried to carry the credential | [Leak guard](/admin/help/runbooks#leak-guard) |
| Shared state unavailable | The shared database could not be used | [Caller errors](/admin/help/runbooks#caller-errors) |
| Internal error | A bug | [Unhandled errors](/admin/help/runbooks#unhandled-errors) |

**Clients refused most**: the address table of the [Clients](#clients) page, sorted by refusals, ten rows at first:
IP, Refused, Refused %, Requests, Top endpoint, Last seen (Bot score is hidden). Press a row to open that address in
the Clients drawer, with its requests, its strikes and the ban and bypass actions.

**Normal**: Per-IP throttle at the top; game server addresses with a small Refused %. **Worrying**: one address
with many requests and a Refused % near 100 (a script ignoring 429s: ban it); a known game's servers with many
refusals (your limits may be too tight: look for a THROTTLE-TUNE recommendation).

**Clear refusal records** forgets each reason's newest status and path, its clients, first and last seen and the
message split; the attempts tabs of the endpoint blocks, endpoint rules and request filters start again too. The
counts per reason stay (they belong to the traffic totals). Typed phrase: `reset refusals`.

### Limits

#### Throttle

The per-IP limit, said in words from the live settings: "Each client may make 10 requests per 50 seconds, with
smooth pacing: a burst of 10, then one more request every 5 seconds." Cache hits count toward it by default (the
owner's choice: serving them still costs Roxy work). A client over the limit gets 429 and a
[strike](/admin/help#term-strike).

Three tabs:

- **Throttled now**: clients serving a penalty right now, longest first: Client, Strikes, Rung, Time left. Press a
  row to open the client's strike drawer (see Strike board).
- **Throttled in this range** (v1's "Throttled IPs"): Client, Times throttled, Last throttled, most often first.
  "Clear throttled clients" starts the list again (strikes and running penalties stay; typed phrase
  `reset throttled_clients`).
- **Reset**: deletes limiter counters (per-IP, flood, emergency limit, User-Agent and endpoint rules) and strikes.
  Unlike forgiving, a reset also ends running penalties. "Reset one client" asks for the address (or IPv6 network)
  and a reason. "Reset every client" says how many rows it deletes, asks for a reason and the typed phrase
  `limiter state`. Bans, rules, settings and the tarpit's own bookkeeping are left alone. Use it after a mistake
  (your own load test), not during an attack: abusers get a clean sheet too.

| Setting | Key | Default | Note |
|---|---|---|---|
| Requests per window | `allowed_requests_per_minute` | 10 | Per window, not per minute (the key keeps its v1 name). High risk at 1,000 or more |
| Throttle window length | `throttle_reset_duration` | 50 seconds | Also the base penalty a rung multiplies |
| Window algorithm | `throttle_window_mode` | Smooth pacing | Fixed window is v1's, which lets short bursts of twice the limit through |
| Count cache hits toward the per-IP limit | `throttle_count_cache_hits` | On | Off: only requests that miss the cache count |
| Escalating throttles (strike ladder) | `throttle_escalation_enabled` | On | Off: every penalty is one window long |
| Strike decay time | `throttle_strike_decay_seconds` | 1,800 seconds | Good behavior this long drops one rung. 0 (never) is high risk |
| Retrying while throttled adds a strike | `throttle_strike_on_retry` | On | At most one extra strike per window |
| Forget idle clients after | `stale_ip_duration` | 60 seconds | Keep it at or above the window length |
| Emergency limit: requests per period | `global_throttle_limit` | 1 | Used only while the emergency limit is on |
| Emergency limit period | `global_throttle_period` | 60 seconds | Used only while the emergency limit is on |

**Normal**: a few clients throttled at busy times, each once or twice. **Worrying**: the same game server addresses
throttled again and again. Their games need more: raise "Requests per window" a little (an endpoint rule cannot
help here, because endpoint rules are only ever stricter than the per-IP limit). A THROTTLE-TUNE recommendation says
when legitimate clients are throttled too often.

#### Ladder

Repeat offenders climb a ladder of longer penalties. Each throttle gives a strike; the number of strikes picks the
[rung](/admin/help#term-rung); a rung's [multiplier](/admin/help#term-multiplier) times the throttle window is the
wait. The subtitle says "Escalation on: 4 rungs" or "Escalation off".

**What happens to a repeat offender, using your current ladder** turns the saved ladder into plain steps. With the
shipped ladder and the 50-second window: the 1st strike waits 50 seconds, the 2nd 1 minute 40s, the 3rd 3 minutes
20s, the 4th and later 6 minutes 40s (the last rung repeats), each with its own message; 30 minutes of good behavior
drops one rung. The simulation follows the saved ladder, so save to see a change.

**The editor** has one row per rung (rung 1 is a caller's first strike), each with the number of new strikes it got
in the range:

- **Multiplier**: 4 makes that rung's wait 4 times the throttle window. Up to 1,000.
- **Action**: Throttle, or Ban the IP. A ban rung bans the address (never a place) for its **Ban minutes**; these
  bans appear under Bans with the detector `throttle_ladder`.
- **Message shown to the caller**: write it for a person reading an error. It is what changes behavior.
- **Note (private)**: for you.

Add a rung (at most 12), remove one with its X, then **Save ladder** (the whole ladder is saved at once; "Unsaved
changes" warns you before then). **Restore defaults** puts back the four shipped rungs (1, 2, 4 and 8 times the
window) and their messages; callers keep their strikes. Both take an optional reason. To undo a save, edit again or
restore the defaults. "Clear stats" resets the new strikes per rung and the User-Agent rules' allowed and refused
counts (typed phrase `reset throttle_rule_hits`).

**Normal**: most new strikes on rung 1. **Worrying**: many new strikes on the last rung, the same callers ignoring
every warning. Make sure the messages say what to do; add a ban rung, or ban those addresses.

#### Strike board

Callers carrying strikes, worst first: Client, Strikes (after decay), Rung ("2 of 4", highlighted on the last
rung), Status ("Serving 1 minute 40s" or "Free to call"), Drops a rung in ("never" when decay is off) and Last
strike. The rung's multiplier and message are hidden columns.

Press a row for the client's drawer: its strikes, rung, the message it was told, status, last strike and when it
drops a rung, with links to its live requests and to the client on the Clients page, and two forms:

- **Forgive this client**: wipes its strikes, so its next throttle uses rung 1. A running penalty still runs out.
- **Reset its limits**: deletes its limiter counters and strikes; the running penalty ends now. Needs a reason.

**Forgive everyone** wipes every caller's strikes (running penalties still run out) and writes the count to the
audit log. Forgiving cannot be undone, but strikes come back with the next throttle.

**Normal**: a short list that empties as strikes decay. **Worrying**: a game server address that stays on the last
rung; forgive it and look at the per-IP limit on the Throttle card.

#### Emergency limit

The [emergency limit](/admin/help#term-emergency-limit) (also called throttle-all) is a softer brake than pausing:
every address gets a few requests per period and the rest get 429. Bypass addresses are never limited, and the
other limits still apply. The card says whether it is on, the limit, since when, how many requests it refused, and
the exact text callers get over the limit.

**Turn the emergency limit on** (or off) opens the same dialog as the Emergency limit button in the top bar. It asks
for Requests per IP, Per (seconds), a message shown to callers (empty sends the default pause message) and an
optional reason. Requests per IP and Per (seconds) are the two emergency limit settings of the Throttle card, so
the values you type are saved as those settings. While it is on, a banner on every dashboard page shows the limit,
the refusals and what callers see, with a Turn off button.

Below, **who the emergency limit refuses right now**, refreshed while the page is open: Client, Refused and Requests
(since the limit was switched on), Rate (requests in the last minute, with the last 5 minutes and hour below it),
Top endpoint, Last seen and Refused now. "Requests this window" and "Window ends in" are hidden columns.

**Normal**: off. **While it is on**, watch the Rate column: it is highlighted as a warning from 10 requests a minute
and as bad from 60. Switch the limit off as soon as rates calm down; the defaults (1 request per 60 seconds) refuse
almost everything.

#### Request limits

The flood limit is an absolute ceiling per client address that counts every request, cache hits included: a safety
net normal callers never reach. The size limits refuse a request before anything else looks at it (413 for a large
body, 431 for large or many headers, 414 for a long URL). The card lists what each one refused in the range, and
when last: Flood limit, Body too large, Headers too large, URL too long, and Method not allowed (405, a method the
route does not accept).

Size and method refusals happen before the request reaches the proxy. Each one is counted here (and as a refused
request on the Overview and the Pipeline's "Refused elsewhere"), and logged as a probe: Security > Probes lists it
with its address and path.

| Setting | Key | Default | Note |
|---|---|---|---|
| Flood limit per IP | `flood_limit_per_minute` | 300 per minute | High risk at 10,000 or more. Keep it well above the per-IP rate |
| IPv6 grouping prefix | `ipv6_limit_prefix` | 64 | IPv6 addresses sharing this many leading bits count as one client. High risk above 64 |
| Largest request body | `max_body_bytes` | 2 MiB | Cannot exceed nginx's 2 MiB |
| Largest single header | `max_header_bytes` | 8 KiB | Cannot exceed nginx's 8 KiB |
| Most request headers | `max_header_count` | 100 | |
| Longest URL | `max_url_length` | 4,096 characters | |

**Normal**: zero flood refusals; a few size refusals from scanners on Security > Probes. **Worrying**: flood
refusals from a game server address, or many 413 or 414 probes from one game's servers (it sends long id lists; ask
its developer to split them).

#### Place limits

A [place limit](/admin/help#term-place-limit) caps how much one experience (its Roblox-Id header) may send across
all of its servers, which per-address limits cannot do. Off by default: Roxy only measures places. The card says
whether it is on and the limit, and what it refused in the range. See each experience's traffic on
[Clients](#clients) > Places.

Its settings are the ones of the Clients page's Places card, explained under [Places](#places) in the Clients chapter:
Enforce per-experience limits (`place_limit_enabled`, off), Place limit counts by (`place_limit_key`, place id and
caller network; "Claimed place id only" is high risk, because a forger could use up a real game's budget) and
Per-experience limit (`place_limit_per_minute`, 600 per minute). Roblox game server IP ranges (`roblox_egress_cidrs`)
is shown here read-only and edited on Bot heuristics.

**Worrying** (once on): place limit refusals for a big, legitimate game at its busy hours; raise the
per-experience limit.

### Bans and lists

#### Bans

Bans in force, with countdowns and evidence. The subtitle counts the bans in force and says how banned clients are
answered: 403 "Access denied.", or a normal-looking 429 while "Disguise bans as throttles" is on (the default), so
abusers believe they are only throttled and wait instead of moving to a new address.

Filters: State (In force, Expired, All), Made by (An admin, A detector), Type (Address, Network, Place, User-Agent)
and Detector. Columns: Subject, Type, Active, Ends in ("Permanent" for no end), Origin, Created by (an admin, or
`auto:<detector>`), Requests refused (since the ban was made, counted every few seconds) and Last refused; Created,
Ends at, Evidence and Id are hidden. Expired bans stay listed until retention removes them.

**Ban a subject** asks for the Type (Address, Network in CIDR form such as `203.0.113.0/24`, Place (Roblox-Id), or
User-Agent hash), the Subject, a Length in minutes (60 by default) or Permanent, a message kept with the ban as
evidence (callers never see it) and an optional reason. Places and User-Agents are claims a caller can change: ban
an address when you can. For a User-Agent hash, the form takes the key Security > Fingerprints shows for the
User-Agent (32 hex characters), its 16-character ban hash (the User-Agent's drawer there shows it as "Ban hash"), or
a full SHA-256 of the User-Agent text; any other length is refused, because it could never match. A User-Agent that
page shows masked (`[redacted]`) or cut at 400 characters names the stored text, not what the caller sent, so its
hash refuses nobody: use a User-Agent rule or a request filter for those. An active ban of the same subject is
extended instead (the later end wins). A ban refuses at once, before every check except pause. To undo a ban, lift
it (below).

Press a row for the ban's drawer: subject, when it ends, who made it, requests refused, the evidence (reason code and
text), the detector events about that client, and a chart of the requests it refused over the range. **Lift this
ban** removes it; **Lift every ban of this subject** removes all of them, active or expired. Both take effect on
every worker within a second.

**Delete bans** removes many at once; each choice needs a reason and most show a count first: Expired bans, Bans
made by detectors (spam detectors and the ladder), Bans made by one detector, and Every ban (typed phrase
`all bans`). Deny list entries, rules and settings are left alone. Every dialog says the one thing that changes for
callers even when only expired bans go: repeat offenders start again from the first ban length, because a detector
doubles a client's next ban for each automatic ban of it from the last 30 days, expired ones included. Deleted bans
cannot be restored; make them again by hand.

| Setting | Key | Default | Note |
|---|---|---|---|
| Disguise bans as throttles | `ban_disguise_as_throttle` | On | Off: 403 with `Roxy-Refusal: banned`. The deny list follows this switch too |

**Normal**: a handful of bans, most made by detectors and expiring on their own. **Worrying**: someone reports
endless 429s (search their address here: a disguised ban looks like a throttle); a ban on a wide network without a
note, or one that covers your own address or a busy game (health check H-BANS; follow
[Config or ban list problems](/admin/help/runbooks#config-or-ban-list-problems)).

#### Deny and allow lists

Two lists of addresses and networks, on two tabs. Your own address, as Roxy sees it, is shown at the top.

- **Deny list**: refused before any other check except pause, like a ban, but meant for networks you never want.
  It answers the same way bans do (403 "Access denied.", or the disguised 429 while "Disguise bans as throttles" is
  on). **Deny an address** asks for the address or network, an optional expiry in hours (empty: never), a private
  note and an optional reason. Prefer an expiry: addresses change hands.
- **Admin allowlist**: while the "Admin network allowlist" setting is on (Security > Admin access), only these
  networks can reach `/admin` at all; everyone else gets a plain 404. **Allow a network into /admin** asks you to
  confirm it is you. Add every network you sign in from before you switch the allowlist on (see
  [The admin network allowlist](#the-admin-network-allowlist) in the Security chapter).

Both tables show Network, Note, Active, Expires in ("Never"), Hits (in the range) and Last hit (the allowlist records
no hits), Added by. Press a row for its drawer, with a chart of its hits (deny list only) and **Remove**, which asks
for an optional reason. Removing an admin allowlist entry needs a fresh second factor, and when the allowlist is on
and the entry is the only one that covers your own address, Roxy also asks you to tick "I understand: this hides
the dashboard from my own address". If you lock yourself out, follow
[Admin locked out](/admin/help/runbooks#admin-locked-out). Check the deny list's Hits now and then: an entry that has
matched nothing for weeks can go.

#### Bypass

Addresses on the bypass list skip the rate limits and the tarpit, so you can load-test Roxy. Per the Pipeline card,
bypass skips the flood limit, spam detector refusals, the emergency limit, the per-IP throttle, place limits, the
browser challenge, the bot score block, User-Agent rules and endpoint rules. It never skips pause, bans, the deny
list, ignored paths, the probe checks, request filters or endpoint blocks, and it never skips the credential's own
budget.

The card shows **Your current IP** with a Bypassed or Not bypassed badge.

- **Bypass my IP** adds your address at once, for the default expiry (24 hours unless you changed it). When an
  entry already covers your address, the card says so.
- **Use my IP in the form** opens Add a bypass with your address filled in.
- **Add a bypass** asks for an address or network, Expires after (hours; empty uses the default expiry), a note and
  an optional reason. **Never expire** needs a second tick: "I understand: this address skips the limits until
  someone removes it".

The table and the drawer work like the deny list's; **Remove** puts the address back under the normal limits.

| Setting | Key | Default | Note |
|---|---|---|---|
| Default bypass expiry | `bypass_default_expiry_h` | 24 hours | 0 means new entries never expire, which is high risk |

**Worrying**: an entry that never expires, or one nobody has used for weeks. A SEC-BYPASS-FOREVER or FILTER-REMOVE
recommendation flags them; give the entry an expiry or remove it.

### Rules and filters

The four rule cards share one drawer. Press a rule's row to see it as stored, how often it matched (in the range
and since it was added), a chart of its hits, and these actions: **Switch it off** (or on), **Change this ...**
(named for the kind of rule, for example "Change this request filter": the same fields as Add, plus an optional
reason), and **Remove** (with an optional reason). A switched-off rule is kept but skipped, which is the easy
way to test whether a rule matters. A removed rule is gone; add it again to undo. Each card also has an Attempts tab
(except User-Agent rules) with its own Clear button.

#### User-Agent rules

A [User-Agent rule](/admin/help#term-ua-rule) gives one kind of client its own limit, matched on the User-Agent
header it sends: a [burst](/admin/help#term-burst) allowance (N requests per P seconds, for a scraper that works in
batches) or a [cooldown](/admin/help#term-cooldown) (a minimum gap between requests, for a bot that hammers
steadily). The first enabled rule that matches decides; the ordinary per-IP limit still applies too. The subtitle
counts the active rules.

**Rules** tab, in evaluation order: Order, Matches (with the match mode and "off" below it), Limit ("10 per 1
minute" or "1 per 2 seconds"), Scope (per IP, or shared), Message ("default" when empty), Allowed / refused (in the
range), Hits, Last hit, Enabled. In the drawer, **Move earlier** and **Move later** change the order.

**Add a rule** asks for: the User-Agent text to match (with Contains, a fragment such as `python-requests` is
enough), Match (Contains, Exact or Regex), Limit type (Burst allowance or Cooldown between requests), Scope (Per IP:
each address gets its own allowance; Shared: every address using this User-Agent draws on one allowance), the
numbers, a message for the client and a private note. Say the limit in the message: a cooperative bot can only
respect a limit it has been told about. A new rule goes to the end of the order.

**Tester** tab: paste a User-Agent and press Test. It says which saved rule would limit it, or "No client rule
applies". Open "Also try a rule I am writing" to judge a draft rule alongside the saved ones without saving it.

| Setting | Key | Default | Note |
|---|---|---|---|
| User-Agent rules | `user_agent_rules_enabled` | On | Off pauses every rule at once: a quick switch when a rule catches real callers |

**Worrying**: a rule with many refusals for a client you trust. Switch that rule off, or narrow its text.

#### Request filters

A [request filter](/admin/help#term-request-filter) refuses requests whose headers contain a text you choose.
Matching ignores case. By default the caller gets an ordinary-looking throttle 429 and cannot tell it was filtered. A
filter's refusal never counts toward the per-IP limit and adds no strike. Three tabs:

- **Filters**, first match first: Text, Header ("(any)" when empty), Match against, Mode, Reply ("stealth 429" when
  empty), Hits, Last hit, Enabled. **Add a filter** asks for: Header (optional; name one to look only at its value),
  Match against (Name or value, Header name, Header value), Match (Contains, Exact, Regex), Text to match, an
  optional Reply (which breaks the stealth) and a private note. The same filter twice is refused.
- **Tester**: paste headers, one `Name: value` per line, or load a recent request's (live rows keep only the
  User-Agent and Roblox-Id; open a capture on the [Live](#live) page for every header), or "Use an example". It says
  whether the request "would be BLOCKED", by which filter and on which header, or "would be allowed through". You can
  also judge a draft filter without saving it. Always test a new filter here with a real game server's headers.
- **Attempts**: each path a filter refused in the range: Endpoint, Attempts, Distinct clients, Methods, Refused by
  (the filter), Matching rule now, Last attempt. "Clear attempts" uses the typed phrase `reset header_rule_attempts`.

**Worrying**: a filter whose hits suddenly jump, or a game developer who reports 429s you cannot explain. Switch the
filter off and see whether the reports stop. A FILTER-COLLATERAL recommendation says when a filter refuses traffic
from places that are otherwise served normally; FILTER-REMOVE flags filters that have not matched for a long time.

#### Endpoint blocks

An [endpoint block](/admin/help#term-endpoint-block) refuses every request to the endpoints its pattern names, for
every caller (bypass addresses included), with 403 and its reply or "This endpoint is currently blocked.". Two tabs:

- **Blocks**: Pattern, Type, Reply, Hits, Last hit, Enabled. **Block an endpoint** asks for the pattern (host and
  path without `https://`; a whole host such as `games.roblox.com`, a path such as `games.roblox.com/v1/games`, or
  `*` for one path segment; everything under the pattern is blocked too), Pattern type (Wildcard or Regex), an
  optional reply (for example to point callers at a cheaper endpoint) and a note.
- **Attempts**: who still asks for blocked endpoints, with the same columns as the filter attempts. Typed phrase for
  its Clear button: `reset endpoint_block_attempts`.

When several blocks match, the most specific enabled one answers. **Worrying**: many distinct clients in the
Attempts tab, meaning real callers still need the endpoint. Give the block a reply that says where to go instead, or
replace it with an endpoint rule.

#### Endpoint rules

An [endpoint rule](/admin/help#term-endpoint-rule) gives the endpoints its pattern names their own limit; over it,
callers get 429 with the rule's reply or "This endpoint is rate-limited for you; try again in N seconds.". Rules are
only ever stricter: the per-IP limit still applies, and a per-IP rule is never more generous than the per-IP
allowance (the card says the current one). The most specific matching rule applies. Two tabs:

- **Rules**: Pattern, Limit, Per, Scope, Type, Reply, Hits, Last hit, Enabled. **Add a rule** asks for the pattern
  and type, Requests allowed, Per (seconds), Scope (Per IP; "Per experience (and caller network)": one budget per
  Roblox-Id and caller network while "Place limit counts by" is "Place id and caller network", the default, so a
  forged Roblox-Id from another network never uses up a real game's budget; or Shared by everyone), a reply and a
  note. A second rule on the same pattern is refused. Bypass addresses skip it.
- **Attempts**: what the rules refused. Typed phrase for its Clear button: `reset endpoint_rule_attempts`.

**Worrying**: a known game's servers in the Attempts tab, or a FILTER-COLLATERAL recommendation about the rule
(its change removes the rule). Raise the limit or narrow the pattern if part of the rule is still needed.

#### Ignored paths

An [ignored path](/admin/help#term-ignored-path) is answered 404 at once and never counted as a probe: useful for
files browsers and tools ask every site for. Roxy ships two (`favicon.ico` and the file Chrome DevTools asks for).
**Add a path** takes a pattern without the leading slash (every path under it matches too) and a note; Roblox
endpoints cannot be ignored. The drawer's **Remove** sends the path through the normal checks again, where a
non-Roblox path counts as a probe. Ignored paths are never held by the tarpit and bypass does not change them. Add
a path only when Security > Probes shows harmless tools asking for it again and again.

### Detectors

#### Spam detectors

A [spam detector](/admin/help#term-spam-detector) watches each client over minutes to hours for sustained abuse
and acts when a threshold is crossed. The lead line says the state: **Off** (no detector runs), **Dry run** (the
start state: detectors only record who they *would* have banned; the strike, tarpit and recommend actions work
normally), or **Armed** (detectors whose action is ban make real, temporary bans). In dry run nobody is banned, a
trusted game server included: the "Would have banned" decision says what arming would do to it. Once armed, Roblox
game servers (by their signature, from inside "Roblox game server IP ranges") get a strike instead of a ban from
every detector, also for a request that came without the signature, and places are never banned automatically.

The card shows a table of the seven detectors (Detector, Watches, Action now, Threshold, Window, Decisions in the
range), a chart of **Detector decisions over time** (bars stacked by detector, dry-run would-bans included), and the
**Decisions** table, newest first: When, Decision (Would have banned, Banned, Strike, Tarpit, Recommendation),
Detector, Subject, Action, Evidence; the measured value, threshold and window are hidden. Filter it by decision and
by detector. A line at the bottom gives this worker's own counters (clients watched now, detections since start).

What the actions do: **ban** bans the address for the first ban length and doubles it for each repeat offense
within 30 days, up to the ban cap; **strike** and **tarpit** refuse the client's requests (with a strike, or held by
the tarpit) for 10 seconds at a time, renewed while the detector keeps firing; **recommend** takes no action on
traffic and only feeds a recommendation (ABUSE-SPAM, or ABUSE-DIST for SPAM-DIST). Each detector acts on its chosen
action, SPAM-ENUM and SPAM-BUST included (they act on the one client behind the subject). SPAM-DIST offers only
recommend: its subject is many addresses sending one User-Agent (Roblox game servers share theirs), so there is no
one client to strike, hold or ban. The card's thresholds read as the detectors compare: probe and auth fire at
"at least" their threshold, the others at "more than" it.

**Arm the detectors** turns dry run off. Its dialog first shows the collateral preview: how many clients the
detectors would have banned in the last 7 days, and which of them look legitimate (the first 20 are listed): a
trusted game server, one whose requests were mostly served (95% or more by default: the FILTER-COLLATERAL "served
share" setting, tuned on the Recommendations page, decides), or one Roxy has no activity records for. Arming needs a
reason, the typed word `arm` and a fresh second factor. If the list changed while the dialog was open, Roxy
refuses; open it again and review the new list. **Back to dry run** is
always allowed; bans already made stay until they expire or you lift them.

| Setting | Key | Default | Note |
|---|---|---|---|
| Spam detectors | `spam_enabled` | On | Master switch for all seven |
| Spam detectors dry run | `spam_dry_run` | On | High risk. This control can only switch dry run back on; to switch it off, use Arm |

**Normal**: in dry run, a few "Would have banned" decisions for obvious scripts. **Before arming**: read the
decisions for a week. If a legitimate game shows up, raise that detector's threshold first. A SPAM-DIST or
SPAM-ENUM decision is a hint to add a rule, not a ban (see
[Which tool for which problem](#which-tool-for-which-problem)).

#### The seven detector cards

Each detector has its own card ("Spam detector: rate" and so on): what it does now, its shipped default, its
decisions in the range, and six settings one click away (`spam_<name>_enabled`, `_threshold`, `_window_s`,
`_action`, `_ban_minutes` and `_ban_max_minutes`: on or off, threshold, window, action, first ban, ban cap).

| Card | Watches | Fires at (default) | Window | Default action | First ban, cap |
|---|---|---|---|---|---|
| rate (SPAM-RATE) | Sustained request rate | More than 5 times the per-IP limit rate | 10 minutes | Ban | 60 minutes, 7 days |
| refused (SPAM-REFUSED) | Keeps sending while refused | More than 200 refused requests | 10 minutes | Ban | 30 minutes, 1 day |
| probe (SPAM-PROBE) | Probe paths (`.env`, unsafe or non-Roblox URLs) | 5 or more probes | 10 minutes | Ban | 60 minutes, 1 day |
| auth (SPAM-AUTH) | Auth smuggling: sending a Roblox login cookie or its marker through Roxy | 3 or more attempts | 1 hour | Ban | 60 minutes, 7 days |
| enum (SPAM-ENUM) | Walking through ids on one endpoint | More than 500 distinct ids | 10 minutes | Recommend (an endpoint rule) | used only with the ban action |
| bust (SPAM-BUST) | Cache busting (a new query value every time) | At least 200 requests, with more than 90% distinct query strings | 10 minutes | Recommend (ignore the parameter) | used only with the ban action |
| dist (SPAM-DIST) | One User-Agent from many addresses on one endpoint | More than 50 addresses, over 1,000 requests | 5 minutes | Recommend (a shared User-Agent rule), the only action it offers | none |

SPAM-ENUM and SPAM-BUST ship with the action "recommend": they exist mainly to suggest a fix (an endpoint rule, an
ignored parameter). Set their action to strike, tarpit or ban and they act on the one client behind a finding, like
the first four (in dry run a ban is only recorded). SPAM-DIST only ever recommends (a shared User-Agent rule): its
subject is many addresses, so its action setting offers nothing else, and its card says "this detector never bans".
A recommend-only detector reads "Recommends only" in the "Action now" column. A place that SPAM-RATE or
SPAM-REFUSED flags only ever gets a recommendation, and Roxy's own "other" sum of quieter places is never a subject.

**Worrying**: a game you know in the Decisions of SPAM-RATE or SPAM-REFUSED. Raise that detector's threshold or
window, or fix the limit that refuses the game, before you arm.

#### Bot heuristics

The [bot score](/admin/help#term-bot-score) (0 to 100) adds up signals that a caller is a script rather than a game
server. It mainly explains: you see it on the Clients page and recommendations use it. The card's table lists each
signal with its Weight, its Share of the score and how it is measured (the "No Roblox game server signature" note
says it is 0 only with a `Roblox-Id`, a Roblox User-Agent and an address inside the game server IP ranges, so with
that list empty every caller scores 1 on it). It says "Not blocking" while "Block clients at or above bot score" is 0
(the default), or "Blocking" with what it refused in the range. A line at the bottom counts the clients this worker
scores right now.

The signals, their default weights and the settings of this card (the score ceiling and floor, the block threshold
and the seven weights) are the ones of the Clients page's bot score card, explained under [Bot score](#bot-score) in
the Clients chapter. One more setting is edited here: Roblox game server IP ranges (`roblox_egress_cidrs`, empty).
Add only ranges you know belong to Roblox game servers: a wrong range shields any abuser inside it.

With the game server ranges empty, every caller gets the "no signature" points, so real game servers score like any
other client and get no protection from automatic bans. Leave blocking off unless the scores on the Clients page show
that it separates your bad clients from your game servers well: with the default weights, a client without a
trusted game server signature already starts at 15 points before any bad behavior.

#### Challenge

The [challenge](/admin/help#term-challenge) is a small proof-of-work page for browsers only (Roblox game servers
cannot solve it): a browser whose bot score is at or above the trigger must solve it once, then a signed cookie lets it
through for a while. It is a tool against browser-based scraping, off by default. The card says whether it is on,
how many requests got the challenge in the range, and warns "The challenge cannot work here" when the key that signs
puzzles (the `ip_hash_key` credential) is missing.

| Setting | Key | Default | Note |
|---|---|---|---|
| Browser challenge | `challenge_enabled` | Off | |
| Challenge at or above bot score | `challenge_trigger_score` | 80 | |
| Challenge difficulty | `challenge_difficulty_bits` | 18 | About 0.3 seconds on a laptop; high risk at 24 or more |
| Challenge pass lasts | `challenge_cookie_minutes` | 30 minutes | |

**Worrying** (once on): real visitors challenged often. Raise the trigger score or lower the difficulty.

### Tarpit

A [tarpit](/admin/help#term-tarpit) makes a caller Roxy has already refused wait for its error, so an abusive script
loses seconds per attempt while Roxy spends almost nothing. The caller always gets the same refusal it would have
got at once; only the timing changes. It never holds a request Roxy serves, and never a bypass address.

**State.** The lead line says Off, "On, but nothing selected" (no category switched on), or "Holding N kinds", with
the hold style and the hold range. Below it, the hold slots: "N of M hold slots in use; K free", a gauge, and how
much of the connection budget holding uses. A "Clamped" warning means the "Most holds at once" setting asks for more
than the connection budget allows. A "Shared state is unavailable" alert means the tarpit holds nothing until the
shared database works again (it fails closed: the refusal goes out at once).

**Four tiles**, for every worker (the hold statistics are written each minute). The first three follow the range
in the top bar; the fourth and the "last 15 minutes, hour and day" lines always look back from now:

- **Requests held**, with "Skipped (at capacity)" and "Holding right now". Skipped is the number to watch: refusals
  let go at once because no slot was free. "More skipped than held" means the cap, not the abuser, is the limit.
- **Average hold**, with the 95% mark, the longest hold and the total time held.
- **Time between requests**: the average gap before a held caller's next request, for the range and the last 15
  minutes, hour and day, next to the gap after an instant refusal, and a trend sentence ("Backing off", "Speeding
  up" or "Holding steady"). If the tarpit works, the gap after a hold is longer.
- **Held in the last hour**, with the last 15 minutes and day, and the distinct callers this worker held.

Three tabs: **By category** (each category, whether it is held, and its holds, skips, average and total hold time in
the range, with the hold styles used), **Hold lengths** (how long holds lasted), and **Who is held** (this worker's
own lists since it started, the busiest 25 rows: why each hold happened, by category and rule, and the callers held).
"Clear stats" resets the hold statistics on every worker within a few seconds (typed phrase `reset tarpit`).

**Normal**: Skipped near zero; the gap after a hold clearly longer than after an instant refusal. **Worrying**:
Skipped above Held, so raise "Most holds at once" (within the budget) or switch off a noisy category such as the
per-IP throttle; or a gap after a hold that is no longer than after an instant refusal, so holding does not slow
those clients and a ban fits better. A TARPIT-TUNE recommendation reads the same numbers.

#### Tarpit types

Every held refusal uses one of three styles, chosen by "Hold style":

- **Hold** (the default, as in v1): wait a random time between the shortest and the longest hold (8 to 20 seconds by
  default), then send the refusal. The random length stops a script from learning the delay and setting its timeout
  just below it. Best for probes and request filter hits.
- **Drip**: send the headers at once, then the body one byte per drip interval until the hold ends. Clients that read
  the body stay held the whole time, and some give up. Best for scrapers that ignore status codes.
- **Jitter**: add only a short random delay (0.5 to 3 seconds by default). It costs almost nothing and breaks tight
  retry loops without holding connections. Best for ordinary rate-limit refusals. Callers retrying inside their
  Retry-After always get jitter, whatever the style.

Every hold ends by 55 seconds, and before the request's own deadline, so nginx never times out first.

#### Tarpit categories

A refusal is held only when its category's switch is on (and the master switch is on):

| Category on the card | Setting | Default | Fed by | Note on the card |
|---|---|---|---|---|
| Caught by a Request Filter | `tarpit_on_header_rule` | On | Request filters | Traffic you fingerprinted. Safest to hold |
| Not a Roblox URL | `tarpit_on_probe` | On | Unsafe URL, Not a Roblox URL | Scanners and junk paths. Never a real caller |
| Per-IP rate limit | `tarpit_on_throttle` | Off | Per-IP throttle, flood limit, place limit | Careful: also catches ordinary users who went too fast |
| Global throttle-all | `tarpit_on_throttle_all` | Off | Emergency limit | Careful: also catches ordinary users |
| Per-endpoint rate rule | `tarpit_on_endpoint_rule` | Off | Endpoint rules | Careful: also catches ordinary users |
| Blocked endpoint | `tarpit_on_blocked_endpoint` | Off | Endpoint blocks | May catch a caller who just wants that endpoint |
| Sent a ROBLOSECURITY cookie | `tarpit_on_auth_attempt` | On | Auth smuggling | Never valid here, but sometimes a genuine mistake |
| Hit a client (User-Agent) rule | `tarpit_on_user_agent_rule` | Off | User-Agent rules | Usually cooperative bots; holding them punishes clients that would obey |
| Banned or denied client | `tarpit_on_ban` | On | Bans and deny list, bot score block | They already cannot get an answer |
| Flagged by a spam detector | `tarpit_on_spam` | On | Spam detectors | |
| Retried inside its Retry-After | `tarpit_on_upstream_cooldown_retry` | Off | Early retries during a Roblox cooldown | Always the short jitter |

Pause, ignored paths and the challenge page are never held.

#### Tarpit settings

| Setting | Key | Default | Note |
|---|---|---|---|
| Tarpit enabled | `tarpit_enabled` | On | Master switch |
| Hold style | `tarpit_default_type` | Hold | Hold, Drip or Jitter |
| Shortest hold, Longest hold | `tarpit_min_seconds`, `tarpit_max_seconds` | 8 and 20 seconds | The longest is at most 55 |
| Drip interval | `tarpit_drip_interval_ms` | 1,000 ms | Drip style only |
| Jitter minimum delay, Jitter maximum delay | `tarpit_jitter_min_ms`, `tarpit_jitter_max_ms` | 500 and 3,000 ms | |
| Most holds at once | `tarpit_max_concurrent` | 50 | For the whole fleet; 0 stops all holding |
| Connection budget | `tarpit_connection_budget` | 4,000 | What nginx can carry; change it only after changing nginx |
| Share of connection budget the tarpit may use | `tarpit_max_capacity_fraction` | 0.25 | High risk above 0.4 |
| Hold slot grace period | `tarpit_slot_grace_s` | 15 seconds | Frees the slot of a worker that died mid-hold |
| The eleven category switches ("Hold ... refusals", "Jitter early retries during a Roblox cooldown") | `tarpit_on_<category>` | see the table above | |

The cap in force is the smaller of "Most holds at once" and the budget times the share, rounded down. The card shows
the formula with your values; with the defaults it reads `min(50, floor(4000 x 0.25)) = min(50, 1000) = 50`.

### On a phone

- The On this page list wraps and its links are sized for a finger. Cards shown side by side on a wide screen
  (Request limits and Place limits, Bot heuristics and Challenge, the detector cards) stack one under the other.
- Data tables show each row as a small card with its two or three main columns (for example Subject, Active and Ends
  in for bans); tap the row for the rest in its drawer.
- The ladder editor shows each rung as a small form with a label over every field; the detectors, bot signals and
  tarpit tables show each cell under its column name.

## Security

The Security page (`/admin/security`) answers two questions: who has been knocking on Roxy's doors, and who is
signed in as you. The top half lists sign-in attempts, probes, crawlers and browser reports. The bottom half holds
your own sessions, trusted devices, passkeys and recovery codes, then the fingerprints of what callers send and the
settings that decide how anyone signs in.

**When to use this page**

- You got a "Roxy Admin Login" email you did not expect: check Admin logins and Sessions, then sign out everywhere
  (or use the kill-switch link in that email).
- You got the alert "Roxy: login attempts throttled globally": read Admin logins.
- You lost a phone or a laptop: end its session, revoke its trusted device, delete its passkey, and make new recovery
  codes if they were stored on it.
- A caller looks odd on the Live or Clients page: see what it probed and what it sends (Probes, Fingerprints).
- Once a month: count your recovery codes and remove passkeys and trusted devices you no longer use.
- You want to change how sign-in works (session lengths, lockouts, trusted devices, the admin allowlist): Admin
  access.

### How the page is laid out

The cards appear in this order:

1. Admin logins, Probes, then Probe summary and Crawler activity side by side.
2. CSP reports.
3. Sessions and Trusted devices, then Passkeys and Recovery codes side by side.
4. Fingerprints and Admin access. These two read the most data, so they load on their own a moment after the page
   (or as soon as you scroll to them); the rest of the page shows at once.

The buttons at the top of the page jump to Your sessions and to Fingerprints; Account changes opens the Audit page
filtered to sign-in and account actions (`/admin/audit?action=auth.*`). The "How to read this page" panel explains
signatures, fingerprints and the account controls in a few lines.

Everything a caller chose (a probed path, a User-Agent, a header name or value, a CSP report field) is shown as
plain text, exactly as stored, with secrets already removed; where Roxy makes a link from such text (a probe
signature), the text only fills in one of Roxy's own addresses.

The tables work as on every page (see [Tables and drawers](#tables-and-drawers)). The sign-in and probe logs are
always listed newest first, so their column headers do not sort.

### Time range on this page

The time range in the top bar decides which sign-ins, probes, crawls, CSP reports and Blocked
fingerprints are listed. The Header names, User-Agents and Not recorded tabs count everything kept (they have no time
per request), and the account cards (Sessions to Recovery codes, Admin access) show how things stand now. The
comparison (the C key) changes no number on this page, and the subtitles name only the range.

### Admin logins

Every attempt to sign in to the dashboard in the time range, successful or not, newest first. The subtitle counts
them, for example "Last 24 hours: 6 attempts, 2 failed".

| Column | What it means |
|---|---|
| When | When the attempt happened. |
| Result | Signed in, or Failed. |
| IP | The address the attempt came from. |
| Username | The account name, when it is a real account. It is empty for a wrong second factor and for a name that is not an account: Roxy never stores such a name, in case someone typed a password into the username box. |
| Method | Where a failure happened, or how a success got in (below). |

Method values: `password` (a wrong password) and `second_factor` (a wrong code) for failures; for a success, the
second factor used: `totp` (the authenticator app), `passkey`, `recovery` (a recovery code), `email` (an emailed
code), `trusted_device` (a trusted browser, no code asked) or `bootstrap` (the one-time first sign-in after the
upgrade from v1).

The Result filter shows Every attempt, Successful or Failed. Clear sign-in records (card header) opens the Data page's
reset form with the Logins family chosen; nothing is deleted before its preview (see [Resets](#resets)).

**Normal:** a few successful sign-ins, all from addresses you know (home, work, your phone), with `totp`, `passkey`
or `trusted_device`; now and then a failed attempt from your own address after a typo.

**Worrying, and what to do:**

- A successful sign-in you did not make, or from an address you do not know. Press Sign out everywhere on the
  Sessions card (or open the kill-switch link in that sign-in's email), then follow the runbook
  [Unexpected admin login](/admin/help/runbooks#unexpected-admin-login).
- A successful sign-in with `recovery` that was not you: someone holds one of your recovery codes. Make new codes at
  once (Recovery codes card) and follow the same runbook.
- Many failures from many addresses: password guessing. After 5 failures for one username from one network within 10
  minutes, Roxy refuses further attempts from that network for a while; and once more than 30 attempts a minute
  arrive from all networks together, each further attempt waits 5 seconds before it is checked (never refused, so a
  guesser cannot lock you out). Those numbers are Admin access settings. The runbook
  [Login attempts throttled](/admin/help/runbooks#login-attempts-throttled) has the steps; the admin network
  allowlist (below) hides the sign-in page altogether.

How many records are kept: Admin login records kept (`max_login_records`, 5,000 by default) on Data > Record caps.

### Probes

A [probe](/admin/help#term-probe) is a request that looked for something Roxy does not have: an admin page of other
software, a file, a script, or a URL that is not a Roblox address. Scanners on the internet send them all day, and
they are how most attacks begin. This card lists each one in the time range, newest first.

| Column | What it means |
|---|---|
| When | When it arrived. |
| IP | Who sent it. |
| Signature | The kind of probe, without the address it tried, for example `Invalid URL` or `HTTP 404 via GET`. |
| Target | What was probed, with secrets removed. |
| Path | The path asked for. |
| User-Agent | The software name the caller sent. |
| Count | Hidden by default. 1, or how many probes were folded into one row when a flood went over the event budget. |

The Signature filter offers Every signature and the 40 busiest signatures of the range, each with its count. This is
the page's main table: its filter is kept in the address bar, so a filtered view can be bookmarked. A link from
another page may narrow it to one address (`?ip=`); the card then says "Only probes from" that address, with Show
every address to go back. Clear probe records opens the reset form with the Probes family chosen.

**Normal:** a steady trickle from many addresses, mostly 404-style signatures for paths of other software (WordPress,
PHP admin pages). An empty card says "No probes in this range": good news. Mistakes on the sign-in page are listed
here too: a wrong code shows as `Invalid 2FA code`, and an attempt refused by the lockout as
`Login attempts rate-limited`, so your own typos can appear with your own address.

**Worrying, and what to do:**

- Hundreds of probes from one address or network: a scanner that will not stop. Ban it (Protection > Bans, or from
  that address on the Clients page); for a network you never want, add it to the deny list (Protection > Deny and
  allow lists). If the probes come with a flood of traffic, follow [Under attack](/admin/help/runbooks#under-attack).
- A harmless path that fills the log (a monitoring service checking a URL): add it to Protection > Ignored paths,
  which refuses it at once without counting it as a probe.

How many records are kept: Probe records kept (`max_exploit_records`, 5,000) on Data > Record caps.

### Probe summary

The same probes, one line per signature, so a scanner trying a thousand paths stays one line. Columns: Signature (a
link that opens the probe log filtered to it), Count, Last seen, and First seen (hidden by default; Columns shows
it). It starts sorted by Count, and its search box finds signatures. Clear probe records is the same reset as on the
Probes card.

Use it to see which kinds of probing dominate. A signature you have never seen before at the top of the list is
worth a look in the log.

### Crawler activity

Search engines and other crawlers read `robots.txt` (and the sitemap) before they look around. Each address that
fetched `robots.txt` or `sitemap.xml` in the range is one row: IP, Count (fetches) and Last fetch. It starts sorted
by Count, and its search box finds addresses. Clear crawl records opens the reset form with the Crawls family.

**Normal:** a few search engine addresses that check back now and then. **Worrying:** nothing here is dangerous by
itself; an address that fetches `robots.txt` hundreds of times a day is a badly behaved bot, which you can ban like
any other caller. How many records are kept: Crawler records kept (`max_crawl_records`, 5,000).

### CSP reports

Roxy's pages carry a Content-Security-Policy ([CSP](/admin/help#term-csp)): a rule that tells the browser to run only
Roxy's own scripts and styles. When a browser refuses something on one of Roxy's pages, it can send a report. This
card groups the reports of the time range by what was refused.

| Column | What it means |
|---|---|
| Directive | The part of the policy that refused it, such as `script-src` (scripts) or `style-src` (styles). |
| Blocked | What the browser refused to load or run. |
| Page | The Roxy page it happened on. |
| Source file | Hidden by default. The file that tried. |
| Disposition | Hidden by default. `enforce` (it was stopped) or `report` (only reported). |
| Count | Reports in the range. |
| Last seen | The latest report. |

The Directive filter lists every part of Roxy's policy. Count and Last seen sort.

**Normal:** empty ("No CSP reports in this range: good news"), or a few reports caused by a browser extension in your
own browser (extensions often add their own scripts or styles to every page).

**Worrying:** a steady stream from one page, above all `script-src` reports naming a script you do not recognize.
Something tried to run foreign code on a Roxy page. Turn off your browser extensions and reload; if the reports go on,
treat it like an unexpected sign-in and follow [Unexpected admin login](/admin/help/runbooks#unexpected-admin-login).
Any browser on the internet can send a report, so a few odd ones from pages you never opened mean little.

### Sessions

Your signed-in sessions, newest first. A session is one browser signed in as you. The subtitle counts them, and the
line at the top says when a session ends by itself: after a number of minutes without use (Session idle timeout) and
after a number of hours at the most (Maximum session lifetime). Only real pointer or keyboard input counts as use; an
open tab nobody touches still times out.

| Column | What it means |
|---|---|
| Browser | The browser's User-Agent; "This browser" marks the one you are using. |
| From | The address it signed in from, or the address of its latest "Confirm it is you". |
| Signed in | When the session started. Each "Confirm it is you" replaces the session with a new one, so it then shows that moment. |
| Last active | Your last real use in that browser. |
| Ends at the latest | When the session ends whatever happens. A "Confirm it is you" never moves it. |
| Second factor | How it passed sign-in, or the factor of its latest "Confirm it is you": the same values as Method in Admin logins. |

A `bootstrap` session is the one-time first sign-in after the upgrade from v1: it may only enroll the authenticator
app, and it lasts 30 minutes at most (see [Getting started](#getting-started)).

**Actions** (none needs a fresh second factor; each is written to the audit log):

- End (on another session's row): signs that browser out at once.
- Sign out here (on this browser's row): signs you out; the page goes back to the sign-in screen.
- End every other session (shown when there are others): every session but this one ends. A dialog says what will
  happen first.
- Sign out everywhere: every admin session ends at once, this one included. This is the kill switch from inside the
  dashboard: it raises the session epoch (a counter every session is checked against; this is not the leader's
  epoch of the glossary), so every older session stops working, and deletes them. Use it when you think someone
  else is signed in as you.

There is no undo: you simply sign in again with your password and second factor. Ending a session does not revoke
trusted devices, so a lost device's browser would still skip the second factor next time: revoke its trusted device
too (next card).

**Normal:** one or two sessions, all yours. **Worrying:** a browser or address you do not recognize. Sign out
everywhere, revoke all trusted devices, then follow
[Unexpected admin login](/admin/help/runbooks#unexpected-admin-login).

### Trusted devices

A trusted device is a browser that skips the second factor for a while, after a sign-in where you ticked "Trust this
device". It still needs your password every time, and the trust is tied to the browser and operating system it was
given to.

The top of the card says whether trusted devices are on (the Trusted devices setting, Admin access card) and whether
this browser is trusted. With the setting off, no device skips the second factor, even one still listed.

| Column | What it means |
|---|---|
| Device | Its name; "This browser" marks yours. |
| Browser | The browser and operating system the trust is tied to, for example `firefox/linux`. |
| Trusted since | When the trust was given. |
| Last used | The last sign-in that used it ("not yet" when none). |
| Trusted until | When the trust runs out (Trusted device lifetime, 30 days by default). Using the device does not extend it. |

**Actions** (neither needs a fresh second factor; each is written to the audit log):

- Revoke (one row): that device needs the full second factor at its next sign-in. Nobody is signed out now.
- Revoke all (shown when at least one device is listed): every device of yours, this one included, needs the full
  second factor next time. A dialog asks first. Nobody is signed out now; end sessions on the Sessions card if you
  need that too.

To undo, tick "Trust this device" again at the next sign-in on that browser.

**Normal:** your own browsers, used recently. **Worrying:** a device you do not know, or one on a computer you no
longer have: revoke it and end its session.

A session that started on a trusted device has entered no code, so the first sensitive action in it (a passkey, new
recovery codes, a sign-in setting) asks for your code ("Confirm it is you").

### Passkeys

A [passkey](/admin/help#term-passkey) signs you in with your device's fingerprint, face or PIN instead of a 6-digit
code. It is optional: the authenticator app ([TOTP](/admin/help#term-totp)) stays required (owner decision D5) and
keeps working whatever you do here. You may have up to 10 passkeys; the subtitle says how many you have.

Each passkey shows its name, when it was added and when it was last used.

**Actions** (each asks you to confirm it is you):

- Add a passkey: type a name under "Name for a new passkey" (for example "Laptop"), press Add a passkey, and follow
  your browser's prompt. The button is off when you already have 10.
- Rename: open Rename, type the new name and press Save the name.
- Delete: a dialog asks first. The passkey can no longer sign you in; your device keeps its copy until you remove it
  there. To undo, add a new passkey from that device.

**Normal:** one passkey per device you use. **Worrying:** a passkey you did not add, or a "last used" time when you did
not sign in. Delete it and follow [Unexpected admin login](/admin/help/runbooks#unexpected-admin-login).

### Recovery codes

Recovery codes are single-use codes that stand in for the authenticator app when your phone is not at hand. You get
10 when you enroll the authenticator app (see [Getting started](#getting-started)). The card shows how many are left
(never the codes themselves) with a badge: "Enough codes left", "Running low: make new ones soon" (3 or fewer), or
"No codes left: make new ones now".

**Make new codes:** a dialog asks first, then a fresh second factor if your last code is older than the window. Every
old code stops working at once. The new codes appear once, on this card, with Copy the codes and Hide them; Roxy
never shows them again. Store them somewhere safe and offline (a password manager or paper), never only on the phone
that holds your authenticator app. The "Confirm it is you" box also accepts a recovery code, which uses it up.

**Normal:** most codes left. **Worrying:** fewer left than you remember using (someone used one: look for Method
`recovery` in Admin logins), or none left.

With neither the phone nor a code, the second factor is reset from the server console: runbook
[Admin locked out](/admin/help/runbooks#admin-locked-out).

### Fingerprints

[Fingerprints](/admin/help#term-fingerprint) count what callers send when their request passes every check: the
header names, each header's values, and the User-Agents. An unusual client stands out here because it sends
something nobody else does. The card has four tabs (the arrow keys move between them, and the open tab is kept when
the card refreshes); each tab's badge counts its rows.

#### Header names

| Column | What it means |
|---|---|
| Header name | Lowercase; a name that looks like a secret is shown as `fp:<hash>`. |
| Count | Requests that carried it. |
| Values | Distinct values stored (capped per header). |
| Values ignored | Recorded, or Not recorded. |
| High cardinality | "Yes: consider not recording" when 90 percent or more of its values were new. |
| Last seen | The latest request that carried it. |
| Unique ratio, First seen | Hidden by default. |

Open a header for its drawer:

- Its facts: requests that carried it, whether its values are recorded, distinct values kept, first and last seen,
  and a warning when it has high cardinality (a value that is new on nearly every request, such as a trace id).
- Stored values: the 50 most frequent, each with how many requests carried it. Values that look like secrets are
  stored as a keyed hash (`fp:`). Download every value (CSV) gets all of them.
- What you can do:
  - Stop recording its values (optional reason): deletes the stored values now and from then on keeps only the
    count. Record its values again undoes it for new requests; the deleted values do not come back.
  - Clear its stored values: deletes the values; the header, its count and its recording stay.
  - Remove this header from the table: deletes the row and its values; the next request that carries it adds it
    again, counted from one.

Clear and Remove write their audit entry first and cannot be undone (no snapshot is taken). Headers that carry client
addresses (such as `x-forwarded-for`) are never recorded, not even as a hash, and cannot be switched on: such a value
identifies a client.

#### User-Agents

Columns: User-Agent ("(none)" for requests without one), Count and Last seen; First seen, Last path, Last caller,
Last header names and Last detail at are hidden by default. Open one for its drawer: its counts, its **Ban hash** (the
subject of a "User-Agent hash" ban on Protection > Bans; a User-Agent shown masked, `[redacted]`, or cut at 400
characters names the stored text rather than what the caller sent, so its hash refuses nobody), and "Its newest
recorded request" (when, the path, the address, and the header names in the order they were sent, never their
values), with Its address in Live. Rows from before the upgrade, or imported from v1, have counts only.

#### Blocked

What the requests refused by a [request filter](/admin/help#term-request-filter) (Protection > Request filters)
carried, in the time range: Type (Header name or User-Agent), Header, User-Agent, Count and Last seen, with a Type
filter (Both, Header names, User-Agents). A header row opens a drawer with Remove it from the Blocked list. Use this
tab to catch mistakes: a real game server here means the filter that refused it is too broad.

#### Not recorded

Headers whose values are not recorded (their count still is): Header, Why ("Detected automatically", "Default" for
one shipped with Roxy, or "Added by an admin") and Detail (for an automatic entry, how unique its values were). A
row opens the same header drawer, where Record its values again takes the header off this list (except for the
headers that carry client addresses, which always stay).

None of the fingerprint actions asks for a fresh second factor or a typed phrase; each is written to the audit log.

Clear fingerprints (card header) opens the reset form with the Fingerprints family chosen: the Header names (with
their stored values), User-Agents and Blocked tabs. The Not recorded list is a rule, not a statistic, so a reset
leaves it alone.

**Normal:** the same few header names on most requests (the ones Roblox game servers send), and a handful of
User-Agents with big counts.

**Worrying, and what to do:**

- A header marked High cardinality: stop recording its values; they only fill the table. Auto-ignore unique header
  values (`auto_ignore_high_cardinality`, on by default, Data > Record caps) does it by itself.
- A new User-Agent with many requests, or one of a script library (curl, python-requests): open its newest request,
  look at its address in Live, and consider a User-Agent rule (Protection > User-Agent rules) or a ban.
- A real caller in the Blocked tab: loosen the request filter that caught it.

Limits: Header names tracked (`max_header_name_records`, 1,000), Values tracked per header (`max_header_value_records`,
500), User-Agents tracked (`max_user_agent_records`, 5,000) and Fingerprint retention (`retention_fingerprints_days`,
90 days after a fingerprint was last seen), all on the Data page.

### Admin access

This card holds the sign-in and session settings, next to the facts they act on:

- You are signing in from: your address as Roxy sees it.
- Admin allowlist: On, or "Off: any address may see the sign-in page"; how many entries the list has and whether
  your address is on it; Manage the entries (Protection > Deny and allow lists).
- Trusted devices: On or Off.
- Second factor again: how many minutes a sensitive action trusts your last code.

**Changing a setting.** These settings are changed like any setting on a card (see
[Changing a setting on a card](#changing-a-setting-on-a-card)), with one addition: every one of them decides who may
sign in, so saving also asks you to confirm it is you. To undo a change, set the old value again or use Revert on its
audit entry.

The card's "Settings for this card" list (open when the card loads) holds its 17 settings, each with its label and
key; here they are by purpose:

| Setting | Key | Default | What it decides |
|---|---|---|---|
| Session idle timeout | `admin_session_idle_timeout_s` | 900 s (15 min) | How long a session lives without real use. High risk above 4 hours. |
| Maximum session lifetime | `admin_session_max_age_s` | 43,200 s (12 h) | The longest a session lives, however active you are. High risk above a day. |
| Dashboard keepalive interval | `admin_heartbeat_interval_s` | 30 s | How often an open dashboard tells Roxy you are still there (only after real input). |
| Activity window | `admin_activity_window_s` | 60 s | How recent your input must be for a keepalive to count as use. |
| Fresh second factor window | `admin_reauth_window_s` | 600 s (10 min) | How long after a code sensitive actions go ahead without asking again. High risk above 30 minutes. |
| Login failures before lockout | `admin_login_max_failures` | 5 | Failures per username and network before that network is locked out. A network is an IPv4 /24 (256 neighboring addresses) or an IPv6 /64. High risk above 20. |
| Lockout window | `admin_login_window_s` | 600 s (10 min) | The window failures are counted in, and roughly how long a lockout lasts. High risk below 5 minutes. |
| Global login attempt limit | `admin_login_global_max_per_min` | 30 a minute | Attempts per minute from all networks together; beyond it each attempt is slowed, never refused. Networks on the admin allowlist and browsers with a valid trusted device are exempt. High risk above 200. |
| Global login delay | `admin_login_global_delay_s` | 5 s | How long each attempt beyond that limit waits. High risk at 0. |
| Allow emailed login codes | `admin_email_code_enabled` | Off | Whether a code sent by email may replace the authenticator app. High risk when on; owner decision D5 keeps it off. |
| Emailed code lifetime | `two_fa_expiration` | 300 s | How long an emailed code works (also for the first sign-in after the upgrade), but never longer than the Login step time limit below: a code lives the shorter of the two, 2 minutes at the defaults. To give codes longer, raise both. High risk above 10 minutes. |
| Emailed code length | `email_code_digits` | 16 digits | How long an emailed code is. |
| Login step time limit | `challenge_expiration` | 120 s | The time between entering the password and entering the second factor. |
| Trusted devices | `admin_trusted_devices_enabled` | On | Whether "Trust this device" is offered and honored. |
| Trusted device lifetime | `trusted_device_days` | 30 days | How long a trusted browser skips the code. High risk above 60 days. |
| Kill-switch link lifetime | `invalidation_link_ttl_s` | 86,400 s (24 h) | How long the "this was not me" link in the sign-in email works. |
| Admin network allowlist | `admin_allowlist_enabled` | Off | Whether `/admin` answers only the networks on the admin allowlist (below). |

The recommendation engine never changes these settings by itself. The SEC-DEFAULTS recommendation points out any of
them sitting at a high-risk value, with the default as the safer choice.

**Normal:** everything at its default. **Worrying:** a red high-risk badge on a setting you did not mean to change:
open its History to see who changed it and when.

### The kill-switch link

Every successful sign-in, a trusted device's included, sends the email "Roxy Admin Login" to your alert email address.
That address is not a dashboard setting: it lives in a credential file on the server (`alert_emails`), and System >
Alerts shows whether the email channel is set up. The email names the address, the browser and the time (in UTC),
and carries a one-time link of the form `/admin/invalidate/<token>` that works for the Kill-switch link lifetime (24
hours by default).

If the sign-in was not you:

1. Open the link. It only shows a confirmation page; mail scanners open links by themselves, so opening it changes
   nothing.
2. Leave both boxes ticked: "Sign out every admin session" and "Also revoke every trusted device". Untick the first
   only to keep sessions that signed in with a passkey (for example your own, if you use one).
3. Press Sign out all admin sessions. The page then says what was done, and the audit log records `auth.kill_switch`.

The link works once, and it works even from a network that is not on the admin allowlist. A used or expired link
says it is no longer valid; then sign in and use Sign out everywhere (Sessions) and Revoke all (Trusted devices)
instead. Either way, go on with [Unexpected admin login](/admin/help/runbooks#unexpected-admin-login): a new password
from the server console, new recovery codes, and a read of the Audit page for anything the intruder changed.

### The admin network allowlist

Owner decision D6: off by default. With Admin network allowlist (`admin_allowlist_enabled`) on, `/admin`, the
sign-in page included, answers only networks on the admin allowlist. Every other address gets a plain 404 Not Found,
as if the dashboard did not exist, so scanners cannot even find the sign-in page. Listed networks are also exempt from
the global login slowdown.

The list itself is on Protection > Deny and allow lists, tab Admin allowlist. Allow a network into /admin takes an
address or a network in CIDR form (a base address, a slash, and how many leading bits must match: `203.0.113.0/24`
is the 256 addresses from 203.0.113.0 to 203.0.113.255), an optional expiry in hours and a private note. Adding or
removing an entry needs a fresh second factor, and removing the entry that covers your own address while the
allowlist is on asks you to confirm that you mean it.

To switch it on safely:

1. Read your address on the Admin access card ("You are signing in from").
2. Add every network you sign in from on Protection > Deny and allow lists. Home and office lines keep their network
   for a long time; a mobile network changes addresses often, and a wide range for it shows the sign-in page to many
   more people.
3. Check that Admin access now says your address is on the list.
4. Turn on Admin network allowlist on the Admin access card.

Switching it on does not check the list. On with an empty list, or without your network, it hides `/admin` from
every network, yours included. The way back is the server console:
`roxyctl settings set admin_allowlist_enabled=0 --reason "locked out"` (runbook
[Admin locked out](/admin/help/runbooks#admin-locked-out)). The kill-switch link keeps working from any network.

When every successful sign-in of recent days came from a few networks, the recommendation SEC-ADMIN-ALLOWLIST proposes
the change for you: it adds one entry per network first and turns the switch on last. Check its list of networks
before you apply it: a network you use rarely may be missing.

### Replacing the credential

The one Roblox credential is not managed here. Its rules (exactly one credential, never rotated or switched by Roxy,
used for Roxy's own probes and for the endpoints the [Endpoint policy](#endpoint-policy) sends with Roxy's account,
and replaced only by hand with a fresh second factor) are in the [Credential](#credential) chapter.

### On a phone

Below 900 pixels wide, the side-by-side pairs (Probe summary and Crawler activity, Passkeys and Recovery codes)
stack. At 640 pixels and narrower, each row of the log tables becomes a small card with its key columns (for the
logs: When, Result or Signature, and IP); tap the first line to see every column in the drawer. The Sessions and
Trusted devices tables become one labeled block per session or device, with its button at the end. The fingerprint
tabs wrap two to a row, and the facts of the Admin access card and of a fingerprint drawer stack under their labels.
On a touch screen every button and tab is at least 44 pixels tall.

## Endpoint policy

The Endpoint policy page (`/admin/policy`) decides which Roblox endpoints Roxy forwards, which of them carry Roxy's own
Roblox account (the [credential](/admin/help#term-credential)), and which it refuses before Roblox. The owner decided
on 2026-10-16 (owner decision D1, revised) that Roxy sends its account with caller requests, except for the endpoints
this policy blocks. It replaces the credential allowlist the Credential page used to have.

Every operation in Roblox's own API reference (992 of them, on 35 hosts) has exactly one verdict:

| Verdict | What Roxy does |
|---|---|
| Sent with Roxy's account | Forwards the request with the account. Public data, or data that needs a sign-in but is about other users or public things (catalog search, followers lists, badges of a user). |
| Sent without an account | Forwards the request, never with the account. Useful anonymously, but the account would make the answer describe Roxy's own account (ownership flags, "has voted", friend states) or would send the session where it has no business. |
| Blocked | Refuses the request before Roblox, whatever the caller sends. Sign-in, account security, the account's private data, changes to the account, money, trades, groups, creator tools and every Open Cloud route that takes only an API key. |

Roxy ships a reviewed default for each one, with a **risk** from 1 to 4: what a stranger could do with Roxy's account
through that endpoint. 1 is harmless, 2 low, 3 meaningful (private data, a change of state, a reason for Roblox to flag
the account) and 4 critical (session takeover, money, logout, anything irreversible).

One request gets one verdict, first match wins:

1. A caller who sent their own Roblox cookie, API key or sign-in token is refused, whatever the policy says (see
   Caller sign-in attempts below).
2. Your override for that endpoint (with one exception: "Send without the account" on its category takes the
   account away even from an endpoint you set to "Sent with Roxy's account").
3. The switch of its category ("Block all", or "Send without the account").
4. The shipped default.
5. A default for hosts Roblox does not document (`gamejoin`, `billing`, `engagementpayouts` and `voice` are blocked;
   `search` and `translations` are sent without the account).
6. An endpoint Roblox does not document: a write (anything but GET or HEAD) is blocked; a read is sent without the
   account, unless its path holds a word that account endpoints use (`login`, `settings`, `robux`, `/my/` and a few
   dozen more), which blocks it.

Then a few query guards can block one request of an allowed endpoint: a games server list for friend servers
(`serverType` 1 or `Friend`) and group roles with `includePrivate`, because both answer with what only Roxy's account
may see.

The account is only ever sent with GET, HEAD or POST, always from the server's own address, never through the
rotator, and at the pace of its bucket (`credential_bucket_per_min`). An endpoint Roblox answers without a sign-in
goes out anonymously instead when the account is busy or cooling down; one that only answers signed-in users waits
for the account, or gets the "busy" 429.

**Who may do what.** Tightening (blocking, or sending without the account; a category's "Block all" or "Send without
the account") takes effect at once with your session. Loosening (anything that sends more to Roblox, or sends the
account where it was not sent; a category back to Defaults) asks you to confirm it is you
([Step 4](#step-4-save-the-recovery-codes)) and a reason. Loosening a risk 4 endpoint also asks you to type its path.
**Reset to shipped defaults** asks for a reason and your second factor. Every change is written to the audit log and
reaches every worker within a second. **Policy history** at the top opens the Audit page filtered to every change of
the policy.

**When to use this page**

- A caller says an endpoint they need is refused with "Roxy does not forward this Roblox endpoint": find it with the
  Tester, read why in its drawer, and loosen it only if the reason no longer holds.
- The account is throttled by Roblox (the recommendation UP-429-CREDENTIAL, or "Cooling down" on the Credential page):
  switch Public data to "Send without the account" until it recovers.
- An alert or the Summary shows caller sign-in attempts: read Caller sign-in attempts.
- Before you switch the policy on for real after a deploy: read Shadow mode.

### Time range on this page

Summary, Categories, Endpoints and the Tester show the policy now; the Summary's "Last 24 hours" and the Endpoints
table's "Refused (24 h)" always cover the last 24 hours. Unknown endpoints seen, Caller sign-in attempts and Shadow
mode cover the time range in the top bar. Nothing on this page draws a comparison.

### Summary

A badge says whether the policy is **Enforced** (blocked endpoints are refused before Roblox, with the status of
`endpoint_policy_block_status`) or in **Shadow mode** (`endpoint_policy_enforce` is off: blocked endpoints are sent
without the account and counted, never refused). Then:

- How many endpoints have each verdict now, with your overrides and the category switches applied, and how many are
  changed from the defaults.
- **Last 24 hours**: requests refused before Roblox, unknown endpoints (and their requests), what shadow mode would
  have refused, and caller sign-in attempts.
- **Overrides**, **Category switches**, **Shipped defaults** (how many endpoints, on how many hosts, and the date
  they were reviewed) and **Roxy's account** (whether `credential_enabled` is on, and its rate a minute).
- **The old credential allowlist**: the rows the allowlist held before this page existed. Roxy no longer reads them;
  each line says what the policy does with that path now (a GET), so you can check nothing you relied on changed.

**Reset to shipped defaults** removes every override and every category switch.

- **Normal:** Enforced, a handful of overrides you can explain, no caller sign-in attempts.
- **Worrying:** Shadow mode long after a deploy; overrides nobody remembers (open Policy history); sign-in attempts
  (see below).

Settings for this card: Refuse blocked endpoints (`endpoint_policy_enforce`, on), Status code for blocked endpoints
(`endpoint_policy_block_status`, 403; 404 or 500 are the other choices) and Message for blocked endpoints
(`endpoint_policy_block_message`, the text callers get with the refusal).

### Categories

One row per category, the policy's toggle groups: Sign-in and account security, Who the account is, The account's
private data, Changing the account, Social actions, Group actions, Robux, purchases and trades, The account's
inventory, Changing the avatar, Creator tools, Creator private data, Ads, Open Cloud (API key only), Other and Public
data. Each row shows its switch, how many endpoints it holds with each verdict, and its highest risk. Open a row for
its description, the counts now and by default, a link to its endpoints in the Endpoints table, and its switch:

- **Defaults**: each endpoint keeps its own verdict.
- **Block all**: every endpoint of the category is blocked.
- **Send without the account** (only for a category with endpoints sent with the account, which today is Public
  data): every allowed endpoint of the category goes out anonymously. This is the panic switch when Roblox throttles
  the account.

"Block all" never overrides an endpoint that has its own override; "Send without the account" does, because it
only ever takes the account away. An endpoint Roblox does not document can be sent with the account on GET only. There is no "allow all": loosening is one endpoint at
a time, with a reason.

### Endpoints

Every endpoint in Roblox's reference: the page's main table. Search looks in the path, Roblox's summary, the host and
the reason for the verdict; the filters are host, category, verdict, risk, method, Roblox sign-in ("Only answers
signed-in users", "Answers anyone; a sign-in changes the answer", "No sign-in listed", "Open Cloud API key or OAuth
only") and Changed. Search, filters, sort and page are kept in the address bar, so a link such as
`/admin/policy?category=ads#endpoints` opens the table filtered.

Columns: **Method**, **Host**, **Path**, **What Roblox says it does**, **Verdict** (in words; "Your override" or
"Category switch" under it when it is not the default), **Default**, **Risk**, **Category**, **Refused (24 h)** and
**Roblox docs**, two links that open Roblox's own documentation in a new tab: "Roblox feature docs" (the feature
page, when Roblox has one) and "Roblox domain docs" (the page of its host). The column chooser adds Roblox sign-in.

Press a row to open it in a drawer: what Roblox says it does and what sign-in it accepts, its verdict now and where
that came from, its shipped default and the reason for it, notes from the review, its risk and category, your note,
its refusals in the last 24 hours, the two documentation links and a link to every change of it in the audit log.
**Set its verdict**: pick a verdict (sent with the account is offered only for GET, HEAD and POST endpoints), tick
"Keep the answers private" when an answer sent with the account must never be cached or shared between callers, add a
note and a reason, and save. When the verdict you pick is looser than the one now, the form says it will ask for your
second factor, and on a risk 4 endpoint it asks you to type the endpoint's path. **Back to default** removes your
override.

Below the table, tick rows and use **Block selected** (a reason; tightening needs no code) or **Reset selected to
default** (asks for your second factor when a default is looser than the override it replaces). The boxes select rows
on the page shown; the box in the header selects the whole page.

### Tester

Paste a URL in any form: a Roxy URL (`https://<your Roxy>/games.roblox.com/v1/...`), a roblox.com URL or host and
path, a query included; pick a method and press **What does the policy do?**. Nothing is sent to Roblox. The answer
shows the request, the matched endpoint (with a button to open it) or "Not in Roblox's reference" (with a button to
set a verdict for it), each step of the order above with what it said, the final verdict and where it came from,
whether Roxy's account goes with it and whether it falls back to the anonymous path, and what happens: "Refused before
Roblox", "Shadow mode" or "Forwarded". It also warns when the host is not one of the allowed Roblox hosts, which Roxy
refuses anyway.

### Unknown endpoints seen

Endpoints callers asked for in the range that Roblox's reference does not list, written as
`unknown:<METHOD>:<host>/<path template>`, with the verdict Roxy gave them, the requests and the last one, and the
verdict they have now. **Set verdict** opens a drawer to give one its own verdict (sending it with the account, or
sending what was blocked, asks for your second factor and a reason); **Back to the rule** removes that override. Roblox
adds endpoints without notice, so look here now and then and decide.

### Caller sign-in attempts

Callers who sent their own Roblox `.ROBLOSECURITY` cookie, an `Authorization` header, an API key or an
`X-Roblox-Token`, newest first. Every one was refused with a message telling the caller never to send it. Columns:
When, IP, What (the kind), Where (header, cookie, query or body), Name, **Looks real**, **Fingerprint**, Endpoint,
User-Agent and Count. Roxy never stores what the caller sent, only the fingerprint, a keyed hash: rows with the same
fingerprint are the same secret sent again.

"Yes: this caller leaked a live cookie" in red means the value had Roblox's warning prefix and a real cookie's
length: a real person just sent their live session through somebody's game. A notice above the table says so. Whoever
owns it should sign out of every session on roblox.com to make it useless; the address and User-Agent help find who
sent it.

### Shadow mode

What the policy would have refused while Refuse blocked endpoints (`endpoint_policy_enforce`) was off, per endpoint,
with the requests and the last one. Shadow mode sends a blocked endpoint's request without Roxy's account instead of
refusing it, so you can see what enforcing would break before you switch it on. The table fills only while the setting
is off; once it is on, everything blocked is refused and counted in the Summary instead.

### On a phone

The category rows wrap their summary line. Below 640 px the Endpoints table turns each row into a small card with its
key columns (Method, Host) and opens the rest in the drawer; the documentation links and the select box stay on the
card. The drawer's facts become one column below 480 px.

## Health

The Health page (`/admin/health`) runs **Check Proxy Health**: 34 kinds of check over every part of Roxy
(databases, workers, the cache, each Roblox host, the credential, the rotator, the server) in about a minute. Each
check passes, warns or fails and says how to fix it. Runs are kept, so you can compare today with last week. The
**Health** button in the top bar (on a phone, in the bottom bar) opens it.

**When to use this page**

- Every day, as step 3 of the [daily routine](#daily-routine): look at the newest run.
- When something seems off: a game developer reports errors, a number on the Overview turned red, an alert arrived.
- After a deploy, a settings change or a server change, to confirm everything still works.
- When the alert "Roxy: health check found N new failures" arrives (see
  [Health check found new failures](/admin/help/runbooks#health-check-found-new-failures)).

### Time range on this page

Only the **Run history** card follows the range in the top bar (by when each run started). The page opens on **All**
when its address names no range. The comparison is not used; to compare two runs, use **Compare with** on the Run
card.

### Run a health check

**Starting a run**

- **Include the credential check** (ticked by default): the credential check (H-CRED-AUTH) spends one call on the
  Roblox account, so it asks you to confirm it is you. Untick it to run every other check at once without a code.
- **Run a health check** starts the run and shows it right here. Only one run can go at a time in the whole fleet:
  pressing the button while a run is going (from any page or worker) opens that run instead.

The **Check Proxy Health** button on the Overview does the same without the credential check.

**The run view**

The card shows the newest run, or the one named in the address (`/admin/health?run=<number>`, which the history
links use). While it shows the newest run, a run started anywhere else (the Overview, another admin, the schedule)
takes its place. Its head says **Run N** ("the newest" when it is), with **Running** or the worst result (**Worst:
Pass**, **Worst: Warn** or **Worst: Fail**). Under it:

- **Started**, **Who** (Started by an admin with the name, Scheduled, After a deploy, or From the command line) and
  **State** (Running, Finished, or Interrupted: its worker stopped), how long it took, and "without the credential
  check" when it was left out.
- While it runs: a progress bar (for example "12 of 40 checks done") and the checklist, where the checks still to
  come say **Waiting**. The card follows the run live; if the live stream is not connected, the page asks again
  every few seconds. Checks run four at a time, each with a time limit: a check that does not finish in time fails
  ("did not finish within N s"), and a check that crashes warns and names the error.
- When it is finished: counts (passed, warned, failed, n/a, and critical when there is one), then **Needs attention**
  with every warning and failure already open, or "Nothing needs attention: Every check passed or does not apply
  here". The other checks sit in a group below them ("The other N checks"), closed when something needs attention
  and open when nothing does.

**One check**

A check shows its status in words (**Pass**, **Warn**, **Fail** or **n/a**), its title, its id (for example
`H-DNS`), a **Critical** badge when the result is critical (the credential signed in as another account, the leak
guard letting a test request through, or Roxy's outbound clients honoring proxy variables), and the measured value.
Open it for:

- **Measured**: the value it found. **Judged by**: the pass, warn and fail limits.
- What the check means, and its details (for example the queue wait and call time of a probe).
- **Apply fix** (when an open recommendation would fix it; the newest one is linked): opens that recommendation's
  drawer on the [Recommendations](#recommendations) page, where **Preview and apply** is one click away.
- The fix link, named after its page or runbook (for example "Runbook: DNS" or "Egress page").
- **Copy for LLM** (on a warning or failure): copies this check with the instructions an AI assistant needs; text
  that came from outside Roxy is marked as untrusted in it.

**n/a** means the check does not apply here: for example the nginx checks on a development machine, or the
credential check when you left it out. It is not a problem.

- Normal: every check Pass or n/a.
- Warn: look at it soon; Roxy still works.
- Fail: fix it now. Each check names its runbook; the
  [health check table](/admin/help/runbooks#health-checks-and-their-runbooks) lists them all.

**Exports**: **Copy whole run for LLM**, **JSON** (the full report) and **Printable report** (a page you can print or
save). Every export is written to the audit log.

**What changed** (on a finished run): "Since run N:" with the checks that are **newly failing** and the ones
**fixed**, or "This is the first finished run" when there is nothing to compare with. **Compare with** lists up to
25 recent runs; pick one and press **Compare** to get a table, check by check, of the two runs: **Check**,
**Change** (Worse, New check, Value changed, Better, Not in this run, Same, with the worse ones first) and each run's
status and value. Compare a failing run with the last good one to see what broke, and when.

### Run history

The page's main table: every run, newest first. Columns: **Run** (it opens the run in the Run card), **Started**,
**Worst**, **Trigger**, **State**, **Pass**, **Warn**, **Fail** and **Duration**; **n/a**, **Critical**,
**Finished**, **Started by** and **Version** are in the column chooser. Filters: **Trigger** (Started by an admin,
Scheduled, After a deploy, From the command line) and **Worst result** (Pass, Warn, Fail, n/a); a search box; CSV or
JSON export (written to the audit log). The filters, sort and page stay in the page address.

Runs are kept for `retention_health_days` (180 days) and at most `health_runs_max` (2,000 runs); both are on the Data
page's Retention card.

- Normal: Scheduled runs every few hours, mostly Pass.
- Worrying: the same check failing run after run, scheduled runs that stopped appearing (the leader is not running
  its jobs: see [Workers or leader missing](/admin/help/runbooks#workers-or-leader-missing)), or runs that end
  **Interrupted** (a worker stopped in the middle: see [Service down](/admin/help/runbooks#service-down)).

### Schedule

Roxy can run the health check by itself. The card says in words:

- **Automatic runs**: On ("Every 6 hours, run by the leader; a new failure sends an alert") or Off ("Runs happen only
  when you press Run").
- **Credential check**: left out of scheduled runs (the default, to save the account's calls) or included.
- **Last scheduled run**, and **Next**: about when the next one starts.

Its two settings:

- **Scheduled health check interval** (`health_auto_interval_h`, 6 hours, 0 to 168): 0 turns scheduled runs off;
  you can still press Run.
- **Include credential checks in scheduled runs** (`health_auto_include_credential`, off): when on, every scheduled
  run spends one call on the Roblox account (about 4 a day at the default interval). Changing it either way asks you
  to confirm it is you. The credential has its own periodic check as well (Credential page).

When a scheduled run finds failures that the run before did not have, Roxy sends the alert "Roxy: health check found
N new failures" (the same set of failures is alerted at most once a day).

- Normal: On, with the last scheduled run within the interval.
- Worrying: Off when you did not turn it off, or a last scheduled run much older than the interval (see
  [Workers or leader missing](/admin/help/runbooks#workers-or-leader-missing)).

### Checks

The catalog of every check: what it measures, how it is judged and where its fix is. The subtitle says how many
checks there are; the reachability check (`H-REACH-` followed by the host) runs once for each allowed Roblox host.
Columns: **Check** (title and id; **Calls the account** marks the one that spends a credential call), **Measures**,
**Pass, warn and fail** (the limits) and **Fix** (a link to the page or runbook).

The checks, in the order a run lists them:

- **The credential**: configured, still signed in as the same account, not cooling down, and the leak guard
  self-test (a fake credential-bearing rotator request must be blocked; it is never sent).
- **The network**: no proxy variables leaking into Roxy's clients, name lookups (DNS) and encrypted connections
  (TLS) to each allowed Roblox host, each host's reachability, and a full trip through nginx (the web server in
  front of Roxy) and Roxy.
- **Recent traffic**: Roblox latency, the Roblox 429 rate and the caller 5xx rate over the last 15 minutes. The 5xx
  rate leaves the pause's own 503 answers out: a pause you chose is not an error, and while only the pause answered,
  H-ERR-RATE is n/a with the value "Roxy is paused".
- **Cache and storage**: a cache write, read and delete round trip, cache effectiveness over the last hour, database
  integrity, database sizes against the budget, [WAL](/admin/help#term-wal) file sizes and free disk space.
- **Workers**: worker heartbeats, the scheduler leader and the event loop lag (how long a worker is too busy to
  answer).
- **The rotator**: reachable, sticky sessions working (one session keeps one exit address), and the quota left.
- **The server and the setup**: the system services that run Roxy (systemd units), nginx, the public certificate,
  the clock, the settings and rules, the ban list, secret file permissions, the alert channels (tested without
  sending), the last backup and its restore test, and the running version.

### On a phone

- The Run button takes the full width; the facts of a run and of each check sit in one column.
- The history table shows each run as a card with its number, start and worst result; tap it for the rest.
- The checks catalog turns into one block per check, each part labeled, so the page never scrolls sideways.

## Settings

The Settings page (`/admin/settings`, keys `g` then `s`) lists every runtime setting Roxy has: about 500 of them,
in 14 groups. A runtime setting is a value you can change while Roxy runs. A changed value is stored in Roxy's
control database, every [worker](/admin/help#term-worker) (one of the server processes that answer requests) picks it
up within about a second, and every change goes in the [audit log](/admin/help#term-audit-log) and the settings
history.

Most settings also sit on the card of the feature they tune (the throttle limit on Protection, the cache lifetimes on
Cache, and so on). It is the same setting in both places: a change made on one shows on the other. This page is the
full list, plus the change history, import and export, where alerts go, and the texts of the public site.

**When to use this page**

- You know (or can guess) a setting's name and want to find it fast, wherever it lives.
- You want to see everything you have changed from the defaults.
- You want to know who changed a setting, when and why, or to undo a change.
- You are about to change many things and want a copy of your settings first (export), or you want to load a copy
  back (import).
- You want to change where alerts go and how often, or what the public pages say.
- A recommendation or an audit entry sent you to one setting, or a failed health check sent you here (H-CONFIG
  opens this page, H-ALERTS its Alerts card).

The page has five cards, in this order: All settings, Change history, Import and export, Alerts and Public site. The
buttons at the top, Export my changes and Change history, are shortcuts to the export download and the history card.

### Time range on this page

The time range in the top bar changes only the Change history card. The page opens on "All" so the history starts
complete; the comparison switch has no effect here. The editor always shows the values in force now.

### How to read one setting

Every setting looks the same wherever it appears, here or inline on a feature card. (When one page shows a
setting on two of its cards, the second card shows only its value, with a link to the card that edits it.) From top
to bottom:

| Part | What it tells you |
|---|---|
| Label | The setting's plain name, for example "Requests per window". |
| Default badge | "Default" when the value is the catalog default; "Changed (default ...)" when you or something else changed it, with the default in the badge. |
| Risk badge | "Medium risk" or "High risk". A low-risk setting shows no risk badge, unless its value now is a high-risk one: then it shows "High risk". See "Risk levels" below. |
| Key | The setting's fixed name, for example `allowed_requests_per_minute`, with a Copy button. The key is what the audit log, exports, the API and the server command line use. |
| Description | What the setting does, in one or two sentences. |
| The value | A switch (On or Off), a choice list (the chosen option's meaning shows under it), a number with its unit (plain numbers with a range also get a slider; durations and sizes do not), a text box, or a list with one entry per line. |
| Hint line | What you may type (the allowed range, the longest text, or "One entry per line") and the default. Durations accept 90, 90s, 15m or 2h; sizes accept 65536, 64 KiB or 1 GiB (KB, MB and GB count in thousands, KiB, MiB and GiB in 1,024s). |
| What happens if I change this? | Opens the catalog's own explanation: what happens when a switch is turned on or off, what each choice means, what happens when a number is raised or lowered, when a value is high risk, notes, and related settings (each a link). |
| Footer | Who changed it last, when and why ("Changed ... by ...: reason"), or "Never changed from the default." ("Changed from the default." when the value differs from the default but no history row records who set it.) The History link opens the Audit page filtered to this setting. Reset to default fills in the default value; nothing is saved until you review and save it. |

On the Settings page, a few more lines can follow a setting:

- **Also on**: the cards that edit the same setting, as links (for example "Protection: Throttle"). A few settings
  also live outside the page cards: in the top bar's Pause dialog, the top bar's Emergency limit dialog, or the
  account menu's Preferences.
- **Open recommendations**: the rules that currently suggest changing this setting, with their severity. Each one
  opens on the Recommendations page.
- **Called `...` in v1**: the setting's old name. Eleven settings were renamed; search finds them by either name.
- A note under **Spam detectors dry run** (`spam_dry_run`): see "One setting this page cannot switch off" below.

Every setting in this release applies live. The code also knows a "Restart required" badge for a setting that waits
for the next restart or deploy, but no setting uses it today.

The full reference of every setting (its range, default, risk and notes) is `docs/SETTINGS.md` in the repository,
generated from the same catalog the page reads.

### Risk levels and what a high-risk change asks for

Every setting has one of three risk levels:

| Level | Badge | Meaning | How many |
|---|---|---|---|
| Low | none | Safe to experiment with and easy to undo. | about 390 |
| Medium | "Medium risk" (amber) | The change has visible effects; read "What happens if I change this?" first. | about 100 |
| High | "High risk" (red) | The change can break callers or weaken security. | 5 |

The five high-risk settings are high risk whatever value you pick: Strict Roblox host allowlist
(`strict_host_allowlist`), Spam detectors dry run (`spam_dry_run`), Allow emailed login codes
(`admin_email_code_enabled`), Raw IP addresses in exports (`export_include_ips`) and Allow browsers on any website
(CORS) (`public_cors_allow_any_origin`). Every change of these five, even back to the safe value, asks for the reason
and the tick described below.

About 70 other settings are high risk only at certain values. For example Metrics queue size per worker
(`metrics_queue_max`) is medium risk, but a value above 200,000 is high risk because it can push a worker past its
memory limit on this server; Lowest alert severity sent (`alert_min_severity`) is high risk at "Critical only". As soon
as you type such a value, a red "High-risk value." box appears under it with the reason. For the five settings above,
the box appears for any change and says that a reason and a confirmation are needed.

A high-risk change asks for two things before it is saved:

1. **A reason.** It goes in the audit log and the settings history. For other changes the reason is optional (but
   still worth writing).
2. **A tick** in "I understand the risk described above" (or, when you save several at once, "I understand the high
   risk of these changes").

No typed phrase is asked on this page. The server checks both rules again when it saves, so the boxes in the browser
are a convenience, not the guard.

**A fresh second factor.** Separately from the risk level, 26 settings need a recent second factor: every setting in
the groups "Admin security and sessions" and "Credential", plus Raw IP addresses in exports (`export_include_ips`) and
Include credential checks in scheduled runs (`health_auto_include_credential`). These decide who may sign in and what
the one Roblox credential is used for. Such a setting says "Saving asks for a current code from your authenticator
app first.", and saving asks you to confirm it is you ([Step 4](#step-4-save-the-recovery-codes)): the "Confirm it is
you" dialog takes a code from your authenticator app or a recovery code, and the save goes on. Cancel it and nothing
is saved.

**Rules between settings.** Some settings must agree with each other, for example a minimum may not be above its
maximum, and the request deadline must leave room for the retries. The list is under "Rules between settings" at the
bottom of the All settings card. A change that would break one is refused with the rule's text, and the review shows
the problem before anything is saved.

**One setting this page cannot switch off.** Spam detectors dry run (`spam_dry_run`) is on by default: the spam
detectors only report who they would ban. Switching it off arms them, so they ban for real. The Settings page refuses
that change and points to Protection > Spam detectors, which first replays recent traffic and shows who would have
been banned (see [Protection](#protection)). An import, a revert or the server command line that would switch it off
is refused the same way. Switching the dry run back on is allowed here at any time.

**Reasons and dashes.** A reason may not contain the long dash characters (em dash and en dash), which Roxy does not
use anywhere. Use a comma, a colon, parentheses or a plain hyphen instead; the save says so if you paste one.

**No secret in a setting.** No setting is meant to hold a secret, and several are texts every caller reads (the pause
message, the public site texts). A value that holds the Roblox credential (or a long piece of it), another secret
Roxy keeps, or a `.ROBLOSECURITY` cookie value is refused, whoever writes it (this page, a card, an import, a revert,
a recommendation or the command line), and the message never repeats the value. A secret that reached a reason is
removed from the history like from the audit log, and the history, its downloads and the export never show one.

### The All settings card

This is the editor. Its subtitle says how many settings exist and how many you have changed from the default.

**Finding a setting**

- **Find a setting**: type part of a key, an old v1 name, a label or a word from the description. Every word you type
  must appear; the best matches come first (an exact key, then keys that start with or contain your text, then
  labels, then descriptions).
- **Group**: one of the 14 groups, each with its count: Routing and egress; Credential; Upstream pacing and
  resilience; Cache; Throttling; Abuse detection; Tarpit; Admin security and sessions; Alerts and email; Metrics,
  retention and capture; Insights; Recommendation rule tuning; Public site and compatibility; Dashboard.
- **Risk**: the setting's own level (Low, Medium or High). A low-risk setting with a high-risk value still counts as
  low here.
- **Only what I have changed**: the settings that differ from their default, with the count. This is the quickest
  way to see how your server differs from a fresh install.
- **Only with an open recommendation**: the settings a recommendation currently suggests changing, with the count.

The line under the filters says what is shown ("Showing 1 to 10 of 35 settings"). Settings are grouped under their
group's name. The pager at the bottom moves between pages (Previous, Page 1 of 4, Next) and chooses how many settings
a page shows: 10 (the default, which keeps the page light on the 1 GB server), 25, 50 or 100. The search and the
filters stay in the address bar, so you can bookmark a view or send the link.

**One setting on its own.** `/admin/settings?key=<key>` shows only that setting (the address `/admin/settings#<key>`
goes there too). Recommendation evidence and the audit log link this way, and the command palette (Ctrl K) sends you
here for a setting that has no feature card. Under the setting, "Changes of this setting" lists its newest 10
changes: when, from what to what, by whom and why. Each opens in the side drawer with its revert form (see the Change
history card), and "Its whole history in the audit log" opens the rest. "Show every setting" goes back to the list.

**Saving one setting**

1. Change the value. A Reason box appears; for a high-risk value it is required and the "I understand" box appears.
2. Press **Review**. The setting shows "Review this change": the value now, the value after saving, what happens (the
   catalog's text for raising, lowering, turning on or off), and the risk.
3. Press **Save** (the same button, renamed). If the setting needs a fresh second factor, "Confirm it is you" may open
   first. The setting then shows "Saved" and its new last-change line, and a message confirms it.

Cancel puts the value back as it was. Changing the value again after a review goes back to Review.

**Saving several settings at once**

Change as many settings as you like, even on different pages of results: the page remembers each unsaved edit until
you save, discard, reload or leave it. A bar at the bottom of the card counts them ("3 unsaved changes (1 on other
pages of results)").

- **Review all changes** opens "Review your changes": one row per setting with Now, After saving and What happens
  (the consequence, "High risk: ..." when it applies, or what is wrong with the value). Problems with the rules
  between settings are listed under the table.
- Give one reason for the whole batch. It is required when the batch holds a high-risk change, and so is the "I
  understand the high risk of these changes" box. A line names the settings that need a fresh second factor.
- **Save N changes** sends only the settings you changed, all together: either every one is saved or none is. A
  message confirms it, and the card and the history refresh.
- **Discard all** drops every unsaved edit.

If you try to leave the page with unsaved edits, the browser asks first.

**What looks normal and what to worry about.** "Only what I have changed" should list settings you remember
changing, or changes made by recommendations you applied. A setting you do not recognize: open it, read its footer
and its history (who, when, why), and revert it if it was not meant (see below). A setting showing "High-risk value."
deserves a second look even if you set it on purpose. A count next to "Only with an open recommendation" means
Roxy's own numbers suggest a change: review those on the [Recommendations](#recommendations) page, where you can
preview them first.

### The Change history card

Every settings change, newest first: made on this page, on a feature card, by a recommendation (applied by you or by
automatic apply), by an import, by a revert, from the server's command line, or by Roxy itself. The card loads as it
scrolls into view.

The page opens on the time range "All", so the card lists every change ("Every change: 42 changes"). Pick another
range in the top bar and only the changes inside it are listed; a notice says so.

| Column | What it shows |
|---|---|
| When | When the change was saved, in your dashboard time zone. |
| Setting | The label, with the key under it. It links to that setting on its own. |
| Before | The value before the change. "the default" under it means it was the catalog default. |
| After | The value after the change, with "the default" when the change put the default back. |
| Changed by | Who made it, as a kind and a name: `admin:` and your user name (also for a recommendation you applied and an import you ran), `cli:` and your server login for the command line, `auto_apply:insights` for automatic apply, `import:v1` for the values the move from v1 brought over, or `system:` and a part of Roxy for its own changes. |
| Source | Where it came from: `admin` (the dashboard), `revert`, `import`, `recommendation:<id>`, `auto_apply`, `cli` or `system`. |
| Reason | The reason given with the change, if any. |
| Change | The change's number (hidden by default; the Columns menu shows it). |

Above the table: a search box (it looks in keys, reasons and who made the change), a Source filter with a count per
source, the Columns menu, and Export (CSV, safe to open in a spreadsheet, or JSON). Every download is written to the
audit log. Sorting and rows per page work as in every table.

**One change in the drawer.** Press a row to open "Settings change #N": when, who, the source, the reason, the value
before and after, a link to the setting ("Open this setting") and to its whole history in the audit log, and "Undo
this change".

**Reverting a change.** "Revert this change" puts the setting back to the value it had right before that change, on
every worker within a second.

- The revert is itself a change: it is written to the history (source `revert`) and the audit log with your reason,
  so you can revert the revert.
- The reason is optional, except for a high-risk setting or when the value it goes back to is high risk; then the
  reason is required and so is the tick in "I understand: the old value is high risk". For one of the five high-risk
  settings the box shows from the start; for another setting it appears when the server asks for it.
- A setting that needs a fresh second factor asks for it before the revert.
- A revert goes back to the value from before that change, even if the setting was changed again since. When it was,
  the drawer says so first: "This setting was changed again after this change (it is now ...). Reverting this one
  also undoes those later changes; to undo only a later one, revert that change instead." The message after the
  revert repeats the server's own warning.

The drawer offers no revert in three cases, and says why: the revert would switch the spam detectors' dry run off
(arm them from Protection instead); the setting no longer exists in this release; or the setting is a secret whose
earlier value is never kept (no setting in this release is a secret, so you should not see this).

Two other ways to undo: change the value back by hand, or use Reset to default on the setting. The Audit page also
reverts settings changes from its entries (see [Audit](#audit)).

**How long the history is kept.** Settings history retention (`retention_settings_history_days`, on Data >
Retention) is 0 by default, which keeps every change. Whatever it says, at most 100,000 rows are kept (oldest first
to go) and the latest change of every setting is never deleted. The audit log keeps its own copy for Audit log
retention (`retention_audit_days`, 730 days by default).

**What to worry about.** You run the server alone, so changes should come from `admin:` and your own name, from
recommendations you applied, from `auto_apply` only if you allowed automatic apply, or from `cli` when you used the
command line. A change by a name you do not know, or at a time you were not signed in, is a reason to follow the
[Unexpected admin login](/admin/help/runbooks#unexpected-admin-login) runbook.

### The Import and export card

**Export.** "Download my changes" (or the page's Export my changes button) downloads a JSON file named like
`roxy_settings_1760000000000.json`. The card says how many settings it will hold.

- **What it holds:** every setting you changed from its default, with its value, plus the catalog version (so an
  import can tell when the file comes from another release), the configuration version and the time of the export.
- **What it leaves out:** every setting that is at its default; secrets (Roxy's secrets are systemd credentials on
  the server, never settings; a secret setting would be written as `[redacted]` and skipped on import, but none
  exists in this release); the environment files; the Roblox credential and the rotator address; rules, bans, lists
  and every other table you edit on the feature pages (they are data, kept in the databases; a backup holds them, see
  [Backups and resets](#backups-and-resets)); the history and the audit log; your admin account, passkeys and sessions.
- The download is written to the audit log. There is nothing to undo.

Export before a session of risky changes: the file is your way back.

**Import.** Load a file made by Export my changes:

1. Choose the file (at most 512 KB), or open "Or paste the file's text" and paste it. A small JSON object of keys and
   values, such as `{"alert_rate_limit_per_hour": 40}`, works too. Old v1 names are understood.
2. Decide on **Replace: settings the file does not name go back to their defaults**. Leave it off to apply only what
   the file holds. Tick it to make this server match the file exactly: every other changed setting goes back to its
   default.
3. Press **Preview the import**. Nothing changes yet. A table lists each setting with its value now, the value in the
   file and the result: Will change, Already set, Back to the default (with Replace), Not valid (with the reason),
   Unknown setting, Not imported here (a value an import may not set, such as the spam detectors' dry run switched
   off), or Skipped. A summary counts the changes and says when the file was made with another version of the
   catalog.
4. If any row is Not valid or Unknown setting, or a rule between settings would break, nothing can be imported: fix
   the file (correct the value, or delete the line of a setting this release does not know) and preview again. A
   file that would switch the spam detectors' dry run off is refused too (see "One setting this page cannot switch
   off" above).
5. Give a reason (always required: an import changes many values at once). Tick "I understand: the file holds
   high-risk values" when it appears. A line names the settings that need a fresh second factor; "Confirm it is you"
   opens if yours is not fresh.
6. Press **Import these changes**. Everything is applied at once or nothing is, and every worker uses the new values
   within a second. Each setting gets its own row in the history (source `import`).

To undo an import, revert its rows in the Change history card, or import the export you took before (with Replace
ticked if you want an exact match).

### The Alerts card

Where alerts go and how often. The same seven settings are on System > Alerts; change them in either place. Alerts
are deduplicated by their cooldown and capped per hour across all workers; a leak guard alert and the daily digest
are never held back. The
channels themselves (the email password and addresses, the webhook address) are credentials on the server, not
settings: System > Alerts shows which exist. **Send test alert** posts one real low-severity message to every
configured channel (one a minute, within the hourly cap; see [Testing that alerts arrive](#testing-that-alerts-arrive)).

| Setting | Key | Default | What it does |
|---|---|---|---|
| Lowest alert severity sent | `alert_min_severity` | Warnings and above | Alerts below this level are not sent. "Info and above" is noisy; "Critical only" is high risk because slow problems (Roblox rate limiting, a failed backup, a filling disk) would reach you late. New admin login emails are always sent. |
| Alert limit per hour | `alert_rate_limit_per_hour` | 20 messages per channel per hour | Alerts over the limit are held back and counted; the next message says how many were suppressed. |
| Send the daily digest | `alert_digest_enabled` | On | Emails a daily summary: open recommendations, failing health checks and the Roblox rate limiting numbers. It is sent whatever `alert_min_severity` says, and the hourly limit never holds it back (it is one email a day). Switch it off here. |
| Daily digest hour | `alert_digest_hour` | 9 | The hour (0 to 23, in the dashboard time zone, New York by default) at which the daily digest is emailed. |
| Send alerts to webhook | `alert_webhook_enabled` | Off | Also post alerts to a webhook (for example a Discord channel). The address is the server credential `alert_webhook_url`. |
| Credential alert cooldown | `email_cooldown` | 600 seconds | The least time between two alerts about the Roblox credential. |
| Error alert cooldown | `error_email_cooldown` | 300 seconds | The least time between two alerts about the same Roxy error, shared by every worker. |

The defaults suit one owner. If your alert emails often say that alerts were suppressed, something keeps going wrong:
follow the runbook the alerts link to rather than raising the limit. The [Alerts](#alerts) chapter lists every alert.

### The Public site card

The thirteen settings that change what visitors and callers see. No feature page has them, so apart from the All
settings card this card is the only place to edit them. The card loads as it scrolls into view. While a page is
under construction, the card's introduction links it ("Under construction now: ..."), so you can open it from here.

| Setting | Key | What it changes |
|---|---|---|
| Bug bounty text | `site_bug_bounty_text` | The bug bounty paragraph on the home page. Empty by default (no bug bounty): the home page leaves the paragraph out and the user guide says there is none. A text you set names amounts of money, so keep it current; v1's paragraph is in the setting's notes. |
| Contact name and where to reach them | `site_contact_name` | Who the public site tells visitors to contact, and where (by default "CeaselessQuokka on the DevForums or Twitter"). It completes "Contact ..." sentences. Plain text: use public handles and places only, never a private email address or phone number. |
| Footer text | `site_footer_text` | The small line at the bottom of every public page. |
| Hosting and costs note | `site_hosting_note` | The "Roxy internals" section of the home page. |
| Support and 'also by the author' text | `site_support_links` | The "Support me" section of the home page, with links to your other projects. Empty by default: the home page leaves the section out. |
| No login required and white hats text | `site_white_hats_text` | The home page section that warns visitors never to send their .ROBLOSECURITY cookie. |
| Public status page | `public_status_page_enabled` | Turns the public `/status` page on (the default) or off. |
| Home page under construction | `public_home_under_construction` | Off by default. On, visitors to `/` get the under-construction page instead of the home page; you still see the real page while signed in. See [Putting a page under construction](#putting-a-page-under-construction). |
| User guide under construction | `public_docs_under_construction` | The same for the user guide (`/docs`). |
| Status page under construction | `public_status_under_construction` | The same for the status page (`/status`). While the status page is turned off, `/status` stays a 404 for everyone, whatever this says. |
| Under construction message | `site_construction_text` | The message on the under-construction page, by default "Roxy's site is being updated. Check back soon." Up to 500 characters. |
| Allow browsers on any website (CORS) | `public_cors_allow_any_origin` | Off by default and high risk: on, any website can use Roxy from its visitors' browsers as a free API. Game servers never need it. |
| v1-style upstream errors (always 500) | `compat_collapse_upstream_errors` | Off by default (medium risk): callers get Roblox's real status, such as 404, or 429 with a Retry-After header (owner decision D4). On brings back v1's "every upstream failure is a 500". |

The texts take plain paragraphs (a blank line starts a new one) and https links written as `[label](https://...)`;
anything else, HTML included, is shown exactly as typed. Each home page text holds up to 2,000 characters (the
under-construction message 500) and, like every text setting, may not contain an em or en dash. After a change, open
the home page (`/`) or the status page (`/status`) to check the result.

### Putting a page under construction

When you want to rework the home page, the user guide or the status page without the public reading it meanwhile,
turn on its switch on this card: **Home page under construction**, **User guide under construction** or **Status
page under construction**. Each page has its own switch, and the change takes effect at once, like every setting
(it is in the change history and the audit log, and you can revert it there).

- **What the public sees.** A short page in the site's style: "Roxy's user guide is under construction" (or the home
  page, or the status page), your message from **Under construction message**, and a line saying the proxy keeps
  working. It answers with HTTP 503 and `Retry-After: 3600`, which tells search engines the page is away for a while,
  not gone, and it asks them not to index the stand-in. The page also leaves `sitemap.xml` until you turn the switch
  off. Search engines keep a page through a short absence; one left under construction for many days may drop out
  of search results for a while.
- **What you see.** Open the page while you are signed in to the dashboard (the links on this card are the easy way)
  and you get the real page, with a banner at the top: "Admins only: the public currently sees the
  under-construction page for this page." Its button **See what the public sees** shows you exactly the public page,
  with a small notice in the bottom corner, "You are viewing this page as the public sees it", and a **Back to admin
  view** link.
- **How Roxy knows it is you.** Your dashboard sign-in, checked again on every visit: nothing else is handed out. So
  signing out, revoking the session on the Security page or the kill switch shows you the public page on the next
  load, and so does a session that expired (after `admin_session_idle_timeout_s`, 15 minutes by default, without
  using the dashboard; reading the pages one after another counts as using it). With the admin allowlist on, only
  allowlisted networks get the admin view. A link to Roxy you follow from another site (Discord, the DevForum) does
  not carry your sign-in, because the session cookie is only sent from Roxy's own pages; open the page from the
  dashboard or type its address instead.
- **What never changes.** Only these three pages. The proxy, `/health`, `/robots.txt`, the favicon, the dashboard and
  the sign-in page answer as always, so game servers and uptime monitors notice nothing. Deploys keep working too: the
  deploy's smoke test accepts the under-construction page as the answer of `/` (it carries the header
  `Roxy-Under-Construction: True`), as it accepts a pause.

Turn the switch off again when you are done; the page is back for everyone on the next load.

### Settings only the server can set

Some configuration is not a runtime setting at all, so the Settings page cannot change it. It is read once when a
color (the blue or the green copy of Roxy, see [System](#system)) starts. To change it, edit the file on the server as
root, then restart the colors. The simplest way without downtime is to deploy the commit that is already running:
`/opt/roxy/deploy.sh <the commit in /var/lib/roxy-deploy/deployed_version>`. System > Environment shows what the
running workers started with.

**The environment files** (`/etc/roxy/roxy.env` for both colors, then `/etc/roxy/<color>.env`). Not secret; root
owns them.

| Variable | What it sets |
|---|---|
| `ROXY_ENV` | `production` on the server; `development` is for a laptop only. |
| `ROXY_WORKERS` | Worker processes per color: 2 on this server. |
| `ROXY_MAX_REQUESTS` | A worker is replaced after this many requests (20,000), a guard against slow memory growth. |
| `ROXY_TRUSTED_PROXY_HOPS`, `ROXY_TRUSTED_PROXY_CIDRS` | Which proxies in front of Roxy may name the caller's address (nginx on the same machine: 1 hop from loopback). |
| `ROXY_SITE_ORIGIN` | The public address: used in alert email links, and to check that dashboard requests come from your own site. |
| `ROXY_SEND_HSTS` | Off: nginx sends the HSTS header, not Roxy. |
| `ROXY_LOG_LEVEL` | How much Roxy writes to the journal (`info`). |
| `ROXY_STATE_DIR` | Where the databases live (`/var/lib/roxy`). |
| `ROXY_ROTATOR_IP_ECHO_URL` | The address used to see which exit address the rotator gave. |
| `ROXY_BACKUP_REMOTE` | The name of the off-server backup destination, when you use one. |
| `ROXY_COLOR`, `ROXY_BIND`, `ROXY_INTERNAL_SOCKET` | Per color, in `/etc/roxy/<color>.env`: which color this is, and where nginx and the server tools reach it. |
| `ROXY_NGINX_WORKER_PROCESSES`, `ROXY_NGINX_WORKER_CONNECTIONS` | Not yours to edit: `roxy-nginx-apply` writes them into a third file, `/etc/roxy/nginx-hints.env`, from the installed nginx. Roxy only uses them for a consistency check (H-NGINX). |
| `ROXY_AUTO_MIGRATE` | Development only; a production worker never migrates, whatever it says. |

The deploy tools and the backup read a few more from `roxy.env`: `ROXY_DEPLOY_REPO_URL`, `ROXY_DEPLOY_BRANCH`,
`ROXY_BACKUP_HOT`, `ROXY_BACKUP_AGE_RECIPIENTS` and `ROXY_NGINX_SERVER_NAMES`.

**The systemd credentials** (`/etc/roxy/credentials/<name>`, one file each, root only, mode 0600). These are the
secrets. A [systemd credential](/admin/help#term-systemd-credential) is handed to Roxy privately when a color starts;
it never appears in the environment, a page, an export or a log. An empty file means "not configured". System >
Environment lists seven of them by name with "present" or "missing" (a file that is empty counts as missing), never
a value; the Roblox credential gets its own line there, and `rclone_config` is not listed.

| Credential | What it holds |
|---|---|
| `roblox_credential` | The starting value of the one Roblox credential. The Credential page can replace it with a value it stores encrypted, and go back to this file. |
| `rotator_url` | The rotator's address with its login (optional: empty when you do not use the rotator). The Egress page can set a value that takes its place. |
| `smtp_password`, `alert_emails` | The email channel: the mail (Gmail app) password, and the to and from addresses. |
| `alert_webhook_url` | The webhook channel (optional). |
| `credential_encryption_key` | Encrypts a Roblox credential or rotator address set from the dashboard. |
| `totp_encryption_key` | Encrypts your authenticator app secret. |
| `ip_hash_key` | Turns client addresses into the hashes stored in statistics and exports. |
| `rclone_config` | The off-server backup's keys (optional; used by the backup, not by Roxy itself). |

The [Alert channels down](/admin/help/runbooks#alert-channels-down) runbook walks through replacing a credential.

### From the server

When the dashboard is out of reach (for example the admin allowlist hides `/admin` from your network), the operator
command line on the server reads and writes the same settings, with the same validation, the same rules between
settings and the same history (source `cli`, changed by `cli:` and your login name). It asks for no second factor:
only someone logged in to the server can run it. Every worker picks up the change within about a second.

```sh
roxyctl settings show alert_rate_limit_per_hour
roxyctl settings set alert_rate_limit_per_hour=40 --reason "more room during the migration"
```

A high-risk value (or any change of one of the five high-risk settings) needs both `--reason` and
`--confirm-high-risk`. `settings show` without a key lists every setting. `roxyctl` is the runbooks' short name for
`scripts/ctl.py`, run as the `roxy` user; see [The operator CLI](#the-operator-cli) and the
[Admin locked out](/admin/help/runbooks#admin-locked-out) runbook.

### On a phone

The filters stack one per line, and the bar of unsaved changes sits just above the phone's menu bar. The
history table shows When, Setting and After; press a row for the rest. The review and import tables turn each row
into a block with its column names.

## Credential

The Credential page (`/admin/credential`) shows the one Roblox account Roxy may use: whether it works, how hard it is
used, and how to replace it safely. The [credential](/admin/help#term-credential) is the
account's `.ROBLOSECURITY` cookie. Its value is never shown anywhere: only its last characters and a fingerprint (a
keyed hash that identifies a value without revealing it).

Two rules shape the page:

- **One account, always (plan C1).** Roxy holds exactly one credential and never rotates or switches accounts on its
  own. Roblox ties rate limits and abuse scoring to the account and the server address together, so several accounts
  behind one address look like account farming. The credential always leaves from the server's own address, never
  through the rotator.
- **The endpoint policy decides who gets it (owner decision D1, revised 2026-10-16).** Caller requests carry the
  account only for the endpoints the [Endpoint policy](#endpoint-policy) page sends with it; Roxy's own checks use it
  too, about 50 to 60 calls a day.

The button at the top, **Credential history**, opens the Audit page filtered to every credential change.

Checking, replacing and deleting the credential, and changing any setting on this page, ask you to confirm it is
you ([Step 4](#step-4-save-the-recovery-codes)). Every one of these actions is
written to the audit log; the value itself never is, only its fingerprint and masked form.

**When to use this page**

- The alert "Token Expired" arrived, or the health check H-CRED-AUTH or H-CRED-PRESENT fails: Status and Probes,
  then the runbook [Credential rejected](/admin/help/runbooks#credential-rejected).
- The alert "Roxy: credential cooling down" arrived, or H-CRED-COOLDOWN warns: Status and Budget, then
  [Credential cooling down](/admin/help/runbooks#credential-cooling-down).
- The alert "Roxy: Roblox sent a new credential cookie" arrived:
  [Credential rotated by Roblox](/admin/help/runbooks#credential-rotated-by-roblox).
- You need to renew the cookie, or you set Roxy up for the first time: the Replace card.
- You want to know or change which endpoints use the account: the [Endpoint policy](#endpoint-policy) page.

### Time range on this page

Status shows the state now; the "Calls with the credential" lines of Status cover the time range in the
top bar. Budget shows its buckets now, their reservations and refusals in the range, and fixed totals for the last
hour and the last 24 hours. Probes lists the latest 50 checks of the last 90 days. Nothing on this page draws a
comparison.

### Status

Is the credential working? A badge and a sentence:

| Badge | Meaning |
|---|---|
| Working | Roblox accepted the credential at its last check. |
| Not checked yet | A credential is loaded; the next check (or Check credential) tells whether it works. |
| Cooling down | Roblox answered a credential call with 429; it rests until the cooldown ends. |
| Rejected | Roblox refused the credential (expired or revoked), so Roxy no longer uses it. |
| None loaded | No credential is loaded: only anonymous paths are used. |
| Switched off | `credential_enabled` is 0: no call uses the credential. |

Then:

- **Value**: an ellipsis and the last 6 characters ("only the last characters are ever shown").
- **Loaded from**: "set from this page" or "the bootstrap file (systemd credential roblox_credential)"; it also says
  when a dashboard value is in use, and when the bootstrap value was replaced and is refused.
- **Set**: when and by whom. **Fingerprint**: the value's fingerprint.
- **Account**: the fingerprint of the Roblox account it belongs to ("not recorded yet" before the first good check),
  with "Same account as before"; in amber "A different account than before the replace", with the earlier account's
  fingerprint (you replaced the cookie with another account's: used, because a replace is the deliberate change);
  or, in red, "A different account: not used until you confirm" (see Replace).
- **Cooldown**: a countdown with its source and the 429s that fed it, or "none".
- **Last probe**: when, and what it found, in words, for example "OK: Roblox accepted it", "Not checked yet since the
  replace", "OK: a different account than before the replace (replaced on purpose)", "Rate limited (a 429 means slow
  down, never expired)", "Rejected: the cookie expired or was revoked (Roblox answered 401)", "A different account
  than before: not used until you confirm", "Unexpected answer: Roblox answered 500, which says nothing about the
  credential" or "Failed: Roblox did not answer in time". A check's verdict always belongs to the cookie it checked: a
  check still on its way when you replace the cookie never marks the new one.
- **Probe schedule**: "every 30 minutes" (or "off") and the address checked.
- **Calls with the credential (this range)**: calls (and how many by Roxy itself), failed (timeouts, Roblox 429s),
  last success and last error.

**Check credential** (the button at the top of the card) checks it now: one call with the account to the check
address, through the reserved probe bucket. It asks you to confirm it is you first, because every check spends a
call on your account. Only one check runs at a time in the whole fleet; a second one is skipped
("Skipped: another probe was running"), and so is a check while the credential is cooling down ("Skipped: the
credential was cooling down") or switched off. The result appears on this card and in Probes; when the check is
still waiting for its slot after 40 s, the page stops waiting and the result shows up there a little later.

- **Normal:** "Working", the same account as before, no cooldown, the last probe OK within the last 30 minutes, and
  credential calls within the account's pace.
- **Worrying:** "Rejected" or "None loaded" (follow [Credential rejected](/admin/help/runbooks#credential-rejected));
  "Cooling down" (wait; see [Credential cooling down](/admin/help/runbooks#credential-cooling-down)); "A different
  account" (see Replace); many failed calls for callers (see the Endpoint policy page for what is sent with it).

Settings for this card (each asks for a fresh second factor, like every credential setting): Use the Roblox
credential (`credential_enabled`, on), Credential check interval (`credential_probe_interval_min`, 30 minutes; 0
turns the scheduled check off; every 1 to 4 minutes is high risk) and Credential check URL (`credential_probe_url`,
`https://users.roblox.com/v1/users/authenticated`; changing it is high risk, because the check must name the account
it belongs to). Turning `credential_enabled` off is the quick, reversible way to stop all account use, for example
while you look into a leak guard alert; it keeps the stored value.

### Budget

v1's "Token Safety Budget": how fast the account may be used. Two fill gauges:

- **Callers sent with the account (the credential rate limit minus the reserve)**: the credential bucket for caller
  requests the endpoint policy sends with the account. Its rate is `credential_bucket_per_min` minus the reserved
  share: 18 a minute (one every 3.3 s), with the credential burst minus 1 (2 by default). When it has no slot, an
  endpoint Roblox answers without a sign-in goes out anonymously instead; one that only answers signed-in users waits.
- **Reserved for Roxy's credential checks**: Roxy's own checks, kept apart so a check never waits behind caller
  traffic and caller traffic can never use up the checks' share: 2 a minute, burst 1. The two bursts add up to the
  credential burst, so no more than that many calls ever leave on the account back to back.

Under each gauge: its reservations, refusals and peak fill in the range. Then two totals: **Last hour** and **Last 24
hours**, each split into calls for callers and probes (the 24 hours also give the busiest hour's probes), next to
what to expect for the checks: "about 50 to 60 credential calls a day". Credential calls also pass the
global, host and endpoint buckets of the Upstream page.

- **Normal:** about 2 probes an hour (one every 30 minutes, a few more when you run Check credential or a health
  check that includes the credential), calls for callers below the account's pace, the probe gauge at "room to
  spare".
- **Worrying:** more than 6 probe calls in an hour (the recommendation CRED-PROBE-COST); the callers' gauge full most
  of the time, or Roblox 429s on the account (the recommendation UP-429-CREDENTIAL: lower the pace, or send the
  busiest endpoints without the account on the Endpoint policy page).

Settings for this card (each asks for a fresh second factor): Credential rate limit (`credential_bucket_per_min`, 20
a minute; high risk above 60), Credential burst (`credential_bucket_burst`, 3, shared as above: at 1, a check also
takes the callers' slot; high risk above 10), Reserved rate
for credential checks (`credential_probe_reserved_per_min`, 2; it must stay below the rate limit) and Credential rest
after a 429 (`credential_cooldown_default_s`, 60 s; high risk below 15; the same setting is also on the Upstream
page's Cooldowns card). v1 allowed about 88 account calls a minute with no pacing, so its whole budget could leave in
about one second; keep these low and raise them only with a reason.

### Which endpoints use it

The Credential page used to have an Allowlist card. It is gone: since owner decision D1 was revised (2026-10-16),
the [Endpoint policy](#endpoint-policy) page decides which caller requests carry the account, and its Summary card
lists the old allowlist rows with what the policy does with each now.

### Probes

Roxy's own calls with the credential, newest first (at most 50, over 90 days); the subtitle gives the last result.
Columns:

- **When**.
- **Why**: "Scheduled liveness probe", "Check credential (admin)", "Check Proxy Health (H-CRED-AUTH)" or "Confirm a
  Roblox 401 before marking it rejected".
- **Outcome**: **OK** (Roblox accepted it), **Rate limited** (a 429: slow down, never "expired"), **Rejected** (a 401 or
  403: the cookie expired or was revoked) or **Failed** (any other failure).
- **Status**, **Time** (how long the call took) and **Error**.

- **Normal:** OK every 30 minutes, with the occasional health check or admin check.
- **Worrying:** Rejected (replace the cookie: [Credential rejected](/admin/help/runbooks#credential-rejected));
  Rate limited more than once in a while (the account is called too often; see Budget); Failed several times in a
  row (Roblox or the network; see the Upstream page).

### Replace

The deliberate acts of rule C1. A warning stays on the card: Roxy uses exactly one Roblox account; replacing the
credential switches every credential call to the new cookie at once and the old value is never used again; moving
between accounts looks like account farming and can get the accounts and the server address throttled or banned;
replace it only to renew the same account's cookie, or when you deliberately move Roxy to another account; afterwards
remove the old cookie from the bootstrap file `/etc/roxy/credentials/roblox_credential`.

| Action | When it shows | What it asks | What it changes |
|---|---|---|---|
| **Replace the credential** | always | the new `.ROBLOSECURITY` value (a hidden field), the typed phrase `replace the credential` and an optional reason; then it asks you to confirm it is you | Every worker uses the new value within a second; the old one is never used again. Roxy checks the new value once, at once, to record which account it belongs to. |
| **Go back to the bootstrap file** | while a value set from this page is in use | an optional reason; then it asks you to confirm it is you | Deletes the dashboard value; Roxy loads the bootstrap file again, checks it at once and compares its account with the one used before. |
| **Confirm the account switch** | when that check found a different account | the typed phrase `switch to the other account` and an optional reason; then it asks you to confirm it is you | Roxy starts using the bootstrap value on every worker at once. |

The typed phrases ignore capital letters and extra spaces; anything else is refused and nothing changes.
The value is never echoed back, logged or written to the audit log: the audit log keeps only its fingerprint and
masked form. Pasting the cookie as `.ROBLOSECURITY=...` is fine; Roxy keeps the value only.

There is no undo, on purpose: Roxy never goes back to an older value by itself. Going back to the bootstrap file is
the only other source, and it only helps when that file holds a valid cookie of the same account.

**Renewing the cookie, step by step** (the runbook [Credential rejected](/admin/help/runbooks#credential-rejected)
has the same steps):

1. Write down the **Account** fingerprint the Status card shows now.
2. Sign in to the same Roblox account in a private browser window and copy its `.ROBLOSECURITY` cookie value. Never
   paste it into a ticket, a chat or a reason box.
3. Press **Replace the credential**, paste the value, type `replace the credential`, add a reason if you like, and
   confirm it is you.
4. Check the Status card once the first check after the replace has run ("Not checked yet since the replace" until
   then): "Working" and "Same account as before", the same Account fingerprint as in step 1. "A different account
   than before the replace" means the cookie belongs to another Roblox account: if you did not mean to move Roxy,
   replace it again at once with the right account's cookie.
5. Empty the bootstrap file on the server so the old cookie is not kept on disk:
   `sudo truncate -s 0 /etc/roxy/credentials/roblox_credential`. Keep the file itself; an empty file means "no
   bootstrap value".

**When Roblox rotates the cookie** (the alert "Roxy: Roblox sent a new credential cookie"): Roxy does not store the
new cookie, and the one it holds may stop working soon. Renew it as above, with the same account.

**When a check finds a different account** (the Status card says "A different account: not used until you
confirm", and the alert "Token Expired" is sent, its text saying that the credential now answers for a different
Roblox account): Roxy stops using the credential until you decide. This happens after going back to a bootstrap file
that holds another account's cookie, or when the bootstrap file was changed to another account's cookie and the
service restarted while no dashboard value was in use. (A replace from this page is different: it is the deliberate
change itself, so another account's cookie is used at once and shows as "A different account than before the
replace".) Confirm the switch only if you meant to move Roxy to that account; otherwise replace the credential with
a cookie of the right account. Never switch back and forth between accounts.

### On a phone

Below 900 px wide the Status and Budget cards stack into one column. Below 600 px the Probes table turns each row
into a block of labeled lines. The Status lists become one column below 480 px.

## Data

The Data page (`/admin/data`) shows what Roxy stores and for how long. It deletes statistics you no longer want,
takes backups, gives disk space back to the server, and exports any dataset as a file.

**When to use this page**

- After the alert "Roxy: storage at <pct>% of budget", or when the health checks H-DB-SIZE, H-WAL or H-DISK warn:
  Storage first, then Retention and Vacuum. Runbook:
  [Disk full or database large](/admin/help/runbooks#disk-full-or-database-large).
- A load test or an attack left numbers you do not want in your charts: Resets.
- Before a risky change: Back up now.
- After the alert "Roxy: backup failed" or "Roxy: no backup for <hours> h": Backups. Runbook:
  [Backups](/admin/help/runbooks#backups).
- To open numbers in a spreadsheet, share them, or ask an AI assistant about Roxy: Exports.
- To keep data longer or shorter: Retention and Record caps.

### How the page is laid out

The cards appear in this order: Storage, Resets, Backups, Exports, Vacuum, Retention, Record caps. Storage, Vacuum,
Retention and Record caps measure every database, so they load on their own a moment after the page (or as soon as
you scroll to them). The buttons at the top are Back up now (the same dialog as on the Backups card) and Reset
statistics (it jumps to Resets). The "How to read this page" panel explains snapshots, chart markers and export
privacy.

Roxy keeps its data in four SQLite files: `control.db` (settings, rules, admin accounts and the audit log),
`metrics.db` (statistics and logs), `hot.db` (short-lived limiter and pacing state) and `cache.db` (stored Roblox
answers).

### Time range on this page

Only the Exports card follows the time range in the top bar: the datasets that have a time cover that range (the LLM
export uses its own Covering choice instead). The other cards show how things stand now. The comparison changes no
number on this page, and the Exports subtitle names only the range.

### Storage

Four numbers open the card:

- Stored by Roxy: every database file with its write-ahead log ([WAL](/admin/help#term-wal), the file SQLite writes
  recent changes to first), plus the snapshots and exports folders.
- Storage budget used: stored bytes against the Disk budget (`storage_total_budget_gb`, 12 GB by default), labeled
  Within the budget, Close to the budget (90 percent or more) or Over the budget. An alert is sent from 90 percent,
  and the SYS-DISK recommendation appears from 70 percent. Reaching the budget deletes nothing: retention does that.
- Measured growth per day: how much the files really grew per day, from the leader's hourly disk samples over the last
  30 days, with a small chart. It needs at least six hours of samples; until then the card says how many it has.
- In 30 days (projected): an estimate for 30 days from now, from the rows added over the last week, bounded by each
  table's age and row limits.

A line under the numbers says how many traffic rows are written a minute over the last week. The subtitle says when
the card measured (a measurement is reused for up to a minute); Measure again measures now. A database that could not
be measured gets a warning with the reason.

"Database files, write-ahead logs and folders" (folded) lists each database file with its Database, WAL and SHM
(shared memory) sizes and the three together, then the `snapshots/` and `exports/` folders.

The table lists every table of the four databases:

| Column | What it means |
|---|---|
| What it holds | The table in plain words. |
| Database | Its file. |
| Rows | Rows now. |
| Bytes | Bytes on disk, its indexes included (empty when SQLite cannot tell). |
| Bytes in 30 days | The projection. |
| Retention | Within its limits; Older rows wait for the next prune; or Over its row cap until the next prune. |
| Table, Rows in 7 days, Rows in 30 days, Oldest row | Hidden by default. |

It starts sorted by Bytes, biggest first, and its search box finds tables. Open a table for its drawer: rows, bytes,
oldest and newest row, rows added in 7 days, the 30 day projection and how it was made, how long rows are kept and the
row cap (each with a link to the setting that sets it, or the rule in words where no setting does), its state, and its
measured size over time (sampled every 6 hours).

**Normal:** the budget well under 70 percent, a steady growth per day, and every table Within its limits, or briefly
"Older rows wait for the next prune" (the prune runs every 10 minutes).

**Worrying, and what to do:**

- Close to or over the budget: the table starts sorted by Bytes, so the biggest tables are at the top; shorten their
  retention or cap (Retention, Record caps), reset a family you do not need (Resets), then give the space back
  (Vacuum). Runbook:
  [Disk full or database large](/admin/help/runbooks#disk-full-or-database-large).
- A table that stays Over its row cap: the prune is not keeping up; look at the jobs on the System page.
- A growth per day that suddenly jumps: usually a flood of events (probes, refusals); see the Protection page.

### Resets

A reset deletes one kind of statistics, for example the traffic numbers of a load test. Statistics resets never
touch settings or rules; the Bans scope deletes only bans, and only the factory reset puts settings and rules back to
their defaults. This section describes the card. [Statistics resets](#statistics-resets), in the Backups and resets
chapter, adds the narrower families, the v1 targets with nothing to reset, what a reset never clears, and how to put
a reset back from its snapshot.

**How a reset goes:**

1. Choose What to reset (the scope) and fill in the fields it needs.
2. Press Preview. Nothing is deleted yet: the preview lists each table with the rows it would lose or change and
   their oldest and newest dates, what stays, and whether a snapshot (a copy of the database) is taken first.
3. Press Run this reset. The dialog asks for a reason and, for the destructive scopes, a phrase to type (table
   below); its Reset button stays off until the phrase matches. Discard the preview drops it instead. The factory
   reset then also asks you to confirm it is you.
4. The reset runs. A long one keeps going in the background and the card says when it is done. A preview is only
   good for the exact choice it showed: change a field and you preview again.

A reason is required when a phrase is asked and for the factory reset; otherwise it is optional. Every reset is
written to the audit log (`data.reset`, then `data.reset.done` or `data.reset.failed`), and a marker
([annotation](/admin/help#term-annotation)) is put on every chart that covers the deleted time, so a drop never looks
like real traffic going away. A reset that failed or was stopped part way (a worker restart, a recycle or a deploy
ended it: "Stopped part way: the worker shut down ... before it finished") still records how it ended, counts the rows
it had already deleted, and keeps its marker as "Data reset (incomplete)". Only one reset or backup runs at a time.

| Scope | What it removes | Phrase to type |
|---|---|---|
| Metric families | The chosen families (next table); optionally only between two dates | `reset <family>` for one, with the family's short name (for example `reset traffic` or `reset cache_stats`), `reset <n> families` for several; none with dates |
| Metric families between two dates | The chosen families between From and To (read in the dashboard's timezone) | None |
| One client (address or place) | Its activity rows, strikes, limiter state and events. Bans stay. | None |
| One endpoint template | Its traffic rows, cached answers, breaker and cooldown state, and 429 rows. Rules stay. | None |
| Cached answers | All, one host's, one cache rule's, those matching a pattern, or expired ones only | `purge cache` for all |
| Bans | All, those a detector made, expired ones, or one detector's. The deny list stays. | `delete all bans` for all |
| Limiter state (strikes and allowances) | Every client starts again with a full allowance, penalties included. Bans and rules stay. | `reset limiters` |
| Upstream cooldowns and breakers | Every upstream [cooldown](/admin/help#term-cooldown) (a pause on an endpoint or egress, usually after a Roblox 429) and circuit [breaker](/admin/help#term-breaker) (which stops calls to an endpoint that keeps failing). Buckets are never refilled. | None |
| Recommendation history | Closed ones only (dismissed, expired, applied or undone; open and snoozed ones stay), or every recommendation, open ones too. Applied settings stay. | `delete recommendations` for all |
| Health check history | Finished runs, optionally between two dates; a run in progress stays | `delete health history` without dates |
| Everything (statistics) | Every statistic in `metrics.db` (recommendations, health history and chart markers included) and every cached answer. Settings, rules, bans, users, sessions, the audit log and the limiter state stay. | `everything` |
| Factory reset | All of the above, and every setting and rule table back to the shipped defaults | `factory reset`, and a fresh second factor |

The factory reset keeps the admin accounts, passkeys, sessions and trusted devices, the credential and the rotator
URL, the admin allowlist, the audit log and settings history, and the pause and throttle-all switches. It refuses to
run unless it can first take a snapshot of `control.db`, and only the dashboard can run it (the operator command line
refuses it).

#### What each family clears

Each family is the data one card shows; the form names that card, says what the family does to its rows and links
there. A narrower family (indented under its parent in the form) clears only part of it.

| Family | What it clears | Shown on |
|---|---|---|
| Traffic | The traffic rows of every minute, hour, day and month. They also hold the latency, cache and upstream numbers of the same requests, which go with them, and the counts of Roblox's answers go too (the Overview's "2xx, 4xx and 5xx from Roblox"). | Traffic > Requests over time |
| Latency | Only the latency and queue wait histograms; request counts stay. | Traffic > Latency |
| Cache statistics | Hits, misses, stale and coalesced answers together; ratios start again. Stored answers stay. | Cache > Cache statistics |
| Upstream | Upstream events, the Roblox 429 log, bucket and attempt history. Call counts inside traffic rows stay. | Upstream > Egress and host health |
| Egress usage | The egress byte accounting. The rotator's billing count (its monthly hard stop, daily cap and budget alerts) is kept apart from these statistics, so the stop still holds after this reset. | Egress > Usage |
| Tarpit | The tarpit counters and history (each worker's counters within a few seconds). | Protection > Tarpit |
| Throttle | Throttle events. Narrower: Throttle rule hits (ladder rung and User-Agent rule hit counts) and Throttled clients (the clients that became throttled). | Protection > Throttle |
| Fingerprints | Header names, values and User-Agents, the blocked counts included. | Security > Fingerprints |
| Client activity | Per-client minute, hour and day rows, and the hourly bot scores. | Clients > Activity |
| Errors | Error signatures and their per-minute counts. | System > Error log |
| Probes | Probe records. | Security > Probes |
| Logins | Sign-in records. | Security > Admin logins |
| Crawls | Crawler records. | Security > Crawler activity |
| Visits | Visits to the public site and the sign-in page. | Overview > Visitors |
| Refusals | Refusal events. Narrower: Endpoint block attempts, Endpoint rule attempts and Request filter attempts (each also leaves the Refusals card). | Protection > Refusal reasons |
| Internal calls | Roxy's own calls to Roblox (probes, lookups). | Upstream > Internal calls |
| Live feed and captures | The live feed's events and the captured request bodies. | Live > Live requests |

Below the form, "Recent data operations" (folded) lists the latest resets, backups and VACUUM runs, each a link to
its audit entry, and "Where v1's Clear data buttons went" maps each of v1's 27 clear buttons to the reset that
replaces it (a link that fills the form in), or says "Nothing to reset" with why (see
[Old v1 targets with nothing to reset](#old-v1-targets-with-nothing-to-reset)).

The Clear buttons of other cards (on the Security page, for example) open this card with their family already
chosen. Some pages offer the same reset in a drawer next to the numbers (Overview > Visitors, Traffic > Requests over
time and Latency, the Live page, one endpoint's page), with the same preview, reason and phrase.

**Undo.** Before deleting from `control.db` or `metrics.db`, a reset copies that database into a snapshot when the
copy fits; the preview says so, or says why no snapshot is taken and the reset cannot be undone. Putting a snapshot
back is a restore on the server (see [Snapshots on the server](#snapshots-on-the-server)). `cache.db` and `hot.db`
are never copied: stored answers and limiter state build up again by themselves.

### Backups

What the card shows:

- Last nightly backup: Succeeded, when, how many files, whether they were encrypted, and either "copied off the
  server" or "kept on this server only". Before the first success it says none is recorded yet.
- Last failure (when there was one): when, the step it failed at and the error.
- Restore test: Passed, Failed, or Not run automatically, with when and the detail.
- Last Back up now: what the server's backup did with the last request (The backup ran; Skipped: a good backup was
  less than 10 minutes old; Skipped: no database was found to back up), when, and who asked.
- Waiting to run: a request the server's backup has not picked up yet, or Nothing waiting.
- Snapshots on this server: how many, their size against the cap (with the percent) and how many days each is kept,
  then up to 50 of them, newest first: File, Kind (Before a reset, Back up now, or Before a migration; see
  [Snapshots on the server](#snapshots-on-the-server)), Size, Taken.
- How Back up now works (folded): the same explanation in a few lines.

**Back up now** (card button or page button) opens a dialog with an optional reason. It asks the server's nightly
backup to run now (it skips a request within 10 minutes of its last good backup) and also copies `control.db` and
`metrics.db` into the snapshots folder here when they fit, removing Back up now's own oldest copies first (reset and
migration snapshots are never removed to make room). Nothing is deleted from the databases, and the proxy keeps
serving. It asks for no phrase and no fresh second factor. While a reset or another backup runs it is refused ("wait
for it to finish"): try again when that one ends. The card then says what was asked, copied, replaced and skipped.
Audit: `data.backup`, then `data.backup.done`, or `data.backup.failed` with the step, the error and what was copied
(also when a worker restart stopped it part way). [Back up now](#back-up-now) in the Backups and resets chapter
explains how the request reaches the server's backup.

**Normal:** the last nightly backup succeeded within the last day, was copied off the server, and the restore test
passed.

**Worrying:** no success for more than a day, a failure, a failed restore test, or "kept on this server only" (a lost
disk would take the backups with it). A failure at the step "rclone push" with an off-box remote set means the set
was not encrypted: only an encrypted set ever leaves the server, so add the age recipient (see
[Backups and resets](#backups-and-resets)). Follow the runbook [Backups](/admin/help/runbooks#backups). Restoring is
done on the server: see [Backups and resets](#backups-and-resets) and the runbook
[Restore from backup](/admin/help/runbooks#restore-from-backup).

### Exports

The subtitle names the time range the files cover. A badge says how client addresses appear: "Client addresses are
replaced by keyed hashes" (the default) or "Client addresses are included in exports". Every download is written to
the audit log first (`export.download`), and a file holds at most 50,000 rows or 16 MiB; a file that was cut comes
with a warning. When two downloads are already being built, a third says to try again in a few seconds.

Datasets, each as CSV (safe to open in a spreadsheet) or JSON: Endpoints, Hosts, Clients by IP address, Clients by
place, Refusal reasons, Internal calls, Roblox 429s, Probes, Admin logins, Crawls, Throttled clients, Errors, Audit
log, Settings, Settings history, Workers. Errors, Settings and Workers have no time range: they export everything
kept. A dataset download asks for no fresh second factor and no phrase.

**Everything at once, for an assistant.** The [LLM export](/admin/help#term-llm-export) is one JSON document with
Roxy's settings, numbers, recommendations and health, written for an AI assistant to read; it replaces v1's
diagnostics download. Text that callers chose is kept apart and marked untrusted, and addresses are hashed. Choose
Covering (the last 24 hours, 7 days or 30 days) and Detail: Summary, or Full (every setting and rule row, evidence
details and tracebacks), which asks for a fresh second factor. Then press Copy for LLM, or Download JSON; Open
schema shows the document's layout.

Settings on this card (in its folded "Settings for this card" list):

| Setting | Key | Default | What it decides |
|---|---|---|---|
| Raw IP addresses in exports | `export_include_ips` | Off | Whether files carry real client addresses. High risk when on, and changing it needs a fresh second factor. |
| Same IP hashes across exports | `export_stable_ip_hash` | Off | When on, one client has the same hash in every export, so it can be followed from file to file. High risk when on. It does nothing while raw addresses are on. |
| Hash client IPs in logs | `log_hash_client_ips` | Off | Whether the server logs write client addresses as keyed hashes. |

**Normal:** the defaults. **Worrying:** downloads you did not make: filter the Audit page by the action
`export.download`. A file that has left Roxy cannot be deleted by it, so keep raw addresses off unless you must.
Export files kept on the server are deleted after Export file retention (14 days).

### Vacuum

SQLite keeps the space of deleted rows for reuse, and the retention job already gives most of it back. A full
VACUUM rewrites a whole database file to return the rest. It never runs by itself.

| Column | What it means |
|---|---|
| Database | `control.db`, `metrics.db`, `cache.db` or `hot.db`. |
| Size | The file, plus its WAL when there is one. |
| Reclaimable | The space a VACUUM would give back. |
| Takes about | An estimate (about 40 MiB a second). |

The last column holds the action:

- Vacuum opens a dialog that asks you to type `vacuum <database>` (for example `vacuum metrics`), with an optional
  reason; it asks for no fresh second factor. Writes to that database wait (or fail after 5 seconds) while it runs,
  so pick a quiet hour. The card then says how much space came back. Audit: `data.vacuum`, then `data.vacuum.done`
  (or `data.vacuum.failed`). There is nothing to undo: no data changes.
- "Not enough free disk": VACUUM needs free space of about twice the file.
- `hot.db` is never vacuumed from the dashboard: it would stall every proxied request.

**When:** after a big reset, or after shortening retention, when Reclaimable is large and the disk is tight. A small
Reclaimable value is normal and needs nothing.

### Retention

How long each kind of record is kept ([retention](/admin/help#term-retention)). The subtitle counts the tables with a
limit and how many wait for the next prune. The leader's retention job deletes what is past its limit every 10
minutes, oldest first, and gives the space back. The audit log is kept at least 400 days, whatever its setting says.

"Every table and its limits" (folded; it opens by itself when a table waits for a prune) lists Table (its plain name,
`database.table`, and the rule in words where no single setting sets it), Rows now, Oldest row, Kept for, Row cap
(each limit with a link to its setting below) and State.

The settings below the table, with their defaults. These defaults keep week over week, month over month and year
over year comparisons with a bounded disk (owner decision D16):

| What | Setting and key | Default |
|---|---|---|
| Traffic per minute | Minute statistics retention, `retention_minute_days` | 14 days (high risk above 30) |
| Traffic per hour | Hour statistics retention, `retention_hour_days` | 400 days |
| Traffic per day and month | Day and month statistics retention, `retention_day_days` | 0: kept forever (1 to 29 is high risk) |
| Client activity | Per-client minute, hour and day retention: `retention_client_minute_days`, `retention_client_hour_days`, `retention_client_day_days` | 3, 90 and 730 days |
| Event log | Event log retention, `retention_events_days`; Event log row cap, `events_max_rows` | 90 days; 2,000,000 rows (high risk above 10,000,000) |
| Roblox 429 log | Roblox 429 log retention, `retention_upstream_429_days`; Roblox 429 log row cap, `upstream_429_max_rows` | 90 days; 200,000 rows (high risk above 10,000,000) |
| Request samples (for previews) | Request sample history, `request_sample_hours`; Request sample row limit, `request_sample_max_rows`; Request sampling rate, `request_sample_pct` | 24 hours; 3,000,000 rows (high risk above 20,000,000); 100 percent |
| Captures | Capture lifetime, `capture_ttl_seconds`; Captures kept, `capture_max_records`; Capture disk cap, `capture_max_bytes` | 900 s (15 min, high risk above an hour; 0 deletes every capture at the next prune); 2,000; 64 MiB (captures still waiting to be written are held within the same two caps) |
| Fingerprints | Fingerprint retention, `retention_fingerprints_days` | 90 days after last seen (and at most "Values tracked per header" values per header name, the most seen kept) |
| Error signatures | Error signature retention, `retention_errors_days` | 180 days after last seen |
| Health check history | Health check history retention, `retention_health_days`; Health check history cap, `health_runs_max` | 180 days; 2,000 runs |
| Closed recommendations | Closed recommendation retention, `retention_recommendations_days` | 365 days |
| Anomalies | Anomaly retention, `retention_anomalies_days` | 90 days |
| Audit log | Audit log retention, `retention_audit_days` | 730 days (never below 400) |
| Settings history | Settings history retention, `retention_settings_history_days` | 0: kept forever (at most 100,000 rows; the latest change of each setting always stays) |
| Expired bans | Expired ban retention, `retention_expired_bans_days` | 30 days |
| Export files | Export file retention, `retention_exports_days` | 14 days (400 files at most) |
| Safety snapshots | Safety snapshot retention, `retention_snapshots_days`; Safety snapshot disk cap, `snapshots_max_bytes` | 7 days; 2 GiB (0 turns snapshots off: high risk) |
| The whole disk | Disk budget, `storage_total_budget_gb` | 12 GB |
| Daily maintenance | Daily maintenance hour, `maintenance_hour` | 4 (the local hour; it waits for quiet traffic) |

Some limits are fixed by the code, not by a setting: expired sessions, trusted devices and kill-switch links are
deleted every hour; idle limiter, strike and pacing rows in `hot.db` are deleted every minute; stored answers in
`cache.db` are bounded by the cache size settings on the Cache page; rule tables keep their rows until you remove
them, up to a fixed number.

These settings are changed as on every card (see
[Changing a setting on a card](#changing-a-setting-on-a-card)); none asks for a fresh second factor. A shorter limit
takes effect at the next prune; a longer one keeps what is still there (deleted rows do not come back).

**Normal:** the defaults, and every table within its limits. **Worrying:** a table that keeps waiting for a prune, or a
limit raised far above its default: each high-risk warning says what the value may cost (for most of them, how much
disk).

### Record caps

The most rows the busiest record tables may hold, so that endless new values from callers (header values,
User-Agents, endpoints) can never grow a table without end. The oldest rows go first. The caps on probe, sign-in,
crawl and throttled client records bound their share of the event log, and the leader enforces them every minute.

The table lists the tables a cap bounds: Table, Rows now, Oldest row, Row cap (with a link to its setting) and State.
The settings below it (they are edited like the retention settings, with no fresh second factor):

| Setting | Key | Default |
|---|---|---|
| Per-client activity tracking | `activity_tracking` | On (off is high risk: after an attack, no record of who caused it) |
| Auto-ignore unique header values | `auto_ignore_high_cardinality` | On (a header seen on at least 500 requests, whose stored values reached their cap with 90 percent or more distinct, stops being recorded) |
| Recent requests per endpoint | `endpoint_recent_requests` | 10 |
| Experiences kept per period | `max_caller_records` | 500 (the rest are summed into one "other" row) |
| IP addresses kept per period | `max_ip_activity_records` | 500 (the same) |
| Endpoints tracked in detail | `max_endpoint_records` | 5,000 |
| Error signatures kept | `max_error_records` | 2,000 |
| Probe records kept | `max_exploit_records` | 5,000 (0 is high risk) |
| Admin login records kept | `max_login_records` | 5,000 (0 is high risk) |
| Crawler records kept | `max_crawl_records` | 5,000 |
| Throttled client records kept | `max_throttle_records` | 5,000 (0 is high risk) |
| Header names tracked | `max_header_name_records` | 1,000 |
| Values tracked per header | `max_header_value_records` | 500 |
| User-Agents tracked | `max_user_agent_records` | 5,000 |

**Normal:** the defaults. Raise a cap only when its table is full of rows you need (the Storage card shows how big
each table is); lower one when a table is large and its rows are of little use.

### On a phone

At 640 pixels and narrower, the small tables (the files, the limits, the snapshots, Vacuum, the preview and the v1
map) become labeled blocks, one per row. The storage table shows What it holds, Bytes and Retention for each table;
tap the first line for the rest in the drawer. The fields of the reset form stack, the facts of the Backups card and
of a table's drawer stack under their labels, and on a touch screen every button is at least 44 pixels tall.

## Audit

The Audit page (`/admin/audit`) is the record of every change: who changed what, when, from where and why, with the
state before and after. Every admin action is written to it, and so is every important automatic one (an automatic
ban, a leader job, a change the recommendation engine applied by itself), as well as changes made with the server's
command line. The only thing this page can change is a setting, through Revert on one of its changes.

**When to use this page**

- After an unexpected sign-in: read what that session did.
- A number changed and you do not know why: a settings change, a rule or a reset at that moment is usually the
  answer. The markers on charts link straight to their entry here.
- To put a setting back the way it was: open the change and press Revert this change.
- To see the whole history of one setting: the History link of any setting opens this page filtered to it.
- To see what Roxy did by itself: filter Who by `system`, `system:*` or `auto_apply:*`.

### How the page is laid out

One card, the Audit log, plus the entry drawer. Unlike most pages, this one opens on All time, so every entry kept is
listed; the Whole log button at the top comes back to it. With a shorter range chosen, a note says that only entries
from that range are listed.

Entries are kept for Audit log retention (`retention_audit_days`, 730 days by default, never below 400) on the Data
page. A secret is never written to the log: for the credential, the rotator address or a password, only a
fingerprint and a masked form are kept.

### Time range on this page

The page opens on All time. Another range lists only the entries of that range, by when the action happened, and
Export follows it; Whole log goes back to everything. The comparison changes nothing on this page.

### Audit log

| Column | What it means |
|---|---|
| When | When the action happened. |
| Who | Who acted (below). |
| Action | What was done, as a dotted name (below). |
| Target | What it was done to (below). |
| Reason | The reason given, if any. |
| Entry | The entry number (`#1234`). |
| From | Hidden by default. The address the admin acted from. |
| Request | Hidden by default. The request id, for finding the matching lines in the server logs. |
| Before, After | Hidden by default. The first 2,000 characters of the state before and after. |

**Who:**

- `admin:<name>`: an admin on the dashboard (you). When you apply a recommendation, the changes are yours too: their
  Reason starts with `recommendation:` and the recommendation's id (`undo recommendation:` for an undo).
- `cli:<login name>`: the command line on the server (`scripts/ctl.py`, see [The operator CLI](#the-operator-cli));
  `cli:create_admin` is `scripts/create_admin.py`, the console tool that resets a password or a second factor.
- `system:<what>`, or just `system`: Roxy itself, for example `system:auto:<detector>` for an automatic ban,
  `system:adaptive` for the adaptive rate controller, a leader job, a lockout after failed sign-ins, or the kill-switch
  link.
- `auto_apply:insights`: a change the recommendation engine applied by itself, within its guardrails.
- `import:v1`: the one-time import of v1's settings, rules and admin account during the upgrade. A settings import
  you make on the Settings page is yours (`admin:<name>`, action `settings.import`).

**Action** names start with their area: for example `setting.update`, `setting.revert` and `settings.import`;
`rule.create`, `rule.update` and `rule.delete`; `auth.login`, `auth.login_failed`, `auth.lockout`,
`auth.sessions_revoked_all` and `auth.kill_switch`; `credential.replace`; `cache.purge`; `data.reset`, `data.backup`
and `data.vacuum`; `export.download`.

**Target** names the thing: `setting:<key>` for a setting, `<rule table>:<id>` for a rule (bans and access list
entries included), `credential`, `admin_user:<id>` for most sign-in and account actions, `table:<dataset>` for a
download, `operation:<id>` for a reset, backup or VACUUM run, `fingerprint_header:<name>` for a fingerprint clear or
removal, and `blocked_header:<name>` for a removal from the Blocked fingerprints.

**Search** looks in the action, the target, who acted, the reason and the request id.

**Filters:**

- Action: Any action, then each family (such as `setting.*` or `auth.*`) with its count, then each action seen.
- Who: Anyone, then each kind (such as `admin:*`), then each actor seen with its count.
- Target: Any target, Settings, Cache rules, Endpoint blocks, Endpoint rules, User-Agent rules, Request filters,
  Routing rules, Upstream limits, Endpoint policy: endpoint verdicts, Endpoint policy: category switches,
  Credential allowlist (before the endpoint policy), Access lists, Bans, The credential (value, replace, delete),
  Credential status changes, Credential account checks, Everything about the credential, allowlist included,
  Downloads, Data resets, Backups and VACUUM runs.

A filter value ending in `*` matches everything that starts with it: Everything about the credential is
`credential*`, and Data resets, Backups and VACUUM runs find the `operation:reset_...`, `operation:backup_...` and
`operation:vacuum_...` targets these operations write.

The log starts with the newest entry first; Entry, When, Who, Action and Target sort. Its search, filters, sort and
page are kept in the address bar, so a filtered view can be bookmarked. Export gives the filtered log as CSV or JSON;
client addresses in it are hashed unless Raw IP addresses in exports is on, and the download is itself audited.

Links that open this page filtered: `/admin/audit?entry=<number>` opens one entry, `/admin/audit?target=setting:<key>`
lists one setting's history, and Account changes on the Security page opens `/admin/audit?action=auth.*`.

**Normal:** your own `admin:` changes with their reasons, your sign-ins, and routine `system:` entries.

**Worrying:** a change by an admin name or an address you do not know, a change at a time you were not signed in, a
burst of `auth.lockout`, or a `credential.replace` you did not make. Follow
[Unexpected admin login](/admin/help/runbooks#unexpected-admin-login), and use this page to list and undo what was
changed.

### Audit entry

Open a row (or a link with `?entry=`) to see one entry in the drawer:

- The facts: When, Who, From, What (the action), Target, Reason ("No reason was given." when empty) and Request.
- "A secret is involved", when the target holds a secret: the diff can show only its fingerprint and masked form.
- What changed: a table of Field, Before and After, each field marked added, removed or changed (the first 500
  fields). An action with no before and after (a download, a sign-in, a run) says so.
- The stored before and after, line by line (folded): the two documents side by side as a line diff. Very long
  documents are cut at 20,000 characters here; the admin API (`GET /admin/api/v1/audit/{audit_id}`) has them whole.
- Open: a link to the card that manages the target, for example Protection > Bans, the setting on the Settings
  page, Data > Resets, Backups or VACUUM for a data operation, or Credential > Status for the credential's status
  and account entries.
- Undo this change.

**Undo this change.** A settings change (`setting.update`, `setting.reset`, `setting.revert` or `settings.import`)
offers Revert this change. It puts the setting back to the value it had right before that change, on every worker
within a second, and writes a new entry (`setting.revert`), so a revert can itself be reverted. The reason box is
saved in the log; it is required when the old value is high risk, and then the form also asks you to tick "I
understand: the old value is high risk". A setting that needs a fresh second factor (the Admin access settings, the
credential settings, Raw IP addresses in exports) asks for it first. A revert that would arm the spam detectors is
refused: arm them on the Protection page, which first shows who would have been banned. When the setting was changed
again after this entry, the form says so first, with the value now: reverting this entry also undoes those later
changes, so to undo only a later one, revert that one instead.

When no revert is offered, the drawer says why:

- "Sensitive values are not kept in history; enter the value again.": a secret setting.
- "The settings history entry of this change was pruned.": retention has deleted the history row the revert needs.
- "This setting no longer exists."
- "Rules are changed back on the card that manages them, with their own checks.": use the Open link.
- "This action has nothing to revert.": sign-ins, downloads and runs. A reset is put back from its snapshot (see
  [Backups and resets](#backups-and-resets)).

### Quick answers

- Who changed a setting, and when: press History on that setting anywhere on the dashboard, or choose Target
  Settings here and search for its key.
- Everything one session did: choose Who `admin:<name>`, narrow the time range to when it was signed in, and show the
  From column to see the address of each change (the log has no session column). A request id from the server logs
  finds the one entry that request wrote.
- Every sign-in and account change: Action `auth.*` (the Security page's Account changes button).
- Every reset, backup and VACUUM: Action `data.*`, or the Target choices Data resets, Backups and VACUUM runs (the
  Data page's Recent data operations shows the latest).
- Every download and export: Action `export.download`.
- Changes made by applying recommendations: search for `recommendation:`.
- What Roxy did by itself: Who `system`, `system:*` or `auto_apply:*`.

### On a phone

At 640 pixels and narrower, each row of the log becomes a small card with When, Action and Target; tap the first line
to open the entry. Below 480 pixels the entry's facts stack under their labels, and the What changed table keeps the
field name to 40 percent of the width.

## System

The System page (`/admin/system`, in the Operate group of the sidebar) shows the machinery under Roxy: the
[worker](/admin/help#term-worker) processes and their memory, which worker is the
[leader](/admin/help#term-leader) and whether its scheduled jobs ran, whether statistics are being written, how big
the databases are, which errors happened, what version runs, and what the server started with.

A few words first:

- **Worker**: one of the processes that answer requests. This server runs 2 (`ROXY_WORKERS`). Each one is replaced
  on purpose after 20,000 requests, so their ages differ.
- **Color**: Roxy is installed twice on the server, as blue and green. One serves; a deploy starts the other with the
  new release, switches traffic to it, then stops the old one. During a deploy both colors show up for a short time.
- **Leader**: one worker at a time is the leader and runs the scheduled jobs (pruning old data, looking for
  recommendations, sampling the disk and more). If it stops, another takes over.
- **This worker** against **fleet**: a number marked "this worker" comes from the worker that answered this page
  (each keeps its own queue and writers). Everything else is read from shared state and covers every worker, the
  [fleet](/admin/help#term-fleet).

The Error log button at the top jumps to the error log. Apart from the settings on two cards, the only action here
that changes data is Reset request counts (on the Workers card); the forced flush only writes what the workers
already hold.

**When to use this page**

- A failed health check linked here: H-WORKERS and H-LOOP-LAG (the workers table), H-LEADER (the Jobs card),
  H-ERR-RATE (the error log), or H-CACHE-RW, H-WAL and H-DISK (the database files).
- An alert "Roxy Error: ..." arrived, or a page looks wrong and you suspect an internal error.
- Numbers on other pages look too low or late (metrics drops, a stalled flush).
- Right after a deploy: both colors, the versions, the database schemas.
- You worry about memory on this 909 MB server.
- You want to know whether the email and webhook alert channels are set up.

The cards, in the order the page shows them: Workers; Leader and Forced flush side by side; Error log; then Jobs,
Metrics pipeline and Persistence; Versions and Environment side by side; and Alerts. The heavier cards load as they
scroll into view.

### Time range on this page

The System page shows the state now, so the top bar's time range and comparison change nothing here: the error log
covers every kept error, the disk chart the last 30 days, and the drops the last hour.

### The Workers card

**The tiles**

| Tile | What it means | Normal | Worrying |
|---|---|---|---|
| Service uptime | How long this color's gunicorn master (the process that starts and replaces workers) has run. This, not a worker's age, is the uptime of the service. | Since your last deploy or reboot. | Much shorter than expected: the service restarted on its own. See [Service down](/admin/help/runbooks#service-down). |
| Workers | Workers of this color with a heartbeat in the last 20 seconds, against `ROXY_WORKERS`. "All reporting", "Stale rows" or "Fewer than expected". | "2 of 2", All reporting. | Fewer than expected, or stale rows, for more than a minute. |
| Fleet memory | The resident memory of every fresh worker added up. | A worker starts near 150 MiB; after a while the leader (it runs the jobs) sits around 200 to 240 MiB and the other worker around 160 to 195 MiB. | One worker climbing while the other stays flat, or the total near 420 MiB or above (see below). |
| Host uptime | How long the server itself has been up since its last boot. | Days or weeks. | A reboot you did not do. |
| Since the last deploy | Time since a deploy last switched colors. "n/a" on a server never deployed by the pipeline. | Since your last deploy. | A switch you did not make. |
| Tarpit connections | Connections the [tarpit](/admin/help#term-tarpit) holds now, against its hold cap in force (the smaller of "Most holds at once", 50 by default, and its share of the connection budget); the tile's help also gives v1's figure, the share of the whole connection budget. | Well under the cap. | "Near the cap" (80% or more), or "Full: refusals answered at once": new refusals are no longer held. See [Protection](#protection). |

About memory: each color may use up to 500 MiB (systemd's `MemoryMax`); above 420 MiB (`MemoryHigh`) the kernel
starts slowing it down, and past 500 MiB it kills one process of that color (a worker), which gunicorn replaces
while the other worker keeps serving (the unit's `OOMPolicy=continue`). A healthy
color settles at about 365 to 405 MiB in all (see
[Memory per color](/admin/help/performance#memory-per-color-and-the-systemd-decision) in the Performance document).
The sum on the tile counts memory the workers share more than once, so it can read a little higher than what systemd
counts. A worker that keeps growing while the other stays flat is the one to look at; settings that grow every
worker's memory include the metrics queue (`metrics_queue_max`, on this page), the Live view history
(`live_tail_buffer`) and the in-memory cache (`cache_memory_bytes`, on Cache).

**Warnings and the colors.** "Check the workers" boxes appear when a color runs fewer workers than it should (gunicorn
restarts a stopped worker, so a lasting shortfall needs a look at the journal) or has stale rows (a stopped or frozen
worker; its row goes away once the heartbeat table is pruned). During a deploy a notice says both colors are serving.
Below the tiles, each color has a line: Blue or Green, "serving you" for the color that answered, "not running" for
the stopped one, then "2 of 2 workers fresh", the master's process id and how long the service has been up. When
less than 700 MB of memory is available before a deploy (which a warm color always causes on this server), the
deploy starts the new color with one worker and adds the second once the old color has stopped, so "1 of 2" during
a deploy is normal, not a warning sign.

**The workers table** (its address is `/admin/system#workers`, where health checks link)

| Column | What it shows |
|---|---|
| PID | The worker's process id; "serving you" under the one that answered this page. |
| Color | blue, green (or dev on a laptop). |
| Leader | "Leader" for the worker that runs the scheduled jobs. |
| Fresh | "Fresh" with a heartbeat in the last 20 seconds; "Stale" for a stopped or frozen worker. |
| Uptime | How long the worker has run. |
| Memory | Its resident memory. |
| All requests | Everything the worker served since its counters were last reset, this dashboard included (what gunicorn counts toward replacing it). |
| Proxy requests | Only requests aimed at the proxy, served or refused. If All requests climbs and Proxy requests does not, only you are talking to the server: the proxy is idle, not broken. |
| Loop lag p99 | How late the worker's main loop woke up, at the [99th percentile](/admin/help#term-percentile) over the last minute. When it climbs, every request on that worker waits. |
| CPU | The share of a processor the worker used over its last full minute, with the peak under it. |
| Connections | Open connections. |
| Last heartbeat | When the worker last reported. |

Hidden by default (the Columns menu shows them): In flight (calls to Roblox in progress), Recycle after (the request
count at which the worker is replaced), Counters reset (when Reset request counts last zeroed it), Version and Serving
you. Press a row to see every column of that worker, each with its explanation. The table has a search box ("Pid,
color or version") and Export.

**What to do.**

- Fewer than expected or stale for more than a minute, or a health check H-WORKERS failure: follow
  [Workers or leader missing](/admin/help/runbooks#workers-or-leader-missing).
- Loop lag of 50 ms or more: the health check H-LOOP-LAG, which reads the worst worker over the last 5 minutes,
  warns from 50 ms and fails from 200 ms. Follow
  [Slow event loop](/admin/help/runbooks#slow-event-loop). A recent deploy is the usual suspect.

**Reset request counts** (the button on the card) opens a confirmation: it zeroes All requests and Proxy requests on
every worker. Each worker takes the reset within 5 seconds and keeps the time as Counters reset; uptime, memory and the
statistics on the other pages are not touched. The reason is optional and goes in the audit log with your name. It
asks for no second factor, and there is nothing to undo: the counters simply start again from zero. Use it before a
test when you want to count requests from a clean start.

### The Leader card

| Line | What it means |
|---|---|
| Leader | The worker that holds the leader [lease](/admin/help#term-lease) (a claim it must keep renewing), with "this worker" when it is the one that answered. "No worker holds the lease right now" while nobody leads. |
| Epoch | A number that goes up each time leadership moves (the [epoch](/admin/help#term-epoch)). Every write a job makes carries it, so a worker that lost the lead without noticing can never overwrite the new leader's work. |
| Lease | "Held" and when it runs out unless renewed, or "Not held": another worker takes over within 15 seconds. |
| This worker | "Leads the fleet" or "Follows the leader", with the epoch it knows. |
| Leading since | When this worker became the leader (only when it leads). |
| Leadership changes | How many times this worker saw the lead move. |
| Last error | The last problem this worker had with the lease, if any. |

Normal: Held, one leader, an epoch that moves only at deploys, restarts or when the leading worker is replaced.
Worrying: no leader for more than about 15 seconds, the changes count climbing quickly, or a Last error that keeps
coming back (the lease lives in hot.db, so a locked or full disk shows here). Follow
[Workers or leader missing](/admin/help/runbooks#workers-or-leader-missing); from the server, `roxyctl leader` shows
the same and every worker's heartbeat.

### The Forced flush card

Workers keep their counters in memory and write them to the statistics database every few seconds (the Metrics flush
interval, `metrics_flush_interval_ms`, 2,000 ms by default; the card shows the value in force). Every chart and number
on the dashboard lags by up to that much.

**Flush every worker now** writes them at once: this worker immediately, every other worker within about 2 seconds.
The Metrics pipeline and Workers cards then refresh. The reason is optional and goes in the audit log. It changes no
setting, deletes nothing and needs no second factor, so there is nothing to undo. Use it when you need a number to
include the last few seconds, for example right after a test. From the server: `roxyctl flush-metrics`.

### The Error log card

Errors inside Roxy, grouped by signature, with how often each happened. In this release a row is added when a request
fails inside Roxy's own code with an error nothing handled (the caller gets a 500); the errors v1 had logged were
brought over when you moved. The subtitle counts the distinct errors (or the matching ones while you search). This is
the page's main table, so its search, filter, sorting and page stay in the address bar and you can share the link.

| Column | What it shows |
|---|---|
| Signature | The error's name: its type and its message, for example `KeyError: ...` (up to 200 characters, secrets removed). The same failure gets the same signature, so it adds to one row. |
| Count | How often it happened since it was first seen. |
| Source | Where it was recorded: Roxy for an error Roxy raised while answering a request (every new row); rows brought over from v1 keep v1's source (Roxy, Roblox, Relay, Internal or Cache). |
| Last seen | When it last happened. |
| Last detail | What the last occurrence was doing: the request's method and path, the client address and the request id, with secrets removed. |

Hidden by default: First seen and Where (the module and line that raised it). Above the table: "Search errors", a
Source filter, Columns and Export.

**One error in the drawer.** Press a row for its count, first and last time, source, where it was raised ("Raised
at": the module and line inside Roxy), the last detail, the traceback (the chain of code lines that led to it;
secrets were removed before it was stored and again when it was read) and a small chart of how many times it happened
in each of the last 24 hours ("Show the hours as a list" gives the numbers). Rows brought over from v1 have no
traceback, and the page says none was kept.

**Normal and worrying.** An empty log ("No errors recorded"), or old signatures whose Last seen is days ago, is
normal. A new signature, or a count that keeps growing, is not, especially right after a deploy. The alert "Roxy
Error: ..." is sent when an error happens, at most once per Error alert cooldown (`error_email_cooldown`) for the same
signature. Follow [Unhandled errors](/admin/help/runbooks#unhandled-errors): if it started with a deploy, roll back
first; otherwise rule out the disk and the databases, then report the signature, its place and a request id. The
health check H-ERR-RATE (the share of caller requests answered with a 5xx) also links here; its own runbook is
[Caller errors](/admin/help/runbooks#caller-errors).

**How long errors are kept.** The card says it with the values in force: a signature is deleted 180 days after it
last happened (Error signature retention, `retention_errors_days`), and at most 2,000 signatures are kept (Error
signatures kept, `max_error_records`, the least recent go first); both are on the Data page. A data reset of the
Errors family clears the log at once (see [Data](#data)).

### The Jobs card

Every scheduled job, with its last run. The subtitle counts them and says when this worker leads.

| Column | What it shows |
|---|---|
| Job | The job's name and what it does. |
| Runs on | "The leader" (most jobs) or "Every worker". |
| Every | How often it runs. |
| Last run | When it last started or finished. |
| Result | Running, Not run yet, Worked or Failed (with the error under it). |
| Took | How long the last run took. |
| Runs, Failures | How many runs and failures since the worker started ("n/a" on a row from the leader's status). |
| Source | Where the row comes from: "This worker" when this worker ran it, "Leader's status" when another worker leads and published its status (every 30 seconds), or "Unknown". |

When another worker leads, its jobs' failure details stay with it: the row shows Failed without the error and without
Took, and the journal has the details (look for `job_failed`). "Checkpoint durations" below
the table shows how long the last WAL checkpoint took per database (the [WAL](/admin/help#term-wal) is the file
where a database collects recent writes until they are folded back in, every few minutes on the leader) and whether
the daily maintenance ran (once a day, at the maintenance hour while traffic is quiet). Only the leader knows these
numbers.

Normal: Worked everywhere, each last run within its "Every", and few or no failures. Worrying: a job that keeps
failing, a last run far older than its interval, or most rows "Unknown". The error under a failed job names the cause;
then follow [Workers or leader missing](/admin/help/runbooks#workers-or-leader-missing). From the server:
`roxyctl jobs`.

### The Metrics pipeline card

How statistics get from the workers to the charts. Each worker collects counters and events in memory, queues them,
and writes them to the statistics database (metrics.db) at every flush. When a queue is full or a write fails, items
are dropped, and some numbers on other pages are then lower than what really happened. If anything was dropped in the
last hour, a "Some numbers are missing" box says how much. Captures waiting in the queue are also held within the
capture caps (Captures kept and Capture disk cap): the oldest leave first, counted as capped rather than dropped,
since they would have been pruned when written anyway.

**This worker**

| Line | What it means |
|---|---|
| Queued | Items waiting for the next write, out of the queue's size. |
| Dropped since start | Items this worker dropped since it started. |
| Flushes | Writes done, and how many failed. |
| Last flush | When the last write happened and how long it took. |
| Recording errors | Times recording a request failed (the request itself went on). |
| History items dropped | Samples for the recommendations' detailed history that were dropped because a bounded list was full. |
| Captures dropped | Redacted request copies (Live > Capture) that were dropped, and errors while making them. |
| Endpoint templates | How many endpoint templates the worker knows, and how many new ones it refused (its list is bounded). |
| Live rows kept | Recent requests kept in memory for the Live page. |
| Forced flushes here | Forced flushes this worker has done. |

**Every worker, last hour**: items, history items and captures dropped across the fleet, the minutes that had drops,
and "Rows per minute": how many distinct counter rows a minute the workers write. Above about 1,500 the disk grows
fast.

**Database writers of this worker**: one row per database (control, hot, metrics, cache) with Writes, Reads, Write
errors, Busy (writes that found the database locked for too long), Last write, Slowest write, and Waiting (operations
queued for the writer right now).

Normal: no drops, no failed flushes, a last flush a few seconds ago, zero write errors, Busy at or near zero, Waiting
near zero. Worrying:

- **Drops.** Usually a burst bigger than the queue, or a slow disk. Check the Persistence card for write errors and
  disk space first. The SYS-METRICS-DROP recommendation suggests a change when it sees a pattern.
- **Write errors or a growing Waiting.** The disk or a database is in trouble: see
  [Disk full or database large](/admin/help/runbooks#disk-full-or-database-large).
- **Rows per minute above 1,500.** Many distinct combinations of endpoint, status, outcome and the other counted
  details each minute. The SYS-DISK recommendation fires when the 7-day average passes 1,500; Data > Storage
  projects the growth and the retention settings bound it.

**Settings for this card** (open by default):

| Setting | Key | Default | Notes |
|---|---|---|---|
| Live view history per worker | `live_tail_buffer` | 500 requests | Recent requests each worker keeps for the Live page; more costs memory per worker. Also on Live. |
| Metrics flush interval | `metrics_flush_interval_ms` | 2,000 ms | How often each worker writes. Lower is fresher but costs more writes; below about 500 ms it rarely helps. |
| Metrics queue size per worker | `metrics_queue_max` | 50,000 items | Medium risk; above 200,000 is high risk, because a full queue that large can push a worker over its memory limit. Raise it a little at a time if drops come from bursts. |

### The Persistence card

The database files and whether they are being written without errors. The subtitle gives their total size, and a
status line says either "OK: every database writer is writing without errors" or "Problem: writing failed recently
for ..." with the database names.

**Database files** (its address is `/admin/system#storage`, where the storage health checks link): one row per file
with Size, WAL (recent writes not yet folded back in), Shared memory, Writes and Write errors. The four databases are
control.db (settings and their history, the audit log, rules, bans, lists, admin accounts), hot.db (the shared limits,
leases and other small, fast-changing state), metrics.db (statistics, recommendations, health runs) and cache.db
(stored answers; disposable).

**Disk over the last 30 days**: a chart of Roxy's storage and of the free disk, one sample an hour taken by the
leader (the first an hour after it starts leading). Until then the card says no samples exist yet.

**Largest tables**: the 15 biggest tables of the newest size sample (the leader measures them every 6 hours), with a
link to Data > Storage, which lists every table with its rows, its retention and a projection.

Normal: OK, a WAL that stays small (it shrinks after each checkpoint), and a free disk line that is roughly flat.
Worrying: Problem, write errors, a WAL that keeps growing, or the free disk line heading toward zero. Follow
[Disk full or database large](/admin/help/runbooks#disk-full-or-database-large), or
[Database corrupt](/admin/help/runbooks#database-corrupt) when errors mention a malformed database.

### The Versions card

What is running: the release and the deployed commit, Roxy's own version, Python, SQLite, the settings catalog (its
version, how many settings, and the configuration version, which goes up with every change to settings, rules, bans
or lists), the endpoint template version, and which releases the fresh workers report (with how many workers each).
"Database schemas" lists each database's schema version with "up to date" or "needs N"; "Libraries" lists the main
libraries.

Normal: one release reported by every worker, and every schema up to date. During a deploy two releases show for a
short time, with the warning "Workers run different releases". If that lasts, follow
[Version mismatch](/admin/help/runbooks#version-mismatch) (the health check H-VERSION, which compares the running
commit with the deployed one, leads there too). A schema that "needs" a newer version means the deploy's migration
step (step 3) did not finish for that database; a worker refuses to start below the schema its release needs. See
[Deploy failed](/admin/help/runbooks#deploy-failed).

### The Environment card

The startup facts the answering worker read from the environment files (see "Settings only the server can set" in
the [Settings](#settings) chapter): Environment, Color, Workers, Recycle after, Listens on, Trusted proxies, nginx,
HSTS, Log level, Site origin, State directory, Internal socket, Rotator address check (shown without any login),
Off-server backups, Migrations at start and Release commit. "Database files" opens the full path of each database.

**Credentials** lists seven systemd credentials by name with "present" or "missing" (an empty file counts as
missing), never a value: `rotator_url`, `smtp_password`, `alert_emails`, `alert_webhook_url`,
`credential_encryption_key`, `totp_encryption_key` and `ip_hash_key`. Below it, the Roblox credential gets its own
line: whether the bootstrap file is present, whether a value set from the dashboard exists, and whether a credential
is in use, with a link to the Credential page.

Normal on the server: Environment production, Workers 2, Recycle after 20,000 requests, trusted proxies 1 hop from
loopback, HSTS not sent (nginx sends it), Migrations at start off, and "present" for every credential you use.
Worrying: development on the server; a required credential missing (`smtp_password`, `alert_emails`,
`credential_encryption_key`, `totp_encryption_key` and `ip_hash_key` are required, and so is the Roblox credential's
bootstrap file; `rotator_url` and `alert_webhook_url` are optional, empty when you do not use them); or the Roblox
credential not in use: see the [Credential](#credential) chapter and the
[Credential rejected](/admin/help/runbooks#credential-rejected) runbook.

### The Alerts card

Whether each alert channel has its credentials on the server:

- **Email** needs the `smtp_password` and `alert_emails` credentials.
- **Webhook** needs the `alert_webhook_url` credential.

Each shows "Configured", "Configured, switched off" (the webhook file has a value but Send alerts to webhook is off)
or "Not configured". A channel counts as configured when its credential files are present; the card does not test
them. The health check H-ALERTS does, without sending anything (it logs in to the mail server and looks the webhook
up): it warns when one channel is down or cannot be tested and fails when all are down. The card's settings are the
same six as Settings > Alerts (see the Alerts card in the [Settings](#settings) chapter); change them in either
place.

Normal: Email configured. Worrying: Email not configured, which means no alert reaches you at all. Channels are
credentials, so a fix happens on the server: follow [Alert channels down](/admin/help/runbooks#alert-channels-down).

### On a phone

The workers table shows PID, Color, Uptime and Memory, and the error log Signature, Count and Last seen;
press a row for the rest. The jobs and database tables turn each row into a block with its column names, the cards
that sit side by side on a wide screen (Leader and Forced flush, Versions and Environment) stack, and on very narrow
screens each label sits above its value.

## Help

The Help page (`/admin/help`, at the bottom of the sidebar) gathers everything that explains Roxy: this guide, the
runbooks and other documents, the glossary, the keyboard shortcuts, and one paragraph on what every page does. It
reads no statistics and changes nothing, and nothing on it depends on the time range or the comparison.

**When to use this page**

- An alert email's "What to do" link or a failed health check's fix link brought you here: they open the runbook
  that matches.
- A word on the dashboard is unclear. Terms with a dotted underline link to their glossary entry here.
- You want to read this guide or a runbook from the start.
- You forgot a keyboard shortcut.
- You are looking for the page that does something.

At the top, the Runbooks button opens the runbooks, and Shortcut overlay opens the same list the `?` key shows. A
short row of links ("Parts of the Help page" to a screen reader) jumps to the four cards: Admin guide, Glossary,
Keyboard shortcuts and What each page does.

### The Admin guide card

- **Read the admin guide** opens this guide at `/admin/help/guide`. "Its chapters" (closed until you open it) lists
  them, each a link to its own page.
- **Where each topic is on the dashboard** lists twelve topics (first-time setup, the daily routine, one chapter per
  page, recommendations, rate limiting from Roblox, protection, egress, settings, data, security, incident runbooks
  and the glossary), each with links to the pages, cards and runbooks that cover it.
- **Documents**: Runbooks, Architecture, Security, Learning path and Performance, each opening on its own page
  (`/admin/help/runbooks`, `/admin/help/architecture`, `/admin/help/security`, `/admin/help/learning-path` and
  `/admin/help/performance`); the public User guide (`/docs`), written for the developers who call Roxy from their
  games; and the Settings page. A document missing from a release is listed as "Not in this release".
- **Incident runbooks**: one entry per link name of the runbooks' link index, with the alerts or health checks that
  use it (a runbook reached by two names, such as Backups, appears twice). An alert email links to
  `/admin/help#runbook-<name>`, and the page goes straight on to that runbook. If your browser blocks the page's
  script, the link stops at the entry instead; press the entry's link.

If the guide's file is missing from a release, the card says so, and the topic list still points to the right pages.

**When an alert arrives.** Open its "What to do" link. Every runbook has the same parts: Symptoms (what you notice),
Confirm (where to look to be sure, on the dashboard and on the server), Likely causes, Fix (safest steps first),
Verify (how to tell it worked), Roll back (how to undo the fix) and Prevent. Start with Confirm: it tells you whether
the problem is still there before you change anything.

**Reading a document.** Each document has its contents list (open on a wide screen; closed on a phone or any screen
narrower than 1,100 pixels, so the text comes first), and every heading has a "#" link you can copy to point someone
at that section. Commands are shown in boxes that scroll sideways; they are meant for the server's console, and
nothing on the page runs them. "More documents" at the end lists the others and the glossary, and the Help button at
the top comes back here. Health checks also link to `/admin/help/operations#<name>`, which opens the runbooks at the
matching section.

**Reading this guide.** The guide is one long document, so the Help page shows it one chapter at a time: its first
page, `/admin/help/guide`, has the introduction, the contents (every chapter, each a link) and the first chapter,
Getting started; every other chapter has its own page, `/admin/help/guide/<chapter>` (for example
`/admin/help/guide/protection`). The contents list beside the text links every chapter and lists the sections of the
one you are reading, and "Keep reading" at the end goes to the previous and the next chapter. A link in the text to
another chapter opens that chapter's page at the right section. The guide is also one Markdown file in the repository
(`docs/ADMIN_GUIDE.md`), which reads well on GitHub.

### The Glossary card

Every term the dashboard uses, with a plain definition of one or two sentences. It comes from the same file as every
tooltip on the dashboard, so the two never disagree. Type in "Filter the glossary" to keep only the terms whose name
or definition contains your text; the count under the box says how many are left. Each term has its own address,
`/admin/help#term-<id>` (for example `/admin/help#term-cooldown`), which is where every dotted term on the dashboard
links.

### The Keyboard shortcuts card

| Keys | What they do |
|---|---|
| Ctrl K or / | Open the command palette: search pages and actions, settings, open recommendations and endpoints. |
| ? | Show the shortcut list. |
| Esc | Close a dialog, a menu or the palette. |
| T | Cycle the time range. |
| C | Turn the comparison on or off. |
| G then O, R, L, U, C, P or S | Go to Overview, Recommendations, Live, Upstream, Cache, Protection or Settings. |
| Up and Down | Move between rows of a table. |
| Enter | Open the row's details. |
| P | Pause or resume the live tail on the Live page. |

Shortcuts never fire while you type in a field. Ctrl K always works because it needs a modifier key. The single-key
shortcuts can fire by accident (for example with speech input), so "Single-key shortcuts" turns them off; the choice
is remembered in this browser. "Show the shortcut overlay" opens the same list as the `?` key.

### The What each page does card

Every page with its name (a link to it) and its one-sentence purpose. "How to read the ... page, and its cards" opens
the same "How to read this page" paragraphs the page shows at its top, and the list of its cards, each a link
straight to that card. The texts come from the same source as the pages themselves, so this list is always current.
Use it when you know what you want to do but not where it lives.

### On a phone

A document's contents list starts closed, each glossary term sits above its definition, and the shortcut groups, the
documents and the runbook index each take one column. The "Keep reading" links stack, previous above next.

## Alerts

Roxy tells you about trouble by email and, if you switch it on, a webhook. This chapter lists every alert, when it
fires, how often it can repeat and which runbook it points to. Setting up the channels is
[Step 9](#step-9-choose-where-alerts-go) of Getting started.

### Where alerts go

- **Email.** Gmail over SSL (port 465), to the `to:` address of the `alert_emails` credential, from its `from:`
  address, with the `smtp_password` app password. Without those files there is no email.
- **Webhook.** When `alert_webhook_enabled` is on and the `alert_webhook_url` credential holds an address, the same
  alert is also posted there as JSON. The message carries `content` (what Discord shows) and `text` (what Slack-style
  receivers show) plus every field. Only https addresses are accepted (plain http only to the server itself, for a
  local relay), any answer other than 2xx counts as a failure, and Roxy never follows a redirect.
- Two alerts are email only: the new admin login email and the daily digest.
- Two alerts come from outside Roxy. `Roxy DOWN` and `deploy failed` are sent by a small separate program
  (`alert_on_failure.py`, which systemd runs with the system Python) so they still arrive when a release is broken.
  It reads the same three credential files but none of the dashboard's settings: it posts to the webhook whenever
  that file holds an address, and it ignores `alert_min_severity` and the hourly cap. Instead it sends at most one
  message per failed unit (or per failed deploy commit) every 10 minutes and counts the ones it held back.

The login code email (subject `Admin 2FA`) is not an alert: no filter, cooldown or cap applies to it.

The Alerts card of the System page shows each channel as Configured, Configured, switched off, or Not configured. The
Alerts card of the Settings page holds the settings described below (the System page shows the same settings).

### Every alert Roxy sends

Severity is info, warn or critical. "Repeats at most" is how long Roxy waits before it sends the same alert again;
that gap is shared by every worker process, so you get one message, not one per process. The last column is the
runbook the alert belongs to.

| Subject | Severity | Sent when | Repeats at most | Runbook |
|---|---|---|---|---|
| `Roxy Error: <signature>` | warn | Roxy hit an unexpected error while serving a request | once per signature every `error_email_cooldown` (300 s) | [Unhandled errors](/admin/help/runbooks#unhandled-errors) |
| `Roxy: all upstream methods unavailable` | critical | every way to reach Roblox is switched off, so callers cannot be served | every `error_email_cooldown` (300 s) | [All upstream paths unavailable](/admin/help/runbooks#all-upstream-paths-unavailable) |
| `Token Expired` | critical | Roblox rejected the credential (a 401 or 403, confirmed by a check), or a check found it now signs in as a different Roblox account | every `email_cooldown` (600 s) | [Credential rejected](/admin/help/runbooks#credential-rejected) |
| `Roxy: credential cooling down` | warn | Roblox rate-limited the credential and it must rest 10 minutes or more | every `email_cooldown` (600 s) | [Credential cooling down](/admin/help/runbooks#credential-cooling-down) |
| `Roxy: Roblox sent a new credential cookie` | critical | Roblox answered with a new login cookie; Roxy did not store it | once an hour | [Credential rotated by Roblox](/admin/help/runbooks#credential-rotated-by-roblox) |
| `Roxy Admin Login` | info | someone signed in to the dashboard; it carries the link that ends every session | every sign-in, always sent | [Unexpected admin login](/admin/help/runbooks#unexpected-admin-login) |
| `Roxy SECURITY: credential leak blocked` | critical | the leak guard stopped a request that carried the credential and switched that egress off | every time, always sent, never held back | [Leak guard](/admin/help/runbooks#leak-guard) |
| `Roxy: Roblox is rate-limiting us (<rate>%)` | warn | more than 2% of upstream calls got a Roblox 429 in the last 10 complete minutes, and at least 5 of them | once every 30 minutes | [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us) |
| `Roxy: caller errors at <rate>%` | warn | more than 2% of caller requests got a 5xx answer in the last 10 complete minutes, and at least 5 of them (a pause does not count) | once every 30 minutes | [Caller errors](/admin/help/runbooks#caller-errors) |
| `Roxy: rotator at <pct>% of monthly quota` | warn; critical from 95% | rotator use this billing cycle passed one of `rotator_budget_alert_pcts` (needs the quota set) | once per threshold per billing cycle | [Rotator down or quota exhausted](/admin/help/runbooks#rotator-down-or-quota-exhausted) |
| `Roxy: storage at <pct>% of budget` | warn; critical from 100% | Roxy's data reached 90% of `storage_total_budget_gb` (12 GB by default; checked every 30 minutes) | once every 6 hours | [Disk full or database large](/admin/help/runbooks#disk-full-or-database-large) |
| `Roxy: database integrity check failed` | critical | the daily database check during maintenance found damage | once an hour | [Database corrupt](/admin/help/runbooks#database-corrupt) |
| `Roxy: backup failed` | warn | the newest backup record is a failure (checked every 30 minutes) | once every 6 hours, together with the next row | [Backups](/admin/help/runbooks#backups) |
| `Roxy: no backup for <hours> h` | warn | no backup has succeeded for more than 26 hours | once every 6 hours | [Backups](/admin/help/runbooks#backups) |
| `Roxy: health check found <n> new failures` | warn | a scheduled health run found failures the scheduled run before it did not have | once a day for the same failures | [Health check found new failures](/admin/help/runbooks#health-check-found-new-failures) |
| `Roxy: auto-applied change rolled back` | warn | a change Roxy applied by itself made things worse, so Roxy undid it | once a day per recommendation | [Auto-applied change rolled back](/admin/help/runbooks#auto-applied-change-rolled-back) |
| `Roxy: auto-applied change could not be rolled back` | critical | the same, but the undo was refused, so the change is still in place | once a day per recommendation | [Auto-applied change rolled back](/admin/help/runbooks#auto-applied-change-rolled-back) |
| `Roxy: login attempts throttled globally` | warn | more than `admin_login_global_max_per_min` (30) sign-in attempts in one minute | once an hour | [Login attempts throttled](/admin/help/runbooks#login-attempts-throttled) |
| `Roxy daily digest: <n> open recommendations` | info | while `alert_digest_enabled` is on (the default), at `alert_digest_hour` (9, in the dashboard time zone): open recommendations, the latest health run's failing checks and the Roblox 429 numbers of the last 24 hours | once a day, never held back by the hourly cap | [Daily digest](/admin/help/runbooks#daily-digest) |
| `Roxy DOWN: <unit> failed on <host>` | critical | a Roxy color, the nightly backup or the file permission audit failed under systemd | once per unit every 10 minutes | [Service down](/admin/help/runbooks#service-down) |
| `Roxy: deploy <short sha> failed at step <n>` | critical | a deploy stopped at one of its steps | once per commit every 10 minutes | [Deploy failed](/admin/help/runbooks#deploy-failed) |
| `Roxy: test alert` | the lowest severity sent | you pressed Send test alert on the Settings page's Alerts card | once a minute | none: nothing needs doing |

### What keeps alerts quiet

- **Severity.** `alert_min_severity` (default warn) is the lowest severity sent. The admin login email and the leak
  guard alert are always sent, whatever it says. The daily digest has its own switch, `alert_digest_enabled` (on by
  default), and is sent whatever this says. Critical only is marked high risk,
  because slow problems (rate limiting, failing backups, a filling disk) raise only warnings.
- **Cooldowns.** Once an alert goes out, the same alert waits its gap from the table before it is sent again. Two of
  those gaps are settings: `error_email_cooldown` (300 s, the error and all upstream methods alerts) and
  `email_cooldown` (600 s, the `Token Expired` and cooling down alerts); the others are fixed.
- **Hourly cap.** At most `alert_rate_limit_per_hour` (20) messages per channel per hour, counted across all workers.
  Alerts over the cap are held back and counted, and the next message that goes out says
  `Suppressed since last alert: N`. The leak guard and admin login alerts are never held back.
- **Noise floor.** The two rate alerts need more than 2% over 10 complete minutes and at least 5 bad answers, so one
  failed call out of three never pages you. These numbers are fixed in the code, not settings.
- **Start and deploy.** The leader's alert checks never run at startup, so a deploy does not alert about what it just
  did.
- **When the shared state is down.** The cooldowns and the cap live in hot.db. If it cannot be written, each worker
  applies the same rules from its own memory: the hourly cap still holds, but each of the two workers may send its
  own copy of an alert.

### What an alert says, and its runbook link

An alert email starts with a short summary, then: What happened, When (in UTC and in your dashboard time zone,
`ui_timezone`, America/New_York until you change it), Where (the dashboard page to open), Evidence (up to 5
numbers), What to do (the runbook link) and, when alerts were held back, Suppressed since last alert. The webhook
gets the same fields as JSON. Every field goes through the same redaction as Roxy's logs, so no secret, cookie or
token reaches your inbox; the one link that may carry a token is the session kill link in the admin login email.

The What to do link has the form `https://<your site>/admin/help#runbook-<name>` (for example
`/admin/help#runbook-roblox-429`). The Help page opens its incident runbook index at that entry and goes on to the
runbook itself; the runbooks' [Link index](/admin/help/runbooks#link-index) lists every name.

The Where line is a full address on your site (`ROXY_SITE_ORIGIN` in front of the dashboard path), so it opens from
a mail client: the credential alerts link Credential > Status (the new cookie alert Credential > Replace), the rotator
quota alert Egress > Budget, the leak guard alert Egress > Leak guard, the all upstream methods alert the Upstream
page, and an auto-apply rollback alert the recommendation's own card. Three messages differ: the admin login email
keeps v1's exact text; `Roxy DOWN` carries the failed unit's status, its restart count and its last 60 journal lines
(redacted); and `deploy failed` carries the step's error, what the rollback did and the commands to check first. For
those, the runbook column of the table above tells you where to go.

### Testing that alerts arrive

- Run Check Proxy Health. Its H-ALERTS check tests the channels without sending anything: it connects and signs in
  to the mail server, and for a Discord webhook it asks Discord about the webhook without posting. It passes when
  every channel answers, warns when one is down or cannot be tested (a webhook that is not Discord's), and fails when
  no channel works.
- Sign in. Every sign-in sends the `Roxy Admin Login` email whatever the severity setting says, so it proves that
  email really arrives.
- Press **Send test alert** on the Settings page's Alerts card. It posts one real message, `Roxy: test alert`,
  through every configured channel, at the lowest severity `alert_min_severity` lets through (so the filter never
  hides it), at most one a minute and within the hourly cap, and says which channels it reached or why nothing was
  sent. The press is written to the audit log first (`alerts.test`). This is the way to prove a webhook that is not
  Discord's.
- When H-ALERTS fails, follow [Alert channels down](/admin/help/runbooks#alert-channels-down).

## Backups and resets

Two different things live on the Data page. Backups copy your databases so you can get them back; resets delete
statistics you no longer want. A backup never deletes anything from the databases, and a statistics reset never
touches your settings, rules, admin accounts or the audit log (see
[What a reset never clears](#what-a-reset-never-clears)).

### The nightly backup

`roxy-backup.timer` starts `roxy-backup.service` every night at 03:30 server time, plus up to 15 minutes at random;
if the server was off at that time, it runs soon after it boots. The service runs `backup.sh` as root, which:

1. copies control.db (settings, rules, admin accounts, the audit log) and metrics.db (the statistics) with SQLite's
   `VACUUM INTO`, a consistent copy made while Roxy keeps running (hot.db too, but only when `ROXY_BACKUP_HOT=1`);
2. checks each copy with `PRAGMA integrity_check`, compresses it with zstd and tests the compressed file;
3. encrypts each file with age when a recipients file exists (see
   [The off-box copy and encryption](#the-off-box-copy-and-encryption));
4. writes a `SHA256SUMS` file and moves the set into place only when every file passed, so a half-made backup is
   never mistaken for a good one;
5. removes old sets, runs a restore test every 28 days, copies the set off the server when that is set up, and
   records the result in `/var/lib/roxy/audit/backup.json`, which the Data page, health check H-BACKUP and the backup
   alerts read.

cache.db is never backed up (it rebuilds itself), and neither are the encryption keys. A failed run sends
`Roxy DOWN: roxy-backup.service failed on <host>` at once, and Roxy's own `Roxy: backup failed` within 30 minutes.
Before the first deploy there is no database yet; the backup then ends quietly instead of failing.

### Back up now

The Back up now button (in the Data page's header and on its Backups card) asks for an optional reason, then:

- asks the nightly backup to run now. Roxy runs as the unprivileged `roxy` user, which may not start system
  services, so it writes a small request file, `/var/lib/roxy/backup-request`, and `roxy-backup-request.path` starts
  the same `roxy-backup.service` within seconds. A request within 10 minutes of the last good backup is answered by
  that backup and skipped.
- also copies control.db and metrics.db into the snapshots folder on this server when they fit (see
  [Snapshots on the server](#snapshots-on-the-server)).

Nothing is deleted from the databases, and the proxy keeps serving. When it finishes, the card says whether the
request was written, which databases were copied here and their sizes, which were not and why, and "Replaced older
Back up now copies: ..." when it removed its own oldest copies to make room.

The Data page's Backups card then shows how the server's backup answered (see [Backups](#backups) in the Data
chapter). Its "Last nightly backup" line shows the last good run, nightly or requested, and an encrypted set's
restore test reads "Not run automatically" (it is tested by hand). If a request stays under "Waiting to run" for more
than a few minutes, check that `roxy-backup-request.path` is enabled on the server.

From the shell, `roxyctl backup-now --wait 600` sends the same request to the nightly backup (without the copies
here) and waits for its answer (see [The operator CLI](#the-operator-cli)).

### Where backups live and how many are kept

- One directory per day, `/var/backups/roxy/<date>/` (dates in UTC; only root can read it), holding
  `control.db.zst` and `metrics.db.zst` (with `.age` added when encrypted) and a `SHA256SUMS` file.
- A second run on the same day, such as Back up now after the nightly backup, replaces that day's set: the new set
  goes into place first, then the earlier one is removed.
- Kept: the 14 newest sets, plus the newest set of each of the last 8 weeks. Older sets are deleted at the end of
  each run.
- These sets sit on the same disk as Roxy, so a lost server takes them with it. That is what the off-box copy is
  for.

### Snapshots on the server

Apart from the backups, Roxy keeps safety snapshots in `/var/lib/roxy/snapshots/`: plain database copies taken
before a reset (Before a reset, files named `reset-<time>-<database>.db`), by Back up now (Back up now, files named
`manual-...`) and, when a color starts with a database migration to apply, before that migration (control.db only,
files named `pre-migrate-...`, the newest 10 kept, Kind Before a migration). The Backups card lists them with their
kind, size and time. They are kept
`retention_snapshots_days` (7 days), and all of them together may use `snapshots_max_bytes` (2 GiB); past that, the
oldest go first, and a reset whose snapshot would not fit runs without one (its preview says so), except the factory
reset, which refuses to run without its control.db snapshot. Back up now makes room by removing only its own oldest
copies, and says which ones it replaced. cache.db and hot.db are never snapshotted. A snapshot is on the same disk
too, so it is a quick way back from a reset, not a backup.

### The off-box copy and encryption

One disk is a single point of failure. Two optional additions make the backup safe to keep somewhere else (owner
decision D15):

- **Encryption.** Put one or more age public keys (recipients) in `/etc/roxy/backup-age-recipients` and install
  `age` (a recipients file without `age` installed fails the run). Every database file of every set is then
  encrypted, and only the matching private key, which you keep off the server, can read it. The automatic restore
  test cannot open an encrypted set, so practice the restore by hand.
- **Off-box copy.** Install `rclone`, set `ROXY_BACKUP_REMOTE` in `/etc/roxy/roxy.env` to the name of an rclone
  remote (the name only: letters, digits, `_` and `-`) and put that remote's rclone configuration, with its access
  keys, in the credential file `/etc/roxy/credentials/rclone_config` (an empty file means no off-box copy). Each set
  is then copied to `<remote>:roxy-backups/<date>`. Only an encrypted set ever leaves the server: a set holds the
  admin password hash, raw client addresses and the audit log, so with a remote and no age recipient the run fails at
  its `rclone push` step instead of copying it. A failed copy, or the remote name set while that file is empty, fails
  the run too, so you hear about it.
- **The keys are never in a backup.** Nothing in `/etc/roxy/credentials/` is copied (the Roblox credential, the keys
  that encrypt the stored credential and the authenticator secrets, the mail password), so a stolen backup reveals
  none of them. Keep your own offline, age-encrypted copy of that folder, made once and again after any key changes:
  without `totp_encryption_key` nobody can sign in after a restore on a new server. The
  [Restore from backup](/admin/help/runbooks#restore-from-backup) runbook has the commands.

### Restoring a backup

A restore replaces a live database, so it is done from the server shell with both colors stopped. The backup sets
are readable by root only, so the whole restore runs in a root shell (`sudo -i`). The
[Restore from backup](/admin/help/runbooks#restore-from-backup) runbook has every command; in short:

1. On a new server, first put `/etc/roxy/credentials/` back from your offline copy, then fetch a set from the
   off-box copy with rclone when the disk was lost.
2. Pick a set in `/var/backups/roxy` and check it against its `SHA256SUMS` file.
3. Stop both colors.
4. Move the damaged files aside (for example `control.db` to `control.db.bad`, with its `-wal` and `-shm` files).
   Keep these replaced copies until everything works again: they are your way back if the restore makes things
   worse.
5. Decrypt the file if the set is encrypted (with your age identity, which never stays on the server), and
   decompress it into `/var/lib/roxy/`.
6. Give it back to the `roxy` user (owner `roxy:roxy`, mode 0640) before anything opens it, then check it with
   `PRAGMA integrity_check` as that user.
7. Start the live color, leave the root shell and run Check Proxy Health.

hot.db never needs restoring (a fresh one is made at start), and cache.db is never backed up. When the backup itself
fails, see the [Backups](/admin/help/runbooks#backups) runbook. Practice a restore once a quarter, so the first one is
not during an incident.

Putting a reset snapshot back is a restore as well: the same steps with the snapshot file from
`/var/lib/roxy/snapshots/` in place of a backup set. A snapshot is already a plain database file, so the decrypt and
decompress steps do not apply. Everything recorded after the snapshot was taken is lost with it.

### Statistics resets

A reset deletes one kind of statistics, if you like only between two dates. The Resets card on the Data page (Reset
statistics in the page header jumps to it) does every kind; [Resets](#resets) in the Data chapter walks through the
card, with every scope, its typed phrase and what each family clears. In short: choose what to reset, press
Preview (nothing is deleted yet), then Run this reset with a reason and, when the scope asks for one, the typed
phrase. It deletes exactly what the preview showed. A reset limited by dates, one client, one endpoint, part of the
cached answers, bans or recommendations, or the upstream reset asks no phrase, and then the reason is optional.

Every reset is written to the audit log with the rows it deleted per table, takes a snapshot first of control.db or
metrics.db when it deletes rows there and the snapshot fits (see
[Snapshots on the server](#snapshots-on-the-server)), and leaves a marker on every chart that covers that time, so a
drop never looks like traffic going away. To undo one, put that snapshot back (see
[Restoring a backup](#restoring-a-backup)); without a snapshot a reset cannot be undone.

Several cards also have their own button next to their numbers: Reset on the Traffic page's Requests and Latency
cards and on the Overview's Visitors card, Clear stats on the Cache page, Reset its numbers on an endpoint's page,
Delete the records on the Live page and Clear client activity on the Clients page. They preview and run these same
resets. Two families are gentler than their names: Latency empties only the latency histograms and keeps the request
counts, and Cache statistics clears hits, misses, stale and coalesced answers together while the cached entries
stay.

### Narrower reset families

v1 cleared some lists on their own, so two families have narrower parts nested under them on the card (the Data
chapter's [What each family clears](#what-each-family-clears) lists every family):

- **Throttle**: Throttle rule hits (the ladder rung and User-Agent rule hit counts; the throttled clients list stays)
  and Throttled clients (the clients that became throttled; the hit counts stay).
- **Refusals**: Endpoint block attempts, Endpoint rule attempts and Request filter attempts. Each deletes only that
  kind of refusal, which also leaves the Refusals card; the other refusals stay.

### Old v1 targets with nothing to reset

v1 had 27 "Clear data" targets. "Where v1's 'Clear data' buttons went", at the bottom of the Resets card, lists
where each one went in v2. Two of them answer "Nothing to reset", because v2 counts them from a moment that moves by
itself:

- `pause_drops`: the pause banner counts from the moment the pause began.
- `throttle_drops`: switching throttle-all on starts a new count by itself.

v1's `all` became Everything (statistics) plus the Reset request counts button on the System page's Workers card,
which zeroes each worker's request counters (the map's note says so: "System > Reset request counts").

### What a reset never clears

- **Settings and rules.** No statistics reset touches them; only the factory reset puts them back to their defaults.
- **The audit log and the settings history.** No reset deletes them, not even the factory reset.
- **Admin accounts and the credential.** Every reset keeps them.
- **Rule hit history** (how often each rule, list entry and filter matched). No family reset deletes it: the
  recommendation that suggests removing an unused filter reads it, and a filter whose hits vanished would look as if
  it never matched. Only Everything (statistics) and the factory reset remove it.
- **Bans.** Kept, unless you choose the Bans scope or the factory reset.

## The operator CLI

`scripts/ctl.py` is a command line for the server shell; the runbooks call it `roxyctl`. It uses the same services as
the dashboard, so its changes are checked the same way, reach every worker within about a second, and are written to
the audit log as `cli:<your login name>` (the name behind sudo) with the reason you give. It never reads a credential
and never prints a secret.

### Running it

Run it as the `roxy` user, from the release of the live color. A shell alias saves typing (replace `blue` with the
live color):

```sh
alias roxyctl='sudo -u roxy /opt/roxy/releases/current-blue/.venv/bin/python /opt/roxy/releases/current-blue/scripts/ctl.py'
roxyctl status
```

It finds the databases and the sockets from `/etc/roxy/roxy.env` and the color env files, and falls back to
`/var/lib/roxy` and `/run/roxy-<color>/internal.sock`; `--env-dir`, `--state-dir`, `--socket` and `--color` override
them (`--nginx-dir` and `--deploy-state-dir` say where nginx's active color link and the deploy's records are). These
options and `--json` go before the command: `roxyctl --json status` prints JSON for scripts. The exit status is 0
when done, 1 when refused or failed (the message says why), 2 for bad arguments, and 3 when there is nothing to talk
to (no database, or no color answers).

### When to use it instead of the dashboard

Prefer the dashboard: it explains each change and shows its effect. Use the CLI when the dashboard is out of reach
(nginx is down, you are locked out, the admin allowlist hides `/admin` from your network, the server is under attack)
or when you want a command in a script. A few things are dashboard only: the factory reset (it needs a fresh second
factor), replacing the credential, replacing the rotator URL, and arming the spam detectors (`settings set
spam_dry_run=0` is refused, because the Protection page first shows who would have been banned). To get back into a
locked account, use `scripts/create_admin.py`, or `roxyctl settings set admin_allowlist_enabled=0` when the admin
allowlist keeps you out ([Admin locked out](/admin/help/runbooks#admin-locked-out)).

### Every command

- `status`: which color nginx serves, both colors' sockets, pause and throttle-all, the config version, active bans,
  the leader and the last backup. Example: `roxyctl status`
- `pause` and `resume`: the maintenance switch; while paused, every proxy request gets 503 with your message (kept
  from last time when you leave out `--reason`). Example: `roxyctl pause --reason "Back soon."`, later
  `roxyctl resume`
- `throttle-all on` or `off`: the emergency per-IP limit for every client. Example:
  `roxyctl throttle-all on --reason "flood"`
- `purge-cache`: removes cached answers on every worker: `--all` (needs `--yes`), `--host`, `--pattern` (a glob, or a
  regular expression with `--regex`), `--id`, `--rule` or `--expired`; `--preview` only counts. Example:
  `roxyctl purge-cache --expired --preview`
- `reset preview` and `reset run`: a Data page reset. The run repeats the preview's options and adds the 64-character
  `--digest` the preview printed, a `--reason`, and `--confirm` with the phrase the preview asked for. Example:
  `roxyctl reset preview --scope family --family live`, then
  `roxyctl reset run --scope family --family live --digest <digest> --reason "old captures" --confirm "reset live"`
- `export-llm`: the LLM export, written to a file only its owner can read (mode 0600); `--window` 24h, 7d or 30d,
  `--detail` summary or full, `--format` json or text. Example:
  `roxyctl export-llm --window 7d --detail summary --out /tmp/roxy-week.json`
- `health-run`: Check Proxy Health, waiting for the result; it exits with 1 when a check fails. `--check` picks
  checks (repeat it), `--include-credential` adds the credential check (one Roblox call), `--no-wait` returns at
  once. Example: `roxyctl health-run --check H-BACKUP`
- `backup-now`: asks the nightly backup to run now; `--wait` waits that many seconds for its answer. Example:
  `roxyctl backup-now --wait 600 --reason "before the upgrade"`
- `leader`: which worker leads the fleet, and every worker's heartbeat. Example: `roxyctl leader`
- `jobs`: what the leader last published about its scheduled jobs. Example: `roxyctl jobs`
- `bans list` and `bans lift`: the ban list (`--state` active, expired or all, `--search`, `--limit`), and lifting
  every ban of one subject (`ip`, `cidr`, `place` or `ua_hash`). Example:
  `roxyctl bans lift ip 192.0.2.10 --reason "false positive"`
- `flush-metrics`: every worker writes its buffered counters within about a second. Example:
  `roxyctl flush-metrics`
- `settings show` and `settings set`: read settings (all of them, or the keys you name), or change them through the
  same checks as the Settings page, as `KEY=VALUE` pairs; a high-risk setting or value also needs `--reason` and
  `--confirm-high-risk`. Example: `roxyctl settings show alert_digest_hour`,
  then `roxyctl settings set alert_digest_hour=7 --reason "the daily digest before work"`

### Which commands need the roxy user

In practice all of them, which is why the alias runs `sudo -u roxy`:

- The commands that work on the databases directly (`pause`, `resume`, `throttle-all`, `purge-cache`, `backup-now`,
  `leader`, `jobs`, `bans`, `flush-metrics`, `settings`, and the database half of `status`) refuse to run as anyone
  but the databases' owner, because SQLite would create files the service could not open. They also work while both
  colors are stopped. `status` still reports the sockets when it cannot read the databases.
- The commands that ask a running color through its internal socket (`reset`, `export-llm`, `health-run`) need
  root or the `roxy` group to open the socket, and at least one running color (nginx's color is asked first). A
  `reset run`, an `export-llm --detail full` and a `health-run --include-credential` must also prove they run as
  `roxy`, so the deploy account, which may open the socket, can never use those three.

## Incident runbooks

The runbooks say what to do when something goes wrong. Each one has the same parts: the symptoms, how to confirm,
the likely causes, the fix (safest step first), how to check it worked, how to roll back, and how to prevent it next
time. They are on the Help page at [Runbooks](/admin/help/runbooks). Most alert emails link to their runbook, and
the [Alerts](#alerts) chapter names the runbook of every alert; every failing health check links to its own. The
runbooks' [Link index](/admin/help/runbooks#link-index) and
[Health checks and their runbooks](/admin/help/runbooks#health-checks-and-their-runbooks) tables list every link.
Read [How to use these runbooks](/admin/help/runbooks#how-to-use-these-runbooks) once, and keep
[Everyday commands](/admin/help/runbooks#everyday-commands) at hand.

**Stopping everything**

- [Emergency stop](/admin/help/runbooks#emergency-stop): Roxy must stop calling Roblox right now (Roblox is
  complaining, the account is at risk, the rotator bill is running away, or you suspect a compromise).
- [Under attack](/admin/help/runbooks#under-attack): a sudden jump in requests and refusals, slower answers, spam
  detector events.

**Roblox and the path to it**

- [Roblox is rate-limiting us](/admin/help/runbooks#roblox-is-rate-limiting-us): the 429 alert, or callers getting
  429 answers with a cooldown.
- [All upstream paths unavailable](/admin/help/runbooks#all-upstream-paths-unavailable): every egress is off and
  callers get 503.
- [Upstream slow or unreachable](/admin/help/runbooks#upstream-slow-or-unreachable): slow answers, open breakers,
  or the reach and latency health checks warn.
- [Caller errors](/admin/help/runbooks#caller-errors): the caller errors alert, or many callers getting 5xx.
- [Cache not working](/admin/help/runbooks#cache-not-working): the cache health checks fail or warn.

**The credential and the rotator**

- [Credential rejected](/admin/help/runbooks#credential-rejected): `Token Expired`, or the Credential page says
  rejected.
- [Credential cooling down](/admin/help/runbooks#credential-cooling-down): the credential must rest 10 minutes or
  more after a Roblox 429.
- [Credential rotated by Roblox](/admin/help/runbooks#credential-rotated-by-roblox): Roblox sent a new cookie.
- [Leak guard](/admin/help/runbooks#leak-guard): the leak guard blocked a request with the credential and switched
  an egress off.
- [Rotator down or quota exhausted](/admin/help/runbooks#rotator-down-or-quota-exhausted): the quota alert, or the
  rotator parked or stopped on the Egress page.

**The service, deploys and the server**

- [Service down](/admin/help/runbooks#service-down): `Roxy DOWN`, or nginx answers 502.
- [Deploy failed](/admin/help/runbooks#deploy-failed): a deploy stopped at a step.
- [Unhandled errors](/admin/help/runbooks#unhandled-errors): `Roxy Error: <signature>`.
- [Workers or leader missing](/admin/help/runbooks#workers-or-leader-missing): stale heartbeats, no leader, late
  jobs.
- [Slow event loop](/admin/help/runbooks#slow-event-loop): every request of a worker gets slower.
- [Version mismatch](/admin/help/runbooks#version-mismatch): the running release is not the deployed one.
- [nginx](/admin/help/runbooks#nginx), [Certificate](/admin/help/runbooks#certificate),
  [Clock](/admin/help/runbooks#clock), [DNS](/admin/help/runbooks#dns), [TLS](/admin/help/runbooks#tls),
  [Proxy variables in the environment](/admin/help/runbooks#proxy-variables-in-the-environment),
  [End to end check](/admin/help/runbooks#end-to-end-check) and
  [File permissions](/admin/help/runbooks#file-permissions): the health check of the same topic warns or fails.

**Storage and backups**

- [Disk full or database large](/admin/help/runbooks#disk-full-or-database-large): the storage alert, or the disk
  and database size checks.
- [Database corrupt](/admin/help/runbooks#database-corrupt): the integrity alert, or errors about a malformed
  database.
- [Backups](/admin/help/runbooks#backups): a backup failed or is too old.
- [Restore from backup](/admin/help/runbooks#restore-from-backup): a database is damaged or lost, or a bad change
  must be undone as a whole.

**Admin access and alerts**

- [Unexpected admin login](/admin/help/runbooks#unexpected-admin-login): a `Roxy Admin Login` email you did not
  cause.
- [Admin locked out](/admin/help/runbooks#admin-locked-out): a lost phone, a forgotten password, the allowlist or
  the lockout keeps you out.
- [Login attempts throttled](/admin/help/runbooks#login-attempts-throttled): password guessing from many networks.
- [Alert channels down](/admin/help/runbooks#alert-channels-down): alerts may be failing silently.

**After a health run or a recommendation**

- [Health check found new failures](/admin/help/runbooks#health-check-found-new-failures): the scheduled run's
  alert.
- [Auto-applied change rolled back](/admin/help/runbooks#auto-applied-change-rolled-back): an automatic change was
  undone, or could not be.
- [Config or ban list problems](/admin/help/runbooks#config-or-ban-list-problems): a stored setting or rule no
  longer validates, or a ban covers you, a bypass entry or a top place.
- [Daily digest](/admin/help/runbooks#daily-digest): what to do with the morning summary.

## Glossary

Every term the dashboard uses has a plain definition in the [glossary on the Help page](/admin/help#glossary), and a
term with a dotted underline anywhere in the dashboard shows its definition on hover and links to its entry there
(`/admin/help#term-<id>`). The definitions live in one file, `docs/glossary.yml`, which feeds both the dashboard's
hover texts and the Help page, so they never disagree. The ten terms a new owner meets first:

- [Credential](/admin/help#term-credential): the single Roblox .ROBLOSECURITY cookie Roxy owns, used for Roxy's own
  probes and the endpoints the endpoint policy sends with it, and never sent through the rotator.
- [Egress](/admin/help#term-egress): the path a request leaves Roxy through on its way to Roblox: direct,
  credential or rotator.
- [DataImpulse / rotator](/admin/help#term-rotator): a paid rotating residential proxy service Roxy can use as an
  alternate exit for anonymous requests, only when the direct path cannot be used.
- [systemd credential](/admin/help#term-systemd-credential): a secret file that systemd hands privately to the
  service when it starts, readable only by that service.
- [TOTP](/admin/help#term-totp): the six-digit code from an authenticator app that changes every 30 seconds.
- [Passkey (WebAuthn)](/admin/help#term-passkey): a phishing-resistant login that uses a key stored on your device
  and unlocked with your fingerprint, face or PIN.
- [Health check](/admin/help#term-health-check): a run of Roxy's built-in checks over every part of the system,
  with a pass, warn or fail for each and a fix for every failure.
- [Recommendation](/admin/help#term-recommendation): a suggested change backed by evidence, with a preview of its
  effect, one-click apply, and undo.
- [Cooldown](/admin/help#term-cooldown): a period during which Roxy will not contact an endpoint or egress at all,
  usually set from the Retry-After header of a Roblox 429.
- [Leak guard](/admin/help#term-leak-guard): the check on every anonymous outgoing request that refuses to send it
  if it contains the credential, and switches that egress off until an admin turns it back on.
