"""Alerts to the admin: email (Gmail SMTP over SSL) and an optional webhook, deduped fleet-wide and capped.

What this is
    The package every part of Roxy uses to tell the owner something needs attention: `alerts.py` (the catalog of
    alert types with their exact subjects, plan 17.7), `gate.py` (fleet-wide dedupe and the hourly cap, in
    hot.db), `mail.py` and `webhook.py` (the two channels), and `notifier.py` (`Notifier`, which ties them
    together and never blocks a request).

Why it exists
    v1 sent mail inline from request threads, deduped per worker process (so two workers sent the same alert
    twice), and could put unredacted text in mail. Plan 17.7 and DESIGN.md 11.6: every alert is deduped by its
    cooldown key in hot.db `email_gate` for the whole fleet, capped per channel per hour (a storm becomes one
    "N alerts suppressed" line instead of 200 mails), redacted field by field, and sent from a background task
    with a timeout, so a slow mail server never slows a caller.

How it works
    Producers build an `Alert` with `alerts.make_alert(type, ...)` and call `ctx.alerts.notify(alert)` (fire and
    forget) or `await ctx.alerts.send(alert)` (when they need the result). Subjects that existed in v1 are kept
    byte for byte because owners filter mail on them.

What to read next
    `roxy/notify/notifier.py`, then `roxy/notify/gate.py` and `roxy/notify/alerts.py`.
"""
