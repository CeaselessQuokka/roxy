# Roxy admin guide

This guide is being written: each chapter below is a placeholder that names where its topic lives on the dashboard
today. Every dashboard page also says what it is for in its first line and explains itself in its "How to read this
page" panel, and the Help page lists them all.

## Getting started

Being written. First-time setup: sign in, enroll your authenticator app and a passkey, keep the recovery codes
(Security page), then check the credential (Credential page), the rotator (Egress page) and where alerts go
(Settings page, Alerts card).

## Overview

Being written. The Overview page (`/admin/overview`): the status strip, the top recommendations, the KPI tiles, the
visitors, and the traffic, outcome and top ten cards.

## Recommendations

Being written. The Recommendations page (`/admin/recommendations`): what each rule found, the evidence, the dry run
preview, apply and undo, snooze and dismiss, and the guardrails of automatic apply.

## Traffic

Being written. The Traffic page (`/admin/traffic`): requests over time, bytes, methods, status codes and who returned
them, latency, the busiest hours and the trends.

## Upstream

Being written. The Upstream page (`/admin/upstream`): how Roxy stays below Roblox's limits (buckets, cooldowns,
breakers, the queue and retries), the failures log and "why did this request wait".

## Egress

Being written. The Egress page (`/admin/egress`): bytes per egress, the rotator's budget and projection, exit
addresses, sessions and the leak guard trips.

## Cache

Being written. The Cache page (`/admin/cache`): hit ratios, the cache settings explained with one request, the rules,
the ignored parameters, the key spread and the browser.

## Endpoints

Being written. The Endpoints page (`/admin/endpoints`): every endpoint template with its volume, latency and rules,
and the drill-down of one endpoint.

## Clients

Being written. The Clients page (`/admin/clients`): places and addresses, their rates, refusals and bot scores, the
place lookup and the actions on one client.

## Protection

Being written. The Protection page (`/admin/protection`): the order of the checks, the throttle and its ladder, bans
and lists, request filters, endpoint rules, the spam detectors, the tarpit and the bot score.

## Live

Being written. The Live page (`/admin/live`): the request tail, its filters, and what one request did.

## Security

Being written. The Security page (`/admin/security`): sign-ins, probes, crawls, fingerprints, CSP reports, your
sessions, trusted devices, passkeys and recovery codes, and where you may sign in from.

## Health

Being written. The Health page (`/admin/health`): Check Proxy Health, a run's results with their fixes, the history
and the automatic runs.

## Settings

Being written. The Settings page (`/admin/settings`): every setting with what it does, its risk, its history and
revert, and import and export.

## Credential

Being written. The Credential page (`/admin/credential`): the one Roblox credential, its budget and probes, the
endpoints it may be used for, and the rules for replacing it.

## Data

Being written. The Data page (`/admin/data`): what is stored and for how long, the resets, the backups, VACUUM and
the exports.

## Audit

Being written. The Audit page (`/admin/audit`): every change, who made it and why, with the difference and the
revert.

## System

Being written. The System page (`/admin/system`): the workers of both colors, the leader, the jobs, the metrics
pipeline, the storage, the error log and the versions.

## Help

Being written. The Help page (`/admin/help`): this guide, the runbooks, the glossary, the keyboard shortcuts and what
every page does.

## Alerts

Being written. Which alerts Roxy sends, how often, and where; every alert email links to its runbook on the Help page.

## Backups and resets

Being written. The nightly backup, Back up now, restoring, and the statistics resets (whole families, narrower ones,
and the old targets with nothing to reset): the Data page and the Backups runbook.

## The operator CLI

Being written. The command line on the server (`scripts/ctl.py`, called roxyctl in the runbooks) pauses, flushes, runs
health checks and backups when the dashboard is out of reach; the runbooks' "Everyday commands" lists it.
