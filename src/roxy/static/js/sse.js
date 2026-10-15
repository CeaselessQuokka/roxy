/**
 * Server-Sent Events client with Last-Event-ID resume (plan 14.11).
 *
 * What this is
 *   `new EventStream(url, {onEvent, onState})` keeps one stream open to `GET /admin/api/v1/stream` (or any SSE
 *   URL), parses it, and reconnects after a drop, sending `Last-Event-ID` so the server resumes right after the last
 *   event this page saw. `initStream()` opens the page-wide stream named by `data-stream-url` on <body>, re-raises
 *   each event as a DOM event (`roxy:sse` and `roxy:sse:<type>`) and drives the "Live" pill in the top bar.
 *
 * Why it exists
 *   The browser's EventSource cannot report the status of a failed connection, so it cannot tell "the session
 *   expired" (401: show the overlay, stop) from "the network blinked" (retry). It also cannot set Last-Event-ID on
 *   a reconnect it did not make itself. Reading the stream with fetch() solves both and lets the client bound its
 *   buffer (plan P9): a line longer than 1 MiB means something is wrong, and the connection is dropped.
 *
 * How it works
 *   The text/event-stream format: lines `event:`, `data:` (several are joined with newlines), `id:`, `retry:`, and
 *   comments starting with ":"; a blank line ends one event. Reconnects wait the server's `retry` value, or an
 *   exponential backoff from 1 to 30 seconds with jitter (so many tabs do not reconnect in lockstep), reset once a
 *   connection has delivered events. A 401, or the server's control event `unauthorized` (the session ended while
 *   the stream was open; the server closes it), is checked with `GET /admin/api/v1/auth/session` before the
 *   page is told it is signed out: a re-entered second factor rotates the session cookie, and the stream opened
 *   with the old one is ended although the admin is still signed in (review finding authz-1). While the session
 *   answers 200 the stream reconnects at once with the new cookie (and the page takes the new CSRF token); a 401
 *   raises `roxy:unauthorized` and stops for good; anything else (no answer, a 503) reconnects with the backoff,
 *   and after `MAX_RECHECKS` checks within a minute the server's word stands (it sends `unauthorized` and 401 only
 *   for a session it read as ended; a control.db outage is a 503 and never a recheck, C7). This traffic never
 *   counts as session activity on the server (plan 9.6). `gap` (a resume could not replay everything that was
 *   missed) is passed on like any event, so each consumer reloads or marks what it shows (`roxy:sse:gap` on the page-wide stream).
 *   Settings: the page-wide stream's URL carries the `config_version` the page was rendered with, and every
 *   `settings_changed` moves it, so a reconnect after a drop is told at once about a change it missed (finding
 *   functional-5). `roxy:session-rotated` (static/js/reauth.js, or another tab) reconnects at once.
 *
 * What to read next
 *   static/js/live_tail.js (the main consumer), roxy/admin/sse.py (the server side, P11 part two).
 */

import { qs } from "roxy/dom";
import { setCsrfToken, signalUnauthorized } from "roxy/net";

const MAX_BUFFER = 1024 * 1024;
const MIN_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;
const MAX_RECHECKS = 3;  // session checks within RECHECK_WINDOW_MS before the server's word stands
const RECHECK_WINDOW_MS = 60000;
const SESSION_URL = "/admin/api/v1/auth/session";

/**
 * Is the session of this browser still alive? `"alive"` (200: the new masked CSRF token is taken too), `"ended"`
 * (401), or `"unknown"` (no answer, 503 while control.db cannot be read, anything else).
 */
export async function sessionState() {
  let response;
  try {
    response = await fetch(document.body.dataset.sessionUrl || SESSION_URL, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
    });
  } catch {
    return "unknown";
  }
  if (response.status === 401) return "ended";
  if (!response.ok) return "unknown";
  const body = await response.json().catch(() => ({}));
  if (body && typeof body.CsrfToken === "string") setCsrfToken(body.CsrfToken);
  return "alive";
}

export class EventStream {
  constructor(url, { onEvent = () => {}, onState = () => {}, params = {} } = {}) {
    this.baseUrl = url;
    this.params = params;
    this.onEvent = onEvent;
    this.onState = onState;
    this.lastEventId = "";
    this.retryMs = 0;
    this.backoffMs = MIN_BACKOFF_MS;
    this.controller = null;
    this.timer = 0;
    this.stopped = true;
    this.state = "off";
    this.rechecks = [];  // when each recent session check ran (Date.now())
  }

  setState(state) {
    if (state === this.state) return;
    this.state = state;
    this.onState(state);
  }

  url() {
    const target = new URL(this.baseUrl, window.location.href);
    for (const [name, value] of Object.entries(this.params)) {
      if (value === "" || value === null || value === undefined) target.searchParams.delete(name);
      else target.searchParams.set(name, value);
    }
    return target.pathname + target.search;
  }

  start() {
    if (!this.stopped) return;
    this.stopped = false;
    this.connect();
  }

  stop() {
    this.stopped = true;
    window.clearTimeout(this.timer);
    if (this.controller) this.controller.abort();
    this.controller = null;
    this.setState("off");
  }

  /** Reconnect at once (the session cookie was rotated: the open connection still carries the old one). */
  reconnectNow() {
    if (this.stopped) return;
    window.clearTimeout(this.timer);
    if (this.controller) this.controller.abort();
    this.backoffMs = MIN_BACKOFF_MS;
    this.connect();
  }

  /**
   * The server said the session ended (a 401, or the `unauthorized` event). Ask whether it did: a rotated
   * session (a fresh second factor) is alive under a new cookie, and a control.db outage proves nothing.
   */
  async recheckSession() {
    window.clearTimeout(this.timer);
    if (this.controller) this.controller.abort();
    this.controller = null;
    // The server's own word (a 401 or `unauthorized`; it never says so while it cannot read the session, authz-4)
    // stands once MAX_RECHECKS checks within RECHECK_WINDOW_MS did not prove the session alive under a new cookie:
    // a stream that keeps being ended is not reopened forever.
    const now = Date.now();
    this.rechecks = this.rechecks.filter((at) => now - at < RECHECK_WINDOW_MS);
    const verdict = this.rechecks.length < MAX_RECHECKS ? await sessionState() : "ended";
    this.rechecks.push(now);
    if (this.stopped) return;
    if (verdict === "alive") {
      this.backoffMs = MIN_BACKOFF_MS;
      this.connect();
      return;
    }
    if (verdict === "unknown") {
      this.scheduleReconnect();  // no answer either way: try again with the backoff
      return;
    }
    this.stopped = true;
    this.setState("expired");
    signalUnauthorized("sse");
  }

  /** Change the server-side filter: reconnects at once, keeping Last-Event-ID. */
  setParams(params) {
    this.params = params;
    if (this.stopped) return;
    window.clearTimeout(this.timer);
    if (this.controller) this.controller.abort();
    this.connect();
  }

  scheduleReconnect() {
    if (this.stopped) return;
    this.setState("reconnecting");
    const base = this.retryMs || this.backoffMs;
    const delay = base / 2 + Math.random() * (base / 2);  // jitter: spread reconnects of many tabs
    this.backoffMs = Math.min(this.backoffMs * 2, MAX_BACKOFF_MS);
    window.clearTimeout(this.timer);
    this.timer = window.setTimeout(() => this.connect(), delay);
  }

  async connect() {
    if (this.stopped) return;
    const controller = new AbortController();
    this.controller = controller;
    this.setState(this.state === "reconnecting" ? "reconnecting" : "connecting");
    const headers = { Accept: "text/event-stream" };
    if (this.lastEventId) headers["Last-Event-ID"] = this.lastEventId;
    let response;
    try {
      response = await fetch(this.url(), {
        headers,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
      });
    } catch {
      if (!controller.signal.aborted) this.scheduleReconnect();
      return;
    }
    if (response.status === 401) {
      this.recheckSession();
      return;
    }
    if (!response.ok || !response.body) {
      this.setState("error");
      this.scheduleReconnect();
      return;
    }
    this.setState("live");
    let delivered = false;
    try {
      delivered = await this.read(response.body, controller);
    } catch {
      /* the connection dropped; fall through to reconnect */
    }
    if (delivered) this.backoffMs = MIN_BACKOFF_MS;
    if (!controller.signal.aborted) this.scheduleReconnect();
  }

  async read(body, controller) {
    const reader = body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = "";
    let event = { type: "message", data: [], id: null };
    let delivered = false;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return delivered;
      buffer += value;
      if (buffer.length > MAX_BUFFER) {
        controller.abort();
        return delivered;
      }
      let match;
      while ((match = /\r\n|\r|\n/.exec(buffer)) !== null) {
        const line = buffer.slice(0, match.index);
        buffer = buffer.slice(match.index + match[0].length);
        if (line === "") {
          if (event.data.length) {
            if (event.id !== null) this.lastEventId = event.id;
            this.dispatch(event);
            delivered = true;
          } else if (event.id !== null) {
            this.lastEventId = event.id;
          }
          event = { type: "message", data: [], id: null };
          continue;
        }
        if (line.startsWith(":")) continue;  // a comment: the server's keepalive
        const colon = line.indexOf(":");
        const field = colon === -1 ? line : line.slice(0, colon);
        let text = colon === -1 ? "" : line.slice(colon + 1);
        if (text.startsWith(" ")) text = text.slice(1);
        if (field === "event") event.type = text || "message";
        else if (field === "data") event.data.push(text);
        else if (field === "id" && !text.includes("\0")) event.id = text;
        else if (field === "retry" && /^\d+$/.test(text)) this.retryMs = Math.min(Number(text), 5 * 60 * 1000);
      }
    }
  }

  dispatch(event) {
    if (event.type === "unauthorized") {
      // The server ended the stream for its session: check whether the session really ended (see above).
      this.recheckSession();
      return;
    }
    const raw = event.data.join("\n");
    let data = raw;
    try {
      data = JSON.parse(raw);
    } catch {
      /* not JSON: hand over the text */
    }
    if (event.type === "settings_changed" && data && Number.isInteger(data.config_version)) {
      // A reconnect then starts from the version this page has seen (functional-5).
      this.params = { ...this.params, config_version: String(data.config_version) };
    }
    this.onEvent({ type: event.type, data, id: this.lastEventId });
  }
}

const LIVE_TEXT = {
  off: "Live off",
  connecting: "Connecting",
  live: "Live",
  reconnecting: "Reconnecting",
  error: "Live paused",
  expired: "Signed out",
};

/** The page-wide stream: re-raises events on document and keeps the top bar's Live pill honest. */
export function initStream() {
  const url = document.body.dataset.streamUrl;
  const pill = qs("[data-live-indicator]");
  const setPill = (state) => {
    if (!pill) return;
    pill.dataset.state = state;
    const text = qs("[data-live-text]", pill);
    if (text) text.textContent = LIVE_TEXT[state] || state;
  };
  if (!url) {
    setPill("off");
    return null;
  }
  const stream = new EventStream(url, {
    onState: setPill,
    onEvent: (event) => {
      document.dispatchEvent(new CustomEvent("roxy:sse", { detail: event }));
      document.dispatchEvent(new CustomEvent(`roxy:sse:${event.type}`, { detail: event }));
    },
  });
  stream.start();
  // A fresh second factor in this tab or another rotated the session cookie: reconnect with it at once.
  document.addEventListener("roxy:session-rotated", () => stream.reconnectNow());
  return stream;
}
