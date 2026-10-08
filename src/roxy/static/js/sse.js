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
 *   connection has delivered events. A 401 raises `roxy:unauthorized` and stops for good; this traffic never counts
 *   as session activity on the server (plan 9.6).
 *
 * What to read next
 *   static/js/live_tail.js (the main consumer), roxy/admin/sse.py (the server side, P11 part two).
 */

import { qs } from "roxy/dom";
import { signalUnauthorized } from "roxy/net";

const MAX_BUFFER = 1024 * 1024;
const MIN_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;

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
      this.stopped = true;
      this.setState("expired");
      signalUnauthorized("sse");
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
    const raw = event.data.join("\n");
    let data = raw;
    try {
      data = JSON.parse(raw);
    } catch {
      /* not JSON: hand over the text */
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
  return stream;
}
