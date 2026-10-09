/**
 * Live tail: a virtualized, pausable, filterable list of requests as they happen (plan 14.5, 14.11).
 *
 * What this is
 *   `initLiveTails(root)` turns every `[data-live-tail]` (templates/components/live_tail.html) into a live list fed
 *   by its own EventStream (static/js/sse.js). Each event is one request (the plan 4.8 row 126 fields: request id,
 *   time, status, outcome, reason, egress, cache state, latency, client, method and endpoint).
 *
 * Why it exists
 *   A busy proxy produces hundreds of rows a second. Creating a DOM node per row would freeze the page, so only
 *   the rows inside the visible window (plus a small margin) exist, recycled from a pool, positioned with CSS
 *   transforms set through the CSSOM (allowed by the CSP, unlike inline style attributes). Memory is bounded:
 *   at most `data-max-rows` rows (default 1000) and the same number waiting while paused; older ones are dropped
 *   and counted (plan P9).
 *
 * How it works
 *   Pausing: the Pause button (aria-pressed), the P key inside the tail, or simply hovering the list (so a row
 *   does not move under the pointer). Paused events wait in a bounded buffer and join on resume. Filters apply
 *   instantly in the browser and are also sent to the server as stream parameters (the server samples above 50
 *   events a second, plan 14.11). Each new set of parameters means a new stream connection, so typed filters
 *   reach the server only once typing pauses for 400 ms (a select applies at once). Keyboard: Up and Down move a
 *   roving focus between rows, Home and End jump, and Enter opens the request's details in the drawer (from
 *   `data-detail-url`, or from the row's own fields). Screen readers hear a polite summary at most every 10
 *   seconds, never every row (plan 14.9).
 *   Teardown: a tail that leaves the page (an htmx swap, or any removal, which its ResizeObserver reports) stops
 *   its stream, its announce timer and its observer; otherwise it would keep a server connection open forever.
 *
 * What to read next
 *   static/js/sse.js, roxy/metrics/live.py (the server side, P7), roxy/admin/sse.py (P11 part two).
 */

import { el, qs, qsa, rafThrottle } from "roxy/dom";
import { EventStream } from "roxy/sse";
import { openDrawer, openDrawerFrom } from "roxy/dialog";
import { fmtNumber, fmtTime } from "roxy/format";

const ANNOUNCE_EVERY_MS = 10000;
const FILTER_DEBOUNCE_MS = 400;
const OVERSCAN = 6;
const OUTCOME_WORDS = {
  served_upstream: "Served by Roblox",
  served_cache: "Served from cache",
  refused: "Refused",
  failed: "Failed",
};

function statusTone(status) {
  if (status >= 500) return "bad";
  if (status === 429 || status >= 400) return "warn";
  if (status >= 300) return "muted";
  return "ok";
}

function normalize(raw) {
  const data = typeof raw === "object" && raw !== null ? raw : {};
  const at = Number(data.t ?? (data.at_ms ? data.at_ms / 1000 : Date.now() / 1000));
  return {
    id: String(data.id ?? data.request_id ?? ""),
    t: at,
    status: Number(data.status ?? 0),
    outcome: String(data.outcome ?? ""),
    reason: String(data.reason ?? ""),
    egress: String(data.egress ?? ""),
    cache: String(data.cache ?? data.cache_state ?? ""),
    latency: Number(data.latency_ms ?? data.latency ?? 0),
    client: String(data.client ?? data.client_ip ?? ""),
    place: String(data.place ?? data.place_id ?? ""),
    method: String(data.method ?? "GET"),
    endpoint: String(data.endpoint ?? data.path ?? ""),
  };
}

class LiveTail {
  constructor(root) {
    this.root = root;
    this.viewport = qs("[data-tail-viewport]", root);
    this.spacer = qs("[data-tail-spacer]", root);
    this.empty = qs("[data-tail-empty]", root);
    this.stateLabel = qs("[data-tail-state]", root);
    this.countLabel = qs("[data-tail-count]", root);
    this.pauseButton = qs("[data-tail-pause]", root);
    this.announcer = qs("[data-tail-announce]", root);
    this.maxRows = Math.max(50, Number(root.dataset.maxRows) || 1000);
    this.detailUrl = root.dataset.detailUrl || "";
    this.rows = [];  // newest first
    this.waiting = [];
    this.dropped = 0;
    this.newSinceAnnounce = 0;
    this.filters = {};
    this.visible = [];
    this.pool = [];
    this.active = -1;
    this.pausedByButton = false;
    this.pausedByHover = false;
    this.connection = "connecting";
    this.rowHeight = 34;
    this.render = rafThrottle(() => this.draw());
    this.paramsTimer = 0;
    this.destroyed = false;
    this.gap = false;  // a reconnect could not replay every missed request (the server's `gap` event)

    this.stream = new EventStream(root.dataset.streamUrl, {
      onEvent: (event) => {
        if (event.type === "live" || event.type === "message") this.add(normalize(event.data));
        else if (event.type === "gap") this.markGap();
      },
      onState: (state) => {
        this.connection = state;
        this.updateState();
      },
    });
    this.bind();
    this.stream.start();
    this.announceTimer = window.setInterval(() => this.announce(), ANNOUNCE_EVERY_MS);
    this.updateState();
  }

  get paused() {
    return this.pausedByButton || this.pausedByHover;
  }

  bind() {
    this.viewport.addEventListener("scroll", () => this.render(), { passive: true });
    this.viewport.addEventListener("pointerenter", () => this.setHoverPause(true));
    this.viewport.addEventListener("pointerleave", () => this.setHoverPause(false));
    this.viewport.addEventListener("keydown", (event) => this.onKey(event));
    this.viewport.addEventListener("click", (event) => {
      const row = event.target instanceof Element ? event.target.closest(".tail__row") : null;
      if (row) this.open(Number(row.dataset.index), row);
    });
    if (this.pauseButton) this.pauseButton.addEventListener("click", () => this.togglePause());
    const clear = qs("[data-tail-clear]", this.root);
    if (clear) {
      clear.addEventListener("click", () => {
        this.rows = [];
        this.waiting = [];
        this.dropped = 0;
        this.gap = false;
        this.active = -1;
        this.draw();
        this.updateState();
      });
    }
    for (const input of qsa("[data-tail-filter]", this.root)) {
      const typed = input.tagName !== "SELECT";
      input.addEventListener(typed ? "input" : "change", () => this.readFilters(typed));
    }
    this.root.addEventListener("keydown", (event) => {
      if (event.key.toLowerCase() === "p" && !event.ctrlKey && !event.metaKey && !event.altKey
          && !(event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement)) {
        event.preventDefault();
        this.togglePause();
      }
    });
    this.observer = new ResizeObserver(() => {
      if (!this.root.isConnected) this.destroy();  // observers also fire when the element leaves the document
      else this.render();
    });
    this.observer.observe(this.viewport);
  }

  /** Filters apply to the list at once; the server hears about typed text once typing pauses (one reconnect). */
  readFilters(debounce = false) {
    const filters = {};
    for (const input of qsa("[data-tail-filter]", this.root)) {
      const value = input.value.trim();
      if (value) filters[input.dataset.tailFilter] = value;
    }
    this.filters = filters;
    window.clearTimeout(this.paramsTimer);
    if (debounce) this.paramsTimer = window.setTimeout(() => this.stream.setParams(this.filters), FILTER_DEBOUNCE_MS);
    else this.stream.setParams(filters);
    this.active = -1;
    this.draw();
  }

  /** Stop everything that would outlive the element: the stream, the timers and the observer. */
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    this.stream.stop();
    window.clearInterval(this.announceTimer);
    window.clearTimeout(this.paramsTimer);
    if (this.observer) this.observer.disconnect();
    if (tails.get(this.root) === this) tails.delete(this.root);
  }

  matches(row) {
    const f = this.filters;
    if (f.outcome && row.outcome !== f.outcome) return false;
    if (f.egress && row.egress !== f.egress) return false;
    if (f.cache && row.cache.toUpperCase() !== f.cache) return false;
    if (f.status) {
      if (/^\dxx$/.test(f.status)) {
        if (Math.floor(row.status / 100) !== Number(f.status[0])) return false;
      } else if (String(row.status) !== f.status) {
        return false;
      }
    }
    if (f.client && !(`${row.client} ${row.place}`.toLowerCase().includes(f.client.toLowerCase()))) return false;
    if (f.endpoint && !row.endpoint.toLowerCase().includes(f.endpoint.toLowerCase())) return false;
    return true;
  }

  add(row) {
    if (this.paused) {
      this.waiting.unshift(row);
      if (this.waiting.length > this.maxRows) {
        this.waiting.length = this.maxRows;
        this.dropped += 1;
      }
      this.updateState();
      return;
    }
    row.fresh = true;
    this.rows.unshift(row);
    if (this.rows.length > this.maxRows) this.rows.length = this.maxRows;
    if (this.active >= 0) this.active += 1;  // keep the focused row under the cursor as new rows arrive on top
    this.newSinceAnnounce += 1;
    this.render();
    this.updateState();
  }

  setHoverPause(on) {
    this.pausedByHover = on;
    if (!this.paused) this.flush();
    this.updateState();
  }

  togglePause() {
    this.pausedByButton = !this.pausedByButton;
    if (this.pauseButton) {
      this.pauseButton.setAttribute("aria-pressed", String(this.pausedByButton));
      const label = qs("span", this.pauseButton);
      if (label) label.textContent = this.pausedByButton ? "Resume" : "Pause";
    }
    if (!this.paused) this.flush();
    this.updateState();
  }

  flush() {
    if (!this.waiting.length) return;
    this.rows = this.waiting.concat(this.rows).slice(0, this.maxRows);
    this.newSinceAnnounce += this.waiting.length;
    this.waiting = [];
    this.render();
  }

  updateState() {
    let state = "live";
    let text = "Live";
    if (this.connection === "connecting") [state, text] = ["connecting", "Connecting"];
    else if (this.connection === "reconnecting" || this.connection === "error") [state, text] = ["error", "Reconnecting"];
    else if (this.connection === "expired") [state, text] = ["error", "Signed out"];
    if (this.pausedByButton) [state, text] = ["paused", "Paused"];
    else if (this.pausedByHover) [state, text] = ["paused", "Paused while the pointer is over the list"];
    this.root.dataset.state = state;
    if (this.stateLabel && this.stateLabel.textContent !== text) this.stateLabel.textContent = text;
    if (this.countLabel) {
      let count = `${fmtNumber(this.rows.length)} row${this.rows.length === 1 ? "" : "s"}`;
      if (this.waiting.length) count += `, ${fmtNumber(this.waiting.length)} waiting`;
      if (this.dropped) count += `, ${fmtNumber(this.dropped)} dropped`;
      if (this.gap) count += ", some missed while reconnecting";
      this.countLabel.textContent = count;
    }
  }

  /** The server could not replay everything missed during a reconnect: say so instead of implying a full list. */
  markGap() {
    this.gap = true;
    this.updateState();
  }

  announce() {
    if (!this.announcer || this.paused || this.newSinceAnnounce === 0) return;
    const n = this.newSinceAnnounce;
    this.newSinceAnnounce = 0;
    this.announcer.textContent = `${fmtNumber(n)} new request${n === 1 ? "" : "s"}`;
  }

  measure() {
    const probe = this.pool[0];
    if (probe && probe.offsetHeight) this.rowHeight = probe.offsetHeight;
  }

  buildRow() {
    const row = el("div", { class: "tail__row", role: "listitem", tabindex: "-1" });
    for (const name of ["time", "status", "outcome", "egress", "cache", "latency num", "client", "endpoint"]) {
      row.append(el("span", { class: name.split(" ").map((part, i) => (i === 0 ? `tail__${part}` : part)).join(" ") }));
    }
    return row;
  }

  fill(node, row, index) {
    const [time, status, outcome, egress, cache, latency, client, endpoint] = node.children;
    node.dataset.index = String(index);
    time.textContent = fmtTime(row.t);
    status.textContent = row.status ? String(row.status) : "n/a";
    status.className = `tail__status tone--${statusTone(row.status)}`;
    outcome.textContent = OUTCOME_WORDS[row.outcome] || row.outcome || "n/a";
    outcome.title = row.reason;
    egress.textContent = row.egress || "n/a";
    cache.textContent = row.cache || "n/a";
    latency.textContent = `${fmtNumber(row.latency)} ms`;
    client.textContent = row.place ? `${row.client} (${row.place})` : row.client;
    endpoint.textContent = `${row.method} ${row.endpoint}`;
    node.classList.toggle("is-active", index === this.active);
    node.classList.toggle("is-new", Boolean(row.fresh));
    row.fresh = false;
    node.setAttribute("aria-label", `${time.textContent}, status ${status.textContent}, ${outcome.textContent}, ${endpoint.textContent}`);
    node.style.transform = `translateY(${index * this.rowHeight}px)`;
  }

  draw() {
    this.visible = this.rows.filter((row) => this.matches(row));
    const total = this.visible.length;
    if (this.empty) this.empty.hidden = total > 0;
    if (total > 0 && !this.spacer.getAttribute("role")) {
      this.spacer.setAttribute("role", "list");
      this.spacer.setAttribute("aria-label", this.spacer.dataset.listLabel || "Requests");
    }
    this.spacer.style.height = `${total * this.rowHeight}px`;
    const first = Math.max(0, Math.floor(this.viewport.scrollTop / this.rowHeight) - OVERSCAN);
    const count = Math.ceil(this.viewport.clientHeight / this.rowHeight) + OVERSCAN * 2;
    const last = Math.min(total, first + count);
    while (this.pool.length < last - first) {
      const node = this.buildRow();
      this.pool.push(node);
      this.spacer.append(node);
    }
    this.pool.forEach((node, i) => {
      const index = first + i;
      if (index < last) {
        node.hidden = false;
        this.fill(node, this.visible[index], index);
      } else {
        node.hidden = true;
      }
    });
    this.measure();
  }

  nodeFor(index) {
    return this.pool.find((node) => !node.hidden && Number(node.dataset.index) === index) || null;
  }

  focusRow(index) {
    if (!this.visible.length) return;
    this.active = Math.min(Math.max(index, 0), this.visible.length - 1);
    const top = this.active * this.rowHeight;
    if (top < this.viewport.scrollTop) this.viewport.scrollTop = top;
    else if (top + this.rowHeight > this.viewport.scrollTop + this.viewport.clientHeight) {
      this.viewport.scrollTop = top + this.rowHeight - this.viewport.clientHeight;
    }
    this.draw();
    const node = this.nodeFor(this.active);
    if (node) node.focus({ preventScroll: true });
  }

  onKey(event) {
    const keys = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10 };
    if (event.key in keys) {
      event.preventDefault();
      this.focusRow((this.active < 0 ? -1 : this.active) + keys[event.key]);
    } else if (event.key === "Home") {
      event.preventDefault();
      this.focusRow(0);
    } else if (event.key === "End") {
      event.preventDefault();
      this.focusRow(this.visible.length - 1);
    } else if (event.key === "Enter" && this.active >= 0) {
      event.preventDefault();
      this.open(this.active, this.nodeFor(this.active));
    }
  }

  open(index, opener) {
    const row = this.visible[index];
    if (!row) return;
    this.active = index;
    const title = `${row.method} ${row.endpoint}`;
    if (this.detailUrl && row.id) {
      openDrawerFrom(this.detailUrl.replace("{id}", encodeURIComponent(row.id)), title, opener);
      return;
    }
    const list = el("dl", { class: "kv" });
    const fields = [
      ["Request id", row.id || "n/a"], ["Time", fmtTime(row.t, { withDay: true })], ["Status", row.status],
      ["Outcome", OUTCOME_WORDS[row.outcome] || row.outcome], ["Reason", row.reason || "n/a"],
      ["Egress", row.egress || "n/a"], ["Cache", row.cache || "n/a"], ["Latency", `${fmtNumber(row.latency)} ms`],
      ["Client", row.client || "n/a"], ["Place", row.place || "n/a"], ["Endpoint", `${row.method} ${row.endpoint}`],
    ];
    for (const [name, value] of fields) list.append(el("dt", { text: name }), el("dd", { text: value }));
    openDrawer(title, list, opener);
  }
}

const tails = new WeakMap();
let cleanupListener = false;

export function initLiveTails(root = document) {
  const nodes = root instanceof Element && root.matches("[data-live-tail]") ? [root] : qsa("[data-live-tail]", root);
  for (const node of nodes) {
    if (!tails.has(node) && node.dataset.streamUrl) tails.set(node, new LiveTail(node));
  }
  if (!cleanupListener) {
    cleanupListener = true;
    // htmx raises this on every element of the content it is about to remove.
    document.addEventListener("htmx:beforeCleanupElement", (event) => {
      const tail = event.target instanceof Element ? tails.get(event.target) : null;
      if (tail) tail.destroy();
    });
  }
}
