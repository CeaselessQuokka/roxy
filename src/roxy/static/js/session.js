/**
 * Session presence: the activity heartbeat, the session-expired overlay, and logout (plan 9.6, parity rows 98, 119).
 *
 * What this is
 *   `initSession()` starts the heartbeat, listens for `roxy:unauthorized`, and wires the logout forms;
 *   `expireSession()` shows the session-expired dialog and then goes to the login page.
 *
 * Why it exists
 *   Plan 9.6: a session stays alive only while someone is really using the dashboard. A heartbeat is sent every
 *   `admin_heartbeat_interval_s` seconds ONLY if there was pointer or keyboard input in the last
 *   `admin_activity_window_s` seconds; live updates, automatic refreshes and an unattended open tab never extend
 *   the session, so a forgotten tab expires on time. v1 sent a heartbeat whenever the page was visible, which kept
 *   unattended sessions alive forever (v1 notes, dashboard section 2.3).
 *
 * How it works
 *   Input listeners (pointer down and move, keys, wheel, touch) only record a monotonic timestamp
 *   (performance.now, which never jumps when the wall clock is adjusted). A timer ticks and posts to the heartbeat
 *   URL (with the CSRF header) only when the last input is recent enough. It ticks every heartbeat interval, or
 *   every activity window when that is shorter: the server extends the session only for input inside the window,
 *   so with an interval longer than the window, input between two ticks would otherwise never be reported.
 *   Any 401, from the heartbeat or from any other request (net.js and htmx_setup.js raise `roxy:unauthorized`, the
 *   SSE client too), opens the alertdialog with "Log in again" focused and a 5 second countdown to the login page.
 *   "Stay on this page", or Escape, cancels the countdown (WCAG 2.2.1). The alert opens on top of any open dialog
 *   without closing it (dialog.js), so text typed there can still be copied. The intervals come from data
 *   attributes on <body>, rendered from the live settings, so changing a setting changes the browser's behavior on
 *   the next page load.
 *   Logout is a POST with the CSRF header (a plain form cannot send headers). Only an answer that ends the session
 *   (2xx, or 401 when it had already ended) leads to the login page; any other answer, or no answer, keeps the
 *   page and says the admin is still signed in, so nobody walks away believing they logged out.
 *
 * What to read next
 *   templates/admin/_layout/overlays.html (the dialog), roxy/admin/auth/sessions.py (the server side, P8).
 */

import { leaveOnPurpose, qs } from "roxy/dom";
import { openDialog } from "roxy/dialog";
import { postJSON, request } from "roxy/net";
import { toast } from "roxy/toast";

const REDIRECT_SECONDS = 5;

let lastInputAt = -Infinity;
let expired = false;
let stayed = false;
let countdownTimer = 0;
let heartbeatTimer = 0;

function config() {
  const data = document.body.dataset;
  const seconds = (value, fallback) => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  };
  return {
    heartbeatMs: seconds(data.heartbeatS, 30) * 1000,
    windowMs: seconds(data.activityWindowS, 60) * 1000,
    heartbeatUrl: data.heartbeatUrl || "",
    loginUrl: data.loginUrl || "/admin",
  };
}

function noteInput() {
  lastInputAt = performance.now();
}

async function beat(cfg) {
  if (expired || !cfg.heartbeatUrl) return;
  const idleMs = Math.round(performance.now() - lastInputAt);
  if (!(idleMs <= cfg.windowMs)) return;  // nobody is here: let the idle timeout run
  try {
    // The server checks idle_ms against the window again (it never trusts the browser alone).
    await postJSON(cfg.heartbeatUrl, { idle_ms: idleMs });  // a 401 raises roxy:unauthorized inside request()
  } catch {
    /* a network hiccup is not an expiry; the next tick tries again */
  }
}

function goToLogin(url) {
  leaveOnPurpose();  // the session is over: the "unsaved changes" question would only get in the way
  window.location.assign(url);
}

export function expireSession() {
  if (expired && stayed) {
    // The admin chose to stay once; show the dialog again without a countdown.
    const dialog = document.getElementById("session-expired");
    if (dialog && !dialog.open) openDialog(dialog);
    return;
  }
  if (expired) return;
  expired = true;
  window.clearInterval(heartbeatTimer);
  document.body.dataset.session = "expired";
  const cfg = config();
  const dialog = document.getElementById("session-expired");
  if (!dialog) {
    goToLogin(cfg.loginUrl);
    return;
  }
  openDialog(dialog);
  const login = qs("[data-session-login]", dialog);
  if (login) login.focus();
  const count = qs("[data-session-countdown]", dialog);
  let left = REDIRECT_SECONDS;
  const render = () => {
    if (count) count.textContent = `Going to the login page in ${left} second${left === 1 ? "" : "s"}.`;
  };
  render();
  countdownTimer = window.setInterval(() => {
    left -= 1;
    if (left <= 0) {
      window.clearInterval(countdownTimer);
      goToLogin(cfg.loginUrl);
      return;
    }
    render();
  }, 1000);
}

function stay() {
  stayed = true;
  window.clearInterval(countdownTimer);
  const dialog = document.getElementById("session-expired");
  const count = dialog ? qs("[data-session-countdown]", dialog) : null;
  if (count) count.textContent = "Staying on this page. Log in again when you are ready.";
  if (dialog && dialog.open) dialog.close();
}

async function logout(form, cfg) {
  let response = null;
  try {
    response = await request(form.action, { method: "POST" });
  } catch {
    response = null;  // no answer at all: the session may still be alive
  }
  if (response && (response.ok || response.status === 401)) {
    expired = true;
    window.clearInterval(heartbeatTimer);
    window.clearInterval(countdownTimer);
    goToLogin(cfg.loginUrl);
    return;
  }
  const why = response ? `the server answered ${response.status}` : "Roxy could not be reached";
  toast(`Logging out did not work (${why}). You are still signed in; try again.`, { tone: "bad" });
}

export function initSession() {
  const cfg = config();
  const options = { capture: true, passive: true };
  for (const type of ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"]) {
    window.addEventListener(type, noteInput, options);
  }
  // Tick at the shorter of the two settings (see "How it works").
  heartbeatTimer = window.setInterval(() => beat(cfg), Math.min(cfg.heartbeatMs, cfg.windowMs));
  document.addEventListener("roxy:unauthorized", expireSession);
  document.addEventListener("click", (event) => {
    if (event.target instanceof Element && event.target.closest("[data-session-stay]")) stay();
  });
  // Escape on the alert is a request to dismiss it: the same as "Stay on this page" (the countdown stops).
  const overlay = document.getElementById("session-expired");
  if (overlay) overlay.addEventListener("cancel", () => stay());
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("[data-logout]")) return;
    event.preventDefault();
    logout(form, cfg);
  });
}
