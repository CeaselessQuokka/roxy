/**
 * Dialogs, the details drawer, the phone bottom sheet, and dropdown menus.
 *
 * What this is
 *   `openDialog(idOrNode, opener)` and `closeDialog(node)` for every native <dialog> on the page, plus the click
 *   wiring: `data-dialog-open="id"` opens, `data-dialog-close` closes, a click on the dimmed backdrop closes, and
 *   `data-drawer-src="url"` opens the drawer and loads that fragment into it. `openDrawer(title, content)` shows
 *   content built in the browser (table row details). `initMenus()` makes <details data-menu> dropdowns close on
 *   Escape, on a click elsewhere, and when another menu opens.
 *
 * Why it exists
 *   A modal <dialog> opened with showModal() gives us the hard accessibility parts for free: focus moves into it,
 *   Tab stays inside, the rest of the page is inert, and Escape closes it. What the browser does not do is give
 *   focus back to the button that opened it, which keyboard users rely on (WCAG 2.4.3); that is done here.
 *
 * How it works
 *   The opener is remembered per dialog and refocused on the `close` event. Dialog forms posting with htmx
 *   (`data-dialog-form`) close after a 2xx answer and show the server's error text (as text, never HTML) after a
 *   failure, so the person can fix the input without losing it. The drawer loads its fragment with itself as the
 *   htmx source, so a failed load writes the error into the drawer instead of leaving "Loading" there.
 *   Opening a dialog closes the others (a sheet, the palette and a confirm dialog never stack), with one
 *   exception: the session-expired alert (`#session-expired`) opens ON TOP and closes nothing, so a half-written
 *   form underneath survives "Stay on this page"; while it is open no other dialog may open over it.
 *
 * What to read next
 *   templates/components/dialog.html, templates/admin/_layout/overlays.html, static/js/tables.js (drawer content).
 */

import htmx from "roxy/htmx_setup";
import { el, icon, qs, qsa } from "roxy/dom";
import { errorMessage, isReauthRequired } from "roxy/net";

const openers = new WeakMap();
const SESSION_DIALOG_ID = "session-expired";

function resolve(target) {
  return typeof target === "string" ? document.getElementById(target) : target;
}

/** True while the session-expired alert is showing (nothing else may open or take keys then). */
export function sessionOverlayOpen() {
  const overlay = document.getElementById(SESSION_DIALOG_ID);
  return Boolean(overlay && overlay.open);
}

export function openDialog(target, opener = document.activeElement) {
  const dialog = resolve(target);
  if (!dialog || typeof dialog.showModal !== "function") return null;
  if (dialog.open) return dialog;
  const isSessionOverlay = dialog.id === SESSION_DIALOG_ID;
  if (!isSessionOverlay && sessionOverlayOpen()) return null;
  // Only one menu sheet or palette at a time: close any other open modal first (they would stack). The session
  // alert is the exception: it stacks over whatever is open, so nothing the admin typed is thrown away.
  if (!isSessionOverlay) {
    for (const other of qsa("dialog[open]")) {
      if (other !== dialog && !other.contains(dialog)) other.close();
    }
  }
  for (const menu of qsa("details[data-menu][open]")) menu.open = false;
  openers.set(dialog, opener instanceof HTMLElement ? opener : null);
  dialog.showModal();
  const autofocus = dialog.querySelector("[autofocus], input:not([type=hidden]):not([disabled]), select, textarea");
  if (autofocus && !dialog.classList.contains("dialog--danger")) autofocus.focus();
  return dialog;
}

export function closeDialog(target) {
  const dialog = resolve(target);
  if (dialog && dialog.open) dialog.close();
}

/** Show browser-built content (a Node) in the drawer. */
export function openDrawer(title, content, opener) {
  const drawer = document.getElementById("drawer");
  if (!drawer) return;
  qs("#drawer-title", drawer).textContent = title || "Details";
  const body = qs("#drawer-body", drawer);
  body.replaceChildren(content);
  openDialog(drawer, opener);
}

/** Open the drawer and load a server fragment into it with htmx. */
export function openDrawerFrom(src, title, opener) {
  const drawer = document.getElementById("drawer");
  if (!drawer || !src) return;
  qs("#drawer-title", drawer).textContent = title || "Details";
  const body = qs("#drawer-body", drawer);
  body.replaceChildren(el("p", { class: "muted" }, [el("span", { class: "spinner", "aria-hidden": "true" }), " Loading"]));
  if (!openDialog(drawer, opener)) return;
  // The drawer body is the request's source too, so its errors are reported here (see drawerFailed below).
  htmx.ajax("GET", src, { source: body, target: body, swap: "innerHTML" });
}

function drawerFailed(body, xhr) {
  const status = xhr ? xhr.status : 0;
  let text;
  if (status === 0) text = "Roxy could not be reached, so the details could not be loaded.";
  else if (status === 401) text = "Your session ended, so the details could not be loaded.";
  else if (isReauthRequired(status, xhr.getResponseHeader("Roxy-Reauth"), xhr.responseText)) {
    text = "These details need your second factor again, so they could not be loaded.";
  } else text = `The details could not be loaded (${status}). ${errorMessage(xhr.responseText)}`.trim();
  body.replaceChildren(el("div", { class: "alert alert--bad", role: "alert" }, [
    el("span", { class: "alert__icon" }, [icon("alert-octagon")]),
    el("div", { class: "alert__text" }, [
      el("p", { class: "alert__title", text }),
      el("p", { class: "alert__body", text: "Close the details and open them again to retry." }),
    ]),
  ]));
}

export function initDialogs() {
  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;

    const opener = target.closest("[data-dialog-open]");
    if (opener) {
      event.preventDefault();
      openDialog(opener.dataset.dialogOpen, opener);
      return;
    }
    const closer = target.closest("[data-dialog-close]");
    if (closer) {
      closeDialog(closer.closest("dialog"));
      return;
    }
    // A click on the backdrop lands on the <dialog> element itself, outside its box.
    if (target.tagName === "DIALOG" && target.open) {
      const box = target.getBoundingClientRect();
      const inside = event.clientX >= box.left && event.clientX <= box.right && event.clientY >= box.top
        && event.clientY <= box.bottom;
      if (!inside && !target.matches(".session-expired")) target.close();
      return;
    }
    const drawerTrigger = target.closest("button[data-drawer-src], a[data-drawer-src]");
    if (drawerTrigger) {
      event.preventDefault();
      openDrawerFrom(drawerTrigger.dataset.drawerSrc, drawerTrigger.dataset.drawerTitle || drawerTrigger.textContent.trim(),
        drawerTrigger);
    }
  });

  // Give focus back to whatever opened the dialog (WCAG 2.4.3).
  document.addEventListener("close", (event) => {
    const dialog = event.target;
    if (!(dialog instanceof HTMLDialogElement)) return;
    const opener = openers.get(dialog);
    openers.delete(dialog);
    if (opener && opener.isConnected && opener !== document.body) {
      opener.focus();
    } else if (dialog.contains(document.activeElement)) {
      // Nothing to return to: never leave focus on a field inside a closed dialog (keys would go nowhere, and
      // the single-key shortcuts would think the admin is still typing).
      document.activeElement.blur();
    }
  }, true);

  document.addEventListener("htmx:afterRequest", (event) => {
    const elt = event.detail.elt instanceof Element ? event.detail.elt : null;
    if (elt && elt.id === "drawer-body") {
      if (!event.detail.successful) drawerFailed(elt, event.detail.xhr);
      return;
    }
    const form = elt ? elt.closest("form[data-dialog-form]") : null;
    if (!form) return;
    const error = qs("[data-dialog-error]", form);
    const xhr = event.detail.xhr;
    if (event.detail.successful) {
      if (error) error.hidden = true;
      form.reset();
      closeDialog(form.closest("dialog"));
    } else if (error && xhr && xhr.status !== 401) {
      let text;
      if (xhr.status === 0) text = "Roxy could not be reached. Nothing was changed; try again.";
      else if (isReauthRequired(xhr.status, xhr.getResponseHeader("Roxy-Reauth"), xhr.responseText)) {
        text = "This needs your second factor again: confirm it is you, then try again. Nothing was changed.";
      } else text = errorMessage(xhr.responseText) || `The server refused this (${xhr.status}). Nothing was changed.`;
      error.textContent = text;
      error.hidden = false;
    }
  });
}

export function initMenus() {
  const closeAll = (except) => {
    for (const menu of qsa("details[data-menu][open]")) if (menu !== except) menu.open = false;
  };
  document.addEventListener("toggle", (event) => {
    const menu = event.target;
    if (menu instanceof HTMLDetailsElement && menu.matches("[data-menu]") && menu.open) closeAll(menu);
  }, true);
  document.addEventListener("click", (event) => {
    const inside = event.target instanceof Element ? event.target.closest("details[data-menu]") : null;
    closeAll(inside);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || event.defaultPrevented) return;  // prevented: the Escape closed a tooltip
    const open = qs("details[data-menu][open]");
    if (open && !qs("dialog[open]")) {
      open.open = false;
      const summary = qs("summary", open);
      if (summary) summary.focus();
    }
  });
}
