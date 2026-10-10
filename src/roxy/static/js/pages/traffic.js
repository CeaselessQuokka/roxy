/**
 * The Traffic page's own script (templates/admin/pages/traffic.html): load the cards below the first one, one at a
 * time, once the page is idle.
 *
 * What this is
 *   Six of the seven cards are lazy (`@page.card(..., lazy=True)`): the first paint carries only the requests chart,
 *   and each other card is a placeholder that asks its own fragment when it scrolls into view. On this page the
 *   admin almost always scrolls through every chart, so once the page is idle this script asks for the next
 *   placeholder that has not loaded yet, waits for that answer, and moves on to the next one.
 *
 * Why it exists
 *   Plan 6.7 and the P11 page rules: a fast first paint (one card), and no burst of six fragment requests at once on
 *   the 1 GB server. Loading the cards one by one in the background also means a card is usually ready before the
 *   admin reaches it, and a jump to a card far down the page (the browser's find, a link to `#latency`, a test
 *   that scrolls straight to the end) never leaves the cards it skipped as placeholders forever: htmx reveals only
 *   the cards inside the window when scrolling stops.
 *
 * How it works
 *   A placeholder is `section.page-card--lazy` with `hx-trigger="revealed"`. This script marks it the way htmx marks
 *   a revealed element (`data-hx-revealed`, so a scroll cannot ask a second time) and raises the `revealed` event
 *   on it, which is what htmx's trigger listens for. It waits for that request to finish (`htmx:afterRequest` on the
 *   card itself, answered or not) and for a short pause before the next card; a hidden tab waits until it is shown
 *   again. A
 *   card that failed to load stays a placeholder with its own message; nothing here builds markup.
 *
 * What to read next
 *   templates/admin/pages/_card_lazy.html (the placeholder), static/js/cards.js, roxy/admin/pages/traffic.py.
 */

const PAUSE_MS = 120;
const FIRST_DELAY_MS = 300;
const MAX_WAIT_MS = 15000;

function nextPlaceholder() {
  return document.querySelector("section.page-card--lazy:not([data-hx-revealed])");
}

function loadOne(card) {
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve();
    };
    // On the card itself: the answer replaces the card (outerHTML), and an event raised on an element that has
    // left the document never bubbles up to `document`.
    card.addEventListener("htmx:afterRequest", finish, { once: true });
    window.setTimeout(finish, MAX_WAIT_MS);  // never wait forever on one card
    card.setAttribute("data-hx-revealed", "true");
    card.dispatchEvent(new CustomEvent("revealed"));
  });
}

function whenVisible() {
  if (!document.hidden) return Promise.resolve();
  return new Promise((resolve) => {
    const onChange = () => {
      if (document.hidden) return;
      document.removeEventListener("visibilitychange", onChange);
      resolve();
    };
    document.addEventListener("visibilitychange", onChange);
  });
}

async function loadAll() {
  for (;;) {
    await whenVisible();
    const card = nextPlaceholder();
    if (!card) return;
    await loadOne(card);
    await new Promise((resolve) => window.setTimeout(resolve, PAUSE_MS));
  }
}

window.setTimeout(() => {
  loadAll();
}, FIRST_DELAY_MS);
