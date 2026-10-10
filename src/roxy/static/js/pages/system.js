/**
 * The System page's own script (templates/admin/pages/system.html): open an error named in the address.
 *
 * What this is
 *   `/admin/system?signature=<text>` opens that error's details (its traceback) in the drawer as soon as the page has
 *   loaded, as a click on its row would. Everything else on the page (the tables, the reset dialog, the flush form,
 *   the lazy cards) is the shared design system and needs no page code.
 *
 * Why it exists
 *   A link to one error (from a recommendation's evidence, or one admin to another) should land on that error.
 *
 * How it works
 *   The signature is only ever a query value: it is bounded, put into the fragment URL with URLSearchParams (which
 *   encodes it), and the server looks it up as text. The drawer's title is fixed text, never the signature.
 *
 * What to read next
 *   static/js/page.js (the helpers every page module uses), roxy/admin/pages/system.py.
 */

import { openDrawerFrom, pageParams } from "roxy/page";

const MAX_SIGNATURE = 300;
const signature = (pageParams().get("signature") || "").slice(0, MAX_SIGNATURE);
if (signature.trim()) {
  const params = new URLSearchParams({ signature });
  openDrawerFrom(`/admin/system/fragment/errors?${params.toString()}`, "Error details", document.body);
}
