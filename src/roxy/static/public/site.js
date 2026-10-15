// Roxy public site script (plan 16.1): small progressive enhancements. Every page works without it.
//
// Loaded as <script type="module" nonce="..."> by templates/public/base.html, the only way a script may run under
// the strict CSP (plan 9.2). It never writes inline styles or HTML strings: it creates elements, sets text and
// toggles the `open` property of <details>, so it cannot introduce markup an attacker controls.
//
// 1. Copy buttons on every code block. The text is captured BEFORE the button is added (v1 once copied the
//    button label along with the code). Labels follow v1: Copy, Copied!, Error, back to Copy after 1.5 s. The
//    visible text is the button's accessible name (a fixed ARIA label would go stale), and the result is also
//    written to the page's one polite live region (#announcer in base.html), so screen readers announce it.
// 2. Collapsibles are native <details> elements. When the address points at something inside a closed one
//    (for example /#tokenSafetyHeading or /docs#4-limits), that section is opened so the target is visible.

const COPY_RESET_MS = 1500;
const announcer = document.getElementById("announcer");

function announce(message) {
	if (announcer) {
		announcer.textContent = message;
	}
}

function addCopyButtons() {
	for (const pre of document.querySelectorAll("main pre")) {
		const source = pre.querySelector("code") || pre;
		const text = source.textContent;
		const wrapper = document.createElement("div");
		wrapper.className = "code";
		const button = document.createElement("button");
		button.type = "button";
		button.className = "copy-button";
		button.textContent = "Copy";
		button.addEventListener("click", async () => {
			try {
				await navigator.clipboard.writeText(text);
				button.textContent = "Copied!";
				announce("Code copied to clipboard.");
			} catch (err) {
				console.error("Copy failed:", err);
				button.textContent = "Error";
				announce("Copy failed. Select the code and copy it by hand.");
			}
			setTimeout(() => {
				button.textContent = "Copy";
				announce(""); // cleared, so the same message is announced again on the next copy
			}, COPY_RESET_MS);
		});
		pre.replaceWith(wrapper);
		wrapper.append(pre, button);
	}
}

function openHashTarget() {
	let id = "";
	try {
		id = decodeURIComponent(window.location.hash.slice(1));
	} catch {
		return;
	}
	const target = id ? document.getElementById(id) : null;
	if (!target) {
		return;
	}
	let opened = false;
	for (let node = target; node; node = node.parentElement) {
		if (node.tagName === "DETAILS" && !node.open) {
			node.open = true;
			opened = true;
		}
	}
	if (opened) {
		target.scrollIntoView(); // the browser could not scroll to it while it was hidden
	}
}

addCopyButtons();
window.addEventListener("hashchange", openHashTarget);
openHashTarget();
