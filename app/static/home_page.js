/* =========================================================
   Roxy Proxy Homepage JS
   - Handles collapsible example sections
   - Adds copy buttons for code examples
   - Maintains accessibility (aria-expanded, focus states)
   ========================================================= */

(() => {
	const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

	// ---- COLLAPSIBLES ----
	function setupCollapsibles() {
		$$(".collapsible-toggle").forEach(btn => {
			btn.addEventListener("click", () => {
				const targetId = btn.dataset.target;
				const section = document.getElementById(targetId);
				if (!section) return;
				const isOpen = section.classList.toggle("is-open");
				btn.textContent = isOpen ? "Collapse" : "Expand";
				btn.setAttribute("aria-expanded", String(isOpen));
			});
		});
	}

	// ---- COPY BUTTONS FOR CODE BLOCKS ----
	function setupCopyButtons() {
		$$("pre.example, pre.output").forEach(block => {
			// Capture the snippet BEFORE the button is added, rather than slicing
			// the button's label back off afterwards: that slice assumed the label
			// was always exactly "Copy", so clicking again while it read "Copied!"
			// silently handed over a truncated snippet.
			const code = block.textContent;

			const button = document.createElement("button");
			button.className = "btn btn--tonal copy-btn";
			button.textContent = "Copy";
			button.setAttribute("aria-label", "Copy code to clipboard");
			block.style.position = "relative";
			block.appendChild(button);

			button.addEventListener("click", async () => {
				try {
					await navigator.clipboard.writeText(code);
					button.textContent = "Copied!";
					setTimeout(() => (button.textContent = "Copy"), 1500);
				} catch (err) {
					console.error("Copy failed:", err);
					button.textContent = "Error";
					setTimeout(() => (button.textContent = "Copy"), 1500);
				}
			});
		});
	}

	// ---- SMOOTH SCROLL TO ANCHORS ----
	function setupSmoothScroll() {
		$$('a[href^="#"]').forEach(link => {
			link.addEventListener("click", e => {
				const id = link.getAttribute("href").substring(1);
				const target = document.getElementById(id);
				if (!target) return;
				e.preventDefault();
				target.scrollIntoView({ behavior: "smooth", block: "start" });
				history.replaceState(null, "", `#${id}`);
			});
		});
	}

	// ---- ON LOAD ----
	document.addEventListener("DOMContentLoaded", () => {
		setupCollapsibles();
		setupCopyButtons();
		setupSmoothScroll();
	});
})();
