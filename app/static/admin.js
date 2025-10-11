const print = console.log;

// Elements
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));
const submitBtn = $("#submit");
const twofaModal = $("#twofaModal");
const twofaInput = $("#twofaInput");
const twofaSubmit = $("#twofaSubmit");
const twofaError = $("#twofaError");

// Modal helpers
function openModal() {
	twofaModal.classList.add("is-open");
	twofaModal.setAttribute("aria-hidden", "false");
	// focus 2FA input shortly after paint
	setTimeout(() => twofaInput?.focus(), 0);
	// basic focus trap
	document.addEventListener("keydown", trapTab);
}
function closeModal() {
	twofaModal.classList.remove("is-open");
	twofaModal.setAttribute("aria-hidden", "true");
	twofaError.hidden = true;
	twofaError.textContent = "";
	document.removeEventListener("keydown", trapTab);
}
function trapTab(e) {
	if (e.key !== "Tab") return;
	const focusables = $$(
		"button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])",
		twofaModal,
	).filter(el => !el.hasAttribute("disabled") && el.offsetParent !== null);
	if (focusables.length === 0) return;
	const first = focusables[0],
		last = focusables[focusables.length - 1];
	if (e.shiftKey && document.activeElement === first) {
		last.focus();
		e.preventDefault();
	} else if (!e.shiftKey && document.activeElement === last) {
		first.focus();
		e.preventDefault();
	}
}

// Dismiss actions
twofaModal.addEventListener("click", e => {
	if (e.target?.dataset?.close === "true") closeModal();
});
document.addEventListener("keydown", e => {
	if (e.key === "Escape" && twofaModal.classList.contains("is-open")) closeModal();
});

// Submit login → send IsLogin; open 2FA modal on success
submitBtn.addEventListener("click", async () => {
	const USERNAME = $("#username").value;
	const PASSWORD = $("#password").value;

	const FORM = { IsLogin: true, Username: USERNAME, Password: PASSWORD };

	try {
		const res = await fetch("/admin", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(FORM),
		});
		if (!res.ok) return; // optionally show error feedback here
		openModal();
	} catch (err) {}
});

// Verify 2FA from modal
twofaSubmit.addEventListener("click", async () => {
	const code = (twofaInput.value || "").trim();
	if (!/^[0-9]+$/.test(code)) {
		twofaError.hidden = false;
		twofaError.textContent = "Enter a valid code.";
		twofaInput.focus();
		return;
	}

	try {
		const res = await fetch("/admin", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ Is2FA: true, TwoFA: code }),
		});
		if (res.ok) {
			closeModal();
			window.location.href = "/admin/dashboard";
		} else {
			twofaError.hidden = false;
			twofaError.textContent = "Invalid or expired code. Try again.";
			twofaInput.select();
		}
	} catch (err) {
		twofaError.hidden = false;
		twofaError.textContent = "Network error. Check connection and retry.";
	}
});

// Optional: submit on Enter in the input
twofaInput.addEventListener("keydown", e => {
	if (e.key === "Enter") twofaSubmit.click();
});
