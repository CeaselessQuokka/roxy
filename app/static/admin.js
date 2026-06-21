const print = console.log;

// Elements
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));
const loginForm = $("#loginForm");
const submitBtn = $("#submit");
const loginError = $("#loginError");
const twofaModal = $("#twofaModal");
const twofaInput = $("#twofaInput");
const twofaSubmit = $("#twofaSubmit");
const twofaError = $("#twofaError");

// Modal helpers
function openModal() {
	twofaModal.classList.add("is-open");
	twofaModal.setAttribute("aria-hidden", "false");
	twofaInput.value = "";
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

function showLoginError(msg) {
	loginError.hidden = false;
	loginError.textContent = msg;
}
function clearLoginError() {
	loginError.hidden = true;
	loginError.textContent = "";
}
function setBusy(btn, busy, busyText, idleText) {
	btn.disabled = busy;
	btn.textContent = busy ? busyText : idleText;
}

// Read the server's response body (it sends JSON-encoded strings); fall back to a default.
async function readMessage(res, fallback) {
	try {
		const data = await res.json();
		if (typeof data === "string" && data) return data;
	} catch {}
	return fallback;
}

// Dismiss actions
twofaModal.addEventListener("click", e => {
	if (e.target?.dataset?.close === "true") closeModal();
});
document.addEventListener("keydown", e => {
	if (e.key === "Escape" && twofaModal.classList.contains("is-open")) closeModal();
});

// Submit login → send IsLogin; open 2FA modal on success
loginForm.addEventListener("submit", async e => {
	e.preventDefault();
	if (submitBtn.disabled) return; // already in flight
	clearLoginError();

	const USERNAME = $("#username").value;
	const PASSWORD = $("#password").value;
	if (!USERNAME || !PASSWORD) {
		showLoginError("Enter a username and password.");
		return;
	}

	const FORM = {
		IsLogin: true,
		Username: USERNAME,
		Password: PASSWORD,
		TrustDevice: $("#trustDevice")?.checked || false,
	};
	setBusy(submitBtn, true, "Checking…", "Login");
	try {
		const res = await fetch("/admin", {
			method: "POST",
			headers: { "Content-Type": "application/json", Accept: "application/json" },
			body: JSON.stringify(FORM),
		});
		if (res.ok) {
			const data = await res.json().catch(() => ({}));
			if (data && data.LoggedIn) {
				// Trusted device: 2FA was skipped, go straight to the dashboard.
				window.location.href = "/admin/dashboard";
			} else {
				openModal();
			}
		} else if (res.status === 403) {
			showLoginError("Invalid credentials.");
		} else if (res.status === 429) {
			showLoginError(await readMessage(res, "Too many attempts; try again later."));
		} else if (res.status === 503) {
			showLoginError(await readMessage(res, "Could not send the 2FA email; try again shortly."));
		} else {
			showLoginError(`Login failed (${res.status}). Try again.`);
		}
	} catch (err) {
		showLoginError("Network error. Check your connection and retry.");
	} finally {
		setBusy(submitBtn, false, "Checking…", "Login");
	}
});

// Verify 2FA from modal
twofaSubmit.addEventListener("click", async () => {
	if (twofaSubmit.disabled) return;
	const code = (twofaInput.value || "").trim();
	if (!/^[0-9]+$/.test(code)) {
		twofaError.hidden = false;
		twofaError.textContent = "Enter a valid code.";
		twofaInput.focus();
		return;
	}

	setBusy(twofaSubmit, true, "Verifying…", "Verify");
	try {
		const res = await fetch("/admin", {
			method: "POST",
			headers: { "Content-Type": "application/json", Accept: "application/json" },
			body: JSON.stringify({ Is2FA: true, TwoFA: code }),
		});
		if (res.ok) {
			closeModal();
			window.location.href = "/admin/dashboard";
			return;
		}
		twofaError.hidden = false;
		if (res.status === 429) {
			twofaError.textContent = await readMessage(res, "Too many attempts; try again later.");
		} else {
			twofaError.textContent = "Invalid or expired code. Try again.";
		}
		twofaInput.select();
	} catch (err) {
		twofaError.hidden = false;
		twofaError.textContent = "Network error. Check connection and retry.";
	} finally {
		setBusy(twofaSubmit, false, "Verifying…", "Verify");
	}
});

// Submit on Enter in the 2FA input
twofaInput.addEventListener("keydown", e => {
	if (e.key === "Enter") {
		e.preventDefault();
		twofaSubmit.click();
	}
});
