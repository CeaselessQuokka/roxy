// Roxy admin login and authenticator enrollment (plan 9.5, owner decision D5).
//
// What this is: the browser side of templates/auth/login.html and templates/auth/enroll.html. Loaded as one
// module script carrying the page's CSP nonce; it adds every event listener itself, so the pages contain no
// inline script and no inline style (plan 9.2).
// How it works: the password step POSTs /admin/api/v1/auth/login. The answer is either "logged in" (a trusted
// device) or a short-lived login transaction plus the second factors this account can use. The second step
// POSTs /admin/api/v1/auth/mfa with the transaction and a code or a passkey answer. Every failed second factor
// gets the same 404 from the server, so this page shows one message for all of them. The enrollment page asks
// for a new authenticator secret, confirms it with the first code, then shows the 10 recovery codes once.
// What to read next: src/roxy/admin/auth/routes.py and src/roxy/admin/auth/flow.py.

const API = "/admin/api/v1/auth";

const MESSAGES = {
  missingFields: "Enter a username and password.",
  checking: "Checking…",
  login: "Login",
  invalidCredentials: "Invalid credentials.",
  tooMany: "Too many attempts; try again later.",
  mailFailed: "Could not send the 2FA email; try again shortly.",
  network: "Network error. Check your connection and retry.",
  invalidCode: "Enter a valid code.",
  verifying: "Verifying…",
  verify: "Verify",
  wrongCode: "Invalid or expired code. Try again.",
  networkShort: "Network error. Check connection and retry.",
  sending: "Sending…",
  resend: "Send a new code",
  resendFailed: "Could not send a new code. Start the login again.",
  codeExpired: "This code has expired; send a new one.",
  stepExpired: "This login step expired. Enter your password again.",
  passkeyFailed: "The passkey was not accepted. Try again or use another factor.",
  passkeyUnsupported: "This browser cannot use passkeys here.",
};

const HINTS = {
  totp: "Enter the 6-digit code from your authenticator app.",
  recovery: "Enter one of your recovery codes. Each one works only once.",
  email: "Enter the code sent to your admin email.",
  passkey: "Use your passkey: your device will ask for your fingerprint, face or PIN.",
};

const LABELS = { totp: "6-digit code", recovery: "Recovery code", email: "Emailed code", passkey: "Code" };

const PATTERNS = {
  totp: /^[0-9]{6}$/,
  email: /^[0-9]{6,20}$/,
  recovery: /^[0-9A-Za-z\- ]{16,24}$/,
};

function $(id) {
  return document.getElementById(id);
}

function show(element, visible) {
  if (element) element.hidden = !visible;
}

function setError(element, text) {
  if (!element) return;
  element.textContent = text || "";
  element.hidden = !text;
}

function csrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : null;
}

function updateCsrf(token) {
  if (!token) return;
  let meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta) {
    meta = document.createElement("meta");
    meta.setAttribute("name", "csrf-token");
    document.head.appendChild(meta);
  }
  meta.setAttribute("content", token);
}

// POST JSON and read the JSON answer. The server sends plain JSON strings for refusals (v1 wire form).
async function post(path, body) {
  const headers = { "Content-Type": "application/json", Accept: "application/json" };
  const token = csrfToken();
  if (token) headers["X-CSRF-Token"] = token;
  const response = await fetch(path, {
    method: "POST",
    headers,
    body: JSON.stringify(body || {}),
    credentials: "same-origin",
    cache: "no-store",
  });
  let data = null;
  try {
    data = await response.json();
  } catch (error) {
    data = null;
  }
  return { status: response.status, ok: response.ok, data };
}

function serverText(data, fallback) {
  if (typeof data === "string" && data) return data;
  if (data && typeof data.detail === "string") return data.detail;
  return fallback;
}

// ------------------------------------------------------------------------------------------- WebAuthn helpers

function fromBase64url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function toBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function passkeysSupported() {
  return typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

function requestOptions(options) {
  const publicKey = { ...options, challenge: fromBase64url(options.challenge) };
  if (Array.isArray(options.allowCredentials)) {
    publicKey.allowCredentials = options.allowCredentials.map((c) => ({ ...c, id: fromBase64url(c.id) }));
  }
  return publicKey;
}

function creationOptions(options) {
  const publicKey = {
    ...options,
    challenge: fromBase64url(options.challenge),
    user: { ...options.user, id: fromBase64url(options.user.id) },
  };
  if (Array.isArray(options.excludeCredentials)) {
    publicKey.excludeCredentials = options.excludeCredentials.map((c) => ({ ...c, id: fromBase64url(c.id) }));
  }
  return publicKey;
}

function credentialJson(credential) {
  if (typeof credential.toJSON === "function") return credential.toJSON();
  const response = credential.response;
  const json = {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    response: { clientDataJSON: toBase64url(response.clientDataJSON) },
  };
  if (response.attestationObject) {
    json.response.attestationObject = toBase64url(response.attestationObject);
    if (typeof response.getTransports === "function") json.response.transports = response.getTransports();
  } else {
    json.response.authenticatorData = toBase64url(response.authenticatorData);
    json.response.signature = toBase64url(response.signature);
    if (response.userHandle) json.response.userHandle = toBase64url(response.userHandle);
  }
  return json;
}

// ------------------------------------------------------------------------------------------- login page

function initLogin() {
  const loginForm = $("login-form");
  const loginError = $("login-error");
  const loginButton = $("login-submit");
  const mfa = $("mfa");
  const mfaForm = $("mfa-form");
  const mfaError = $("mfa-error");
  const mfaCode = $("mfa-code");
  const mfaButton = $("mfa-submit");
  const resendButton = $("mfa-resend");
  const passkeyButton = $("passkey-button");
  const countdown = $("mfa-countdown");
  const state = { transaction: null, methods: [], method: null, txTimer: null, codeTimer: null };

  function stopTimers() {
    window.clearInterval(state.txTimer);
    window.clearInterval(state.codeTimer);
    state.txTimer = null;
    state.codeTimer = null;
  }

  function backToPassword(message) {
    stopTimers();
    state.transaction = null;
    show(mfa, false);
    show(loginForm, true);
    setError(loginError, message || "");
    $("password").value = "";
    $("password").focus();
  }

  function startTransactionClock(seconds) {
    let left = seconds;
    window.clearInterval(state.txTimer);
    state.txTimer = window.setInterval(() => {
      left -= 1;
      if (left <= 0) backToPassword(MESSAGES.stepExpired);
    }, 1000);
  }

  function startCodeCountdown(seconds) {
    let left = seconds;
    window.clearInterval(state.codeTimer);
    countdown.classList.remove("is-expired");
    countdown.textContent = `Expires in ${left}s.`;
    state.codeTimer = window.setInterval(() => {
      left -= 1;
      if (left > 0) {
        countdown.textContent = `Expires in ${left}s.`;
      } else {
        window.clearInterval(state.codeTimer);
        countdown.textContent = MESSAGES.codeExpired;
        countdown.classList.add("is-expired");
      }
    }, 1000);
  }

  function chooseMethod(method) {
    state.method = method;
    $("mfa-hint").textContent = HINTS[method] || "";
    $("mfa-code-label").textContent = LABELS[method] || "Code";
    const usesCode = method !== "passkey";
    show($("mfa-code-group"), usesCode);
    show(mfaButton, usesCode);
    show(passkeyButton, method === "passkey");
    show(resendButton, method === "email");
    if (method !== "email") countdown.textContent = "";
    mfaCode.value = "";
    mfaCode.setAttribute("inputmode", method === "recovery" ? "text" : "numeric");
    setError(mfaError, "");
    const radio = $(`method-${method}`);
    if (radio) radio.checked = true;
    if (usesCode) mfaCode.focus();
  }

  function openMfa(data) {
    state.transaction = data.Transaction;
    state.methods = Array.isArray(data.Methods) ? data.Methods : [];
    show(loginForm, false);
    show(mfa, true);
    document.querySelectorAll("#mfa-methods [data-method]").forEach((row) => {
      row.hidden = !state.methods.includes(row.getAttribute("data-method"));
    });
    show($("mfa-methods"), state.methods.length > 1);
    const preferred = ["passkey", "totp", "email", "recovery"].find(
      (m) => state.methods.includes(m) && (m !== "passkey" || passkeysSupported()),
    );
    chooseMethod(preferred || state.methods[0] || "totp");
    startTransactionClock(Number(data.ExpiresIn) || 120);
    if (data.EmailExpiresIn) startCodeCountdown(Number(data.EmailExpiresIn));
    $("mfa-title").focus();
  }

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = $("username").value.trim();
    const password = $("password").value;
    if (!username || !password) {
      setError(loginError, MESSAGES.missingFields);
      return;
    }
    const trust = $("trust-device");
    loginButton.disabled = true;
    loginButton.textContent = MESSAGES.checking;
    setError(loginError, "");
    try {
      const result = await post(`${API}/login`, {
        username,
        password,
        trust_device: trust ? trust.checked : false,
      });
      if (result.ok && result.data && result.data.LoggedIn) {
        window.location.assign(result.data.Redirect || "/admin/dashboard");
        return;
      }
      if (result.ok && result.data && result.data.TwoFA) {
        openMfa(result.data);
        return;
      }
      if (result.status === 403) setError(loginError, MESSAGES.invalidCredentials);
      else if (result.status === 429) setError(loginError, serverText(result.data, MESSAGES.tooMany));
      else if (result.status === 503) setError(loginError, serverText(result.data, MESSAGES.mailFailed));
      else setError(loginError, `Login failed (${result.status}). Try again.`);
    } catch (error) {
      setError(loginError, MESSAGES.network);
    } finally {
      loginButton.disabled = false;
      loginButton.textContent = MESSAGES.login;
    }
  });

  document.querySelectorAll('input[name="mfa-method"]').forEach((radio) => {
    radio.addEventListener("change", () => chooseMethod(radio.value));
  });

  async function finish(result) {
    if (result.ok && result.data && result.data.LoggedIn) {
      stopTimers();
      window.location.assign(result.data.Redirect || "/admin/dashboard");
      return true;
    }
    if (result.status === 429) setError(mfaError, serverText(result.data, MESSAGES.tooMany));
    else setError(mfaError, MESSAGES.wrongCode);
    return false;
  }

  mfaForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.method === "passkey") return;
    const code = mfaCode.value.trim();
    const pattern = PATTERNS[state.method];
    if (!code || (pattern && !pattern.test(code))) {
      setError(mfaError, MESSAGES.invalidCode);
      return;
    }
    mfaButton.disabled = true;
    mfaButton.textContent = MESSAGES.verifying;
    setError(mfaError, "");
    try {
      const result = await post(`${API}/mfa`, { transaction: state.transaction, method: state.method, code });
      if (!(await finish(result))) mfaCode.select();
    } catch (error) {
      setError(mfaError, MESSAGES.networkShort);
    } finally {
      mfaButton.disabled = false;
      mfaButton.textContent = MESSAGES.verify;
    }
  });

  passkeyButton.addEventListener("click", async () => {
    if (!passkeysSupported()) {
      setError(mfaError, MESSAGES.passkeyUnsupported);
      return;
    }
    passkeyButton.disabled = true;
    setError(mfaError, "");
    try {
      const options = await post(`${API}/mfa/passkey/options`, { transaction: state.transaction });
      if (!options.ok || !options.data || !options.data.Options) {
        backToPassword(MESSAGES.stepExpired);
        return;
      }
      const credential = await navigator.credentials.get({ publicKey: requestOptions(options.data.Options) });
      const result = await post(`${API}/mfa`, {
        transaction: state.transaction,
        method: "passkey",
        credential: credentialJson(credential),
      });
      await finish(result);
    } catch (error) {
      setError(mfaError, MESSAGES.passkeyFailed);
    } finally {
      passkeyButton.disabled = false;
    }
  });

  resendButton.addEventListener("click", async () => {
    resendButton.disabled = true;
    resendButton.textContent = MESSAGES.sending;
    try {
      const result = await post(`${API}/mfa/email`, { transaction: state.transaction });
      if (result.ok) {
        setError(mfaError, "");
        mfaCode.value = "";
        startCodeCountdown(Number(result.data && result.data.ExpiresIn) || 300);
        mfaCode.focus();
      } else {
        setError(mfaError, serverText(result.data, MESSAGES.resendFailed));
      }
    } catch (error) {
      setError(mfaError, MESSAGES.network);
    } finally {
      resendButton.disabled = false;
      resendButton.textContent = MESSAGES.resend;
    }
  });

  $("mfa-cancel").addEventListener("click", () => backToPassword(""));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !mfa.hidden) backToPassword("");
  });
  $("username").focus();
}

// ------------------------------------------------------------------------------------------- enrollment page

function initEnroll() {
  const startButton = $("enroll-start-button");
  const form = $("enroll-form");
  const codeInput = $("enroll-code");
  const error = $("enroll-error");
  const status = $("enroll-status");

  startButton.addEventListener("click", async () => {
    startButton.disabled = true;
    setError($("enroll-start-error"), "");
    try {
      const result = await post(`${API}/totp/enroll/start`, {});
      if (!result.ok || !result.data) {
        setError($("enroll-start-error"), serverText(result.data, `Could not start (${result.status}).`));
        return;
      }
      $("enroll-qr").src = result.data.Qr;
      $("enroll-secret").textContent = result.data.Secret.replace(/(.{4})/g, "$1 ").trim();
      show($("enroll-start"), false);
      show($("enroll-scan"), true);
      $("enroll-scan-title").focus();
    } catch (err) {
      setError($("enroll-start-error"), MESSAGES.network);
    } finally {
      startButton.disabled = false;
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = codeInput.value.trim();
    if (!PATTERNS.totp.test(code)) {
      setError(error, MESSAGES.invalidCode);
      return;
    }
    $("enroll-confirm").disabled = true;
    setError(error, "");
    try {
      const result = await post(`${API}/totp/enroll/confirm`, { code });
      if (!result.ok || !result.data) {
        setError(error, result.status === 404 ? MESSAGES.wrongCode : serverText(result.data, MESSAGES.wrongCode));
        codeInput.select();
        return;
      }
      updateCsrf(result.data.CsrfToken);
      const list = $("recovery-list");
      list.textContent = "";
      (result.data.RecoveryCodes || []).forEach((code) => {
        const item = document.createElement("li");
        item.textContent = code;
        list.appendChild(item);
      });
      show($("enroll-scan"), false);
      show($("enroll-codes"), true);
      $("enroll-codes-title").focus();
    } catch (err) {
      setError(error, MESSAGES.network);
    } finally {
      $("enroll-confirm").disabled = false;
    }
  });

  $("codes-copy").addEventListener("click", async () => {
    const codes = Array.from(document.querySelectorAll("#recovery-list li")).map((li) => li.textContent);
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      status.textContent = "Copied. Paste them somewhere safe now.";
    } catch (err) {
      status.textContent = "Copying is not allowed here; select the codes and copy them by hand.";
    }
  });

  $("passkey-add").addEventListener("click", async () => {
    if (!passkeysSupported()) {
      status.textContent = MESSAGES.passkeyUnsupported;
      return;
    }
    $("passkey-add").disabled = true;
    try {
      const options = await post(`${API}/passkeys/register/options`, {});
      if (!options.ok || !options.data) {
        status.textContent = serverText(options.data, "Could not start adding a passkey.");
        return;
      }
      const credential = await navigator.credentials.create({ publicKey: creationOptions(options.data.Options) });
      const result = await post(`${API}/passkeys/register/verify`, {
        credential: credentialJson(credential),
        name: "Passkey",
      });
      status.textContent = result.ok ? "Passkey added." : serverText(result.data, "The passkey could not be added.");
    } catch (err) {
      status.textContent = "Adding the passkey was canceled or failed.";
    } finally {
      $("passkey-add").disabled = false;
    }
  });
}

function boot() {
  const page = document.body.dataset.page;
  if (page === "login") initLogin();
  else if (page === "enroll") initEnroll();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot, { once: true });
else boot();
