"use strict";
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();

// --- theme toggle (localStorage holds only "light"/"dark") ---
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("zp.theme", t); } catch { /* private mode: session-only */ }
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = t === "light" ? "#a78bfa" : "#1c1917";
  // hljs ships two palettes; the right one gets media="all", the other drops out
  for (const el of [{ id: "hljs-light", theme: "light" }, { id: "hljs-dark", theme: "dark" }]) {
    const link = document.getElementById(el.id);
    if (link) link.media = el.theme === t ? "all" : "not all";
  }
}
const savedTheme = (() => {
  try { return localStorage.getItem("zp.theme"); } catch { return null; }
})();
applyTheme(savedTheme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
$("theme").addEventListener("click", () =>
  applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light"));

// --- base64url helpers ---
function b64uFromBytes(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function bytesFromB64u(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
const PBKDF2_ITERATIONS = 600000; // OWASP recommendation for PBKDF2-HMAC-SHA256

async function randomKey() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return { key: await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]), keyB64: b64uFromBytes(raw) };
}

async function deriveKey(passphrase, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function seal(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text)));
  return b64uFromBytes(new Uint8Array([...iv, ...ct]));
}

async function open_(payloadB64, key) {
  const buf = bytesFromB64u(payloadB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, key, buf.slice(12));
  return dec.decode(pt);
}

function show(id) {
  for (const s of ["gate", "compose", "linkbox", "read"]) $(s).classList.toggle("hidden", s !== id);
  window.scrollTo(0, 0);
}

async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn.classList.contains("copybtn")) {
      const old = btn.innerHTML;
      btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      btn.classList.add("copied");
      setTimeout(() => { btn.innerHTML = old; btn.classList.remove("copied"); }, 1200);
    } else {
      const old = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = old), 1200);
    }
  } catch { /* unsupported: user selects manually */ }
}

// --- compose flow ---
const burnOn = () => $("burn").getAttribute("aria-pressed") === "true";
$("burn").addEventListener("click", () =>
  $("burn").setAttribute("aria-pressed", burnOn() ? "false" : "true"));

// create-gate passphrase: revealed only when the server answers 401;
// kept in sessionStorage (per tab), never localStorage, never a cookie.
async function createPaste(text) {
  const pass = $("pass").value;
  let payload, salt = "", keyB64 = "";
  if (pass) {
    const s = crypto.getRandomValues(new Uint8Array(16));
    salt = b64uFromBytes(s);
    payload = await seal(await deriveKey(pass, s), text);
  } else {
    const k = await randomKey();
    payload = await seal(k.key, text);
    keyB64 = k.keyB64;
  }
  const siteKey = sessionStorage.getItem("zp.siteKey") || "";
  const res = await fetch("/api/paste", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(siteKey ? { Authorization: "Bearer " + siteKey } : {}) },
    body: JSON.stringify({ data: payload, salt, ttl: $("ttl").value, hl: true, burn: burnOn() }),
  });
  if (res.status === 401) {
    // stale or hand-forged site key: force the gate screen again
    sessionStorage.removeItem("zp.siteKey");
    show("gate");
    $("gateerr").textContent = "Site passphrase was rejected — unlock again.";
    $("gateerr").classList.remove("hidden");
    throw { silent: true };
  }
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
  return { id: (await res.json()).id, keyB64, pass };
}

$("create").addEventListener("click", async () => {
  const text = $("text").value;
  if (!text) { $("text").focus(); return; }
  $("create").disabled = true;
  try {
    const out = await createPaste(text);
    const link = location.origin + "/p/" + out.id + (out.keyB64 ? "#" + out.keyB64 : "");
    $("share").value = link;
    $("passnote").classList.toggle("hidden", !out.pass);
    drawQR(link);
    $("composeerr").classList.add("hidden");
    show("linkbox");
  } catch (e) {
    if (e && e.silent) return; // already routed to the gate screen
    const box = $("composeerr");
    box.textContent = (e && e.message ? e.message : "Failed to create paste.");
    box.classList.remove("hidden");
  } finally {
    $("create").disabled = false;
  }
});

// gate screen: shown before the app when this instance has a create gate;
// unlocking is verified against POST /api/gate, then kept per tab (sessionStorage).
async function gateFlow() {
  try {
    const { enabled } = await (await fetch("/api/gate")).json();
    if (!enabled) return show("compose");
    const stored = sessionStorage.getItem("zp.siteKey") || "";
    const unlock = async (key) => {
      const res = await fetch("/api/gate", { method: "POST", headers: { Authorization: "Bearer " + key } });
      if (res.status === 204) {
        sessionStorage.setItem("zp.siteKey", key);
        $("create").disabled = false;
        show("compose");
        return;
      }
      sessionStorage.removeItem("zp.siteKey");
      $("gateerr").textContent = "Wrong passphrase.";
      $("gateerr").classList.remove("hidden");
      $("gatepass").value = "";
      $("gatepass").select();
    };
    $("gatebtn").addEventListener("click", () => unlock($("gatepass").value));
    $("gatepass").addEventListener("keydown", (e) => { if (e.key === "Enter") unlock($("gatepass").value); });
    if (stored) {
      const res = await fetch("/api/gate", { method: "POST", headers: { Authorization: "Bearer " + stored } });
      if (res.status === 204) return show("compose");
      $("gateerr").textContent = "Wrong passphrase.";
      $("gateerr").classList.remove("hidden");
      $("gatepass").value = "";
      $("gatepass").select();
      return show("gate");
    }
    return show("gate");
  } catch {
    return show("compose"); // server unreachable; let the submit path handle errors
  }
}

function drawQR(text) {
  const box = $("qr");
  box.textContent = "";
  if (typeof qrcode !== "function") return;
  const qr = qrcode(0, "M"); // type 0 = auto size, M = medium error correction
  qr.addData(text);
  qr.make();
  box.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0 });
}
// the link itself is the affordance: tap it to copy
$("share").addEventListener("click", () => copy($("share").value, $("copylink")));
$("copylink").addEventListener("click", () => copy($("share").value, $("copylink")));
$("again").addEventListener("click", () => {
  $("text").value = ""; $("burn").setAttribute("aria-pressed", "false"); $("pass").value = "";
  $("composeerr").classList.add("hidden");
  show("compose"); $("text").focus();
});
$("text").addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") $("create").click(); });

// --- read flow ---
async function fetchPaste() {
  const m = location.pathname.match(/^\/p\/([A-Za-z0-9_-]+)$/);
  if (!m) throw { code: "incomplete", message: "Invalid paste link." };
  const res = await fetch(`/api/paste/${m[1]}`);
  if (res.status === 404) throw { code: "gone", message: "This paste is gone — it was burned after reading, or it expired." };
  if (!res.ok) throw { code: "server", message: "Server error: " + res.statusText };
  return { id: m[1], ...(await res.json()) };
}

function renderPaste(paste, text) {
  $("pasteview").textContent = text;
  if (paste.hl && window.hljs) hljs.highlightElement($("pasteview"));
  $("expiresnote").textContent = paste.expires ? expiresIn(paste.expires) : "";
  if (paste.burn) {
    $("burnnote").textContent = "This paste was burned — the link is now dead.";
    fetch(`/api/paste/${paste.id}`, { method: "DELETE" }).catch(() => {});
  }
  $("unlock").classList.add("hidden");
  $("readbody").classList.remove("hidden");
}

function expiresIn(unixSec) {
  const ms = unixSec * 1000 - Date.now();
  if (!(ms > 0)) return "already expired — refresh to confirm";
  const min = Math.max(1, Math.round(ms / 60000));
  if (min < 60) return `expires in ${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `expires in ${h} h`;
  return `expires in ${Math.round(h / 24)} d`;
}

async function readView() {
  show("read");
  const fail = (msg) => { $("readbody").classList.add("hidden"); $("unlock").classList.add("hidden"); $("readerr").classList.remove("hidden"); $("readerr").textContent = msg; };
  let paste;
  try {
    paste = await fetchPaste();
  } catch (e) {
    return fail(e.message);
  }

  if (paste.salt) {
    // passphrase-protected: key derived locally from passphrase + stored salt
    const unlock = async () => {
      $("unlockerr").classList.add("hidden");
      try {
        const key = await deriveKey($("unlockpass").value, bytesFromB64u(paste.salt));
        renderPaste(paste, await open_(paste.data, key));
      } catch {
        $("unlockerr").textContent = "Wrong passphrase.";
        $("unlockerr").classList.remove("hidden");
        $("unlockpass").select();
      }
    };
    $("unlockbtn").addEventListener("click", unlock);
    $("unlockpass").addEventListener("keydown", (e) => { if (e.key === "Enter") unlock(); });
    $("unlock").classList.remove("hidden");
    $("unlockpass").focus();
    return;
  }

  const keyB64 = location.hash.slice(1);
  if (!keyB64) return fail("This link is incomplete — it needs the secret part after #.");
  try {
    const key = await crypto.subtle.importKey("raw", bytesFromB64u(keyB64), "AES-GCM", false, ["decrypt"]);
    const text = await open_(paste.data, key);
    history.replaceState(null, "", location.pathname); // strip key from address bar after use
    renderPaste(paste, text);
  } catch {
    fail("Decryption failed — the link was probably altered or truncated.");
  }
}

// quick-start popover copy buttons (popover itself opens with zero JS)
document.querySelectorAll("[data-copy]").forEach((btn) => {
  const src = document.getElementById(btn.getAttribute("data-copy"));
  if (src) btn.addEventListener("click", () => copy(src.textContent, btn));
});

$("copytext").addEventListener("click", () => copy($("pasteview").textContent, $("copytext")));

if (location.pathname.startsWith("/p/")) {
  readView();
} else {
  gateFlow();
}
