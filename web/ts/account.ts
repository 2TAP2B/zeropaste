import { $ } from "./dom";
import { b64uFromBytes, bytesFromB64u, deriveKey, seal } from "./crypto";
import { humanSize, copy } from "./ui";

// Passkey account flows + the active-shares dashboard, both passkey-only.
// Anonymous behavior is untouched; login exists purely for the dashboard.
// The header icon button opens the #accpanel popover (zero JS to open).

interface MeRec {
  name?: string;
  id?: string;
  accounts?: boolean; // false = this instance has USER_ACCOUNTS off
  open?: boolean;
  passkeys?: string[]; // credential ids of the signed-in identity
}

interface ShareRow {
  id: string;
  kind: "text" | "bundle";
  burn: boolean;
  expires: number;
  views?: number;
}

// fragment stash: create flow stores <id> -> key fragment client-side so the
// dashboard re-opens shares. Deliberately client-side only - the
// zero-knowledge mandate protects the server boundary, not the local disk
// (same threat model as browser history).
function fragGet(id: string): string {
  try {
    return localStorage.getItem("zp.frag." + id) ?? "";
  } catch {
    return "";
  }
}

function fragPut(id: string, keyB64: string): void {
  try {
    localStorage.setItem("zp.frag." + id, keyB64);
  } catch {
    /* private mode */
  }
}

export function stashForCreate(id: string, keyB64: string): void {
  if (keyB64) fragPut(id, keyB64);
}

function dropFrags(): void {
  try {
    const doomed: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith("zp.frag.")) doomed.push(k);
    }
    for (const k of doomed) localStorage.removeItem(k);
  } catch {
    /* private mode */
  }
}

function expiryText(unixSec: number): string {
  const ms = unixSec * 1000 - Date.now();
  if (!(ms > 0)) return "already expired";
  const min = Math.round(ms / 60000);
  if (min < 60) return `in ${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `in ${h} h`;
  return `in ${Math.round(h / 24)} d`;
}

export async function refreshMe(): Promise<void> {
  try {
    const res = await fetch("/api/me");
    const me = (await res.json()) as MeRec;
    const reg = $("regbtn") as HTMLButtonElement;
    const login = $("loginbtn") as HTMLButtonElement;
    const poll = $("accpoll") as HTMLElement;

    signedIn = !!me.name;
    // USER_ACCOUNTS=false: the whole identity feature is off - the account
    // button and pane go away entirely (the /dash card adapts in loadDash)
    const accountsOff = me.accounts === false;
    ($("accbtn") as HTMLButtonElement).classList.toggle("hidden", accountsOff);
    if (accountsOff) {
      poll.textContent = "accounts are disabled on this instance";
      reg.disabled = true;
      login.disabled = true;
      return; // the button is hidden; nothing else in the pane matters
    }
    // IP hosts cannot hold passkeys: the browser needs a domain RP ID and the
    // server config rejects IPs, so 127.0.0.1 and LAN addresses get the hint
    const host = location.hostname;
    const isIPHost =
      /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ||
      host.startsWith("[") || // bracketed IPv6
      (/^[0-9a-f:]+$/i.test(host) && host.includes(":")); // bare IPv6 like ::1
    const insecure =
      isIPHost ||
      (!window.isSecureContext && host !== "localhost" && !host.endsWith(".localhost"));
    ($("browserhint") as HTMLElement).textContent = isIPHost
      ? "Passkeys don't work on an IP address - open the site over its real domain."
      : "Passkeys need HTTPS (or localhost). You are on an insecure origin - open the site over its real domain.";
    ($("browserhint") as HTMLElement).classList.toggle("hidden", !insecure);
    if (insecure) {
      reg.disabled = true;
      login.disabled = true;
      poll.textContent = "passkeys need HTTPS (or localhost)";
      $("accanon").classList.remove("hidden");
      $("accuser").classList.add("hidden");
      return;
    }
    reg.disabled = false;
    login.disabled = false;
    if (signedIn) {
      // registered view: identity line + dashboard/sign-out + attach row;
      // the whole groups swap keeps the pane a simple two-state surface
      $("accanon").classList.add("hidden");
      $("accuser").classList.remove("hidden");
      poll.classList.add("hidden");
      ($("accwhoname") as HTMLElement).textContent = me.name ?? "";
    } else {
      $("accuser").classList.add("hidden");
      $("accanon").classList.remove("hidden");
      poll.classList.remove("hidden");
      const open = me.open !== false;
      poll.textContent = open ? "create an account - passkey only" : "sign in - new registrations are closed";
      $("reggroup").classList.toggle("hidden", !open);
      $("accor").classList.toggle("hidden", !open); // no choice to divide when only sign-in remains
    }
  } catch {
    /* server unreachable: leave the pane as configured */
  }
}

function accError(msg: string): void {
  const err = $("accerr");
  err.textContent = msg;
  err.classList.remove("hidden");
}

// --- webauthn plumbing ---
// go-webauthn emits CredentialCreation/CredentialRequest JSON whose challenge
// and user id are base64url strings; the browser wants ArrayBuffers.

interface CeremonyShape {
  publicKey?: Record<string, unknown>;
  rp?: { id?: string; name?: string };
  user?: { id?: string; name?: string; displayName?: string };
  challenge?: string;
  pubKeyCredParams?: unknown[];
  timeout?: number;
  excludeCredentials?: Array<{ id?: string }>;
  authenticatorSelection?: unknown;
  attestation?: string;
  userVerification?: string;
}

function creationToPublicKey(options: unknown): PublicKeyCredentialCreationOptions {
  const pk = unwrapPublicKey(options);
  return {
    challenge: bytesFromB64u(pk.challenge ?? ""),
    rp: { id: pk.rp?.id ?? "", name: pk.rp?.name ?? "" },
    user: {
      id: bytesFromB64u(pk.user?.id ?? ""),
      name: pk.user?.name ?? "",
      displayName: pk.user?.displayName ?? (pk.user?.name ?? ""),
    },
    pubKeyCredParams: (pk.pubKeyCredParams ?? [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ]) as PublicKeyCredentialParameters[],
    timeout: pk.timeout ?? 60000,
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({
      id: bytesFromB64u(c.id ?? ""),
      type: "public-key" as PublicKeyCredentialType,
    })),
    authenticatorSelection: (pk.authenticatorSelection ?? {
      residentKey: "preferred",
      userVerification: "preferred",
    }) as AuthenticatorSelectionCriteria,
    attestation: (pk.attestation ?? "none") as AttestationConveyancePreference,
  };
}

function assertionToPublicKey(options: unknown): PublicKeyCredentialRequestOptions {
  const pk = unwrapPublicKey(options);
  return {
    challenge: bytesFromB64u(pk.challenge ?? ""),
    timeout: pk.timeout ?? 60000,
    userVerification: (pk.userVerification ?? "preferred") as UserVerificationRequirement,
  };
}

function unwrapPublicKey(options: unknown): CeremonyShape {
  const shape = (options ?? {}) as CeremonyShape;
  return (shape.publicKey ?? shape) as CeremonyShape;
}

function attestationBody(c: PublicKeyCredential, sessionId: string): string {
  const res = c.response as AuthenticatorAttestationResponse;
  return JSON.stringify({
    sessionId,
    id: c.id,
    rawId: arrayB64u(c.rawId),
    type: "public-key", // the server-side parser rejects bodies without it
    response: {
      attestationObject: arrayB64u(res.attestationObject),
      clientDataJSON: arrayB64u(res.clientDataJSON),
    },
  });
}

function assertionBody(c: PublicKeyCredential, sessionId: string): string {
  const res = c.response as AuthenticatorAssertionResponse;
  return JSON.stringify({
    sessionId,
    id: c.id,
    rawId: arrayB64u(c.rawId),
    type: "public-key",
    response: {
      authenticatorData: arrayB64u(res.authenticatorData),
      clientDataJSON: arrayB64u(res.clientDataJSON),
      signature: arrayB64u(res.signature),
      userHandle: res.userHandle ? arrayB64u(res.userHandle) : "",
    },
  });
}

function arrayB64u(v: ArrayBuffer | Uint8Array): string {
  return b64uFromBytes(new Uint8Array(v));
}

export async function registerStart(): Promise<void> {
  ($("accerr") as HTMLElement).classList.add("hidden");
  try {
    const name = ($("accname") as HTMLInputElement).value;
    const res = await fetch("/api/identity/register/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) {
      throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "register begin failed");
    }
    const { options, sessionId } = (await res.json()) as { options: unknown; sessionId: string };
    const cred = (await navigator.credentials.create({ publicKey: creationToPublicKey(options) })) as PublicKeyCredential;
    const fin = await fetch("/api/identity/register/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: attestationBody(cred, sessionId),
    });
    if (!fin.ok) {
      throw new Error(((await fin.json().catch(() => ({}))) as { error?: string }).error ?? "registration failed");
    }
    ($("accerr") as HTMLElement).classList.add("hidden");
    await refreshMe();
  } catch (e) {
    accError(e instanceof Error ? e.message : "registration failed");
  }
}

export async function loginStart(): Promise<boolean> {
  ($("accerr") as HTMLElement).classList.add("hidden");
  try {
    const res = await fetch("/api/identity/login/begin", { method: "POST" });
    if (!res.ok) {
      throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "login begin failed");
    }
    const { options, sessionId } = (await res.json()) as { options: unknown; sessionId: string };
    const cred = (await navigator.credentials.get({ publicKey: assertionToPublicKey(options) })) as PublicKeyCredential | null;
    if (!cred) throw new Error("no credential returned");
    const fin = await fetch("/api/identity/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: assertionBody(cred, sessionId),
    });
    if (!fin.ok) {
      throw new Error(((await fin.json().catch(() => ({}))) as { error?: string }).error ?? "login failed");
    }
    ($("accerr") as HTMLElement).classList.add("hidden");
    await refreshMe();
    return true;
  } catch (e) {
    accError(e instanceof Error ? e.message : "login failed");
    return false;
  }
}

export async function logout(): Promise<void> {
  await fetch("/api/identity/logout", { method: "POST" }).catch(() => {});
  dropFrags();
  await refreshMe();
}

export async function bootAccount(): Promise<void> {
  $("regbtn").addEventListener("click", () => void registerStart());
  $("attachbtn").addEventListener("click", () => void registerStart()); // signed-in: attach another key
  // signing in from the lightbox: straight to the dashboard, no lingering panel
  $("loginbtn").addEventListener("click", () => {
    void loginStart().then((ok) => {
      if (!ok) return; // accError already surfaced the problem
      (document.getElementById("accpanel") as HTMLDivElement).hidePopover();
      location.href = "/dash";
    });
  });
  $("logoutbtn").addEventListener("click", () => void logout());
  // the header button: signed-in users land on /dash (this refreshes the row
  // list); anonymous visitors get the identity popover
  $("accbtn").addEventListener("click", () => {
    if (signedIn) {
      location.href = "/dash";
      return;
    }
    (document.getElementById("accpanel") as HTMLDivElement).showPopover();
  });
  // statistics refresh whenever the lightbox opens or closes
  const panel = $("accpanel") as HTMLElement;
  panel.addEventListener("toggle", () => {
    if ((panel as HTMLElement & { open: boolean }).open) void refreshMe();
  });
  await refreshMe();
}

let signedIn = false;

// --- the dashboard page (/dash) ---
// Reuses the standard header/footer/popovers: the compose cards are hidden,
// #dashroot renders rows plus the identity edit. Anonymous visitors get a
// sign-in card instead of an empty page.

function shareURL(r: ShareRow): string {
  return location.origin + "/p/" + r.id + (fragGet(r.id) ? "#" + fragGet(r.id) : "");
}

function dashTab(which: string): void {
  for (const b of document.querySelectorAll("#dashtabs .dashtab")) {
    b.classList.toggle("active", (b as HTMLElement).dataset.tab === which);
  }
  for (const pane of ["pane-shares", "pane-reverse", "pane-account"]) {
    $(pane).classList.toggle("hidden", pane !== "pane-" + which);
  }
  try {
    localStorage.setItem("zp.tab", which);
  } catch {
    /* private mode */
  }
}

export async function dashboardPage(): Promise<void> {
  $("gate").classList.add("hidden");
  $("compose").classList.add("hidden");
  $("linkbox").classList.add("hidden");
  $("read").classList.add("hidden");
  $("dashroot").classList.remove("hidden");

  // persisted dashboard tab (default shares; holdings tab view choice)
  let tab = "shares";
  try {
    const saved = localStorage.getItem("zp.tab");
    if (saved === "shares" || saved === "reverse" || saved === "account") tab = saved;
  } catch {
    /* private mode */
  }
  dashTab(tab);
  for (const b of document.querySelectorAll("#dashtabs .dashtab")) {
    (b as HTMLElement).addEventListener("click", () => dashTab((b as HTMLElement).dataset.tab ?? "shares"));
  }

  $("dashsave").addEventListener("click", () => void saveName());
  $("dashreg").addEventListener("click", () => {
    (document.getElementById("dashreg") as HTMLButtonElement).disabled = true;
    registerStart()
      .then(() => void loadDash())
      .catch((e) => dashError(e instanceof Error ? e.message : "failed"));
  });
  $("dashlogout").addEventListener("click", async () => {
    await logout();
    location.reload(); // land on the anonymous dashboard
  });
  $("dashlogin").addEventListener("click", () => {
    // errors must land in #dasherr (the accpanel is closed on /dash);
    // registerStart swallows into accError, so mirror the failed state here
    void loginStart().then((ok) => {
      if (ok) return void loadDash();
      dashError("sign in failed - check the passkey dialog and try again");
    });
  });

  // reverse shares: create + rows (uplinks carry the key in the fragment, so
  // the stash is what lets this browser open and read the arriving files)
  $("revform").addEventListener("submit", (e) => {
    e.preventDefault();
    void (async () => {
      const btn = $("revcreate") as HTMLButtonElement;
      btn.disabled = true;
      try {
        const slug = ($("revslug") as HTMLInputElement).value.trim().toLowerCase();
        const ttl = ($("revttl") as HTMLInputElement).value.trim();
        const mb = Number(($("revsize") as HTMLInputElement).value);
        const pass = ($("revpass") as HTMLInputElement).value;
        let salt = "";
        let check = "";
        let keyB64 = "";
        if (pass) {
          // passphrase uplink: the server stores the public salt + a sealed
          // verifier; the passphrase itself never leaves this tab
          salt = b64uFromBytes(crypto.getRandomValues(new Uint8Array(16)));
          const key = await deriveKey(pass, bytesFromB64u(salt));
          check = await seal(key, "zeropaste-rshare");
        } else {
          keyB64 = freshKeyB64(); // fragment mode: the uplink rides the key
        }
        const res = await fetch("/api/rshare", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ slug, ttl, maxSize: Math.round(mb * 1024 * 1024), salt, check }),
        });
        if (!res.ok) {
          throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "create failed");
        }
        if (keyB64) fragPut("rv:" + slug, keyB64); // fragment mode only
        ($("revslug") as HTMLInputElement).value = "";
        ($("revpass") as HTMLInputElement).value = "";
        await renderRshares();
      } catch (e) {
        dashError(e instanceof Error ? e.message : "create failed");
      } finally {
        btn.disabled = false;
      }
    })();
  });

  await loadDash();
}

async function saveName(): Promise<void> {
  try {
    const res = await fetch("/api/identity/name", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: ($("dashname") as HTMLInputElement).value }),
    });
    if (!res.ok) {
      throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "name save failed");
    }
    ($("dasherr") as HTMLElement).classList.add("hidden");
    await loadDash();
  } catch (e) {
    dashError(e instanceof Error ? e.message : "name save failed");
  }
}

function dashError(msg: string): void {
  const err = $("dasherr");
  err.textContent = msg;
  err.classList.remove("hidden");
}

// uplink keys: 32 fresh bytes, base64url - same shape as paste fragments
function freshKeyB64(): string {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  let s = "";
  for (const b of raw) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface RevRow {
  slug: string;
  maxSize: number;
  expires: number;
  uploads: number;
  bytes: number;
  pass?: boolean; // passphrase uplink: bare links, no stashed fragment
  items: { id: string; size: number; created: number }[];
}

// inline icon snippets (static strings only; never user data)
const IC = {
  chev: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>',
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>',
  open: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>',
  del: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>',
};

function iconBtn(aria: string, svg: string, cls = "rowicon"): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = cls;
  b.setAttribute("aria-label", aria);
  b.title = aria;
  b.innerHTML = svg; // static icon markup only
  return b;
}

async function renderRshares(): Promise<void> {
  const box = $("revlist") as HTMLElement;
  box.textContent = "";
  const res = await fetch("/api/rshares");
  if (!res.ok) return;
  const rows = (await res.json()) as RevRow[];
  if (rows.length === 0) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = "No reverse shares yet - create a drop link below.";
    box.append(empty);
    return;
  }
  for (const r of rows) {
    // pass mode never stashes a fragment; ignore leftover stash entries from
    // a same-slug fragment-mode predecessor wiped and recreated with a pass
    const keyB64 = r.pass ? "" : fragGet("rv:" + r.slug);
    const uplink = r.pass
      ? location.origin + "/r/" + r.slug
      : location.origin + "/r/" + r.slug + (keyB64 ? "#" + keyB64 : "");

    const row = document.createElement("div");
    row.className = "revrow";

    // head: chevron + slug + meta + icon actions
    const head = document.createElement("div");
    head.className = "revhead";
    const chev = iconBtn("Uploaded files", IC.chev, "rowicon chev");
    chev.setAttribute("aria-expanded", "false");
    const slug = document.createElement("button");
    slug.type = "button";
    slug.className = "revslug";
    slug.textContent = "/" + r.slug;
    const stats = document.createElement("span");
    stats.className = "revmeta";
    stats.textContent =
      (r.pass ? "passphrase mode · " : "") +
      (r.uploads === 0
        ? "awaiting files"
        : `${r.uploads} file${r.uploads === 1 ? "" : "s"} · ${humanSize(r.bytes)}`) +
      ` · expires ${expiryText(r.expires).replace(/^in /, "")}`;
    const acts = document.createElement("span");
    acts.className = "revacts";
    const cp = iconBtn("Copy drop link", IC.copy);
    cp.addEventListener("click", () => void copy(uplink, cp));
    const del = iconBtn("Delete reverse share", IC.del, "rowicon danger");
    del.addEventListener("click", () => {
      if (!confirm("Delete this reverse share? The link dies and all collected files are removed.")) return;
      del.disabled = true;
      void (async () => {
        const res = await fetch("/api/rshare/" + r.slug, { method: "DELETE" });
        if (!res.ok) {
          del.disabled = false;
          dashError("delete failed");
          return;
        }
        try {
          localStorage.removeItem("zp.frag.rv:" + r.slug);
          localStorage.removeItem("zp.tab-rev:" + r.slug);
        } catch {
          /* private mode */
        }
        await renderRshares();
      })();
    });
    acts.append(cp, del);
    head.append(chev, slug, stats, acts);
    row.append(head);

    // collapsible detail: uplink row + arrivals
    const detail = document.createElement("div");
    detail.className = "revdetail hidden";
    const ul = document.createElement("div");
    ul.className = "srow revup";
    const lk = document.createElement("span");
    lk.className = "revuplink";
    lk.textContent = uplink;
    const valid = r.pass || keyB64;
    ul.append(lk);
    if (!valid) {
      const warn = document.createElement("span");
      warn.className = "chipmeta burn";
      warn.textContent = "key missing on this browser - recreate the uplink or copy from the original tab";
      ul.append(warn);
    }
    detail.append(ul);
    for (const it of r.items) {
      const ar = document.createElement("div");
      ar.className = "srow revarrival";
      const fid = document.createElement("a");
      fid.textContent = "/p/" + it.id.slice(0, 6) + "…";
      if (r.pass || keyB64) {
        fid.href = location.origin + "/p/" + it.id + (r.pass ? "" : "#" + keyB64);
      } else {
        fid.className = "missing";
      }
      fid.title = it.id;
      const fsize = document.createElement("span");
      fsize.className = "swhen";
      fsize.textContent = it.size > 0 ? humanSize(it.size) : "text";
      ar.append(fid, fsize);
      detail.append(ar);
    }
    const toggle = (): void => {
      const open = detail.classList.toggle("hidden");
      chev.classList.toggle("open", !open);
      chev.setAttribute("aria-expanded", String(!open));
    };
    chev.addEventListener("click", toggle);
    slug.addEventListener("click", toggle);
    row.append(detail);
    box.append(row);
  }
}

async function loadDash(): Promise<void> {
  $("dasherr").classList.add("hidden");
  const me = (await (await fetch("/api/me")).json()) as MeRec;
  const accountsOff = me.accounts === false;
  const anon = !me.name;
  $("dashhead").classList.toggle("hidden", anon);
  $("dashrows").classList.toggle("hidden", anon);
  $("dashanon").classList.toggle("hidden", !anon);
  $("dashedit").classList.toggle("hidden", anon);
  if (anon) {
    if (accountsOff) {
      // no sign-in button, no invite: the instance runs anonymous-only
      $("dashlogin").classList.add("hidden");
      ($("dashanon").querySelector(":scope > b") as HTMLElement).textContent = "anonymous paste box";
      $("dashanontext").textContent = "This instance runs anonymous-only - accounts are disabled. Every paste stands on its own link and expiry.";
    } else {
      $("dashlogin").classList.remove("hidden");
      ($("dashanon").querySelector(":scope > b") as HTMLElement).textContent = "your shares live here";
      $("dashanontext").textContent = "Create an account or sign in with a passkey to see, copy and delete your active shares.";
    }
    $("dashtabs").classList.add("hidden");
    $("dashpanes").classList.add("hidden");
    $("dashanon").classList.remove("hidden");
    return; // sign-in card is up
  }
  $("dashanon").classList.add("hidden");
  $("dashtabs").classList.remove("hidden");
  $("dashpanes").classList.remove("hidden");
  void renderRshares().catch(() => {
    dashError("could not list reverse shares");
  });

  const nameBox = $("dashname") as HTMLInputElement;
  nameBox.value = me.name ?? "";
  const list = $("passkeylist") as HTMLElement;
  list.textContent = "";
  for (const id of me.passkeys ?? []) {
    const row = document.createElement("div");
    row.className = "passrow";
    const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg") as SVGSVGElement;
    icon.setAttribute("viewBox", "0 0 24 24");
    icon.setAttribute("fill", "none");
    icon.setAttribute("aria-hidden", "true");
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", "M12 17v2M20 4a2 2 0 0 0-2 1.4L10.9 13a3 3 0 1 0 2.1 2.1L21 7.1A2 2 0 0 0 20 4");
    p.setAttribute("stroke", "currentColor");
    p.setAttribute("stroke-width", "2");
    p.setAttribute("stroke-linecap", "round");
    p.setAttribute("stroke-linejoin", "round");
    icon.append(p);
    const code = document.createElement("code");
    code.textContent = id.length > 14 ? id.slice(0, 11) + "…" : id;
    code.title = id;
    row.append(icon, code);
    list.append(row);
  }
  if ((me.passkeys ?? []).length === 0) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = "No passkeys registered yet.";
    list.append(empty);
  }
  const rowsBox = $("dashrows") as HTMLElement;
  rowsBox.textContent = "";
  const res = await fetch("/api/shares");
  const rows = (await res.json()) as ShareRow[];
  if (rows.length === 0) {
    rowsBox.textContent = "";
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = "Nothing active yet - share a paste or file bundle while signed in.";
    rowsBox.appendChild(empty);
    return;
  }
  for (const r of rows) {
    const row = document.createElement("div");
    row.className = "srow";
    const link = document.createElement("a");
    link.href = shareURL(r);
    link.textContent = "/p/" + r.id.slice(0, 6) + "…";
    const kind = document.createElement("span");
    kind.textContent = r.kind === "bundle" ? "files" : "text";
    kind.className = "skind";
    const views = document.createElement("span");
    views.textContent = (r.views ?? 0) + " views";
    views.className = "susers";
    const alive = document.createElement("span");
    alive.textContent = r.burn ? "burn after reading" : expiryText(r.expires);
    alive.className = "swhen";
    const cp = document.createElement("button");
    cp.type = "button";
    cp.className = "rowcopy";
    cp.setAttribute("aria-label", "Copy share link");
    cp.textContent = "copy link";
    cp.addEventListener("click", () => {
      void (async () => {
        await navigator.clipboard.writeText(shareURL(r));
        cp.textContent = "copied!";
        setTimeout(() => (cp.textContent = "copy link"), 1200);
      })();
    });
    const del = document.createElement("button");
    del.type = "button";
    del.className = "rowdel";
    del.setAttribute("aria-label", "Delete share " + r.id);
    del.textContent = "Delete";
    del.addEventListener("click", () => {
      if (!confirm("Delete this share? The link stops working for everyone, including you.")) return;
      del.disabled = true;
      del.textContent = "deleting…";
      void (async () => {
        const res = await fetch("/api/paste/" + r.id, { method: "DELETE" });
        if (!res.ok) {
          del.disabled = false;
          del.textContent = "Delete";
          dashError("delete failed - the share may already be gone");
          return;
        }
        await loadDash(); // rows recompute live; the deleted one is gone
      })();
    });
    row.append(link, kind, views, alive, cp, del);
    rowsBox.append(row);
  }
}
