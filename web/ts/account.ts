import { $ } from "./dom";
import { b64uFromBytes, bytesFromB64u } from "./crypto";

// Passkey account flows + the active-shares dashboard, both passkey-only.
// Anonymous behavior is untouched; login exists purely for the dashboard.
// The header icon button opens the #accpanel popover (zero JS to open).

interface MeRec {
  name?: string;
  id?: string;
  open?: boolean;
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
    const nameInput = $("accname") as HTMLInputElement;
    const login = $("loginbtn") as HTMLButtonElement;
    const out = $("logoutbtn") as HTMLButtonElement;
    const poll = $("accpoll") as HTMLElement;

    const signedIn = !!me.name;
    const insecure = !window.isSecureContext && !location.hostname.includes("localhost") && !location.hostname.includes("127.0.0.1");
    ($("browserhint") as HTMLElement).classList.toggle("hidden", !insecure);
    if (insecure) {
      reg.disabled = true;
      login.disabled = true;
      poll.textContent = "passkeys need HTTPS (or localhost)";
      return;
    }
    reg.disabled = false;
    login.disabled = false;
    if (signedIn) {
      poll.textContent = me.name ?? "";
      reg.textContent = "Add another passkey";
      nameInput.classList.add("hidden");
      login.classList.add("hidden");
      out.classList.remove("hidden");
      ($("dashlink") as HTMLElement).classList.remove("hidden");
      ($("dashview") as HTMLElement).classList.add("hidden"); // overview lives on /dash now
    } else {
      poll.textContent =
        me.open === false ? "sign in - new registrations are closed" : "create an account - passkey only";
      reg.textContent = "Create account";
      if (me.open === false) {
        reg.classList.add("hidden");
        nameInput.classList.add("hidden");
      } else {
        reg.classList.remove("hidden");
        nameInput.classList.remove("hidden");
      }
      login.classList.remove("hidden");
      out.classList.add("hidden");
      ($("dashview") as HTMLElement).classList.add("hidden");
    }
  } catch {
    /* server unreachable: leave the pane as configured */
  }
}

export async function dashboardRefresh(): Promise<void> {
  const out = $("sharelist") as HTMLElement;
  out.textContent = "";
  const res = await fetch("/api/shares");
  if (!res.ok) {
    out.textContent = "Could not load shares.";
    return;
  }
  const rows = (await res.json()) as ShareRow[];
  if (rows.length === 0) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = "No active shares - create a paste while signed in.";
    out.append(empty);
    return;
  }
  for (const r of rows) {
    const row = document.createElement("div");
    row.className = "srow";
    const link = document.createElement("a");
    const frag = fragGet(r.id);
    link.href = "/p/" + r.id + (frag ? "#" + frag : "");
    link.textContent = r.id.slice(0, 6) + "…";
    const kind = document.createElement("span");
    kind.textContent = r.kind === "bundle" ? "files" : "text";
    kind.className = "skind";
    const when = document.createElement("span");
    when.textContent = r.burn ? "burn after reading" : "expires " + expiryText(r.expires);
    when.className = "swhen";
    row.append(link, kind, when);
    out.append(row);
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

export async function loginStart(): Promise<void> {
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
  } catch (e) {
    accError(e instanceof Error ? e.message : "login failed");
  }
}

export async function logout(): Promise<void> {
  await fetch("/api/identity/logout", { method: "POST" }).catch(() => {});
  dropFrags();
  await refreshMe();
}

export async function bootAccount(): Promise<void> {
  $("regbtn").addEventListener("click", () => void registerStart());
  $("loginbtn").addEventListener("click", () => void loginStart());
  $("logoutbtn").addEventListener("click", () => void logout());
  // statistics refresh whenever the lightbox opens or closes
  const panel = $("accpanel") as HTMLElement;
  panel.addEventListener("toggle", () => {
    if ((panel as HTMLElement & { open: boolean }).open) void refreshMe();
  });
  await refreshMe();
}

// --- the real dashboard page (/dash) ---
// Detailed share overview: copy-link per row, alive countdown, views counter,
// plus the identity edit section (name, add passkey).

function shareURL(r: ShareRow): string {
  return location.origin + "/p/" + r.id + (fragGet(r.id) ? "#" + fragGet(r.id) : "");
}

export async function dashboardPage(): Promise<void> {
  document.body.textContent = "";
  const main = document.createElement("main");
  const head = document.createElement("header");
  head.className = "top";
  head.appendChild(
    Object.assign(document.createElement("a"), {
      className: "brand",
      href: "/",
      textContent: "zeropaste",
    } as Partial<HTMLAnchorElement>),
  );
  main.appendChild(head);
  const card = document.createElement("section");
  card.className = "card";
  card.id = "dashfull";
  card.innerHTML = "<h2 class='dashtitle'>your active shares</h2>" +
    "<div id='dashrows'></div>" +
    "<div class='dashedit hidden' id='dashedit'>" +
    "  <b>account</b>" +
    "  <div class='accrow'>" +
    "    <input type='text' id='dashname' maxlength='64' placeholder='display name' autocomplete='off'>" +
    "    <button type='button' id='dashsave'>Save name</button>" +
    "    <button type='button' id='dashreg'>Add passkey</button>" +
    "  </div>" +
    "  <div id='dasherr' class='hint danger hidden'></div>" +
    "</div>" +
    "<div class='hint'>Links carry the decryption key in the fragment; the server cannot read any of them. Rows disappear when the share expires or burns.</div>";
  main.appendChild(card);
  document.body.appendChild(main);

  $("dashsave").addEventListener("click", () => void saveName());
  $("dashreg").addEventListener("click", () => {
    (document.getElementById("dashreg") as HTMLButtonElement).disabled = true;
    registerStart()
      .then(() => void loadDash())
      .catch((e) => dashError(e instanceof Error ? e.message : "failed"));
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

async function loadDash(): Promise<void> {
  const me = (await (await fetch("/api/me")).json()) as MeRec;
  if (!me.name) return; // anonymous: routers out; the page stays empty
  ($("dashedit") as HTMLElement).classList.remove("hidden");
  ($("dashname") as HTMLInputElement).value = me.name;
  const rowsBox = $("dashrows") as HTMLElement;
  rowsBox.textContent = "";
  const res = await fetch("/api/shares");
  const rows = (await res.json()) as ShareRow[];
  if (rows.length === 0) {
    rowsBox.innerHTML = "";
    rowsBox.appendChild(Object.assign(document.createElement("div"), {
      className: "hint",
      textContent: "Nothing active yet - share a paste or file bundle while signed in.",
    } as Partial<HTMLDivElement>));
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
    alive.textContent = r.burn ? "" : expiryText(r.expires);
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
    row.append(link, kind, views, alive, cp);
    rowsBox.append(row);
  }
}
