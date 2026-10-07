import { $ } from "./dom";
import { b64uFromBytes, bytesFromB64u } from "./crypto";

// Passkey account flows + the active-shares dashboard. Anonymous behavior is
// untouched; login exists purely for the dashboard convenience view.

interface MeRec {
  name?: string;
  id?: string;
}

interface ShareRow {
  id: string;
  kind: "text" | "bundle";
  burn: boolean;
  expires: number;
}

// fragment stash: create flow stores <id> -> key fragment client-side so the
// dashboard can offer "open". Privacy note: deliberately client-side only -
// the zero-knowledge mandate protects the server boundary, not the local
// disk (same threat model as browser history).
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
    const chip = $("accbtn") as HTMLElement;
    const reg = $("regbtn") as HTMLButtonElement;
    const login = $("loginbtn") as HTMLButtonElement;
    const out = $("logoutbtn") as HTMLButtonElement;
    if (me.name) {
      chip.textContent = me.name;
      reg.textContent = "Add another passkey";
      login.classList.add("hidden");
      out.classList.remove("hidden");
      dashShow();
      void dashboardRefresh();
    } else {
      chip.textContent = "account";
      reg.textContent = "Register passkey";
      login.classList.remove("hidden");
      out.classList.add("hidden");
      ($("dashview") as HTMLElement).classList.add("hidden");
    }
  } catch {
    /* server unreachable: leave header as-is */
  }
}

function dashShow(): void {
  ($("dashview") as HTMLElement).classList.remove("hidden");
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
    empty.textContent = "No active shares - create a paste while logged in.";
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

interface CreationShape {
  publicKey?: Record<string, unknown>;
  rp?: { id?: string; name?: string };
  user?: { id?: string; name?: string; displayName?: string };
  challenge?: string;
  pubKeyCredParams?: unknown[];
  timeout?: number;
  excludeCredentials?: Array<{ id?: string }>;
  authenticatorSelection?: unknown;
  attestation?: string;
}

function creationToPublicKey(options: unknown): PublicKeyCredentialCreationOptions {
  const o = (options ?? {}) as CreationShape;
  const pk = (o.publicKey ?? o) as CreationShape;
  const u = pk.user ?? {};
  return {
    challenge: bytesFromB64u(pk.challenge ?? ""),
    rp: { id: pk.rp?.id ?? "", name: pk.rp?.name ?? "" },
    user: {
      id: bytesFromB64u(u.id ?? ""),
      name: u.name ?? "",
      displayName: u.displayName ?? (u.name ?? "") as string,
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
    authenticatorSelection: pk.authenticatorSelection as AuthenticatorSelectionCriteria,
    attestation: (pk.attestation ?? "none") as AttestationConveyancePreference,
  };
}

interface AssertionShape {
  publicKey?: Record<string, unknown>;
  challenge?: string;
  userVerification?: string;
  timeout?: number;
}

function assertionToPublicKey(options: unknown): PublicKeyCredentialRequestOptions {
  const o = (options ?? {}) as AssertionShape;
  const pk = (o.publicKey ?? o) as AssertionShape;
  return {
    challenge: bytesFromB64u(pk.challenge ?? ""),
    timeout: pk.timeout ?? 60000,
    userVerification: (pk.userVerification ?? "preferred") as UserVerificationRequirement,
  };
}

function attestationBody(c: PublicKeyCredential, sessionId: string): string {
  const res = c.response as AuthenticatorAttestationResponse;
  return JSON.stringify({
    sessionId,
    id: c.id,
    rawId: arrayB64u(c.rawId),
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
  $("accbtn").addEventListener("click", () => {
    ($("accpane") as HTMLElement).classList.toggle("hidden");
    void refreshMe();
  });
  $("regbtn").addEventListener("click", () => void registerStart());
  $("loginbtn").addEventListener("click", () => void loginStart());
  $("logoutbtn").addEventListener("click", () => void logout());
  $("refreshout").addEventListener("click", () => void dashboardRefresh());
  await refreshMe();
}
