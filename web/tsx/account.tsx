import { $ } from "./dom";
import { b64uFromBytes, bytesFromB64u } from "./crypto";
import { sessionName, regOpen, insecureOrigin } from "./state";

// Passkey account flows. Anonymous behavior is untouched; login exists purely
// for the dashboard. The header icon opens #accpanel only when anonymous
// (signed-in users navigate straight to /dash - see app.tsx).
export const COOKIE_STASH_PREFIX = "zp.frag.";

// fragment stash: create flow stores <id> -> key fragment client-side so the
// dashboard re-opens shares. Deliberately client-side only - the
// zero-knowledge mandate protects the server boundary, not the local disk
// (same threat model as browser history).
function fragGet(id: string): string {
  try {
    return localStorage.getItem(COOKIE_STASH_PREFIX + id) ?? "";
  } catch {
    return "";
  }
}

function fragPut(id: string, keyB64: string): void {
  try {
    localStorage.setItem(COOKIE_STASH_PREFIX + id, keyB64);
  } catch {
    /* private mode */
  }
}

export function stashForCreate(id: string, keyB64: string): void {
  if (keyB64) fragPut(id, keyB64);
}

export function openShareTarget(id: string): string {
  return "/p/" + id + (fragGet(id) ? "#" + fragGet(id) : "");
}

function dropFrags(): void {
  try {
    const doomed: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(COOKIE_STASH_PREFIX)) doomed.push(k);
    }
    for (const k of doomed) localStorage.removeItem(k);
  } catch {
    /* private mode */
  }
}

export async function refreshMe(): Promise<void> {
  try {
    const res = await fetch("/api/me");
    const me = (await res.json()) as { name?: string; open?: boolean };
    sessionName.value = me.name ?? "";
    if (me.open !== undefined) regOpen.value = me.open;
  } catch {
    /* server unreachable: keep current chip */
  }
}

function accError(msg: string): void {
  const el = $("accerr");
  el.textContent = msg;
  el.classList.remove("hidden");
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

function unwrapPublicKey(options: unknown): CeremonyShape {
  const shape = (options ?? {}) as CeremonyShape;
  return (shape.publicKey ?? shape) as CeremonyShape;
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

export async function registerStart(nameOpt?: string): Promise<void> {
  try {
    let name = nameOpt ?? "";
    if (!nameOpt) {
      const el = document.getElementById("accname") as HTMLInputElement | null;
      name = el?.value ?? "";
    }
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
