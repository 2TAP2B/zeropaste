import { $, enc, dec } from "./dom";

const PBKDF2_ITERATIONS = 600000; // OWASP recommendation for PBKDF2-HMAC-SHA256

export function b64uFromBytes(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function bytesFromB64u(str: string): Uint8Array<ArrayBuffer> {
  const norm = str.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  let padded = norm;
  while (padded.length % 4) padded += "=";
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export type AesKey = CryptoKey;

export interface Sealed {
  iv: Uint8Array<ArrayBuffer>;
  ct: Uint8Array<ArrayBuffer>;
}

export async function sealBytes(key: AesKey, plain: Uint8Array<ArrayBuffer>): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
  return { iv, ct: new Uint8Array(ct) };
}

export async function openBytes(
  key: AesKey,
  iv: Uint8Array<ArrayBuffer>,
  ct: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

export async function randomKey(): Promise<{ key: AesKey; keyB64: string }> {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return {
    key: await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]),
    keyB64: b64uFromBytes(raw),
  };
}

export function deriveKey(passphrase: string, salt: Uint8Array<ArrayBuffer>): Promise<AesKey> {
  const base = crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, [
    "deriveKey",
  ]);
  return base.then((b) =>
    crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
      b,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    ),
  );
}

export async function seal(key: AesKey, text: string): Promise<string> {
  const { iv, ct } = await sealBytes(key, enc.encode(text));
  return b64uFromBytes(new Uint8Array([...iv, ...ct]));
}

export async function open_(payloadB64: string, key: AesKey): Promise<string> {
  const buf = bytesFromB64u(payloadB64);
  const pt = await openBytes(key, buf.subarray(0, 12), buf.subarray(12));
  return dec.decode(pt);
}

export const siteKey = {
  get(): string {
    try {
      return sessionStorage.getItem("zp.siteKey") ?? "";
    } catch {
      return "";
    }
  },
  set(v: string): void {
    sessionStorage.setItem("zp.siteKey", v); // per tab, never localStorage, never a cookie
  },
  clear(): void {
    sessionStorage.removeItem("zp.siteKey");
  },
};
