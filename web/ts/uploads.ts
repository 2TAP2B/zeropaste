import { randomKey, deriveKey, b64uFromBytes, AesKey } from "./crypto";
import { assembleEnv } from "./bundle";

// Byte-level caps mirror the server env defaults (MAX_BLOB). The server is
// the authority; init rejects oversized shares regardless of this constant.
// NOTE: 2 ** 31, not 2 << 30 - JS bitwise shifts are 32-bit signed, so the
// shift form yields -2147483648 and silently caps every share at zero.
export const CLIENT_MAX_BLOB = 2 ** 31;

export interface UploadResult {
  id: string; // finished paste id
  keyB64: string; // fragment key for random-key shares ("" for passphrase shares)
  pass: string; // the passphrase (kept in-memory client-side only)
}

export interface UploadOpts {
  note: string;
  files: File[];
  ttl: string;
  burn: boolean;
  pass: string;
  onProgress?: (pct: number, phase: "encrypt" | "upload" | "finish") => void;
  onSession?: (uploadId: string) => void; // lets callers abort/delete the temp session
  signal?: AbortSignal;
}

export class UploadAborted extends Error {
  constructor() {
    super("upload aborted");
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new UploadAborted();
}

function saltIfNeeded(pass: string): { salt?: Uint8Array<ArrayBuffer>; saltB64?: string } {
  if (!pass) return {};
  const s = crypto.getRandomValues(new Uint8Array(16));
  return { salt: s, saltB64: b64uFromBytes(s) };
}

export async function uploadBundle(o: UploadOpts): Promise<UploadResult> {
  throwIfAborted(o.signal);
  let totalFiles = 0;
  for (const f of o.files) {
    totalFiles += f.size;
    if (f.size < 0 || totalFiles > CLIENT_MAX_BLOB) {
      throw new Error("combined file size exceeds the share cap");
    }
  }
  let key: AesKey;
  let keyB64 = "";
  const { salt, saltB64 } = saltIfNeeded(o.pass);
  if (o.pass) {
    key = await deriveKey(o.pass, salt as Uint8Array<ArrayBuffer>);
  } else {
    const k = await randomKey();
    key = k.key;
    keyB64 = k.keyB64;
  }
  o.onProgress?.(0, "encrypt");
  const blob = await assembleEnv(key, o.note, o.files);
  throwIfAborted(o.signal);

  const req = await fetch("/api/uploads", {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ len: blob.length, ttl: o.ttl, burn: o.burn, salt: saltB64 ?? "" }),
  });  if (!req.ok) {
    throw new Error(((await req.json().catch(() => ({}))) as { error?: string }).error ?? "upload init failed");
  }
  const init = (await req.json()) as { id: string; chunkSize: number; chunks: number };
  o.onSession?.(init.id);
  o.onProgress?.(0, "upload");

  const total = blob.length;
  let doneBytes = 0;
  for (let n = 0, off = 0; n < init.chunks; n++, off += init.chunkSize) {
    throwIfAborted(o.signal);
    const end = Math.min(off + init.chunkSize, total);
    if (end <= off) break;
    const chunk = blob.subarray(off, end);
    let lastErr: unknown = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        throwIfAborted(o.signal);
        const res = await fetch(`/api/uploads/${init.id}/${n}`, {
          method: "PUT",
          headers: jsonHeaders(), // chunked PUTs are gated too when the instance locks creation
          body: chunk,
          signal: o.signal,
        });
        if (res.status === 204) {
          lastErr = null;
          break;
        }
        if (res.status >= 400 && res.status < 500 && res.status !== 429) {
          throw new Error(`chunk ${n} rejected (${res.status})`);
        }
        lastErr = new Error(`chunk ${n} attempt ${attempt} -> ${res.status}`);
      } catch (e) {
        if (e instanceof UploadAborted) throw e;
        if (o.signal?.aborted) throw new UploadAborted();
        if (e instanceof TypeError || e instanceof RangeError) {
          lastErr = e; // network hiccup: retry
        } else {
          throw e;
        }
      }
    }
    if (lastErr !== null) throw lastErr;
    doneBytes += chunk.length;
    o.onProgress?.(Math.min(99, Math.floor((doneBytes / total) * 100)), "upload");
  }

  o.onProgress?.(100, "finish");
  const fin = await fetch(`/api/uploads/${init.id}/finish`, {
    method: "POST",
    headers: jsonHeaders(),
  });
  if (!fin.ok) {
    const body = (await fin.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? "finish failed");
  }
  const finBody = (await fin.json()) as { id: string };
  return { id: finBody.id, keyB64, pass: o.pass };
}

function jsonHeaders(): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  try {
    const site = sessionStorage.getItem("zp.siteKey");
    if (site) h.Authorization = "Bearer " + site;
  } catch {
    /* private mode */
  }
  return h;
}

export function abortUpload(id: string): void {
  // abort is public by design - the server's DELETE endpoint takes no auth
  fetch(`/api/uploads/${id}`, { method: "DELETE" }).catch(() => {});
}
