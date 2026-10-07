import { $ } from "./dom";
import { deriveKey, open_, bytesFromB64u, AesKey } from "./crypto";
import { show } from "./ui";
import { readManifest, parseEnvHead, MANIFEST_HEAD, ENV_TAG, Manifest } from "./bundle";
import { openBytes } from "./crypto";
import { humanSize } from "./ui";

interface PasteBody {
  data: string;
  salt?: string;
  hl?: boolean;
  burn: boolean;
  len?: number;
  expires?: number;
}

interface PasteRec extends PasteBody {
  id: string;
}

function expiresIn(unixSec: number): string {
  const ms = unixSec * 1000 - Date.now();
  if (!(ms > 0)) return "already expired - refresh to confirm";
  const min = Math.max(1, Math.round(ms / 60000));
  if (min < 60) return `expires in ${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `expires in ${h} h`;
  return `expires in ${Math.round(h / 24)} d`;
}

async function fetchPaste(): Promise<PasteRec> {
  const m = location.pathname.match(/^\/p\/([A-Za-z0-9_-]+)$/);
  if (!m || !m[1]) throw { code: "incomplete", message: "Invalid paste link." };
  const res = await fetch(`/api/paste/${m[1]}`);
  if (res.status === 404)
    throw { code: "gone", message: "This paste is gone - it was burned after reading, or it expired." };
  if (!res.ok) throw { code: "server", message: "Server error: " + res.statusText };
  const body = (await res.json()) as PasteBody;
  return { ...body, id: m[1] };
}

interface PasteBody {
  data: string;
  salt?: string;
  hl?: boolean;
  burn: boolean;
  len?: number;
  expires?: number;
}

interface PasteRec extends PasteBody {
  id: string;
}

function renderPaste(paste: PasteRec, text: string): void {
  $("pasteview").textContent = text;
  if (paste.hl && window.hljs) hljs?.highlightElement($("pasteview"));
  ($("expiresnote") as HTMLElement).textContent = paste.burn
    ? ""
    : paste.expires
      ? expiresIn(paste.expires)
      : "";
  if (paste.burn) {
    ($("burnnote") as HTMLElement).textContent = "This paste was burned - the link is now dead.";
    fetch(`/api/paste/${paste.id}`, { method: "DELETE" }).catch(() => {});
  } else {
    ($("burnnote") as HTMLElement).textContent = "";
  }
  $("unlock").classList.add("hidden");
  $("readbody").classList.remove("hidden");
}

async function fetchRange(id: string, offset: number, maxLen: number): Promise<Uint8Array<ArrayBuffer>> {
  const res = await fetch(`/api/paste/${id}/blob?offset=${offset}`);
  if (!res.ok) throw new Error(`blob range at ${offset} -> ${res.status}`);
  const buf = await res.arrayBuffer();
  const got = new Uint8Array(buf);
  return got.subarray(0, Math.min(got.length, maxLen));
}

async function fetchRangeExact(
  paste: PasteRec,
  offset: number,
  len: number,
  onBytes?: (got: number) => void,
): Promise<Uint8Array<ArrayBuffer>> {
  if (len <= 0) return new Uint8Array(0);
  const total = paste.len ?? 0;
  const parts: Uint8Array<ArrayBuffer>[] = [];
  let want = Math.min(len, total - offset);
  let off = offset;
  while (want > 0) {
    const slice = await fetchRange(paste.id, off, want).then((u) => new Uint8Array(u));
    if (slice.length === 0) throw new Error("blob ended early");
    parts.push(new Uint8Array(slice));
    onBytes?.(slice.length);
    off += slice.length;
    want -= slice.length;
  }
  const out = new Uint8Array(len);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

// bundle: decrypt the head, render note + table; files decrypt on Save.
async function renderBundle(paste: PasteRec, key: AesKey): Promise<void> {
  const head = await fetchRangeExact(paste, 0, MANIFEST_HEAD);
  const { mlen } = await parseEnvHead(head);
  const manifestCt = await fetchRangeExact(paste, 16, mlen);
  let manifest: Manifest;
  try {
    manifest = await readManifest(key, head.subarray(4, 16), manifestCt);
  } catch {
    return fail("Decryption failed - the link was probably altered or truncated.");
  }
  // link validated: bundles burn via this DELETE after the envelope opens
  // note renders through the existing paste-view code block (copy icon rides along)
  ($("pasteview") as HTMLElement).textContent = manifest.note ?? "";
  ($("expiresnote") as HTMLElement).textContent = paste.burn
    ? ""
    : paste.expires
      ? expiresIn(paste.expires)
      : "";
  if (paste.burn) {
    ($("burnnote") as HTMLElement).textContent = "This paste was burned - the link is now dead.";
    fetch(`/api/paste/${paste.id}`, { method: "DELETE" }).catch(() => {});
  } else {
    ($("burnnote") as HTMLElement).textContent = "";
  }

  const list = $("filelist") as HTMLElement;
  list.textContent = "";
  let off = 16 + mlen;
  for (const f of manifest.files) {
    const start = off; // captured per row before we advance
    const row = document.createElement("div");
    row.className = "filerow";
    const name = document.createElement("span");
    name.className = "filedata";
    name.textContent = f.name;
    const size = document.createElement("span");
    size.className = "filedata";
    size.textContent = humanSize(f.size);
    const save = document.createElement("button");
    save.type = "button";
    save.className = "filesave";
    save.textContent = "Save";
    save.addEventListener("click", async () => {
      save.disabled = true;
      save.textContent = "decrypting…";
      try {
        const data = await fetchRangeExact(paste, start, f.size);
        const full = await openBytes(key, bytesFromB64u(f.iv), data);
        const blob = new Blob([full], { type: f.mime });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = f.name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        save.textContent = "saved";
      } catch {
        save.textContent = "failed";
        save.disabled = false;
      }
    });
    row.append(name, size, save);
    list.append(row);
    off += f.size;
  }

  $("unlock").classList.add("hidden");
  $("readbody").classList.remove("hidden");
  $("readerr").classList.add("hidden");
}

function fail(msg: string): void {
  ($("readbody") as HTMLElement).classList.add("hidden");
  $("unlock").classList.add("hidden");
  const err = $("readerr");
  err.classList.remove("hidden");
}

export async function readView(): Promise<void> {
  show("read");
  let paste: PasteRec;
  try {
    paste = await fetchPaste();
  } catch (e) {
    return fail((e as { message?: string }).message ?? "Could not fetch the paste.");
  }

  if (paste.salt) {
    // passphrase-protected: key derived locally from passphrase + stored salt
    const unlock = async (): Promise<void> => {
      $("unlockerr").classList.add("hidden");
      try {
        const pass = ($("unlockpass") as HTMLInputElement).value;
        const key = await deriveKey(pass, bytesFromB64u(paste.salt as string));
        if (paste.len) {
          paste.data = ""; // bundle metas carry no text payload
          await renderBundle(paste, key);
        } else {
          renderPaste(paste, await open_(paste.data, key));
        }
      } catch {
        const err = $("unlockerr");
        err.textContent = "Wrong passphrase.";
        err.classList.remove("hidden");
        ($("unlockpass") as HTMLInputElement).select();
      }
    };
    $("unlockbtn").addEventListener("click", () => void unlock());
    $("unlockpass").addEventListener("keydown", (e) => {
      if (e.key === "Enter") void unlock();
    });
    $("unlock").classList.remove("hidden");
    ($("unlockpass") as HTMLInputElement).focus();
    return;
  }

  const keyB64 = location.hash.slice(1);
  if (!keyB64) return fail("This link is incomplete - it needs the secret part after #.");
  try {
    const key = await crypto.subtle.importKey("raw", bytesFromB64u(keyB64), "AES-GCM", false, [
      "decrypt",
    ]);
    if (paste.len) {
      await renderBundle(paste, key);
    } else {
      const text = await open_(paste.data, key);
      renderPaste(paste, text);
    }
    history.replaceState(null, "", location.pathname); // strip key from address bar after use
  } catch {
    fail("Decryption failed - the link was probably altered or truncated.");
  }
}
