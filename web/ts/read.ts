import { $ } from "./dom";
import { deriveKey, open_, bytesFromB64u } from "./crypto";
import { show } from "./ui";

interface PasteBody {
  data: string;
  salt?: string;
  hl?: boolean;
  burn: boolean;
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

function fail(msg: string): void {
  ($("readbody") as HTMLElement).classList.add("hidden");
  $("unlock").classList.add("hidden");
  const err = $("readerr");
  err.classList.remove("hidden");
  ($("readerr") as HTMLElement).textContent = msg;
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
        renderPaste(paste, await open_(paste.data, key));
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
    const text = await open_(paste.data, key);
    history.replaceState(null, "", location.pathname); // strip key from address bar after use
    renderPaste(paste, text);
  } catch {
    fail("Decryption failed - the link was probably altered or truncated.");
  }
}
