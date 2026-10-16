import { $, dec } from "./dom";
import { deriveKey, open_, bytesFromB64u, AesKey } from "./crypto";
import { show, copy, humanSize } from "./ui";
import { readManifest, parseEnvHead, parsePublicHead, MANIFEST_HEAD, ENV_TAG, Manifest } from "./bundle";
import { openBytes } from "./crypto";

// copy icon rides on the code block; wired once at import (read view only)
$("copytext").addEventListener("click", () =>
  void copy($("pasteview").textContent ?? "", $("copytext")),
);

// image lightbox: one native <dialog>; ESC, ✕ and backdrop click close it
const imgbox = $("imgbox") as HTMLDialogElement;
$("imgboxx").addEventListener("click", () => imgbox.close());
imgbox.addEventListener("click", (e) => {
  if (e.target === imgbox) imgbox.close(); // ::backdrop clicks hit the dialog itself
});
imgbox.addEventListener("close", () => {
  // empty string would resolve to the page URL and fetch it as an image
  ($("imgboximg") as HTMLImageElement).removeAttribute("src");
});

function openLightbox(url: string): void {
  ($("imgboximg") as HTMLImageElement).src = url;
  imgbox.showModal();
}

interface PasteBody {
  data: string;
  salt?: string;
  hl?: boolean;
  burn: boolean;
  len?: number;
  expires?: number;
  public?: boolean;
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

interface PasteRec extends PasteBody {
  id: string;
}

// header chips + burn side-effect, shared by text pastes and bundles;
// runs after successful decryption only (burn DELETE must not fire on failed reads)
function setReadMeta(paste: PasteRec, title: string): void {
  $("readtitle").textContent = title;
  // public shares open with the globe, not the padlock (text pastes + bundles)
  document.querySelector(".readtitle .lockico")?.classList.toggle("hidden", !!paste.public);
  document.querySelector(".readtitle .pubico")?.classList.toggle("hidden", !paste.public);
  if (paste.burn) {
    $("burnnote").textContent = "burn after reading";
    fetch(`/api/paste/${paste.id}`, { method: "DELETE" }).catch(() => {});
  } else {
    $("burnnote").textContent = "";
  }
  $("expiresnote").textContent =
    paste.burn || !paste.expires ? "" : expiresIn(paste.expires);
}

function renderPaste(paste: PasteRec, text: string): void {
  $("pasteview").textContent = text;
  if (paste.hl && window.hljs) hljs?.highlightElement($("pasteview"));
  setReadMeta(paste, paste.public ? "public paste" : "encrypted paste");
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

// bundle: parse the head, render note + table; files open on Save.
// key null => public lane: manifest and file bytes are plaintext (head is
// 4 bytes, no IVs), every open is the identity function.
async function renderBundle(paste: PasteRec, key: AesKey | null): Promise<void> {
  const head = await fetchRangeExact(paste, 0, key ? MANIFEST_HEAD : 4);
  const { mlen, manifestStart } = key ? await parseEnvHead(head) : parsePublicHead(head);
  const mraw = await fetchRangeExact(paste, manifestStart, mlen);
  let manifest: Manifest;
  try {
    manifest = key
      ? await readManifest(key, head.subarray(4, 16), mraw)
      : (JSON.parse(dec.decode(mraw)) as Manifest);
  } catch {
    return fail("Decryption failed - the link was probably altered or truncated.");
  }
  // link validated: bundles burn via this DELETE after the envelope opens
  // note renders through the existing paste-view code block (copy icon rides along)
  const openBlob = key
    ? async (data: Uint8Array<ArrayBuffer>, ivB64?: string): Promise<Uint8Array<ArrayBuffer>> =>
        openBytes(key, bytesFromB64u(ivB64 ?? ""), data)
    : async (data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> => data;
  const label = key ? "encrypted bundle" : "public bundle";
  const note = manifest.note ?? "";
  ($("pasteview") as HTMLElement).textContent = note;
  ($("codewrap") as HTMLElement).classList.toggle("hidden", !note);
  const n = manifest.files.length;
  setReadMeta(paste, `${label} · ${n} file${n === 1 ? "" : "s"}`);

  const list = $("filelist") as HTMLElement;
  list.textContent = "";
  let off = manifestStart + mlen;
  // thumbnail block: every file's ciphertext first, then thumbs in manifest order
  let toff = off;
  for (const mf of manifest.files) toff += mf.size;
  for (const f of manifest.files) {
    const start = off; // captured per row before we advance
    const t = f.thumb;
    const thumbStart = t ? toff : 0;
    if (t) toff += t.size;
    const name = document.createElement("span");
    name.className = "filedata name";
    name.textContent = f.name;
    const size = document.createElement("span");
    size.className = "filedata fsize";
    size.textContent = humanSize(f.size);
    const save = document.createElement("button");
    save.type = "button";
    save.className = "filesave";
    save.textContent = "Save";
    save.addEventListener("click", async () => {
      save.disabled = true;
      save.textContent = key ? "decrypting…" : "saving…";
      try {
        const data = await fetchRangeExact(paste, start, f.size);
        const full = await openBlob(data, f.iv);
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

    // image attachments: media card with inline preview, click opens the
    // lightbox; with a stored thumbnail the card stays small and the full
    // image only decrypts when actually opened
    const canEager = /^image\/(jpeg|png|gif|webp)$/.test(f.mime) && f.size <= 5 << 20;
    const foot = document.createElement("div");
    foot.className = "filefoot";
    foot.append(name, size, save);
    const row = document.createElement("div");
    if (t || canEager) {
      row.className = "filecard";
      const open = document.createElement("button");
      open.type = "button";
      open.className = "previewopen";
      open.setAttribute("aria-label", "Open " + f.name + " larger");
      const img = document.createElement("img");
      img.className = "preview";
      img.alt = f.name;
      // click is gated on load: an undecodable blob never opens a broken lightbox
      img.addEventListener("load", () => {
        if (!t) {
          open.addEventListener("click", () => openLightbox(img.src));
          return;
        }
        // thumbnail path: show the small version instantly, swap in the full
        // decrypt when it lands (cached for re-opens)
        let fullUrl: string | null = null;
        open.addEventListener("click", () => {
          if (fullUrl) return void openLightbox(fullUrl); // already decrypted
          openLightbox(img.src); // thumb as instant placeholder
          void fetchRangeExact(paste, start, f.size)
            .then((d) => openBlob(d, f.iv))
            .then((full) => {
              fullUrl = URL.createObjectURL(new Blob([full], { type: f.mime }));
              const box = $("imgbox") as HTMLDialogElement;
              if (box.open) ($("imgboximg") as HTMLImageElement).src = fullUrl; // closed meanwhile: cached for the next open
            })
            .catch(() => {}); // lightbox keeps the thumb; Save still works
        });
      }, { once: true });
      img.onerror = () => {
        open.hidden = true; // undecodable blob: keep the file row working
        row.classList.add("filecard-flat");
      };
      const decode = t
        ? fetchRangeExact(paste, thumbStart, t.size).then((d) => openBlob(d, t.iv))
        : fetchRangeExact(paste, start, f.size).then((d) => openBlob(d, f.iv));
      void decode
        .then((full) => {
          img.src = URL.createObjectURL(new Blob([full], { type: t ? "image/jpeg" : f.mime }));
          open.append(img);
          row.append(open, foot);
        })
        .catch(() => {
          open.hidden = true; // preview is decorative; Save still works
          row.classList.add("filecard-flat");
          row.append(foot);
        });
    } else {
      row.className = "filerow";
      row.append(name, size, save);
    }
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
  ($("readerrmsg") as HTMLElement).textContent = msg;
  $("readerr").classList.remove("hidden");
}

export async function readView(): Promise<void> {
  show("read");
  let paste: PasteRec;
  try {
    paste = await fetchPaste();
  } catch (e) {
    return fail((e as { message?: string }).message ?? "Could not fetch the paste.");
  }

  // public lane: the payload IS the content - no key exists, nothing to decrypt
  if (paste.public) {
    if (paste.len) {
      paste.data = ""; // bundle metas carry no text payload
      await renderBundle(paste, null);
    } else {
      renderPaste(paste, paste.data);
    }
    return;
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
