import type { JSX } from "preact";
import { $ } from "./dom";
import { deriveKey, open_, openBytes, bytesFromB64u, AesKey } from "./crypto";
import { humanSize } from "./ui";
import { view, show, readBundle, readText, readBurnInfo, linkError } from "./state";
import { useSignal } from "@preact/signals";
import { useEffect } from "preact/hooks";
import { readManifest, parseEnvHead, MANIFEST_HEAD, ENV_TAG, Manifest } from "./bundle";


interface PasteRec {
  id: string;
  data: string;
  salt?: string;
  hl?: boolean;
  burn: boolean;
  expires?: number;
  len?: number;
  views?: number;
}

function expiryText(unixSec: number): string {
  const ms = unixSec * 1000 - Date.now();
  if (!(ms > 0)) return "already expired - refresh to confirm";
  const min = Math.max(1, Math.round(ms / 60000));
  if (min < 60) return `expires in ${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `expires in ${h} h`;
  return `expires in ${Math.round(h / 24)} d`;
}

export function ReadView(): JSX.Element {
  const state = useSignal<"loading" | "text" | "bundle" | "unlock" | "error">("loading");
  const paste = useSignal<PasteRec | null>(null);
  const text = useSignal("");
  const bundle = useSignal<Manifest | null>(null);
  const theKey = useSignal<AesKey | null>(null);
  const err = useSignal("");
  const unlocked = useSignal(false); // passphrase gate state

  useEffect(() => {
    void (async () => {
      const m = location.pathname.match(/^\/p\/([A-Za-z0-9_-]+)$/);
      if (!m || !m[1]) return errFail("Invalid paste link.");
      const res = await fetch(`/api/paste/${m[1]}`);
      if (res.status === 404)
        return errFail("This paste is gone - it was burned after reading, or it expired.");
      if (!res.ok) return errFail("Server error: " + res.statusText);
      const p = { id: m[1], ...((await res.json()) as PartialPaste) } as PasteRec;
      paste.value = p;
      readBurnInfo.value = { burned: p.burn, expires: p.expires };
      if (p.salt) {
        state.value = "unlock";
        return;
      }
      const keyB64 = location.hash.slice(1);
      if (!keyB64) return errFail("This link is incomplete - it needs the secret part after #.");
      try {
        const key = await importKey(keyB64);
        await decodeWith(key);
      } catch {
        return errFail("Decryption failed - the link was probably altered or truncated.");
      }

      function errFail(msg: string): void {
        err.value = msg;
        state.value = "error";
        show("read");
      }

      async function importKey(kb: string): Promise<AesKey> {
        return crypto.subtle.importKey("raw", bytesFromB64u(kb), "AES-GCM", false, ["decrypt"]);
      }

      async function decodeWith(key: AesKey): Promise<void> {
        theKey.value = key;
        if (p.len && p.len > 0) {
          await loadBundleHead(key);
          state.value = "bundle";
        } else {
          text.value = await open_(p.data, key);
          state.value = "text";
        }
        show("read");
        history.replaceState(null, "", location.pathname); // strip key from address bar after use
      }

      async function loadBundleHead(key: AesKey): Promise<void> {
        // head = u32 + manifest iv + manifest ct
        const need = (async () => {
          const head = await fetchRange(p.id!, 0, 65536);
          const { mlen } = await parseEnvHead(head);
          if (head.length < 16 + mlen) throw new Error("manifest truncated");
          const manifest = await readManifest(
            key,
            head.subarray(4, 16) as Uint8Array<ArrayBuffer>,
            head.subarray(16, 16 + mlen) as Uint8Array<ArrayBuffer>,
          );
          let start = 16 + mlen;
          for (const f of manifest.files) start += f.size;
          readBundle.value = { id: p.id!, key, mlen, manifest, start: 16 + mlen };
          bundle.value = manifest;
          if (p.burn) {
            // link opened and validated: fires the server DELETE
            fetch(`/api/paste/${p.id}`, { method: "DELETE" }).catch(() => {});
          }
        })();
        await need;
      }
    })();
  }, []);

  function errFailStatic(msg: string): void {
    err.value = msg;
    state.value = "error";
    show("read");
  }
  void errFailStatic;

  const unlockPass = async (): Promise<void> => {
    try {
      const p = paste.value;
      if (!p?.salt) return;
      const key = await deriveKey(
        ($("#unlockpass") as HTMLInputElement).value,
        bytesFromB64u(p.salt),
      );
      theKey.value = key;
      if (p.len && p.len > 0) {
        // passphrase bundles: no text payload; manifest only
        const head = await fetchRange(p.id, 0, 65536);
        const { mlen } = await parseEnvHead(head);
        const manifest = await readManifest(
          key,
          head.subarray(4, 16) as Uint8Array<ArrayBuffer>,
          head.subarray(16, 16 + mlen) as Uint8Array<ArrayBuffer>,
        );
        readBundle.value = { id: p.id, key, mlen, manifest, start: 16 + mlen };
        bundle.value = manifest;
        if (p.burn) {
          fetch(`/api/paste/${p.id}`, { method: "DELETE" }).catch(() => {});
        }
        state.value = "bundle";
      } else {
        text.value = await open_(p.data, key);
        state.value = "text";
      }
      show("read");
      unlocked.value = true;
    } catch {
      ($("#unlockerr") as HTMLElement).textContent = "Wrong passphrase.";
      ($("#unlockerr") as HTMLElement).classList.remove("hidden");
      ($("#unlockpass") as HTMLInputElement).select();
    }
  };
  void unlocked;

  return (
    <section id="read" class={"card" + (view.value === "read" ? "" : " hidden")}>
      {state.value === "error" && <div id="readerr" class="error">{err.value}</div>}
      {state.value === "unlock" && (
        <div id="unlockgate">
          <div class="hint">This paste is passphrase-protected.</div>
          <div class="row">
            <input type="password" id="unlockpass" placeholder="passphrase" autocomplete="off" onKeyDown={(e) => { if (e.key === "Enter") void unlockPass(); }} />
            <button class="primary" id="unlockbtn" onClick={() => void unlockPass()}>Decrypt</button>
          </div>
          <div id="unlockerr" class="hint danger hidden" />
        </div>
      )}
      {state.value === "text" && (
        <div id="readbody">
          <div class="textblock">
            <button type="button" class="copybtn" aria-label="Copy" onClick={() => void copyRead(text.value)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            </button>
            <pre class="paste-view"><code id="pasteview" class={paste.value?.hl ? "hljs" : ""}>{text.value}</code></pre>
          </div>
          {readBurnInfo.value.burned && <div class="hint" id="burnnote">This paste was burned - the link is now dead.</div>}
          <div class="hint" id="expiresnote">{readBurnInfo.value.burned ? "" : readBurnInfo.value.expires ? expiryText(readBurnInfo.value.expires) : ""}</div>
        </div>
      )}
      {state.value === "bundle" && (
        <div id="readbody">
          {bundle.value?.note && (
            <div class="textblock">
              <button type="button" class="copybtn" aria-label="Copy note" onClick={() => void copyRead(bundle.value?.note ?? "")}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </button>
              <pre class="paste-view"><code>{bundle.value.note}</code></pre>
            </div>
          )}
          <div id="filelist">
            {bundle.value?.files.map((f, i) => (
              <FileRow key={i} file={f} i={i} bstate={readBundle.value!} past={state} />
            ))}
          </div>
          {readBurnInfo.value.burned && <div class="hint" id="burnnote">This paste was burned - the link is now dead.</div>}
          <div class="hint" id="expiresnote">{readBurnInfo.value.burned ? "" : readBurnInfo.value.expires ? expiryText(readBurnInfo.value.expires) : ""}</div>
        </div>
      )}
    </section>
  );
}

async function copyRead(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch { /* manual select fallback */ }
}

type PartialPaste = Omit<PasteRec, "id" | "burn" | "data"> & Partial<PasteRec>;

async function fetchRange(id: string, offset: number, maxLen: number): Promise<Uint8Array<ArrayBuffer>> {
  const res = await fetch(`/api/paste/${id}/blob?offset=${offset}`);
  if (!res.ok) throw new Error(`blob range at ${offset} -> ${res.status}`);
  const buf = await res.arrayBuffer();
  const got = new Uint8Array(buf);
  return got.length > maxLen ? (got.subarray(0, maxLen) as Uint8Array<ArrayBuffer>) : got;
}

function FileRow(props: {
  file: { name: string; mime: string; size: number; iv: string };
  i: number;
  bstate: { id: string; key: AesKey; mlen: number; start: number };
  past: { value: string };
}): JSX.Element {
  const { file: f, i, bstate } = props;
  const start = useSignal<number>(0);
  // recompute cumulative start per mount: start = bundle.start + sum(sizes before i)
  useEffect(() => {
    const b = readBundle.value;
    if (!b) return;
    let acc = b.start;
    for (let j = 0; j < i; j++) acc += (b.manifest.files[j]?.size ?? 0);
    start.value = acc;
  }, []);
  const saved = useSignal<"" | "busy" | "done" | "failed">("");
  const previewURL = useSignal("");
  useEffect(() => {
    void (async () => {
      if (!/^image\/(jpeg|png|gif|webp)$/.test(f.mime) || f.size > 5 << 20) return;
      try {
        const data = await fetchRangeExact(bstate.id, start.value, f.size);
        const pt = await openBytes(bstate.key, bytesFromB64u(f.iv), data);
        previewURL.value = URL.createObjectURL(new Blob([pt], { type: f.mime }));
      } catch { /* decorative */ }
    })();
  }, []);
  const save = async (): Promise<void> => {
    saved.value = "busy";
    try {
      const data = await fetchRangeExact(bstate.id, start.value, f.size);
      const pt = await openBytes(bstate.key, bytesFromB64u(f.iv), data);
      const url = URL.createObjectURL(new Blob([pt], { type: f.mime }));
      const a = document.createElement("a");
      a.href = url;
      a.download = f.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      saved.value = "done";
    } catch {
      saved.value = "failed";
    }
  };
  return (
    <div class="filerow">
      {previewURL.value !== "" && <img class="preview" alt={f.name} src={previewURL.value} />}
      <span class="filedata name">{f.name}</span>
      <span class="filedata">{humanSize(f.size)}</span>
      <button type="button" class="filesave" disabled={saved.value === "busy" || saved.value === "done"} onClick={() => void save()}>
        {saved.value === "" ? "Save" : saved.value === "busy" ? "decrypting…" : saved.value === "done" ? "saved" : "failed - retry"}
      </button>
    </div>
  );
}

export async function fetchRangeExact(
  id: string,
  offset: number,
  len: number,
): Promise<Uint8Array<ArrayBuffer>> {
  if (len <= 0) return new Uint8Array(0);
  const parts: Uint8Array<ArrayBuffer>[] = [];
  let off = offset;
  let want = len;
  while (want > 0) {
    const slice = await fetchRange(id, off, want);
    if (slice.length === 0) throw new Error("blob ended early");
    parts.push(slice);
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

// exported for the dash image feature reuse

