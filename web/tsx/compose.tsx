import type { JSX } from "preact";
import { $ } from "./dom";
import { randomKey, deriveKey, seal, siteKey, b64uFromBytes } from "./crypto";
import { drawQR, humanSize } from "./ui";
import {
  view, show, picked, uploadProgress, composeError, shareLink, shareIsPassphrase,
} from "./state";
import { uploadBundle, abortUpload, UploadAborted } from "./uploads";
import { stashForCreate } from "./account";
import { useSignal } from "@preact/signals";
import { useEffect, useRef } from "preact/hooks";

const burnOn = (): boolean => {
  const b = document.getElementById("burn");
  return b?.getAttribute("aria-pressed") === "true";
};

export function Gate(): JSX.Element {
  // full-screen pre-screen when the instance locks creates (CREATE_KEY)
  const err = useSignal<string>("");
  const unlock = async (): Promise<void> => {
    const res = await fetch("/api/gate", {
      method: "POST",
      headers: { Authorization: "Bearer " + ($("#gatepass") as HTMLInputElement).value },
    });
    if (res.status === 204) {
      siteKey.set(($("#gatepass") as HTMLInputElement).value);
      show("compose");
      return;
    }
    siteKey.clear();
    err.value = "Wrong passphrase.";
  };
  useEffect(() => {
    (async () => {
      try {
        const { enabled } = (await (await fetch("/api/gate")).json()) as { enabled: boolean };
        if (!enabled) return show("compose");
        const stored = siteKey.get();
        if (stored) {
          const res = await fetch("/api/gate", { method: "POST", headers: { Authorization: "Bearer " + stored } });
          if (res.status === 204) return show("compose");
        }
        err.value = "";
        show("gate");
      } catch {
        show("compose"); // server unreachable: the submit path reports
      }
    })();
  }, []);
  void $;
  void b64uFromBytes;
  return (
    <section id="gate" class={"card" + (view.value === "gate" ? "" : " hidden")}>
      <div class="hint big">This instance is passphrase-protected.</div>
      <div class="row">
        <input type="password" id="gatepass" placeholder="site passphrase" autocomplete="off" />
        <button class="primary" id="gatebtn" onClick={() => void unlock()}>Unlock</button>
      </div>
      {err.value !== "" && <div id="gateerr" class="hint danger">{err.value}</div>}
    </section>
  );
}

export function ComposeView(): JSX.Element {
  useEffect(() => {
    // session stash: redirect compose into the gate view if locked, once
    void (async () => {
      const res = await fetch("/api/gate");
      const j = (await res.json()) as { enabled: boolean };
      const stored = siteKey.get();
      if (j.enabled && !stored) show("gate");
      else if (view.value !== "linkbox") show("compose");
    })();
  }, []);
  const prog = uploadProgress.value;
  const files = picked.value;
  const ta = document.getElementById("text") as HTMLTextAreaElement | null;
  const hasSomething = !!ta?.value || files.length > 0;
  return (
    <section id="compose" class={"card" + (view.value === "compose" ? "" : " hidden")}>
      <textarea id="text" placeholder="Type or paste anything - text, passwords, snippets…" spellcheck={false} autofocus />
      <div id="dropzone" onClick={() => ($("#fileinput") as HTMLInputElement).click()}>
        <input type="file" id="fileinput" multiple class="hidden" onInput={(e) => {
          const fl = (e.target as HTMLInputElement).files;
          if (fl) picked.value = [...picked.value, ...Array.from(fl).filter((f) => f.size >= 0)];
          (e.target as HTMLInputElement).value = "";
        }} />
        <span>drop files here - or click to browse</span>
      </div>
      {files.length > 0 && (
        <div id="files">
          {files.map((f) => (
            <span class="chip">
              {f.name}
              <span class="chipsz">{humanSize(f.size)}</span>
              <button type="button" aria-label={"Remove " + f.name} onClick={() => {
                picked.value = picked.value.filter((k) => k !== f);
              }}>×</button>
            </span>
          ))}
        </div>
      )}
      {prog !== null && (
        <div id="prog">
          <div class="progwrap">
            <div id="progbar"><div id="progfill" style={"width:" + prog.pct + "%"} /></div>
            <span id="proglabel">
              {prog.phase === "encrypt" ? "encrypting…" : prog.phase === "finish" ? "finishing…" : "uploading " + prog.pct + "%"}
            </span>
            <button type="button" id="progcancel" onClick={() => compose_abort("cancel")}>Cancel</button>
          </div>
        </div>
      )}
      <div class="row burnrow">
        <div class="field">
          <label class="field-label" for="ttl">burn paste after</label>
          <input type="text" id="ttl" value="1d" aria-label="Burn time" autocomplete="off" autocapitalize="off" spellcheck={false} placeholder='e.g. "10 min", "6h", "1d"' />
        </div>
        <button type="button" class="toggle" id="burn" aria-pressed="false" onClick={(e) => {
          const b = e.currentTarget;
          b.setAttribute("aria-pressed", burnOn() ? "false" : "true");
        }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"></path></svg>
          burn after reading
        </button>
        <input type="password" id="pass" placeholder="optional passphrase - protects the link" autocomplete="new-password" />
      </div>
      <div class="row">
        <button class="primary" id="create" disabled={!hasSomething} onClick={() => void submit()}>Encrypt &amp; share</button>
      </div>
      {composeError.value !== "" && <div id="composeerr" class="hint danger">{composeError.value}</div>}
      <div class="hint">With a passphrase the link alone is useless; share it over a different channel. The passphrase never reaches the server.</div>
    </section>
  );
}

let activeAbort: AbortController | null = null;
let activeUploadId = "";

function compose_abort(msg: string): void {
  if (msg === "cancel") activeAbort?.abort();
}

async function submit(): Promise<void> {
  const ta = $("#text") as HTMLTextAreaElement;
  const text = ta.value;
  const btn = $("#create") as HTMLButtonElement;
  btn.disabled = true;
  uploadProgress.value = { pct: 0, phase: "encrypt" };
  activeAbort = new AbortController();
  try {
    const out =
      picked.value.length === 0
        ? await createPaste(text)
        : await uploadBundle({
            note: text,
            files: picked.value,
            ttl: ($("#ttl") as HTMLInputElement).value,
            burn: burnOn(),
            pass: ($("#pass") as HTMLInputElement).value,
            onProgress: (pct, phase) => (uploadProgress.value = { pct, phase }),
            onSession: (id) => (activeUploadId = id),
            signal: activeAbort.signal,
          });
    const link = location.origin + "/p/" + out.id + (out.keyB64 ? "#" + out.keyB64 : "");
    shareLink.value = link;
    shareIsPassphrase.value = !!out.pass;
    stashForCreate(out.id, out.keyB64);
    drawQR(link);
    composeError.value = "";
    picked.value = [];
    show("linkbox");
  } catch (e) {
    if (e && typeof e === "object" && "silent" in (e as Record<string, unknown>)) {
      return; // handled: gate reroute
    }
    if (activeUploadId) abortUpload(activeUploadId);
    composeError.value =
      e instanceof UploadAborted || activeAbort?.signal.aborted
        ? "Upload cancelled."
        : e instanceof Error
          ? e.message
          : "Failed to create paste.";
  } finally {
    activeAbort = null;
    activeUploadId = "";
    btn.disabled = false;
    uploadProgress.value = null;
  }
}

// create-gate passphrase: revealed only when the server answers 401;
// kept in sessionStorage (per tab), never localStorage, never a cookie.
async function createPaste(text: string): Promise<{ id: string; keyB64: string; pass: string }> {
  const pass = ($("#pass") as HTMLInputElement).value;
  let payload: string;
  let salt = "";
  let keyB64 = "";
  if (pass) {
    const s = crypto.getRandomValues(new Uint8Array(16));
    salt = b64uFromBytes(s);
    payload = await seal(await deriveKey(pass, s), text);
  } else {
    const k = await randomKey();
    payload = await seal(k.key, text);
    keyB64 = k.keyB64;
  }
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const site = siteKey.get();
  if (site) headers.Authorization = "Bearer " + site;
  const res = await fetch("/api/paste", {
    method: "POST",
    headers,
    body: JSON.stringify({ data: payload, salt, ttl: ($("#ttl") as HTMLInputElement).value, hl: true, burn: burnOn() }),
  });
  if (res.status === 401) {
    // stale or hand-forged site key: force the gate screen again
    siteKey.clear();
    show("gate");
    throw { silent: true };
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? res.statusText);
  }
  const id = ((await res.json()) as { id: string }).id;
  return { id, keyB64, pass };
}

export function LinkView(): JSX.Element {
  const showPass = shareIsPassphrase.value;
  return (
    <section id="linkbox" class={"card" + (view.value === "linkbox" ? "" : " hidden")}>
      <div class="hint">Share this link. The decryption key never leaves the browser.</div>
      {showPass && <div id="passnote" class="hint danger">This link is passphrase-protected - send the passphrase separately, not with the link.</div>}
      <div class="link-box">
        <input id="share" readonly title="Click the link to copy" value={shareLink.value} onClick={() => void copyShare(shareLink.value)} />
        <button id="copylink" onClick={() => void copyShare(shareLink.value)}>Copy</button>
        <button id="again" onClick={() => resetCompose()}>New paste</button>
      </div>
      <div class="qrwrap">
        <div id="qr" />
      </div>
    </section>
  );
}

async function copyShare(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    const btn = $("#copylink") as HTMLButtonElement;
    const old = btn.textContent ?? "";
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = old), 1200);
  } catch { /* unsupported: user selects manually */ }
}

function resetCompose(): void {
  ($("#text") as HTMLTextAreaElement).value = "";
  ($("#pass") as HTMLInputElement).value = "";
  composeError.value = "";
  show("compose");
  ($("#text") as HTMLTextAreaElement).focus();
}
