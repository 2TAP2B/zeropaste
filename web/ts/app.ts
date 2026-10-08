import { $ } from "./dom";
import { randomKey, deriveKey, seal, siteKey, b64uFromBytes } from "./crypto";
import { show, copy, drawQR, humanSize } from "./ui";
import { initTheme } from "./theme";
import { readView } from "./read";
import { uploadBundle, abortUpload, UploadAborted } from "./uploads";
import { selfcheck } from "./selfcheck";
import { bootAccount, stashForCreate } from "./account";

const burnOn = (): boolean => $("burn").getAttribute("aria-pressed") === "true";
$("burn").addEventListener("click", () =>
  $("burn").setAttribute("aria-pressed", burnOn() ? "false" : "true"),
);

// ---- file attachments ----
let picked: File[] = [];
const dropzone = $("dropzone") as HTMLElement;
const fileinput = $("fileinput") as HTMLInputElement;

function addFiles(list: FileList | File[]): void {
  const incoming = Array.from(list).filter((f) => f.size >= 0);
  for (const f of incoming) if (!picked.some((k) => k === f)) picked.push(f);
  renderChips();
}

function renderChips(): void {
  const box = $("files") as HTMLElement;
  box.textContent = "";
  for (const f of picked) {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = f.name;
    const size = document.createElement("span");
    size.className = "chipsz";
    size.textContent = humanSize(f.size);
    const x = document.createElement("button");
    x.type = "button";
    x.setAttribute("aria-label", "Remove " + f.name);
    x.textContent = "×";
    x.addEventListener("click", () => {
      picked = picked.filter((k) => k !== f);
      renderChips();
    });
    chip.append(size, x);
    box.append(chip);
  }
  box.classList.toggle("hidden", picked.length === 0);
  // textarea repurposes as the note field when files ride along
  ($("text") as HTMLTextAreaElement).placeholder = picked.length
    ? "Optional note - shown above the files"
    : "Type or paste anything - text, passwords, snippets…";
}

dropzone.addEventListener("click", () => fileinput.click());
fileinput.addEventListener("change", () => {
  if (fileinput.files) addFiles(fileinput.files);
  fileinput.value = "";
});
dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("drag");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("drag");
  if (e.dataTransfer?.files.length) addFiles(e.dataTransfer.files);
});

// submit enabled iff there is something to share
function validateReady(): void {
  const ta = $("text") as HTMLTextAreaElement;
  ($("create") as HTMLButtonElement).disabled = !ta.value && picked.length === 0;
}
$("text").addEventListener("input", validateReady);

// create-gate passphrase: revealed only when the server answers 401;
// kept in sessionStorage (per tab), never localStorage, never a cookie.
async function createPaste(text: string): Promise<{ id: string; keyB64: string; pass: string }> {
  const pass = ($("pass") as HTMLInputElement).value;
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
    body: JSON.stringify({ data: payload, salt, ttl: ($("ttl") as HTMLInputElement).value, hl: true, burn: burnOn() }),
  });
  if (res.status === 401) {
    // stale or hand-forged site key: force the gate screen again
    siteKey.clear();
    show("gate");
    const err = $("gateerr");
    err.textContent = "Site passphrase was rejected - unlock again.";
    err.classList.remove("hidden");
    throw { silent: true };
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? res.statusText);
  }
  const id = ((await res.json()) as { id: string }).id;
  return { id, keyB64, pass };
}

let activeAbort: AbortController | null = null;
let activeUploadId = "";

$("create").addEventListener("click", async () => {
  const ta = $("text") as HTMLTextAreaElement;
  const text = ta.value;
  if (!text && picked.length === 0) {
    ta.focus();
    return;
  }
  const btn = $("create") as HTMLButtonElement;
  btn.disabled = true;
  $("prog").classList.remove("hidden");
  const fill = document.getElementById("progfill") as HTMLElement;
  const label = document.getElementById("proglabel") as HTMLElement;
  const progress = (pct: number, phase: "encrypt" | "upload" | "finish"): void => {
    fill.style.width = pct + "%";
    label.textContent =
      phase === "encrypt" ? "encrypting…" : phase === "finish" ? "finishing…" : "uploading " + pct + "%";
  };
  activeAbort = new AbortController();
  progress(0, "encrypt");
  try {
    const out =
      picked.length === 0
        ? await createPaste(text)
        : await uploadBundle({
            note: text,
            files: picked,
            ttl: ($("ttl") as HTMLInputElement).value,
            burn: burnOn(),
            pass: ($("pass") as HTMLInputElement).value,
            onProgress: progress,
            onSession: (id) => (activeUploadId = id),
            signal: activeAbort.signal,
          });
    const link = location.origin + "/p/" + out.id + (out.keyB64 ? "#" + out.keyB64 : "");
    ($("share") as HTMLInputElement).value = link;
    stashForCreate(out.id, out.keyB64); // dashboard rows re-open via locally stashed fragments
    ($("passnote") as HTMLElement).classList.toggle("hidden", !out.pass);
    drawQR(link);
    $("composeerr").classList.add("hidden");
    picked = [];
    renderChips();
    show("linkbox");
  } catch (e) {
    if (e && typeof e === "object" && "silent" in e) return; // handled: gate reroute
    if (activeUploadId) abortUpload(activeUploadId); // cancel: kill the temp session
    const err = $("composeerr");
    err.textContent =
      e instanceof UploadAborted || activeAbort?.signal.aborted
        ? "Upload cancelled."
        : e instanceof Error
          ? e.message
          : "Failed to create paste.";
    err.classList.remove("hidden");
  } finally {
    activeAbort = null;
    activeUploadId = "";
    btn.disabled = false;
    validateReady();
    $("prog").classList.add("hidden");
  }
});

$("progcancel").addEventListener("click", () => {
  activeAbort?.abort();
});

// gate screen: shown before the app when this instance has a create gate;
// unlocking is verified against POST /api/gate, then kept per tab (sessionStorage).
async function gateFlow(): Promise<void> {
  initTheme();
  try {
    const { enabled } = (await (await fetch("/api/gate")).json()) as { enabled: boolean };
    if (!enabled) return show("compose");
    const stored = siteKey.get();
    const unlock = async (key: string): Promise<void> => {
      const res = await fetch("/api/gate", { method: "POST", headers: { Authorization: "Bearer " + key } });
      if (res.status === 204) {
        siteKey.set(key);
        ($("create") as HTMLButtonElement).disabled = false;
        show("compose");
        return;
      }
      siteKey.clear();
      const err = $("gateerr");
      err.textContent = "Wrong passphrase.";
      err.classList.remove("hidden");
      const pass = $("gatepass") as HTMLInputElement;
      pass.value = "";
      pass.select();
    };
    $("gatebtn").addEventListener("click", () => void unlock(($("gatepass") as HTMLInputElement).value));
    $("gatepass").addEventListener("keydown", (e) => {
      if (e.key === "Enter") void unlock(($("gatepass") as HTMLInputElement).value);
    });
    if (stored) {
      const res = await fetch("/api/gate", { method: "POST", headers: { Authorization: "Bearer " + stored } });
      if (res.status === 204) return show("compose");
      const err = $("gateerr");
      err.textContent = "Wrong passphrase.";
      err.classList.remove("hidden");
      const pass = $("gatepass") as HTMLInputElement;
      pass.value = "";
      pass.select();
      return show("gate");
    }
    return show("gate");
  } catch {
    return show("compose"); // server unreachable; let the submit path handle errors
  }
}

// the link itself is the affordance: tap it to copy
$("share").addEventListener("click", () => void copy(($("share") as HTMLInputElement).value, $("copylink")));
$("copylink").addEventListener("click", () => void copy(($("share") as HTMLInputElement).value, $("copylink")));
$("again").addEventListener("click", () => {
  ($("text") as HTMLTextAreaElement).value = "";
  $("burn").setAttribute("aria-pressed", "false");
  ($("pass") as HTMLInputElement).value = "";
  $("composeerr").classList.add("hidden");
  show("compose");
  ($("text") as HTMLTextAreaElement).focus();
});
$("text").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") $("create").click();
});

// quick-start popover copy buttons (popover itself opens with zero JS)
document.querySelectorAll<HTMLButtonElement>("[data-copy]").forEach((btn) => {
  const src = document.getElementById(btn.getAttribute("data-copy") ?? "") as HTMLElement | null;
  if (src) btn.addEventListener("click", () => void copy(src.textContent ?? "", btn));
});

if (location.search.includes("selfcheck")) {
  document.body.textContent = "";
  const preEl = document.createElement("pre");
  preEl.id = "selfout";
  document.body.appendChild(preEl);
  void selfcheck();
} else if (location.pathname.startsWith("/p/")) {
  initTheme();
  readView();
  void bootAccount(); // /p pages share the header: the account chip must reflect the session too
} else {
  void gateFlow();
  void bootAccount();
}
