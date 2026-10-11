import { $ } from "./dom";
import { uploadBundle, abortUpload, UploadAborted } from "./uploads";
import { humanSize } from "./ui";
import { deriveKey, open_, bytesFromB64u, importKeyB64u, AesKey } from "./crypto";

// /r/<slug>#<keyB64>: the sender-facing reverse upload page. The slug picks
// the inbox, the fragment key is required - uploads are encrypted client-side
// with it, so nothing new reaches the server: same contract as every paste.
let picked: File[] = [];
let activeAbort: AbortController | null = null;
let activeUpload = "";
let rslug = "";

function rshow(id: string): void {
  for (const sid of ["gate", "compose", "linkbox", "read", "dashroot"]) $(sid).classList.add("hidden");
  ($(id) as HTMLElement).classList.remove("hidden");
}

function rfail(msg: string): void {
  ($("rfailmsg") as HTMLElement).textContent = msg;
  $("rfail").classList.remove("hidden");
  $("rbody").classList.add("hidden");
}

// the remaining inbox lifetime becomes the file TTL so uploads never die
// before the collector checks the inbox; parsed again server-side
function ttlFor(expires: number): string {
  const secs = Math.max(60, expires - Math.floor(Date.now() / 1000));
  if (secs >= 48 * 3600) return Math.min(Math.floor(secs / 86400), 365) + "d";
  return Math.max(1, Math.ceil(secs / 3600)) + "h";
}

function renderChips(): void {
  const box = $("rfiles") as HTMLElement;
  box.textContent = "";
  for (const f of picked) {
    const chip = document.createElement("span");
    chip.className = "chip";
    const label = document.createElement("span");
    label.textContent = f.name;
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
    chip.append(label, size, x);
    box.append(chip);
  }
  box.classList.toggle("hidden", picked.length === 0);
  const ok = picked.length > 0;
  ($("rsend") as HTMLButtonElement).disabled = !ok;
}

function addFiles(list: FileList | File[]): void {
  const total = picked.reduce((a, f) => a + f.size, 0);
  for (const f of list) {
    picked.push(f);
  }
  renderChips();
}

export async function reverseView(): Promise<void> {
  rshow("rshare");
  const raw = decodeURIComponent(location.pathname.slice(3));
  if (!/^[a-z0-9_-]{3,32}$/.test(raw)) {
    rfail("This link has no usable slug. Ask the collector for the intact drop link.");
    return;
  }
  rslug = raw;
  const keyB64 = location.hash.slice(1);
  let meta: { maxSize: number; expires: number; salt?: string; check?: string };
  try {
    meta = (await (await fetch("/api/rshare/" + rslug)).json()) as { maxSize: number; expires: number; salt?: string; check?: string };
  } catch {
    rfail("The collector could not be reached.");
    return;
  }
  if (!meta || !meta.maxSize) {
    rfail("No reverse share with this slug exists (or it expired).");
    return;
  }
  if (keyB64 && meta.salt) {
    rfail("This drop link is passphrase-protected - open it WITHOUT the # part and use the collector's passphrase.");
    return;
  }
  const cap = meta.maxSize;
  const expires = new Date(meta.expires * 1000);
  $("rmeta").textContent =
    "files up to " + humanSize(cap) + " · link lives until " + expires.toLocaleDateString() + " " + expires.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  // passphrase uplinks: unlock first - the AES key derives locally from the
  // passphrase + public salt and is verified against the sealed check token
  if (meta.salt) {
    if (keyB64) {
      rfail("This drop link is passphrase-protected - open it without the # part and use the collector's passphrase.");
      return;
    }
    history.replaceState(null, "", location.pathname);
    const unlock = $("runlock") as HTMLElement;
    unlock.classList.remove("hidden");
    const passIn = $("runlockpass") as HTMLInputElement;
    passIn.focus();
    const tryUnlock = async (): Promise<void> => {
      const err = $("runlockerr") as HTMLElement;
      err.classList.add("hidden");
      const key = await deriveKey(passIn.value, bytesFromB64u(meta.salt as string));
      let ok = false;
      try {
        ok = (await open_(meta.check as string, key)) === "zeropaste-rshare";
      } catch {
        ok = false; // malformed verifier or wrong key
      }
      if (!ok) {
        err.textContent = "Wrong passphrase.";
        err.classList.remove("hidden");
        passIn.select();
        return;
      }
      unlock.classList.add("hidden");
      await startBody(key, meta.expires, cap, meta.salt as string);
    };
    $("runlockbtn").addEventListener("click", () => void tryUnlock());
    passIn.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void tryUnlock();
    });
    return;
  }
  if (keyB64) {
    // fragment mode: validate the key shape, then strip it from the bar
    if (!/^[A-Za-z0-9_-]{10,}$/.test(keyB64)) {
      rfail("This drop link lost its decryption key - only the intact link (with the part after #) can upload.");
      return;
    }
    history.replaceState(null, "", location.pathname);
    await startBody(await importKeyB64u(keyB64), meta.expires, cap);
    return;
  }
  rfail("This drop link lost its decryption key - only the intact link (with the part after #) can upload.");
}

// drop card: listeners + send pipeline; key arrives unlocked (imported or
// passphrase-derived), salt is set when the pass came from the passphrase flow
async function startBody(key: AesKey, expires: number, cap: number, salt?: string): Promise<void> {
  const drop = $("rdrop") as HTMLElement;
  const fileinput = $("rfileinput") as HTMLInputElement;
  drop.addEventListener("click", () => fileinput.click());
  fileinput.addEventListener("change", () => {
    addFiles(fileinput.files ?? []);
    fileinput.value = ""; // re-drop support
  });
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("drag");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("drag");
    if (e.dataTransfer?.files.length) addFiles(e.dataTransfer.files);
  });
  renderChips();

  $("rprogcancel").addEventListener("click", () => {
    activeAbort?.abort();
  });

  ($("rsend") as HTMLButtonElement).addEventListener("click", () => {
    if (activeUpload) return; // one in flight
    const err = $("rror") as HTMLElement;
    err.classList.add("hidden");
    const total = picked.reduce((a, f) => a + f.size, 0);
    if (picked.length === 0) return;
    if (total > cap) {
      err.textContent = "combined file size exceeds the drop cap (" + humanSize(cap) + ").";
      err.classList.remove("hidden");
      return;
    }
    const send = $("rsend") as HTMLButtonElement;
    const prog = $("rprog") as HTMLElement;
    const fill = $("rprogfill") as HTMLElement;
    const label = $("rproglabel") as HTMLElement;
    send.disabled = true;
    prog.classList.remove("hidden");
    const ac = new AbortController();
    activeAbort = ac;
    void (async () => {
      try {
        label.textContent = "encrypting…";
        const res = await uploadBundle({
          note: "",
          files: picked,
          ttl: ttlFor(expires),
          burn: false,
          pass: "",
          preKey: key,
          preSalt: salt,
          signal: ac.signal,
          onProgress: (pct, phase) => {
            fill.style.width = pct + "%";
            label.textContent = phase === "encrypt" ? "encrypting…" : "uploading " + pct + "%";
          },
          onSession: (uploadId) => {
            activeUpload = uploadId; // enables abort/cleanup of the temp session
          },
        });
        label.textContent = "finishing…";
        const reg = await fetch("/api/rshare/" + rslug + "/in", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: res.id }),
        });
        if (!reg.ok) {
          const e = ((await reg.json().catch(() => ({}))) as { error?: string }).error ?? "registration failed";
          throw new Error(e);
        }
        picked = [];
        renderChips();
        prog.classList.add("hidden");
        fill.style.width = "0";
        const done = $("rdone") as HTMLElement;
        done.textContent = "Delivered - the collector has it now.";
        done.classList.remove("hidden");
        setTimeout(() => done.classList.add("hidden"), 6000);
      } catch (e) {
        prog.classList.add("hidden");
        fill.style.width = "0";
        picked = [];
        renderChips();
        if (activeUpload) abortUpload(activeUpload); // clean half-uploaded session
        if (e instanceof UploadAborted) {
          // cancelled: silent reset, the button stays ready
        } else {
          err.textContent = e instanceof Error ? e.message : "upload failed";
          if (err.textContent) err.classList.remove("hidden");
        }
      } finally {
        send.disabled = false;
        activeUpload = "";
        activeAbort = null;
      }
    })();
  });

  $("rbody").classList.remove("hidden");
}
