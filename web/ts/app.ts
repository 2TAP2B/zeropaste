import { $ } from "./dom";
import { randomKey, deriveKey, seal, siteKey, b64uFromBytes } from "./crypto";
import { show, copy, drawQR } from "./ui";
import { initTheme } from "./theme";
import { readView } from "./read";

const burnOn = (): boolean => $("burn").getAttribute("aria-pressed") === "true";
$("burn").addEventListener("click", () =>
  $("burn").setAttribute("aria-pressed", burnOn() ? "false" : "true"),
);

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

$("create").addEventListener("click", async () => {
  const ta = $("text") as HTMLTextAreaElement;
  const text = ta.value;
  if (!text) {
    ta.focus();
    return;
  }
  const btn = $("create") as HTMLButtonElement;
  btn.disabled = true;
  try {
    const out = await createPaste(text);
    const link = location.origin + "/p/" + out.id + (out.keyB64 ? "#" + out.keyB64 : "");
    ($("share") as HTMLInputElement).value = link;
    ($("passnote") as HTMLElement).classList.toggle("hidden", !out.pass);
    drawQR(link);
    $("composeerr").classList.add("hidden");
    show("linkbox");
  } catch (e) {
    if (e && typeof e === "object" && "silent" in e) return; // handled: gate reroute
    const err = $("composeerr");
    err.textContent = e instanceof Error ? e.message : "Failed to create paste.";
    err.classList.remove("hidden");
  } finally {
    btn.disabled = false;
  }
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

if (location.pathname.startsWith("/p/")) {
  initTheme();
  readView();
} else {
  void gateFlow();
}
