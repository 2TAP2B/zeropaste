import type { JSX } from "preact";
import { useSignal } from "@preact/signals";
import { useEffect } from "preact/hooks";
import { sessionName } from "./state";
import { openShareTarget, registerStart } from "./account";
import { humanSize } from "./ui";
import { $ } from "./dom";

// The real dashboard: /dash. Detailed rows per active share - id link, kind,
// views counter, alive countdown and a copy-link button. Identity edit below.

interface ShareRow {
  id: string;
  kind: "text" | "bundle";
  burn: boolean;
  expires: number;
  views?: number;
}

function expiryText(unixSec: number): string {
  const ms = unixSec * 1000 - Date.now();
  if (!(ms > 0)) return "already expired";
  const min = Math.round(ms / 60000);
  if (min < 60) return `in ${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `in ${h} h`;
  return `in ${Math.round(h / 24)} d`;
}

export function DashPage(): JSX.Element {
  const rows = useSignal<ShareRow[]>([]);
  const loadErr = useSignal("");
  const load = async (): Promise<void> => {
    try {
      const [meRes, shareRes] = [await fetch("/api/me"), await fetch("/api/shares")];
      const me = (await meRes.json()) as { name?: string };
      if (!me.name) {
        rows.value = [];
        loadErr.value = "Sign in first - the dashboard lists your own shares.";
        return;
      }
      sessionName.value = me.name;
      loadErr.value = "";
      rows.value = ((await shareRes.json()) as ShareRow[]) ?? [];
    } catch {
      loadErr.value = "Could not load shares.";
    }
  };
  useEffect(() => {
    void load();
  }, []);
  const signed = !!sessionName.value;

  const editName = async (): Promise<void> => {
    try {
      const res = await fetch("/api/identity/name", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: ($("#dashname") as HTMLInputElement).value }),
      });
      if (!res.ok) {
        throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "name save failed");
      }
      void load();
    } catch (e) {
      loadErr.value = e instanceof Error ? e.message : "name save failed";
    }
  };

  return (
    <section id="dashfull" class="card">
      <h2 class="dashtitle">{signed ? sessionName.value : "your active shares"}</h2>
      {loadErr.value && <div class="hint danger">{loadErr.value}</div>}
      {signed && rows.value.length === 0 && !loadErr.value && (
        <div class="hint">Nothing active yet - share a paste or file bundle while signed in.</div>
      )}
      {rows.value.map((r) => (
        <div class="srow" key={r.id}>
          <a href={openShareTarget(r.id)}>{"/p/" + r.id.slice(0, 6) + "…"}</a>
          <span class="skind">{r.kind === "bundle" ? "files" : "text"}</span>
          <span class="susers">{(r.views ?? 0) + " views"}</span>
          <span class="swhen">{r.burn ? "" : expiryText(r.expires)}</span>
          <button
            type="button"
            class="rowcopy"
            aria-label="Copy share link"
            onClick={(e) => {
              void copyLink(r, e.currentTarget);
            }}
          >
            copy link
          </button>
        </div>
      ))}
      {signed && (
        <div class="dashedit">
          <b>account</b>
          <div class="accrow">
            <input type="text" id="dashname" maxlength={64} placeholder="display name" autocomplete="off" value={sessionName.value} />
            <button type="button" id="dashsave" onClick={() => void editName()}>Save name</button>
            <button type="button" id="dashreg" onClick={() => void registerStart(($("dashname") as HTMLInputElement).value)}>Add passkey</button>
          </div>
          <div class="hint">Adding a passkey opens your browser's authenticator - fingerprint/pin/YubiKey.</div>
        </div>
      )}
    </section>
  );
}

async function copyLink(r: ShareRow, btn: HTMLButtonElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(location.origin + openShareTarget(r.id));
    btn.textContent = "copied!";
    setTimeout(() => (btn.textContent = "copy link"), 1200);
  } catch { /* manual fallback */ }
}

// re-export for app-level image preview consumers
export { humanSize };
