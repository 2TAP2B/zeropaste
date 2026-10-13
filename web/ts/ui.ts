import { $ } from "./dom";

export function humanSize(n: number): string {
  if (n < 1024) return n + " B";
  const units = ["KB", "MB", "GB"];
  let v = n;
  let u = 0; // divisions done: 1 = KB, 2 = MB, 3 = GB
  while (v >= 1024 && u < units.length) {
    v /= 1024;
    u++;
  }
  return (v >= 10 ? Math.round(v) : Math.round(v * 10) / 10) + " " + units[u - 1];
}

export function show(id: "gate" | "compose" | "linkbox" | "read"): void {
  for (const s of ["gate", "compose", "linkbox", "read"]) {
    $(s).classList.toggle("hidden", s !== id);
  }
  window.scrollTo(0, 0);
}

// clipboard helper; copies and flashes the trigger. Icon buttons (any SVG
// content) swap the glyph for a check and back - a textContent write would
// destroy the icon permanently.
export async function copy(text: string, btn: HTMLElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return; // unsupported: user selects manually
  }
  if (btn.querySelector("svg") !== null) {
    const old = btn.innerHTML;
    btn.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    btn.classList.add("copied");
    setTimeout(() => {
      btn.innerHTML = old;
      btn.classList.remove("copied");
    }, 1200);
  } else {
    const old = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => {
      if (old !== null) btn.textContent = old;
    }, 1200);
  }
}

export function drawQR(text: string): void {
  const box = $("qr");
  box.textContent = "";
  if (typeof qrcode !== "function") return;
  const qr = qrcode(0, "M"); // type 0 = auto size, M = medium error correction
  qr.addData(text);
  qr.make();
  box.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0 });
}
