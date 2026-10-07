import { $ } from "./dom";

export function show(id: "gate" | "compose" | "linkbox" | "read"): void {
  for (const s of ["gate", "compose", "linkbox", "read"]) {
    $(s).classList.toggle("hidden", s !== id);
  }
  window.scrollTo(0, 0);
}

// clipboard helper; copies and flashes the trigger
export async function copy(text: string, btn: HTMLElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    if (btn.classList.contains("copybtn")) {
      const old = btn.innerHTML;
      btn.innerHTML =
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
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
  } catch {
    /* unsupported: user selects manually */
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
