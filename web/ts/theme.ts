import { $ } from "./dom";

export type Theme = "light" | "dark";

export function applyTheme(t: Theme): void {
  document.documentElement.dataset.theme = t;
  try {
    localStorage.setItem("zp.theme", t); // UI preference, not paste data
  } catch {
    /* private mode: session-only */
  }
  const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (meta) meta.content = t === "light" ? "#a78bfa" : "#1c1917";
  for (const el of [
    { id: "hljs-light", theme: "light" },
    { id: "hljs-dark", theme: "dark" },
  ]) {
    const link = document.getElementById(el.id) as HTMLLinkElement | null;
    if (link) link.media = el.theme === t ? "all" : "not all";
  }
}

export function initTheme(): void {
  let saved: string | null = null;
  try {
    saved = localStorage.getItem("zp.theme");
  } catch {
    /* private mode */
  }
  const preferred: Theme =
    saved === "light" || saved === "dark"
      ? saved
      : matchMedia("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark";
  applyTheme(preferred);
  $("theme").addEventListener("click", () => {
    const cur = document.documentElement.dataset.theme;
    applyTheme(cur === "light" ? "dark" : "light");
  });
}
