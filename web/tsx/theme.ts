import { signal } from "@preact/signals";
import type { Theme } from "./types";

export const theme = signal<Theme>(
  (() => {
    try {
      const saved = localStorage.getItem("zp.theme");
      if (saved === "light" || saved === "dark") return saved;
    } catch {
      /* private mode */
    }
    return matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  })(),
);

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
  theme.value = t;
}

export function toggleTheme(): void {
  applyTheme(theme.value === "light" ? "dark" : "light");
}
