import { signal } from "@preact/signals";

// Shared app state: one signal per axis of the formerly hand-rolled show()/
// hidden-class choreography. Components read these; only the flows write.

export type View = "gate" | "compose" | "linkbox" | "read";

export const view = signal<View>("compose");

export function show(v: View): void {
  view.value = v;
  window.scrollTo(0, 0);
}

// session (account) state
export const sessionName = signal<string>("");
export const regOpen = signal<boolean>(true);
export const insecureOrigin = signal<boolean>(
  !window.isSecureContext && !location.hostname.includes("localhost") && !location.hostname.includes("127.0.0.1"),
);

// compose state
export const picked = signal<File[]>([]);
export const uploadProgress = signal<{ pct: number; phase: "encrypt" | "upload" | "finish" } | null>(null);
export const composeError = signal<string>("");
export const shareLink = signal<string>("");
export const shareIsPassphrase = signal<boolean>(false);

// read state
export interface ManifestFile {
  name: string;
  mime: string;
  size: number;
  iv: string;
}

export interface BundleState {
  id: string;
  key: CryptoKey;
  mlen: number;
  manifest: { note?: string; files: ManifestFile[] };
  start: number; // payload base offset
}

export const readBundle = signal<BundleState | null>(null);
export const readText = signal<{ text: string; hl: boolean } | null>(null);
export const readBurnInfo = signal<{ burned: boolean; expires?: number }>({ burned: false });
export const linkError = signal<string>("");

// theme (zp.theme) is handled in app/theme.ts.
