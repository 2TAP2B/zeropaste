export function $ (id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
}

export const enc = new TextEncoder();
export const dec = new TextDecoder();
