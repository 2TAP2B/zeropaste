import { sealBytes, openBytes, b64uFromBytes, AesKey, Sealed } from "./crypto";
import { enc, dec } from "./dom";

// Bundle envelope framing (client-only; server stores opaque bytes):
//   u32le(manifestCtLen) | manifestIv(12) | manifestCt | file1Ct | file2Ct | ...
// manifest plaintext: {note?, files: [{name, mime, size(ct+tag), iv}]}
// The manifest's own IV lives outside its ciphertext so a reader can validate
// the link by decrypting just the head, before touching the file ranges.

export interface ManifestFile {
  name: string;
  mime: string;
  size: number; // ciphertext size incl. 16-byte GCM tag
  iv: string; // b64u
}

export interface Manifest {
  note?: string;
  files: ManifestFile[];
}

export const ENV_TAG = 16; // GCM tag size
export const MANIFEST_HEAD = 4 + 12; // u32 length + manifest IV

export function u32le(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

export async function assembleEnv(
  key: AesKey,
  note: string,
  files: File[],
): Promise<Uint8Array<ArrayBuffer>> {
  const encs: Sealed[] = [];
  for (const f of files) {
    const data = new Uint8Array(await f.arrayBuffer());
    encs.push(await sealBytes(key, data));
  }
  const manifest: Manifest = {
    note: note || undefined,
    files: files.map((f, i) => {
      const e = encs[i];
      if (!e) throw new Error("internal: encryption result missing");
      return {
        name: f.name,
        mime: f.type || "application/octet-stream",
        size: e.ct.length,
        iv: b64uFromBytes(e.iv),
      };
    }),
  };
  const ms = await sealBytes(key, enc.encode(JSON.stringify(manifest)));
  const pre = new Uint8Array(4 + 12 + ms.ct.length);
  pre.set(u32le(ms.ct.length), 0);
  pre.set(ms.iv, 4);
  pre.set(ms.ct, 16);
  const parts: Uint8Array<ArrayBuffer>[] = [pre, ...encs.map((e) => e.ct)];
  return concatBytes(parts);
}

export function concatBytes(parts: Uint8Array<ArrayBuffer>[]): Uint8Array<ArrayBuffer> {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export async function parseEnvHead(
  head: Uint8Array<ArrayBuffer>, // first 4+12 bytes minimum
): Promise<{ mlen: number; manifestStart: number }> {
  if (head.length < 4) throw new Error("bundle head short");
  const mlen = new DataView(head.buffer, head.byteOffset, head.byteLength).getUint32(0, true);
  return { mlen, manifestStart: 16 };
}

export async function readManifest(
  key: AesKey,
  headIv: Uint8Array<ArrayBuffer>,
  manifestCt: Uint8Array<ArrayBuffer>,
): Promise<Manifest> {
  const plain = await openBytes(key, headIv, manifestCt);
  return JSON.parse(dec.decode(plain)) as Manifest;
}
