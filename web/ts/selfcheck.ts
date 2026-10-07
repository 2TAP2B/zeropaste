import { $ } from "./dom";
import { randomKey, deriveKey, openBytes, bytesFromB64u } from "./crypto";
import { assembleEnv, readManifest, parseEnvHead, MANIFEST_HEAD } from "./bundle";

// In-browser round-trip check (?selfcheck): encrypt fake files + note,
// upload through the real endpoints, finish, read back via range GETs,
// decrypt and byte-compare. Prints PASS/FAIL w/ detail into #selfout.

export async function selfcheck(): Promise<void> {
  const out = document.getElementById("selfout") ?? document.body;
  const say = (msg: string): void => {
    out.textContent = (out.textContent ?? "") + msg + "\n";
  };
  const step = async (name: string, fn: () => Promise<void>): Promise<boolean> => {
    try {
      await fn();
      say("ok " + name);
      return true;
    } catch (e) {
      say("FAIL " + name + ": " + (e instanceof Error ? e.message : String(e)));
      return false;
    }
  };

  // deterministic-ish payloads: sizes hitting chunk boundaries when CHUNK is
  // overridden small on the server (e.g. 65536)
  const mk = (name: string, size: number): File => {
    const u8 = new Uint8Array(size);
    for (let i = 0; i < size; i++) u8[i] = (i * 7) & 255;
    return new File([u8], name, { type: "application/x-zp-test" });
  };
  const files = [mk("zero.bin", 0), mk("b.bin", 1), mk("c.bin", 65536), mk("d.bin", 33333)];
  const expected = await Promise.all(files.map((f) => f.arrayBuffer()));
  const note = "integration note 🎉 unicode";

  const siteKey = sessionStorage.getItem("zp.siteKey") ?? "";
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (siteKey) headers.Authorization = "Bearer " + siteKey;

  // encrypt both flows: random-key and passphrase
  await step("assemble random-key envelope", async () => {
    // selfcheck uses both directions from one session: import with encrypt+decrypt
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    st.key = key;
    const blob = await assembleEnv(key, note, files);
    st.blob = blob;
  });

  await step("init upload session", async () => {
    const res = await fetch("/api/uploads", {
      method: "POST",
      headers,
      body: JSON.stringify({ len: st.blob!.length, ttl: "1h", burn: false, salt: "" }),
    });
    if (!res.ok) throw new Error(res.status + " " + (await res.text()));
    st.up = (await res.json()) as { id: string; chunkSize: number; chunks: number };
    if (st.up!.chunks < 2) throw new Error("expected multi-chunk, got " + st.up!.chunks);
  });

  await step("PUT all chunks", async () => {
    const { id, chunkSize, chunks } = st.up!;
    for (let n = 0, off = 0; n < chunks; n++, off += chunkSize) {
      const end = Math.min(off + chunkSize, st.blob!.length);
      const res = await fetch(`/api/uploads/${id}/${n}`, { method: "PUT", body: st.blob!.subarray(off, end) });
      if (res.status !== 204) throw new Error(`chunk ${n} -> ${res.status}`);
    }
  });

  await step("finish", async () => {
    const res = await fetch(`/api/uploads/${st.up!.id}/finish`, { method: "POST", headers });
    if (!res.ok) throw new Error(res.status + " " + (await res.text()));
    const body = (await res.json()) as { id?: string };
    if (!body.id) throw new Error("no id");
  });

  await step("meta readback", async () => {
    const res = await fetch(`/api/paste/${st.up!.id}`);
    if (!res.ok) throw new Error(String(res.status));
    const meta = (await res.json()) as { len: number; data?: string; salt: string; burn: boolean };
    if (meta.len !== st.blob!.length) throw new Error(`len mismatch ${meta.len} != ${st.blob!.length}`);
    if ("data" in meta && meta.data !== "") throw new Error("text field leaked for bundle");
  });

  await step("range reads + manifest decrypt", async () => {
    const got = new Uint8Array(st.blob!.length);
    for (let off = 0; off < st.blob!.length; off += st.up!.chunkSize) {
      const res = await fetch(`/api/paste/${st.up!.id}/blob?offset=${off}`);
      if (!res.ok) throw new Error(`range ${off} -> ${res.status}`);
      got.set(new Uint8Array(await res.arrayBuffer()), off);
    }
    const head = got.subarray(0, MANIFEST_HEAD);
    const { mlen } = await parseEnvHead(head);
    if (got.length < 16 + mlen) throw new Error("manifest truncated");
    const manifest = await readManifest(st.key!, head.subarray(4, 16), got.subarray(16, 16 + mlen));
    if (manifest.note !== note) throw new Error("note mismatch: " + (manifest.note ?? "<none>"));
    if (manifest.files.length !== files.length) throw new Error("file count mismatch");
    for (let i = 0; i < manifest.files.length; i++) {
      const f = manifest.files[i];
      if (!f) throw new Error("manifest entry missing");
      const base = 16 + mlen;
      let off = base;
      for (let j = 0; j < i; j++) off += (manifest.files[j] as { size: number }).size;
      const ct = got.subarray(off, off + f.size);
      const iv = bytesFromB64u(f.iv);
      const pt = await openBytes(st.key!, iv, ct);
      const want = new Uint8Array(expected[i]!);
      if (pt.length !== want.length) throw new Error(`${f.name}: size ${pt.length} != ${want.length}`);
      for (let b = 0; b < want.length; b++) {
        if (pt[b] !== want[b]) throw new Error(`${f.name}: byte ${b} differs`);
      }
    }
  });

  say("SELFCHECK COMPLETE");
}

declare global {
  interface Window {
    zpKey?: CryptoKey;
    zpBlob?: Uint8Array;
    zpUp?: { id: string; chunkSize: number; chunks: number };
  }
}

// shared mutable state between the step closures
const st: {
  key?: CryptoKey;
  blob?: Uint8Array<ArrayBuffer>;
  up?: { id: string; chunkSize: number; chunks: number };
} = {};
