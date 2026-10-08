import type { JSX } from "preact";
import { useSignal } from "@preact/signals";
import { useEffect } from "preact/hooks";
import { assembleEnv, readManifest } from "./bundle";
import { bytesFromB64u, openBytes } from "./crypto";

// In-browser integration check (?selfcheck): encrypt fake files + a note,
// upload through the real endpoints, finish, read back via range GETs,
// decrypt and byte-compare. Renders PASS/FAIL per step.

const st: {
  key?: CryptoKey;
  blob?: Uint8Array<ArrayBuffer>;
  up?: { id: string; chunkSize: number; chunks: number };
} = {};

export function SelfCheck(): JSX.Element {
  const log = useSignal<string[]>([]);
  const done = useSignal(false);

  useEffect(() => {
    void (async () => {
      st.key = undefined;
      st.blob = undefined;
      st.up = undefined;
      const step = async (name: string, fn: () => Promise<void>): Promise<boolean> => {
        try {
          await fn();
          log.value = [...log.value, "ok " + name];
          return true;
        } catch (e) {
          log.value = [...log.value, "FAIL " + name + ": " + (e instanceof Error ? e.message : String(e))];
          return false;
        }
      };

      const mk = (name: string, size: number): File => {
        const u8 = new Uint8Array(size);
        for (let i = 0; i < size; i++) u8[i] = (i * 7) & 255;
        return new File([u8], name, { type: "application/x-zp-test" });
      };
      const files = [mk("zero.bin", 0), mk("b.bin", 1), mk("c.bin", 65536), mk("d.bin", 33333)];
      const expected = await Promise.all(files.map((f) => f.arrayBuffer()));
      const note = "integration note 🎉 unicode";

      if (!(await step("assemble random-key envelope", async () => {
        const raw = crypto.getRandomValues(new Uint8Array(32));
        const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
        st.key = key;
        st.blob = await assembleEnv(key, note, files);
      }))) {
        return done.value = true;
      }

      if (!(await step("init upload session", async () => {
        const res = await fetch("/api/uploads", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ len: st.blob!.length, ttl: "1h", burn: false, salt: "" }),
        });
        if (!res.ok) throw new Error(res.status + " " + (await res.text()));
        st.up = (await res.json()) as { id: string; chunkSize: number; chunks: number };
        if (st.up.chunks < 2) throw new Error("expected multi-chunk, got " + st.up.chunks);
      }))) return done.value = true;

      if (!(await step("PUT all chunks", async () => {
        const { id, chunkSize, chunks } = st.up!;
        for (let n = 0, off = 0; n < chunks; n++, off += chunkSize) {
          const end = Math.min(off + chunkSize, st.blob!.length);
          const res = await fetch(`/api/uploads/${id}/${n}`, { method: "PUT", body: st.blob!.subarray(off, end) });
          if (res.status !== 204) throw new Error(`chunk ${n} -> ${res.status}`);
        }
      }))) return done.value = true;

      if (!(await step("finish", async () => {
        const res = await fetch(`/api/uploads/${st.up!.id}/finish`, { method: "POST", headers: { "Content-Type": "application/json" } });
        if (!res.ok) throw new Error(res.status + " " + (await res.text()));
        const body = (await res.json()) as { id?: string };
        if (!body.id) throw new Error("no id");
      }))) return done.value = true;

      if (!(await step("meta readback", async () => {
        const res = await fetch(`/api/paste/${st.up!.id}`);
        if (!res.ok) throw new Error(String(res.status));
        const meta = (await res.json()) as { len: number; data?: string; views?: number };
        if (meta.len !== st.blob!.length) throw new Error(`len mismatch ${meta.len} != ${st.blob!.length}`);
        if ("data" in meta && meta.data !== "") throw new Error("text field leaked for bundle");
        if ((meta.views ?? 0) < 1) throw new Error("opens counter missing on bundle meta");
      }))) return done.value = true;

      if (!(await step("range reads + manifest decrypt + per-file bytes", async () => {
        const got = new Uint8Array(st.blob!.length);
        for (let off = 0; off < st.blob!.length; off += st.up!.chunkSize) {
          const res = await fetch(`/api/paste/${st.up!.id}/blob?offset=${off}`);
          if (!res.ok) throw new Error(`range ${off} -> ${res.status}`);
          got.set(new Uint8Array(await res.arrayBuffer()), off);
        }
        const head = got.subarray(0, 16);
        const mlen = new DataView(head.buffer, head.byteOffset, head.byteLength).getUint32(0, true);
        const manifest = await readManifest(
          st.key!,
          head.subarray(4, 16) as Uint8Array<ArrayBuffer>,
          got.subarray(16, 16 + mlen) as Uint8Array<ArrayBuffer>,
        );
        if (manifest.note !== note) throw new Error("note mismatch: " + (manifest.note ?? "<none>"));
        if (manifest.files.length !== files.length) throw new Error("file count mismatch");
        let off = 16 + mlen;
        for (let i = 0; i < manifest.files.length; i++) {
          const f = manifest.files[i]!;
          const ct = got.subarray(off, off + f.size);
          const iv = bytesFromB64u(f.iv);
          const pt = await openBytes(st.key!, iv, ct);
          const want = new Uint8Array(expected[i]!);
          if (pt.length !== want.length) throw new Error(`${f.name}: ${pt.length} != ${want.length}`);
          for (let b = 0; b < want.length; b++) {
            if (pt[b] !== want[b]) throw new Error(`${f.name}: byte ${b}`);
          }
          off += f.size;
        }
      }))) return done.value = true;

      log.value = [...log.value, "SELFCHECK COMPLETE"];
      done.value = true;
    })();
  }, []);

  return (
    <section id="selfout" class="card">
      <b>selfcheck</b>
      {log.value.map((l, i) => (
        <div key={i} class={l.startsWith("FAIL") ? "hint danger" : "hint"}>{l}</div>
      ))}
    </section>
  );
}
