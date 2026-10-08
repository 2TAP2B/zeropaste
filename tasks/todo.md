# Tasks

- [x] Task: Scaffold SvelteKit project with deps and tooling (Node dev shell = flake.nix+direnv, node 24)
- [x] Task: DB schema + db layer + migrate script
- [x] Task: Client crypto core (chunked AES-256-GCM `ZPC1` format, PBKDF2 wrap, PRF account-key wrap) + unit tests
- [x] Task: Storage interface + disk + s3 impls (presigned single/multipart) + tests
- [x] Task: Shares lifecycle + slugs + site gate (scrypt) + tests
- [x] Task: API routes (shares, blobs, complete, content w/ burn trigger, p/[slug], r/[lsug], reverse, dashboard, auth, gate)
- [x] Task: UI pages + theme (home wizard, p/[slug] viewer w/ image preview, r/[lsug] drop, login, dashboard) — light/dark pastel purple
- [x] Task: Cleanup interval job (hooks, 5 min, globalThis guard)
- [x] Task: Live smoke (disk): create → upload → download bytes equal → burn flip → purge
- [x] Task: Dockerfile + README (incl. S3 CORS recipe)
- [ ] Task: Playwright smoke e2e (browser passkeys can't be automated headlessly; unit + live API smoke cover the flows)
- [ ] Backlog: s3 multipart part streaming in upload wizard UI (s3put single-part works; >5 MB files with s3 backend not wired in UI)

