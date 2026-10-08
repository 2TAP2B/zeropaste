# Plan: ZeroPaste

Single SvelteKit service, modules in dependency order (see SPEC.md capability map).

## Implementation order & risks

1. **Scaffold** — SvelteKit 2 + Svelte 5 TS, adapter-node, vitest, playwright, eslint/prettier.
2. **db + schema** (`src/lib/server/db`) — better-sqlite3, `schema.sql`, `migrate.mjs`. Risk: adapter-node bundling of native module → mark `better-sqlite3` external in vite config.
3. **crypto core** (`src/lib/crypto`) — chunked AES-256-GCM format, PBKDF2 passphrase wrap, b64url helpers, PRF account-key derivation. Nothing server-side. Risk: 1 GB single-shot GCM blows memory → chunked design (5 MB chunks, counter IV + total-length AAD).
4. **storage backends** (`src/lib/server/storage`) — `Storage` iface; disk (fs streams); s3 (lazy SDK import, presigned PUT/GET/multipart, batched delete). Runtime-selected via `ZP_STORAGE`.
5. **shares lifecycle** (`src/lib/server/shares`) — create/consume/expiry/purge, dictionary slugs, site gate check.
6. **API routes** — upload (disk-body or s3-presign), finalize, metadata, download session, reverse create/upload, auth (webauthn register/login/logout), gate.
7. **UI** — home/upload page, share page (preview/burn), reverse pages, auth pages, dashboard (lists, revoke). Light/dark pastel-purple theme tokens + toggle.
8. **cleanup job** — in-process interval, guard against HMR/duplicate; fake-clock injection for tests.
9. **tests** — vitest unit (crypto, storage, lifecycle, db) + integration "dump decrypts nothing"; Playwright smoke (3 flows).
10. **docker + README**.

## Parallelizable

UI theming can go alongside API work; storage s3 impl independent of auth.

## Verification checkpoints

- After 3: unit test full chunked round-trip + tamper fails.
- After 5: lifecycle state machine tests (fresh → consumed/expired → purged).
- After 8: `npm run check` clean; integration test asserts data-dir dump indecipherable.
- After 9: full test suite green.
