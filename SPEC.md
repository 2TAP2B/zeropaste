# Spec: ZeroPaste — zero-knowledge encrypted file/paste sharing

## Objective

Self-hostable web app (WeTransfer × pastebin) where the server stores only ciphertext:

- Browser-side encryption (WebCrypto). Server/operator can never decrypt.
- Human-readable links (`/p/quiet-otter-42`); decryption key in URL fragment (`#k=...`) — never sent to server.
- Burn after reading (first download session start consumes it) and/or TTL expiry.
- Optional per-share passphrase folded into client key derivation (server stores KDF salt + verifier only).
- Image shares (png/jpg/webp/gif) get a client-side-decrypted preview.
- **Reverse shares**: `/r/<lsug>` (custom slug) sent to friends; friends' browsers encrypt to the owner's key (WebAuthn PRF account key), only the owner can decrypt. Included fragment `#k=...` lets friends encrypt; the stored copy is wrapped with the owner's account key.
- **Dashboard**: passkey-only; overview of created + received shares; revoke/delete. Anonymous uploads unless site gate enabled.
- Light/dark theme, pastel purple accent.

## Capability Map

| Module id        | Responsibility                                                                       | Depends on                                  |
| ---------------- | ------------------------------------------------------------------------------------ | ------------------------------------------- |
| `identity`       | Passkey-only WebAuthn auth (PRF required), sessions                                  | —                                           |
| `vault`          | Crypto core, ciphertext storage via `Storage` backend, TTL/burn lifecycle, site gate | —                                           |
| `share-links`    | Public share pages, slugs, passphrase shares, image preview, burn trigger            | `vault`                                     |
| `reverse-shares` | Reverse upload links (custom lsug), PRF-wrapped key delivery, owner retrieval        | `vault`, `identity`                         |
| `dashboard`      | Created + received links overview, revoke/delete                                     | `identity`, `share-links`, `reverse-shares` |

Build order: identity → vault → share-links → reverse-shares → dashboard. Theming is cross-cutting.

## Tech Stack

- SvelteKit 2 + Svelte 5, TypeScript → single Node service
- SQLite via `better-sqlite3`, plain `schema.sql`, no ORM
- `@simplewebauthn/server` (passkeys + PRF extension)
- WebCrypto: AES-256-GCM, PBKDF2-SHA256 600k (passphrases), PRF-derived account keys
- `@aws-sdk/client-s3` + `s3-request-presigner`, lazy-loaded only in s3 mode
- Node 22+

## Storage backends

One `Storage` interface (`put` / `get` / `delete` / `exists`), two impls:

- **disk** (default): blobs on local volume, streamed through server.
- **s3**: server mints presigned PUT (uploads, incl. multipart for large files) and presigned GET (downloads); browser talks to bucket directly. Custom endpoint + path-style → works with AWS, R2, MinIO, B2. Bucket needs CORS config once (README recipe). Cleanup deletes via batched `DeleteObjects`.

Upload flows:

- disk mode: browser POSTs ciphertext to `/api/.../blob` (multipart/body).
- s3 mode: browser PUTs directly via presigned URL (multipart for >5 MB), then calls finalize.

Burn semantics uniform: a share is marked consumed **when its download session starts**, then the presigned URL is minted / disk stream begins. Second visitor sees "burned". In-flight downloads that already started may complete — documented race, no locking machinery in v1 (`ponytail:` accepted race; add row-level locking if it matters).

Key material never touches S3; bucket stores only ciphertext.

## Deployment

Single service; SQLite db + (disk mode) blobs on a local volume. Dockerfile provided. In s3 mode only the db lives locally.

## Commands

```
Dev:        npm run dev
Build:      npm run build
Production: npm run build && node build/index.js
Test:       npm test
E2E:        npm run test:e2e
Lint:       npm run lint
Typecheck:  npm run check
Migrate:    node scripts/migrate.mjs <db path>
```

## Project Structure

```
src/lib/crypto/     # client crypto core: keys, GCM, KDF, PRF — the ZK heart
src/lib/server/
  db/               # better-sqlite3, schema.sql, migrations
  auth/             # WebAuthn + sessions
  storage/          # Storage interface + disk, s3 impls
  shares/           # share + reverse-share logic, expiry/burn lifecycle
src/routes/         # share pages, upload/download API, auth, dashboard
src/app.css         # theme tokens: light/dark, pastel purple
tests/  e2e/
```

Server persistence holds **no key material ever**: id, slug, kind, blob refs, sizes, timestamps, burn flags, KDF salt + passphrase verifier, reverse-share wrapped-key blobs.

## Code Style

TypeScript strict, no comments, named exports:

```ts
export async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
	const base = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(passphrase),
		'PBKDF2',
		false,
		['deriveKey']
	);
	return crypto.subtle.deriveKey(
		{ name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
		base,
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt', 'decrypt']
	);
}
```

## Crypto rules (never violate)

- Keys live only in URL fragments, browser memory, or PRF-wrapped blobs. Never query strings, cookies, logs, or DB.
- Site gate passphrase (env) is access control only (bcrypt in DB), never derives content keys.
- Reverse-share keys: random 32B per link, delivered in fragment to friends, stored server-side wrapped with the owner's PRF-derived account key, bound to the owning credentialId. Later-registered passkeys retrieve only if their credential has a wrap. Fragment never stored raw.
- No passwords, no account recovery.

## Environment

```
ZP_DATA_DIR           # required: db + blobs (disk mode)
ZP_STORAGE            # disk | s3 (default disk)
ZP_SITE_PASSPHRASE    # optional site gate (empty = public)
ZP_MAX_FILE_MB        # default 1000
ZP_MAX_FILES          # default unlimited
ZP_DEFAULT_TTL        # e.g. 7d default for UI
ZP_PORT
ZP_S3_ENDPOINT ZP_S3_BUCKET ZP_S3_REGION
ZP_S3_ACCESS_KEY_ID ZP_S3_SECRET_ACCESS_KEY ZP_S3_PREFIX
```

## Testing Strategy

- **Vitest**: crypto round-trips/encodings/KDF, burn+expiry state machine, both storage backends (s3 impl tested against MinIO in Docker when available, SDK-mocked unit tests otherwise), auth, db. Crypto module ≥ 90% coverage; it is the trust boundary.
- **Playwright smoke (3 flows)**: create share → open link → decrypt; burn-on-read; reverse share upload → owner retrieve.

## Boundaries

- **Always**: typecheck + tests before commits; encrypt in browser only; purge consumed/expired blobs; keep keys out of all server persistence/logs.
- **Ask first**: new dependencies; schema changes (migration required); limit changes; any crypto parameter change.
- **Never**: log URL fragments; store/echo key material server-side; fallback passwords; delete failing crypto tests.

## Success criteria

- Full data dump (db + blobs/S3) decrypts nothing without link fragments — asserted by an integration test.
- Wrong/missing fragment key or failed passphrase → no content; burn marks after first download session start; cleanup purges blobs.
- Image share renders decrypted preview without the user keeping ciphertext.
- Reverse share: friend uploads with no account via `/r/<lsug>`; owner decrypts via PRF in dashboard; owner can revoke link + received items.
- Site gate env blocks uploads behind passphrase prompt; public when unset.
- S3 mode verified end-to-end against MinIO (presigned PUT upload, presigned GET download, purge on burn/expiry).
- Theme toggle persists; pastel purple in both themes.

## Open Questions

1. Share-link delivery beyond copy-to-clipboard? _Assumed: no for v1._
2. Cleanup interval default? _Assumed: every 5 min in-process._
3. PRF lacking browser on owner side — show explicit "this device can't decrypt" error? _Assumed: yes, no silent fallback._
