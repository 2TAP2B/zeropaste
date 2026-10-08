# ZeroPaste

Zero-knowledge encrypted file/paste sharing (WeTransfer × pastebin), self-hostable.

- Browser-side encryption (AES-256-GCM, chunked). The server stores only ciphertext.
- Human-readable links (`/p/quiet-otter-42`); the decryption key lives in the URL fragment and never reaches the server.
- Burn after reading (consumed at download-session start), TTL expiry, optional passphrase per share.
- Image shares (png/jpg/webp/gif) get a decrypted preview.
- Reverse shares: `/r/<lsug>` — friends upload, you decrypt with your passkey (WebAuthn PRF).
- Passkey-only dashboard; anonymous uploads unless a site gate is configured.
- Light/dark theme, pastel purple accent.
- Storage: local disk (default) or any S3-compatible bucket (presigned browser-direct).

## Dev shell

```
cd zeropaste2        # direnv auto-activates the Nix dev shell (node 24, docker, tools)
npm run dev
```

First `cd` runs `npm install` automatically via the flake's shellHook.

## Commands

```
npm run dev        # dev server
npm run build      # production build (adapter-node)
npm run start      # run the built server (PORT env)
npm test           # vitest unit + integration
npm run lint       # prettier + eslint
npm run check      # svelte-check
npm run migrate /path/to/zp.db
```

## Environment

| var                                                                                          | default          | meaning                          |
| -------------------------------------------------------------------------------------------- | ---------------- | -------------------------------- |
| `ZP_DATA_DIR`                                                                                | `./data`         | SQLite db + blobs (disk storage) |
| `ZP_STORAGE`                                                                                 | `disk`           | `disk` or `s3`                   |
| `ZP_SITE_PASSPHRASE`                                                                         | —                | optional site-wide upload gate   |
| `ZP_MAX_FILE_MB`                                                                             | `1000`           | per-file limit                   |
| `ZP_MAX_FILES`                                                                               | unlimited        | files per share                  |
| `ZP_DEFAULT_TTL_SECS`                                                                        | `604800`         | default expiry (7 days)          |
| `PORT`                                                                                       | `3000`           | server port                      |
| `ZP_RP_ID`                                                                                   | `localhost`      | WebAuthn RP ID = your domain     |
| `ZP_ORIGIN`                                                                                  | `https://<rpId>` | expected WebAuthn origin         |
| `ZP_S3_ENDPOINT`                                                                             | —                | custom S3 endpoint (R2/MinIO/B2) |
| `ZP_S3_BUCKET` `ZP_S3_REGION` `ZP_S3_ACCESS_KEY_ID` `ZP_S3_SECRET_ACCESS_KEY` `ZP_S3_PREFIX` | —                | s3 settings                      |

## S3 mode

The server never proxies blobs: it mints presigned PUT/GET URLs and the browser talks to the bucket directly. Bucket side needs a one-time CORS config, e.g. (AWS/R2/MinIO):

```json
[
	{
		"AllowedOrigins": ["https://your-zp.host"],
		"AllowedMethods": ["GET", "PUT"],
		"AllowedHeaders": ["*"],
		"MaxAgeSeconds": 3600
	}
]
```

## Security notes

- Key material lives only in URL fragments / WebAuthn PRF. Nothing key-related is stored server-side.
- Site gate passphrase is verified server-side (scrypt) and gates uploads only; it never derives content keys.
- Passphrase shares use a client-derived verifier: the server can compare the proof without ever seeing the derived key or the content.
- Reverse-share content keys are wrapped with the owner's PRF-derived account key (bound to the credential that created them). Devices/passkeys without PRF cannot unwrap; that's shown as an explicit error, never a fallback.
- `ponytail:` accepted race: two visitors racing a burn-after-read download can both complete in-flight downloads; the second distinct fetch gets "gone". Row-level locking can be added when it matters.

## Docker

```
docker build -t zeropaste .
docker run -p 3000:3000 -v /srv/zeropaste:/data -e ZP_RP_ID=zp.example -e ZP_ORIGIN=https://zp.example zeropaste
```

(Serve behind TLS reverse proxy; HTTPS is required for passkeys in browsers.)
