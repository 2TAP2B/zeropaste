# AGENTS.md — zeropaste

Instructions for agents working on this repository. If you rebuild this project from scratch, follow this document exactly; it is a complete specification of every deliberate decision.

## 1. What this project is

**zeropaste** — a self-hosted, zero-knowledge paste-sharing service for a small friend group. Users paste text, passwords, or code snippets; the browser encrypts them (AES-256-GCM) and the server stores only ciphertext. Sharing works via a link whose URL fragment (`#...`) carries the decryption key, or — for passphrase-protected pastes — via a link plus a separately shared passphrase.

Hard constraints (do not violate, do not "improve"):

- **Single Go binary.** Stdlib only — no web framework, no router lib, no DB driver, no third-party Go dependencies at all.
- **Zero-knowledge.** Keys are generated and used exclusively in the browser (WebCrypto). The server never sees plaintext, keys, or passphrases. No CDN calls from the frontend; everything (including syntax highlighting) is embedded in the binary.
- **No accounts, no cookies, no sessions, no per-request logging.** The link is the capability. This is intentional; do not add auth or logging of request data. (Exception: the optional create-gate below — a single site passphrase in front of `POST /api/paste` via env `CREATE_KEY`; it is not a user-account system.)
- **English UI only.**
- Allowed Go version: 1.25+ (built and verified on 1.26.x).

Out of scope by design (an agent must not add these): authentication *beyond the optional create-gate* (no user accounts per se), paste editing or listing (except the phase-2 identity dashboard when approved), comments, per-language syntax selection, a database.

**Spec revision v0.3 (user approved):** file uploads ARE in scope now (phase-1); passkey accounts + reverse shares planned (phases 2-3). The zero-knowledge crypto contract (§2) is untouched: the server only ever stores ciphertext.

## 2. Crypto contract (non-negotiable)

- Encryption: **AES-256-GCM** via browser WebCrypto.
- Random-key flow (default): 32 random bytes → raw key. Payload sent to server: `base64url(iv [12 bytes] ‖ ciphertext)`.
- Passphrase flow (optional): 16 random salt bytes (base64url, sent to server) + **PBKDF2-HMAC-SHA256, 600,000 iterations** (OWASP figure) → derived AES-256 key. The passphrase never leaves the browser; the server stores only the salt.
- Random-key pastes: key in the **URL fragment** (`/p/<id>#<keyB64>`) — fragments are never sent to servers, logs, or proxies. The reader strips it via `history.replaceState` after decryption.
- Passphrase-protected links contain **no** fragment.

## 3. Repository layout

| File | Mandate |
|---|---|
| `main.go` | Entire server: routing, handlers, validation, limiter, janitor, embedding. All logic lives here. |
| `web/index.html` | Markup for all three views (compose / link / read). No inline JS or CSS — links below. |
| `web/assets/style.css` | All styling. |
| `web/ts/` | Typed TS sources (`app.ts` entry, `crypto.ts`, `theme.ts`, `ui.ts`, `read.ts`, `globals.d.ts`); strict `tsc` (`tsconfig.json`, DOM types only — WebCrypto/WebAuthn wrappers). Vanilla, **no framework**; direct DOM. |
| `web/assets/highlight.min.js` | highlight.js v11.11.1 "common" build (~127 KB), fetched once from `https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.11.1/build/highlight.min.js` and committed. Never hotlink. |
| `web/assets/qrcode.min.js` | qrcode-generator v1.4.4 (~21 KB) from `https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js`, committed. QR is rendered client-side only. |
| `web/assets/atom-one-dark.min.css` | highlight.js dark theme from the same release, committed. Paired with `atom-one-light.min.css`: both are linked with static `prefers-color-scheme` media (no-JS safe) and `applyTheme` pins the active one to `media="all"` (theme = `#hljs-dark` / `#hljs-light`). |
| `main_test.go` | httptest-based suite (see §8). |
| `go.mod` | `module paste`, `go 1.25`, empty require block. |
| `flake.nix`, `.envrc`, `flake.lock` | Nix: dev shell (Go via nixpkgs unstable, git, ripgrep, node), package (see `package.nix`), NixOS module (see `module.nix`); `.envrc` contains exactly `use flake`. |
| `package.nix` | Single Go derivation: `buildGoModule`, `vendorHash = null` (stdlib only), `CGO_ENABLED=0`, ldflags `-s -w`; binary renamed `paste` → `zeropaste` (avoids colliding with coreutils `paste` in PATH). MIT license. |
| `module.nix` | `services.zeropaste`: `enable`, `listenAddress` (default `127.0.0.1:8080`), `createKeyFile` (EnvironmentFile — secrets never in the option system/store). systemd: `DynamicUser`, `StateDirectory = zeropaste` (`/var/lib/zeropaste`), `Restart = on-failure`, sandbox hardening. |
| `Dockerfile` | Three-stage build (see §6). |
| `.github/workflows/docker.yml` | CI: on `v*` tags and `workflow_dispatch`, builds and pushes the image to `ghcr.io/2tap2b/zeropaste` (semver tag, `latest`, sha) via GITHUB_TOKEN, gha cache. amd64 only. **Release naming:** `vX.Y.Z - name` with a plain hyphen — no emdash anywhere user-visible (titles and bodies). |
| `compose.yaml` | Single service, port 8080, named volume `paste-data` → `/data`. |
| `.dockerignore` | Excludes `data/`, `paste`, `*.md`, `.envrc`, `flake.*`, `.git`. |

No other files belong here. `data/` (runtime store) is created on demand and must never be committed.

## 4. API contract

Base: all routes carry security headers via `secure()` middleware. Errors are JSON `{"error": "<generic message>"}` — never internal details.

### `POST /api/paste` (rate limited: 30/min/IP, then HTTP 429)

Request JSON:

```json
{"data": "<base64url(iv‖ct)>", "salt": "<base64url or ''>", "ttl": "1d", "hl": true, "burn": false}
```

Validation, in order, all failures produce 400:

- Body capped by `http.MaxBytesReader` at 256 KiB; JSON decode failure → 400.
- `ttl` parsed by `parseTTL`: lowercase, spaces stripped, `<number><unit>` with unit in {m, min, mins, minute, minutes, h, hr, hrs, hour, hours, d, day, days}. Must equal 1 minute … 30 days (both inclusive); 30 days is a hard ceiling. Compound durations like `1h30m` are intentionally unsupported.
- `data`: strict base64url decode, decoded length ≥ 28 (12 IV + 16 GCM tag) and ≤ 64 KiB (`maxData`).
- `salt` (if non-empty): base64url decode to 8–32 bytes.

Success: 200 `{"id": "<11-char base64url of 8 random bytes>"}`. File written as `<dir>/<id>.json`, mode 0600, data dir created 0700. `newID(dir)` retries on the (astronomically unlikely) collision **against the data dir** — a previous version checked `./` and was wrong; do not regress.

### File uploads (chunked, resumable) — build on `/api/uploads`

Config via env at startup: `MAX_BLOB` (default `2147483648` = 2 GiB, 1 MiB..64 GiB) total ciphertext per share; `CHUNK` (default `8388608` = 8 MiB, 64 KiB..64 MiB) per PUT and per range GET; `MAX_BLOB < CHUNK` is a fatal misconfig. Values are plain byte integers.

- `POST /api/uploads` `{len, ttl, salt, burn}` → `{"id", "chunkSize": CHUNK, "chunks": ceil(len/CHUNK)}`. Body capped 1 KiB. Same ttl/salt validation as `POST /api/paste` (ttl shape only here; expiry computed at finish). Creates `data/uploads/<id>/upload.json` (`{len, ttl, salt, burn, created}`) 0600, dirs 0700. Id = 8 random bytes b64url, collision-checked against the uploads dir.
- `PUT /api/uploads/{id}/{n}` — raw ciphertext chunk `n` (0-based). `validID` gates `{id}`; `n` strict int `0..chunks-1`; body `MaxBytesReader` at CHUNK+1, `1..CHUNK` bytes required. Overwrite = resume. **NOT rate limited** (a 2 GiB share is ~250 PUTs; body caps + temp quotas carry the protection). Behind the create-gate when enabled.
- `DELETE /api/uploads/{id}` — `os.RemoveAll(session)`, idempotent 200 `{"ok": true}`. Public (abort must always work).
- `POST /api/uploads/{id}/finish` — rate limited + gated like a paste create. Verifies every `n.part` exists with exact sizes (full chunks = CHUNK, last = len-(chunks-1)*CHUNK), joins to `<dir>/<id>.blob` 0600, writes meta `<dir>/<id>.json` (`{len, salt, burn, expires}`, no `data`), removes the session dir. Incomplete/off-size → 400, parts kept for retry, partial blob removed. Double finish → 200 idempotent.
- `GET /api/paste/{id}/blob?offset=N` — ciphertext ranges (`no-store`, `application/octet-stream`), max CHUNK bytes from offset; off-range offset → 400; expired → 404 + file removed. Reader paginates 0..len.
- Meta read for a bundle (`len > 0`) with `burn && salt==""`: expiry flips to `now-1+30s` grace window (var `burnWindowSec`) so the legitimate reader can finish the range downloads; janitor reaps both `<id>.json` and `<id>.blob` when expired. Text pastes keep exact read-then-delete. **`DELETE /api/paste/{id}` removes `.blob` too** (bundle dies whole, burn flag or not).
- Janitor (`sweep`, shared with tests): also removes `uploads/<dir>` sessions whose manifest is missing or `created` older than 2h.

### Create-gate (optional auth in front of POST)

- Enabled when env `CREATE_KEY` is non-empty at startup (its presence *is* the switch — no separate boolean). Disabled entirely when unset/empty.
- `POST /api/paste` then requires header `Authorization: Bearer <CREATE_KEY>`, compared with `subtle.ConstantTimeCompare` (`authGate`). Failure → 401 generic error. Tested at 30/min/IP by the same limiter.
- Everything else stays public behind the gate: reads, DELETE (burn pastes need it after decrypt), `/`, `/p/`, `/assets/`, `/healthz`.
- **Gate UX is a full-screen pre-screen**, not a field in the compose card: with the gate enabled, the client renders a bare unlock card (`#gate`, passphrase input + Unlock button) *before* any app view. Verification runs against `GET /api/gate` (→ `{"enabled": bool}`, no key metadata) and `POST /api/gate` (Bearer candidate → 204 or 401, rate limited). On 204 the passphrase is kept in `sessionStorage` key `zp.siteKey` (per tab, never localStorage, never a cookie) and future sends carry it as `Authorization: Bearer`. A 401 from a paste create drops the user back to the gate screen (stale key). Reader views (`/p/…`) never show the gate.
- The create flow needs no UI changes when the gate is disabled: `GET /api/gate` says `enabled:false`, the compose card renders directly.

### Identity (phase 2): passkeys via go-webauthn (first third-party dep)

- Storage stays file-shaped: `data/identities/<id>.json` (`{id, name, creds[]}` — creds are the lib's `webauthn.Credential` JSON). Sessions are HMAC-signed cookies (`zp.session`: `b64url({sub,exp}).b64url(sig)`), HttpOnly SameSite=Lax, 30 day TTL. Secret: `data/.session.key` (auto-generated 32 B, 0600) or env `SESSION_SECRET`.
- `GET /api/me` → `{name}` (empty string = anonymous). `POST /api/identity/{register,login}/begin|finish` (rate limited), `POST /api/identity/logout` clears the cookie.
- RP config derives from the request per ceremony: `RPID = host (no port)`, origin = `X-Forwarded-Proto ?? http` + `:// + Host`. Session challenge state lives **in-memory** (`ceremony` map, 2 min) — a restart drops pending ceremonies; that is the ponytail ceiling for multi-instance deployments.
- Login discoverable-credential style: allowlist = every stored credential id; identity resolved from the returned `userHandle`.
- Dashboard ownership rows: `data/shares/<ident>/<paste>.json` written at `create`/`uploadFinish` when the session cookie is present; `GET /api/shares` computes rows live from the actual paste metas and prunes gone/expired rows — zero bookkeeping. Anonymous creation records nothing.

### `GET /healthz`

Exact-match route, returns 200 `ok`. Not rate limited, no auth.

### `GET /api/paste/{id}`

- `validID(id)`: length 8–16, charset `[A-Za-z0-9_-]` only. Invalid → 404. This charset check is the **sole path-traversal defense** and gates every `filepath.Join(dir, id+".json")` — keep it.
- Missing / corrupt / expired → 404 (expired ones are deleted on sight).
- Success → 200 `{"data", "salt", "hl", "burn", "expires"}` with header `Cache-Control: no-store` (`expires` = unix seconds; the read view renders it as a countdown).
- **Burn semantics:** if `burn && salt == ""` → the file is deleted immediately after this read (read-then-delete; two racing readers can both succeed — accepted `ponytail:` ceiling). If `burn && salt != ""` → **do NOT delete on read**; the client issues `DELETE` after successful decryption (a link unfurler or wrong-passphrase visitor must not destroy the paste).

### `DELETE /api/paste/{id}`

Same `validID` gate. Removes the file; idempotent (nonexistent → still 200 `{"ok": true}`); other removal errors → 500.

### Static routes

- `GET /` and `GET /p/{any}` → serve embedded `web/index.html` with `Cache-Control: no-store`. Invalid id after `/p/` → 404. Any other path → 404.
- `GET /assets/{file}` → files from embedded `web/assets`; directory roots (empty path or trailing `/` after strip) → 404 (no listings); `Cache-Control: public, max-age=86400`. Note `http.StripPrefix` leaves `""` (not `"/"`) for the bare prefix — guard both.
- Routing uses Go ≥1.22 ServeMux method patterns (`"GET /"`, `"POST /api/paste"`). Every handler is wrapped `secure(...)`.

## 5. Server behavior mandates

- **Security headers on every response** (`secure()`): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.
- **No HSTS at app level** — TLS/HSTS belongs to the reverse proxy in front; the app must keep working on plain-HTTP LANs.
- **HTTP server timeouts** (slowloris): ReadHeaderTimeout 10s, ReadTimeout 30s, WriteTimeout 30s, IdleTimeout 120s.
- **Rate limiter:** in-memory fixed-window per IP. The **last** `X-Forwarded-For` entry is used when present (the single trusted reverse proxy in front appends the real client IP; spoofed earlier entries only pollute the client's own chain), else the `RemoteAddr` host. 30 per minute window; window resets by wall clock; `clear(l.hits)` on rotation.
- **Janitor:** goroutine, `time.Tick(time.Minute)`: deletes `*.burn` leftovers and any `*.json` whose `expires < now`.
- **No request logging** (privacy: never store IPs). Server log is startup + internal errors only (`log.Print(err)`), never paste content.
- **Graceful shutdown:** SIGTERM/SIGINT triggers `srv.Shutdown` with a 5s drain — in-flight creates finish before exit (`docker stop` works cleanly).
- Deliberate ceilings are marked `// ponytail:` in code; preserve the comments and the weaker-but-fine behavior they describe.

## 6. UI mandates (`web/`)

- **Brand: `zeropaste`**, tagline `/ zero-knowledge pastes`. Header logo is an `<a href="/">` (accent purple). `<title>zeropaste</title>`.
- **Design system:** monospace (`ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace`). Two themes, exact CSS variables in `style.css`: **light** (`--bg #f3e5f5`, `--surface #e9d8fd`, `--border #d8b4fe`, `--text #374151`, `--muted #4b5563`, `--accent #a78bfa`, `--on-accent #fff`) and **dark** (`--bg #1c1917`, `--surface #3f324a`, `--border #4a3d5a`, `--text #d1d5db`, `--muted #a5a0ad`, `--accent #c0aafd`, `--on-accent #1c1917`). Default follows system via `prefers-color-scheme` (no-JS safe); toggle button (`#theme`) in the header pins `data-theme` and stores it in localStorage key `zp.theme` (only "light"/"dark" — the zero-knowledge mandate covers paste data, not UI prefs). Cards = surface bg, 1px border, 10px radius.
- **Compose view:** textarea (`autofocus`, spellcheck off, Ctrl/⌘+Enter submits) → dashed `#dropzone` ("drop files here - or click to browse"; click opens hidden `#fileinput` multiple, drag/drop wired) → removable `#files` chips (name + humanSize + ×) → one-line settings row: label `burn paste after` above a compact free-form ttl text input (`value="1d"`, ~140px), the **toggle button** `burn after reading` (flame SVG, `aria-pressed`, inactive = muted / active = red; NOT a checkbox), and the passphrase input (`type=password`, `autocomplete=new-password`) filling the row → `Encrypt & share` primary button → passphrase hint below. Submit enabled iff text non-empty **or** ≥1 file; textarea becomes the encrypted note for bundles. During upload: `#prog` bar + label (`encrypting… / uploading N% / finishing…`) + Cancel (aborts fetches, deletes the temp session).
- **Bundle envelope (client framing, server-opaque):** `u32le(manifestCtLen) | manifestIv | manifestCt | file1Ct | ...`; manifest plaintext `{note?, files:[{name, mime, size, iv}]}` — one AES-GCM key per share (random or PBKDF2), fresh IV per file; filenames/mime/note never reach the server. Cap ~2 GiB (in-memory encrypt ceiling, documented in the UI as a practical bound).
- **Read view (bundles):** meta `len > 0` ⇒ manifest path — paginated range reads, decrypt note (rendered in the existing paste-view block w/ its copy button), `#filelist` rows (name + size + Save button); Save = fetch file ranges, decrypt, Blob URL download; burn note shown + server DELETE fired only after the manifest decrypt succeeds.
- **Link view** (after create): showing-read-only link (`/p/<id>#<key>` when random-key; bare `/p/<id>` when passphrase-protected, with red note to share the passphrase separately), Copy + New paste buttons. Copy button flashes `Copied!`; the icon copy button swaps to a check SVG (`copied` class = green). **Share URLs are built client-side from `location.origin`** — the server never knows its public domain, so there is deliberately no base-URL env/config; whatever address the browser is on becomes the link prefix. Below the link row: a `<details>` "Show QR code" toggle — QR of the full share URL rendered client-side via `qrcode-generator` (`drawQR`), white bg tile, block only `qrcode.min.js` globals, `~20 KB`.
- **Read view:** passphrase pastes show an unlock form (wrong passphrase → inline "Wrong passphrase.", `select()` the field); random-key pastes decrypt via fragment, then strip the hash. Paste renders in `pre.paste-view > code` via **`textContent` only — never `innerHTML` with paste content** (hljs handles its own escaping). Editor-style copy icon (`.copybtn`, absolute top-right of `.codewrap`, copy SVG). Below the paste: burn note (when burned) and an expiry countdown (`expiresIn()`: "X min", "X h", "X d"). `head` carries static OG tags (`og:title zeropaste`, generic `og:description`) — no content leaks to unfurlers. Syntax highlighting is **always on** (`hl: true` sent on every create; old pastes with `hl:false` may render plain — honoring the stored flag is correct). Burned pastes fire `DELETE` (fire-and-forget) after successful decrypt and show a burned note; burn+passphrase pastes delete only after successful decrypt.
- hljs is invoked as `hljs.highlightElement` when `paste.hl && window.hljs`.
- **Mobile:** `@media (max-width: 540px)` — single-column stacking, full-width controls/tap targets, `#ttl` full width, smaller body padding. Base layout already fluid (`clamp` padding, `viewport-fit=cover`).
- **Footer (`.foot`)** — one line: `<b>zeropaste</b> — zero-knowledge pastes · <button .foot-link popovertarget="quickstart">self-host</button> · <a>source code</a>` (`https://github.com/2TAP2B/zeropaste`). `self-host` opens the `#quickstart` **popover** (native API, zero JS to open) with copyable `docker run` + `compose.yaml` blocks (copy buttons wired by `[data-copy]` in app.js).

## 7. Dev environment (NixOS)

- `flake.nix`: single `nixpkgs` (`github:NixOS/nixpkgs/nixos-unstable`) input. Outputs: `devShells.x86_64-linux.default = mkShell` (packages `go`, `git`, `ripgrep`, `nodejs`), `packages.${system}.default` (see `package.nix`), `nixosModules.zeropaste` (see `module.nix`). Self-contained — no external flake inputs.
- `.envrc`: `use flake` (user runs `direnv allow` once).
- Run everything inside the shell: `nix develop --command sh -c '...'`.
- hljs assets were fetched over TLS from jsdelivr (see §3) — if rebuilding from zero, fetch those two files before building.

## 8. Verification protocol (must pass before "done")

```sh
nix develop --command sh -c 'gofmt -l . && go vet ./... && go test ./... && esbuild --bundle web/ts/app.ts --outfile=web/assets/app.js --minify --target=es2020 && tsc --noEmit && go build -trimpath -ldflags="-s -w" -o paste .'
```

- `gofmt -l` prints nothing; vet and tests must be green; `tsc --noEmit` must typecheck `web/ts/` (strict, noUncheckedIndexedAccess) — type errors are the gate the old `node --check` syntactic pass can't catch. esbuild emits the minified bundle (`web/assets/app.js`, committed artifact — regen before testing the server).
- Test suite (all in `main_test.go`, unreferenced helpers there): `TestRoundTrip` (create→read, metadata echo incl. `expires`), `TestBurnAfterRead` (2nd GET 404), `TestExpiredPaste404s` (rewinds expiry on disk: 404 + file removed), `TestBadRequests` (short data / bad ttl `2w` / `31d` / empty ttl / undecodable data / bad salt → all 400), `TestParseTTL` (valid table incl. `"10 min"`, `30 days`, `6H`; invalid `"0d"`, `"1w"`, `"1h30m"`, `"-5m"`, `"5"`, empty), `TestPassphrasePaste` (salt+burn: GET does NOT destroy, metadata echoed, `DELETE` → 200 → GET 404), `TestAssetsServed` (file 200 + dir listing 404), `TestIndexServed` (`/` and `/p/whatever` 200 with page, unknown path 404), `TestRateLimit` (30× 200 then 429), `TestPathValueAbuse` (charset/traversal/short ids → 404; DELETE same), `TestHealthz` (200 `ok`), `TestAuthGate` (with `CREATE_KEY` set: no header → 401, wrong key → 401, correct key → 200, paste publicly readable, healthz open).
- Upload suite: `TestUploadRoundTrip` (odd-sized 3-chunk init/put/finish → meta `{len,...}` no `data` → paginated range reads equal the plaintext), `TestUploadResumeOverwrite` (PUT same chunk twice: latest wins), `TestUploadFinishMissingPart` (400 + parts survive + off-size chunk rejected; retry completes; double finish idempotent), `TestUploadAbortCleans` (chunk PUT after abort → 404, second abort idempotent), `TestUploadBadRequests` (len 0/-65 above cap/bad ttl/short salt → 400; chunk index out of range/junk/negative/bad-id charset → 4xx), `TestUploadSweep` (fresh session survives; `created` older than 2h → wiped), `TestBlobBurnExpiresOnRead` (meta read flips to grace window, blob stays reachable, expired+rereaped by janitor → both gone), `TestAuthGateUpload` (init + chunk PUTs: no header/wrong key → 401, correct key → 200/204; blobs/files publicly readable AFTER they exist).
- Live smoke (expected results): request POST → GET returns `data`; burn paste second GET → 404; `31d` → 400; assets `200`; `/assets/` → 404; `curl -sI /` shows all four security headers.
- Supply-chain audit: `nix shell nixpkgs#govulncheck nixpkgs#go -c sh -c 'CGO_ENABLED=0 govulncheck ./...'` → `No vulnerabilities found.` (There are no third-party Go deps; any `go.sum` is a regression.)

## 9. Docker

- Build stage: `golang:1.26-alpine`, `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/paste .`, `COPY web/ ./web/` (embeds need it).
- Data-dir stage: `FROM alpine`, `mkdir /data && chown 65534:65534 /data`.
- Runtime: `FROM scratch`; copy binary; **`COPY --chown=65534:65534 --from=data /data /data`** — the `--chown` is required: copying an *empty* directory into scratch silently drops its ownership and non-root writes then fail with "could not store paste".
- `USER 65534:65534`, `EXPOSE 8080`, `VOLUME /data`, `ENTRYPOINT ["/paste"]`, `CMD ["-addr", ":8080", "-data", "/data"]`. Expected image size ≈ 9 MB.
- `compose.yaml`: service builds locally, `8080:8080`, named volume `paste-data:/data`, `restart: unless-stopped`, and sets `CREATE_KEY: "change-me"` as a **placeholder** — a deploy must replace it; never commit a real key. Removing the env line makes the instance fully public. No TLS in compose — TLS termination is a reverse-proxy concern (document separately at deploy time); the app stays plain HTTP.
- Container smoke test: start mapped to a host port, POST a paste → 200, GET → 200, `/` → 200, `/assets/highlight.min.js` → 200.

## 10. When changing this project

Preserve, in this order: the zero-knowledge crypto contract (§2), the stdlib-only constraint (§1), the security headers and validation order (§4–5), `textContent` rendering (§6). Deliberate simplifications stay marked with `// ponytail:` — do not silently "fix" them into complexity. Add a test for every abuse case before adding the mitigation.
