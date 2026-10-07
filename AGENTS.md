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

Out of scope by design (an agent must not add these): authentication *beyond the optional create-gate* (no user accounts per se), file/image uploads, paste editing or listing, comments, per-language syntax selection, a database.

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
| `web/assets/app.js` | All client logic incl. crypto helpers (`b64uFromBytes`, `bytesFromB64u`, `randomKey`, `deriveKey`, `seal`, `open_`). |
| `web/assets/highlight.min.js` | highlight.js v11.11.1 "common" build (~127 KB), fetched once from `https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.11.1/build/highlight.min.js` and committed. Never hotlink. |
| `web/assets/qrcode.min.js` | qrcode-generator v1.4.4 (~21 KB) from `https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js`, committed. QR is rendered client-side only. |
| `web/assets/atom-one-dark.min.css` | highlight.js dark theme from the same release, committed. Paired with `atom-one-light.min.css`: both are linked with static `prefers-color-scheme` media (no-JS safe) and `applyTheme` pins the active one to `media="all"` (theme = `#hljs-dark` / `#hljs-light`). |
| `main_test.go` | httptest-based suite (see §8). |
| `go.mod` | `module paste`, `go 1.25`, empty require block. |
| `flake.nix`, `.envrc`, `flake.lock` | Nix: dev shell (Go via nixpkgs unstable, git, ripgrep, node), package (see `package.nix`), NixOS module (see `module.nix`); `.envrc` contains exactly `use flake`. |
| `package.nix` | Single Go derivation: `buildGoModule`, `vendorHash = null` (stdlib only), `CGO_ENABLED=0`, ldflags `-s -w`; binary renamed `paste` → `zeropaste` (avoids colliding with coreutils `paste` in PATH). MIT license. |
| `module.nix` | `services.zeropaste`: `enable`, `listenAddress` (default `127.0.0.1:8080`), `createKeyFile` (EnvironmentFile — secrets never in the option system/store). systemd: `DynamicUser`, `StateDirectory = zeropaste` (`/var/lib/zeropaste`), `Restart = on-failure`, sandbox hardening. |
| `Dockerfile` | Three-stage build (see §6). |
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

### Create-gate (optional auth in front of POST)

- Enabled when env `CREATE_KEY` is non-empty at startup (its presence *is* the switch — no separate boolean). Disabled entirely when unset/empty.
- `POST /api/paste` then requires header `Authorization: Bearer <CREATE_KEY>`, compared with `subtle.ConstantTimeCompare` (`authGate`). Failure → 401 generic error. Tested at 30/min/IP by the same limiter.
- Everything else stays public behind the gate: reads, DELETE (burn pastes need it after decrypt), `/`, `/p/`, `/assets/`, `/healthz`.
- **Gate UX is a full-screen pre-screen**, not a field in the compose card: with the gate enabled, the client renders a bare unlock card (`#gate`, passphrase input + Unlock button) *before* any app view. Verification runs against `GET /api/gate` (→ `{"enabled": bool}`, no key metadata) and `POST /api/gate` (Bearer candidate → 204 or 401, rate limited). On 204 the passphrase is kept in `sessionStorage` key `zp.siteKey` (per tab, never localStorage, never a cookie) and future sends carry it as `Authorization: Bearer`. A 401 from a paste create drops the user back to the gate screen (stale key). Reader views (`/p/…`) never show the gate.
- The create flow needs no UI changes when the gate is disabled: `GET /api/gate` says `enabled:false`, the compose card renders directly.

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
- **Compose view:** textarea (`autofocus`, spellcheck off, Ctrl/⌘+Enter submits) → row with label `burn paste after` above a compact free-form ttl text input (`value="1d"`, ~140px) and a **toggle button** `burn after reading` (flame SVG, `aria-pressed`, inactive = muted / active = red border+text; NOT a checkbox) → passphrase input (`type=password`, `autocomplete=new-password`) on its own row → full-width purple `Encrypt & share` primary button on its own row → passphrase hint text below the rows.
- **Link view** (after create): showing-read-only link (`/p/<id>#<key>` when random-key; bare `/p/<id>` when passphrase-protected, with red note to share the passphrase separately), Copy + New paste buttons. Copy button flashes `Copied!`; the icon copy button swaps to a check SVG (`copied` class = green). **Share URLs are built client-side from `location.origin`** — the server never knows its public domain, so there is deliberately no base-URL env/config; whatever address the browser is on becomes the link prefix. Below the link row: a `<details>` "Show QR code" toggle — QR of the full share URL rendered client-side via `qrcode-generator` (`drawQR`), white bg tile, block only `qrcode.min.js` globals, `~20 KB`.
- **Read view:** passphrase pastes show an unlock form (wrong passphrase → inline "Wrong passphrase.", `select()` the field); random-key pastes decrypt via fragment, then strip the hash. Paste renders in `pre.paste-view > code` via **`textContent` only — never `innerHTML` with paste content** (hljs handles its own escaping). Editor-style copy icon (`.copybtn`, absolute top-right of `.codewrap`, copy SVG). Below the paste: burn note (when burned) and an expiry countdown (`expiresIn()`: "X min", "X h", "X d"). `head` carries static OG tags (`og:title zeropaste`, generic `og:description`) — no content leaks to unfurlers. Syntax highlighting is **always on** (`hl: true` sent on every create; old pastes with `hl:false` may render plain — honoring the stored flag is correct). Burned pastes fire `DELETE` (fire-and-forget) after successful decrypt and show a burned note; burn+passphrase pastes delete only after successful decrypt.
- hljs is invoked as `hljs.highlightElement` when `paste.hl && window.hljs`.
- **Mobile:** `@media (max-width: 540px)` — single-column stacking, full-width controls/tap targets, `#ttl` full width, smaller body padding. Base layout already fluid (`clamp` padding, `viewport-fit=cover`).
- **Footer (`.foot`)** — three lines: (1) `<b>zeropaste</b> — share secrets, not plaintext. … encrypted in your browser (AES-256-GCM) …`, (2) burn-time glossary (`m`inutes · `h`ours · `d`ays, e.g. "10m", "6h", "1d" · 1 minute to 30 days), (3) links `GitHub` / `Report an issue` pointing at `https://github.com/2TAP2B/zeropaste` plus `self-hosted · no accounts · no tracking`.

## 7. Dev environment (NixOS)

- `flake.nix`: single `nixpkgs` (`github:NixOS/nixpkgs/nixos-unstable`) input. Outputs: `devShells.x86_64-linux.default = mkShell` (packages `go`, `git`, `ripgrep`, `nodejs`), `packages.${system}.default` (see `package.nix`), `nixosModules.zeropaste` (see `module.nix`). Self-contained — no external flake inputs.
- `.envrc`: `use flake` (user runs `direnv allow` once).
- Run everything inside the shell: `nix develop --command sh -c '...'`.
- hljs assets were fetched over TLS from jsdelivr (see §3) — if rebuilding from zero, fetch those two files before building.

## 8. Verification protocol (must pass before "done")

```sh
nix develop --command sh -c 'gofmt -l . && go vet ./... && go test ./... && node --check web/assets/app.js && go build -trimpath -ldflags="-s -w" -o paste .'
```

- `gofmt -l` prints nothing; vet and tests must be green; `node --check` must accept `app.js` — a JS syntax error silently kills every event handler while the page still renders, so this gate is mandatory (learned the hard way).
- Test suite (all in `main_test.go`, unreferenced helpers there): `TestRoundTrip` (create→read, metadata echo incl. `expires`), `TestBurnAfterRead` (2nd GET 404), `TestExpiredPaste404s` (rewinds expiry on disk: 404 + file removed), `TestBadRequests` (short data / bad ttl `2w` / `31d` / empty ttl / undecodable data / bad salt → all 400), `TestParseTTL` (valid table incl. `"10 min"`, `30 days`, `6H`; invalid `"0d"`, `"1w"`, `"1h30m"`, `"-5m"`, `"5"`, empty), `TestPassphrasePaste` (salt+burn: GET does NOT destroy, metadata echoed, `DELETE` → 200 → GET 404), `TestAssetsServed` (file 200 + dir listing 404), `TestIndexServed` (`/` and `/p/whatever` 200 with page, unknown path 404), `TestRateLimit` (30× 200 then 429), `TestPathValueAbuse` (charset/traversal/short ids → 404; DELETE same), `TestHealthz` (200 `ok`), `TestAuthGate` (with `CREATE_KEY` set: no header → 401, wrong key → 401, correct key → 200, paste publicly readable, healthz open).
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
