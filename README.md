# zeropaste

Self-hosted, zero-knowledge paste sharing in a single Go binary. The browser encrypts your paste (AES-256-GCM via WebCrypto) before it ever hits the wire — the server stores ciphertext and nothing else. The decryption key rides in the URL fragment, which browsers never send upstream.

No accounts. No cookies. No request logs. No third-party Go dependencies.

## Features

- Zero-knowledge: random key per paste, lives in the URL fragment, stripped from the address bar after decrypt
- Optional passphrase mode: PBKDF2-SHA-256 (600k iterations) + random salt; the link alone is useless, share the passphrase over another channel
- Burn after reading (paste dies on first successful decrypt — link unfurlers and wrong-passphrase visitors can't destroy it)
- Free-form burn time: `10m`, `6h`, `1d`, `30 days` — 1 minute to 30 days by default (`MAX_TTL_DAYS` raises or lowers the ceiling), swept by a janitor every minute
- File bundles that stay encrypted end to end (AES-GCM key per share, manifest never readable by the server), with client-side thumbnails so big photo bundles load fast
- Optional syntax highlighting (vendored highlight.js, no CDN calls) with auto language detection
- Share link QR code, rendered client-side
- Optional create-gate: one site passphrase in front of `POST /api/paste` (`CREATE_KEY` env); reads stay public — the link is the capability
- Optional passkey accounts: register/sign in from the account pane (header icon). Creating pastes while signed in feeds the **active-shares dashboard** (the server sees only expiry/burn, never content) with per-row copy and delete. Registration can be locked with `REG_OPEN=false`, closed after the first account with `USER_REGISTRATION=false`, and the whole thing switched off with `USER_ACCOUNTS=false`
- Hardened defaults: strict CSP, nosniff, DENY framing, no-referrer, 30 pastes/min/IP rate limit, slowloris timeouts, no directory listings

## Install

Self-host in 30 seconds — image from GHCR, ~9 MB, nothing to build:

```sh
docker run -d --name zeropaste -p 8080:8080 -v paste-data:/data ghcr.io/2tap2b/zeropaste:latest
```

Open the address and share. That single line is already fully zero-knowledge and anonymous. All knobs (create-gate, accounts, TTL ceiling, share caps) live in `compose.yaml`, every one commented, so a fresh deploy never surprises:

```yaml
services:
  paste:
    image: ghcr.io/2tap2b/zeropaste:latest
    ports:
      - "8080:8080"
    volumes:
      - paste-data:/data
    restart: unless-stopped
    # environment:                 # all optional
    #   CREATE_KEY: "change-me"       # site passphrase in front of creates
    #   USER_ACCOUNTS: "true"         # "false" disables accounts entirely
    #   USER_REGISTRATION: "true"     # "false": sign-up closes after the first account
    #   MAX_TTL_DAYS: "30"            # share-time ceiling in days (1..366)
    #   MAX_SHARES_PER_ACCOUNT: "0"   # active shares per account; 0 = unlimited
volumes:
  paste-data:
```

The app UI carries the same two blocks — footer → **self-host in 30 seconds**.

From source (Go 1.25+):

```sh
git clone https://github.com/2TAP2B/zeropaste && cd zeropaste
go build -trimpath -ldflags="-s -w" -o paste .
./paste                     # http://127.0.0.1:8080
```

Production: the app speaks plain HTTP and is proxy-agnostic. Put any TLS-capable reverse proxy in front; HSTS belongs there, not in the app. The rate limiter reads the last `X-Forwarded-For` entry, which is what a typical proxy appends. Shares links are built in the browser from the address you opened, so there is no base-URL config and never will be.

## Configuration

Every value is optional; unset means the default. Set them via `environment:` in compose.yaml or plain env:

| env | default | what it does |
|---|---|---|
| `CREATE_KEY` | _(unset)_ | site passphrase in front of `POST /api/paste` and bundle creates; reads stay public — the link is the capability. **Presence is the switch.** |
| `USER_ACCOUNTS` | `true` | `false` switches the whole identity subsystem off: no registration, no sign-in, no dashboard rows — the app runs anonymous-only. |
| `USER_REGISTRATION` | `true` | `false` = first-user bootstrap: sign-up stays open only until the first account exists, then closes (sign-ins keep working). |
| `REG_OPEN` | `true` | static registration kill switch (useful after the first account; sign-ins always stay open). |
| `MAX_TTL_DAYS` | `30` | share-time ceiling in days (1–366); enforced on text pastes and file bundles alike. |
| `MAX_SHARES_PER_ACCOUNT` | `0` (unlimited) | cap on active shares per account; beyond it creations answer `403 share limit reached`. |
| `MAX_BLOB` | `2147483648` (2 GiB) | total ciphertext per file bundle (1 MiB–64 GiB). |
| `CHUNK` | `8388608` (8 MiB) | bytes per upload/range chunk (64 KiB–64 MiB). |
| `SESSION_SECRET` | auto-generated | HMAC key for account session cookies; set it when the data dir does not persist it. |

TLS/HSTS belong to the reverse proxy in front — the app speaks plain HTTP and stays proxy-agnostic.

## How it works

Random-key flow: the browser generates 32 random bytes, encrypts (AES-256-GCM, 12-byte IV), uploads `base64url(iv || ciphertext)`. The key goes into `https://your.host/p/<id>#<keyB64>`. Fragments never leave the browser, so neither server logs nor proxies ever see the key. The reader decrypts locally, then `history.replaceState` removes the key from the address bar.

Passphrase flow: 16-byte salt goes to the server, the key is derived in the browser from passphrase + salt (PBKDF2, 600k iterations). The link contains no key; the passphrase never touches the network.

Burn: for random-key pastes the server deletes the file right after the first fetch. For passphrase pastes the client sends `DELETE` only after a successful decrypt. A janitor goroutine removes expired files every minute. Everything is a 0600 JSON file in a 0700 directory — no database. Share links are assembled client-side from `location.origin`; the server never knows its public hostname.

## Security model

- Keys exist only in the browser; the server cannot read any paste, compromised or subpoenaed
- Nothing to find: no accounts, cookies, sessions, or request logs — the only traces are ciphertext, salt, and an expiry timestamp
- Create-gate passphrase is per-tab in `sessionStorage`, never persisted
- Supply chain: zero Go modules (`govulncheck` clean), vendored highlight.js and qrcode-generator are committed, never hotlinked
- Advanced: strict CSP (`default-src 'self'`), `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, body caps, per-IP fixed-window limiter, constant-time key comparison
- Paste rendering uses `textContent` only — `innerHTML` with paste content does not exist

For full details, read [AGENTS.md](AGENTS.md) — the complete spec.

## Contributing

PRs welcome, but respect the constraints: single binary, stdlib-only Go, no auth beyond the create-gate, no cookies, English UI. Run `gofmt`, `go vet`, `go test`, and `node --check web/assets/app.js` before submitting; add a test for every abuse case before adding the mitigation.
