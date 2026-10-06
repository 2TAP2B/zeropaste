# zeropaste

Share secrets, not plaintext. A self-hosted, zero-knowledge paste service in a **single Go binary** — no accounts, no cookies, no logs, no third-party dependencies.

Text is encrypted **in your browser** (AES-256-GCM via WebCrypto) before it ever touches the server. The server stores only ciphertext; the decryption key lives in the URL fragment (`#…`), which browsers never send to servers, proxies, or logs.

## How it works

1. Type or paste text → browser generates a random 256-bit key, encrypts, uploads ciphertext only
2. You get a share link — the key rides in the fragment: `https://your.host/p/<id>#<key>`
3. Friends open the link → the page decrypts locally, then strips the key from the address bar
4. Optional **passphrase mode**: the key is derived from a passphrase (PBKDF2-SHA-256, 600k iterations + random salt) — the link alone is useless, share the passphrase over a different channel
5. Optional **burn after reading**: the paste is destroyed on first read (passphrase pastes: only after a *successful* decrypt — a link unfurler or wrong-passphrase visitor can't destroy it)

Pastes expire after a free-form burn time you type in (`10m`, `6h`, `1d`, `30 days` … between 1 minute and 30 days). A janitor sweeps expired ciphertext every minute.

Optional syntax highlighting (highlight.js, embedded — no CDN calls) and a QR code of the share link round out the UI.

## Quickstart

```sh
docker compose up -d --build   # http://localhost:8080
```

Or without Docker (Go 1.25+):

```sh
go build -o paste . && ./paste
```

Set your real burn-time passphrase and domain for production — TLS termination belongs to a reverse proxy; see [deployment notes](#deployment) below.

## Configuration

| Env / flag | Meaning |
|---|---|
| `CREATE_KEY` (env) | Optional create-gate: when set, `POST /api/paste` requires `Authorization: Bearer <key>`. Reads stay public — the link is the capability. Unset = fully public. |
| `-addr` (flag) | Listen address, default `127.0.0.1:8080` |
| `-data` (flag) | Directory for stored ciphertext, default `./data` (created `0700`, files `0600`) |

There is deliberately **no domain/base-URL setting** — share links are built in the browser from whatever address you opened the app under.

## Deployment

The app speaks plain HTTP and is proxy-agnostic. Put any reverse proxy with TLS in front (Caddy, nginx, traefik…):

- proxy `https://paste.example.com` → `http://127.0.0.1:8080`
- security headers (`CSP`, `X-Frame-Options`, …) are set by the app; `HSTS` belongs in the proxy config
- the rate limiter reads the **last** `X-Forwarded-For` entry — your proxy should append the real client IP (that is the default behavior of typical proxies)

Backups: pastes live as plain JSON files in the `paste-data` volume — tar it or snapshot it. In-flight pastes survive restarts and redeploys (SIGTERM drains gracefully).

Monitoring: `GET /healthz` returns `ok`.

## Security model

- **Zero knowledge:** keys generated and used exclusively in the browser; server stores AES-256-GCM ciphertext, at most 64 KiB per paste
- **No accounts, no cookies, no sessions, no request logging** — nothing to breach or subpoena
- Site-passphrase mode (create-gate): stored per browser tab in `sessionStorage`, never a cookie
- Hardened by default: strict CSP, `nosniff`, `DENY` framing, `no-referrer`, 30 pastes/min/IP rate limit, slowloris timeouts, directory listings off
- `govulncheck` clean; zero Go dependencies — supply chain is one vendored highlight.js

## Development

NixOS dev shell:

```sh
direnv allow                     # once; uses flake.nix
gofmt -l . && go vet ./... && go test ./... && node --check web/assets/app.js
```

Agents rebuilding or extending this project: read [AGENTS.md](AGENTS.md) — it is the complete specification of every deliberate decision (crypto contract, API, UI, Docker gotchas) and takes precedence over improvisation.

## License

No license yet — all rights reserved by the author until a license file lands.
