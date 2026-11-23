# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub:
[Security → Report a vulnerability](https://github.com/2TAP2B/zeropaste/security/advisories/new).
Do not open a public issue for anything exploitable.

Include what you can: affected version (footer of the instance), the request
or steps that trigger it, and the impact you expect. zeropaste is maintained in
spare time - expect an acknowledgement within a week; fixes ship as a point
release with credit in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives fixes. Self-hosters: update the image or the
flake input - `docker compose pull && docker compose up -d`.

## Scope

In scope: the server (`main.go`), the browser client and its crypto
(`web/`), the container image, the Nix package and NixOS module, and the CI
that builds and publishes them.

The zero-knowledge model, its limits, and deliberate trade-offs (for example:
whoever holds a paste link can delete an encrypted paste; sessions are
stateless cookies) are documented in the
[security model](https://2tap2b.github.io/zeropaste/guide/security). Reports
showing those trade-offs are worse than documented are welcome.

## Dependencies

Dependabot watches every ecosystem in the repo (Go modules, Docker base
images, GitHub Actions, the docs site's npm packages, the Nix flake), and CI
runs `govulncheck` daily against both shipped Go toolchains (the Docker
builder and the Nix package).
