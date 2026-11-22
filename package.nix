{
  lib,
  buildGoModule,
  go_1_26,
}:

# zeropaste in one derivation: single Go binary, embedded web/, stdlib only.
# rec: the -X main.version stamp interpolates the version attr in this set.
# go_1_26, not the default go: nixpkgs moved its default to the 1.27 line,
# whose 1.27.3 still carries CVE-2026-97054 (GO-2026-6859, net/http
# MaxBytesReader crash - fixed in 1.26.11 / 1.27.4). The 1.26 line matches
# go.mod and the docker builder (golang:1.26-alpine).
(buildGoModule.override { go = go_1_26; }) rec {
  pname = "zeropaste";
  version = "0.12.6";
  src = ./.;
  # real vendor hash: Go now has the go-webauthn dependency
  vendorHash = "sha256-9/wut8nmHfRSwoTUxf1YgdFqggGe+eh9YCzLLpFFaUU=";

  env.CGO_ENABLED = "0";
  # the footer shows the installed version; nix checkouts have no .git either
  ldflags = [ "-s" "-w" "-X main.version=${version}" ];

  # go installs the binary after the module path ("paste"), which collides
  # with coreutils paste(1) in PATH - rename it.
  postInstall = ''
    if [ -f "$out/bin/paste" ]; then
      mv "$out/bin/paste" "$out/bin/zeropaste"
    fi
  '';

  meta = {
    mainProgram = "zeropaste";
    description = "Zero-knowledge paste sharing in a single Go binary";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
