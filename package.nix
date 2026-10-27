{
  lib,
  buildGoModule,
}:

# zeropaste in one derivation: single Go binary, embedded web/, stdlib only.
# rec: the -X main.version stamp interpolates the version attr in this set.
buildGoModule rec {
  pname = "zeropaste";
  version = "0.12.0";
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
