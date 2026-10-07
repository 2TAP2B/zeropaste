{
  lib,
  buildGoModule,
}:

# zeropaste in one derivation: single Go binary, embedded web/, stdlib only.
buildGoModule {
  pname = "zeropaste";
  version = "0.2.0";
  src = ./.;
  vendorHash = null; # stdlib only — nothing to vendor

  env.CGO_ENABLED = "0";
  ldflags = [ "-s" "-w" ];

  # go installs the binary after the module path ("paste"), which collides
  # with coreutils paste(1) in PATH — rename it.
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
