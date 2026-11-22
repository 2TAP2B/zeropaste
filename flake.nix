{
  description = "zeropaste - zero-knowledge paste sharing: dev shell, package, NixOS module";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system}.default = pkgs.callPackage ./package.nix { };

      nixosModules.zeropaste = ./module.nix;

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          go_1_26 # same line as package.nix and the docker builder (golang:1.26-alpine)
          git
          ripgrep
          nodejs # typescript runner (tsc)
          typescript
          esbuild # bundles web/ts -> one embedded app.js
        ];

        shellHook = ''
          echo "paste dev shell: $(go version)"
        '';
      };
    };
}
