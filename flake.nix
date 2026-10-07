{
  description = "zeropaste — zero-knowledge paste sharing: dev shell, package, NixOS module";

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
          go
          git
          ripgrep
          nodejs # JS syntax gate: node --check web/assets/app.js
        ];

        shellHook = ''
          echo "paste dev shell: $(go version)"
        '';
      };
    };
}
