{
  description = "ZeroPaste dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          nodejs_24
          gcc
          python3
          gnumake
          docker
          docker-compose
          git
          ripgrep
          fd
          jq
        ];

        env = {
          NODE_ENV = "development";
        };

        shellHook = ''
          if [ ! -d node_modules ]; then
            echo "Installing dependencies..."
            npm install --no-audit --no-fund
          fi
          echo "zeropaste dev shell: node $(node --version)"
        '';
      };
    };
}
