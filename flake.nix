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

      # boots the module in a VM: the sandbox (MemoryDenyWriteExecute,
      # ProtectProc, ProcSubset, syscall filter) must not break the Go
      # runtime, and createKeyFile must reach the process as the create gate
      checks.${system}.module = pkgs.testers.runNixOSTest {
        name = "zeropaste-module";
        nodes.machine = {
          imports = [ self.nixosModules.zeropaste ];
          services.zeropaste = {
            enable = true;
            createKeyFile = "/etc/zeropaste.env";
          };
          environment.etc."zeropaste.env".text = "CREATE_KEY=vm-test-key\n";
        };
        testScript = ''
          paste = """-H 'Content-Type: application/json' -d '{"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ttl":"5m"}' http://127.0.0.1:8080/api/paste"""
          machine.wait_for_unit("zeropaste.service")
          machine.wait_for_open_port(8080)
          machine.succeed("curl -fsS http://127.0.0.1:8080/healthz | grep -qx ok")
          machine.succeed(f"test \"$(curl -s -o /dev/null -w '%{{http_code}}' {paste})\" = 401")
          machine.succeed(f"curl -fsS -H 'Authorization: Bearer vm-test-key' {paste} | grep -q '\"id\"'")
          machine.succeed("test \"$(stat -c %a /var/lib/private/zeropaste)\" = 700")
          print(machine.succeed("systemd-analyze security zeropaste.service | tail -n 1"))
        '';
      };

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
