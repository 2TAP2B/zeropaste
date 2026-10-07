{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.zeropaste;
in
{
  options.services.zeropaste = {
    enable = mkEnableOption "zeropaste — zero-knowledge paste sharing";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The zeropaste package to run.";
    };

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1:8080";
      description = ''
        Listen address (`addr:port`). Keep it on loopback when a reverse proxy
        terminates TLS in front — the app deliberately sets no HSTS.
      '';
    };

    createKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Path to a root-owned file with a `CREATE_KEY=<secret>` line. When set,
        POST /api/paste requires Authorization: Bearer <secret>; reads and
        burns stay open (the link is the capability). Leave null for a fully
        public instance. Kept out of the option system on purpose so the
        secret never lands in the world-readable store.
      '';
    };
  };

  config = mkIf cfg.enable {
    systemd.services.zeropaste = {
      description = "zeropaste — zero-knowledge paste sharing";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/zeropaste -addr ${cfg.listenAddress} -data /var/lib/zeropaste";
        EnvironmentFile = mkIf (cfg.createKeyFile != null) [ cfg.createKeyFile ];
        StateDirectory = "zeropaste"; # /var/lib/zeropaste, emitted per DynamicUser
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = 5;

        # hardening: the server is two flags and a static dir — sandbox it tight
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        CapabilityBoundingSet = [ ];
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
      };
    };
  };
}
