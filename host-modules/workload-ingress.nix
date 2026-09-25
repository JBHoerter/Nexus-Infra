{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-ingress;
  configJson = pkgs.writeText "nexus-ingress-config.json" (builtins.toJSON {
    schemaVersion = 2;
    registryUrl = cfg.registryUrl;
    registry = cfg.registry;
    listenPort = cfg.listenPort;
    stateDir = "/var/lib/nexus-ingress";
  });
  ingressLib = pkgs.runCommand "nexus-ingress-lib" { } ''
    mkdir $out
    cp ${../console/ingress.py} $out/ingress.py
    cp ${../console/registry.py} $out/registry.py
    cp ${../console/statefiles.py} $out/statefiles.py
    cp ${../console/worker.py} $out/worker.py
    cp ${../console/catalog.py} $out/catalog.py
    cp ${../console/artifacts.py} $out/artifacts.py
    cp ${../console/common.py} $out/common.py
  '';
  ingressService = pkgs.writeShellApplication {
    name = "nexus-ingress";
    runtimeInputs = [ pkgs.python3 ];
    text = ''
      exec ${pkgs.python3}/bin/python3 ${ingressLib}/ingress.py --config ${configJson}
    '';
  };
in {
  options.services.nexus-workload-ingress = {
    enable = lib.mkEnableOption "the expiry-enforced Traefik ingress consumer";
    registryUrl = lib.mkOption {
      type = lib.types.str;
      description = "Administrator-owned https URL of the workload registry.";
    };
    registry = lib.mkOption {
      type = lib.types.attrs;
      description = "Registry core configuration for independent approval checks (definitions, hosts, routes).";
    };
    listenPort = lib.mkOption {
      type = lib.types.int;
      default = 9445;
      description = "Loopback-only port serving the Traefik provider document and forwardAuth guard.";
    };
    caFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the PEM certificate authority bundle; must not be a Nix store path.";
    };
    certificateFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the ingress client certificate; must not be a Nix store path.";
    };
    keyFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the ingress client private key; must not be a Nix store path.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = !lib.hasPrefix builtins.storeDir cfg.caFile
        && !lib.hasPrefix builtins.storeDir cfg.certificateFile
        && !lib.hasPrefix builtins.storeDir cfg.keyFile;
      message = "services.nexus-workload-ingress credential paths must be runtime paths, not Nix store paths.";
    }];

    users.users.nexus-ingress = {
      isSystemUser = true;
      group = "nexus-ingress";
      description = "Nexus workload ingress service user";
    };
    users.groups.nexus-ingress = { };

    services.traefik = {
      enable = true;
      staticConfigOptions = {
        entryPoints.web.address = ":80";
        providers.http = {
          endpoint = "http://127.0.0.1:${toString cfg.listenPort}/traefik";
          pollInterval = "2s";
        };
      };
    };

    systemd.services.nexus-workload-ingress = {
      description = "Nexus ingress route consumer and forwardAuth guard";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${ingressService}/bin/nexus-ingress";
        User = "nexus-ingress";
        Group = "nexus-ingress";
        StateDirectory = "nexus-ingress";
        StateDirectoryMode = "0700";
        LoadCredential = [
          "ca:${cfg.caFile}"
          "cert:${cfg.certificateFile}"
          "key:${cfg.keyFile}"
        ];
        UMask = "0077";
        Restart = "on-failure";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      };
    };

    systemd.services.traefik = {
      requires = [ "nexus-workload-ingress.service" ];
      after = [ "nexus-workload-ingress.service" ];
    };
  };
}
