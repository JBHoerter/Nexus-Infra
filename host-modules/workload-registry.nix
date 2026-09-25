{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-registry;
  configJson = pkgs.writeText "nexus-registry-config.json" (builtins.toJSON {
    schemaVersion = 2;
    listenAddress = cfg.listenAddress;
    port = cfg.port;
    dbPath = "/var/lib/nexus-registry/registry.db";
    registry = cfg.registry;
    clients = cfg.clients;
  });
  registryLib = pkgs.runCommand "nexus-registry-lib" { } ''
    mkdir $out
    cp ${../console/registry_api.py} $out/registry_api.py
    cp ${../console/registry.py} $out/registry.py
    cp ${../console/statefiles.py} $out/statefiles.py
    cp ${../console/worker.py} $out/worker.py
    cp ${../console/artifacts.py} $out/artifacts.py
    cp ${../console/catalog.py} $out/catalog.py
    cp ${../console/common.py} $out/common.py
  '';
  registryService = pkgs.writeShellApplication {
    name = "nexus-registry";
    runtimeInputs = [ pkgs.python3 ];
    text = ''
      exec ${pkgs.python3}/bin/python3 ${registryLib}/registry_api.py --config ${configJson}
    '';
  };
in {
  options.services.nexus-workload-registry = {
    enable = lib.mkEnableOption "the authenticated mTLS workload placement registry";
    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Address the registry TLS listener binds to.";
    };
    port = lib.mkOption {
      type = lib.types.int;
      default = 9444;
      description = "TCP port the registry TLS listener binds to.";
    };
    registry = lib.mkOption {
      type = lib.types.attrs;
      description = "Registry core configuration: definitions, hosts and routes.";
    };
    clients = lib.mkOption {
      type = lib.types.listOf lib.types.attrs;
      default = [ ];
      description = "Authorized mTLS clients ({identity,role,hostId}); identities are urn:nexus:<role>:<identifier> URI SANs.";
    };
    caFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the PEM certificate authority bundle; must not be a Nix store path.";
    };
    certificateFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the server certificate; must not be a Nix store path.";
    };
    keyFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the server private key; must not be a Nix store path.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = !lib.hasPrefix builtins.storeDir cfg.caFile
        && !lib.hasPrefix builtins.storeDir cfg.certificateFile
        && !lib.hasPrefix builtins.storeDir cfg.keyFile;
      message = "services.nexus-workload-registry credential paths must be runtime paths, not Nix store paths.";
    }];

    users.users.nexus-registry = {
      isSystemUser = true;
      group = "nexus-registry";
      description = "Nexus workload registry service user";
    };
    users.groups.nexus-registry = { };

    systemd.services.nexus-workload-registry = {
      description = "Nexus workload placement registry (mTLS)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${registryService}/bin/nexus-registry";
        User = "nexus-registry";
        Group = "nexus-registry";
        StateDirectory = "nexus-registry";
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
  };
}
