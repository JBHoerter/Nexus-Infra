# Durable workload-move controller (M5). Disabled by default.
#
# The controller is a root-only, single-request CLI:
#
#     nexus-controller --config <file> execute  < request.json
#
# with verbs plan/execute/status/abort. Every phase transition is
# journaled under a private flock; replay of the same operationId
# returns the identical record. It never claims fencing: a dead source
# host blocks the move rather than completing it.
#
# Two invocation surfaces are provided:
#
#   * the `nexus-controller` CLI in systemPackages for interactive root
#     use (expects CREDENTIALS_DIRECTORY to name a directory holding
#     ca/cert/key PEM files — e.g. systemd-run --setenv or a wrapper);
#   * a dormant hardened oneshot template `nexus-controller@<name>`:
#     stage a bounded request JSON at <requestDirectory>/<name>.json,
#     then `systemctl start nexus-controller@<name>`; the controller
#     mTLS credentials and the request are loaded as credentials and
#     the canonical response lands in the journal.
#
# Cross-host note (M5): the controller can only *mutate* the local
# worker; remote target steps are journaled as verified remote-deferred
# instructions whose completion is proven by fresh registry evidence.
{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-controller;
  controllerLib = pkgs.runCommand "nexus-controller-lib" { } ''
    mkdir $out
    for name in controller registry statefiles worker artifacts catalog; do
      cp ${../console}/$name.py $out/$name.py
    done
  '';
  controllerCli = pkgs.writeShellApplication {
    name = "nexus-controller";
    runtimeInputs = [ pkgs.python3 ];
    text = ''
      exec ${pkgs.python3}/bin/python3 ${controllerLib}/controller.py \
        --config ${lib.escapeShellArg cfg.configurationFile} "$@"
    '';
  };
  controllerExecute = pkgs.writeShellApplication {
    name = "nexus-controller-execute";
    runtimeInputs = [
      pkgs.python3 pkgs.systemd pkgs.util-linux pkgs.iproute2
      pkgs.coreutils pkgs.restic pkgs.openssh pkgs.nix
    ];
    text = ''
      exec ${pkgs.python3}/bin/python3 ${controllerLib}/controller.py \
        --config ${lib.escapeShellArg cfg.configurationFile} execute \
        < "$CREDENTIALS_DIRECTORY/request"
    '';
  };
in {
  options.services.nexus-workload-controller = {
    enable = lib.mkEnableOption "the durable root-only workload-move controller";
    configurationFile = lib.mkOption {
      type = lib.types.str;
      description = "Absolute path to the admin-provided non-secret controller configuration JSON (hostId, stateDir, workerConfigFile, registryUrl, registry, backupProgram, backupConfigFile, restoreProgram, restoreConfigFile, requestTimeoutSeconds).";
    };
    requestDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/run/nexus-controller";
      description = "Directory where operators stage bounded request JSON for nexus-controller@<name>.service (name must match the operationId).";
    };
    caFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the PEM certificate authority bundle; must not be a Nix store path.";
    };
    certificateFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the controller client certificate (identity urn:nexus:controller:<id>); must not be a Nix store path.";
    };
    keyFile = lib.mkOption({
      type = lib.types.str;
      description = "Runtime path to the controller client private key; must not be a Nix store path.";
    });
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = lib.hasPrefix "/" cfg.configurationFile
        && !lib.hasPrefix builtins.storeDir cfg.caFile
        && !lib.hasPrefix builtins.storeDir cfg.certificateFile
        && !lib.hasPrefix builtins.storeDir cfg.keyFile
        && lib.hasPrefix "/" cfg.requestDirectory;
      message = "services.nexus-workload-controller credential paths must be runtime paths, not Nix store paths, and configurationFile/requestDirectory must be absolute.";
    }];

    environment.systemPackages = [ controllerCli ];

    systemd.tmpfiles.rules = [
      "d ${cfg.requestDirectory} 0700 root root -"
    ];

    # Dormant oneshot template — nothing starts it unless an operator
    # stages a request file and runs `systemctl start`.
    systemd.services."nexus-controller@" = {
      description = "Nexus workload controller request '%i'";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${controllerExecute}/bin/nexus-controller-execute";
        LoadCredential = [
          "ca:${cfg.caFile}"
          "cert:${cfg.certificateFile}"
          "key:${cfg.keyFile}"
          "request:${cfg.requestDirectory}/%i.json"
        ];
        UMask = "0077";
        TimeoutStartSec = "1h";
        # Children (nexus-backup/nexus-restore) unshare mounts and shell
        # out to restic/ssh, so filesystem and home access stay broader
        # than the registry/reporter units — but still read-only /usr,
        # private /tmp and read-only home.
        ProtectSystem = "full";
        ProtectHome = "read-only";
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = [
          "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK"
        ];
      };
    };
  };
}
