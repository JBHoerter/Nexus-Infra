# Persistent per-host observation reporter (M5). Disabled by default.
#
# The reporter holds this host's mTLS client certificate (URI SAN
# urn:nexus:host:<hostId>), keeps a registry session open, observes every
# bound instance through the local worker and POSTs strictly-sequenced
# /v2/observations. It is strictly read-only with respect to the worker:
# it never starts, stops or mutates an instance, and it never claims
# fencing — missing evidence simply means no observation.
#
# Runs as root because it embeds the local worker (observe) whose journal
# and storage are root-owned; the only network surface is an outbound
# verified-TLS client plus short TCP liveness probes to slot addresses.
{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-reporter;
  configJson = pkgs.writeText "nexus-reporter-config.json" (builtins.toJSON ({
    schemaVersion = 2;
    hostId = cfg.hostId;
    registryUrl = cfg.registryUrl;
    registry = cfg.registry;
    stateDir = cfg.stateDir;
    workerConfigFile = cfg.workerConfigFile;
    observeIntervalSeconds = cfg.observeIntervalSeconds;
    requestTimeoutSeconds = cfg.requestTimeoutSeconds;
    maxBackoffSeconds = cfg.maxBackoffSeconds;
    # Optional dispatch CLIs: reporter.py accepts each program/config
    # pair only together; an absent pair makes the matching dispatch
    # steps refuse locally with a typed error receipt.
  } // lib.optionalAttrs (cfg.backupProgram != null) {
    inherit (cfg) backupProgram backupConfigFile;
  } // lib.optionalAttrs (cfg.restoreProgram != null) {
    inherit (cfg) restoreProgram restoreConfigFile;
  }));
  reporterLib = pkgs.runCommand "nexus-reporter-lib" { } ''
    mkdir $out
    for name in reporter registry statefiles worker artifacts catalog; do
      cp ${../console}/$name.py $out/$name.py
    done
  '';
  reporterService = pkgs.writeShellApplication {
    name = "nexus-reporter";
    # pkgs.nix is required: the embedded worker's verify_closure
    # shells out to nix/nix-store on dispatched prepare/start steps.
    runtimeInputs = [
      pkgs.python3 pkgs.systemd pkgs.util-linux pkgs.iproute2
      pkgs.coreutils pkgs.nix
    ];
    text = ''
      exec ${pkgs.python3}/bin/python3 ${reporterLib}/reporter.py --config ${configJson}
    '';
  };
in {
  options.services.nexus-workload-reporter = {
    enable = lib.mkEnableOption "the persistent host observation reporter";
    hostId = lib.mkOption {
      type = lib.types.str;
      description = "Stable host identity; must equal the worker's hostId and the host certificate identity (urn:nexus:host:<hostId>).";
    };
    registryUrl = lib.mkOption {
      type = lib.types.str;
      description = "Base https URL of the workload registry, e.g. https://registry.internal:9444.";
    };
    registry = lib.mkOption {
      type = lib.types.attrs;
      description = "Registry core configuration (definitions, hosts, routes); must match the registry server exactly — the reporter uses it to approve endpoint addresses, services and definitions.";
    };
    workerConfigFile = lib.mkOption {
      type = lib.types.str;
      description = "Absolute path to the local worker configuration JSON; pin services.nexus-workload-worker.configFile so both components share one binding.";
    };
    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/nexus-reporter";
      description = "Private reporter state directory holding the durable session/sequence file (must live under a writable root-owned path).";
    };
    observeIntervalSeconds = lib.mkOption {
      type = lib.types.int;
      default = 5;
      description = "Interval between observe/publish cycles (1..300).";
    };
    requestTimeoutSeconds = lib.mkOption {
      type = lib.types.int;
      default = 10;
      description = "Per-request registry HTTP timeout (1..120).";
    };
    maxBackoffSeconds = lib.mkOption {
      type = lib.types.int;
      default = 300;
      description = "Upper bound of the exponential backoff with jitter applied to failed cycles (1..3600).";
    };
    caFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the PEM certificate authority bundle; must not be a Nix store path.";
    };
    certificateFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the host client certificate; must not be a Nix store path.";
    };
    keyFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime path to the host client private key; must not be a Nix store path.";
    };
    backupProgram = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the pinned nexus-backup executable used for dispatched capture/upload steps; must be set together with backupConfigFile or the pair is omitted.";
    };
    backupConfigFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Absolute runtime path to the backup configuration JSON consumed by backupProgram; required when backupProgram is set.";
    };
    restoreProgram = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the pinned nexus-restore executable used for dispatched restore-stage/restore-commit steps; must be set together with restoreConfigFile or the pair is omitted.";
    };
    restoreConfigFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Absolute runtime path to the restore configuration JSON consumed by restoreProgram; required when restoreProgram is set.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = !lib.hasPrefix builtins.storeDir cfg.caFile
        && !lib.hasPrefix builtins.storeDir cfg.certificateFile
        && !lib.hasPrefix builtins.storeDir cfg.keyFile
        && lib.hasPrefix "/" cfg.workerConfigFile
        && lib.hasPrefix "/" cfg.stateDir
        && (cfg.backupProgram == null) == (cfg.backupConfigFile == null)
        && (cfg.restoreProgram == null) == (cfg.restoreConfigFile == null)
        && (cfg.backupConfigFile == null
            || lib.hasPrefix "/" cfg.backupConfigFile)
        && (cfg.restoreConfigFile == null
            || lib.hasPrefix "/" cfg.restoreConfigFile);
      message = "services.nexus-workload-reporter credential paths must be runtime paths, not Nix store paths; workerConfigFile/stateDir must be absolute; and each backup/restore program must be paired with its absolute configFile.";
    }];

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0700 root root -"
    ];

    systemd.services.nexus-workload-reporter = {
      description = "Nexus host observation reporter (mTLS)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = "${reporterService}/bin/nexus-reporter";
        LoadCredential = [
          "ca:${cfg.caFile}"
          "cert:${cfg.certificateFile}"
          "key:${cfg.keyFile}"
        ];
        UMask = "0077";
        Restart = "on-failure";
        RestartSec = "5s";
        # Root user, full /usr+/boot+/efi read-only; needs /var/lib
        # (worker journal) and its own stateDir writable.
        ProtectSystem = "full";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = [
          "AF_UNIX"   # systemctl over the local D-Bus socket
          "AF_INET" "AF_INET6"
          "AF_NETLINK"
        ];
      };
    };
  };
}
