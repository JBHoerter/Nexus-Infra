{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-worker;
  configJson = pkgs.writeText "nexus-worker-config.json" (builtins.toJSON {
    schemaVersion = 1;
    hostId = cfg.hostId;
    architecture = pkgs.stdenv.hostPlatform.system;
    stateDir = cfg.stateDir;
    storage = cfg.storage;
    capacity = cfg.capacity;
    capabilities = cfg.capabilities;
    approvedBundles = cfg.approvedBundles;
    slots = cfg.slots;
  });
  workerLib = pkgs.runCommand "nexus-worker-lib" { } ''
    mkdir $out
    cp ${../console/worker.py} $out/worker.py
    cp ${../console/artifacts.py} $out/artifacts.py
    cp ${../console/catalog.py} $out/catalog.py
  '';
  workerCli = pkgs.writeShellApplication {
    name = "nexus-worker";
    runtimeInputs = [ pkgs.python3 pkgs.systemd pkgs.nix pkgs.util-linux pkgs.iproute2 pkgs.coreutils ];
    text = ''
      exec ${pkgs.python3}/bin/python3 ${workerLib}/worker.py --config ${configJson} "$@"
    '';
  };
  upstream = config.systemd.services."container@";
  pathEnv = lib.makeBinPath
    (upstream.path ++ [ pkgs.systemd pkgs.coreutils pkgs.findutils pkgs.util-linux ]);
  startScript = pkgs.writeShellScript "nexus-workload-start" upstream.script;
  preStartScript = pkgs.writeShellScript "nexus-workload-prestart" upstream.preStart;
  postStartScript = pkgs.writeShellScript "nexus-workload-poststart" upstream.postStart;
in {
  options.services.nexus-workload-worker = {
    enable = lib.mkEnableOption "the root-only local nexus workload worker";
    hostId = lib.mkOption {
      type = lib.types.str;
      description = "Stable host identity recorded in worker responses.";
    };
    approvedBundles = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = "Allowlisted workload bundle store paths the worker may instantiate.";
    };
    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/nexus-worker";
      description = "Root-owned worker journal directory.";
    };
    storage = lib.mkOption {
      type = lib.types.attrs;
      description = "Dedicated storage root/mountPoint/uuid record; the worker verifies the mounted UUID before use.";
    };
    capacity = lib.mkOption {
      type = lib.types.attrs;
      description = "Capacity ceiling {memoryMiB,cpuMillis,stateBytes}; effective budget is the minimum with measured values.";
    };
    capabilities = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "userns" "nspawn-v1" ];
      description = "Host capabilities advertised to admission.";
    };
    slots = lib.mkOption {
      type = lib.types.listOf lib.types.attrs;
      default = [ ];
      description = "Slot records {id,uidBase,hostAddress,localAddress} bound per workload instance.";
    };
  };

  config = lib.mkIf cfg.enable {
    boot.enableContainers = true;
    boot.kernelModules = [ "overlay" "tun" ];
    environment.systemPackages = [ workerCli ];
    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0700 root root -"
      "d ${cfg.stateDir}/instances 0700 root root -"
    ];
    systemd.units."nexus-workload@.service".text = ''
      [Unit]
      Description=Nexus workload instance '%i'
      RequiresMountsFor=${cfg.storage.mountPoint}

      [Service]
      Type=${upstream.serviceConfig.Type}
      SyslogIdentifier=nexus-workload %i
      Environment=INSTANCE=%i
      Environment=root=/run/nexus-workloads/%i
      Environment=PATH=${pathEnv}
      EnvironmentFile=${cfg.stateDir}/instances/%i/nspawn.env
      ExecCondition=${workerCli}/bin/nexus-worker guard --machine %i
      ExecStartPre=${preStartScript}
      ExecStart=${startScript}
      ExecStartPost=${postStartScript}
      RuntimeDirectory=nexus-workloads/%i
      TimeoutStartSec=${upstream.serviceConfig.TimeoutStartSec}
      Restart=no
      SuccessExitStatus=${toString upstream.serviceConfig.SuccessExitStatus}
      Slice=${upstream.serviceConfig.Slice}
      Delegate=yes
      KillMode=${upstream.serviceConfig.KillMode}
      KillSignal=${upstream.serviceConfig.KillSignal}
      DevicePolicy=closed
      DeviceAllow=/dev/net/tun rwm
      LimitNPROC=65535
      TasksMax=8192
    '';
  };
}
