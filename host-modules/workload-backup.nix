{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-backup;
  backupLib = pkgs.runCommand "nexus-backup-lib" { } ''
    mkdir $out
    for name in worker catalog artifacts recovery statefiles repository backup; do
      cp ${../console}/$name.py $out/$name.py
    done
  '';
  backupCli = pkgs.writeShellApplication {
    name = "nexus-backup";
    runtimeInputs = [
      pkgs.python3 pkgs.restic pkgs.openssh pkgs.util-linux
      pkgs.coreutils pkgs.systemd pkgs.nix pkgs.iproute2
    ];
    text = ''
      exec ${pkgs.util-linux}/bin/unshare --mount --propagation private -- \
        ${pkgs.python3}/bin/python3 ${backupLib}/backup.py \
          --config ${lib.escapeShellArg cfg.configurationFile} "$@"
    '';
  };
in {
  options.services.nexus-workload-backup = {
    enable = lib.mkEnableOption "the root-only nexus backup capture/upload worker";
    configurationFile = lib.mkOption {
      type = lib.types.str;
      description = "Absolute path to the admin-provided non-secret backup configuration JSON (cache, repository ids, bindings, workerConfigFile).";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = lib.hasPrefix "/" cfg.configurationFile;
      message = "services.nexus-workload-backup.configurationFile must be an absolute path";
    }];
    environment.systemPackages = [ backupCli ];
  };
}
