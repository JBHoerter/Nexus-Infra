{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-restore;
  restoreLib = pkgs.runCommand "nexus-restore-lib" { } ''
    mkdir $out
    for name in worker catalog artifacts recovery statefiles repository restore; do
      cp ${../console}/$name.py $out/$name.py
    done
  '';
  restoreCli = pkgs.writeShellApplication {
    name = "nexus-restore";
    runtimeInputs = [
      pkgs.python3 pkgs.restic pkgs.openssh pkgs.util-linux
      pkgs.coreutils pkgs.systemd pkgs.nix pkgs.iproute2
    ];
    text = ''
      exec ${pkgs.util-linux}/bin/unshare --mount --propagation private -- \
        ${pkgs.python3}/bin/python3 ${restoreLib}/restore.py \
          --config ${lib.escapeShellArg cfg.configurationFile} "$@"
    '';
  };
in {
  options.services.nexus-workload-restore = {
    enable = lib.mkEnableOption "the root-only nexus restore-installation worker";
    configurationFile = lib.mkOption {
      type = lib.types.str;
      description = "Absolute path to the admin-provided non-secret restore configuration JSON (journal stateDir, workerConfigFile, repositories).";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = lib.hasPrefix "/" cfg.configurationFile;
      message = "services.nexus-workload-restore.configurationFile must be an absolute path";
    }];
    environment.systemPackages = [ restoreCli ];
  };
}
