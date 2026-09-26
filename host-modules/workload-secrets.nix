{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-secrets;
  secretsLib = pkgs.runCommand "nexus-secrets-lib" { } ''
    mkdir $out
    for name in worker catalog artifacts statefiles secrets; do
      cp ${../console}/$name.py $out/$name.py
    done
  '';
  secretsCli = pkgs.writeShellApplication {
    name = "nexus-secrets";
    runtimeInputs = [
      pkgs.python3 pkgs.age pkgs.util-linux pkgs.coreutils
    ];
    text = ''
      exec ${pkgs.util-linux}/bin/unshare --mount --propagation private -- \
        ${pkgs.python3}/bin/python3 ${secretsLib}/secrets.py \
          --config ${lib.escapeShellArg cfg.configurationFile} "$@"
    '';
  };
in {
  options.services.nexus-workload-secrets = {
    enable = lib.mkEnableOption "the root-only nexus secret-bundle escrow tool";
    configurationFile = lib.mkOption {
      type = lib.types.str;
      description = "Absolute path to the admin-provided root-owned secrets configuration JSON ({schemaVersion:1, keyFile} — keyFile is an age identity file for seal+provision or a recipients-only file for seal-only).";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = lib.hasPrefix "/" cfg.configurationFile;
      message = "services.nexus-workload-secrets.configurationFile must be an absolute path";
    }];
    environment.systemPackages = [ secretsCli ];
  };
}
