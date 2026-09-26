{ config, lib, pkgs, options, ... }:
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
    bundleDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/nexus-secrets/bundles";
      description = "Root-owned 0700 host escrow directory holding the sealed secret bundles (<secretSetRef>.json envelope records plus <secretSetRef>.blob sealed blobs), populated out-of-band by the controller or operator; wired as the worker's secretsBundleDir default when the worker module is present.";
    };
  };
  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      assertions = [{
        assertion = lib.hasPrefix "/" cfg.configurationFile;
        message = "services.nexus-workload-secrets.configurationFile must be an absolute path";
      } {
        assertion = lib.hasPrefix "/" cfg.bundleDir;
        message = "services.nexus-workload-secrets.bundleDir must be an absolute path";
      }];
      environment.systemPackages = [ secretsCli ];
      systemd.tmpfiles.rules = [
        "d ${cfg.bundleDir} 0700 root root -"
      ];
    }
    (lib.optionalAttrs (options.services ? nexus-workload-worker) {
      # Pin the same wrapper binary, config file and escrow dir into
      # the worker as defaults — explicit worker options still win.
      services.nexus-workload-worker = {
        secretsProgram = lib.mkDefault "${secretsCli}/bin/nexus-secrets";
        secretsConfigFile = lib.mkDefault cfg.configurationFile;
        secretsBundleDir = lib.mkDefault cfg.bundleDir;
      };
    })
  ]);
}
