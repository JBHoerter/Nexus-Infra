{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-workload-artifacts;
  configJson = pkgs.writeText "nexus-artifacts-config.json" (builtins.toJSON {
    schemaVersion = 1;
    stateDir = cfg.stateDir;
    trustedPublicKeys = cfg.trustedPublicKeys;
    sources = cfg.sources;
    bundles = cfg.bundles;
  });
  artifactLib = pkgs.runCommand "nexus-artifacts-lib" { } ''
    mkdir $out
    cp ${../console/worker.py} $out/worker.py
    cp ${../console/artifacts.py} $out/artifacts.py
    cp ${../console/catalog.py} $out/catalog.py
    cp ${../console/distribution.py} $out/distribution.py
  '';
  artifactsCli = pkgs.writeShellApplication {
    name = "nexus-artifacts";
    runtimeInputs = [ pkgs.python3 pkgs.nix ];
    text = ''
      exec ${pkgs.python3}/bin/python3 ${artifactLib}/distribution.py --config ${configJson} "$@"
    '';
  };
in {
  options.services.nexus-workload-artifacts = {
    enable = lib.mkEnableOption "the root-only local signed artifact distribution worker";
    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/nexus-artifacts";
      description = "Root-owned retained-reference and gcroot directory.";
    };
    trustedPublicKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Nix Ed25519 public keys (name:base64) the fetched store paths must be signed by.";
    };
    sources = lib.mkOption {
      type = lib.types.listOf lib.types.attrs;
      default = [ ];
      description = "Administrator-declared binary cache sources ({id,uri}); callers never supply URIs.";
    };
    bundles = lib.mkOption {
      type = lib.types.listOf lib.types.attrs;
      default = [ ];
      description = "Approved {workloadId,revisionDigest,bundlePath,sourceId} records; bundle paths are strings, not dependencies.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ artifactsCli ];
    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0700 root root -"
      "d ${cfg.stateDir}/roots 0700 root root -"
      "d ${cfg.stateDir}/refs 0700 root root -"
    ];
  };
}
