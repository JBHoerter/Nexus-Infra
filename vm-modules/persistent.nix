{ config, lib, ... }:
{
  options.nexus.persistence = lib.mkOption {
    default = { };
    description = "Named guest storage requests, with backing directories assigned by the deployment.";
    type = lib.types.attrsOf (lib.types.submodule {
      options = {
        mountPoint = lib.mkOption {
          type = lib.types.str;
          description = "Absolute mount point inside the guest.";
        };
        source = lib.mkOption {
          type = lib.types.str;
          description = "Absolute host directory supplied by the deployment's storage mapping.";
        };
      };
    });
  };

  config = {
    assertions = lib.mapAttrsToList (name: storage: {
      assertion = builtins.match "[a-zA-Z0-9_-]+" name != null
        && lib.hasPrefix "/" storage.mountPoint
        && lib.hasPrefix "/" storage.source;
      message = "Persistent share ${name} requires a simple name and absolute host/guest paths.";
    }) config.nexus.persistence;

    microvm.shares = lib.mapAttrsToList (name: storage: {
      tag = name;
      proto = "virtiofs";
      inherit (storage) source mountPoint;
    }) config.nexus.persistence;
  };
}
