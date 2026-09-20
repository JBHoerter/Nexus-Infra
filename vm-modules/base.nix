{ lib, ... }:
{
  microvm = {
    hypervisor = lib.mkDefault "qemu";
    vcpu = lib.mkDefault 1;
    mem = lib.mkDefault 256;
    shares = [{
      proto = "virtiofs";
      tag = "ro-store";
      source = "/nix/store";
      mountPoint = "/nix/.ro-store";
      readOnly = true;
    }];
  };

  networking.useDHCP = false;
  networking.useNetworkd = true;
  system.stateVersion = lib.mkDefault "26.05";
}
