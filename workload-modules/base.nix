{ lib, ... }: {
  boot.isNspawnContainer = true;
  networking.useDHCP = false;
  networking.useHostResolvConf = false;
  nix.enable = false;
  system.stateVersion = lib.mkDefault "26.05";
}
