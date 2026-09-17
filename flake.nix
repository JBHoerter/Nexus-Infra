{
  description = "Nexus Infra - reusable NixOS infrastructure modules";

  outputs = { self }: {
    nixosModules = {
      host-base = import ./host-modules/base.nix;
    };
  };
}
