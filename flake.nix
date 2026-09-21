{
  description = "Nexus Infra - reusable NixOS infrastructure modules";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm.url = "github:microvm-nix/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { microvm, ... }: {
    nixosModules = {
      host-base = import ./host-modules/base.nix;
      microvm-host = {
        imports = [
          microvm.nixosModules.host
          ./host-modules/microvm-host.nix
        ];
      };
      vm-base = import ./vm-modules/base.nix;
      vm-persistent = import ./vm-modules/persistent.nix;
      nexus-agent = import ./host-modules/nexus-agent.nix;
      nexus-console = import ./vm-modules/console.nix;
    };
  };
}
