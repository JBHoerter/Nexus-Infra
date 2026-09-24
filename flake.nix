{
  description = "Nexus Infra - reusable NixOS infrastructure modules";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm.url = "github:microvm-nix/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, microvm, ... }: {
    lib.tests.antragsbank = import ./tests/nspawn-antragsbank.nix;
    lib.buildWorkload = import ./workload-modules/build.nix { inherit nixpkgs; };
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
      workload-host = import ./host-modules/workload-host.nix;
      workload-base = import ./workload-modules/base.nix;
      workload-docker = import ./workload-modules/docker.nix;
    };
    checks.x86_64-linux =
      let pkgs = import nixpkgs { system = "x86_64-linux"; };
      in {
        nspawn-native = pkgs.testers.runNixOSTest (import ./tests/nspawn-native.nix);
        nspawn-docker = pkgs.testers.runNixOSTest (import ./tests/nspawn-docker.nix);
        nspawn-mailcow-netfilter = pkgs.testers.runNixOSTest (import ./tests/nspawn-mailcow-netfilter.nix);
        nspawn-homeassistant = pkgs.testers.runNixOSTest (import ./tests/nspawn-homeassistant.nix);
        nspawn-govee = pkgs.testers.runNixOSTest (import ./tests/nspawn-govee.nix);
        workload-artifact = pkgs.testers.runNixOSTest (import ./tests/workload-artifact.nix { inherit nixpkgs; });
        workload-worker = pkgs.testers.runNixOSTest (import ./tests/workload-worker.nix { inherit nixpkgs; });
      };
    packages.x86_64-linux.mailcow-integration-lab =
      let pkgs = import nixpkgs { system = "x86_64-linux"; };
      in (pkgs.testers.runNixOSTest (import ./tests/mailcow-integration.nix)).driver;
  };
}
