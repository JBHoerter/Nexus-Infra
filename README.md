# Nexus Infra

Reusable NixOS modules. This public repository never depends on a private deployment.

- `host-modules/base.nix`: existing physical-host baseline.
- `host-modules/microvm-host.nix`: MicroVM host capability; the flake export also imports the pinned upstream host module.
- `vm-modules/base.nix`: small QEMU/KVM guest defaults and a read-only host Nix store share. Import through a host's `microvm.vms.<name>.config`.

The deployment owns physical machines, VM instances, addresses and named storage mappings. Use `nixosModules.host-base`, `nixosModules.microvm-host` and `nixosModules.vm-base` from this flake. Follow this flake's `nixpkgs` input from the deployment to use one package set.

Upstream: https://microvm-nix.github.io/microvm.nix/declarative.html
