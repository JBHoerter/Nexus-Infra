# Nexus Infra

Reusable NixOS host and MicroVM modules. Dependencies point from a deployment to this public repository, never back to a private deployment.

- `nixosModules.host-base`: physical-host baseline.
- `nixosModules.microvm-host`: pinned upstream MicroVM host integration. For fully declarative guests, backing filesystems are required before share directories, virtiofs daemons and guests start.
- `nixosModules.vm-base`: small QEMU/KVM guest defaults and a read-only host Nix-store share.
- `nixosModules.vm-persistent`: named persistent directory requests using virtiofs.

A guest requests `nexus.persistence.<name>.mountPoint`. Its deployment supplies `nexus.persistence.<name>.source`. The module produces the virtiofs share; the host module orders startup against the actual backing filesystem. Disk identities, concrete paths, VM names, addresses and placements remain in the deployment.

Import guest modules through `microvm.vms.<name>.config`. Set this flake's `nixpkgs` input to follow the deployment's package set. The lock file pins upstream dependencies.

Upstream: https://microvm-nix.github.io/microvm.nix/declarative.html
