# Create a deployment

This is a starting point for an **already installed NixOS host**, not an installer or disk-provisioning tool. Run these steps on the intended host or through its SSH alias. Enable CPU virtualization in firmware and verify KVM is available. The public guest defaults have been tested on x86_64 with QEMU/KVM.

Keep your existing hardware configuration, working administrator account, SSH access and state version. Review the public host baseline's boot/network/SSH choices before adopting it. These examples use placeholder machine and workload names, not the reference deployment's private configuration.

## Private repository

A small deployment can start with:

```text
flake.nix
flake.lock
hosts/my-host/
  configuration.nix
  hardware-configuration.nix
vms/demo/default.nix
cluster/my-host.nix
```

`hosts/` defines physical machines. `vms/` defines concrete guest instances. `cluster/` assigns those instances to a host and supplies networking/storage mappings. This is a directory convention, not an additional orchestration framework.

Use this `flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nexus-infra.url = "github:JBHoerter/Nexus-Infra";
    nexus-infra.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, nexus-infra, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = { inherit nexus-infra; };
      modules = [
        nexus-infra.nixosModules.host-base
        nexus-infra.nixosModules.microvm-host
        ./hosts/my-host/configuration.nix
        ./cluster/my-host.nix
      ];
    };
  };
}
```

Move/adapt your existing installed host configuration into `hosts/my-host/`; import its real `hardware-configuration.nix`. Do not copy another machine's filesystem UUIDs. Preserve user access and explicitly review `networking.hostName`, bootloader, network management and `system.stateVersion`. Use `lib.mkForce` where the public baseline sets a conflicting non-default value. No account password or private key belongs in this file or the store; public authorized SSH keys are not secrets.

For a host-only first build, `cluster/my-host.nix` can be `{ ... }: { }`. Initialize Git and stage new Nix files before building: Git-backed flakes exclude untracked files.

```sh
git init -b main
git add flake.nix hosts cluster
nix flake lock
git add flake.lock
sudo nixos-rebuild build --flake .#my-host
# Review the result and preserve an existing SSH session before activating.
sudo nixos-rebuild switch --flake .#my-host
```

These commands do not partition disks. New hardware needs installation/provisioning and the correct hardware configuration before this workflow can reproduce it.

## First MicroVM

Create `vms/demo/default.nix`:

```nix
{ ... }: {
  networking.hostName = "demo";
  microvm.vcpu = 1;
  microvm.mem = 256;
}
```

Replace `cluster/my-host.nix` with:

```nix
{ nexus-infra, ... }: {
  microvm.vms.demo = {
    autostart = true;
    config = {
      imports = [
        nexus-infra.nixosModules.vm-base
        nexus-infra.nixosModules.vm-persistent
        ../vms/demo
      ];
    };
  };
}
```

Stage the guest, build and switch. This boots a minimal guest with **no configured network interface or SSH service**; add those explicitly in your deployment. Inspect it through the host:

```sh
git add vms cluster
sudo nixos-rebuild build --flake .#my-host
sudo nixos-rebuild switch --flake .#my-host
systemctl status microvm@demo --no-pager
sudo journalctl -u microvm@demo -n 100 --no-pager
sudo systemctl restart microvm@demo
```

Systemd accepting a restart does not mean the guest application is ready. Check application readiness separately. After changing runners, compare `/var/lib/microvms/demo/booted` with `current`; a full explicit restart after the guest has finished booting reconciles stale MicroVM helper metadata that can remain after switching.

## Persistent data and networking

A concrete guest asks for a logical mount:

```nix
# Inside vms/demo/default.nix:
nexus.persistence.app-data.mountPoint = "/var/lib/demo";
```

The placement module supplies its backing directory:

```nix
# Alongside the imports in microvm.vms.demo.config:
nexus.persistence.app-data.source = "/srv/workload-data/demo/app-data";
```

The path above is illustrative: declare your real backing filesystem in the private host configuration, mount it first, and choose ownership appropriate to the guest service. A disk is not provisioned by merely naming a directory. See [Storage and networking](storage-network.md) for startup ordering and numeric UID considerations.

For connectivity, the private deployment must define a host bridge, attach each guest's TAP using `microvm.interfaces`, assign guest addresses with networkd, and declare firewall/routes. `vm-base` enables networkd and disables DHCP; it does not allocate addresses or provide Internet access. Choose an unused subnet appropriate for your deployment. Keep the physical host's management interface separate unless you deliberately design otherwise.

## Add console and infrastructure roles

The current private deployment defines Headscale and Traefik using their ordinary NixOS modules. They are not public Nexus exports or a generated reference deployment. Configure and review your own endpoints, storage and access policy before adopting these roles.

For the console, import `nixosModules.nexus-agent` on each physical host and `nixosModules.nexus-console` in its management VM. Supply matching inventory, agent URLs, browser origins and runtime TLS credential paths through the services' `settings` and credential options. Declare `/var/lib/nexus-console` as persistent guest storage. Provision certificates at runtime and restrict agent connectivity in the host firewall. The public modules do not generate deployment PKI, expose ingress, select controllable VMs or reserve service UIDs for you.

[Console documentation](../console/README.md) and its source define the current API/configuration contract. Settings are currently an untyped attribute set; there is no turnkey enrollment command or complete multi-host configuration generator.

## Update dependencies and contribute

After reviewing an upstream change, update only the intended input and commit its lock:

```sh
nix flake update nexus-infra
sudo nixos-rebuild build --flake .#my-host
git add flake.lock
git commit -m 'Update Nexus modules'
```

To test a local public checkout without changing the committed GitHub dependency:

```sh
sudo nixos-rebuild build --flake .#my-host \
  --override-input nexus-infra path:/absolute/path/to/Nexus-Infra \
  --no-write-lock-file
```

Stage newly added files in the public Git checkout as appropriate. Keep local overrides out of deployment commits. Push tested public changes first, update the private lock to that public revision, build, and then commit/push the private deployment. Do not add a dependency on a private deployment to Nexus-Infra.
