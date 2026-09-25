{ canary, hostId, uuid, slots }: { pkgs, lib, config, ... }: {
  imports = [ ../host-modules/workload-host.nix ];
  virtualisation.memorySize = 1536;
  virtualisation.cores = 1;
  virtualisation.useNixStoreImage = true;
  virtualisation.emptyDiskImages = [ 128 ];
  systemd.services.nix-daemon.serviceConfig = {
    PrivateMounts = true;
    ExecStart = [
      ""
      (pkgs.writeShellScript "nix-daemon-store-view" ''
        set -eu
        view=$(${pkgs.coreutils}/bin/mktemp -d /run/nix-daemon-view.XXXXXX)
        mkdir "$view/upper" "$view/work"
        ${pkgs.util-linux}/bin/mount -t overlay overlay \
          -o "lowerdir=/nix/store,upperdir=$view/upper,workdir=$view/work" \
          /nix/store
        exec ${config.nix.package}/bin/nix-daemon --daemon
      '')
    ];
  };
  systemd.services.register-nix-paths.script = lib.mkForce ''
    if [[ "$(cat /proc/cmdline)" =~ regInfo=([^ ]*) ]]; then
      ${pkgs.util-linux}/bin/unshare --mount --propagation private \
        ${pkgs.runtimeShell} -c '
          set -e
          view=$(${pkgs.coreutils}/bin/mktemp -d /run/register-store.XXXXXX)
          mkdir "$view/upper" "$view/work"
          ${pkgs.util-linux}/bin/mount -t overlay overlay \
            -o "lowerdir=/nix/store,upperdir=$view/upper,workdir=$view/work" \
            /nix/store
          exec ${lib.getExe' pkgs.nix "nix-store"} --load-db
        ' < "''${BASH_REMATCH[1]}"
    fi
  '';
  environment.systemPackages = [ pkgs.curl pkgs.e2fsprogs pkgs.jq ];
  boot.kernelModules = [ "tun" ];
  services.nexus-workload-worker = {
    enable = true;
    inherit hostId slots;
    approvedBundles = [ canary.bundle ];
    storage = { root = "/srv/workloads"; mountPoint = "/srv/workloads"; inherit uuid; };
    capacity = { memoryMiB = 768; cpuMillis = 1000; stateBytes = 33554432; };
    capabilities = [ "userns" "nspawn-v1" ];
  };
}
