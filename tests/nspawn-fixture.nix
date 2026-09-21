{ docker ? false }:
{ lib, pkgs, ... }:
{
  virtualisation.memorySize = if docker then 3072 else 1536;
  virtualisation.cores = 1;
  virtualisation.useNixStoreImage = true;
  environment.systemPackages = [ pkgs.curl pkgs.iptables ];
  boot.kernelModules = lib.optionals docker [ "overlay" "br_netfilter" ];
  systemd.tmpfiles.rules = [
    "d /nix/var/nix/db 0755 root root -"
    "d /nix/var/nix/daemon-socket 0755 root root -"
    "d /var/lib/nexus-lab 0711 root root -"
    "d /var/lib/nexus-lab/state 0700 65536 65536 -"
  ] ++ lib.optionals docker [
    "d /var/lib/nexus-lab/docker 0700 65536 65536 -"
    "d /var/lib/nexus-lab/containerd 0700 65536 65536 -"
  ];
  containers.probe = {
    autoStart = false;
    ephemeral = true;
    privateNetwork = true;
    privateUsers = 65536;
    hostAddress = "192.168.100.1";
    localAddress = "192.168.100.2";
    extraFlags = [
      "--private-users-ownership=auto"
      "--inaccessible=/nix/var/nix/daemon-socket"
    ] ++ lib.optionals docker [
      "--system-call-filter=keyctl"
      "--system-call-filter=bpf"
    ];
    bindMounts = {
      "/state" = { hostPath = "/var/lib/nexus-lab/state"; isReadOnly = false; };
    } // lib.optionalAttrs docker {
      "/var/lib/docker" = { hostPath = "/var/lib/nexus-lab/docker"; isReadOnly = false; };
      "/var/lib/containerd" = { hostPath = "/var/lib/nexus-lab/containerd"; isReadOnly = false; };
    };
    config = { lib, pkgs, ... }: {
      system.stateVersion = "26.05";
      networking.hostName = "probe";
      networking.useHostResolvConf = false;
      networking.firewall.allowedTCPPorts = [ 8080 ];
      nix.enable = false;
      environment.systemPackages = [ pkgs.curl pkgs.iptables ] ++ lib.optionals docker [ pkgs.docker-compose ];
      virtualisation.docker = {
        enable = docker;
        storageDriver = "overlay2";
        daemon.settings = lib.mkIf docker {
          "default-runtime" = "crun";
          runtimes.crun.path = "${pkgs.crun}/bin/crun";
        };
      };
      systemd.services.fixture = lib.mkIf (!docker) {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind 0.0.0.0 --directory /state";
          Restart = "on-failure";
          NoNewPrivileges = true;
        };
      };
    };
  };
}
