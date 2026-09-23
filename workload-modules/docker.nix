{ pkgs, ... }: {
  imports = [ ./base.nix ];
  virtualisation.docker = {
    enable = true;
    storageDriver = "overlay2";
    daemon.settings = {
      "default-runtime" = "crun";
      runtimes.crun.path = "${pkgs.crun}/bin/crun";
    };
  };
  systemd.services.docker.serviceConfig.LimitNPROC = 65535;
}
