{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-agent;
  settingsFile = (pkgs.formats.json { }).generate "nexus-agent.json" cfg.settings;
  units = map (vm: "microvm@${vm.id}.service")
    (lib.filter (vm: vm.controllable or false) (cfg.settings.inventory.vms or [ ]));
in {
  options.services.nexus-agent = {
    enable = lib.mkEnableOption "Nexus host observation and bounded VM actions";
    settings = lib.mkOption { type = lib.types.attrs; };
    caFile = lib.mkOption { type = lib.types.str; };
    certificateFile = lib.mkOption { type = lib.types.str; };
    keyFile = lib.mkOption { type = lib.types.str; };
  };
  config = lib.mkIf cfg.enable {
    users.users.nexus-agent = { isSystemUser = true; group = "nexus-agent"; };
    users.groups.nexus-agent = { };
    security.polkit.enable = true;
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        if (subject.user !== "nexus-agent") return polkit.Result.NOT_HANDLED;
        var units = ${builtins.toJSON units};
        if (action.id === "org.freedesktop.systemd1.manage-units" &&
            units.indexOf(action.lookup("unit")) !== -1 &&
            ["start", "stop", "restart"].indexOf(action.lookup("verb")) !== -1)
          return polkit.Result.YES;
        return polkit.Result.NO;
      });
    '';
    systemd.services.nexus-agent = {
      description = "Nexus host agent";
      wantedBy = [ "multi-user.target" ];
      # Binding retries until the private address exists; do not wait on unrelated links.
      after = [ "network.target" "polkit.service" ];
      path = [ pkgs.systemd pkgs.iproute2 ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 ${../console}/agent.py ${settingsFile}";
        User = "nexus-agent";
        Group = "nexus-agent";
        LoadCredential = [ "ca:${cfg.caFile}" "cert:${cfg.certificateFile}" "key:${cfg.keyFile}" ];
        Restart = "on-failure";
        RestartSec = 3;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        CapabilityBoundingSet = "";
        MemoryMax = "192M";
        TasksMax = 64;
      };
    };
  };
}
