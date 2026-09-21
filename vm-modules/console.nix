{ config, lib, pkgs, ... }:
let
  cfg = config.services.nexus-console;
  settingsFile = (pkgs.formats.json { }).generate "nexus-console.json" cfg.settings;
in {
  options.services.nexus-console = {
    enable = lib.mkEnableOption "Nexus cluster management console";
    settings = lib.mkOption { type = lib.types.attrs; };
    caFile = lib.mkOption { type = lib.types.str; };
    certificateFile = lib.mkOption { type = lib.types.str; };
    keyFile = lib.mkOption { type = lib.types.str; };
  };
  config = lib.mkIf cfg.enable {
    users.users.nexus-console = { isSystemUser = true; group = "nexus-console"; };
    users.groups.nexus-console = { };
    systemd.services.nexus-console = {
      description = "Nexus cluster console and management API";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      unitConfig.RequiresMountsFor = [ "/var/lib/nexus-console" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 ${../console}/server.py ${settingsFile}";
        User = "nexus-console";
        Group = "nexus-console";
        StateDirectory = "nexus-console";
        StateDirectoryMode = "0700";
        UMask = "0077";
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
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        CapabilityBoundingSet = "";
        MemoryMax = "256M";
        TasksMax = 64;
      };
    };
  };
}
