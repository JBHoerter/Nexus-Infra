{ config, lib, pkgs, ... }:
{
  microvm.host.enable = true;

  # Fully declarative guests: mount each backing filesystem before creating
  # its share directories or starting the share daemon and guest.
  systemd.services = lib.mkMerge (lib.mapAttrsToList (name: vm:
    let
      sources = map (share: share.source)
        (lib.filter (share: share.source != "/nix/store") vm.config.config.microvm.shares);
    in lib.optionalAttrs (sources != [ ]) {
      "microvm@${name}".unitConfig.RequiresMountsFor = sources;
      "microvm-virtiofsd@${name}" = {
        unitConfig.RequiresMountsFor = sources;
        requires = [ "microvm-storage-${name}.service" ];
        after = [ "microvm-storage-${name}.service" ];
      };
      "microvm-storage-${name}" = {
        description = "Prepare mounted storage for MicroVM ${name}";
        unitConfig.RequiresMountsFor = sources;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.systemd}/bin/systemd-tmpfiles --create "
            + lib.escapeShellArgs (map (source: "--prefix=${source}") sources);
        };
      };
    }
  ) (lib.filterAttrs (_: vm: vm.config != null) config.microvm.vms));
}
