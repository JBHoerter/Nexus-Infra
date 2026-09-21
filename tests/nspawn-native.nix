{ ... }:
{
  name = "nexus-nspawn-native";
  nodes.source = import ./nspawn-fixture.nix { };
  nodes.target = import ./nspawn-fixture.nix { };
  testScript = ''
    import shlex

    start_all()
    for host in (source, target):
        host.wait_for_unit("multi-user.target")
        host.succeed("systemctl start nix-daemon.socket")
        host.succeed("test -S /nix/var/nix/daemon-socket/socket")
        host.succeed("printf host-only > /root/nexus-host-only")
        host.succeed("printf initial-state > /var/lib/nexus-lab/state/index.html")
        host.succeed("chown 65536:65536 /var/lib/nexus-lab/state/index.html")
        host.succeed("systemctl start container@probe.service")
        host.wait_until_succeeds("curl --fail --silent http://192.168.100.2:8080/", timeout=90)
        host.succeed("nixos-container run probe -- test ! -e /root/nexus-host-only")
        host.fail("nixos-container run probe -- touch /nix/store/nexus-lab-write")
        host.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
        uid_map = host.succeed("nixos-container run probe -- cat /proc/self/uid_map").split()
        assert uid_map == ["0", "65536", "65536"], uid_map
        host_net = host.succeed("readlink /proc/1/ns/net").strip()
        guest_net = host.succeed("nixos-container run probe -- readlink /proc/1/ns/net").strip()
        assert host_net != guest_net

    with subtest("same workload configuration on either host"):
        source_system = source.succeed("nixos-container run probe -- readlink /run/current-system").strip()
        target_system = target.succeed("nixos-container run probe -- readlink /run/current-system").strip()
        assert source_system == target_system, (source_system, target_system)

    with subtest("persistent state survives outer container restart"):
        source.succeed("nixos-container run probe -- sh -c " + shlex.quote("printf recovered-state > /state/index.html"))
        source.succeed("systemctl restart container@probe.service")
        source.wait_until_succeeds("curl --fail --silent http://192.168.100.2:8080/", timeout=90)
        assert source.succeed("curl --fail --silent http://192.168.100.2:8080/").strip() == "recovered-state"

    with subtest("state can be restored on a stopped target with the same workload"):
        source.succeed("systemctl stop container@probe.service")
        target.succeed("systemctl stop container@probe.service")
        state = source.succeed("cat /var/lib/nexus-lab/state/index.html")
        target.succeed("printf %s " + shlex.quote(state) + " > /var/lib/nexus-lab/state/index.html")
        target.succeed("systemctl start container@probe.service")
        target.wait_until_succeeds("curl --fail --silent http://192.168.100.2:8080/", timeout=90)
        assert target.succeed("curl --fail --silent http://192.168.100.2:8080/").strip() == "recovered-state"
        source.fail("systemctl is-active --quiet container@probe.service")
  '';
}
