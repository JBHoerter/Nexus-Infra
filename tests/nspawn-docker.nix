{ pkgs, ... }:
let
  image = pkgs.dockerTools.buildLayeredImage {
    name = "nexus-runtime-probe";
    tag = "1";
    contents = [ pkgs.python3 pkgs.iptables ];
    config.Cmd = [ "${pkgs.python3}/bin/python3" "-m" "http.server" "8080" "--bind" "0.0.0.0" "--directory" "/state" ];
  };
  compose = pkgs.writeText "nexus-lab-compose.yml" ''
    services:
      probe:
        image: nexus-runtime-probe:1
        pull_policy: never
        container_name: nexus-lab-probe
        restart: unless-stopped
        ports:
          - "8080:8080"
        volumes:
          - /state:/state
  '';
in {
  name = "nexus-nspawn-docker";
  nodes.machine = import ./nspawn-fixture.nix { docker = true; };
  testScript = ''
    import shlex

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl start nix-daemon.socket")
    machine.succeed("test -S /nix/var/nix/daemon-socket/socket")
    machine.fail("test -S /run/docker.sock")
    machine.succeed("printf nested-initial > /var/lib/nexus-lab/state/index.html")
    machine.succeed("chown 65536:65536 /var/lib/nexus-lab/state/index.html")
    machine.succeed("mkdir /sys/fs/cgroup/nexus-host-sentinel")
    machine.succeed("systemctl start container@probe.service")
    machine.wait_until_succeeds("nixos-container run probe -- systemctl is-active docker.service", timeout=90)
    machine.succeed("nixos-container run probe -- docker load --input ${image}")
    machine.succeed("nixos-container run probe -- docker-compose --file ${compose} --project-name nexus-lab up --detach")
    machine.wait_until_succeeds("curl --fail --silent http://192.168.100.2:8080/", timeout=90)
    assert machine.succeed("curl --fail --silent http://192.168.100.2:8080/").strip() == "nested-initial"
    machine.fail("test -S /run/docker.sock")
    machine.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
    uid_map = machine.succeed("nixos-container run probe -- cat /proc/self/uid_map").split()
    assert uid_map == ["0", "65536", "65536"], uid_map

    with subtest("the selected OCI runtime preserves the isolation boundary"):
        runtime = machine.succeed("nixos-container run probe -- docker inspect --format '{{.HostConfig.Runtime}}' nexus-lab-probe").strip()
        assert runtime == "crun", runtime
        program = "from pathlib import Path; rows = Path('/proc/self/mountinfo').read_text().splitlines(); assert any(row.split()[4] == '/sys' and 'ro' in row.split()[5].split(',') for row in rows); assert not Path('/sys/fs/cgroup/nexus-host-sentinel').exists(); assert Path('/proc/self/uid_map').read_text().split() == ['0', '65536', '65536']"
        machine.succeed("nixos-container run probe -- docker exec nexus-lab-probe ${pkgs.python3}/bin/python3 -c " + shlex.quote(program))
    machine.succeed("test -d /sys/fs/cgroup/nexus-host-sentinel")

    with subtest("Docker host networking stays inside the workload namespace"):
        machine.succeed("nixos-container run probe -- docker run --rm --network host --cap-add NET_ADMIN nexus-runtime-probe:1 ${pkgs.iptables}/bin/iptables --wait -N NEXUS_LAB")
        machine.succeed("nixos-container run probe -- iptables --wait -S NEXUS_LAB")
        machine.fail("iptables --wait -S NEXUS_LAB")

    with subtest("Docker and application state survive outer-container restart"):
        program = "from pathlib import Path; Path('/state/index.html').write_text('nested-persisted')"
        machine.succeed("nixos-container run probe -- docker exec nexus-lab-probe ${pkgs.python3}/bin/python3 -c " + shlex.quote(program))
        machine.succeed("systemctl restart container@probe.service")
        machine.wait_until_succeeds("nixos-container run probe -- docker inspect nexus-lab-probe", timeout=90)
        machine.wait_until_succeeds("curl --fail --silent http://192.168.100.2:8080/", timeout=90)
        assert machine.succeed("curl --fail --silent http://192.168.100.2:8080/").strip() == "nested-persisted"
        machine.fail("test -S /run/docker.sock")
  '';
}
