{ pkgs, ... }:
let
  haImage = pkgs.dockerTools.pullImage {
    imageName = "ghcr.io/home-assistant/home-assistant";
    imageDigest = "sha256:a21689ef0510df9760ee11bab4d6b2fef3ed5c1a29ed9c3224271597a23729eb";
    hash = "sha256-RfevjTYLw5qIbyY6p0g09cNwNFFC5mrxGZYOQuMDDhs=";
    finalImageName = "nexus-homeassistant";
    finalImageTag = "fixture";
    os = "linux";
    arch = "amd64";
  };
  mqttImage = pkgs.dockerTools.pullImage {
    imageName = "docker.io/library/eclipse-mosquitto";
    imageDigest = "sha256:a908c65cc8e67ec9d292ef27c2c0360dbaaee7eb1b935cdd194e67697f15dea1";
    hash = "sha256-Tp46OmFa9XNAY2BKwvt07TrxfvE6mAPKy/wbmrK4hUI=";
    finalImageName = "nexus-mosquitto";
    finalImageTag = "fixture";
    os = "linux";
    arch = "amd64";
  };
  haConfig = pkgs.writeText "configuration.yaml" ''
    homeassistant:
      name: Nexus Lab
      latitude: 0
      longitude: 0
      elevation: 0
      unit_system: metric
      time_zone: UTC
    default_config:
    http:
      server_host: 0.0.0.0
  '';
  mqttConfig = pkgs.writeText "mosquitto.conf" ''
    listener 1883
    allow_anonymous true
    persistence true
    persistence_location /mosquitto/data/
    autosave_interval 1
    log_dest stdout
  '';
  compose = pkgs.writeText "homeassistant-probe.json" (builtins.toJSON {
    services = {
      homeassistant = {
        image = "nexus-homeassistant:fixture";
        pull_policy = "never";
        container_name = "nexus-ha";
        restart = "unless-stopped";
        network_mode = "host";
        privileged = false;
        environment.TZ = "UTC";
        volumes = [ "/state/ha:/config" ];
      };
      mosquitto = {
        image = "nexus-mosquitto:fixture";
        pull_policy = "never";
        container_name = "nexus-mqtt";
        restart = "unless-stopped";
        privileged = false;
        ports = [ "127.0.0.1:1883:1883" ];
        volumes = [
          "${mqttConfig}:/mosquitto/config/mosquitto.conf:ro"
          "/state/mqtt:/mosquitto/data"
        ];
      };
    };
  });
in {
  name = "nexus-nspawn-homeassistant";
  nodes.machine = { lib, ... }: {
    imports = [ (import ./nspawn-fixture.nix { docker = true; }) ];
    virtualisation.memorySize = lib.mkForce 4096;
    virtualisation.cores = lib.mkForce 2;
    virtualisation.diskSize = 16384;
    containers.probe.config.networking.firewall.allowedTCPPorts = [ 8123 ];
  };
  testScript = ''
    import json
    import shlex

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl start nix-daemon.socket")
    machine.succeed("test -S /nix/var/nix/daemon-socket/socket")
    machine.fail("test -S /run/docker.sock")
    machine.succeed("mkdir -p /var/lib/nexus-lab/state/ha /var/lib/nexus-lab/state/mqtt")
    machine.succeed("chown 65536:65536 /var/lib/nexus-lab/state/ha")
    machine.succeed("chown 67419:67419 /var/lib/nexus-lab/state/mqtt")
    machine.succeed("cp ${haConfig} /var/lib/nexus-lab/state/ha/configuration.yaml")
    machine.succeed("chown 65536:65536 /var/lib/nexus-lab/state/ha/configuration.yaml")
    machine.succeed("mkdir /sys/fs/cgroup/nexus-host-sentinel")
    machine.succeed("systemctl start container@probe.service")
    machine.wait_until_succeeds("nixos-container run probe -- systemctl is-active docker.service", timeout=90)
    machine.succeed("nixos-container run probe -- docker load --input ${haImage}")
    machine.succeed("nixos-container run probe -- docker load --input ${mqttImage}")
    machine.succeed("nixos-container run probe -- docker-compose --file ${compose} --project-name nexus-lab up --detach")

    machine.wait_until_succeeds("curl --fail --silent http://192.168.100.2:8123/api/onboarding", timeout=240)
    onboarding = json.loads(machine.succeed("curl --fail --silent http://192.168.100.2:8123/api/onboarding"))
    assert isinstance(onboarding, list), onboarding
    assert any(step.get("step") == "user" and step.get("done") is False for step in onboarding), onboarding
    assert machine.succeed("curl --silent --location --output /dev/null --write-out '%{http_code}' http://192.168.100.2:8123/").strip() == "200"

    with subtest("Home Assistant and Mosquitto run non-privileged under crun"):
        for name in ("nexus-ha", "nexus-mqtt"):
            inspected = json.loads(machine.succeed(f"nixos-container run probe -- docker inspect {name}"))
            assert inspected[0]["State"]["Running"] is True, name
            assert inspected[0]["HostConfig"]["Privileged"] is False, name
            assert inspected[0]["HostConfig"]["Runtime"] == "crun", name
        ha = json.loads(machine.succeed("nixos-container run probe -- docker inspect nexus-ha"))
        assert ha[0]["HostConfig"]["NetworkMode"] == "host", ha[0]["HostConfig"]["NetworkMode"]

    with subtest("host networking stays inside the workload network namespace"):
        ha_netns = machine.succeed("nixos-container run probe -- docker exec nexus-ha python3 -c " + shlex.quote("import os; print(os.readlink('/proc/self/ns/net'))")).strip()
        probe_netns = machine.succeed("nixos-container run probe -- readlink /proc/1/ns/net").strip()
        host_netns = machine.succeed("readlink /proc/1/ns/net").strip()
        assert ha_netns == probe_netns, (ha_netns, probe_netns)
        assert ha_netns != host_netns, (ha_netns, host_netns)

    machine.fail("test -S /run/docker.sock")
    machine.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
    uid_map = machine.succeed("nixos-container run probe -- cat /proc/self/uid_map").split()
    assert uid_map == ["0", "65536", "65536"], uid_map
    program = "from pathlib import Path; rows = Path('/proc/self/mountinfo').read_text().splitlines(); assert any(row.split()[4] == '/sys' and 'ro' in row.split()[5].split(',') for row in rows); assert not Path('/sys/fs/cgroup/nexus-host-sentinel').exists(); assert Path('/proc/self/uid_map').read_text().split() == ['0', '65536', '65536']"
    machine.succeed("nixos-container run probe -- docker exec nexus-ha python3 -c " + shlex.quote(program))
    machine.succeed("test -d /sys/fs/cgroup/nexus-host-sentinel")

    with subtest("MQTT retained state and Home Assistant identity survive outer-container restart"):
        machine.succeed("nixos-container run probe -- docker exec nexus-mqtt mosquitto_pub -h 127.0.0.1 -t nexus/lab/state -m synthetic-retained -r")
        payload = machine.succeed("nixos-container run probe -- docker exec nexus-mqtt mosquitto_sub -h 127.0.0.1 -t nexus/lab/state -C 1 -W 10").strip()
        assert payload == "synthetic-retained", payload
        machine.wait_until_succeeds("test -s /var/lib/nexus-lab/state/mqtt/mosquitto.db", timeout=30)
        uuid_program = "import base64, json; from pathlib import Path; raw = Path('/config/.storage/core.uuid').read_bytes(); value = json.loads(raw); assert isinstance(value, dict) and value; print(base64.b64encode(raw).decode())"
        machine.wait_until_succeeds("nixos-container run probe -- docker exec nexus-ha python3 -c " + shlex.quote(uuid_program), timeout=90)
        uuid_before = machine.succeed("nixos-container run probe -- docker exec nexus-ha python3 -c " + shlex.quote(uuid_program)).strip()
        config_program = "import base64; from pathlib import Path; print(base64.b64encode(Path('/config/configuration.yaml').read_bytes()).decode())"
        config_before = machine.succeed("nixos-container run probe -- docker exec nexus-ha python3 -c " + shlex.quote(config_program)).strip()
        machine.succeed("systemctl restart container@probe.service")
        machine.wait_until_succeeds("nixos-container run probe -- docker inspect nexus-ha nexus-mqtt", timeout=120)
        for name in ("nexus-ha", "nexus-mqtt"):
            inspected = json.loads(machine.succeed(f"nixos-container run probe -- docker inspect {name}"))
            assert inspected[0]["State"]["Running"] is True, name
            assert inspected[0]["HostConfig"]["Privileged"] is False, name
            assert inspected[0]["HostConfig"]["Runtime"] == "crun", name
        ha = json.loads(machine.succeed("nixos-container run probe -- docker inspect nexus-ha"))
        assert ha[0]["HostConfig"]["NetworkMode"] == "host", ha[0]["HostConfig"]["NetworkMode"]
        machine.wait_until_succeeds("nixos-container run probe -- docker exec nexus-mqtt mosquitto_sub -h 127.0.0.1 -t nexus/lab/state -C 1 -W 10", timeout=120)
        payload_after = machine.succeed("nixos-container run probe -- docker exec nexus-mqtt mosquitto_sub -h 127.0.0.1 -t nexus/lab/state -C 1 -W 10").strip()
        assert payload_after == "synthetic-retained", payload_after
        machine.wait_until_succeeds("curl --fail --silent http://192.168.100.2:8123/api/onboarding", timeout=240)
        onboarding_after = json.loads(machine.succeed("curl --fail --silent http://192.168.100.2:8123/api/onboarding"))
        assert isinstance(onboarding_after, list), onboarding_after
        assert any(step.get("step") == "user" and step.get("done") is False for step in onboarding_after), onboarding_after
        uuid_after = machine.succeed("nixos-container run probe -- docker exec nexus-ha python3 -c " + shlex.quote(uuid_program)).strip()
        config_after = machine.succeed("nixos-container run probe -- docker exec nexus-ha python3 -c " + shlex.quote(config_program)).strip()
        assert uuid_after == uuid_before
        assert config_after == config_before
        machine.fail("test -S /run/docker.sock")
        machine.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
  '';
}
