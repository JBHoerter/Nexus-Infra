{ pkgs, ... }:
let
  goveeImage = pkgs.dockerTools.pullImage {
    imageName = "ghcr.io/wez/govee2mqtt";
    imageDigest = "sha256:d5427fa1524e3e6f87c59e5cbc59e782036a2b5274e4f96cfb581d844aa2b6dc";
    hash = "sha256-gOoO3MyxwMcn5DQ2kU0cnclzJRUUXCdEQueWVKCLtXc=";
    finalImageName = "nexus-govee";
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
  mqttConfig = pkgs.writeText "mosquitto.conf" ''
    listener 1883
    allow_anonymous true
    persistence true
    persistence_location /mosquitto/data/
    autosave_interval 1
    log_dest stdout
  '';
  compose = pkgs.writeText "govee-probe.json" (builtins.toJSON {
    services = {
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
      govee = {
        image = "nexus-govee:fixture";
        pull_policy = "never";
        container_name = "nexus-govee";
        restart = "unless-stopped";
        privileged = false;
        network_mode = "host";
        volumes = [ "/state/govee:/data" ];
        environment = {
          GOVEE_MQTT_HOST = "127.0.0.1";
          GOVEE_MQTT_PORT = "1883";
          GOVEE_TEMPERATURE_SCALE = "C";
          TZ = "UTC";
        };
      };
    };
  });
in {
  name = "nexus-nspawn-govee";
  nodes.machine = { lib, pkgs, ... }: {
    imports = [ (import ./nspawn-fixture.nix { docker = true; }) ];
    virtualisation.diskSize = 8192;
    networking.firewall.allowedUDPPorts = [ 4001 4003 ];
    boot.kernel.sysctl."net.ipv4.ip_forward" = lib.mkForce 0;
    boot.kernel.sysctl."net.ipv6.conf.all.forwarding" = lib.mkForce 0;
    containers.probe.config.networking.firewall.allowedUDPPorts = [ 4002 ];
    containers.probe.config.networking.firewall.allowedTCPPorts = [ 8056 ];
    systemd.services.govee-fixture = {
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${./govee-device.py}";
    };
  };
  testScript = ''
    import json
    import shlex
    import time

    DEVICE_ID = "00:00:00:00:00:00:00:42"
    COMMAND_TOPIC = "gv2mqtt/light/0000000000000042/command"

    def helper_state():
        rc, out = machine.execute("cat /run/govee-fixture.json")
        return json.loads(out) if rc == 0 else {}

    def multicast_route():
        route = json.loads(machine.succeed("nixos-container run probe -- ip -j route get 192.168.100.1"))
        machine.succeed(f"nixos-container run probe -- ip route replace 239.255.255.250/32 dev {route[0]['dev']}")

    def discovered(timeout=120):
        deadline = time.monotonic() + timeout
        devices = []
        while time.monotonic() < deadline:
            rc, out = machine.execute("curl --fail --silent http://192.168.100.2:8056/api/devices")
            if rc == 0:
                try:
                    devices = json.loads(out)
                except ValueError:
                    devices = []
                if isinstance(devices, list) and any(
                    device.get("id") == DEVICE_ID
                    and device.get("sku") == "H610A"
                    and device.get("ip") == "192.168.100.1"
                    and isinstance(device.get("state"), dict)
                    and device["state"].get("source") == "LAN API"
                    and device["state"].get("on") is True
                    for device in devices if isinstance(device, dict)
                ) and helper_state().get("sawMulticast") is True:
                    return devices
            time.sleep(2)
        raise AssertionError(f"synthetic Govee device not discovered via LAN: {devices} {helper_state()}")

    def mqtt_command(command, expect_on, timeout=90):
        deadline = time.monotonic() + timeout
        current = {}
        while time.monotonic() < deadline:
            machine.succeed("nixos-container run probe -- docker exec nexus-mqtt mosquitto_pub -h 127.0.0.1 -t " + COMMAND_TOPIC + " -m " + shlex.quote(json.dumps({"state": command})))
            time.sleep(2)
            current = helper_state()
            if current.get("on") == expect_on and current.get("lastCommandSource") == "192.168.100.2":
                return
        raise AssertionError(f"synthetic device did not observe MQTT {command}: {current}")

    def assert_containers():
        for name in ("nexus-mqtt", "nexus-govee"):
            inspected = json.loads(machine.succeed(f"nixos-container run probe -- docker inspect {name}"))
            assert inspected[0]["State"]["Running"] is True, name
            assert inspected[0]["HostConfig"]["Privileged"] is False, name
            assert inspected[0]["HostConfig"]["Runtime"] == "crun", name
        govee = json.loads(machine.succeed("nixos-container run probe -- docker inspect nexus-govee"))
        assert govee[0]["HostConfig"]["NetworkMode"] == "host", govee[0]["HostConfig"]["NetworkMode"]

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl start nix-daemon.socket")
    machine.succeed("test -S /nix/var/nix/daemon-socket/socket")
    machine.fail("test -S /run/docker.sock")
    assert machine.succeed("cat /proc/sys/net/ipv4/ip_forward").strip() == "0"
    assert machine.succeed("cat /proc/sys/net/ipv6/conf/all/forwarding").strip() == "0"
    machine.succeed("mkdir -p /var/lib/nexus-lab/state/mqtt /var/lib/nexus-lab/state/govee")
    machine.succeed("chown 67419:67419 /var/lib/nexus-lab/state/mqtt")
    machine.succeed("chown 66536:66536 /var/lib/nexus-lab/state/govee")
    machine.succeed("systemctl start container@probe.service")
    machine.wait_until_succeeds("nixos-container run probe -- systemctl is-active docker.service", timeout=90)
    machine.succeed("nixos-container run probe -- docker load --input ${mqttImage}")
    machine.succeed("nixos-container run probe -- docker load --input ${goveeImage}")
    uid_map = machine.succeed("nixos-container run probe -- cat /proc/self/uid_map").split()
    assert uid_map == ["0", "65536", "65536"], uid_map
    machine.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")

    multicast_route()
    machine.succeed("systemctl start govee-fixture.service")
    machine.wait_until_succeeds("test -s /run/govee-fixture.json", timeout=30)

    machine.succeed("nixos-container run probe -- docker-compose --file ${compose} --project-name nexus-lab up --detach mosquitto")
    machine.wait_until_succeeds("nixos-container run probe -- docker exec nexus-mqtt mosquitto_pub -h 127.0.0.1 -t nexus/lab/canary -m govee-lab-canary -r", timeout=60)
    canary = machine.succeed("nixos-container run probe -- docker exec nexus-mqtt mosquitto_sub -h 127.0.0.1 -t nexus/lab/canary -C 1 -W 10").strip()
    assert canary == "govee-lab-canary", canary

    machine.succeed("nixos-container run probe -- docker-compose --file ${compose} --project-name nexus-lab up --detach govee")
    discovered()

    with subtest("both services run non-privileged under crun"):
        assert_containers()

    with subtest("the Govee LAN client stays inside the workload network namespace"):
        pid = machine.succeed("nixos-container run probe -- docker inspect --format '{{.State.Pid}}' nexus-govee").strip()
        govee_netns = machine.succeed(f"nixos-container run probe -- readlink /proc/{pid}/ns/net").strip()
        probe_netns = machine.succeed("nixos-container run probe -- readlink /proc/1/ns/net").strip()
        host_netns = machine.succeed("readlink /proc/1/ns/net").strip()
        assert govee_netns == probe_netns, (govee_netns, probe_netns)
        assert govee_netns != host_netns, (govee_netns, host_netns)

    mqtt_command("OFF", False)
    mqtt_command("ON", True)

    with subtest("LAN discovery and MQTT commands survive outer-container restart"):
        old_generation = helper_state()["generation"]
        machine.succeed("printf govee-bind-persist > /var/lib/nexus-lab/state/govee/nexus-sentinel")
        machine.succeed("systemctl restart container@probe.service")
        machine.wait_until_succeeds("nixos-container run probe -- docker inspect nexus-govee nexus-mqtt", timeout=120)
        assert_containers()
        multicast_route()
        machine.succeed("systemctl restart govee-fixture.service")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = helper_state()
            if current.get("generation") and current["generation"] != old_generation:
                break
            time.sleep(1)
        else:
            raise AssertionError(f"helper did not produce a fresh state generation: {current}")
        discovered()
        mqtt_command("OFF", False)
        mqtt_command("ON", True)
        rc, sentinel = machine.execute("nixos-container run probe -- docker exec nexus-govee cat /data/nexus-sentinel")
        if rc != 0:
            machine.succeed("nixos-container run probe -- docker cp nexus-govee:/data/nexus-sentinel /tmp/nexus-sentinel-copy")
            sentinel = machine.succeed("nixos-container run probe -- cat /tmp/nexus-sentinel-copy")
        assert sentinel.strip() == "govee-bind-persist", sentinel
        machine.fail("test -S /run/docker.sock")
        machine.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
  '';
}
