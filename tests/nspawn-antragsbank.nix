{ image, controlsFile, sourceRevision }:
{ pkgs, ... }:
let
  compose = pkgs.writeText "antragsbank-probe.json" (builtins.toJSON {
    services.antragsbank = {
      image = "nexus-antragsbank:fixture";
      pull_policy = "never";
      container_name = "nexus-antragsbank";
      restart = "unless-stopped";
      privileged = false;
      ports = [ "8000:8000" ];
      env_file = [ "/state/lab.env" ];
      volumes = [ "/state/data:/app/data" "/state/lab:/lab:ro" ];
    };
  });
  node = { lib, pkgs, ... }: {
    imports = [ (import ./nspawn-fixture.nix { docker = true; }) ];
    virtualisation.memorySize = lib.mkForce 4096;
    virtualisation.cores = lib.mkForce 2;
    virtualisation.diskSize = 16384;
    boot.kernel.sysctl."net.ipv4.ip_forward" = lib.mkForce 0;
    boot.kernel.sysctl."net.ipv6.conf.all.forwarding" = lib.mkForce 0;
    containers.probe.config.networking.firewall.allowedTCPPorts = [ 8000 ];
  };
in {
  name = "nexus-nspawn-antragsbank";
  nodes = { source = node; target = node; };
  testScript = ''
    import json
    import shlex

    def boot_checks(node):
        node.wait_for_unit("multi-user.target")
        node.succeed("systemctl start nix-daemon.socket")
        node.succeed("test -S /nix/var/nix/daemon-socket/socket")
        node.fail("test -S /run/docker.sock")
        assert node.succeed("cat /proc/sys/net/ipv4/ip_forward").strip() == "0"
        assert node.succeed("cat /proc/sys/net/ipv6/conf/all/forwarding").strip() == "0"
        node.succeed("mkdir /sys/fs/cgroup/nexus-host-sentinel")
        node.succeed("test -d /sys/fs/cgroup/nexus-host-sentinel")

    def lab_exec(node, action):
        return node.succeed("nixos-container run probe -- docker exec nexus-antragsbank /usr/local/bin/python /lab/antragsbank-lab.py " + action)

    def container_checks(node):
        inspected = json.loads(node.succeed("nixos-container run probe -- docker inspect nexus-antragsbank"))
        assert inspected[0]["State"]["Running"] is True
        assert inspected[0]["HostConfig"]["Privileged"] is False
        assert inspected[0]["HostConfig"]["Runtime"] == "crun"
        labels = inspected[0]["Config"]["Labels"] or {}
        assert labels.get("org.nexus.sourceRevision") == "${sourceRevision}", labels
        assert labels.get("org.nexus.provenance") == "sanitized-rebuild", labels
        node.succeed("test -d /sys/fs/cgroup/nexus-host-sentinel")
        uid_map = node.succeed("nixos-container run probe -- cat /proc/self/uid_map").split()
        assert uid_map == ["0", "65536", "65536"], uid_map
        node.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
        program = "from pathlib import Path; rows = Path('/proc/self/mountinfo').read_text().splitlines(); assert any(row.split()[4] == '/sys' and 'ro' in row.split()[5].split(',') for row in rows); assert not Path('/sys/fs/cgroup/nexus-host-sentinel').exists(); assert Path('/proc/self/uid_map').read_text().split() == ['0', '65536', '65536']"
        node.succeed("nixos-container run probe -- docker exec nexus-antragsbank /usr/local/bin/python -c " + shlex.quote(program))

    def wait_app(node):
        node.wait_until_succeeds("curl --fail --silent --output /dev/null http://192.168.100.2:8000/login", timeout=180)

    start_all()
    for machine_node in (source, target):
        boot_checks(machine_node)

    source.succeed("mkdir -p /var/lib/nexus-lab/state/data /var/lib/nexus-lab/state/lab")
    source.succeed("chown -R 65536:65536 /var/lib/nexus-lab/state")
    source.succeed("cp ${./antragsbank-lab.py} /var/lib/nexus-lab/state/lab/antragsbank-lab.py")
    source.succeed("cp ${controlsFile} /var/lib/nexus-lab/state/lab/event_state_controls.json")
    source.succeed("chmod 644 /var/lib/nexus-lab/state/lab/antragsbank-lab.py /var/lib/nexus-lab/state/lab/event_state_controls.json")
    source.succeed("systemctl start container@probe.service")
    source.wait_until_succeeds("nixos-container run probe -- systemctl is-active docker.service", timeout=90)
    source.succeed("nixos-container run probe -- docker load --input ${image}")

    gen_env = "import os, secrets; open('/state/lab.env', 'w').write('JWT_SECRET=' + secrets.token_urlsafe(32) + '\\nLAB_PASSWORD=' + secrets.token_urlsafe(16) + '\\nANONYMIZED_TELEMETRY=False\\n'); os.chmod('/state/lab.env', 0o600)"
    source.succeed("nixos-container run probe -- docker run --rm --network none -v /state:/state nexus-antragsbank:fixture /usr/local/bin/python -c " + shlex.quote(gen_env))
    source.succeed("nixos-container run probe -- docker run --rm --network none --env-file /state/lab.env -v /state/data:/app/data -v /state/lab:/lab:ro nexus-antragsbank:fixture /usr/local/bin/python /lab/antragsbank-lab.py seed")
    labenv_hash = source.succeed("sha256sum /var/lib/nexus-lab/state/lab.env").split()[0]

    source.succeed("nixos-container run probe -- docker-compose --file ${compose} --project-name nexus-lab up --detach")
    wait_app(source)
    acknowledged = json.loads(lab_exec(source, "http-create"))["created"]
    receipts = json.loads(lab_exec(source, "http-verify"))
    assert receipts["created"] == acknowledged
    archive_receipt = receipts["archive"]
    lab_exec(source, "verify-state")

    with subtest("the service runs non-privileged under crun inside the mapped namespace"):
        container_checks(source)

    source_closure = source.succeed("nixos-container run probe -- readlink /run/current-system").strip()
    image_id = source.succeed("nixos-container run probe -- docker inspect --format '{{.Image}}' nexus-antragsbank").strip()

    with subtest("application state survives outer-container restart"):
        source.succeed("systemctl restart container@probe.service")
        source.wait_until_succeeds("nixos-container run probe -- docker inspect nexus-antragsbank", timeout=120)
        wait_app(source)
        receipts = json.loads(lab_exec(source, "http-verify"))
        assert receipts["created"] == acknowledged
        assert receipts["archive"] == archive_receipt
        lab_exec(source, "verify-state")
        container_checks(source)
        assert source.succeed("sha256sum /var/lib/nexus-lab/state/lab.env").split()[0] == labenv_hash
        source.fail("test -S /run/docker.sock")

    with subtest("the complete workload state transfers to a fresh simulated host"):
        source.succeed("systemctl stop container@probe.service")
        source.fail("systemctl is-active --quiet container@probe.service")
        source.succeed("${pkgs.gnutar}/bin/tar --numeric-owner --create --file /var/lib/nexus-lab-state.tar --directory /var/lib/nexus-lab state")
        source.copy_from_vm("/var/lib/nexus-lab-state.tar", "")
        target.copy_from_host(str(source.out_dir / "nexus-lab-state.tar"), "/var/lib/nexus-lab-state.tar")
        target.fail("systemctl is-active --quiet container@probe.service")
        target.fail("test -e /var/lib/nexus-lab/state/data/general.db")
        target.succeed("mkdir -p /var/lib/nexus-lab")
        target.succeed("${pkgs.gnutar}/bin/tar --numeric-owner --extract --file /var/lib/nexus-lab-state.tar --directory /var/lib/nexus-lab")
        assert target.succeed("sha256sum /var/lib/nexus-lab/state/lab.env").split()[0] == labenv_hash
        assert target.succeed("stat -c %a /var/lib/nexus-lab/state/lab.env").strip() == "600"
        target.succeed("systemctl start container@probe.service")
        target.wait_until_succeeds("nixos-container run probe -- systemctl is-active docker.service", timeout=90)
        target.succeed("nixos-container run probe -- docker load --input ${image}")
        target.succeed("nixos-container run probe -- docker-compose --file ${compose} --project-name nexus-lab up --detach")
        wait_app(target)
        assert target.succeed("nixos-container run probe -- readlink /run/current-system").strip() == source_closure
        assert target.succeed("nixos-container run probe -- docker inspect --format '{{.Image}}' nexus-antragsbank").strip() == image_id
        receipts = json.loads(lab_exec(target, "http-verify"))
        assert receipts["created"] == acknowledged
        assert receipts["archive"] == archive_receipt
        lab_exec(target, "verify-state")
        container_checks(target)
        source.fail("systemctl is-active --quiet container@probe.service")
        target.fail("test -S /run/docker.sock")
        target.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
  '';
}
