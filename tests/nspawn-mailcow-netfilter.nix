{ pkgs, ... }:
let
  netfilterImage = pkgs.dockerTools.pullImage {
    imageName = "ghcr.io/mailcow/netfilter";
    imageDigest = "sha256:a6c7f44c10c5edf01afa1bb155d1d42e2b04f81284a738a2d5643c834c33a143";
    hash = "sha256-Szars6Kfva2Atf5CXyONWLbOSj205pLKLlvKX8lJ50c=";
    finalImageName = "nexus-mailcow-netfilter";
    finalImageTag = "1.64";
    os = "linux";
    arch = "amd64";
  };
  redisImage = pkgs.dockerTools.pullImage {
    imageName = "docker.io/library/redis";
    imageDigest = "sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98";
    hash = "sha256-RHj4dFP1Z/7zc6DC+0ybUNBHgAeMVV8+9ZPJoW3BvDU=";
    finalImageName = "nexus-mailcow-redis";
    finalImageTag = "7.4.6-alpine";
    os = "linux";
    arch = "amd64";
  };
  compose = pkgs.writeText "mailcow-netfilter-probe.json" (builtins.toJSON {
    services = {
      redis = {
        image = "nexus-mailcow-redis:7.4.6-alpine";
        pull_policy = "never";
        container_name = "nexus-mailcow-redis";
        command = [ "redis-server" "--appendonly" "yes" ];
        restart = "unless-stopped";
        volumes = [ "redis-data:/data" ];
        networks.mailcow-network.ipv4_address = "172.22.1.249";
      };
      netfilter = {
        image = "nexus-mailcow-netfilter:1.64";
        pull_policy = "never";
        container_name = "nexus-mailcow-netfilter";
        command = [ "python" "-u" "/app/main.py" "nftables" ];
        restart = "unless-stopped";
        privileged = false;
        cap_add = [ "NET_ADMIN" "NET_RAW" ];
        network_mode = "host";
        dns = [ "172.22.1.254" ];
        environment = {
          TZ = "Etc/UTC";
          IPV4_NETWORK = "172.22.1";
          REDISPASS = "";
          MAILCOW_REPLICA_IP = "";
          DISABLE_NETFILTER_ISOLATION_RULE = "n";
        };
      };
    };
    volumes.redis-data = { };
    networks.mailcow-network = {
      driver = "bridge";
      driver_opts."com.docker.network.bridge.name" = "br-mailcow";
      ipam.config = [ { subnet = "172.22.1.0/24"; } ];
    };
  });
in {
  name = "nexus-nspawn-mailcow-netfilter";
  nodes.machine = { pkgs, ... }: {
    imports = [ (import ./nspawn-fixture.nix { docker = true; }) ];
    boot.kernelModules = [ "nf_tables" "nft_compat" ];
    environment.systemPackages = [ pkgs.nftables ];
    containers.probe.config.environment.systemPackages = [ pkgs.nftables ];
  };
  testScript = ''
    import json
    import shlex

    def normalized(value):
        if isinstance(value, dict):
            return {key: normalized(item) for key, item in value.items() if key not in ("handle", "packets", "bytes")}
        if isinstance(value, list):
            return [normalized(item) for item in value]
        return value

    def table_records(family):
        raw = machine.succeed("nixos-container run probe -- docker exec nexus-mailcow-netfilter nft --json list table " + family + " filter")
        return json.loads(raw)["nftables"]

    def assert_firewall():
        for family in ("ip", "ip6"):
            records = table_records(family)
            chains = [record["chain"] for record in records if "chain" in record]
            rules = [record["rule"] for record in records if "rule" in record]
            assert any(chain["name"] == "MAILCOW" for chain in chains), records
            for hook in ("input", "forward"):
                hooked = {chain["name"] for chain in chains if chain.get("hook") == hook}
                assert hooked, (family, hook, chains)
                assert any(rule["chain"] in hooked and any(expr.get("jump", {}).get("target") == "MAILCOW" for expr in rule["expr"]) for rule in rules), (family, hook, rules)
            if family != "ip":
                continue
            mail_rules = [rule for rule in rules if rule["chain"] == "MAILCOW"]
            def has_match(rule, left, op, right):
                return any(expr.get("match") == {"left": left, "op": op, "right": right} for expr in rule["expr"])
            def drops(rule):
                return any("drop" in expr for expr in rule["expr"])
            source = {"payload": {"protocol": "ip", "field": "saddr"}}
            addresses = ("192.0.2.20", "192.0.2.20/32", {"prefix": {"addr": "192.0.2.20", "len": 32}})
            assert any(drops(rule) and any(has_match(rule, source, "==", address) for address in addresses) for rule in mail_rules), mail_rules
            assert any(drops(rule)
                and has_match(rule, {"meta": {"key": "iifname"}}, "!=", "br-mailcow")
                and has_match(rule, {"meta": {"key": "oifname"}}, "==", "br-mailcow")
                and has_match(rule, {"payload": {"protocol": "tcp", "field": "dport"}}, "==", {"set": [3306, 6379, 8983, 12345]})
                for rule in mail_rules), mail_rules

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl start nix-daemon.socket")
    machine.succeed("test -S /nix/var/nix/daemon-socket/socket")
    machine.fail("test -S /run/docker.sock")
    baseline = normalized(json.loads(machine.succeed("nft --json list ruleset")))
    machine.succeed("systemctl start container@probe.service")
    machine.wait_until_succeeds("nixos-container run probe -- systemctl is-active docker.service", timeout=90)
    for archive in ("${netfilterImage}", "${redisImage}"):
        machine.succeed("nixos-container run probe -- docker load --input " + shlex.quote(archive))
    compose_command = "nixos-container run probe -- docker-compose --file ${compose} --project-name nexus-mailcow-probe"
    machine.succeed(compose_command + " up --detach redis")
    machine.wait_until_succeeds("nixos-container run probe -- docker exec nexus-mailcow-redis redis-cli ping", timeout=60)
    machine.succeed("nixos-container run probe -- docker exec nexus-mailcow-redis redis-cli HSET F2B_BLACKLIST 192.0.2.20/32 lab-fixture")
    machine.succeed(compose_command + " up --detach netfilter")
    ready_program = (
        "import json, subprocess, redis; "
        "assert redis.Redis(host='172.22.1.249').hexists('F2B_PERM_BANS', '192.0.2.20/32'); "
        "records = json.loads(subprocess.check_output(['nft', '--json', 'list', 'chain', 'ip', 'filter', 'MAILCOW']))['nftables']; "
        "addresses = ('192.0.2.20', '192.0.2.20/32', {'prefix': {'addr': '192.0.2.20', 'len': 32}}); "
        "assert any(any('drop' in term for term in item.get('rule', {}).get('expr', [])) "
        "and any(term.get('match') == {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': address} "
        "for term in item.get('rule', {}).get('expr', []) for address in addresses) for item in records)"
    )
    ready_command = "nixos-container run probe -- docker exec nexus-mailcow-netfilter python -c " + shlex.quote(ready_program)
    machine.wait_until_succeeds(ready_command, timeout=120)

    with subtest("Mailcow nftables firewall operates with narrow capabilities"):
        privileged = machine.succeed("nixos-container run probe -- docker inspect --format '{{.HostConfig.Privileged}}' nexus-mailcow-netfilter").strip()
        assert privileged == "false", privileged
        caps = json.loads(machine.succeed("nixos-container run probe -- docker inspect --format '{{json .HostConfig.CapAdd}}' nexus-mailcow-netfilter"))
        assert {cap.removeprefix("CAP_") for cap in caps} == {"NET_ADMIN", "NET_RAW"}, caps
        assert_firewall()
        program = "from pathlib import Path; assert Path('/proc/self/uid_map').read_text().split() == ['0','65536','65536']; rows=Path('/proc/self/mountinfo').read_text().splitlines(); assert any(row.split()[4]=='/sys' and 'ro' in row.split()[5].split(',') for row in rows)"
        machine.succeed("nixos-container run probe -- docker exec nexus-mailcow-netfilter python -c " + shlex.quote(program))
        machine.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
        machine.fail("nft list chain ip filter MAILCOW")
        after = normalized(json.loads(machine.succeed("nft --json list ruleset")))
        assert baseline == after, (baseline, after)

    with subtest("firewall and backing Redis state recover after outer restart"):
        machine.succeed("systemctl restart container@probe.service")
        machine.wait_until_succeeds(ready_command, timeout=120)
        assert_firewall()
        assert machine.succeed("nixos-container run probe -- docker exec nexus-mailcow-redis redis-cli HGET F2B_BLACKLIST 192.0.2.20/32").strip() == "lab-fixture"
        machine.fail("test -S /run/docker.sock")
        machine.fail("nft list chain ip filter MAILCOW")
        after = normalized(json.loads(machine.succeed("nft --json list ruleset")))
        assert baseline == after, (baseline, after)
  '';
}
