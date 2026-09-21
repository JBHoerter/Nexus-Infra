{ pkgs, lib, ... }:
let
  inputs = builtins.fromJSON (builtins.readFile ./mailcow-lab-inputs.json);
  source = pkgs.fetchFromGitHub inputs.source;
  images = lib.mapAttrs (_: spec: pkgs.dockerTools.pullImage spec) inputs.images;
  artifacts = pkgs.writeText "nexus-mailcow-artifacts.json" (builtins.toJSON {
    bootstrapVersion = 2;
    source = toString source;
    sourceRevision = inputs.source.rev;
    images = lib.mapAttrs (name: image: {
      archive = toString image;
      reference = "${inputs.images.${name}.finalImageName}:${inputs.images.${name}.finalImageTag}";
    }) images;
  });
  runner = ./mailcow-lab.py;
in {
  name = "nexus-mailcow-integration";
  globalTimeout = 3600;
  nodes.machine = { lib, pkgs, ... }: {
    imports = [ (import ./nspawn-fixture.nix { docker = true; }) ];
    virtualisation.memorySize = lib.mkForce 8192;
    virtualisation.cores = lib.mkForce 2;
    virtualisation.diskSize = 32768;
    networking.useDHCP = false;
    networking.interfaces.eth0.ipv4.addresses = [{ address = "10.0.2.15"; prefixLength = 24; }];
    networking.defaultGateway = "10.0.2.2";
    networking.nameservers = [ "10.0.2.3" ];
    networking.nat = {
      enable = true;
      externalInterface = "eth0";
      internalIPs = [ "192.168.100.2/32" ];
    };
    networking.nftables.enable = true;
    networking.nftables.tables.nexus_lab_egress = {
      family = "inet";
      content = ''
        set private_ipv4 {
          type ipv4_addr; flags interval;
          elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
        }
        counter smtp_block { }
        counter lan_block { }
        chain public_egress {
          tcp dport { 25, 465, 587 } counter name smtp_block reject
          ip daddr 10.0.2.3 udp dport 53 accept
          ip daddr 10.0.2.3 tcp dport 53 accept
          ip daddr @private_ipv4 counter name lan_block reject
          meta nfproto ipv6 reject
          udp dport 53 accept
          tcp dport { 53, 80, 443 } accept
          ip protocol icmp accept
          counter reject
        }
        chain output {
          type filter hook output priority -10; policy drop;
          oifname "lo" accept
          ct state established,related accept
          oifname "ve-probe" ip daddr 192.168.100.2 accept
          jump public_egress
        }
        chain forward {
          type filter hook forward priority -10; policy drop;
          ct state established,related accept
          iifname "ve-probe" oifname "eth0" jump public_egress
        }
      '';
    };
    environment.systemPackages = [ pkgs.nftables pkgs.python3 ];
    environment.etc."nexus-mailcow-lab/artifacts.json".source = artifacts;
    environment.etc."nexus-mailcow-lab/runner.py".source = runner;
    systemd.tmpfiles.rules = [ "d /var/lib/nexus-lab/mailcow 0700 65536 65536 -" ];
    systemd.services."container@probe".serviceConfig = {
      LimitNPROC = 65535;
      TasksMax = 8192;
    };
    containers.probe.bindMounts."/work" = { hostPath = "/var/lib/nexus-lab/mailcow"; isReadOnly = false; };
    containers.probe.extraFlags = [ "--rlimit=RLIMIT_NPROC=65535:65535" ];
    containers.probe.config = {
      networking.nameservers = [ "10.0.2.3" ];
      networking.extraHosts = "127.0.0.1 mail.nexus.test";
      environment.systemPackages = [ pkgs.python3 pkgs.openssl pkgs.nftables ];
      environment.etc."nexus-mailcow-lab-enabled".text = "synthetic-only\n";
      systemd.services.docker.serviceConfig.LimitNPROC = 65535;
    };
  };
  testScript = ''
    import json
    import shlex

    def counter(name):
        data = json.loads(machine.succeed("nft --json list counter inet nexus_lab_egress " + name))
        return next(item["counter"]["packets"] for item in data["nftables"] if "counter" in item)

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("nftables.service")
    machine.succeed("nft list table inet nexus_lab_egress")
    machine.succeed("systemctl start nix-daemon.socket")
    machine.succeed("test -S /nix/var/nix/daemon-socket/socket")
    machine.fail("test -S /run/docker.sock")
    machine.succeed("systemctl start container@probe.service")
    machine.wait_until_succeeds("nixos-container run probe -- systemctl is-active docker.service", timeout=90)
    machine.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
    with subtest("outer VM egress guard blocks mail delivery and LAN access"):
        for host, port, name in (("192.0.2.1", 25, "smtp_block"), ("192.168.250.250", 80, "lan_block")):
            before = counter(name)
            program = "import socket; socket.create_connection((" + repr(host) + ", " + str(port) + "), timeout=3)"
            machine.fail("nixos-container run probe -- ${pkgs.python3}/bin/python3 -c " + shlex.quote(program))
            assert counter(name) > before, name
    machine.succeed("nixos-container run probe -- ping -c 1 -W 5 1.1.1.1")
    machine.succeed("nixos-container run probe -- curl --fail --silent --max-time 30 --output /dev/null https://www.internic.net/domain/named.cache")
    command = "nixos-container run probe -- ${pkgs.python3}/bin/python3 ${runner} "
    machine.succeed(command + "bootstrap ${artifacts}", timeout=1200)
    machine.succeed(command + "start ${artifacts}", timeout=600)
    machine.succeed(command + "ready ${artifacts}", timeout=1900)
    machine.succeed(command + "exercise ${artifacts}", timeout=300)
    machine.succeed(command + "verify ${artifacts}", timeout=240)
    with subtest("whole stack state and certificates survive outer restart"):
        machine.succeed("systemctl restart container@probe.service")
        machine.wait_until_succeeds("nixos-container run probe -- systemctl is-active docker.service", timeout=90)
        machine.succeed(command + "ready ${artifacts}", timeout=600)
        machine.succeed(command + "verify ${artifacts}", timeout=240)
        machine.fail("test -S /run/docker.sock")
        machine.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
        machine.succeed("nft list table inet nexus_lab_egress")
  '';
}
