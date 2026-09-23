{ nixpkgs }:
let
  buildWorkload = import ../workload-modules/build.nix { inherit nixpkgs; };
  draft = {
    schemaVersion = 2;
    workloadId = "canary";
    displayName = "Canary";
    category = "project";
    runtimeVersion = "nspawn-v1";
    architecture = "x86_64-linux";
    runtimeArtifactId = "runtime";
    artifacts = [ ];
    stateSchemaVersion = 1;
    stateMounts = [
      { id = "data"; mountPoint = "/state"; ownerUid = 0; ownerGid = 0; consistencyAdapter = "quiesce-v1"; }
    ];
    secretSetRef = null;
    dependencies = [ ];
    services = [
      { id = "web"; protocol = "http"; port = 8080; exposure = "private"; }
    ];
    requirements = {
      memoryMiB = 64;
      cpuMillis = 100;
      stateBytes = 1024;
      capabilities = [ "userns" "nspawn-v1" ];
    };
    allowedOperations = [ "start" "stop" "restart" "backup" "restore" "move" ];
    policyProfiles = [ "normal" ];
  };
  canary = buildWorkload {
    definition = draft;
    modules = [
      ({ pkgs, ... }: {
        networking.firewall.allowedTCPPorts = [ 8080 ];
        systemd.services.canary = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind 0.0.0.0 --directory /state";
            Restart = "on-failure";
          };
        };
      })
    ];
  };
  dockerEval = (nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [ ../workload-modules/docker.nix ];
  }).config;
  violations = [
    ({ lib, ... }: { nix.enable = lib.mkForce true; })
    ({ lib, ... }: { networking.useDHCP = lib.mkForce true; })
    ({ lib, ... }: { networking.useHostResolvConf = lib.mkForce true; })
    ({ lib, ... }: { boot.isNspawnContainer = lib.mkForce false; })
    ({ lib, ... }: { networking.hostName = lib.mkForce "other"; })
  ];
  violationsRejected = builtins.all
    (module: !(builtins.tryEval (builtins.seq
      (buildWorkload { definition = draft; modules = [ module ]; }).system null)).success)
    violations;
  hostNode = { privateUsers, hostAddress, localAddress, statePath, stateOwner }: { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 1;
    virtualisation.useNixStoreImage = true;
    environment.systemPackages = [ pkgs.curl ];
    systemd.tmpfiles.rules = [
      "d /nix/var/nix/db 0755 root root -"
      "d /nix/var/nix/daemon-socket 0755 root root -"
      "d ${statePath} 0700 ${stateOwner} ${stateOwner} -"
    ];
    containers.probe = {
      autoStart = false;
      ephemeral = true;
      privateNetwork = true;
      inherit privateUsers hostAddress localAddress;
      path = canary.system.config.system.build.toplevel;
      extraFlags = [
        "--private-users-ownership=auto"
        "--inaccessible=/nix/var/nix/daemon-socket"
      ];
      bindMounts."/state" = { hostPath = statePath; isReadOnly = false; };
    };
  };
in { pkgs, ... }: {
  name = "nexus-workload-artifact";
  nodes = {
    source = hostNode {
      privateUsers = 65536;
      hostAddress = "192.168.110.1";
      localAddress = "192.168.110.2";
      statePath = "/srv/host-a/data";
      stateOwner = "65536";
    };
    target = hostNode {
      privateUsers = 131072;
      hostAddress = "192.168.120.1";
      localAddress = "192.168.120.2";
      statePath = "/srv/host-b/data";
      stateOwner = "131072";
    };
  };
  testScript = ''
    import hashlib
    import importlib.util
    import json
    import shlex
    import sys
    from pathlib import Path

    def _load_console_module(name):
        spec = importlib.util.spec_from_file_location(name, "${../console}/" + name + ".py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    catalog = _load_console_module("catalog")
    artifacts = _load_console_module("artifacts")

    assert ${if violationsRejected then "True" else builtins.throw "buildWorkload accepted a profile invariant violation"}
    manifest = artifacts.validate_manifest(json.loads(Path("${canary.bundle}/artifact.json").read_bytes()))
    assert manifest["root"] == "${canary.system.config.system.build.toplevel}"
    assert manifest["architecture"] == "${canary.system.pkgs.stdenv.hostPlatform.system}"
    digest = Path("${canary.bundle}/artifact.sha256").read_text().strip()
    assert digest == artifacts.manifest_digest(manifest)
    assert digest == "sha256:" + hashlib.sha256(Path("${canary.bundle}/artifact.json").read_bytes()).hexdigest()
    definition = catalog.validate_definition(json.loads(Path("${canary.bundle}/definition.json").read_bytes()))
    artifact = [entry for entry in definition["artifacts"] if entry["id"] == "runtime"]
    assert len(artifact) == 1 and artifact[0]["kind"] == "nixos-closure" and artifact[0]["digest"] == digest
    definition_bytes = Path("${canary.bundle}/definition.json").read_bytes()
    for leak in (b"192.168.110", b"192.168.120", b"/srv/host", b"host-a", b"host-b"):
        assert leak not in definition_bytes, leak
    assert "${toString dockerEval.virtualisation.docker.daemon.settings."default-runtime"}" == "crun"
    assert "${toString dockerEval.systemd.services.docker.serviceConfig.LimitNPROC}" == "65535"
    assert "${if dockerEval.boot.isNspawnContainer then "true" else "false"}" == "true"

    def boot_checks(node):
        node.wait_for_unit("multi-user.target")
        node.succeed("systemctl start nix-daemon.socket")
        node.succeed("test -S /nix/var/nix/daemon-socket/socket")
        node.succeed("touch /nexus-host-sentinel")
        assert node.succeed("cat /proc/sys/net/ipv4/ip_forward").strip() == "0"

    def guest_checks(node, address, uid_map):
        assert node.succeed("readlink /proc/1/ns/net").strip() != node.succeed("nixos-container run probe -- readlink /proc/1/ns/net").strip()
        assert node.succeed("nixos-container run probe -- hostname").strip() == "canary"
        assert node.succeed("nixos-container run probe -- readlink /run/current-system").strip() == "${canary.system.config.system.build.toplevel}"
        assert node.succeed("nixos-container run probe -- cat /proc/self/uid_map").split() == uid_map
        node.fail("nixos-container run probe -- test -e /nexus-host-sentinel")
        node.fail("nixos-container run probe -- test -S /nix/var/nix/daemon-socket/socket")
        node.fail("nixos-container run probe -- touch /nix/store/write-test")
        assert node.succeed("nixos-container run probe -- stat -c %u /state").strip() == "0"
        inside = node.succeed("nixos-container run probe -- ip -4 -o addr show scope global").strip()
        assert address in inside, inside

    start_all()
    boot_checks(source)
    boot_checks(target)

    source.succeed("printf %s nexus-canary-source > /srv/host-a/data/index.html")
    source.succeed("chown 65536:65536 /srv/host-a/data/index.html")
    source.succeed("systemctl start container@probe.service")
    source.wait_until_succeeds("curl --fail --silent http://192.168.110.2:8080/index.html | grep -qx nexus-canary-source", timeout=120)
    guest_checks(source, "192.168.110.2", ["0", "65536", "65536"])

    source.succeed("nixos-container run probe -- sh -c " + shlex.quote("printf mutated > /state/index.html"))
    source.succeed("systemctl stop container@probe.service")
    source.fail("systemctl is-active --quiet container@probe.service")
    target.fail("test -e /srv/host-b/data/index.html")
    state = source.succeed("cat /srv/host-a/data/index.html")
    target.succeed("printf %s " + shlex.quote(state) + " > /srv/host-b/data/index.html")
    target.succeed("chown 131072:131072 /srv/host-b/data/index.html")
    target.succeed("systemctl start container@probe.service")
    target.wait_until_succeeds("curl --fail --silent http://192.168.120.2:8080/index.html | grep -qx mutated", timeout=120)
    guest_checks(target, "192.168.120.2", ["0", "131072", "65536"])
    source.fail("systemctl is-active --quiet container@probe.service")
  '';
}
