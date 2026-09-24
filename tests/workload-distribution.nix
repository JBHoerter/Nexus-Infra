{ nixpkgs }:
let
  canary = import ./workload-canary.nix { inherit nixpkgs; };
  bundleString = builtins.unsafeDiscardStringContext (toString canary.bundle);
in { pkgs, ... }: {
  name = "nexus-workload-distribution";
  globalTimeout = 20 * 60;
  includeTestScriptReferences = false;
  nodes = {
    publisher = { pkgs, ... }: {
      virtualisation.memorySize = 2048;
      virtualisation.cores = 1;
      virtualisation.useNixStoreImage = true;
      virtualisation.writableStore = true;
      virtualisation.diskSize = 8192;
      environment.etc."canary-bundle".source = canary.bundle;
    };
    consumer = { pkgs, ... }: {
      imports = [
        ../host-modules/workload-host.nix
        ../host-modules/workload-artifacts.nix
      ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 1;
      virtualisation.useBootLoader = true;
      virtualisation.diskSize = 8192;
      virtualisation.emptyDiskImages = [ 128 ];
      boot.growPartition = true;
      virtualisation.fileSystems."/".autoResize = true;
      environment.etc."nexus-library".source = ../console;
      environment.systemPackages = [ pkgs.python3 pkgs.curl pkgs.jq pkgs.e2fsprogs ];
      services.nexus-workload-worker = {
        enable = true;
        hostId = "consumer";
        approvedBundlePaths = [ bundleString ];
        storage = {
          root = "/srv/workloads";
          mountPoint = "/srv/workloads";
          uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        };
        capacity = { memoryMiB = 768; cpuMillis = 1000; stateBytes = 33554432; };
        slots = [
          { id = "first"; uidBase = 65536; hostAddress = "192.168.150.1"; localAddress = "192.168.150.2"; }
        ];
      };
      services.nexus-workload-artifacts = {
        enable = true;
        trustedPublicKeys = [ "fixture:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];
        sources = [ { id = "fixture"; uri = "file:///srv/fixture"; } ];
        bundles = [
          { workloadId = "canary";
            revisionDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            bundlePath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture";
            sourceId = "fixture"; }
        ];
      };
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

    BUNDLE = "${canary.bundle}"
    MANIFEST_ROOT = "${canary.system.config.system.build.toplevel}"
    INSTANCE = "0a" * 16
    REF_UNSIGNED = "aa" * 16
    REF_WRONG = "bb" * 16
    REF_SIGNED = "cc" * 16
    STORAGE_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    NIX = "nix --extra-experimental-features nix-command"

    expected_definition = Path(BUNDLE + "/definition.json").read_bytes()
    expected_manifest = Path(BUNDLE + "/artifact.json").read_bytes()
    expected_digest = Path(BUNDLE + "/artifact.sha256").read_text().strip()
    revision = json.loads(expected_definition)["revisionDigest"]
    manifest_root = json.loads(expected_manifest)["root"]

    assert artifacts.canonical_bytes(json.loads(expected_definition)) == expected_definition
    assert artifacts.canonical_bytes(json.loads(expected_manifest)) == expected_manifest
    assert artifacts.manifest_digest(json.loads(expected_manifest)) == expected_digest
    assert manifest_root == MANIFEST_ROOT
    catalog.validate_definition(json.loads(expected_definition))
    artifacts.validate_manifest(json.loads(expected_manifest))

    def write_config(node, config):
        node.succeed("printf %s " + shlex.quote(json.dumps(config))
                     + " > /root/artifacts.json && chmod 600 /root/artifacts.json")

    def fetch(node, request):
        rc, output = node.execute(
            "printf %s " + shlex.quote(json.dumps(request))
            + " | python3 /etc/nexus-library/distribution.py --config /root/artifacts.json execute")
        return rc, json.loads(output)

    def worker(node, request):
        rc, output = node.execute("printf %s " + shlex.quote(json.dumps(request))
                                  + " | nexus-worker execute")
        return rc, json.loads(output)

    def worker_request(op, action, generation):
        return {
            "schemaVersion": 1,
            "operationId": op,
            "action": action,
            "workloadId": "canary",
            "revisionDigest": revision,
            "instanceId": INSTANCE,
            "generation": generation,
        }

    def fetch_request(ref):
        return {
            "schemaVersion": 1,
            "action": "fetch",
            "workloadId": "canary",
            "revisionDigest": revision,
            "referenceId": ref,
        }

    def artifact_config(source_uri, keys):
        return {
            "schemaVersion": 1,
            "stateDir": "/var/lib/nexus-artifacts",
            "trustedPublicKeys": keys,
            "sources": [{"id": "cache", "uri": source_uri}],
            "bundles": [{"workloadId": "canary", "revisionDigest": revision,
                         "bundlePath": BUNDLE, "sourceId": "cache"}],
        }

    def ref_record(node, ref):
        rc, output = node.execute(
            "cat /var/lib/nexus-artifacts/refs/" + ref + ".json")
        if rc != 0:
            return None
        return json.loads(output)

    def local_sha256(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    start_all()
    for node in (publisher, consumer):
        node.wait_for_unit("multi-user.target")
        node.succeed("systemctl start nix-daemon.socket")
        node.succeed("test -S /nix/var/nix/daemon-socket/socket")

    with subtest("publisher serves byte-identical canonical bundle files"):
        for name in ("definition.json", "artifact.json", "artifact.sha256"):
            digest = publisher.succeed("sha256sum " + BUNDLE + "/" + name).split()[0]
            assert digest == local_sha256(BUNDLE + "/" + name), name

    with subtest("bundle is genuinely absent from consumer before any fetch"):
        consumer.fail("test -e " + BUNDLE)
        consumer.fail(NIX + " --store daemon path-info " + BUNDLE)

    with subtest("publisher creates ephemeral keys and distinct signed/unsigned caches"):
        publisher.succeed("umask 077; " + NIX + " key generate-secret --key-name nexus-lab > /root/cache.sec")
        publisher.succeed(NIX + " key convert-secret-to-public < /root/cache.sec > /root/cache.pub")
        publisher.succeed("umask 077; " + NIX + " key generate-secret --key-name wrong-lab > /root/wrong.sec")
        publisher.succeed(NIX + " key convert-secret-to-public < /root/wrong.sec > /root/wrong.pub")
        publisher.succeed(NIX + " copy --to file:///srv/cache-unsigned " + BUNDLE)
        publisher.succeed(NIX + " --store daemon store sign --recursive --key-file /root/cache.sec " + BUNDLE)
        publisher.succeed(NIX + " copy --to file:///srv/cache-signed " + BUNDLE)

    with subtest("caches and public keys transfer to consumer without secrets"):
        publisher.succeed("tar --create --file /tmp/caches.tar --directory /srv cache-unsigned cache-signed")
        publisher.copy_from_vm("/tmp/caches.tar", "")
        consumer.copy_from_host(str(publisher.out_dir / "caches.tar"), "/tmp/caches.tar")
        consumer.succeed("tar --extract --file /tmp/caches.tar --directory /srv")
        public_key = publisher.succeed("cat /root/cache.pub").strip()
        wrong_key = publisher.succeed("cat /root/wrong.pub").strip()
        assert public_key.startswith("nexus-lab:") and wrong_key.startswith("wrong-lab:")
        consumer.fail("test -e /root/cache.sec")

    with subtest("unsigned cache cannot satisfy the signature requirement"):
        write_config(consumer, artifact_config("file:///srv/cache-unsigned", [public_key]))
        rc, result = fetch(consumer, fetch_request(REF_UNSIGNED))
        assert rc != 0 and result["status"] == "error", result
        record = ref_record(consumer, REF_UNSIGNED)
        assert record is not None and record["status"] == "pending", record
        assert "manifestDigest" not in record
        consumer.fail("test -e /var/lib/nexus-artifacts/roots/" + REF_UNSIGNED)

    with subtest("signatures from an untrusted key are rejected"):
        write_config(consumer, artifact_config("file:///srv/cache-signed", [wrong_key]))
        rc, result = fetch(consumer, fetch_request(REF_WRONG))
        assert rc != 0 and result["status"] == "error", result
        consumer.fail("test -e /var/lib/nexus-artifacts/roots/" + REF_WRONG)

    with subtest("correctly signed bundle verifies and is retained"):
        write_config(consumer, artifact_config("file:///srv/cache-signed", [public_key]))
        rc, result = fetch(consumer, fetch_request(REF_SIGNED))
        assert rc == 0 and result["status"] == "retained", result
        assert result["workloadId"] == "canary"
        assert result["revisionDigest"] == revision
        assert result["referenceId"] == REF_SIGNED
        assert result["bundlePath"] == BUNDLE
        assert result["manifestDigest"] == expected_digest, result
        assert consumer.succeed("readlink /var/lib/nexus-artifacts/roots/" + REF_SIGNED).strip() == BUNDLE
        record = ref_record(consumer, REF_SIGNED)
        assert record["status"] == "retained" and record["manifestDigest"] == expected_digest
        for name, expected in (("definition.json", expected_definition),
                               ("artifact.json", expected_manifest)):
            digest = consumer.succeed("sha256sum " + BUNDLE + "/" + name).split()[0]
            assert digest == hashlib.sha256(expected).hexdigest(), name
        consumer.succeed(NIX + " --store daemon path-info " + BUNDLE)
        consumer.succeed(NIX + " --store daemon path-info " + manifest_root)
        rc, result2 = fetch(consumer, fetch_request(REF_SIGNED))
        assert result2 == result

    publisher.crash()

    with subtest("retained closure runs the canary without publisher or caches"):
        consumer.succeed("mkdir -p /srv/cache-offline")
        consumer.succeed("mv /srv/cache-unsigned /srv/cache-signed /srv/cache-offline/")
        assert consumer.succeed(
            "systemctl list-units --all --type=service --plain --no-legend --no-pager 'nexus-workload@*.service'").strip() == ""
        consumer.succeed("mkfs.ext4 -q -U " + STORAGE_UUID + " /dev/vdb")
        consumer.wait_until_succeeds("test -b /dev/disk/by-uuid/" + STORAGE_UUID, timeout=30)
        consumer.succeed("mkdir -p /srv/workloads")
        consumer.succeed("mount /dev/disk/by-uuid/" + STORAGE_UUID + " /srv/workloads")
        rc, result = worker(consumer, worker_request("aa" * 16, "prepare", 1))
        assert result["status"] == "completed" and result["appliedPhase"] == "prepared", result
        rc, result = worker(consumer, worker_request("ab" * 16, "start", 1))
        assert result["status"] == "completed" and result["appliedPhase"] == "running", result
        consumer.wait_until_succeeds("curl --fail --silent http://192.168.150.2:8080/", timeout=120)
        guest = json.loads(consumer.succeed("curl --fail --silent http://192.168.150.2:8080/"))
        assert guest["hostname"] == "canary", guest
        assert guest["uid_map"] == ["0", "65536", "65536"], guest["uid_map"]
        rc, observed = worker(consumer, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE})
        assert observed["endpointAddress"] == "192.168.150.2"
        leader = consumer.succeed("machinectl show " + observed["machineName"] + " --property=Leader --value").strip()
        assert consumer.succeed("readlink /proc/" + leader + "/root/run/current-system").strip() == MANIFEST_ROOT
        rc, result = worker(consumer, worker_request("ac" * 16, "stop", 1))
        assert result["status"] == "completed" and result["appliedPhase"] == "stopped", result
        unit = "nexus-workload@" + observed["machineName"] + ".service"
        assert consumer.succeed("systemctl show " + unit + " --property=ActiveState --value").strip() == "inactive"

    with subtest("daemon gc keeps the retained bundle and runtime closure"):
        consumer.succeed("nix-store --store daemon --gc")
        consumer.succeed(NIX + " --store daemon path-info " + BUNDLE)
        consumer.succeed(NIX + " --store daemon path-info " + manifest_root)
        record = ref_record(consumer, REF_SIGNED)
        assert record["status"] == "retained" and record["manifestDigest"] == expected_digest
        assert consumer.succeed("readlink /var/lib/nexus-artifacts/roots/" + REF_SIGNED).strip() == BUNDLE

    with subtest("consumer power loss: retained closure still starts the same instance"):
        boot_before = consumer.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        consumer.crash()
        consumer.start()
        consumer.wait_for_unit("multi-user.target")
        assert consumer.succeed("cat /proc/sys/kernel/random/boot_id").strip() != boot_before
        consumer.succeed("systemctl start nix-daemon.socket")
        assert consumer.succeed("readlink /var/lib/nexus-artifacts/roots/" + REF_SIGNED).strip() == BUNDLE
        record = ref_record(consumer, REF_SIGNED)
        assert record["status"] == "retained" and record["manifestDigest"] == expected_digest
        consumer.succeed(NIX + " --store daemon path-info " + BUNDLE)
        consumer.succeed(NIX + " --store daemon path-info " + manifest_root)
        consumer.succeed("mkdir -p /srv/workloads")
        consumer.succeed("mount /dev/disk/by-uuid/" + STORAGE_UUID + " /srv/workloads")
        rc, result = worker(consumer, worker_request("ad" * 16, "start", 1))
        assert result["status"] == "completed" and result["appliedPhase"] == "running", result
        consumer.wait_until_succeeds("curl --fail --silent http://192.168.150.2:8080/", timeout=120)
        guest = json.loads(consumer.succeed("curl --fail --silent http://192.168.150.2:8080/"))
        assert guest["hostname"] == "canary", guest
        rc, observed = worker(consumer, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE})
        leader = consumer.succeed("machinectl show " + observed["machineName"] + " --property=Leader --value").strip()
        assert consumer.succeed("readlink /proc/" + leader + "/root/run/current-system").strip() == MANIFEST_ROOT
        rc, result = worker(consumer, worker_request("ae" * 16, "stop", 1))
        assert result["status"] == "completed" and result["appliedPhase"] == "stopped", result
  '';
}
