{ nixpkgs }:
let
  canary = import ./workload-canary.nix { inherit nixpkgs; };
  hostNode = args: import ./workload-worker-host.nix ({ inherit canary; } // args);
in { pkgs, ... }: {
  name = "nexus-workload-worker";
  globalTimeout = 15 * 60;
  nodes = {
    source = hostNode {
      hostId = "host-a";
      uuid = "11111111-2222-3333-4444-555555555555";
      slots = [
        { id = "first"; uidBase = 65536; hostAddress = "192.168.130.1"; localAddress = "192.168.130.2"; }
        { id = "second"; uidBase = 131072; hostAddress = "192.168.131.1"; localAddress = "192.168.131.2"; }
      ];
    };
    target = hostNode {
      hostId = "host-b";
      uuid = "66666666-7777-4888-8999-aaaaaaaaaaaa";
      slots = [
        { id = "first"; uidBase = 262144; hostAddress = "192.168.140.1"; localAddress = "192.168.140.2"; }
        { id = "second"; uidBase = 327680; hostAddress = "192.168.141.1"; localAddress = "192.168.141.2"; }
      ];
    };
  };
  testScript = ''
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
    worker_module = _load_console_module("worker")

    INSTANCE_A = "0a" * 16
    INSTANCE_B = "1b" * 16
    INSTANCE_C = "2c" * 16

    def worker(node, request):
        rc, output = node.execute("printf %s " + shlex.quote(json.dumps(request))
                                  + " | nexus-worker execute")
        return rc, json.loads(output)

    def request(op, action, instance, generation):
        return {
            "schemaVersion": 1,
            "operationId": op,
            "action": action,
            "workloadId": "canary",
            "revisionDigest": revision,
            "instanceId": instance,
            "generation": generation,
        }

    start_all()
    revision = json.loads(Path("${canary.bundle}/definition.json").read_text())["revisionDigest"]
    assert "${canary.system.pkgs.stdenv.hostPlatform.system}" == "x86_64-linux"

    for node in (source, target):
        node.wait_for_unit("multi-user.target")
        node.succeed("test -f /run/current-system/init")
        node.succeed("systemctl start nix-daemon.socket")
        node.succeed("test -S /nix/var/nix/daemon-socket/socket")
    host_closure = source.succeed("readlink /run/current-system").strip()

    with subtest("prepare fails before dedicated storage is mounted"):
        rc, result = worker(source, request("aa" * 16, "prepare", INSTANCE_A, 1))
        assert rc != 0 and result["status"] == "failed", result
        assert result["error"].startswith("storage-"), result
        source.fail("find /srv/workloads -mindepth 1 -print -quit | grep -q .")

    with subtest("mount verified dedicated disk then prepare and start"):
        source.succeed("mkfs.ext4 -q -U 11111111-2222-3333-4444-555555555555 /dev/vdc")
        source.wait_until_succeeds("test -b /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555", timeout=30)
        source.succeed("mkdir -p /srv/workloads")
        source.succeed("mount /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555 /srv/workloads")
        rc, result = worker(source, request("ab" * 16, "prepare", INSTANCE_A, 1))
        assert result["status"] == "completed" and result["appliedPhase"] == "prepared", result
        rc, result = worker(source, request("ac" * 16, "start", INSTANCE_A, 1))
        assert result["status"] == "completed" and result["appliedPhase"] == "running", result
        source.wait_until_succeeds("curl --fail --silent http://192.168.130.2:8080/", timeout=120)
        source.succeed("curl --fail --silent -X PUT --data-binary nexus-worker-canary http://192.168.130.2:8080/")
        rc, observed = worker(source, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE_A})
        assert observed["machineName"].startswith("n") and observed["slotId"] == "first"
        assert observed["unitActiveState"] == "active"
        assert observed["endpointAddress"] == "192.168.130.2"
        unit = "nexus-workload@" + observed["machineName"] + ".service"
        pid = source.succeed("systemctl show " + unit + " --property=MainPID --value").strip()
        guest = json.loads(source.succeed("curl --fail --silent http://192.168.130.2:8080/"))
        assert guest["hostname"] == "canary" and guest["value"] == "nexus-worker-canary"
        assert guest["uid_map"] == ["0", "65536", "65536"], guest["uid_map"]
        assert guest["host_socket"] is False
        assert guest["netns"] != source.succeed("readlink /proc/1/ns/net").strip()
        leader = source.succeed("machinectl show " + observed["machineName"] + " --property=Leader --value").strip()
        assert source.succeed("readlink /proc/" + leader + "/root/run/current-system").strip() \
            == "${canary.system.config.system.build.toplevel}"

    with subtest("operation replay returns receipt without restarting"):
        rc, replay = worker(source, request("ac" * 16, "start", INSTANCE_A, 1))
        assert replay["status"] == "completed" and replay["appliedPhase"] == "running"
        assert source.succeed("systemctl show " + unit + " --property=MainPID --value").strip() == pid

    with subtest("unknown workloads and malformed requests rejected"):
        bad = dict(request("ad" * 16, "start", INSTANCE_A, 1))
        bad["workloadId"] = "unknown"
        rc, bad_result = worker(source, bad)
        assert rc != 0 and bad_result["status"] == "failed", bad_result
        assert bad_result["error"] == "instance-conflict", bad_result
        bad = dict(request("ae" * 16, "start", INSTANCE_A, 1))
        bad["revisionDigest"] = "sha256:" + "0" * 64
        rc, bad_result = worker(source, bad)
        assert rc != 0 and bad_result["status"] == "failed", bad_result
        assert bad_result["error"] == "instance-conflict", bad_result
        bad = dict(request("a1" * 16, "prepare", "4e" * 16, 1))
        bad["workloadId"] = "unknown"
        rc, bad_result = worker(source, bad)
        assert rc != 0 and bad_result["status"] == "failed", bad_result
        assert bad_result["error"] == "unknown-workload", bad_result
        bad["operationId"] = "a2" * 16
        bad["workloadId"] = "canary"
        bad["revisionDigest"] = "sha256:" + "0" * 64
        rc, bad_result = worker(source, bad)
        assert rc != 0 and bad_result["status"] == "failed", bad_result
        assert bad_result["error"] == "unknown-workload", bad_result
        bad = dict(request("af" * 16, "start", INSTANCE_A, 1))
        bad["unitName"] = "evil.service"
        rc, bad_result = worker(source, bad)
        assert rc != 0 and bad_result["status"] == "error", bad_result
        bad = dict(request("b9" * 16, "start", INSTANCE_A, 1))
        bad["generation"] = 2
        rc, bad_result = worker(source, bad)
        assert rc != 0 and bad_result["status"] == "failed", bad_result
        assert bad_result["error"] == "instance-conflict", bad_result
        assert source.succeed("readlink /run/current-system").strip() == host_closure

    with subtest("direct systemctl start without permit fails"):
        source.succeed("systemctl stop " + unit)
        source.execute("systemctl start " + unit)
        assert source.succeed(
            "systemctl show " + unit + " --property=ActiveState --value").strip() != "active"
        assert source.succeed(
            "systemctl show " + unit + " --property=MainPID --value").strip() == "0"

    with subtest("worker stop and mount guard"):
        rc, result = worker(source, request("ba" * 16, "stop", INSTANCE_A, 1))
        assert result["status"] == "completed" and result["appliedPhase"] == "stopped", result
        assert source.succeed("systemctl show " + unit + " --property=ActiveState --value").strip() == "inactive"
        source.succeed("umount /srv/workloads")
        rc, result = worker(source, request("bb" * 16, "start", INSTANCE_A, 1))
        assert result["status"] == "failed" and result["error"].startswith("storage-"), result
        source.fail("test -e /srv/workloads/" + INSTANCE_A + "/data/value")
        source.wait_until_succeeds("test -b /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555", timeout=30)
        source.succeed("mount /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555 /srv/workloads")
        rc, result = worker(source, request("bc" * 16, "start", INSTANCE_A, 1))
        assert result["status"] == "completed", result
        source.wait_until_succeeds("curl --fail --silent http://192.168.130.2:8080/", timeout=120)
        guest = json.loads(source.succeed("curl --fail --silent http://192.168.130.2:8080/"))
        assert guest["value"] == "nexus-worker-canary", guest

    with subtest("stale generation cannot start after newer prepare"):
        rc, result = worker(source, request("bd" * 16, "stop", INSTANCE_A, 1))
        assert result["status"] == "completed"
        rc, result = worker(source, request("be" * 16, "prepare", INSTANCE_C, 2))
        assert result["status"] == "completed", result
        rc, result = worker(source, request("bf" * 16, "start", INSTANCE_A, 1))
        assert result["status"] == "failed", result
        assert result["error"] == "generation-stale", result

    with subtest("host power loss: no autoactivation, explicit start rebuilds runtime files"):
        machine_c = worker_module._machine_name(INSTANCE_C)
        unit_c = "nexus-workload@" + machine_c + ".service"
        boot_before = source.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        source.crash()
        source.start()
        source.wait_for_unit("multi-user.target")
        assert source.succeed("cat /proc/sys/kernel/random/boot_id").strip() != boot_before
        source.succeed("systemctl start nix-daemon.socket")
        assert source.succeed("readlink /run/current-system").strip() == host_closure
        assert source.succeed("systemctl show " + unit_c + " --property=ActiveState --value").strip() != "active"
        source.execute("systemctl start " + unit_c)
        assert source.succeed("systemctl show " + unit_c + " --property=ActiveState --value").strip() != "active"
        assert source.succeed("systemctl show " + unit_c + " --property=MainPID --value").strip() == "0"
        source.succeed("mkdir -p /srv/workloads")
        source.succeed("mount /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555 /srv/workloads")
        rc, result = worker(source, request("c0" * 16, "start", INSTANCE_C, 2))
        assert result["status"] == "completed" and result["appliedPhase"] == "running", result
        source.wait_until_succeeds("curl --fail --silent http://192.168.131.2:8080/", timeout=120)
        guest = json.loads(source.succeed("curl --fail --silent http://192.168.131.2:8080/"))
        assert guest["hostname"] == "canary", guest
        assert guest["uid_map"] == ["0", "131072", "65536"], guest["uid_map"]
        rc, result = worker(source, request("c1" * 16, "stop", INSTANCE_C, 2))
        assert result["status"] == "completed" and result["appliedPhase"] == "stopped", result

    with subtest("second host binds same closure with different slot"):
        target.succeed("mkfs.ext4 -q -U 66666666-7777-4888-8999-aaaaaaaaaaaa /dev/vdc")
        target.wait_until_succeeds("test -b /dev/disk/by-uuid/66666666-7777-4888-8999-aaaaaaaaaaaa", timeout=30)
        target.succeed("mkdir -p /srv/workloads")
        target.succeed("mount /dev/disk/by-uuid/66666666-7777-4888-8999-aaaaaaaaaaaa /srv/workloads")
        rc, result = worker(target, request("ca" * 16, "prepare", INSTANCE_B, 3))
        assert result["status"] == "completed", result
        rc, result = worker(target, request("cb" * 16, "start", INSTANCE_B, 3))
        assert result["status"] == "completed", result
        target.wait_until_succeeds("curl --fail --silent http://192.168.140.2:8080/", timeout=120)
        target.succeed("curl --fail --silent -X PUT --data-binary nexus-worker-canary http://192.168.140.2:8080/")
        guest = json.loads(target.succeed("curl --fail --silent http://192.168.140.2:8080/"))
        assert guest["hostname"] == "canary" and guest["value"] == "nexus-worker-canary"
        assert guest["uid_map"] == ["0", "262144", "65536"], guest["uid_map"]
        rc, observed = worker(target, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE_B})
        leader = target.succeed("machinectl show " + observed["machineName"] + " --property=Leader --value").strip()
        assert target.succeed("readlink /proc/" + leader + "/root/run/current-system").strip() \
            == "${canary.system.config.system.build.toplevel}"

    with subtest("nix base32 conversion matches pinned nix"):
        hex_digest = "ab" * 32
        converted = target.succeed(
            "nix --extra-experimental-features nix-command hash convert --hash-algo sha256 "
            "--to nix32 sha256:" + hex_digest).strip()
        converted = converted.removeprefix("sha256:")
        assert worker_module.nar_hash_bytes("sha256:" + converted).hex() == hex_digest, converted

    with subtest("retired instance can never start again, even after power loss"):
        machine_b = worker_module._machine_name(INSTANCE_B)
        unit_b = "nexus-workload@" + machine_b + ".service"
        rc, result = worker(target, request("d0" * 16, "retire", INSTANCE_B, 3))
        assert result["status"] == "completed" and result["appliedPhase"] == "stopped", result
        rc, observed = worker(target, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE_B})
        assert observed["retired"] is True and observed["unitDrained"] is True, observed
        rc, result = worker(target, request("d1" * 16, "start", INSTANCE_B, 3))
        assert result["status"] == "failed" and result["error"] == "instance-retired", result
        target.execute("systemctl start " + unit_b)
        assert target.succeed(
            "systemctl show " + unit_b + " --property=ActiveState --value").strip() != "active"
        assert target.succeed(
            "systemctl show " + unit_b + " --property=MainPID --value").strip() == "0"
        boot_before = target.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        target.crash()
        target.start()
        target.wait_for_unit("multi-user.target")
        assert target.succeed("cat /proc/sys/kernel/random/boot_id").strip() != boot_before
        target.succeed("systemctl start nix-daemon.socket")
        target.wait_until_succeeds(
            "test -b /dev/disk/by-uuid/66666666-7777-4888-8999-aaaaaaaaaaaa", timeout=30)
        target.succeed("mkdir -p /srv/workloads")
        target.succeed("mount /dev/disk/by-uuid/66666666-7777-4888-8999-aaaaaaaaaaaa /srv/workloads")
        rc, result = worker(target, request("d2" * 16, "start", INSTANCE_B, 3))
        assert result["status"] == "failed" and result["error"] == "instance-retired", result
        rc, observed = worker(target, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE_B})
        assert observed["retired"] is True and observed["unitDrained"] is True, observed

    with subtest("durable capture barrier survives power loss until matching thaw"):
        capture = "5e" * 16
        unit_c = "nexus-workload@" + worker_module._machine_name(INSTANCE_C) + ".service"
        rc, result = worker(source, request("d3" * 16, "start", INSTANCE_C, 2))
        assert result["status"] == "completed" and result["appliedPhase"] == "running", result
        source.wait_until_succeeds("curl --fail --silent http://192.168.131.2:8080/", timeout=120)
        source.succeed("curl --fail --silent -X PUT --data-binary capture-marker http://192.168.131.2:8080/")
        freeze = dict(request("d4" * 16, "freeze", INSTANCE_C, 2))
        freeze["captureId"] = capture
        rc, result = worker(source, freeze)
        assert result["status"] == "completed" and result["appliedPhase"] == "stopped", result
        assert result["captureId"] == capture, result
        rc, observed = worker(source, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE_C})
        assert observed["captureId"] == capture, observed
        assert observed["phase"] == "stopped" and observed["unitDrained"] is True, observed
        rc, result = worker(source, request("d5" * 16, "start", INSTANCE_C, 2))
        assert result["status"] == "failed" and result["error"] == "capture-held", result
        rc, result = worker(source, request("d6" * 16, "prepare", "3d" * 16, 3))
        assert result["status"] == "failed" and result["error"] == "capture-held", result
        source.fail("test -e /srv/workloads/" + "3d" * 16)
        source.execute("systemctl start " + unit_c)
        assert source.succeed("systemctl show " + unit_c + " --property=MainPID --value").strip() == "0"
        # Flush the marker to the dedicated disk before the hard crash;
        # a clean container stop does not fsync the backing filesystem.
        source.succeed("sync")
        boot_before = source.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        source.crash()
        source.start()
        source.wait_for_unit("multi-user.target")
        assert source.succeed("cat /proc/sys/kernel/random/boot_id").strip() != boot_before
        source.succeed("systemctl start nix-daemon.socket")
        assert source.succeed("systemctl show " + unit_c + " --property=ActiveState --value").strip() != "active"
        source.execute("systemctl start " + unit_c)
        assert source.succeed("systemctl show " + unit_c + " --property=MainPID --value").strip() == "0"
        source.wait_until_succeeds(
            "test -b /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555", timeout=30)
        source.succeed("mkdir -p /srv/workloads")
        source.succeed("mount /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555 /srv/workloads")
        rc, observed = worker(source, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE_C})
        assert observed["captureId"] == capture and observed["unitDrained"] is True, observed
        wrong = dict(request("d7" * 16, "thaw", INSTANCE_C, 2))
        wrong["captureId"] = "6f" * 16
        rc, result = worker(source, wrong)
        assert result["status"] == "failed" and result["error"] == "capture-missing", result
        thaw = dict(request("d8" * 16, "thaw", INSTANCE_C, 2))
        thaw["captureId"] = capture
        rc, result = worker(source, thaw)
        assert result["status"] == "completed" and result["appliedPhase"] == "stopped", result
        assert result["captureId"] == capture, result
        rc, observed = worker(source, {
            "schemaVersion": 1, "action": "observe", "instanceId": INSTANCE_C})
        assert observed["captureId"] is None and observed["phase"] == "stopped", observed
        rc, result = worker(source, request("d9" * 16, "start", INSTANCE_C, 2))
        assert result["status"] == "completed" and result["appliedPhase"] == "running", result
        source.wait_until_succeeds("curl --fail --silent http://192.168.131.2:8080/", timeout=120)
        guest = json.loads(source.succeed("curl --fail --silent http://192.168.131.2:8080/"))
        assert guest["value"] == "capture-marker", guest
  '';
}
