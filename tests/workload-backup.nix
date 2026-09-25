{ nixpkgs }:
let
  canary = import ./workload-canary.nix { inherit nixpkgs; };
  hostNode = args: import ./workload-worker-host.nix ({ inherit canary; } // args);
  repoLib = pkgs: pkgs.runCommand "nexus-repository-lib" { } ''
    mkdir $out
    for name in artifacts catalog recovery statefiles worker repository; do
      cp ${../console}/$name.py $out/$name.py
    done
    cp ${./repository-cli.py} $out/repository-cli.py
  '';
  clientNode = args: { pkgs, ... }: {
    imports = [ (hostNode args) ];
    virtualisation.restrictNetwork = true;
    networking.hosts."192.168.1.1" = [ "repository" ];
    environment.systemPackages = [
      pkgs.python3 pkgs.restic pkgs.openssh
    ];
  };
in { pkgs, lib, ... }: {
  name = "nexus-workload-backup";
  globalTimeout = 20 * 60;
  nodes = {
    repository = { pkgs, ... }: {
      virtualisation.restrictNetwork = true;
      virtualisation.memorySize = 512;
      virtualisation.cores = 1;
      users.groups.backup = { };
      users.users.backup = {
        isNormalUser = true;
        group = "backup";
        home = "/var/lib/backup";
      };
      services.openssh = {
        enable = true;
        settings = {
          PasswordAuthentication = false;
          X11Forwarding = false;
          PermitRootLogin = "no";
        };
        extraConfig = ''
          Match User backup
            ChrootDirectory /srv/repos
            ForceCommand internal-sftp
            AllowTcpForwarding no
            PermitTTY no
            X11Forwarding no
            PasswordAuthentication no
        '';
      };
      systemd.tmpfiles.rules = [
        "d /srv/repos 0755 root root -"
        "d /srv/repos/canary 0700 backup backup -"
        "d /var/lib/backup 0755 backup backup -"
        "d /var/lib/backup/.ssh 0700 backup backup -"
      ];
      environment.systemPackages = [ pkgs.openssh pkgs.restic ];
      networking.firewall.allowedTCPPorts = [ 22 ];
    };
    source = clientNode {
      hostId = "host-a";
      uuid = "11111111-2222-3333-4444-555555555555";
      slots = [
        { id = "first"; uidBase = 65536; hostAddress = "192.168.130.1"; localAddress = "192.168.130.2"; }
        { id = "second"; uidBase = 131072; hostAddress = "192.168.131.1"; localAddress = "192.168.131.2"; }
      ];
    };
    target = clientNode {
      hostId = "host-b";
      uuid = "66666666-7777-4888-8999-aaaaaaaaaaaa";
      slots = [
        { id = "first"; uidBase = 262144; hostAddress = "192.168.140.1"; localAddress = "192.168.140.2"; }
        { id = "second"; uidBase = 327680; hostAddress = "192.168.141.1"; localAddress = "192.168.141.2"; }
      ];
    };
  };
  testScript = ''
    import json
    import shlex
    from pathlib import Path

    INSTANCE_A = "0a" * 16
    CAPTURE = "c1" * 16
    PRIVATE = "/root/backup-private"
    STAGE = "/root/capture-stage"
    MARKER = "backup-canary-marker"

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

    def cli(node, payload):
        body = dict(payload)
        body["config"] = client_config if "config" not in body else body["config"]
        rc, output = node.execute(
            "printf %s " + shlex.quote(json.dumps(body))
            + " | python3 ${repoLib pkgs}/repository-cli.py")
        return rc, json.loads(output)

    def expect_failed(node, payload, code=None):
        rc, result = cli(node, payload)
        assert result["status"] == "failed", result
        if code is not None:
            assert result["error"] == code, result
        assert "record" not in result and "records" not in result, result
        return result

    start_all()
    revision = json.loads(Path("${canary.bundle}/definition.json").read_text())["revisionDigest"]
    definition = json.loads(Path("${canary.bundle}/definition.json").read_text())

    for node in (source, target, repository):
        node.wait_for_unit("multi-user.target")
    for node in (source, target):
        node.succeed("systemctl start nix-daemon.socket")

    with subtest("repository host runs SFTP-only backup account"):
        assert repository.succeed("hostname").strip() == "repository"
        repository.succeed("test -d /srv/repos/canary")
        repository.succeed("stat -c '%U %a' /srv/repos/canary | grep -qx 'backup 700'")

    with subtest("runtime keys and private client configuration"):
        for node in (source, target):
            node.succeed("install -d -m 0700 " + PRIVATE)
            node.succeed("ssh-keygen -q -t ed25519 -N \"\" -f "
                         + PRIVATE + "/id_ed25519")
            node.succeed("chmod 600 " + PRIVATE + "/id_ed25519")
        hostkey = repository.succeed(
            "cat /etc/ssh/ssh_host_ed25519_key.pub").strip()
        known_hosts = "repository " + " ".join(hostkey.split()[:2]) + "\n"
        pubs = []
        for node in (source, target):
            pubs.append(node.succeed(
                "cat " + PRIVATE + "/id_ed25519.pub").strip())
            node.succeed("printf %s " + shlex.quote(known_hosts)
                         + "> " + PRIVATE + "/known_hosts")
            node.succeed("chmod 600 " + PRIVATE + "/known_hosts")
        keys_body = "\n".join(pubs) + "\n"
        repository.succeed(
            "printf %s " + shlex.quote(keys_body)
            + "> /var/lib/backup/.ssh/authorized_keys"
            + " && chown backup:backup /var/lib/backup/.ssh/authorized_keys"
            + " && chmod 600 /var/lib/backup/.ssh/authorized_keys")
        target_public = pubs[1]

    with subtest("one shared repository password reaches only the clients"):
        repository.succeed(
            "head -c 32 /dev/urandom | od -An -tx1 -v"
            + " | tr -d ' \\n' > /srv/repos/canary/.password-share"
            + " && chown backup:backup /srv/repos/canary/.password-share"
            + " && chmod 600 /srv/repos/canary/.password-share")
        sftp_opts = (
            "-oBatchMode=yes -oIdentitiesOnly=yes -oIdentityAgent=none"
            " -oStrictHostKeyChecking=yes"
            " -oUserKnownHostsFile=" + PRIVATE + "/known_hosts"
            " -oGlobalKnownHostsFile=/dev/null"
            " -i " + PRIVATE + "/id_ed25519 -P 22")
        for node in (source, target):
            node.succeed(
                "printf 'get /canary/.password-share "
                + PRIVATE + "/password\\n'"
                + " | sftp -b - " + sftp_opts + " backup@repository")
            node.succeed("chmod 600 " + PRIVATE + "/password")
        repository.succeed("rm -f /srv/repos/canary/.password-share")

    ssh_argv = [
        "ssh", "-F", "/dev/null",
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + PRIVATE + "/known_hosts",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-i", PRIVATE + "/id_ed25519", "-p", "22",
        "-s", "backup@repository", "sftp"]
    admin_base = [
        "restic", "--no-cache", "--repo", "sftp:backup@repository:/canary",
        "--password-file", PRIVATE + "/password",
        "-o", "sftp.command=" + shlex.join(ssh_argv)]

    with subtest("admin step initializes the repository over SFTP"):
        source.succeed(
            " ".join(shlex.quote(arg) for arg in admin_base + ["init"]))
        config_out = source.succeed(
            " ".join(shlex.quote(arg)
                     for arg in admin_base + ["cat", "config"]))
        repo_id = json.loads(config_out)["id"]
        assert len(repo_id) == 64
        client_config = {
            "schemaVersion": 1,
            "id": "repo-a",
            "repositoryIdentity": repo_id,
            "passwordFile": PRIVATE + "/password",
            "transport": {
                "kind": "sftp", "host": "repository", "port": 22,
                "user": "backup", "path": "/canary",
                "identityFile": PRIVATE + "/id_ed25519",
                "knownHostsFile": PRIVATE + "/known_hosts",
            },
        }
        for node in (source, target):
            node.succeed("printf %s " + shlex.quote(json.dumps(client_config))
                         + "> " + PRIVATE + "/repository.json")
            node.succeed("chmod 600 " + PRIVATE + "/repository.json")

    with subtest("source canary runs and records marker"):
        source.succeed(
            "mkfs.ext4 -q -U 11111111-2222-3333-4444-555555555555 /dev/vdc")
        source.wait_until_succeeds(
            "test -b /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555",
            timeout=30)
        source.succeed("mkdir -p /srv/workloads")
        source.succeed(
            "mount /dev/disk/by-uuid/11111111-2222-3333-4444-555555555555"
            " /srv/workloads")
        rc, result = worker(source, request("aa" * 16, "prepare",
                                            INSTANCE_A, 1))
        assert result["status"] == "completed", result
        rc, result = worker(source, request("ab" * 16, "start",
                                            INSTANCE_A, 1))
        assert result["status"] == "completed", result
        source.wait_until_succeeds(
            "curl --fail --silent http://192.168.130.2:8080/", timeout=120)
        source.succeed("curl --fail --silent -X PUT --data-binary "
                       + MARKER + " http://192.168.130.2:8080/")

    with subtest("held capture barrier protects private staging copy"):
        started_at = int(source.succeed("date +%s").strip())
        freeze = dict(request("ac" * 16, "freeze", INSTANCE_A, 1))
        freeze["captureId"] = CAPTURE
        rc, result = worker(source, freeze)
        assert result["status"] == "completed" \
            and result["appliedPhase"] == "stopped", result
        source_stats = source.succeed(
            "stat -c '%u:%g:%a' /srv/workloads/" + INSTANCE_A + "/data"
            + " /srv/workloads/" + INSTANCE_A + "/data/value").split()
        source.succeed("install -d -m 0700 " + STAGE)
        source.succeed("install -d -m 0700 " + STAGE + "/state")
        source.succeed("cp -a /srv/workloads/" + INSTANCE_A + "/data "
                       + STAGE + "/state/data")
        source.succeed("sync -f " + STAGE)
        staged_stats = source.succeed(
            "stat -c '%u:%g:%a' " + STAGE + "/state/data"
            + " " + STAGE + "/state/data/value").split()
        assert staged_stats == source_stats, (staged_stats, source_stats)
        rc, observed = worker(source, {
            "schemaVersion": 1, "action": "observe",
            "instanceId": INSTANCE_A})
        assert observed["captureId"] == CAPTURE, observed
        assert observed["phase"] == "stopped" \
            and observed["unitDrained"] is True, observed
        # The capture window closes only after the copy, its fsync and
        # the held-barrier re-query all succeeded.
        completed_at = int(source.succeed("date +%s").strip())
        capture_record = {
            "adapter": "quiesce-v1", "consistency": "quiesced",
            "startedAt": started_at, "completedAt": completed_at}
        source_record = {
            "hostId": "host-a", "instanceId": INSTANCE_A,
            "generation": 1, "uidBase": 65536}

    with subtest("adapter stores, inspects and verifies the recovery point"):
        rc, stored = cli(source, {
            "operation": "store", "stageDir": STAGE,
            "definition": definition, "source": source_record,
            "capture": capture_record, "captureId": CAPTURE})
        assert stored["status"] == "completed", stored
        record = stored["record"]
        assert record["schemaVersion"] == 1
        assert record["repositoryId"] == "repo-a"
        assert record["repositoryIdentity"] == repo_id
        assert len(record["snapshotId"]) == 64
        rc, looked = cli(source, {
            "operation": "inspect",
            "snapshotId": record["snapshotId"]})
        assert looked["status"] == "completed" \
            and looked["record"] == record, looked
        rc, checked = cli(source, {"operation": "check"})
        assert checked["status"] == "completed", checked
        rc, listed = cli(source, {"operation": "list_points"})
        assert listed["status"] == "completed", listed
        assert [item["snapshotId"] for item in listed["records"]] \
            == [record["snapshotId"]], listed

    with subtest("remote repository holds only encrypted opaque data"):
        repository.succeed("test -d /srv/repos/canary/data")
        repository.succeed("test -d /srv/repos/canary/snapshots")
        # grep rc must be exactly 1 (no match): an I/O or usage error
        # is not proof that plaintext is absent.
        rc, _out = repository.execute(
            "grep -rl " + MARKER + " /srv/repos/canary")
        assert rc == 1, "plaintext marker leaked into repository files"
        assert repository.succeed("hostname").strip() \
            != source.succeed("hostname").strip()

    with subtest("thaw and restart work after the immutable capture"):
        thaw = dict(request("ad" * 16, "thaw", INSTANCE_A, 1))
        thaw["captureId"] = CAPTURE
        rc, result = worker(source, thaw)
        assert result["status"] == "completed", result
        rc, result = worker(source, request("ae" * 16, "start",
                                            INSTANCE_A, 1))
        assert result["status"] == "completed", result
        source.wait_until_succeeds(
            "curl --fail --silent http://192.168.130.2:8080/", timeout=120)
        guest = json.loads(source.succeed(
            "curl --fail --silent http://192.168.130.2:8080/"))
        assert guest["value"] == MARKER, guest

    with subtest("source host becomes unavailable"):
        source.crash()

    with subtest("surviving target reconstructs and restores off-host"):
        rc, listed = cli(target, {"operation": "list_points"})
        assert listed["status"] == "completed", listed
        assert len(listed["records"]) == 1, listed
        point = listed["records"][0]
        assert point["snapshotId"] == record["snapshotId"], point
        assert point["manifest"]["definition"]["revisionDigest"] \
            == revision, point
        target.succeed("install -d -m 0700 /root/recovery-root")
        rc, restored = cli(target, {
            "operation": "restore",
            "snapshotId": point["snapshotId"],
            "destination": "/root/recovery-root/point"})
        assert restored["status"] == "completed", restored
        assert restored["record"]["manifest"] == point["manifest"]
        value = target.succeed(
            "cat /root/recovery-root/point/state/data/value")
        assert value == MARKER, value
        restored_stats = target.succeed(
            "stat -c '%u:%g:%a' /root/recovery-root/point/state/data"
            + " /root/recovery-root/point/state/data/value").split()
        assert restored_stats == source_stats, \
            (restored_stats, source_stats)

    with subtest("missing password file blocks without exposing secrets"):
        bad = dict(client_config)
        bad["passwordFile"] = PRIVATE + "/password-missing"
        expect_failed(target, {"operation": "check", "config": bad},
                      "repository-key-missing")

    with subtest("wrong password file is not a usable key"):
        target.succeed("head -c 32 /dev/urandom | od -An -tx1 -v"
                       + " | tr -d ' \\n' > " + PRIVATE + "/password-wrong")
        target.succeed("chmod 600 " + PRIVATE + "/password-wrong")
        bad = dict(client_config)
        bad["passwordFile"] = PRIVATE + "/password-wrong"
        result = expect_failed(
            target, {"operation": "check", "config": bad})
        assert result["error"] == "repository-key-unavailable", result

    with subtest("wrong pinned host key is refused before any operation"):
        # The target's own public key stands in as a fake repository
        # host key; strict host-key checking must fail every op.
        target.succeed(
            "printf %s "
            + shlex.quote("repository " + target_public + "\n")
            + "> " + PRIVATE + "/known_hosts_wrong")
        target.succeed("chmod 600 " + PRIVATE + "/known_hosts_wrong")
        bad = dict(client_config)
        bad["transport"] = dict(
            client_config["transport"],
            knownHostsFile=PRIVATE + "/known_hosts_wrong")
        expect_failed(target, {"operation": "check", "config": bad})
        expect_failed(
            target, {"operation": "restore", "config": bad,
                     "snapshotId": record["snapshotId"],
                     "destination": "/root/recovery-root/rogue"})

    with subtest("wrong repository identity blocks all operations"):
        bad = dict(client_config)
        bad["repositoryIdentity"] = "b" * 64
        expect_failed(target, {"operation": "check", "config": bad},
                      "repository-identity-mismatch")
        expect_failed(
            target, {"operation": "restore", "config": bad,
                     "snapshotId": record["snapshotId"],
                     "destination": "/root/recovery-root/other"},
            "repository-identity-mismatch")

    with subtest("faulted repository copy fails closed"):
        repository.succeed(
            "cp -a /srv/repos/canary /srv/repos/faulted")
        pack = repository.succeed(
            "find /srv/repos/faulted/data -type f -print -quit").strip()
        assert pack, "expected a data pack to remove"
        repository.succeed("rm " + pack)
        faulted = dict(client_config)
        faulted["transport"] = dict(
            client_config["transport"], path="/faulted")
        # A removed pack may only lose payload: metadata
        # reconstruction (list_points) is not required to fail, but a
        # full native check and an isolated restore of the recorded
        # snapshot must both fail closed on the faulted copy.
        expect_failed(target, {"operation": "check", "config": faulted})
        expect_failed(
            target, {"operation": "restore", "config": faulted,
                     "snapshotId": record["snapshotId"],
                     "destination": "/root/recovery-root/faulted"})

    with subtest("existing destination is refused before extraction"):
        target.succeed("install -d -m 0700 /root/recovery-root/existing")
        expect_failed(
            target, {"operation": "restore",
                     "snapshotId": record["snapshotId"],
                     "destination": "/root/recovery-root/existing"},
            "destination-exists")

    with subtest("the good repository remains usable afterwards"):
        rc, checked = cli(target, {"operation": "check"})
        assert checked["status"] == "completed", checked
        rc, listed = cli(target, {"operation": "list_points"})
        assert listed["status"] == "completed" \
            and len(listed["records"]) == 1, listed
  '';
}
