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
  clientNode = args: { pkgs, config, ... }: {
    imports = [ (hostNode args) ];
    virtualisation.restrictNetwork = true;
    networking.hosts."192.168.1.1" = [ "repository" ];
    environment.systemPackages = [
      pkgs.python3 pkgs.restic pkgs.openssh pkgs.acl pkgs.libcap
    ];
    # The test reads the pinned admin worker config through this
    # indirection instead of discovering files in the store.
    environment.etc."nexus-worker-config-path".text =
      "${config.services.nexus-workload-worker.configFile}\n";
  };
in { pkgs, lib, ... }: {
  name = "nexus-workload-restore";
  # KVM finishes in minutes; pure emulation needs three container
  # starts at ~7 min each plus restic round-trips.
  globalTimeout = 45 * 60;
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
    source = { pkgs, config, ... }: {
      imports = [
        (clientNode {
          hostId = "host-a";
          uuid = "11111111-2222-3333-4444-555555555555";
          slots = [
            { id = "first"; uidBase = 65536; hostAddress = "192.168.130.1"; localAddress = "192.168.130.2"; }
            { id = "second"; uidBase = 131072; hostAddress = "192.168.131.1"; localAddress = "192.168.131.2"; }
          ];
        })
        ../host-modules/workload-backup.nix
      ];
      services.nexus-workload-backup = {
        enable = true;
        configurationFile = "/run/backup-config.json";
      };
    };
    target = { pkgs, config, ... }: {
      imports = [
        (clientNode {
          hostId = "host-b";
          uuid = "66666666-7777-4888-8999-aaaaaaaaaaaa";
          slots = [
            { id = "first"; uidBase = 262144; hostAddress = "192.168.140.1"; localAddress = "192.168.140.2"; }
            { id = "second"; uidBase = 327680; hostAddress = "192.168.141.1"; localAddress = "192.168.141.2"; }
          ];
        })
        ../host-modules/workload-restore.nix
      ];
      services.nexus-workload-restore = {
        enable = true;
        configurationFile = "/run/restore-config.json";
      };
    };
  };
  testScript = ''
    import hashlib
    import json
    import shlex
    import time
    from pathlib import Path

    INSTANCE_A = "0a" * 16
    INSTANCE_B = "1b" * 16
    CAPTURE = "c1" * 16
    RESTORE_ID = "d5" * 16
    PRIVATE = "/root/backup-private"
    MARKER = "restore-canary-marker"
    LIVE_MARKER = "post-restore-live-marker"
    CACHE_REPO = "/var/lib/nexus-backup-cache"
    BACKUP_CONFIG = "/run/backup-config.json"
    RESTORE_CONFIG = "/run/restore-config.json"

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

    def backup(node, request):
        rc, output = node.execute(
            "printf %s " + shlex.quote(json.dumps(request))
            + " | nexus-backup execute")
        return rc, json.loads(output)

    def backup_request(action, **fields):
        request = {"schemaVersion": 1, "action": action,
                   "captureId": CAPTURE}
        request.update(fields)
        return request

    def restore(node, request):
        rc, output = node.execute(
            "printf %s " + shlex.quote(json.dumps(request))
            + " | nexus-restore execute")
        return rc, json.loads(output)

    def restore_request(restore_id, snapshot_id, **target):
        binding = {"workloadId": "canary", "revisionDigest": revision,
                   "instanceId": INSTANCE_B, "generation": 2,
                   "slotId": "first"}
        binding.update(target)
        return {"schemaVersion": 1, "action": "stage",
                "restoreId": restore_id, "repositoryId": "repo-a",
                "snapshotId": snapshot_id, "target": binding}

    def expect_blocked(node, request, code):
        rc, result = restore(node, request)
        assert result["status"] == "blocked", result
        assert result["error"] == code, result
        return result

    def start_instance(node, op, instance, generation):
        # Under emulation the unit's start budget can outlive the
        # worker's own subprocess cap; the operation stays replayable
        # and reconciles once the unit reports active.
        req = request(op, "start", instance, generation)
        result = None
        for _attempt in range(30):
            rc, result = worker(node, req)
            if result["status"] == "completed":
                return result
            # 'failed' is a terminal receipt; only 'uncertain'
            # (in-flight unit past the caller's subprocess cap)
            # is worth replaying.
            assert result["status"] == "uncertain", result
            time.sleep(20)
        raise AssertionError(result)

    start_all()
    revision = json.loads(Path("${canary.bundle}/definition.json").read_text())["revisionDigest"]
    CAPTURE_REQUEST = {
        "workloadId": "canary",
        "revisionDigest": revision,
        "instanceId": INSTANCE_A,
        "generation": 1,
    }

    for node in (source, target, repository):
        node.wait_for_unit("multi-user.target")
    for node in (source, target):
        node.succeed("systemctl start nix-daemon.socket")

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

    with subtest("local encrypted cache and admin backup configuration"):
        source.succeed("install -d -m 0700 " + CACHE_REPO)
        source.succeed(
            "head -c 32 /dev/urandom | od -An -tx1 -v"
            + " | tr -d ' \\n' > " + PRIVATE + "/cache-password"
            + " && chmod 600 " + PRIVATE + "/cache-password")
        source.succeed(
            "restic --no-cache --repo " + CACHE_REPO
            + " --password-file " + PRIVATE + "/cache-password init")
        cache_id = json.loads(source.succeed(
            "restic --no-cache --repo " + CACHE_REPO
            + " --password-file " + PRIVATE + "/cache-password"
            + " cat config"))["id"]
        worker_config = source.succeed(
            "cat /etc/nexus-worker-config-path").strip()
        source.succeed("install -D -m 0600 " + worker_config
                       + " /run/nexus-worker-config.json")
        backup_config = {
            "schemaVersion": 1,
            "stateDir": "/var/lib/nexus-backup",
            "workerConfigFile": "/run/nexus-worker-config.json",
            "cache": {
                "schemaVersion": 1, "id": "cache",
                "repositoryIdentity": cache_id,
                "passwordFile": PRIVATE + "/cache-password",
                "transport": {"kind": "local", "path": CACHE_REPO},
            },
            "repositories": [client_config],
            "bindings": [{
                "workloadId": "canary",
                "revisionDigest": revision,
                "repositoryIds": ["repo-a"],
            }],
        }
        source.succeed(
            "printf %s " + shlex.quote(json.dumps(backup_config))
            + " > " + BACKUP_CONFIG
            + " && chmod 600 " + BACKUP_CONFIG)

    with subtest("admin restore configuration on the surviving host"):
        worker_config = target.succeed(
            "cat /etc/nexus-worker-config-path").strip()
        target.succeed("install -D -m 0600 " + worker_config
                       + " /run/nexus-worker-config.json")
        restore_config = {
            "schemaVersion": 1,
            "stateDir": "/var/lib/nexus-restore",
            "workerConfigFile": "/run/nexus-worker-config.json",
            "repositories": [client_config],
        }
        target.succeed(
            "printf %s " + shlex.quote(json.dumps(restore_config))
            + " > " + RESTORE_CONFIG
            + " && chmod 600 " + RESTORE_CONFIG)

    with subtest("source canary runs and records a rich marker tree"):
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
        result = start_instance(source, "ab" * 16, INSTANCE_A, 1)
        assert result["status"] == "completed", result
        source.wait_until_succeeds(
            "curl --fail --silent http://192.168.130.2:8080/", timeout=120)
        source.succeed("curl --fail --silent -X PUT --data-binary "
                       + MARKER + " http://192.168.130.2:8080/")
        leaf = "/srv/workloads/" + INSTANCE_A + "/data"
        # Metadata that must survive backup + idmapped translation:
        # ACL uid, v3 capability rootid, setuid bit, hardlink, symlink
        # and a user xattr — all anchored in the source uid domain.
        source.succeed("cp ${pkgs.coreutils}/bin/true " + leaf + "/cap")
        source.succeed("cp ${pkgs.coreutils}/bin/true " + leaf + "/suid")
        source.succeed("ln " + leaf + "/value " + leaf + "/hardlink")
        source.succeed("ln -s value " + leaf + "/link")
        source.succeed("chown 65536:65536 " + leaf + "/cap "
                       + leaf + "/suid")
        # A symlink's own uid is only moved by chown -h.
        source.succeed("chown -h 65536:65536 " + leaf + "/link")
        source.succeed("chmod 04755 " + leaf + "/suid")
        source.succeed("setfacl -m u:65543:r-- " + leaf + "/value")
        source.succeed("setcap -n 65536 cap_net_bind_service=ep "
                       + leaf + "/cap")
        source.succeed(
            "python3 -c 'import os; os.setxattr("
            + '"/srv/workloads/' + INSTANCE_A
            + '/data/value", "user.nexus-marker", b"restored")' + "'")

    with subtest("held barrier capture uploads a verified remote point"):
        freeze = dict(request("ac" * 16, "freeze", INSTANCE_A, 1))
        freeze["captureId"] = CAPTURE
        rc, result = worker(source, freeze)
        assert result["status"] == "completed" \
            and result["appliedPhase"] == "stopped", result
        rc, captured = backup(
            source, backup_request("capture", **CAPTURE_REQUEST))
        assert captured["status"] == "completed", captured
        record = captured["record"]
        thaw = dict(request("ad" * 16, "thaw", INSTANCE_A, 1))
        thaw["captureId"] = CAPTURE
        rc, result = worker(source, thaw)
        assert result["status"] == "completed", result
        result = start_instance(source, "ae" * 16, INSTANCE_A, 1)
        assert result["status"] == "completed", result
        source.wait_until_succeeds(
            "curl --fail --silent http://192.168.130.2:8080/", timeout=120)
        source.succeed("curl --fail --silent -X PUT --data-binary "
                       + LIVE_MARKER + " http://192.168.130.2:8080/")
        rc, uploaded = backup(
            source, backup_request("upload", repositoryId="repo-a"))
        assert uploaded["status"] == "completed", uploaded
        remote = uploaded["record"]
        assert remote["manifest"]["schemaVersion"] == 3, remote
        assert remote["manifest"]["stateFormat"] \
            == "restic-posix-v2", remote

    with subtest("source host becomes unavailable"):
        source.crash()

    with subtest("target prepares a fresh instance on a different uid base"):
        target.succeed(
            "mkfs.ext4 -q -U 66666666-7777-4888-8999-aaaaaaaaaaaa /dev/vdc")
        target.wait_until_succeeds(
            "test -b /dev/disk/by-uuid/66666666-7777-4888-8999-aaaaaaaaaaaa",
            timeout=30)
        target.succeed("mkdir -p /srv/workloads")
        target.succeed(
            "mount /dev/disk/by-uuid/66666666-7777-4888-8999-aaaaaaaaaaaa"
            " /srv/workloads")
        rc, result = worker(target, request("ba" * 16, "prepare",
                                            INSTANCE_B, 2))
        assert result["status"] == "completed", result
        rc, observed = worker(target, {
            "schemaVersion": 1, "action": "observe",
            "instanceId": INSTANCE_B})
        assert observed["phase"] == "prepared", observed
        assert observed["restorePending"] is False, observed

    with subtest("stage rejects bindings that do not match the instance"):
        expect_blocked(
            target,
            restore_request("e0" * 16, remote["snapshotId"],
                            slotId="second"),
            "instance-conflict")
        expect_blocked(
            target,
            restore_request("e0" * 16, remote["snapshotId"],
                            generation=9),
            "instance-conflict")
        expect_blocked(
            target,
            restore_request("e0" * 16, remote["snapshotId"],
                            revisionDigest="sha256:" + "0" * 64),
            "instance-conflict")
        expect_blocked(
            target,
            restore_request("e0" * 16, remote["snapshotId"],
                            instanceId="9e" * 16),
            "unknown-instance")
        rc, observed = worker(target, {
            "schemaVersion": 1, "action": "observe",
            "instanceId": INSTANCE_B})
        assert observed["restorePending"] is False, observed

    with subtest("legacy schema-2 points are readable but never installable"):
        legacy = "/root/legacy-point"
        target.succeed("install -d -m 0700 " + legacy + " "
                       + legacy + "/state")
        target.succeed("install -d -m 0755 " + legacy + "/state/data")
        target.succeed("printf legacy-marker > "
                       + legacy + "/state/data/value")
        target.succeed("chown -R 65536:65536 " + legacy + "/state/data")
        draft = target.succeed(
            "cd " + legacy + " && " + " ".join(shlex.quote(a) for a in
            admin_base) + " backup --json --quiet"
            " --tag nexus-legacy-draft state | tail -n 1")
        top = json.loads(target.succeed(
            " ".join(shlex.quote(a) for a in admin_base)
            + " cat snapshot " + json.loads(draft)["snapshot_id"]))["tree"]
        # `cat tree` resolves its argument as a snapshot id; raw tree
        # JSON must be read through `cat blob` instead.
        state_tree = json.loads(target.succeed(
            " ".join(shlex.quote(a) for a in admin_base)
            + " cat blob " + top))
        data_subtree = [n["subtree"] for n in state_tree["nodes"]
                        if n["name"] == "state"]
        state_nodes = json.loads(target.succeed(
            " ".join(shlex.quote(a) for a in admin_base)
            + " cat blob " + data_subtree[0]))
        data_id = [n["subtree"] for n in state_nodes["nodes"]
                   if n["name"] == "data"][0]
        manifest = dict(remote["manifest"])
        manifest.pop("stateSetDigest")
        manifest["schemaVersion"] = 2
        manifest["stateFormat"] = "restic-posix-v1"
        manifest["state"] = [{"id": "data", "path": "state/data",
                              "treeDigest": "sha256:" + data_id}]
        body = {key: value for key, value in manifest.items()
                if key != "recoveryPointId"}
        manifest["recoveryPointId"] = "sha256:" + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False,
                       allow_nan=False).encode("utf-8")).hexdigest()
        # decode_manifest rejects anything but the canonical encoding.
        canonical = json.dumps(manifest, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False,
                               allow_nan=False)
        target.succeed("printf %s " + shlex.quote(canonical)
                       + " > " + legacy + "/manifest.json")
        final = target.succeed(
            "cd " + legacy + " && " + " ".join(shlex.quote(a) for a in
            admin_base) + " backup --json --quiet"
            " --tag nexus-recovery-v2 state manifest.json | tail -n 1")
        legacy_snapshot = json.loads(final)["snapshot_id"]
        rc, looked = cli(target, {"operation": "inspect",
                                  "snapshotId": legacy_snapshot})
        assert looked["status"] == "completed", looked
        assert looked["record"]["manifest"]["schemaVersion"] == 2, looked
        expect_blocked(
            target,
            restore_request("e1" * 16, legacy_snapshot),
            "manifest-unsupported")

    with subtest("stage translates ownership into durable staging"):
        staged_request = restore_request(RESTORE_ID, remote["snapshotId"])
        rc, staged = restore(target, staged_request)
        assert staged["status"] == "completed", staged
        assert staged["record"] == remote, staged
        sentinel = "/srv/workloads/" + INSTANCE_B + "/.nexus-restore-pending"
        target.succeed("test -f " + sentinel)
        staging = "/srv/workloads/" + INSTANCE_B + "/.nexus-restore-staging"
        assert target.succeed("stat -c '%u:%g' " + staging + "/data") \
            .strip() == "262144:262144"
        assert target.succeed("stat -c '%u:%g' " + staging + "/data/value") \
            .strip() == "262144:262144"
        rc, observed = worker(target, {
            "schemaVersion": 1, "action": "observe",
            "instanceId": INSTANCE_B})
        assert observed["restorePending"] is True, observed
        # The idmapped view lived only inside the CLI's private mount
        # namespace; no mount or leftover extract leaks on the host.
        rc, _out = target.execute(
            "mountpoint -q /var/lib/nexus-restore/scratch/"
            + RESTORE_ID + "/view")
        assert rc != 0, "idmap mount leaked into the host namespace"
        target.fail("test -e /var/lib/nexus-restore/scratch/"
                    + RESTORE_ID + "/extract")

    with subtest("worker refuses to start while the sentinel exists"):
        rc, result = worker(target, request("bb" * 16, "start",
                                            INSTANCE_B, 2))
        assert result["status"] == "failed", result
        assert result["error"] == "restore-incomplete", result
        unit = "nexus-workload@" + observed["machineName"] + ".service"
        assert target.succeed(
            "systemctl show " + unit
            + " --property=MainPID --value").strip() == "0"

    with subtest("stage replay returns the identical staged record"):
        rc, replay = restore(target, staged_request)
        assert replay == staged, (replay, staged)

    with subtest("conflicting replay of the same restoreId is refused"):
        bad = dict(staged_request)
        bad["target"] = dict(staged_request["target"], slotId="second")
        expect_blocked(target, bad, "restore-conflict")

    with subtest("commit installs the translated tree atomically"):
        commit_request = {"schemaVersion": 1, "action": "commit",
                          "restoreId": RESTORE_ID}
        rc, committed = restore(target, commit_request)
        assert committed["status"] == "completed", committed
        assert type(committed["committedAt"]) is int, committed
        target.fail("test -e " + sentinel)
        target.fail("test -e " + staging)
        leaf = "/srv/workloads/" + INSTANCE_B + "/data"
        assert sorted(target.succeed(
            "ls " + leaf).split()) == \
            ["cap", "hardlink", "link", "suid", "value"]
        assert target.succeed("cat " + leaf + "/value").strip() == MARKER
        verify = (
            "import json, os, stat, struct\n"
            "leaf = '" + leaf + "'\n"
            "report = {}\n"
            "for name in ('cap', 'hardlink', 'link', 'suid', 'value'):\n"
            "    st = os.lstat(leaf + '/' + name)\n"
            "    report[name] = [st.st_uid, st.st_gid,"
            "                    stat.S_IMODE(st.st_mode)]\n"
            "cap = os.getxattr(leaf + '/cap', 'security.capability')\n"
            "report['capRoot'] = struct.unpack('<6I', cap)[-1]\n"
            "report['marker'] = os.getxattr("
            "leaf + '/value', 'user.nexus-marker').decode()\n"
            "report['sameInode'] = (os.stat(leaf + '/value').st_ino\n"
            "                      == os.stat(leaf + '/hardlink').st_ino)\n"
            "report['linkTarget'] = os.readlink(leaf + '/link')\n"
            "print(json.dumps(report))\n")
        target.succeed("printf %s " + shlex.quote(verify)
                       + " > /root/verify-restore.py")
        report = json.loads(
            target.succeed("python3 /root/verify-restore.py"))
        # Target slot uidBase 262144 owns everything; nothing in the
        # source uidBase 65536 domain survives.
        assert report["capRoot"] == 262144, report
        assert report["marker"] == "restored", report
        assert report["sameInode"] is True, report
        assert report["linkTarget"] == "value", report
        assert report["suid"][2] & 0o4000, report
        for name in ("cap", "hardlink", "link", "suid", "value"):
            assert report[name][:2] == [262144, 262144], report
        facl = target.succeed("getfacl -cn " + leaf + "/value")
        assert "user:262151:r--" in facl, facl
        assert "user:65543" not in facl, facl
        rc, observed = worker(target, {
            "schemaVersion": 1, "action": "observe",
            "instanceId": INSTANCE_B})
        assert observed["restorePending"] is False, observed

    with subtest("commit replay returns the identical committed record"):
        rc, replay = restore(target, commit_request)
        assert replay == committed, (replay, committed)

    with subtest("restored workload starts and serves pre-thaw state"):
        result = start_instance(target, "bc" * 16, INSTANCE_B, 2)
        assert result["status"] == "completed", result
        target.wait_until_succeeds(
            "curl --fail --silent http://192.168.140.2:8080/", timeout=120)
        guest = json.loads(target.succeed(
            "curl --fail --silent http://192.168.140.2:8080/"))
        assert guest["value"] == MARKER, guest
        assert guest["value"] != LIVE_MARKER, guest
        assert guest["uid_map"] == ["0", "262144", "65536"], guest
        leader = target.succeed(
            "machinectl show " + observed["machineName"]
            + " --property=Leader --value").strip()
        assert target.succeed(
            "readlink /proc/" + leader + "/root/run/current-system").strip() \
            == "${canary.system.config.system.build.toplevel}"

    with subtest("an instance that has ever started is never a target"):
        expect_blocked(
            target,
            restore_request("f7" * 16, remote["snapshotId"],
                            generation=2),
            "instance-not-fresh")
        rc, status = restore(target, {"schemaVersion": 1,
                                      "action": "status",
                                      "restoreId": RESTORE_ID})
        assert status["status"] == "completed", status
        assert status["phase"] == "committed", status
  '';
}
