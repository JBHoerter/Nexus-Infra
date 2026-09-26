# M7 prototype fixture — DRBD 9 protocol C failover (see
# docs/replication-failover-design.md). Standalone: does not import the
# shared worker-host fixture, but keeps the worker mount conventions
# (/srv/workloads, emptyDiskImages as the state backing disk).
#
# Topology: source + target are diskful application hosts; control is a
# diskless quorum tiebreaker and hosts the fence-attestation endpoint.
# The fence record is modeled as a POST to control, persisted with
# fsync as /var/lib/fence-records/<resource>-<peer>.json — same durable
# semantics as the real registry fence endpoint (separate workstream).
#
# VLANs: vlan1 = management/fence endpoint (eth1, 192.168.1.x),
#        vlan2 = DRBD replication mesh (eth2, 192.168.2.x).
# Node numbers are alphabetical: control=1, source=2, target=3.
{ nixpkgs }:
let
  drbdPort = 7789;
  fencePort = 7799;
  workloadPort = 8080;
  fsUuid = "55555555-4444-3333-2222-111111111111";
  mountPoint = "/srv/workloads";

  # Write loop: each record is fsynced to the replicated volume before
  # its sequence number is appended (fsynced) to the acked ledger —
  # i.e. the ledger is the journal of *acknowledged* writes.
  writerScript = ''
    import hashlib, os, sys, time
    root = "${mountPoint}/canary"
    os.makedirs(root + "/store", exist_ok=True)
    ledger = open(root + "/acked", "ab", buffering=0)
    i = 0
    marker = root + "/seq"
    if os.path.exists(marker):
        i = int(open(marker).read().strip()) + 1
    while True:
        payload = hashlib.sha256("nexus-drbd-{}".format(i).encode()).hexdigest().encode()
        with open(root + "/store/{:08d}".format(i), "wb") as handle:
            handle.write(payload + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        ledger.write(str(i).encode() + b"\n")
        os.fsync(ledger.fileno())
        dirfd = os.open(root + "/store", os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        with open(marker, "w") as handle:
            handle.write(str(i))
            handle.flush()
            os.fsync(handle.fileno())
        i += 1
        time.sleep(0.02)
  '';

  # Read side of the canary workload: serves ledger + records off the
  # replicated mount. Same service definition on both storage hosts —
  # adopt is "mount the replicated dir and start the same unit".
  serverScript = ''
    import json, os
    from http.server import BaseHTTPRequestHandler, HTTPServer

    ROOT = "${mountPoint}/canary"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self._reply(200, b"ok\n")
            elif self.path == "/acked":
                try:
                    with open(ROOT + "/acked", "rb") as handle:
                        self._reply(200, handle.read())
                except FileNotFoundError:
                    self._reply(404, b"no ledger\n")
            elif self.path.startswith("/record/"):
                seq = self.path.rsplit("/", 1)[1]
                try:
                    with open(ROOT + "/store/" + seq, "rb") as handle:
                        self._reply(200, handle.read())
                except FileNotFoundError:
                    self._reply(404, b"missing\n")
            else:
                self._reply(404, b"unknown\n")

        def _reply(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    HTTPServer(("0.0.0.0", ${toString workloadPort}), Handler).serve_forever()
  '';

  # Fence-attestation listener on control: POST /fence?resource&peer&by
  # commits a durable record (write + fsync file + fsync dir) before
  # answering 200 — fail-closed like the registry endpoint will be.
  fenceListener = ''
    import json, os, time
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    DIR = "/var/lib/fence-records"
    os.makedirs(DIR, exist_ok=True)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            query = parse_qs(urlparse(self.path).query)
            resource = query.get("resource", [""])[0]
            peer = query.get("peer", [""])[0]
            if not resource or not peer:
                self._reply(400, b"bad request\n")
                return
            record = {
                "resource": resource,
                "peer": peer,
                "by": query.get("by", [""])[0],
                "seq": int(time.time() * 1000),
                "state": "committed",
            }
            path = DIR + "/{}-{}.json".format(resource, peer)
            tmp = path + ".tmp"
            with open(tmp, "w") as handle:
                handle.write(json.dumps(record))
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(tmp, path)
            dirfd = os.open(DIR, os.O_RDONLY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
            self._reply(200, b"committed\n")

        def do_GET(self):
            parts = [p for p in self.path.split("/") if p]
            if len(parts) == 3 and parts[0] == "record":
                path = DIR + "/{}-{}.json".format(parts[1], parts[2])
                if os.path.exists(path):
                    with open(path, "rb") as handle:
                        self._reply(200, handle.read())
                else:
                    self._reply(404, b"no record\n")
            elif self.path == "/records":
                names = sorted(os.listdir(DIR))
                self._reply(200, ("\n".join(names) + "\n").encode())
            else:
                self._reply(404, b"unknown\n")

        def _reply(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    HTTPServer(("0.0.0.0", ${toString fencePort}), Handler).serve_forever()
  '';
in
{ pkgs, config, lib, nodes, ... }:
let
  nodeNumber = n: nodes.${n}.virtualisation.test.nodeNumber;
  replAddr = n: "192.168.2.${toString (nodeNumber n)}";
  mgmtAddr = n: nodes.${n}.networking.primaryIPAddress;

  # fence-peer runs when a primary-capable node needs the lost peer
  # fenced (fencing resource-and-stonith freezes I/O meanwhile). It must
  # commit the durable record before promotion is allowed — unreachable
  # control plane means outage, not divergence (fails closed).
  # Exit codes are semantic (drbd_nl.c conn_try_outdate_peer):
  #   4 = peer fenced/outdated -> promotion proceeds
  #   anything else -> IO stays frozen, promotion refused.
  fencePeerHandler = pkgs.writeShellScript "drbd-fence-peer" ''
    ${pkgs.coreutils}/bin/env | ${pkgs.coreutils}/bin/sort \
      > /var/log/fence-peer-env.txt 2>/dev/null || true
    resource="''${DRBD_RESOURCE:-r0}"
    # drbdadm exports DRBD_PEER_NODE_ID + DRBD_NODE_ID_<n>=<name>
    peer_var="DRBD_NODE_ID_''${DRBD_PEER_NODE_ID:-}"
    peer="''${!peer_var:-''${DRBD_PEER:-unknown}}"
    ${pkgs.curl}/bin/curl -fsS --max-time 10 \
      --retry 10 --retry-delay 1 --retry-all-errors \
      -X POST "http://${mgmtAddr "control"}:${toString fencePort}/fence?resource=$resource&peer=$peer&by=$(hostname)" \
      && exit 4
    exit 1
  '';

  # Self-fence: quorum loss on the loser stops the workload units AND
  # drops the mount. io-error alone is not a durable write fence: peers
  # marked Outdated restore quorum via outdate-async, after which new
  # writes could land locally (discarded on heal by discard-secondary,
  # but a mounted loser could still serve stale reads / accept writes).
  # --no-block: DRBD holds I/O frozen (susp-io fencing) until handlers
  # return; a synchronous stop prolongs the freeze window for no gain.
  quorumLostHandler = pkgs.writeShellScript "drbd-quorum-lost" ''
    ${pkgs.systemd}/bin/systemctl stop --no-block \
      drbd-server.service drbd-writer.service srv-workloads.mount || true
  '';

  drbdConf = pkgs.writeText "drbd.conf" ''
    global {
      usage-count no;
    }

    common {
      net {
        protocol C;
        fencing resource-and-stonith;
        after-sb-0pri discard-zero-changes;
        after-sb-1pri discard-secondary;
        after-sb-2pri disconnect;
      }
      disk {
        resync-rate 200M;
      }
      options {
        quorum majority;
        on-no-quorum io-error;
        auto-promote no;
      }
      handlers {
        fence-peer "${fencePeerHandler}";
        quorum-lost "${quorumLostHandler}";
      }
    }

    resource r0 {
      connection-mesh {
        hosts source target control;
      }
      on source {
        node-id 0;
        address ${replAddr "source"}:${toString drbdPort};
        volume 0 {
          device /dev/drbd0;
          disk /dev/vdb;
          meta-disk internal;
        }
      }
      on target {
        node-id 1;
        address ${replAddr "target"}:${toString drbdPort};
        volume 0 {
          device /dev/drbd0;
          disk /dev/vdb;
          meta-disk internal;
        }
      }
      on control {
        node-id 2;
        address ${replAddr "control"}:${toString drbdPort};
        volume 0 {
          device /dev/drbd0;
          disk none;
          meta-disk internal;
        }
      }
    }
  '';

  # services.drbd is incomplete (no boot.extraModulePackages); per the
  # design doc the fixture uses dedicated per-resource systemd units.
  drbdBase = { pkgs, config, ... }: {
    virtualisation.memorySize = 1024;
    virtualisation.cores = 2;
    virtualisation.vlans = [ 1 2 ];
    networking.firewall.enable = false;
    boot.kernelPackages = pkgs.linuxPackages_6_18;
    boot.extraModulePackages = [ config.boot.kernelPackages.drbd ];
    boot.kernelModules = [ "drbd" ];
    boot.extraModprobeConfig = ''
      options drbd usermode_helper=${pkgs.drbd}/bin/drbdadm
    '';
    services.udev.packages = [ pkgs.drbd ];
    environment.etc."drbd.conf".source = drbdConf;
    environment.etc."drbd.d/fence-peer".source = fencePeerHandler;
    environment.etc."drbd.d/quorum-lost".source = quorumLostHandler;
    environment.systemPackages = [ pkgs.drbd pkgs.curl pkgs.e2fsprogs pkgs.jq pkgs.iptables ];
    systemd.tmpfiles.rules = [ "d /var/lib/drbd 0755 root root -" ];

    systemd.services."drbd-r0-up" = {
      description = "Bring up DRBD resource r0";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" "systemd-udev-settle.service" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.drbd}/bin/drbdadm up r0";
        ExecStop = "${pkgs.drbd}/bin/drbdadm down r0";
        # `up` can fail half-applied (minor created, attach failed);
        # always tear down so a restart retries from clean state.
        ExecStopPost = "-${pkgs.drbd}/bin/drbdadm down r0";
        TimeoutStartSec = 120;
        # fails on first boot before create-md; restarted by the driver
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
    systemd.services."drbd-r0-primary" = {
      description = "Promote DRBD resource r0";
      requires = [ "drbd-r0-up.service" ];
      after = [ "drbd-r0-up.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.drbd}/bin/drbdadm primary r0";
        ExecStop = "${pkgs.drbd}/bin/drbdadm secondary r0";
        TimeoutStartSec = 120;
      };
    };
  };

  diskfulNode = { pkgs, ... }: {
    imports = [ drbdBase ];
    virtualisation.emptyDiskImages = [ 512 ];

    # drbd-primary -> mount -> unit ordering, per the design doc.
    systemd.mounts = [{
      what = "/dev/drbd0";
      where = mountPoint;
      type = "ext4";
      requires = [ "drbd-r0-primary.service" ];
      after = [ "drbd-r0-primary.service" ];
    }];

    systemd.services.drbd-writer = {
      description = "Canary acked-write loop through the DRBD mount";
      requires = [ "srv-workloads.mount" ];
      after = [ "srv-workloads.mount" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 ${pkgs.writeText "drbd-writer.py" writerScript}";
        Restart = "no";
        # in-flight I/O can hang in D-state when quorum is lost; the
        # self-fence must not wait out the default 90s SIGTERM window.
        TimeoutStopSec = 10;
      };
    };
    systemd.services.drbd-server = {
      description = "Canary read path served off the DRBD mount";
      requires = [ "srv-workloads.mount" ];
      after = [ "srv-workloads.mount" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 ${pkgs.writeText "drbd-server.py" serverScript}";
        Restart = "on-failure";
        TimeoutStopSec = 10;
      };
    };
  };
in
{
  name = "nexus-workload-drbd";
  globalTimeout = 30 * 60;

  nodes.source = diskfulNode;
  nodes.target = diskfulNode;
  nodes.control = { pkgs, ... }: {
    imports = [ drbdBase ];
    systemd.services.fence-attestation = {
      description = "Durable fence-record endpoint (registry stand-in)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 ${pkgs.writeText "fence-listener.py" fenceListener}";
        Restart = "on-failure";
      };
    };
  };

  testScript = ''
    import time

    MGMT = {"source": "${mgmtAddr "source"}", "target": "${mgmtAddr "target"}", "control": "${mgmtAddr "control"}"}
    REPL = {"source": "${replAddr "source"}", "target": "${replAddr "target"}", "control": "${replAddr "control"}"}

    def wait_connected(node, count=2, timeout=180):
        node.wait_until_succeeds(
            "drbdsetup status --verbose r0 | grep -c 'connection:Connected' | grep -qx %d" % count,
            timeout=timeout)

    def acked_on(node):
        return node.succeed("wc -l ${mountPoint}/canary/acked | cut -d' ' -f1").strip()

    start_all()
    for m in (source, target, control):
        m.wait_for_unit("multi-user.target")
    control.wait_for_unit("fence-attestation.service")

    # --- bring up the resource ---------------------------------------
    source.succeed("test -b /dev/vdb", "drbdadm create-md r0")
    target.succeed("test -b /dev/vdb", "drbdadm create-md r0")
    for m in (control, source, target):
        m.succeed("systemctl start drbd-r0-up")
        m.wait_for_unit("drbd-r0-up.service")
    for m in (source, target):
        wait_connected(m)

    # Initial promotion needs --force (all peers start Inconsistent);
    # quorum already held by target+control once connected.
    source.succeed("drbdadm primary r0 --force")
    # local disk UpToDate and no disked peer lagging (control is
    # diskless: it legitimately stays peer-disk:Diskless)
    for m in (source, target):
        m.wait_until_succeeds(
            "drbdsetup status --verbose r0 | grep -q ' disk:UpToDate' && "
            "! drbdsetup status --verbose r0 | "
            "grep -Eq 'peer-disk:(Inconsistent|Outdated|DUnknown|Failed)'",
            timeout=300)

    source.succeed("mkfs.ext4 -q -U ${fsUuid} /dev/drbd0")
    source.succeed("systemctl start srv-workloads.mount drbd-writer drbd-server")
    source.wait_until_succeeds("curl -fsS http://127.0.0.1:${toString workloadPort}/health", timeout=60)
    time.sleep(8)
    pre_crash_acked = int(acked_on(source))
    assert pre_crash_acked > 50, pre_crash_acked
    print("acked writes before crash:", pre_crash_acked, flush=True)

    # --- crash failover ----------------------------------------------
    t0 = time.monotonic()
    source.crash()

    # fencing resource-and-stonith: promoting while the peer is lost
    # freezes I/O and runs fence-peer, which commits the durable record
    # on control before the promotion is allowed to complete.
    target.succeed("systemctl start drbd-r0-primary")
    control.wait_until_succeeds(
        "curl -fsS http://127.0.0.1:${toString fencePort}/records | grep -q .",
        timeout=120)
    records = control.succeed("curl -fsS http://127.0.0.1:${toString fencePort}/records")
    print("fence records:", records.strip(), flush=True)
    env = target.succeed("cat /var/log/fence-peer-env.txt 2>/dev/null | grep DRBD || true")
    print("fence-peer env:", env.strip(), flush=True)
    assert "r0-source" in records, records
    fence_record = control.succeed("curl -fsS http://127.0.0.1:${toString fencePort}/record/r0/source")
    assert "committed" in fence_record, fence_record
    print("fence record:", fence_record.strip(), flush=True)
    fsck_rc = target.execute("e2fsck -p /dev/drbd0")[0]
    assert fsck_rc in (0, 1), fsck_rc
    target.succeed("systemctl start srv-workloads.mount drbd-server")

    deadline = t0 + 300
    while True:
        if target.execute("curl -fsS --max-time 2 http://127.0.0.1:${toString workloadPort}/health")[0] == 0:
            break
        assert time.monotonic() < deadline, "target never served after crash failover"
        time.sleep(0.5)
    rto = time.monotonic() - t0
    print("RTO crash->first-serve: %.2f s" % rto, flush=True)

    # Every acknowledged write must be present and byte-identical.
    target.succeed(
      "${pkgs.python3}/bin/python3 -c '" +
      "import hashlib,os\n" +
      "root=\"${mountPoint}/canary\"\n" +
      "acked=[int(x) for x in open(root+\"/acked\")]\n" +
      "assert acked, \"empty ledger\"\n" +
      "missing=[];bad=[]\n" +
      "for i in acked:\n" +
      "  p=root+\"/store/%08d\"%i\n" +
      "  if not os.path.exists(p): missing.append(i); continue\n" +
      "  want=hashlib.sha256(\"nexus-drbd-{}\".format(i).encode()).hexdigest().encode()+b\"\\n\"\n" +
      "  if open(p,\"rb\").read()!=want: bad.append(i)\n" +
      "assert not missing and not bad, (missing[:10],bad[:10])\n" +
      "print(\"verified acked records:\",len(acked))\n" +
      "'")

    # fsck clean after the adopt mount cycle.
    target.succeed("systemctl stop drbd-server drbd-writer srv-workloads.mount")
    target.succeed("e2fsck -fn /dev/drbd0")
    target.succeed("systemctl start srv-workloads.mount drbd-server")

    # --- rejoin crashed node, fail back to source --------------------
    source.start()
    source.wait_for_unit("drbd-r0-up.service")
    wait_connected(source)
    source.wait_until_succeeds(
        "drbdsetup status --verbose r0 | grep -q ' disk:UpToDate'", timeout=300)

    target.succeed("systemctl stop drbd-server drbd-writer srv-workloads.mount drbd-r0-primary")
    source.succeed("systemctl start drbd-r0-primary srv-workloads.mount drbd-writer drbd-server")
    source.wait_until_succeeds("curl -fsS http://127.0.0.1:${toString workloadPort}/health", timeout=60)
    time.sleep(4)
    pre_partition_acked = int(acked_on(source))
    assert pre_partition_acked > 0, pre_partition_acked
    print("acked writes before partition:", pre_partition_acked, flush=True)

    # --- partition: replication link down on source, mgmt stays up ---
    source.send_monitor_command("set_link virtio-net-pci.2 off")
    source.wait_until_fails("ping -c1 -W2 " + REPL["target"], timeout=30)
    source.succeed("ping -c1 -W2 " + MGMT["target"])  # control plane reachable

    # Loser: quorum lost -> writes io-error + self-fence stops workload.
    # quorum:no is transient on the loser (fence-peer marks the missing
    # peers Outdated and outdate-async regains quorum); assert the event
    # from the kernel log instead of racing the state.
    source.wait_until_succeeds(
        "dmesg | grep -q 'quorum( yes -> no )'", timeout=120)
    source.succeed("drbdsetup status --verbose r0")  # logged for inspection
    source.wait_until_fails("systemctl is-active -q drbd-writer.service", timeout=180)
    source.wait_until_fails("systemctl is-active -q drbd-server.service", timeout=180)
    # self-fence drops the mount too: the loser can neither serve stale
    # reads nor accept writes once fenced, even after quorum transiently
    # returns via outdate-async.
    source.wait_until_fails("systemctl is-active -q srv-workloads.mount", timeout=180)
    source.fail("timeout 10 dd if=/dev/zero of=${mountPoint}/canary/quorum-probe bs=4096 count=1 oflag=direct conv=fsync")

    # Survivor: quorum held via control tiebreaker -> fence + promote.
    target.succeed("systemctl start drbd-r0-primary")
    control.wait_until_succeeds(
        "curl -fsS http://127.0.0.1:${toString fencePort}/records | grep -q 'r0-source'",
        timeout=120)
    target.succeed("systemctl start srv-workloads.mount drbd-server drbd-writer")
    target.wait_until_succeeds("curl -fsS http://127.0.0.1:${toString workloadPort}/health", timeout=120)
    time.sleep(4)
    post_partition_acked = int(acked_on(target))
    assert post_partition_acked > pre_partition_acked, (post_partition_acked, pre_partition_acked)
    print("acked writes recovered on target:", post_partition_acked, flush=True)

    # --- heal: link back, loser rejoins secondary/Outdated ------------
    source.send_monitor_command("set_link virtio-net-pci.2 on")
    # Both nodes were primary: after-sb-2pri disconnect keeps them
    # StandAlone. Tear down the loser's stack (services already stopped
    # by quorum-lost), umount so the demote can succeed, then demote and
    # reconnect: after-sb-1pri discard-secondary discards its divergence.
    source.wait_until_succeeds(
        "systemctl stop drbd-server drbd-writer srv-workloads.mount && "
        "drbdadm secondary r0",
        timeout=120)
    # Rejoin after fencing: the loser's uuid history is disjoint from
    # the survivor's (the fence forced a new generation without the
    # peer's uuid in its history) -> "Unrelated data, aborting!" which
    # neither after-sb-* nor --discard-my-data can resolve. The fenced
    # replica is rebuilt: wipe + recreate metadata, re-attach, full
    # resync from the surviving primary (failover-controller step).
    source.succeed("drbdadm disconnect r0 || true")
    source.succeed("drbdadm down r0")
    source.succeed(
        "${pkgs.drbd}/bin/drbdmeta --force 0 v09 /dev/vdb internal wipe-md")
    # Destroy the filesystem signature too, else create-md refuses
    # ("Device size would be truncated").
    source.succeed("dd if=/dev/zero of=/dev/vdb bs=1M count=16")
    # Recreate via drbdadm (not drbdmeta <n>) so max-peers matches the
    # config — a wrong max-peers shrinks the reported device size and the
    # peer rejects the connect ("peer's disk size is too small").
    source.succeed("drbdadm create-md r0")
    # `drbdadm down` ran outside systemd, so drbd-r0-up is still
    # "active" (RemainAfterExit): `systemctl start` would be a no-op.
    source.succeed("drbdadm up r0")
    wait_connected(source, timeout=300)
    source.wait_until_succeeds(
        "drbdsetup status --verbose r0 | head -1 | grep -q 'role:Secondary' && "
        "drbdsetup status --verbose r0 | grep -q ' disk:UpToDate'",
        timeout=300)
    # no divergence: source fully resynced from target as SyncTarget
    status = source.succeed("drbdsetup status --verbose r0")
    assert "StandAlone" not in status, status
    assert "split-brain" not in status.lower(), status
    print("source rejoined:", status, flush=True)
    print("RTO crash->first-serve: %.2f s" % rto, flush=True)
  '';
}
