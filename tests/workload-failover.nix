# M8 integration fixture — real-stack zero-loss failover over DRBD
# protocol C.
#
# Combines the workload-drbd.nix replication mesh (source + target
# diskful, control as diskless quorum tiebreaker) with the
# workload-move.nix control plane: mTLS registry, durable
# nexus-controller failover journal, and pull-model reporter dispatch of
# adopt/observe/start through the durable ops queue. There is no restic
# and no shared image — the target's DRBD replica carries the canary's
# acknowledged state and the controller's remote adopt step claims it.
#
# Topology (three VMs, two VLANs):
#   control  - registry API + nexus-controller CLI host; also the
#              diskless DRBD quorum tiebreaker (vlan1 = mgmt, vlan2 =
#              replication).
#   source   - worker host "host-a" + reporter; DRBD diskful; canary
#              generation 1 runs here until it is killed mid-write.
#   target   - worker host "host-b" + reporter; DRBD diskful standby;
#              takes over the replica after fencing.
#
# vs. workload-drbd.nix the stand-in fence listener is replaced by the
# REAL registry: the DRBD fence-peer handler on the promoting survivor
# POSTs /v2/placements/fence over mTLS with its own controller-role
# identity (urn:nexus:controller:fence), and promotion is refused unless
# the durable fence tombstone commits first — fencing
# resource-and-stonith holds IO frozen meanwhile. The operator failover
# itself is the real `nexus-controller` failover action end to end:
#   refresh -> fence -> assign -> adopt -> ready -> publish.
#
# Loss oracle: a writer inside the workload fsyncs a new record then
# appends the sequence to an acked ledger; source is killed mid-write;
# afterwards every acked record is verified byte-for-byte through the
# target's live workload service and directly on the replicated
# filesystem.
#
# 'quorum-attested' evidence plus the registry's 30s freshness window
# means failover intentionally waits for the incumbent observation to
# age out before fencing is allowed — measured RTO includes that
# honesty bound.
{ nixpkgs }:

let
  drbdPort = 7789;
  workloadPort = 8080;
  fsUuid = "55555555-4444-3333-2222-111111111111";
  mountPoint = "/srv/workloads";

  buildWorkload = import ../workload-modules/build.nix { inherit nixpkgs; };
  hostNode = args:
    import ./workload-worker-host.nix ({ canary = canary; } // args);

  # Acked-write canary for failover. Inside the workload's systemd unit
  # a writer thread performs fsync'd record writes to /state/store plus
  # an acked ledger, while the HTTP server exposes the ledger, single
  # records and a deterministic digest so the client can verify every
  # acknowledged write byte-for-byte after failover.
  canaryHandler = ''
    import hashlib
    import json
    import os
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    ROOT = "/state"


    def expected_record(i):
        return hashlib.sha256(
            "nexus-failover-{}".format(i).encode()).hexdigest().encode() \
            + b"\n"


    def writer():
        os.makedirs(os.path.join(ROOT, "store"), exist_ok=True)
        ledger = open(os.path.join(ROOT, "acked"), "ab", buffering=0)
        marker = os.path.join(ROOT, "seq")
        i = int(open(marker).read().strip()) + 1 \
            if os.path.exists(marker) else 0
        while True:
            with open(os.path.join(ROOT, "store", "{:08d}".format(i)),
                      "wb") as handle:
                handle.write(expected_record(i))
                handle.flush()
                os.fsync(handle.fileno())
            ledger.write(str(i).encode() + b"\n")
            os.fsync(ledger.fileno())
            dirfd = os.open(os.path.join(ROOT, "store"), os.O_RDONLY)
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


    def ledger_seqs():
        with open(os.path.join(ROOT, "acked"), "rb") as handle:
            return [int(line) for line in handle.read().split()
                    if line.strip()]


    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _reply(self, status, body,
                   content_type="application/octet-stream"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._reply(200, b"ok\n", "text/plain")
                return
            if self.path == "/acked":
                with open(os.path.join(ROOT, "acked"), "rb") as handle:
                    self._reply(200, handle.read(), "text/plain")
                return
            if self.path.startswith("/digest/"):
                # Bounded digest over the first n ledger entries — the
                # ledger and records are append-only, so a prefix proof
                # never races the live writer (an unbounded digest would).
                raw = self.path[len("/digest/"):]
                if not raw.isdigit():
                    self._reply(404, b"not-found\n", "text/plain")
                    return
                n = int(raw)
                with open(os.path.join(ROOT, "acked"), "rb") as handle:
                    lines = handle.read().splitlines(keepends=True)
                if n > len(lines):
                    self._reply(409, b"beyond-ledger\n", "text/plain")
                    return
                digest = hashlib.sha256()
                digest.update(b"".join(lines[:n]))
                for line in lines[:n]:
                    with open(os.path.join(ROOT, "store",
                               "{:08d}".format(int(line))),
                              "rb") as handle:
                        digest.update(handle.read())
                self._reply(200, json.dumps({
                    "sha256": digest.hexdigest(),
                    "records": n,
                }).encode(), "application/json")
                return
            if self.path.startswith("/record/"):
                name = self.path[len("/record/"):]
                if len(name) == 8 and name.isdigit():
                    path = os.path.join(ROOT, "store", name)
                    if os.path.exists(path):
                        with open(path, "rb") as handle:
                            self._reply(200, handle.read())
                        return
                self._reply(404, b"missing\n", "text/plain")
                return
            if self.path == "/":
                self._reply(200, json.dumps({
                    "hostname": os.uname().nodename,
                    "uid_map": open("/proc/self/uid_map").read().split(),
                }).encode(), "application/json")
                return
            self._reply(404, b"not-found\n", "text/plain")

        def log_message(self, fmt, *args):
            pass


    threading.Thread(target=writer, daemon=True).start()
    HTTPServer(("0.0.0.0", ${toString workloadPort}),
               Handler).serve_forever()
  '';

  canary = buildWorkload {
    definition = {
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
        { id = "data"; mountPoint = "/state"; ownerUid = 0;
          ownerGid = 0; consistencyAdapter = "quiesce-v1"; }
      ];
      secretSetRef = null;
      dependencies = [ ];
      services = [
        { id = "web"; protocol = "http"; port = workloadPort;
          exposure = "private"; }
      ];
      requirements = {
        memoryMiB = 256;
        cpuMillis = 100;
        stateBytes = 1048576;
        capabilities = [ "userns" "nspawn-v1" ];
      };
      allowedOperations = [ "start" "stop" "restart" "backup"
        "restore" "move" ];
      policyProfiles = [ "normal" ];
    };
    modules = [
      ({ pkgs, ... }: {
        networking.firewall.allowedTCPPorts = [ workloadPort ];
        systemd.services.failover-canary = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            ExecStart = "${pkgs.python3}/bin/python3 "
              + pkgs.writeText "failover-canary.py" canaryHandler;
            Restart = "on-failure";
          };
        };
      })
    ];
  };

  # Minimal standby workload, same pattern as workload-move.nix: it
  # gives the target host a real bound instance so its reporter can post
  # fresh current-session evidence — the controller refuses a failover
  # to an unproven host.
  sentinelHandler = ''
    import json
    import os
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            value = ""
            if os.path.exists('/state/value'):
                with open('/state/value', 'rb') as handle:
                    value = handle.read().decode('utf-8')
            body = json.dumps({'value': value,
                               'hostname': os.uname().nodename}).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    HTTPServer(('0.0.0.0', ${toString workloadPort}),
               Handler).serve_forever()
  '';

  sentinel = buildWorkload {
    definition = {
      schemaVersion = 2;
      workloadId = "sentinel";
      displayName = "Sentinel";
      category = "project";
      runtimeVersion = "nspawn-v1";
      architecture = "x86_64-linux";
      runtimeArtifactId = "runtime";
      artifacts = [ ];
      stateSchemaVersion = 1;
      stateMounts = [
        { id = "data"; mountPoint = "/state"; ownerUid = 0;
          ownerGid = 0; consistencyAdapter = "quiesce-v1"; }
      ];
      secretSetRef = null;
      dependencies = [ ];
      services = [
        { id = "web"; protocol = "http"; port = workloadPort;
          exposure = "private"; }
      ];
      requirements = {
        memoryMiB = 256;
        cpuMillis = 100;
        stateBytes = 1048576;
        capabilities = [ "userns" "nspawn-v1" ];
      };
      allowedOperations = [ "start" "stop" "restart" "backup"
        "restore" "move" ];
      policyProfiles = [ "normal" ];
    };
    modules = [
      ({ pkgs, ... }: {
        networking.firewall.allowedTCPPorts = [ workloadPort ];
        systemd.services.sentinel = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            ExecStart = "${pkgs.python3}/bin/python3 "
              + pkgs.writeText "sentinel-handler.py" sentinelHandler;
            Restart = "on-failure";
          };
        };
      })
    ];
  };

  canaryDefinition = builtins.fromJSON
    (builtins.readFile "${canary.bundle}/definition.json");
  sentinelDefinition = builtins.fromJSON
    (builtins.readFile "${sentinel.bundle}/definition.json");

  registryConfig = {
    schemaVersion = 2;
    definitions = [ canaryDefinition sentinelDefinition ];
    hosts = [
      { hostId = "control"; architecture = "x86_64-linux";
        addresses = [ "192.168.1.1" ]; }
      { hostId = "host-a"; architecture = "x86_64-linux";
        addresses = [ "192.168.130.2" "192.168.131.2" ]; }
      { hostId = "host-b"; architecture = "x86_64-linux";
        addresses = [ "192.168.140.2" "192.168.141.2" ]; }
    ];
    routes = [
      { id = "route-web"; workloadId = "canary"; serviceId = "web";
        hostname = "canary.internal"; }
    ];
  };

  # urn:nexus:controller:fence is the DRBD quorum machinery's own
  # controller-role identity; urn:nexus:controller:ops is the operator
  # controller. Both are authorized to commit durable fences; the
  # tombstone records which identity attested.
  clients = [
    { identity = "urn:nexus:controller:ops"; role = "controller";
      hostId = null; }
    { identity = "urn:nexus:controller:fence"; role = "controller";
      hostId = null; }
    { identity = "urn:nexus:host:host-a"; role = "host";
      hostId = "host-a"; }
    { identity = "urn:nexus:host:host-b"; role = "host";
      hostId = "host-b"; }
  ];

  # Slot pools are identical in id and uidBase on both workers — the
  # uidBase symmetry is REQUIRED for remote adopt: the worker claims a
  # replica directory only when every state leaf is owned exactly
  # uidBase+ownerUid:uidBase+ownerGid. The canary occupies slot
  # "second" (uidBase 131072) on both sides; slot "first" holds a
  # host-local instance (a local-only pad on source, the assigned
  # sentinel on target).
  slots = [
    { id = "first"; uidBase = 65536; }
    { id = "second"; uidBase = 131072; }
  ];
  sourceSlots = map (slot: slot // (
    if slot.id == "first" then
      { hostAddress = "192.168.130.1"; localAddress = "192.168.130.2"; }
    else
      { hostAddress = "192.168.131.1"; localAddress = "192.168.131.2"; }
  )) slots;
  targetSlots = map (slot: slot // (
    if slot.id == "first" then
      { hostAddress = "192.168.140.1"; localAddress = "192.168.140.2"; }
    else
      { hostAddress = "192.168.141.1"; localAddress = "192.168.141.2"; }
  )) slots;

  # The DRBD fence-peer handler runs in drbdadm's context on the
  # promoting survivor while replication IO is still frozen. It commits
  # a REAL registry fence tombstone over mTLS — promotion is refused
  # (exit != 4) unless the POST is durably accepted. Same mechanism as
  # workload-drbd.nix, but the attestation now lands in the production
  # registry's fences table.
  fenceMap = builtins.toJSON {
    "r0:source" = {
      workloadId = "canary";
      generation = 1;
      hostId = "host-a";
      evidence = "quorum-attested";
    };
  };

  fencePeerHandler = pkgs:
    pkgs.writeShellScript "drbd-fence-peer" ''
      ${pkgs.coreutils}/bin/env | ${pkgs.coreutils}/bin/sort \
        > /var/log/fence-peer-env.txt 2>/dev/null || true
      resource="''${DRBD_RESOURCE:-r0}"
      # drbdadm exports DRBD_PEER_NODE_ID + DRBD_NODE_ID_<n>=<name>
      peer_var="DRBD_NODE_ID_''${DRBD_PEER_NODE_ID:-}"
      peer="''${!peer_var:-''${DRBD_PEER:-unknown}}"
      entry="$(${pkgs.jq}/bin/jq -c ".[\"$resource:$peer\"] // empty" \
        /etc/nexus-drbd-fence-map.json)"
      [ -n "$entry" ] || {
        echo "fence-peer: no map entry for $resource:$peer" \
          > /var/log/fence-peer.log; exit 1; }
      workload=$(printf %s "$entry" | ${pkgs.jq}/bin/jq -r .workloadId)
      generation=$(printf %s "$entry" \
        | ${pkgs.jq}/bin/jq -r .generation)
      host=$(printf %s "$entry" | ${pkgs.jq}/bin/jq -r .hostId)
      evidence=$(printf %s "$entry" | ${pkgs.jq}/bin/jq -r .evidence)
      request_id=$(printf %s \
        "nexus-drbd-fence:$resource:$peer:$workload:$generation:$host" \
        | ${pkgs.coreutils}/bin/sha256sum \
        | ${pkgs.coreutils}/bin/cut -c1-32)
      body=$(printf '{"schemaVersion":2,"requestId":"%s","workloadId":"%s","generation":%s,"hostId":"%s","evidence":"%s"}' \
        "$request_id" "$workload" "$generation" "$host" "$evidence")
      code=$(${pkgs.curl}/bin/curl -sS --max-time 10 \
        --retry 10 --retry-delay 1 --retry-all-errors \
        --cacert /run/lab-pki/ca.crt \
        --cert /run/lab-pki/fence.crt --key /run/lab-pki/fence.key \
        -H 'Content-Type: application/json' --data "$body" \
        -o /var/log/fence-peer-response.json -w '%{http_code}' \
        "https://control:9444/v2/placements/fence") || exit 1
      echo "fence-peer: $resource:$peer -> http $code" \
        > /var/log/fence-peer.log
      [ "$code" = 200 ] && exit 4
      exit 1
    '';

  # Durable self-fence on the DRBD loser: stop every workload unit AND
  # drop the workload mount. io-error alone is not a write fence —
  # outdate-async transiently restores quorum, after which a mounted
  # loser could serve stale reads or accept doomed writes. --no-block:
  # DRBD holds IO frozen (susp-io fencing) until handlers return.
  quorumLostHandler = pkgs:
    pkgs.writeShellScript "drbd-quorum-lost" ''
      units=$(${pkgs.systemd}/bin/systemctl list-units --all --plain \
        --no-legend --type=service 'nexus-workload@*.service' \
        | ${pkgs.gawk}/bin/awk '{print $1}')
      if [ -n "$units" ]; then
        ${pkgs.systemd}/bin/systemctl stop --no-block $units || true
      fi
      ${pkgs.systemd}/bin/systemctl stop --no-block \
        srv-workloads.mount || true
    '';

  drbdConf = pkgs:
    pkgs.writeText "drbd.conf" ''
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
          fence-peer "${fencePeerHandler pkgs}";
          quorum-lost "${quorumLostHandler pkgs}";
        }
      }

      resource r0 {
        connection-mesh {
          hosts source target control;
        }
        # The backing disk is the worker host's emptyDiskImages[0]:
        # /dev/vda root, /dev/vdb nix-store image (useNixStoreImage),
        # /dev/vdc first empty disk.
        on source {
          node-id 0;
          address 192.168.2.2:${toString drbdPort};
          volume 0 {
            device /dev/drbd0;
            disk /dev/vdc;
            meta-disk internal;
          }
        }
        on target {
          node-id 1;
          address 192.168.2.3:${toString drbdPort};
          volume 0 {
            device /dev/drbd0;
            disk /dev/vdc;
            meta-disk internal;
          }
        }
        on control {
          node-id 2;
          address 192.168.2.1:${toString drbdPort};
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
    virtualisation.vlans = [ 1 2 ];
    networking.firewall.enable = false;
    boot.kernelPackages = pkgs.linuxPackages_6_18;
    boot.extraModulePackages = [ config.boot.kernelPackages.drbd ];
    boot.kernelModules = [ "drbd" ];
    boot.extraModprobeConfig = ''
      options drbd usermode_helper=${pkgs.drbd}/bin/drbdadm
    '';
    services.udev.packages = [ pkgs.drbd ];
    # Upstream 60-persistent-storage.rules skips drbd* minors, so the
    # device's udev record never carries ID_FS_UUID. The workload
    # unit's ExecCondition guard resolves the storage mount's uuid
    # inside DevicePolicy=closed — where a direct libblkid probe of
    # /dev/drbd0 is denied — so the uuid must come from the udev
    # database (and the by-uuid symlink every mount unit expects).
    # NB: env values imported by IMPORT{builtin} on a rule line are not
    # visible to match keys later on the SAME line — the fs-uuid guard
    # must live on a following line (event env is shared across lines).
    services.udev.extraRules = ''
      SUBSYSTEM=="block", KERNEL=="drbd*", IMPORT{builtin}="blkid"
      SUBSYSTEM=="block", KERNEL=="drbd*", ENV{ID_FS_UUID_ENC}=="?*", SYMLINK+="disk/by-uuid/$env{ID_FS_UUID_ENC}"
    '';
    environment.etc."drbd.conf".source = drbdConf pkgs;
    environment.etc."drbd.d/fence-peer".source = fencePeerHandler pkgs;
    environment.etc."drbd.d/quorum-lost".source = quorumLostHandler pkgs;
    environment.etc."nexus-drbd-fence-map.json".text = fenceMap;
    environment.systemPackages = [
      pkgs.drbd pkgs.curl pkgs.e2fsprogs pkgs.jq pkgs.iptables
    ];
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

  workerNode = { hostId, slots, extraWorker ? { } }:
    { pkgs, lib, config, ... }: {
      imports = [
        drbdBase
        (hostNode { inherit hostId slots; uuid = fsUuid; })
        ../host-modules/workload-reporter.nix
      ];
      virtualisation.cores = lib.mkForce 2;
      virtualisation.emptyDiskImages = lib.mkForce [ 512 ];
      virtualisation.restrictNetwork = true;
      networking.hosts."192.168.1.1" = [ "control" ];
      environment.systemPackages = [
        pkgs.python3 pkgs.openssl pkgs.jq pkgs.curl
      ];
      environment.etc."nexus-worker-config-path".text =
        "${config.services.nexus-workload-worker.configFile}\n";
      environment.etc."nexus-registry-config.json".text =
        builtins.toJSON registryConfig;
      services.nexus-workload-reporter = {
        enable = true;
        inherit hostId;
        registryUrl = "https://control:9444";
        registry = registryConfig;
        workerConfigFile =
          "${config.services.nexus-workload-worker.configFile}";
        observeIntervalSeconds = 1;
        requestTimeoutSeconds = 10;
        maxBackoffSeconds = 15;
        caFile = "/run/lab-pki/ca.crt";
        certificateFile = "/run/lab-pki/${hostId}.crt";
        keyFile = "/run/lab-pki/${hostId}.key";
      };
      services.nexus-workload-worker = extraWorker;
      # Certs appear at runtime; keep the shipped unit dormant until
      # the testScript starts it.
      systemd.services.nexus-workload-reporter.wantedBy =
        lib.mkForce [ ];
      # drbd-primary -> mount -> workload unit ordering, per the
      # design doc. RequiresMountsFor on nexus-workload@ pulls this
      # mount; it can only succeed while the node holds primary.
      systemd.mounts = [
        { what = "/dev/drbd0"; where = mountPoint; type = "ext4";
          requires = [ "drbd-r0-primary.service" ];
          after = [ "drbd-r0-primary.service" ]; }
      ];
    };

in
{ pkgs, lib, ... }:
{
  name = "nexus-workload-failover";
  globalTimeout = 30 * 60;

  nodes = {
    control = { pkgs, lib, config, ... }: {
      imports = [
        drbdBase
        ../host-modules/workload-registry.nix
        ../host-modules/workload-controller.nix
        ../host-modules/workload-backup.nix
        ../host-modules/workload-restore.nix
      ];
      virtualisation.memorySize = 1536;
      virtualisation.cores = 2;
      virtualisation.restrictNetwork = true;
      networking.hosts."192.168.1.1" = [ "control" ];
      environment.systemPackages =
        [ pkgs.curl pkgs.jq pkgs.openssl pkgs.iproute2 pkgs.python3 ];
      environment.etc."nexus-registry-config.json".text =
        builtins.toJSON registryConfig;
      services.nexus-workload-registry = {
        enable = true;
        listenAddress = "0.0.0.0";
        port = 9444;
        registry = registryConfig;
        inherit clients;
        caFile = "/run/lab-pki/ca.crt";
        certificateFile = "/run/lab-pki/registry.crt";
        keyFile = "/run/lab-pki/registry.key";
      };
      services.nexus-workload-controller = {
        enable = true;
        configurationFile = "/run/nexus-controller-config.json";
        caFile = "/run/lab-pki/ca.crt";
        certificateFile = "/run/lab-pki/controller.crt";
        keyFile = "/run/lab-pki/controller.key";
      };
      # The controller never runs local worker steps here (its hostId
      # is neither worker host), but the module requires the pinned
      # config/program paths to be honest ones — failover needs no
      # backup/restore CLI, the paths are still real.
      services.nexus-workload-backup = {
        enable = true;
        configurationFile = "/run/nexus-backup-config.json";
      };
      services.nexus-workload-restore = {
        enable = true;
        configurationFile = "/run/nexus-restore-config.json";
      };
      # The registry reads runtime-issued credentials; it stays down
      # until the lab CA and server certificate exist.
      systemd.services.nexus-workload-registry.wantedBy =
        lib.mkForce [ ];
    };
    source = workerNode {
      hostId = "host-a";
      slots = sourceSlots;
      # The local-only slot-holder pad prepares a sentinel instance —
      # it needs the sentinel bundle approved on source too.
      extraWorker = {
        approvedBundles = [ sentinel.bundle ];
      };
    };
    target = workerNode {
      hostId = "host-b";
      slots = targetSlots;
      extraWorker = {
        approvedBundles = [ sentinel.bundle ];
      };
    };
  };

  testScript = ''
    import hashlib
    import json
    import shlex
    import time
    from pathlib import Path

    REGISTRY = "https://control:9444"
    MOUNT = "${mountPoint}"
    WORKLOAD_PORT = ${toString workloadPort}
    SLOT_SECOND_UIDBASE = 131072
    INSTANCE_A = "0a" * 16          # canary generation 1 on host-a
    INSTANCE_PAD = "5d" * 16        # local-only slot holder on source
    INSTANCE_S = "5e" * 16          # sentinel generation 1 on host-b
    FO_OP = "f0" * 16               # failover operation id
    FENCE_REQ = "f1" * 16           # controller fence request id
    NONCE_GEN1 = "04" * 16
    NONCE_GEN2 = "05" * 16
    NONCE_LATE = "06" * 16
    revision = json.loads(
        Path("${canary.bundle}/definition.json")
        .read_text())["revisionDigest"]
    sentinel_revision = json.loads(
        Path("${sentinel.bundle}/definition.json")
        .read_text())["revisionDigest"]
    NEW_ID = hashlib.sha256(
        ("nexus-controller:instance:" + FO_OP).encode()
    ).hexdigest()[:32]
    FENCE_PEER_REQ = hashlib.sha256(
        "nexus-drbd-fence:r0:source:canary:1:host-a".encode()
    ).hexdigest()[:32]

    def api(node, role, method, path, body=None, headers=None):
        cmd = ("curl --silent --show-error --max-time 15"
               " --cacert /run/lab-pki/ca.crt --cert /run/lab-pki/"
               + role + ".crt --key /run/lab-pki/" + role
               + ".key -o /tmp/api-response.json -w '%{http_code}' -X "
               + method + " " + REGISTRY + path)
        for header in (headers or []):
            cmd += " -H " + shlex.quote(header)
        if body is not None:
            node.succeed("printf %s " + shlex.quote(json.dumps(body))
                         + " > /tmp/api-request.json")
            cmd += (" -H 'Content-Type: application/json'"
                    " --data-binary @/tmp/api-request.json")
        rc, code = node.execute(cmd)
        assert rc == 0, "curl transport failed for " + path
        raw = node.succeed("cat /tmp/api-response.json")
        return int(code.strip()), json.loads(raw)


    def registry_state():
        status, body = api(control, "controller", "GET", "/v2/state")
        assert status == 200, body
        return body


    def workload_row(workload_id):
        for row in registry_state()["workloads"]:
            if row["workloadId"] == workload_id:
                return row
        raise AssertionError("workload %s missing" % workload_id)


    def routes_view(nonce):
        status, body = api(control, "controller", "GET", "/v2/routes",
                           headers=["X-Nexus-Nonce: " + nonce])
        assert status == 200, body
        return {route["id"]: route["backend"]
                for route in body["routes"]}


    def worker(node, request):
        rc, output = node.execute(
            "printf %s " + shlex.quote(json.dumps(request))
            + " | nexus-worker execute")
        return rc, json.loads(output)


    def host_op(node, operation_id, action, workload, instance,
                generation):
        rev = revision if workload == "canary" else sentinel_revision
        rc, result = worker(node, {
            "schemaVersion": 1, "operationId": operation_id,
            "action": action, "workloadId": workload,
            "revisionDigest": rev, "instanceId": instance,
            "generation": generation})
        if not (rc == 0 and result.get("status") == "completed"):
            # Failure forensics: the nspawn unit's journal explains a
            # drained workload unit better than the worker envelope.
            for cmd in (
                    "journalctl -b --no-pager -n 120"
                    " -u 'nexus-workload@*' || true",
                    "journalctl -b --no-pager -n 60"
                    " -t 'nexus-worker' || true",
                    "python3 -c 'import sqlite3;"
                    " db=sqlite3.connect("
                    "\"/var/lib/nexus-worker/worker.db\");"
                    " [print(r) for r in db.execute("
                    "\"select instance_id,workload_id,phase,permit,"
                    "retired,slot_id,generation,binding_json"
                    " from instances\")];"
                    " [print(r) for r in db.execute("
                    "\"select * from generations\")]' || true",
                    "ls -lna /srv/workloads/ /srv/workloads/*/"
                    " 2>/dev/null || true",
                    "findmnt --json --noheadings"
                    " --output TARGET,SOURCE,UUID"
                    " --target /srv/workloads || true",
                    "systemd-run --unit=guarddiag --wait --pipe"
                    " --collect -q -p Type=exec"
                    " -p RequiresMountsFor=/srv/workloads"
                    " -p Delegate=yes -p KillMode=mixed"
                    " -p DevicePolicy=closed"
                    " -p 'DeviceAllow=/dev/net/tun rwm'"
                    " -p LimitNPROC=65535 -p TasksMax=8192"
                    " -p Slice=machine.slice"
                    " sh -c 'test -d /srv/workloads && echo DIR-OK;"
                    " grep -E \"workloads|drbd\" /proc/self/mounts;"
                    " findmnt --json --noheadings"
                    " --output TARGET,SOURCE,UUID"
                    " --target /srv/workloads;"
                    " echo ==UDEV-DB==; udevadm info -q property"
                    " -n /dev/drbd0 | grep -E \"ID_FS|DEVNAME\";"
                    " echo ==NIXSTORE==; findmnt --json --noheadings"
                    " --output TARGET,SOURCE,UUID"
                    " --target /nix/var; ls -l /dev/disk/by-uuid/'"
                    " || true",
                    "journalctl -b --no-pager -n 20 -u guarddiag"
                    " || true",
                    "udevadm info -q property -n /dev/drbd0"
                    " | grep -E 'ID_FS|DEVNAME' || true",
                    "ls -l /dev/disk/by-uuid/ || true",
                    "cat /run/blkid/blkid.tab 2>/dev/null"
                    " | grep -i drbd || true",
                    "ls -lna /var/lib/nexus-worker/instances/*/"
                    " 2>/dev/null || true"):
                try:
                    print(node.succeed(cmd))
                except Exception as exc:
                    print("diagnostic dump failed:", exc)
        assert rc == 0 and result["status"] == "completed", (
            node.name + " " + action + " " + workload + ": "
            + repr(result))
        return result


    def controller(request):
        control.succeed(
            "printf %s " + shlex.quote(json.dumps(request))
            + " > /tmp/ctrl-req.json && chmod 600 /tmp/ctrl-req.json")
        rc, out = control.execute(
            "env CREDENTIALS_DIRECTORY=/run/controller-creds"
            " nexus-controller execute < /tmp/ctrl-req.json")
        return rc, json.loads(out)


    def derive(label):
        return hashlib.sha256(("nexus-controller:" + label + ":"
                               + FO_OP).encode()).hexdigest()[:32]


    def assign_request(instance, host, workload, rev, expected,
                       request_id):
        return {"schemaVersion": 2, "requestId": request_id,
                "workloadId": workload, "revisionDigest": rev,
                "hostId": host, "instanceId": instance,
                "expectedGeneration": expected}


    def failover_request():
        return {
            "schemaVersion": 1,
            "action": "failover",
            "operationId": FO_OP,
            "workloadId": "canary",
            "fenceRequestId": FENCE_REQ,
            "toHostId": "host-b",
            "toSlotId": None,
            "evidence": "quorum-attested",
        }


    def issue(node, name, cn, san, eku):
        # Private key is generated on its destination VM and never
        # leaves it; only the public CSR and signed certificate pass
        # through the lab shared directory.
        node.succeed("mkdir -p /run/lab-pki && chmod 700 /run/lab-pki")
        node.succeed("openssl ecparam -genkey -name prime256v1"
                     " -out /run/lab-pki/" + name + ".key")
        node.succeed("openssl req -new -key /run/lab-pki/" + name
                     + ".key -subj '/CN=" + cn
                     + "' -out /tmp/shared/pki/" + name + ".csr")
        control.succeed("printf '%s\\n'"
                        " 'basicConstraints=critical,CA:FALSE'"
                        " 'keyUsage=critical,digitalSignature'"
                        " 'extendedKeyUsage=" + eku + "'"
                        " 'subjectAltName=" + san + "'"
                        " > /tmp/shared/pki/" + name + ".ext")
        control.succeed("openssl x509 -req -in /tmp/shared/pki/" + name
                        + ".csr -CA /run/lab-pki/ca.crt"
                        " -CAkey /run/lab-pki/ca.key -CAcreateserial"
                        " -days 1 -extfile /tmp/shared/pki/" + name
                        + ".ext -out /tmp/shared/pki/" + name + ".crt")
        node.succeed("cp /tmp/shared/pki/" + name + ".crt"
                     " /run/lab-pki/" + name + ".crt")
        node.succeed("rm -f /tmp/shared/pki/" + name
                     + ".csr /tmp/shared/pki/" + name + ".ext")
        control.succeed("rm -f /tmp/shared/pki/" + name + ".crt")


    def wait_connected(node, count=2, timeout=180):
        node.wait_until_succeeds(
            "drbdsetup status --verbose r0"
            + " | grep -c 'connection:Connected' | grep -qx %d" % count,
            timeout=timeout)


    def expected_record(i):
        return hashlib.sha256(
            "nexus-failover-{}".format(i).encode()).hexdigest() \
            .encode() + b"\n"


    start_all()
    for node in (source, target, control):
        node.wait_for_unit("multi-user.target")
    # Clock discipline (identical to workload-move): the registry sits
    # on control and classifies observations by wall-clock freshness —
    # pin workers to the epoch and control 5s ahead so a source's
    # posthumous observation ages out ~5s early, not late.
    epoch = int(time.time())
    control.succeed("date -s '@%d'" % (epoch + 5))
    for node in (source, target):
        node.succeed("date -s '@%d'" % epoch)

    with subtest("drbd bring-up"):
        source.succeed("test -b /dev/vdc", "drbdadm create-md r0")
        target.succeed("test -b /dev/vdc", "drbdadm create-md r0")
        for node in (control, source, target):
            node.succeed("systemctl start drbd-r0-up")
            node.wait_for_unit("drbd-r0-up.service")
        for node in (source, target):
            wait_connected(node)
        # Initial promotion needs --force (all peers start
        # Inconsistent); quorum is held by target+control.
        source.succeed("drbdadm primary r0 --force")
        for node in (source, target):
            node.wait_until_succeeds(
                "drbdsetup status --verbose r0"
                + " | grep -q ' disk:UpToDate' && "
                + "! drbdsetup status --verbose r0 | "
                + "grep -Eq 'peer-disk:(Inconsistent|Outdated"
                + "|DUnknown|Failed)'",
                timeout=300)
        source.succeed("mkfs.ext4 -q -U ${fsUuid} /dev/drbd0")
        # The DRBD minor was registered before the filesystem existed,
        # so udev's device record carries no ID_FS_UUID. The workload
        # unit's ExecCondition runs under DevicePolicy=closed where
        # libblkid cannot probe the device itself — it resolves the
        # mount's uuid from the udev/blkid database, which must be
        # reprobed once the filesystem exists (as every later device
        # event would do in a real deployment).
        source.succeed(
            "udevadm trigger --action=change /sys/class/block/drbd0")
        source.succeed("udevadm settle --timeout=30")
        source.succeed("udevadm info -q property -n /dev/drbd0"
                       " | grep -q 'ID_FS_UUID=${fsUuid}'")
        source.succeed("blkid /dev/drbd0 > /dev/null")
        source.succeed("systemctl start srv-workloads.mount")
        source.succeed("test -d ${mountPoint}/lost+found")

    with subtest("pki"):
        control.succeed("mkdir -p /run/lab-pki /tmp/shared/pki")
        control.succeed("chmod 700 /run/lab-pki")
        control.succeed("openssl ecparam -genkey -name prime256v1"
                        " -out /run/lab-pki/ca.key")
        control.succeed("openssl req -x509 -new -key /run/lab-pki/ca.key"
                        " -days 1 -subj '/CN=nexus-test-ca'"
                        " -addext 'basicConstraints=critical,CA:TRUE'"
                        " -addext 'keyUsage=critical,keyCertSign,cRLSign'"
                        " -out /run/lab-pki/ca.crt")
        control.succeed("cp /run/lab-pki/ca.crt /tmp/shared/pki/ca.crt")
        for node in (source, target):
            node.succeed("mkdir -p /run/lab-pki"
                         " && chmod 700 /run/lab-pki")
            node.succeed("cp /tmp/shared/pki/ca.crt"
                         " /run/lab-pki/ca.crt")
        issue(control, "registry", "nexus-registry",
              "DNS:control", "serverAuth")
        issue(control, "controller", "ops",
              "URI:urn:nexus:controller:ops", "clientAuth")
        # The fence credential lives on the diskful hosts — the DRBD
        # fence-peer handler presents it when committing the quorum
        # fence into the real registry.
        for node in (source, target):
            issue(node, "fence", "fence",
                  "URI:urn:nexus:controller:fence", "clientAuth")
        issue(source, "host-a", "host-a",
              "URI:urn:nexus:host:host-a", "clientAuth")
        issue(target, "host-b", "host-b",
              "URI:urn:nexus:host:host-b", "clientAuth")
        # Private keys never cross machines: only CSRs/certs transit
        # /tmp/shared.
        control.fail("test -f /run/lab-pki/host-a.key")
        control.fail("test -f /run/lab-pki/host-b.key")

    with subtest("registry up"):
        control.succeed("systemctl start nexus-workload-registry")
        control.wait_until_succeeds(
            "curl -sS -o /dev/null -w '%{http_code}' "
            + "--cacert /run/lab-pki/ca.crt "
            + "--cert /run/lab-pki/controller.crt "
            + "--key /run/lab-pki/controller.key "
            + REGISTRY + "/v2/state | grep -qx 200", timeout=60)
        rc, _ = control.execute(
            "curl -sS --cacert /run/lab-pki/ca.crt "
            + REGISTRY + "/v2/state")
        assert rc != 0, "registry must require client certs"
        rc, _ = control.execute(
            "curl -sS http://control:9444/v2/state")
        assert rc != 0, "registry must reject plaintext"

    with subtest("staged configs"):
        for node in (source, target):
            node.succeed("systemctl start nix-daemon.socket")
        registry_cfg = json.loads(control.succeed(
            "cat /etc/nexus-registry-config.json"))
        control_worker = {
            "schemaVersion": 1, "hostId": "control",
            "architecture": "x86_64-linux",
            "stateDir": "/var/lib/nexus-worker-control",
            "storage": {
                "root": "/srv/workloads-control",
                "mountPoint": "/srv/workloads-control",
                "uuid": "33333333-4444-4555-8666-777777777777",
            },
            "capacity": {"memoryMiB": 256, "cpuMillis": 100,
                         "stateBytes": 1048576},
            "capabilities": ["userns", "nspawn-v1"],
            "approvedBundles":
                ["${canary.bundle}", "${sentinel.bundle}"],
            "slots": [{"id": "idle", "uidBase": 393216,
                       "hostAddress": "10.66.0.1",
                       "localAddress": "10.66.0.2"}],
        }
        control.succeed(
            "printf %s " + shlex.quote(json.dumps(control_worker))
            + " > /run/control-worker-config.json"
            + " && chmod 600 /run/control-worker-config.json")
        backup_program = control.succeed(
            "command -v nexus-backup").strip()
        restore_program = control.succeed(
            "command -v nexus-restore").strip()
        controller_config = {
            "schemaVersion": 1, "hostId": "control",
            "stateDir": "/var/lib/nexus-controller",
            "workerConfigFile": "/run/control-worker-config.json",
            "registryUrl": REGISTRY, "registry": registry_cfg,
            "backupProgram": backup_program,
            "backupConfigFile": "/run/nexus-backup-config.json",
            "restoreProgram": restore_program,
            "restoreConfigFile": "/run/nexus-restore-config.json",
            "requestTimeoutSeconds": 15,
        }
        control.succeed(
            "printf %s " + shlex.quote(json.dumps(controller_config))
            + " > /run/nexus-controller-config.json"
            + " && chmod 600 /run/nexus-controller-config.json")
        # The failover path never invokes backup/restore — stage
        # structurally honest minimal configs anyway so the pinned
        # program+config pairs resolve to real files.
        control.succeed(
            ("printf %s > /run/nexus-backup-config.json && "
             + "chmod 600 /run/nexus-backup-config.json")
            % shlex.quote(json.dumps({
                "schemaVersion": 1,
                "stateDir": "/var/lib/nexus-backup",
                "workerConfigFile": "/run/control-worker-config.json",
                "cache": {
                    "schemaVersion": 1, "id": "cache",
                    "repositoryIdentity": "0" * 64,
                    "passwordFile":
                        "/run/nexus-backup-cache-password",
                    "transport": {"kind": "local",
                                  "path": "/var/lib/nexus-backup-cache"},
                },
                "repositories": [], "bindings": []})))
        control.succeed(
            ("printf %s > /run/nexus-restore-config.json && "
             + "chmod 600 /run/nexus-restore-config.json")
            % shlex.quote(json.dumps({
                "schemaVersion": 1,
                "stateDir": "/var/lib/nexus-restore",
                "workerConfigFile": "/run/control-worker-config.json",
                "repositories": []})))
        control.succeed("install -d -m 0700 /run/controller-creds")
        control.succeed("install -m 0400 /run/lab-pki/ca.crt"
                        " /run/controller-creds/ca")
        control.succeed("install -m 0400 /run/lab-pki/controller.crt"
                        " /run/controller-creds/cert")
        control.succeed("install -m 0400 /run/lab-pki/controller.key"
                        " /run/controller-creds/key")

    with subtest("placements seeded and canary runs on source"):
        status, payload = api(
            control, "controller", "POST", "/v2/placements/assign",
            assign_request(INSTANCE_A, "host-a", "canary", revision, 0,
                           "01" * 16))
        assert status == 200 and payload["status"] == "completed" \
            and payload["generation"] == 1, (status, payload)
        status, payload = api(
            control, "controller", "POST", "/v2/placements/assign",
            assign_request(INSTANCE_S, "host-b", "sentinel",
                           sentinel_revision, 0, "02" * 16))
        assert status == 200 and payload["status"] == "completed" \
            and payload["generation"] == 1, (status, payload)
        # Slot discipline: a local-only sentinel occupies slot "first"
        # on source so the canary lands in slot "second" (uidBase
        # 131072) — the same free slot the target allocates at adopt
        # time once its own sentinel holds "first". The pad is never
        # assigned in the registry; it exists only to pin the slot.
        host_op(source, "aa" * 16, "prepare", "sentinel",
                INSTANCE_PAD, 1)
        host_op(source, "ab" * 16, "prepare", "canary",
                INSTANCE_A, 1)
        host_op(source, "ac" * 16, "start", "canary",
                INSTANCE_A, 1)
        rc, obs = worker(source, {"schemaVersion": 1,
                                  "action": "observe",
                                  "instanceId": INSTANCE_A})
        assert rc == 0 and obs["phase"] == "running" \
            and obs["slotId"] == "second" \
            and obs["endpointAddress"] == "192.168.131.2", obs
        source.wait_until_succeeds(
            "curl -sf http://192.168.131.2:%d/health" % WORKLOAD_PORT,
            timeout=90)

    with subtest("reporters post fresh evidence"):
        # Sanity probe (same as workload-move): a host-scoped session
        # plus a live observation is a real registry contract; the
        # response asserts the clock discipline landed. The persistent
        # reporters open their own session afterwards and supersede.
        status, sess = api(
            source, "host-a", "POST", "/v2/hosts/session",
            {"schemaVersion": 2, "hostId": "host-a"})
        assert status == 200 and sess["hostId"] == "host-a", sess
        probe = {"schemaVersion": 2, "hostId": "host-a",
                 "sessionId": sess["sessionId"], "sequence": 1,
                 "instanceId": INSTANCE_A, "workloadId": "canary",
                 "revisionDigest": revision, "generation": 1,
                 "observedAt": int(source.succeed("date +%s")),
                 "phase": "running",
                 "unitActiveState": "active", "unitDrained": False,
                 "retired": False,
                 "endpointAddress": "192.168.131.2",
                 "readyServices": ["web"]}
        status, body = api(
            source, "host-a", "POST", "/v2/observations", probe)
        assert status == 200 and body["status"] == "accepted", body
        for node in (source, target):
            node.succeed("systemctl start nexus-workload-reporter")
        # Wait for the persistent reporter's OWN session to supersede
        # the seeded probe — readiness for the publish below must come
        # from real reporter evidence, not the manual sanity row.
        deadline = time.time() + 180
        while True:
            row = workload_row("canary")
            obs = row["observation"]
            if row["hostId"] == "host-a" \
                    and row["instanceId"] == INSTANCE_A \
                    and row["observedState"] == "running" \
                    and obs is not None \
                    and obs["sessionId"] != sess["sessionId"] \
                    and "web" in obs["readyServices"] \
                    and obs["endpointAddress"] == "192.168.131.2":
                break
            assert time.time() < deadline, \
                "fresh reporter evidence never arrived: " \
                + json.dumps(row)
            time.sleep(2)

    with subtest("generation 1 publication exposes source backend"):
        status, payload = api(
            control, "controller", "POST", "/v2/placements/publish",
            {"schemaVersion": 2, "requestId": "03" * 16,
             "workloadId": "canary", "expectedGeneration": 1})
        assert status == 200 and payload["status"] == "completed", \
            (status, payload)
        deadline = time.time() + 60
        while True:
            backend = routes_view(NONCE_GEN1)["route-web"]
            if backend is not None \
                    and backend["hostId"] == "host-a" \
                    and backend["generation"] == 1 \
                    and backend["address"] == "192.168.131.2" \
                    and backend["instanceId"] == INSTANCE_A:
                break
            assert time.time() < deadline, backend
            time.sleep(1)

    with subtest("baseline acknowledged writes"):
        source.wait_until_succeeds(
            "test $(curl -sf http://192.168.131.2:%d/acked"
            % WORKLOAD_PORT + " | wc -l) -gt 50", timeout=90)

    # --- negative (a): quorum-attested failover while the incumbent
    # still reports fresh is refused with incumbent-live and leaves no
    # journal residue — the same request is later replayed to success,
    # proving a refused attempt never poisons an operationId. ---
    with subtest("negative: failover refused while incumbent live"):
        row = workload_row("canary")
        assert row["observedState"] == "running", row
        rc, result = controller(failover_request())
        assert rc != 0 and result["status"] == "blocked" \
            and result["error"] == "incumbent-live", (rc, result)
        control.fail("test -f /var/lib/nexus-controller/operations/"
                     + FO_OP + ".json")
        assert registry_state()["fences"] == [], \
            registry_state()["fences"]

    # --- money path: crash source mid-write, DRBD fence-peer commits
    # the real durable fence tombstone, target promotes + mounts the
    # replica, the real controller failover assigns and remotely adopts
    # through the ops queue, then publishes. ---
    with subtest("crash source mid-write"):
        t0 = time.monotonic()
        source.crash()

    with subtest("target promote via real registry fence"):
        # fencing resource-and-stonith freezes IO until the fence-peer
        # handler's POST to the real registry commits the tombstone.
        target.succeed("systemctl start drbd-r0-primary")
        deadline = time.time() + 120
        fence_row = None
        while True:
            fence_row = [f for f in registry_state()["fences"]
                         if f["workloadId"] == "canary"
                         and f["generation"] == 1]
            if fence_row:
                break
            assert time.time() < deadline, \
                "no durable fence committed for the crashed source"
            time.sleep(1)
        assert len(fence_row) == 1, fence_row
        assert fence_row[0]["hostId"] == "host-a", fence_row
        assert fence_row[0]["evidence"] == "quorum-attested", \
            fence_row
        assert fence_row[0]["attestedBy"] \
            == "urn:nexus:controller:fence", fence_row
        assert fence_row[0]["requestId"] == FENCE_PEER_REQ, fence_row
        out = target.succeed("drbdsetup status --verbose r0")
        assert "role:Primary" in out and "disk:UpToDate" in out, out

    with subtest("target mounts replica and provisions adoptee"):
        rc, _ = target.execute("e2fsck -p /dev/drbd0")
        assert rc in (0, 1), "e2fsck rc %r" % rc
        # This node's udev record was last probed while drbd0 was
        # Secondary — reads are refused in that role, so blkid saw no
        # filesystem. Reprobe now that the replica is Primary and the
        # worker mount guard needs the uuid from the udev database.
        target.succeed(
            "udevadm trigger --action=change /sys/class/block/drbd0")
        target.succeed("udevadm settle --timeout=30")
        target.succeed("udevadm info -q property -n /dev/drbd0"
                       " | grep -q 'ID_FS_UUID=${fsUuid}'")
        target.succeed("blkid /dev/drbd0 > /dev/null")
        target.succeed("systemctl start srv-workloads.mount")
        # Adopt contract (worker._adopt_dirs): the successor instance
        # directory must already exist, mode 0700, owned exactly
        # uidBase:uidBase of the slot the worker will allocate — the
        # replica-provenance marker — and each declared stateMount leaf
        # owned uidBase+ownerUid:uidBase+ownerGid. The replicated dir
        # arrives root:root 0700 (prepare's claim on source); the
        # authorized operator provisions it to the provenance marker.
        target.succeed("test -d " + MOUNT + "/" + INSTANCE_A)
        target.succeed("mv " + MOUNT + "/" + INSTANCE_A + " "
                       + MOUNT + "/" + NEW_ID)
        target.succeed("chown %d:%d %s/%s"
                       % (SLOT_SECOND_UIDBASE, SLOT_SECOND_UIDBASE,
                          MOUNT, NEW_ID))
        target.succeed("stat -c '%u:%g %a' " + MOUNT + "/" + NEW_ID
                       + " | grep -qx '131072:131072 700'")
        target.succeed("stat -c '%u:%g' " + MOUNT + "/" + NEW_ID
                       + "/data | grep -qx '131072:131072'")

    with subtest("target fresh evidence"):
        # The assigned sentinel prepares against the mounted replica
        # root and the target reporter posts a fresh observation —
        # the only honest way to satisfy target-session-unproven.
        host_op(target, "ba" * 16, "prepare", "sentinel",
                INSTANCE_S, 1)
        deadline = time.time() + 180
        while True:
            state = registry_state()
            sentinel_row = [r for r in state["workloads"]
                            if r["workloadId"] == "sentinel"][0]
            canary_row = [r for r in state["workloads"]
                          if r["workloadId"] == "canary"][0]
            sentinel_fresh = (
                sentinel_row["hostId"] == "host-b"
                and sentinel_row["observation"] is not None
                and sentinel_row["observedState"]
                not in ("stale", "lost", "unknown"))
            incumbent_gone = (
                canary_row["observedState"] in ("stale", "lost"))
            if sentinel_fresh and incumbent_gone:
                break
            assert time.time() < deadline, \
                "evidence never converged: " + json.dumps(
                    {"sentinel": sentinel_row,
                     "canary": canary_row})
            time.sleep(1)

    with subtest("controller failover"):
        t_failover = time.monotonic()
        deadline = time.time() + 300
        operation = None
        while True:
            rc, result = controller(failover_request())
            assert result is not None, (rc, result)
            if result["status"] == "completed":
                operation = result["operation"]
                break
            # Deferred is the designed pacing boundary; the two
            # blocked codes mean evidence has not converged yet —
            # anything else is a real failure and must fail here.
            assert result["status"] == "deferred" or (
                result["status"] == "blocked"
                and result["error"] in ("incumbent-live",
                                        "target-session-unproven")), \
                (rc, result)
            assert time.time() < deadline, result
            time.sleep(2)
        failover_seconds = time.monotonic() - t_failover

        assert operation["phase"] == "completed", operation
        assert operation["workloadId"] == "canary", operation
        assert operation["fromHostId"] == "host-a", operation
        assert operation["fromInstanceId"] == INSTANCE_A, operation
        assert operation["toHostId"] == "host-b", operation
        assert operation["newInstanceId"] == NEW_ID, operation
        assert operation["generation"] == 1, operation
        assert operation["newGeneration"] == 2, operation
        assert operation["toSlotId"] == "second", operation
        plan = operation["plan"]["steps"]
        assert plan == [
            {"step": "refresh", "disposition": "local"},
            {"step": "fence", "disposition": "local"},
            {"step": "assign", "disposition": "local"},
            {"step": "adopt", "disposition": "remote"},
            {"step": "ready", "disposition": "local"},
            {"step": "publish", "disposition": "local"},
        ], plan
        checkpoints = operation["checkpoints"]
        assert [c["step"] for c in checkpoints] == [
            "refresh", "fence", "assign", "adopt", "ready",
            "publish",
        ], checkpoints
        assert all(c["state"] == "completed"
                   for c in checkpoints), checkpoints
        assert all(checkpoints[i]["at"] <= checkpoints[i + 1]["at"]
                   for i in range(len(checkpoints) - 1)), checkpoints
        # The fence step verified the DRBD quorum tombstone in a fresh
        # /v2/state read — attestedBy proves the quorum machinery, not
        # the operator controller, committed it first.
        fence_detail = checkpoints[1]["detail"]
        assert fence_detail["hostId"] == "host-a", fence_detail
        assert fence_detail["evidence"] == "quorum-attested", \
            fence_detail
        assert fence_detail["attestedBy"] \
            == "urn:nexus:controller:fence", fence_detail
        assert fence_detail["requestId"] == FENCE_PEER_REQ, \
            fence_detail
        assign_detail = checkpoints[2]["detail"]
        assert assign_detail["generation"] == 2, assign_detail
        adopt_detail = checkpoints[3]["detail"]
        assert adopt_detail["disposition"] == "remote", adopt_detail
        assert adopt_detail["slotId"] == "second", adopt_detail
        ready_detail = checkpoints[4]["detail"]
        assert ready_detail["readyServices"] == ["web"], ready_detail
        publish_detail = checkpoints[5]["detail"]
        assert publish_detail["generation"] == 2, publish_detail

    with subtest("remote ops went through the durable queue"):
        # adopt/start are worker-action payloads carrying their own
        # derived operationId; observe carries none and gets
        # derive('op:observe'). All bind generation 2 on host-b — the
        # queue only delivers ops to the current placement holder.
        remote_ops = [
            ("adopt", "adopt", "adopt", "prepared"),
            ("observe", "op:observe", "observe", "prepared"),
            ("start", "start", "start", "running"),
        ]
        for step, op_label, post_label, phase in remote_ops:
            status, view = api(
                control, "controller", "GET",
                "/v2/operations/" + derive(op_label)
                + "?requestId=" + derive("post:" + post_label))
            assert status == 200 and view["status"] == "completed", \
                (step, view)
            assert view["workloadId"] == "canary", view
            assert view["step"] == step, view
            assert view["hostId"] == "host-b", view
            assert view["generation"] == 2, view
            assert view["operationId"] == derive(op_label), view
            assert view["requestId"] == derive("post:" + post_label), \
                view
            if step == "observe":
                result = view["result"]
                assert result["phase"] == phase, result
                assert result["bindingCurrent"] is True, result
                assert result["slotId"] == "second", result
            else:
                assert view["result"]["appliedPhase"] == phase, view
        # Replay-safe dispatch: re-posting the adopt operation with its
        # recorded requestId returns the same durable acceptance (same
        # seq), never a duplicate queue entry.
        adopt_body = {
            "schemaVersion": 2,
            "requestId": derive("post:adopt"),
            "operationId": derive("adopt"),
            "workloadId": "canary",
            "hostId": "host-b",
            "generation": 2,
            "step": "adopt",
            "payload": {
                "schemaVersion": 1,
                "operationId": derive("adopt"),
                "action": "adopt",
                "workloadId": "canary",
                "revisionDigest": revision,
                "instanceId": NEW_ID,
                "generation": 2,
            },
        }
        status, first = api(control, "controller", "POST",
                            "/v2/operations", adopt_body)
        assert status == 200 and first["status"] == "accepted", \
            (status, first)
        status, again = api(control, "controller", "POST",
                            "/v2/operations", adopt_body)
        assert status == 200 and again["status"] == "accepted" \
            and again["seq"] == first["seq"], (status, again)

    with subtest("adopted workload serves on target"):
        deadline = time.time() + 90
        while True:
            backend = routes_view(NONCE_GEN2)["route-web"]
            if backend is not None \
                    and backend["hostId"] == "host-b" \
                    and backend["generation"] == 2 \
                    and backend["instanceId"] == NEW_ID \
                    and backend["address"] == "192.168.141.2":
                break
            assert time.time() < deadline, backend
            time.sleep(1)
        target.wait_until_succeeds(
            "curl -sf http://192.168.141.2:%d/health" % WORKLOAD_PORT,
            timeout=90)
        t_serve = time.monotonic()
        print("nexus-failover-rto-seconds: %.2f" % (t_serve - t0),
              flush=True)
        print("nexus-failover-pipeline-seconds: %.2f"
              % failover_seconds, flush=True)
        # Provenance: the target worker adopted the replica directory,
        # and the container reports the same uidBase identity — the
        # replica rides through without an idmap translation.
        rc, obs = worker(target, {"schemaVersion": 1,
                                  "action": "observe",
                                  "instanceId": NEW_ID})
        assert rc == 0 and obs["adopted"] is True \
            and obs["phase"] == "running" \
            and obs["bindingCurrent"] is True \
            and obs["slotId"] == "second" \
            and obs["endpointAddress"] == "192.168.141.2", obs
        guest = json.loads(target.succeed(
            "curl -sf http://192.168.141.2:%d/" % WORKLOAD_PORT))
        assert guest["uid_map"] == ["0", "131072", "65536"], guest

    with subtest("zero acknowledged-write loss"):
        ledger_text = target.succeed(
            "curl -sf http://192.168.141.2:%d/acked" % WORKLOAD_PORT)
        seqs = [int(line) for line in ledger_text.split()
                if line.strip()]
        assert len(seqs) > 50, "ledger too short: %d" % len(seqs)
        # Filesystem truth on the replica: every acked record exists
        # byte-for-byte.
        target.succeed("test -f " + MOUNT + "/" + NEW_ID
                       + "/data/acked")
        digest = hashlib.sha256()
        digest.update(ledger_text.encode())
        for i in seqs:
            expected = expected_record(i)
            raw = target.succeed(
                "sha256sum " + MOUNT + "/" + NEW_ID
                + "/data/store/%08d" % i)
            assert raw.split()[0] == hashlib.sha256(expected) \
                .hexdigest(), "record %d diverged on replica" % i
            digest.update(expected)
        # Served-path truth: the workload's bounded digest endpoint
        # agrees — every acked record byte-for-byte through the real
        # service (bounded so the live writer cannot race the check).
        served = json.loads(target.succeed(
            "curl -sf http://192.168.141.2:%d/digest/%d"
            % (WORKLOAD_PORT, len(seqs))))
        assert served["sha256"] == digest.hexdigest(), served
        assert served["records"] == len(seqs), served
        for i in (seqs[0], seqs[len(seqs) // 2], seqs[-1]):
            body = target.succeed(
                "curl -sf http://192.168.141.2:%d/record/%08d"
                % (WORKLOAD_PORT, i))
            assert body.strip().encode() + b"\n" \
                == expected_record(i), i
        # The adopted writer keeps appending on the target.
        target.wait_until_succeeds(
            "test $(curl -sf http://192.168.141.2:%d/acked"
            % WORKLOAD_PORT + " | wc -l) -gt %d" % len(seqs),
            timeout=60)

    # --- negative (b): replaying the same failover request must return
    # a byte-identical completed journal with no duplicate fence or
    # assign side effects. ---
    with subtest("negative: failover replay is idempotent"):
        fences_before = registry_state()["fences"]
        rc, result = controller(failover_request())
        assert rc == 0 and result["status"] == "completed", \
            (rc, result)
        assert result["operation"] == operation, \
            "replay journal differs"
        assert registry_state()["fences"] == fences_before
        assert len(fences_before) == 1, fences_before
        # The controller's own fence POST (fenceRequestId) is durably
        # recorded: replaying it returns the identical acceptance and
        # never a second tombstone row.
        status, body = api(control, "controller", "POST",
                           "/v2/placements/fence", {
                               "schemaVersion": 2,
                               "requestId": FENCE_REQ,
                               "workloadId": "canary",
                               "generation": 1,
                               "hostId": "host-a",
                               "evidence": "quorum-attested",
                           })
        assert status == 200 and body["status"] == "accepted", \
            (status, body)
        assert registry_state()["fences"] == fences_before
        # The assign replay is acknowledged without advancing the
        # generation again — byte-identical request, recorded seq.
        status, body = api(control, "controller", "POST",
                           "/v2/placements/assign", {
                               "schemaVersion": 2,
                               "requestId": derive("assign"),
                               "workloadId": "canary",
                               "revisionDigest": revision,
                               "instanceId": NEW_ID,
                               "hostId": "host-b",
                               "expectedGeneration": 1,
                           })
        assert status == 200 and body["status"] == "completed" \
            and body["generation"] == 2, (status, body)
        row = workload_row("canary")
        assert row["generation"] == 2 and row["hostId"] == "host-b" \
            and row["instanceId"] == NEW_ID, row

    # --- negative (c): resurrect source and prove the old generation
    # cannot serve or influence the new one. ---
    with subtest("negative: resurrected source stays fenced"):
        source.start()
        source.wait_for_unit("multi-user.target")
        source.wait_for_unit("drbd-r0-up.service")
        time.sleep(3)
        _, role = source.execute(
            "drbdsetup role r0 2>/dev/null || echo none")
        assert "Primary" not in role, role
        rc, _ = source.execute(
            "systemctl is-active srv-workloads.mount")
        assert rc != 0, "mount must stay down on the fenced host"
        # Even a live resurrected reporter cannot move anything: the
        # fence tombstone plus generation-2 placement gate every path.
        # /run is tmpfs so the lab CA re-issues the host credential
        # and the trust anchor returns through the shared dir.
        issue(source, "host-a", "host-a",
              "URI:urn:nexus:host:host-a", "clientAuth")
        source.succeed("cp /tmp/shared/pki/ca.crt"
                       " /run/lab-pki/ca.crt")
        source.succeed("systemctl start nexus-workload-reporter")
        time.sleep(5)
        row = workload_row("canary")
        assert row["hostId"] == "host-b" and row["generation"] == 2 \
            and row["instanceId"] == NEW_ID, row
        backend = routes_view(NONCE_LATE)["route-web"]
        assert backend["hostId"] == "host-b" \
            and backend["generation"] == 2 \
            and backend["instanceId"] == NEW_ID, backend
        status, body = api(control, "controller", "POST",
                           "/v2/operations", {
                               "schemaVersion": 2,
                               "requestId": "ce" * 16,
                               "operationId": "cf" * 16,
                               "workloadId": "canary",
                               "hostId": "host-a",
                               "generation": 1,
                               "step": "stop",
                               "payload": {
                                   "schemaVersion": 1,
                                   "action": "stop",
                                   "operationId": "cf" * 16,
                                   "workloadId": "canary",
                                   "revisionDigest": revision,
                                   "instanceId": INSTANCE_A,
                                   "generation": 1,
                               },
                           })
        assert status == 409 \
            and body["error"] == "generation-conflict", \
            (status, body)
        # The resurrected worker cannot start the stale instance
        # locally either — the storage mount gate rejects it before
        # the unit ever renders (the mountpoint resolves to the root
        # filesystem, so the check is a mount mismatch, not absent).
        rc, result = worker(source, {
            "schemaVersion": 1, "operationId": "d1" * 16,
            "action": "start", "workloadId": "canary",
            "revisionDigest": revision, "instanceId": INSTANCE_A,
            "generation": 1})
        assert rc != 0 and result["status"] == "failed" \
            and result["error"].startswith("storage-"), \
            (rc, result)
        # The fence tombstone is permanent.
        fences = registry_state()["fences"]
        assert len(fences) == 1 and fences[0]["hostId"] == "host-a" \
            and fences[0]["generation"] == 1, fences
  '';
}
