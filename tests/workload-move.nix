# M5 VM-level proof: an end-to-end workload MOVE executed by the real
# durable controller through the real pull-model dispatch path.
#
# Topology (four VMs on the lab VLAN):
#   control    - mTLS registry API plus the `nexus-controller` root CLI
#                with its own registered host identity ("control");
#                colocated with neither worker host, so every worker,
#                backup and restore step is dispatched remotely.
#   repository - SFTP-only chrooted restic repository host (same
#                pattern as tests/workload-backup.nix).
#   source     - worker host "host-a" (canary generation 1) plus the
#                persistent nexus-reporter daemon and a local
#                encrypted backup cache.
#   target     - worker host "host-b" (sentinel generation 1, then the
#                moved canary generation 2) plus its reporter.
#
# Nothing below fabricates transports: the controller only talks
# authenticated mTLS to the registry, posts bounded operations to
# /v2/operations, and the per-host reporters claim, execute and
# receipt them against their real local workers, nexus-backup and
# nexus-restore. The sentinel instance exists only to give the target
# host's live session honest fresh registry evidence — the controller's
# validate step fail-closes on a target host with zero reported
# instances, so an already-placed workload is the only real proof.
{ nixpkgs }:
let
  canary = import ./workload-canary.nix { inherit nixpkgs; };
  buildWorkload = import ../workload-modules/build.nix { inherit nixpkgs; };
  hostNode = args:
    import ./workload-worker-host.nix ({ inherit canary; } // args);

  # Minimal second workload: a plain HTTP value service like the
  # canary's, kept running on the target so the registry sees fresh
  # observations from host-b before and across the move.
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

    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
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
        { id = "data"; mountPoint = "/state"; ownerUid = 0; ownerGid = 0; consistencyAdapter = "quiesce-v1"; }
      ];
      secretSetRef = null;
      dependencies = [ ];
      services = [
        { id = "web"; protocol = "http"; port = 8080; exposure = "private"; }
      ];
      requirements = {
        memoryMiB = 256;
        cpuMillis = 100;
        stateBytes = 1048576;
        capabilities = [ "userns" "nspawn-v1" ];
      };
      allowedOperations = [ "start" "stop" "restart" "backup" "restore" "move" ];
      policyProfiles = [ "normal" ];
    };
    modules = [
      ({ pkgs, ... }: {
        networking.firewall.allowedTCPPorts = [ 8080 ];
        systemd.services.sentinel = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            ExecStart = "${pkgs.python3}/bin/python3 ${pkgs.writeText "sentinel-handler.py" sentinelHandler}";
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
  clients = [
    { identity = "urn:nexus:controller:ops"; role = "controller";
      hostId = null; }
    { identity = "urn:nexus:host:host-a"; role = "host";
      hostId = "host-a"; }
    { identity = "urn:nexus:host:host-b"; role = "host";
      hostId = "host-b"; }
  ];

  # Resolve one of the shipped CLI wrappers out of a node's own system
  # closure — the same store path `readlink -f
  # /run/current-system/sw/bin/<name>` yields on the guest at runtime.
  swProgram = config: name:
    let
      pkg = nixpkgs.lib.findFirst (p: (p.name or "") == name)
        (throw "workload-move: ${name} is not on the node's PATH")
        config.environment.systemPackages;
    in "${pkg}/bin/${name}";

  workerNode = { hostId, uuid, slots, extraWorker ? { } }:
    { pkgs, lib, config, ... }: {
    imports = [
      (hostNode { inherit hostId uuid slots; })
      ../host-modules/workload-reporter.nix
      ../host-modules/workload-backup.nix
      ../host-modules/workload-restore.nix
    ];
    virtualisation.restrictNetwork = true;
    networking.hosts."192.168.1.1" = [ "control" ];
    networking.hosts."192.168.1.2" = [ "repository" ];
    environment.systemPackages = [
      pkgs.python3 pkgs.restic pkgs.openssh pkgs.openssl pkgs.jq
    ];
    # The test stages the pinned worker config through this
    # indirection instead of discovering files in the store.
    environment.etc."nexus-worker-config-path".text =
      "${config.services.nexus-workload-worker.configFile}\n";
    # The exact registry attrset the staged controller config and the
    # registry sanity probe must mirror; delivered read-only via /etc.
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
      # Dispatched capture/upload and stage/commit steps run the same
      # shipped nexus-backup/nexus-restore wrappers an operator would
      # invoke, pointed at the runtime-staged /run configs.
      backupProgram = swProgram config "nexus-backup";
      backupConfigFile = "/run/nexus-backup-config.json";
      restoreProgram = swProgram config "nexus-restore";
      restoreConfigFile = "/run/nexus-restore-config.json";
    };
    services.nexus-workload-backup = {
      enable = true;
      configurationFile = "/run/nexus-backup-config.json";
    };
    services.nexus-workload-restore = {
      enable = true;
      configurationFile = "/run/nexus-restore-config.json";
    };
    services.nexus-workload-worker = extraWorker;
    # Certs appear at runtime; keep the shipped unit dormant until
    # the testScript starts it.
    systemd.services.nexus-workload-reporter.wantedBy =
      lib.mkForce [ ];
  };
in { pkgs, lib, ... }: {
  name = "nexus-workload-move";
  globalTimeout = 12 * 60;
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
    source = workerNode {
      hostId = "host-a";
      uuid = "11111111-2222-3333-4444-555555555555";
      slots = [
        { id = "first"; uidBase = 65536;
          hostAddress = "192.168.130.1"; localAddress = "192.168.130.2"; }
        { id = "second"; uidBase = 131072;
          hostAddress = "192.168.131.1"; localAddress = "192.168.131.2"; }
      ];
    };
    target = workerNode {
      hostId = "host-b";
      uuid = "66666666-7777-4888-8999-aaaaaaaaaaaa";
      slots = [
        { id = "first"; uidBase = 262144;
          hostAddress = "192.168.140.1"; localAddress = "192.168.140.2"; }
        { id = "second"; uidBase = 327680;
          hostAddress = "192.168.141.1"; localAddress = "192.168.141.2"; }
      ];
      extraWorker = {
        approvedBundles = [ sentinel.bundle ];
      };
    };
    control = { pkgs, lib, ... }: {
      imports = [
        ../host-modules/workload-registry.nix
        ../host-modules/workload-controller.nix
        ../host-modules/workload-backup.nix
        ../host-modules/workload-restore.nix
      ];
      virtualisation.restrictNetwork = true;
      virtualisation.memorySize = 1024;
      virtualisation.cores = 1;
      networking.hosts."192.168.1.1" = [ "control" ];
      networking.hosts."192.168.1.2" = [ "repository" ];
      networking.firewall.allowedTCPPorts = [ 9444 ];
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
      # The controller never executes local steps here (its hostId is
      # neither worker host), but the module requires the pinned
      # config/program paths to be honest ones.
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
  };
  testScript = ''
    import hashlib
    import json
    import shlex
    import time
    from pathlib import Path

    INSTANCE_A = "0a" * 16
    INSTANCE_S = "5e" * 16
    MOVE_OP = "7a" * 16
    REGISTRY = "https://control:9444"
    MARKER = "move-canary-pre-capture-marker"
    PRIVATE = "/var/lib/move-private"
    CACHE_REPO = "/var/lib/nexus-backup-cache"
    WORKER_CONFIG = "/run/nexus-worker-config.json"
    BACKUP_CONFIG = "/run/nexus-backup-config.json"
    RESTORE_CONFIG = "/run/nexus-restore-config.json"
    CONTROLLER_CONFIG = "/run/nexus-controller-config.json"
    STEP_ORDER = ["validate", "freeze", "capture", "thaw",
                  "retire-source", "assign", "install-target",
                  "await-ready", "publish", "retain"]
    DISPOSITIONS = {"validate": "local", "freeze": "remote",
                    "capture": "remote", "thaw": "remote",
                    "retire-source": "remote", "assign": "local",
                    "install-target": "remote", "await-ready": "local",
                    "publish": "local", "retain": "local"}
    # Queue operation/request ids the controller derives per step:
    # worker-request payloads carry their own operationId
    # derive('<label>') while stage/commit/capture/observe payloads get
    # derive('op:<label>'); every POST requestId is
    # derive('post:<label>'). The receipt proof below re-reads each
    # one through GET /v2/operations/<id>?requestId=... .
    REMOTE_OPS = [
        ("freeze", "freeze", "freeze"),
        ("capture", "op:capture", "capture"),
        ("thaw", "thaw", "thaw"),
        ("retire", "retire", "retire"),
        ("prepare", "prepare", "prepare"),
        ("observe", "op:observe", "observe"),
        ("restore-stage", "op:restore-stage", "restore-stage"),
        ("restore-commit", "op:restore-commit", "restore-commit"),
        ("start", "start", "start"),
    ]

    def derive(label):
        return hashlib.sha256(("nexus-controller:" + label + ":"
                               + MOVE_OP).encode()).hexdigest()[:32]

    def worker(node, request):
        rc, output = node.execute(
            "printf %s " + shlex.quote(json.dumps(request))
            + " | nexus-worker execute")
        return rc, json.loads(output)

    def host_op(node, operation_id, action, workload, revision,
                instance, generation):
        req = {"schemaVersion": 1, "operationId": operation_id,
               "action": action, "workloadId": workload,
               "revisionDigest": revision, "instanceId": instance,
               "generation": generation}
        rc, result = worker(node, req)
        assert rc == 0 and result["status"] == "completed", result
        return result

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

    def assign_request(instance, host, workload, revision, expected,
                       request_id):
        return {"schemaVersion": 2, "requestId": request_id,
                "workloadId": workload, "revisionDigest": revision,
                "hostId": host, "instanceId": instance,
                "expectedGeneration": expected}

    def controller(request):
        control.succeed(
            "printf %s " + shlex.quote(json.dumps(request))
            + " > /tmp/ctrl-req.json && chmod 600 /tmp/ctrl-req.json")
        rc, out = control.execute(
            "env CREDENTIALS_DIRECTORY=/run/controller-creds"
            " nexus-controller execute < /tmp/ctrl-req.json")
        return rc, json.loads(out)

    def workload_row(workload_id):
        status, body = api(control, "controller", "GET", "/v2/state")
        assert status == 200, body
        for row in body["workloads"]:
            if row["workloadId"] == workload_id:
                return row
        return None

    def issue(node, name, cn, san, eku):
        # Private key is generated on its destination VM and never
        # leaves it; only the public CSR and signed certificate pass
        # through the lab shared directory.
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

    start_all()
    # Clock discipline: the lab has no NTP, so each VM is pinned to the
    # host epoch (as a deployed host's NTP would). The registry drops
    # observations stamped in its future, and QEMU machines disagree by
    # sub-second boot offsets — enough to drop a whole reporter stream
    # (observedAt is a float). The registry host is therefore pinned
    # five seconds ahead of the worker hosts, which keeps every
    # observation marginally in its past and far inside the 30s
    # freshness window.
    epoch = int(time.time())
    control.succeed("date -s '@" + str(epoch + 5) + "'")
    for node in (source, target, repository):
        node.succeed("date -s '@" + str(epoch) + "'")
    revision = json.loads(
        Path("${canary.bundle}/definition.json")
        .read_text())["revisionDigest"]
    sentinel_revision = json.loads(
        Path("${sentinel.bundle}/definition.json")
        .read_text())["revisionDigest"]

    for node in (source, target, control, repository):
        node.wait_for_unit("multi-user.target")
    for node in (source, target):
        node.succeed("systemctl start nix-daemon.socket")
        node.succeed("test -S /nix/var/nix/daemon-socket/socket")

    with subtest("runtime PKI issued per identity"):
        control.succeed("mkdir -p /run/lab-pki /tmp/shared/pki")
        control.succeed("chmod 700 /run/lab-pki")
        control.succeed("openssl ecparam -genkey -name prime256v1"
                        " -out /run/lab-pki/ca.key")
        control.succeed("openssl req -x509 -new -key /run/lab-pki/ca.key"
                        " -days 1 -subj '/CN=Nexus Lab CA'"
                        " -addext 'basicConstraints=critical,CA:TRUE'"
                        " -addext 'keyUsage=critical,keyCertSign,cRLSign'"
                        " -out /run/lab-pki/ca.crt")
        control.succeed("cp /run/lab-pki/ca.crt /tmp/shared/pki/ca.crt")
        for node in (source, target):
            node.succeed("mkdir -p /run/lab-pki"
                         " && chmod 700 /run/lab-pki")
            node.succeed("cp /tmp/shared/pki/ca.crt /run/lab-pki/ca.crt")
        issue(control, "registry", "nexus-registry",
              "DNS:control", "serverAuth")
        issue(control, "controller", "ops",
              "URI:urn:nexus:controller:ops", "clientAuth")
        issue(source, "host-a", "host-a",
              "URI:urn:nexus:host:host-a", "clientAuth")
        issue(target, "host-b", "host-b",
              "URI:urn:nexus:host:host-b", "clientAuth")
        source.fail("test -f /run/lab-pki/host-b.key")
        target.fail("test -f /run/lab-pki/host-a.key")
        control.fail("test -f /run/lab-pki/host-a.key")

    with subtest("registry serves authenticated mTLS state"):
        control.succeed("systemctl start nexus-workload-registry")
        control.wait_until_succeeds(
            "curl --fail --silent --max-time 10"
            " --cacert /run/lab-pki/ca.crt"
            " --cert /run/lab-pki/controller.crt"
            " --key /run/lab-pki/controller.key"
            " https://control:9444/v2/state", timeout=90)
        rc, _ = control.execute(
            "curl --silent --cacert /run/lab-pki/ca.crt --max-time 10"
            " https://control:9444/v2/state")
        assert rc != 0, "client-less TLS must fail"
        rc, _ = control.execute(
            "curl --silent --max-time 10 http://control:9444/v2/state")
        assert rc != 0, "plaintext fallback must not exist"

    with subtest("repository host runs SFTP-only backup account"):
        assert repository.succeed("hostname").strip() == "repository"
        repository.succeed("test -d /srv/repos/canary")
        repository.succeed(
            "stat -c '%U %a' /srv/repos/canary | grep -qx 'backup 700'")

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
            + " && chown backup:backup"
            + " /var/lib/backup/.ssh/authorized_keys"
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

    with subtest("local encrypted cache and staged admin configs"):
        # The backup cache is a second, independent encrypted
        # repository on the source with a different runtime password.
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
        # Every config reaches the components through a root-owned
        # runtime path; the module pins the worker config the store
        # generated for this exact host.
        for node in (source, target):
            worker_config = node.succeed(
                "cat /etc/nexus-worker-config-path").strip()
            node.succeed("install -D -m 0600 " + worker_config
                         + " " + WORKER_CONFIG)
        backup_config = {
            "schemaVersion": 1,
            "stateDir": "/var/lib/nexus-backup",
            "workerConfigFile": WORKER_CONFIG,
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
        restore_config = {
            "schemaVersion": 1,
            "stateDir": "/var/lib/nexus-restore",
            "workerConfigFile": WORKER_CONFIG,
            "repositories": [client_config],
        }
        source.succeed(
            "printf %s " + shlex.quote(json.dumps(backup_config))
            + " > " + BACKUP_CONFIG + " && chmod 600 " + BACKUP_CONFIG)
        target.succeed(
            "printf %s " + shlex.quote(json.dumps(restore_config))
            + " > " + RESTORE_CONFIG + " && chmod 600 " + RESTORE_CONFIG)

    with subtest("placements seeded and canary runs on the source"):
        status, payload = api(
            control, "controller", "POST", "/v2/placements/assign",
            assign_request(INSTANCE_A, "host-a", "canary", revision, 0,
                           "01" * 16))
        assert status == 200 and payload["generation"] == 1, payload
        status, payload = api(
            control, "controller", "POST", "/v2/placements/assign",
            assign_request(INSTANCE_S, "host-b", "sentinel",
                           sentinel_revision, 0, "02" * 16))
        assert status == 200 and payload["generation"] == 1, payload
        for node, uuid in (
                (source, "11111111-2222-3333-4444-555555555555"),
                (target, "66666666-7777-4888-8999-aaaaaaaaaaaa")):
            node.succeed("mkfs.ext4 -q -U " + uuid + " /dev/vdc")
            node.wait_until_succeeds(
                "test -b /dev/disk/by-uuid/" + uuid, timeout=30)
            node.succeed("mkdir -p /srv/workloads")
            node.succeed("mount /dev/disk/by-uuid/" + uuid
                         + " /srv/workloads")
        host_op(source, "aa" * 16, "prepare", "canary", revision,
                INSTANCE_A, 1)
        host_op(source, "ab" * 16, "start", "canary", revision,
                INSTANCE_A, 1)
        source.wait_until_succeeds(
            "curl --fail --silent --max-time 10"
            " http://192.168.130.2:8080/", timeout=120)
        host_op(target, "ba" * 16, "prepare", "sentinel",
                sentinel_revision, INSTANCE_S, 1)
        host_op(target, "bb" * 16, "start", "sentinel",
                sentinel_revision, INSTANCE_S, 1)
        target.wait_until_succeeds(
            "curl --fail --silent --max-time 10"
            " http://192.168.140.2:8080/", timeout=120)
        # The marker is written BEFORE the freeze so the restored
        # bytes prove the pre-capture state crossed hosts.
        source.succeed("curl --fail --silent -X PUT --data-binary "
                       + MARKER + " http://192.168.130.2:8080/")
        guest = json.loads(source.succeed(
            "curl --fail --silent http://192.168.130.2:8080/"))
        assert guest["value"] == MARKER, guest
        assert guest["uid_map"] == ["0", "65536", "65536"], guest

    with subtest("reporters open sessions and post fresh evidence"):
        registry_cfg = json.loads(control.succeed(
            "cat /etc/nexus-registry-config.json"))
        # Sanity probe: a host-scoped session + observation is a real
        # registry contract; the response asserts the clock discipline
        # above landed (an 'observation-future' here means the fleet
        # clocks disagree). The persistent reporters open their own
        # session afterwards and supersede this one.
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
                 "retired": False, "endpointAddress": "192.168.130.2",
                 "readyServices": ["web"]}
        status, body = api(
            source, "host-a", "POST", "/v2/observations", probe)
        assert status == 200 and body["status"] == "accepted", body
        # The reporters run the shipped unit as installed: the module
        # baked the backup/restore program+config pairs into its own
        # pinned config, so nothing is staged per-host here — the
        # units were only held dormant until the host certificates
        # existed.
        for node in (source, target):
            node.succeed("systemctl start nexus-workload-reporter")
        deadline = time.time() + 180
        while True:
            row = workload_row("canary")
            srow = workload_row("sentinel")
            canary_fresh = (
                row is not None and row["instanceId"] == INSTANCE_A
                and row["hostId"] == "host-a"
                and row["observedState"] == "running"
                and row["observation"] is not None
                and "web" in row["observation"]["readyServices"])
            sentinel_fresh = (
                srow is not None and srow["instanceId"] == INSTANCE_S
                and srow["hostId"] == "host-b"
                and srow["observation"] is not None
                and srow["observedState"] not in ("stale", "lost"))
            if canary_fresh and sentinel_fresh:
                break
            assert time.time() < deadline, \
                "fresh reporter evidence never arrived: " \
                + json.dumps({"canary": row, "sentinel": srow})
            time.sleep(2)

    with subtest("generation 1 publication exposes the source backend"):
        status, payload = api(
            control, "controller", "POST", "/v2/placements/publish",
            {"schemaVersion": 2, "requestId": "03" * 16,
             "workloadId": "canary", "expectedGeneration": 1})
        assert status == 200, payload
        status, body = api(
            control, "controller", "GET", "/v2/routes",
            headers=["X-Nexus-Nonce: " + "04" * 16])
        assert status == 200, body
        backends = {r["id"]: r["backend"] for r in body["routes"]}
        backend = backends["route-web"]
        assert backend["address"] == "192.168.130.2", backend
        assert backend["generation"] == 1, backend
        assert backend["hostId"] == "host-a", backend

    with subtest("controller staged on control with its own identity"):
        backup_program = control.succeed(
            "readlink -f /run/current-system/sw/bin/nexus-backup").strip()
        restore_program = control.succeed(
            "readlink -f /run/current-system/sw/bin/nexus-restore").strip()
        # A real but uninvolved worker binding for the control hostId:
        # the controller embeds a Worker only for local steps, and no
        # step is ever local to this node.
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
            "approvedBundles": ["${canary.bundle}", "${sentinel.bundle}"],
            "slots": [{"id": "idle", "uidBase": 393216,
                       "hostAddress": "10.66.0.1",
                       "localAddress": "10.66.0.2"}],
        }
        control.succeed(
            "printf %s " + shlex.quote(json.dumps(control_worker))
            + " > /run/control-worker-config.json"
            + " && chmod 600 /run/control-worker-config.json")
        controller_config = {
            "schemaVersion": 1, "hostId": "control",
            "stateDir": "/var/lib/nexus-controller",
            "workerConfigFile": "/run/control-worker-config.json",
            "registryUrl": REGISTRY, "registry": registry_cfg,
            "backupProgram": backup_program,
            "backupConfigFile": BACKUP_CONFIG,
            "restoreProgram": restore_program,
            "restoreConfigFile": RESTORE_CONFIG,
            "requestTimeoutSeconds": 15,
        }
        control.succeed(
            "printf %s " + shlex.quote(json.dumps(controller_config))
            + " > " + CONTROLLER_CONFIG
            + " && chmod 600 " + CONTROLLER_CONFIG)
        control.succeed("install -d -m 0700 /run/controller-creds")
        control.succeed("install -m 0400 /run/lab-pki/ca.crt"
                        " /run/controller-creds/ca")
        control.succeed("install -m 0400 /run/lab-pki/controller.crt"
                        " /run/controller-creds/cert")
        control.succeed("install -m 0400 /run/lab-pki/controller.key"
                        " /run/controller-creds/key")

    plan_request = {
        "schemaVersion": 1, "action": "plan", "operationId": MOVE_OP,
        "workloadId": "canary", "revisionDigest": revision,
        "fromInstanceId": INSTANCE_A, "toHostId": "host-b",
        "toSlotId": None, "repositoryId": "repo-a",
    }

    with subtest("plan journals every step as remote"):
        rc, result = controller(plan_request)
        assert rc == 0 and result["status"] == "completed", result
        operation = result["operation"]
        assert operation["phase"] == "planned", operation
        assert operation["fromHostId"] == "host-a", operation
        assert operation["toHostId"] == "host-b", operation
        assert operation["generation"] == 1, operation
        assert operation["newGeneration"] == 2, operation
        steps = {entry["step"]: entry["disposition"]
                 for entry in operation["plan"]["steps"]}
        assert steps == DISPOSITIONS, steps
        new_instance = operation["newInstanceId"]
        capture_id = operation["captureId"]
        restore_id = operation["restoreId"]

    with subtest("execute walks every remote step to completion"):
        # A deferred status is the designed pacing boundary: the
        # controller re-posts nothing destructive, it just re-reads
        # the durable queue. Blocked is a real failure and fails here.
        deadline = time.time() + 420
        last = None
        while True:
            rc, result = controller(
                {"schemaVersion": 1, "action": "execute",
                 "operationId": MOVE_OP})
            assert rc == 0 and result["status"] in (
                "completed", "deferred"), result
            last = result
            if result["status"] == "completed":
                break
            operation = result["operation"]
            pending = [c for c in operation["checkpoints"]
                       if c["state"] != "completed"]
            assert pending, result
            assert time.time() < deadline, \
                "move did not converge: " + json.dumps(operation)
            time.sleep(3)
        operation = last["operation"]
        assert operation["phase"] == "completed", operation
        checkpoints = operation["checkpoints"]
        assert [c["step"] for c in checkpoints] == STEP_ORDER, \
            checkpoints
        assert [c["state"] for c in checkpoints] == \
            ["completed"] * len(STEP_ORDER), checkpoints
        assert [c["at"] for c in checkpoints] == \
            sorted(c["at"] for c in checkpoints), checkpoints
        # Checkpoints for the remote worker steps carry the queue
        # operationId; retire-source and install-target journal a
        # summary detail instead — their dispatch is proven by the
        # durable /v2/operations receipts asserted below.
        remote = {c["step"]: c["detail"]
                  for c in checkpoints
                  if type(c.get("detail")) is dict
                  and c["detail"].get("disposition") == "remote"}
        for step in ("freeze", "capture", "thaw"):
            assert remote[step]["operationId"], (step, remote)
        assert remote["freeze"]["operationId"] == derive("freeze")
        assert remote["capture"]["operationId"] \
            == derive("op:capture")
        assert remote["install-target"]["slotId"] == "second", remote
        assert operation["snapshotId"] is not None, operation
        assert operation["toSlotId"] == "second", operation

    with subtest("every remote operation receipt is durably recorded"):
        hosts = {"freeze": "host-a", "capture": "host-a",
                 "thaw": "host-a", "retire": "host-a",
                 "prepare": "host-b", "observe": "host-b",
                 "restore-stage": "host-b", "restore-commit": "host-b",
                 "start": "host-b"}
        for step, op_label, post_label in REMOTE_OPS:
            status, view = api(
                control, "controller", "GET",
                "/v2/operations/" + derive(op_label)
                + "?requestId=" + derive("post:" + post_label))
            assert status == 200 and view["status"] == "completed", \
                (step, view)
            assert view["workloadId"] == "canary", view
            assert view["step"] == step, view
            assert view["hostId"] == hosts[step], (step, view)
            assert view["operationId"] == derive(op_label), view
            assert view["requestId"] == derive("post:" + post_label), view
            # Source steps were posted against generation 1, the
            # target install steps against generation 2 — the queue
            # binds each op to the placement generation at post time.
            assert view["generation"] == \
                (1 if hosts[step] == "host-a" else 2), view

    with subtest("source instance is retired and drained"):
        rc, observed = worker(
            source, {"schemaVersion": 1, "action": "observe",
                     "instanceId": INSTANCE_A})
        assert observed["retired"] is True, observed
        assert observed["phase"] == "stopped", observed
        assert observed["unitDrained"] is True, observed
        unit = "nexus-workload@" + observed["machineName"] + ".service"
        assert source.succeed(
            "systemctl show " + unit
            + " --property=ActiveState --value").strip() != "active"
        # A retired instance can never start again.
        rc, result = worker(
            source, {"schemaVersion": 1,
                     "operationId": "ac" * 16,
                     "action": "start", "workloadId": "canary",
                     "revisionDigest": revision,
                     "instanceId": INSTANCE_A, "generation": 1})
        assert result["status"] == "failed" \
            and result["error"] == "instance-retired", result

    with subtest("target serves the captured marker bytes"):
        guest = json.loads(target.succeed(
            "curl --fail --silent --max-time 10"
            " http://192.168.141.2:8080/"))
        assert guest["value"] == MARKER, guest
        assert guest["hostname"] == "canary", guest
        assert guest["uid_map"] == ["0", "327680", "65536"], guest

    with subtest("route and publication flip to the target backend"):
        deadline = time.time() + 60
        while True:
            status, body = api(
                control, "controller", "GET", "/v2/routes",
                headers=["X-Nexus-Nonce: " + "05" * 16])
            assert status == 200, body
            backend = {r["id"]: r["backend"]
                       for r in body["routes"]}["route-web"]
            if backend is not None \
                    and backend["address"] == "192.168.141.2":
                break
            assert time.time() < deadline, \
                "route never flipped: " + json.dumps(body)
            time.sleep(2)
        assert backend["generation"] == 2, backend
        assert backend["hostId"] == "host-b", backend
        assert backend["instanceId"] == new_instance, backend
        row = workload_row("canary")
        assert row["generation"] == 2, row
        assert row["instanceId"] == new_instance, row
        assert row["hostId"] == "host-b", row
        assert row["published"] is True, row
        assert row["observedState"] == "running", row

    with subtest("replay of the same operationId is identical"):
        rc, replay_plan = controller(plan_request)
        assert rc == 0 and replay_plan["status"] == "completed", \
            replay_plan
        rc, replay_exec = controller(
            {"schemaVersion": 1, "action": "execute",
             "operationId": MOVE_OP})
        assert rc == 0 and replay_exec["status"] == "completed", \
            replay_exec
        assert replay_exec["operation"] == operation, (
            replay_exec["operation"], operation)
        # And no duplicate side effects: the queue still holds one
        # operation per dispatched step.
        status, view = api(
            control, "controller", "GET",
            "/v2/operations/" + derive("start")
            + "?requestId=" + derive("post:start"))
        assert status == 200 and view["status"] == "completed", view

    with subtest("stale generation and stale instance are refused"):
        # A raw dispatch op pinned to the pre-move generation is
        # rejected at the registry before any host sees it.
        status, payload = api(
            control, "controller", "POST", "/v2/operations",
            {"schemaVersion": 2, "requestId": "06" * 16,
             "operationId": "07" * 16, "workloadId": "canary",
             "hostId": "host-a", "generation": 1, "step": "observe",
             "payload": {"schemaVersion": 1, "action": "observe",
                         "instanceId": INSTANCE_A}})
        assert status == 409 \
            and payload["error"] == "generation-conflict", payload
        # The refused operation never entered the queue.
        status, payload = api(
            control, "controller", "GET",
            "/v2/operations/" + "07" * 16
            + "?requestId=" + "06" * 16)
        assert status == 404 \
            and payload["error"] == "unknown-operation", payload
        # A fresh controller plan against the retired source instance
        # mismatches the registry's current placement.
        rc, result = controller(
            dict(plan_request, operationId="08" * 16))
        assert rc != 0 and result["status"] == "blocked", result
        assert result["error"] == "instance-mismatch", result
        # A stale-generation publish is refused too.
        status, payload = api(
            control, "controller", "POST", "/v2/placements/publish",
            {"schemaVersion": 2, "requestId": "09" * 16,
             "workloadId": "canary", "expectedGeneration": 1})
        assert status == 409 \
            and payload["error"] == "generation-conflict", payload
        # A host may not read the controller's operation view.
        status, payload = api(
            source, "host-a", "GET",
            "/v2/operations/" + derive("start")
            + "?requestId=" + derive("post:start"))
        assert status == 403, payload
  '';
}
