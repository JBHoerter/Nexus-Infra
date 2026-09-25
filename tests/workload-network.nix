# Full-plane VM fixture: workload workers + authenticated registry +
# Traefik ingress behind a per-request expiry guard, with backend
# traffic carried over a lab Headscale/Tailscale overlay.
#
# This exercises endpoint placement and graceful host-connected
# ownership change through the real services; it is not the worker
# power-loss/retirement proof (tests/workload-worker.nix) and not
# production authorization.
{ nixpkgs }:
let
  canary = import ./workload-canary.nix { inherit nixpkgs; };
  hostNode = args:
    import ./workload-worker-host.nix ({ inherit canary; } // args);
  definition = builtins.fromJSON
    (builtins.readFile "${canary.bundle}/definition.json");
  registryConfig = {
    schemaVersion = 2;
    definitions = [ definition ];
    hosts = [
      { hostId = "host-a"; architecture = "x86_64-linux";
        addresses = [ "192.168.130.2" ]; }
      { hostId = "host-b"; architecture = "x86_64-linux";
        addresses = [ "192.168.140.2" ]; }
    ];
    routes = [
      { id = "route-web"; workloadId = "canary"; serviceId = "web";
        hostname = "canary.internal"; }
    ];
  };
  clients = [
    { identity = "urn:nexus:controller:ops"; role = "controller";
      hostId = null; }
    { identity = "urn:nexus:reader:audit"; role = "reader";
      hostId = null; }
    { identity = "urn:nexus:ingress:edge"; role = "ingress";
      hostId = null; }
    { identity = "urn:nexus:host:host-a"; role = "host";
      hostId = "host-a"; }
    { identity = "urn:nexus:host:host-b"; role = "host";
      hostId = "host-b"; }
  ];
  aclFile = pkgs: pkgs.writeText "nexus-lab-acl.json" (builtins.toJSON {
    tagOwners = { "tag:edge" = [ "lab@" ]; "tag:worker" = [ "lab@" ]; };
    acls = [
      { action = "accept"; src = [ "tag:edge" ];
        dst = [ "192.168.130.2:8080" "192.168.140.2:8080" ]; }
    ];
  });
  overlay = { routing }: { pkgs, lib, ... }: {
    virtualisation.restrictNetwork = true;
    # Driver-assigned lab VLAN address of the control node; registry
    # bootstrap and the Headscale login URL resolve it on every VM.
    networking.hosts."192.168.1.1" = [ "control" ];
    services.tailscale = {
      enable = true;
      useRoutingFeatures = routing;
      openFirewall = true;
      disableUpstreamLogging = true;
    };
    # tailscaled starts only after the runtime lab CA exists on each VM;
    # the testScript starts it explicitly before enrollment.
    systemd.services.tailscaled.wantedBy = lib.mkForce [ ];
    systemd.services.tailscaled.serviceConfig.Environment = [
      "SSL_CERT_FILE=/run/lab-pki/ca.crt"
    ];
    environment.systemPackages = [ pkgs.openssl pkgs.iproute2 ];
  };
in { pkgs, lib, ... }: {
  name = "nexus-workload-network";
  globalTimeout = 20 * 60;
  nodes = {
    source = { ... }: {
      imports = [
        (hostNode {
          hostId = "host-a";
          uuid = "11111111-2222-3333-4444-555555555555";
          slots = [
            { id = "first"; uidBase = 65536;
              hostAddress = "192.168.130.1";
              localAddress = "192.168.130.2"; }
          ];
        })
        (overlay { routing = "both"; })
      ];
    };
    target = { ... }: {
      imports = [
        (hostNode {
          hostId = "host-b";
          uuid = "66666666-7777-4888-8999-aaaaaaaaaaaa";
          slots = [
            { id = "first"; uidBase = 262144;
              hostAddress = "192.168.140.1";
              localAddress = "192.168.140.2"; }
          ];
        })
        (overlay { routing = "both"; })
      ];
    };
    control = { ... }: {
      imports = [
        ../host-modules/workload-registry.nix
        ../host-modules/workload-ingress.nix
        (overlay { routing = "client"; })
      ];
      virtualisation.memorySize = 1024;
      virtualisation.cores = 1;
      networking.firewall.allowedTCPPorts = [ 443 9444 18080 ];
      networking.firewall.allowedUDPPorts = [ 3478 ];
      environment.systemPackages =
        [ pkgs.curl pkgs.jq pkgs.openssl pkgs.iproute2 ];

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
      services.nexus-workload-ingress = {
        enable = true;
        registryUrl = "https://control:9444";
        registry = registryConfig;
        listenPort = 9445;
        caFile = "/run/lab-pki/ca.crt";
        certificateFile = "/run/lab-pki/ingress.crt";
        keyFile = "/run/lab-pki/ingress.key";
      };
      services.traefik.staticConfigOptions.entryPoints.web.address =
        lib.mkForce ":18080";

      services.headscale = {
        enable = true;
        port = 8080;
        settings = {
          server_url = "https://control";
          prefixes = {
            v4 = "100.64.0.0/10";
            v6 = "fd7a:115c:a1e0::/48";
          };
          dns = {
            magic_dns = false;
            base_domain = "";
            override_local_dns = false;
            nameservers = { global = [ ]; split = { }; };
            search_domains = [ ];
            extra_records = [ ];
          };
          derp = {
            server = {
              enabled = true;
              region_id = 999;
              stun_listen_addr = "0.0.0.0:3478";
              verify_clients = true;
              automatically_add_embedded_derp_region = true;
            };
            urls = [ ];
            paths = [ ];
            auto_update_enabled = false;
          };
          policy = { mode = "file"; path = aclFile pkgs; };
          metrics_listen_addr = "127.0.0.1:9090";
          grpc_listen_addr = "127.0.0.1:50443";
        };
      };

      services.nginx = {
        enable = true;
        virtualHosts."control" = {
          onlySSL = true;
          sslCertificate = "/run/credentials/nginx.service/nginx.crt";
          sslCertificateKey = "/run/credentials/nginx.service/nginx.key";
          locations."/" = {
            proxyPass = "http://127.0.0.1:8080";
            proxyWebsockets = true;
          };
        };
      };
      # The nginx unit runs as the unprivileged nginx user; deliver the
      # runtime identity through credentials like the other services.
      systemd.services.nginx.serviceConfig.LoadCredential = [
        "nginx.crt:/run/lab-pki/nginx.crt"
        "nginx.key:/run/lab-pki/nginx.key"
      ];

      # PKI is issued at runtime; services with credential references or
      # certificate reads stay down until the lab CA material exists.
      systemd.services.nexus-workload-registry.wantedBy = lib.mkForce [ ];
      systemd.services.nexus-workload-ingress.wantedBy = lib.mkForce [ ];
      systemd.services.traefik.wantedBy = lib.mkForce [ ];
      systemd.services.nginx.wantedBy = lib.mkForce [ ];
    };
  };
  testScript = ''
    import json
    import secrets
    import shlex
    import time
    from pathlib import Path

    INSTANCE_A = "0a" * 16
    INSTANCE_B = "1b" * 16
    REGISTRY = "https://control:9444"
    CA = "SSL_CERT_FILE=/run/lab-pki/ca.crt"

    def worker(node, request):
        rc, output = node.execute(
            "printf %s " + shlex.quote(json.dumps(request))
            + " | nexus-worker execute")
        return rc, json.loads(output)

    def op(node, action, instance, generation):
        req = {"schemaVersion": 1, "operationId": secrets.token_hex(16),
               "action": action, "workloadId": "canary",
               "revisionDigest": revision, "instanceId": instance,
               "generation": generation}
        rc, result = worker(node, req)
        assert rc == 0 and result["status"] == "completed", result
        return result

    def api(node, role, method, path, body=None):
        cmd = ("curl --silent --show-error --max-time 10"
               " --cacert /run/lab-pki/ca.crt --cert /run/lab-pki/"
               + role + ".crt --key /run/lab-pki/" + role
               + ".key -o /tmp/api-response.json -w '%{http_code}' -X "
               + method + " " + REGISTRY + path)
        if body is not None:
            node.succeed("printf %s " + shlex.quote(json.dumps(body))
                         + " > /tmp/api-request.json")
            cmd += (" -H 'Content-Type: application/json'"
                    " --data-binary @/tmp/api-request.json")
        rc, code = node.execute(cmd)
        assert rc == 0, "curl transport failed for " + path
        raw = node.succeed("cat /tmp/api-response.json")
        return int(code.strip()), json.loads(raw)

    def assign_request(instance, host, expected, request_id):
        return {"schemaVersion": 2, "requestId": request_id,
                "workloadId": "canary", "revisionDigest": revision,
                "hostId": host, "instanceId": instance,
                "expectedGeneration": expected}

    def placement_request(generation, request_id):
        return {"schemaVersion": 2, "requestId": request_id,
                "workloadId": "canary", "expectedGeneration": generation}

    def observe(node, instance):
        rc, observed = worker(
            node, {"schemaVersion": 1, "action": "observe",
                   "instanceId": instance})
        assert rc == 0 and observed["bindingCurrent"] is True, observed
        ready = []
        if observed["phase"] == "running" \
                and observed["unitActiveState"] == "active" \
                and observed["unitDrained"] is False \
                and observed["retired"] is False:
            rc, code = node.execute(
                "curl --silent --max-time 5 -o /tmp/guest.json"
                " -w '%{http_code}' http://"
                + observed["endpointAddress"] + ":8080/")
            if rc == 0 and code.strip() == "200":
                guest = json.loads(node.succeed("cat /tmp/guest.json"))
                if guest.get("hostname") == "canary":
                    ready = ["web"]
        return {"schemaVersion": 2, "hostId": observed["hostId"],
                "sessionId": None, "sequence": None,
                "instanceId": observed["instanceId"],
                "workloadId": observed["workloadId"],
                "revisionDigest": observed["revisionDigest"],
                "generation": observed["generation"],
                "observedAt": observed["observedAt"],
                "phase": observed["phase"],
                "unitActiveState": observed["unitActiveState"],
                "unitDrained": observed["unitDrained"],
                "retired": observed["retired"],
                "endpointAddress": observed["endpointAddress"],
                "readyServices": ready}, observed

    sequences = {"host-a": 0, "host-b": 0}

    def open_session(node, host):
        status, payload = api(node, "host-" + host[-1], "POST",
                              "/v2/hosts/session",
                              {"schemaVersion": 2, "hostId": host})
        assert status == 200, payload
        sequences[host] = 0
        return payload["sessionId"]

    def sync_clock(node):
        # Synthetic fixture clock alignment: guests drift under
        # emulation, so the observing worker's wall clock is pinned to
        # control's before each observe(). The observation payload is
        # never rewritten — observedAt stays whatever the real
        # nexus-worker state query reported on that (now-aligned)
        # clock, and the registry's freshness bounds stay intact.
        stamp = control.succeed("date +%s").strip()
        node.succeed("date -s @" + stamp)

    def push_observation(node, host, instance, session,
                         expect=200, error=None):
        sync_clock(node)
        sequences[host] += 1
        body, observed = observe(node, instance)
        body["sessionId"] = session
        body["sequence"] = sequences[host]
        status, payload = api(node, "host-" + host[-1], "POST",
                              "/v2/observations", body)
        assert status == expect, (payload, observed)
        if error is not None:
            assert payload["error"] == error, payload
        return observed

    def app(node):
        rc, code = node.execute(
            "curl --silent --max-time 10 -o /tmp/app-body.json"
            " -w '%{http_code}' -H 'Host: canary.internal'"
            " http://127.0.0.1:18080/")
        if rc != 0:
            return 0, ""
        body = node.succeed("cat /tmp/app-body.json")
        status = int(code.strip()) if code.strip().isdigit() else 0
        return status, body

    def app_status(node):
        return app(node)[0]

    def hs(command):
        return control.succeed("headscale " + command).strip()

    def hs_json(command):
        return json.loads(
            control.succeed("headscale -o json " + command).strip())

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

    def guest(node, address):
        return json.loads(node.succeed(
            "curl --fail --silent --max-time 5 http://" + address
            + ":8080/"))

    def enroll(node, tag, extra=""):
        # The one-time key transits the shared directory as a file;
        # command lines only reference the file, never the value.
        try:
            control.succeed(
                "umask 077; set -o pipefail;"
                " headscale -o json preauthkeys create --user "
                + str(lab_user) + " --tags " + tag
                + " --expiration 10m"
                + " | jq -er '.key | select(type == \"string\""
                + " and length > 0)' > /tmp/shared/tskey")
            node.succeed(
                CA + " tailscale up --login-server https://control"
                + " --auth-key=file:/tmp/shared/tskey"
                + " --accept-dns=false --accept-routes=true"
                + " --timeout=60s " + extra)
        finally:
            control.succeed("rm -f /tmp/shared/tskey")

    def node_id(hostname):
        for item in hs_json("nodes list"):
            if item.get("hostname") == hostname \
                    or item.get("given_name") == hostname \
                    or item.get("name") == hostname:
                return item["id"]
        raise AssertionError("node not enrolled: " + hostname)

    def tailscale_ip(hostname):
        for item in hs_json("nodes list"):
            if item.get("hostname") == hostname \
                    or item.get("given_name") == hostname \
                    or item.get("name") == hostname:
                for address in item.get("ip_addresses", []):
                    if "." in address:
                        return address
        raise AssertionError("no IPv4 tailscale address: " + hostname)

    def direct_ping(node, peer):
        # A freshly enrolled peer can take seconds to appear in the
        # caller's netmap ("no matching peer"); retry bounded while the
        # assertion itself stays unchanged — the final pong line must
        # prove a direct, non-DERP path.
        deadline = time.time() + 120
        last_error = "no ping attempt made"
        while time.time() < deadline:
            rc, out = node.execute(
                CA + " tailscale ping --until-direct=true --c=10"
                + " --timeout=5s " + peer)
            if rc == 0:
                final = [line for line in out.splitlines()
                         if line.strip()]
                if final:
                    last = final[-1]
                    if " via " in last and "via DERP" not in last:
                        return
                    last_error = "no direct pong: " + out
                else:
                    last_error = "empty ping output"
            else:
                last_error = "ping rc=" + str(rc) + ": " + out
            time.sleep(3)
        raise AssertionError(last_error)

    start_all()
    revision = json.loads(
        Path("${canary.bundle}/definition.json")
        .read_text())["revisionDigest"]

    for node in (source, target, control):
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
            node.succeed("mkdir -p /run/lab-pki && chmod 700 /run/lab-pki")
            node.succeed("cp /tmp/shared/pki/ca.crt /run/lab-pki/ca.crt")
        issue(control, "registry", "nexus-registry",
              "DNS:control", "serverAuth")
        issue(control, "nginx", "control", "DNS:control", "serverAuth")
        issue(control, "controller", "ops",
              "URI:urn:nexus:controller:ops", "clientAuth")
        issue(control, "reader", "audit",
              "URI:urn:nexus:reader:audit", "clientAuth")
        issue(control, "ingress", "edge",
              "URI:urn:nexus:ingress:edge", "clientAuth")
        issue(source, "host-a", "host-a",
              "URI:urn:nexus:host:host-a", "clientAuth")
        issue(target, "host-b", "host-b",
              "URI:urn:nexus:host:host-b", "clientAuth")
        source.fail("test -f /run/lab-pki/host-b.key")
        target.fail("test -f /run/lab-pki/host-a.key")
        control.fail("test -f /run/lab-pki/host-a.key")
        # tailscaled is suppressed at boot and only starts once the
        # runtime CA it must trust actually exists.
        for node in (source, target, control):
            node.succeed("systemctl start tailscaled")
            node.wait_for_unit("tailscaled.service")

    with subtest("real units start under credential isolation"):
        for unit in ("nexus-workload-registry",
                     "nexus-workload-ingress", "traefik", "nginx"):
            control.succeed("systemctl start " + unit)
        control.wait_until_succeeds(
            "curl --fail --silent --max-time 10 --cacert /run/lab-pki/ca.crt"
            " --cert /run/lab-pki/reader.crt"
            " --key /run/lab-pki/reader.key"
            " https://control:9444/v2/state", timeout=90)
        users = control.succeed(
            "systemctl show nexus-workload-registry"
            " --property=User --value").strip()
        assert users == "nexus-registry", users
        users = control.succeed(
            "systemctl show nexus-workload-ingress"
            " --property=User --value").strip()
        assert users == "nexus-ingress", users
        control.succeed(
            "test -d /run/credentials/nexus-workload-registry.service")
        control.succeed(
            "test -d /run/credentials/nexus-workload-ingress.service")
        listeners = [line for line in
                     control.succeed("ss -tln").splitlines()
                     if ":9445" in line]
        assert listeners, "guard not listening on 9445"
        for line in listeners:
            assert "127.0.0.1:9445" in line, line
        listeners = control.succeed("ss -tln")
        assert ":9444" in listeners, listeners
        control.wait_until_succeeds(
            "ss -tln | grep -q ':18080'", timeout=90)
        # 503 is the guard's deny; a transient 404 just means Traefik
        # has not applied the provider document yet.
        deadline = time.time() + 60
        status = None
        while status != 503:
            assert time.time() < deadline, \
                "ingress never denied: " + str(status)
            status, _ = app(control)
            if status != 503:
                time.sleep(1)

    with subtest("unauthenticated and wrong-role access rejected"):
        rc, _ = control.execute(
            "curl --silent --cacert /run/lab-pki/ca.crt --max-time 10"
            " https://control:9444/v2/state")
        assert rc != 0, "client-less TLS must fail"
        rc, _ = control.execute(
            "curl --silent --max-time 10 http://control:9444/v2/state")
        assert rc != 0, "plaintext fallback must not exist"
        status, payload = api(
            control, "reader", "POST", "/v2/placements/publish",
            placement_request(1, secrets.token_hex(16)))
        assert status == 403, payload
        session_a = open_session(source, "host-a")
        # Well-formed observation claimed for host-b; role binding must
        # reject it before session/instance checks matter.
        forged = {"schemaVersion": 2, "hostId": "host-b",
                  "sessionId": secrets.token_hex(16), "sequence": 1,
                  "instanceId": INSTANCE_A, "workloadId": "canary",
                  "revisionDigest": revision, "generation": 1,
                  "observedAt": float(
                      control.succeed("date +%s.%N")),
                  "phase": "running",
                  "unitActiveState": "active", "unitDrained": False,
                  "retired": False,
                  "endpointAddress": "192.168.140.2",
                  "readyServices": ["web"]}
        status, payload = api(
            source, "host-a", "POST", "/v2/observations", forged)
        assert status == 403 and payload["error"] == "host-mismatch", \
            payload

    with subtest("lab overlay enrollment and approvals"):
        control.wait_for_unit("headscale.service")
        hs("users create lab")
        users = hs_json("users list")
        matching = [u for u in users if u.get("name") == "lab"]
        assert len(matching) == 1, users
        lab_user = matching[0]["id"]
        enroll(source, "tag:worker",
               "--advertise-routes=192.168.130.2/32")
        enroll(target, "tag:worker",
               "--advertise-routes=192.168.140.2/32")
        enroll(control, "tag:edge")
        hs("nodes approve-routes --identifier "
           + str(node_id("source"))
           + " --routes 192.168.130.2/32")
        hs("nodes approve-routes --identifier "
           + str(node_id("target"))
           + " --routes 192.168.140.2/32")
        source_ts = tailscale_ip("source")
        target_ts = tailscale_ip("target")
        direct_ping(control, source_ts)
        direct_ping(control, target_ts)
        route = control.succeed("ip route get 192.168.130.2")
        assert "tailscale0" in route, route
        route = control.succeed("ip route get 192.168.140.2")
        assert "tailscale0" in route, route

    with subtest("generation 1 placement serves over the overlay"):
        status, payload = api(
            control, "controller", "POST", "/v2/placements/assign",
            assign_request(INSTANCE_A, "host-a", 0,
                           secrets.token_hex(16)))
        assert status == 200 and payload["generation"] == 1, payload
        source.succeed(
            "mkfs.ext4 -q -U"
            " 11111111-2222-3333-4444-555555555555 /dev/vdc")
        source.wait_until_succeeds(
            "test -b /dev/disk/by-uuid/"
            "11111111-2222-3333-4444-555555555555", timeout=30)
        source.succeed("mkdir -p /srv/workloads")
        source.succeed(
            "mount /dev/disk/by-uuid/"
            "11111111-2222-3333-4444-555555555555 /srv/workloads")
        op(source, "prepare", INSTANCE_A, 1)
        op(source, "start", INSTANCE_A, 1)
        source.wait_until_succeeds(
            "curl --fail --silent --max-time 10 http://192.168.130.2:8080/",
            timeout=120)
        source.succeed(
            "curl --fail --silent --max-time 10 -X PUT --data-binary source-marker"
            " http://192.168.130.2:8080/")
        push_observation(source, "host-a", INSTANCE_A, session_a)
        status, payload = api(
            control, "controller", "POST", "/v2/placements/publish",
            placement_request(1, secrets.token_hex(16)))
        assert status == 200, payload
        control.wait_until_succeeds(
            "curl --silent --max-time 10 -o /tmp/app-body.json"
            " -w '%{http_code}' -H 'Host: canary.internal'"
            " http://127.0.0.1:18080/ | grep -q '^200$'", timeout=60)
        status, body = app(control)
        assert status == 200, status
        marker = json.loads(body)
        assert marker["hostname"] == "canary", marker
        assert marker["value"] == "source-marker", marker
        assert marker["uid_map"] == ["0", "65536", "65536"], marker
        direct_ping(control, source_ts)

    with subtest("successor requires retired plus drained evidence"):
        status, payload = api(
            control, "controller", "POST", "/v2/placements/assign",
            assign_request(INSTANCE_B, "host-b", 1,
                           secrets.token_hex(16)))
        assert status == 409 \
            and payload["error"] == "retirement-required", payload
        op(source, "stop", INSTANCE_A, 1)
        push_observation(source, "host-a", INSTANCE_A, session_a)
        status, payload = api(
            control, "controller", "POST", "/v2/placements/assign",
            assign_request(INSTANCE_B, "host-b", 1,
                           secrets.token_hex(16)))
        assert status == 409 \
            and payload["error"] == "retirement-required", payload
        op(source, "retire", INSTANCE_A, 1)
        observed = push_observation(source, "host-a", INSTANCE_A,
                                    session_a)
        assert observed["retired"] is True \
            and observed["unitDrained"] is True, observed
        status, payload = api(
            control, "controller", "POST", "/v2/placements/assign",
            assign_request(INSTANCE_B, "host-b", 1,
                           secrets.token_hex(16)))
        assert status == 200 and payload["generation"] == 2, payload
        unit_a = "nexus-workload@" + observed["machineName"] \
            + ".service"
        source.execute("systemctl start " + unit_a)
        assert source.succeed(
            "systemctl show " + unit_a
            + " --property=ActiveState --value").strip() != "active"
        assert source.succeed(
            "systemctl show " + unit_a
            + " --property=MainPID --value").strip() == "0"
        rc, result = worker(
            source, {"schemaVersion": 1,
                     "operationId": secrets.token_hex(16),
                     "action": "start", "workloadId": "canary",
                     "revisionDigest": revision,
                     "instanceId": INSTANCE_A, "generation": 1})
        assert result["status"] == "failed" \
            and result["error"] == "instance-retired", result
        control.wait_until_succeeds(
            "curl --silent --max-time 10 -o /dev/null"
            " -w '%{http_code}' -H 'Host: canary.internal'"
            " http://127.0.0.1:18080/ | grep -q '^503$'", timeout=60)

    with subtest("generation 2 on target with role isolation"):
        target.succeed(
            "mkfs.ext4 -q -U"
            " 66666666-7777-4888-8999-aaaaaaaaaaaa /dev/vdc")
        target.wait_until_succeeds(
            "test -b /dev/disk/by-uuid/"
            "66666666-7777-4888-8999-aaaaaaaaaaaa", timeout=30)
        target.succeed("mkdir -p /srv/workloads")
        target.succeed(
            "mount /dev/disk/by-uuid/"
            "66666666-7777-4888-8999-aaaaaaaaaaaa /srv/workloads")
        op(target, "prepare", INSTANCE_B, 2)
        op(target, "start", INSTANCE_B, 2)
        target.wait_until_succeeds(
            "curl --fail --silent --max-time 10 http://192.168.140.2:8080/",
            timeout=120)
        target.succeed(
            "curl --fail --silent --max-time 10 -X PUT --data-binary target-marker"
            " http://192.168.140.2:8080/")
        session_b = open_session(target, "host-b")
        push_observation(target, "host-b", INSTANCE_B, session_b)
        status, payload = api(
            control, "reader", "POST", "/v2/placements/publish",
            placement_request(2, secrets.token_hex(16)))
        assert status == 403, payload
        status, payload = api(
            source, "host-a", "POST", "/v2/placements/publish",
            placement_request(2, secrets.token_hex(16)))
        assert status == 403, payload
        status, payload = api(
            control, "controller", "POST", "/v2/placements/publish",
            placement_request(2, secrets.token_hex(16)))
        assert status == 200, payload
        control.wait_until_succeeds(
            "curl --silent --max-time 10 -o /tmp/app-body.json"
            " -w '%{http_code}' -H 'Host: canary.internal'"
            " http://127.0.0.1:18080/ | grep -q '^200$'", timeout=60)
        status, body = app(control)
        assert status == 200, status
        marker = json.loads(body)
        assert marker["value"] == "target-marker", marker
        assert marker["uid_map"] == ["0", "262144", "65536"], marker
        assert marker["hostname"] == "canary", marker
        # Replay and stale-generation mutations are rejected.
        sequences["host-b"] -= 1
        push_observation(
            target, "host-b", INSTANCE_B, session_b, expect=409,
            error="sequence-conflict")
        status, payload = api(
            control, "controller", "POST", "/v2/placements/publish",
            placement_request(1, secrets.token_hex(16)))
        assert status == 409 \
            and payload["error"] == "generation-conflict", payload
        # A peer may not reach the approved backend address itself;
        # only tag:edge is allowed by the lab ACL. Headscale withholds
        # the route from unauthorized peers entirely, so denial is
        # either no route at all or a tailscale0 route whose traffic is
        # dropped — never an underlay route.
        route_rc, route = source.execute("ip route get 192.168.140.2")
        assert route_rc != 0 or "tailscale0" in route, route
        rc, _ = source.execute(
            "curl --silent --max-time 5 http://192.168.140.2:8080/")
        assert rc != 0, "tag:worker must not reach 192.168.140.2:8080"
        control.succeed(
            "curl --fail --silent --max-time 5"
            " http://192.168.140.2:8080/")

    with subtest("coordinator loss keeps established overlay live"):
        # A direct path to the target must already exist so this phase
        # cannot silently pass through a still-working DERP relay.
        direct_ping(control, target_ts)
        push_observation(target, "host-b", INSTANCE_B, session_b)
        status, _ = app(control)
        assert status == 200, status
        control.succeed("systemctl stop headscale")
        push_observation(target, "host-b", INSTANCE_B, session_b)
        status, _ = app(control)
        assert status == 200, status
        control.succeed("systemctl start headscale")
        control.wait_for_unit("headscale.service")

    with subtest("tailscaled loss fails closed then recovers"):
        control.succeed("systemctl stop tailscaled")
        control.wait_until_succeeds(
            "! ip route get 192.168.140.2 | grep -q tailscale0",
            timeout=30)
        status, _ = app(control)
        assert status != 200, status
        control.succeed("systemctl start tailscaled")
        control.wait_until_succeeds(
            "ip route get 192.168.140.2 | grep -q tailscale0",
            timeout=60)
        push_observation(target, "host-b", INSTANCE_B, session_b)
        control.wait_until_succeeds(
            "curl --silent --max-time 10 -o /dev/null"
            " -w '%{http_code}' -H 'Host: canary.internal'"
            " http://127.0.0.1:18080/ | grep -q '^200$'", timeout=60)

    with subtest("registry restart invalidates old sessions"):
        control.succeed("systemctl restart nexus-workload-registry")
        control.wait_until_succeeds(
            "curl --fail --silent --max-time 10 --cacert /run/lab-pki/ca.crt"
            " --cert /run/lab-pki/reader.crt"
            " --key /run/lab-pki/reader.key"
            " https://control:9444/v2/state", timeout=90)
        # Align the worker clock first or future-clock rejection could
        # mask the session error this probe must demonstrate.
        sync_clock(target)
        sequences["host-b"] += 1
        body, _ = observe(target, INSTANCE_B)
        body["sessionId"] = session_b
        body["sequence"] = sequences["host-b"]
        status, payload = api(
            target, "host-b", "POST", "/v2/observations", body)
        assert status == 403 \
            and payload["error"] == "session-mismatch", payload
        control.wait_until_succeeds(
            "curl --silent --max-time 10 -o /dev/null"
            " -w '%{http_code}' -H 'Host: canary.internal'"
            " http://127.0.0.1:18080/ | grep -q '^503$'", timeout=90)
        session_b = open_session(target, "host-b")
        push_observation(target, "host-b", INSTANCE_B, session_b)
        status, payload = api(
            control, "controller", "POST", "/v2/placements/publish",
            placement_request(2, secrets.token_hex(16)))
        assert status == 200, payload
        control.wait_until_succeeds(
            "curl --silent --max-time 10 -o /dev/null"
            " -w '%{http_code}' -H 'Host: canary.internal'"
            " http://127.0.0.1:18080/ | grep -q '^200$'", timeout=60)
        listeners = [line for line in
                     control.succeed("ss -tln").splitlines()
                     if ":9445" in line]
        assert listeners, "guard not listening on 9445"
        for line in listeners:
            assert "127.0.0.1:9445" in line, line
        listeners = control.succeed("ss -tln")
        assert "127.0.0.1:8080" in listeners, listeners
  '';
}
