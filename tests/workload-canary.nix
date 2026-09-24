{ nixpkgs }:
let
  buildWorkload = import ../workload-modules/build.nix { inherit nixpkgs; };
  handler = ''
    import json
    import os
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_PUT(self):
            length = min(int(self.headers.get('Content-Length') or 0), 1024)
            body = self.rfile.read(length)
            with open('/state/value', 'wb') as handle:
                handle.write(body)
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            value = ""
            if os.path.exists('/state/value'):
                with open('/state/value', 'rb') as handle:
                    value = handle.read().decode('utf-8')
            payload = {
                'value': value,
                'hostname': os.uname().nodename,
                'uid_map': open('/proc/self/uid_map').read().split(),
                'netns': os.readlink('/proc/1/ns/net'),
                'host_socket': os.path.exists('/nix/var/nix/daemon-socket/socket'),
            }
            body = json.dumps(payload).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
  '';
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
      memoryMiB = 256;
      cpuMillis = 100;
      stateBytes = 1048576;
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
            ExecStart = "${pkgs.python3}/bin/python3 ${pkgs.writeText "canary-handler.py" handler}";
            Restart = "on-failure";
          };
        };
      })
    ];
  };
in canary
