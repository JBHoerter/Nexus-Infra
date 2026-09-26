# Ingress edge on non-NixOS hosts (Debian + Docker)

`host-modules/workload-ingress.nix` deploys the expiry-enforced route
consumer only on NixOS. This document packages the same consumer for a
plain Debian host — the Hetzner VPS edge (49.12.110.247) or a LAN
ingress host during transition — where Traefik runs under Docker.

## What runs where

| Component | Process | Purpose |
| --- | --- | --- |
| `console/ingress_consumer.py` | systemd unit `nexus-ingress.service` | mTLS poll of `GET /v2/routes` every 2 s; atomic render of the Traefik dynamic document; forwardAuth guard on `127.0.0.1:9445` |
| Traefik | Docker container, `network_mode: host` | file provider watches the rendered document; owns all application traffic |

The consumer is Python-stdlib-only. It reuses `ingress.Ingress` for the
entire security contract — it is not a reimplementation:

- each poll sends a fresh `X-Nexus-Nonce` header and the response must
  echo it;
- snapshots are strictly validated (fields, bounded timestamps, ≤10 s
  validity window, every route/backend re-derived against the
  administrator-pinned `registry` config embedded in `config.json`);
- a version high-water mark persists in `stateDir/version.json` so a
  replayed older snapshot can never restore a route;
- `stateDir/ingress.lock` refuses a second consumer on the same state;
- every rendered router carries a forwardAuth middleware whose token is
  `sha256(registryEpoch + route id + backend identity)` — Traefik
  configuration cached across a guard outage can never route after
  expiry, and an ownership change invalidates previously cached tokens.

Expiry propagates into the file itself: `tick()` re-renders every poll
interval, so when a snapshot ages past `validUntil` — or the registry
stops answering — the next tick rewrites `renderFile` to the deny-all
document (backends repointed at `127.0.0.1:<port>/unavailable`, guard
tokens zeroed). Dead consumer + dead guard both fail closed.

## File layout

```text
/opt/nexus-ingress/                  code set (copied from console/)
  ingress_consumer.py
  ingress.py  registry.py  statefiles.py  worker.py
  catalog.py  artifacts.py  common.py
/etc/nexus-ingress/config.json       consumer config (0640 root:nexus-ingress)
/etc/nexus-ingress/pki/ca.crt        registry CA bundle
/etc/nexus-ingress/pki/ingress.crt   client certificate, ingress role
/etc/nexus-ingress/pki/ingress.key   client key (0600, root only)
/var/lib/nexus-ingress/              stateDir (systemd StateDirectory, 0700)
/srv/nexus-edge/dynamic/nexus.yaml   renderFile consumed by Traefik
```

The emitted document is canonical JSON, which is also valid YAML 1.2 —
the Traefik file provider reads only YAML/TOML, so the file **must**
carry a `.yaml`/`.yml` name. It lands mode 0640 and contains live guard
tokens; the render directory must be owned by the service user with no
group/other write (enforced at startup, `render-path-unsafe`).

```sh
useradd --system --home /nonexistent --shell /usr/sbin/nologin nexus-ingress
install -d -o nexus-ingress -g nexus-ingress -m 0755 /srv/nexus-edge/dynamic
install -d -o root -g nexus-ingress -m 0750 /etc/nexus-ingress/pki
install -o root -g root -m 0755 -t /opt/nexus-ingress \
    console/{ingress_consumer,ingress,registry,statefiles,worker,catalog,artifacts,common}.py
```

`config.json`:

```json
{
  "schemaVersion": 2,
  "registryUrl": "https://192.168.178.192:9444",
  "listenPort": 9445,
  "stateDir": "/var/lib/nexus-ingress",
  "renderFile": "/srv/nexus-edge/dynamic/nexus.yaml",
  "registry": {
    "schemaVersion": 2,
    "definitions": [ "..." ],
    "hosts": [ "..." ],
    "routes": [ "..." ]
  }
}
```

`registry` is the administrator-pinned core config (definitions, hosts,
routes) — the consumer independently re-derives every advertised route
against it, so a malicious registry reply cannot introduce a route the
operator did not preapprove. Two deployment notes:

- `registryUrl` uses an IP literal, so the registry server certificate
  must carry an `IP:192.168.178.192` subjectAltName — the consumer
  requires `check_hostname` + `CERT_REQUIRED` + TLS ≥ 1.2 and refuses
  to start on a weaker context (`insecure-context`).
- The client certificate's URI SAN must be listed in the registry's
  `clients` with `role: "ingress"` (lab convention:
  `urn:nexus:ingress:edge`). Only that role may read `/v2/routes`.

`nexus-ingress.service` — mirrors the NixOS unit; `LoadCredential`
stages the three PEM files into `$CREDENTIALS_DIRECTORY` as `ca`,
`cert`, `key`, exactly as `main()` expects:

```ini
[Unit]
Description=Nexus ingress route consumer (file provider variant)
After=network.target

[Service]
Type=simple
User=nexus-ingress
Group=nexus-ingress
StateDirectory=nexus-ingress
StateDirectoryMode=0700
LoadCredential=ca:/etc/nexus-ingress/pki/ca.crt
LoadCredential=cert:/etc/nexus-ingress/pki/ingress.crt
LoadCredential=key:/etc/nexus-ingress/pki/ingress.key
ExecStart=/usr/bin/python3 /opt/nexus-ingress/ingress_consumer.py \
    --config /etc/nexus-ingress/config.json
UMask=0077
Restart=on-failure
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

## Traefik under Docker

`network_mode: host` is **required**, not optional: the rendered
forwardAuth and `unavailable` URLs point at `127.0.0.1:9445` and the
backend URLs must resolve through the host's `tailscale0` routes.

```yaml
services:
  traefik:
    image: traefik:v3
    network_mode: host
    restart: unless-stopped
    volumes:
      - /srv/nexus-edge/dynamic:/dynamic:ro
      # TLS material for public hostnames, if terminated here:
      # - /etc/traefik/certs:/certs:ro
    command:
      - --entrypoints.web.address=:80
      # - --entrypoints.websecure.address=:443
      - --providers.file.filename=/dynamic/nexus.yaml
      - --providers.file.watch=true
      - --global.checknewversion=false
      - --global.sendanonymoususage=false
```

DNS for each `routes[].hostname` must resolve to 49.12.110.247; public
TLS termination is a Traefik-side concern (certificates file or a
resolver) and does not change the consumer contract. The guard port
9445 must never be exposed beyond loopback — the unit binds
`127.0.0.1` only.

## Overlay reachability — required, and not yet deployed

Rendered backend URLs are `http://<slot address>:<port>` where the
address comes from `registry.hosts[].addresses` — workload slot
addresses (production: 10.90.0.0/16) that live on the workload hosts'
internal bridges. **They are not LAN-routable**: the VPS cannot reach
them via the homeserver's LAN IP, and the registry design gives no
per-edge address override — reachability is the deployment's job.

The lab-proven mechanism (`tests/workload-network.nix`) is a
Headscale/Tailscale overlay in which each worker advertises its slot
addresses as approved /32 subnet routes and the edge node accepts them:

1. **Headscale reachability.** The coordinator runs on the
   network-control microvm at test-host, inside the LAN. The VPS is
   off-LAN, so headscale's configured `server_url` must be reachable
   from 49.12.110.247 — a public DNS name plus router port-forward, or
   another public endpoint fronting it. Verify this first; enrollment
   below assumes it.
2. **Worker side (homeserver).** Each workload host runs `tailscaled`
   and advertises its slot /32s, e.g.
   `tailscale up --login-server https://<headscale> --auth-key=file:... --advertise-tags=tag:worker --advertise-routes=10.90.x.y/32 --accept-dns=false`,
   then `headscale nodes approve-routes --identifier <id> --routes 10.90.x.y/32`.
   A single subnet router on the homeserver advertising the whole slot
   range is an acceptable alternative if per-host enrollment is
   deferred.
3. **VPS side.** Install tailscale (`pkgs.tailscale` tarball or the
   tailscale.com apt repo), then
   `tailscale up --login-server https://<headscale> --auth-key=file:... --advertise-tags=tag:edge --accept-routes=true --accept-dns=false`
   with a one-time tagged pre-auth key issued on the coordinator.
4. **ACL.** Grant `tag:edge` access only to `10.90.0.0/16` on the
   routed service ports — mirroring the lab ACL (`tag:edge` → slot
   addresses; `tag:worker` peers cannot reach each other's slots).
5. **DERP.** Keep headscale's embedded DERP enabled. The VPS has a
   public IP so a direct WireGuard path to it is likely, but the
   NATed homeserver needs DERP fallback when hole-punching fails.
6. **Verify before cutting over:**
   `ip route get 10.90.x.y` must show `dev tailscale0`;
   `tailscale ping <worker>` should reach a direct (non-DERP) pong;
   `curl http://10.90.x.y:<port>/` from the VPS must answer.

Honest current state: production has **not** enrolled any Tailscale
clients or established the cross-host data plane — headscale on
network-control is coordination-only today. Steps 2–4 are new work on
both sides, not only on the VPS. Until the overlay exists, the consumer
renders correct documents and the guard authorizes, but Traefik
blackholes every backend.

## Operations

- Events are single-line JSON on stdout (`rendered`, `poll-error`,
  `tick-error`) — `journalctl -u nexus-ingress`.
- Credential rotation: replace the PEM files under
  `/etc/nexus-ingress/pki/` and `systemctl restart nexus-ingress` —
  `LoadCredential` re-stages them.
- A LAN transition edge can run the identical unit; only `registryUrl`,
  the client identity and the render path differ. Both consumers may
  poll the same registry concurrently — nonces are per request.
- During a full outage the last rendered file stays on disk; Traefik
  keeps it loaded but every route's forwardAuth fails closed, so no
  traffic flows — matching the NixOS module's HTTP-provider behavior.
