# Nexus Console

A lightweight cluster console with separate host agents. Python standard-library services and a static JavaScript/CSS frontend avoid a large dependency stack.

## Architecture

A deployment supplies one inventory record per physical host, generated from the same declarations that create its VMs. The record contains VM identities, resource allocations, roles, network identities, persistent-directory attachments and permitted controls. No credentials belong in these records.

Each unprivileged host agent observes `/proc`, systemd accounting, mounted-filesystem capacity, actual MicroVM units, runner symlinks, interfaces and declared HTTP readiness endpoints. Samples are cached every five seconds. The console polls hosts concurrently with bounded fan-out and serves cached observations to browsers. Known but unavailable hosts remain visible with stale data marked explicitly. Inventory represents the activated deployment, not uncommitted Git edits. Per-VM CPU is measured in core-percent and memory includes the hypervisor's host cgroup overhead.

Agents require client certificates and verified TLS. Host certificate identities are checked, and agent responses must match their configured host ID and schema. A cluster CA can issue separate identities for additional physical hosts; adding them requires inventory, an endpoint and provisioning their certificates. This implements collection/placement visibility, not scheduling or migration.

## API and authority

- Agent: `GET /v1/state`; `POST /v1/vms/{id}/actions` with exactly `{"action":"start|stop|restart"}`.
- Console: `/console/api/v1/session`, `/state`, `/logout`, `/hosts/{host}/vms/{vm}/actions`.
- Host IDs, VM IDs and actions are validated against configuration. There is no shell/file/Nix/SSH endpoint.
- The agent account receives only per-unit start/stop/restart authority through polkit. It has no root account, sudo rule, disk-writing capability or guest-state read permission.
- The console receives only an agent client identity. Its process cannot access the host bus or an SSH key.
- Browser authentication uses a runtime-generated administrator password, a salted scrypt verifier, expiring HttpOnly/SameSite sessions, Host/Origin validation, and a session CSRF token. Login attempts, request sizes, worker counts and action rates are bounded.
- Accepted actions are recorded in the console's persistent SQLite audit log and the host journal. An accepted action is not reported as completed until subsequent live observations change.
- Agent TLS credentials and the console password are generated at runtime, outside Git and the Nix store. Browser transport is selected by the deployment; a plain-HTTP LAN deployment should use an SSH tunnel on an untrusted network.

## Deliberate limits

One administrator, no roles or shared session storage; in-memory sessions expire on service restart. No historical metrics store. Volume attachments share backend capacity; per-directory consumption is not measured. Certificate rotation and host enrollment are manual. No automatic failover, relocation, or configuration editing. Infrastructure VMs can be marked protected to prevent self-disruption.
