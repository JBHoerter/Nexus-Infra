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

## Internal workload catalog contract

`catalog.py` defines the internal `schemaVersion: 2` workload-definition contract used for catalog and admission work. `seal_definition` computes a canonical JSON `sha256` revision digest over a caller-supplied definition that must not already carry one; `validate_definition` strictly checks every field and verifies the digest; `Catalog` stores canonical JSON bytes, rejects duplicate workload IDs, unknown dependencies and dependency cycles, and answers exact `(workloadId, revisionDigest)` lookups with detached copies; `admit` is a pure preflight returning an eligible flag plus an ordered reason list — it performs no scheduling, reservation, health check or fencing.

The contract is deliberately narrow: `nspawn-v1` runtime only (archived metadata records carry a null runtime and are never executable), artifact records are `id`/`kind`/`digest` references without presence or signature verification, state mount points are internal guest paths with reserved roots and overlap rejection, `quiesce-v1` is the only consistency adapter, and the contract accepts no secret-value fields — only secret-set references; operators must not put secrets in metadata. Digest equality proves content consistency, not authority. There is no v2 HTTP endpoint; the existing v1 API is unchanged.

`artifacts.py` compiles a Nix `exportReferencesGraph` closure record into a workload bundle: `build_manifest` selects `path`/`narHash`/`narSize`/`references` into a canonical, path-sorted manifest, `validate_manifest` strictly checks shape, store-path syntax, NAR-hash encodings, reference integrity and root reachability (self-references and cycles are legal), and `seal_workload` inserts the manifest digest as the `runtimeArtifactId` entry into a draft definition before `seal_definition` validates it. The digest covers exact canonical manifest bytes. The `build` CLI writes `artifact.json`, `artifact.sha256` and `definition.json` inside a Nix derivation; it verifies nothing about signatures, distribution or recovery.

`worker.py` is an experimental root-only local worker (not part of the console or agent): `nexus-worker execute` consumes a strict bounded JSON request from stdin and `nexus-worker guard` serves as the `nexus-workload@` unit `ExecCondition`. The immutable Nix-generated config pins approved store bundles, capacity ceilings and slot UID/address bindings; `prepare`/`start`/`stop` journal durable pending-then-terminal receipts in a root-owned SQLite database, re-verify the store closure against the artifact manifest through the local Nix daemon store, enforce the dedicated-storage mount UUID, gate starts through single-use boot-scoped permits, and admit only within measured capacity minus reservations (conservative — live usage may be double-counted; no quotas are enforced). `observe` exposes recorded identity and unit state only — never readiness, recoverability or fencing claims. There is no RPC server, HTTP endpoint, controller integration, secret handling, or restore/move/backup verb.

Pure contract tests run without Nix, hosts or credentials:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s console -p 'test_catalog.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s console -p 'test_artifacts.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s console -p 'test_worker.py' -v
```
