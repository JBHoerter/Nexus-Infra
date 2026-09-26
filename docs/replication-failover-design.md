# M7/M8 design — synchronous state protection and fencing

Scope: two application hosts plus the existing control host; the
Antragsbank guarantee is *no acknowledged submissions lost* with brief
automatic recovery on the loss of **one** application host while the
ingress and control plane stay up. Antragsbank keeps state in SQLite,
Chroma files and JSON — there is no application-level replication, so
replication must be at block/filesystem level.

## Selected primitive: DRBD 9, protocol C

- `protocol C` completes a write only after local **and** remote
  persistence; `disk-barrier`/`disk-flushes` forward fsync→FLUSH to the
  peer, so an acked SQLite WAL commit exists on both hosts. This is the
  only candidate that meets the zero-loss bar for an arbitrary POSIX
  workload: ZFS send/recv is point-in-time (lossy by construction),
  lvmlockd/sanlock arbitrate shared LUNs (none exist here — and nixpkgs
  `lvm2` is not built with lvmlockd), and app-level shipping does not
  cover Chroma/JSON.
- Quorum: 2 diskful hosts + the control host as a **diskless**
  tiebreaker (`quorum majority`, `on-no-quorum io-error`). A
  partitioned-but-alive old primary loses quorum and its writes become
  hard I/O errors — write-safety is enforced below the application, not
  by observation.
- One DRBD resource per workload (the failover unit), not per instance
  directory.

## Fencing mapped onto Nexus primitives

- **Write fence:** DRBD quorum (above). A dead or partitioned host
  cannot write.
- **Placement fence:** the existing registry `assign` CAS (monotonic
  generation). New required evidence path: a durable **fence record**
  committed by an authorized attester (the `fence-peer` handler on the
  survivor, or the control host after observing quorum via the
  tiebreaker), accepted by `assign` as an alternative to self-reported
  retired+drained — because a dead host can never report itself.
- **Promotion gate:** survivor promotes only when DRBD reports quorum
  held AND the peer fence record is committed. `fencing
  resource-and-stonith` freezes I/O until the handler returns; fails
  closed — unreachable control plane means outage, not divergence.
- **Self-fence:** `quorum-lost` handler stops `nexus-workload@*` on the
  partitioned host; on reconnect, reporter reconciliation sees the
  superseded generation and forces local retire.
- **Failover controller:** thin Nexus component (promote → adopt →
  assign → publish), not Pacemaker — corosync/pacemaker exist in
  nixpkgs but buy nothing over DRBD quorum here and would need custom
  OCF agents anyway.

## Required deltas

1. `registry.assign`: accept a committed fence record as an alternative
   to retired+drained evidence (new sealed record type + authorization).
2. Worker **state-dir adoption**: `prepare` currently refuses a
   pre-existing instance dir; failover must validate/adopt the
   replicated dir (strict validation — this weakens a deliberate
   invariant). Keep slot `uidBase` symmetric on failover pairs to avoid
   idmap translation on adopt. Provisioned secrets ride inside the
   replicated instance dir (`secrets/` plus the `.nexus-secrets`
   binding marker — outside the declared `stateMount` leaves, so never
   captured by backup), so a replica already carries everything the
   workload needs to start: adoption requires the pair present,
   slot-owned and bound to the local escrow envelope, and never
   reprovisions — an incomplete or foreign replica is rejected rather
   than silently re-seeded.
3. Mount ordering becomes `drbd-primary → mount → unit`
   (`RequiresMountsFor` alone does not promote).
4. Reporter: honor superseded generations by forcing local retire.
5. Deployment: a **cross-host replication link** (LAN or Headscale) —
   none exists today; its partition is the tested failure mode.

## NixOS packaging (pinned nixos-26.05)

- `linuxPackages.drbd` (9.2.x out-of-tree module) + `pkgs.drbd`
  (drbd-utils) exist; `services.drbd` module is incomplete (does not set
  `boot.extraModulePackages`) — plan dedicated Nexus systemd units.
- Verify `meta.broken`/`version` at the exact pinned rev; the module
  previously broke on kernel 6.17 and was fixed at 9.2.16 — pin
  `linuxPackages_6_18`, gate channel bumps on the module building.
- `nixosTests.drbd` exists as a fixture reference.

## Prototype (disposable KVM/TCG VMs)

3-node `runNixOSTest`: source + target (each with a second empty disk as
DRBD backing, ext4 on `/dev/drbd0` at the worker mount — same UUID both
sides) + control (registry/ingress + diskless tiebreaker + fence
endpoint). Assertions: Antragsbank `http-create` loop, `source.crash()`
mid-write, promote+fsck+adopt on target, `integrity_check` + every acked
record byte-identical, partition variant (survivor quorum, loser
io-error + self-fence, route flip, no divergence on heal), RTO
measured crash→first-serve.

## Honest gaps

- Correlated loss (both storage hosts, or storage+control) is out of
  scope; the control host is a failover-decision SPOF.
- The guarantee holds only if the application fsyncs before acking —
  Antragsbank durability (SQLite synchronous mode, Chroma) is an audit
  item, and virtio/caches must honor FLUSH.
- The losing partition of a split can't serve (io-error) — safe, but
  that workload is down on the loser.
- A live partitioned old host can serve stale *reads* until the route
  flips and it self-fences.
- DRBD faithfully replicates corruption — restic points remain the
  separate DR/corruption tier.
