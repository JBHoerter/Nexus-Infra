# Workload recovery-point manifests

`console/recovery.py` defines the **immutable recovery-point manifest** —
the sealed metadata record produced at capture time that binds a workload's
sealed definition, its capture provenance, and the content identity of each
state root. It is the contract a future restic engine, lifecycle planner
and restore controller validate against. The module performs no backup and
asserts nothing about repository location, snapshot identity, availability
or recoverability — those are deliberately separate records established by
future authorized transport and evidence.

## Record shape

```json
{
  "schemaVersion": 3,
  "kind": "workload-recovery-point",
  "recoveryPointId": "sha256:<64 lowercase hex>",
  "definition": { "...": "<complete sealed catalog definition>" },
  "source": {
    "hostId": "host-a",
    "instanceId": "<32 lowercase hex>",
    "generation": 1,
    "uidBase": 65536
  },
  "capture": {
    "adapter": "quiesce-v1",
    "consistency": "quiesced",
    "startedAt": 1000,
    "completedAt": 1005
  },
  "stateFormat": "restic-posix-v2",
  "state": [
    { "id": "data", "path": "state/data",
      "treeDigest": "sha256:<64 lowercase hex>" }
  ],
  "stateSetDigest": "sha256:<64 lowercase hex>",
  "secretBundle": null
}
```

Every object admits exactly these fields — extensions (repository IDs,
restic snapshot IDs, copy/integrity/restore evidence, availability or
recoverable flags) are rejected by design. Snapshot IDs only exist after
upload; embedding one would make the digest self-referential.

## Identity and provenance

`recoveryPointId` is the SHA-256 of the canonical bytes of the entire
record minus `recoveryPointId` itself. Content hashing binds metadata to
its identifier — it does **not** authenticate its author; trust comes from
the future authorized transport and evidence records.

- `source.instanceId`/`generation` identify which instance incarnation was
  captured; `source.uidBase` is **numeric ownership provenance** — the
  user-namespace base a host used for this instance's filesystem ownership,
  needed to translate restic's numeric UID/GID onto a different target
  namespace. It is not a placement binding or a host path.
- `capture` admits only `quiesce-v1`/`quiesced`: a *claimed* write barrier
  window, not proof of application-level consistency. Recovery-point
  objectives must reckon conservatively from `capture.startedAt`, not from
  upload completion.
- `state` is the exact sorted set of the definition's `stateMounts` IDs —
  nothing omitted, nothing extra, no arbitrary excludes. Under
  `restic-posix-v2`, each `treeDigest` is the SHA-256 of the **raw
  decrypted/uncompressed restic tree blob bytes** for that state root's
  children (restic's native tree ID), and `stateSetDigest` is the same
  digest of the `state` parent node's subtree blob — the tree that carries
  every state root's own metadata (mode, ACLs, xattrs) plus child ids, so
  captures differing only in state-root metadata can no longer alias.
  This module validates only the declared digest references; a future
  engine must derive and verify each tree ID from the selected snapshot
  and emit the manifest with matching data before a point may be
  published as usable.
- **Schema 2 / `restic-posix-v1` records remain readable** for catalog
  reconstruction and manual full-snapshot-id restores — old points are
  never upgraded in place — but they carry no `stateSetDigest` and do not
  bind state-root metadata. They need a native parent-tree comparison
  before reuse and are not sufficient for automatic installation.
- `secretBundle` is present exactly when the definition declares a
  `secretSetRef`, and then carries only `{secretSetRef, versionDigest,
  bundleDigest}` — encrypted-bundle/version references, never key material
  and no recoverability claim.

## Canonical encoding

`encode_manifest`/`decode_manifest` round-trip strict canonical UTF-8:
sorted keys, compact separators, ≤ 2 MiB, duplicate keys and non-finite
constants rejected, byte-exact re-encode required — whitespace, key order
or alternate escapes all fail.

## In-memory reconstruction

`catalog_from_manifests(records)` rebuilds a deterministic catalog view
from supplied manifests alone — no live catalog or repository discovery:
every record validated, identical `recoveryPointId`s deduplicated
(conflicting same-identity bodies rejected defensively), sorted by
`(workloadId, capture.startedAt, recoveryPointId)`. Because the tree
digests sit inside the sealed body, two captures with identical metadata
but different content are distinct points and both survive
reconstruction.

## What this is not

No backup is executed. No `available`, `recoverable`, `green` or
`event-ready` field exists. The manifest says *what a point claims to
contain and where it came from* — whether the claimed tree blobs exist,
are intact and are usable for restore is evidence the future engine and
lifecycle layers must establish separately.
