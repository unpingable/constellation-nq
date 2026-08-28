# SOCKETWRENCH S2 — fresh VM authority lifecycle

Date: 2026-08-28
Campaign: SOCKETWRENCH
Slug: passive-vm-lifecycle-repair-v1

## Classification

PASSIVE-VM-AUTHORITY-LIFECYCLE-NOT-QUALIFIED — FIRST SAMPLE STORE ABSENT

This result is independent of the qualified S0 AF_UNIX repair and S1
enrollment-lifetime fixture repair. It does not qualify recurrence, admission,
activation, succession handoff, fencing, recovery, or multi-VM behavior.

## Source and release custody

- Base source: 675e247e85d8e2e1f2801c06445bf863f82b3a5b
- Repair source: 4e109f889330b876e7c1776b27fcde697ef77f21
- Branch: campaign/passive-vm-lifecycle-repair-v1
- Package SHA-256:
  821c8f7f5dc536c46222c514f9d3b0114efd23a9045bf946d1eb76cd0ddcf0a8
- nq SHA-256:
  686f6928767a9896e359b1b9a6cf054ee4759fd586586977330c54ab32b68f1c
- Passive helper SHA-256:
  901272c1a54ca10e8ba610ce706bc54d455f17602398bc5c13e65b68e4073134

The final driver SHA-256 was
4fec0940eb42482df6baab1f00ee5016c98ef1379caf076fdf96a70ea57305ab.

The disposable guest was Ubuntu 24.04.4 on the verified immutable base
d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30,
with a fresh 20 GiB overlay, two vCPUs, 2 GiB memory, and distinct campaign
identity passive-vm-lifecycle-repair-v1-s2-final.

## Preserved pre-authority refusal

The first fixture attempted H activation before H.not_before. The product
correctly refused the finite interval. Its grant-create receipt stated
authority_created=false. It created no active H authority, child issuance,
admission, activation, timer, attempt, or sample. Its 112 artifacts, overlay,
seed, serial log, and host-key custody remain preserved unchanged.

The same disposable target was reset from the immutable base only while this
pre-authority fact remained exact. Every authority identity, domain, mutable
path, cloud-init instance identity, and sample path was rotated. The corrected
driver waited until H.not_before before activation. No reset or replacement
occurred after authority activation.

## Authority reached

The corrected fixture activated H:

sha256:175da6d75cebc8d164e6d45328688fe069264cdbb49185fa8b5a16be211191fc

It then issued exactly one succession relation, two G children, and two E
children:

- relation:
  sha256:3fee289d565a597a7df122ac534f2c506531d5b414c5cad9bf054d69ca08ddf7
- G1:
  sha256:449c8c7b2bb8a6337e56bcf51e2cec08193ddc1baf2fe6cf36964ea076087d6e
- G2:
  sha256:9f167d35af6b516cdaf1e8049d99104f94a307810eb70ffb371ebb48d1730cdb
- E1:
  sha256:e07cccf06de8523a4c9ed4e797cd8bbe4a9e418bd9d7446cad31e9a84e332b84
- E2:
  sha256:fa79a1740e991f4704ba34af087e5ffa7cbd4519913216e492bc1bb9a97415de

The grant-status aggregate_samples_issued=24 and
aggregate_acquisitions_issued=8 fields are delegated child ceilings. They are
not observed samples or acquisitions.

## Exact refusal and cause

The first observer transition invoked the packaged helper under the intended
observer transient service:

nq-passive-load-helper sample-once-generation
/etc/passive-vm-lifecycle-repair-v1-s2-final/observer-policy.json
/etc/passive-vm-lifecycle-repair-v1-s2-final/g1-generation.json

It refused with status 2:

nq-passive-load-helper: passive-load I/O failed: No such file or directory
(os error 2)

The G1 sample store
/var/lib/nq-passive-load/samples/passive-vm-lifecycle-repair-v1-s2-final/g1
was absent. The helper's first GenerationSession open requires the store
through acquire_observer_lock -> require_sample_store -> symlink_metadata.
Repository fixtures explicitly call make_store before this path. The
SOCKETWRENCH driver created the staging directory but omitted the two sample
store directories.

The refusal is therefore a fixture/deployment construction defect, not a VM
portability law. The helper correctly failed closed; no directory was
implicitly manufactured and no gate was weakened.

## Exact observed counts

- admissions: 0
- activations: 0
- canonical samples: 0
- recurrence attempts: 0
- diagnostic acquisitions: 0
- skipped slots: 0
- successor handoffs: 0
- provider starts: 0
- fencing epochs: 0
- outcome_unknown: 0

The failure happened before the static recurrence service was activated. No
recurrence timer was created or enabled.

## Fail-closed closeout

- H retirement succeeded and final H status is active=false,
  terminal_reason=retired.
- E1 and E2 revocation succeeded.
- Watcher revocation correctly refused because no authoritative admission ever
  existed.
- Observer generation retirement and key-revocation commands returned the same
  ENOENT because no GenerationSession/runtime generation state ever
  materialized.
- The 32-byte generation signing key was removed from its live configured path
  and preserved inside the stopped overlay as mode 000 evidence. Its SHA-256
  is f31e64b7e0017c465dbb888c4e4880669038e995d71f864562fcdb68bcab6161.
- Final matching loaded units and timers were empty.
- The VM was powered off.
- Final qemu-img check passed.
- No replacement VM charter was created after authority activation.

The private-key-excluding terminal archive is
evidence/final-authority-run/terminal-evidence.tar with SHA-256
f7eba691c0aaf2dd8069301353709c02c82042dc5375a19dcc5172106de129bb.
The stopped qcow2 overlay remains the retained custody for the root-only
generation key and exact terminal filesystem.
