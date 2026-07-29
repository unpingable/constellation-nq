# NQ custody arena v1

Status: Campaign 3B storage-format precursor. This record narrows the
implementation required by the already-ratified custody invariant. It does not
authorize deployment, recurrence, action, or a change to the diagnostic
contract.

The physical implementation remains store-private. The schema-v7 host-role
runtime now reserves and claims arenas during governed prelaunch and performs
a bounded, read-only startup inventory. That inventory classifies exact
physical frontiers and keeps unreadable entries visible; it does not resume an
invocation, synthesize a failure, or establish a diagnostic result. No
arena/index projection, backup/archive integration, or cycle-free NQ-core
validation bridge is claimed.

## Reason

An SQLite `zeroblob` in the main database does not reserve the space needed by
a later WAL transaction. Releasing that blob and inserting a same-sized
payload can leave the main database unchanged while allocating a new WAL.
Consequently the provisional same-database reservation cannot justify provider
launch under real store pressure.

The selected storage-format precursor is therefore a store-owned, preallocated
Linux file. In the intended product design SQLite becomes an
integrity-checked, bound, rebuildable index over that custody; it cannot be the
only copy of bytes required to retain a governed execution.

The implemented arena-local digests and alternating headers detect torn writes
and accidental local corruption. Future SQLite joins must additionally detect
incoherent substitution or rollback between the retained arena and index. Even
then, neither representation authenticates itself against a malicious
administrator or detects coordinated rollback without an independently
retained checkpoint root. This format establishes no external authentication
or anti-rollback root by itself.

## Store shape

For database `PATH`, the arena root is the sibling directory
`PATH.nq-custody-v1/`. Each governed reservation owns exactly one immutable
arena identity and one file named from its exact reservation digest. Future
index integration must commit the relative path, format identity, allocated
length, and exact reservation identity in SQLite with the prelaunch
checkpoint. It must add the launch identity only through the later claim
transaction. Schema v6 contains none of these index rows today.

Every arena and prelaunch-reserve handle acquires a nonblocking exclusive
Linux `flock` before reading or mutating retained state and holds it for the
handle lifetime. A second conforming process or independently opened handle
refuses until the first handle is dropped. This is advisory writer exclusion,
not protection against an administrator or program that ignores the lock, and
not an external authenticity or anti-rollback mechanism.

Before a future NQ product path receives a launch capability, the integrated
store must:

1. create the arena root and reservation file with restrictive permissions;
2. allocate the complete file with `posix_fallocate`;
3. write and sync a valid initial superblock;
4. sync the file and containing directory;
5. commit the request/decision/reservation prelaunch ledger, arena identity,
   and reservation index;
6. reopen and verify the exact arena identity before returning the capability.

Failure at any step must return no capability. A crash-created file without a
committed reservation must remain an orphan, never evidence of a launch. The
current private precursor issues no product launch capability.

Two alternating fixed-size superblocks carry a monotonic arena sequence, the
exact reservation manifest, request, prelaunch checkpoint, and launch
identities, partition bounds, the current state, and the digests and lengths of
sealed sections. Each superblock has an independent digest. Reopen accepts
exact equal copies or one exact legal successor and selects the newer copy.
Equal-sequence disagreement, a sequence gap, or an illegal successor is
split-brain/corruption. One damaged or partial copy is a detected torn-write
recovery; two invalid copies are arena corruption.

Section frames independently bind kind, length, and SHA-256 digest. A frame
written before its referencing superblock is durable scratch, not state
advancement. Reopen follows the selected superblock and ignores unreferenced
scratch. A future restart adjudicator may report and clear it, but cannot promote it
into evidence or a disposition merely because its local frame is valid.

The file is preallocated for:

- fixed format and section-frame overhead;
- the exact raw-evidence bound;
- the exact final-closure bound;
- the exact protected-failure bound.

Future integration must obtain the semantic component bounds from the admitted
`nq.custody_reservation.v1` record. The private constructor currently receives
explicit bounds directly. Fixed arena overhead is added by the store mechanism;
it is never hidden inside a diagnostic payload estimate. SQLite/WAL growth is
not part of canonical-custody capacity because future SQLite projection may
remain explicitly unavailable after canonical sealing.

## State machine

The private mechanism implements the arena-local states below, including an
index-pending/indexed distinction. The transition labeled “SQLite projection”
is only a stand-in exercised by private tests; no schema-v6 SQLite projection
or product indexing API exists.

```text
RESERVED (no launch occurrence yet)
  ├─ trusted-time expiry before claim ─────────► EXPIRED_UNLAUNCHED
  └─ atomic exact launch record + claim ───────► CLAIMED

CLAIMED
  ├─ exact raw evidence sealed ─────────────────► RAW_EVIDENCE_SEALED
  └─ crash/write failure before raw seal ───────► FAILED_INDETERMINATE

RAW_EVIDENCE_SEALED
  ├─ one exact evaluator occurrence claimed ───► EVALUATION_CLAIMED
  └─ custody failure ───────────────────────────► FAILED_INDETERMINATE

EVALUATION_CLAIMED
  ├─ exact final V2 closure sealed ─────────────► FINAL_V2_SEALED_INDEX_PENDING
  ├─ final seal failure ────────────────────────► FAILED_INDETERMINATE
  └─ restart before final seal ─────────────────► FAILED_INDETERMINATE

FINAL_V2_SEALED_INDEX_PENDING
  └─ exact SQLite projection committed ─────────► FINAL_V2_SEALED_INDEXED
```

`RAW_EVIDENCE_SEALED → EVALUATION_CLAIMED` is the only transition that can mint
the store-private precursor evaluation token. The durable claim binds the exact
profile, evaluator, evaluation identity, evaluation time, clock identity, and
clock uncertainty. It is one-use within the isolated mechanism. Provider bytes
therefore enter exact durable custody before that token exists. Product-level
proof that NQ evaluates only through this token remains unimplemented.

The raw section is never an untyped provider byte bag. It is the distinct
arena-owned `nq.acquisition_custody_carrier.v1` wrapper, which embeds:

- the exact canonical provider request and provider-attempt records with their
  self-identities and byte digests;
- the exact launch occurrence;
- the wrapper's native acquisition outcome and provider interpretation;
- exact response bytes when a response occurred;
- separately bounded native stdout/stderr error testimony for non-response
  outcomes; and
- byte lengths and digests for every byte carrier.

The isolated mechanism can seal a nonempty typed carrier for provider
no-response even when it has no response bytes. Protocol rejection, malformed
or partial native output, provider refusal, and successful candidate testimony
use the same raw custody transition without being collapsed. Future core
integration must decode the embedded provider-attempt record using the real
provider contract and prove that its request, native outcome, interpretation,
and byte commitments correspond exactly to the wrapper before evaluation.
Arena tests use a deliberately distinct test-attempt schema and do not claim
live provider-contract correspondence. The intended later path would also make
profile or evaluator refusal consume the reopened raw token and seal an exact
refused V2 artifact; no such product path exists yet.

The intended final closure includes the exact V2 artifact, its execution
binding, and every verdict-affecting retained input needed by the governed
path. The arena precursor owns exact byte custody, binding, one-use
transitions, and reopen verification. It does not implement or claim the
complete `nq.diagnostic_execution.v2` semantic validator. Its store-private
candidate constructor and basic schema/identity checks are defense in depth,
not a live-engine correspondence proof.

There is currently no cycle-free boundary by which sibling `nq-core` can
consume the store-private reopened token and return a fully validated result
without exposing an arbitrary caller-byte seal API. That bridge is explicitly
unimplemented. A later design may move shared contract validation into a
neutral crate or use another capability boundary, but this precursor does not
ratify either choice. There is likewise no SQLite indexing API consuming the
final token today.

After any final-section or superblock write begins, an API error is
indeterminate. The poisoned handle can claim neither that a disposition exists
nor that none exists. Reopen may select the prior evaluation state, or it may
select `FINAL_V2_SEALED_INDEX_PENDING` with the exact closure. Only that
reopened frontier determines which statement is earned. The intended future
index integration must treat an SQLite projection failure after a reopened
final seal as index-unavailable without erasing or weakening the sealed
disposition.

No downstream caller can construct the store-private arena failure-carrier
candidate. The precursor checks its self-identity and narrow
reservation/launch correspondence only. It is not a qualified governed failure
receipt, and no product orchestration currently proves that only the stated
source conditions reach the protected partition.

## Before-reservation refusal and no-launch law

Authentication or authorization refusal, stale generation, missing or
incompatible witness, malformed request, and role/cohort refusal are
invocation-decision results. They occur before a launch claim, do not invoke a
provider, and do not produce a V2 execution artifact. They remain typed
request/decision records and cannot be represented as zero-byte acquisitions.

A successfully allocated reservation still has no launch occurrence. It may be
released or expire only with one exact, durable no-launch terminal decision
bound to that reservation. Release cannot cite an arbitrary “terminal” runtime
record, cannot coexist with a claim, and never turns absence of a launch into
an execution result.

Failure to create or preallocate a per-reservation arena refuses before launch.
Its reporting capacity cannot come from the arena that failed to exist. A
production store therefore requires a separately preallocated, bounded global
prelaunch-refusal reserve. The precursor includes fixed, preallocated,
one-use slots that retain exact candidate bytes and their digests. It does not
validate those bytes as typed refusals, initialize the reserve from `Store`, or
implement drain/recycle; consequently a used slot is never overwritten.

If that reserve is exhausted, read-only, corrupt, unavailable, or encounters an
indeterminate write, the current mechanism returns an error and makes no
durable-refusal-receipt claim. The live handle is poisoned after any write
begins and all semantic reads or retries refuse until drop/reopen adjudication.
From another consumer's vantage an unvalidated or unavailable carrier remains
store/receiver silence or a coverage gap, never a healthy or ordinary refusal.
The per-reservation protected partition covers only failures after that
reservation exists.

## Intended restart and history integration

A restart scanner is required but not implemented. Its normative adjudication
must compare future SQLite reservation/claim/terminal index rows with both
superblocks and all section frames:

- an expired reservation without a claim becomes `EXPIRED_UNLAUNCHED`;
- a durable provider-launch claim without sealed raw evidence becomes
  `FAILED_INDETERMINATE`; it is never launched again;
- sealed raw evidence without an evaluation claim remains evaluation-pending
  and must not reacquire the provider;
- an evaluation claim without a final closure becomes
  `FAILED_INDETERMINATE`; restart does not mint another evaluation token;
- a sealed final closure without its SQLite projection remains
  index-unavailable and is rebuilt from exact sealed bytes;
- an indexed row whose arena bytes differ is corruption, never a plausible
  reconstruction;
- current role, cohort, witness, or dependency generations cannot reinterpret
  an older arena.

Future product integration must obtain claim time at the store boundary from
the configured bounded clock; caller-supplied historical text cannot reactivate
an expired reservation. Reservation and launch remain two required durable
phases: the first checkpoint contains no launch occurrence; the second
integration transaction must append the exact `nq.execution_launch.v1` record
and its same-identity claim, then update the arena before provider code can run.
The precursor does not yet implement that SQLite/arena transaction boundary.
The required law is reservation-before-launch and
durable-launch-before-provider, not one atomic batch that labels future work
already launched.

## Intended backup, archive, restore, and availability

A future governed-store backup is complete only when it is taken at a quiesced cut
that binds one immutable SQLite checkpoint to exact arena sequences and
contains:

- the SQLite database and its verified schema identity;
- every arena file referenced by a retained reservation;
- a canonical inventory binding relative path, allocated length, arena state,
  superblock digest, and every sealed-section digest;
- exact archive/seal verification results.

A SQLite-only copy must refuse the governed-backup-complete claim. Restore must
verify the arena inventory before reopening current history. Missing arena bytes
are canonical-custody unavailable; missing or stale SQLite rows with valid arena
bytes are projection/index unavailable. Those states are distinct.

Removal and purge must treat the arena as retained custody. Ordinary package or
database removal must not delete it. Destructive purge remains a separately
previewed and authorized operation.

Schema-v6 migration cannot attach a new arena or authenticated dependency
generation to pre-existing launch-shaped records. Such history is refused or
explicitly quarantined as legacy unqualified provenance; it is never upgraded
into governed current truth. The public store bootstrap operation also refuses
to establish a dependency trust root after a v6-to-v7 migration boundary;
no unattributed post-migration bootstrap path is implied.

## API stop rules

- In-memory stores cannot issue production governed launch capabilities.
- No raw-evidence token exists before an exact section frame and superblock are
  synced and reopened.
- No final-seal token exists before the V2 closure is synced and reopened.
- SQLite projection cannot accept caller bytes that differ from the sealed
  final closure.
- The public governed-custody facade cannot mark a final closure indexed.
  Store-owned exact SQL/custody verification remains required before that
  state can become product-reachable.
- Neither exact replay nor a copied/relabeled capability mints another launch.
- Arena/index availability is orthogonal to diagnostic outcome.
- The host-role runtime may inspect arena and protected-failure state through
  bounded read-only methods. Those methods cannot repair, evaluate, schedule,
  authorize, or classify a diagnostic outcome.
- The arena module is not a public arbitrary-byte sealing surface. Rust crate
  privacy proves it is unreachable to downstream crates. There is no shipped
  production entry or core/store validation bridge today; later integration
  must solve that boundary and prove the supported product path cannot bypass
  complete contract validation.
- After any section or superblock write begins, an error poisons that live
  handle. All state reads and transitions refuse until drop/reopen selects the
  durable frontier. The same rule applies to the prelaunch reserve.
- Arena and prelaunch-reserve state reads and writes require the exclusive
  lifetime lock; a cached predecessor is never advanced concurrently by two
  conforming handles.

## Qualification boundary

Product integration still requires evidence for:

- the WAL counterexample that falsified same-database reservation;
- injected `ENOSPC` before reservation, during raw seal, during final seal, and
  during SQLite indexing;
- a finite-filesystem reserve-then-exhaust specimen where locally feasible;
- torn superblock and torn section-frame recovery;
- crash/restart at every state edge;
- duplicate claim and duplicate seal refusal;
- final-sealed/index-pending rebuild without provider rerun or semantic
  reconstruction;
- backup/archive/seal/restore with exact arena inventory;
- refusal of a SQLite-only backup as complete.

The current unprivileged local environment denies mount namespaces and exposes
no `/dev/fuse`, so a true disposable finite-filesystem specimen is not earned
here. Injected `ENOSPC` coverage and the exact SQLite-WAL falsifier remain
required; finite-filesystem exhaustion stays explicitly blocked on a suitable
non-production lab rather than seeking additional privilege in this campaign.

`posix_fallocate`, successful writes, and `fsync` establish the qualified Linux
mechanism, not immunity from media loss, kernel faults, controller lies,
filesystem corruption, or simultaneous loss of the declared failure domain.
