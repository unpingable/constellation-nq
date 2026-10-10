# Retention and capacity admission

This describes the schema-v15 implementation and operator controls. It does
not qualify a deployment, a filesystem, or seven days of a particular workload.
The intended ordinary-history window is **604800 seconds (seven days)**.
Capacity refusal never shortens that window automatically.

## Choose the envelope before initialization

The optional `[retention]` table uses integer bytes and seconds:

```toml
[retention]
horizon_seconds = 604800
# byte_ceiling = 8589934592
# reserve_bytes = 1073741824
# auxiliary_bytes = 67108864
```

Omit a key to select its automatic default. The commented values are examples,
not a recommended deployment envelope. In particular, an 8 GiB ceiling is a
qualification candidate, not a universal allocation or seven-day guarantee.

At the first admission NQ measures the database directory's filesystem total
and available bytes, free inodes, existing store occupancy, and the process's
actual soft `RLIMIT_FSIZE`. With automatic defaults:

- Reserve is `max(1 GiB, ceil(filesystem total / 5))`.
- Auxiliary allowance is 64 MiB.
- Aggregate budget is existing occupied store bytes plus **half** the available
  free bytes remaining above the reserve.

An explicit aggregate ceiling must fit the actual filesystem and file limits.
A larger configured ceiling does not override either limit. This reserve is
store admission policy; it does not replace a shared host's independently
established storage reserve or admit other allocations on that host.

The effective envelope, its admission observation, requested ceiling, horizon,
and reserve selection origin are persisted in the database. Normal open uses
that envelope without growing or shrinking it when free space changes.
Configuration is matched against its recorded admission observation. Changing
retention keys on an existing store does not resize it: differing policy is
refused. Set overrides before `init` or before an explicitly supported schema
upgrade establishes its first envelope. There is no general live resize
command. A crash leaving initialized schema without a complete envelope is
refused; ordinary open does not guess a replacement policy.

## Initialize with the intended service limits

The shipped `nqd.service` has **`LimitFSIZE=1G`**, as well as `MemoryMax=2G` and
other runtime limits. Initializing in an ordinary login process with an
unlimited file-size limit can persist an envelope the service cannot use.
Initialization and writable maintenance must run with the intended service's
limits. Do not remove the shipped limit to make a mismatched store open.

For the intact packaged unit, define `nq_helper_command` exactly as shown in
[OPERATIONS.md, “Test and admit a watcher”](OPERATIONS.md#test-and-admit-a-watcher).
That existing transient `systemd-run --wait --pipe --collect` wrapper includes
`LimitFSIZE=1G` and the packaged memory, task, filesystem and process controls.
With `nqd` stopped, initialize through it:

```sh
nq_helper_command --config /etc/nq/nq.toml config check
nq_helper_command --config /etc/nq/nq.toml init
nq_helper_command --config /etc/nq/nq.toml doctor
```

These are operator commands, not package-install actions. `init` creates new
state; do not run it against an existing initialized database. If the intended
service has an explicitly admitted local override, keep the transient wrapper
and service limits identical before initializing. Check the effective unit,
including drop-ins, rather than assuming the packaged text is the active
configuration:

```sh
systemctl cat nqd.service
systemctl show nqd.service -p LimitFSIZE -p LimitFSIZESoft -p MemoryMax
```

A proposed qualification case is a dedicated approximately 32 GiB volume with
an 8 GiB per-file process limit, synchronized between initialization and the
service. That requires explicit local admission and a sustained workload run;
it is not a shipped setting or deployment claim. A constrained 10 GiB case is
not qualified for the seven-day target. Volume size alone is insufficient:
available space, other tenants, file limits, custody holds, and write rate all
matter. The formula does not establish a history duration.

## What the byte budget covers

The envelope reserves a full main database plus a full-database transaction
WAL. The WAL allowance includes SQLite frame/header bytes and conservative
FULL-commit sector padding; SHM sizing includes the smaller first WAL-index
region. Both main and WAL are constrained by the observed per-file limit.
Fixed allocation headroom and configured auxiliary bytes are charged
separately. Existing main, WAL, SHM, rollback journal, known lock/watermark
sidecars and owned watermark temporaries are counted using the greater of
logical size and allocated blocks.

Cooperating store operations serialize through the database operation lock.
Before an ordinary write NQ checks the current envelope and attempts a
TRUNCATE checkpoint. A held reader can prevent it; the write is refused rather
than allowing another transaction to accumulate an unbounded WAL. Lock wait
and SQLite busy handling are bounded. SQLite page limits, disabled cache spill,
and explicit checkpoints provide the implemented bound under the supported
SQLite/filesystem assumptions. They do not impose a filesystem quota on
unrelated writers, or bound all process memory.

Ordinary read-only SQLite access can rebuild SHM. Bootstrap admission checks
its possible allocation and current file limit before inspecting the policy.
Rollback recovery is admitted against the journal's original main extent and
rewrite headroom before SQLite performs its own replay. Immutable sealed
archive reads do not consult WAL or create sidecars.

## Expiry, declared protected holes, and refusal

Ordinary collection performs dependency-aware expiry before collecting again.
Eligibility uses local arrival/admission and completed-run times. Provider
sample time is not permission to discard a freshly received report.

Each history sequence (evaluations, admitted reports, provider intakes,
run-bound status) has an *expired-through* floor. Above a floor, history is
complete and contiguous. A floor advances over every aged collection, including
protected ones. At or below a floor a row survives in only two declared forms:

- **Island**: a whole collection kept in full because a live root needs it.
- **Compact source record**: the identity header of an evaluation, admitted
  report, or raw submission that a retained finding, finding-evidence, or
  saved-check row still names. Its bodies are cleared (`source_expired=1`). It
  records that a decision was made from a source that has since expired. It is
  never re-verified against that source and is never paged as history.

Roots that keep an island, and when they release it:

| Root | Holds while | After release |
| --- | --- | --- |
| Unresolved finding | the finding's latest event is not `explicitly_absent`; only the current episode's opening event and its latest event keep full closures | the events stay; their evaluations and cited reports become compact |
| Notification custody | any delivery for the finding event is pending; a delivery intent is terminal at `accepted`, `refused` or `failed`; a legacy outbox at `delivered`, `failed`, or exhausted retries | as above |
| Notification outcome `unknown` | always: no later outcome can be recorded, so the hold is permanent for that occurrence | — |
| Saved-check claim | a claim without a terminal outcome | compact |
| Diagnostic origin, successor acquisition | always (consumer lifetime unknown) | — |
| Latest report per instance, latest acknowledged checkpoint per checkpoint contract, current status target, newest evaluation of each evaluation lineage | while it is the latest | an ordinary candidate |
| Reports named by a surviving full evaluation | while that evaluation survives | an ordinary candidate |

Finding, notification, saved-check, diagnostic and successor rows are never
deleted. A resolved finding therefore keeps its own consequential history and
no longer pins any other history. A lineage whose newest evaluation is old
keeps reporting that evaluation in status rather than disappearing. Islands
and compact records are charged to the byte budget. If protected dependencies
exhaust it, admission refuses rather than discarding them. The store also
keeps monotonic lineage anchors and compact provider-intake identity
commitments after removing large capture bytes. Those commitments preserve
retry/idempotency behavior and are not free metadata.

`nq doctor` reports the generation, the floors, the last cutoff, the horizon,
island counts by root kind (including islands released and pending
reclamation), compact record counts, pending and `unknown` notification
custody, and the persisted envelope against current occupancy. When the next
ordinary write would be refused, the `database` field reads
`capacity_refusing` instead of `healthy`.

The durable expiry boundary and its deletions and compactions commit together
in a FULL transaction. Validation proves every row below a floor is a declared
island or compact record; any other row is an undeclared retained row and
fails closed, as does a live root whose closure was compacted. A stale advisory
watermark is not authority to delete. Reclaimed pages can be reused without
reducing the main file's physical size.

Expiry is maintenance. A refused expiry (capacity, checkpoint contention, or
history changed by a concurrent writer during validation) is logged with its
class, and the collection continues to admission. Admission applies its own
capacity preflight and refuses explicitly. Preserve the database and inspect
the reported cause; do not shorten the horizon, delete sidecars, or remove
identity rows to bypass it.

An explicit **expired** result refers to a committed retirement boundary. It
means the requested range starts in an expired region. It names the floor and
the protected evaluations retained below it, and the API answers `410` with
the contiguous interval that can be paged instead. An **unavailable** result or
ordinary missing/error condition does not prove retirement. A source-expired
record is reported as expired, never as verified. None of these results means
a successful full-history verification. `nq admin validate --full` reports
`history.coverage` as `bounded` after any expiry. Surviving-history
verification and sealed pre-expiry archive inspection have their respective
scopes. A cold archive of an expired store declares its retention boundary
(`complete_history: false`, generation, floors, cutoff, islands by root kind,
compact counts) and its verification re-derives that declaration; it never
claims complete history.

## Backup and explicit restore

Backup destinations and supported migration writes require capacity admission
as well as source validation. Read-only backup verification accepts a copied
source envelope without treating the archive's filesystem as the live store.
Backup storage is an additional allocation; the live-store ceiling does not
reserve arbitrary backup or archive bundles.

The existing explicit `restore` workflow admits its temporary destination
before publishing it. If the original envelope still fits on the same
filesystem, it preserves the database bytes and envelope exactly. When a new
destination admission is required, the receipt records both prior and current
envelopes. An automatically selected reserve is resolved from the destination
filesystem total; an explicitly configured reserve stays fixed. The recorded
selection origin distinguishes these cases even when their original byte
values happened to be equal. Ordinary reopen never performs this re-admission.

Full runtime, filesystem, memory, concurrent-writer and sustained seven-day
qualification remain necessary for an operating claim. A passing bounded
local fixture or successful initialization is evidence only for that case.
