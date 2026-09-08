# Bounded Docket factual purpose candidate

`nq docket-purpose-support --docket-binary BIN --docket-sha256 SHA --state DIR
--request REQUEST --snapshot-history HISTORY` directly invokes the supported
Docket `show-read-only --json` surface.
It accepts an existing campaign-owned state directory, never an M2 store.
Docket runtime baseline c49ad8d; source-store fixture increment f1ea283 changes
tests only; read-only query correction6c57926 adds a separate command which older
binaries refuse. It uses READ_ONLY/query_only and one query transaction, requires
current schema, and performs no mkdir, migration or journal-mode transition.
SQLite WAL reader coordination is explicit, not an immutable-file guarantee.
The DTO inventory follows Docket's closed v3 rendering, with classic
DTOs used solely as historical field inventory, not an executable dependency.

NQ owns bounded qualification/replay, not Docket settlement. The allowlisted
`docket_attempt_settled` means only Docket's **normal committed state**; refused,
prepared, indeterminate and recovery terminal states are not positive. The exact
Docket repository/ref/result subject is retained, never inferred from a path.

The two consumer profiles retain the donor policy: strict readonly requires
direct native observation; continuity readonly additionally requires exact
named Continuity memory eligibility. File projections do not gain native custody.
Settlement and upstream premises remain asserted, explicitly retained limitations.
Empty/unenforceable premises refuse; unresolved obligations and contradictory
execution or qualification refuse current support. Purposes continue/wait/request/
stop/human-escalation are read-only posture inputs, never action permissions.

The Linux producer binds the opened executable descriptor and expected content
digest, fixes argv to `show-read-only`, strips environment, and bounds output/time to
4MiB/10s. Assumptions: trusted immutable executable contents and runtime libraries,
trusted same-UID environment and configured state. Descriptor binding prevents
pathname replacement, not in-place mutation; no stronger confinement is claimed.
Acquisition time comes from the producer and becomes the effective recorded request
time. NQ source clocks do not independently establish present truth.

Nightshift separately consumes the exact canonical receipt and request and binds
receipt/source/support identities into its existing PresentEvidencePort query.
Currentness refusal cannot repair NQ factual refusal. The old generic host-claim
bridge now refuses the Docket current role; historical inspection remains valid.

Run001 used actual real prepared/committed/refused/indeterminate stores and real
native acquisition, then positive, allowlist, purpose, premise, residual,
contradiction, stale, wrong-source, duplicate-key and named-continuity controls.
Nightshift exercised these receipts and separate current/absent/unknown/expired/
wrong-authority/wrong-subject support cases. These are local fixture qualification,
not deployment or independent acceptance; exact review follows integration.

Required history custody is one configured artifact directory per Docket source
store. Same(attempt,version) changed immutable core refuses, while associated
observation/authorization growth remains allowed under the original ten-field
core inventory. Creation and duplicate success both fsync the file and directory;
incomplete records fail closed. This is not authenticated/global history and
reset/deletion invalidates its continuity assumption. Native current consumption
requires this exact snapshot context; stateless qualification cannot replace it.

Continuity's distinct source-history and typed bad-premise corrections are now
implemented. Final integrated qualification and independent review remain separate
from passing earlier source snapshots.
