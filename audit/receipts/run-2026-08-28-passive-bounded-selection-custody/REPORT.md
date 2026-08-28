# Passive bounded-selection custody qualification

## Classification

**BOUNDED-SELECTION-CUSTODY-QUALIFIED**

Separate coordination/admission result:

**SUCCESSOR COORDINATION/ADMISSION GATE QUALIFIED**

This source-only campaign began at clean branch
`campaign/passive-watcher-succession-v1`, HEAD
`e2435f307bdcdd18ac2e7e77b6caca8a1e256ffc`. It preserved the failed
replacement-charter evidence and created, prepared, deployed, or enabled no
new charter.

## Selection custody

The implementation uses immutable per-sample selection entries and immutable
chained manifests. Each entry content-binds generation, sequence, observed
time, occurrence, payload digest, canonical filename, and exact canonical
document digest. The small current locator is replaceable derived state. It is
insufficient to select anything without reopening the exact manifest, entry,
and sample.

Newest-at-or-before-cutoff lookup binary-searches immutable manifest times,
then reopens exactly one entry and one canonical sample. The selected sample
crosses canonical-byte, SHA-256, filename, sequence, occurrence, observed-time,
payload, producer, binding, capacity-context, and Ed25519 verification. No
historical signature verification remains on the routine selection path.

Retain-all custody is unchanged. Index loss reduces availability and is
reconstructible from exact retained samples. Reconstruction intentionally
performs one full canonical scan; provider selection never falls back to it.

## Crash, corruption, and concurrency

Append holds a narrow exclusive index lock and commits a durable update marker
before the sample. It then persists sample, immutable entry, immutable
manifest, and atomic current projection before removing the marker. Selection
holds the shared form of the same lock. An interrupted append therefore either
is wholly visible or refuses `selection_index_stale`; it cannot silently expose
an older sample as newest.

Observer reopen verified canonical custody, recovered an interrupted sample's
missing index state, cleared the durable marker, and selected the same exact
sample. Index-directory loss returned `selection_index_missing`; deterministic
reconstruction restored identical selectable facts. Corrupt manifest/entry,
stale locator, missing canonical sample, and changed canonical bytes each
reached their distinct fail-closed class. No path sampled, used the old helper,
or created diagnostic authority.

## Performance

Release-mode measurements are retained in `selection-performance.json`.

| samples | first | median | max | manifests | entries | samples verified |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,440 | 2.822 ms | 1.762 ms | 2.625 ms | 13 | 1 | 1 |
| 4,334 | 3.049 ms | 1.445 ms | 2.997 ms | 15 | 1 | 1 |
| 5,760 | 0.662 ms | 0.601 ms | 0.612 ms | 15 | 1 | 1 |
| 11,520 | 3.157 ms | 1.531 ms | 3.038 ms | 16 | 1 | 1 |

Filesystem cache explains latency variation but cannot explain the object-count
law: growing the corpus eightfold increased immutable manifest reads from 13
to 16 while entry and exact sample reads remained one. The hot path is no
longer linear and is comfortably inside the 90-second service envelope.

## Coordination/admission repair

The replacement-charter repair is now one lazy admission gate. Occupied domain,
outcome-unknown fence, or unelapsed provider-safe spacing returns before sample
re-evaluation and keeps the handoff `sample_ready`, timer-inert, with zero
attempts. Once coordination becomes eligible, the evaluator performs the
bounded exact index selection again. A sample that aged out while waiting
remains inert; an exact still-eligible sample permits only the existing
ordinary admission transition.

Deterministic qualification covered occupied holder, outcome-unknown fence,
spacing immediately before and at equality, lazy sample evaluation, sample
expiry during wait, and the ready transition. Existing handoff ledger tests
retain exact state ordering, duplicate convergence, semantic substitution
refusal, restart behavior, and ordinary admission/genesis ownership.

## Validation

The release benchmark generated and verified canonical signed retained
custody at 1,440, 4,334, 5,760, and 11,520 samples. The complete locked
workspace/all-target suite passed outside the restricted execution sandbox.
The same suite's first sandboxed run reached two expected `EACCES` failures in
real subprocess-spawn tests; the unrestricted rerun passed those tests and the
entire workspace. Warnings-denied workspace/all-target Clippy, formatting,
`git diff --check`, JSON receipt parsing, and the passive selection,
operating-grant, bounded-recurrence, and provider-operation structural checks
all passed.

The only intentionally linear operation is explicit reconstruction and
observer-generation reopen, which verify canonical retain-all custody before
rebuilding derived state. The unattended provider hot path is logarithmic in
immutable manifest reads and constant in entry/sample verification.

## Standing

The failed 24-hour H/G/E/handoff objects remain terminal evidence. A4 remains
unresolved and fenced under its old provider boundary. No service, timer,
installed binary, provider configuration, admission, enrollment, or operating
grant was changed.

A fresh charter is technically eligible for a separate deployment/release and
authorization campaign only after the exact new binary and packaging are
assembled, checksummed, installed, preflighted, and explicitly authorized.
This report itself grants none of those actions.
