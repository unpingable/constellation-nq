# Passive load bounded selection custody V1

This contract closes the retain-all selection defect witnessed by the failed
replacement 24-hour charter. It changes neither the load-pressure proposition
nor the immutable signed sample schema.

> Retain-all evidence is canonical custody. Selection metadata is derived
> acceleration, not evidence and not authority.

## Immutable index chain

Each canonical sample append also produces one immutable
`nq.passive_load_selection_index_entry.v1`. The entry binds the exact observer
generation, sequence, observation time, occurrence identity, payload digest,
canonical sample filename, and SHA-256 digest of the exact canonical sample
document. One immutable `nq.passive_load_selection_manifest.v1` per sequence
binds that entry and the predecessor manifest. Manifest zero is the exact empty
generation state.

A replaceable `nq.passive_load_selection_index_current.v1` file locates the
latest immutable manifest. It is a reconstructible projection. It cannot make
a sample eligible by itself: selection reopens the exact manifest, exact entry,
and exact canonical sample and then repeats structure, content digest,
filename, producer, binding, capacity-context, payload-digest, and Ed25519
signature verification. A locator trailing an extant next manifest refuses as
stale. There is no persisted diagnostic `latest` authority.

The manifests are numbered contiguously. Newest-at-or-before-cutoff selection
uses binary search over immutable manifest observation times. Routine work is
therefore logarithmic in retained sample count and verifies exactly one signed
sample. It does not list, parse, hash, or verify the historical corpus.

## Append and crash law

Append and selection share a narrow selection-index flock. Append holds it
exclusively; selection holds it shared. Before the canonical sample is
created, append durably creates an `update-in-progress` record binding the
intended generation, sequence, payload, and document digest. It then commits,
in order:

```text
durable update marker
→ durable canonical sample
→ durable immutable entry
→ durable immutable manifest
→ atomic derived-current replacement
→ remove update marker
```

The index can never durably point to a sample that was not already committed.
A crash at any intermediate cut leaves the marker, so selection refuses
`selection_index_stale` rather than using an older sample. Observer reopen
performs the expensive exact canonical scan once, recreates missing identical
derived objects, atomically restores the current projection, and removes the
marker. A crash during current replacement may leave only a temporary derived
file; reconstruction discards that incomplete projection.

Canonical samples remain immutable and retain-all throughout. Index loss
returns `selection_index_missing`; it does not alter sample meaning. The
explicit `reconstruct-selection-index` helper command derives the same index
from exact retained custody and creates no sample, admission, acquisition, or
Nightshift authority. Corrupt canonical custody refuses reconstruction.

## Failure taxonomy

The provider distinguishes:

* `no_eligible_sample` — a valid index contains no sample inside the exact
  cutoff/age window;
* `selection_index_missing` — required derived metadata is absent;
* `selection_index_corrupt` — a manifest, entry, locator, or lock is malformed
  or content-substituted;
* `selection_index_stale` — an append was interrupted or the chain/current
  projection is inconsistent;
* `canonical_sample_missing` — the selected entry's exact sample is absent;
* `canonical_sample_content_mismatch` — selected bytes, identity, or signature
  differ from the immutable entry and provider contract.

None permits corpus-scan fallback, old-helper fallback, stale sample use, or
diagnostic fabrication.

## Performance qualification

The sushi-k synthetic qualification retained canonical signed sample files and
immutable entries/manifests at four increasing corpus sizes. Each checkpoint
forced directory synchronization before the first measurement and then ran 25
repeated selections. Filesystem cache affects latency, so the conformance
claim rests primarily on bounded object counts:

| samples | first lookup | repeated median | repeated max | manifests | entries | signed samples |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,440 | 2.822 ms | 1.762 ms | 2.625 ms | 13 | 1 | 1 |
| 4,334 | 3.049 ms | 1.445 ms | 2.997 ms | 15 | 1 | 1 |
| 5,760 | 0.662 ms | 0.601 ms | 0.612 ms | 15 | 1 | 1 |
| 11,520 | 3.157 ms | 1.531 ms | 3.038 ms | 16 | 1 | 1 |

The largest corpus is eight six-hour generation counts and twice the reviewed
24-hour sample ceiling. Manifest reads grew from 13 to 16 while exact sample
verification remained one. This is comfortably below the 90-second one-shot
envelope and demonstrates logarithmic metadata scaling rather than cache-only
improvement.

Reconstruction remains linear by design because its job is to re-establish
derived facts from every canonical object. It is an explicit recovery/startup
operation, never the recurrence selection hot path.

## Coordination composition

Sample readiness does not imply that successor admission is compositionally
schedulable. The handoff evaluator first checks shared-domain occupancy,
outcome-unknown fencing, and provider-safe spacing. While any applies it stays
`sample_ready`, timer-inert, and consumes zero attempts. Only after coordination
is available does it rerun the bounded indexed eligibility lookup. A sample
that aged out during the wait leaves the handoff inert. Exact eligibility plus
available coordination permits the existing ordinary admission boundary; it
does not guarantee admission.

No charter, deployment, unattended enablement, archive, retention deletion,
or Nightshift cadence is authorized by this contract.
