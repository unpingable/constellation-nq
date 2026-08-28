# Replacement reviewed 24-hour passive-load charter

## Classification

**REPLACEMENT CHARTER FAILED CLOSED AT THE THIRD SUCCESSOR HANDOFF — HUMAN TIME**

The fresh reviewed charter ran from `2026-08-27T18:00:00Z` until fail-closed
closeout at `2026-08-28T12:06:20Z`. It did not reach its planned exclusive
expiry `2026-08-28T18:00:00Z`. No third charter is authorized or prepared.

The observer template was pinned to `Slice=system.slice`; exact preflight
observed capacity context
`sha256:6c6e34b0e088655fce62d4dd15ea355e6d79015736c6e0fb5b8219feac492c7d`
(`cpu.max = max 100000`, allowed/effective CPUs `0-3`). H, every G/E child,
all three typed succession relations, handoffs, admissions, genesis IDs, and
activations were fresh and did not reuse the refused predecessor charter.

## Exact authority

Operating grant H:

```text
sha256:13dd77121ce3786cf967a4e0e98993e1639dc94612cdb17ce5309d49ba8df06d
[2026-08-27T18:00:00Z, 2026-08-28T18:00:00Z)
4 G / 4 E / 3 succession edges / 5,760 samples / 288 acquisitions
```

All four ordinary G and E children and all three exact succession edges were
pre-issued under H before unattended operation. H never created another H.
Timer wakeups remained inert until the exact initial activation was Armed.

The live transitions were:

```text
G1/W1/E1 -> G2/W2/fresh admission/genesis/E2  armed at 00:00Z
G2/W2/E2 -> G3/W3/fresh admission/genesis/E3  armed at 06:00Z
G3/W3/E3 -> G4/W4                         outcome_unknown at 12:01:59Z
```

The third relation remained the directed, distinct-identity edge
`sha256:22bf46899a5e9a2f5df4b37ff29d93b58d559a2b339dca2729b26122f0898fdf`.
W4 admission ID `d1e9fb00-3705-4894-9963-cd011ef02ab3` was preallocated but
was not admitted. E4 remained at zero occurrences and its activation remained
timer-inert.

## Operational evidence

Immutable samples retained:

| generation | count | first observed | last observed |
| --- | ---: | --- | --- |
| G1 | 1,430 | `2026-08-27T18:02:42.595Z` | `2026-08-27T23:59:45Z` |
| G2 | 1,440 | `2026-08-28T00:00:00.214Z` | `2026-08-28T05:59:45Z` |
| G3 | 1,440 | `2026-08-28T06:00:00.125Z` | `2026-08-28T11:59:45Z` |
| G4 | 24 | `2026-08-28T12:00:00.164Z` | `2026-08-28T12:05:45Z` |

Total samples: **4,334**. G1's initial 162.595-second gap records the repaired
sample-directory packaging omission; no sample was fabricated. G2 and G3 each
reached their exact 1,440-sample ceiling. Generation boundaries remained
half-open and sample sequences did not cross generations.

Recurrence custody at close:

| enrollment | occurrences | completed | skipped slots | terminal action |
| --- | ---: | ---: | --- | --- |
| E1 | 71 | 70 | `[50,50]` | revoked |
| E2 | 70 | 70 | `[46,46]`, `[70,70]` | revoked |
| E3 | 54 | 53 | `[12,12]`, `[36,36]`, `[50,50]` | revoked |
| E4 | 0 | 0 | none | revoked |

Total completed diagnostic acquisitions: **193**. Latest-only recovery
recorded six skipped slots and produced no catch-up burst. E1's final
occurrence remained pre-provider (`created` only). E3 occurrence
`recurrence:4d452935962a2a9bb82fceee832a3f3b31accba312928afef406da52ce7430b2`
crossed `provider_invocation_started` at fencing epoch 194 but did not retain
an exact provider intake/artifact. Exact local process-group evidence
`sha256:9b446b2e04c86cf71ce9704ce3c21e81e3c44243dea40b02072651123610e5ea`
establishes provider quiescence only; it does not recover a diagnostic result.

## Failure and root cause

At approximately `10:48Z`, recurrence one-shots began exceeding their
`TimeoutStartSec=90s` process boundary. The journal retained 49 recurrence
timeouts before closeout. The decisive epoch-194 provider run returned to its
local supervisor at `10:52:50.022Z`, but systemd killed the enclosing NQ
one-shot at `10:52:51Z` before exact intake was committed.

The passive selector currently reopens and verifies every retained sample in
one generation for each selection. Under a realistic retain-all generation,
that bounded but growing work crossed the deployed process/resource envelope.
This is an operational sample-selection scalability gap; increasing the timer
alone would not establish a sound long-horizon bound.

At 12:00Z, E3 still held the shared passive coordination domain. The third
handoff selected an exact G4 sample and appended `admission_started` without
first treating that domain occupancy as a readiness wait. Its one-shot then
timed out; restart correctly recorded:

```text
handoff: sha256:a46648572c5dab442f0c29496ecf4cbbc7effaaad406750f6934056db4139c1e
state: outcome_unknown
exact admission custody: false
timer exposure: inert
human required: true
```

No admission refusal or diagnostic conclusion is inferred.

The mechanically determined handoff defect is repaired in source: before
`admission_started`, the evaluator now waits with zero attempts consumed while
the exact domain is occupied/fenced or provider-safe spacing remains, and it
rechecks sample eligibility after the wait. This repair does not resolve the
historical handoff, optimize sample selection, or authorize another charter.
It was qualified locally after closeout and was deliberately **not deployed**;
the installed release remains the exact release that ran the replacement
charter.

## Storage and independence

At close:

```text
sample-generation stores: 10,143,744 bytes
charter DB/operating/admission custody: 16,110,692 bytes
total attributable custody: 26,254,436 bytes
available filesystem bytes: 26,273,411,072
required free-space guard: 10 GiB
```

Observed attributable growth was about 1.45 MB/hour over the partial window,
or roughly 35 MB/day at this profile. Archive custody remains unnecessary for
one 24-hour horizon. Retain-all was preserved and no history was deleted.

No Nightshift file was created or changed during the charter. Sampling,
diagnostic acquisition, and Nightshift reasoning remained three independent
clocks. No old-helper provider path was used.

## Fail-closed closeout

At `12:06Z`:

* recurrence, handoff, observer, and scheduled-closeout timers were disabled;
* observer and recurrence services were stopped;
* all four activation objects were closed and timer-inert;
* H was retired by event
  `sha256:d69b43e9977eafde489faf84a75b5e33393f67e10eb17e9a0586dbf05db14ce2`;
* E1-E4 were revoked append-only;
* G1-G4 were retired append-only;
* systemd failed-state latches were cleared without restarting work;
* no prepared object can self-activate.

Installed unit/binary custody:

```text
observer unit  sha256:100f6cb51257c058ed62380af349a361c35090c7de90d8578606538d6f0d8051
recurrence     sha256:8800d0844e3151f5b9e75a8bba640792ab5efcbb69e8f845946c5dc4a11e3365
handoff        sha256:7782f0f7ed445e59c42605c6e9f3b880efad03ac63c1bf9eea8fae33688ffeaf
closeout       sha256:848cd8aa67fd735039ddfcc91c80476a8b3b3e893b4f94db3f0c2808265c2424
nq              sha256:d43f928af34ef7873ae52499c4118ebf660702e8bce40f337788d1cd6e0081ad
observer helper sha256:bc8e36f7a3569a8b430da44040acdd7d3a368e595385db03571a332ce30ec9a1
```

## A4

A4 was verified directly from its canonical immutable database at close. It
remains exactly:

```text
acquisition: recurrence:d555a10d2b4f11e7c6d550f43a6fd6d07631573bec5c14b54d09ca6b8e04beea
diagnostic outcome: unknown
provider activity: unknown
coordination domain: linode:labelwatch-host
coordination: fenced_outcome_unknown
fencing epoch: 1
```

Its events remain `created`, `pre_provider_failed`,
`provider_invocation_started`, `outcome_unknown`. Nothing in this charter
referenced, reconciled, migrated, or released A4.

## Validation and HUMAN TIME

After the live failure, the handoff coordination repair passed:

* full locked workspace/all-target test suite;
* Clippy across the locked workspace/all targets with warnings denied;
* formatting;
* passive operating-grant structural checks;
* bounded recurrence/fencing structural checks;
* provider-operation noninterference structural checks;
* `git diff --check`.

The next required work is not authorization for another charter. First, NQ
needs a separately reviewed bounded sample-selection custody/index law that can
select and verify the newest eligible retained sample without rescanning an
ever-growing generation on every acquisition, while preserving corruption
refusal and exact replay. The legitimate design choice is between an immutable
content-bound selection index/manifest and a bounded active-selection window
backed by unchanged replay custody. That choice changes custody mechanics and
belongs at HUMAN TIME. No third charter may be enabled under this campaign.
