# Passive load successor handoff V1

`nq.passive_load_successor_handoff.v1` is one immutable, content-derived,
restart-safe procedure delegation under a finite operating grant H. It binds:

```text
exact H
exact passive_watcher_succession/v1 edge
exact predecessor activation
exact pre-issued G_next
exact distinct W_next
one preallocated admission identity
one required genesis acquisition identity and V3 origin boundary
exact pre-issued E_next
exact staged successor activation
```

The handoff is procedure authority only. It may invoke the already-canonical
validation sequence. It is not admission authority, diagnostic authority,
sampling authority, recurrence authority, or identity equivalence.

## Closed sequence

The append-only state machine is:

```text
staged
  → waiting_for_sample
  → sample_ready
  → admission_started
  → admission_completed
  → genesis_started
  → genesis_completed
  → validated
  → armed
```

The only other terminal states are `admission_refused`, `genesis_refused`,
`outcome_unknown`, and `expired`. There is no skip-ahead transition. Duplicate
evaluator delivery converges through the exact handoff and operation
identities.

The evaluator first verifies that the predecessor activation is still exactly
Armed and that `G_next` is inside its half-open interval. A read-only readiness
query applies the same signature, generation, subject/vantage, capacity,
cutoff, and age law as the passive provider. It creates no sample, admission,
or occurrence. Missing sample custody records one deterministic sampling-slot
wait under the same handoff. It never falls back to the retired helper and
never selects a predecessor-generation sample.

Once one eligible successor sample exists, the handoff records
`admission_started` before invoking the ordinary admission owner with its exact
preallocated UUID. Admission still performs its own fresh provider exchange,
conformance checks, profile checks, and binding transition. A governed refusal
is terminal. A restart that finds `admission_started` without the exact
admission and active binding records `outcome_unknown`; it does not retry
against a later sample.

Sample readiness is not compositional scheduling permission. Before appending
`admission_started`, the evaluator projects the successor enrollment's exact
coordination domain. A predecessor acquisition holder, an outcome-unknown
domain fence, or an unelapsed provider-safe start-spacing boundary leaves the
handoff at `sample_ready`, timer-inert, with zero admission attempts consumed.
The evaluator also rechecks the ordinary passive sample-eligibility predicate
after that wait. A stale or missing successor sample cannot cross the admission
fence. This prevents a service-manager timeout during ordinary coordination
delay from being misclassified as an unknown admission outcome.

After exact admission custody exists, the handoff initiates one preallocated
genesis acquisition through the already-qualified Linode V3 origin boundary.
The NQ acquisition intent remains the provider fence. A pre-provider crash may
resume the same exact occurrence; provider-started custody without completed
intake becomes `outcome_unknown` and cannot reinvoke. A completed intake is
reconciled exactly on restart.

Activation prerequisites are then recomputed. Validation remains timer-inert.
The arm transition closes the exact predecessor activation first and exposes
the successor activation second. A crash between those append-only events
produces a safe real gap, never overlapping E authority. Restart completes the
same handoff. Stale predecessor timer wakeups see `closed` and consume zero
attempts.

## Finite H relationship

H contains an exact closed set and count of watcher succession edges. A
handoff must correspond to the next paired G/E child indexes and the matching
directed edge; it cannot reorder or skip. Its origin helper and coordinate must
equal the successor watcher binding in H's deployment policy. G/E children
must already be ordinary issued children fitting H. H expiry prevents new
provider work or activation, and H exhaustion never creates another H.

All future handoffs may be staged before an unattended window. Staging creates
no child, admission, sample, acquisition, or recurrence authority. The service
manager may wake every staged handoff; before its exact boundary and before
Armed, those wakeups are semantically inert.

The recurrence one-shot uses `operating tick-grant H`. H projects exactly one
Armed child activation and then applies its ordinary tick gate. Zero Armed
children is inert; more than one is a protocol contradiction and refuses.
This keeps one static service valid across successor activations without a
mutable authoritative “current activation” pointer. Selecting H in a wakeup
still grants nothing: only an already-Armed activation can expose its finite E.

> H may delegate execution of an exact finite validation sequence. It may not
> delegate the outcomes of those validations.

> An eligible sample permits one admission evaluation. It does not guarantee
> admission.

> The timer may wake a staged successor. It cannot spend recurrence authority
> until the successor activation is canonically Armed.

The passive handoff never references, clears, migrates, or reuses the retired
one-shot provider boundary or A4. It creates no Nightshift cycle or support
evidence.
