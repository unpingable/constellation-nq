# Bounded Recurring Diagnostic Office V1

## Scope

V1 gives one already-admitted watcher a finite, immutable grant to attempt new
diagnostic acquisition occurrences at deterministic anchored slots. It is not
a monitoring platform, a generic scheduler, a retry daemon, or a Nightshift
clock.

> Recurrence decides when a new acquisition occurrence may be attempted. It
> does not decide what the diagnostic means.

> Backoff may delay work. It may not move the clock.

> Replay shows history. A recurrence slot authorizes a new observation.

## Three layers

### Protocol law

The implementation permanently enforces these non-configurable laws:

* replay has no provider or origin-attestation source;
* one deterministic enrollment slot creates at most one acquisition identity;
* one acquisition may cross its provider invocation fence once;
* pre-provider retry retains enrollment, slot, acquisition, and domain epoch;
* completed occurrences never reopen and outcome-unknown occurrences never
  reinvoke their provider;
* slot times derive from the immutable anchor and interval, never completion;
* durable history is append-only and restart creates no authority;
* watcher semantics and the complete V3 origin binding remain exact;
* stale domain epochs refuse and lease expiry is not evidence that work stopped;
* support evidence and Nightshift cannot construct recurrence triggers;
* every enrollment is finite.

Configuration may select a safe behavior. It may not select a behavior that
invalidates the protocol assumptions.

### Deployment safety envelope

`nq.recurring_office_policy.v1` is content-addressed, append-only deployment
input. It permits bounded selections; registration or activation creates no
acquisition. It declares interval/lifetime/occurrence limits, the closed
missed-slot and startup modes available, retry/backoff and failure thresholds,
provider timeout and storage ceilings, fixed watcher-to-coordination-domain
mappings, per-domain safe-start spacing, and the exact qualified Linode V3
helper/coordinate binding.

V1 fixes watcher and domain concurrency at one. This is a protocol limitation,
not a tunable default. A profile requesting another value refuses. Deployment
topology is explicit input and is never inferred from hostnames, URLs, watcher
name similarity, DNS, or IP.

Activation of a tighter profile prevents future occurrences under an old
enrollment. It does not reinterpret an already in-flight occurrence. Broader
limits do not enlarge old enrollments. New semantic capability requires a new
immutable enrollment under the newly active profile.

### Immutable recurrence enrollment

`nq.recurrence_enrollment_spec.v1` records an operator-selected subset of the
active envelope: UTC Unix-millisecond anchor, fixed interval, finite occurrence
count, exclusive expiry, missed-slot mode, startup mode, finite pre-provider
attempt count, deterministic fixed backoff, failure-pause threshold, concurrency
request, and the only V1 reason `diagnostic_recurrence`.

The materialized `nq.recurrence_enrollment.v1` also binds the exact watcher
semantic digest, deployment-policy identity, and coordination domain. Any
change to these semantic facts creates a new enrollment identity/epoch. Exact
watcher admission renewal may continue only when the watcher semantic digest
is unchanged; the ordinary acquisition path still verifies current admission.

Code defines what recurrence can mean. Deployment policy defines which
meanings are permitted. Enrollment records which permitted meaning was
selected.

## Slots, wakeups, and downtime

For anchor `T0` and interval `I`, slot `n` is always scheduled for `T0 + nI`.
Its identity is derived from the enrollment identity, slot index, and scheduled
time. Repeated or concurrent `tick` calls in one slot converge through the
store transaction, kernel domain guard, slot uniqueness, and durable epoch.

A service-manager wakeup merely invokes the one-shot `recurring tick` command.
It carries no watcher, slot, or diagnostic authority. The packaged timer's
minute is only wakeup granularity; cadence remains in the enrollment.

V1 supports two closed missed-slot policies:

* `skip`: record missed opportunities and acquire none for them;
* `latest_only`: record older opportunities as skipped and allow at most the
  latest due slot.

Startup likewise selects either `wait_for_next_slot` or
`evaluate_current_slot`. Startup, clock-forward, and downtime never create a
catch-up burst. Clock rollback cannot reopen any slot at or below the highest
durably evaluated slot. Actual observation time remains actual provider time,
not scheduled slot time.

## Retry, failure, and finite authority

A pre-provider failure may be reevaluated for the same occurrence after the
enrollment's fixed backoff, up to its finite attempt limit. Attempts do not
consume another recurrence occurrence and do not alter future slot times. A
pre-provider exhaustion is a retained terminal acquisition failure.

After `provider_invocation_started`, the same occurrence cannot invoke again.
Explicit completion terminates the occurrence. Ambiguity becomes
`outcome_unknown`, pauses the enrollment, and fences the entire coordination
domain in conservative V1. Lease or process expiry alone cannot clear that
fence. An explicit `recurring reconcile ACQUISITION_ID` may release it only
when read-only replay reopens exact local artifact custody for that same
acquisition, attempt, and fencing epoch. Reconciliation has no provider or
origin-helper source. It leaves the enrollment paused until a separate
operator resume.

Terminal failure increments the derived consecutive-failure projection;
success resets that projection. Reaching the selected threshold appends a
pause event. Operator pause, resume, and revoke are append-only operations.
Resume erases nothing and cannot clear outcome-unknown. It never changes the
anchor.

The occurrence count and exclusive expiry bound every enrollment. Exhaustion
requires a new operator enrollment. Before origin/provider work, the one-shot
command also checks exact store-size and filesystem free-space bounds captured
from the deployment profile. It never deletes evidence to make room.

## Coordination domains and fencing

A valid acquisition is not necessarily schedulable concurrently with another
valid acquisition. Local permission does not imply compositional
schedulability.

Each deployment-mapped domain has one durable holder acquisition and monotonic
fencing epoch. A process-local kernel lock closes concurrent local evaluation;
append-only coordination events make ownership reconstructible after restart.
Provider-safe start spacing applies across different watchers in the same
domain. Contention is a scheduling deferral, not watcher refusal, provider
failure, or diagnostic result. It never moves cadence.

The provider fence binds the acquisition, enrollment, deployment profile,
watcher semantic digest, coordination domain/epoch, exact Linode V3 profile,
expected coordinate, issuer, and helper key. The acquisition completes under
that snapshot even if a later deployment profile is activated.

> Lease expiry is not proof that provider-side work stopped.

> Policy changes do not reinterpret historical or in-flight acquisition
> occurrences.

> Local permission does not imply compositional schedulability.

No generic distributed lock manager is introduced. The domain ledger exists
only around bounded diagnostic provider custody. The first eligible claimant
whose exact domain claim commits durably holds the domain; every losing claim
is an inspectable deferral. V1 introduces no priorities or general fairness
scheduler. Finite enrollments and provider-safe release prevent any claimant
from holding unbounded authority, and a blocked slot does not accumulate future
authority.

## Read-only projections and independent systems

`recurring status` derives enrollment policy, remaining budget, highest slot,
next due time, in-flight and last-completed acquisition, failure streak,
skipped ranges, storage guard, domain holder/epoch, safe-start time, and
outcome-unknown fence from immutable records. There is no mutable `latest`
authority record or health score.

NQ recurrence never creates a Nightshift cycle. Nightshift consumes an exact
acquisition only through its separate lifecycle. Present-support evidence
cannot create an NQ trigger, advance slots, reset recurrence failures, or mint
enrollment authority.

## Deployment

The optional `nq-recurring-office.service` is a bounded one-shot process. Its
paired timer is installed disabled. Before enabling it, an operator must write
an exact enrollment ID to root-owned `/etc/nq/recurring-office.env`, validate
the deployment profile and enrollment, and separately qualify cadence,
retention/archive operations, failure escalation, and host principal custody.
V1 never enables a timer during package installation.

What remains external/manual: policy registration/activation, finite
enrollment, admission renewal, invoking exact outcome-unknown reconciliation,
pause/resume/revoke, archive/store-generation rotation, Nightshift cadence, and
any decision to enable a real-host timer.

The production operator surface keeps each authority transition explicit:

```sh
nq --config /etc/nq/nq.toml recurring policy-register /path/policy.json
nq --config /etc/nq/nq.toml recurring policy-activate POLICY_ID \
  --operation-id OPERATION_ID
nq --config /etc/nq/nq.toml recurring enroll /path/enrollment.json
nq --config /etc/nq/nq.toml recurring tick ENROLLMENT_ID
nq --config /etc/nq/nq.toml recurring status ENROLLMENT_ID
nq --config /etc/nq/nq.toml recurring reconcile ACQUISITION_ID
```

`policy-register`, `policy-activate`, and `enroll` are operator actions.
`tick` is the sole service-manager entry point and is safe to duplicate. Pause,
resume, and revocation likewise require an explicit caller-owned operation ID
and retained reason:

```sh
nq --config /etc/nq/nq.toml recurring pause ENROLLMENT_ID \
  --operation-id OPERATION_ID --reason REASON
nq --config /etc/nq/nq.toml recurring resume ENROLLMENT_ID \
  --operation-id OPERATION_ID --reason REASON
nq --config /etc/nq/nq.toml recurring revoke ENROLLMENT_ID \
  --operation-id OPERATION_ID --reason REASON
```

`reconcile` is not resume and is not retry. It consumes only retained exact
custody, performs no provider invocation, and releases only the matching
outcome-unknown domain fence. The separate `resume` operation records the
operator decision to allow later finite slots after reconciliation.

Production policy/specification files are deployment- and operator-owned exact
inputs. Passing a different pathname with similar prose does not establish an
equivalent policy or enrollment.
