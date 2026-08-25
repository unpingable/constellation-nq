# Outcome-unknown provider-fence disposition V1

This contract answers one narrow question: what may NQ do after a recurring
acquisition crossed its provider-invocation fence but exact local custody cannot
reconstruct the diagnostic result? It adds no operator override and no provider
retry.

## Two independent facts

Diagnostic outcome and provider activity are separate dimensions. A diagnostic
may have an exact result, an exact provider failure, or remain `outcome_unknown`.
Provider activity may be definitely absent, proven terminal/quiescent, or
unknown. The important reachable state is:

```text
diagnostic outcome: unknown
provider activity:  quiescent
coordination:       released
```

> A diagnostic result may remain unknown forever even after provider activity
> is known to have ended.

The coordination fence prevents overlapping provider work. Its release requires
proof that overlap risk is gone; it does not require or invent a diagnostic
result.

## Closed taxonomy

* `reconciled_result`: exact local intake/artifact custody reopens. Existing
  exact-result reconciliation appends `provider_succeeded` and releases the
  exact fence.
* `provider_not_invoked`: the closed local supervisor proves spawn never
  succeeded. A later outcome-unknown fence may be released without reopening
  that acquisition.
* `outcome_unknown_provider_quiescent`: the closed local supervisor proves the
  exact helper process group terminated and was reaped. Coordination may be
  released while the acquisition remains `outcome_unknown`.
* `outcome_unknown_provider_activity_unknown`: no admissible evidence exists;
  the domain remains fenced.
* enrollment retirement: append-only revoke ends future authority but does not
  classify the acquisition or release an unknown provider fence.

There is no `force`, `clear`, `unlock`, risk-acceptance, timeout, lease-expiry,
restart, policy-change, or rename path to release an unknown fence.

## Evidence and producer

`nq.provider_activity_evidence.v1` binds the exact acquisition, enrollment,
slot, coordination domain, fencing epoch, recurrence attempt, provider request,
provider attempt, watcher run, provider semantic/artifact/execution identities,
closed runner outcome, producer, and observation occurrence. Its content-derived
identity excludes its outer identity field. It has no diagnostic result,
artifact, report, condition, Nightshift, support, or effect-authority field.

V1 has one producer:

```text
nq.local_stdio_process_group_supervision.v1
```

NQ emits `provider_not_invoked` only for an exact spawn failure. It emits
`provider_quiescent` only for closed stdio outcomes reached after the bounded
runner terminated/reaped the process group. Persistent-carrier and ambiguous
I/O/wait outcomes emit no activity evidence and remain fenced. Evidence is
persisted after capture and before fallible intake, parsing, evaluation, or
artifact custody, so a later local failure cannot erase the already-proven
provider fact.

This is local-supervisor evidence, not a remote-provider status API and not a
claim that an external provider honors NQ fencing epochs. A remote operation
already accepted beyond this process boundary would require its own exact
provider reconciliation contract.

## Commands and transitions

`recurring inspect-fence ACQUISITION_ID` is read-only and shows diagnostic
outcome, provider activity, coordination state, epoch, evidence, reconciliation,
and reason separately.

`recurring reconcile ACQUISITION_ID` retains its existing exact-result law. It
has no provider source and refuses missing/partial custody.

`recurring reconcile-provider ACQUISITION_ID --enrollment-id ...
--coordination-domain ... --fencing-epoch ... --evidence-id ...` consumes only
preexisting local provider-activity evidence. Exact acquisition/enrollment/
slot/domain/epoch/attempt/provider bindings must match. Acceptance and release
are one transaction. Duplicate delivery converges. A conflicting evidence or
target substitution refuses.

The provider-activity transition is:

```text
outcome_unknown + provider_activity_unknown + exact activity evidence
  -> append provider-activity reconciliation
  -> append exact coordination release
  -> outcome_unknown + provider_activity_known + coordination released
```

No recurrence acquisition event is rewritten. If stronger exact result custody
arrives later, exact-result reconciliation may append the result while retaining
the earlier activity evidence. Both facts survive.

After release, a future eligible recurrence slot must still pass admission,
finite enrollment, deployment policy, storage guard, and coordination. It
creates a new acquisition and a strictly higher fencing epoch. Release itself
creates no slot, acquisition, provider invocation, origin evidence, support
evidence, Nightshift cycle, or diagnostic conclusion.

## Time, retirement, and permanent uncertainty

Elapsed time, recurrence interval, enrollment expiry, process/service/host
restart, provider timeout, operator pause/resume, or deployment-policy
replacement never proves quiescence. Revoking an enrollment safely retires its
future finite authority but leaves any unresolved coordination fence intact.
Renaming a domain cannot establish resource independence and is not a bypass.

If exact result custody and admissible provider-activity evidence are both
unavailable, the only sound state is a dormant office with the domain still
fenced.

> Coordination may resume when overlap risk is proven gone. That does not
> rewrite epistemic history.

> An operator may acknowledge uncertainty. An operator may not manufacture
> quiescence.
