# Passive load operational continuity V1

This document governs useful-period operation of the one closed passive
boundary in [`PASSIVE_LOAD_SAMPLING_V1.md`](PASSIVE_LOAD_SAMPLING_V1.md). It
does not change the `nq.host.load_pressure/v1` proposition, watcher admission,
diagnostic recurrence, origin proof, support evidence, or Nightshift.

> Continuous operation is a sequence of bounded grants, not an unbounded grant.

> Sampling creates observations, not diagnostic occurrences.

> Diagnostic recurrence consumes observations, not sampling authority.

> Nightshift reasoning remains an independent clock.

## Three clocks and three layers

The deployment owns three independent clocks. An observer generation schedules
raw kernel sampling. An immutable finite NQ recurrence enrollment schedules
diagnostic acquisition occurrences. Nightshift owns any separately governed
reasoning cycle. Divisibility or coincident wakeups do not transfer authority
between them.

The implementation also separates three policy layers:

1. Protocol invariants are not configurable. Samples and timestamps are
   immutable; one deterministic sampling slot has at most one sample; replay
   never samples; acquisition never invokes or renews the observer; the
   observer never creates NQ or Nightshift occurrences; referenced custody is
   never opportunistically deleted; context drift refuses; and exhausted,
   retired, or key-revoked generations never reopen.
2. `nq.passive_load_operational_policy.v1` is a content-addressed,
   deployment-owned safety envelope. It bounds cadence, scheduling
   granularity/jitter, generation duration/count/store bytes, free space,
   failure escalation, sample eligibility, key overlap, startup modes, and
   retention modes. The policy creates no sample or acquisition authority.
3. `nq.passive_load_observer_generation.v1` contains one immutable operator
   selection inside that envelope and embeds the exact policy snapshot. A
   changed selection is a new generation identity.

Configuration may tune cadence and resource budgets. It may not tune away
identity, custody, temporal, capacity, vantage, concurrency, or finite-authority
invariants.

## Observer generation

An observer generation binds the exact executable/profile, subject/scope/local
vantage, capacity-context digest, raw sample schema, signing key and acceptance
window, fixed sampling anchor/interval, explicit startup law, exclusive
not-before/expiry, finite sample count, store/free-space bounds, failure-pause
threshold, retention mode, eligibility horizon, operator occurrence, and
deployment-policy identity. Its ID is the SHA-256 digest of its exact canonical
JSON bytes. The same digest is the existing V1 sample's
`observer_config_digest`, so no sample-schema churn is needed.

The generation grants only permission for that deployed observer to create raw
samples. It is not watcher admission and grants no diagnostic or reasoning
authority. Both `max_samples` and an exclusive expiry are mandatory. Reaching
either makes later sampling return an exhausted projection. There is no
automatic successor generation or recurrence enrollment.

Renewal materializes a new canonical generation. It requires the exact
predecessor, a distinct operator occurrence and store, unchanged
subject/vantage/capacity context, non-overlapping sampling windows, and bounded
key overlap. G1 remains G1; G2 does not rewrite samples, timestamps, gaps, or
sequence history from G1. V1 deliberately has no recursive renewal grant.

## Sampling slots and startup

Sampling slots are deterministic and independent of NQ recurrence slots:

```text
slot_index = floor((now - sampling_anchor) / sample_interval)
slot_id = digest(generation_id, slot_index, scheduled_for)
```

The immutable generation selects one closed startup law:

- `wait_for_next_sample_slot` excludes the slot open when the generation was
  materialized;
- `sample_current_slot` permits that exact current slot.

Repeated wakeups, duplicate starts, or restart within one slot converge on its
one stored sample. Missed slots are gaps and are never backfilled. Clock
rollback cannot reopen a sampled slot. Clock forward selects only the current
slot; it does not burst through history. `observed_at` is the sampling
occurrence time, not slot time, retrieval time, file mtime, NQ trigger time, or
Nightshift time.

The long-lived process shape is retained because a per-sample process spawn
would reintroduce the load perturbation this boundary was created to avoid.
The process sleeps between fixed slots and reads only `/proc/loadavg` plus the
qualified `available_parallelism()` context. Its stable bounded overhead is
part of the deployed observation environment; it is not claimed to be free.

## Restart, failure, and drift

The static systemd unit uses `Restart=on-failure`. Restart is process recovery,
not generation authority: every open revalidates the exact executable,
generation bytes, current deployment policy, key, capacity context, samples,
events, count, expiry, and terminal state. The helper exits successfully when
exhausted, paused, retired, or key-revoked, so service-manager restart cannot
extend the grant. Duplicate starts converge through the store's durable writer
lock.

The closed operational failures are source/read failure, store/write failure,
signing/key failure, capacity/vantage drift, storage refusal, generation
exhaustion, operator retirement, and unexpected process exit. Failure events
are append-only. Successful durable sampling resets the projected consecutive
failure streak; restart does not. Reaching the selected bounded threshold
pauses the generation. Capacity-context drift, storage refusal, retirement,
and key revocation are terminal for that generation. Corrective deployment
review and a new exact generation are required.

`Cpus_allowed_list`, cgroup-v2 `cpu.max`, `cpuset.cpus.effective`, subject,
scope, vantage, executable, or key drift cannot be normalized away. The pinned
capacity-context digest is re-derived before each sample. A changed runtime
context produces no sample under the old identity.

## Signing-key generations

Each sample identifies one issuer and key ID and carries an Ed25519 signature.
The immutable generation binds the public key and the private-key custody path,
plus inclusive activation and exclusive retirement boundaries. Software key
custody authenticates the deployed sample producer; it is not hardware-bound
or non-exportable identity.

Rotation associates K2 with a new generation G2. K1 remains in G1's immutable
metadata, so historical G1 samples stay verifiable after K1 is no longer
accepted for new sampling. Policy bounds any K1/K2 acceptance overlap, and a
key-revocation event immediately stops new samples under its generation. It
does not erase or invalidate already admitted historical signatures. Both keys
are never accepted for arbitrary new samples indefinitely.

## Storage, retention, and replay

V1 exposes only the closed retention mode `retain_all`. Every observer
generation has a distinct bounded active store, maximum sample count, byte
ceiling, and required-free-space floor. Before writing a sample the observer
checks these guards and refuses rather than deleting history. Samples and
events are create-new canonical files followed by file and directory sync.
Malformed or partial files are never selectable; store corruption fails
closed.

No archive-generation machinery is implemented in V1. Finite generation
bounds make it unnecessary for the qualified bounded operating window. A
future archive is earned only when measured growth requires it and must retain
byte-exact sample identity, a content-bound manifest, exact referenced-sample
lookup, and seal/reopen proof before active custody can be removed.

The active sample store has no mutable `latest` authority pointer. “Latest” in
status is a projection over canonical records. NQ binds an exact signed sample
and retains its exact provider intake/artifact/provenance, so replay neither
reopens the observer nor resamples. V1 retain-all also keeps the source sample
available. A sample referenced by retained diagnostic custody cannot be
deleted by operational retention.

An unreferenced sample becomes ineligible only under the fixed sample-age and
pre-launch cutoff law. This V1 still retains it; no claim that “currently
unreferenced” means disposable is made.

## Gaps and expected coverage

Eligibility remains exact: a sample is before the acquisition cutoff and no
older than the configured horizon, with exact subject, vantage, profile,
generation, key, and capacity context. Deployment policy separately validates
expected coverage with the strict relation:

```text
sampling_interval + maximum_scheduling_jitter < sample_eligibility_max_age
```

A normal cadence may therefore be expected to offer a sample, but a gap never
widens eligibility. If no sample qualifies, NQ refuses or performs only its
already-bounded pre-provider reevaluation of the same occurrence. It never
starts the observer, invokes the retired one-shot helper, invents a sample, or
changes the age policy.

Stopping or restarting the observer produces a real gap. G1 ending before G2
begins also produces a real gap. An exact still-eligible G1 sample may be
consumed only when the provider profile, key, capacity context, and temporal
selection law explicitly admit G1; otherwise the acquisition refuses. Renewal
never fabricates samples between generations.

## Recurrence renewal and admission

NQ recurrence enrollment remains the already-qualified finite, immutable
grant. Exhausted E1 creates no new diagnostic occurrences. An operator may
create E2 only through the existing admission and recurrence-policy boundary.
Identical renewed watcher semantics may continue; subject, vantage, profile,
provider, evaluator, origin, or admission drift refuses and requires a new
exact watcher/admission decision.

Observer renewal does not renew recurrence. Recurrence renewal does not renew,
start, stop, or reconfigure the observer. A new passive provider generation is
content-bound in the watcher/provider request, so deployment performs an exact
admission/enrollment transition rather than silently transferring an old
provider identity.

## Operational status

`generation-status` is a read-only projection over the exact generation,
current and original policy IDs, signed samples, and append-only events. It
exposes state/reason, anchor/interval, next slot, exclusive bounds, produced and
remaining samples, last sample, failure streak/reason, missed slots, byte/free
space guards, key identity/window, capacity context, retention mode, and prior
generation. It creates no sample.

The existing NQ recurrence status independently exposes watcher/admission,
enrollment, recurrence slot, remaining acquisition budget, provider profile,
coordination/failure state, and exact acquisition history. Nightshift status is
not projected as evidence by either component. A human-facing three-clock
summary may compose these read-only projections, but no single green/red office
health flag becomes authority.

## Service-manager and policy change law

Package installation creates only service identities and empty bounded
directories. It creates no policy, generation, key, enrollment, or sample, and
starts/enables nothing. The observer unit is static and has no `[Install]`
section. The NQ recurring-office timer remains a separate optional wakeup whose
cadence is not sampling cadence.

A tightened deployment policy is checked before each future sample and may
pause an active generation; it does not rewrite history. A broadened policy
does not enlarge an immutable generation's interval, count, expiry, storage,
failure, or key terms. Semantic change requires a new materialized generation.
The fixed `/etc/nq` service arguments are deployment locators only; replacing
them while the unit runs is not supported and does not change already persisted
sample identity.

## Historical A4 and nonclaims

A4 remains an `outcome_unknown`, provider-activity-unknown occurrence under the
retired one-shot-helper boundary, with its original epoch-1 coordination fence.
The passive operational lifecycle neither releases, migrates, reinterprets,
nor reuses A4 or its coordination domain. It governs a genuinely different
provider boundary.

This feature is not a metrics platform, time-series query system, arbitrary
sensor registry, cron language, alert manager, dashboard health score, command
runner, archive/backup system, generic PKI, or Nightshift scheduler. It does
not prove zero observer effect, hardware key custody, indefinite disk safety,
physical-host identity, or long-running production cadence. Those claims need
their own evidence and authority.

## Enabled operational pilot standing

The bounded live pilot in
[`PASSIVE_LOAD_ENABLED_PILOT_2026-08-26.md`](PASSIVE_LOAD_ENABLED_PILOT_2026-08-26.md)
qualified real service-manager operation through one G renewal and one
independent E renewal. It also established the operational ordering law:

```text
new provider-bound watcher configuration
→ first independently produced sample
→ watcher admission
→ exact genesis
→ finite recurrence enrollment
→ timer activation
```

The recurrence timer must remain paused until admission and genesis are
complete. Duplicate timer delivery correctly consumes only the bounded
pre-provider attempt budget, but consuming that budget during deployment is an
operational defect rather than useful observation.

The pilot used 15-second sampling and five-minute diagnostics. A planned
observer restart left an exact gap; recurrence during the gap persisted a
governed missing-sample refusal and did not fall back. Expired G and E grants
refused service-manager restart/wakeup without producing new work. Closeout
left all services inactive and the timer disabled.

The current 15-minute G and 10-minute E deployment limits remain qualified but
are intentionally too short for unattended production. Longer finite grants
or a finite higher-level renewal grant require a separate policy campaign; the
enabled pilot does not imply them.
