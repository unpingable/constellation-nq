# Provider-operation noninterference V1

This campaign asks two questions without collapsing them:

1. Does exact A4-bound evidence establish its result, non-invocation, or
   provider quiescence?
2. Even if A4 remains active, may another exact provider operation overlap it
   without invalidating either operation?

The first answer is no. The second answer is also no for the exact
`labelwatch-host-local` load-pressure operation. A4 remains diagnostically and
provider-activity unknown, and `linode:labelwatch-host` remains fenced.

## Bounded A4 archaeology

A4 is:

```text
acquisition  recurrence:d555a10d2b4f11e7c6d550f43a6fd6d07631573bec5c14b54d09ca6b8e04beea
enrollment   sha256:37878cc8a3e2342be8e3dfbc6b3d93ad0fe7a3d9574a3f1237dd83a52c53935c
slot         sha256:d555a10d2b4f11e7c6d550f43a6fd6d07631573bec5c14b54d09ca6b8e04beea
epoch        1
run          cc82da86-0fc1-4f76-acbc-fd14e213bdef
request      a3232fc8-ba24-4b40-9528-b5e96797fb7f
attempt      23fe06d4-f987-4a56-a7d4-0a9ac1f03474
```

The exact substrate-origin intent and its pre-provider event survive. The
recurrence ledger records `provider_invocation_started` followed by
`outcome_unknown`. No provider intake, diagnostic artifact,
`nq.provider_activity_evidence.v1`, or provider-activity reconciliation is
present for A4.

The old event's diagnostic says that the provider path returned before a later
evaluator-admission refusal. It is not the typed, A4-bound process-group
supervision receipt required by the qualified reconciliation law. Current
process absence, service inactivity, journald text, elapsed time, and the lack
of intake are not substitutes. The local helper exposes no independent
request-status API. The Linode metadata service proves acquisition origin, not
the state of the diagnostic helper process. Archaeology therefore terminates
as:

```text
no exact A4-bound result or provider-activity evidence exists
```

No result or quiescence reconciliation is applied.

## Exact operation class

The operation under A4's provider fence is not a generic Linode API read. It is
the admitted local helper executable:

```text
/opt/nq-ng/linode-v3-20260824/bin/nq-host-helper
sha256:a0665c7ec0d21dc321f4f7e9a08183787bce55c38e92603a1160f047bef993de
```

running as `nq-helper`, with profile `nq.host/v1`, local vantage, host scope,
and the fixed capabilities `read_procfs` and `read_system_info`. It receives
one `nq.helper.v1` request through stdin and emits at most one bounded response
frame through its own stdout pipe. It opens no network endpoint and invokes no
backend command or shell.

Its exact content-derived operation-class identity is:

```text
sha256:e46d9c18ca22579a4e00ccfc92ad923b50a345016b7e0944c2818ddfd65d1fda
```

The identity basis is stored in
`audit/provider-operation-noninterference/labelwatch-host-load-pressure-v1.json`
under schema `nq.provider_operation_class_basis.v1`. It binds provider and
execution identities, helper bytes and process model, subject/scope/vantage,
logical-instance coordinate, profile and detector semantics, request bounds,
and these four bounded observation methods:

* read at most 4096 bytes from `/proc/uptime`;
* read at most 4096 bytes from `/proc/loadavg`;
* call `gethostname`;
* call `std::thread::available_parallelism`.

The Linode V3 origin helper runs before this provider operation. It is a
prerequisite of the acquisition but is not the provider result whose activity
became unknown in A4.

Any binary, execution identity, provider semantic, profile, subject, scope,
vantage, coordinate, capability, method, or bound drift creates a different
operation class. A watcher or enrollment cannot nominate the class itself.

## Read-only is not noninterference

The helper contains no write, command, or network acquisition surface. That
supports a narrow world-effect statement, but it does not support compositional
noninterference for `nq.host.load_pressure/v1`.

Linux defines `/proc/loadavg` in terms of jobs that are runnable or waiting for
disk I/O. Launching another origin/helper acquisition creates additional
processes and scheduled work on the same monitored host. An indefinitely
active A4 may itself remain runnable or uninterruptible. The detector then
computes:

```text
load_1m / cpu_count >= 2.000
```

with an inclusive threshold. A load perturbation around that boundary can
change the diagnostic conclusion. The observation mechanism is therefore part
of the world relevant to its own proposition. Reading a kernel file is
non-mutating at the file API, but the process doing the reading is not absent
from scheduler state.

The authoritative semantic references used for this conclusion are:

* Linux `proc_loadavg(5)`: <https://man7.org/linux/man-pages/man5/proc_loadavg.5.html>
* Linux `/proc` documentation:
  <https://www.kernel.org/doc/html/latest/filesystems/proc.html>
* Rust `available_parallelism` limitations:
  <https://doc.rust-lang.org/stable/std/thread/fn.available_parallelism.html>

No source promises that an unknown prior helper and a successor helper can
overlap without affecting load, resource availability, timing, or the derived
proposition.

> Read-only is a property of effects. Noninterference is a property of
> composition.

## Dimension result

The exact R-to-R assessment is deliberately not a `safe` boolean.

| Dimension | Standing | Reason |
| --- | --- | --- |
| World-state | Refuted | Helper and origin acquisition processes participate in the observed host scheduler/resource state. |
| Evidence attribution | Qualified locally | Descriptor-bound one-shot processes have distinct request identities, process groups, pipes, captures, and occurrence custody. |
| Semantic | Refuted | Overlap can perturb `load_1m` across the inclusive detector threshold. |
| Provider safety | Unqualified | No contract bounds an indefinitely active old helper's combined scheduler/process/memory/cgroup use with a new acquisition. |
| Local runtime | Qualified locally | The helper has no persistent state, mutable file, network session, shell, or shared stdout/stderr channel. |

Separate-process concurrency tests prove only attribution and local-runtime
isolation. They cannot prove that the measured host proposition is unchanged.
No live Linode overlap test is run: doing so while A4 may still be active would
exercise the unqualified composition through the very fence under review.

## Fence scopes and the refused narrowing

Three concepts remain distinct:

* an occurrence fence prevents A4 from reinvoking;
* an operation-class overlap fence would prevent only unsafe class pairs;
* the current coordination-domain fence conservatively prevents all later
  provider starts in the deployment-declared shared boundary.

A future protocol may narrow a domain fence only when an exact, independently
qualified directed class-pair relation covers every required dimension and the
deployment safety envelope permits the overlap. Configuration cannot create
that relation. Deployment and enrollment may be stricter, never broader.

For the exact class above, the required relation is not qualified. There is no
runtime fence-narrowing event, no policy flag, and no acquisition after A4.

```text
A4 outcome_unknown
+ A4 provider_activity_unknown
+ R-to-R noninterference_not_qualified
-> whole coordination domain remains fenced
```

This result does not classify A4 and does not fabricate quiescence.

> Noninterference can remove the need to wait for an unknown operation to
> finish. It cannot tell us what that operation concluded.

## Late result and replacement boundaries

Exact late A4 result custody, if it ever appears, remains A4-bound and may use
the existing result-reconciliation path. It cannot capture a later occurrence,
and stale epoch 1 cannot regain coordination ownership. No later occurrence
exists today.

If A4 can never be reconciled, an operator may retire the finite enrollment or
permanently abandon the domain while retaining its fence and history. A
replacement domain is valid only when provider/deployment topology proves an
actually independent subject/resource, state, rate, and acquisition boundary.
Changing a string is not evidence.

> A renamed coordination domain is not an independent system.

## Nonclaims

This campaign introduces no generic concurrency algebra, distributed lock
manager, overlap configuration, provider scheduler, new acquisition, A4 retry,
Nightshift cycle, support event, or live timer. The existing exact-result and
provider-quiescence laws remain unchanged.
