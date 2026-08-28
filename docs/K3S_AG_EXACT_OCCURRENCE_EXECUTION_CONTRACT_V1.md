# NQ k3s / AG exact-occurrence execution contract V1

Status: **TURNSTILE T0-T3 implemented; primitive adjudicated separately**

Campaign: `TURNSTILE`

Campaign slug: `k3s-ag-exact-occurrence-adapter-v1`

The original entry-gate classification in this document was
`PASSIVE-K3S-AG-EXECUTION-CONTRACT-SPECIFIED-ADAPTER-BLOCKED`. TURNSTILE then
implemented T0-T3 on the scoped successor branch. The post-T3 primitive
decision is recorded in `K3S_AG_TURNSTILE_PRIMITIVE_DECISION_V1.md`; this
document remains the constitutional contract and historical entry decision.

This document specifies the narrow boundary by which an already-prepared NQ
occurrence could be governed by AG, custodied by Docket, and executed by
Kubernetes without granting semantic authority to Kubernetes.  It is not an
implementation, a deployment grant, an NQ occurrence, an AG authorization, or
a Kubernetes manifest.

The current repositories do not yet expose the NQ half of this boundary.  The
precise stopping condition is in [Current interface decision](#current-interface-decision).

## Constitutional ownership

The only admissible composition is:

```text
NQ finite authority and exact prepared occurrence
  -> fresh qualified observation and standing
  -> AG exact-occurrence admissibility and one-use authorization spend
  -> Docket fresh execution standing, exact attempt custody, and dispatch
  -> authority-neutral k3s executor adapter
  -> one non-reconciling bare Pod for the already-authorized occurrence
  -> durable NQ and adapter evidence outside Pod-local state
  -> Docket settlement or outcome_unknown
  -> fresh observation before any successor
```

The roles are non-convertible:

* NQ owns diagnostic, passive-sampling, recurrence, grant, watcher, admission,
  provider-fence, and exact sample-custody semantics.
* AG owns admissibility and one-use authorization for one exact work
  occurrence.  A proposal or prepared NQ object is not AG authority.
* Docket authenticates the spent AG issuance, consumes its separate execution
  standing, assigns one attempt and marker, retains dispatch/outcome custody,
  and settles or preserves an indeterminate result.  Docket does not mint NQ
  authority and a settlement does not retroactively authorize execution.
* The adapter owns only Kubernetes mechanics, a durable idempotency journal,
  and mechanics receipts.  It cannot prepare, admit, renew, or succeed an NQ
  occurrence.
* Kubernetes schedules and runs the exact submitted Pod.  Namespace, RBAC,
  admission policy, object existence, desired state, status, retry, and
  reconciliation are facts and permission boundaries, never semantic
  authorization.

Docket's frozen `docket.governed-executor-transport/v1` is the transport.  A
new authorization token, Docket command, Kubernetes custom authority object,
or Docket-as-policy service is forbidden.

## Required immutable NQ execution plan

Before AG proposal recording, NQ must be able to produce one canonical,
create-once `nq.k3s_exact_occurrence_execution_plan.v1`.  Its content digest is
the Docket executor plan identity and AG exact work identity.  The plan must
bind at least:

* the exact NQ occurrence/acquisition identity and occurrence schema;
* H, G, E, watcher, admission, recurrence-enrollment, succession-edge, and
  provider-fencing identities applicable to that occurrence;
* recurrence slot, cutoff, preparation expiry, maximum launch time, and the
  no-catch-up law;
* coordination domain and the exact provider-safe-spacing requirement;
* exact subject, scope, vantage, origin profile, capacity context, and passive
  sample-selection contract;
* qualified NQ source commit, OCI manifest digest, executable digest, helper
  digest, configuration digests, and command/arguments;
* Kubernetes cluster identity, namespace name and UID, execution service
  account name and UID, and the admitted mechanics policy identity;
* the deterministic Pod-name derivation rule, required closed Pod spec, and
  the prohibition on owner references and controller-managed workload kinds;
* persistent NQ custody volume identity, external adapter-journal identity,
  external receipt destination, retention law, and capacity guard; and
* the exact terminal-result and closeout policy.

The plan must not contain an AG issuance or Docket attempt: those values do not
exist when AG binds the plan and including them would create a digest cycle.
Instead, the immutable identity is the following verified graph:

```text
AG issuance.work == SHA256(canonical NQ execution plan)
Docket custody binds issuance -> attempt -> marker
Docket dispatch repeats plan digest, subject, and scope
adapter plan-id remeasures the canonical plan
Pod name = deterministic_name(Docket attempt)
Pod annotations bind attempt, marker, plan digest, and NQ occurrence
mechanics receipt binds Pod UID and first container ID to that graph
```

The Kubernetes-assigned Pod UID is the exact runtime-instance identity.  It is
not knowable at authorization time, so it is a result-side binding, not a
precondition smuggled into the plan.  A later Pod with the same name and a
different UID is a different runtime instance and is not authorized.

## NQ preparation boundary required before AG

NQ needs a split-phase, fail-closed API with these semantic operations:

1. `prepare-exact-occurrence` performs the existing recurrence, grant,
   admission, succession, coordination, storage, and bounded-selection gates;
   allocates one exact NQ occurrence; and publishes the immutable execution
   plan.  It does not commit the provider-invocation fence and cannot invoke a
   provider or create Kubernetes state.
2. `execute-prepared-occurrence` accepts only that exact prepared identity plus
   the Docket dispatch binding.  Immediately before provider launch it
   revalidates current grant/enrollment state, coordination ownership,
   provider-safe spacing, selected-sample eligibility, exact retained sample
   bytes, artifact/configuration identity, and preparation expiry.  It then
   atomically commits the existing NQ provider fence before any provider
   mechanics.
3. `reconcile-prepared-occurrence` is read-only with respect to provider
   mechanics.  It may derive success only from exact retained NQ custody,
   definite non-occurrence/failure only from qualified evidence, and otherwise
   records or returns `outcome_unknown` while retaining the fence.
4. `retire-prepared-occurrence` makes a never-executed prepared object
   terminal.  Expiry, revocation, or refusal cannot make it reusable or permit
   self-activation.

Preparation may consume the one selected recurrence slot only if that is
explicitly ratified as the NQ occurrence-allocation boundary.  It may never
consume a provider attempt or claim provider invocation occurred.  If AG or
Docket is unavailable after preparation, the object remains inert until it is
lawfully executed or terminally retired.  No timer or Kubernetes controller
may activate it.

This split is constitutional rather than mechanical because the current NQ
command performs occurrence creation, coordination claim, provider fencing,
and provider execution within one operation.  It cannot be emulated by parsing
CLI output after provider invocation.

## Creation contract

Kubernetes may create the first runtime object only after all of the following
are true:

1. AG has durably spent authorization for the exact plan digest.
2. Docket has authenticated that issuance, freshly resolved and consumed its
   execution standing, and durably assigned the attempt and marker.
3. The adapter has remeasured its executable, configuration, plan, cluster,
   namespace, service account, image digest, evidence destinations, and NQ
   prepared occurrence.
4. The adapter has inserted an external durable reservation keyed uniquely by
   NQ occurrence, Docket attempt, marker, and Pod name.
5. NQ's `execute-prepared-occurrence` consequence-time checks have succeeded
   and its provider fence is durably committed.

The adapter then performs one create-only request for one bare `Pod`.  It must
not use `Deployment`, `ReplicaSet`, `StatefulSet`, `DaemonSet`, `Job`,
`CronJob`, or an owner reference.  The Pod uses `restartPolicy: Never`, one
authority-bearing NQ container, an image by immutable digest, no mutable image
tag, `automountServiceAccountToken: false`, a fixed security/resource context,
and an exact deadline.

`AlreadyExists` is never automatic success.  The adapter must retrieve the
object and require exact name, namespace UID, Pod UID retained in its journal
if already known, closed spec, annotations, image digest, service account,
volume bindings, and absence of owner references.  A mismatch is a refusal and
the result remains indeterminate after the provider fence.

## Reconciliation, replacement, and retry

Kubernetes recreation is never a semantic continuation by default.  V1 uses
this closed rule:

* The same Pod UID with the same first container ID and `restartCount == 0`
  may continue the same exact occurrence.
* A different Pod UID, a different authority-bearing container ID, or a
  positive restart count is a different runtime execution.  It has no
  authority under the old occurrence and must be refused/fenced.
* Deletion, eviction, node loss, kubelet restart, cluster restart, or scheduler
  relocation that loses the original runtime identity does not authorize a
  replacement.  The exact attempt is reconciled from durable evidence; absent
  a qualified terminal result it becomes `outcome_unknown`.
* A fresh execution after a definite terminal failure is a new NQ occurrence,
  a fresh AG authorization, and a fresh Docket attempt, subject to the existing
  bounded successor law.  It is never a Kubernetes retry.

The adapter's `execute` operation may invoke create mechanics once only after
its reservation commits.  Repeated identical Docket dispatch returns the
retained terminal result or reports the existing in-progress/indeterminate
state; it never creates another Pod.  A same-attempt substitution refuses.
The adapter's `reconcile` operation never creates, restarts, patches, or
replaces a workload.

`Job` is deliberately excluded even with `parallelism: 1`, `completions: 1`,
`backoffLimit: 0`, and `restartPolicy: Never`: the Job controller owns Pod
replacement behavior and Kubernetes documents that the same program may be
started twice.  A bare Pod makes every replacement an explicit external
operation that the adapter can refuse.

## Replica and concurrency law

V1 has no replica field and accepts no controller-managed object.  A manifest
containing replicas, parallelism, completions, owner references, init
containers that can perform NQ work, sidecars with NQ credentials, or more than
one authority-bearing container is outside the closed plan and refuses before
creation.

The canonical concurrency fence is the external adapter journal, not a
Kubernetes Lease.  It has unique durable keys for NQ occurrence, Docket
attempt, marker, and derived Pod name and is shared by every adapter process in
the enrolled execution domain.  Kubernetes API name uniqueness is a second
mechanical race fence.  A Lease may provide additional coordination but is
mutable cluster state and never becomes evidence of authority.

Two independently configured Docket custody roots for the same AG issuer and
execution domain are a deployment-invalid state.  Namespace separation cannot
launder that duplication into independent authority.

## Durable evidence custody

No qualification evidence may exist only in an ephemeral container layer,
Pod log buffer, Event, status field, ConfigMap, Secret, or Kubernetes object.
The deployment must provide two independently inspectable stores:

1. NQ's canonical retain-all custody on a persistent volume whose storage
   identity, placement, capacity, ownership, and retain/reclaim behavior are
   in the execution plan.  The bounded-selection index remains derived and
   reconstructible; normal selection follows immutable manifests and verifies
   only the selected canonical sample.
2. The adapter's append-only external journal and receipt store outside Pod
   state.  It records the exact plan bytes/digest, dispatch, reservation,
   Kubernetes requests/responses, namespace UID, service-account UID, Pod
   name/UID, node UID, container ID/restart count, image ID, status transitions,
   NQ custody references, deletion/closeout facts, and uncertainty.

The Kubernetes volume's reclaim policy must be `Retain` or an equivalently
qualified external retention mechanism.  Dynamic storage whose default
deletion follows PVC deletion is inadmissible for canonical evidence.  Adapter
receipts are append-only; a replacement runtime may not rewrite an earlier
runtime's result.

## Closeout and non-resurrection

Retirement/revocation first makes the NQ prepared occurrence and all enclosing
H/G/E authority terminal.  The adapter then records a closeout intent, deletes
only the exact Pod UID using a UID/resource-version precondition, observes its
absence, verifies no owner/controller object exists, and appends a terminal
tombstone.  The namespace credential is withdrawn or disabled according to the
deployment contract after evidence capture.

If exact deletion cannot be established, closeout is `outcome_unknown`; the
external fence remains and no successor may cross the same provider boundary.
Deleting a Pod, namespace, Lease, PVC, or adapter database does not count as
semantic retirement.  A retained plan file is inert because only a fresh
spent AG issuance plus Docket custody can reach adapter `execute`, and the
adapter tombstone independently prevents replay.

## Observation projection

AG and Docket must preserve these distinctions without synthesizing agreement:

| Observation | Required projection |
| --- | --- |
| AG spent, Docket not accepted | authorization consumed; no execution result inferred |
| Docket accepted, no Pod identity retained | exact attempt custodied; outcome unknown |
| exact Pod UID running | intended runtime for the custodied attempt; not success |
| same name, different Pod UID | refused resurrection / duplicate runtime |
| Pod deleted before exact result custody | runtime lost; outcome unknown |
| exact NQ terminal evidence retained | executor may return the corresponding bound result |
| executor result retained, Docket ingest interrupted | exact reconciliation required; do not rerun |
| Docket settled | historical attempt outcome; fresh observation required |

Docket records custody and settlement.  It does not reinterpret Kubernetes
status as NQ evidence or use a later receipt to retroactively authorize a
runtime.  AG consumes Docket facts but does not infer NQ currentness from them.

## Required qualification cases

A future implementation must run distinct, identity-separated cases for:

* initial create and exact completion;
* running Pod deletion;
* node/runtime loss and scheduler relocation;
* kubelet, adapter, Docket, and cluster restart;
* duplicate create and concurrent adapter action;
* same-name/different-UID substitution;
* attempted Deployment, ReplicaSet, Job, retry, and replicas-greater-than-one;
* stale prepared-object replay;
* AG unavailable after authorization but before Docket custody;
* Docket/adapter interruption after durable reservation and after API create;
* runtime completion with interrupted result ingestion;
* revocation/retirement while the Pod remains desired or running;
* persistent-custody restart with stale derived selection metadata;
* concurrent append and bounded selection; and
* complete closeout followed by attempted resurrection.

Every case must classify continuation, refusal, fresh-authority requirement, or
`outcome_unknown` from exact evidence.  Test names historically using broader
language are ordinary negative qualification and state-transition-race cases.

## Current interface decision

The AG and Docket half is narrow enough today:

* AG-NG has an occurrence-bound exact-work proposal, consequence-time
  rechecks, a one-use spend, and a signed issuance.
* Docket's qualified executor transport binds attempt, marker, work schema,
  work, subject, and scope; persists custody before invocation; calls execute
  once; and has a mechanics-free reconcile operation.
* A Kubernetes executor can therefore remain an authority-neutral Docket
  adapter.  No new AG authority type and no Docket authorization role are
  required.

The NQ and deployment half is not present:

1. `nq recurring tick` currently creates/claims a recurrence acquisition and
   proceeds through provider preparation, fence, and invocation in one command.
   It exposes no immutable prepared occurrence that AG can bind and no exact
   execute/reconcile API for a preallocated occurrence.  Post-hoc parsing of
   its output would verify identity only after mechanics began.
2. The current recurrence deployment binding accepts only the Linode origin
   profile and its isolated Linode origin helper.  There is no ratified
   Kubernetes subject/vantage/origin/capacity/placement role that preserves
   NQ claim meaning.
3. The qualified source has no immutable OCI image, Kubernetes execution
   manifest, external adapter journal, or campaign-owned k3s context.
4. The current passive observer law is qualified through a static systemd unit
   and pins systemd/cgroup capacity context.  Translating it to a Pod changes
   placement, restart, capacity, and vantage facts and cannot be represented as
   packaging alone.

Closing items 1, 2, and 4 requires a new NQ constitutional mechanism and
separate semantic qualification, not a narrow mechanics adapter.  Implementing
only a Pod launcher now would leave no exact NQ occurrence for AG to authorize
and would make the Kubernetes launch itself the missing authority transition.

Therefore V1 stops before adapter code or cluster creation.  Re-entry requires
ratification and qualification of the NQ prepared-occurrence split and a
Kubernetes role/origin/capacity contract, followed by an immutable image build.
Only then is the Docket executor adapter a narrow independently testable
implementation.

## Reference behavior

The Kubernetes primitive choice follows the upstream behavior that a Pod UID
defines one Pod lifetime and a replacement has a different UID, while a Job
may start the same program more than once even with one completion and one
parallel slot:

* <https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/>
* <https://kubernetes.io/docs/concepts/workloads/controllers/job/>
* <https://kubernetes.io/docs/concepts/architecture/leases/>
* <https://kubernetes.io/docs/concepts/storage/persistent-volumes/>
