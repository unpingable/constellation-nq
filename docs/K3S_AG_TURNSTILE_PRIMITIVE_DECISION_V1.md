# TURNSTILE Kubernetes primitive decision V1

Campaign: `TURNSTILE`

Campaign slug: `k3s-ag-exact-occurrence-adapter-v1`

Status: **post-T3 primitive decision**

Decision: **one create-only, ownerless bare Pod is the only admitted V1
execution object; Kubernetes Lease is optional secondary race coordination and
is never authority or canonical evidence**

This decision was made only after the following mechanics-independent laws
were implemented and qualified:

* T0 binds one immutable prepared occurrence and the exact-one cardinality;
* T1 separates the sole execute call from mechanics-free reconciliation;
* T2 binds portable cluster, namespace, service-account, placement, resource,
  origin, vantage, procfs, cgroup-v2, and capacity facts; and
* T3 binds OCI artifacts and an external append-only evidence chain.

No Kubernetes primitive can create AG or NQ authority. The primitive carries
an already-authorized exact occurrence into mechanics after the T0/T1 claim.

## Required bare-Pod profile

The adapter may perform one create-only request for one exact Pod after the
prepared occurrence has reached `claimed`. The closed representation must
require:

* deterministic namespace/name from the exact Docket attempt;
* exact namespace UID and service-account UID recheck before creation;
* no owner references and no controller adoption;
* `restartPolicy: Never`;
* one authority-bearing container, no authority-bearing init container or
  sidecar, and no mutable injection;
* an image reference ending in the exact authorized OCI digest;
* fixed command, arguments, environment, mounts, resource envelope,
  RuntimeClass, scheduling constraints, and deadline;
* `automountServiceAccountToken: false` for the NQ runtime unless a separately
  qualified runtime fact acquisition requires a token through a narrower
  projected volume;
* immutable annotations for the TURNSTILE slug, plan, NQ occurrence, AG
  issuance, Docket attempt/marker, artifact digest, custody digest, and
  coordination domain;
* persistent canonical NQ custody and external evidence custody outside
  container-local storage; and
* delete/closeout operations addressed to the exact observed Pod UID, with
  object preconditions where the Kubernetes API supports them.

`AlreadyExists` is observation, not success. The adapter must retrieve the
object and compare its UID and entire closed authority-relevant representation.
Before an exact UID has been durably retained, inability to distinguish the
create result is `outcome_unknown`. After a UID is retained, any different UID
under the same name is an unauthorized runtime replacement and refuses.

The same Pod UID and same first authority-bearing container ID may continue the
same occurrence. A different Pod UID, a changed container ID, or positive
restart count cannot inherit the occurrence. Exact retained evidence decides a
definite result; otherwise reconciliation records `outcome_unknown` and keeps
the occurrence fenced.

## Rejected alternatives

### Deployment and ReplicaSet

Rejected. Desired replica count and replacement reconciliation intentionally
create new Pod UIDs. Scaling, rollout, controller restart, or mutation could
turn desired state into another runtime instance. `replicas: 1` is not exact
cardinality and `replicas > 1` would clone mechanics for one occurrence.

### StatefulSet

Rejected. Stable ordinal/name is not stable runtime identity. Controller
replacement produces a new Pod UID and could execute the same occurrence
again.

### DaemonSet

Rejected. Node membership and controller reconciliation determine Pod
cardinality, which is incompatible with one exact already-authorized
occurrence.

### Job and CronJob

Rejected. A Job controller owns retry/replacement behavior and may start the
program more than once even when parallelism/completions are one and backoff is
zero. CronJob adds recurring authority-like mechanics outside NQ recurrence.
Neither controller may decide whether a fresh exact occurrence exists.

### Static or mirror Pod

Rejected. Kubelet-managed static-Pod recreation is desired-state replacement
outside the adapter's exact create boundary.

### Custom resource/controller

Rejected for V1. A controller could encode the laws, but introduces a new
long-running semantic component, status/reconciliation protocol, upgrade law,
and duplicate-controller fencing problem. T0-T3 make that redesign
unnecessary for one create-only runtime.

### Kubernetes Lease

Insufficient as the canonical fence and rejected as authority or evidence. A
Lease is mutable cluster coordination state whose expiry, renewal, deletion,
or recreation cannot retire an AG/NQ occurrence or prove its outcome. It may be
used only as an additional mechanical race reducer after the external durable
reservation commits. Loss of a Lease never permits replay.

## Reconciliation matrix

| Observed condition | V1 result |
| --- | --- |
| exact Pod UID and first container ID still present | same exact runtime may continue |
| exact Pod UID terminal with exact external/NQ receipt | definite result may settle |
| Pod deleted after runtime could have started, no exact receipt | `outcome_unknown`; no replacement |
| same name, different Pod UID | duplicate/replacement refusal; original outcome remains exact or unknown |
| restart count positive or changed authority-bearing container ID | different runtime; refuse and retain fence |
| node/runtime/kubelet/controller interruption with retained original identity | mechanics-free evidence reconciliation only |
| scheduler cannot place the Pod before runtime exists and definite non-creation is proved | definite pre-runtime refusal |
| create response lost and object identity cannot be established | `outcome_unknown` |
| AG unavailable after authorization but before create | prepared/authorized object remains inert; no Kubernetes object |
| revocation/retirement while object still exists | NQ authority closes first; exact UID deletion/absence is mechanics closeout |

## Constitutional projection

The path remains:

```text
NQ prepared exact occurrence (inert)
  -> AG exact-work authorization
  -> Docket custody, attempt, marker, and one execute dispatch
  -> NQ consequence-time claim/fence
  -> TURNSTILE authority-neutral create-only bare-Pod mechanics
  -> external NQ and adapter evidence
  -> mechanics-free reconciliation
  -> Docket records settlement or indeterminate result
```

Docket does not authorize the occurrence. Kubernetes desired state, admission,
RBAC, object status, and reconciliation do not authorize it. The external
journal records the transition history but cannot drive the T0 state machine.

## Current environment and next gate

At decision time the control host exposed Docker only. It had no `kubectl`,
`k3s`, `k3d`, `kind`, `minikube`, `helm`, or campaign-owned kubeconfig. That is
not a semantic defect, but it prevents live cluster qualification here.

The next bounded step is a pure closed bare-Pod representation and a fake
create/observe/delete client exercising T1. Real k3s integration remains gated
on a campaign-owned cluster/context, immutable TURNSTILE OCI artifact, external
durable evidence destination, and qualified node-host origin/capacity fact
source. No manifest or Pod may be treated as authority while those deployment
facts are absent.
