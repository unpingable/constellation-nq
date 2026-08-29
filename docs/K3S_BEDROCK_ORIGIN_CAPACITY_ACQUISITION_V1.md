| node identity | exact API node name, API Hostname address, UID, provider ID, machine ID, and boot ID bind placement, reported OS identity, and node incarnation without treating names as aliases | name/Hostname/UID/provider/machine/boot from API; Hostname/machine/boot independently compared with node observation | node-specific; UID/machine remain across reboot, boot ID changes; replacement refuses | raw SSH facts were not attributable to exact API facts |# BEDROCK Kubernetes origin/capacity acquisition V1

Campaign: `BEDROCK`

Slug: `k3s-live-origin-capacity-qualification-v1`

Parent: TURNSTILE terminal commit
`1dbae78451abb6958bb30b94c65cacbd0666ef0e`

Status: **B0 decomposed; B1 two-stage acquisition and authority boundary
implemented for qualification**

This contract closes TURNSTILE T10's generic origin/capacity gap without
promoting Kubernetes labels, SSH output, or projected future cgroups into
semantic facts. The collector observes and signs substrate facts. It does not
authorize execution, create workloads, claim an NQ occurrence, or release an
already-authorized occurrence.

## B0 fact decomposition

| Fact | Required form and reason | Source/class | Scope and transition law | Prior T10 refusal |
| --- | --- | --- | --- | --- |
| cluster identity | kube-system UID plus API CA digest distinguishes this API/cluster | Kubernetes API and configured CA; authoritative for this campaign coordinate | cluster-specific; stable across node scheduling | raw values existed but no acquisition contract bound them |
| node identity | exact node name, UID, provider ID, machine ID, and boot ID binds placement and node incarnation | name/UID/provider/machine/boot from API; independently compared with node observation | node-specific; UID/machine remain across reboot, boot ID changes; replacement refuses | raw SSH facts were not attributable to exact API facts |
| execution origin | exact cluster/node/API coordinate plus pinned observer key and contract | derived, content-bound node-host coordinate | node-specific; rescheduling is false in V1 | no ratified node-host subject/scope/vantage role |
| procfs source | exact `/proc` mount identity and effective `Cpus_allowed_list` | node OS observation; observed | node-incarnation and process-context specific | source pathname had no pinned collector/verifier |
| cgroup source | cgroup-v2 mount, exact membership, `cpu.max`, effective cpuset and memory ceiling | node OS observation; observed | process-context specific; must be reacquired after restart or relocation | SSH readings could not prove the future Pod cgroup |
| CPU request/limit | exact millicore request and optional limit | prepared Pod resource intent; authoritative as requested mechanics only | workload-specific; does not prove the resulting cgroup | resource intent and consequence-time capacity were conflated |
| CPU capacity | actual in-container procfs/cgroup-v2 inputs plus Rust `available_parallelism` | mandatory runtime observation | exact Pod UID/container/node/boot context; expires | impossible before a container cgroup exists |
| memory allowance/capacity | exact request/limit plus actual runtime `memory.max` | request is authoritative intent; runtime value observed | workload/cgroup specific | future runtime value did not yet exist |
| storage identity | Retain StorageClass, exact PV/PVC UIDs, volume relation and mount source | Kubernetes API plus node/filesystem observation | storage-specific; remount requires recheck | PV facts existed but were not in the node-host acquisition contract |
| storage capacity | requested bytes plus `statvfs` total/available bytes on exact retained path | node OS observation; capacity guard | storage mount and observation-time specific | raw capacity lacked content-bound source and freshness |
| namespace/service account | exact names and immutable UIDs | Kubernetes API; authoritative mechanics identity | cluster/namespace specific | available, but not linked to acquisition contract |
| mechanics policy | digest of fixed bare-Pod/bootstrap/resource/volume representation | campaign-owned source artifact; authoritative mechanics intent | plan-specific; mutation changes digest | no link from raw host observations to exact future envelope |
| coordination/fencing domain | exact NQ domain and epoch in the prepared occurrence | NQ/AG plan; semantic authority fact | occurrence-specific | outside T10 raw observation; must never be inferred from Kubernetes |
| durable evidence location | exact retained path, PV/PVC custody and append-only journal IDs | API plus filesystem custody | campaign/storage specific; Pod-local state is excluded | available but not incorporated in origin/capacity acquisition |
| runtime/container identity | Pod UID and first container ID | Kubernetes/CRI observation; observational only | exact runtime; replacement/restart does not inherit authority | nonexistent because T11 correctly never began |

## B1 one-shot observation boundary

The node observer is a fixed Rust executable with a pinned SHA-256 identity and
a node-local Ed25519 key. It is invoked once through the campaign control path.
It accepts only canonical JCS `nq.bedrock_node_observation_basis.v1` bytes and
an absolute canonical contract pathname. Its fixed sources are `/proc`,
`/sys/fs/cgroup`, `/etc/hostname`, `/etc/machine-id`, the boot ID, kernel
release, and one exact retained evidence directory.

The signing key is an observation credential. It is not an AG issuance key,
NQ grant, Docket credential, Kubernetes service-account token, or execution
release. The observer has no Kubernetes API credential and cannot validate
Kubernetes API facts on its own. The controller independently retrieves and
compares cluster, node, namespace, service-account, PV and PVC facts.

The observer is one-shot rather than a privileged daemon. Root-owned key
custody permits observation attribution on these disposable campaign nodes;
it grants no ongoing service, workload, or execution authority.

## Required two stages

Pre-runtime and consequence-time facts are intentionally different objects.

### Stage A — pre-runtime plan

Before any workload exists, the verifier may establish:

* exact cluster, node, namespace and service-account API identities;
* exact node machine/boot/procfs/cgroup/storage observation;
* fixed placement, scheduler and no-rescheduling law;
* exact requested resource envelope and mechanics digest;
* retained evidence path/capacity; and
* bounded freshness and exact collector/verifier/key identities.

The result is `nq.bedrock_pre_runtime_origin_capacity.v1`. It is schedulability
and infrastructure-preparation evidence only. It is not
`nq.available_parallelism_context.v1` for a future Pod.

The paired `nq.bedrock_deferred_runtime_capacity.v1` makes all of these future
facts mandatory: Pod UID, first container ID, in-container procfs recheck,
in-container cgroup-v2 recheck, Rust `available_parallelism`, and an exact NQ
claim/fence before one execution release.

V1 accepts no CPU limit at Stage A. This is a closed qualification choice that
avoids predicting a quota-derived `cpu.max`. It does not assert that the
future cgroup equals the observer's current cgroup.

### Stage B — inert bootstrap and exact runtime recheck

After AG/Docket authorize the exact prepared plan, Kubernetes may create only
one ownerless bare Pod whose sole container is an inert bootstrap blocked on
an external one-use release. Pod existence and container start are mechanics,
not NQ execution.

The exact Pod UID, first container ID, node UID, in-container procfs/cgroup-v2
facts, resource links, and `available_parallelism` then form
`nq.bedrock_runtime_capacity_recheck.v1`. The deferred-capacity state machine
refuses NQ claim before this object is exact. It refuses execution release
before the existing NQ claim/fence is durable. The release is content-bound to
the exact plan, claim and runtime recheck and is emitted once.

Kubernetes deletion, restart, replacement, rescheduling, or a changed
container ID cannot recreate the release or inherit the occurrence.

## State transition

```text
authority-empty prepared plan + mandatory deferred obligation
  -> AG/Docket exact authorization
  -> one inert bootstrap Pod/container identity
  -> exact in-container runtime-capacity recheck
  -> NQ exact claim and provider fence
  -> one content-bound execution release
  -> existing exact execution/terminal or outcome_unknown law
```

At every state before the execution release, NQ provider work remains absent.
Kubernetes reconciliation cannot advance this state machine.

## B2 portability expectations

* kube-system UID and API CA are cluster-scoped and remain stable across node
  scheduling; a recreated cluster changes them.
* node UID and machine ID identify the admitted node. A replacement changes the
  binding. Boot ID changes on reboot and forces a fresh Stage-A observation.
* the API object name fixes placement. The API-reported Hostname address binds
  the operating-system hostname observed on that node. They may differ and are
  never treated as aliases. Node names and provider IDs are compared exactly
  but are not sufficient on their own.
* procfs/cgroup mount IDs and process cgroup paths are observed facts and may
  change across reboot/runtime changes; they are not durable identity.
* placement is fixed to one node and `rescheduling_allowed=false` in V1.
* PV/PVC UIDs and storage mount facts are storage-specific. Remount or storage
  substitution requires reacquisition.
* runtime Pod/container/cgroup values are exact-occurrence facts and cannot be
  carried from node A to node B.

Both campaign nodes must execute the same checked observer bytes and contract,
while retaining distinct node observation keys, node facts, acquisition IDs,
and observation receipts.

## Negative controls

Focused tests require fail-closed behavior for changed API node UID, boot ID,
resource envelope, observer key/signature, expiry, CPU-limit projection,
bootstrap node, runtime resource link, claim before runtime recheck, release
before claim/fence, and execution before release.

## Nonclaims

This contract does not establish application correctness, monitor health,
qualification outcome, provider execution, passive sample eligibility, or AG
authorization. It does not make labels or annotations authoritative and does
not add Kubernetes monitor RBAC.
