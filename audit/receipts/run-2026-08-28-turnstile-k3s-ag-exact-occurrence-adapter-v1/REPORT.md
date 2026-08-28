# TURNSTILE k3s / AG exact-occurrence adapter V1

Campaign: `TURNSTILE`

Campaign slug: `k3s-ag-exact-occurrence-adapter-v1`

Date: `2026-08-28`

Core classification:
`PASSIVE-K3S-AG-ADAPTER-CORE-QUALIFIED`

Live-substrate classification:
`PASSIVE-K3S-AG-LIVE-NOT-QUALIFIED`

Combined bounded classification:
`PASSIVE-K3S-AG-ADAPTER-CORE-QUALIFIED-LIVE-NOT-QUALIFIED`

No Kubernetes workload, NQ authority object, AG authorization, Docket attempt,
recurrence attempt, sample, or acquisition was created by this campaign.

## Scope and custody

TURNSTILE continued from qualified NQ source
`675e247e85d8e2e1f2801c06445bf863f82b3a5b` on isolated branch
`campaign/k3s-exact-occurrence-adapter-v1`. It did not modify or replace the
Linode artifact or either independent campaign track.

Implementation checkpoints:

| Checkpoint | Commit | Result |
| --- | --- | --- |
| contract/interface decision | `e6433f1afbda47455270bdb5c439d847829f1a1c` | AG/Docket transport sufficient; NQ/deployment split initially absent |
| T0 prepared occurrence | `f8befe404412f48dc06de0103f7019fae1aad5ec` | immutable exact-one prepared/authorized/claimed/executing/terminal law |
| T1 execute/reconcile split | `123dbd69d1f188583c3d751d5d0a2366c50aa372` | sole mechanics call; mechanics-free reconciliation |
| T2 portable origin/capacity | `166aebbc9f7b0a44baf2fa52d2f54871a7cf6d71` | workload-local and node-host roles remain distinct; exact cgroup-v2 context |
| T3 OCI/external evidence | `cf6f87fc53f1013aa72f86fbc9e0d1b966d06ffa` | digest-only OCI and predecessor-linked external custody |
| T4 primitive decision | `d16155b16d4eaedc331f9518ff255d16641892d4` | create-only ownerless bare Pod selected after T0-T3 |
| T5 closed representation | `90535c80ae57e6b16734cc9751dd81a79ce1fd44` | inert exact Pod projection and runtime observation classification |

The frozen qualified Linode source remains an ancestor and is not reclassified
by this successor branch.

## Constitutional result

The implementation preserves the required separation:

* possession of a prepared NQ occurrence grants no authority;
* AG work must equal the immutable prepared-plan digest;
* Docket attempt and marker are exact one-use dispatch custody;
* T1 can invoke mechanics only from `claimed`;
* reconciliation has no mechanics trait and cannot create or replace work;
* Kubernetes object existence, RBAC, admission, desired state, and status are
  facts and permissions, not authority;
* Docket observes settlement or indeterminate result and does not authorize NQ;
* external evidence is append-only observation and cannot drive the T0 state
  machine; and
* exact replay converges without another runtime instance.

T2 defines closed workload-local and node-host-delegated profiles. A
workload-local procfs/cgroup observation cannot satisfy existing passive
host-load semantics. Node-host delegation requires one exact host coordinate,
a qualified origin contract, exact node placement, exact procfs/cgroup source,
fresh capacity facts, and cgroup v2. Relocation and stale facts refuse.

T3 requires a digest-only OCI reference, exact index/manifest/platform/layer
and in-image artifact identities, an external non-ephemeral append-only
retain-all custody contract, and an exact predecessor-linked event chain.
Runtime identity may be introduced only at `executing` and cannot later be
dropped or substituted.

## Primitive decision

One create-only, ownerless bare Pod is the only admitted V1 object. The closed
representation has no replica, owner-reference, controller, init-container,
retry, or recurrence field. It requires `restartPolicy: Never`, one
authority-bearing container, a digest-only image, no command/argument override,
empty environment, a non-privileged security context, exact deadline and
resources, and three exact retain-all PVC bindings.

Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob, static Pod, and a
new custom controller were rejected for the reasons recorded in
`docs/K3S_AG_TURNSTILE_PRIMITIVE_DECISION_V1.md`. A Lease may reduce a
mechanical race only after external reservation; it is never authority,
canonical fencing, result evidence, or replay permission.

## Reconciliation qualification matrix

| Qualification case | Implemented deterministic result | Live result |
| --- | --- | --- |
| delete running Pod / exact Pod absent | retained runtime projects `OutcomeUnknown`; no execute call exists in reconciliation | not exercised on cluster |
| node/runtime interruption | same mechanics-free evidence rule | not exercised |
| scheduler relocation / replacement Pod UID | `DifferentRuntime`; old occurrence remains fenced | not exercised |
| kubelet restart | same Pod UID plus same first container ID may continue; changed ID/restart count is different runtime | not exercised |
| controller-manager reconciliation | controller/owner/replica fields are outside closed JSON shape | not exercised |
| duplicate workload submission | same T0/T1 transition and evidence event is idempotent; substitution refuses | Kubernetes API race not exercised |
| replicas greater than one | field is unrepresentable and unknown JSON member refuses | not exercised |
| Job retry/backoff | `Job` differs from exact `Pod`; Job primitive rejected | not exercised |
| stale prepared object replay | plan/content/lifetime and exact transition checks refuse | not exercised |
| concurrent controller action | different UID/container/owner facts classify different runtime | not exercised |
| adapter restart while executing | T1 returns `ReconciliationRequired`; execute counter remains zero | process/cluster restart not exercised |
| AG unavailable before runtime creation | prepared/authorized state cannot call execute | real AG outage not exercised |
| completion with result-ingestion interruption | exact result loss becomes `outcome_unknown`; later read-only evidence may settle without execution | not exercised |
| retirement while Kubernetes still desires work | closed representation has no desired-state controller; exact-UID deletion remains a live closeout gate | not exercised |
| cluster restart | no replacement authority; reconcile exact retained identity or preserve unknown | not exercised |

These model results qualify the adapter core, not Kubernetes API/server,
scheduler, kubelet, CSI, CNI, container runtime, or node behavior.

## AG and Docket interface fit

No new AG authorization type and no Docket authorization role are required.
The existing Docket executor transport already binds attempt, marker, work,
subject, scope, one execute call, and mechanics-free reconcile. Interface
evidence inspected:

* campaign-driver-ng commit
  `b6cb51bb6abc459b04ef0a64fc79ef4f6ec90a55`,
  `src/executor.rs` SHA-256
  `39b10db14019b827de689077692f9dc421c1558a78a3838e9a9308c7d806b29c`;
* Docket commit `3ce07f9bb3be6ba86ca65f3b521f807970b56119`;
* agent_gov commit `df61549a5e9a0dcc63ebe21efc90bd8958f64123`.

The actual AG+friends process path was not invoked because no live deployment
facts or Kubernetes substrate were available. Synthetic identities in unit
tests are deterministic fixtures and grant no human or production authority.

## Implementation digests at T5

| Artifact | SHA-256 |
| --- | --- |
| crate `lib.rs` | `f21b946e873b70cfcc7073868297278dc175d8b0c21f4407214ac1d63284d82c` |
| `executor.rs` | `52ec346beeffb5f605cc6a9538143c2785a2a59ebe4bd398095de4521038142b` |
| `origin_capacity.rs` | `1afc99db19f588a75de60810ee3126fc72e9d9859babcacc4ef4619803997efe` |
| `artifact_evidence.rs` | `9a2f0040a27bcaffac0a1769d7be20938a707b4c1daafd9ff55a8982b72a7f79` |
| `kubernetes.rs` | `d587b4e0e81ebe26d3448b7f685e0899ce0d54f373055f1d3838141280a5de8e` |
| execution contract | `2367317405762674b89449ebcd1cf50b91dc3793d866c54dafe9e9b5dc97a612` |
| primitive decision | `0b252355cb0d488f716de676ec46993d32993b50c26f83b2afa463333b75168c` |
| `Cargo.lock` | `2e84f1f6acd0351a27c864190cad07cc1a092d7494acf2bd36f8b5522c8fcb67` |

## Qualification commands and results

Passed:

* `cargo fmt --all -- --check`;
* `cargo test --locked -p nq-k3s-exact-occurrence`: 28 passed;
* `cargo clippy --locked -p nq-k3s-exact-occurrence --all-targets -- -D warnings`;
* `cargo clippy --locked --workspace --all-targets -- -D warnings`;
* `git diff --check`.

The full parallel workspace test reached an existing `nq-core` group with 201
passes, one ignored case, and three runner timeouts. No timeout was increased.
Each exact timeout case then passed unchanged and serially:

* `bare_cwd_relative_script_argument_executes_only_qualified_snapshot` — pass
  (captured rerun 2.08 seconds);
* `replaced_script_and_env_shebang_paths_execute_only_retained_bytes` — pass
  (9.49 seconds); and
* `same_inode_script_source_mutation_cannot_change_sealed_launch` — pass (2.73
  seconds).

This is recorded as parallel host-load interference, not silently promoted to
a clean parallel-workspace pass and not attributed to TURNSTILE semantics.

## Live stopping condition and re-entry

The control host had Docker 29.1.3 but no `kubectl`, `k3s`, `k3d`, `kind`,
`minikube`, `helm`, campaign kubeconfig, immutable TURNSTILE OCI image, or
qualified external CSI/PV deployment facts. Creating a Pod under those
conditions would substitute unbound mechanics for qualification evidence.

Live re-entry requires all of the following, without changing the core law:

1. a campaign-owned disposable k3s cluster and exact kubeconfig/cluster UID;
2. an immutable TURNSTILE OCI artifact whose T3 facts remeasure exactly;
3. exact namespace and service-account UIDs plus the admitted mechanics policy;
4. a qualified node-host origin/procfs/cgroup-v2/capacity fact source;
5. three retained PVC/PV bindings and an external append-only journal driver;
6. an authority-neutral adapter process implementing create-only Pod mechanics
   only through T1 after `claimed`;
7. actual AG issuance and Docket custody through their existing transport; and
8. the live reconciliation matrix, exact-UID closeout, and non-resurrection
   proof.

Until those facts exist, the Pod representation is inert. Kubernetes has no
object to reconcile and no prepared object can self-activate.
