# NQ passive k3s / AG exact-occurrence execution-contract decision

Classification: **`PASSIVE-K3S-AG-EXECUTION-CONTRACT-SPECIFIED-ADAPTER-BLOCKED`**

Inspection/decision interval: `2026-08-28T19:03:19Z` through
`2026-08-28T19:08:05Z`.

This is an independent Workstream C receipt.  It does not aggregate, alter, or
classify the Linode or VM workstreams.  It supersedes only the prior Track C
claim that the AG/Docket execution seam itself was absent: current AG-NG and
Docket now provide that seam.  It does not supersede the prior finding that NQ
and Kubernetes lack a qualified exact-occurrence deployment boundary.

No Kubernetes object, namespace, service account, image, NQ authority object,
AG proposal/spend/issuance, Docket attempt, NQ occurrence, charter, recurrence
attempt, sample, or acquisition was created or consumed by this workstream.

## Decision

The narrow constitutional placement is coherent and is fully specified in
[`docs/K3S_AG_EXACT_OCCURRENCE_EXECUTION_CONTRACT_V1.md`](../../../docs/K3S_AG_EXACT_OCCURRENCE_EXECUTION_CONTRACT_V1.md).

The selected mechanics are:

```text
prepared exact NQ occurrence
  -> AG one-use exact-work authorization
  -> Docket standing, attempt custody, and frozen executor dispatch
  -> authority-neutral adapter with external durable idempotency journal
  -> one create-only bare Pod, restartPolicy Never, no owner/controller
  -> exact Pod UID/container identity and durable evidence
  -> Docket settlement or outcome_unknown
```

A Pod with a different UID is a different runtime instance.  Pod deletion,
node/runtime loss, scheduler relocation, controller retry, or same-name
replacement never continues the old occurrence.  V1 excludes Deployment,
ReplicaSet, StatefulSet, DaemonSet, Job, and CronJob.  The adapter's
`reconcile` operation cannot create or restart mechanics.  Persistent NQ
custody and the adapter journal remain outside ephemeral Pod state.

### Interface fit

The AG/Docket transport is sufficient:

* AG-NG at `37dbbbf4ce7024c82541fa8dd6839179f00ca1b2` owns one exact
  occurrence, fresh consequence-time gates, a one-use authorization spend,
  and a signed exact-work issuance.
* Docket runtime at `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`
  includes the qualified C1 executor transport and C2 layering.  Its closed V1
  dispatch binds attempt, marker, work schema, work, subject, and scope; it
  persists custody before one `execute` and exposes mechanics-free
  `reconcile`.
* The future Kubernetes component can therefore be an ordinary Docket
  executor adapter.  No new AG authority family, Docket authorization role, or
  Kubernetes authorization object is required.

The implementation gate remains closed because exact NQ input to that
transport does not exist:

1. Current `nq recurring tick` allocates/claims a recurrence acquisition and
   continues through provider preparation, provider fence, and invocation in
   one command.  It has no immutable prepared-occurrence envelope for AG to
   bind and no exact execute/reconcile operation for a preallocated NQ
   occurrence.  An output-checking wrapper would learn the occurrence identity
   only after mechanics had begun.
2. Current recurrence execution admits only the Linode origin profile and the
   isolated Linode origin helper.  No qualified Kubernetes
   subject/vantage/origin/capacity/placement contract exists.
3. Passive observer operation is qualified through a static systemd unit and
   binds exact systemd/cgroup capacity context.  A Pod changes placement,
   restart, capacity, and vantage facts; it is not a packaging-only
   substitution.
4. The source has no qualified immutable OCI artifact, Kubernetes
   representation, external adapter journal, or campaign-owned k3s context.

Items 1–3 change NQ semantic state transitions and claim context.  They are a
new constitutional NQ mechanism, not a narrow adapter implementation.  This
workstream therefore stopped before code, image construction, cluster
installation, authority preparation, or workload creation.  A YAML-only
launcher would incorrectly make Kubernetes creation the missing authority
transition.

## Exact source custody

| Repository/interface | Branch or checkout | Exact commit | Workstream use |
| --- | --- | --- | --- |
| NQ | isolated `campaign/k3s-exact-occurrence-adapter-v1`, derived from `campaign/passive-watcher-succession-v1` | `675e247e85d8e2e1f2801c06445bf863f82b3a5b` | contract and receipt only |
| AG-NG | detached test/inspection cut from `campaign/governed-campaign-loop-v1-worker-vm` | `37dbbbf4ce7024c82541fa8dd6839179f00ca1b2` | exact-work/issuance interface |
| Docket runtime | clean detached qualified C2 checkout | `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b` | custody/executor transport |
| outer Docket campaign repository | read-only `codex/c2-amendment-rereview` | `3ce07f9bb3be6ba86ca65f3b521f807970b56119` | no runtime authority inferred |

The NQ worktree was created from the exact Linode-qualified source commit so it
could not move or mutate the authoritative Linode worktree or artifact.  During
inspection the shared AG worktree advanced from `37dbbbf` to unrelated worker
VM commit `1567b24`; Track C pinned and retested `37dbbbf` in a clean detached
worktree.  The changed AG files were worker image/agent mechanics and did not
touch the inspected exact-occurrence or Docket transport interfaces.

The shared Docket runtime worktree contained unrelated untracked VM experiment
files that Cargo auto-discovered as targets.  An initial test from that shared
worktree therefore failed to compile those incomplete unrelated targets.
Track C did not alter them; it created a clean detached checkout at the same
`c49ad8d` commit, where the exact governed-loop suite passed.

## Source and contract digests

| Object | SHA-256 |
| --- | --- |
| contract | `0ca3c5ba02a5ff19dae1cb018cdeca1c4b32060e923618a6578315cab41e4e2a` |
| NQ `crates/nq-app/src/cli.rs` | `af8b5274b43d24c022ba3672111b27199b884af7093a98fc6b3f9975d16ab7eb` |
| NQ `crates/nq-store/src/recurrence.rs` | `e5701efced5fdc2be51f1202d0abf71752774c87a0765976a59e13a08c18ec34` |
| NQ passive continuity law | `6e708224ea3283cd4f0f11fac55807039fb76d1d7347e7b2dffba36e44c97fc9` |
| NQ bounded-selection law | `0fd6cf82fe5b78162787a2dda4798587333b8d2a630644f36a3ca04952b1e89c` |
| NQ operational portrait policy ledger | `caa1fc221e5ae6ccaae2c54acae53885479379a1bad358f3a49a74b7cb99d52b` |
| AG-NG `README.md` | `4a34ca387595d4c0e2c09b7011bad088db70449d8ca58711336f18d75b049dce` |
| AG-NG governed-loop C1 contract | `5413774507b5ebb9f15c7149599ac02c006de4bead1a3854fbf1f44c747acd22` |
| AG-NG independent executor conformance | `c287702649336b2f234e75636cb356e03ed8b4a2bc271649ce0cedc8bcd29080` |
| Docket executor transport V1 | `b54f8db4d89c7e422733757f7a69b7fcc7420ce225f782f493c703c8e39e41a1` |
| Docket C1 adjudication | `1aca787c6cfe2704803082b0d16dee51795400194d7432f017d2c7ca326d27cf` |
| Docket governed-loop port | `387d7c4ac9e58b2d02450889d99e01640ffe45c4e27c9565d48a33e87ad5b075` |
| Docket governed-loop service | `a4932634ea2dda2d39e4b3f07076d361db71c5b46a51f925ea08e21500ff551a` |
| Docket executor transport corpus | `3e58081f7cc36ecfad44ee9860c77ec5784b34c91e7c707d126f00ef778cf687` |

## Targeted qualification

All successful commands used locked dependency resolution:

| Command | Exact checkout | Result |
| --- | --- | --- |
| `cargo test --locked -p nq-store recurrence` | NQ `675e247` | 19 passed, 0 failed |
| `cargo test --locked -p gwr-local governed_loop` | clean Docket `c49ad8d` | 17 passed, 0 failed |
| `DOCKET_EXECUTOR_TRANSPORT_CORPUS=.../corpus.json cargo test --locked -p ag-app --test executor_transport_conformance -- --ignored` | clean AG `37dbbbf` against clean Docket `c49ad8d` corpus | 1 passed, 0 failed |

The NQ cases covered finite/exclusive authority bounds, deterministic slots,
no catch-up behavior, coordination serialization, provider spacing,
outcome-unknown fencing, stale epochs, and restart recovery.  The Docket cases
covered one custody/one delivery under concurrency, transport failure after
custody, mechanics-free reconcile, unknown outcome, binding substitution,
restart, and exact terminal replay.  The AG case independently accepted the
exact Docket V1 corpus.

These tests qualify the existing seams used in the decision.  They do not
qualify a Kubernetes adapter or an NQ Kubernetes role.

## Local substrate observation

The control host was `crow`, Linux `6.5.0-44-generic`, x86-64.  Docker
client/server `29.1.3` was reachable through its `default` context.  `k3s`,
`kubectl`, `helm`, `kind`, `minikube`, and `k3d` were absent; no user or system
k3s kubeconfig existed; and no local `rancher/k3s:latest` image existed.

Installing a disposable cluster would not repair the semantic blockers and
was therefore not attempted.  This was a bounded stopping decision, not a
claim that k3s cannot execute the future adapter.

## Re-entry requirements

Implementation may start only after a separately reviewed NQ change provides:

1. canonical create-once `nq.k3s_exact_occurrence_execution_plan.v1` custody;
2. split `prepare-exact-occurrence`, `execute-prepared-occurrence`,
   mechanics-free `reconcile-prepared-occurrence`, and terminal retirement;
3. exact preparation-expiry, slot-consumption, consequence-time sample
   recheck, provider-fence, and outcome-unknown laws;
4. a qualified Kubernetes subject/vantage/origin/capacity/placement role;
5. an immutable OCI artifact and persistent retain-all custody representation.

After those qualify, the narrow Docket adapter may be implemented with the
contract's external journal, bare-Pod primitive, UID/container binding,
duplicate fences, non-resurrection closeout, and reconciliation matrix.  Only
then does creating a disposable k3s cluster add independent qualification
value.

## Closeout

* Kubernetes objects: `0`
* NQ H/G/E/watcher/admission/successor identities: `0`
* AG proposals/spends/issuances: `0/0/0`
* Docket attempts: `0`
* recurrence/sample/acquisition occurrences: `0/0/0`
* prepared object capable of activation: `none`
* external state changed: none
* Track A or Track B state touched: none
