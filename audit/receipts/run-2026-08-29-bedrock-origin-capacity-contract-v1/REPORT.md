# BEDROCK origin/capacity contract receipt

Campaign: `BEDROCK`

Slug: `k3s-live-origin-capacity-qualification-v1`

Classification:
`PASSIVE-K3S-AG-DEFERRED-ORIGIN-CAPACITY-CONTRACT-QUALIFIED`

This is a bounded B0–B2 source/contract result. It creates no AG/NQ authority,
Kubernetes workload, runtime occurrence, or execution release. The live B4
origin/capacity result remains separate.

## Custody

* TURNSTILE terminal parent:
  `1dbae78451abb6958bb30b94c65cacbd0666ef0e`;
* BEDROCK source commit:
  `a107ac5b2bef3e09b65f47be6a79fb831381ef9e`;
* branch: `campaign/k3s-live-origin-capacity-qualification-v1`;
* observer executable SHA-256:
  `6bd397593dbc053b6dfeee6eeec1716c2651672e8617c84be3a6679ae316451d`;
* doctrine: `docs/K3S_BEDROCK_ORIGIN_CAPACITY_ACQUISITION_V1.md`.

## B0 result

The T10 refusal was decomposed into cluster, node, origin, procfs, cgroup,
CPU, memory, storage, coordination, evidence, and runtime-identity facts.
Kubernetes API facts, node OS observations, requested resource intent, derived
identities, and consequence-time runtime facts retain distinct source and
scope classifications. No Kubernetes label or annotation is treated as an
authoritative source.

TURNSTILE possessed raw cluster/node/cgroup values. It correctly refused
because no content-bound acquisition/verifier contract or lawful projection
from pre-runtime intent to future workload cgroup facts existed.

## B1 result

BEDROCK implements a fixed one-shot node observer. It accepts only canonical
JCS basis/contract input, reads fixed node OS/procfs/cgroup/storage sources,
and returns exact signed canonical bytes. It has no Kubernetes API credential,
execution, reconciliation, NQ claim, or authorization operation.

The controller must independently compare the signed node observation with
API cluster/node/namespace/service-account/PV/PVC facts.

The two-stage boundary is explicit:

1. Stage A produces a pre-runtime origin/capacity plan and a content-bound list
   of mandatory deferred runtime facts.
2. Stage B may record one inert Pod/container identity, then must retain actual
   in-container procfs, cgroup-v2 and Rust capacity facts before NQ claim.
3. A one-use execution release is impossible until the existing NQ claim and
   provider fence are exact.

The bootstrap Pod is not authorized by Kubernetes desired state and its mere
existence is not semantic execution.

## B2 result

The contract classifies cluster facts as cluster-scoped; node UID/machine ID as
node-scoped; boot ID as node-incarnation scoped; mount IDs/cgroup paths as
observed runtime details; PV/PVC facts as storage-scoped; and Pod/container
facts as exact-runtime scoped. Reboot, node replacement, rescheduling, remount,
and changed cgroup identities require the corresponding recheck rather than
identity inheritance.

## Qualification

Commands completed at sealed source custody:

```text
cargo fmt --all -- --check
cargo test --locked -p nq-k3s-exact-occurrence --all-targets
cargo clippy --locked -p nq-k3s-exact-occurrence --all-targets -- -D warnings
cargo build --locked --release -p nq-k3s-exact-occurrence --bin bedrock-node-observer
git diff --check
```

The crate result was 37 passed, 0 failed. Five focused BEDROCK cases cover the
pre-runtime contract, deferred transition ordering, and deterministic negative
controls. Existing T0–T5 core, evidence, executor and bare-Pod cases remained
passing.

## Exact negative controls

Changed API node UID, boot ID, resource envelope, observer key/signature,
freshness, CPU-limit projection, bootstrap node, runtime resource link, claim
before runtime recheck, release before claim/fence, and execution before
release all refuse closed.

## Counts

AG authorizations, NQ prepared occurrences, claims, execution releases,
Kubernetes workloads, runtime occurrences, Docket attempts, recurrence
attempts, samples and acquisitions: all zero.

No VM was started for this result. GLASSHOPPER and CALIPER were not accessed.
