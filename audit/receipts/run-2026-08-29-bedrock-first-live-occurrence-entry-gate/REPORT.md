# BEDROCK B5 first live exact occurrence entry refusal

Campaign: `BEDROCK`
Slug: `k3s-live-origin-capacity-qualification-v1`
Date: 2026-08-29

## Classification

`PASSIVE-K3S-AG-LIVE-OCCURRENCE-NOT-QUALIFIED — EXACT EXECUTION/INERT BOOTSTRAP SEAM ABSENT BEFORE AUTHORITY`

B3 remains independently
`PASSIVE-K3S-BEDROCK-LIVE-SUBSTRATE-REQUALIFIED`. B4 remains independently
`PASSIVE-K3S-AG-LIVE-ORIGIN-CAPACITY-QUALIFIED`. B6 is
`NOT-STARTED`.

This result does not alter TURNSTILE or any other campaign classification.

## Entry-gate ordering

B4 qualified exact content-bound Stage-A plans with mandatory deferred
consequence-time obligations. BEDROCK then inspected the qualified AG/Docket
process boundary and the actual immutable image before minting authority or
creating infrastructure.

Creating the first Pod would not satisfy the qualified ordering. The exact
three missing live mechanics interfaces are:

1. **Docket process executor.** The crate has a pure
   `ExecuteMechanicsV1`/`ReconcileEvidenceV1` law, but no campaign binary
   implements the frozen Docket
   `EXECUTOR plan-id CONFIG`, `execute`, and `reconcile` process surface.
   The available BEDROCK binaries are the node observer, origin/capacity
   verifier, and authority-neutral evidence probe.
2. **In-container inert bootstrap and release carrier.** The exact OCI
   configuration starts `/usr/bin/nq --version`. The closed bare-Pod
   projection requires the OCI default invocation and makes command, args, and
   environment overrides absent. Kubernetes would therefore start and finish
   NQ mechanics immediately rather than hold an inert container, retain its
   runtime facts, and wait for one exact release.
3. **Durable NQ claim/fence seam.** The deferred state machine proves the
   ordering in memory, but deployed NQ has no process operation that durably
   claims/fences an already prepared exact occurrence without continuing into
   provider invocation. `nq recurring tick` still combines allocation,
   claim, provider preparation, fence, and invocation. Inventing a local
   claim record in the adapter would move semantic authority into deployment
   mechanics.

The qualified BEDROCK doctrine requires:

```text
AG/Docket exact authorization
-> inert Pod/container identity
-> exact in-container runtime recheck
-> durable NQ claim/provider fence
-> one-use release
-> execution
```

The deployed artifacts cannot implement that chain. A bare Pod launcher would
make Kubernetes creation the missing authority transition, so the gate refused
before authority.

## Exact custody

- NQ/BEDROCK receipt source before this report:
  `7c361a9b43c6eb25645dcde5fa5222ae5a70ac28`.
- Qualified AG source was inspected from a clean campaign-owned clone at
  `37dbbbf4ce7024c82541fa8dd6839179f00ca1b2`.
- Qualified Docket source was inspected from a clean campaign-owned clone at
  `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`.
- Immutable OCI manifest:
  `sha256:c57aa0eca562425a8038e323d968af206f4d2eae6eec112d4c126cea56dce33d`.
- OCI configuration:
  `sha256:7190e6d3c3dede7a1402a3d6031a627e5c9f62182ea52931ea43fdee7cc8570d`.

No AG or Docket source was modified.

## Zero-authority and zero-workload proof

Immediately before closeout:

- AG proposals/spends/issuances: 0/0/0;
- Docket attempts/settlements: 0/0;
- NQ prepared authority objects/claims/fences/releases: 0/0/0/0;
- Kubernetes Pods across all namespaces: 0;
- campaign workloads/controllers/Services/Endpoints: 0;
- provider starts: 0.

The only non-storage object returned by the broad campaign-namespace read was
Kubernetes' standard `kube-root-ca.crt` ConfigMap. No ServiceAccount token was
automounted and no workload identity ever existed.

Because no authority was created, there was no H/G/E, AG issuance, Docket
attempt, NQ claim, or prepared successor to retire or revoke.

## Terminal inert closeout

The agent `k3s-agent.service` and server `k3s.service` were stopped and
disabled. The agent and server VMs then powered off cleanly. Their recoverable
overlays passed `qemu-img check`, no QEMU process remained, and controller
ports 19321, 19322, and 17443 were not listening.

- server overlay SHA-256:
  `8eb0128efb01248b103259cb3c7033f04e16cac96f46bef61c4804440c404fd8`;
- agent overlay SHA-256:
  `a8e6100996176143470f3e001a5863bd227a5223e104b87d9644936e7b030f80`;
- server seed SHA-256:
  `19c735b57417c8fe4a6a7abc2a3c0727a89dc151819173595ecf45cbab370555`;
- agent seed SHA-256:
  `b82fb31211072977579ea7232426fe779ea6cfcdcfdb3ffeb9f5cfe71332a560`.

Retain PV/PVC metadata and external evidence custody remain in the powered-off,
recoverable cluster. Neither unit can start automatically if a VM is powered
on without an explicit new campaign decision.

## Required successor mechanism

A future successor must separately qualify a narrow Docket executor binary, an
immutable inert-bootstrap image/release carrier, and a durable NQ
prepared-occurrence claim/fence operation. That is new source qualification;
this campaign did not reinterpret the B4 plan or create an unauthorized
replacement occurrence.
