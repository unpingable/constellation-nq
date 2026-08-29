# RIVER-CLERK BEDROCK Docket-adapter integration classification

Campaign: `RIVER-CLERK`

Slug: `bedrock-docket-adapter-prerequisite-v1`

Classification:
`NOT-QUALIFIED-IDENTITY-CONTRACT-SUCCESSOR-REQUIRED`

Docket's independently owned local process-host half is qualified. The
composed BEDROCK executor prerequisite is not qualified because the frozen
Docket host and the retained NQ V1 prepared-occurrence contract require two
different objects to be the same AG work identity. This campaign does not
weaken either contract or introduce an unauthorized NQ V2.

## Exact custody

* retained canonical NQ base:
  `7c361a9b43c6eb25645dcde5fa5222ae5a70ac28`;
* consumed GRANITE-FENCE implementation:
  `a73edb188ac4d9746a720432f5b9cfc3b9110e6e`;
* equivalent successor-branch cherry-pick:
  `baf6b709333965ca408f6a949872f9e47f940a70`;
* Docket RIVER-CLERK head:
  `13d37da4dbff3164e96d555172f4cf4d3c961117`;
* Docket canonical base:
  `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`;
* NQ branch:
  `campaign/river-clerk-bedrock-docket-adapter-prerequisite-v1`;
* Docket branch:
  `campaign/live-docket-executor-prerequisite-v1`.

The Docket head and branch ref were independently verified exact on the
established remote. Its worktree was clean.

Frozen source artifact SHA-256 values:

```text
681f054d6a5f045b74c722140422117cd9956665517716451c35e9ab8c3bb8c2  live-docket-executor-prerequisite-v1.md
b54f8db4d89c7e422733757f7a69b7fcc7420ce225f782f493c703c8e39e41a1  executor-transport-v1.md
3e58081f7cc36ecfad44ee9860c77ec5784b34c91e7c707d126f00ef778cf687  corpus.json
```

## Exact incompatibility

Docket's qualified process host computes its plan identity over the closed
host configuration, the adapter-program content digest, and the
adapter-configuration content digest. It refuses unless:

```text
dispatch.work == local_docket_host_plan_id == AG issuance.work
```

NQ's retained `PreparedOccurrenceV1` validates its authorization with:

```text
AuthorizationBindingV1.ag_work == PreparedOccurrenceV1.plan_id
```

The Docket host-plan digest and NQ prepared-plan JCS digest have distinct
domains and distinct preimages. They are not generally equal. Placing one in
the other's content creates a digest dependency cycle; treating either field
as some other identity would misrepresent the retained V1 contract.

The mismatch is reached before a valid composed dispatch can be admitted, so
an adapter cannot honestly demonstrate the required exact work binding against
both frozen halves. Attempt/marker, claim/fence, execute-once, persistence,
outcome mapping, and reconciliation implementation cannot cure a contradictory
entry identity.

## Disposition and resume point

Docket head `13d37da4dbff3164e96d555172f4cf4d3c961117` remains independently
qualified as the Docket half. GRANITE-FENCE remains an independent qualified
NQ prerequisite. The complete BEDROCK executor prerequisite remains not
qualified.

Resume only under separately authorized normative work that introduces a
versioned NQ successor contract with distinct, explicit identities for the NQ
prepared plan and the Docket executor plan. That successor must preserve the
frozen Docket transport and independently requalify preparation,
authorization, claim/fence, adapter execute-once, durable evidence, outcome
mapping, replay, process termination, outcome-unknown, and reconciliation.

No adapter, compatibility shim, live route, service unit, or production
configuration was added. BEDROCK B6 and OPEN-QUARRY were not started.

## Live-effect and teardown counts

AG authorizations, NQ authority objects, live claims, live fences, live
releases, mechanics invocations, Docket attempts, Kubernetes workloads,
provider starts, VMs, listeners, live-route changes, recurrence attempts,
samples, and acquisitions: all zero.

No process, listener, VM, credential, secret, temporary artifact, or teardown
obligation remains. GLASSHOPPER and its live route were not accessed.
