# Lean correspondence ledger

## Exact pin

| Field | Value |
|---|---|
| repository | `unpingable/skunkworks` |
| commit | `5302a09256160c8fcfb08903a122ece218d40d66` |
| tree | `3e9241cde3adfffe2d6b5609964cf84f2b3334a5` |
| Lean | `4.29.0` |
| target | `NightshiftOperationalPosture` |
| aggregate | `Skunkworks.NightshiftOperationalPosture` |
| aggregate blob | `e630a23ea514b51ae62473276573bb5e10d69409` |
| `Core` blob | `670e4339827bab47417d344ce935ccf29b4e6bdf` |
| `Evaluation` blob | `596d6ac1e9c5d1bcc356f8bbe491278d94ee6a35` |
| `Scheduling` blob | `0125e113e9a6a1e642fc2c188b6f4339242d961b` |
| `ProposalBoundary` blob | `f66e37deaad21ea282efbb182c2087ee778fe818` |
| `OperatorProjection` blob | `9f023f39884fc8e0aa22ede613b39195aef17091` |
| `Hostile` blob | `831d72723f2b21462aae60f2c855ffdd2ee71728` |
| `Qualification` blob | `500a4846c08a9844266a298750e94ccdefb36d66` |

## NQ-side map

| Runtime surface | Lean surface | Relation | Evidence |
|---|---|---|---|
| distinct transparent Rust `request_id`, `run_id`, `artifact_id` types | `RequestId`, `ExecutionId`, `ArtifactId` | semantic invariant | compile-time type separation, canonical round-trip, and self-ID tests |
| `question` + subject/profile/vantage | `DiagnosticKey` | refinement | closed DTO + strict decoding |
| per-claim `state_binding_ids` | `StateBinding` | refinement | reference validation |
| `outcome.derivation/condition/coherence/coverage` | corresponding four kernel axes | vocabulary refinement | explicit-absence and refusal tests |
| exact raw → normalized → projected identities and rules | `dependencies` | stronger runtime detail | partition and projected-substitution tests |
| typed projection omissions and claim-required distinctions | projection-loss hostile family | executable refinement | `E_match`/`E_mismatch` collision vectors both refuse the richer claim |
| per-input source acquisition intervals, execution clock, and NQ-owned `attempt_interval` | `acquiredAt` | conservative refinement | interval/clock validation; source clocks remain attached to exact received inputs |
| `Clean` distinct from `ExplicitlyAbsent`, each requiring complete joint evidence | `ConditionStatus.clean` plus coverage/coherence fields | vocabulary refinement | positive and hostile condition tests |
| NQ input refusal distinct from provider `no_response` | no exact Lean correspondence | stronger producer-side runtime detail | two valid canonical artifacts with different accounting and identities; Lean `InputStatus.noResponse` instead means Nightshift received no artifact |
| canonical byte identity | schematic `canonicalDigest` | runtime implementation, not proved by Lean | JCS fixture and digest tests |

The Rust contract is richer than the schematic Lean artifact in several
places. The table does not claim a total mapping or proof of implementation.

## Executable vectors

| Vector/test | Lean anchor | Result represented |
|---|---|---|
| `positive.json` | four-axis `DiagnosticArtifact` vocabulary | complete, explicit absence under joint coherence; this is not an exact correspondence to Lean's `.clean` positive control |
| `refused.json` | delivered `DiagnosticArtifact` with `derivation = .refused` | exact producer-side NQ refusal artifact only; Nightshift no-artifact behavior is not proved here |
| `provider_no_response.json` | no exact Lean correspondence | richer producer-level input accounting remains distinct; Lean `InputStatus.noResponse` is the Nightshift receiver-side no-artifact case, which is not proved here |
| declared-denominator unit test | `favorable_subset_cannot_complete_closed_inventory` | an unsatisfied declared required input cannot be hidden; profile-manifest closure remains unearned |
| selected-identity substitution | projection/dependency hostile family | projected evidence identity cannot be substituted |
| `hostile_projection_collision_{match,mismatch}.json` | projection-loss hostile family | two canonical self-identified candidate byte strings encode different raw states and one lossy projection; validation rejects both because the claim requires `workflow_attempt`; no Nightshift runtime claim follows |
| noncanonical JSON | operator/canonical identity nonclaim | presentation-equivalent JSON is not canonical artifact bytes |
| partial explicit absence | `contradiction_fools_condition_only_rollup` family | absence cannot clear under partial coverage |

## Claim ceiling

This pin is a semantic north star and executable hostile corpus. It is not a
wire dependency and does not establish:

- current-engine emission or storage correspondence;
- producer authentication, custody, transport, or access control;
- untrusted-input size, collection-cardinality, and evaluation-time bounds;
- profile/catalog admission proving that the artifact's declared denominator is
  the compiled profile's denominator;
- independent verification that declared required distinctions and projection
  omissions match the governed provider/profile transforms;
- a structured machine-readable reason contract for `unsupported`;
- a current evidence-availability/read contract or end-to-end archived replay;
- all Portrait v1 categories;
- global joint-coherence or failure-domain independence;
- Nightshift runtime, scheduling-worker, notification, UI, authorization, or
  Docket correspondence.

The earned verdict at this layer is at most:

```text
NQ-DIAGNOSTIC-EXECUTION-CONTRACT-FOUNDATION
NQ-CANONICAL-VECTORS-EXECUTABLE
```

`RUNTIME-CORRESPONDENCE` remains unearned.
