# NQ–Nightshift Stage 6 Foundation

Status: bounded implementation campaign  
Authorized: 2026-07-27

The operator's 2026-07-27 instruction to begin the NQ/Nightshift campaign is
new authority for this one Stage 6 foundation. It does not authorize general
Stage 6 implementation and does not change either subject's Portrait v1
completeness verdict.

## Slice

This repository contributes the producer-owned contract:

```text
nq.diagnostic_execution.v1
```

It accounts for the complete declared input denominator; occurrence and
raw/normalized/projected content identities; admission, normalization,
projection, refusal, acquisition failure, exclusion, and selection; exact
subject/profile/vantage/state/evaluator/threshold/projection/canonicalization
identities; projection omissions and claim-required distinctions; per-claim
dependencies and state bindings; exact per-input source intervals reachable
through those dependencies; raw-capture/redaction policy and derivation-time
availability; and the bounded NQ disposition or refusal.

The contract is strict, self-identifying, and JCS-canonical. Contract
validation does not authenticate a producer, admit evidence, grant reliance,
or authorize action. Set-like arrays use unsigned UTF-8 byte order, explicitly
not JCS's UTF-16 object-key order. The three positive/refusal/no-response files
are exact valid canonical artifact bytes. The two hostile collision files are
canonical, self-identified candidate bytes intentionally rejected by semantic
validation. All five intentionally have no trailing line feed.

Contract validation closes only the denominator declared by the artifact. It
does not prove that a caller's self-declared expected inputs equal the admitted
compiled profile/catalog manifest. That binding remains an engine integration
obligation; until it exists, this foundation is not a live producer contract.

The normative structural and cross-field validator in this bounded unit is the
strict Rust DTO in `nq-core`. A standalone JSON Schema is intentionally not
published yet: the repository's existing public read DTOs do not establish a
schema-file convention, and JSON Schema alone would duplicate only the shallow
shape while missing the partition, ordering, dependency, projection, clock,
coverage, and self-identity laws. A future transport publication must generate
or add a schema with a native drift gate; it may not weaken the Rust contract.

## Deliberate stop

The current engine's `EvaluationEnvelopeV2` retains selected evidence and an
evaluation watermark, but not the complete expected/received/admitted/
refused/failed/excluded/selected accounting required here. Conversion would
therefore reconstruct missing meaning. This campaign provides no conversion
and exposes no ordinary product command that seals caller-supplied JSON as NQ
authority.

Live engine emission, storage, API/pagination, cross-host intake, and a
production Nightshift conversion remain follow-on work. Until then this slice
can earn contract and executable-vector conformance only.

The availability field is historical at derivation. Current online/archive
availability needs a separate attributable custody/read artifact, not mutation
of this artifact. That surface and end-to-end replay remain unearned.

## Executable corpus

- `vectors/positive.json`: complete selected testimony and explicit bounded
  absence under joint coherence;
- `vectors/refused.json`: received testimony refused by NQ, with no exported
  claim;
- `vectors/provider_no_response.json`: NQ produces an unresolved artifact whose
  required provider input failed as `no_response`; this is not Nightshift
  receiving no NQ artifact;
- `vectors/hostile_projection_collision_match.json` and
  `vectors/hostile_projection_collision_mismatch.json`: distinct raw states
  collapse to the same projected artifact in canonical candidate bytes, while
  both candidates are rejected because the proposed claim requires the omitted
  `workflow_attempt` distinction.

These vectors prove producer-side contract behavior only. They do not prove a
Nightshift receiver, posture evaluator, schedule, or presentation.

## Non-authority

The artifact:

- is one NQ-owned bounded diagnostic result, not operational posture;
- exports producer identity but does not declare consumer reliance;
- distinguishes provider-level acquisition no-response inside its input
  accounting from Nightshift receiving no NQ artifact;
- does not authorize campaigns, notification, remediation, or execution;
- does not change the frozen `v0.1.0` tag or either subject's completeness.
