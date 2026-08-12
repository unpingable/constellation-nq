# C1 Gen5 Live C2 — successor enrollment contract contradiction

Date: 2026-08-10

Status: **OPEN CONTRACT CONTRADICTION — AFFECTED IMPLEMENTATION STOPPED**

This is development evidence, not a qualification artifact or earned claim.

## Smallest counterexample

Let `proposal`, `proof`, and `finalization` describe one lawful finalized
successor enrollment, and let `enrollment = finalization.enrollment`.

1. `SuccessorFinalizationMatches.predecessorExact` requires
   `enrollment.predecessor = some proposal.predecessor`.
2. `PendingSuccessorPhaseBasis.selectedReceipt` and
   `LegalPhaseCorrespondence.pendingSelected` require the same selected
   successor to carry an adopted foundational enrollment and a signer
   enrollment transition.
3. The contract's sole bridge from foundational evidence to established
   enrollment authority is `FoundationalAuthorityBridge`.
4. That bridge consumes `FirstEnrollmentAuthority`, whose exact-match premise
   is `GrantMatchesEnrollment`.
5. `GrantMatchesEnrollment.firstEnrollment` requires
   `enrollment.predecessor = none`.

The same exact successor enrollment therefore has to satisfy both
`predecessor = some proposal.predecessor` and `predecessor = none`. No runtime
record or sealed wrapper can meet both premises.

## Exact contract sites

- `Skunkworks/StoreIntegritySignerLifecycle/ContractShape.lean:326-343`:
  `FoundationalAuthorityBridge` consumes `FirstEnrollmentAuthority`.
- `Skunkworks/StoreIntegritySignerLifecycle/Authority.lean:32-51`:
  `GrantMatchesEnrollment.firstEnrollment` fixes the predecessor to `none`.
- `Skunkworks/StoreIntegritySignerLifecycle/Authority.lean:198-213`:
  `SuccessorFinalizationMatches.predecessorExact` fixes it to `some`.
- `Skunkworks/StoreIntegritySignerLifecycle/ContractShape.lean:1064-1076` and
  `1213-1239`: selected pending-successor correspondence requires adopted
  foundational enrollment plus signer acceptance.
- `docs/c1-gen5-live-c2-contract-shape-2026-08-10/DECISIONS.md:179-207` and
  `390-408`: the normative prose requires the same forward enrollment layering
  and selected-successor basis.

## Runtime confirmation

- `crates/nq-store/src/store_generation/signer/records.rs:1160-1230` admits
  foundational enrollment only from a durably consumed initial MSG-02 result
  and the bootstrap grant chain.
- `crates/nq-store/src/store_generation/signer/external_governance.rs:1158-1180`
  enforces bootstrap grant key generation zero.
- The closed registry gives healthy rotation MSG-06/MSG-07 and recovery
  MSG-15, but none of those routes is an admitted input to the sole
  foundational bridge. Reusing ordinary MSG-01 would change its closed
  bootstrap-grant source/effect contract.

## Classification and stop boundary

Classification: **genuinely inconsistent contract**, not an implementation
error and not an impossible filesystem/cryptographic premise.

Stopped work:

- successor foundational-enrollment adoption;
- `PendingSelected` standing construction;
- healthy-rotation transition/currentness closure;
- successor-current reopen completion that depends on that transition.

Independent initial bootstrap/install, initial `GenerationCurrent` reopen,
durable append/replay, typed refusal, and verification work may continue.

Architecture must choose a lawful successor authority premise before the
stopped thread resumes. In particular, implementation must not invent another
external route, broaden ordinary MSG-01, or silently treat MSG-06/MSG-07/MSG-15
as foundational authority without a corresponding contract amendment.
