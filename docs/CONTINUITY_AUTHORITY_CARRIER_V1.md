# Continuity authority carrier v1

This contract closes one causal proof seam for one closed relation:
`substrate_incarnation`. It does not identify physical hosts and it does not
authorize effects.

## Ownership

Standing issues `standing.continuity_authority.v1`. It means only that the
exact edge `(subject, substrate_incarnation, predecessor, successor)` is
eligible to support continuity if later evidence establishes the successor
state. It does not assert that the transition occurred, that either substrate
claim is true, or that Nightshift may rely on an observation.

NQ verifies the pinned Standing Ed25519 key, key identity, Standing instance,
audience, exact edge, authority signature, and acquisition-commitment
signature. NQ then commits `nq.provider_acquisition_intent.v1` and the
`provider_invocation_started` fence in one SQLite transaction before it can
invoke the configured provider. The intent contains the complete signed
Standing bundle and the exact acquisition basis. The resulting provider
intake and diagnostic run retain the same preallocated acquisition identity.

Nightshift consumes `nq.diagnostic_admission_provenance.v2`, re-verifies the
signatures and all duplicated coordinates, and produces an owner-side
applicability verdict. Neither NQ nor Nightshift can issue the warrant.

AG and Docket do not participate. Continuity permission is not effectful work.

## Structural causality

The causal proof is not a clock comparison:

```text
signed Standing authority A
→ signed Standing commitment to exact NQ basis B
→ atomic NQ intent + invocation-start fence
→ provider invocation
→ provider intake
→ diagnostic execution
→ NQ admission provenance v2
```

`issued_at`, `committed_at`, provider times, and receipt times remain evidence
but do not establish this ordering. A completed acquisition without the
carrier cannot be amended or resealed into one that had it. Consequently an
authority learned late by Nightshift remains usable when it was already inside
the original NQ intent; an authority issued after the provider result cannot
retrofit that result.

The construction establishes source-independence only for the exact dependent
provider acquisition: its result did not yet exist when the signed prerequisite
was durably fenced. It is not a universal causal ledger and makes no claim
about unrelated planning evidence.

## Replay, deliberate reissuance, and revocation

- Exact Standing request replay converges on the same occurrence.
- A deliberate reissuance uses a new request and occurrence identity, even for
  the same edge.
- Exact NQ acquisition replay converges on the same intent/intake/artifact.
- Substitution under any reused authority, basis, acquisition, intent, or event
  identity refuses.
- Revocation prevents Standing from creating a new acquisition commitment.
  It does not rewrite a commitment that was validly issued earlier, erase
  historical evidence, or refresh that evidence.

## Physical-origin boundary

A valid carrier proves that the declared edge warrant was an authenticated
precondition. It does not prove that provider bytes actually originated on the
declared successor substrate. Production NQ v2 currently supplies no
independently owned predecessor/successor substrate coordinate. Nightshift
therefore reports that attribution as `unresolved`, and refuses routine
reliance, rather than treating reused subject/producer/scope/vantage tokens as
continuity.

Before rerunning full substrate attribution, a qualified producer or custody
boundary must supply independently authenticated origin evidence for the
observation. DNS, hostname, IP, matching configured identity, and authority
itself are not that evidence.

## Operator sequence

1. Standing issues an exact signed authority occurrence.
2. `nq diagnostics continuity-basis` verifies it and emits the exact static
   NQ acquisition basis plus the canonical `basis_digest` Standing must bind
   for a caller-preallocated acquisition ID. The digest is not a hash of
   incidental pretty-JSON or file bytes.
3. Standing verifies the NQ caller and signs a commitment to that exact basis.
4. `nq diagnostics execute-continuity` verifies the complete bundle before
   atomically fencing and invoking the provider.
5. `nq diagnostics qualify` returns v2 admission provenance for the resulting
   exact artifact.

Private signing seeds remain in Standing custody. NQ and Nightshift receive
only a pinned public key and immutable signed artifacts.
