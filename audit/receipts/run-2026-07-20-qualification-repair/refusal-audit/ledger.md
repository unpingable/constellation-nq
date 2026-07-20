# Admissibility conformance ledger — nq-ng

> Lean proves the abstract law. This audit demonstrates that the pinned runtime artifact corresponds to that law under the explicit assumptions listed here. It is not a verified-implementation claim, and a green gate is never evidence that a Lean theorem holds.

- as of: `2026-07-20`
- target pin: `git:dd0d23f6c1339d4dbce8a44ed4d8b4e715629f71 (dirty)`
- lean baseline: `lean` release `14.0.0` revision `ff491b808ebeab2a132d9ade46d234cf85dcfbe9`
- authority fence: `lean_theorems_are_specification_evidence_and_never_runtime_authority`

## Gate: **Fail**

| policy | result | detail |
|---|---|---|
| census-fully-classified | Pass | 0 unclassified projection(s), 0 serialization violation(s), 0 missing entry point(s) |
| no-obstructions | Pass | 0 obstruction(s) |
| no-expired-waiver | Pass | none expired |
| mutations-bite | Pass | 2/2 bit |
| active-controls-pass | Fail | failing: AC-R4-001, AC-R4-003 |

## AC-R1 (rung 1) — Domain transport and located diagnostics do not repair evidence [inactive]
*registered and pinned; no claim of executable coverage in this campaign*

| control | verdict | findings |
|---|---|---|
| AC-R1-001 | Inactive | *: Inactive — registered and pinned; no claim of executable coverage in this campaign |

Nonclaims:
- Located ids are caller-supplied diagnostic labels, not authenticated origins or occurrence history.
- Relocation is not repair; erasure recovers the Edges fold exactly.

## AC-R2 (rung 2) — Governed-family signature: candidate is not authority [inactive]
*registered and pinned; no claim of executable coverage in this campaign*

| control | verdict | findings |
|---|---|---|
| AC-R2-001 | Inactive | *: Inactive — registered and pinned; no claim of executable coverage in this campaign |

Nonclaims:
- No runtime correspondence or conformance is proved by rung 2.
- Authority is derived (Nonempty witness); there is no alternative introduction rule.

## AC-R3 (rung 3) — Concrete instances: no endpoint-only check is a faithful judge [inactive]
*registered and pinned; no claim of executable coverage in this campaign*

| control | verdict | findings |
|---|---|---|
| AC-R3-001 | Inactive | *: Inactive — registered and pinned; no claim of executable coverage in this campaign |

Nonclaims:
- Staleness is a licensing judgment, not negation.
- No discharge/payment lifecycle is proved.

## AC-R4 (rung 4) — Refusal-packet losslessness [active]

| control | verdict | findings |
|---|---|---|
| AC-R4-001 | Fail | protocol-wire: Pass — forcing evidence command passed<br>collection-cli: Fail — forcing evidence command failed (exit Some(101))<br>daemon-log: Fail — forcing evidence command failed (exit Some(101))<br>sqlite-history: Pass — forcing evidence command passed<br>status-read-model: Fail — forcing evidence command failed (exit Some(101))<br>local-api: Fail — forcing evidence command failed (exit Some(101))<br>cold-archive: Pass — forcing evidence command passed<br>*: Pass — mutation delete-acquisition-detail bit (check went red) |
| AC-R4-002 | Pass | *: Pass — projection semantic_report_status is classified<br>*: Pass — projection acquisition_code is classified<br>*: Pass — projection as_str is classified<br>*: Pass — projection as_str is classified<br>*: Pass — projection as_str is classified |
| AC-R4-003 | Fail | sqlite-history: Pass — forcing evidence command passed<br>status-read-model: Fail — forcing evidence command failed (exit Some(101))<br>*: Pass — mutation rederive-status-detail-from-code bit (check went red) |

Nonclaims:
- The Lean spine serializes no witness identity or multiplicity; witnesses remain recoverable from the family's evidence-returning checker.
- No runtime serialization, canonical byte encoding, or cryptographic commitment is proved by rung 4.
- SpineEncoding is permissive and must never be described as lossless; LosslessEncoding is the only exact contract.

## AC-R5 (rung 5) — Indexed comparison: collapsed projections recover nothing [inactive]
*registered and pinned; no claim of executable coverage in this campaign*

| control | verdict | findings |
|---|---|---|
| AC-R5-001 | Inactive | *: Inactive — registered and pinned; no claim of executable coverage in this campaign |

Nonclaims:
- The concrete seven-entry comparison ledger is research-tree evidence custody, not public surface.
- Digests do not prove comparison laws.

## AC-R6 (rung 6) — Stored decisions are rendered, never re-decided [inactive]
*registered and pinned; no claim of executable coverage in this campaign*

| control | verdict | findings |
|---|---|---|
| AC-R6-001 | Inactive | *: Inactive — registered and pinned; no claim of executable coverage in this campaign |

Nonclaims:
- The verdict serializes refusals, not accepted witness identity.
- Rollback resistance beyond the stored pair requires store-epoch ceremony not proved here.

## AC-R7 (rung 7) — Origin and history non-transport; lifecycle non-resurrection [inactive]
*registered and pinned; no claim of executable coverage in this campaign*

| control | verdict | findings |
|---|---|---|
| AC-R7-001 | Inactive | *: Inactive — registered and pinned; no claim of executable coverage in this campaign |
| AC-R7-002 | Inactive | *: Inactive — registered and pinned; no claim of executable coverage in this campaign |

Nonclaims:
- Sequential replay protection only (BreakGlass/Lifecycle.lean:423); no claim over arbitrary concurrent or restart adversaries.
- No origin-allocator uniqueness, attestor honesty, runtime invocation counts, or runtime conformance.
- No byte serialization or cryptographic commitment; settlement standing does not imply audit cleanliness; custody does not imply standing or authority.

## ANNEX-NR — Temporal non-resurrection (outside-calculus annex) [inactive]
*registered and pinned; no claim of executable coverage in this campaign*

| control | verdict | findings |
|---|---|---|
| ANNEX-NR-001 | Inactive | *: Inactive — registered and pinned; no claim of executable coverage in this campaign |

Nonclaims:
- These declarations live in the broader Admissibility tree, not the v14 Calculus surface; the calculus's per-rung nonclaim fences do not cover them.
- DeferredWitness Layer B (budget/refresh) is a declared open frontier.

## Assumptions

- Forcing fixtures and commands are supplied by the target repo and trusted to test what they claim; the framework verifies exit codes, mutation-anchor uniqueness, and classification completeness — not fixture intent.
- The static census is heuristic (string-returning functions with projection-shaped names); projections outside the heuristic must be declared in the manifest to be governed.
- Lab specimens provide compatibility evidence about the framework's mechanics, never live testimony about any production estate.

