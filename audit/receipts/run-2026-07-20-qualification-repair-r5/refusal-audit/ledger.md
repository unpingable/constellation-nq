# Admissibility conformance ledger — nq-ng

> Lean proves the abstract law. This audit demonstrates that the pinned runtime artifact corresponds to that law under the explicit assumptions listed here. It is not a verified-implementation claim, and a green gate is never evidence that a Lean theorem holds.

- as of: `2026-07-20`
- tool: `admissibility-audit` `0.1.0` revision `unrecorded-development-build` executable sha256 `4cef41d898e4ad770196a5709d1bcbcc5bd6757a3c63938f53824363aa68ede9`
- catalog: `/home/jbeck/git/audit/controls/v14` sha256 `ec7ffee1192d5411f4adab2569288d4bcd61581040d9c6b66473871c3999c3ef`
- target pin: `git:2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`
- qualification campaign: `AC-AUDIT-1`
- target post-run pin: `git:2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`
- lean baseline: `unpingable/lean` release `14.0.0` revision `ff491b808ebeab2a132d9ade46d234cf85dcfbe9` tree `72cba07e35588e9f67c252b0bd92cf0523ab178f` toolchain `leanprover/lean4:v4.29.0`
- authority fence: `lean_theorems_are_specification_evidence_and_never_runtime_authority`

## Gate: **Pass**

| policy | result | detail |
|---|---|---|
| census-fully-classified | Pass | 0 unclassified projection(s), 0 serialization violation(s), 0 missing entry point(s) |
| no-obstructions | Pass | 0 obstruction(s) |
| no-expired-waiver | Pass | none expired |
| target-pinned-clean | Pass | initial target pin is admissible |
| target-stable-during-run | Pass | initial and final pins match |
| mutation-execution-complete | Pass | 2/2 executed |
| mutations-bite | Pass | 2/2 bit |
| active-controls-pass | Pass | 3 control(s) evaluated |

## AC-R1 (rung 1) — Domain transport preserves authority; diagnostics do not repair evidence [inactive]
*registered and pinned; no claim of executable coverage in this campaign*
- scope: `Calculus`
- campaign: `AC-AUDIT-FOUNDATION`
- law: `Admissibility.PathVerdict.mapDomain_authority_iff` (`LeanProofs/Admissibility/PathVerdict/Domains.lean`)
- law: `Admissibility.PathVerdict.located_pinpoints` (`LeanProofs/Admissibility/PathVerdict/Located.lean`)
- law: `Admissibility.PathVerdict.mapId_authority_iff` (`LeanProofs/Admissibility/PathVerdict/Located.lean`)
- law: `Admissibility.PathVerdict.forget_foldLocated` (`LeanProofs/Admissibility/PathVerdict/Located.lean`)

| control | version | verdict | claim | findings |
|---|---|---|---|---|
| AC-R1-001 | 1 | Inactive | Transporting a verdict through a declared domain map must preserve and reflect its authority-bearing status. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |
| AC-R1-002 | 1 | Inactive | Adding or renaming diagnostic locations must not repair an obstruction; unique caller-supplied ids must still identify the obstructing edge, and erasure must recover the undecorated verdict. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |

Nonclaims:
- Located ids are caller-supplied diagnostic labels, not authenticated origins or occurrence history.
- Relocation is not repair; erasure recovers the Edges fold exactly.

## AC-R2 (rung 2) — Governed-family signature: candidate is not authority [inactive]
*registered and pinned; no claim of executable coverage in this campaign*
- scope: `Calculus`
- campaign: `AC-AUDIT-FOUNDATION`
- law: `Admissibility.Calculus.GovernedFamily.no_claim_erasing_check_is_faithful` (`LeanProofs/Admissibility/Calculus/Core.lean`)
- law: `Admissibility.Calculus.GovernedFamily.authority_requires_standing` (`LeanProofs/Admissibility/Calculus/Core.lean`)
- law: `Admissibility.Calculus.GovernedFamily.refusal_refutes_authority` (`LeanProofs/Admissibility/Calculus/Core.lean`)
- law: `Admissibility.Calculus.GovernedFamily.authority_preserves_custody` (`LeanProofs/Admissibility/Calculus/Core.lean`)

| control | version | verdict | claim | findings |
|---|---|---|---|---|
| AC-R2-001 | 1 | Inactive | No runtime boolean check that erases which claim was witnessed may gate authority-bearing paths. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |
| AC-R2-002 | 1 | Inactive | Authority-bearing runtime paths require native witness evidence; standing and custody are necessary books rather than alternate authority constructors, and native refusal evidence excludes authority. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |

Nonclaims:
- No runtime correspondence or conformance is proved by rung 2.
- Authority is derived (Nonempty witness); there is no alternative introduction rule.

## AC-R3 (rung 3) — Concrete instances: no endpoint-only check is a faithful judge [inactive]
*registered and pinned; no claim of executable coverage in this campaign*
- scope: `Calculus`
- campaign: `AC-AUDIT-FOUNDATION`
- law: `Admissibility.Calculus.Instances.BoundedPaidReachability.signature_refuses_endpoint_only_checks` (`LeanProofs/Admissibility/Calculus/Instances/BoundedPaidReachability.lean`)
- law: `Admissibility.Calculus.Instances.BoundedPaidReachability.Staged.Run.occurrence_provenance` (`LeanProofs/Admissibility/Calculus/Instances/BoundedPaidReachability/Native.lean`)
- law: `Admissibility.Calculus.Instances.Weathering.weathering_authority_iff_native` (`LeanProofs/Admissibility/Calculus/Instances/Weathering.lean`)
- law: `Admissibility.Calculus.Instances.Weathering.weathering_refuses_stale_direct` (`LeanProofs/Admissibility/Calculus/Instances/Weathering.lean`)

| control | version | verdict | claim | findings |
|---|---|---|---|---|
| AC-R3-001 | 1 | Inactive | Runtime checks that observe only endpoints (final state, exit label) must not stand in for history-bearing authority judgments. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |
| AC-R3-002 | 1 | Inactive | Every final wallet or paid occurrence must retain provenance to initial inventory or an initially held warrant; endpoint equality is not provenance. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |
| AC-R3-003 | 1 | Inactive | The runtime Weathering decision matrix must correspond exactly to the native admissibility judgment, including refusal of stale direct reliance. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |

Nonclaims:
- Staleness is a licensing judgment, not negation.
- No discharge/payment lifecycle is proved.

## AC-R4 (rung 4) — Refusal-packet losslessness [active]
- scope: `Calculus`
- campaign: `AC-AUDIT-1`
- law: `Admissibility.Calculus.LosslessEncoding` (`LeanProofs/Admissibility/Calculus/Spine.lean`)
- law: `Admissibility.Calculus.LosslessEncoding.encodePacket_injective` (`LeanProofs/Admissibility/Calculus/Spine.lean`)
- law: `Admissibility.Calculus.LosslessEncoding.distinct_refusals_encode_distinct` (`LeanProofs/Admissibility/Calculus/Spine.lean`)
- law: `Admissibility.Calculus.LosslessEncoding.decode_encodePacket` (`LeanProofs/Admissibility/Calculus/Spine.lean`)
- law: `Admissibility.Calculus.LosslessEncoding.refusal_recoverable` (`LeanProofs/Admissibility/Calculus/Spine.lean`)

| control | version | verdict | claim | findings |
|---|---|---|---|---|
| AC-R4-001 | 1 | Pass | Rich refusal payloads remain distinguishable through every testimonial boundary: same coarse code with distinct witnesses must stay distinguishable on each testimonial surface. | protocol-wire: Pass — reason: helper-protocol-wire-preserves-refusal-pair evidence command passed; evidence: command:AC-R4-001:helper-protocol-wire-preserves-refusal-pair<br>product-result-wire: Pass — reason: governed-result-wire-preserves-helper-payload-pair evidence command passed; evidence: command:AC-R4-001:governed-result-wire-preserves-helper-payload-pair<br>product-result-wire: Pass — reason: admitted-wire-requires-exact-evaluation-envelopes evidence command passed; evidence: command:AC-R4-001:admitted-wire-requires-exact-evaluation-envelopes<br>product-result-wire: Pass — reason: product-result-frame-reopens-exactly evidence command passed; evidence: command:AC-R4-001:product-result-frame-reopens-exactly<br>product-result-wire: Pass — reason: product-result-frame-refuses-invalid-source evidence command passed; evidence: command:AC-R4-001:product-result-frame-refuses-invalid-source<br>status-read-model: Pass — reason: real-host-detector-preserves-structured-refusal-pair evidence command passed; evidence: command:AC-R4-001:real-host-detector-preserves-structured-refusal-pair<br>status-read-model: Pass — reason: real-host-detector-pair-survives-governed-store-reopen evidence command passed; evidence: command:AC-R4-001:real-host-detector-pair-survives-governed-store-reopen<br>status-read-model: Pass — reason: finding-uses-only-exact-evaluation-context evidence command passed; evidence: command:AC-R4-001:finding-uses-only-exact-evaluation-context<br>status-read-model: Pass — reason: actual-helper-collection-preserves-refusals-through-status evidence command passed; evidence: command:AC-R4-001:actual-helper-collection-preserves-refusals-through-status<br>collection-cli: Pass — reason: cli-preserves-all-governed-pairs evidence command passed; evidence: command:AC-R4-001:cli-preserves-all-governed-pairs<br>collection-cli: Pass — reason: structured-collection-cli-reopens-v2-wire evidence command passed; evidence: command:AC-R4-001:structured-collection-cli-reopens-v2-wire<br>collection-cli: Pass — reason: cli-dry-watcher-preserves-helper-pair evidence command passed; evidence: command:AC-R4-001:cli-dry-watcher-preserves-helper-pair<br>collection-cli: Pass — reason: cli-evaluation-cursor-is-exact-and-frozen evidence command passed; evidence: command:AC-R4-001:cli-evaluation-cursor-is-exact-and-frozen<br>collection-cli: Pass — reason: cli-refusal-cursor-is-exact-and-unique evidence command passed; evidence: command:AC-R4-001:cli-refusal-cursor-is-exact-and-unique<br>daemon-log: Pass — reason: daemon-log-preserves-helper-pair evidence command passed; evidence: command:AC-R4-001:daemon-log-preserves-helper-pair<br>sqlite-history: Pass — reason: sqlite-preserves-linked-refusal-pair evidence command passed; evidence: command:AC-R4-001:sqlite-preserves-linked-refusal-pair<br>sqlite-history: Pass — reason: sqlite-refuses-bare-rejected-custody evidence command passed; evidence: command:AC-R4-001:sqlite-refuses-bare-rejected-custody<br>sqlite-history: Pass — reason: admitted-chain-commits-as-one-unit evidence command passed; evidence: command:AC-R4-001:admitted-chain-commits-as-one-unit<br>sqlite-history: Pass — reason: historical-admitted-chain-requires-run-result evidence command passed; evidence: command:AC-R4-001:historical-admitted-chain-requires-run-result<br>sqlite-history: Pass — reason: historical-admitted-result-requires-exact-evaluation-set evidence command passed; evidence: command:AC-R4-001:historical-admitted-result-requires-exact-evaluation-set<br>sqlite-history: Pass — reason: completed-response-run-requires-canonical-result evidence command passed; evidence: command:AC-R4-001:completed-response-run-requires-canonical-result<br>sqlite-history: Pass — reason: admitted-suite-and-evaluator-bindings-rollback-atomically evidence command passed; evidence: command:AC-R4-001:admitted-suite-and-evaluator-bindings-rollback-atomically<br>sqlite-history: Pass — reason: historical-admitted-suite-omission-fails-closed evidence command passed; evidence: command:AC-R4-001:historical-admitted-suite-omission-fails-closed<br>sqlite-history: Pass — reason: historical-admitted-evaluator-substitution-fails-closed evidence command passed; evidence: command:AC-R4-001:historical-admitted-evaluator-substitution-fails-closed<br>sqlite-history: Pass — reason: historical-admitted-evaluation-order-fails-closed evidence command passed; evidence: command:AC-R4-001:historical-admitted-evaluation-order-fails-closed<br>status-read-model: Pass — reason: evaluation-refusal-boundary-is-producer-closed evidence command passed; evidence: command:AC-R4-001:evaluation-refusal-boundary-is-producer-closed<br>status-read-model: Pass — reason: evaluation-refusal-code-is-producer-closed evidence command passed; evidence: command:AC-R4-001:evaluation-refusal-code-is-producer-closed<br>status-read-model: Pass — reason: evaluation-refusal-message-is-producer-closed evidence command passed; evidence: command:AC-R4-001:evaluation-refusal-message-is-producer-closed<br>status-read-model: Pass — reason: evaluation-refusal-cannot-borrow-affirmative-evidence evidence command passed; evidence: command:AC-R4-001:evaluation-refusal-cannot-borrow-affirmative-evidence<br>sqlite-history: Pass — reason: historical-run-cannot-borrow-another-instance-admission evidence command passed; evidence: command:AC-R4-001:historical-run-cannot-borrow-another-instance-admission<br>local-api: Pass — reason: api-transports-large-canonical-response-exactly evidence command passed; evidence: command:AC-R4-001:api-transports-large-canonical-response-exactly<br>status-read-model: Pass — reason: status-preserves-timeout-phase-pair evidence command passed; evidence: command:AC-R4-001:status-preserves-timeout-phase-pair<br>status-read-model: Pass — reason: status-preserves-profile-pair evidence command passed; evidence: command:AC-R4-001:status-preserves-profile-pair<br>status-read-model: Pass — reason: status-backup-preserves-admission-refusal-pair evidence command passed; evidence: command:AC-R4-001:status-backup-preserves-admission-refusal-pair<br>product-result-wire: Pass — reason: wire-custody-status-preserve-protocol-rejection-pair evidence command passed; evidence: command:AC-R4-001:wire-custody-status-preserve-protocol-rejection-pair<br>local-api: Pass — reason: api-v2-preserves-all-governed-pairs evidence command passed; evidence: command:AC-R4-001:api-v2-preserves-all-governed-pairs<br>local-api: Pass — reason: api-v3-status-history-and-findings-preserve-evaluation-pair evidence command passed; evidence: command:AC-R4-001:api-v3-status-history-and-findings-preserve-evaluation-pair<br>local-api: Pass — reason: api-evaluation-cursor-is-exact-and-frozen evidence command passed; evidence: command:AC-R4-001:api-evaluation-cursor-is-exact-and-frozen<br>cold-archive: Pass — reason: archive-reopens-all-governed-pairs evidence command passed; evidence: command:AC-R4-001:archive-reopens-all-governed-pairs<br>collection-cli: Pass — reason: cli-pages-complete-custody-pair evidence command passed; evidence: command:AC-R4-001:cli-pages-complete-custody-pair<br>cold-archive: Pass — reason: evaluation-pair-survives-cli-backup-archive evidence command passed; evidence: command:AC-R4-001:evaluation-pair-survives-cli-backup-archive<br>cold-archive: Pass — reason: immutable-archive-open-preserves-sealed-inventory evidence command passed; evidence: command:AC-R4-001:immutable-archive-open-preserves-sealed-inventory<br>cold-archive: Pass — reason: archive-validators-cross-every-history-page evidence command passed; evidence: command:AC-R4-001:archive-validators-cross-every-history-page<br>status-read-model: Pass — reason: public-evaluation-history-crosses-maximum-page evidence command passed; evidence: command:AC-R4-001:public-evaluation-history-crosses-maximum-page<br>*: Pass — reason: mutation erase-exchange-timeout-phase bit (pristine green, mutant red); evidence: mutation:AC-R4-001:erase-exchange-timeout-phase |
| AC-R4-002 | 1 | Pass | Every coarse projection over a refusal/outcome type is classified, and non-testimonial projections carry explicit allowed/forbidden uses. | *: Pass — reason: projection semantic_report_status is classified; evidence: projection:crates/nq-core/src/engine.rs:free:semantic_report_status<br>*: Pass — reason: projection acquisition_code is classified; evidence: projection:crates/nq-core/src/engine.rs:free:acquisition_code<br>*: Pass — reason: projection as_str is classified; evidence: projection:crates/nq-profiles/src/descriptor.rs:ProfileDigest:as_str<br>*: Pass — reason: projection as_str is classified; evidence: projection:crates/nq-profiles/src/identity.rs:ProfileSemanticId:as_str<br>*: Pass — reason: projection as_str is classified; evidence: projection:crates/nq-protocol/src/canonical.rs:Sha256Digest:as_str |
| AC-R4-003 | 1 | Pass | Stored refusal outcomes are rendered from stored detail, never re-derived from the coarse code. | sqlite-history: Pass — reason: sqlite-reopens-stored-refusal-detail evidence command passed; evidence: command:AC-R4-003:sqlite-reopens-stored-refusal-detail<br>status-read-model: Pass — reason: status-renders-canonical-stored-result evidence command passed; evidence: command:AC-R4-003:status-renders-canonical-stored-result<br>collection-cli: Pass — reason: cli-renders-stored-result evidence command passed; evidence: command:AC-R4-003:cli-renders-stored-result<br>local-api: Pass — reason: api-renders-stored-result evidence command passed; evidence: command:AC-R4-003:api-renders-stored-result<br>cold-archive: Pass — reason: archive-renders-preserved-result evidence command passed; evidence: command:AC-R4-003:archive-renders-preserved-result<br>*: Pass — reason: mutation rederive-status-detail-from-code bit (pristine green, mutant red); evidence: mutation:AC-R4-003:rederive-status-detail-from-code |

Nonclaims:
- The Lean spine serializes no witness identity or multiplicity; witnesses remain recoverable from the family's evidence-returning checker.
- No runtime serialization, canonical byte encoding, or cryptographic commitment is proved by rung 4.
- SpineEncoding is permissive and must never be described as lossless; LosslessEncoding is the only exact contract.

## AC-R5 (rung 5) — Indexed comparison: collapsed projections recover nothing [inactive]
*registered and pinned; no claim of executable coverage in this campaign*
- scope: `Calculus`
- campaign: `AC-AUDIT-5`
- law: `Admissibility.Calculus.Comparison.DirectionalWithLossReceipt.no_left_inverse` (`LeanProofs/Admissibility/Calculus/Comparison.lean`)
- law: `Admissibility.Calculus.Comparison.SeparationReceipt.not_universal_preservation` (`LeanProofs/Admissibility/Calculus/Comparison.lean`)
- law: `Admissibility.Calculus.Comparison.collapsed_map_rejects_exact_representation` (`LeanProofs/Admissibility/Calculus/Comparison.lean`)

| control | version | verdict | claim | findings |
|---|---|---|---|---|
| AC-R5-001 | 1 | Inactive | When two distinct source-positive values collapse under one declared projection, that projection must not be classified as exact representation and no decoder may claim to recover every source. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |
| AC-R5-002 | 1 | Inactive | A declared separation must retain both its source-positive counterexample and target-positive control, and must reject universal preservation through that exact declared map. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |

Nonclaims:
- The concrete seven-entry comparison ledger is research-tree evidence custody, not public surface.
- Digests do not prove comparison laws.
- Published v14 does not establish exact-basis promotion, stored-artifact identity, or a rule that byte-identical reconstruction carries authority.

## AC-R6 (rung 6) — Stored decisions are rendered, never re-decided [inactive]
*registered and pinned; no claim of executable coverage in this campaign*
- scope: `Calculus`
- campaign: `AC-AUDIT-2`
- law: `Admissibility.Calculus.Crossing.check` (`LeanProofs/Admissibility/Calculus/Crossing.lean`)
- law: `Admissibility.Calculus.Crossing.checkedProjectionExact` (`LeanProofs/Admissibility/Calculus/Crossing.lean`)
- law: `Admissibility.Calculus.Crossing.CheckedCrossing.verdict_authority_iff_result` (`LeanProofs/Admissibility/Calculus/Crossing.lean`)
- law: `Admissibility.Calculus.Crossing.authority_iff_components` (`LeanProofs/Admissibility/Calculus/Crossing.lean`)
- law: `Admissibility.Calculus.Crossing.CheckedCrossing.both_refusals_located_and_decode` (`LeanProofs/Admissibility/Calculus/Crossing.lean`)

| control | version | verdict | claim | findings |
|---|---|---|---|---|
| AC-R6-001 | 1 | Inactive | Every downstream view of a stored decision renders the stored pair; no consumer re-runs the native decision procedure. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |
| AC-R6-002 | 1 | Inactive | Stored result, verdict, located diagnostics, and testimonial renderings must agree with the same stored native pair across accepted, left-refused, right-refused, and both-refused branches. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |

Nonclaims:
- The verdict serializes refusals, not accepted witness identity.
- Rollback resistance beyond the stored pair requires store-epoch ceremony not proved here.

## AC-R7 (rung 7) — Origin non-transport and bounded sequential lifecycle refusal [inactive]
*registered and pinned; no claim of executable coverage in this campaign*
- scope: `Calculus`
- campaign: `AC-AUDIT-3`
- law: `Admissibility.Calculus.Instances.BreakGlass.witness_retains_exact_origin` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass.lean`)
- law: `Admissibility.Calculus.Instances.BreakGlass.Ref.same_local_ne_of_origin_ne` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass/LifecycleOrigin.lean`)
- law: `Admissibility.Calculus.Instances.BreakGlass.foreign_claim_rejected` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass.lean`)
- law: `Admissibility.Calculus.Instances.BreakGlass.OriginBound.EndToEnd.settlement_before_commit_rejected` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass/Lifecycle.lean`)
- law: `Admissibility.Calculus.Instances.BreakGlass.OriginBound.EndToEnd.duplicate_settlement_rejected` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass/Lifecycle.lean`)
- law: `Admissibility.Calculus.Instances.BreakGlass.OriginBound.EndToEnd.no_exceptional_attempt_after_commit` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass/Lifecycle.lean`)
- law: `Admissibility.Calculus.Instances.BreakGlass.OriginBound.EndToEnd.no_exceptional_attempt_after_settlement` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass/Lifecycle.lean`)
- law: `Admissibility.Calculus.Instances.BreakGlass.phase_only_checker_cannot_be_faithful` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass.lean`)
- law: `Admissibility.Calculus.Instances.BreakGlass.exceptional_permission_does_not_embed_into_authorized_verdict` (`LeanProofs/Admissibility/Calculus/Instances/BreakGlass/Comparison.lean`)

| control | version | verdict | claim | findings |
|---|---|---|---|---|
| AC-R7-001 | 1 | Inactive | Origin identifiers travel with witnesses and authority across every runtime boundary; foreign-origin claims are structurally refused, not coerced. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |
| AC-R7-002 | 1 | Inactive | Within the published bounded sequential model, settlement before commit and duplicate settlement are refused, and no exceptional attempt begins after commit or settlement. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |
| AC-R7-003 | 1 | Inactive | Exceptional permission remains separate from ordinary authorization; a runtime adapter must not coerce the retained ordinary denial into an authorized verdict. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |

Nonclaims:
- Sequential replay protection only; no claim over arbitrary concurrent, restart, serialization, or distributed-replay adversaries.
- No origin-allocator uniqueness, attestor honesty, runtime invocation counts, or runtime conformance.
- No byte serialization or cryptographic commitment; settlement standing does not imply audit cleanliness; custody does not imply standing or authority.

## ANNEX-NR — Temporal non-resurrection (outside-calculus annex) [inactive]
*registered and pinned; no claim of executable coverage in this campaign*
- scope: `OutsideCalculus`
- campaign: `AC-AUDIT-4`
- law: `Admissibility.TemporalBasis.retired_source_cannot_become_live_by_time_passing` (`LeanProofs/Admissibility/TemporalBasis.lean`)
- law: `Admissibility.DeferredWitness.no_retroactive_standing` (`LeanProofs/Admissibility/DeferredWitness.lean`)
- law: `Admissibility.DeferredWitness.necromancy_rejected` (`LeanProofs/Admissibility/DeferredWitness.lean`)

| control | version | verdict | claim | findings |
|---|---|---|---|---|
| ANNEX-NR-001 | 1 | Inactive | No runtime path revives a retired source merely because time passed or backfills standing for a claim that already relied on a later grant. | *: Inactive — reason: registered and pinned; no claim of executable coverage in this campaign; evidence: none |

Nonclaims:
- These declarations live in the broader published Admissibility tree, not in the v14 Calculus surface.
- The annex does not extend rung 7's bounded sequential model to restart, serialization, concurrency, or distributed replay.
- DeferredWitness Layer B (budget/refresh) remains an open frontier.

## Assumptions

- Forcing fixtures and commands are supplied by the target repo and trusted to test what they claim; the framework verifies exit codes, mutation-anchor uniqueness, and classification completeness — not fixture intent.
- The static census is heuristic (string-returning functions with projection-shaped names); projections outside the heuristic must be declared in the manifest to be governed.
- Lab specimens provide compatibility evidence about the framework's mechanics, never live testimony about any production estate.

