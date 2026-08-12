# C1 Gen5 — Live C2 Store Path Closure

Date: 2026-08-10

Status: **AFFECTED SUCCESSOR THREAD STOPPED — CONTRACT CONTRADICTION DISCOVERED — NOT A QUALIFICATION RECORD**

Source basis: `campaign/c1-gen5` at
`895f653fdcf253c1d029cd1fc84badc1bb36979b`, implemented in the dedicated
local worktree branch `campaign/c1-gen5-live-c2-closure`.

Normative contract:
`skunkworks/formalization/docs/c1-gen5-live-c2-contract-shape-2026-08-10/DECISIONS.md`.

This ledger records development work only. It does not freeze a candidate,
earn a qualification claim, issue a certificate, or promote NQ.

## Live status

| Slice | Status | Evidence / boundary |
| --- | --- | --- |
| Exact source/ref/worktree basis | Implemented | Dedicated local branch at the audited Gen5 commit; no commit, remote, or publication action |
| Canonical implementation manifest and Store admission | Implemented and focused-tested | Sole RFC-8785 wire record/schema, exact-byte derivation, Store-private admission, schema parity, mutation, source-file mutation, and substitution tests |
| Foundational enrollment to signer acceptance | Initial path implemented and focused-tested; successor path blocked | Pre-generation initial foundational evidence, durable adoption, later signer acceptance, and process-local rewrap obey the forward direction; the closed contract has no lawful foundational-authority premise for a predecessor-bound successor |
| Closed MSG-01…MSG-16 signing registry | Implemented and focused-tested | Sole 16-family registry, 10 Store-signable families, 11 Store routes, 7 external routes, typed messages, closed census, domain/substitution hostiles, and durable envelopes |
| Store-owned installation and live phase context | Initial substrate implemented; integrated lifecycle incomplete | Store-owned bootstrap/install and initial-current reopen roots, phase-branded borrowed context, and C2 writer session exist; top Store roots are crate-private and unused; no legal pending/rotation continuation can be implemented under the contradictory successor premise |
| Durable custody/frontier, append, replay, and receipts | Component path implemented and focused-tested; rotation blocked | Store-derived custody/frontier, filesystem-first reconciliation, authenticated B/G append, SQL projection, replay/collision, and receipts are durable; healthy successor rotation/currentness is stopped at the contract contradiction |
| Governed external-carrier ingress | Typed route surface and durable substrate implemented; production reachability incomplete | Seven actor routes and corresponding current-session wrappers exist with exact replay/collision persistence, but the top Store lifecycle roots have no non-test production callers |
| Restart/reopen and recovery refusal | Initial `GenerationCurrent` implemented; successor/recovery matrix incomplete | Reopen re-verifies process, Store, manifest, enrollment, custody, and physical generation, restores the latest healthy MSG-08 frontier, and refuses pending/non-initial bindings; restore-successor and the full coordinate-mismatch/no-write matrix are absent |
| Development crash evidence | Exact inventory present; exhaustive recovery evidence incomplete | Source-derived 56-node `SC-01…SC-56` crash-cut manifest matches the current source byte-for-byte; it is an inventory, not proof that every cut has a restart/recovery test |
| Development call graph and mutator census | Partial / PASS respectively | Call graph 36/39; only CG-06, CG-07, and CG-21 fail. Mutator census passes at the reviewed current inventory |
| Broad regression | Known ten-failure baseline retained; one additional integration harness fails | `nq-store` library: 420 passed, 10 failed; all ten are the pre-existing governed-projection candidate-evidence mismatch observed before this campaign. Eight integration targets pass; `runtime_authority_noninjectability` has one failing harness because 5/35 Gen4 trybuild actual diagnostics add `nq_store::` type qualification absent from the expected snapshots; this campaign did not bless historical snapshots |
| Formal contract conformance | Formal build passes; runtime contradiction recorded | `lake build StoreIntegritySignerLifecycle -KwarningAsError=true` passes 19 jobs and the normative files are unchanged; the successor inconsistency is exposed by combining existing formal premises, while a missing link in the model prevents Lean from deriving the contradiction directly |

## Contract contradiction and stop boundary

Decision 4 requires `PendingSelected` to contain adopted successor
foundational enrollment plus signer acceptance. Decision 2's only authority
bridge consumes `FirstEnrollmentAuthority`, whose exact-match premise fixes
`EnrollmentRecord.predecessor = none`. A lawful successor enrollment is
predecessor-bound and fixes the same field to `some predecessor`.

The stopped work is:

- successor foundational-enrollment adoption;
- `PendingSelected` standing construction;
- healthy-rotation transition/currentness closure;
- successor-current reopen and restore-successor completion that depend on
  that transition.

No additional external route, broadened MSG-01 meaning, or invented authority
premise was introduced. The exact counterexample and source sites are recorded
in `CONTRACT_CONTRADICTION.md`.

## Remaining hostile findings

- Physical B/G append precedes its SQLite projection and the outer actor
  commit. Component tests defend authenticated orphan reconciliation, but the
  integrated live lifecycle does not yet exercise every torn boundary.
- Exact pending-SQL-commit durability is not observable: the pending insert is
  inside the outer transaction, and savepoint release is not crash durability.
- There is no live fresh-path closed-backend construction cut.
- Append/receipt observer labels bracket the durable batch effect rather than
  every internal carrier write and superblock synchronization.
- The top Store live-C2 roots and governed route machinery remain crate-private
  with no non-test production caller.
- Initial-current reopen lacks the required one-coordinate-at-a-time mismatch
  and no-write test matrix.

## Development acceptance gates

`PASS` means both implementation and current development evidence close the
named gate. A blocked or failed row is not described as substantially complete.

| Gate | Status | Exact current evidence / gap |
| --- | --- | --- |
| 1. One canonical manifest | PASS | One Rust semantic wire type and one JSON schema; six canonicalization/parity/mutation/substitution tests pass |
| 2. Manifest possession cannot create authority | PASS | Store-private borrowed admission and live-context/ingress-permit compile-fail specimens |
| 3. Enrollment legal direction | BLOCKED | Initial bootstrap direction is implemented and tested; the closed successor contract has no lawful foundational-authority premise |
| 4. No intentionally unconstructible production C2 permit | FAIL | Pending phase markers exist, but no legal Store actor can mint pending possession/selected permits under the contradictory premise |
| 5. One Store-owned live driver/path | FAIL | Fresh initial install and initial reopen exist; healthy rotation, successor continuation, and restore-successor do not |
| 6. No standing from caller digest containers | PASS | Private borrowed nonserializable context/session constructors plus compile-fail evidence |
| 7. Generic writer refuses every C2 state | FAIL | Fixed-file, symlink/wrong-type, and table detection exists; exhaustive S1–S5 restart/writer-refusal tests at every live I/O cut do not |
| 8. One production external-carrier ingress | FAIL | Seven typed actor methods and session wrappers exist, but top Store roots are crate-private and have no non-test production callers |
| 9. Durable replay/collision across restart | PASS | External-ingress and B/G component tests cover database reopen, exact replay, changed content, gaps, and orphan reprojection |
| 10. Durable B/G append and receipts | PASS | Physical authenticated carrier plus durable SQL projection/effect receipt and torn-tail component tests |
| 11. Every production signing path uses registry | PASS | All implemented signing consumes typed `SignerMessageV1` routes in the closed registry |
| 12. No arbitrary-byte/digest/domain signing API | PASS | No production raw-byte, raw-digest, caller-domain, or detached-signature signing API exists |
| 13. Live authority process-local/nonserializable | PASS | Private borrowed nonserde, non-Clone/non-Copy authority types plus compile-fail evidence |
| 14. Restart destroys live authority | PASS | Process/snapshot verification and absence of serialized authority; fresh authority is minted only after reopen verification |
| 15. Exact complete `GenerationCurrent` reopen only | FAIL | Initial binding reopens and pending state refuses; lawful completed successor currentness and the full coordinate-mismatch matrix are absent |
| 16. Pending state not directly reopened | PASS | No pending reopen constructor; lifecycle-bearing pending carrier suffixes refuse generic reprojection |
| 17. Named mismatches typed/no-write | FAIL | Focused collision/custody cases pass, but many coordinate mismatches share broad refusal variants and the required full no-write matrix is absent |
| 18. Call-graph verifier 39/39 | FAIL | 36/39; CG-06 healthy rotation, CG-07 successor continuation, and CG-21 restore-successor fail |
| 19. Mutator census passes/reviewed | PASS | Current census and allowlist pass; all newly observed roots are inventoried |
| 20. Full focused hostile/restart/compile-fail/replay/crash/lineage/no-write surface | FAIL | Component suites pass; integrated every-cut live crash recovery, successor lifecycle, restore driver, and exact reopen mismatch suites do not exist |

Current score: **11 PASS / 8 FAIL / 1 BLOCKED**.

## Verified development checkpoint

- Exact crash manifest: 56 source-derived nodes, `SC-01…SC-56`; checked
  byte-for-byte against `verify_c2_callgraph.py --emit-io-manifest`.
- Call graph: 36/39,
  `sha256:9562e85efb8d7d439cb37f558e705e3acc7424e4c9e2785f5313f5704bb5f7c7`.
- Call-graph verifier controls: 33/33 pass.
- Mutator census: PASS,
  `sha256:e7eb9e4b262f32a0a8b10588d67be700f0159bcc85f4acc1b57a65df9131fb0f`.
- Test inventory: 464 runnable tests, no ignored tests: 430 library
  units, 30 integration-harness tests, and 4 doctests.
- Broad library run: 420 pass, 10 known pre-existing failures.
- Broad integration run: eight targets pass; `runtime_authority_noninjectability`
  reports 2 pass and 1 failing harness because 5/35 historical trybuild
  snapshots have spelling-only output differences. This was not established
  by the pre-edit baseline, so it is reported as current rather than labeled
  pre-existing.
- Doctests: 4/4 pass.
- Formal build: PASS, 19 jobs; no `sorry` or custom axiom was added.

## Explicit boundaries

- Qualification-only: candidate freeze, candidate-specific manifest instance,
  detached qualification replay, certificate, packet/index, registry entry,
  independent review, and claim publication.
- Later documentation: canonical README/status/architecture/operator rewrite.
- Out of scope: Gen4 compatibility, WU-16, downstream C3/F/M/L authority,
  decommission expansion, repository promotion, GitHub/remotes/PR work, and
  unrelated refactoring.
