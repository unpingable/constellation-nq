# C1 Gen5 — Live C2 Store Path Closure: resumed implementation ledger

Date resumed: 2026-08-11

Status: **IMPLEMENTATION GATES 1–34 CLOSED; PRODUCTION CANDIDATE VERIFIER BLOCKS GATE 35 — NOT A QUALIFICATION RECORD**

Source basis remains `campaign/c1-gen5-live-c2-closure` at the original
campaign HEAD `895f653fdcf253c1d029cd1fc84badc1bb36979b`, with the intentional
uncommitted implementation preserved and continued in place. No reset, clean,
stash, rebase, replacement, commit, push, freeze, or qualification action was
performed.

The earlier stop report in `CAMPAIGN.md` and counterexample in
`CONTRACT_CONTRADICTION.md` remain historical development evidence. The
normative contract now closes the authority law with four exhaustive
foundation-adoption lineages: initial external, ordinary successor continuity,
historical restore, and new-foundation recovery.

This ledger is development status only. It does not freeze a candidate, earn a
qualification claim, issue a certificate, or promote NQ.

## Resume checkpoint

The following hashes were recorded before the resumed implementation changed
the load-bearing driver files:

| File | Resume SHA-256 |
| --- | --- |
| `store_generation/live_c2.rs` | `171b6852aaf951563d1c44bc25ab2fae6eeb2b13c8d559e1219a0f4a0967a310` |
| `signer/records.rs` | `de2099dc1c17f3886a77cd0e44faff31d7e99299f07767690f543d7fb1f8289c` |
| `signer/terminal.rs` | `ee1345e46d315e242b80e36cccd2bf18c75b15a5256cb60ba99ada120f6123d7` |
| `signer/lineage.rs` | `f58e2f2954d017001a33d5a42f2d71860d150408c6ef82b2bb34af63af04fdf0` |
| `signer/coordinator.rs` | `52d9b96403d960407fad2cb6bb7f3f9fcd0852d10f775646ded5f4d2d311de27` |

## Implemented slices

| Slice | Status | Current evidence / boundary |
| --- | --- | --- |
| Preserved paused worktree | Implemented | Existing dirty worktree retained without destructive Git operations |
| Repaired formal contract | Implemented and validated | Four-path contract remains normative; formal target builds without `sorry`, `admit`, or custom axiom declarations |
| Canonical implementation manifest/admission | Implemented and component-tested | One canonical record, deterministic identity, Store-private candidate/tree/runtime/snapshot/process admission |
| Stable foundation versus adoption event | Implemented and component-tested | Stable semantic identity is separate from append-only adoption identity; restore may re-adopt the same foundation under a new event |
| Closed foundational lineage | Implemented and component-tested | Runtime and SQL close exactly initial, ordinary successor, restore historical, and recovery new-foundation variants |
| Route-aware custody/frontier | Implemented and component-tested | Ordinary successor and recovery proposals are Store-derived; restore reopens the exact historical custody basis |
| Healthy successor driver | Implemented and end-to-end tested | Store root enforces MSG-07, predecessor-context refresh, mandatory MSG-06, conditional MSG-05, MSG-11, adoption, acceptance, pending MSG-12, and terminal currentness; A→B→C succeeds only after B is freshly current |
| Restore driver | Implemented and end-to-end tested | Store root consumes MSG-13, exact discontinuity and historical terminal/foundation, MSG-07, same-foundation/new-adoption, acceptance, MSG-12, and restored terminal; completed restore reopens |
| Recovery driver | Implemented and end-to-end tested | Store prepare/complete roots consume MSG-15, exact discontinuity, new custody/foundation, MSG-07, adoption, acceptance, MSG-12, and recovered terminal; completed recovery reopens |
| Four-lineage terminal/reopen substrate | Implemented and end-to-end tested | Durable resolver accepts all four terminal provenance modes and rejects incomplete pending evidence; every completed lineage reopens through fresh process/Store correspondence |
| Generic-writer fence | Implemented and component-tested | Filesystem-first and every SQL-first C2 marker refuse generic writer admission without SQL mutation |
| Typed registry and governed ingress | Implemented and component-tested | Closed 16/10/11/7/1 registry; seven external routes have durable replay/collision/no-write tests |
| Consequence-root mismatch/no-write matrices | Implemented and tested | Bootstrap (8), healthy successor (2), restore (12), and recovery (12) one-coordinate matrices require typed refusal and byte/logical no-write; all exact controls succeed |
| Durable replay and route one-use | Implemented and tested | Exact replay, changed-content collision, restart replay, and repeated MSG-06/07/12/13/15 paths are Store-backed and route-specific |
| Authority noninjectability | Implemented and tested | Public-facade and live-authority trybuild suites prevent raw authority tuples, generic routes, live-context construction, and private permit construction |
| Internal call graph | Implemented and verified | `39/39`; evidence `sha256:cc4b3725b9d2048d0b607947ef0f08169f709561dd086182f073bfe2eba37c69` |
| Mutator census | Implemented and verified | PASS; 35 actor mutation roots, two state attachments, one delegate; inventory `sha256:6fc468a23ff1e298face3bb50eeb7b386e4d6baa30be026b9d8a7e95223b0b6b` |
| Source-derived crash execution | Implemented and tested | All 70 exact nodes (`SC-01`–`SC-70`) terminate a fresh child abruptly and pass fresh-process restart/fence/no-authority/no-write checks; manifest SHA-256 `8d0cddb0ea43b70762564e137e658f4e9766b2236a37d0df68985d5102dac4da` |
| Public typed lifecycle facade | Implemented but not production-reachable | One public surface bounds bootstrap, healthy successor, restore, recovery, reopen/writer, and governed ingress; its opaque candidate-verifier input has no production verifier |
| Candidate freeze and qualification | Intentionally out of scope | No candidate identity, certificate, packet, registry entry, or qualification claim was created |

## Remaining implementation blocker

The typed public lifecycle facade deliberately requires
`StoreC2CandidateVerifierResultV1`, and callers cannot construct that result.
The only sealing seam consumes the private
`VerifiedC2ExternalCandidateRuntimeRecordV1`; the current source explicitly has
no production constructor for that record and provides only a test constructor.
There is no candidate-certificate schema/parser, authenticated registry or
trust-root lookup, or production verifier that establishes the exact
candidate/tree/manifest/runtime correspondence.

This is not qualification ceremony: the final candidate-specific certificate
may be created only after freeze, but the certificate/trust-root verification
contract and production verifier must exist in source before the candidate is
frozen. Consequently gate 35 (production reachability) fails while gates 1–34
pass. The four-path lifecycle itself has no remaining known implementation or
test blocker.

## Hostile defect found and closed during final validation

The restore consequence root originally compared the supplied predecessor
generation commitment only after MSG-07 had been durably appended. A wrong
coordinate therefore returned a typed refusal but changed B state. The resolver
now checks the coordinate against the exact durable bootstrap generation
commitment before any append. The 12-cell restore mismatch/no-write matrix now
passes with exact control success; SQL, B/G, custody, and lock snapshots remain
unchanged on every refusal.

## Validation checkpoint

- Focused manifest/records/messages/terminal/external-governance/custody units:
  75 passed, 0 failed.
- Complete production-path specimens: bootstrap plus two healthy rotations and
  reopen PASS; same-foundation/new-adoption restore and reopen PASS; new-
  foundation recovery and reopen PASS.
- Consequence-root mismatch/no-write matrices: bootstrap 8/8, healthy 2/2,
  restore 12/12, recovery 12/12.
- Semantic crash suites: bootstrap 20 cuts, healthy successor 8 cuts, restore 6
  cuts, recovery 6 cuts, plus both discontinuity carrier-first pending cuts.
- Source-derived abrupt crash suite: 70/70 exact cuts PASS in fresh children.
- Restart integration harness: 5 passed; hostile harness: 4 passed; governed
  route census: 2 passed.
- Public-facade trybuild: 2 passed. Live-authority noninjectability harness: one
  harness passed, containing four compile-fail specimens and one pass control.
  No trybuild snapshots were rewritten.
- Call-graph verifier: PASS, 39/39. Verifier self-tests: 45/45.
- Mutator census: PASS.
- Formal lifecycle build: PASS, 19 jobs; no `sorry`, `admit`, or custom axiom
  declaration was introduced.
- Final broad `nq-store` library run (excluding the separately executed 70-cut
  suite): 501 passed, 10 failed, 0 ignored, 1 filtered. All ten failures are the
  known candidate-bound governed-capacity fixtures refusing because the frozen
  capsule manifest inventory does not match this dirty development tree; no C2
  lifecycle regression failed.
- `cargo check -p nq-store --lib`, `cargo check -p nq-store --tests`, the formal
  repository `git diff --check`, and this worktree's `git diff --check`: PASS.

## Final load-bearing hashes at this checkpoint

| File | SHA-256 |
| --- | --- |
| `store_generation/live_c2.rs` | `ae476dc65bba1734089523cbb9919860a6e34f81eeb0813998222cf1e8bc4a12` |
| `store_generation/c2_lifecycle.rs` | `79131020da2234ea4319fc08085fd5a4736426070a7d1f450655007f65d1e335` |
| `store_generation/live_c2_hostile_tests.rs` | `4dee68dd92d120ca01a94aa9f0617113b711e5d6d69247f7868f401a379a0c70` |
| `store_generation/live_c2_bootstrap_crash_tests.rs` | `cb06b005ff4c091a6d76447a85166c822ff92132563a8c769de108bc8c1ce3b7` |
| `signer/records.rs` | `fd761349c71bcbde9bf8f65f48d8f2c6407fdc4b25f8a24e0a7466e4c346ee8e` |
| `signer/terminal.rs` | `23bfa3265ddb071a55d4f0a852e64a2657a05ffb2ae2df6bb86938ad7165434c` |
| `signer/lineage.rs` | `f58e2f2954d017001a33d5a42f2d71860d150408c6ef82b2bb34af63af04fdf0` |
| `signer/coordinator.rs` | `c40b62368e23c46817eeeec3c7b26aa65306f9a3794b0f2b93b872250a084190` |
| `signer/custody.rs` | `5ad05ddfb8e67949746ea4df2f92f403c10a681a83252b74535f192f93dff48f` |
| `signer/messages.rs` | `5ae0df11fd1914bda55f95b1cf0d97d8be88497b6d364f9784550a866d432f8d` |
| `v9_c2_signer_lineage.sql` | `e8001146d221261a4b6b8016bb29a554154da8d4edc9b583757000328c9568f8` |
| `nq.c2_io_crash_cut_manifest.v1.json` | `8d0cddb0ea43b70762564e137e658f4e9766b2236a37d0df68985d5102dac4da` |
