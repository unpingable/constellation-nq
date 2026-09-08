# Repository-state prerequisite for Codex classic retirement

2026-09-08. Active bounded contract-design lane; **not implemented or qualified**.
Integration owner: Constellation main loop. NQ-ng owns profile semantics; Codex
owns the evidence consumer/reviewer. M2 remains accepted and closed.

## Observed topology and contract availability

Primary checkout `/data/git/skunkworks/nq-ng`, branch
`campaign/passive-watcher-succession-v1`, at `675e247` retains untracked campaign
and audit material, untouched. Local main is `59abd3b`. The beta profile worktree
is clean at `9f1b081b7fc5b2d99fb92ee6b0ac4107c7e7dfe4`; this isolated documentation
lane uses that exact parent, not a portfolio-wide merge. Other current worktrees
include FIELD-CLOCK, SILICON-ORCHARD, AMBER-COMPASS, BEDROCK, GRANITE-FENCE,
GROUP-ANCHOR and QUIET-EMBER. Their acceptance and production state are not
inferred from branch names.

Read-only inspection of every local branch under `crates/nq-profiles`,
`crates/nq-app` and `crates/nq-host-helper` found no `repo_clean`,
`claim_registry`, `git_status` or `repository_state` implementation. This is a
bounded source search, not proof about external modules or unnamed worktrees.
Primary registry has conformance/host; beta registry adds systemd-unit and
HTTP-endpoint. Those profiles cannot answer repository cleanliness. Host/Git
build-identity checks and generic evidence storage are not a repository-state
diagnostic contract.

Codex source parent `2701043b38533d68d6b77b6f45e18c3524b415c1` has an untracked
external-reviewer candidate whose `src/nq_adapter.rs` SHA-256 is
`874966561ad089da949672ce8c3378d7df13eda21bb048b755066c55ea380389`.
It maps classic claim-registry receipt statuses to subject-scoped true/false or
no established fact. The crate and core end-to-end suites are not registered in
the current Cargo/test entrypoints. The precise consumer inventory and tests
are recorded in Codex commit `19111bd6470bbf5320447c4623a4b83e298f2025`,
`qualification/classic-retirement/CODEX_MIGRATION.md`.

## Concrete contract decision and smallest implementation order

Use one separately versioned, static **repository-state** profile; do not
implement a generic claim registry or shell-predicate interpreter. The existing
`ProfileModule` validation/projection/detector seams and admitted helper protocol
are reusable infrastructure, not already-qualified repo-clean semantics.

The bounded design proposal to settle before source implementation is:

1. One explicitly enrolled non-bare Git worktree, local vantage, exact repository
   and worktree identity, HEAD and observation interval. No organization-wide or
   future-execution claim. Bare/unborn/unsupported worktrees receive explicit
   unsupported or unavailable results until independently covered.
2. Fixed Git porcelain acquisition with bounded output/deadline and pinned
   collector execution identity. Declare whether staged, unstaged, untracked,
   ignored and submodule content are covered. Initial proposed scope covers
   tracked and untracked changes, excludes ignored contents, and refuses
   submodules rather than silently narrowing them. This is a proposal, not an
   adopted definition of universal `repo_clean`.
3. Define concurrent-writer semantics: either qualify an explicitly stable
   snapshot/enrolled quiescent fixture or limit the claim to the observed status
   response interval. Repeating HEAD/status is not proof of atomic worktree
   observation. No result grants execution custody or guarantees absence of
   later changes.
4. Profile-owned three-way disposition: supported clean *within declared scope*,
   supported changes present, or not established. Missing/expired/wrong-subject/
   contradictory/truncated/provider-failed input cannot become clean or dirty.
5. Export through an existing exact diagnostic artifact path only after proving
   that path carries the new profile's evidence, semantic identity and typed
   refusal without host-specific assumptions. Name any required bounded export
   extension explicitly. Do not mint a cosmetic classic-shaped receipt.

**Work that can proceed now:** NQ-ng owner closes these bounded semantic choices
against the named Codex consumer, prepares profile/witness fixture cases, and
checks the existing export seam. After that decision, implement the static
profile and bounded acquisition path, qualifying them before consumer migration.
No deployment inventory is needed to design this local repository fixture role;
the historical fleet G0 is not a reason to postpone it indefinitely.

**Dependent Codex work:** separately admit the existing reviewer candidate;
implement a modern evidence adapter; replace both fixture sources and register
the suites; retain qualifier/subject/time identity and three-way outcomes.
No wholesale import of unrelated untracked MCP/publication code. AG-ng may own
later action authorization and Docket later execution custody, but neither owns
the diagnostic claim and neither is a substitute prerequisite for this profile.

## Exact qualification gate

- Positive: owner-produced clean-in-scope evidence reaches the selected Codex
  policy and permits Continue; changed tracked/untracked fixtures yield the
  corresponding established-false evidence and Refuse.
- Uncertainty: unavailable Git, partial/truncated output, deadline, stale,
  wrong subject, submodule exclusion, contradictory evidence and interruption
  remain not-established or typed refusal as the settled contract specifies.
- Identity: mutation/substitution and unsupported schema/profile controls cannot
  reuse a prior claim; hash shape alone is not verification. Replay checks exact
  artifact and evaluator/profile identity.
- Boundary: no test asserts future worktree stability from an observation;
  generic and prepared-review witnesses preserve exact call identity and do not
  continue after Refuse/Indeterminate.
- Integration: run actual registered tests with modern owner-generated fixtures,
  scanner/build/test census and affected witnesses on exact integrated heads.
  Existing M2 qualification remains attached only to its original revisions.

Current execution validation: **NOT_RUN** (contract/design record only).
Source census and documentation diff checks completed. No classic generation,
schema/class implementation, source port, fleet change, push or deployment.
