# NQ #27 bounded-history retention repair: campaign report

Status: FINAL (2026-10-11). Campaign `nq-27-repair-20261010`, host crow, run f7548308.
Owner authorization 2026-10-10: repair the four confirmed audit defects and implement the
DECLARED PROTECTED HOLES policy under ten boundaries; requalify with the full `nq-app` suite;
no merge, push, deploy; NQ #27 stays open; production untouched; no seven-day launch.

**Disposition: SUPERVISED_BETA_ONLY for the integrated candidate 3d0b2b6 (nq 0.2.6).
The seven-day unattended qualification is BLOCKED_WITH_EXACT_OBLIGATIONS (§9).**

## 1. Source and evidence identities

| Item | Identity |
| --- | --- |
| Accepted pre-campaign candidate | 257096b (= origin/dev/operator-beta), worktree `/data/git/.worktrees/nq-bounded-retention-20261009`, untouched |
| Audit specimens S1–S4 and audit docs | 53a1eab on `audit/nq-27-specimens-20261010` (895aee7 test-only specimens), untouched |
| Audit report | `/data/git/.campaign-artifacts/nq-27-readiness-audit-20261010/REPORT.md` (SUPERVISED_BETA_ONLY; defects D1–D7, gaps G1–G8, N1) |
| Lane A (archive, D7) | `lane/nq-27-archive-20261010` tip a7f081b: 2cf226f, 727c73d, c8389c1, 0d19c0f, a7f081b; review `evidence/lane-A-archive-opus.md` |
| Lane B (D5 + holes) | on `campaign/nq-27-repair-20261010`: 442930e, 22d3258, 07ce646, 8144227; design `DESIGN-NOTE-lane-B.md`, review `evidence/lane-B-step-A-opus.md` |
| Lane C (merge, D2, D4 step C, consumer contract, S4, suites) | 7103a01 (merge of a7f081b), db3ca28, fdd3342, bb4ce3a, ac652ac, 961cd04, 4529f72, 0e167fe; report `evidence/lane-C.md` |
| Phase 8 review (independent Opus) of 0e167fe | `evidence/phase-8-review-opus.md`: BLOCKED (B1, B2), M1–M4, m1–m5, N1–N4 |
| Residue probes (main session) | `evidence/residue-probe-20261011.md` (+ samples CSVs, script, doctor JSON for 0e167fe and f5b78a9) |
| Lane D (one repair cycle) | 1bdce92 B1, debadd0 B2, 63f06a2 M1, c181363 M3, bd8146f M4, cb088c9 M2+m1, ce5259b m5, ba5164c m2, dbdda20 m3, f5b78a9 m4/N2/docs; report `evidence/lane-D.md` |
| Phase 8 re-review of f5b78a9 | `evidence/phase-8-rereview-opus.md`: SUPERVISED only, nothing blocking, five obligations |
| Docs after re-review | f69e753 (batch-wait and residue claims bounded), f3076da (shipped-binary residue figure) |
| **Integrated candidate** | **3d0b2b6 `nq: version 0.2.6`** on `campaign/nq-27-repair-20261010` (Cargo.toml, Cargo.lock, packaging/debian/OPERATOR.md, docs/PUBLIC_RELEASE.md). README.md line 27 still says 0.2.5: the edit was refused by the session's permission classifier twice and is left for the owner. |
| Toolchain | rustc 1.94.0 pinned, `--locked`, `umask 0022`; debug builds in the session scratchpad; one release build of nq-core tests for the speed ratio |

Nothing was pushed, merged, deployed or executed against production. The production zone
(`nqd-ops` on nq-ng 0.2.4, store 1,111,912,448 B above its 1 GiB cap, crash-looping) was
inspected read-only in the audit and not touched in this campaign. `ZONE-ROLLOVER-PLAN-DRAFT.md`
remains a non-executable draft with placeholder identities.

## 2. Concurrency reconciliation (Phase 0)

No other NQ implementation or qualification was active: no NQ cargo/nqd/qemu processes; host
cargo activity was ABSD; the ABSD U1 seven-day VM and the Labelwatch VM were running and were not
disturbed; peer sessions git-10/git-6c/git-b2 were on ABSD work; no NQ branch had moved since
53a1eab and no NQ worktree was dirty. The campaign used two new worktrees
(`nq-27-repair-20261010`, `nq-27-archive-20261010`) and left the accepted candidate, the
specimens worktree and the audit record untouched (`git status --short` empty in all three at
the end).

## 3. Audit findings carried into the repair

| Defect | Audit finding (at 257096b) | Repair |
| --- | --- | --- |
| D1 permanent hold | any finding, saved check, notification, diagnostic or successor dependency, or a stale instance/contract, pins the global prefix forever | Declared protected holes (07ce646): islands below the floors, compact source rows (`source_expired`), anchor runs; finding release = resolved AND custody terminal AND no other root; `unknown` custody = permanent island; released islands reclaimed; compact rows repacked so their pages are released (c181363) |
| D4 post-expiry full validation on every open | at generation > 0 `store_identity`/`since_open`/`engine_semantic_state` forced FULL | Watermark v4 bound to the retention boundary, carry-forward at expiry commit, scoped pre-deletion validation, quantum, `validate --full` deep pass (bb4ce3a, 961cd04); long-lived engines extend their certification before carrying and never regress the shared sidecar (debadd0); nqd startup incremental (ce5259b) |
| D5 expiry refusal aborts collection | an expiry race or capacity refusal propagated through the collect path | Typed refusals `Refused(Capacity|Contention|HistoryChanged)`; collection continues; admission still refuses (442930e); expiry in batches of 64 runs releasing the lock between batches, 20 s budget, continuation at the next collection (63f06a2) |
| D7 archive refuses v14 stores | archive/backup paths assumed v13 and left sidecars/locks | Sidecar retirement, inode-bound guard, staged-copy retirement, bounded stop checkpoint (lane A); archive declares `complete_history`/`retention` and verification re-derives it (db3ca28) |
| D2 archive after expiry (declared gap) | archive refused or implied continuity | `complete_history: false` + boundary in ARCHIVE.json; consumer contract in docs/HISTORICAL_READS.md; `source_expired` on the finding read model, the public view and `nq query` (ac652ac, ba5164c); 410 + resume; CLI refusal |
| D6 production migration blocked | 271,463 pages > 260,599 cap at 1 GiB | not repaired by design: in-place migration not authorized; recovery = controlled generation rollover (draft only) |
| G7 restart loop | no StartLimit on nqd.service | StartLimitIntervalSec=300 / StartLimitBurst=5 (22d3258) |

## 4. Owner boundaries (ten): verdicts at f5b78a9 (unchanged at 3d0b2b6)

| # | Boundary | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | historical collections reclaimable once obligations end | HOLDS | released closures reclaimed (`released_islands`; S4 released cycle; lifecycle test) |
| 2 | unresolved findings and live dependencies keep required evidence | HOLDS | opening + latest closures are islands; B1 repaired so a released finding's later evaluation needs nothing that was reclaimed |
| 3 | resolved findings must not pin global history | HOLDS | floors advance over protected rows; no global pin (review Q2) |
| 4 | custody and continuing obligations accounted before reclaiming | HOLDS, vacuous in shipped paths | no shipped notification path binds a finding event (M2); disclosed in docs and `doctor` (bound/unbound counts); late custody on a compact event holds nothing (m1) |
| 5 | protected material may create declared gaps | HOLDS | islands and compact rows below the floors |
| 6 | gaps observable, never continuity | HOLDS | every surface in docs/HISTORICAL_READS.md handles or refuses; `nq query` view carries `source_expired` (m2) |
| 7 | contiguous-history consumers refuse when assumptions break | HOLDS | 410 + resume, CLI refusal, archive declaration + verification |
| 8 | protected material inside the storage envelope | HOLDS | islands and compact rows charged to occupancy; residue measured and disclosed (M3, §6.2) |
| 9 | exhausted budget → refuse admission, never discard or exceed | HOLDS | preflight refusal on every write; lane B capacity test |
| 10 | no new authority ledger / custody authority / retention framework | HOLDS | v15 adds columns, triggers, indexes and a view; sidecar stays advisory; selection never reads it |

## 5. Regression coverage and full test results (main-session runs, debug, crow)

| Head | Run | Result |
| --- | --- | --- |
| 0e167fe (lane C) | `cargo test --locked --workspace --no-fail-fast` (`scratchpad/logs/verify-0e167fe-workspace.log`, 23:46–00:02Z, exit 0) | 744 passed / 0 failed / 13 ignored; nq-app 169 lib + 27 integration = 196/0; nq-core lib 231/6 ign; nq-store lib 105/5 ign |
| f5b78a9 (lane D) | same (`verify-f5b78a9-workspace.log`, 02:35–02:50Z, exit 0) | 754 passed / 0 failed / 14 ignored over 74 result lines (753 excluding the crash-test child line); nq-app lib 169 + 27 integration = 196/0; nq-core lib 238/7 ign; nq-store lib 108/5 ign |
| 3d0b2b6 (version bump) | `cargo test --locked -p nq-app` (`verify-3d0b2b6-nq-app.log`, 03:53–04:06Z, exit 0) | 196 passed / 0 failed over 18 targets (lib 169 + 27 integration) |

nq-app integration targets at every head: admin_lifecycle 9, archive_lifecycle 1,
bounded_document_inputs 1, build_info 2, custody_pagination 1, daemon_evaluator_identity 1,
daemon_signals 1, e2e_cli 1, evaluation_refusal_surfaces 2, file_size_limit 1,
mutation_serialization 1, repository_state 2, retention_lifecycle 2, semantic_surfaces 2.
Implementer counts matched the main-session runs at both heads. Failures seen during development
(classified, none waived): the load-sensitive `concurrent_engines_collect_without_spurious_integrity_failures`
(bounded, no longer hangs; still fails under contention at load ≥6, review N1) and a 100 ms
timing flake in untouched coordination code.

Specimens: S1 and S3 flipped to the repaired behaviour; S2 is
`archive_after_expiry_declares_retention_boundary`; S4 is the ignored harness
`retention_open_cost_is_flat_in_retained_collections`, now judged in ticks with a long-lived
collector case. New regression tests cover: released-finding cannot-evaluate on sweep and
collect paths; long-lived handle carry and never-regress; batch lock release and continuation;
file-level residue; derived cited-report sequence; late custody on a compact event; incremental
nqd startup; frontier re-anchoring; carry-forward, both crash sides, tamper detection, stale
retention, generation transition, quantum; archive lifecycle (success/failure/interrupt/SIGTERM/
restart); the end-to-end finding lifecycle through `nq` and the local API plus the
`unknown`-custody negative.

## 6. Measurements

### 6.1 Open and expiry cost against retained collections (S4 at f5b78a9, debug, ticks exact)

| Column | N=50 | N=800 | Class |
| --- | --- | --- | --- |
| (a)(b) first store/engine open without a watermark | 179,472 / 384,472 | 7,721,240 / 11,282,402 | O(history), by design |
| (c) restart open (store + engine) | 53,551 | 53,551 | **O(1)** |
| (d) zero-candidate expiry probe | 3,568 | 12,568 | O(window), 12 ticks per collection |
| (e) one-candidate expiry | 88,155 | 391,905 | **O(window)**, 405 ticks per retained collection (688 before the index; FK check, floor union, run scan remain) |
| (f) open after a generation transition | 53,551 | 53,551 | **O(1)** |
| (g) open after a crash between COMMIT and sidecar write | 553,334 | 18,993,032 | O(history), exactly once |
| (h) the open after that | 53,551 | 53,551 | **O(1)** |
| (i) long-lived collector's expiry (20 appended) | 238,881 | 542,635 | O(window) + O(appended since its certification) |
| (j) open after the collector's expiry | 53,787 | 53,787 | **O(1)** (was O(appended since the collector opened) before B2) |

Base (fdd3342, before step C): every open after expiry was O(history), (c) 505,805 →
14,841,509 ticks. The audit's S4 at 257096b: 1.18 → 24.17 s wall across the same N.
nqd restart is incremental since ce5259b. Routine collection evaluation remains O(window within
the horizon) by detector semantics (out of scope).

Release speed: the engine harnesses cannot run in a release build (the fixture's same-identity
helper execution is debug-only), so the production-scale lock hold is unmeasured in release.
Five store-level expiry/validation tests ran 1.4–1.5× faster in release than debug
(`scratchpad/logs/release-ratio-f69e753.log`), so for fsync-bound store work the debug figures
are close to release; the CPU-bound in-lock validation ratio is unknown.

### 6.2 Bytes per collection and permanent residue (file level, shipped `nq`, real helper)

| Quantity | Value | Source |
| --- | --- | --- |
| Production ordinary growth | ≈39.8 KB per collection, 660/h ≈ 26.3 MB/h ≈ 630 MB/day | audit capacity model from the zone store |
| Seven-day window, main only | ≈4.11 GiB | audit model |
| 8 GiB-limit profile on a 32 GiB volume | main cap 6,206,705,664 B (5.78 GiB), reserve 6.24 GiB, headroom ≈1.67 GiB above the window | ENVELOPE-BASELINE + audit |
| 1 GiB limit | window does not fit; cap in ≈40.7 h; production store already above it | audit |
| Residue, no finding | **≈2.55 KB per retired collection** (retired intake commitment + indexes), permanent → ≈40 MB/day; headroom lasts ≈42 days | probes at 0e167fe and f5b78a9 |
| Residue, finding open, at 0e167fe | ≈22 KB per collection, permanent | probe; cause: in-place compaction kept the full row's page |
| Residue, finding open, at f5b78a9 | **≈11.9 KB per collection**, permanent after resolution; dominated by the ≈5.5 KB anchor run row kept in full; ≈19 MB/day per open finding at 66/h; ≈188 MB/day if every watcher has one (headroom ≈9 days) | probe on the repaired binary; `retention.residue` in `doctor` |
| Payload floor under an open finding | ≈4.96 KB per collection (reviewer's per-row table) | review M3 |
| WAL | one transaction (TRUNCATE before each write); peak observed 329,632 B | lane B capacity report |

The 8 GiB profile supports the seven-day window with ≈1.67 GiB of headroom; that headroom is
consumed by permanent residue at ≈40 MB/day in ordinary operation and faster while findings are
open. Capacity refusal (boundary 9) holds at the ceiling; the horizon bounds the window, not the
residue. A generation rollover is the only reclamation path for residue.

### 6.3 Expiry lock hold and concurrent writers (debug)

| Configuration | Expiry | Concurrent `record_component_status` |
| --- | --- | --- |
| 0e167fe, 300 candidates, one transaction | 8.2 s in lock | refused `Contention` after 5 s (review probe B) |
| f5b78a9, 660 candidates, unbatched (reference) | 20.1 s, 31.7 M ticks | 3 of 4 refused |
| f5b78a9, 660 candidates, batches of 64 | 21.5 s total, 33.1 M ticks, 11 batches | 11 of 11 Ok, longest wait 1,957 ms |
| re-review, 300 candidates, batched | 8.5 s total | 5 of 5 Ok, longest wait 1,639 ms |

Per-batch in-lock work still carries ≈405 ticks per retained collection (R1): at the production
window (≈110k collections) that is ≈45 M ticks per batch, ≈20 s in debug, which exceeds the
writers' 5 s bound unless release is ≥4× faster there. Not demonstrated either way.

## 7. Independent review results

Phase 8 (0e167fe): BLOCKED for unattended. B1 released finding breaks the lineage's next
cannot-evaluate (demonstrated); B2 long-lived engine regresses the shared sidecar (demonstrated);
M1 in-lock expiry time grows with candidates and refuses writers; M2 custody root unreachable from
shipped notification paths; M3 undisclosed permanent residue; M4 expiry O(window) in ticks behind a
noisy wall-clock criterion; m1–m5; N1–N4. Holds: archive and lock state, crash recovery and
watermark adoption, refusal taxonomy and quantum, paged-history surfaces, boundaries 9 and 10,
suite counts. Decisions per finding: REVIEW-DECISIONS.md "Phase 8 decisions" and the M3
amendment after the main-session residue probe.

Re-review (f5b78a9, same reviewer): **SUPERVISED operation only; nothing blocking remains.**
B1, B2, m1, M2 (disclosed), M3, m2, m4, N2, m5 REPAIRED; M1, M4, m3 PARTIALLY REPAIRED (R1
above; a rowid reused before a handle observes a boundary change is a disclosed window). No new
correctness defect in the ten commits. The reviewer built the accepted 257096b binary, created a
populated v14 store at generation 4 with a resolved finding, and took it through the amended
v14→v15 migration, full validation, expiry/compaction, a reopen and an archive whose own verifier
passed. Collections after the binary change needed `nq watcher admit` again (existing
evaluator-identity binding). The two doc overclaims it named were corrected at f69e753; the
shipped-binary residue figure was added at f3076da.

## 8. Risks that remain by design or outside this scope

- Routine collection evaluation reads every full report of the instance within the horizon
  (quadratic in the window; detector semantics; pre-existing; S4 growth to N=800 took ≈30 min).
- Anchor run rows are kept in full (≈5.5 KB with a real helper); compacting their execution
  record is the follow-up that would bring open-finding residue near the payload floor.
- Expiry in-lock work is O(window) per batch (R1); the production-scale release measurement is an
  obligation, and removing the floor-union and run-scan terms within v15 is the fallback.
- Null-run status events never expire (pre-existing; bounded by restart/refusal cadence).
- The custody hold is unreachable from shipped notification paths; it engages only for intents
  bound to a finding event, which nothing ships today (disclosed in docs and `doctor`).
- Production store cannot migrate in place under its 1 GiB limit (D6); recovery is a controlled
  generation rollover whose draft stays non-executable until artifact identities exist.
- A commitment mismatch in the watermark sidecar refuses the open until `admin validate --full`
  is run (accepted; an operator action when unattended).
- The load-sensitive concurrent-engines test fails under host load ≥6 (bounded, not fixed).
- Release-build timings for the engine paths were not measured.

## 9. Disposition

**Supervised operation: SUPERVISED_BETA_ONLY** for the integrated candidate 3d0b2b6 (nq 0.2.6,
schema v15). The four audit defects and the review's blocking findings are repaired and
independently re-reviewed; the full workspace suite passes at the code head; S1–S4 are integrated;
crash/restart/generation-transition opens are O(1) in retained collections; the 8 GiB profile
supports the seven-day window by measurement with ≈1.67 GiB of headroom. Supervised means an
operator watches `nq doctor` (`retention`, `retention.residue`, `expiry_schedule`, `capacity`)
and the journal for `collection refused` / `collection engine error`, on a non-production store.

**Seven-day unattended qualification: BLOCKED_WITH_EXACT_OBLIGATIONS.** Before a run may start:

1. Measure the longest per-batch operation-guard hold in a **release** build at a retained window
   of production scale (≈110k collections, or a measured slope with margin), with a concurrent
   writer never refused; otherwise remove the window terms within v15 (index `trigger_run_id`,
   floor-anchored union and run scan) and record whether the full FK check per batch stays accepted.
2. Make "zero collections lost to contention and zero collection engine errors" a pass criterion
   of the run, alongside the audit's §7.1 criteria.
3. Add `nq admin upgrade` followed by `nq watcher admit` for every watcher to the install/upgrade
   procedure (evaluator-identity rebinding after a binary change).
4. Check capacity headroom against the measured residue (§6.2) for the run's volume and limit,
   and track `doctor` residue counts during the run.
5. Decide the anchor-run compaction follow-up (reduces open-finding residue ≈2×) or accept the
   measured ≈11.9 KB per collection.
6. Owner storage authorization for the run, and the audit's remaining §7 items.

Do not claim seven-day qualification from the accelerated tests here. NQ #27 stays open.

## 10. Exact next action

Owner review of this report and of `campaign/nq-27-repair-20261010` at 3d0b2b6, plus the docs
commit 33c87ce that records this report (33 commits above 257096b, including the two
specimen/audit-docs commits the branch was based on). If accepted: merge or fast-forward is the owner's decision (nothing is
pushed); then supervised operation on a non-production store under an 8 GiB-class profile, and
the obligations in §9 before scheduling the seven-day run. Production recovery remains a separate
controlled generation rollover; fill `ZONE-ROLLOVER-PLAN-DRAFT.md` identities only from a
qualified package record and keep its preflight checks.

## 11. Custody and storage closeout

- Durable record: this directory (`REPORT.md`, `CHECKPOINT.json`, `WORKER-BRIEF.md`,
  `DESIGN-NOTE-lane-B.md`, `REVIEW-DECISIONS.md`, `PHASE-8-REVIEW-BRIEF.md`, `LANE-D-BRIEF.md`,
  `PROGRESS.md`, `ZONE-ROLLOVER-PLAN-DRAFT.md`, `evidence/`). The report is also committed as
  `docs/working/NQ-27-REPAIR-CAMPAIGN-20261010.md` on the campaign branch after 3d0b2b6 (a
  docs-only commit; the version commit identifies the code).
- Branches, all local, none pushed: `campaign/nq-27-repair-20261010` @3d0b2b6 (+ docs commit),
  `lane/nq-27-archive-20261010` @a7f081b, `audit/nq-27-specimens-20261010` @53a1eab (untouched).
- Prior records untouched: audit directory, specimen branch, accepted candidate worktree.
- Build artifacts removed: `target-base` 1,153,661,254 B, `target-release` 302,048,970 B,
  `base-src` 9,508,509 B, and `target-repair` 25,844,215,137 B at the end (total ≈27.3 GB
  returned; / at 59 % after); probe run directories `/tmp/nq-residue-probe.{JU2ENc,FDne0J}`
  (5,867,139 B) removed after their samples and doctor output were copied into `evidence/`;
  the two copied `nq` probe binaries removed. Worktrees kept (≈0.5 GB) for the owner's review;
  scratchpad logs ≈1 GB kept for the session.
- Logs kept in the session scratchpad (`logs/`, `logs-C/`, `logs-D/`, `review-probes/`,
  `reports/`); the lane reports and probe sources that the record cites are copied into `evidence/`.
- Memory updated: `nq-27-retention-readiness-audit.md` (campaign outcome) and
  `nq-qualification-bar.md` (owner's bar).
