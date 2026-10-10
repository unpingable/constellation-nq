# NQ #27 bounded-retention operational-readiness audit — 2026-10-10

## 1. Exact source and evidence identities

| Item | Identity | Verified how |
| --- | --- | --- |
| Repository | unpingable/constellation-nq | `git remote -v` in worktree |
| Repair worktree | /data/git/.worktrees/nq-bounded-retention-20261009, branch campaign/nq-bounded-retention-20261009 | `git worktree list` |
| Repair commits | 245ff45 (file-size-limit errors returned, not fatal), 7144ae7 (retention + capacity, schema v14), b1a2dc0 (operator guide), 605d9d6 (metadata page memory), 257096b (test-only fixtures) | `git show --stat` |
| Base | a7d37dc (NQ 0.2.5 candidate; runtime ancestor 7e2c821) | `git merge-base`, records |
| Publication | origin/dev/operator-beta == 257096b, pushed 2026-10-10T05:36:36Z by `unpingable` (GitHub PushEvent); origin/main == 82af0ac (0.2.0 line); no tag; no PR | `git reflog`, `gh api events` |
| Qualified package | nq-ng 0.2.5 package-002 SHA256 6d097caa…dfb5, built from runtime 605d9d6 (bookworm-build-001/002) | GATE1-DISPOSITION.md, package-002/TERMINAL.json |
| Supervised successor archive | constellation-supervised-candidate-20261010.tar.gz SHA256 af17c59b…ceba, source commit d7de325 on unpingable-site branch campaign/constellation-supervised-successor-20261010 (local only) | supervised-beta-continuation/prepared/SUPERVISED-ACCEPTANCE.json |
| Companion lanes (unpushed) | Monitor d801241 (maintenance wrapper limits), Workbench 65f1530 (bounded init) | worktrees monitor-nq-envelope-20261009, workbench-nq-envelope-20261009 |
| Issue | constellation-nq #27, open, one comment (2026-10-08 reproduction) | `gh api` |
| Campaign record | /data/git/.campaign-artifacts/constellation-beta-readiness-20261009/ (RESULT.md, nq-policy.md, retention-spike/, retention-implementation/ with GATE1-DISPOSITION.md and 60+ lane receipts) | read |
| Production | zone host nqd-ops.service on nq-ng 0.2.4, crash-looping (see evidence/production-observation-20261010.md) | read-only ssh |

Corrections to the assignment's background, from later evidence:
- "Committed a local repair" is superseded: the repair is pushed to the shared `dev/operator-beta` branch (not main, untagged, no PR, no release). Nothing is deployed.
- The repair's 7-day horizon is a configured target (`horizon_seconds = 604800` default), not a qualified window; the records and docs say so consistently.
- "Approximately 4.25 GiB over seven days" is 4,250,400,000 bytes = 3.96 GiB of main-database growth at 25.3 MB/h; it excludes WAL reservation, protected growth, and retired-identity residue (capacity-options.json).
- The spike's abstract model (71,357 states / 232,662 transitions / 17 controls) is as stated and independently rerun (independent-model-review.md).
- Ten-GiB and 32-GiB VM occurrences and a 30-minute accelerated run (61 samples, horizon 60 s) exist as stated (GATE1-DISPOSITION.md, capacity-plan ACCEPTANCE.md).
- No seven-day or sustained observation is running anywhere. All campaign producers are terminal; VMs retired.


**Disposition: SUPERVISED_BETA_ONLY. Unattended hosting: NOT READY, blocked by exact obligations (§8, §10).**

What NQ can safely do today: run the accepted bounded supervised trial (fresh VM, operator present, hours-scale sessions well inside the seven-day horizon, so no expiry occurs), with the known limitation that on the shipped 1 GiB file limit the store reaches controlled refusal after about 40 hours. What it cannot defend: any claim of sustained or unattended operation, any seven-day history window under the production workload, deployment of the repair to the production ops store under its current limit, or the documented archive/rollover procedure: at the repair head `nq admin archive` refuses every schema-v14 store (regression D7, found by running the nq-app test targets the prior campaign did not run).

Review method: this audit was performed by one Claude session (Fable 5.1) with three Opus subagents (retention-semantics review, capacity/recovery review, independent challenge review), one Opus test-specimen worker and one Sonnet build/test worker. Every load-bearing code claim below was spot-checked in source by the main session; the reviewer reports are preserved in `evidence/`.

## 2. Current retention and expiry contract (as implemented at 257096b)

Source of truth: docs/retention.md, packaging/debian/OPERATOR-OPERATIONS.md §"Retention and capacity", schema_v13_to_v14_retention.sql, crates/nq-store/src/{retention.rs,capacity.rs}.

- Ordinary completed history (watcher runs, provider intakes, raw submissions, admitted reports, observations/coverage, evaluation runs, run-bound status events) is eligible for expiry once older than `horizon_seconds` (default 604,800 s) measured on local arrival/admission/completed-run time, never on provider sample time.
- Expiry retires contiguous global prefixes per sequence (evaluation/report/intake/status floors in `retention_state`, monotonic, delete-protected by triggers). A protected occurrence holds every older ordinary row behind it.
- Protected: finding evidence closures, saved-check and notification custody, diagnostic origins, successor-acquisition custody, current status/report anchors, latest usable checkpoint. No operator command releases these holds.
- Retained after expiry: monotonic lineage anchors and compact per-intake identity commitments (`provider_intake_attempts` rows with `history_expired=1`, `retired_identity_digest`, raw bytes cleared). These preserve replay-conflict/idempotency detection and stay charged to the byte budget.
- Capacity envelope persisted at first admission (init or v13→v14 upgrade): reserve = max(1 GiB, ceil(fs_total/5)); auxiliary 64 MiB; aggregate = occupied + ½ of free-above-reserve; main and WAL each clamped to the soft RLIMIT_FSIZE; envelope reserves a full main plus a full-database WAL. Normal open neither grows nor shrinks it; policy change on an existing store is refused; no live resize.
- Before an ordinary write: envelope check and TRUNCATE checkpoint; a held reader causes refusal, not WAL growth. Capacity pressure, custody holds, checkpoint contention or insufficient working space produce controlled refusal; the horizon is never shortened automatically.
- Expiry runs at daemon startup (daemon.rs:61) and before each collection cycle (engine.rs:2794). Deletions and the boundary advance commit in one FULL transaction; surviving history is re-validated; the advisory watermark sidecar is not deletion authority.
- Consumer-visible semantics: `expired` = committed retirement boundary, original history unavailable for full replay; `unavailable`/missing ≠ proof of retirement; surviving-history validation ≠ full-history verification. Main-file physical shrink is not promised (pages reused).
- Shipped nqd.service keeps LimitFSIZE=1G; initialization and writable maintenance must run under the same limits (documented), otherwise the persisted envelope may not fit the service.

## 3. Status of previously unresolved policy decisions

| Decision | Status | Record |
| --- | --- | --- |
| Gate 1 policy: capacity hold vs. budgeted archive rollover vs. finite retention | RESOLVED by owner: finite seven-day ordinary-history expiry, protected dependencies retained, capacity refusal, persisted automatic envelope, no silent shortening | retention-spike/DISPOSITION.md (EXPIRY_CONDITIONAL → owner amendment), .lanes/boundary-review/*/boundary-review.md ("The user has already authorized…"), expiry-plan ("The admitted amendment permits implementation") |
| Consumer-contract amendment (bounded historical replay) | RESOLVED as part of the above; legacy complete-history consumers get explicit `expired`/refusal, not silent narrowing | same |
| Expiring completed successor/diagnostic closures whose external consumer (Monitor coproducer, Nightshift admission) may still need them | RESOLVED conservatively: protected regardless of age; reclaiming them would need a separate consumer lifetime/discharge contract (owner decision, NOT taken) | boundary-review.md |
| Protection of RESOLVED findings, saved-check-claimed and diagnostic-origin evaluations forever | NOT an owner decision: the owner amendment names *current* findings and *unresolved* dependencies; the implementation plan widened this to all finding history (expiry-plan line 15, 44) and root accepted it in GATE1 ("conservative prefix custody can prevent reclamation"). Narrowing back to current findings is implementation work within the existing authorization, not a new policy question (challenge review Q2/E2). | retention-spike/DISPOSITION.md, expiry-plan, GATE1-DISPOSITION.md |
| F2: strict contiguous global prefix vs. retention with declared protected holes | OPEN owner decision; it decides whether detector-version bumps, removed watchers and open findings end reclamation (§6 D1) | this audit |
| Stale-anchor release (last report of a removed instance, superseded checkpoint contract, retired detector version, removed component status) | OPEN; follows F2 | this audit |
| Operating envelope numbers (7 d / 8 GiB; 32 GiB volume + 8G file limit) | OPEN: recorded as qualification options only; nothing admitted as an operating guarantee | capacity-options.json, docs/retention.md |
| Seven-day unattended qualification | OPEN and explicitly NOT authorized by the owner in this campaign ("No seven-day hosting qualification…") | supervised-beta-continuation/CHECKPOINT.json authorization field |
| NQ #27 closure | OPEN; records say closure requires restored bounded operation on the actual installed release | issue body, GATE1-DISPOSITION.md |
| Production host remediation (zone nqd-ops crash loop; store above file limit) | OPEN; separately authorized production change; not addressed by the repair's existence | issue body, production observation |

## 4. Verified capacity and reclamation behavior

Evidence classes: [code] read in the worktree by the main session or an Opus reviewer and spot-checked by the main session; [record] prior campaign receipts; [measured] values extracted from sample series or production; [derived] arithmetic on measured values; [projection] order-of-magnitude extrapolation; [not established].

### 4.1 What the repair bounds [code, verified]
- Main file: `PRAGMA max_page_count` = persisted `max_pages`, applied on every writable open (capacity.rs:366-384). WAL: one transaction at most, because `wal_autocheckpoint=0`, `cache_spill=OFF`, and a TRUNCATE checkpoint runs before every guarded write; a held reader makes the write refuse instead of letting the WAL grow (capacity.rs:388-402; test `held_reader_refuses_checkpoint_then_release_permits_write`). Every Store write path the capacity reviewer enumerated goes through `write_guard`/`immediate_transaction` (lib.rs:4580-4623); this is an enumeration plus spot checks, not an exhaustive proof.
- Reserve: checked live before each write (`available ≥ reserve + (aggregate − occupied)`, capacity.rs:325-331), not physically reserved. Other tenants consuming the filesystem therefore cause refusal, not ENOSPC; real ENOSPC is untested.
- Envelope formula verified to the byte against both VM records (32 GiB: aggregate 12,533,305,344 → main 6,206,705,664 B = 5.78 GiB, WAL 6,243,139,032, reserve 6,700,351,488 B = 6.24 GiB; 10 GiB at 1G: max_pages 260,599 → main 1,067,413,504 B).
- SIGXFSZ: handler installed before any write (bin/nq.rs:11-19, commit 245ff45); at HEAD the pre-SQLite preflight refuses before EFBIG can occur for cooperating writers; raw-writer negative control exists (10 GiB occurrence filelimit-002).
- Expiry transaction: deletion and boundary advance in one IMMEDIATE transaction under `synchronous=FULL`; `delete_enabled` set and reset inside it (retention.rs:477, 524); structural FK check before commit (retention.rs:526-534); persisted `delete_enabled=1` refused at open; advisory watermark never selects deletion; restart cannot revive an expired prefix (retention.rs:119-128). Crash specimen `expiry_crash_restarts_preserve_old_or_new_state` covers process abort at three phases; it does not cover power loss, a crash during COMMIT or checkpoint, or the v13→v14 migration. Note (challenge review Q3): semantic re-validation of the surviving history runs after the irreversible commit (engine.rs:2795-2797); if the structural closure were ever short, the store would fail every later open rather than refuse the expiry. No counterexample was found.
- No second authority ledger: retired identity commitments yield only `HistoricalEvidenceExpired` or `ReplayConflict`; unknown IDs yield `HistoryIdentityUnavailable`, never `expired` (lib.rs:12680-12712).

### 4.2 What the repair does not bound [code + measured]
- **Reclamation stops permanently at the first protected root.** `finding_events` rows are never deleted (only `finding_current` is rebuilt, lib.rs:4549) and every evaluation they reference is protected (retention.rs:421); expiry retires only a contiguous global prefix, and every run whose evaluation lies above the evaluation floor is held with its report, intake and status rows (retention.rs:428 and the final `DELETE FROM expiry_runs`). The same holds for saved-check-claimed evaluations, diagnostic origins, successor intents, the latest report of a removed instance, the last checkpoint of a superseded contract digest, `status_current` targets, and the last evaluation of a retired detector version (retention.rs:407-416, 421). Resolved findings pin exactly as unresolved ones do. This was a disclosed and accepted limitation ("a protected occurrence can hold older ordinary rows behind it", docs/retention.md; GATE1); the new contribution here is the quantification and the routine triggers. [measured] 32 GiB run: generation advanced 0→48 while no finding existed (t=439–709 s), froze at 48 from t=739 s for the remaining 1,410 s after 12 finding events, while admitted reports grew 15→246 and the store grew 1.63→10.19 MB (37.1 KB/report). See evidence/vm32g-trajectory.txt.
- **After the first expiry, every open validates the whole history.** Once `retention_generation > 0`: `store_identity()` returns None so no validation watermark applies (lib.rs:2351, 2287-2320); `since_open()` returns `Scope::FULL` (lib.rs:2341); `engine_semantic_state` returns None so every engine open replays all semantic planes in full (engine.rs:8362, 8388-8399); `validate_boundary` recomputes the canonical digest of every retired intake commitment ever written (retention.rs:150-163). The daemon opens a new `CollectionEngine` for every freshness sweep of every watcher every `reliance/2` (1–60) s (daemon.rs:382-395); every API request and every `nq` CLI run (doctor, the 10-minute saved checks, daily validate) also pays a full open. In addition, the expiry pre-check `prefix_may_advance` tests only row age (retention.rs:258-275), so under a hold or a full window each collection also runs the full typed validation plus a FULL digest scan inside the write lock and rolls back (retention.rs:330-400, engine.rs:8726). [measured] daemon CPU rose from ~3% to ~25% of one core as retained reports grew 15→246 at 5 s cadence (one watcher, mixed causes). [projection] at a seven-day production window (≈110,880 retained collections) the per-open cost is of the order of minutes; even if the measured slope is wrong by two orders of magnitude, 660 collections plus ~600 sweeps per hour cannot each afford a full-history validation. Specimen S4 (§6) measured the pinned typed expiry call at ≈30 ms per retained collection (debug build, N=50–800, linear), of which only ≈0.5 ms is the store digest pass; the rest is typed semantic replay.
- **Residual growth outside the horizon [code]**: retired identity commitments (one row per intake kept forever; ≤2.65–2.85 KB each by record upper bound, not directly measured); status events with no run (daemon start/stop, admission refusals) never expire (retention.rs:502); saved-check, notification, diagnostic and successor rows never expire; the main file never shrinks (freelist reused). [derived] production residue ≤43 MB/day, ≤14.5 GiB/year, even with perfect ordinary expiry, and the per-open digest recompute grows with it.
- **Expiry refusal aborts the collection**: the "history changed after typed semantic validation" refusal propagates through `?` at engine.rs:2794; [measured] 10 of 347 admitted collections in the 32 GiB occurrence's journal (02:10–02:46Z, including the restart phase) were lost this way with one watcher and the daemon's own freshness sweep as the only concurrent writer.

### 4.3 Capacity arithmetic for the real workloads (capacity-model.py; evidence/capacity-model-output.txt)

| Quantity | Production (10 watchers, 660 collections/h) | Fixture (1 watcher @5 s, 720/h) | Class |
| --- | --- | --- | --- |
| Ordinary growth | 26.3 MB/h, 630 MB/day (39.8 KB/collection) | 26.6 MB/h, 639 MB/day (37 KB/collection) | measured (gen4 init→first XFSZ 40.9 h; 32 GiB samples) |
| Seven-day window, main only | 4.11 GiB | 4.17 GiB | derived |
| Shipped LimitFSIZE=1G (main cap 1,067,413,504 B) | full in 40.7 h; nothing is older than 7 d by then, so zero reclamation; controlled refusal replaces the crash | full in 40.1 h | derived |
| 32 GiB volume, 8G file limit (main cap 5.78 GiB) | window fits with 1.67 GiB headroom; residue alone fills it in ≈42 days; under any permanent hold full in ≈9.9 days | ≈37 days / ≈9.7 days | derived |
| Main needed for 7 d + 30/90/365 d of residue | 5.3 / 7.7 / 18.7 GiB (aggregate ≈ 2× + 0.07 GiB; per-file limit ≥ main) | — | derived (upper bound) |

Separation requested by the assignment:
- Normal steady state: not reachable under production conditions once any protected root exists, and the validation cost grows with elapsed time even when it is reached.
- Peak transient: WAL ≤ one transaction (peak 329,632 B observed); checkpoint before every write; SHM 32 KiB. Backups, upgrade copies, admissions and archives live outside the envelope on the same filesystem; the automatic envelope leaves about two main files of slack before refusal, so they do not threaten the bound, but they do shorten time to refusal.
- Pathological but valid: a long-lived finding, a removed watcher, a rebind with checkpoints, a retired detector version. Each is a permanent hold today.
- Permanently unresolved dependencies: hold by owner decision; the owner decided *current* findings, the implementation protects *all* finding history (see §3).

Automatic-sizing evaluation: the implemented policy already is "optional operator hard ceiling + conservative derived defaults + explicit reserve + dependency-aware reclamation + refusal". It preserves an explicit bound. Predictive warnings and operator visibility do not exist (§6 G2). Deriving the horizon from storage would not help: the binding constraints are the hold and the validation cost, not the window length. Recommendation: keep the explicit `horizon_seconds` + ceiling model; do not add dynamic horizon scaling.

## 5. Proposed operating envelope and defaults (what can be defended today)

| Default | Value | Class | Defensible claim |
| --- | --- | --- | --- |
| Hard ceiling | automatic: occupied + ½ free-above-reserve, each of main/WAL clamped by RLIMIT_FSIZE | verified in code and against two records | Cooperating NQ writers cannot exceed it; they refuse. Non-NQ writers and backups are outside it. |
| Reserve | max(1 GiB, fs_total/5) | verified | Checked per write against live free space; not physically reserved. |
| horizon_seconds | 604,800 | assumption (shipped default) | Not achievable on a 1 GiB file limit at ≈26 MB/h; not achievable while any protected root exists; validation cost makes a full window infeasible at production cadence (projection). |
| Supervised session envelope | hours-scale sessions on a fresh VM, ≤ ~40 h on a 1 GiB limit, limitation disclosed | measured rate | Unchanged from SUPERVISED-ACCEPTANCE.json; inside the horizon nothing expires, so D1–D5 cannot occur. |
| Unattended envelope | none | — | No default can be defended; see §7. |

## 6. Negative-case qualification findings

Scopes: R = the retention mechanism claim as accepted; S = supervised operation; U = unattended operation; Z = applying the repair to the production zone store.

| # | Finding | Evidence | Blocks |
| --- | --- | --- | --- |
| D1 | First protected root (any finding, resolved or not; saved-check-claimed evaluation; diagnostic origin; successor intent; stale instance/contract/status/detector-version anchor) stops all ordinary expiry permanently. Disclosed limitation, now quantified; routine triggers were not previously named. | retention.rs:407-428 [code]; 32 GiB samples frozen at gen 48 [measured]; specimen S1 CONFIRMED (895aee7) | U |
| D2 | `nq admin archive` fails after any expiry (pages from `after=None` → HistoryExpired); OPERATIONS.md and ROLLOVER.md still prescribe it as the oversized-store remedy. Masked today by D7, which makes archive fail on every v14 store before expiry matters; D2 remains once D7 is repaired. | archive.rs:186-196, engine.rs:9539-9545 [code]; specimen S2 CONFIRMED (895aee7) | U; S recovery procedure once expiry has run |
| D3 | `GET /v1/evaluations` without a cursor returns no HTTP response after expiry; `HistoryExpired` is logged at debug and the socket closes; the typed `expired` never reaches the wire | api.rs:81-83, 272-288 [code]; specimen S3 CONFIRMED (895aee7) | U; S consumer contract once expiry has run |
| D4 | After generation > 0, every Store/engine open (daemon start, each per-watcher sweep every 1–60 s, each API/CLI open) runs full history validation including an O(residue) digest recompute; the expiry pre-check adds a full validation per collection under a hold or full window | lib.rs:2287-2351, engine.rs:8362-8399, retention.rs:150-163, 258-275, 330-400, daemon.rs:382-395 [code]; CPU series [measured]; specimen S4 MEASURED: ≈30 ms per retained collection, debug (895aee7) | U |
| D5 | Expiry refusal ("history changed") aborts the whole collection; 10 of 347 lost with one watcher | engine.rs:2794 [code]; nqd-journal.txt [measured] | U |
| D6 | Production store (1,111,912,448 B = 271,463 pages) cannot be migrated to v14 under a 1 GiB limit: `admit_maintenance` refuses `existing_pages > max_pages` (lib.rs:6220 → capacity.rs:1001 → 258); raising the limit for maintenance alone then fails the service preflight | arithmetic + code; no test | Z |
| D7 | **Regression:** `nq admin archive` refuses every v14 store. The new `capacity::operation_guard` creates `<db>.capacity.lock` and never removes it (capacity.rs:898-956); the unchanged archive staging copies it (and, with checkpoint-on-close disabled, `-shm`) into `db/`, and the exact-inventory check rejects it (archive.rs:859-873). Fails closed with a clear error, no partial archive. 38 archive unit tests plus `semantic_surfaces` and `evaluation_refusal_surfaces::same_code_…cold_archive` fail at HEAD and pass at base; confirmed by CLI `nq init` → `admin archive` at HEAD vs base. Minimal repair: remove the staging lock and `-shm` and require an empty/absent `-wal` after `prepare_archive_copy`, as cli.rs:2366 already does for restore. | evidence/review-F-regressions-opus.md, evidence/nq-app-tests-base-vs-head.md | S recovery procedure (ROLLOVER.md §3, OPERATIONS.md oversized-store advice), U, future Z rollovers of v14 stores |
| G8 | **Behavior change with stale docs:** a graceful `nqd` stop now leaves `-wal` (24,752 B observed), `-shm` and the lock behind, because checkpoint-on-close is disabled and `wal_autocheckpoint=0` (capacity.rs:367-371); by design, since a close-time checkpoint is an unbudgeted write. OPERATIONS.md:838-841 and the daemon.rs:146-148 comment still say the WAL is removed; `tests/daemon_signals.rs:72` asserts it. Hazard: any file-level copy of `nq.db` alone is one transaction short (a probe copy lost the daemon's `stopped` status). CLI backup/restore use the online backup API and are unaffected. | same | S disclosure (docs + test); not a storage-bound defect |
| N1 | **Not a repair defect:** `bounded_status_export_equals_the_complete_history_walk` fails because the test copies only `nq.db` (line 975) for its comparison store and so loses the last WAL-resident commit; the bounded export (`cannot_evaluate` through seq 7) is the true history. Monitor reads `nq status export` through the WAL and is unaffected. Fix the fixture (copy `-wal` too or checkpoint first). | same | none |
| G1 | Startup refusal (capacity, SQLITE_FULL, slack consumed, st_dev change, envelope mismatch) exits 1 and `Restart=on-failure` with no StartLimit loops forever; each iteration past open re-runs full validation | daemon.rs:45-117, nqd.service:43-44 [code] | U (fold into G2) |
| G2 | Operator cannot distinguish capacity exhaustion / custody hold / ordinary expiry / corruption: `doctor` prints the literal `"database":"healthy"` and checks no capacity state (cli.rs:2240-2244); capacity refusal shares `StoreError::Invariant` with real invariant failures (capacity.rs:64-66); custody blockage is silent (`deleted_rows: 0`); the daemon's "healthy" component status written at startup goes stale while collection is refused because status writes are store writes. Deploying under the shipped 1G limit would turn today's visible crash loop into a silent stall after ≈40 h. | [code] | S disclosure, U, Z |
| G3 | `nq admin validate --full` prints `"validated":"full"` after expiry; `require_complete_history` has no production caller | cli.rs:2684-2700, retention.rs:286-294 [code] | anti-amplification disclosure |
| G4 | Forward wall-clock step deletes the whole unprotected window in one commit; no guard against the persisted previous cutoff | engine.rs:2785-2793 [code] | U (low; not a blocker) |
| G5 | Not covered by any test or occurrence: real ENOSPC; SQLite-level EFBIG at a real envelope boundary; daemon-level concurrent readers; restart while full; many refused cycles; power loss; v13→v14 migration of an oversized store; holds lasting days; any run longer than 30 minutes | B-capacity gap matrix | U (restart-while-full and oversized migration matter; ENOSPC/power loss are not blockers) |
| G6 | Backups, upgrade copies, admissions and archives share the filesystem outside the envelope; an explicit `byte_ceiling` equal to capacity leaves zero slack | capacity.rs:213-224, 317-325 [code] | future optimization |
| G7 | Production: nq-validate-full-ops and nq-ops-saved-checks run with LimitFSIZE=infinity against the daemon's store; with 0.2.4 their connection-close checkpoints are the likely way the main file grew 38 MB past the daemon's limit [hypothesis]. Under v14 the persisted `max_page_count` would bound them too [code]. | production observation | Z |

Build and test baseline (worker C, Sonnet; evidence/build-tests-C-sonnet.md, logs in the session scratchpad): HEAD 257096b, clean tree, rustc 1.94.0 (pinned), debug profile, `--locked`, isolated target directory (17.9 GB including an accidental first pass on 1.98.0 whose failure set was identical except for one trybuild snapshot). `cargo build --workspace --bins` succeeded. `cargo test --workspace` FAILED (rc=101): nq-store 93 passed / 0 failed / 5 ignored (matches the accepted 93); nq-core lib 222 passed / 0 failed / 5 ignored; nq-app lib 112 passed / 47 failed (≈37 archive-module tests on the D7 unmanifested sidecar, ≈12 `notification::local_inbox_*` tests refusing a uid-1000 group-writable temp ancestor, which is environmental); nq-app integration: `daemon_signals` 1 failed (G8), `evaluation_refusal_surfaces` 2 failed (one D7 cold-archive, one N1 fixture), `semantic_surfaces` 1 failed (D7); `admin_lifecycle` 9/9 and `file_size_limit` 1/1 pass. Both ignored store fixtures pass when run individually: eight 1 MiB captures in 4.1 s (peak RSS 61 MB); 128/4096 retained identities over two expiry cycles in 7 min 41 s (peak RSS 61 MB); neither prints store byte counts. The same archive, SIGTERM and integration targets pass at base a7d37dc (evidence/nq-app-tests-base-vs-head.md). The prior campaign ran only `nq-store --lib`, `nq-core --lib`/`checkpoint_commit`, and `nq-app --test admin_lifecycle --test file_size_limit` (integration-00N/results.json), which is why none of this was seen.

Regression specimens (worker D, Opus; evidence/specimens-D-opus.md, raw in evidence/specimen-raw/): commit `895aee751da5594c629e5d3c8dd4a6e0d071a7dc` "Add NQ #27 retention defect specimens (test-only)" on branch `audit/nq-27-specimens-20261010` (worktree /data/git/.worktrees/nq-27-audit-specimens-20261010, off 257096b, not pushed; both hunks inside `mod tests`, +341 lines, no trailer; the candidate worktree untouched).
- **S1 confirmed** (engine.rs:13152): a finding opened at evaluation 3 and resolved at 4; the first expiry moved the floors to 2 (generation 1, 32 rows deleted); two later expiries with cutoffs past all 13 collections deleted 0 rows and left generation 1, floors 2. A resolved finding pins the prefix.
- **S2 confirmed** (api.rs:1621): after expiry, `create_archive` fails with "reopen public governed-evaluation history: full history unavailable: ordinary history expired through evaluation sequence 2".
- **S3 confirmed** (api.rs:1652): after expiry, `GET /v1/evaluations?limit=10` returns zero bytes (handler error, socket closed); `after=2` alone is a 400 and `after=2&through=3` a 200, but no surface tells a client those numbers.
- **S4 measured, debug build on crow** (engine.rs:13254, `#[ignore]`): with the prefix pinned by a resolved finding, every call deleted 0 rows and cost grew linearly with retained collections: typed `expire_ordinary_history` 1.18 s at N=50, 2.75 s at 100, 4.65 s at 200, 9.83 s at 400, 12.88 s at 500, 24.17 s at 800 (≈30 ms per retained collection); the store-only boundary-plus-FULL-digest pass ≈0.5 ms per retained collection. N≥2000 was not reached because the fixture's own setup slows as history grows (N=800 took 1,446 s of setup). Release was not measured. Debug-to-release ratios for this code are not established; even at 1 ms per retained collection a seven-day production window (≈110,880 collections) would cost ≈110 s per call.
- Suite at the specimen head: nq-core lib 223 passed / 0 failed / 6 ignored; nq-app lib 123 passed / 38 failed (all archive tests, D7); the two archive CLI tests, `sigterm_stops_nqd_and_closes_the_store` (G8) and `bounded_status_export_equals_the_complete_history_walk` (N1) also fail; nine notification tests fail environmentally under umask 0002.

No destructive experiment was run. No production data was touched. Original specimens (VM archives, journals) remain in the prior campaign record.

## 7. Unattended-readiness requirements

Project terminology mapping: SUPERVISED_BETA ≈ the accepted "bounded supervised trial" (hours-scale, fresh VM, operator present); UNATTENDED_QUALIFIED ≈ the project's "seven-day unattended hosting qualification".

Is the seven-day observation still necessary for an UNATTENDED claim? Yes; no equivalent accepted test exists (longest run 30 minutes). Is the current candidate ready to enter it? **No**, and entering it now would waste ≈66 GB of host allocation for a predictable result: with no finding, a window whose per-open validation cost grows with elapsed time; with any finding, zero reclamation and refusal at the ceiling (≈40 h on 1G, ≈10 days on the 32 GiB profile) followed by a startup restart loop. No qualifying observation is running anywhere, so nothing needs preserving or restarting.

Requirements before any unattended observation (each with what it blocks):
1. Bound post-expiry validation cost on every open, sweep, collection and API request (validation incremental across retention generations: watermark anchored at the floors; commitment digests certified once), and measure it with a production-scale synthetic store. Blocks U.
2. Expiry refusal must not lose the collection (D5). Blocks U.
3. Narrow finding protection to current findings (with notification custody made explicit, since `notification_outbox` references `finding_events`). Implementation work under the existing owner amendment. Blocks U.
4. Owner answer on F2 (declared holes vs. strict prefix), which decides whether detector-version bumps, removed watchers and open findings end reclamation. Blocks U.
5. Capacity refusal and holds visible in status and `doctor`, with a distinct refusal class (G2, G1). Blocks U and Z.
6. D2/D3 repairs. Blocks U and the post-expiry recovery procedure.
7. Then an accelerated, production-shaped run (10 watchers at 60 s, horizon 60–600 s, one finding opened and resolved mid-run, one restart) on the existing vm.py/guest-setup.py occurrence. The seven-day run comes last, only if the owner wants an UNATTENDED claim.

### 7.1 Executable plan for the seven-day observation (only after items 1–7 and with explicit owner storage authorization)
- Candidate: a successor commit on dev/operator-beta above 257096b carrying the repairs; package built by the existing bookworm-build/package-00N pipeline with SHA256 in SOURCE-IDENTITIES.json; specimens S1–S4 passing as regression tests with S1 asserting the repaired behavior.
- Host: the existing vm-qualification-preparation occurrence pattern (vm.py, guest-setup.py): fresh Ubuntu 22.04 guest, 4 GiB RAM/2 vCPU, dedicated 32 GiB data filesystem at /var/lib/nq; root storage admission ≈66 GB against the 60 GiB-per-filesystem reserve on crow; durable systemd unit with CHECKPOINT/TERMINAL receipts per AGENTS.md.
- Limits: LimitFSIZE=8G identical in init wrapper, maintenance wrapper and daemon; MemoryMax=2G; automatic envelope (expected main 5.78 GiB, reserve 6.24 GiB).
- Workload: production shape, 10 stdio watchers (nine at 60 s, one at 30 s) over harmless fixture units; one watcher's unit deliberately stopped for 48 h mid-run to open and then resolve a finding; one saved-check claim against a real evaluation per day; one planned graceful restart and one planned SIGKILL.
- Retention: horizon_seconds=604800. A 30-minute accelerated pre-run at horizon 60 s on the same build first, to re-check that floors advance past the resolved finding.
- Sampler: guest-setup.py sample at 60 s for 8 days (--duration-seconds 691200, ceiling 128 MiB), already prepared; records floors, counts, bytes, envelope, NRestarts, CPU, RSS.
- FAILED conditions: any `status=25/XFSZ`; NRestarts beyond the two planned; any `capacity refused` while retained ordinary history is younger than the horizon; generation not advancing within 2 h after the finding resolves; collection or sweep latency exceeding cadence; store_allocated_bytes above the main cap; `doctor` reporting healthy while any of the above holds.
- Recovery policy: no operator intervention except the two planned restarts; on FAILED preserve the guest, seal records, stop.
- Completion: 7 × 24 h with floors advancing; store bytes ≤ (seven-day volume + residue) within 10%; per-open validation time flat over elapsed time; zero XFSZ; zero unplanned restarts; `doctor` reporting retention state truthfully; final full validation; sealed archive of samples.
- Custody: sealed-guest-records.tar.gz + SEALED-CUSTODY.json as in lifecycle-001; VM image retired after acceptance; retirement condition named by the creating agent.

## 8. Concrete remaining obligations

| Obligation | Blocks | Kind |
| --- | --- | --- |
| Incremental validation across retention generations (D4) + measurement on a production-scale synthetic store | U | engineering, medium |
| Expiry refusal does not fail the collection (D5) | U | engineering, small |
| Narrow finding protection to current findings; make notification protection explicit (D1 part) | U | engineering, small-medium, within existing owner amendment |
| Owner decision F2: strict prefix vs. declared protected holes; stale-anchor release follows | U | owner decision |
| `doctor`/status retention fields (generation, floors, cutoff, occupancy vs ceiling, hold attribution); distinct `CapacityRefused` error class; StartLimit or degraded startup (G2, G1) | U, Z | engineering, small |
| D7 archive sidecar cleanup (lock, `-shm`, empty `-wal`) + run the full `cargo test -p nq-app` in the qualification pipeline (the campaign ran only `admin_lifecycle` and `file_size_limit` there) | S recovery procedure, U | engineering, small; qualification-process fix |
| G8: update OPERATIONS.md/daemon.rs comment/`daemon_signals` test to the no-checkpoint-on-close contract, or add a bounded TRUNCATE checkpoint at shutdown; fix the N1 fixture | S disclosure | docs/test, small |
| D2 archive after expiry; D3 wire-level `expired` | U; S post-expiry recovery/contract | engineering, small |
| Coverage: restart while full; many refused cycles; 24 h+ hold | U | tests + one accelerated occurrence |
| Accelerated production-shaped run (§7 item 7) | U | ≈40 GB, hours |
| Seven-day observation (§7.1) | UNATTENDED claim only | ≈66 GB, 8 days, owner authorization |
| Zone recovery: rollover to a fresh gen5 store with the repaired package on a dedicated filesystem with an 8G limit matched across init/maintenance/daemon, sealing gen4 as an archive; do not attempt in-place migration under 1G (D6); fix the unlimited-LimitFSIZE maintenance units (G7) | Z, NQ #27 closure | separately authorized production change |
| Residue lifetime (retired commitments, run-less status rows): accept as disclosed linear growth with a computed time-to-refusal shown by `doctor`, or decide a lifetime later | future optimization | defer |
| NQ #27 closure | — | only after the zone store is restored under a bounded envelope on the installed release (issue exit criterion) |

Not blockers (cut from earlier drafts after review): ENOSPC and power-loss cases, the clock guard (G4), an in-place migration test for D6, a separate residue-lifetime decision now.

Preserved, not reopened: the bounded-replay amendment; the seven-day horizon as target; refusal over deletion; no automatic shrinking; conservative protection of successor/diagnostic closures with unknown external lifetime; the supervised trial envelope and its acceptance; the 10/32 GiB and memory-fixture acceptances within their stated scopes.

## 9. Independent review findings

Reviewer: one separate Opus context (evidence/review-E-challenge-opus.md), given the draft, the two scout reports, the evidence files and the source; instructed to challenge, not extend. Its seven answers:
1. Weakest bounded-storage claim: the reserve is checked, not reserved, and ENOSPC is untested; backups outside the envelope are not material to the bound. Accepted (§4.1, §5).
2. Long-lived dependency defeats the envelope: AGREE on the code reading (resolved findings pin forever); DISAGREE that this needs a new owner decision, because the owner authorized protecting *current* findings and the widening was an accepted implementation choice. Accepted; F1 is now an engineering obligation (§3, §8).
3. Reclamation destroying required evidence: no race found; semantic re-validation runs after the irreversible commit; JSON references scanned only in evaluation detail. Accepted as a caveat (§4.1).
4. False success at capacity: AGREE; `doctor` "healthy" is a literal, startup "healthy" status goes stale, the API fails by dropping the socket rather than returning cached success. Accepted (§6 G2).
5. Operating configuration vs. measurements: arithmetic sound apart from two unit errors (5.78 GiB not 6.21; 6.24 GiB not 6.7), corrected; DISAGREE on the CPU attribution: the growth is dominated by post-expiry full validation on every open, not by the expiry pre-check, so the draft's D4 repair was insufficient and the §7.1 "CPU flat" criterion would have failed by design. Verified in source by the main session and accepted (§4.2, §7).
6. Unnecessary qualification: replace the 8-day run as the next step with a production-scale synthetic store plus an accelerated run; drop in-place migration for D6; fold G1 into G2; do not treat ENOSPC, power loss or the clock guard as blockers; F1/F8 are repairs. Accepted (§7, §8).
7. Disposition: the draft was too harsh on supervised use, since inside the horizon nothing expires and the 40 h limit arrives with or without D1; recommended SUPERVISED_BETA_ONLY with unattended NOT READY. Accepted (§10). The main session adds that the unattended path is blocked by demonstrated defects, not merely by missing measurements.

Errors it found in the draft and that were corrected: the D6 citation chain (lib.rs:5691 was the wrong backup function; the refusal is lib.rs:6220 → capacity.rs:1001 → 258); "production has findings" is an inference, not shown by the production evidence; the D5 journal spans 02:10–02:46Z including the restart phase; the ≈4.5 ms/report slope was labelled measured but is a derived, mixed-cause figure; the residue rate is an upper bound.

Material disagreements were reconciled against source: the post-expiry full-validation mechanism (lib.rs `since_open`, `store_identity`; engine.rs `engine_semantic_state`; retention.rs `validate_boundary`; daemon.rs sweep) was re-read by the main session and confirmed. One review cycle was performed; no second cycle was needed because no new defect emerged from the review, only recharacterization.

## 10. Disposition and smallest next action

**SUPERVISED_BETA_ONLY.** The mechanism repair stands as accepted: for cooperating writers the store is bounded by a persisted envelope and refuses instead of crashing; expiry is atomic and non-amplifying; no second authority ledger exists. Within the already-accepted supervised scope (fresh VM, operator present, sessions far shorter than the seven-day horizon, ≤ ~40 h on a 1 GiB limit, limitations disclosed), NQ can be used today.

**Unattended hosting: NOT READY, blocked by exact obligations**, not by missing measurement alone. Three demonstrated behaviors make the seven-day window unreachable under the production workload: the permanent global hold at the first protected root (D1), full-history validation on every open after the first expiry (D4), and collection loss on expiry refusal (D5). Two more (D2, D3) break the documented recovery and consumer contract after the first expiry, and one (G2) would turn the production crash loop into a silent stall. Nothing is structurally unbounded in bytes; what is unbounded is validation work over retained residue, and what is unbounded in time is the hold.

The repair cannot be applied to the production ops store under its current limit (D6); zone recovery is a separately authorized rollover. Separately, the repair head carries one regression that the prior campaign's test selection did not exercise: `nq admin archive` refuses every v14 store (D7). It fails closed and does not affect bounded storage, but it breaks the documented rollover and oversized-store procedure and must be repaired and re-qualified with the full nq-app test suite before the package is promoted beyond the supervised trial.

Do not start the seven-day observation on this candidate. Do not close NQ #27.

**Smallest next action (engineering, no owner decision required):** make validation incremental across retention generations and measure post-expiry open cost on a production-scale synthetic store; in the same lane, stop failing the collection on expiry refusal and narrow finding protection to current findings with notification protection explicit, using specimens S1–S4 as acceptance tests. **In parallel (owner):** answer F2, strict prefix versus declared protected holes.

## 11. Custody and storage closeout

- Record: this directory (/data/git/.campaign-artifacts/nq-27-readiness-audit-20261010), ≈1 MB: REPORT.md, CHECKPOINT.json, capacity-model.py, evidence/ (production observation, capacity arithmetic, 32 GiB trajectory, base-vs-head test comparison, the five AI-agent reports A/B/C/E/F and the specimen report D with raw outputs). Owner: jbeck. Retire when NQ #27 reaches its next disposition; the report is also committed as documentation on the specimen branch.
- Specimens: constellation-nq branch `audit/nq-27-specimens-20261010` at 895aee7 (test-only) in /data/git/.worktrees/nq-27-audit-specimens-20261010; not pushed. Retire the worktree after the branch is pushed or its tests are folded into the repair lane; the branch is the regression evidence.
- Qualified candidate worktree /data/git/.worktrees/nq-bounded-retention-20261009 left at 257096b, clean, unchanged.
- Disposable substrate created and removed by this audit: compiler targets for HEAD (17.9 GB), specimens (≈9.3 GB), base (2.4 GB) and probe (2.2 GB); the detached base worktree; CLI reproduction scratch dirs. Measurements are in CHECKPOINT.json. No VM, container, credential or production change was created. Host reserve (60 GiB per filesystem) was never approached: /tmp (on /) had ≥362 GB available at the low point.
- AI-agent review disclosure: findings were produced by one Fable 5.1 session with Opus subagents for semantic review, capacity review, regression diagnosis, specimen construction and the independent challenge review, and a Sonnet subagent for the build/test baseline. Load-bearing code claims were spot-checked in source by the main session; measured values come from preserved sample series, the production host's journal, and the specimen outputs.
