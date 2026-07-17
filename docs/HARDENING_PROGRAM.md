# nq-ng Hardening Program

**Status: RATIFIED / FROZEN — 2026-07-17.**

Reviewed by two independent adversarial passes (Fable and codex) against the
provisional at plan hash `c51511db…50db`, then reconciled by Opus. The frozen plan
hash is in `docs/HARDENING_PROGRAM.sha256`. Implement from the workstreams as amended
below; **§8 is the authoritative ratification delta and governs wherever a workstream
paragraph and a §8 entry disagree.** Reopen only on a new forcing case, not on taste.

## Pins

- **Substrate:** `~/git/skunkworks/nq-ng`, **uncommitted working tree** (`?? nq-ng/`
  under skunkworks `main` @ `788c9632ac472cbe68eb1a2526dea94d4666c435`, 2026-07-17).
  There is no nq-ng revision to pin yet — see §0.
- **Plan hash:** recorded in `docs/HARDENING_PROGRAM.sha256` (sha256 of this file at
  the moment it was handed to review). Any edit invalidates it; re-hash before each
  review pass.
- **Review lineage:** codex audit (2026-07-17) → Opus review → ChatGPT sharpen ×2 →
  Opus consolidation. Two terminology corrections and one identity correction from
  ChatGPT are folded in (see §1, §3).

## 0. Precondition — pin the substrate

The whole program, and every downstream review, references "the pinned nq-ng
revision." That revision does not exist: nq-ng is untracked working tree. **Step 0
is to commit nq-ng** so there is an exact source identity to review, rebuild, and
bind reports against.

How it is committed is the lineage decision in miniature (§6): a commit *inside*
skunkworks vs `git init` nq-ng as its own repo whose history later becomes the
canonical beta lineage. Recommendation: init nq-ng as its own repo now (its history
is the thing §6 fetches intact into canonical `nq`), commit the reviewed state, and
pin *that* commit. Do this before the first review pass.

## 1. Vocabulary and the immutability law

The layers, kept distinct (a watcher *acquires*; a profile *admits* — do not
recombine them):

- **watcher** — the acquisition mechanism. Acquires one bounded observation. No
  admission authority.
- **witness** — the immutable observation artifact the watcher produces.
- **profile / evaluator** — interprets a witness and *admits* it. This is the only
  path that turns testimony into relied-upon evidence.
- **admission context** — the complete identity under which admission happened:
  watcher artifact digest + witness schema id + profile semantic id +
  evaluator/build/carrier identities (§3C).
- **admitted report / finding** — the immutable judgment produced under one
  admission context.
- **reassessment** — a *new* report over an existing witness under current
  semantics. Appends; never rewrites.
- **receipt** — the custody/authority record.
- **`nq-helper`** — the sandbox OS *privilege principal* (an account names a
  privilege domain, not an epistemic object). Distinct from "watcher," which names
  the mechanism.

**The law:**

> A witness is immutable. An admitted report is immutable and bound to the complete
> admission context under which it was produced. Reassessment appends; it never
> rewrites.

## 2. The beta bar (adopted verbatim)

> nq public beta guarantees reproducible packaging, protocol and storage integrity,
> operationally functional supervised watchers, explicit semantic identity for
> findings, and preservation of historical admission meaning. It does not yet claim
> remote operation, universal multi-user confidentiality, or sealed lifecycle
> evidence beyond the published specimen scope.

Beta-blocker vs post-beta classification (the line to defend — is each item a
*blocker*, or an obligation the beta merely *names*?):

| Item | Beta blocker? | Rationale |
|---|---|---|
| Semantic identity (rule IR + evaluator digest + build_id) | **Yes** | Beta claims "explicit semantic identity." Guarantee-typed; one uncovered law falsifies it. |
| reconstruct → verify / replay / reassess split | **Yes** | Beta claims "preservation of historical admission meaning." |
| Packaged-helper Unix contract + parent-side enforcement + packaged-bytes black-box test | **Yes** | Non-functional over the Unix carrier today; beta claims "operationally functional supervised watchers." |
| Loopback HTTP opt-in + precise two-surface language | **Yes (cheap)** | Silent default is a product decision, not a fix. |
| QEMU harness sealing | **Yes, off the merge path** | Gates promotion-by-evidence, not code review/merge. |
| SQLite store contract (integrity, WAL/recovery, guarded migration, portable archive) | **Yes** | Beta claims "protocol and storage integrity" + guarded migrations — coverage inside committed scope. |
| watcher/witness/`nq-helper` rename | **Yes** | Cheapest while unminted; the atomic-rename window closes at mint. |
| v1 wire/admission child-subject mismatch: fix-or-disclaim + pin schema id | **Yes** | Current-schema honesty; broader v0 standing reconciliation stays post-beta. |
| Full composite admission identity (5-tuple, cross-repo) | **No — name it** | Load-bearing only when acquisition & interpretation live in separate repos. |
| Watcher admission registry / lockfile | **No — name it** | Gates the *first external watcher*, not the beta. |
| `case-engine` adoption | **No — compare first** | Two generic bounded-execution substrates → microkernel-in-a-microkernel. |
| Multi-backend storage (PostgreSQL, etc.) | **No — name it** | No distributed/multi-writer forcing case yet; arrives as a new admitted storage profile with equivalence evidence. |
| Witness-zoo re-homing, hauntd, iperf3 governed-inquiry | **No** | Post-beta migration, gated by the registry. |

**Database scope:** SQLite is the sole beta storage backend. Beta must prove its
integrity, recovery, migration, and archival contracts. Multi-backend storage is
deferred until a concrete distributed or multi-writer forcing case exists.

**Release shape — beta-1 vs beta-2.** Beta-1 proves the spine: semantic identity is
real; historical judgments don't drift; supervised watchers work; storage is durable
and recoverable; deployment defaults are honest; promotion evidence can testify.
Everything in §5 is the **beta-2** backlog — canonical logical export, the external
watcher registry, witness-v1 reconciliation, the first non-core watcher migration, and
whatever operational ugliness the canary bake surfaces. Beta-1 establishes trustworthy
local custody; beta-2 improves portability and ecosystem boundaries once there is real
state worth exporting. The only lineage obligation beta-1 carries is the **sealed
native archive** (§4 storage) — enough to preserve and inspect the alpha/beta lineage
later, without inventing a backend-independent export format before its consumers
exist.

## 3. Workstream 1 (concrete sketch) — semantic identity + historical custody

The largest and most architectural; everything downstream keys off the rule-IR /
evaluator-digest boundary. Target files: `crates/nq-profiles/src/{descriptor.rs,
detector.rs,host.rs,validation.rs}`, `crates/nq-core/src/engine.rs`,
`crates/nq-store/src/schema.sql`.

### 3A. Identity — declarative semantics + evaluator closure; corpus is conformance, not identity

The golden corpus is a **drift detector, not an identity source** — a finite input
vector proves "these observations still produce these verdicts," which a formula
change in an uncovered branch can preserve while behavior changes. Tests are not
semantics.

Target shape:

```
profile_semantic_id = H(
      protocol_semantics_version
   || canonical_rule_ir                 // typed constants + rule structure, canonical JSON
   || evaluator_engine_semantic_digest  // generic interpreter identity
   || profile_source_closure_hash       // build-time hash of any imperative rule source not in the IR
)

build_id = H(packaged executable / build artifact)   // names the bytes, not the meaning
```

- **Canonical rule IR** carries thresholds, comparison directions, coverage
  requirements, payload bounds, and aggregation rules as typed data the evaluator
  *reads*. Concretely, the constants currently loose in Rust move into it:
  - `2.0` normalized-load threshold + comparison (`host.rs:398`)
  - hostname byte bounds, `cpu_count > 0`, load finiteness/sign (`host.rs:199-227`)
  - the load coverage↔fields consistency matrix (`host.rs:244-254`) and
    `require_coverage_consistency` bands, to the extent expressible as data
  - the access-path→capability map (`host.rs:503-508`)
  - (freshness `reliance_seconds`/`alignment_seconds` is already descriptor data)
- **Evaluator engine digest** identifies the generic machinery interpreting the IR.
  Closure generation must be **transitive and fail-closed** — it must cover shared
  admission machinery (`validation.rs`, esp. `validate_common` and everything it
  calls), the protocol canonicalization it delegates to, and each profile's non-IR
  `validate` body. A *merely declared* source list that silently omits a shared law
  is the failure mode; name the source set explicitly.
- **Detector semantics are identified separately.** The `>= 2.0` law is *detector*
  semantics, not profile-admission semantics (`detector.rs:18-44`, `host.rs:397-402`).
  Findings bind a distinct **detector semantic id** — the detector descriptor already
  has its own digest (`detector.rs:41`), separate from the profile digest, so the rule
  parameters belong *there*. Negative test: change an uncovered branch or threshold and
  require the appropriate id (detector vs profile) to rotate.
- **Source-closure hash** is the escape hatch for rule logic that cannot be reduced
  to IR (the *shape* of `validate`): hash its declared source at build time.
  Conservative false rotation (identity changes on a semantic no-op edit) is
  explicitly accepted — far safer than silent semantic drift. A hand-maintained
  `rule_revision` survives only as a human-readable label, never as authority.
- **Golden corpus** is a *required conformance test* binding compiled implementation
  to declared IR — not part of identity.

Rename the misnamed field: the descriptor's `digest()` /`ProfileDigest` /
`semantic_digest(self)` (`descriptor.rs:147`, self-documented as "descriptor bytes
only") becomes `descriptor_digest` — an honest vocabulary/metadata identity. The
detector descriptor (`detector.rs:18-33`) either carries the typed threshold so its
digest covers it, or references the rule IR by `profile_semantic_id`.

### 3B. Historical custody — stop reconstructing by evaluation

`reconstruct_admitted` (`engine.rs:1879`) currently re-runs *current* `validate`
against the *stored (unchanged) descriptor digest* (`validation.rs` binding check),
so a threshold change silently reinterprets history. Replace it with three explicit
paths:

- **`verify_admitted(report)`** — load and verify bytes, custody chain, witness
  reference, and recorded admission context. **No re-evaluation.** Default read path.
- **`replay_admission(report)`** — optional reproducibility check: re-run the
  original witness *only* under an exactly matching semantic + build identity;
  refuse on mismatch.
- **`reassess_witness(witness)`** — evaluate the immutable witness under current
  semantics; **append** a new report linked to both the witness and the prior
  report, tagged with the new admission context. Never rewrites.

**Persist the judgment (review amendment).** The store currently retains the source
protocol JSON, not the admitted `ValidatedReport` (`schema.sql:112-130`), and
reconstruction rebuilds a judgment by rerunning *current* `validate` under a
*fabricated, weaker* context — `granted_capabilities` is set from the report's own
`used_capabilities` (`engine.rs:1900-1904`), making the capability-escape law vacuous
on replay. So `verify_admitted` must verify a **persisted, versioned admitted-judgment
snapshot** (lossless), not re-derive one. Adding that snapshot to the store is part of
this workstream.

### 3C. Admission-context binding — minimal now, composite later

Each admitted report records an inspectable `admission_context` (summary id
`admission_context_id`, constituents preserved):

```
admission_context = {
  watcher_artifact_digest,     // helper bytes that produced the witness
  helper_protocol_version,     // carrier contract (nq.helper.v1)
  witness_schema_id,           // artifact schema (post witness.v0 graduation, §5)
  profile_key + profile_semantic_id,
  evaluator_engine_digest,
  build_id,
}
```

- **Beta (revised in review):** most context is *already recorded* — `admission_records`
  carries `executable_digest`, `config_digest`, `profile_digest`, `protocol_version`,
  `conformance_json`, `lock_json` (`schema.sql:20-37`), reachable via
  report→submission→run→admission, and execution identity already includes the helper
  root / interpreter+argument chain / account / cwd
  (`nq-helper-sandbox/src/identity.rs:59-94`). So the beta work is **not** a new
  context column; it is: (a) close the nullable seam — `witness_runs.admission_id` is
  nullable (`schema.sql:80`) exactly where the law needs it mandatory for
  admitted-report-producing runs; (b) add the *new* semantic-identity fields (rule-IR
  digest, evaluator digest, detector semantic id — §3A, which don't exist yet); (c)
  record profile-admission vs detector/evaluation identities *separately* (`BuildInfo`
  is metadata, not daemon byte identity); (d) mark legacy rows context-incomplete,
  never backfill invented identities. **Preserve** the existing atomic
  run+submission+report+observations transaction (`nq-store/src/lib.rs:735-800`) — do
  not split it into independent append calls.
- **Post-beta:** the registry that *validates* these fields against an admitted
  allowlist (§5) becomes load-bearing when a watcher decouples into its own repo. A
  profile digest alone cannot protect history once acquisition lives elsewhere
  (a Python ZFS watcher changing coverage with the Rust profile untouched is still
  drift).

## 4. Workstreams 2–6 (beta)

2. **Helper Unix contract.** The security boundary is **parent-side**: the
   supervisor authoritatively verifies dir ownership + exact mode *before launch*,
   socket path type + symlink absence, socket ownership + mode *after creation*,
   peer credentials, and cleanup/replacement. The packaged helper's own check is
   conformance/diagnostics only (an unsafe helper can ignore its own checks). Fix
   the real conflict (`nq-helper-sandbox/src/lib.rs:493` 0730 daemon-owned dir vs
   `helpers/python-conformance/nq_conformance_helper.py:403-406` helper-owned/no-
   group-write) by having the supervisor communicate the expected UID/GID
   explicitly and enforce parent-side; align the helper's check to the supervised
   contract. Passing a pre-bound socket FD is cleaner long-term but need not block
   beta. **Add a black-box test that executes the packaged helper bytes over the
   real Unix carrier** — replace the permissive inline doppelgänger
   (`nq-core/src/unix_runner.rs:1433`).

3. **Loopback read.** *(Corrected in review — the drop-the-flag fix was wrong.)*
   `console_address` defaults to `127.0.0.1:8787` (`daemon.rs:22`) and the listener is
   bound + spawned unconditionally (`daemon.rs:68-70, 94-96`), so removing the
   unit-file flag disables nothing. Real fix: make the console address an
   `Option<String>` (absent ⇒ no INET listener), bind/spawn only when present, and
   omit it from the packaged unit. Keep the 0660 Unix socket as the primary local
   surface. **Negative test (required):** default packaged startup exposes *no* INET
   listener. Document the two surfaces separately — Unix socket = group-bounded by
   DAC; loopback HTTP = host-local, UID-agnostic, off by default.

4. **watcher/witness/`nq-helper` rename.** Atomic across code/docs/SDK/packaging/
   harness while unminted. SDK/profile/runtime language → watcher; produced
   artifact → witness; sandbox account + helper carrier → `nq-helper`. The distinct-
   UID assertion in the specimen harness keys on the account name — rename in one
   coordinated change or the specimen breaks.

5. **Seal the QEMU harness** (before any pass counts as promotion evidence). Flow:
   stage + hash executable inputs → execute only staged inputs → close all output
   writers → verify shutdown + disk state → hash outputs → verify manifest → write
   final pass marker last. Specifics: stage + hash `guest-lifecycle.sh` before
   upload and re-verify in guest; stop `tee` before hashing `host.log`; post-
   shutdown `qemu-img check`; write `RESULT=pass` only after the manifest verifies;
   reject `GUEST_REFUSAL`; accept ssh 255 only inside a bounded expected-reboot
   window; bound `wait_ssh` by `remaining()`. *(The earlier `remaining()==0 →
   timeout 0` item is withdrawn — `remaining()` already refuses at expiry,
   `run-noble-qemu.sh:103`.)* Also fix `test-harness.sh`, which currently enshrines
   the broad ssh-255 acceptance it should be catching.

6. **Rebuild + run the two capable specimens** from the reviewed, committed
   revision (§0). Promote only from their verified evidence.

### Storage contract (SQLite, beta)

A narrow internal store API defined over **NQ operations, not database primitives** —
keep the SQLite implementation concrete; do **not** build a generic multi-backend
trait (that is ORM-shaped fog). Operations: append raw witness · append admitted
report · link reassessment · verify immutable record · enumerate/report · guarded
schema migration · sealed archive/export.

Beta obligations: WAL + startup recovery; busy-timeout / concurrency policy;
transactional admission of witness + report links; foreign keys + integrity checks
enabled; explicit schema-version refusal; guarded migration with verified backup;
deterministic export/archive (canonical records + manifests + hashes, **not** a SQL
dump); crash / partial-write tests; a documented maximum intended deployment shape.

Escape route (revised in review): (1) **canonical logical export is deferred past
beta** — beta ships a *sealed cold archive* (the SQLite DB, a WAL-consistent backup,
the exact binary, config, schema version, manifests, hashes, and frozen alpha
tooling); that is enough to make the §6 replacement honest without promising a
portable lineage format now. (2) backend-independent store-contract tests run against
SQLite now, which any future backend must pass in full plus its own operational tests
— keep these; they are cheap and make another backend an *earned successor*. Also
required in beta: `Store::validate` must recompute stored raw/report/descriptor
digests (today it checks SQLite/schema/FK/projection only,
`nq-store/src/lib.rs:426-482`), and the backup-before-refusal ordering must be
resolved — exact-version `open` + `backup_verified` currently reject an old schema
*before* it can be backed up (`lib.rs:1105-1135`). Migration: v1 has no predecessor,
so beta needs exact-version refusal + WAL-consistent backup + atomicity, **not** a
full migration path (gate a real migration on the first schema bump plus a
prior-schema fixture).

## 5. Beta-2 / post-beta named surfaces (candidates, not authorization to build)

- **`nq.witness.v0` standing reconciliation → deferred; intra-v1 fix → beta.**
  helper.v1 (transport) does not supersede witness.v0 (artifact contract) — different
  layers. But review found the two hold *opposing* standing philosophies: v0 has the
  witness *declare* standing (`nq-witness/SPEC.md:149-157`), while ng *forbids*
  helper-authored standing (`validation.rs:871-898`; `authoritative_for` is a refused
  key). Resolving that inversion is the v1-graduation job and is **deferred**. What is
  *not* deferrable (see §2 beta row): the current v1 wire advertises child-subject
  coverage declarations while admission collapses them by kind and restricts to the
  request subject (`nq-protocol/src/model.rs:251-264` vs `validation.rs:771-817`) — fix
  or explicitly disclaim that, and pin the `nq.evidence_report.v1` schema id, in beta.
  (v0's Tier system — Tier-2 sources may not feed profile detectors — is the doctrinal
  ancestor of the `nq-blackbox` ingestion seam; same law, note it once.)
- **Watcher admission registry / lockfile.** Reviewed catalog pinning each admitted
  integration: watcher id+version, repo/release identity, artifact digest, helper
  protocol version, witness schema version, compatible profile id + semantic digest,
  declared coverage/refusal contract, custody state
  (incubating/admitted/retired). Extends nq-ng's existing reviewed-lockfile / stale-
  refusal / compiled-profile / release-manifest machinery — not dynamic discovery.
  This is what retires old nq's "GPU fans through 25 files": adding a watcher
  becomes a governed data operation.
- **Witness-zoo re-homing**, boring-first: `fs_inode`/ZFS reference watcher →
  security-exposure watcher (`nq-security-witness` → `nq-security-watcher`) →
  another refusal-heavy watcher → hauntd passive half → iperf3 governed inquiry.
  Prove registry/wire/schema/packaging/cross-UID/profile-binding on the least
  interesting watcher first.
- **hauntd** stays fenced (its own THESIS "SKUNKWORKS DRAWER" custody); adopt the
  passive half only after the boring watchers prove the seam. **Compare
  `case-engine` against `nq-helper-sandbox` + the nq execution pipeline before
  adopting either** — do not absorb it merely because it is generic.
- **`nq-blackbox`** is an *external evidence producer*, not a local helper: needs a
  distinct ingestion contract (provenance, transport auth, replay protection,
  possibly signing), not a helper-command masquerade.
- **Multi-backend storage (PostgreSQL, etc.)** arrives only on a concrete forcing
  case — federated nodes sharing state, multiple daemons writing one evidence
  domain, first-class remote ingestion, HA as a product requirement, retention/query
  volume beyond sane SQLite operation, tenant isolation, or a hosted nq service — as
  a new *admitted storage profile* with migration + equivalence evidence, never a
  checkbox beside `sqlite`.

## 6. Integration and cutover

- **Repository:** harden fully in skunkworks/nq-ng → tag/freeze final classic-nq →
  fetch nq-ng history intact into canonical `nq` as the beta lineage (no source-
  merge, no squash) → promote to default → classic stays as legacy branch/tags →
  provenance record links {final-alpha-commit, beta-candidate-commit, promotion-
  evidence, archived-store-manifest}. Move the *lineage*, not the files. Do not
  thread nq-ng into classic nq component-by-component.
- **Deployment (side-by-side) + state (clean break) — both, at different layers:**
  run nq-ng as a canary on **one** of the four hosts with separate service name /
  socket / ports / user / database; keep classic nq authoritative during the bake;
  compare overlapping observations and refusal behavior; do **not** import old
  reports as current state; on promotion, stop alpha and cold-archive its DB +
  config + release manifest + schema version + hashes; nq-ng becomes canonical with
  a clean store; classic remains queryable as separate lineage.

## 7. Review choreography

**sketch → save provisional (pinned + hashed) → Fable kill-test → codex pass →
Opus reconcile (ratification delta, not an essay) → freeze → implement slice by
slice.**

The same model must not both invent and certify the plan. Fable and codex review
this frozen provisional independently; Opus produces a **ratification delta**
(accepted / amended / rejected / deferred, with code references), then freezes.

**Fable instruction (narrow, hostile):**
> Review `HARDENING_PROGRAM.md` against the pinned nq-ng revision as a candidate
> plan, not authority. Verify layer boundaries, claimed invariants, beta-blocker
> classification, migration safety, and required negative tests. Identify
> contradictions, missing guarantee seams, accidental scope expansion, and anything
> deferred past the point where it becomes necessary. Return explicit
> accept/amend/reject findings with code references. Do not redesign unless the
> candidate is structurally insufficient.

**codex instruction:** same target and disposition; emphasize the packaged-bytes-vs-
live-semantics seam and the identity/reconstruction mechanics against the actual
code.

**Named challenge points** (reviewers must land a verdict on each):
1. Does the source-closure hash + rule IR + evaluator digest actually close the
   semantic-identity gap, or does an uncovered imperative branch still drift?
2. Is parent-side enforcement in workstream 2 complete (dir, socket, symlink,
   peercred, cleanup) — or is any check still delegated to the untrusted helper?
3. **witness.v0 deferral:** has beta's current witness schema *already* dropped a
   coverage/refusal/standing law that v0 discovered? "Audit later" is only safe if
   beta is not silently claiming the missing law now.
4. Is the beta/post-beta line in §2 honest, or is a named post-beta surface
   actually a beta blocker (or vice-versa)?
5. Does minimal admission-context binding (§3C) record enough to keep history honest
   at cutover without the registry?
6. Is the current `nq-store` boundary already a narrow NQ-operations API, or is SQL
   scattered such that the storage contract (§4) needs a refactor before its
   obligations can be proved?

## 8. Ratification delta (authoritative)

Frozen 2026-07-17 after two independent adversarial passes against provisional plan
hash `c51511db…50db`, reconciled by Opus. Where a workstream paragraph and this
section disagree, this section governs.

**Reviews of record.** Fable (in-thread model toggle; re-read the load-bearing code
first-hand) and codex (`gpt-5.5`, read-only, separate process). Verdicts overlapped
heavily; every disagreement is pinned to specific lines.

| CP | Fable | codex | Ratified disposition |
|----|-------|-------|----------------------|
| 1 identity closure | amend | amend | **Amend** — closure transitive + fail-closed; name the source set; detector semantics get a *separate* id from profile/admission (`>=2.0` is detector, not profile). |
| 2 helper enforcement | amend | amend | **Amend — align, don't rebuild.** Parent-side custody largely exists; fix packaged-helper conformance, add packaged-bytes test, KEEP the inline fault injector, actually exercise `SO_PEERCRED` (wrong PID/UID/GID), give cleanup an absence postcondition. |
| 3 witness.v0 deferral | amend | reject-deferral | **Split** — defer the v0 *standing* reconciliation (opposing philosophies); fix-or-disclaim the intra-v1 child-subject wire/admission mismatch and pin the v1 schema id **in beta**. |
| 4 beta line | accept | amend | **Amend** — real cross-version migration is *not* a beta blocker (v1 has no predecessor); exact-version refusal + WAL-consistent backup + atomicity are. Portable logical export **deferred** (operator decision below). |
| 5 admission context | amend | amend | **Amend (codex superset)** — not a new column; close nullable `admission_id`, add the new semantic-identity fields, record admission vs detector/evaluation identities separately, mark legacy rows context-incomplete, preserve the atomic transaction. |
| 6 store boundary | accept | accept | **Accept** — SQL is contained; obligations are additive. Constraint: do not split the atomic run+submission+report+observations commit. |

**Self-corrections (the choreography working):**
- Fable withdrew the `remaining()==0 → timeout 0` claim after codex flagged it stale
  (`run-noble-qemu.sh:103` refuses at expiry). Provenance: the first exploration pass
  misread it, the provisional inherited it, Fable repeated it, codex caught it.
- The provisional's loopback fix (drop the unit-file flag) was wrong; codex showed the
  default binds unconditionally (`daemon.rs:22, 68-96`). Corrected in §4 workstream 3.

**Operator decision — portable export:** *Deferred past beta.* A sealed cold archive
(SQLite DB + WAL-consistent backup + exact binary + config + schema + manifests +
hashes + frozen alpha tooling) is sufficient to make the §6 replacement honest.
Canonical logical export is named for post-beta, not built now.

**Minor, fold into WS1:** `build_finding_event` ignores `_detector_digest`
(`engine.rs:1939`) while continuity logic compares digests elsewhere — clean up at the
identity seam being reworked.

**No structural insufficiency found by either pass. No further review gate before
implementation.**
