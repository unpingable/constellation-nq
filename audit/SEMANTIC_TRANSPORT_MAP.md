# Governed-result transport map

Status: **repair implemented; clean-pinned audit pending** (2026-07-20).

This map preserves the pre-repair failure record and describes the current
canonical transport chain. It follows existing refusal-preservation policy;
it does not create new refusal doctrine. Matching numeric or status codes are
indexes and control-flow inputs only, never substitutes for dependent typed
testimony.

## Preserved pre-repair observations

At source revision `df075c8ff4d08ea69148786a45c55a2da7b2db2c`, each
historical release-forcing command below exited 101. They were then ignored
expected-product-defect demonstrations:

```text
cargo test --offline -p nq-core engine::tests::forcing_exchange_timeout_phase_survives_dry_and_status_surfaces -- --ignored --exact
cargo test --offline -p nq-core engine::tests::forcing_protocol_refusal_dependent_fields_survive_collection_status -- --ignored --exact
cargo test --offline -p nq-core engine::tests::forcing_profile_refusal_identity_survives_collection_status -- --ignored --exact
cargo test --offline -p nq-store tests::forcing_rejected_submission_requires_typed_refusal -- --ignored --exact
```

The exact failed observations were:

- exchange timeout: `write_detail=None` and `read_detail=None`; both dry
  diagnostics were `helper protocol failure: dry collection acquisition
  outcome timeout`; both status documents had `code="timeout"` and
  `detail=null`;
- helper refusal: retriable/EAGAIN and non-retriable/ENODEV became byte-identical
  `CollectionOutcome::HelperRefused` documents containing only boundary, code,
  and message;
- profile refusal: different profile identities, boundaries, and details became
  byte-identical generic rejection documents containing only plane, code, and
  message;
- rejected custody: `SubmissionDisposition::Rejected { refusal: None }`
  returned a successful collection receipt instead of an invariant error.

The helper-protocol wire pair already passed at that revision. The original
helper response v1 object was not the lossy boundary.

## Repaired canonical source types

```text
runner / helper / profile / admission / detector source
                         |
                         v
 AcquisitionFailure | GovernedRefusal | AdmissionRefusal
                         |
              +----------+----------+
              |                     |
              v                     v
 CollectionOutcome          EvaluationEnvelopeV2
 v1 non-admitted /          nq.evaluation_envelope.v2
 v2 admitted                         |
                                      v
                              EvaluationResultV1
                              nq.evaluation_result.v1
```

The governing carrier is now `engine::CollectionOutcome`, with an explicit
schema identity, responsible instance, optional run identity, and a closed
`CollectionResult` variant. It does not store a display string as the primary
result.

- `AcquisitionFailure` contains the complete authoritative
  `runner::AcquisitionOutcome`, plus checked `class` and `retry` projections.
  `ExchangeTimeout { phase }` therefore survives. When acquisition does not
  prove retryability, the canonical value is `unspecified`; no message-based
  inference is made.
- `GovernedRefusal` (`nq.governed_refusal.v1`) contains a stable refusal ID and
  a closed origin variant. Acquisition, typed protocol rejection, complete
  `nq_protocol::Refusal`, and complete `nq_profiles::ProfileRefusal` are distinct
  variants.
- `AdmissionRefusal` carries its responsible instance, typed boundary, typed
  code, and closed dependent details. A nested governed refusal or acquisition
  failure stays exact.
- `EvaluationEnvelopeV2` is the canonical persisted outer evaluation object.
  It binds the stable evaluation ID, optional triggering run, responsible
  instance, subject, full scope and vantage, exact detector identity,
  evaluator artifact digest, compiled profile identity, times, and
  instance-qualified watermark to its inner `EvaluationResultV1`.
  `CannotEvaluate` requires exactly one profile-origin `GovernedRefusal`;
  successful evaluations forbid one.
- `CollectionOutcome` retains V1 for non-admitted results. A newly admitted
  result is V2 and embeds the exact ordered `EvaluationEnvelopeV2` values
  committed for that run; an admitted result cannot be relabeled V1.

Serialization uses explicit nested result/origin tags, denies unknown fields,
and validates identity and projection agreement after decode. Omitted,
duplicate, unknown, defaulted, or mismatched mandatory fields are refused.

## End-to-end transport and conversion map

| Family | Origin and conversion functions | Store / serialized form | Outward consumers | Historical erasure and current repair |
|---|---|---|---|---|
| Persistent exchange timeout | `UnixIoPhase` -> `UnixAcquisitionOutcome::Timeout { phase }` -> `engine::unix_acquisition_outcome` -> `AcquisitionOutcome::ExchangeTimeout { phase }` -> `AcquisitionFailure::from_outcome` -> `CollectionOutcome::acquisition_failed` | Full run resource outcome plus canonical non-admitted `nq.collection_outcome.v1` in `status_events.detail_json`; `watcher_runs.acquisition_outcome="timeout"` remains an index. | `EngineError::AcquisitionFailed` for dry watcher; status V3, API, CLI, daemon canonical JSON log, backup, and archive for normal status. | `acquisition_detail` formerly returned `None`. It is no longer a testimonial adapter; all consumers receive the exact `AcquisitionFailure.outcome`. |
| Retained acquisition rejection | non-response acquisition with retained bytes -> `rejected_transport_submission` -> `AcquisitionRefusal` -> `GovernedRefusal::acquisition` | Rejected submission must carry the canonical refusal; stable refusal ID links status and custody. | Typed refusal export/status/API/CLI/archive. | Retained rejection and no-custody failure are now distinct typed paths; neither is reconstructed from `acquisition_code`. |
| Helper refusal | helper `Refusal` -> `HelperResponse::refusal` -> canonical NDJSON -> `parse_response` -> `ResponseOutcome::Refusal` -> `GovernedRefusal::helper` | One canonical governed refusal supplies `RefusalInput.detail`, stable ID, boundary/code projections, and the outward collection result. | Normal collection, dry watcher `EngineError::GovernedRefusal`, status V3, daemon log, API, CLI/refusal export, backup, archive. | The old normal adapter dropped `retriable`, details, ID, and origin; dry exchange converted all fields to text. Both now transport the same complete refusal object. |
| Invalid helper response | `parse_response` error -> `protocol_rejection` -> structured JSON/framing/validation/canonicalization mirror -> `GovernedRefusal::protocol` | Raw bytes remain in rejected custody; canonical typed rejection and stable ID are linked. | Same governed-result surfaces as helper refusal. | Generic `invalid_response` remains only a projection. Structured failure facts are not recreated downstream. |
| Profile refusal | `ProfileModule::validate`, the real host detector, or `profile_normalization_refusal` -> complete `ProfileRefusal` -> `GovernedRefusal::profile` | Canonical refusal detail plus exact run/submission/profile linkage; same object embedded in collection or evaluation testimony. | Normal collection, dry watcher, status V3, daemon log, API, CLI/refusal and evaluation export, backup, archive. | The old generic rejection dropped profile identity, boundary, details, and ID. Real host-detector paths now supply stable structured dependent facts, and the authoritative profile object crosses the first adapter intact. |
| Admission refusal | admission/binding/conformance error -> `admission_refusal` or `admission_refusal_from_engine` -> `AdmissionRefusal` -> `CollectionOutcome::admission_refused` | Canonical pre-run collection result; `run_id` must be absent and responsible instance must agree. | Status V3/API/CLI; nested upstream refusal remains typed. | The former generic diagnostic-only outcome is replaced with boundary/code/dependent-detail structure. |
| Rejected custody | `SubmissionDisposition::Rejected { refusal: RefusalInput }` -> `validate_collection` -> `commit_non_success_collection` | One transaction writes `raw_submissions`, exactly one `refusals` row linked by submission/run and stable refusal ID, and the run-linked canonical status result. `Store::rejected_custody_*` reads the association directly. | `rejected_custody_snapshot`, status V3 linked-refusal check, `/v1/rejected-custody`, `nq refusals export`, backup, archive. | Refusal is mandatory for new typed writes. Validation rejects zero, duplicate, admitted-row, projection, identity, profile, or canonical-detail mismatch. No log/neighbor-row reconstruction exists. |
| Detector/evaluation refusal | `DetectorResult` -> `GovernedRefusal::profile` -> `governed_evaluation_result` -> `EvaluationResultV1` -> `EvaluationEnvelopeV2`; envelope validation requires the detector producer's exact `Detector`/`CannotEvaluate` boundary/code, message/summary equality, and empty affirmative evidence. | Schema-v3 `evaluation_runs.detail_json` stores the complete envelope and projects its append sequence, trigger run, context, detector, evaluator artifact, profile, time, outcome, watermark, and refusal linkage into checked columns/rows. The V2 carrier sequence must equal ascending durable `evaluation_sequence`; reopen never sorts both sides into a merely equal set. A finding event may copy only the identical canonical refusal and retains the prior condition under refused visibility. | `StatusSnapshotV3`, `/v3/status`, `/v1/evaluations`, `nq evaluations export`, `public_finding_snapshot_v3`, `/v3/findings`, CLI/console, verified backup, and cold archive. `/v2/status` returns 409 when governed evaluations exist; `/v2/findings` likewise requires V3. | The evaluation profile binding was formerly memory-only and first-ever `CannotEvaluate` had no outward carrier because the no-finding law correctly forbids fabricating a finding. The V2 envelope plus authoritative evaluation status/history now preserves that result without changing the no-finding law; substituted refusal semantics or coherently reordered persisted rows fail closed. |

Final boundary review found one additional in-repair erasure point:
`evaluate_instance` selected exact profile/subject/scope/vantage rows for the
detector and watermark, but then passed the whole same-instance snapshot to
`build_finding_event`. A newer report from another boundary could therefore
alter finding visibility or retained-evidence resolution while disagreeing
with the canonical envelope. `evaluation_context_rows` now produces one owned
exact-context carrier used by reconstruction, watermarking, and finding
construction; a hostile different-scope regression proves the foreign row is
excluded.

The three original outward-result defects shared the lossy
`CollectionOutcome`/dry-error adapter and are repaired there. Rejected custody
required the additional store linkage repair. Exact detector evaluation
identity required the schema-v3 persisted `EvaluationEnvelopeV2`, V3 status,
the frozen evaluation-history read model, and the V3 finding projection so
later surfaces could consume, rather than reconstruct, the semantic binding.

## Store to surface chain

Normal current status follows one canonical path:

```text
CollectionOutcome
  -> admitted: Store::commit_admitted_collection
       [run + custody + report + EvaluationEnvelopeV2/finding rows
        + exact run-linked status] in one SQLite transaction
  -> non-success: Store::commit_non_success_collection
       [run + optional rejected custody/refusal + exact run-linked status]
       in one SQLite transaction
  -> status_events.detail_json (append-only, exact run link)
  -> status_snapshot_v3 / status_from_row_v3 / status_component_v2
       -> decode_collection_outcome
       -> validate coarse state/code projection
       -> for Rejected: resolve refusal_id in rejected custody
       -> require exact run + instance + GovernedRefusal equality
  -> daemon/API/CLI/console DTO serialization
```

The admitted builder runs only after SQLite has assigned the report sequence,
inside the still-uncommitted transaction. Evaluation watermarks can therefore
name the real report occurrence without predicting a global counter. The store
compares the V2 result's report projections and canonical evaluation set to the
rows being committed before making any part visible. It also recomputes the
unique detector-suite digest and checks every evaluator artifact against the
originating admission. `Store::validate` repeats those checks on reopen. A late
status insertion failure rolls back the run, custody, report, evaluations,
refusals, and findings together; every completed run requires one run-linked
result, and coherent carrier-and-row omission, duplication, extension, or
evaluator substitution fails closed rather than inheriting a pass from
adjacent rows.

The daemon uses `canonical_result_document` over the complete result rather
than Rust debug text. Both that daemon field and `nq --json collect` now cross
one application protocol boundary:
`CollectionOutcomeFrame::encode` -> `nq_protocol::encode_ndjson` ->
`decode_collection_outcome_ndjson`. The strict decoder reopens the canonical
one-record frame and checks typed equality before the daemon strips only the
framing LF or the CLI writes the exact NDJSON bytes. Human-readable `nq
collect` is rendered from that reopened object, not independently from the
engine value. `/v3/status`, the console, and `nq status export` use
`StatusSnapshotV3`. V3 captures a stable status/evaluation boundary, retains
all ordinary status rows, and adds the latest exact `EvaluationEnvelopeV2` for
each complete semantic evaluation lineage. `/v2/status` remains a compatibility
DTO for stores with no evaluations and returns 409 with `/v3/status` as the
required endpoint when governed evaluation history exists. `/v1/status` does
not reinterpret typed collection or evaluation results. A dry watcher failure
uses `nq.watcher_action_error.v1` with the same governed refusal or acquisition
failure rather than a string reconstruction.

Rejected-custody testimony follows a parallel exact-link path:

```text
GovernedRefusal
  -> RefusalInput (same refusal_id, canonical complete document)
  -> raw_submissions + refusals exact-one association
  -> Store::rejected_custody_bounded / rejected_custody_by_refusal_id
  -> rejected_custody_snapshot (typed decode + projection checks)
  -> API / CLI / archive reopen
```

Detector refusal testimony follows the same identity discipline:

```text
DetectorResult + compiled EvaluationProfileIdentity
  -> EvaluationResultV1 + the same GovernedRefusal
  -> EvaluationEnvelopeV2 (context + detector + evaluator + time + watermark)
  -> evaluation_runs + watermarks + exactly one evaluation-linked refusals row
  -> optional finding event with byte-identical refusal and immutable lineage
  +-> StatusSnapshotV3 / /v3/status / CLI status / console
  +-> EvaluationHistoryPageV1 / /v1/evaluations / `nq evaluations export`
  +-> public_finding_snapshot_v3 when a finding lawfully exists
  -> backup / immutable archive reopen
```

`build_finding_event` intentionally creates no finding for a first-ever
`CannotEvaluate`; missing testimony cannot create either absence or a
condition. That result remains authoritative through the evaluation component
and immutable history above. The history uses the store-wide monotone
`evaluation_sequence`; callers freeze a logical snapshot at
`through_sequence` and page with exclusive `after_sequence`, so rows beyond
the 1,000-record maximum page cannot disappear silently.

## Persisted, wire, and read-model versions

The physical SQLite schema is explicitly version 3. It adds the associations
and projections the old representation could not prove: run-linked status;
context-bound admitted judgments; exact report materialization; store-wide
evaluation sequence and optional trigger run; full detector, evaluator,
profile, time, watermark, and canonical-envelope persistence; exclusive
custody-versus-evaluation refusal association; and the V3 finding view. It
also makes every completed run/result association, exact detector-suite and
evaluator-artifact closure,
the admitted report/evaluation/status closure, admitted run/evaluation
membership, and evaluation/refusal cardinality fail closed.

There is no inference-based migration. `Store::open` refuses old version-1 and
version-2 files before any persistent PRAGMA, and a file-backed regression
proves refused bytes remain unchanged. Old history may be preserved or backed
up as incompatible data, but is not silently rewritten into context,
evaluation identity, or typed linkage it never recorded.

Independent transported schemas are explicit:

| Schema | Purpose | Compatibility treatment |
|---|---|---|
| `nq.helper.response.v1` | Existing helper request/response wire | Unchanged; already preserves the complete helper refusal. |
| `nq.governed_refusal.v1` | Stable typed refusal and origin | New strict carrier; no unversioned fallback. |
| `nq.collection_outcome.v1` | Canonical non-admitted collection result | Strict carrier for admission refusal, acquisition failure, and rejected custody. |
| `nq.collection_outcome.v2` | Canonical admitted collection result | Requires the exact ordered set of committed `EvaluationEnvelopeV2` values for its triggering run; cannot be relabeled V1. |
| `nq.run_resource_outcome.v1` | Exact watcher acquisition/resource testimony | Strict persisted envelope; timeout phase and every dependent acquisition field are reopened before use. |
| `nq.evaluation_result.v1` | Governed detector-owned result inside the outer envelope | Preserves detector state, profile identity, evidence, limitation, watermark, and refusal payload. |
| `nq.evaluation_envelope.v2` | Canonical persisted evaluation | Binds the inner result to evaluation/run/context/detector/evaluator/time/watermark identity; all SQL columns are checked projections. |
| `nq.status_snapshot.v3` | Current typed status DTO | Adds authoritative latest evaluation components selected from exhaustively reopened immutable history. |
| `nq.status_snapshot.v2` | Collection-only compatibility DTO | Explicitly refuses when evaluation history exists and directs consumers to V3. |
| `nq.evaluation_history.v1` | Bounded immutable evaluation history | Uses monotone `evaluation_sequence` plus frozen `through_sequence` and exclusive `after_sequence`; no silent maximum-page truncation. |
| `nq.finding_snapshot.v3` | Finding, visibility refusal, and exact profile semantic identity | New endpoint/read model; `/v2/findings` returns an explicit 409 requiring V3. |
| `nq.rejected_custody.v1` | Bounded rejected-custody testimony | Exact linked refusal, run, profile, and raw digest. |
| `nq.watcher_action_error.v1` | Structured dry-watcher failure | Exact governed refusal or acquisition failure. |
| `nq.cold_archive.v1` | Sealed historical bundle | Format identity unchanged; semantic verification is strengthened. |

Historical version-1 and version-2 databases/rows are not rewritten into facts
they never stored. A
bare or ambiguous rejected-custody row remains preserved historical data but
cannot open as a current version-3 store. Within version 3, an unversioned or
substituted canonical result similarly fails exhaustive semantic reopening; a
newer current row cannot hide it.

## Backup, archive, and exhaustive reopening

SQLite backup uses the online backup API and reopens the result. Cold archive
creation seals that verified copy and the verifier binary. Archive verification
then opens the archived database itself and performs all of the following:

1. `Store::validate` checks physical/schema and exact-one refusal invariants,
   calls `validate_run_results` so every completed run has one canonical
   result, and calls `validate_admitted_evaluation_closures` so every admitted
   trigger set reproduces its admission's exact
   `detector_suite_identity_digest` and evaluator artifact. `insert_evaluation`
   enforces the evaluator binding on write; core independently repeats the
   profile-suite and evidence checks in `validate_run_profile_identity` and
   `validate_evaluation_watermarks_and_evidence`.
2. `validate_admitted_report_history` reopens every admitted judgment and its
   exact observations, coverage, errors, checkpoint, run, admission context,
   and triggering evaluation set.
3. `validate_watcher_run_history` pages every versioned acquisition/resource
   envelope and proves its coarse SQL projection and atomic result link.
4. `validate_status_history_v2` pages through every immutable status event,
   not merely `status_current`.
5. `validate_rejected_custody_history` pages through every rejected submission,
   not merely a bounded operator snapshot.
6. `validate_evaluation_refusal_history` pages every evaluation and compares
   the complete `EvaluationEnvelopeV2`, SQL projections, refusal row, and
   optional finding copy.
7. `status_snapshot_v3` and every frozen page of
   `evaluation_history_bounded` are reopened; their total must equal the
   exhaustive evaluation count.
8. Each typed refusal/result is decoded from canonical stored bytes and checked
   against stable SQL projections and associations.
9. The verification report records exact admitted-report, status, custody, and
   evaluation counts.

Archive inventory is exact rather than open-ended: all required content files
must be present once in canonical order, control files and parent directories
must have the required non-symlink types, and no extra entry is accepted. The
archived verifier digest must equal both sealed metadata and the currently
executing verifier. Schema/version metadata is checked as a projection of that
verifier. The database copy is checkpointed before sealing and opened through
SQLite immutable mode; repeated verification and preserved-binary read-only
exports must leave every sealed byte and path unchanged.

Thus a newer valid status cannot hide an older unversioned or substituted
event, and a resealed archive with a mismatched refusal document fails semantic
verification even if generic SQLite integrity and archive digests pass.

## Direct regression and mutation bindings

The original four release-forcing names are retained but are ordinary passing
regressions after the product repair; no `--ignored` flag remains in current
evidence commands. Direct additional tests exercise:

- helper-protocol same-code wire round trip;
- core carrier construction, strict encode/decode, same-code timeout/helper/
  protocol-rejection/profile/admission pairs, actual collection, status
  storage, backup/reopen, exhaustive watcher/status/custody/evaluation history,
  and refusal-ID or profile-semantic substitution;
- store exact-one linkage, same-code helper payload backup/reopen, duplicate
  association, evaluation/finding lineage, projection mismatch, immutable-open,
  and canonical-detail failures;
- application-level canonical collection-result framing, strict production
  reopening, exact structured CLI output, and daemon canonical result logging;
- V3 status/evaluation/finding HTTP APIs, frozen sequence paging, and explicit
  older-route incompatibility behavior;
- shipped structured CLI status/evaluation/refusal/dry-watcher modes;
- actual host detector same-code refusals through the governed envelope,
  schema-v3 store, V3 status, verified backup, and reopen, plus a hostile
  newer same-instance/different-boundary row proving finding visibility and
  retained evidence use only the exact evaluation context;
- cold archive creation, exact inventory and verifier identity, non-mutating
  repeated verification, preserved-binary rendering, exhaustive reopen, and
  hostile resealed-history failures.

`admissibility.toml` binds these actual entry points. Its `delete-detail`
mutation is designed to compile while replacing phase-specific exchange timeouts with the
coarse timeout variant; the timeout pair assertion must fail. Its
`recompute-from-code` mutation is designed to compile while storing a code-derived status
document instead of the canonical result; the status reopen assertion must
fail. A new clean-pinned ledger must execute both. No outcome is inherited from
the authoritative old r4 receipt or its earlier r3 attempt.

## Qualification boundary

The current repair map is implementation evidence, not mint evidence. The old
candidate SHA-256
`44e7bd1af43ac4d6f9543d2dc286610be43d86426334ca24ff1a05a45d24e2e0`
remains blocked. Its external run `run-2026-07-20-06aa918` remains
cryptographically intact but insufficiently sealed because mandatory
`guest-results/RESULT` was omitted from the manifest; it is not corrupt and is
not mint-sufficient. Until the product source is committed and clean-pinned,
all direct tests pass, both mutations bite, the release package is rebuilt to
different bytes, and a fresh corrected VM qualification passes, the release
verdict remains **BLOCKED** with no waiver and no inherited pass.
