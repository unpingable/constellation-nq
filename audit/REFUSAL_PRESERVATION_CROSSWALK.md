# Refusal-preservation crosswalk

Status: **repair implemented; clean-pinned audit pending** (2026-07-20).

This is the target-owned complement to `admissibility.toml`. It derives its
scope from `docs/HARDENING_PROGRAM.md` section 8 and the existing invariant
that refusals retain the exact responsible instance and boundary. It does not
add product doctrine. Matching codes remain non-testimonial indexes; exact
typed payloads and associations are the testimony.

This status is deliberately narrower than a release verdict. The repair is
present in current source, but no new package identity, clean-pinned AC-R4
ledger, or fresh VM qualification is claimed here.

## Historical bound object and governing control

The failed candidate-specific audit remains immutable:

- old package: `dist/nq-ng_0.1.0_amd64.deb`;
- old package SHA-256:
  `44e7bd1af43ac4d6f9543d2dc286610be43d86426334ca24ff1a05a45d24e2e0`;
- packaged source commit: `06aa918b7b51cf165070d53215ee4e943192102e`;
- authoritative clean-pinned blocked target and qualification-repair commit:
  `d82cf574b16cf4ff1d21ab5adda4b2b275f35069`;
- receipt-recording commit:
  `df075c8ff4d08ea69148786a45c55a2da7b2db2c`;
- old external run: `run-2026-07-20-06aa918`, cryptographically intact but
  insufficiently sealed because mandatory `guest-results/RESULT` was outside
  its seal; it is not corrupt and is not mint-sufficient;
- authoritative old AC-R4 receipt:
  `audit/receipts/run-2026-07-20-qualification-repair-r4/RECEIPT.md`, with
  ledger at
  `audit/receipts/run-2026-07-20-qualification-repair-r4/refusal-audit` and
  verdict fail at clean target pin
  `d82cf574b16cf4ff1d21ab5adda4b2b275f35069`, with no waiver or obstruction.
  The r3 receipt remains the earlier dirty/pre-commit attempt, not the
  authoritative campaign verdict.

The r4 receipt retains its own historical verifier and control identities
without reinterpretation. The current external inputs measured for the pending
r5 execution are:

- verifier: `/home/jbeck/git/audit/target/debug/admissibility-audit`, SHA-256
  `4cef41d898e4ad770196a5709d1bcbcc5bd6757a3c63938f53824363aa68ede9`;
- AC-R4 control:
  `/home/jbeck/git/audit/controls/v14/rung4-refusal-preservation.toml`, SHA-256
  `4d130b594a0804c2f8607638feff940167ed741939fcf96bc64e11a04a43e460`;
- control baseline: `/home/jbeck/git/audit/controls/v14/BASELINE.toml`, SHA-256
  `a28c44cab85f22264f713084f91a700bbae196b047f777dfbd898578dbe5a7f9`;
- formal baseline: Lean release `14.0.0`, revision
  `ff491b808ebeab2a132d9ade46d234cf85dcfbe9`, tree
  `72cba07e35588e9f67c252b0bd92cf0523ab178f`.

AC-R4 requires same-code/different-payload refusals to remain distinguishable
on every testimonial surface, every coarse projection to be classified, and
stored detail to be rendered rather than reconstructed from a code. The Lean
law is specification evidence only; it does not prove this runtime mapping,
serialization, persistence, or archive behavior.

This dependency is explicitly **release-required**. It is neither a
qualification-only check nor merely archival provenance, so a rebuilt package
cannot proceed to mint ratification without a fresh passing closure receipt.

## Canonical transport objects

The repair introduces one shared semantic spine rather than per-surface
reconstruction:

- `engine::CollectionOutcome` is the exact collection-result envelope.
  `nq.collection_outcome.v1` remains the non-admitted carrier;
  `nq.collection_outcome.v2` is required for admitted results and embeds the
  exact ordered `EvaluationEnvelopeV2` set committed for the triggering run.
- `engine::AcquisitionFailure` pairs the complete `AcquisitionOutcome` with a
  checked coarse class and a retry disposition. When the source does not prove
  retryability, the value is explicitly `unspecified`; it is never guessed
  from a message.
- `nq.governed_refusal.v1` / `engine::GovernedRefusal` carries one stable
  refusal ID and an exact acquisition, protocol, helper, or profile origin.
  Helper and profile variants embed their authoritative source objects.
- `engine::AdmissionRefusal` retains a typed boundary, code, responsible
  instance, and a closed dependent-detail variant before a run exists.
- `nq.status_snapshot.v3` embeds the canonical collection result for each
  instance and the latest exact evaluation in every complete semantic lineage.
  State and code remain checked projections, not substitutes. V2 refuses when
  governed evaluation history exists.
- `nq.rejected_custody.v1` exposes a rejected submission together with the
  exact linked `GovernedRefusal` and originating run/profile identity.
- `nq.watcher_action_error.v1` exposes dry-watcher governed refusals or exact
  acquisition failures without converting them to generic process text.
- `nq.run_resource_outcome.v1` persists the exact acquisition testimony for
  every watcher run, independently of its coarse SQL outcome index.
- `nq.evaluation_envelope.v2` is the canonical persisted evaluation object. It
  binds evaluation and optional triggering-run identity, responsible instance,
  subject, full scope and vantage, detector and evaluator identities, profile,
  times, and instance-qualified watermark around `EvaluationResultV1`. The
  same refusal may reach a finding only byte-for-byte.
- `nq.evaluation_history.v1` exposes immutable envelopes in monotone
  `evaluation_sequence` order with a frozen inclusive `through_sequence` and
  exclusive `after_sequence`; `nq evaluations export` and `/v1/evaluations`
  share that read model.
- `nq.finding_snapshot.v3` exposes the exact profile semantic identity and the
  typed visibility refusal. The older V2 route fails explicitly rather than
  presenting a representation that cannot carry those fields.

All new nested result and refusal representations deny unknown fields, require
mandatory dependent fields, use explicit tagged variants, and validate
cross-field projections after decode. The helper request/response wire remains
`nq.helper.response.v1`; it was already lossless and is not silently revised.

## Family and surface matrix

| Family | Stable source and canonical carrier | Persistence and historical reopening | Outward surfaces | Repair status |
|---|---|---|---|---|
| Exchange/acquisition failure | `runner::AcquisitionOutcome` becomes `AcquisitionFailure { class, retry, outcome }`; `ExchangeTimeout { phase }` remains inside `outcome`. | The complete run resource document and canonical `CollectionOutcome` are stored. `watcher_runs.acquisition_outcome` is only an index. Status backup/reopen decodes the exact carrier and revalidates class/retry. | Dry watcher errors, status V3, API, CLI, daemon canonical log, backup, and archive consume the same typed value. | **Repaired in source.** `write_request` and `read_response` remain different despite the same outward code. |
| Helper refusal | `nq_protocol::Refusal` is embedded unchanged in `GovernedRefusalOrigin::Helper`, alongside an NQ-owned refusal ID. | `SubmissionDisposition::Rejected` requires the same refusal at commit. `refusals.detail_json` stores canonical `GovernedRefusal`; rejected-custody reopening checks ID, origin, run, instance, profile, boundary, code, and canonical bytes. | Normal collection, dry watcher, status V3, refusal export, API, CLI, daemon log, and archive expose `retriable` and structured `details` directly. | **Repaired in source.** Retriable EAGAIN and non-retriable ENODEV pairs remain distinct. |
| Protocol response rejection | Framing, JSON category/location, validation variant, and canonicalization failure are mirrored by closed typed protocol-rejection variants inside `GovernedRefusal`. | The canonical refusal is linked to retained raw response custody. | The same governed refusal reaches status/API/CLI/archive; no generic `invalid_response` string is treated as the testimony. | **Repaired in source.** Coarse `invalid_response` remains an index only. |
| Profile refusal | The complete `nq_profiles::ProfileRefusal` is embedded in `GovernedRefusalOrigin::Profile`; strict decoding requires profile identity, boundary, code, message, and structured details. The real host detector emits stable dependent facts for missing testimony, profile mismatch, coverage, projection, and freshness refusals. | Canonical refusal detail is linked to the exact run/submission/profile or evaluation envelope. Reopening compares the embedded value to every duplicated projection. | Status V3, refusal/evaluation export, API, CLI, daemon log, backup, and archive consume the canonical value. | **Repaired in source.** Same-code missing-testimony and stale host-detector refusals retain distinct structured details, as do different profile boundaries. |
| Admission verification | `AdmissionError` is converted once to `AdmissionRefusal { responsible_instance_id, boundary, code, details }`. Nested upstream acquisition or governed refusals remain typed. | Admission refusal status stores the canonical `CollectionOutcome`; no run identity is fabricated for a pre-run refusal. | Status/API/CLI decode the same typed result. Local failures that have no richer committed source type retain a bounded diagnostic only inside a closed typed refusal variant. | **Repaired in source; clean-pinned evidence pending.** |
| Rejected custody | New writers must supply `SubmissionDisposition::Rejected { refusal: RefusalInput }`; the rejection code is derived from that refusal. | Validation requires exactly one linked refusal and rejects zero, duplicate, admitted-row, run/instance/profile/code, or noncanonical-detail mismatches. Bounded and paged readers expose stable refusal identity. | Status V3 reopening resolves the embedded refusal ID and demands exact equality with custody. Refusal export, API, CLI, backup, and archive do not reconstruct from adjacent rows or logs. | **Repaired in source.** A bare rejected-custody row is historical incompatible data, not a synthetic typed refusal. |
| Detector/evaluation refusal | `DetectorState::CannotEvaluate` becomes `EvaluationResultV1` inside the exact `EvaluationEnvelopeV2`, with the same profile-origin `GovernedRefusal` used at the finding boundary when a finding already exists. Envelope validation closes the detector producer law: boundary `Detector`, code `CannotEvaluate`, refusal message equal to the result summary, and no affirmative evidence. | Schema-v3 evaluation rows persist and validate the complete envelope, append sequence, trigger-run membership, full context, detector/evaluator identity, profile identity, times, watermarks, and refusal. A collection-triggered sequence commits atomically with its report and exact V2 run result. Reopening compares the carrier directly with ascending durable `evaluation_sequence`, requires every completed run result, recomputes the trigger set's sorted detector-suite digest against the admission, rejects duplicate detector execution, and requires the admission's exact evaluator artifact. Thus coherent carrier-and-row omission, extension, reorder, or substitution fails closed. Finding copies must be byte-identical and cannot open/resolve/substitute a condition. | V3 status, `/v1/evaluations`, `nq evaluations export`, V3 findings when one lawfully exists, backup, and archive expose the exact envelope/refusal. `/v2/status` and `/v2/findings` explicitly require V3 when needed. | **Repaired in source.** First-ever `CannotEvaluate` creates no finding but remains visible in the authoritative evaluation component/history. Same-code, different-scope/refusal payloads remain distinct. |
| Status code | `status_events.code` is paired with canonical detail. `status_component_v2` decodes collection rows, checks component identity, recomputes only the coarse state/code projection, and for rejected results verifies exact linked custody. | `status_events` remains append-only. `validate_status_history_v2` pages through every immutable event, while `status_snapshot_v3` freezes and exhaustively reopens evaluation history before selecting current evaluation components. | `/v3/status`, structured CLI status, console, and archive use V3. `/v2/status` returns 409 when evaluations exist; `/v1/status` does not reinterpret governed collection or evaluation results. | **Repaired in source.** Carrier testimony comes from stored detail, never from code. |
| Cold archive | The archive seals a checkpointed database copy, exact verifier binary, interpretation config, and a canonical exact-coverage content manifest. | Verification uses SQLite immutable mode, exhaustively pages admitted-report, watcher, status, custody, and evaluation history, invokes V3 status and every frozen public evaluation page, and leaves the complete sealed inventory byte-identical. Metadata schema/tool projections and archived binary digest must match the executing preserved verifier; symlinked, omitted, substituted, duplicate, or extra content refuses. | The preserved executable uses read-only status, evaluation, finding, and refusal exports from the preserved database with no live store or archive mutation. | **Repaired in source.** Integrity alone does not imply authority; incompatible history fails closed and a hostile reseal cannot substitute verifier identity or suppress mandatory content. |
| Success/control-flow projection | `CollectionOutcome::is_success()` reads the complete typed result. | The boolean is not persisted as testimony. | Scheduler cadence and exit selection may use it only after the full result is retained/rendered. | Classified non-testimonial. |
| Coarse SQL and serde projections | `watcher_runs.acquisition_outcome`, `refusals.source_kind`, `raw_submissions.rejection_code`, `status_events.code`, binding kind/reason fields, and tagged-union discriminants remain linked to canonical payloads. | Exact detail and associations are mandatory where the projection is testimonial context. | Allowed for bounded indexing, stable comparison, grouping, or tagged-union selection only. | Classified non-testimonial/internal; forbidden as standalone diagnosis or qualification evidence. |
| Historical verification refusal | Typed verification errors remain read-only and never rewrite stored decisions. | Historical bytes are preserved; unsupported or unprovable meaning refuses current semantic reopening. | No candidate-facing CLI/API authority upgrade is introduced. | Existing implementation boundary retained. |
| System-cut coherence refusal | `nq-system-contract::CutCoherenceRefusal` remains typed in its separate crate. | Its own tests cover that workspace object. | `nq-app`/`nq-core` do not silently project it into this runtime cone. | Crate separation preserved; not reopened here. |

## Schema and historical-data treatment

The physical SQLite schema is explicitly version 3. Earlier columns could
retain some canonical JSON, but they could not prove every required relation.
Version 3 binds admissions and admitted judgments to their recomputable
contexts, persists exact admitted-report materialization, and adds the
store-wide evaluation sequence, optional triggering run, detector/evaluator
identity, full canonical `EvaluationEnvelopeV2`, watermarks, exclusive
custody-versus-evaluation refusal association, and
`public_finding_snapshot_v3`. New writes atomically commit every completed
run-bearing result. An admitted completion assigns the report sequence and
then commits custody, report, exact evaluation/refusal/finding set, and its V2
run-linked status in one transaction; non-success custody/result remains one
transaction as well. Cannot-evaluate commits its typed refusal and optional
finding copy with its evaluation.

There is deliberately no evidence-inventing upgrade. Version-1 and version-2
databases are refused before any persistent PRAGMA; a file-backed test hashes
the old v2 bytes before and after failed open. They may be copied as
incompatible historical data, but no bare custody row, unversioned result,
missing context, or missing semantic identity is upgraded from a code, log,
adjacent row, or later status. Within version 3, any omitted,
ambiguous, noncanonical, or projection-inconsistent relation prevents semantic
reopening even when a newer current projection is valid.

The JSON/read-model schemas are independently versioned from SQLite and from
the helper protocol. Strict decoding rejects omitted, duplicate, unknown, or
projection-inconsistent fields. V1 is not silently changed into V2, admitted
collection testimony cannot be relabeled V1, and V2 status does not flatten
evaluation testimony; an unrepresentable status directs consumers to V3.
The structured collection CLI and daemon result field share the production
`CollectionOutcomeFrame` boundary: it canonical-NDJSON encodes and strictly
reopens the typed frame before either surface emits it. Human-readable
collection output is rendered only from that reopened object.

## Direct executable correspondence

`admissibility.toml` now binds the actual surfaces rather than reusing one
upstream ignored test as proxy evidence:

```text
# canonical core / protocol carrier
cargo test --offline -p nq-protocol --test conformance_corpus same_code_distinct_refusals_remain_distinct_on_wire -- --exact
cargo test --offline -p nq-core engine::tests::forcing_exchange_timeout_phase_survives_dry_and_status_surfaces -- --exact
cargo test --offline -p nq-core engine::tests::forcing_protocol_refusal_dependent_fields_survive_collection_status -- --exact
cargo test --offline -p nq-core engine::tests::forcing_profile_refusal_identity_survives_collection_status -- --exact
cargo test --offline -p nq-core engine::tests::collect_persists_exact_helper_and_profile_refusals_through_status -- --exact
cargo test --offline -p nq-core engine::tests::status_store_and_backup_preserve_same_code_distinct_detail -- --exact
cargo test --offline -p nq-core engine::tests::status_history_validation_cannot_hide_legacy_event_behind_typed_current -- --exact
cargo test --offline -p nq-core engine::tests::same_refusal_id_with_different_payload_is_rejected_on_status_reopen -- --exact
cargo test --offline -p nq-core engine::tests::same_code_admission_upstream_refusal_pair_survives_status_backup_reopen -- --exact
cargo test --offline -p nq-core engine::tests::same_code_protocol_rejection_pair_survives_wire_custody_status_backup_reopen -- --exact
cargo test --offline -p nq-core engine::tests::hostile_same_profile_borrowed_admission_fails_on_late_reopen -- --exact
cargo test --offline -p nq-core engine::tests::exhaustive_history_pagination_crosses_one_row_pages_and_checks_late_rows -- --exact
cargo test --offline -p nq-core engine::tests::collection_outcome_wire_codec_rejects_omitted_extra_duplicate_and_substituted_fields -- --exact
cargo test --offline -p nq-core engine::tests::public_evaluation_history_crosses_the_maximum_page_without_silent_truncation -- --exact
cargo test --offline -p nq-core engine::tests::real_host_detector_same_code_refusals_survive_governed_store_and_reopen -- --exact
cargo test --offline -p nq-core engine::tests::finding_transport_uses_only_the_exact_evaluation_context_rows -- --exact
cargo test --offline -p nq-profiles --test profile_validation host_detector_same_code_refusals_preserve_distinct_structured_details -- --exact

# storage and backup/reopen
cargo test --offline -p nq-store tests::forcing_rejected_submission_requires_typed_refusal -- --exact
cargo test --offline -p nq-store tests::same_code_refusal_payloads_and_links_survive_backup_and_reopen -- --exact
cargo test --offline -p nq-store tests::refusal_linkage_validation_rejects_duplicate_and_admitted_links -- --exact
cargo test --offline -p nq-store tests::historical_refusal_mismatches_and_noncanonical_detail_fail_closed -- --exact
cargo test --offline -p nq-store tests::admitted_report_evaluations_and_result_rollback_as_one_unit -- --exact
cargo test --offline -p nq-store tests::historical_admitted_report_without_run_result_fails_closed -- --exact
cargo test --offline -p nq-store tests::historical_partial_evaluation_set_cannot_reopen_as_admitted_result -- --exact
cargo test --offline -p nq-store tests::historical_response_run_without_result_fails_closed -- --exact
cargo test --offline -p nq-store tests::admitted_detector_suite_and_evaluator_binding_fail_atomically -- --exact
cargo test --offline -p nq-store tests::historical_reopen_rejects_omitted_admission_detector_suite -- --exact
cargo test --offline -p nq-store tests::historical_reopen_rejects_substituted_admission_evaluator_artifact -- --exact
cargo test --offline -p nq-store tests::historical_reopen_rejects_reordered_admitted_evaluation_sequence -- --exact
cargo test --offline -p nq-store tests::immutable_open_preserves_prepared_archive_bytes_and_file_inventory -- --exact

# detector producer closure
cargo test --offline -p nq-core engine::tests::evaluation_envelope_rejects_substituted_cannot_evaluate_boundary -- --exact
cargo test --offline -p nq-core engine::tests::evaluation_envelope_rejects_substituted_cannot_evaluate_code -- --exact
cargo test --offline -p nq-core engine::tests::evaluation_envelope_rejects_substituted_cannot_evaluate_message -- --exact
cargo test --offline -p nq-core engine::tests::evaluation_envelope_rejects_evidence_on_cannot_evaluate -- --exact

# direct shipped surfaces
cargo test --offline -p nq-app transport::tests::admitted_v2_outbound_frame_is_exactly_reopenable -- --exact
cargo test --offline -p nq-app transport::tests::invalid_outbound_result_is_refused_before_serialization -- --exact
cargo test --offline -p nq-app cli::tests::structured_collection_cli_emits_exact_reopenable_v2_ndjson -- --exact
cargo test --offline -p nq-app daemon::tests::daemon_result_document_preserves_same_code_refusal_payloads -- --exact
cargo test --offline -p nq-app api::tests::v2_api_preserves_same_code_refusals_and_v1_route_stays_v1 -- --exact
cargo test --offline -p nq-app api::tests::v3_findings_api_preserves_same_code_evaluation_refusals -- --exact
cargo test --offline -p nq-app api::tests::evaluation_history_query_has_exact_numeric_snapshot_bounds -- --exact
cargo test --offline -p nq-app api::tests::response_larger_than_one_stored_document_is_transported_exactly -- --exact
cargo test --offline -p nq-app cli::tests::evaluation_export_exposes_one_exact_frozen_numeric_cursor -- --exact
cargo test --offline -p nq-app cli::tests::refusal_export_exposes_one_exact_immutable_cursor -- --exact
cargo test --offline -p nq-app --test semantic_surfaces cli_and_cold_archive_reopen_exact_same_code_refusal_payloads -- --exact
cargo test --offline -p nq-app --test semantic_surfaces structured_watcher_test_emits_the_canonical_typed_refusal -- --exact
cargo test --offline -p nq-app --test custody_pagination cli_pages_same_code_refusals_without_losing_payloads -- --exact
cargo test --offline -p nq-app --test evaluation_refusal_surfaces same_code_evaluation_refusals_survive_backup_cli_and_cold_archive -- --exact
cargo test --offline -p nq-app archive::tests::a_resealed_unversioned_instance_status_fails_typed_history_verification -- --exact
cargo test --offline -p nq-app archive::tests::a_resealed_mismatched_refusal_document_fails_typed_history_verification -- --exact
```

The four original release-forcing tests are retained under their original
names and are ordinary regressions now; they are no longer ignored expected
failures. The manifest's two mutations are production-code semantic erasures:
one is designed to collapse exchange-timeout phase while still compiling, and
one is designed to replace stored canonical status detail with a code-derived
document while still compiling. Their paired assertions must turn red. A fresh
clean-pinned audit must execute and record compilation and both mutation
outcomes; this file does not inherit the old r4 mutation ledger (or its earlier
r3 attempt).

## Current boundary and verdict

The current manifest parses and its static census resolves the five
function-shaped projections, all role bindings, and all declared surface entry
points. SQL columns, serde discriminants, and the boolean control-flow method
are explicitly classified above because the framework's function-shaped
census cannot discover them.

The product repair is implemented, but this is not yet an AC-R4 pass receipt:
the source must be committed and clean-pinned, every bound evidence command and
mutation must be green/biting, the full hardening and admissibility batteries
must pass, package bytes must be rebuilt to a new SHA-256, and the corrected VM
qualification must run from a fresh directory. Until those records exist, the
release remains **BLOCKED**. There is no waiver and no inherited pass.
