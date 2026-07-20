# Refusal-preservation crosswalk

Status: **candidate crosswalk closed with FAIL; rebuild required** (2026-07-20).

This is the target-owned complement to `admissibility.toml`. It enumerates
coarse SQL fields and serde discriminants that the external framework's
function-shaped census cannot discover. It derives its scope from
`docs/HARDENING_PROGRAM.md` section 8 and the existing “refusals retain the
exact responsible instance and boundary” runtime invariant in
`docs/internal/INVARIANT_CROSSWALK.md`. It does not add a new product policy.

## Bound object and governing control

- package: `dist/nq-ng_0.1.0_amd64.deb`
- package SHA-256:
  `44e7bd1af43ac4d6f9543d2dc286610be43d86426334ca24ff1a05a45d24e2e0`
- packaged source commit: `06aa918b7b51cf165070d53215ee4e943192102e`
- AC-R4 control: `/home/jbeck/git/audit/controls/v14/rung4-refusal-preservation.toml`
  SHA-256 `f4369b7de1fa49009a80b99c41b62aaa4b50cab487f534f5e6dc8525d3ea2fcf`
- control baseline: `/home/jbeck/git/audit/controls/BASELINE.toml` SHA-256
  `2ad530769f8de10104b80b6aa90172eef3d12f354411161172a41c6a40865c30`
- formal baseline: Lean release `14.0.0`, revision
  `ff491b808ebeab2a132d9ade46d234cf85dcfbe9`, tree
  `72cba07e35588e9f67c252b0bd92cf0523ab178f`

AC-R4 requires same-code/different-witness refusals to remain distinguishable
on every testimonial surface, every coarse projection to be classified, and
stored detail to be rendered rather than reconstructed from a code. The Lean
law is specification evidence only; it does not prove this runtime mapping,
serialization, or archive.

## Family and surface matrix

| Family | Stable typed carrier | Persistence and historical reopening | Projection / outward surfaces | Result |
|---|---|---|---|---|
| Acquisition | `runner.rs::AcquisitionOutcome`, including `ExchangeTimeout { phase }` | `engine.rs::capture_resource_document` places the complete outcome in `watcher_runs.resource_outcome_json`; verified SQLite backup and the cold archive retain it. `watcher_runs.acquisition_outcome` is a non-testimonial index only. | `acquisition_code` maps all timeouts to `timeout`; `acquisition_detail` returns no detail for `ExchangeTimeout`. Dry CLI, `CollectionOutcome::AcquisitionFailed`, daemon logging, status storage/read model, API, and console therefore collapse `write_request` and `read_response`. | **Fail.** `forcing_exchange_timeout_phase_survives_dry_and_status_surfaces` reproduces byte-identical outward testimony. |
| Helper-protocol refusal | `nq_protocol::Refusal` carries responsible instance, boundary, code, message, `retriable`, and structured `details`; `ResponseOutcome::kind` is only its tagged-union discriminator. | Normal collection retains raw response bytes and canonical full refusal detail in `refusals`; backup/archive retain both. `refusals.source_kind` is a non-testimonial index while exact boundary and detail remain linked. | The exact wire test preserves a same-code/different-payload pair. Admission dry exchange then replaces every helper refusal with one generic protocol error. Normal `CollectionOutcome::HelperRefused` retains boundary/code/message but drops `retriable` and `details`; all downstream status/operator surfaces inherit the loss. | **Fail after the wire boundary.** `same_code_distinct_refusals_remain_distinct_on_wire` passes; `forcing_protocol_refusal_dependent_fields_survive_collection_status` proves the later adapter collapse. |
| Profile refusal | `nq_profiles::ProfileRefusal` carries instance, profile identity, boundary, code, message, and structured details. | Normal profile rejection stores the full canonical refusal and raw response; verified backup/archive retain it. | Dry exchange reduces the refusal to its message. Normal `CollectionOutcome::Rejected` retains only `plane = profile`, code, and message, dropping profile identity, exact boundary, and details before status/CLI/log/API/console. | **Fail.** `forcing_profile_refusal_identity_survives_collection_status` reproduces the collapse. |
| Admission verification | `admission.rs::AdmissionError` has distinct binary, config, profile, protocol, malformed, conformance, and I/O variants. | Successful admissions and binding events are durable, but a failed `collect` admission is stored only after conversion to `CollectionOutcome::AdmissionRefused`. | That outcome has a generic `admission_refused` status code and one diagnostic string, with no stable variant/boundary payload for reopening. | **Fail.** This is an implementation boundary that must become typed before a rebuilt candidate can close AC-R4. |
| Detector/evaluation refusal | `DetectorResult` uses `DetectorState::CannotEvaluate` plus a full `ProfileRefusal`. | Evaluation detail, the canonical refusal row, immutable finding event `refusal_json`, and archive all retain the refusal. The public finding DTO decodes stored `refusal_json` rather than re-deriving it. | Current finding CLI/API/console use the shared DTO. | No loss located, but a dedicated same-code restart→backup/archive→public forcing test is still required for closure of the rebuilt candidate. |
| Rejected-custody index | `SubmissionDisposition::Rejected` is the store boundary; `rejection_code` is a coarse index. | Production callers usually provide a full `RefusalInput`, but the type, schema, and validator allow a rejected submission with no typed refusal (and structurally allow no rejection code). | No supported public refusal-history view repairs missing stored testimony. | **Fail.** `forcing_rejected_submission_requires_typed_refusal` proves that missing typed evidence is accepted. |
| Refusal source-family index | Exact helper/profile/acquisition boundaries remain in their typed carriers and canonical refusal rows. | `refusal_source(&str)` groups exact boundary strings into `protocol`, `profile`, or `acquisition` for `refusals.source_kind`; the linked exact boundary and canonical detail remain the testimony. | The family token is allowed for indexing only and cannot replace the linked refusal or diagnose its exact boundary. | Classified non-testimonial projection; no repair for any failed adapter above. |
| Status code | `StatusEventInput` pairs `code` with canonical `detail`; `ComponentStatus` carries both. | `status_events` is append-only, its current projection retains exact stored detail, and verified backup/reopen preserves it. | `status_events.code` is non-testimonial by itself. The transport is lossless for what it receives, but `record_instance_status` receives already-truncated `CollectionOutcome` values in the failed families above. | **Fail upstream; pass as a carrier.** The positive store/backup test and recompute-from-code mutation distinguish these claims. |
| Success/control-flow projection | The complete `CollectionOutcome` is the typed carrier. | `CollectionOutcome::is_success()` returns false for every refusal/failure and is not persisted as testimony. | CLI computes it only after retaining the full outcome for rendering; daemon branches use it for exit/retry cadence while logging the full debug outcome. | Classified non-testimonial: allowed for control flow, forbidden as diagnosis, storage, or a typed-outcome replacement. |
| Binding `kind` / `reason` | `BindingEventInput` carries `event_kind`, `reason_code`, and canonical detail. | All three survive append-only storage and archive. | `event_kind` and `reason_code` are individually non-testimonial lifecycle indices; the authority reader may use kind to select active/inactive state but not to claim a cause. | Classified boundary; not a refusal-payload repair for the failed families. |
| Historical verification refusal | `engine.rs::VerificationRefusal` wraps typed `SnapshotVerificationError` and distinct identity failures. | It is produced by read-only historical verification and does not rewrite stored decisions. | Library-only in the current package; no CLI/API testimonial route exists. | Explicit current implementation boundary; no lossy candidate-facing projection found. |
| System-cut coherence refusal | `nq-system-contract::CutCoherenceRefusal` remains typed in its separate crate. | Its own tests cover that formal/workspace object. | `nq-app` and `nq-core` do not link the system-contract crate into `nq`/`nqd`. | Outside this package's runtime cone; crate separation is preserved, not reopened. |

`semantic_report_status` is exact report-state rendering, not a refusal
projection. Digest `as_str` methods render identities, not qualification
results. The framework heuristic did not enumerate private `refusal_source` or
the boolean `CollectionOutcome::is_success`; both are explicitly classified in
`admissibility.toml` and above. Generic `EngineError`, `StoreError`,
configuration, and local I/O errors are process failures unless an adapter
exports them as refusal testimony; they are not silently promoted into
admissibility judgments here.

## Executable evidence

Passing controls:

```text
cargo test --offline -p nq-protocol --test conformance_corpus positive_corpus_exercises_all_result_planes -- --exact
cargo test --offline -p nq-protocol --test conformance_corpus same_code_distinct_refusals_remain_distinct_on_wire -- --exact
cargo test --offline -p nq-core engine::tests::status_store_and_backup_preserve_same_code_distinct_detail -- --exact
hardening/test-harness.sh
```

Release-forcing controls (each exits 101 against the preserved candidate
source and is ignored by the ordinary developer suite):

```text
cargo test --offline -p nq-core engine::tests::forcing_exchange_timeout_phase_survives_dry_and_status_surfaces -- --ignored --exact
cargo test --offline -p nq-core engine::tests::forcing_protocol_refusal_dependent_fields_survive_collection_status -- --ignored --exact
cargo test --offline -p nq-core engine::tests::forcing_profile_refusal_identity_survives_collection_status -- --ignored --exact
cargo test --offline -p nq-store tests::forcing_rejected_submission_requires_typed_refusal -- --ignored --exact
```

The test additions are below `#[cfg(test)]`. The non-test portions of
`crates/nq-core/src/engine.rs` and `crates/nq-store/src/lib.rs` hash identically
to source commit `06aa918`:

```text
nq-core engine production portion  e0fe928f4ec72496430039b4a362e92da9ffc6c3fe019313a24b70b2146d0b41
nq-store production portion        278618f16ddd57f49578ab1ce2f5343aeea7a72423553e6ab81114fe8106941e
```

The authoritative pre-commit audit attempt is
`audit/receipts/run-2026-07-20-qualification-repair-r3/refusal-audit`.
Its AC-R4-002 heuristic census passes, its v1 ledger records 2/2 declared
mutations as biting, and AC-R4-001 plus AC-R4-003 fail. There are no waivers
and no obstruction. The ledger serializes only a nonzero mutation-command exit
and cannot distinguish an assertion failure from a compile failure; mutation
phase is therefore auxiliary and is not relied upon for this blocked verdict.

## Residual limitations and verdict

The external framework is inactive infrastructure with no committed target
integration; its executable is therefore identified by byte digest in the
receipt, not by a trustworthy framework Git revision. Its static census sees
only a heuristic subset of projections. `admissibility.toml` and the matrix
above explicitly enumerate the SQL/serde/private/boolean projections it cannot
discover.

The r3 ledger's bound per-surface commands are not an end-to-end surface suite.
Its CLI, daemon, and API findings reuse the shared upstream timeout-mapping
forcing test rather than launching those entry points. Protocol-wire
preservation is established separately by
`same_code_distinct_refusals_remain_distinct_on_wire`; cold-archive preservation
is traced through canonical stored values and the verified SQLite backup/reopen
path, not by an `nq-app` archive create/verify pair. Protocol-wire and
cold-archive therefore remain declared testimonial entry points but are not
bound as direct AC-R4 forcing surfaces in r3. The upstream
typed-to-`CollectionOutcome` collapses are sufficient to block this candidate
because downstream adapters cannot reconstruct erased dependent fields. A
rebuilt candidate still requires direct pairwise tests at every actual
testimonial entry point before a passing closure can be issued.

This receipt closes the candidate-specific crosswalk with verdict **fail**: the
census and code-path traces are complete enough to force a rebuild. It is not a
passing gate-closure or mint qualification. Product changes in `nq-core` and
`nq-store`, rebuilt `nq`/`nqd` bytes, all forcing and direct-surface tests green,
and a new clean-pinned AC-R4 ledger are required for that later result. No prior
qualification receipt can be reinterpreted to supply it.
