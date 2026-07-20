# Governed-result transport map

Status: **pre-repair audit; product transport is release-blocking**
(2026-07-20).

This map records the four release-forcing failures before changing product
code.  It follows the repository's existing refusal-preservation policy and
does not create new refusal doctrine.  Matching coarse codes are indexes and
control-flow inputs only; they are not substitutes for dependent testimony.

## Reproduced release-forcing assertions

Each command below exited 101 at source revision
`df075c8ff4d08ea69148786a45c55a2da7b2db2c`:

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
- helper refusal: the retriable/EAGAIN and non-retriable/ENODEV values became
  byte-identical `CollectionOutcome::HelperRefused` documents containing only
  boundary, code, and message;
- profile refusal: different profile identities, boundaries, and details
  became byte-identical `CollectionOutcome::Rejected` documents containing
  only `plane="profile"`, code, and message;
- rejected custody: `SubmissionDisposition::Rejected { refusal: None }`
  returned a successful `CollectionReceipt` instead of an invariant error.

The existing helper-wire pair control passed: protocol v1 already preserves a
same-code/different-payload `nq_protocol::Refusal` exactly.

## Transport map and earliest erasure

| Family | Canonical source and conversions | Persisted / serialized representations | Earliest semantic erasure |
|---|---|---|---|
| Persistent exchange timeout | `UnixIoPhase` -> `UnixAcquisitionOutcome::Timeout { phase }` -> `engine::unix_acquisition_outcome` -> `AcquisitionOutcome::ExchangeTimeout { phase }` -> `RunCapture` | Full `RunCapture` outcome is serialized by `capture_resource_document` into `watcher_runs.resource_outcome_json`. `watcher_runs.acquisition_outcome="timeout"` is a coarse index. | `engine::acquisition_detail` maps `ExchangeTimeout` to `None`. Both `dry_collection_error` and `CollectionOutcome::AcquisitionFailed` consume that projection, so direct CLI, daemon status/log, status API, and status CLI receive no phase. |
| Helper refusal | helper `Refusal` -> `HelperResponse::refusal` -> canonical NDJSON -> `parse_response` -> `ResponseOutcome::Refusal` | Raw response bytes and the complete canonical `nq_protocol::Refusal` are written to `raw_submissions` and `refusals.detail_json`. | Normal collection constructs `CollectionOutcome::HelperRefused` without `retriable`, structured `details`, `refusal_id`, or stable helper origin. Dry exchange replaces the entire refusal with one generic `EngineError::Protocol` string. |
| Profile refusal | `ProfileModule::validate` -> `ProfileRefusal` | Normal collection writes the complete canonical refusal to `refusals.detail_json`, with run/submission/profile associations. | Normal collection constructs generic `CollectionOutcome::Rejected`, dropping profile identity, exact boundary, details, and `refusal_id`. Dry exchange maps the refusal to `EngineError::Profile(refusal.message)`. |
| Rejected custody | `SubmissionDisposition::Rejected` -> `validate_collection` -> `commit_collection` | `raw_submissions` retains custody; optional `RefusalInput` becomes a row in `refusals` whose stable ID and canonical detail can already be linked by run and submission. | `SubmissionDisposition` makes the refusal optional, validation accepts absence, insertion is conditional, and no supported typed refusal/custody reader exists. The SQL shape can therefore contain zero, one, or multiple refusal rows for one rejected submission. |

## Downstream carrier classification

After a normal `CollectionOutcome` is constructed, the current status path is
byte-preserving:

```text
CollectionOutcome
  -> record_instance_status / canonical JSON
  -> status_events.detail_json
  -> public_status_snapshot_v1
  -> ComponentStatus.details
  -> CLI status export / API / console
```

`nq collect` serializes the same outcome directly.  The daemon currently logs
its Rust debug representation, which is not a versioned testimonial encoding.
SQLite backup copies the database through the online backup API.  Cold archive
creation then seals that verified copy; verification opens and validates it.
Those mechanisms preserve the bytes they receive but cannot restore testimony
erased before storage.

The dry watcher workflow is a separate adapter: expected acquisition, helper,
and profile refusals are routed through display-only `EngineError` values and
therefore never reach the canonical normal-collection carrier.

## Canonical repair boundary

The three normal-path defects share one earliest lossy carrier:
`CollectionOutcome`.  Replace it with (or evolve it into) one explicitly
versioned, serializable and deserializable governed-result representation that
embeds exact typed acquisition/helper/profile testimony and the stable refusal
identity assigned before persistence.  Status, daemon, API, CLI, backup, and
archive readers must consume that representation rather than reconstructing
fields from codes or adjacent rows.  Dry watcher actions must expose the same
typed result instead of converting it to a string error.

Rejected custody additionally requires a mandatory `RefusalInput` for every
new rejected submission, exact-one linkage validation, stable typed
enumeration/reopening, and equality between the linked stored refusal and the
canonical outward result.  Existing v1 columns already store the refusal ID,
submission association, and canonical detail, so this repair does not by
itself require a SQL representation change.  Historical v1 rows with no exact
linked refusal remain historical bytes but must fail current semantic
validation; no refusal may be synthesized for them.

The helper request/response wire remains `nq.helper.response.v1`: it is already
lossless for helper refusal fields.  Any new governed-result wire/read-model
identifier must be versioned independently rather than silently changing that
helper protocol.
