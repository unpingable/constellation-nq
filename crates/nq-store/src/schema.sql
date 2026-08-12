PRAGMA application_id = 1313951303; -- "NQNG"
PRAGMA user_version = 9;

CREATE TABLE schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    product TEXT NOT NULL CHECK (product = 'nq-ng'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 9),
    -- Digest of the exact schema.sql artifact compiled into the writing binary.
    -- Rejects stale provisional-candidate databases at startup; it is NOT a
    -- tamper attestation of the live SQLite schema (which the structural
    -- fingerprint checks separately).
    schema_artifact_digest TEXT NOT NULL CHECK (length(schema_artifact_digest) = 71 AND substr(schema_artifact_digest, 1, 7) = 'sha256:'),
    initialized_at TEXT NOT NULL
) STRICT;

CREATE TABLE profile_descriptor_snapshots (
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL CHECK (length(profile_digest) = 71 AND substr(profile_digest, 1, 7) = 'sha256:'),
    descriptor_json BLOB NOT NULL CHECK (json_valid(CAST(descriptor_json AS TEXT))),
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (profile_id, profile_version, profile_digest)
) STRICT;

CREATE TABLE admission_records (
    admission_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    config_digest TEXT NOT NULL CHECK (length(config_digest) = 71 AND substr(config_digest, 1, 7) = 'sha256:'),
    -- Digest of the opened helper executable bytes (was `executable_digest`;
    -- renamed while the schema is provisional so the helper artifact is not
    -- confused with the evaluator artifact below).
    helper_artifact_digest TEXT NOT NULL CHECK (length(helper_artifact_digest) = 71 AND substr(helper_artifact_digest, 1, 7) = 'sha256:'),
    -- Identity-bearing admission-context constituents. admission_context_digest
    -- is H over exactly these seven fields (config_digest, protocol_version, and
    -- the five here); the store computes it, never a caller outside tests.
    profile_semantic_id TEXT NOT NULL CHECK (length(profile_semantic_id) = 71 AND substr(profile_semantic_id, 1, 7) = 'sha256:'),
    detector_identity_digest TEXT NOT NULL CHECK (length(detector_identity_digest) = 71 AND substr(detector_identity_digest, 1, 7) = 'sha256:'),
    evaluator_source_digest TEXT NOT NULL CHECK (length(evaluator_source_digest) = 71 AND substr(evaluator_source_digest, 1, 7) = 'sha256:'),
    evaluator_artifact_digest TEXT NOT NULL CHECK (length(evaluator_artifact_digest) = 71 AND substr(evaluator_artifact_digest, 1, 7) = 'sha256:'),
    admission_context_digest TEXT NOT NULL CHECK (length(admission_context_digest) = 71 AND substr(admission_context_digest, 1, 7) = 'sha256:'),
    execution_chain_json BLOB NOT NULL CHECK (json_valid(CAST(execution_chain_json AS TEXT))),
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    -- Inspectable receipt metadata about how evaluator identity was obtained.
    -- Intentionally NOT part of admission_context_digest: the artifact digest
    -- already captures the compiled result.
    target_triple TEXT NOT NULL,
    artifact_identity_method TEXT NOT NULL,
    platform_runtime_version TEXT NOT NULL,
    capability_grant_json BLOB NOT NULL CHECK (json_valid(CAST(capability_grant_json AS TEXT))),
    conformance_json BLOB NOT NULL CHECK (json_valid(CAST(conformance_json AS TEXT))),
    lock_json BLOB NOT NULL CHECK (json_valid(CAST(lock_json AS TEXT))),
    admitted_at TEXT NOT NULL,
    operator_identity_json BLOB NOT NULL CHECK (json_valid(CAST(operator_identity_json AS TEXT))),
    FOREIGN KEY (profile_id, profile_version, profile_digest)
        REFERENCES profile_descriptor_snapshots(profile_id, profile_version, profile_digest)
) STRICT;

-- A narrowly scoped, NQ-derived admission of the current local helper as an
-- acquisition provider. It is deliberately distinct from the later decision
-- to admit or reject any submitted report. The source AdmissionLock remains
-- the authority and the current instance binding remains the revocation gate.
CREATE TABLE local_provider_admissions (
    provider_admission_id TEXT PRIMARY KEY CHECK (length(provider_admission_id) = 71 AND substr(provider_admission_id, 1, 7) = 'sha256:'),
    schema_id TEXT NOT NULL CHECK (schema_id = 'nq.local_provider_admission.v1'),
    source_admission_id TEXT NOT NULL UNIQUE,
    provider_semantic_id TEXT NOT NULL CHECK (length(provider_semantic_id) = 71 AND substr(provider_semantic_id, 1, 7) = 'sha256:'),
    provider_artifact_digest TEXT NOT NULL CHECK (length(provider_artifact_digest) = 71 AND substr(provider_artifact_digest, 1, 7) = 'sha256:'),
    provider_protocol_identity TEXT NOT NULL,
    provider_config_digest TEXT NOT NULL CHECK (length(provider_config_digest) = 71 AND substr(provider_config_digest, 1, 7) = 'sha256:'),
    contract_json BLOB NOT NULL CHECK (length(contract_json) <= 1048576 AND json_valid(CAST(contract_json AS TEXT))),
    contract_digest TEXT NOT NULL CHECK (length(contract_digest) = 71 AND substr(contract_digest, 1, 7) = 'sha256:'),
    source_admitted_at TEXT NOT NULL,
    derived_at TEXT NOT NULL,
    derivation_kind TEXT NOT NULL CHECK (derivation_kind IN ('admission_append', 'schema_v3_migration')),
    FOREIGN KEY (source_admission_id) REFERENCES admission_records(admission_id)
) STRICT;

CREATE TABLE instance_binding_events (
    binding_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    binding_event_id TEXT NOT NULL UNIQUE,
    instance_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('activate', 'quiesce', 'revoke', 'rollback')),
    admission_id TEXT,
    binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 71 AND substr(binding_digest, 1, 7) = 'sha256:'),
    occurred_at TEXT NOT NULL,
    reason_code TEXT,
    detail_json BLOB NOT NULL CHECK (length(detail_json) <= 65536 AND json_valid(CAST(detail_json AS TEXT))),
    CHECK ((event_kind IN ('activate', 'rollback') AND admission_id IS NOT NULL)
        OR (event_kind IN ('quiesce', 'revoke'))),
    FOREIGN KEY (admission_id) REFERENCES admission_records(admission_id)
) STRICT;
CREATE INDEX instance_binding_events_by_instance
    ON instance_binding_events(instance_id, binding_sequence);

-- Active admission files are a local materialization of the append-only
-- binding history. An intent is committed in the same transaction as its
-- binding event; a later completion proves the corresponding filesystem state
-- was durably materialized. Pending intents are safe to replay after a crash.
CREATE TABLE binding_materialization_events (
    materialization_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    materialization_event_id TEXT NOT NULL UNIQUE,
    operation_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    binding_event_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('intent', 'completed')),
    occurred_at TEXT NOT NULL,
    detail_json BLOB NOT NULL CHECK (length(detail_json) <= 3145728 AND json_valid(CAST(detail_json AS TEXT))),
    UNIQUE (operation_id, phase),
    UNIQUE (binding_event_id, phase),
    FOREIGN KEY (binding_event_id) REFERENCES instance_binding_events(binding_event_id)
) STRICT;
CREATE INDEX binding_materialization_by_instance
    ON binding_materialization_events(instance_id, materialization_sequence);

CREATE TABLE watcher_runs (
    run_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    instance_id TEXT NOT NULL,
    admission_id TEXT,
    binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 71 AND substr(binding_digest, 1, 7) = 'sha256:'),
    checkpoint_contract_digest TEXT NOT NULL CHECK (length(checkpoint_contract_digest) = 71 AND substr(checkpoint_contract_digest, 1, 7) = 'sha256:'),
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    carrier TEXT NOT NULL CHECK (carrier IN ('stdio', 'unix')),
    started_at TEXT NOT NULL,
    deadline_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    acquisition_outcome TEXT NOT NULL,
    execution_identity_json BLOB NOT NULL CHECK (json_valid(CAST(execution_identity_json AS TEXT))),
    resource_outcome_json BLOB NOT NULL CHECK (json_valid(CAST(resource_outcome_json AS TEXT))),
    FOREIGN KEY (admission_id) REFERENCES admission_records(admission_id)
) STRICT;
CREATE INDEX watcher_runs_by_instance ON watcher_runs(instance_id, started_at, run_id);

-- Versioned semantic boundary between an admitted acquisition provider and NQ's
-- own normalization, admission, evaluation, and publication machinery. The
-- outer raw capture is retained even when no protocol submission can be made.
CREATE TABLE provider_intake_attempts (
    intake_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    intake_id TEXT NOT NULL UNIQUE,
    schema_id TEXT NOT NULL CHECK (schema_id = 'nq.provider_intake.v1'),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (length(idempotency_key) = 71 AND substr(idempotency_key, 1, 7) = 'sha256:'),
    attempt_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    provider_admission_id TEXT NOT NULL,
    source_admission_id TEXT NOT NULL,
    provider_sequence TEXT CHECK (provider_sequence IS NULL OR (length(provider_sequence) BETWEEN 1 AND 256)),
    origin_carrier TEXT NOT NULL CHECK (origin_carrier IN ('stdio', 'unix')),
    deadline_at TEXT NOT NULL,
    checkpoint_contract_digest TEXT NOT NULL CHECK (length(checkpoint_contract_digest) = 71 AND substr(checkpoint_contract_digest, 1, 7) = 'sha256:'),
    execution_identity_digest TEXT NOT NULL CHECK (length(execution_identity_digest) = 71 AND substr(execution_identity_digest, 1, 7) = 'sha256:'),
    admission_context_digest TEXT NOT NULL CHECK (length(admission_context_digest) = 71 AND substr(admission_context_digest, 1, 7) = 'sha256:'),
    provider_semantic_id TEXT NOT NULL CHECK (length(provider_semantic_id) = 71 AND substr(provider_semantic_id, 1, 7) = 'sha256:'),
    provider_artifact_digest TEXT NOT NULL CHECK (length(provider_artifact_digest) = 71 AND substr(provider_artifact_digest, 1, 7) = 'sha256:'),
    provider_protocol_identity TEXT NOT NULL,
    provider_config_digest TEXT NOT NULL CHECK (length(provider_config_digest) = 71 AND substr(provider_config_digest, 1, 7) = 'sha256:'),
    binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 71 AND substr(binding_digest, 1, 7) = 'sha256:'),
    instance_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL CHECK (length(profile_digest) = 71 AND substr(profile_digest, 1, 7) = 'sha256:'),
    profile_semantic_id TEXT NOT NULL CHECK (length(profile_semantic_id) = 71 AND substr(profile_semantic_id, 1, 7) = 'sha256:'),
    evaluator_artifact_digest TEXT NOT NULL CHECK (length(evaluator_artifact_digest) = 71 AND substr(evaluator_artifact_digest, 1, 7) = 'sha256:'),
    context_json BLOB NOT NULL CHECK (length(context_json) <= 1048576 AND json_valid(CAST(context_json AS TEXT))),
    context_digest TEXT NOT NULL CHECK (length(context_digest) = 71 AND substr(context_digest, 1, 7) = 'sha256:'),
    interpretation_kind TEXT NOT NULL CHECK (interpretation_kind IN
        ('unavailable', 'protocol_rejected', 'provider_refusal', 'candidate_report')),
    interpretation_json BLOB NOT NULL CHECK (length(interpretation_json) <= 16777216 AND json_valid(CAST(interpretation_json AS TEXT))),
    interpretation_digest TEXT NOT NULL CHECK (length(interpretation_digest) = 71 AND substr(interpretation_digest, 1, 7) = 'sha256:'),
    native_outcome_kind TEXT NOT NULL CHECK (native_outcome_kind IN
        ('response', 'spawn_failed', 'request_write_failed', 'timeout',
         'output_too_large', 'stderr_too_large', 'eof', 'malformed_framing',
         'malformed_json', 'exit_nonzero', 'helper_exited', 'disconnect',
         'carrier_startup_failed', 'not_running', 'io_failed')),
    native_outcome_json BLOB NOT NULL CHECK (length(native_outcome_json) <= 1048576 AND json_valid(CAST(native_outcome_json AS TEXT))),
    native_outcome_digest TEXT NOT NULL CHECK (length(native_outcome_digest) = 71 AND substr(native_outcome_digest, 1, 7) = 'sha256:'),
    raw_bytes BLOB NOT NULL CHECK (length(raw_bytes) <= 16777217),
    raw_sha256 TEXT NOT NULL CHECK (length(raw_sha256) = 71 AND substr(raw_sha256, 1, 7) = 'sha256:'),
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    replay_digest TEXT NOT NULL CHECK (length(replay_digest) = 71 AND substr(replay_digest, 1, 7) = 'sha256:'),
    intake_digest TEXT NOT NULL CHECK (length(intake_digest) = 71 AND substr(intake_digest, 1, 7) = 'sha256:'),
    FOREIGN KEY (provider_admission_id) REFERENCES local_provider_admissions(provider_admission_id),
    FOREIGN KEY (source_admission_id) REFERENCES admission_records(admission_id)
) STRICT;
CREATE INDEX provider_intake_attempts_by_provider
    ON provider_intake_attempts(provider_admission_id, intake_sequence);

-- The only admitted live origin in schema v4. A later provider kind must add a
-- new exact subtype and extend the exact-one-origin invariant; it may not hide
-- behind a nullable watcher-run foreign key.
CREATE TABLE local_watcher_provider_intakes (
    intake_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    FOREIGN KEY (intake_id) REFERENCES provider_intake_attempts(intake_id),
    FOREIGN KEY (run_id) REFERENCES watcher_runs(run_id)
) STRICT;

-- Schema-v3 runs cannot be upgraded into provider-intake-v1: some acquisition
-- failures recorded only retained-byte counts, not the exact captured bytes.
-- Migration classifies that limitation explicitly instead of inventing an
-- intake identity or durable acknowledgment.
CREATE TABLE legacy_v3_watcher_run_intake_gaps (
    run_id TEXT PRIMARY KEY,
    source_schema_version INTEGER NOT NULL CHECK (source_schema_version = 3),
    source_schema_artifact_digest TEXT NOT NULL CHECK (length(source_schema_artifact_digest) = 71 AND substr(source_schema_artifact_digest, 1, 7) = 'sha256:'),
    limitation_code TEXT NOT NULL CHECK (limitation_code = 'provider_intake_not_recorded'),
    detail_json BLOB NOT NULL CHECK (length(detail_json) <= 65536 AND json_valid(CAST(detail_json AS TEXT))),
    migrated_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES watcher_runs(run_id)
) STRICT;

CREATE TABLE raw_submissions (
    submission_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    raw_bytes BLOB NOT NULL CHECK (length(raw_bytes) <= 16777216),
    raw_sha256 TEXT NOT NULL CHECK (length(raw_sha256) = 71 AND substr(raw_sha256, 1, 7) = 'sha256:'),
    received_at TEXT NOT NULL,
    protocol_outcome TEXT NOT NULL,
    admission_outcome TEXT NOT NULL CHECK (admission_outcome IN ('admitted', 'rejected')),
    rejection_code TEXT,
    CHECK ((admission_outcome = 'admitted' AND rejection_code IS NULL)
        OR admission_outcome = 'rejected'),
    FOREIGN KEY (run_id) REFERENCES watcher_runs(run_id)
) STRICT;
CREATE INDEX raw_submissions_by_digest ON raw_submissions(raw_sha256);

CREATE TABLE admitted_reports (
    report_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT NOT NULL UNIQUE,
    submission_id TEXT NOT NULL UNIQUE,
    instance_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    report_status TEXT NOT NULL CHECK (report_status IN ('complete', 'partial', 'failed')),
    -- Source protocol JSON as received. Retained as watcher material; the
    -- admitted judgment below does not substitute for it, nor it for the judgment.
    canonical_json BLOB NOT NULL CHECK (length(canonical_json) <= 16777216 AND json_valid(CAST(canonical_json AS TEXT))),
    semantic_digest TEXT NOT NULL CHECK (length(semantic_digest) = 71 AND substr(semantic_digest, 1, 7) = 'sha256:'),
    -- Persisted, versioned admitted judgment (the canonical ValidatedReport).
    -- verify_admitted (3B) checks this snapshot; it never re-derives one.
    validated_report_json BLOB NOT NULL CHECK (length(validated_report_json) <= 16777216 AND json_valid(CAST(validated_report_json AS TEXT))),
    judgment_schema_version TEXT NOT NULL,
    -- H(judgment_schema_version || admission_context_digest || canonical
    -- validated report). Binds the judgment bytes to their exact admission context.
    judgment_digest TEXT NOT NULL CHECK (length(judgment_digest) = 71 AND substr(judgment_digest, 1, 7) = 'sha256:'),
    -- The admission context this report was judged under, copied from the
    -- admission reached through its run. The trigger below forbids any other value.
    admission_context_digest TEXT NOT NULL CHECK (length(admission_context_digest) = 71 AND substr(admission_context_digest, 1, 7) = 'sha256:'),
    next_checkpoint_json BLOB CHECK (next_checkpoint_json IS NULL OR json_valid(CAST(next_checkpoint_json AS TEXT))),
    admitted_at TEXT NOT NULL,
    UNIQUE (report_id, semantic_digest),
    FOREIGN KEY (submission_id) REFERENCES raw_submissions(submission_id),
    FOREIGN KEY (profile_id, profile_version, profile_digest)
        REFERENCES profile_descriptor_snapshots(profile_id, profile_version, profile_digest)
) STRICT;
CREATE INDEX admitted_reports_by_instance
    ON admitted_reports(instance_id, report_sequence);
CREATE INDEX admitted_reports_by_semantic_digest
    ON admitted_reports(semantic_digest);

CREATE TRIGGER admitted_reports_only_from_admitted_submission
BEFORE INSERT ON admitted_reports
WHEN (SELECT admission_outcome FROM raw_submissions WHERE submission_id = NEW.submission_id) <> 'admitted'
BEGIN
    SELECT RAISE(ABORT, 'rejected submissions cannot become admitted reports');
END;

-- The conditional admission-context law: a run that produced an admitted report
-- has a complete admission context, and the report is bound to exactly that
-- context. The join reaches the admission through submission -> run ->
-- admission_id; a null admission_id yields no matching row, so an admitted
-- report from a context-less run is refused. watcher_runs.admission_id stays
-- globally nullable (refused/failed runs legitimately have none).
CREATE TRIGGER admitted_reports_bind_admission_context
BEFORE INSERT ON admitted_reports
WHEN (
    SELECT COUNT(*)
    FROM raw_submissions AS s
    JOIN watcher_runs AS r ON r.run_id = s.run_id
    JOIN admission_records AS a ON a.admission_id = r.admission_id
    WHERE s.submission_id = NEW.submission_id
      AND a.admission_context_digest = NEW.admission_context_digest
) <> 1
BEGIN
    SELECT RAISE(ABORT, 'admitted report must bind the admission context reached through its run');
END;

CREATE TABLE observations (
    report_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    kind TEXT NOT NULL,
    subject_json BLOB NOT NULL CHECK (json_valid(CAST(subject_json AS TEXT))),
    observed_at TEXT NOT NULL,
    payload_json BLOB NOT NULL CHECK (json_valid(CAST(payload_json AS TEXT))),
    PRIMARY KEY (report_id, ordinal),
    FOREIGN KEY (report_id) REFERENCES admitted_reports(report_id)
) STRICT;
CREATE INDEX observations_by_kind ON observations(kind, report_id, ordinal);

CREATE TABLE report_coverage (
    report_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    coverage_kind TEXT NOT NULL,
    coverage_state TEXT NOT NULL,
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    PRIMARY KEY (report_id, ordinal),
    UNIQUE (report_id, coverage_kind),
    FOREIGN KEY (report_id) REFERENCES admitted_reports(report_id)
) STRICT;

CREATE TABLE observation_coverage (
    report_id TEXT NOT NULL,
    observation_ordinal INTEGER NOT NULL CHECK (observation_ordinal >= 0),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    coverage_kind TEXT NOT NULL,
    coverage_state TEXT NOT NULL,
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    PRIMARY KEY (report_id, observation_ordinal, ordinal),
    UNIQUE (report_id, observation_ordinal, coverage_kind),
    FOREIGN KEY (report_id, observation_ordinal) REFERENCES observations(report_id, ordinal)
) STRICT;

CREATE TABLE report_errors (
    report_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    code TEXT NOT NULL,
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    PRIMARY KEY (report_id, ordinal),
    FOREIGN KEY (report_id) REFERENCES admitted_reports(report_id)
) STRICT;

CREATE TABLE evaluation_runs (
    evaluation_id TEXT PRIMARY KEY,
    evaluation_sequence INTEGER NOT NULL UNIQUE CHECK (evaluation_sequence > 0),
    detector_id TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    detector_digest TEXT NOT NULL CHECK (length(detector_digest) = 71 AND substr(detector_digest, 1, 7) = 'sha256:'),
    evaluator_artifact_digest TEXT NOT NULL CHECK (length(evaluator_artifact_digest) = 71 AND substr(evaluator_artifact_digest, 1, 7) = 'sha256:'),
    trigger_run_id TEXT,
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL CHECK (length(profile_digest) = 71 AND substr(profile_digest, 1, 7) = 'sha256:'),
    profile_semantic_id TEXT NOT NULL CHECK (length(profile_semantic_id) = 71 AND substr(profile_semantic_id, 1, 7) = 'sha256:'),
    evaluation_revision INTEGER NOT NULL CHECK (evaluation_revision > 0),
    started_at TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('condition_present', 'condition_explicitly_absent', 'cannot_evaluate')),
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    UNIQUE (detector_id, detector_version, evaluation_revision),
    FOREIGN KEY (trigger_run_id) REFERENCES watcher_runs(run_id),
    FOREIGN KEY (profile_id, profile_version, profile_digest)
        REFERENCES profile_descriptor_snapshots(profile_id, profile_version, profile_digest)
) STRICT;

CREATE TABLE evaluation_watermarks (
    evaluation_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    max_report_sequence INTEGER NOT NULL CHECK (max_report_sequence >= 0),
    watermark_received_at TEXT,
    PRIMARY KEY (evaluation_id, instance_id),
    FOREIGN KEY (evaluation_id) REFERENCES evaluation_runs(evaluation_id)
) STRICT;

CREATE TABLE refusals (
    refusal_id TEXT PRIMARY KEY,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('acquisition', 'protocol', 'admission', 'profile', 'evaluation')),
    responsible_instance_id TEXT NOT NULL,
    boundary TEXT NOT NULL,
    code TEXT NOT NULL,
    run_id TEXT,
    submission_id TEXT,
    evaluation_id TEXT,
    profile_id TEXT,
    profile_version TEXT,
    profile_digest TEXT,
    profile_semantic_id TEXT CHECK (profile_semantic_id IS NULL OR
        (length(profile_semantic_id) = 71 AND substr(profile_semantic_id, 1, 7) = 'sha256:')),
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    created_at TEXT NOT NULL,
    CHECK ((run_id IS NOT NULL AND submission_id IS NOT NULL AND evaluation_id IS NULL)
        OR (run_id IS NULL AND submission_id IS NULL AND evaluation_id IS NOT NULL)),
    FOREIGN KEY (run_id) REFERENCES watcher_runs(run_id),
    FOREIGN KEY (submission_id) REFERENCES raw_submissions(submission_id),
    FOREIGN KEY (evaluation_id) REFERENCES evaluation_runs(evaluation_id)
) STRICT;
CREATE INDEX refusals_by_instance ON refusals(responsible_instance_id, created_at);

-- The commitment is the durable identity and exact-byte promise for one
-- diagnostic execution artifact. It remains present when the separately
-- materialized bytes are unavailable. The store treats the contract bytes as
-- opaque canonical JSON; diagnostic semantics remain owned by nq-core.
CREATE TABLE diagnostic_artifact_commitments (
    artifact_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL UNIQUE CHECK (length(artifact_id) = 71 AND substr(artifact_id, 1, 7) = 'sha256:'),
    contract_schema TEXT NOT NULL CHECK (length(contract_schema) BETWEEN 1 AND 256),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (length(canonical_bytes_sha256) = 71 AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'),
    canonical_bytes_length INTEGER NOT NULL CHECK (canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216),
    committed_at TEXT NOT NULL
) STRICT;

-- Exact bytes are a materialization of the immutable commitment. They are
-- split deliberately so a missing materialization remains distinguishable
-- from an artifact identity that never existed. Product code never updates
-- these bytes; a later archive/prune protocol may remove and rematerialize
-- them without rewriting the commitment.
CREATE TABLE diagnostic_artifact_payloads (
    artifact_id TEXT PRIMARY KEY,
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0 AND length(canonical_bytes) <= 16777216),
    FOREIGN KEY (artifact_id) REFERENCES diagnostic_artifact_commitments(artifact_id)
) STRICT;

-- A local artifact is bound to the exact run committed in the same
-- collection transaction. Admitted/evaluated artifacts also name their exact
-- evaluation; run-bearing non-success artifacts deliberately leave it null.
CREATE TABLE local_diagnostic_artifact_origins (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    evaluation_id TEXT UNIQUE,
    completed_at TEXT NOT NULL,
    execution_binding_record_id TEXT,
    outer_request_record_id TEXT,
    invocation_decision_record_id TEXT,
    execution_launch_record_id TEXT,
    outer_request_id TEXT,
    CHECK (
        (execution_binding_record_id IS NULL
         AND outer_request_record_id IS NULL
         AND invocation_decision_record_id IS NULL
         AND execution_launch_record_id IS NULL
         AND outer_request_id IS NULL)
        OR
        (execution_binding_record_id IS NOT NULL
         AND outer_request_record_id IS NOT NULL
         AND invocation_decision_record_id IS NOT NULL
         AND execution_launch_record_id IS NOT NULL
         AND outer_request_id IS NOT NULL)
    ),
    FOREIGN KEY (artifact_id) REFERENCES diagnostic_artifact_commitments(artifact_id),
    FOREIGN KEY (run_id) REFERENCES watcher_runs(run_id),
    FOREIGN KEY (evaluation_id) REFERENCES evaluation_runs(evaluation_id),
    FOREIGN KEY (execution_binding_record_id)
        REFERENCES runtime_record_ledger(record_id),
    FOREIGN KEY (outer_request_record_id)
        REFERENCES runtime_record_ledger(record_id),
    FOREIGN KEY (invocation_decision_record_id)
        REFERENCES runtime_record_ledger(record_id),
    FOREIGN KEY (execution_launch_record_id)
        REFERENCES runtime_record_ledger(record_id)
) STRICT;
CREATE UNIQUE INDEX local_diagnostic_artifact_origins_by_execution_binding
    ON local_diagnostic_artifact_origins(execution_binding_record_id)
    WHERE execution_binding_record_id IS NOT NULL;
CREATE UNIQUE INDEX local_diagnostic_artifact_origins_by_outer_request_record
    ON local_diagnostic_artifact_origins(outer_request_record_id)
    WHERE outer_request_record_id IS NOT NULL;
CREATE UNIQUE INDEX local_diagnostic_artifact_origins_by_invocation_decision
    ON local_diagnostic_artifact_origins(invocation_decision_record_id)
    WHERE invocation_decision_record_id IS NOT NULL;
CREATE UNIQUE INDEX local_diagnostic_artifact_origins_by_execution_launch
    ON local_diagnostic_artifact_origins(execution_launch_record_id)
    WHERE execution_launch_record_id IS NOT NULL;
CREATE UNIQUE INDEX local_diagnostic_artifact_origins_by_outer_request_id
    ON local_diagnostic_artifact_origins(outer_request_id)
    WHERE outer_request_id IS NOT NULL;

CREATE TABLE diagnostic_artifact_import_events (
    import_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id TEXT NOT NULL UNIQUE CHECK (length(import_id) BETWEEN 1 AND 256),
    artifact_id TEXT NOT NULL,
    contract_schema TEXT NOT NULL CHECK (length(contract_schema) BETWEEN 1 AND 256),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (length(canonical_bytes_sha256) = 71 AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'),
    canonical_bytes_length INTEGER NOT NULL CHECK (canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216),
    outcome TEXT NOT NULL CHECK (outcome IN
        ('committed', 'committed_unavailable', 'existing', 'rematerialized')),
    imported_at TEXT NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES diagnostic_artifact_commitments(artifact_id)
) STRICT;

-- Imported artifacts receive custody only. The import identity and time do not
-- authenticate the producer or grant reliance, standing, or authority.
CREATE TABLE imported_diagnostic_artifact_origins (
    artifact_id TEXT PRIMARY KEY,
    import_id TEXT NOT NULL UNIQUE,
    imported_at TEXT NOT NULL,
    initial_outcome TEXT NOT NULL CHECK (initial_outcome IN
        ('committed', 'committed_unavailable')),
    FOREIGN KEY (artifact_id) REFERENCES diagnostic_artifact_commitments(artifact_id),
    FOREIGN KEY (import_id) REFERENCES diagnostic_artifact_import_events(import_id)
) STRICT;

CREATE TABLE finding_events (
    event_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    event_revision INTEGER NOT NULL CHECK (event_revision > 0),
    event_kind TEXT NOT NULL CHECK (event_kind IN ('opened', 'updated', 'resolved', 'reopened', 'operator_updated')),
    evaluation_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    -- The detector *semantic* id (descriptor digest covers the threshold since
    -- slice 1); a canonical ordered-set digest when several detectors judge one
    -- finding. This is evaluation-seam identity, distinct from report admission.
    detector_digest TEXT NOT NULL CHECK (length(detector_digest) = 71 AND substr(detector_digest, 1, 7) = 'sha256:'),
    -- Artifact digest of the running evaluator (nqd) that produced this finding.
    evaluator_artifact_digest TEXT NOT NULL CHECK (length(evaluator_artifact_digest) = 71 AND substr(evaluator_artifact_digest, 1, 7) = 'sha256:'),
    evaluation_revision INTEGER NOT NULL CHECK (evaluation_revision > 0),
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL CHECK (length(profile_digest) = 71 AND substr(profile_digest, 1, 7) = 'sha256:'),
    subject_json BLOB NOT NULL CHECK (json_valid(CAST(subject_json AS TEXT))),
    condition_name TEXT NOT NULL,
    condition_state TEXT NOT NULL CHECK (condition_state IN ('present', 'explicitly_absent', 'cannot_evaluate')),
    visibility_state TEXT NOT NULL CHECK (visibility_state IN ('sufficient', 'partial', 'stale', 'missing', 'refused')),
    operator_work_state TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    limitations_json BLOB NOT NULL CHECK (json_valid(CAST(limitations_json AS TEXT))),
    safe_next_checks_json BLOB NOT NULL CHECK (json_valid(CAST(safe_next_checks_json AS TEXT))),
    freshness_json BLOB NOT NULL CHECK (json_valid(CAST(freshness_json AS TEXT))),
    basis_json BLOB NOT NULL CHECK (json_valid(CAST(basis_json AS TEXT))),
    refusal_json BLOB CHECK (refusal_json IS NULL OR json_valid(CAST(refusal_json AS TEXT))),
    origin_mode TEXT NOT NULL,
    historical_refs_json BLOB NOT NULL CHECK (json_valid(CAST(historical_refs_json AS TEXT))),
    observed_at TEXT,
    received_at TEXT,
    evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (finding_id, event_revision),
    CHECK (event_kind <> 'resolved'
        OR (condition_state = 'explicitly_absent' AND visibility_state = 'sufficient')),
    FOREIGN KEY (evaluation_id) REFERENCES evaluation_runs(evaluation_id),
    FOREIGN KEY (profile_id, profile_version, profile_digest)
        REFERENCES profile_descriptor_snapshots(profile_id, profile_version, profile_digest)
) STRICT;
CREATE INDEX finding_events_by_finding ON finding_events(finding_id, event_revision);

CREATE TABLE finding_evidence (
    event_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    report_id TEXT NOT NULL,
    report_semantic_digest TEXT NOT NULL CHECK (length(report_semantic_digest) = 71 AND substr(report_semantic_digest, 1, 7) = 'sha256:'),
    observation_ordinal INTEGER,
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY (event_id, ordinal),
    FOREIGN KEY (event_id) REFERENCES finding_events(event_id),
    FOREIGN KEY (report_id, report_semantic_digest)
        REFERENCES admitted_reports(report_id, semantic_digest)
) STRICT;

-- This is a rebuildable projection. All source history remains in finding_events.
CREATE TABLE finding_current (
    finding_id TEXT PRIMARY KEY,
    latest_event_id TEXT NOT NULL UNIQUE,
    FOREIGN KEY (latest_event_id) REFERENCES finding_events(event_id)
) STRICT;

CREATE TABLE notification_outbox (
    notification_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    finding_event_id TEXT,
    destination_kind TEXT NOT NULL,
    payload_json BLOB NOT NULL CHECK (json_valid(CAST(payload_json AS TEXT))),
    available_at TEXT NOT NULL,
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY (finding_event_id) REFERENCES finding_events(event_id)
) STRICT;

CREATE TABLE notification_attempts (
    notification_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    attempted_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('delivered', 'failed', 'retryable')),
    delivery_identity TEXT,
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    PRIMARY KEY (notification_id, attempt_number),
    FOREIGN KEY (notification_id) REFERENCES notification_outbox(notification_id)
) STRICT;

CREATE TABLE retention_tombstones (
    tombstone_id TEXT PRIMARY KEY,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_digest TEXT,
    reason_code TEXT NOT NULL,
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    created_at TEXT NOT NULL,
    UNIQUE (target_kind, target_id, tombstone_id)
) STRICT;

CREATE TABLE genesis_records (
    genesis_id TEXT PRIMARY KEY,
    legacy_manifest_digest TEXT CHECK (legacy_manifest_digest IS NULL OR (length(legacy_manifest_digest) = 71 AND substr(legacy_manifest_digest, 1, 7) = 'sha256:')),
    created_at TEXT NOT NULL,
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT)))
) STRICT;

CREATE TABLE legacy_references (
    legacy_reference_id TEXT PRIMARY KEY,
    genesis_id TEXT NOT NULL,
    reference_uri TEXT NOT NULL UNIQUE CHECK (reference_uri LIKE 'legacy-nq://%'),
    artifact_digest TEXT CHECK (artifact_digest IS NULL OR (length(artifact_digest) = 71 AND substr(artifact_digest, 1, 7) = 'sha256:')),
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    created_at TEXT NOT NULL,
    FOREIGN KEY (genesis_id) REFERENCES genesis_records(genesis_id)
) STRICT;

CREATE TABLE upgrade_receipts (
    receipt_id TEXT PRIMARY KEY,
    from_schema_version INTEGER NOT NULL CHECK (from_schema_version >= 0),
    to_schema_version INTEGER NOT NULL CHECK (to_schema_version >= 0),
    migrations_json BLOB NOT NULL CHECK (json_valid(CAST(migrations_json AS TEXT))),
    binary_digest TEXT NOT NULL CHECK (length(binary_digest) = 71 AND substr(binary_digest, 1, 7) = 'sha256:'),
    backup_digest TEXT NOT NULL CHECK (length(backup_digest) = 71 AND substr(backup_digest, 1, 7) = 'sha256:'),
    backup_location TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    result TEXT NOT NULL,
    operator_identity_json BLOB NOT NULL CHECK (json_valid(CAST(operator_identity_json AS TEXT))),
    verification_json BLOB NOT NULL CHECK (json_valid(CAST(verification_json AS TEXT)))
) STRICT;

-- One canonical, globally sequenced ledger for host-role runtime records.
-- The record bytes are the governed fact. Checkpoints bind one atomic append;
-- runtime_record_lookup is only a disposable lookup accelerator.
CREATE TABLE runtime_record_checkpoints (
    checkpoint_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_id TEXT NOT NULL UNIQUE CHECK (length(checkpoint_id) BETWEEN 1 AND 256),
    batch_digest TEXT NOT NULL CHECK (length(batch_digest) = 71 AND substr(batch_digest, 1, 7) = 'sha256:'),
    first_record_sequence INTEGER NOT NULL CHECK (first_record_sequence > 0),
    last_record_sequence INTEGER NOT NULL CHECK (last_record_sequence >= first_record_sequence),
    record_count INTEGER NOT NULL CHECK (
        record_count > 0
        AND record_count = last_record_sequence - first_record_sequence + 1
    ),
    predecessor_checkpoint_id TEXT,
    predecessor_ledger_root TEXT CHECK (
        predecessor_ledger_root IS NULL
        OR (length(predecessor_ledger_root) = 71 AND substr(predecessor_ledger_root, 1, 7) = 'sha256:')
    ),
    checkpoint_ledger_root TEXT NOT NULL UNIQUE CHECK (
        length(checkpoint_ledger_root) = 71
        AND substr(checkpoint_ledger_root, 1, 7) = 'sha256:'
    ),
    committed_at TEXT NOT NULL,
    CHECK (
        (checkpoint_sequence = 1
         AND predecessor_checkpoint_id IS NULL
         AND predecessor_ledger_root IS NULL)
        OR
        (checkpoint_sequence > 1
         AND predecessor_checkpoint_id IS NOT NULL
         AND predecessor_ledger_root IS NOT NULL)
    ),
    FOREIGN KEY (predecessor_checkpoint_id)
        REFERENCES runtime_record_checkpoints(checkpoint_id)
) STRICT;

-- One immutable dependency-admission trust root for this store occurrence.
-- It is established separately from every dependency generation so retained
-- closure bytes cannot select the key under which they are authenticated.
-- Protecting the complete SQLite store against coordinated offline
-- substitution remains a deployment/custody responsibility.
CREATE TABLE runtime_dependency_trust_roots (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    trust_anchor_id TEXT NOT NULL CHECK (
        length(trust_anchor_id) = 71
        AND substr(trust_anchor_id, 1, 7) = 'sha256:'
    ),
    established_at TEXT NOT NULL
) STRICT;

-- C1 Gen4 authority custody is native and separate from the generic runtime
-- record ledger.  Genesis A1/A2 remain in the exact external custody bundle;
-- every post-genesis authority event is retained in one family-specific table.
CREATE TABLE runtime_operator_authority_rotations (
    authority_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL UNIQUE CHECK (
        length(record_id) = 71 AND substr(record_id, 1, 7) = 'sha256:'
    ),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 16777216
    ),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216
    ),
    committed_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length)
) STRICT;

CREATE TABLE runtime_resident_activation_successors (
    activation_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL UNIQUE CHECK (
        length(record_id) = 71 AND substr(record_id, 1, 7) = 'sha256:'
    ),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 16777216
    ),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216
    ),
    committed_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length)
) STRICT;

CREATE TABLE runtime_activation_revocations (
    revocation_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL UNIQUE CHECK (
        length(record_id) = 71 AND substr(record_id, 1, 7) = 'sha256:'
    ),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 16777216
    ),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216
    ),
    committed_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length)
) STRICT;

CREATE TABLE runtime_dependency_establishment_receipts (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(receipt_id) = 71 AND substr(receipt_id, 1, 7) = 'sha256:'
    ),
    root_singleton INTEGER NOT NULL UNIQUE CHECK (root_singleton = 1),
    occurrence_id TEXT NOT NULL CHECK (
        length(occurrence_id) BETWEEN 1 AND 256
    ),
    genesis_activation_digest TEXT NOT NULL CHECK (
        length(genesis_activation_digest) = 71
        AND substr(genesis_activation_digest, 1, 7) = 'sha256:'
    ),
    controlling_tip_digest TEXT NOT NULL CHECK (
        length(controlling_tip_digest) = 71
        AND substr(controlling_tip_digest, 1, 7) = 'sha256:'
    ),
    trust_anchor_id TEXT NOT NULL CHECK (
        length(trust_anchor_id) = 71
        AND substr(trust_anchor_id, 1, 7) = 'sha256:'
    ),
    a1_genesis_identity TEXT NOT NULL CHECK (
        length(a1_genesis_identity) = 71
        AND substr(a1_genesis_identity, 1, 7) = 'sha256:'
    ),
    a1_key_generation INTEGER NOT NULL CHECK (a1_key_generation > 0),
    domain TEXT NOT NULL CHECK (length(domain) BETWEEN 1 AND 256),
    establishment_cut INTEGER NOT NULL CHECK (establishment_cut >= 0),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    establishment_arm TEXT NOT NULL CHECK (
        establishment_arm IN ('genesis', 'migration')
    ),
    migration_receipt_digest TEXT CHECK (
        migration_receipt_digest IS NULL
        OR (length(migration_receipt_digest) = 71
            AND substr(migration_receipt_digest, 1, 7) = 'sha256:')
    ),
    candidate_set_digest TEXT NOT NULL CHECK (
        length(candidate_set_digest) = 71
        AND substr(candidate_set_digest, 1, 7) = 'sha256:'
    ),
    canonical_transcript BLOB NOT NULL CHECK (
        length(canonical_transcript) > 0
        AND length(canonical_transcript) <= 16777216
    ),
    canonical_transcript_sha256 TEXT NOT NULL CHECK (
        length(canonical_transcript_sha256) = 71
        AND substr(canonical_transcript_sha256, 1, 7) = 'sha256:'
    ),
    canonical_transcript_length INTEGER NOT NULL CHECK (
        canonical_transcript_length > 0
        AND canonical_transcript_length <= 16777216
    ),
    established_at TEXT NOT NULL,
    CHECK (length(canonical_transcript) = canonical_transcript_length),
    CHECK (
        (establishment_arm = 'genesis' AND migration_receipt_digest IS NULL)
        OR
        (establishment_arm = 'migration' AND migration_receipt_digest IS NOT NULL)
    ),
    FOREIGN KEY (root_singleton) REFERENCES runtime_dependency_trust_roots(singleton)
) STRICT;

CREATE TABLE runtime_migration_receipt_consumptions (
    migration_receipt_digest TEXT PRIMARY KEY CHECK (
        length(migration_receipt_digest) = 71
        AND substr(migration_receipt_digest, 1, 7) = 'sha256:'
    ),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 16777216
    ),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216
    ),
    establishment_receipt_id TEXT NOT NULL UNIQUE,
    consumed_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    FOREIGN KEY (establishment_receipt_id)
        REFERENCES runtime_dependency_establishment_receipts(receipt_id)
) STRICT;

-- Successful classification of a non-accepted migration disposition.  This
-- freezes evidence but establishes no runtime authority.
CREATE TABLE runtime_migration_disposition_freezes (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    migration_receipt_digest TEXT NOT NULL UNIQUE CHECK (
        length(migration_receipt_digest) = 71
        AND substr(migration_receipt_digest, 1, 7) = 'sha256:'
    ),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    disposition TEXT NOT NULL CHECK (
        disposition IN ('observed', 'superseded', 'refused')
    ),
    source_logical_digest TEXT NOT NULL CHECK (
        length(source_logical_digest) = 71
        AND substr(source_logical_digest, 1, 7) = 'sha256:'
    ),
    candidate_set_digest TEXT NOT NULL CHECK (
        length(candidate_set_digest) = 71
        AND substr(candidate_set_digest, 1, 7) = 'sha256:'
    ),
    restore_declaration_digest TEXT CHECK (
        restore_declaration_digest IS NULL
        OR (length(restore_declaration_digest) = 71
            AND substr(restore_declaration_digest, 1, 7) = 'sha256:')
    ),
    restore_proof_digest TEXT CHECK (
        restore_proof_digest IS NULL
        OR (length(restore_proof_digest) = 71
            AND substr(restore_proof_digest, 1, 7) = 'sha256:')
    ),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 16777216
    ),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216
    ),
    classified_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (
        (restore_declaration_digest IS NULL AND restore_proof_digest IS NULL)
        OR
        (restore_declaration_digest IS NOT NULL AND restore_proof_digest IS NOT NULL)
    )
) STRICT;

CREATE TABLE runtime_v7_cardinality_disposition_freezes (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    disposition_digest TEXT NOT NULL UNIQUE CHECK (
        length(disposition_digest) = 71
        AND substr(disposition_digest, 1, 7) = 'sha256:'
    ),
    disposition TEXT NOT NULL CHECK (
        disposition IN ('observed', 'superseded', 'refused')
    ),
    genesis_identities BLOB NOT NULL CHECK (
        length(genesis_identities) > 0
        AND length(genesis_identities) <= 16777216
        AND json_valid(CAST(genesis_identities AS TEXT))
    ),
    source_logical_digest TEXT NOT NULL CHECK (
        length(source_logical_digest) = 71
        AND substr(source_logical_digest, 1, 7) = 'sha256:'
    ),
    old_root_kind TEXT NOT NULL CHECK (old_root_kind IN ('rooted', 'rootless')),
    old_root_digest TEXT CHECK (
        old_root_digest IS NULL
        OR (length(old_root_digest) = 71
            AND substr(old_root_digest, 1, 7) = 'sha256:')
    ),
    domain TEXT NOT NULL CHECK (length(domain) BETWEEN 1 AND 256),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    operator_authority_digest TEXT NOT NULL CHECK (
        length(operator_authority_digest) = 71
        AND substr(operator_authority_digest, 1, 7) = 'sha256:'
    ),
    operator_key_generation INTEGER NOT NULL CHECK (operator_key_generation > 0),
    restore_declaration_digest TEXT CHECK (
        restore_declaration_digest IS NULL
        OR (length(restore_declaration_digest) = 71
            AND substr(restore_declaration_digest, 1, 7) = 'sha256:')
    ),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 16777216
    ),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216
    ),
    classified_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (
        (old_root_kind = 'rootless' AND old_root_digest IS NULL)
        OR
        (old_root_kind = 'rooted' AND old_root_digest IS NOT NULL)
    )
) STRICT;

-- Exact authenticated dependency closures are committed independently of
-- their current byte availability. A generation is deduplicated by its
-- semantic identity; byte identity and trust-anchor identity are immutable.
CREATE TABLE runtime_dependency_generation_commitments (
    dependency_generation_id TEXT PRIMARY KEY CHECK (
        length(dependency_generation_id) = 71
        AND substr(dependency_generation_id, 1, 7) = 'sha256:'
    ),
    trust_anchor_id TEXT NOT NULL CHECK (
        length(trust_anchor_id) = 71
        AND substr(trust_anchor_id, 1, 7) = 'sha256:'
    ),
    custody_schema TEXT NOT NULL CHECK (
        custody_schema = 'nq.host_role_runtime_dependency_generation_custody.v1'
    ),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0
        AND canonical_bytes_length <= 16777216
    ),
    committed_at TEXT NOT NULL,
    UNIQUE (
        dependency_generation_id,
        trust_anchor_id,
        canonical_bytes_sha256
    )
) STRICT;

-- Exact bytes are a materialization of the immutable dependency commitment.
-- Their absence means committed-unavailable, never an invitation to use a
-- caller's current dependency generation.
CREATE TABLE runtime_dependency_generation_payloads (
    dependency_generation_id TEXT PRIMARY KEY,
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0
        AND length(canonical_bytes) <= 16777216
        AND json_valid(CAST(canonical_bytes AS TEXT))
    ),
    FOREIGN KEY (dependency_generation_id)
        REFERENCES runtime_dependency_generation_commitments(dependency_generation_id)
) STRICT;

-- Every schema-v7 checkpoint has one exact authenticated dependency binding.
-- Schema-v6 checkpoints receive only an explicit legacy-unbound
-- classification during the v6-to-v7 migration; no provenance is invented.
CREATE TABLE runtime_checkpoint_dependency_bindings (
    checkpoint_id TEXT PRIMARY KEY,
    binding_state TEXT NOT NULL CHECK (
        binding_state IN ('authenticated', 'legacy_unbound')
    ),
    dependency_generation_id TEXT,
    trust_anchor_id TEXT,
    canonical_bytes_sha256 TEXT,
    source_schema_version INTEGER,
    CHECK (
        (binding_state = 'authenticated'
         AND dependency_generation_id IS NOT NULL
         AND trust_anchor_id IS NOT NULL
         AND canonical_bytes_sha256 IS NOT NULL
         AND source_schema_version IS NULL)
        OR
        (binding_state = 'legacy_unbound'
         AND dependency_generation_id IS NULL
         AND trust_anchor_id IS NULL
         AND canonical_bytes_sha256 IS NULL
         AND source_schema_version = 6)
    ),
    FOREIGN KEY (checkpoint_id)
        REFERENCES runtime_record_checkpoints(checkpoint_id),
    FOREIGN KEY (
        dependency_generation_id,
        trust_anchor_id,
        canonical_bytes_sha256
    ) REFERENCES runtime_dependency_generation_commitments (
        dependency_generation_id,
        trust_anchor_id,
        canonical_bytes_sha256
    )
) STRICT;

-- Present only on a database migrated from schema v6. It freezes exactly
-- which checkpoint prefix lacked authenticated dependency provenance before
-- schema v7 existed.
CREATE TABLE runtime_dependency_binding_migration_boundaries (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    source_schema_version INTEGER NOT NULL CHECK (source_schema_version = 6),
    source_schema_artifact_digest TEXT NOT NULL CHECK (
        length(source_schema_artifact_digest) = 71
        AND substr(source_schema_artifact_digest, 1, 7) = 'sha256:'
    ),
    legacy_checkpoint_count INTEGER NOT NULL CHECK (legacy_checkpoint_count >= 0),
    legacy_last_checkpoint_id TEXT,
    legacy_last_checkpoint_root TEXT,
    classified_at TEXT NOT NULL,
    CHECK (
        (legacy_checkpoint_count = 0
         AND legacy_last_checkpoint_id IS NULL
         AND legacy_last_checkpoint_root IS NULL)
        OR
        (legacy_checkpoint_count > 0
         AND legacy_last_checkpoint_id IS NOT NULL
         AND legacy_last_checkpoint_root IS NOT NULL)
    )
) STRICT;

CREATE TABLE runtime_record_ledger (
    record_sequence INTEGER PRIMARY KEY,
    record_id TEXT NOT NULL UNIQUE CHECK (length(record_id) BETWEEN 1 AND 256),
    record_schema TEXT NOT NULL CHECK (length(record_schema) BETWEEN 1 AND 256),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) <= 1048576
        AND json_valid(CAST(canonical_bytes AS TEXT))
    ),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    checkpoint_id TEXT NOT NULL,
    predecessor_record_id TEXT,
    predecessor_ledger_root TEXT CHECK (
        predecessor_ledger_root IS NULL
        OR (length(predecessor_ledger_root) = 71 AND substr(predecessor_ledger_root, 1, 7) = 'sha256:')
    ),
    ledger_root TEXT NOT NULL UNIQUE CHECK (
        length(ledger_root) = 71
        AND substr(ledger_root, 1, 7) = 'sha256:'
    ),
    committed_at TEXT NOT NULL,
    CHECK (
        (record_sequence = 1
         AND predecessor_record_id IS NULL
         AND predecessor_ledger_root IS NULL)
        OR
        (record_sequence > 1
         AND predecessor_record_id IS NOT NULL
         AND predecessor_ledger_root IS NOT NULL)
    ),
    FOREIGN KEY (checkpoint_id)
        REFERENCES runtime_record_checkpoints(checkpoint_id),
    FOREIGN KEY (predecessor_record_id)
        REFERENCES runtime_record_ledger(record_id)
) STRICT;

-- Rebuildable projection. Canonical reads verify this index against the
-- append-only ledger before using it; deleting or corrupting it cannot change
-- runtime-record truth.
CREATE TABLE runtime_record_lookup (
    record_id TEXT PRIMARY KEY,
    record_sequence INTEGER NOT NULL UNIQUE,
    record_schema TEXT NOT NULL,
    ledger_root TEXT NOT NULL,
    FOREIGN KEY (record_sequence)
        REFERENCES runtime_record_ledger(record_sequence)
) STRICT;
CREATE INDEX runtime_record_lookup_by_schema
    ON runtime_record_lookup(record_schema, record_sequence);

CREATE TABLE local_diagnostic_artifact_provider_attempt_bindings (
    artifact_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    provider_attempt_record_id TEXT NOT NULL UNIQUE,
    intake_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (artifact_id, ordinal),
    FOREIGN KEY (artifact_id)
        REFERENCES local_diagnostic_artifact_origins(artifact_id),
    FOREIGN KEY (provider_attempt_record_id)
        REFERENCES runtime_record_ledger(record_id),
    FOREIGN KEY (intake_id)
        REFERENCES provider_intake_attempts(intake_id)
) STRICT;

CREATE TABLE status_events (
    status_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    status_event_id TEXT NOT NULL UNIQUE,
    component_kind TEXT NOT NULL CHECK (component_kind IN
        ('daemon', 'database', 'profile_catalog', 'admission', 'scheduler', 'instance', 'diagnostic_execution', 'evaluation', 'notification')),
    component_id TEXT NOT NULL,
    -- Present exactly for canonical results of completed watcher runs,
    -- including admitted reports. A governed run-level result is keyed to its
    -- diagnostic execution instead of being projected into instance health.
    -- Admission refusals and non-run operational status have no run identity.
    run_id TEXT,
    state TEXT NOT NULL,
    code TEXT NOT NULL,
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    observed_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES watcher_runs(run_id)
) STRICT;
CREATE INDEX status_events_by_component
    ON status_events(component_kind, component_id, status_sequence);
CREATE UNIQUE INDEX status_events_by_run
    ON status_events(run_id) WHERE run_id IS NOT NULL;

-- NQ issues this receipt only after the exact attempt and its canonical
-- downstream result have been assembled in one transaction. Returning the row
-- occurs only after COMMIT; the receipt establishes durable processing, never
-- report admission, detector state, health, testimony, or authority.
CREATE TABLE provider_intake_acknowledgments (
    acknowledgment_id TEXT PRIMARY KEY,
    intake_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL UNIQUE,
    provider_admission_id TEXT NOT NULL,
    status_event_id TEXT NOT NULL UNIQUE,
    schema_id TEXT NOT NULL CHECK (schema_id = 'nq.provider_intake_ack.v1'),
    detail_json BLOB NOT NULL CHECK (length(detail_json) <= 1048576 AND json_valid(CAST(detail_json AS TEXT))),
    acknowledgment_digest TEXT NOT NULL CHECK (length(acknowledgment_digest) = 71 AND substr(acknowledgment_digest, 1, 7) = 'sha256:'),
    committed_at TEXT NOT NULL,
    FOREIGN KEY (intake_id) REFERENCES provider_intake_attempts(intake_id),
    FOREIGN KEY (run_id) REFERENCES watcher_runs(run_id),
    FOREIGN KEY (provider_admission_id) REFERENCES local_provider_admissions(provider_admission_id),
    FOREIGN KEY (status_event_id) REFERENCES status_events(status_event_id)
) STRICT;

-- This is a rebuildable projection. All source history remains in status_events.
CREATE TABLE status_current (
    component_kind TEXT NOT NULL,
    component_id TEXT NOT NULL,
    latest_status_event_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (component_kind, component_id),
    FOREIGN KEY (latest_status_event_id) REFERENCES status_events(status_event_id)
) STRICT;

CREATE VIEW public_finding_snapshot_v3 AS
SELECT
    f.finding_id,
    e.instance_id,
    e.detector_id,
    e.detector_version,
    e.detector_digest,
    e.evaluation_revision,
    evaluation.profile_id,
    evaluation.profile_version,
    evaluation.profile_digest,
    evaluation.profile_semantic_id,
    CAST(e.subject_json AS TEXT) AS subject_json,
    e.condition_name,
    e.condition_state,
    e.visibility_state,
    e.operator_work_state,
    e.severity,
    e.summary,
    CAST(e.limitations_json AS TEXT) AS limitations_json,
    CAST(e.safe_next_checks_json AS TEXT) AS safe_next_checks_json,
    CAST(e.freshness_json AS TEXT) AS freshness_json,
    CAST(e.basis_json AS TEXT) AS basis_json,
    CAST(e.refusal_json AS TEXT) AS refusal_json,
    e.origin_mode,
    CAST(e.historical_refs_json AS TEXT) AS historical_refs_json,
    e.observed_at,
    e.received_at,
    e.evaluated_at,
    e.evaluation_id,
    (
        SELECT CAST(refusal.detail_json AS TEXT)
        FROM refusals AS refusal
        WHERE refusal.evaluation_id = e.evaluation_id
    ) AS evaluation_refusal_json,
    COALESCE((
        SELECT json_group_array(json_object(
            'report_id', ordered.report_id,
            'semantic_digest', ordered.report_semantic_digest,
            'observation_ordinal', ordered.observation_ordinal,
            'observed_at', ordered.observed_at,
            'received_at', ordered.received_at
        ))
        FROM (
            SELECT report_id, report_semantic_digest, observation_ordinal, observed_at, received_at
            FROM finding_evidence
            WHERE event_id = e.event_id
            ORDER BY ordinal
        ) AS ordered
    ), '[]') AS evidence_json
FROM finding_current AS f
JOIN finding_events AS e ON e.event_id = f.latest_event_id
JOIN evaluation_runs AS evaluation ON evaluation.evaluation_id = e.evaluation_id;

CREATE VIEW public_status_snapshot_v1 AS
SELECT
    c.component_kind,
    c.component_id,
    e.state,
    e.code,
    CAST(e.detail_json AS TEXT) AS detail_json,
    e.observed_at
FROM status_current AS c
JOIN status_events AS e ON e.status_event_id = c.latest_status_event_id;

CREATE VIEW public_notification_status_v1 AS
SELECT
    o.notification_id,
    o.idempotency_key,
    o.destination_kind,
    o.available_at,
    o.max_attempts,
    COUNT(a.attempt_number) AS attempt_count,
    CASE
        WHEN MAX(CASE WHEN a.outcome = 'delivered' THEN 1 ELSE 0 END) = 1 THEN 'delivered'
        WHEN COUNT(a.attempt_number) >= o.max_attempts THEN 'failed'
        WHEN COUNT(a.attempt_number) = 0 THEN 'pending'
        ELSE 'pending'
    END AS delivery_state
FROM notification_outbox AS o
LEFT JOIN notification_attempts AS a ON a.notification_id = o.notification_id
GROUP BY o.notification_id;

-- Durable facts are append-only. finding_current, status_current, and
-- runtime_record_lookup are the only mutable tables; they are rebuildable
-- projections over immutable event streams.
CREATE TRIGGER immutable_schema_metadata_update BEFORE UPDATE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_schema_metadata_delete BEFORE DELETE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_profile_descriptor_snapshots_update BEFORE UPDATE ON profile_descriptor_snapshots BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_profile_descriptor_snapshots_delete BEFORE DELETE ON profile_descriptor_snapshots BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_admission_records_update BEFORE UPDATE ON admission_records BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_admission_records_delete BEFORE DELETE ON admission_records BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_provider_admissions_update BEFORE UPDATE ON local_provider_admissions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_provider_admissions_delete BEFORE DELETE ON local_provider_admissions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_instance_binding_events_update BEFORE UPDATE ON instance_binding_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_instance_binding_events_delete BEFORE DELETE ON instance_binding_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_binding_materialization_events_update BEFORE UPDATE ON binding_materialization_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_binding_materialization_events_delete BEFORE DELETE ON binding_materialization_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_watcher_runs_update BEFORE UPDATE ON watcher_runs BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_watcher_runs_delete BEFORE DELETE ON watcher_runs BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_attempts_update BEFORE UPDATE ON provider_intake_attempts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_attempts_delete BEFORE DELETE ON provider_intake_attempts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_watcher_provider_intakes_update BEFORE UPDATE ON local_watcher_provider_intakes BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_watcher_provider_intakes_delete BEFORE DELETE ON local_watcher_provider_intakes BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_legacy_v3_watcher_run_intake_gaps_update BEFORE UPDATE ON legacy_v3_watcher_run_intake_gaps BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_legacy_v3_watcher_run_intake_gaps_delete BEFORE DELETE ON legacy_v3_watcher_run_intake_gaps BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_raw_submissions_update BEFORE UPDATE ON raw_submissions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_raw_submissions_delete BEFORE DELETE ON raw_submissions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_admitted_reports_update BEFORE UPDATE ON admitted_reports BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_admitted_reports_delete BEFORE DELETE ON admitted_reports BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_observations_update BEFORE UPDATE ON observations BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_observations_delete BEFORE DELETE ON observations BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_report_coverage_update BEFORE UPDATE ON report_coverage BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_report_coverage_delete BEFORE DELETE ON report_coverage BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_observation_coverage_update BEFORE UPDATE ON observation_coverage BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_observation_coverage_delete BEFORE DELETE ON observation_coverage BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_report_errors_update BEFORE UPDATE ON report_errors BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_report_errors_delete BEFORE DELETE ON report_errors BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_evaluation_runs_update BEFORE UPDATE ON evaluation_runs BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_evaluation_runs_delete BEFORE DELETE ON evaluation_runs BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_evaluation_watermarks_update BEFORE UPDATE ON evaluation_watermarks BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_evaluation_watermarks_delete BEFORE DELETE ON evaluation_watermarks BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_refusals_update BEFORE UPDATE ON refusals BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_refusals_delete BEFORE DELETE ON refusals BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_diagnostic_artifact_commitments_update BEFORE UPDATE ON diagnostic_artifact_commitments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_diagnostic_artifact_commitments_delete BEFORE DELETE ON diagnostic_artifact_commitments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_diagnostic_artifact_payloads_update BEFORE UPDATE ON diagnostic_artifact_payloads BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_diagnostic_artifact_payloads_delete BEFORE DELETE ON diagnostic_artifact_payloads BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_diagnostic_artifact_origins_update BEFORE UPDATE ON local_diagnostic_artifact_origins BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_diagnostic_artifact_origins_delete BEFORE DELETE ON local_diagnostic_artifact_origins BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_diagnostic_artifact_import_events_update BEFORE UPDATE ON diagnostic_artifact_import_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_diagnostic_artifact_import_events_delete BEFORE DELETE ON diagnostic_artifact_import_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_imported_diagnostic_artifact_origins_update BEFORE UPDATE ON imported_diagnostic_artifact_origins BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_imported_diagnostic_artifact_origins_delete BEFORE DELETE ON imported_diagnostic_artifact_origins BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_finding_events_update BEFORE UPDATE ON finding_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_finding_events_delete BEFORE DELETE ON finding_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_finding_evidence_update BEFORE UPDATE ON finding_evidence BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_finding_evidence_delete BEFORE DELETE ON finding_evidence BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_notification_outbox_update BEFORE UPDATE ON notification_outbox BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_notification_outbox_delete BEFORE DELETE ON notification_outbox BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_notification_attempts_update BEFORE UPDATE ON notification_attempts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_notification_attempts_delete BEFORE DELETE ON notification_attempts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_retention_tombstones_update BEFORE UPDATE ON retention_tombstones BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_retention_tombstones_delete BEFORE DELETE ON retention_tombstones BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_genesis_records_update BEFORE UPDATE ON genesis_records BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_genesis_records_delete BEFORE DELETE ON genesis_records BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_legacy_references_update BEFORE UPDATE ON legacy_references BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_legacy_references_delete BEFORE DELETE ON legacy_references BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_upgrade_receipts_update BEFORE UPDATE ON upgrade_receipts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_upgrade_receipts_delete BEFORE DELETE ON upgrade_receipts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_record_checkpoints_update BEFORE UPDATE ON runtime_record_checkpoints BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_record_checkpoints_delete BEFORE DELETE ON runtime_record_checkpoints BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_trust_roots_update BEFORE UPDATE ON runtime_dependency_trust_roots BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_trust_roots_delete BEFORE DELETE ON runtime_dependency_trust_roots BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_operator_authority_rotations_update BEFORE UPDATE ON runtime_operator_authority_rotations BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_operator_authority_rotations_delete BEFORE DELETE ON runtime_operator_authority_rotations BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_resident_activation_successors_update BEFORE UPDATE ON runtime_resident_activation_successors BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_resident_activation_successors_delete BEFORE DELETE ON runtime_resident_activation_successors BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_activation_revocations_update BEFORE UPDATE ON runtime_activation_revocations BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_activation_revocations_delete BEFORE DELETE ON runtime_activation_revocations BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_establishment_receipts_update BEFORE UPDATE ON runtime_dependency_establishment_receipts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_establishment_receipts_delete BEFORE DELETE ON runtime_dependency_establishment_receipts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_migration_receipt_consumptions_update BEFORE UPDATE ON runtime_migration_receipt_consumptions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_migration_receipt_consumptions_delete BEFORE DELETE ON runtime_migration_receipt_consumptions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_migration_disposition_freezes_update BEFORE UPDATE ON runtime_migration_disposition_freezes BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_migration_disposition_freezes_delete BEFORE DELETE ON runtime_migration_disposition_freezes BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_v7_cardinality_disposition_freezes_update BEFORE UPDATE ON runtime_v7_cardinality_disposition_freezes BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_v7_cardinality_disposition_freezes_delete BEFORE DELETE ON runtime_v7_cardinality_disposition_freezes BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_generation_commitments_update BEFORE UPDATE ON runtime_dependency_generation_commitments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_generation_commitments_delete BEFORE DELETE ON runtime_dependency_generation_commitments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_generation_payloads_update BEFORE UPDATE ON runtime_dependency_generation_payloads BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_generation_payloads_delete BEFORE DELETE ON runtime_dependency_generation_payloads BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_checkpoint_dependency_bindings_update BEFORE UPDATE ON runtime_checkpoint_dependency_bindings BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_checkpoint_dependency_bindings_delete BEFORE DELETE ON runtime_checkpoint_dependency_bindings BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_binding_migration_boundaries_update BEFORE UPDATE ON runtime_dependency_binding_migration_boundaries BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_binding_migration_boundaries_delete BEFORE DELETE ON runtime_dependency_binding_migration_boundaries BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_record_ledger_update BEFORE UPDATE ON runtime_record_ledger BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_record_ledger_delete BEFORE DELETE ON runtime_record_ledger BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_diagnostic_artifact_provider_attempt_bindings_update BEFORE UPDATE ON local_diagnostic_artifact_provider_attempt_bindings BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_diagnostic_artifact_provider_attempt_bindings_delete BEFORE DELETE ON local_diagnostic_artifact_provider_attempt_bindings BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_status_events_update BEFORE UPDATE ON status_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_status_events_delete BEFORE DELETE ON status_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_acknowledgments_update BEFORE UPDATE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_acknowledgments_delete BEFORE DELETE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
-- C1 Gen5 / C2 schema-v8 to schema-v9 projection migration.
--
-- Canonical C2 authority remains in the authenticated B/G carriers.  These
-- two SQLite tables are disposable, rebuildable projections only.  They do
-- not construct a Store generation, signer standing, currentness, B/G
-- authority, or a writer session.

CREATE TABLE c2_installation_projection (
    projection_identity TEXT PRIMARY KEY CHECK (
        length(projection_identity) = 71
        AND substr(projection_identity, 1, 7) = 'sha256:'
    ),
    schema_id TEXT NOT NULL CHECK (
        schema_id = 'nq.c2_installation_projection.v1'
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    physical_store_generation_identity TEXT NOT NULL UNIQUE CHECK (
        length(physical_store_generation_identity) = 71
        AND substr(physical_store_generation_identity, 1, 7) = 'sha256:'
    ),
    bootstrap_identity TEXT NOT NULL UNIQUE CHECK (
        length(bootstrap_identity) = 71
        AND substr(bootstrap_identity, 1, 7) = 'sha256:'
    ),
    installation_nonce TEXT NOT NULL CHECK (
        length(installation_nonce) = 64
        AND installation_nonce NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state = 'pending'),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0
        AND length(canonical_bytes) <= 1048576
        AND json_valid(CAST(canonical_bytes AS TEXT))
    ),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 1048576
    ),
    projected_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.schema')
        = 'nq.c2_installation_projection.v1'),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.schema_version') = 1),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.projection_identity')
        = projection_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.occurrence_id')
        = occurrence_id),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.physical_store_generation_identity')
        = physical_store_generation_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.bootstrap_identity')
        = bootstrap_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.installation_nonce')
        = installation_nonce),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.state') = state)
) STRICT;

CREATE TABLE c2_installation_receipt_index (
    installation_receipt_identity TEXT PRIMARY KEY CHECK (
        length(installation_receipt_identity) = 71
        AND substr(installation_receipt_identity, 1, 7) = 'sha256:'
    ),
    physical_store_generation_identity TEXT NOT NULL UNIQUE CHECK (
        length(physical_store_generation_identity) = 71
        AND substr(physical_store_generation_identity, 1, 7) = 'sha256:'
    ),
    installation_intent_identity TEXT NOT NULL UNIQUE CHECK (
        length(installation_intent_identity) = 71
        AND substr(installation_intent_identity, 1, 7) = 'sha256:'
    ),
    bootstrap_identity TEXT NOT NULL UNIQUE CHECK (
        length(bootstrap_identity) = 71
        AND substr(bootstrap_identity, 1, 7) = 'sha256:'
    ),
    pending_projection_identity TEXT NOT NULL UNIQUE CHECK (
        length(pending_projection_identity) = 71
        AND substr(pending_projection_identity, 1, 7) = 'sha256:'
    ),
    pre_receipt_b_root_identity TEXT NOT NULL CHECK (
        length(pre_receipt_b_root_identity) = 71
        AND substr(pre_receipt_b_root_identity, 1, 7) = 'sha256:'
    ),
    pre_receipt_b_cursor INTEGER NOT NULL CHECK (pre_receipt_b_cursor >= 0),
    g_root_identity TEXT NOT NULL CHECK (
        length(g_root_identity) = 71
        AND substr(g_root_identity, 1, 7) = 'sha256:'
    ),
    g_cursor INTEGER NOT NULL CHECK (g_cursor >= 0),
    completion_state TEXT NOT NULL CHECK (completion_state = 'complete'),
    canonical_receipt_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_receipt_sha256) = 71
        AND substr(canonical_receipt_sha256, 1, 7) = 'sha256:'
    ),
    indexed_at TEXT NOT NULL,
    FOREIGN KEY (pending_projection_identity)
        REFERENCES c2_installation_projection(projection_identity),
    FOREIGN KEY (physical_store_generation_identity)
        REFERENCES c2_installation_projection(physical_store_generation_identity),
    FOREIGN KEY (bootstrap_identity)
        REFERENCES c2_installation_projection(bootstrap_identity)
) STRICT;

-- Projection rows are append-only.  Their absence is rebuildable; a present
-- mismatch is a refusal and is never repaired by an in-place rewrite.
CREATE TRIGGER immutable_c2_installation_projection_update
BEFORE UPDATE ON c2_installation_projection
BEGIN
    SELECT RAISE(ABORT, 'c2 installation projection is append-only');
END;

CREATE TRIGGER immutable_c2_installation_projection_delete
BEFORE DELETE ON c2_installation_projection
BEGIN
    SELECT RAISE(ABORT, 'c2 installation projection is append-only');
END;

CREATE TRIGGER immutable_c2_installation_receipt_index_update
BEFORE UPDATE ON c2_installation_receipt_index
BEGIN
    SELECT RAISE(ABORT, 'c2 installation receipt index is append-only');
END;

CREATE TRIGGER immutable_c2_installation_receipt_index_delete
BEFORE DELETE ON c2_installation_receipt_index
BEGIN
    SELECT RAISE(ABORT, 'c2 installation receipt index is append-only');
END;

-- Unsigned MSG-04 bootstrap-to-generation relation.  This is canonical inert
-- evidence consumed by the generation-current resolver; it is deliberately
-- outside the signer-message ledger and has no signature/domain column.
CREATE TABLE c2_signer_bootstrap_transition (
    relation_identity TEXT PRIMARY KEY CHECK (
        length(relation_identity) = 71
        AND substr(relation_identity, 1, 7) = 'sha256:'
    ),
    schema_id TEXT NOT NULL CHECK (
        schema_id = 'nq.c2_signer_bootstrap_transition.v1'
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    identity_domain TEXT NOT NULL CHECK (
        identity_domain = 'nq.c2.signer_bootstrap_transition.identity.v1'
    ),
    bootstrap_grant_identity TEXT NOT NULL CHECK (
        length(bootstrap_grant_identity) = 71
        AND substr(bootstrap_grant_identity, 1, 7) = 'sha256:'
    ),
    foundational_enrollment_identity TEXT NOT NULL CHECK (
        length(foundational_enrollment_identity) = 71
        AND substr(foundational_enrollment_identity, 1, 7) = 'sha256:'
    ),
    signer_enrollment_identity TEXT NOT NULL UNIQUE CHECK (
        length(signer_enrollment_identity) = 71
        AND substr(signer_enrollment_identity, 1, 7) = 'sha256:'
    ),
    initial_pop_identity TEXT NOT NULL UNIQUE CHECK (
        length(initial_pop_identity) = 71
        AND substr(initial_pop_identity, 1, 7) = 'sha256:'
    ),
    physical_generation_bootstrap_identity TEXT NOT NULL UNIQUE CHECK (
        length(physical_generation_bootstrap_identity) = 71
        AND substr(physical_generation_bootstrap_identity, 1, 7) = 'sha256:'
    ),
    generation_commitment_identity TEXT NOT NULL UNIQUE CHECK (
        length(generation_commitment_identity) = 71
        AND substr(generation_commitment_identity, 1, 7) = 'sha256:'
    ),
    installation_receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(installation_receipt_identity) = 71
        AND substr(installation_receipt_identity, 1, 7) = 'sha256:'
    ),
    physical_store_generation_identity TEXT NOT NULL UNIQUE CHECK (
        length(physical_store_generation_identity) = 71
        AND substr(physical_store_generation_identity, 1, 7) = 'sha256:'
    ),
    transition_cut INTEGER NOT NULL CHECK (
        transition_cut > 0 AND transition_cut <= 9007199254740991
    ),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0
        AND length(canonical_bytes) <= 1048576
        AND json_valid(CAST(canonical_bytes AS TEXT))
    ),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 1048576
    ),
    derived_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.schema') = schema_id),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.schema_version') = schema_version),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.identity_domain') = identity_domain),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.relation_identity') = relation_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.bootstrap_grant_identity') = bootstrap_grant_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.foundational_enrollment_identity') = foundational_enrollment_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.signer_enrollment_identity') = signer_enrollment_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.initial_pop_identity') = initial_pop_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.physical_generation_bootstrap_identity') = physical_generation_bootstrap_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.generation_commitment_identity') = generation_commitment_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.installation_receipt_identity') = installation_receipt_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.physical_store_generation_identity') = physical_store_generation_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.transition_cut') = transition_cut),
    FOREIGN KEY (installation_receipt_identity)
        REFERENCES c2_installation_receipt_index(installation_receipt_identity),
    FOREIGN KEY (physical_store_generation_identity)
        REFERENCES c2_installation_receipt_index(physical_store_generation_identity)
) STRICT;

CREATE TRIGGER immutable_c2_signer_bootstrap_transition_update
BEFORE UPDATE ON c2_signer_bootstrap_transition
BEGIN
    SELECT RAISE(ABORT, 'unsigned MSG-04 bootstrap transition is append-only');
END;

CREATE TRIGGER immutable_c2_signer_bootstrap_transition_delete
BEFORE DELETE ON c2_signer_bootstrap_transition
BEGIN
    SELECT RAISE(ABORT, 'unsigned MSG-04 bootstrap transition is append-only');
END;

-- C1 Gen5 / C2 signer-lineage projection for schema v9.
--
-- Authenticated B records remain canonical.  These append-only tables retain
-- exact, independently verifiable projections and never select a signer by
-- maximum cut, insertion order, key generation, or lexical identity.

CREATE TABLE c2_signer_root_binding_projection (
    root_binding_identity TEXT PRIMARY KEY CHECK (
        length(root_binding_identity) = 71
        AND substr(root_binding_identity, 1, 7) = 'sha256:'
    ),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    physical_store_generation_identity TEXT NOT NULL CHECK (
        length(physical_store_generation_identity) = 71
        AND substr(physical_store_generation_identity, 1, 7) = 'sha256:'
    ),
    signer_lifecycle_root_identity TEXT NOT NULL CHECK (
        length(signer_lifecycle_root_identity) = 71
        AND substr(signer_lifecycle_root_identity, 1, 7) = 'sha256:'
    ),
    initial_enrollment_identity TEXT NOT NULL CHECK (
        length(initial_enrollment_identity) = 71
        AND substr(initial_enrollment_identity, 1, 7) = 'sha256:'
    ),
    initial_key_generation INTEGER NOT NULL CHECK (initial_key_generation = 0),
    initial_public_key BLOB NOT NULL CHECK (length(initial_public_key) = 32),
    generation_genesis_identity TEXT NOT NULL CHECK (
        length(generation_genesis_identity) = 71
        AND substr(generation_genesis_identity, 1, 7) = 'sha256:'
    ),
    generation_commitment_identity TEXT NOT NULL CHECK (
        length(generation_commitment_identity) = 71
        AND substr(generation_commitment_identity, 1, 7) = 'sha256:'
    ),
    scope_identity TEXT NOT NULL CHECK (
        length(scope_identity) = 71 AND substr(scope_identity, 1, 7) = 'sha256:'
    ),
    resident_identity TEXT NOT NULL CHECK (
        length(CAST(resident_identity AS BLOB)) BETWEEN 1 AND 1024
    ),
    resident_generation INTEGER NOT NULL CHECK (resident_generation > 0),
    host_role TEXT NOT NULL CHECK (length(host_role) BETWEEN 1 AND 256),
    role_manifest_generation INTEGER NOT NULL CHECK (role_manifest_generation > 0),
    authority_domain TEXT NOT NULL CHECK (length(authority_domain) BETWEEN 1 AND 256),
    policy_lineage_root_identity TEXT NOT NULL CHECK (
        length(policy_lineage_root_identity) = 71
        AND substr(policy_lineage_root_identity, 1, 7) = 'sha256:'
    ),
    creation_cut INTEGER NOT NULL CHECK (creation_cut > 0),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 1048576
    ),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 1048576
    ),
    projected_at TEXT NOT NULL,
    UNIQUE (
        occurrence_id,
        physical_store_generation_identity,
        signer_lifecycle_root_identity,
        scope_identity
    ),
    CHECK (length(canonical_bytes) = canonical_bytes_length)
) STRICT;

CREATE TABLE c2_signer_current_binding_projection (
    current_binding_identity TEXT PRIMARY KEY CHECK (
        length(current_binding_identity) = 71
        AND substr(current_binding_identity, 1, 7) = 'sha256:'
    ),
    root_binding_identity TEXT NOT NULL CHECK (
        length(root_binding_identity) = 71
        AND substr(root_binding_identity, 1, 7) = 'sha256:'
    ),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    physical_store_generation_identity TEXT NOT NULL CHECK (
        length(physical_store_generation_identity) = 71
        AND substr(physical_store_generation_identity, 1, 7) = 'sha256:'
    ),
    signer_lifecycle_root_identity TEXT NOT NULL CHECK (
        length(signer_lifecycle_root_identity) = 71
        AND substr(signer_lifecycle_root_identity, 1, 7) = 'sha256:'
    ),
    scope_identity TEXT NOT NULL CHECK (
        length(scope_identity) = 71 AND substr(scope_identity, 1, 7) = 'sha256:'
    ),
    resident_identity TEXT NOT NULL CHECK (
        length(CAST(resident_identity AS BLOB)) BETWEEN 1 AND 1024
    ),
    resident_generation INTEGER NOT NULL CHECK (resident_generation > 0),
    host_role TEXT NOT NULL CHECK (length(host_role) BETWEEN 1 AND 256),
    role_manifest_generation INTEGER NOT NULL CHECK (role_manifest_generation > 0),
    authority_domain TEXT NOT NULL CHECK (length(authority_domain) BETWEEN 1 AND 256),
    policy_lineage_root_identity TEXT NOT NULL CHECK (
        length(policy_lineage_root_identity) = 71
        AND substr(policy_lineage_root_identity, 1, 7) = 'sha256:'
    ),
    current_enrollment_identity TEXT NOT NULL CHECK (
        length(current_enrollment_identity) = 71
        AND substr(current_enrollment_identity, 1, 7) = 'sha256:'
    ),
    current_key_generation INTEGER NOT NULL CHECK (current_key_generation >= 0),
    current_public_key BLOB NOT NULL CHECK (length(current_public_key) = 32),
    current_policy_identity TEXT NOT NULL CHECK (
        length(current_policy_identity) = 71
        AND substr(current_policy_identity, 1, 7) = 'sha256:'
    ),
    current_standing_identity TEXT NOT NULL CHECK (
        length(current_standing_identity) = 71
        AND substr(current_standing_identity, 1, 7) = 'sha256:'
    ),
    binding_mode TEXT NOT NULL CHECK (
        binding_mode IN ('initial', 'normal_successor', 'restore_successor', 'recovery_successor')
    ),
    provenance_identity TEXT NOT NULL CHECK (
        length(provenance_identity) = 71
        AND substr(provenance_identity, 1, 7) = 'sha256:'
    ),
    transition_identity TEXT CHECK (
        transition_identity IS NULL
        OR (length(transition_identity) = 71
            AND substr(transition_identity, 1, 7) = 'sha256:')
    ),
    predecessor_binding_identity TEXT CHECK (
        predecessor_binding_identity IS NULL
        OR (length(predecessor_binding_identity) = 71
            AND substr(predecessor_binding_identity, 1, 7) = 'sha256:')
    ),
    continuity_authorization_identity TEXT CHECK (
        continuity_authorization_identity IS NULL
        OR (length(continuity_authorization_identity) = 71
            AND substr(continuity_authorization_identity, 1, 7) = 'sha256:')
    ),
    restore_lineage_identity TEXT CHECK (
        restore_lineage_identity IS NULL
        OR (length(restore_lineage_identity) = 71
            AND substr(restore_lineage_identity, 1, 7) = 'sha256:')
    ),
    restore_authority_identity TEXT CHECK (
        restore_authority_identity IS NULL
        OR (length(restore_authority_identity) = 71
            AND substr(restore_authority_identity, 1, 7) = 'sha256:')
    ),
    historical_foundation_identity TEXT CHECK (
        historical_foundation_identity IS NULL
        OR (length(historical_foundation_identity) = 71
            AND substr(historical_foundation_identity, 1, 7) = 'sha256:')
    ),
    recovery_condition_identity TEXT CHECK (
        recovery_condition_identity IS NULL
        OR (length(recovery_condition_identity) = 71
            AND substr(recovery_condition_identity, 1, 7) = 'sha256:')
    ),
    recovery_authority_identity TEXT CHECK (
        recovery_authority_identity IS NULL
        OR (length(recovery_authority_identity) = 71
            AND substr(recovery_authority_identity, 1, 7) = 'sha256:')
    ),
    recovery_grant_identity TEXT CHECK (
        recovery_grant_identity IS NULL
        OR (length(recovery_grant_identity) = 71
            AND substr(recovery_grant_identity, 1, 7) = 'sha256:')
    ),
    persisted_resolution_identity TEXT NOT NULL CHECK (
        length(persisted_resolution_identity) = 71
        AND substr(persisted_resolution_identity, 1, 7) = 'sha256:'
    ),
    effective_cut INTEGER NOT NULL CHECK (effective_cut > 0),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 1048576
    ),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 1048576
    ),
    projected_at TEXT NOT NULL,
    UNIQUE (root_binding_identity, effective_cut),
    UNIQUE (root_binding_identity, persisted_resolution_identity),
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (
        (binding_mode = 'initial'
            AND current_key_generation = 0
            AND transition_identity IS NULL
            AND predecessor_binding_identity IS NULL
            AND continuity_authorization_identity IS NULL
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (binding_mode = 'normal_successor'
            AND current_key_generation > 0
            AND transition_identity IS NOT NULL
            AND predecessor_binding_identity IS NOT NULL
            AND continuity_authorization_identity IS NOT NULL
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (binding_mode = 'restore_successor'
            AND current_key_generation >= 0
            AND transition_identity IS NOT NULL
            AND predecessor_binding_identity IS NOT NULL
            AND continuity_authorization_identity IS NULL
            AND restore_lineage_identity IS NOT NULL
            AND restore_authority_identity IS NOT NULL
            AND historical_foundation_identity IS NOT NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (binding_mode = 'recovery_successor'
            -- Recovery requires a semantically new stable key-generation
            -- identity, not a globally monotone ordinal. A discontinuous new
            -- foundation may lawfully begin at generation zero.
            AND current_key_generation >= 0
            AND transition_identity IS NOT NULL
            AND predecessor_binding_identity IS NOT NULL
            AND continuity_authorization_identity IS NULL
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NOT NULL
            AND recovery_authority_identity IS NOT NULL
            AND recovery_grant_identity IS NOT NULL)
    ),
    FOREIGN KEY (root_binding_identity)
        REFERENCES c2_signer_root_binding_projection(root_binding_identity),
    FOREIGN KEY (predecessor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

CREATE TABLE c2_signer_succession_projection (
    succession_identity TEXT PRIMARY KEY CHECK (
        length(succession_identity) = 71
        AND substr(succession_identity, 1, 7) = 'sha256:'
    ),
    root_binding_identity TEXT NOT NULL,
    succession_mode TEXT NOT NULL CHECK (succession_mode IN ('normal', 'restore', 'recovery')),
    transition_identity TEXT NOT NULL UNIQUE CHECK (
        length(transition_identity) = 71
        AND substr(transition_identity, 1, 7) = 'sha256:'
    ),
    predecessor_binding_identity TEXT NOT NULL UNIQUE,
    successor_binding_identity TEXT NOT NULL UNIQUE,
    authorization_identity TEXT NOT NULL UNIQUE CHECK (
        length(authorization_identity) = 71
        AND substr(authorization_identity, 1, 7) = 'sha256:'
    ),
    restore_lineage_identity TEXT UNIQUE,
    restore_authority_identity TEXT UNIQUE,
    historical_foundation_identity TEXT,
    recovery_condition_identity TEXT UNIQUE,
    recovery_authority_identity TEXT UNIQUE,
    recovery_grant_identity TEXT UNIQUE,
    proposal_identity TEXT NOT NULL CHECK (
        length(proposal_identity) = 71
        AND substr(proposal_identity, 1, 7) = 'sha256:'
    ),
    successor_pop_identity TEXT NOT NULL CHECK (
        length(successor_pop_identity) = 71
        AND substr(successor_pop_identity, 1, 7) = 'sha256:'
    ),
    completion_identity TEXT NOT NULL UNIQUE CHECK (
        length(completion_identity) = 71
        AND substr(completion_identity, 1, 7) = 'sha256:'
    ),
    receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(receipt_identity) = 71
        AND substr(receipt_identity, 1, 7) = 'sha256:'
    ),
    append_identity TEXT NOT NULL UNIQUE CHECK (
        length(append_identity) = 71
        AND substr(append_identity, 1, 7) = 'sha256:'
    ),
    persisted_resolution_identity TEXT NOT NULL UNIQUE CHECK (
        length(persisted_resolution_identity) = 71
        AND substr(persisted_resolution_identity, 1, 7) = 'sha256:'
    ),
    predecessor_cut INTEGER NOT NULL CHECK (predecessor_cut > 0),
    successor_cut INTEGER NOT NULL CHECK (successor_cut > predecessor_cut),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 2097152
    ),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 2097152
    ),
    projected_at TEXT NOT NULL,
    CHECK (predecessor_binding_identity <> successor_binding_identity),
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (
        (succession_mode = 'normal'
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (succession_mode = 'restore'
            AND restore_lineage_identity IS NOT NULL
            AND restore_authority_identity IS NOT NULL
            AND historical_foundation_identity IS NOT NULL
            AND length(restore_lineage_identity) = 71
            AND substr(restore_lineage_identity, 1, 7) = 'sha256:'
            AND length(restore_authority_identity) = 71
            AND substr(restore_authority_identity, 1, 7) = 'sha256:'
            AND length(historical_foundation_identity) = 71
            AND substr(historical_foundation_identity, 1, 7) = 'sha256:'
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (succession_mode = 'recovery'
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NOT NULL
            AND recovery_authority_identity IS NOT NULL
            AND recovery_grant_identity IS NOT NULL
            AND length(recovery_condition_identity) = 71
            AND substr(recovery_condition_identity, 1, 7) = 'sha256:'
            AND length(recovery_authority_identity) = 71
            AND substr(recovery_authority_identity, 1, 7) = 'sha256:'
            AND length(recovery_grant_identity) = 71
            AND substr(recovery_grant_identity, 1, 7) = 'sha256:')
    ),
    FOREIGN KEY (root_binding_identity)
        REFERENCES c2_signer_root_binding_projection(root_binding_identity),
    FOREIGN KEY (predecessor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity),
    FOREIGN KEY (successor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

CREATE TABLE c2_signer_lineage_projection (
    lineage_identity TEXT PRIMARY KEY CHECK (
        length(lineage_identity) = 71
        AND substr(lineage_identity, 1, 7) = 'sha256:'
    ),
    root_binding_identity TEXT NOT NULL,
    initial_binding_identity TEXT NOT NULL,
    terminal_binding_identity TEXT NOT NULL,
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    terminal_candidate_set_identity TEXT NOT NULL CHECK (
        length(terminal_candidate_set_identity) = 71
        AND substr(terminal_candidate_set_identity, 1, 7) = 'sha256:'
    ),
    effective_cut INTEGER NOT NULL CHECK (effective_cut > 0),
    -- A complete proof-relevant lineage grows with arbitrary finite depth.
    -- No fixed fixture-depth or compaction bound is introduced here.
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (canonical_bytes_length > 0),
    projected_at TEXT NOT NULL,
    UNIQUE (root_binding_identity, terminal_binding_identity),
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (edge_count > 0 OR initial_binding_identity = terminal_binding_identity),
    FOREIGN KEY (root_binding_identity)
        REFERENCES c2_signer_root_binding_projection(root_binding_identity),
    FOREIGN KEY (initial_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity),
    FOREIGN KEY (terminal_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

CREATE TABLE c2_signer_lineage_edge_projection (
    lineage_identity TEXT NOT NULL,
    edge_ordinal INTEGER NOT NULL CHECK (edge_ordinal >= 0),
    succession_identity TEXT NOT NULL,
    predecessor_binding_identity TEXT NOT NULL,
    successor_binding_identity TEXT NOT NULL,
    succession_mode TEXT NOT NULL CHECK (succession_mode IN ('normal', 'restore', 'recovery')),
    PRIMARY KEY (lineage_identity, edge_ordinal),
    UNIQUE (lineage_identity, succession_identity),
    UNIQUE (lineage_identity, predecessor_binding_identity),
    UNIQUE (lineage_identity, successor_binding_identity),
    FOREIGN KEY (lineage_identity)
        REFERENCES c2_signer_lineage_projection(lineage_identity),
    FOREIGN KEY (succession_identity)
        REFERENCES c2_signer_succession_projection(succession_identity),
    FOREIGN KEY (predecessor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity),
    FOREIGN KEY (successor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

CREATE TABLE c2_signer_lineage_completion_projection (
    lineage_identity TEXT PRIMARY KEY,
    completion_identity TEXT NOT NULL UNIQUE CHECK (
        length(completion_identity) = 71
        AND substr(completion_identity, 1, 7) = 'sha256:'
    ),
    root_binding_identity TEXT NOT NULL,
    terminal_binding_identity TEXT NOT NULL,
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    completed_at TEXT NOT NULL,
    FOREIGN KEY (lineage_identity)
        REFERENCES c2_signer_lineage_projection(lineage_identity),
    FOREIGN KEY (root_binding_identity)
        REFERENCES c2_signer_root_binding_projection(root_binding_identity),
    FOREIGN KEY (terminal_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

-- Every current binding must repeat the exact immutable root coordinates.
CREATE TRIGGER c2_signer_current_binding_root_correspondence
BEFORE INSERT ON c2_signer_current_binding_projection
WHEN NOT EXISTS (
    SELECT 1 FROM c2_signer_root_binding_projection AS root
    WHERE root.root_binding_identity = NEW.root_binding_identity
      AND root.occurrence_id = NEW.occurrence_id
      AND root.physical_store_generation_identity = NEW.physical_store_generation_identity
      AND root.signer_lifecycle_root_identity = NEW.signer_lifecycle_root_identity
      AND root.scope_identity = NEW.scope_identity
      AND root.resident_identity = NEW.resident_identity
      AND root.resident_generation = NEW.resident_generation
      AND root.host_role = NEW.host_role
      AND root.role_manifest_generation = NEW.role_manifest_generation
      AND root.authority_domain = NEW.authority_domain
      AND root.policy_lineage_root_identity = NEW.policy_lineage_root_identity
      AND (NEW.binding_mode <> 'initial'
        OR (root.initial_enrollment_identity = NEW.current_enrollment_identity
          AND root.initial_key_generation = NEW.current_key_generation
          AND root.initial_public_key = NEW.current_public_key))
)
BEGIN
    SELECT RAISE(ABORT, 'current binding does not correspond to immutable signer root');
END;

-- A succession is one exact adjacent edge under one immutable root.
CREATE TRIGGER c2_signer_succession_exact_bindings
BEFORE INSERT ON c2_signer_succession_projection
WHEN NOT EXISTS (
    SELECT 1
    FROM c2_signer_current_binding_projection AS predecessor
    JOIN c2_signer_current_binding_projection AS successor
      ON successor.current_binding_identity = NEW.successor_binding_identity
    WHERE predecessor.current_binding_identity = NEW.predecessor_binding_identity
      AND predecessor.root_binding_identity = NEW.root_binding_identity
      AND successor.root_binding_identity = NEW.root_binding_identity
      AND predecessor.effective_cut = NEW.predecessor_cut
      AND successor.effective_cut = NEW.successor_cut
      AND successor.predecessor_binding_identity = predecessor.current_binding_identity
      AND successor.transition_identity = NEW.transition_identity
      AND successor.persisted_resolution_identity = NEW.persisted_resolution_identity
      AND ((NEW.succession_mode = 'normal'
            AND successor.binding_mode = 'normal_successor'
            AND successor.continuity_authorization_identity = NEW.authorization_identity)
        OR (NEW.succession_mode = 'restore'
            AND successor.binding_mode = 'restore_successor'
            AND successor.restore_lineage_identity = NEW.restore_lineage_identity
            AND successor.restore_authority_identity = NEW.restore_authority_identity
            AND successor.historical_foundation_identity = NEW.historical_foundation_identity
            AND NEW.authorization_identity = NEW.restore_authority_identity)
        OR (NEW.succession_mode = 'recovery'
            AND successor.binding_mode = 'recovery_successor'
            AND successor.recovery_condition_identity = NEW.recovery_condition_identity
            AND successor.recovery_authority_identity = NEW.recovery_authority_identity
            AND successor.recovery_grant_identity = NEW.recovery_grant_identity))
)
BEGIN
    SELECT RAISE(ABORT, 'succession does not bind exact adjacent predecessor and successor');
END;

-- Edge zero consumes the declared initial binding.  Every later edge consumes
-- exactly the immediately preceding successor; ordering or sorting cannot
-- manufacture adjacency.
CREATE TRIGGER c2_signer_lineage_edge_zero_exact_initial
BEFORE INSERT ON c2_signer_lineage_edge_projection
WHEN NEW.edge_ordinal = 0 AND NOT EXISTS (
    SELECT 1
    FROM c2_signer_lineage_projection AS lineage
    JOIN c2_signer_succession_projection AS succession
      ON succession.succession_identity = NEW.succession_identity
    WHERE lineage.lineage_identity = NEW.lineage_identity
      AND lineage.edge_count > 0
      AND NEW.edge_ordinal < lineage.edge_count
      AND lineage.root_binding_identity = succession.root_binding_identity
      AND lineage.initial_binding_identity = NEW.predecessor_binding_identity
      AND succession.predecessor_binding_identity = NEW.predecessor_binding_identity
      AND succession.successor_binding_identity = NEW.successor_binding_identity
      AND succession.succession_mode = NEW.succession_mode
)
BEGIN
    SELECT RAISE(ABORT, 'first lineage edge does not consume exact initial binding');
END;

CREATE TRIGGER c2_signer_lineage_edge_exact_previous_terminal
BEFORE INSERT ON c2_signer_lineage_edge_projection
WHEN NEW.edge_ordinal > 0 AND NOT EXISTS (
    SELECT 1
    FROM c2_signer_lineage_projection AS lineage
    JOIN c2_signer_lineage_edge_projection AS previous
      ON previous.lineage_identity = NEW.lineage_identity
     AND previous.edge_ordinal = NEW.edge_ordinal - 1
    JOIN c2_signer_succession_projection AS succession
      ON succession.succession_identity = NEW.succession_identity
    WHERE lineage.lineage_identity = NEW.lineage_identity
      AND NEW.edge_ordinal < lineage.edge_count
      AND lineage.root_binding_identity = succession.root_binding_identity
      AND previous.successor_binding_identity = NEW.predecessor_binding_identity
      AND succession.predecessor_binding_identity = NEW.predecessor_binding_identity
      AND succession.successor_binding_identity = NEW.successor_binding_identity
      AND succession.succession_mode = NEW.succession_mode
)
BEGIN
    SELECT RAISE(ABORT, 'lineage edge does not consume exact previous terminal binding');
END;

-- Completion can be projected only for a complete zero-edge lineage or for a
-- gap-free exact edge sequence whose last successor is the declared terminal.
CREATE TRIGGER c2_signer_lineage_completion_exact
BEFORE INSERT ON c2_signer_lineage_completion_projection
WHEN NOT EXISTS (
    SELECT 1 FROM c2_signer_lineage_projection AS lineage
    WHERE lineage.lineage_identity = NEW.lineage_identity
      AND lineage.root_binding_identity = NEW.root_binding_identity
      AND lineage.terminal_binding_identity = NEW.terminal_binding_identity
      AND lineage.edge_count = NEW.edge_count
      AND (
        (lineage.edge_count = 0
          AND lineage.initial_binding_identity = lineage.terminal_binding_identity
          AND NOT EXISTS (
              SELECT 1 FROM c2_signer_lineage_edge_projection AS edge
              WHERE edge.lineage_identity = lineage.lineage_identity
          ))
        OR
        (lineage.edge_count > 0
          AND (SELECT COUNT(*) FROM c2_signer_lineage_edge_projection AS edge
               WHERE edge.lineage_identity = lineage.lineage_identity) = lineage.edge_count
          AND EXISTS (
              SELECT 1 FROM c2_signer_lineage_edge_projection AS edge
              WHERE edge.lineage_identity = lineage.lineage_identity
                AND edge.edge_ordinal = lineage.edge_count - 1
                AND edge.successor_binding_identity = lineage.terminal_binding_identity
          ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'lineage completion has a gap, fork, mismatch, or incomplete terminal');
END;

-- Every signer projection is immutable.  Malformed or incomplete material is
-- refused; SQL never silently repairs, deletes, or chooses among candidates.
CREATE TRIGGER immutable_c2_signer_root_binding_update BEFORE UPDATE ON c2_signer_root_binding_projection BEGIN SELECT RAISE(ABORT, 'append-only signer root projection'); END;
CREATE TRIGGER immutable_c2_signer_root_binding_delete BEFORE DELETE ON c2_signer_root_binding_projection BEGIN SELECT RAISE(ABORT, 'append-only signer root projection'); END;
CREATE TRIGGER immutable_c2_signer_current_binding_update BEFORE UPDATE ON c2_signer_current_binding_projection BEGIN SELECT RAISE(ABORT, 'append-only current binding projection'); END;
CREATE TRIGGER immutable_c2_signer_current_binding_delete BEFORE DELETE ON c2_signer_current_binding_projection BEGIN SELECT RAISE(ABORT, 'append-only current binding projection'); END;
CREATE TRIGGER immutable_c2_signer_succession_update BEFORE UPDATE ON c2_signer_succession_projection BEGIN SELECT RAISE(ABORT, 'append-only succession projection'); END;
CREATE TRIGGER immutable_c2_signer_succession_delete BEFORE DELETE ON c2_signer_succession_projection BEGIN SELECT RAISE(ABORT, 'append-only succession projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_update BEFORE UPDATE ON c2_signer_lineage_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_delete BEFORE DELETE ON c2_signer_lineage_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_edge_update BEFORE UPDATE ON c2_signer_lineage_edge_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage edge projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_edge_delete BEFORE DELETE ON c2_signer_lineage_edge_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage edge projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_completion_update BEFORE UPDATE ON c2_signer_lineage_completion_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage completion projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_completion_delete BEFORE DELETE ON c2_signer_lineage_completion_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage completion projection'); END;
-- Durable Store-owned pre-generation custody/proposal frontier.  Rows are
-- immutable evidence only: ordinals and digests cannot construct custody or
-- signer standing.  The live Store actor recomputes the complete frontier,
-- reopens the fixed NOFOLLOW custody carrier, and mints fresh process-local
-- custody before any authority-bearing use.
CREATE TABLE c2_custody_proposal_preparations (
    preparation_identity TEXT PRIMARY KEY CHECK (
        length(preparation_identity) = 71 AND substr(preparation_identity, 1, 7) = 'sha256:'
    ),
    -- Custody preparation exists only when a stable foundation is created.
    -- Restore reuses the exact preparation of the historical foundation and
    -- therefore never creates a `restoreHistorical` preparation row.
    preparation_lineage TEXT NOT NULL CHECK (preparation_lineage IN (
        'initialExternal', 'ordinarySuccessorContinuity',
        'recoveryNewFoundation'
    )),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    scope_token TEXT NOT NULL CHECK (
        length(scope_token) = 71 AND substr(scope_token, 1, 7) = 'sha256:'
    ),
    proposal_ordinal INTEGER NOT NULL CHECK (
        proposal_ordinal > 0 AND proposal_ordinal <= 9007199254740991
    ),
    predecessor_frontier_identity TEXT NOT NULL CHECK (
        length(predecessor_frontier_identity) = 71
        AND substr(predecessor_frontier_identity, 1, 7) = 'sha256:'
    ),
    resulting_frontier_identity TEXT NOT NULL UNIQUE CHECK (
        length(resulting_frontier_identity) = 71
        AND substr(resulting_frontier_identity, 1, 7) = 'sha256:'
    ),
    proposal_identity TEXT NOT NULL UNIQUE CHECK (
        length(proposal_identity) = 71 AND substr(proposal_identity, 1, 7) = 'sha256:'
    ),
    proposal_canonical_bytes BLOB NOT NULL CHECK (
        length(proposal_canonical_bytes) > 0
        AND length(proposal_canonical_bytes) <= 1048576
        AND json_valid(CAST(proposal_canonical_bytes AS TEXT))
    ),
    proposal_canonical_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(proposal_canonical_sha256) = 71
        AND substr(proposal_canonical_sha256, 1, 7) = 'sha256:'
    ),
    proposal_canonical_length INTEGER NOT NULL CHECK (
        proposal_canonical_length > 0 AND proposal_canonical_length <= 1048576
    ),
    bootstrap_request_identity TEXT UNIQUE CHECK (
        bootstrap_request_identity IS NULL OR (
            length(bootstrap_request_identity) = 71
            AND substr(bootstrap_request_identity, 1, 7) = 'sha256:'
        )
    ),
    bootstrap_request_canonical_bytes BLOB CHECK (
        bootstrap_request_canonical_bytes IS NULL OR (
            length(bootstrap_request_canonical_bytes) > 0
            AND length(bootstrap_request_canonical_bytes) <= 1048576
            AND json_valid(CAST(bootstrap_request_canonical_bytes AS TEXT))
        )
    ),
    bootstrap_request_canonical_sha256 TEXT UNIQUE CHECK (
        bootstrap_request_canonical_sha256 IS NULL OR (
            length(bootstrap_request_canonical_sha256) = 71
            AND substr(bootstrap_request_canonical_sha256, 1, 7) = 'sha256:'
        )
    ),
    bootstrap_request_canonical_length INTEGER CHECK (
        bootstrap_request_canonical_length IS NULL OR (
            bootstrap_request_canonical_length > 0
            AND bootstrap_request_canonical_length <= 1048576
        )
    ),
    install_policy_calculation_identity TEXT CHECK (
        install_policy_calculation_identity IS NULL OR (
            length(install_policy_calculation_identity) = 71
            AND substr(install_policy_calculation_identity, 1, 7) = 'sha256:'
        )
    ),
    install_policy_calculation_canonical_bytes BLOB CHECK (
        install_policy_calculation_canonical_bytes IS NULL OR (
            length(install_policy_calculation_canonical_bytes) > 0
            AND length(install_policy_calculation_canonical_bytes) <= 1048576
            AND json_valid(CAST(install_policy_calculation_canonical_bytes AS TEXT))
        )
    ),
    install_policy_calculation_canonical_sha256 TEXT CHECK (
        install_policy_calculation_canonical_sha256 IS NULL OR (
            length(install_policy_calculation_canonical_sha256) = 71
            AND substr(install_policy_calculation_canonical_sha256, 1, 7) = 'sha256:'
        )
    ),
    install_policy_calculation_canonical_length INTEGER CHECK (
        install_policy_calculation_canonical_length IS NULL OR (
            install_policy_calculation_canonical_length > 0
            AND install_policy_calculation_canonical_length <= 1048576
        )
    ),
    successor_request_identity TEXT UNIQUE CHECK (
        successor_request_identity IS NULL OR (
            length(successor_request_identity) = 71
            AND substr(successor_request_identity, 1, 7) = 'sha256:'
        )
    ),
    successor_request_canonical_bytes BLOB CHECK (
        successor_request_canonical_bytes IS NULL OR (
            length(successor_request_canonical_bytes) > 0
            AND length(successor_request_canonical_bytes) <= 1048576
            AND json_valid(CAST(successor_request_canonical_bytes AS TEXT))
        )
    ),
    successor_request_canonical_sha256 TEXT UNIQUE CHECK (
        successor_request_canonical_sha256 IS NULL OR (
            length(successor_request_canonical_sha256) = 71
            AND substr(successor_request_canonical_sha256, 1, 7) = 'sha256:'
        )
    ),
    successor_request_canonical_length INTEGER CHECK (
        successor_request_canonical_length IS NULL OR (
            successor_request_canonical_length > 0
            AND successor_request_canonical_length <= 1048576
        )
    ),
    predecessor_binding_identity TEXT CHECK (
        predecessor_binding_identity IS NULL OR (
            length(predecessor_binding_identity) = 71
            AND substr(predecessor_binding_identity, 1, 7) = 'sha256:'
        )
    ),
    transition_identity TEXT CHECK (
        transition_identity IS NULL OR (
            length(transition_identity) = 71
            AND substr(transition_identity, 1, 7) = 'sha256:'
        )
    ),
    -- Custody preparation precedes MSG-06/MSG-15 verification.  It must not
    -- serialize or predict the later live adoption authority; exact authority
    -- references belong to the append-only foundation-adoption event.
    lineage_authority_identity TEXT CHECK (
        lineage_authority_identity IS NULL OR (
            length(lineage_authority_identity) = 71
            AND substr(lineage_authority_identity, 1, 7) = 'sha256:'
        )
    ),
    historical_foundation_identity TEXT CHECK (
        historical_foundation_identity IS NULL OR (
            length(historical_foundation_identity) = 71
            AND substr(historical_foundation_identity, 1, 7) = 'sha256:'
        )
    ),
    terminal_binding_identity TEXT CHECK (
        terminal_binding_identity IS NULL OR (
            length(terminal_binding_identity) = 71
            AND substr(terminal_binding_identity, 1, 7) = 'sha256:'
        )
    ),
    implementation_manifest_identity TEXT NOT NULL CHECK (
        length(implementation_manifest_identity) = 71
        AND substr(implementation_manifest_identity, 1, 7) = 'sha256:'
    ),
    qualified_candidate_identity TEXT NOT NULL CHECK (
        length(qualified_candidate_identity) = 71
        AND substr(qualified_candidate_identity, 1, 7) = 'sha256:'
    ),
    source_tree_identity TEXT NOT NULL CHECK (
        length(source_tree_identity) = 71 AND substr(source_tree_identity, 1, 7) = 'sha256:'
    ),
    runtime_artifact_identity TEXT NOT NULL CHECK (
        length(runtime_artifact_identity) = 71
        AND substr(runtime_artifact_identity, 1, 7) = 'sha256:'
    ),
    prepared_at TEXT NOT NULL,
    UNIQUE (scope_token, proposal_ordinal),
    CHECK (length(proposal_canonical_bytes) = proposal_canonical_length),
    CHECK (bootstrap_request_canonical_bytes IS NULL
        OR length(bootstrap_request_canonical_bytes) = bootstrap_request_canonical_length),
    CHECK (install_policy_calculation_canonical_bytes IS NULL
        OR length(install_policy_calculation_canonical_bytes)
            = install_policy_calculation_canonical_length),
    CHECK (successor_request_canonical_bytes IS NULL
        OR length(successor_request_canonical_bytes) = successor_request_canonical_length),
    CHECK (json_extract(CAST(proposal_canonical_bytes AS TEXT), '$.proposal_identity')
        = proposal_identity),
    CHECK (bootstrap_request_canonical_bytes IS NULL OR
        json_extract(CAST(bootstrap_request_canonical_bytes AS TEXT), '$.grant_request_identity')
            = bootstrap_request_identity),
    CHECK (bootstrap_request_canonical_bytes IS NULL OR
        json_extract(CAST(bootstrap_request_canonical_bytes AS TEXT), '$.proposal_identity')
            = proposal_identity),
    CHECK (
        (preparation_lineage = 'initialExternal'
         AND bootstrap_request_identity IS NOT NULL
         AND bootstrap_request_canonical_bytes IS NOT NULL
         AND bootstrap_request_canonical_sha256 IS NOT NULL
         AND bootstrap_request_canonical_length IS NOT NULL
         AND install_policy_calculation_identity IS NOT NULL
         AND install_policy_calculation_canonical_bytes IS NOT NULL
         AND install_policy_calculation_canonical_sha256 IS NOT NULL
         AND install_policy_calculation_canonical_length IS NOT NULL
         AND successor_request_identity IS NULL
         AND successor_request_canonical_bytes IS NULL
         AND successor_request_canonical_sha256 IS NULL
         AND successor_request_canonical_length IS NULL
         AND predecessor_binding_identity IS NULL
         AND transition_identity IS NULL
         AND lineage_authority_identity IS NULL
         AND historical_foundation_identity IS NULL
         AND terminal_binding_identity IS NULL)
        OR
        (preparation_lineage = 'ordinarySuccessorContinuity'
         AND bootstrap_request_identity IS NULL
         AND bootstrap_request_canonical_bytes IS NULL
         AND bootstrap_request_canonical_sha256 IS NULL
         AND bootstrap_request_canonical_length IS NULL
         AND install_policy_calculation_identity IS NULL
         AND install_policy_calculation_canonical_bytes IS NULL
         AND install_policy_calculation_canonical_sha256 IS NULL
         AND install_policy_calculation_canonical_length IS NULL
         AND successor_request_identity IS NOT NULL
         AND successor_request_canonical_bytes IS NOT NULL
         AND successor_request_canonical_sha256 IS NOT NULL
         AND successor_request_canonical_length IS NOT NULL
         AND predecessor_binding_identity IS NOT NULL
         AND transition_identity IS NOT NULL
         AND lineage_authority_identity IS NULL
         AND historical_foundation_identity IS NULL
         AND terminal_binding_identity IS NULL)
        OR
        (preparation_lineage = 'recoveryNewFoundation'
         AND bootstrap_request_identity IS NULL
         AND bootstrap_request_canonical_bytes IS NULL
         AND bootstrap_request_canonical_sha256 IS NULL
         AND bootstrap_request_canonical_length IS NULL
         AND install_policy_calculation_identity IS NULL
         AND install_policy_calculation_canonical_bytes IS NULL
         AND install_policy_calculation_canonical_sha256 IS NULL
         AND install_policy_calculation_canonical_length IS NULL
         AND successor_request_identity IS NOT NULL
         AND successor_request_canonical_bytes IS NOT NULL
         AND successor_request_canonical_sha256 IS NOT NULL
         AND successor_request_canonical_length IS NOT NULL
         AND predecessor_binding_identity IS NOT NULL
         AND transition_identity IS NOT NULL
         AND lineage_authority_identity IS NULL
         AND historical_foundation_identity IS NOT NULL
         AND terminal_binding_identity IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER immutable_c2_custody_proposal_preparations_update
BEFORE UPDATE ON c2_custody_proposal_preparations
BEGIN SELECT RAISE(ABORT, 'custody proposal preparation is append-only'); END;
CREATE TRIGGER immutable_c2_custody_proposal_preparations_delete
BEFORE DELETE ON c2_custody_proposal_preparations
BEGIN SELECT RAISE(ABORT, 'custody proposal preparation is append-only'); END;

-- Durable closed-family signing ledger.  The canonical message, exact
-- signature preimage, signature, route correspondence, frontier, and effect
-- receipt commit in one SQLite transaction.  Live signer authority is never
-- serialized here.
CREATE TABLE c2_signer_message_appends (
    ledger_sequence INTEGER PRIMARY KEY CHECK (ledger_sequence > 0),
    generation_sequence INTEGER NOT NULL CHECK (generation_sequence > 0),
    append_identity TEXT NOT NULL UNIQUE CHECK (
        length(append_identity) = 71 AND substr(append_identity, 1, 7) = 'sha256:'
    ),
    message_identity BLOB NOT NULL UNIQUE CHECK (length(message_identity) = 32),
    family TEXT NOT NULL CHECK (family IN (
        'MSG-02', 'MSG-03', 'MSG-05', 'MSG-06', 'MSG-07', 'MSG-08',
        'MSG-09', 'MSG-10', 'MSG-11', 'MSG-12'
    )),
    route TEXT NOT NULL CHECK (route IN (
        'msg02_initial_pop', 'msg03_physical_generation_bootstrap',
        'msg05_active_policy_continuity', 'msg06_normal_rotation_continuity',
        'msg07_successor_pop', 'msg08_global_refusal',
        'msg09_installation_intent', 'msg10_installation_receipt',
        'msg11_policy_transition_intent', 'msg12_receipt_current',
        'msg12_receipt_pending'
    )),
    identity_domain TEXT NOT NULL,
    signature_domain TEXT NOT NULL,
    signer_phase TEXT NOT NULL CHECK (signer_phase IN (
        'proposed_initial', 'bootstrap', 'current_predecessor',
        'generation_current', 'pending_successor'
    )),
    scope_class TEXT NOT NULL CHECK (scope_class IN (
        'pre_generation', 'prospective_physical_generation', 'generation_bound'
    )),
    authority_class TEXT NOT NULL CHECK (authority_class IN (
        'proposed_key', 'bootstrap', 'current_predecessor',
        'generation_current', 'pending_successor'
    )),
    input_kind TEXT NOT NULL,
    sole_consumer TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL CHECK (signature_algorithm = 'ed25519'),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) > 0),
    occurrence_identity BLOB NOT NULL CHECK (length(occurrence_identity) = 32),
    physical_generation_identity BLOB CHECK (
        physical_generation_identity IS NULL OR length(physical_generation_identity) = 32
    ),
    lifecycle_root_identity BLOB CHECK (
        lifecycle_root_identity IS NULL OR length(lifecycle_root_identity) = 32
    ),
    prospective_generation_preimage BLOB CHECK (
        prospective_generation_preimage IS NULL OR length(prospective_generation_preimage) = 32
    ),
    scope_identity BLOB NOT NULL CHECK (length(scope_identity) = 32),
    resident_identity TEXT NOT NULL CHECK (length(resident_identity) > 0),
    resident_generation INTEGER NOT NULL CHECK (
        resident_generation > 0 AND resident_generation <= 9007199254740991
    ),
    host_role TEXT NOT NULL CHECK (length(host_role) > 0),
    role_manifest_identity BLOB NOT NULL CHECK (length(role_manifest_identity) = 32),
    role_manifest_generation INTEGER NOT NULL CHECK (
        role_manifest_generation > 0 AND role_manifest_generation <= 9007199254740991
    ),
    authority_domain TEXT NOT NULL CHECK (length(authority_domain) > 0),
    terminal_a1_identity BLOB NOT NULL CHECK (length(terminal_a1_identity) = 32),
    current_a2_snapshot_identity BLOB NOT NULL CHECK (length(current_a2_snapshot_identity) = 32),
    grant_or_predecessor_standing_identity BLOB NOT NULL CHECK (
        length(grant_or_predecessor_standing_identity) = 32
    ),
    signer_public_key BLOB NOT NULL CHECK (length(signer_public_key) = 32),
    signer_scope_policy_identity BLOB NOT NULL CHECK (length(signer_scope_policy_identity) = 32),
    signer_scope_policy_version INTEGER NOT NULL CHECK (
        signer_scope_policy_version > 0 AND signer_scope_policy_version <= 9007199254740991
    ),
    active_store_policy_identity BLOB NOT NULL CHECK (length(active_store_policy_identity) = 32),
    active_store_policy_generation INTEGER NOT NULL CHECK (
        active_store_policy_generation > 0 AND active_store_policy_generation <= 9007199254740991
    ),
    active_store_policy_digest BLOB NOT NULL CHECK (length(active_store_policy_digest) = 32),
    implementation_manifest_identity BLOB NOT NULL CHECK (length(implementation_manifest_identity) = 32),
    manifest_admission_correspondence_identity BLOB NOT NULL CHECK (length(manifest_admission_correspondence_identity) = 32),
    qualified_candidate_identity BLOB NOT NULL CHECK (length(qualified_candidate_identity) = 32),
    source_tree_identity BLOB NOT NULL CHECK (length(source_tree_identity) = 32),
    runtime_artifact_identity BLOB NOT NULL CHECK (length(runtime_artifact_identity) = 32),
    terminal_binding_identity BLOB CHECK (
        terminal_binding_identity IS NULL OR length(terminal_binding_identity) = 32
    ),
    signer_key_generation INTEGER NOT NULL CHECK (
        signer_key_generation >= 0 AND signer_key_generation <= 9007199254740991
    ),
    signer_key_generation_identity BLOB NOT NULL CHECK (length(signer_key_generation_identity) = 32),
    event_predecessor_identity BLOB NOT NULL CHECK (length(event_predecessor_identity) = 32),
    transaction_identity BLOB NOT NULL CHECK (length(transaction_identity) = 32),
    transaction_intent_identity BLOB NOT NULL CHECK (length(transaction_intent_identity) = 32),
    frontier_namespace_identity BLOB NOT NULL CHECK (length(frontier_namespace_identity) = 32),
    predecessor_frontier_identity BLOB NOT NULL CHECK (length(predecessor_frontier_identity) = 32),
    exact_content_identity BLOB NOT NULL CHECK (length(exact_content_identity) = 32),
    resulting_frontier_identity BLOB NOT NULL UNIQUE CHECK (length(resulting_frontier_identity) = 32),
    event_cut INTEGER NOT NULL CHECK (event_cut > 0 AND event_cut <= 9007199254740991),
    canonical_message BLOB NOT NULL CHECK (length(canonical_message) > 0),
    canonical_message_sha256 TEXT NOT NULL CHECK (
        length(canonical_message_sha256) = 71
        AND substr(canonical_message_sha256, 1, 7) = 'sha256:'
    ),
    signing_preimage BLOB NOT NULL CHECK (length(signing_preimage) > 0),
    signing_preimage_sha256 TEXT NOT NULL CHECK (
        length(signing_preimage_sha256) = 71
        AND substr(signing_preimage_sha256, 1, 7) = 'sha256:'
    ),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    effect_receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_receipt_identity) = 71
        AND substr(effect_receipt_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_bytes BLOB NOT NULL CHECK (length(effect_receipt_bytes) > 0),
    physical_carrier_bytes BLOB,
    physical_carrier_sha256 TEXT CHECK (
        physical_carrier_sha256 IS NULL OR (
            length(physical_carrier_sha256) = 71
            AND substr(physical_carrier_sha256, 1, 7) = 'sha256:'
        )
    ),
    physical_carrier_length INTEGER CHECK (
        physical_carrier_length IS NULL OR physical_carrier_length > 0
    ),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0),
    CHECK (
        (route = 'msg02_initial_pop'
         AND physical_carrier_bytes IS NULL
         AND physical_carrier_sha256 IS NULL
         AND physical_carrier_length IS NULL)
        OR
        (route <> 'msg02_initial_pop'
         AND physical_carrier_bytes IS NOT NULL
         AND physical_carrier_sha256 IS NOT NULL
         AND physical_carrier_length IS NOT NULL
         AND length(physical_carrier_bytes) = physical_carrier_length)
    ),
    UNIQUE (frontier_namespace_identity, generation_sequence),
    UNIQUE (route, occurrence_identity, transaction_identity)
) STRICT;

-- Registry parity is enforced again at the durable boundary.  No row may
-- relabel a family, phase, scope, authority, input, consumer, or domain.
CREATE TRIGGER c2_signer_message_registry_exact
BEFORE INSERT ON c2_signer_message_appends
WHEN NOT (
    (NEW.route = 'msg02_initial_pop' AND NEW.family = 'MSG-02'
      AND NEW.identity_domain = 'nq.c2.store_integrity_initial_pop.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_initial_pop.possession_signature.v1'
      AND NEW.signer_phase = 'proposed_initial' AND NEW.scope_class = 'pre_generation'
      AND NEW.physical_generation_identity IS NULL AND NEW.lifecycle_root_identity IS NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NULL
      AND NEW.authority_class = 'proposed_key' AND NEW.input_kind = 'initial_pop_candidate'
      AND NEW.sole_consumer = 'accepted_enrollment_wrapper')
 OR (NEW.route = 'msg03_physical_generation_bootstrap' AND NEW.family = 'MSG-03'
      AND NEW.identity_domain = 'nq.c2.store_generation.bootstrap.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_generation.bootstrap.signature.v1'
      AND NEW.signer_phase = 'bootstrap' AND NEW.scope_class = 'prospective_physical_generation'
      AND NEW.physical_generation_identity IS NULL AND NEW.lifecycle_root_identity IS NULL
      AND NEW.prospective_generation_preimage IS NOT NULL AND NEW.terminal_binding_identity IS NULL
      AND NEW.authority_class = 'bootstrap' AND NEW.input_kind = 'physical_generation_bootstrap_facts'
      AND NEW.sole_consumer = 'installation_bootstrap_append')
 OR (NEW.route = 'msg05_active_policy_continuity' AND NEW.family = 'MSG-05'
      AND NEW.identity_domain = 'nq.c2.active_policy_continuity.identity.v1'
      AND NEW.signature_domain = 'nq.c2.active_policy_continuity.current_predecessor_signature.v1'
      AND NEW.signer_phase = 'current_predecessor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'current_predecessor' AND NEW.input_kind = 'active_policy_continuity_facts'
      AND NEW.sole_consumer = 'active_policy_transition_append')
 OR (NEW.route = 'msg06_normal_rotation_continuity' AND NEW.family = 'MSG-06'
      AND NEW.identity_domain = 'nq.c2.signer_rotation_continuity.identity.v1'
      AND NEW.signature_domain = 'nq.c2.signer_rotation_continuity.current_predecessor_signature.v1'
      AND NEW.signer_phase = 'current_predecessor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'current_predecessor' AND NEW.input_kind = 'healthy_rotation_continuity_facts'
      AND NEW.sole_consumer = 'healthy_rotation_append')
 OR (NEW.route = 'msg07_successor_pop' AND NEW.family = 'MSG-07'
      AND NEW.identity_domain = 'nq.c2.store_integrity_successor_pop.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_successor_pop.pending_possession_signature.v1'
      AND NEW.signer_phase = 'pending_successor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'pending_successor' AND NEW.input_kind = 'successor_pop_challenge'
      AND NEW.sole_consumer = 'selected_successor_pop')
 OR (NEW.route = 'msg08_global_refusal' AND NEW.family = 'MSG-08'
      AND NEW.identity_domain = 'nq.c2.global_refusal.identity.v1'
      AND NEW.signature_domain = 'nq.c2.global_refusal.generation_current_signature.v1'
      AND NEW.signer_phase = 'generation_current' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'generation_current' AND NEW.input_kind = 'classified_global_refusal'
      AND NEW.sole_consumer = 'global_refusal_append')
 OR (NEW.route = 'msg09_installation_intent' AND NEW.family = 'MSG-09'
      AND NEW.identity_domain = 'nq.c2.installation_intent.identity.v1'
      AND NEW.signature_domain = 'nq.c2.installation_intent.store_integrity_signature.v1'
      AND NEW.signer_phase = 'bootstrap' AND NEW.scope_class = 'pre_generation'
      AND NEW.physical_generation_identity IS NULL AND NEW.lifecycle_root_identity IS NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NULL
      AND NEW.authority_class = 'bootstrap' AND NEW.input_kind = 'installation_intent_facts'
      AND NEW.sole_consumer = 'installation_intent_append')
 OR (NEW.route = 'msg10_installation_receipt' AND NEW.family = 'MSG-10'
      AND NEW.identity_domain = 'nq.c2.installation_receipt.identity.v1'
      AND NEW.signature_domain = 'nq.c2.installation_receipt.store_integrity_signature.v1'
      AND NEW.signer_phase = 'bootstrap' AND NEW.scope_class = 'prospective_physical_generation'
      AND NEW.physical_generation_identity IS NULL AND NEW.lifecycle_root_identity IS NULL
      AND NEW.prospective_generation_preimage IS NOT NULL AND NEW.terminal_binding_identity IS NULL
      AND NEW.authority_class = 'bootstrap' AND NEW.input_kind = 'installation_completion_facts'
      AND NEW.sole_consumer = 'bootstrap_transition_close')
 OR (NEW.route = 'msg11_policy_transition_intent' AND NEW.family = 'MSG-11'
      AND NEW.identity_domain = 'nq.c2.policy_transition_intent.identity.v1'
      AND NEW.signature_domain = 'nq.c2.policy_transition_intent.current_predecessor_signature.v1'
      AND NEW.signer_phase = 'current_predecessor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'current_predecessor' AND NEW.input_kind = 'policy_transition_intent_facts'
      AND NEW.sole_consumer = 'transition_intent_append')
 OR (NEW.route = 'msg12_receipt_current' AND NEW.family = 'MSG-12'
      AND NEW.identity_domain = 'nq.c2.policy_transition_receipt.identity.v1'
      AND NEW.signature_domain = 'nq.c2.policy_transition_receipt.generation_current_signature.v1'
      AND NEW.signer_phase = 'generation_current' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'generation_current' AND NEW.input_kind = 'transition_receipt_current_facts'
      AND NEW.sole_consumer = 'generation_current_resolution')
 OR (NEW.route = 'msg12_receipt_pending' AND NEW.family = 'MSG-12'
      AND NEW.identity_domain = 'nq.c2.policy_transition_receipt.identity.v1'
      AND NEW.signature_domain = 'nq.c2.policy_transition_receipt.pending_successor_signature.v1'
      AND NEW.signer_phase = 'pending_successor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'pending_successor' AND NEW.input_kind = 'transition_receipt_pending_facts'
      AND NEW.sole_consumer = 'pending_successor_resolution')
)
BEGIN
    SELECT RAISE(ABORT, 'signer message row disagrees with the closed MSG-01 through MSG-16 registry');
END;

-- Durable governed external-carrier ingress.  One request occurrence may have
-- exactly one canonical carrier.  Exact replay reopens this receipt; changed
-- canonical bytes at the same occurrence are a collision and cannot insert.
CREATE TABLE c2_external_carrier_ingress (
    ingress_sequence INTEGER PRIMARY KEY CHECK (ingress_sequence > 0),
    receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(receipt_identity) = 71 AND substr(receipt_identity, 1, 7) = 'sha256:'
    ),
    route TEXT NOT NULL CHECK (route IN (
        'msg01_bootstrap_grant', 'msg01_activation_successor_grant',
        'msg01_proposal_disposition', 'msg13_restore_authorization',
        'msg14_revocation_judgment', 'msg15_recovery_grant',
        'msg16_quarantine_closure'
    )),
    family TEXT NOT NULL CHECK (family IN ('MSG-01', 'MSG-13', 'MSG-14', 'MSG-15', 'MSG-16')),
    identity_domain TEXT NOT NULL,
    signature_domain TEXT NOT NULL,
    input_kind TEXT NOT NULL,
    sole_consumer TEXT NOT NULL,
    request_identity BLOB NOT NULL CHECK (length(request_identity) = 32),
    carrier_identity BLOB NOT NULL UNIQUE CHECK (length(carrier_identity) = 32),
    canonical_request BLOB NOT NULL CHECK (length(canonical_request) > 0),
    canonical_request_sha256 TEXT NOT NULL CHECK (
        length(canonical_request_sha256) = 71
        AND substr(canonical_request_sha256, 1, 7) = 'sha256:'
    ),
    canonical_carrier BLOB NOT NULL CHECK (length(canonical_carrier) > 0),
    canonical_carrier_sha256 TEXT NOT NULL CHECK (
        length(canonical_carrier_sha256) = 71
        AND substr(canonical_carrier_sha256, 1, 7) = 'sha256:'
    ),
    effect_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_identity) = 71 AND substr(effect_identity, 1, 7) = 'sha256:'
    ),
    receipt_bytes BLOB NOT NULL CHECK (length(receipt_bytes) > 0),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0),
    UNIQUE (route, request_identity)
) STRICT;

CREATE TRIGGER c2_external_carrier_registry_exact
BEFORE INSERT ON c2_external_carrier_ingress
WHEN NOT (
    (NEW.route = 'msg01_bootstrap_grant' AND NEW.family = 'MSG-01'
      AND NEW.identity_domain = 'nq.c2.store_integrity_bootstrap_grant.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_bootstrap_grant.a1_signature.v1'
      AND NEW.input_kind = 'bootstrap_grant_request' AND NEW.sole_consumer = 'reserve_bootstrap_attempt')
 OR (NEW.route = 'msg01_activation_successor_grant' AND NEW.family = 'MSG-01'
      AND NEW.identity_domain = 'nq.c2.store_integrity_activation_successor_grant.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_activation_successor_grant.a1_signature.v1'
      AND NEW.input_kind = 'activation_successor_grant_request'
      AND NEW.sole_consumer = 'active_policy_transition_regrant')
 OR (NEW.route = 'msg01_proposal_disposition' AND NEW.family = 'MSG-01'
      AND NEW.identity_domain = 'nq.c2.store_integrity_proposal_disposition.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_proposal_disposition.a1_signature.v1'
      AND NEW.input_kind = 'proposal_disposition_request'
      AND NEW.sole_consumer = 'deterministic_proposal_disposition')
 OR (NEW.route = 'msg13_restore_authorization' AND NEW.family = 'MSG-13'
      AND NEW.identity_domain = 'nq.c2.restore_authorization.identity.v1'
      AND NEW.signature_domain = 'nq.c2.restore_authorization.a1_signature.v1'
      AND NEW.input_kind = 'restore_authorization_request'
      AND NEW.sole_consumer = 'restore_successor_continuation')
 OR (NEW.route = 'msg14_revocation_judgment' AND NEW.family = 'MSG-14'
      AND NEW.identity_domain = 'nq.c2.store_integrity_revocation_judgment.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_revocation_judgment.a1_signature.v1'
      AND NEW.input_kind = 'revocation_judgment_request'
      AND NEW.sole_consumer = 'atomic_revocation_effect')
 OR (NEW.route = 'msg15_recovery_grant' AND NEW.family = 'MSG-15'
      AND NEW.identity_domain = 'nq.c2.store_integrity_recovery_grant.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_recovery_grant.a1_signature.v1'
      AND NEW.input_kind = 'recovery_grant_request'
      AND NEW.sole_consumer = 'recovery_transition')
 OR (NEW.route = 'msg16_quarantine_closure' AND NEW.family = 'MSG-16'
      AND NEW.identity_domain = 'nq.c2.quarantine_closure_judgment.identity.v1'
      AND NEW.signature_domain = 'nq.c2.quarantine_closure_judgment.a1_signature.v1'
      AND NEW.input_kind = 'quarantine_closure_request'
      AND NEW.sole_consumer = 'atomic_quarantine_closure_effect')
)
BEGIN
    SELECT RAISE(ABORT, 'external carrier row disagrees with the closed MSG-01 through MSG-16 registry');
END;

-- MSG-14 is not receipt-only evidence. The Store persists the exact
-- revocation target and unsigned effect receipt in the same transaction as
-- the governed ingress row. Reopen resolves this table before minting current
-- standing.
CREATE TABLE c2_revocation_effects (
    effect_sequence INTEGER PRIMARY KEY CHECK (effect_sequence > 0),
    ingress_sequence INTEGER NOT NULL UNIQUE
        REFERENCES c2_external_carrier_ingress(ingress_sequence),
    request_identity BLOB NOT NULL UNIQUE CHECK (length(request_identity) = 32),
    judgment_identity BLOB NOT NULL UNIQUE CHECK (length(judgment_identity) = 32),
    physical_generation_identity TEXT NOT NULL CHECK (
        length(physical_generation_identity) = 71
        AND substr(physical_generation_identity, 1, 7) = 'sha256:'
    ),
    lifecycle_root_identity TEXT NOT NULL CHECK (
        length(lifecycle_root_identity) = 71
        AND substr(lifecycle_root_identity, 1, 7) = 'sha256:'
    ),
    scope_identity TEXT NOT NULL CHECK (
        length(scope_identity) = 71 AND substr(scope_identity, 1, 7) = 'sha256:'
    ),
    active_policy_identity TEXT NOT NULL CHECK (
        length(active_policy_identity) = 71
        AND substr(active_policy_identity, 1, 7) = 'sha256:'
    ),
    active_policy_generation INTEGER NOT NULL CHECK (
        active_policy_generation > 0 AND active_policy_generation <= 9007199254740991
    ),
    target_enrollment_identity TEXT NOT NULL CHECK (
        length(target_enrollment_identity) = 71
        AND substr(target_enrollment_identity, 1, 7) = 'sha256:'
    ),
    target_public_key BLOB NOT NULL CHECK (length(target_public_key) = 32),
    target_key_generation INTEGER NOT NULL CHECK (
        target_key_generation >= 0 AND target_key_generation <= 9007199254740991
    ),
    target_standing_identity TEXT NOT NULL UNIQUE CHECK (
        length(target_standing_identity) = 71
        AND substr(target_standing_identity, 1, 7) = 'sha256:'
    ),
    pre_effect_frontier_identity TEXT NOT NULL CHECK (
        length(pre_effect_frontier_identity) = 71
        AND substr(pre_effect_frontier_identity, 1, 7) = 'sha256:'
    ),
    effective_cut INTEGER NOT NULL CHECK (
        effective_cut > 0 AND effective_cut <= 9007199254740991
    ),
    revocation_projection_identity TEXT NOT NULL UNIQUE CHECK (
        length(revocation_projection_identity) = 71
        AND substr(revocation_projection_identity, 1, 7) = 'sha256:'
    ),
    candidate_set_identity TEXT NOT NULL CHECK (
        length(candidate_set_identity) = 71
        AND substr(candidate_set_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_receipt_identity) = 71
        AND substr(effect_receipt_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_bytes BLOB NOT NULL CHECK (length(effect_receipt_bytes) > 0),
    effect_receipt_sha256 TEXT NOT NULL CHECK (
        length(effect_receipt_sha256) = 71
        AND substr(effect_receipt_sha256, 1, 7) = 'sha256:'
    ),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0)
) STRICT;

CREATE TRIGGER c2_revocation_effect_exact_ingress
BEFORE INSERT ON c2_revocation_effects
WHEN NOT EXISTS (
    SELECT 1 FROM c2_external_carrier_ingress AS ingress
    WHERE ingress.ingress_sequence = NEW.ingress_sequence
      AND ingress.route = 'msg14_revocation_judgment'
      AND ingress.family = 'MSG-14'
      AND ingress.request_identity = NEW.request_identity
      AND ingress.carrier_identity = NEW.judgment_identity
)
BEGIN
    SELECT RAISE(ABORT, 'revocation effect is detached from exact MSG-14 ingress');
END;

CREATE TRIGGER immutable_c2_revocation_effects_update
BEFORE UPDATE ON c2_revocation_effects
BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_c2_revocation_effects_delete
BEFORE DELETE ON c2_revocation_effects
BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

-- MSG-16 closes one exact restore quarantine. Absence of this row leaves the
-- restore successor closed to writes; its unsigned receipt cannot be stored
-- independently of the exact judgment and current signer correspondence.
CREATE TABLE c2_quarantine_closure_effects (
    effect_sequence INTEGER PRIMARY KEY CHECK (effect_sequence > 0),
    ingress_sequence INTEGER NOT NULL UNIQUE
        REFERENCES c2_external_carrier_ingress(ingress_sequence),
    request_identity BLOB NOT NULL UNIQUE CHECK (length(request_identity) = 32),
    judgment_identity BLOB NOT NULL UNIQUE CHECK (length(judgment_identity) = 32),
    physical_generation_identity TEXT NOT NULL CHECK (
        length(physical_generation_identity) = 71
        AND substr(physical_generation_identity, 1, 7) = 'sha256:'
    ),
    lifecycle_root_identity TEXT NOT NULL CHECK (
        length(lifecycle_root_identity) = 71
        AND substr(lifecycle_root_identity, 1, 7) = 'sha256:'
    ),
    scope_identity TEXT NOT NULL CHECK (
        length(scope_identity) = 71 AND substr(scope_identity, 1, 7) = 'sha256:'
    ),
    active_policy_identity TEXT NOT NULL CHECK (
        length(active_policy_identity) = 71
        AND substr(active_policy_identity, 1, 7) = 'sha256:'
    ),
    active_policy_generation INTEGER NOT NULL CHECK (
        active_policy_generation > 0 AND active_policy_generation <= 9007199254740991
    ),
    restore_authorization_identity TEXT NOT NULL UNIQUE CHECK (
        length(restore_authorization_identity) = 71
        AND substr(restore_authorization_identity, 1, 7) = 'sha256:'
    ),
    predecessor_generation_identity TEXT NOT NULL CHECK (
        length(predecessor_generation_identity) = 71
        AND substr(predecessor_generation_identity, 1, 7) = 'sha256:'
    ),
    restore_lineage_identity TEXT NOT NULL CHECK (
        length(restore_lineage_identity) = 71
        AND substr(restore_lineage_identity, 1, 7) = 'sha256:'
    ),
    restore_disposition_identity TEXT NOT NULL CHECK (
        length(restore_disposition_identity) = 71
        AND substr(restore_disposition_identity, 1, 7) = 'sha256:'
    ),
    restore_proof_identity TEXT NOT NULL CHECK (
        length(restore_proof_identity) = 71
        AND substr(restore_proof_identity, 1, 7) = 'sha256:'
    ),
    generation_commitment_identity TEXT NOT NULL CHECK (
        length(generation_commitment_identity) = 71
        AND substr(generation_commitment_identity, 1, 7) = 'sha256:'
    ),
    installation_receipt_identity TEXT NOT NULL CHECK (
        length(installation_receipt_identity) = 71
        AND substr(installation_receipt_identity, 1, 7) = 'sha256:'
    ),
    current_enrollment_identity TEXT NOT NULL CHECK (
        length(current_enrollment_identity) = 71
        AND substr(current_enrollment_identity, 1, 7) = 'sha256:'
    ),
    current_public_key BLOB NOT NULL CHECK (length(current_public_key) = 32),
    current_key_generation INTEGER NOT NULL CHECK (
        current_key_generation >= 0 AND current_key_generation <= 9007199254740991
    ),
    current_standing_identity TEXT NOT NULL CHECK (
        length(current_standing_identity) = 71
        AND substr(current_standing_identity, 1, 7) = 'sha256:'
    ),
    quarantine_identity TEXT NOT NULL UNIQUE CHECK (
        length(quarantine_identity) = 71
        AND substr(quarantine_identity, 1, 7) = 'sha256:'
    ),
    pre_effect_frontier_identity TEXT NOT NULL CHECK (
        length(pre_effect_frontier_identity) = 71
        AND substr(pre_effect_frontier_identity, 1, 7) = 'sha256:'
    ),
    closure_cut INTEGER NOT NULL CHECK (
        closure_cut > 0 AND closure_cut <= 9007199254740991
    ),
    quarantine_closure_projection_identity TEXT NOT NULL UNIQUE CHECK (
        length(quarantine_closure_projection_identity) = 71
        AND substr(quarantine_closure_projection_identity, 1, 7) = 'sha256:'
    ),
    candidate_set_identity TEXT NOT NULL CHECK (
        length(candidate_set_identity) = 71
        AND substr(candidate_set_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_receipt_identity) = 71
        AND substr(effect_receipt_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_bytes BLOB NOT NULL CHECK (length(effect_receipt_bytes) > 0),
    effect_receipt_sha256 TEXT NOT NULL CHECK (
        length(effect_receipt_sha256) = 71
        AND substr(effect_receipt_sha256, 1, 7) = 'sha256:'
    ),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0)
) STRICT;

CREATE TRIGGER c2_quarantine_closure_effect_exact_ingress
BEFORE INSERT ON c2_quarantine_closure_effects
WHEN NOT EXISTS (
    SELECT 1 FROM c2_external_carrier_ingress AS ingress
    WHERE ingress.ingress_sequence = NEW.ingress_sequence
      AND ingress.route = 'msg16_quarantine_closure'
      AND ingress.family = 'MSG-16'
      AND ingress.request_identity = NEW.request_identity
      AND ingress.carrier_identity = NEW.judgment_identity
)
BEGIN
    SELECT RAISE(ABORT, 'quarantine closure is detached from exact MSG-16 ingress');
END;

CREATE TRIGGER immutable_c2_quarantine_closure_effects_update
BEFORE UPDATE ON c2_quarantine_closure_effects
BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_c2_quarantine_closure_effects_delete
BEFORE DELETE ON c2_quarantine_closure_effects
BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

-- Canonical inert definition of a stable signer key/custody foundation.
-- Adoption lineage and live authority are deliberately absent. A historical
-- restore may therefore reference the same foundation identity through a new
-- adoption event, while recovery must insert a semantically new foundation.
CREATE TABLE c2_signer_foundations (
    foundation_identity TEXT PRIMARY KEY CHECK (
        length(foundation_identity) = 71 AND substr(foundation_identity, 1, 7) = 'sha256:'
    ),
    foundation_canonical_bytes BLOB NOT NULL CHECK (
        length(foundation_canonical_bytes) > 0
        AND json_valid(CAST(foundation_canonical_bytes AS TEXT))
    ),
    foundation_canonical_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(foundation_canonical_sha256) = 71
        AND substr(foundation_canonical_sha256, 1, 7) = 'sha256:'
    ),
    algorithm TEXT NOT NULL CHECK (algorithm = 'ed25519'),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    key_generation INTEGER NOT NULL CHECK (
        key_generation >= 0 AND key_generation <= 9007199254740991
    ),
    custody_evidence_identity BLOB NOT NULL CHECK (length(custody_evidence_identity) = 32),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0),
    UNIQUE (public_key, key_generation, custody_evidence_identity),
    CHECK (json_extract(CAST(foundation_canonical_bytes AS TEXT), '$.foundation_identity')
        = foundation_identity),
    CHECK (json_extract(CAST(foundation_canonical_bytes AS TEXT), '$.schema')
        = 'nq.c2_store_integrity_signer_foundation.v1'),
    CHECK (json_extract(CAST(foundation_canonical_bytes AS TEXT), '$.algorithm') = algorithm),
    CHECK (json_extract(CAST(foundation_canonical_bytes AS TEXT), '$.key_generation')
        = key_generation)
) STRICT;

CREATE TRIGGER immutable_c2_signer_foundations_update
BEFORE UPDATE ON c2_signer_foundations
BEGIN SELECT RAISE(ABORT, 'append-only signer foundation'); END;
CREATE TRIGGER immutable_c2_signer_foundations_delete
BEFORE DELETE ON c2_signer_foundations
BEGIN SELECT RAISE(ABORT, 'append-only signer foundation'); END;

-- Durable evidence that the Store adopted one exact stable foundation under
-- one member of the closed four-lineage taxonomy. The canonical adoption
-- bytes bind all lineage/Store/scope/cut coordinates. Process/actor fields are
-- audit evidence only and never reconstruct process-local adoption authority.
CREATE TABLE c2_foundational_enrollment_adoptions (
    adoption_sequence INTEGER PRIMARY KEY CHECK (adoption_sequence > 0),
    adoption_identity TEXT NOT NULL UNIQUE CHECK (
        length(adoption_identity) = 71 AND substr(adoption_identity, 1, 7) = 'sha256:'
    ),
    foundation_identity TEXT NOT NULL REFERENCES c2_signer_foundations(foundation_identity) CHECK (
        length(foundation_identity) = 71 AND substr(foundation_identity, 1, 7) = 'sha256:'
    ),
    adoption_canonical_bytes BLOB NOT NULL CHECK (
        length(adoption_canonical_bytes) > 0
        AND json_valid(CAST(adoption_canonical_bytes AS TEXT))
    ),
    adoption_canonical_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(adoption_canonical_sha256) = 71
        AND substr(adoption_canonical_sha256, 1, 7) = 'sha256:'
    ),
    lineage TEXT NOT NULL CHECK (lineage IN (
        'initialExternal', 'ordinarySuccessorContinuity',
        'restoreHistorical', 'recoveryNewFoundation'
    )),
    foundational_enrollment_identity TEXT UNIQUE CHECK (
        foundational_enrollment_identity IS NULL OR (
            length(foundational_enrollment_identity) = 71
            AND substr(foundational_enrollment_identity, 1, 7) = 'sha256:'
        )
    ),
    foundational_enrollment_canonical_bytes BLOB CHECK (
        foundational_enrollment_canonical_bytes IS NULL
        OR length(foundational_enrollment_canonical_bytes) > 0
    ),
    foundational_enrollment_canonical_sha256 TEXT CHECK (
        foundational_enrollment_canonical_sha256 IS NULL OR (
            length(foundational_enrollment_canonical_sha256) = 71
            AND substr(foundational_enrollment_canonical_sha256, 1, 7) = 'sha256:'
        )
    ),
    msg02_message_identity BLOB UNIQUE CHECK (
        msg02_message_identity IS NULL OR length(msg02_message_identity) = 32
    ),
    msg02_append_identity TEXT UNIQUE REFERENCES c2_signer_message_appends(append_identity) CHECK (
        msg02_append_identity IS NULL OR (
            length(msg02_append_identity) = 71
            AND substr(msg02_append_identity, 1, 7) = 'sha256:'
        )
    ),
    msg02_effect_receipt_identity TEXT UNIQUE CHECK (
        msg02_effect_receipt_identity IS NULL OR (
            length(msg02_effect_receipt_identity) = 71
            AND substr(msg02_effect_receipt_identity, 1, 7) = 'sha256:'
        )
    ),
    grant_identity BLOB CHECK (grant_identity IS NULL OR length(grant_identity) = 32),
    candidate_identity BLOB NOT NULL UNIQUE CHECK (length(candidate_identity) = 32),
    attempt_identity BLOB NOT NULL UNIQUE CHECK (length(attempt_identity) = 32),
    custody_evidence_identity BLOB NOT NULL CHECK (length(custody_evidence_identity) = 32),
    pre_generation_scope_identity BLOB NOT NULL CHECK (length(pre_generation_scope_identity) = 32),
    pre_effect_store_snapshot_identity TEXT NOT NULL CHECK (
        length(pre_effect_store_snapshot_identity) = 71
        AND substr(pre_effect_store_snapshot_identity, 1, 7) = 'sha256:'
    ),
    process_identity TEXT NOT NULL CHECK (
        length(process_identity) = 71 AND substr(process_identity, 1, 7) = 'sha256:'
    ),
    actor_instance_identity TEXT NOT NULL CHECK (
        length(actor_instance_identity) = 71 AND substr(actor_instance_identity, 1, 7) = 'sha256:'
    ),
    actor_effect_epoch INTEGER NOT NULL CHECK (
        actor_effect_epoch >= 0 AND actor_effect_epoch <= 9007199254740991
    ),
    enrollment_cut INTEGER NOT NULL CHECK (
        enrollment_cut > 0 AND enrollment_cut <= 9007199254740991
    ),
    effect_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_identity) = 71 AND substr(effect_identity, 1, 7) = 'sha256:'
    ),
    receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(receipt_identity) = 71 AND substr(receipt_identity, 1, 7) = 'sha256:'
    ),
    receipt_bytes BLOB NOT NULL CHECK (length(receipt_bytes) > 0),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0),
    CHECK (json_extract(CAST(adoption_canonical_bytes AS TEXT), '$.adoption_identity')
        = adoption_identity),
    CHECK (json_extract(CAST(adoption_canonical_bytes AS TEXT), '$.foundation_identity')
        = foundation_identity),
    CHECK (json_extract(CAST(adoption_canonical_bytes AS TEXT), '$.lineage') = lineage),
    CHECK (json_extract(CAST(adoption_canonical_bytes AS TEXT), '$.enrollment_cut')
        = enrollment_cut),
    CHECK (
        (lineage = 'initialExternal'
         AND foundational_enrollment_identity IS NOT NULL
         AND foundational_enrollment_canonical_bytes IS NOT NULL
         AND foundational_enrollment_canonical_sha256 IS NOT NULL
         AND msg02_message_identity IS NOT NULL
         AND msg02_append_identity IS NOT NULL
         AND msg02_effect_receipt_identity IS NOT NULL
         AND grant_identity IS NOT NULL
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.physical_generation_identity') = 'null'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.lifecycle_root_identity') = 'null'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.frontier_identity') = 'null'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.current_predecessor_identity') = 'null'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.transition_identity') = 'null')
        OR
        (lineage <> 'initialExternal'
         AND foundational_enrollment_identity IS NULL
         AND foundational_enrollment_canonical_bytes IS NULL
         AND foundational_enrollment_canonical_sha256 IS NULL
         AND msg02_message_identity IS NULL
         AND msg02_append_identity IS NULL
         AND msg02_effect_receipt_identity IS NULL
         AND grant_identity IS NULL
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.physical_generation_identity') = 'text'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.lifecycle_root_identity') = 'text'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.frontier_identity') = 'text'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.current_predecessor_identity') = 'text'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.transition_identity') = 'text')
    )
) STRICT;

CREATE TRIGGER c2_foundational_enrollment_requires_exact_msg02_append
BEFORE INSERT ON c2_foundational_enrollment_adoptions
WHEN NEW.lineage = 'initialExternal' AND NOT EXISTS (
    SELECT 1
    FROM c2_signer_message_appends AS append
    WHERE append.append_identity = NEW.msg02_append_identity
      AND append.family = 'MSG-02'
      AND append.route = 'msg02_initial_pop'
      AND append.message_identity = NEW.msg02_message_identity
)
BEGIN
    SELECT RAISE(ABORT, 'foundational enrollment adoption requires its exact consumed MSG-02 append');
END;

-- Durable later-cut signer-lifecycle acceptance.  The foreign key preserves
-- the one-way dependency on prior Store adoption; no acceptance row can
-- synthesize foundational enrollment evidence.
CREATE TABLE c2_signer_enrollment_acceptances (
    acceptance_sequence INTEGER PRIMARY KEY CHECK (acceptance_sequence > 0),
    acceptance_effect_identity TEXT NOT NULL UNIQUE CHECK (
        length(acceptance_effect_identity) = 71
        AND substr(acceptance_effect_identity, 1, 7) = 'sha256:'
    ),
    signer_enrollment_identity TEXT NOT NULL UNIQUE CHECK (
        length(signer_enrollment_identity) = 71
        AND substr(signer_enrollment_identity, 1, 7) = 'sha256:'
    ),
    signer_enrollment_canonical_bytes BLOB NOT NULL CHECK (
        length(signer_enrollment_canonical_bytes) > 0
    ),
    signer_enrollment_canonical_sha256 TEXT NOT NULL CHECK (
        length(signer_enrollment_canonical_sha256) = 71
        AND substr(signer_enrollment_canonical_sha256, 1, 7) = 'sha256:'
    ),
    foundational_adoption_identity TEXT NOT NULL UNIQUE REFERENCES c2_foundational_enrollment_adoptions(adoption_identity),
    pre_effect_store_snapshot_identity TEXT NOT NULL CHECK (
        length(pre_effect_store_snapshot_identity) = 71
        AND substr(pre_effect_store_snapshot_identity, 1, 7) = 'sha256:'
    ),
    process_identity TEXT NOT NULL CHECK (
        length(process_identity) = 71 AND substr(process_identity, 1, 7) = 'sha256:'
    ),
    actor_instance_identity TEXT NOT NULL CHECK (
        length(actor_instance_identity) = 71 AND substr(actor_instance_identity, 1, 7) = 'sha256:'
    ),
    actor_effect_epoch INTEGER NOT NULL CHECK (
        actor_effect_epoch >= 0 AND actor_effect_epoch <= 9007199254740991
    ),
    accepted_cut INTEGER NOT NULL CHECK (
        accepted_cut > 0 AND accepted_cut <= 9007199254740991
    ),
    receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(receipt_identity) = 71 AND substr(receipt_identity, 1, 7) = 'sha256:'
    ),
    receipt_bytes BLOB NOT NULL CHECK (length(receipt_bytes) > 0),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0)
) STRICT;

CREATE TRIGGER immutable_c2_signer_message_appends_update BEFORE UPDATE ON c2_signer_message_appends BEGIN SELECT RAISE(ABORT, 'append-only signer message ledger'); END;
CREATE TRIGGER immutable_c2_signer_message_appends_delete BEFORE DELETE ON c2_signer_message_appends BEGIN SELECT RAISE(ABORT, 'append-only signer message ledger'); END;
CREATE TRIGGER immutable_c2_external_carrier_ingress_update BEFORE UPDATE ON c2_external_carrier_ingress BEGIN SELECT RAISE(ABORT, 'append-only external carrier ingress'); END;
CREATE TRIGGER immutable_c2_external_carrier_ingress_delete BEFORE DELETE ON c2_external_carrier_ingress BEGIN SELECT RAISE(ABORT, 'append-only external carrier ingress'); END;
CREATE TRIGGER immutable_c2_foundational_enrollment_adoptions_update BEFORE UPDATE ON c2_foundational_enrollment_adoptions BEGIN SELECT RAISE(ABORT, 'append-only foundational enrollment adoption'); END;
CREATE TRIGGER immutable_c2_foundational_enrollment_adoptions_delete BEFORE DELETE ON c2_foundational_enrollment_adoptions BEGIN SELECT RAISE(ABORT, 'append-only foundational enrollment adoption'); END;
CREATE TRIGGER immutable_c2_signer_enrollment_acceptances_update BEFORE UPDATE ON c2_signer_enrollment_acceptances BEGIN SELECT RAISE(ABORT, 'append-only signer enrollment acceptance'); END;
CREATE TRIGGER immutable_c2_signer_enrollment_acceptances_delete BEFORE DELETE ON c2_signer_enrollment_acceptances BEGIN SELECT RAISE(ABORT, 'append-only signer enrollment acceptance'); END;
