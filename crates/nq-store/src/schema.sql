PRAGMA application_id = 1313951303; -- "NQNG"
PRAGMA user_version = 13;

CREATE TABLE schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    product TEXT NOT NULL CHECK (product = 'nq-ng'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 13),
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
    FOREIGN KEY (artifact_id) REFERENCES diagnostic_artifact_commitments(artifact_id),
    FOREIGN KEY (run_id) REFERENCES watcher_runs(run_id),
    FOREIGN KEY (evaluation_id) REFERENCES evaluation_runs(evaluation_id)
) STRICT;

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

-- One deliberately named ordinary-local successor occurrence.  This is not a
-- provider or origin framework: it only fences the closed `acquire-next-local`
-- diagnostic operation before its existing local provider dispatch.
CREATE TABLE local_successor_acquisition_intents (
    acquisition_id TEXT PRIMARY KEY,
    watcher_instance_id TEXT NOT NULL,
    watcher_semantic_digest TEXT NOT NULL CHECK (length(watcher_semantic_digest) = 71 AND substr(watcher_semantic_digest, 1, 7) = 'sha256:'),
    selection_digest TEXT NOT NULL CHECK (length(selection_digest) = 71 AND substr(selection_digest, 1, 7) = 'sha256:'),
    run_id TEXT NOT NULL UNIQUE,
    intake_id TEXT NOT NULL UNIQUE,
    intent_json BLOB NOT NULL CHECK (length(intent_json) <= 32768 AND json_valid(CAST(intent_json AS TEXT))),
    intent_digest TEXT NOT NULL CHECK (length(intent_digest) = 71 AND substr(intent_digest, 1, 7) = 'sha256:'),
    committed_at TEXT NOT NULL
) STRICT;
CREATE TABLE local_successor_acquisition_events (
    acquisition_id TEXT NOT NULL REFERENCES local_successor_acquisition_intents(acquisition_id),
    event_number INTEGER NOT NULL CHECK (event_number > 0),
    phase TEXT NOT NULL CHECK (phase IN ('provider_invocation_started', 'provider_intake_completed')),
    event_json BLOB NOT NULL CHECK (length(event_json) <= 32768 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (length(event_digest) = 71 AND substr(event_digest, 1, 7) = 'sha256:'),
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (acquisition_id, event_number),
    UNIQUE (acquisition_id, phase)
) STRICT;
CREATE TRIGGER local_successor_event_first BEFORE INSERT ON local_successor_acquisition_events
WHEN NEW.event_number = 1 AND NEW.phase != 'provider_invocation_started'
BEGIN SELECT RAISE(ABORT, 'local successor first event must fence provider invocation'); END;
CREATE TRIGGER local_successor_event_followup BEFORE INSERT ON local_successor_acquisition_events
WHEN NEW.event_number > 1 AND (NEW.event_number != (SELECT COUNT(*) + 1 FROM local_successor_acquisition_events WHERE acquisition_id = NEW.acquisition_id) OR NEW.phase != 'provider_intake_completed')
BEGIN SELECT RAISE(ABORT, 'local successor completion must immediately follow its fence'); END;
CREATE TRIGGER immutable_local_successor_acquisition_intents_update BEFORE UPDATE ON local_successor_acquisition_intents BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_successor_acquisition_intents_delete BEFORE DELETE ON local_successor_acquisition_intents BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_successor_acquisition_events_update BEFORE UPDATE ON local_successor_acquisition_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_successor_acquisition_events_delete BEFORE DELETE ON local_successor_acquisition_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

CREATE TABLE status_events (
    status_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    status_event_id TEXT NOT NULL UNIQUE,
    component_kind TEXT NOT NULL CHECK (component_kind IN
        ('daemon', 'database', 'profile_catalog', 'admission', 'scheduler', 'instance', 'evaluation', 'notification')),
    component_id TEXT NOT NULL,
    -- Present exactly for canonical results of completed watcher runs,
    -- including admitted reports. Admission refusals and non-instance
    -- operational status have no run identity.
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

-- Durable facts are append-only. finding_current and status_current are the only
-- mutable tables; they are rebuildable projections over immutable event streams.
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
CREATE TRIGGER immutable_status_events_update BEFORE UPDATE ON status_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_status_events_delete BEFORE DELETE ON status_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_acknowledgments_update BEFORE UPDATE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_acknowledgments_delete BEFORE DELETE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

-- Keep this fresh-store suffix exactly aligned with schema_v5_to_v12_local_checks_notifications.sql.
CREATE TABLE notification_delivery_intents (notification_id TEXT PRIMARY KEY, intent_schema TEXT NOT NULL CHECK (intent_schema = 'nq.notification_delivery_intent.v1'), stable_event_id TEXT NOT NULL, attention_kind TEXT NOT NULL CHECK (attention_kind IN ('operator_assertion', 'nightshift_receipt')), attention_receipt_digest TEXT, attention_policy_id TEXT NOT NULL, attention_policy_digest TEXT NOT NULL CHECK (length(attention_policy_digest) = 71 AND substr(attention_policy_digest, 1, 7) = 'sha256:'), transition_id TEXT NOT NULL, route_reference TEXT NOT NULL, destination_identity TEXT NOT NULL, content_digest TEXT NOT NULL CHECK (length(content_digest) = 71 AND substr(content_digest, 1, 7) = 'sha256:'), intent_json BLOB NOT NULL CHECK (length(intent_json) <= 32768 AND json_valid(CAST(intent_json AS TEXT))), created_at TEXT NOT NULL, UNIQUE (stable_event_id, destination_identity), FOREIGN KEY (notification_id) REFERENCES notification_outbox(notification_id)) STRICT;
CREATE TABLE notification_delivery_events (notification_id TEXT NOT NULL, event_number INTEGER NOT NULL CHECK (event_number > 0), occurred_at TEXT NOT NULL, outcome TEXT NOT NULL CHECK (outcome IN ('claimed', 'refused', 'failed', 'unknown', 'accepted')), detail_json BLOB NOT NULL CHECK (length(detail_json) <= 32768 AND json_valid(CAST(detail_json AS TEXT))), PRIMARY KEY (notification_id, event_number), FOREIGN KEY (notification_id) REFERENCES notification_delivery_intents(notification_id)) STRICT;
CREATE VIEW public_notification_delivery_status_v1 AS SELECT i.notification_id, i.stable_event_id, i.route_reference, i.destination_identity, i.content_digest, COUNT(e.event_number) AS event_count, COALESCE(MAX(CASE WHEN e.outcome IN ('refused', 'failed', 'unknown', 'accepted') THEN e.outcome END), 'pending') AS delivery_state FROM notification_delivery_intents AS i LEFT JOIN notification_delivery_events AS e ON e.notification_id = i.notification_id GROUP BY i.notification_id;
CREATE TRIGGER notification_delivery_event_first BEFORE INSERT ON notification_delivery_events WHEN NEW.event_number = 1 AND NEW.outcome NOT IN ('claimed', 'refused') BEGIN SELECT RAISE(ABORT, 'first notification delivery event must be claimed or refused'); END;
CREATE TRIGGER notification_delivery_event_followup BEFORE INSERT ON notification_delivery_events WHEN NEW.event_number > 1 AND (NEW.event_number != (SELECT COUNT(*) + 1 FROM notification_delivery_events WHERE notification_id = NEW.notification_id) OR (SELECT outcome FROM notification_delivery_events WHERE notification_id = NEW.notification_id AND event_number = NEW.event_number - 1) != 'claimed' OR NEW.outcome NOT IN ('failed', 'unknown', 'accepted')) BEGIN SELECT RAISE(ABORT, 'notification delivery requires one claim followed by one terminal outcome'); END;
CREATE TRIGGER notification_delivery_event_terminal BEFORE INSERT ON notification_delivery_events WHEN EXISTS (SELECT 1 FROM notification_delivery_events WHERE notification_id = NEW.notification_id AND outcome IN ('refused', 'failed', 'unknown', 'accepted')) BEGIN SELECT RAISE(ABORT, 'terminal notification delivery outcome cannot be replayed'); END;
CREATE TRIGGER immutable_notification_delivery_intents_update BEFORE UPDATE ON notification_delivery_intents BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_notification_delivery_intents_delete BEFORE DELETE ON notification_delivery_intents BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_notification_delivery_events_update BEFORE UPDATE ON notification_delivery_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_notification_delivery_events_delete BEFORE DELETE ON notification_delivery_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TABLE saved_check_definitions (definition_id TEXT PRIMARY KEY, stable_reference TEXT NOT NULL UNIQUE, definition_digest TEXT NOT NULL CHECK (length(definition_digest) = 71 AND substr(definition_digest, 1, 7) = 'sha256:'), definition_json BLOB NOT NULL CHECK (length(definition_json) <= 32768 AND json_valid(CAST(definition_json AS TEXT))), installed_at TEXT NOT NULL) STRICT;
CREATE TABLE saved_check_events (definition_id TEXT NOT NULL REFERENCES saved_check_definitions(definition_id), event_number INTEGER NOT NULL CHECK (event_number > 0), occurred_at TEXT NOT NULL, outcome TEXT NOT NULL CHECK (outcome IN ('installed', 'claimed', 'refused', 'passed', 'failed')), detail_json BLOB NOT NULL CHECK (length(detail_json) <= 32768 AND json_valid(CAST(detail_json AS TEXT))), evaluation_id TEXT, PRIMARY KEY (definition_id, event_number)) STRICT;
CREATE INDEX saved_check_events_evaluation_id ON saved_check_events(evaluation_id) WHERE evaluation_id IS NOT NULL;
CREATE UNIQUE INDEX saved_check_events_one_claim_per_evaluation ON saved_check_events(evaluation_id) WHERE outcome = 'claimed';
CREATE UNIQUE INDEX saved_check_events_one_terminal_per_evaluation ON saved_check_events(evaluation_id) WHERE outcome IN ('refused', 'passed', 'failed');
CREATE TRIGGER saved_check_terminal_requires_exact_claim BEFORE INSERT ON saved_check_events WHEN NEW.outcome IN ('refused', 'passed', 'failed') BEGIN SELECT CASE WHEN NEW.evaluation_id IS NULL THEN RAISE(ABORT, 'saved check terminal outcome requires an evaluation claim') END; SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM saved_check_events WHERE definition_id = NEW.definition_id AND evaluation_id = NEW.evaluation_id AND outcome = 'claimed') THEN RAISE(ABORT, 'saved check terminal outcome requires its exact claim') END; END;
CREATE TABLE maintenance_declarations (maintenance_id TEXT PRIMARY KEY, declaration_digest TEXT NOT NULL CHECK (length(declaration_digest) = 71 AND substr(declaration_digest, 1, 7) = 'sha256:'), declaration_json BLOB NOT NULL CHECK (length(declaration_json) <= 32768 AND json_valid(CAST(declaration_json AS TEXT))), declared_at TEXT NOT NULL) STRICT;
CREATE TRIGGER immutable_saved_check_definitions_update BEFORE UPDATE ON saved_check_definitions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_saved_check_definitions_delete BEFORE DELETE ON saved_check_definitions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_saved_check_events_update BEFORE UPDATE ON saved_check_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_saved_check_events_delete BEFORE DELETE ON saved_check_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_maintenance_declarations_update BEFORE UPDATE ON maintenance_declarations BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_maintenance_declarations_delete BEFORE DELETE ON maintenance_declarations BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
