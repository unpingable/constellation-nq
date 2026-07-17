PRAGMA application_id = 1313951303; -- "NQNG"
PRAGMA user_version = 1;

CREATE TABLE schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    product TEXT NOT NULL CHECK (product = 'nq-ng'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
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

CREATE TABLE witness_runs (
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
CREATE INDEX witness_runs_by_instance ON witness_runs(instance_id, started_at, run_id);

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
    FOREIGN KEY (run_id) REFERENCES witness_runs(run_id)
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
    -- Source protocol JSON as received. Retained as witness material; the
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
-- report from a context-less run is refused. witness_runs.admission_id stays
-- globally nullable (refused/failed runs legitimately have none).
CREATE TRIGGER admitted_reports_bind_admission_context
BEFORE INSERT ON admitted_reports
WHEN (
    SELECT COUNT(*)
    FROM raw_submissions AS s
    JOIN witness_runs AS r ON r.run_id = s.run_id
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
    detector_id TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    detector_digest TEXT NOT NULL CHECK (length(detector_digest) = 71 AND substr(detector_digest, 1, 7) = 'sha256:'),
    evaluation_revision INTEGER NOT NULL CHECK (evaluation_revision >= 0),
    started_at TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('condition_present', 'condition_explicitly_absent', 'cannot_evaluate')),
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    UNIQUE (detector_id, detector_version, evaluation_revision)
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
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    created_at TEXT NOT NULL,
    CHECK (run_id IS NOT NULL OR evaluation_id IS NOT NULL),
    FOREIGN KEY (run_id) REFERENCES witness_runs(run_id),
    FOREIGN KEY (submission_id) REFERENCES raw_submissions(submission_id),
    FOREIGN KEY (evaluation_id) REFERENCES evaluation_runs(evaluation_id)
) STRICT;
CREATE INDEX refusals_by_instance ON refusals(responsible_instance_id, created_at);

CREATE TABLE finding_events (
    event_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    event_revision INTEGER NOT NULL CHECK (event_revision >= 0),
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
    evaluation_revision INTEGER NOT NULL CHECK (evaluation_revision >= 0),
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

CREATE TABLE status_events (
    status_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    status_event_id TEXT NOT NULL UNIQUE,
    component_kind TEXT NOT NULL CHECK (component_kind IN
        ('daemon', 'database', 'profile_catalog', 'admission', 'scheduler', 'instance', 'evaluation', 'notification')),
    component_id TEXT NOT NULL,
    state TEXT NOT NULL,
    code TEXT NOT NULL,
    detail_json BLOB NOT NULL CHECK (json_valid(CAST(detail_json AS TEXT))),
    observed_at TEXT NOT NULL
) STRICT;
CREATE INDEX status_events_by_component
    ON status_events(component_kind, component_id, status_sequence);

-- This is a rebuildable projection. All source history remains in status_events.
CREATE TABLE status_current (
    component_kind TEXT NOT NULL,
    component_id TEXT NOT NULL,
    latest_status_event_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (component_kind, component_id),
    FOREIGN KEY (latest_status_event_id) REFERENCES status_events(status_event_id)
) STRICT;

CREATE VIEW public_finding_snapshot_v2 AS
SELECT
    f.finding_id,
    e.instance_id,
    e.detector_id,
    e.detector_version,
    e.detector_digest,
    e.evaluation_revision,
    e.profile_id,
    e.profile_version,
    e.profile_digest,
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
JOIN finding_events AS e ON e.event_id = f.latest_event_id;

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
CREATE TRIGGER immutable_instance_binding_events_update BEFORE UPDATE ON instance_binding_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_instance_binding_events_delete BEFORE DELETE ON instance_binding_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_binding_materialization_events_update BEFORE UPDATE ON binding_materialization_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_binding_materialization_events_delete BEFORE DELETE ON binding_materialization_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_witness_runs_update BEFORE UPDATE ON witness_runs BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_witness_runs_delete BEFORE DELETE ON witness_runs BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
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
