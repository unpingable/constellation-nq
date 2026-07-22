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
CREATE TRIGGER immutable_local_provider_admissions_update BEFORE UPDATE ON local_provider_admissions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_provider_admissions_delete BEFORE DELETE ON local_provider_admissions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_attempts_update BEFORE UPDATE ON provider_intake_attempts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_attempts_delete BEFORE DELETE ON provider_intake_attempts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_watcher_provider_intakes_update BEFORE UPDATE ON local_watcher_provider_intakes BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_watcher_provider_intakes_delete BEFORE DELETE ON local_watcher_provider_intakes BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_legacy_v3_watcher_run_intake_gaps_update BEFORE UPDATE ON legacy_v3_watcher_run_intake_gaps BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_legacy_v3_watcher_run_intake_gaps_delete BEFORE DELETE ON legacy_v3_watcher_run_intake_gaps BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_acknowledgments_update BEFORE UPDATE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_acknowledgments_delete BEFORE DELETE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
