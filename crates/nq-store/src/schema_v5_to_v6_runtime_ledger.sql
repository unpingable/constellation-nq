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

DROP TRIGGER immutable_local_diagnostic_artifact_origins_update;
DROP TRIGGER immutable_local_diagnostic_artifact_origins_delete;
ALTER TABLE local_diagnostic_artifact_origins
    RENAME TO local_diagnostic_artifact_origins_v5;
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
INSERT INTO local_diagnostic_artifact_origins (
    artifact_id, run_id, evaluation_id, completed_at
)
SELECT artifact_id, run_id, evaluation_id, completed_at
FROM local_diagnostic_artifact_origins_v5;
DROP TABLE local_diagnostic_artifact_origins_v5;
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
CREATE TRIGGER immutable_local_diagnostic_artifact_origins_update BEFORE UPDATE ON local_diagnostic_artifact_origins BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_diagnostic_artifact_origins_delete BEFORE DELETE ON local_diagnostic_artifact_origins BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

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

CREATE TRIGGER immutable_runtime_record_checkpoints_update BEFORE UPDATE ON runtime_record_checkpoints BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_record_checkpoints_delete BEFORE DELETE ON runtime_record_checkpoints BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_record_ledger_update BEFORE UPDATE ON runtime_record_ledger BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_record_ledger_delete BEFORE DELETE ON runtime_record_ledger BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_diagnostic_artifact_provider_attempt_bindings_update BEFORE UPDATE ON local_diagnostic_artifact_provider_attempt_bindings BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_diagnostic_artifact_provider_attempt_bindings_delete BEFORE DELETE ON local_diagnostic_artifact_provider_attempt_bindings BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
