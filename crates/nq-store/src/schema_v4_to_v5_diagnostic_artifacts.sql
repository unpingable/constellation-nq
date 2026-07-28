CREATE TABLE diagnostic_artifact_commitments (
    artifact_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL UNIQUE CHECK (length(artifact_id) = 71 AND substr(artifact_id, 1, 7) = 'sha256:'),
    contract_schema TEXT NOT NULL CHECK (length(contract_schema) BETWEEN 1 AND 256),
    canonical_bytes_sha256 TEXT NOT NULL CHECK (length(canonical_bytes_sha256) = 71 AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'),
    canonical_bytes_length INTEGER NOT NULL CHECK (canonical_bytes_length > 0 AND canonical_bytes_length <= 16777216),
    committed_at TEXT NOT NULL
) STRICT;

CREATE TABLE diagnostic_artifact_payloads (
    artifact_id TEXT PRIMARY KEY,
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0 AND length(canonical_bytes) <= 16777216),
    FOREIGN KEY (artifact_id) REFERENCES diagnostic_artifact_commitments(artifact_id)
) STRICT;

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

CREATE TABLE imported_diagnostic_artifact_origins (
    artifact_id TEXT PRIMARY KEY,
    import_id TEXT NOT NULL UNIQUE,
    imported_at TEXT NOT NULL,
    initial_outcome TEXT NOT NULL CHECK (initial_outcome IN
        ('committed', 'committed_unavailable')),
    FOREIGN KEY (artifact_id) REFERENCES diagnostic_artifact_commitments(artifact_id),
    FOREIGN KEY (import_id) REFERENCES diagnostic_artifact_import_events(import_id)
) STRICT;

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
