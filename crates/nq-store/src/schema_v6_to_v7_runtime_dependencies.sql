CREATE TABLE runtime_dependency_trust_roots (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    trust_anchor_id TEXT NOT NULL CHECK (
        length(trust_anchor_id) = 71
        AND substr(trust_anchor_id, 1, 7) = 'sha256:'
    ),
    established_at TEXT NOT NULL
) STRICT;

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

CREATE TRIGGER immutable_runtime_dependency_generation_commitments_update BEFORE UPDATE ON runtime_dependency_generation_commitments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_generation_commitments_delete BEFORE DELETE ON runtime_dependency_generation_commitments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_trust_roots_update BEFORE UPDATE ON runtime_dependency_trust_roots BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_trust_roots_delete BEFORE DELETE ON runtime_dependency_trust_roots BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_generation_payloads_update BEFORE UPDATE ON runtime_dependency_generation_payloads BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_generation_payloads_delete BEFORE DELETE ON runtime_dependency_generation_payloads BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_checkpoint_dependency_bindings_update BEFORE UPDATE ON runtime_checkpoint_dependency_bindings BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_checkpoint_dependency_bindings_delete BEFORE DELETE ON runtime_checkpoint_dependency_bindings BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_binding_migration_boundaries_update BEFORE UPDATE ON runtime_dependency_binding_migration_boundaries BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_runtime_dependency_binding_migration_boundaries_delete BEFORE DELETE ON runtime_dependency_binding_migration_boundaries BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

-- Schema v7 admits bounded diagnostic-execution processing results without
-- projecting them into watcher-instance health. Rebuild the status parent and
-- its durable acknowledgment child exactly; status_current is disposable and
-- is reconstructed from the append-only event sequence.
DROP VIEW public_status_snapshot_v1;
DROP TABLE status_current;
DROP TRIGGER immutable_provider_intake_acknowledgments_update;
DROP TRIGGER immutable_provider_intake_acknowledgments_delete;
DROP TRIGGER immutable_status_events_update;
DROP TRIGGER immutable_status_events_delete;

ALTER TABLE provider_intake_acknowledgments
    RENAME TO provider_intake_acknowledgments_v6;
ALTER TABLE status_events RENAME TO status_events_v6;

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

INSERT INTO status_events (
    status_sequence, status_event_id, component_kind, component_id, run_id,
    state, code, detail_json, observed_at
)
SELECT
    status_sequence, status_event_id, component_kind, component_id, run_id,
    state, code, detail_json, observed_at
FROM status_events_v6
ORDER BY status_sequence;

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

INSERT INTO provider_intake_acknowledgments (
    acknowledgment_id, intake_id, run_id, provider_admission_id,
    status_event_id, schema_id, detail_json, acknowledgment_digest, committed_at
)
SELECT
    acknowledgment_id, intake_id, run_id, provider_admission_id,
    status_event_id, schema_id, detail_json, acknowledgment_digest, committed_at
FROM provider_intake_acknowledgments_v6;

DROP TABLE provider_intake_acknowledgments_v6;
DROP TABLE status_events_v6;

CREATE INDEX status_events_by_component
    ON status_events(component_kind, component_id, status_sequence);
CREATE UNIQUE INDEX status_events_by_run
    ON status_events(run_id) WHERE run_id IS NOT NULL;

CREATE TABLE status_current (
    component_kind TEXT NOT NULL,
    component_id TEXT NOT NULL,
    latest_status_event_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (component_kind, component_id),
    FOREIGN KEY (latest_status_event_id) REFERENCES status_events(status_event_id)
) STRICT;

INSERT INTO status_current (
    component_kind, component_id, latest_status_event_id
)
SELECT event.component_kind, event.component_id, event.status_event_id
FROM status_events AS event
WHERE event.status_sequence = (
    SELECT MAX(candidate.status_sequence)
    FROM status_events AS candidate
    WHERE candidate.component_kind = event.component_kind
      AND candidate.component_id = event.component_id
);

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

CREATE TRIGGER immutable_status_events_update BEFORE UPDATE ON status_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_status_events_delete BEFORE DELETE ON status_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_acknowledgments_update BEFORE UPDATE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_intake_acknowledgments_delete BEFORE DELETE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
