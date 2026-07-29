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
