-- C1 Gen4 native authority custody.  Genesis A1/A2 remain external custody;
-- only post-genesis authority events are Store-ledger resident.  These
-- families are deliberately separate from the generic runtime-record ledger.

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

-- Historical establishment fact.  `genesis_activation_digest` is the
-- immutable A2 chain root; `controlling_tip_digest` is the tip that controlled
-- when establishment committed.  Later successors rewrite neither.
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

-- Exact signed migration evidence is consumed at most once.  The full
-- canonical carrier is retained; its semantic fields are verified in Rust.
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
