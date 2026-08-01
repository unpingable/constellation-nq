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

-- A valid non-accepted migration classification is a successful governed
-- evidence-freeze act, not a refusal receipt. It never establishes standing,
-- inserts/replaces a root, or permits later writes in this occurrence.
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

-- Explicit signed disposition for a schema-v7 source that has no unique
-- Store occurrence because its genesis cardinality is zero or multiple.
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
