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
    bootstrap_identity TEXT NOT NULL CHECK (
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
