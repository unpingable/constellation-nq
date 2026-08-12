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
    bootstrap_identity TEXT NOT NULL UNIQUE CHECK (
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

-- Unsigned MSG-04 bootstrap-to-generation relation.  This is canonical inert
-- evidence consumed by the generation-current resolver; it is deliberately
-- outside the signer-message ledger and has no signature/domain column.
CREATE TABLE c2_signer_bootstrap_transition (
    relation_identity TEXT PRIMARY KEY CHECK (
        length(relation_identity) = 71
        AND substr(relation_identity, 1, 7) = 'sha256:'
    ),
    schema_id TEXT NOT NULL CHECK (
        schema_id = 'nq.c2_signer_bootstrap_transition.v1'
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    identity_domain TEXT NOT NULL CHECK (
        identity_domain = 'nq.c2.signer_bootstrap_transition.identity.v1'
    ),
    bootstrap_grant_identity TEXT NOT NULL CHECK (
        length(bootstrap_grant_identity) = 71
        AND substr(bootstrap_grant_identity, 1, 7) = 'sha256:'
    ),
    foundational_enrollment_identity TEXT NOT NULL CHECK (
        length(foundational_enrollment_identity) = 71
        AND substr(foundational_enrollment_identity, 1, 7) = 'sha256:'
    ),
    signer_enrollment_identity TEXT NOT NULL UNIQUE CHECK (
        length(signer_enrollment_identity) = 71
        AND substr(signer_enrollment_identity, 1, 7) = 'sha256:'
    ),
    initial_pop_identity TEXT NOT NULL UNIQUE CHECK (
        length(initial_pop_identity) = 71
        AND substr(initial_pop_identity, 1, 7) = 'sha256:'
    ),
    physical_generation_bootstrap_identity TEXT NOT NULL UNIQUE CHECK (
        length(physical_generation_bootstrap_identity) = 71
        AND substr(physical_generation_bootstrap_identity, 1, 7) = 'sha256:'
    ),
    generation_commitment_identity TEXT NOT NULL UNIQUE CHECK (
        length(generation_commitment_identity) = 71
        AND substr(generation_commitment_identity, 1, 7) = 'sha256:'
    ),
    installation_receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(installation_receipt_identity) = 71
        AND substr(installation_receipt_identity, 1, 7) = 'sha256:'
    ),
    physical_store_generation_identity TEXT NOT NULL UNIQUE CHECK (
        length(physical_store_generation_identity) = 71
        AND substr(physical_store_generation_identity, 1, 7) = 'sha256:'
    ),
    transition_cut INTEGER NOT NULL CHECK (
        transition_cut > 0 AND transition_cut <= 9007199254740991
    ),
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
    derived_at TEXT NOT NULL,
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.schema') = schema_id),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.schema_version') = schema_version),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.identity_domain') = identity_domain),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.relation_identity') = relation_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.bootstrap_grant_identity') = bootstrap_grant_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.foundational_enrollment_identity') = foundational_enrollment_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.signer_enrollment_identity') = signer_enrollment_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.initial_pop_identity') = initial_pop_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.physical_generation_bootstrap_identity') = physical_generation_bootstrap_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.generation_commitment_identity') = generation_commitment_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.installation_receipt_identity') = installation_receipt_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.physical_store_generation_identity') = physical_store_generation_identity),
    CHECK (json_extract(CAST(canonical_bytes AS TEXT), '$.transition_cut') = transition_cut),
    FOREIGN KEY (installation_receipt_identity)
        REFERENCES c2_installation_receipt_index(installation_receipt_identity),
    FOREIGN KEY (physical_store_generation_identity)
        REFERENCES c2_installation_receipt_index(physical_store_generation_identity)
) STRICT;

CREATE TRIGGER immutable_c2_signer_bootstrap_transition_update
BEFORE UPDATE ON c2_signer_bootstrap_transition
BEGIN
    SELECT RAISE(ABORT, 'unsigned MSG-04 bootstrap transition is append-only');
END;

CREATE TRIGGER immutable_c2_signer_bootstrap_transition_delete
BEFORE DELETE ON c2_signer_bootstrap_transition
BEGIN
    SELECT RAISE(ABORT, 'unsigned MSG-04 bootstrap transition is append-only');
END;
