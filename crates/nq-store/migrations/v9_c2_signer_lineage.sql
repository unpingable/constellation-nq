-- C1 Gen5 / C2 signer-lineage projection for schema v9.
--
-- Authenticated B records remain canonical.  These append-only tables retain
-- exact, independently verifiable projections and never select a signer by
-- maximum cut, insertion order, key generation, or lexical identity.

CREATE TABLE c2_signer_root_binding_projection (
    root_binding_identity TEXT PRIMARY KEY CHECK (
        length(root_binding_identity) = 71
        AND substr(root_binding_identity, 1, 7) = 'sha256:'
    ),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    physical_store_generation_identity TEXT NOT NULL CHECK (
        length(physical_store_generation_identity) = 71
        AND substr(physical_store_generation_identity, 1, 7) = 'sha256:'
    ),
    signer_lifecycle_root_identity TEXT NOT NULL CHECK (
        length(signer_lifecycle_root_identity) = 71
        AND substr(signer_lifecycle_root_identity, 1, 7) = 'sha256:'
    ),
    initial_enrollment_identity TEXT NOT NULL CHECK (
        length(initial_enrollment_identity) = 71
        AND substr(initial_enrollment_identity, 1, 7) = 'sha256:'
    ),
    initial_key_generation INTEGER NOT NULL CHECK (initial_key_generation = 0),
    initial_public_key BLOB NOT NULL CHECK (length(initial_public_key) = 32),
    generation_genesis_identity TEXT NOT NULL CHECK (
        length(generation_genesis_identity) = 71
        AND substr(generation_genesis_identity, 1, 7) = 'sha256:'
    ),
    generation_commitment_identity TEXT NOT NULL CHECK (
        length(generation_commitment_identity) = 71
        AND substr(generation_commitment_identity, 1, 7) = 'sha256:'
    ),
    scope_identity TEXT NOT NULL CHECK (
        length(scope_identity) = 71 AND substr(scope_identity, 1, 7) = 'sha256:'
    ),
    resident_identity TEXT NOT NULL CHECK (
        length(CAST(resident_identity AS BLOB)) BETWEEN 1 AND 1024
    ),
    resident_generation INTEGER NOT NULL CHECK (resident_generation > 0),
    host_role TEXT NOT NULL CHECK (length(host_role) BETWEEN 1 AND 256),
    role_manifest_generation INTEGER NOT NULL CHECK (role_manifest_generation > 0),
    authority_domain TEXT NOT NULL CHECK (length(authority_domain) BETWEEN 1 AND 256),
    policy_lineage_root_identity TEXT NOT NULL CHECK (
        length(policy_lineage_root_identity) = 71
        AND substr(policy_lineage_root_identity, 1, 7) = 'sha256:'
    ),
    creation_cut INTEGER NOT NULL CHECK (creation_cut > 0),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 1048576
    ),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 1048576
    ),
    projected_at TEXT NOT NULL,
    UNIQUE (
        occurrence_id,
        physical_store_generation_identity,
        signer_lifecycle_root_identity,
        scope_identity
    ),
    CHECK (length(canonical_bytes) = canonical_bytes_length)
) STRICT;

CREATE TABLE c2_signer_current_binding_projection (
    current_binding_identity TEXT PRIMARY KEY CHECK (
        length(current_binding_identity) = 71
        AND substr(current_binding_identity, 1, 7) = 'sha256:'
    ),
    root_binding_identity TEXT NOT NULL CHECK (
        length(root_binding_identity) = 71
        AND substr(root_binding_identity, 1, 7) = 'sha256:'
    ),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    physical_store_generation_identity TEXT NOT NULL CHECK (
        length(physical_store_generation_identity) = 71
        AND substr(physical_store_generation_identity, 1, 7) = 'sha256:'
    ),
    signer_lifecycle_root_identity TEXT NOT NULL CHECK (
        length(signer_lifecycle_root_identity) = 71
        AND substr(signer_lifecycle_root_identity, 1, 7) = 'sha256:'
    ),
    scope_identity TEXT NOT NULL CHECK (
        length(scope_identity) = 71 AND substr(scope_identity, 1, 7) = 'sha256:'
    ),
    resident_identity TEXT NOT NULL CHECK (
        length(CAST(resident_identity AS BLOB)) BETWEEN 1 AND 1024
    ),
    resident_generation INTEGER NOT NULL CHECK (resident_generation > 0),
    host_role TEXT NOT NULL CHECK (length(host_role) BETWEEN 1 AND 256),
    role_manifest_generation INTEGER NOT NULL CHECK (role_manifest_generation > 0),
    authority_domain TEXT NOT NULL CHECK (length(authority_domain) BETWEEN 1 AND 256),
    policy_lineage_root_identity TEXT NOT NULL CHECK (
        length(policy_lineage_root_identity) = 71
        AND substr(policy_lineage_root_identity, 1, 7) = 'sha256:'
    ),
    current_enrollment_identity TEXT NOT NULL CHECK (
        length(current_enrollment_identity) = 71
        AND substr(current_enrollment_identity, 1, 7) = 'sha256:'
    ),
    current_key_generation INTEGER NOT NULL CHECK (current_key_generation >= 0),
    current_public_key BLOB NOT NULL CHECK (length(current_public_key) = 32),
    current_policy_identity TEXT NOT NULL CHECK (
        length(current_policy_identity) = 71
        AND substr(current_policy_identity, 1, 7) = 'sha256:'
    ),
    current_standing_identity TEXT NOT NULL CHECK (
        length(current_standing_identity) = 71
        AND substr(current_standing_identity, 1, 7) = 'sha256:'
    ),
    binding_mode TEXT NOT NULL CHECK (
        binding_mode IN ('initial', 'normal_successor', 'restore_successor', 'recovery_successor')
    ),
    provenance_identity TEXT NOT NULL CHECK (
        length(provenance_identity) = 71
        AND substr(provenance_identity, 1, 7) = 'sha256:'
    ),
    transition_identity TEXT CHECK (
        transition_identity IS NULL
        OR (length(transition_identity) = 71
            AND substr(transition_identity, 1, 7) = 'sha256:')
    ),
    predecessor_binding_identity TEXT CHECK (
        predecessor_binding_identity IS NULL
        OR (length(predecessor_binding_identity) = 71
            AND substr(predecessor_binding_identity, 1, 7) = 'sha256:')
    ),
    continuity_authorization_identity TEXT CHECK (
        continuity_authorization_identity IS NULL
        OR (length(continuity_authorization_identity) = 71
            AND substr(continuity_authorization_identity, 1, 7) = 'sha256:')
    ),
    restore_lineage_identity TEXT CHECK (
        restore_lineage_identity IS NULL
        OR (length(restore_lineage_identity) = 71
            AND substr(restore_lineage_identity, 1, 7) = 'sha256:')
    ),
    restore_authority_identity TEXT CHECK (
        restore_authority_identity IS NULL
        OR (length(restore_authority_identity) = 71
            AND substr(restore_authority_identity, 1, 7) = 'sha256:')
    ),
    historical_foundation_identity TEXT CHECK (
        historical_foundation_identity IS NULL
        OR (length(historical_foundation_identity) = 71
            AND substr(historical_foundation_identity, 1, 7) = 'sha256:')
    ),
    recovery_condition_identity TEXT CHECK (
        recovery_condition_identity IS NULL
        OR (length(recovery_condition_identity) = 71
            AND substr(recovery_condition_identity, 1, 7) = 'sha256:')
    ),
    recovery_authority_identity TEXT CHECK (
        recovery_authority_identity IS NULL
        OR (length(recovery_authority_identity) = 71
            AND substr(recovery_authority_identity, 1, 7) = 'sha256:')
    ),
    recovery_grant_identity TEXT CHECK (
        recovery_grant_identity IS NULL
        OR (length(recovery_grant_identity) = 71
            AND substr(recovery_grant_identity, 1, 7) = 'sha256:')
    ),
    persisted_resolution_identity TEXT NOT NULL CHECK (
        length(persisted_resolution_identity) = 71
        AND substr(persisted_resolution_identity, 1, 7) = 'sha256:'
    ),
    effective_cut INTEGER NOT NULL CHECK (effective_cut > 0),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 1048576
    ),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 1048576
    ),
    projected_at TEXT NOT NULL,
    UNIQUE (root_binding_identity, effective_cut),
    UNIQUE (root_binding_identity, persisted_resolution_identity),
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (
        (binding_mode = 'initial'
            AND current_key_generation = 0
            AND transition_identity IS NULL
            AND predecessor_binding_identity IS NULL
            AND continuity_authorization_identity IS NULL
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (binding_mode = 'normal_successor'
            AND current_key_generation > 0
            AND transition_identity IS NOT NULL
            AND predecessor_binding_identity IS NOT NULL
            AND continuity_authorization_identity IS NOT NULL
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (binding_mode = 'restore_successor'
            AND current_key_generation >= 0
            AND transition_identity IS NOT NULL
            AND predecessor_binding_identity IS NOT NULL
            AND continuity_authorization_identity IS NULL
            AND restore_lineage_identity IS NOT NULL
            AND restore_authority_identity IS NOT NULL
            AND historical_foundation_identity IS NOT NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (binding_mode = 'recovery_successor'
            -- Recovery requires a semantically new stable key-generation
            -- identity, not a globally monotone ordinal. A discontinuous new
            -- foundation may lawfully begin at generation zero.
            AND current_key_generation >= 0
            AND transition_identity IS NOT NULL
            AND predecessor_binding_identity IS NOT NULL
            AND continuity_authorization_identity IS NULL
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NOT NULL
            AND recovery_authority_identity IS NOT NULL
            AND recovery_grant_identity IS NOT NULL)
    ),
    FOREIGN KEY (root_binding_identity)
        REFERENCES c2_signer_root_binding_projection(root_binding_identity),
    FOREIGN KEY (predecessor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

CREATE TABLE c2_signer_succession_projection (
    succession_identity TEXT PRIMARY KEY CHECK (
        length(succession_identity) = 71
        AND substr(succession_identity, 1, 7) = 'sha256:'
    ),
    root_binding_identity TEXT NOT NULL,
    succession_mode TEXT NOT NULL CHECK (succession_mode IN ('normal', 'restore', 'recovery')),
    transition_identity TEXT NOT NULL UNIQUE CHECK (
        length(transition_identity) = 71
        AND substr(transition_identity, 1, 7) = 'sha256:'
    ),
    predecessor_binding_identity TEXT NOT NULL UNIQUE,
    successor_binding_identity TEXT NOT NULL UNIQUE,
    authorization_identity TEXT NOT NULL UNIQUE CHECK (
        length(authorization_identity) = 71
        AND substr(authorization_identity, 1, 7) = 'sha256:'
    ),
    restore_lineage_identity TEXT UNIQUE,
    restore_authority_identity TEXT UNIQUE,
    historical_foundation_identity TEXT,
    recovery_condition_identity TEXT UNIQUE,
    recovery_authority_identity TEXT UNIQUE,
    recovery_grant_identity TEXT UNIQUE,
    proposal_identity TEXT NOT NULL CHECK (
        length(proposal_identity) = 71
        AND substr(proposal_identity, 1, 7) = 'sha256:'
    ),
    successor_pop_identity TEXT NOT NULL CHECK (
        length(successor_pop_identity) = 71
        AND substr(successor_pop_identity, 1, 7) = 'sha256:'
    ),
    completion_identity TEXT NOT NULL UNIQUE CHECK (
        length(completion_identity) = 71
        AND substr(completion_identity, 1, 7) = 'sha256:'
    ),
    receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(receipt_identity) = 71
        AND substr(receipt_identity, 1, 7) = 'sha256:'
    ),
    append_identity TEXT NOT NULL UNIQUE CHECK (
        length(append_identity) = 71
        AND substr(append_identity, 1, 7) = 'sha256:'
    ),
    persisted_resolution_identity TEXT NOT NULL UNIQUE CHECK (
        length(persisted_resolution_identity) = 71
        AND substr(persisted_resolution_identity, 1, 7) = 'sha256:'
    ),
    predecessor_cut INTEGER NOT NULL CHECK (predecessor_cut > 0),
    successor_cut INTEGER NOT NULL CHECK (successor_cut > predecessor_cut),
    canonical_bytes BLOB NOT NULL CHECK (
        length(canonical_bytes) > 0 AND length(canonical_bytes) <= 2097152
    ),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (
        canonical_bytes_length > 0 AND canonical_bytes_length <= 2097152
    ),
    projected_at TEXT NOT NULL,
    CHECK (predecessor_binding_identity <> successor_binding_identity),
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (
        (succession_mode = 'normal'
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (succession_mode = 'restore'
            AND restore_lineage_identity IS NOT NULL
            AND restore_authority_identity IS NOT NULL
            AND historical_foundation_identity IS NOT NULL
            AND length(restore_lineage_identity) = 71
            AND substr(restore_lineage_identity, 1, 7) = 'sha256:'
            AND length(restore_authority_identity) = 71
            AND substr(restore_authority_identity, 1, 7) = 'sha256:'
            AND length(historical_foundation_identity) = 71
            AND substr(historical_foundation_identity, 1, 7) = 'sha256:'
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (succession_mode = 'recovery'
            AND restore_lineage_identity IS NULL
            AND restore_authority_identity IS NULL
            AND historical_foundation_identity IS NULL
            AND recovery_condition_identity IS NOT NULL
            AND recovery_authority_identity IS NOT NULL
            AND recovery_grant_identity IS NOT NULL
            AND length(recovery_condition_identity) = 71
            AND substr(recovery_condition_identity, 1, 7) = 'sha256:'
            AND length(recovery_authority_identity) = 71
            AND substr(recovery_authority_identity, 1, 7) = 'sha256:'
            AND length(recovery_grant_identity) = 71
            AND substr(recovery_grant_identity, 1, 7) = 'sha256:')
    ),
    FOREIGN KEY (root_binding_identity)
        REFERENCES c2_signer_root_binding_projection(root_binding_identity),
    FOREIGN KEY (predecessor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity),
    FOREIGN KEY (successor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

CREATE TABLE c2_signer_lineage_projection (
    lineage_identity TEXT PRIMARY KEY CHECK (
        length(lineage_identity) = 71
        AND substr(lineage_identity, 1, 7) = 'sha256:'
    ),
    root_binding_identity TEXT NOT NULL,
    initial_binding_identity TEXT NOT NULL,
    terminal_binding_identity TEXT NOT NULL,
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    terminal_candidate_set_identity TEXT NOT NULL CHECK (
        length(terminal_candidate_set_identity) = 71
        AND substr(terminal_candidate_set_identity, 1, 7) = 'sha256:'
    ),
    effective_cut INTEGER NOT NULL CHECK (effective_cut > 0),
    -- A complete proof-relevant lineage grows with arbitrary finite depth.
    -- No fixed fixture-depth or compaction bound is introduced here.
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    canonical_bytes_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(canonical_bytes_sha256) = 71
        AND substr(canonical_bytes_sha256, 1, 7) = 'sha256:'
    ),
    canonical_bytes_length INTEGER NOT NULL CHECK (canonical_bytes_length > 0),
    projected_at TEXT NOT NULL,
    UNIQUE (root_binding_identity, terminal_binding_identity),
    CHECK (length(canonical_bytes) = canonical_bytes_length),
    CHECK (edge_count > 0 OR initial_binding_identity = terminal_binding_identity),
    FOREIGN KEY (root_binding_identity)
        REFERENCES c2_signer_root_binding_projection(root_binding_identity),
    FOREIGN KEY (initial_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity),
    FOREIGN KEY (terminal_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

CREATE TABLE c2_signer_lineage_edge_projection (
    lineage_identity TEXT NOT NULL,
    edge_ordinal INTEGER NOT NULL CHECK (edge_ordinal >= 0),
    succession_identity TEXT NOT NULL,
    predecessor_binding_identity TEXT NOT NULL,
    successor_binding_identity TEXT NOT NULL,
    succession_mode TEXT NOT NULL CHECK (succession_mode IN ('normal', 'restore', 'recovery')),
    PRIMARY KEY (lineage_identity, edge_ordinal),
    UNIQUE (lineage_identity, succession_identity),
    UNIQUE (lineage_identity, predecessor_binding_identity),
    UNIQUE (lineage_identity, successor_binding_identity),
    FOREIGN KEY (lineage_identity)
        REFERENCES c2_signer_lineage_projection(lineage_identity),
    FOREIGN KEY (succession_identity)
        REFERENCES c2_signer_succession_projection(succession_identity),
    FOREIGN KEY (predecessor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity),
    FOREIGN KEY (successor_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

CREATE TABLE c2_signer_lineage_completion_projection (
    lineage_identity TEXT PRIMARY KEY,
    completion_identity TEXT NOT NULL UNIQUE CHECK (
        length(completion_identity) = 71
        AND substr(completion_identity, 1, 7) = 'sha256:'
    ),
    root_binding_identity TEXT NOT NULL,
    terminal_binding_identity TEXT NOT NULL,
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    completed_at TEXT NOT NULL,
    FOREIGN KEY (lineage_identity)
        REFERENCES c2_signer_lineage_projection(lineage_identity),
    FOREIGN KEY (root_binding_identity)
        REFERENCES c2_signer_root_binding_projection(root_binding_identity),
    FOREIGN KEY (terminal_binding_identity)
        REFERENCES c2_signer_current_binding_projection(current_binding_identity)
) STRICT;

-- Every current binding must repeat the exact immutable root coordinates.
CREATE TRIGGER c2_signer_current_binding_root_correspondence
BEFORE INSERT ON c2_signer_current_binding_projection
WHEN NOT EXISTS (
    SELECT 1 FROM c2_signer_root_binding_projection AS root
    WHERE root.root_binding_identity = NEW.root_binding_identity
      AND root.occurrence_id = NEW.occurrence_id
      AND root.physical_store_generation_identity = NEW.physical_store_generation_identity
      AND root.signer_lifecycle_root_identity = NEW.signer_lifecycle_root_identity
      AND root.scope_identity = NEW.scope_identity
      AND root.resident_identity = NEW.resident_identity
      AND root.resident_generation = NEW.resident_generation
      AND root.host_role = NEW.host_role
      AND root.role_manifest_generation = NEW.role_manifest_generation
      AND root.authority_domain = NEW.authority_domain
      AND root.policy_lineage_root_identity = NEW.policy_lineage_root_identity
      AND (NEW.binding_mode <> 'initial'
        OR (root.initial_enrollment_identity = NEW.current_enrollment_identity
          AND root.initial_key_generation = NEW.current_key_generation
          AND root.initial_public_key = NEW.current_public_key))
)
BEGIN
    SELECT RAISE(ABORT, 'current binding does not correspond to immutable signer root');
END;

-- A succession is one exact adjacent edge under one immutable root.
CREATE TRIGGER c2_signer_succession_exact_bindings
BEFORE INSERT ON c2_signer_succession_projection
WHEN NOT EXISTS (
    SELECT 1
    FROM c2_signer_current_binding_projection AS predecessor
    JOIN c2_signer_current_binding_projection AS successor
      ON successor.current_binding_identity = NEW.successor_binding_identity
    WHERE predecessor.current_binding_identity = NEW.predecessor_binding_identity
      AND predecessor.root_binding_identity = NEW.root_binding_identity
      AND successor.root_binding_identity = NEW.root_binding_identity
      AND predecessor.effective_cut = NEW.predecessor_cut
      AND successor.effective_cut = NEW.successor_cut
      AND successor.predecessor_binding_identity = predecessor.current_binding_identity
      AND successor.transition_identity = NEW.transition_identity
      AND successor.persisted_resolution_identity = NEW.persisted_resolution_identity
      AND ((NEW.succession_mode = 'normal'
            AND successor.binding_mode = 'normal_successor'
            AND successor.continuity_authorization_identity = NEW.authorization_identity)
        OR (NEW.succession_mode = 'restore'
            AND successor.binding_mode = 'restore_successor'
            AND successor.restore_lineage_identity = NEW.restore_lineage_identity
            AND successor.restore_authority_identity = NEW.restore_authority_identity
            AND successor.historical_foundation_identity = NEW.historical_foundation_identity
            AND NEW.authorization_identity = NEW.restore_authority_identity)
        OR (NEW.succession_mode = 'recovery'
            AND successor.binding_mode = 'recovery_successor'
            AND successor.recovery_condition_identity = NEW.recovery_condition_identity
            AND successor.recovery_authority_identity = NEW.recovery_authority_identity
            AND successor.recovery_grant_identity = NEW.recovery_grant_identity))
)
BEGIN
    SELECT RAISE(ABORT, 'succession does not bind exact adjacent predecessor and successor');
END;

-- Edge zero consumes the declared initial binding.  Every later edge consumes
-- exactly the immediately preceding successor; ordering or sorting cannot
-- manufacture adjacency.
CREATE TRIGGER c2_signer_lineage_edge_zero_exact_initial
BEFORE INSERT ON c2_signer_lineage_edge_projection
WHEN NEW.edge_ordinal = 0 AND NOT EXISTS (
    SELECT 1
    FROM c2_signer_lineage_projection AS lineage
    JOIN c2_signer_succession_projection AS succession
      ON succession.succession_identity = NEW.succession_identity
    WHERE lineage.lineage_identity = NEW.lineage_identity
      AND lineage.edge_count > 0
      AND NEW.edge_ordinal < lineage.edge_count
      AND lineage.root_binding_identity = succession.root_binding_identity
      AND lineage.initial_binding_identity = NEW.predecessor_binding_identity
      AND succession.predecessor_binding_identity = NEW.predecessor_binding_identity
      AND succession.successor_binding_identity = NEW.successor_binding_identity
      AND succession.succession_mode = NEW.succession_mode
)
BEGIN
    SELECT RAISE(ABORT, 'first lineage edge does not consume exact initial binding');
END;

CREATE TRIGGER c2_signer_lineage_edge_exact_previous_terminal
BEFORE INSERT ON c2_signer_lineage_edge_projection
WHEN NEW.edge_ordinal > 0 AND NOT EXISTS (
    SELECT 1
    FROM c2_signer_lineage_projection AS lineage
    JOIN c2_signer_lineage_edge_projection AS previous
      ON previous.lineage_identity = NEW.lineage_identity
     AND previous.edge_ordinal = NEW.edge_ordinal - 1
    JOIN c2_signer_succession_projection AS succession
      ON succession.succession_identity = NEW.succession_identity
    WHERE lineage.lineage_identity = NEW.lineage_identity
      AND NEW.edge_ordinal < lineage.edge_count
      AND lineage.root_binding_identity = succession.root_binding_identity
      AND previous.successor_binding_identity = NEW.predecessor_binding_identity
      AND succession.predecessor_binding_identity = NEW.predecessor_binding_identity
      AND succession.successor_binding_identity = NEW.successor_binding_identity
      AND succession.succession_mode = NEW.succession_mode
)
BEGIN
    SELECT RAISE(ABORT, 'lineage edge does not consume exact previous terminal binding');
END;

-- Completion can be projected only for a complete zero-edge lineage or for a
-- gap-free exact edge sequence whose last successor is the declared terminal.
CREATE TRIGGER c2_signer_lineage_completion_exact
BEFORE INSERT ON c2_signer_lineage_completion_projection
WHEN NOT EXISTS (
    SELECT 1 FROM c2_signer_lineage_projection AS lineage
    WHERE lineage.lineage_identity = NEW.lineage_identity
      AND lineage.root_binding_identity = NEW.root_binding_identity
      AND lineage.terminal_binding_identity = NEW.terminal_binding_identity
      AND lineage.edge_count = NEW.edge_count
      AND (
        (lineage.edge_count = 0
          AND lineage.initial_binding_identity = lineage.terminal_binding_identity
          AND NOT EXISTS (
              SELECT 1 FROM c2_signer_lineage_edge_projection AS edge
              WHERE edge.lineage_identity = lineage.lineage_identity
          ))
        OR
        (lineage.edge_count > 0
          AND (SELECT COUNT(*) FROM c2_signer_lineage_edge_projection AS edge
               WHERE edge.lineage_identity = lineage.lineage_identity) = lineage.edge_count
          AND EXISTS (
              SELECT 1 FROM c2_signer_lineage_edge_projection AS edge
              WHERE edge.lineage_identity = lineage.lineage_identity
                AND edge.edge_ordinal = lineage.edge_count - 1
                AND edge.successor_binding_identity = lineage.terminal_binding_identity
          ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'lineage completion has a gap, fork, mismatch, or incomplete terminal');
END;

-- Every signer projection is immutable.  Malformed or incomplete material is
-- refused; SQL never silently repairs, deletes, or chooses among candidates.
CREATE TRIGGER immutable_c2_signer_root_binding_update BEFORE UPDATE ON c2_signer_root_binding_projection BEGIN SELECT RAISE(ABORT, 'append-only signer root projection'); END;
CREATE TRIGGER immutable_c2_signer_root_binding_delete BEFORE DELETE ON c2_signer_root_binding_projection BEGIN SELECT RAISE(ABORT, 'append-only signer root projection'); END;
CREATE TRIGGER immutable_c2_signer_current_binding_update BEFORE UPDATE ON c2_signer_current_binding_projection BEGIN SELECT RAISE(ABORT, 'append-only current binding projection'); END;
CREATE TRIGGER immutable_c2_signer_current_binding_delete BEFORE DELETE ON c2_signer_current_binding_projection BEGIN SELECT RAISE(ABORT, 'append-only current binding projection'); END;
CREATE TRIGGER immutable_c2_signer_succession_update BEFORE UPDATE ON c2_signer_succession_projection BEGIN SELECT RAISE(ABORT, 'append-only succession projection'); END;
CREATE TRIGGER immutable_c2_signer_succession_delete BEFORE DELETE ON c2_signer_succession_projection BEGIN SELECT RAISE(ABORT, 'append-only succession projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_update BEFORE UPDATE ON c2_signer_lineage_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_delete BEFORE DELETE ON c2_signer_lineage_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_edge_update BEFORE UPDATE ON c2_signer_lineage_edge_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage edge projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_edge_delete BEFORE DELETE ON c2_signer_lineage_edge_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage edge projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_completion_update BEFORE UPDATE ON c2_signer_lineage_completion_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage completion projection'); END;
CREATE TRIGGER immutable_c2_signer_lineage_completion_delete BEFORE DELETE ON c2_signer_lineage_completion_projection BEGIN SELECT RAISE(ABORT, 'append-only lineage completion projection'); END;

-- Durable Store-owned pre-generation custody/proposal frontier.  Rows are
-- immutable evidence only: ordinals and digests cannot construct custody or
-- signer standing.  The live Store actor recomputes the complete frontier,
-- reopens the fixed NOFOLLOW custody carrier, and mints fresh process-local
-- custody before any authority-bearing use.
CREATE TABLE c2_custody_proposal_preparations (
    preparation_identity TEXT PRIMARY KEY CHECK (
        length(preparation_identity) = 71 AND substr(preparation_identity, 1, 7) = 'sha256:'
    ),
    -- Custody preparation exists only when a stable foundation is created.
    -- Restore reuses the exact preparation of the historical foundation and
    -- therefore never creates a `restoreHistorical` preparation row.
    preparation_lineage TEXT NOT NULL CHECK (preparation_lineage IN (
        'initialExternal', 'ordinarySuccessorContinuity',
        'recoveryNewFoundation'
    )),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) BETWEEN 1 AND 256),
    scope_token TEXT NOT NULL CHECK (
        length(scope_token) = 71 AND substr(scope_token, 1, 7) = 'sha256:'
    ),
    proposal_ordinal INTEGER NOT NULL CHECK (
        proposal_ordinal > 0 AND proposal_ordinal <= 9007199254740991
    ),
    predecessor_frontier_identity TEXT NOT NULL CHECK (
        length(predecessor_frontier_identity) = 71
        AND substr(predecessor_frontier_identity, 1, 7) = 'sha256:'
    ),
    resulting_frontier_identity TEXT NOT NULL UNIQUE CHECK (
        length(resulting_frontier_identity) = 71
        AND substr(resulting_frontier_identity, 1, 7) = 'sha256:'
    ),
    proposal_identity TEXT NOT NULL UNIQUE CHECK (
        length(proposal_identity) = 71 AND substr(proposal_identity, 1, 7) = 'sha256:'
    ),
    proposal_canonical_bytes BLOB NOT NULL CHECK (
        length(proposal_canonical_bytes) > 0
        AND length(proposal_canonical_bytes) <= 1048576
        AND json_valid(CAST(proposal_canonical_bytes AS TEXT))
    ),
    proposal_canonical_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(proposal_canonical_sha256) = 71
        AND substr(proposal_canonical_sha256, 1, 7) = 'sha256:'
    ),
    proposal_canonical_length INTEGER NOT NULL CHECK (
        proposal_canonical_length > 0 AND proposal_canonical_length <= 1048576
    ),
    bootstrap_request_identity TEXT UNIQUE CHECK (
        bootstrap_request_identity IS NULL OR (
            length(bootstrap_request_identity) = 71
            AND substr(bootstrap_request_identity, 1, 7) = 'sha256:'
        )
    ),
    bootstrap_request_canonical_bytes BLOB CHECK (
        bootstrap_request_canonical_bytes IS NULL OR (
            length(bootstrap_request_canonical_bytes) > 0
            AND length(bootstrap_request_canonical_bytes) <= 1048576
            AND json_valid(CAST(bootstrap_request_canonical_bytes AS TEXT))
        )
    ),
    bootstrap_request_canonical_sha256 TEXT UNIQUE CHECK (
        bootstrap_request_canonical_sha256 IS NULL OR (
            length(bootstrap_request_canonical_sha256) = 71
            AND substr(bootstrap_request_canonical_sha256, 1, 7) = 'sha256:'
        )
    ),
    bootstrap_request_canonical_length INTEGER CHECK (
        bootstrap_request_canonical_length IS NULL OR (
            bootstrap_request_canonical_length > 0
            AND bootstrap_request_canonical_length <= 1048576
        )
    ),
    install_policy_calculation_identity TEXT CHECK (
        install_policy_calculation_identity IS NULL OR (
            length(install_policy_calculation_identity) = 71
            AND substr(install_policy_calculation_identity, 1, 7) = 'sha256:'
        )
    ),
    install_policy_calculation_canonical_bytes BLOB CHECK (
        install_policy_calculation_canonical_bytes IS NULL OR (
            length(install_policy_calculation_canonical_bytes) > 0
            AND length(install_policy_calculation_canonical_bytes) <= 1048576
            AND json_valid(CAST(install_policy_calculation_canonical_bytes AS TEXT))
        )
    ),
    install_policy_calculation_canonical_sha256 TEXT CHECK (
        install_policy_calculation_canonical_sha256 IS NULL OR (
            length(install_policy_calculation_canonical_sha256) = 71
            AND substr(install_policy_calculation_canonical_sha256, 1, 7) = 'sha256:'
        )
    ),
    install_policy_calculation_canonical_length INTEGER CHECK (
        install_policy_calculation_canonical_length IS NULL OR (
            install_policy_calculation_canonical_length > 0
            AND install_policy_calculation_canonical_length <= 1048576
        )
    ),
    successor_request_identity TEXT UNIQUE CHECK (
        successor_request_identity IS NULL OR (
            length(successor_request_identity) = 71
            AND substr(successor_request_identity, 1, 7) = 'sha256:'
        )
    ),
    successor_request_canonical_bytes BLOB CHECK (
        successor_request_canonical_bytes IS NULL OR (
            length(successor_request_canonical_bytes) > 0
            AND length(successor_request_canonical_bytes) <= 1048576
            AND json_valid(CAST(successor_request_canonical_bytes AS TEXT))
        )
    ),
    successor_request_canonical_sha256 TEXT UNIQUE CHECK (
        successor_request_canonical_sha256 IS NULL OR (
            length(successor_request_canonical_sha256) = 71
            AND substr(successor_request_canonical_sha256, 1, 7) = 'sha256:'
        )
    ),
    successor_request_canonical_length INTEGER CHECK (
        successor_request_canonical_length IS NULL OR (
            successor_request_canonical_length > 0
            AND successor_request_canonical_length <= 1048576
        )
    ),
    predecessor_binding_identity TEXT CHECK (
        predecessor_binding_identity IS NULL OR (
            length(predecessor_binding_identity) = 71
            AND substr(predecessor_binding_identity, 1, 7) = 'sha256:'
        )
    ),
    transition_identity TEXT CHECK (
        transition_identity IS NULL OR (
            length(transition_identity) = 71
            AND substr(transition_identity, 1, 7) = 'sha256:'
        )
    ),
    -- Custody preparation precedes MSG-06/MSG-15 verification.  It must not
    -- serialize or predict the later live adoption authority; exact authority
    -- references belong to the append-only foundation-adoption event.
    lineage_authority_identity TEXT CHECK (
        lineage_authority_identity IS NULL OR (
            length(lineage_authority_identity) = 71
            AND substr(lineage_authority_identity, 1, 7) = 'sha256:'
        )
    ),
    historical_foundation_identity TEXT CHECK (
        historical_foundation_identity IS NULL OR (
            length(historical_foundation_identity) = 71
            AND substr(historical_foundation_identity, 1, 7) = 'sha256:'
        )
    ),
    terminal_binding_identity TEXT CHECK (
        terminal_binding_identity IS NULL OR (
            length(terminal_binding_identity) = 71
            AND substr(terminal_binding_identity, 1, 7) = 'sha256:'
        )
    ),
    implementation_manifest_identity TEXT NOT NULL CHECK (
        length(implementation_manifest_identity) = 71
        AND substr(implementation_manifest_identity, 1, 7) = 'sha256:'
    ),
    qualified_candidate_identity TEXT NOT NULL CHECK (
        length(qualified_candidate_identity) = 71
        AND substr(qualified_candidate_identity, 1, 7) = 'sha256:'
    ),
    source_tree_identity TEXT NOT NULL CHECK (
        length(source_tree_identity) = 71 AND substr(source_tree_identity, 1, 7) = 'sha256:'
    ),
    runtime_artifact_identity TEXT NOT NULL CHECK (
        length(runtime_artifact_identity) = 71
        AND substr(runtime_artifact_identity, 1, 7) = 'sha256:'
    ),
    prepared_at TEXT NOT NULL,
    UNIQUE (scope_token, proposal_ordinal),
    CHECK (length(proposal_canonical_bytes) = proposal_canonical_length),
    CHECK (bootstrap_request_canonical_bytes IS NULL
        OR length(bootstrap_request_canonical_bytes) = bootstrap_request_canonical_length),
    CHECK (install_policy_calculation_canonical_bytes IS NULL
        OR length(install_policy_calculation_canonical_bytes)
            = install_policy_calculation_canonical_length),
    CHECK (successor_request_canonical_bytes IS NULL
        OR length(successor_request_canonical_bytes) = successor_request_canonical_length),
    CHECK (json_extract(CAST(proposal_canonical_bytes AS TEXT), '$.proposal_identity')
        = proposal_identity),
    CHECK (bootstrap_request_canonical_bytes IS NULL OR
        json_extract(CAST(bootstrap_request_canonical_bytes AS TEXT), '$.grant_request_identity')
            = bootstrap_request_identity),
    CHECK (bootstrap_request_canonical_bytes IS NULL OR
        json_extract(CAST(bootstrap_request_canonical_bytes AS TEXT), '$.proposal_identity')
            = proposal_identity),
    CHECK (
        (preparation_lineage = 'initialExternal'
         AND bootstrap_request_identity IS NOT NULL
         AND bootstrap_request_canonical_bytes IS NOT NULL
         AND bootstrap_request_canonical_sha256 IS NOT NULL
         AND bootstrap_request_canonical_length IS NOT NULL
         AND install_policy_calculation_identity IS NOT NULL
         AND install_policy_calculation_canonical_bytes IS NOT NULL
         AND install_policy_calculation_canonical_sha256 IS NOT NULL
         AND install_policy_calculation_canonical_length IS NOT NULL
         AND successor_request_identity IS NULL
         AND successor_request_canonical_bytes IS NULL
         AND successor_request_canonical_sha256 IS NULL
         AND successor_request_canonical_length IS NULL
         AND predecessor_binding_identity IS NULL
         AND transition_identity IS NULL
         AND lineage_authority_identity IS NULL
         AND historical_foundation_identity IS NULL
         AND terminal_binding_identity IS NULL)
        OR
        (preparation_lineage = 'ordinarySuccessorContinuity'
         AND bootstrap_request_identity IS NULL
         AND bootstrap_request_canonical_bytes IS NULL
         AND bootstrap_request_canonical_sha256 IS NULL
         AND bootstrap_request_canonical_length IS NULL
         AND install_policy_calculation_identity IS NULL
         AND install_policy_calculation_canonical_bytes IS NULL
         AND install_policy_calculation_canonical_sha256 IS NULL
         AND install_policy_calculation_canonical_length IS NULL
         AND successor_request_identity IS NOT NULL
         AND successor_request_canonical_bytes IS NOT NULL
         AND successor_request_canonical_sha256 IS NOT NULL
         AND successor_request_canonical_length IS NOT NULL
         AND predecessor_binding_identity IS NOT NULL
         AND transition_identity IS NOT NULL
         AND lineage_authority_identity IS NULL
         AND historical_foundation_identity IS NULL
         AND terminal_binding_identity IS NULL)
        OR
        (preparation_lineage = 'recoveryNewFoundation'
         AND bootstrap_request_identity IS NULL
         AND bootstrap_request_canonical_bytes IS NULL
         AND bootstrap_request_canonical_sha256 IS NULL
         AND bootstrap_request_canonical_length IS NULL
         AND install_policy_calculation_identity IS NULL
         AND install_policy_calculation_canonical_bytes IS NULL
         AND install_policy_calculation_canonical_sha256 IS NULL
         AND install_policy_calculation_canonical_length IS NULL
         AND successor_request_identity IS NOT NULL
         AND successor_request_canonical_bytes IS NOT NULL
         AND successor_request_canonical_sha256 IS NOT NULL
         AND successor_request_canonical_length IS NOT NULL
         AND predecessor_binding_identity IS NOT NULL
         AND transition_identity IS NOT NULL
         AND lineage_authority_identity IS NULL
         AND historical_foundation_identity IS NOT NULL
         AND terminal_binding_identity IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER immutable_c2_custody_proposal_preparations_update
BEFORE UPDATE ON c2_custody_proposal_preparations
BEGIN SELECT RAISE(ABORT, 'custody proposal preparation is append-only'); END;
CREATE TRIGGER immutable_c2_custody_proposal_preparations_delete
BEFORE DELETE ON c2_custody_proposal_preparations
BEGIN SELECT RAISE(ABORT, 'custody proposal preparation is append-only'); END;

-- Durable closed-family signing ledger.  The canonical message, exact
-- signature preimage, signature, route correspondence, frontier, and effect
-- receipt commit in one SQLite transaction.  Live signer authority is never
-- serialized here.
CREATE TABLE c2_signer_message_appends (
    ledger_sequence INTEGER PRIMARY KEY CHECK (ledger_sequence > 0),
    generation_sequence INTEGER NOT NULL CHECK (generation_sequence > 0),
    append_identity TEXT NOT NULL UNIQUE CHECK (
        length(append_identity) = 71 AND substr(append_identity, 1, 7) = 'sha256:'
    ),
    message_identity BLOB NOT NULL UNIQUE CHECK (length(message_identity) = 32),
    family TEXT NOT NULL CHECK (family IN (
        'MSG-02', 'MSG-03', 'MSG-05', 'MSG-06', 'MSG-07', 'MSG-08',
        'MSG-09', 'MSG-10', 'MSG-11', 'MSG-12'
    )),
    route TEXT NOT NULL CHECK (route IN (
        'msg02_initial_pop', 'msg03_physical_generation_bootstrap',
        'msg05_active_policy_continuity', 'msg06_normal_rotation_continuity',
        'msg07_successor_pop', 'msg08_global_refusal',
        'msg09_installation_intent', 'msg10_installation_receipt',
        'msg11_policy_transition_intent', 'msg12_receipt_current',
        'msg12_receipt_pending'
    )),
    identity_domain TEXT NOT NULL,
    signature_domain TEXT NOT NULL,
    signer_phase TEXT NOT NULL CHECK (signer_phase IN (
        'proposed_initial', 'bootstrap', 'current_predecessor',
        'generation_current', 'pending_successor'
    )),
    scope_class TEXT NOT NULL CHECK (scope_class IN (
        'pre_generation', 'prospective_physical_generation', 'generation_bound'
    )),
    authority_class TEXT NOT NULL CHECK (authority_class IN (
        'proposed_key', 'bootstrap', 'current_predecessor',
        'generation_current', 'pending_successor'
    )),
    input_kind TEXT NOT NULL,
    sole_consumer TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL CHECK (signature_algorithm = 'ed25519'),
    occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) > 0),
    occurrence_identity BLOB NOT NULL CHECK (length(occurrence_identity) = 32),
    physical_generation_identity BLOB CHECK (
        physical_generation_identity IS NULL OR length(physical_generation_identity) = 32
    ),
    lifecycle_root_identity BLOB CHECK (
        lifecycle_root_identity IS NULL OR length(lifecycle_root_identity) = 32
    ),
    prospective_generation_preimage BLOB CHECK (
        prospective_generation_preimage IS NULL OR length(prospective_generation_preimage) = 32
    ),
    scope_identity BLOB NOT NULL CHECK (length(scope_identity) = 32),
    resident_identity TEXT NOT NULL CHECK (length(resident_identity) > 0),
    resident_generation INTEGER NOT NULL CHECK (
        resident_generation > 0 AND resident_generation <= 9007199254740991
    ),
    host_role TEXT NOT NULL CHECK (length(host_role) > 0),
    role_manifest_identity BLOB NOT NULL CHECK (length(role_manifest_identity) = 32),
    role_manifest_generation INTEGER NOT NULL CHECK (
        role_manifest_generation > 0 AND role_manifest_generation <= 9007199254740991
    ),
    authority_domain TEXT NOT NULL CHECK (length(authority_domain) > 0),
    terminal_a1_identity BLOB NOT NULL CHECK (length(terminal_a1_identity) = 32),
    current_a2_snapshot_identity BLOB NOT NULL CHECK (length(current_a2_snapshot_identity) = 32),
    grant_or_predecessor_standing_identity BLOB NOT NULL CHECK (
        length(grant_or_predecessor_standing_identity) = 32
    ),
    signer_public_key BLOB NOT NULL CHECK (length(signer_public_key) = 32),
    signer_scope_policy_identity BLOB NOT NULL CHECK (length(signer_scope_policy_identity) = 32),
    signer_scope_policy_version INTEGER NOT NULL CHECK (
        signer_scope_policy_version > 0 AND signer_scope_policy_version <= 9007199254740991
    ),
    active_store_policy_identity BLOB NOT NULL CHECK (length(active_store_policy_identity) = 32),
    active_store_policy_generation INTEGER NOT NULL CHECK (
        active_store_policy_generation > 0 AND active_store_policy_generation <= 9007199254740991
    ),
    active_store_policy_digest BLOB NOT NULL CHECK (length(active_store_policy_digest) = 32),
    implementation_manifest_identity BLOB NOT NULL CHECK (length(implementation_manifest_identity) = 32),
    manifest_admission_correspondence_identity BLOB NOT NULL CHECK (length(manifest_admission_correspondence_identity) = 32),
    qualified_candidate_identity BLOB NOT NULL CHECK (length(qualified_candidate_identity) = 32),
    source_tree_identity BLOB NOT NULL CHECK (length(source_tree_identity) = 32),
    runtime_artifact_identity BLOB NOT NULL CHECK (length(runtime_artifact_identity) = 32),
    terminal_binding_identity BLOB CHECK (
        terminal_binding_identity IS NULL OR length(terminal_binding_identity) = 32
    ),
    signer_key_generation INTEGER NOT NULL CHECK (
        signer_key_generation >= 0 AND signer_key_generation <= 9007199254740991
    ),
    signer_key_generation_identity BLOB NOT NULL CHECK (length(signer_key_generation_identity) = 32),
    event_predecessor_identity BLOB NOT NULL CHECK (length(event_predecessor_identity) = 32),
    transaction_identity BLOB NOT NULL CHECK (length(transaction_identity) = 32),
    transaction_intent_identity BLOB NOT NULL CHECK (length(transaction_intent_identity) = 32),
    frontier_namespace_identity BLOB NOT NULL CHECK (length(frontier_namespace_identity) = 32),
    predecessor_frontier_identity BLOB NOT NULL CHECK (length(predecessor_frontier_identity) = 32),
    exact_content_identity BLOB NOT NULL CHECK (length(exact_content_identity) = 32),
    resulting_frontier_identity BLOB NOT NULL UNIQUE CHECK (length(resulting_frontier_identity) = 32),
    event_cut INTEGER NOT NULL CHECK (event_cut > 0 AND event_cut <= 9007199254740991),
    canonical_message BLOB NOT NULL CHECK (length(canonical_message) > 0),
    canonical_message_sha256 TEXT NOT NULL CHECK (
        length(canonical_message_sha256) = 71
        AND substr(canonical_message_sha256, 1, 7) = 'sha256:'
    ),
    signing_preimage BLOB NOT NULL CHECK (length(signing_preimage) > 0),
    signing_preimage_sha256 TEXT NOT NULL CHECK (
        length(signing_preimage_sha256) = 71
        AND substr(signing_preimage_sha256, 1, 7) = 'sha256:'
    ),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    effect_receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_receipt_identity) = 71
        AND substr(effect_receipt_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_bytes BLOB NOT NULL CHECK (length(effect_receipt_bytes) > 0),
    physical_carrier_bytes BLOB,
    physical_carrier_sha256 TEXT CHECK (
        physical_carrier_sha256 IS NULL OR (
            length(physical_carrier_sha256) = 71
            AND substr(physical_carrier_sha256, 1, 7) = 'sha256:'
        )
    ),
    physical_carrier_length INTEGER CHECK (
        physical_carrier_length IS NULL OR physical_carrier_length > 0
    ),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0),
    CHECK (
        (route = 'msg02_initial_pop'
         AND physical_carrier_bytes IS NULL
         AND physical_carrier_sha256 IS NULL
         AND physical_carrier_length IS NULL)
        OR
        (route <> 'msg02_initial_pop'
         AND physical_carrier_bytes IS NOT NULL
         AND physical_carrier_sha256 IS NOT NULL
         AND physical_carrier_length IS NOT NULL
         AND length(physical_carrier_bytes) = physical_carrier_length)
    ),
    UNIQUE (frontier_namespace_identity, generation_sequence),
    UNIQUE (route, occurrence_identity, transaction_identity)
) STRICT;

-- Registry parity is enforced again at the durable boundary.  No row may
-- relabel a family, phase, scope, authority, input, consumer, or domain.
CREATE TRIGGER c2_signer_message_registry_exact
BEFORE INSERT ON c2_signer_message_appends
WHEN NOT (
    (NEW.route = 'msg02_initial_pop' AND NEW.family = 'MSG-02'
      AND NEW.identity_domain = 'nq.c2.store_integrity_initial_pop.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_initial_pop.possession_signature.v1'
      AND NEW.signer_phase = 'proposed_initial' AND NEW.scope_class = 'pre_generation'
      AND NEW.physical_generation_identity IS NULL AND NEW.lifecycle_root_identity IS NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NULL
      AND NEW.authority_class = 'proposed_key' AND NEW.input_kind = 'initial_pop_candidate'
      AND NEW.sole_consumer = 'accepted_enrollment_wrapper')
 OR (NEW.route = 'msg03_physical_generation_bootstrap' AND NEW.family = 'MSG-03'
      AND NEW.identity_domain = 'nq.c2.store_generation.bootstrap.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_generation.bootstrap.signature.v1'
      AND NEW.signer_phase = 'bootstrap' AND NEW.scope_class = 'prospective_physical_generation'
      AND NEW.physical_generation_identity IS NULL AND NEW.lifecycle_root_identity IS NULL
      AND NEW.prospective_generation_preimage IS NOT NULL AND NEW.terminal_binding_identity IS NULL
      AND NEW.authority_class = 'bootstrap' AND NEW.input_kind = 'physical_generation_bootstrap_facts'
      AND NEW.sole_consumer = 'installation_bootstrap_append')
 OR (NEW.route = 'msg05_active_policy_continuity' AND NEW.family = 'MSG-05'
      AND NEW.identity_domain = 'nq.c2.active_policy_continuity.identity.v1'
      AND NEW.signature_domain = 'nq.c2.active_policy_continuity.current_predecessor_signature.v1'
      AND NEW.signer_phase = 'current_predecessor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'current_predecessor' AND NEW.input_kind = 'active_policy_continuity_facts'
      AND NEW.sole_consumer = 'active_policy_transition_append')
 OR (NEW.route = 'msg06_normal_rotation_continuity' AND NEW.family = 'MSG-06'
      AND NEW.identity_domain = 'nq.c2.signer_rotation_continuity.identity.v1'
      AND NEW.signature_domain = 'nq.c2.signer_rotation_continuity.current_predecessor_signature.v1'
      AND NEW.signer_phase = 'current_predecessor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'current_predecessor' AND NEW.input_kind = 'healthy_rotation_continuity_facts'
      AND NEW.sole_consumer = 'healthy_rotation_append')
 OR (NEW.route = 'msg07_successor_pop' AND NEW.family = 'MSG-07'
      AND NEW.identity_domain = 'nq.c2.store_integrity_successor_pop.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_successor_pop.pending_possession_signature.v1'
      AND NEW.signer_phase = 'pending_successor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'pending_successor' AND NEW.input_kind = 'successor_pop_challenge'
      AND NEW.sole_consumer = 'selected_successor_pop')
 OR (NEW.route = 'msg08_global_refusal' AND NEW.family = 'MSG-08'
      AND NEW.identity_domain = 'nq.c2.global_refusal.identity.v1'
      AND NEW.signature_domain = 'nq.c2.global_refusal.generation_current_signature.v1'
      AND NEW.signer_phase = 'generation_current' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'generation_current' AND NEW.input_kind = 'classified_global_refusal'
      AND NEW.sole_consumer = 'global_refusal_append')
 OR (NEW.route = 'msg09_installation_intent' AND NEW.family = 'MSG-09'
      AND NEW.identity_domain = 'nq.c2.installation_intent.identity.v1'
      AND NEW.signature_domain = 'nq.c2.installation_intent.store_integrity_signature.v1'
      AND NEW.signer_phase = 'bootstrap' AND NEW.scope_class = 'pre_generation'
      AND NEW.physical_generation_identity IS NULL AND NEW.lifecycle_root_identity IS NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NULL
      AND NEW.authority_class = 'bootstrap' AND NEW.input_kind = 'installation_intent_facts'
      AND NEW.sole_consumer = 'installation_intent_append')
 OR (NEW.route = 'msg10_installation_receipt' AND NEW.family = 'MSG-10'
      AND NEW.identity_domain = 'nq.c2.installation_receipt.identity.v1'
      AND NEW.signature_domain = 'nq.c2.installation_receipt.store_integrity_signature.v1'
      AND NEW.signer_phase = 'bootstrap' AND NEW.scope_class = 'prospective_physical_generation'
      AND NEW.physical_generation_identity IS NULL AND NEW.lifecycle_root_identity IS NULL
      AND NEW.prospective_generation_preimage IS NOT NULL AND NEW.terminal_binding_identity IS NULL
      AND NEW.authority_class = 'bootstrap' AND NEW.input_kind = 'installation_completion_facts'
      AND NEW.sole_consumer = 'bootstrap_transition_close')
 OR (NEW.route = 'msg11_policy_transition_intent' AND NEW.family = 'MSG-11'
      AND NEW.identity_domain = 'nq.c2.policy_transition_intent.identity.v1'
      AND NEW.signature_domain = 'nq.c2.policy_transition_intent.current_predecessor_signature.v1'
      AND NEW.signer_phase = 'current_predecessor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'current_predecessor' AND NEW.input_kind = 'policy_transition_intent_facts'
      AND NEW.sole_consumer = 'transition_intent_append')
 OR (NEW.route = 'msg12_receipt_current' AND NEW.family = 'MSG-12'
      AND NEW.identity_domain = 'nq.c2.policy_transition_receipt.identity.v1'
      AND NEW.signature_domain = 'nq.c2.policy_transition_receipt.generation_current_signature.v1'
      AND NEW.signer_phase = 'generation_current' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'generation_current' AND NEW.input_kind = 'transition_receipt_current_facts'
      AND NEW.sole_consumer = 'generation_current_resolution')
 OR (NEW.route = 'msg12_receipt_pending' AND NEW.family = 'MSG-12'
      AND NEW.identity_domain = 'nq.c2.policy_transition_receipt.identity.v1'
      AND NEW.signature_domain = 'nq.c2.policy_transition_receipt.pending_successor_signature.v1'
      AND NEW.signer_phase = 'pending_successor' AND NEW.scope_class = 'generation_bound'
      AND NEW.physical_generation_identity IS NOT NULL AND NEW.lifecycle_root_identity IS NOT NULL
      AND NEW.prospective_generation_preimage IS NULL AND NEW.terminal_binding_identity IS NOT NULL
      AND NEW.authority_class = 'pending_successor' AND NEW.input_kind = 'transition_receipt_pending_facts'
      AND NEW.sole_consumer = 'pending_successor_resolution')
)
BEGIN
    SELECT RAISE(ABORT, 'signer message row disagrees with the closed MSG-01 through MSG-16 registry');
END;

-- Durable governed external-carrier ingress.  One request occurrence may have
-- exactly one canonical carrier.  Exact replay reopens this receipt; changed
-- canonical bytes at the same occurrence are a collision and cannot insert.
CREATE TABLE c2_external_carrier_ingress (
    ingress_sequence INTEGER PRIMARY KEY CHECK (ingress_sequence > 0),
    receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(receipt_identity) = 71 AND substr(receipt_identity, 1, 7) = 'sha256:'
    ),
    route TEXT NOT NULL CHECK (route IN (
        'msg01_bootstrap_grant', 'msg01_activation_successor_grant',
        'msg01_proposal_disposition', 'msg13_restore_authorization',
        'msg14_revocation_judgment', 'msg15_recovery_grant',
        'msg16_quarantine_closure'
    )),
    family TEXT NOT NULL CHECK (family IN ('MSG-01', 'MSG-13', 'MSG-14', 'MSG-15', 'MSG-16')),
    identity_domain TEXT NOT NULL,
    signature_domain TEXT NOT NULL,
    input_kind TEXT NOT NULL,
    sole_consumer TEXT NOT NULL,
    request_identity BLOB NOT NULL CHECK (length(request_identity) = 32),
    carrier_identity BLOB NOT NULL UNIQUE CHECK (length(carrier_identity) = 32),
    canonical_request BLOB NOT NULL CHECK (length(canonical_request) > 0),
    canonical_request_sha256 TEXT NOT NULL CHECK (
        length(canonical_request_sha256) = 71
        AND substr(canonical_request_sha256, 1, 7) = 'sha256:'
    ),
    canonical_carrier BLOB NOT NULL CHECK (length(canonical_carrier) > 0),
    canonical_carrier_sha256 TEXT NOT NULL CHECK (
        length(canonical_carrier_sha256) = 71
        AND substr(canonical_carrier_sha256, 1, 7) = 'sha256:'
    ),
    effect_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_identity) = 71 AND substr(effect_identity, 1, 7) = 'sha256:'
    ),
    receipt_bytes BLOB NOT NULL CHECK (length(receipt_bytes) > 0),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0),
    UNIQUE (route, request_identity)
) STRICT;

CREATE TRIGGER c2_external_carrier_registry_exact
BEFORE INSERT ON c2_external_carrier_ingress
WHEN NOT (
    (NEW.route = 'msg01_bootstrap_grant' AND NEW.family = 'MSG-01'
      AND NEW.identity_domain = 'nq.c2.store_integrity_bootstrap_grant.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_bootstrap_grant.a1_signature.v1'
      AND NEW.input_kind = 'bootstrap_grant_request' AND NEW.sole_consumer = 'reserve_bootstrap_attempt')
 OR (NEW.route = 'msg01_activation_successor_grant' AND NEW.family = 'MSG-01'
      AND NEW.identity_domain = 'nq.c2.store_integrity_activation_successor_grant.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_activation_successor_grant.a1_signature.v1'
      AND NEW.input_kind = 'activation_successor_grant_request'
      AND NEW.sole_consumer = 'active_policy_transition_regrant')
 OR (NEW.route = 'msg01_proposal_disposition' AND NEW.family = 'MSG-01'
      AND NEW.identity_domain = 'nq.c2.store_integrity_proposal_disposition.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_proposal_disposition.a1_signature.v1'
      AND NEW.input_kind = 'proposal_disposition_request'
      AND NEW.sole_consumer = 'deterministic_proposal_disposition')
 OR (NEW.route = 'msg13_restore_authorization' AND NEW.family = 'MSG-13'
      AND NEW.identity_domain = 'nq.c2.restore_authorization.identity.v1'
      AND NEW.signature_domain = 'nq.c2.restore_authorization.a1_signature.v1'
      AND NEW.input_kind = 'restore_authorization_request'
      AND NEW.sole_consumer = 'restore_successor_continuation')
 OR (NEW.route = 'msg14_revocation_judgment' AND NEW.family = 'MSG-14'
      AND NEW.identity_domain = 'nq.c2.store_integrity_revocation_judgment.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_revocation_judgment.a1_signature.v1'
      AND NEW.input_kind = 'revocation_judgment_request'
      AND NEW.sole_consumer = 'atomic_revocation_effect')
 OR (NEW.route = 'msg15_recovery_grant' AND NEW.family = 'MSG-15'
      AND NEW.identity_domain = 'nq.c2.store_integrity_recovery_grant.identity.v1'
      AND NEW.signature_domain = 'nq.c2.store_integrity_recovery_grant.a1_signature.v1'
      AND NEW.input_kind = 'recovery_grant_request'
      AND NEW.sole_consumer = 'recovery_transition')
 OR (NEW.route = 'msg16_quarantine_closure' AND NEW.family = 'MSG-16'
      AND NEW.identity_domain = 'nq.c2.quarantine_closure_judgment.identity.v1'
      AND NEW.signature_domain = 'nq.c2.quarantine_closure_judgment.a1_signature.v1'
      AND NEW.input_kind = 'quarantine_closure_request'
      AND NEW.sole_consumer = 'atomic_quarantine_closure_effect')
)
BEGIN
    SELECT RAISE(ABORT, 'external carrier row disagrees with the closed MSG-01 through MSG-16 registry');
END;

-- MSG-14 is not receipt-only evidence. The Store persists the exact
-- revocation target and unsigned effect receipt in the same transaction as
-- the governed ingress row. Reopen resolves this table before minting current
-- standing.
CREATE TABLE c2_revocation_effects (
    effect_sequence INTEGER PRIMARY KEY CHECK (effect_sequence > 0),
    ingress_sequence INTEGER NOT NULL UNIQUE
        REFERENCES c2_external_carrier_ingress(ingress_sequence),
    request_identity BLOB NOT NULL UNIQUE CHECK (length(request_identity) = 32),
    judgment_identity BLOB NOT NULL UNIQUE CHECK (length(judgment_identity) = 32),
    physical_generation_identity TEXT NOT NULL CHECK (
        length(physical_generation_identity) = 71
        AND substr(physical_generation_identity, 1, 7) = 'sha256:'
    ),
    lifecycle_root_identity TEXT NOT NULL CHECK (
        length(lifecycle_root_identity) = 71
        AND substr(lifecycle_root_identity, 1, 7) = 'sha256:'
    ),
    scope_identity TEXT NOT NULL CHECK (
        length(scope_identity) = 71 AND substr(scope_identity, 1, 7) = 'sha256:'
    ),
    active_policy_identity TEXT NOT NULL CHECK (
        length(active_policy_identity) = 71
        AND substr(active_policy_identity, 1, 7) = 'sha256:'
    ),
    active_policy_generation INTEGER NOT NULL CHECK (
        active_policy_generation > 0 AND active_policy_generation <= 9007199254740991
    ),
    target_enrollment_identity TEXT NOT NULL CHECK (
        length(target_enrollment_identity) = 71
        AND substr(target_enrollment_identity, 1, 7) = 'sha256:'
    ),
    target_public_key BLOB NOT NULL CHECK (length(target_public_key) = 32),
    target_key_generation INTEGER NOT NULL CHECK (
        target_key_generation >= 0 AND target_key_generation <= 9007199254740991
    ),
    target_standing_identity TEXT NOT NULL UNIQUE CHECK (
        length(target_standing_identity) = 71
        AND substr(target_standing_identity, 1, 7) = 'sha256:'
    ),
    pre_effect_frontier_identity TEXT NOT NULL CHECK (
        length(pre_effect_frontier_identity) = 71
        AND substr(pre_effect_frontier_identity, 1, 7) = 'sha256:'
    ),
    effective_cut INTEGER NOT NULL CHECK (
        effective_cut > 0 AND effective_cut <= 9007199254740991
    ),
    revocation_projection_identity TEXT NOT NULL UNIQUE CHECK (
        length(revocation_projection_identity) = 71
        AND substr(revocation_projection_identity, 1, 7) = 'sha256:'
    ),
    candidate_set_identity TEXT NOT NULL CHECK (
        length(candidate_set_identity) = 71
        AND substr(candidate_set_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_receipt_identity) = 71
        AND substr(effect_receipt_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_bytes BLOB NOT NULL CHECK (length(effect_receipt_bytes) > 0),
    effect_receipt_sha256 TEXT NOT NULL CHECK (
        length(effect_receipt_sha256) = 71
        AND substr(effect_receipt_sha256, 1, 7) = 'sha256:'
    ),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0)
) STRICT;

CREATE TRIGGER c2_revocation_effect_exact_ingress
BEFORE INSERT ON c2_revocation_effects
WHEN NOT EXISTS (
    SELECT 1 FROM c2_external_carrier_ingress AS ingress
    WHERE ingress.ingress_sequence = NEW.ingress_sequence
      AND ingress.route = 'msg14_revocation_judgment'
      AND ingress.family = 'MSG-14'
      AND ingress.request_identity = NEW.request_identity
      AND ingress.carrier_identity = NEW.judgment_identity
)
BEGIN
    SELECT RAISE(ABORT, 'revocation effect is detached from exact MSG-14 ingress');
END;

CREATE TRIGGER immutable_c2_revocation_effects_update
BEFORE UPDATE ON c2_revocation_effects
BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_c2_revocation_effects_delete
BEFORE DELETE ON c2_revocation_effects
BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

-- MSG-16 closes one exact restore quarantine. Absence of this row leaves the
-- restore successor closed to writes; its unsigned receipt cannot be stored
-- independently of the exact judgment and current signer correspondence.
CREATE TABLE c2_quarantine_closure_effects (
    effect_sequence INTEGER PRIMARY KEY CHECK (effect_sequence > 0),
    ingress_sequence INTEGER NOT NULL UNIQUE
        REFERENCES c2_external_carrier_ingress(ingress_sequence),
    request_identity BLOB NOT NULL UNIQUE CHECK (length(request_identity) = 32),
    judgment_identity BLOB NOT NULL UNIQUE CHECK (length(judgment_identity) = 32),
    physical_generation_identity TEXT NOT NULL CHECK (
        length(physical_generation_identity) = 71
        AND substr(physical_generation_identity, 1, 7) = 'sha256:'
    ),
    lifecycle_root_identity TEXT NOT NULL CHECK (
        length(lifecycle_root_identity) = 71
        AND substr(lifecycle_root_identity, 1, 7) = 'sha256:'
    ),
    scope_identity TEXT NOT NULL CHECK (
        length(scope_identity) = 71 AND substr(scope_identity, 1, 7) = 'sha256:'
    ),
    active_policy_identity TEXT NOT NULL CHECK (
        length(active_policy_identity) = 71
        AND substr(active_policy_identity, 1, 7) = 'sha256:'
    ),
    active_policy_generation INTEGER NOT NULL CHECK (
        active_policy_generation > 0 AND active_policy_generation <= 9007199254740991
    ),
    restore_authorization_identity TEXT NOT NULL UNIQUE CHECK (
        length(restore_authorization_identity) = 71
        AND substr(restore_authorization_identity, 1, 7) = 'sha256:'
    ),
    predecessor_generation_identity TEXT NOT NULL CHECK (
        length(predecessor_generation_identity) = 71
        AND substr(predecessor_generation_identity, 1, 7) = 'sha256:'
    ),
    restore_lineage_identity TEXT NOT NULL CHECK (
        length(restore_lineage_identity) = 71
        AND substr(restore_lineage_identity, 1, 7) = 'sha256:'
    ),
    restore_disposition_identity TEXT NOT NULL CHECK (
        length(restore_disposition_identity) = 71
        AND substr(restore_disposition_identity, 1, 7) = 'sha256:'
    ),
    restore_proof_identity TEXT NOT NULL CHECK (
        length(restore_proof_identity) = 71
        AND substr(restore_proof_identity, 1, 7) = 'sha256:'
    ),
    generation_commitment_identity TEXT NOT NULL CHECK (
        length(generation_commitment_identity) = 71
        AND substr(generation_commitment_identity, 1, 7) = 'sha256:'
    ),
    installation_receipt_identity TEXT NOT NULL CHECK (
        length(installation_receipt_identity) = 71
        AND substr(installation_receipt_identity, 1, 7) = 'sha256:'
    ),
    current_enrollment_identity TEXT NOT NULL CHECK (
        length(current_enrollment_identity) = 71
        AND substr(current_enrollment_identity, 1, 7) = 'sha256:'
    ),
    current_public_key BLOB NOT NULL CHECK (length(current_public_key) = 32),
    current_key_generation INTEGER NOT NULL CHECK (
        current_key_generation >= 0 AND current_key_generation <= 9007199254740991
    ),
    current_standing_identity TEXT NOT NULL CHECK (
        length(current_standing_identity) = 71
        AND substr(current_standing_identity, 1, 7) = 'sha256:'
    ),
    quarantine_identity TEXT NOT NULL UNIQUE CHECK (
        length(quarantine_identity) = 71
        AND substr(quarantine_identity, 1, 7) = 'sha256:'
    ),
    pre_effect_frontier_identity TEXT NOT NULL CHECK (
        length(pre_effect_frontier_identity) = 71
        AND substr(pre_effect_frontier_identity, 1, 7) = 'sha256:'
    ),
    closure_cut INTEGER NOT NULL CHECK (
        closure_cut > 0 AND closure_cut <= 9007199254740991
    ),
    quarantine_closure_projection_identity TEXT NOT NULL UNIQUE CHECK (
        length(quarantine_closure_projection_identity) = 71
        AND substr(quarantine_closure_projection_identity, 1, 7) = 'sha256:'
    ),
    candidate_set_identity TEXT NOT NULL CHECK (
        length(candidate_set_identity) = 71
        AND substr(candidate_set_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_receipt_identity) = 71
        AND substr(effect_receipt_identity, 1, 7) = 'sha256:'
    ),
    effect_receipt_bytes BLOB NOT NULL CHECK (length(effect_receipt_bytes) > 0),
    effect_receipt_sha256 TEXT NOT NULL CHECK (
        length(effect_receipt_sha256) = 71
        AND substr(effect_receipt_sha256, 1, 7) = 'sha256:'
    ),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0)
) STRICT;

CREATE TRIGGER c2_quarantine_closure_effect_exact_ingress
BEFORE INSERT ON c2_quarantine_closure_effects
WHEN NOT EXISTS (
    SELECT 1 FROM c2_external_carrier_ingress AS ingress
    WHERE ingress.ingress_sequence = NEW.ingress_sequence
      AND ingress.route = 'msg16_quarantine_closure'
      AND ingress.family = 'MSG-16'
      AND ingress.request_identity = NEW.request_identity
      AND ingress.carrier_identity = NEW.judgment_identity
)
BEGIN
    SELECT RAISE(ABORT, 'quarantine closure is detached from exact MSG-16 ingress');
END;

CREATE TRIGGER immutable_c2_quarantine_closure_effects_update
BEFORE UPDATE ON c2_quarantine_closure_effects
BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_c2_quarantine_closure_effects_delete
BEFORE DELETE ON c2_quarantine_closure_effects
BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

-- Canonical inert definition of a stable signer key/custody foundation.
-- Adoption lineage and live authority are deliberately absent. A historical
-- restore may therefore reference the same foundation identity through a new
-- adoption event, while recovery must insert a semantically new foundation.
CREATE TABLE c2_signer_foundations (
    foundation_identity TEXT PRIMARY KEY CHECK (
        length(foundation_identity) = 71 AND substr(foundation_identity, 1, 7) = 'sha256:'
    ),
    foundation_canonical_bytes BLOB NOT NULL CHECK (
        length(foundation_canonical_bytes) > 0
        AND json_valid(CAST(foundation_canonical_bytes AS TEXT))
    ),
    foundation_canonical_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(foundation_canonical_sha256) = 71
        AND substr(foundation_canonical_sha256, 1, 7) = 'sha256:'
    ),
    algorithm TEXT NOT NULL CHECK (algorithm = 'ed25519'),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    key_generation INTEGER NOT NULL CHECK (
        key_generation >= 0 AND key_generation <= 9007199254740991
    ),
    custody_evidence_identity BLOB NOT NULL CHECK (length(custody_evidence_identity) = 32),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0),
    UNIQUE (public_key, key_generation, custody_evidence_identity),
    CHECK (json_extract(CAST(foundation_canonical_bytes AS TEXT), '$.foundation_identity')
        = foundation_identity),
    CHECK (json_extract(CAST(foundation_canonical_bytes AS TEXT), '$.schema')
        = 'nq.c2_store_integrity_signer_foundation.v1'),
    CHECK (json_extract(CAST(foundation_canonical_bytes AS TEXT), '$.algorithm') = algorithm),
    CHECK (json_extract(CAST(foundation_canonical_bytes AS TEXT), '$.key_generation')
        = key_generation)
) STRICT;

CREATE TRIGGER immutable_c2_signer_foundations_update
BEFORE UPDATE ON c2_signer_foundations
BEGIN SELECT RAISE(ABORT, 'append-only signer foundation'); END;
CREATE TRIGGER immutable_c2_signer_foundations_delete
BEFORE DELETE ON c2_signer_foundations
BEGIN SELECT RAISE(ABORT, 'append-only signer foundation'); END;

-- Durable evidence that the Store adopted one exact stable foundation under
-- one member of the closed four-lineage taxonomy. The canonical adoption
-- bytes bind all lineage/Store/scope/cut coordinates. Process/actor fields are
-- audit evidence only and never reconstruct process-local adoption authority.
CREATE TABLE c2_foundational_enrollment_adoptions (
    adoption_sequence INTEGER PRIMARY KEY CHECK (adoption_sequence > 0),
    adoption_identity TEXT NOT NULL UNIQUE CHECK (
        length(adoption_identity) = 71 AND substr(adoption_identity, 1, 7) = 'sha256:'
    ),
    foundation_identity TEXT NOT NULL REFERENCES c2_signer_foundations(foundation_identity) CHECK (
        length(foundation_identity) = 71 AND substr(foundation_identity, 1, 7) = 'sha256:'
    ),
    adoption_canonical_bytes BLOB NOT NULL CHECK (
        length(adoption_canonical_bytes) > 0
        AND json_valid(CAST(adoption_canonical_bytes AS TEXT))
    ),
    adoption_canonical_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(adoption_canonical_sha256) = 71
        AND substr(adoption_canonical_sha256, 1, 7) = 'sha256:'
    ),
    lineage TEXT NOT NULL CHECK (lineage IN (
        'initialExternal', 'ordinarySuccessorContinuity',
        'restoreHistorical', 'recoveryNewFoundation'
    )),
    foundational_enrollment_identity TEXT UNIQUE CHECK (
        foundational_enrollment_identity IS NULL OR (
            length(foundational_enrollment_identity) = 71
            AND substr(foundational_enrollment_identity, 1, 7) = 'sha256:'
        )
    ),
    foundational_enrollment_canonical_bytes BLOB CHECK (
        foundational_enrollment_canonical_bytes IS NULL
        OR length(foundational_enrollment_canonical_bytes) > 0
    ),
    foundational_enrollment_canonical_sha256 TEXT CHECK (
        foundational_enrollment_canonical_sha256 IS NULL OR (
            length(foundational_enrollment_canonical_sha256) = 71
            AND substr(foundational_enrollment_canonical_sha256, 1, 7) = 'sha256:'
        )
    ),
    msg02_message_identity BLOB UNIQUE CHECK (
        msg02_message_identity IS NULL OR length(msg02_message_identity) = 32
    ),
    msg02_append_identity TEXT UNIQUE REFERENCES c2_signer_message_appends(append_identity) CHECK (
        msg02_append_identity IS NULL OR (
            length(msg02_append_identity) = 71
            AND substr(msg02_append_identity, 1, 7) = 'sha256:'
        )
    ),
    msg02_effect_receipt_identity TEXT UNIQUE CHECK (
        msg02_effect_receipt_identity IS NULL OR (
            length(msg02_effect_receipt_identity) = 71
            AND substr(msg02_effect_receipt_identity, 1, 7) = 'sha256:'
        )
    ),
    grant_identity BLOB CHECK (grant_identity IS NULL OR length(grant_identity) = 32),
    candidate_identity BLOB NOT NULL UNIQUE CHECK (length(candidate_identity) = 32),
    attempt_identity BLOB NOT NULL UNIQUE CHECK (length(attempt_identity) = 32),
    custody_evidence_identity BLOB NOT NULL CHECK (length(custody_evidence_identity) = 32),
    pre_generation_scope_identity BLOB NOT NULL CHECK (length(pre_generation_scope_identity) = 32),
    pre_effect_store_snapshot_identity TEXT NOT NULL CHECK (
        length(pre_effect_store_snapshot_identity) = 71
        AND substr(pre_effect_store_snapshot_identity, 1, 7) = 'sha256:'
    ),
    process_identity TEXT NOT NULL CHECK (
        length(process_identity) = 71 AND substr(process_identity, 1, 7) = 'sha256:'
    ),
    actor_instance_identity TEXT NOT NULL CHECK (
        length(actor_instance_identity) = 71 AND substr(actor_instance_identity, 1, 7) = 'sha256:'
    ),
    actor_effect_epoch INTEGER NOT NULL CHECK (
        actor_effect_epoch >= 0 AND actor_effect_epoch <= 9007199254740991
    ),
    enrollment_cut INTEGER NOT NULL CHECK (
        enrollment_cut > 0 AND enrollment_cut <= 9007199254740991
    ),
    effect_identity TEXT NOT NULL UNIQUE CHECK (
        length(effect_identity) = 71 AND substr(effect_identity, 1, 7) = 'sha256:'
    ),
    receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(receipt_identity) = 71 AND substr(receipt_identity, 1, 7) = 'sha256:'
    ),
    receipt_bytes BLOB NOT NULL CHECK (length(receipt_bytes) > 0),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0),
    CHECK (json_extract(CAST(adoption_canonical_bytes AS TEXT), '$.adoption_identity')
        = adoption_identity),
    CHECK (json_extract(CAST(adoption_canonical_bytes AS TEXT), '$.foundation_identity')
        = foundation_identity),
    CHECK (json_extract(CAST(adoption_canonical_bytes AS TEXT), '$.lineage') = lineage),
    CHECK (json_extract(CAST(adoption_canonical_bytes AS TEXT), '$.enrollment_cut')
        = enrollment_cut),
    CHECK (
        (lineage = 'initialExternal'
         AND foundational_enrollment_identity IS NOT NULL
         AND foundational_enrollment_canonical_bytes IS NOT NULL
         AND foundational_enrollment_canonical_sha256 IS NOT NULL
         AND msg02_message_identity IS NOT NULL
         AND msg02_append_identity IS NOT NULL
         AND msg02_effect_receipt_identity IS NOT NULL
         AND grant_identity IS NOT NULL
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.physical_generation_identity') = 'null'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.lifecycle_root_identity') = 'null'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.frontier_identity') = 'null'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.current_predecessor_identity') = 'null'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.transition_identity') = 'null')
        OR
        (lineage <> 'initialExternal'
         AND foundational_enrollment_identity IS NULL
         AND foundational_enrollment_canonical_bytes IS NULL
         AND foundational_enrollment_canonical_sha256 IS NULL
         AND msg02_message_identity IS NULL
         AND msg02_append_identity IS NULL
         AND msg02_effect_receipt_identity IS NULL
         AND grant_identity IS NULL
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.physical_generation_identity') = 'text'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.lifecycle_root_identity') = 'text'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.frontier_identity') = 'text'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.current_predecessor_identity') = 'text'
         AND json_type(CAST(adoption_canonical_bytes AS TEXT), '$.transition_identity') = 'text')
    )
) STRICT;

CREATE TRIGGER c2_foundational_enrollment_requires_exact_msg02_append
BEFORE INSERT ON c2_foundational_enrollment_adoptions
WHEN NEW.lineage = 'initialExternal' AND NOT EXISTS (
    SELECT 1
    FROM c2_signer_message_appends AS append
    WHERE append.append_identity = NEW.msg02_append_identity
      AND append.family = 'MSG-02'
      AND append.route = 'msg02_initial_pop'
      AND append.message_identity = NEW.msg02_message_identity
)
BEGIN
    SELECT RAISE(ABORT, 'foundational enrollment adoption requires its exact consumed MSG-02 append');
END;

-- Durable later-cut signer-lifecycle acceptance.  The foreign key preserves
-- the one-way dependency on prior Store adoption; no acceptance row can
-- synthesize foundational enrollment evidence.
CREATE TABLE c2_signer_enrollment_acceptances (
    acceptance_sequence INTEGER PRIMARY KEY CHECK (acceptance_sequence > 0),
    acceptance_effect_identity TEXT NOT NULL UNIQUE CHECK (
        length(acceptance_effect_identity) = 71
        AND substr(acceptance_effect_identity, 1, 7) = 'sha256:'
    ),
    signer_enrollment_identity TEXT NOT NULL UNIQUE CHECK (
        length(signer_enrollment_identity) = 71
        AND substr(signer_enrollment_identity, 1, 7) = 'sha256:'
    ),
    signer_enrollment_canonical_bytes BLOB NOT NULL CHECK (
        length(signer_enrollment_canonical_bytes) > 0
    ),
    signer_enrollment_canonical_sha256 TEXT NOT NULL CHECK (
        length(signer_enrollment_canonical_sha256) = 71
        AND substr(signer_enrollment_canonical_sha256, 1, 7) = 'sha256:'
    ),
    foundational_adoption_identity TEXT NOT NULL UNIQUE REFERENCES c2_foundational_enrollment_adoptions(adoption_identity),
    pre_effect_store_snapshot_identity TEXT NOT NULL CHECK (
        length(pre_effect_store_snapshot_identity) = 71
        AND substr(pre_effect_store_snapshot_identity, 1, 7) = 'sha256:'
    ),
    process_identity TEXT NOT NULL CHECK (
        length(process_identity) = 71 AND substr(process_identity, 1, 7) = 'sha256:'
    ),
    actor_instance_identity TEXT NOT NULL CHECK (
        length(actor_instance_identity) = 71 AND substr(actor_instance_identity, 1, 7) = 'sha256:'
    ),
    actor_effect_epoch INTEGER NOT NULL CHECK (
        actor_effect_epoch >= 0 AND actor_effect_epoch <= 9007199254740991
    ),
    accepted_cut INTEGER NOT NULL CHECK (
        accepted_cut > 0 AND accepted_cut <= 9007199254740991
    ),
    receipt_identity TEXT NOT NULL UNIQUE CHECK (
        length(receipt_identity) = 71 AND substr(receipt_identity, 1, 7) = 'sha256:'
    ),
    receipt_bytes BLOB NOT NULL CHECK (length(receipt_bytes) > 0),
    committed_at TEXT NOT NULL CHECK (length(committed_at) > 0)
) STRICT;

CREATE TRIGGER immutable_c2_signer_message_appends_update BEFORE UPDATE ON c2_signer_message_appends BEGIN SELECT RAISE(ABORT, 'append-only signer message ledger'); END;
CREATE TRIGGER immutable_c2_signer_message_appends_delete BEFORE DELETE ON c2_signer_message_appends BEGIN SELECT RAISE(ABORT, 'append-only signer message ledger'); END;
CREATE TRIGGER immutable_c2_external_carrier_ingress_update BEFORE UPDATE ON c2_external_carrier_ingress BEGIN SELECT RAISE(ABORT, 'append-only external carrier ingress'); END;
CREATE TRIGGER immutable_c2_external_carrier_ingress_delete BEFORE DELETE ON c2_external_carrier_ingress BEGIN SELECT RAISE(ABORT, 'append-only external carrier ingress'); END;
CREATE TRIGGER immutable_c2_foundational_enrollment_adoptions_update BEFORE UPDATE ON c2_foundational_enrollment_adoptions BEGIN SELECT RAISE(ABORT, 'append-only foundational enrollment adoption'); END;
CREATE TRIGGER immutable_c2_foundational_enrollment_adoptions_delete BEFORE DELETE ON c2_foundational_enrollment_adoptions BEGIN SELECT RAISE(ABORT, 'append-only foundational enrollment adoption'); END;
CREATE TRIGGER immutable_c2_signer_enrollment_acceptances_update BEFORE UPDATE ON c2_signer_enrollment_acceptances BEGIN SELECT RAISE(ABORT, 'append-only signer enrollment acceptance'); END;
CREATE TRIGGER immutable_c2_signer_enrollment_acceptances_delete BEFORE DELETE ON c2_signer_enrollment_acceptances BEGIN SELECT RAISE(ABORT, 'append-only signer enrollment acceptance'); END;
