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
        binding_mode IN ('initial', 'normal_successor', 'recovery_successor')
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
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (binding_mode = 'normal_successor'
            AND current_key_generation > 0
            AND transition_identity IS NOT NULL
            AND predecessor_binding_identity IS NOT NULL
            AND continuity_authorization_identity IS NOT NULL
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (binding_mode = 'recovery_successor'
            AND current_key_generation > 0
            AND transition_identity IS NOT NULL
            AND predecessor_binding_identity IS NOT NULL
            AND continuity_authorization_identity IS NULL
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
    succession_mode TEXT NOT NULL CHECK (succession_mode IN ('normal', 'recovery')),
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
            AND recovery_condition_identity IS NULL
            AND recovery_authority_identity IS NULL
            AND recovery_grant_identity IS NULL)
        OR
        (succession_mode = 'recovery'
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
    succession_mode TEXT NOT NULL CHECK (succession_mode IN ('normal', 'recovery')),
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
