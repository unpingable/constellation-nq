CREATE TABLE continuity_acquisition_intents (
    intent_id TEXT PRIMARY KEY CHECK (length(intent_id) = 71 AND substr(intent_id, 1, 7) = 'sha256:'),
    schema_id TEXT NOT NULL CHECK (schema_id = 'nq.provider_acquisition_intent.v1'),
    acquisition_id TEXT NOT NULL UNIQUE,
    intake_id TEXT NOT NULL UNIQUE,
    authority_occurrence_ref TEXT NOT NULL,
    authority_digest TEXT NOT NULL CHECK (length(authority_digest) = 71 AND substr(authority_digest, 1, 7) = 'sha256:'),
    commitment_occurrence_ref TEXT NOT NULL,
    commitment_digest TEXT NOT NULL CHECK (length(commitment_digest) = 71 AND substr(commitment_digest, 1, 7) = 'sha256:'),
    acquisition_basis_digest TEXT NOT NULL CHECK (length(acquisition_basis_digest) = 71 AND substr(acquisition_basis_digest, 1, 7) = 'sha256:'),
    intent_json BLOB NOT NULL CHECK (length(intent_json) <= 1048576 AND json_valid(CAST(intent_json AS TEXT))),
    intent_digest TEXT NOT NULL UNIQUE CHECK (length(intent_digest) = 71 AND substr(intent_digest, 1, 7) = 'sha256:'),
    committed_at TEXT NOT NULL
) STRICT;

CREATE TABLE continuity_acquisition_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 71 AND substr(event_id, 1, 7) = 'sha256:'),
    intent_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('provider_invocation_started', 'provider_intake_completed')),
    event_json BLOB NOT NULL CHECK (length(event_json) <= 1048576 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (length(event_digest) = 71 AND substr(event_digest, 1, 7) = 'sha256:'),
    occurred_at TEXT NOT NULL,
    UNIQUE (intent_id, phase),
    CHECK (event_id = event_digest),
    FOREIGN KEY (intent_id) REFERENCES continuity_acquisition_intents(intent_id)
) STRICT;
CREATE INDEX continuity_acquisition_events_by_intent
    ON continuity_acquisition_events(intent_id, event_sequence);

CREATE TRIGGER immutable_continuity_intents_update BEFORE UPDATE ON continuity_acquisition_intents BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_continuity_intents_delete BEFORE DELETE ON continuity_acquisition_intents BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_continuity_events_update BEFORE UPDATE ON continuity_acquisition_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_continuity_events_delete BEFORE DELETE ON continuity_acquisition_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
