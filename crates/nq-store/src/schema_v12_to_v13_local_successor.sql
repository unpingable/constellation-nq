CREATE TABLE local_successor_acquisition_intents (
    acquisition_id TEXT PRIMARY KEY,
    watcher_instance_id TEXT NOT NULL,
    watcher_semantic_digest TEXT NOT NULL CHECK (length(watcher_semantic_digest) = 71 AND substr(watcher_semantic_digest, 1, 7) = 'sha256:'),
    selection_digest TEXT NOT NULL CHECK (length(selection_digest) = 71 AND substr(selection_digest, 1, 7) = 'sha256:'),
    run_id TEXT NOT NULL UNIQUE,
    intake_id TEXT NOT NULL UNIQUE,
    intent_json BLOB NOT NULL CHECK (length(intent_json) <= 32768 AND json_valid(CAST(intent_json AS TEXT))),
    intent_digest TEXT NOT NULL CHECK (length(intent_digest) = 71 AND substr(intent_digest, 1, 7) = 'sha256:'),
    committed_at TEXT NOT NULL
) STRICT;
CREATE TABLE local_successor_acquisition_events (
    acquisition_id TEXT NOT NULL REFERENCES local_successor_acquisition_intents(acquisition_id),
    event_number INTEGER NOT NULL CHECK (event_number > 0),
    phase TEXT NOT NULL CHECK (phase IN ('provider_invocation_started', 'provider_intake_completed')),
    event_json BLOB NOT NULL CHECK (length(event_json) <= 32768 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (length(event_digest) = 71 AND substr(event_digest, 1, 7) = 'sha256:'),
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (acquisition_id, event_number), UNIQUE (acquisition_id, phase)
) STRICT;
CREATE TRIGGER local_successor_event_first BEFORE INSERT ON local_successor_acquisition_events WHEN NEW.event_number = 1 AND NEW.phase != 'provider_invocation_started' BEGIN SELECT RAISE(ABORT, 'local successor first event must fence provider invocation'); END;
CREATE TRIGGER local_successor_event_followup BEFORE INSERT ON local_successor_acquisition_events WHEN NEW.event_number > 1 AND (NEW.event_number != (SELECT COUNT(*) + 1 FROM local_successor_acquisition_events WHERE acquisition_id = NEW.acquisition_id) OR NEW.phase != 'provider_intake_completed') BEGIN SELECT RAISE(ABORT, 'local successor completion must immediately follow its fence'); END;
CREATE TRIGGER immutable_local_successor_acquisition_intents_update BEFORE UPDATE ON local_successor_acquisition_intents BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_successor_acquisition_intents_delete BEFORE DELETE ON local_successor_acquisition_intents BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_successor_acquisition_events_update BEFORE UPDATE ON local_successor_acquisition_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_local_successor_acquisition_events_delete BEFORE DELETE ON local_successor_acquisition_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
