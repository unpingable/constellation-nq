CREATE TABLE provider_activity_evidence (
    evidence_id TEXT PRIMARY KEY CHECK (length(evidence_id) = 71 AND substr(evidence_id, 1, 7) = 'sha256:'),
    schema_id TEXT NOT NULL CHECK (schema_id = 'nq.provider_activity_evidence.v1'),
    acquisition_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    coordination_domain_id TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch > 0),
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    claim TEXT NOT NULL CHECK (claim IN ('provider_not_invoked', 'provider_quiescent')),
    producer_schema TEXT NOT NULL CHECK (producer_schema = 'nq.local_stdio_process_group_supervision.v1'),
    evidence_json BLOB NOT NULL CHECK (length(evidence_json) <= 1048576 AND json_valid(CAST(evidence_json AS TEXT))),
    evidence_digest TEXT NOT NULL UNIQUE CHECK (evidence_digest = evidence_id),
    observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms >= 0),
    UNIQUE (acquisition_id, fencing_epoch, attempt_number, claim, producer_schema),
    FOREIGN KEY (acquisition_id) REFERENCES recurrence_acquisitions(acquisition_id),
    FOREIGN KEY (enrollment_id) REFERENCES recurrence_enrollments(enrollment_id)
) STRICT;
CREATE INDEX provider_activity_evidence_by_acquisition
    ON provider_activity_evidence(acquisition_id, observed_at_unix_ms, evidence_id);

CREATE TABLE provider_activity_reconciliation_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 71 AND substr(event_id, 1, 7) = 'sha256:'),
    acquisition_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    coordination_domain_id TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch > 0),
    disposition TEXT NOT NULL CHECK (disposition IN ('provider_not_invoked', 'outcome_unknown_provider_quiescent')),
    event_json BLOB NOT NULL CHECK (length(event_json) <= 1048576 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (event_digest = event_id),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    UNIQUE (acquisition_id, evidence_id),
    UNIQUE (acquisition_id, fencing_epoch),
    FOREIGN KEY (acquisition_id) REFERENCES recurrence_acquisitions(acquisition_id),
    FOREIGN KEY (evidence_id) REFERENCES provider_activity_evidence(evidence_id),
    FOREIGN KEY (enrollment_id) REFERENCES recurrence_enrollments(enrollment_id)
) STRICT;
CREATE INDEX provider_activity_reconciliation_by_domain
    ON provider_activity_reconciliation_events(coordination_domain_id, fencing_epoch, event_sequence);

CREATE TRIGGER immutable_provider_activity_evidence_update BEFORE UPDATE ON provider_activity_evidence BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_activity_evidence_delete BEFORE DELETE ON provider_activity_evidence BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_activity_reconciliation_events_update BEFORE UPDATE ON provider_activity_reconciliation_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_provider_activity_reconciliation_events_delete BEFORE DELETE ON provider_activity_reconciliation_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
