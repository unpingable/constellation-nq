CREATE TABLE recurring_office_policies (
    policy_id TEXT PRIMARY KEY CHECK (length(policy_id) = 71 AND substr(policy_id, 1, 7) = 'sha256:'),
    schema_id TEXT NOT NULL CHECK (schema_id = 'nq.recurring_office_policy.v1'),
    policy_json BLOB NOT NULL CHECK (length(policy_json) <= 1048576 AND json_valid(CAST(policy_json AS TEXT))),
    policy_digest TEXT NOT NULL UNIQUE CHECK (policy_digest = policy_id),
    registered_at_unix_ms INTEGER NOT NULL CHECK (registered_at_unix_ms >= 0),
    operator_identity_json BLOB NOT NULL CHECK (length(operator_identity_json) <= 65536 AND json_valid(CAST(operator_identity_json AS TEXT)))
) STRICT;

CREATE TABLE recurring_office_policy_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 71 AND substr(event_id, 1, 7) = 'sha256:'),
    policy_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind = 'activated'),
    event_json BLOB NOT NULL CHECK (length(event_json) <= 65536 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (event_digest = event_id),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    operator_identity_json BLOB NOT NULL CHECK (length(operator_identity_json) <= 65536 AND json_valid(CAST(operator_identity_json AS TEXT))),
    FOREIGN KEY (policy_id) REFERENCES recurring_office_policies(policy_id)
) STRICT;

CREATE TABLE recurrence_enrollments (
    enrollment_id TEXT PRIMARY KEY CHECK (length(enrollment_id) = 71 AND substr(enrollment_id, 1, 7) = 'sha256:'),
    schema_id TEXT NOT NULL CHECK (schema_id = 'nq.recurrence_enrollment.v1'),
    policy_id TEXT NOT NULL,
    watcher_instance_id TEXT NOT NULL,
    watcher_semantic_digest TEXT NOT NULL CHECK (length(watcher_semantic_digest) = 71 AND substr(watcher_semantic_digest, 1, 7) = 'sha256:'),
    coordination_domain_id TEXT NOT NULL,
    anchor_unix_ms INTEGER NOT NULL CHECK (anchor_unix_ms >= 0),
    interval_ms INTEGER NOT NULL CHECK (interval_ms > 0),
    first_eligible_slot INTEGER NOT NULL CHECK (first_eligible_slot >= 0),
    max_acquisition_occurrences INTEGER NOT NULL CHECK (max_acquisition_occurrences > 0),
    expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > anchor_unix_ms),
    missed_slot_policy TEXT NOT NULL CHECK (missed_slot_policy IN ('skip', 'latest_only')),
    startup_policy TEXT NOT NULL CHECK (startup_policy IN ('wait_for_next_slot', 'evaluate_current_slot')),
    max_pre_provider_attempts INTEGER NOT NULL CHECK (max_pre_provider_attempts > 0),
    pre_provider_backoff_ms INTEGER NOT NULL CHECK (pre_provider_backoff_ms >= 0),
    failure_pause_threshold INTEGER NOT NULL CHECK (failure_pause_threshold > 0),
    requested_domain_concurrency INTEGER NOT NULL CHECK (requested_domain_concurrency = 1),
    enrollment_json BLOB NOT NULL CHECK (length(enrollment_json) <= 1048576 AND json_valid(CAST(enrollment_json AS TEXT))),
    enrollment_digest TEXT NOT NULL UNIQUE CHECK (enrollment_digest = enrollment_id),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    operator_identity_json BLOB NOT NULL CHECK (length(operator_identity_json) <= 65536 AND json_valid(CAST(operator_identity_json AS TEXT))),
    FOREIGN KEY (policy_id) REFERENCES recurring_office_policies(policy_id)
) STRICT;
CREATE INDEX recurrence_enrollments_by_watcher
    ON recurrence_enrollments(watcher_instance_id, created_at_unix_ms, enrollment_id);

CREATE TABLE recurrence_enrollment_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 71 AND substr(event_id, 1, 7) = 'sha256:'),
    enrollment_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN
        ('enrolled', 'paused_operator', 'resumed_operator', 'revoked_operator',
         'paused_failure_threshold', 'paused_outcome_unknown', 'exhausted', 'expired')),
    operation_id TEXT NOT NULL,
    event_json BLOB NOT NULL CHECK (length(event_json) <= 65536 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (event_digest = event_id),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    operator_identity_json BLOB NOT NULL CHECK (length(operator_identity_json) <= 65536 AND json_valid(CAST(operator_identity_json AS TEXT))),
    UNIQUE (enrollment_id, operation_id),
    FOREIGN KEY (enrollment_id) REFERENCES recurrence_enrollments(enrollment_id)
) STRICT;
CREATE INDEX recurrence_enrollment_events_by_enrollment
    ON recurrence_enrollment_events(enrollment_id, event_sequence);
CREATE UNIQUE INDEX recurrence_enrollment_creation_operation
    ON recurrence_enrollment_events(operation_id)
    WHERE event_kind = 'enrolled';

CREATE TABLE recurrence_slot_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 71 AND substr(event_id, 1, 7) = 'sha256:'),
    enrollment_id TEXT NOT NULL,
    slot_index INTEGER NOT NULL CHECK (slot_index >= 0),
    slot_id TEXT NOT NULL CHECK (length(slot_id) = 71 AND substr(slot_id, 1, 7) = 'sha256:'),
    scheduled_for_unix_ms INTEGER NOT NULL CHECK (scheduled_for_unix_ms >= 0),
    event_kind TEXT NOT NULL CHECK (event_kind IN
        ('skipped', 'coordination_deferred', 'acquisition_created', 'clock_rollback')),
    acquisition_id TEXT,
    event_json BLOB NOT NULL CHECK (length(event_json) <= 65536 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (event_digest = event_id),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    FOREIGN KEY (enrollment_id) REFERENCES recurrence_enrollments(enrollment_id)
) STRICT;
CREATE INDEX recurrence_slot_events_by_enrollment
    ON recurrence_slot_events(enrollment_id, slot_index, event_sequence);
CREATE UNIQUE INDEX recurrence_slot_events_terminal_slot_fact
    ON recurrence_slot_events(enrollment_id, slot_index, event_kind)
    WHERE event_kind IN ('skipped', 'acquisition_created', 'clock_rollback');

CREATE TABLE recurrence_acquisitions (
    acquisition_id TEXT PRIMARY KEY,
    schema_id TEXT NOT NULL CHECK (schema_id = 'nq.recurrence_acquisition_binding.v1'),
    enrollment_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    slot_id TEXT NOT NULL UNIQUE,
    slot_index INTEGER NOT NULL CHECK (slot_index >= 0),
    scheduled_for_unix_ms INTEGER NOT NULL CHECK (scheduled_for_unix_ms >= 0),
    watcher_instance_id TEXT NOT NULL,
    watcher_semantic_digest TEXT NOT NULL CHECK (length(watcher_semantic_digest) = 71 AND substr(watcher_semantic_digest, 1, 7) = 'sha256:'),
    coordination_domain_id TEXT NOT NULL,
    binding_json BLOB NOT NULL CHECK (length(binding_json) <= 1048576 AND json_valid(CAST(binding_json AS TEXT))),
    binding_digest TEXT NOT NULL UNIQUE CHECK (length(binding_digest) = 71 AND substr(binding_digest, 1, 7) = 'sha256:'),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    FOREIGN KEY (enrollment_id) REFERENCES recurrence_enrollments(enrollment_id),
    FOREIGN KEY (policy_id) REFERENCES recurring_office_policies(policy_id)
) STRICT;
CREATE INDEX recurrence_acquisitions_by_watcher
    ON recurrence_acquisitions(watcher_instance_id, slot_index, acquisition_id);

CREATE TABLE recurrence_acquisition_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 71 AND substr(event_id, 1, 7) = 'sha256:'),
    acquisition_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN
        ('created', 'pre_provider_failed', 'pre_provider_exhausted',
         'provider_invocation_started', 'provider_succeeded',
         'provider_terminal_failed', 'outcome_unknown')),
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 0),
    fencing_epoch INTEGER CHECK (fencing_epoch IS NULL OR fencing_epoch > 0),
    event_json BLOB NOT NULL CHECK (length(event_json) <= 1048576 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (event_digest = event_id),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    UNIQUE (acquisition_id, event_kind, attempt_number),
    FOREIGN KEY (acquisition_id) REFERENCES recurrence_acquisitions(acquisition_id)
) STRICT;
CREATE INDEX recurrence_acquisition_events_by_acquisition
    ON recurrence_acquisition_events(acquisition_id, event_sequence);

CREATE TABLE recurrence_coordination_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 71 AND substr(event_id, 1, 7) = 'sha256:'),
    coordination_domain_id TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch > 0),
    event_kind TEXT NOT NULL CHECK (event_kind IN ('claimed', 'released', 'fenced_outcome_unknown')),
    holder_acquisition_id TEXT NOT NULL,
    holder_watcher_instance_id TEXT NOT NULL,
    event_json BLOB NOT NULL CHECK (length(event_json) <= 65536 AND json_valid(CAST(event_json AS TEXT))),
    event_digest TEXT NOT NULL CHECK (event_digest = event_id),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    UNIQUE (coordination_domain_id, fencing_epoch, event_kind),
    FOREIGN KEY (holder_acquisition_id) REFERENCES recurrence_acquisitions(acquisition_id)
) STRICT;
CREATE INDEX recurrence_coordination_events_by_domain
    ON recurrence_coordination_events(coordination_domain_id, fencing_epoch, event_sequence);

CREATE TRIGGER immutable_recurring_office_policies_update BEFORE UPDATE ON recurring_office_policies BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurring_office_policies_delete BEFORE DELETE ON recurring_office_policies BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurring_office_policy_events_update BEFORE UPDATE ON recurring_office_policy_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurring_office_policy_events_delete BEFORE DELETE ON recurring_office_policy_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_enrollments_update BEFORE UPDATE ON recurrence_enrollments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_enrollments_delete BEFORE DELETE ON recurrence_enrollments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_enrollment_events_update BEFORE UPDATE ON recurrence_enrollment_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_enrollment_events_delete BEFORE DELETE ON recurrence_enrollment_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_slot_events_update BEFORE UPDATE ON recurrence_slot_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_slot_events_delete BEFORE DELETE ON recurrence_slot_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_acquisitions_update BEFORE UPDATE ON recurrence_acquisitions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_acquisitions_delete BEFORE DELETE ON recurrence_acquisitions BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_acquisition_events_update BEFORE UPDATE ON recurrence_acquisition_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_acquisition_events_delete BEFORE DELETE ON recurrence_acquisition_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_coordination_events_update BEFORE UPDATE ON recurrence_coordination_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER immutable_recurrence_coordination_events_delete BEFORE DELETE ON recurrence_coordination_events BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
