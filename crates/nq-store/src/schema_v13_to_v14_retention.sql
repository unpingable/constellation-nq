
-- Fixed operational retention boundary, not an event archive. Floors describe
-- deliberately unavailable complete prefixes; surviving evidence stays immutable.
CREATE TABLE retention_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
 generation INTEGER NOT NULL CHECK(generation >= 0),
 evaluation_floor INTEGER NOT NULL CHECK(evaluation_floor >= 0),
 report_floor INTEGER NOT NULL CHECK(report_floor >= 0),
 intake_floor INTEGER NOT NULL CHECK(intake_floor >= 0),
 status_floor INTEGER NOT NULL CHECK(status_floor >= 0),
 cutoff TEXT,
 lineage_floors_json BLOB NOT NULL CHECK(json_valid(CAST(lineage_floors_json AS TEXT))),
 capacity_json BLOB NOT NULL CHECK(json_valid(CAST(capacity_json AS TEXT))),
 delete_enabled INTEGER NOT NULL CHECK(delete_enabled IN (0,1))
) STRICT;
INSERT INTO retention_state VALUES(1,0,0,0,0,0,NULL,CAST('[]' AS BLOB),CAST('{}' AS BLOB),0);
CREATE TRIGGER retention_state_no_delete BEFORE DELETE ON retention_state BEGIN SELECT RAISE(ABORT,'retention boundary cannot be deleted'); END;
CREATE TRIGGER retention_state_monotonic BEFORE UPDATE ON retention_state WHEN NEW.generation < OLD.generation OR NEW.evaluation_floor < OLD.evaluation_floor OR NEW.report_floor < OLD.report_floor OR NEW.intake_floor < OLD.intake_floor OR NEW.status_floor < OLD.status_floor BEGIN SELECT RAISE(ABORT,'retention boundary cannot move backward'); END;
DROP TRIGGER immutable_watcher_runs_delete;
CREATE TRIGGER immutable_watcher_runs_delete BEFORE DELETE ON watcher_runs WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_provider_intake_attempts_delete;
CREATE TRIGGER immutable_provider_intake_attempts_delete BEFORE DELETE ON provider_intake_attempts WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_local_watcher_provider_intakes_delete;
CREATE TRIGGER immutable_local_watcher_provider_intakes_delete BEFORE DELETE ON local_watcher_provider_intakes WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_legacy_v3_watcher_run_intake_gaps_delete;
CREATE TRIGGER immutable_legacy_v3_watcher_run_intake_gaps_delete BEFORE DELETE ON legacy_v3_watcher_run_intake_gaps WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_raw_submissions_delete;
CREATE TRIGGER immutable_raw_submissions_delete BEFORE DELETE ON raw_submissions WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_admitted_reports_delete;
CREATE TRIGGER immutable_admitted_reports_delete BEFORE DELETE ON admitted_reports WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_observations_delete;
CREATE TRIGGER immutable_observations_delete BEFORE DELETE ON observations WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_report_coverage_delete;
CREATE TRIGGER immutable_report_coverage_delete BEFORE DELETE ON report_coverage WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_observation_coverage_delete;
CREATE TRIGGER immutable_observation_coverage_delete BEFORE DELETE ON observation_coverage WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_report_errors_delete;
CREATE TRIGGER immutable_report_errors_delete BEFORE DELETE ON report_errors WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_evaluation_runs_delete;
CREATE TRIGGER immutable_evaluation_runs_delete BEFORE DELETE ON evaluation_runs WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_evaluation_watermarks_delete;
CREATE TRIGGER immutable_evaluation_watermarks_delete BEFORE DELETE ON evaluation_watermarks WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_refusals_delete;
CREATE TRIGGER immutable_refusals_delete BEFORE DELETE ON refusals WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_status_events_delete;
CREATE TRIGGER immutable_status_events_delete BEFORE DELETE ON status_events WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_provider_intake_acknowledgments_delete;
CREATE TRIGGER immutable_provider_intake_acknowledgments_delete BEFORE DELETE ON provider_intake_acknowledgments WHEN COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0) != 1 BEGIN SELECT RAISE(ABORT, 'append-only table'); END;

ALTER TABLE provider_intake_attempts ADD COLUMN history_expired INTEGER NOT NULL DEFAULT 0 CHECK(history_expired IN (0,1));
ALTER TABLE provider_intake_attempts ADD COLUMN retired_identity_digest TEXT CHECK(retired_identity_digest IS NULL OR (length(retired_identity_digest)=71 AND substr(retired_identity_digest,1,7)='sha256:'));
DROP TRIGGER immutable_provider_intake_attempts_update;
CREATE TRIGGER immutable_provider_intake_attempts_update BEFORE UPDATE ON provider_intake_attempts WHEN NOT (COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0)=1 AND OLD.history_expired=0 AND NEW.history_expired=1 AND NEW.intake_sequence IS OLD.intake_sequence AND NEW.intake_id IS OLD.intake_id AND NEW.schema_id IS OLD.schema_id AND NEW.idempotency_key IS OLD.idempotency_key AND NEW.attempt_id IS OLD.attempt_id AND NEW.request_id IS OLD.request_id AND NEW.provider_admission_id IS OLD.provider_admission_id AND NEW.source_admission_id IS OLD.source_admission_id AND NEW.provider_sequence IS OLD.provider_sequence AND NEW.origin_carrier IS OLD.origin_carrier AND NEW.deadline_at IS OLD.deadline_at AND NEW.checkpoint_contract_digest IS OLD.checkpoint_contract_digest AND NEW.execution_identity_digest IS OLD.execution_identity_digest AND NEW.admission_context_digest IS OLD.admission_context_digest AND NEW.provider_semantic_id IS OLD.provider_semantic_id AND NEW.provider_artifact_digest IS OLD.provider_artifact_digest AND NEW.provider_protocol_identity IS OLD.provider_protocol_identity AND NEW.provider_config_digest IS OLD.provider_config_digest AND NEW.binding_digest IS OLD.binding_digest AND NEW.instance_id IS OLD.instance_id AND NEW.profile_id IS OLD.profile_id AND NEW.profile_version IS OLD.profile_version AND NEW.profile_digest IS OLD.profile_digest AND NEW.profile_semantic_id IS OLD.profile_semantic_id AND NEW.evaluator_artifact_digest IS OLD.evaluator_artifact_digest AND NEW.context_digest IS OLD.context_digest AND NEW.interpretation_kind IS OLD.interpretation_kind AND NEW.interpretation_digest IS OLD.interpretation_digest AND NEW.native_outcome_kind IS OLD.native_outcome_kind AND NEW.native_outcome_digest IS OLD.native_outcome_digest AND NEW.raw_sha256 IS OLD.raw_sha256 AND NEW.started_at IS OLD.started_at AND NEW.finished_at IS OLD.finished_at AND NEW.received_at IS OLD.received_at AND NEW.replay_digest IS OLD.replay_digest AND NEW.intake_digest IS OLD.intake_digest) BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
ALTER TABLE provider_intake_attempts ADD COLUMN retired_run_id TEXT;
ALTER TABLE provider_intake_attempts ADD COLUMN retired_submission_id TEXT;
ALTER TABLE provider_intake_attempts ADD COLUMN retired_report_id TEXT;
ALTER TABLE provider_intake_attempts ADD COLUMN retired_report_semantic_digest TEXT;
CREATE UNIQUE INDEX provider_intake_attempts_by_retired_run_id ON provider_intake_attempts(retired_run_id) WHERE retired_run_id IS NOT NULL;
CREATE UNIQUE INDEX provider_intake_attempts_by_retired_submission_id ON provider_intake_attempts(retired_submission_id) WHERE retired_submission_id IS NOT NULL;
CREATE UNIQUE INDEX provider_intake_attempts_by_retired_report_id ON provider_intake_attempts(retired_report_id) WHERE retired_report_id IS NOT NULL;
