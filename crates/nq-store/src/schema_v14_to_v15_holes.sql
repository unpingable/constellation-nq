
-- Declared protected holes. Rows at or below a retention floor survive only as
-- whole protected collections (islands) or as compact source rows that a
-- retained finding, finding-evidence, or saved-check row still names. A
-- compact row keeps its identity columns and clears only its bodies; it never
-- verifies the expired source and is never paged as ordinary history.
ALTER TABLE evaluation_runs ADD COLUMN source_expired INTEGER NOT NULL DEFAULT 0 CHECK(source_expired IN (0,1));
-- The lowest admitted-report sequence an evaluation's envelope names (any JSON
-- text value equal to a report id), derived at insert. Expiry finds the
-- evaluations that name an aged report through it instead of scanning every
-- envelope above the floor.
ALTER TABLE evaluation_runs ADD COLUMN min_cited_report_sequence INTEGER;
ALTER TABLE admitted_reports ADD COLUMN source_expired INTEGER NOT NULL DEFAULT 0 CHECK(source_expired IN (0,1));
ALTER TABLE raw_submissions ADD COLUMN source_expired INTEGER NOT NULL DEFAULT 0 CHECK(source_expired IN (0,1));
DROP TRIGGER immutable_evaluation_runs_update;
UPDATE evaluation_runs SET min_cited_report_sequence=(SELECT MIN((SELECT a.report_sequence FROM admitted_reports a WHERE a.report_id=j.value)) FROM json_tree(CAST(evaluation_runs.detail_json AS TEXT)) j WHERE j.type='text');
CREATE TRIGGER immutable_evaluation_runs_update BEFORE UPDATE ON evaluation_runs WHEN NOT (COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0)=1 AND OLD.source_expired=0 AND NEW.source_expired=1 AND NEW.detail_json=CAST('{}' AS BLOB) AND NEW.evaluation_id IS OLD.evaluation_id AND NEW.evaluation_sequence IS OLD.evaluation_sequence AND NEW.detector_id IS OLD.detector_id AND NEW.detector_version IS OLD.detector_version AND NEW.detector_digest IS OLD.detector_digest AND NEW.evaluator_artifact_digest IS OLD.evaluator_artifact_digest AND NEW.trigger_run_id IS OLD.trigger_run_id AND NEW.profile_id IS OLD.profile_id AND NEW.profile_version IS OLD.profile_version AND NEW.profile_digest IS OLD.profile_digest AND NEW.profile_semantic_id IS OLD.profile_semantic_id AND NEW.evaluation_revision IS OLD.evaluation_revision AND NEW.started_at IS OLD.started_at AND NEW.evaluated_at IS OLD.evaluated_at AND NEW.outcome IS OLD.outcome AND NEW.min_cited_report_sequence IS OLD.min_cited_report_sequence) BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_admitted_reports_update;
CREATE TRIGGER immutable_admitted_reports_update BEFORE UPDATE ON admitted_reports WHEN NOT (COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0)=1 AND OLD.source_expired=0 AND NEW.source_expired=1 AND NEW.canonical_json=CAST('{}' AS BLOB) AND NEW.validated_report_json=CAST('{}' AS BLOB) AND NEW.next_checkpoint_json IS NULL AND NEW.report_sequence IS OLD.report_sequence AND NEW.report_id IS OLD.report_id AND NEW.submission_id IS OLD.submission_id AND NEW.instance_id IS OLD.instance_id AND NEW.profile_id IS OLD.profile_id AND NEW.profile_version IS OLD.profile_version AND NEW.profile_digest IS OLD.profile_digest AND NEW.observed_at IS OLD.observed_at AND NEW.received_at IS OLD.received_at AND NEW.report_status IS OLD.report_status AND NEW.semantic_digest IS OLD.semantic_digest AND NEW.judgment_schema_version IS OLD.judgment_schema_version AND NEW.judgment_digest IS OLD.judgment_digest AND NEW.admission_context_digest IS OLD.admission_context_digest AND NEW.admitted_at IS OLD.admitted_at) BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
DROP TRIGGER immutable_raw_submissions_update;
CREATE TRIGGER immutable_raw_submissions_update BEFORE UPDATE ON raw_submissions WHEN NOT (COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0)=1 AND OLD.source_expired=0 AND NEW.source_expired=1 AND length(NEW.raw_bytes)=0 AND NEW.submission_id IS OLD.submission_id AND NEW.run_id IS OLD.run_id AND NEW.raw_sha256 IS OLD.raw_sha256 AND NEW.received_at IS OLD.received_at AND NEW.protocol_outcome IS OLD.protocol_outcome AND NEW.admission_outcome IS OLD.admission_outcome AND NEW.rejection_code IS OLD.rejection_code) BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE INDEX evaluation_runs_full_by_sequence ON evaluation_runs(evaluation_sequence) WHERE source_expired=0;
CREATE INDEX evaluation_runs_by_min_cited_report ON evaluation_runs(min_cited_report_sequence) WHERE source_expired=0 AND min_cited_report_sequence IS NOT NULL;
CREATE INDEX admitted_reports_full_by_sequence ON admitted_reports(report_sequence) WHERE source_expired=0;
CREATE INDEX evaluation_watermarks_by_report ON evaluation_watermarks(instance_id, max_report_sequence);
CREATE INDEX finding_evidence_by_report ON finding_evidence(report_id);
CREATE INDEX finding_events_by_evaluation ON finding_events(evaluation_id);
-- Compaction rewrites rows by delete and re-insert (an in-place shrinking
-- update keeps the full row's page). A compact or retired row may be inserted
-- only inside an expiry transaction and only in its compact form.
CREATE TRIGGER compact_evaluation_runs_insert BEFORE INSERT ON evaluation_runs WHEN NEW.source_expired<>0 AND NOT (COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0)=1 AND NEW.detail_json=CAST('{}' AS BLOB)) BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER compact_admitted_reports_insert BEFORE INSERT ON admitted_reports WHEN NEW.source_expired<>0 AND NOT (COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0)=1 AND NEW.canonical_json=CAST('{}' AS BLOB) AND NEW.validated_report_json=CAST('{}' AS BLOB) AND NEW.next_checkpoint_json IS NULL) BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER compact_raw_submissions_insert BEFORE INSERT ON raw_submissions WHEN NEW.source_expired<>0 AND NOT (COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0)=1 AND length(NEW.raw_bytes)=0) BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
CREATE TRIGGER retired_provider_intake_attempts_insert BEFORE INSERT ON provider_intake_attempts WHEN NEW.history_expired<>0 AND NOT (COALESCE((SELECT delete_enabled FROM retention_state WHERE singleton=1),0)=1 AND NEW.retired_identity_digest IS NOT NULL AND length(NEW.raw_bytes)=0) BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
-- The public finding read model declares an expired source (`nq query`).
DROP VIEW public_finding_snapshot_v3;
CREATE VIEW public_finding_snapshot_v3 AS
SELECT
    f.finding_id,
    e.instance_id,
    e.detector_id,
    e.detector_version,
    e.detector_digest,
    e.evaluation_revision,
    evaluation.profile_id,
    evaluation.profile_version,
    evaluation.profile_digest,
    evaluation.profile_semantic_id,
    CAST(e.subject_json AS TEXT) AS subject_json,
    e.condition_name,
    e.condition_state,
    e.visibility_state,
    e.operator_work_state,
    e.severity,
    e.summary,
    CAST(e.limitations_json AS TEXT) AS limitations_json,
    CAST(e.safe_next_checks_json AS TEXT) AS safe_next_checks_json,
    CAST(e.freshness_json AS TEXT) AS freshness_json,
    CAST(e.basis_json AS TEXT) AS basis_json,
    CAST(e.refusal_json AS TEXT) AS refusal_json,
    e.origin_mode,
    CAST(e.historical_refs_json AS TEXT) AS historical_refs_json,
    e.observed_at,
    e.received_at,
    e.evaluated_at,
    e.evaluation_id,
    (
        SELECT CAST(refusal.detail_json AS TEXT)
        FROM refusals AS refusal
        WHERE refusal.evaluation_id = e.evaluation_id
    ) AS evaluation_refusal_json,
    COALESCE((
        SELECT json_group_array(json_object(
            'report_id', ordered.report_id,
            'semantic_digest', ordered.report_semantic_digest,
            'observation_ordinal', ordered.observation_ordinal,
            'observed_at', ordered.observed_at,
            'received_at', ordered.received_at
        ))
        FROM (
            SELECT report_id, report_semantic_digest, observation_ordinal, observed_at, received_at
            FROM finding_evidence
            WHERE event_id = e.event_id
            ORDER BY ordinal
        ) AS ordered
    ), '[]') AS evidence_json,
    -- 1 when the finding's evaluation or a cited report survives only as a
    -- compact source-expired record (the decision stands; its source expired).
    (evaluation.source_expired <> 0 OR EXISTS (
        SELECT 1 FROM finding_evidence AS cited
        JOIN admitted_reports AS cited_report
          ON cited_report.report_id = cited.report_id
         AND cited_report.semantic_digest = cited.report_semantic_digest
        WHERE cited.event_id = e.event_id AND cited_report.source_expired <> 0
    )) AS source_expired
FROM finding_current AS f
JOIN finding_events AS e ON e.event_id = f.latest_event_id
JOIN evaluation_runs AS evaluation ON evaluation.evaluation_id = e.evaluation_id;
