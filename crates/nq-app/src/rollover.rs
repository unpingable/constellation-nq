//! Read-only eligibility scan for an operator-controlled archive rollover.
//!
//! The scan is deliberately snapshot-scoped. It opens one operator-selected
//! immutable database, reports exact identity lineage needed by a later
//! operator procedure, and refuses unresolved local work. The archive's own
//! embedded binary separately owns seal verification; this successor scanner
//! must not claim it reverified a differently versioned archive. The scan does
//! not establish process quiescence, initialize or activate another store, or
//! delete anything.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use nq_protocol::Sha256Digest;
use nq_store::{CanonicalDocument, Store};
use serde::Serialize;
use serde_json::Value;

use crate::saved_check::{MaintenanceDeclaration, SavedCheckDefinition};

const PAGE: u32 = nq_store::MAX_PUBLIC_QUERY_ROWS;

#[derive(Debug, Serialize)]
pub(crate) struct RolloverInspection {
    schema: &'static str,
    inspected_at: String,
    eligible: bool,
    grants_authority: bool,
    snapshot: SnapshotScope,
    definitions: Vec<DefinitionTransfer>,
    evaluations: Vec<EvaluationIdentity>,
    notifications: Vec<NotificationIdentity>,
    legacy_notifications: Vec<LegacyNotificationIdentity>,
    maintenance_history: Vec<MaintenanceIdentity>,
    current_maintenance: Vec<MaintenanceTransfer>,
    local_successor_acquisitions: Vec<LocalSuccessorAcquisitionIdentity>,
    refusals: Vec<RolloverRefusal>,
    limitations: [&'static str; 4],
}

impl RolloverInspection {
    /// Narrow eligibility predicate for a command that has already verified the
    /// containing archive with its own verifier.  It exposes no transfer data.
    pub(crate) fn permits_maintenance_carry(
        &self,
        maintenance_id: &str,
        declaration_digest: &str,
        declared_at: &str,
    ) -> bool {
        self.eligible
            && self.refusals.is_empty()
            && self.current_maintenance.iter().any(|current| {
                current.prior_maintenance_id == maintenance_id
                    && current.prior_declaration_digest == declaration_digest
                    && current.prior_declared_at == declared_at
            })
    }
}

#[derive(Debug, Serialize)]
struct SnapshotScope {
    source: &'static str,
    opened_immutable: bool,
    archive_verification_claimed: bool,
}

#[derive(Debug, Serialize)]
struct DefinitionTransfer {
    definition_id: String,
    reference: String,
    definition_digest: String,
    installed_at: String,
    definition: Value,
}

#[derive(Debug, Serialize)]
struct EvaluationIdentity {
    definition_id: String,
    evaluation_id: String,
    claim_event_number: u32,
    claim_occurred_at: String,
    terminal_event_number: Option<u32>,
    terminal_occurred_at: Option<String>,
    outcome: &'static str,
}

#[derive(Debug, Serialize)]
struct NotificationIdentity {
    notification_id: String,
    stable_event_id: String,
    attention_kind: String,
    attention_receipt_digest: Option<String>,
    attention_policy_id: String,
    attention_policy_digest: String,
    transition_id: String,
    route_reference: String,
    destination_identity: String,
    content_digest: String,
    created_at: String,
    event_count: usize,
    delivery_state: &'static str,
    events: Vec<NotificationEventIdentity>,
}

#[derive(Debug, Serialize)]
struct NotificationEventIdentity {
    event_number: u32,
    occurred_at: String,
    outcome: String,
}

#[derive(Debug, Serialize)]
struct LegacyNotificationIdentity {
    notification_id: String,
    max_attempts: u32,
    attempt_count: u32,
    state: &'static str,
}

#[derive(Debug, Serialize)]
struct MaintenanceIdentity {
    maintenance_id: String,
    declaration_digest: String,
    declared_at: String,
    start_at: String,
    end_at: String,
}

#[derive(Debug, Serialize)]
struct MaintenanceTransfer {
    prior_maintenance_id: String,
    prior_declaration_digest: String,
    prior_declared_at: String,
    declaration: Value,
}

#[derive(Debug, Serialize)]
struct LocalSuccessorAcquisitionIdentity {
    acquisition_id: String,
    watcher_instance_id: String,
    watcher_semantic_digest: String,
    selection_digest: String,
    run_id: String,
    intake_id: String,
    phases: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RolloverRefusal {
    kind: &'static str,
    identity: String,
    state: String,
}

#[derive(Debug)]
struct ClaimState {
    definition_id: String,
    claim_event_number: u32,
    claim_occurred_at: String,
    terminal_event_number: Option<u32>,
    terminal_occurred_at: Option<String>,
    outcome: &'static str,
    binding: Value,
}

/// Inspect one operator-selected immutable archive database snapshot.
///
/// The operator procedure must separately verify the containing archive with
/// its exact embedded binary and bind that verification to this pathname and a
/// stable before/after inventory.
pub(crate) fn inspect_rollover(
    database_path: &Path,
    inspected_at: &str,
) -> Result<RolloverInspection> {
    let inspected = DateTime::parse_from_rfc3339(inspected_at)
        .context("inspected_at must be an explicit RFC3339 timestamp")?
        .with_timezone(&Utc);
    let store = Store::open_immutable(database_path)
        .context("open operator-selected rollover snapshot immutable")?;
    let mut report = inspect_store(&store, inspected, inspected_at.to_owned())?;
    report.snapshot = SnapshotScope {
        source: "operator_selected_immutable_database",
        opened_immutable: true,
        archive_verification_claimed: false,
    };
    Ok(report)
}

fn inspect_store(
    store: &Store,
    inspected: DateTime<Utc>,
    inspected_at: String,
) -> Result<RolloverInspection> {
    let (definitions, evaluations, mut refusals) = scan_saved_checks(store)?;
    let (notifications, notification_refusals) = scan_notifications(store)?;
    refusals.extend(notification_refusals);
    let (legacy_notifications, legacy_refusals) = scan_legacy_notifications(store)?;
    refusals.extend(legacy_refusals);
    let (maintenance_history, current_maintenance) = scan_maintenance(store, inspected)?;
    let (local_successor_acquisitions, acquisition_refusals) =
        scan_local_successor_acquisitions(store)?;
    refusals.extend(acquisition_refusals);

    Ok(RolloverInspection {
        schema: "nq.rollover-inspection/v1",
        inspected_at,
        eligible: refusals.is_empty(),
        grants_authority: false,
        snapshot: SnapshotScope {
            source: "local_test_fixture",
            opened_immutable: false,
            archive_verification_claimed: false,
        },
        definitions,
        evaluations,
        notifications,
        legacy_notifications,
        maintenance_history,
        current_maintenance,
        local_successor_acquisitions,
        refusals,
        limitations: [
            "Inspection does not prove that source writers or schedules are stopped",
            "Inspection grants no activation, notification, evaluation, or deletion authority",
            "Historical reads remain explicit archive reads; no cross-store lookup is provided",
            "Archive integrity does not make its containing filesystem immutable",
        ],
    })
}

fn scan_saved_checks(
    store: &Store,
) -> Result<(
    Vec<DefinitionTransfer>,
    Vec<EvaluationIdentity>,
    Vec<RolloverRefusal>,
)> {
    let mut definitions = Vec::new();
    let mut claims: BTreeMap<String, ClaimState> = BTreeMap::new();
    let mut after = None;
    loop {
        let page = store.saved_check_definitions_bounded(PAGE, after.as_deref())?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for record in page {
            after = Some(record.definition_id.clone());
            let document = canonical(&record.definition_json, "saved-check definition")?;
            require_digest(
                &record.definition_digest,
                &document,
                "saved-check definition",
            )?;
            let definition: SavedCheckDefinition = serde_json::from_slice(document.as_bytes())
                .context("saved-check definition is not typed material")?;
            definition.validate()?;
            if definition.reference != record.stable_reference {
                bail!("saved-check stable reference differs from typed definition");
            }
            parse_time(&record.installed_at, "saved-check installed_at")?;
            scan_saved_check_events(store, &record.definition_id, &mut claims)?;
            definitions.push(DefinitionTransfer {
                definition_id: record.definition_id,
                reference: record.stable_reference,
                definition_digest: record.definition_digest,
                installed_at: record.installed_at,
                definition: serde_json::from_slice(document.as_bytes())?,
            });
        }
        if page_len < PAGE as usize {
            break;
        }
    }
    let mut evaluations = Vec::with_capacity(claims.len());
    let mut refusals = Vec::new();
    for (evaluation_id, state) in claims {
        if state.terminal_event_number.is_none() {
            refusals.push(RolloverRefusal {
                kind: "saved_check",
                identity: evaluation_id.clone(),
                state: "claimed".into(),
            });
        }
        evaluations.push(EvaluationIdentity {
            definition_id: state.definition_id,
            evaluation_id,
            claim_event_number: state.claim_event_number,
            claim_occurred_at: state.claim_occurred_at,
            terminal_event_number: state.terminal_event_number,
            terminal_occurred_at: state.terminal_occurred_at,
            outcome: state.outcome,
        });
    }
    Ok((definitions, evaluations, refusals))
}

fn scan_saved_check_events(
    store: &Store,
    definition_id: &str,
    claims: &mut BTreeMap<String, ClaimState>,
) -> Result<()> {
    let mut after = None;
    let mut expected = 1;
    loop {
        let page = store.saved_check_events_bounded(definition_id, PAGE, after)?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for event in page {
            if event.event_number != expected {
                bail!("saved-check event sequence is incomplete");
            }
            expected = expected
                .checked_add(1)
                .context("saved-check sequence overflow")?;
            parse_time(&event.occurred_at, "saved-check event time")?;
            let detail = canonical(&event.detail_json, "saved-check event detail")?;
            let detail: Value = serde_json::from_slice(detail.as_bytes())?;
            match event.outcome.as_str() {
                "installed" if event.event_number == 1 && event.evaluation_id.is_none() => {}
                "claimed" => {
                    let evaluation_id = event
                        .evaluation_id
                        .filter(|id| !id.is_empty())
                        .context("saved-check claim lacks evaluation ID")?;
                    let binding = detail
                        .get("binding")
                        .filter(|value| value.as_object().is_some_and(|map| !map.is_empty()))
                        .context("saved-check claim lacks a nonempty binding")?
                        .clone();
                    if claims
                        .insert(
                            evaluation_id,
                            ClaimState {
                                definition_id: definition_id.to_owned(),
                                claim_event_number: event.event_number,
                                claim_occurred_at: event.occurred_at,
                                terminal_event_number: None,
                                terminal_occurred_at: None,
                                outcome: "claimed",
                                binding,
                            },
                        )
                        .is_some()
                    {
                        bail!("saved-check evaluation has multiple claims");
                    }
                }
                outcome @ ("passed" | "failed" | "refused") => {
                    let evaluation_id = event
                        .evaluation_id
                        .filter(|id| !id.is_empty())
                        .context("saved-check terminal event lacks evaluation ID")?;
                    let claim = claims
                        .get_mut(&evaluation_id)
                        .context("saved-check terminal event lacks an exact claim")?;
                    if claim.definition_id != definition_id || claim.terminal_event_number.is_some()
                    {
                        bail!("saved-check terminal event contradicts its claim");
                    }
                    if detail.get("binding") != Some(&claim.binding) {
                        bail!("saved-check terminal binding differs from its exact claim");
                    }
                    claim.terminal_event_number = Some(event.event_number);
                    claim.terminal_occurred_at = Some(event.occurred_at);
                    claim.outcome = match outcome {
                        "passed" => "passed",
                        "failed" => "failed",
                        "refused" => "refused",
                        _ => unreachable!(),
                    };
                }
                _ => bail!("saved-check event has unknown state"),
            }
            after = Some(event.event_number);
        }
        if page_len < PAGE as usize {
            break;
        }
    }
    if expected == 1 {
        bail!("saved-check definition has no installation event");
    }
    Ok(())
}

fn scan_notifications(store: &Store) -> Result<(Vec<NotificationIdentity>, Vec<RolloverRefusal>)> {
    let mut notifications = Vec::new();
    let mut refusals = Vec::new();
    let mut after = None;
    loop {
        let page = store.notification_delivery_intents_bounded(PAGE, after.as_deref())?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for intent in page {
            after = Some(intent.notification_id.clone());
            parse_time(&intent.created_at, "notification created_at")?;
            let intent_document = canonical(&intent.intent_json, "notification intent")?;
            let typed = crate::notification::reopen_retained_intent(&intent_document)?;
            if typed.stable_event_id != intent.stable_event_id
                || typed.attention_kind != intent.attention_kind
                || typed.attention_receipt_digest != intent.attention_receipt_digest
                || typed.attention_policy_id != intent.attention_policy_id
                || typed.attention_policy_digest != intent.attention_policy_digest
                || typed.transition_id != intent.transition_id
                || typed.route_reference != intent.route_reference
                || typed.destination_identity != intent.destination_identity
            {
                bail!("notification columns differ from retained typed intent");
            }
            let payload = canonical(&intent.payload_json, "notification payload")?;
            require_digest(&intent.content_digest, &payload, "notification content")?;
            Sha256Digest::parse(intent.attention_policy_digest.clone())
                .context("notification attention policy digest is invalid")?;
            if let Some(digest) = &intent.attention_receipt_digest {
                Sha256Digest::parse(digest.clone())
                    .context("notification attention receipt digest is invalid")?;
            }
            let events = all_notification_events(store, &intent.notification_id)?;
            let state = notification_state(&events)?;
            if matches!(state, "pending" | "unknown") {
                refusals.push(RolloverRefusal {
                    kind: "notification",
                    identity: intent.notification_id.clone(),
                    state: state.into(),
                });
            }
            notifications.push(NotificationIdentity {
                notification_id: intent.notification_id,
                stable_event_id: intent.stable_event_id,
                attention_kind: intent.attention_kind,
                attention_receipt_digest: intent.attention_receipt_digest,
                attention_policy_id: intent.attention_policy_id,
                attention_policy_digest: intent.attention_policy_digest,
                transition_id: intent.transition_id,
                route_reference: intent.route_reference,
                destination_identity: intent.destination_identity,
                content_digest: intent.content_digest,
                created_at: intent.created_at,
                event_count: events.len(),
                delivery_state: state,
                events: events
                    .into_iter()
                    .map(|event| NotificationEventIdentity {
                        event_number: event.event_number,
                        occurred_at: event.occurred_at,
                        outcome: event.outcome,
                    })
                    .collect(),
            });
        }
        if page_len < PAGE as usize {
            break;
        }
    }
    Ok((notifications, refusals))
}

fn scan_legacy_notifications(
    store: &Store,
) -> Result<(Vec<LegacyNotificationIdentity>, Vec<RolloverRefusal>)> {
    let mut identities = Vec::new();
    let mut refusals = Vec::new();
    let mut after = None;
    loop {
        let page = store.legacy_notification_attempt_statuses_bounded(PAGE, after.as_deref())?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for row in page {
            after = Some(row.notification_id.clone());
            let state = legacy_notification_state(
                row.max_attempts,
                row.attempt_count,
                row.last_outcome.as_deref(),
            )?;
            if state == "pending" {
                refusals.push(RolloverRefusal {
                    kind: "legacy_notification",
                    identity: row.notification_id.clone(),
                    state: state.into(),
                });
            }
            identities.push(LegacyNotificationIdentity {
                notification_id: row.notification_id,
                max_attempts: row.max_attempts,
                attempt_count: row.attempt_count,
                state,
            });
        }
        if page_len < PAGE as usize {
            break;
        }
    }
    Ok((identities, refusals))
}

fn legacy_notification_state(
    max_attempts: u32,
    attempt_count: u32,
    last_outcome: Option<&str>,
) -> Result<&'static str> {
    if max_attempts == 0 || attempt_count > max_attempts {
        bail!("legacy notification attempt bounds are inconsistent");
    }
    match (attempt_count, last_outcome) {
        (0, None) => Ok("pending"),
        (0, Some(_)) | (_, None) => bail!("legacy notification attempt state is incomplete"),
        (_, Some("delivered")) => Ok("delivered"),
        (attempts, Some("failed")) if attempts == max_attempts => Ok("failed"),
        (_, Some("failed" | "retryable")) => Ok("pending"),
        (_, Some(_)) => bail!("legacy notification attempt outcome is unknown"),
    }
}

fn all_notification_events(
    store: &Store,
    notification_id: &str,
) -> Result<Vec<nq_store::NotificationDeliveryHistoryEventRecord>> {
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let page = store.notification_delivery_events_bounded(notification_id, PAGE, after)?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for event in &page {
            parse_time(&event.occurred_at, "notification event time")?;
            canonical(&event.detail_json, "notification event detail")?;
            after = Some(event.event_number);
        }
        all.extend(page);
        if page_len < PAGE as usize {
            break;
        }
    }
    Ok(all)
}

fn notification_state(
    events: &[nq_store::NotificationDeliveryHistoryEventRecord],
) -> Result<&'static str> {
    match events {
        [] => Ok("pending"),
        [claim] if claim.event_number == 1 && claim.outcome == "claimed" => Ok("unknown"),
        [terminal] if terminal.event_number == 1 && terminal.outcome == "refused" => Ok("refused"),
        [claim, terminal]
            if claim.event_number == 1
                && claim.outcome == "claimed"
                && terminal.event_number == 2
                && matches!(terminal.outcome.as_str(), "accepted" | "failed" | "unknown") =>
        {
            Ok(match terminal.outcome.as_str() {
                "accepted" => "accepted",
                "failed" => "failed",
                "unknown" => "unknown",
                _ => unreachable!(),
            })
        }
        _ => bail!("notification has an unknown or contradictory event sequence"),
    }
}

fn scan_maintenance(
    store: &Store,
    inspected: DateTime<Utc>,
) -> Result<(Vec<MaintenanceIdentity>, Vec<MaintenanceTransfer>)> {
    let mut history = Vec::new();
    let mut current = Vec::new();
    let mut after: Option<(String, String)> = None;
    loop {
        let page = store.maintenance_declarations_bounded(
            PAGE,
            after.as_ref().map(|(time, _)| time.as_str()),
            after.as_ref().map(|(_, id)| id.as_str()),
        )?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for record in page {
            let document = canonical(&record.declaration_json, "maintenance declaration")?;
            require_digest(
                &record.declaration_digest,
                &document,
                "maintenance declaration",
            )?;
            let declaration: MaintenanceDeclaration =
                serde_json::from_slice(document.as_bytes())
                    .context("maintenance declaration is not typed material")?;
            declaration.validate()?;
            if declaration.maintenance_id != record.maintenance_id {
                bail!("maintenance ID differs from typed declaration");
            }
            let declared_at = parse_time(&record.declared_at, "maintenance declared_at")?;
            let start = parse_time(&declaration.start_at, "maintenance start_at")?;
            let end = parse_time(&declaration.end_at, "maintenance end_at")?;
            history.push(MaintenanceIdentity {
                maintenance_id: record.maintenance_id.clone(),
                declaration_digest: record.declaration_digest.clone(),
                declared_at: record.declared_at.clone(),
                start_at: declaration.start_at.clone(),
                end_at: declaration.end_at.clone(),
            });
            if declared_at <= inspected && start <= inspected && inspected < end {
                current.push(MaintenanceTransfer {
                    prior_maintenance_id: record.maintenance_id.clone(),
                    prior_declaration_digest: record.declaration_digest.clone(),
                    prior_declared_at: record.declared_at.clone(),
                    declaration: serde_json::from_slice(document.as_bytes())?,
                });
            }
            after = Some((record.declared_at, record.maintenance_id));
        }
        if page_len < PAGE as usize {
            break;
        }
    }
    Ok((history, current))
}

fn scan_local_successor_acquisitions(
    store: &Store,
) -> Result<(Vec<LocalSuccessorAcquisitionIdentity>, Vec<RolloverRefusal>)> {
    let mut identities = Vec::new();
    let mut refusals = Vec::new();
    let mut after = None;
    loop {
        let page = store.local_successor_acquisitions_bounded(PAGE, after.as_deref())?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for row in page {
            after = Some(row.acquisition_id.clone());
            validate_local_successor_intent(&row)?;
            let phases = store.local_successor_acquisition_phases(&row.acquisition_id)?;
            if !local_successor_phases_are_terminal(&phases) {
                refusals.push(RolloverRefusal {
                    kind: "local_successor_acquisition",
                    identity: row.acquisition_id.clone(),
                    state: "pending_or_unknown".into(),
                });
            }
            identities.push(LocalSuccessorAcquisitionIdentity {
                acquisition_id: row.acquisition_id,
                watcher_instance_id: row.watcher_instance_id,
                watcher_semantic_digest: row.watcher_semantic_digest,
                selection_digest: row.selection_digest,
                run_id: row.run_id,
                intake_id: row.intake_id,
                phases,
            });
        }
        if page_len < PAGE as usize {
            break;
        }
    }
    Ok((identities, refusals))
}

fn validate_local_successor_intent(
    row: &nq_store::LocalSuccessorAcquisitionIntentRow,
) -> Result<()> {
    Sha256Digest::parse(row.watcher_semantic_digest.clone())
        .context("local-successor watcher semantic digest is invalid")?;
    Sha256Digest::parse(row.selection_digest.clone())
        .context("local-successor selection digest is invalid")?;
    let expected = serde_json::json!({
        "schema":"nq.local_successor_acquisition_intent.v1",
        "acquisition_id":row.acquisition_id,
        "watcher_instance_id":row.watcher_instance_id,
        "watcher_semantic_digest":row.watcher_semantic_digest,
        "selection_digest":row.selection_digest,
        "run_id":row.run_id,
        "intake_id":row.intake_id,
    });
    let actual: Value = serde_json::from_slice(row.intent.as_bytes())
        .context("local-successor intent is not JSON")?;
    if actual != expected {
        bail!("local-successor columns differ from canonical intent");
    }
    Ok(())
}

fn local_successor_phases_are_terminal(phases: &[String]) -> bool {
    nq_core::engine::validate_local_successor_terminal_phases(phases).is_ok()
}

fn canonical(bytes: &[u8], label: &str) -> Result<CanonicalDocument> {
    CanonicalDocument::from_canonical_bytes(bytes.to_vec())
        .with_context(|| format!("{label} is not exact canonical JSON"))
}

fn require_digest(expected: &str, document: &CanonicalDocument, label: &str) -> Result<()> {
    let expected = Sha256Digest::parse(expected.to_owned())
        .with_context(|| format!("{label} digest is invalid"))?;
    if expected.as_str() != document.digest() {
        bail!("{label} digest differs from canonical bytes");
    }
    Ok(())
}

fn parse_time(value: &str, label: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{label} is not RFC3339"))?
        .with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_store::{
        MaintenanceDeclarationInput, NotificationDeliveryEventInput,
        NotificationDeliveryIntentInput, NotificationInput, SavedCheckDefinitionInput,
        SavedCheckEventInput,
    };
    use serde_json::json;
    use tempfile::TempDir;

    const AT: &str = "2026-09-14T12:00:00Z";

    fn document(value: Value) -> CanonicalDocument {
        CanonicalDocument::from_serializable(&value).expect("canonical fixture")
    }

    fn store() -> (TempDir, Store) {
        let root = TempDir::new().expect("tempdir");
        let store = Store::initialize(root.path().join("nq.db")).expect("initialize store");
        (root, store)
    }

    fn install_definition(store: &mut Store) {
        let definition = document(json!({
            "schema":"nq.saved-check-definition/v1",
            "reference":"fixture.saved-check",
            "source_identity":"fixture-source",
            "currentness_seconds":120,
            "name":"fixture",
            "sql_text":"SELECT value FROM fixture",
            "mode":"non_empty",
            "threshold":null,
            "column":null,
            "description":null
        }));
        store
            .install_saved_check(&SavedCheckDefinitionInput {
                definition_id: "definition-fixture".into(),
                stable_reference: "fixture.saved-check".into(),
                definition_digest: definition.digest().into(),
                definition,
                installed_at: "2026-09-14T11:00:00Z".into(),
            })
            .expect("install definition");
    }

    fn claim(store: &mut Store, evaluation_id: &str) {
        store
            .claim_saved_check_evaluation(
                "definition-fixture",
                evaluation_id,
                "2026-09-14T11:30:00Z",
                &document(json!({"binding":{"fixture":true}})),
            )
            .expect("claim evaluation");
    }

    #[test]
    fn unfinished_saved_check_claim_refuses_rollover() {
        let (_root, mut store) = store();
        install_definition(&mut store);
        claim(&mut store, "evaluation-pending");
        let report = inspect_store(&store, parse_time(AT, "at").unwrap(), AT.into()).unwrap();
        assert!(!report.eligible);
        assert_eq!(report.refusals.len(), 1);
        assert_eq!(report.refusals[0].kind, "saved_check");
        assert_eq!(report.refusals[0].state, "claimed");
    }

    #[test]
    fn terminal_saved_check_is_transferable_history_not_pending_work() {
        let (_root, mut store) = store();
        install_definition(&mut store);
        claim(&mut store, "evaluation-terminal");
        store
            .append_saved_check_event(&SavedCheckEventInput {
                definition_id: "definition-fixture".into(),
                event_number: 0,
                occurred_at: "2026-09-14T11:30:01Z".into(),
                outcome: "failed".into(),
                detail: document(json!({"binding":{"fixture":true},"read_attempted_at":"2026-09-14T11:30:01Z","refusal_reason":null})),
                evaluation_id: Some("evaluation-terminal".into()),
            })
            .expect("terminal event");
        let report = inspect_store(&store, parse_time(AT, "at").unwrap(), AT.into()).unwrap();
        assert!(report.eligible);
        assert_eq!(report.evaluations[0].outcome, "failed");
        assert!(report.evaluations[0].terminal_event_number.is_some());
    }

    fn notification(store: &mut Store, id: &str) {
        let policy_digest = document(json!({"policy":true})).digest().to_owned();
        let intent = document(json!({
            "schema":"nq.notification_delivery_intent.v1",
            "attention_kind":"operator_assertion",
            "stable_event_id":format!("event-{id}"),
            "attention_receipt_digest":null,
            "attention_policy_id":"policy-fixture",
            "attention_policy_digest":policy_digest,
            "transition_id":"transition-fixture",
            "route_reference":"route-fixture",
            "destination_identity":format!("destination-{id}"),
            "summary":"fixture notification",
            "inspection_reference":"fixture://notification",
            "owner_receipt":null
        }));
        let payload = document(json!({"fixture":"payload"}));
        store
            .retain_notification_delivery(
                &NotificationInput {
                    notification_id: id.into(),
                    idempotency_key: format!("key-{id}"),
                    finding_event_id: None,
                    destination_kind: "local".into(),
                    payload: payload.clone(),
                    available_at: "2026-09-14T11:00:00Z".into(),
                    max_attempts: 1,
                    created_at: "2026-09-14T11:00:00Z".into(),
                },
                &NotificationDeliveryIntentInput {
                    notification_id: id.into(),
                    stable_event_id: format!("event-{id}"),
                    attention_kind: "operator_assertion".into(),
                    attention_receipt_digest: None,
                    attention_policy_id: "policy-fixture".into(),
                    attention_policy_digest: policy_digest,
                    transition_id: "transition-fixture".into(),
                    route_reference: "route-fixture".into(),
                    destination_identity: format!("destination-{id}"),
                    content_digest: payload.digest().into(),
                    intent,
                    created_at: "2026-09-14T11:00:00Z".into(),
                },
            )
            .expect("retain notification");
    }

    #[test]
    fn pending_and_claimed_notification_states_refuse() {
        let (_root, mut store) = store();
        notification(&mut store, "notification-pending");
        notification(&mut store, "notification-claimed");
        store
            .append_notification_delivery_event(&NotificationDeliveryEventInput {
                notification_id: "notification-claimed".into(),
                event_number: 1,
                occurred_at: "2026-09-14T11:01:00Z".into(),
                outcome: "claimed".into(),
                detail: document(json!({"fixture":"claim"})),
            })
            .expect("append claim");
        let report = inspect_store(&store, parse_time(AT, "at").unwrap(), AT.into()).unwrap();
        assert!(!report.eligible);
        assert!(report.refusals.iter().any(|r| r.state == "pending"));
        assert!(report.refusals.iter().any(|r| r.state == "unknown"));
    }

    #[test]
    fn unknown_notification_sequence_is_not_treated_as_settled() {
        let events = vec![nq_store::NotificationDeliveryHistoryEventRecord {
            event_number: 1,
            occurred_at: "2026-09-14T11:01:00Z".into(),
            outcome: "accepted".into(),
            detail_json: document(json!({"fixture":"invalid-first-event"}))
                .as_bytes()
                .to_vec(),
        }];
        assert!(notification_state(&events).is_err());
    }

    #[test]
    fn local_successor_phase_gate_accepts_only_the_exact_terminal_pair() {
        assert!(local_successor_phases_are_terminal(&[
            "provider_invocation_started".into(),
            "provider_intake_completed".into(),
        ]));
        for phases in [
            vec![],
            vec!["provider_invocation_started".into()],
            vec!["provider_intake_completed".into()],
            vec!["provider_invocation_started".into(), "unknown".into()],
        ] {
            assert!(!local_successor_phases_are_terminal(&phases));
        }
    }

    #[test]
    fn legacy_notification_terminal_and_pending_states_are_closed() {
        assert_eq!(
            legacy_notification_state(3, 1, Some("delivered")).unwrap(),
            "delivered"
        );
        assert_eq!(
            legacy_notification_state(3, 3, Some("failed")).unwrap(),
            "failed"
        );
        for (attempts, outcome) in [(0, None), (1, Some("failed")), (2, Some("retryable"))] {
            assert_eq!(
                legacy_notification_state(3, attempts, outcome).unwrap(),
                "pending"
            );
        }
        assert!(legacy_notification_state(3, 1, Some("future-state")).is_err());
        assert!(legacy_notification_state(3, 4, Some("failed")).is_err());
    }

    #[test]
    fn only_current_maintenance_is_transferable() {
        let (_root, mut store) = store();
        for (id, start, end) in [
            ("expired", "2026-09-14T10:00:00Z", "2026-09-14T11:00:00Z"),
            ("current", "2026-09-14T11:00:00Z", "2026-09-14T13:00:00Z"),
            ("future", "2026-09-14T13:00:00Z", "2026-09-14T14:00:00Z"),
        ] {
            let declaration = document(json!({
                "schema":"nq.maintenance-declaration/v1",
                "maintenance_id":id,
                "declared_by":"fixture",
                "start_at":start,
                "end_at":end,
                "component":"fixture-component",
                "kind":"fixture-kind",
                "subject":"fixture-subject",
                "reason":"fixture"
            }));
            store
                .declare_maintenance(&MaintenanceDeclarationInput {
                    maintenance_id: id.into(),
                    declaration_digest: declaration.digest().into(),
                    declaration,
                    declared_at: "2026-09-14T09:00:00Z".into(),
                })
                .expect("declare maintenance");
        }
        let report = inspect_store(&store, parse_time(AT, "at").unwrap(), AT.into()).unwrap();
        assert_eq!(report.maintenance_history.len(), 3);
        assert_eq!(report.current_maintenance.len(), 1);
        assert_eq!(
            report.current_maintenance[0].prior_maintenance_id,
            "current"
        );
    }

    #[test]
    fn malformed_inspection_time_refuses_before_archive_access() {
        let error = inspect_rollover(Path::new("/does/not/matter"), "not-a-time").unwrap_err();
        assert!(error.to_string().contains("inspected_at"));
    }
}
