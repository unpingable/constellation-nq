//! Complete operator command surface.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::notification;
use crate::saved_check::{self, MaintenanceDeclaration, SavedCheckDefinition, SavedCheckOutcome};
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use nix::libc;
use nq_core::config::{LoadedConfig, NqConfig};
use nq_helper_sandbox::{open_runtime_root, require_no_posix_acl};
use nq_profiles::all_profiles;
use nq_protocol::{Sha256Digest, semantic_digest};
use nq_store::{
    CanonicalDocument, DiagnosticArtifactByteState, DiagnosticArtifactImportDisposition,
    DiagnosticArtifactImportInput, DiagnosticArtifactLookup, DiagnosticArtifactOrigin,
    DiagnosticArtifactSchemaSupport, MAX_PUBLIC_QUERY_ROWS, MAX_STORED_JSON_BYTES,
    MaintenanceDeclarationInput, SavedCheckDefinitionInput, SavedCheckEventInput, Store,
    UpgradeReceiptInput,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

/// Local-first NQ-ng operator CLI.
#[derive(Debug, Parser)]
#[command(name = "nq", version, about)]
pub struct Nq {
    /// Human-edited configuration path.
    #[arg(
        long,
        env = "NQ_CONFIG",
        default_value = "/etc/nq/nq.toml",
        global = true
    )]
    pub config: PathBuf,
    /// Emit machine-readable JSON for commands that otherwise use text.
    #[arg(long, global = true)]
    pub json: bool,
    /// Operator operation.
    #[command(subcommand)]
    pub command: Command,
}

/// Operator workflows.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Qualify independent held-cut, backup and restore prerequisites; no authority.
    LabelwatchCleanup {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Qualify fresh read-only Labelwatch maintenance facts; no action authority.
    LabelwatchRelief {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Acquire and qualify a bounded Docket committed-attempt factual record.
    DocketPurposeSupport {
        #[arg(long)]
        docket_binary: PathBuf,
        #[arg(long)]
        docket_sha256: String,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        snapshot_history: PathBuf,
    },
    /// Qualify an exact external Continuity memory rely export, not action authority.
    ContinuitySupport {
        #[arg(long)]
        source_export: PathBuf,
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        snapshot_history: PathBuf,
    },
    /// Admit or replay one compiled, content-bound factual predicate.
    BoundedPredicate {
        #[command(subcommand)]
        command: crate::queue_cli::QueueCommand,
    },
    /// Read-only compiled repository-stage qualification.
    CampaignStageQualification {
        #[command(subcommand)]
        command: crate::stage_cli::StageCommand,
    },
    /// Read-only compiled reservation-realization qualification.
    CampaignStageRealization {
        #[command(subcommand)]
        command: crate::stage_cli::StageCommand,
    },
    /// Bounded repository-state observation and exact replay.
    RepositoryState {
        #[command(subcommand)]
        command: crate::repository_cli::RepositoryCommand,
    },
    /// Explicitly initialize an empty nq-ng database and directory layout.
    Init(InitArgs),
    /// Validate, compare, and atomically activate human intent.
    Config {
        /// Configuration workflow.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect the compiled profile catalog.
    Profiles {
        /// Catalog operation.
        #[command(subcommand)]
        command: ProfilesCommand,
    },
    /// Verify the exact embedded helper-protocol conformance corpus.
    Protocol {
        /// Protocol contract workflow.
        #[command(subcommand)]
        command: ProtocolCommand,
    },
    /// Test and manage watcher admissions.
    Watcher {
        /// Watcher workflow.
        #[command(subcommand)]
        command: WatcherCommand,
    },
    /// Run one explicitly requested collection (never triggered by a read).
    Collect(InstanceArg),
    /// Execute and emit one immutable bounded diagnostic artifact.
    Diagnostics {
        /// Diagnostic-execution workflow.
        #[command(subcommand)]
        command: DiagnosticsCommand,
    },
    /// Diagnose configuration, storage, profiles, and admission drift.
    Doctor,
    /// Create a verified backup while the daemon is stopped.
    Backup(BackupArgs),
    /// Restore a verified nq-ng backup to an absent destination.
    Restore(RestoreArgs),
    /// Explicit schema maintenance.
    Admin {
        /// Administrative workflow.
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Export current findings.
    Findings {
        /// Finding workflow.
        #[command(subcommand)]
        command: FindingsCommand,
    },
    /// Export service and component status.
    Status {
        /// Status workflow.
        #[command(subcommand)]
        command: StatusCommand,
    },
    /// Export immutable governed detector-evaluation history.
    Evaluations {
        /// Evaluation-history workflow.
        #[command(subcommand)]
        command: EvaluationsCommand,
    },
    /// Export rejected custody with its exact linked typed refusal.
    Refusals {
        /// Refusal-history workflow.
        #[command(subcommand)]
        command: RefusalsCommand,
    },
    /// Retain and inspect bounded human-notification delivery custody. This
    /// never creates attention, admission, or execution authority.
    Notification {
        #[command(subcommand)]
        command: NotificationCommand,
    },
    /// Retain and locally evaluate bounded explicit saved checks.
    SavedCheck {
        #[command(subcommand)]
        command: SavedCheckCommand,
    },
    /// Retain append-only scoped maintenance declarations.
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
    /// Execute a single bounded read-only query over documented public views.
    Query(QueryArgs),
}

/// Initialization arguments.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Optional digest of an immutable legacy-cut manifest.
    #[arg(long)]
    pub legacy_manifest_digest: Option<String>,
}

/// Configuration operations.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Strictly parse and semantically validate a TOML file.
    Check {
        /// Candidate path; defaults to the global configuration.
        path: Option<PathBuf>,
    },
    /// Compare canonical intent without treating formatting as drift.
    Diff {
        /// Candidate configuration.
        candidate: PathBuf,
    },
    /// Atomically replace the active configuration after full validation.
    Apply {
        /// Candidate configuration.
        candidate: PathBuf,
    },
}

/// Profile catalog operations.
#[derive(Debug, Subcommand)]
pub enum ProfilesCommand {
    /// List every explicitly compiled profile and descriptor digest.
    List,
    /// Print one canonical descriptor.
    Show {
        /// Profile ID.
        id: String,
        /// Profile version.
        version: u32,
    },
}

/// Protocol contract operations.
#[derive(Debug, Clone, Copy, Subcommand)]
pub enum ProtocolCommand {
    /// Check every shipped valid and hostile fixture and print its receipt.
    Check,
}

/// Watcher admission operations.
#[derive(Debug, Subcommand)]
pub enum WatcherCommand {
    /// Execute a bounded dry request without creating admission state.
    Test(InstanceArg),
    /// Conformance-test, dry-collect, and atomically activate a new lock.
    Admit(InstanceArg),
    /// Re-admit changed bytes/config/profile and retain admission history.
    Rotate(InstanceArg),
    /// Activate a previously retained and currently verifiable lock.
    Rollback {
        /// Configured instance ID.
        instance_id: String,
        /// Historical lock path.
        lock: PathBuf,
    },
    /// Revoke and retain an active binding under the per-instance lifecycle lock.
    Revoke(InstanceArg),
}

/// One configured instance selector.
#[derive(Debug, Args)]
pub struct InstanceArg {
    /// Configured instance ID.
    pub instance_id: String,
}

/// Bounded diagnostic-execution operations.
#[derive(Debug, Subcommand)]
pub enum DiagnosticsCommand {
    /// Derive explicit read-only purpose support from locally qualified history.
    PurposeSupport {
        #[arg(long)]
        request: PathBuf,
    },
    /// Collect, evaluate, and emit one exact supported diagnostic artifact.
    Execute(InstanceArg),
    /// Inspect one immutable artifact commitment without changing it.
    Inspect {
        /// Exact contract-owned artifact identity.
        artifact_id: String,
    },
    /// Qualify one local artifact's retained NQ admission provenance.
    ///
    /// This establishes evidence eligibility only. It does not grant
    /// freshness, reliance, authorization, or permission to act.
    Qualify {
        /// Exact contract-owned artifact identity.
        artifact_id: String,
    },
    /// Export the exact verified canonical bytes with no framing or newline.
    Export {
        /// Exact contract-owned artifact identity.
        artifact_id: String,
    },
    /// Import exact canonical artifact bytes into custody without granting reliance.
    Import {
        /// Physical regular file containing one canonical artifact.
        artifact: PathBuf,
        /// Stable caller-owned operation identity for crash-safe retry.
        #[arg(long)]
        import_id: Option<String>,
    },
}

/// Backup workflow.
#[derive(Debug, Args)]
pub struct BackupArgs {
    /// Backup destination. Must not already exist.
    pub destination: PathBuf,
}

/// Restore workflow.
#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// Verified nq-ng backup.
    pub backup: PathBuf,
    /// Destination database. Must not already exist.
    pub destination: PathBuf,
}

/// Administrative maintenance.
#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Validate, back up, and explicitly apply the binary's migration chain.
    Upgrade {
        /// Directory for the digest-addressed pre-upgrade backup.
        #[arg(long)]
        backup_directory: PathBuf,
    },
    /// Create a sealed cold archive that verifies the historical system
    /// independently of this installation. Grants no authority.
    Archive {
        /// Archive directory to create. Must not already exist.
        #[arg(long)]
        destination: PathBuf,
    },
    /// Verify a sealed cold archive using only its own contents.
    ArchiveVerify {
        /// Archive directory to verify.
        archive: PathBuf,
    },
}

/// Finding commands.
#[derive(Debug, Subcommand)]
pub enum FindingsCommand {
    /// Export `nq.finding_snapshot.v3` records.
    Export {
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
    },
}

/// Status commands.
#[derive(Debug, Subcommand)]
pub enum StatusCommand {
    /// Export `nq.status_snapshot.v3`.
    Export,
}

/// Governed evaluation-history commands.
#[derive(Debug, Subcommand)]
pub enum EvaluationsCommand {
    /// Export one explicit `nq.evaluation_history.v1` page.
    Export {
        /// Maximum immutable evaluations to return.
        #[arg(long, default_value_t = MAX_PUBLIC_QUERY_ROWS)]
        limit: u32,
        /// Continue after this store-wide append sequence.
        #[arg(long)]
        after: Option<u64>,
        /// Freeze the history at this inclusive append sequence.
        #[arg(long)]
        through: Option<u64>,
    },
}

/// Rejected-custody history commands.
#[derive(Debug, Subcommand)]
pub enum RefusalsCommand {
    /// Export a bounded `nq.rejected_custody.v1` snapshot.
    Export {
        /// Maximum immutable rejection records to return.
        #[arg(long, default_value_t = MAX_PUBLIC_QUERY_ROWS)]
        limit: u32,
        /// Continue after this immutable submission identity.
        #[arg(long)]
        after: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum NotificationCommand {
    /// Retain one explicit operator/Nightshift intent and perform at most one
    /// transport attempt. Network dispatch is disabled unless explicitly named.
    Submit {
        #[arg(long)]
        intent: PathBuf,
        #[arg(long)]
        route: String,
        #[arg(long)]
        enable_network: bool,
    },
    /// Inspect retained delivery custody. A claim without terminal result is
    /// shown as unknown and is never resubmitted automatically.
    Inspect {
        #[arg(long)]
        notification_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SavedCheckCommand {
    Install {
        #[arg(long)]
        definition: PathBuf,
    },
    Inspect {
        reference: String,
    },
    /// Inspect retained work without touching its source or submitting again.
    Result {
        #[arg(long)]
        evaluation_id: String,
    },
    Evaluate {
        reference: String,
        #[arg(long)]
        evaluation_id: String,
        #[arg(long)]
        target: PathBuf,
        /// Caller-supplied observation time for this source, not inferred from a file's mtime.
        #[arg(long)]
        source_observed_at: String,
    },
    /// Project one retained result and a caller-selected maintenance annotation.
    /// This is read-only and never rereads the saved-check source.
    Condition {
        #[arg(long)]
        evaluation_id: String,
        #[arg(long)]
        component: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        at: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum MaintenanceCommand {
    Declare {
        #[arg(long)]
        declaration: PathBuf,
    },
    List,
    /// Annotate an explicitly supplied condition; does not detect or clear it.
    Inspect {
        #[arg(long)]
        component: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        at: String,
    },
}

/// Closed schema identity for structured watcher-action failures.
#[derive(Debug, Clone, Copy, Serialize)]
enum WatcherActionErrorSchema {
    #[serde(rename = "nq.watcher_action_error.v1")]
    V1,
}

/// Versioned, structured non-success result from a watcher dry action.
#[derive(Serialize)]
struct WatcherActionErrorV1<'a> {
    schema: WatcherActionErrorSchema,
    instance_id: &'a str,
    action: &'a str,
    failure: WatcherActionFailureV1<'a>,
}

/// Exact typed failure carried by the watcher-action envelope.
#[derive(Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
enum WatcherActionFailureV1<'a> {
    GovernedRefusal(&'a nq_core::engine::GovernedRefusal),
    AcquisitionFailure(&'a nq_core::engine::AcquisitionFailure),
}

/// Public export format.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    /// One JSON array.
    Json,
    /// One compact JSON object per line.
    Jsonl,
}

/// Restricted public SQL query.
#[derive(Debug, Args)]
pub struct QueryArgs {
    /// A single SELECT over a documented `public_*` view.
    pub sql: String,
    /// Maximum returned rows.
    #[arg(long, default_value_t = MAX_PUBLIC_QUERY_ROWS)]
    pub limit: u32,
}

/// Execute the selected workflow.
///
/// # Errors
///
/// Returns a contextual operator error while preserving the selected
/// workflow's atomicity and custody rules.
pub async fn run(options: Nq) -> Result<()> {
    match options.command {
        Command::LabelwatchRelief { source, request } => {
            crate::labelwatch_relief_cli::run(&source, &request)
        }
        Command::LabelwatchCleanup { source, request } => {
            crate::labelwatch_cleanup_cli::run(&source, &request)
        }
        Command::DocketPurposeSupport {
            docket_binary,
            docket_sha256,
            state,
            request,
            snapshot_history,
        } => crate::docket_cli::run(
            &docket_binary,
            &docket_sha256,
            &state,
            &request,
            &snapshot_history,
        ),
        Command::ContinuitySupport {
            source_export,
            binding,
            snapshot_history,
        } => crate::continuity_cli::run(&source_export, &binding, &snapshot_history),
        Command::BoundedPredicate { command } => crate::queue_cli::run(command),
        Command::CampaignStageQualification { command } => crate::stage_cli::run(command, false),
        Command::CampaignStageRealization { command } => crate::stage_cli::run(command, true),
        Command::RepositoryState { command } => crate::repository_cli::run(command),
        Command::Init(arguments) => initialize(&options.config, arguments, options.json),
        Command::Config { command } => config_command(&options.config, command, options.json),
        Command::Profiles { command } => profiles_command(command, options.json),
        Command::Protocol { command } => protocol_command(command, options.json),
        Command::Watcher { command } => {
            watcher_command(&options.config, command, options.json).await
        }
        Command::Collect(instance) => {
            collect_command(&options.config, &instance.instance_id, options.json).await
        }
        Command::Diagnostics { command } => {
            diagnostics_command(&options.config, command, options.json).await
        }
        Command::Doctor => doctor(&options.config, options.json),
        Command::Backup(arguments) => backup(&options.config, &arguments.destination, options.json),
        Command::Restore(arguments) => {
            restore(&arguments.backup, &arguments.destination, options.json)
        }
        Command::Admin { command } => admin_command(&options.config, command, options.json),
        Command::Findings { command } => findings_command(&options.config, &command),
        Command::Status { command } => status_command(&options.config, &command),
        Command::Evaluations { command } => evaluations_command(&options.config, &command),
        Command::Refusals { command } => refusals_command(&options.config, &command),
        Command::Notification { command } => {
            notification_command(&options.config, command, options.json).await
        }
        Command::SavedCheck { command } => {
            saved_check_command(&options.config, command, options.json)
        }
        Command::Maintenance { command } => {
            maintenance_command(&options.config, command, options.json)
        }
        Command::Query(arguments) => query_command(&options.config, &arguments),
    }
}

fn read_exact_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    // Reuse the public descriptor-bound reader before allocation/decoding.
    // Duplicate keys cannot disappear through a Value conversion.
    let bytes = crate::bounded_input::read(path, MAX_STORED_JSON_BYTES)?;
    let value = nq_protocol::decode_json_document(&bytes, MAX_STORED_JSON_BYTES)?;
    serde_json::from_value(value).with_context(|| format!("cannot decode {}", path.display()))
}

fn saved_check_command(
    config_path: &Path,
    command: SavedCheckCommand,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    match command {
        SavedCheckCommand::Condition {
            evaluation_id,
            component,
            kind,
            subject,
            at,
        } => saved_check_condition(
            &config.database_path,
            &evaluation_id,
            &component,
            &kind,
            &subject,
            &at,
            json_output,
        ),
        SavedCheckCommand::Result { evaluation_id } => {
            let store = Store::open_read_only(&config.database_path)?;
            let event = store.saved_check_event_by_evaluation_id(&evaluation_id)?;
            match event {
                Some(event) => print_value(
                    &json!({"evaluation_id":evaluation_id,"outcome":event.outcome,"detail":serde_json::from_slice::<serde_json::Value>(&event.detail_json)?,"indeterminate":event.outcome == "claimed"}),
                    json_output,
                ),
                None => print_value(
                    &json!({"evaluation_id":evaluation_id,"outcome":"missing","indeterminate":true}),
                    json_output,
                ),
            }
        }
        SavedCheckCommand::Install { definition } => {
            let definition: SavedCheckDefinition = read_exact_json(&definition)?;
            definition.validate()?;
            let document = CanonicalDocument::from_serializable(&definition)?;
            let digest = format!("sha256:{:x}", Sha256::digest(document.as_bytes()));
            let mut store = Store::open(&config.database_path)?;
            store.install_saved_check(&SavedCheckDefinitionInput {
                definition_id: uuid::Uuid::new_v4().to_string(),
                stable_reference: definition.reference.clone(),
                definition_digest: digest.to_string(),
                definition: document,
                installed_at: chrono::Utc::now().to_rfc3339(),
            })?;
            print_value(
                &json!({"result":"installed", "reference": definition.reference, "definition_digest": digest}),
                json_output,
            )
        }
        SavedCheckCommand::Inspect { reference } => {
            let store = Store::open_read_only(&config.database_path)?;
            let record = store
                .saved_check_definition(&reference)?
                .context("saved check reference is not installed")?;
            let definition: serde_json::Value = serde_json::from_slice(&record.definition_json)?;
            print_value(
                &json!({"definition_id":record.definition_id,"reference":record.stable_reference,"definition_digest":record.definition_digest,"installed_at":record.installed_at,"definition":definition}),
                json_output,
            )
        }
        SavedCheckCommand::Evaluate {
            reference,
            evaluation_id,
            target,
            source_observed_at,
        } => {
            if !target.is_absolute() {
                bail!("saved-check target must be an explicit absolute pathname");
            }
            let observed_at = chrono::DateTime::parse_from_rfc3339(&source_observed_at)
                .context("source_observed_at must be an explicit RFC3339 timestamp")?
                .with_timezone(&chrono::Utc);
            let mut store = Store::open(&config.database_path)?;
            let record = store
                .saved_check_definition(&reference)?
                .context("saved check reference is not installed")?;
            let definition: SavedCheckDefinition = serde_json::from_slice(&record.definition_json)?;
            // Replay compares request material, without inspecting a target which
            // may since have changed or disappeared. Snapshot details are evidence
            // of the first read only, never a condition for retrieving that result.
            let binding = json!({"definition_digest":record.definition_digest,"target_reference":target,"source_identity":definition.source_identity,"currentness_seconds":definition.currentness_seconds,"source_observed_at_assertion":source_observed_at});
            if let Some(event) = store.saved_check_event_by_evaluation_id(&evaluation_id)? {
                let detail: serde_json::Value = serde_json::from_slice(&event.detail_json)?;
                if detail.get("binding") != Some(&binding) {
                    bail!("evaluation_id is already bound to different saved-check material");
                }
                return print_value(
                    &json!({"reference":reference,"evaluation_id":evaluation_id,"outcome":event.outcome,"detail":detail,"retained":true,"indeterminate":event.outcome == "claimed"}),
                    json_output,
                );
            }
            let claim = CanonicalDocument::from_serializable(&json!({"binding":binding}))?;
            if !store.claim_saved_check_evaluation(
                &record.definition_id,
                &evaluation_id,
                &chrono::Utc::now().to_rfc3339(),
                &claim,
            )? {
                return print_value(
                    &json!({"reference":reference,"evaluation_id":evaluation_id,"outcome":"claimed","retained":true,"indeterminate":true}),
                    json_output,
                );
            }
            // This records when the bounded read was attempted, not when an
            // external collector last refreshed the database's contents.
            let checked_at = chrono::Utc::now();
            let outcome =
                saved_check::evaluate_read_only_at(&definition, &target, observed_at, checked_at);
            let (outcome_text, refusal_reason) = match outcome
                .unwrap_or(SavedCheckOutcome::Refused("target_or_sqlite_unavailable"))
            {
                SavedCheckOutcome::Passed => ("passed", None),
                SavedCheckOutcome::Failed => ("failed", None),
                SavedCheckOutcome::Refused(reason) => ("refused", Some(reason)),
            };
            let detail = json!({"binding":binding,"read_attempted_at":checked_at.to_rfc3339(),"refusal_reason":refusal_reason});
            store.append_saved_check_event(&SavedCheckEventInput {
                definition_id: record.definition_id,
                event_number: 0,
                occurred_at: checked_at.to_rfc3339(),
                outcome: outcome_text.into(),
                detail: CanonicalDocument::from_serializable(&detail)?,
                evaluation_id: Some(evaluation_id.clone()),
            })?;
            print_value(
                &json!({"reference":reference,"evaluation_id":evaluation_id,"outcome":outcome_text,"detail":detail,"retained":false,"indeterminate":false}),
                json_output,
            )
        }
    }
}

/// Read one retained saved-check outcome together with a caller-selected
/// maintenance annotation. This is deliberately a projection: it neither reads
/// the saved target nor turns historical custody into a present condition.
fn saved_check_condition(
    database_path: &Path,
    evaluation_id: &str,
    component: &str,
    kind: &str,
    subject: &str,
    at: &str,
    json_output: bool,
) -> Result<()> {
    let requested_at = at;
    let at = chrono::DateTime::parse_from_rfc3339(requested_at)
        .context("condition --at must be RFC3339")?
        .with_timezone(&chrono::Utc);
    let store = Store::open_read_only(database_path)?;
    let value = saved_check_condition_value(
        &store,
        evaluation_id,
        component,
        kind,
        subject,
        requested_at,
        at,
    )?;
    print_value(&value, json_output)
}

/// Construct a projection exclusively from retained NQ custody. This accepts no
/// source target or evaluator and therefore cannot read a saved-check target.
fn saved_check_condition_value(
    store: &Store,
    evaluation_id: &str,
    component: &str,
    kind: &str,
    subject: &str,
    requested_at: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Value> {
    let mapping = json!({"component":component,"kind":kind,"subject":subject,"at":requested_at,"mapping_owner":"caller"});
    let Some(event) = store.saved_check_evaluation_by_id(evaluation_id)? else {
        return Ok(saved_check_condition_refusal(
            evaluation_id,
            mapping,
            "evaluation_missing",
        ));
    };
    let detail: Value = match serde_json::from_slice(&event.detail_json) {
        Ok(value) => value,
        Err(_) => {
            return Ok(saved_check_condition_refusal(
                evaluation_id,
                mapping,
                "retained_result_invalid",
            ));
        }
    };
    let binding = match retained_saved_check_binding(&detail) {
        Ok(binding) => binding,
        Err(_) => {
            return Ok(saved_check_condition_refusal(
                evaluation_id,
                mapping,
                "retained_result_invalid",
            ));
        }
    };
    let definition_document =
        match CanonicalDocument::from_canonical_bytes(event.definition_json.clone()) {
            Ok(document) => document,
            Err(_) => {
                return Ok(saved_check_condition_refusal(
                    evaluation_id,
                    mapping,
                    "retained_definition_invalid",
                ));
            }
        };
    let definition_digest = match Sha256Digest::parse(event.definition_digest.clone()) {
        Ok(digest) if digest.as_str() == definition_document.digest() => digest,
        _ => {
            return Ok(saved_check_condition_refusal(
                evaluation_id,
                mapping,
                "retained_definition_invalid",
            ));
        }
    };
    let definition: SavedCheckDefinition =
        match serde_json::from_slice(definition_document.as_bytes()) {
            Ok(definition) if definition.validate().is_ok() => definition,
            _ => {
                return Ok(saved_check_condition_refusal(
                    evaluation_id,
                    mapping,
                    "retained_definition_invalid",
                ));
            }
        };
    if !retained_definition_binding_matches(
        &event.stable_reference,
        &definition,
        &binding,
        definition_digest.as_str(),
    ) {
        return Ok(saved_check_condition_refusal(
            evaluation_id,
            mapping,
            "retained_binding_mismatch",
        ));
    }
    let declarations: Result<Vec<_>> = store
        .maintenance_declarations()?
        .into_iter()
        .map(|record| {
            let document = CanonicalDocument::from_canonical_bytes(record.declaration_json.clone())
                .context("retained maintenance declaration is not canonical")?;
            let stored_digest = Sha256Digest::parse(record.declaration_digest.clone())
                .context("retained maintenance declaration digest is invalid")?;
            if stored_digest.as_str() != document.digest() {
                bail!("retained maintenance declaration digest does not match canonical bytes");
            }
            let declaration: MaintenanceDeclaration =
                serde_json::from_slice(document.as_bytes())
                    .context("retained maintenance declaration is invalid")?;
            let declared_at = chrono::DateTime::parse_from_rfc3339(&record.declared_at)
                .context("retained maintenance declaration time is invalid")?
                .with_timezone(&chrono::Utc);
            Ok((
                declaration,
                record.declaration_digest,
                record.declared_at,
                declared_at,
            ))
        })
        .collect();
    let maintenance = match declarations {
        Err(error) => json!({"state":"unavailable","reason":error.to_string()}),
        Ok(declarations) => match saved_check::maintenance_annotation(
            declarations
                .iter()
                .map(|(declaration, _, _, declared_at)| (declaration, *declared_at)),
            component,
            kind,
            subject,
            at,
        ) {
            Err(error) => json!({"state":"unavailable","reason":error.to_string()}),
            Ok(annotation) => match annotation {
                Some((declaration, saved_check::MaintenanceAnnotation::Covered)) => {
                    let record = declarations
                        .iter()
                        .find(|(candidate, _, _, _)| {
                            candidate.maintenance_id == declaration.maintenance_id
                        })
                        .context("maintenance annotation lost retained record")?;
                    json!({"state":"covered","maintenance_id":declaration.maintenance_id,"declaration_digest":record.1,"declared_at":record.2})
                }
                Some((declaration, saved_check::MaintenanceAnnotation::Overrun)) => {
                    let record = declarations
                        .iter()
                        .find(|(candidate, _, _, _)| {
                            candidate.maintenance_id == declaration.maintenance_id
                        })
                        .context("maintenance annotation lost retained record")?;
                    json!({"state":"overrun","maintenance_id":declaration.maintenance_id,"declaration_digest":record.1,"declared_at":record.2})
                }
                None => json!({"state":"uncovered"}),
            },
        },
    };
    let result_state = retained_result_state(&event.outcome);
    Ok(json!({
        "schema":"nq.saved-check-condition/v1", "projection_state": projection_state(result_state),
        "evaluation_id":evaluation_id, "definition_identity":{"id":event.definition_id,"reference":event.stable_reference,"digest":definition_digest.as_str(),"installed_at":event.installed_at},
        "original_result":{"state":result_state,"outcome":event.outcome,"detail":detail},
        "source_assertion":{"identity":binding.source_identity,"observed_at":binding.source_assertion,"currentness_seconds":binding.currentness_seconds,"state":currentness_state(binding.observed_at, at, binding.currentness_seconds)},
        "maintenance":maintenance, "caller_mapping":mapping,
        "authority":"none", "automatic_nightshift_integration":false,
        "limitations":["Projection does not reread the source","Maintenance annotates and does not alter the original result","A retained result does not establish current conditions or attention authority","The current Store read helpers do not expose one explicit cross-table read snapshot"]
    }))
}

struct RetainedSavedCheckBinding<'a> {
    definition_digest: &'a str,
    target_reference: &'a str,
    source_identity: &'a str,
    source_assertion: &'a str,
    currentness_seconds: u32,
    observed_at: chrono::DateTime<chrono::Utc>,
}

fn retained_saved_check_binding(detail: &Value) -> Result<RetainedSavedCheckBinding<'_>> {
    let binding = detail
        .get("binding")
        .and_then(Value::as_object)
        .context("retained saved-check event has no exact binding")?;
    let definition_digest = binding
        .get("definition_digest")
        .and_then(Value::as_str)
        .context("retained saved-check event has no definition digest")?;
    Sha256Digest::parse(definition_digest.to_owned())
        .context("retained saved-check definition digest is invalid")?;
    let target_reference = binding
        .get("target_reference")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .context("retained saved-check event has no target reference")?;
    let source_identity = binding
        .get("source_identity")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .context("retained saved-check event has no source identity")?;
    let source_assertion = binding
        .get("source_observed_at_assertion")
        .and_then(Value::as_str)
        .context("retained saved-check event has no source observation assertion")?;
    let currentness_seconds = binding
        .get("currentness_seconds")
        .and_then(Value::as_u64)
        .context("retained saved-check event has no currentness bound")?;
    let currentness_seconds = u32::try_from(currentness_seconds)
        .context("retained saved-check currentness exceeds definition bounds")?;
    let observed_at = chrono::DateTime::parse_from_rfc3339(source_assertion)
        .context("retained saved-check source assertion is not RFC3339")?
        .with_timezone(&chrono::Utc);
    Ok(RetainedSavedCheckBinding {
        definition_digest,
        target_reference,
        source_identity,
        source_assertion,
        currentness_seconds,
        observed_at,
    })
}

fn retained_definition_binding_matches(
    stable_reference: &str,
    definition: &SavedCheckDefinition,
    binding: &RetainedSavedCheckBinding<'_>,
    definition_digest: &str,
) -> bool {
    stable_reference == definition.reference
        && binding.definition_digest == definition_digest
        && !binding.target_reference.is_empty()
        && binding.source_identity == definition.source_identity
        && binding.currentness_seconds == definition.currentness_seconds
}

fn currentness_state(
    observed_at: chrono::DateTime<chrono::Utc>,
    at: chrono::DateTime<chrono::Utc>,
    currentness_seconds: u32,
) -> &'static str {
    if at < observed_at {
        "future"
    } else if at.signed_duration_since(observed_at)
        > chrono::Duration::seconds(i64::from(currentness_seconds))
    {
        "stale"
    } else {
        "fresh"
    }
}

fn retained_result_state(outcome: &str) -> &str {
    match outcome {
        "passed" | "failed" | "refused" => outcome,
        "claimed" => "indeterminate",
        _ => "unavailable",
    }
}

fn projection_state(result_state: &str) -> &'static str {
    match result_state {
        "refused" | "unavailable" => "refused",
        "indeterminate" => "indeterminate",
        _ => "available",
    }
}

fn saved_check_condition_refusal(evaluation_id: &str, mapping: Value, reason: &str) -> Value {
    json!({
        "schema":"nq.saved-check-condition/v1",
        "projection_state":"refused",
        "refusal_reason":reason,
        "evaluation_id":evaluation_id,
        "caller_mapping":mapping,
        "maintenance":{"state":"unavailable","reason":"retained_result_unavailable"},
        "authority":"none",
        "automatic_nightshift_integration":false
    })
}

fn maintenance_command(
    config_path: &Path,
    command: MaintenanceCommand,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    match command {
        MaintenanceCommand::Declare { declaration } => {
            let declaration: MaintenanceDeclaration = read_exact_json(&declaration)?;
            declaration.validate()?;
            let document = CanonicalDocument::from_serializable(&declaration)?;
            let digest = format!("sha256:{:x}", Sha256::digest(document.as_bytes()));
            let mut store = Store::open(&config.database_path)?;
            if let Some(retained) = store.maintenance_declaration(&declaration.maintenance_id)? {
                if retained.declaration_digest == digest {
                    return print_value(
                        &json!({"result":"declared","maintenance_id":declaration.maintenance_id,"declaration_digest":digest,"retained":true}),
                        json_output,
                    );
                }
                bail!("maintenance_id is already bound to different declaration material");
            }
            let start = chrono::DateTime::parse_from_rfc3339(&declaration.start_at)?
                .with_timezone(&chrono::Utc);
            if start < chrono::Utc::now() - chrono::Duration::seconds(1) {
                bail!("maintenance start_at is in the past");
            }
            store.declare_maintenance(&MaintenanceDeclarationInput {
                maintenance_id: declaration.maintenance_id.clone(),
                declaration_digest: digest.to_string(),
                declaration: document,
                declared_at: chrono::Utc::now().to_rfc3339(),
            })?;
            print_value(
                &json!({"result":"declared","maintenance_id":declaration.maintenance_id,"declaration_digest":digest}),
                json_output,
            )
        }
        MaintenanceCommand::List => {
            let store = Store::open_read_only(&config.database_path)?;
            let records = store.maintenance_declarations()?;
            let values: Result<Vec<_>> = records.into_iter().map(|r| Ok(json!({"maintenance_id":r.maintenance_id,"declaration_digest":r.declaration_digest,"declared_at":r.declared_at,"declaration":serde_json::from_slice::<serde_json::Value>(&r.declaration_json)?}))).collect();
            print_value(&values?, json_output)
        }
        MaintenanceCommand::Inspect {
            component,
            kind,
            subject,
            at,
        } => {
            let at = chrono::DateTime::parse_from_rfc3339(&at)?.with_timezone(&chrono::Utc);
            let store = Store::open_read_only(&config.database_path)?;
            let declarations: Result<Vec<_>> = store
                .maintenance_declarations()?
                .into_iter()
                .map(|record| {
                    Ok((
                        serde_json::from_slice::<MaintenanceDeclaration>(&record.declaration_json)?,
                        chrono::DateTime::parse_from_rfc3339(&record.declared_at)?
                            .with_timezone(&chrono::Utc),
                    ))
                })
                .collect();
            let declarations = declarations?;
            let annotation = saved_check::maintenance_annotation(
                declarations.iter().map(|(d, t)| (d, *t)),
                &component,
                &kind,
                &subject,
                at,
            )?;
            let (state, declaration_id) = match annotation {
                Some((d, saved_check::MaintenanceAnnotation::Covered)) => {
                    ("covered", Some(&d.maintenance_id))
                }
                Some((d, saved_check::MaintenanceAnnotation::Overrun)) => {
                    ("overrun", Some(&d.maintenance_id))
                }
                None => ("uncovered", None),
            };
            print_value(
                &json!({"component":component,"kind":kind,"subject":subject,"at":at,"maintenance_state":state,"maintenance_id":declaration_id,"condition_source":"caller_assertion","condition_changed":false}),
                json_output,
            )
        }
    }
}

async fn notification_command(
    config_path: &Path,
    command: NotificationCommand,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    match command {
        NotificationCommand::Submit {
            intent,
            route,
            enable_network,
        } => {
            let result = notification::submit(&config, &intent, &route, enable_network).await?;
            print_value(&result, json_output)
        }
        NotificationCommand::Inspect { notification_id } => print_value(
            &notification::inspect(&config, notification_id.as_deref())?,
            json_output,
        ),
    }
}

fn initialize(config_path: &Path, arguments: InitArgs, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)
        .with_context(|| format!("cannot load {}", config_path.display()))?;
    validate_compiled_profiles(&config)?;
    if let Some(parent) = config.database_path.parent() {
        ensure_daemon_directory(parent, 0o700)?;
    }
    ensure_daemon_directory(&config.admissions_dir, 0o700)?;
    let helper_parent = config
        .helper_runtime_dir
        .parent()
        .context("helper runtime directory must have a parent")?;
    ensure_daemon_directory(helper_parent, 0o751)?;
    ensure_daemon_directory(&config.helper_runtime_dir, 0o711)?;
    if let Some(socket_parent) = config.socket_path.parent()
        && socket_parent != helper_parent
    {
        ensure_daemon_directory(socket_parent, 0o751)?;
    }
    open_runtime_root(&config.helper_runtime_dir).with_context(|| {
        format!(
            "helper runtime root {} is not a safe package-compatible directory",
            config.helper_runtime_dir.display()
        )
    })?;
    let mut store = Store::initialize(&config.database_path)
        .with_context(|| format!("cannot initialize {}", config.database_path.display()))?;
    for module in all_profiles() {
        append_descriptor_if_supported(&mut store, module)?;
    }
    if let Some(digest) = arguments.legacy_manifest_digest {
        validate_sha256(&digest)?;
        append_genesis_if_supported(&mut store, Some(digest))?;
    } else {
        append_genesis_if_supported(&mut store, None)?;
    }
    nq_core::engine::record_component_status(
        &mut store,
        "database",
        "local",
        "healthy",
        "initialized",
        &json!({"schema_version": nq_store::SCHEMA_VERSION}),
    )?;
    nq_core::engine::record_component_status(
        &mut store,
        "profile_catalog",
        "compiled",
        "healthy",
        "catalog_loaded",
        &json!({"profile_count": all_profiles().len()}),
    )?;
    nq_core::engine::record_component_status(
        &mut store,
        "notification",
        "outbox",
        "healthy",
        "outbox_empty",
        &json!({"delivery_enabled": false}),
    )?;
    print_value(
        &json!({
            "initialized": true,
            "database": config.database_path,
            "schema_version": nq_store::SCHEMA_VERSION,
        }),
        json_output,
    )
}

fn config_command(active: &Path, command: ConfigCommand, json_output: bool) -> Result<()> {
    match command {
        ConfigCommand::Check { path } => {
            let path = path.unwrap_or_else(|| active.to_path_buf());
            let config = NqConfig::load(&path)
                .with_context(|| format!("cannot validate {}", path.display()))?;
            validate_compiled_profiles(&config)?;
            let digest = semantic_digest(&config)?.to_string();
            print_value(
                &json!({"valid": true, "path": path, "config_digest": digest}),
                json_output,
            )
        }
        ConfigCommand::Diff { candidate } => {
            let current = NqConfig::load(active)
                .with_context(|| format!("cannot load active config {}", active.display()))?;
            let candidate_config = NqConfig::load(&candidate)
                .with_context(|| format!("cannot load candidate {}", candidate.display()))?;
            validate_compiled_profiles(&candidate_config)?;
            let current_digest = semantic_digest(&current)?.to_string();
            let candidate_digest = semantic_digest(&candidate_config)?.to_string();
            print_value(
                &json!({
                    "equal": current_digest == candidate_digest,
                    "current_digest": current_digest,
                    "candidate_digest": candidate_digest,
                }),
                json_output,
            )
        }
        ConfigCommand::Apply { candidate } => {
            let loaded = LoadedConfig::load(&candidate)
                .with_context(|| format!("cannot load candidate {}", candidate.display()))?;
            validate_compiled_profiles(loaded.config())?;
            let config_digest = semantic_digest(loaded.config())?.to_string();
            activate_loaded_config(&loaded, active)
                .with_context(|| format!("cannot activate candidate {}", candidate.display()))?;
            print_value(
                &json!({
                    "applied": true,
                    "path": active,
                    "config_digest": config_digest,
                }),
                json_output,
            )
        }
    }
}

fn profiles_command(command: ProfilesCommand, json_output: bool) -> Result<()> {
    match command {
        ProfilesCommand::List => {
            let profiles: Vec<_> = all_profiles()
                .iter()
                .map(|module| {
                    let descriptor = module.descriptor();
                    Ok(json!({
                        "id": descriptor.profile.id,
                        "version": descriptor.profile.version,
                        "digest": descriptor.digest()?.as_str(),
                        "family": descriptor.family,
                        "title": descriptor.title,
                    }))
                })
                .collect::<Result<_, nq_profiles::DescriptorError>>()?;
            print_value(&profiles, json_output)
        }
        ProfilesCommand::Show { id, version } => {
            let module = nq_profiles::resolve_profile(&id, version)
                .with_context(|| format!("profile {id} v{version} is not compiled"))?;
            print_value(module.descriptor(), true)
        }
    }
}

fn protocol_command(command: ProtocolCommand, json_output: bool) -> Result<()> {
    match command {
        ProtocolCommand::Check => {
            let receipt = nq_protocol::verify_embedded_conformance_corpus()?;
            print_value(&receipt, json_output)
        }
    }
}

async fn watcher_command(
    config_path: &Path,
    command: WatcherCommand,
    json_output: bool,
) -> Result<()> {
    match command {
        WatcherCommand::Test(instance) => {
            run_watcher_action(config_path, &instance.instance_id, "test", json_output).await
        }
        WatcherCommand::Admit(instance) => {
            run_watcher_action(config_path, &instance.instance_id, "admit", json_output).await
        }
        WatcherCommand::Rotate(instance) => {
            run_watcher_action(config_path, &instance.instance_id, "rotate", json_output).await
        }
        WatcherCommand::Rollback { instance_id, lock } => {
            rollback(config_path, &instance_id, &lock, json_output).await
        }
        WatcherCommand::Revoke(instance) => {
            revoke(config_path, &instance.instance_id, json_output).await
        }
    }
}

async fn collect_command(config_path: &Path, instance_id: &str, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.collect(&watcher)
    })
    .await??;
    let successful = result.is_success();
    print_collection_outcome(&result, json_output)?;
    if successful {
        Ok(())
    } else {
        bail!("collection did not produce a complete or partial admitted report")
    }
}

async fn diagnostics_command(
    config_path: &Path,
    command: DiagnosticsCommand,
    json_output: bool,
) -> Result<()> {
    match command {
        DiagnosticsCommand::Execute(instance) => {
            diagnostic_execute(config_path, &instance.instance_id).await
        }
        DiagnosticsCommand::PurposeSupport { request } => {
            crate::purpose_cli::run(config_path, &request)
        }
        DiagnosticsCommand::Inspect { artifact_id } => {
            diagnostic_inspect(config_path, &artifact_id, json_output)
        }
        DiagnosticsCommand::Qualify { artifact_id } => {
            diagnostic_qualify(config_path, &artifact_id, json_output)
        }
        DiagnosticsCommand::Export { artifact_id } => diagnostic_export(config_path, &artifact_id),
        DiagnosticsCommand::Import {
            artifact,
            import_id,
        } => diagnostic_import(config_path, &artifact, import_id.as_deref(), json_output),
    }
}

fn diagnostic_qualify(config_path: &Path, artifact_id: &str, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let artifact_id = nq_protocol::Sha256Digest::parse(artifact_id.to_owned())?;
    let store = Store::open_read_only(&config.database_path)?;
    let provenance = nq_core::qualify_diagnostic_admission(&store, &artifact_id)?;
    print_value(&provenance, json_output)
}

async fn diagnostic_execute(config_path: &Path, instance_id: &str) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let artifact = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.diagnostic_execute(&watcher)
    })
    .await??;
    std::io::stdout()
        .lock()
        .write_all(&artifact.canonical_bytes()?)?;
    Ok(())
}

fn diagnostic_inspect(config_path: &Path, artifact_id: &str, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let artifact_id = nq_protocol::Sha256Digest::parse(artifact_id.to_owned())?;
    let store = Store::open_read_only(&config.database_path)?;
    if matches!(
        store.diagnostic_artifact(
            &artifact_id,
            nq_core::SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS
        )?,
        DiagnosticArtifactLookup::Found(nq_store::DiagnosticArtifactAccess {
            commitment: nq_store::DiagnosticArtifactCommitment {
                origin: DiagnosticArtifactOrigin::Local { .. },
                ..
            },
            ..
        })
    ) {
        nq_core::engine::validate_semantic_history(&store)?;
    }
    print_value(
        &diagnostic_artifact_access_value(&store, &artifact_id)?,
        json_output,
    )
}

fn diagnostic_export(config_path: &Path, artifact_id: &str) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let artifact_id = nq_protocol::Sha256Digest::parse(artifact_id.to_owned())?;
    let store = Store::open_read_only(&config.database_path)?;
    let DiagnosticArtifactLookup::Found(access) = store.diagnostic_artifact(
        &artifact_id,
        nq_core::SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS,
    )?
    else {
        bail!("diagnostic artifact {artifact_id} is not committed");
    };
    if matches!(
        access.commitment.origin,
        DiagnosticArtifactOrigin::Local { .. }
    ) {
        nq_core::engine::validate_semantic_history(&store)?;
    }
    match access.byte_state {
        DiagnosticArtifactByteState::VerifiedAvailable { canonical_bytes } => {
            if matches!(
                access.schema_support,
                DiagnosticArtifactSchemaSupport::Supported
            ) {
                let diagnostic = nq_core::SupportedDiagnosticExecution::decode_canonical(
                    canonical_bytes.as_bytes(),
                )
                .with_context(|| {
                    format!("diagnostic artifact {artifact_id} failed strict contract reopening")
                })?;
                if diagnostic.artifact_id().as_digest() != &artifact_id {
                    bail!(
                        "diagnostic artifact {artifact_id} strictly reopened with a different self-identity"
                    );
                }
            }
            std::io::stdout()
                .lock()
                .write_all(canonical_bytes.as_bytes())?;
            Ok(())
        }
        DiagnosticArtifactByteState::CommittedUnavailable => {
            bail!(
                "diagnostic artifact {artifact_id} is committed but its exact bytes are unavailable"
            )
        }
        DiagnosticArtifactByteState::Corrupt { reason } => {
            bail!("diagnostic artifact {artifact_id} failed byte verification: {reason}")
        }
    }
}

fn diagnostic_import(
    config_path: &Path,
    artifact: &Path,
    import_id: Option<&str>,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let document = CanonicalDocument::from_canonical_bytes(read_bounded_artifact_file(artifact)?)?;
    let value: serde_json::Value = serde_json::from_slice(document.as_bytes())?;
    let object = value
        .as_object()
        .context("diagnostic artifact must be one canonical JSON object")?;
    let contract_schema = object
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context("diagnostic artifact has no nonempty top-level schema")?
        .to_owned();
    let artifact_id = nq_protocol::Sha256Digest::parse(
        object
            .get("artifact_id")
            .and_then(serde_json::Value::as_str)
            .context("diagnostic artifact has no typed top-level artifact_id")?
            .to_owned(),
    )?;
    let schema_supported =
        nq_core::SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS.contains(&contract_schema.as_str());
    if schema_supported {
        let reopened =
            nq_core::SupportedDiagnosticExecution::decode_canonical(document.as_bytes())?;
        if reopened.artifact_id().as_digest() != &artifact_id {
            bail!("diagnostic artifact payload self-identity differs from imported identity");
        }
    }
    let imported_at = chrono::Utc::now().to_rfc3339();
    let import_id = import_id.map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned);
    let mut store = Store::open(&config.database_path)?;
    let receipt = store.import_diagnostic_artifact(&DiagnosticArtifactImportInput {
        import_id,
        artifact_id,
        contract_schema: contract_schema.clone(),
        canonical_bytes: document,
        imported_at,
    })?;
    let disposition = match receipt.disposition {
        DiagnosticArtifactImportDisposition::Committed => "committed",
        DiagnosticArtifactImportDisposition::CommittedUnavailable => "committed_unavailable",
        DiagnosticArtifactImportDisposition::Existing => "existing",
        DiagnosticArtifactImportDisposition::Rematerialized => "rematerialized",
    };
    print_value(
        &json!({
            "schema": "nq.diagnostic_artifact_import_receipt.v1",
            "import_id": receipt.import_id,
            "artifact_id": receipt.artifact_id,
            "contract_schema": receipt.contract_schema,
            "canonical_bytes_sha256": receipt.canonical_bytes_sha256,
            "canonical_bytes_length": receipt.canonical_bytes_length,
            "schema_support": if schema_supported { "supported" } else { "unsupported" },
            "disposition": disposition,
            "imported_at": receipt.imported_at,
            "producer_authenticated": false,
            "relied_upon": false,
            "grants_authority": false,
        }),
        json_output,
    )
}

fn read_bounded_artifact_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        // Opening a FIFO read-only can otherwise block before metadata proves
        // that the input is not the bounded physical regular file required by
        // this interface.
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open diagnostic artifact {}", path.display()))?;
    let before = file.metadata()?;
    if !before.is_file() {
        bail!(
            "diagnostic artifact {} is not a physical regular file",
            path.display()
        );
    }
    let limit = u64::try_from(MAX_STORED_JSON_BYTES)?
        .checked_add(1)
        .context("diagnostic artifact read limit overflowed")?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_STORED_JSON_BYTES {
        bail!(
            "diagnostic artifact is {} bytes; limit is {MAX_STORED_JSON_BYTES}",
            bytes.len()
        );
    }
    let after = file.metadata()?;
    let before_identity = (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
    );
    let after_identity = (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
    );
    if before_identity != after_identity || after.len() != u64::try_from(bytes.len())? {
        bail!(
            "diagnostic artifact {} changed during bounded read",
            path.display()
        );
    }
    Ok(bytes)
}

#[allow(clippy::too_many_lines)] // Keep every artifact access and byte-state projection visibly closed.
fn diagnostic_artifact_access_value(
    store: &Store,
    artifact_id: &nq_protocol::Sha256Digest,
) -> Result<serde_json::Value> {
    let lookup =
        store.diagnostic_artifact(artifact_id, nq_core::SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS)?;
    let DiagnosticArtifactLookup::Found(access) = lookup else {
        return Ok(json!({
            "schema": "nq.diagnostic_artifact_access.v1",
            "artifact_id": artifact_id,
            "lookup_state": "record_missing",
            "nonclaims": [
                "a missing commitment is not a committed artifact whose bytes are unavailable",
                "this read grants no reliance, authorization, or action"
            ],
        }));
    };
    let origin = match access.commitment.origin {
        DiagnosticArtifactOrigin::Local {
            run_id,
            evaluation_id,
            completed_at,
        } => json!({
            "kind": "local_execution",
            "run_id": run_id,
            "evaluation_id": evaluation_id,
            "completed_at": completed_at,
        }),
        DiagnosticArtifactOrigin::Imported {
            import_id,
            imported_at,
        } => json!({
            "kind": "imported_custody",
            "import_id": import_id,
            "imported_at": imported_at,
        }),
    };
    let schema_supported = matches!(
        access.schema_support,
        DiagnosticArtifactSchemaSupport::Supported
    );
    let schema_support = match access.schema_support {
        DiagnosticArtifactSchemaSupport::Supported => json!({"state": "supported"}),
        DiagnosticArtifactSchemaSupport::Unsupported { contract_schema } => json!({
            "state": "unsupported",
            "contract_schema": contract_schema,
        }),
    };
    let (byte_state, diagnostic) = match access.byte_state {
        DiagnosticArtifactByteState::VerifiedAvailable { canonical_bytes } if schema_supported => {
            match nq_core::SupportedDiagnosticExecution::decode_canonical(
                canonical_bytes.as_bytes(),
            ) {
                Ok(diagnostic) if diagnostic.artifact_id().as_digest() == artifact_id => (
                    json!({"state": "verified_available"}),
                    Some(serde_json::from_slice::<serde_json::Value>(
                        canonical_bytes.as_bytes(),
                    )?),
                ),
                Ok(_) => (
                    json!({
                        "state": "corrupt",
                        "reason": "strictly reopened self-identity differs from lookup identity",
                    }),
                    None,
                ),
                Err(error) => (
                    json!({
                        "state": "corrupt",
                        "reason": format!("strict contract reopening failed: {error}"),
                    }),
                    None,
                ),
            }
        }
        DiagnosticArtifactByteState::VerifiedAvailable { .. } => {
            (json!({"state": "verified_available"}), None)
        }
        DiagnosticArtifactByteState::CommittedUnavailable => {
            (json!({"state": "committed_unavailable"}), None)
        }
        DiagnosticArtifactByteState::Corrupt { reason } => {
            (json!({"state": "corrupt", "reason": reason}), None)
        }
    };
    Ok(json!({
        "schema": "nq.diagnostic_artifact_access.v1",
        "artifact_id": artifact_id,
        "lookup_state": "found",
        "commitment": {
            "artifact_sequence": access.commitment.artifact_sequence,
            "artifact_id": access.commitment.artifact_id,
            "contract_schema": access.commitment.contract_schema,
            "canonical_bytes_sha256": access.commitment.canonical_bytes_sha256,
            "canonical_bytes_length": access.commitment.canonical_bytes_length,
            "committed_at": access.commitment.committed_at,
            "origin": origin,
        },
        "schema_support": schema_support,
        "byte_state": byte_state,
        "diagnostic": diagnostic,
        "nonclaims": [
            "query lookup does not redefine the immutable artifact",
            "import custody does not authenticate the producer",
            "this read grants no reliance, authorization, or action"
        ],
    }))
}

fn collection_outcome_output(
    outcome: &nq_core::CollectionOutcome,
    json_output: bool,
) -> Result<Vec<u8>> {
    let frame = crate::transport::CollectionOutcomeFrame::encode(outcome)?;
    if json_output {
        return Ok(frame.into_wire());
    }
    let mut rendered = serde_json::to_vec_pretty(frame.reopened())?;
    rendered.push(b'\n');
    Ok(rendered)
}

fn print_collection_outcome(outcome: &nq_core::CollectionOutcome, json_output: bool) -> Result<()> {
    let bytes = collection_outcome_output(outcome, json_output)?;
    std::io::stdout().lock().write_all(&bytes)?;
    Ok(())
}

fn doctor(config_path: &Path, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    validate_compiled_profiles(&config)?;
    let store = Store::open_read_only(&config.database_path)?;
    store.validate()?;
    nq_core::engine::validate_provider_intake_history(&store)?;
    let mut diagnostic_artifacts = diagnostic_artifact_custody_summary(&store)?;
    let semantic_artifact_error = if diagnostic_artifacts.first_corruption.is_none() {
        match nq_core::engine::validate_diagnostic_artifact_history(&store) {
            Ok(verified) => {
                diagnostic_artifacts = DiagnosticArtifactCustodySummary::from(verified);
                None
            }
            Err(error) => Some(error),
        }
    } else {
        None
    };
    let mut diagnostics = Vec::new();
    for watcher in &config.watchers {
        let lock_path = config
            .admissions_dir
            .join(format!("{}.json", watcher.instance_id));
        let profile = nq_profiles::resolve_profile(&watcher.profile.id, watcher.profile.version)
            .expect("validated profile");
        let profile_digest = profile.descriptor().digest()?;
        let outcome = nq_core::AdmissionManager.load(&lock_path).and_then(|lock| {
            nq_core::AdmissionManager.verify(
                watcher,
                &lock,
                profile_digest.as_str(),
                nq_protocol::HELPER_PROTOCOL_VERSION,
            )
        });
        diagnostics.push(match outcome {
            Ok(verification) => json!({
                "instance_id": watcher.instance_id,
                "state": "healthy",
                "binding_digest": verification.binding_digest,
            }),
            Err(error) => json!({
                "instance_id": watcher.instance_id,
                "state": "failed",
                "diagnostic": error.to_string(),
            }),
        });
    }
    let instances_healthy = diagnostics.iter().all(|value| value["state"] == "healthy");
    let unsupported_artifacts = diagnostic_artifacts
        .unsupported_available
        .checked_add(diagnostic_artifacts.unsupported_committed_unavailable)
        .context("diagnostic artifact count overflow")?;
    let artifact_state =
        if diagnostic_artifacts.first_corruption.is_some() || semantic_artifact_error.is_some() {
            "corrupt"
        } else if diagnostic_artifacts.commitments == 0 {
            "empty"
        } else if unsupported_artifacts > 0 {
            "unsupported"
        } else if diagnostic_artifacts.supported_committed_unavailable > 0 {
            "committed_unavailable"
        } else {
            "available_supported"
        };
    let artifact_custody_complete = matches!(artifact_state, "empty" | "available_supported");
    let healthy = instances_healthy && artifact_custody_complete;
    print_value(
        &json!({
            "healthy": healthy,
            "database": "healthy",
            "diagnostic_artifacts": {
                "state": artifact_state,
                "commitments": diagnostic_artifacts.commitments,
                "supported_available": diagnostic_artifacts.supported_available,
                "supported_committed_unavailable":
                    diagnostic_artifacts.supported_committed_unavailable,
                "unsupported_available": diagnostic_artifacts.unsupported_available,
                "unsupported_committed_unavailable":
                    diagnostic_artifacts.unsupported_committed_unavailable,
            },
            "profiles": all_profiles().len(),
            "instances": diagnostics,
        }),
        json_output,
    )?;
    if healthy {
        Ok(())
    } else if let Some(error) = semantic_artifact_error {
        Err(error.into())
    } else if let Some(error) = diagnostic_artifacts.first_corruption {
        bail!("{error}")
    } else {
        bail!("doctor found one or more failed or incomplete diagnostic surfaces")
    }
}

fn backup(config_path: &Path, destination: &Path, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let store = Store::open(&config.database_path)?;
    store.validate()?;
    let source_artifacts = nq_core::engine::validate_diagnostic_artifact_history(&store)?;
    if destination.exists() {
        bail!(
            "backup destination already exists: {}",
            destination.display()
        );
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    // SQLite's online backup API is used by the store so WAL state is captured
    // consistently; a filesystem copy is not sufficient.
    store_backup_if_supported(&store, destination)?;
    let backup_store = Store::open(destination)?;
    backup_store.validate()?;
    let backup_artifacts = nq_core::engine::validate_diagnostic_artifact_history(&backup_store)?;
    if backup_artifacts != source_artifacts {
        bail!("backup did not preserve the exact diagnostic artifact custody counts");
    }
    let digest = digest_file(destination)?;
    print_value(
        &json!({
            "backup": destination,
            "sha256": digest,
            "verified": true,
            "diagnostic_artifacts": diagnostic_artifact_preservation_value(&backup_artifacts),
        }),
        json_output,
    )
}

fn restore(backup: &Path, destination: &Path, json_output: bool) -> Result<()> {
    if destination.exists() {
        bail!(
            "restore destination already exists: {}",
            destination.display()
        );
    }
    let source = Store::open_read_only(backup)?;
    source.validate()?;
    let source_artifacts = nq_core::engine::validate_diagnostic_artifact_history(&source)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    // Restore into an absent sibling first. Only an exact, fully validated
    // logical copy is linked into the requested destination, and hard-link
    // creation refuses to replace a path that appears concurrently.
    let temporary = destination.with_file_name(format!(
        ".{}.restore-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("nq"),
        uuid::Uuid::new_v4()
    ));
    let restore_result = (|| {
        store_backup_if_supported(&source, &temporary)?;
        let restored = Store::open_read_only(&temporary)?;
        restored.validate()?;
        let restored_artifacts = nq_core::engine::validate_diagnostic_artifact_history(&restored)?;
        if restored_artifacts != source_artifacts {
            bail!("restore did not preserve the exact diagnostic artifact custody counts");
        }
        fs::hard_link(&temporary, destination).with_context(|| {
            format!(
                "publish validated restore {} without replacing another path",
                destination.display()
            )
        })?;
        Ok::<_, anyhow::Error>(restored_artifacts)
    })();
    let _ = fs::remove_file(&temporary);
    let restored_artifacts = restore_result?;
    print_value(
        &json!({
            "restored": true,
            "destination": destination,
            "sha256": digest_file(destination)?,
            "diagnostic_artifacts":
                diagnostic_artifact_preservation_value(&restored_artifacts),
        }),
        json_output,
    )
}

fn diagnostic_artifact_preservation_value(
    verification: &nq_core::DiagnosticArtifactHistoryVerification,
) -> serde_json::Value {
    let all_required_bytes_available = verification.supported_committed_unavailable == 0
        && verification.unsupported_committed_unavailable == 0;
    json!({
        "commitments": verification.commitments,
        "supported_available": verification.supported_available,
        "supported_committed_unavailable":
            verification.supported_committed_unavailable,
        "unsupported_available": verification.unsupported_available,
        "unsupported_committed_unavailable":
            verification.unsupported_committed_unavailable,
        "structurally_preserved": true,
        "all_required_bytes_available": all_required_bytes_available,
        "full_replay_available": all_required_bytes_available,
    })
}

#[derive(Debug, Default)]
struct DiagnosticArtifactCustodySummary {
    commitments: usize,
    supported_available: usize,
    supported_committed_unavailable: usize,
    unsupported_available: usize,
    unsupported_committed_unavailable: usize,
    first_corruption: Option<String>,
}

impl From<nq_core::DiagnosticArtifactHistoryVerification> for DiagnosticArtifactCustodySummary {
    fn from(value: nq_core::DiagnosticArtifactHistoryVerification) -> Self {
        Self {
            commitments: value.commitments,
            supported_available: value.supported_available,
            supported_committed_unavailable: value.supported_committed_unavailable,
            unsupported_available: value.unsupported_available,
            unsupported_committed_unavailable: value.unsupported_committed_unavailable,
            first_corruption: None,
        }
    }
}

fn diagnostic_artifact_custody_summary(store: &Store) -> Result<DiagnosticArtifactCustodySummary> {
    let mut summary = DiagnosticArtifactCustodySummary::default();
    let mut after = None;
    loop {
        let commitments =
            store.diagnostic_artifact_commitments_bounded(MAX_PUBLIC_QUERY_ROWS, after)?;
        if commitments.is_empty() {
            return Ok(summary);
        }
        let page_len = commitments.len();
        for commitment in commitments {
            after = Some(commitment.artifact_sequence);
            summary.commitments = summary
                .commitments
                .checked_add(1)
                .context("diagnostic artifact count overflow")?;
            let DiagnosticArtifactLookup::Found(access) = store.diagnostic_artifact(
                &commitment.artifact_id,
                nq_core::SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS,
            )?
            else {
                bail!(
                    "diagnostic artifact index lost commitment {}",
                    commitment.artifact_id
                );
            };
            let counter = match (access.schema_support, access.byte_state) {
                (
                    DiagnosticArtifactSchemaSupport::Supported,
                    DiagnosticArtifactByteState::VerifiedAvailable { .. },
                ) => Some(&mut summary.supported_available),
                (
                    DiagnosticArtifactSchemaSupport::Supported,
                    DiagnosticArtifactByteState::CommittedUnavailable,
                ) => Some(&mut summary.supported_committed_unavailable),
                (
                    DiagnosticArtifactSchemaSupport::Unsupported { .. },
                    DiagnosticArtifactByteState::VerifiedAvailable { .. },
                ) => Some(&mut summary.unsupported_available),
                (
                    DiagnosticArtifactSchemaSupport::Unsupported { .. },
                    DiagnosticArtifactByteState::CommittedUnavailable,
                ) => Some(&mut summary.unsupported_committed_unavailable),
                (_, DiagnosticArtifactByteState::Corrupt { reason }) => {
                    summary.first_corruption.get_or_insert_with(|| {
                        format!(
                            "diagnostic artifact {} failed byte verification: {reason}",
                            commitment.artifact_id
                        )
                    });
                    None
                }
            };
            if let Some(counter) = counter {
                *counter = counter
                    .checked_add(1)
                    .context("diagnostic artifact count overflow")?;
            }
        }
        if page_len < MAX_PUBLIC_QUERY_ROWS as usize {
            return Ok(summary);
        }
    }
}

fn upgrade_v5_to_current(
    database_path: &Path,
    backup_directory: &Path,
    binary_digest: &str,
    operator_identity: &CanonicalDocument,
) -> Result<(PathBuf, String)> {
    let started_at = chrono::Utc::now();
    let temporary = backup_directory.join(format!(".nq-upgrade-{}.db", uuid::Uuid::new_v4()));
    let artifact = Store::backup_v5_verified(database_path, &temporary)?;
    let backup = finalize_upgrade_backup(&temporary, backup_directory, &artifact.sha256)?;
    let receipt = UpgradeReceiptInput {
        receipt_id: uuid::Uuid::new_v4().to_string(),
        from_schema_version: 5,
        to_schema_version: 12,
        migrations: CanonicalDocument::from_serializable(&[
            "schema_v5_to_v12_local_checks_notifications",
        ])?,
        binary_digest: binary_digest.to_owned(),
        backup_digest: artifact.sha256.clone(),
        backup_location: backup.display().to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: started_at.to_rfc3339(),
        result: "migrated".into(),
        operator_identity: operator_identity.clone(),
        verification: CanonicalDocument::from_serializable(&json!({
            "integrity":"ok", "source_schema_version":5,
            "source_schema_artifact_digest":nq_store::SCHEMA_V5_ARTIFACT_DIGEST,
            "backup_reopened":true, "historical_notification_delivery":"absent_not_synthesized",
            "historical_saved_checks":"absent_not_synthesized"
        }))?,
    };
    Store::upgrade_v5_to_v12(database_path, &receipt)?.validate()?;
    Ok((backup, artifact.sha256))
}

fn finalize_upgrade_backup(
    temporary_backup: &Path,
    backup_directory: &Path,
    backup_digest: &str,
) -> Result<PathBuf> {
    let backup = backup_directory.join(format!(
        "nq-{}.db",
        backup_digest
            .strip_prefix("sha256:")
            .context("qualified backup digest")?
    ));
    if backup.exists() {
        if digest_file(&backup)? != backup_digest {
            bail!(
                "digest-addressed backup path contains different bytes: {}",
                backup.display()
            );
        }
        fs::remove_file(temporary_backup)?;
    } else {
        fs::rename(temporary_backup, &backup)?;
        File::open(backup_directory)?.sync_all()?;
    }
    Ok(backup)
}

#[allow(clippy::too_many_lines)]
fn admin_command(config_path: &Path, command: AdminCommand, json_output: bool) -> Result<()> {
    match command {
        AdminCommand::Archive { destination } => {
            let report = crate::archive::create_archive(config_path, &destination)?;
            print_value(&serde_json::to_value(&report)?, json_output)
        }
        AdminCommand::ArchiveVerify { archive } => {
            let report = crate::archive::verify_archive(&archive)?;
            print_value(&serde_json::to_value(&report)?, json_output)
        }
        AdminCommand::Upgrade { backup_directory } => {
            let config = NqConfig::load(config_path)?;
            let _ownership = crate::ownership::acquire(&config.database_path, "admin-upgrade")?;
            fs::create_dir_all(&backup_directory)?;
            let started_at = chrono::Utc::now();
            let source_version = Store::database_schema_version(&config.database_path)?;
            let temporary_backup =
                backup_directory.join(format!(".nq-upgrade-{}.db", uuid::Uuid::new_v4()));
            let binary_digest = digest_file(&std::env::current_exe()?)?;
            let operator_identity = CanonicalDocument::from_serializable(&json!({
                "uid": nix::unistd::Uid::effective().as_raw(),
                "gid": nix::unistd::Gid::effective().as_raw(),
            }))?;

            match source_version {
                nq_store::SCHEMA_VERSION => {
                    let mut store = Store::open(&config.database_path)?;
                    store.validate()?;
                    let source_digest = digest_file(&config.database_path)?;
                    // An already-current upgrade still promises a verified
                    // pre-operation backup. Route it through the complete
                    // typed history verifier, including provider-intake
                    // context/raw correspondence, before calling it verified.
                    store_backup_if_supported(&store, &temporary_backup)?;
                    let backup_digest = digest_file(&temporary_backup)?;
                    let backup = finalize_upgrade_backup(
                        &temporary_backup,
                        &backup_directory,
                        &backup_digest,
                    )?;
                    Store::open(&backup)?.validate()?;
                    let finished_at = chrono::Utc::now();
                    store.append_upgrade_receipt(&UpgradeReceiptInput {
                        receipt_id: uuid::Uuid::new_v4().to_string(),
                        from_schema_version: u32::try_from(nq_store::SCHEMA_VERSION)?,
                        to_schema_version: u32::try_from(nq_store::SCHEMA_VERSION)?,
                        migrations: CanonicalDocument::from_serializable(&Vec::<String>::new())?,
                        binary_digest,
                        backup_digest: backup_digest.clone(),
                        backup_location: backup.display().to_string(),
                        started_at: started_at.to_rfc3339(),
                        finished_at: finished_at.to_rfc3339(),
                        result: "already_current".into(),
                        operator_identity: operator_identity.clone(),
                        verification: CanonicalDocument::from_serializable(&json!({
                            "integrity": "ok",
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "source_digest": source_digest,
                        }))?,
                    })?;
                    print_value(
                        &json!({
                            "result": "already_current",
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "backup": backup,
                            "backup_digest": backup_digest,
                        }),
                        json_output,
                    )
                }
                3 => {
                    validate_v3_upgrade_source_semantics(&config.database_path)?;
                    let v3_artifact =
                        Store::backup_v3_verified(&config.database_path, &temporary_backup)?;
                    let v3_backup = finalize_upgrade_backup(
                        &temporary_backup,
                        &backup_directory,
                        &v3_artifact.sha256,
                    )?;
                    validate_v3_upgrade_source_semantics(&v3_backup)?;
                    let v3_receipt = UpgradeReceiptInput {
                        receipt_id: uuid::Uuid::new_v4().to_string(),
                        from_schema_version: 3,
                        to_schema_version: 4,
                        migrations: CanonicalDocument::from_serializable(&[
                            "schema_v3_to_v4_provider_intake",
                        ])?,
                        binary_digest: binary_digest.clone(),
                        backup_digest: v3_artifact.sha256.clone(),
                        backup_location: v3_backup.display().to_string(),
                        started_at: started_at.to_rfc3339(),
                        // The store replaces this preflight value with a
                        // terminal timestamp after migration validation and
                        // immediately before committing the receipt.
                        finished_at: started_at.to_rfc3339(),
                        result: "migrated".into(),
                        operator_identity: operator_identity.clone(),
                        verification: CanonicalDocument::from_serializable(&json!({
                            "integrity": "ok",
                            "source_schema_version": 3,
                            "source_schema_artifact_digest": nq_store::SCHEMA_V3_ARTIFACT_DIGEST,
                            "backup_reopened": true,
                            "historical_provider_intake": "explicit_gap_only",
                            "provider_intakes_synthesized": false,
                            "acknowledgments_synthesized": false,
                        }))?,
                    };
                    Store::upgrade_v3_to_v4(&config.database_path, &v3_receipt)?;

                    let v4_started_at = chrono::Utc::now();
                    let v4_temporary_backup =
                        backup_directory.join(format!(".nq-upgrade-{}.db", uuid::Uuid::new_v4()));
                    let v4_artifact =
                        Store::backup_v4_verified(&config.database_path, &v4_temporary_backup)?;
                    let v4_backup = finalize_upgrade_backup(
                        &v4_temporary_backup,
                        &backup_directory,
                        &v4_artifact.sha256,
                    )?;
                    let v4_receipt = UpgradeReceiptInput {
                        receipt_id: uuid::Uuid::new_v4().to_string(),
                        from_schema_version: 4,
                        to_schema_version: 5,
                        migrations: CanonicalDocument::from_serializable(&[
                            "schema_v4_to_v5_diagnostic_artifacts",
                        ])?,
                        binary_digest: binary_digest.clone(),
                        backup_digest: v4_artifact.sha256.clone(),
                        backup_location: v4_backup.display().to_string(),
                        started_at: v4_started_at.to_rfc3339(),
                        // The store owns the durable terminal timestamp.
                        finished_at: v4_started_at.to_rfc3339(),
                        result: "migrated".into(),
                        operator_identity: operator_identity.clone(),
                        verification: CanonicalDocument::from_serializable(&json!({
                            "integrity": "ok",
                            "source_schema_version": 4,
                            "source_schema_artifact_digest": nq_store::SCHEMA_V4_ARTIFACT_DIGEST,
                            "backup_reopened": true,
                            "historical_diagnostic_artifacts": "no_durable_commitments",
                            "diagnostic_artifacts_synthesized": false,
                        }))?,
                    };
                    drop(Store::upgrade_v4_to_v5(&config.database_path, &v4_receipt)?);
                    let (v5_backup, v5_backup_digest) = upgrade_v5_to_current(
                        &config.database_path,
                        &backup_directory,
                        &binary_digest,
                        &operator_identity,
                    )?;
                    let store = Store::open(&config.database_path)?;
                    store.validate()?;
                    print_value(
                        &json!({
                            "result": "migrated",
                            "from_schema_version": 3,
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "v3_backup": v3_backup,
                            "v3_backup_digest": v3_artifact.sha256,
                            "v4_backup": v4_backup,
                            "v4_backup_digest": v4_artifact.sha256,
                            "v5_backup": v5_backup,
                            "v5_backup_digest": v5_backup_digest,
                            "historical_provider_intake": "explicit_gap_only",
                            "historical_diagnostic_artifacts": "no_durable_commitments",
                        }),
                        json_output,
                    )
                }
                4 => {
                    let artifact =
                        Store::backup_v4_verified(&config.database_path, &temporary_backup)?;
                    let backup = finalize_upgrade_backup(
                        &temporary_backup,
                        &backup_directory,
                        &artifact.sha256,
                    )?;
                    let receipt = UpgradeReceiptInput {
                        receipt_id: uuid::Uuid::new_v4().to_string(),
                        from_schema_version: 4,
                        to_schema_version: 5,
                        migrations: CanonicalDocument::from_serializable(&[
                            "schema_v4_to_v5_diagnostic_artifacts",
                        ])?,
                        binary_digest: binary_digest.clone(),
                        backup_digest: artifact.sha256.clone(),
                        backup_location: backup.display().to_string(),
                        started_at: started_at.to_rfc3339(),
                        // The store owns the durable terminal timestamp.
                        finished_at: started_at.to_rfc3339(),
                        result: "migrated".into(),
                        operator_identity: operator_identity.clone(),
                        verification: CanonicalDocument::from_serializable(&json!({
                            "integrity": "ok",
                            "source_schema_version": 4,
                            "source_schema_artifact_digest": nq_store::SCHEMA_V4_ARTIFACT_DIGEST,
                            "backup_reopened": true,
                            "historical_diagnostic_artifacts": "no_durable_commitments",
                            "diagnostic_artifacts_synthesized": false,
                        }))?,
                    };
                    drop(Store::upgrade_v4_to_v5(&config.database_path, &receipt)?);
                    let (v5_backup, v5_backup_digest) = upgrade_v5_to_current(
                        &config.database_path,
                        &backup_directory,
                        &binary_digest,
                        &operator_identity,
                    )?;
                    let store = Store::open(&config.database_path)?;
                    store.validate()?;
                    print_value(
                        &json!({
                            "result": "migrated",
                            "from_schema_version": 4,
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "v5_backup": v5_backup,
                            "v5_backup_digest": v5_backup_digest,
                            "backup": backup,
                            "backup_digest": artifact.sha256,
                            "historical_diagnostic_artifacts": "no_durable_commitments",
                        }),
                        json_output,
                    )
                }
                5 => {
                    let (backup, backup_digest) = upgrade_v5_to_current(
                        &config.database_path,
                        &backup_directory,
                        &binary_digest,
                        &operator_identity,
                    )?;
                    print_value(
                        &json!({"result":"migrated", "from_schema_version":5,
                        "schema_version":nq_store::SCHEMA_VERSION, "backup":backup,
                        "backup_digest":backup_digest, "historical_saved_checks":"absent_not_synthesized",
                        "historical_notification_delivery":"absent_not_synthesized"}),
                        json_output,
                    )
                }
                _ => {
                    // Reuse the store's exact fail-closed diagnostic. `open`
                    // checks version and identity before any persistent PRAGMA.
                    let _ = Store::open(&config.database_path)?;
                    unreachable!("a non-current schema cannot pass exact Store::open")
                }
            }
        }
    }
}

fn findings_command(config_path: &Path, command: &FindingsCommand) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let store = Store::open_read_only(&config.database_path)?;
    let findings = list_findings_if_supported(&store)?;
    match command {
        FindingsCommand::Export {
            format: ExportFormat::Json,
        } => print_value(&findings, true),
        FindingsCommand::Export {
            format: ExportFormat::Jsonl,
        } => {
            for finding in findings {
                println!("{}", serde_json::to_string(&finding)?);
            }
            Ok(())
        }
    }
}

fn status_command(config_path: &Path, command: &StatusCommand) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let store = Store::open_read_only(&config.database_path)?;
    match command {
        StatusCommand::Export => print_value(&status_snapshot_if_supported(&store)?, true),
    }
}

fn evaluations_command(config_path: &Path, command: &EvaluationsCommand) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let store = Store::open_read_only(&config.database_path)?;
    match command {
        EvaluationsCommand::Export {
            limit,
            after,
            through,
        } => {
            validate_evaluation_page(*limit, *after, *through)?;
            print_value(
                &evaluation_history_if_supported(&store, *limit, *after, *through)?,
                true,
            )
        }
    }
}

fn validate_evaluation_page(limit: u32, after: Option<u64>, through: Option<u64>) -> Result<()> {
    if !(1..=MAX_PUBLIC_QUERY_ROWS).contains(&limit) {
        bail!("evaluation history limit must be between 1 and {MAX_PUBLIC_QUERY_ROWS}");
    }
    if after.is_some() && through.is_none() {
        bail!("evaluation history continuation requires the frozen --through bound");
    }
    if matches!((after, through), (Some(after), Some(through)) if after > through) {
        bail!("evaluation history cursor cannot be greater than its frozen upper bound");
    }
    Ok(())
}

fn refusals_command(config_path: &Path, command: &RefusalsCommand) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let store = Store::open_read_only(&config.database_path)?;
    match command {
        RefusalsCommand::Export { limit, after } => {
            validate_refusal_page(*limit, after.as_deref())?;
            print_value(
                &rejected_custody_if_supported(&store, *limit, after.as_deref())?,
                true,
            )
        }
    }
}

fn validate_refusal_page(limit: u32, after_submission_id: Option<&str>) -> Result<()> {
    if !(1..=MAX_PUBLIC_QUERY_ROWS).contains(&limit) {
        bail!("refusal limit must be between 1 and {MAX_PUBLIC_QUERY_ROWS}");
    }
    if after_submission_id.is_some_and(|cursor| !is_stable_submission_cursor(cursor)) {
        bail!("refusal cursor must be a stable submission-ID token");
    }
    Ok(())
}

fn is_stable_submission_cursor(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
        })
}

fn query_command(config_path: &Path, arguments: &QueryArgs) -> Result<()> {
    validate_query_arguments(arguments)?;
    let config = NqConfig::load(config_path)?;
    let store = Store::open_read_only(&config.database_path)?;
    let rows = public_query_if_supported(&store, &arguments.sql, arguments.limit)?;
    print_value(&rows, true)
}

fn validate_query_arguments(arguments: &QueryArgs) -> Result<()> {
    if !(1..=MAX_PUBLIC_QUERY_ROWS).contains(&arguments.limit) {
        bail!("query limit must be between 1 and {MAX_PUBLIC_QUERY_ROWS}");
    }
    let normalized = arguments.sql.trim().to_ascii_lowercase();
    if !normalized.starts_with("select ")
        || normalized.contains(';')
        || !normalized.contains("public_")
    {
        bail!("only one SELECT over documented public_* views is accepted");
    }
    Ok(())
}

fn validate_compiled_profiles(config: &NqConfig) -> Result<()> {
    Ok(nq_core::engine::validate_compiled_config(config)?)
}

fn atomic_activate(validated_bytes: &[u8], destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .context("destination must have a parent directory")?;
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(validated_bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(destination)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn activate_loaded_config(loaded: &LoadedConfig, destination: &Path) -> Result<()> {
    loaded
        .verify_source_unchanged()
        .context("candidate changed after validation; refusing activation")?;
    atomic_activate(loaded.source_bytes(), destination)
}

fn digest_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn validate_sha256(digest: &str) -> Result<()> {
    let valid = digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if !valid {
        bail!("expected `sha256:` followed by 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn print_value(value: &impl Serialize, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn print_canonical_value(value: &impl Serialize) -> Result<()> {
    let bytes = nq_protocol::canonical_json_bytes(value)?;
    println!(
        "{}",
        String::from_utf8(bytes).context("canonical JSON is not UTF-8")?
    );
    Ok(())
}

// These narrow adapters isolate application wiring from the generic store API.
// They are filled by the store integration once its independently tested slice
// lands.
fn append_descriptor_if_supported(
    store: &mut Store,
    module: &&dyn nq_profiles::ProfileModule,
) -> Result<()> {
    Ok(nq_core::engine::append_profile_descriptor(store, *module)?)
}

fn append_genesis_if_supported(store: &mut Store, digest: Option<String>) -> Result<()> {
    Ok(nq_core::engine::append_genesis(store, digest)?)
}

fn store_backup_if_supported(store: &Store, destination: &Path) -> Result<()> {
    Ok(nq_core::engine::backup_store(store, destination)?)
}

fn validate_v3_upgrade_source_semantics(path: &Path) -> Result<()> {
    let store = Store::open_v3_upgrade_source_read_only(path)?;
    nq_core::engine::validate_admitted_report_history(&store)?;
    nq_core::engine::validate_watcher_run_history(&store)?;
    nq_core::engine::validate_status_history_v2(&store)?;
    nq_core::engine::validate_rejected_custody_history(&store)?;
    nq_core::engine::validate_evaluation_refusal_history(&store)?;
    nq_core::engine::status_snapshot_v3(&store)?;
    Ok(())
}

fn list_findings_if_supported(store: &Store) -> Result<Vec<nq_core::FindingSnapshotV3>> {
    Ok(nq_core::engine::list_findings(store)?)
}

fn status_snapshot_if_supported(store: &Store) -> Result<nq_core::public::StatusSnapshotV3> {
    Ok(nq_core::engine::status_snapshot_v3(store)?)
}

fn evaluation_history_if_supported(
    store: &Store,
    limit: u32,
    after: Option<u64>,
    through: Option<u64>,
) -> Result<nq_core::public::EvaluationHistoryPageV1> {
    Ok(nq_core::engine::evaluation_history_bounded(
        store, limit, after, through,
    )?)
}

fn rejected_custody_if_supported(
    store: &Store,
    limit: u32,
    after_submission_id: Option<&str>,
) -> Result<nq_core::public::RejectedCustodySnapshotV1> {
    Ok(nq_core::engine::rejected_custody_snapshot_bounded(
        store,
        limit,
        after_submission_id,
    )?)
}

fn public_query_if_supported(
    store: &Store,
    sql: &str,
    limit: u32,
) -> Result<Vec<serde_json::Value>> {
    Ok(nq_core::engine::public_query(store, sql, limit)?)
}

async fn run_watcher_action(
    config_path: &Path,
    instance_id: &str,
    action: &str,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let engine_action = action.to_owned();
    let result = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.watcher_action(&watcher, &engine_action)
    })
    .await?;
    match result {
        Ok(result) => print_value(&result, json_output),
        Err(error) => {
            // In structured mode, expected dry-exchange refusals and
            // acquisition failures are emitted as their exact canonical typed
            // objects before the process exits non-zero. The application does
            // not replace them with a display string or infer fields from a
            // coarse error code.
            if json_output
                && let Some(envelope) = watcher_action_error_envelope(instance_id, action, &error)
            {
                print_canonical_value(&envelope)?;
            }
            Err(error.into())
        }
    }
}

fn watcher_action_error_envelope<'a>(
    instance_id: &'a str,
    action: &'a str,
    error: &'a nq_core::engine::EngineError,
) -> Option<WatcherActionErrorV1<'a>> {
    let failure = match error {
        nq_core::engine::EngineError::GovernedRefusal(refusal) => {
            WatcherActionFailureV1::GovernedRefusal(refusal)
        }
        nq_core::engine::EngineError::AcquisitionFailed(failure) => {
            WatcherActionFailureV1::AcquisitionFailure(failure)
        }
        _ => return None,
    };
    Some(WatcherActionErrorV1 {
        schema: WatcherActionErrorSchema::V1,
        instance_id,
        action,
        failure,
    })
}

fn ensure_daemon_directory(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("cannot create daemon directory {}", path.display()))?;
    let descriptor = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("cannot safely open daemon directory {}", path.display()))?;
    let before = descriptor.metadata()?;
    let path_before = fs::symlink_metadata(path)?;
    let daemon_user_id = nix::unistd::geteuid().as_raw();
    let daemon_group_id = nix::unistd::getegid().as_raw();
    if !before.is_dir()
        || !path_before.is_dir()
        || before.dev() != path_before.dev()
        || before.ino() != path_before.ino()
        || before.uid() != daemon_user_id
        || before.gid() != daemon_group_id
    {
        bail!(
            "daemon directory {} must be one real directory owned by uid={daemon_user_id}, gid={daemon_group_id}",
            path.display()
        );
    }
    require_no_posix_acl(&descriptor)
        .with_context(|| format!("unsupported ACL on daemon directory {}", path.display()))?;
    descriptor.set_permissions(fs::Permissions::from_mode(mode))?;
    let after = descriptor.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if !path_after.is_dir()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || path_after.dev() != before.dev()
        || path_after.ino() != before.ino()
        || after.uid() != daemon_user_id
        || after.gid() != daemon_group_id
        || after.mode() & 0o7777 != mode
    {
        bail!(
            "daemon directory {} changed while establishing mode {mode:#06o}",
            path.display()
        );
    }
    Ok(())
}

async fn rollback(
    config_path: &Path,
    instance_id: &str,
    historical: &Path,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let historical = historical.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.rollback_binding(&watcher, &historical)
    })
    .await??;
    print_value(&outcome, json_output)
}

async fn revoke(config_path: &Path, instance_id: &str, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let outcome = tokio::task::spawn_blocking(move || {
        nq_core::CollectionEngine::revoke_configured_binding(&config, &watcher)
    })
    .await??;
    print_value(&outcome, json_output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_core::engine::{EngineError, GovernedRefusal};
    use nq_protocol::{InstanceId, Refusal, RefusalBoundary, RefusalCode, canonical_json_bytes};

    fn config_fixture() -> &'static str {
        r#"schema = "nq.config.v1"
database_path = "/var/lib/nq/nq.db"
socket_path = "/run/nq/nqd.sock"
admissions_dir = "/var/lib/nq/admissions"
helper_runtime_dir = "/run/nq/helpers"
"#
    }

    fn condition_test_store(
        terminal_outcome: Option<&str>,
        malformed_terminal_binding: bool,
        declare_maintenance: bool,
        expired_maintenance: bool,
    ) -> Store {
        let mut store = Store::initialize_in_memory().expect("initialize Store");
        let definition = SavedCheckDefinition {
            schema: crate::saved_check::SavedCheckSchema::V1,
            reference: "capacity".into(),
            source_identity: "sqlite:disposable".into(),
            currentness_seconds: 60,
            name: "Capacity".into(),
            sql_text: "SELECT 1".into(),
            mode: crate::saved_check::SavedCheckMode::Empty,
            threshold: None,
            column: None,
            description: None,
        };
        let definition_document =
            CanonicalDocument::from_serializable(&definition).expect("canonical definition");
        let definition_digest = definition_document.digest().to_owned();
        store
            .install_saved_check(&SavedCheckDefinitionInput {
                definition_id: "definition-001".into(),
                stable_reference: definition.reference.clone(),
                definition_digest: definition_digest.clone(),
                definition: definition_document,
                installed_at: "2026-09-14T12:00:00Z".into(),
            })
            .expect("install definition");
        let binding = if malformed_terminal_binding {
            json!({"definition_digest":"sha256:invalid","source_identity":"sqlite:disposable"})
        } else {
            json!({
                "definition_digest": definition_digest,
                "target_reference": "/removed/disposable-source.sqlite",
                "source_identity": "sqlite:disposable",
                "currentness_seconds": 60,
                "source_observed_at_assertion": "2026-09-14T12:00:00Z"
            })
        };
        let claim = CanonicalDocument::from_serializable(&json!({"binding":binding.clone()}))
            .expect("canonical claim");
        assert!(
            store
                .claim_saved_check_evaluation(
                    "definition-001",
                    "evaluation-001",
                    "2026-09-14T12:00:01Z",
                    &claim,
                )
                .expect("claim evaluation")
        );
        if let Some(outcome) = terminal_outcome {
            let detail = CanonicalDocument::from_serializable(&json!({
                "binding":binding,
                "read_attempted_at":"2026-09-14T12:00:02Z",
                "refusal_reason":null
            }))
            .expect("canonical terminal event");
            store
                .append_saved_check_event(&SavedCheckEventInput {
                    definition_id: "definition-001".into(),
                    event_number: 0,
                    occurred_at: "2026-09-14T12:00:02Z".into(),
                    outcome: outcome.into(),
                    detail,
                    evaluation_id: Some("evaluation-001".into()),
                })
                .expect("append terminal result");
        }
        if declare_maintenance {
            let declaration = MaintenanceDeclaration {
                schema: crate::saved_check::MaintenanceSchema::V1,
                maintenance_id: "maintenance-001".into(),
                declared_by: Some("operator".into()),
                start_at: "2026-09-14T12:00:00Z".into(),
                end_at: if expired_maintenance {
                    "2026-09-14T12:00:10Z".into()
                } else {
                    "2026-09-14T13:00:00Z".into()
                },
                component: "queue".into(),
                kind: "backlog".into(),
                subject: Some("local".into()),
                reason: None,
            };
            let document = CanonicalDocument::from_serializable(&declaration)
                .expect("canonical maintenance declaration");
            store
                .declare_maintenance(&MaintenanceDeclarationInput {
                    maintenance_id: declaration.maintenance_id,
                    declaration_digest: document.digest().to_owned(),
                    declaration: document,
                    declared_at: "2026-09-14T11:59:00Z".into(),
                })
                .expect("declare maintenance");
        }
        store
    }

    #[test]
    fn command_tree_exposes_required_operator_workflows() {
        use clap::CommandFactory;
        Nq::command().debug_assert();
    }

    #[test]
    fn diagnostic_execute_has_one_explicit_bounded_instance() {
        let options = Nq::try_parse_from(["nq", "diagnostics", "execute", "host-local"])
            .expect("bounded diagnostic command parses");
        let Command::Diagnostics {
            command: DiagnosticsCommand::Execute(instance),
        } = options.command
        else {
            panic!("diagnostic execute command expected");
        };
        assert_eq!(instance.instance_id, "host-local");
        assert!(
            Nq::try_parse_from(["nq", "diagnostics", "execute", "host-a", "host-b"]).is_err(),
            "one invocation cannot silently broaden to multiple subjects"
        );
    }

    #[test]
    fn diagnostic_artifact_commands_have_explicit_single_targets() {
        let artifact_id = format!("sha256:{}", "a".repeat(64));
        let inspect = Nq::try_parse_from([
            "nq",
            "--json",
            "diagnostics",
            "inspect",
            artifact_id.as_str(),
        ])
        .expect("artifact inspection parses");
        assert!(inspect.json);
        assert!(matches!(
            inspect.command,
            Command::Diagnostics {
                command: DiagnosticsCommand::Inspect { .. }
            }
        ));

        let qualify = Nq::try_parse_from([
            "nq",
            "--json",
            "diagnostics",
            "qualify",
            artifact_id.as_str(),
        ])
        .expect("artifact admission qualification parses");
        assert!(qualify.json);
        assert!(matches!(
            qualify.command,
            Command::Diagnostics {
                command: DiagnosticsCommand::Qualify { .. }
            }
        ));

        let export = Nq::try_parse_from(["nq", "diagnostics", "export", artifact_id.as_str()])
            .expect("artifact export parses");
        assert!(matches!(
            export.command,
            Command::Diagnostics {
                command: DiagnosticsCommand::Export { .. }
            }
        ));

        let import = Nq::try_parse_from([
            "nq",
            "diagnostics",
            "import",
            "/tmp/artifact.json",
            "--import-id",
            "import:retryable-operation",
        ])
        .expect("artifact import parses");
        let Command::Diagnostics {
            command:
                DiagnosticsCommand::Import {
                    import_id: Some(import_id),
                    ..
                },
        } = import.command
        else {
            panic!("diagnostic import preserves caller operation identity");
        };
        assert_eq!(import_id, "import:retryable-operation");
    }

    #[test]
    fn bounded_artifact_read_refuses_fifo_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let fifo = directory.path().join("artifact.fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR)
            .expect("create diagnostic import FIFO");

        let error =
            read_bounded_artifact_file(&fifo).expect_err("a FIFO is not an importable artifact");
        assert!(
            error.to_string().contains("is not a physical regular file"),
            "unexpected FIFO refusal: {error:#}"
        );
    }

    #[test]
    fn diagnostic_export_refuses_semantically_corrupt_supported_artifact() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        let artifact_id = nq_protocol::sha256_bytes(b"semantic-corruption-fixture");
        let malformed = CanonicalDocument::from_serializable(&json!({
            "schema": nq_core::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA,
            "artifact_id": artifact_id.as_str(),
            "outcome": "not-a-diagnostic-outcome",
        }))
        .expect("canonical malformed fixture");
        let mut store = Store::initialize(&database).expect("initialize store");
        store
            .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                import_id: "import:semantic-corruption".to_owned(),
                artifact_id: artifact_id.clone(),
                contract_schema: nq_core::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA
                    .to_owned(),
                canonical_bytes: malformed,
                imported_at: "2026-07-28T12:00:00Z".to_owned(),
            })
            .expect("opaque storage accepts the structurally bounded artifact");
        drop(store);

        let config = directory.path().join("nq.toml");
        fs::write(
            &config,
            format!(
                r#"schema = "nq.config.v1"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"
"#,
                database.display(),
                directory.path().join("nqd.sock").display(),
                directory.path().join("admissions").display(),
                directory.path().join("helpers").display(),
            ),
        )
        .expect("write test configuration");

        let error = diagnostic_export(&config, artifact_id.as_str())
            .expect_err("supported semantic corruption must not be exported");
        assert!(
            error
                .to_string()
                .contains("failed strict contract reopening"),
            "unexpected export refusal: {error:#}"
        );
    }

    #[test]
    fn refusal_export_exposes_one_exact_immutable_cursor() {
        let options = Nq::try_parse_from([
            "nq",
            "refusals",
            "export",
            "--limit",
            "1",
            "--after",
            "submission-first",
        ])
        .expect("bounded refusal page parses");
        let Command::Refusals {
            command: RefusalsCommand::Export { limit, after },
        } = options.command
        else {
            panic!("refusal export command expected");
        };
        assert_eq!(limit, 1);
        assert_eq!(after.as_deref(), Some("submission-first"));
        validate_refusal_page(limit, after.as_deref()).expect("cursor is stable");

        assert!(
            Nq::try_parse_from([
                "nq",
                "refusals",
                "export",
                "--after",
                "submission-first",
                "--after",
                "submission-second",
            ])
            .is_err(),
            "the CLI must not guess between duplicate cursors"
        );
        assert!(validate_refusal_page(0, None).is_err());
        assert!(validate_refusal_page(MAX_PUBLIC_QUERY_ROWS + 1, None).is_err());
        assert!(validate_refusal_page(1, Some("submission%2Dfirst")).is_err());
    }

    #[test]
    fn evaluation_export_exposes_one_exact_frozen_numeric_cursor() {
        let options = Nq::try_parse_from([
            "nq",
            "evaluations",
            "export",
            "--limit",
            "1",
            "--after",
            "2",
            "--through",
            "9",
        ])
        .expect("bounded evaluation page parses");
        let Command::Evaluations {
            command:
                EvaluationsCommand::Export {
                    limit,
                    after,
                    through,
                },
        } = options.command
        else {
            panic!("evaluation export command expected");
        };
        assert_eq!(limit, 1);
        assert_eq!(after, Some(2));
        assert_eq!(through, Some(9));
        validate_evaluation_page(limit, after, through).expect("cursor is stable");

        assert!(
            Nq::try_parse_from([
                "nq",
                "evaluations",
                "export",
                "--after",
                "2",
                "--after",
                "3",
            ])
            .is_err(),
            "the CLI must not guess between duplicate cursors"
        );
        assert!(validate_evaluation_page(0, None, None).is_err());
        assert!(validate_evaluation_page(MAX_PUBLIC_QUERY_ROWS + 1, None, None).is_err());
        assert!(validate_evaluation_page(1, Some(2), None).is_err());
        assert!(validate_evaluation_page(1, Some(10), Some(9)).is_err());
    }

    #[test]
    fn daemon_directory_setup_establishes_exact_modes_and_safe_runtime_root() {
        let parent = tempfile::tempdir().expect("runtime parent");
        ensure_daemon_directory(parent.path(), 0o751).expect("secure runtime parent");
        let helpers = parent.path().join("helpers");
        ensure_daemon_directory(&helpers, 0o711).expect("secure helper root");
        let parent_metadata = fs::symlink_metadata(parent.path()).unwrap();
        let helper_metadata = fs::symlink_metadata(&helpers).unwrap();
        assert_eq!(parent_metadata.mode() & 0o7777, 0o751);
        assert_eq!(helper_metadata.mode() & 0o7777, 0o711);
        assert_eq!(helper_metadata.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(helper_metadata.gid(), nix::unistd::getegid().as_raw());
        open_runtime_root(&helpers).expect("runtime root passes launch validation");
    }

    #[test]
    fn public_query_rejects_multiple_statements() {
        let arguments = QueryArgs {
            sql: "select * from public_status_snapshot_v1; delete from watcher_runs".into(),
            limit: 1,
        };
        assert!(validate_query_arguments(&arguments).is_err());
    }

    #[test]
    fn public_query_limit_matches_store_surface() {
        let mut arguments = QueryArgs {
            sql: "select * from public_status_snapshot_v1".into(),
            limit: MAX_PUBLIC_QUERY_ROWS,
        };
        validate_query_arguments(&arguments).expect("store maximum must be accepted");
        arguments.limit = MAX_PUBLIC_QUERY_ROWS + 1;
        assert!(validate_query_arguments(&arguments).is_err());
    }

    #[test]
    fn canonical_config_diff_ignores_toml_formatting_by_construction() {
        let bytes = canonical_json_bytes(&json!({"b": 1, "a": 2})).unwrap();
        assert_eq!(bytes, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn structured_collection_cli_emits_exact_reopenable_v2_ndjson() {
        let outcome = nq_core::CollectionOutcome::admitted(
            "cli.protocol".to_owned(),
            "run-cli-protocol".to_owned(),
            "report-cli-protocol".to_owned(),
            "complete".to_owned(),
            nq_protocol::sha256_bytes(b"cli-protocol-report").into_string(),
            Vec::new(),
        );

        let bytes = collection_outcome_output(&outcome, true)
            .expect("structured CLI output crosses the exact result boundary");
        let reopened = nq_core::decode_collection_outcome_ndjson(&bytes, bytes.len())
            .expect("structured CLI result strictly reopens");
        assert_eq!(reopened, outcome);
        assert_eq!(bytes.last(), Some(&b'\n'));
    }

    #[test]
    fn structured_watcher_error_is_the_exact_governed_refusal() {
        let refusal = GovernedRefusal::helper(
            "refusal-cli".to_owned(),
            Refusal {
                responsible_instance_id: InstanceId::new("cli-transport").expect("instance token"),
                boundary: RefusalBoundary::Collection,
                code: RefusalCode::CollectionFailed,
                message: "backend collection failed".to_owned(),
                retriable: true,
                details: json!({"attempt": 1, "errno": "EAGAIN"}),
            },
        );
        let error = EngineError::GovernedRefusal(Box::new(refusal.clone()));
        let envelope = watcher_action_error_envelope("cli-transport", "test", &error)
            .expect("governed refusal is structured");
        let value = serde_json::to_value(&envelope).expect("envelope serializes");
        assert_eq!(value["schema"], "nq.watcher_action_error.v1");
        assert_eq!(value["instance_id"], "cli-transport");
        assert_eq!(value["action"], "test");
        assert_eq!(value["failure"]["kind"], "governed_refusal");
        assert_eq!(
            value["failure"]["payload"],
            serde_json::to_value(&refusal).expect("refusal serializes")
        );
        assert_eq!(
            canonical_json_bytes(&envelope).expect("structured CLI error canonicalizes"),
            canonical_json_bytes(&value).expect("envelope value canonicalizes")
        );
    }

    #[test]
    fn config_activation_refuses_candidate_mutated_after_validation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let candidate = directory.path().join("candidate.toml");
        let active = directory.path().join("active.toml");
        fs::write(&candidate, config_fixture()).expect("write candidate");
        fs::write(&active, b"previous active bytes\n").expect("write active sentinel");
        let loaded = LoadedConfig::load(&candidate).expect("validate candidate");

        fs::write(&candidate, b"unvalidated = true\n").expect("mutate candidate");
        let error = activate_loaded_config(&loaded, &active)
            .expect_err("changed candidate must not activate");
        assert!(error.to_string().contains("changed after validation"));
        assert_eq!(
            fs::read(&active).expect("read active sentinel"),
            b"previous active bytes\n"
        );
    }

    #[test]
    fn config_activation_refuses_candidate_path_replacement() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let candidate = directory.path().join("candidate.toml");
        let retained = directory.path().join("retained.toml");
        let active = directory.path().join("active.toml");
        fs::write(&candidate, config_fixture()).expect("write candidate");
        fs::write(&active, b"previous active bytes\n").expect("write active sentinel");
        let loaded = LoadedConfig::load(&candidate).expect("validate candidate");

        fs::rename(&candidate, &retained).expect("retain original candidate");
        fs::write(&candidate, config_fixture()).expect("replace candidate inode");
        let error = activate_loaded_config(&loaded, &active)
            .expect_err("replacement candidate must not activate");
        assert!(error.to_string().contains("changed after validation"));
        assert_eq!(
            fs::read(&active).expect("read active sentinel"),
            b"previous active bytes\n"
        );
    }

    #[test]
    fn final_source_race_can_only_install_the_validated_snapshot() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let candidate = directory.path().join("candidate.toml");
        let active = directory.path().join("active.toml");
        fs::write(&candidate, config_fixture()).expect("write candidate");
        let loaded = LoadedConfig::load(&candidate).expect("validate candidate");
        loaded
            .verify_source_unchanged()
            .expect("candidate unchanged at final check");

        // Model replacement in the last possible interval, after the final
        // source check but before the destination rename.
        fs::write(&candidate, b"unvalidated = true\n").expect("race source replacement");
        atomic_activate(loaded.source_bytes(), &active).expect("activate captured bytes");

        assert_eq!(
            fs::read(&active).expect("read active config"),
            config_fixture().as_bytes()
        );
        NqConfig::load(&active).expect("active config remains the validated document");
    }

    #[test]
    fn saved_check_condition_keeps_result_currentness_and_maintenance_separate() {
        let detail = json!({"binding":{
            "definition_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "target_reference":"/removed/disposable-source.sqlite",
            "source_identity":"sqlite:disposable",
            "source_observed_at_assertion":"2026-09-14T12:00:00Z",
            "currentness_seconds":60
        }});
        let binding = retained_saved_check_binding(&detail).expect("exact retained binding");
        let at = chrono::DateTime::parse_from_rfc3339("2026-09-14T12:00:30Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        assert_eq!(retained_result_state("failed"), "failed");
        assert_eq!(
            projection_state(retained_result_state("failed")),
            "available"
        );
        assert_eq!(
            currentness_state(binding.observed_at, at, binding.currentness_seconds),
            "fresh"
        );

        let declaration = MaintenanceDeclaration {
            schema: crate::saved_check::MaintenanceSchema::V1,
            maintenance_id: "maintenance-001".into(),
            declared_by: Some("operator".into()),
            start_at: "2026-09-14T12:00:00Z".into(),
            end_at: "2026-09-14T13:00:00Z".into(),
            component: "queue".into(),
            kind: "backlog".into(),
            subject: Some("local".into()),
            reason: None,
        };
        let annotation = saved_check::maintenance_annotation(
            [(&declaration, binding.observed_at)],
            "queue",
            "backlog",
            "local",
            at,
        )
        .expect("valid declaration")
        .expect("covered declaration");
        assert_eq!(annotation.1, saved_check::MaintenanceAnnotation::Covered);
        // Coverage annotates the caller condition but never rewrites failure.
        assert_eq!(retained_result_state("failed"), "failed");

        let mismatched_definition = SavedCheckDefinition {
            schema: crate::saved_check::SavedCheckSchema::V1,
            reference: "other-reference".into(),
            source_identity: "sqlite:disposable".into(),
            currentness_seconds: 60,
            name: "Other".into(),
            sql_text: "SELECT 1".into(),
            mode: crate::saved_check::SavedCheckMode::Empty,
            threshold: None,
            column: None,
            description: None,
        };
        assert!(!retained_definition_binding_matches(
            "capacity",
            &mismatched_definition,
            &binding,
            binding.definition_digest,
        ));
    }

    #[test]
    fn saved_check_condition_reports_stale_future_pending_and_invalid_material() {
        let detail = json!({"binding":{
            "definition_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "target_reference":"/removed/disposable-source.sqlite",
            "source_identity":"sqlite:disposable",
            "source_observed_at_assertion":"2026-09-14T12:00:00Z",
            "currentness_seconds":60
        }});
        let binding = retained_saved_check_binding(&detail).expect("exact retained binding");
        let stale = chrono::DateTime::parse_from_rfc3339("2026-09-14T12:01:01Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        let future = chrono::DateTime::parse_from_rfc3339("2026-09-14T11:59:59Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        assert_eq!(
            currentness_state(binding.observed_at, stale, binding.currentness_seconds),
            "stale"
        );
        let boundary = chrono::DateTime::parse_from_rfc3339("2026-09-14T12:01:00Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        assert_eq!(
            currentness_state(binding.observed_at, boundary, binding.currentness_seconds),
            "fresh"
        );
        assert_eq!(
            currentness_state(binding.observed_at, future, binding.currentness_seconds),
            "future"
        );
        assert_eq!(retained_result_state("claimed"), "indeterminate");
        assert_eq!(
            projection_state(retained_result_state("claimed")),
            "indeterminate"
        );
        assert_eq!(
            projection_state(retained_result_state("unknown")),
            "refused"
        );
        assert_eq!(
            projection_state(retained_result_state("refused")),
            "refused"
        );
        assert!(retained_saved_check_binding(&json!({"binding":{}})).is_err());
        assert!(
            retained_saved_check_binding(&json!({"binding":{
            "definition_digest":"sha256:definition",
            "target_reference":"/removed/disposable-source.sqlite",
            "source_identity":"sqlite:disposable",
                "source_observed_at_assertion":"2026-09-14T12:00:00Z",
                "currentness_seconds":60
            }}))
            .is_err()
        );
        assert!(retained_saved_check_binding(&json!({"binding":{
            "definition_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "target_reference":"/removed/disposable-source.sqlite",
            "source_identity":"sqlite:disposable",
            "source_observed_at_assertion":"2026-09-14T12:00:00Z",
            "currentness_seconds":4294967296u64
        }})).is_err());
        assert!(retained_saved_check_binding(&json!({"binding":{
            "definition_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "target_reference":"",
            "source_identity":"sqlite:disposable",
            "source_observed_at_assertion":"2026-09-14T12:00:00Z",
            "currentness_seconds":60
        }})).is_err());
        let refusal = saved_check_condition_refusal(
            "absent",
            json!({"mapping_owner":"caller"}),
            "evaluation_missing",
        );
        assert_eq!(refusal["projection_state"], "refused");
        assert_eq!(refusal["maintenance"]["state"], "unavailable");
    }

    #[test]
    fn saved_check_condition_preserves_an_overrun_annotation() {
        let declaration = MaintenanceDeclaration {
            schema: crate::saved_check::MaintenanceSchema::V1,
            maintenance_id: "maintenance-ended".into(),
            declared_by: None,
            start_at: "2026-09-14T10:00:00Z".into(),
            end_at: "2026-09-14T11:00:00Z".into(),
            component: "queue".into(),
            kind: "backlog".into(),
            subject: None,
            reason: None,
        };
        let declared_at = chrono::DateTime::parse_from_rfc3339("2026-09-14T09:00:00Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        let at = chrono::DateTime::parse_from_rfc3339("2026-09-14T12:00:00Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        let annotation = saved_check::maintenance_annotation(
            [(&declaration, declared_at)],
            "queue",
            "backlog",
            "local",
            at,
        )
        .expect("valid declaration")
        .expect("expired matching declaration");
        assert_eq!(annotation.1, saved_check::MaintenanceAnnotation::Overrun);
    }

    #[test]
    fn saved_check_condition_reads_retained_store_material_without_a_source_target() {
        let store = condition_test_store(Some("failed"), false, true, false);
        let at = chrono::DateTime::parse_from_rfc3339("2026-09-14T12:00:30Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        // The target reference retained in the event does not exist. The
        // projection accepts no target path and only reads Store custody.
        let value = saved_check_condition_value(
            &store,
            "evaluation-001",
            "queue",
            "backlog",
            "local",
            "2026-09-14T12:00:30Z",
            at,
        )
        .expect("retained projection");
        assert_eq!(value["projection_state"], "available");
        assert_eq!(value["original_result"]["state"], "failed");
        assert_eq!(value["maintenance"]["state"], "covered");
        assert_eq!(value["definition_identity"]["id"], "definition-001");
        assert_eq!(value["source_assertion"]["state"], "fresh");
    }

    #[test]
    fn saved_check_condition_returns_store_backed_overrun_without_rewriting_failure() {
        let store = condition_test_store(Some("failed"), false, true, true);
        let at = chrono::DateTime::parse_from_rfc3339("2026-09-14T12:00:30Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        let value = saved_check_condition_value(
            &store,
            "evaluation-001",
            "queue",
            "backlog",
            "local",
            "2026-09-14T12:00:30Z",
            at,
        )
        .expect("retained projection");
        assert_eq!(value["original_result"]["state"], "failed");
        assert_eq!(value["maintenance"]["state"], "overrun");
        assert_eq!(value["maintenance"]["maintenance_id"], "maintenance-001");
        assert!(
            value["maintenance"]["declaration_digest"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
    }

    #[test]
    fn saved_check_condition_refuses_missing_or_invalid_store_material_and_keeps_claims_indeterminate()
     {
        let at = chrono::DateTime::parse_from_rfc3339("2026-09-14T14:00:00Z")
            .expect("RFC3339")
            .with_timezone(&chrono::Utc);
        let missing = Store::initialize_in_memory().expect("initialize Store");
        let missing = saved_check_condition_value(
            &missing,
            "absent",
            "queue",
            "backlog",
            "local",
            "2026-09-14T14:00:00Z",
            at,
        )
        .expect("missing projection");
        assert_eq!(missing["projection_state"], "refused");
        assert_eq!(missing["refusal_reason"], "evaluation_missing");

        let claimed = condition_test_store(None, false, false, false);
        let claimed = saved_check_condition_value(
            &claimed,
            "evaluation-001",
            "queue",
            "backlog",
            "local",
            "2026-09-14T14:00:00Z",
            at,
        )
        .expect("claimed projection");
        assert_eq!(claimed["projection_state"], "indeterminate");
        assert_eq!(claimed["original_result"]["state"], "indeterminate");

        let invalid = condition_test_store(Some("failed"), true, false, false);
        let invalid = saved_check_condition_value(
            &invalid,
            "evaluation-001",
            "queue",
            "backlog",
            "local",
            "2026-09-14T14:00:00Z",
            at,
        )
        .expect("invalid retained projection");
        assert_eq!(invalid["projection_state"], "refused");
        assert_eq!(invalid["refusal_reason"], "retained_result_invalid");
    }
}
