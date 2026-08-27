//! Complete operator command surface.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use nix::libc;
use nq_core::config::{LoadedConfig, NqConfig};
use nq_helper_sandbox::{
    IsolationLimits, isolate_command_with_limits, open_runtime_root, require_no_posix_acl,
    resolve_account,
};
use nq_profiles::all_profiles;
use nq_protocol::semantic_digest;
use nq_store::{
    CanonicalDocument, DiagnosticArtifactByteState, DiagnosticArtifactImportDisposition,
    DiagnosticArtifactImportInput, DiagnosticArtifactLookup, DiagnosticArtifactOrigin,
    DiagnosticArtifactSchemaSupport, MAX_PUBLIC_QUERY_ROWS, MAX_STORED_JSON_BYTES, Store,
    UpgradeReceiptInput,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
    /// Manage one finite, policy-bounded recurring diagnostic office.
    Recurring {
        /// Recurring-office workflow.
        #[command(subcommand)]
        command: RecurringCommand,
    },
    /// Manage finite delegated passive-office authority and transactional activation.
    Operating {
        /// Operating-office workflow.
        #[command(subcommand)]
        command: OperatingCommand,
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
    /// Print the exact content-derived watcher semantic identity without admission or collection.
    Digest(InstanceArg),
    /// Execute a bounded dry request without creating admission state.
    Test(InstanceArg),
    /// Conformance-test, dry-collect, and atomically activate a new lock.
    Admit(InstanceArg),
    /// Admit a distinct passive watcher only after consuming an exact H-bound succession edge.
    AdmitSuccessor {
        /// Exact predecessor watcher identity.
        predecessor_instance_id: String,
        /// Exact successor watcher identity.
        successor_instance_id: String,
        /// Finite operating grant containing the closed relation.
        #[arg(long)]
        grant_id: String,
        /// Exact succession relation identity.
        #[arg(long)]
        relation_id: String,
        /// Operating-office append-only ledger.
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        operating_state_dir: PathBuf,
    },
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
    /// Collect, evaluate, and emit one exact supported diagnostic artifact.
    Execute(InstanceArg),
    /// Derive the exact static basis that Standing must sign before invocation.
    ContinuityBasis {
        /// Configured watcher instance.
        instance_id: String,
        /// Standing-signed exact continuity authority JSON.
        #[arg(long)]
        authority: PathBuf,
        /// Caller-preallocated provider-intake/acquisition identity.
        #[arg(long)]
        acquisition_id: String,
        /// Pinned Standing instance identity (raw SHA-256 hex).
        #[arg(long)]
        standing_instance: String,
        /// Pinned Standing audience for this NQ workload identity.
        #[arg(long)]
        nq_audience: String,
        /// Pinned Standing signing-key identity.
        #[arg(long)]
        standing_key_id: String,
        /// File containing the pinned 32-byte Ed25519 public key in hex.
        #[arg(long)]
        standing_public_key: PathBuf,
    },
    /// Execute only after verifying the exact Standing authority/commitment bundle.
    ExecuteContinuity {
        /// Configured watcher instance.
        instance_id: String,
        /// Exact signed Standing acquisition bundle JSON.
        #[arg(long)]
        carrier: PathBuf,
        /// Pinned Standing instance identity (raw SHA-256 hex).
        #[arg(long)]
        standing_instance: String,
        /// Pinned Standing audience for this NQ workload identity.
        #[arg(long)]
        nq_audience: String,
        /// Pinned Standing signing-key identity.
        #[arg(long)]
        standing_key_id: String,
        /// File containing the pinned 32-byte Ed25519 public key in hex.
        #[arg(long)]
        standing_public_key: PathBuf,
    },
    /// Execute one genesis diagnostic under the closed Linode V3 origin profile.
    ExecuteLinodeOrigin {
        /// Configured watcher instance.
        instance_id: String,
        /// Caller-preallocated provider-intake/acquisition identity.
        #[arg(long)]
        acquisition_id: String,
        /// Independently pinned `sha256:` digest of the decimal Linode instance ID.
        #[arg(long)]
        expected_instance_id_sha256: String,
        /// Exact absolute installed Linode origin-helper executable.
        #[arg(long)]
        origin_helper: PathBuf,
        /// Exact `sha256:` digest of the installed origin-helper executable.
        #[arg(long)]
        origin_helper_sha256: String,
        /// Dedicated local execution account for the origin helper.
        #[arg(long)]
        origin_helper_account: String,
        /// File containing the pinned 32-byte helper Ed25519 public key in hex.
        #[arg(long)]
        origin_helper_public_key: PathBuf,
    },
    /// Deliberately acquire one successor diagnostic under the closed Linode V3 profile.
    AcquireNextLinodeOrigin {
        /// Configured watcher instance with prior exact diagnostic history.
        instance_id: String,
        /// Caller-owned deliberate trigger and acquisition occurrence identity.
        #[arg(long)]
        acquisition_id: String,
        /// Independently pinned `sha256:` digest of the decimal Linode instance ID.
        #[arg(long)]
        expected_instance_id_sha256: String,
        /// Exact absolute installed Linode origin-helper executable.
        #[arg(long)]
        origin_helper: PathBuf,
        /// Exact `sha256:` digest of the installed origin-helper executable.
        #[arg(long)]
        origin_helper_sha256: String,
        /// Dedicated local execution account for the origin helper.
        #[arg(long)]
        origin_helper_account: String,
        /// File containing the pinned 32-byte helper Ed25519 public key in hex.
        #[arg(long)]
        origin_helper_public_key: PathBuf,
    },
    /// Replay one completed substrate-origin acquisition without invoking any provider.
    ReplaySubstrateOrigin {
        /// Exact configured watcher instance.
        instance_id: String,
        /// Exact completed acquisition occurrence identity.
        #[arg(long)]
        acquisition_id: String,
    },
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

/// Finite recurring-office operations. `Tick` is a one-shot schedule
/// evaluation, never an internal loop.
#[derive(Debug, Subcommand)]
pub enum RecurringCommand {
    /// Register exact deployment-owned safety-envelope bytes.
    PolicyRegister {
        /// Exact closed deployment safety-envelope JSON.
        policy: PathBuf,
    },
    /// Activate a registered deployment policy for future enrollments/slots.
    PolicyActivate {
        /// Content-derived registered policy identity.
        policy_id: String,
        /// Caller-owned idempotency identity for this activation.
        #[arg(long)]
        operation_id: String,
    },
    /// Materialize one immutable finite operator enrollment.
    Enroll {
        /// Exact immutable enrollment-spec JSON.
        spec: PathBuf,
    },
    /// Evaluate the current deterministic slot exactly once.
    Tick {
        /// Exact finite enrollment to evaluate.
        enrollment_id: String,
    },
    /// Project current state from immutable recurrence records.
    Status {
        /// Exact enrollment whose immutable history is projected.
        enrollment_id: String,
    },
    /// Reconcile one outcome-unknown occurrence from exact retained custody.
    /// This command has no provider or origin-helper source.
    Reconcile {
        /// Exact acquisition occurrence whose fenced result is reopened.
        acquisition_id: String,
    },
    /// Inspect diagnostic and provider-activity uncertainty independently.
    InspectFence {
        /// Exact recurrence acquisition occurrence.
        acquisition_id: String,
    },
    /// Release only an exact provider-activity fence using preexisting local
    /// evidence. This command performs no provider query or diagnostic work.
    ReconcileProvider {
        /// Exact outcome-unknown acquisition occurrence.
        acquisition_id: String,
        /// Exact immutable recurrence enrollment.
        #[arg(long)]
        enrollment_id: String,
        /// Exact deployment-owned coordination domain.
        #[arg(long)]
        coordination_domain: String,
        /// Exact stale-proof fencing epoch held by the occurrence.
        #[arg(long)]
        fencing_epoch: u64,
        /// Exact preexisting provider-activity evidence identity.
        #[arg(long)]
        evidence_id: String,
    },
    /// Pause one enrollment without changing its anchor or history.
    Pause {
        /// Exact enrollment to pause.
        enrollment_id: String,
        /// Caller-owned idempotency identity.
        #[arg(long)]
        operation_id: String,
        /// Bounded operator reason retained in custody.
        #[arg(long)]
        reason: String,
    },
    /// Resume one non-fenced enrollment without changing cadence.
    Resume {
        /// Exact enrollment to resume.
        enrollment_id: String,
        /// Caller-owned idempotency identity.
        #[arg(long)]
        operation_id: String,
        /// Bounded operator reason retained in custody.
        #[arg(long)]
        reason: String,
    },
    /// Revoke future finite slot authority append-only.
    Revoke {
        /// Exact enrollment whose future slot authority is revoked.
        enrollment_id: String,
        /// Caller-owned idempotency identity.
        #[arg(long)]
        operation_id: String,
        /// Bounded operator reason retained in custody.
        #[arg(long)]
        reason: String,
    },
}

/// Finite higher-level operating-grant and activation operations.
#[allow(missing_docs)]
#[derive(Debug, Subcommand)]
pub enum OperatingCommand {
    /// Materialize one finite reviewed operating grant.
    GrantCreate {
        spec: PathBuf,
        #[arg(long)]
        observer_policy: PathBuf,
        #[arg(long)]
        recurrence_policy: PathBuf,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Activate a materialized operating grant; creates no child grant.
    GrantActivate {
        grant_id: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Retire future child issuance without rewriting children.
    GrantRetire {
        grant_id: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Inspect append-only higher-level authority accounting.
    GrantStatus {
        grant_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Bind one ordinary observer generation as an H-authorized child.
    IssueGeneration {
        grant_id: String,
        generation: PathBuf,
        #[arg(long)]
        operation_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Bind one ordinary recurrence enrollment as an H-authorized child.
    IssueEnrollment {
        grant_id: String,
        enrollment_id: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Construct one exact relation candidate; creates no admission or grant authority.
    BuildWatcherSuccession {
        predecessor_instance_id: String,
        successor_instance_id: String,
        #[arg(long)]
        predecessor_provider_config: PathBuf,
        #[arg(long)]
        successor_provider_config: PathBuf,
        #[arg(long)]
        operator_occurrence_id: String,
    },
    /// Consume one predeclared exact watcher succession edge under finite H.
    IssueWatcherSuccession {
        grant_id: String,
        relation: PathBuf,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Persist one exact finite successor-handoff procedure; creates no admission.
    HandoffStage {
        spec: PathBuf,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Evaluate one exact handoff step; waits, refuses, or advances append-only.
    HandoffTick {
        handoff_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Inspect the exact successor-handoff projection.
    HandoffStatus {
        handoff_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Persist an immutable, initially inert activation bundle.
    ActivationStage {
        spec: PathBuf,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Recheck every durable prerequisite without arming timer exposure.
    ActivationValidate {
        activation_id: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Atomically expose the exact finite E only after validation.
    ActivationArm {
        activation_id: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Project activation state and timer exposure.
    ActivationStatus {
        activation_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Disarm first, then append exact closeout facts.
    ActivationClose {
        activation_id: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// Service-manager one-shot: inert before Armed, ordinary recurrence after.
    Tick {
        activation_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
    },
    /// One-shot H gate: project and tick its sole canonically Armed activation.
    TickGrant {
        grant_id: String,
        #[arg(long, default_value = "/var/lib/nq-operating-office")]
        state_dir: PathBuf,
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
        Command::Recurring { command } => recurring_command(&options.config, command, options.json),
        Command::Operating { command } => {
            operating_command(&options.config, command, options.json).await
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
        Command::Query(arguments) => query_command(&options.config, &arguments),
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
        WatcherCommand::Digest(instance) => {
            let config = NqConfig::load(config_path)?;
            let watcher = config
                .watcher(&instance.instance_id)
                .context("watcher is absent from current configuration")?;
            print_value(
                &serde_json::json!({
                    "schema": "nq.watcher_semantic_identity.v1",
                    "instance_id": watcher.instance_id,
                    "watcher_semantic_digest": semantic_digest(watcher)?.to_string(),
                }),
                json_output,
            )
        }
        WatcherCommand::Test(instance) => {
            run_watcher_action(config_path, &instance.instance_id, "test", json_output).await
        }
        WatcherCommand::Admit(instance) => {
            run_watcher_action(config_path, &instance.instance_id, "admit", json_output).await
        }
        WatcherCommand::AdmitSuccessor {
            predecessor_instance_id,
            successor_instance_id,
            grant_id,
            relation_id,
            operating_state_dir,
        } => {
            let config = NqConfig::load(config_path)?;
            let predecessor = config
                .watcher(&predecessor_instance_id)
                .context("predecessor watcher is absent from current configuration")?;
            let successor = config
                .watcher(&successor_instance_id)
                .context("successor watcher is absent from current configuration")?;
            let ledger = crate::operating::OperatingLedger::open(&operating_state_dir)?;
            let relation = ledger.watcher_succession(&grant_id, &relation_id)?;
            if &relation.predecessor != predecessor || &relation.successor != successor {
                bail!("current watcher configurations differ from the exact succession relation");
            }
            if passive_provider_custody(&relation.predecessor_custody.provider_config_path)?
                != relation.predecessor_custody
                || passive_provider_custody(&relation.successor_custody.provider_config_path)?
                    != relation.successor_custody
            {
                bail!("passive provider custody changed after succession relation qualification");
            }
            let predecessor_digest = semantic_digest(predecessor)?.to_string();
            let store = Store::open_read_only(&config.database_path)?;
            let binding = store
                .latest_binding(&predecessor_instance_id)?
                .context("predecessor watcher has no admission binding")?;
            let admission_id = binding
                .admission_id
                .as_deref()
                .context("predecessor watcher binding is not active")?;
            let admission = store
                .admission(admission_id)?
                .context("predecessor admission is absent")?;
            if !matches!(binding.event_kind.as_str(), "activate" | "rollback")
                || admission.instance_id != predecessor_instance_id
                || admission.config_digest != predecessor_digest
            {
                bail!(
                    "predecessor watcher does not hold the exact active admission required by succession"
                );
            }
            drop(ledger);
            run_watcher_action(config_path, &successor_instance_id, "admit", json_output).await
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

#[allow(clippy::too_many_lines)]
async fn diagnostics_command(
    config_path: &Path,
    command: DiagnosticsCommand,
    json_output: bool,
) -> Result<()> {
    match command {
        DiagnosticsCommand::Execute(instance) => {
            diagnostic_execute(config_path, &instance.instance_id).await
        }
        DiagnosticsCommand::ContinuityBasis {
            instance_id,
            authority,
            acquisition_id,
            standing_instance,
            nq_audience,
            standing_key_id,
            standing_public_key,
        } => diagnostic_continuity_basis(
            config_path,
            &instance_id,
            &authority,
            &acquisition_id,
            &standing_instance,
            &nq_audience,
            &standing_key_id,
            &standing_public_key,
            json_output,
        ),
        DiagnosticsCommand::ExecuteContinuity {
            instance_id,
            carrier,
            standing_instance,
            nq_audience,
            standing_key_id,
            standing_public_key,
        } => {
            diagnostic_execute_continuity(
                config_path,
                &instance_id,
                &carrier,
                &standing_instance,
                &nq_audience,
                &standing_key_id,
                &standing_public_key,
            )
            .await
        }
        DiagnosticsCommand::ExecuteLinodeOrigin {
            instance_id,
            acquisition_id,
            expected_instance_id_sha256,
            origin_helper,
            origin_helper_sha256,
            origin_helper_account,
            origin_helper_public_key,
        } => {
            diagnostic_execute_linode_origin(
                config_path,
                &instance_id,
                &acquisition_id,
                &expected_instance_id_sha256,
                &origin_helper,
                &origin_helper_sha256,
                &origin_helper_account,
                &origin_helper_public_key,
            )
            .await
        }
        DiagnosticsCommand::AcquireNextLinodeOrigin {
            instance_id,
            acquisition_id,
            expected_instance_id_sha256,
            origin_helper,
            origin_helper_sha256,
            origin_helper_account,
            origin_helper_public_key,
        } => {
            diagnostic_acquire_next_linode_origin(
                config_path,
                &instance_id,
                &acquisition_id,
                &expected_instance_id_sha256,
                &origin_helper,
                &origin_helper_sha256,
                &origin_helper_account,
                &origin_helper_public_key,
            )
            .await
        }
        DiagnosticsCommand::ReplaySubstrateOrigin {
            instance_id,
            acquisition_id,
        } => diagnostic_replay_substrate_origin(config_path, &instance_id, &acquisition_id),
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

fn recurrence_operator_identity() -> Result<CanonicalDocument> {
    CanonicalDocument::from_serializable(&json!({
        "kind": "local_nq_operator_boundary",
        "uid": nix::unistd::Uid::effective().as_raw(),
        "gid": nix::unistd::Gid::effective().as_raw(),
    }))
    .map_err(Into::into)
}

fn read_exact_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() > MAX_STORED_JSON_BYTES {
        bail!("{} exceeds the bounded JSON limit", path.display());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("cannot decode {}", path.display()))
}

#[allow(clippy::too_many_lines)]
fn recurring_command(
    config_path: &Path,
    command: RecurringCommand,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let now = chrono::Utc::now().timestamp_millis();
    let operator = recurrence_operator_identity()?;
    match command {
        RecurringCommand::PolicyRegister { policy } => {
            let policy: nq_store::recurrence::RecurringOfficePolicyV1 = read_exact_json(&policy)?;
            let mut store = Store::open(&config.database_path)?;
            let policy_id = store.register_recurring_office_policy(&policy, now, &operator)?;
            print_value(
                &json!({"policy_id": policy_id, "registered": true}),
                json_output,
            )
        }
        RecurringCommand::PolicyActivate {
            policy_id,
            operation_id,
        } => {
            let mut store = Store::open(&config.database_path)?;
            let event_id = store.activate_recurring_office_policy(
                &policy_id,
                &operation_id,
                now,
                &operator,
            )?;
            print_value(
                &json!({"policy_id": policy_id, "activation_event_id": event_id}),
                json_output,
            )
        }
        RecurringCommand::Enroll { spec } => {
            let spec: nq_store::recurrence::RecurrenceEnrollmentSpecV1 = read_exact_json(&spec)?;
            let watcher = config
                .watcher(&spec.watcher_instance_id)
                .with_context(|| format!("unknown instance {}", spec.watcher_instance_id))?;
            let watcher_digest = semantic_digest(watcher)?.to_string();
            let mut store = Store::open(&config.database_path)?;
            let policy = store
                .recurring_office_policy(&spec.policy_id)?
                .context("enrollment names an unknown deployment policy")?;
            let enrollment = nq_store::recurrence::RecurrenceEnrollmentV1::new(
                spec,
                &policy,
                &watcher_digest,
                watcher.schedule.deadline_ms,
                now,
            )
            .map_err(|refusal| {
                anyhow::anyhow!(
                    "recurrence enrollment refused [{}]: {}",
                    refusal.code,
                    refusal.detail
                )
            })?;
            let enrollment_id = store.create_recurrence_enrollment(&enrollment, &operator)?;
            print_value(
                &json!({"enrollment": enrollment, "enrollment_id": enrollment_id}),
                true,
            )
        }
        RecurringCommand::Tick { enrollment_id } => {
            recurring_tick(&config, &enrollment_id, now, json_output)
        }
        RecurringCommand::Status { enrollment_id } => {
            let store = Store::open_read_only(&config.database_path)?;
            print_value(
                &serde_json::to_value(store.recurrence_status(&enrollment_id)?)?,
                true,
            )
        }
        RecurringCommand::Reconcile { acquisition_id } => {
            reconcile_outcome_unknown(&config, &acquisition_id, json_output)
        }
        RecurringCommand::InspectFence { acquisition_id } => {
            let store = Store::open_read_only(&config.database_path)?;
            print_value(
                &serde_json::to_value(store.provider_fence_status(&acquisition_id)?)?,
                true,
            )
        }
        RecurringCommand::ReconcileProvider {
            acquisition_id,
            enrollment_id,
            coordination_domain,
            fencing_epoch,
            evidence_id,
        } => reconcile_provider_activity_command(
            &config,
            &acquisition_id,
            &enrollment_id,
            &coordination_domain,
            fencing_epoch,
            &evidence_id,
            now,
            json_output,
        ),
        RecurringCommand::Pause {
            enrollment_id,
            operation_id,
            reason,
        } => recurrence_operator_event(
            &config,
            &enrollment_id,
            "paused_operator",
            &operation_id,
            &reason,
            now,
            &operator,
            json_output,
        ),
        RecurringCommand::Resume {
            enrollment_id,
            operation_id,
            reason,
        } => recurrence_operator_event(
            &config,
            &enrollment_id,
            "resumed_operator",
            &operation_id,
            &reason,
            now,
            &operator,
            json_output,
        ),
        RecurringCommand::Revoke {
            enrollment_id,
            operation_id,
            reason,
        } => recurrence_operator_event(
            &config,
            &enrollment_id,
            "revoked_operator",
            &operation_id,
            &reason,
            now,
            &operator,
            json_output,
        ),
    }
}

fn operating_operator_identity() -> serde_json::Value {
    json!({
        "kind": "local_nq_operator_boundary",
        "uid": nix::unistd::Uid::effective().as_raw(),
        "gid": nix::unistd::Gid::effective().as_raw(),
    })
}

#[allow(clippy::too_many_lines)]
async fn operating_command(
    config_path: &Path,
    command: OperatingCommand,
    json_output: bool,
) -> Result<()> {
    use crate::operating::{OperatingGrantV1, OperatingLedger, TickGateV1};

    let now = chrono::Utc::now().timestamp_millis();
    match command {
        OperatingCommand::GrantCreate {
            spec,
            observer_policy,
            recurrence_policy,
            state_dir,
        } => {
            let spec: crate::operating::OperatingGrantSpecV1 = read_exact_json(&spec)?;
            let observer_policy: nq_passive_load_helper::OperationalPolicyV1 =
                read_exact_json(&observer_policy)?;
            let recurrence_policy: nq_store::recurrence::RecurringOfficePolicyV1 =
                read_exact_json(&recurrence_policy)?;
            let grant = OperatingGrantV1::new(
                spec,
                observer_policy,
                recurrence_policy,
                now,
                operating_operator_identity(),
            )?;
            let ledger = OperatingLedger::open(&state_dir)?;
            let id = ledger.create_grant(&grant)?;
            let persisted = ledger.grant(&id)?;
            print_value(
                &json!({"grant_id": id, "grant": persisted, "authority_created": false}),
                true,
            )
        }
        OperatingCommand::GrantActivate {
            grant_id,
            operation_id,
            state_dir,
        } => {
            let event_id =
                OperatingLedger::open(&state_dir)?.activate_grant(&grant_id, &operation_id, now)?;
            print_value(
                &json!({"grant_id": grant_id, "event_id": event_id, "child_grant_created": false}),
                json_output,
            )
        }
        OperatingCommand::GrantRetire {
            grant_id,
            operation_id,
            reason,
            state_dir,
        } => {
            let event_id = OperatingLedger::open(&state_dir)?.retire_grant(
                &grant_id,
                &operation_id,
                now,
                &reason,
            )?;
            print_value(
                &json!({"grant_id": grant_id, "event_id": event_id, "future_child_issuance": "refused"}),
                json_output,
            )
        }
        OperatingCommand::GrantStatus {
            grant_id,
            state_dir,
        } => print_value(
            &OperatingLedger::open(&state_dir)?.grant_status(&grant_id, now)?,
            true,
        ),
        OperatingCommand::IssueGeneration {
            grant_id,
            generation,
            operation_id,
            state_dir,
        } => {
            let child: nq_passive_load_helper::ObserverGenerationV1 =
                read_exact_canonical_json(&generation)?;
            let child_id = semantic_digest(&child)?.to_string();
            let issuance = OperatingLedger::open(&state_dir)?.issue_generation(
                &grant_id,
                &child,
                &child_id,
                &operation_id,
                now,
            )?;
            print_value(&issuance, true)
        }
        OperatingCommand::IssueEnrollment {
            grant_id,
            enrollment_id,
            operation_id,
            state_dir,
        } => {
            let config = NqConfig::load(config_path)?;
            let enrollment = Store::open_read_only(&config.database_path)?
                .recurrence_enrollment(&enrollment_id)?
                .context("unknown recurrence enrollment")?;
            let issuance = OperatingLedger::open(&state_dir)?.issue_enrollment(
                &grant_id,
                &enrollment,
                &operation_id,
                now,
            )?;
            print_value(&issuance, true)
        }
        OperatingCommand::BuildWatcherSuccession {
            predecessor_instance_id,
            successor_instance_id,
            predecessor_provider_config,
            successor_provider_config,
            operator_occurrence_id,
        } => {
            let config = NqConfig::load(config_path)?;
            let predecessor = config
                .watcher(&predecessor_instance_id)
                .context("unknown predecessor watcher")?
                .clone();
            let successor = config
                .watcher(&successor_instance_id)
                .context("unknown successor watcher")?
                .clone();
            let predecessor_custody = passive_provider_custody(&predecessor_provider_config)?;
            let successor_custody = passive_provider_custody(&successor_provider_config)?;
            let relation = nq_core::PassiveWatcherSuccessionV1::new(
                predecessor,
                successor,
                predecessor_custody,
                successor_custody,
                operator_occurrence_id,
                now,
            )?;
            print_canonical_value(&relation)
        }
        OperatingCommand::IssueWatcherSuccession {
            grant_id,
            relation,
            state_dir,
        } => {
            let relation: nq_core::PassiveWatcherSuccessionV1 =
                read_exact_canonical_json(&relation)?;
            let relation_id = OperatingLedger::open(&state_dir)?
                .issue_watcher_succession(&grant_id, &relation, now)?;
            print_value(
                &json!({"grant_id": grant_id, "relation_id": relation_id,
                    "admission_created": false, "acquisition_authority_created": false}),
                true,
            )
        }
        OperatingCommand::HandoffStage { spec, state_dir } => {
            let spec: crate::operating::SuccessorHandoffSpecV1 = read_exact_json(&spec)?;
            let handoff = OperatingLedger::open(&state_dir)?.stage_successor_handoff(spec, now)?;
            print_value(
                &json!({"handoff": handoff, "admission_created": false,
                    "diagnostic_authority_created": false, "timer_exposure": "inert"}),
                true,
            )
        }
        OperatingCommand::HandoffTick {
            handoff_id,
            state_dir,
        } => successor_handoff_tick(config_path, &state_dir, &handoff_id, now).await,
        OperatingCommand::HandoffStatus {
            handoff_id,
            state_dir,
        } => print_value(
            &OperatingLedger::open(&state_dir)?.handoff_status(&handoff_id)?,
            true,
        ),
        OperatingCommand::ActivationStage { spec, state_dir } => {
            let spec: crate::operating::OfficeActivationSpecV1 = read_exact_json(&spec)?;
            let activation = OperatingLedger::open(&state_dir)?.stage_activation(spec, now)?;
            print_value(
                &json!({"activation": activation, "timer_exposure": "inert", "attempts_consumed": 0}),
                true,
            )
        }
        OperatingCommand::ActivationValidate {
            activation_id,
            operation_id,
            state_dir,
        } => {
            let config = NqConfig::load(config_path)?;
            let ledger = OperatingLedger::open(&state_dir)?;
            let readiness =
                validate_activation_prerequisites(&config, &ledger, &activation_id, now)?;
            let event_id =
                ledger.mark_validated(&activation_id, &operation_id, now, readiness.clone())?;
            print_value(
                &json!({"activation_id": activation_id, "event_id": event_id,
                "state": "validated", "timer_exposure": "inert", "readiness": readiness}),
                true,
            )
        }
        OperatingCommand::ActivationArm {
            activation_id,
            operation_id,
            state_dir,
        } => {
            let config = NqConfig::load(config_path)?;
            let ledger = OperatingLedger::open(&state_dir)?;
            let readiness =
                validate_activation_prerequisites(&config, &ledger, &activation_id, now)?;
            let event_id = ledger.arm(&activation_id, &operation_id, now)?;
            print_value(
                &json!({"activation_id": activation_id, "event_id": event_id,
                "state": "armed", "timer_exposure": "finite_recurrence", "readiness": readiness}),
                true,
            )
        }
        OperatingCommand::ActivationStatus {
            activation_id,
            state_dir,
        } => print_value(
            &OperatingLedger::open(&state_dir)?.activation_status(&activation_id)?,
            true,
        ),
        OperatingCommand::ActivationClose {
            activation_id,
            operation_id,
            reason,
            state_dir,
        } => {
            let event_ids = OperatingLedger::open(&state_dir)?.close_activation(
                &activation_id,
                &operation_id,
                now,
                &reason,
            )?;
            print_value(
                &json!({"activation_id": activation_id, "event_ids": event_ids,
                "state": "closed", "timer_exposure": "inert"}),
                true,
            )
        }
        OperatingCommand::Tick {
            activation_id,
            state_dir,
        } => {
            let config = NqConfig::load(config_path)?;
            let ledger = OperatingLedger::open(&state_dir)?;
            match ledger.tick_gate(&activation_id, now)? {
                inert @ TickGateV1::Inert { .. } => print_value(&inert, true),
                TickGateV1::Exposed { enrollment_id, .. } => {
                    validate_activation_prerequisites(&config, &ledger, &activation_id, now)
                        .context(
                            "armed activation prerequisites drifted; recurrence remains unspent",
                        )?;
                    recurring_tick(&config, &enrollment_id, now, json_output)
                }
            }
        }
        OperatingCommand::TickGrant {
            grant_id,
            state_dir,
        } => {
            let config = NqConfig::load(config_path)?;
            let ledger = OperatingLedger::open(&state_dir)?;
            match ledger.grant_tick_gate(&grant_id, now)? {
                inert @ crate::operating::GrantTickGateV1::Inert { .. } => {
                    print_value(&inert, true)
                }
                crate::operating::GrantTickGateV1::Exposed {
                    activation_id,
                    enrollment_id,
                    ..
                } => {
                    validate_activation_prerequisites(&config, &ledger, &activation_id, now)
                        .context(
                            "H-selected Armed activation prerequisites drifted; recurrence remains unspent",
                        )?;
                    recurring_tick(&config, &enrollment_id, now, json_output)
                }
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn successor_handoff_tick(
    config_path: &Path,
    state_dir: &Path,
    handoff_id: &str,
    now: i64,
) -> Result<()> {
    use crate::operating::{ActivationStateV1, SuccessorHandoffStateV1 as State};

    // One invocation may finish the exact ready sequence, but is bounded and
    // can never walk into another handoff.
    for _ in 0..12 {
        let ledger = crate::operating::OperatingLedger::open(state_dir)?;
        let handoff = ledger.handoff(handoff_id)?;
        let status = ledger.handoff_status(handoff_id)?;
        if status.state.is_terminal() {
            return print_value(&status, true);
        }
        let grant = ledger.grant(&handoff.spec.grant_id)?;
        if now >= grant.spec.expires_at_unix_ms
            && !matches!(
                status.state,
                State::AdmissionStarted | State::GenesisStarted
            )
        {
            ledger.advance_handoff(
                handoff_id,
                State::Expired,
                &format!("handoff:{handoff_id}:h-expired"),
                now,
                json!({"reason": "operating_grant_expired", "timer_exposure": "inert"}),
            )?;
            continue;
        }
        drop(ledger);

        match status.state {
            State::Staged | State::WaitingForSample => {
                let predecessor_state = crate::operating::OperatingLedger::open(state_dir)?
                    .activation_status(&handoff.spec.predecessor_activation_id)?
                    .state;
                if matches!(
                    predecessor_state,
                    ActivationStateV1::Staging | ActivationStateV1::Validated
                ) {
                    return print_value(
                        &json!({
                            "handoff_id": handoff_id,
                            "state": "staged",
                            "timer_exposure": "inert",
                            "attempts_consumed": 0,
                            "reason": "predecessor_activation_not_armed"
                        }),
                        true,
                    );
                }
                if predecessor_state != ActivationStateV1::Armed {
                    bail!(
                        "successor handoff predecessor activation is terminal before this exact handoff"
                    );
                }
                let config = NqConfig::load(config_path)?;
                let watcher = config
                    .watcher(&handoff.spec.successor_watcher_instance_id)
                    .context("successor handoff watcher is absent")?;
                if semantic_digest(watcher)?.as_str()
                    != handoff.spec.successor_watcher_semantic_digest
                {
                    bail!("successor handoff watcher semantics drifted");
                }
                let generation: nq_passive_load_helper::ObserverGenerationV1 =
                    read_exact_canonical_json(&handoff.spec.next_generation_path)?;
                if semantic_digest(&generation)?.as_str() != handoff.spec.next_generation_id {
                    bail!("successor handoff generation bytes were substituted");
                }
                if now < generation.spec.not_before_unix_ms {
                    return print_value(
                        &json!({"handoff_id": handoff_id, "state": "staged",
                            "timer_exposure": "inert", "reason": "next_generation_not_started"}),
                        true,
                    );
                }
                if now >= generation.spec.expires_at_unix_ms {
                    crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                        handoff_id,
                        State::Expired,
                        &format!("handoff:{handoff_id}:g-expired"),
                        now,
                        json!({"reason": "next_generation_expired_without_admission",
                            "timer_exposure": "inert"}),
                    )?;
                    continue;
                }
                let binding = watcher_subject_binding(watcher)?;
                let cutoff = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now)
                    .context("handoff clock is outside chrono range")?;
                let passive = watcher
                    .passive_host_load_sample
                    .as_ref()
                    .context("successor handoff watcher is not passive load")?;
                let activation = crate::operating::OperatingLedger::open(state_dir)?
                    .activation(&handoff.spec.next_activation_id)?;
                let sample = nq_passive_load_helper::eligible_sample_at(
                    &activation.spec.provider_config_path,
                    &binding,
                    cutoff,
                    passive.max_sample_age_ms,
                )?;
                let Some(sample) = sample else {
                    let slot = u64::try_from(now - generation.spec.sampling_anchor_unix_ms)
                        .unwrap_or(0)
                        / generation.spec.sample_interval_ms;
                    crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                        handoff_id,
                        State::WaitingForSample,
                        &format!("handoff:{handoff_id}:sample-slot:{slot}"),
                        now,
                        json!({"sampling_slot": slot, "reason": "no_eligible_successor_sample",
                            "timer_exposure": "inert", "admission_attempted": false}),
                    )?;
                    return print_value(
                        &crate::operating::OperatingLedger::open(state_dir)?
                            .handoff_status(handoff_id)?,
                        true,
                    );
                };
                crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                    handoff_id,
                    State::SampleReady,
                    &format!("handoff:{handoff_id}:sample:{}", sample.payload_digest),
                    now,
                    json!({"sample": sample, "timer_exposure": "inert",
                        "admission_attempted": false}),
                )?;
            }
            State::SampleReady => {
                crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                    handoff_id,
                    State::AdmissionStarted,
                    &format!("handoff:{handoff_id}:admission-started"),
                    now,
                    json!({"expected_admission_id": handoff.spec.expected_admission_id,
                        "timer_exposure": "inert"}),
                )?;
                match execute_preallocated_successor_admission(
                    config_path,
                    &handoff.spec.successor_watcher_instance_id,
                    &handoff.spec.expected_admission_id,
                )
                .await
                {
                    Ok(()) => {
                        crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                            handoff_id,
                            State::AdmissionCompleted,
                            &format!("handoff:{handoff_id}:admission-completed"),
                            chrono::Utc::now().timestamp_millis(),
                            json!({"admission_id": handoff.spec.expected_admission_id,
                                "admission_owner": "ordinary_nq_admission", "timer_exposure": "inert"}),
                        )?;
                    }
                    Err(error) => {
                        let state = if matches!(
                            error.downcast_ref::<nq_core::engine::EngineError>(),
                            Some(
                                nq_core::engine::EngineError::GovernedRefusal(_)
                                    | nq_core::engine::EngineError::AcquisitionFailed(_)
                            )
                        ) {
                            State::AdmissionRefused
                        } else {
                            State::OutcomeUnknown
                        };
                        crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                            handoff_id,
                            state,
                            &format!("handoff:{handoff_id}:admission-terminal"),
                            chrono::Utc::now().timestamp_millis(),
                            json!({"reason": error.to_string(), "human_required": true,
                                "timer_exposure": "inert"}),
                        )?;
                    }
                }
            }
            State::AdmissionStarted => {
                let config = NqConfig::load(config_path)?;
                let store = Store::open_read_only(&config.database_path)?;
                let exact = store
                    .admission(&handoff.spec.expected_admission_id)?
                    .is_some()
                    && store
                        .latest_binding(&handoff.spec.successor_watcher_instance_id)?
                        .and_then(|binding| binding.admission_id)
                        .as_deref()
                        == Some(handoff.spec.expected_admission_id.as_str());
                let next = if exact {
                    State::AdmissionCompleted
                } else {
                    State::OutcomeUnknown
                };
                crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                    handoff_id,
                    next,
                    &format!("handoff:{handoff_id}:admission-reconcile"),
                    now,
                    json!({"admission_id": handoff.spec.expected_admission_id,
                        "exact_custody": exact, "human_required": !exact,
                        "timer_exposure": "inert"}),
                )?;
            }
            State::AdmissionCompleted => {
                crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                    handoff_id,
                    State::GenesisStarted,
                    &format!("handoff:{handoff_id}:genesis-started"),
                    now,
                    json!({"acquisition_id": handoff.spec.genesis_acquisition_id,
                        "timer_exposure": "inert"}),
                )?;
                match execute_handoff_genesis(config_path, &handoff).await {
                    Ok(artifact_id) => {
                        crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                            handoff_id,
                            State::GenesisCompleted,
                            &format!("handoff:{handoff_id}:genesis-completed"),
                            chrono::Utc::now().timestamp_millis(),
                            json!({"acquisition_id": handoff.spec.genesis_acquisition_id,
                                "artifact_id": artifact_id, "timer_exposure": "inert"}),
                        )?;
                    }
                    Err(error) => {
                        let config = NqConfig::load(config_path)?;
                        let store = Store::open_read_only(&config.database_path)?;
                        let started = store
                            .substrate_origin_acquisition_intent_for_intake(
                                &handoff.spec.genesis_acquisition_id,
                            )?
                            .is_some();
                        let next = if started {
                            State::OutcomeUnknown
                        } else {
                            State::GenesisRefused
                        };
                        crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                            handoff_id,
                            next,
                            &format!("handoff:{handoff_id}:genesis-terminal"),
                            chrono::Utc::now().timestamp_millis(),
                            json!({"reason": error.to_string(), "provider_fence_exists": started,
                                "human_required": true, "timer_exposure": "inert"}),
                        )?;
                    }
                }
            }
            State::GenesisStarted => {
                let config = NqConfig::load(config_path)?;
                let store = Store::open_read_only(&config.database_path)?;
                if let Some(intent) = store.substrate_origin_acquisition_intent_for_intake(
                    &handoff.spec.genesis_acquisition_id,
                )? {
                    let phases =
                        store.substrate_origin_acquisition_event_phases(&intent.intent_id)?;
                    let completed = phases
                        .last()
                        .is_some_and(|phase| phase == "provider_intake_completed");
                    crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                        handoff_id,
                        if completed {
                            State::GenesisCompleted
                        } else {
                            State::OutcomeUnknown
                        },
                        &format!("handoff:{handoff_id}:genesis-reconcile"),
                        now,
                        json!({"phases": phases, "exact_intake": completed,
                            "human_required": !completed, "timer_exposure": "inert"}),
                    )?;
                } else if now >= grant.spec.expires_at_unix_ms {
                    crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                        handoff_id,
                        State::Expired,
                        &format!("handoff:{handoff_id}:h-expired-pre-provider"),
                        now,
                        json!({"reason": "operating_grant_expired_before_genesis_provider_intent",
                            "timer_exposure": "inert"}),
                    )?;
                } else {
                    // The engine persists intent before its provider fence. No
                    // intent proves this crash cut remained pre-provider, so
                    // the same exact occurrence may start once.
                    match execute_handoff_genesis(config_path, &handoff).await {
                        Ok(artifact_id) => {
                            crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                                handoff_id,
                                State::GenesisCompleted,
                                &format!("handoff:{handoff_id}:genesis-completed"),
                                chrono::Utc::now().timestamp_millis(),
                                json!({"acquisition_id": handoff.spec.genesis_acquisition_id,
                                    "artifact_id": artifact_id, "resumed_pre_provider": true,
                                    "timer_exposure": "inert"}),
                            )?;
                        }
                        Err(error) => {
                            crate::operating::OperatingLedger::open(state_dir)?.advance_handoff(
                                handoff_id,
                                State::GenesisRefused,
                                &format!("handoff:{handoff_id}:genesis-terminal"),
                                chrono::Utc::now().timestamp_millis(),
                                json!({"reason": error.to_string(), "human_required": true,
                                    "timer_exposure": "inert"}),
                            )?;
                        }
                    }
                }
            }
            State::GenesisCompleted => {
                let config = NqConfig::load(config_path)?;
                let ledger = crate::operating::OperatingLedger::open(state_dir)?;
                let readiness = validate_activation_prerequisites(
                    &config,
                    &ledger,
                    &handoff.spec.next_activation_id,
                    now,
                )?;
                let activation_state = ledger
                    .activation_status(&handoff.spec.next_activation_id)?
                    .state;
                if activation_state == ActivationStateV1::Staging {
                    ledger.mark_validated(
                        &handoff.spec.next_activation_id,
                        &format!("handoff:{handoff_id}:activation-validated"),
                        now,
                        readiness.clone(),
                    )?;
                } else if activation_state != ActivationStateV1::Validated {
                    bail!("successor activation reached an unexpected state before handoff arm");
                }
                ledger.advance_handoff(
                    handoff_id,
                    State::Validated,
                    &format!("handoff:{handoff_id}:validated"),
                    now,
                    readiness,
                )?;
            }
            State::Validated => {
                crate::operating::OperatingLedger::open(state_dir)?.arm_successor_handoff(
                    handoff_id,
                    &format!("handoff:{handoff_id}:arm"),
                    now,
                )?;
            }
            State::Armed
            | State::AdmissionRefused
            | State::GenesisRefused
            | State::OutcomeUnknown
            | State::Expired => unreachable!("terminal state returned above"),
        }
    }
    bail!("successor handoff exceeded its bounded local transition count")
}

fn watcher_subject_binding(
    watcher: &nq_core::WatcherConfig,
) -> Result<nq_protocol::SubjectBinding> {
    Ok(nq_protocol::SubjectBinding {
        subject: nq_protocol::SubjectId::new(watcher.subject.clone())?,
        scope: nq_protocol::ScopeBinding {
            kind: nq_protocol::ScopeKind::new(watcher.scope.kind.clone())?,
            value: watcher.scope.value.clone(),
        },
        vantage: nq_protocol::VantageBinding {
            kind: nq_protocol::VantageKind::new(watcher.vantage.kind.clone())?,
            value: watcher.vantage.value.clone(),
        },
    })
}

async fn execute_preallocated_successor_admission(
    config_path: &Path,
    instance_id: &str,
    admission_id: &str,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown successor watcher {instance_id}"))?
        .clone();
    let admission_id = admission_id.to_owned();
    let expected_admission_id = admission_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.watcher_admit_preallocated(&watcher, &admission_id)
    })
    .await??;
    match outcome {
        nq_core::engine::WatcherActionOutcome::Activated {
            admission_id: actual,
            ..
        } if actual == expected_admission_id => Ok(()),
        _ => bail!("ordinary admission owner returned a substituted outcome"),
    }
}

async fn execute_handoff_genesis(
    config_path: &Path,
    handoff: &crate::operating::SuccessorHandoffV1,
) -> Result<String> {
    let spec = &handoff.spec;
    validate_sha256(&spec.expected_instance_id_sha256)?;
    validate_sha256(&spec.origin_helper_sha256)?;
    validate_origin_helper_executable(&spec.origin_helper_path, &spec.origin_helper_sha256)?;
    let public_key = continuity_verifier(&spec.origin_helper_public_key_path)?;
    let key_id = nq_core::linode_origin_helper_key_id(&public_key);
    let verifier = nq_core::SubstrateOriginVerifierV1::for_linode_instance_metadata(
        nq_core::LINODE_ORIGIN_HELPER_ISSUER_V1.into(),
        key_id,
        nq_protocol::Sha256Digest::parse(spec.expected_instance_id_sha256.clone())?,
        public_key,
    )?;
    let account = resolve_account(&spec.origin_helper_account, false)?;
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(&spec.successor_watcher_instance_id)
        .context("successor handoff watcher is absent")?
        .clone();
    let acquisition_id = spec.genesis_acquisition_id.clone();
    let mut source = IsolatedLinodeOriginSource {
        executable: spec.origin_helper_path.clone(),
        account,
    };
    let artifact = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.diagnostic_execute_with_substrate_origin(
            &watcher,
            &acquisition_id,
            &verifier,
            &mut source,
            None,
        )
    })
    .await??;
    Ok(artifact.artifact_id().0.to_string())
}

#[allow(clippy::too_many_lines)]
fn validate_activation_prerequisites(
    config: &NqConfig,
    ledger: &crate::operating::OperatingLedger,
    activation_id: &str,
    now: i64,
) -> Result<serde_json::Value> {
    use crate::operating::ChildGrantKindV1;
    let activation = ledger.activation(activation_id)?;
    let grant = ledger.grant(&activation.spec.grant_id)?;
    if !ledger.grant_permits_issued_child_runtime(&grant.grant_id, now)? {
        bail!("activation operating grant is not active");
    }
    if !ledger.watcher_digest_is_authorized(
        &grant.grant_id,
        &activation.spec.watcher_instance_id,
        &activation.spec.watcher_semantic_digest,
    )? || activation.spec.passive_provider_boundary_id != grant.spec.passive_provider_boundary_id
        || activation.spec.capacity_context_id != grant.spec.capacity_context_id
    {
        bail!("activation manifest changed H-bound semantics");
    }
    if !ledger.has_child_issuance(
        &grant.grant_id,
        ChildGrantKindV1::ObserverGeneration,
        &activation.spec.generation_id,
    )? || !ledger.has_child_issuance(
        &grant.grant_id,
        ChildGrantKindV1::RecurrenceEnrollment,
        &activation.spec.enrollment_id,
    )? {
        bail!("activation names a G/E child not issued under its exact H");
    }

    let generation: nq_passive_load_helper::ObserverGenerationV1 =
        read_exact_canonical_json(&activation.spec.generation_path)?;
    if semantic_digest(&generation)?.as_str() != activation.spec.generation_id
        || generation.spec.sample_store != activation.spec.sample_store
        || generation.spec.capacity_context_id.as_str() != activation.spec.capacity_context_id
        || now < generation.spec.not_before_unix_ms
        || now >= generation.spec.expires_at_unix_ms
    {
        bail!("activation observer generation is substituted, inactive, or context-drifted");
    }

    let watcher = config
        .watcher(&activation.spec.watcher_instance_id)
        .context("activation watcher is absent from current configuration")?;
    if semantic_digest(watcher)?.as_str() != activation.spec.watcher_semantic_digest {
        bail!("activation watcher semantics drifted");
    }
    let store = Store::open_read_only(&config.database_path)?;
    let enrollment = store
        .recurrence_enrollment(&activation.spec.enrollment_id)?
        .context("activation recurrence enrollment is absent")?;
    if enrollment.spec.watcher_instance_id != activation.spec.watcher_instance_id
        || enrollment.watcher_semantic_digest != activation.spec.watcher_semantic_digest
        || now >= enrollment.spec.expires_at_unix_ms
    {
        bail!("activation recurrence enrollment is inactive or substituted");
    }
    let recurrence_status = store.recurrence_status(&activation.spec.enrollment_id)?;
    if recurrence_status.enrollment_state != "active"
        || !recurrence_status.enrollment_policy_current
    {
        bail!("activation recurrence enrollment is not active under current deployment policy");
    }
    let admission = store
        .admission(&activation.spec.admission_id)?
        .context("activation admission is absent")?;
    let binding = store
        .latest_binding(&activation.spec.watcher_instance_id)?
        .context("activation watcher has no active binding")?;
    if admission.instance_id != activation.spec.watcher_instance_id
        || binding.admission_id.as_deref() != Some(activation.spec.admission_id.as_str())
        || !matches!(binding.event_kind.as_str(), "activate" | "rollback")
    {
        bail!("activation admission is not the current exact watcher binding");
    }
    let genesis = store
        .substrate_origin_acquisition_intent_for_intake(&activation.spec.genesis_acquisition_id)?
        .context("activation genesis acquisition is absent")?;
    let phases = store.substrate_origin_acquisition_event_phases(&genesis.intent_id)?;
    if !phases
        .iter()
        .any(|phase| phase == "provider_intake_completed")
    {
        bail!("activation genesis lacks exact completed provider intake");
    }

    let provider = load_passive_provider_config(&activation.spec.provider_config_path)?;
    if digest_file(&activation.spec.provider_config_path)? != activation.spec.provider_config_digest
        || provider.sample_store != activation.spec.sample_store
        || provider.observer_config_digest.as_str() != activation.spec.generation_id
        || provider.observer_profile != grant.spec.observer_profile
        || provider.observer_artifact_digest.as_str() != grant.spec.observer_artifact_digest
        || provider.capacity_context_id.as_str() != grant.spec.capacity_context_id
    {
        bail!("activation passive selector/provider configuration is substituted");
    }
    validate_sha256(&activation.spec.service_manager_deployment_digest)?;
    if digest_file(&activation.spec.service_manager_deployment_path)?
        != activation.spec.service_manager_deployment_digest
    {
        bail!("activation service-manager deployment bytes are substituted");
    }
    Ok(json!({
        "operating_grant": "ready",
        "observer_generation": "ready",
        "watcher_admission": "ready",
        "genesis": "ready",
        "recurrence_enrollment": "ready",
        "passive_selector": "ready",
        "capacity_context": "ready",
        "sample_store": "ready",
        "service_manager_deployment": "ready"
    }))
}

fn passive_provider_custody(path: &Path) -> Result<nq_core::PassiveProviderCustodyV1> {
    if !path.is_absolute() {
        bail!("passive provider configuration path must be absolute");
    }
    let provider = load_passive_provider_config(path)?;
    Ok(nq_core::PassiveProviderCustodyV1 {
        provider_config_path: path.to_owned(),
        provider_config_digest: digest_file(path)?,
        sample_store: provider.sample_store,
        max_sample_age_ms: provider.max_sample_age_ms,
        observer_profile: provider.observer_profile,
        observer_artifact_digest: provider.observer_artifact_digest.to_string(),
        observer_config_digest: provider.observer_config_digest.to_string(),
        producer_issuer: provider.producer_issuer,
        producer_key_id: provider.producer_key_id,
        producer_public_key_hex: provider.producer_public_key_hex,
        capacity_context_id: provider.capacity_context_id.to_string(),
    })
}

fn load_passive_provider_config(path: &Path) -> Result<nq_passive_load_helper::ProviderConfigV1> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() > MAX_STORED_JSON_BYTES {
        bail!("passive provider configuration exceeds bounded size");
    }
    if path
        .extension()
        .is_some_and(|extension| extension == "toml")
    {
        Ok(toml::from_str(
            std::str::from_utf8(&bytes).context("provider config is not UTF-8")?,
        )?)
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn read_exact_canonical_json<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() > MAX_STORED_JSON_BYTES {
        bail!("{} exceeds bounded JSON limit", path.display());
    }
    let value: T = serde_json::from_slice(&bytes)
        .with_context(|| format!("cannot decode {}", path.display()))?;
    if nq_protocol::canonical_json_bytes(&value)? != bytes {
        bail!("{} is not exact canonical JSON", path.display());
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
fn reconcile_provider_activity_command(
    config: &NqConfig,
    acquisition_id: &str,
    enrollment_id: &str,
    coordination_domain: &str,
    fencing_epoch: u64,
    evidence_id: &str,
    now: i64,
    json_output: bool,
) -> Result<()> {
    let _domain_guard = nq_core::CoordinationDomainGuard::acquire(
        &config.database_path,
        coordination_domain,
        "recurring-reconcile-provider",
    )?;
    let event_id = Store::open(&config.database_path)?.reconcile_provider_activity(
        acquisition_id,
        enrollment_id,
        coordination_domain,
        fencing_epoch,
        evidence_id,
        now,
    )?;
    print_value(
        &json!({
            "outcome": "provider_activity_reconciled",
            "acquisition_id": acquisition_id,
            "enrollment_id": enrollment_id,
            "coordination_domain_id": coordination_domain,
            "fencing_epoch": fencing_epoch,
            "evidence_id": evidence_id,
            "reconciliation_event_id": event_id,
            "diagnostic_outcome": "outcome_unknown",
            "provider_invoked": false,
            "new_acquisition_created": false,
            "operator_resume_required": true
        }),
        json_output,
    )
}

fn reconcile_outcome_unknown(
    config: &NqConfig,
    acquisition_id: &str,
    json_output: bool,
) -> Result<()> {
    let store = Store::open_read_only(&config.database_path)?;
    let acquisition = store
        .recurrence_acquisition(acquisition_id)?
        .context("unknown recurrence acquisition")?;
    let state = store
        .recurrence_acquisition_state(acquisition_id)?
        .context("recurrence acquisition has no state")?;
    if state.event_kind != "outcome_unknown" {
        bail!("only an exact outcome-unknown recurrence acquisition may be reconciled");
    }
    let fencing_epoch = state
        .fencing_epoch
        .context("outcome-unknown recurrence acquisition lacks fencing epoch")?;
    let watcher = config
        .watcher(&acquisition.watcher_instance_id)
        .with_context(|| format!("unknown instance {}", acquisition.watcher_instance_id))?
        .clone();
    let watcher_digest = semantic_digest(&watcher)?.to_string();
    if watcher_digest != acquisition.watcher_semantic_digest {
        bail!("current watcher semantics differ from the fenced acquisition");
    }
    drop(store);
    let _domain_guard = nq_core::CoordinationDomainGuard::acquire(
        &config.database_path,
        &acquisition.coordination_domain_id,
        "recurring-reconcile",
    )?;
    let engine = nq_core::CollectionEngine::open(config)?;
    let artifact = engine.diagnostic_replay_substrate_origin(&watcher, acquisition_id)?;
    drop(engine);
    let reconciled_at = chrono::Utc::now().timestamp_millis();
    Store::open(&config.database_path)?.reconcile_recurrence_from_exact_custody(
        acquisition_id,
        state.attempt_number,
        fencing_epoch,
        artifact.artifact_id().as_digest().as_str(),
        reconciled_at,
    )?;
    print_value(
        &json!({
            "outcome": "reconciled_succeeded",
            "acquisition_id": acquisition_id,
            "artifact_id": artifact.artifact_id().as_digest().as_str(),
            "fencing_epoch": fencing_epoch,
            "provider_invoked": false,
            "operator_resume_required": true
        }),
        json_output,
    )
}

#[allow(clippy::too_many_arguments)]
fn recurrence_operator_event(
    config: &NqConfig,
    enrollment_id: &str,
    kind: &str,
    operation_id: &str,
    reason: &str,
    now: i64,
    operator: &CanonicalDocument,
    json_output: bool,
) -> Result<()> {
    let mut store = Store::open(&config.database_path)?;
    let event_id = store.append_recurrence_enrollment_operator_event(
        enrollment_id,
        kind,
        operation_id,
        now,
        reason,
        operator,
    )?;
    print_value(
        &json!({"enrollment_id": enrollment_id, "event_kind": kind, "event_id": event_id}),
        json_output,
    )
}

#[allow(clippy::too_many_lines)]
fn recurring_tick(
    config: &NqConfig,
    enrollment_id: &str,
    now: i64,
    json_output: bool,
) -> Result<()> {
    let enrollment = Store::open_read_only(&config.database_path)?
        .recurrence_enrollment(enrollment_id)?
        .context("unknown recurrence enrollment")?;
    let watcher = config
        .watcher(&enrollment.spec.watcher_instance_id)
        .with_context(|| format!("unknown instance {}", enrollment.spec.watcher_instance_id))?
        .clone();
    let watcher_digest = semantic_digest(&watcher)?.to_string();
    let _domain_guard = nq_core::CoordinationDomainGuard::acquire(
        &config.database_path,
        &enrollment.coordination_domain_id,
        "recurring-tick",
    )?;
    let plan = Store::open(&config.database_path)?.plan_recurrence_tick(
        enrollment_id,
        &watcher_digest,
        now,
    )?;
    let (acquisition, fencing_epoch, attempt_number, watcher_binding) = match plan {
        nq_store::recurrence::RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            attempt_number,
            watcher_binding,
        } => (acquisition, fencing_epoch, attempt_number, watcher_binding),
        nq_store::recurrence::RecurrenceTickPlanV1::ReconcileRequired { acquisition_id } => {
            return reconcile_recurring_occurrence(
                config,
                &watcher,
                &acquisition_id,
                now,
                json_output,
            );
        }
        other => return print_value(&serde_json::to_value(other)?, true),
    };

    if let Err(error) = enforce_recurrence_storage_guard(&config.database_path, &acquisition) {
        let mut store = Store::open(&config.database_path)?;
        store.record_recurrence_pre_provider_failure(
            &acquisition.acquisition_id,
            attempt_number,
            fencing_epoch,
            now,
            json!({"reason": "storage_guard_refused", "detail": error.to_string()}),
        )?;
        return print_value(
            &json!({"outcome": "pre_provider_refused", "acquisition_id": acquisition.acquisition_id, "reason": "storage_guard_refused"}),
            true,
        );
    }

    let (verifier, mut source) = match prepare_recurring_origin(&watcher_binding) {
        Ok(prepared) => prepared,
        Err(error) => {
            record_recurring_pre_provider_refusal(
                config,
                &acquisition.acquisition_id,
                attempt_number,
                fencing_epoch,
                now,
                &error.to_string(),
            )?;
            return Err(error);
        }
    };
    let fence = nq_store::recurrence::RecurrenceProviderFenceV1 {
        acquisition_id: acquisition.acquisition_id.clone(),
        enrollment_id: acquisition.enrollment_id.clone(),
        policy_id: acquisition.policy_id.clone(),
        coordination_domain_id: acquisition.coordination_domain_id.clone(),
        fencing_epoch,
        attempt_number,
        occurred_at_unix_ms: chrono::Utc::now().timestamp_millis(),
        watcher_instance_id: acquisition.watcher_instance_id.clone(),
        watcher_semantic_digest: acquisition.watcher_semantic_digest.clone(),
        origin_profile: watcher_binding.origin_profile.clone(),
        expected_instance_id_sha256: watcher_binding.expected_instance_id_sha256.clone(),
        origin_helper_issuer: watcher_binding.origin_helper_issuer.clone(),
        origin_helper_key_id: watcher_binding.origin_helper_key_id.clone(),
    };
    let mut engine = nq_core::CollectionEngine::open(config)?;
    let result = engine.diagnostic_acquire_recurring_with_substrate_origin(
        &watcher,
        &acquisition.acquisition_id,
        &verifier,
        &mut source,
        None,
        &fence,
    );
    drop(engine);
    let terminal_at = chrono::Utc::now().timestamp_millis();
    match result {
        Ok(artifact) => {
            Store::open(&config.database_path)?.finish_recurrence_acquisition(
                &acquisition.acquisition_id,
                "provider_succeeded",
                u64::from(attempt_number),
                Some(fencing_epoch),
                terminal_at,
                json!({"artifact_id": artifact.artifact_id().as_digest().as_str()}),
            )?;
            print_value(
                &json!({
                    "outcome": "acquired",
                    "enrollment_id": enrollment_id,
                    "slot": acquisition.slot,
                    "acquisition_id": acquisition.acquisition_id,
                    "artifact_id": artifact.artifact_id().as_digest().as_str(),
                    "fencing_epoch": fencing_epoch,
                    "attempt_number": attempt_number,
                }),
                json_output,
            )
        }
        Err(error) => {
            let mut store = Store::open(&config.database_path)?;
            let state = store
                .recurrence_acquisition_state(&acquisition.acquisition_id)?
                .context("recurrence acquisition state disappeared")?;
            if state.event_kind == "provider_invocation_started" {
                store.finish_recurrence_acquisition(
                    &acquisition.acquisition_id,
                    "outcome_unknown",
                    u64::from(attempt_number),
                    Some(fencing_epoch),
                    terminal_at,
                    json!({"reason": "provider_path_returned_after_fence", "diagnostic": error.to_string()}),
                )?;
            } else {
                store.record_recurrence_pre_provider_failure(
                    &acquisition.acquisition_id,
                    attempt_number,
                    fencing_epoch,
                    terminal_at,
                    json!({"reason": "pre_provider_failure", "diagnostic": error.to_string()}),
                )?;
            }
            Err(error.into())
        }
    }
}

fn prepare_recurring_origin(
    binding: &nq_store::recurrence::WatcherCoordinationBindingV1,
) -> Result<(
    nq_core::SubstrateOriginVerifierV1,
    IsolatedLinodeOriginSource,
)> {
    if binding.origin_profile != nq_store::recurrence::LINODE_ORIGIN_PROFILE_V1 {
        bail!("recurrence deployment binding names unsupported origin profile");
    }
    if binding.origin_helper_issuer != nq_core::LINODE_ORIGIN_HELPER_ISSUER_V1 {
        bail!("recurrence deployment binding substituted the closed origin-helper issuer");
    }
    let helper_path = PathBuf::from(&binding.origin_helper_path);
    validate_origin_helper_executable(&helper_path, &binding.origin_helper_sha256)?;
    let public_key = continuity_verifier(Path::new(&binding.origin_helper_public_key_path))?;
    let key_id = nq_core::linode_origin_helper_key_id(&public_key);
    if key_id != binding.origin_helper_key_id {
        bail!("origin helper key identity differs from deployment policy");
    }
    let verifier = nq_core::SubstrateOriginVerifierV1::for_linode_instance_metadata(
        binding.origin_helper_issuer.clone(),
        key_id,
        nq_protocol::Sha256Digest::parse(binding.expected_instance_id_sha256.clone())?,
        public_key,
    )?;
    let account = resolve_account(&binding.origin_helper_account, false)?;
    Ok((
        verifier,
        IsolatedLinodeOriginSource {
            executable: helper_path,
            account,
        },
    ))
}

fn reconcile_recurring_occurrence(
    config: &NqConfig,
    watcher: &nq_core::WatcherConfig,
    acquisition_id: &str,
    now: i64,
    json_output: bool,
) -> Result<()> {
    let state = Store::open_read_only(&config.database_path)?
        .recurrence_acquisition_state(acquisition_id)?
        .context("recurrence acquisition state disappeared during reconciliation")?;
    if state.event_kind == "outcome_unknown" {
        return print_value(
            &json!({"outcome": "reconcile_required", "acquisition_id": acquisition_id, "reason": "provider_outcome_unknown"}),
            true,
        );
    }
    if state.event_kind != "provider_invocation_started" {
        bail!(
            "recurrence reconciliation reached unexpected state {}",
            state.event_kind
        );
    }
    let epoch = state
        .fencing_epoch
        .context("provider-started occurrence lacks fencing epoch")?;
    let attempt = state.attempt_number;
    let engine = nq_core::CollectionEngine::open(config)?;
    match engine.diagnostic_replay_substrate_origin(watcher, acquisition_id) {
        Ok(artifact) => {
            Store::open(&config.database_path)?.finish_recurrence_acquisition(
                acquisition_id,
                "provider_succeeded",
                attempt,
                Some(epoch),
                now,
                json!({"artifact_id": artifact.artifact_id().as_digest().as_str(), "reconciled_from_exact_custody": true}),
            )?;
            print_value(
                &json!({"outcome": "reconciled_succeeded", "acquisition_id": acquisition_id, "artifact_id": artifact.artifact_id().as_digest().as_str()}),
                json_output,
            )
        }
        Err(error) => {
            Store::open(&config.database_path)?.finish_recurrence_acquisition(
                acquisition_id,
                "outcome_unknown",
                attempt,
                Some(epoch),
                now,
                json!({"reason": "provider_started_without_replayable_exact_result", "diagnostic": error.to_string()}),
            )?;
            print_value(
                &json!({"outcome": "reconcile_required", "acquisition_id": acquisition_id, "reason": "provider_outcome_unknown"}),
                true,
            )
        }
    }
}

fn record_recurring_pre_provider_refusal(
    config: &NqConfig,
    acquisition_id: &str,
    attempt_number: u16,
    fencing_epoch: u64,
    now: i64,
    detail: &str,
) -> Result<()> {
    Store::open(&config.database_path)?.record_recurrence_pre_provider_failure(
        acquisition_id,
        attempt_number,
        fencing_epoch,
        now,
        json!({"reason": "deployment_binding_refused", "detail": detail}),
    )?;
    Ok(())
}

fn enforce_recurrence_storage_guard(
    database_path: &Path,
    acquisition: &nq_store::recurrence::RecurrenceAcquisitionBindingV1,
) -> Result<()> {
    enforce_recurrence_storage_guard_limits(
        database_path,
        acquisition.max_store_bytes,
        acquisition.min_free_bytes,
    )
}

fn enforce_recurrence_storage_guard_limits(
    database_path: &Path,
    max_store_bytes: u64,
    min_free_bytes: u64,
) -> Result<()> {
    let store_bytes = fs::metadata(database_path)?.len();
    if store_bytes > max_store_bytes {
        bail!("durable store is {store_bytes} bytes, above configured maximum {max_store_bytes}");
    }
    let parent = database_path
        .parent()
        .context("recurrence database path has no parent")?;
    let stats = nix::sys::statvfs::statvfs(parent)?;
    let free_bytes = stats
        .blocks_available()
        .saturating_mul(stats.fragment_size());
    if free_bytes < min_free_bytes {
        bail!(
            "durable store filesystem has {free_bytes} free bytes, below configured minimum {min_free_bytes}"
        );
    }
    Ok(())
}

fn diagnostic_qualify(config_path: &Path, artifact_id: &str, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let artifact_id = nq_protocol::Sha256Digest::parse(artifact_id.to_owned())?;
    let store = Store::open_read_only(&config.database_path)?;
    let provenance = nq_core::qualify_diagnostic_admission_supported(&store, &artifact_id)?;
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

fn continuity_verifier(path: &Path) -> Result<ed25519_dalek::VerifyingKey> {
    let bytes = read_bounded_artifact_file(path)?;
    let value = std::str::from_utf8(&bytes).context("Standing public key is not UTF-8")?;
    nq_core::parse_verifying_key(value).map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
fn diagnostic_continuity_basis(
    config_path: &Path,
    instance_id: &str,
    authority_path: &Path,
    acquisition_id: &str,
    standing_instance: &str,
    nq_audience: &str,
    standing_key_id: &str,
    public_key_path: &Path,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?;
    let authority: nq_core::SignedContinuityAuthorityV1 =
        serde_json::from_slice(&read_bounded_artifact_file(authority_path)?)
            .context("decode signed Standing continuity authority")?;
    let verifier = continuity_verifier(public_key_path)?;
    authority.verify_for_watcher(
        watcher,
        standing_instance,
        nq_audience,
        standing_key_id,
        &verifier,
    )?;
    let basis = nq_core::ContinuityAcquisitionBasisV1::for_watcher(
        watcher,
        acquisition_id.to_owned(),
        &authority,
    )?;
    let export = basis.export()?;
    if json_output {
        print_value(&export, true)
    } else {
        std::io::stdout()
            .lock()
            .write_all(&nq_protocol::canonical_json_bytes(&export)?)?;
        Ok(())
    }
}

async fn diagnostic_execute_continuity(
    config_path: &Path,
    instance_id: &str,
    carrier_path: &Path,
    standing_instance: &str,
    nq_audience: &str,
    standing_key_id: &str,
    public_key_path: &Path,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let carrier: nq_core::ContinuityAcquisitionCarrierV1 =
        serde_json::from_slice(&read_bounded_artifact_file(carrier_path)?)
            .context("decode signed Standing continuity acquisition bundle")?;
    let verifier = continuity_verifier(public_key_path)?;
    let verified_carrier = carrier.verify_for_watcher(
        &watcher,
        standing_instance,
        nq_audience,
        standing_key_id,
        &verifier,
    )?;
    let artifact = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.diagnostic_execute_with_continuity(&watcher, &verified_carrier)
    })
    .await??;
    std::io::stdout()
        .lock()
        .write_all(&artifact.canonical_bytes()?)?;
    Ok(())
}

struct IsolatedLinodeOriginSource {
    executable: PathBuf,
    account: nq_helper_sandbox::ExecutionAccount,
}

impl nq_core::SubstrateOriginAttestationSourceV1 for IsolatedLinodeOriginSource {
    fn attest(
        &mut self,
        basis: &nq_core::SubstrateOriginAcquisitionBasisV1,
    ) -> Result<nq_core::SignedSubstrateOriginAttestationV1, String> {
        let mut command = ProcessCommand::new(&self.executable);
        command
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        isolate_command_with_limits(
            &mut command,
            &self.account,
            IsolationLimits {
                address_space_bytes: 256 * 1024 * 1024,
                cpu_seconds: 10,
                processes: 4,
                open_files: 16,
                file_bytes: 0,
            },
        );
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot launch isolated Linode origin helper: {error}"))?;
        let basis_bytes = nq_protocol::canonical_json_bytes(basis)
            .map_err(|error| format!("cannot encode Linode origin basis: {error}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "Linode origin helper stdin is unavailable".to_owned())?
            .write_all(&basis_bytes)
            .map_err(|error| format!("cannot write Linode origin basis: {error}"))?;
        let output = child
            .wait_with_output()
            .map_err(|error| format!("cannot wait for Linode origin helper: {error}"))?;
        if !output.status.success() {
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "Linode origin helper exited {}: {}",
                output.status,
                diagnostic.chars().take(1024).collect::<String>()
            ));
        }
        if !output.stderr.is_empty() || output.stdout.is_empty() || output.stdout.len() > 64 * 1024
        {
            return Err("Linode origin helper emitted an invalid bounded response".into());
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("Linode origin helper response is malformed: {error}"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn diagnostic_execute_linode_origin(
    config_path: &Path,
    instance_id: &str,
    acquisition_id: &str,
    expected_instance_id_sha256: &str,
    helper_executable: &Path,
    helper_sha256: &str,
    helper_account: &str,
    helper_public_key: &Path,
) -> Result<()> {
    diagnostic_run_linode_origin(
        config_path,
        instance_id,
        acquisition_id,
        expected_instance_id_sha256,
        helper_executable,
        helper_sha256,
        helper_account,
        helper_public_key,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn diagnostic_acquire_next_linode_origin(
    config_path: &Path,
    instance_id: &str,
    acquisition_id: &str,
    expected_instance_id_sha256: &str,
    helper_executable: &Path,
    helper_sha256: &str,
    helper_account: &str,
    helper_public_key: &Path,
) -> Result<()> {
    diagnostic_run_linode_origin(
        config_path,
        instance_id,
        acquisition_id,
        expected_instance_id_sha256,
        helper_executable,
        helper_sha256,
        helper_account,
        helper_public_key,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn diagnostic_run_linode_origin(
    config_path: &Path,
    instance_id: &str,
    acquisition_id: &str,
    expected_instance_id_sha256: &str,
    helper_executable: &Path,
    helper_sha256: &str,
    helper_account: &str,
    helper_public_key: &Path,
    successor: bool,
) -> Result<()> {
    validate_sha256(expected_instance_id_sha256)?;
    validate_sha256(helper_sha256)?;
    validate_origin_helper_executable(helper_executable, helper_sha256)?;
    let public_key = continuity_verifier(helper_public_key)?;
    let key_id = nq_core::linode_origin_helper_key_id(&public_key);
    let verifier = nq_core::SubstrateOriginVerifierV1::for_linode_instance_metadata(
        nq_core::LINODE_ORIGIN_HELPER_ISSUER_V1.into(),
        key_id,
        nq_protocol::Sha256Digest::parse(expected_instance_id_sha256.to_owned())?,
        public_key,
    )?;
    let account = resolve_account(helper_account, false)?;
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let acquisition_id = acquisition_id.to_owned();
    let mut source = IsolatedLinodeOriginSource {
        executable: helper_executable.to_path_buf(),
        account,
    };
    let artifact = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        if successor {
            engine.diagnostic_acquire_successor_with_substrate_origin(
                &watcher,
                &acquisition_id,
                &verifier,
                &mut source,
                None,
            )
        } else {
            engine.diagnostic_execute_with_substrate_origin(
                &watcher,
                &acquisition_id,
                &verifier,
                &mut source,
                None,
            )
        }
    })
    .await??;
    std::io::stdout()
        .lock()
        .write_all(&artifact.canonical_bytes()?)?;
    Ok(())
}

fn diagnostic_replay_substrate_origin(
    config_path: &Path,
    instance_id: &str,
    acquisition_id: &str,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let watcher = config
        .watcher(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let engine = nq_core::CollectionEngine::open(&config)?;
    let artifact = engine.diagnostic_replay_substrate_origin(&watcher, acquisition_id)?;
    std::io::stdout()
        .lock()
        .write_all(&artifact.canonical_bytes()?)?;
    Ok(())
}

fn validate_origin_helper_executable(path: &Path, expected_sha256: &str) -> Result<()> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        bail!("Linode origin helper must be an absolute canonical path without symlinks");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        bail!(
            "Linode origin helper must be a root-owned executable regular file with no group/world write bits"
        );
    }
    if digest_file(path)? != expected_sha256 {
        bail!("Linode origin helper digest differs from the independently pinned executable");
    }
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
                        operator_identity,
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
                    let (v5_backup, v5_backup_digest, v6_backup, v6_backup_digest) =
                        upgrade_v5_to_current(
                            &config.database_path,
                            &backup_directory,
                            &binary_digest,
                            &operator_identity,
                        )?;
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
                            "v6_backup": v6_backup,
                            "v6_backup_digest": v6_backup_digest,
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
                    let (v5_backup, v5_backup_digest, v6_backup, v6_backup_digest) =
                        upgrade_v5_to_current(
                            &config.database_path,
                            &backup_directory,
                            &binary_digest,
                            &operator_identity,
                        )?;
                    print_value(
                        &json!({
                            "result": "migrated",
                            "from_schema_version": 4,
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "backup": backup,
                            "backup_digest": artifact.sha256,
                            "v5_backup": v5_backup,
                            "v5_backup_digest": v5_backup_digest,
                            "v6_backup": v6_backup,
                            "v6_backup_digest": v6_backup_digest,
                            "historical_diagnostic_artifacts": "no_durable_commitments",
                        }),
                        json_output,
                    )
                }
                5 => {
                    let (backup, backup_digest, v6_backup, v6_backup_digest) =
                        upgrade_v5_to_current(
                            &config.database_path,
                            &backup_directory,
                            &binary_digest,
                            &operator_identity,
                        )?;
                    print_value(
                        &json!({
                            "result": "migrated",
                            "from_schema_version": 5,
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "backup": backup,
                            "backup_digest": backup_digest,
                            "v6_backup": v6_backup,
                            "v6_backup_digest": v6_backup_digest,
                            "historical_continuity_prerequisites": "absent_not_synthesized",
                        }),
                        json_output,
                    )
                }
                6 => {
                    let (backup, backup_digest) = upgrade_v6_to_current(
                        &config.database_path,
                        &backup_directory,
                        &binary_digest,
                        &operator_identity,
                    )?;
                    print_value(
                        &json!({
                            "result": "migrated",
                            "from_schema_version": 6,
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "backup": backup,
                            "backup_digest": backup_digest,
                            "historical_substrate_origin_proofs": "absent_not_synthesized",
                        }),
                        json_output,
                    )
                }
                7 => {
                    let (backup, backup_digest) = upgrade_v7_to_current(
                        &config.database_path,
                        &backup_directory,
                        &binary_digest,
                        &operator_identity,
                    )?;
                    print_value(
                        &json!({
                            "result": "migrated",
                            "from_schema_version": 7,
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "backup": backup,
                            "backup_digest": backup_digest,
                            "historical_recurrence_enrollments": "absent_not_synthesized",
                            "recurrence_authority_synthesized": false,
                        }),
                        json_output,
                    )
                }
                8 => {
                    let (backup, backup_digest) = upgrade_v8_to_current(
                        &config.database_path,
                        &backup_directory,
                        &binary_digest,
                        &operator_identity,
                    )?;
                    print_value(
                        &json!({
                            "result": "migrated",
                            "from_schema_version": 8,
                            "schema_version": nq_store::SCHEMA_VERSION,
                            "backup": backup,
                            "backup_digest": backup_digest,
                            "historical_provider_activity_evidence": "absent_not_synthesized",
                            "historical_provider_quiescence_synthesized": false,
                            "historical_outcome_unknown_fences_released": false,
                        }),
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

fn upgrade_v5_to_current(
    database_path: &Path,
    backup_directory: &Path,
    binary_digest: &str,
    operator_identity: &CanonicalDocument,
) -> Result<(PathBuf, String, PathBuf, String)> {
    let started_at = chrono::Utc::now();
    let temporary = backup_directory.join(format!(".nq-upgrade-{}.db", uuid::Uuid::new_v4()));
    let artifact = Store::backup_v5_verified(database_path, &temporary)?;
    let backup = finalize_upgrade_backup(&temporary, backup_directory, &artifact.sha256)?;
    let receipt = UpgradeReceiptInput {
        receipt_id: uuid::Uuid::new_v4().to_string(),
        from_schema_version: 5,
        to_schema_version: 6,
        migrations: CanonicalDocument::from_serializable(&[
            "schema_v5_to_v6_continuity_prerequisites",
        ])?,
        binary_digest: binary_digest.to_owned(),
        backup_digest: artifact.sha256.clone(),
        backup_location: backup.display().to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: started_at.to_rfc3339(),
        result: "migrated".into(),
        operator_identity: operator_identity.clone(),
        verification: CanonicalDocument::from_serializable(&json!({
            "integrity": "ok",
            "source_schema_version": 5,
            "source_schema_artifact_digest": nq_store::SCHEMA_V5_ARTIFACT_DIGEST,
            "backup_reopened": true,
            "historical_continuity_prerequisites": "absent_not_synthesized",
            "continuity_intents_synthesized": false,
        }))?,
    };
    drop(Store::upgrade_v5_to_v6(database_path, &receipt)?);
    let (v6_backup, v6_digest) = upgrade_v6_to_current(
        database_path,
        backup_directory,
        binary_digest,
        operator_identity,
    )?;
    Ok((backup, artifact.sha256, v6_backup, v6_digest))
}

fn upgrade_v6_to_current(
    database_path: &Path,
    backup_directory: &Path,
    binary_digest: &str,
    operator_identity: &CanonicalDocument,
) -> Result<(PathBuf, String)> {
    let started_at = chrono::Utc::now();
    let temporary = backup_directory.join(format!(".nq-upgrade-{}.db", uuid::Uuid::new_v4()));
    let artifact = Store::backup_v6_verified(database_path, &temporary)?;
    let backup = finalize_upgrade_backup(&temporary, backup_directory, &artifact.sha256)?;
    let receipt = UpgradeReceiptInput {
        receipt_id: uuid::Uuid::new_v4().to_string(),
        from_schema_version: 6,
        to_schema_version: 7,
        migrations: CanonicalDocument::from_serializable(&["schema_v6_to_v7_substrate_origin"])?,
        binary_digest: binary_digest.to_owned(),
        backup_digest: artifact.sha256.clone(),
        backup_location: backup.display().to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: started_at.to_rfc3339(),
        result: "migrated".into(),
        operator_identity: operator_identity.clone(),
        verification: CanonicalDocument::from_serializable(&json!({
            "integrity": "ok",
            "source_schema_version": 6,
            "source_schema_artifact_digest": nq_store::SCHEMA_V6_ARTIFACT_DIGEST,
            "backup_reopened": true,
            "historical_substrate_origin_proofs": "absent_not_synthesized",
            "substrate_origin_intents_synthesized": false,
        }))?,
    };
    drop(Store::upgrade_v6_to_v7(database_path, &receipt)?);
    let _ = upgrade_v7_to_current(
        database_path,
        backup_directory,
        binary_digest,
        operator_identity,
    )?;
    Ok((backup, artifact.sha256))
}

fn upgrade_v7_to_current(
    database_path: &Path,
    backup_directory: &Path,
    binary_digest: &str,
    operator_identity: &CanonicalDocument,
) -> Result<(PathBuf, String)> {
    let started_at = chrono::Utc::now();
    let temporary = backup_directory.join(format!(".nq-upgrade-{}.db", uuid::Uuid::new_v4()));
    let artifact = Store::backup_incompatible(database_path, &temporary)?;
    let backup = finalize_upgrade_backup(&temporary, backup_directory, &artifact.sha256)?;
    let receipt = UpgradeReceiptInput {
        receipt_id: uuid::Uuid::new_v4().to_string(),
        from_schema_version: 7,
        to_schema_version: 8,
        migrations: CanonicalDocument::from_serializable(&["schema_v7_to_v8_bounded_recurrence"])?,
        binary_digest: binary_digest.to_owned(),
        backup_digest: artifact.sha256.clone(),
        backup_location: backup.display().to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: started_at.to_rfc3339(),
        result: "migrated".into(),
        operator_identity: operator_identity.clone(),
        verification: CanonicalDocument::from_serializable(&json!({
            "integrity": "ok",
            "source_schema_version": 7,
            "source_schema_artifact_digest": nq_store::SCHEMA_V7_ARTIFACT_DIGEST,
            "backup_reopened": true,
            "historical_recurrence_enrollments": "absent_not_synthesized",
            "recurrence_authority_synthesized": false,
        }))?,
    };
    drop(Store::upgrade_v7_to_v8(database_path, &receipt)?);
    let _ = upgrade_v8_to_current(
        database_path,
        backup_directory,
        binary_digest,
        operator_identity,
    )?;
    Ok((backup, artifact.sha256))
}

fn upgrade_v8_to_current(
    database_path: &Path,
    backup_directory: &Path,
    binary_digest: &str,
    operator_identity: &CanonicalDocument,
) -> Result<(PathBuf, String)> {
    let started_at = chrono::Utc::now();
    let temporary = backup_directory.join(format!(".nq-upgrade-{}.db", uuid::Uuid::new_v4()));
    let artifact = Store::backup_incompatible(database_path, &temporary)?;
    let backup = finalize_upgrade_backup(&temporary, backup_directory, &artifact.sha256)?;
    let receipt = UpgradeReceiptInput {
        receipt_id: uuid::Uuid::new_v4().to_string(),
        from_schema_version: 8,
        to_schema_version: 9,
        migrations: CanonicalDocument::from_serializable(&[
            "schema_v8_to_v9_provider_activity_reconciliation",
        ])?,
        binary_digest: binary_digest.to_owned(),
        backup_digest: artifact.sha256.clone(),
        backup_location: backup.display().to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: started_at.to_rfc3339(),
        result: "migrated".into(),
        operator_identity: operator_identity.clone(),
        verification: CanonicalDocument::from_serializable(&json!({
            "integrity": "ok",
            "source_schema_version": 8,
            "source_schema_artifact_digest": nq_store::SCHEMA_V8_ARTIFACT_DIGEST,
            "backup_reopened": true,
            "historical_provider_activity_evidence": "absent_not_synthesized",
            "historical_provider_quiescence_synthesized": false,
            "historical_outcome_unknown_fences_released": false,
        }))?,
    };
    let store = Store::upgrade_v8_to_v9(database_path, &receipt)?;
    store.validate()?;
    Ok((backup, artifact.sha256))
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
    let existing_custody = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(destination)
    {
        Ok(file) => {
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                bail!("active configuration must be one regular file");
            }
            Some((metadata.uid(), metadata.gid(), metadata.mode() & 0o7777))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(validated_bytes)?;
    if let Some((uid, gid, mode)) = existing_custody {
        nix::unistd::fchown(
            temporary.as_file().as_raw_fd(),
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
        .context("cannot preserve active configuration owner and group")?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .context("cannot preserve active configuration mode")?;
    }
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
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.revoke_binding(&watcher)
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

    #[test]
    fn command_tree_exposes_required_operator_workflows() {
        use clap::CommandFactory;
        Nq::command().debug_assert();
    }

    #[test]
    fn passive_succession_surface_is_exact_and_has_no_equivalence_override() {
        let relation = Nq::try_parse_from([
            "nq",
            "operating",
            "build-watcher-succession",
            "watcher-g1",
            "watcher-g2",
            "--predecessor-provider-config",
            "/etc/nq/provider-g1.toml",
            "--successor-provider-config",
            "/etc/nq/provider-g2.toml",
            "--operator-occurrence-id",
            "operator:edge-1",
        ])
        .expect("typed succession builder parses");
        assert!(matches!(
            relation.command,
            Command::Operating {
                command: OperatingCommand::BuildWatcherSuccession { .. }
            }
        ));
        let admission = Nq::try_parse_from([
            "nq",
            "watcher",
            "admit-successor",
            "watcher-g1",
            "watcher-g2",
            "--grant-id",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--relation-id",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .expect("successor admission parses");
        assert!(matches!(
            admission.command,
            Command::Watcher {
                command: WatcherCommand::AdmitSuccessor { .. }
            }
        ));
        assert!(
            Nq::try_parse_from([
                "nq",
                "watcher",
                "admit-successor",
                "watcher-g1",
                "watcher-g2",
                "--grant-id",
                "g",
                "--relation-id",
                "r",
                "--same-enough",
            ])
            .is_err()
        );
    }

    #[test]
    fn recurring_tick_is_explicit_one_shot_enrollment_evaluation() {
        let options = Nq::try_parse_from([
            "nq",
            "--json",
            "recurring",
            "tick",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .expect("recurring tick parses");
        let Command::Recurring {
            command: RecurringCommand::Tick { enrollment_id },
        } = options.command
        else {
            panic!("recurring tick command expected");
        };
        assert!(enrollment_id.starts_with("sha256:"));
    }

    #[test]
    fn recurring_reconciliation_is_exact_custody_only() {
        let options = Nq::try_parse_from([
            "nq",
            "--json",
            "recurring",
            "reconcile",
            "acquisition:outcome-unknown",
        ])
        .expect("exact recurrence reconciliation parses");
        assert!(matches!(
            options.command,
            Command::Recurring {
                command: RecurringCommand::Reconcile { acquisition_id }
            } if acquisition_id == "acquisition:outcome-unknown"
        ));
        assert!(
            Nq::try_parse_from([
                "nq",
                "recurring",
                "reconcile",
                "acquisition:outcome-unknown",
                "--origin-helper",
                "/tmp/not-allowed",
            ])
            .is_err(),
            "reconciliation exposes no origin or provider acquisition surface"
        );
    }

    #[test]
    fn provider_reconciliation_requires_exact_preexisting_evidence_target() {
        let options = Nq::try_parse_from([
            "nq",
            "--json",
            "recurring",
            "reconcile-provider",
            "recurrence:unknown",
            "--enrollment-id",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--coordination-domain",
            "domain:fixture",
            "--fencing-epoch",
            "7",
            "--evidence-id",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .expect("exact provider reconciliation parses");
        assert!(matches!(
            options.command,
            Command::Recurring {
                command: RecurringCommand::ReconcileProvider {
                    acquisition_id,
                    fencing_epoch: 7,
                    ..
                }
            } if acquisition_id == "recurrence:unknown"
        ));
        assert!(
            Nq::try_parse_from([
                "nq",
                "recurring",
                "reconcile-provider",
                "recurrence:unknown",
                "--force",
            ])
            .is_err(),
            "provider reconciliation exposes no operator override flag"
        );
    }

    #[test]
    fn recurrence_storage_guard_refuses_both_store_growth_and_free_space_pressure() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        fs::write(&database, [0_u8; 32]).expect("write bounded fixture");

        let size_error = enforce_recurrence_storage_guard_limits(&database, 31, 1)
            .expect_err("oversized store must refuse before provider");
        assert!(size_error.to_string().contains("above configured maximum"));

        let free_error = enforce_recurrence_storage_guard_limits(&database, u64::MAX, u64::MAX)
            .expect_err("free-space floor must refuse before provider");
        assert!(free_error.to_string().contains("below configured minimum"));
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
    fn linode_origin_execution_requires_exact_closed_inputs() {
        let options = Nq::try_parse_from([
            "nq",
            "diagnostics",
            "execute-linode-origin",
            "labelwatch-host-local",
            "--acquisition-id",
            "acquisition:fixture",
            "--expected-instance-id-sha256",
            &format!("sha256:{}", "a".repeat(64)),
            "--origin-helper",
            "/opt/nq-ng/bin/nq-linode-origin-helper",
            "--origin-helper-sha256",
            &format!("sha256:{}", "b".repeat(64)),
            "--origin-helper-account",
            "nq-origin-helper",
            "--origin-helper-public-key",
            "/etc/nq/origin-helper-public-key.hex",
        ])
        .expect("closed Linode origin execution parses");
        assert!(matches!(
            options.command,
            Command::Diagnostics {
                command: DiagnosticsCommand::ExecuteLinodeOrigin { .. }
            }
        ));
        assert!(
            Nq::try_parse_from([
                "nq",
                "diagnostics",
                "execute-linode-origin",
                "labelwatch-host-local",
                "--url",
                "http://example.invalid",
            ])
            .is_err(),
            "the closed origin path has no caller-selected URL"
        );
    }

    #[test]
    fn successor_acquisition_and_replay_are_distinct_closed_commands() {
        let coordinate = format!("sha256:{}", "a".repeat(64));
        let helper = format!("sha256:{}", "b".repeat(64));
        let successor = Nq::try_parse_from([
            "nq",
            "diagnostics",
            "acquire-next-linode-origin",
            "labelwatch-host-local",
            "--acquisition-id",
            "acquisition:successor-2",
            "--expected-instance-id-sha256",
            coordinate.as_str(),
            "--origin-helper",
            "/opt/nq-ng/bin/nq-linode-origin-helper",
            "--origin-helper-sha256",
            helper.as_str(),
            "--origin-helper-account",
            "nq-origin-helper",
            "--origin-helper-public-key",
            "/etc/nq/origin-helper-public-key.hex",
        ])
        .expect("explicit successor acquisition parses");
        assert!(matches!(
            successor.command,
            Command::Diagnostics {
                command: DiagnosticsCommand::AcquireNextLinodeOrigin { .. }
            }
        ));

        let replay = Nq::try_parse_from([
            "nq",
            "diagnostics",
            "replay-substrate-origin",
            "labelwatch-host-local",
            "--acquisition-id",
            "acquisition:successor-2",
        ])
        .expect("explicit read-only replay parses");
        assert!(matches!(
            replay.command,
            Command::Diagnostics {
                command: DiagnosticsCommand::ReplaySubstrateOrigin { .. }
            }
        ));
        assert!(
            Nq::try_parse_from([
                "nq",
                "diagnostics",
                "replay-substrate-origin",
                "labelwatch-host-local",
                "--acquisition-id",
                "acquisition:successor-2",
                "--origin-helper",
                "/tmp/not-allowed",
            ])
            .is_err(),
            "replay has no producer or origin-helper surface"
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
    fn config_activation_preserves_existing_owner_group_and_mode() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let candidate = directory.path().join("candidate.toml");
        let active = directory.path().join("active.toml");
        fs::write(&candidate, config_fixture()).expect("write candidate");
        fs::write(&active, b"previous active bytes\n").expect("write active sentinel");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o640))
            .expect("set governed active mode");
        let before = fs::metadata(&active).expect("active metadata before");
        let loaded = LoadedConfig::load(&candidate).expect("validate candidate");

        activate_loaded_config(&loaded, &active).expect("activate validated candidate");

        let after = fs::metadata(&active).expect("active metadata after");
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
        assert_eq!(after.mode() & 0o7777, 0o640);
        assert_eq!(
            fs::read(&active).expect("read active config"),
            config_fixture().as_bytes()
        );
    }
}
