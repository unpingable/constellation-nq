//! Complete operator command surface.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use nix::libc;
use nq_core::config::{LoadedConfig, NqConfig};
use nq_helper_sandbox::{open_runtime_root, require_no_posix_acl};
use nq_profiles::all_profiles;
use nq_protocol::semantic_digest;
use nq_store::{CanonicalDocument, MAX_PUBLIC_QUERY_ROWS, Store, UpgradeReceiptInput};
use serde::Serialize;
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
    /// Test and manage witness admissions.
    Witness {
        /// Witness workflow.
        #[command(subcommand)]
        command: WitnessCommand,
    },
    /// Run one explicitly requested collection (never triggered by a read).
    Collect(InstanceArg),
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

/// Witness admission operations.
#[derive(Debug, Subcommand)]
pub enum WitnessCommand {
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
    /// Export `nq.finding_snapshot.v2` records.
    Export {
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
    },
}

/// Status commands.
#[derive(Debug, Subcommand)]
pub enum StatusCommand {
    /// Export `nq.status_snapshot.v1`.
    Export,
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
        Command::Witness { command } => {
            witness_command(&options.config, command, options.json).await
        }
        Command::Collect(instance) => {
            collect_command(&options.config, &instance.instance_id, options.json).await
        }
        Command::Doctor => doctor(&options.config, options.json),
        Command::Backup(arguments) => backup(&options.config, &arguments.destination, options.json),
        Command::Restore(arguments) => {
            restore(&arguments.backup, &arguments.destination, options.json)
        }
        Command::Admin { command } => admin_command(&options.config, command, options.json),
        Command::Findings { command } => findings_command(&options.config, &command),
        Command::Status { command } => status_command(&options.config, &command),
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

async fn witness_command(
    config_path: &Path,
    command: WitnessCommand,
    json_output: bool,
) -> Result<()> {
    match command {
        WitnessCommand::Test(instance) => {
            run_witness_action(config_path, &instance.instance_id, "test", json_output).await
        }
        WitnessCommand::Admit(instance) => {
            run_witness_action(config_path, &instance.instance_id, "admit", json_output).await
        }
        WitnessCommand::Rotate(instance) => {
            run_witness_action(config_path, &instance.instance_id, "rotate", json_output).await
        }
        WitnessCommand::Rollback { instance_id, lock } => {
            rollback(config_path, &instance_id, &lock, json_output).await
        }
        WitnessCommand::Revoke(instance) => {
            revoke(config_path, &instance.instance_id, json_output).await
        }
    }
}

async fn collect_command(config_path: &Path, instance_id: &str, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let witness = config
        .witness(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.collect(&witness)
    })
    .await??;
    let successful = result.is_success();
    print_value(&result, json_output)?;
    if successful {
        Ok(())
    } else {
        bail!("collection did not produce a complete or partial admitted report")
    }
}

fn doctor(config_path: &Path, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    validate_compiled_profiles(&config)?;
    let store = Store::open(&config.database_path)?;
    store.validate()?;
    let mut diagnostics = Vec::new();
    for witness in &config.witnesses {
        let lock_path = config
            .admissions_dir
            .join(format!("{}.json", witness.instance_id));
        let profile = nq_profiles::resolve_profile(&witness.profile.id, witness.profile.version)
            .expect("validated profile");
        let profile_digest = profile.descriptor().digest()?;
        let outcome = nq_core::AdmissionManager.load(&lock_path).and_then(|lock| {
            nq_core::AdmissionManager.verify(
                witness,
                &lock,
                profile_digest.as_str(),
                nq_protocol::HELPER_PROTOCOL_VERSION,
            )
        });
        diagnostics.push(match outcome {
            Ok(verification) => json!({
                "instance_id": witness.instance_id,
                "state": "healthy",
                "binding_digest": verification.binding_digest,
            }),
            Err(error) => json!({
                "instance_id": witness.instance_id,
                "state": "failed",
                "diagnostic": error.to_string(),
            }),
        });
    }
    let healthy = diagnostics.iter().all(|value| value["state"] == "healthy");
    print_value(
        &json!({
            "healthy": healthy,
            "database": "healthy",
            "profiles": all_profiles().len(),
            "instances": diagnostics,
        }),
        json_output,
    )?;
    if healthy {
        Ok(())
    } else {
        bail!("doctor found one or more failed instances")
    }
}

fn backup(config_path: &Path, destination: &Path, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let store = Store::open(&config.database_path)?;
    store.validate()?;
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
    let digest = digest_file(destination)?;
    print_value(
        &json!({"backup": destination, "sha256": digest, "verified": true}),
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
    let source = Store::open(backup)?;
    source.validate()?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    // Restore through SQLite's backup API so a verified source with live WAL
    // pages is copied as one consistent logical database without loading the
    // artifact into memory or copying a stale main file alone.
    store_backup_if_supported(&source, destination)?;
    Store::open(destination)?.validate()?;
    print_value(
        &json!({
            "restored": true,
            "destination": destination,
            "sha256": digest_file(destination)?,
        }),
        json_output,
    )
}

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
            let mut store = Store::open(&config.database_path)?;
            store.validate()?;
            let source_digest = digest_file(&config.database_path)?;
            let temporary_backup =
                backup_directory.join(format!(".nq-upgrade-{}.db", uuid::Uuid::new_v4()));
            store_backup_if_supported(&store, &temporary_backup)?;
            Store::open(&temporary_backup)?.validate()?;
            let backup_digest = digest_file(&temporary_backup)?;
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
                fs::remove_file(&temporary_backup)?;
            } else {
                fs::rename(&temporary_backup, &backup)?;
                File::open(&backup_directory)?.sync_all()?;
            }
            Store::open(&backup)?.validate()?;
            let binary_digest = digest_file(&std::env::current_exe()?)?;
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
                operator_identity: CanonicalDocument::from_serializable(&json!({
                    "uid": nix::unistd::Uid::effective().as_raw(),
                    "gid": nix::unistd::Gid::effective().as_raw(),
                }))?,
                verification: CanonicalDocument::from_serializable(&json!({
                    "integrity": "ok",
                    "schema_version": nq_store::SCHEMA_VERSION,
                    "source_digest": source_digest,
                }))?,
            })?;
            // v1 has no preceding migration. Still perform all safety checks and
            // return an explicit no-op receipt rather than silently starting.
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
    }
}

fn findings_command(config_path: &Path, command: &FindingsCommand) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let store = Store::open(&config.database_path)?;
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
    let store = Store::open(&config.database_path)?;
    match command {
        StatusCommand::Export => print_value(&status_snapshot_if_supported(&store)?, true),
    }
}

fn query_command(config_path: &Path, arguments: &QueryArgs) -> Result<()> {
    validate_query_arguments(arguments)?;
    let config = NqConfig::load(config_path)?;
    let store = Store::open(&config.database_path)?;
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

fn list_findings_if_supported(store: &Store) -> Result<Vec<nq_core::FindingSnapshotV2>> {
    Ok(nq_core::engine::list_findings(store)?)
}

fn status_snapshot_if_supported(store: &Store) -> Result<nq_core::StatusSnapshotV1> {
    Ok(nq_core::engine::status_snapshot(store)?)
}

fn public_query_if_supported(
    store: &Store,
    sql: &str,
    limit: u32,
) -> Result<Vec<serde_json::Value>> {
    Ok(nq_core::engine::public_query(store, sql, limit)?)
}

async fn run_witness_action(
    config_path: &Path,
    instance_id: &str,
    action: &str,
    json_output: bool,
) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let witness = config
        .witness(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let action = action.to_owned();
    let result = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.witness_action(&witness, &action)
    })
    .await??;
    print_value(&result, json_output)
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
    let witness = config
        .witness(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let historical = historical.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.rollback_binding(&witness, &historical)
    })
    .await??;
    print_value(&outcome, json_output)
}

async fn revoke(config_path: &Path, instance_id: &str, json_output: bool) -> Result<()> {
    let config = NqConfig::load(config_path)?;
    let witness = config
        .witness(instance_id)
        .with_context(|| format!("unknown instance {instance_id}"))?
        .clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut engine = nq_core::CollectionEngine::open(&config)?;
        engine.revoke_binding(&witness)
    })
    .await??;
    print_value(&outcome, json_output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_protocol::canonical_json_bytes;

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
            sql: "select * from public_status_snapshot_v1; delete from witness_runs".into(),
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
}
