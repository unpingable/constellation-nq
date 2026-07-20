//! Sealed cold archive — the beta-1 lineage obligation.
//!
//! An archive preserves enough material to verify a historical nq-ng system
//! independently of the live installation: the evidence database (WAL-consistent
//! backup), the exact verifier binary, interpretation config, schema identity,
//! canonical manifests, and per-file plus archive-level digests. It is a plain
//! inspectable directory, not an opaque or encrypted blob.
//!
//! Verification confirms historical integrity; it establishes no current
//! standing and no executable admission. Replay of history cannot mint present
//! authority (the beta-1 historical-admission guarantee).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nq_core::config::NqConfig;
use nq_store::Store;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Archive format identity. A verifier that does not recognize this refuses.
pub const ARCHIVE_FORMAT: &str = "nq.cold_archive.v1";

const SEAL_FILE: &str = "SEAL";
const ARCHIVE_FILE: &str = "ARCHIVE.json";
const MANIFEST_FILE: &str = "MANIFEST.sha256";
/// Content files covered by the manifest, in canonical order.
const CONTENT_FILES: &[&str] = &["VERIFY.md", "bin/nq", "config/nq.toml", "db/nq.db"];

/// Archive-level metadata. `SEAL` binds these exact bytes; `manifest_sha256`
/// binds `MANIFEST.sha256`, which binds every content file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveMetadata {
    archive_format: String,
    created_at: String,
    tool_version: String,
    tool_binary_digest: String,
    /// Exact store schema version supported by the sealed verifier binary.
    schema_version: i64,
    /// Digest of the exact schema artifact supported by the sealed verifier.
    schema_artifact_digest: String,
    /// Whether the source database opened and validated as a current store. When
    /// false, the database was preserved but its historical meaning cannot be
    /// verified by this format — that claim fails closed.
    source_openable: bool,
    manifest_sha256: String,
}

/// Outcome of a successful archive creation.
#[derive(Debug, Serialize)]
pub struct ArchiveReport {
    /// The sealed archive directory.
    pub archive: PathBuf,
    /// Archive format identity.
    pub archive_format: String,
    /// Whether the source database validated as a current store.
    pub source_openable: bool,
    /// The archive seal (digest of the sealed metadata).
    pub seal: String,
}

/// Outcome of archive verification. Carries integrity facts only; never standing.
#[derive(Debug, Serialize)]
pub struct VerifyReport {
    /// The verified archive directory.
    pub archive: PathBuf,
    /// Archive format identity.
    pub archive_format: String,
    /// Whether the seal, manifest, per-file, and file-set checks all held.
    pub integrity_verified: bool,
    /// Whether the preserved database opened and validated under this verifier.
    /// `None` when the archive records the source as un-openable (fails closed).
    pub historical_database_verified: Option<bool>,
    /// Whether every immutable status event reopened through the versioned,
    /// typed collection-result reader. `None` when history is un-openable.
    pub historical_status_semantics_verified: Option<bool>,
    /// Exact number of immutable status events reopened by the typed verifier.
    pub historical_status_events_verified: Option<usize>,
    /// Whether every rejected-custody row reopened through the versioned, typed
    /// refusal reader. `None` when history is un-openable.
    pub historical_rejected_custody_semantics_verified: Option<bool>,
    /// Exact number of immutable rejected-custody rows reopened by the typed
    /// verifier.
    pub historical_rejected_custody_records_verified: Option<usize>,
    /// Whether every immutable evaluation and any linked finding refusal
    /// reopened through the typed historical verifier.
    pub historical_evaluation_refusal_semantics_verified: Option<bool>,
    /// Exact number of immutable evaluation rows checked together with their
    /// finding/refusal linkage.
    pub historical_evaluation_records_verified: Option<usize>,
    /// Always false: verification confirms history, it grants nothing.
    pub grants_authority: bool,
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn require_physical_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_dir() {
        bail!("{label} is not a physical directory");
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file() {
        bail!("{label} is not a regular file");
    }
    Ok(metadata)
}

/// A `sha256sum --check`-compatible manifest over the content files (two spaces,
/// hex digest without the `sha256:` prefix, path relative to the archive root).
fn write_manifest(root: &Path) -> Result<()> {
    use std::fmt::Write;
    let mut lines = String::new();
    for relative in CONTENT_FILES {
        let digest = sha256_file(&root.join(relative))?;
        let hex = digest.strip_prefix("sha256:").context("qualified digest")?;
        writeln!(lines, "{hex}  {relative}").expect("write to string is infallible");
    }
    fs::write(root.join(MANIFEST_FILE), lines)?;
    Ok(())
}

/// Verify the manifest lines against the on-disk content files. Returns the set
/// of relative paths the manifest claims to cover.
fn check_manifest(root: &Path) -> Result<Vec<String>> {
    let manifest = fs::read_to_string(root.join(MANIFEST_FILE)).context("read manifest")?;
    let mut covered = Vec::new();
    for (index, line) in manifest.lines().enumerate() {
        let (hex, relative) = line
            .split_once("  ")
            .with_context(|| format!("malformed manifest line: {line}"))?;
        let expected = CONTENT_FILES
            .get(index)
            .with_context(|| format!("manifest contains unexpected content entry {relative}"))?;
        if relative != *expected {
            bail!(
                "manifest content entry {index} is {relative}, required exact entry is {expected}"
            );
        }
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("manifest references a missing file: {relative}"))?;
        if !metadata.file_type().is_file() {
            bail!("manifest content is not a regular file: {relative}");
        }
        let actual = sha256_file(&path)?;
        if actual != format!("sha256:{hex}") {
            bail!("content file {relative} does not match its manifest digest");
        }
        covered.push(relative.to_owned());
    }
    if covered.len() != CONTENT_FILES.len() {
        bail!(
            "manifest covers {} content files, required exact coverage is {}",
            covered.len(),
            CONTENT_FILES.len()
        );
    }
    Ok(covered)
}

/// Create a sealed cold archive of the configured live store.
///
/// # Errors
///
/// Returns an error if the destination exists, the configuration or store
/// cannot be read, or the archive cannot be staged and sealed.
pub fn create_archive(config_path: &Path, destination: &Path) -> Result<ArchiveReport> {
    if destination.exists() {
        bail!(
            "archive destination already exists: {}",
            destination.display()
        );
    }
    let config = NqConfig::load(config_path)?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    fs::create_dir_all(&parent)?;

    // Build in a sibling temp directory so the final rename is atomic on the
    // same filesystem; a failure before the rename leaves no sealed result.
    let staging = parent.join(format!(".nq-archive-{}.partial", uuid::Uuid::new_v4()));
    let result = build_staging(&config, config_path, &staging);
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    let report = result?;
    // The atomic seal: only now does the destination exist.
    fs::rename(&staging, destination).context("seal archive by atomic rename")?;
    if let Ok(dir) = fs::File::open(&parent) {
        let _ = dir.sync_all();
    }
    Ok(ArchiveReport {
        archive: destination.to_path_buf(),
        ..report
    })
}

fn build_staging(config: &NqConfig, config_path: &Path, staging: &Path) -> Result<ArchiveReport> {
    fs::create_dir(staging)?;
    fs::create_dir(staging.join("db"))?;
    fs::create_dir(staging.join("bin"))?;
    fs::create_dir(staging.join("config"))?;

    // The evidence database, WAL-consistent. A live store that validates is
    // backed up verified; one that open() refuses is still preserved, but its
    // historical meaning is not verifiable under this format.
    let db = staging.join("db/nq.db");
    let source_openable = if let Ok(store) = Store::open(&config.database_path) {
        store.backup_verified(&db)?;
        let archived_copy = Store::open(&db).context("open archive database backup for freeze")?;
        archived_copy
            .prepare_archive_copy()
            .context("checkpoint and freeze archive database before sealing")?;
        drop(archived_copy);
        true
    } else {
        Store::backup_incompatible(&config.database_path, &db)?;
        false
    };

    // The exact verifier binary and interpretation config.
    let binary = std::env::current_exe()?;
    let archived_binary = staging.join("bin/nq");
    fs::copy(&binary, &archived_binary)?;
    fs::set_permissions(&archived_binary, fs::Permissions::from_mode(0o755))?;
    fs::copy(config_path, staging.join("config/nq.toml")).context("copy interpretation config")?;
    fs::write(staging.join("VERIFY.md"), verify_instructions())?;

    write_manifest(staging)?;
    let manifest_sha256 = sha256_file(&staging.join(MANIFEST_FILE))?;

    let metadata = ArchiveMetadata {
        archive_format: ARCHIVE_FORMAT.to_owned(),
        created_at: chrono::Utc::now().to_rfc3339(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        tool_binary_digest: sha256_file(&binary)?,
        schema_version: nq_store::SCHEMA_VERSION,
        schema_artifact_digest: nq_store::schema_artifact_digest(),
        source_openable,
        manifest_sha256,
    };
    let metadata_bytes = serde_json::to_vec_pretty(&metadata)?;
    fs::write(staging.join(ARCHIVE_FILE), &metadata_bytes)?;

    // The seal binds ARCHIVE.json, which binds the manifest, which binds content.
    let seal = sha256_bytes(&metadata_bytes);
    fs::write(staging.join(SEAL_FILE), &seal)?;

    // Re-verify the fully staged archive before it can be sealed.
    let verified = verify_archive(staging)?;
    if !verified.integrity_verified {
        bail!("freshly staged archive failed its own integrity check");
    }
    Ok(ArchiveReport {
        archive: staging.to_path_buf(),
        archive_format: ARCHIVE_FORMAT.to_owned(),
        source_openable,
        seal,
    })
}

/// Verify a cold archive using only its own contents. Never opens the live store
/// and never mints authority.
///
/// # Errors
///
/// Returns an error if the archive metadata, seal, manifest, per-file digests,
/// file set, or (when the source was openable) the preserved database fail to
/// verify, or if the archive format is unrecognized.
#[allow(clippy::too_many_lines)]
pub fn verify_archive(archive: &Path) -> Result<VerifyReport> {
    require_physical_directory(archive, "archive root")?;
    for control in [ARCHIVE_FILE, SEAL_FILE, MANIFEST_FILE] {
        require_regular_file(&archive.join(control), control)?;
    }
    for directory in ["db", "bin", "config"] {
        require_physical_directory(&archive.join(directory), directory)?;
    }

    let metadata_path = archive.join(ARCHIVE_FILE);
    let metadata_bytes = fs::read(&metadata_path).context("read archive metadata")?;
    let metadata: ArchiveMetadata =
        serde_json::from_slice(&metadata_bytes).context("parse archive metadata")?;

    // An unrecognized archive format refuses clearly rather than guessing.
    if metadata.archive_format != ARCHIVE_FORMAT {
        bail!(
            "unsupported archive format {:?}; this verifier understands only {ARCHIVE_FORMAT}",
            metadata.archive_format
        );
    }

    // SEAL binds these exact metadata bytes.
    let seal = fs::read(archive.join(SEAL_FILE)).context("read seal")?;
    if seal != sha256_bytes(&metadata_bytes).as_bytes() {
        bail!("archive seal does not match ARCHIVE.json");
    }

    // These fields are duplicated projections of the exact verifier identity.
    // A different verifier must fail closed and direct the operator to the
    // archive's preserved binary; it must not guess at historical meaning.
    if metadata.tool_version != env!("CARGO_PKG_VERSION") {
        bail!(
            "archive tool version {} does not match this verifier version {}; use the archive's own bin/nq",
            metadata.tool_version,
            env!("CARGO_PKG_VERSION")
        );
    }
    if metadata.schema_version != nq_store::SCHEMA_VERSION {
        bail!(
            "archive schema version {} is not supported by this verifier (expected {}; use the archive's own bin/nq)",
            metadata.schema_version,
            nq_store::SCHEMA_VERSION
        );
    }
    let supported_schema_digest = nq_store::schema_artifact_digest();
    if metadata.schema_artifact_digest != supported_schema_digest {
        bail!(
            "archive schema artifact digest is not supported by this verifier; use the archive's own bin/nq"
        );
    }
    // ARCHIVE.json binds the manifest.
    if metadata.manifest_sha256 != sha256_file(&archive.join(MANIFEST_FILE))? {
        bail!("MANIFEST.sha256 does not match the sealed manifest digest");
    }
    // The manifest binds every content file (missing/substituted/corrupt refuse).
    let covered = check_manifest(archive)?;
    let required_coverage = CONTENT_FILES
        .iter()
        .map(|relative| (*relative).to_owned())
        .collect::<Vec<_>>();
    if covered != required_coverage {
        bail!("manifest does not provide exact required content coverage");
    }

    // The archived verifier must be the exact tool identity sealed in archive
    // metadata *and* the exact verifier executing now. Comparing only two
    // archive-controlled values would let a hostile reseal substitute both.
    // A different verifier fails closed and points at the preserved binary.
    let archived_binary_digest = sha256_file(&archive.join("bin/nq"))?;
    if archived_binary_digest != metadata.tool_binary_digest {
        bail!("archived bin/nq does not match the sealed tool binary digest");
    }
    let executing_binary = std::env::current_exe().context("resolve executing verifier binary")?;
    let executing_binary_digest = sha256_file(&executing_binary)?;
    if archived_binary_digest != executing_binary_digest {
        bail!(
            "archived bin/nq does not match the executing verifier binary; use the archive's own bin/nq"
        );
    }
    let archived_binary_metadata = require_regular_file(&archive.join("bin/nq"), "bin/nq")?;
    let archived_binary_mode = archived_binary_metadata.permissions().mode();
    if archived_binary_mode & 0o100 == 0 {
        bail!("archived bin/nq is not owner-executable");
    }
    if archived_binary_mode & 0o022 != 0 {
        bail!("archived bin/nq is group- or world-writable");
    }

    // No unmanifested file may be present (insertion detection).
    let mut expected: Vec<String> = required_coverage;
    expected.extend([SEAL_FILE, ARCHIVE_FILE, MANIFEST_FILE].map(str::to_owned));
    expected.push("db".to_owned());
    expected.push("bin".to_owned());
    expected.push("config".to_owned());
    let mut present = enumerate_relative(archive, archive)?;
    present.sort();
    expected.sort();
    if let Some(missing) = expected.iter().find(|entry| !present.contains(entry)) {
        bail!("archive is missing required entry: {missing}");
    }
    if let Some(extra) = present.iter().find(|entry| !expected.contains(entry)) {
        bail!("archive contains an unmanifested entry: {extra}");
    }

    // Historical database verification independently attempts a strictly
    // read-only open of the self-contained archived DB (never the live store).
    // The sealed source_openable flag cannot be downgraded to bypass semantic
    // validators: a structurally valid current store paired with `false`
    // refuses as a metadata contradiction.
    let (
        historical_database_verified,
        historical_status_semantics_verified,
        historical_status_events_verified,
        historical_rejected_custody_semantics_verified,
        historical_rejected_custody_records_verified,
        historical_evaluation_refusal_semantics_verified,
        historical_evaluation_records_verified,
    ) = match (
        metadata.source_openable,
        Store::open_immutable(archive.join("db/nq.db")),
    ) {
        (true, Ok(store)) => {
            let status_events = nq_core::engine::validate_status_history_v2(&store)
                .context("reopen typed status semantics from the preserved database")?;
            let rejected_custody = nq_core::engine::validate_rejected_custody_history(&store)
                .context("reopen typed rejected-custody semantics from the preserved database")?;
            let evaluations = nq_core::engine::validate_evaluation_refusal_history(&store)
                .context("reopen typed evaluation/refusal semantics from the preserved database")?;
            (
                Some(true),
                Some(true),
                Some(status_events),
                Some(true),
                Some(rejected_custody),
                Some(true),
                Some(evaluations),
            )
        }
        (true, Err(error)) => {
            return Err(error).context(
                "open the preserved database read-only (use the archive's own bin/nq if this refuses)",
            );
        }
        (false, Ok(_)) => {
            bail!(
                "archive records source_openable=false but its preserved database opens as a valid current store"
            );
        }
        (false, Err(_)) => (None, None, None, None, None, None, None),
    };

    Ok(VerifyReport {
        archive: archive.to_path_buf(),
        archive_format: metadata.archive_format,
        integrity_verified: true,
        historical_database_verified,
        historical_status_semantics_verified,
        historical_status_events_verified,
        historical_rejected_custody_semantics_verified,
        historical_rejected_custody_records_verified,
        historical_evaluation_refusal_semantics_verified,
        historical_evaluation_records_verified,
        grants_authority: false,
    })
}

fn enumerate_relative(root: &Path, dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let relative = path
            .strip_prefix(root)
            .expect("path is under root")
            .to_string_lossy()
            .into_owned();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            out.push(relative);
            out.extend(enumerate_relative(root, &path)?);
        } else {
            out.push(relative);
        }
    }
    Ok(out)
}

fn verify_instructions() -> String {
    format!(
        "# nq-ng cold archive ({ARCHIVE_FORMAT})\n\n\
         This directory preserves a historical nq-ng system for independent\n\
         verification. It grants no authority and admits no transition.\n\n\
         Verify integrity using the preserved binary:\n\n\
         ```\n./bin/nq admin archive-verify .\n```\n\n\
         The seal binds ARCHIVE.json, which binds MANIFEST.sha256, which binds\n\
         every content file. `sha256sum --check MANIFEST.sha256` (run from this\n\
         directory) independently checks the content files.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(value: &impl serde::Serialize) -> nq_store::CanonicalDocument {
        nq_store::CanonicalDocument::from_serializable(value)
            .expect("fixture document canonicalizes")
    }

    fn read_metadata(archive: &Path) -> ArchiveMetadata {
        serde_json::from_slice(
            &fs::read(archive.join(ARCHIVE_FILE)).expect("read archive metadata"),
        )
        .expect("decode archive metadata")
    }

    fn write_metadata_and_seal(archive: &Path, metadata: &mut ArchiveMetadata) {
        metadata.manifest_sha256 =
            sha256_file(&archive.join(MANIFEST_FILE)).expect("digest rewritten manifest");
        let metadata_bytes = serde_json::to_vec_pretty(&metadata).expect("encode archive metadata");
        fs::write(archive.join(ARCHIVE_FILE), &metadata_bytes).expect("rewrite archive metadata");
        fs::write(archive.join(SEAL_FILE), sha256_bytes(&metadata_bytes))
            .expect("rewrite archive seal");
    }

    fn reseal_metadata(archive: &Path) {
        let mut metadata = read_metadata(archive);
        write_metadata_and_seal(archive, &mut metadata);
    }

    fn reseal_after_database_change(archive: &Path) {
        write_manifest(archive).expect("rewrite content manifest");
        reseal_metadata(archive);
    }

    #[allow(clippy::too_many_lines)]
    fn append_mismatched_typed_custody(database: &Path) {
        let mut store = Store::open(database).expect("open archived store");
        let profile = nq_profiles::resolve_profile("nq.conformance", 1)
            .expect("compiled archive fixture profile");
        let descriptor = canonical(profile.descriptor());
        let profile_digest = descriptor.digest().to_owned();
        store
            .append_profile_descriptor(&nq_store::ProfileDescriptorInput {
                profile_id: "nq.conformance".to_owned(),
                profile_version: "1".to_owned(),
                descriptor,
                recorded_at: "2026-07-20T12:00:00Z".to_owned(),
            })
            .expect("append profile descriptor");

        let instance_id = "archive-transport";
        let admission_id = "admission-archive-transport";
        let semantic_id = nq_profiles::profile_semantic_id(profile.descriptor())
            .expect("compiled profile semantic identity");
        let digest = |label: &str| nq_protocol::sha256_bytes(label.as_bytes());
        store
            .append_admission(&nq_store::AdmissionInput {
                admission_id: admission_id.to_owned(),
                instance_id: instance_id.to_owned(),
                identity: nq_store::AdmissionIdentity {
                    profile_semantic_id: nq_protocol::Sha256Digest::parse(semantic_id.as_str())
                        .expect("semantic identity digest"),
                    detector_identity_digest: digest("detector"),
                    evaluator_source_digest: digest("source"),
                    evaluator_artifact_digest: digest("evaluator"),
                    helper_artifact_digest: digest("helper"),
                    config_digest: digest("config"),
                    protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                    target_triple: "fixture-target".to_owned(),
                    artifact_identity_method: "fixture".to_owned(),
                    platform_runtime_version: "fixture".to_owned(),
                },
                execution_chain: canonical(&serde_json::json!({"fixture": true})),
                profile_id: "nq.conformance".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest: profile_digest.clone(),
                capability_grant: canonical(&serde_json::json!([])),
                conformance: canonical(&serde_json::json!({"fixture": true})),
                lock: canonical(&serde_json::json!({"fixture": true})),
                admitted_at: "2026-07-20T12:00:00Z".to_owned(),
                operator_identity: canonical(&serde_json::json!({"fixture": true})),
            })
            .expect("append archive fixture admission");
        let refusal = nq_core::engine::GovernedRefusal::helper(
            "refusal-inside-document".to_owned(),
            nq_protocol::Refusal {
                responsible_instance_id: nq_protocol::InstanceId::new(instance_id)
                    .expect("instance token"),
                boundary: nq_protocol::RefusalBoundary::Collection,
                code: nq_protocol::RefusalCode::CollectionFailed,
                message: "backend collection failed".to_owned(),
                retriable: true,
                details: serde_json::json!({"attempt": 1, "errno": "EAGAIN"}),
            },
        );
        let outcome = nq_core::engine::CollectionOutcome::rejected(
            instance_id.to_owned(),
            "run-archive-transport".to_owned(),
            refusal.clone(),
        );
        let resource_outcome = nq_core::engine::RunResourceOutcomeV1 {
            schema: nq_core::engine::RunResourceOutcomeSchema::V1,
            duration_ms: 1,
            exit_code: Some(0),
            hard_limits: nq_core::engine::RunHardLimits {
                address_space_bytes_per_process: 1,
                cpu_seconds_per_process: 1,
                processes_per_execution_uid: 1,
                open_files_per_process: 1,
                file_bytes_per_regular_file: 1,
                core_bytes: 0,
            },
            stdout_bytes_retained: b"rejected response".len(),
            stderr_bytes_retained: 0,
            stderr_hex: String::new(),
            outcome: nq_core::runner::AcquisitionOutcome::Response,
        };
        let collection = nq_store::CollectionInput {
            run: nq_store::RunInput {
                run_id: "run-archive-transport".to_owned(),
                request_id: "request-archive-transport".to_owned(),
                instance_id: instance_id.to_owned(),
                admission_id: Some(admission_id.to_owned()),
                binding_digest: nq_protocol::sha256_bytes(b"binding").into_string(),
                checkpoint_contract_digest: nq_protocol::sha256_bytes(b"checkpoint").into_string(),
                profile_id: "nq.conformance".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest,
                carrier: "stdio".to_owned(),
                started_at: "2026-07-20T12:00:00Z".to_owned(),
                deadline_at: "2026-07-20T12:00:01Z".to_owned(),
                finished_at: "2026-07-20T12:00:00Z".to_owned(),
                acquisition_outcome: "response".to_owned(),
                execution_identity: canonical(&serde_json::json!({"fixture": true})),
                resource_outcome: canonical(&resource_outcome),
            },
            submission: Some(nq_store::SubmissionInput {
                submission_id: "submission-archive-transport".to_owned(),
                raw_bytes: b"rejected response".to_vec(),
                received_at: "2026-07-20T12:00:00Z".to_owned(),
                protocol_outcome: "valid_refusal".to_owned(),
                disposition: nq_store::SubmissionDisposition::Rejected {
                    refusal: nq_store::RefusalInput {
                        // SQL projections are self-consistent, but this ID
                        // deliberately disagrees with the canonical object.
                        refusal_id: "refusal-in-sql-row".to_owned(),
                        source_kind: "protocol".to_owned(),
                        responsible_instance_id: instance_id.to_owned(),
                        boundary: "collection".to_owned(),
                        code: "collection_failed".to_owned(),
                        profile_semantic_id: None,
                        detail: canonical(&refusal),
                        created_at: "2026-07-20T12:00:00Z".to_owned(),
                    },
                },
            }),
        };
        store
            .commit_non_success_collection(
                &collection,
                &nq_store::RunResultStatusInput {
                    run_id: "run-archive-transport".to_owned(),
                    status: nq_store::StatusEventInput {
                        status_event_id: uuid::Uuid::new_v4().to_string(),
                        component_kind: "instance".to_owned(),
                        component_id: instance_id.to_owned(),
                        state: "degraded".to_owned(),
                        code: "helper_refused".to_owned(),
                        detail: canonical(&outcome),
                        observed_at: "2026-07-20T12:00:00Z".to_owned(),
                    },
                },
            )
            .expect("store structurally valid but semantically mismatched custody");
        store
            .validate()
            .expect("generic store validation does not interpret refusal payload");
    }

    fn write_config(root: &Path, database: &Path) -> PathBuf {
        let config = root.join("nq.toml");
        fs::write(
            &config,
            format!(
                "schema = \"nq.config.v1\"\ndatabase_path = \"{}\"\nsocket_path = \"{}\"\n\
                 admissions_dir = \"{}\"\nhelper_runtime_dir = \"{}\"\n",
                database.display(),
                root.join("nqd.sock").display(),
                root.join("admissions").display(),
                root.join("helpers").display(),
            ),
        )
        .expect("write config");
        config
    }

    fn valid_archive(root: &Path) -> PathBuf {
        let database = root.join("nq.db");
        drop(Store::initialize(&database).expect("init store"));
        let config = write_config(root, &database);
        let archive = root.join("archive");
        create_archive(&config, &archive).expect("create archive");
        archive
    }

    fn complete_inventory(root: &Path) -> Vec<(String, String)> {
        let mut entries = enumerate_relative(root, root).expect("enumerate complete archive");
        entries.sort();
        entries
            .into_iter()
            .map(|relative| {
                let path = root.join(&relative);
                let metadata = fs::symlink_metadata(&path).expect("inventory entry metadata");
                let identity = if metadata.file_type().is_file() {
                    sha256_file(&path).expect("digest inventory file")
                } else if metadata.file_type().is_dir() {
                    "directory".to_owned()
                } else {
                    "unsupported-file-type".to_owned()
                };
                (relative, identity)
            })
            .collect()
    }

    #[test]
    fn a_sealed_archive_verifies_and_grants_no_authority() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        assert!(archive.join("SEAL").is_file());
        assert_eq!(
            fs::metadata(archive.join("bin/nq"))
                .expect("archived verifier metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "archive creation normalizes the verifier to a safe executable mode"
        );
        let report = verify_archive(&archive).expect("verify");
        assert!(report.integrity_verified);
        assert_eq!(report.historical_database_verified, Some(true));
        assert_eq!(report.historical_status_semantics_verified, Some(true));
        assert_eq!(report.historical_status_events_verified, Some(0));
        assert_eq!(
            report.historical_rejected_custody_semantics_verified,
            Some(true)
        );
        assert_eq!(report.historical_rejected_custody_records_verified, Some(0));
        assert_eq!(
            report.historical_evaluation_refusal_semantics_verified,
            Some(true)
        );
        assert_eq!(report.historical_evaluation_records_verified, Some(0));
        assert!(!report.grants_authority);
    }

    #[test]
    fn verification_is_repeatable_and_leaves_every_entry_and_byte_unchanged() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let before = complete_inventory(&archive);

        assert!(
            verify_archive(&archive)
                .expect("first independent verification")
                .integrity_verified
        );
        let after_first = complete_inventory(&archive);
        assert_eq!(after_first, before);

        assert!(
            verify_archive(&archive)
                .expect("second independent verification")
                .integrity_verified
        );
        let after_second = complete_inventory(&archive);
        assert_eq!(after_second, before);
    }

    #[test]
    fn a_resealed_unversioned_instance_status_fails_typed_history_verification() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let database = archive.join("db/nq.db");
        let mut store = Store::open(&database).expect("open archived store");
        nq_core::engine::record_component_status(
            &mut store,
            "instance",
            "legacy-instance",
            "failed",
            "legacy_failure",
            &serde_json::json!({"legacy": "unversioned status detail"}),
        )
        .expect("append structurally valid legacy status");
        // A newer exact v2 result advances the rebuildable current projection.
        // Archive verification must still inspect and reject the older event.
        let current = nq_core::engine::CollectionOutcome::acquisition_failed(
            "legacy-instance".to_owned(),
            "run-current".to_owned(),
            nq_core::runner::AcquisitionOutcome::ExchangeTimeout {
                phase: nq_core::runner::ExchangeTimeoutPhase::ReadResponse,
            },
        )
        .expect("construct current typed result");
        nq_core::engine::record_component_status(
            &mut store,
            "instance",
            "legacy-instance",
            "failed",
            "collection_failed",
            &serde_json::to_value(current).expect("typed result serializes"),
        )
        .expect("append current typed status");
        store
            .validate()
            .expect("generic store validation accepts canonical legacy detail");
        drop(store);
        reseal_after_database_change(&archive);

        let error = verify_archive(&archive)
            .expect_err("typed archive verification must refuse unversioned status");
        assert!(
            error.to_string().contains("reopen typed status semantics"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn a_resealed_mismatched_refusal_document_fails_typed_history_verification() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        append_mismatched_typed_custody(&archive.join("db/nq.db"));
        reseal_after_database_change(&archive);

        let error = verify_archive(&archive)
            .expect_err("typed archive verification must refuse mismatched custody");
        // Status reopening follows the typed refusal link into custody, so it
        // detects this substitution before the subsequent custody-only pass.
        assert!(
            error.to_string().contains("reopen typed status semantics"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn verification_needs_no_live_store() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        // Remove the live database entirely; the archive still verifies.
        fs::remove_file(dir.path().join("nq.db")).expect("remove live db");
        assert!(verify_archive(&archive).expect("verify").integrity_verified);
    }

    #[test]
    fn a_mutated_database_byte_is_detected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let db = archive.join("db/nq.db");
        let mut bytes = fs::read(&db).expect("read");
        bytes[0] ^= 0xff;
        fs::write(&db, bytes).expect("mutate");
        assert!(verify_archive(&archive).is_err());
    }

    #[test]
    fn a_substituted_binary_is_detected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        fs::write(archive.join("bin/nq"), b"impostor").expect("substitute binary");
        assert!(verify_archive(&archive).is_err());
    }

    #[test]
    fn a_resealed_manifest_cannot_omit_required_content() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        fs::remove_file(archive.join("bin/nq")).expect("remove archived verifier");
        let manifest = fs::read_to_string(archive.join(MANIFEST_FILE)).expect("read manifest");
        let rewritten = manifest
            .lines()
            .filter(|line| !line.ends_with("  bin/nq"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(archive.join(MANIFEST_FILE), rewritten).expect("omit manifest line");
        reseal_metadata(&archive);

        let error = verify_archive(&archive)
            .expect_err("resealed archive cannot omit a required content file and line");
        assert!(
            error.to_string().contains("required exact entry"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn a_resealed_binary_substitution_disagrees_with_tool_identity() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        fs::write(archive.join("bin/nq"), b"impostor").expect("substitute verifier");
        write_manifest(&archive).expect("bind substituted bytes in content manifest");
        let mut metadata = read_metadata(&archive);
        metadata.tool_binary_digest =
            sha256_file(&archive.join("bin/nq")).expect("digest substituted verifier");
        write_metadata_and_seal(&archive, &mut metadata);

        let error = verify_archive(&archive)
            .expect_err("hostile reseal cannot substitute both archived verifier identities");
        assert!(
            error.to_string().contains("executing verifier binary"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn a_resealed_schema_version_substitution_is_rejected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let mut metadata = read_metadata(&archive);
        metadata.schema_version += 1;
        write_metadata_and_seal(&archive, &mut metadata);

        let error = verify_archive(&archive)
            .expect_err("sealed metadata cannot substitute the verifier-supported schema version");
        assert!(
            error.to_string().contains("schema version")
                && error.to_string().contains("not supported by this verifier"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn a_resealed_tool_version_substitution_is_rejected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let mut metadata = read_metadata(&archive);
        metadata.tool_version = "999.0.0-hostile".to_owned();
        write_metadata_and_seal(&archive, &mut metadata);

        let error = verify_archive(&archive)
            .expect_err("sealed metadata cannot substitute the executing tool version");
        assert!(
            error.to_string().contains("tool version")
                && error
                    .to_string()
                    .contains("does not match this verifier version"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn a_resealed_schema_artifact_substitution_is_rejected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let mut metadata = read_metadata(&archive);
        metadata.schema_artifact_digest = format!("sha256:{}", "0".repeat(64));
        write_metadata_and_seal(&archive, &mut metadata);

        let error = verify_archive(&archive)
            .expect_err("sealed metadata cannot substitute the supported schema artifact");
        assert!(
            error
                .to_string()
                .contains("schema artifact digest is not supported by this verifier"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn resealed_unknown_metadata_is_rejected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let metadata_path = archive.join(ARCHIVE_FILE);
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(&metadata_path).expect("read archive metadata"))
                .expect("decode archive metadata value");
        metadata
            .as_object_mut()
            .expect("metadata object")
            .insert("inferred_schema".to_owned(), serde_json::json!(true));
        let metadata_bytes = serde_json::to_vec_pretty(&metadata).expect("encode hostile metadata");
        fs::write(&metadata_path, &metadata_bytes).expect("rewrite hostile metadata");
        fs::write(archive.join(SEAL_FILE), sha256_bytes(&metadata_bytes))
            .expect("seal hostile metadata");

        let error = verify_archive(&archive).expect_err("unknown sealed metadata must fail closed");
        assert!(
            error.to_string().contains("parse archive metadata"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn a_resealed_source_openable_downgrade_cannot_skip_semantic_verification() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let mut metadata = read_metadata(&archive);
        metadata.source_openable = false;
        write_metadata_and_seal(&archive, &mut metadata);

        let error = verify_archive(&archive)
            .expect_err("source-openable metadata cannot be downgraded around validators");
        assert!(
            error
                .to_string()
                .contains("records source_openable=false but its preserved database opens"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn a_mutated_manifest_is_detected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let mut manifest = fs::read_to_string(archive.join(MANIFEST_FILE)).expect("read");
        manifest.push_str("deadbeef  bin/nq\n");
        fs::write(archive.join(MANIFEST_FILE), manifest).expect("mutate manifest");
        assert!(verify_archive(&archive).is_err());
    }

    #[test]
    fn a_removed_file_is_detected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        fs::remove_file(archive.join("VERIFY.md")).expect("remove");
        assert!(verify_archive(&archive).is_err());
    }

    #[test]
    fn an_unmanifested_file_is_detected() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        fs::write(archive.join("smuggled.txt"), b"x").expect("insert");
        assert!(verify_archive(&archive).is_err());
    }

    #[test]
    fn a_mutated_metadata_body_breaks_the_seal() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let mut metadata = fs::read(archive.join(ARCHIVE_FILE)).expect("read");
        metadata.extend_from_slice(b"\n");
        fs::write(archive.join(ARCHIVE_FILE), metadata).expect("mutate metadata");
        assert!(verify_archive(&archive).is_err());
    }

    #[test]
    fn seal_representation_is_exact_and_rejects_appended_whitespace() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let mut seal = fs::read(archive.join(SEAL_FILE)).expect("read canonical seal");
        seal.push(b'\n');
        fs::write(archive.join(SEAL_FILE), seal).expect("append seal whitespace");

        let error = verify_archive(&archive).expect_err("noncanonical seal must be rejected");
        assert!(
            error
                .to_string()
                .contains("archive seal does not match ARCHIVE.json"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn archived_verifier_mode_must_remain_executable_and_nonwritable() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        let binary = archive.join("bin/nq");
        let original_mode = fs::metadata(&binary)
            .expect("archived verifier metadata")
            .permissions()
            .mode()
            & 0o7777;

        fs::set_permissions(&binary, fs::Permissions::from_mode(0o644))
            .expect("remove verifier execute bit");
        let error = verify_archive(&archive)
            .expect_err("manifest bytes alone cannot prove an executable verifier");
        assert!(
            error.to_string().contains("not owner-executable"),
            "unexpected refusal: {error:#}"
        );

        fs::set_permissions(&binary, fs::Permissions::from_mode(0o775))
            .expect("make verifier group-writable");
        let error = verify_archive(&archive)
            .expect_err("manifest bytes alone cannot permit a writable verifier");
        assert!(
            error.to_string().contains("group- or world-writable"),
            "unexpected refusal: {error:#}"
        );

        fs::set_permissions(&binary, fs::Permissions::from_mode(original_mode))
            .expect("restore verifier mode");
        assert!(
            verify_archive(&archive)
                .expect("restored verifier mode verifies")
                .integrity_verified
        );
    }

    #[test]
    fn symlinked_root_control_or_parent_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());

        let root_link = dir.path().join("archive-link");
        symlink(&archive, &root_link).expect("symlink archive root");
        let error = verify_archive(&root_link).expect_err("archive root symlink must refuse");
        assert!(
            error.to_string().contains("not a physical directory"),
            "unexpected refusal: {error:#}"
        );

        let outside_seal = dir.path().join("outside-seal");
        fs::rename(archive.join(SEAL_FILE), &outside_seal).expect("move seal outside archive");
        symlink(&outside_seal, archive.join(SEAL_FILE)).expect("symlink archive seal");
        let error = verify_archive(&archive).expect_err("control-file symlink must refuse");
        assert!(
            error.to_string().contains("SEAL is not a regular file"),
            "unexpected refusal: {error:#}"
        );
        fs::remove_file(archive.join(SEAL_FILE)).expect("remove seal symlink");
        fs::rename(&outside_seal, archive.join(SEAL_FILE)).expect("restore physical seal");

        let outside_db = dir.path().join("outside-db");
        fs::rename(archive.join("db"), &outside_db).expect("move database directory outside");
        symlink(&outside_db, archive.join("db")).expect("symlink database parent");
        let error = verify_archive(&archive).expect_err("content-parent symlink must refuse");
        assert!(
            error.to_string().contains("db is not a physical directory"),
            "unexpected refusal: {error:#}"
        );
    }

    #[test]
    fn an_archive_missing_its_seal_does_not_verify() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        // An interrupted construction (no SEAL written yet) must never verify.
        fs::remove_file(archive.join(SEAL_FILE)).expect("remove seal");
        assert!(verify_archive(&archive).is_err());
    }

    #[test]
    fn an_incompatible_database_is_preserved_but_fails_closed_on_history() {
        let dir = tempfile::tempdir().expect("dir");
        // A valid SQLite file that is not an nq store: open() refuses it.
        let foreign = dir.path().join("foreign.db");
        {
            let connection = rusqlite::Connection::open(&foreign).expect("sqlite");
            connection
                .execute_batch("CREATE TABLE x(a);")
                .expect("table");
        }
        let config = write_config(dir.path(), &foreign);
        let archive = dir.path().join("foreign-archive");
        let report = create_archive(&config, &archive).expect("archive incompatible db");
        assert!(!report.source_openable);
        let verified = verify_archive(&archive).expect("integrity still verifies");
        assert!(verified.integrity_verified);
        // The historical-meaning claim fails closed.
        assert_eq!(verified.historical_database_verified, None);
        assert_eq!(verified.historical_status_semantics_verified, None);
        assert_eq!(verified.historical_status_events_verified, None);
        assert_eq!(
            verified.historical_rejected_custody_semantics_verified,
            None
        );
        assert_eq!(verified.historical_rejected_custody_records_verified, None);
        assert_eq!(
            verified.historical_evaluation_refusal_semantics_verified,
            None
        );
        assert_eq!(verified.historical_evaluation_records_verified, None);
    }

    #[test]
    fn an_unknown_archive_format_refuses_clearly() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = dir.path().join("future");
        fs::create_dir(&archive).expect("dir");
        for directory in ["db", "bin", "config"] {
            fs::create_dir(archive.join(directory)).expect("physical content parent");
        }
        fs::write(archive.join(SEAL_FILE), b"").expect("physical seal placeholder");
        fs::write(archive.join(MANIFEST_FILE), b"").expect("physical manifest placeholder");
        let metadata = ArchiveMetadata {
            archive_format: "nq.cold_archive.v99".to_owned(),
            created_at: "2026-07-18T00:00:00Z".to_owned(),
            tool_version: "9.9.9".to_owned(),
            tool_binary_digest: format!("sha256:{}", "0".repeat(64)),
            schema_version: 1,
            schema_artifact_digest: format!("sha256:{}", "0".repeat(64)),
            source_openable: true,
            manifest_sha256: format!("sha256:{}", "0".repeat(64)),
        };
        fs::write(
            archive.join(ARCHIVE_FILE),
            serde_json::to_vec(&metadata).expect("metadata"),
        )
        .expect("write");
        let error = verify_archive(&archive).expect_err("unknown format refuses");
        assert!(error.to_string().contains("unsupported archive format"));
    }

    #[test]
    fn an_existing_destination_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let database = dir.path().join("nq.db");
        drop(Store::initialize(&database).expect("init"));
        let config = write_config(dir.path(), &database);
        let archive = dir.path().join("archive");
        fs::create_dir(&archive).expect("pre-existing");
        assert!(create_archive(&config, &archive).is_err());
    }
}
