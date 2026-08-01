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
    /// Whether every admitted report reopened through its exact canonical
    /// judgment and complete submission/run/admission/materialization chain.
    /// `None` when history is un-openable.
    pub historical_admitted_report_semantics_verified: Option<bool>,
    /// Exact number of admitted reports reopened by the historical verifier.
    pub historical_admitted_reports_verified: Option<usize>,
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
    /// Whether every schema-v4 provider intake reopened through its exact
    /// identity, raw-byte custody, local-run origin, and durable acknowledgment,
    /// and every migrated schema-v3 run remained an explicit limitation rather
    /// than synthetic intake evidence. `None` when history is un-openable.
    pub historical_provider_intake_semantics_verified: Option<bool>,
    /// Exact number of real schema-v4 provider-intake records reopened.
    pub historical_provider_intake_records_verified: Option<usize>,
    /// Exact number of durable provider-intake acknowledgments reopened and
    /// matched to their canonical downstream result.
    pub historical_provider_intake_acknowledgments_verified: Option<usize>,
    /// Exact number of schema-v3 watcher runs reopened as explicit provider-
    /// intake gaps. These are limitations, never synthesized evidence.
    pub historical_legacy_provider_intake_gaps_verified: Option<usize>,
    /// Whether every diagnostic-artifact commitment was classified, every
    /// available current-schema artifact reopened strictly, and no corrupt
    /// payload was present.
    pub historical_diagnostic_artifact_semantics_verified: Option<bool>,
    /// Exact number of immutable diagnostic-artifact commitments visited.
    pub historical_diagnostic_artifact_commitments_verified: Option<usize>,
    /// Exact number of available current-schema artifacts reopened strictly.
    pub historical_diagnostic_artifacts_reopened: Option<usize>,
    /// Exact number of current-schema commitments with explicitly unavailable
    /// bytes. These were not reconstructed.
    pub historical_diagnostic_artifacts_committed_unavailable: Option<usize>,
    /// Exact number of available canonical artifacts retained under an
    /// unsupported schema and therefore not interpreted.
    pub historical_unsupported_diagnostic_artifacts_available: Option<usize>,
    /// Exact number of unsupported-schema commitments with unavailable bytes.
    pub historical_unsupported_diagnostic_artifacts_committed_unavailable: Option<usize>,
    /// Always false: verification confirms history, it grants nothing.
    pub grants_authority: bool,
}

struct HistoricalSemanticCounts {
    admitted_reports: usize,
    status_events: usize,
    rejected_custody_records: usize,
    evaluations: usize,
    provider_intakes: usize,
    provider_intake_acknowledgments: usize,
    legacy_provider_intake_gaps: usize,
    diagnostic_artifacts: nq_core::DiagnosticArtifactHistoryVerification,
}

fn validate_historical_semantics(store: &mut Store) -> Result<HistoricalSemanticCounts> {
    let admitted_reports = nq_core::engine::validate_admitted_report_history(store)
        .context("reopen admitted-report semantics")?;
    let status_events = nq_core::engine::validate_status_history_v2(store)
        .context("reopen typed status semantics")?;
    let rejected_custody_records = nq_core::engine::validate_rejected_custody_history(store)
        .context("reopen typed rejected-custody semantics")?;
    let evaluations = nq_core::engine::validate_evaluation_refusal_history(store)
        .context("reopen typed evaluation/refusal semantics")?;
    nq_core::engine::status_snapshot_v3(store)
        .context("reopen public V3 status evaluation semantics")?;
    let mut after = None;
    let mut through = None;
    let mut public_evaluations = 0usize;
    loop {
        let page = nq_core::engine::evaluation_history_bounded(
            store,
            nq_store::MAX_PUBLIC_QUERY_ROWS,
            after,
            through,
        )
        .context("reopen public governed-evaluation history")?;
        through = Some(page.through_sequence);
        public_evaluations = public_evaluations
            .checked_add(page.records.len())
            .context("public evaluation history count overflowed")?;
        if page.complete {
            break;
        }
        after = Some(
            page.next_after_sequence
                .context("incomplete evaluation page lacks its continuation cursor")?,
        );
    }
    if public_evaluations != evaluations {
        bail!(
            "public evaluation history reopened {public_evaluations} rows; typed verifier reopened {evaluations}"
        );
    }
    let provider_history = nq_core::engine::validate_provider_intake_history(store)
        .context("reopen provider-intake and legacy-gap semantics")?;
    let diagnostic_artifacts = nq_core::validate_diagnostic_artifact_history(store)
        .context("reopen diagnostic-artifact commitments and available semantics")?;
    Ok(HistoricalSemanticCounts {
        admitted_reports,
        status_events,
        rejected_custody_records,
        evaluations,
        provider_intakes: provider_history.provider_intakes,
        provider_intake_acknowledgments: provider_history.acknowledgments,
        legacy_provider_intake_gaps: provider_history.legacy_gaps,
        diagnostic_artifacts,
    })
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
    let source_openable = if let Ok(mut store) = Store::open(&config.database_path) {
        validate_historical_semantics(&mut store)
            .context("validate source database semantics before archiving")?;
        store.backup_verified(&db)?;
        let mut archived_copy =
            Store::open(&db).context("open archive database backup for freeze")?;
        validate_historical_semantics(&mut archived_copy)
            .context("validate copied database semantics before sealing")?;
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
    let historical_counts = match (
        metadata.source_openable,
        Store::open_immutable(archive.join("db/nq.db")),
    ) {
        (true, Ok(mut store)) => {
            let counts = validate_historical_semantics(&mut store)?;
            Some(counts)
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
        (false, Err(_)) => None,
    };

    Ok(VerifyReport {
        archive: archive.to_path_buf(),
        archive_format: metadata.archive_format,
        integrity_verified: true,
        historical_database_verified: historical_counts.as_ref().map(|_| true),
        historical_admitted_report_semantics_verified: historical_counts.as_ref().map(|_| true),
        historical_admitted_reports_verified: historical_counts
            .as_ref()
            .map(|counts| counts.admitted_reports),
        historical_status_semantics_verified: historical_counts.as_ref().map(|_| true),
        historical_status_events_verified: historical_counts
            .as_ref()
            .map(|counts| counts.status_events),
        historical_rejected_custody_semantics_verified: historical_counts.as_ref().map(|_| true),
        historical_rejected_custody_records_verified: historical_counts
            .as_ref()
            .map(|counts| counts.rejected_custody_records),
        historical_evaluation_refusal_semantics_verified: historical_counts.as_ref().map(|_| true),
        historical_evaluation_records_verified: historical_counts
            .as_ref()
            .map(|counts| counts.evaluations),
        historical_provider_intake_semantics_verified: historical_counts.as_ref().map(|_| true),
        historical_provider_intake_records_verified: historical_counts
            .as_ref()
            .map(|counts| counts.provider_intakes),
        historical_provider_intake_acknowledgments_verified: historical_counts
            .as_ref()
            .map(|counts| counts.provider_intake_acknowledgments),
        historical_legacy_provider_intake_gaps_verified: historical_counts
            .as_ref()
            .map(|counts| counts.legacy_provider_intake_gaps),
        historical_diagnostic_artifact_semantics_verified: historical_counts.as_ref().map(|_| true),
        historical_diagnostic_artifact_commitments_verified: historical_counts
            .as_ref()
            .map(|counts| counts.diagnostic_artifacts.commitments),
        historical_diagnostic_artifacts_reopened: historical_counts
            .as_ref()
            .map(|counts| counts.diagnostic_artifacts.supported_available),
        historical_diagnostic_artifacts_committed_unavailable: historical_counts
            .as_ref()
            .map(|counts| counts.diagnostic_artifacts.supported_committed_unavailable),
        historical_unsupported_diagnostic_artifacts_available: historical_counts
            .as_ref()
            .map(|counts| counts.diagnostic_artifacts.unsupported_available),
        historical_unsupported_diagnostic_artifacts_committed_unavailable: historical_counts
            .as_ref()
            .map(|counts| {
                counts
                    .diagnostic_artifacts
                    .unsupported_committed_unavailable
            }),
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
    use nq_host_role_runtime::{
        HostRoleRuntime, RuntimeAuthorityResidentBinding,
        test_support::authenticated_runtime_dependencies,
    };
    use nq_runtime_dependency_authority::{
        OldRootState,
        test_support::{
            FIXTURE_DOMAIN, FIXTURE_HOST_ROLE, FIXTURE_OCCURRENCE_ID, FIXTURE_RESIDENT_GENERATION,
            FIXTURE_RESIDENT_ID, FIXTURE_ROLE_MANIFEST_GENERATION, RawAuthorityFixture,
        },
    };

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
    fn append_provider_intake_collection(
        database: &Path,
        mismatch_refusal_identity: bool,
    ) -> nq_store::ProviderIntakeRow {
        let mut store = Store::open(database).expect("open archived store");
        let profile = nq_profiles::resolve_profile("nq.conformance", 1)
            .expect("compiled archive fixture profile");
        let descriptor = canonical(profile.descriptor());
        let profile_digest = descriptor.digest().to_owned();
        store
            .begin_writer_session()
            .expect("begin writer session")
            .append_profile_descriptor(&nq_store::ProfileDescriptorInput {
                profile_id: "nq.conformance".to_owned(),
                profile_version: "1".to_owned(),
                descriptor,
                recorded_at: "2026-07-20T12:00:00Z".to_owned(),
            })
            .expect("append profile descriptor");

        let instance_id = "archive-transport";
        let admission_id = "00000000-0000-4000-8000-000000000101";
        let semantic_id = nq_profiles::profile_semantic_id(profile.descriptor())
            .expect("compiled profile semantic identity");
        let digest = |label: &str| nq_protocol::sha256_bytes(label.as_bytes());
        let conformance = nq_core::admission::ConformanceReceipt {
            tool_version: "archive-fixture-v1".to_owned(),
            protocol_passed: true,
            protocol_corpus_digest: digest("archive-provider-corpus").into_string(),
            protocol_fixtures_checked: 1,
            dry_collection_passed: true,
            dry_report_digest: Some(digest("archive-dry-report").into_string()),
        };
        let conformance_document = canonical(&conformance);
        let admission_identity = nq_store::AdmissionIdentity {
            profile_semantic_id: nq_protocol::Sha256Digest::parse(semantic_id.as_str())
                .expect("semantic identity digest"),
            detector_identity_digest: nq_store::detector_suite_identity_digest(
                profile.detectors().iter().map(|detector| {
                    detector
                        .descriptor()
                        .digest()
                        .expect("compiled detector identity")
                }),
            )
            .expect("compiled detector suite identity"),
            evaluator_source_digest: digest("source"),
            evaluator_artifact_digest: digest("evaluator"),
            helper_artifact_digest: digest("helper"),
            config_digest: digest("config"),
            protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
            target_triple: "fixture-target".to_owned(),
            artifact_identity_method: "fixture".to_owned(),
            platform_runtime_version: "fixture".to_owned(),
        };
        let execution = nq_core::identity::ExecutionIdentity {
            execution_account: Some(nq_helper_sandbox::ExecutionAccount {
                configured: "991".to_owned(),
                name: "archive-fixture".to_owned(),
                uid: 991,
                gid: 991,
                debug_same_identity: false,
            }),
            configured_path: std::path::PathBuf::from("/fixture/archive-provider"),
            resolved_path: std::path::PathBuf::from("/fixture/archive-provider"),
            sha256: admission_identity
                .helper_artifact_digest
                .as_str()
                .to_owned(),
            size: 1,
            device: 1,
            inode: 1,
            mode: 0o100_755,
            modified_ns: "0".to_owned(),
            fixed_argv: Vec::new(),
            working_directory: None,
            working_directory_identity: None,
            execution_chain: Vec::new(),
            startup_runtime: None,
        };
        let execution_identity = canonical(&execution);
        let source_lock = canonical(&nq_core::admission::AdmissionLock {
            schema: nq_core::admission::ADMISSION_SCHEMA.to_owned(),
            admission_id: admission_id.to_owned(),
            instance_id: instance_id.to_owned(),
            config_digest: admission_identity.config_digest.as_str().to_owned(),
            execution,
            profile: nq_core::admission::AdmittedProfile {
                id: "nq.conformance".to_owned(),
                version: 1,
                digest: profile_digest.clone(),
            },
            protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
            granted_capabilities: std::collections::BTreeSet::new(),
            conformance: conformance.clone(),
            admitted_at: chrono::DateTime::parse_from_rfc3339("2026-07-20T12:00:00Z")
                .expect("fixture admission time")
                .with_timezone(&chrono::Utc),
            operator: nq_core::admission::OperatorIdentity {
                uid: 991,
                gid: 991,
                login_hint: Some("archive-fixture".to_owned()),
            },
        });
        store
            .begin_writer_session()
            .expect("begin writer session")
            .append_admission(&nq_store::AdmissionInput {
                admission_id: admission_id.to_owned(),
                instance_id: instance_id.to_owned(),
                identity: admission_identity.clone(),
                execution_chain: execution_identity.clone(),
                profile_id: "nq.conformance".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest: profile_digest.clone(),
                capability_grant: canonical(&serde_json::json!([])),
                conformance: conformance_document.clone(),
                lock: source_lock.clone(),
                admitted_at: "2026-07-20T12:00:00Z".to_owned(),
                operator_identity: canonical(&serde_json::json!({
                    "uid": 991,
                    "gid": 991,
                    "login_hint": "archive-fixture",
                })),
            })
            .expect("append archive fixture admission");

        let binding_digest = nq_protocol::Sha256Digest::parse(source_lock.digest().to_owned())
            .expect("source lock digest");
        let binding_event_id = "00000000-0000-4000-8000-000000000102";
        let operation_id = "00000000-0000-4000-8000-000000000103";
        store
            .begin_writer_session()
            .expect("begin writer session")
            .begin_binding_transition(
                &nq_store::BindingEventInput {
                    binding_event_id: binding_event_id.to_owned(),
                    instance_id: instance_id.to_owned(),
                    event_kind: "activate".to_owned(),
                    admission_id: Some(admission_id.to_owned()),
                    binding_digest: binding_digest.as_str().to_owned(),
                    occurred_at: "2026-07-20T12:00:00Z".to_owned(),
                    reason_code: Some("archive_fixture".to_owned()),
                    detail: canonical(&serde_json::json!({"fixture": true})),
                },
                &nq_store::BindingMaterializationInput {
                    materialization_event_id: "00000000-0000-4000-8000-000000000104".to_owned(),
                    operation_id: operation_id.to_owned(),
                    instance_id: instance_id.to_owned(),
                    binding_event_id: binding_event_id.to_owned(),
                    phase: "intent".to_owned(),
                    occurred_at: "2026-07-20T12:00:00Z".to_owned(),
                    detail: canonical(&serde_json::json!({"desired": "active"})),
                },
            )
            .expect("activate archive fixture provider admission");
        store
            .begin_writer_session()
            .expect("begin writer session")
            .complete_binding_materialization(&nq_store::BindingMaterializationInput {
                materialization_event_id: "00000000-0000-4000-8000-000000000105".to_owned(),
                operation_id: operation_id.to_owned(),
                instance_id: instance_id.to_owned(),
                binding_event_id: binding_event_id.to_owned(),
                phase: "completed".to_owned(),
                occurred_at: "2026-07-20T12:00:00Z".to_owned(),
                detail: canonical(&serde_json::json!({"durable": true})),
            })
            .expect("complete archive fixture provider binding");

        let request_id = "request-archive-transport";
        let request = nq_protocol::HelperRequest::builder(
            nq_protocol::RequestId::new(request_id).expect("request identity"),
            nq_protocol::InstanceId::new(instance_id).expect("instance identity"),
            nq_protocol::ProfileBinding {
                id: nq_protocol::ProfileId::new("nq.conformance").expect("profile identity"),
                version: nq_protocol::ProfileVersion::new("1").expect("profile version"),
                digest: nq_protocol::Sha256Digest::parse(profile_digest.clone())
                    .expect("profile digest"),
            },
            nq_protocol::SubjectBinding {
                subject: nq_protocol::SubjectId::new("archive:provider-intake")
                    .expect("subject identity"),
                scope: nq_protocol::ScopeBinding {
                    kind: nq_protocol::ScopeKind::new("archive").expect("scope kind"),
                    value: serde_json::json!({"fixture": "provider-intake"}),
                },
                vantage: nq_protocol::VantageBinding {
                    kind: nq_protocol::VantageKind::new("local").expect("vantage kind"),
                    value: serde_json::json!({}),
                },
            },
            nq_protocol::MonotonicDeadline {
                clock: nq_protocol::MonotonicClock::LinuxBoottime,
                expires_at_ns: 10_000,
            },
        )
        .build()
        .expect("archive fixture helper request");
        let helper_refusal = nq_protocol::Refusal {
            responsible_instance_id: nq_protocol::InstanceId::new(instance_id)
                .expect("instance token"),
            boundary: nq_protocol::RefusalBoundary::Collection,
            code: nq_protocol::RefusalCode::CollectionFailed,
            message: "backend collection failed".to_owned(),
            retriable: true,
            details: serde_json::json!({"attempt": 1, "errno": "EAGAIN"}),
        };
        let response = nq_protocol::HelperResponse::refusal(&request, helper_refusal.clone());
        let raw_bytes = nq_protocol::encode_ndjson(&response).expect("encode provider response");
        let governed_refusal_id = "refusal-inside-document";
        let refusal = nq_core::engine::GovernedRefusal::helper(
            governed_refusal_id.to_owned(),
            helper_refusal,
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
            stdout_bytes_retained: raw_bytes.len(),
            stderr_bytes_retained: 0,
            stderr_hex: String::new(),
            outcome: nq_core::runner::AcquisitionOutcome::Response,
        };
        let admission = store
            .admission(admission_id)
            .expect("reopen fixture admission")
            .expect("fixture admission exists");
        let provider_admission = store
            .provider_admission_for_source(admission_id)
            .expect("reopen fixture provider admission")
            .expect("fixture provider admission exists");
        let provider_semantic_id = nq_store::local_provider_semantic_id(
            nq_protocol::HELPER_PROTOCOL_VERSION,
            &conformance_document,
        )
        .expect("derive provider semantic identity");
        let execution_identity_digest =
            nq_protocol::Sha256Digest::parse(execution_identity.digest().to_owned())
                .expect("execution identity digest");
        let provider_identity = nq_core::ProviderIdentityV1 {
            schema: nq_core::ProviderIdentitySchema::V1,
            kind: nq_core::ProviderKind::LocalHelper,
            provider_semantic_id: provider_semantic_id.clone(),
            provider_admission_id: nq_protocol::Sha256Digest::parse(
                provider_admission.provider_admission_id.clone(),
            )
            .expect("provider admission digest"),
            source_admission_id: admission_id.to_owned(),
            binding_digest: binding_digest.clone(),
            artifact_digest: admission_identity.helper_artifact_digest.clone(),
            execution_identity_digest: execution_identity_digest.clone(),
            configuration_digest: admission_identity.config_digest.clone(),
            protocol_identity: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
            conformance_corpus_digest: nq_protocol::Sha256Digest::parse(
                conformance.protocol_corpus_digest.clone(),
            )
            .expect("corpus digest"),
            conformance_tool_version: conformance.tool_version.clone(),
            conformance: conformance.clone(),
            profile_semantic_id: admission_identity.profile_semantic_id.clone(),
            evaluator_artifact_digest: admission_identity.evaluator_artifact_digest.clone(),
            admission_context_digest: nq_protocol::Sha256Digest::parse(
                admission.admission_context_digest.clone(),
            )
            .expect("admission context digest"),
        };
        let checkpoint_contract_digest = digest("checkpoint");
        let intake_id = "intake-archive-transport";
        let attempt_id = "attempt-archive-transport";
        let run_id = "run-archive-transport";
        let context = nq_core::ProviderIntakeContextV1 {
            schema: nq_core::ProviderIntakeContextSchema::V1,
            intake_id: intake_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            run_id: run_id.to_owned(),
            request: request.clone(),
            provider: provider_identity,
            origin_carrier: "stdio".to_owned(),
            deadline_at: chrono::DateTime::parse_from_rfc3339("2026-07-20T12:00:01Z")
                .expect("provider deadline")
                .with_timezone(&chrono::Utc),
            checkpoint_contract_digest: checkpoint_contract_digest.clone(),
        };
        let interpretation = nq_core::ProviderResponseInterpretationV1::Validated { response };
        let idempotency_key = nq_store::provider_idempotency_key(
            &provider_admission.provider_admission_id,
            attempt_id,
        )
        .expect("derive provider idempotency identity");
        let collection = nq_store::CollectionInput {
            intake: nq_store::ProviderIntakeInput {
                intake_id: intake_id.to_owned(),
                attempt_id: attempt_id.to_owned(),
                idempotency_key,
                request_id: request_id.to_owned(),
                provider_admission_id: provider_admission.provider_admission_id,
                source_admission_id: admission_id.to_owned(),
                provider_sequence: None,
                origin_carrier: "stdio".to_owned(),
                deadline_at: "2026-07-20T12:00:01Z".to_owned(),
                checkpoint_contract_digest: checkpoint_contract_digest.as_str().to_owned(),
                execution_identity_digest,
                admission_context_digest: nq_protocol::Sha256Digest::parse(
                    admission.admission_context_digest,
                )
                .expect("admission context digest"),
                provider_semantic_id,
                provider_artifact_digest: admission_identity.helper_artifact_digest,
                provider_protocol_identity: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                provider_config_digest: admission_identity.config_digest,
                binding_digest: binding_digest.as_str().to_owned(),
                instance_id: instance_id.to_owned(),
                profile_id: "nq.conformance".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest: profile_digest.clone(),
                profile_semantic_id: admission_identity.profile_semantic_id,
                evaluator_artifact_digest: admission_identity.evaluator_artifact_digest,
                context: canonical(&context),
                interpretation_kind: "provider_refusal".to_owned(),
                interpretation: canonical(&interpretation),
                native_outcome_kind: "response".to_owned(),
                native_outcome: canonical(&resource_outcome),
                raw_bytes: raw_bytes.clone(),
                started_at: "2026-07-20T12:00:00Z".to_owned(),
                finished_at: "2026-07-20T12:00:00Z".to_owned(),
                received_at: "2026-07-20T12:00:00Z".to_owned(),
            },
            run: nq_store::RunInput {
                run_id: run_id.to_owned(),
                request_id: request_id.to_owned(),
                instance_id: instance_id.to_owned(),
                admission_id: Some(admission_id.to_owned()),
                binding_digest: binding_digest.into_string(),
                checkpoint_contract_digest: checkpoint_contract_digest.into_string(),
                profile_id: "nq.conformance".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest,
                carrier: "stdio".to_owned(),
                started_at: "2026-07-20T12:00:00Z".to_owned(),
                deadline_at: "2026-07-20T12:00:01Z".to_owned(),
                finished_at: "2026-07-20T12:00:00Z".to_owned(),
                acquisition_outcome: "response".to_owned(),
                execution_identity,
                resource_outcome: canonical(&resource_outcome),
            },
            submission: Some(nq_store::SubmissionInput {
                submission_id: "submission-archive-transport".to_owned(),
                raw_bytes,
                received_at: "2026-07-20T12:00:00Z".to_owned(),
                protocol_outcome: "valid_refusal".to_owned(),
                disposition: nq_store::SubmissionDisposition::Rejected {
                    refusal: nq_store::RefusalInput {
                        // SQL projections are self-consistent, but this ID
                        // deliberately disagrees with the canonical object.
                        refusal_id: if mismatch_refusal_identity {
                            "refusal-in-sql-row".to_owned()
                        } else {
                            governed_refusal_id.to_owned()
                        },
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
            .begin_writer_session()
            .expect("begin writer session")
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
        store
            .provider_intake(intake_id)
            .expect("query provider intake")
            .expect("provider intake persists")
    }

    fn append_mismatched_typed_custody(database: &Path) {
        let _ = append_provider_intake_collection(database, true);
    }

    fn write_config(root: &Path, database: &Path) -> PathBuf {
        let config = root.join("nq.toml");
        fs::write(
            &config,
            format!(
                "schema = \"nq.config.v2\"\ndatabase_path = \"{}\"\nsocket_path = \"{}\"\n\
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
        drop(Store::initialize_unqualified_storage(&database).expect("init store"));
        let config = write_config(root, &database);
        let archive = root.join("archive");
        create_archive(&config, &archive).expect("create archive");
        archive
    }

    fn diagnostic_artifact_archive(root: &Path) -> PathBuf {
        let database = root.join("nq.db");
        let mut store = Store::initialize_unqualified_storage(&database).expect("init store");
        let bytes = include_bytes!("../../../diagnostic-contract/fixtures/valid/positive.json");
        let document = nq_store::CanonicalDocument::from_canonical_bytes(bytes.to_vec())
            .expect("positive diagnostic fixture is canonical");
        let diagnostic = nq_core::DiagnosticExecutionV1::decode_canonical(document.as_bytes())
            .expect("positive diagnostic fixture reopens");
        store
            .begin_writer_session()
            .expect("begin writer session")
            .import_diagnostic_artifact(&nq_store::DiagnosticArtifactImportInput {
                import_id: "archive-current-available".to_owned(),
                artifact_id: diagnostic.artifact_id.0,
                contract_schema: nq_core::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA
                    .to_owned(),
                canonical_bytes: document,
                imported_at: "2026-07-28T12:00:00Z".to_owned(),
            })
            .expect("import current diagnostic artifact");

        let future_id = nq_protocol::sha256_bytes(b"archive-future-available");
        let future = canonical(&serde_json::json!({
            "schema": "nq.future_diagnostic_execution.v2",
            "artifact_id": future_id,
        }));
        store
            .begin_writer_session()
            .expect("begin writer session")
            .import_diagnostic_artifact(&nq_store::DiagnosticArtifactImportInput {
                import_id: "archive-future-available".to_owned(),
                artifact_id: future_id,
                contract_schema: "nq.future_diagnostic_execution.v2".to_owned(),
                canonical_bytes: future,
                imported_at: "2026-07-28T12:00:01Z".to_owned(),
            })
            .expect("import unsupported available artifact");

        store
            .begin_writer_session()
            .expect("begin writer session")
            .import_unavailable_diagnostic_artifact(
                &nq_store::UnavailableDiagnosticArtifactImportInput {
                    import_id: "archive-current-unavailable".to_owned(),
                    artifact_id: nq_protocol::sha256_bytes(b"archive-current-unavailable-id"),
                    contract_schema: nq_core::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA
                        .to_owned(),
                    canonical_bytes_sha256: nq_protocol::sha256_bytes(
                        b"archive-current-unavailable-bytes",
                    ),
                    canonical_bytes_length: 32,
                    imported_at: "2026-07-28T12:00:02Z".to_owned(),
                },
            )
            .expect("commit unavailable current artifact");
        store
            .begin_writer_session()
            .expect("begin writer session")
            .import_unavailable_diagnostic_artifact(
                &nq_store::UnavailableDiagnosticArtifactImportInput {
                    import_id: "archive-future-unavailable".to_owned(),
                    artifact_id: nq_protocol::sha256_bytes(b"archive-future-unavailable-id"),
                    contract_schema: "nq.future_diagnostic_execution.v2".to_owned(),
                    canonical_bytes_sha256: nq_protocol::sha256_bytes(
                        b"archive-future-unavailable-bytes",
                    ),
                    canonical_bytes_length: 31,
                    imported_at: "2026-07-28T12:00:03Z".to_owned(),
                },
            )
            .expect("commit unavailable unsupported artifact");
        drop(store);
        let config = write_config(root, &database);
        let archive = root.join("archive");
        create_archive(&config, &archive).expect("create diagnostic artifact archive");
        archive
    }

    fn provider_archive(root: &Path) -> (PathBuf, nq_store::ProviderIntakeRow, Vec<u8>) {
        let database = root.join("nq.db");
        drop(Store::initialize_unqualified_storage(&database).expect("init store"));
        let expected = append_provider_intake_collection(&database, false);
        let raw_bytes = Store::open(&database)
            .expect("reopen provider source")
            .provider_intake_raw_bytes(&expected.intake_id)
            .expect("query provider raw bytes")
            .expect("provider raw bytes exist");
        let config = write_config(root, &database);
        let archive = root.join("archive");
        create_archive(&config, &archive).expect("create provider archive");
        (archive, expected, raw_bytes)
    }

    /// Replace typed provider documents while making every store-level digest
    /// and the durable acknowledgment internally self-consistent. The exact raw
    /// provider bytes remain untouched, so typed reconstruction—not the store's
    /// self-consistency checks—must decide whether the documents correspond.
    #[allow(clippy::too_many_lines)]
    fn reseal_provider_documents(
        archive: &Path,
        expected: &nq_store::ProviderIntakeRow,
        context: &nq_store::CanonicalDocument,
        interpretation: &nq_store::CanonicalDocument,
    ) {
        let replay = canonical(&serde_json::json!({
            "schema": "nq.provider_intake_replay.v1",
            "idempotency_key": expected.idempotency_key,
            "attempt_id": expected.attempt_id,
            "request_id": expected.request_id,
            "provider_admission_id": expected.provider_admission_id,
            "source_admission_id": expected.source_admission_id,
            "provider_sequence": expected.provider_sequence,
            "origin_carrier": expected.origin_carrier,
            "deadline_at": expected.deadline_at,
            "checkpoint_contract_digest": expected.checkpoint_contract_digest,
            "execution_identity_digest": expected.execution_identity_digest,
            "admission_context_digest": expected.admission_context_digest,
            "provider_semantic_id": expected.provider_semantic_id,
            "provider_artifact_digest": expected.provider_artifact_digest,
            "provider_protocol_identity": expected.provider_protocol_identity,
            "provider_config_digest": expected.provider_config_digest,
            "binding_digest": expected.binding_digest,
            "instance_id": expected.instance_id,
            "profile_id": expected.profile_id,
            "profile_version": expected.profile_version,
            "profile_digest": expected.profile_digest,
            "profile_semantic_id": expected.profile_semantic_id,
            "evaluator_artifact_digest": expected.evaluator_artifact_digest,
            "context_digest": context.digest(),
            "interpretation_kind": expected.interpretation_kind,
            "interpretation_digest": interpretation.digest(),
            "native_outcome_kind": expected.native_outcome_kind,
            "native_outcome_digest": expected.native_outcome_digest,
            "raw_sha256": expected.raw_sha256,
            "started_at": expected.started_at,
            "finished_at": expected.finished_at,
        }));
        let intake = canonical(&serde_json::json!({
            "schema": nq_store::PROVIDER_INTAKE_SCHEMA,
            "intake_id": expected.intake_id,
            "replay_digest": replay.digest(),
            "received_at": expected.received_at,
        }));
        let acknowledgment = &expected.acknowledgment;
        let acknowledgment_detail = canonical(&serde_json::json!({
            "schema": nq_store::PROVIDER_INTAKE_ACK_SCHEMA,
            "acknowledgment_id": acknowledgment.acknowledgment_id,
            "intake_id": acknowledgment.intake_id,
            "attempt_id": acknowledgment.attempt_id,
            "run_id": acknowledgment.run_id,
            "provider_admission_id": acknowledgment.provider_admission_id,
            "intake_digest": intake.digest(),
            "raw_sha256": acknowledgment.raw_sha256,
            "status_event_id": acknowledgment.status_event_id,
            "canonical_result_digest": acknowledgment.canonical_result_digest,
            "committed_at": acknowledgment.committed_at,
            "establishes": "durable_custody_and_canonical_processing",
            "does_not_establish": [
                "report_admission",
                "detector_result",
                "health",
                "testimonial_sufficiency",
                "authority",
                "external_obligation_discharge",
            ],
        }));

        let database = archive.join("db/nq.db");
        let connection = rusqlite::Connection::open(&database).expect("open archive database");
        connection
            .execute_batch(
                "DROP TRIGGER immutable_provider_intake_attempts_update;
                 DROP TRIGGER immutable_provider_intake_acknowledgments_update;",
            )
            .expect("open append-only rows for hostile substitution");
        connection
            .execute(
                "UPDATE provider_intake_attempts
                    SET context_json = ?1, context_digest = ?2,
                        interpretation_json = ?3, interpretation_digest = ?4,
                        replay_digest = ?5, intake_digest = ?6
                  WHERE intake_id = ?7",
                rusqlite::params![
                    context.as_bytes(),
                    context.digest(),
                    interpretation.as_bytes(),
                    interpretation.digest(),
                    replay.digest(),
                    intake.digest(),
                    expected.intake_id,
                ],
            )
            .expect("replace context and all store-level intake digests");
        connection
            .execute(
                "UPDATE provider_intake_acknowledgments
                    SET detail_json = ?1, acknowledgment_digest = ?2
                  WHERE intake_id = ?3",
                rusqlite::params![
                    acknowledgment_detail.as_bytes(),
                    acknowledgment_detail.digest(),
                    expected.intake_id,
                ],
            )
            .expect("replace acknowledgment with self-consistent intake digest");
        connection
            .execute_batch(
                "CREATE TRIGGER immutable_provider_intake_attempts_update BEFORE UPDATE ON provider_intake_attempts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;
                 CREATE TRIGGER immutable_provider_intake_acknowledgments_update BEFORE UPDATE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;",
            )
            .expect("restore exact append-only schema");
        drop(connection);
        reseal_after_database_change(archive);
    }

    fn substitute_provider_context_and_reseal(
        archive: &Path,
        expected: &nq_store::ProviderIntakeRow,
    ) {
        let mut context: nq_core::ProviderIntakeContextV1 =
            serde_json::from_slice(&expected.context_json).expect("decode provider context");
        context.request.binding.subject =
            nq_protocol::SubjectId::new("archive:substituted-provider-subject")
                .expect("substituted subject identity");
        let context = canonical(&context);
        let interpretation =
            nq_store::CanonicalDocument::from_canonical_bytes(expected.interpretation_json.clone())
                .expect("reopen exact provider interpretation");
        reseal_provider_documents(archive, expected, &context, &interpretation);
    }

    fn substitute_provider_interpretation_and_reseal(
        archive: &Path,
        expected: &nq_store::ProviderIntakeRow,
    ) {
        let context =
            nq_store::CanonicalDocument::from_canonical_bytes(expected.context_json.clone())
                .expect("reopen exact provider context");
        let mut interpretation: nq_core::ProviderResponseInterpretationV1 =
            serde_json::from_slice(&expected.interpretation_json)
                .expect("decode provider interpretation");
        let nq_core::ProviderResponseInterpretationV1::Validated { response } = &mut interpretation
        else {
            panic!("fixture interpretation is validated")
        };
        let nq_protocol::ResponseOutcome::Refusal { refusal } = &mut response.outcome else {
            panic!("fixture interpretation contains a provider refusal")
        };
        refusal.retriable = !refusal.retriable;
        let interpretation = canonical(&interpretation);
        reseal_provider_documents(archive, expected, &context, &interpretation);
    }

    #[allow(clippy::too_many_lines)]
    fn migrated_v3_archive(root: &Path) -> PathBuf {
        let database = root.join("nq-v3.db");
        let connection = rusqlite::Connection::open(&database).expect("create schema-v3 store");
        connection
            .execute_batch(include_str!("../../nq-store/src/schema_v3.sql"))
            .expect("install exact frozen schema v3");
        connection
            .execute(
                "INSERT INTO schema_metadata (
                    singleton, product, schema_version, schema_artifact_digest, initialized_at
                 ) VALUES (1, 'nq-ng', 3, ?1, ?2)",
                rusqlite::params![nq_store::SCHEMA_V3_ARTIFACT_DIGEST, "2026-07-20T12:00:00Z"],
            )
            .expect("record exact schema-v3 identity");
        connection
            .execute(
                "INSERT INTO genesis_records (
                    genesis_id, legacy_manifest_digest, created_at, detail_json
                 ) VALUES (?1, NULL, ?2, CAST(?3 AS BLOB))",
                rusqlite::params![
                    FIXTURE_OCCURRENCE_ID,
                    "2026-07-20T12:00:00Z",
                    br#"{"schema":"nq.archive_test_occurrence.v1"}"#,
                ],
            )
            .expect("append exact legacy occurrence identity");
        let profile = nq_profiles::resolve_profile("nq.conformance", 1)
            .expect("compiled legacy archive fixture profile");
        let descriptor = canonical(profile.descriptor());
        let profile_digest = descriptor.digest().to_owned();
        let profile_semantic_id = nq_profiles::profile_semantic_id(profile.descriptor())
            .expect("compiled legacy profile semantics");
        let detector_identity =
            nq_store::detector_suite_identity_digest(profile.detectors().iter().map(|detector| {
                detector
                    .descriptor()
                    .digest()
                    .expect("compiled legacy detector identity")
            }))
            .expect("compiled legacy detector suite");
        connection
            .execute(
                "INSERT INTO profile_descriptor_snapshots (
                    profile_id, profile_version, profile_digest, descriptor_json, recorded_at
                 ) VALUES ('nq.conformance', '1', ?1, ?2, ?3)",
                rusqlite::params![
                    profile_digest,
                    descriptor.as_bytes(),
                    "2026-07-20T12:00:00Z"
                ],
            )
            .expect("append exact schema-v3 profile descriptor");
        let config_digest = nq_protocol::sha256_bytes(b"legacy-config");
        let helper_artifact_digest = nq_protocol::sha256_bytes(b"legacy-helper");
        let evaluator_source_digest = nq_protocol::sha256_bytes(b"legacy-evaluator-source");
        let evaluator_artifact_digest = nq_protocol::sha256_bytes(b"legacy-evaluator");
        let protocol_version = nq_protocol::HELPER_PROTOCOL_VERSION;
        let admission_context_digest = nq_protocol::semantic_digest(&serde_json::json!({
            "admission_context_schema": nq_store::ADMISSION_CONTEXT_SCHEMA,
            "config_digest": config_digest,
            "detector_identity_digest": detector_identity,
            "evaluator_artifact_digest": evaluator_artifact_digest,
            "evaluator_source_digest": evaluator_source_digest,
            "helper_artifact_digest": helper_artifact_digest,
            "profile_semantic_id": profile_semantic_id.as_str(),
            "protocol_version": protocol_version,
        }))
        .expect("derive exact schema-v3 admission context")
        .into_string();
        let source_admission_id = "00000000-0000-4000-8000-000000000201";
        connection
            .execute(
                "INSERT INTO admission_records (
                    admission_id, instance_id, config_digest, helper_artifact_digest,
                    profile_semantic_id, detector_identity_digest, evaluator_source_digest,
                    evaluator_artifact_digest, admission_context_digest, execution_chain_json,
                    profile_id, profile_version, profile_digest, protocol_version,
                    target_triple, artifact_identity_method, platform_runtime_version,
                    capability_grant_json, conformance_json, lock_json, admitted_at,
                    operator_identity_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                           CAST(?10 AS BLOB), 'nq.conformance', '1', ?11, ?12,
                           'fixture-target', 'fixture', 'fixture', CAST(?13 AS BLOB),
                           CAST(?14 AS BLOB), CAST(?15 AS BLOB), ?16, CAST(?17 AS BLOB))",
                rusqlite::params![
                    source_admission_id,
                    "legacy-archive-provider",
                    config_digest.as_str(),
                    helper_artifact_digest.as_str(),
                    profile_semantic_id.as_str(),
                    detector_identity.as_str(),
                    evaluator_source_digest.as_str(),
                    evaluator_artifact_digest.as_str(),
                    admission_context_digest,
                    br#"{"artifacts":[]}"#,
                    profile_digest,
                    protocol_version,
                    br"[]",
                    br#"{"fixture":true}"#,
                    br#"{"fixture":true}"#,
                    "2026-07-20T12:00:00Z",
                    br#"{"uid":991}"#,
                ],
            )
            .expect("append exact schema-v3 source admission");
        let resource_outcome = nq_core::RunResourceOutcomeV1 {
            schema: nq_core::RunResourceOutcomeSchema::V1,
            duration_ms: 1,
            exit_code: None,
            hard_limits: nq_core::RunHardLimits {
                address_space_bytes_per_process: 1,
                cpu_seconds_per_process: 1,
                processes_per_execution_uid: 1,
                open_files_per_process: 1,
                file_bytes_per_regular_file: 1,
                core_bytes: 0,
            },
            stdout_bytes_retained: 0,
            stderr_bytes_retained: 0,
            stderr_hex: String::new(),
            outcome: nq_core::runner::AcquisitionOutcome::ExchangeTimeout {
                phase: nq_core::ExchangeTimeoutPhase::ReadResponse,
            },
        };
        let outcome = nq_core::CollectionOutcome::acquisition_failed(
            "legacy-archive-provider".to_owned(),
            "run-legacy-provider-gap".to_owned(),
            resource_outcome.outcome.clone(),
        )
        .expect("construct exact legacy run result");
        let resource_outcome = canonical(&resource_outcome);
        let outcome = canonical(&outcome);
        connection
            .execute(
                "INSERT INTO watcher_runs (
                    run_id, request_id, instance_id, admission_id, binding_digest,
                    checkpoint_contract_digest, profile_id, profile_version, profile_digest,
                    carrier, started_at, deadline_at, finished_at, acquisition_outcome,
                    execution_identity_json, resource_outcome_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'nq.conformance', '1', ?7, 'stdio',
                           ?8, ?9, ?10, 'timeout', CAST(?11 AS BLOB), ?12)",
                rusqlite::params![
                    "run-legacy-provider-gap",
                    "request-legacy-provider-gap",
                    "legacy-archive-provider",
                    source_admission_id,
                    nq_protocol::sha256_bytes(b"legacy-binding").into_string(),
                    nq_protocol::sha256_bytes(b"legacy-checkpoint").into_string(),
                    profile_digest,
                    "2026-07-20T12:00:00Z",
                    "2026-07-20T12:00:01Z",
                    "2026-07-20T12:00:01Z",
                    br#"{"fixture":true}"#,
                    resource_outcome.as_bytes(),
                ],
            )
            .expect("append schema-v3 watcher run");
        connection
            .execute(
                "INSERT INTO status_events (
                    status_event_id, component_kind, component_id, run_id,
                    state, code, detail_json, observed_at
                 ) VALUES (?1, 'instance', ?2, ?3, 'failed', 'collection_failed', ?4, ?5)",
                rusqlite::params![
                    "status-legacy-provider-gap",
                    "legacy-archive-provider",
                    "run-legacy-provider-gap",
                    outcome.as_bytes(),
                    "2026-07-20T12:00:01Z",
                ],
            )
            .expect("append schema-v3 canonical run result");
        connection
            .execute(
                "INSERT INTO status_current (
                    component_kind, component_id, latest_status_event_id
                 ) VALUES ('instance', ?1, ?2)",
                rusqlite::params!["legacy-archive-provider", "status-legacy-provider-gap"],
            )
            .expect("materialize schema-v3 status projection");
        drop(connection);

        let backup = root.join("nq-v3.pre-upgrade.db");
        let backup = Store::backup_v3_verified(&database, &backup)
            .expect("create exact verified schema-v3 backup");
        let receipt = nq_store::UpgradeReceiptInput {
            receipt_id: "upgrade-archive-v3-v4".to_owned(),
            from_schema_version: 3,
            to_schema_version: 4,
            migrations: canonical(&serde_json::json!(["schema_v3_to_v4_provider_intake"])),
            binary_digest: nq_protocol::sha256_bytes(b"archive-upgrade-binary").into_string(),
            backup_digest: backup.sha256,
            backup_location: backup.path.to_string_lossy().into_owned(),
            started_at: "2026-07-20T12:00:02Z".to_owned(),
            finished_at: "2026-07-20T12:00:03Z".to_owned(),
            result: "migrated".to_owned(),
            operator_identity: canonical(&serde_json::json!({"uid": 991})),
            verification: canonical(&serde_json::json!({
                "integrity": "ok",
                "source_schema_version": 3,
                "source_schema_artifact_digest": nq_store::SCHEMA_V3_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_provider_intake": "explicit_gap_only",
                "provider_intakes_synthesized": false,
                "acknowledgments_synthesized": false,
            })),
        };
        Store::upgrade_v3_to_v4(&database, &receipt).expect("upgrade schema-v3 store");
        let v4_backup = root.join("nq-v4.pre-upgrade.db");
        let v4_backup =
            Store::backup_v4_verified(&database, &v4_backup).expect("backup schema-v4 store");
        let v4_receipt = nq_store::UpgradeReceiptInput {
            receipt_id: "upgrade-archive-v4-v5".to_owned(),
            from_schema_version: 4,
            to_schema_version: 5,
            migrations: canonical(&serde_json::json!(["schema_v4_to_v5_diagnostic_artifacts"])),
            binary_digest: nq_protocol::sha256_bytes(b"archive-upgrade-binary").into_string(),
            backup_digest: v4_backup.sha256,
            backup_location: v4_backup.path.to_string_lossy().into_owned(),
            started_at: "2026-07-20T12:00:04Z".to_owned(),
            finished_at: "2026-07-20T12:00:05Z".to_owned(),
            result: "migrated".to_owned(),
            operator_identity: canonical(&serde_json::json!({"uid": 991})),
            verification: canonical(&serde_json::json!({
                "integrity": "ok",
                "source_schema_version": 4,
                "source_schema_artifact_digest": nq_store::SCHEMA_V4_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_diagnostic_artifacts": "no_durable_commitments",
                "diagnostic_artifacts_synthesized": false,
            })),
        };
        Store::upgrade_v4_to_v5(&database, &v4_receipt).expect("upgrade schema-v4 store");
        let v5_backup = root.join("nq-v5.pre-upgrade.db");
        let v5_backup =
            Store::backup_v5_verified(&database, &v5_backup).expect("backup schema-v5 store");
        let v5_receipt = nq_store::UpgradeReceiptInput {
            receipt_id: "upgrade-archive-v5-v6".to_owned(),
            from_schema_version: 5,
            to_schema_version: 6,
            migrations: canonical(&serde_json::json!(["schema_v5_to_v6_runtime_ledger"])),
            binary_digest: nq_protocol::sha256_bytes(b"archive-upgrade-binary").into_string(),
            backup_digest: v5_backup.sha256,
            backup_location: v5_backup.path.to_string_lossy().into_owned(),
            started_at: "2026-07-20T12:00:06Z".to_owned(),
            finished_at: "2026-07-20T12:00:07Z".to_owned(),
            result: "migrated".to_owned(),
            operator_identity: canonical(&serde_json::json!({"uid": 991})),
            verification: canonical(&serde_json::json!({
                "integrity": "ok",
                "source_schema_version": 5,
                "source_schema_artifact_digest": nq_store::SCHEMA_V5_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_runtime_records": "no_durable_commitments",
                "runtime_records_synthesized": false,
                "diagnostic_execution_bindings_synthesized": false,
            })),
        };
        Store::upgrade_v5_to_v6(&database, &v5_receipt).expect("upgrade schema-v5 store");
        let v6_backup = root.join("nq-v6.pre-upgrade.db");
        let v6_backup =
            Store::backup_v6_verified(&database, &v6_backup).expect("backup schema-v6 store");
        let v6_receipt = nq_store::UpgradeReceiptInput {
            receipt_id: "upgrade-archive-v6-v7".to_owned(),
            from_schema_version: 6,
            to_schema_version: 7,
            migrations: canonical(&serde_json::json!(["schema_v6_to_v7_runtime_dependencies"])),
            binary_digest: nq_protocol::sha256_bytes(b"archive-upgrade-binary").into_string(),
            backup_digest: v6_backup.sha256,
            backup_location: v6_backup.path.to_string_lossy().into_owned(),
            started_at: "2026-07-20T12:00:08Z".to_owned(),
            finished_at: "2026-07-20T12:00:09Z".to_owned(),
            result: "migrated".to_owned(),
            operator_identity: canonical(&serde_json::json!({"uid": 991})),
            verification: canonical(&serde_json::json!({
                "integrity": "ok",
                "source_schema_version": 6,
                "source_schema_artifact_digest": nq_store::SCHEMA_V6_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_dependency_binding": "legacy_unbound",
                "dependency_generations_synthesized": false,
                "trust_anchors_synthesized": false,
            })),
        };
        drop(Store::upgrade_v6_to_v7(&database, &v6_receipt).expect("upgrade schema-v6 store"));
        let v7_backup =
            Store::backup_v7_verified(&database, root.join("nq-v7.pre-authority-migration.db"))
                .expect("backup exact schema-v7 Store");
        let dependencies =
            authenticated_runtime_dependencies(72, Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let authority = RawAuthorityFixture::accepted_migration_with_anchor(
            dependencies
                .custody()
                .trust_anchor_id()
                .expect("archive migration dependency anchor"),
            OldRootState::Rootless,
            None,
        );
        let custody = authority.custody();
        let migration_receipt = authority
            .migration_receipt()
            .expect("accepted migration fixture");
        let resident = RuntimeAuthorityResidentBinding {
            resident_identity: FIXTURE_RESIDENT_ID.to_owned(),
            resident_generation: FIXTURE_RESIDENT_GENERATION,
            host_role: FIXTURE_HOST_ROLE.to_owned(),
            role_manifest_generation: FIXTURE_ROLE_MANIFEST_GENERATION,
            domain: FIXTURE_DOMAIN.to_owned(),
            policy_floor: 1,
        };
        let store = HostRoleRuntime::migrate_v7_runtime_authority(
            &database,
            &v7_backup,
            dependencies,
            &custody,
            &migration_receipt,
            &resident,
        )
        .expect("migrate legacy archive fixture into Gen4 authority law");
        drop(store);
        let config = write_config(root, &database);
        let archive = root.join("archive");
        create_archive(&config, &archive).expect("create migrated-v3 archive");
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
        assert_eq!(
            report.historical_admitted_report_semantics_verified,
            Some(true)
        );
        assert_eq!(report.historical_admitted_reports_verified, Some(0));
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
        assert_eq!(
            report.historical_provider_intake_semantics_verified,
            Some(true)
        );
        assert_eq!(report.historical_provider_intake_records_verified, Some(0));
        assert_eq!(
            report.historical_provider_intake_acknowledgments_verified,
            Some(0)
        );
        assert_eq!(
            report.historical_legacy_provider_intake_gaps_verified,
            Some(0)
        );
        assert!(!report.grants_authority);
    }

    #[test]
    fn diagnostic_artifact_availability_and_schema_support_survive_archive() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = diagnostic_artifact_archive(dir.path());
        let report = verify_archive(&archive).expect("verify diagnostic artifact archive");
        assert_eq!(
            report.historical_diagnostic_artifact_semantics_verified,
            Some(true)
        );
        assert_eq!(
            report.historical_diagnostic_artifact_commitments_verified,
            Some(4)
        );
        assert_eq!(report.historical_diagnostic_artifacts_reopened, Some(1));
        assert_eq!(
            report.historical_diagnostic_artifacts_committed_unavailable,
            Some(1)
        );
        assert_eq!(
            report.historical_unsupported_diagnostic_artifacts_available,
            Some(1)
        );
        assert_eq!(
            report.historical_unsupported_diagnostic_artifacts_committed_unavailable,
            Some(1)
        );
        assert!(!report.grants_authority);
    }

    #[test]
    fn provider_intake_and_acknowledgment_survive_backup_and_archive_reopen_exactly() {
        let dir = tempfile::tempdir().expect("dir");
        let (archive, expected, raw_bytes) = provider_archive(dir.path());

        let report = verify_archive(&archive).expect("verify provider archive");
        assert_eq!(
            report.historical_provider_intake_semantics_verified,
            Some(true)
        );
        assert_eq!(report.historical_provider_intake_records_verified, Some(1));
        assert_eq!(
            report.historical_provider_intake_acknowledgments_verified,
            Some(1)
        );
        assert_eq!(
            report.historical_legacy_provider_intake_gaps_verified,
            Some(0)
        );
        assert!(!report.grants_authority);

        let reopened = Store::open_immutable(archive.join("db/nq.db"))
            .expect("independently reopen archived provider store");
        assert_eq!(
            reopened
                .provider_intake(&expected.intake_id)
                .expect("reopen intake by identity"),
            Some(expected.clone())
        );
        assert_eq!(
            reopened
                .provider_intake_raw_bytes(&expected.intake_id)
                .expect("reopen exact raw bytes"),
            Some(raw_bytes)
        );
        let (acknowledgment, canonical_result) = reopened
            .provider_intake_acknowledgment(&expected.idempotency_key)
            .expect("reopen acknowledgment")
            .expect("acknowledgment exists");
        assert_eq!(acknowledgment, expected.acknowledgment);
        assert_eq!(
            acknowledgment.canonical_result_digest,
            canonical_result.digest()
        );
    }

    #[test]
    fn a_resealed_provider_acknowledgment_substitution_fails_closed() {
        let dir = tempfile::tempdir().expect("dir");
        let (archive, expected, _) = provider_archive(dir.path());
        let database = archive.join("db/nq.db");
        let connection = rusqlite::Connection::open(&database).expect("open archive database");
        connection
            .execute_batch(
                "DROP TRIGGER immutable_provider_intake_acknowledgments_update;
                 UPDATE provider_intake_acknowledgments
                    SET detail_json = CAST('{\"forged\":true}' AS BLOB)
                  WHERE intake_id = 'intake-archive-transport';
                 CREATE TRIGGER immutable_provider_intake_acknowledgments_update BEFORE UPDATE ON provider_intake_acknowledgments BEGIN SELECT RAISE(ABORT, 'append-only table'); END;",
            )
            .expect("substitute acknowledgment behind restored append-only schema");
        drop(connection);
        reseal_after_database_change(&archive);

        let error = verify_archive(&archive)
            .expect_err("substituted provider acknowledgment must fail closed");
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains(&expected.intake_id) && diagnostic.contains("acknowledgment"),
            "unexpected refusal: {diagnostic}"
        );
    }

    #[test]
    fn a_resealed_typed_context_substitution_fails_against_exact_raw_bytes() {
        let dir = tempfile::tempdir().expect("dir");
        let (archive, expected, _) = provider_archive(dir.path());
        substitute_provider_context_and_reseal(&archive, &expected);

        let error = verify_archive(&archive)
            .expect_err("self-consistent store digests must not hide typed context substitution");
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("provider intake")
                && diagnostic.contains("raw custody")
                && !diagnostic.contains("substituted canonical bytes or derived digests"),
            "typed historical verification did not own the refusal: {diagnostic}"
        );
    }

    #[test]
    fn a_resealed_typed_interpretation_substitution_fails_against_exact_raw_bytes() {
        let dir = tempfile::tempdir().expect("dir");
        let (archive, expected, _) = provider_archive(dir.path());
        substitute_provider_interpretation_and_reseal(&archive, &expected);

        let error = verify_archive(&archive).expect_err(
            "self-consistent store digests must not hide typed interpretation substitution",
        );
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("provider intake")
                && diagnostic.contains("raw custody")
                && !diagnostic.contains("substituted canonical bytes or derived digests"),
            "typed historical verification did not own the refusal: {diagnostic}"
        );
    }

    #[test]
    fn migrated_v3_history_reopens_as_an_explicit_gap_not_a_synthetic_intake() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = migrated_v3_archive(dir.path());

        let report = verify_archive(&archive).expect("verify migrated-v3 archive");
        assert_eq!(
            report.historical_provider_intake_semantics_verified,
            Some(true)
        );
        assert_eq!(report.historical_provider_intake_records_verified, Some(0));
        assert_eq!(
            report.historical_provider_intake_acknowledgments_verified,
            Some(0)
        );
        assert_eq!(
            report.historical_legacy_provider_intake_gaps_verified,
            Some(1)
        );

        let reopened = Store::open_immutable(archive.join("db/nq.db"))
            .expect("reopen migrated archive database");
        assert!(
            reopened
                .provider_intakes_bounded(nq_store::MAX_PUBLIC_QUERY_ROWS, None)
                .expect("query real intakes")
                .is_empty(),
            "migration must not invent provider-intake evidence"
        );
        let gaps = reopened
            .legacy_provider_intake_gaps_bounded(nq_store::MAX_PUBLIC_QUERY_ROWS, None)
            .expect("query explicit migration gaps");
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].run_id, "run-legacy-provider-gap");
        assert_eq!(gaps[0].source_schema_version, 3);
        assert_eq!(
            gaps[0].source_schema_artifact_digest,
            nq_store::SCHEMA_V3_ARTIFACT_DIGEST
        );
        assert_eq!(gaps[0].limitation_code, "provider_intake_not_recorded");
    }

    #[test]
    fn a_resealed_legacy_gap_contradiction_fails_typed_archive_reopen() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = migrated_v3_archive(dir.path());
        let database = archive.join("db/nq.db");
        let connection = rusqlite::Connection::open(&database).expect("open archived database");
        let contradictory = canonical(&serde_json::json!({
            "schema": "nq.legacy_provider_intake_gap.v1",
            "source_schema_version": 4,
            "source_schema_artifact_digest": nq_store::SCHEMA_V3_ARTIFACT_DIGEST,
            "limitation": "schema v3 did not preserve a versioned provider intake or exact outer raw capture for every acquisition",
            "provider_intake_synthesized": false,
            "acknowledgment_synthesized": false,
        }));
        connection
            .execute_batch("DROP TRIGGER immutable_legacy_v3_watcher_run_intake_gaps_update;")
            .expect("drop append-only trigger for hostile mutation");
        connection
            .execute(
                "UPDATE legacy_v3_watcher_run_intake_gaps SET detail_json = ?1",
                [contradictory.as_bytes()],
            )
            .expect("install contradictory legacy gap");
        connection
            .execute_batch(
                "CREATE TRIGGER immutable_legacy_v3_watcher_run_intake_gaps_update BEFORE UPDATE ON legacy_v3_watcher_run_intake_gaps BEGIN SELECT RAISE(ABORT, 'append-only table'); END;",
            )
            .expect("restore append-only trigger");
        drop(connection);
        reseal_after_database_change(&archive);

        let error = verify_archive(&archive)
            .expect_err("contradictory legacy-gap receipt must fail typed reopen");
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("legacy provider-intake gap")
                && diagnostic.contains("substitutes or invents"),
            "unexpected legacy-gap diagnostic: {diagnostic}"
        );
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
        let mut session = store.begin_writer_session().expect("begin writer session");
        nq_core::engine::record_component_status(
            &mut session,
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
            &mut session,
            "instance",
            "legacy-instance",
            "failed",
            "collection_failed",
            &serde_json::to_value(current).expect("typed result serializes"),
        )
        .expect("append current typed status");
        drop(session);
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
        assert_eq!(verified.historical_admitted_report_semantics_verified, None);
        assert_eq!(verified.historical_admitted_reports_verified, None);
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
        drop(Store::initialize_unqualified_storage(&database).expect("init"));
        let config = write_config(dir.path(), &database);
        let archive = dir.path().join("archive");
        fs::create_dir(&archive).expect("pre-existing");
        assert!(create_archive(&config, &archive).is_err());
    }
}
