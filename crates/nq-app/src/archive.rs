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
struct ArchiveMetadata {
    archive_format: String,
    created_at: String,
    tool_version: String,
    tool_binary_digest: String,
    schema_version: i64,
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
    for line in manifest.lines() {
        let (hex, relative) = line
            .split_once("  ")
            .with_context(|| format!("malformed manifest line: {line}"))?;
        let path = root.join(relative);
        if !path.is_file() {
            bail!("manifest references a missing file: {relative}");
        }
        let actual = sha256_file(&path)?;
        if actual != format!("sha256:{hex}") {
            bail!("content file {relative} does not match its manifest digest");
        }
        covered.push(relative.to_owned());
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
        true
    } else {
        Store::backup_incompatible(&config.database_path, &db)?;
        false
    };

    // The exact verifier binary and interpretation config.
    let binary = std::env::current_exe()?;
    fs::copy(&binary, staging.join("bin/nq"))?;
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
pub fn verify_archive(archive: &Path) -> Result<VerifyReport> {
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
    let seal = fs::read_to_string(archive.join(SEAL_FILE)).context("read seal")?;
    if seal.trim() != sha256_bytes(&metadata_bytes) {
        bail!("archive seal does not match ARCHIVE.json");
    }
    // ARCHIVE.json binds the manifest.
    if metadata.manifest_sha256 != sha256_file(&archive.join(MANIFEST_FILE))? {
        bail!("MANIFEST.sha256 does not match the sealed manifest digest");
    }
    // The manifest binds every content file (missing/substituted/corrupt refuse).
    let covered = check_manifest(archive)?;

    // No unmanifested file may be present (insertion detection).
    let mut expected: Vec<String> = covered.clone();
    expected.extend([SEAL_FILE, ARCHIVE_FILE, MANIFEST_FILE].map(str::to_owned));
    expected.push("db".to_owned());
    expected.push("bin".to_owned());
    expected.push("config".to_owned());
    let mut present = enumerate_relative(archive, archive)?;
    present.sort();
    expected.sort();
    let present_files: Vec<&String> = present
        .iter()
        .filter(|entry| !archive.join(entry).is_dir())
        .collect();
    for entry in &present_files {
        if !expected.contains(entry) {
            bail!("archive contains an unmanifested file: {entry}");
        }
    }

    // Historical database verification: open the self-contained archived DB (not
    // the live store). If the source was recorded un-openable, the claim fails
    // closed. A schema this verifier cannot open refuses via Store::open.
    let historical_database_verified = if metadata.source_openable {
        let store = Store::open(archive.join("db/nq.db")).context(
            "open the preserved database (use the archive's own bin/nq if this refuses)",
        )?;
        store
            .validate()
            .context("validate the preserved database")?;
        Some(true)
    } else {
        None
    };

    Ok(VerifyReport {
        archive: archive.to_path_buf(),
        archive_format: metadata.archive_format,
        integrity_verified: true,
        historical_database_verified,
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
        if path.is_dir() {
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

    #[test]
    fn a_sealed_archive_verifies_and_grants_no_authority() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = valid_archive(dir.path());
        assert!(archive.join("SEAL").is_file());
        let report = verify_archive(&archive).expect("verify");
        assert!(report.integrity_verified);
        assert_eq!(report.historical_database_verified, Some(true));
        assert!(!report.grants_authority);
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
    }

    #[test]
    fn an_unknown_archive_format_refuses_clearly() {
        let dir = tempfile::tempdir().expect("dir");
        let archive = dir.path().join("future");
        fs::create_dir(&archive).expect("dir");
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
