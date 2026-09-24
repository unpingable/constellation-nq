//! First-party, one-shot stdio watcher for the compiled
//! `nq.host_filesystem_capacity/v1`, `nq.host_filesystem_inodes/v1`, and
//! `nq.host_memory/v1` profiles: closed branches selected by the exact
//! admitted profile, in the same way `nq-operator-beta-helper` selects its two.
//!
//! Read-only by construction: it reads `/etc/machine-id`, `/proc/self/mountinfo`,
//! one `/dev/disk/by-uuid` entry, and performs `open(O_PATH)`, `statx`, `fstat`
//! and `fstatfs` on the declared mountpoint only. It rejects non-ext4 and
//! subtree (bind) mounts before touching the path, so it never triggers an
//! automount and never blocks on a hard network mount. Identity or access
//! failures produce a Failed report with a typed error code, never absence.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt, io::AsRawFd},
    path::Path,
};

use chrono::{Duration, Utc};
use nix::{
    sys::statvfs::fstatvfs,
    time::{ClockId, clock_gettime},
};
use nq_profiles::{
    EvidenceBasis, ProfileModule, ReportInput, ScopeGrant, ValidationContext, VantageGrant,
    host_filesystem::FilesystemFailureCode,
    host_filesystem::{
        self, ACCESS_PATH, CAPABILITIES, COVERAGE_KIND, HostFilesystemScope, OBSERVATION_KIND,
        SCOPE_KIND,
    },
    host_memory,
    host_memory::MemoryFailureCode,
};
use nq_protocol::{
    BackendIdentity, BackendProvenance, Capability, CoverageDeclaration, CoverageKind,
    CoverageState, ErrorCode, ErrorSeverity, EvidenceReport, FramingError, HelperRequest,
    HelperResponse, ImplementationName, MAX_REQUEST_FRAME_BYTES, ObservationKind, Refusal,
    RefusalBoundary, RefusalCode, ReportError, ReportStatus, encode_ndjson, parse_request,
    validate_exchange,
};
use serde_json::{Value, json};
use thiserror::Error;

const MACHINE_ID_PATH: &str = "/etc/machine-id";
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
const BY_UUID_DIR: &str = "/dev/disk/by-uuid";
const MAX_MOUNTINFO_BYTES: usize = 1 << 20;
const PRESSURE_MEMORY_PATH: &str = "/proc/pressure/memory";

/// Failure before a valid bounded response can be written.
#[derive(Debug, Error)]
pub enum StdioError {
    /// Reading the one request frame failed.
    #[error("cannot read request: {0}")]
    Read(#[source] io::Error),
    /// The input exceeded the protocol request-frame ceiling.
    #[error("request frame exceeds {MAX_REQUEST_FRAME_BYTES} bytes")]
    RequestTooLarge,
    /// The request was not one strict, valid protocol frame.
    #[error("invalid request: {0}")]
    InvalidRequest(#[source] FramingError),
    /// No protocol-valid response can fit the request's own response bound.
    #[error("cannot construct a bounded response: {0}")]
    UnrepresentableResponse(String),
    /// Writing the response frame failed.
    #[error("cannot write response: {0}")]
    Write(#[source] io::Error),
}

/// Runs one request/response exchange on standard input and standard output.
///
/// # Errors
///
/// Returns [`StdioError`] when no request can be parsed, no valid response can
/// fit negotiated bounds, or stdio fails.
pub fn run_stdio() -> Result<(), StdioError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run(stdin.lock(), stdout.lock())
}

/// Runs one exchange over supplied streams (public for embedding tests).
///
/// # Errors
///
/// Returns [`StdioError`] under the same conditions as [`run_stdio`].
pub fn run(input: impl Read, mut output: impl Write) -> Result<(), StdioError> {
    let limit = u64::try_from(MAX_REQUEST_FRAME_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(8 * 1_024);
    input
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(StdioError::Read)?;
    if bytes.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(StdioError::RequestTooLarge);
    }
    let request = parse_request(&bytes).map_err(StdioError::InvalidRequest)?;
    let response = handle_request(&request, &LinuxSource, &LinuxBoottimeClock);
    let response = ensure_bounded_response(&request, response)?;
    let frame = encode_ndjson(&response)
        .map_err(|error| StdioError::UnrepresentableResponse(error.to_string()))?;
    output.write_all(&frame).map_err(StdioError::Write)?;
    output.flush().map_err(StdioError::Write)
}

/// Which compiled profile the request names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Branch {
    Capacity,
    Inodes,
    Memory,
}

impl Branch {
    fn module(self) -> &'static dyn ProfileModule {
        match self {
            Self::Capacity => &host_filesystem::CAPACITY_MODULE,
            Self::Inodes => &host_filesystem::INODES_MODULE,
            Self::Memory => &host_memory::MODULE,
        }
    }

    fn capabilities(self) -> &'static [&'static str] {
        match self {
            Self::Capacity | Self::Inodes => &CAPABILITIES,
            Self::Memory => &host_memory::CAPABILITIES,
        }
    }

    fn coverage(self) -> &'static str {
        match self {
            Self::Capacity | Self::Inodes => COVERAGE_KIND,
            Self::Memory => host_memory::COVERAGE_KIND,
        }
    }
}

/// A typed collection failure that becomes a Failed report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionFailure {
    /// Stable error code (see the profile design's refusal table).
    pub code: &'static str,
    /// Bounded operator-facing message.
    pub message: String,
    /// Whether a retry may succeed without operator action.
    pub retriable: bool,
}

impl CollectionFailure {
    fn new(code: &'static str, message: impl Into<String>, retriable: bool) -> Self {
        Self {
            code,
            message: bounded_message(&message.into(), 768),
            retriable,
        }
    }
}

fn handle_request(
    request: &HelperRequest,
    source: &impl ResourceSource,
    clock: &impl DeadlineClock,
) -> HelperResponse {
    let branch = match validate_profile_request(request) {
        Ok(branch) => branch,
        Err(response) => return *response,
    };
    if let Some(response) = validate_capability_request(request, branch) {
        return response;
    }
    if let Some(response) = validate_execution_request(request, clock) {
        return response;
    }
    let report = match branch {
        Branch::Capacity | Branch::Inodes => {
            let scope = match validate_binding_request(request) {
                Ok(scope) => scope,
                Err(response) => return *response,
            };
            match observe(&scope, source) {
                Ok(observation) => complete_report(request, &scope, &observation),
                Err(failure) => failed_report(request, branch, failure),
            }
        }
        Branch::Memory => {
            let scope = match validate_memory_binding_request(request) {
                Ok(scope) => scope,
                Err(response) => return *response,
            };
            match observe_memory(&scope, source, clock) {
                Ok(observation) => complete_memory_report(request, &scope, &observation),
                Err(failure) => failed_report(request, branch, failure),
            }
        }
    };
    match report {
        Ok(report) => match validate_compiled_report(request, branch, &report) {
            Ok(()) => HelperResponse::report(request, report),
            Err(error) => internal_refusal(
                request,
                "the collected report failed the compiled profile contract",
                json!({"validation_error": bounded_message(&error, 1_024)}),
            ),
        },
        Err(error) => internal_refusal(
            request,
            "the helper could not construct testimony",
            json!({"error": bounded_message(&error, 1_024)}),
        ),
    }
}

fn validate_profile_request(request: &HelperRequest) -> Result<Branch, Box<HelperResponse>> {
    let branch = match (
        request.profile.id.as_str(),
        request.profile.version.as_str(),
    ) {
        (host_filesystem::CAPACITY_PROFILE_ID, "1") => Branch::Capacity,
        (host_filesystem::INODES_PROFILE_ID, "1") => Branch::Inodes,
        (host_memory::PROFILE_ID, "1") => Branch::Memory,
        _ => {
            return Err(Box::new(refusal(
                request,
                RefusalBoundary::Profile,
                RefusalCode::UnknownProfile,
                "this helper implements only nq.host_filesystem_capacity/v1, nq.host_filesystem_inodes/v1, and nq.host_memory/v1",
                false,
                json!({
                    "requested_id": request.profile.id,
                    "requested_version": request.profile.version,
                }),
            )));
        }
    };
    let compiled = match branch.module().descriptor().digest() {
        Ok(digest) => digest,
        Err(error) => {
            return Err(Box::new(internal_refusal(
                request,
                "the compiled profile descriptor could not be identified",
                json!({"error": bounded_message(&error.to_string(), 1_024)}),
            )));
        }
    };
    if request.profile.digest.as_str() != compiled.as_str() {
        return Err(Box::new(refusal(
            request,
            RefusalBoundary::Profile,
            RefusalCode::ProfileDigestMismatch,
            "the requested profile digest does not match the compiled descriptor",
            false,
            json!({"requested_digest": request.profile.digest, "compiled_digest": compiled.as_str()}),
        )));
    }
    Ok(branch)
}

fn validate_binding_request(
    request: &HelperRequest,
) -> Result<HostFilesystemScope, Box<HelperResponse>> {
    if request.binding.scope.kind.as_str() != SCOPE_KIND {
        return Err(Box::new(refusal(
            request,
            RefusalBoundary::Scope,
            RefusalCode::UnsupportedScope,
            "filesystem profiles require host_filesystem scope",
            false,
            json!({}),
        )));
    }
    let scope = host_filesystem::validate_scope_value(
        &request.binding.scope.value,
        request.binding.subject.as_str(),
    )
    .map_err(|message| {
        Box::new(refusal(
            request,
            RefusalBoundary::Scope,
            RefusalCode::UnsupportedScope,
            &message,
            false,
            json!({}),
        ))
    })?;
    if request.binding.vantage.kind.as_str() != "local"
        || request.binding.vantage.value != json!({})
    {
        return Err(Box::new(refusal(
            request,
            RefusalBoundary::Vantage,
            RefusalCode::UnsupportedVantage,
            "filesystem profiles require the empty local vantage",
            false,
            json!({}),
        )));
    }
    Ok(scope)
}

fn validate_capability_request(request: &HelperRequest, branch: Branch) -> Option<HelperResponse> {
    if request.checkpoint.is_some() {
        return Some(refusal(
            request,
            RefusalBoundary::Checkpoint,
            RefusalCode::CheckpointInvalid,
            "filesystem profiles do not accept polling checkpoints",
            false,
            json!({}),
        ));
    }
    let granted: Vec<&str> = request
        .granted_capabilities
        .iter()
        .map(Capability::as_str)
        .collect();
    let required = branch.capabilities();
    let unsupported: Vec<&str> = granted
        .iter()
        .copied()
        .filter(|capability| !required.contains(capability))
        .collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|capability| !granted.contains(capability))
        .collect();
    if !unsupported.is_empty() || !missing.is_empty() {
        return Some(refusal(
            request,
            RefusalBoundary::Capability,
            RefusalCode::CapabilityDenied,
            "this profile requires exactly its declared capability set",
            false,
            json!({"unsupported_capabilities": unsupported, "missing_capabilities": missing}),
        ));
    }
    None
}

fn validate_execution_request(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Option<HelperResponse> {
    if request.bounds.max_observations < 1
        || request.bounds.max_coverage_entries < 1
        || request.bounds.max_report_errors < 1
        || request.bounds.max_payload_bytes < 2_048
    {
        return Some(refusal(
            request,
            RefusalBoundary::Resource,
            RefusalCode::BoundsUnsupported,
            "the negotiated bounds cannot represent bounded testimony",
            false,
            json!({"minimum_observations": 1, "minimum_coverage_entries": 1, "minimum_report_errors": 1, "minimum_payload_bytes": 2048}),
        ));
    }
    match clock.now_ns() {
        Ok(now_ns) if now_ns >= request.deadline.expires_at_ns => Some(refusal(
            request,
            RefusalBoundary::Deadline,
            RefusalCode::DeadlineExpired,
            "the monotonic request deadline expired before collection began",
            true,
            json!({}),
        )),
        Ok(_) => None,
        Err(error) => Some(internal_refusal(
            request,
            "the Linux boot-time clock could not be read",
            json!({"error": bounded_message(&error, 1_024)}),
        )),
    }
}

// ---------------------------------------------------------------------------
// Observation

/// One parsed `/proc/self/mountinfo` line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountEntry {
    /// Mount id (field 1).
    pub mount_id: u64,
    /// Parent mount id (field 2).
    pub parent_id: u64,
    /// `major:minor` (field 3).
    pub major: u32,
    /// `major:minor` (field 3).
    pub minor: u32,
    /// Root of the mount within the filesystem (field 4).
    pub root: String,
    /// Mount point (field 5), unescaped.
    pub mount_point: String,
    /// Filesystem type (after the separator).
    pub fs_type: String,
}

/// Raw counters and identity witnesses from one statfs cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatfsCut {
    /// `st_dev` of the opened mountpoint.
    pub st_dev: u64,
    /// `stx_mnt_id` of the opened mountpoint.
    pub mount_id: u64,
    /// `f_fsid` folded to one u64 (`val[0] | val[1] << 32`).
    pub fsid: u64,
    /// `f_frsize`.
    pub fragment_size: u64,
    /// `f_blocks`.
    pub blocks_total: u64,
    /// `f_bfree`.
    pub blocks_free: u64,
    /// `f_bavail`.
    pub blocks_available: u64,
    /// `f_files`.
    pub inodes_total: u64,
    /// `f_ffree`.
    pub inodes_free: u64,
}

/// Read-only system access, abstracted so the classification logic is testable.
#[allow(clippy::missing_errors_doc)]
pub trait ResourceSource {
    /// Contents of `/etc/machine-id`, trimmed. Errors are read failures.
    fn machine_id(&self) -> Result<String, String>;
    /// Contents of `/proc/self/mountinfo`. Errors are read failures.
    fn mountinfo(&self) -> Result<String, String>;
    /// `st_rdev` of `/dev/disk/by-uuid/<uuid>` (following the symlink), or
    /// `None` when absent. Errors are read failures other than absence.
    fn by_uuid_rdev(&self, uuid: &str) -> Result<Option<u64>, String>;
    /// Open the mountpoint with `O_PATH|O_DIRECTORY|O_NOFOLLOW`, require the
    /// descriptor's mount id to equal `expected_mount_id` before any stat call,
    /// then take the cut. Errors are typed collection failures.
    fn statfs_cut(
        &self,
        mountpoint: &str,
        expected_mount_id: u64,
    ) -> Result<StatfsCut, CollectionFailure>;
    /// Bounded read-only read of `/proc/pressure/memory`. Errors are typed
    /// collection failures (`psi_not_provided`, `psi_read_failed`).
    fn pressure_memory(&self) -> Result<String, CollectionFailure>;
}

/// Validated memory observation ready for the payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryObservation {
    /// `CLOCK_BOOTTIME` whole seconds at the read.
    pub boot_age_seconds: u64,
    /// Parsed `some` line.
    pub some: host_memory::PressureLine,
    /// Parsed `full` line.
    pub full: host_memory::PressureLine,
}

fn validate_memory_binding_request(
    request: &HelperRequest,
) -> Result<host_memory::HostMemoryScope, Box<HelperResponse>> {
    if request.binding.scope.kind.as_str() != host_memory::SCOPE_KIND {
        return Err(Box::new(refusal(
            request,
            RefusalBoundary::Scope,
            RefusalCode::UnsupportedScope,
            "nq.host_memory/v1 requires host_memory scope",
            false,
            json!({}),
        )));
    }
    let scope = host_memory::validate_scope_value(
        &request.binding.scope.value,
        request.binding.subject.as_str(),
    )
    .map_err(|message| {
        Box::new(refusal(
            request,
            RefusalBoundary::Scope,
            RefusalCode::UnsupportedScope,
            &message,
            false,
            json!({}),
        ))
    })?;
    if request.binding.vantage.kind.as_str() != "local"
        || request.binding.vantage.value != json!({})
    {
        return Err(Box::new(refusal(
            request,
            RefusalBoundary::Vantage,
            RefusalCode::UnsupportedVantage,
            "nq.host_memory/v1 requires the empty local vantage",
            false,
            json!({}),
        )));
    }
    Ok(scope)
}

/// Read-only memory pressure observation: machine identity, then one bounded
/// read of the PSI file, then the boot age from `CLOCK_BOOTTIME`.
///
/// # Errors
///
/// Returns a typed [`CollectionFailure`] for identity mismatch, PSI absence,
/// PSI read failure, or a malformed PSI file.
pub fn observe_memory(
    scope: &host_memory::HostMemoryScope,
    source: &impl ResourceSource,
    clock: &impl DeadlineClock,
) -> Result<MemoryObservation, CollectionFailure> {
    let machine_id = source.machine_id().map_err(|error| {
        CollectionFailure::new(
            MemoryFailureCode::MachineIdentityUnavailable.as_str(),
            error,
            true,
        )
    })?;
    if machine_id != scope.machine_id {
        return Err(CollectionFailure::new(
            MemoryFailureCode::MachineIdentityMismatch.as_str(),
            "live /etc/machine-id differs from the exact request scope",
            false,
        ));
    }
    let text = source.pressure_memory()?;
    let (some, full) = host_memory::parse_pressure_file(&text).map_err(|error| {
        CollectionFailure::new(MemoryFailureCode::PsiMalformed.as_str(), error, false)
    })?;
    if full.avg10_centipercent > some.avg10_centipercent
        || full.avg60_centipercent > some.avg60_centipercent
        || full.avg300_centipercent > some.avg300_centipercent
        || full.total_microseconds > some.total_microseconds
    {
        return Err(CollectionFailure::new(
            MemoryFailureCode::PsiMalformed.as_str(),
            "full stall figures exceed some stall figures",
            false,
        ));
    }
    let boot_age_seconds = clock.now_ns().map_err(|error| {
        CollectionFailure::new(
            MemoryFailureCode::BootClockUnavailable.as_str(),
            error,
            true,
        )
    })? / 1_000_000_000;
    Ok(MemoryObservation {
        boot_age_seconds,
        some,
        full,
    })
}

fn complete_memory_report(
    request: &HelperRequest,
    scope: &host_memory::HostMemoryScope,
    observation: &MemoryObservation,
) -> Result<EvidenceReport, String> {
    let observed_at = Utc::now();
    let basis = EvidenceBasis {
        scope: ScopeGrant {
            kind: request.binding.scope.kind.to_string(),
            value: request.binding.scope.value.clone(),
        },
        vantage: VantageGrant {
            kind: request.binding.vantage.kind.to_string(),
            value: request.binding.vantage.value.clone(),
        },
        access_path: host_memory::ACCESS_PATH.to_owned(),
        basis: "kernel_snapshot".to_owned(),
        regime: "normal".to_owned(),
        capabilities_used: host_memory::CAPABILITIES
            .iter()
            .map(|c| (*c).to_owned())
            .collect(),
    };
    let payload = host_memory::MemoryPressurePayload {
        evidence_basis: basis,
        machine_id: scope.machine_id.clone(),
        boot_age_seconds: observation.boot_age_seconds,
        some: observation.some.clone(),
        full: observation.full.clone(),
    };
    let payload = serde_json::to_value(payload).map_err(|error| error.to_string())?;
    let mut builder = EvidenceReport::builder(
        request.profile.clone(),
        request.binding.clone(),
        observed_at,
        ReportStatus::Complete,
        backend_provenance()?,
    )
    .coverage(CoverageDeclaration {
        kind: token(CoverageKind::new(host_memory::COVERAGE_KIND))?,
        subject: None,
        state: CoverageState::Complete,
        detail: None,
    })
    .observed_payload(
        token(ObservationKind::new(host_memory::OBSERVATION_KIND))?,
        request.binding.subject.clone(),
        observed_at,
        payload,
    );
    for capability in host_memory::CAPABILITIES {
        builder = builder.used_capability(token(Capability::new(capability))?);
    }
    builder.build().map_err(|error| format!("{error:?}"))
}

/// Validated observation ready for the payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    /// Selected mount entry (verified twice).
    pub mount: MountEntry,
    /// Counters and witnesses.
    pub cut: StatfsCut,
}

/// Unescape the octal sequences mountinfo uses for space, tab, newline, backslash.
fn unescape_mount_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 4 <= bytes.len()
            && let Ok(value) = u8::from_str_radix(&field[index + 1..index + 4], 8)
        {
            out.push(value);
            index += 4;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse mountinfo text into entries; malformed lines are skipped.
#[must_use]
pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let left: Vec<&str> = left.split(' ').collect();
            if left.len() < 6 {
                return None;
            }
            let (major, minor) = left[2].split_once(':')?;
            let fs_type = right.split(' ').next()?;
            Some(MountEntry {
                mount_id: left[0].parse().ok()?,
                parent_id: left[1].parse().ok()?,
                major: major.parse().ok()?,
                minor: minor.parse().ok()?,
                root: unescape_mount_field(left[3]),
                mount_point: unescape_mount_field(left[4]),
                fs_type: fs_type.to_owned(),
            })
        })
        .collect()
}

/// The top-of-stack mount at exactly this mountpoint: the entry there that is
/// not the parent of another entry at the same mountpoint. Listing order is
/// not used, because a mount inserted beneath (or propagated) can be listed
/// after the one users see. `None` when there is no entry or the stack is
/// ambiguous.
#[must_use]
pub fn select_mount<'a>(entries: &'a [MountEntry], mountpoint: &str) -> Option<&'a MountEntry> {
    let candidates: Vec<&MountEntry> = entries
        .iter()
        .filter(|entry| entry.mount_point == mountpoint)
        .collect();
    let tops: Vec<&MountEntry> = candidates
        .iter()
        .copied()
        .filter(|entry| {
            !candidates
                .iter()
                .any(|other| other.mount_id != entry.mount_id && other.parent_id == entry.mount_id)
        })
        .collect();
    match tops.as_slice() {
        [top] => Some(top),
        _ => None,
    }
}

fn makedev(major: u32, minor: u32) -> u64 {
    // Linux dev_t encoding (glibc makedev).
    let major = u64::from(major);
    let minor = u64::from(minor);
    ((major & 0xffff_f000) << 32)
        | ((major & 0x0000_0fff) << 8)
        | ((minor & 0xffff_ff00) << 12)
        | (minor & 0x0000_00ff)
}

/// Read-only observation with identity cross-checks; the ordering is part of
/// the contract (type and root are checked before the path is opened).
///
/// # Errors
///
/// Returns a typed [`CollectionFailure`] for every refusal case in the design.
#[allow(clippy::too_many_lines)]
pub fn observe(
    scope: &HostFilesystemScope,
    source: &impl ResourceSource,
) -> Result<Observation, CollectionFailure> {
    let machine_id = source.machine_id().map_err(|error| {
        CollectionFailure::new(
            FilesystemFailureCode::MachineIdentityUnavailable.as_str(),
            error,
            true,
        )
    })?;
    if machine_id != scope.machine_id {
        return Err(CollectionFailure::new(
            FilesystemFailureCode::MachineIdentityMismatch.as_str(),
            "live /etc/machine-id differs from the exact request scope",
            false,
        ));
    }
    let before = parse_mountinfo(&source.mountinfo().map_err(|error| {
        CollectionFailure::new(
            FilesystemFailureCode::MountTableUnavailable.as_str(),
            error,
            true,
        )
    })?);
    let Some(mount) = select_mount(&before, &scope.mountpoint).cloned() else {
        return Err(CollectionFailure::new(
            FilesystemFailureCode::NotAMountpoint.as_str(),
            "the declared path is not a mount point in this mount namespace",
            false,
        ));
    };
    if mount.fs_type != scope.filesystem_type {
        return Err(CollectionFailure::new(
            FilesystemFailureCode::UnsupportedFilesystemType.as_str(),
            format!(
                "top mount at the declared path is {} not {}",
                mount.fs_type, scope.filesystem_type
            ),
            false,
        ));
    }
    if mount.root != "/" {
        return Err(CollectionFailure::new(
            FilesystemFailureCode::MountRootNotFilesystemRoot.as_str(),
            "the top mount at the declared path is a subtree (bind) mount",
            false,
        ));
    }
    let expected_dev = makedev(mount.major, mount.minor);
    match source.by_uuid_rdev(&scope.filesystem_uuid) {
        Ok(Some(rdev)) if rdev == expected_dev => {}
        Ok(Some(_)) => {
            return Err(CollectionFailure::new(
                FilesystemFailureCode::FilesystemIdentityMismatch.as_str(),
                "the by-uuid device differs from the mounted device",
                false,
            ));
        }
        Ok(None) => {
            return Err(CollectionFailure::new(
                FilesystemFailureCode::FilesystemIdentityMismatch.as_str(),
                "no by-uuid entry exists for the declared filesystem UUID",
                false,
            ));
        }
        Err(error) => {
            return Err(CollectionFailure::new(
                FilesystemFailureCode::FilesystemIdentityUnavailable.as_str(),
                error,
                true,
            ));
        }
    }
    let cut = source.statfs_cut(&scope.mountpoint, mount.mount_id)?;
    if cut.st_dev != expected_dev || cut.mount_id != mount.mount_id {
        return Err(CollectionFailure::new(
            FilesystemFailureCode::MountChangedDuringObservation.as_str(),
            "the opened path is not the selected mount entry",
            true,
        ));
    }
    let expected_fsid =
        host_filesystem::ext4_fsid_hex(&scope.filesystem_uuid).ok_or_else(|| {
            CollectionFailure::new(
                FilesystemFailureCode::FilesystemIdentityMismatch.as_str(),
                "scope UUID is not canonical",
                false,
            )
        })?;
    if format!("{:016x}", cut.fsid) != expected_fsid {
        return Err(CollectionFailure::new(
            FilesystemFailureCode::FilesystemIdentityMismatch.as_str(),
            "statfs f_fsid differs from the ext4 fold of the declared UUID",
            false,
        ));
    }
    let after = parse_mountinfo(&source.mountinfo().map_err(|error| {
        CollectionFailure::new(
            FilesystemFailureCode::MountTableUnavailable.as_str(),
            error,
            true,
        )
    })?);
    match select_mount(&after, &scope.mountpoint) {
        Some(again)
            if again.mount_id == mount.mount_id
                && again.major == mount.major
                && again.minor == mount.minor => {}
        _ => {
            return Err(CollectionFailure::new(
                FilesystemFailureCode::MountChangedDuringObservation.as_str(),
                "the mount table changed between the pre and post reads",
                true,
            ));
        }
    }
    Ok(Observation { mount, cut })
}

fn complete_report(
    request: &HelperRequest,
    scope: &HostFilesystemScope,
    observation: &Observation,
) -> Result<EvidenceReport, String> {
    let observed_at = Utc::now();
    let basis = EvidenceBasis {
        scope: ScopeGrant {
            kind: request.binding.scope.kind.to_string(),
            value: request.binding.scope.value.clone(),
        },
        vantage: VantageGrant {
            kind: request.binding.vantage.kind.to_string(),
            value: request.binding.vantage.value.clone(),
        },
        access_path: ACCESS_PATH.to_owned(),
        basis: "kernel_snapshot".to_owned(),
        regime: "normal".to_owned(),
        capabilities_used: CAPABILITIES.iter().map(|c| (*c).to_owned()).collect(),
    };
    let payload = host_filesystem::FilesystemSnapshotPayload {
        evidence_basis: basis,
        machine_id: scope.machine_id.clone(),
        filesystem_uuid: scope.filesystem_uuid.clone(),
        filesystem_type: scope.filesystem_type.clone(),
        mountpoint: scope.mountpoint.clone(),
        mount_id: observation.mount.mount_id,
        device_major: observation.mount.major,
        device_minor: observation.mount.minor,
        fsid_hex: format!("{:016x}", observation.cut.fsid),
        fragment_size: observation.cut.fragment_size,
        blocks_total: observation.cut.blocks_total,
        blocks_free: observation.cut.blocks_free,
        blocks_available: observation.cut.blocks_available,
        inodes_total: observation.cut.inodes_total,
        inodes_free: observation.cut.inodes_free,
    };
    let payload = serde_json::to_value(payload).map_err(|error| error.to_string())?;
    let mut builder = EvidenceReport::builder(
        request.profile.clone(),
        request.binding.clone(),
        observed_at,
        ReportStatus::Complete,
        backend_provenance()?,
    )
    .coverage(CoverageDeclaration {
        kind: token(CoverageKind::new(COVERAGE_KIND))?,
        subject: None,
        state: CoverageState::Complete,
        detail: None,
    })
    .observed_payload(
        token(ObservationKind::new(OBSERVATION_KIND))?,
        request.binding.subject.clone(),
        observed_at,
        payload,
    );
    for capability in CAPABILITIES {
        builder = builder.used_capability(token(Capability::new(capability))?);
    }
    builder.build().map_err(|error| format!("{error:?}"))
}

fn failed_report(
    request: &HelperRequest,
    branch: Branch,
    failure: CollectionFailure,
) -> Result<EvidenceReport, String> {
    let mut builder = EvidenceReport::builder(
        request.profile.clone(),
        request.binding.clone(),
        Utc::now(),
        ReportStatus::Failed,
        backend_provenance()?,
    )
    .coverage(CoverageDeclaration {
        kind: token(CoverageKind::new(branch.coverage()))?,
        subject: None,
        state: CoverageState::Unavailable,
        detail: None,
    })
    .error(ReportError {
        code: token(ErrorCode::new(failure.code))?,
        severity: ErrorSeverity::Error,
        message: failure.message,
        subject: Some(request.binding.subject.clone()),
        observation_ordinal: None,
        retriable: failure.retriable,
    });
    for capability in branch.capabilities() {
        builder = builder.used_capability(token(Capability::new(*capability))?);
    }
    builder.build().map_err(|error| format!("{error:?}"))
}

fn validate_compiled_report(
    request: &HelperRequest,
    branch: Branch,
    report: &EvidenceReport,
) -> Result<(), String> {
    let input =
        ReportInput::from_protocol_with_digest(report).map_err(|error| format!("{error:?}"))?;
    let context = ValidationContext::from_request(request, Utc::now(), Duration::seconds(5));
    branch
        .module()
        .validate(&context, &input)
        .map(|_| ())
        .map_err(|error| format!("{:?}: {}", error.code, error.message))
}

fn ensure_bounded_response(
    request: &HelperRequest,
    response: HelperResponse,
) -> Result<HelperResponse, StdioError> {
    if validate_exchange(request, &response).is_ok() {
        return Ok(response);
    }
    let fallback = refusal(
        request,
        RefusalBoundary::Resource,
        RefusalCode::BoundsUnsupported,
        "the negotiated response or payload bound is too small for filesystem testimony",
        false,
        json!({}),
    );
    validate_exchange(request, &fallback)
        .map(|()| fallback)
        .map_err(|error| StdioError::UnrepresentableResponse(error.to_string()))
}

fn refusal(
    request: &HelperRequest,
    boundary: RefusalBoundary,
    code: RefusalCode,
    message: &str,
    retriable: bool,
    details: Value,
) -> HelperResponse {
    HelperResponse::refusal(
        request,
        Refusal {
            responsible_instance_id: request.instance_id.clone(),
            boundary,
            code,
            message: message.to_owned(),
            retriable,
            details,
        },
    )
}

fn internal_refusal(request: &HelperRequest, message: &str, details: Value) -> HelperResponse {
    refusal(
        request,
        RefusalBoundary::Internal,
        RefusalCode::InternalError,
        message,
        false,
        details,
    )
}

fn backend_provenance() -> Result<BackendProvenance, String> {
    Ok(BackendProvenance {
        implementation: BackendIdentity {
            name: token(ImplementationName::new("nq-host-resource-helper"))?,
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            digest: None,
        },
        tools: Vec::new(),
    })
}

fn token<T>(result: Result<T, nq_protocol::TokenError>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

fn bounded_message(message: &str, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message.to_owned();
    }
    let mut end = max_bytes;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

/// Monotonic boot-time clock used for the request deadline and the boot age.
pub trait DeadlineClock {
    /// Nanoseconds since boot.
    ///
    /// # Errors
    ///
    /// Returns the clock read failure as text.
    fn now_ns(&self) -> Result<u64, String>;
}

struct LinuxBoottimeClock;

impl DeadlineClock for LinuxBoottimeClock {
    fn now_ns(&self) -> Result<u64, String> {
        let time = clock_gettime(ClockId::CLOCK_BOOTTIME).map_err(|error| error.to_string())?;
        let seconds = u64::try_from(time.tv_sec()).map_err(|_| "negative seconds".to_owned())?;
        let nanoseconds =
            u64::try_from(time.tv_nsec()).map_err(|_| "negative nanoseconds".to_owned())?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or_else(|| "CLOCK_BOOTTIME overflow".to_owned())
    }
}

/// The real Linux source.
pub struct LinuxSource;

fn read_bounded(path: &str, max_bytes: usize) -> Result<String, String> {
    let file = File::open(path).map_err(|error| format!("{path}: {error}"))?;
    let mut bytes = Vec::with_capacity(4_096);
    file.take(
        u64::try_from(max_bytes)
            .map_err(|e| e.to_string())?
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|error| format!("{path}: {error}"))?;
    if bytes.len() > max_bytes {
        return Err(format!("{path} exceeds the {max_bytes}-byte bound"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{path} is not UTF-8"))
}

impl ResourceSource for LinuxSource {
    fn machine_id(&self) -> Result<String, String> {
        Ok(read_bounded(MACHINE_ID_PATH, 256)?.trim().to_owned())
    }

    fn mountinfo(&self) -> Result<String, String> {
        read_bounded(MOUNTINFO_PATH, MAX_MOUNTINFO_BYTES)
    }

    fn pressure_memory(&self) -> Result<String, CollectionFailure> {
        // O_RDONLY only: a write to this file registers a PSI trigger.
        match File::open(PRESSURE_MEMORY_PATH) {
            Ok(file) => {
                let mut bytes = Vec::with_capacity(512);
                file.take(4_097).read_to_end(&mut bytes).map_err(|error| {
                    CollectionFailure::new(
                        MemoryFailureCode::PsiReadFailed.as_str(),
                        error.to_string(),
                        true,
                    )
                })?;
                if bytes.len() > 4_096 {
                    return Err(CollectionFailure::new(
                        MemoryFailureCode::PsiReadFailed.as_str(),
                        "pressure file exceeds its bound",
                        false,
                    ));
                }
                String::from_utf8(bytes).map_err(|_| {
                    CollectionFailure::new(
                        MemoryFailureCode::PsiMalformed.as_str(),
                        "pressure file is not UTF-8",
                        false,
                    )
                })
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::EOPNOTSUPP) =>
            {
                Err(CollectionFailure::new(
                    MemoryFailureCode::PsiNotProvided.as_str(),
                    "/proc/pressure/memory is not available to this process (kernel without PSI, psi=0, or a restricted proc view)",
                    false,
                ))
            }
            Err(error) => Err(CollectionFailure::new(
                MemoryFailureCode::PsiReadFailed.as_str(),
                error.to_string(),
                true,
            )),
        }
    }

    fn by_uuid_rdev(&self, uuid: &str) -> Result<Option<u64>, String> {
        if !host_filesystem::is_canonical_uuid(uuid) {
            return Ok(None);
        }
        let path = Path::new(BY_UUID_DIR).join(uuid);
        match std::fs::metadata(&path) {
            Ok(metadata) => Ok(Some(metadata.rdev())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    fn statfs_cut(
        &self,
        mountpoint: &str,
        expected_mount_id: u64,
    ) -> Result<StatfsCut, CollectionFailure> {
        // O_PATH opens no file description for reading; the access mode is
        // required by the standard library, not used by the kernel.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(mountpoint)
            .map_err(|error| {
                CollectionFailure::new(
                    FilesystemFailureCode::FilesystemInaccessible.as_str(),
                    error.to_string(),
                    false,
                )
            })?;
        // The mount id of the open descriptor, from the kernel's fdinfo view,
        // checked before any stat call so a mount that moved between the table
        // read and the open is never measured.
        let fdinfo = read_bounded(&format!("/proc/self/fdinfo/{}", file.as_raw_fd()), 4_096)
            .map_err(|error| {
                CollectionFailure::new(
                    FilesystemFailureCode::MountIdentityUnavailable.as_str(),
                    error,
                    true,
                )
            })?;
        let mount_id = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:"))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .ok_or_else(|| {
                CollectionFailure::new(
                    FilesystemFailureCode::MountIdentityUnavailable.as_str(),
                    "kernel did not report a mount id",
                    false,
                )
            })?;
        if mount_id != expected_mount_id {
            return Err(CollectionFailure::new(
                FilesystemFailureCode::MountChangedDuringObservation.as_str(),
                "the opened path is not the selected mount entry",
                true,
            ));
        }
        let metadata = file.metadata().map_err(|error| {
            CollectionFailure::new(
                FilesystemFailureCode::StatFailed.as_str(),
                error.to_string(),
                true,
            )
        })?;
        // statvfs carries the same superblock counters; glibc folds f_fsid into
        // one word exactly as the ext4 UUID fold expects (val[0] | val[1] << 32).
        let statistics = fstatvfs(&file).map_err(|error| {
            CollectionFailure::new(
                FilesystemFailureCode::StatfsFailed.as_str(),
                error.to_string(),
                true,
            )
        })?;
        Ok(StatfsCut {
            st_dev: metadata.dev(),
            mount_id,
            fsid: statistics.filesystem_id(),
            fragment_size: statistics.fragment_size(),
            blocks_total: statistics.blocks(),
            blocks_free: statistics.blocks_free(),
            blocks_available: statistics.blocks_available(),
            inodes_total: statistics.files(),
            inodes_free: statistics.files_free(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
28 1 253:0 / / rw,relatime shared:1 - ext4 /dev/mapper/vgubuntu-root rw,errors=remount-ro
40 28 259:1 / /data rw,relatime shared:20 - ext4 /dev/nvme0n1p1 rw,errors=remount-ro
41 28 0:50 /sub /mnt/bind rw,relatime shared:21 - ext4 /dev/nvme0n1p1 rw
42 28 0:60 / /mnt/net rw,relatime - nfs4 server:/export rw
43 28 0:61 / /mnt/with\\040space rw - tmpfs tmpfs rw
";

    struct Fake {
        machine_id: &'static str,
        rdev: Option<u64>,
        cut: StatfsCut,
    }

    impl ResourceSource for Fake {
        fn machine_id(&self) -> Result<String, String> {
            Ok(self.machine_id.to_owned())
        }
        fn mountinfo(&self) -> Result<String, String> {
            Ok(MOUNTINFO.to_owned())
        }
        fn by_uuid_rdev(&self, _uuid: &str) -> Result<Option<u64>, String> {
            Ok(self.rdev)
        }
        fn statfs_cut(
            &self,
            _mountpoint: &str,
            expected_mount_id: u64,
        ) -> Result<StatfsCut, CollectionFailure> {
            if self.cut.mount_id != expected_mount_id {
                return Err(CollectionFailure::new(
                    FilesystemFailureCode::MountChangedDuringObservation.as_str(),
                    "the opened path is not the selected mount entry",
                    true,
                ));
            }
            Ok(self.cut.clone())
        }
        fn pressure_memory(&self) -> Result<String, CollectionFailure> {
            Ok(
                "some avg10=0.00 avg60=12.34 avg300=0.00 total=311022455\nfull avg10=0.00 avg60=1.00 avg300=0.00 total=304797313\n"
                    .to_owned(),
            )
        }
    }

    struct FixedClock(u64);

    impl DeadlineClock for FixedClock {
        fn now_ns(&self) -> Result<u64, String> {
            Ok(self.0)
        }
    }

    #[test]
    fn memory_observation_binds_machine_and_reads_psi_exactly() {
        let ok = Fake {
            machine_id: "1a5b08928e884e73bf4f60a3c73ef497",
            rdev: None,
            cut: good_cut(),
        };
        let scope = host_memory::HostMemoryScope {
            schema: host_memory::SCOPE_SCHEMA.to_owned(),
            machine_id: "1a5b08928e884e73bf4f60a3c73ef497".to_owned(),
        };
        let observation =
            observe_memory(&scope, &ok, &FixedClock(1_000 * 1_000_000_000)).expect("observation");
        assert_eq!(observation.some.avg60_centipercent, 1_234);
        assert_eq!(observation.boot_age_seconds, 1_000);
        let other = host_memory::HostMemoryScope {
            machine_id: "ffffffffffffffffffffffffffffffff".to_owned(),
            ..scope
        };
        assert_eq!(
            observe_memory(&other, &ok, &FixedClock(1))
                .unwrap_err()
                .code,
            "machine_identity_mismatch"
        );
        let real = LinuxSource.pressure_memory();
        if let Ok(text) = real {
            host_memory::parse_pressure_file(&text).expect("real PSI file parses");
        }
    }

    fn scope(mountpoint: &str, fs_type: &str) -> HostFilesystemScope {
        HostFilesystemScope {
            schema: host_filesystem::SCOPE_SCHEMA.to_owned(),
            machine_id: "1a5b08928e884e73bf4f60a3c73ef497".to_owned(),
            filesystem_uuid: "41530d0d-bad6-4c21-b740-99c992d5126b".to_owned(),
            filesystem_type: fs_type.to_owned(),
            mountpoint: mountpoint.to_owned(),
        }
    }

    fn good_cut() -> StatfsCut {
        StatfsCut {
            st_dev: makedev(259, 1),
            mount_id: 40,
            fsid: 0x4a5e_0328_c494_13f6,
            fragment_size: 4096,
            blocks_total: 491_968_500,
            blocks_free: 56_656_020,
            blocks_available: 31_646_960,
            inodes_total: 125_026_304,
            inodes_free: 121_788_771,
        }
    }

    #[test]
    fn mountinfo_selection_unescapes_and_picks_the_top_mount() {
        let entries = parse_mountinfo(MOUNTINFO);
        assert_eq!(entries.len(), 5);
        let data = select_mount(&entries, "/data").unwrap();
        assert_eq!(
            (
                data.mount_id,
                data.parent_id,
                data.major,
                data.minor,
                data.fs_type.as_str(),
                data.root.as_str()
            ),
            (40, 28, 259, 1, "ext4", "/")
        );
        assert_eq!(
            select_mount(&entries, "/mnt/with space").unwrap().fs_type,
            "tmpfs"
        );
        assert!(select_mount(&entries, "/data/sub").is_none());
    }

    #[test]
    fn identity_and_access_failures_are_typed_and_never_absence() {
        let ok = Fake {
            machine_id: "1a5b08928e884e73bf4f60a3c73ef497",
            rdev: Some(makedev(259, 1)),
            cut: good_cut(),
        };
        let observation = observe(&scope("/data", "ext4"), &ok).expect("real-shaped observation");
        assert_eq!(observation.mount.mount_id, 40);

        let other_machine = Fake {
            machine_id: "ffffffffffffffffffffffffffffffff",
            ..ok_clone(&ok)
        };
        assert_eq!(
            observe(&scope("/data", "ext4"), &other_machine)
                .unwrap_err()
                .code,
            "machine_identity_mismatch"
        );
        assert_eq!(
            observe(&scope("/nope", "ext4"), &ok).unwrap_err().code,
            "not_a_mountpoint"
        );
        assert_eq!(
            observe(&scope("/mnt/net", "ext4"), &ok).unwrap_err().code,
            "unsupported_filesystem_type"
        );
        assert_eq!(
            observe(&scope("/mnt/bind", "ext4"), &ok).unwrap_err().code,
            "mount_root_not_filesystem_root"
        );
        let replaced = Fake {
            rdev: Some(makedev(259, 2)),
            ..ok_clone(&ok)
        };
        assert_eq!(
            observe(&scope("/data", "ext4"), &replaced)
                .unwrap_err()
                .code,
            "filesystem_identity_mismatch"
        );
        let missing = Fake {
            rdev: None,
            ..ok_clone(&ok)
        };
        assert_eq!(
            observe(&scope("/data", "ext4"), &missing).unwrap_err().code,
            "filesystem_identity_mismatch"
        );
        let mut cloned_uuid_other_fsid = ok_clone(&ok);
        cloned_uuid_other_fsid.cut.fsid = 1;
        assert_eq!(
            observe(&scope("/data", "ext4"), &cloned_uuid_other_fsid)
                .unwrap_err()
                .code,
            "filesystem_identity_mismatch"
        );
        let mut moved = ok_clone(&ok);
        moved.cut.mount_id = 99;
        assert_eq!(
            observe(&scope("/data", "ext4"), &moved).unwrap_err().code,
            "mount_changed_during_observation"
        );
    }

    fn ok_clone(fake: &Fake) -> Fake {
        Fake {
            machine_id: fake.machine_id,
            rdev: fake.rdev,
            cut: fake.cut.clone(),
        }
    }

    #[test]
    fn the_real_source_takes_a_cut_of_the_root_filesystem_read_only() {
        // "/" is always a mount point; this exercises O_PATH open, fdinfo
        // mount id, st_dev, and statvfs on the running kernel.
        let entries = parse_mountinfo(&LinuxSource.mountinfo().expect("mountinfo"));
        let root = select_mount(&entries, "/").expect("root mount entry");
        let cut = LinuxSource
            .statfs_cut("/", root.mount_id)
            .expect("root statvfs cut");
        assert!(cut.fragment_size > 0);
        assert!(cut.mount_id > 0);
        assert!(cut.blocks_total >= cut.blocks_free && cut.blocks_free >= cut.blocks_available);
        assert_eq!(root.mount_id, cut.mount_id);
        assert_eq!(
            LinuxSource
                .statfs_cut("/", root.mount_id + 1_000_000)
                .unwrap_err()
                .code,
            "mount_changed_during_observation"
        );
        assert_eq!(makedev(root.major, root.minor), cut.st_dev);
        assert!(LinuxSource.machine_id().expect("machine id").len() == 32);
        assert_eq!(
            LinuxSource.by_uuid_rdev("not-a-uuid").expect("no error"),
            None
        );
    }

    struct Stacked<'a>(&'a Fake);

    impl ResourceSource for Stacked<'_> {
        fn machine_id(&self) -> Result<String, String> {
            self.0.machine_id()
        }
        fn mountinfo(&self) -> Result<String, String> {
            // An nfs mount stacked on the ext4 at /data, with the lower ext4
            // listed last (as MOVE_MOUNT_BENEATH or propagation can produce).
            Ok("28 1 253:0 / / rw - ext4 /dev/mapper/root rw\n50 40 0:60 / /data rw - nfs4 server:/export rw\n40 28 259:1 / /data rw - ext4 /dev/nvme0n1p1 rw\n".to_owned())
        }
        fn by_uuid_rdev(&self, uuid: &str) -> Result<Option<u64>, String> {
            self.0.by_uuid_rdev(uuid)
        }
        fn statfs_cut(
            &self,
            mountpoint: &str,
            expected: u64,
        ) -> Result<StatfsCut, CollectionFailure> {
            self.0.statfs_cut(mountpoint, expected)
        }
        fn pressure_memory(&self) -> Result<String, CollectionFailure> {
            self.0.pressure_memory()
        }
    }

    #[test]
    fn a_lower_mount_listed_last_is_not_selected() {
        let ok = Fake {
            machine_id: "1a5b08928e884e73bf4f60a3c73ef497",
            rdev: Some(makedev(259, 1)),
            cut: good_cut(),
        };
        let entries = parse_mountinfo(&Stacked(&ok).mountinfo().unwrap());
        let top = select_mount(&entries, "/data").unwrap();
        assert_eq!((top.mount_id, top.fs_type.as_str()), (50, "nfs4"));
        // Refused by type before any open; the ext4 listed last is never chosen.
        assert_eq!(
            observe(&scope("/data", "ext4"), &Stacked(&ok))
                .unwrap_err()
                .code,
            "unsupported_filesystem_type"
        );
        // An ambiguous stack (two tops) is refused as not a mountpoint.
        let two_tops = parse_mountinfo(
            "28 1 253:0 / / rw - ext4 a rw\n40 28 259:1 / /data rw - ext4 b rw\n41 28 259:2 / /data rw - ext4 c rw\n",
        );
        assert!(select_mount(&two_tops, "/data").is_none());
        assert_eq!(
            observe(&scope("/data", "ext4"), &ok).map(|o| o.mount.mount_id),
            Ok(40)
        );
    }

    #[test]
    fn makedev_matches_glibc_encoding() {
        assert_eq!(makedev(259, 1), 0x1_0301);
        assert_eq!(makedev(253, 0), 0xfd00);
    }
}
