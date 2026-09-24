//! `nq.host_filesystem_capacity/v1` and `nq.host_filesystem_inodes/v1`:
//! bounded local testimony about one exact filesystem instance.
//!
//! The subject is the filesystem instance, `host-filesystem:<machine-id>/<uuid>`,
//! observed through its declared mountpoint. Two conditions are two profiles
//! because diagnostic execution admits one detector per profile; both share
//! this payload contract and identity law. Neither condition is storage
//! health: pressure absent says nothing about integrity, performance, quotas,
//! growth, or whether any particular writer can allocate.

use std::{any::Any, collections::BTreeMap, sync::LazyLock};

use chrono::Duration;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CardinalityLimits, DETECTOR_DESCRIPTOR_SCHEMA, Detector, DetectorDescriptor, DetectorEvidence,
    DetectorInput, DetectorReport, DetectorResult, DetectorRuleParameters, DetectorState,
    EvidenceBasis, FreshnessPolicy, ProfileDescriptor, ProfileModule, ProfileProjection,
    ProfileRefusal, ProfileRefusalCode, ProjectionResult, RefusalBoundary, SemanticCoverageState,
    SemanticReportStatus, SubjectRules, ValidatedReport, ValidationContext, ValidationResult,
    VocabularyTerm,
    descriptor::PROFILE_DESCRIPTOR_SCHEMA,
    validation::{ReportInput, validate_basis, validate_common},
};

/// Capacity profile identifier.
pub const CAPACITY_PROFILE_ID: &str = "nq.host_filesystem_capacity";
/// Inode profile identifier.
pub const INODES_PROFILE_ID: &str = "nq.host_filesystem_inodes";
/// Compiled semantic version of both profiles.
pub const PROFILE_VERSION: u32 = 1;
/// Capacity detector identifier.
pub const CAPACITY_DETECTOR_ID: &str = "nq.host_filesystem_capacity.pressure";
/// Inode detector identifier.
pub const INODES_DETECTOR_ID: &str = "nq.host_filesystem_inodes.pressure";
/// Scope kind shared by both profiles.
pub const SCOPE_KIND: &str = "host_filesystem";
/// Exact scope value schema.
pub const SCOPE_SCHEMA: &str = "nq.host_filesystem_scope.v1";
/// Subject namespace.
pub const SUBJECT_PREFIX: &str = "host-filesystem:";
/// Observation kind.
pub const OBSERVATION_KIND: &str = "filesystem_snapshot";
/// The one coverage class.
pub const COVERAGE_KIND: &str = "filesystem_statistics";
/// Controlled access path: mountinfo selection followed by statfs on the
/// declared path only.
pub const ACCESS_PATH: &str = "mountinfo_statfs";
/// Required capabilities; partial grants are refused.
/// The closed set of typed failure codes the filesystem helper may emit,
/// shared by the capacity and inodes profiles (one collector). This list is
/// the owner's whole vocabulary: a detector carries a code into its refusal
/// only if it parses here, and the helper builds its failures only from it.
/// The meaning of each code belongs to this module and nowhere else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemFailureCode {
    /// `/etc/machine-id` could not be read (retriable).
    MachineIdentityUnavailable,
    /// The live machine identity is not the enrolled one.
    MachineIdentityMismatch,
    /// The mount table could not be read (retriable).
    MountTableUnavailable,
    /// The enrolled mountpoint is not a mountpoint.
    NotAMountpoint,
    /// The mounted filesystem is not of the enrolled type.
    UnsupportedFilesystemType,
    /// The mount at the mountpoint is not a filesystem root.
    MountRootNotFilesystemRoot,
    /// The mounted device is not the enrolled filesystem.
    FilesystemIdentityMismatch,
    /// The by-uuid identity could not be read (retriable).
    FilesystemIdentityUnavailable,
    /// The mount changed while it was being observed (retriable).
    MountChangedDuringObservation,
    /// The mountpoint could not be opened.
    FilesystemInaccessible,
    /// The descriptor's mount identity could not be read.
    MountIdentityUnavailable,
    /// `fstat` failed (retriable).
    StatFailed,
    /// `fstatvfs` failed (retriable).
    StatfsFailed,
}

impl FilesystemFailureCode {
    /// Every code, in declaration order.
    pub const ALL: [Self; 13] = [
        Self::MachineIdentityUnavailable,
        Self::MachineIdentityMismatch,
        Self::MountTableUnavailable,
        Self::NotAMountpoint,
        Self::UnsupportedFilesystemType,
        Self::MountRootNotFilesystemRoot,
        Self::FilesystemIdentityMismatch,
        Self::FilesystemIdentityUnavailable,
        Self::MountChangedDuringObservation,
        Self::FilesystemInaccessible,
        Self::MountIdentityUnavailable,
        Self::StatFailed,
        Self::StatfsFailed,
    ];

    /// The wire code, exactly as the helper emits it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachineIdentityUnavailable => "machine_identity_unavailable",
            Self::MachineIdentityMismatch => "machine_identity_mismatch",
            Self::MountTableUnavailable => "mount_table_unavailable",
            Self::NotAMountpoint => "not_a_mountpoint",
            Self::UnsupportedFilesystemType => "unsupported_filesystem_type",
            Self::MountRootNotFilesystemRoot => "mount_root_not_filesystem_root",
            Self::FilesystemIdentityMismatch => "filesystem_identity_mismatch",
            Self::FilesystemIdentityUnavailable => "filesystem_identity_unavailable",
            Self::MountChangedDuringObservation => "mount_changed_during_observation",
            Self::FilesystemInaccessible => "filesystem_inaccessible",
            Self::MountIdentityUnavailable => "mount_identity_unavailable",
            Self::StatFailed => "stat_failed",
            Self::StatfsFailed => "statfs_failed",
        }
    }

    /// Exact lookup; anything else is not a filesystem code, whatever it
    /// looks like.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|known| known.as_str() == code)
    }
}

pub const CAPABILITIES: [&str; 3] = [
    "read_machine_identity",
    "read_mount_table",
    "read_filesystem_statistics",
];
/// Compiled used-fraction threshold in thousandths (90 percent).
pub const USED_THRESHOLD_PERMILLE: u32 = 900;
/// Largest counter accepted in a payload (I-JSON safe integer).
pub const MAX_SAFE_COUNTER: u64 = (1 << 53) - 1;

fn descriptor(id: &str, title: &str, condition_word: &str) -> ProfileDescriptor {
    ProfileDescriptor {
        schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
        family: "host_filesystem".to_owned(),
        profile: crate::ProfileKey::new(id, PROFILE_VERSION),
        title: title.to_owned(),
        observation_kinds: vec![VocabularyTerm::new(
            OBSERVATION_KIND,
            "One statfs snapshot of one exact filesystem instance through its declared mountpoint",
        )],
        coverage: vec![VocabularyTerm::new(
            COVERAGE_KIND,
            "Block, fragment-size, and inode counters for the exact filesystem",
        )],
        subjects: SubjectRules {
            namespace: SUBJECT_PREFIX.to_owned(),
            exact_request_subject: true,
        },
        scope_kinds: vec![VocabularyTerm::new(
            SCOPE_KIND,
            "One exact machine, filesystem UUID, filesystem type, and mountpoint",
        )],
        vantages: vec![VocabularyTerm::new(
            "local",
            "Observation from a process on the machine that mounts the filesystem",
        )],
        access_paths: vec![VocabularyTerm::new(
            ACCESS_PATH,
            "Mount table selection, identity cross-checks, then statfs on the declared path only",
        )],
        bases: vec![VocabularyTerm::new(
            "kernel_snapshot",
            "A bounded local kernel superblock counter snapshot",
        )],
        regimes: vec![VocabularyTerm::new(
            "normal",
            "Read-only observation that triggers no automount and writes nothing",
        )],
        capabilities: vec![
            VocabularyTerm::new(CAPABILITIES[0], "Read /etc/machine-id"),
            VocabularyTerm::new(CAPABILITIES[1], "Read the process mount table"),
            VocabularyTerm::new(
                CAPABILITIES[2],
                "Resolve the filesystem UUID and read statfs counters for the declared path",
            ),
        ],
        freshness: FreshnessPolicy {
            reliance_seconds: 300,
            alignment_seconds: 0,
        },
        limits: CardinalityLimits {
            max_observations: 1,
            max_payload_bytes: 8_192,
            max_subject_bytes: 128,
            max_coverage_declarations: 1,
        },
        disturbance_assumptions: vec![
            "Reading superblock counters does not alter the filesystem".to_owned(),
            format!(
                "One local statfs snapshot establishes {condition_word} pressure only; it is not storage health, integrity, performance, quota, or growth evidence"
            ),
        ],
    }
}

static CAPACITY_DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| {
    descriptor(
        CAPACITY_PROFILE_ID,
        "Local filesystem capacity pressure",
        "capacity",
    )
});

static INODES_DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| {
    descriptor(
        INODES_PROFILE_ID,
        "Local filesystem inode pressure",
        "inode",
    )
});

/// Exact scope value, copied verbatim into the payload and re-verified there.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostFilesystemScope {
    /// Must equal [`SCOPE_SCHEMA`].
    pub schema: String,
    /// 32 lowercase hex characters from `/etc/machine-id`.
    pub machine_id: String,
    /// Lowercase canonical filesystem UUID (8-4-4-4-12).
    pub filesystem_uuid: String,
    /// Only `ext4` is admitted in v1.
    pub filesystem_type: String,
    /// Absolute, normalized declared mountpoint; access path, not subject.
    pub mountpoint: String,
}

/// Payload of one `filesystem_snapshot` observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSnapshotPayload {
    /// Exact evidence basis.
    pub evidence_basis: EvidenceBasis,
    /// Machine identity read during this observation.
    pub machine_id: String,
    /// Filesystem UUID resolved during this observation.
    pub filesystem_uuid: String,
    /// Filesystem type from the mount table entry.
    pub filesystem_type: String,
    /// Mountpoint of the selected mount table entry.
    pub mountpoint: String,
    /// Mount id of the selected entry, re-read after statfs.
    pub mount_id: u64,
    /// Block device major of the selected entry.
    pub device_major: u32,
    /// Block device minor of the selected entry.
    pub device_minor: u32,
    /// `f_fsid` as 16 lowercase hex characters; on ext4 this is a fold of the UUID.
    pub fsid_hex: String,
    /// `f_frsize`.
    pub fragment_size: u64,
    /// `f_blocks`.
    pub blocks_total: u64,
    /// `f_bfree`.
    pub blocks_free: u64,
    /// `f_bavail` (available to unprivileged writers).
    pub blocks_available: u64,
    /// `f_files`.
    pub inodes_total: u64,
    /// `f_ffree`.
    pub inodes_free: u64,
}

/// Typed rebuildable view of one admitted filesystem snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemSnapshotProjection {
    profile: crate::ProfileKey,
    /// Source observation ordinal.
    pub ordinal: u32,
    /// Validated subject.
    pub subject: String,
    /// Exact validated payload.
    pub payload: FilesystemSnapshotPayload,
}

impl ProfileProjection for FilesystemSnapshotProjection {
    fn profile(&self) -> &crate::ProfileKey {
        &self.profile
    }

    fn ordinal(&self) -> u32 {
        self.ordinal
    }

    fn canonical_json(&self) -> Value {
        json!({
            "profile": self.profile,
            "ordinal": self.ordinal,
            "subject": self.subject,
            "payload": self.payload,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Expected subject string for a scope.
#[must_use]
pub fn subject_for(machine_id: &str, filesystem_uuid: &str) -> String {
    format!("{SUBJECT_PREFIX}{machine_id}/{filesystem_uuid}")
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Canonical lowercase UUID form check (8-4-4-4-12).
#[must_use]
pub fn is_canonical_uuid(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(len, part)| is_lower_hex(part, *len))
}

/// The ext4 `f_fsid` derivation: the UUID's two 8-byte halves `XOR`ed, read as
/// two little-endian 32-bit words, `val[0] | val[1] << 32`, as 16 hex digits.
#[must_use]
pub fn ext4_fsid_hex(filesystem_uuid: &str) -> Option<String> {
    if !is_canonical_uuid(filesystem_uuid) {
        return None;
    }
    let hex: String = filesystem_uuid.chars().filter(|c| *c != '-').collect();
    let mut bytes = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    let mut folded = [0_u8; 8];
    for index in 0..8 {
        folded[index] = bytes[index] ^ bytes[index + 8];
    }
    let low = u32::from_le_bytes([folded[0], folded[1], folded[2], folded[3]]);
    let high = u32::from_le_bytes([folded[4], folded[5], folded[6], folded[7]]);
    Some(format!("{:016x}", u64::from(low) | (u64::from(high) << 32)))
}

/// Validates a scope value and returns it.
///
/// # Errors
///
/// Returns a message describing the first violated rule.
pub fn validate_scope_value(
    value: &Value,
    request_subject: &str,
) -> Result<HostFilesystemScope, String> {
    let scope: HostFilesystemScope = serde_json::from_value(value.clone())
        .map_err(|error| format!("scope must be exactly {SCOPE_SCHEMA}: {error}"))?;
    if scope.schema != SCOPE_SCHEMA {
        return Err(format!("scope schema must be {SCOPE_SCHEMA}"));
    }
    if !is_lower_hex(&scope.machine_id, 32) {
        return Err("machine_id must be 32 lowercase hex characters".to_owned());
    }
    if !is_canonical_uuid(&scope.filesystem_uuid) {
        return Err("filesystem_uuid must be a lowercase canonical UUID".to_owned());
    }
    if scope.filesystem_type != "ext4" {
        return Err("v1 admits only filesystem_type ext4".to_owned());
    }
    if !scope.mountpoint.starts_with('/')
        || scope.mountpoint.len() > 1_024
        || (scope.mountpoint.len() > 1 && scope.mountpoint.ends_with('/'))
        || scope.mountpoint.contains("//")
        || scope
            .mountpoint
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        || scope.mountpoint.contains('\0')
    {
        return Err("mountpoint must be an absolute normalized path".to_owned());
    }
    if request_subject != subject_for(&scope.machine_id, &scope.filesystem_uuid) {
        return Err("subject must equal host-filesystem:<machine_id>/<filesystem_uuid>".to_owned());
    }
    Ok(scope)
}

/// Validates payload counters and identity against the scope.
///
/// # Errors
///
/// Returns a message describing the first violated rule.
pub fn validate_payload_against_scope(
    payload: &FilesystemSnapshotPayload,
    scope: &HostFilesystemScope,
) -> Result<(), String> {
    if payload.machine_id != scope.machine_id
        || payload.filesystem_uuid != scope.filesystem_uuid
        || payload.filesystem_type != scope.filesystem_type
        || payload.mountpoint != scope.mountpoint
    {
        return Err("payload identity fields must equal the request scope".to_owned());
    }
    if ext4_fsid_hex(&payload.filesystem_uuid).as_deref() != Some(payload.fsid_hex.as_str()) {
        return Err("fsid_hex must equal the ext4 fold of the filesystem UUID".to_owned());
    }
    for (name, value) in [
        ("mount_id", payload.mount_id),
        ("fragment_size", payload.fragment_size),
        ("blocks_total", payload.blocks_total),
        ("blocks_free", payload.blocks_free),
        ("blocks_available", payload.blocks_available),
        ("inodes_total", payload.inodes_total),
        ("inodes_free", payload.inodes_free),
    ] {
        if value > MAX_SAFE_COUNTER {
            return Err(format!("{name} exceeds the safe integer bound"));
        }
    }
    if payload.fragment_size == 0 {
        return Err("fragment_size must be positive".to_owned());
    }
    if payload.blocks_available > payload.blocks_free || payload.blocks_free > payload.blocks_total
    {
        return Err("block counters must satisfy available <= free <= total".to_owned());
    }
    if payload.inodes_free > payload.inodes_total {
        return Err("inode counters must satisfy free <= total".to_owned());
    }
    Ok(())
}

/// Capacity law: `1000 * used >= threshold * (used + available)`; `None` when
/// the usable size is zero (cannot evaluate).
#[must_use]
pub fn capacity_pressure_state(
    payload: &FilesystemSnapshotPayload,
    threshold_permille: u32,
) -> Option<DetectorState> {
    let used = u128::from(payload.blocks_total.saturating_sub(payload.blocks_free));
    let usable = used + u128::from(payload.blocks_available);
    if usable == 0 {
        return None;
    }
    Some(if 1_000 * used >= u128::from(threshold_permille) * usable {
        DetectorState::Present
    } else {
        DetectorState::ExplicitlyAbsent
    })
}

/// Inode law: `1000 * (total - free) >= threshold * total`; `None` when the
/// filesystem reports no inode accounting.
#[must_use]
pub fn inode_pressure_state(
    payload: &FilesystemSnapshotPayload,
    threshold_permille: u32,
) -> Option<DetectorState> {
    let total = u128::from(payload.inodes_total);
    if total == 0 {
        return None;
    }
    let used = total - u128::from(payload.inodes_free);
    Some(if 1_000 * used >= u128::from(threshold_permille) * total {
        DetectorState::Present
    } else {
        DetectorState::ExplicitlyAbsent
    })
}

// ---------------------------------------------------------------------------
// Profile modules

/// Filesystem capacity-pressure profile.
#[derive(Debug)]
pub struct CapacityProfile;
/// Filesystem inode-pressure profile.
#[derive(Debug)]
pub struct InodesProfile;

/// Registry singleton.
pub static CAPACITY_MODULE: CapacityProfile = CapacityProfile;
/// Registry singleton.
pub static INODES_MODULE: InodesProfile = InodesProfile;

fn validate_binding(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
) -> Result<(), ProfileRefusal> {
    if context.scope.kind != SCOPE_KIND {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "filesystem scope kind must be host_filesystem",
        ));
    }
    validate_scope_value(&context.scope.value, &context.request_subject).map_err(|message| {
        ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "filesystem scope does not correlate with its request subject or bounds",
        )
        .with_detail("error", message)
    })?;
    if context.vantage.kind != "local" || context.vantage.value != json!({}) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "filesystem vantage must be the empty local vantage",
        ));
    }
    Ok(())
}

fn validate_report(
    descriptor: &'static ProfileDescriptor,
    context: &ValidationContext,
    report: &ReportInput,
) -> ValidationResult {
    validate_binding(context, descriptor)?;
    let admitted = validate_common(descriptor, context, report)?;
    if admitted.status == SemanticReportStatus::Failed {
        return Ok(admitted);
    }
    if admitted.observations.len() != 1 {
        return Err(inconsistent(
            context,
            descriptor,
            "a non-failed filesystem report requires exactly one filesystem snapshot",
        ));
    }
    let observation = &admitted.observations[0];
    let payload: FilesystemSnapshotPayload = serde_json::from_value(observation.payload.clone())
        .map_err(|error| {
            invalid_payload(
                context,
                descriptor,
                "filesystem payload does not match the compiled contract",
            )
            .with_detail("error", error.to_string())
        })?;
    validate_basis(descriptor, context, &payload.evidence_basis)?;
    if payload.evidence_basis.capabilities_used != admitted.used_capabilities {
        return Err(inconsistent(
            context,
            descriptor,
            "payload capabilities differ from report used_capabilities",
        ));
    }
    if payload.evidence_basis.access_path != ACCESS_PATH
        || payload.evidence_basis.capabilities_used.len() != CAPABILITIES.len()
        || !CAPABILITIES.iter().all(|capability| {
            payload
                .evidence_basis
                .capabilities_used
                .contains(*capability)
        })
    {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::CapabilityEscape,
            "filesystem access path must declare exactly its three exercised capabilities",
        ));
    }
    if observation.observed_at != admitted.observed_at {
        return Err(inconsistent(
            context,
            descriptor,
            "filesystem snapshot time must equal the report observation time",
        ));
    }
    let scope = validate_scope_value(&context.scope.value, &context.request_subject)
        .map_err(|message| invalid_payload(context, descriptor, &message))?;
    validate_payload_against_scope(&payload, &scope)
        .map_err(|message| invalid_payload(context, descriptor, &message))?;
    if admitted.coverage.get(COVERAGE_KIND) != Some(&SemanticCoverageState::Complete) {
        return Err(inconsistent(
            context,
            descriptor,
            "a filesystem snapshot requires complete filesystem_statistics coverage",
        ));
    }
    Ok(admitted)
}

fn project_report(report: &ValidatedReport) -> ProjectionResult {
    let mut rows: Vec<Box<dyn ProfileProjection>> = Vec::with_capacity(report.observations.len());
    for observation in &report.observations {
        let payload: FilesystemSnapshotPayload =
            serde_json::from_value(observation.payload.clone())
                .map_err(|error| projection_failure(report, error.to_string()))?;
        rows.push(Box::new(FilesystemSnapshotProjection {
            profile: report.profile.clone(),
            ordinal: observation.ordinal,
            subject: observation.subject.clone(),
            payload,
        }));
    }
    Ok(rows)
}

impl ProfileModule for CapacityProfile {
    fn descriptor(&self) -> &'static ProfileDescriptor {
        &CAPACITY_DESCRIPTOR
    }
    fn validate_binding(&self, context: &ValidationContext) -> Result<(), ProfileRefusal> {
        validate_binding(context, self.descriptor())
    }
    fn validate(&self, context: &ValidationContext, report: &ReportInput) -> ValidationResult {
        validate_report(self.descriptor(), context, report)
    }
    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        project_report(report)
    }
    fn detectors(&self) -> &'static [&'static dyn Detector] {
        &CAPACITY_DETECTORS
    }
}

impl ProfileModule for InodesProfile {
    fn descriptor(&self) -> &'static ProfileDescriptor {
        &INODES_DESCRIPTOR
    }
    fn validate_binding(&self, context: &ValidationContext) -> Result<(), ProfileRefusal> {
        validate_binding(context, self.descriptor())
    }
    fn validate(&self, context: &ValidationContext, report: &ReportInput) -> ValidationResult {
        validate_report(self.descriptor(), context, report)
    }
    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        project_report(report)
    }
    fn detectors(&self) -> &'static [&'static dyn Detector] {
        &INODES_DETECTORS
    }
}

// ---------------------------------------------------------------------------
// Detectors

/// Capacity-pressure detector.
#[derive(Debug)]
pub struct CapacityPressureDetector;
/// Inode-pressure detector.
#[derive(Debug)]
pub struct InodePressureDetector;

/// Singleton detector revision.
pub static CAPACITY_PRESSURE_DETECTOR: CapacityPressureDetector = CapacityPressureDetector;
/// Singleton detector revision.
pub static INODE_PRESSURE_DETECTOR: InodePressureDetector = InodePressureDetector;

static CAPACITY_DETECTOR_DESCRIPTOR: LazyLock<DetectorDescriptor> =
    LazyLock::new(|| DetectorDescriptor {
        schema: DETECTOR_DESCRIPTOR_SCHEMA.to_owned(),
        id: CAPACITY_DETECTOR_ID.to_owned(),
        version: 1,
        profile: CAPACITY_DESCRIPTOR.profile.clone(),
        profile_digest: CAPACITY_DESCRIPTOR.digest().unwrap_or_else(|error| {
            panic!("compiled filesystem descriptor must canonicalize: {error}")
        }),
        title: "Filesystem capacity pressure".to_owned(),
        condition: "filesystem_capacity_pressure".to_owned(),
        parameters: DetectorRuleParameters::FilesystemCapacityPressure {
            used_threshold_permille: USED_THRESHOLD_PERMILLE,
        },
    });

static INODES_DETECTOR_DESCRIPTOR: LazyLock<DetectorDescriptor> =
    LazyLock::new(|| DetectorDescriptor {
        schema: DETECTOR_DESCRIPTOR_SCHEMA.to_owned(),
        id: INODES_DETECTOR_ID.to_owned(),
        version: 1,
        profile: INODES_DESCRIPTOR.profile.clone(),
        profile_digest: INODES_DESCRIPTOR.digest().unwrap_or_else(|error| {
            panic!("compiled filesystem descriptor must canonicalize: {error}")
        }),
        title: "Filesystem inode pressure".to_owned(),
        condition: "filesystem_inode_pressure".to_owned(),
        parameters: DetectorRuleParameters::FilesystemInodePressure {
            used_threshold_permille: USED_THRESHOLD_PERMILLE,
        },
    });

static CAPACITY_DETECTORS: [&'static dyn Detector; 1] = [&CAPACITY_PRESSURE_DETECTOR];
static INODES_DETECTORS: [&'static dyn Detector; 1] = [&INODE_PRESSURE_DETECTOR];

enum Law {
    Capacity,
    Inodes,
}

fn evaluate(
    input: &DetectorInput<'_>,
    descriptor: &DetectorDescriptor,
    profile_descriptor: &ProfileDescriptor,
    law: &Law,
) -> DetectorResult {
    let occurrence = match newest_current_report(input, descriptor, profile_descriptor) {
        Ok(occurrence) => occurrence,
        Err(result) => return *result,
    };
    let report = &occurrence.report;
    let Some(observation) = report
        .observations
        .iter()
        .find(|observation| observation.kind == OBSERVATION_KIND)
    else {
        return DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest report has no filesystem snapshot",
            vec!["Missing observations cannot establish absence".to_owned()],
            BTreeMap::from([
                ("observation_kind".to_owned(), OBSERVATION_KIND.to_owned()),
                ("reason".to_owned(), "missing_observation".to_owned()),
            ]),
        );
    };
    let Ok(payload) =
        serde_json::from_value::<FilesystemSnapshotPayload>(observation.payload.clone())
    else {
        return DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the admitted filesystem snapshot cannot be projected",
            vec!["Projection failure requires operator inspection".to_owned()],
            BTreeMap::from([("reason".to_owned(), "projection_failure".to_owned())]),
        );
    };
    let threshold = match descriptor.parameters {
        DetectorRuleParameters::FilesystemCapacityPressure {
            used_threshold_permille,
        }
        | DetectorRuleParameters::FilesystemInodePressure {
            used_threshold_permille,
        } => used_threshold_permille,
        DetectorRuleParameters::LoadPressure { .. }
        | DetectorRuleParameters::SystemdUnitPostcondition { .. }
        | DetectorRuleParameters::HttpEndpointPostcondition { .. }
        | DetectorRuleParameters::SyntheticCacheExecutorResult
        | DetectorRuleParameters::MemoryPressureStall { .. } => {
            unreachable!("filesystem detectors use only filesystem pressure parameters")
        }
    };
    let (state, present_summary, absent_summary, unevaluable) = match law {
        Law::Capacity => (
            capacity_pressure_state(&payload, threshold),
            "available space is at or below 10% of non-reserved capacity on the exact filesystem",
            "current complete counters place available space above 10% of non-reserved capacity",
            (
                "zero_capacity_reported",
                "the filesystem reports no usable capacity",
            ),
        ),
        Law::Inodes => (
            inode_pressure_state(&payload, threshold),
            "free inodes are at or below 10% of total inodes on the exact filesystem",
            "current complete counters place free inodes above 10% of total inodes",
            (
                "inode_accounting_not_reported",
                "the filesystem reports no inode accounting",
            ),
        ),
    };
    let Some(state) = state else {
        return DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            unevaluable.1,
            vec!["A zero denominator cannot establish presence or absence".to_owned()],
            BTreeMap::from([("reason".to_owned(), unevaluable.0.to_owned())]),
        );
    };
    DetectorResult {
        state,
        condition: descriptor.condition.clone(),
        summary: if state == DetectorState::Present {
            present_summary.to_owned()
        } else {
            absent_summary.to_owned()
        },
        evidence: vec![DetectorEvidence {
            report_id: occurrence.report_id.clone(),
            report_sequence: occurrence.report_sequence,
            report_digest: report.report_digest.clone(),
            observation_ordinal: Some(observation.ordinal),
            observed_at: observation.observed_at,
        }],
        limitations: vec![
            "One statfs snapshot establishes no storage health, integrity, performance, quota, or growth fact".to_owned(),
            "Root-reserved blocks and per-user quotas are outside the condition".to_owned(),
        ],
        refusal: None,
        watermark: input.watermark,
    }
}

impl Detector for CapacityPressureDetector {
    fn descriptor(&self) -> &'static DetectorDescriptor {
        &CAPACITY_DETECTOR_DESCRIPTOR
    }
    fn evaluate(&self, input: &DetectorInput<'_>) -> DetectorResult {
        evaluate(
            input,
            self.descriptor(),
            &CAPACITY_DESCRIPTOR,
            &Law::Capacity,
        )
    }
}

impl Detector for InodePressureDetector {
    fn descriptor(&self) -> &'static DetectorDescriptor {
        &INODES_DETECTOR_DESCRIPTOR
    }
    fn evaluate(&self, input: &DetectorInput<'_>) -> DetectorResult {
        evaluate(input, self.descriptor(), &INODES_DESCRIPTOR, &Law::Inodes)
    }
}

fn newest_current_report<'a>(
    input: &DetectorInput<'a>,
    descriptor: &DetectorDescriptor,
    profile_descriptor: &ProfileDescriptor,
) -> Result<&'a DetectorReport, Box<DetectorResult>> {
    let Some(report) = input
        .reports
        .iter()
        .filter(|report| report.report.instance_id == input.instance_id)
        .max_by_key(|report| report.report_sequence)
    else {
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "no admitted filesystem testimony is available",
            vec!["Missing testimony cannot establish absence".to_owned()],
            BTreeMap::from([("reason".to_owned(), "missing_testimony".to_owned())]),
        )));
    };
    let admitted = &report.report;
    if admitted.profile != descriptor.profile
        || admitted.profile_digest != descriptor.profile_digest
    {
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest testimony uses a different profile contract",
            vec!["Profile revisions are never silently combined".to_owned()],
            BTreeMap::from([("reason".to_owned(), "profile_contract_mismatch".to_owned())]),
        )));
    }
    if admitted.status != SemanticReportStatus::Complete
        || admitted.coverage.get(COVERAGE_KIND) != Some(&SemanticCoverageState::Complete)
    {
        // The owner's typed code travels with the refusal when the report
        // carries exactly one collection error and that code is in this
        // module's closed list; NQ copies it and interprets nothing.
        let mut details = BTreeMap::from([
            (
                "reason".to_owned(),
                "incomplete_filesystem_coverage".to_owned(),
            ),
            (
                "report_status".to_owned(),
                match admitted.status {
                    SemanticReportStatus::Complete => "complete",
                    SemanticReportStatus::Partial => "partial",
                    SemanticReportStatus::Failed => "failed",
                }
                .to_owned(),
            ),
            (
                "failure_error_count".to_owned(),
                admitted.failure_error_count.to_string(),
            ),
        ]);
        if let Some(failure) = admitted.single_failure_error()
            && let Some(code) = FilesystemFailureCode::parse(&failure.code)
        {
            details.insert("failure_code".to_owned(), code.as_str().to_owned());
            details.insert(
                "failure_retriable".to_owned(),
                failure.retriable.to_string(),
            );
        }
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest filesystem testimony lacks complete filesystem_statistics coverage",
            vec!["A newer failed report is not shadowed by older success".to_owned()],
            details,
        )));
    }
    let age = input
        .evaluated_at
        .signed_duration_since(admitted.observed_at);
    let reliance = Duration::seconds(
        i64::try_from(profile_descriptor.freshness.reliance_seconds).unwrap_or(i64::MAX),
    );
    if age < Duration::zero() || age > reliance {
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest filesystem testimony is outside its freshness window",
            vec!["Staleness removes reliance; it does not negate testimony".to_owned()],
            BTreeMap::from([
                ("age_seconds".to_owned(), age.num_seconds().to_string()),
                ("reason".to_owned(), "invalid_freshness".to_owned()),
                (
                    "reliance_seconds".to_owned(),
                    profile_descriptor.freshness.reliance_seconds.to_string(),
                ),
            ]),
        )));
    }
    Ok(report)
}

fn inconsistent(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    message: &str,
) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Report,
        ProfileRefusalCode::InconsistentReport,
        message,
    )
}

fn invalid_payload(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    message: &str,
) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Observation,
        ProfileRefusalCode::InvalidPayload,
        message,
    )
}

fn projection_failure(report: &ValidatedReport, error: String) -> ProfileRefusal {
    ProfileRefusal {
        instance_id: report.instance_id.clone(),
        profile: report.profile.clone(),
        boundary: RefusalBoundary::Observation,
        code: ProfileRefusalCode::InvalidPayload,
        message: "admitted filesystem payload could not be projected".to_owned(),
        details: BTreeMap::from([("error".to_owned(), error)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(
        total: u64,
        free: u64,
        avail: u64,
        itotal: u64,
        ifree: u64,
    ) -> FilesystemSnapshotPayload {
        FilesystemSnapshotPayload {
            evidence_basis: EvidenceBasis {
                scope: crate::ScopeGrant {
                    kind: SCOPE_KIND.to_owned(),
                    value: json!({}),
                },
                vantage: crate::VantageGrant {
                    kind: "local".to_owned(),
                    value: json!({}),
                },
                access_path: ACCESS_PATH.to_owned(),
                basis: "kernel_snapshot".to_owned(),
                regime: "normal".to_owned(),
                capabilities_used: CAPABILITIES.iter().map(|c| (*c).to_owned()).collect(),
            },
            machine_id: "1a5b08928e884e73bf4f60a3c73ef497".to_owned(),
            filesystem_uuid: "41530d0d-bad6-4c21-b740-99c992d5126b".to_owned(),
            filesystem_type: "ext4".to_owned(),
            mountpoint: "/data".to_owned(),
            mount_id: 40,
            device_major: 259,
            device_minor: 1,
            fsid_hex: "4a5e0328c49413f6".to_owned(),
            fragment_size: 4096,
            blocks_total: total,
            blocks_free: free,
            blocks_available: avail,
            inodes_total: itotal,
            inodes_free: ifree,
        }
    }

    #[test]
    fn ext4_fsid_fold_matches_the_real_host_sample() {
        assert_eq!(
            ext4_fsid_hex("41530d0d-bad6-4c21-b740-99c992d5126b").as_deref(),
            Some("4a5e0328c49413f6")
        );
        assert_eq!(
            ext4_fsid_hex("c109e6b0-7eb1-4034-89bf-9d17b0e84ad5").as_deref(),
            Some("e10a59cea77bb648")
        );
        assert!(ext4_fsid_hex("not-a-uuid").is_none());
    }

    #[test]
    fn capacity_law_uses_the_non_reserved_denominator_and_refuses_zero() {
        // crow /data sample: total 491_968_500 blocks, free 56_656_020, available 31_646_960 (4096-byte frags)
        let present = payload(
            491_968_500,
            56_656_020,
            31_646_960,
            125_026_304,
            121_788_771,
        );
        assert_eq!(
            capacity_pressure_state(&present, 900),
            Some(DetectorState::Present)
        );
        assert_eq!(
            inode_pressure_state(&present, 900),
            Some(DetectorState::ExplicitlyAbsent)
        );
        // crow / sample: 795 permille used -> absent
        let absent = payload(239_945_484, 58_741_421, 46_537_657, 61_022_208, 56_875_824);
        assert_eq!(
            capacity_pressure_state(&absent, 900),
            Some(DetectorState::ExplicitlyAbsent)
        );
        // Exactly at threshold is present (inclusive): used 900, avail 100.
        let edge = payload(1_000, 100, 100, 10, 1);
        assert_eq!(
            capacity_pressure_state(&edge, 900),
            Some(DetectorState::Present)
        );
        assert_eq!(
            inode_pressure_state(&edge, 900),
            Some(DetectorState::Present)
        );
        let zero = payload(0, 0, 0, 0, 0);
        assert_eq!(capacity_pressure_state(&zero, 900), None);
        assert_eq!(inode_pressure_state(&zero, 900), None);
    }

    #[test]
    fn scope_and_payload_identity_are_exact() {
        let scope_value = json!({
            "schema": SCOPE_SCHEMA,
            "machine_id": "1a5b08928e884e73bf4f60a3c73ef497",
            "filesystem_uuid": "41530d0d-bad6-4c21-b740-99c992d5126b",
            "filesystem_type": "ext4",
            "mountpoint": "/data",
        });
        let subject = subject_for(
            "1a5b08928e884e73bf4f60a3c73ef497",
            "41530d0d-bad6-4c21-b740-99c992d5126b",
        );
        let scope = validate_scope_value(&scope_value, &subject).expect("valid scope");
        assert!(
            validate_scope_value(
                &scope_value,
                "host-filesystem:other/41530d0d-bad6-4c21-b740-99c992d5126b"
            )
            .is_err()
        );
        let mut bad_type = scope_value.clone();
        bad_type["filesystem_type"] = json!("xfs");
        assert!(validate_scope_value(&bad_type, &subject).is_err());
        let mut trailing = scope_value.clone();
        trailing["mountpoint"] = json!("/data/");
        assert!(validate_scope_value(&trailing, &subject).is_err());

        let good = payload(10, 5, 4, 10, 5);
        validate_payload_against_scope(&good, &scope).expect("consistent payload");
        let mut other_fs = good.clone();
        other_fs.filesystem_uuid = "c109e6b0-7eb1-4034-89bf-9d17b0e84ad5".to_owned();
        assert!(validate_payload_against_scope(&other_fs, &scope).is_err());
        let mut wrong_fsid = good.clone();
        wrong_fsid.fsid_hex = "0000000000000000".to_owned();
        assert!(validate_payload_against_scope(&wrong_fsid, &scope).is_err());
        let mut inverted = good.clone();
        inverted.blocks_free = 11;
        assert!(validate_payload_against_scope(&inverted, &scope).is_err());
        let mut unsafe_counter = good;
        unsafe_counter.blocks_total = MAX_SAFE_COUNTER + 1;
        assert!(validate_payload_against_scope(&unsafe_counter, &scope).is_err());
    }
}
