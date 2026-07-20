//! End-to-end collection, admission, evaluation, and public read-model wiring.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use nq_profiles::{
    DetectorInput, DetectorReport, DetectorState, EVALUATOR_SOURCE_DIGEST, EvidenceWatermark,
    ProfileModule, ReportInput as ProfileReportInput, ScopeGrant, SemanticReportStatus,
    ValidatedReport, ValidationContext, VantageGrant, profile_semantic_id,
};
use nq_protocol::{
    Capability, Checkpoint, CollectionBounds, HelperRequest, InstanceId, MonotonicClock,
    MonotonicDeadline, ProfileBinding, ProfileId, ProfileVersion, RequestId, ResponseOutcome,
    ScopeBinding, ScopeKind, Sha256Digest, SubjectBinding, SubjectId, VantageBinding, VantageKind,
};
use nq_store::{
    AdmissionIdentity, AdmissionInput, BindingEventInput, BindingMaterializationInput,
    CanonicalDocument, CollectionInput, CoverageInput, EvaluationInput, FindingEventInput,
    FindingEvidenceInput, GenesisInput, ObservationInput, ProfileDescriptorInput, RefusalInput,
    ReportErrorInput, ReportInput, RunInput, StatusEventInput, Store, SubmissionDisposition,
    SubmissionInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::admission::{
    AdmissionError, AdmissionLock, AdmissionManager, CandidateEvidence, ConformanceReceipt,
};
use crate::config::{Carrier, CheckpointPolicy, NqConfig, ResourceLimits, WatcherConfig};
use crate::coordination::{CoordinationError, InstanceGuard};
use crate::evaluator_identity::EvaluatorRuntimeIdentity;
use crate::identity::{ExecutionIdentity, VerifiedLaunch};
use crate::public::{
    ComponentKind, ComponentStatus, ConditionState, ConditionView, DetectorIdentity,
    FINDING_SNAPSHOT_SCHEMA, FindingSnapshotV2, HealthState, OriginMode, PublicEvidenceReference,
    PublicProfileIdentity, STATUS_SNAPSHOT_SCHEMA, Severity, StatusSnapshotV1, VisibilityState,
    VisibilityView,
};
use crate::runner::{AcquisitionOutcome, RunCapture, StdioRunner};
use crate::unix_runner::{
    UnixAcquisitionOutcome, UnixExchangeCapture, UnixIoPhase, UnixRunner, UnixRunnerOptions,
};

/// Engine-level failures. Expected watcher outcomes are returned as
/// [`CollectionOutcome`] and still committed when applicable.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Generic store failure.
    #[error(transparent)]
    Store(#[from] nq_store::StoreError),
    /// Admission construction or verification failed outside a scheduled
    /// attempt.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// Per-instance collection/binding serialization failed.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
    /// Local filesystem failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The configured profile is not compiled.
    #[error("profile {id} v{version} is not compiled")]
    UnknownProfile {
        /// Profile ID.
        id: String,
        /// Profile version.
        version: u32,
    },
    /// A strict identity token could not be constructed.
    #[error("invalid protocol identity: {0}")]
    Token(String),
    /// Protocol serialization, framing, or echo validation failed in a context
    /// that must itself succeed (such as admission dry collection).
    #[error("helper protocol failure: {0}")]
    Protocol(String),
    /// Compiled profile refused a dry collection or admitted-row reconstruction.
    #[error("profile validation failure: {0}")]
    Profile(String),
    /// Canonical JSON conversion failed.
    #[error("canonical document failure: {0}")]
    Canonical(String),
    /// Durable data contradicted an invariant expected after admission.
    #[error("engine invariant failed: {0}")]
    Invariant(String),
}

/// Result of an operator watcher test/admission workflow.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WatcherActionOutcome {
    /// Dry collection validated without changing active state.
    Tested {
        /// Instance tested.
        instance_id: String,
        /// Canonical dry-report digest.
        report_digest: String,
        /// Validated report state.
        report_status: String,
    },
    /// A new admission was activated.
    Activated {
        /// Instance activated.
        instance_id: String,
        /// Opaque admission identity.
        admission_id: String,
        /// Digest binding subsequent runs.
        binding_digest: String,
        /// Active lock path.
        lock_path: PathBuf,
        /// Whether an earlier active lock was archived.
        previous_lock_archived: bool,
    },
}

/// Result of a rollback or revocation binding transition.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BindingActionOutcome {
    /// A historical admission became active.
    RolledBack {
        /// Exact instance.
        instance_id: String,
        /// Activated admission.
        admission_id: String,
        /// Active binding digest.
        binding_digest: String,
        /// Derived active lock materialization.
        lock_path: PathBuf,
    },
    /// The active admission was revoked and retained in durable history.
    Revoked {
        /// Exact instance.
        instance_id: String,
        /// Revoked admission.
        admission_id: String,
        /// Retained derived historical materialization.
        retained_lock: PathBuf,
    },
}

/// Persisted outcome of one scheduled or explicitly requested collection.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CollectionOutcome {
    /// A report passed acquisition, protocol, and profile admission and was
    /// committed. `failed` remains a valid report status, not a transport error.
    Admitted {
        /// Exact instance.
        instance_id: String,
        /// NQ-owned run ID.
        run_id: String,
        /// NQ-owned immutable report ID.
        report_id: String,
        /// Helper-declared, profile-validated report state.
        report_status: String,
        /// Canonical semantic identity.
        semantic_digest: String,
        /// Number of compiled detector revisions evaluated.
        evaluations: usize,
    },
    /// The active admission could not bind a run; no helper was launched.
    AdmissionRefused {
        /// Exact instance.
        instance_id: String,
        /// Typed operator diagnostic.
        diagnostic: String,
    },
    /// Process acquisition failed; only a run record exists.
    AcquisitionFailed {
        /// Exact instance.
        instance_id: String,
        /// NQ-owned run ID.
        run_id: String,
        /// Acquisition outcome code.
        code: String,
        /// Exact diagnostic carried by the outcome, when it has one.
        ///
        /// The code alone cannot distinguish a refused socket mode from a
        /// spawn failure, so a supervised daemon that logs only the code
        /// cannot explain its own refusal. Preserve the variant's message.
        detail: Option<String>,
    },
    /// A response was retained as rejected custody and never entered detectors.
    Rejected {
        /// Exact instance.
        instance_id: String,
        /// NQ-owned run ID.
        run_id: String,
        /// Exact rejecting plane.
        plane: String,
        /// Typed diagnostic code.
        code: String,
        /// Operator-facing explanation.
        diagnostic: String,
    },
    /// A valid helper refusal was retained separately from transport and report
    /// failure.
    HelperRefused {
        /// Exact instance.
        instance_id: String,
        /// NQ-owned run ID.
        run_id: String,
        /// Exact refusal boundary.
        boundary: String,
        /// Typed helper refusal code.
        code: String,
        /// Operator-facing explanation.
        diagnostic: String,
    },
}

impl CollectionOutcome {
    /// Exact responsible instance.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        match self {
            Self::Admitted { instance_id, .. }
            | Self::AdmissionRefused { instance_id, .. }
            | Self::AcquisitionFailed { instance_id, .. }
            | Self::Rejected { instance_id, .. }
            | Self::HelperRefused { instance_id, .. } => instance_id,
        }
    }

    /// Whether scheduling should resume at its normal cadence. A valid `failed`
    /// report is committed but still asks the scheduler to use retry backoff.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Self::Admitted { report_status, .. } if report_status != "failed"
        )
    }
}

/// End-to-end collection, admission, evaluation, and public read-model engine
/// over one explicitly opened compatible database.
pub struct CollectionEngine {
    config: NqConfig,
    store: Store,
    admission: AdmissionManager,
    runner: StdioRunner,
    unix_runners: BTreeMap<String, BoundUnixRunner>,
    /// The running evaluator's trusted identity, resolved once from the platform
    /// provider at open, or a structured reason it could not be established.
    /// Admission and collection fail closed on the error side.
    evaluator_identity: Result<EvaluatorRuntimeIdentity, String>,
}

struct BoundUnixRunner {
    binding_digest: Option<String>,
    runner: UnixRunner,
}

/// The result of verifying a historical admitted report.
///
/// Its existence is the verdict: verification confirmed that the admission was
/// validly made and its stored judgment is intact, under a current evaluator
/// whose identity matches the admitted one. It may carry recorded ambient
/// observations that qualify the *present* context without altering the
/// *historical* verdict. Verification never re-evaluates and never mutates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReportVerification {
    /// The verified admitted report.
    pub report_id: String,
    /// The admission whose context the report was verified against.
    pub admission_id: String,
    /// The instance both belong to.
    pub instance_id: String,
    /// Recorded ambient observations that qualify the present context.
    pub platform_observations: Vec<PlatformObservation>,
}

/// A recorded ambient-drift observation. It qualifies the context in which a
/// historical admission is inspected; it does not refuse or reinterpret it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformObservation {
    /// The platform runtime version (kernel release) differs from admission
    /// time. Recorded context only — a kernel upgrade does not invalidate a
    /// prior admission, whose identity deliberately excludes the kernel.
    RuntimeDrift {
        /// The platform runtime version recorded at admission.
        admitted: String,
        /// The platform runtime version observed now.
        current: String,
    },
}

/// Why verification refused. Each variant preserves the specific reason rather
/// than flattening every mismatch into "digest changed"; none of them mutate the
/// store or re-run the evaluator.
#[derive(Debug, Error)]
pub enum VerificationRefusal {
    /// The stored admission snapshot failed authentication (corruption,
    /// substitution, broken binding, or an unsupported judgment schema).
    #[error("stored admission snapshot failed authentication: {0}")]
    SnapshotUnauthenticated(#[from] nq_store::SnapshotVerificationError),
    /// The current evaluator identity could not be observed, so drift cannot be
    /// assessed. Fails closed.
    #[error("current evaluator identity is unverifiable: {0}")]
    CurrentIdentityUnverifiable(String),
    /// The identity-observation method changed, so the admitted and current
    /// artifact digests are not comparable.
    #[error("evaluator identity method changed: admitted {admitted}, current {current}")]
    MethodIncompatible {
        /// The identity-observation method recorded at admission.
        admitted: String,
        /// The identity-observation method in effect now.
        current: String,
    },
    /// The running evaluator artifact differs from the admitted one.
    #[error("evaluator artifact drift: admitted {admitted}, current {current}")]
    EvaluatorArtifactDrift {
        /// The evaluator artifact digest recorded at admission.
        admitted: String,
        /// The evaluator artifact digest observed now.
        current: String,
    },
}

impl CollectionEngine {
    /// Open an initialized exactly compatible store and resolve the running
    /// evaluator's identity from the platform provider.
    ///
    /// Identity enters the engine only here and only from the provider — there
    /// is no caller-supplied identity, no provider parameter, and no public
    /// constructor for [`EvaluatorRuntimeIdentity`]. On an unsupported or
    /// unverifiable platform the identity resolves to a structured refusal and
    /// admission and collection fail closed.
    ///
    /// # Errors
    ///
    /// Returns a version, integrity, or database-opening error.
    pub fn open(config: &NqConfig) -> Result<Self, EngineError> {
        Ok(Self {
            config: config.clone(),
            store: Store::open(&config.database_path)?,
            admission: AdmissionManager,
            runner: StdioRunner,
            unix_runners: BTreeMap::new(),
            evaluator_identity: crate::evaluator_identity::resolved(),
        })
    }

    /// Test-only constructor that installs a specific evaluator identity (or a
    /// refusal) without consulting the platform provider. Gated on `cfg(test)`
    /// so no shipping binary and no downstream crate can reach it.
    #[cfg(test)]
    pub(crate) fn open_with_evaluator_identity(
        config: &NqConfig,
        evaluator_identity: Result<EvaluatorRuntimeIdentity, String>,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            config: config.clone(),
            store: Store::open(&config.database_path)?,
            admission: AdmissionManager,
            runner: StdioRunner,
            unix_runners: BTreeMap::new(),
            evaluator_identity,
        })
    }

    /// The running evaluator identity, or a typed refusal carrying the exact
    /// reason it could not be established.
    fn require_evaluator_identity(&self) -> Result<&EvaluatorRuntimeIdentity, EngineError> {
        self.evaluator_identity.as_ref().map_err(|reason| {
            EngineError::Invariant(format!("evaluator runtime identity unavailable: {reason}"))
        })
    }

    /// Assemble the full, typed admission-context identity. Every constituent
    /// except the running evaluator artifact is derived here from the profile,
    /// the compiled evaluator source, or the admission lock; the store computes
    /// `admission_context_digest` from the result.
    fn admission_identity(
        &self,
        profile: &'static dyn ProfileModule,
        lock: &AdmissionLock,
    ) -> Result<AdmissionIdentity, EngineError> {
        let evaluator = self.require_evaluator_identity()?;
        let profile_semantic = profile_semantic_id(profile.descriptor())
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        Ok(AdmissionIdentity {
            profile_semantic_id: parse_identity_digest(
                "profile_semantic_id",
                profile_semantic.as_str(),
            )?,
            detector_identity_digest: detector_identity_digest(profile)?,
            evaluator_source_digest: parse_identity_digest(
                "evaluator_source_digest",
                EVALUATOR_SOURCE_DIGEST,
            )?,
            evaluator_artifact_digest: evaluator.artifact_digest().clone(),
            helper_artifact_digest: parse_identity_digest(
                "helper_artifact_digest",
                &lock.execution.sha256,
            )?,
            config_digest: parse_identity_digest("config_digest", &lock.config_digest)?,
            protocol_version: lock.protocol_version.clone(),
            target_triple: evaluator.target_triple().to_owned(),
            artifact_identity_method: evaluator.artifact_identity_method().to_owned(),
            platform_runtime_version: evaluator.platform_runtime_version().to_owned(),
        })
    }

    /// Verify a historical admitted report (read-only; no re-evaluation).
    ///
    /// Order matters: authenticate the stored snapshot from persisted data
    /// first, rejecting corruption or substitution before consulting any present
    /// runtime state; then observe the current sealed identity; then compare,
    /// distinguishing artifact drift (refuse), method incompatibility (refuse),
    /// and platform drift (recorded, non-refusing). Verification may confirm or
    /// reject the historical admission; it may never recreate it under present
    /// conditions, refresh a binding, or ask the evaluator what it thinks today.
    ///
    /// # Errors
    ///
    /// Returns a [`VerificationRefusal`] preserving the exact reason.
    pub fn verify_admitted(
        &self,
        report_id: &str,
    ) -> Result<AdmittedReportVerification, VerificationRefusal> {
        // Steps 1-2: authenticate the stored snapshot and verify the stored
        // judgment, purely from persisted data. Corruption/substitution/broken
        // binding/unsupported schema are rejected here, before runtime state.
        let snapshot = self.store.verify_admitted_snapshot(report_id)?;

        // Step 3: observe the current sealed identity; fail closed if absent.
        let current = self
            .require_evaluator_identity()
            .map_err(|error| VerificationRefusal::CurrentIdentityUnverifiable(error.to_string()))?;

        // Step 4: compare, distinguishing the reason.
        // Digests observed by different methods are not comparable.
        if snapshot.artifact_identity_method != current.artifact_identity_method() {
            return Err(VerificationRefusal::MethodIncompatible {
                admitted: snapshot.artifact_identity_method,
                current: current.artifact_identity_method().to_owned(),
            });
        }
        if snapshot.evaluator_artifact_digest != current.artifact_digest().as_str() {
            return Err(VerificationRefusal::EvaluatorArtifactDrift {
                admitted: snapshot.evaluator_artifact_digest,
                current: current.artifact_digest().as_str().to_owned(),
            });
        }
        // Platform drift is recorded ambient context, never a refusal.
        let mut platform_observations = Vec::new();
        if snapshot.platform_runtime_version != current.platform_runtime_version() {
            platform_observations.push(PlatformObservation::RuntimeDrift {
                admitted: snapshot.platform_runtime_version.clone(),
                current: current.platform_runtime_version().to_owned(),
            });
        }

        Ok(AdmittedReportVerification {
            report_id: snapshot.report_id,
            admission_id: snapshot.admission_id,
            instance_id: snapshot.instance_id,
            platform_observations,
        })
    }

    /// Test, admit, or rotate a configured helper.
    ///
    /// # Errors
    ///
    /// Returns a typed acquisition, protocol, profile, admission, or durable
    /// storage error. A failed workflow never silently refreshes a lock.
    #[allow(clippy::too_many_lines)]
    pub fn watcher_action(
        &mut self,
        watcher: &WatcherConfig,
        action: &str,
    ) -> Result<WatcherActionOutcome, EngineError> {
        let _guard = InstanceGuard::acquire(
            &self.config.database_path,
            &watcher.instance_id,
            &format!("watcher-{action}"),
        )?;
        self.reconcile_pending_binding(watcher)?;
        let previous = if matches!(action, "admit" | "rotate") {
            self.authoritative_active_lock(watcher)?
        } else {
            None
        };
        let profile = resolve(watcher)?;
        // Bind conformance to the exact bytes that existed before the dry
        // exchange, then prove they did not change while the helper ran.
        let execution_before =
            ExecutionIdentity::resolve_command(&watcher.command).map_err(AdmissionError::from)?;
        let launch = VerifiedLaunch::open_expected(&watcher.command, &execution_before)
            .map_err(AdmissionError::from)?;
        let corpus = nq_protocol::verify_embedded_conformance_corpus()
            .map_err(|error| EngineError::Protocol(error.to_string()))?;
        let dry = self.dry_exchange(watcher, profile, launch)?;
        execution_before
            .verify_current()
            .map_err(AdmissionError::from)?;
        let status = semantic_report_status(dry.validated.status).to_owned();
        if action == "test" {
            self.stop_unix_runner(&watcher.instance_id);
            return Ok(WatcherActionOutcome::Tested {
                instance_id: watcher.instance_id.clone(),
                report_digest: dry.report_digest,
                report_status: status,
            });
        }
        if !matches!(action, "admit" | "rotate") {
            return Err(EngineError::Invariant(format!(
                "unsupported watcher action {action}"
            )));
        }

        let descriptor_digest = profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let lock = AdmissionManager::candidate_with_execution(
            watcher,
            CandidateEvidence {
                profile_digest: descriptor_digest.as_str().to_owned(),
                protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                // Until an optional helper support-description exchange is
                // standardized, the compiled profile vocabulary is the
                // mechanically possible set. Admission still intersects it
                // with the configured ceiling; a helper can only narrow
                // further by using fewer capabilities in each report.
                declared_capabilities: profile
                    .descriptor()
                    .capabilities
                    .iter()
                    .map(|term| term.name.clone())
                    .collect(),
                conformance: ConformanceReceipt {
                    tool_version: corpus.version.verifier_version,
                    protocol_passed: true,
                    protocol_corpus_digest: corpus.version.corpus_digest.to_string(),
                    protocol_fixtures_checked: corpus.fixtures_checked,
                    dry_collection_passed: true,
                    dry_report_digest: Some(dry.report_digest),
                },
            },
            execution_before.clone(),
        )?;
        let verification = self.admission.verify_opened_execution(
            watcher,
            &lock,
            descriptor_digest.as_str(),
            nq_protocol::HELPER_PROTOCOL_VERSION,
            &execution_before,
        )?;

        // Assemble the typed admission-context identity before taking a mutable
        // store borrow. This refuses (fail closed) when the running evaluator
        // identity is unavailable, rather than admitting under a fabricated one.
        let identity = self.admission_identity(profile, &lock)?;
        self.store.append_admission(&AdmissionInput {
            admission_id: lock.admission_id.clone(),
            instance_id: lock.instance_id.clone(),
            identity,
            execution_chain: canonical(&lock.execution)?,
            profile_id: lock.profile.id.clone(),
            profile_version: lock.profile.version.to_string(),
            profile_digest: lock.profile.digest.clone(),
            capability_grant: canonical(&lock.granted_capabilities)?,
            conformance: canonical(&lock.conformance)?,
            lock: canonical(&lock)?,
            admitted_at: timestamp(lock.admitted_at),
            operator_identity: canonical(&lock.operator)?,
        })?;

        let archived = previous.is_some();
        let lock_path =
            self.transition_binding(watcher, "activate", Some(&lock), previous.as_ref(), action)?;
        // Every binding change creates a new helper lifetime. A dry-collection
        // process is never silently promoted into the active persistent one.
        self.stop_unix_runner(&watcher.instance_id);
        Ok(WatcherActionOutcome::Activated {
            instance_id: watcher.instance_id.clone(),
            admission_id: lock.admission_id,
            binding_digest: verification.binding_digest,
            lock_path,
            previous_lock_archived: archived,
        })
    }

    /// Execute and persist one admitted collection attempt.
    ///
    /// # Errors
    ///
    /// Returns only local engine/storage failures. Expected helper, protocol,
    /// and admission outcomes are retained and returned as `CollectionOutcome`.
    #[allow(clippy::too_many_lines)]
    pub fn collect(&mut self, watcher: &WatcherConfig) -> Result<CollectionOutcome, EngineError> {
        let _guard =
            InstanceGuard::acquire(&self.config.database_path, &watcher.instance_id, "collect")?;
        // Fail closed before any persistence: a collection stamps evaluator
        // identity onto its finding events, so refuse up front when it is
        // unavailable rather than commit an admitted report and only then refuse
        // at evaluation, leaving a durable report behind.
        self.require_evaluator_identity()?;
        self.reconcile_pending_binding(watcher)?;
        let profile = resolve(watcher)?;
        let descriptor_digest = profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let authoritative = match self.authoritative_active_lock(watcher) {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                self.stop_unix_runner(&watcher.instance_id);
                let outcome = CollectionOutcome::AdmissionRefused {
                    instance_id: watcher.instance_id.clone(),
                    diagnostic: "no active authoritative admission binding".to_owned(),
                };
                self.record_instance_status(watcher, &outcome)?;
                return Ok(outcome);
            }
            Err(error) => {
                self.stop_unix_runner(&watcher.instance_id);
                let outcome = CollectionOutcome::AdmissionRefused {
                    instance_id: watcher.instance_id.clone(),
                    diagnostic: error.to_string(),
                };
                self.record_instance_status(watcher, &outcome)?;
                return Ok(outcome);
            }
        };
        let lock = match (|| {
            let lock = authoritative;
            let launch = VerifiedLaunch::open_expected(&watcher.command, &lock.execution)?;
            self.admission
                .verify_opened_execution(
                    watcher,
                    &lock,
                    descriptor_digest.as_str(),
                    nq_protocol::HELPER_PROTOCOL_VERSION,
                    launch.identity(),
                )
                .map(|verification| (lock, verification, launch))
        })() {
            Ok(binding) => binding,
            Err(error) => {
                self.stop_unix_runner(&watcher.instance_id);
                let outcome = CollectionOutcome::AdmissionRefused {
                    instance_id: watcher.instance_id.clone(),
                    diagnostic: error.to_string(),
                };
                self.record_instance_status(watcher, &outcome)?;
                return Ok(outcome);
            }
        };
        let (lock, verification, launch) = lock;
        let checkpoint_contract_digest = checkpoint_contract_digest(
            watcher,
            &lock,
            &verification.binding_digest,
            descriptor_digest.as_str(),
        )?;
        let checkpoint = match watcher.checkpoint_policy {
            CheckpointPolicy::Disabled => None,
            CheckpointPolicy::AdvanceAfterAdmission => self
                .store
                .latest_checkpoint(&watcher.instance_id, &checkpoint_contract_digest)?
                .map(|bytes| serde_json::from_slice(&bytes).map(|value| Checkpoint { value }))
                .transpose()
                .map_err(|error| {
                    EngineError::Invariant(format!("stored checkpoint cannot decode: {error}"))
                })?,
        };
        let request = build_request(watcher, profile, &lock.granted_capabilities, checkpoint)?;
        let request_json = nq_protocol::canonical_json_bytes(&request)
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let capture = self.run_capture(
            watcher,
            &request_json,
            Some(&verification.binding_digest),
            launch,
        );

        let run_id = Uuid::new_v4().to_string();
        let run = RunInput {
            run_id: run_id.clone(),
            request_id: request.request_id.to_string(),
            instance_id: watcher.instance_id.clone(),
            admission_id: Some(lock.admission_id.clone()),
            binding_digest: verification.binding_digest,
            checkpoint_contract_digest,
            profile_id: watcher.profile.id.clone(),
            profile_version: watcher.profile.version.to_string(),
            profile_digest: descriptor_digest.as_str().to_owned(),
            carrier: carrier_name(watcher.carrier).into(),
            started_at: timestamp(capture.started_at),
            deadline_at: timestamp(
                capture.started_at
                    + Duration::milliseconds(
                        i64::try_from(watcher.schedule.deadline_ms).unwrap_or(i64::MAX),
                    ),
            ),
            finished_at: timestamp(capture.finished_at),
            acquisition_outcome: acquisition_code(&capture.outcome).to_owned(),
            execution_identity: canonical(&lock.execution)?,
            resource_outcome: capture_resource_document(&capture, &watcher.resources)?,
        };

        if capture.outcome != AcquisitionOutcome::Response {
            let submission = rejected_transport_submission(&run_id, watcher, &capture)?;
            self.store
                .commit_collection(&CollectionInput { run, submission })?;
            let outcome = CollectionOutcome::AcquisitionFailed {
                instance_id: watcher.instance_id.clone(),
                run_id,
                code: acquisition_code(&capture.outcome).to_owned(),
                detail: acquisition_detail(&capture.outcome),
            };
            self.record_instance_status(watcher, &outcome)?;
            return Ok(outcome);
        }

        let raw = capture.stdout.clone();
        let response = match nq_protocol::parse_response(&request, &raw) {
            Ok(response) => response,
            Err(error) => {
                let refusal = rejection_refusal(
                    watcher,
                    "protocol",
                    "invalid_response",
                    &error.to_string(),
                    &run_id,
                )?;
                let submission = SubmissionInput {
                    submission_id: Uuid::new_v4().to_string(),
                    raw_bytes: raw,
                    received_at: timestamp(capture.finished_at),
                    protocol_outcome: "rejected".into(),
                    disposition: SubmissionDisposition::Rejected {
                        rejection_code: Some("invalid_response".into()),
                        refusal: Some(refusal),
                    },
                };
                self.store.commit_collection(&CollectionInput {
                    run,
                    submission: Some(submission),
                })?;
                let outcome = CollectionOutcome::Rejected {
                    instance_id: watcher.instance_id.clone(),
                    run_id,
                    plane: "protocol".into(),
                    code: "invalid_response".into(),
                    diagnostic: error.to_string(),
                };
                self.record_instance_status(watcher, &outcome)?;
                return Ok(outcome);
            }
        };

        match response.outcome {
            ResponseOutcome::Refusal { refusal } => {
                let boundary = enum_token(&refusal.boundary)?;
                let code = enum_token(&refusal.code)?;
                let stored_refusal = RefusalInput {
                    refusal_id: Uuid::new_v4().to_string(),
                    source_kind: refusal_source(&boundary).into(),
                    responsible_instance_id: refusal.responsible_instance_id.to_string(),
                    boundary: boundary.clone(),
                    code: code.clone(),
                    detail: canonical(&refusal)?,
                    created_at: timestamp(capture.finished_at),
                };
                let submission = SubmissionInput {
                    submission_id: Uuid::new_v4().to_string(),
                    raw_bytes: raw,
                    received_at: timestamp(capture.finished_at),
                    protocol_outcome: "valid_refusal".into(),
                    disposition: SubmissionDisposition::Rejected {
                        rejection_code: Some(code.clone()),
                        refusal: Some(stored_refusal),
                    },
                };
                self.store.commit_collection(&CollectionInput {
                    run,
                    submission: Some(submission),
                })?;
                let outcome = CollectionOutcome::HelperRefused {
                    instance_id: watcher.instance_id.clone(),
                    run_id,
                    boundary,
                    code,
                    diagnostic: refusal.message,
                };
                self.record_instance_status(watcher, &outcome)?;
                Ok(outcome)
            }
            ResponseOutcome::Report { report } => {
                let report_digest = nq_protocol::semantic_digest(&report)
                    .map_err(|error| EngineError::Canonical(error.to_string()))?;
                let normalized = ProfileReportInput::from_protocol(&report, &report_digest)
                    .map_err(|error| EngineError::Profile(error.to_string()))?;
                let context = ValidationContext::from_request(
                    &request,
                    capture.finished_at,
                    Duration::seconds(60),
                );
                match profile.validate(&context, &normalized) {
                    Err(refusal) => {
                        let code = enum_token(&refusal.code)?;
                        let boundary = enum_token(&refusal.boundary)?;
                        let stored_refusal = RefusalInput {
                            refusal_id: Uuid::new_v4().to_string(),
                            source_kind: "profile".into(),
                            responsible_instance_id: refusal.instance_id.clone(),
                            boundary: boundary.clone(),
                            code: code.clone(),
                            detail: canonical(&refusal)?,
                            created_at: timestamp(capture.finished_at),
                        };
                        let submission = SubmissionInput {
                            submission_id: Uuid::new_v4().to_string(),
                            raw_bytes: raw,
                            received_at: timestamp(capture.finished_at),
                            protocol_outcome: "valid_report".into(),
                            disposition: SubmissionDisposition::Rejected {
                                rejection_code: Some(code.clone()),
                                refusal: Some(stored_refusal),
                            },
                        };
                        self.store.commit_collection(&CollectionInput {
                            run,
                            submission: Some(submission),
                        })?;
                        let outcome = CollectionOutcome::Rejected {
                            instance_id: watcher.instance_id.clone(),
                            run_id,
                            plane: "profile".into(),
                            code,
                            diagnostic: refusal.message,
                        };
                        self.record_instance_status(watcher, &outcome)?;
                        Ok(outcome)
                    }
                    Ok(validated) => {
                        let report_id = Uuid::new_v4().to_string();
                        let report_status = semantic_report_status(validated.status).to_owned();
                        let stored_report = store_report(
                            &report_id,
                            watcher,
                            profile,
                            &report,
                            &validated,
                            capture.finished_at,
                        )?;
                        let submission = SubmissionInput {
                            submission_id: Uuid::new_v4().to_string(),
                            raw_bytes: raw,
                            received_at: timestamp(capture.finished_at),
                            protocol_outcome: "valid_report".into(),
                            disposition: SubmissionDisposition::Admitted(stored_report),
                        };
                        let receipt = self.store.commit_collection(&CollectionInput {
                            run,
                            submission: Some(submission),
                        })?;
                        let evaluations = self.evaluate_instance(watcher, profile)?;
                        let outcome = CollectionOutcome::Admitted {
                            instance_id: watcher.instance_id.clone(),
                            run_id,
                            report_id,
                            report_status,
                            semantic_digest: receipt.semantic_digest.ok_or_else(|| {
                                EngineError::Invariant(
                                    "admitted collection returned no semantic digest".into(),
                                )
                            })?,
                            evaluations,
                        };
                        self.record_instance_status(watcher, &outcome)?;
                        Ok(outcome)
                    }
                }
            }
        }
    }

    /// Re-evaluate compiled detectors at a new wall-clock time without
    /// collecting or refreshing any evidence.
    ///
    /// # Errors
    ///
    /// Returns when the profile is unavailable, admitted evidence cannot be
    /// reconstructed, or the evaluation cannot be committed atomically.
    pub fn freshness_sweep(&mut self, watcher: &WatcherConfig) -> Result<usize, EngineError> {
        let _guard = InstanceGuard::acquire(
            &self.config.database_path,
            &watcher.instance_id,
            "freshness-sweep",
        )?;
        self.reconcile_pending_binding(watcher)?;
        let profile = resolve(watcher)?;
        self.evaluate_instance(watcher, profile)
    }

    /// Activate one retained historical admission under the same serialized,
    /// crash-recoverable transition protocol used by admission and rotation.
    ///
    /// # Errors
    ///
    /// Returns when the historical lock is not a byte-exact durable admission,
    /// no longer verifies against current local facts, or cannot be
    /// materialized durably.
    pub fn rollback_binding(
        &mut self,
        watcher: &WatcherConfig,
        historical: &Path,
    ) -> Result<BindingActionOutcome, EngineError> {
        let _guard = InstanceGuard::acquire(
            &self.config.database_path,
            &watcher.instance_id,
            "watcher-rollback",
        )?;
        self.reconcile_pending_binding(watcher)?;
        let previous = self.authoritative_active_lock(watcher)?;
        let profile = resolve(watcher)?;
        let lock = self.admission.load(historical)?;
        let verification = self.admission.verify(
            watcher,
            &lock,
            profile
                .descriptor()
                .digest()
                .map_err(|error| EngineError::Canonical(error.to_string()))?
                .as_str(),
            nq_protocol::HELPER_PROTOCOL_VERSION,
        )?;
        let durable = self.store.admission(&lock.admission_id)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "historical lock {} has no durable admission record",
                lock.admission_id
            ))
        })?;
        if durable.instance_id != watcher.instance_id
            || durable.lock_json != canonical(&lock)?.as_bytes()
        {
            return Err(EngineError::Invariant(format!(
                "historical lock {} differs from its durable admission record",
                lock.admission_id
            )));
        }
        let lock_path = self.transition_binding(
            watcher,
            "rollback",
            Some(&lock),
            previous.as_ref(),
            "operator_rollback",
        )?;
        self.stop_unix_runner(&watcher.instance_id);
        Ok(BindingActionOutcome::RolledBack {
            instance_id: watcher.instance_id.clone(),
            admission_id: lock.admission_id,
            binding_digest: verification.binding_digest,
            lock_path,
        })
    }

    /// Revoke the exact active authoritative admission. The lock remains in
    /// immutable `SQLite` admission history and in a derived history path; no
    /// active lock is left behind.
    ///
    /// # Errors
    ///
    /// Returns when there is no active authoritative binding or the durable
    /// transition/materialization cannot complete.
    pub fn revoke_binding(
        &mut self,
        watcher: &WatcherConfig,
    ) -> Result<BindingActionOutcome, EngineError> {
        let _guard = InstanceGuard::acquire(
            &self.config.database_path,
            &watcher.instance_id,
            "watcher-revoke",
        )?;
        self.reconcile_pending_binding(watcher)?;
        let previous = self.authoritative_active_lock(watcher)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "instance {} has no active authoritative admission",
                watcher.instance_id
            ))
        })?;
        let admission_id = previous.admission_id.clone();
        let retained_lock = history_lock_path(&self.config.admissions_dir, &previous);
        self.transition_binding(
            watcher,
            "revoke",
            None,
            Some(&previous),
            "operator_revocation",
        )?;
        self.stop_unix_runner(&watcher.instance_id);
        Ok(BindingActionOutcome::Revoked {
            instance_id: watcher.instance_id.clone(),
            admission_id,
            retained_lock,
        })
    }

    fn transition_binding(
        &mut self,
        watcher: &WatcherConfig,
        event_kind: &str,
        desired_lock: Option<&AdmissionLock>,
        previous_lock: Option<&AdmissionLock>,
        reason_code: &str,
    ) -> Result<PathBuf, EngineError> {
        let operation_id = Uuid::new_v4().to_string();
        let binding_event_id = Uuid::new_v4().to_string();
        let binding_digest = desired_lock
            .or(previous_lock)
            .ok_or_else(|| EngineError::Invariant("binding transition has no lock basis".into()))
            .and_then(|lock| Ok(self.admission.binding_digest(lock)?))?;
        let plan = BindingMaterializationPlan {
            schema: BINDING_MATERIALIZATION_PLAN_SCHEMA.to_owned(),
            operation_id: operation_id.clone(),
            instance_id: watcher.instance_id.clone(),
            binding_event_id: binding_event_id.clone(),
            admissions_root: AdmissionRootIdentity::resolve(&self.config.admissions_dir)?,
            desired_lock: desired_lock.cloned(),
            previous_lock: previous_lock.cloned(),
        };
        plan.validate()?;
        let plan_document = canonical(&plan)?;
        let occurred_at = timestamp(Utc::now());
        let event = BindingEventInput {
            binding_event_id: binding_event_id.clone(),
            instance_id: watcher.instance_id.clone(),
            event_kind: event_kind.to_owned(),
            admission_id: desired_lock.map(|lock| lock.admission_id.clone()),
            binding_digest,
            occurred_at: occurred_at.clone(),
            reason_code: Some(reason_code.to_owned()),
            detail: canonical(&json!({
                "schema": "nq.binding_event_detail.v1",
                "materialization_operation_id": operation_id,
                "previous_admission_id": previous_lock.map(|lock| &lock.admission_id),
            }))?,
        };
        let intent = BindingMaterializationInput {
            materialization_event_id: Uuid::new_v4().to_string(),
            operation_id: operation_id.clone(),
            instance_id: watcher.instance_id.clone(),
            binding_event_id: binding_event_id.clone(),
            phase: "intent".to_owned(),
            occurred_at,
            detail: plan_document.clone(),
        };
        self.store.begin_binding_transition(&event, &intent)?;
        // From this point onward SQLite is authoritative. A failure or process
        // death leaves the intent pending for the next lock holder to replay.
        self.apply_binding_materialization(&plan)?;
        self.store
            .complete_binding_materialization(&binding_materialization_completion(
                &plan,
                &plan_document,
            )?)?;
        Ok(self.active_lock_path(watcher))
    }

    fn reconcile_pending_binding(&mut self, watcher: &WatcherConfig) -> Result<bool, EngineError> {
        let Some(pending) = self
            .store
            .pending_binding_materialization(&watcher.instance_id)?
        else {
            return Ok(false);
        };
        let document = CanonicalDocument::from_canonical_bytes(pending.detail_json.clone())?;
        let plan: BindingMaterializationPlan = serde_json::from_slice(document.as_bytes())
            .map_err(|error| {
                EngineError::Invariant(format!(
                    "pending binding materialization {} cannot decode: {error}",
                    pending.operation_id
                ))
            })?;
        plan.validate()?;
        if plan.operation_id != pending.operation_id
            || plan.instance_id != watcher.instance_id
            || plan.binding_event_id != pending.binding_event_id
        {
            return Err(EngineError::Invariant(format!(
                "pending binding materialization {} metadata disagrees with its plan",
                pending.operation_id
            )));
        }
        self.apply_binding_materialization(&plan)?;
        self.store
            .complete_binding_materialization(&binding_materialization_completion(
                &plan, &document,
            )?)?;
        self.stop_unix_runner(&watcher.instance_id);
        Ok(true)
    }

    fn apply_binding_materialization(
        &self,
        plan: &BindingMaterializationPlan,
    ) -> Result<(), EngineError> {
        plan.validate()?;
        let current_root = AdmissionRootIdentity::resolve(&self.config.admissions_dir)?;
        if current_root != plan.admissions_root {
            return Err(EngineError::Invariant(format!(
                "pending binding materialization {} targets a different admissions root",
                plan.operation_id
            )));
        }
        let (root_handle, admissions_root) = plan.admissions_root.open_retained()?;
        let active_path = admissions_root.join(format!("{}.json", plan.instance_id));
        let current = if active_path.exists() {
            Some(self.admission.load(&active_path)?)
        } else {
            None
        };
        let current_digest = current
            .as_ref()
            .map(|lock| self.admission.binding_digest(lock))
            .transpose()?;
        let desired_digest = plan
            .desired_lock
            .as_ref()
            .map(|lock| self.admission.binding_digest(lock))
            .transpose()?;
        let previous_digest = plan
            .previous_lock
            .as_ref()
            .map(|lock| self.admission.binding_digest(lock))
            .transpose()?;
        if current_digest.is_some()
            && current_digest != desired_digest
            && current_digest != previous_digest
        {
            return Err(EngineError::Invariant(format!(
                "active lock for {} changed outside its pending materialization",
                plan.instance_id
            )));
        }

        if let Some(previous) = &plan.previous_lock {
            archive_active_lock(&admissions_root, previous)?;
        }
        if let Some(desired) = &plan.desired_lock {
            self.admission.activate(&admissions_root, desired)?;
        } else {
            if current.is_none() && plan.previous_lock.is_none() {
                return Err(EngineError::Invariant(
                    "revocation materialization has no previous lock".into(),
                ));
            }
            match fs::remove_file(&active_path) {
                Ok(()) => root_handle.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn authoritative_active_lock(
        &self,
        watcher: &WatcherConfig,
    ) -> Result<Option<AdmissionLock>, EngineError> {
        let active_path = self.active_lock_path(watcher);
        let latest = self.store.latest_binding(&watcher.instance_id)?;
        let Some(latest) = latest else {
            if active_path.exists() {
                return Err(EngineError::Invariant(format!(
                    "instance {} has an active lock but no authoritative binding event",
                    watcher.instance_id
                )));
            }
            return Ok(None);
        };
        if matches!(latest.event_kind.as_str(), "revoke" | "quiesce") {
            if active_path.exists() {
                return Err(EngineError::Invariant(format!(
                    "instance {} is durably {} but still has an active lock",
                    watcher.instance_id, latest.event_kind
                )));
            }
            return Ok(None);
        }
        let admission_id = latest.admission_id.as_deref().ok_or_else(|| {
            EngineError::Invariant(format!(
                "active binding event {} lacks admission identity",
                latest.binding_event_id
            ))
        })?;
        let durable = self.store.admission(admission_id)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "active binding references missing admission {admission_id}"
            ))
        })?;
        let document = CanonicalDocument::from_canonical_bytes(durable.lock_json)?;
        let expected: AdmissionLock =
            serde_json::from_slice(document.as_bytes()).map_err(|error| {
                EngineError::Invariant(format!(
                    "durable admission {admission_id} lock cannot decode: {error}"
                ))
            })?;
        let expected_digest = self.admission.binding_digest(&expected)?;
        if durable.instance_id != watcher.instance_id
            || expected.instance_id != watcher.instance_id
            || expected.admission_id != admission_id
            || expected_digest != latest.binding_digest
        {
            return Err(EngineError::Invariant(format!(
                "active binding event {} disagrees with admission {}",
                latest.binding_event_id, admission_id
            )));
        }
        let materialized = self.admission.load(&active_path)?;
        if materialized != expected {
            return Err(EngineError::Invariant(format!(
                "active lock materialization for {} differs from authoritative admission {}",
                watcher.instance_id, admission_id
            )));
        }
        Ok(Some(materialized))
    }

    fn dry_exchange(
        &mut self,
        watcher: &WatcherConfig,
        profile: &'static dyn ProfileModule,
        launch: VerifiedLaunch,
    ) -> Result<DryExchange, EngineError> {
        let request = build_request(watcher, profile, &watcher.capability_ceiling, None)?;
        let request_json = nq_protocol::canonical_json_bytes(&request)
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let capture = self.run_capture(watcher, &request_json, None, launch);
        if capture.outcome != AcquisitionOutcome::Response {
            return Err(dry_collection_error(&capture.outcome));
        }
        let response = nq_protocol::parse_response(&request, &capture.stdout)
            .map_err(|error| EngineError::Protocol(error.to_string()))?;
        let ResponseOutcome::Report { report } = response.outcome else {
            return Err(EngineError::Protocol(
                "helper refused the admission dry collection".into(),
            ));
        };
        let digest = nq_protocol::semantic_digest(&report)
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let input = ProfileReportInput::from_protocol(&report, &digest)
            .map_err(|error| EngineError::Profile(error.to_string()))?;
        let context =
            ValidationContext::from_request(&request, capture.finished_at, Duration::seconds(60));
        let validated = profile
            .validate(&context, &input)
            .map_err(|refusal| EngineError::Profile(refusal.message))?;
        Ok(DryExchange {
            report_digest: digest.to_string(),
            validated,
        })
    }

    fn run_capture(
        &mut self,
        watcher: &WatcherConfig,
        request_json: &[u8],
        binding_digest: Option<&str>,
        launch: VerifiedLaunch,
    ) -> RunCapture {
        let deadline = StdDuration::from_millis(watcher.schedule.deadline_ms);
        match watcher.carrier {
            Carrier::Stdio => {
                self.runner
                    .run_verified(&launch, request_json, deadline, &watcher.resources)
            }
            Carrier::Unix => {
                self.run_unix_capture(watcher, request_json, deadline, binding_digest, launch)
            }
        }
    }

    fn run_unix_capture(
        &mut self,
        watcher: &WatcherConfig,
        request_json: &[u8],
        deadline: StdDuration,
        binding_digest: Option<&str>,
        launch: VerifiedLaunch,
    ) -> RunCapture {
        let started_at = Utc::now();
        let started = Instant::now();
        if self
            .unix_runners
            .get(&watcher.instance_id)
            .is_some_and(|active| active.binding_digest.as_deref() != binding_digest)
        {
            self.stop_unix_runner(&watcher.instance_id);
        }
        if !self.unix_runners.contains_key(&watcher.instance_id) {
            let options = UnixRunnerOptions::for_account(
                &self.config.helper_runtime_dir,
                &watcher.instance_id,
                deadline,
                watcher.resources.max_stderr_bytes,
                launch.execution_account(),
            )
            .with_isolation_limits(watcher.resources.isolation_limits());
            match UnixRunner::launch_verified(launch, options) {
                Ok(runner) => {
                    self.unix_runners.insert(
                        watcher.instance_id.clone(),
                        BoundUnixRunner {
                            binding_digest: binding_digest.map(str::to_owned),
                            runner,
                        },
                    );
                }
                Err(error) => {
                    return RunCapture {
                        started_at,
                        finished_at: Utc::now(),
                        duration_ms: elapsed_ms(started),
                        exit_code: None,
                        stdout: Vec::new(),
                        stderr: error.stderr,
                        outcome: AcquisitionOutcome::CarrierStartupFailed {
                            message: error.failure.to_string(),
                        },
                    };
                }
            }
        }

        let remaining = deadline.saturating_sub(started.elapsed());
        let exchange = self
            .unix_runners
            .get_mut(&watcher.instance_id)
            .expect("runner inserted above")
            .runner
            .exchange(
                request_json,
                remaining,
                watcher.resources.max_response_bytes,
            );
        let keep_running = exchange.outcome == UnixAcquisitionOutcome::Response;
        let capture = normalize_unix_capture(started_at, started, exchange);
        if !keep_running {
            self.stop_unix_runner(&watcher.instance_id);
        }
        capture
    }

    fn stop_unix_runner(&mut self, instance_id: &str) {
        if let Some(mut active) = self.unix_runners.remove(instance_id) {
            active.runner.shutdown();
        }
    }

    /// Terminate a persistent helper when its active lock has been removed or
    /// replaced since the runner was bound. This lightweight check compares
    /// canonical lock identity; the next collection still performs complete
    /// executable/profile/config verification.
    ///
    /// # Errors
    ///
    /// Returns only unexpected local errors while reading a present lock.
    pub fn quiesce_if_binding_changed(
        &mut self,
        watcher: &WatcherConfig,
    ) -> Result<bool, EngineError> {
        let Some(expected) = self
            .unix_runners
            .get(&watcher.instance_id)
            .and_then(|active| active.binding_digest.clone())
        else {
            return Ok(false);
        };
        let path = self.active_lock_path(watcher);
        let actual = self
            .admission
            .load(&path)
            .and_then(|lock| self.admission.binding_digest(&lock));
        match actual {
            Ok(actual) if actual == expected => Ok(false),
            Ok(_) | Err(AdmissionError::Io { .. }) => {
                self.stop_unix_runner(&watcher.instance_id);
                Ok(true)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn active_lock_path(&self, watcher: &WatcherConfig) -> PathBuf {
        self.config
            .admissions_dir
            .join(format!("{}.json", watcher.instance_id))
    }

    fn record_instance_status(
        &mut self,
        watcher: &WatcherConfig,
        outcome: &CollectionOutcome,
    ) -> Result<(), EngineError> {
        let (state, code) = match outcome {
            CollectionOutcome::Admitted { report_status, .. } if report_status == "complete" => {
                ("healthy", "report_complete")
            }
            CollectionOutcome::Admitted { report_status, .. } if report_status == "partial" => {
                ("degraded", "report_partial")
            }
            CollectionOutcome::Admitted { .. } => ("failed", "report_failed"),
            CollectionOutcome::AdmissionRefused { .. } => ("failed", "admission_refused"),
            CollectionOutcome::AcquisitionFailed { .. } => ("failed", "collection_failed"),
            CollectionOutcome::Rejected { .. } => ("failed", "report_rejected"),
            CollectionOutcome::HelperRefused { .. } => ("degraded", "helper_refused"),
        };
        self.store.record_status(&StatusEventInput {
            status_event_id: Uuid::new_v4().to_string(),
            component_kind: "instance".into(),
            component_id: watcher.instance_id.clone(),
            state: state.into(),
            code: code.into(),
            detail: canonical(outcome)?,
            observed_at: timestamp(Utc::now()),
        })?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate_instance(
        &mut self,
        watcher: &WatcherConfig,
        profile: &'static dyn ProfileModule,
    ) -> Result<usize, EngineError> {
        let snapshot = self
            .store
            .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))?;
        let watermark = snapshot
            .watermarks
            .first()
            .ok_or_else(|| EngineError::Invariant("missing instance watermark".into()))?;
        let profile_version = watcher.profile.version.to_string();
        let profile_digest = profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let reports = reconstruct_detector_reports(
            &snapshot.reports,
            profile,
            &watcher.profile.id,
            &profile_version,
            profile_digest.as_str(),
        )?;
        let current_findings = self.store.finding_snapshots()?;
        let subject_json = serde_json::to_string(&Value::String(watcher.subject.clone()))
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        // Every finding event records the running evaluator that produced it;
        // refuse (fail closed) rather than stamp findings with a fabricated one.
        let evaluator_artifact_digest = self
            .require_evaluator_identity()?
            .artifact_digest()
            .as_str()
            .to_owned();
        let mut count = 0;
        for detector in profile.detectors() {
            let evaluated_at = Utc::now();
            let detector_input = DetectorInput {
                instance_id: &watcher.instance_id,
                evaluated_at,
                watermark: EvidenceWatermark(
                    u64::try_from(watermark.max_report_sequence).unwrap_or(u64::MAX),
                ),
                reports: &reports,
            };
            let result = detector.evaluate(&detector_input);
            let descriptor = detector.descriptor();
            let detector_digest = descriptor.digest().map_err(EngineError::Canonical)?;
            let evaluation_id = Uuid::new_v4().to_string();
            let outcome = match result.state {
                DetectorState::Present => "condition_present",
                DetectorState::ExplicitlyAbsent => "condition_explicitly_absent",
                DetectorState::CannotEvaluate => "cannot_evaluate",
            };
            let refusal = result
                .refusal
                .as_ref()
                .map(|refusal| {
                    Ok::<RefusalInput, EngineError>(RefusalInput {
                        refusal_id: Uuid::new_v4().to_string(),
                        source_kind: "evaluation".into(),
                        responsible_instance_id: refusal.instance_id.clone(),
                        boundary: enum_token(&refusal.boundary)?,
                        code: enum_token(&refusal.code)?,
                        detail: canonical(refusal)?,
                        created_at: timestamp(evaluated_at),
                    })
                })
                .transpose()?;
            let evaluation = EvaluationInput {
                evaluation_id: evaluation_id.clone(),
                detector_id: descriptor.id.clone(),
                detector_version: descriptor.version.to_string(),
                detector_digest: detector_digest.clone(),
                evaluator_artifact_digest: evaluator_artifact_digest.clone(),
                started_at: timestamp(evaluated_at),
                evaluated_at: timestamp(evaluated_at),
                outcome: outcome.into(),
                detail: canonical(&result)?,
                watermarks: snapshot.watermarks.clone(),
                refusal,
            };
            let detector_version = descriptor.version.to_string();
            let lineage = FindingLineage {
                instance_id: &watcher.instance_id,
                detector_id: &descriptor.id,
                detector_version: &detector_version,
                detector_digest: &detector_digest,
                profile_id: &watcher.profile.id,
                profile_version: &profile_version,
                profile_digest: profile_digest.as_str(),
                subject_json: &subject_json,
            };
            let current = find_current_finding(&current_findings, &lineage);
            let finding = build_finding_event(
                watcher,
                profile,
                descriptor,
                &result,
                evaluated_at,
                current,
                &snapshot.reports,
            )?;
            self.store
                .commit_evaluation(&evaluation, finding.as_ref())?;
            count += 1;
        }
        Ok(count)
    }
}

#[derive(Clone, Copy)]
struct FindingLineage<'a> {
    instance_id: &'a str,
    detector_id: &'a str,
    detector_version: &'a str,
    detector_digest: &'a str,
    profile_id: &'a str,
    profile_version: &'a str,
    profile_digest: &'a str,
    subject_json: &'a str,
}

impl FindingLineage<'_> {
    fn matches(self, finding: &nq_store::FindingSnapshotRow) -> bool {
        finding.instance_id == self.instance_id
            && finding.detector_id == self.detector_id
            && finding.detector_version == self.detector_version
            && finding.detector_digest == self.detector_digest
            && finding.profile_id == self.profile_id
            && finding.profile_version == self.profile_version
            && finding.profile_digest == self.profile_digest
            && finding.subject_json == self.subject_json
    }
}

fn find_current_finding<'a>(
    findings: &'a [nq_store::FindingSnapshotRow],
    lineage: &FindingLineage<'_>,
) -> Option<&'a nq_store::FindingSnapshotRow> {
    findings.iter().find(|finding| lineage.matches(finding))
}

fn report_matches_profile_contract(
    report: &nq_store::AdmittedReportRow,
    profile_id: &str,
    profile_version: &str,
    profile_digest: &str,
) -> bool {
    report.profile_id == profile_id
        && report.profile_version == profile_version
        && report.profile_digest == profile_digest
}

fn reconstruct_detector_reports(
    rows: &[nq_store::AdmittedReportRow],
    profile: &'static dyn ProfileModule,
    profile_id: &str,
    profile_version: &str,
    profile_digest: &str,
) -> Result<Vec<DetectorReport>, EngineError> {
    rows.iter()
        .filter(|row| {
            report_matches_profile_contract(row, profile_id, profile_version, profile_digest)
        })
        .map(|row| reconstruct_admitted(row, profile))
        .collect()
}

struct DryExchange {
    report_digest: String,
    validated: ValidatedReport,
}

const BINDING_MATERIALIZATION_PLAN_SCHEMA: &str = "nq.binding_materialization_plan.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingMaterializationPlan {
    schema: String,
    operation_id: String,
    instance_id: String,
    binding_event_id: String,
    admissions_root: AdmissionRootIdentity,
    desired_lock: Option<AdmissionLock>,
    previous_lock: Option<AdmissionLock>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdmissionRootIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
}

impl AdmissionRootIdentity {
    fn resolve(path: &Path) -> Result<Self, EngineError> {
        let canonical_path = fs::canonicalize(path)?;
        let metadata = fs::metadata(&canonical_path)?;
        if !metadata.is_dir() {
            return Err(EngineError::Invariant(format!(
                "admissions root {} is not a directory",
                path.display()
            )));
        }
        Ok(Self {
            canonical_path,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        })
    }

    fn open_retained(&self) -> Result<(File, PathBuf), EngineError> {
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&self.canonical_path)?;
        let metadata = directory.metadata()?;
        let opened = Self {
            canonical_path: self.canonical_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        };
        if &opened != self {
            return Err(EngineError::Invariant(format!(
                "admissions root {} changed before materialization",
                self.canonical_path.display()
            )));
        }
        let retained_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        if fs::metadata(&retained_path)?.ino() != self.inode {
            return Err(EngineError::Invariant(
                "retained admissions-root descriptor identity disagrees".into(),
            ));
        }
        Ok((directory, retained_path))
    }

    fn validate_shape(&self) -> Result<(), EngineError> {
        if !self.canonical_path.is_absolute()
            || self.device == 0
            || self.inode == 0
            || self.mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(EngineError::Invariant(
                "malformed admissions-root identity in materialization plan".into(),
            ));
        }
        Ok(())
    }
}

impl BindingMaterializationPlan {
    fn validate(&self) -> Result<(), EngineError> {
        if self.schema != BINDING_MATERIALIZATION_PLAN_SCHEMA
            || Uuid::parse_str(&self.operation_id).is_err()
            || Uuid::parse_str(&self.binding_event_id).is_err()
            || self.instance_id.is_empty()
            || self.instance_id.len() > 128
            || self.desired_lock.is_none() && self.previous_lock.is_none()
        {
            return Err(EngineError::Invariant(
                "malformed binding materialization plan identity".into(),
            ));
        }
        self.admissions_root.validate_shape()?;
        if !self
            .instance_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(EngineError::Invariant(
                "binding materialization instance is not a safe path component".into(),
            ));
        }
        for lock in [self.desired_lock.as_ref(), self.previous_lock.as_ref()]
            .into_iter()
            .flatten()
        {
            if lock.instance_id != self.instance_id {
                return Err(EngineError::Invariant(format!(
                    "binding materialization {} contains a lock for another instance",
                    self.operation_id
                )));
            }
            AdmissionManager.binding_digest(lock)?;
        }
        Ok(())
    }
}

fn binding_materialization_completion(
    plan: &BindingMaterializationPlan,
    intent: &CanonicalDocument,
) -> Result<BindingMaterializationInput, EngineError> {
    Ok(BindingMaterializationInput {
        materialization_event_id: Uuid::new_v4().to_string(),
        operation_id: plan.operation_id.clone(),
        instance_id: plan.instance_id.clone(),
        binding_event_id: plan.binding_event_id.clone(),
        phase: "completed".to_owned(),
        occurred_at: timestamp(Utc::now()),
        detail: canonical(&json!({
            "schema": "nq.binding_materialization_completion.v1",
            "intent_digest": intent.digest(),
        }))?,
    })
}

fn resolve(watcher: &WatcherConfig) -> Result<&'static dyn ProfileModule, EngineError> {
    nq_profiles::resolve_profile(&watcher.profile.id, watcher.profile.version).ok_or_else(|| {
        EngineError::UnknownProfile {
            id: watcher.profile.id.clone(),
            version: watcher.profile.version,
        }
    })
}

/// Validate every configured binding against the explicitly compiled profile
/// catalog before any directory, database, listener, or helper is touched.
///
/// # Errors
///
/// Returns the exact instance and catalog vocabulary mismatch.
pub fn validate_compiled_config(config: &NqConfig) -> Result<(), EngineError> {
    for watcher in &config.watchers {
        let profile = resolve(watcher)?;
        let descriptor = profile.descriptor();
        if !watcher.subject.starts_with(&descriptor.subjects.namespace) {
            return Err(EngineError::Profile(format!(
                "instance {} subject is outside profile namespace {}",
                watcher.instance_id, descriptor.subjects.namespace
            )));
        }
        if !descriptor
            .scope_kinds
            .iter()
            .any(|term| term.name == watcher.scope.kind)
        {
            return Err(EngineError::Profile(format!(
                "instance {} uses unknown scope kind {}",
                watcher.instance_id, watcher.scope.kind
            )));
        }
        if !descriptor
            .vantages
            .iter()
            .any(|term| term.name == watcher.vantage.kind)
        {
            return Err(EngineError::Profile(format!(
                "instance {} uses unknown vantage {}",
                watcher.instance_id, watcher.vantage.kind
            )));
        }
        if let Some(capability) = watcher.capability_ceiling.iter().find(|capability| {
            !descriptor
                .capabilities
                .iter()
                .any(|term| term.name == capability.as_str())
        }) {
            return Err(EngineError::Profile(format!(
                "instance {} capability ceiling contains profile-unknown {}",
                watcher.instance_id, capability
            )));
        }
        let context = ValidationContext {
            instance_id: watcher.instance_id.clone(),
            request_subject: watcher.subject.clone(),
            scope: ScopeGrant {
                kind: watcher.scope.kind.clone(),
                value: watcher.scope.value.clone(),
            },
            vantage: VantageGrant {
                kind: watcher.vantage.kind.clone(),
                value: watcher.vantage.value.clone(),
            },
            granted_capabilities: watcher.capability_ceiling.clone(),
            received_at: Utc::now(),
            max_observations: u32::try_from(watcher.resources.max_observations)
                .unwrap_or(u32::MAX)
                .min(descriptor.limits.max_observations),
            max_future_skew: Duration::seconds(60),
        };
        profile.validate_binding(&context).map_err(|refusal| {
            EngineError::Profile(format!(
                "instance {} binding refused at {:?}/{:?}: {}",
                watcher.instance_id, refusal.boundary, refusal.code, refusal.message
            ))
        })?;
    }
    Ok(())
}

/// Compute the exact cursor namespace for one admitted execution contract.
/// A new admission or any profile, subject, scope, vantage, or capability
/// change produces a different namespace and therefore cannot inherit a stale
/// helper cursor. V1 profile descriptors do not declare cross-implementation
/// checkpoint portability, so the admission and binding identities are
/// intentionally included and every rotation starts a new cursor namespace.
///
/// # Errors
///
/// Returns when the contract cannot be represented as bounded canonical JSON.
pub fn checkpoint_contract_digest(
    watcher: &WatcherConfig,
    lock: &AdmissionLock,
    binding_digest: &str,
    profile_digest: &str,
) -> Result<String, EngineError> {
    Ok(canonical(&json!({
        "schema": "nq.checkpoint_contract.v1",
        "instance_id": watcher.instance_id,
        "admission_id": lock.admission_id,
        "binding_digest": binding_digest,
        "profile": {
            "id": watcher.profile.id,
            "version": watcher.profile.version,
            "digest": profile_digest,
        },
        "subject": watcher.subject,
        "scope": watcher.scope,
        "vantage": watcher.vantage,
        "granted_capabilities": lock.granted_capabilities,
    }))?
    .digest()
    .to_owned())
}

fn build_request(
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    granted: &BTreeSet<String>,
    checkpoint: Option<Checkpoint>,
) -> Result<HelperRequest, EngineError> {
    let descriptor = profile.descriptor();
    let digest = descriptor
        .digest()
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let request = HelperRequest {
        schema: nq_protocol::HELPER_REQUEST_SCHEMA.into(),
        protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.into(),
        request_id: token(RequestId::new(Uuid::new_v4().to_string()))?,
        instance_id: token(InstanceId::new(watcher.instance_id.clone()))?,
        profile: ProfileBinding {
            id: token(ProfileId::new(descriptor.profile.id.clone()))?,
            version: token(ProfileVersion::new(descriptor.profile.version.to_string()))?,
            digest: Sha256Digest::parse(digest.as_str().to_owned())
                .map_err(|error| EngineError::Token(error.to_string()))?,
        },
        binding: SubjectBinding {
            subject: token(SubjectId::new(watcher.subject.clone()))?,
            scope: ScopeBinding {
                kind: token(ScopeKind::new(watcher.scope.kind.clone()))?,
                value: watcher.scope.value.clone(),
            },
            vantage: VantageBinding {
                kind: token(VantageKind::new(watcher.vantage.kind.clone()))?,
                value: watcher.vantage.value.clone(),
            },
        },
        granted_capabilities: granted
            .iter()
            .map(|capability| token(Capability::new(capability.clone())))
            .collect::<Result<_, _>>()?,
        checkpoint,
        deadline: MonotonicDeadline {
            clock: MonotonicClock::LinuxBoottime,
            expires_at_ns: boottime_ns()?
                .saturating_add(watcher.schedule.deadline_ms.saturating_mul(1_000_000)),
        },
        bounds: CollectionBounds {
            max_response_bytes: u32::try_from(watcher.resources.max_response_bytes)
                .unwrap_or(u32::MAX),
            max_observations: u32::try_from(watcher.resources.max_observations)
                .unwrap_or(u32::MAX)
                .min(descriptor.limits.max_observations),
            max_payload_bytes: descriptor.limits.max_payload_bytes,
            max_coverage_entries: descriptor.limits.max_coverage_declarations,
            max_report_errors: 128,
            max_checkpoint_bytes: 65_536,
        },
    };
    nq_protocol::validate_request(&request)
        .map_err(|error| EngineError::Protocol(error.to_string()))?;
    Ok(request)
}

fn store_report(
    report_id: &str,
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    report: &nq_protocol::EvidenceReport,
    validated: &ValidatedReport,
    received_at: DateTime<Utc>,
) -> Result<ReportInput, EngineError> {
    let coverage: Vec<_> = report
        .coverage
        .iter()
        .enumerate()
        .map(|(ordinal, coverage)| {
            Ok(CoverageInput {
                ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                coverage_kind: coverage.kind.to_string(),
                coverage_state: enum_token(&coverage.state)?,
                detail: canonical(&json!({
                    "subject": coverage.subject,
                    "detail": coverage.detail,
                }))?,
            })
        })
        .collect::<Result<_, EngineError>>()?;
    let observations = report
        .observations
        .iter()
        .map(|observation| {
            let observation_coverage = report
                .coverage
                .iter()
                .filter(|coverage| {
                    coverage
                        .subject
                        .as_ref()
                        .is_none_or(|subject| subject.as_str() == observation.subject.as_str())
                })
                .enumerate()
                .map(|(ordinal, coverage)| {
                    Ok(CoverageInput {
                        ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                        coverage_kind: coverage.kind.to_string(),
                        coverage_state: enum_token(&coverage.state)?,
                        detail: canonical(&coverage.detail)?,
                    })
                })
                .collect::<Result<_, EngineError>>()?;
            Ok(ObservationInput {
                ordinal: observation.ordinal,
                kind: observation.kind.to_string(),
                subject: canonical(&observation.subject.to_string())?,
                observed_at: timestamp(observation.observed_at),
                payload: canonical(&observation.payload)?,
                coverage: observation_coverage,
            })
        })
        .collect::<Result<_, EngineError>>()?;
    let errors = report
        .errors
        .iter()
        .enumerate()
        .map(|(ordinal, error)| {
            Ok(ReportErrorInput {
                ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                code: error.code.to_string(),
                detail: canonical(error)?,
            })
        })
        .collect::<Result<_, EngineError>>()?;
    Ok(ReportInput {
        report_id: report_id.to_owned(),
        instance_id: watcher.instance_id.clone(),
        profile_id: profile.descriptor().profile.id.clone(),
        profile_version: profile.descriptor().profile.version.to_string(),
        profile_digest: profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?
            .as_str()
            .to_owned(),
        observed_at: timestamp(validated.observed_at),
        received_at: timestamp(received_at),
        report_status: semantic_report_status(validated.status).into(),
        canonical_report: canonical(report)?,
        // The persisted, versioned admitted judgment. The store binds it to the
        // admission context reached through the run and derives its digest.
        validated_report: canonical(validated)?,
        next_checkpoint: report
            .next_checkpoint
            .as_ref()
            .map(|checkpoint| canonical(&checkpoint.value))
            .transpose()?,
        admitted_at: timestamp(Utc::now()),
        observations,
        coverage,
        errors,
    })
}

fn rejected_transport_submission(
    run_id: &str,
    watcher: &WatcherConfig,
    capture: &RunCapture,
) -> Result<Option<SubmissionInput>, EngineError> {
    let retains_exact_submission = !capture.stdout.is_empty()
        && matches!(
            capture.outcome,
            AcquisitionOutcome::MalformedFraming { .. }
                | AcquisitionOutcome::MalformedJson { .. }
                | AcquisitionOutcome::ExitNonzero { .. }
        );
    if !retains_exact_submission {
        return Ok(None);
    }
    let code = acquisition_code(&capture.outcome).to_owned();
    let refusal = rejection_refusal(
        watcher,
        "acquisition",
        &code,
        "helper bytes did not form a successful protocol exchange",
        run_id,
    )?;
    Ok(Some(SubmissionInput {
        submission_id: Uuid::new_v4().to_string(),
        raw_bytes: capture.stdout.clone(),
        received_at: timestamp(capture.finished_at),
        protocol_outcome: "not_validated".into(),
        disposition: SubmissionDisposition::Rejected {
            rejection_code: Some(code),
            refusal: Some(refusal),
        },
    }))
}

fn rejection_refusal(
    watcher: &WatcherConfig,
    source: &str,
    code: &str,
    message: &str,
    _run_id: &str,
) -> Result<RefusalInput, EngineError> {
    Ok(RefusalInput {
        refusal_id: Uuid::new_v4().to_string(),
        source_kind: source.into(),
        responsible_instance_id: watcher.instance_id.clone(),
        boundary: source.into(),
        code: code.into(),
        detail: canonical(&json!({"message": message}))?,
        created_at: timestamp(Utc::now()),
    })
}

fn capture_resource_document(
    capture: &RunCapture,
    limits: &ResourceLimits,
) -> Result<CanonicalDocument, EngineError> {
    canonical(&json!({
        "duration_ms": capture.duration_ms,
        "exit_code": capture.exit_code,
        "hard_limits": {
            "address_space_bytes_per_process": limits.max_address_space_bytes,
            "cpu_seconds_per_process": limits.max_cpu_seconds,
            "processes_per_execution_uid": limits.max_processes,
            "open_files_per_process": limits.max_open_files,
            "file_bytes_per_regular_file": limits.max_file_bytes,
            "core_bytes": 0,
        },
        "stdout_bytes_retained": capture.stdout.len(),
        "stderr_bytes_retained": capture.stderr.len(),
        "stderr_hex": hex::encode(&capture.stderr),
        "outcome": capture.outcome,
    }))
}

fn reconstruct_admitted(
    row: &nq_store::AdmittedReportRow,
    profile: &'static dyn ProfileModule,
) -> Result<DetectorReport, EngineError> {
    let report: nq_protocol::EvidenceReport = serde_json::from_slice(&row.canonical_json)
        .map_err(|error| EngineError::Invariant(format!("stored report cannot decode: {error}")))?;
    let digest = Sha256Digest::parse(row.semantic_digest.clone())
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    let normalized = ProfileReportInput::from_protocol(&report, &digest)
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    let context = ValidationContext {
        instance_id: row.instance_id.clone(),
        request_subject: report.binding.subject.to_string(),
        scope: ScopeGrant {
            kind: report.binding.scope.kind.to_string(),
            value: report.binding.scope.value.clone(),
        },
        vantage: VantageGrant {
            kind: report.binding.vantage.kind.to_string(),
            value: report.binding.vantage.value.clone(),
        },
        granted_capabilities: report
            .used_capabilities
            .iter()
            .map(ToString::to_string)
            .collect(),
        received_at: parse_timestamp(&row.received_at)?,
        max_observations: profile.descriptor().limits.max_observations,
        max_future_skew: Duration::seconds(60),
    };
    let validated = profile.validate(&context, &normalized).map_err(|refusal| {
        EngineError::Invariant(format!(
            "previously admitted report {} no longer validates: {}",
            row.report_id, refusal.message
        ))
    })?;
    let report_sequence = u64::try_from(row.report_sequence).map_err(|_| {
        EngineError::Invariant(format!(
            "admitted report {} has a negative durable sequence",
            row.report_id
        ))
    })?;
    if report_sequence == 0 {
        return Err(EngineError::Invariant(format!(
            "admitted report {} has a zero durable sequence",
            row.report_id
        )));
    }
    Ok(DetectorReport {
        report_id: row.report_id.clone(),
        report_sequence,
        report: validated,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
/// Parse an already-`sha256:`-shaped identity string into the typed digest the
/// store requires. A failure here is an internal invariant, not caller input.
fn parse_identity_digest(field: &str, value: &str) -> Result<Sha256Digest, EngineError> {
    Sha256Digest::parse(value).map_err(|_| {
        EngineError::Invariant(format!("{field} is not a valid sha256 digest: {value}"))
    })
}

/// Canonical ordered-set digest of a profile's detector semantic ids. Binds the
/// admitted judging mechanism to the exact detector suite, independent of which
/// detector later produces any one finding.
fn detector_identity_digest(
    profile: &'static dyn ProfileModule,
) -> Result<Sha256Digest, EngineError> {
    let mut ids: Vec<String> = profile
        .detectors()
        .iter()
        .map(|detector| {
            detector
                .descriptor()
                .digest()
                .map_err(EngineError::Canonical)
        })
        .collect::<Result<_, _>>()?;
    ids.sort();
    ids.dedup();
    nq_protocol::semantic_digest(&ids).map_err(|error| EngineError::Canonical(error.to_string()))
}

#[allow(clippy::too_many_lines)]
fn build_finding_event(
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    descriptor: &nq_profiles::DetectorDescriptor,
    result: &nq_profiles::DetectorResult,
    evaluated_at: DateTime<Utc>,
    current: Option<&nq_store::FindingSnapshotRow>,
    rows: &[nq_store::AdmittedReportRow],
) -> Result<Option<FindingEventInput>, EngineError> {
    if current.is_none() && result.state != DetectorState::Present {
        return Ok(None);
    }
    if current.is_some_and(|finding| finding.condition_state == "explicitly_absent")
        && result.state == DetectorState::ExplicitlyAbsent
    {
        return Ok(None);
    }
    let event_kind = match (current, result.state) {
        (None, DetectorState::Present) => "opened",
        (Some(existing), DetectorState::Present)
            if existing.condition_state == "explicitly_absent" =>
        {
            "reopened"
        }
        (Some(_), DetectorState::ExplicitlyAbsent) => "resolved",
        (Some(_), _) => "updated",
        (None, _) => return Ok(None),
    };
    let finding_id =
        current.map_or_else(|| Uuid::new_v4().to_string(), |row| row.finding_id.clone());
    let visibility = visibility_for(result, profile, evaluated_at, rows);
    let evidence = if result.evidence.is_empty() {
        current
            .map(|finding| retained_finding_evidence(finding, rows))
            .transpose()?
            .unwrap_or_default()
    } else {
        result
            .evidence
            .iter()
            .enumerate()
            .map(|(ordinal, evidence)| {
                let report_sequence = i64::try_from(evidence.report_sequence).map_err(|_| {
                    EngineError::Invariant(format!(
                        "detector cited report {} with a sequence outside SQLite INTEGER",
                        evidence.report_id
                    ))
                })?;
                let row = rows
                    .iter()
                    .find(|row| {
                        row.report_id == evidence.report_id
                            && row.report_sequence == report_sequence
                            && row.semantic_digest == evidence.report_digest
                    })
                    .ok_or_else(|| {
                        EngineError::Invariant(format!(
                            "detector cited unknown report occurrence {} at sequence {} with digest {}",
                            evidence.report_id,
                            evidence.report_sequence,
                            evidence.report_digest
                        ))
                    })?;
                Ok(FindingEvidenceInput {
                    ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                    report_id: row.report_id.clone(),
                    report_semantic_digest: row.semantic_digest.clone(),
                    observation_ordinal: evidence.observation_ordinal,
                    observed_at: timestamp(evidence.observed_at),
                    received_at: row.received_at.clone(),
                })
            })
            .collect::<Result<Vec<_>, EngineError>>()?
    };
    let newest = evidence
        .iter()
        .filter_map(|evidence| rows.iter().find(|row| row.report_id == evidence.report_id))
        .max_by_key(|row| row.report_sequence);
    Ok(Some(FindingEventInput {
        event_id: Uuid::new_v4().to_string(),
        finding_id,
        event_kind: event_kind.into(),
        instance_id: watcher.instance_id.clone(),
        profile_id: profile.descriptor().profile.id.clone(),
        profile_version: profile.descriptor().profile.version.to_string(),
        profile_digest: profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?
            .as_str()
            .into(),
        subject: canonical(&watcher.subject)?,
        condition_name: descriptor.condition.clone(),
        condition_state: if result.state == DetectorState::CannotEvaluate {
            current.map_or("cannot_evaluate", |finding| {
                finding.condition_state.as_str()
            })
        } else {
            detector_state(result.state)
        }
        .into(),
        visibility_state: visibility.0.into(),
        operator_work_state: current.map_or_else(
            || "unreviewed".to_owned(),
            |row| row.operator_work_state.clone(),
        ),
        severity: match result.state {
            DetectorState::Present => "warning".to_owned(),
            DetectorState::ExplicitlyAbsent => "info".to_owned(),
            DetectorState::CannotEvaluate => {
                current.map_or_else(|| "info".to_owned(), |finding| finding.severity.clone())
            }
        },
        summary: if result.state == DetectorState::CannotEvaluate {
            current.map_or_else(|| result.summary.clone(), |finding| finding.summary.clone())
        } else {
            result.summary.clone()
        },
        limitations: canonical(&result.limitations)?,
        safe_next_checks: canonical(&vec![
            "Inspect the cited admitted evidence".to_owned(),
            "Run `nq watcher test` if collection remains unavailable".to_owned(),
        ])?,
        freshness: canonical(&visibility.1)?,
        basis: canonical(&json!({
            "profile_digest": profile.descriptor().digest().map_err(|error| EngineError::Canonical(error.to_string()))?.as_str(),
            "vantage": watcher.vantage.kind,
            "scope": watcher.scope,
        }))?,
        refusal: result.refusal.as_ref().map(canonical).transpose()?,
        origin_mode: "native".into(),
        historical_refs: canonical(&Vec::<String>::new())?,
        observed_at: newest.map(|row| row.observed_at.clone()),
        received_at: newest.map(|row| row.received_at.clone()),
        created_at: timestamp(evaluated_at),
        evidence,
    }))
}

fn retained_finding_evidence(
    finding: &nq_store::FindingSnapshotRow,
    rows: &[nq_store::AdmittedReportRow],
) -> Result<Vec<FindingEvidenceInput>, EngineError> {
    let references: Vec<PublicEvidenceReference> = serde_json::from_str(&finding.evidence_json)
        .map_err(|error| {
            EngineError::Invariant(format!("invalid retained finding evidence: {error}"))
        })?;
    references
        .into_iter()
        .enumerate()
        .map(|(ordinal, reference)| {
            if !rows.iter().any(|row| {
                row.report_id == reference.report_id
                    && row.semantic_digest == reference.semantic_digest
            }) {
                return Err(EngineError::Invariant(format!(
                    "retained finding evidence {} is outside the evaluation watermark",
                    reference.report_id
                )));
            }
            Ok(FindingEvidenceInput {
                ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                report_id: reference.report_id,
                report_semantic_digest: reference.semantic_digest,
                observation_ordinal: reference.observation_ordinal,
                observed_at: timestamp(reference.observed_at),
                received_at: timestamp(reference.received_at),
            })
        })
        .collect()
}

fn visibility_for(
    result: &nq_profiles::DetectorResult,
    profile: &'static dyn ProfileModule,
    evaluated_at: DateTime<Utc>,
    rows: &[nq_store::AdmittedReportRow],
) -> (&'static str, Value) {
    if result.state != DetectorState::CannotEvaluate {
        return ("sufficient", json!({"state": "current"}));
    }
    let Some(newest) = rows.iter().max_by_key(|row| row.report_sequence) else {
        return ("missing", json!({"state": "missing"}));
    };
    if newest.report_status == "partial" || newest.report_status == "failed" {
        return (
            "partial",
            json!({"state": newest.report_status, "observed_at": newest.observed_at}),
        );
    }
    let observed = parse_timestamp(&newest.observed_at).ok();
    let stale = observed.is_none_or(|observed| {
        evaluated_at.signed_duration_since(observed)
            > Duration::seconds(
                i64::try_from(profile.descriptor().freshness.reliance_seconds).unwrap_or(i64::MAX),
            )
    });
    if stale {
        (
            "stale",
            json!({
                "state": "stale",
                "observed_at": newest.observed_at,
                "reliance_seconds": profile.descriptor().freshness.reliance_seconds,
            }),
        )
    } else {
        ("refused", json!({"state": "cannot_evaluate"}))
    }
}

fn archive_active_lock(
    admissions_dir: &Path,
    previous: &AdmissionLock,
) -> Result<PathBuf, EngineError> {
    let history = history_lock_directory(admissions_dir, previous);
    fs::create_dir_all(&history)?;
    let manager = AdmissionManager;
    Ok(manager.activate(&history, previous)?)
}

fn history_lock_directory(admissions_dir: &Path, lock: &AdmissionLock) -> PathBuf {
    admissions_dir
        .join("history")
        .join(&lock.instance_id)
        .join(&lock.admission_id)
}

fn history_lock_path(admissions_dir: &Path, lock: &AdmissionLock) -> PathBuf {
    history_lock_directory(admissions_dir, lock).join(format!("{}.json", lock.instance_id))
}

fn boottime_ns() -> Result<u64, EngineError> {
    let uptime = fs::read_to_string("/proc/uptime")?;
    let value = uptime
        .split_whitespace()
        .next()
        .ok_or_else(|| EngineError::Invariant("/proc/uptime is empty".into()))?;
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, "0"));
    let seconds = seconds
        .parse::<u64>()
        .map_err(|error| EngineError::Invariant(format!("invalid /proc/uptime: {error}")))?;
    let mut nanos = fraction
        .as_bytes()
        .iter()
        .take(9)
        .fold(0_u64, |value, byte| {
            value
                .saturating_mul(10)
                .saturating_add(u64::from(byte.saturating_sub(b'0')))
        });
    for _ in fraction.len().min(9)..9 {
        nanos = nanos.saturating_mul(10);
    }
    Ok(seconds.saturating_mul(1_000_000_000).saturating_add(nanos))
}

fn token<T>(value: Result<T, nq_protocol::TokenError>) -> Result<T, EngineError> {
    value.map_err(|error| EngineError::Token(error.to_string()))
}

fn canonical<T: Serialize>(value: &T) -> Result<CanonicalDocument, EngineError> {
    CanonicalDocument::from_serializable(value).map_err(EngineError::from)
}

fn enum_token<T: Serialize>(value: &T) -> Result<String, EngineError> {
    serde_json::to_value(value)
        .map_err(|error| EngineError::Canonical(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| EngineError::Canonical("enum did not serialize as a string".into()))
}

fn semantic_report_status(status: SemanticReportStatus) -> &'static str {
    match status {
        SemanticReportStatus::Complete => "complete",
        SemanticReportStatus::Partial => "partial",
        SemanticReportStatus::Failed => "failed",
    }
}

fn normalize_unix_capture(
    started_at: DateTime<Utc>,
    started: Instant,
    capture: UnixExchangeCapture,
) -> RunCapture {
    let exit_code = match &capture.outcome {
        UnixAcquisitionOutcome::HelperExited { code } => *code,
        _ => None,
    };
    RunCapture {
        started_at,
        finished_at: capture.finished_at,
        duration_ms: elapsed_ms(started),
        exit_code,
        stdout: capture.response,
        stderr: capture.stderr,
        outcome: unix_acquisition_outcome(capture.outcome),
    }
}

fn unix_acquisition_outcome(outcome: UnixAcquisitionOutcome) -> AcquisitionOutcome {
    match outcome {
        UnixAcquisitionOutcome::Response => AcquisitionOutcome::Response,
        UnixAcquisitionOutcome::InvalidRequestFraming { message }
        | UnixAcquisitionOutcome::MalformedFraming { message } => {
            AcquisitionOutcome::MalformedFraming { message }
        }
        UnixAcquisitionOutcome::RequestWriteFailed { message } => {
            AcquisitionOutcome::RequestWriteFailed { message }
        }
        UnixAcquisitionOutcome::Timeout { phase } => AcquisitionOutcome::ExchangeTimeout {
            phase: match phase {
                UnixIoPhase::WriteRequest => "write_request",
                UnixIoPhase::ReadResponse => "read_response",
            }
            .into(),
        },
        UnixAcquisitionOutcome::OutputTooLarge => AcquisitionOutcome::OutputTooLarge,
        UnixAcquisitionOutcome::StderrTooLarge => AcquisitionOutcome::StderrTooLarge,
        UnixAcquisitionOutcome::Eof => AcquisitionOutcome::Eof,
        UnixAcquisitionOutcome::Disconnect { message } => {
            AcquisitionOutcome::Disconnect { message }
        }
        UnixAcquisitionOutcome::MalformedJson { message } => {
            AcquisitionOutcome::MalformedJson { message }
        }
        UnixAcquisitionOutcome::HelperExited { code } => AcquisitionOutcome::HelperExited { code },
        UnixAcquisitionOutcome::NotRunning => AcquisitionOutcome::NotRunning,
        UnixAcquisitionOutcome::IoFailed { message } => AcquisitionOutcome::IoFailed { message },
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::Stdio => "stdio",
        Carrier::Unix => "unix",
    }
}

fn detector_state(state: DetectorState) -> &'static str {
    match state {
        DetectorState::Present => "present",
        DetectorState::ExplicitlyAbsent => "explicitly_absent",
        DetectorState::CannotEvaluate => "cannot_evaluate",
    }
}

fn acquisition_code(outcome: &AcquisitionOutcome) -> &'static str {
    match outcome {
        AcquisitionOutcome::Response => "response",
        AcquisitionOutcome::SpawnFailed { .. } => "spawn_failed",
        AcquisitionOutcome::RequestWriteFailed { .. } => "request_write_failed",
        AcquisitionOutcome::Timeout | AcquisitionOutcome::ExchangeTimeout { .. } => "timeout",
        AcquisitionOutcome::OutputTooLarge => "output_too_large",
        AcquisitionOutcome::StderrTooLarge => "stderr_too_large",
        AcquisitionOutcome::Eof => "eof",
        AcquisitionOutcome::MalformedFraming { .. } => "malformed_framing",
        AcquisitionOutcome::MalformedJson { .. } => "malformed_json",
        AcquisitionOutcome::ExitNonzero { .. } => "exit_nonzero",
        AcquisitionOutcome::HelperExited { .. } => "helper_exited",
        AcquisitionOutcome::Disconnect { .. } => "disconnect",
        AcquisitionOutcome::CarrierStartupFailed { .. } => "carrier_startup_failed",
        AcquisitionOutcome::NotRunning => "not_running",
        AcquisitionOutcome::IoFailed { .. } => "io_failed",
    }
}

/// Exact diagnostic carried by an acquisition outcome, when it has one.
///
/// Codes are a stable vocabulary, not an explanation. `carrier_startup_failed`
/// covers every supervised-startup refusal — wrong socket mode, wrong owner,
/// spawn failure, startup timeout — so a caller holding only the code cannot
/// say which predicate refused. Callers that report a failure to an operator
/// must report this alongside the code.
fn acquisition_detail(outcome: &AcquisitionOutcome) -> Option<String> {
    match outcome {
        AcquisitionOutcome::SpawnFailed { message }
        | AcquisitionOutcome::RequestWriteFailed { message }
        | AcquisitionOutcome::MalformedFraming { message }
        | AcquisitionOutcome::MalformedJson { message }
        | AcquisitionOutcome::Disconnect { message }
        | AcquisitionOutcome::CarrierStartupFailed { message }
        | AcquisitionOutcome::IoFailed { message } => Some(message.clone()),
        AcquisitionOutcome::ExitNonzero { code } | AcquisitionOutcome::HelperExited { code } => {
            Some(code.map_or_else(
                || "terminated by signal".to_owned(),
                |code| format!("exit code {code}"),
            ))
        }
        AcquisitionOutcome::ExchangeTimeout { .. }
        | AcquisitionOutcome::Response
        | AcquisitionOutcome::Timeout
        | AcquisitionOutcome::OutputTooLarge
        | AcquisitionOutcome::StderrTooLarge
        | AcquisitionOutcome::Eof
        | AcquisitionOutcome::NotRunning => None,
    }
}

/// Operator-facing error for a dry collection that did not return a response.
///
/// Preserves the stable acquisition code and appends `acquisition_detail` when
/// the outcome carries one, mirroring the daemon path's `AcquisitionFailed`
/// (code + detail). A refusal family whose members share one coarse code but
/// carry distinct dependent watchers -- every `carrier_startup_failed` variant:
/// wrong socket mode, wrong owner, spawn failure, startup timeout -- must not be
/// exported through a code-only projection that collapses those distinctions.
fn dry_collection_error(outcome: &AcquisitionOutcome) -> EngineError {
    let code = acquisition_code(outcome);
    let message = match acquisition_detail(outcome) {
        Some(detail) => format!("dry collection acquisition outcome {code}: {detail}"),
        None => format!("dry collection acquisition outcome {code}"),
    };
    EngineError::Protocol(message)
}

fn refusal_source(boundary: &str) -> &'static str {
    match boundary {
        "protocol" => "protocol",
        "profile" | "scope" | "vantage" | "capability" | "checkpoint" => "profile",
        _ => "acquisition",
    }
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, EngineError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| EngineError::Invariant(format!("invalid stored timestamp: {error}")))
}

/// Append a compiled descriptor snapshot during explicit initialization.
///
/// # Errors
///
/// Returns a canonicalization or storage error.
pub fn append_profile_descriptor(
    store: &mut Store,
    module: &dyn ProfileModule,
) -> Result<(), EngineError> {
    let descriptor = module.descriptor();
    store.append_profile_descriptor(&ProfileDescriptorInput {
        profile_id: descriptor.profile.id.clone(),
        profile_version: descriptor.profile.version.to_string(),
        descriptor: canonical(descriptor)?,
        recorded_at: timestamp(Utc::now()),
    })?;
    Ok(())
}

/// Append the fresh-store genesis record. This never imports active legacy
/// state.
///
/// # Errors
///
/// Returns a canonicalization or storage error.
pub fn append_genesis(store: &mut Store, legacy_digest: Option<String>) -> Result<(), EngineError> {
    store.append_genesis(&GenesisInput {
        genesis_id: Uuid::new_v4().to_string(),
        legacy_manifest_digest: legacy_digest,
        created_at: timestamp(Utc::now()),
        detail: canonical(&json!({
            "schema": "nq.genesis.v1",
            "legacy_state_imported": false,
        }))?,
    })?;
    Ok(())
}

/// Append and project one bounded component-health event.
///
/// # Errors
///
/// Returns when the details cannot be canonicalized or the durable status
/// event violates the storage contract.
pub fn record_component_status(
    store: &mut Store,
    component_kind: &str,
    component_id: &str,
    state: &str,
    code: &str,
    details: &Value,
) -> Result<(), EngineError> {
    store.record_status(&StatusEventInput {
        status_event_id: Uuid::new_v4().to_string(),
        component_kind: component_kind.to_owned(),
        component_id: component_id.to_owned(),
        state: state.to_owned(),
        code: code.to_owned(),
        detail: canonical(details)?,
        observed_at: timestamp(Utc::now()),
    })?;
    Ok(())
}

/// Create a consistent `SQLite` backup through the storage boundary.
///
/// # Errors
///
/// Returns when the source, backup, or verification step fails.
pub fn backup_store(store: &Store, destination: &Path) -> Result<(), EngineError> {
    let _artifact = store.backup_verified(destination)?;
    Ok(())
}

/// Convert stable SQL finding rows into the exact public DTO.
///
/// # Errors
///
/// Returns when a durable row violates the public DTO contract.
pub fn list_findings(store: &Store) -> Result<Vec<FindingSnapshotV2>, EngineError> {
    store
        .finding_snapshots()?
        .into_iter()
        .map(finding_from_row)
        .collect()
}

/// Convert one bounded page of stable SQL finding rows into public DTOs.
///
/// # Errors
///
/// Returns when the page bound is invalid or a durable row violates the DTO.
pub fn list_findings_bounded(
    store: &Store,
    limit: u32,
    after_finding_id: Option<&str>,
) -> Result<Vec<FindingSnapshotV2>, EngineError> {
    store
        .finding_snapshots_bounded(limit, after_finding_id)?
        .into_iter()
        .map(finding_from_row)
        .collect()
}

/// Convert stable SQL status rows into the exact shared public DTO.
///
/// # Errors
///
/// Returns when a durable row violates the public DTO contract.
pub fn status_snapshot(store: &Store) -> Result<StatusSnapshotV1, EngineError> {
    let components = store
        .status_snapshots()?
        .into_iter()
        .map(status_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StatusSnapshotV1 {
        schema: STATUS_SNAPSHOT_SCHEMA.into(),
        generated_at: Utc::now(),
        components,
    })
}

/// Run a bounded read-only public-view query.
///
/// # Errors
///
/// Returns when the query is not one of the documented exact public-view
/// selects, exceeds the bound, or a row violates its DTO contract.
pub fn public_query(store: &Store, sql: &str, limit: u32) -> Result<Vec<Value>, EngineError> {
    let normalized = sql
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    match normalized.as_str() {
        "select * from public_finding_snapshot_v2" => store
            .finding_snapshots_bounded(limit, None)?
            .into_iter()
            .map(finding_from_row)
            .map(|result| {
                result.and_then(|value| {
                    serde_json::to_value(value)
                        .map_err(|error| EngineError::Canonical(error.to_string()))
                })
            })
            .collect(),
        "select * from public_status_snapshot_v1" => store
            .status_snapshots_bounded(limit, None)?
            .into_iter()
            .map(status_from_row)
            .map(|result| {
                result.and_then(|value| {
                    serde_json::to_value(value)
                        .map_err(|error| EngineError::Canonical(error.to_string()))
                })
            })
            .collect(),
        _ => Err(EngineError::Invariant(
            "query must be exactly `SELECT * FROM public_finding_snapshot_v2` or `SELECT * FROM public_status_snapshot_v1`"
                .into(),
        )),
    }
}

fn finding_from_row(row: nq_store::FindingSnapshotRow) -> Result<FindingSnapshotV2, EngineError> {
    let evidence: Vec<PublicEvidenceReference> = serde_json::from_str(&row.evidence_json)
        .map_err(|error| EngineError::Invariant(format!("invalid evidence view JSON: {error}")))?;
    Ok(FindingSnapshotV2 {
        schema: FINDING_SNAPSHOT_SCHEMA.into(),
        finding_id: row.finding_id,
        instance_id: row.instance_id,
        detector: DetectorIdentity {
            id: row.detector_id,
            version: row
                .detector_version
                .parse()
                .map_err(|error| EngineError::Invariant(format!("detector version: {error}")))?,
            digest: row.detector_digest,
        },
        profile: PublicProfileIdentity {
            id: row.profile_id,
            version: row
                .profile_version
                .parse()
                .map_err(|error| EngineError::Invariant(format!("profile version: {error}")))?,
            digest: row.profile_digest,
        },
        subject: serde_json::from_str(&row.subject_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
        evaluation_revision: u64::try_from(row.evaluation_revision)
            .map_err(|_| EngineError::Invariant("negative evaluation revision".into()))?,
        condition: ConditionView {
            name: row.condition_name,
            state: parse_condition(&row.condition_state)?,
        },
        visibility: VisibilityView {
            state: parse_visibility(&row.visibility_state)?,
            freshness: serde_json::from_str(&row.freshness_json)
                .map_err(|error| EngineError::Invariant(error.to_string()))?,
            basis: serde_json::from_str(&row.basis_json)
                .map_err(|error| EngineError::Invariant(error.to_string()))?,
            refusal: row
                .refusal_json
                .map(|value| serde_json::from_str(&value))
                .transpose()
                .map_err(|error| EngineError::Invariant(error.to_string()))?,
        },
        operator_work_state: row.operator_work_state,
        severity: parse_severity(&row.severity)?,
        summary: row.summary,
        evidence,
        limitations: serde_json::from_str(&row.limitations_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
        safe_next_checks: serde_json::from_str(&row.safe_next_checks_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
        observed_at: row
            .observed_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?,
        received_at: row
            .received_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?,
        evaluated_at: parse_timestamp(&row.evaluated_at)?,
        origin_mode: match row.origin_mode.as_str() {
            "native" => OriginMode::Native,
            "native_with_historical_reference" => OriginMode::NativeWithHistoricalReference,
            value => {
                return Err(EngineError::Invariant(format!(
                    "unknown origin mode {value}"
                )));
            }
        },
        historical_references: serde_json::from_str(&row.historical_refs_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
    })
}

fn status_from_row(row: nq_store::StatusSnapshotRow) -> Result<ComponentStatus, EngineError> {
    Ok(ComponentStatus {
        kind: match row.component_kind.as_str() {
            "daemon" => ComponentKind::Daemon,
            "database" => ComponentKind::Database,
            "profile_catalog" => ComponentKind::ProfileCatalog,
            "admission" => ComponentKind::Admission,
            "scheduler" => ComponentKind::Scheduler,
            "instance" => ComponentKind::Instance,
            "evaluation" => ComponentKind::Evaluation,
            "notification" => ComponentKind::Notification,
            value => return Err(EngineError::Invariant(format!("unknown component {value}"))),
        },
        id: row.component_id,
        state: match row.state.as_str() {
            "healthy" => HealthState::Healthy,
            "degraded" => HealthState::Degraded,
            "failed" => HealthState::Failed,
            "unknown" => HealthState::Unknown,
            value => {
                return Err(EngineError::Invariant(format!(
                    "unknown health state {value}"
                )));
            }
        },
        code: row.code,
        details: serde_json::from_str(&row.detail_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
        observed_at: parse_timestamp(&row.observed_at)?,
    })
}

fn parse_condition(value: &str) -> Result<ConditionState, EngineError> {
    match value {
        "present" => Ok(ConditionState::Present),
        "explicitly_absent" => Ok(ConditionState::ExplicitlyAbsent),
        "cannot_evaluate" => Ok(ConditionState::CannotEvaluate),
        _ => Err(EngineError::Invariant(format!(
            "unknown condition state {value}"
        ))),
    }
}

fn parse_visibility(value: &str) -> Result<VisibilityState, EngineError> {
    match value {
        "sufficient" => Ok(VisibilityState::Sufficient),
        "partial" => Ok(VisibilityState::Partial),
        "stale" => Ok(VisibilityState::Stale),
        "missing" => Ok(VisibilityState::Missing),
        "refused" => Ok(VisibilityState::Refused),
        _ => Err(EngineError::Invariant(format!(
            "unknown visibility state {value}"
        ))),
    }
}

fn parse_severity(value: &str) -> Result<Severity, EngineError> {
    match value {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "error" => Ok(Severity::Error),
        "critical" => Ok(Severity::Critical),
        _ => Err(EngineError::Invariant(format!("unknown severity {value}"))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::PermissionsExt;

    use crate::config::{
        CommandConfig, ProfileSelection, ResourceLimits, ScheduleConfig, ScopeConfig, VantageConfig,
    };

    use super::*;

    fn host_example_text() -> String {
        include_str!("../../../examples/nq-host.toml").replace(
            "execution_account = \"nq-helper\"",
            &format!(
                "execution_account = \"{}\"\nallow_same_identity_in_debug = true",
                nix::unistd::geteuid().as_raw()
            ),
        )
    }

    fn binding_recovery_fixture(root: &Path) -> (NqConfig, WatcherConfig, AdmissionLock) {
        fs::create_dir(root.join("admissions")).expect("fixture admissions root");
        let helper = root.join("helper.sh");
        fs::write(&helper, b"#!/bin/sh\nexit 0\n").expect("fixture helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755))
            .expect("fixture helper mode");
        let watcher = WatcherConfig {
            instance_id: "recovery.primary".to_owned(),
            command: CommandConfig {
                executable: helper,
                args: Vec::new(),
                env: BTreeMap::new(),
                execution_account: nix::unistd::geteuid().as_raw().to_string(),
                allow_same_identity_in_debug: true,
                working_directory: root.to_path_buf(),
            },
            carrier: Carrier::Stdio,
            profile: ProfileSelection {
                id: "nq.conformance".to_owned(),
                version: 1,
            },
            subject: "conformance:recovery".to_owned(),
            scope: ScopeConfig {
                kind: "fixture".to_owned(),
                value: json!({"id": "recovery", "nonce": "test"}),
            },
            vantage: VantageConfig {
                kind: "local".to_owned(),
                value: json!({}),
            },
            capability_ceiling: BTreeSet::new(),
            schedule: ScheduleConfig::default(),
            resources: ResourceLimits::default(),
            checkpoint_policy: CheckpointPolicy::Disabled,
        };
        let config = NqConfig {
            schema: crate::config::CONFIG_SCHEMA.to_owned(),
            database_path: root.join("nq.db"),
            socket_path: root.join("nqd.sock"),
            admissions_dir: root.join("admissions"),
            helper_runtime_dir: root.join("helpers"),
            watchers: vec![watcher.clone()],
        };
        let profile = resolve(&watcher).expect("compiled fixture profile");
        let corpus = nq_protocol::verify_embedded_conformance_corpus().expect("corpus");
        let lock = AdmissionManager
            .candidate(
                &watcher,
                CandidateEvidence {
                    profile_digest: profile
                        .descriptor()
                        .digest()
                        .expect("profile digest")
                        .as_str()
                        .to_owned(),
                    protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                    declared_capabilities: BTreeSet::new(),
                    conformance: ConformanceReceipt {
                        tool_version: corpus.version.verifier_version,
                        protocol_passed: true,
                        protocol_corpus_digest: corpus.version.corpus_digest.to_string(),
                        protocol_fixtures_checked: corpus.fixtures_checked,
                        dry_collection_passed: true,
                        dry_report_digest: Some(format!("sha256:{}", "a".repeat(64))),
                    },
                },
            )
            .expect("candidate lock");
        (config, watcher, lock)
    }

    struct SemanticLineageFixture {
        config: NqConfig,
        profile: &'static dyn ProfileModule,
        detector_version: String,
        detector_digest: String,
        profile_version: String,
        profile_digest: String,
        subject_json: String,
        observed_at: DateTime<Utc>,
        semantic_digest: String,
        finding: nq_store::FindingSnapshotRow,
    }

    impl SemanticLineageFixture {
        fn new() -> Self {
            let config = NqConfig::from_toml(&host_example_text()).expect("valid host example");
            let watcher = &config.watchers[0];
            let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
            let descriptor = profile.detectors()[0].descriptor();
            let detector_version = descriptor.version.to_string();
            let detector_digest = descriptor.digest().expect("compiled detector digest");
            let profile_version = profile.descriptor().profile.version.to_string();
            let profile_digest = profile
                .descriptor()
                .digest()
                .expect("compiled profile digest")
                .as_str()
                .to_owned();
            let subject_json = serde_json::to_string(&Value::String(watcher.subject.clone()))
                .expect("subject JSON");
            let observed_at = Utc::now();
            let semantic_digest = format!("sha256:{}", "a".repeat(64));
            let finding = nq_store::FindingSnapshotRow {
                finding_id: "finding:old-lineage".to_owned(),
                instance_id: watcher.instance_id.clone(),
                detector_id: descriptor.id.clone(),
                detector_version: detector_version.clone(),
                detector_digest: detector_digest.clone(),
                evaluation_revision: 1,
                profile_id: profile.descriptor().profile.id.clone(),
                profile_version: profile_version.clone(),
                profile_digest: profile_digest.clone(),
                subject_json: subject_json.clone(),
                condition_name: descriptor.condition.clone(),
                condition_state: "present".to_owned(),
                visibility_state: "sufficient".to_owned(),
                operator_work_state: "unreviewed".to_owned(),
                severity: "warning".to_owned(),
                summary: "old compiled semantics found a condition".to_owned(),
                limitations_json: "[]".to_owned(),
                safe_next_checks_json: "[]".to_owned(),
                freshness_json: "{}".to_owned(),
                basis_json: "{}".to_owned(),
                refusal_json: None,
                origin_mode: "native".to_owned(),
                historical_refs_json: "[]".to_owned(),
                observed_at: Some(timestamp(observed_at)),
                received_at: Some(timestamp(observed_at)),
                evaluated_at: timestamp(observed_at),
                evidence_json: serde_json::to_string(&vec![PublicEvidenceReference {
                    report_id: "report:old-lineage".to_owned(),
                    semantic_digest: semantic_digest.clone(),
                    observation_ordinal: None,
                    observed_at,
                    received_at: observed_at,
                }])
                .expect("evidence JSON"),
            };
            Self {
                config,
                profile,
                detector_version,
                detector_digest,
                profile_version,
                profile_digest,
                subject_json,
                observed_at,
                semantic_digest,
                finding,
            }
        }

        fn watcher(&self) -> &WatcherConfig {
            &self.config.watchers[0]
        }

        fn descriptor(&self) -> &'static nq_profiles::DetectorDescriptor {
            self.profile.detectors()[0].descriptor()
        }

        fn lineage(&self) -> FindingLineage<'_> {
            FindingLineage {
                instance_id: &self.watcher().instance_id,
                detector_id: &self.descriptor().id,
                detector_version: &self.detector_version,
                detector_digest: &self.detector_digest,
                profile_id: &self.watcher().profile.id,
                profile_version: &self.profile_version,
                profile_digest: &self.profile_digest,
                subject_json: &self.subject_json,
            }
        }

        fn report(
            &self,
            report_sequence: i64,
            report_id: &str,
            semantic_digest: &str,
        ) -> nq_store::AdmittedReportRow {
            nq_store::AdmittedReportRow {
                report_sequence,
                report_id: report_id.to_owned(),
                instance_id: self.watcher().instance_id.clone(),
                profile_id: self.watcher().profile.id.clone(),
                profile_version: self.profile_version.clone(),
                profile_digest: self.profile_digest.clone(),
                observed_at: timestamp(self.observed_at),
                received_at: timestamp(self.observed_at),
                report_status: "complete".to_owned(),
                canonical_json: Vec::new(),
                semantic_digest: semantic_digest.to_owned(),
            }
        }
    }

    #[test]
    fn compiled_config_enforces_profile_owned_binding_correlation() {
        let text =
            host_example_text().replace("value = { id = \"local\" }", "value = { id = \"other\" }");
        let config = NqConfig::from_toml(&text).expect("shape-valid configuration");
        let error = validate_compiled_config(&config).expect_err("subject must correlate to scope");
        assert!(error.to_string().contains("does not correlate"));
    }

    #[test]
    fn compiled_config_accepts_valid_host_binding() {
        let config = NqConfig::from_toml(&host_example_text()).expect("valid host example");
        validate_compiled_config(&config).expect("compiled profile binding");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn pending_authoritative_binding_is_reconciled_but_untracked_tampering_is_not() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (config, watcher, lock) = binding_recovery_fixture(directory.path());
        let profile = resolve(&watcher).expect("profile");
        let mut store = Store::initialize(&config.database_path).expect("initialize store");
        append_profile_descriptor(&mut store, profile).expect("descriptor");
        store
            .append_admission(&AdmissionInput {
                admission_id: lock.admission_id.clone(),
                instance_id: lock.instance_id.clone(),
                identity: AdmissionIdentity {
                    profile_semantic_id: Sha256Digest::parse(format!("sha256:{}", "b".repeat(64)))
                        .unwrap(),
                    detector_identity_digest: Sha256Digest::parse(format!(
                        "sha256:{}",
                        "c".repeat(64)
                    ))
                    .unwrap(),
                    evaluator_source_digest: Sha256Digest::parse(EVALUATOR_SOURCE_DIGEST).unwrap(),
                    evaluator_artifact_digest: Sha256Digest::parse(format!(
                        "sha256:{}",
                        "d".repeat(64)
                    ))
                    .unwrap(),
                    helper_artifact_digest: Sha256Digest::parse(lock.execution.sha256.clone())
                        .unwrap(),
                    config_digest: Sha256Digest::parse(lock.config_digest.clone()).unwrap(),
                    protocol_version: lock.protocol_version.clone(),
                    target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                    artifact_identity_method: "fixture".to_owned(),
                    platform_runtime_version: "test".to_owned(),
                },
                execution_chain: canonical(&lock.execution).expect("execution JSON"),
                profile_id: lock.profile.id.clone(),
                profile_version: lock.profile.version.to_string(),
                profile_digest: lock.profile.digest.clone(),
                capability_grant: canonical(&lock.granted_capabilities).expect("capability JSON"),
                conformance: canonical(&lock.conformance).expect("conformance JSON"),
                lock: canonical(&lock).expect("lock JSON"),
                admitted_at: timestamp(lock.admitted_at),
                operator_identity: canonical(&lock.operator).expect("operator JSON"),
            })
            .expect("admission");
        drop(store);

        let mut engine = CollectionEngine::open(&config).expect("engine");
        let operation_id = Uuid::new_v4().to_string();
        let binding_event_id = Uuid::new_v4().to_string();
        let plan = BindingMaterializationPlan {
            schema: BINDING_MATERIALIZATION_PLAN_SCHEMA.to_owned(),
            operation_id: operation_id.clone(),
            instance_id: watcher.instance_id.clone(),
            binding_event_id: binding_event_id.clone(),
            admissions_root: AdmissionRootIdentity::resolve(&config.admissions_dir)
                .expect("admissions root identity"),
            desired_lock: Some(lock.clone()),
            previous_lock: None,
        };
        let plan_document = canonical(&plan).expect("plan JSON");
        engine
            .store
            .begin_binding_transition(
                &BindingEventInput {
                    binding_event_id: binding_event_id.clone(),
                    instance_id: watcher.instance_id.clone(),
                    event_kind: "activate".to_owned(),
                    admission_id: Some(lock.admission_id.clone()),
                    binding_digest: AdmissionManager
                        .binding_digest(&lock)
                        .expect("binding digest"),
                    occurred_at: timestamp(Utc::now()),
                    reason_code: Some("crash-window-test".to_owned()),
                    detail: canonical(&json!({})).expect("event detail"),
                },
                &BindingMaterializationInput {
                    materialization_event_id: Uuid::new_v4().to_string(),
                    operation_id,
                    instance_id: watcher.instance_id.clone(),
                    binding_event_id,
                    phase: "intent".to_owned(),
                    occurred_at: timestamp(Utc::now()),
                    detail: plan_document,
                },
            )
            .expect("authoritative event and intent");
        assert!(!config.admissions_dir.join("recovery.primary.json").exists());

        // Simulated crash: drop the process after the SQLite transaction and
        // reopen without ever applying the active file.
        drop(engine);
        let mut drifting_config = config.clone();
        drifting_config.admissions_dir = directory.path().join("different-admissions");
        fs::create_dir(&drifting_config.admissions_dir).expect("drifting admissions root");
        let mut drifting = CollectionEngine::open(&drifting_config).expect("drifting engine");
        assert!(matches!(
            drifting.reconcile_pending_binding(&watcher),
            Err(EngineError::Invariant(message)) if message.contains("different admissions root")
        ));
        assert!(
            drifting
                .store
                .pending_binding_materialization(&watcher.instance_id)
                .expect("pending after drift refusal")
                .is_some(),
            "config drift must leave the original intent recoverable"
        );
        assert!(
            !drifting_config
                .admissions_dir
                .join("recovery.primary.json")
                .exists()
        );
        drop(drifting);

        let mut recovered = CollectionEngine::open(&config).expect("recovered engine");
        assert!(
            recovered
                .reconcile_pending_binding(&watcher)
                .expect("reconcile pending intent")
        );
        assert_eq!(
            recovered
                .authoritative_active_lock(&watcher)
                .expect("authoritative lock")
                .expect("active lock"),
            lock
        );
        assert!(
            recovered
                .store
                .pending_binding_materialization(&watcher.instance_id)
                .expect("pending query")
                .is_none()
        );

        // With no pending intent, a different valid-looking lock is drift and
        // must not be silently overwritten from SQLite.
        let corpus = nq_protocol::verify_embedded_conformance_corpus().expect("corpus");
        let forged = AdmissionManager
            .candidate(
                &watcher,
                CandidateEvidence {
                    profile_digest: lock.profile.digest.clone(),
                    protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                    declared_capabilities: BTreeSet::new(),
                    conformance: ConformanceReceipt {
                        tool_version: corpus.version.verifier_version,
                        protocol_passed: true,
                        protocol_corpus_digest: corpus.version.corpus_digest.to_string(),
                        protocol_fixtures_checked: corpus.fixtures_checked,
                        dry_collection_passed: true,
                        dry_report_digest: Some(format!("sha256:{}", "b".repeat(64))),
                    },
                },
            )
            .expect("second valid lock shape");
        AdmissionManager
            .activate(&config.admissions_dir, &forged)
            .expect("tamper with materialization");
        assert!(matches!(
            recovered.authoritative_active_lock(&watcher),
            Err(EngineError::Invariant(message)) if message.contains("differs from authoritative")
        ));
        assert_eq!(
            AdmissionManager
                .load(&config.admissions_dir.join("recovery.primary.json"))
                .expect("tampered lock remains for diagnosis"),
            forged,
            "ordinary drift must not be auto-healed without a durable pending intent"
        );
    }

    #[test]
    fn boottime_deadline_basis_is_available() {
        assert!(boottime_ns().unwrap() > 0);
    }

    #[test]
    fn missing_testimony_does_not_create_an_absence_finding() {
        assert_eq!(
            detector_state(DetectorState::CannotEvaluate),
            "cannot_evaluate"
        );
        assert_ne!(
            detector_state(DetectorState::CannotEvaluate),
            "explicitly_absent"
        );
    }

    #[test]
    fn valid_failed_report_is_not_an_acquisition_failure() {
        let outcome = CollectionOutcome::Admitted {
            instance_id: "x".into(),
            run_id: "r".into(),
            report_id: "p".into(),
            report_status: "failed".into(),
            semantic_digest: format!("sha256:{}", "a".repeat(64)),
            evaluations: 0,
        };
        assert!(!outcome.is_success());
        assert!(matches!(outcome, CollectionOutcome::Admitted { .. }));
    }

    #[test]
    fn changed_semantic_identity_cannot_inherit_or_relabel_a_finding() {
        let fixture = SemanticLineageFixture::new();
        let findings = [fixture.finding.clone()];
        let exact = fixture.lineage();
        assert_eq!(
            find_current_finding(&findings, &exact).map(|finding| finding.finding_id.as_str()),
            Some("finding:old-lineage")
        );

        let changed_detector_version = "999".to_owned();
        let changed_detector_digest = format!("sha256:{}", "b".repeat(64));
        let changed_profile_version = "999".to_owned();
        let changed_profile_digest = format!("sha256:{}", "c".repeat(64));
        let changed_lineages = [
            FindingLineage {
                detector_version: &changed_detector_version,
                ..exact
            },
            FindingLineage {
                detector_digest: &changed_detector_digest,
                ..exact
            },
            FindingLineage {
                profile_version: &changed_profile_version,
                ..exact
            },
            FindingLineage {
                profile_digest: &changed_profile_digest,
                ..exact
            },
        ];
        for changed in changed_lineages {
            assert!(
                find_current_finding(&findings, &changed).is_none(),
                "a changed semantic identity must start a distinct lineage"
            );
        }

        let old_report = fixture.report(1, "report:old-lineage", &fixture.semantic_digest);
        assert!(report_matches_profile_contract(
            &old_report,
            &fixture.watcher().profile.id,
            &fixture.profile_version,
            &fixture.profile_digest,
        ));
        assert!(
            !report_matches_profile_contract(
                &old_report,
                &fixture.watcher().profile.id,
                &fixture.profile_version,
                &changed_profile_digest,
            ),
            "old-digest evidence must not enter a changed profile contract"
        );
    }

    #[test]
    fn changed_semantics_open_a_distinct_finding_or_no_finding() {
        let fixture = SemanticLineageFixture::new();
        let findings = [fixture.finding.clone()];
        let exact = fixture.lineage();
        let changed_detector_digest = format!("sha256:{}", "b".repeat(64));
        let changed_detector_lineage = FindingLineage {
            detector_digest: &changed_detector_digest,
            ..exact
        };
        let changed_current = find_current_finding(&findings, &changed_detector_lineage);
        assert!(changed_current.is_none());
        let watcher = fixture.watcher();
        let descriptor = fixture.descriptor();
        let detector_input = DetectorInput {
            instance_id: &watcher.instance_id,
            evaluated_at: fixture.observed_at,
            watermark: EvidenceWatermark(1),
            reports: &[],
        };
        let cannot_evaluate = nq_profiles::DetectorResult::cannot_evaluate(
            &detector_input,
            descriptor,
            "the changed detector has no evidence under its exact contract",
            Vec::new(),
        );
        let new_semantic_digest = format!("sha256:{}", "d".repeat(64));
        let new_report = fixture.report(2, "report:new-lineage", &new_semantic_digest);
        let present = nq_profiles::DetectorResult {
            state: DetectorState::Present,
            condition: descriptor.condition.clone(),
            summary: "changed compiled semantics found a condition".to_owned(),
            evidence: vec![nq_profiles::DetectorEvidence {
                report_id: new_report.report_id.clone(),
                report_sequence: 2,
                report_digest: new_semantic_digest,
                observation_ordinal: None,
                observed_at: fixture.observed_at,
            }],
            limitations: Vec::new(),
            refusal: None,
            watermark: EvidenceWatermark(2),
        };
        let opened = build_finding_event(
            watcher,
            fixture.profile,
            descriptor,
            &present,
            fixture.observed_at,
            changed_current,
            std::slice::from_ref(&new_report),
        )
        .expect("changed lineage finding is well formed")
        .expect("present condition opens a distinct finding lineage");
        assert_ne!(opened.finding_id, findings[0].finding_id);
        assert_eq!(opened.evidence.len(), 1);
        assert_eq!(opened.evidence[0].report_id, "report:new-lineage");

        let event = build_finding_event(
            watcher,
            fixture.profile,
            descriptor,
            &cannot_evaluate,
            fixture.observed_at,
            changed_current,
            &[],
        )
        .expect("changed lineage evaluation is well formed");
        assert!(
            event.is_none(),
            "cannot-evaluate under changed semantics must not update or retain the old finding"
        );
    }

    #[test]
    fn identical_semantic_reports_keep_exact_detector_evidence_identity() {
        let config = NqConfig::from_toml(&host_example_text()).expect("valid host example");
        let watcher = &config.watchers[0];
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        let descriptor = profile.detectors()[0].descriptor();
        let semantic_digest = format!("sha256:{}", "a".repeat(64));
        let profile_digest = profile
            .descriptor()
            .digest()
            .expect("compiled profile digest")
            .as_str()
            .to_owned();
        let observed_at = Utc::now();
        let old_received_at = timestamp(observed_at);
        let new_received_at = timestamp(observed_at + Duration::seconds(1));
        let report_row =
            |report_sequence, report_id: &str, received_at: &str| nq_store::AdmittedReportRow {
                report_sequence,
                report_id: report_id.to_owned(),
                instance_id: watcher.instance_id.clone(),
                profile_id: profile.descriptor().profile.id.clone(),
                profile_version: profile.descriptor().profile.version.to_string(),
                profile_digest: profile_digest.clone(),
                observed_at: timestamp(observed_at),
                received_at: received_at.to_owned(),
                report_status: "complete".to_owned(),
                canonical_json: Vec::new(),
                semantic_digest: semantic_digest.clone(),
            };
        let rows = [
            report_row(1, "report:old", &old_received_at),
            report_row(2, "report:new", &new_received_at),
        ];
        let result = nq_profiles::DetectorResult {
            state: DetectorState::Present,
            condition: descriptor.condition.clone(),
            summary: "host load pressure is present".to_owned(),
            evidence: vec![nq_profiles::DetectorEvidence {
                report_id: "report:new".to_owned(),
                report_sequence: 2,
                report_digest: semantic_digest,
                observation_ordinal: None,
                observed_at,
            }],
            limitations: Vec::new(),
            refusal: None,
            watermark: EvidenceWatermark(2),
        };

        let event = build_finding_event(
            watcher,
            profile,
            descriptor,
            &result,
            observed_at + Duration::seconds(2),
            None,
            &rows,
        )
        .expect("exact evidence occurrence resolves")
        .expect("present condition opens a finding");
        assert_eq!(event.evidence[0].report_id, "report:new");
        assert_eq!(event.evidence[0].received_at, new_received_at);
        assert_eq!(event.received_at.as_deref(), Some(new_received_at.as_str()));

        let mut mismatched = result;
        mismatched.evidence[0].report_sequence = 1;
        let error = build_finding_event(
            watcher,
            profile,
            descriptor,
            &mismatched,
            observed_at + Duration::seconds(2),
            None,
            &rows,
        )
        .expect_err("report ID, durable sequence, and semantic digest must agree");
        assert!(error.to_string().contains("unknown report occurrence"));
    }

    #[test]
    fn collection_fails_closed_when_evaluator_identity_is_unresolved() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (config, watcher, _lock) = binding_recovery_fixture(directory.path());
        Store::initialize(&config.database_path).expect("initialize store");

        // An unresolved (unsupported/unverifiable) identity refuses collection
        // before any persistence, carrying the exact structured reason — never a
        // fabricated fallback.
        let mut refusing = CollectionEngine::open_with_evaluator_identity(
            &config,
            Err("evaluator identity is unsupported on this platform (plan9)".to_owned()),
        )
        .expect("engine opens");
        let error = refusing
            .collect(&watcher)
            .expect_err("collection refuses without a resolved evaluator identity");
        assert!(matches!(
            error,
            EngineError::Invariant(message)
                if message.contains("evaluator runtime identity unavailable")
                    && message.contains("plan9")
        ));

        // A resolved identity clears the identity gate; with no active admission
        // the next step is an ordinary admission refusal, proving the gate is
        // what the first engine tripped on, not helper execution.
        let identity = EvaluatorRuntimeIdentity::for_test(
            Sha256Digest::parse(format!("sha256:{}", "a".repeat(64))).expect("digest"),
        );
        let mut ready =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(identity)).expect("engine");
        let outcome = ready
            .collect(&watcher)
            .expect("collection clears the identity gate");
        assert!(matches!(
            outcome,
            CollectionOutcome::AdmissionRefused { .. }
        ));
    }

    /// Seed one admitted report with a chosen recorded evaluator identity, so a
    /// verification against a chosen *current* identity can be exercised.
    fn seed_admitted_report(
        db_path: &Path,
        evaluator_artifact_digest: Sha256Digest,
        artifact_identity_method: &str,
        platform_runtime_version: &str,
    ) -> String {
        const TS: &str = "2026-07-16T12:00:00.000Z";
        let doc = |value: Value| CanonicalDocument::from_serializable(&value).expect("canonical");
        let sd = |label: &str| nq_protocol::sha256_bytes(label.as_bytes());
        let mut store = Store::initialize(db_path).expect("initialize verify store");
        let descriptor = doc(json!({"profile": "verify.fixture"}));
        let profile_digest = descriptor.digest().to_owned();
        store
            .append_profile_descriptor(&ProfileDescriptorInput {
                profile_id: "verify.fixture".to_owned(),
                profile_version: "1".to_owned(),
                descriptor,
                recorded_at: TS.to_owned(),
            })
            .expect("descriptor");
        store
            .append_admission(&AdmissionInput {
                admission_id: "adm-1".to_owned(),
                instance_id: "inst-1".to_owned(),
                identity: AdmissionIdentity {
                    profile_semantic_id: sd("semantic"),
                    detector_identity_digest: sd("detector"),
                    evaluator_source_digest: sd("source"),
                    evaluator_artifact_digest,
                    helper_artifact_digest: sd("helper"),
                    config_digest: sd("config"),
                    protocol_version: "1.0".to_owned(),
                    target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                    artifact_identity_method: artifact_identity_method.to_owned(),
                    platform_runtime_version: platform_runtime_version.to_owned(),
                },
                execution_chain: doc(json!({})),
                profile_id: "verify.fixture".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest: profile_digest.clone(),
                capability_grant: doc(json!([])),
                conformance: doc(json!({})),
                lock: doc(json!({})),
                admitted_at: TS.to_owned(),
                operator_identity: doc(json!({})),
            })
            .expect("admission");
        let run = RunInput {
            run_id: "run-1".to_owned(),
            request_id: "req-1".to_owned(),
            instance_id: "inst-1".to_owned(),
            admission_id: Some("adm-1".to_owned()),
            binding_digest: sd("binding").as_str().to_owned(),
            checkpoint_contract_digest: sd("checkpoint").as_str().to_owned(),
            profile_id: "verify.fixture".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.clone(),
            carrier: "stdio".to_owned(),
            started_at: TS.to_owned(),
            deadline_at: TS.to_owned(),
            finished_at: TS.to_owned(),
            acquisition_outcome: "response".to_owned(),
            execution_identity: doc(json!({})),
            resource_outcome: doc(json!({})),
        };
        let report = ReportInput {
            report_id: "rep-1".to_owned(),
            instance_id: "inst-1".to_owned(),
            profile_id: "verify.fixture".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest,
            observed_at: TS.to_owned(),
            received_at: TS.to_owned(),
            report_status: "complete".to_owned(),
            canonical_report: doc(json!({"report": 1})),
            validated_report: doc(json!({"validated": 1})),
            next_checkpoint: None,
            admitted_at: TS.to_owned(),
            observations: Vec::new(),
            coverage: Vec::new(),
            errors: Vec::new(),
        };
        store
            .commit_collection(&CollectionInput {
                run,
                submission: Some(SubmissionInput {
                    submission_id: "sub-1".to_owned(),
                    raw_bytes: b"raw".to_vec(),
                    received_at: TS.to_owned(),
                    protocol_outcome: "valid_exchange".to_owned(),
                    disposition: SubmissionDisposition::Admitted(report),
                }),
            })
            .expect("commit admitted report");
        "rep-1".to_owned()
    }

    #[test]
    fn verify_admitted_passes_when_snapshot_and_runtime_agree() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        let artifact = nq_protocol::sha256_bytes(b"evaluator-artifact");
        let report = seed_admitted_report(
            &config.database_path,
            artifact.clone(),
            "test-fixture-v1",
            "test",
        );
        let engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Ok(EvaluatorRuntimeIdentity::for_test(artifact)),
        )
        .expect("engine");
        let verified = engine
            .verify_admitted(&report)
            .expect("verification passes");
        assert_eq!(verified.report_id, "rep-1");
        assert_eq!(verified.admission_id, "adm-1");
        assert!(verified.platform_observations.is_empty());
    }

    #[test]
    fn verify_admitted_refuses_evaluator_artifact_drift() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        let report = seed_admitted_report(
            &config.database_path,
            nq_protocol::sha256_bytes(b"admitted-artifact"),
            "test-fixture-v1",
            "test",
        );
        let current = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(b"different"));
        let engine =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(current)).expect("engine");
        assert!(matches!(
            engine.verify_admitted(&report),
            Err(VerificationRefusal::EvaluatorArtifactDrift { .. })
        ));
    }

    #[test]
    fn verify_admitted_refuses_when_the_identity_method_changed() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        let artifact = nq_protocol::sha256_bytes(b"artifact");
        // Admitted under an older observation method; digests are not comparable.
        let report = seed_admitted_report(
            &config.database_path,
            artifact.clone(),
            "linux-proc-self-exe-fd-sha256-v0",
            "test",
        );
        let engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Ok(EvaluatorRuntimeIdentity::for_test(artifact)),
        )
        .expect("engine");
        assert!(matches!(
            engine.verify_admitted(&report),
            Err(VerificationRefusal::MethodIncompatible { .. })
        ));
    }

    #[test]
    fn verify_admitted_records_platform_drift_without_refusing() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        let artifact = nq_protocol::sha256_bytes(b"artifact");
        let report = seed_admitted_report(
            &config.database_path,
            artifact.clone(),
            "test-fixture-v1",
            "6.1.0-admitted",
        );
        let engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Ok(EvaluatorRuntimeIdentity::for_test(artifact)),
        )
        .expect("engine");
        let verified = engine
            .verify_admitted(&report)
            .expect("platform drift still verifies the historical admission");
        assert_eq!(
            verified.platform_observations,
            vec![PlatformObservation::RuntimeDrift {
                admitted: "6.1.0-admitted".to_owned(),
                current: "test".to_owned(),
            }]
        );
    }

    #[test]
    fn verify_admitted_fails_closed_when_current_identity_is_unavailable() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        // The snapshot authenticates, but the current identity cannot be
        // observed, so drift cannot be assessed and verification fails closed.
        let report = seed_admitted_report(
            &config.database_path,
            nq_protocol::sha256_bytes(b"artifact"),
            "test-fixture-v1",
            "test",
        );
        let engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Err("evaluator identity is unsupported on this platform".to_owned()),
        )
        .expect("engine");
        assert!(matches!(
            engine.verify_admitted(&report),
            Err(VerificationRefusal::CurrentIdentityUnverifiable(_))
        ));
    }

    /// A supervised daemon must be able to explain its own acquisition
    /// refusal. `carrier_startup_failed` is one code covering every
    /// supervised-startup predicate, so dropping the message leaves an
    /// operator unable to tell a refused socket mode from a spawn failure.
    ///
    /// Regression: the 2026-07-18 sealed VM run refused at
    /// `explicit-service-lifecycle` with four `carrier_startup_failed`
    /// outcomes and no recoverable cause, because this detail was discarded.
    #[test]
    fn acquisition_detail_preserves_the_exact_startup_diagnostic() {
        let refused = AcquisitionOutcome::CarrierStartupFailed {
            message: "helper socket mode is 0o660; expected 0o600".to_owned(),
        };
        let spawn = AcquisitionOutcome::CarrierStartupFailed {
            message: "could not spawn Unix helper: Permission denied (os error 13)".to_owned(),
        };

        // The code is a stable vocabulary, not an explanation: both refusals
        // share it, so the code alone cannot distinguish them.
        assert_eq!(acquisition_code(&refused), "carrier_startup_failed");
        assert_eq!(acquisition_code(&spawn), "carrier_startup_failed");
        assert_ne!(acquisition_detail(&refused), acquisition_detail(&spawn));

        assert_eq!(
            acquisition_detail(&refused).as_deref(),
            Some("helper socket mode is 0o660; expected 0o600")
        );
        assert_eq!(
            acquisition_detail(&AcquisitionOutcome::HelperExited { code: Some(2) }).as_deref(),
            Some("exit code 2")
        );
        assert_eq!(
            acquisition_detail(&AcquisitionOutcome::HelperExited { code: None }).as_deref(),
            Some("terminated by signal")
        );
        // Outcomes that genuinely carry no diagnostic must not invent one.
        assert!(acquisition_detail(&AcquisitionOutcome::Timeout).is_none());
        assert!(acquisition_detail(&AcquisitionOutcome::Eof).is_none());
    }

    /// The reported outcome must carry the diagnostic, not merely compute it:
    /// the daemon logs `CollectionOutcome`, so a dropped field is invisible.
    #[test]
    fn acquisition_failed_outcome_reports_its_detail() {
        let outcome = CollectionOutcome::AcquisitionFailed {
            instance_id: "conformance-local".to_owned(),
            run_id: "0b8c140b-84ab-41f8-a473-fe77444ed64f".to_owned(),
            code: acquisition_code(&AcquisitionOutcome::CarrierStartupFailed {
                message: "helper socket mode is 0o660; expected 0o600".to_owned(),
            })
            .to_owned(),
            detail: acquisition_detail(&AcquisitionOutcome::CarrierStartupFailed {
                message: "helper socket mode is 0o660; expected 0o600".to_owned(),
            }),
        };

        assert!(!outcome.is_success());
        let rendered = format!("{outcome:?}");
        assert!(
            rendered.contains("helper socket mode is 0o660"),
            "the logged outcome must name the refused predicate: {rendered}"
        );
    }

    /// Forcing case for refusal preservation: a refusal family whose members
    /// share one coarse code but carry distinct dependent watchers must stay
    /// distinguishable through EVERY operator-facing and archival surface, not
    /// merely internally. `carrier_startup_failed` covers a refused socket mode,
    /// a spawn failure, and a startup timeout alike, so any surface that exports
    /// only the code laundering-collapses them.
    ///
    /// Regression: through 2026-07-19 the `nq watcher test` dry-collection path
    /// exported only the code, so a helper-directory-missing failure (run
    /// 0a2938c) and a 30s startup timeout (run a4faf06) were byte-identical
    /// `carrier_startup_failed` to the operator. This proves the two now stay
    /// distinct through the CLI error and the persisted status-event bytes,
    /// while both retain the stable code.
    #[test]
    fn carrier_startup_detail_survives_the_cli_and_archival_surfaces() {
        let mode = AcquisitionOutcome::CarrierStartupFailed {
            message: "helper socket mode is 0o660; expected 0o600".to_owned(),
        };
        let timeout = AcquisitionOutcome::CarrierStartupFailed {
            message: "supervised helper did not become ready within 30s".to_owned(),
        };

        // Same coarse code: the code alone cannot tell the two causes apart.
        assert_eq!(acquisition_code(&mode), "carrier_startup_failed");
        assert_eq!(acquisition_code(&timeout), "carrier_startup_failed");

        // CLI surface (`nq watcher test` dry collection): the stable code is
        // retained and the distinct detail is appended, so the two differ.
        let cli_mode = dry_collection_error(&mode).to_string();
        let cli_timeout = dry_collection_error(&timeout).to_string();
        assert!(cli_mode.contains("carrier_startup_failed"), "{cli_mode}");
        assert!(cli_timeout.contains("carrier_startup_failed"), "{cli_timeout}");
        assert!(cli_mode.contains("helper socket mode is 0o660"), "{cli_mode}");
        assert!(cli_timeout.contains("did not become ready within 30s"), "{cli_timeout}");
        assert_ne!(cli_mode, cli_timeout);

        // Archival surface: record_instance_status persists canonical(outcome)
        // into status_events.detail, so the same two causes must stay distinct
        // in the stored bytes, code included.
        let persist = |o: &AcquisitionOutcome| -> String {
            let outcome = CollectionOutcome::AcquisitionFailed {
                instance_id: "conformance-local".to_owned(),
                run_id: "00000000-0000-4000-8000-000000000000".to_owned(),
                code: acquisition_code(o).to_owned(),
                detail: acquisition_detail(o),
            };
            String::from_utf8(nq_protocol::canonical_json_bytes(&outcome).expect("canonical"))
                .expect("utf8")
        };
        let stored_mode = persist(&mode);
        let stored_timeout = persist(&timeout);
        assert!(stored_mode.contains("carrier_startup_failed"), "{stored_mode}");
        assert!(stored_mode.contains("helper socket mode is 0o660"), "{stored_mode}");
        assert!(stored_timeout.contains("did not become ready within 30s"), "{stored_timeout}");
        assert_ne!(stored_mode, stored_timeout);

        // Regression guard: an outcome that genuinely carries no detail keeps
        // the bare code, with no invented `: <detail>` suffix appended.
        let bare = dry_collection_error(&AcquisitionOutcome::Timeout).to_string();
        assert!(bare.ends_with("timeout"), "{bare}");
        assert!(!bare.contains("carrier_startup_failed"), "{bare}");
    }
}
