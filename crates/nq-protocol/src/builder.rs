use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    BackendProvenance, Capability, Checkpoint, CollectionBounds, CoverageDeclaration,
    EVIDENCE_REPORT_SCHEMA, EvidenceReport, HELPER_PROTOCOL_VERSION, HELPER_REQUEST_SCHEMA,
    HelperRequest, InstanceId, MonotonicDeadline, Observation, ObservationKind, ProfileBinding,
    ReportError, ReportStatus, SubjectBinding, SubjectId, ValidationError,
};

/// Fluent constructor that applies common client-side request checks at build.
#[derive(Debug, Clone)]
pub struct HelperRequestBuilder {
    request: HelperRequest,
}

impl HelperRequestBuilder {
    pub(crate) fn new(
        request_id: crate::RequestId,
        instance_id: InstanceId,
        profile: ProfileBinding,
        binding: SubjectBinding,
        deadline: MonotonicDeadline,
    ) -> Self {
        Self {
            request: HelperRequest {
                schema: HELPER_REQUEST_SCHEMA.to_owned(),
                protocol_version: HELPER_PROTOCOL_VERSION.to_owned(),
                request_id,
                instance_id,
                profile,
                binding,
                granted_capabilities: Vec::new(),
                checkpoint: None,
                deadline,
                bounds: CollectionBounds::default(),
            },
        }
    }

    /// Replaces negotiated response and cardinality bounds.
    #[must_use]
    pub fn bounds(mut self, bounds: CollectionBounds) -> Self {
        self.request.bounds = bounds;
        self
    }

    /// Appends one granted capability. Order is retained and echoed exactly.
    #[must_use]
    pub fn capability(mut self, capability: Capability) -> Self {
        self.request.granted_capabilities.push(capability);
        self
    }

    /// Replaces the complete ordered capability grant.
    #[must_use]
    pub fn capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.request.granted_capabilities = capabilities;
        self
    }

    /// Supplies an already committed NQ-owned polling checkpoint.
    #[must_use]
    pub fn checkpoint(mut self, checkpoint: Checkpoint) -> Self {
        self.request.checkpoint = Some(checkpoint);
        self
    }

    /// Validates and returns the request.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if a common request law or protocol-wide
    /// hard bound is violated.
    pub fn build(self) -> Result<HelperRequest, ValidationError> {
        crate::validate_request(&self.request)?;
        Ok(self.request)
    }
}

/// Fluent constructor that applies common report checks at build.
#[derive(Debug, Clone)]
pub struct EvidenceReportBuilder {
    report: EvidenceReport,
}

impl EvidenceReportBuilder {
    pub(crate) fn new(
        profile: ProfileBinding,
        binding: SubjectBinding,
        observed_at: DateTime<Utc>,
        status: ReportStatus,
        backend: BackendProvenance,
    ) -> Self {
        Self {
            report: EvidenceReport {
                schema: EVIDENCE_REPORT_SCHEMA.to_owned(),
                profile,
                binding,
                observed_at,
                status,
                coverage: Vec::new(),
                observations: Vec::new(),
                errors: Vec::new(),
                used_capabilities: Vec::new(),
                backend,
                next_checkpoint: None,
            },
        }
    }

    /// Appends one controlled coverage declaration.
    #[must_use]
    pub fn coverage(mut self, declaration: CoverageDeclaration) -> Self {
        self.report.coverage.push(declaration);
        self
    }

    /// Appends a fully constructed observation.
    #[must_use]
    pub fn observation(mut self, observation: Observation) -> Self {
        self.report.observations.push(observation);
        self
    }

    /// Appends an observation and assigns the next contiguous ordinal.
    #[must_use]
    pub fn observed_payload(
        mut self,
        kind: ObservationKind,
        subject: SubjectId,
        observed_at: DateTime<Utc>,
        payload: Value,
    ) -> Self {
        let ordinal = u32::try_from(self.report.observations.len()).unwrap_or(u32::MAX);
        self.report.observations.push(Observation {
            ordinal,
            kind,
            subject,
            observed_at,
            payload,
        });
        self
    }

    /// Appends one ordered structured error.
    #[must_use]
    pub fn error(mut self, error: ReportError) -> Self {
        self.report.errors.push(error);
        self
    }

    /// Records use of one granted capability.
    #[must_use]
    pub fn used_capability(mut self, capability: Capability) -> Self {
        self.report.used_capabilities.push(capability);
        self
    }

    /// Supplies a candidate next cursor. NQ does not advance it until commit.
    #[must_use]
    pub fn next_checkpoint(mut self, checkpoint: Checkpoint) -> Self {
        self.report.next_checkpoint = Some(checkpoint);
        self
    }

    /// Validates and returns the report.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if a common report law or protocol-wide
    /// hard bound is violated.
    pub fn build(self) -> Result<EvidenceReport, ValidationError> {
        crate::validate_report(&self.report)?;
        Ok(self.report)
    }
}
