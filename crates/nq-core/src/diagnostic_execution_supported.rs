//! Strict dispatch across diagnostic-execution wire versions supported by this
//! build.
//!
//! A schema probe selects a version-specific decoder; that decoder still
//! reopens the complete canonical bytes and enforces every contract invariant.
//! The probe never provides a best-effort compatibility path.

use serde_json::Value;

use crate::{
    diagnostic_execution::{
        DiagnosticArtifactId, DiagnosticExecutionError, DiagnosticExecutionV1, DiagnosticRequestId,
        DiagnosticRunId, SemanticIdentityV1,
    },
    diagnostic_execution_v2::{DIAGNOSTIC_EXECUTION_V2_SCHEMA, DiagnosticExecutionV2},
};

/// Every diagnostic-execution contract understood by this build.
pub const SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS: &[&str] = &[
    crate::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA,
    DIAGNOSTIC_EXECUTION_V2_SCHEMA,
];

/// One strictly reopened diagnostic-execution artifact.
#[derive(Debug, Clone, PartialEq)]
pub enum SupportedDiagnosticExecution {
    /// Frozen first contract.
    V1(DiagnosticExecutionV1),
    /// Exact-refusal and explicit-clock-qualification contract.
    V2(DiagnosticExecutionV2),
}

impl SupportedDiagnosticExecution {
    /// Strictly decode one canonical artifact under its exact declared
    /// contract.
    ///
    /// # Errors
    ///
    /// Unknown schemas, missing schema identity, noncanonical bytes, and any
    /// version-specific semantic failure are refused.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DiagnosticExecutionError> {
        let value: Value = serde_json::from_slice(bytes)?;
        let schema = value
            .as_object()
            .and_then(|object| object.get("schema"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DiagnosticExecutionError::Invariant(
                    "diagnostic artifact has no string schema identity".to_owned(),
                )
            })?;
        match schema {
            crate::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA => {
                DiagnosticExecutionV1::decode_canonical(bytes).map(Self::V1)
            }
            DIAGNOSTIC_EXECUTION_V2_SCHEMA => {
                DiagnosticExecutionV2::decode_canonical(bytes).map(Self::V2)
            }
            other => Err(DiagnosticExecutionError::Invariant(format!(
                "unsupported diagnostic execution schema {other}"
            ))),
        }
    }

    /// Exact declared wire schema.
    #[must_use]
    pub fn contract_schema(&self) -> &'static str {
        match self {
            Self::V1(_) => crate::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA,
            Self::V2(_) => DIAGNOSTIC_EXECUTION_V2_SCHEMA,
        }
    }

    /// Contract-owned artifact self-identity.
    #[must_use]
    pub fn artifact_id(&self) -> &DiagnosticArtifactId {
        match self {
            Self::V1(artifact) => &artifact.artifact_id,
            Self::V2(artifact) => &artifact.artifact_id,
        }
    }

    /// Request occurrence identity.
    #[must_use]
    pub fn request_id(&self) -> &DiagnosticRequestId {
        match self {
            Self::V1(artifact) => &artifact.request_id,
            Self::V2(artifact) => &artifact.request_id,
        }
    }

    /// Run occurrence identity.
    #[must_use]
    pub fn run_id(&self) -> &DiagnosticRunId {
        match self {
            Self::V1(artifact) => &artifact.run_id,
            Self::V2(artifact) => &artifact.run_id,
        }
    }

    /// Exact profile descriptor identity.
    #[must_use]
    pub fn profile(&self) -> &SemanticIdentityV1 {
        match self {
            Self::V1(artifact) => &artifact.profile,
            Self::V2(artifact) => &artifact.profile,
        }
    }

    /// Reproduce the exact canonical wire bytes.
    ///
    /// # Errors
    ///
    /// Returns the version-specific semantic or canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DiagnosticExecutionError> {
        match self {
            Self::V1(artifact) => artifact.canonical_bytes(),
            Self::V2(artifact) => artifact.canonical_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_reopens_frozen_v1_and_refuses_unknown_schema() {
        let v1 = include_bytes!("../../../diagnostic-contract/fixtures/valid/positive.json");
        let reopened =
            SupportedDiagnosticExecution::decode_canonical(v1).expect("frozen v1 reopens");
        assert_eq!(
            reopened.contract_schema(),
            crate::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA
        );
        assert_eq!(reopened.canonical_bytes().expect("v1 canonical bytes"), v1);

        let unknown = br#"{"schema":"nq.diagnostic_execution.v999"}"#;
        assert!(matches!(
            SupportedDiagnosticExecution::decode_canonical(unknown),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("unsupported diagnostic execution schema")
        ));
    }
}
