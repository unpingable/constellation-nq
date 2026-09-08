//! Native NQ-ng compiled factual contract. Domain predicate requirements adapted
//! from the closed historical stage contract; no classic runtime or storage is used.
//! Closed contracts for deterministic repository-stage qualification.
//!
//! Raw evidence is factual producer testimony.  Only the NQ evaluator may
//! derive a qualification status from it.  A qualification receipt is an
//! immutable historical statement about exact evidence; it has no freshness
//! semantics and grants no standing, authorization, successor choice,
//! continuation, or effect authority.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const EVALUATOR_ID: &str = "nq-ng.campaign-stage-qualification-evaluator/v1";

pub const CAMPAIGN_STAGE_QUALIFICATION_PROFILE_SCHEMA_V1: &str =
    "nq-ng.campaign-stage-qualification-profile/v1";
pub const CAMPAIGN_STAGE_QUALIFICATION_EVIDENCE_SCHEMA_V1: &str =
    "nq-ng.campaign-stage-qualification-evidence/v1";
pub const CAMPAIGN_STAGE_QUALIFICATION_SCHEMA_V1: &str = "nq-ng.campaign-stage-qualification/v1";
pub const CAMPAIGN_STAGE_QUALIFICATION_REPLAY_SCHEMA_V1: &str =
    "nq-ng.campaign-stage-qualification-replay/v1";

pub const CAMPAIGN_STAGE_QUALIFICATION_NONCLAIMS_V1: &[&str] = &[
    "standing",
    "authorization",
    "successor choice",
    "continuation",
    "effect authority",
    "freshness or present applicability",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitObjectIdentityV1 {
    /// `sha1` or `sha256`; the digest is lower-case hexadecimal.
    pub object_format: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProducerIdentityV1 {
    pub producer_id: String,
    pub producer_version: String,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateExecutionContextV1 {
    pub executable_sha256: String,
    /// SHA-256 over a versioned, length-prefixed argv transcript.
    pub argv_transcript_sha256: String,
    /// Exact repository-relative working directory, `.` for the root.
    pub repository_relative_cwd: String,
    /// SHA-256 over the versioned, sorted allowed-environment transcript.
    pub environment_transcript_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateRequirementV1 {
    pub ordinal: u32,
    pub gate_id: String,
    pub context: GateExecutionContextV1,
    pub required_exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRequirementV1 {
    pub repository_relative_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkspaceCustodyPredicateV1 {
    RepositoryIdentityMatches,
    PersistentWriteReadRoundTrip,
    HeadAndTreeStableDuringQualification,
    WorktreeMatchesDeclaredCleanliness,
    MutationScopeRespected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CampaignStageQualificationProfileV1 {
    pub schema: String,
    pub profile_id: String,
    pub campaign_packet_sha256: String,
    pub stage_id: String,
    pub repository_id: String,
    pub repository_ref: String,
    pub predecessor_head: GitObjectIdentityV1,
    pub predecessor_tree: GitObjectIdentityV1,
    pub result_head: GitObjectIdentityV1,
    pub result_tree: GitObjectIdentityV1,
    pub expected_evidence_producer: EvidenceProducerIdentityV1,
    /// Exactly ordered, contiguous from ordinal zero, and fail-fast.
    pub ordered_gates: Vec<GateRequirementV1>,
    /// Exact set: no required artifact may be absent and no undeclared
    /// artifact may be presented as qualification evidence.
    pub required_artifacts: Vec<ArtifactRequirementV1>,
    /// Exact set of required workspace-custody predicates.
    pub required_workspace_predicates: Vec<WorkspaceCustodyPredicateV1>,
    pub expected_clean_worktree: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "outcome",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum GateOutcomeV1 {
    Completed {
        exit_code: i32,
        stdout_sha256: String,
        stderr_sha256: String,
    },
    /// Lawful only after the first completed gate with a non-required exit.
    NotRunAfterFailure { failed_gate_ordinal: u32 },
    /// Producer could not retain an exact result. This is never failure proof.
    Indeterminate { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateEvidenceV1 {
    pub ordinal: u32,
    pub gate_id: String,
    pub context: GateExecutionContextV1,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub outcome: GateOutcomeV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidenceV1 {
    pub repository_relative_path: String,
    pub present: bool,
    pub sha256: Option<String>,
    pub observation_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "outcome",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum WorkspacePredicateOutcomeV1 {
    Passed,
    Failed { reason: String },
    Indeterminate { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCustodyEvidenceV1 {
    pub predicate: WorkspaceCustodyPredicateV1,
    pub observation_sha256: String,
    pub outcome: WorkspacePredicateOutcomeV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CampaignStageQualificationEvidenceV1 {
    pub schema: String,
    pub evidence_id: String,
    pub profile_id: String,
    /// Digest of the exact profile document evaluated by the producer.
    pub profile_sha256: String,
    pub campaign_packet_sha256: String,
    pub stage_id: String,
    pub repository_id: String,
    pub repository_ref: String,
    pub predecessor_head: GitObjectIdentityV1,
    pub predecessor_tree: GitObjectIdentityV1,
    pub result_head: GitObjectIdentityV1,
    pub result_tree: GitObjectIdentityV1,
    pub producer: EvidenceProducerIdentityV1,
    pub qualification_started_at_unix_ms: u64,
    pub qualification_finished_at_unix_ms: u64,
    pub gates: Vec<GateEvidenceV1>,
    pub artifacts: Vec<ArtifactEvidenceV1>,
    pub workspace_custody: Vec<WorkspaceCustodyEvidenceV1>,
    pub observed_clean_worktree: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualificationStatusV1 {
    Qualified,
    Failed,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualificationReasonV1 {
    AllRequiredPredicatesHold,
    RequiredGateFailed,
    RequiredArtifactFailed,
    WorkspaceCustodyFailed,
    EvidenceIncomplete,
    ContractOrIdentityMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CampaignStageQualificationReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub evaluator_id: String,
    pub evaluator_version: String,
    pub evaluator_executable_sha256: String,
    pub evaluated_at_unix_ms: u64,
    pub profile_id: String,
    pub profile_sha256: String,
    pub evidence_id: String,
    pub evidence_sha256: String,
    pub campaign_packet_sha256: String,
    pub stage_id: String,
    pub repository_id: String,
    pub repository_ref: String,
    pub predecessor_head: GitObjectIdentityV1,
    pub predecessor_tree: GitObjectIdentityV1,
    pub result_head: GitObjectIdentityV1,
    pub result_tree: GitObjectIdentityV1,
    pub status: QualificationStatusV1,
    pub reasons: Vec<QualificationReasonV1>,
    /// Explicitly restates the contract boundary in every receipt.
    pub does_not_establish: Vec<String>,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvaluatorIdentityV1 {
    pub evaluator_id: String,
    pub evaluator_version: String,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CampaignStageQualificationReplayV1 {
    pub schema: String,
    pub matches: bool,
    pub expected_receipt_sha256: String,
    pub recomputed_receipt_sha256: String,
}

/// Deterministically evaluate one exact closed profile against one factual
/// evidence document. The caller supplies no verdict or reason.
pub fn evaluate_campaign_stage_qualification(
    profile: &CampaignStageQualificationProfileV1,
    evidence: &CampaignStageQualificationEvidenceV1,
    evaluator: &QualificationEvaluatorIdentityV1,
    evaluated_at_unix_ms: u64,
) -> CampaignStageQualificationReceiptV1 {
    let profile_sha256 = canonical_sha256(profile);
    let evidence_sha256 = canonical_sha256(evidence);
    let mut indeterminate = false;
    let mut failed_gate = false;
    let mut failed_artifact = false;
    let mut failed_custody = false;

    if !profile_is_well_formed(profile)
        || !matches!(
            evaluator.evaluator_id.as_str(),
            EVALUATOR_ID | crate::stage_realization::EVALUATOR_ID
        )
        || evaluator.evaluator_version.is_empty()
        || !is_sha256(&evaluator.executable_sha256)
        || evidence.schema != CAMPAIGN_STAGE_QUALIFICATION_EVIDENCE_SCHEMA_V1
        || evidence.evidence_id.is_empty()
        || evidence.profile_id != profile.profile_id
        || evidence.profile_sha256 != profile_sha256
        || !same_bindings(profile, evidence)
        || evidence.producer != profile.expected_evidence_producer
        || !producer_is_well_formed(&evidence.producer)
        || evidence.qualification_started_at_unix_ms > evidence.qualification_finished_at_unix_ms
        || evaluated_at_unix_ms < evidence.qualification_finished_at_unix_ms
        || !is_sha256(&profile_sha256)
        || !is_sha256(&evidence_sha256)
    {
        indeterminate = true;
    }

    if !gates_are_well_formed(profile, evidence, &mut failed_gate) {
        indeterminate = true;
    }
    if !artifacts_are_well_formed(profile, evidence, &mut failed_artifact) {
        indeterminate = true;
    }
    if !custody_is_well_formed(profile, evidence, &mut failed_custody) {
        indeterminate = true;
    }
    match evidence.observed_clean_worktree {
        Some(actual) if actual != profile.expected_clean_worktree => failed_custody = true,
        None => indeterminate = true,
        _ => {}
    }

    let (status, reasons) = if indeterminate {
        (
            QualificationStatusV1::Indeterminate,
            vec![
                QualificationReasonV1::EvidenceIncomplete,
                QualificationReasonV1::ContractOrIdentityMismatch,
            ],
        )
    } else if failed_gate || failed_artifact || failed_custody {
        let mut reasons = Vec::new();
        if failed_gate {
            reasons.push(QualificationReasonV1::RequiredGateFailed);
        }
        if failed_artifact {
            reasons.push(QualificationReasonV1::RequiredArtifactFailed);
        }
        if failed_custody {
            reasons.push(QualificationReasonV1::WorkspaceCustodyFailed);
        }
        (QualificationStatusV1::Failed, reasons)
    } else {
        (
            QualificationStatusV1::Qualified,
            vec![QualificationReasonV1::AllRequiredPredicatesHold],
        )
    };

    let mut receipt = CampaignStageQualificationReceiptV1 {
        schema: CAMPAIGN_STAGE_QUALIFICATION_SCHEMA_V1.to_owned(),
        receipt_id: format!(
            "qualification:{}:{}",
            profile.profile_id, evidence.evidence_id
        ),
        evaluator_id: evaluator.evaluator_id.clone(),
        evaluator_version: evaluator.evaluator_version.clone(),
        evaluator_executable_sha256: evaluator.executable_sha256.clone(),
        evaluated_at_unix_ms,
        profile_id: profile.profile_id.clone(),
        profile_sha256,
        evidence_id: evidence.evidence_id.clone(),
        evidence_sha256,
        campaign_packet_sha256: profile.campaign_packet_sha256.clone(),
        stage_id: profile.stage_id.clone(),
        repository_id: profile.repository_id.clone(),
        repository_ref: profile.repository_ref.clone(),
        predecessor_head: profile.predecessor_head.clone(),
        predecessor_tree: profile.predecessor_tree.clone(),
        result_head: profile.result_head.clone(),
        result_tree: profile.result_tree.clone(),
        status,
        reasons,
        does_not_establish: CAMPAIGN_STAGE_QUALIFICATION_NONCLAIMS_V1
            .iter()
            .map(|claim| (*claim).to_owned())
            .collect(),
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt_digest(&receipt);
    receipt
}

pub fn replay_campaign_stage_qualification(
    profile: &CampaignStageQualificationProfileV1,
    evidence: &CampaignStageQualificationEvidenceV1,
    receipt: &CampaignStageQualificationReceiptV1,
) -> CampaignStageQualificationReplayV1 {
    let evaluator = QualificationEvaluatorIdentityV1 {
        evaluator_id: receipt.evaluator_id.clone(),
        evaluator_version: receipt.evaluator_version.clone(),
        executable_sha256: receipt.evaluator_executable_sha256.clone(),
    };
    let recomputed = evaluate_campaign_stage_qualification(
        profile,
        evidence,
        &evaluator,
        receipt.evaluated_at_unix_ms,
    );
    CampaignStageQualificationReplayV1 {
        schema: CAMPAIGN_STAGE_QUALIFICATION_REPLAY_SCHEMA_V1.to_owned(),
        matches: recomputed == *receipt && receipt.receipt_sha256 == receipt_digest(receipt),
        expected_receipt_sha256: receipt.receipt_sha256.clone(),
        recomputed_receipt_sha256: recomputed.receipt_sha256,
    }
}

fn canonical_sha256<T: Serialize>(value: &T) -> String {
    match nq_protocol::semantic_digest(value) {
        Ok(digest) => digest.into_string(),
        Err(error) => format!("invalid:{error}"),
    }
}

fn receipt_digest(receipt: &CampaignStageQualificationReceiptV1) -> String {
    let mut unsigned = receipt.clone();
    unsigned.receipt_sha256.clear();
    canonical_sha256(&unsigned)
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn git_object_is_well_formed(value: &GitObjectIdentityV1) -> bool {
    let length = match value.object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        _ => return false,
    };
    value.digest.len() == length
        && value
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn producer_is_well_formed(value: &EvidenceProducerIdentityV1) -> bool {
    !value.producer_id.is_empty()
        && !value.producer_version.is_empty()
        && is_sha256(&value.executable_sha256)
}

fn context_is_well_formed(value: &GateExecutionContextV1) -> bool {
    is_sha256(&value.executable_sha256)
        && is_sha256(&value.argv_transcript_sha256)
        && is_sha256(&value.environment_transcript_sha256)
        && !value.repository_relative_cwd.is_empty()
        && !value.repository_relative_cwd.starts_with('/')
        && !value
            .repository_relative_cwd
            .split('/')
            .any(|part| part == "..")
}

fn profile_is_well_formed(profile: &CampaignStageQualificationProfileV1) -> bool {
    if profile.schema != CAMPAIGN_STAGE_QUALIFICATION_PROFILE_SCHEMA_V1
        || profile.profile_id.is_empty()
        || profile.stage_id.is_empty()
        || profile.repository_id.is_empty()
        || !profile.repository_ref.starts_with("refs/")
        || !is_sha256(&profile.campaign_packet_sha256)
        || !producer_is_well_formed(&profile.expected_evidence_producer)
        || !git_object_is_well_formed(&profile.predecessor_head)
        || !git_object_is_well_formed(&profile.predecessor_tree)
        || !git_object_is_well_formed(&profile.result_head)
        || !git_object_is_well_formed(&profile.result_tree)
        || profile.ordered_gates.is_empty()
        || profile.required_workspace_predicates.is_empty()
    {
        return false;
    }
    let mut gate_ids = BTreeSet::new();
    if profile
        .ordered_gates
        .iter()
        .enumerate()
        .any(|(ordinal, gate)| {
            gate.ordinal as usize != ordinal
                || gate.gate_id.is_empty()
                || !gate_ids.insert(gate.gate_id.as_str())
                || !context_is_well_formed(&gate.context)
        })
    {
        return false;
    }
    let mut artifact_paths = BTreeSet::new();
    if profile.required_artifacts.iter().any(|artifact| {
        artifact.repository_relative_path.is_empty()
            || artifact.repository_relative_path.starts_with('/')
            || artifact
                .repository_relative_path
                .split('/')
                .any(|part| part == "..")
            || !is_sha256(&artifact.sha256)
            || !artifact_paths.insert(artifact.repository_relative_path.as_str())
    }) {
        return false;
    }
    let custody: BTreeSet<_> = profile.required_workspace_predicates.iter().collect();
    custody.len() == profile.required_workspace_predicates.len()
}

fn same_bindings(
    profile: &CampaignStageQualificationProfileV1,
    evidence: &CampaignStageQualificationEvidenceV1,
) -> bool {
    evidence.campaign_packet_sha256 == profile.campaign_packet_sha256
        && evidence.stage_id == profile.stage_id
        && evidence.repository_id == profile.repository_id
        && evidence.repository_ref == profile.repository_ref
        && evidence.predecessor_head == profile.predecessor_head
        && evidence.predecessor_tree == profile.predecessor_tree
        && evidence.result_head == profile.result_head
        && evidence.result_tree == profile.result_tree
}

fn gates_are_well_formed(
    profile: &CampaignStageQualificationProfileV1,
    evidence: &CampaignStageQualificationEvidenceV1,
    failed: &mut bool,
) -> bool {
    if evidence.gates.len() != profile.ordered_gates.len() {
        return false;
    }
    let mut first_failure = None;
    let mut previous_finish = evidence.qualification_started_at_unix_ms;
    for (required, observed) in profile.ordered_gates.iter().zip(&evidence.gates) {
        if observed.ordinal != required.ordinal
            || observed.gate_id != required.gate_id
            || observed.context != required.context
            || observed.started_at_unix_ms > observed.finished_at_unix_ms
            || observed.started_at_unix_ms < evidence.qualification_started_at_unix_ms
            || observed.finished_at_unix_ms > evidence.qualification_finished_at_unix_ms
            || observed.started_at_unix_ms < previous_finish
        {
            return false;
        }
        previous_finish = observed.finished_at_unix_ms;
        match (&observed.outcome, first_failure) {
            (
                GateOutcomeV1::Completed {
                    exit_code,
                    stdout_sha256,
                    stderr_sha256,
                },
                None,
            ) => {
                if !is_sha256(stdout_sha256) || !is_sha256(stderr_sha256) {
                    return false;
                }
                if *exit_code != required.required_exit_code {
                    *failed = true;
                    first_failure = Some(required.ordinal);
                }
            }
            (
                GateOutcomeV1::NotRunAfterFailure {
                    failed_gate_ordinal,
                },
                Some(first),
            ) if *failed_gate_ordinal == first => {}
            (GateOutcomeV1::Indeterminate { .. }, _) => return false,
            _ => return false,
        }
    }
    true
}

fn artifacts_are_well_formed(
    profile: &CampaignStageQualificationProfileV1,
    evidence: &CampaignStageQualificationEvidenceV1,
    failed: &mut bool,
) -> bool {
    if evidence.artifacts.len() != profile.required_artifacts.len() {
        return false;
    }
    let expected: BTreeSet<_> = profile
        .required_artifacts
        .iter()
        .map(|value| value.repository_relative_path.as_str())
        .collect();
    let actual: BTreeSet<_> = evidence
        .artifacts
        .iter()
        .map(|value| value.repository_relative_path.as_str())
        .collect();
    if expected != actual || actual.len() != evidence.artifacts.len() {
        return false;
    }
    for observed in &evidence.artifacts {
        if !is_sha256(&observed.observation_sha256) {
            return false;
        }
        let required = profile
            .required_artifacts
            .iter()
            .find(|value| value.repository_relative_path == observed.repository_relative_path)
            .expect("set equality established");
        match (&observed.sha256, observed.present) {
            (Some(digest), true) if is_sha256(digest) => {
                if digest != &required.sha256 {
                    *failed = true;
                }
            }
            (None, false) => *failed = true,
            _ => return false,
        }
    }
    true
}

fn custody_is_well_formed(
    profile: &CampaignStageQualificationProfileV1,
    evidence: &CampaignStageQualificationEvidenceV1,
    failed: &mut bool,
) -> bool {
    if evidence.workspace_custody.len() != profile.required_workspace_predicates.len() {
        return false;
    }
    let expected: BTreeSet<_> = profile.required_workspace_predicates.iter().collect();
    let actual: BTreeSet<_> = evidence
        .workspace_custody
        .iter()
        .map(|value| &value.predicate)
        .collect();
    if expected != actual || actual.len() != evidence.workspace_custody.len() {
        return false;
    }
    for observed in &evidence.workspace_custody {
        if !is_sha256(&observed.observation_sha256) {
            return false;
        }
        match observed.outcome {
            WorkspacePredicateOutcomeV1::Passed => {}
            WorkspacePredicateOutcomeV1::Failed { .. } => *failed = true,
            WorkspacePredicateOutcomeV1::Indeterminate { .. } => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn object(byte: char) -> GitObjectIdentityV1 {
        GitObjectIdentityV1 {
            object_format: "sha1".to_owned(),
            digest: byte.to_string().repeat(40),
        }
    }

    fn context(byte: char) -> GateExecutionContextV1 {
        GateExecutionContextV1 {
            executable_sha256: digest(byte),
            argv_transcript_sha256: digest(byte),
            repository_relative_cwd: ".".to_owned(),
            environment_transcript_sha256: digest(byte),
        }
    }

    fn evaluator() -> QualificationEvaluatorIdentityV1 {
        QualificationEvaluatorIdentityV1 {
            evaluator_id: "nq-ng.campaign-stage-qualification-evaluator/v1".to_owned(),
            evaluator_version: "1.0.0".to_owned(),
            executable_sha256: digest('e'),
        }
    }

    fn specimen() -> (
        CampaignStageQualificationProfileV1,
        CampaignStageQualificationEvidenceV1,
    ) {
        let producer = EvidenceProducerIdentityV1 {
            producer_id: "porter.repository-facts/v1".to_owned(),
            producer_version: "1.0.0".to_owned(),
            executable_sha256: digest('a'),
        };
        let profile = CampaignStageQualificationProfileV1 {
            schema: CAMPAIGN_STAGE_QUALIFICATION_PROFILE_SCHEMA_V1.to_owned(),
            profile_id: "campaign/profile/stage-1".to_owned(),
            campaign_packet_sha256: digest('b'),
            stage_id: "stage-1".to_owned(),
            repository_id: "repo/example".to_owned(),
            repository_ref: "refs/heads/campaign/example".to_owned(),
            predecessor_head: object('1'),
            predecessor_tree: object('2'),
            result_head: object('3'),
            result_tree: object('4'),
            expected_evidence_producer: producer.clone(),
            ordered_gates: vec![
                GateRequirementV1 {
                    ordinal: 0,
                    gate_id: "format".to_owned(),
                    context: context('5'),
                    required_exit_code: 0,
                },
                GateRequirementV1 {
                    ordinal: 1,
                    gate_id: "test".to_owned(),
                    context: context('6'),
                    required_exit_code: 0,
                },
            ],
            required_artifacts: vec![ArtifactRequirementV1 {
                repository_relative_path: "evidence/result.json".to_owned(),
                sha256: digest('7'),
            }],
            required_workspace_predicates: vec![
                WorkspaceCustodyPredicateV1::RepositoryIdentityMatches,
                WorkspaceCustodyPredicateV1::PersistentWriteReadRoundTrip,
                WorkspaceCustodyPredicateV1::HeadAndTreeStableDuringQualification,
                WorkspaceCustodyPredicateV1::WorktreeMatchesDeclaredCleanliness,
                WorkspaceCustodyPredicateV1::MutationScopeRespected,
            ],
            expected_clean_worktree: true,
        };
        let mut evidence = CampaignStageQualificationEvidenceV1 {
            schema: CAMPAIGN_STAGE_QUALIFICATION_EVIDENCE_SCHEMA_V1.to_owned(),
            evidence_id: "evidence/stage-1/attempt-1".to_owned(),
            profile_id: profile.profile_id.clone(),
            profile_sha256: String::new(),
            campaign_packet_sha256: profile.campaign_packet_sha256.clone(),
            stage_id: profile.stage_id.clone(),
            repository_id: profile.repository_id.clone(),
            repository_ref: profile.repository_ref.clone(),
            predecessor_head: profile.predecessor_head.clone(),
            predecessor_tree: profile.predecessor_tree.clone(),
            result_head: profile.result_head.clone(),
            result_tree: profile.result_tree.clone(),
            producer,
            qualification_started_at_unix_ms: 1,
            qualification_finished_at_unix_ms: 40,
            gates: profile
                .ordered_gates
                .iter()
                .map(|gate| GateEvidenceV1 {
                    ordinal: gate.ordinal,
                    gate_id: gate.gate_id.clone(),
                    context: gate.context.clone(),
                    started_at_unix_ms: 10 + u64::from(gate.ordinal) * 10,
                    finished_at_unix_ms: 19 + u64::from(gate.ordinal) * 10,
                    outcome: GateOutcomeV1::Completed {
                        exit_code: 0,
                        stdout_sha256: digest('8'),
                        stderr_sha256: digest('9'),
                    },
                })
                .collect(),
            artifacts: vec![ArtifactEvidenceV1 {
                repository_relative_path: "evidence/result.json".to_owned(),
                present: true,
                sha256: Some(digest('7')),
                observation_sha256: digest('a'),
            }],
            workspace_custody: profile
                .required_workspace_predicates
                .iter()
                .cloned()
                .map(|predicate| WorkspaceCustodyEvidenceV1 {
                    predicate,
                    observation_sha256: digest('c'),
                    outcome: WorkspacePredicateOutcomeV1::Passed,
                })
                .collect(),
            observed_clean_worktree: Some(true),
        };
        evidence.profile_sha256 = canonical_sha256(&profile);
        (profile, evidence)
    }

    fn status(
        profile: &CampaignStageQualificationProfileV1,
        evidence: &CampaignStageQualificationEvidenceV1,
    ) -> QualificationStatusV1 {
        evaluate_campaign_stage_qualification(profile, evidence, &evaluator(), 50).status
    }

    #[test]
    fn schemas_and_nonclaims_are_frozen() {
        assert_eq!(
            CAMPAIGN_STAGE_QUALIFICATION_PROFILE_SCHEMA_V1,
            "nq-ng.campaign-stage-qualification-profile/v1"
        );
        assert_eq!(
            CAMPAIGN_STAGE_QUALIFICATION_EVIDENCE_SCHEMA_V1,
            "nq-ng.campaign-stage-qualification-evidence/v1"
        );
        assert_eq!(
            CAMPAIGN_STAGE_QUALIFICATION_SCHEMA_V1,
            "nq-ng.campaign-stage-qualification/v1"
        );
        assert_eq!(CAMPAIGN_STAGE_QUALIFICATION_NONCLAIMS_V1.len(), 6);
        assert!(CAMPAIGN_STAGE_QUALIFICATION_NONCLAIMS_V1.contains(&"authorization"));
        assert!(CAMPAIGN_STAGE_QUALIFICATION_NONCLAIMS_V1.contains(&"continuation"));
        assert!(
            CAMPAIGN_STAGE_QUALIFICATION_NONCLAIMS_V1
                .contains(&"freshness or present applicability")
        );
    }

    #[test]
    fn modern_identity_time_order_and_canonical_limits_are_required() {
        let (profile, evidence) = specimen();
        let mut old = evaluator();
        old.evaluator_id = "nq.campaign-stage-qualification-evaluator/v1".into();
        assert_eq!(
            evaluate_campaign_stage_qualification(&profile, &evidence, &old, 50).status,
            QualificationStatusV1::Indeterminate
        );
        assert_eq!(
            evaluate_campaign_stage_qualification(&profile, &evidence, &evaluator(), 1).status,
            QualificationStatusV1::Indeterminate
        );
        let mut reordered = evidence.clone();
        reordered.gates[1].started_at_unix_ms = 10;
        assert_eq!(
            status(&profile, &reordered),
            QualificationStatusV1::Indeterminate
        );
        let mut oversized = evidence;
        oversized.qualification_finished_at_unix_ms = u64::MAX;
        assert_eq!(
            evaluate_campaign_stage_qualification(&profile, &oversized, &evaluator(), u64::MAX)
                .status,
            QualificationStatusV1::Indeterminate
        );
    }

    #[test]
    fn raw_evidence_has_no_verdict_field() {
        let fields = serde_json::to_value(CampaignStageQualificationEvidenceV1 {
            schema: CAMPAIGN_STAGE_QUALIFICATION_EVIDENCE_SCHEMA_V1.to_owned(),
            evidence_id: "e".to_owned(),
            profile_id: "p".to_owned(),
            profile_sha256: "sha256:00".to_owned(),
            campaign_packet_sha256: "sha256:00".to_owned(),
            stage_id: "s".to_owned(),
            repository_id: "r".to_owned(),
            repository_ref: "refs/heads/c".to_owned(),
            predecessor_head: GitObjectIdentityV1 {
                object_format: "sha1".to_owned(),
                digest: "0".repeat(40),
            },
            predecessor_tree: GitObjectIdentityV1 {
                object_format: "sha1".to_owned(),
                digest: "0".repeat(40),
            },
            result_head: GitObjectIdentityV1 {
                object_format: "sha1".to_owned(),
                digest: "1".repeat(40),
            },
            result_tree: GitObjectIdentityV1 {
                object_format: "sha1".to_owned(),
                digest: "1".repeat(40),
            },
            producer: EvidenceProducerIdentityV1 {
                producer_id: "producer".to_owned(),
                producer_version: "v1".to_owned(),
                executable_sha256: "sha256:00".to_owned(),
            },
            qualification_started_at_unix_ms: 1,
            qualification_finished_at_unix_ms: 2,
            gates: vec![],
            artifacts: vec![],
            workspace_custody: vec![],
            observed_clean_worktree: Some(true),
        })
        .unwrap();
        assert!(fields.get("status").is_none());
        assert!(fields.get("verdict").is_none());
        assert!(fields.get("authorized").is_none());

        let mut with_verdict = fields;
        with_verdict["verdict"] = serde_json::json!("QUALIFIED");
        assert!(
            serde_json::from_value::<CampaignStageQualificationEvidenceV1>(with_verdict).is_err()
        );
    }

    #[test]
    fn exact_complete_evidence_is_qualified_and_replays() {
        let (profile, evidence) = specimen();
        let receipt = evaluate_campaign_stage_qualification(&profile, &evidence, &evaluator(), 50);
        assert_eq!(receipt.status, QualificationStatusV1::Qualified);
        assert_eq!(
            receipt.reasons,
            vec![QualificationReasonV1::AllRequiredPredicatesHold]
        );
        assert_eq!(receipt.does_not_establish.len(), 6);
        assert!(replay_campaign_stage_qualification(&profile, &evidence, &receipt).matches);

        let mut tampered = receipt;
        tampered.status = QualificationStatusV1::Failed;
        assert!(!replay_campaign_stage_qualification(&profile, &evidence, &tampered).matches);
    }

    #[test]
    fn complete_negative_evidence_is_failed() {
        let (profile, mut evidence) = specimen();
        evidence.gates[0].outcome = GateOutcomeV1::Completed {
            exit_code: 1,
            stdout_sha256: digest('8'),
            stderr_sha256: digest('9'),
        };
        evidence.gates[1].outcome = GateOutcomeV1::NotRunAfterFailure {
            failed_gate_ordinal: 0,
        };
        assert_eq!(status(&profile, &evidence), QualificationStatusV1::Failed);

        let (_, mut evidence) = specimen();
        evidence.artifacts[0].sha256 = Some(digest('d'));
        assert_eq!(status(&profile, &evidence), QualificationStatusV1::Failed);

        let (_, mut evidence) = specimen();
        evidence.workspace_custody[0].outcome = WorkspacePredicateOutcomeV1::Failed {
            reason: "probe did not survive reopen".to_owned(),
        };
        assert_eq!(status(&profile, &evidence), QualificationStatusV1::Failed);
    }

    #[test]
    fn identity_and_completeness_substitutions_are_indeterminate() {
        let (profile, evidence) = specimen();
        let mut cases = Vec::new();

        let mut value = evidence.clone();
        value.schema = "wrong".to_owned();
        cases.push(value);
        let mut value = evidence.clone();
        value.profile_sha256 = digest('f');
        cases.push(value);
        let mut value = evidence.clone();
        value.campaign_packet_sha256 = digest('f');
        cases.push(value);
        let mut value = evidence.clone();
        value.predecessor_head = object('f');
        cases.push(value);
        let mut value = evidence.clone();
        value.result_tree = object('f');
        cases.push(value);
        let mut value = evidence.clone();
        value.producer.producer_id = "worker-self-assertion".to_owned();
        cases.push(value);
        let mut value = evidence.clone();
        value.gates.remove(0);
        cases.push(value);
        let mut value = evidence.clone();
        value.gates.swap(0, 1);
        cases.push(value);
        let mut value = evidence.clone();
        value.gates[0].context.argv_transcript_sha256 = digest('f');
        cases.push(value);
        let mut value = evidence.clone();
        value.artifacts.clear();
        cases.push(value);
        let mut value = evidence.clone();
        value.workspace_custody.clear();
        cases.push(value);
        let mut value = evidence.clone();
        value.observed_clean_worktree = None;
        cases.push(value);
        let mut value = evidence;
        value.gates[0].outcome = GateOutcomeV1::Indeterminate {
            reason: "process disappeared".to_owned(),
        };
        cases.push(value);

        for case in cases {
            assert_eq!(
                status(&profile, &case),
                QualificationStatusV1::Indeterminate
            );
        }
    }
}
