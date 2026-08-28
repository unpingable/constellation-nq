//! Mechanics-separated execute and read-only reconciliation law.
//!
//! `execute_once` is the sole method permitted to cross into runtime mechanics.
//! `reconcile` receives a different trait that can only observe retained facts.
//! Rust traits cannot prove physical read-only behavior, so deployments must
//! separately qualify the reconciler binary and permissions; the type split
//! prevents this crate from accidentally calling execute during reconciliation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AuthorizationBindingV1, ClaimBindingV1, ExactOccurrenceMachineV1, OccurrenceError,
    OccurrenceStateV1, OutcomeUnknownBindingV1, RuntimeBindingV1, TerminalBindingV1,
    TerminalClassV1, TransitionEffectV1,
};
use nq_protocol::Sha256Digest;

/// Exact immutable request presented to mechanics or reconciliation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequestV1 {
    /// Prepared plan identity.
    pub plan_id: Sha256Digest,
    /// Exact NQ occurrence.
    pub nq_occurrence: Sha256Digest,
    /// Exact AG/Docket authorization binding.
    pub authorization: AuthorizationBindingV1,
    /// Exact NQ coordination claim.
    pub claim: ClaimBindingV1,
    /// Optional already-retained runtime for read-only reconciliation.
    pub runtime: Option<RuntimeBindingV1>,
}

/// Definite completion returned by the sole mechanics call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MechanicsCompletionV1 {
    /// Exact runtime instance created by mechanics.
    pub runtime: RuntimeBindingV1,
    /// Exact terminal evidence for that runtime.
    pub terminal: TerminalBindingV1,
}

/// Closed failure classes from the sole mechanics call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MechanicsFailureV1 {
    /// Qualified evidence proves refusal before a runtime existed.
    DefinitePreRuntimeRefusal(TerminalBindingV1),
    /// A runtime may exist or a result was lost; exact outcome is unknown.
    OutcomeUnknown {
        /// Runtime identity when it was durably learned.
        runtime: Option<RuntimeBindingV1>,
        /// Exact uncertainty evidence.
        unknown: OutcomeUnknownBindingV1,
    },
}

/// Authority-neutral mechanics. This is the only trait allowed to create work.
pub trait ExecuteMechanicsV1 {
    /// Performs the one exact already-claimed runtime operation.
    fn execute(
        &mut self,
        request: &ExecutionRequestV1,
    ) -> Result<MechanicsCompletionV1, Box<MechanicsFailureV1>>;
}

/// Closed read-only reconciliation observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationObservationV1 {
    /// Exact retained evidence establishes a definite result.
    Definite(TerminalBindingV1),
    /// Exact retained evidence cannot establish a definite result.
    OutcomeUnknown(OutcomeUnknownBindingV1),
}

/// Mechanics-free evidence reader used only by [`reconcile`].
pub trait ReconcileEvidenceV1 {
    /// Reads retained external/NQ evidence without invoking runtime mechanics.
    fn observe(&mut self, request: &ExecutionRequestV1) -> ReconciliationObservationV1;
}

/// Result of a bounded execute or reconcile call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryResultV1 {
    /// A definite terminal result was newly retained.
    Terminal(TransitionEffectV1),
    /// Outcome-unknown was newly retained or exactly replayed.
    OutcomeUnknown(TransitionEffectV1),
    /// Existing definite terminal state was projected without mechanics.
    ReplayedTerminal,
    /// Existing outcome-unknown state was projected without mechanics.
    ReplayedOutcomeUnknown,
}

/// Boundary refusal preserving exact current state.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BoundaryErrorV1 {
    /// Exact-occurrence state/binding refusal.
    #[error(transparent)]
    Occurrence(#[from] OccurrenceError),
    /// Execute may not repeat after a runtime identity is retained.
    #[error("exact occurrence requires mechanics-free reconciliation")]
    ReconciliationRequired,
    /// Mechanics claimed a definite non-refusal without a runtime identity.
    #[error("pre-runtime definite result must be refusal")]
    InvalidPreRuntimeResult,
}

/// Invokes the sole exact mechanics operation from `claimed` state.
///
/// Existing terminal states are replayed without calling mechanics. An
/// `executing` state requires [`reconcile`] and can never call mechanics again.
/// Candidate transitions are applied to a clone and committed only when all
/// returned bindings validate, preventing a substituted completion from
/// partially advancing in-memory state.
///
/// # Errors
///
/// Returns [`BoundaryErrorV1`] for invalid state, returned binding
/// substitution, or an invalid pre-runtime result class.
pub fn execute_once<M: ExecuteMechanicsV1>(
    machine: &mut ExactOccurrenceMachineV1,
    mechanics: &mut M,
) -> Result<BoundaryResultV1, BoundaryErrorV1> {
    match machine.state {
        OccurrenceStateV1::Terminal { .. } => return Ok(BoundaryResultV1::ReplayedTerminal),
        OccurrenceStateV1::OutcomeUnknown { .. } => {
            return Ok(BoundaryResultV1::ReplayedOutcomeUnknown);
        }
        OccurrenceStateV1::Executing { .. } => {
            return Err(BoundaryErrorV1::ReconciliationRequired);
        }
        OccurrenceStateV1::Prepared | OccurrenceStateV1::Authorized { .. } => {
            return Err(BoundaryErrorV1::Occurrence(
                OccurrenceError::InvalidTransition {
                    state: machine.state.label(),
                    requested: "execute",
                },
            ));
        }
        OccurrenceStateV1::Claimed { .. } => {}
    }

    let request = request_from_machine(machine)?;
    let response = mechanics.execute(&request);
    let mut candidate = machine.clone();
    let result = match response {
        Ok(completion) => {
            candidate.begin_execution(completion.runtime)?;
            let effect = candidate.finish(completion.terminal)?;
            BoundaryResultV1::Terminal(effect)
        }
        Err(failure) => match *failure {
            MechanicsFailureV1::DefinitePreRuntimeRefusal(terminal) => {
                if terminal.class != TerminalClassV1::Refused {
                    return Err(BoundaryErrorV1::InvalidPreRuntimeResult);
                }
                let effect = candidate.finish(terminal)?;
                BoundaryResultV1::Terminal(effect)
            }
            MechanicsFailureV1::OutcomeUnknown { runtime, unknown } => {
                if let Some(runtime) = runtime {
                    candidate.begin_execution(runtime)?;
                }
                let effect = candidate.mark_outcome_unknown(unknown)?;
                BoundaryResultV1::OutcomeUnknown(effect)
            }
        },
    };
    *machine = candidate;
    Ok(result)
}

/// Reconciles retained evidence without access to the mechanics trait.
///
/// This operation is legal only after claim. It can settle `executing` or
/// `outcome_unknown` from exact evidence and can mark an unresolved claimed or
/// executing attempt unknown. It never constructs a runtime identity and never
/// calls [`ExecuteMechanicsV1::execute`].
///
/// # Errors
///
/// Returns [`BoundaryErrorV1`] for state or evidence substitution.
pub fn reconcile<R: ReconcileEvidenceV1>(
    machine: &mut ExactOccurrenceMachineV1,
    evidence: &mut R,
) -> Result<BoundaryResultV1, BoundaryErrorV1> {
    match machine.state {
        OccurrenceStateV1::Terminal { .. } => return Ok(BoundaryResultV1::ReplayedTerminal),
        OccurrenceStateV1::Prepared | OccurrenceStateV1::Authorized { .. } => {
            return Err(BoundaryErrorV1::Occurrence(
                OccurrenceError::InvalidTransition {
                    state: machine.state.label(),
                    requested: "reconcile",
                },
            ));
        }
        OccurrenceStateV1::Claimed { .. }
        | OccurrenceStateV1::Executing { .. }
        | OccurrenceStateV1::OutcomeUnknown { .. } => {}
    }

    let request = request_from_machine(machine)?;
    let observation = evidence.observe(&request);
    let mut candidate = machine.clone();
    let result = match observation {
        ReconciliationObservationV1::Definite(terminal) => {
            let effect = match candidate.state {
                OccurrenceStateV1::OutcomeUnknown { .. } => {
                    candidate.settle_outcome_unknown(terminal)?
                }
                _ => candidate.finish(terminal)?,
            };
            BoundaryResultV1::Terminal(effect)
        }
        ReconciliationObservationV1::OutcomeUnknown(unknown) => {
            let effect = candidate.mark_outcome_unknown(unknown)?;
            BoundaryResultV1::OutcomeUnknown(effect)
        }
    };
    *machine = candidate;
    Ok(result)
}

fn request_from_machine(
    machine: &ExactOccurrenceMachineV1,
) -> Result<ExecutionRequestV1, OccurrenceError> {
    let (authorization, claim, runtime) = match &machine.state {
        OccurrenceStateV1::Claimed {
            authorization,
            claim,
        } => (authorization, claim, None),
        OccurrenceStateV1::Executing {
            authorization,
            claim,
            runtime,
        } => (authorization, claim, Some(runtime.clone())),
        OccurrenceStateV1::OutcomeUnknown {
            authorization,
            claim,
            runtime,
            ..
        } => (authorization, claim, runtime.clone()),
        _ => {
            return Err(OccurrenceError::InvalidTransition {
                state: machine.state.label(),
                requested: "build_execution_request",
            });
        }
    };
    Ok(ExecutionRequestV1 {
        plan_id: machine.prepared.plan_id.clone(),
        nq_occurrence: machine.prepared.plan.nq.occurrence_id.clone(),
        authorization: authorization.clone(),
        claim: claim.clone(),
        runtime,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        ArtifactBindingV1, CAMPAIGN_NAME, CAMPAIGN_SLUG, CardinalityBindingV1,
        CoordinationBindingV1, EXECUTOR_WORK_SCHEMA_V1, EvidenceBindingV1, LifetimeBindingV1,
        NqAuthorityBindingV1, OriginCapacityBindingV1, PREPARED_PLAN_SCHEMA_V1,
        PreparedOccurrencePlanV1, PreparedOccurrenceV1,
    };

    fn digest(label: &str) -> Sha256Digest {
        nq_protocol::sha256_bytes(label.as_bytes())
    }

    fn prepared() -> PreparedOccurrenceV1 {
        PreparedOccurrenceV1::new(PreparedOccurrencePlanV1 {
            schema: PREPARED_PLAN_SCHEMA_V1.to_owned(),
            campaign: CAMPAIGN_NAME.to_owned(),
            campaign_slug: CAMPAIGN_SLUG.to_owned(),
            work_schema: EXECUTOR_WORK_SCHEMA_V1.to_owned(),
            nq: NqAuthorityBindingV1 {
                occurrence_id: digest("occurrence"),
                h_grant_id: "turnstile-h".into(),
                g_grant_id: "turnstile-g".into(),
                e_grant_id: "turnstile-e".into(),
                watcher_id: "turnstile-watcher".into(),
                admission_id: "turnstile-admission".into(),
                enrollment_id: digest("enrollment"),
                succession_relation_id: None,
                recurrence_slot: 1,
                selected_sample_id: digest("sample"),
                selected_sample_digest: digest("sample-doc"),
            },
            artifact: ArtifactBindingV1 {
                source_commit: "675e247e85d8e2e1f2801c06445bf863f82b3a5b".into(),
                oci_manifest_digest: digest("oci"),
                nq_executable_digest: digest("nq"),
                passive_helper_digest: digest("helper"),
                configuration_digests: BTreeMap::from([("nq.toml".into(), digest("config"))]),
            },
            origin_capacity: OriginCapacityBindingV1 {
                origin_profile: "nq.kubernetes.pod-origin/v1".into(),
                subject: digest("subject"),
                scope: digest("scope"),
                vantage: digest("vantage"),
                cluster: digest("cluster"),
                namespace_uid: digest("namespace"),
                service_account_uid: digest("service-account"),
                placement_digest: digest("placement"),
                resource_envelope_digest: digest("resources"),
                capacity_context_digest: digest("capacity"),
            },
            coordination: CoordinationBindingV1 {
                domain_id: "turnstile:test".into(),
                fencing_epoch: 1,
                provider_safe_spacing_ms: 100,
            },
            evidence: EvidenceBindingV1 {
                canonical_custody_id: digest("custody"),
                selection_contract_digest: digest("selection"),
                external_journal_id: digest("journal"),
                receipt_destination_id: digest("receipts"),
                required_free_bytes: 1024,
                retention_mode: "retain_all".into(),
            },
            lifetime: LifetimeBindingV1 {
                not_before_unix_ms: 100,
                expires_at_unix_ms: 1_000,
                max_runtime_ms: 500,
            },
            cardinality: CardinalityBindingV1 {
                max_authorizations: 1,
                max_docket_attempts: 1,
                max_runtime_instances: 1,
                max_terminal_results: 1,
            },
        })
        .unwrap()
    }

    fn claimed_machine() -> ExactOccurrenceMachineV1 {
        let prepared = prepared();
        let auth = AuthorizationBindingV1 {
            ag_campaign: digest("ag-campaign"),
            ag_occurrence: digest("ag-occurrence"),
            ag_issuance: digest("issuance"),
            ag_work: prepared.plan_id.clone(),
            docket_attempt: digest("attempt"),
            docket_marker: digest("marker"),
            work_schema: EXECUTOR_WORK_SCHEMA_V1.into(),
            subject: prepared.plan.origin_capacity.subject.clone(),
            scope: prepared.plan.origin_capacity.scope.clone(),
            authorized_at_unix_ms: 200,
        };
        let claim = ClaimBindingV1 {
            claim_id: digest("claim"),
            nq_occurrence: prepared.plan.nq.occurrence_id.clone(),
            plan_id: prepared.plan_id.clone(),
            docket_attempt: auth.docket_attempt.clone(),
            docket_marker: auth.docket_marker.clone(),
            fencing_epoch: 1,
            selected_sample_id: prepared.plan.nq.selected_sample_id.clone(),
            claimed_at_unix_ms: 300,
        };
        let mut machine = ExactOccurrenceMachineV1::prepare(prepared).unwrap();
        machine.authorize(auth).unwrap();
        machine.claim(claim).unwrap();
        machine
    }

    fn runtime(machine: &ExactOccurrenceMachineV1) -> RuntimeBindingV1 {
        RuntimeBindingV1 {
            runtime_instance_id: digest("runtime"),
            oci_manifest_digest: machine.prepared.plan.artifact.oci_manifest_digest.clone(),
            plan_id: machine.prepared.plan_id.clone(),
            started_at_unix_ms: 400,
        }
    }

    fn success() -> TerminalBindingV1 {
        TerminalBindingV1 {
            class: TerminalClassV1::Success,
            receipt: digest("receipt"),
            evidence_head: digest("head"),
            terminal_at_unix_ms: 500,
        }
    }

    fn unknown() -> OutcomeUnknownBindingV1 {
        OutcomeUnknownBindingV1 {
            evidence: digest("uncertainty"),
            evidence_head: digest("unknown-head"),
            terminal_at_unix_ms: 500,
        }
    }

    struct CountingMechanics {
        calls: usize,
        result: Result<MechanicsCompletionV1, Box<MechanicsFailureV1>>,
    }

    impl ExecuteMechanicsV1 for CountingMechanics {
        fn execute(
            &mut self,
            _request: &ExecutionRequestV1,
        ) -> Result<MechanicsCompletionV1, Box<MechanicsFailureV1>> {
            self.calls += 1;
            self.result.clone()
        }
    }

    struct CountingEvidence {
        calls: usize,
        observation: ReconciliationObservationV1,
    }

    impl ReconcileEvidenceV1 for CountingEvidence {
        fn observe(&mut self, _request: &ExecutionRequestV1) -> ReconciliationObservationV1 {
            self.calls += 1;
            self.observation.clone()
        }
    }

    #[test]
    fn exact_execute_runs_once_and_terminal_replay_runs_zero_more_mechanics() {
        let mut machine = claimed_machine();
        let mut mechanics = CountingMechanics {
            calls: 0,
            result: Ok(MechanicsCompletionV1 {
                runtime: runtime(&machine),
                terminal: success(),
            }),
        };
        assert!(matches!(
            execute_once(&mut machine, &mut mechanics),
            Ok(BoundaryResultV1::Terminal(_))
        ));
        assert_eq!(mechanics.calls, 1);
        assert_eq!(
            execute_once(&mut machine, &mut mechanics).unwrap(),
            BoundaryResultV1::ReplayedTerminal
        );
        assert_eq!(mechanics.calls, 1);
    }

    #[test]
    fn result_loss_is_outcome_unknown_and_duplicate_execute_is_inert() {
        let mut machine = claimed_machine();
        let mut mechanics = CountingMechanics {
            calls: 0,
            result: Err(Box::new(MechanicsFailureV1::OutcomeUnknown {
                runtime: Some(runtime(&machine)),
                unknown: unknown(),
            })),
        };
        assert!(matches!(
            execute_once(&mut machine, &mut mechanics),
            Ok(BoundaryResultV1::OutcomeUnknown(_))
        ));
        assert_eq!(mechanics.calls, 1);
        assert_eq!(
            execute_once(&mut machine, &mut mechanics).unwrap(),
            BoundaryResultV1::ReplayedOutcomeUnknown
        );
        assert_eq!(mechanics.calls, 1);
    }

    #[test]
    fn executing_restart_requires_reconcile_and_never_reexecutes() {
        let mut machine = claimed_machine();
        machine.begin_execution(runtime(&machine)).unwrap();
        let mut mechanics = CountingMechanics {
            calls: 0,
            result: Ok(MechanicsCompletionV1 {
                runtime: runtime(&machine),
                terminal: success(),
            }),
        };
        assert_eq!(
            execute_once(&mut machine, &mut mechanics),
            Err(BoundaryErrorV1::ReconciliationRequired)
        );
        assert_eq!(mechanics.calls, 0);
        let mut evidence = CountingEvidence {
            calls: 0,
            observation: ReconciliationObservationV1::Definite(success()),
        };
        assert!(matches!(
            reconcile(&mut machine, &mut evidence),
            Ok(BoundaryResultV1::Terminal(_))
        ));
        assert_eq!(evidence.calls, 1);
        assert_eq!(mechanics.calls, 0);
    }

    #[test]
    fn later_read_only_evidence_can_settle_unknown_without_new_runtime() {
        let mut machine = claimed_machine();
        let exact_runtime = runtime(&machine);
        machine.begin_execution(exact_runtime).unwrap();
        machine.mark_outcome_unknown(unknown()).unwrap();
        let mut evidence = CountingEvidence {
            calls: 0,
            observation: ReconciliationObservationV1::Definite(success()),
        };
        assert!(matches!(
            reconcile(&mut machine, &mut evidence),
            Ok(BoundaryResultV1::Terminal(_))
        ));
        assert_eq!(machine.state.label(), "terminal");
        assert_eq!(evidence.calls, 1);
    }

    #[test]
    fn substituted_completion_is_atomic_and_preserves_claimed_state() {
        let mut machine = claimed_machine();
        let before = machine.clone();
        let mut wrong = runtime(&machine);
        wrong.plan_id = digest("wrong-plan");
        let mut mechanics = CountingMechanics {
            calls: 0,
            result: Ok(MechanicsCompletionV1 {
                runtime: wrong,
                terminal: success(),
            }),
        };
        assert!(matches!(
            execute_once(&mut machine, &mut mechanics),
            Err(BoundaryErrorV1::Occurrence(
                OccurrenceError::ReplayConflict("runtime binding")
            ))
        ));
        assert_eq!(machine, before);
        assert_eq!(mechanics.calls, 1);
    }

    #[test]
    fn terminal_reconcile_projects_without_calling_evidence_reader() {
        let mut machine = claimed_machine();
        machine.begin_execution(runtime(&machine)).unwrap();
        machine.finish(success()).unwrap();
        let mut evidence = CountingEvidence {
            calls: 0,
            observation: ReconciliationObservationV1::OutcomeUnknown(unknown()),
        };
        assert_eq!(
            reconcile(&mut machine, &mut evidence).unwrap(),
            BoundaryResultV1::ReplayedTerminal
        );
        assert_eq!(evidence.calls, 0);
    }
}
