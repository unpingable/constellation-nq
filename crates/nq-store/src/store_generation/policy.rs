//! Closed C2 install-policy and active-policy records.
//!
//! These types retain the exact authenticated coordinates used by Store-owned
//! verifiers.  They expose neither a generic policy bag nor a conversion to a
//! writer session.  Complete active-policy resolution walks predecessor links
//! and refuses malformed material instead of filtering or tie-breaking it.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Closed C2 installation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C2InstallPolicyModeV1 {
    Fresh,
    RestoreSuccessor,
}

/// Complete immutable install-policy field corpus.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct C2StoreGenerationInstallPolicyV1 {
    schema: String,
    schema_version: u8,
    install_policy_identity: Sha256Digest,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    signer_lifecycle_root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    resident_identity: Sha256Digest,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    authority_domain: String,
    signer_scope_policy_identity: Sha256Digest,
    signer_scope_policy_version: u64,
    gen4_root_identity: Sha256Digest,
    gen4_initial_tip_identity: Sha256Digest,
    selected_enrollment_identity: Sha256Digest,
    installation_nonce: String,
    installation_mode: C2InstallPolicyModeV1,
    layout_identity: Sha256Digest,
    lock_domain_identity: Sha256Digest,
    b_payload_bound: u32,
    g_payload_bound: u32,
    key_generation_maximum: u32,
    policy_generation_maximum: u32,
    qualified_backend_profile_identity: Sha256Digest,
    backend_implementation_manifest_identity: Sha256Digest,
    predecessor_policy_identity: Option<Sha256Digest>,
    predecessor_physical_store_generation_identity: Option<Sha256Digest>,
    predecessor_bootstrap_identity: Option<Sha256Digest>,
    predecessor_installation_receipt_identity: Option<Sha256Digest>,
    predecessor_installation_cut: Option<u64>,
    restore_disposition_identity: Option<Sha256Digest>,
    restore_proof_identity: Option<Sha256Digest>,
    installation_cut: u64,
}

/// Explicit constructor input; the identity is always derived internally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2StoreGenerationInstallPolicyInputV1 {
    pub occurrence_id: String,
    pub physical_store_generation_identity: Sha256Digest,
    pub signer_lifecycle_root_identity: Sha256Digest,
    pub scope_identity: Sha256Digest,
    pub resident_identity: Sha256Digest,
    pub resident_generation: u64,
    pub host_role: String,
    pub role_manifest_generation: u64,
    pub authority_domain: String,
    pub signer_scope_policy_identity: Sha256Digest,
    pub signer_scope_policy_version: u64,
    pub gen4_root_identity: Sha256Digest,
    pub gen4_initial_tip_identity: Sha256Digest,
    pub selected_enrollment_identity: Sha256Digest,
    pub installation_nonce: String,
    pub installation_mode: C2InstallPolicyModeV1,
    pub layout_identity: Sha256Digest,
    pub lock_domain_identity: Sha256Digest,
    pub b_payload_bound: u32,
    pub g_payload_bound: u32,
    pub key_generation_maximum: u32,
    pub policy_generation_maximum: u32,
    pub qualified_backend_profile_identity: Sha256Digest,
    pub backend_implementation_manifest_identity: Sha256Digest,
    pub predecessor_policy_identity: Option<Sha256Digest>,
    pub predecessor_physical_store_generation_identity: Option<Sha256Digest>,
    pub predecessor_bootstrap_identity: Option<Sha256Digest>,
    pub predecessor_installation_receipt_identity: Option<Sha256Digest>,
    pub predecessor_installation_cut: Option<u64>,
    pub restore_disposition_identity: Option<Sha256Digest>,
    pub restore_proof_identity: Option<Sha256Digest>,
    pub installation_cut: u64,
}

/// Exact, checked B-size model used by N-24.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalBSizeModelV1 {
    pub fixed_bytes: u64,
    pub per_key_generation_bytes: u64,
    pub per_policy_generation_bytes: u64,
    pub final_alignment_bytes: u64,
}

/// Append-only active C2 policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct C2ActiveStorePolicyV1 {
    schema: String,
    schema_version: u8,
    active_store_policy_identity: Sha256Digest,
    active_store_policy_generation: u64,
    predecessor_active_store_policy_identity: Option<Sha256Digest>,
    activation_predecessor_identity: Sha256Digest,
    activation_successor_identity: Sha256Digest,
    selected_enrollment_identity: Sha256Digest,
    anchor_signature_identity: Sha256Digest,
    old_key_countersignature_identity: Option<Sha256Digest>,
    new_key_possession_signature_identity: Option<Sha256Digest>,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    signer_lifecycle_root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    resident_identity: Sha256Digest,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    authority_domain: String,
    signer_scope_policy_identity: Sha256Digest,
    signer_scope_policy_version: u64,
    generation_lock_identity: Sha256Digest,
    b_root_identity: Sha256Digest,
    g_root_identity: Sha256Digest,
    layout_identity: Sha256Digest,
    backend_profile_identity: Sha256Digest,
    implementation_manifest_identity: Sha256Digest,
    installation_mode: C2InstallPolicyModeV1,
    restore_authorization_identity: Option<Sha256Digest>,
    key_generation_maximum: u32,
    policy_generation_maximum: u32,
    g_entry_maximum: u32,
    policy_cut: u64,
}

/// Explicit active-policy constructor input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2ActiveStorePolicyInputV1 {
    pub active_store_policy_generation: u64,
    pub predecessor_active_store_policy_identity: Option<Sha256Digest>,
    pub activation_predecessor_identity: Sha256Digest,
    pub activation_successor_identity: Sha256Digest,
    pub selected_enrollment_identity: Sha256Digest,
    pub anchor_signature_identity: Sha256Digest,
    pub old_key_countersignature_identity: Option<Sha256Digest>,
    pub new_key_possession_signature_identity: Option<Sha256Digest>,
    pub occurrence_id: String,
    pub physical_store_generation_identity: Sha256Digest,
    pub signer_lifecycle_root_identity: Sha256Digest,
    pub scope_identity: Sha256Digest,
    pub resident_identity: Sha256Digest,
    pub resident_generation: u64,
    pub host_role: String,
    pub role_manifest_generation: u64,
    pub authority_domain: String,
    pub signer_scope_policy_identity: Sha256Digest,
    pub signer_scope_policy_version: u64,
    pub generation_lock_identity: Sha256Digest,
    pub b_root_identity: Sha256Digest,
    pub g_root_identity: Sha256Digest,
    pub layout_identity: Sha256Digest,
    pub backend_profile_identity: Sha256Digest,
    pub implementation_manifest_identity: Sha256Digest,
    pub installation_mode: C2InstallPolicyModeV1,
    pub restore_authorization_identity: Option<Sha256Digest>,
    pub key_generation_maximum: u32,
    pub policy_generation_maximum: u32,
    pub g_entry_maximum: u32,
    pub policy_cut: u64,
}

/// One complete active-policy chain and its structurally derived terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteActivePolicyResolutionV1 {
    initial_policy_identity: Sha256Digest,
    terminal_policy_identity: Sha256Digest,
    policies: Vec<C2ActiveStorePolicyV1>,
}

/// Exact pre-effect binding for P-04/N-39.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2PolicyTransitionPredecessorV1 {
    old_policy_identity: Sha256Digest,
    proposed_policy_identity: Sha256Digest,
    transition_intent_identity: Sha256Digest,
    lock_identity: Sha256Digest,
    profile_identity: Sha256Digest,
}

/// Private policy-transition brand.  It has no ordinary mutation methods.
#[derive(Debug)]
pub struct C2PolicyTransitionBrandV1(C2PolicyTransitionPredecessorV1);

/// Admissible, exact partial policy frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2PolicyPartialFrontierV1 {
    IntentDurable,
    AuthoritySuccessorDurable,
    PolicySuffixDurable,
}

/// Private exact-intent continuation brand.
#[derive(Debug)]
pub struct C2PolicyTransitionContinuationBrandV1 {
    transition_intent_identity: Sha256Digest,
    exact_prefix_identity: Sha256Digest,
    frontier: C2PolicyPartialFrontierV1,
}

/// Evidence that transition and continuation brands cannot substitute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2PolicyTransitionModeDisjointnessV1;

/// Typed no-write policy refusal.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PolicyRefusalV1 {
    #[error("a required policy coordinate is empty")]
    EmptyCoordinate,
    #[error("a policy cut or generation is outside the exact range")]
    UnsafeInteger,
    #[error("the closed fresh/restore mode union is malformed")]
    InstallationModeMismatch,
    #[error("restore predecessor correspondence is absent, partial, or not later")]
    RestorePredecessorMismatch,
    #[error("installed maxima or canonical B arithmetic is invalid")]
    InstalledMaximumMismatch,
    #[error("the asserted policy identity differs from its canonical preimage")]
    IdentityMismatch,
    #[error("an active policy changes its immutable Store tuple")]
    ImmutableTupleMismatch,
    #[error("the active-policy predecessor relation has a gap, fork, or cycle")]
    PolicyChainMalformed,
    #[error("a policy candidate is duplicated")]
    DuplicatePolicy,
    #[error("the active-policy candidate set is incomplete")]
    IncompleteCandidateSet,
    #[error("zero or multiple policies are current")]
    CurrentPolicyCardinality,
    #[error("the resolved policy does not match the exact current activation")]
    ActivationPolicyMismatch,
    #[error("anchor, continuity, and proof-of-possession signatures were substituted")]
    SignatureRoleMismatch,
    #[error("the transition does not consume the exact current policy")]
    TransitionPredecessorMismatch,
    #[error("the transition profile or retained-lock evidence is substituted")]
    TransitionCorrespondenceMismatch,
    #[error("the continuation prefix or historical intent is not exact")]
    ContinuationFrontierMismatch,
    #[error("canonical identity derivation failed")]
    Canonicalization,
}

#[derive(Serialize)]
struct InstallPolicyPreimage<'a> {
    schema: &'static str,
    input: &'a C2StoreGenerationInstallPolicyInputV1,
}

#[derive(Serialize)]
struct ActivePolicyPreimage<'a> {
    schema: &'static str,
    input: &'a C2ActiveStorePolicyInputV1,
}

impl Serialize for C2StoreGenerationInstallPolicyInputV1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Repr<'a> {
            occurrence_id: &'a str,
            physical_store_generation_identity: &'a Sha256Digest,
            signer_lifecycle_root_identity: &'a Sha256Digest,
            scope_identity: &'a Sha256Digest,
            resident_identity: &'a Sha256Digest,
            resident_generation: u64,
            host_role: &'a str,
            role_manifest_generation: u64,
            authority_domain: &'a str,
            signer_scope_policy_identity: &'a Sha256Digest,
            signer_scope_policy_version: u64,
            gen4_root_identity: &'a Sha256Digest,
            gen4_initial_tip_identity: &'a Sha256Digest,
            selected_enrollment_identity: &'a Sha256Digest,
            installation_nonce: &'a str,
            installation_mode: C2InstallPolicyModeV1,
            layout_identity: &'a Sha256Digest,
            lock_domain_identity: &'a Sha256Digest,
            b_payload_bound: u32,
            g_payload_bound: u32,
            key_generation_maximum: u32,
            policy_generation_maximum: u32,
            qualified_backend_profile_identity: &'a Sha256Digest,
            backend_implementation_manifest_identity: &'a Sha256Digest,
            predecessor_policy_identity: &'a Option<Sha256Digest>,
            predecessor_physical_store_generation_identity: &'a Option<Sha256Digest>,
            predecessor_bootstrap_identity: &'a Option<Sha256Digest>,
            predecessor_installation_receipt_identity: &'a Option<Sha256Digest>,
            predecessor_installation_cut: Option<u64>,
            restore_disposition_identity: &'a Option<Sha256Digest>,
            restore_proof_identity: &'a Option<Sha256Digest>,
            installation_cut: u64,
        }
        Repr {
            occurrence_id: &self.occurrence_id,
            physical_store_generation_identity: &self.physical_store_generation_identity,
            signer_lifecycle_root_identity: &self.signer_lifecycle_root_identity,
            scope_identity: &self.scope_identity,
            resident_identity: &self.resident_identity,
            resident_generation: self.resident_generation,
            host_role: &self.host_role,
            role_manifest_generation: self.role_manifest_generation,
            authority_domain: &self.authority_domain,
            signer_scope_policy_identity: &self.signer_scope_policy_identity,
            signer_scope_policy_version: self.signer_scope_policy_version,
            gen4_root_identity: &self.gen4_root_identity,
            gen4_initial_tip_identity: &self.gen4_initial_tip_identity,
            selected_enrollment_identity: &self.selected_enrollment_identity,
            installation_nonce: &self.installation_nonce,
            installation_mode: self.installation_mode,
            layout_identity: &self.layout_identity,
            lock_domain_identity: &self.lock_domain_identity,
            b_payload_bound: self.b_payload_bound,
            g_payload_bound: self.g_payload_bound,
            key_generation_maximum: self.key_generation_maximum,
            policy_generation_maximum: self.policy_generation_maximum,
            qualified_backend_profile_identity: &self.qualified_backend_profile_identity,
            backend_implementation_manifest_identity: &self
                .backend_implementation_manifest_identity,
            predecessor_policy_identity: &self.predecessor_policy_identity,
            predecessor_physical_store_generation_identity: &self
                .predecessor_physical_store_generation_identity,
            predecessor_bootstrap_identity: &self.predecessor_bootstrap_identity,
            predecessor_installation_receipt_identity: &self
                .predecessor_installation_receipt_identity,
            predecessor_installation_cut: self.predecessor_installation_cut,
            restore_disposition_identity: &self.restore_disposition_identity,
            restore_proof_identity: &self.restore_proof_identity,
            installation_cut: self.installation_cut,
        }
        .serialize(serializer)
    }
}

impl Serialize for C2ActiveStorePolicyInputV1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Repr<'a> {
            generation: u64,
            predecessor: &'a Option<Sha256Digest>,
            activation_predecessor: &'a Sha256Digest,
            activation_successor: &'a Sha256Digest,
            selected_enrollment: &'a Sha256Digest,
            anchor_signature: &'a Sha256Digest,
            old_key_countersignature: &'a Option<Sha256Digest>,
            new_key_possession_signature: &'a Option<Sha256Digest>,
            occurrence_id: &'a str,
            physical_generation: &'a Sha256Digest,
            lifecycle_root: &'a Sha256Digest,
            scope: &'a Sha256Digest,
            resident: &'a Sha256Digest,
            resident_generation: u64,
            host_role: &'a str,
            role_manifest_generation: u64,
            authority_domain: &'a str,
            scope_policy: &'a Sha256Digest,
            scope_policy_version: u64,
            generation_lock: &'a Sha256Digest,
            b_root: &'a Sha256Digest,
            g_root: &'a Sha256Digest,
            layout: &'a Sha256Digest,
            backend_profile: &'a Sha256Digest,
            implementation_manifest: &'a Sha256Digest,
            installation_mode: C2InstallPolicyModeV1,
            restore_authorization: &'a Option<Sha256Digest>,
            key_generation_maximum: u32,
            policy_generation_maximum: u32,
            g_entry_maximum: u32,
            policy_cut: u64,
        }
        Repr {
            generation: self.active_store_policy_generation,
            predecessor: &self.predecessor_active_store_policy_identity,
            activation_predecessor: &self.activation_predecessor_identity,
            activation_successor: &self.activation_successor_identity,
            selected_enrollment: &self.selected_enrollment_identity,
            anchor_signature: &self.anchor_signature_identity,
            old_key_countersignature: &self.old_key_countersignature_identity,
            new_key_possession_signature: &self.new_key_possession_signature_identity,
            occurrence_id: &self.occurrence_id,
            physical_generation: &self.physical_store_generation_identity,
            lifecycle_root: &self.signer_lifecycle_root_identity,
            scope: &self.scope_identity,
            resident: &self.resident_identity,
            resident_generation: self.resident_generation,
            host_role: &self.host_role,
            role_manifest_generation: self.role_manifest_generation,
            authority_domain: &self.authority_domain,
            scope_policy: &self.signer_scope_policy_identity,
            scope_policy_version: self.signer_scope_policy_version,
            generation_lock: &self.generation_lock_identity,
            b_root: &self.b_root_identity,
            g_root: &self.g_root_identity,
            layout: &self.layout_identity,
            backend_profile: &self.backend_profile_identity,
            implementation_manifest: &self.implementation_manifest_identity,
            installation_mode: self.installation_mode,
            restore_authorization: &self.restore_authorization_identity,
            key_generation_maximum: self.key_generation_maximum,
            policy_generation_maximum: self.policy_generation_maximum,
            g_entry_maximum: self.g_entry_maximum,
            policy_cut: self.policy_cut,
        }
        .serialize(serializer)
    }
}

fn require_policy_strings(values: &[&str]) -> Result<(), PolicyRefusalV1> {
    if values.iter().any(|value| value.is_empty()) {
        Err(PolicyRefusalV1::EmptyCoordinate)
    } else {
        Ok(())
    }
}

fn verify_install_mode(
    input: &C2StoreGenerationInstallPolicyInputV1,
) -> Result<(), PolicyRefusalV1> {
    let tuple_presence = [
        input
            .predecessor_physical_store_generation_identity
            .is_some(),
        input.predecessor_bootstrap_identity.is_some(),
        input.predecessor_installation_receipt_identity.is_some(),
        input.predecessor_installation_cut.is_some(),
        input.restore_disposition_identity.is_some(),
        input.restore_proof_identity.is_some(),
    ];
    match input.installation_mode {
        C2InstallPolicyModeV1::Fresh if tuple_presence.iter().all(|present| !present) => Ok(()),
        C2InstallPolicyModeV1::RestoreSuccessor
            if tuple_presence.iter().all(|present| *present)
                && input
                    .predecessor_installation_cut
                    .is_some_and(|cut| cut < input.installation_cut) =>
        {
            Ok(())
        }
        C2InstallPolicyModeV1::Fresh => Err(PolicyRefusalV1::InstallationModeMismatch),
        C2InstallPolicyModeV1::RestoreSuccessor => Err(PolicyRefusalV1::RestorePredecessorMismatch),
    }
}

/// N-22 constructs the exact closed install-policy corpus.
pub(crate) fn construct_n_22_install_policy_binds_complete_gen4_tuple_enrollment(
    input: C2StoreGenerationInstallPolicyInputV1,
) -> Result<C2StoreGenerationInstallPolicyV1, PolicyRefusalV1> {
    require_policy_strings(&[
        &input.occurrence_id,
        &input.host_role,
        &input.authority_domain,
        &input.installation_nonce,
    ])?;
    if input.resident_generation == 0
        || input.role_manifest_generation == 0
        || input.signer_scope_policy_version == 0
        || input.installation_cut == 0
        || input.installation_cut > MAX_IJSON_INTEGER
        || input.b_payload_bound == 0
        || input.g_payload_bound == 0
        || input.key_generation_maximum == 0
        || input.policy_generation_maximum == 0
        || input.key_generation_maximum > input.policy_generation_maximum
    {
        return Err(PolicyRefusalV1::UnsafeInteger);
    }
    verify_install_mode(&input)?;
    let install_policy_identity = semantic_digest(&InstallPolicyPreimage {
        schema: "nq.c2.store_generation_install_policy.identity.v1",
        input: &input,
    })
    .map_err(|_| PolicyRefusalV1::Canonicalization)?;
    Ok(C2StoreGenerationInstallPolicyV1 {
        schema: "nq.c2_store_generation_install_policy.v1".into(),
        schema_version: 1,
        install_policy_identity,
        occurrence_id: input.occurrence_id,
        physical_store_generation_identity: input.physical_store_generation_identity,
        signer_lifecycle_root_identity: input.signer_lifecycle_root_identity,
        scope_identity: input.scope_identity,
        resident_identity: input.resident_identity,
        resident_generation: input.resident_generation,
        host_role: input.host_role,
        role_manifest_generation: input.role_manifest_generation,
        authority_domain: input.authority_domain,
        signer_scope_policy_identity: input.signer_scope_policy_identity,
        signer_scope_policy_version: input.signer_scope_policy_version,
        gen4_root_identity: input.gen4_root_identity,
        gen4_initial_tip_identity: input.gen4_initial_tip_identity,
        selected_enrollment_identity: input.selected_enrollment_identity,
        installation_nonce: input.installation_nonce,
        installation_mode: input.installation_mode,
        layout_identity: input.layout_identity,
        lock_domain_identity: input.lock_domain_identity,
        b_payload_bound: input.b_payload_bound,
        g_payload_bound: input.g_payload_bound,
        key_generation_maximum: input.key_generation_maximum,
        policy_generation_maximum: input.policy_generation_maximum,
        qualified_backend_profile_identity: input.qualified_backend_profile_identity,
        backend_implementation_manifest_identity: input.backend_implementation_manifest_identity,
        predecessor_policy_identity: input.predecessor_policy_identity,
        predecessor_physical_store_generation_identity: input
            .predecessor_physical_store_generation_identity,
        predecessor_bootstrap_identity: input.predecessor_bootstrap_identity,
        predecessor_installation_receipt_identity: input.predecessor_installation_receipt_identity,
        predecessor_installation_cut: input.predecessor_installation_cut,
        restore_disposition_identity: input.restore_disposition_identity,
        restore_proof_identity: input.restore_proof_identity,
        installation_cut: input.installation_cut,
    })
}

fn install_policy_input(
    value: &C2StoreGenerationInstallPolicyV1,
) -> C2StoreGenerationInstallPolicyInputV1 {
    C2StoreGenerationInstallPolicyInputV1 {
        occurrence_id: value.occurrence_id.clone(),
        physical_store_generation_identity: value.physical_store_generation_identity.clone(),
        signer_lifecycle_root_identity: value.signer_lifecycle_root_identity.clone(),
        scope_identity: value.scope_identity.clone(),
        resident_identity: value.resident_identity.clone(),
        resident_generation: value.resident_generation,
        host_role: value.host_role.clone(),
        role_manifest_generation: value.role_manifest_generation,
        authority_domain: value.authority_domain.clone(),
        signer_scope_policy_identity: value.signer_scope_policy_identity.clone(),
        signer_scope_policy_version: value.signer_scope_policy_version,
        gen4_root_identity: value.gen4_root_identity.clone(),
        gen4_initial_tip_identity: value.gen4_initial_tip_identity.clone(),
        selected_enrollment_identity: value.selected_enrollment_identity.clone(),
        installation_nonce: value.installation_nonce.clone(),
        installation_mode: value.installation_mode,
        layout_identity: value.layout_identity.clone(),
        lock_domain_identity: value.lock_domain_identity.clone(),
        b_payload_bound: value.b_payload_bound,
        g_payload_bound: value.g_payload_bound,
        key_generation_maximum: value.key_generation_maximum,
        policy_generation_maximum: value.policy_generation_maximum,
        qualified_backend_profile_identity: value.qualified_backend_profile_identity.clone(),
        backend_implementation_manifest_identity: value
            .backend_implementation_manifest_identity
            .clone(),
        predecessor_policy_identity: value.predecessor_policy_identity.clone(),
        predecessor_physical_store_generation_identity: value
            .predecessor_physical_store_generation_identity
            .clone(),
        predecessor_bootstrap_identity: value.predecessor_bootstrap_identity.clone(),
        predecessor_installation_receipt_identity: value
            .predecessor_installation_receipt_identity
            .clone(),
        predecessor_installation_cut: value.predecessor_installation_cut,
        restore_disposition_identity: value.restore_disposition_identity.clone(),
        restore_proof_identity: value.restore_proof_identity.clone(),
        installation_cut: value.installation_cut,
    }
}

/// N-22 verifies canonical identity and the complete closed tuple.
pub fn verify_n_22_install_policy_binds_complete_gen4_tuple_enrollment(
    value: &C2StoreGenerationInstallPolicyV1,
) -> Result<(), PolicyRefusalV1> {
    let expected = construct_n_22_install_policy_binds_complete_gen4_tuple_enrollment(
        install_policy_input(value),
    )?;
    if value.schema == "nq.c2_store_generation_install_policy.v1"
        && value.schema_version == 1
        && expected.install_policy_identity == value.install_policy_identity
    {
        Ok(())
    } else {
        Err(PolicyRefusalV1::IdentityMismatch)
    }
}

/// N-23 requires the exact complete restore tuple and strictly later cut.
pub fn verify_n_23_restore_mode_additionally_binds_predecessor_generation_bootstrap(
    value: &C2StoreGenerationInstallPolicyV1,
) -> Result<(), PolicyRefusalV1> {
    if value.installation_mode != C2InstallPolicyModeV1::RestoreSuccessor {
        return Err(PolicyRefusalV1::RestorePredecessorMismatch);
    }
    verify_install_mode(&install_policy_input(value))
}

/// N-23 uses the same canonical constructor after exact mode verification.
pub(crate) fn construct_n_23_restore_mode_additionally_binds_predecessor_generation_bootstrap(
    input: C2StoreGenerationInstallPolicyInputV1,
) -> Result<C2StoreGenerationInstallPolicyV1, PolicyRefusalV1> {
    if input.installation_mode != C2InstallPolicyModeV1::RestoreSuccessor {
        return Err(PolicyRefusalV1::RestorePredecessorMismatch);
    }
    construct_n_22_install_policy_binds_complete_gen4_tuple_enrollment(input)
}

/// N-24 performs checked worst-case B arithmetic.
pub fn verify_n_24_installed_positive_u32_maxima_fit_worst_case(
    value: &C2StoreGenerationInstallPolicyV1,
    model: CanonicalBSizeModelV1,
) -> Result<(), PolicyRefusalV1> {
    let key_bytes = model
        .per_key_generation_bytes
        .checked_mul(u64::from(value.key_generation_maximum))
        .ok_or(PolicyRefusalV1::InstalledMaximumMismatch)?;
    let policy_bytes = model
        .per_policy_generation_bytes
        .checked_mul(u64::from(value.policy_generation_maximum))
        .ok_or(PolicyRefusalV1::InstalledMaximumMismatch)?;
    let required = model
        .fixed_bytes
        .checked_add(key_bytes)
        .and_then(|sum| sum.checked_add(policy_bytes))
        .and_then(|sum| sum.checked_add(model.final_alignment_bytes))
        .ok_or(PolicyRefusalV1::InstalledMaximumMismatch)?;
    if value.key_generation_maximum > 0
        && value.key_generation_maximum <= value.policy_generation_maximum
        && required <= u64::from(value.b_payload_bound)
    {
        Ok(())
    } else {
        Err(PolicyRefusalV1::InstalledMaximumMismatch)
    }
}

/// Matrix constructor alias for N-24; it validates and returns the policy.
pub(crate) fn construct_n_24_installed_positive_u32_maxima_fit_worst_case(
    value: C2StoreGenerationInstallPolicyV1,
    model: CanonicalBSizeModelV1,
) -> Result<C2StoreGenerationInstallPolicyV1, PolicyRefusalV1> {
    verify_n_24_installed_positive_u32_maxima_fit_worst_case(&value, model)?;
    Ok(value)
}

/// N-25 refusal verifier for a malformed closed mode union.
pub fn verify_n_25_refusal(
    value: &C2StoreGenerationInstallPolicyV1,
) -> Result<(), PolicyRefusalV1> {
    verify_install_mode(&install_policy_input(value))
}

/// N-34 constructs one append-only active policy.
pub(crate) fn construct_n_34_active_policy(
    input: C2ActiveStorePolicyInputV1,
) -> Result<C2ActiveStorePolicyV1, PolicyRefusalV1> {
    require_policy_strings(&[
        &input.occurrence_id,
        &input.host_role,
        &input.authority_domain,
    ])?;
    if input.active_store_policy_generation == 0
        || input.active_store_policy_generation > MAX_IJSON_INTEGER
        || input.resident_generation == 0
        || input.role_manifest_generation == 0
        || input.signer_scope_policy_version == 0
        || input.policy_cut == 0
        || input.policy_cut > MAX_IJSON_INTEGER
        || input.policy_generation_maximum == 0
        || input.key_generation_maximum == 0
        || input.key_generation_maximum > input.policy_generation_maximum
        || input.g_entry_maximum == 0
    {
        return Err(PolicyRefusalV1::UnsafeInteger);
    }
    match input.installation_mode {
        C2InstallPolicyModeV1::Fresh if input.restore_authorization_identity.is_some() => {
            return Err(PolicyRefusalV1::InstallationModeMismatch);
        }
        C2InstallPolicyModeV1::RestoreSuccessor
            if input.restore_authorization_identity.is_none() =>
        {
            return Err(PolicyRefusalV1::InstallationModeMismatch);
        }
        _ => {}
    }
    let active_store_policy_identity = semantic_digest(&ActivePolicyPreimage {
        schema: "nq.c2.active_store_policy.identity.v1",
        input: &input,
    })
    .map_err(|_| PolicyRefusalV1::Canonicalization)?;
    Ok(C2ActiveStorePolicyV1 {
        schema: "nq.c2_active_store_policy.v1".into(),
        schema_version: 1,
        active_store_policy_identity,
        active_store_policy_generation: input.active_store_policy_generation,
        predecessor_active_store_policy_identity: input.predecessor_active_store_policy_identity,
        activation_predecessor_identity: input.activation_predecessor_identity,
        activation_successor_identity: input.activation_successor_identity,
        selected_enrollment_identity: input.selected_enrollment_identity,
        anchor_signature_identity: input.anchor_signature_identity,
        old_key_countersignature_identity: input.old_key_countersignature_identity,
        new_key_possession_signature_identity: input.new_key_possession_signature_identity,
        occurrence_id: input.occurrence_id,
        physical_store_generation_identity: input.physical_store_generation_identity,
        signer_lifecycle_root_identity: input.signer_lifecycle_root_identity,
        scope_identity: input.scope_identity,
        resident_identity: input.resident_identity,
        resident_generation: input.resident_generation,
        host_role: input.host_role,
        role_manifest_generation: input.role_manifest_generation,
        authority_domain: input.authority_domain,
        signer_scope_policy_identity: input.signer_scope_policy_identity,
        signer_scope_policy_version: input.signer_scope_policy_version,
        generation_lock_identity: input.generation_lock_identity,
        b_root_identity: input.b_root_identity,
        g_root_identity: input.g_root_identity,
        layout_identity: input.layout_identity,
        backend_profile_identity: input.backend_profile_identity,
        implementation_manifest_identity: input.implementation_manifest_identity,
        installation_mode: input.installation_mode,
        restore_authorization_identity: input.restore_authorization_identity,
        key_generation_maximum: input.key_generation_maximum,
        policy_generation_maximum: input.policy_generation_maximum,
        g_entry_maximum: input.g_entry_maximum,
        policy_cut: input.policy_cut,
    })
}

fn active_policy_input(value: &C2ActiveStorePolicyV1) -> C2ActiveStorePolicyInputV1 {
    C2ActiveStorePolicyInputV1 {
        active_store_policy_generation: value.active_store_policy_generation,
        predecessor_active_store_policy_identity: value
            .predecessor_active_store_policy_identity
            .clone(),
        activation_predecessor_identity: value.activation_predecessor_identity.clone(),
        activation_successor_identity: value.activation_successor_identity.clone(),
        selected_enrollment_identity: value.selected_enrollment_identity.clone(),
        anchor_signature_identity: value.anchor_signature_identity.clone(),
        old_key_countersignature_identity: value.old_key_countersignature_identity.clone(),
        new_key_possession_signature_identity: value.new_key_possession_signature_identity.clone(),
        occurrence_id: value.occurrence_id.clone(),
        physical_store_generation_identity: value.physical_store_generation_identity.clone(),
        signer_lifecycle_root_identity: value.signer_lifecycle_root_identity.clone(),
        scope_identity: value.scope_identity.clone(),
        resident_identity: value.resident_identity.clone(),
        resident_generation: value.resident_generation,
        host_role: value.host_role.clone(),
        role_manifest_generation: value.role_manifest_generation,
        authority_domain: value.authority_domain.clone(),
        signer_scope_policy_identity: value.signer_scope_policy_identity.clone(),
        signer_scope_policy_version: value.signer_scope_policy_version,
        generation_lock_identity: value.generation_lock_identity.clone(),
        b_root_identity: value.b_root_identity.clone(),
        g_root_identity: value.g_root_identity.clone(),
        layout_identity: value.layout_identity.clone(),
        backend_profile_identity: value.backend_profile_identity.clone(),
        implementation_manifest_identity: value.implementation_manifest_identity.clone(),
        installation_mode: value.installation_mode,
        restore_authorization_identity: value.restore_authorization_identity.clone(),
        key_generation_maximum: value.key_generation_maximum,
        policy_generation_maximum: value.policy_generation_maximum,
        g_entry_maximum: value.g_entry_maximum,
        policy_cut: value.policy_cut,
    }
}

fn same_immutable_tuple(a: &C2ActiveStorePolicyV1, b: &C2ActiveStorePolicyV1) -> bool {
    a.occurrence_id == b.occurrence_id
        && a.physical_store_generation_identity == b.physical_store_generation_identity
        && a.signer_lifecycle_root_identity == b.signer_lifecycle_root_identity
        && a.scope_identity == b.scope_identity
        && a.resident_identity == b.resident_identity
        && a.resident_generation == b.resident_generation
        && a.host_role == b.host_role
        && a.role_manifest_generation == b.role_manifest_generation
        && a.authority_domain == b.authority_domain
        && a.signer_scope_policy_identity == b.signer_scope_policy_identity
        && a.signer_scope_policy_version == b.signer_scope_policy_version
        && a.generation_lock_identity == b.generation_lock_identity
        && a.b_root_identity == b.b_root_identity
        && a.g_root_identity == b.g_root_identity
        && a.layout_identity == b.layout_identity
        && a.backend_profile_identity == b.backend_profile_identity
        && a.implementation_manifest_identity == b.implementation_manifest_identity
        && a.installation_mode == b.installation_mode
        && a.restore_authorization_identity == b.restore_authorization_identity
        && a.key_generation_maximum == b.key_generation_maximum
        && a.policy_generation_maximum == b.policy_generation_maximum
}

/// N-34 verifies identity and, for a successor, exact immutable tuple.
pub fn verify_n_34_active_policy_tuple(
    value: &C2ActiveStorePolicyV1,
    predecessor: Option<&C2ActiveStorePolicyV1>,
) -> Result<(), PolicyRefusalV1> {
    let expected = construct_n_34_active_policy(active_policy_input(value))?;
    if expected.active_store_policy_identity != value.active_store_policy_identity
        || value.schema != "nq.c2_active_store_policy.v1"
        || value.schema_version != 1
    {
        return Err(PolicyRefusalV1::IdentityMismatch);
    }
    match predecessor {
        None if value.active_store_policy_generation == 1
            && value.predecessor_active_store_policy_identity.is_none() =>
        {
            Ok(())
        }
        Some(old)
            if value.predecessor_active_store_policy_identity.as_ref()
                == Some(&old.active_store_policy_identity)
                && value.active_store_policy_generation
                    == old.active_store_policy_generation + 1
                && value.policy_cut > old.policy_cut
                && same_immutable_tuple(old, value) =>
        {
            Ok(())
        }
        Some(_) => Err(PolicyRefusalV1::ImmutableTupleMismatch),
        None => Err(PolicyRefusalV1::PolicyChainMalformed),
    }
}

/// N-35 keeps anchor authentication, old-key continuity, and changed-key PoP
/// as three non-substitutable roles.
pub fn verify_n_35_initial_old_new_signatures_have_distinct_anchor(
    value: &C2ActiveStorePolicyV1,
    predecessor: Option<&C2ActiveStorePolicyV1>,
) -> Result<(), PolicyRefusalV1> {
    match predecessor {
        None if value.old_key_countersignature_identity.is_some()
            && value.new_key_possession_signature_identity.is_none() =>
        {
            Ok(())
        }
        Some(old) => {
            let changed_key =
                value.selected_enrollment_identity != old.selected_enrollment_identity;
            if value.old_key_countersignature_identity.is_some()
                && (value.new_key_possession_signature_identity.is_some() == changed_key)
                && value.anchor_signature_identity
                    != value.old_key_countersignature_identity.clone().unwrap()
                && value
                    .new_key_possession_signature_identity
                    .as_ref()
                    .is_none_or(|pop| {
                        pop != &value.anchor_signature_identity
                            && Some(pop) != value.old_key_countersignature_identity.as_ref()
                    })
            {
                Ok(())
            } else {
                Err(PolicyRefusalV1::SignatureRoleMismatch)
            }
        }
        None => Err(PolicyRefusalV1::SignatureRoleMismatch),
    }
}

/// N-35 constructor alias: retain the record only after all three signature
/// roles have been checked against the exact predecessor.
pub(crate) fn construct_n_35_initial_old_new_signatures_have_distinct_anchor(
    value: C2ActiveStorePolicyV1,
    predecessor: Option<&C2ActiveStorePolicyV1>,
) -> Result<C2ActiveStorePolicyV1, PolicyRefusalV1> {
    verify_n_35_initial_old_new_signatures_have_distinct_anchor(&value, predecessor)?;
    Ok(value)
}

/// N-37 resolves the complete B-resident policy chain with no filtering.
pub(crate) fn resolve_complete_active_policy_chain_v1(
    policies: Vec<C2ActiveStorePolicyV1>,
    expected_current_activation: &Sha256Digest,
    expected_terminal_policy: &Sha256Digest,
) -> Result<CompleteActivePolicyResolutionV1, PolicyRefusalV1> {
    if policies.is_empty() {
        return Err(PolicyRefusalV1::CurrentPolicyCardinality);
    }
    let mut by_id = BTreeMap::new();
    for policy in &policies {
        let expected = construct_n_34_active_policy(active_policy_input(policy))?;
        if expected.active_store_policy_identity != policy.active_store_policy_identity {
            return Err(PolicyRefusalV1::IdentityMismatch);
        }
        if by_id
            .insert(policy.active_store_policy_identity.clone(), policy)
            .is_some()
        {
            return Err(PolicyRefusalV1::DuplicatePolicy);
        }
    }
    let initials: Vec<_> = policies
        .iter()
        .filter(|policy| policy.predecessor_active_store_policy_identity.is_none())
        .collect();
    if initials.len() != 1 {
        return Err(PolicyRefusalV1::CurrentPolicyCardinality);
    }
    let mut successors = BTreeMap::new();
    for policy in policies
        .iter()
        .filter(|policy| policy.predecessor_active_store_policy_identity.is_some())
    {
        let predecessor_id = policy
            .predecessor_active_store_policy_identity
            .as_ref()
            .unwrap();
        let predecessor = by_id
            .get(predecessor_id)
            .ok_or(PolicyRefusalV1::PolicyChainMalformed)?;
        verify_n_34_active_policy_tuple(policy, Some(predecessor))?;
        verify_n_35_initial_old_new_signatures_have_distinct_anchor(policy, Some(predecessor))?;
        if successors
            .insert(predecessor_id.clone(), &policy.active_store_policy_identity)
            .is_some()
        {
            return Err(PolicyRefusalV1::PolicyChainMalformed);
        }
    }
    verify_n_34_active_policy_tuple(initials[0], None)?;
    verify_n_35_initial_old_new_signatures_have_distinct_anchor(initials[0], None)?;
    let initial_id = initials[0].active_store_policy_identity.clone();
    let mut cursor = initial_id.clone();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(cursor.clone()) {
            return Err(PolicyRefusalV1::PolicyChainMalformed);
        }
        match successors.get(&cursor) {
            Some(next) => cursor = (*next).clone(),
            None => break,
        }
    }
    if visited.len() != policies.len() {
        return Err(PolicyRefusalV1::IncompleteCandidateSet);
    }
    let terminal = by_id
        .get(&cursor)
        .ok_or(PolicyRefusalV1::CurrentPolicyCardinality)?;
    if &cursor != expected_terminal_policy
        || &terminal.activation_successor_identity != expected_current_activation
    {
        return Err(PolicyRefusalV1::ActivationPolicyMismatch);
    }
    Ok(CompleteActivePolicyResolutionV1 {
        initial_policy_identity: initial_id,
        terminal_policy_identity: cursor,
        policies,
    })
}

/// N-36 refuses an activation/policy mismatch; it constructs no standing.
pub fn verify_n_36_refusal(
    resolution: &CompleteActivePolicyResolutionV1,
    current_activation: &Sha256Digest,
) -> Result<(), PolicyRefusalV1> {
    let terminal = resolution
        .policies
        .iter()
        .find(|policy| policy.active_store_policy_identity == resolution.terminal_policy_identity)
        .ok_or(PolicyRefusalV1::IncompleteCandidateSet)?;
    if &terminal.activation_successor_identity == current_activation {
        Ok(())
    } else {
        Err(PolicyRefusalV1::ActivationPolicyMismatch)
    }
}

/// N-37 refusal verifier reruns complete-set resolution.
pub fn verify_n_37_refusal(
    policies: Vec<C2ActiveStorePolicyV1>,
    current_activation: &Sha256Digest,
    terminal_policy: &Sha256Digest,
) -> Result<(), PolicyRefusalV1> {
    resolve_complete_active_policy_chain_v1(policies, current_activation, terminal_policy)
        .map(|_| ())
}

/// N-39 binds the exact current policy, proposal, lock and profile before any
/// transition brand can exist.
pub(crate) fn construct_n_39_transition_predecessor(
    resolution: &CompleteActivePolicyResolutionV1,
    proposed_predecessor: &Sha256Digest,
    proposed_policy_identity: Sha256Digest,
    transition_intent_identity: Sha256Digest,
    expected_lock_identity: &Sha256Digest,
    observed_lock_identity: Sha256Digest,
    expected_profile_identity: &Sha256Digest,
    observed_profile_identity: Sha256Digest,
) -> Result<C2PolicyTransitionPredecessorV1, PolicyRefusalV1> {
    if proposed_predecessor != &resolution.terminal_policy_identity {
        return Err(PolicyRefusalV1::TransitionPredecessorMismatch);
    }
    if expected_lock_identity != &observed_lock_identity
        || expected_profile_identity != &observed_profile_identity
    {
        return Err(PolicyRefusalV1::TransitionCorrespondenceMismatch);
    }
    Ok(C2PolicyTransitionPredecessorV1 {
        old_policy_identity: resolution.terminal_policy_identity.clone(),
        proposed_policy_identity,
        transition_intent_identity,
        lock_identity: observed_lock_identity,
        profile_identity: observed_profile_identity,
    })
}

/// N-39 rechecks the exact pre-effect tuple.
pub fn verify_n_39_predecessor_under_lock(
    predecessor: &C2PolicyTransitionPredecessorV1,
    current_policy: &Sha256Digest,
    lock_identity: &Sha256Digest,
    profile_identity: &Sha256Digest,
) -> Result<(), PolicyRefusalV1> {
    if &predecessor.old_policy_identity == current_policy
        && &predecessor.lock_identity == lock_identity
        && &predecessor.profile_identity == profile_identity
    {
        Ok(())
    } else {
        Err(PolicyRefusalV1::TransitionCorrespondenceMismatch)
    }
}

/// N-13/P-04 construct the sole transition brand from an exact predecessor.
pub(crate) fn construct_n_13_policy_transition_brand(
    predecessor: C2PolicyTransitionPredecessorV1,
) -> C2PolicyTransitionBrandV1 {
    C2PolicyTransitionBrandV1(predecessor)
}

pub fn verify_n_13_old_and_proposed_tuples(
    brand: &C2PolicyTransitionBrandV1,
    expected_old: &Sha256Digest,
    expected_proposed: &Sha256Digest,
) -> Result<(), PolicyRefusalV1> {
    if &brand.0.old_policy_identity == expected_old
        && &brand.0.proposed_policy_identity == expected_proposed
    {
        Ok(())
    } else {
        Err(PolicyRefusalV1::TransitionPredecessorMismatch)
    }
}

pub(crate) fn transition_c2_active_policy(
    predecessor: C2PolicyTransitionPredecessorV1,
) -> C2PolicyTransitionBrandV1 {
    construct_n_13_policy_transition_brand(predecessor)
}

pub fn verify_active_policy_transition_inputs(
    brand: &C2PolicyTransitionBrandV1,
    expected_intent: &Sha256Digest,
) -> Result<(), PolicyRefusalV1> {
    if &brand.0.transition_intent_identity == expected_intent {
        Ok(())
    } else {
        Err(PolicyRefusalV1::TransitionCorrespondenceMismatch)
    }
}

/// N-14/P-05 construct an exact-intent continuation, never a synthesized tip.
pub(crate) fn construct_n_14_transition_continuation(
    historical_intent: Sha256Digest,
    expected_intent: &Sha256Digest,
    exact_prefix_identity: Sha256Digest,
    observed_prefix_identity: &Sha256Digest,
    frontier: C2PolicyPartialFrontierV1,
) -> Result<C2PolicyTransitionContinuationBrandV1, PolicyRefusalV1> {
    if &historical_intent != expected_intent || &exact_prefix_identity != observed_prefix_identity {
        return Err(PolicyRefusalV1::ContinuationFrontierMismatch);
    }
    Ok(C2PolicyTransitionContinuationBrandV1 {
        transition_intent_identity: historical_intent,
        exact_prefix_identity,
        frontier,
    })
}

pub fn verify_n_14_exact_partial_frontier(
    brand: &C2PolicyTransitionContinuationBrandV1,
    intent: &Sha256Digest,
    prefix: &Sha256Digest,
) -> Result<(), PolicyRefusalV1> {
    if &brand.transition_intent_identity == intent && &brand.exact_prefix_identity == prefix {
        Ok(())
    } else {
        Err(PolicyRefusalV1::ContinuationFrontierMismatch)
    }
}

pub(crate) fn continue_c2_policy_transition(
    historical_intent: Sha256Digest,
    expected_intent: &Sha256Digest,
    exact_prefix_identity: Sha256Digest,
    observed_prefix_identity: &Sha256Digest,
    frontier: C2PolicyPartialFrontierV1,
) -> Result<C2PolicyTransitionContinuationBrandV1, PolicyRefusalV1> {
    construct_n_14_transition_continuation(
        historical_intent,
        expected_intent,
        exact_prefix_identity,
        observed_prefix_identity,
        frontier,
    )
}

pub fn verify_policy_transition_frontier(
    brand: &C2PolicyTransitionContinuationBrandV1,
    expected: C2PolicyPartialFrontierV1,
) -> Result<(), PolicyRefusalV1> {
    if brand.frontier == expected {
        Ok(())
    } else {
        Err(PolicyRefusalV1::ContinuationFrontierMismatch)
    }
}

/// N-38 verifies the brand is tied to one exact predecessor and proposal.
pub fn verify_n_38_sole_transition_install_path(
    brand: &C2PolicyTransitionBrandV1,
    predecessor: &Sha256Digest,
    proposal: &Sha256Digest,
) -> Result<(), PolicyRefusalV1> {
    verify_n_13_old_and_proposed_tuples(brand, predecessor, proposal)
}

pub(crate) fn construct_n_38_policy_transition_brand(
    predecessor: C2PolicyTransitionPredecessorV1,
) -> C2PolicyTransitionBrandV1 {
    C2PolicyTransitionBrandV1(predecessor)
}

/// N-41 refuses unresolved intent on an ordinary-open path.
pub fn verify_n_41_refusal(
    unresolved_intent: Option<&Sha256Digest>,
) -> Result<(), PolicyRefusalV1> {
    if unresolved_intent.is_none() {
        Ok(())
    } else {
        Err(PolicyRefusalV1::ContinuationFrontierMismatch)
    }
}

/// Fresh observation used by N-42 before and after every continuation effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2PolicyTransitionContinuationV1 {
    before_profile: Sha256Digest,
    after_profile: Sha256Digest,
    before_lock: Sha256Digest,
    after_lock: Sha256Digest,
}

pub(crate) fn construct_n_42_transition_continuation(
    before_profile: Sha256Digest,
    after_profile: Sha256Digest,
    before_lock: Sha256Digest,
    after_lock: Sha256Digest,
) -> C2PolicyTransitionContinuationV1 {
    C2PolicyTransitionContinuationV1 {
        before_profile,
        after_profile,
        before_lock,
        after_lock,
    }
}

pub fn verify_n_42_profile_correspondence(
    value: &C2PolicyTransitionContinuationV1,
) -> Result<(), PolicyRefusalV1> {
    if value.before_profile == value.after_profile && value.before_lock == value.after_lock {
        Ok(())
    } else {
        Err(PolicyRefusalV1::TransitionCorrespondenceMismatch)
    }
}

/// N-54 records the compile-time separation of transition/continuation brands.
pub(crate) fn construct_n_54_transition_mode_disjointness() -> C2PolicyTransitionModeDisjointnessV1
{
    C2PolicyTransitionModeDisjointnessV1
}

pub fn verify_n_54_transition_continuation_disjointness(
    _: C2PolicyTransitionModeDisjointnessV1,
) -> Result<(), PolicyRefusalV1> {
    Ok(())
}

impl CompleteActivePolicyResolutionV1 {
    #[must_use]
    pub fn initial_policy_identity(&self) -> &Sha256Digest {
        &self.initial_policy_identity
    }

    #[must_use]
    pub fn terminal_policy_identity(&self) -> &Sha256Digest {
        &self.terminal_policy_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn install_input(mode: C2InstallPolicyModeV1) -> C2StoreGenerationInstallPolicyInputV1 {
        let restore = mode == C2InstallPolicyModeV1::RestoreSuccessor;
        C2StoreGenerationInstallPolicyInputV1 {
            occurrence_id: "occurrence-a".into(),
            physical_store_generation_identity: digest('a'),
            signer_lifecycle_root_identity: digest('b'),
            scope_identity: digest('c'),
            resident_identity: digest('d'),
            resident_generation: 1,
            host_role: "host-role".into(),
            role_manifest_generation: 1,
            authority_domain: "domain".into(),
            signer_scope_policy_identity: digest('e'),
            signer_scope_policy_version: 1,
            gen4_root_identity: digest('f'),
            gen4_initial_tip_identity: digest('0'),
            selected_enrollment_identity: digest('1'),
            installation_nonce: "2".repeat(64),
            installation_mode: mode,
            layout_identity: digest('3'),
            lock_domain_identity: digest('4'),
            b_payload_bound: 100_000,
            g_payload_bound: 10_000,
            key_generation_maximum: 8,
            policy_generation_maximum: 16,
            qualified_backend_profile_identity: digest('5'),
            backend_implementation_manifest_identity: digest('6'),
            predecessor_policy_identity: None,
            predecessor_physical_store_generation_identity: restore.then(|| digest('7')),
            predecessor_bootstrap_identity: restore.then(|| digest('8')),
            predecessor_installation_receipt_identity: restore.then(|| digest('9')),
            predecessor_installation_cut: restore.then_some(4),
            restore_disposition_identity: restore.then(|| digest('a')),
            restore_proof_identity: restore.then(|| digest('b')),
            installation_cut: 5,
        }
    }

    fn active_input(
        generation: u64,
        predecessor: Option<Sha256Digest>,
        activation_predecessor: char,
        activation_successor: char,
        enrollment: char,
        cut: u64,
    ) -> C2ActiveStorePolicyInputV1 {
        C2ActiveStorePolicyInputV1 {
            active_store_policy_generation: generation,
            predecessor_active_store_policy_identity: predecessor,
            activation_predecessor_identity: digest(activation_predecessor),
            activation_successor_identity: digest(activation_successor),
            selected_enrollment_identity: digest(enrollment),
            anchor_signature_identity: digest('a'),
            old_key_countersignature_identity: Some(digest('b')),
            new_key_possession_signature_identity: (generation > 1).then(|| digest('c')),
            occurrence_id: "occurrence-a".into(),
            physical_store_generation_identity: digest('d'),
            signer_lifecycle_root_identity: digest('e'),
            scope_identity: digest('f'),
            resident_identity: digest('0'),
            resident_generation: 1,
            host_role: "host-role".into(),
            role_manifest_generation: 1,
            authority_domain: "domain".into(),
            signer_scope_policy_identity: digest('1'),
            signer_scope_policy_version: 1,
            generation_lock_identity: digest('2'),
            b_root_identity: digest('3'),
            g_root_identity: digest('4'),
            layout_identity: digest('5'),
            backend_profile_identity: digest('6'),
            implementation_manifest_identity: digest('7'),
            installation_mode: C2InstallPolicyModeV1::Fresh,
            restore_authorization_identity: None,
            key_generation_maximum: 8,
            policy_generation_maximum: 16,
            g_entry_maximum: 32,
            policy_cut: cut,
        }
    }

    #[test]
    fn fresh_forbids_restore_predecessor_material() {
        let mut input = install_input(C2InstallPolicyModeV1::Fresh);
        input.predecessor_bootstrap_identity = Some(digest('a'));
        assert!(matches!(
            construct_n_22_install_policy_binds_complete_gen4_tuple_enrollment(input),
            Err(PolicyRefusalV1::InstallationModeMismatch)
        ));
    }

    #[test]
    fn restore_requires_a_strictly_later_cut() {
        let mut input = install_input(C2InstallPolicyModeV1::RestoreSuccessor);
        input.predecessor_installation_cut = Some(5);
        assert!(matches!(
            construct_n_23_restore_mode_additionally_binds_predecessor_generation_bootstrap(input),
            Err(PolicyRefusalV1::RestorePredecessorMismatch)
        ));
    }

    #[test]
    fn maxima_use_checked_canonical_b_arithmetic() {
        let policy = construct_n_22_install_policy_binds_complete_gen4_tuple_enrollment(
            install_input(C2InstallPolicyModeV1::Fresh),
        )
        .unwrap();
        assert!(
            verify_n_24_installed_positive_u32_maxima_fit_worst_case(
                &policy,
                CanonicalBSizeModelV1 {
                    fixed_bytes: 1_000,
                    per_key_generation_bytes: 100,
                    per_policy_generation_bytes: 200,
                    final_alignment_bytes: 4_096,
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn transition_continuation_requires_exact_intent_and_prefix() {
        let refusal = construct_n_14_transition_continuation(
            digest('a'),
            &digest('b'),
            digest('c'),
            &digest('c'),
            C2PolicyPartialFrontierV1::IntentDurable,
        )
        .unwrap_err();
        assert_eq!(refusal, PolicyRefusalV1::ContinuationFrontierMismatch);
    }

    #[test]
    fn complete_policy_chain_is_predecessor_derived_not_input_order() {
        let initial =
            construct_n_34_active_policy(active_input(1, None, '8', '8', '9', 1)).unwrap();
        let successor = construct_n_34_active_policy(active_input(
            2,
            Some(initial.active_store_policy_identity.clone()),
            '8',
            'a',
            '0',
            4,
        ))
        .unwrap();
        let resolved = resolve_complete_active_policy_chain_v1(
            vec![successor.clone(), initial.clone()],
            &digest('a'),
            &successor.active_store_policy_identity,
        )
        .unwrap();
        assert_eq!(
            resolved.initial_policy_identity(),
            &initial.active_store_policy_identity
        );
        assert_eq!(
            resolved.terminal_policy_identity(),
            &successor.active_store_policy_identity
        );
    }

    #[test]
    fn competing_policy_successors_refuse_without_tie_break() {
        let initial =
            construct_n_34_active_policy(active_input(1, None, '8', '8', '9', 1)).unwrap();
        let successor_a = construct_n_34_active_policy(active_input(
            2,
            Some(initial.active_store_policy_identity.clone()),
            '8',
            'a',
            '0',
            4,
        ))
        .unwrap();
        let successor_b = construct_n_34_active_policy(active_input(
            2,
            Some(initial.active_store_policy_identity.clone()),
            '8',
            'b',
            '1',
            5,
        ))
        .unwrap();
        assert!(matches!(
            resolve_complete_active_policy_chain_v1(
                vec![initial, successor_a.clone(), successor_b],
                &digest('a'),
                &successor_a.active_store_policy_identity,
            ),
            Err(PolicyRefusalV1::PolicyChainMalformed)
        ));
    }
}
