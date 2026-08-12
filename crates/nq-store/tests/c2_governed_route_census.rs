//! Source-derived census for the seven Store-owned governed-carrier roots.
//!
//! Runtime carrier/durability behavior is tested inside
//! `signer::external_governance`; this specimen keeps the production wiring
//! closed by proving that every public-in-crate route derives its expectation
//! and permit inside the Store actor and reaches only its typed verifier and
//! typed consumer.  It intentionally does not claim that source shape alone
//! proves Store semantics.

const LIVE_C2_SOURCE: &str = include_str!("../src/store_generation/live_c2.rs");

fn method_source(name: &str) -> &str {
    let marker = format!("pub(crate) fn {name}");
    let start = LIVE_C2_SOURCE
        .find(&marker)
        .unwrap_or_else(|| panic!("missing Store-owned governed route {name}"));
    let source = &LIVE_C2_SOURCE[start..];
    let body_start = source
        .find('{')
        .unwrap_or_else(|| panic!("missing body for {name}"));
    let mut depth = 0_u64;
    for (offset, byte) in source.as_bytes()[body_start..].iter().copied().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[..body_start + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated body for {name}")
}

#[test]
fn all_seven_governed_routes_are_store_owned_typed_and_closed() {
    let routes = [
        (
            "adopt_bootstrap_grant_v1",
            "verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity",
            "prepare_bootstrap_grant_ingress",
        ),
        (
            "adopt_activation_successor_grant_v1",
            "verify_activation_successor_grant_terminal_a1_signature_scope_policy_cut_request_identity",
            "prepare_activation_successor_grant_ingress",
        ),
        (
            "adopt_proposal_disposition_v1",
            "verify_proposal_disposition_terminal_a1_signature_scope_policy_cut_request_identity",
            "prepare_proposal_disposition_ingress",
        ),
        (
            "adopt_restore_authorization_v1",
            "verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity",
            "prepare_restore_authorization_ingress",
        ),
        (
            "adopt_recovery_grant_v1",
            "verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity",
            "prepare_recovery_grant_ingress",
        ),
        (
            "apply_revocation_judgment_v1",
            "verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity",
            "prepare_verified_revocation_effect_v1",
        ),
        (
            "apply_quarantine_closure_judgment_v1",
            "verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity",
            "prepare_verified_quarantine_closure_effect_v1",
        ),
    ];

    for (name, verifier, consumer) in routes {
        let source = method_source(name);
        let signature = source.split_once('{').unwrap().0;
        assert!(
            signature.starts_with(&format!("pub(crate) fn {name}")),
            "{name} is no longer a closed crate-owned root"
        );
        for forbidden in [
            "BTreeMap",
            "ExternalGovernanceExpectationV1",
            "ExternalCarrierVerificationPermitV1",
            "C2PreparedExternalIngressV1",
            "DurableExternalIngressReceiptV1",
        ] {
            assert!(
                !signature.contains(forbidden),
                "{name} exposes caller-authored governance internals: {forbidden}"
            );
        }
        for required in [
            "ExternalGovernanceExpectationV1::new(self",
            "ExternalCarrierVerificationPermitV1::from_store_actor(self)",
            "StoreTerminalA1VerifierV1",
            verifier,
            consumer,
        ] {
            assert!(
                source.contains(required),
                "{name} bypasses required Store-owned typed step {required}"
            );
        }
        let expectation_index = source
            .find("ExternalGovernanceExpectationV1::new(self")
            .unwrap();
        let permit_index = source
            .find("ExternalCarrierVerificationPermitV1::from_store_actor(self)")
            .unwrap();
        let verifier_index = source.find(verifier).unwrap();
        let consumer_index = source.find(consumer).unwrap();
        assert!(
            expectation_index < permit_index
                && permit_index < verifier_index
                && verifier_index < consumer_index,
            "{name} does not verify before its first possible durable consumer"
        );
        for forbidden_effect in [
            "append_prepared_foundational_enrollment_adoption_v1",
            "append_prepared_signer_enrollment_acceptance_v1",
            "c2_signer_current_binding_projection",
            "seal_store_accepted_signer_enrollment_v1",
        ] {
            assert!(
                !source.contains(forbidden_effect),
                "{name} unexpectedly mutates enrollment/currentness via {forbidden_effect}"
            );
        }
    }
}

#[test]
fn effect_routes_are_atomic_and_evidence_routes_only_append_governed_ingress() {
    for name in [
        "adopt_bootstrap_grant_v1",
        "adopt_activation_successor_grant_v1",
        "adopt_proposal_disposition_v1",
        "adopt_restore_authorization_v1",
        "adopt_recovery_grant_v1",
    ] {
        let source = method_source(name);
        assert!(source.contains("append_verified_governed_carrier_effect"));
        assert!(!source.contains("with_permitted_effect("));
    }

    for name in [
        "apply_revocation_judgment_v1",
        "apply_quarantine_closure_judgment_v1",
    ] {
        let source = method_source(name);
        assert!(source.contains("prepared.verify_for_actor(self)"));
        assert!(source.contains("with_permitted_effect("));
        assert!(source.contains("prepared"));
        assert!(source.contains(".apply(transaction)"));
        assert!(!source.contains("append_verified_governed_carrier_effect"));
    }
}
