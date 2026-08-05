#!/usr/bin/env python3
"""Unit controls for the fail-closed C2 call-graph verifier."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("verify_c2_callgraph.py")
SPEC = importlib.util.spec_from_file_location("verify_c2_callgraph", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CallGraphVerifierControls(unittest.TestCase):
    def test_exact_matrix_surface_has_39_unique_verifiers(self) -> None:
        names = [verifier.__name__ for verifier in MODULE.ASSIGNED_VERIFIERS]
        self.assertEqual(len(names), 39)
        self.assertEqual(len(names), len(set(names)))
        self.assertIn(
            "verify_wu_14_immutable_wu_machine_constructor_mutator_i_o", names
        )
        self.assertIn(
            "verify_cg_26_gen4_establishment_restart_r0b_constraints_remain_intact",
            names,
        )

    def test_scanner_ignores_comment_and_literal_decoy_edges(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                "fixture.rs": '''
                    fn actual() { target(); }
                    fn decoy() {
                        // target();
                        let _ = "target()";
                    }
                ''',
            }
        )
        callers = inventory.callers_of("target")
        self.assertEqual([function.name for function in callers], ["actual"])

    def test_protected_public_reexport_is_rejected(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                "fixture.rs": '''
                    pub(crate) struct C2StoreIntegrityCustodian;
                    pub use crate::C2StoreIntegrityCustodian;
                ''',
            }
        )
        self.assertTrue(
            inventory.public_reexports({"C2StoreIntegrityCustodian"})
        )

    def test_source_inventory_digest_is_deterministic(self) -> None:
        texts = {
            "b.rs": "fn b() { a(); }",
            "a.rs": "fn a() {}",
        }
        first = MODULE.SourceInventory.from_texts(texts)
        second = MODULE.SourceInventory.from_texts(dict(reversed(list(texts.items()))))
        self.assertEqual(first.digest(), second.digest())

    def test_call_order_control_rejects_reversal(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {"fixture.rs": "fn bridge() { consume(); sign(); }"}
        )
        function = inventory.require_function("fixture.rs", "bridge")
        with self.assertRaises(MODULE.VerificationError):
            MODULE._require_calls_in_order(function, ("sign", "consume"))

    def test_signer_unsafe_boundary_requires_exact_forbid_attribute(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {MODULE.SIGNER_MOD: "#![forbid(unsafe_code)]\nmod custody;"}
        )
        self.assertEqual(
            MODULE._verify_signer_module_unsafe_boundary(inventory),
            ("signer-unsafe-code=forbidden-at-module-root",),
        )

    def test_signer_unsafe_boundary_rejects_weaker_deny_attribute(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {MODULE.SIGNER_MOD: "#![deny(unsafe_code)]\nmod custody;"}
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "exactly one #!\\[forbid\\(unsafe_code\\)\\]",
        ):
            MODULE._verify_signer_module_unsafe_boundary(inventory)

    def test_schema_projection_gate_accepts_only_an_unconstructed_permit(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                MODULE.INSTALL: """
                    pub(crate) struct C2PendingSqlProjectionPermitV1<Mode> {
                        marker: core::marker::PhantomData<Mode>,
                    }
                """,
                MODULE.STORE_LIB: """
                    pub(crate) fn apply_c2_schema_v8_to_v9<Mode>(
                        permit: crate::store_generation::install::C2PendingSqlProjectionPermitV1<Mode>,
                    ) { consume(permit); }
                """,
                MODULE.HOST_RUNTIME: "fn ordinary_open() {}",
            }
        )
        self.assertEqual(
            MODULE._verify_schema_projection_gate(inventory),
            (
                "schema-v9-path-only-route=absent",
                "schema-v9-permit-production-constructors=0",
                "schema-v9-production-apply-callers=0",
            ),
        )

    def test_schema_projection_gate_rejects_the_path_only_runtime_bypass(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                MODULE.INSTALL: """
                    pub(crate) struct C2PendingSqlProjectionPermitV1<Mode> {
                        marker: core::marker::PhantomData<Mode>,
                    }
                """,
                MODULE.STORE_LIB: """
                    pub(crate) fn apply_c2_schema_v8_to_v9<Mode>(
                        permit: crate::store_generation::install::C2PendingSqlProjectionPermitV1<Mode>,
                    ) { consume(permit); }
                """,
                MODULE.HOST_RUNTIME: """
                    pub fn migrate_c1_gen4_to_c2_schema_projection(path: &str) {
                        consume(path);
                    }
                """,
            }
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError, "path-only schema-v9 projection bypass"
        ):
            MODULE._verify_schema_projection_gate(inventory)

    def test_pending_signer_append_gate_accepts_only_unconstructed_permit(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                MODULE.SIGNER_COORDINATOR: """
                    pub(super) struct C2SignerDurableAppendPermitV1 { private: () }
                    pub(crate) struct NonescapingSignedFrameV1 {
                        canonical_payload: Vec<u8>,
                    }
                    pub(crate) struct C2SignerDurableAppendConsumerV1 {
                        permit: C2SignerDurableAppendPermitV1,
                    }
                    impl C2SignerDurableAppendConsumerV1 {
                        fn new(permit: C2SignerDurableAppendPermitV1) -> Self {
                            Self { permit }
                        }
                    }
                    struct C2SignerTransitionCoordinator {
                        append_consumer: C2SignerDurableAppendConsumerV1,
                    }
                    impl C2SignerTransitionCoordinator {
                        fn new(append_permit: C2SignerDurableAppendPermitV1) -> Self {
                            Self {
                                append_consumer: C2SignerDurableAppendConsumerV1::new(
                                    append_permit,
                                ),
                            }
                        }
                    }
                """,
            }
        )
        self.assertEqual(
            MODULE._verify_pending_signer_append_gate(inventory),
            (
                "signer-append-permit-production-constructors=0",
                "signed-frame-owned-payload=one",
                "durable-append-status=not-yet-wired",
            ),
        )

    def test_pending_signer_append_gate_rejects_production_permit_constructor(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                MODULE.SIGNER_COORDINATOR: """
                    pub(super) struct C2SignerDurableAppendPermitV1 { private: () }
                    pub(crate) struct NonescapingSignedFrameV1 {
                        canonical_payload: Vec<u8>,
                    }
                    pub(crate) struct C2SignerDurableAppendConsumerV1 {
                        permit: C2SignerDurableAppendPermitV1,
                    }
                    impl C2SignerDurableAppendConsumerV1 {
                        fn new(permit: C2SignerDurableAppendPermitV1) -> Self {
                            Self { permit }
                        }
                    }
                    struct C2SignerTransitionCoordinator;
                    impl C2SignerTransitionCoordinator {
                        fn new(append_permit: C2SignerDurableAppendPermitV1) -> Self { Self }
                    }
                    fn bypass() -> C2SignerDurableAppendPermitV1 {
                        C2SignerDurableAppendPermitV1 { private: () }
                    }
                """,
            }
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError, "production constructor before durable wiring"
        ):
            MODULE._verify_pending_signer_append_gate(inventory)

    @staticmethod
    def _external_ingress_inventory(
        *,
        raw_bootstrap_ingress: bool = False,
        public_snapshot_verifier: bool = False,
    ):
        bootstrap_projection = (
            "StoreIntegrityBootstrapGrantV1"
            if raw_bootstrap_ingress
            else "VerifiedBootstrapGrantV1"
        )
        verifier_owner = (
            "ControllingActivationSnapshot"
            if public_snapshot_verifier
            else "TerminalA1AuthoritySnapshotV1<'_>"
        )
        return MODULE.SourceInventory.from_texts(
            {
                MODULE.SIGNER_GOVERNANCE: f"""
                    pub(super) trait TerminalA1AuthenticityVerifierV1 {{
                        fn verify_unique_terminal_a1(&self);
                    }}
                    pub(super) struct ExternalGovernanceExpectationV1;
                    impl ExternalGovernanceExpectationV1 {{
                        fn new() -> Self {{ Self }}
                    }}
                    pub(super) struct ExternalCarrierVerificationPermitV1 {{
                        private: (),
                    }}
                    pub(super) struct ExternalCarrierStoreIngressPermitV1 {{
                        private: (),
                    }}
                    pub(crate) struct ExternalCarrierReplayGuardV1 {{
                        permit: ExternalCarrierStoreIngressPermitV1,
                    }}
                    impl ExternalCarrierReplayGuardV1 {{
                        pub(super) fn new(
                            permit: ExternalCarrierStoreIngressPermitV1,
                        ) -> Self {{ Self {{ permit }} }}
                    }}
                    fn verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity(
                        _permit: &ExternalCarrierVerificationPermitV1,
                    ) {{}}
                    macro_rules! pair_verifier {{
                        ($name:ident) => {{
                            fn $name(_permit: &ExternalCarrierVerificationPermitV1) {{}}
                        }};
                    }}
                    macro_rules! ingress_type {{
                        ($name:ident, $verified:ident, $receipt:ident, $result:ident, $method:ident) => {{
                            #[derive(Debug, PartialEq, Eq)]
                            pub(crate) struct $receipt {{
                                carrier_identity: ExternalCarrierIdentityV1,
                                _private: (),
                            }}
                        }};
                    }}
                    #[derive(Debug)]
                    pub(crate) enum ExternalCarrierIngressResultV2 {{
                        ProposalDispositionConsumed(ProposalDispositionIngressReceiptV1),
                        BootstrapGrantConsumed(BootstrapGrantIngressReceiptV1),
                        ActivationSuccessorGrantConsumed(ActivationSuccessorGrantIngressReceiptV1),
                        RevocationJudgmentConsumed(RevocationJudgmentIngressReceiptV1),
                        RecoveryGrantConsumed(RecoveryGrantIngressReceiptV1),
                        RestoreAuthorizationConsumed(RestoreAuthorizationIngressReceiptV1),
                        QuarantineClosureJudgmentConsumed(QuarantineClosureIngressReceiptV1),
                    }}
                    verified_pair_type!(
                        VerifiedProposalDispositionV1,
                        StoreIntegrityProposalDispositionV1
                    );
                    struct VerifiedBootstrapGrantV1;
                    verified_pair_type!(
                        VerifiedActivationSuccessorGrantV1,
                        StoreIntegrityActivationSuccessorGrantV1
                    );
                    verified_pair_type!(
                        VerifiedRevocationJudgmentV1,
                        StoreIntegrityRevocationJudgmentV1
                    );
                    verified_pair_type!(
                        VerifiedRecoveryGrantV1,
                        StoreIntegrityRecoveryGrantV1
                    );
                    verified_pair_type!(
                        VerifiedRestoreAuthorizationV1,
                        StoreIntegrityRestoreAuthorizationV1
                    );
                    verified_pair_type!(
                        VerifiedQuarantineClosureJudgmentV1,
                        StoreIntegrityQuarantineClosureJudgmentV1
                    );
                    ingress_type!(
                        ProposalDispositionIngressV1,
                        VerifiedProposalDispositionV1,
                        ProposalDispositionIngressReceiptV1,
                        ProposalDispositionConsumed,
                        apply
                    );
                    ingress_type!(
                        BootstrapGrantIngressV1,
                        {bootstrap_projection},
                        BootstrapGrantIngressReceiptV1,
                        BootstrapGrantConsumed,
                        consume
                    );
                    ingress_type!(
                        ActivationSuccessorGrantIngressV1,
                        VerifiedActivationSuccessorGrantV1,
                        ActivationSuccessorGrantIngressReceiptV1,
                        ActivationSuccessorGrantConsumed,
                        apply
                    );
                    ingress_type!(
                        RevocationJudgmentIngressV1,
                        VerifiedRevocationJudgmentV1,
                        RevocationJudgmentIngressReceiptV1,
                        RevocationJudgmentConsumed,
                        apply
                    );
                    ingress_type!(
                        RecoveryGrantIngressV1,
                        VerifiedRecoveryGrantV1,
                        RecoveryGrantIngressReceiptV1,
                        RecoveryGrantConsumed,
                        apply
                    );
                    ingress_type!(
                        RestoreAuthorizationIngressV1,
                        VerifiedRestoreAuthorizationV1,
                        RestoreAuthorizationIngressReceiptV1,
                        RestoreAuthorizationConsumed,
                        install_successor
                    );
                    ingress_type!(
                        QuarantineClosureIngressV1,
                        VerifiedQuarantineClosureJudgmentV1,
                        QuarantineClosureIngressReceiptV1,
                        QuarantineClosureJudgmentConsumed,
                        close
                    );
                """,
                MODULE.SIGNER_AUTHORITY: f"""
                    struct TerminalA1AuthoritySnapshotV1<'snapshot> {{
                        input: &'snapshot CurrentActivationResolverInputV1<'snapshot>,
                        resolved: &'snapshot ControllingActivationSnapshot,
                    }}
                    impl TerminalA1AuthenticityVerifierV1 for {verifier_owner} {{
                        fn verify_unique_terminal_a1(&self) {{}}
                    }}
                    pub(crate) fn construct_sg_n_03_issuer_currentness_is_resolved_complete_store_owned<'snapshot>(
                        input: &'snapshot CurrentActivationResolverInputV1<'snapshot>,
                        resolved: &'snapshot ControllingActivationSnapshot,
                    ) -> Result<TerminalA1AuthoritySnapshotV1<'snapshot>, SignerRefusalV2> {{
                        consume(input);
                        consume(resolved);
                    }}
                    pub(crate) fn verify_sg_n_03_issuer_currentness_is_resolved_complete_store_owned(
                        snapshot: &TerminalA1AuthoritySnapshotV1<'_>,
                    ) {{ consume(snapshot); }}
                """,
                MODULE.HOST_RUNTIME: """
                    fn resolve_store_runtime_authority() {
                        let activation = project_current_activation_for_c2();
                        let terminal = construct_sg_n_03_issuer_currentness_is_resolved_complete_store_owned();
                        verify_sg_n_03_issuer_currentness_is_resolved_complete_store_owned(&terminal);
                    }
                """,
            }
        )

    def test_external_ingress_gate_accepts_only_verified_carriers(self) -> None:
        self.assertEqual(
            MODULE._verify_pending_external_carrier_ingress_gate(
                self._external_ingress_inventory()
            ),
            (
                "external-verification-permit-production-constructors=0",
                "terminal-A1-production-verifiers=1-store-owned-same-snapshot",
                "external-ingress-permit-production-constructors=0",
                "external-ingress-routes=7-terminal-A1-verified-only",
                "external-ingress-receipts=7-opaque",
                "external-replay-status=process-local-pending-not-durable",
            ),
        )

    def test_external_ingress_gate_rejects_public_resolver_terminal_verifier(self) -> None:
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "exactly one private Store-owned snapshot implementation",
        ):
            MODULE._verify_pending_external_carrier_ingress_gate(
                self._external_ingress_inventory(public_snapshot_verifier=True)
            )

    def test_external_ingress_gate_rejects_decoded_carrier(self) -> None:
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "does not require VerifiedBootstrapGrantV1",
        ):
            MODULE._verify_pending_external_carrier_ingress_gate(
                self._external_ingress_inventory(raw_bootstrap_ingress=True)
            )

    @staticmethod
    def _process_fence_inventory(*, alternate_spawn: bool = False):
        alternate = (
            "fn bypass(command: &mut Command) { let _ = command.spawn(); }"
            if alternate_spawn
            else ""
        )
        return MODULE.SourceInventory.from_texts(
            {
                MODULE.HELPER_SANDBOX: """
                    static C2_PROCESS_FENCE: Mutex<()> = Mutex::new(());
                    pub fn enter_c2_secret_process_interval() {
                        let _guard = C2_PROCESS_FENCE.lock();
                    }
                    pub fn with_c2_process_spawn_fence(operation: impl FnOnce()) {
                        let _guard = C2_PROCESS_FENCE.lock();
                        operation();
                    }
                """,
                MODULE.CORE_IDENTITY: f"""
                    fn spawn_with_inherited_descriptors(command: &mut Command, descriptors: &[i32]) {{
                        with_c2_process_spawn_fence(|| {{
                            let _guard = DESCRIPTOR_LAUNCH.lock();
                            let original_flags = make_inheritable(descriptors);
                            let spawned = command.spawn();
                            let restored = restore_descriptor_flags(descriptors, &original_flags);
                        }});
                    }}
                    {alternate}
                """,
                MODULE.SIGNER_CUSTODY: """
                    struct C2StoreIntegrityCustodian;
                    impl C2StoreIntegrityCustodian {
                        fn create_below_root() {
                            let secret_process_guard = enter_c2_secret_process_interval();
                            getrandom::fill(&mut seed);
                            bytes.fill(0);
                            secret_process_guard.verify_same_process();
                        }
                        fn sign(&self) {
                            let secret_process_guard = enter_c2_secret_process_interval();
                            let seed = self.load_seed_for_signing();
                            signing_key.sign(&preimage);
                            object_facts(&reopened);
                            drop(seed);
                            secret_process_guard.verify_same_process();
                        }
                    }
                """,
            }
        )

    def test_signer_process_fence_accepts_one_shared_spawn_boundary(self) -> None:
        self.assertEqual(
            MODULE._verify_signer_process_fence(self._process_fence_inventory()),
            (
                "signer-secret-fence=shared",
                "production-command-spawn-bypasses=0",
                "secret-process-recheck=after-zeroization",
            ),
        )

    def test_signer_process_fence_rejects_alternate_command_spawn(self) -> None:
        with self.assertRaisesRegex(
            MODULE.VerificationError, "production Command spawn bypasses"
        ):
            MODULE._verify_signer_process_fence(
                self._process_fence_inventory(alternate_spawn=True)
            )


if __name__ == "__main__":
    unittest.main()
