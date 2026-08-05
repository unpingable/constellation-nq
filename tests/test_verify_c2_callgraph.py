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


if __name__ == "__main__":
    unittest.main()
