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


if __name__ == "__main__":
    unittest.main()
