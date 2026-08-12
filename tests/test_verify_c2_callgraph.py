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

    def test_scanner_does_not_treat_array_length_semicolon_as_trait_declaration(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                "fixture.rs": """
                    impl Actor {
                        fn accepts_identity(&self, identity: [u8; 32]) -> Result<(), Error> {
                            consume(identity);
                            Ok(())
                        }
                    }
                """
            }
        )
        function = inventory.require_function("fixture.rs", "accepts_identity", "Actor")
        self.assertFalse(function.declaration_only)
        self.assertEqual(len(function.calls("consume")), 1)

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

    def test_source_derived_io_manifest_is_deterministic_and_nonclaiming(self) -> None:
        texts = {
            "crates/nq-store/src/store_generation/b.rs": "fn b() { sync_all(); }",
            "crates/nq-store/src/store_generation/a.rs": "fn a() { execute(); write_all(); }",
        }
        first = MODULE.source_derived_io_manifest(
            MODULE.SourceInventory.from_texts(texts)
        )
        second = MODULE.source_derived_io_manifest(
            MODULE.SourceInventory.from_texts(dict(reversed(list(texts.items()))))
        )
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], "nq.c2_io_crash_cut_manifest.v1")
        self.assertEqual(
            [entry["cut"] for entry in first["nodes"]],
            ["SC-01", "SC-02", "SC-03"],
        )

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

    def test_schema_projection_gate_accepts_only_live_driver_owned_projection(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                MODULE.LIVE_C2: """
                    struct StoreC2SnapshotActorV1;
                    impl StoreC2SnapshotActorV1 {
                        pub(crate) fn install_c2_live_v1(&mut self) {
                            self.install_c2_live_with_observer_v1();
                        }
                        fn install_c2_live_with_observer_v1(&mut self) {}
                    }
                """,
                MODULE.HOST_RUNTIME: "fn ordinary_open() {}",
            }
        )
        self.assertEqual(
            MODULE._verify_schema_projection_gate(inventory),
            (
                "schema-v9-path-only-route=absent",
                "obsolete-schema-v9-permit=compile-confined",
                "schema-v9-sequencing=live-install-driver-owned",
            ),
        )

    def test_schema_projection_gate_rejects_the_path_only_runtime_bypass(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                MODULE.LIVE_C2: """
                    struct StoreC2SnapshotActorV1;
                    impl StoreC2SnapshotActorV1 {
                        pub(crate) fn install_c2_live_v1(&mut self) {
                            self.install_c2_live_with_observer_v1();
                        }
                        fn install_c2_live_with_observer_v1(&mut self) {}
                    }
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

    @staticmethod
    def _current_source_inventory(*paths: str) -> object:
        return MODULE.SourceInventory.from_texts(
            {
                path: (MODULE.ROOT / path).read_text(encoding="utf-8")
                for path in paths
            }
        )

    def test_live_signer_append_gate_accepts_only_actor_owned_durable_roots(self) -> None:
        inventory = self._current_source_inventory(
            MODULE.LIVE_C2,
            MODULE.SIGNER_COORDINATOR,
        )
        evidence = MODULE._verify_live_signer_append_gate(inventory)
        self.assertIn("durable-bg-append-owner=live-store-actor", evidence)

    def test_live_signer_append_gate_rejects_alternate_permit_constructor(self) -> None:
        paths = (MODULE.LIVE_C2, MODULE.SIGNER_COORDINATOR)
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        texts[MODULE.SIGNER_COORDINATOR] += """
            fn bypass_live_signer_permit() -> StoreC2SignerAppendPermitV1<'static, 'static, BootstrapV1> {
                StoreC2SignerAppendPermitV1 { live: panic!(), private: () }
            }
        """
        with self.assertRaisesRegex(
            MODULE.VerificationError, "constructor outside the closed actor roots"
        ):
            MODULE._verify_live_signer_append_gate(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_live_external_ingress_gate_accepts_one_store_terminal(self) -> None:
        inventory = self._current_source_inventory(
            MODULE.LIVE_C2,
            MODULE.SIGNER_GOVERNANCE,
            MODULE.SIGNER_MANIFEST,
            MODULE.SIGNER_CUSTODY,
            MODULE.SIGNER_RECORDS,
            MODULE.SIGNER_MOD,
            MODULE.SIGNER_MESSAGES,
            MODULE.C2_SIGNING_PROJECTION,
        )
        evidence = MODULE._verify_live_external_carrier_ingress_gate(inventory)
        self.assertIn(
            "terminal-A1-production-verifiers=1-live-store-same-snapshot", evidence
        )
        self.assertIn(
            "permit-expectation-join=actor+snapshot+epoch+process", evidence
        )

    def test_live_external_ingress_gate_rejects_missing_expectation_join(self) -> None:
        paths = (
            MODULE.LIVE_C2,
            MODULE.SIGNER_GOVERNANCE,
            MODULE.SIGNER_MANIFEST,
            MODULE.SIGNER_CUSTODY,
            MODULE.SIGNER_RECORDS,
            MODULE.SIGNER_MOD,
            MODULE.SIGNER_MESSAGES,
            MODULE.C2_SIGNING_PROJECTION,
        )
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        needle = "permit.verify_expectation_basis(expectation)?;"
        self.assertEqual(texts[MODULE.SIGNER_GOVERNANCE].count(needle), 2)
        texts[MODULE.SIGNER_GOVERNANCE] = texts[MODULE.SIGNER_GOVERNANCE].replace(
            needle, "permit.verify_current_actor()?;", 1
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "do not both enforce the expectation join",
        ):
            MODULE._verify_live_external_carrier_ingress_gate(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_closed_live_c2_roots_cover_all_four_lineages_and_recovery_prepare(self) -> None:
        inventory = self._current_source_inventory(MODULE.LIVE_C2)
        paths = MODULE._special_path_inventory(inventory)
        self.assertEqual(
            [identity.name for identity in paths.special_roots],
            [
                "prepare_c2_live_bootstrap_v1",
                "install_c2_live_from_bootstrap_grant_v1",
                "rotate_c2_live_healthy_successor_v1",
                "rotate_c2_live_healthy_successor_with_activation_grant_v1",
                "restore_c2_live_historical_foundation_v1",
                "prepare_c2_live_recovery_v1",
                "recover_c2_live_new_foundation_v1",
            ],
        )

    def test_closed_live_c2_root_census_rejects_alternate_store_surface(self) -> None:
        text = (MODULE.ROOT / MODULE.LIVE_C2).read_text(encoding="utf-8")
        text += """
            impl Store {
                pub(crate) fn alternate_c2_authority_root(&mut self) {}
            }
        """
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "closed eight-root API",
        ):
            MODULE._special_path_inventory(
                MODULE.SourceInventory.from_texts({MODULE.LIVE_C2: text})
            )

    def test_public_c2_facade_reaches_exact_eight_internal_roots(self) -> None:
        inventory = self._current_source_inventory(
            MODULE.STORE_GENERATION_MOD,
            MODULE.CANDIDATE_QUALIFICATION,
            MODULE.C2_LIFECYCLE,
            MODULE.LIVE_C2,
        )
        evidence = MODULE._verify_public_c2_lifecycle_facade(inventory)
        self.assertIn("public-c2-root-delegations=8/8", evidence)
        self.assertIn("public-writer-shell=borrowed-nonescaping", evidence)
        self.assertIn(
            "candidate-runtime-verifier=fixed-root+signature+candidate-basis+manifest+self-measurement",
            evidence,
        )
        self.assertIn(
            "qualification-root-custody=root+etc+nq+file-nofollow", evidence
        )
        self.assertIn(
            "candidate-runtime-bridge=authenticated-certificate-only", evidence
        )

    def test_public_c2_facade_rejects_second_internal_root_caller(self) -> None:
        paths = (
            MODULE.STORE_GENERATION_MOD,
            MODULE.CANDIDATE_QUALIFICATION,
            MODULE.C2_LIFECYCLE,
            MODULE.LIVE_C2,
        )
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        texts[MODULE.C2_LIFECYCLE] += """
            fn alternate_bootstrap_root(store: &mut Store) {
                store.prepare_c2_live_bootstrap_v1();
            }
        """
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "non-facade or duplicate production caller",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_public_c2_facade_rejects_generic_route_operation(self) -> None:
        paths = (
            MODULE.STORE_GENERATION_MOD,
            MODULE.CANDIDATE_QUALIFICATION,
            MODULE.C2_LIFECYCLE,
            MODULE.LIVE_C2,
        )
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        texts[MODULE.C2_LIFECYCLE] += """
            impl StoreC2LifecycleV1<'_> {
                pub fn execute_route(&mut self, route: C2StoreSigningRouteV1, bytes: &[u8]) {
                    let _ = (route, bytes);
                }
            }
        """
        with self.assertRaises(MODULE.VerificationError):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_public_c2_facade_rejects_raw_bootstrap_authority_tuple(self) -> None:
        paths = (
            MODULE.STORE_GENERATION_MOD,
            MODULE.CANDIDATE_QUALIFICATION,
            MODULE.C2_LIFECYCLE,
            MODULE.LIVE_C2,
        )
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        needle = "pub struct C2BootstrapInstallSelectionV1 {"
        self.assertEqual(texts[MODULE.C2_LIFECYCLE].count(needle), 1)
        texts[MODULE.C2_LIFECYCLE] = texts[MODULE.C2_LIFECYCLE].replace(
            needle,
            needle + "\n    pub authority: C2InstallAuthorityTupleV1,",
            1,
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "caller-authored bootstrap authority tuple",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    @staticmethod
    def _candidate_verifier_source_texts() -> dict[str, str]:
        paths = (
            MODULE.STORE_GENERATION_MOD,
            MODULE.CANDIDATE_QUALIFICATION,
            MODULE.C2_LIFECYCLE,
            MODULE.LIVE_C2,
        )
        return {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }

    def test_candidate_verifier_rejects_caller_selected_trust_key(self) -> None:
        texts = self._candidate_verifier_source_texts()
        needle = """pub fn verify_candidate_runtime(
        certificate_bytes: &[u8],
        manifest: &C2SignerImplementationManifestV1,"""
        self.assertEqual(texts[MODULE.C2_LIFECYCLE].count(needle), 1)
        texts[MODULE.C2_LIFECYCLE] = texts[MODULE.C2_LIFECYCLE].replace(
            needle,
            needle + "\n        qualification_key: &[u8],",
            1,
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "caller-selected trust key or raw coordinate",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_candidate_verifier_rejects_signature_verification_bypass(self) -> None:
        texts = self._candidate_verifier_source_texts()
        needle = ".verify_strict("
        self.assertEqual(texts[MODULE.CANDIDATE_QUALIFICATION].count(needle), 1)
        texts[MODULE.CANDIDATE_QUALIFICATION] = texts[
            MODULE.CANDIDATE_QUALIFICATION
        ].replace(needle, ".accept_without_verification(", 1)
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "verify_strict exactly once",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_candidate_verifier_rejects_caller_artifact_substitution(self) -> None:
        texts = self._candidate_verifier_source_texts()
        needle = "measure_current_runtime_artifact()"
        self.assertGreaterEqual(
            texts[MODULE.CANDIDATE_QUALIFICATION].count(needle), 1
        )
        texts[MODULE.CANDIDATE_QUALIFICATION] = texts[
            MODULE.CANDIDATE_QUALIFICATION
        ].replace(
            needle,
            "wire.unsigned.runtime_artifact_identity.clone()",
            1,
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "measure_current_runtime_artifact exactly once",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_candidate_verifier_rejects_alternate_raw_record_conversion(self) -> None:
        texts = self._candidate_verifier_source_texts()
        texts[MODULE.LIVE_C2] += """
            impl VerifiedC2ExternalCandidateRuntimeRecordV1 {
                pub(in crate::store_generation) fn from_raw_coordinates(
                    candidate: Sha256Digest,
                    tree: Sha256Digest,
                    artifact: Sha256Digest,
                ) -> Self {
                    let _ = (candidate, tree, artifact);
                    loop {}
                }
            }
        """
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "authenticated typed certificate",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_candidate_verifier_rejects_flat_trust_path_custody(self) -> None:
        texts = self._candidate_verifier_source_texts()
        needle = 'let etc = open_fixed_trust_directory_component(&filesystem_root, "etc")?;'
        self.assertEqual(texts[MODULE.CANDIDATE_QUALIFICATION].count(needle), 1)
        texts[MODULE.CANDIDATE_QUALIFICATION] = texts[
            MODULE.CANDIDATE_QUALIFICATION
        ].replace(needle, "let etc = filesystem_root.try_clone()?;", 1)
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "component-wise fixed-path custody",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_candidate_verifier_rejects_unrecomputed_candidate_basis(self) -> None:
        texts = self._candidate_verifier_source_texts()
        needle = (
            "qualified_candidate_identity(&wire.unsigned)?\n            "
            "!= wire.unsigned.qualified_candidate_identity"
        )
        self.assertEqual(texts[MODULE.CANDIDATE_QUALIFICATION].count(needle), 1)
        texts[MODULE.CANDIDATE_QUALIFICATION] = texts[
            MODULE.CANDIDATE_QUALIFICATION
        ].replace(
            needle,
            "wire.unsigned.qualified_candidate_identity "
            "!= wire.unsigned.qualified_candidate_identity",
            1,
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "exact commit/tree/candidate basis",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_candidate_verifier_rejects_manifest_source_map_bypass(self) -> None:
        texts = self._candidate_verifier_source_texts()
        needle = "manifest_source_files_identity(manifest)?"
        self.assertEqual(texts[MODULE.CANDIDATE_QUALIFICATION].count(needle), 1)
        texts[MODULE.CANDIDATE_QUALIFICATION] = texts[
            MODULE.CANDIDATE_QUALIFICATION
        ].replace(
            needle,
            "wire.unsigned.manifest_source_files_identity.clone()",
            1,
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "fixed-root signature, manifest, or runtime-measurement chain",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_candidate_verifier_rejects_durable_mutation_surface(self) -> None:
        texts = self._candidate_verifier_source_texts()
        texts[MODULE.CANDIDATE_QUALIFICATION] += """
            fn persist_unverified_candidate(file: &mut File, bytes: &[u8]) {
                file.write_all(bytes).unwrap();
            }
        """
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "Store or durable mutation path",
        ):
            MODULE._verify_public_c2_lifecycle_facade(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_post_msg07_refresh_is_required_before_predecessor_authority(self) -> None:
        paths = (MODULE.LIVE_C2, MODULE.SIGNER_COORDINATOR)
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        needle = (
            "self.refresh_current_predecessor_after_msg07_v1("
            "current, pending, &possession)?;"
        )
        self.assertEqual(texts[MODULE.LIVE_C2].count(needle), 1)
        texts[MODULE.LIVE_C2] = texts[MODULE.LIVE_C2].replace(
            needle, "current.verify_live(self)?;", 1
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "omits or duplicates refresh/authority/MSG-06 construction",
        ):
            MODULE._verify_post_msg07_predecessor_refresh_before_msg06(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_post_msg07_refresh_must_bind_consumed_frontier(self) -> None:
        paths = (MODULE.LIVE_C2, MODULE.SIGNER_COORDINATOR)
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        needle = "possession.resulting_frontier_identity();"
        self.assertEqual(texts[MODULE.LIVE_C2].count(needle), 1)
        texts[MODULE.LIVE_C2] = texts[MODULE.LIVE_C2].replace(
            needle, "pending.coordinates.predecessor_frontier_identity;", 1
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "does not bind the exact consumed MSG-07 result",
        ):
            MODULE._verify_post_msg07_predecessor_refresh_before_msg06(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_completed_transition_must_refuse_before_successor_custody(self) -> None:
        paths = {
            MODULE.LIVE_C2,
            MODULE.SIGNER_COORDINATOR,
        }
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        exact_terminal_query = (
            "SELECT 1 FROM c2_signer_succession_projection\n"
            "                    WHERE transition_identity = ?1"
        )
        self.assertIn(exact_terminal_query, texts[MODULE.LIVE_C2])
        texts[MODULE.LIVE_C2] = texts[MODULE.LIVE_C2].replace(
            exact_terminal_query,
            "SELECT 1 FROM c2_signer_message_appends\n"
            "                    WHERE message_identity = ?1",
            1,
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "pre-custody terminal-transition one-use refusal",
        ):
            MODULE._verify_post_msg07_predecessor_refresh_before_msg06(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_io_manifest_excludes_test_harness_io(self) -> None:
        inventory = MODULE.SourceInventory.from_texts(
            {
                "crates/nq-store/src/store_generation/product.rs": """
                    fn product_cut() { backend.open(); }
                    #[test]
                    fn inline_test_cut() { fixture.open(); }
                """,
                "crates/nq-store/src/store_generation/product_crash_tests.rs": """
                    fn module_test_helper() { fixture.open(); }
                """,
            }
        )
        nodes = MODULE._collect_io_nodes(inventory).nodes
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].function, "product_cut")

    def test_test_confinement_accepts_test_module_and_rejects_product_helper(self) -> None:
        confined = MODULE.SourceInventory.from_texts(
            {
                "crates/nq-store/src/store_generation/live_c2_hostile_tests.rs": """
                    fn exact_hostile_fixture_for_test() {}
                """,
            }
        )
        self.assertIn("test-helper-leaks=0", MODULE._verify_test_confinement(confined))

        leaked = MODULE.SourceInventory.from_texts(
            {
                "crates/nq-store/src/store_generation/product.rs": """
                    fn product_fixture_for_test() {}
                """,
            }
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "C2 test helper is in the product graph",
        ):
            MODULE._verify_test_confinement(leaked)

    def test_live_external_ingress_gate_rejects_second_terminal_verifier(self) -> None:
        paths = (MODULE.LIVE_C2, MODULE.SIGNER_GOVERNANCE)
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        texts[MODULE.SIGNER_GOVERNANCE] += """
            struct AlternateTerminalA1VerifierV1;
            impl TerminalA1AuthenticityVerifierV1 for AlternateTerminalA1VerifierV1 {
                fn verify_unique_terminal_a1(
                    &self,
                    _request_identity: &ExternalCarrierIdentityV1,
                    _carrier_identity: &ExternalCarrierIdentityV1,
                    _asserted_terminal: &CanonicalRecordId,
                    _asserted_cut: u64,
                    _asserted_scope: &BTreeMap<String, Value>,
                ) -> Result<(), SignerRefusalV2> { Ok(()) }
            }
        """
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "exactly one live Store same-snapshot implementation",
        ):
            MODULE._verify_live_external_carrier_ingress_gate(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_live_authority_noninjectability_accepts_current_types_and_mints(self) -> None:
        inventory = self._current_source_inventory(
            MODULE.LIVE_C2,
            MODULE.SIGNER_GOVERNANCE,
            MODULE.SIGNER_MANIFEST,
            MODULE.SIGNER_CUSTODY,
            MODULE.SIGNER_RECORDS,
            MODULE.SIGNER_MOD,
            MODULE.SIGNER_MESSAGES,
            MODULE.C2_SIGNING_PROJECTION,
        )
        evidence = MODULE._verify_live_authority_noninjectability(inventory)
        self.assertIn("live-context-constructors=7-store-owned", evidence)
        self.assertIn("nominal-live-authority-constructors=8-store-owned", evidence)
        self.assertIn("writer-session-constructor=complete-current-only", evidence)
        self.assertIn("live-authority-transfer-traits=absent", evidence)

    def test_live_authority_noninjectability_rejects_cloneable_context(self) -> None:
        paths = (
            MODULE.LIVE_C2,
            MODULE.SIGNER_GOVERNANCE,
            MODULE.SIGNER_MANIFEST,
            MODULE.SIGNER_CUSTODY,
            MODULE.SIGNER_RECORDS,
            MODULE.SIGNER_MOD,
            MODULE.SIGNER_MESSAGES,
            MODULE.C2_SIGNING_PROJECTION,
        )
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        needle = "pub(crate) struct C2LiveSignerContextV1<'live, 'store, Phase> {"
        self.assertIn(needle, texts[MODULE.LIVE_C2])
        texts[MODULE.LIVE_C2] = texts[MODULE.LIVE_C2].replace(
            needle,
            "#[derive(Clone)]\n" + needle,
            1,
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "implements a transferable/serializable trait",
        ):
            MODULE._verify_live_authority_noninjectability(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_live_authority_noninjectability_rejects_public_generic_signer(self) -> None:
        paths = (
            MODULE.LIVE_C2,
            MODULE.SIGNER_GOVERNANCE,
            MODULE.SIGNER_MANIFEST,
            MODULE.SIGNER_CUSTODY,
            MODULE.SIGNER_RECORDS,
            MODULE.SIGNER_MOD,
            MODULE.SIGNER_MESSAGES,
            MODULE.C2_SIGNING_PROJECTION,
        )
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        texts[MODULE.C2_SIGNING_PROJECTION] += """
            pub fn sign_arbitrary_c2_route(
                route: C2StoreSigningRouteV1,
                key: &[u8],
                bytes: &[u8],
            ) -> Vec<u8> { let _ = (route, key); bytes.to_vec() }
        """
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "restricted to inert registry metadata",
        ):
            MODULE._verify_live_authority_noninjectability(
                MODULE.SourceInventory.from_texts(texts)
            )

    def test_live_authority_noninjectability_rejects_alternate_nominal_mint(self) -> None:
        paths = (
            MODULE.LIVE_C2,
            MODULE.SIGNER_GOVERNANCE,
            MODULE.SIGNER_MANIFEST,
            MODULE.SIGNER_CUSTODY,
            MODULE.SIGNER_RECORDS,
            MODULE.SIGNER_MOD,
            MODULE.SIGNER_MESSAGES,
            MODULE.C2_SIGNING_PROJECTION,
        )
        texts = {
            path: (MODULE.ROOT / path).read_text(encoding="utf-8") for path in paths
        }
        texts[MODULE.LIVE_C2] += """
            fn alternate_restore_entry_constructor() {
                let _forged = StoreVerifiedRestoreEntryAuthorityV1 {};
            }
        """
        with self.assertRaisesRegex(
            MODULE.VerificationError,
            "StoreVerifiedRestoreEntryAuthorityV1 does not have exactly one nominal Store-actor constructor",
        ):
            MODULE._verify_live_authority_noninjectability(
                MODULE.SourceInventory.from_texts(texts)
            )

    @staticmethod
    def _fence_manifests(*, helper_depends_on_store: bool = False):
        helper_dependencies = {"libc": {}, "nix": {}}
        if helper_depends_on_store:
            helper_dependencies["nq-store"] = {"path": "../nq-store"}
        return {
            MODULE.HELPER_SANDBOX_MANIFEST: {
                "package": {"name": "nq-helper-sandbox"},
                "dependencies": helper_dependencies,
            },
            MODULE.STORE_MANIFEST: {
                "package": {"name": "nq-store"},
                "dependencies": {"nq-helper-sandbox": {"path": "../nq-helper-sandbox"}},
            },
        }

    @classmethod
    def _process_fence_inventory(
        cls,
        *,
        alternate_spawn: bool = False,
        choke_fence: str = "first",
        loader_output: bool = False,
        poison_recovery: bool = False,
        second_fence_static: bool = False,
        custody_recheck: bool = True,
        custody_acquire_late: bool = False,
        custody_command: bool = False,
        feature_gated_spawn: bool = False,
        fence_reset_api: bool = False,
        row_constructor_spawns: bool = False,
        helper_depends_on_store: bool = False,
    ):
        lock_expression = (
            "C2_FORK_FENCE.lock().unwrap_or_else(PoisonError::into_inner)"
            if poison_recovery
            else 'C2_FORK_FENCE.lock().map_err(|_| io::Error::other("poisoned"))?'
        )
        reset_function = (
            """
            pub fn reset_fork_fence() {
                C2_FORK_FENCE.clear_poison();
            }
            """
            if fence_reset_api
            else ""
        )
        choke_fence_first = """
            let _fork_fence = C2ForkFence::acquire()?;
            let _guard = DESCRIPTOR_LAUNCH.lock().map_err(|_| io::Error::other("poisoned"))?;
        """
        choke_body_lock = {
            "first": choke_fence_first,
            "missing": """
            let _guard = DESCRIPTOR_LAUNCH.lock().map_err(|_| io::Error::other("poisoned"))?;
            """,
            "late": """
            let _guard = DESCRIPTOR_LAUNCH.lock().map_err(|_| io::Error::other("poisoned"))?;
            let _fork_fence = C2ForkFence::acquire()?;
            """,
        }[choke_fence]
        alternate = (
            "fn bypass(command: &mut Command) { let _ = command.spawn(); }"
            if alternate_spawn
            else ""
        )
        second_static = (
            "static SECOND_FORK_FENCE: Mutex<()> = Mutex::new(());"
            if second_fence_static
            else ""
        )
        feature_gated = (
            """
            #[cfg(feature = "extended-helper")]
            fn gated_helper(command: &mut Command) { let _ = command.output(); }
            """
            if feature_gated_spawn
            else ""
        )
        row_constructor_body = (
            "Ok(command.spawn()?)"
            if row_constructor_spawns
            else "spawn_with_inherited_descriptors(command, descriptors)"
        )
        loader_body = (
            """
            let mut command = Command::new(loader);
            isolate_command(&mut command, account);
            let output = command.output()?;
            drain(output)
            """
            if loader_output
            else """
            let mut command = Command::new(loader);
            isolate_command(&mut command, account);
            let child = spawn_with_inherited_descriptors(&mut command, &[descriptor])?;
            drain(child)
            """
        )
        create_acquire = (
            ""
            if custody_acquire_late
            else "let fork_fence_guard = C2ForkFence::acquire().map_err(|_| SignerRefusalV2::CustodyIo)?;"
        )
        create_acquire_late = (
            "let fork_fence_guard = C2ForkFence::acquire().map_err(|_| SignerRefusalV2::CustodyIo)?;"
            if custody_acquire_late
            else ""
        )
        create_recheck = (
            "fork_fence_guard.verify_same_process().map_err(|_| SignerRefusalV2::CustodyIo)?;"
            if custody_recheck
            else ""
        )
        custody_process = (
            """
            fn hold_command(command: &mut Command) {
                let _ = command;
            }
            """
            if custody_command
            else ""
        )
        inventory = MODULE.SourceInventory.from_texts(
            {
                MODULE.HELPER_SANDBOX: f"""
                    static C2_FORK_FENCE: Mutex<()> = Mutex::new(());
                    thread_local! {{
                        static C2_FORK_FENCE_HELD: Cell<bool> = const {{ Cell::new(false) }};
                    }}
                    pub struct C2ForkFence;
                    impl C2ForkFence {{
                        pub fn acquire() -> io::Result<C2ForkFenceGuard> {{
                            C2_FORK_FENCE_HELD.with(|held| {{
                                if held.get() {{ return Err(io::Error::other("non-reentrant")); }}
                                let guard = {lock_expression};
                                held.set(true);
                                Ok(C2ForkFenceGuard {{ _guard: guard, owner_pid: std::process::id() }})
                            }})
                        }}
                    }}
                    pub struct C2ForkFenceGuard {{
                        _guard: MutexGuard<'static, ()>,
                        owner_pid: u32,
                    }}
                    impl C2ForkFenceGuard {{
                        pub fn verify_same_process(&self) -> io::Result<()> {{
                            if std::process::id() != self.owner_pid {{
                                return Err(io::Error::other("crossed"));
                            }}
                            Ok(())
                        }}
                    }}
                    impl Drop for C2ForkFenceGuard {{
                        fn drop(&mut self) {{
                            let _ = C2_FORK_FENCE_HELD.try_with(|held| held.set(false));
                        }}
                    }}
                    pub fn construct_sg_wu_02_fence_shared_process_global_fork_fence_primitive() -> C2ForkFence {{
                        C2ForkFence
                    }}
                    pub fn verify_sg_wu_02_fence_shared_process_global_fork_fence_primitive(
                        fence: &C2ForkFence,
                    ) -> io::Result<()> {{
                        let _ = fence;
                        let guard = C2ForkFence::acquire()?;
                        guard.verify_same_process()
                    }}
                    {reset_function}
                """,
                MODULE.CORE_IDENTITY: f"""
                    static DESCRIPTOR_LAUNCH: Mutex<()> = Mutex::new(());
                    {second_static}
                    pub(crate) fn spawn_with_inherited_descriptors(
                        command: &mut Command,
                        descriptors: &[i32],
                    ) -> io::Result<Child> {{
                        {choke_body_lock}
                        let original_flags = make_inheritable(descriptors)?;
                        let spawned = command.spawn();
                        let restored = restore_descriptor_flags(descriptors, &original_flags);
                        match (spawned, restored) {{
                            (Ok(child), Ok(())) => Ok(child),
                            (Err(error), _) => Err(error),
                            (_, Err(error)) => Err(error),
                        }}
                    }}
                    pub(crate) fn construct_sg_wu_02_spawn_production_spawn_integration_shared_fence(
                        command: &mut Command,
                        descriptors: &[i32],
                    ) -> io::Result<Child> {{
                        {row_constructor_body}
                    }}
                    pub(crate) fn verify_sg_wu_02_spawn_production_spawn_integration_shared_fence() -> io::Result<()> {{
                        let guard = C2ForkFence::acquire()?;
                        guard.verify_same_process()
                    }}
                    struct VerifiedLaunch;
                    impl VerifiedLaunch {{
                        pub(crate) fn spawn(&self, configure: impl FnOnce(&mut Command)) -> io::Result<Child> {{
                            let mut command = Command::new(&self.executable);
                            configure(&mut command);
                            let descriptors = self.inherited_descriptors();
                            spawn_with_inherited_descriptors(&mut command, &descriptors)
                        }}
                    }}
                    {alternate}
                    {feature_gated}
                """,
                MODULE.CORE_RUNTIME: f"""
                    fn invoke_loader(
                        loader: &Path,
                        descriptor: i32,
                        account: &ExecutionAccount,
                    ) -> Result<Vec<u8>, IdentityError> {{
                        {loader_body}
                    }}
                """,
                MODULE.CORE_RUNNER: """
                    fn spawn(launch: &VerifiedLaunch) -> io::Result<Child> {
                        launch.spawn(|command| {
                            command.env_clear();
                        })
                    }
                """,
                MODULE.CORE_UNIX_RUNNER: """
                    fn spawn_helper(launch: &VerifiedLaunch) -> io::Result<Child> {
                        launch.spawn(|command| {
                            command.env_clear();
                        })
                    }
                """,
                MODULE.SIGNER_CUSTODY: f"""
                    struct C2StoreIntegrityCustodian;
                    impl C2StoreIntegrityCustodian {{
                        fn create_below_root() {{
                            {create_acquire}
                            coordinates.validate()?;
                            let scope_mutex = custody_scope_mutex(&scope_token);
                            let _scope_guard = scope_mutex.lock().map_err(|_| SignerRefusalV2::CustodyIo)?;
                            getrandom::fill(&mut seed).map_err(|_| SignerRefusalV2::CustodyIo)?;
                            {create_acquire_late}
                            bytes.fill(0);
                            drop(private_file);
                            drop(seed);
                            {create_recheck}
                        }}
                        fn sign(&self) {{
                            self.sign_after_authority_checks();
                        }}
                        fn sign_initial_possession(&self) {{
                            self.sign_after_authority_checks();
                        }}
                        #[cfg(test)]
                        fn sign_for_custody_hostile_test(&self) {{
                            self.sign_after_authority_checks();
                        }}
                        fn sign_after_authority_checks(&self) {{
                            let fork_fence_guard = C2ForkFence::acquire().map_err(|_| SignerRefusalV2::CustodyIo)?;
                            let (seed, retained_file, retained_facts) = self.load_seed_for_signing()?;
                            signing_key.sign(&preimage);
                            object_facts(&reopened)?;
                            drop(retained_file);
                            drop(signing_key);
                            drop(seed);
                            {create_recheck}
                        }}
                    }}
                    {custody_process}
                """,
            }
        )
        return inventory, cls._fence_manifests(
            helper_depends_on_store=helper_depends_on_store
        )

    def test_signer_process_fence_accepts_one_shared_spawn_boundary(self) -> None:
        inventory, manifests = self._process_fence_inventory()
        self.assertEqual(
            MODULE._verify_signer_process_fence(inventory, manifests),
            (
                "signer-secret-fence=shared",
                "production-command-spawn-bypasses=0",
                "secret-process-recheck=after-zeroization",
                "fork-fence-owner=one-process-global",
                "fork-fence-poison-recovery=absent",
                "fork-fence-nonreentrancy=thread-local",
                "guard-lock-accessor=absent",
                "fence-api=authority-neutral",
                "spawn-choke=fence-before-descriptor-handoff",
                "process-creation-bypasses=0",
                "loader-and-runner-routes=single-choke",
                "spawn-row-constructor=delegates-only",
                "custody-secret-intervals=fenced-entry-to-recheck",
                "secret-interval-process-creation=0",
                "command-secret-material=absent",
                "fence-dependency-direction=helper-sandbox-leaf",
                "fence-reset-bypass=absent",
            ),
        )

    def test_signer_process_fence_rejects_alternate_command_spawn(self) -> None:
        inventory, manifests = self._process_fence_inventory(alternate_spawn=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "production Command spawn bypasses"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_choke_missing_fence(self) -> None:
        inventory, manifests = self._process_fence_inventory(choke_fence="missing")
        with self.assertRaisesRegex(
            MODULE.VerificationError, "does not hold the C2 fork fence"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_fence_after_descriptor_lock(self) -> None:
        inventory, manifests = self._process_fence_inventory(choke_fence="late")
        with self.assertRaisesRegex(
            MODULE.VerificationError, "does not hold the C2 fork fence"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_loader_command_output(self) -> None:
        inventory, manifests = self._process_fence_inventory(loader_output=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "process creation bypasses the fenced choke"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_poison_recovery(self) -> None:
        inventory, manifests = self._process_fence_inventory(poison_recovery=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "fence poison recovery is present"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_second_fence_static(self) -> None:
        inventory, manifests = self._process_fence_inventory(second_fence_static=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "second fork/fence process mutex"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_custody_missing_process_recheck(self) -> None:
        inventory, manifests = self._process_fence_inventory(custody_recheck=False)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "does not fence its complete live-secret interval"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_custody_acquire_after_random_fill(self) -> None:
        inventory, manifests = self._process_fence_inventory(custody_acquire_late=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "does not fence its complete live-secret interval"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_command_in_custody(self) -> None:
        inventory, manifests = self._process_fence_inventory(custody_command=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "signer custody path creates a process"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_feature_gated_spawn(self) -> None:
        inventory, manifests = self._process_fence_inventory(feature_gated_spawn=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "feature-gated production function creates processes"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_helper_manifest_store_dependency(self) -> None:
        inventory, manifests = self._process_fence_inventory(helper_depends_on_store=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "nq-helper-sandbox depends upward"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_fence_reset_api(self) -> None:
        inventory, manifests = self._process_fence_inventory(fence_reset_api=True)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "fence poison recovery is present"
        ):
            MODULE._verify_signer_process_fence(inventory, manifests)

    def test_signer_process_fence_rejects_non_delegating_spawn_row_constructor(self) -> None:
        inventory, manifests = self._process_fence_inventory(row_constructor_spawns=True)
        with self.assertRaises(MODULE.VerificationError):
            MODULE._verify_signer_process_fence(inventory, manifests)


if __name__ == "__main__":
    unittest.main()
