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
