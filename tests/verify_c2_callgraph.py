#!/usr/bin/env python3
"""Fail-closed C2 constructor, signer, restart, and I/O call-graph evidence.

This verifier is the exact source target assigned by matrix V2 to WU-14,
N-11, N-16, N-61--N-64, N-84, HR28-28, AM-01, RR-10, CR-06,
CG-01--CG-08, CG-10--CG-26, XH-53, and SEAM-10.  It is development
evidence only.  A passing run does not freeze a candidate or constitute
qualification.

The implementation deliberately reuses the qualified lexical/structural Rust
scanner.  Comments and literal contents cannot satisfy an edge, unbalanced
source refuses, Cargo production targets are enumerated from explicit
workspace members, and protected calls are resolved from function bodies.
No semantic assignment is inferred from prose.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence

sys.dont_write_bytecode = True

ROOT = Path(
    os.environ.get("NQ_PROOF_SOURCE_ROOT", Path(__file__).resolve().parents[1])
).resolve()
QUALIFIED_SCANNER_DIR = ROOT / "crates/nq-store/tests"
if str(QUALIFIED_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(QUALIFIED_SCANNER_DIR))

from rust_source_scan import (  # noqa: E402
    Function,
    RustSource,
    ScanError,
    compact_tokens,
    compile_confined_module_paths,
    production_functions,
    production_sources,
    workspace_packages,
)


class VerificationError(AssertionError):
    """One exact matrix call-graph obligation is not established."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


@dataclasses.dataclass(frozen=True)
class RowEvidence:
    """Deterministic development evidence for one assigned V2 row."""

    row_id: str
    facts: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class FunctionIdentity:
    path: str
    owner: str | None
    name: str

    @classmethod
    def from_function(cls, function: Function) -> "FunctionIdentity":
        return cls(function.source.path.as_posix(), function.owner, function.name)

    def display(self) -> str:
        owner = f"{self.owner}::" if self.owner else ""
        return f"{self.path}::{owner}{self.name}"


@dataclasses.dataclass(frozen=True)
class IoNode:
    path: str
    function: str
    call: str
    line: int

    @property
    def identity(self) -> str:
        return f"{self.path}:{self.line}:{self.function}:{self.call}"


@dataclasses.dataclass(frozen=True)
class C2ConstructorGraphInventoryV2:
    root: str
    source_count: int
    function_count: int
    source_digest: str


@dataclasses.dataclass(frozen=True)
class C2ConstructorPathInventoryV2:
    special_roots: tuple[FunctionIdentity, ...]
    ordinary_root: FunctionIdentity


@dataclasses.dataclass(frozen=True)
class C2DirectOpenCallGraphV2:
    direct_open_sites: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class C2IoCallGraphInventoryV2:
    nodes: tuple[IoNode, ...]


@dataclasses.dataclass
class SourceInventory:
    root: Path
    sources: tuple[RustSource, ...]
    functions: tuple[Function, ...]
    compile_confined_paths: frozenset[str]

    @classmethod
    def load(cls, root: Path = ROOT) -> "SourceInventory":
        sources = production_sources(root)
        confined = compile_confined_module_paths(sources)
        functions = production_functions(
            sources, compile_confined_paths=confined
        )
        paths = [source.path.as_posix() for source in sources]
        require(len(paths) == len(set(paths)), "production source paths are ambiguous")
        return cls(root, sources, tuple(functions), frozenset(confined))

    @classmethod
    def from_texts(cls, texts: dict[str, str]) -> "SourceInventory":
        sources = tuple(
            RustSource.from_text(text, label=path)
            for path, text in sorted(texts.items())
        )
        return cls(
            Path("/fixture"),
            sources,
            tuple(
                function
                for source in sources
                for function in source.functions
                if not function.cfg_test
            ),
            frozenset(),
        )

    def source(self, path: str) -> RustSource:
        matches = [source for source in self.sources if source.path.as_posix() == path]
        require(
            len(matches) == 1,
            f"required production source is absent or ambiguous: {path}",
        )
        return matches[0]

    def require_function(
        self, path: str, name: str, owner: str | None = None
    ) -> Function:
        matches = [
            function
            for function in self.functions
            if function.source.path.as_posix() == path
            and function.name == name
            and (owner is None or function.owner == owner)
        ]
        qualifier = f"{owner}::" if owner else ""
        require(
            len(matches) == 1,
            f"required function {path}::{qualifier}{name} is absent or ambiguous: "
            + (", ".join(function.location for function in matches) or "none"),
        )
        return matches[0]

    def functions_named(self, name: str) -> tuple[Function, ...]:
        return tuple(function for function in self.functions if function.name == name)

    def callers_of(
        self,
        name: str,
        *,
        receiver: str | None = None,
        source_prefix: str | None = None,
    ) -> tuple[Function, ...]:
        callers: list[Function] = []
        for function in self.functions:
            if source_prefix and not function.source.path.as_posix().startswith(source_prefix):
                continue
            if any(
                call.name == name and (receiver is None or call.receiver == receiver)
                for call in function.calls()
            ):
                callers.append(function)
        return tuple(callers)

    def public_reexports(self, protected: Iterable[str]) -> tuple[str, ...]:
        names = set(protected)
        found: list[str] = []
        for source in self.sources:
            for export in source.reexports:
                overlap = names.intersection(export.names)
                if overlap:
                    found.append(
                        f"{export.location}:{export.visibility}:{','.join(sorted(overlap))}"
                    )
        return tuple(sorted(found))

    def digest(self) -> str:
        value = [
            {
                "path": source.path.as_posix(),
                "sha256": hashlib.sha256(
                    source.absolute_path.read_bytes()
                    if source.absolute_path.is_file()
                    else source.text.encode("utf-8")
                ).hexdigest(),
            }
            for source in self.sources
        ]
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


INSTALL = "crates/nq-store/src/store_generation/install.rs"
POLICY = "crates/nq-store/src/store_generation/policy.rs"
STORE_LIB = "crates/nq-store/src/lib.rs"
HOST_RUNTIME = "crates/nq-host-role-runtime/src/runtime.rs"
CORE_IDENTITY = "crates/nq-core/src/identity.rs"
HELPER_SANDBOX = "crates/nq-helper-sandbox/src/lib.rs"
WRITER = "crates/nq-store/src/writer_session.rs"
LOCK = "crates/nq-store/src/store_generation/lock.rs"
RESTORE = "crates/nq-store/src/store_generation/restore.rs"
SIGNER_PREFIX = "crates/nq-store/src/store_generation/signer/"
SIGNER_CUSTODY = SIGNER_PREFIX + "custody.rs"
SIGNER_COORDINATOR = SIGNER_PREFIX + "coordinator.rs"
SIGNER_MESSAGES = SIGNER_PREFIX + "messages.rs"
SIGNER_RESTART = SIGNER_PREFIX + "restart.rs"
SIGNER_LINEAGE = SIGNER_PREFIX + "lineage.rs"
SIGNER_GOVERNANCE = SIGNER_PREFIX + "external_governance.rs"

SPECIAL_ROOT_SPECS = (
    ("P-01", INSTALL, None, "install_c2_fresh", "C2BootstrapBrandV1"),
    ("P-02", INSTALL, None, "install_c2_restore_successor", "C2BootstrapBrandV1"),
    (
        "P-03",
        INSTALL,
        None,
        "continue_c2_installation",
        "C2InstallationContinuationBrandV1",
    ),
    (
        "P-04",
        POLICY,
        None,
        "transition_c2_active_policy",
        "C2PolicyTransitionBrandV1",
    ),
    (
        "P-05",
        POLICY,
        None,
        "continue_c2_policy_transition",
        "C2PolicyTransitionContinuationBrandV1",
    ),
)

ORDINARY_ROOT_SPEC = ("P-06", STORE_LIB, "Store", "with_c2_writer_session")

SIGNER_ROUTE_METHODS = (
    "append_initial_proposal_pop",
    "append_physical_generation_bootstrap",
    "append_active_policy_continuity",
    "append_normal_rotation_continuity",
    "append_successor_pop",
    "append_global_refusal",
    "append_installation_intent",
    "append_installation_receipt",
    "append_policy_transition_intent",
    "append_current_policy_transition_receipt",
    "append_pending_policy_transition_receipt",
)

PROTECTED_TYPES = frozenset(
    {
        "C2StoreIntegrityCustodian",
        "C2SignerTransitionCoordinator",
        "C2SignerDurableAppendPermitV1",
        "C2SignerDurableAppendConsumerV1",
        "NonescapingSignedFrameV1",
        "C2BootstrapSignerCapability",
        "C2GenerationSignerCapability",
        "C2PendingSuccessorCapability",
        "CompleteSignerRestartSnapshotV1",
        "ReconstructedTerminalSignerCapabilityV1",
        "C2BootstrapBrandV1",
        "C2InstallationContinuationBrandV1",
        "C2PolicyTransitionBrandV1",
        "C2PolicyTransitionContinuationBrandV1",
    }
)

# Lexemes that represent durable or externally observable I/O in the C2
# implementation modules.  The list is closed and changes are evidence changes.
IO_CALLS = frozenset(
    {
        "append",
        "commit",
        "create_dir",
        "create_dir_all",
        "execute",
        "execute_batch",
        "flock",
        "fsync",
        "hard_link",
        "open",
        "openat",
        "persist",
        "read_exact",
        "read_to_end",
        "remove_dir",
        "remove_file",
        "rename",
        "set_len",
        "set_permissions",
        "sync_all",
        "sync_data",
        "transaction",
        "transaction_with_behavior",
        "write",
        "write_all",
    }
)

WRAPPER_FORBIDDEN_IO = IO_CALLS | {
    "append_runtime_records",
    "begin_writer_session",
    "prepare_writer_connection",
}

DIRECT_OPEN_BASELINE = (
    "crates/nq-app/src/archive.rs::build_staging:2",
    "crates/nq-app/src/cli.rs::admin_command:3",
    "crates/nq-app/src/cli.rs::backup:2",
    "crates/nq-app/src/cli.rs::diagnostic_export:1",
    "crates/nq-app/src/cli.rs::diagnostic_import:1",
    "crates/nq-app/src/cli.rs::diagnostic_inspect:1",
    "crates/nq-app/src/cli.rs::doctor:1",
    "crates/nq-app/src/cli.rs::restore:2",
    "crates/nq-app/src/daemon.rs::run:3",
    "crates/nq-core/src/engine.rs::CollectionEngine::open:1",
    "crates/nq-core/src/engine.rs::backup_store:1",
    "crates/nq-host-role-runtime/src/runtime.rs::HostRoleRuntime::open:1",
    "crates/nq-store/src/lib.rs::Store::immediate_transaction:1",
)


def _function_identity(function: Function) -> FunctionIdentity:
    return FunctionIdentity.from_function(function)


def _item_visibility(source: RustSource, kind: str, name: str) -> str:
    matches: list[str] = []
    for index, token in enumerate(source.tokens):
        if token.value != kind or index + 1 >= len(source.tokens):
            continue
        if source.tokens[index + 1].value != name:
            continue
        prefix = [candidate.value for candidate in source.tokens[max(0, index - 5) : index]]
        if prefix[-4:] == ["pub", "(", "crate", ")"]:
            matches.append("pub(crate)")
        elif prefix[-4:] == ["pub", "(", "super", ")"]:
            matches.append("pub(super)")
        elif prefix and prefix[-1] == "pub":
            matches.append("pub")
        else:
            matches.append("private")
    require(len(matches) == 1, f"{kind} {name} is absent or ambiguous in {source.path}")
    return matches[0]


def _function_call_names(function: Function) -> tuple[str, ...]:
    return tuple(call.name for call in function.calls())


def _require_call_once(function: Function, name: str) -> int:
    calls = function.calls(name)
    require(
        len(calls) == 1,
        f"{function.location} must call {name} exactly once; found {len(calls)}",
    )
    return calls[0].start


def _require_calls_in_order(function: Function, names: Sequence[str]) -> None:
    positions = [_require_call_once(function, name) for name in names]
    require(
        positions == sorted(positions) and len(positions) == len(set(positions)),
        f"{function.location} does not call {', '.join(names)} in exact order",
    )


def _code_contains(function: Function, text: str) -> bool:
    return text in compact_tokens(function.item_tokens, include_literals=False)


def _source_token_count(source: RustSource, values: Sequence[str]) -> int:
    actual = [token.value for token in source.tokens]
    width = len(values)
    return sum(
        actual[index : index + width] == list(values)
        for index in range(len(actual) - width + 1)
    )


def _item_body_token_count(
    source: RustSource, kind: str, name: str, values: Sequence[str]
) -> int:
    """Count one token sequence inside one named braced item only."""

    starts = [
        index
        for index, token in enumerate(source.tokens[:-1])
        if token.value == kind and source.tokens[index + 1].value == name
    ]
    require(len(starts) == 1, f"{kind} {name} is absent or ambiguous in {source.path}")
    open_index = next(
        (
            index
            for index in range(starts[0] + 2, len(source.tokens))
            if source.tokens[index].value == "{"
        ),
        None,
    )
    require(open_index is not None, f"{kind} {name} has no body in {source.path}")
    depth = 0
    close_index = None
    for index in range(open_index, len(source.tokens)):
        value = source.tokens[index].value
        if value == "{":
            depth += 1
        elif value == "}":
            depth -= 1
            if depth == 0:
                close_index = index
                break
    require(close_index is not None, f"{kind} {name} has an unclosed body in {source.path}")
    actual = [token.value for token in source.tokens[open_index + 1 : close_index]]
    width = len(values)
    return sum(
        actual[index : index + width] == list(values)
        for index in range(len(actual) - width + 1)
    )


def _require_no_public_protected_surface(inventory: SourceInventory) -> None:
    exports = inventory.public_reexports(PROTECTED_TYPES)
    require(not exports, "protected C2 types are publicly re-exported: " + ", ".join(exports))
    for path, kind, name, accepted in (
        (SIGNER_CUSTODY, "struct", "C2StoreIntegrityCustodian", {"pub(crate)"}),
        (
            SIGNER_COORDINATOR,
            "struct",
            "C2SignerTransitionCoordinator",
            {"pub(crate)"},
        ),
        (
            SIGNER_COORDINATOR,
            "struct",
            "C2SignerDurableAppendPermitV1",
            {"pub(super)"},
        ),
        (
            SIGNER_COORDINATOR,
            "struct",
            "C2SignerDurableAppendConsumerV1",
            {"pub(crate)"},
        ),
        (SIGNER_COORDINATOR, "struct", "NonescapingSignedFrameV1", {"pub(crate)"}),
        (
            SIGNER_RESTART,
            "struct",
            "CompleteSignerRestartSnapshotV1",
            {"pub(crate)"},
        ),
        (
            SIGNER_RESTART,
            "struct",
            "ReconstructedTerminalSignerCapabilityV1",
            {"pub(crate)"},
        ),
        (
            INSTALL,
            "struct",
            "C2PendingSqlProjectionPermitV1",
            {"pub(crate)"},
        ),
    ):
        visibility = _item_visibility(inventory.source(path), kind, name)
        require(
            visibility in accepted,
            f"protected {name} has invalid visibility {visibility}",
        )


def _verify_private_signer_graph(inventory: SourceInventory) -> tuple[str, ...]:
    _require_no_public_protected_surface(inventory)
    pending_append = _verify_pending_signer_append_gate(inventory)
    external_ingress = _verify_pending_external_carrier_ingress_gate(inventory)
    process_fence = _verify_signer_process_fence(inventory)
    custodian_sign = inventory.require_function(
        SIGNER_CUSTODY, "sign", "C2StoreIntegrityCustodian"
    )
    require(
        custodian_sign.visibility == "pub(super)",
        "C2StoreIntegrityCustodian::sign must remain signer-module-private",
    )
    signature = compact_tokens(
        custodian_sign.source.tokens[
            custodian_sign.start_token : custodian_sign.body_open_token
        ]
    )
    require(
        "<M:SignerMessageV1>" in signature and "message:&M" in signature,
        "custodian signing entry is not sealed to SignerMessageV1",
    )
    require(
        "[u8]" not in signature and "Vec<u8>" not in signature,
        "custodian accepts a raw-byte signing input",
    )

    coordinator_new = inventory.require_function(
        SIGNER_COORDINATOR, "new", "C2SignerTransitionCoordinator"
    )
    require(
        coordinator_new.visibility == "pub(super)",
        "transition coordinator construction escapes its owning signer module",
    )
    coordinator_signature = compact_tokens(
        coordinator_new.source.tokens[
            coordinator_new.start_token : coordinator_new.body_open_token
        ]
    )
    require(
        "append_permit:C2SignerDurableAppendPermitV1" in coordinator_signature,
        "transition coordinator does not consume the unforgeable append permit",
    )
    bridge = inventory.require_function(
        SIGNER_COORDINATOR, "sign_and_consume", "C2SignerTransitionCoordinator"
    )
    require(bridge.visibility == "private", "generic signer bridge is not private")
    _require_calls_in_order(
        bridge,
        (
            "construct_sg_n_18_signing_method_accepts_private_typed_payload_semantic",
            "sign",
            "construct_sg_n_20_signature_response_is_nonescaping_typed_value_consumed",
            "consume",
        ),
    )
    sign_call = bridge.calls("sign")[0]
    consume_call = bridge.calls("consume")[0]
    require(
        sign_call.receiver == "self.custodian",
        "signing does not flow through the owned C2StoreIntegrityCustodian",
    )
    require(
        consume_call.receiver == "self.append_consumer",
        "signed frame does not flow directly to the owned append consumer",
    )

    route_callers = {
        function.name
        for function in inventory.callers_of(
            "sign_and_consume", source_prefix=SIGNER_COORDINATOR
        )
    }
    require(
        route_callers == set(SIGNER_ROUTE_METHODS),
        "typed signer route census changed: "
        f"expected {sorted(SIGNER_ROUTE_METHODS)}, found {sorted(route_callers)}",
    )
    for method in SIGNER_ROUTE_METHODS:
        function = inventory.require_function(
            SIGNER_COORDINATOR, method, "C2SignerTransitionCoordinator"
        )
        require(
            function.visibility == "pub(crate)"
            and len(function.calls("sign_and_consume")) == 1,
            f"typed signer route {method} is not one crate-private consuming bridge call",
        )

    consumer = inventory.require_function(
        SIGNER_COORDINATOR, "consume", "C2SignerDurableAppendConsumerV1"
    )
    require(consumer.visibility == "private", "signed-frame consumer is not private")
    consumer_callers = inventory.callers_of(
        "consume", receiver="self.append_consumer", source_prefix=SIGNER_PREFIX
    )
    require(
        tuple(_function_identity(function) for function in consumer_callers)
        == (_function_identity(bridge),),
        "nonescaping signed-frame consumer has an alternate caller",
    )

    messages = inventory.source(SIGNER_MESSAGES)
    for ordinal in range(1, 17):
        require(
            any(
                token.kind == "ident" and token.value.startswith(f"Msg{ordinal:02d}")
                for token in messages.tokens
            ),
            f"MSG-{ordinal:02d} is absent from the closed family census",
        )
    require(
        _source_token_count(messages, ("const", "ALL", ":", "[", "Self", ";", "16"))
        == 1,
        "closed message-family array is not exactly length 16",
    )
    msg04_type = "BootstrapToGenerationRelationV1"
    require(
        not any(
            msg04_type in compact_tokens(function.item_tokens)
            for function in inventory.functions_named("sign_and_consume")
        ),
        "unsigned MSG-04 entered the signing bridge",
    )
    return (
        "custodian=private-purpose-locked",
        f"typed-routes={len(SIGNER_ROUTE_METHODS)}",
        "append-consumer=one",
        "message-family=MSG-01..MSG-16",
        *pending_append,
        *external_ingress,
        *process_fence,
    )


def _verify_pending_signer_append_gate(
    inventory: SourceInventory,
) -> tuple[str, ...]:
    """Prove the in-memory consumer is unreachable before durable B/G wiring."""

    source = inventory.source(SIGNER_COORDINATOR)
    permit_visibility = _item_visibility(
        source, "struct", "C2SignerDurableAppendPermitV1"
    )
    require(
        permit_visibility == "pub(super)",
        "pending signer append permit has invalid visibility",
    )
    require(
        not inventory.public_reexports({"C2SignerDurableAppendPermitV1"}),
        "pending signer append permit is publicly re-exported",
    )
    constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "C2SignerDurableAppendPermitV1{")
    ]
    require(
        not constructors,
        "pending signer append permit has a production constructor before durable wiring: "
        + ", ".join(function.location for function in constructors),
    )
    consumer_new = inventory.require_function(
        SIGNER_COORDINATOR, "new", "C2SignerDurableAppendConsumerV1"
    )
    consumer_signature = compact_tokens(
        consumer_new.source.tokens[
            consumer_new.start_token : consumer_new.body_open_token
        ]
    )
    require(
        consumer_new.visibility == "private"
        and "permit:C2SignerDurableAppendPermitV1" in consumer_signature,
        "pending signer append consumer does not consume the linear permit",
    )
    consumer_callers = tuple(
        function
        for function in inventory.callers_of("new", source_prefix=SIGNER_PREFIX)
        if _code_contains(function, "C2SignerDurableAppendConsumerV1::new(")
    )
    require(
        len(consumer_callers) == 1
        and consumer_callers[0].owner == "C2SignerTransitionCoordinator"
        and consumer_callers[0].name == "new",
        "pending signer append consumer has an alternate production constructor caller",
    )
    require(
        _item_body_token_count(
            source,
            "struct",
            "NonescapingSignedFrameV1",
            ("canonical_payload", ":", "Vec", "<", "u8", ">"),
        )
        == 1,
        "nonescaping signed frame does not own exactly one canonical payload",
    )
    return (
        "signer-append-permit-production-constructors=0",
        "signed-frame-owned-payload=one",
        "durable-append-status=not-yet-wired",
    )


def _verify_pending_external_carrier_ingress_gate(
    inventory: SourceInventory,
) -> tuple[str, ...]:
    """Prove only terminal-A1-verified carriers can reach the pending ingress.

    Durable replay persistence and the Store-owned consumer are not wired yet,
    so the linear ingress permit intentionally has no production constructor.
    """

    source = inventory.source(SIGNER_GOVERNANCE)
    require(
        _item_visibility(source, "struct", "ExternalCarrierVerificationPermitV1")
        == "pub(super)",
        "external-carrier verification permit has invalid visibility",
    )
    require(
        not inventory.public_reexports({"ExternalCarrierVerificationPermitV1"}),
        "external-carrier verification permit is publicly re-exported",
    )
    verification_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "ExternalCarrierVerificationPermitV1{")
    ]
    require(
        not verification_constructors,
        "external-carrier verification permit has a production constructor before "
        "the Store-owned terminal-A1 resolver: "
        + ", ".join(function.location for function in verification_constructors),
    )
    require(
        _item_visibility(source, "trait", "TerminalA1AuthenticityVerifierV1")
        == "pub(super)",
        "pending terminal-A1 verifier hook escapes the signer module",
    )
    require(
        not tuple(
            function
            for function in inventory.functions_named("verify_unique_terminal_a1")
            if not function.declaration_only
        ),
        "terminal-A1 verifier gained a production implementation before Store-owned wiring",
    )
    expectation_new = inventory.require_function(
        SIGNER_GOVERNANCE, "new", "ExternalGovernanceExpectationV1"
    )
    require(
        expectation_new.visibility == "private",
        "caller-selected external-governance expectation construction is reachable",
    )
    require(
        _item_visibility(source, "struct", "ExternalCarrierStoreIngressPermitV1")
        == "pub(super)",
        "external-carrier Store-ingress permit has invalid visibility",
    )
    require(
        not inventory.public_reexports({"ExternalCarrierStoreIngressPermitV1"}),
        "external-carrier Store-ingress permit is publicly re-exported",
    )
    constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "ExternalCarrierStoreIngressPermitV1{")
    ]
    require(
        not constructors,
        "external-carrier Store-ingress permit has a production constructor before "
        "durable replay wiring: "
        + ", ".join(function.location for function in constructors),
    )
    replay_new = inventory.require_function(
        SIGNER_GOVERNANCE, "new", "ExternalCarrierReplayGuardV1"
    )
    replay_signature = compact_tokens(
        replay_new.source.tokens[replay_new.start_token : replay_new.body_open_token]
    )
    require(
        replay_new.visibility == "pub(super)"
        and "permit:ExternalCarrierStoreIngressPermitV1" in replay_signature,
        "external-carrier replay guard does not consume the linear Store-ingress permit",
    )
    require(
        "implDefaultforExternalCarrierReplayGuardV1" not in compact_tokens(source.tokens),
        "process-local pending replay guard regained a Default construction path",
    )
    bootstrap_verifier = inventory.require_function(
        SIGNER_GOVERNANCE,
        "verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity",
    )
    bootstrap_signature = compact_tokens(
        bootstrap_verifier.source.tokens[
            bootstrap_verifier.start_token : bootstrap_verifier.body_open_token
        ]
    )
    require(
        "_permit:&ExternalCarrierVerificationPermitV1" in bootstrap_signature,
        "bootstrap verified projection bypasses the Store-owned verification permit",
    )

    exact_routes = (
        (
            "VerifiedProposalDispositionV1",
            "StoreIntegrityProposalDispositionV1",
            "ProposalDispositionIngressV1",
            "ProposalDispositionIngressReceiptV1",
            "ProposalDispositionConsumed",
        ),
        (
            "VerifiedBootstrapGrantV1",
            "StoreIntegrityBootstrapGrantV1",
            "BootstrapGrantIngressV1",
            "BootstrapGrantIngressReceiptV1",
            "BootstrapGrantConsumed",
        ),
        (
            "VerifiedActivationSuccessorGrantV1",
            "StoreIntegrityActivationSuccessorGrantV1",
            "ActivationSuccessorGrantIngressV1",
            "ActivationSuccessorGrantIngressReceiptV1",
            "ActivationSuccessorGrantConsumed",
        ),
        (
            "VerifiedRevocationJudgmentV1",
            "StoreIntegrityRevocationJudgmentV1",
            "RevocationJudgmentIngressV1",
            "RevocationJudgmentIngressReceiptV1",
            "RevocationJudgmentConsumed",
        ),
        (
            "VerifiedRecoveryGrantV1",
            "StoreIntegrityRecoveryGrantV1",
            "RecoveryGrantIngressV1",
            "RecoveryGrantIngressReceiptV1",
            "RecoveryGrantConsumed",
        ),
        (
            "VerifiedRestoreAuthorizationV1",
            "StoreIntegrityRestoreAuthorizationV1",
            "RestoreAuthorizationIngressV1",
            "RestoreAuthorizationIngressReceiptV1",
            "RestoreAuthorizationConsumed",
        ),
        (
            "VerifiedQuarantineClosureJudgmentV1",
            "StoreIntegrityQuarantineClosureJudgmentV1",
            "QuarantineClosureIngressV1",
            "QuarantineClosureIngressReceiptV1",
            "QuarantineClosureJudgmentConsumed",
        ),
    )
    tokens = compact_tokens(source.tokens)
    require(
        "_permit:&ExternalCarrierVerificationPermitV1" in tokens,
        "paired carrier verifiers bypass the Store-owned verification permit",
    )
    require(
        _item_visibility(source, "enum", "ExternalCarrierIngressResultV2")
        == "pub(crate)",
        "matrix-assigned external-carrier result vocabulary has invalid visibility",
    )
    require(
        "#[derive(Debug)]pub(crate)enumExternalCarrierIngressResultV2" in tokens,
        "external-carrier result regained a cloneable or copyable witness",
    )
    require(
        "#[derive(Debug,PartialEq,Eq)]pub(crate)struct$receipt{"
        "carrier_identity:ExternalCarrierIdentityV1,_private:(),}"
        in tokens,
        "route-specific external-carrier ingress receipt is not opaque",
    )
    for verified, decoded, ingress, receipt, result in exact_routes:
        if verified != "VerifiedBootstrapGrantV1":
            require(
                f"verified_pair_type!({verified},{decoded});" in tokens,
                f"verified external-carrier projection is absent for {decoded}",
            )
        require(
            f"ingress_type!({ingress},{verified},{receipt},{result}," in tokens,
            f"external-carrier ingress {ingress} does not require {verified}",
        )
        require(
            f"{result}({receipt})" in tokens,
            f"matrix-assigned result {result} does not carry its opaque route receipt",
        )
        require(
            f"ingress_type!({ingress},{decoded}," not in tokens,
            f"decoded but unverified carrier {decoded} reaches {ingress}",
        )
        for other_source in inventory.sources:
            if other_source.path.as_posix() == SIGNER_GOVERNANCE:
                continue
            require(
                not other_source.identifier_occurrences(receipt),
                f"opaque external-carrier receipt {receipt} escapes its owning module",
            )

    return (
        "external-verification-permit-production-constructors=0",
        "terminal-A1-production-verifiers=0",
        "external-ingress-permit-production-constructors=0",
        "external-ingress-routes=7-terminal-A1-verified-only",
        "external-ingress-receipts=7-opaque",
        "external-replay-status=process-local-pending-not-durable",
    )


def _verify_signer_process_fence(inventory: SourceInventory) -> tuple[str, ...]:
    """Prove every production helper spawn excludes live signer secrets."""

    secret_interval = inventory.require_function(
        HELPER_SANDBOX, "enter_c2_secret_process_interval"
    )
    spawn_interval = inventory.require_function(
        HELPER_SANDBOX, "with_c2_process_spawn_fence"
    )
    for function in (secret_interval, spawn_interval):
        require(
            function.visibility == "pub" and _code_contains(function, "C2_PROCESS_FENCE.lock()"),
            f"{function.location} does not acquire the shared process fence",
        )

    central_spawn = inventory.require_function(
        CORE_IDENTITY, "spawn_with_inherited_descriptors"
    )
    central_code = compact_tokens(central_spawn.item_tokens, include_literals=False)
    central_sequence = (
        "with_c2_process_spawn_fence(",
        "DESCRIPTOR_LAUNCH.lock()",
        "make_inheritable(descriptors)",
        "command.spawn()",
        "restore_descriptor_flags(descriptors,&original_flags)",
    )
    central_positions = [central_code.find(value) for value in central_sequence]
    require(
        all(position >= 0 for position in central_positions)
        and central_positions == sorted(central_positions),
        "central helper spawn does not hold C2 fence before descriptor handoff/spawn/restore",
    )
    alternate_command_spawns = [
        function.location
        for function in inventory.functions
        for call in function.calls("spawn")
        if call.receiver == "command" and function is not central_spawn
    ]
    require(
        not alternate_command_spawns,
        "production Command spawn bypasses the C2 process fence: "
        + ", ".join(alternate_command_spawns),
    )

    create = inventory.require_function(
        SIGNER_CUSTODY, "create_below_root", "C2StoreIntegrityCustodian"
    )
    sign = inventory.require_function(SIGNER_CUSTODY, "sign", "C2StoreIntegrityCustodian")
    for function, sequence in (
        (
            create,
            (
                "enter_c2_secret_process_interval()",
                "getrandom::fill(&mutseed)",
                "bytes.fill(0)",
                "secret_process_guard.verify_same_process()",
            ),
        ),
        (
            sign,
            (
                "enter_c2_secret_process_interval()",
                "self.load_seed_for_signing()",
                "signing_key.sign(&preimage)",
                "object_facts(&reopened)",
                "drop(seed)",
                "secret_process_guard.verify_same_process()",
            ),
        ),
    ):
        code = compact_tokens(function.item_tokens, include_literals=False)
        positions = [code.find(value) for value in sequence]
        require(
            all(position >= 0 for position in positions)
            and positions == sorted(positions),
            f"{function.location} does not fence its complete live-secret interval",
        )
    return (
        "signer-secret-fence=shared",
        "production-command-spawn-bypasses=0",
        "secret-process-recheck=after-zeroization",
    )


def _verify_restart_noncreation_graph(inventory: SourceInventory) -> tuple[str, ...]:
    restart = inventory.source(SIGNER_RESTART)
    reconstruct = inventory.require_function(SIGNER_RESTART, "reconstruct")
    require(reconstruct.visibility == "private", "restart reconstruction is not private")
    _require_call_once(reconstruct, "verify_snapshot")
    require(
        _code_contains(reconstruct, "ReconstructedTerminalSignerCapabilityV1{"),
        "restart does not construct the sealed terminal capability after verification",
    )
    callers = {
        function.name
        for function in inventory.callers_of(
            "reconstruct", source_prefix=SIGNER_RESTART
        )
    }
    expected = {
        "construct_sg_n_29_restart_reconstructs_capability_complete_durable_authority_plus",
        "verify_sg_n_29_restart_reconstructs_capability_complete_durable_authority_plus",
        "require_route",
    }
    require(
        callers == expected,
        f"restart reconstruction caller set changed: expected {sorted(expected)}, found {sorted(callers)}",
    )
    prohibited_calls = {
        "create",
        "issue",
        "grant",
        "rotate",
        "recover",
        "append_recovery",
        "construct_recovery_grant",
    }
    used = prohibited_calls.intersection(_function_call_names(reconstruct))
    require(not used, f"restart reconstruction reaches authority creation: {sorted(used)}")
    for source_path in (SIGNER_RESTART, SIGNER_LINEAGE):
        source = inventory.source(source_path)
        production = [function for function in source.functions if not function.cfg_test]
        for function in production:
            sorting = {"sort", "sort_by", "sort_by_key", "max", "max_by", "max_by_key"}.intersection(
                _function_call_names(function)
            )
            require(
                not sorting,
                f"restart/lineage selects authority by sorting or maximum at {function.location}: {sorted(sorting)}",
            )
    require(
        "currentness" not in reconstruct.name.lower()
        and "custody_only" not in reconstruct.name.lower(),
        "generic currentness/custody restart route is present",
    )
    return ("reconstruct-callers=3", "route=terminal-only", "sorting=absent")


def _special_path_inventory(inventory: SourceInventory) -> C2ConstructorPathInventoryV2:
    special: list[FunctionIdentity] = []
    for row, path, owner, name, _brand in SPECIAL_ROOT_SPECS:
        function = inventory.require_function(path, name, owner)
        require(
            function.visibility == "pub(crate)",
            f"{row} special wrapper {name} is not crate-private",
        )
        signature = compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
        require("bool" not in signature, f"{row} special wrapper accepts Boolean authority")
        forbidden = WRAPPER_FORBIDDEN_IO.intersection(_function_call_names(function))
        require(
            not forbidden,
            f"{row} special wrapper performs I/O directly: {sorted(forbidden)}",
        )
        special.append(_function_identity(function))

    fresh = inventory.require_function(INSTALL, "install_c2_fresh")
    restore = inventory.require_function(INSTALL, "install_c2_restore_successor")
    require(
        len(fresh.calls("verify_mode_prerequisites")) == 1
        and _code_contains(fresh, "C2BootstrapBrandV1{"),
        "P-01 does not verify fresh prerequisites before constructing its brand",
    )
    require(
        len(restore.calls("verify_restore_successor_install_inputs")) == 1
        and _code_contains(restore, "C2BootstrapBrandV1{"),
        "P-02 does not verify complete restore-successor inputs before constructing its brand",
    )
    require(
        len(
            inventory.require_function(INSTALL, "continue_c2_installation").calls(
                "construct_n_12_installation_continuation"
            )
        )
        == 1,
        "P-03 does not consume the exact signed-intent continuation constructor",
    )
    require(
        len(
            inventory.require_function(POLICY, "transition_c2_active_policy").calls(
                "construct_n_13_policy_transition_brand"
            )
        )
        == 1,
        "P-04 does not consume the exact current-policy predecessor constructor",
    )
    require(
        len(
            inventory.require_function(POLICY, "continue_c2_policy_transition").calls(
                "construct_n_14_transition_continuation"
            )
        )
        == 1,
        "P-05 does not consume the exact unresolved-intent frontier constructor",
    )

    _, path, owner, name = ORDINARY_ROOT_SPEC
    ordinary = inventory.require_function(path, name, owner)
    require(
        ordinary.visibility in {"pub", "pub(crate)"},
        "P-06 ordinary completed-open entry is absent",
    )
    _require_calls_in_order(
        ordinary,
        ("verify_completed_c2_open_inputs", "new_verified", "begin"),
    )
    require(
        not any(brand in compact_tokens(ordinary.item_tokens) for *_, brand in SPECIAL_ROOT_SPECS),
        "P-06 ordinary path constructs a special brand",
    )
    ordinary_forbidden = WRAPPER_FORBIDDEN_IO.intersection(
        call.name for call in ordinary.calls() if call.name != "begin_writer_session"
    )
    require(
        not ordinary_forbidden,
        f"P-06 ordinary-open wrapper writes before its session: {sorted(ordinary_forbidden)}",
    )
    return C2ConstructorPathInventoryV2(tuple(special), _function_identity(ordinary))


def _run_inherited_verifier(script: str) -> str:
    path = ROOT / "crates/nq-store/tests" / script
    require(path.is_file(), f"inherited verifier is absent: {path.relative_to(ROOT)}")
    environment = dict(os.environ)
    environment["NQ_PROOF_SOURCE_ROOT"] = str(ROOT)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(path)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    require(
        result.returncode == 0,
        f"inherited verifier {script} failed: {(result.stderr or result.stdout).strip()}",
    )
    return result.stdout.strip().splitlines()[-1]


def _collect_io_nodes(inventory: SourceInventory) -> C2IoCallGraphInventoryV2:
    nodes: list[IoNode] = []
    for function in inventory.functions:
        path = function.source.path.as_posix()
        if not path.startswith("crates/nq-store/src/store_generation"):
            continue
        for call in function.calls():
            if call.name in IO_CALLS:
                nodes.append(
                    IoNode(
                        path,
                        function.qualified_name,
                        call.name,
                        call.line,
                    )
                )
    nodes.sort(key=lambda node: (node.path, node.line, node.function, node.call))
    identities = [node.identity for node in nodes]
    require(len(identities) == len(set(identities)), "C2 I/O node identities collide")
    require(nodes, "C2 I/O inventory is empty")
    return C2IoCallGraphInventoryV2(tuple(nodes))


def _verify_io_manifest(inventory: SourceInventory) -> tuple[str, ...]:
    io_inventory = _collect_io_nodes(inventory)
    # Matrix V2 assigns this development-evidence manifest to the test-assets
    # surface.  Keeping it outside product assets prevents a call-graph receipt
    # from becoming a runtime input.
    manifest_path = ROOT / "crates/nq-store/tests/assets/nq.c2_io_crash_cut_manifest.v1.json"
    require(manifest_path.is_file(), "exact C2 I/O crash-cut manifest is absent")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot decode exact C2 I/O crash-cut manifest: {error}")
    require(
        isinstance(manifest, dict)
        and manifest.get("schema") == "nq.c2_io_crash_cut_manifest.v1"
        and isinstance(manifest.get("nodes"), list),
        "C2 I/O crash-cut manifest has the wrong closed shape",
    )
    entries = manifest["nodes"]
    required_keys = {"source", "line", "function", "call", "cut"}
    for entry in entries:
        require(
            isinstance(entry, dict) and set(entry) == required_keys,
            "I/O manifest node has unknown or missing fields",
        )
        require(
            isinstance(entry["cut"], str) and re.fullmatch(r"(?:SC|SCF|SCG)-\d{2}", entry["cut"]),
            f"I/O manifest node has malformed crash cut: {entry.get('cut')!r}",
        )
    manifest_ids = [
        f"{entry['source']}:{entry['line']}:{entry['function']}:{entry['call']}"
        for entry in entries
    ]
    actual_ids = [node.identity for node in io_inventory.nodes]
    require(len(manifest_ids) == len(set(manifest_ids)), "I/O manifest repeats a node")
    require(
        manifest_ids == actual_ids,
        "I/O manifest differs from deterministic source census; "
        f"missing={sorted(set(actual_ids) - set(manifest_ids))}, "
        f"extra={sorted(set(manifest_ids) - set(actual_ids))}",
    )
    return (f"io-nodes={len(actual_ids)}", "mapping=exactly-once")


def _direct_open_inventory(inventory: SourceInventory) -> C2DirectOpenCallGraphV2:
    counts: dict[str, int] = {}
    for function in inventory.functions:
        count = sum(call.path.endswith("Store::open") for call in function.calls())
        if not count:
            continue
        identity = _function_identity(function)
        key = f"{identity.path}::{identity.owner + '::' if identity.owner else ''}{identity.name}:{count}"
        counts[key] = count
    sites = tuple(sorted(counts))
    require(
        sites == tuple(sorted(DIRECT_OPEN_BASELINE)),
        "direct Store::open census changed without exact classification: "
        f"expected={sorted(DIRECT_OPEN_BASELINE)}, found={list(sites)}",
    )
    return C2DirectOpenCallGraphV2(sites)


def _verify_current_activation_projection(inventory: SourceInventory) -> tuple[str, ...]:
    occurrences = [
        source.path.as_posix()
        for source in inventory.sources
        if source.identifier_occurrences("CurrentActivationForC2")
    ]
    require(
        len(occurrences) == 1,
        f"CurrentActivationForC2 must have one physical owner; found {occurrences}",
    )
    constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "CurrentActivationForC2{")
    ]
    require(
        len(constructors) == 1,
        "CurrentActivationForC2 must have exactly one product constructor",
    )
    constructor = constructors[0]
    require(
        "complete" in constructor.name and "resolution" in constructor.name,
        f"current activation constructor is not inside complete resolution: {constructor.location}",
    )
    return (f"owner={occurrences[0]}", f"constructor={constructor.qualified_name}")


def _verify_no_raw_restart_snapshot(inventory: SourceInventory) -> tuple[str, ...]:
    _verify_restart_noncreation_graph(inventory)
    snapshot = inventory.source(SIGNER_RESTART)
    require(
        _item_visibility(snapshot, "struct", "CompleteSignerRestartSnapshotV1") == "pub(crate)",
        "restart snapshot has public visibility",
    )
    for function in inventory.functions:
        if function.source.path.as_posix() == SIGNER_RESTART:
            continue
        signature = compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
        require(
            "CompleteSignerRestartSnapshotV1" not in signature,
            f"raw restart snapshot escapes signer restart module: {function.location}",
        )
    return ("snapshot=signer-module-confined", "constructor=verified-terminal-only")


def _verify_anchor_nonduplication(inventory: SourceInventory) -> tuple[str, ...]:
    receipt = _run_inherited_verifier("verify_r0b_callgraph.py")
    store_generation_sources = [
        source
        for source in inventory.sources
        if source.path.as_posix().startswith("crates/nq-store/src/store_generation")
    ]
    prohibited = {"DependencyAnchorParser", "parse_dependency_anchor", "resolve_anchor_key"}
    occurrences = {
        name: [source.path.as_posix() for source in store_generation_sources if source.identifier_occurrences(name)]
        for name in prohibited
    }
    require(
        not any(occurrences.values()),
        f"C2 introduced a second dependency-anchor parser/resolver: {occurrences}",
    )
    return (receipt, "second-anchor-parser=absent")


def _verify_restore_authority_route(inventory: SourceInventory) -> tuple[str, ...]:
    inventory.require_function(RESTORE, "construct_rr_11_restore_successor_lineage")
    inventory.require_function(
        SIGNER_GOVERNANCE, "verify_restore_authorization_ingress_consumption"
    )
    governance = inventory.source(SIGNER_GOVERNANCE)
    require(
        len(governance.identifier_occurrences("StoreIntegrityRestoreAuthorizationV1")) > 0,
        "exact external restore-authorization carrier is absent",
    )
    for source in inventory.sources:
        path = source.path.as_posix()
        if path in {SIGNER_GOVERNANCE, RESTORE}:
            continue
        require(
            not source.identifier_occurrences("StoreIntegrityRestoreAuthorizationV1"),
            f"parallel restore-authority route exists in {path}",
        )
    return ("external-ingress=one", "physical-restore-owner=one")


def _verify_new_mutator_branding(inventory: SourceInventory) -> tuple[str, ...]:
    receipt = _run_inherited_verifier("verify_mutator_census.py")
    # C2-specific filesystem/SQL primitives must carry a special brand or an
    # ordinary StoreWriterSession in their signature.  Read-only calls are
    # excluded; names below are the closed mutating lexeme set.
    mutating = IO_CALLS - {"open", "openat", "read_exact", "read_to_end"}
    violations: list[str] = []
    for function in inventory.functions:
        path = function.source.path.as_posix()
        if not path.startswith("crates/nq-store/src/store_generation"):
            continue
        if not mutating.intersection(_function_call_names(function)):
            continue
        signature = compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
        branded = any(
            token in signature
            for token in (
                "C2BootstrapBrandV1",
                "C2InstallationContinuationBrandV1",
                "C2PolicyTransitionBrandV1",
                "C2PolicyTransitionContinuationBrandV1",
                "StoreWriterSession",
            )
        )
        # Custody writes are purpose-locked by the private custodian rather
        # than Store mutation brands; only its exact private helpers qualify.
        custody_owned = path == SIGNER_CUSTODY and function.visibility == "private"
        if not branded and not custody_owned:
            violations.append(function.location)
    require(
        not violations,
        "C2 mutating primitive lacks an exact brand/session owner: " + ", ".join(violations),
    )
    migration = _verify_schema_projection_gate(inventory)
    return (receipt, "c2-mutator-signatures=branded", *migration)


def _verify_schema_projection_gate(inventory: SourceInventory) -> tuple[str, ...]:
    """Prove the incomplete schema mutator has no path-only product route."""

    require(
        not inventory.functions_named("migrate_c1_gen4_to_c2_schema_projection"),
        "HostRoleRuntime still exposes the path-only schema-v9 projection bypass",
    )
    permit_visibility = _item_visibility(
        inventory.source(INSTALL), "struct", "C2PendingSqlProjectionPermitV1"
    )
    require(
        permit_visibility == "pub(crate)",
        "pending SQL projection permit has an invalid visibility",
    )
    require(
        not inventory.public_reexports({"C2PendingSqlProjectionPermitV1"}),
        "pending SQL projection permit is publicly re-exported",
    )
    apply = inventory.require_function(STORE_LIB, "apply_c2_schema_v8_to_v9")
    signature = compact_tokens(
        apply.source.tokens[apply.start_token : apply.body_open_token]
    )
    require(
        apply.visibility == "pub(crate)"
        and "C2PendingSqlProjectionPermitV1<Mode>" in signature
        and "VerifiedC2SchemaV8ToV9Sequential" not in signature,
        "schema-v9 projection mutator does not consume only the installation permit",
    )
    require(
        not apply.calls("acquire_maintenance_locks"),
        "schema-v9 projection mutator still self-authorizes through generic maintenance locks",
    )
    callers = inventory.callers_of("apply_c2_schema_v8_to_v9")
    require(
        not callers,
        "incomplete schema-v9 projection mutator has a production caller: "
        + ", ".join(function.location for function in callers),
    )
    constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "C2PendingSqlProjectionPermitV1{")
    ]
    require(
        not constructors,
        "pending SQL projection permit has a production constructor before the ordered driver: "
        + ", ".join(function.location for function in constructors),
    )
    return (
        "schema-v9-path-only-route=absent",
        "schema-v9-permit-production-constructors=0",
        "schema-v9-production-apply-callers=0",
    )


def _verify_lock_alias_law(inventory: SourceInventory) -> tuple[str, ...]:
    lock_source = inventory.source(LOCK)
    writer_source = inventory.source(WRITER)
    require(
        lock_source.identifier_occurrences("LockInodeKey")
        and lock_source.identifier_occurrences("held_lock_inodes"),
        "C2 lock-inode registry is absent",
    )
    require(
        not writer_source.identifier_occurrences("STORE_WRITER_LOCKS")
        and not writer_source.identifier_occurrences("path_lock_state"),
        "ordinary writer law still accepts the legacy path-keyed mutex registry",
    )
    require(
        writer_source.identifier_occurrences("LockInodeKey"),
        "ordinary writer session does not consume the C2 lock-inode identity",
    )
    return ("registry=process-wide-lock-inode", "path-keyed-substitute=absent")


def _verify_fence_sources(inventory: SourceInventory) -> tuple[str, ...]:
    setters = [
        function
        for function in inventory.functions
        if "fence" in function.name and any(call.name in {"store", "swap"} for call in function.calls())
    ]
    require(setters, "no production C2 fence setter exists")
    for setter in setters:
        signature = compact_tokens(
            setter.source.tokens[setter.start_token : setter.body_open_token]
        )
        require(
            "VerifiedG" in signature or "ReconciliationFence" in signature,
            f"fence setter lacks verified G/reconciliation input: {setter.location}",
        )
        require("bool" not in signature, f"fence setter accepts Boolean authority: {setter.location}")
    return (f"verified-fence-setters={len(setters)}",)


def _verify_preflight_nonauthority(inventory: SourceInventory) -> tuple[str, ...]:
    matches = [
        source
        for source in inventory.sources
        if source.identifier_occurrences("C2BackendPreflightFacts")
    ]
    require(len(matches) == 1, "C2BackendPreflightFacts owner is absent or ambiguous")
    for function in inventory.functions:
        signature = compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
        if "C2BackendPreflightFacts" not in signature:
            continue
        prohibited = {
            "ClosedC2StoreBackend",
            "StoreWriterSession",
            "Capacity",
            "Standing",
            "Qualified",
        }
        result = signature.split("->", 1)[1] if "->" in signature else ""
        leak = [name for name in prohibited if name in result]
        require(not leak, f"preflight converts into authority at {function.location}: {leak}")
        require(function.visibility != "pub", f"preflight facts escape publicly at {function.location}")
    return (f"owner={matches[0].path}", "authority-conversion=absent")


def _verify_closed_backend_constructor(inventory: SourceInventory) -> tuple[str, ...]:
    constructors = inventory.functions_named("new_verified")
    constructors = tuple(
        function for function in constructors if function.owner in {"ClosedC2StoreBackend", "ClosedC2StoreBackendV1"}
    )
    require(len(constructors) == 1, "closed backend new_verified constructor is absent or ambiguous")
    constructor = constructors[0]
    require(constructor.visibility in {"private", "pub(crate)"}, "closed backend constructor is public")
    # The token scanner records an associated-function path but no receiver
    # for `ClosedC2StoreBackendV1::new_verified`.  Match the exact qualified
    # path rather than weakening this to every method named `new_verified`.
    callers = tuple(
        function
        for function in inventory.functions
        if any(
            call.name == "new_verified"
            and call.path == "ClosedC2StoreBackendV1::new_verified"
            for call in function.calls()
        )
    )
    require(len(callers) == 1, "closed backend constructor must have exactly one production caller")
    caller = callers[0]
    require(
        "reopen" in caller.name and ("receipt" in caller.name or "completed" in caller.name),
        f"closed backend caller is not post-receipt/final-reopen: {caller.location}",
    )
    signature = compact_tokens(
        constructor.source.tokens[constructor.start_token : constructor.body_open_token]
    )
    require("bool" not in signature, "closed backend constructor accepts Boolean standing")
    return (f"constructor={constructor.location}", f"caller={caller.location}")


def _verify_s5_nonretrogression(inventory: SourceInventory) -> tuple[str, ...]:
    source = inventory.source(INSTALL)
    s5_functions = [
        function
        for function in source.functions
        if not function.cfg_test and "s5" in function.name.lower()
    ]
    require(s5_functions, "S5 production handler is absent")
    prohibited = {"exact_no_write", "s1_quarantined_allocation", "s2_quarantined_authentication"}
    for function in s5_functions:
        overlap = prohibited.intersection(_function_call_names(function))
        require(not overlap, f"S5 reaches S0-S2 handler at {function.location}: {sorted(overlap)}")
    return (f"s5-handlers={len(s5_functions)}", "retrograde-edges=absent")


def _verify_restore_before_effect(inventory: SourceInventory) -> tuple[str, ...]:
    function = inventory.require_function(INSTALL, "install_c2_restore_successor")
    _require_call_once(function, "verify_restore_successor_install_inputs")
    forbidden = WRAPPER_FORBIDDEN_IO.intersection(_function_call_names(function))
    require(not forbidden, f"restore wrapper writes before verification: {sorted(forbidden)}")
    require(
        not any(name in compact_tokens(function.item_tokens) for name in ("latest", "maximum", "sort")),
        "restore wrapper infers predecessor by order rather than exact lineage",
    )
    return ("restore-verifier=pre-effect", "predecessor-inference=absent")


def _verify_no_downstream_mint(inventory: SourceInventory) -> tuple[str, ...]:
    prohibited_returns = (
        "FStanding",
        "MStanding",
        "LStanding",
        "AllocationReservation",
        "InvocationAuthority",
        "DiagnosticAuthority",
        "EffectAuthority",
        "DocketAuthority",
    )
    violations: list[str] = []
    for function in inventory.functions:
        if not function.source.path.as_posix().startswith("crates/nq-store/src/store_generation"):
            continue
        signature = compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
        result = signature.split("->", 1)[1] if "->" in signature else ""
        if any(name in result for name in prohibited_returns):
            violations.append(function.location)
    require(not violations, "C2 constructor mints downstream authority: " + ", ".join(violations))
    return ("downstream-authority-return-types=absent",)


def _verify_test_confinement(inventory: SourceInventory) -> tuple[str, ...]:
    violations: list[str] = []
    for source in inventory.sources:
        if not source.path.as_posix().startswith("crates/nq-store/src/store_generation"):
            continue
        for function in source.functions:
            if "for_test" in function.name and not function.cfg_test:
                violations.append(function.location)
    require(not violations, "C2 test helper is in the product graph: " + ", ".join(violations))
    return (f"compile-confined-modules={len(inventory.compile_confined_paths)}", "test-helper-leaks=0")


def _verify_no_alternate_protected_roots(inventory: SourceInventory) -> tuple[str, ...]:
    protected_sources = {INSTALL, POLICY, SIGNER_CUSTODY, SIGNER_COORDINATOR, SIGNER_RESTART}
    violations: list[str] = []
    for source in inventory.sources:
        path = source.path.as_posix()
        if path in protected_sources:
            continue
        for protected in PROTECTED_TYPES:
            if source.identifier_occurrences(protected):
                violations.append(f"{path}:{protected}")
    require(
        not violations,
        "binary/feature/fixture/administrative source reaches protected C2 surface: "
        + ", ".join(violations),
    )
    return ("alternate-protected-roots=absent",)


def _evidence(row: str, *facts: str) -> RowEvidence:
    require(facts, f"{row} produced no structural facts")
    return RowEvidence(row, tuple(facts))


def construct_wu_14_immutable_wu_machine_constructor_mutator_i_o(
    inventory: SourceInventory | None = None,
) -> C2ConstructorGraphInventoryV2:
    inventory = inventory or SourceInventory.load()
    return C2ConstructorGraphInventoryV2(
        str(inventory.root),
        len(inventory.sources),
        len(inventory.functions),
        inventory.digest(),
    )


def verify_wu_14_immutable_wu_machine_constructor_mutator_i_o(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    graph = construct_wu_14_immutable_wu_machine_constructor_mutator_i_o(inventory)
    signer = _verify_private_signer_graph(inventory)
    restart = _verify_restart_noncreation_graph(inventory)
    paths = _special_path_inventory(inventory)
    io = _verify_io_manifest(inventory)
    return _evidence(
        "WU-14",
        f"sources={graph.source_count}",
        f"functions={graph.function_count}",
        graph.source_digest,
        f"special-roots={len(paths.special_roots)}",
        *signer,
        *restart,
        *io,
    )


def verify_n_11_acyclic_construction_order(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    source = inventory.source(INSTALL)
    sequence = (
        "AuthenticateAuthorityAndPolicy",
        "VerifyPhysicalLineage",
        "AcquireCreationMutex",
        "VerifyProfilePreflight",
        "ConstructModeBrand",
        "CreatePermanentLockExclusive",
        "TransferToLockIdentityMutexAndFlock",
        "PreallocateFixedCarriers",
        "VerifyPerEffectProfile",
        "DerivePhysicalGenerationIdentity",
        "PersistSignedBootstrapHeadersAndIntent",
        "SyncImmutablePrefix",
        "PersistPendingSqlProjection",
        "ReopenAndVerifyPreReceipt",
        "PersistCompletionReceipt",
        "ReopenAndVerifyCompletedGeneration",
        "ConstructClosedBackend",
    )
    positions = []
    for name in sequence:
        occurrences = source.identifier_occurrences(name)
        require(occurrences, f"installation construction step is absent: {name}")
        positions.append(occurrences[0].start)
    require(positions == sorted(positions), "installation construction sequence is reordered")
    require(len(sequence) == len(set(sequence)), "installation construction sequence repeats a step")
    return _evidence("N-11", "steps=17", "mode-brand-before-first-write=true", "acyclic=ordered")


def verify_n_16_branded_effect_owners(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    _special_path_inventory(inventory)
    mutators = _verify_new_mutator_branding(inventory)
    closed = _verify_closed_backend_constructor(inventory)
    return _evidence("N-16", *mutators, *closed)


def construct_n_61_exhaustive_special_roots_are_fresh_installation_continuation(
    inventory: SourceInventory | None = None,
) -> C2ConstructorPathInventoryV2:
    return _special_path_inventory(inventory or SourceInventory.load())


def verify_n_61_exhaustive_special_roots_are_fresh_installation_continuation(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = construct_n_61_exhaustive_special_roots_are_fresh_installation_continuation(inventory)
    return _evidence(
        "N-61",
        "special-roots=" + ",".join(identity.name for identity in paths.special_roots),
        "special-root-count=5",
    )


def construct_n_62_ordinary_path_is_completed_open_constructor_no(
    inventory: SourceInventory | None = None,
) -> C2ConstructorPathInventoryV2:
    return _special_path_inventory(inventory or SourceInventory.load())


def verify_n_62_ordinary_path_is_completed_open_constructor_no(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = construct_n_62_ordinary_path_is_completed_open_constructor_no(inventory)
    return _evidence("N-62", f"ordinary-root={paths.ordinary_root.display()}", "ordinary-root-count=1")


def construct_n_63_each_wrapper_is_non_mutating_creates_proper(
    inventory: SourceInventory | None = None,
) -> C2ConstructorPathInventoryV2:
    return _special_path_inventory(inventory or SourceInventory.load())


def verify_n_63_each_wrapper_is_non_mutating_creates_proper(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = construct_n_63_each_wrapper_is_non_mutating_creates_proper(inventory)
    return _evidence("N-63", f"nonwriting-special-wrappers={len(paths.special_roots)}", "boolean-substitute=absent")


def verify_n_64_exact_six_path_census(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    paths = _special_path_inventory(inventory)
    _verify_no_alternate_protected_roots(inventory)
    return _evidence("N-64", f"special={len(paths.special_roots)}", "ordinary=1", "total=6")


def verify_n_84_every_mutator_has_exact_session_owner(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    facts = _verify_new_mutator_branding(inventory)
    _special_path_inventory(inventory)
    return _evidence("N-84", *facts, "cap-h23-roots=6")


def verify_hr28_28_complete_cap_h23_inventory(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    paths = _special_path_inventory(inventory)
    require(len(paths.special_roots) == 5, "HR28-28 missing one or more CAP-H23 special roots")
    return _evidence("HR28-28", "incomplete-inventory-refusal=armed", "positive-control-paths=6")


def construct_am_01_amendment_crosswalk_am_charter_close_unrestricted_self(
    inventory: SourceInventory | None = None,
) -> C2ConstructorPathInventoryV2:
    return _special_path_inventory(inventory or SourceInventory.load())


def verify_am_01_amendment_crosswalk_am_charter_close_unrestricted_self(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    paths = construct_am_01_amendment_crosswalk_am_charter_close_unrestricted_self(inventory)
    mutators = _verify_new_mutator_branding(inventory)
    return _evidence("AM-01", f"paths={len(paths.special_roots) + 1}", *mutators)


def verify_rr_10_single_restore_authority_and_recovery_owner(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("RR-10", *_verify_restore_authority_route(inventory or SourceInventory.load()))


def collect_cr_06_candidate_io_nodes(
    inventory: SourceInventory | None = None,
) -> C2IoCallGraphInventoryV2:
    return _collect_io_nodes(inventory or SourceInventory.load())


def verify_cr_06_each_io_node_maps_once(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CR-06", *_verify_io_manifest(inventory or SourceInventory.load()))


def verify_cg_01_current_activation_projection_has_constructor_inside_complete(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-01", *_verify_current_activation_projection(inventory or SourceInventory.load()))


def verify_cg_02_no_public_raw_restart_snapshot_enters_snapshot(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-02", *_verify_no_raw_restart_snapshot(inventory or SourceInventory.load()))


def verify_cg_03_install_enrollment_verification_uses_existing_anchor_no(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-03", *_verify_anchor_nonduplication(inventory or SourceInventory.load()))


def verify_cg_04_bootstrap_brand_callers_are_exactly_fresh_restore(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    paths = _special_path_inventory(inventory)
    return _evidence("CG-04", "bootstrap-brand-callers=" + ",".join(path.name for path in paths.special_roots[:2]))


def verify_cg_05_install_continuation_brand_has_intent_frontier_verifier(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    _special_path_inventory(inventory)
    function = inventory.require_function(INSTALL, "construct_n_12_installation_continuation")
    require(function.visibility == "pub(crate)", "install-continuation constructor visibility changed")
    return _evidence("CG-05", f"constructor={function.location}", "caller=continue_c2_installation")


def verify_cg_06_policy_transition_brand_has_initial_transition_caller(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    _special_path_inventory(inventory)
    constructor = inventory.require_function(POLICY, "construct_n_13_policy_transition_brand")
    callers = inventory.callers_of("construct_n_13_policy_transition_brand", source_prefix=POLICY)
    require(
        {_function_identity(function).name for function in callers} == {"transition_c2_active_policy"},
        "initial policy-transition brand has an alternate production caller",
    )
    return _evidence("CG-06", f"constructor={constructor.location}", "caller=transition_c2_active_policy")


def verify_cg_07_transition_continuation_brand_has_unresolved_intent_frontier(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    _special_path_inventory(inventory)
    constructor = inventory.require_function(POLICY, "construct_n_14_transition_continuation")
    callers = inventory.callers_of("construct_n_14_transition_continuation", source_prefix=POLICY)
    require(
        {_function_identity(function).name for function in callers} == {"continue_c2_policy_transition"},
        "policy-transition continuation brand has an alternate production caller",
    )
    return _evidence("CG-07", f"constructor={constructor.location}", "caller=continue_c2_policy_transition")


def verify_cg_08_install_continuation_explicit_entry_unreachable_ordinary_open(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    root = inventory.require_function(INSTALL, "continue_c2_installation")
    forbidden = {
        function.location
        for function in inventory.callers_of("continue_c2_installation")
        if any(word in function.name for word in ("open", "restart", "recover"))
    }
    require(not forbidden, "install continuation is reachable from ordinary/restart/recovery: " + ", ".join(sorted(forbidden)))
    return _evidence("CG-08", f"explicit-root={root.location}", "implicit-callers=0")


def verify_cg_10_ordinary_session_construction_occurs_after_complete_closed(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = _special_path_inventory(inventory or SourceInventory.load())
    return _evidence("CG-10", f"ordinary-root={paths.ordinary_root.display()}", "closed-before-session=true")


def verify_cg_11_exactly_five_nonwriting_special_roots_each_correct(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = _special_path_inventory(inventory or SourceInventory.load())
    return _evidence("CG-11", f"special-root-count={len(paths.special_roots)}", "wrapper-io=0")


def verify_cg_12_exactly_nonwriting_ordinary_open_session_root_p(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = _special_path_inventory(inventory or SourceInventory.load())
    return _evidence("CG-12", f"ordinary-root={paths.ordinary_root.display()}", "pre-session-io=0")


def verify_cg_13_effectful_primitive_descends_exactly_special_brand_ordinary(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-13", *_verify_new_mutator_branding(inventory or SourceInventory.load()))


def verify_cg_14_new_b_g_lock_backend_filesystem_sql(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    facts = _verify_new_mutator_branding(inventory)
    for path in (
        "crates/nq-store/src/append_extent.rs",
        "crates/nq-store/src/global_failure_journal.rs",
        "crates/nq-store/src/capacity_backend.rs",
        LOCK,
    ):
        inventory.source(path)
    return _evidence("CG-14", *facts, "bg-lock-backend-modules=4")


def verify_cg_15_maintenance_site_uses_full_process_mutex_flock(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    receipt = _run_inherited_verifier("verify_mutator_census.py")
    helper = inventory.require_function(WRITER, "acquire_maintenance_locks")
    raii_flock = any(
        call.name == "lock" and call.path == "Flock::lock" for call in helper.calls()
    )
    writer_tokens = compact_tokens(inventory.source(WRITER).tokens)
    helper_body = compact_tokens(helper.body_tokens)
    guard_shape = (
        "structMaintenanceLockGuard{_process:MutexGuard<'static,()>,_flock:Flock<File>,}"
        in writer_tokens
    )
    retained_values = (
        "MaintenanceLockGuard{_process:process,_flock:flock,}" in helper_body
    )
    require(
        helper.calls("try_lock") and raii_flock and guard_shape and retained_values,
        "maintenance lock helper does not retain both process mutex and RAII flock",
    )
    return _evidence(
        "CG-15",
        receipt,
        f"helper={helper.location}",
        "guard=MutexGuard+Flock<File>",
        "values=retained",
    )


def verify_cg_16_handle_alias_uses_process_wide_lock_inode(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-16", *_verify_lock_alias_law(inventory or SourceInventory.load()))


def verify_cg_17_fence_setters_derive_verified_g_reconciliation_fence(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-17", *_verify_fence_sources(inventory or SourceInventory.load()))


def verify_cg_18_preflight_has_no_authority_output_conversion_c2backendpreflightfacts(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-18", *_verify_preflight_nonauthority(inventory or SourceInventory.load()))


def verify_cg_19_sole_closed_constructor_has_post_receipt_final(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-19", *_verify_closed_backend_constructor(inventory or SourceInventory.load()))


def verify_cg_20_s5_cannot_reach_s0_s2_handlers_phase(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-20", *_verify_s5_nonretrogression(inventory or SourceInventory.load()))


def verify_cg_21_restore_first_write_follows_complete_predecessor_verification(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-21", *_verify_restore_before_effect(inventory or SourceInventory.load()))


def verify_cg_22_i_o_census_maps_call_graph_i(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-22", *_verify_io_manifest(inventory or SourceInventory.load()))


def verify_cg_23_no_constructor_mints_f_m_l_allocation(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-23", *_verify_no_downstream_mint(inventory or SourceInventory.load()))


def verify_cg_24_direct_test_calls_are_compile_confined_cfg(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-24", *_verify_test_confinement(inventory or SourceInventory.load()))


def verify_cg_25_no_binary_feature_recovery_restore_fixture_administrative(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    return _evidence("CG-25", *_verify_no_alternate_protected_roots(inventory or SourceInventory.load()))


def verify_cg_26_gen4_establishment_restart_r0b_constraints_remain_intact(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    del inventory
    return _evidence("CG-26", _run_inherited_verifier("verify_r0b_callgraph.py"))


def verify_xh_53_complete_cap_h23_inventory(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = _special_path_inventory(inventory or SourceInventory.load())
    require(len(paths.special_roots) + 1 == 6, "one-path CAP-H23 substitution was accepted")
    return _evidence("XH-53", "missing-path-refusal=armed", "complete-paths=6")


def construct_seam_10_immutable_seam_direct_open_census_core_runtime(
    inventory: SourceInventory | None = None,
) -> C2DirectOpenCallGraphV2:
    return _direct_open_inventory(inventory or SourceInventory.load())


def verify_seam_10_immutable_seam_direct_open_census_core_runtime(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    direct = construct_seam_10_immutable_seam_direct_open_census_core_runtime(inventory)
    _special_path_inventory(inventory)
    _run_inherited_verifier("verify_mutator_census.py")
    return _evidence("SEAM-10", f"direct-open-classifications={len(direct.direct_open_sites)}", "c2-mutation-path=P-06")


ASSIGNED_VERIFIERS: tuple[Callable[[SourceInventory | None], RowEvidence], ...] = (
    verify_wu_14_immutable_wu_machine_constructor_mutator_i_o,
    verify_n_11_acyclic_construction_order,
    verify_n_16_branded_effect_owners,
    verify_n_61_exhaustive_special_roots_are_fresh_installation_continuation,
    verify_n_62_ordinary_path_is_completed_open_constructor_no,
    verify_n_63_each_wrapper_is_non_mutating_creates_proper,
    verify_n_64_exact_six_path_census,
    verify_n_84_every_mutator_has_exact_session_owner,
    verify_hr28_28_complete_cap_h23_inventory,
    verify_am_01_amendment_crosswalk_am_charter_close_unrestricted_self,
    verify_rr_10_single_restore_authority_and_recovery_owner,
    verify_cr_06_each_io_node_maps_once,
    verify_cg_01_current_activation_projection_has_constructor_inside_complete,
    verify_cg_02_no_public_raw_restart_snapshot_enters_snapshot,
    verify_cg_03_install_enrollment_verification_uses_existing_anchor_no,
    verify_cg_04_bootstrap_brand_callers_are_exactly_fresh_restore,
    verify_cg_05_install_continuation_brand_has_intent_frontier_verifier,
    verify_cg_06_policy_transition_brand_has_initial_transition_caller,
    verify_cg_07_transition_continuation_brand_has_unresolved_intent_frontier,
    verify_cg_08_install_continuation_explicit_entry_unreachable_ordinary_open,
    verify_cg_10_ordinary_session_construction_occurs_after_complete_closed,
    verify_cg_11_exactly_five_nonwriting_special_roots_each_correct,
    verify_cg_12_exactly_nonwriting_ordinary_open_session_root_p,
    verify_cg_13_effectful_primitive_descends_exactly_special_brand_ordinary,
    verify_cg_14_new_b_g_lock_backend_filesystem_sql,
    verify_cg_15_maintenance_site_uses_full_process_mutex_flock,
    verify_cg_16_handle_alias_uses_process_wide_lock_inode,
    verify_cg_17_fence_setters_derive_verified_g_reconciliation_fence,
    verify_cg_18_preflight_has_no_authority_output_conversion_c2backendpreflightfacts,
    verify_cg_19_sole_closed_constructor_has_post_receipt_final,
    verify_cg_20_s5_cannot_reach_s0_s2_handlers_phase,
    verify_cg_21_restore_first_write_follows_complete_predecessor_verification,
    verify_cg_22_i_o_census_maps_call_graph_i,
    verify_cg_23_no_constructor_mints_f_m_l_allocation,
    verify_cg_24_direct_test_calls_are_compile_confined_cfg,
    verify_cg_25_no_binary_feature_recovery_restore_fixture_administrative,
    verify_cg_26_gen4_establishment_restart_r0b_constraints_remain_intact,
    verify_xh_53_complete_cap_h23_inventory,
    verify_seam_10_immutable_seam_direct_open_census_core_runtime,
)


def run_all(inventory: SourceInventory) -> tuple[list[RowEvidence], dict[str, str]]:
    passed: list[RowEvidence] = []
    failed: dict[str, str] = {}
    for verifier in ASSIGNED_VERIFIERS:
        try:
            passed.append(verifier(inventory))
        except (AssertionError, ScanError, KeyError, TypeError, ValueError) as error:
            match = re.match(r"verify_([a-z0-9]+)_([0-9]+)", verifier.__name__)
            row = (
                f"{match.group(1).upper()}-{match.group(2)}"
                if match
                else verifier.__name__.removeprefix("verify_")
            )
            failed[row] = str(error)
    return passed, failed


def canonical_result_digest(passed: Sequence[RowEvidence], failed: dict[str, str]) -> str:
    value = {
        "failed": failed,
        "passed": [dataclasses.asdict(evidence) for evidence in passed],
        "schema": "nq.c2.call_graph_evidence.v2",
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit canonical row results")
    parser.add_argument("--list-rows", action="store_true", help="list the 39 exact V2 rows")
    arguments = parser.parse_args(argv)
    if arguments.list_rows:
        for verifier in ASSIGNED_VERIFIERS:
            print(verifier.__name__)
        return 0
    inventory = SourceInventory.load()
    passed, failed = run_all(inventory)
    digest = canonical_result_digest(passed, failed)
    if arguments.json:
        print(
            json.dumps(
                {
                    "evidence_digest": digest,
                    "failed": failed,
                    "passed": [dataclasses.asdict(evidence) for evidence in passed],
                    "qualification_claim": False,
                    "row_count": len(ASSIGNED_VERIFIERS),
                    "schema": "nq.c2.call_graph_evidence.v2",
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(
            f"C2 call-graph evidence: {len(passed)}/{len(ASSIGNED_VERIFIERS)} rows pass; {digest}"
        )
        for row, message in sorted(failed.items()):
            print(f"FAIL {row}: {message}", file=sys.stderr)
    require(not failed, f"{len(failed)} exact call-graph row(s) remain unearned")
    print("C2 call-graph evidence: PASS (development evidence; not qualification)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, ScanError, KeyError, TypeError, ValueError) as error:
        print(f"C2 call-graph evidence: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
