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
import tomllib
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
LIVE_C2 = "crates/nq-store/src/store_generation/live_c2.rs"
POLICY = "crates/nq-store/src/store_generation/policy.rs"
STORE_LIB = "crates/nq-store/src/lib.rs"
HOST_RUNTIME = "crates/nq-host-role-runtime/src/runtime.rs"
CORE_IDENTITY = "crates/nq-core/src/identity.rs"
CORE_RUNTIME = "crates/nq-core/src/runtime.rs"
CORE_RUNNER = "crates/nq-core/src/runner.rs"
CORE_UNIX_RUNNER = "crates/nq-core/src/unix_runner.rs"
HELPER_SANDBOX = "crates/nq-helper-sandbox/src/lib.rs"
HELPER_SANDBOX_MANIFEST = "crates/nq-helper-sandbox/Cargo.toml"
STORE_MANIFEST = "crates/nq-store/Cargo.toml"
WRITER = "crates/nq-store/src/writer_session.rs"
STORE_GENERATION_MOD = "crates/nq-store/src/store_generation.rs"
CANDIDATE_QUALIFICATION = (
    "crates/nq-store/src/store_generation/candidate_qualification.rs"
)
C2_LIFECYCLE = "crates/nq-store/src/store_generation/c2_lifecycle.rs"
LOCK = "crates/nq-store/src/store_generation/lock.rs"
RESTORE = "crates/nq-store/src/store_generation/restore.rs"
SIGNER_PREFIX = "crates/nq-store/src/store_generation/signer/"
SIGNER_MOD = SIGNER_PREFIX + "mod.rs"
SIGNER_CUSTODY = SIGNER_PREFIX + "custody.rs"
SIGNER_COORDINATOR = SIGNER_PREFIX + "coordinator.rs"
SIGNER_MESSAGES = SIGNER_PREFIX + "messages.rs"
SIGNER_RESTART = SIGNER_PREFIX + "restart.rs"
SIGNER_LINEAGE = SIGNER_PREFIX + "lineage.rs"
SIGNER_GOVERNANCE = SIGNER_PREFIX + "external_governance.rs"
SIGNER_AUTHORITY = SIGNER_PREFIX + "authority.rs"
SIGNER_MANIFEST = SIGNER_PREFIX + "manifest.rs"
SIGNER_RECORDS = SIGNER_PREFIX + "records.rs"
SIGNER_TERMINAL = SIGNER_PREFIX + "terminal.rs"
C2_SIGNING_PROJECTION = "crates/nq-store/src/store_generation/signing.rs"

SPECIAL_ROOT_SPECS = (
    (
        "LIVE-BOOTSTRAP-PREPARE",
        LIVE_C2,
        "Store",
        "prepare_c2_live_bootstrap_v1",
        "StorePreparedBootstrapGrantRequestV1",
    ),
    (
        "LIVE-BOOTSTRAP-INSTALL",
        LIVE_C2,
        "Store",
        "install_c2_live_from_bootstrap_grant_v1",
        "BootstrapV1",
    ),
    (
        "LIVE-HEALTHY-SUCCESSOR",
        LIVE_C2,
        "Store",
        "rotate_c2_live_healthy_successor_v1",
        "C2HealthySuccessorIntentV1",
    ),
    (
        "LIVE-HEALTHY-SUCCESSOR-POLICY-CHANGE",
        LIVE_C2,
        "Store",
        "rotate_c2_live_healthy_successor_with_activation_grant_v1",
        "StoreIntegrityActivationSuccessorGrantV1",
    ),
    (
        "LIVE-RESTORE",
        LIVE_C2,
        "Store",
        "restore_c2_live_historical_foundation_v1",
        "StoreIntegrityRestoreAuthorizationV1",
    ),
    (
        "LIVE-RECOVERY-PREPARE",
        LIVE_C2,
        "Store",
        "prepare_c2_live_recovery_v1",
        "StorePreparedRecoveryGrantRequestV1",
    ),
    (
        "LIVE-RECOVERY",
        LIVE_C2,
        "Store",
        "recover_c2_live_new_foundation_v1",
        "StoreIntegrityRecoveryGrantV1",
    ),
)

ORDINARY_ROOT_SPEC = (
    "LIVE-REOPEN",
    LIVE_C2,
    "Store",
    "with_reopened_c2_generation_current_v1",
)

SIGNER_ROUTE_METHODS = (
    "append_initial_proposal_pop_v1",
    "append_installation_bootstrap_batch",
    "append_installation_receipt",
    "append_active_policy_continuity",
    "append_normal_rotation_continuity",
    "append_global_refusal",
    "append_policy_transition_intent",
    "append_current_policy_transition_receipt",
    "append_successor_possession",
    "append_pending_healthy_rotation_receipt",
)

PROTECTED_TYPES = frozenset(
    {
        "C2StoreIntegrityCustodian",
        "C2SignerTransitionCoordinator",
        "C2PreparedSignedAppendV1",
        "C2FinalizedSignedAppendV1",
        "StoreC2SignerAppendPermitV1",
        "StoreC2InitialPossessionAppendPermitV1",
        "StoreC2SnapshotActorV1",
        "C2LiveSignerContextV1",
        "C2LiveSigningViewV1",
        "C2LiveWriterSessionV1",
        "GenerationCurrentV1",
        "PendingPossessionV1",
        "PendingSelectedV1",
        "StoreVerifiedCurrentPredecessorAuthorityV1",
        "StoreVerifiedOrdinarySuccessorFoundationAuthorityV1",
        "StoreVerifiedRestoreEntryAuthorityV1",
        "StoreVerifiedRecoveryEntryAuthorityV1",
        "StoreVerifiedRestorePossessionPermitV1",
        "StoreVerifiedRecoveryPossessionPermitV1",
        "StoreVerifiedRestoreFoundationAuthorityV1",
        "StoreVerifiedRecoveryFoundationAuthorityV1",
        "ConsumedStoreFoundationAdoptionAuthorityV1",
        "SignerMessageV1",
        "C2PreparedExternalIngressV1",
        "ExternalCarrierVerificationPermitV1",
        "C2BootstrapSignerCapability",
        "C2GenerationSignerCapability",
        "C2PendingSuccessorCapability",
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
        prefix = [candidate.value for candidate in source.tokens[max(0, index - 16) : index]]
        compact_prefix = "".join(prefix)
        if prefix[-4:] == ["pub", "(", "crate", ")"]:
            matches.append("pub(crate)")
        elif prefix[-4:] == ["pub", "(", "super", ")"]:
            matches.append("pub(super)")
        elif compact_prefix.endswith("pub(incrate::store_generation)"):
            matches.append("pub(in crate::store_generation)")
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


def _item_header_code(source: RustSource, kind: str, name: str) -> str:
    """Return one named item's attributes/visibility/header, without its body."""

    starts = [
        index
        for index, token in enumerate(source.tokens[:-1])
        if token.value == kind and source.tokens[index + 1].value == name
    ]
    require(len(starts) == 1, f"{kind} {name} is absent or ambiguous in {source.path}")
    item = starts[0]
    depth = source.depths[item]
    start = item
    while start > 0:
        prior = start - 1
        if (
            source.tokens[prior].value == ";"
            and source.depths[prior] == depth
        ) or (
            source.tokens[prior].value == "}"
            and source.depths[prior] == depth + 1
        ):
            break
        start = prior
    body = next(
        (
            index
            for index in range(item + 2, len(source.tokens))
            if source.depths[index] == depth and source.tokens[index].value in ("{", ";")
        ),
        None,
    )
    require(body is not None, f"{kind} {name} has no body terminator in {source.path}")
    return compact_tokens(source.tokens[start:body], include_literals=False)


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
            "C2PreparedSignedAppendV1",
            {"pub(crate)"},
        ),
        (
            SIGNER_COORDINATOR,
            "struct",
            "C2FinalizedSignedAppendV1",
            {"pub(crate)"},
        ),
        (LIVE_C2, "struct", "StoreC2SignerAppendPermitV1", {"pub(crate)"}),
        (
            LIVE_C2,
            "struct",
            "StoreC2InitialPossessionAppendPermitV1",
            {"pub(crate)"},
        ),
        (LIVE_C2, "struct", "StoreC2SnapshotActorV1", {"pub(crate)"}),
        (LIVE_C2, "struct", "C2LiveSignerContextV1", {"pub(crate)"}),
        (LIVE_C2, "struct", "C2LiveSigningViewV1", {"pub(crate)"}),
        (LIVE_C2, "struct", "C2LiveWriterSessionV1", {"pub(crate)"}),
        (LIVE_C2, "enum", "GenerationCurrentV1", {"pub(crate)"}),
        (LIVE_C2, "enum", "PendingPossessionV1", {"pub(crate)"}),
        (LIVE_C2, "enum", "PendingSelectedV1", {"pub(crate)"}),
        (
            LIVE_C2,
            "struct",
            "StoreVerifiedCurrentPredecessorAuthorityV1",
            {"pub(crate)"},
        ),
        (
            LIVE_C2,
            "struct",
            "StoreVerifiedOrdinarySuccessorFoundationAuthorityV1",
            {"pub(crate)"},
        ),
        (LIVE_C2, "struct", "StoreVerifiedRestoreEntryAuthorityV1", {"pub(crate)"}),
        (LIVE_C2, "struct", "StoreVerifiedRecoveryEntryAuthorityV1", {"pub(crate)"}),
        (
            LIVE_C2,
            "struct",
            "StoreVerifiedRestorePossessionPermitV1",
            {"pub(crate)"},
        ),
        (
            LIVE_C2,
            "struct",
            "StoreVerifiedRecoveryPossessionPermitV1",
            {"pub(crate)"},
        ),
        (
            LIVE_C2,
            "struct",
            "StoreVerifiedRestoreFoundationAuthorityV1",
            {"pub(crate)"},
        ),
        (
            LIVE_C2,
            "struct",
            "StoreVerifiedRecoveryFoundationAuthorityV1",
            {"pub(crate)"},
        ),
        (
            LIVE_C2,
            "struct",
            "ConsumedStoreFoundationAdoptionAuthorityV1",
            {"pub(crate)"},
        ),
        (
            SIGNER_GOVERNANCE,
            "struct",
            "C2PreparedExternalIngressV1",
            {"pub(crate)"},
        ),
        (
            SIGNER_GOVERNANCE,
            "struct",
            "ExternalCarrierVerificationPermitV1",
            {"pub(in crate::store_generation)"},
        ),
    ):
        visibility = _item_visibility(inventory.source(path), kind, name)
        require(
            visibility in accepted,
            f"protected {name} has invalid visibility {visibility}",
        )


def _verify_live_authority_noninjectability(
    inventory: SourceInventory,
) -> tuple[str, ...]:
    """Pin the process-local live types and their sole Store-owned mints."""

    forbidden_traits = ("Clone", "Copy", "Default", "Serialize", "Deserialize")
    protected_items = (
        (LIVE_C2, "C2LiveSignerContextV1"),
        (LIVE_C2, "C2LiveSigningViewV1"),
        (LIVE_C2, "C2LiveWriterSessionV1"),
        (LIVE_C2, "StoreC2SignerAppendPermitV1"),
        (LIVE_C2, "StoreC2InitialPossessionAppendPermitV1"),
        (LIVE_C2, "StoreVerifiedCurrentPredecessorAuthorityV1"),
        (LIVE_C2, "StoreVerifiedOrdinarySuccessorFoundationAuthorityV1"),
        (LIVE_C2, "StoreVerifiedRestoreEntryAuthorityV1"),
        (LIVE_C2, "StoreVerifiedRecoveryEntryAuthorityV1"),
        (LIVE_C2, "StoreVerifiedRestorePossessionPermitV1"),
        (LIVE_C2, "StoreVerifiedRecoveryPossessionPermitV1"),
        (LIVE_C2, "StoreVerifiedRestoreFoundationAuthorityV1"),
        (LIVE_C2, "StoreVerifiedRecoveryFoundationAuthorityV1"),
        (LIVE_C2, "ConsumedStoreFoundationAdoptionAuthorityV1"),
        (SIGNER_GOVERNANCE, "ExternalCarrierVerificationPermitV1"),
        (SIGNER_GOVERNANCE, "StoreAdoptedBootstrapGrantV1"),
        (SIGNER_MANIFEST, "StoreAdmittedSignerImplementationManifestV1"),
        (SIGNER_CUSTODY, "VerifiedFoundationalCustodyV1"),
        (SIGNER_RECORDS, "StoreAdoptedFoundationalEnrollmentV1"),
        (SIGNER_RECORDS, "StoreAcceptedSignerEnrollmentV1"),
    )
    for path, name in protected_items:
        source = inventory.source(path)
        header = _item_header_code(source, "struct", name)
        derived = [trait for trait in forbidden_traits if trait in header]
        explicit = sorted(
            scope.trait_name
            for scope in source.impl_scopes
            if scope.owner == name and scope.trait_name in forbidden_traits
        )
        require(
            not derived and not explicit,
            f"authority-bearing {name} implements a transferable/serializable trait: "
            f"derive={derived}, explicit={explicit}",
        )

    signer_module = inventory.source(SIGNER_MOD)
    messages = inventory.source(SIGNER_MESSAGES)
    signing_projection = inventory.source(C2_SIGNING_PROJECTION)
    require(
        _source_token_count(signer_module, ("pub", "(", "crate", ")", "mod", "messages"))
        == 1
        and _item_visibility(messages, "trait", "SignerMessageV1") == "pub(super)"
        and _item_visibility(messages, "enum", "C2StoreSigningRouteV1") == "pub",
        "generic signer route/trait escaped the crate-private messages module",
    )
    public_projection_functions = {
        function.name
        for function in inventory.functions
        if function.source.path.as_posix() == C2_SIGNING_PROJECTION
        and function.visibility == "pub"
    }
    require(
        public_projection_functions
        == {
            "c2_message_families",
            "c2_store_signing_registry",
            "c2_external_signing_registry",
            "verify_closed_c2_signing_registry",
        }
        and _source_token_count(
            signing_projection, ("pub", "use", "super", "::", "signer", "::", "messages")
        )
        == 1
        and _source_token_count(signing_projection, ("SignerMessageV1",)) == 0,
        "public signing projection is not restricted to inert registry metadata",
    )

    context_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "C2LiveSignerContextV1{")
    ]
    expected_context_constructors = {
        "mint_bootstrap_signer_context",
        "mint_generation_current_from_bootstrap_v1",
        "mint_reopened_terminal_generation_current_v1",
        "mint_ordinary_successor_pending_possession_v1",
        "mint_pending_selected_from_consumed_acceptance_v1",
        "mint_restore_pending_possession_v1",
        "mint_recovery_pending_possession_v1",
    }
    require(
        {function.name for function in context_constructors}
        == expected_context_constructors
        and all(
            function.source.path.as_posix() == LIVE_C2
            and function.owner == "StoreC2SnapshotActorV1"
            for function in context_constructors
        ),
        "live signer context has a constructor outside the seven Store-owned phase mints: "
        + ", ".join(function.location for function in context_constructors),
    )
    reopen = inventory.require_function(
        LIVE_C2,
        "mint_reopened_terminal_generation_current_v1",
        "StoreC2SnapshotActorV1",
    )
    require(
        reopen.visibility == "private"
        and len(reopen.calls("verify_authority_lineage")) == 1
        and len(reopen.calls("verify_store_admitted_signer_implementation_manifest_v1")) == 1
        and len(reopen.calls("verify_same_process")) == 1,
        "fresh-process reopen mint omits authority/manifest/custody correspondence",
    )
    reopen_code = compact_tokens(reopen.item_tokens)
    for lineage in (
        "InitialExternal",
        "OrdinarySuccessorContinuity",
        "RestoreHistorical",
        "RecoveryNewFoundation",
    ):
        require(
            f"FoundationalAdoptionLineageV1::{lineage}" in reopen_code,
            f"fresh-process reopen omits the closed {lineage} lineage",
        )

    authority_constructors = {
        "StoreVerifiedCurrentPredecessorAuthorityV1": "mint_current_predecessor_authority_v1",
        "StoreVerifiedOrdinarySuccessorFoundationAuthorityV1": "append_healthy_rotation_intent_v1",
        "StoreVerifiedRestoreEntryAuthorityV1": "begin_restore_successor_v1",
        "StoreVerifiedRecoveryEntryAuthorityV1": "begin_recovery_entry_v1",
        "StoreVerifiedRestorePossessionPermitV1": "seal_restore_possession_permit_v1",
        "StoreVerifiedRecoveryPossessionPermitV1": "seal_recovery_possession_permit_v1",
        "StoreVerifiedRestoreFoundationAuthorityV1": "refine_restore_foundation_after_msg07_v1",
        "StoreVerifiedRecoveryFoundationAuthorityV1": "refine_recovery_foundation_after_msg07_v1",
    }
    for type_name, expected_constructor in authority_constructors.items():
        constructors = [
            function
            for function in inventory.functions
            if function.source.path.as_posix() == LIVE_C2
            and _code_contains(function, f"{type_name}{{")
            and not _code_contains(function, f"let{type_name}{{")
        ]
        require(
            len(constructors) == 1
            and constructors[0].owner == "StoreC2SnapshotActorV1"
            and constructors[0].name == expected_constructor,
            f"{type_name} does not have exactly one nominal Store-actor constructor: "
            + (", ".join(function.location for function in constructors) or "none"),
        )

    consumed_authority_constructors = [
        function
        for function in inventory.functions
        if function.source.path.as_posix() == LIVE_C2
        and _code_contains(function, "ConsumedStoreFoundationAdoptionAuthorityV1{")
    ]
    require(
        {function.name for function in consumed_authority_constructors}
        == {
            "consume_ordinary_successor_foundation_authority_v1",
            "consume_restore_foundation_authority_v1",
            "consume_recovery_foundation_authority_v1",
        }
        and all(
            function.owner == "StoreC2SnapshotActorV1"
            for function in consumed_authority_constructors
        ),
        "consumed foundation-adoption authority has a generic or alternate constructor: "
        + ", ".join(function.location for function in consumed_authority_constructors),
    )

    writer_constructor = inventory.require_function(
        LIVE_C2, "from_exact_generation_current", "C2LiveWriterSessionV1"
    )
    writer_callers = inventory.callers_of("from_exact_generation_current")
    require(
        writer_constructor.visibility == "private"
        and len(writer_constructor.calls("verify_same_snapshot")) == 1
        and len(writer_constructor.calls("verify_live")) == 1
        and len(
            writer_constructor.calls(
                "verify_wu_04_immutable_wu_local_lock_flock_process_registry"
            )
        )
        == 1
        and len(writer_callers) == 1
        and writer_callers[0].source.path.as_posix() == LIVE_C2
        and writer_callers[0].owner == "Store"
        and writer_callers[0].name == "with_reopened_c2_generation_current_v1",
        "writer-session authority is not confined to exact complete-current reopen",
    )
    verify_live = inventory.require_function(
        LIVE_C2, "verify_live", "C2LiveSignerContextV1"
    )
    require(
        "std::process::id" in compact_tokens(verify_live.item_tokens)
        and "actor_instance_identity" in compact_tokens(verify_live.item_tokens)
        and "actor_snapshot_identity" in compact_tokens(verify_live.item_tokens)
        and "actor_effect_epoch" in compact_tokens(verify_live.item_tokens),
        "live context verification omits process/actor/snapshot/effect correspondence",
    )

    ingress_permit_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "ExternalCarrierVerificationPermitV1{")
        or (
            function.owner == "ExternalCarrierVerificationPermitV1"
            and _code_contains(function, "Self{")
        )
    ]
    require(
        len(ingress_permit_constructors) == 1
        and ingress_permit_constructors[0].source.path.as_posix() == SIGNER_GOVERNANCE
        and ingress_permit_constructors[0].owner == "ExternalCarrierVerificationPermitV1"
        and ingress_permit_constructors[0].name == "from_store_actor",
        "external ingress permit has a constructor outside its Store-actor gate: "
        + ", ".join(function.location for function in ingress_permit_constructors),
    )
    adopted_grant_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "StoreAdoptedBootstrapGrantV1{")
        or (
            function.owner == "StoreAdoptedBootstrapGrantV1"
            and _code_contains(function, "Self{")
        )
    ]
    require(
        len(adopted_grant_constructors) == 1
        and adopted_grant_constructors[0].source.path.as_posix() == SIGNER_GOVERNANCE
        and adopted_grant_constructors[0].owner == "StoreAdoptedBootstrapGrantV1"
        and adopted_grant_constructors[0].name == "from_actor_append",
        "Store-adopted bootstrap grant has an alternate constructor: "
        + ", ".join(function.location for function in adopted_grant_constructors),
    )
    return (
        "live-context-constructors=7-store-owned",
        "live-authority-transfer-traits=absent",
        "nominal-live-authority-constructors=8-store-owned",
        "foundation-adoption-authority-constructors=3-route-specific",
        "writer-session-constructor=complete-current-only",
        "reopen-premises=authority+manifest+terminal-enrollment+custody",
        "external-ingress-permit-constructors=1",
        "adopted-bootstrap-grant-constructors=1",
    )


def _verify_private_signer_graph(inventory: SourceInventory) -> tuple[str, ...]:
    unsafe_boundary = _verify_signer_module_unsafe_boundary(inventory)
    _require_no_public_protected_surface(inventory)
    noninjectability = _verify_live_authority_noninjectability(inventory)
    live_append = _verify_live_signer_append_gate(inventory)
    external_ingress = _verify_live_external_carrier_ingress_gate(inventory)
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
        "M:SignerMessageV1" in signature and "message:&M" in signature,
        "custodian signing entry is not sealed to SignerMessageV1",
    )
    require(
        "[u8]" not in signature and "Vec<u8>" not in signature,
        "custodian accepts a raw-byte signing input",
    )
    initial_sign = inventory.require_function(
        SIGNER_CUSTODY, "sign_initial_possession", "C2StoreIntegrityCustodian"
    )
    initial_signature = compact_tokens(
        initial_sign.source.tokens[initial_sign.start_token : initial_sign.body_open_token]
    )
    require(
        initial_sign.visibility == "pub(super)"
        and "StoreC2InitialPossessionAppendPermitV1" in initial_signature
        and "VerifiedInitialPossessionRequestV1" in initial_signature
        and "[u8]" not in initial_signature
        and "Vec<u8>" not in initial_signature,
        "MSG-02 custody entry is not purpose-locked to the actor request/permit",
    )

    coordinator_new = inventory.require_function(
        SIGNER_COORDINATOR, "from_store_actor", "C2SignerTransitionCoordinator"
    )
    require(
        coordinator_new.visibility == "pub(crate)",
        "transition coordinator has the wrong Store-private visibility",
    )
    coordinator_signature = compact_tokens(
        coordinator_new.source.tokens[
            coordinator_new.start_token : coordinator_new.body_open_token
        ]
    )
    require(
        "actor:&'opmutStoreC2SnapshotActorV1<'actor_store>" in coordinator_signature
        and "context:&'opmutC2LiveSignerContextV1<'context_live,'context_store,Phase>"
        in coordinator_signature
        and "custodian:" not in coordinator_signature
        and len(coordinator_new.calls("verify_live")) == 1
        and len(coordinator_new.calls("retained_custodian")) == 1,
        "transition coordinator does not derive its sole custodian from the verified live context",
    )
    bridge = inventory.require_function(
        SIGNER_COORDINATOR, "prepare_typed_signed_frame"
    )
    require(bridge.visibility == "private", "typed signer preparation bridge is not private")
    _require_calls_in_order(
        bridge,
        (
            "construct_signing_brand",
            "sign",
            "construct_nonescaping_frame",
        ),
    )
    require(
        "<M:SignerMessageV1,Phase>" in compact_tokens(
            bridge.source.tokens[bridge.start_token : bridge.body_open_token]
        ),
        "typed signer preparation bridge is not sealed to SignerMessageV1",
    )

    route_specs = (
        ("append_initial_proposal_pop_v1", None, "pub(crate)", ("InitialProposalPoPFrameV1",), "with_initial_possession_append_effect"),
        ("append_installation_bootstrap_batch", "C2SignerTransitionCoordinator", "pub(incrate::store_generation)", ("StoreGenerationInstallationIntentFrameV1", "PhysicalGenerationBootstrapFrameV1"), "with_installation_bootstrap_batch_effect"),
        ("append_installation_receipt", "C2SignerTransitionCoordinator", "pub(incrate::store_generation)", ("StoreGenerationInstallationReceiptFrameV1",), "sign_and_append_prospective_generation"),
        ("append_active_policy_continuity", "C2SignerTransitionCoordinator", "private", ("ActivePolicyContinuityFrameV1",), "sign_and_append_current_predecessor"),
        ("append_normal_rotation_continuity", "C2SignerTransitionCoordinator", "private", ("NormalRotationContinuityFrameV1",), "sign_and_append_current_predecessor"),
        ("append_global_refusal", "C2SignerTransitionCoordinator", "private", ("GlobalRefusalFrameV1",), "sign_and_append"),
        ("append_policy_transition_intent", "C2SignerTransitionCoordinator", "private", ("PolicyTransitionIntentFrameV1",), "sign_and_append_current_predecessor"),
        ("append_current_policy_transition_receipt", "C2SignerTransitionCoordinator", "private", ("CurrentPolicyTransitionReceiptFrameV1",), "sign_and_append"),
        ("append_successor_possession", "C2SignerTransitionCoordinator", "pub(incrate::store_generation)", ("SuccessorPoPFrameV1",), "sign_and_append"),
        ("append_pending_healthy_rotation_receipt", "C2SignerTransitionCoordinator", "pub(incrate::store_generation)", ("PendingPolicyTransitionReceiptFrameV1",), "sign_and_append"),
    )
    require(
        tuple(spec[0] for spec in route_specs) == SIGNER_ROUTE_METHODS,
        "verifier's closed typed-route specification drifted",
    )
    realized_routes = 0
    for method, owner, visibility, message_types, sink in route_specs:
        function = inventory.require_function(SIGNER_COORDINATOR, method, owner)
        require(
            function.visibility == visibility and len(function.calls(sink)) == 1,
            f"typed signer route {method} does not enter its one Store-owned sink {sink}",
        )
        for message_type in message_types:
            require(
                _code_contains(function, f"{message_type}::from_store_verified("),
                f"typed signer route {method} does not construct exact {message_type}",
            )
            constructors = {
                _function_identity(candidate)
                for candidate in inventory.functions
                if candidate.source.path.as_posix() == SIGNER_COORDINATOR
                and _code_contains(candidate, f"{message_type}::from_store_verified(")
            }
            require(
                constructors == {_function_identity(function)},
                f"typed signer message {message_type} has an alternate constructor: "
                + ", ".join(
                    identity.display()
                    for identity in sorted(constructors, key=lambda value: value.display())
                ),
            )
        function_signature = compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
        require(
            "&[u8]" not in function_signature
            and "Vec<u8>" not in function_signature
            and "domain:&str" not in function_signature
            and "C2StoreSigningRouteV1" not in function_signature
            and "ClosedMessageFamilyV1" not in function_signature,
            f"typed signer route {method} accepts a generic bytes/domain/family selector",
        )
        realized_routes += len(message_types)
    require(realized_routes == 11, "Store-signable route census is not exactly 11")
    for obsolete in ("append_physical_generation_bootstrap", "append_installation_intent"):
        require(
            not [
                function
                for function in inventory.functions_named(obsolete)
                if function.source.path.as_posix() == SIGNER_COORDINATOR
            ],
            f"obsolete parallel signer route remains in product: {obsolete}",
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
        f"typed-route-methods={len(SIGNER_ROUTE_METHODS)}",
        "store-signable-routes=11",
        "append-owner=live-store-actor",
        "message-family=MSG-01..MSG-16",
        *unsafe_boundary,
        *noninjectability,
        *live_append,
        *external_ingress,
        *process_fence,
    )


def _verify_signer_module_unsafe_boundary(
    inventory: SourceInventory,
) -> tuple[str, ...]:
    """Require an unrelaxable unsafe-code prohibition for the signer subtree."""

    source = inventory.source(SIGNER_MOD)
    require(
        _source_token_count(
            source,
            ("#", "!", "[", "forbid", "(", "unsafe_code", ")", "]"),
        )
        == 1,
        "signer module root must contain exactly one #![forbid(unsafe_code)]",
    )
    return ("signer-unsafe-code=forbidden-at-module-root",)


def _verify_live_signer_append_gate(
    inventory: SourceInventory,
) -> tuple[str, ...]:
    """Prove typed signing reaches only the live actor's durable append roots."""

    actor_source = inventory.source(LIVE_C2)
    coordinator = inventory.source(SIGNER_COORDINATOR)
    require(
        _item_visibility(actor_source, "struct", "StoreC2SignerAppendPermitV1")
        == "pub(crate)"
        and _item_visibility(
            actor_source, "struct", "StoreC2InitialPossessionAppendPermitV1"
        )
        == "pub(crate)",
        "live signer append permits have invalid visibility",
    )
    require(
        not inventory.public_reexports(
            {"StoreC2SignerAppendPermitV1", "StoreC2InitialPossessionAppendPermitV1"}
        ),
        "live signer append permit is publicly re-exported",
    )
    live_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "StoreC2SignerAppendPermitV1{")
    ]
    expected_live_constructors = {
        "with_signer_append_effect",
        "with_installation_bootstrap_batch_effect",
        "with_prospective_generation_append_effect",
        "with_current_predecessor_append_effect",
    }
    require(
        {function.name for function in live_constructors} == expected_live_constructors
        and all(
            function.source.path.as_posix() == LIVE_C2
            and function.owner == "StoreC2SnapshotActorV1"
            for function in live_constructors
        ),
        "live signer append permit has a constructor outside the closed actor roots: "
        + ", ".join(function.location for function in live_constructors),
    )
    initial_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "StoreC2InitialPossessionAppendPermitV1{")
    ]
    require(
        len(initial_constructors) == 1
        and initial_constructors[0].source.path.as_posix() == LIVE_C2
        and initial_constructors[0].owner == "StoreC2SnapshotActorV1"
        and initial_constructors[0].name == "with_initial_possession_append_effect",
        "MSG-02 permit has a constructor outside its purpose-locked actor root",
    )

    frame_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "C2PreparedSignedAppendV1{")
    ]
    expected_frame_constructors = {
        FunctionIdentity(SIGNER_COORDINATOR, None, "construct_nonescaping_frame"),
        FunctionIdentity(
            SIGNER_COORDINATOR,
            None,
            "reproject_exact_durable_signer_carrier_suffix_v1",
        ),
    }
    require(
        {_function_identity(function) for function in frame_constructors}
        == expected_frame_constructors,
        "prepared signed append has an alternate constructor: "
        + ", ".join(function.location for function in frame_constructors),
    )
    reprojection = inventory.require_function(
        SIGNER_COORDINATOR, "reproject_exact_durable_signer_carrier_suffix_v1"
    )
    require(
        len(reprojection.calls("verify_durable_signer_carrier_envelope_v1")) == 1
        and len(
            reprojection.calls("append_prepared_signed_frame_with_physical_carrier")
        )
        == 1
        and not reprojection.calls("sign"),
        "durable reprojection can construct a prepared frame without authenticated carrier verification",
    )
    require(
        _item_body_token_count(
            coordinator,
            "struct",
            "C2PreparedSignedAppendV1",
            ("canonical_message", ":", "Vec", "<", "u8", ">"),
        )
        == 1,
        "prepared signed append does not own exactly one canonical message",
    )

    append_effect = inventory.require_function(
        LIVE_C2, "append_prepared_signer_effect", "StoreC2SnapshotActorV1"
    )
    require(append_effect.visibility == "private", "durable signer append root escapes actor")
    _require_calls_in_order(
        append_effect,
        (
            "finalize_prepared_signed_frame",
            "append_or_replay_exact",
            "append_finalized_signed_frame_projection",
        ),
    )
    batch = inventory.require_function(
        LIVE_C2, "with_installation_bootstrap_batch_effect", "StoreC2SnapshotActorV1"
    )
    require(
        len(batch.calls("finalize_prepared_signed_frame")) == 2
        and len(batch.calls("append_or_replay_exact")) == 2
        and len(batch.calls("append_finalized_signed_frame_projection")) == 2,
        "installation batch does not own exactly two typed finalize/B/project append lanes",
    )
    initial = inventory.require_function(
        LIVE_C2, "with_initial_possession_append_effect", "StoreC2SnapshotActorV1"
    )
    require(
        len(initial.calls("append_prepared_signed_frame")) == 1,
        "MSG-02 actor root does not own exactly one durable proposal append",
    )
    bootstrap = inventory.require_function(
        LIVE_C2, "install_c2_live_from_bootstrap_grant_v1", "Store"
    )
    require(
        len(bootstrap.calls("append_initial_proposal_pop_v1")) == 1,
        "sole live bootstrap driver does not reach MSG-02 exactly once",
    )
    return (
        f"signer-live-permit-actor-roots={len(expected_live_constructors)}",
        "initial-possession-permit-actor-roots=1",
        "prepared-signed-append-constructors=1-live+1-authenticated-reprojection",
        "durable-bg-append-owner=live-store-actor",
        "msg02-durable-proposal-append-owner=live-store-actor",
    )


def _verify_live_external_carrier_ingress_gate(
    inventory: SourceInventory,
) -> tuple[str, ...]:
    """Prove governed carriers enter through one same-snapshot durable actor root."""

    source = inventory.source(SIGNER_GOVERNANCE)
    actor_source = inventory.source(LIVE_C2)
    require(
        _item_visibility(source, "struct", "ExternalCarrierVerificationPermitV1")
        == "pub(in crate::store_generation)",
        "external-carrier verification permit is not confined to the Store generation owner",
    )
    require(
        not inventory.public_reexports(
            {
                "ExternalCarrierVerificationPermitV1",
                "C2PreparedExternalIngressV1",
                "DurableExternalIngressReceiptV1",
            }
        ),
        "governed external-ingress authority/evidence is publicly re-exported",
    )
    permit_constructor = inventory.require_function(
        SIGNER_GOVERNANCE,
        "from_store_actor",
        "ExternalCarrierVerificationPermitV1",
    )
    require(
        permit_constructor.visibility == "pub(incrate::store_generation)"
        and len(permit_constructor.calls("verify_same_snapshot")) == 1,
        "external verification permit is not minted from an exact live Store actor",
    )
    verification_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "ExternalCarrierVerificationPermitV1{")
        or (
            function.owner == "ExternalCarrierVerificationPermitV1"
            and _code_contains(function, "Self{")
        )
    ]
    require(
        len(verification_constructors) == 1
        and _function_identity(verification_constructors[0])
        == _function_identity(permit_constructor),
        "external verification permit has an alternate production constructor: "
        + ", ".join(function.location for function in verification_constructors),
    )

    terminal_verifiers = tuple(
        function
        for function in inventory.functions_named("verify_unique_terminal_a1")
        if not function.declaration_only
    )
    require(
        len(terminal_verifiers) == 1
        and terminal_verifiers[0].source.path.as_posix() == LIVE_C2
        and terminal_verifiers[0].owner == "StoreTerminalA1VerifierV1",
        "terminal-A1 authenticity must have exactly one live Store same-snapshot implementation: "
        + (", ".join(function.location for function in terminal_verifiers) or "none"),
    )
    route_specs = (
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
            "apply_revocation_judgment_v1",
            "verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity",
            "prepare_verified_revocation_effect_v1",
        ),
        (
            "adopt_recovery_grant_v1",
            "verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity",
            "prepare_recovery_grant_ingress",
        ),
        (
            "apply_quarantine_closure_judgment_v1",
            "verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity",
            "prepare_verified_quarantine_closure_effect_v1",
        ),
    )
    actor_routes = tuple(
        inventory.require_function(LIVE_C2, method, "StoreC2SnapshotActorV1")
        for method, _, _ in route_specs
    )
    terminal_literals = {
        _function_identity(function)
        for function in inventory.functions
        if _code_contains(function, "StoreTerminalA1VerifierV1{")
    }
    require(
        terminal_literals == {_function_identity(function) for function in actor_routes},
        "terminal-A1 adapter constructors differ from the seven typed Store routes: "
        + ", ".join(identity.display() for identity in sorted(terminal_literals, key=lambda value: value.display())),
    )
    for function, (_, verifier, consumer) in zip(actor_routes, route_specs, strict=True):
        require(
            function.visibility == "pub(crate)",
            f"governed-carrier route is not crate-owned: {function.location}",
        )
        signature = compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
        forbidden_inputs = (
            "BTreeMap",
            "ExternalGovernanceExpectationV1",
            "ExternalCarrierVerificationPermitV1",
            "C2PreparedExternalIngressV1",
            "DurableExternalIngressReceiptV1",
        )
        require(
            not any(name in signature for name in forbidden_inputs),
            f"{function.location} exposes caller-authored ingress internals",
        )
        _require_calls_in_order(
            function,
            ("new", "from_store_actor", verifier, consumer),
        )

    bootstrap_install = inventory.require_function(
        LIVE_C2, "install_c2_live_from_bootstrap_grant_v1", "Store"
    )
    require(
        len(bootstrap_install.calls("adopt_bootstrap_grant_v1")) == 1,
        "bootstrap resume does not enter its exact Store-owned MSG-01 route once",
    )

    durable_callers = {
        _function_identity(function)
        for function in inventory.callers_of("append_prepared_external_ingress")
    }
    expected_durable_callers = {
        FunctionIdentity(
            LIVE_C2,
            "StoreC2SnapshotActorV1",
            "append_verified_governed_carrier_effect",
        ),
        FunctionIdentity(
            SIGNER_GOVERNANCE,
            "StorePreparedRevocationEffectV1",
            "apply",
        ),
        FunctionIdentity(
            SIGNER_GOVERNANCE,
            "StorePreparedQuarantineClosureEffectV1",
            "apply",
        ),
    }
    require(
        durable_callers == expected_durable_callers,
        "durable governed-carrier ingress caller set changed: "
        + ", ".join(identity.display() for identity in sorted(durable_callers, key=lambda value: value.display())),
    )

    exact_routes = (
        ("prepare_bootstrap_grant_ingress", "VerifiedBootstrapGrantV1"),
        ("prepare_activation_successor_grant_ingress", "VerifiedActivationSuccessorGrantV1"),
        ("prepare_proposal_disposition_ingress", "VerifiedProposalDispositionV1"),
        ("prepare_restore_authorization_ingress", "VerifiedRestoreAuthorizationV1"),
        ("prepare_revocation_judgment_ingress", "VerifiedRevocationJudgmentV1"),
        ("prepare_recovery_grant_ingress", "VerifiedRecoveryGrantV1"),
        ("prepare_quarantine_closure_ingress", "VerifiedQuarantineClosureJudgmentV1"),
    )
    tokens = compact_tokens(source.tokens)
    for constructor, verified in exact_routes:
        require(
            f"{constructor},{verified}," in tokens,
            f"durable external-ingress route {constructor} does not consume {verified}",
        )
    require(
        _item_visibility(source, "struct", "C2PreparedExternalIngressV1")
        == "pub(crate)",
        "opaque prepared external ingress has invalid visibility",
    )
    prepared_body = compact_tokens(source.tokens)
    require(
        "pub(crate)structC2PreparedExternalIngressV1{route:C2ExternalSigningRouteV1,"
        "request_identity:ExternalCarrierIdentityV1,"
        "carrier_identity:ExternalCarrierIdentityV1,canonical_request:Vec<u8>,"
        "canonical_carrier:Vec<u8>,}"
        in prepared_body,
        "prepared external ingress does not retain exact route/request/carrier/content",
    )
    expectation_join = inventory.require_function(
        SIGNER_GOVERNANCE,
        "verify_expectation_basis",
        "ExternalCarrierVerificationPermitV1",
    )
    expectation_join_code = compact_tokens(expectation_join.item_tokens)
    require(
        expectation_join.visibility == "private"
        and len(expectation_join.calls("verify_current_actor")) == 1
        and all(
            coordinate in expectation_join_code
            for coordinate in (
                "creator_pid",
                "actor_instance_identity",
                "actor_snapshot_identity",
                "actor_effect_epoch",
            )
        ),
        "carrier verification does not join permit and expectation actor/snapshot/epoch/process seals",
    )
    require(
        _source_token_count(
            source,
            ("permit", ".", "verify_expectation_basis", "(", "expectation", ")", "?"),
        )
        == 2,
        "bootstrap and macro-generated pair verifiers do not both enforce the expectation join",
    )
    for preparer in (
        "prepare_verified_revocation_effect_v1",
        "prepare_verified_quarantine_closure_effect_v1",
    ):
        function = inventory.require_function(SIGNER_GOVERNANCE, preparer)
        require(
            function.visibility == "pub(incrate::store_generation)"
            and len(function.calls("verify_for_actor")) == 1,
            f"{preparer} does not bind its prepared effect to the exact Store actor",
        )
    durable_append = inventory.require_function(
        SIGNER_GOVERNANCE, "append_prepared_external_ingress"
    )
    require(
        durable_append.visibility == "pub(crate)"
        and len(durable_append.calls("execute")) == 1
        and len(durable_append.calls("load_external_ingress_for_request")) == 1,
        "durable external ingress lacks one exact replay/collision/insert boundary",
    )

    obsolete_product = [
        function
        for function in inventory.functions
        if not function.cfg_test
        and (
            function.owner == "ExternalCarrierReplayGuardV1"
            or "ExternalCarrierStoreIngressPermitV1" in function.signature_code
        )
    ]
    require(
        not obsolete_product,
        "obsolete process-local external replay path remains product-reachable: "
        + ", ".join(function.location for function in obsolete_product),
    )
    return (
        "external-verification-permit-constructors=1-live-actor",
        "terminal-A1-production-verifiers=1-live-store-same-snapshot",
        f"durable-external-ingress-routes={len(exact_routes)}",
        "governed-route-actor-roots=7",
        "durable-external-ingress-consumers=3-sealed",
        "permit-expectation-join=actor+snapshot+epoch+process",
        "external-replay-status=durable-exact-replay-vs-collision",
    )
FENCE_ROW_CONSTRUCTOR = (
    "construct_sg_wu_02_fence_shared_process_global_fork_fence_primitive"
)
FENCE_ROW_VERIFIER = "verify_sg_wu_02_fence_shared_process_global_fork_fence_primitive"
SPAWN_ROW_CONSTRUCTOR = (
    "construct_sg_wu_02_spawn_production_spawn_integration_shared_fence"
)
SPAWN_ROW_VERIFIER = "verify_sg_wu_02_spawn_production_spawn_integration_shared_fence"

# Call names that create or replace a process image without going through
# std::process::Command.  Exact call-name matching (not substring scanning)
# keeps unrelated identifiers such as `chain_fork` out of scope.
PROCESS_CREATION_CALL_NAMES = frozenset(
    {
        "fork",
        "vfork",
        "posix_spawn",
        "posix_spawnp",
        "execve",
        "execveat",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execvp",
        "execvpe",
        "fexecve",
    }
)

# Production launch wrappers whose `launch.spawn(...)` call is the pinned
# `VerifiedLaunch::spawn` delegation into the choke, not a Command spawn.
LAUNCH_WRAPPER_SPECS = (
    (CORE_RUNNER, "spawn"),
    (CORE_UNIX_RUNNER, "spawn_helper"),
)

# The complete public API the fork fence may expose.  Anything beyond this
# surface is a reset/recovery/bypass route and is refused.
FENCE_PUBLIC_API_NAMES = frozenset(
    {
        "acquire",
        "verify_same_process",
        "drop",
        FENCE_ROW_CONSTRUCTOR,
        FENCE_ROW_VERIFIER,
    }
)

FENCE_IDENTS = frozenset(
    {"C2ForkFence", "C2ForkFenceGuard", "C2_FORK_FENCE", "C2_FORK_FENCE_HELD"}
)

# Identifier stems the authority-neutral fence API must never reference.
FENCE_AUTHORITY_STEMS = (
    "signer",
    "store",
    "key",
    "seed",
    "path",
    "message",
    "policy",
    "authority",
    "custody",
    "secret",
)

FENCE_RESET_STEMS = ("reset", "clear", "recover", "bypass")


def _function_idents(function: Function) -> frozenset[str]:
    return frozenset(token.value for token in function.item_tokens if token.kind == "ident")


def _static_mutex_names(source: RustSource) -> tuple[str, ...]:
    values = [token.value for token in source.tokens]
    return tuple(
        values[index + 1]
        for index in range(len(values) - 3)
        if values[index] == "static"
        and values[index + 1] not in {"mut"}
        and values[index + 2] == ":"
        and "Mutex" in values[index + 3 : index + 9]
    )


def _manifest_dependency_names(manifest: dict) -> frozenset[str]:
    names: set[str] = set()
    for key, table in manifest.items():
        if "dependencies" in key and isinstance(table, dict):
            names.update(table)
    target = manifest.get("target")
    if isinstance(target, dict):
        for target_table in target.values():
            if not isinstance(target_table, dict):
                continue
            for key, table in target_table.items():
                if "dependencies" in key and isinstance(table, dict):
                    names.update(table)
    return frozenset(names)


def _load_manifest(root: Path, relative: str) -> dict:
    path = root / relative
    require(path.is_file(), f"required Cargo manifest is absent: {relative}")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _verify_fence_dependency_acyclicity(
    root: Path, manifests: dict[str, dict] | None = None
) -> None:
    """Prove the fence owner is a leaf: nq-store depends on it, never back."""

    if manifests is None:
        manifests = {
            relative: _load_manifest(root, relative)
            for relative in (HELPER_SANDBOX_MANIFEST, STORE_MANIFEST)
        }
    helper_dependencies = _manifest_dependency_names(manifests[HELPER_SANDBOX_MANIFEST])
    require(
        "nq-store" not in helper_dependencies and "nq-core" not in helper_dependencies,
        "nq-helper-sandbox depends upward on nq-store/nq-core: "
        + ", ".join(sorted(helper_dependencies)),
    )
    store_dependencies = _manifest_dependency_names(manifests[STORE_MANIFEST])
    require(
        "nq-helper-sandbox" in store_dependencies,
        "nq-store does not depend on the fence owner nq-helper-sandbox",
    )


def _verify_signer_process_fence(
    inventory: SourceInventory, manifests: dict[str, dict] | None = None
) -> tuple[str, ...]:
    """Prove the shared fork fence has one owner and no production bypass."""

    sandbox = inventory.source(HELPER_SANDBOX)

    # 1. Exactly one process-global fence owner.
    require(
        _source_token_count(sandbox, ("static", "C2_FORK_FENCE", ":", "Mutex")) == 1,
        "helper sandbox must define exactly one static C2_FORK_FENCE: Mutex",
    )
    for source in inventory.sources:
        static_count = _source_token_count(source, ("static", "C2_FORK_FENCE"))
        require(
            static_count == (1 if source.path.as_posix() == HELPER_SANDBOX else 0),
            f"C2_FORK_FENCE static count changed in {source.path}",
        )
        for name in _static_mutex_names(source):
            lowered = name.lower()
            if "fence" in lowered or "fork" in lowered:
                require(
                    source.path.as_posix() == HELPER_SANDBOX and name == "C2_FORK_FENCE",
                    f"second fork/fence process mutex {name} in {source.path}",
                )
        if source.path.as_posix() != HELPER_SANDBOX:
            require(
                not source.identifier_occurrences("C2_FORK_FENCE"),
                f"C2_FORK_FENCE escapes its owner into {source.path}",
            )
    guard_structs = sum(
        _source_token_count(source, ("struct", "C2ForkFenceGuard"))
        for source in inventory.sources
    )
    require(guard_structs == 1, "C2ForkFenceGuard must have exactly one definition")
    fence_structs = sum(
        _source_token_count(source, ("struct", "C2ForkFence"))
        for source in inventory.sources
    )
    require(fence_structs == 1, "C2ForkFence must have exactly one definition")
    fence_acquires = tuple(
        function
        for function in inventory.functions_named("acquire")
        if function.owner == "C2ForkFence"
    )
    require(
        len(fence_acquires) == 1
        and fence_acquires[0].source.path.as_posix() == HELPER_SANDBOX,
        "C2ForkFence::acquire is absent or ambiguous",
    )
    acquire = fence_acquires[0]

    # 2. acquire is pub, locks the shared static, is non-reentrant, and never
    # recovers from poison.
    require(
        acquire.visibility == "pub",
        "C2ForkFence::acquire is not public",
    )
    acquire_code = compact_tokens(acquire.item_tokens, include_literals=False)
    require(
        "C2_FORK_FENCE.lock()" in acquire_code,
        "C2ForkFence::acquire does not lock C2_FORK_FENCE",
    )
    require(
        _source_token_count(sandbox, ("thread_local", "!")) >= 1
        and _source_token_count(
            sandbox, ("static", "C2_FORK_FENCE_HELD", ":", "Cell")
        )
        == 1
        and "C2_FORK_FENCE_HELD" in acquire_code,
        "fork fence non-reentrancy thread-local is absent or not consulted in acquire",
    )
    sandbox_production = [
        function
        for function in sandbox.functions
        if not function.cfg_test
        and function.source.path.as_posix() == HELPER_SANDBOX
    ]
    for function in sandbox_production:
        code = compact_tokens(function.item_tokens, include_literals=False)
        idents = _function_idents(function)
        require(
            "into_inner" not in idents and "clear_poison" not in idents,
            f"fence poison recovery is present at {function.location}",
        )
        if "C2_FORK_FENCE" in idents:
            require(
                "lock().unwrap(" not in code
                and "lock().expect(" not in code
                and "unwrap_or_else(" not in code,
                f"fence lock result is unwrapped or recovered at {function.location}",
            )

    # 3. The guard rechecks process identity and never leaks the inner lock.
    verify_same_process = inventory.require_function(
        HELPER_SANDBOX, "verify_same_process", "C2ForkFenceGuard"
    )
    require(
        verify_same_process.visibility == "pub",
        "C2ForkFenceGuard::verify_same_process is not public",
    )
    same_process_code = compact_tokens(
        verify_same_process.item_tokens, include_literals=False
    )
    require(
        "std::process::id()" in same_process_code
        and "self.owner_pid" in same_process_code,
        "verify_same_process does not compare the live pid against the stored owner pid",
    )
    require(
        _item_body_token_count(sandbox, "struct", "C2ForkFenceGuard", ("owner_pid", ":", "u32"))
        == 1
        and _item_body_token_count(
            sandbox, "struct", "C2ForkFenceGuard", ("_guard", ":", "MutexGuard")
        )
        == 1,
        "C2ForkFenceGuard does not retain exactly the lock guard and the owner pid",
    )
    for function in inventory.functions:
        if function.owner != "C2ForkFenceGuard":
            continue
        require(
            "MutexGuard" not in function.signature_code
            and "Mutex" not in function.signature_code,
            f"guard accessor leaks the inner lock at {function.location}",
        )

    # 4. The fence public API is authority-neutral.  The lexer omits comments
    # and literal contents, so only parsed code tokens are consulted here.
    fence_api_functions = [
        function
        for function in sandbox_production
        if function.owner in {"C2ForkFence", "C2ForkFenceGuard"}
        or function.name in {FENCE_ROW_CONSTRUCTOR, FENCE_ROW_VERIFIER}
    ]
    require(
        {function.name for function in fence_api_functions}
        >= {"acquire", "verify_same_process", FENCE_ROW_CONSTRUCTOR, FENCE_ROW_VERIFIER},
        "fence public API census is incomplete",
    )
    for function in fence_api_functions:
        signature = compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
        lowered = signature.lower()
        leaks = [stem for stem in FENCE_AUTHORITY_STEMS if stem in lowered]
        require(
            not leaks,
            f"authority-neutral fence API references {leaks} at {function.location}",
        )
    for type_name in ("C2ForkFence", "C2ForkFenceGuard"):
        lowered = type_name.lower()
        require(
            not any(stem in lowered for stem in FENCE_AUTHORITY_STEMS),
            f"fence public type name {type_name} is not authority-neutral",
        )

    # 5. The sole production spawn choke holds the fence across the complete
    # descriptor-handoff/spawn/restore interval.
    central_spawn = inventory.require_function(
        CORE_IDENTITY, "spawn_with_inherited_descriptors"
    )
    require(
        central_spawn.visibility == "pub(crate)",
        "spawn choke visibility changed",
    )
    central_code = compact_tokens(central_spawn.item_tokens, include_literals=False)
    central_sequence = (
        "C2ForkFence::acquire()",
        "DESCRIPTOR_LAUNCH.lock()",
        "make_inheritable(descriptors)",
        "command.spawn()",
        "restore_descriptor_flags(descriptors,&original_flags)",
    )
    central_positions = [central_code.find(value) for value in central_sequence]
    require(
        all(position >= 0 for position in central_positions)
        and central_positions == sorted(central_positions)
        and len(set(central_positions)) == len(central_positions),
        "central helper spawn does not hold the C2 fork fence before descriptor handoff/spawn/restore",
    )
    require(
        len(central_spawn.calls("spawn")) == 1,
        "spawn choke must contain exactly one command.spawn()",
    )

    # 6. No production process-creation bypass anywhere in the searched
    # production source scope.
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
    pinned_wrappers = {(path, name) for path, name in LAUNCH_WRAPPER_SPECS}
    process_bypasses: list[str] = []
    for function in inventory.functions:
        path = function.source.path.as_posix()
        idents = _function_idents(function)
        code = compact_tokens(function.item_tokens, include_literals=False)
        if "tokio::process" in code:
            process_bypasses.append(f"{function.location}:tokio::process")
        for call in function.calls():
            if call.name in {"output", "status"}:
                process_bypasses.append(f"{function.location}:{call.name}")
            elif call.name in PROCESS_CREATION_CALL_NAMES:
                process_bypasses.append(f"{function.location}:{call.name}")
            elif call.name == "spawn":
                allowed = (
                    (function is central_spawn and call.receiver == "command")
                    or call.path == "thread::spawn"
                    or (
                        (path, function.name) in pinned_wrappers
                        and call.receiver == "launch"
                    )
                    or (
                        call.receiver is None
                        and call.path == "spawn"
                        and (path, "spawn") in pinned_wrappers
                    )
                    or (call.receiver is not None and "Command" not in idents)
                )
                if not allowed:
                    process_bypasses.append(f"{function.location}:spawn:{call.receiver}")
        if any("cfg(feature" in attribute for attribute in function.attributes):
            feature_calls = {
                call.name
                for call in function.calls()
                if call.name in {"spawn", "output", "status"} | PROCESS_CREATION_CALL_NAMES
            }
            require(
                "Command" not in idents and not feature_calls,
                f"feature-gated production function creates processes at {function.location}",
            )
    require(
        not process_bypasses,
        "production process creation bypasses the fenced choke: "
        + ", ".join(process_bypasses),
    )
    command_constructors = {
        function.location
        for function in inventory.functions
        if "Command::new(" in compact_tokens(function.item_tokens, include_literals=False)
    }
    launcher = inventory.require_function(CORE_IDENTITY, "spawn", "VerifiedLaunch")
    loader = inventory.require_function(CORE_RUNTIME, "invoke_loader")
    require(
        command_constructors == {launcher.location, loader.location},
        "production Command construction census changed: "
        + ", ".join(sorted(command_constructors)),
    )

    # 7. Loader and runner launch sites route to the fenced choke.
    require(
        len(loader.calls("spawn_with_inherited_descriptors")) == 1,
        "invoke_loader does not route through the fenced spawn choke",
    )
    loader_process_calls = {
        call.name
        for call in loader.calls()
        if call.name in {"spawn", "output", "status"}
    }
    require(
        not loader_process_calls,
        f"invoke_loader creates a process directly: {sorted(loader_process_calls)}",
    )
    require(
        "Command::new(" in compact_tokens(launcher.item_tokens, include_literals=False)
        and len(launcher.calls("spawn_with_inherited_descriptors")) == 1,
        "VerifiedLaunch::spawn no longer builds the command and delegates to the choke",
    )
    for wrapper_path, wrapper_name in LAUNCH_WRAPPER_SPECS:
        wrapper = inventory.require_function(wrapper_path, wrapper_name)
        wrapper_spawns = [
            call for call in wrapper.calls("spawn") if call.receiver == "launch"
        ]
        require(
            len(wrapper_spawns) == 1,
            f"{wrapper.location} does not launch exactly once through VerifiedLaunch::spawn",
        )
    launch_spawn_callers = {
        (function.source.path.as_posix(), function.name)
        for function in inventory.functions
        for call in function.calls("spawn")
        if call.receiver == "launch"
    }
    require(
        launch_spawn_callers == pinned_wrappers,
        "VerifiedLaunch::spawn has an alternate production caller: "
        + ", ".join(f"{path}::{name}" for path, name in sorted(launch_spawn_callers)),
    )
    choke_callers = {
        function.qualified_name
        for function in inventory.callers_of("spawn_with_inherited_descriptors")
    }
    require(
        choke_callers
        == {
            "VerifiedLaunch::spawn",
            "invoke_loader",
            SPAWN_ROW_CONSTRUCTOR,
        },
        "spawn choke has an alternate production caller: "
        + ", ".join(sorted(choke_callers)),
    )

    # 8. The named spawn row constructor only delegates to the choke.
    spawn_row = inventory.require_function(CORE_IDENTITY, SPAWN_ROW_CONSTRUCTOR)
    require(
        spawn_row.visibility == "pub(crate)"
        and len(spawn_row.calls("spawn_with_inherited_descriptors")) == 1
        and not spawn_row.calls("spawn")
        and "Command::new("
        not in compact_tokens(spawn_row.item_tokens, include_literals=False),
        "spawn row constructor is a second spawn owner instead of a choke delegation",
    )
    spawn_row_verifier = inventory.require_function(CORE_IDENTITY, SPAWN_ROW_VERIFIER)
    require(
        "C2ForkFence::acquire()"
        in compact_tokens(spawn_row_verifier.item_tokens, include_literals=False),
        "spawn row verifier does not acquire the shared fork fence",
    )

    # 9. Custody secret-live intervals hold the fence from entry through the
    # post-zeroization process recheck.
    create = inventory.require_function(
        SIGNER_CUSTODY, "create_below_root", "C2StoreIntegrityCustodian"
    )
    sign_crypto = inventory.require_function(
        SIGNER_CUSTODY,
        "sign_after_authority_checks",
        "C2StoreIntegrityCustodian",
    )
    for function, sequence in (
        (
            create,
            (
                "C2ForkFence::acquire()",
                "coordinates.validate()",
                "scope_mutex.lock()",
                "getrandom::fill(&mutseed)",
                "bytes.fill(0)",
                "drop(private_file)",
                "drop(seed)",
                "fork_fence_guard.verify_same_process()",
            ),
        ),
        (
            sign_crypto,
            (
                "C2ForkFence::acquire()",
                "self.load_seed_for_signing()",
                "signing_key.sign(&preimage)",
                "object_facts(&reopened)",
                "drop(seed)",
                "fork_fence_guard.verify_same_process()",
            ),
        ),
    ):
        code = compact_tokens(function.item_tokens, include_literals=False)
        positions = [code.find(value) for value in sequence]
        require(
            all(position >= 0 for position in positions)
            and positions == sorted(positions)
            and len(set(positions)) == len(positions),
            f"{function.location} does not fence its complete live-secret interval",
        )

    # Public/purpose-locked signing entry points perform only authority checks;
    # every route that actually reloads secret custody is centralized in the
    # private fenced helper above.  Pin its complete caller set so moving the
    # fence out of an entry point cannot create an alternate secret-live lane.
    sign_crypto_callers = {
        function.name
        for function in inventory.callers_of("sign_after_authority_checks")
        if function.source.path.as_posix() == SIGNER_CUSTODY
    }
    require(
        sign_crypto_callers
        == {"sign", "sign_initial_possession"},
        "custody cryptographic helper has an alternate or missing caller: "
        + ", ".join(sorted(sign_crypto_callers)),
    )

    # 10. No secret-live path performs process creation.
    custody_source = inventory.source(SIGNER_CUSTODY)
    for function in custody_source.functions:
        if function.cfg_test:
            continue
        idents = _function_idents(function)
        process_calls = {
            call.name
            for call in function.calls()
            if call.name in {"spawn", "output", "status"} | PROCESS_CREATION_CALL_NAMES
        }
        require(
            "Command" not in idents and not process_calls,
            f"signer custody path creates a process at {function.location}",
        )

    # 11. No constructed child receives signer-secret material.
    for function in inventory.functions:
        idents = _function_idents(function)
        code = compact_tokens(function.item_tokens, include_literals=False)
        if "Command" not in idents and "Command::new(" not in code:
            continue
        lowered = {ident.lower() for ident in idents}
        secret_leaks = sorted(
            ident
            for ident in lowered
            if "seed" in ident or "signing_key" in ident or "private_key" in ident
        )
        require(
            not secret_leaks,
            f"Command-constructing path references signer secret material "
            f"{secret_leaks} at {function.location}",
        )

    # 12. Dependency direction is acyclic: the fence owner is a leaf crate.
    _verify_fence_dependency_acyclicity(inventory.root, manifests)

    # 13. No production reset, recovery, or bypass route exists for the fence.
    fence_lockers = [
        function
        for function in inventory.functions
        if "C2_FORK_FENCE.lock()" in compact_tokens(function.item_tokens, include_literals=False)
    ]
    require(
        [function.qualified_name for function in fence_lockers]
        == ["C2ForkFence::acquire"],
        "a function other than acquire locks C2_FORK_FENCE: "
        + ", ".join(function.location for function in fence_lockers),
    )
    for function in inventory.functions:
        idents = _function_idents(function)
        if not (FENCE_IDENTS & idents or "fork_fence_guard" in idents):
            continue
        require(
            not any(stem in function.name.lower() for stem in FENCE_RESET_STEMS),
            f"fence reset/recovery/bypass route present at {function.location}",
        )
        if function.source.path.as_posix() != HELPER_SANDBOX:
            continue
        if function.owner in {"C2ForkFence", "C2ForkFenceGuard"} or (
            FENCE_IDENTS & idents
        ):
            require(
                function.name in FENCE_PUBLIC_API_NAMES,
                f"fence exposes an unapproved public surface at {function.location}",
            )
    for row_name in (FENCE_ROW_CONSTRUCTOR, FENCE_ROW_VERIFIER):
        row_function = inventory.require_function(HELPER_SANDBOX, row_name)
        require(
            row_function.visibility == "pub",
            f"{row_name} must remain public",
        )
    return (
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
    )


def _verify_restart_noncreation_graph(inventory: SourceInventory) -> tuple[str, ...]:
    legacy_product = [
        function
        for function in inventory.functions
        if function.source.path.as_posix() == SIGNER_RESTART
    ]
    require(
        not legacy_product,
        "superseded raw restart model remains product-compiled: "
        + ", ".join(function.location for function in legacy_product),
    )
    prohibited = {
        "CompleteSignerRestartSnapshotV1",
        "ReconstructedTerminalSignerCapabilityV1",
        "construct_complete_signer_restart_snapshot",
        "construct_sg_n_29_restart_reconstructs_capability_complete_durable_authority_plus",
    }
    leaks: list[str] = []
    for function in inventory.functions:
        code = compact_tokens(function.item_tokens)
        overlap = sorted(name for name in prohibited if name in code)
        if overlap:
            leaks.append(f"{function.location}:{','.join(overlap)}")
    require(
        not leaks,
        "raw restart evidence/capability shape remains product-reachable: "
        + ", ".join(leaks),
    )
    reopen = inventory.require_function(
        LIVE_C2, "with_reopened_c2_generation_current_v1", "Store"
    )
    require(
        reopen.visibility == "pub(crate)"
        and len(reopen.calls("with_c2_authority_snapshot")) == 1,
        "fresh-process reopen is not owned by the sole Store snapshot actor factory",
    )
    actor_reopen = inventory.require_function(
        LIVE_C2, "with_reopened_generation_current_v1", "StoreC2SnapshotActorV1"
    )
    require(
        actor_reopen.visibility == "private"
        and len(reopen.calls("with_reopened_generation_current_v1")) == 1
        and len(actor_reopen.calls("resolve_generation_current_evidence_v1")) == 1
        and len(actor_reopen.calls("reopen_complete_physical_substrate_v1")) == 1
        and len(actor_reopen.calls("reopen_terminal_foundation_custodian_v1")) == 1
        and len(actor_reopen.calls("verify_generation_current_custody")) == 1
        and len(
            actor_reopen.calls("mint_reopened_terminal_generation_current_v1")
        )
        == 1,
        "fresh Store reopen does not re-resolve complete evidence inside the sole actor",
    )
    code = compact_tokens((*reopen.item_tokens, *actor_reopen.item_tokens))
    require(
        "GenerationCurrentV1" in code
        and "CompleteSignerRestartSnapshotV1" not in code
        and "ReconstructedTerminalSignerCapabilityV1" not in code,
        "fresh Store reopen delegates authority to the superseded raw restart model",
    )
    lineage = inventory.source(SIGNER_LINEAGE)
    for function in [function for function in lineage.functions if not function.cfg_test]:
        sorting = {
            "sort",
            "sort_by",
            "sort_by_key",
            "max",
            "max_by",
            "max_by_key",
        }.intersection(_function_call_names(function))
        require(
            not sorting,
            f"lineage selects authority by sorting or maximum at {function.location}: {sorted(sorting)}",
        )
    return (
        "legacy-raw-restart-model=compile-confined",
        "reopen-owner=live-store-snapshot-actor",
        "lineage-sorting=absent",
    )


def _verify_post_msg07_predecessor_refresh_before_msg06(
    inventory: SourceInventory,
) -> tuple[str, ...]:
    """Pin the linear MSG-07 -> refreshed predecessor -> MSG-06 seam.

    MSG-07 advances the retained actor snapshot.  The former current context
    is therefore stale and must be refined in place before it can mint the
    predecessor authority consumed by the mandatory MSG-06 route.  This
    verifier binds all three layers of that dependency rather than merely
    checking that the refresh helper happens to exist.
    """

    driver = inventory.require_function(
        LIVE_C2, "complete_healthy_successor_v1", "StoreC2SnapshotActorV1"
    )
    require(
        len(driver.calls("append_successor_possession_v1")) == 1
        and len(driver.calls("append_healthy_rotation_intent_v1")) == 1,
        "healthy successor does not have exactly one MSG-07 and one continuity step",
    )
    driver_code = compact_tokens(driver.item_tokens)
    driver_code_with_literals = compact_tokens(driver.item_tokens, include_literals=True)
    terminal_one_use = (
        "FROM c2_signer_succession_projection\n"
        "                    WHERE transition_identity = ?1"
    )
    require(
        terminal_one_use in driver_code_with_literals
        and "LineageRefusalV1::DuplicateTransition" in driver_code
        and driver_code_with_literals.index(terminal_one_use)
        < driver_code_with_literals.index("prepare_ordinary_successor_custody_v1"),
        "healthy successor lacks the pre-custody terminal-transition one-use refusal",
    )
    _require_calls_in_order(
        driver,
        (
            "append_successor_possession_v1",
            "append_healthy_rotation_intent_v1",
            "consume_ordinary_successor_foundation_authority_v1",
        ),
    )

    continuity = inventory.require_function(
        LIVE_C2, "append_healthy_rotation_intent_v1", "StoreC2SnapshotActorV1"
    )
    required_once = (
        "refresh_current_predecessor_after_msg07_v1",
        "mint_current_predecessor_authority_v1",
        "consume_current_predecessor_authority_v1",
        "from_store_actor_resolution",
        "append_healthy_rotation_intent",
    )
    require(
        all(len(continuity.calls(name)) == 1 for name in required_once),
        "post-MSG-07 continuity seam omits or duplicates refresh/authority/MSG-06 construction",
    )
    _require_calls_in_order(continuity, required_once)
    continuity_code = compact_tokens(continuity.item_tokens)
    require(
        "refresh_current_predecessor_after_msg07_v1(current,pending,&possession)?"
        in continuity_code
        and "mint_current_predecessor_authority_v1(current)?" in continuity_code
        and "consume_current_predecessor_authority_v1(predecessor,current)?"
        in continuity_code,
        "refresh output is not the exact predecessor context consumed before MSG-06",
    )

    refresh = inventory.require_function(
        LIVE_C2,
        "refresh_current_predecessor_after_msg07_v1",
        "StoreC2SnapshotActorV1",
    )
    refresh_signature = compact_tokens(
        refresh.source.tokens[refresh.start_token : refresh.body_open_token]
    )
    refresh_code = compact_tokens(refresh.item_tokens)
    require(
        "possession:&ConsumedSuccessorPossessionV1" in refresh_signature
        and len(refresh.calls("verify_same_snapshot")) == 1
        and len(refresh.calls("verify_for_actor")) == 1
        and len(refresh.calls("verify_live")) == 2
        and (
            "current.coordinates.predecessor_frontier_identity="
            "possession.resulting_frontier_identity()"
        )
        in refresh_code
        and (
            "current.coordinates.predecessor_event_identity="
            "Some(possession.message_identity())"
        )
        in refresh_code
        and "possession.append_identity().as_bytes()" in refresh_code
        and "possession.effect_receipt_identity().as_bytes()" in refresh_code,
        "predecessor refresh does not bind the exact consumed MSG-07 result",
    )

    coordinator = inventory.require_function(
        SIGNER_COORDINATOR,
        "append_healthy_rotation_intent",
        "C2SignerTransitionCoordinator",
    )
    require(
        len(coordinator.calls("append_normal_rotation_continuity")) == 1
        and len(coordinator.calls("append_policy_transition_intent")) == 1,
        "healthy coordinator does not append exactly one mandatory MSG-06 before MSG-11",
    )
    _require_calls_in_order(
        coordinator,
        (
            "verify_for_actor",
            "append_normal_rotation_continuity",
            "append_policy_transition_intent",
        ),
    )
    coordinator_code = compact_tokens(coordinator.item_tokens)
    require(
        "mandatory_msg06.message_identity" in coordinator_code
        and "mandatory_msg06," in coordinator_code,
        "MSG-06 consumption is not retained in the healthy continuity result",
    )
    return (
        "terminal-transition-one-use=before-custody",
        "healthy-order=MSG07<refresh<predecessor-authority<MSG06",
        "msg07-refresh-binding=frontier+event+append+receipt",
        "mandatory-msg06-count=1",
    )


def _special_path_inventory(inventory: SourceInventory) -> C2ConstructorPathInventoryV2:
    """Inventory every Store-owned live-C2 entry plus fresh reopen root.

    Terminal-A1 signing is asynchronous, so a SQLite transaction, OS lock, or
    process-local authority object cannot honestly span the request/carrier
    boundary.  The canonical fresh lifecycle therefore has two Store-owned
    entry roots: a durable inert preparation and an exact resume/install.  The
    pair is one bootstrap lifecycle path, not two alternate installers.  The
    two healthy-successor roots are likewise one nominal lifecycle with
    distinct unchanged-policy and governed-MSG-01 entry contracts.  Restore
    and recovery remain nominally distinct discontinuity paths.
    """

    prepare_row, prepare_path, prepare_owner, prepare_name, _ = SPECIAL_ROOT_SPECS[0]
    prepare = inventory.require_function(prepare_path, prepare_name, prepare_owner)
    require(
        prepare.visibility == "pub(crate)",
        f"{prepare_row} root is not crate-private",
    )
    prepare_signature = compact_tokens(
        prepare.source.tokens[prepare.start_token : prepare.body_open_token]
    )
    require(
        "bool" not in prepare_signature
        and "&mutself" in prepare_signature
        and "StoreC2QualifiedRuntimeEvidenceV1" in prepare_signature
        and "StoreIntegritySignerImplementationManifestV1" in prepare_signature
        and "StorePreparedBootstrapGrantRequestV1" in prepare_signature,
        "bootstrap preparation accepts raw authority or returns something other than inert request evidence",
    )
    _require_calls_in_order(
        prepare,
        (
            "with_c2_authority_snapshot",
            "admit_signer_implementation_manifest_v1",
            "prepare_initial_bootstrap_grant_request_v1",
        ),
    )
    require(
        not prepare.calls("mint_bootstrap_signer_context")
        and not prepare.calls("install_c2_live_v1"),
        "asynchronous bootstrap preparation minted live standing or entered installation",
    )

    install_row, install_path, install_owner, install_name, _ = SPECIAL_ROOT_SPECS[1]
    install = inventory.require_function(install_path, install_name, install_owner)
    require(
        install.visibility == "pub(crate)",
        f"{install_row} root is not crate-private",
    )
    install_signature = compact_tokens(
        install.source.tokens[install.start_token : install.body_open_token]
    )
    require(
        "bool" not in install_signature
        and "&mutself" in install_signature
        and "StoreC2QualifiedRuntimeEvidenceV1" in install_signature
        and "StoreIntegritySignerImplementationManifestV1" in install_signature
        and "StoreIntegrityBootstrapGrantV1" in install_signature
        and "StorePreparedBootstrapGrantRequestV1" not in install_signature,
        "bootstrap resume accepts raw authority or caller-supplied prepared custody/request state",
    )
    _require_calls_in_order(
        install,
        (
            "with_c2_authority_snapshot",
            "admit_signer_implementation_manifest_v1",
            "reopen_prepared_bootstrap_custodian_v1",
            "seal_reopened_foundational_custody",
            "adopt_bootstrap_grant_v1",
            "construct_initial_enrollment_candidate_v1",
            "construct_verified_initial_possession_request_v1",
            "append_initial_proposal_pop_v1",
            "derive_initial_foundational_enrollment_v1",
            "adopt_foundational_enrollment_v1",
            "accept_signer_enrollment_v1",
            "derive_final_install_policy_v1",
            "mint_bootstrap_signer_context",
            "install_c2_live_v1",
        ),
    )

    transition_root_specs = (
        (
            SPECIAL_ROOT_SPECS[2],
            (
                "StoreC2QualifiedRuntimeEvidenceV1",
                "StoreIntegritySignerImplementationManifestV1",
                "C2HealthySuccessorIntentV1",
            ),
            (
                "with_c2_authority_snapshot",
                "admit_signer_implementation_manifest_v1",
                "with_reopened_generation_current_v1",
                "complete_healthy_successor_v1",
            ),
            (
                "complete_store_restore_lifecycle_v1",
                "complete_store_recovery_lifecycle_v1",
                "adopt_activation_successor_grant_v1",
            ),
        ),
        (
            SPECIAL_ROOT_SPECS[3],
            (
                "StoreC2QualifiedRuntimeEvidenceV1",
                "StoreIntegritySignerImplementationManifestV1",
                "C2HealthySuccessorIntentV1",
                "StoreIntegrityActivationSuccessorGrantRequestV1",
                "StoreIntegrityActivationSuccessorGrantV1",
            ),
            (
                "with_c2_authority_snapshot",
                "admit_signer_implementation_manifest_v1",
                "with_reopened_generation_current_v1",
                "adopt_activation_successor_grant_v1",
                "refresh_current_after_external_ingress_v1",
                "from_store_adopted_activation_successor_grant",
                "complete_healthy_successor_v1",
            ),
            (
                "complete_store_restore_lifecycle_v1",
                "complete_store_recovery_lifecycle_v1",
            ),
        ),
        (
            SPECIAL_ROOT_SPECS[4],
            (
                "StoreC2QualifiedRuntimeEvidenceV1",
                "StoreIntegritySignerImplementationManifestV1",
                "StoreIntegrityRestoreAuthorizationRequestV1",
                "StoreIntegrityRestoreAuthorizationV1",
            ),
            (
                "with_c2_authority_snapshot",
                "admit_signer_implementation_manifest_v1",
                "complete_store_restore_lifecycle_v1",
            ),
            (
                "complete_healthy_successor_v1",
                "complete_store_recovery_lifecycle_v1",
            ),
        ),
        (
            SPECIAL_ROOT_SPECS[5],
            (
                "StoreC2QualifiedRuntimeEvidenceV1",
                "StoreIntegritySignerImplementationManifestV1",
                "C2RecoveryPreparationIntentV1",
            ),
            (
                "with_c2_authority_snapshot",
                "admit_signer_implementation_manifest_v1",
                "prepare_recovery_grant_request_v1",
            ),
            (
                "complete_healthy_successor_v1",
                "complete_store_restore_lifecycle_v1",
                "complete_store_recovery_lifecycle_v1",
            ),
        ),
        (
            SPECIAL_ROOT_SPECS[6],
            (
                "StoreC2QualifiedRuntimeEvidenceV1",
                "StoreIntegritySignerImplementationManifestV1",
                "StoreIntegrityRecoveryRequestV1",
                "StoreIntegrityRecoveryGrantV1",
            ),
            (
                "with_c2_authority_snapshot",
                "admit_signer_implementation_manifest_v1",
                "complete_store_recovery_lifecycle_v1",
            ),
            (
                "complete_healthy_successor_v1",
                "complete_store_restore_lifecycle_v1",
            ),
        ),
    )
    transition_roots: list[Function] = []
    for (row, path, owner, name, _), signature_types, ordered, forbidden_calls in transition_root_specs:
        root = inventory.require_function(path, name, owner)
        transition_roots.append(root)
        signature = compact_tokens(
            root.source.tokens[root.start_token : root.body_open_token]
        )
        require(
            root.visibility == "pub(crate)"
            and "&mutself" in signature
            and "bool" not in signature
            and all(type_name in signature for type_name in signature_types),
            f"{row} is not a crate-private typed Store root",
        )
        _require_calls_in_order(root, ordered)
        require(
            not any(root.calls(name) for name in forbidden_calls)
            and not WRAPPER_FORBIDDEN_IO.intersection(_function_call_names(root)),
            f"{row} crosses another lifecycle route or performs direct wrapper I/O",
        )

    _, reopen_path, reopen_owner, reopen_name = ORDINARY_ROOT_SPEC
    reopen = inventory.require_function(reopen_path, reopen_name, reopen_owner)
    require(
        reopen.visibility == "pub(crate)",
        "live GenerationCurrent reopen root is not crate-private",
    )
    reopen_signature = compact_tokens(
        reopen.source.tokens[reopen.start_token : reopen.body_open_token]
    )
    require(
        "bool" not in reopen_signature
        and "&mutself" in reopen_signature
        and "StoreC2QualifiedRuntimeEvidenceV1" in reopen_signature
        and "StoreIntegritySignerImplementationManifestV1" in reopen_signature,
        "live reopen root accepts Boolean/raw authority or omits qualified runtime/manifest evidence",
    )
    _require_calls_in_order(
        reopen,
        (
            "with_c2_authority_snapshot",
            "admit_signer_implementation_manifest_v1",
            "with_reopened_generation_current_v1",
        ),
    )
    actor_reopen = inventory.require_function(
        LIVE_C2, "with_reopened_generation_current_v1", "StoreC2SnapshotActorV1"
    )
    require(
        actor_reopen.visibility == "private",
        "fresh-process generation resolver escapes the Store actor",
    )
    call_groups = {
        name: actor_reopen.calls(name)
        for name in (
            "verify_authority_snapshot",
            "resolve_generation_current_evidence_v1",
            "reopen_complete_physical_substrate_v1",
            "reopen_terminal_foundation_custodian_v1",
            "verify_generation_current_custody",
            "mint_reopened_terminal_generation_current_v1",
        )
    }
    require(
        {name: len(calls) for name, calls in call_groups.items()}
        == {
            "verify_authority_snapshot": 1,
            "resolve_generation_current_evidence_v1": 1,
            "reopen_complete_physical_substrate_v1": 1,
            "reopen_terminal_foundation_custodian_v1": 1,
            "verify_generation_current_custody": 1,
            "mint_reopened_terminal_generation_current_v1": 1,
        },
        "reopen correspondence census changed",
    )
    ordered_positions = (
        call_groups["verify_authority_snapshot"][0].start,
        call_groups["resolve_generation_current_evidence_v1"][0].start,
        call_groups["reopen_complete_physical_substrate_v1"][0].start,
        call_groups["reopen_terminal_foundation_custodian_v1"][0].start,
        call_groups["verify_generation_current_custody"][0].start,
        call_groups["mint_reopened_terminal_generation_current_v1"][0].start,
    )
    require(
        list(ordered_positions) == sorted(ordered_positions),
        "reopen does not re-resolve and re-seal exact evidence after physical B/G reconciliation",
    )

    physical_reopen = inventory.require_function(
        LIVE_C2, "reopen_complete_physical_substrate_v1", "StoreC2SnapshotActorV1"
    )
    physical_groups = {
        name: physical_reopen.calls(name)
        for name in (
            "load_verified_durable_enrollment_bridge_v1",
            "reopen_from_foundational_evidence",
            "seal_reopened_foundational_custody",
            "load_durable_bootstrap_grant_pair_for_reopen_v1",
            "adopt_bootstrap_grant_v1",
            "rewrap_verified_durable_enrollment_bridge_v1",
            "reopen_complete_physical_generation_v1",
            "load_generation_current_evidence_before_governance_v1",
        )
    }
    require(
        all(len(calls) == 1 for calls in physical_groups.values()),
        "physical reopen substrate correspondence census changed",
    )
    _require_calls_in_order(
        physical_reopen,
        (
            "load_verified_durable_enrollment_bridge_v1",
            "reopen_from_foundational_evidence",
            "seal_reopened_foundational_custody",
            "load_durable_bootstrap_grant_pair_for_reopen_v1",
            "adopt_bootstrap_grant_v1",
            "rewrap_verified_durable_enrollment_bridge_v1",
            "reopen_complete_physical_generation_v1",
            "load_generation_current_evidence_before_governance_v1",
        ),
    )

    # The old five wrapper functions are retained only as archaeological
    # model/specimen code during this campaign. They are not canonical roots
    # and may have no production caller.
    superseded = (
        "install_c2_fresh",
        "install_c2_restore_successor",
        "continue_c2_installation",
        "transition_c2_active_policy",
        "continue_c2_policy_transition",
    )
    stale_callers = {
        name: [function.location for function in inventory.callers_of(name)]
        for name in superseded
        if inventory.callers_of(name)
    }
    require(
        not stale_callers,
        "superseded model-era C2 wrapper regained production reachability: "
        + json.dumps(stale_callers, sort_keys=True),
    )
    store_methods = {
        function.name: function
        for function in inventory.functions
        if function.source.path.as_posix() == LIVE_C2 and function.owner == "Store"
    }
    expected_public_roots = {
        spec[3] for spec in SPECIAL_ROOT_SPECS
    } | {ORDINARY_ROOT_SPEC[3]}
    require(
        {
            name
            for name, function in store_methods.items()
            if function.visibility == "pub(crate)"
        }
        == expected_public_roots
        and {
            name
            for name, function in store_methods.items()
            if function.visibility == "private"
        }
        == {"with_c2_authority_snapshot"},
        "live C2 Store production surface differs from the closed eight-root API: "
        + ", ".join(
            f"{name}:{function.visibility}"
            for name, function in sorted(store_methods.items())
        ),
    )
    return C2ConstructorPathInventoryV2(
        (
            _function_identity(prepare),
            _function_identity(install),
            *(_function_identity(root) for root in transition_roots),
        ),
        _function_identity(reopen),
    )
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
        # Candidate-certificate verification runs before Store admission and
        # has no durable mutation surface. Its fixed-path read-only trust I/O
        # is pinned separately by the facade/trust verifier below; including
        # those reads here would misclassify a precondition failure as a
        # lifecycle crash cut.
        if path == CANDIDATE_QUALIFICATION:
            continue
        # The manifest inventories production crash cuts.  Executable crash
        # specimens are evidence *about* those cuts, not additional product
        # mutation sites.  Module-level `#[cfg(test)]` is not propagated into
        # a separately parsed source file, so exclude both directly annotated
        # test functions and the conventional test-only module suffix.
        if (
            function.cfg_test
            or "test" in function.attributes
            or function.source.path.name.endswith("_tests.rs")
        ):
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


def source_derived_io_manifest(inventory: SourceInventory) -> dict:
    """Return the deterministic development crash-cut manifest on stdout.

    Cut labels are inventory ordinals, not semantic claims.  Regeneration is
    deliberately explicit because line/call changes require hostile review;
    this function never writes the checked-in artifact itself.
    """

    nodes = _collect_io_nodes(inventory).nodes
    require(
        len(nodes) <= 99,
        "C2 I/O inventory exceeds the two-digit development cut namespace",
    )
    return {
        "nodes": [
            {
                "call": node.call,
                "cut": f"SC-{index:02d}",
                "function": node.function,
                "line": node.line,
                "source": node.path,
            }
            for index, node in enumerate(nodes, start=1)
        ],
        "schema": "nq.c2_io_crash_cut_manifest.v1",
    }


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
    # Physical ownership means the single definition site of the projection
    # type.  Typed downstream references (imports, `&CurrentActivationForC2`
    # parameters in the terminal-A1 snapshot and ingress verifiers) are
    # consumers, not owners; the definition-site census below still refuses
    # any second definition anywhere, and the constructor census below still
    # refuses any second construction site, so this refines -- not weakens --
    # the single-owner obligation.
    owners = [
        source.path.as_posix()
        for source in inventory.sources
        if _source_token_count(source, ("struct", "CurrentActivationForC2"))
    ]
    require(
        len(owners) == 1,
        f"CurrentActivationForC2 must have one physical owner; found {owners}",
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
    return (f"owner={owners[0]}", f"constructor={constructor.qualified_name}")


def _verify_no_raw_restart_snapshot(inventory: SourceInventory) -> tuple[str, ...]:
    _verify_restart_noncreation_graph(inventory)
    return (
        "raw-restart-snapshot=absent-from-product",
        "authority-constructor=fresh-store-reopen-only",
    )


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
    governance = inventory.source(SIGNER_GOVERNANCE)
    route_specs = (
        (
            "restore",
            "StoreIntegrityRestoreAuthorizationV1",
            "adopt_restore_authorization",
            "adopt_restore_authorization_v1",
            "complete_store_restore_lifecycle_v1",
            "restore_c2_live_historical_foundation_v1",
            "prepare_restore_authorization_ingress",
            "verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity",
            "verify_restore_authorization_ingress_consumption",
            "begin_restore_successor_v1",
        ),
        (
            "recovery",
            "StoreIntegrityRecoveryGrantV1",
            "adopt_recovery_grant",
            "adopt_recovery_grant_v1",
            "complete_store_recovery_lifecycle_v1",
            "recover_c2_live_new_foundation_v1",
            "prepare_recovery_grant_ingress",
            "verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity",
            "verify_recovery_grant_ingress_consumption",
            "begin_recovery_entry_v1",
        ),
    )
    for (
        route,
        raw_type,
        session_name,
        adoption_name,
        driver_name,
        root_name,
        prepare_name,
        verification_name,
        consumption_name,
        entry_name,
    ) in route_specs:
        require(
            governance.identifier_occurrences(raw_type),
            f"exact external {route} carrier is absent",
        )
        session_entry = inventory.require_function(
            LIVE_C2, session_name, "C2LiveWriterSessionV1"
        )
        actor_adoption = inventory.require_function(
            LIVE_C2, adoption_name, "StoreC2SnapshotActorV1"
        )
        actor_driver = inventory.require_function(
            LIVE_C2, driver_name, "StoreC2SnapshotActorV1"
        )
        store_root = inventory.require_function(LIVE_C2, root_name, "Store")
        raw_carrier_consumers = [
            function
            for function in inventory.functions
            if raw_type in compact_tokens(function.item_tokens)
        ]
        require(
            {_function_identity(function) for function in raw_carrier_consumers}
            == {
                _function_identity(session_entry),
                _function_identity(actor_adoption),
                _function_identity(actor_driver),
                _function_identity(store_root),
            },
            f"raw {route} carrier escapes its exact session/adoption/driver/root chain: "
            + ", ".join(function.location for function in raw_carrier_consumers),
        )
        require(
            session_entry.visibility == "pub(crate)"
            and len(session_entry.calls(adoption_name)) == 1
            and not (
                set(_function_call_names(session_entry))
                & ({prepare_name} | WRAPPER_FORBIDDEN_IO)
            ),
            f"{route} writer-session ingress does not delegate without independently verifying or mutating",
        )
        _require_calls_in_order(
            actor_adoption,
            ("new", "from_store_actor", verification_name),
        )
        require(
            len(actor_adoption.calls(prepare_name)) == 1
            and len(actor_adoption.calls("append_verified_governed_carrier_effect")) == 1,
            f"{route} adoption does not append its exact verified preparation",
        )
        _require_calls_in_order(actor_driver, (adoption_name, entry_name))
        require(
            len(store_root.calls(driver_name)) == 1
            and not WRAPPER_FORBIDDEN_IO.intersection(_function_call_names(store_root)),
            f"{route} Store root bypasses its nominal actor driver",
        )
        consumption = inventory.require_function(SIGNER_GOVERNANCE, consumption_name)
        consumers = inventory.callers_of(consumption_name)
        require(
            consumption.visibility == "pub(crate)"
            and len(consumers) == 1
            and consumers[0].source.path.as_posix() == LIVE_C2
            and consumers[0].owner == "StoreC2SnapshotActorV1"
            and consumers[0].name == entry_name,
            f"Store-adopted {route} evidence has an alternate live-authority consumer",
        )
    return (
        "raw-discontinuity-carrier-consumers=2x4-exact-chain",
        "store-adopted-discontinuity-consumers=2x1-nominal-entry",
        "physical-restore-owner=one",
    )


def _verify_new_mutator_branding(inventory: SourceInventory) -> tuple[str, ...]:
    receipt = _run_inherited_verifier("verify_mutator_census.py")
    # The current live path owns mutation through one nonescaping Store actor,
    # not through the superseded model-era brands. Exact lower helpers may
    # accept a transaction/descriptor only when their complete caller set is
    # pinned below to that actor graph.
    mutating = IO_CALLS - {"open", "openat", "read_exact", "read_to_end"}
    exact_helpers = {
        FunctionIdentity(INSTALL, None, "create_fixed_file"),
        FunctionIdentity(INSTALL, None, "allocate_live_c2_fixed_files_v1"),
        FunctionIdentity(LOCK, None, "finalize_provisional_generation_lock_v1"),
        FunctionIdentity(
            SIGNER_COORDINATOR,
            None,
            "append_prepared_signed_frame_with_physical_carrier",
        ),
        FunctionIdentity(
            SIGNER_COORDINATOR,
            None,
            "reproject_exact_durable_signer_carrier_suffix_v1",
        ),
        FunctionIdentity(
            SIGNER_GOVERNANCE, None, "append_prepared_external_ingress"
        ),
        FunctionIdentity(
            SIGNER_GOVERNANCE,
            None,
            "apply_verified_revocation_effect_in_transaction_v1",
        ),
        FunctionIdentity(
            SIGNER_GOVERNANCE,
            None,
            "apply_verified_quarantine_closure_effect_in_transaction_v1",
        ),
        FunctionIdentity(
            SIGNER_PREFIX + "records.rs",
            None,
            "append_prepared_foundational_enrollment_adoption_v1",
        ),
        FunctionIdentity(
            SIGNER_PREFIX + "records.rs",
            None,
            "append_prepared_signer_enrollment_acceptance_v1",
        ),
        FunctionIdentity(
            SIGNER_TERMINAL,
            None,
            "insert_successor_projection_plan_v1",
        ),
        FunctionIdentity(
            SIGNER_TERMINAL,
            None,
            "append_successor_terminal_v1",
        ),
    }
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
        branded = "StoreWriterSession" in signature
        actor_owned = (
            path == LIVE_C2 and function.owner == "StoreC2SnapshotActorV1"
        )
        actor_factory = (
            path == LIVE_C2
            and function.owner == "Store"
            and function.name == "with_c2_authority_snapshot"
        )
        exact_helper = _function_identity(function) in exact_helpers
        # Custody writes are purpose-locked by the private custodian rather
        # than Store mutation brands; only its exact private helpers qualify.
        custody_owned = path == SIGNER_CUSTODY and function.visibility == "private"
        if not (
            branded or actor_owned or actor_factory or exact_helper or custody_owned
        ):
            violations.append(function.location)
    require(
        not violations,
        "C2 mutating primitive lacks an exact live-actor/session owner: "
        + ", ".join(violations),
    )

    helper_callers = {
        FunctionIdentity(INSTALL, None, "create_fixed_file"): {
            FunctionIdentity(INSTALL, None, "allocate_live_c2_fixed_files_v1")
        },
        FunctionIdentity(INSTALL, None, "allocate_live_c2_fixed_files_v1"): {
            FunctionIdentity(
                LIVE_C2, "StoreC2SnapshotActorV1", "install_c2_live_with_observer_v1"
            )
        },
        FunctionIdentity(LOCK, None, "finalize_provisional_generation_lock_v1"): {
            FunctionIdentity(
                LIVE_C2, "StoreC2SnapshotActorV1", "install_c2_live_with_observer_v1"
            )
        },
        FunctionIdentity(
            SIGNER_COORDINATOR,
            None,
            "append_prepared_signed_frame_with_physical_carrier",
        ): {
            FunctionIdentity(
                SIGNER_COORDINATOR, None, "append_finalized_signed_frame_projection"
            ),
            FunctionIdentity(
                SIGNER_COORDINATOR, None, "append_prepared_signed_frame"
            ),
            FunctionIdentity(
                SIGNER_COORDINATOR,
                None,
                "reproject_exact_durable_signer_carrier_suffix_v1",
            ),
        },
        FunctionIdentity(
            SIGNER_COORDINATOR,
            None,
            "reproject_exact_durable_signer_carrier_suffix_v1",
        ): {
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "reopen_complete_physical_generation_v1",
            )
        },
        FunctionIdentity(
            SIGNER_GOVERNANCE, None, "append_prepared_external_ingress"
        ): {
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "append_verified_governed_carrier_effect",
            ),
            FunctionIdentity(
                SIGNER_GOVERNANCE,
                "StorePreparedRevocationEffectV1",
                "apply",
            ),
            FunctionIdentity(
                SIGNER_GOVERNANCE,
                "StorePreparedQuarantineClosureEffectV1",
                "apply",
            ),
        },
        FunctionIdentity(
            SIGNER_GOVERNANCE,
            None,
            "apply_verified_revocation_effect_in_transaction_v1",
        ): {
            FunctionIdentity(
                SIGNER_GOVERNANCE,
                "StorePreparedRevocationEffectV1",
                "apply",
            )
        },
        FunctionIdentity(
            SIGNER_GOVERNANCE,
            None,
            "apply_verified_quarantine_closure_effect_in_transaction_v1",
        ): {
            FunctionIdentity(
                SIGNER_GOVERNANCE,
                "StorePreparedQuarantineClosureEffectV1",
                "apply",
            )
        },
        FunctionIdentity(
            SIGNER_PREFIX + "records.rs",
            None,
            "append_prepared_foundational_enrollment_adoption_v1",
        ): {
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "adopt_foundational_enrollment_v1",
            ),
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "adopt_consumed_foundational_enrollment_v1",
            ),
        },
        FunctionIdentity(
            SIGNER_PREFIX + "records.rs",
            None,
            "append_prepared_signer_enrollment_acceptance_v1",
        ): {
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "accept_signer_enrollment_v1",
            ),
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "accept_consumed_signer_enrollment_v1",
            ),
        },
        FunctionIdentity(
            SIGNER_TERMINAL,
            None,
            "insert_successor_projection_plan_v1",
        ): {
            FunctionIdentity(
                SIGNER_TERMINAL,
                None,
                "append_successor_terminal_v1",
            )
        },
        FunctionIdentity(
            SIGNER_TERMINAL,
            None,
            "append_successor_terminal_v1",
        ): {
            FunctionIdentity(
                SIGNER_TERMINAL,
                None,
                "append_healthy_successor_terminal_v1",
            ),
            FunctionIdentity(
                SIGNER_TERMINAL,
                None,
                "append_restore_successor_terminal_v1",
            ),
            FunctionIdentity(
                SIGNER_TERMINAL,
                None,
                "append_recovery_successor_terminal_v1",
            ),
        },
        FunctionIdentity(
            SIGNER_TERMINAL,
            None,
            "append_healthy_successor_terminal_v1",
        ): {
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "persist_healthy_successor_terminal_v1",
            )
        },
        FunctionIdentity(
            SIGNER_TERMINAL,
            None,
            "append_restore_successor_terminal_v1",
        ): {
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "persist_restore_successor_terminal_v1",
            )
        },
        FunctionIdentity(
            SIGNER_TERMINAL,
            None,
            "append_recovery_successor_terminal_v1",
        ): {
            FunctionIdentity(
                LIVE_C2,
                "StoreC2SnapshotActorV1",
                "persist_recovery_successor_terminal_v1",
            )
        },
    }
    for helper, expected in helper_callers.items():
        actual = {
            _function_identity(function)
            for function in inventory.callers_of(helper.name)
            if function.source.path.as_posix().startswith(
                "crates/nq-store/src/store_generation"
            )
        }
        require(
            actual == expected,
            f"live C2 mutation helper caller set changed for {helper.display()}: "
            f"expected {[value.display() for value in sorted(expected, key=lambda value: value.display())]}, "
            f"found {[value.display() for value in sorted(actual, key=lambda value: value.display())]}",
        )
    migration = _verify_schema_projection_gate(inventory)
    return (
        receipt,
        "c2-mutator-owner=live-store-actor",
        f"live-c2-lower-helper-caller-sets={len(helper_callers)}",
        *migration,
    )


def _verify_schema_projection_gate(inventory: SourceInventory) -> tuple[str, ...]:
    """Prove obsolete path-only/provisional schema authority is not product code."""

    require(
        not inventory.functions_named("migrate_c1_gen4_to_c2_schema_projection"),
        "HostRoleRuntime still exposes the path-only schema-v9 projection bypass",
    )
    require(
        not inventory.public_reexports({"C2PendingSqlProjectionPermitV1"}),
        "pending SQL projection permit is publicly re-exported",
    )
    product_permit_users = [
        function
        for function in inventory.functions
        if "C2PendingSqlProjectionPermitV1" in compact_tokens(function.item_tokens)
    ]
    require(
        not product_permit_users,
        "obsolete unconstructible schema-v9 permit remains in product: "
        + ", ".join(function.location for function in product_permit_users),
    )
    require(
        not inventory.functions_named("apply_c2_schema_v8_to_v9"),
        "obsolete detached schema-v9 projection mutator remains product-compiled",
    )
    live_driver = inventory.require_function(
        LIVE_C2, "install_c2_live_v1", "StoreC2SnapshotActorV1"
    )
    require(
        len(live_driver.calls("install_c2_live_with_observer_v1")) == 1,
        "live C2 installation driver no longer owns schema/projection sequencing",
    )
    return (
        "schema-v9-path-only-route=absent",
        "obsolete-schema-v9-permit=compile-confined",
        "schema-v9-sequencing=live-install-driver-owned",
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
    route_specs = (
        (
            "restore",
            "restore_c2_live_historical_foundation_v1",
            "complete_store_restore_lifecycle_v1",
            "begin_restore_successor_v1",
            "verify_restore_authorization_ingress_consumption",
        ),
        (
            "recovery",
            "recover_c2_live_new_foundation_v1",
            "complete_store_recovery_lifecycle_v1",
            "begin_recovery_entry_v1",
            "verify_recovery_grant_ingress_consumption",
        ),
    )
    for route, root_name, driver_name, entry_name, verifier_name in route_specs:
        root = inventory.require_function(LIVE_C2, root_name, "Store")
        driver = inventory.require_function(
            LIVE_C2, driver_name, "StoreC2SnapshotActorV1"
        )
        entry = inventory.require_function(
            LIVE_C2, entry_name, "StoreC2SnapshotActorV1"
        )
        require(
            root.visibility == "pub(crate)"
            and driver.visibility == "private"
            and entry.visibility in {"private", "pub(crate)"}
            and len(root.calls(driver_name)) == 1
            and len(driver.calls(entry_name)) == 1
            and len(entry.calls(verifier_name)) == 1,
            f"live {route} route does not verify consumed external authority before entry",
        )
        for function in (root, driver, entry):
            forbidden = WRAPPER_FORBIDDEN_IO.intersection(
                _function_call_names(function)
            )
            require(
                not forbidden,
                f"{route} wrapper writes before nominal verification: {sorted(forbidden)}",
            )
            require(
                not any(
                    name in compact_tokens(function.item_tokens)
                    for name in ("latest", "maximum", "sort_by", "max_by")
                ),
                f"{route} wrapper infers predecessor by non-exact order",
            )
    return (
        "discontinuity-verifiers=2-pre-effect",
        "predecessor-inference=absent",
    )


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
        # A sibling module can apply `#[cfg(test)]` at the `mod` declaration,
        # which is not propagated into this independently parsed source file.
        # Keep the same conventional test-module confinement rule as the I/O
        # crash-cut census; product files remain subject to per-function cfg.
        if source.path.name.endswith("_tests.rs"):
            continue
        for function in source.functions:
            if "for_test" in function.name and not function.cfg_test:
                violations.append(function.location)
    require(not violations, "C2 test helper is in the product graph: " + ", ".join(violations))
    return (f"compile-confined-modules={len(inventory.compile_confined_paths)}", "test-helper-leaks=0")


def _verify_no_alternate_protected_roots(inventory: SourceInventory) -> tuple[str, ...]:
    facade_evidence = _verify_public_c2_lifecycle_facade(inventory)
    protected_sources = {
        INSTALL,
        POLICY,
        LIVE_C2,
        C2_LIFECYCLE,
        SIGNER_CUSTODY,
        SIGNER_COORDINATOR,
        SIGNER_MESSAGES,
        SIGNER_PREFIX + "records.rs",
        SIGNER_RESTART,
        SIGNER_GOVERNANCE,
    }
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
    superseded_authority_shapes = {
        "C2BootstrapBrandV1",
        "C2BootstrapSessionV1",
        "C2InstallationContinuationBrandV1",
        "C2PolicyTransitionBrandV1",
        "C2PolicyTransitionContinuationBrandV1",
        "C2OrdinaryRestartPipelineV1",
        "ReconstructedTerminalSignerCapabilityV1",
    }
    obsolete_product: list[str] = []
    for function in inventory.functions:
        overlap = sorted(
            name
            for name in superseded_authority_shapes
            if name in compact_tokens(function.item_tokens)
        )
        if overlap:
            obsolete_product.append(f"{function.location}:{','.join(overlap)}")
    require(
        not obsolete_product,
        "model-era C2 authority shape remains product-compiled: "
        + ", ".join(obsolete_product),
    )
    return (
        "alternate-protected-roots=absent",
        "model-era-authority-shapes=compile-confined",
        *facade_evidence,
    )


def _verify_public_c2_lifecycle_facade(
    inventory: SourceInventory,
) -> tuple[str, ...]:
    """Pin the sole public facade without widening any internal constructor root."""

    module = inventory.source(STORE_GENERATION_MOD)
    qualification = inventory.source(CANDIDATE_QUALIFICATION)
    facade = inventory.source(C2_LIFECYCLE)
    require(
        _source_token_count(
            module, ("pub", "mod", "c2_lifecycle", ";")
        )
        == 1,
        "the nominal C2 lifecycle facade is not the sole public lifecycle module",
    )
    protected_in_facade = {
        protected
        for protected in PROTECTED_TYPES
        if facade.identifier_occurrences(protected)
    }
    require(
        protected_in_facade == {"C2LiveWriterSessionV1"},
        "public facade references authority-bearing implementation types beyond its borrowed writer shell: "
        + ", ".join(sorted(protected_in_facade)),
    )
    require(
        not facade.identifier_occurrences("C2InstallAuthorityTupleV1"),
        "public facade exposes a caller-authored bootstrap authority tuple",
    )
    bootstrap_intent = inventory.require_function(
        C2_LIFECYCLE, "new", "C2BootstrapIntentV1"
    )
    require(
        len(bootstrap_intent.calls("from_operator_install_selection")) == 1
        and not bootstrap_intent.calls("C2InstallAuthorityTupleV1"),
        "bootstrap intent does not defer authority-tuple derivation to Store resolution",
    )

    entry = inventory.require_function(C2_LIFECYCLE, "c2_lifecycle_v1", "Store")
    entry_signature = compact_tokens(
        entry.source.tokens[entry.start_token : entry.body_open_token]
    )
    require(
        entry.visibility == "pub"
        and "&'storemutself" in entry_signature
        and "&'storeStoreC2CandidateVerifierResultV1" in entry_signature
        and "&'storeC2SignerImplementationManifestV1" in entry_signature
        and "->StoreC2LifecycleV1<'store>" in entry_signature,
        "Store does not expose exactly one borrowed candidate+manifest lifecycle facade",
    )
    facade_entries = [
        function
        for function in inventory.functions
        if function.source.path.as_posix() == C2_LIFECYCLE
        and function.owner == "Store"
        and function.visibility == "pub"
    ]
    require(
        [_function_identity(function) for function in facade_entries]
        == [_function_identity(entry)],
        "public facade defines an alternate Store entry point",
    )

    root_specs = (
        ("prepare_bootstrap", "prepare_c2_live_bootstrap_v1"),
        ("complete_bootstrap", "install_c2_live_from_bootstrap_grant_v1"),
        ("rotate_healthy_successor", "rotate_c2_live_healthy_successor_v1"),
        (
            "rotate_healthy_successor_with_activation_grant",
            "rotate_c2_live_healthy_successor_with_activation_grant_v1",
        ),
        (
            "restore_historical_foundation",
            "restore_c2_live_historical_foundation_v1",
        ),
        ("prepare_recovery", "prepare_c2_live_recovery_v1"),
        ("complete_recovery", "recover_c2_live_new_foundation_v1"),
        ("with_current_writer", "with_reopened_c2_generation_current_v1"),
    )
    root_names = {root for _, root in root_specs}
    for method_name, root_name in root_specs:
        method = inventory.require_function(
            C2_LIFECYCLE, method_name, "StoreC2LifecycleV1"
        )
        signature = compact_tokens(
            method.source.tokens[method.start_token : method.body_open_token]
        )
        require(
            method.visibility == "pub"
            and len(method.calls(root_name)) == 1
            and not (
                (root_names - {root_name})
                & set(_function_call_names(method))
            )
            and not WRAPPER_FORBIDDEN_IO.intersection(_function_call_names(method))
            and "C2StoreSigningRouteV1" not in signature
            and "ClosedMessageFamilyV1" not in signature
            and "SignerMessageV1" not in signature
            and "&[u8]" not in signature
            and "Vec<u8>" not in signature,
            f"public facade method {method_name} does not delegate once through its exact typed Store root",
        )
        callers = inventory.callers_of(root_name)
        require(
            len(callers) == 1 and _function_identity(callers[0]) == _function_identity(method),
            f"internal Store root {root_name} has a non-facade or duplicate production caller: "
            + ", ".join(function.location for function in callers),
        )

    writer_view = _item_header_code(facade, "struct", "C2CurrentWriterV1")
    require(
        all(
            trait not in writer_view
            for trait in ("Clone", "Copy", "Default", "Serialize", "Deserialize")
        )
        and _item_body_token_count(
            facade,
            "struct",
            "C2CurrentWriterV1",
            ("inner", ":", "&", "'", "borrow", "mut", "C2LiveWriterSessionV1"),
        )
        == 1,
        "public writer view is not one private borrowed nontransferable live-session shell",
    )
    writer_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "C2CurrentWriterV1{inner:session}")
    ]
    require(
        len(writer_constructors) == 1
        and writer_constructors[0].source.path.as_posix() == C2_LIFECYCLE
        and writer_constructors[0].owner == "StoreC2LifecycleV1"
        and writer_constructors[0].name == "with_current_writer",
        "public writer shell has an alternate constructor",
    )

    route_specs = (
        (
            "adopt_proposal_disposition",
            "adopt_proposal_disposition",
        ),
        (
            "apply_revocation_judgment",
            "apply_revocation_judgment",
        ),
        (
            "apply_quarantine_closure",
            "apply_quarantine_closure_judgment",
        ),
    )
    for facade_name, session_consumer in route_specs:
        top = inventory.require_function(
            C2_LIFECYCLE, facade_name, "StoreC2LifecycleV1"
        )
        writer = inventory.require_function(
            C2_LIFECYCLE, facade_name, "C2CurrentWriterV1"
        )
        require(
            top.visibility == "pub"
            and len(top.calls("with_current_writer")) == 1
            and len(top.calls(facade_name)) == 1
            and writer.visibility == "pub"
            and len(writer.calls(session_consumer)) == 1
            and not WRAPPER_FORBIDDEN_IO.intersection(_function_call_names(top))
            and not WRAPPER_FORBIDDEN_IO.intersection(_function_call_names(writer)),
            f"route-specific public facade {facade_name} bypasses its borrowed typed writer consumer",
        )
    quarantine = inventory.require_function(
        C2_LIFECYCLE, "apply_quarantine_closure", "C2CurrentWriterV1"
    )
    _require_calls_in_order(
        quarantine,
        ("adopt_restore_authorization", "apply_quarantine_closure_judgment"),
    )

    require(
        not facade.identifier_occurrences("C2StoreSigningRouteV1")
        and not facade.identifier_occurrences("SignerMessageV1")
        and not facade.identifier_occurrences("ClosedMessageFamilyV1")
        and not [
            function
            for function in inventory.functions
            if function.source.path.as_posix() == C2_LIFECYCLE
            and function.calls("sign")
        ],
        "public lifecycle facade exposes a generic family/route/signing operation",
    )

    candidate = _item_header_code(
        facade, "struct", "StoreC2CandidateVerifierResultV1"
    )
    verifier = _item_header_code(
        facade, "struct", "StoreC2CandidateRuntimeVerifierV1"
    )
    verified_certificate = _item_header_code(
        qualification, "struct", "StoreVerifiedCandidateCertificateV1"
    )
    verify_runtime = inventory.require_function(
        C2_LIFECYCLE,
        "verify_candidate_runtime",
        "StoreC2CandidateRuntimeVerifierV1",
    )
    with_lifecycle = inventory.require_function(
        C2_LIFECYCLE,
        "with_verified_c2_lifecycle",
        "StoreC2CandidateRuntimeVerifierV1",
    )
    seal = inventory.require_function(
        C2_LIFECYCLE,
        "seal_verified_candidate_runtime",
        "StoreC2CandidateRuntimeVerifierV1",
    )
    verify_certificate = inventory.require_function(
        CANDIDATE_QUALIFICATION,
        "verify_candidate_certificate_for_current_runtime_v1",
    )
    decode_certificate = inventory.require_function(
        CANDIDATE_QUALIFICATION, "decode_candidate_certificate_v1"
    )
    decode_trust_root = inventory.require_function(
        CANDIDATE_QUALIFICATION, "decode_qualification_trust_root_v1"
    )
    validate_trust_directory = inventory.require_function(
        CANDIDATE_QUALIFICATION, "validate_trust_directory"
    )
    open_trust_directory_component = inventory.require_function(
        CANDIDATE_QUALIFICATION, "open_fixed_trust_directory_component"
    )
    fixed_trust_source = inventory.require_function(
        CANDIDATE_QUALIFICATION, "fixed_trust_source_bytes"
    )
    load_fixed_trust = inventory.require_function(
        CANDIDATE_QUALIFICATION, "load_fixed_qualification_trust_root_v1"
    )
    authenticated_conversion = inventory.require_function(
        LIVE_C2,
        "from_authenticated_candidate_certificate",
        "VerifiedC2ExternalCandidateRuntimeRecordV1",
    )
    candidate_constructors = [
        function
        for function in inventory.functions
        if _code_contains(function, "StoreC2CandidateVerifierResultV1{evidence:")
    ]
    verified_certificate_constructors = [
        function
        for function in inventory.functions
        if _code_contains(
            function,
            "StoreVerifiedCandidateCertificateV1{qualified_candidate_identity:",
        )
    ]
    external_record_constructors = [
        function
        for function in inventory.functions
        if function.owner == "VerifiedC2ExternalCandidateRuntimeRecordV1"
        and "->Self" in compact_tokens(
            function.source.tokens[function.start_token : function.body_open_token]
        )
    ]
    seal_signature = compact_tokens(
        seal.source.tokens[seal.start_token : seal.body_open_token]
    )
    verify_runtime_signature = compact_tokens(
        verify_runtime.source.tokens[
            verify_runtime.start_token : verify_runtime.body_open_token
        ]
    )
    with_lifecycle_signature = compact_tokens(
        with_lifecycle.source.tokens[
            with_lifecycle.start_token : with_lifecycle.body_open_token
        ]
    )
    verify_certificate_signature = compact_tokens(
        verify_certificate.source.tokens[
            verify_certificate.start_token : verify_certificate.body_open_token
        ]
    )
    authenticated_conversion_signature = compact_tokens(
        authenticated_conversion.source.tokens[
            authenticated_conversion.start_token
            : authenticated_conversion.body_open_token
        ]
    )
    public_verifier_methods = {
        function.name
        for function in inventory.functions
        if function.source.path.as_posix() == C2_LIFECYCLE
        and function.owner == "StoreC2CandidateRuntimeVerifierV1"
        and function.visibility == "pub"
    }
    require(
        all(
            trait not in candidate
            and trait not in verifier
            and trait not in verified_certificate
            for trait in ("Clone", "Copy", "Default", "Serialize", "Deserialize")
        )
        and seal.visibility == "pub(crate)"
        and "VerifiedC2ExternalCandidateRuntimeRecordV1" in seal_signature
        and len(candidate_constructors) == 1
        and _function_identity(candidate_constructors[0]) == _function_identity(seal)
        and _item_visibility(
            qualification, "struct", "StoreVerifiedCandidateCertificateV1"
        )
        == "pub(crate)",
        "candidate/runtime evidence types or opaque seal are externally constructible",
    )
    require(
        _source_token_count(module, ("mod", "candidate_qualification", ";")) == 1
        and _source_token_count(
            module, ("pub", "mod", "candidate_qualification", ";")
        )
        == 0,
        "candidate qualification verifier is not one private production module",
    )
    require(
        public_verifier_methods
        == {"verify_candidate_runtime", "with_verified_c2_lifecycle"}
        and verify_runtime_signature
        == "pubfnverify_candidate_runtime(certificate_bytes:&[u8],manifest:&C2SignerImplementationManifestV1,)->Result<StoreC2CandidateVerifierResultV1,C2CandidateVerificationRefusalV1>"
        and with_lifecycle_signature
        == "pubfnwith_verified_c2_lifecycle<R>(store:&mutStore,certificate_bytes:&[u8],manifest:&C2SignerImplementationManifestV1,operation:implFnOnce(&mutStoreC2LifecycleV1<'_>)->R,)->Result<R,C2CandidateVerificationRefusalV1>",
        "candidate verifier public surface accepts a caller-selected trust key or raw coordinate",
    )
    _require_calls_in_order(
        verify_runtime,
        (
            "verify_candidate_certificate_for_current_runtime_v1",
            "from_authenticated_candidate_certificate",
            "seal_verified_candidate_runtime",
        ),
    )
    _require_calls_in_order(
        with_lifecycle,
        ("verify_candidate_runtime", "c2_lifecycle_v1", "operation"),
    )
    require(
        {_function_identity(function) for function in inventory.callers_of(
            "verify_candidate_certificate_for_current_runtime_v1"
        )}
        == {_function_identity(verify_runtime)}
        and {_function_identity(function) for function in inventory.callers_of(
            "from_authenticated_candidate_certificate"
        )}
        == {_function_identity(verify_runtime)}
        and {_function_identity(function) for function in inventory.callers_of(
            "seal_verified_candidate_runtime"
        )}
        == {_function_identity(verify_runtime)}
        and {_function_identity(function) for function in inventory.callers_of(
            "verify_candidate_runtime"
        )}
        == {_function_identity(with_lifecycle)},
        "candidate verifier chain has an alternate production caller or bypass",
    )
    require(
        verify_certificate.visibility == "pub(crate)"
        and verify_certificate_signature
        == "pub(crate)fnverify_candidate_certificate_for_current_runtime_v1(certificate_bytes:&[u8],manifest:&StoreIntegritySignerImplementationManifestV1,)->Result<StoreVerifiedCandidateCertificateV1,C2CandidateVerificationRefusalV1>"
        and len(verified_certificate_constructors) == 1
        and _function_identity(verified_certificate_constructors[0])
        == _function_identity(verify_certificate),
        "authenticated candidate certificate has an alternate or raw-coordinate constructor",
    )
    _require_calls_in_order(
        verify_certificate,
        (
            "load_fixed_qualification_trust_root_v1",
            "decode_candidate_certificate_v1",
            "verify_strict",
            "manifest_identity",
            "measure_current_runtime_artifact",
        ),
    )
    require(
        len(verify_certificate.calls("verify_strict")) == 1
        and len(verify_certificate.calls("measure_current_runtime_artifact")) == 1
        and all(
            len(verify_certificate.calls(method)) == 1
            for method in (
                "manifest_identity",
                "manifest_source_files_identity",
                "toolchain_identity",
                "target_profile_identity",
                "qualification_assumption_identities",
            )
        )
        and {_function_identity(function) for function in inventory.callers_of(
            "load_fixed_qualification_trust_root_v1"
        )}
        == {_function_identity(verify_certificate)},
        "candidate verifier omits the fixed-root signature, manifest, or runtime-measurement chain",
    )
    decode_certificate_code = compact_tokens(decode_certificate.item_tokens)
    require(
        decode_certificate_code.count("exact_git_object_id(") == 2
        and len(decode_certificate.calls("git_object_identity")) == 2
        and len(decode_certificate.calls("qualified_candidate_identity")) == 1
        and _code_contains(
            decode_certificate,
            "wire.unsigned.source_commit_identity||git_object_identity",
        )
        and _code_contains(
            decode_certificate,
            "wire.unsigned.source_tree_identity||qualified_candidate_identity",
        )
        and _code_contains(
            decode_certificate,
            "wire.unsigned.qualified_candidate_identity{returnErr(C2CandidateVerificationRefusalV1::CandidateBasisIdentityMismatch)",
        )
        and all(
            identifier in decode_certificate_code
            for identifier in (
                "C2_SOURCE_COMMIT_IDENTITY_DOMAIN_V1",
                "C2_SOURCE_TREE_IDENTITY_DOMAIN_V1",
                "C2_QUALIFIED_CANDIDATE_IDENTITY_DOMAIN_V1",
            )
        ),
        "candidate certificate does not mechanically derive its exact commit/tree/candidate basis",
    )
    require(
        all(
            len(decode_trust_root.calls(method)) == 1
            for method in (
                "qualification_scope_identity_v1",
                "qualification_verifier_contract_identity_v1",
                "qualification_policy_identity_v1",
                "qualification_key_generation_identity_v1",
                "trust_root_identity",
            )
        )
        and all(
            coordinate in compact_tokens(verify_certificate.item_tokens)
            for coordinate in (
                "qualification_trust_root_identity",
                "qualification_scope_identity",
                "qualification_verifier_contract_identity",
                "qualification_policy_identity",
                "qualification_key_generation_identity",
            )
        ),
        "qualification trust root or certificate omits its closed scope/policy/key-generation binding",
    )
    fixed_trust_literals = [
        token.value
        for token in fixed_trust_source.item_tokens
        if token.kind == "literal"
    ]
    require(
        compact_tokens(
            fixed_trust_source.source.tokens[
                fixed_trust_source.start_token : fixed_trust_source.body_open_token
            ]
        )
        == "fnfixed_trust_source_bytes()->Result<Vec<u8>,C2CandidateVerificationRefusalV1>"
        and len(fixed_trust_source.calls("open")) == 1
        and len(fixed_trust_source.calls("openat")) == 1
        and len(
            fixed_trust_source.calls("open_fixed_trust_directory_component")
        )
        == 2
        and fixed_trust_literals
        == [
            '"/"',
            '"etc"',
            '"nq"',
            '"c2-qualification-trust-root.v1.json"',
        ]
        and _code_contains(
            fixed_trust_source,
            "open(<literal>,OFlags::RDONLY|OFlags::DIRECTORY|OFlags::NOFOLLOW|OFlags::CLOEXEC",
        )
        and _code_contains(
            fixed_trust_source,
            "openat(&nq,<literal>,OFlags::RDONLY|OFlags::NOFOLLOW|OFlags::CLOEXEC",
        )
        and len(fixed_trust_source.calls("validate_trust_directory")) == 1
        and _code_contains(fixed_trust_source, "metadata.uid()!=0")
        and _code_contains(fixed_trust_source, "metadata.mode()&0o022!=0")
        and _code_contains(fixed_trust_source, "metadata.nlink()!=1")
        and {_function_identity(function) for function in inventory.callers_of(
            "fixed_trust_source_bytes"
        )}
        == {_function_identity(load_fixed_trust)},
        "candidate verifier trust root is caller-selected or lacks component-wise fixed-path custody",
    )
    require(
        open_trust_directory_component.visibility == "private"
        and len(open_trust_directory_component.calls("openat")) == 1
        and len(open_trust_directory_component.calls("validate_trust_directory"))
        == 1
        and _code_contains(
            open_trust_directory_component,
            "OFlags::RDONLY|OFlags::DIRECTORY|OFlags::NOFOLLOW|OFlags::CLOEXEC",
        )
        and validate_trust_directory.visibility == "private"
        and _code_contains(validate_trust_directory, "metadata.file_type().is_dir()")
        and _code_contains(validate_trust_directory, "metadata.uid()!=0")
        and _code_contains(validate_trust_directory, "metadata.mode()&0o022!=0")
        and {_function_identity(function) for function in inventory.callers_of(
            "open_fixed_trust_directory_component"
        )}
        == {_function_identity(fixed_trust_source)}
        and {_function_identity(function) for function in inventory.callers_of(
            "validate_trust_directory"
        )}
        == {
            _function_identity(open_trust_directory_component),
            _function_identity(fixed_trust_source),
        },
        "qualification trust path does not verify every root-owned directory component",
    )
    require(
        len(external_record_constructors) == 1
        and _function_identity(external_record_constructors[0])
        == _function_identity(authenticated_conversion)
        and "certificate:StoreVerifiedCandidateCertificateV1"
        in authenticated_conversion_signature
        and authenticated_conversion.visibility != "pub",
        "candidate raw-to-record bridge does not require the authenticated typed certificate",
    )
    qualification_mutation_calls = {
        "append",
        "commit",
        "create_dir",
        "create_dir_all",
        "execute",
        "execute_batch",
        "fsync",
        "hard_link",
        "persist",
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
    qualification_product_functions = [
        function
        for function in inventory.functions
        if function.source.path.as_posix() == CANDIDATE_QUALIFICATION
        and not function.cfg_test
    ]
    require(
        qualification_product_functions
        and all(
            not qualification_mutation_calls.intersection(
                _function_call_names(function)
            )
            and "&mutStore" not in compact_tokens(function.item_tokens)
            for function in qualification_product_functions
        ),
        "candidate qualification verifier gained a Store or durable mutation path",
    )
    return (
        "public-c2-facade=one-borrowed-store-entry",
        "public-c2-root-delegations=8/8",
        "public-governed-writer-routes=3-nominal",
        "public-writer-shell=borrowed-nonescaping",
        "candidate-runtime-verifier=fixed-root+signature+candidate-basis+manifest+self-measurement",
        "qualification-root-custody=root+etc+nq+file-nofollow",
        "qualification-trust-io=read-only-pre-admission",
        "candidate-runtime-bridge=authenticated-certificate-only",
        "candidate-lifecycle-entry=one-scoped-production-chain",
        "bootstrap-authority-tuple=store-derived-not-public-input",
    )


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
        "live-c2-special-root-count=7",
        "live-c2-nonreopen-lifecycle-path-count=4",
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
    return _evidence(
        "N-63",
        f"bounded-live-c2-roots={len(paths.special_roots)}",
        "preparation-returns-inert-evidence=true",
        "boolean-substitute=absent",
    )


def verify_n_64_exact_six_path_census(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    paths = _special_path_inventory(inventory)
    _verify_no_alternate_protected_roots(inventory)
    return _evidence(
        "N-64",
        f"special-entry-roots={len(paths.special_roots)}",
        "special-lifecycle-paths=4",
        "reopen=1",
        "canonical-lifecycle-total=5",
    )


def verify_n_84_every_mutator_has_exact_session_owner(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    facts = _verify_new_mutator_branding(inventory)
    _special_path_inventory(inventory)
    return _evidence("N-84", *facts, "live-c2-entry-roots=8", "live-c2-lifecycles=5")


def verify_hr28_28_complete_cap_h23_inventory(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    paths = _special_path_inventory(inventory)
    require(
        len(paths.special_roots) == 7,
        "HR28-28 closed live C2 root protocol is incomplete",
    )
    return _evidence(
        "HR28-28",
        "incomplete-inventory-refusal=armed",
        "canonical-live-entry-roots=8",
        "canonical-live-lifecycles=5",
    )


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
    return _evidence(
        "AM-01",
        f"entry-roots={len(paths.special_roots) + 1}",
        "lifecycle-paths=5",
        *mutators,
    )


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
    constructor_callers = inventory.callers_of("mint_bootstrap_signer_context")
    install_root = next(
        identity
        for identity in paths.special_roots
        if identity.name == "install_c2_live_from_bootstrap_grant_v1"
    )
    require(
        {_function_identity(function) for function in constructor_callers}
        == {install_root},
        "bootstrap live context has a caller outside the Store resume/install root",
    )
    return _evidence(
        "CG-04",
        "bootstrap-context-caller=install_c2_live_from_bootstrap_grant_v1",
        "preparation-context-mints=0",
    )


def verify_cg_05_install_continuation_brand_has_intent_frontier_verifier(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    _special_path_inventory(inventory)
    function = inventory.require_function(
        LIVE_C2, "install_c2_live_v1", "StoreC2SnapshotActorV1"
    )
    implementation = inventory.require_function(
        LIVE_C2, "install_c2_live_with_observer_v1", "StoreC2SnapshotActorV1"
    )
    require(
        len(function.calls("install_c2_live_with_observer_v1")) == 1
        and len(implementation.calls("append_installation_bootstrap_batch")) == 1,
        "live installation does not consume the ordered MSG-09/MSG-03 batch",
    )
    return _evidence(
        "CG-05",
        f"constructor={function.location}",
        f"implementation={implementation.location}",
        "intent-frontier=typed-batch",
    )


def verify_cg_06_policy_transition_brand_has_initial_transition_caller(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    _special_path_inventory(inventory)
    post_msg07_refresh = _verify_post_msg07_predecessor_refresh_before_msg06(inventory)
    constructor = inventory.require_function(
        SIGNER_COORDINATOR,
        "append_policy_transition_intent",
        "C2SignerTransitionCoordinator",
    )
    require(
        len(constructor.calls("sign_and_append_current_predecessor")) == 1,
        "policy transition intent bypasses the current-predecessor live projection",
    )
    sequence = inventory.require_function(
        SIGNER_COORDINATOR,
        "append_healthy_rotation_intent",
        "C2SignerTransitionCoordinator",
    )
    require(
        len(sequence.calls("append_policy_transition_intent")) == 1,
        "healthy rotation does not consume its exact MSG-11 transition intent",
    )
    callers = inventory.callers_of("append_healthy_rotation_intent")
    require(
        len(callers) == 1
        and callers[0].source.path.as_posix() == LIVE_C2
        and callers[0].owner == "StoreC2SnapshotActorV1",
        "healthy-rotation intent has no exact Store-actor production caller: "
        + (", ".join(function.location for function in callers) or "none"),
    )
    return _evidence(
        "CG-06",
        f"constructor={constructor.location}",
        f"sequence={sequence.location}",
        f"actor-caller={callers[0].location}",
        "authority=current-predecessor",
        *post_msg07_refresh,
    )


def verify_cg_07_transition_continuation_brand_has_unresolved_intent_frontier(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    _special_path_inventory(inventory)
    reopen = inventory.require_function(
        LIVE_C2, "with_reopened_c2_generation_current_v1", "Store"
    )
    actor_reopen = inventory.require_function(
        LIVE_C2, "with_reopened_generation_current_v1", "StoreC2SnapshotActorV1"
    )
    code = compact_tokens((*reopen.item_tokens, *actor_reopen.item_tokens))
    require(
        "GenerationCurrentV1" in code
        and "PendingPossessionV1" not in code
        and "PendingSelectedV1" not in code,
        "restart reopen can reconstruct a pending successor phase",
    )
    require(
        len(reopen.calls("with_reopened_generation_current_v1")) == 1
        and len(
            actor_reopen.calls("mint_reopened_terminal_generation_current_v1")
        )
        == 1,
        "restart reopen does not delegate exclusively to the complete GenerationCurrent resolver",
    )
    continuation_callers: dict[str, Sequence[Function]] = {
        route: inventory.callers_of(route)
        for route in (
            "append_successor_possession",
            "append_pending_healthy_rotation_receipt",
        )
    }
    for route, callers in continuation_callers.items():
        require(
            len(callers) == 1
            and callers[0].source.path.as_posix() == LIVE_C2
            and callers[0].owner == "StoreC2SnapshotActorV1",
            f"{route} has no exact Store-actor production continuation caller: "
            + (", ".join(function.location for function in callers) or "none"),
        )
    return _evidence(
        "CG-07",
        f"reopen={reopen.location}",
        f"resolver={actor_reopen.location}",
        "pending-continuation-callers=2-store-actor",
        "pending-reconstruction=absent",
    )


def verify_cg_08_install_continuation_explicit_entry_unreachable_ordinary_open(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    inventory = inventory or SourceInventory.load()
    paths = _special_path_inventory(inventory)
    reopen = inventory.require_function(
        paths.ordinary_root.path,
        paths.ordinary_root.name,
        paths.ordinary_root.owner,
    )
    require(
        not reopen.calls("install_c2_live_v1"),
        "restart reopen can enter fresh installation",
    )
    return _evidence("CG-08", f"reopen-root={reopen.location}", "fresh-install-callers=0")


def verify_cg_10_ordinary_session_construction_occurs_after_complete_closed(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = _special_path_inventory(inventory or SourceInventory.load())
    return _evidence("CG-10", f"reopen-root={paths.ordinary_root.display()}", "complete-generation-current-before-context=true")


def verify_cg_11_exactly_five_nonwriting_special_roots_each_correct(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = _special_path_inventory(inventory or SourceInventory.load())
    return _evidence(
        "CG-11",
        f"live-c2-special-root-count={len(paths.special_roots)}",
        "live-c2-nonreopen-lifecycle-path-count=4",
        "store-owned=true",
    )


def verify_cg_12_exactly_nonwriting_ordinary_open_session_root_p(
    inventory: SourceInventory | None = None,
) -> RowEvidence:
    paths = _special_path_inventory(inventory or SourceInventory.load())
    return _evidence("CG-12", f"reopen-root={paths.ordinary_root.display()}", "fresh-verification-before-context=true")


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
    require(
        len(paths.special_roots) == 7,
        "one closed live C2 root was substituted",
    )
    return _evidence(
        "XH-53",
        "missing-path-refusal=armed",
        "canonical-live-entry-roots=8",
        "canonical-live-lifecycles=5",
    )


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
    return _evidence("SEAM-10", f"direct-open-classifications={len(direct.direct_open_sites)}", "c2-mutation-path=live-reopen")


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
    parser.add_argument(
        "--emit-io-manifest",
        action="store_true",
        help="emit the current source-derived development crash-cut manifest to stdout",
    )
    arguments = parser.parse_args(argv)
    if sum((arguments.json, arguments.list_rows, arguments.emit_io_manifest)) > 1:
        parser.error("--json, --list-rows, and --emit-io-manifest are mutually exclusive")
    if arguments.list_rows:
        for verifier in ASSIGNED_VERIFIERS:
            print(verifier.__name__)
        return 0
    inventory = SourceInventory.load()
    if arguments.emit_io_manifest:
        print(json.dumps(source_derived_io_manifest(inventory), indent=2, sort_keys=True))
        return 0
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
