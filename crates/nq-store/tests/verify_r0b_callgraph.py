#!/usr/bin/env python3
"""Static R0b proof for Store-owned dependency/source resolution."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
STORE = ROOT / "crates" / "nq-store"
GOVERNED = (STORE / "src" / "governed_custody.rs").read_text(encoding="utf-8")
STORE_LIB = (STORE / "src" / "lib.rs").read_text(encoding="utf-8")
STORE_CARGO = (STORE / "Cargo.toml").read_text(encoding="utf-8")
CORE = (ROOT / "crates" / "nq-core" / "src" / "engine.rs").read_text(encoding="utf-8")
CORE_CARGO = (ROOT / "crates" / "nq-core" / "Cargo.toml").read_text(encoding="utf-8")


def fail(message: str) -> None:
    raise AssertionError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def section(text: str, header: str) -> str:
    start = text.index(header) + len(header)
    following = text.find("\n[", start)
    return text[start:] if following < 0 else text[start:following]


def function(text: str, name: str) -> str:
    match = re.search(rf"\bfn\s+{re.escape(name)}(?:<'[^>]+>)?\s*\(", text)
    if match is None:
        fail(f"function {name} is absent")
    opening = text.find("{", match.end())
    require(opening >= 0, f"function {name} has no body")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[match.start() : index + 1]
    fail(f"function {name} has an unterminated body")
    raise AssertionError("unreachable")


dependencies = section(STORE_CARGO, "\n[dependencies]\n")
require(
    re.search(
        r"^nq-host-role-dependency-custody\s*=\s*\{\s*path\s*=\s*"
        r"\"\.\./nq-host-role-dependency-custody\"\s*\}\s*$",
        dependencies,
        flags=re.MULTILINE,
    )
    is not None,
    "nq-store lacks one direct default-feature shared custody dependency",
)
require(
    "nq-host-role-runtime" not in dependencies,
    "nq-store product dependencies reach upward into host-runtime",
)
require(
    "test-support" not in dependencies,
    "nq-store product dependency enables shared fixture support",
)

require(
    GOVERNED.count("fn resolve_authenticated_physical_prelaunch_sources") == 1,
    "Store must define exactly one private authenticated source helper",
)
require(
    GOVERNED.count("AuthenticatedRuntimeDependencyClosure::reopen_bound") == 1,
    "Store must call the closed reopen_bound verifier exactly once",
)
require(
    GOVERNED.count("ExactDependencyCustodyBinding::new") == 1,
    "Store must construct exactly one exact dependency-custody binding",
)
require(
    GOVERNED.count(".resolve_sources(") == 1,
    "Store must call closed source resolution exactly once",
)
for forbidden in (
    "AuthenticatedRuntimeDependencyClosure::decode_authenticated",
    "RuntimeDependencyGenerationCustody::reopen",
    "RuntimeDependencyGenerationCustody::decode_canonical_closure",
):
    require(forbidden not in GOVERNED, f"Store reaches forbidden low-level API {forbidden}")
require(
    re.search(r"\bEd25519TrustAnchor::(?:decode_[A-Za-z0-9_]*|fixture|new)\b", GOVERNED)
    is None,
    "Store decodes or constructs a caller-selected Ed25519 trust anchor",
)
require(
    GOVERNED.count("AuthenticatedPhysicalPrelaunchSources {") == 1,
    "Store has more than one authenticated physical-source summary constructor",
)

helper = function(GOVERNED, "resolve_authenticated_physical_prelaunch_sources")
for token in (
    "runtime_checkpoint_dependency_on_connection",
    "runtime_dependency_trust_root_on_connection",
    "ExactDependencyCustodyBinding::new",
    "AuthenticatedRuntimeDependencyClosure::reopen_bound",
    "derive_physical_prelaunch_requirements",
    ".resolve_sources(",
):
    require(token in helper, f"common helper omits {token}")
for token in (
    "external.len() != 4",
    "authority.len() != 2",
    "requirement_set_digest != expected_requirement_set_digest",
    "authenticated source resolution is not the complete six-purpose physical requirement set",
):
    require(token in helper, f"common helper omits its closed six-purpose gate: {token}")
require(
    helper.index("runtime_checkpoint_dependency_on_connection")
    < helper.index("runtime_dependency_trust_root_on_connection")
    < helper.index("ExactDependencyCustodyBinding::new")
    < helper.index("AuthenticatedRuntimeDependencyClosure::reopen_bound")
    < helper.index(".resolve_sources("),
    "common helper does not preserve Store selection → root → binding → reopen → resolution",
)

requirements = function(GOVERNED, "derive_physical_prelaunch_requirements")
require(
    requirements.count("ExternalSourcePurpose::") == 4,
    "Store does not derive exactly four closed external source roles",
)
require(
    requirements.count("AuthoritySourcePurpose::") == 2,
    "Store does not derive exactly two closed authority source roles",
)
for purpose in (
    "ExternalSourcePurpose::InvocationAuthentication",
    "ExternalSourcePurpose::GenerationMatch",
    "ExternalSourcePurpose::Capability",
    "ExternalSourcePurpose::CustodyReservationCommit",
    "AuthoritySourcePurpose::InvocationAuthentication",
    "AuthoritySourcePurpose::OperationAuthorization",
):
    require(
        requirements.count(purpose) == 1,
        f"Store physical requirement derivation does not select {purpose} exactly once",
    )

context_guard = function(GOVERNED, "require_same_context")
for token in (
    "exact_external != requirements.external",
    "exact_authority != requirements.authority",
    "requirement_set_digest != self.requirement_set_digest",
):
    require(token in context_guard, f"private context guard omits {token}")

test_only_helpers = (
    "r0b_verify_requirement_context_for_test",
    "r0b_verify_checkpoint_dependency_with_arena_bytes_for_test",
)
for name in test_only_helpers:
    require(
        re.search(
            rf"#\[cfg\(test\)\]\s+pub\(super\)\s+fn\s+{re.escape(name)}\s*\(",
            GOVERNED,
        )
        is not None,
        f"R0b branch-isolation helper {name} is not cfg(test)-only and module-private",
    )
    require(
        name not in STORE_LIB[: STORE_LIB.index("mod tests {")],
        f"R0b branch-isolation helper {name} leaked into Store product source",
    )

structural_test = function(
    STORE_LIB, "r0b_b12_through_b15_requirement_context_is_closed_and_role_exact"
)
for token in (
    '"B12"',
    '"B13"',
    '"B14"',
    '"B15"',
    "OmitExternal",
    "DuplicateExternal",
    "ExtraneousExternal",
    "SwapExternalPurposes",
    "counts.external, 4",
    "counts.authority, 2",
):
    require(token in structural_test, f"B12-B15 structural control omits {token}")

capacity_v2 = function(
    GOVERNED, "verify_governed_execution_custody_closure_v2_capacity"
)
require(
    capacity_v2.count(
        "verify_governed_execution_custody_closure_capacity_on_one_snapshot"
    )
    == 1,
    "public V2 capacity does not delegate exactly once to the common snapshot helper",
)
require(
    "unchecked_transaction" not in capacity_v2
    and "resolve_authenticated_physical_prelaunch_sources" not in capacity_v2,
    "public V2 capacity bypasses or duplicates the common snapshot helper",
)
capacity_v3 = function(
    GOVERNED, "verify_governed_execution_custody_closure_v3_capacity"
)
require(
    capacity_v3.count(
        "verify_governed_execution_custody_closure_capacity_on_one_snapshot"
    )
    == 1,
    "public V3 capacity does not delegate exactly once to the common snapshot helper",
)
require(
    "verify_governed_execution_custody_closure_v2_capacity(" not in capacity_v3
    and "projection_capsule_capacity_bytes" not in capacity_v3
    and "governed_execution_custody_closure_v3_capacity_bound" not in capacity_v3,
    "public V3 capacity performs post-snapshot arithmetic or calls public V2",
)
capacity_common = function(
    GOVERNED,
    "verify_governed_execution_custody_closure_capacity_on_one_snapshot",
)
for token in (
    "unchecked_transaction",
    "governed_reservation_capacity_components",
    "projection_capsule_capacity != reservation.projection_capsule_capacity_bytes",
    "resolve_authenticated_physical_prelaunch_sources",
    "governed_execution_custody_closure_v2_capacity_bound",
    "governed_execution_custody_closure_v3_capacity_bound",
    "drop(authenticated_sources)",
    "drop(snapshot)",
):
    require(token in capacity_common, f"common capacity helper omits {token}")
require(
    capacity_common.index("unchecked_transaction")
    < capacity_common.index("governed_reservation_capacity_components")
    < capacity_common.index("resolve_authenticated_physical_prelaunch_sources")
    < capacity_common.index("governed_execution_custody_closure_v3_capacity_bound")
    < capacity_common.index("drop(authenticated_sources)")
    < capacity_common.index("drop(snapshot)"),
    "V2/V3 capacity is not selected, authenticated, and computed under one snapshot",
)
capacity_components = function(GOVERNED, "governed_reservation_capacity_components")
require(
    '"projected_bytes"' in capacity_components,
    "physical reservation parser omits the projected-byte component",
)

independent = function(GOVERNED, "resolve_independent_governed_projection_sources")
require(
    independent.count("resolve_authenticated_physical_prelaunch_sources") == 1,
    "independent projection resolution does not call the common helper exactly once",
)
require(
    independent.index("resolve_authenticated_physical_prelaunch_sources")
    < independent.index("IndependentGovernedProjectionSources {"),
    "independent projection bundle is constructed before authenticated source resolution",
)

pending = function(GOVERNED, "pending_v3_projection_plans")
require(
    pending.index("resolve_independent_governed_projection_sources")
    < pending.index("shallow_reopen_governed_v3_projection_with_arena"),
    "pending recovery parses a capsule before all Store-selected sources resolve",
)
require(
    pending.index("source_bundles.push")
    < pending.index("for (reservation_record_id, sources) in source_bundles"),
    "pending recovery does not separate global source collection from local capsule work",
)

custody_prevalidate = function(
    GOVERNED, "prevalidate_governed_v3_projection_with_custody"
)
require(
    custody_prevalidate.count("resolve_independent_governed_projection_sources") == 1,
    "custody prevalidation resolves its independent source bundle more than once",
)
require(
    custody_prevalidate.index("resolve_independent_governed_projection_sources")
    < custody_prevalidate.index("shallow_reopen_governed_v3_projection_with_arena")
    < custody_prevalidate.index("prevalidate_governed_v3_projection_with_sources"),
    "custody prevalidation does not pass one resolved bundle through shallow then deep checks",
)
require(
    custody_prevalidate.count("&sources") >= 2,
    "custody prevalidation does not visibly reuse the same source bundle",
)

complete = function(GOVERNED, "verify_governed_projection_and_mark_indexed")
require(
    complete.index("unchecked_transaction")
    < complete.index("verify_governed_projection_on_connection")
    < complete.index("snapshot.commit"),
    "public complete verification is not one explicit snapshot",
)
prevalidate = function(GOVERNED, "prevalidate_governed_v3_projection_with_arena")
require(
    prevalidate.index("resolve_independent_governed_projection_sources")
    < prevalidate.index("prevalidate_governed_v3_projection_with_sources"),
    "complete verification does not authenticate sources before capsule adjudication",
)

public_apis = (
    "verify_governed_execution_custody_closure_v2_capacity",
    "verify_governed_execution_custody_closure_v3_capacity",
    "recover_pending_governed_projections",
    "recover_governed_projection_and_mark_indexed",
    "verify_governed_projection_and_mark_indexed",
)
for api in public_apis:
    body = function(GOVERNED, api)
    signature = body[: body.index("{")]
    for forbidden in ("resolver", "resolution", "proof", "root", "source"):
        require(
            forbidden not in signature.lower(),
            f"public Store API {api} exposes forbidden parameter text {forbidden}",
        )

require(
    "nq-host-role-dependency-custody" not in CORE_CARGO,
    "nq-core directly depends on the shared resolver",
)
require(
    "recover_pending_governed_projections()?" in CORE,
    "nq-core startup no longer calls the zero-resolver recovery API",
)
for forbidden in (
    "AuthenticatedRuntimeDependencyClosure",
    "AuthenticatedSourceResolution",
    "ExternalSourceRequirement",
    "AuthoritySourceRequirement",
):
    require(forbidden not in CORE, f"nq-core imports resolver detail {forbidden}")

require(
    "pub(crate) fn verify_governed_projection_on_connection" not in GOVERNED,
    "connection-level complete verifier remains crate-visible",
)
require(
    "nq_host_role_runtime" not in GOVERNED + STORE_LIB,
    "Store product source reaches host-runtime compatibility exports",
)

print("R0b Store-owned dependency/source callgraph: PASS")
sys.exit(0)
