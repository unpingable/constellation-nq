#!/usr/bin/env python3
"""Static R0b and Gen4 Store authority call-graph proof.

The scanner is deliberately lexical/structural and fail closed.  Comments and
literal contents cannot satisfy call counts, every production Rust target is
parsed, and protected Gen4 names may not hide behind traits, callbacks,
features, FFI exports, or re-exports.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Iterable, Sequence

sys.dont_write_bytecode = True

from rust_source_scan import (  # noqa: E402
    Call,
    CargoPackage,
    Function,
    RustSource,
    ScanError,
    cargo_test_sources,
    compile_confined_module_paths,
    compact_tokens,
    production_functions,
    production_sources,
    require_unique_function,
    workspace_packages,
)


ROOT = Path(
    os.environ.get("NQ_PROOF_SOURCE_ROOT", Path(__file__).resolve().parents[3])
).resolve()
CONFIG_PATH = Path(__file__).with_name("r0b_callgraph_allowlist.json")


def fail(message: str) -> None:
    raise AssertionError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_config() -> dict:
    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {CONFIG_PATH}: {error}")
    require(config.get("schema_version") == 1, "unsupported R0b allowlist schema")
    return config


def package_dependencies(
    package: CargoPackage, *, include_dev: bool = False
) -> dict[str, object]:
    dependencies: dict[str, object] = {}
    for table_name, table in package.dependency_tables(include_dev=include_dev):
        for name, specification in table.items():
            require(
                name not in dependencies,
                f"{package.name} repeats product dependency {name} in {table_name}",
            )
            dependencies[name] = specification
    return dependencies


def path_count(tokens: Sequence, path: str) -> int:
    parts = path.split("::")
    target: list[str] = []
    for index, part in enumerate(parts):
        if index:
            target.append("::")
        target.append(part)
    values = [token.value for token in tokens]
    width = len(target)
    return sum(
        values[index : index + width] == target
        for index in range(len(values) - width + 1)
    )


def struct_literal_count(tokens: Sequence, name: str) -> int:
    count = 0
    for index, token in enumerate(tokens[:-1]):
        if token.value != name or tokens[index + 1].value != "{":
            continue
        if index and tokens[index - 1].value in ("struct", "enum"):
            continue
        count += 1
    return count


def all_calls(
    functions: Iterable[Function], name: str | None = None
) -> list[tuple[Function, Call]]:
    return [(function, call) for function in functions for call in function.calls(name)]


def require_calls(function: Function, names: Iterable[str], label: str) -> None:
    present = {call.name for call in function.calls()}
    for name in names:
        require(name in present, f"{label} omits call {name}")


def call_position(function: Function, name: str) -> int:
    calls = function.calls(name)
    require(len(calls) == 1, f"{function.qualified_name} must call {name} exactly once")
    return calls[0].start


def require_compact(function: Function, expression: str, message: str) -> None:
    require(expression in compact_tokens(function.item_tokens), message)


def selector_function(
    functions: Sequence[Function], selector: dict, label: str
) -> Function:
    require(isinstance(selector, dict), f"{label} selector must be an object")
    for key in ("path", "name"):
        require(
            isinstance(selector.get(key), str) and selector[key],
            f"{label}.{key} is absent",
        )
    owner = selector.get("owner")
    require(
        owner is None or isinstance(owner, str), f"{label}.owner must be string or null"
    )
    return require_unique_function(
        functions,
        path=selector["path"],
        owner=owner,
        name=selector["name"],
    )


def function_identity(function: Function) -> tuple[str, str | None, str]:
    return function.source.path.as_posix(), function.owner, function.name


def direct_callers(
    functions: Sequence[Function], name: str
) -> list[tuple[Function, Call]]:
    return [(function, call) for function, call in all_calls(functions, name)]


def structural_reverse_edges(
    functions: Sequence[Function],
    *,
    protected_override: tuple[Function, Function, str] | None = None,
) -> dict[Function, set[Function]]:
    """Build conservative caller edges with structural owner resolution.

    `protected_override` is (bare helper, typed method, bare receiver).  It
    disambiguates their intentionally identical API names: `self.store.foo()`
    inside the typed method is the bare edge; all other product calls are typed
    API edges.
    """
    by_name: dict[str, list[Function]] = {}
    for function in functions:
        by_name.setdefault(function.name, []).append(function)
    reverse: dict[Function, set[Function]] = {}
    for caller in functions:
        for call in caller.calls():
            candidates: list[Function]
            if protected_override and call.name == protected_override[0].name:
                bare, typed, receiver = protected_override
                if bare.name != typed.name:
                    candidates = [bare]
                else:
                    candidates = [
                        bare
                        if function_identity(caller) == function_identity(typed)
                        and call.receiver == receiver
                        else typed
                    ]
            elif "::" in call.path:
                owner = call.path.split("::")[-2]
                candidates = [
                    function
                    for function in by_name.get(call.name, [])
                    if function.owner == owner
                ]
            elif call.receiver == "self" and caller.owner:
                candidates = [
                    function
                    for function in by_name.get(call.name, [])
                    if function.owner == caller.owner
                ]
            else:
                candidates = by_name.get(call.name, [])
            # An unresolved direct call is not silently discarded when a
            # same-named definition exists; ambiguity broadens the edge set.
            for target in candidates:
                reverse.setdefault(target, set()).add(caller)
    return reverse


def structural_reverse_reachable(
    roots: Iterable[Function], reverse: dict[Function, set[Function]]
) -> set[Function]:
    reached: set[Function] = set()
    frontier = list(roots)
    while frontier:
        target = frontier.pop()
        for caller in reverse.get(target, set()):
            if caller not in reached:
                reached.add(caller)
                frontier.append(caller)
    return reached


def require_no_product_test_support(packages: Sequence[CargoPackage]) -> None:
    for package in packages:
        for table_name, table in package.dependency_tables(include_dev=False):
            for dependency, specification in table.items():
                require(
                    "test-support" not in dependency
                    and "test_support" not in dependency,
                    f"{package.name} product dependency names fixture support in {table_name}: {dependency}",
                )
                if not isinstance(specification, dict):
                    continue
                features = specification.get("features", [])
                require(
                    "test-support" not in features and "test_support" not in features,
                    f"{package.name} product dependency {dependency} enables fixture support in {table_name}",
                )


def require_acyclic_product_dependencies(packages: Sequence[CargoPackage]) -> None:
    package_names = {package.name for package in packages}
    graph = {
        package.name: set(package_dependencies(package)) & package_names
        for package in packages
    }
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            cycle = " -> ".join(visiting[visiting.index(name) :] + [name])
            fail(f"workspace product dependency cycle: {cycle}")
        if name in visited:
            return
        visiting.append(name)
        for dependency in sorted(graph[name]):
            visit(dependency)
        visiting.pop()
        visited.add(name)

    for name in sorted(graph):
        visit(name)


def verify_resolver_pin(config: dict) -> None:
    pin = config["resolver_pin"]
    path = ROOT / pin["path"]
    require(path.is_file(), f"pinned resolver source is absent: {pin['path']}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    require(
        actual == pin["sha256"],
        f"pinned resolver changed: expected {pin['sha256']}, found {actual}",
    )


def verify_r0b(
    config: dict,
    sources_by_path: dict[str, RustSource],
    packages_by_name: dict[str, CargoPackage],
) -> None:
    settings = config["r0b"]
    governed = sources_by_path[settings["governed_source"]]
    store_lib = sources_by_path[settings["store_source"]]
    core = sources_by_path[settings["core_source"]]
    governed_product = [
        function for function in governed.functions if not function.cfg_test
    ]

    store_dependencies = package_dependencies(packages_by_name["nq-store"])
    custody_dependency = store_dependencies.get("nq-host-role-dependency-custody")
    require(
        custody_dependency == {"path": "../nq-host-role-dependency-custody"},
        "nq-store lacks one direct default-feature shared custody dependency",
    )
    require(
        "nq-host-role-runtime" not in store_dependencies,
        "nq-store product dependencies reach upward into host-runtime",
    )

    helper = governed.require_function(
        "resolve_authenticated_physical_prelaunch_sources"
    )
    require(not helper.cfg_test, "authenticated source helper is test-confined")
    require(
        helper.visibility == "private", "authenticated source helper is not private"
    )
    calls = all_calls(governed.functions)
    require(
        sum(
            call.path == "AuthenticatedRuntimeDependencyClosure::reopen_bound"
            for _, call in calls
        )
        == 1,
        "Store must call the closed reopen_bound verifier exactly once",
    )
    require(
        sum(call.path == "ExactDependencyCustodyBinding::new" for _, call in calls)
        == 1,
        "Store must construct exactly one exact dependency-custody binding",
    )
    require(
        sum(call.name == "resolve_sources" for _, call in calls) == 1,
        "Store must call closed source resolution exactly once",
    )
    for forbidden in (
        "AuthenticatedRuntimeDependencyClosure::decode_authenticated",
        "RuntimeDependencyGenerationCustody::reopen",
        "RuntimeDependencyGenerationCustody::decode_canonical_closure",
    ):
        require(
            not any(call.path == forbidden for _, call in calls),
            f"Store reaches forbidden low-level API {forbidden}",
        )
    require(
        not any(
            call.path.startswith("Ed25519TrustAnchor::")
            and (call.name.startswith("decode_") or call.name in ("fixture", "new"))
            for _, call in calls
        ),
        "Store decodes or constructs a caller-selected Ed25519 trust anchor",
    )
    require(
        struct_literal_count(governed.tokens, "AuthenticatedPhysicalPrelaunchSources")
        == 1,
        "Store has more than one authenticated physical-source summary constructor",
    )

    require_calls(
        helper,
        (
            "runtime_checkpoint_dependency_on_connection",
            "runtime_dependency_trust_root_on_connection",
            "new",
            "reopen_bound",
            "derive_physical_prelaunch_requirements",
            "resolve_sources",
        ),
        "common helper",
    )
    for expression in (
        "external.len()!=4",
        "authority.len()!=2",
        "requirement_set_digest!=expected_requirement_set_digest",
    ):
        require_compact(
            helper,
            expression,
            f"common helper omits its closed six-purpose gate: {expression}",
        )
    require(
        any(
            "authenticated source resolution is not the complete six-purpose physical requirement set"
            in literal
            for literal in helper.string_literals
        ),
        "common helper omits its closed six-purpose refusal text",
    )
    ordered = (
        "runtime_checkpoint_dependency_on_connection",
        "runtime_dependency_trust_root_on_connection",
        "new",
        "reopen_bound",
        "resolve_sources",
    )
    positions = [call_position(helper, name) for name in ordered]
    require(
        positions == sorted(positions) and len(set(positions)) == len(positions),
        "common helper does not preserve Store selection -> root -> binding -> reopen -> resolution",
    )

    requirements = governed.require_function(
        "derive_physical_prelaunch_requirements", production_only=True
    )
    require(
        path_count(requirements.item_tokens, "ExternalSourcePurpose") == 4,
        "Store does not derive exactly four closed external source roles",
    )
    require(
        path_count(requirements.item_tokens, "AuthoritySourcePurpose") == 2,
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
            path_count(requirements.item_tokens, purpose) == 1,
            f"Store physical requirement derivation does not select {purpose} exactly once",
        )

    context_guard = governed.require_function(
        "require_same_context", production_only=True
    )
    for expression in (
        "exact_external!=requirements.external",
        "exact_authority!=requirements.authority",
        "requirement_set_digest!=self.requirement_set_digest",
    ):
        require_compact(
            context_guard, expression, f"private context guard omits {expression}"
        )

    for name in settings["test_only_helpers"]:
        found = governed.find_functions(name)
        require(
            len(found) == 1,
            f"R0b branch-isolation helper {name} is absent or ambiguous",
        )
        function = found[0]
        require(
            function.cfg_test and function.visibility == "pub(super)",
            f"R0b branch-isolation helper {name} is not cfg(test)-only and module-private",
        )
        require(
            not any(
                call.name == name
                for product_function in governed_product
                for call in product_function.calls()
            ),
            f"R0b branch-isolation helper {name} leaked into Store product callgraph",
        )
        require(
            not any(name in export.names for export in store_lib.reexports),
            f"R0b branch-isolation helper {name} is publicly re-exported",
        )

    structural_test = store_lib.require_function(
        "r0b_b12_through_b15_requirement_context_is_closed_and_role_exact"
    )
    for label in ("B12", "B13", "B14", "B15"):
        require(
            any(label in literal for literal in structural_test.string_literals),
            f"B12-B15 structural control omits {label}",
        )
    for identifier in (
        "OmitExternal",
        "DuplicateExternal",
        "ExtraneousExternal",
        "SwapExternalPurposes",
    ):
        require(
            len(structural_test.code_identifiers(identifier)) >= 1,
            f"B12-B15 structural control omits {identifier}",
        )
    require_compact(
        structural_test, "counts.external,4", "B12-B15 control omits external count"
    )
    require_compact(
        structural_test, "counts.authority,2", "B12-B15 control omits authority count"
    )

    capacity_v2 = governed.require_function(
        "verify_governed_execution_custody_closure_v2_capacity", production_only=True
    )
    require(
        len(
            capacity_v2.calls(
                "verify_governed_execution_custody_closure_capacity_on_one_snapshot"
            )
        )
        == 1,
        "public V2 capacity does not delegate exactly once to the common snapshot helper",
    )
    require(
        not capacity_v2.calls("unchecked_transaction")
        and not capacity_v2.calls("resolve_authenticated_physical_prelaunch_sources"),
        "public V2 capacity bypasses or duplicates the common snapshot helper",
    )
    capacity_v3 = governed.require_function(
        "verify_governed_execution_custody_closure_v3_capacity", production_only=True
    )
    require(
        len(
            capacity_v3.calls(
                "verify_governed_execution_custody_closure_capacity_on_one_snapshot"
            )
        )
        == 1,
        "public V3 capacity does not delegate exactly once to the common snapshot helper",
    )
    require(
        not capacity_v3.calls("verify_governed_execution_custody_closure_v2_capacity")
        and not capacity_v3.code_identifiers("projection_capsule_capacity_bytes")
        and not capacity_v3.calls(
            "governed_execution_custody_closure_v3_capacity_bound"
        ),
        "public V3 capacity performs post-snapshot arithmetic or calls public V2",
    )
    capacity_common = governed.require_function(
        "verify_governed_execution_custody_closure_capacity_on_one_snapshot",
        production_only=True,
    )
    require_calls(
        capacity_common,
        (
            "unchecked_transaction",
            "governed_reservation_capacity_components",
            "resolve_authenticated_physical_prelaunch_sources",
            "governed_execution_custody_closure_v2_capacity_bound",
            "governed_execution_custody_closure_v3_capacity_bound",
            "drop",
        ),
        "common capacity helper",
    )
    require_compact(
        capacity_common,
        "drop(authenticated_sources)",
        "common capacity helper does not drop authenticated sources explicitly",
    )
    require_compact(
        capacity_common,
        "drop(snapshot)",
        "common capacity helper does not drop the snapshot explicitly",
    )
    require_compact(
        capacity_common,
        "projection_capsule_capacity!=reservation.projection_capsule_capacity_bytes",
        "common capacity helper omits exact projection capacity comparison",
    )
    positions = [
        call_position(capacity_common, name)
        for name in (
            "unchecked_transaction",
            "governed_reservation_capacity_components",
            "resolve_authenticated_physical_prelaunch_sources",
            "governed_execution_custody_closure_v3_capacity_bound",
        )
    ]
    drop_calls = capacity_common.calls("drop")
    require(
        len(drop_calls) == 2,
        "common capacity helper must explicitly drop sources and snapshot",
    )
    require(
        positions == sorted(positions)
        and positions[-1] < drop_calls[0].start < drop_calls[1].start,
        "V2/V3 capacity is not selected, authenticated, and computed under one snapshot",
    )
    capacity_components = governed.require_function(
        "governed_reservation_capacity_components", production_only=True
    )
    require(
        any(
            "projected_bytes" in literal
            for literal in capacity_components.string_literals
        ),
        "physical reservation parser omits the projected-byte component",
    )

    independent = governed.require_function(
        "resolve_independent_governed_projection_sources", production_only=True
    )
    require(
        len(independent.calls("resolve_authenticated_physical_prelaunch_sources")) == 1,
        "independent projection resolution does not call the common helper exactly once",
    )
    bundle_literals = [
        token.start
        for index, token in enumerate(independent.body_tokens[:-1])
        if token.value == "IndependentGovernedProjectionSources"
        and independent.body_tokens[index + 1].value == "{"
    ]
    require(
        len(bundle_literals) == 1
        and call_position(
            independent, "resolve_authenticated_physical_prelaunch_sources"
        )
        < bundle_literals[0],
        "independent projection bundle is constructed before authenticated source resolution",
    )

    pending = governed.require_function(
        "pending_v3_projection_plans", production_only=True
    )
    require(
        call_position(pending, "resolve_independent_governed_projection_sources")
        < call_position(pending, "shallow_reopen_governed_v3_projection_with_arena"),
        "pending recovery parses a capsule before all Store-selected sources resolve",
    )
    require_compact(
        pending,
        "source_bundles.push",
        "pending recovery does not collect source bundles",
    )
    require_compact(
        pending,
        "for(reservation_record_id,sources)insource_bundles",
        "pending recovery does not separate global source collection from local capsule work",
    )

    custody_prevalidate = governed.require_function(
        "prevalidate_governed_v3_projection_with_custody", production_only=True
    )
    require(
        len(
            custody_prevalidate.calls("resolve_independent_governed_projection_sources")
        )
        == 1,
        "custody prevalidation resolves its independent source bundle more than once",
    )
    positions = [
        call_position(custody_prevalidate, name)
        for name in (
            "resolve_independent_governed_projection_sources",
            "shallow_reopen_governed_v3_projection_with_arena",
            "prevalidate_governed_v3_projection_with_sources",
        )
    ]
    require(
        positions == sorted(positions),
        "custody prevalidation does not pass one resolved bundle through shallow then deep checks",
    )
    require(
        compact_tokens(custody_prevalidate.item_tokens).count("&sources") >= 2,
        "custody prevalidation does not visibly reuse the same source bundle",
    )

    complete = governed.require_function(
        "verify_governed_projection_and_mark_indexed", production_only=True
    )
    positions = [
        call_position(complete, name)
        for name in (
            "unchecked_transaction",
            "verify_governed_projection_on_connection",
            "commit",
        )
    ]
    complete_commits = complete.calls("commit")
    require(
        positions == sorted(positions)
        and len(complete_commits) == 1
        and complete_commits[0].receiver == "snapshot",
        "public complete verification is not one explicit snapshot",
    )
    prevalidate = governed.require_function(
        "prevalidate_governed_v3_projection_with_arena", production_only=True
    )
    require(
        call_position(prevalidate, "resolve_independent_governed_projection_sources")
        < call_position(prevalidate, "prevalidate_governed_v3_projection_with_sources"),
        "complete verification does not authenticate sources before capsule adjudication",
    )

    for api in settings["public_zero_resolver_apis"]:
        function = governed.require_function(api, production_only=True)
        signature = function.signature_code.lower()
        for forbidden in ("resolver", "resolution", "proof", "root", "source"):
            require(
                forbidden not in signature,
                f"public Store API {api} exposes forbidden parameter text {forbidden}",
            )

    core_dependencies = package_dependencies(packages_by_name["nq-core"])
    require(
        "nq-host-role-dependency-custody" not in core_dependencies,
        "nq-core directly depends on the shared resolver",
    )
    require(
        "recover_pending_governed_projections()?" in compact_tokens(core.tokens),
        "nq-core startup no longer calls the zero-resolver recovery API",
    )
    for forbidden in (
        "AuthenticatedRuntimeDependencyClosure",
        "AuthenticatedSourceResolution",
        "ExternalSourceRequirement",
        "AuthoritySourceRequirement",
    ):
        require(
            not core.identifier_occurrences(forbidden),
            f"nq-core imports resolver detail {forbidden}",
        )

    connection_verifiers = governed.find_functions(
        "verify_governed_projection_on_connection", production_only=True
    )
    require(
        len(connection_verifiers) == 1
        and connection_verifiers[0].visibility == "private",
        "connection-level complete verifier remains crate-visible",
    )
    store_product_sources = [
        source
        for path, source in sources_by_path.items()
        if path.startswith("crates/nq-store/src/")
    ]
    require(
        not any(
            source.identifier_occurrences("nq_host_role_runtime")
            for source in store_product_sources
        ),
        "Store product source reaches host-runtime compatibility exports",
    )


def enclosing_function(source: RustSource, offset: int) -> Function | None:
    matches = [
        function
        for function in source.functions
        if function.source.tokens[function.start_token].start
        <= offset
        <= function.source.tokens[function.end_token].end
    ]
    return (
        min(
            matches,
            key=lambda function: (
                function.source.tokens[function.end_token].end
                - function.source.tokens[function.start_token].start
            ),
        )
        if matches
        else None
    )


def evidence_construction_sites(
    sources: Sequence[RustSource], evidence_type: str
) -> list[tuple[RustSource, Function | None, int, str]]:
    sites: list[tuple[RustSource, Function | None, int, str]] = []
    constructor_names = {"new", "from", "from_parts", "unchecked", "build", "default"}
    for source in sources:
        tokens = source.tokens
        for index, token in enumerate(tokens):
            if token.value != evidence_type:
                continue
            if index and tokens[index - 1].value in ("struct", "enum", "type"):
                continue
            kind = None
            if index + 1 < len(tokens) and tokens[index + 1].value == "{":
                kind = "struct literal"
            elif (
                index + 3 < len(tokens)
                and tokens[index + 1].value == "::"
                and tokens[index + 2].value in constructor_names
                and tokens[index + 3].value == "("
            ):
                kind = f"associated constructor {tokens[index + 2].value}"
            if kind:
                sites.append(
                    (source, enclosing_function(source, token.start), token.line, kind)
                )
    return sites


def require_additional_sealed_evidence(
    *,
    sources: Sequence[RustSource],
    functions: Sequence[Function],
    evidence_type: str,
    verifier: Function,
    macro_generated: bool = False,
) -> None:
    """Prove another authority result is privately minted by one verifier."""
    definitions = [
        (source, index)
        for source in sources
        for index, token in enumerate(source.tokens[:-1])
        if token.value == "struct"
        and source.tokens[index + 1].value == evidence_type
    ]
    if macro_generated:
        require(
            not definitions,
            f"macro-generated sealed evidence {evidence_type} also has a direct struct definition",
        )
        macro_sources = [
            source
            for source in sources
            if source.identifier_occurrences("verified_event_type")
        ]
        require(
            len(macro_sources) == 1,
            "verified event macro definition/invocations are absent or split across sources",
        )
        macro_code = compact_tokens(macro_sources[0].tokens)
        require(
            "macro_rules!verified_event_type" in macro_code
            and "pubstruct$name<'id>" in macro_code
            and "pub(crate)fnnew(" in macro_code
            and "_invariant:PhantomData<fn(&'idmut())->&'idmut()>" in macro_code
            and f"{evidence_type},re{verifier.name}" in macro_code,
            f"{evidence_type} is not emitted by the sealed invariant verified-event macro",
        )
    else:
        require(
            len(definitions) == 1,
            f"expected exactly one sealed evidence definition {evidence_type}; found {len(definitions)}",
        )
    if macro_generated:
        definition_source = None
        definition_index = None
    else:
        definition_source, definition_index = definitions[0]
    if not macro_generated:
        assert definition_source is not None and definition_index is not None
        definition_depth = definition_source.depths[definition_index]
        definition_open = next(
            (
                index
                for index in range(definition_index + 2, len(definition_source.tokens))
                if definition_source.depths[index] == definition_depth
                and definition_source.tokens[index].value == "{"
            ),
            None,
        )
        require(definition_open is not None, f"{evidence_type} has no field body")
        assert definition_open is not None
        definition_close = definition_source.pairs[definition_open]
        require(
            not any(
                definition_source.tokens[index].value == "pub"
                and definition_source.depths[index] == definition_depth + 1
                and not (
                    index + 1 < definition_close
                    and definition_source.tokens[index + 1].value == "("
                )
                for index in range(definition_open + 1, definition_close)
            ),
            f"{evidence_type} exposes a public field",
        )

    product_identities = {function_identity(function) for function in functions}
    sites = [
        site
        for site in evidence_construction_sites(sources, evidence_type)
        if site[1] is None or function_identity(site[1]) in product_identities
    ]
    require(sites, f"no production construction of {evidence_type} was found")
    require(
        all(
            function is not None
            and function_identity(function) == function_identity(verifier)
            for _, function, _, _ in sites
        ),
        f"{evidence_type} construction escapes {verifier.qualified_name}: "
        + ", ".join(
            f"{source.path}:{line} {kind}" for source, _, line, kind in sites
        ),
    )
    constructors = [
        function
        for function in functions
        if function.owner == evidence_type
        and function.name in ("new", "from", "from_parts", "build", "default", "unchecked")
    ]
    if macro_generated:
        callers = [
            caller
            for caller, call in direct_callers(functions, "new")
            if call.path == f"{evidence_type}::new"
        ]
        require(
            callers
            and all(
                function_identity(caller) == function_identity(verifier)
                for caller in callers
            ),
            f"macro-generated {evidence_type} constructor callers escape {verifier.qualified_name}: "
            + (", ".join(caller.location for caller in callers) or "none"),
        )
    else:
        require(constructors, f"{evidence_type} has no structurally visible constructor")
        for constructor in constructors:
            require(
                constructor.name != "unchecked" and constructor.visibility != "pub",
                f"{evidence_type} exposes forbidden constructor {constructor.qualified_name}",
            )
            callers = [
                caller
                for caller, call in direct_callers(functions, constructor.name)
                if call.path == f"{evidence_type}::{constructor.name}"
            ]
            require(
                callers
                and all(
                    function_identity(caller) == function_identity(verifier)
                    for caller in callers
                ),
                f"{constructor.qualified_name} callers escape {verifier.qualified_name}: "
                + (", ".join(caller.location for caller in callers) or "none"),
            )
    for forbidden_trait in ("Clone", "Copy", "Default", "Serialize", "Deserialize"):
        require(
            not any(
                scope.owner == evidence_type and scope.trait_name == forbidden_trait
                for source in sources
                for scope in source.impl_scopes
            ),
            f"{evidence_type} implements forbidden trait {forbidden_trait}",
        )
        if not macro_generated:
            assert definition_source is not None and definition_index is not None
            require(
                not any(
                    forbidden_trait in attribute
                    for attribute in definition_source.item_attributes(definition_index)
                ),
                f"{evidence_type} derives forbidden trait {forbidden_trait}",
            )


def require_test_support_confinement(
    sources: Sequence[RustSource],
    functions: Sequence[Function],
    protected_call_names: set[str],
    protected_signature_types: set[str],
) -> None:
    """Feature-enabled fixtures may expose raw inputs, never sealed standing."""
    feature_sources = [
        source
        for source in sources
        if source.path.name == "test_support.rs"
        or "test_support" in source.path.parts
    ]
    for function in functions:
        if function.source not in feature_sources or function.cfg_test:
            continue
        if function.visibility == "pub":
            leaked = sorted(
                name
                for name in protected_signature_types
                if name in function.signature_code
            )
            require(
                not leaked,
                f"feature test-support API {function.location} exposes sealed type(s): "
                + ", ".join(leaked),
            )
        reached = sorted(
            {call.name for call in function.calls() if call.name in protected_call_names}
        )
        require(
            not reached,
            f"feature test-support function {function.location} directly reaches protected authority operation(s): "
            + ", ".join(reached),
        )
    for source in feature_sources:
        for export in source.reexports:
            leaked = sorted(set(export.names) & protected_signature_types)
            require(
                not leaked,
                f"feature test-support re-export {export.location} exposes sealed type(s): "
                + ", ".join(leaked),
            )


def verify_symbol_is_direct_only(
    sources: Sequence[RustSource],
    functions: Sequence[Function],
    symbol: str,
    compile_confined_paths: set[str],
) -> None:
    definition_offsets = {
        (
            function.source.path.as_posix(),
            function.source.tokens[function.name_token].start,
        )
        for function in functions
        if function.name == symbol
    }
    call_offsets = {
        (function.source.path.as_posix(), call.start)
        for function in functions
        for call in function.calls(symbol)
    }
    # Call.start points at `(`; map those back to the symbol token immediately before it.
    allowed_identifier_offsets = set(definition_offsets)
    for source in sources:
        for index, token in enumerate(source.tokens):
            if token.value != symbol:
                continue
            if index + 1 < len(source.tokens) and source.tokens[index + 1].value == "(":
                if (
                    source.path.as_posix(),
                    source.tokens[index + 1].start,
                ) in call_offsets:
                    allowed_identifier_offsets.add(
                        (source.path.as_posix(), token.start)
                    )
    unexpected = []
    for source in sources:
        for token in source.identifier_occurrences(symbol):
            identity = source.path.as_posix(), token.start
            if identity not in allowed_identifier_offsets:
                enclosing = enclosing_function(source, token.start)
                if source.path.as_posix() in compile_confined_paths or (
                    enclosing is not None and enclosing.cfg_test
                ):
                    continue
                unexpected.append(f"{source.path}:{token.line}")
    require(
        not unexpected,
        f"protected symbol {symbol} is used as callback/import/alias/macro surface at {', '.join(unexpected)}",
    )


def verify_gen4(
    config: dict,
    sources: Sequence[RustSource],
    test_sources: Sequence[RustSource],
    functions: Sequence[Function],
    packages: Sequence[CargoPackage],
    compile_confined_paths: set[str],
) -> str:
    settings = config["gen4"]
    enforcement = settings.get("enforcement")
    require(
        enforcement in ("pending", "active"),
        "Gen4 enforcement must be pending or active",
    )
    if os.environ.get("NQ_PROOF_FORCE_GEN4_ACTIVE") == "1":
        enforcement = "active"
    marker_locations = [
        f"{source.path}:{token.line} ({marker})"
        for source in sources
        for marker in settings["activation_markers"]
        for token in source.identifier_occurrences(marker)
    ]
    if enforcement == "pending":
        detail = (
            f"{len(marker_locations)} activation marker occurrence(s) observed; active checks not claimed"
            if marker_locations
            else "no Gen4 activation markers present"
        )
        return f"PENDING ({detail})"

    bare = selector_function(
        functions, settings["bare_store_helper"], "bare_store_helper"
    )
    session = selector_function(
        functions, settings["typed_session_method"], "typed_session_method"
    )
    classification_bare = selector_function(
        functions,
        settings["bare_classification_helper"],
        "bare_classification_helper",
    )
    classification_session = selector_function(
        functions,
        settings["typed_classification_method"],
        "typed_classification_method",
    )
    cardinality_bare = selector_function(
        functions,
        settings["bare_cardinality_classification_helper"],
        "bare_cardinality_classification_helper",
    )
    cardinality_session = selector_function(
        functions,
        settings["typed_cardinality_classification_method"],
        "typed_cardinality_classification_method",
    )
    branded_constructor = selector_function(
        functions,
        settings["branded_session_constructor"],
        "branded_session_constructor",
    )
    branded_scope = selector_function(
        functions,
        settings["store_branded_session_scope"],
        "store_branded_session_scope",
    )
    brand_generator = selector_function(
        functions, settings["brand_generator"], "brand_generator"
    )
    authority_candidate_initializer = selector_function(
        functions,
        settings["authority_candidate_initializer"],
        "authority_candidate_initializer",
    )
    unqualified_storage_initializer = selector_function(
        functions,
        settings["unqualified_storage_initializer"],
        "unqualified_storage_initializer",
    )
    require(bare.trait_owner is None, "bare Store helper is supplied by a trait")
    require(
        session.trait_owner is None,
        "typed session establishment is supplied by a trait",
    )
    require(
        session.visibility == "pub",
        "typed session establishment is not the public typed API",
    )
    require(
        classification_session.trait_owner is None
        and classification_session.visibility == "pub",
        "typed migration classification is not a public inherent session API",
    )
    require(
        cardinality_session.trait_owner is None
        and cardinality_session.visibility == "pub",
        "typed cardinality classification is not a public inherent session API",
    )
    require(
        bare.visibility in ("private", "pub(crate)"),
        "bare Store helper is externally public",
    )
    require(
        classification_bare.trait_owner is None
        and classification_bare.visibility in ("private", "pub(crate)"),
        "bare migration classification helper is externally public or trait-supplied",
    )
    require(
        cardinality_bare.trait_owner is None
        and cardinality_bare.visibility in ("private", "pub(crate)"),
        "bare cardinality classification helper is externally public or trait-supplied",
    )
    require(
        branded_constructor.trait_owner is None
        and branded_constructor.visibility == "pub(crate)",
        "branded StoreWriterSession construction is not crate-private inherent plumbing",
    )
    require(
        branded_scope.trait_owner is None and branded_scope.visibility == "pub(crate)",
        "Store-owned branded writer scope is not crate-private inherent plumbing",
    )
    scope_signature_end = branded_scope.body_open_token or branded_scope.end_token + 1
    scope_signature = compact_tokens(
        branded_scope.source.tokens[branded_scope.start_token : scope_signature_end]
    )
    require(
        "implfor<'id>FnOnce(" in scope_signature
        and "&VerificationBrand<'id>" in scope_signature
        and "&mutStoreWriterSession<'_,VerificationBrand<'id>>" in scope_signature
        and scope_signature.count("VerificationBrand<'id>") == 2,
        "Store-owned branded writer scope has lost its HRTB brand/session type law",
    )
    require(
        "'id" not in scope_signature.split("(", 1)[0],
        "Store-owned branded writer scope exposes the fresh brand lifetime as a method parameter",
    )
    public_store_brand_surfaces = [
        function
        for function in functions
        if function.owner == "Store"
        and function.visibility == "pub"
        and "VerificationBrand" in function.signature_code
        and function_identity(function) != function_identity(branded_scope)
    ]
    require(
        not public_store_brand_surfaces,
        "another public Store API accepts or exposes VerificationBrand: "
        + ", ".join(function.location for function in public_store_brand_surfaces),
    )
    constructor_calls = direct_callers(functions, branded_constructor.name)
    require(
        len(constructor_calls) == 1
        and function_identity(constructor_calls[0][0])
        == function_identity(branded_scope)
        and constructor_calls[0][1].path
        == f"StoreWriterSession::{branded_constructor.name}",
        "branded StoreWriterSession constructor must have exactly one production caller, the Store-owned HRTB scope; found "
        + (", ".join(caller.location for caller, _ in constructor_calls) or "none"),
    )
    require(
        len(branded_scope.calls(brand_generator.name)) == 1
        and len(branded_scope.calls(branded_constructor.name)) == 1,
        "Store-owned HRTB scope must mint one fresh brand and exactly one branded session",
    )

    require(
        authority_candidate_initializer.trait_owner is None
        and authority_candidate_initializer.visibility == "pub(crate)",
        "runtime-authority candidate initialization is not crate-private inherent plumbing",
    )
    require(
        unqualified_storage_initializer.trait_owner is None
        and unqualified_storage_initializer.visibility == "pub",
        "explicit storage-only initialization is not the public unqualified lifecycle",
    )
    candidate_calls = direct_callers(functions, authority_candidate_initializer.name)
    candidate_initializer_caller = selector_function(
        functions,
        settings["authority_candidate_initializer_caller"],
        "authority_candidate_initializer_caller",
    )
    require(
        len(candidate_calls) == 1
        and function_identity(candidate_calls[0][0])
        == function_identity(candidate_initializer_caller),
        "private runtime-authority candidate initializer must have exactly one production caller, HostRoleRuntime::initialize; found "
        + (", ".join(caller.location for caller, _ in candidate_calls) or "none"),
    )
    for initializer in (authority_candidate_initializer, unqualified_storage_initializer):
        reached = {
            call.name
            for call in initializer.calls()
            if call.name
            in {
                bare.name,
                session.name,
                classification_bare.name,
                classification_session.name,
                cardinality_bare.name,
                cardinality_session.name,
                branded_scope.name,
                branded_constructor.name,
            }
        }
        require(
            not reached,
            f"initializer {initializer.qualified_name} directly reaches authority establishment: "
            + ", ".join(sorted(reached)),
        )
    raw_store_initializers = [
        function
        for function in functions
        if function.owner == "Store" and function.name == "initialize"
    ]
    require(
        len(raw_store_initializers) <= 1,
        "Store exposes multiple raw initialize definitions",
    )
    if raw_store_initializers:
        raw_initializer = raw_store_initializers[0]
        compact_attributes = {
            attribute.replace(" ", "") for attribute in raw_initializer.attributes
        }
        require(
            raw_initializer.visibility == "pub"
            and 'cfg(feature="test-support")' in compact_attributes,
            "Store::initialize may exist only as an explicit test-support feature alias",
        )
        require(
            len(raw_initializer.calls(unqualified_storage_initializer.name)) == 1
            and not any(
                raw_initializer.calls(name)
                for name in (
                    bare.name,
                    session.name,
                    classification_bare.name,
                    classification_session.name,
                    cardinality_bare.name,
                    cardinality_session.name,
                    branded_scope.name,
                    branded_constructor.name,
                    authority_candidate_initializer.name,
                )
            ),
            "feature-only Store::initialize is not a one-hop storage-only alias",
        )

    protected_definitions = [
        function
        for function in functions
        if function.name
        in (
            bare.name,
            session.name,
            classification_bare.name,
            classification_session.name,
            cardinality_bare.name,
            cardinality_session.name,
        )
    ]
    expected_definitions = {
        function_identity(bare),
        function_identity(session),
        function_identity(classification_bare),
        function_identity(classification_session),
        function_identity(cardinality_bare),
        function_identity(cardinality_session),
    }
    require(
        {function_identity(function) for function in protected_definitions}
        == expected_definitions,
        "establishment name has an alternate function/trait definition: "
        + ", ".join(function.location for function in protected_definitions),
    )
    bare_receiver = settings["bare_helper_receiver"]
    bare_calls = [
        (caller, call)
        for caller, call in direct_callers(functions, bare.name)
        if call.receiver == bare_receiver or call.path.startswith(f"{bare.owner}::")
    ]
    require(
        len(bare_calls) == 1
        and function_identity(bare_calls[0][0]) == function_identity(session),
        "bare Store helper must have exactly one direct production caller, the typed session method; found "
        + (", ".join(caller.location for caller, _ in bare_calls) or "none"),
    )
    classification_bare_calls = [
        (caller, call)
        for caller, call in direct_callers(functions, classification_bare.name)
        if call.receiver == bare_receiver
        or call.path.startswith(f"{classification_bare.owner}::")
    ]
    require(
        len(classification_bare_calls) == 1
        and function_identity(classification_bare_calls[0][0])
        == function_identity(classification_session),
        "bare migration classification helper must have exactly one production caller, the typed session method; found "
        + (
            ", ".join(caller.location for caller, _ in classification_bare_calls)
            or "none"
        ),
    )
    cardinality_bare_calls = [
        (caller, call)
        for caller, call in direct_callers(functions, cardinality_bare.name)
        if call.receiver == bare_receiver
        or call.path.startswith(f"{cardinality_bare.owner}::")
    ]
    require(
        len(cardinality_bare_calls) == 1
        and function_identity(cardinality_bare_calls[0][0])
        == function_identity(cardinality_session),
        "bare cardinality classification helper must have exactly one production caller, the typed session method; found "
        + (
            ", ".join(caller.location for caller, _ in cardinality_bare_calls)
            or "none"
        ),
    )
    compile_confined_calls = [
        (function, call)
        for source in sources
        for function in source.functions
        if function.cfg_test or source.path.as_posix() in compile_confined_paths
        for call in function.calls(bare.name)
    ]
    compile_confined_calls.extend(
        (function, call)
        for source in test_sources
        for function in source.functions
        for call in function.calls(bare.name)
    )

    allowed_establishment_callers = [
        selector_function(
            functions, selector, f"allowed_establishment_callers[{index}]"
        )
        for index, selector in enumerate(settings["allowed_establishment_callers"])
    ]
    allowed_establishment_identities = {
        function_identity(function) for function in allowed_establishment_callers
    }
    session_calls = [
        (caller, call)
        for caller, call in direct_callers(functions, session.name)
        if function_identity(caller) != function_identity(session)
    ]
    require(
        {function_identity(caller) for caller, _ in session_calls}
        == allowed_establishment_identities,
        "typed session establishment callers differ from named initialize/migration allowlist: "
        + (", ".join(caller.location for caller, _ in session_calls) or "none"),
    )
    for caller in allowed_establishment_callers:
        require(
            sum(
                function_identity(found) == function_identity(caller)
                for found, _ in session_calls
            )
            == 1,
            f"named establishment caller {caller.qualified_name} must call the typed API exactly once",
        )
    allowed_scope_callers = [
        selector_function(
            functions, selector, f"allowed_branded_scope_callers[{index}]"
        )
        for index, selector in enumerate(settings["allowed_branded_scope_callers"])
    ]
    allowed_scope_identities = {
        function_identity(function) for function in allowed_scope_callers
    }
    scope_calls = direct_callers(functions, branded_scope.name)
    require(
        {function_identity(caller) for caller, _ in scope_calls}
        == allowed_scope_identities,
        "Store-owned HRTB scope callers differ from named initialize/migrate/classify allowlist: "
        + (", ".join(caller.location for caller, _ in scope_calls) or "none"),
    )
    for caller in allowed_scope_callers:
        require(
            sum(
                function_identity(found) == function_identity(caller)
                for found, _ in scope_calls
            )
            == 1,
            f"named authority caller {caller.qualified_name} must enter the Store-owned HRTB scope exactly once",
        )
    allowed_classification_callers = [
        selector_function(
            functions, selector, f"allowed_classification_callers[{index}]"
        )
        for index, selector in enumerate(settings["allowed_classification_callers"])
    ]
    allowed_classification_identities = {
        function_identity(function) for function in allowed_classification_callers
    }
    classification_calls = [
        (caller, call)
        for caller, call in direct_callers(functions, classification_session.name)
        if function_identity(caller) != function_identity(classification_session)
    ]
    require(
        {function_identity(caller) for caller, _ in classification_calls}
        == allowed_classification_identities,
        "typed migration classification callers differ from named classify allowlist: "
        + (", ".join(caller.location for caller, _ in classification_calls) or "none"),
    )
    for caller in allowed_classification_callers:
        require(
            sum(
                function_identity(found) == function_identity(caller)
                for found, _ in classification_calls
            )
            == 1,
            f"named classification caller {caller.qualified_name} must call the typed API exactly once",
        )
    allowed_cardinality_callers = [
        selector_function(
            functions,
            selector,
            f"allowed_cardinality_classification_callers[{index}]",
        )
        for index, selector in enumerate(
            settings["allowed_cardinality_classification_callers"]
        )
    ]
    allowed_cardinality_identities = {
        function_identity(function) for function in allowed_cardinality_callers
    }
    cardinality_calls = [
        (caller, call)
        for caller, call in direct_callers(functions, cardinality_session.name)
        if function_identity(caller) != function_identity(cardinality_session)
    ]
    require(
        {function_identity(caller) for caller, _ in cardinality_calls}
        == allowed_cardinality_identities,
        "typed cardinality classification callers differ from named classify allowlist: "
        + (", ".join(caller.location for caller, _ in cardinality_calls) or "none"),
    )
    for caller in allowed_cardinality_callers:
        require(
            sum(
                function_identity(found) == function_identity(caller)
                for found, _ in cardinality_calls
            )
            == 1,
            f"named cardinality caller {caller.qualified_name} must call the typed API exactly once",
        )

    evidence_type = settings["evidence_type"]
    evidence_definitions = [
        (source, index, token)
        for source in sources
        for index, token in enumerate(source.tokens[:-1])
        if token.value == "struct" and source.tokens[index + 1].value == evidence_type
    ]
    require(
        len(evidence_definitions) == 1,
        f"expected exactly one evidence type definition {evidence_type}; found {len(evidence_definitions)}",
    )
    definition_source, definition_index, _ = evidence_definitions[0]
    definition_depth = definition_source.depths[definition_index]
    definition_open = next(
        (
            index
            for index in range(definition_index + 2, len(definition_source.tokens))
            if definition_source.depths[index] == definition_depth
            and definition_source.tokens[index].value == "{"
        ),
        None,
    )
    require(
        definition_open is not None, f"{evidence_type} has no structural field body"
    )
    assert definition_open is not None
    definition_close = definition_source.pairs[definition_open]
    public_fields = [
        token
        for index, token in enumerate(
            definition_source.tokens[definition_open + 1 : definition_close],
            definition_open + 1,
        )
        if token.value == "pub"
        and definition_source.depths[index] == definition_depth + 1
        and not (
            index + 1 < definition_close
            and definition_source.tokens[index + 1].value == "("
        )
    ]
    require(
        not public_fields,
        f"{evidence_type} has public field visibility at {definition_source.path}:{public_fields[0].line}"
        if public_fields
        else f"{evidence_type} fields are ambiguous",
    )
    verifiers = [
        selector_function(functions, selector, f"bounded_evidence_verifiers[{index}]")
        for index, selector in enumerate(settings["bounded_evidence_verifiers"])
    ]
    verifier_identities = {function_identity(function) for function in verifiers}
    product_identities = {function_identity(function) for function in functions}
    construction_sites = [
        site
        for site in evidence_construction_sites(sources, evidence_type)
        if site[1] is None or function_identity(site[1]) in product_identities
    ]
    require(
        construction_sites, f"no production construction of {evidence_type} was found"
    )
    require(
        all(
            function is not None and function_identity(function) in verifier_identities
            for _, function, _, _ in construction_sites
        ),
        f"{evidence_type} construction escapes bounded verifier: "
        + ", ".join(
            f"{source.path}:{line} {kind}"
            for source, _, line, kind in construction_sites
        ),
    )
    evidence_constructors = [
        function
        for function in functions
        if function.owner == evidence_type
        and function.name
        in ("new", "from", "from_parts", "build", "default", "unchecked")
    ]
    require(
        evidence_constructors,
        f"{evidence_type} has no structurally visible constructor",
    )
    for constructor in evidence_constructors:
        require(
            constructor.name != "unchecked" and constructor.visibility != "pub",
            f"{evidence_type} exposes forbidden constructor {constructor.qualified_name}",
        )
        constructor_callers = [
            caller
            for caller, call in direct_callers(functions, constructor.name)
            if call.path == f"{evidence_type}::{constructor.name}"
        ]
        require(
            constructor_callers
            and all(
                function_identity(caller) in verifier_identities
                for caller in constructor_callers
            ),
            f"{constructor.qualified_name} callers escape bounded verification: "
            + (", ".join(caller.location for caller in constructor_callers) or "none"),
        )
    for forbidden_trait in ("Clone", "Copy", "Default", "Serialize", "Deserialize"):
        require(
            not any(
                scope.owner == evidence_type and scope.trait_name == forbidden_trait
                for source in sources
                for scope in source.impl_scopes
            ),
            f"{evidence_type} implements forbidden trait {forbidden_trait}",
        )
    definition_attributes = definition_source.item_attributes(definition_index)
    for forbidden_trait in ("Clone", "Copy", "Default", "Serialize", "Deserialize"):
        require(
            not any(
                forbidden_trait in attribute for attribute in definition_attributes
            ),
            f"{evidence_type} derives forbidden trait {forbidden_trait}",
        )
    additional_sealed_verifiers: list[Function] = []
    additional_sealed_types: set[str] = set()
    for index, sealed in enumerate(settings["additional_sealed_evidence"]):
        require(
            isinstance(sealed, dict)
            and isinstance(sealed.get("type"), str)
            and isinstance(sealed.get("verifier"), dict),
            f"additional_sealed_evidence[{index}] is malformed",
        )
        additional_verifier = selector_function(
            functions,
            sealed["verifier"],
            f"additional_sealed_evidence[{index}].verifier",
        )
        require_additional_sealed_evidence(
            sources=sources,
            functions=functions,
            evidence_type=sealed["type"],
            verifier=additional_verifier,
            macro_generated=sealed.get("macro_generated", False),
        )
        additional_sealed_verifiers.append(additional_verifier)
        additional_sealed_types.add(sealed["type"])

    forging_identifiers = set(settings["forbidden_authority_forging_identifiers"])
    authority_prefixes = tuple(settings["authority_source_prefixes"])
    forging_sites = [
        f"{function.location} ({token.value})"
        for function in functions
        if function.source.path.as_posix().startswith(authority_prefixes)
        for token in function.item_tokens
        if token.value in forging_identifiers
    ]
    require(
        not forging_sites,
        "authority path contains unsafe/generic evidence-forging primitives: "
        + ", ".join(forging_sites),
    )

    family_helpers = [
        selector_function(
            functions, selector, f"authority_family_insert_helpers[{index}]"
        )
        for index, selector in enumerate(settings["authority_family_insert_helpers"])
    ]
    typed_family_methods = [
        selector_function(functions, selector, f"typed_family_session_methods[{index}]")
        for index, selector in enumerate(settings["typed_family_session_methods"])
    ]
    typed_family_identities = {
        function_identity(function) for function in typed_family_methods
    }
    reverse_edges = structural_reverse_edges(
        functions,
        protected_override=(bare, session, bare_receiver),
    )
    storage_only_identities = {function_identity(unqualified_storage_initializer)} | {
        function_identity(function) for function in raw_store_initializers
    }
    for protected_target in (
        bare,
        classification_bare,
        cardinality_bare,
        branded_scope,
        *family_helpers,
    ):
        protected_reachers = structural_reverse_reachable(
            (protected_target,), reverse_edges
        )
        storage_reachers = [
            function
            for function in protected_reachers
            if function_identity(function) in storage_only_identities
        ]
        require(
            not storage_reachers,
            f"storage-only initialization transitively reaches {protected_target.qualified_name}: "
            + ", ".join(function.location for function in storage_reachers),
        )
    for helper in family_helpers:
        require(
            helper.visibility in ("private", "pub(crate)"),
            f"authority family insert helper is externally public: {helper.location}",
        )
        reached = structural_reverse_reachable((helper,), reverse_edges)
        require(
            any(
                function_identity(function) in typed_family_identities
                for function in reached
            ),
            f"authority family insert {helper.qualified_name} is not reachable through a typed session path",
        )
        alternate_roots = {
            function_identity(function): function
            for function in reached
            if function.visibility in ("pub", "pub(crate)")
            and function_identity(function) not in typed_family_identities
            and function_identity(function) != function_identity(bare)
        }
        require(
            not alternate_roots,
            f"authority family insert {helper.qualified_name} has alternate public/crate roots: "
            + ", ".join(function.location for function in alternate_roots.values()),
        )

    for index, selector in enumerate(settings["cfg_test_direct_helpers"]):
        matches = [
            function
            for source in sources
            for function in source.functions
            if function.source.path.as_posix() == selector["path"]
            and function.owner == selector.get("owner")
            and function.name == selector["name"]
        ]
        require(
            len(matches) == 1,
            f"cfg_test_direct_helpers[{index}] is absent or ambiguous",
        )
        require(
            matches[0].cfg_test and matches[0].visibility != "pub",
            f"direct test helper {matches[0].qualified_name} is not compile-confined",
        )

    reached = structural_reverse_reachable((bare,), reverse_edges)
    allowed_reached = expected_definitions | allowed_establishment_identities
    forbidden_fragments = settings["forbidden_reachability_name_fragments"]
    offenders = [
        function
        for function in reached
        if function_identity(function) not in allowed_reached
        and any(fragment in function.name.lower() for fragment in forbidden_fragments)
    ]
    require(
        not offenders,
        "open/restart/recovery/validation/repair/backup/schema/diagnostic path reaches establishment: "
        + ", ".join(function.location for function in offenders),
    )

    verify_symbol_is_direct_only(
        sources,
        functions,
        bare.name,
        compile_confined_paths,
    )
    verify_symbol_is_direct_only(
        sources,
        functions,
        session.name,
        compile_confined_paths,
    )
    verify_symbol_is_direct_only(
        sources,
        functions,
        classification_bare.name,
        compile_confined_paths,
    )
    verify_symbol_is_direct_only(
        sources,
        functions,
        classification_session.name,
        compile_confined_paths,
    )
    verify_symbol_is_direct_only(
        sources,
        functions,
        cardinality_bare.name,
        compile_confined_paths,
    )
    verify_symbol_is_direct_only(
        sources,
        functions,
        cardinality_session.name,
        compile_confined_paths,
    )
    verify_symbol_is_direct_only(
        sources,
        functions,
        branded_constructor.name,
        compile_confined_paths,
    )
    verify_symbol_is_direct_only(
        sources,
        functions,
        branded_scope.name,
        compile_confined_paths,
    )
    for source in sources:
        for export in source.reexports:
            leaked = sorted(
                set(export.names)
                & {
                    bare.name,
                    classification_bare.name,
                    cardinality_bare.name,
                    branded_constructor.name,
                    branded_scope.name,
                    authority_candidate_initializer.name,
                }
            )
            require(
                not leaked,
                f"private authority plumbing is publicly re-exported at {export.location}: "
                + ", ".join(leaked),
            )
    for protected in (
        bare,
        session,
        classification_bare,
        classification_session,
        cardinality_bare,
        cardinality_session,
        branded_constructor,
        branded_scope,
        brand_generator,
        authority_candidate_initializer,
        *verifiers,
        *additional_sealed_verifiers,
        *family_helpers,
    ):
        signature = protected.signature_code
        require(
            "extern" not in signature,
            f"protected function has an FFI ABI: {protected.location}",
        )
        require(
            not any(
                "no_mangle" in attribute or "export_name" in attribute
                for attribute in protected.attributes
            ),
            f"protected function is exported through FFI: {protected.location}",
        )

    forbidden_feature_fragments = settings["forbidden_product_features"]
    protected_names = {
        bare.name,
        session.name,
        classification_bare.name,
        classification_session.name,
        cardinality_bare.name,
        cardinality_session.name,
        branded_constructor.name,
        branded_scope.name,
        evidence_type,
        *additional_sealed_types,
        *(helper.name for helper in family_helpers),
    }
    for package in packages:
        for feature, members in package.features.items():
            feature_surface = " ".join([feature, *members]).lower()
            if any(name.lower() in feature_surface for name in protected_names):
                require(
                    not any(
                        fragment in feature_surface
                        for fragment in forbidden_feature_fragments
                    ),
                    f"{package.name} feature {feature} exposes an alternate establishment surface",
                )

    require_test_support_confinement(
        sources,
        functions,
        {
            bare.name,
            session.name,
            classification_bare.name,
            classification_session.name,
            cardinality_bare.name,
            cardinality_session.name,
            branded_constructor.name,
            branded_scope.name,
            authority_candidate_initializer.name,
            *(helper.name for helper in family_helpers),
        },
        {
            "VerificationBrand",
            "StoreWriterSession",
            evidence_type,
            *additional_sealed_types,
        },
    )

    direction = settings["dependency_direction"]
    packages_by_name = {package.name: package for package in packages}
    for package_key, forbidden_key in (
        ("store_package", "store_forbidden_dependencies"),
        ("evidence_package", "evidence_forbidden_dependencies"),
    ):
        package_name = direction[package_key]
        require(
            package_name in packages_by_name,
            f"configured dependency package is absent: {package_name}",
        )
        dependencies = package_dependencies(packages_by_name[package_name])
        for forbidden in direction[forbidden_key]:
            require(
                forbidden not in dependencies,
                f"dependency direction violation: {package_name} -> {forbidden}",
            )
    allowed_site_inventory = {
        "bare_establishment": bare.location,
        "bare_establishment_caller": session.location,
        "establishment_callers": sorted(
            function.location for function in allowed_establishment_callers
        ),
        "bare_migration_classification": classification_bare.location,
        "bare_migration_classification_caller": classification_session.location,
        "migration_classification_callers": sorted(
            function.location for function in allowed_classification_callers
        ),
        "bare_cardinality_classification": cardinality_bare.location,
        "bare_cardinality_classification_caller": cardinality_session.location,
        "cardinality_classification_callers": sorted(
            function.location for function in allowed_cardinality_callers
        ),
        "branded_scope": branded_scope.location,
        "branded_scope_callers": sorted(
            function.location for function in allowed_scope_callers
        ),
        "authority_candidate_initializer": authority_candidate_initializer.location,
        "sealed_verifiers": sorted(
            function.location for function in (*verifiers, *additional_sealed_verifiers)
        ),
    }
    inventory_json = json.dumps(
        allowed_site_inventory, sort_keys=True, separators=(",", ":")
    )
    inventory_digest = hashlib.sha256(inventory_json.encode("utf-8")).hexdigest()
    return (
        f"ACTIVE/PASS ({len(compile_confined_calls)} compile-confined direct test call(s); "
        f"allowed-site-inventory-sha256={inventory_digest}; "
        f"inventory={inventory_json})"
    )


def main() -> int:
    config = load_config()
    verify_resolver_pin(config)
    packages = workspace_packages(ROOT)
    require_no_product_test_support(packages)
    require_acyclic_product_dependencies(packages)
    sources = production_sources(ROOT)
    compile_confined_paths = compile_confined_module_paths(sources)
    sources_by_path = {source.path.as_posix(): source for source in sources}
    require(
        len(sources_by_path) == len(sources),
        "production Rust source inventory contains duplicate paths",
    )
    packages_by_name = {package.name: package for package in packages}
    verify_r0b(config, sources_by_path, packages_by_name)
    functions = production_functions(
        sources,
        compile_confined_paths=compile_confined_paths,
    )
    active_requested = (
        config["gen4"].get("enforcement") == "active"
        or os.environ.get("NQ_PROOF_FORCE_GEN4_ACTIVE") == "1"
    )
    test_sources = cargo_test_sources(ROOT, packages) if active_requested else ()
    gen4_status = verify_gen4(
        config,
        sources,
        test_sources,
        functions,
        packages,
        compile_confined_paths,
    )
    print(
        f"R0b Store-owned dependency/source callgraph: PASS "
        f"({len(sources)} Cargo product-source files scanned; "
        f"{len(compile_confined_paths)} external test module(s) compile-confined; Gen4 {gen4_status})"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, ScanError, KeyError, TypeError, ValueError) as error:
        print(
            f"R0b Store-owned dependency/source callgraph: FAIL: {error}",
            file=sys.stderr,
        )
        sys.exit(1)
