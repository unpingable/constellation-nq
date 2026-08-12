#!/usr/bin/env python3
"""Machine-checkable Store/StoreWriterSession mutation-surface census."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable, Sequence

sys.dont_write_bytecode = True

from rust_source_scan import (  # noqa: E402
    Function,
    RustSource,
    ScanError,
    compact_tokens,
    compile_confined_module_paths,
)


ROOT = Path(
    os.environ.get("NQ_PROOF_SOURCE_ROOT", Path(__file__).resolve().parents[3])
).resolve()
CONFIG_PATH = Path(__file__).with_name("mutator_census_allowlist.json")


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
    require(
        config.get("schema_version") == 1, "unsupported mutator-census allowlist schema"
    )
    return config


def source_inventory(config: dict) -> tuple[RustSource, ...]:
    paths: set[Path] = set()
    for relative in config["store_sources"]:
        directory = ROOT / relative
        require(
            directory.is_dir(),
            f"configured Store source directory is absent: {relative}",
        )
        paths.update(directory.rglob("*.rs"))
    require(paths, "Store source inventory is empty")
    return tuple(RustSource(path, root=ROOT) for path in sorted(paths))


def product_functions(
    sources: Iterable[RustSource], compile_confined_paths: set[str]
) -> list[Function]:
    return [
        function
        for source in sources
        for function in source.functions
        if not function.cfg_test
        and source.path.as_posix() not in compile_confined_paths
    ]


def identity(function: Function) -> tuple[str, str | None, str]:
    return function.source.path.as_posix(), function.owner, function.name


def require_unique(
    functions: Iterable[Function],
    name: str,
    *,
    owner: str | None = None,
    label: str = "function",
) -> Function:
    found = [
        function
        for function in functions
        if function.name == name and (owner is None or function.owner == owner)
    ]
    require(
        len(found) == 1,
        f"{label} {owner + '::' if owner else ''}{name} is absent or ambiguous: "
        + (", ".join(function.location for function in found) or "none"),
    )
    return found[0]


def duplicates(values: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    repeated: set[str] = set()
    for value in values:
        if value in seen:
            repeated.add(value)
        seen.add(value)
    return repeated


def literal_sql_prefixes(function: Function, prefixes: Sequence[str]) -> list[str]:
    pattern = re.compile(
        r"\b(" + "|".join(re.escape(prefix) for prefix in prefixes) + r")\b",
        re.IGNORECASE,
    )
    found: set[str] = set()
    for literal in function.string_literals:
        found.update(match.group(1).upper() for match in pattern.finditer(literal))
    return sorted(found)


def mutation_lexemes(function: Function, config: dict) -> dict[str, list[str]]:
    configured_calls = set(config["mutation_lexemes"]["calls"])
    calls = sorted(
        {call.name for call in function.calls() if call.name in configured_calls}
    )
    sql = literal_sql_prefixes(function, config["mutation_lexemes"]["sql_prefixes"])
    return {"calls": calls, "sql": sql}


def validate_public_store(
    functions: Sequence[Function], config: dict
) -> tuple[dict[str, list[str]], dict[str, dict[str, list[str]]]]:
    settings = config["public_store"]
    public = [
        function
        for function in functions
        if function.owner == "Store" and function.visibility == "pub"
    ]
    repeated = duplicates(function.name for function in public)
    require(
        not repeated, f"public Store method names are ambiguous: {sorted(repeated)}"
    )
    by_name = {function.name: function for function in public}
    scoped_facades = settings.get("scoped_store_facades", [])
    require(
        isinstance(scoped_facades, list)
        and all(
            isinstance(entry, dict)
            and set(entry) == {"path", "owner", "name", "sole_store_factory"}
            and all(isinstance(value, str) for value in entry.values())
            for entry in scoped_facades
        ),
        "public_store.scoped_store_facades must contain exact facade records",
    )
    scoped_identities = {
        (entry["path"], entry["owner"], entry["name"]): entry
        for entry in scoped_facades
    }
    require(
        len(scoped_identities) == len(scoped_facades),
        "public_store.scoped_store_facades repeats an identity",
    )
    observed_scoped_facades: set[tuple[str, str | None, str]] = set()
    alternate_store_mutators = []
    for function in functions:
        if function.visibility not in ("pub", "pub(crate)") or function.owner in (
            "Store",
            "StoreWriterSession",
        ):
            continue
        signature = compact_tokens(
            function.source.tokens[function.fn_token : function.body_open_token]
        )
        # Match the two legacy mutation owners exactly.  A type such as
        # `StoreC2SnapshotActorV1` must not be mistaken for `Store` merely
        # because its name begins with the same token text; that actor has a
        # separate, fail-closed census below.
        if re.search(r"&mut(?:Store|StoreWriterSession)(?![A-Za-z0-9_])", signature):
            function_identity = identity(function)
            if function_identity in scoped_identities:
                entry = scoped_identities[function_identity]
                factory = entry["sole_store_factory"]
                require(
                    len(function.calls(factory)) == 1,
                    f"scoped Store facade must call its sole factory exactly once: {function.location}",
                )
                lexemes = mutation_lexemes(function, config)
                require(
                    not lexemes["calls"] and not lexemes["sql"],
                    f"scoped Store facade contains a direct mutation: {function.location}: {lexemes}",
                )
                observed_scoped_facades.add(function_identity)
                continue
            alternate_store_mutators.append(function)
    require(
        observed_scoped_facades == set(scoped_identities),
        "configured scoped Store facade is absent or does not borrow Store mutably: "
        + repr(sorted(set(scoped_identities) - observed_scoped_facades)),
    )
    require(
        not alternate_store_mutators,
        "public/crate-visible free or trait Store mutation surface bypasses the session census: "
        + ", ".join(function.location for function in alternate_store_mutators),
    )

    required_classes = ("lifecycle", "read_only", "session_factory", "maintenance")
    optional_classes = (
        "optional_read_only",
        "optional_session_factory",
        "optional_maintenance",
    )
    configured: list[str] = []
    for category in (*required_classes, *optional_classes):
        names = settings[category]
        require(
            isinstance(names, list) and all(isinstance(name, str) for name in names),
            f"public_store.{category} must be a string list",
        )
        configured.extend(names)
    repeated = duplicates(configured)
    require(
        not repeated,
        f"public Store allowlist classifies names more than once: {sorted(repeated)}",
    )
    for category in required_classes:
        missing = set(settings[category]) - set(by_name)
        require(
            not missing,
            f"required public Store {category} methods are absent: {sorted(missing)}",
        )
    unknown = set(by_name) - set(configured)
    require(
        not unknown,
        "unclassified public Store mutation surface (update allowlist explicitly): "
        + ", ".join(sorted(unknown)),
    )

    mutable_receiver_read_only = set(settings["mutable_receiver_read_only"])
    require(
        mutable_receiver_read_only <= set(settings["read_only"]),
        "mutable_receiver_read_only must be a subset of read_only",
    )
    mutation_targets = set(config["session"]["mutation_routes"])
    mutation_targets.update(config["session"]["optional_mutation_routes"])
    mutation_targets.update(config["session"]["refusal_only_routes"])
    mutation_targets.update(config["session"]["optional_legacy_routes"])
    for name in settings["read_only"] + settings["optional_read_only"]:
        function = by_name.get(name)
        if function is None:
            continue
        signature = compact_tokens(
            function.source.tokens[function.fn_token : function.body_open_token]
        )
        require(
            "&mutself" not in signature or name in mutable_receiver_read_only,
            f"read-only Store method unexpectedly takes &mut self: {function.location}",
        )
        direct_mutator_calls = sorted(
            {call.name for call in function.calls() if call.name in mutation_targets}
        )
        require(
            not direct_mutator_calls,
            f"read-only Store method {name} calls mutation routes {direct_mutator_calls}",
        )
        dangerous_sql = [
            prefix
            for prefix in literal_sql_prefixes(
                function, config["mutation_lexemes"]["sql_prefixes"]
            )
            if prefix
            in {"ALTER", "CREATE", "DELETE", "DROP", "INSERT", "REPLACE", "UPDATE"}
        ]
        require(
            not dangerous_sql,
            f"read-only Store method {name} contains write SQL lexemes {dangerous_sql}",
        )

    inventory = {
        "lifecycle": sorted(name for name in settings["lifecycle"] if name in by_name),
        "maintenance": sorted(
            name
            for name in settings["maintenance"] + settings["optional_maintenance"]
            if name in by_name
        ),
        "read_only": sorted(
            name
            for name in settings["read_only"] + settings["optional_read_only"]
            if name in by_name
        ),
        "session_factory": sorted(
            name
            for name in settings["session_factory"]
            + settings["optional_session_factory"]
            if name in by_name
        ),
    }
    lexemes = {
        name: mutation_lexemes(by_name[name], config) for name in sorted(by_name)
    }
    return inventory, lexemes


def validate_live_c2_actor(
    product: Sequence[Function], config: dict
) -> dict:
    """Census the Store-owned live-C2 transaction actor and its lock root.

    `StoreC2SnapshotActorV1` intentionally bypasses the ordinary
    `StoreWriterSession`: it retains one immediate transaction, Store
    snapshot, process correspondence, and maintenance lock for the whole C2
    operation.  This verifier therefore treats the actor as a second *closed*
    mutation owner, not as an unclassified session bypass.
    """

    settings = config["live_c2_actor"]
    source_path = settings["source"]
    owner = settings["owner"]
    methods = [
        function
        for function in product
        if function.source.path.as_posix() == source_path and function.owner == owner
    ]
    require(methods, f"live C2 actor is absent from {source_path}")
    repeated = duplicates(function.name for function in methods)
    require(not repeated, f"live C2 actor methods are ambiguous: {sorted(repeated)}")
    by_name = {function.name: function for function in methods}

    categories = (
        "read_only",
        "authority_constructors",
        "state_attachments",
        "mutation_roots",
        "private_helpers",
    )
    configured = [name for category in categories for name in settings[category]]
    require(
        not duplicates(configured),
        "live C2 actor method is classified more than once: "
        + str(sorted(duplicates(configured))),
    )
    require(
        set(configured) == set(by_name),
        "live C2 actor census differs from the closed classification; "
        f"missing={sorted(set(by_name) - set(configured))}, "
        f"stale={sorted(set(configured) - set(by_name))}",
    )

    for name in settings["read_only"] + settings["authority_constructors"]:
        function = by_name[name]
        signature = compact_tokens(
            function.source.tokens[function.fn_token : function.body_open_token]
        )
        require(
            "&mutself" not in signature,
            f"live C2 read/authority method unexpectedly mutates self: {function.location}",
        )
        lexemes = mutation_lexemes(function, config)
        dangerous_sql = [prefix for prefix in lexemes["sql"] if prefix != "PRAGMA"]
        require(
            not lexemes["calls"] and not dangerous_sql,
            f"live C2 read/authority method contains mutation lexemes: "
            f"{function.location}: {lexemes}",
        )

    direct_actor_gates = (
        "verify_same_snapshot",
        "verify_authority_snapshot",
        "verify_authority_lineage",
        "verify_live",
        "with_permitted_effect",
        "append_prepared_signer_effect",
        "append_verified_governed_carrier_effect",
        "install_c2_live_with_observer_v1",
    )
    delegated_mutation_roots = settings.get("delegated_mutation_roots", {})
    require(
        isinstance(delegated_mutation_roots, dict)
        and set(delegated_mutation_roots) <= set(settings["mutation_roots"]),
        "live C2 delegated mutation roots must be an exact mutation-root subset",
    )
    for name, required_calls in delegated_mutation_roots.items():
        require(
            isinstance(required_calls, list)
            and required_calls
            and all(isinstance(call, str) for call in required_calls),
            f"live C2 delegated mutation root {name} must have a nonempty call list",
        )

    for name in settings["state_attachments"] + settings["mutation_roots"]:
        function = by_name[name]
        signature = compact_tokens(
            function.source.tokens[function.fn_token : function.body_open_token]
        )
        require(
            "&mutself" in signature,
            f"live C2 mutation root lacks exclusive actor access: {function.location}",
        )

    for name in settings["state_attachments"]:
        function = by_name[name]
        require(
            any(function.calls(gate) for gate in direct_actor_gates),
            f"live C2 state attachment omits a direct same-snapshot gate: {function.location}",
        )

    mutation_names = set(settings["mutation_roots"])

    def mutation_reaches_gate(name: str, visiting: frozenset[str]) -> bool:
        if name in visiting:
            return False
        function = by_name[name]
        if any(function.calls(gate) for gate in direct_actor_gates):
            return True
        required_calls = delegated_mutation_roots.get(name)
        if required_calls is not None:
            calls = [function.calls(call) for call in required_calls]
            require(
                all(len(found) == 1 for found in calls),
                f"live C2 delegated mutation root {function.location} changed its exact call census",
            )
            require(
                [found[0].start for found in calls]
                == sorted(found[0].start for found in calls),
                f"live C2 delegated mutation root {function.location} reordered verification/effect calls",
            )
            return True
        next_visiting = visiting | {name}
        return any(
            function.calls(callee)
            and mutation_reaches_gate(callee, next_visiting)
            for callee in mutation_names
        )

    for name in settings["mutation_roots"]:
        function = by_name[name]
        require(
            mutation_reaches_gate(name, frozenset()),
            f"live C2 mutation root omits a direct or exact delegated same-snapshot/effect gate: {function.location}",
        )

    for name in settings["private_helpers"]:
        require(
            by_name[name].visibility == "private",
            f"live C2 actor helper is externally reachable: {by_name[name].location}",
        )

    forbidden_traits = {"Clone", "Copy", "Default", "Serialize", "Deserialize"}
    actor_source = methods[0].source
    actor_traits = sorted(
        scope.trait_name
        for scope in actor_source.impl_scopes
        if scope.owner == owner and scope.trait_name in forbidden_traits
    )
    require(not actor_traits, f"live C2 actor implements forbidden traits: {actor_traits}")

    factory_spec = settings["factory"]
    factory = require_unique(
        product,
        factory_spec["name"],
        owner=factory_spec["owner"],
        label="live C2 Store factory",
    )
    require(
        factory.source.path.as_posix() == source_path and factory.visibility == "private",
        "live C2 actor factory is not private to its Store owner",
    )
    factory_signature = compact_tokens(
        factory.source.tokens[factory.fn_token : factory.body_open_token]
    )
    require(
        "&mutself" in factory_signature
        and "for<'operation,'snapshot>FnOnce(" in factory_signature
        and "&'operationmutStoreC2SnapshotActorV1<'snapshot>" in factory_signature,
        "live C2 Store factory does not retain exclusive Store access in a fresh HRTB scope",
    )
    require(
        len(factory.calls("acquire_maintenance_locks")) == 1
        and len(factory.calls("transaction_with_behavior")) == 1
        and len(factory.calls("commit")) == 1,
        "live C2 Store factory must acquire one maintenance lock, retain one transaction, and commit once",
    )
    actor_literals = [
        function
        for function in product
        if f"{owner}{{" in compact_tokens(function.item_tokens)
    ]
    require(
        len(actor_literals) == 1 and identity(actor_literals[0]) == identity(factory),
        "live C2 actor has a constructor outside its sole Store-owned factory: "
        + ", ".join(function.location for function in actor_literals),
    )
    commit_callers = [
        function for function in product if function.calls("commit") and function.owner == "Store"
    ]
    require(
        any(identity(function) == identity(factory) for function in commit_callers),
        "live C2 actor factory no longer closes through actor commit",
    )

    delegate_specs = settings["actor_delegates"]
    delegates: list[Function] = []
    for selector in delegate_specs:
        matches = [
            function
            for function in product
            if function.source.path.as_posix() == selector["source"]
            and function.owner == selector.get("owner")
            and function.name == selector["name"]
        ]
        require(
            len(matches) == 1,
            f"live C2 actor delegate is absent or ambiguous: {selector}",
        )
        delegates.append(matches[0])
    actual_delegates = []
    actor_borrow = f"&mut{owner}"
    for function in product:
        if function.owner in (owner, "Store"):
            continue
        signature = compact_tokens(
            function.source.tokens[function.fn_token : function.body_open_token]
        )
        if actor_borrow in signature:
            actual_delegates.append(function)
    require(
        {identity(function) for function in actual_delegates}
        == {identity(function) for function in delegates},
        "live C2 actor delegate census changed: "
        + ", ".join(function.location for function in actual_delegates),
    )

    return {
        "actor": owner,
        "factory": factory.qualified_name,
        "factory_lock": "acquire_maintenance_locks",
        "read_only": sorted(settings["read_only"]),
        "authority_constructors": sorted(settings["authority_constructors"]),
        "state_attachments": sorted(settings["state_attachments"]),
        "mutation_roots": sorted(settings["mutation_roots"]),
        "private_helpers": sorted(settings["private_helpers"]),
        "actor_delegates": sorted(function.qualified_name for function in delegates),
    }


def validate_session_construction(
    all_functions: Sequence[Function], product: Sequence[Function], config: dict
) -> dict:
    settings = config["session"]
    owner = settings["owner"]
    constructor = require_unique(
        product, settings["constructor"], owner=owner, label="session constructor"
    )
    require(
        constructor.visibility == "pub(crate)",
        "StoreWriterSession constructor must remain crate-private",
    )
    delegate_calls = constructor.calls("begin_with_brand")
    gate = constructor
    if delegate_calls:
        require(len(delegate_calls) == 1, "session constructor delegates ambiguously")
        gate = require_unique(
            product,
            "begin_with_brand",
            owner=owner,
            label="branded session constructor",
        )
        require(
            gate.visibility == "private",
            "branded session constructor is externally reachable",
        )
    # Gen5 keeps the qualified Gen4 path-keyed gate under an explicit legacy
    # name so the C2 ordinary path can use the retained lock-inode registry
    # without conflating the two identities.  The construction law remains
    # unchanged: exact path identity, fence load, then non-reentrant lock.
    require(
        gate.calls("gen4_path_lock_state")
        and gate.calls("load")
        and gate.calls("try_lock"),
        "session construction omits path identity, fence load, or non-reentrant lock",
    )
    require(
        gate.calls("load")[0].start < gate.calls("try_lock")[0].start,
        "session construction acquires the writer lock before checking the fence",
    )

    factories = [
        (function, call)
        for function in product
        for call in function.calls(constructor.name)
        if call.path == "StoreWriterSession::begin"
    ]
    require(
        len(factories) == 1
        and factories[0][0].owner == "Store"
        and factories[0][0].name == "begin_writer_session",
        "StoreWriterSession construction is not confined to Store::begin_writer_session",
    )

    branded_name = config["session"]["optional_branded_constructor"]
    branded_matches = [
        function
        for function in product
        if function.owner == owner and function.name == branded_name
    ]
    require(
        len(branded_matches) <= 1,
        f"branded session constructor {branded_name} is ambiguous",
    )
    branded_inventory = None
    if branded_matches:
        branded = branded_matches[0]
        require(
            branded.visibility == "pub(crate)"
            and len(branded.calls("begin_with_brand")) == 1,
            "branded authority session constructor is public or bypasses the common lock/fence gate",
        )
        branded_factory_name = config["session"]["optional_branded_factory"]
        branded_factories = [
            (function, call)
            for function in product
            for call in function.calls(branded.name)
            if call.path == f"StoreWriterSession::{branded.name}"
        ]
        require(
            len(branded_factories) == 1
            and branded_factories[0][0].owner == "Store"
            and branded_factories[0][0].name == branded_factory_name,
            "branded authority session construction escapes its named Store factory",
        )
        branded_factory = branded_factories[0][0]
        signature_end = branded_factory.body_open_token or branded_factory.end_token + 1
        signature = compact_tokens(
            branded_factory.source.tokens[branded_factory.start_token : signature_end]
        )
        expected_factory_visibility = config["session"].get(
            "optional_branded_factory_visibility", "pub"
        )
        require(
            branded_factory.visibility == expected_factory_visibility
            and "implfor<'id>FnOnce(" in signature
            and "&VerificationBrand<'id>" in signature
            and "&mutStoreWriterSession<'_,VerificationBrand<'id>>" in signature
            and signature.count("VerificationBrand<'id>") == 2
            and "'id" not in signature.split("(", 1)[0],
            "branded authority session factory has the wrong visibility or is not a "
            "Store-owned fresh HRTB scope",
        )
        require(
            len(branded_factory.calls("with_verification_brand")) == 1
            and len(branded_factory.calls(branded.name)) == 1,
            "Store-owned HRTB scope must mint one fresh brand and exactly one branded session",
        )
        alternate_public_brand_surfaces = [
            function
            for function in product
            if function.owner == "Store"
            and function.visibility == "pub"
            and "VerificationBrand" in function.signature_code
            and identity(function) != identity(branded_factory)
        ]
        require(
            not alternate_public_brand_surfaces,
            "another public Store API accepts or exposes VerificationBrand: "
            + ", ".join(
                function.location for function in alternate_public_brand_surfaces
            ),
        )
        branded_inventory = {
            "constructor": branded.qualified_name,
            "factory": branded_factory.qualified_name,
            "fresh_hrtb_scope": True,
        }

    forbidden_traits = {"Clone", "Copy", "Default", "Serialize", "Deserialize"}
    trait_impls = sorted(
        {
            scope.trait_name
            for function in all_functions
            for scope in function.source.impl_scopes
            if scope.owner == owner and scope.trait_name in forbidden_traits
        }
    )
    require(
        not trait_impls,
        f"StoreWriterSession implements forbidden traits: {trait_impls}",
    )
    return {
        "constructor": constructor.qualified_name,
        "gate": gate.qualified_name,
        "factory": factories[0][0].qualified_name,
        "fence_before_lock": True,
        "optional_branded": branded_inventory,
    }


def validate_route(
    route: Function,
    specification: dict,
    functions: Sequence[Function],
    fence: str,
    *,
    classification: str,
    config: dict,
) -> dict:
    calls = route.calls()
    require(calls, f"session route has no calls: {route.location}")
    require(
        calls[0].name == fence and len(route.calls(fence)) == 1,
        f"session route must begin with exactly one {fence}: {route.location}",
    )
    signature = compact_tokens(
        route.source.tokens[route.fn_token : route.body_open_token]
    )
    require(
        "&mutself" in signature,
        f"session mutation route lacks &mut self: {route.location}",
    )
    target_name = specification.get("target")
    target_owner = specification.get("target_owner")
    require(
        isinstance(target_name, str) and isinstance(target_owner, str),
        f"invalid route specification for {route.name}",
    )
    target_matches = [
        function
        for function in functions
        if function.name == target_name and function.owner == target_owner
    ]
    if not target_matches and isinstance(specification.get("legacy_target"), str):
        target_name = specification["legacy_target"]
        target_matches = [
            function
            for function in functions
            if function.name == target_name and function.owner == target_owner
        ]
    require(
        len(target_matches) == 1,
        f"session target {target_owner}::{target_name} is absent or ambiguous: "
        + (", ".join(function.location for function in target_matches) or "none"),
    )
    target_calls = route.calls(target_name)
    require(
        len(target_calls) == 1 and target_calls[0].start > calls[0].start,
        f"session route {route.name} must call {target_owner}::{target_name} exactly once after its fence",
    )
    target = target_matches[0]
    require(
        target.visibility in ("private", "pub(crate)"),
        f"session mutation target is publicly reachable: {target.location}",
    )
    if classification == "refusal_only":
        lexemes = mutation_lexemes(target, config)
        dangerous_sql = [prefix for prefix in lexemes["sql"] if prefix != "PRAGMA"]
        require(
            not lexemes["calls"] and not dangerous_sql,
            f"refusal-only target {target.qualified_name} now contains mutation lexemes {lexemes}",
        )
    return {
        "classification": classification,
        "fence_first": True,
        "method": route.name,
        "target": f"{target_owner}::{target_name}",
        "target_source": target.source.path.as_posix(),
    }


def validate_session_routes(
    sources: Sequence[RustSource], product: Sequence[Function], config: dict
) -> tuple[list[dict], dict, dict[str, list[str]]]:
    settings = config["session"]
    owner = settings["owner"]
    source_path = settings["source"]
    session_source = next(
        (source for source in sources if source.path.as_posix() == source_path), None
    )
    require(session_source is not None, f"session source is absent: {source_path}")
    product_methods = [
        function
        for function in product
        if function.owner == owner and function.visibility == "pub"
    ]
    repeated = duplicates(function.name for function in product_methods)
    require(not repeated, f"public session methods are ambiguous: {sorted(repeated)}")
    by_name = {function.name: function for function in product_methods}

    routes = settings["mutation_routes"]
    optional_mutation_routes = settings["optional_mutation_routes"]
    refusal_routes = settings["refusal_only_routes"]
    optional_routes = settings["optional_legacy_routes"]
    classified = (
        set(routes)
        | set(optional_mutation_routes)
        | set(refusal_routes)
        | set(optional_routes)
    )
    classified.update(settings["read_only"])
    classified.update(settings["lifecycle"])
    repeated = duplicates(
        [
            *routes,
            *optional_mutation_routes,
            *refusal_routes,
            *optional_routes,
            *settings["read_only"],
            *settings["lifecycle"],
        ]
    )
    require(
        not repeated,
        f"session methods have multiple classifications: {sorted(repeated)}",
    )
    missing = (
        set(routes)
        | set(refusal_routes)
        | set(settings["read_only"])
        | set(settings["lifecycle"])
    ) - set(by_name)
    require(
        not missing,
        f"required StoreWriterSession methods are absent: {sorted(missing)}",
    )
    unknown = set(by_name) - classified
    require(
        not unknown,
        "unclassified public StoreWriterSession mutation surface: "
        + ", ".join(sorted(unknown)),
    )

    inventory: list[dict] = []
    for name, specification in sorted(routes.items()):
        inventory.append(
            validate_route(
                by_name[name],
                specification,
                product,
                settings["fence"],
                classification="mutation",
                config=config,
            )
        )
    for name, specification in sorted(optional_mutation_routes.items()):
        if name not in by_name:
            continue
        inventory.append(
            validate_route(
                by_name[name],
                specification,
                product,
                settings["fence"],
                classification="mutation",
                config=config,
            )
        )
    for name, specification in sorted(refusal_routes.items()):
        inventory.append(
            validate_route(
                by_name[name],
                specification,
                product,
                settings["fence"],
                classification="refusal_only",
                config=config,
            )
        )

    legacy: dict[str, str] = {}
    for name, specification in sorted(optional_routes.items()):
        all_matches = session_source.find_functions(name, owner=owner)
        require(
            len(all_matches) <= 1, f"optional legacy session route {name} is ambiguous"
        )
        if not all_matches:
            legacy[name] = "absent"
            continue
        function = all_matches[0]
        if function.cfg_test:
            validate_route(
                function,
                specification,
                [candidate for source in sources for candidate in source.functions],
                settings["fence"],
                classification="test_only_legacy",
                config=config,
            )
            legacy[name] = "cfg(test)"
        else:
            inventory.append(
                validate_route(
                    function,
                    specification,
                    product,
                    settings["fence"],
                    classification="legacy_product",
                    config=config,
                )
            )
            legacy[name] = "production"

    target_callers: dict[tuple[str, str], set[tuple[str, str | None, str]]] = {}
    for route in inventory:
        target_owner, target_name = route["target"].split("::", 1)
        target_callers.setdefault((target_owner, target_name), set()).add(
            identity(by_name[route["method"]])
        )
    all_target_identities = {
        identity(function)
        for target_owner, target_name in target_callers
        for function in product
        if function.owner == target_owner and function.name == target_name
    }
    configured_internal_callers = settings["raw_target_internal_callers"]
    require(
        set(configured_internal_callers)
        <= {f"{owner}::{name}" for owner, name in target_callers},
        "raw_target_internal_callers names a target absent from the route census",
    )
    raw_target_census: dict[str, list[str]] = {}
    for (target_owner, target_name), allowed_callers in sorted(target_callers.items()):
        target_identities = {
            identity(function)
            for function in product
            if function.owner == target_owner and function.name == target_name
        }
        observed_callers = {
            identity(function)
            for function in product
            if function.calls(target_name)
            and identity(function) not in target_identities
        }
        internal_callers: set[tuple[str, str | None, str]] = set()
        for selector in configured_internal_callers.get(
            f"{target_owner}::{target_name}", []
        ):
            matches = [
                function
                for function in product
                if function.source.path.as_posix() == selector["path"]
                and function.owner == selector["owner"]
                and function.name == selector["name"]
            ]
            require(
                len(matches) == 1,
                f"configured internal raw-target caller is absent or ambiguous: {selector}",
            )
            internal_callers.add(identity(matches[0]))
        require(
            internal_callers <= observed_callers,
            f"stale internal-caller allowlist for {target_owner}::{target_name}",
        )
        escaped = (
            observed_callers
            - allowed_callers
            - all_target_identities
            - internal_callers
        )
        require(
            not escaped,
            f"raw mutation target {target_owner}::{target_name} callers escape its fenced session route: "
            + ", ".join(
                function.location
                for function in product
                if identity(function) in escaped
            ),
        )
        raw_target_census[f"{target_owner}::{target_name}"] = sorted(
            f"{path}:{owner + '::' if owner else ''}{name}"
            for path, owner, name in observed_callers
        )

    for name in settings["read_only"]:
        function = by_name[name]
        signature = compact_tokens(
            function.source.tokens[function.fn_token : function.body_open_token]
        )
        require(
            "&mutself" not in signature,
            f"session read-only method takes &mut self: {function.location}",
        )
        require(
            not function.calls(settings["fence"]),
            f"session read-only method consumes fence: {function.location}",
        )
    for name in settings["lifecycle"]:
        function = by_name[name]
        require(
            "self" in function.signature_code,
            f"session lifecycle method does not consume self: {function.location}",
        )

    for name in settings["test_only"]:
        found = session_source.find_functions(name, owner=owner)
        require(
            len(found) == 1, f"session test-only method {name} is absent or ambiguous"
        )
        require(
            found[0].cfg_test, f"session test-only method {name} is product-reachable"
        )

    fence_functions = session_source.find_functions(settings["fence"], owner=owner)
    require(
        len(fence_functions) == 1
        and fence_functions[0].visibility == "private"
        and not fence_functions[0].cfg_test,
        "session fence implementation is absent, ambiguous, public, or test-only",
    )
    return inventory, legacy, raw_target_census


def validate_internal_store(
    product: Sequence[Function],
    config: dict,
    legacy_session_state: dict[str, str],
) -> dict[str, list[str]]:
    settings = config["internal_store"]
    actual = [
        function
        for function in product
        if function.owner == "Store" and function.visibility == "pub(crate)"
    ]
    repeated = duplicates(function.name for function in actual)
    require(
        not repeated, f"crate-visible Store methods are ambiguous: {sorted(repeated)}"
    )
    actual_names = {function.name for function in actual}

    route_targets: set[str] = set()
    for category in (
        "mutation_routes",
        "optional_mutation_routes",
        "refusal_only_routes",
        "optional_legacy_routes",
    ):
        for specification in config["session"][category].values():
            if specification["target_owner"] != "Store":
                continue
            route_targets.add(specification["target"])
            if isinstance(specification.get("legacy_target"), str):
                route_targets.add(specification["legacy_target"])
    configured_extras = set(settings["read_only"]) | set(settings["mutation_helpers"])
    configured_extras.update(settings["optional_session_setup"])
    configured_extras.update(settings["optional_legacy_unrouted"])
    unknown = actual_names - route_targets - configured_extras
    require(
        not unknown,
        "unclassified crate-visible Store method (possible session bypass): "
        + ", ".join(sorted(unknown)),
    )
    missing = (
        set(settings["read_only"]) | set(settings["mutation_helpers"])
    ) - actual_names
    require(
        not missing,
        f"required internal Store classifications are absent: {sorted(missing)}",
    )

    product_callers = {
        name: [
            function
            for function in product
            if any(call.name == name for call in function.calls())
        ]
        for name in settings["optional_legacy_unrouted"]
        if name in actual_names
    }
    for name, callers in product_callers.items():
        # The legacy helper may remain only for compile-confined tests; a
        # production call is accepted solely in the explicit Gen3-compatibility
        # state, where the paired public session route is itself inventoried and
        # fence-checked. Gen4 moves that route under cfg(test).
        if legacy_session_state.get(name) == "production":
            require(
                len(callers) == 1
                and callers[0].owner == config["session"]["owner"]
                and callers[0].name == name,
                f"legacy raw Store helper {name} has callers outside its fenced Gen3 session route: "
                + ", ".join(function.location for function in callers),
            )
        else:
            require(
                not callers,
                f"legacy raw Store helper {name} has production callers: "
                + ", ".join(function.location for function in callers),
            )

    return {
        "legacy_unrouted": sorted(
            set(settings["optional_legacy_unrouted"]) & actual_names
        ),
        "mutation_helpers": sorted(set(settings["mutation_helpers"]) & actual_names),
        "read_only": sorted(set(settings["read_only"]) & actual_names),
        "session_setup": sorted(set(settings["optional_session_setup"]) & actual_names),
        "session_targets": sorted(actual_names & route_targets),
    }


def validate_maintenance(
    product: Sequence[Function], public_inventory: dict[str, list[str]], config: dict
) -> dict:
    names = public_inventory["maintenance"]
    functions = [
        require_unique(product, name, owner="Store", label="maintenance method")
        for name in names
    ]
    prelock_pure = set(config["maintenance_prelock_pure_calls"])
    for function in functions:
        calls = function.calls()
        lock_calls = function.calls("acquire_maintenance_locks")
        before_lock = [
            call.name
            for call in calls
            if lock_calls and call.start < lock_calls[0].start
        ]
        require(
            len(lock_calls) == 1 and set(before_lock) <= prelock_pure,
            f"maintenance method must acquire its lock exactly once before non-pure calls: "
            f"{function.location}; pre-lock calls={before_lock}",
        )
    additional_specs = config.get("additional_maintenance_lock_callers", [])
    additional = []
    for specification in additional_specs:
        require(
            isinstance(specification, dict)
            and isinstance(specification.get("source"), str)
            and isinstance(specification.get("name"), str)
            and (specification.get("owner") is None or isinstance(specification.get("owner"), str)),
            "additional maintenance-lock caller specification is malformed",
        )
        matches = [
            function
            for function in product
            if function.source.path.as_posix() == specification["source"]
            and function.owner == specification.get("owner")
            and function.name == specification["name"]
        ]
        require(
            len(matches) == 1,
            "additional maintenance-lock caller is absent or ambiguous: "
            f"{specification}",
        )
        lock_calls = matches[0].calls("acquire_maintenance_locks")
        require(
            len(lock_calls) == 1,
            f"additional maintenance path must acquire exactly one lock: {matches[0].location}",
        )
        additional.append(matches[0])

    actual_callers = [
        function for function in product if function.calls("acquire_maintenance_locks")
    ]
    require(
        {identity(function) for function in actual_callers}
        == {identity(function) for function in [*functions, *additional]},
        "maintenance-lock caller census differs from classified maintenance methods: "
        + ", ".join(function.location for function in actual_callers),
    )
    lock = require_unique(
        product, "acquire_maintenance_locks", label="maintenance lock helper"
    )
    require(
        lock.visibility == "pub(crate)", "maintenance lock helper changed visibility"
    )
    require(
        lock.calls("load")
        and lock.calls("try_lock")
        and lock.calls("load")[0].start < lock.calls("try_lock")[0].start,
        "maintenance lock helper does not check the fence before locking",
    )
    require(
        lock.calls("sort") and lock.calls("dedup"),
        "maintenance lock helper no longer deterministically sorts and deduplicates keys",
    )
    return {
        "count": len(functions),
        "additional": sorted(function.qualified_name for function in additional),
        "lock_helper": lock.qualified_name,
        "methods": sorted(names),
    }


def canonical_digest(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="emit the complete stable inventory"
    )
    arguments = parser.parse_args(argv)
    config = load_config()
    sources = source_inventory(config)
    compile_confined_paths = compile_confined_module_paths(sources)
    all_functions = [function for source in sources for function in source.functions]
    product = product_functions(sources, compile_confined_paths)
    public, public_lexemes = validate_public_store(product, config)
    live_c2_actor = validate_live_c2_actor(product, config)
    construction = validate_session_construction(all_functions, product, config)
    routes, legacy, raw_target_callers = validate_session_routes(
        sources, product, config
    )
    internal = validate_internal_store(product, config, legacy)
    maintenance = validate_maintenance(product, public, config)
    inventory = {
        "internal_store": internal,
        "live_c2_actor": live_c2_actor,
        "maintenance": maintenance,
        "public_store": public,
        "public_store_mutation_lexemes": public_lexemes,
        "raw_target_callers": raw_target_callers,
        "schema_version": 1,
        "session_construction": construction,
        "session_legacy": legacy,
        "session_routes": routes,
        "source_count": len(sources),
        "compile_confined_external_modules": sorted(compile_confined_paths),
    }
    digest = canonical_digest(inventory)
    if arguments.json:
        print(
            json.dumps(
                {"inventory": inventory, "inventory_digest": digest},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        route_counts: dict[str, int] = {}
        for route in routes:
            route_counts[route["classification"]] = (
                route_counts.get(route["classification"], 0) + 1
            )
        print(f"Store mutator census inventory: {digest}")
        print(
            "public Store: "
            + ", ".join(
                f"{category}={len(names)}" for category, names in sorted(public.items())
            )
        )
        print(
            "session routes: "
            + ", ".join(
                f"{category}={count}"
                for category, count in sorted(route_counts.items())
            )
            + f"; legacy={legacy}"
        )
        print(
            f"maintenance locks: {maintenance['count']} "
            + ",".join(maintenance["methods"])
        )
        print(
            "live C2 actor: "
            f"mutation-roots={len(live_c2_actor['mutation_roots'])}, "
            f"state-attachments={len(live_c2_actor['state_attachments'])}, "
            f"delegates={len(live_c2_actor['actor_delegates'])}"
        )
    print("Store mutation/session/maintenance census: PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, ScanError, KeyError, TypeError, ValueError) as error:
        print(
            f"Store mutation/session/maintenance census: FAIL: {error}", file=sys.stderr
        )
        sys.exit(1)
