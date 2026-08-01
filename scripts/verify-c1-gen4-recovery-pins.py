#!/usr/bin/env python3
"""Read-only inventory and exact-Git-object audit for C1 Gen4 V3 pins.

This tool deliberately cannot mint a recovery freeze, qualification identity,
certificate, or acceptance.  It has three modes:

* ``--check-scaffold`` validates only the inventory policy shape;
* ``--audit-worktree`` previews hashes from a possibly mutable worktree; and
* ``--verify-commit`` audits a clean checkout at one exact commit using only
  regular Git blobs, while also requiring this verifier to equal its committed
  copy byte-for-byte.

Every successful output remains an ``UNMINTED-PIN-AUDIT``.  The separately
governed qualification and acceptance procedure must bind any eventual pin
receipt to a frozen candidate and its exact-hash replay.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Iterable, Mapping, Sequence


INVENTORY_PATH = "audit/c1-gen4-v3-recovery-freeze/PIN-INVENTORY.v1.json"
VERIFIER_PATH = "scripts/verify-c1-gen4-recovery-pins.py"
TEST_PATH = "scripts/test_c1_gen4_recovery_pins.py"

INVENTORY_SCHEMA = "nq.c1_gen4_v3_recovery_pin_inventory.v1"
INVENTORY_STATUS = "INVENTORY-SPECIFICATION-NOT-A-FREEZE"
AUDIT_SCHEMA = "nq.c1_gen4_v3_recovery_pin_audit.v1"
AUDIT_STATUS = "UNMINTED-PIN-AUDIT"

CHARTER_COMMIT = "7acff3d1017d8d3291bb09c830071d133ecdf5cc"
BC_COMMIT = "66bdf8dc9b57be5d326ea7125243ff235e1cd50c"
GEN3_COMMIT = "47a66a70561580818dcd10ae2af07641acbada51"
GEN3_TREE = "370df7951d894b9bfe8e103e6fa18e918379a646"
GEN3_IDENTITY = (
    "sha256:6eed8895ab6a45a046726db9fef20378d5d6f85b3d715df36e80dd6bd3c7b8d5"
)
GEN2_FREEZE_SOURCE_COMMIT = "cf560bd88136f07c6e1e0376d372a0120f0c56df"

RESOLVER_PATH = "crates/nq-host-role-dependency-custody/src/lib.rs"
RESOLVER_SHA256 = (
    "sha256:fccda65babbc350d84866bb441058a24ff7f6c3fcf8692b54633d495810ae08d"
)

PREVIOUS_NINE = (
    "crates/nq-store/src/governed_custody.rs",
    "crates/nq-store/src/lib.rs",
    "crates/nq-store/src/custody_arena.rs",
    "crates/nq-store/src/schema.sql",
    "crates/nq-store/tests/r0b_noninjectability.rs",
    "crates/nq-store/tests/verify_r0b_callgraph.py",
    "crates/nq-host-role-runtime/src/test_support.rs",
    "crates/nq-core/src/engine.rs",
    "crates/nq-core/src/engine_governed_effect_tests.rs",
)

REQUIRED_GROUP_PATHS = {
    "previous-nine-current-forms": frozenset(PREVIOUS_NINE),
    "resolver-continuity": frozenset((RESOLVER_PATH,)),
    "gen4-production-resolution": frozenset(
        (
            "Cargo.lock",
            "Cargo.toml",
            "crates/nq-app/Cargo.toml",
            "crates/nq-app/src/archive.rs",
            "crates/nq-app/src/cli.rs",
            "crates/nq-core/Cargo.toml",
            "crates/nq-core/src/lib.rs",
            "crates/nq-host-role-contract/assets/schemas/nq.restore_activation_proof.v1.schema.json",
            "crates/nq-host-role-contract/src/assets.rs",
            "crates/nq-host-role-runtime/Cargo.toml",
            "crates/nq-host-role-runtime/src/dependency.rs",
            "crates/nq-host-role-runtime/src/facade.rs",
            "crates/nq-host-role-runtime/src/inspector.rs",
            "crates/nq-host-role-runtime/src/lib.rs",
            "crates/nq-host-role-runtime/src/prelaunch.rs",
            "crates/nq-host-role-runtime/src/runtime.rs",
            "crates/nq-runtime-dependency-authority/Cargo.toml",
            "crates/nq-store/Cargo.toml",
            "crates/nq-store/src/schema_v6_to_v7_runtime_dependencies.sql",
            "crates/nq-store/src/schema_v7_to_v8_runtime_authority.sql",
            "crates/nq-store/src/writer_session.rs",
        )
    ),
    "call-graph-proof-closure": frozenset(
        (
            "crates/nq-store/tests/r0b_callgraph_allowlist.json",
            "crates/nq-store/tests/rust_source_scan.py",
        )
    ),
    "gen4-and-gen3-proof-harnesses": frozenset(
        (
            "crates/nq-app/tests/admin_lifecycle.rs",
            "crates/nq-app/tests/e2e_cli.rs",
            "crates/nq-app/tests/semantic_surfaces.rs",
            "crates/nq-app/tests/support/mod.rs",
            "crates/nq-core/src/engine_checkpoint_commit_tests.rs",
            "crates/nq-store/tests/mutator_census_allowlist.json",
            "crates/nq-store/tests/runtime_authority_noninjectability.rs",
            "crates/nq-store/tests/store_contract.rs",
            "crates/nq-store/tests/verify_mutator_census.py",
            "crates/nq-store/tests/writer_session_noninjectability.rs",
        )
    ),
    "pin-proof-infrastructure": frozenset((INVENTORY_PATH, TEST_PATH, VERIFIER_PATH)),
}

REQUIRED_CLOSED_PREFIXES = {
    "host-role-runtime-all-rust-sources": {
        "prefix": "crates/nq-host-role-runtime/src/",
        "suffixes": (".rs",),
        "minimum_files": 7,
        "paired_extensions": False,
    },
    "authority-crate-all-rust-sources": {
        "prefix": "crates/nq-runtime-dependency-authority/src/",
        "suffixes": (".rs",),
        "minimum_files": 1,
        "paired_extensions": False,
    },
    "custody-arena-recovery-submodules": {
        "prefix": "crates/nq-store/src/custody_arena/",
        "suffixes": (".rs",),
        "minimum_files": 1,
        "paired_extensions": False,
    },
    "gen4-compile-fail-specimens": {
        "prefix": "crates/nq-store/tests/ui/gen4/",
        "suffixes": (".rs", ".stderr"),
        "minimum_files": 2,
        "paired_extensions": True,
    },
    "retained-r0b-compile-fail-specimens": {
        "prefix": "crates/nq-store/tests/ui/r0b/",
        "suffixes": (".rs", ".stderr"),
        "minimum_files": 2,
        "paired_extensions": True,
    },
    "retained-writer-compile-fail-specimens": {
        "prefix": "crates/nq-store/tests/ui/writer/",
        "suffixes": (".rs", ".stderr"),
        "minimum_files": 2,
        "paired_extensions": True,
    },
    "isolated-gen4-surfaces": {
        "prefix": "crates/nq-store/tests/isolated/gen4-",
        "suffixes": (),
        "minimum_files": 6,
        "paired_extensions": False,
    },
    "isolated-r0b-surfaces": {
        "prefix": "crates/nq-store/tests/isolated/r0b-",
        "suffixes": (),
        "minimum_files": 1,
        "paired_extensions": False,
    },
}

REQUIRED_EVIDENCE_FUNCTIONS = (
    "GEN4-CALL-GRAPH-PROOF",
    "GEN4-HOSTILE-RESULTS-H09-THROUGH-H19",
    "GEN4-MIGRATION-RESULTS",
    "GEN4-RESTART-RECOVERY",
    "GEN4-V3-RECOVERY-FREEZE",
    "GEN4-INDEPENDENT-ACCEPTANCE",
    "EXACT-HASH-REPLAY",
)

FREEZE_PRECONDITIONS = (
    "one exact committed NQ candidate and tree",
    "clean detached worktree at that candidate",
    "all pin paths resolved as regular Git blobs",
    "resolver continuity digest reproduced exactly",
    "H-09 through H-19 and every charter section 12 guarantee executed at the candidate hash",
    "all previously held recovery specimens retained and green",
    "fresh implementation and semantic reviews accepted",
    "separately authored acceptance names the exact candidate and pin receipt",
)

REQUIRED_NONCLAIMS = frozenset(
    (
        "this inventory is not a source freeze, qualification receipt, certificate, or acceptance",
        "Campaign 3B exit-gate conditions 1 through 6 remain unearned",
        "H-RCV-01 remains unearned",
        "PC-04 continuity is conditional on exact resolver byte identity and complete fresh replay",
        "Gen1, Gen2, and Gen3 recovery records remain immutable historical evidence",
        "no C2, C3, deployment, packaging, launch, or operational authority is created",
    )
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_OBJECT_RE = re.compile(r"[0-9a-f]{40,64}\Z")


class Refusal(RuntimeError):
    """A fail-closed audit refusal."""


def refuse(message: str) -> None:
    raise Refusal(message)


def sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _duplicate_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_float(text: str) -> None:
    refuse(f"floating-point JSON is forbidden in the pin inventory: {text}")


def _reject_constant(text: str) -> None:
    refuse(f"non-finite JSON is forbidden in the pin inventory: {text}")


def load_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_duplicate_guard,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except Refusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        refuse(f"{label} is not strict UTF-8 JSON: {error}")


def as_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        refuse(f"{label} must be an object")
    return value


def as_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        refuse(f"{label} must be an array")
    return value


def as_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        refuse(f"{label} must be a string")
    return value


def string_array(value: Any, label: str) -> list[str]:
    result = as_array(value, label)
    for index, child in enumerate(result):
        if not isinstance(child, str):
            refuse(f"{label}[{index}] must be a string")
    return result


def safe_relative_path(value: Any, label: str) -> str:
    path = as_string(value, label)
    if not path or "\\" in path or "\x00" in path:
        refuse(f"{label} is not a safe repository-relative POSIX path: {path!r}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or path.endswith("/") or pure.as_posix() != path:
        refuse(f"{label} is not a canonical repository-relative path: {path!r}")
    if any(part in ("", ".", "..") for part in pure.parts):
        refuse(f"{label} contains a forbidden path component: {path!r}")
    return path


def safe_prefix(value: Any, label: str) -> str:
    prefix = as_string(value, label)
    if not prefix or "\\" in prefix or "\x00" in prefix:
        refuse(f"{label} is not a safe repository-relative prefix: {prefix!r}")
    trimmed = prefix[:-1] if prefix.endswith("/") else prefix
    pure = PurePosixPath(trimmed)
    if pure.is_absolute() or pure.as_posix() != trimmed:
        refuse(f"{label} is not a canonical repository-relative prefix: {prefix!r}")
    if any(part in ("", ".", "..") for part in pure.parts):
        refuse(f"{label} contains a forbidden path component: {prefix!r}")
    return prefix


def _require_exact(value: Any, expected: Any, label: str) -> None:
    if value != expected:
        refuse(f"{label} differs from the required policy value")


def require_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = frozenset(value)
    required = frozenset(expected)
    if actual != required:
        missing = sorted(required - actual)
        unexpected = sorted(actual - required)
        refuse(f"{label} key set differs: missing={missing}, unexpected={unexpected}")


def validate_inventory(
    value: Any, inventory_path: str = INVENTORY_PATH
) -> dict[str, Any]:
    inventory = as_object(value, "pin inventory")
    require_keys(
        inventory,
        (
            "schema",
            "status",
            "generation",
            "authority_effect",
            "self_path",
            "verifier_path",
            "controlling_basis",
            "resolver_continuity",
            "required_previous_nine",
            "pin_groups",
            "closed_prefixes",
            "required_evidence_functions",
            "freeze_preconditions",
            "nonclaims",
        ),
        "pin inventory",
    )
    _require_exact(inventory.get("schema"), INVENTORY_SCHEMA, "inventory schema")
    _require_exact(inventory.get("status"), INVENTORY_STATUS, "inventory status")
    _require_exact(inventory.get("generation"), "c1.generation.4", "generation")
    _require_exact(inventory.get("authority_effect"), "none", "authority effect")

    normalized_inventory_path = safe_relative_path(inventory_path, "--inventory")
    _require_exact(
        safe_relative_path(inventory.get("self_path"), "self_path"),
        normalized_inventory_path,
        "inventory self_path",
    )
    _require_exact(
        safe_relative_path(inventory.get("verifier_path"), "verifier_path"),
        VERIFIER_PATH,
        "inventory verifier_path",
    )

    basis = as_object(inventory.get("controlling_basis"), "controlling_basis")
    require_keys(
        basis,
        (
            "charter_commit",
            "charter_path",
            "charter_sections",
            "binding_constraints_commit",
            "binding_constraint",
            "qualified_predecessor_commit",
            "qualified_predecessor_tree",
            "qualified_predecessor_identity",
            "historical_freeze_commit",
            "historical_freeze_role",
        ),
        "controlling_basis",
    )
    for field, expected in (
        ("charter_commit", CHARTER_COMMIT),
        (
            "charter_path",
            "c1-gen4-r2-charter/C1-GEN4-IMPLEMENTATION-CHARTER.md",
        ),
        ("binding_constraints_commit", BC_COMMIT),
        ("binding_constraint", "BC-11"),
        ("qualified_predecessor_commit", GEN3_COMMIT),
        ("qualified_predecessor_tree", GEN3_TREE),
        ("qualified_predecessor_identity", GEN3_IDENTITY),
        ("historical_freeze_commit", GEN2_FREEZE_SOURCE_COMMIT),
    ):
        _require_exact(basis.get(field), expected, f"controlling_basis.{field}")
    _require_exact(
        tuple(string_array(basis.get("charter_sections"), "charter_sections")),
        ("12", "15", "16", "17", "18"),
        "controlling charter sections",
    )
    _require_exact(
        basis.get("historical_freeze_role"),
        "context-only; never Gen4 evidence",
        "historical freeze role",
    )

    resolver = as_object(inventory.get("resolver_continuity"), "resolver_continuity")
    require_keys(
        resolver,
        ("path", "required_sha256", "condition"),
        "resolver_continuity",
    )
    _require_exact(resolver.get("path"), RESOLVER_PATH, "resolver path")
    _require_exact(resolver.get("required_sha256"), RESOLVER_SHA256, "resolver digest")
    _require_exact(
        resolver.get("condition"),
        "PC-04 continuity survives only if the exact Git blob reproduces this digest; any mismatch is a campaign stop requiring re-adjudication",
        "resolver continuity condition",
    )
    if (
        SHA256_RE.fullmatch(
            as_string(resolver.get("required_sha256"), "resolver digest")
        )
        is None
    ):
        refuse("resolver digest is not a sha256 identity")

    previous_nine = tuple(
        safe_relative_path(path, f"required_previous_nine[{index}]")
        for index, path in enumerate(
            string_array(
                inventory.get("required_previous_nine"), "required_previous_nine"
            )
        )
    )
    _require_exact(previous_nine, PREVIOUS_NINE, "required previous-nine order")

    groups = as_array(inventory.get("pin_groups"), "pin_groups")
    parsed_groups: dict[str, frozenset[str]] = {}
    explicit_owner: dict[str, str] = {}
    for group_index, raw_group in enumerate(groups):
        group = as_object(raw_group, f"pin_groups[{group_index}]")
        require_keys(
            group,
            ("id", "purpose", "paths"),
            f"pin_groups[{group_index}]",
        )
        group_id = as_string(group.get("id"), f"pin_groups[{group_index}].id")
        if group_id in parsed_groups:
            refuse(f"duplicate pin group id {group_id!r}")
        purpose = as_string(group.get("purpose"), f"pin_groups[{group_index}].purpose")
        if not purpose.strip():
            refuse(f"pin group {group_id!r} has an empty purpose")
        paths = tuple(
            safe_relative_path(path, f"pin group {group_id!r} path {path_index}")
            for path_index, path in enumerate(
                string_array(group.get("paths"), f"pin group {group_id!r}.paths")
            )
        )
        if len(paths) != len(set(paths)):
            refuse(f"pin group {group_id!r} repeats a path")
        for path in paths:
            previous_owner = explicit_owner.get(path)
            if previous_owner is not None:
                refuse(
                    f"explicit pin {path!r} is duplicated across groups "
                    f"{previous_owner!r} and {group_id!r}"
                )
            explicit_owner[path] = group_id
        parsed_groups[group_id] = frozenset(paths)

    _require_exact(
        frozenset(parsed_groups),
        frozenset(REQUIRED_GROUP_PATHS),
        "pin group id set",
    )
    for group_id, required_paths in REQUIRED_GROUP_PATHS.items():
        actual_paths = parsed_groups[group_id]
        if not required_paths.issubset(actual_paths):
            missing = sorted(required_paths - actual_paths)
            refuse(f"pin group {group_id!r} omits required paths: {missing}")
    _require_exact(
        parsed_groups["previous-nine-current-forms"],
        frozenset(PREVIOUS_NINE),
        "previous-nine pin group",
    )
    _require_exact(
        parsed_groups["resolver-continuity"],
        frozenset((RESOLVER_PATH,)),
        "resolver pin group",
    )
    _require_exact(
        parsed_groups["pin-proof-infrastructure"],
        frozenset((normalized_inventory_path, TEST_PATH, VERIFIER_PATH)),
        "pin-proof infrastructure group",
    )

    raw_prefixes = as_array(inventory.get("closed_prefixes"), "closed_prefixes")
    parsed_prefixes: dict[str, dict[str, Any]] = {}
    for prefix_index, raw_prefix in enumerate(raw_prefixes):
        rule = as_object(raw_prefix, f"closed_prefixes[{prefix_index}]")
        require_keys(
            rule,
            (
                "id",
                "purpose",
                "prefix",
                "suffixes",
                "minimum_files",
                "paired_extensions",
            ),
            f"closed_prefixes[{prefix_index}]",
        )
        rule_id = as_string(rule.get("id"), f"closed_prefixes[{prefix_index}].id")
        if rule_id in parsed_prefixes:
            refuse(f"duplicate closed-prefix id {rule_id!r}")
        purpose = as_string(
            rule.get("purpose"), f"closed_prefixes[{prefix_index}].purpose"
        )
        if not purpose.strip():
            refuse(f"closed-prefix rule {rule_id!r} has an empty purpose")
        prefix = safe_prefix(rule.get("prefix"), f"closed-prefix {rule_id!r}.prefix")
        suffixes = tuple(
            string_array(rule.get("suffixes"), f"closed-prefix {rule_id!r}.suffixes")
        )
        if len(suffixes) != len(set(suffixes)):
            refuse(f"closed-prefix rule {rule_id!r} repeats a suffix")
        for suffix in suffixes:
            if not suffix.startswith(".") or "/" in suffix or "\\" in suffix:
                refuse(f"closed-prefix rule {rule_id!r} has unsafe suffix {suffix!r}")
        minimum = rule.get("minimum_files")
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
            refuse(f"closed-prefix rule {rule_id!r} has invalid minimum_files")
        paired = rule.get("paired_extensions")
        if not isinstance(paired, bool):
            refuse(f"closed-prefix rule {rule_id!r} has non-Boolean paired_extensions")
        if paired and len(suffixes) < 2:
            refuse(
                f"closed-prefix rule {rule_id!r} cannot pair fewer than two suffixes"
            )
        parsed_prefixes[rule_id] = {
            "prefix": prefix,
            "suffixes": suffixes,
            "minimum_files": minimum,
            "paired_extensions": paired,
        }

    _require_exact(
        frozenset(parsed_prefixes),
        frozenset(REQUIRED_CLOSED_PREFIXES),
        "closed-prefix id set",
    )
    for rule_id, expected in REQUIRED_CLOSED_PREFIXES.items():
        _require_exact(parsed_prefixes[rule_id], expected, f"closed-prefix {rule_id}")

    evidence_functions = tuple(
        string_array(
            inventory.get("required_evidence_functions"),
            "required_evidence_functions",
        )
    )
    _require_exact(
        evidence_functions,
        REQUIRED_EVIDENCE_FUNCTIONS,
        "required evidence-function set",
    )
    _require_exact(
        tuple(
            string_array(inventory.get("freeze_preconditions"), "freeze_preconditions")
        ),
        FREEZE_PRECONDITIONS,
        "freeze preconditions",
    )
    nonclaims = string_array(inventory.get("nonclaims"), "nonclaims")
    if len(nonclaims) != len(set(nonclaims)):
        refuse("inventory repeats a nonclaim")
    if not REQUIRED_NONCLAIMS.issubset(nonclaims):
        missing = sorted(REQUIRED_NONCLAIMS - set(nonclaims))
        refuse(f"inventory omits required nonclaims: {missing}")

    normalized = copy.deepcopy(inventory)
    normalized["_parsed_groups"] = parsed_groups
    normalized["_parsed_prefixes"] = parsed_prefixes
    return normalized


def expand_pin_set(
    inventory: Mapping[str, Any], available_paths: Iterable[str]
) -> dict[str, set[str]]:
    available = sorted(set(available_paths))
    for index, path in enumerate(available):
        safe_relative_path(path, f"available path {index}")

    pins: dict[str, set[str]] = {}
    for group_id, paths in inventory["_parsed_groups"].items():
        for path in paths:
            pins.setdefault(path, set()).add(group_id)

    for rule_id, rule in inventory["_parsed_prefixes"].items():
        prefix = rule["prefix"]
        suffixes = rule["suffixes"]
        matches = [
            path
            for path in available
            if path.startswith(prefix)
            and (not suffixes or any(path.endswith(suffix) for suffix in suffixes))
        ]
        if len(matches) < rule["minimum_files"]:
            refuse(
                f"closed-prefix rule {rule_id!r} found {len(matches)} files; "
                f"minimum is {rule['minimum_files']}"
            )
        if rule["paired_extensions"]:
            suffix_set = set(suffixes)
            bases: dict[str, set[str]] = {}
            for path in matches:
                matching_suffixes = [
                    suffix for suffix in suffixes if path.endswith(suffix)
                ]
                if len(matching_suffixes) != 1:
                    refuse(
                        f"closed-prefix rule {rule_id!r} cannot determine one suffix "
                        f"for {path!r}"
                    )
                suffix = matching_suffixes[0]
                bases.setdefault(path[: -len(suffix)], set()).add(suffix)
            for base, observed in sorted(bases.items()):
                if observed != suffix_set:
                    missing = sorted(suffix_set - observed)
                    refuse(
                        f"closed-prefix rule {rule_id!r} has an incomplete diagnostic "
                        f"pair for {base!r}; missing {missing}"
                    )
        for path in matches:
            pins.setdefault(path, set()).add(f"closed:{rule_id}")

    unavailable = sorted(set(pins) - set(available))
    if unavailable:
        refuse(f"required pin paths are unavailable: {unavailable}")
    assert_semantic_pin_closure(pins, available)
    return pins


def semantic_required_paths(available_paths: Iterable[str]) -> set[str]:
    """Discover known semantic closures independently of manifest groups.

    This second line of defense prevents a self-consistent manifest/policy edit
    from omitting separately stored runtime modules, the archive migration
    specimen, or either external Gen4 feature surface.
    """
    available = set(available_paths)
    runtime_sources = {
        path
        for path in available
        if path.startswith("crates/nq-host-role-runtime/src/")
        and path.endswith(".rs")
    }
    required_runtime_root = "crates/nq-host-role-runtime/src/facade.rs"
    if required_runtime_root not in runtime_sources or len(runtime_sources) < 7:
        refuse("semantic runtime-source discovery is incomplete")

    archive_specimen = "crates/nq-app/src/archive.rs"
    if archive_specimen not in available:
        refuse("semantic archive/restore specimen is unavailable")

    isolated_surfaces = {
        path
        for path in available
        if path.startswith("crates/nq-store/tests/isolated/gen4-")
    }
    if len(isolated_surfaces) < 6:
        refuse("semantic Gen4 isolated-surface discovery is incomplete")

    return runtime_sources | {archive_specimen} | isolated_surfaces


def assert_semantic_pin_closure(
    pins: Mapping[str, set[str]], available_paths: Iterable[str]
) -> None:
    missing = sorted(semantic_required_paths(available_paths) - set(pins))
    if missing:
        refuse(f"semantic pin closure omits required paths: {missing}")


def assert_resolver_continuity(data: bytes) -> str:
    observed = sha256_bytes(data)
    if observed != RESOLVER_SHA256:
        refuse(
            "resolver continuity STOP: exact resolver bytes changed; "
            f"required {RESOLVER_SHA256}, observed {observed}; PC-04 requires "
            "re-adjudication and cannot be silently requalified"
        )
    return observed


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        refuse(f"cannot canonicalize pin audit input: {error}")


def pin_set_digest(pins: Sequence[Mapping[str, Any]]) -> str:
    return sha256_bytes(canonical_json_bytes(list(pins)))


def materialize_pins(
    pin_groups: Mapping[str, set[str]], reader: Callable[[str], bytes]
) -> list[dict[str, Any]]:
    result = []
    for path in sorted(pin_groups):
        result.append(
            {
                "path": path,
                "sha256": sha256_bytes(reader(path)),
                "groups": sorted(pin_groups[path]),
            }
        )
    return result


def sensitivity_controls(
    pins: Sequence[Mapping[str, Any]], resolver_bytes: bytes
) -> dict[str, bool]:
    if len(pins) < 2:
        refuse("pin-set sensitivity control requires at least two pins")
    mutated = bytearray(resolver_bytes)
    if mutated:
        mutated[0] ^= 1
    else:
        mutated.extend(b"x")
    resolver_mutation_rejected = False
    try:
        assert_resolver_continuity(bytes(mutated))
    except Refusal:
        resolver_mutation_rejected = True
    full_digest = pin_set_digest(pins)
    removed_digest = pin_set_digest(pins[:-1])
    return {
        "resolver_one_byte_mutation_rejected": resolver_mutation_rejected,
        "removing_one_pin_changes_pin_set_digest": full_digest != removed_digest,
    }


def checked_git(repo: Path, arguments: Iterable[str], purpose: str) -> bytes:
    command = ["git", "-C", os.fspath(repo), *arguments]
    try:
        result = subprocess.run(command, check=False, capture_output=True)
    except OSError as error:
        refuse(f"cannot execute Git for {purpose}: {error}")
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        refuse(f"Git failed for {purpose} (exit {result.returncode}): {stderr}")
    return result.stdout


def exact_repo(path: Path) -> Path:
    supplied = path.resolve()
    root_bytes = checked_git(
        supplied, ("rev-parse", "--show-toplevel"), "repository root"
    )
    try:
        root = Path(root_bytes.decode("utf-8").strip()).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as error:
        refuse(f"Git returned an unusable repository root: {error}")
    if root != supplied:
        refuse(f"--repo must be the exact repository root; Git reports {root}")
    return root


def resolve_commit(repo: Path, revision: str, label: str) -> str:
    try:
        resolved = (
            checked_git(
                repo,
                ("rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"),
                label,
            )
            .decode("ascii", "strict")
            .strip()
        )
    except UnicodeDecodeError as error:
        refuse(f"Git returned a non-ASCII commit for {label}: {error}")
    if GIT_OBJECT_RE.fullmatch(resolved) is None:
        refuse(f"Git returned an invalid commit for {label}: {resolved!r}")
    return resolved


def commit_tree(repo: Path, commit: str) -> str:
    try:
        tree = (
            checked_git(
                repo, ("show", "-s", "--format=%T", commit), f"tree for {commit}"
            )
            .decode("ascii", "strict")
            .strip()
        )
    except UnicodeDecodeError as error:
        refuse(f"Git returned a non-ASCII tree: {error}")
    if GIT_OBJECT_RE.fullmatch(tree) is None:
        refuse(f"Git returned an invalid tree for {commit}: {tree!r}")
    return tree


def git_tree_entries(repo: Path, commit: str) -> dict[str, tuple[str, str, str]]:
    raw = checked_git(
        repo, ("ls-tree", "-r", "-z", "--full-tree", commit), f"tree {commit}"
    )
    entries: dict[str, tuple[str, str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii", "strict").split()
            path = raw_path.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError) as error:
            refuse(f"Git returned an invalid tree record: {error}")
        safe_relative_path(path, "Git tree path")
        if path in entries:
            refuse(f"Git tree repeats path {path!r}")
        entries[path] = (mode, object_type, object_id)
    return entries


def git_blob(
    repo: Path, commit: str, path: str, entries: Mapping[str, tuple[str, str, str]]
) -> bytes:
    entry = entries.get(path)
    if entry is None:
        refuse(f"required Git path is absent at {commit}: {path}")
    mode, object_type, _object_id = entry
    if mode not in ("100644", "100755") or object_type != "blob":
        refuse(
            f"required Git path is not a regular blob at {commit}: "
            f"{path} ({mode} {object_type})"
        )
    return checked_git(repo, ("show", f"{commit}:{path}"), f"Git blob {commit}:{path}")


def worktree_paths(repo: Path) -> list[str]:
    raw = checked_git(
        repo,
        ("ls-files", "--cached", "--others", "--exclude-standard", "-z"),
        "worktree file inventory",
    )
    result = []
    for raw_path in raw.split(b"\0"):
        if not raw_path:
            continue
        try:
            path = raw_path.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            refuse(f"worktree has a non-UTF-8 Git path: {error}")
        result.append(safe_relative_path(path, "worktree Git path"))
    return result


def worktree_file(repo: Path, path: str) -> bytes:
    target = repo / safe_relative_path(path, "worktree read path")
    try:
        metadata = target.lstat()
    except OSError as error:
        refuse(f"cannot stat required worktree file {path}: {error}")
    if not stat.S_ISREG(metadata.st_mode):
        refuse(f"required worktree path is not a regular file: {path}")
    try:
        return target.read_bytes()
    except OSError as error:
        refuse(f"cannot read required worktree file {path}: {error}")


def status_records(repo: Path) -> list[str]:
    raw = checked_git(
        repo,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        "worktree status",
    )
    return [record.decode("utf-8", "replace") for record in raw.split(b"\0") if record]


def base_receipt(mode: str, inventory_sha256: str) -> dict[str, Any]:
    return {
        "schema": AUDIT_SCHEMA,
        "status": AUDIT_STATUS,
        "mode": mode,
        "generation": "c1.generation.4",
        "authority_effect": "none",
        "freeze_minted": False,
        "qualification_earned": False,
        "certificate_issued": False,
        "registry_authorized": False,
        "evidence_execution": {
            "performed_by_this_tool": [],
            "still_required": list(REQUIRED_EVIDENCE_FUNCTIONS),
        },
        "independent_acceptance": "NOT-PERFORMED",
        "inventory": {
            "path": INVENTORY_PATH,
            "sha256": inventory_sha256,
            "status": INVENTORY_STATUS,
        },
    }


def scaffold_audit(inventory_bytes: bytes, inventory_path: str) -> dict[str, Any]:
    inventory = validate_inventory(
        load_json(inventory_bytes, inventory_path), inventory_path
    )
    receipt = base_receipt("check-scaffold", sha256_bytes(inventory_bytes))
    receipt.update(
        {
            "paths_read": False,
            "policy": {
                "explicit_pin_count": sum(
                    len(paths) for paths in inventory["_parsed_groups"].values()
                ),
                "closed_prefix_count": len(inventory["_parsed_prefixes"]),
                "resolver_required_sha256": RESOLVER_SHA256,
            },
            "result": "STRUCTURALLY-VALID-INVENTORY-NOT-A-FREEZE",
        }
    )
    return receipt


def worktree_audit(repo: Path, inventory_path: str) -> dict[str, Any]:
    inventory_bytes = worktree_file(repo, inventory_path)
    inventory = validate_inventory(
        load_json(inventory_bytes, inventory_path), inventory_path
    )
    available = worktree_paths(repo)
    groups = expand_pin_set(inventory, available)
    pins = materialize_pins(groups, lambda path: worktree_file(repo, path))
    resolver_bytes = worktree_file(repo, RESOLVER_PATH)
    resolver_sha256 = assert_resolver_continuity(resolver_bytes)
    controls = sensitivity_controls(pins, resolver_bytes)
    dirty = status_records(repo)
    head = resolve_commit(repo, "HEAD", "worktree HEAD")
    receipt = base_receipt("audit-worktree", sha256_bytes(inventory_bytes))
    receipt.update(
        {
            "source": {
                "kind": "mutable-worktree-preview",
                "head": head,
                "tree": commit_tree(repo, head),
                "clean": not dirty,
                "status_record_count": len(dirty),
                "stable_candidate_identity": False,
            },
            "resolver_continuity": {
                "path": RESOLVER_PATH,
                "required_sha256": RESOLVER_SHA256,
                "observed_sha256": resolver_sha256,
                "exact_byte_identity": True,
                "pc04_status": "CONDITIONAL-PENDING-FRESH-REPLAY",
            },
            "pin_count": len(pins),
            "pin_set_algorithm": "sha256(canonical-json(sorted exact pin rows))",
            "pin_set_sha256": pin_set_digest(pins),
            "pins": pins,
            "controls": controls,
            "result": "MUTABLE-PREVIEW-ONLY-NOT-A-FREEZE",
        }
    )
    return receipt


def verify_commit_audit(
    repo: Path, inventory_path: str, revision: str
) -> dict[str, Any]:
    commit = resolve_commit(repo, revision, "candidate commit")
    head = resolve_commit(repo, "HEAD", "checkout HEAD")
    if head != commit:
        refuse(
            f"exact-commit audit requires HEAD {commit}, but checkout HEAD is {head}"
        )
    dirty = status_records(repo)
    if dirty:
        refuse(
            "exact-commit audit requires a clean checkout; "
            f"observed {len(dirty)} status records"
        )

    entries = git_tree_entries(repo, commit)

    def blob_reader(path: str) -> bytes:
        return git_blob(repo, commit, path, entries)

    inventory_bytes = blob_reader(inventory_path)
    inventory = validate_inventory(
        load_json(inventory_bytes, f"{commit}:{inventory_path}"), inventory_path
    )
    groups = expand_pin_set(inventory, entries)
    pins = materialize_pins(groups, blob_reader)

    verifier_bytes = blob_reader(VERIFIER_PATH)
    running_verifier = Path(__file__).resolve()
    expected_running_path = (repo / VERIFIER_PATH).resolve()
    if running_verifier != expected_running_path:
        refuse(
            "exact-commit audit must execute the verifier from the exact repository "
            f"path {expected_running_path}; running {running_verifier}"
        )
    try:
        running_bytes = running_verifier.read_bytes()
    except OSError as error:
        refuse(f"cannot read running verifier bytes: {error}")
    if running_bytes != verifier_bytes:
        refuse("running verifier bytes differ from the candidate Git blob")

    resolver_bytes = blob_reader(RESOLVER_PATH)
    resolver_sha256 = assert_resolver_continuity(resolver_bytes)
    controls = sensitivity_controls(pins, resolver_bytes)
    receipt = base_receipt("verify-commit", sha256_bytes(inventory_bytes))
    receipt.update(
        {
            "source": {
                "kind": "exact-commit-git-objects",
                "commit": commit,
                "tree": commit_tree(repo, commit),
                "checkout_head_matches": True,
                "checkout_clean": True,
                "all_pins_regular_git_blobs": True,
                "running_verifier_matches_git_blob": True,
            },
            "resolver_continuity": {
                "path": RESOLVER_PATH,
                "required_sha256": RESOLVER_SHA256,
                "observed_sha256": resolver_sha256,
                "exact_byte_identity": True,
                "pc04_status": "CONDITIONAL-PENDING-FRESH-REPLAY",
            },
            "pin_count": len(pins),
            "pin_set_algorithm": "sha256(canonical-json(sorted exact pin rows))",
            "pin_set_sha256": pin_set_digest(pins),
            "pins": pins,
            "controls": controls,
            "result": "EXACT-GIT-PIN-AUDIT-PASSED-NOT-A-FREEZE",
        }
    )
    return receipt


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument(
        "--repo", required=True, type=Path, help="exact NQ repository root"
    )
    argument_parser.add_argument(
        "--inventory", default=INVENTORY_PATH, help="repository-relative inventory"
    )
    modes = argument_parser.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "--check-scaffold",
        action="store_true",
        help="validate only inventory structure; read no pin sources",
    )
    modes.add_argument(
        "--audit-worktree",
        action="store_true",
        help="read-only mutable preview; never a freeze",
    )
    modes.add_argument(
        "--verify-commit",
        metavar="COMMIT",
        help="audit regular Git blobs in a clean checkout at COMMIT",
    )
    return argument_parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        repo = exact_repo(arguments.repo)
        inventory_path = safe_relative_path(arguments.inventory, "--inventory")
        if inventory_path != INVENTORY_PATH:
            refuse(
                f"the governed inventory path is fixed at {INVENTORY_PATH}; "
                f"observed {inventory_path}"
            )
        if arguments.check_scaffold:
            inventory_bytes = worktree_file(repo, inventory_path)
            receipt = scaffold_audit(inventory_bytes, inventory_path)
        elif arguments.audit_worktree:
            receipt = worktree_audit(repo, inventory_path)
        else:
            receipt = verify_commit_audit(repo, inventory_path, arguments.verify_commit)
    except Refusal as error:
        refusal = {
            "schema": AUDIT_SCHEMA,
            "status": "REFUSED",
            "authority_effect": "none",
            "freeze_minted": False,
            "qualification_earned": False,
            "reason": str(error),
        }
        print(json.dumps(refusal, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
