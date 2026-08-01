#!/usr/bin/env python3
"""Verify a C1 qualification identity entirely from immutable Git objects.

Both ``--repo`` and ``--commit`` are mandatory.  Every input is obtained with
checked Git commands; the worktree is not evidence.  The verifier independently
recomputes the three section digests, the manifest-v2 exclusion projection, the
carrier pre-review projection and semantic identity, all exact-byte bindings,
the 91+91 engine-source census, and the extension/Rust/test pins.  It also runs
sensitivity and old/new cross-pair rejection controls on every invocation.

The admitted C1 projections contain no floats.  The canonicalizer refuses
floating-point values and unsafe integers, and uses UTF-16 object-key ordering
for the integer/string RFC 8785 domain exercised by these assets.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping


GEN3_COMMIT = "47a66a70561580818dcd10ae2af07641acbada51"
GEN3_TREE = "370df7951d894b9bfe8e103e6fa18e918379a646"
GEN3_RECEIPT = {
    "engine_sha256": "sha256:0e54c22342a3d2fa9e599299b4b49d8509b11b53610d1b2c0f3dc43476f0177c",
    "semantic_outcome_variants_sha256": "sha256:d27c6f0c19472bb3825b9d17ac1f82eb674daf8b31469597c0e67dfe8aa3ea0f",
    "semantic_exclusions_sha256": "sha256:c26b949145f9864c907cd248c93f0de4929e1a6b6e14fec823b33c0a48bbba9d",
    "descriptor_governed_open_semantics_sha256": "sha256:2c885bf666fca9b77cfd1f6dbb3a29425ab78408b8a0af00290a84eb5d535b57",
    "qualification_basis_sha256": "sha256:c8557b9ff37534b3e189d117a9e04cf78617cddc2cf30c48802204acf6501e3b",
    "pre_review_projection_sha256": "sha256:805b5c2e9bef5d2c6e32c44f5af63316f1ada83210ac9ac3dd71338f7923467a",
    "qualification_id": "sha256:6eed8895ab6a45a046726db9fef20378d5d6f85b3d715df36e80dd6bd3c7b8d5",
    "manifest_v1_bytes_sha256": "sha256:a0436b72669c427cae37335abe10ed9bc939181c75c28af427960404e664baec",
    "manifest_v2_bytes_sha256": "sha256:f1c97c59181e10611413a42dd4d401c0db08298bd5513303aed81af000e25d98",
    "carrier_bytes_sha256": "sha256:28b5580fffaf0b03525a202e063503b1934483b66d119cbd136280e0aa8da7f1",
}

ENGINE_PATH = "crates/nq-core/src/engine.rs"
ASSET_DIR = "crates/nq-host-role-contract/assets"
EXTENSION_PATH = f"{ASSET_DIR}/custody-capacity-extension-manifest.v1.json"
MANIFEST_V1_PATH = f"{ASSET_DIR}/nq.v3_projection_capsule_bound_manifest.v1.json"
MANIFEST_V2_PATH = f"{ASSET_DIR}/nq.v3_projection_capsule_bound_manifest.v2.json"
CARRIER_PATH = f"{ASSET_DIR}/nq.v3_projection_capsule_bound_qualification.v1.json"
ASSETS_RS_PATH = "crates/nq-host-role-contract/src/assets.rs"
CAPACITY_TEST_PATH = "crates/nq-host-role-contract/tests/capacity_extension.rs"
CHAIN_PATHS = (
    ENGINE_PATH,
    EXTENSION_PATH,
    MANIFEST_V1_PATH,
    MANIFEST_V2_PATH,
    CARRIER_PATH,
    ASSETS_RS_PATH,
    CAPACITY_TEST_PATH,
)
SECTION_LENGTHS = {
    "semantic_outcome_variants": 50,
    "semantic_exclusions": 9,
    "descriptor_governed_open_semantics": 276,
}
STATIC_ASSETS = {
    "nq.v3_projection_capsule_bound_manifest.v1": MANIFEST_V1_PATH,
    "nq.v3_projection_capsule_bound_manifest.v2": MANIFEST_V2_PATH,
    "nq.v3_projection_capsule_bound_qualification.v1": CARRIER_PATH,
}
EXPECTED_ENGINE_BINDINGS_PER_MANIFEST = 91
GIT_OBJECT_RE = re.compile(r"[0-9a-f]{40,64}\Z")


class Refusal(RuntimeError):
    """A fail-closed verification refusal."""


def refuse(message: str) -> None:
    raise Refusal(message)


def sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _duplicate_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            refuse(f"duplicate JSON key {key!r}")
        value[key] = child
    return value


def _reject_float(text: str) -> None:
    refuse(f"floating-point JSON is outside the qualification domain: {text}")


def _reject_constant(text: str) -> None:
    refuse(f"non-finite JSON value is forbidden: {text}")


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


def _valid_text(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        refuse("unpaired surrogate is outside I-JSON")


def _utf16_key(value: str) -> bytes:
    _valid_text(value)
    return value.encode("utf-16-be")


def canonical_bytes(value: Any) -> bytes:
    def emit(node: Any) -> str:
        if node is None:
            return "null"
        if node is True:
            return "true"
        if node is False:
            return "false"
        if isinstance(node, int):
            if not -(2**53 - 1) <= node <= 2**53 - 1:
                refuse(f"unsafe I-JSON integer: {node}")
            return str(node)
        if isinstance(node, float):
            refuse("floating-point JSON is outside the qualification domain")
        if isinstance(node, str):
            _valid_text(node)
            return json.dumps(node, ensure_ascii=False, allow_nan=False)
        if isinstance(node, list):
            return "[" + ",".join(emit(child) for child in node) + "]"
        if isinstance(node, dict):
            if any(not isinstance(key, str) for key in node):
                refuse("JSON object contains a non-string key")
            return (
                "{"
                + ",".join(
                    f"{emit(key)}:{emit(node[key])}"
                    for key in sorted(node, key=_utf16_key)
                )
                + "}"
            )
        refuse(f"unsupported canonical JSON type: {type(node).__name__}")

    return emit(value).encode("utf-8")


def semantic_digest(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def exact_pretty_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        refuse(f"control could not serialize JSON: {error}")


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
        supplied, ["rev-parse", "--show-toplevel"], "repository root"
    )
    try:
        root = Path(root_bytes.decode("utf-8").strip()).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as error:
        refuse(f"Git returned an unusable root: {error}")
    if root != supplied:
        refuse(f"--repo must be the exact repository root; Git reports {root}")
    return root


def resolve_commit(repo: Path, revision: str, label: str) -> str:
    resolved = (
        checked_git(
            repo,
            ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
            label,
        )
        .decode("ascii", "strict")
        .strip()
    )
    if GIT_OBJECT_RE.fullmatch(resolved) is None:
        refuse(f"Git returned invalid object name for {label}: {resolved!r}")
    return resolved


def commit_tree(repo: Path, commit: str) -> str:
    tree = checked_git(repo, ["show", "-s", "--format=%T", commit], f"tree {commit}")
    decoded = tree.decode("ascii", "strict").strip()
    if GIT_OBJECT_RE.fullmatch(decoded) is None:
        refuse(f"Git returned invalid tree for {commit}: {decoded!r}")
    return decoded


def show_object(repo: Path, commit: str, path: str) -> bytes:
    if GIT_OBJECT_RE.fullmatch(commit) is None:
        refuse("internal invalid commit identifier")
    checked_git(
        repo, ["cat-file", "-e", f"{commit}:{path}"], f"existence {commit}:{path}"
    )
    return checked_git(
        repo, ["show", f"{commit}:{path}"], f"Git object {commit}:{path}"
    )


def object_map(repo: Path, commit: str) -> dict[str, bytes]:
    return {path: show_object(repo, commit, path) for path in CHAIN_PATHS}


def as_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        refuse(f"{label} is not an object")
    return value


def as_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        refuse(f"{label} is not an array")
    return value


def projection_without(value: Any, fields: Iterable[str], label: str) -> dict[str, Any]:
    projection = copy.deepcopy(as_object(value, label))
    for field in fields:
        if field not in projection:
            refuse(f"{label} lacks excluded field {field}")
        del projection[field]
    return projection


def basis_digest(manifest: Any) -> str:
    return semantic_digest(
        projection_without(
            manifest,
            ("qualification_basis", "cap_h14_qualification", "qualification_gaps"),
            "manifest-v2 basis source",
        )
    )


def pre_review_digest(carrier: Any) -> str:
    projection = projection_without(
        carrier, ("qualification_id",), "carrier pre-review source"
    )
    bindings = projection.get("implementation_bindings")
    if not isinstance(bindings, dict):
        refuse("carrier has no implementation_bindings object")
    if "post_acceptance_review" not in bindings:
        refuse("carrier has no post_acceptance_review to exclude")
    del bindings["post_acceptance_review"]
    return semantic_digest(projection)


def carrier_identity(carrier: Any) -> str:
    return semantic_digest(
        projection_without(carrier, ("qualification_id",), "carrier identity source")
    )


def engine_nodes(value: Any) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("source_path") == ENGINE_PATH:
                nodes.append(node)
            for child in node.values():
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return nodes


def string_occurrences(value: Any, target: str) -> int:
    count = 0

    def visit(node: Any) -> None:
        nonlocal count
        if isinstance(node, str):
            count += int(node == target)
        elif isinstance(node, dict):
            for key, child in node.items():
                count += int(key == target)
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return count


def engine_census(manifest: Any, digest: str, label: str) -> int:
    nodes = engine_nodes(manifest)
    if len(nodes) != EXPECTED_ENGINE_BINDINGS_PER_MANIFEST:
        refuse(
            f"{label} has {len(nodes)} engine source bindings, expected "
            f"{EXPECTED_ENGINE_BINDINGS_PER_MANIFEST}"
        )
    for ordinal, node in enumerate(nodes):
        if node.get("source_sha256") != digest:
            refuse(
                f"{label} engine source binding {ordinal} does not match engine Git object"
            )
    occurrences = string_occurrences(manifest, digest)
    if occurrences != EXPECTED_ENGINE_BINDINGS_PER_MANIFEST:
        refuse(
            f"{label} contains {occurrences} total JSON-string occurrences of the engine "
            f"digest, expected {EXPECTED_ENGINE_BINDINGS_PER_MANIFEST}"
        )
    return len(nodes)


def exact_pin(text: str, value: str, expected: int, label: str) -> None:
    count = text.count(value)
    if count != expected:
        refuse(f"{label} has {count} occurrences of {value}, expected {expected}")


def extension_rows(extension: Any) -> dict[str, dict[str, Any]]:
    rows = as_array(
        as_object(extension, "extension").get("static_assets"), "static_assets"
    )
    found: dict[str, dict[str, Any]] = {}
    for raw in rows:
        row = as_object(raw, "static asset row")
        identity = row.get("identity")
        if not isinstance(identity, str) or identity not in STATIC_ASSETS:
            continue
        if identity in found:
            refuse(f"duplicate static asset row: {identity}")
        found[identity] = row
    if set(found) != set(STATIC_ASSETS):
        refuse(
            "extension does not contain the exact three C1 chain static-asset identities"
        )
    return found


@dataclass(frozen=True)
class VerifiedChain:
    commit: str
    tree: str
    objects: Mapping[str, bytes]
    manifest_v1: Any
    manifest_v2: Any
    carrier: Any
    receipt: Mapping[str, Any]


def validate_pair(
    manifest_v2: Any, carrier: Any, carrier_bytes: bytes, label: str
) -> None:
    manifest = as_object(manifest_v2, f"{label} manifest")
    qualification = as_object(carrier, f"{label} carrier")
    basis = basis_digest(manifest)
    manifest_basis = manifest.get("qualification_basis")
    carrier_basis = qualification.get("qualification_basis")
    if not isinstance(manifest_basis, dict) or manifest_basis.get("digest") != basis:
        refuse(f"{label}: manifest self-basis mismatch")
    if not isinstance(carrier_basis, dict) or carrier_basis.get("digest") != basis:
        refuse(f"{label}: carrier/manifest basis mismatch")
    identity = carrier_identity(qualification)
    if qualification.get("qualification_id") != identity:
        refuse(f"{label}: carrier semantic identity mismatch")
    positive = manifest.get("cap_h14_qualification")
    if not isinstance(positive, dict):
        refuse(f"{label}: manifest positive binding is absent")
    if positive.get("qualification_id") != identity:
        refuse(f"{label}: manifest/carrier identity mismatch")
    if positive.get("canonical_bytes_sha256") != sha256_bytes(carrier_bytes):
        refuse(f"{label}: manifest/carrier exact-byte mismatch")


def verify_chain(repo: Path, commit: str) -> VerifiedChain:
    tree = commit_tree(repo, commit)
    objects = object_map(repo, commit)
    engine_digest = sha256_bytes(objects[ENGINE_PATH])
    manifest_v1 = load_json(objects[MANIFEST_V1_PATH], f"{commit} manifest v1")
    manifest_v2 = load_json(objects[MANIFEST_V2_PATH], f"{commit} manifest v2")
    carrier = load_json(objects[CARRIER_PATH], f"{commit} carrier")
    extension = load_json(objects[EXTENSION_PATH], f"{commit} extension")
    v1_object = as_object(manifest_v1, "manifest v1")
    v2_object = as_object(manifest_v2, "manifest v2")
    if v1_object.get("schema") != "nq.v3_projection_capsule_bound_manifest.v1":
        refuse("manifest v1 schema identity differs")
    if v2_object.get("schema") != "nq.v3_projection_capsule_bound_manifest.v2":
        refuse("manifest v2 schema identity differs")

    census_v1 = engine_census(manifest_v1, engine_digest, "manifest v1")
    census_v2 = engine_census(manifest_v2, engine_digest, "manifest v2")
    sections: dict[str, str] = {}
    for name, expected_length in SECTION_LENGTHS.items():
        rows_v1 = as_array(v1_object.get(name), f"manifest v1 {name}")
        rows_v2 = as_array(v2_object.get(name), f"manifest v2 {name}")
        if len(rows_v2) != expected_length:
            refuse(
                f"semantic section {name} has {len(rows_v2)} rows, expected {expected_length}"
            )
        if rows_v1 != rows_v2:
            refuse(f"manifest v1/v2 semantic section {name} differs")
        sections[f"{name}_sha256"] = semantic_digest(rows_v2)

    validate_pair(
        manifest_v2, carrier, objects[CARRIER_PATH], f"{commit} positive pair"
    )
    basis = basis_digest(manifest_v2)
    pre_review = pre_review_digest(carrier)
    carrier_object = as_object(carrier, "carrier")
    review_bindings = carrier_object.get("implementation_bindings")
    if not isinstance(review_bindings, dict):
        refuse("carrier implementation bindings are not an object")
    review = review_bindings.get("post_acceptance_review")
    if not isinstance(review, dict):
        refuse("carrier post-acceptance review is not an object")
    if review.get("qualification_basis_sha256") != basis:
        refuse("post-acceptance review qualification-basis pin differs")
    if review.get("pre_review_projection_sha256") != pre_review:
        refuse("post-acceptance review projection pin differs")
    identity = carrier_identity(carrier)

    exact_hashes = {
        MANIFEST_V1_PATH: sha256_bytes(objects[MANIFEST_V1_PATH]),
        MANIFEST_V2_PATH: sha256_bytes(objects[MANIFEST_V2_PATH]),
        CARRIER_PATH: sha256_bytes(objects[CARRIER_PATH]),
    }
    rows = extension_rows(extension)
    for identity_name, path in STATIC_ASSETS.items():
        row = rows[identity_name]
        if row.get("source_path") != Path(path).name:
            refuse(f"extension path pin differs for {identity_name}")
        if row.get("sha256") != exact_hashes[path]:
            refuse(f"extension exact-byte digest differs for {identity_name}")

    try:
        assets_rs = objects[ASSETS_RS_PATH].decode("utf-8")
        capacity_test = objects[CAPACITY_TEST_PATH].decode("utf-8")
    except UnicodeDecodeError as error:
        refuse(f"Rust pin source is not UTF-8: {error}")
    exact_pin(assets_rs, engine_digest, 1, "assets.rs engine pin")
    for digest in sections.values():
        exact_pin(assets_rs, digest, 1, "assets.rs section pin")
    for path, digest in exact_hashes.items():
        exact_pin(assets_rs, digest, 1, f"assets.rs {Path(path).name} pin")
    exact_pin(assets_rs, basis, 1, "assets.rs qualification-basis pin")
    exact_pin(capacity_test, basis, 1, "capacity test qualification-basis pin")

    receipt: dict[str, Any] = {
        "commit": commit,
        "tree": tree,
        "engine_binding_census": {"manifest_v1": census_v1, "manifest_v2": census_v2},
        "engine_sha256": engine_digest,
        **sections,
        "qualification_basis_sha256": basis,
        "pre_review_projection_sha256": pre_review,
        "qualification_id": identity,
        "manifest_v1_bytes_sha256": exact_hashes[MANIFEST_V1_PATH],
        "manifest_v2_bytes_sha256": exact_hashes[MANIFEST_V2_PATH],
        "carrier_bytes_sha256": exact_hashes[CARRIER_PATH],
        "extension_bytes_sha256": sha256_bytes(objects[EXTENSION_PATH]),
        "assets_rs_bytes_sha256": sha256_bytes(objects[ASSETS_RS_PATH]),
        "capacity_test_bytes_sha256": sha256_bytes(objects[CAPACITY_TEST_PATH]),
    }
    if commit == GEN3_COMMIT:
        if tree != GEN3_TREE:
            refuse(f"exact Gen3 commit has tree {tree}, expected {GEN3_TREE}")
        for field, expected in GEN3_RECEIPT.items():
            if receipt.get(field) != expected:
                refuse(f"exact Gen3 {field} does not reproduce its qualified receipt")
    return VerifiedChain(
        commit, tree, objects, manifest_v1, manifest_v2, carrier, receipt
    )


def expect_pair_refusal(
    manifest: Any, carrier: Any, carrier_bytes: bytes, label: str
) -> str:
    try:
        validate_pair(manifest, carrier, carrier_bytes, label)
    except Refusal as error:
        return str(error)
    refuse(f"control failed: {label} cross-pair was accepted")


def synthetic_successor(chain: VerifiedChain) -> tuple[Any, Any, bytes]:
    synthetic_digest = sha256_bytes(
        b"nq.c1-generation-identity-verifier.synthetic-engine-control.v1"
    )
    if synthetic_digest == chain.receipt["engine_sha256"]:
        refuse(
            "synthetic engine control unexpectedly collides with target engine digest"
        )
    manifest = copy.deepcopy(chain.manifest_v2)
    nodes = engine_nodes(manifest)
    if len(nodes) != EXPECTED_ENGINE_BINDINGS_PER_MANIFEST:
        refuse("synthetic control lost the engine census")
    for node in nodes:
        node["source_sha256"] = synthetic_digest
    basis = basis_digest(manifest)

    carrier = copy.deepcopy(chain.carrier)
    carrier_object = as_object(carrier, "synthetic carrier")
    carrier_object["qualification_basis"]["digest"] = basis
    review = carrier_object["implementation_bindings"]["post_acceptance_review"]
    review["qualification_basis_sha256"] = basis
    review["pre_review_projection_sha256"] = pre_review_digest(carrier)
    carrier_object["qualification_id"] = carrier_identity(carrier)
    carrier_bytes = exact_pretty_json(carrier)

    manifest_object = as_object(manifest, "synthetic manifest")
    manifest_object["qualification_basis"]["digest"] = basis
    manifest_object["cap_h14_qualification"]["qualification_id"] = carrier_object[
        "qualification_id"
    ]
    manifest_object["cap_h14_qualification"]["canonical_bytes_sha256"] = sha256_bytes(
        carrier_bytes
    )
    validate_pair(manifest, carrier, carrier_bytes, "synthetic successor self-pair")
    return manifest, carrier, carrier_bytes


def run_controls(target: VerifiedChain, predecessor: VerifiedChain) -> dict[str, Any]:
    # Source binding and basis sensitivity.
    mutated_manifest = copy.deepcopy(target.manifest_v2)
    nodes = engine_nodes(mutated_manifest)
    original_basis = basis_digest(target.manifest_v2)
    control_digest = sha256_bytes(b"nq.c1.manifest-source-sensitivity.v1")
    if control_digest == target.receipt["engine_sha256"]:
        refuse("source sensitivity control digest collision")
    nodes[0]["source_sha256"] = control_digest
    changed_basis = basis_digest(mutated_manifest)
    if changed_basis == original_basis:
        refuse("control failed: engine source mutation did not change manifest basis")
    census_rejection = ""
    try:
        engine_census(
            mutated_manifest, target.receipt["engine_sha256"], "mutated manifest"
        )
    except Refusal as error:
        census_rejection = str(error)
    if not census_rejection:
        refuse("control failed: engine source mutation survived exact census")

    # Carrier semantic and exact-byte sensitivity are intentionally independent.
    mutated_carrier = copy.deepcopy(target.carrier)
    mutated_carrier["qualification_basis"]["digest"] = sha256_bytes(
        b"nq.c1.carrier-basis-sensitivity.v1"
    )
    if carrier_identity(mutated_carrier) == target.receipt["qualification_id"]:
        refuse(
            "control failed: carrier basis mutation did not change semantic identity"
        )
    padded_carrier_bytes = target.objects[CARRIER_PATH] + b"\n"
    if sha256_bytes(padded_carrier_bytes) == target.receipt["carrier_bytes_sha256"]:
        refuse("control failed: exact carrier byte mutation did not change byte digest")
    if (
        carrier_identity(load_json(padded_carrier_bytes, "padded carrier"))
        != target.receipt["qualification_id"]
    ):
        refuse("control failed: whitespace changed carrier semantic identity")
    padded_rejection = expect_pair_refusal(
        target.manifest_v2,
        target.carrier,
        padded_carrier_bytes,
        "exact-byte sensitivity",
    )

    if predecessor.receipt["qualification_id"] != target.receipt["qualification_id"]:
        old_chain = predecessor
        new_manifest = target.manifest_v2
        new_carrier = target.carrier
        new_carrier_bytes = target.objects[CARRIER_PATH]
        cross_pair_source = "git-predecessor-and-target"
    else:
        old_chain = target
        new_manifest, new_carrier, new_carrier_bytes = synthetic_successor(target)
        cross_pair_source = "deterministic-synthetic-successor"
    old_new_rejection = expect_pair_refusal(
        old_chain.manifest_v2,
        new_carrier,
        new_carrier_bytes,
        "old-manifest/new-carrier",
    )
    new_old_rejection = expect_pair_refusal(
        new_manifest,
        old_chain.carrier,
        old_chain.objects[CARRIER_PATH],
        "new-manifest/old-carrier",
    )

    return {
        "source_digest_mutation_changed_basis": True,
        "source_digest_mutation_rejected_by_91_binding_census": True,
        "source_digest_mutation_rejection": census_rejection,
        "carrier_basis_mutation_changed_identity": True,
        "carrier_whitespace_changed_exact_hash_only": True,
        "carrier_whitespace_pair_rejection": padded_rejection,
        "cross_pair_source": cross_pair_source,
        "old_manifest_new_carrier_rejected": True,
        "old_manifest_new_carrier_rejection": old_new_rejection,
        "new_manifest_old_carrier_rejected": True,
        "new_manifest_old_carrier_rejection": new_old_rejection,
    }


def parse_args(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", required=True, type=Path, help="exact Git repository root"
    )
    parser.add_argument("--commit", required=True, help="candidate commit to verify")
    parser.add_argument(
        "--predecessor-commit",
        default=GEN3_COMMIT,
        help=f"old side of cross-pair controls (default: exact Gen3 {GEN3_COMMIT})",
    )
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        repo = exact_repo(args.repo)
        target_commit = resolve_commit(repo, args.commit, "target commit")
        predecessor_commit = resolve_commit(
            repo, args.predecessor_commit, "predecessor commit"
        )
        target = verify_chain(repo, target_commit)
        predecessor = (
            target
            if predecessor_commit == target_commit
            else verify_chain(repo, predecessor_commit)
        )
        controls = run_controls(target, predecessor)
        document = {
            "schema": "nq.c1_generation_git_identity_verification.v1",
            "status": "verified",
            "input_plane": "Git objects only",
            "repo": os.fspath(repo),
            "target": target.receipt,
            "predecessor": {
                "commit": predecessor.commit,
                "tree": predecessor.tree,
                "qualification_id": predecessor.receipt["qualification_id"],
            },
            "formulas": {
                "section_digest": "sha256(JCS(section-array))",
                "qualification_basis": "sha256(JCS(manifest-v2 excluding qualification_basis, cap_h14_qualification, qualification_gaps))",
                "pre_review_projection": "sha256(JCS(carrier excluding qualification_id and implementation_bindings.post_acceptance_review))",
                "qualification_id": "sha256(JCS(carrier excluding qualification_id))",
                "carrier_bytes": "sha256(exact carrier Git-blob bytes)",
            },
            "controls": controls,
        }
        print(json.dumps(document, sort_keys=True, indent=2))
        return 0
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError) as error:
        print(
            f"REFUSED: operating-system or encoding failure: {error}", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
