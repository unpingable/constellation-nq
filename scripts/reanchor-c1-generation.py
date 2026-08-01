#!/usr/bin/env python3
"""Deterministically re-anchor the C1 qualification chain to reviewed sources.

The default baseline is the exact qualified C1 Gen3 commit.  ``--check`` is
read-only and requires the worktree's engine and six generated/pinned outputs
to equal the deterministic result.  ``--write`` is the qualification mutation
mode; it
requires every output file still to equal its baseline Git object, validates
the complete result in memory, stages every replacement, and then uses
same-directory atomic replacements with rollback on a reported error.

``--prepare-review`` is a distinct non-qualification mutation mode.  It may
update the CAP-H14 evaluator source binding and mechanically keeps the prior
review object structurally joined only so an exact committed pre-review
projection can be independently reviewed.  Its receipt explicitly says that
the old verdict is not evidence for the prepared cut.  A later ``--write``
with a fresh accepted review binding must replace that object before the cut
can be a qualification candidate.

The JSON projections used here contain no floating-point values.  The local
canonicalizer deliberately refuses floats and unsafe integers while matching
RFC 8785 for the admitted JSON domain, including UTF-16 object-key ordering.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tempfile
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
REVIEW_BINDING_PATH = "audit/c1-gen4-cap-h14-review-binding.v1.json"
REVIEW_BINDING_SCHEMA = "nq.c1_gen4_cap_h14_review_binding.v1"
REVIEW_BINDING_STATUS = "accepted-independent-review"
REVIEW_VERDICT = "PASS-PURE-C1"
EVALUATOR_PATH = "crates/nq-store/src/governed_projection_capacity.rs"
SERIALIZER_PATH = "crates/nq-store/src/governed_projection_capsule.rs"
LEGACY_REVIEW_IDENTITY = (
    "nq.host-role-runtime-seam.physical-capacity-c1-post-acceptance-rereview.v3"
)
LEGACY_REVIEW_SHA256 = (
    "sha256:6e4ac4c136386e4a8379ca76ca9d42fd145d5de71e98ea877dab40b3a1c0d8c1"
)
OUTPUT_PATHS = (
    EXTENSION_PATH,
    MANIFEST_V1_PATH,
    MANIFEST_V2_PATH,
    CARRIER_PATH,
    ASSETS_RS_PATH,
    CAPACITY_TEST_PATH,
)
SECTION_NAMES = (
    "semantic_outcome_variants",
    "semantic_exclusions",
    "descriptor_governed_open_semantics",
)
STATIC_ASSETS = {
    "nq.v3_projection_capsule_bound_manifest.v1": MANIFEST_V1_PATH,
    "nq.v3_projection_capsule_bound_manifest.v2": MANIFEST_V2_PATH,
    "nq.v3_projection_capsule_bound_qualification.v1": CARRIER_PATH,
}
EXPECTED_ENGINE_BINDINGS_PER_MANIFEST = 91
SHA256_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
GIT_OBJECT_RE = re.compile(r"[0-9a-f]{40,64}\Z")


class Refusal(RuntimeError):
    """A fail-closed qualification-tool refusal."""


def refuse(message: str) -> None:
    raise Refusal(message)


def sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def parse_digest(value: str) -> str:
    match = SHA256_RE.fullmatch(value)
    if match is None:
        refuse(
            "engine digest must be 64 lowercase hexadecimal digits, optionally prefixed by sha256:"
        )
    return f"sha256:{match.group(1)}"


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_float(value: str) -> None:
    refuse(
        f"floating-point JSON is outside the qualification projection domain: {value}"
    )


def _reject_constant(value: str) -> None:
    refuse(f"non-finite JSON number is forbidden: {value}")


def load_json(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except Refusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        refuse(f"{label} is not strict UTF-8 JSON: {error}")


def _validate_scalar_text(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        refuse("unpaired UTF-16 surrogate is outside I-JSON")


def _utf16_key(value: str) -> bytes:
    _validate_scalar_text(value)
    return value.encode("utf-16-be")


def jcs_bytes(value: Any) -> bytes:
    """Canonicalize the integer/string JSON domain used by the C1 assets."""

    def render(node: Any) -> str:
        if node is None:
            return "null"
        if node is True:
            return "true"
        if node is False:
            return "false"
        if isinstance(node, int):
            if not -(2**53 - 1) <= node <= 2**53 - 1:
                refuse(f"integer exceeds the exact I-JSON range: {node}")
            return str(node)
        if isinstance(node, float):
            refuse("floating-point JSON is outside the qualification projection domain")
        if isinstance(node, str):
            _validate_scalar_text(node)
            return json.dumps(node, ensure_ascii=False, allow_nan=False)
        if isinstance(node, list):
            return "[" + ",".join(render(child) for child in node) + "]"
        if isinstance(node, dict):
            if any(not isinstance(key, str) for key in node):
                refuse("JSON object has a non-string key")
            fields = []
            for key in sorted(node, key=_utf16_key):
                fields.append(f"{render(key)}:{render(node[key])}")
            return "{" + ",".join(fields) + "}"
        refuse(f"unsupported JSON value in canonical projection: {type(node).__name__}")

    return render(value).encode("utf-8")


def semantic_digest(value: Any) -> str:
    return sha256_bytes(jcs_bytes(value))


def pretty_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        refuse(f"cannot serialize generated JSON: {error}")


def run_git(repo: Path, arguments: Iterable[str], label: str) -> bytes:
    command = ["git", "-C", os.fspath(repo), *arguments]
    try:
        result = subprocess.run(command, check=False, capture_output=True)
    except OSError as error:
        refuse(f"cannot run Git for {label}: {error}")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        refuse(f"Git failed for {label} (exit {result.returncode}): {detail}")
    return result.stdout


def resolve_repo(repo: Path) -> Path:
    supplied = repo.resolve()
    root = run_git(supplied, ["rev-parse", "--show-toplevel"], "repository root")
    try:
        resolved = Path(root.decode("utf-8").strip()).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as error:
        refuse(f"Git returned an unusable repository root: {error}")
    if resolved != supplied:
        refuse(f"--repo must name the repository root exactly (Git reports {resolved})")
    return resolved


def resolve_commit(repo: Path, revision: str) -> str:
    output = run_git(
        repo,
        ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
        f"commit {revision!r}",
    )
    commit = output.decode("ascii", "strict").strip()
    if GIT_OBJECT_RE.fullmatch(commit) is None:
        refuse(f"Git resolved {revision!r} to a non-object identifier: {commit!r}")
    return commit


def git_object(repo: Path, commit: str, path: str) -> bytes:
    if GIT_OBJECT_RE.fullmatch(commit) is None:
        refuse("internal error: unvalidated Git object identifier")
    run_git(repo, ["cat-file", "-e", f"{commit}:{path}"], f"object {commit}:{path}")
    return run_git(repo, ["show", f"{commit}:{path}"], f"contents {commit}:{path}")


def git_tree(repo: Path, commit: str) -> str:
    tree = run_git(repo, ["show", "-s", "--format=%T", commit], f"tree for {commit}")
    value = tree.decode("ascii", "strict").strip()
    if GIT_OBJECT_RE.fullmatch(value) is None:
        refuse(f"Git returned an invalid tree identifier for {commit}: {value!r}")
    return value


def project_without(value: Any, fields: Iterable[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        refuse(f"{label} projection source is not an object")
    projection = copy.deepcopy(value)
    for field in fields:
        if field not in projection:
            refuse(f"{label} projection is missing excluded field {field!r}")
        del projection[field]
    return projection


def qualification_basis(manifest_v2: Any) -> str:
    return semantic_digest(
        project_without(
            manifest_v2,
            ("qualification_basis", "cap_h14_qualification", "qualification_gaps"),
            "manifest-v2 qualification basis",
        )
    )


def pre_review_projection(carrier: Any) -> str:
    projection = project_without(carrier, ("qualification_id",), "carrier pre-review")
    bindings = projection.get("implementation_bindings")
    if not isinstance(bindings, dict) or "post_acceptance_review" not in bindings:
        refuse("carrier pre-review projection lacks post_acceptance_review")
    del bindings["post_acceptance_review"]
    return semantic_digest(projection)


def qualification_identity(carrier: Any) -> str:
    return semantic_digest(
        project_without(
            carrier, ("qualification_id",), "carrier qualification identity"
        )
    )


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        refuse(f"{label} is not an object")
    return value


def require_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        refuse(f"{label} is not an array")
    return value


def object_member(value: Any, name: str, label: str) -> dict[str, Any]:
    parent = require_object(value, label)
    if name not in parent:
        refuse(f"{label} is missing object member {name!r}")
    return require_object(parent[name], f"{label}.{name}")


def require_exact_keys(
    value: Mapping[str, Any], expected: Iterable[str], label: str
) -> None:
    actual = frozenset(value)
    required = frozenset(expected)
    if actual != required:
        refuse(
            f"{label} key set differs: missing={sorted(required - actual)}, "
            f"unexpected={sorted(actual - required)}"
        )


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        refuse(f"{label} must be a nonempty string")
    return value


def require_sha256(value: Any, label: str) -> str:
    digest = require_string(value, label)
    if SHA256_RE.fullmatch(digest) is None or not digest.startswith("sha256:"):
        refuse(f"{label} must be a canonical sha256: digest")
    return digest


def safe_relative_path(value: Any, label: str) -> str:
    path = require_string(value, label)
    if "\\" in path or "\x00" in path or path.endswith("/"):
        refuse(f"{label} is not a canonical repository-relative path")
    pure = PurePosixPath(path)
    if pure.is_absolute() or pure.as_posix() != path:
        refuse(f"{label} is not a canonical repository-relative path")
    if any(part in ("", ".", "..") for part in pure.parts):
        refuse(f"{label} contains a forbidden path component")
    return path


def validate_review_binding(
    value: Any, qualification_basis_sha256: str, pre_review_projection_sha256: str
) -> dict[str, Any]:
    binding = require_object(value, "CAP-H14 review binding")
    require_exact_keys(
        binding,
        (
            "schema",
            "status",
            "generation",
            "authority_effect",
            "reviewed_source",
            "records_repository",
            "review_receipt",
        ),
        "CAP-H14 review binding",
    )
    if binding.get("schema") != REVIEW_BINDING_SCHEMA:
        refuse("CAP-H14 review binding schema differs")
    if binding.get("status") != REVIEW_BINDING_STATUS:
        refuse("CAP-H14 review binding is not accepted")
    if binding.get("generation") != "c1.generation.4":
        refuse("CAP-H14 review binding generation differs")
    if binding.get("authority_effect") != "none":
        refuse("CAP-H14 review binding attempts an authority effect")

    source = object_member(binding, "reviewed_source", "CAP-H14 review binding")
    require_exact_keys(
        source,
        (
            "commit",
            "tree",
            "qualification_basis_sha256",
            "pre_review_projection_sha256",
            "evaluator_path",
            "evaluator_sha256",
            "canonical_serializer_path",
            "canonical_serializer_sha256",
        ),
        "CAP-H14 reviewed source",
    )
    for field in ("commit", "tree"):
        object_id = require_string(source.get(field), f"reviewed source {field}")
        if GIT_OBJECT_RE.fullmatch(object_id) is None:
            refuse(f"reviewed source {field} is not a Git object identity")
    if source.get("qualification_basis_sha256") != qualification_basis_sha256:
        refuse("fresh review does not state the generated qualification basis")
    if source.get("pre_review_projection_sha256") != pre_review_projection_sha256:
        refuse("fresh review does not state the generated pre-review projection")
    if (
        safe_relative_path(source.get("evaluator_path"), "reviewed evaluator path")
        != EVALUATOR_PATH
    ):
        refuse("fresh review evaluator path differs")
    if (
        safe_relative_path(
            source.get("canonical_serializer_path"),
            "reviewed canonical serializer path",
        )
        != SERIALIZER_PATH
    ):
        refuse("fresh review canonical serializer path differs")
    require_sha256(source.get("evaluator_sha256"), "reviewed evaluator digest")
    require_sha256(
        source.get("canonical_serializer_sha256"),
        "reviewed canonical serializer digest",
    )

    records = object_member(binding, "records_repository", "CAP-H14 review binding")
    require_exact_keys(records, ("commit", "tree"), "records repository binding")
    for field in ("commit", "tree"):
        object_id = require_string(records.get(field), f"records {field}")
        if GIT_OBJECT_RE.fullmatch(object_id) is None:
            refuse(f"records {field} is not a Git object identity")

    receipt = object_member(binding, "review_receipt", "CAP-H14 review binding")
    require_exact_keys(
        receipt,
        (
            "identity",
            "verdict",
            "receipt_path",
            "receipt_sha256",
            "report_path",
            "report_sha256",
        ),
        "CAP-H14 review receipt binding",
    )
    identity = require_string(receipt.get("identity"), "review identity")
    if identity == LEGACY_REVIEW_IDENTITY:
        refuse("unchanged Gen3 review identity cannot bind a successor cut")
    if receipt.get("verdict") != REVIEW_VERDICT:
        refuse("fresh CAP-H14 review verdict is not PASS-PURE-C1")
    safe_relative_path(receipt.get("receipt_path"), "review receipt path")
    safe_relative_path(receipt.get("report_path"), "review report path")
    require_sha256(receipt.get("receipt_sha256"), "review receipt digest")
    report_sha256 = require_sha256(receipt.get("report_sha256"), "review report digest")
    if report_sha256 == LEGACY_REVIEW_SHA256:
        refuse("unchanged Gen3 review bytes cannot bind a successor cut")
    return binding


def carrier_review_from_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    source = require_object(binding["reviewed_source"], "reviewed source")
    receipt = require_object(binding["review_receipt"], "review receipt")
    return {
        "identity": receipt["identity"],
        "path": receipt["report_path"],
        "sha256": receipt["report_sha256"],
        "qualification_basis_sha256": source["qualification_basis_sha256"],
        "pre_review_projection_sha256": source["pre_review_projection_sha256"],
    }


def engine_binding_nodes(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("source_path") == ENGINE_PATH:
                found.append(node)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return found


def string_occurrences(value: Any, target: str) -> int:
    count = 0

    def walk(node: Any) -> None:
        nonlocal count
        if isinstance(node, str):
            count += int(node == target)
        elif isinstance(node, dict):
            for key, child in node.items():
                count += int(key == target)
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return count


def validate_engine_census(manifest: Any, engine_digest: str, label: str) -> int:
    nodes = engine_binding_nodes(manifest)
    if len(nodes) != EXPECTED_ENGINE_BINDINGS_PER_MANIFEST:
        refuse(
            f"{label} has {len(nodes)} {ENGINE_PATH} bindings; "
            f"expected exactly {EXPECTED_ENGINE_BINDINGS_PER_MANIFEST}"
        )
    for index, node in enumerate(nodes):
        if node.get("source_sha256") != engine_digest:
            refuse(
                f"{label} engine binding {index} has {node.get('source_sha256')!r}; "
                f"expected {engine_digest}"
            )
    digest_occurrences = string_occurrences(manifest, engine_digest)
    if digest_occurrences != EXPECTED_ENGINE_BINDINGS_PER_MANIFEST:
        refuse(
            f"{label} contains {digest_occurrences} total JSON-string occurrences of "
            f"the engine digest; expected exactly {EXPECTED_ENGINE_BINDINGS_PER_MANIFEST}"
        )
    return len(nodes)


def section_digests(manifest_v1: Any, manifest_v2: Any) -> dict[str, str]:
    v1 = require_object(manifest_v1, "manifest v1")
    v2 = require_object(manifest_v2, "manifest v2")
    result: dict[str, str] = {}
    for name in SECTION_NAMES:
        rows_v1 = require_array(v1.get(name), f"manifest v1 {name}")
        rows_v2 = require_array(v2.get(name), f"manifest v2 {name}")
        if rows_v1 != rows_v2:
            refuse(f"manifest v1 and v2 differ in semantic section {name}")
        result[f"{name}_sha256"] = semantic_digest(rows_v2)
    return result


def exact_text_pin(text: str, pin: str, expected: int, label: str) -> None:
    actual = text.count(pin)
    if actual != expected:
        refuse(
            f"{label} contains {actual} occurrences of {pin}; expected exactly {expected}"
        )


def static_asset_rows(extension: Any) -> dict[str, dict[str, Any]]:
    root = require_object(extension, "capacity extension manifest")
    rows = require_array(root.get("static_assets"), "capacity extension static_assets")
    result: dict[str, dict[str, Any]] = {}
    for row_value in rows:
        row = require_object(row_value, "capacity extension static asset")
        identity = row.get("identity")
        if isinstance(identity, str) and identity in STATIC_ASSETS:
            if identity in result:
                refuse(f"capacity extension duplicates static asset {identity}")
            result[identity] = row
    missing = sorted(set(STATIC_ASSETS) - set(result))
    if missing:
        refuse(f"capacity extension omits static assets: {', '.join(missing)}")
    return result


def verify_chain(
    bundle: Mapping[str, bytes],
    engine_digest: str,
    *,
    label: str,
    review_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    missing = sorted(set(OUTPUT_PATHS) - set(bundle))
    if missing:
        refuse(f"{label} bundle omits: {', '.join(missing)}")

    manifest_v1 = load_json(bundle[MANIFEST_V1_PATH], f"{label} manifest v1")
    manifest_v2 = load_json(bundle[MANIFEST_V2_PATH], f"{label} manifest v2")
    carrier = load_json(bundle[CARRIER_PATH], f"{label} carrier")
    extension = load_json(bundle[EXTENSION_PATH], f"{label} extension")
    assets_rs = bundle[ASSETS_RS_PATH].decode("utf-8", "strict")
    capacity_test = bundle[CAPACITY_TEST_PATH].decode("utf-8", "strict")

    census_v1 = validate_engine_census(
        manifest_v1, engine_digest, f"{label} manifest v1"
    )
    census_v2 = validate_engine_census(
        manifest_v2, engine_digest, f"{label} manifest v2"
    )
    sections = section_digests(manifest_v1, manifest_v2)
    basis = qualification_basis(manifest_v2)

    m2 = require_object(manifest_v2, f"{label} manifest v2")
    carrier_object = require_object(carrier, f"{label} carrier")
    manifest_basis = object_member(m2, "qualification_basis", f"{label} manifest v2")
    carrier_basis = object_member(
        carrier_object, "qualification_basis", f"{label} carrier"
    )
    if manifest_basis.get("digest") != basis:
        refuse(
            f"{label} manifest v2 qualification-basis digest differs from projection"
        )
    if carrier_basis.get("digest") != basis:
        refuse(f"{label} carrier qualification-basis digest differs from manifest v2")

    pre_review = pre_review_projection(carrier)
    bindings = object_member(
        carrier_object, "implementation_bindings", f"{label} carrier"
    )
    review = object_member(bindings, "post_acceptance_review", f"{label} bindings")
    if review_binding is None:
        if review.get("qualification_basis_sha256") != basis:
            refuse(f"{label} review does not bind the qualification basis")
        if review.get("pre_review_projection_sha256") != pre_review:
            refuse(f"{label} review pre-review projection digest differs")
    else:
        validated_review_binding = validate_review_binding(
            review_binding, basis, pre_review
        )
        if review != carrier_review_from_binding(validated_review_binding):
            refuse(f"{label} carrier review differs from the fresh review binding")

    identity = qualification_identity(carrier)
    if carrier_object.get("qualification_id") != identity:
        refuse(
            f"{label} carrier qualification identity differs from its JCS projection"
        )
    carrier_bytes_digest = sha256_bytes(bundle[CARRIER_PATH])
    positive = object_member(m2, "cap_h14_qualification", f"{label} manifest v2")
    if positive.get("qualification_id") != identity:
        refuse(f"{label} manifest v2 qualification ID does not bind the carrier")
    if positive.get("canonical_bytes_sha256") != carrier_bytes_digest:
        refuse(f"{label} manifest v2 exact-byte carrier binding differs")

    file_digests = {
        MANIFEST_V1_PATH: sha256_bytes(bundle[MANIFEST_V1_PATH]),
        MANIFEST_V2_PATH: sha256_bytes(bundle[MANIFEST_V2_PATH]),
        CARRIER_PATH: carrier_bytes_digest,
    }
    extension_rows = static_asset_rows(extension)
    for identity_name, path in STATIC_ASSETS.items():
        row = extension_rows[identity_name]
        if row.get("source_path") != Path(path).name:
            refuse(
                f"{label} extension static asset {identity_name} has the wrong source path"
            )
        if row.get("sha256") != file_digests[path]:
            refuse(
                f"{label} extension static asset {identity_name} has the wrong exact-byte digest"
            )

    exact_text_pin(assets_rs, engine_digest, 1, f"{label} assets.rs engine pin")
    for section_digest in sections.values():
        exact_text_pin(assets_rs, section_digest, 1, f"{label} assets.rs section pin")
    for path, digest in file_digests.items():
        exact_text_pin(assets_rs, digest, 1, f"{label} assets.rs {Path(path).name} pin")
    exact_text_pin(assets_rs, basis, 1, f"{label} assets.rs basis pin")
    exact_text_pin(capacity_test, basis, 1, f"{label} capacity test basis pin")
    for field in ("identity", "path", "sha256"):
        value = require_string(review.get(field), f"{label} review {field}")
        exact_text_pin(
            assets_rs,
            value,
            1,
            f"{label} assets.rs post-acceptance review {field} pin",
        )

    return {
        "engine_binding_replacements": {
            "manifest_v1": census_v1,
            "manifest_v2": census_v2,
        },
        "engine_sha256": engine_digest,
        **sections,
        "qualification_basis_sha256": basis,
        "pre_review_projection_sha256": pre_review,
        "post_acceptance_review": copy.deepcopy(review),
        "review_binding_path": REVIEW_BINDING_PATH
        if review_binding is not None
        else None,
        "qualification_id": identity,
        "manifest_v1_bytes_sha256": file_digests[MANIFEST_V1_PATH],
        "manifest_v2_bytes_sha256": file_digests[MANIFEST_V2_PATH],
        "carrier_bytes_sha256": carrier_bytes_digest,
    }


def load_git_bundle(repo: Path, commit: str) -> dict[str, bytes]:
    return {path: git_object(repo, commit, path) for path in OUTPUT_PATHS}


def validate_gen3_receipt(commit: str, tree: str, receipt: Mapping[str, Any]) -> None:
    if commit != GEN3_COMMIT:
        return
    if tree != GEN3_TREE:
        refuse(f"Gen3 tree is {tree}; expected exact tree {GEN3_TREE}")
    for field, expected in GEN3_RECEIPT.items():
        actual = receipt.get(field)
        if actual != expected:
            refuse(f"Gen3 {field} is {actual!r}; expected exact receipt {expected!r}")


def replace_engine_bindings(
    manifest: Any, old_digest: str, new_digest: str, label: str
) -> None:
    nodes = engine_binding_nodes(manifest)
    if len(nodes) != EXPECTED_ENGINE_BINDINGS_PER_MANIFEST:
        refuse(
            f"{label} replacement census is {len(nodes)}; "
            f"expected exactly {EXPECTED_ENGINE_BINDINGS_PER_MANIFEST}"
        )
    for index, node in enumerate(nodes):
        if node.get("source_sha256") != old_digest:
            refuse(
                f"{label} replacement {index} is not pinned to baseline engine digest"
            )
    for node in nodes:
        node["source_sha256"] = new_digest


def replace_cap_h14_evaluator_bindings(
    carrier: Any, old_digest: str, new_digest: str
) -> None:
    root = require_object(carrier, "CAP-H14 carrier")
    implementation = object_member(root, "implementation_bindings", "CAP-H14 carrier")
    bindings = [
        object_member(implementation, field, "CAP-H14 implementation bindings")
        for field in ("evaluator", "independent_arithmetic", "test_source")
    ]
    budget = object_member(root, "qualification_budget", "CAP-H14 carrier")
    bindings.append(
        object_member(budget, "enforcement_binding", "CAP-H14 qualification budget")
    )
    for binding in bindings:
        if binding.get("path") != EVALUATOR_PATH:
            refuse("CAP-H14 evaluator-family binding path differs")
        if binding.get("sha256") != old_digest:
            refuse(
                "CAP-H14 evaluator-family binding digest differs within the baseline"
            )
    for binding in bindings:
        binding["sha256"] = new_digest


def replace_exact(text: str, old: str, new: str, expected: int, label: str) -> str:
    count = text.count(old)
    if count != expected:
        refuse(f"{label} replacement census is {count}; expected exactly {expected}")
    if old == new:
        return text
    return text.replace(old, new)


def reanchor_bundle(
    baseline: Mapping[str, bytes],
    old_engine_digest: str,
    new_engine_digest: str,
    review_binding: Mapping[str, Any] | None = None,
    *,
    old_evaluator_digest: str | None = None,
    new_evaluator_digest: str | None = None,
    prepare_review: bool = False,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if prepare_review and review_binding is not None:
        refuse("review preparation cannot also install an accepted review binding")
    old_receipt = verify_chain(baseline, old_engine_digest, label="baseline")

    manifest_v1 = copy.deepcopy(
        load_json(baseline[MANIFEST_V1_PATH], "baseline manifest v1")
    )
    manifest_v2 = copy.deepcopy(
        load_json(baseline[MANIFEST_V2_PATH], "baseline manifest v2")
    )
    carrier = copy.deepcopy(load_json(baseline[CARRIER_PATH], "baseline carrier"))
    extension = copy.deepcopy(load_json(baseline[EXTENSION_PATH], "baseline extension"))
    replace_engine_bindings(
        manifest_v1, old_engine_digest, new_engine_digest, "manifest v1"
    )
    replace_engine_bindings(
        manifest_v2, old_engine_digest, new_engine_digest, "manifest v2"
    )
    baseline_evaluator = old_evaluator_digest or require_string(
        carrier["implementation_bindings"]["evaluator"].get("sha256"),
        "baseline CAP-H14 evaluator digest",
    )
    requested_evaluator = new_evaluator_digest or baseline_evaluator
    replace_cap_h14_evaluator_bindings(carrier, baseline_evaluator, requested_evaluator)

    sections = section_digests(manifest_v1, manifest_v2)
    new_basis = qualification_basis(manifest_v2)
    carrier_object = require_object(carrier, "generated carrier")
    carrier_object["qualification_basis"]["digest"] = new_basis
    old_review = copy.deepcopy(
        carrier_object["implementation_bindings"]["post_acceptance_review"]
    )
    generated_pre_review = pre_review_projection(carrier)
    if prepare_review:
        new_review = old_review
        new_review["qualification_basis_sha256"] = new_basis
        new_review["pre_review_projection_sha256"] = generated_pre_review
    elif review_binding is None:
        if (
            new_basis != old_receipt["qualification_basis_sha256"]
            or generated_pre_review != old_receipt["pre_review_projection_sha256"]
        ):
            refuse(
                "qualification basis or pre-review projection changed without a fresh "
                "independent review binding"
            )
        new_review = old_review
    else:
        validated_review_binding = validate_review_binding(
            review_binding, new_basis, generated_pre_review
        )
        new_review = carrier_review_from_binding(validated_review_binding)
    carrier_object["implementation_bindings"]["post_acceptance_review"] = new_review
    carrier_object["qualification_id"] = qualification_identity(carrier)
    carrier_bytes = pretty_json(carrier)

    m2 = require_object(manifest_v2, "generated manifest v2")
    m2["qualification_basis"]["digest"] = new_basis
    m2["cap_h14_qualification"]["qualification_id"] = carrier_object["qualification_id"]
    m2["cap_h14_qualification"]["canonical_bytes_sha256"] = sha256_bytes(carrier_bytes)
    manifest_v1_bytes = pretty_json(manifest_v1)
    manifest_v2_bytes = pretty_json(manifest_v2)

    generated_hashes = {
        MANIFEST_V1_PATH: sha256_bytes(manifest_v1_bytes),
        MANIFEST_V2_PATH: sha256_bytes(manifest_v2_bytes),
        CARRIER_PATH: sha256_bytes(carrier_bytes),
    }
    rows = static_asset_rows(extension)
    for identity_name, path in STATIC_ASSETS.items():
        old_expected = old_receipt[
            {
                MANIFEST_V1_PATH: "manifest_v1_bytes_sha256",
                MANIFEST_V2_PATH: "manifest_v2_bytes_sha256",
                CARRIER_PATH: "carrier_bytes_sha256",
            }[path]
        ]
        if rows[identity_name].get("sha256") != old_expected:
            refuse(
                f"baseline extension pin changed during generation for {identity_name}"
            )
        rows[identity_name]["sha256"] = generated_hashes[path]

    assets_rs = baseline[ASSETS_RS_PATH].decode("utf-8", "strict")
    assets_rs = replace_exact(
        assets_rs, old_engine_digest, new_engine_digest, 1, "assets.rs engine pin"
    )
    for name in SECTION_NAMES:
        field = f"{name}_sha256"
        assets_rs = replace_exact(
            assets_rs, old_receipt[field], sections[field], 1, f"assets.rs {name} pin"
        )
    for path, new_hash in generated_hashes.items():
        old_field = {
            MANIFEST_V1_PATH: "manifest_v1_bytes_sha256",
            MANIFEST_V2_PATH: "manifest_v2_bytes_sha256",
            CARRIER_PATH: "carrier_bytes_sha256",
        }[path]
        assets_rs = replace_exact(
            assets_rs,
            old_receipt[old_field],
            new_hash,
            1,
            f"assets.rs {Path(path).name} exact-byte pin",
        )
    assets_rs = replace_exact(
        assets_rs,
        old_receipt["qualification_basis_sha256"],
        new_basis,
        1,
        "assets.rs qualification-basis pin",
    )
    assets_rs = replace_exact(
        assets_rs,
        baseline_evaluator,
        requested_evaluator,
        1,
        "assets.rs CAP-H14 evaluator source pin",
    )
    for field in ("identity", "path", "sha256"):
        assets_rs = replace_exact(
            assets_rs,
            require_string(old_review.get(field), f"baseline review {field}"),
            require_string(new_review.get(field), f"generated review {field}"),
            1,
            f"assets.rs post-acceptance review {field} pin",
        )
    capacity_test = baseline[CAPACITY_TEST_PATH].decode("utf-8", "strict")
    capacity_test = replace_exact(
        capacity_test,
        old_receipt["qualification_basis_sha256"],
        new_basis,
        1,
        "capacity test qualification-basis pin",
    )

    generated = {
        EXTENSION_PATH: pretty_json(extension),
        MANIFEST_V1_PATH: manifest_v1_bytes,
        MANIFEST_V2_PATH: manifest_v2_bytes,
        CARRIER_PATH: carrier_bytes,
        ASSETS_RS_PATH: assets_rs.encode("utf-8"),
        CAPACITY_TEST_PATH: capacity_test.encode("utf-8"),
    }
    receipt = verify_chain(
        generated,
        new_engine_digest,
        label="generated",
        review_binding=review_binding,
    )
    receipt["review_disposition"] = (
        "prepared-pre-review-projection-old-verdict-is-not-evidence"
        if prepare_review
        else "accepted-review-binding-installed"
        if review_binding is not None
        else "unchanged-reviewed-projection"
    )
    return generated, receipt


def read_worktree_file(repo: Path, relative: str) -> bytes:
    path = repo / relative
    try:
        metadata = path.lstat()
    except OSError as error:
        refuse(f"cannot inspect worktree file {relative}: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        refuse(f"worktree target must be a regular non-symlink file: {relative}")
    try:
        return path.read_bytes()
    except OSError as error:
        refuse(f"cannot read worktree file {relative}: {error}")


def read_worktree_bundle(repo: Path) -> dict[str, bytes]:
    return {path: read_worktree_file(repo, path) for path in OUTPUT_PATHS}


def load_worktree_review_binding(repo: Path, relative: Path) -> dict[str, Any]:
    path = safe_relative_path(relative.as_posix(), "--review-binding")
    if path != REVIEW_BINDING_PATH:
        refuse(f"--review-binding must name exact campaign path {REVIEW_BINDING_PATH}")
    value = load_json(read_worktree_file(repo, path), "CAP-H14 review binding")
    return require_object(value, "CAP-H14 review binding")


def validate_reviewed_worktree_sources(
    repo: Path, review_binding: Mapping[str, Any]
) -> None:
    source = require_object(review_binding["reviewed_source"], "reviewed source")
    for path_field, digest_field, label in (
        ("evaluator_path", "evaluator_sha256", "reviewed evaluator"),
        (
            "canonical_serializer_path",
            "canonical_serializer_sha256",
            "reviewed canonical serializer",
        ),
    ):
        path = safe_relative_path(source[path_field], f"{label} path")
        observed = sha256_bytes(read_worktree_file(repo, path))
        if observed != source[digest_field]:
            refuse(
                f"worktree {label} differs from fresh review: "
                f"expected {source[digest_field]}, observed {observed}"
            )


def compare_bundle(
    actual: Mapping[str, bytes], expected: Mapping[str, bytes], label: str
) -> None:
    differences = [
        path for path in OUTPUT_PATHS if actual.get(path) != expected.get(path)
    ]
    if differences:
        refuse(f"{label} differs from deterministic chain at: {', '.join(differences)}")


def _write_staged(path: Path, data: bytes, mode: int) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.c1-reanchor-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat.S_IMODE(mode))
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _restore_file(path: Path, data: bytes, mode: int) -> None:
    replacement = _write_staged(path, data, mode)
    try:
        os.replace(replacement, path)
    finally:
        replacement.unlink(missing_ok=True)


def write_bundle_atomically(
    repo: Path, baseline: Mapping[str, bytes], generated: Mapping[str, bytes]
) -> None:
    originals = read_worktree_bundle(repo)
    compare_bundle(originals, baseline, "write precondition: worktree")
    staged: dict[str, Path] = {}
    modes: dict[str, int] = {}
    try:
        for relative in OUTPUT_PATHS:
            target = repo / relative
            mode = target.lstat().st_mode
            modes[relative] = mode
            staged[relative] = _write_staged(target, generated[relative], mode)
        compare_bundle(
            read_worktree_bundle(repo), originals, "write race check: worktree"
        )

        blocked_signals = {signal.SIGINT, signal.SIGTERM}
        previous_mask = None
        if hasattr(signal, "pthread_sigmask"):
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
        replaced: list[str] = []
        try:
            for relative in OUTPUT_PATHS:
                os.replace(staged[relative], repo / relative)
                replaced.append(relative)
            for directory in sorted({(repo / path).parent for path in OUTPUT_PATHS}):
                descriptor = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except BaseException as error:
            restoration_errors: list[str] = []
            for relative in reversed(replaced):
                try:
                    _restore_file(repo / relative, originals[relative], modes[relative])
                except (
                    BaseException
                ) as restore_error:  # pragma: no cover - catastrophic path
                    restoration_errors.append(f"{relative}: {restore_error}")
            if restoration_errors:
                refuse(
                    "write failed and rollback was incomplete: "
                    + "; ".join(restoration_errors)
                )
            refuse(f"write failed; all reported replacements rolled back: {error}")
        finally:
            if previous_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        compare_bundle(
            read_worktree_bundle(repo), generated, "write postcondition: worktree"
        )
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def receipt_document(
    *, mode: str, baseline_commit: str, baseline_tree: str, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "schema": "nq.c1_generation_reanchor_receipt.v1",
        "status": (
            "prepared-for-independent-review-not-qualified"
            if mode == "prepare-review"
            else "verified"
            if mode == "check"
            else "written-and-verified"
        ),
        "mode": mode,
        "baseline_commit": baseline_commit,
        "baseline_tree": baseline_tree,
        "formulas": {
            "section_digest": "sha256(JCS(section-array))",
            "qualification_basis": "sha256(JCS(manifest-v2 excluding qualification_basis, cap_h14_qualification, qualification_gaps))",
            "pre_review_projection": "sha256(JCS(carrier excluding qualification_id and implementation_bindings.post_acceptance_review))",
            "qualification_id": "sha256(JCS(carrier excluding qualification_id))",
            "carrier_bytes": "sha256(exact pretty-JSON carrier bytes)",
        },
        "write_protocol": "validate-all; stage-all; same-directory atomic replace per file; rollback on reported error",
        **receipt,
    }


def parse_args(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="exact repository root (default: parent of this script's scripts directory)",
    )
    parser.add_argument(
        "--baseline-commit",
        default=GEN3_COMMIT,
        help=f"immutable Git baseline (default: exact C1 Gen3 {GEN3_COMMIT})",
    )
    parser.add_argument(
        "--new-engine-sha256",
        help="requested engine.rs SHA-256; defaults to the baseline engine digest",
    )
    parser.add_argument(
        "--review-binding",
        type=Path,
        help=(
            "exact repository-relative fresh CAP-H14 binding; required whenever "
            "the qualification basis or pre-review projection changes"
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify only; never write")
    mode.add_argument(
        "--write", action="store_true", help="explicitly write all six outputs"
    )
    mode.add_argument(
        "--prepare-review",
        action="store_true",
        help=(
            "write an exact pre-review projection after source changes; the old "
            "review verdict is explicitly not evidence for this prepared cut"
        ),
    )
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        repo = resolve_repo(args.repo)
        baseline_commit = resolve_commit(repo, args.baseline_commit)
        baseline_tree = git_tree(repo, baseline_commit)
        baseline_engine_digest = sha256_bytes(
            git_object(repo, baseline_commit, ENGINE_PATH)
        )
        baseline_evaluator_digest = sha256_bytes(
            git_object(repo, baseline_commit, EVALUATOR_PATH)
        )
        baseline = load_git_bundle(repo, baseline_commit)
        baseline_receipt = verify_chain(
            baseline, baseline_engine_digest, label="baseline"
        )
        validate_gen3_receipt(baseline_commit, baseline_tree, baseline_receipt)

        requested = (
            parse_digest(args.new_engine_sha256)
            if args.new_engine_sha256 is not None
            else baseline_engine_digest
        )
        actual_engine = sha256_bytes(read_worktree_file(repo, ENGINE_PATH))
        if actual_engine != requested:
            refuse(
                f"worktree {ENGINE_PATH} is {actual_engine}; requested engine digest is {requested}"
            )
        review_binding = None
        if args.prepare_review and args.review_binding is not None:
            refuse("--prepare-review cannot be combined with --review-binding")
        if args.review_binding is not None:
            review_binding = load_worktree_review_binding(repo, args.review_binding)
            source = require_object(
                review_binding["reviewed_source"], "reviewed source"
            )
            validate_review_binding(
                review_binding,
                require_sha256(
                    source.get("qualification_basis_sha256"),
                    "reviewed qualification basis",
                ),
                require_sha256(
                    source.get("pre_review_projection_sha256"),
                    "reviewed pre-review projection",
                ),
            )
            validate_reviewed_worktree_sources(repo, review_binding)
        generated, receipt = reanchor_bundle(
            baseline,
            baseline_engine_digest,
            requested,
            review_binding=review_binding,
            old_evaluator_digest=baseline_evaluator_digest,
            new_evaluator_digest=sha256_bytes(read_worktree_file(repo, EVALUATOR_PATH)),
            prepare_review=args.prepare_review,
        )

        if args.check:
            compare_bundle(read_worktree_bundle(repo), generated, "check: worktree")
            mode = "check"
        else:
            if all(generated[path] == baseline[path] for path in OUTPUT_PATHS):
                refuse("--write refuses a no-op re-anchor or review rebinding")
            write_bundle_atomically(repo, baseline, generated)
            mode = "prepare-review" if args.prepare_review else "write"
        document = receipt_document(
            mode=mode,
            baseline_commit=baseline_commit,
            baseline_tree=baseline_tree,
            receipt=receipt,
        )
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
