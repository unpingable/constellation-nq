#!/usr/bin/env python3
"""Strictly verify the published diagnostic-execution v1 asset corpus."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SOURCE_ROOT = Path(__file__).resolve().parent
MAX_ASSET_BYTES = 4 * 1_048_576
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MANIFEST_SCHEMA = "nq.diagnostic_contract_assets.v1"
CONTRACT_SCHEMA = "nq.diagnostic_execution.v1"
SCHEMA_PATH = "schemas/nq.diagnostic_execution.v1.schema.json"
SCHEMA_SHA256 = "sha256:76d3ba3b74f7645a6f87c23094ceb089cd7fe238d9ab387b0d86c0bd53a57c93"
README_SHA256 = "sha256:4b4dc83d2ad6701dcdc5a691425cff0cd87fc16de9b9091f8ede886a776cc85f"
CANONICALIZATION = {
    "id": "rfc8785-jcs",
    "version": "1",
    "digest": "sha256:e49d92d4e86052e66ed2a481b9386d3b214ce3d2df5fd109a6491ccb9ffb24f3",
}
DIGEST_BASIS = (
    "SHA-256 of exact file bytes; artifact_id is SHA-256 of RFC 8785 "
    "canonical artifact bytes with artifact_id omitted"
)
FIXTURES: tuple[dict[str, str], ...] = (
    {
        "id": "positive",
        "class": "valid",
        "path": "fixtures/valid/positive.json",
        "sha256": "sha256:89c7f685aa4aa717484dabe99b06e6ace9b8554f6e7be8e8b63fd9bf45df1545",
        "artifact_id": "sha256:e9902caf4fcda034201f7ffea6442e692fd3ca110831d585c55d0eb81d8f8862",
        "expected_disposition": "accepted",
    },
    {
        "id": "provider_no_response",
        "class": "valid",
        "path": "fixtures/valid/provider_no_response.json",
        "sha256": "sha256:0f423c64a49b108971f2c13c92553457bf2fb7c6ec050270a4587d7620bbe628",
        "artifact_id": "sha256:2317140a92006ccff37cac92cb129e92c7d1205f0676457c364cc43055d80dab",
        "expected_disposition": "accepted",
    },
    {
        "id": "refused",
        "class": "valid",
        "path": "fixtures/valid/refused.json",
        "sha256": "sha256:07680b2bada81225358a1203df2e67154ec3eccfc8a3c7225704d201ccdaaed3",
        "artifact_id": "sha256:b47d3e5b82999221a31ffe18eaedf134bf3d69cd9cc9c09c5b4db5d3df1bc68c",
        "expected_disposition": "accepted",
    },
    {
        "id": "projection_collision_match",
        "class": "hostile",
        "path": "fixtures/hostile/projection_collision_match.json",
        "sha256": "sha256:e70ebbf3d4745e063d33c664bf8063b2c56fc893f28a00b11215055264a4e609",
        "artifact_id": "sha256:44d77dd1d806c7ff7be5d60b0b8437629ca1feeb20ff64859eeaa945f449ffc5",
        "expected_disposition": "rejected_semantic_invariant",
        "expected_error": "claim requires a distinction omitted by the projection",
    },
    {
        "id": "projection_collision_mismatch",
        "class": "hostile",
        "path": "fixtures/hostile/projection_collision_mismatch.json",
        "sha256": "sha256:74fda36f49652838a715e5c57dcecf27778963f27dbc3d2892a4a319118bb3cd",
        "artifact_id": "sha256:6fb8b66b669181db8f592ceca3b159f1f2d300e24ce3608cf453ca71f9f55af1",
        "expected_disposition": "rejected_semantic_invariant",
        "expected_error": "claim requires a distinction omitted by the projection",
    },
)
SOURCE_VECTOR_NAMES = {
    "positive": "positive.json",
    "provider_no_response": "provider_no_response.json",
    "refused": "refused.json",
    "projection_collision_match": "hostile_projection_collision_match.json",
    "projection_collision_mismatch": "hostile_projection_collision_mismatch.json",
}
PUBLIC_FILES = {
    "README.md",
    "manifest.json",
    SCHEMA_PATH,
    *(entry["path"] for entry in FIXTURES),
}


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Decode an object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def bounded_path(root: Path, relative: str) -> Path:
    """Resolve one exact corpus-relative regular file without traversal."""
    if not isinstance(relative, str) or not relative:
        raise ValueError("asset path must be a non-empty string")
    normalized = PurePosixPath(relative)
    if (
        normalized.is_absolute()
        or normalized.as_posix() != relative
        or any(part in {"", ".", ".."} for part in normalized.parts)
    ):
        raise ValueError(f"asset path is not normalized and relative: {relative!r}")
    path = root.joinpath(*normalized.parts)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"asset is not a regular non-symlink file: {relative}")
    if path.stat().st_size > MAX_ASSET_BYTES:
        raise ValueError(f"asset exceeds {MAX_ASSET_BYTES} bytes: {relative}")
    return path


def read_json(root: Path, relative: str) -> Any:
    """Read one bounded strict JSON asset."""
    path = bounded_path(root, relative)
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid strict JSON in {relative}: {error}") from error


def sha256_bytes(data: bytes) -> str:
    """Return an algorithm-qualified SHA-256 digest."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def file_digest(root: Path, relative: str) -> str:
    """Return an algorithm-qualified digest of exact file bytes."""
    return sha256_bytes(bounded_path(root, relative).read_bytes())


def canonical_bytes(value: Any) -> bytes:
    """Canonicalize the deliberately restricted ASCII/I-JSON corpus.

    The published fixtures use ASCII object keys and strings, exact I-JSON
    integers, and no floating-point values. Compact sorted Python JSON is
    therefore byte-identical to RFC 8785 JCS for this corpus. General artifact
    canonicalization remains the responsibility of the NQ implementation.
    """

    def inspect(child: Any) -> None:
        if child is None or isinstance(child, bool):
            return
        if isinstance(child, int):
            if abs(child) > 9_007_199_254_740_991:
                raise ValueError("fixture integer is outside the exact I-JSON range")
            return
        if isinstance(child, float):
            raise ValueError("fixture corpus may not contain floating-point JSON")
        if isinstance(child, str):
            if not child.isascii():
                raise ValueError("fixture corpus must use ASCII strings")
            return
        if isinstance(child, list):
            for item in child:
                inspect(item)
            return
        if isinstance(child, dict):
            for key, item in child.items():
                if not key.isascii():
                    raise ValueError("fixture corpus must use ASCII object keys")
                inspect(item)
            return
        raise ValueError(f"unsupported JSON value {type(child).__name__}")

    inspect(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def expected_manifest() -> dict[str, Any]:
    """Return the exact closed v1 public manifest."""
    return {
        "schema": MANIFEST_SCHEMA,
        "digest_basis": DIGEST_BASIS,
        "contract": {
            "schema": CONTRACT_SCHEMA,
            "canonicalization": CANONICALIZATION,
            "schema_path": SCHEMA_PATH,
            "schema_sha256": SCHEMA_SHA256,
        },
        "documentation": {
            "path": "README.md",
            "sha256": README_SHA256,
        },
        "fixtures": list(FIXTURES),
    }


def verify_inventory(root: Path) -> None:
    """Refuse missing, extra, symlinked, or special public assets."""
    actual: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"diagnostic-contract asset cannot be a symlink: {relative}")
        if path.is_file():
            if relative == "verify_assets.py":
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                raise ValueError(f"diagnostic-contract contains runtime cache: {relative}")
            actual.add(relative)
        elif not path.is_dir():
            raise ValueError(f"diagnostic-contract has unsupported type: {relative}")
    if actual != PUBLIC_FILES:
        raise ValueError(
            "diagnostic-contract asset inventory differs from v1; "
            f"missing={sorted(PUBLIC_FILES - actual)}, "
            f"extra={sorted(actual - PUBLIC_FILES)}"
        )


def verify_schema(root: Path) -> dict[str, Any]:
    """Verify exact schema bytes, identity, closure, and Draft 2020-12 validity."""
    if file_digest(root, SCHEMA_PATH) != SCHEMA_SHA256:
        raise ValueError("diagnostic-execution schema file digest differs from v1")
    schema = read_json(root, SCHEMA_PATH)
    if not isinstance(schema, dict):
        raise ValueError("diagnostic-execution schema is not an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError("diagnostic-execution schema does not pin Draft 2020-12")
    if schema.get("$id") != "https://nq.local/schemas/nq.diagnostic_execution.v1.schema.json":
        raise ValueError("diagnostic-execution schema has the wrong $id")
    if schema.get("title") != CONTRACT_SCHEMA:
        raise ValueError("diagnostic-execution schema has the wrong title")
    if schema.get("additionalProperties") is not False:
        raise ValueError("diagnostic-execution root schema is not closed")
    Draft202012Validator.check_schema(schema)
    return schema


def semantic_disposition(artifact: dict[str, Any]) -> tuple[str, str | None]:
    """Evaluate the hostile projection-loss invariant represented by the corpus.

    This narrow independent check does not replace NQ's complete executable
    semantic validator. Exact fixture hashes bind every other accepted semantic
    result to the Rust-qualified frozen corpus.
    """
    omitted = {
        item["code"]
        for item in artifact["projection"]["omitted_distinctions"]
        if isinstance(item, dict) and isinstance(item.get("code"), str)
    }
    for claim in artifact["claims"]:
        required = set(claim["required_distinctions"])
        if required & omitted:
            return (
                "rejected_semantic_invariant",
                "claim requires a distinction omitted by the projection",
            )
    return ("accepted", None)


def verify_fixture(
    root: Path,
    schema: dict[str, Any],
    entry: dict[str, str],
    source_vectors: Path | None,
) -> dict[str, Any]:
    """Verify one exact fixture and its optional frozen-source copy."""
    relative = entry["path"]
    data = bounded_path(root, relative).read_bytes()
    if sha256_bytes(data) != entry["sha256"]:
        raise ValueError(f"fixture file digest differs from v1: {relative}")
    artifact = read_json(root, relative)
    if not isinstance(artifact, dict):
        raise ValueError(f"fixture is not an object: {relative}")

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(artifact), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ValueError(f"fixture fails structural schema at {path}: {first.message}")

    if canonical_bytes(artifact) != data:
        raise ValueError(f"fixture is not the unique canonical JSON bytes: {relative}")
    if artifact["canonicalization"] != CANONICALIZATION:
        raise ValueError(f"fixture has wrong canonicalization identity: {relative}")
    if artifact["artifact_id"] != entry["artifact_id"]:
        raise ValueError(f"fixture artifact_id differs from manifest: {relative}")
    preimage = copy.deepcopy(artifact)
    del preimage["artifact_id"]
    computed_artifact_id = sha256_bytes(canonical_bytes(preimage))
    if computed_artifact_id != entry["artifact_id"]:
        raise ValueError(f"fixture artifact_id does not identify its preimage: {relative}")

    disposition, error = semantic_disposition(artifact)
    if disposition != entry["expected_disposition"]:
        raise ValueError(f"fixture has the wrong semantic disposition: {relative}")
    if entry.get("expected_error") != error:
        raise ValueError(f"fixture has the wrong expected semantic error: {relative}")

    if source_vectors is not None:
        source_name = SOURCE_VECTOR_NAMES[entry["id"]]
        source = source_vectors / source_name
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"frozen source vector is missing: {source}")
        if source.stat().st_size > MAX_ASSET_BYTES:
            raise ValueError(f"frozen source vector exceeds size bound: {source}")
        if source.read_bytes() != data:
            raise ValueError(f"published fixture differs from frozen source vector: {relative}")
    return artifact


def verify_relationships(artifacts: dict[str, dict[str, Any]]) -> None:
    """Preserve the corpus's key distinction and collision relationships."""
    positive = artifacts["positive"]
    refused = artifacts["refused"]
    no_response = artifacts["provider_no_response"]
    matching = artifacts["projection_collision_match"]
    mismatching = artifacts["projection_collision_mismatch"]

    if (
        positive["outcome"]["derivation"] != "completed"
        or positive["outcome"]["coverage"] != "complete"
        or positive["outcome"]["coherence"] != "jointly_established"
    ):
        raise ValueError("positive fixture no longer represents complete joint derivation")
    if (
        refused["outcome"]["derivation"] != "refused"
        or len(refused["inputs"]["refused"]) != 1
        or refused["inputs"]["failed"]
    ):
        raise ValueError("refused fixture no longer represents explicit NQ refusal")
    if (
        no_response["outcome"]["derivation"] != "partial"
        or no_response["inputs"]["refused"]
        or len(no_response["inputs"]["failed"]) != 1
        or no_response["inputs"]["failed"][0]["kind"] != "no_response"
    ):
        raise ValueError("provider-no-response fixture no longer preserves acquisition failure")
    match_raw = matching["inputs"]["received"][0]["raw_artifact_id"]
    mismatch_raw = mismatching["inputs"]["received"][0]["raw_artifact_id"]
    match_projection = matching["inputs"]["admitted"][0]["projected_artifact_id"]
    mismatch_projection = mismatching["inputs"]["admitted"][0]["projected_artifact_id"]
    if match_raw == mismatch_raw or match_projection != mismatch_projection:
        raise ValueError("hostile vectors no longer demonstrate a projection collision")


def verify(root: Path, source_vectors: Path | None) -> str:
    """Verify the complete closed asset boundary and return its manifest digest."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("diagnostic-contract root must be a real directory")
    verify_inventory(root)
    manifest = read_json(root, "manifest.json")
    if manifest != expected_manifest():
        raise ValueError("diagnostic-contract manifest differs from the immutable v1 inventory")
    if file_digest(root, "README.md") != README_SHA256:
        raise ValueError("diagnostic-contract README file digest differs from v1")
    schema = verify_schema(root)
    artifacts = {
        entry["id"]: verify_fixture(root, schema, entry, source_vectors)
        for entry in FIXTURES
    }
    verify_relationships(artifacts)
    return file_digest(root, "manifest.json")


def main() -> int:
    """Verify source or staged assets."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument(
        "--source-vectors",
        type=Path,
        help="optional frozen audit vector directory for byte-equality proof",
    )
    arguments = parser.parse_args()
    root = arguments.asset_root.resolve(strict=True)
    source_vectors = (
        arguments.source_vectors.resolve(strict=True)
        if arguments.source_vectors is not None
        else None
    )
    manifest_digest = verify(root, source_vectors)
    print(
        f"verified diagnostic contract: 1 schema, {len(FIXTURES)} fixtures, "
        f"manifest={manifest_digest}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"diagnostic-contract verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
