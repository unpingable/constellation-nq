#!/usr/bin/env python3
"""Verify packaged descriptors against the catalog compiled into an nq binary."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
DESCRIPTOR_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,245}\.json\Z")
PROFILE_ID = re.compile(r"[A-Za-z0-9._:/@-]{1,255}\Z")
CATALOG_SCHEMA = "nq.profile_catalog.v1"
CATALOG_FIELDS = {"schema", "digest_basis", "generated_by", "profiles"}
ENTRY_FIELDS = {"id", "version", "descriptor", "semantic_digest"}
EXPECTED_DIGEST_BASIS = (
    "RFC 8785 canonical descriptor JSON, SHA-256, qualified as sha256:<hex>"
)
EXPECTED_GENERATOR = "nq profiles show"
MAX_CATALOG_JSON_BYTES = 1_048_576
FAILURE_CODES_NAME = "failure-codes.json"
FAILURE_CODES_SCHEMA = "nq.profile_failure_codes.v1"
FAILURE_CODES_FIELDS = {"schema", "generated_by", "profiles"}
FAILURE_CODES_GENERATOR = "nq profiles failure-codes"
FAILURE_CODE_TOKEN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Decode one JSON object while refusing duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def decode_strict_json(data: str, *, source: str) -> Any:
    """Decode exactly one strict JSON document with a bounded diagnostic."""
    try:
        return json.loads(data, object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise ValueError(f"{source}: invalid JSON: {error}") from error


def read_strict_json(path: Path) -> Any:
    """Read and strictly decode a catalog artifact."""
    try:
        if path.stat().st_size > MAX_CATALOG_JSON_BYTES:
            raise ValueError(f"catalog JSON exceeds {MAX_CATALOG_JSON_BYTES} bytes: {path}")
        return decode_strict_json(path.read_text(encoding="utf-8"), source=str(path))
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error


def invoke(binary: Path, *arguments: str) -> Any:
    completed = subprocess.run(
        [str(binary), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.stderr:
        raise ValueError(f"{binary} emitted unexpected stderr")
    return decode_strict_json(completed.stdout, source=str(binary))


def load_manifest(catalog_dir: Path) -> list[dict[str, Any]]:
    """Validate the complete catalog manifest and exact descriptor inventory."""
    manifest_path = catalog_dir / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("catalog manifest.json must be a regular non-symlink file")
    manifest = read_strict_json(manifest_path)
    if not isinstance(manifest, dict) or set(manifest) != CATALOG_FIELDS:
        raise ValueError("catalog manifest has missing or unknown fields")
    if manifest["schema"] != CATALOG_SCHEMA:
        raise ValueError("catalog manifest has the wrong schema")
    if manifest["digest_basis"] != EXPECTED_DIGEST_BASIS:
        raise ValueError("catalog manifest has the wrong digest basis")
    if manifest["generated_by"] != EXPECTED_GENERATOR:
        raise ValueError("catalog manifest has the wrong generator identity")

    entries = manifest["profiles"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise ValueError("catalog manifest must contain between one and 256 profiles")

    identities: set[tuple[str, int]] = set()
    descriptor_names: set[str] = set()
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
            raise ValueError(
                f"catalog profile entry {position} has missing or unknown fields"
            )
        profile_id = entry["id"]
        version = entry["version"]
        descriptor = entry["descriptor"]
        digest = entry["semantic_digest"]
        if not isinstance(profile_id, str) or PROFILE_ID.fullmatch(profile_id) is None:
            raise ValueError(f"catalog profile entry {position} has an invalid id")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError(f"catalog profile entry {position} has an invalid version")
        if (
            not isinstance(descriptor, str)
            or DESCRIPTOR_NAME.fullmatch(descriptor) is None
            or descriptor == "manifest.json"
        ):
            raise ValueError(
                f"catalog profile entry {position} has an unsafe descriptor name"
            )
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise ValueError(f"catalog profile entry {position} has an invalid digest")
        identity = (profile_id, version)
        if identity in identities:
            raise ValueError(f"duplicate catalog profile identity {profile_id} v{version}")
        if descriptor in descriptor_names:
            raise ValueError(f"duplicate catalog descriptor name {descriptor}")
        identities.add(identity)
        descriptor_names.add(descriptor)

    actual_names: set[str] = set()
    for path in catalog_dir.iterdir():
        if path.name in ("manifest.json", FAILURE_CODES_NAME) or path.suffix != ".json":
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"catalog descriptor must be a regular file: {path.name}")
        actual_names.add(path.name)
    if actual_names != descriptor_names:
        missing = sorted(descriptor_names - actual_names)
        extra = sorted(actual_names - descriptor_names)
        raise ValueError(
            f"descriptor inventory differs from manifest; missing={missing}, extra={extra}"
        )
    return entries


def normalize_vocabularies(value: Any, *, source: str) -> dict[tuple[str, int], list[str]]:
    """Validate one failure-vocabulary listing: profile keys, unique tokens."""
    if not isinstance(value, list):
        raise ValueError(f"{source}: failure vocabularies are not an array")
    result: dict[tuple[str, int], list[str]] = {}
    for position, entry in enumerate(value):
        if not isinstance(entry, dict) or set(entry) != {"id", "version", "codes"}:
            raise ValueError(f"{source}: vocabulary entry {position} has missing or unknown fields")
        profile_id, version, codes = entry["id"], entry["version"], entry["codes"]
        if not isinstance(profile_id, str) or PROFILE_ID.fullmatch(profile_id) is None:
            raise ValueError(f"{source}: vocabulary entry {position} has an invalid id")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError(f"{source}: vocabulary entry {position} has an invalid version")
        if not isinstance(codes, list) or len(codes) > 256:
            raise ValueError(f"{source}: {profile_id} v{version} codes are not a bounded array")
        seen: set[str] = set()
        for code in codes:
            if not isinstance(code, str) or FAILURE_CODE_TOKEN.fullmatch(code) is None:
                raise ValueError(f"{source}: {profile_id} v{version} has a non-token code {code!r}")
            if code in seen:
                raise ValueError(f"{source}: {profile_id} v{version} lists {code} twice")
            seen.add(code)
        key = (profile_id, version)
        if key in result:
            raise ValueError(f"{source}: duplicate vocabulary for {profile_id} v{version}")
        result[key] = list(codes)
    return result


def verify_failure_codes(
    binary: Path,
    catalog_dir: Path,
    manifest_keys: set[tuple[str, int]],
    helper: Path | None,
) -> int:
    """Check the published owner vocabularies against the compiled ones.

    Each owner's enum is the source of truth; the packaged file is its
    publication. A removed or added token, a duplicate, a non-token, a
    vocabulary for a profile the manifest does not list, and a helper binary
    that disagrees with `nq` about any profile it serves are all errors.
    """
    path = catalog_dir / FAILURE_CODES_NAME
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{FAILURE_CODES_NAME} must be a regular non-symlink file")
    packaged = read_strict_json(path)
    if not isinstance(packaged, dict) or set(packaged) != FAILURE_CODES_FIELDS:
        raise ValueError(f"{FAILURE_CODES_NAME} has missing or unknown fields")
    if packaged["schema"] != FAILURE_CODES_SCHEMA:
        raise ValueError(f"{FAILURE_CODES_NAME} has the wrong schema")
    if packaged["generated_by"] != FAILURE_CODES_GENERATOR:
        raise ValueError(f"{FAILURE_CODES_NAME} has the wrong generator identity")
    published = normalize_vocabularies(packaged["profiles"], source=FAILURE_CODES_NAME)
    compiled = normalize_vocabularies(
        invoke(binary, "profiles", "failure-codes"), source="nq profiles failure-codes"
    )
    if set(published) != manifest_keys or set(compiled) != manifest_keys:
        raise ValueError("failure vocabularies must cover exactly the manifest's profiles")
    for key in sorted(manifest_keys):
        if published[key] != compiled[key]:
            removed = sorted(set(published[key]) - set(compiled[key]))
            added = sorted(set(compiled[key]) - set(published[key]))
            raise ValueError(
                f"{key}: published failure vocabulary differs from the compiled owner enum;"
                f" removed={removed}, added={added}, order_or_duplicates_changed={not removed and not added}"
            )
    counted = sum(len(codes) for codes in compiled.values())
    if helper is not None:
        served = normalize_vocabularies(invoke(helper, "--failure-codes"), source=str(helper))
        for key, codes in served.items():
            if key not in compiled:
                raise ValueError(f"helper serves {key}, which nq does not compile")
            if codes != compiled[key]:
                raise ValueError(f"{key}: the helper's vocabulary differs from nq's")
    return counted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nq", type=Path, help="path to the nq binary under test")
    parser.add_argument(
        "--helper",
        type=Path,
        default=None,
        help="optional nq-host-resource-helper binary whose served vocabularies must equal nq's",
    )
    parser.add_argument(
        "--catalog-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="descriptor/manifest directory (defaults to this script's directory)",
    )
    arguments = parser.parse_args()

    binary = arguments.nq.resolve(strict=True)
    catalog_dir = arguments.catalog_dir.resolve(strict=True)
    entries = load_manifest(catalog_dir)
    compiled = invoke(binary, "profiles", "list")
    if not isinstance(compiled, list):
        raise ValueError("compiled profile catalog is not an array")
    compiled_by_key: dict[tuple[str, int], str] = {}
    for position, entry in enumerate(compiled):
        if not isinstance(entry, dict) or set(entry) != {
            "id",
            "version",
            "digest",
            "family",
            "title",
        }:
            raise ValueError(
                f"compiled profile entry {position} has missing or unknown fields"
            )
        profile_id = entry["id"]
        version = entry["version"]
        digest = entry["digest"]
        if (
            not isinstance(profile_id, str)
            or PROFILE_ID.fullmatch(profile_id) is None
            or isinstance(version, bool)
            or not isinstance(version, int)
            or version <= 0
            or not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
        ):
            raise ValueError(f"compiled profile entry {position} is invalid")
        identity = (profile_id, version)
        if identity in compiled_by_key:
            raise ValueError("compiled profile catalog contains a duplicate identity")
        compiled_by_key[identity] = digest
    manifest_by_key = {
        (entry["id"], entry["version"]): entry for entry in entries
    }
    if set(compiled_by_key) != set(manifest_by_key):
        raise ValueError("manifest profile keys differ from the compiled registry")

    for key, entry in manifest_by_key.items():
        digest = entry["semantic_digest"]
        if DIGEST.fullmatch(digest) is None:
            raise ValueError(f"{key}: semantic digest is not qualified SHA-256")
        if digest != compiled_by_key[key]:
            raise ValueError(f"{key}: semantic digest differs from the compiled registry")

        descriptor_path = catalog_dir / entry["descriptor"]
        packaged_descriptor = read_strict_json(descriptor_path)
        compiled_descriptor = invoke(binary, "profiles", "show", key[0], str(key[1]))
        if packaged_descriptor != compiled_descriptor:
            raise ValueError(f"{key}: packaged descriptor differs from the compiled module")

    counted = verify_failure_codes(binary, catalog_dir, set(manifest_by_key), arguments.helper)
    print(
        f"verified {len(manifest_by_key)} compiled profile descriptors and"
        f" {counted} owner failure codes"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as error:
        print(f"profile catalog verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
