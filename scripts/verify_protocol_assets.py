#!/usr/bin/env python3
"""Verify the exact published protocol corpus against the release nq binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_FILES = (
    "nq.evidence_report.v1.schema.json",
    "nq.helper.request.v1.schema.json",
    "nq.helper.response.v1.schema.json",
)
SCHEMA_DIGESTS = {
    "nq.evidence_report.v1.schema.json": (
        "6fd75587cafb3f9cf895c47e809af49f9ea0c8e21c3aa2d05708bfcd673c8e14"
    ),
    "nq.helper.request.v1.schema.json": (
        "5b858e770c45551615afff368ac571f7e4a93859b1263d7b419f305ef9d64b28"
    ),
    "nq.helper.response.v1.schema.json": (
        "150a31d90d08e56f1d88967a613ae0b43450427d25eb77316f497218e0629805"
    ),
}
FIXTURE_EXPECTATIONS = (
    ("valid/request.ndjson", "accept_request"),
    ("valid/evidence_report.ndjson", "accept_evidence_report"),
    ("valid/response_report.ndjson", "accept_complete_report_response"),
    ("valid/response_refusal.ndjson", "accept_refusal_response"),
    ("valid/response_failed_report.ndjson", "accept_failed_report_response"),
    ("invalid/request_unknown_field.ndjson", "reject_unknown_field"),
    ("invalid/request_duplicate_key.ndjson", "reject_duplicate_key"),
    ("invalid/request_wrong_version.ndjson", "reject_wrong_protocol_version"),
    ("invalid/response_wrong_echo.ndjson", "reject_wrong_request_echo"),
    ("invalid/response_capability_escape.ndjson", "reject_capability_escape"),
    (
        "invalid/response_failed_without_error.ndjson",
        "reject_failed_report_without_error",
    ),
    ("invalid/extra_frame.ndjson", "reject_extra_frame"),
)
FIXTURE_FILES = ("manifest.json", *(path for path, _ in FIXTURE_EXPECTATIONS))
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_PROTOCOL_ASSET_BYTES = 1_048_576

EXPECTED_SOURCE_MANIFEST: dict[str, Any] = {
    "schema": "nq.protocol.conformance_manifest.v1",
    "request": "valid/request.ndjson",
    "valid": [
        {"path": "valid/evidence_report.ndjson", "document": "evidence_report"},
        {
            "path": "valid/response_report.ndjson",
            "document": "response",
            "outcome": "report",
        },
        {
            "path": "valid/response_refusal.ndjson",
            "document": "response",
            "outcome": "refusal",
        },
        {
            "path": "valid/response_failed_report.ndjson",
            "document": "response",
            "outcome": "failed_report",
        },
    ],
    "invalid": [
        {"path": "invalid/request_unknown_field.ndjson", "phase": "decode"},
        {"path": "invalid/request_duplicate_key.ndjson", "phase": "decode"},
        {
            "path": "invalid/request_wrong_version.ndjson",
            "phase": "protocol_validation",
        },
        {
            "path": "invalid/response_wrong_echo.ndjson",
            "phase": "exchange_validation",
        },
        {
            "path": "invalid/response_capability_escape.ndjson",
            "phase": "exchange_validation",
        },
        {
            "path": "invalid/response_failed_without_error.ndjson",
            "phase": "report_validation",
        },
        {"path": "invalid/extra_frame.ndjson", "phase": "framing"},
    ],
}


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def decode_json(data: str, *, source: str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise ValueError(f"{source}: invalid JSON: {error}") from error


def read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"protocol asset must be a regular non-symlink file: {path}")
    try:
        if path.stat().st_size > MAX_PROTOCOL_ASSET_BYTES:
            raise ValueError(
                f"protocol JSON exceeds {MAX_PROTOCOL_ASSET_BYTES} bytes: {path}"
            )
        return decode_json(path.read_text(encoding="utf-8"), source=str(path))
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error


def exact_file_inventory(root: Path, expected: set[str]) -> None:
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"protocol asset cannot be a symlink: {path}")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise ValueError(f"protocol asset has an unsupported type: {path}")
    if actual != expected:
        raise ValueError(
            "protocol asset inventory differs from v1; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def corpus_digest(fixtures: Path) -> str:
    entries = []
    for relative, expectation in FIXTURE_EXPECTATIONS:
        path = fixtures / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"fixture must be a regular non-symlink file: {relative}")
        if path.stat().st_size > MAX_PROTOCOL_ASSET_BYTES:
            raise ValueError(
                f"fixture exceeds {MAX_PROTOCOL_ASSET_BYTES} bytes: {relative}"
            )
        hasher = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(64 * 1024), b""):
                hasher.update(block)
        entries.append(
            {
                "path": relative,
                "expectation": expectation,
                "content_digest": f"sha256:{hasher.hexdigest()}",
            }
        )
    digest_manifest = {
        "schema": "nq.protocol.conformance_digest_manifest.v1",
        "protocol_version": "nq.helper.v1",
        "fixtures": entries,
    }
    # This manifest contains only ASCII strings and arrays. Sorted compact JSON
    # is therefore byte-identical to its RFC 8785 canonical representation.
    canonical = json.dumps(
        digest_manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def verify_schemas(schemas: Path) -> None:
    exact_file_inventory(schemas, set(SCHEMA_FILES))
    for name in SCHEMA_FILES:
        value = read_json(schemas / name)
        title = name.removesuffix(".schema.json")
        expected_id = f"https://nq.local/schemas/{name}"
        if not isinstance(value, dict):
            raise ValueError(f"schema {name} is not an object")
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ValueError(f"schema {name} does not pin JSON Schema 2020-12")
        if value.get("$id") != expected_id or value.get("title") != title:
            raise ValueError(f"schema {name} has the wrong identity")
        hasher = hashlib.sha256()
        with (schemas / name).open("rb") as source:
            for block in iter(lambda: source.read(64 * 1024), b""):
                hasher.update(block)
        if hasher.hexdigest() != SCHEMA_DIGESTS[name]:
            raise ValueError(f"schema {name} bytes differ from the immutable v1 contract")


def verify_receipt(binary: Path, expected_version: str, digest: str) -> None:
    try:
        completed = subprocess.run(
            [str(binary), "--json", "protocol", "check"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(f"cannot execute protocol verifier {binary}: {error}") from error
    if completed.returncode != 0:
        raise ValueError(
            f"protocol verifier exited {completed.returncode}: {completed.stderr.strip()}"
        )
    if completed.stderr:
        raise ValueError("protocol verifier emitted unexpected stderr")
    receipt = decode_json(completed.stdout, source=str(binary))
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema",
        "version",
        "fixtures_checked",
        "valid_fixtures_accepted",
        "invalid_fixtures_rejected",
    }:
        raise ValueError("protocol verifier returned a malformed receipt")
    version = receipt["version"]
    if not isinstance(version, dict) or set(version) != {
        "protocol_version",
        "manifest_schema",
        "verifier_version",
        "corpus_digest",
    }:
        raise ValueError("protocol verifier returned a malformed version summary")
    expected = {
        "protocol_version": "nq.helper.v1",
        "manifest_schema": "nq.protocol.conformance_digest_manifest.v1",
        "verifier_version": expected_version,
        "corpus_digest": digest,
    }
    if receipt["schema"] != "nq.protocol.conformance_receipt.v1" or version != expected:
        raise ValueError("protocol verifier receipt differs from published assets")
    if (
        receipt["fixtures_checked"] != 12
        or receipt["valid_fixtures_accepted"] != 5
        or receipt["invalid_fixtures_rejected"] != 7
    ):
        raise ValueError("protocol verifier receipt has the wrong fixture counts")
    if DIGEST.fullmatch(version["corpus_digest"]) is None:
        raise ValueError("protocol verifier returned an invalid corpus digest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("protocol_dir", type=Path)
    parser.add_argument("nq", type=Path)
    parser.add_argument("version")
    arguments = parser.parse_args()

    protocol_dir = arguments.protocol_dir.resolve(strict=True)
    binary = arguments.nq.resolve(strict=True)
    verify_schemas(protocol_dir / "schemas")
    fixtures = protocol_dir / "fixtures"
    exact_file_inventory(fixtures, set(FIXTURE_FILES))
    if read_json(fixtures / "manifest.json") != EXPECTED_SOURCE_MANIFEST:
        raise ValueError("fixture manifest differs from the compiled v1 inventory")
    digest = corpus_digest(fixtures)
    verify_receipt(binary, arguments.version, digest)
    print(f"verified {len(SCHEMA_FILES)} schemas and {len(FIXTURE_EXPECTATIONS)} fixtures")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"protocol release verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
