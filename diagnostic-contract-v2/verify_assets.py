#!/usr/bin/env python3
"""Strictly verify the published diagnostic-execution v2 asset corpus."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SOURCE_ROOT = Path(__file__).resolve().parent
MAX_ASSET_BYTES = 4 * 1_048_576
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MANIFEST_SCHEMA = "nq.diagnostic_contract_assets.v2"
CONTRACT_SCHEMA = "nq.diagnostic_execution.v2"
SCHEMA_PATH = "schemas/nq.diagnostic_execution.v2.schema.json"
SCHEMA_SHA256 = (
    "sha256:cb42376d1a1dd551b4bd1b6f2f5e3ecd771a043eb47bb58dcf289616c29f8976"
)
README_SHA256 = (
    "sha256:0ab93a1028f50d50ae3c3d91c95bd07c1be101289756103601c396d39614c805"
)
CANONICALIZATION = {
    "id": "rfc8785-jcs",
    "version": "1",
    "digest": "sha256:e49d92d4e86052e66ed2a481b9386d3b214ce3d2df5fd109a6491ccb9ffb24f3",
}
DIGEST_BASIS = (
    "SHA-256 of exact file bytes; artifact_id is SHA-256 of RFC 8785 "
    "canonical artifact bytes with artifact_id omitted"
)


def fixture(
    fixture_id: str,
    fixture_class: str,
    path: str,
    sha256: str,
    artifact_id: str,
    expected_disposition: str,
    expected_error: str | None = None,
) -> dict[str, str]:
    """Construct one exact manifest fixture entry."""
    entry = {
        "id": fixture_id,
        "class": fixture_class,
        "path": path,
        "sha256": sha256,
        "artifact_id": artifact_id,
        "expected_disposition": expected_disposition,
    }
    if expected_error is not None:
        entry["expected_error"] = expected_error
    return entry


FIXTURES: tuple[dict[str, str], ...] = (
    fixture(
        "acquisition_failure",
        "valid",
        "fixtures/valid/acquisition_failure.json",
        "sha256:0a63887d54a98a84109a9dc443ae4c0287721efa6cd4ac144aff6307278b676f",
        "sha256:ad7d675472581968eff853c69f210d52fd45d49b273ba141f637e51a63fce16b",
        "accepted",
    ),
    fixture(
        "completed_bounded_clock",
        "valid",
        "fixtures/valid/completed_bounded_clock.json",
        "sha256:1abad047be8f475c75be645d687481a928e3d5a963f19373649ce11079a764a2",
        "sha256:22e195c711b0a856f68805ed37b3b595ea1e3913222b03af5045e755f5ae1c1b",
        "accepted",
    ),
    fixture(
        "completed_unqualified_clock",
        "valid",
        "fixtures/valid/completed_unqualified_clock.json",
        "sha256:139728d72143f286c4bcc74cf7db0c587af154f79a049e0492a64de616850956",
        "sha256:28e58c8b72ef7ec09817c33869707a4518961568cf1ee1d81353f02b9c9de20a",
        "accepted",
    ),
    fixture(
        "detector_refusal_detail_a",
        "valid",
        "fixtures/valid/detector_refusal_detail_a.json",
        "sha256:96a2e8d8e9cfe4b412f1302c6b58140c16106db8bad14b72803d67b1c001a68d",
        "sha256:0d96e8e8738ac0619061b159f829003b4bca3e702d90d78daa8910f9dbb0ba48",
        "accepted",
    ),
    fixture(
        "detector_refusal_detail_b",
        "valid",
        "fixtures/valid/detector_refusal_detail_b.json",
        "sha256:4c2811f2c14b2ded6d62bcd41ece0752a2fa7718fe23620b7228195225277820",
        "sha256:b2abdd424c127e843bca0608654f05e08901bf75e439cd3ea7673e3069cbe064",
        "accepted",
    ),
    fixture(
        "multiple_input_refusals",
        "valid",
        "fixtures/valid/multiple_input_refusals.json",
        "sha256:690e35b34f3298bb64d4f474165fa186922198e1324f000c374c51ab613131b3",
        "sha256:01cf8ab574e3499e9811e955d03b3f71fbf531a2b4f368359222d832d6178415",
        "accepted",
    ),
    fixture(
        "provider_no_response",
        "valid",
        "fixtures/valid/provider_no_response.json",
        "sha256:7e012dfda2d372c0dfab9e5a032198bbe874e520f0a8cf38e2edd28151159c7d",
        "sha256:38d5ff58a5905b0d1a9239d2c3a185d01388973d4e108dbc07d080d8f1c46754",
        "accepted",
    ),
    fixture(
        "received_input_refusal",
        "valid",
        "fixtures/valid/received_input_refusal.json",
        "sha256:96d90162193eb19326937d5cb208e04ebddefd069af97bc04c1aedf420e923a6",
        "sha256:c8ae44ac6f82b40398c0e0cac1445f6a2facc302844b2b7e2c06f65960253d70",
        "accepted",
    ),
    fixture(
        "retained_acquisition_refusal",
        "valid",
        "fixtures/valid/retained_acquisition_refusal.json",
        "sha256:6c67feb997af11bf2dbccd21a4dc00e40aaa4edd1f16190613e036020ecc6a4a",
        "sha256:f31ea7589e33b6a80bb0041c02c5523104647b441b56c8d056deb41efb8a760f",
        "accepted",
    ),
    fixture(
        "typed_unsupported",
        "valid",
        "fixtures/valid/typed_unsupported.json",
        "sha256:9dd86054485201b18be986345436061c0aec10f13a6ef7960051475a6732b078",
        "sha256:c83df92791ca63b39c2a0415386eabc97131bd17539ceb1af404159227c77136",
        "accepted",
    ),
    fixture(
        "acquisition_failure_with_timeout",
        "hostile",
        "fixtures/hostile/acquisition_failure_with_timeout.json",
        "sha256:42955382d82491074922f8ece9e39a17d47a976ed6b9ae702114440c315296d6",
        "sha256:ce5bcc83b2eae896ab80a5ff65533588739b3b3937f7cf09cc238cb9f02aa6f3",
        "rejected_semantic_invariant",
        "acquisition_failed carries a provider-no-response failure class",
    ),
    fixture(
        "missing_refusal_frontier_member",
        "hostile",
        "fixtures/hostile/missing_refusal_frontier_member.json",
        "sha256:b41bcc826ed206722007bd7dceede8a9818c0fc2b6b51f0b548993cc5c149032",
        "sha256:645b20e2eda021a27af7ed5359cadace08deb3aa129e4fe14c0d1579b5ec2052",
        "rejected_semantic_invariant",
        "refused outcome must preserve the complete exact refusal frontier",
    ),
    fixture(
        "missing_unsupported_frontier",
        "hostile",
        "fixtures/hostile/missing_unsupported_frontier.json",
        "sha256:cb53c2178ee13af30590ad648461d108be71af1a80987c4d7bd3523d669103f7",
        "sha256:a06f32e653a9bcfa919fc4ddff7f24fbec96c13ab05ba0dade0adc78601a6a0d",
        "rejected_schema",
        "unsupported outcome requires at least one typed unsupported cause",
    ),
    fixture(
        "no_response_with_spawn",
        "hostile",
        "fixtures/hostile/no_response_with_spawn.json",
        "sha256:5bbea55f97bca30c36844ffbc992d58e8a62feb0a9839ba7f17828772830ebe1",
        "sha256:51d749127fd3edee84c7723d65e48defb36c19bbe0065cad9df3933860b8123d",
        "rejected_semantic_invariant",
        "provider_no_response carries an acquisition-failure class",
    ),
    fixture(
        "received_before_acquisition",
        "hostile",
        "fixtures/hostile/received_before_acquisition.json",
        "sha256:99096642e06250217a0c0bbc0b7634aba7298efe6a8f851cab07a8114a2d2983",
        "sha256:03bf25965148d522f0d2f47982908a9e8616da5617dbc966c45b2caa2dd11fa4",
        "rejected_semantic_invariant",
        "received_at falls before acquisition completion or after diagnostic completion",
    ),
    fixture(
        "substituted_failure_dependency",
        "hostile",
        "fixtures/hostile/substituted_failure_dependency.json",
        "sha256:ce959be05465e794625bcce78b9f136393d48a8ab92a9b860afdeb3c0db88d60",
        "sha256:b6e0f810878600a2902e2f1975c22326bc5d8754f358254985c078c3913a1080",
        "rejected_semantic_invariant",
        "claim references an unknown failed-input occurrence",
    ),
)
PUBLIC_FILES = {
    "README.md",
    "manifest.json",
    SCHEMA_PATH,
    *(entry["path"] for entry in FIXTURES),
}
NO_RESPONSE_CLASSES = {"timeout", "eof", "helper_exited", "disconnect"}


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
    normalized = PurePosixPath(relative)
    if (
        not relative
        or normalized.is_absolute()
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
    try:
        return json.loads(
            bounded_path(root, relative).read_bytes(),
            object_pairs_hook=strict_object,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid strict JSON in {relative}: {error}") from error


def sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def file_digest(root: Path, relative: str) -> str:
    return sha256_bytes(bounded_path(root, relative).read_bytes())


def canonical_bytes(value: Any) -> bytes:
    """Canonicalize the deliberately restricted ASCII/I-JSON corpus."""

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
    ).encode()


def expected_manifest() -> dict[str, Any]:
    return {
        "schema": MANIFEST_SCHEMA,
        "digest_basis": DIGEST_BASIS,
        "contract": {
            "schema": CONTRACT_SCHEMA,
            "canonicalization": CANONICALIZATION,
            "schema_path": SCHEMA_PATH,
            "schema_sha256": SCHEMA_SHA256,
        },
        "documentation": {"path": "README.md", "sha256": README_SHA256},
        "fixtures": list(FIXTURES),
    }


def verify_inventory(root: Path) -> None:
    actual: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"diagnostic-contract-v2 asset is a symlink: {relative}")
        if path.is_file():
            if relative == "verify_assets.py":
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                raise ValueError(
                    f"diagnostic-contract-v2 has runtime cache: {relative}"
                )
            actual.add(relative)
        elif not path.is_dir():
            raise ValueError(f"diagnostic-contract-v2 has unsupported type: {relative}")
    if actual != PUBLIC_FILES:
        raise ValueError(
            "diagnostic-contract-v2 asset inventory differs; "
            f"missing={sorted(PUBLIC_FILES - actual)}, "
            f"extra={sorted(actual - PUBLIC_FILES)}"
        )


def verify_schema(root: Path) -> dict[str, Any]:
    if file_digest(root, SCHEMA_PATH) != SCHEMA_SHA256:
        raise ValueError("diagnostic-execution v2 schema file digest differs")
    schema = read_json(root, SCHEMA_PATH)
    if not isinstance(schema, dict):
        raise ValueError("diagnostic-execution v2 schema is not an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError("diagnostic-execution v2 schema does not pin Draft 2020-12")
    if schema.get("$id") != (
        "https://nq.local/schemas/nq.diagnostic_execution.v2.schema.json"
    ):
        raise ValueError("diagnostic-execution v2 schema has the wrong $id")
    if schema.get("title") != CONTRACT_SCHEMA:
        raise ValueError("diagnostic-execution v2 schema has the wrong title")
    if schema.get("additionalProperties") is not False:
        raise ValueError("diagnostic-execution v2 root schema is not closed")
    Draft202012Validator.check_schema(schema)
    return schema


def semantic_disposition(artifact: dict[str, Any]) -> tuple[str, str | None]:
    """Independently evaluate only the hostile invariants represented here."""
    attempt = artifact["attempt_interval"]
    for received in artifact["inputs"]["received"]:
        acquisition = received["acquisition"]
        if acquisition["clock"] != attempt["clock"]:
            return (
                "rejected_semantic_invariant",
                "received acquisition attempt does not use the diagnostic execution clock",
            )
        if acquisition["qualification"] != attempt["qualification"]:
            return (
                "rejected_semantic_invariant",
                "received acquisition attempt changes the diagnostic clock qualification",
            )
        if (
            datetime.fromisoformat(acquisition["started_at"].replace("Z", "+00:00"))
            < datetime.fromisoformat(attempt["started_at"].replace("Z", "+00:00"))
            or datetime.fromisoformat(acquisition["ended_at"].replace("Z", "+00:00"))
            > datetime.fromisoformat(attempt["ended_at"].replace("Z", "+00:00"))
        ):
            return (
                "rejected_semantic_invariant",
                "received acquisition attempt falls outside the diagnostic attempt",
            )
        received_at = datetime.fromisoformat(received["received_at"].replace("Z", "+00:00"))
        acquisition_ended = datetime.fromisoformat(
            acquisition["ended_at"].replace("Z", "+00:00")
        )
        completed_at = datetime.fromisoformat(
            artifact["completed_at"].replace("Z", "+00:00")
        )
        if received_at < acquisition_ended or received_at > completed_at:
            return (
                "rejected_semantic_invariant",
                "received_at falls before acquisition completion or after diagnostic completion",
            )

    failures = {failed["failure_id"]: failed for failed in artifact["inputs"]["failed"]}
    for failed in failures.values():
        cause = failed["cause"]
        if cause["kind"] not in {"provider_no_response", "acquisition_failed"}:
            continue
        failure_class = cause["failure"]["class"]
        if cause["kind"] == "provider_no_response" and (
            failure_class not in NO_RESPONSE_CLASSES
        ):
            return (
                "rejected_semantic_invariant",
                "provider_no_response carries an acquisition-failure class",
            )
        if cause["kind"] == "acquisition_failed" and (
            failure_class in NO_RESPONSE_CLASSES
        ):
            return (
                "rejected_semantic_invariant",
                "acquisition_failed carries a provider-no-response failure class",
            )

    for claim in artifact["claims"]:
        if not set(claim["dependency_failure_ids"]).issubset(failures):
            return (
                "rejected_semantic_invariant",
                "claim references an unknown failed-input occurrence",
            )

    if artifact["outcome"]["derivation"] == "refused":
        input_frontier = sorted(
            (item["refusal"] for item in artifact["inputs"]["refused"]),
            key=lambda item: item["refusal_id"].encode(),
        )
        if input_frontier and input_frontier != artifact["outcome"]["refusals"]:
            return (
                "rejected_semantic_invariant",
                "refused outcome must preserve the complete exact refusal frontier",
            )

    input_unsupported = sorted(
        (
            item["cause"]["unsupported"]
            for item in artifact["inputs"]["failed"]
            if item["cause"]["kind"] == "unsupported"
        ),
        key=lambda item: item["unsupported_id"].encode(),
    )
    if input_unsupported and input_unsupported != artifact["outcome"]["unsupported"]:
        return (
            "rejected_semantic_invariant",
            "unsupported outcome must preserve the complete exact input-unsupported frontier",
        )
    return ("accepted", None)


def verify_fixture(
    root: Path,
    schema: dict[str, Any],
    entry: dict[str, str],
) -> dict[str, Any]:
    relative = entry["path"]
    data = bounded_path(root, relative).read_bytes()
    if sha256_bytes(data) != entry["sha256"]:
        raise ValueError(f"fixture file digest differs: {relative}")
    artifact = read_json(root, relative)
    if not isinstance(artifact, dict):
        raise ValueError(f"fixture is not an object: {relative}")
    if data != canonical_bytes(artifact):
        raise ValueError(f"fixture is not exact canonical JSON: {relative}")
    if artifact.get("schema") != CONTRACT_SCHEMA:
        raise ValueError(f"fixture has the wrong contract schema: {relative}")
    artifact_id = artifact.get("artifact_id")
    if (
        artifact_id != entry["artifact_id"]
        or DIGEST.fullmatch(artifact_id or "") is None
    ):
        raise ValueError(f"fixture artifact_id differs from manifest: {relative}")
    preimage = copy.deepcopy(artifact)
    del preimage["artifact_id"]
    if sha256_bytes(canonical_bytes(preimage)) != artifact_id:
        raise ValueError(f"fixture artifact_id does not bind its preimage: {relative}")

    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(artifact),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if entry["expected_disposition"] == "rejected_schema":
        if not errors:
            raise ValueError(
                f"hostile fixture unexpectedly satisfies schema: {relative}"
            )
        if entry["id"] != "missing_unsupported_frontier" or not any(
            list(error.absolute_path) == ["outcome", "unsupported"]
            and error.validator == "minItems"
            for error in errors
        ):
            raise ValueError(
                f"hostile fixture has an unexpected schema failure: {relative}"
            )
        disposition = (
            "rejected_schema",
            "unsupported outcome requires at least one typed unsupported cause",
        )
    else:
        if errors:
            first = errors[0]
            raise ValueError(
                f"fixture fails v2 schema at {list(first.absolute_path)}: {first.message}"
            )
        disposition = semantic_disposition(artifact)
    if disposition[0] != entry["expected_disposition"]:
        raise ValueError(f"fixture disposition differs from manifest: {relative}")
    if disposition[1] != entry.get("expected_error"):
        raise ValueError(f"fixture error differs from manifest: {relative}")
    return artifact


def verify_relationships(artifacts: dict[str, dict[str, Any]]) -> None:
    bounded = artifacts["completed_bounded_clock"]["attempt_interval"]["qualification"]
    unqualified = artifacts["completed_unqualified_clock"]["attempt_interval"][
        "qualification"
    ]
    if bounded["state"] != "bounded" or set(bounded) != {
        "state",
        "maximum_error_ms",
        "basis",
    }:
        raise ValueError("bounded-clock fixture does not retain its exact basis")
    if unqualified["state"] != "unqualified" or set(unqualified) != {
        "state",
        "code",
        "detail",
    }:
        raise ValueError("unqualified-clock fixture invents a numeric uncertainty")

    first = artifacts["detector_refusal_detail_a"]["outcome"]["refusals"][0]
    second = artifacts["detector_refusal_detail_b"]["outcome"]["refusals"][0]
    first_profile = first["origin"]["payload"]["refusal"]
    second_profile = second["origin"]["payload"]["refusal"]
    if (
        first["refusal_id"] != second["refusal_id"]
        or first_profile["code"] != second_profile["code"]
        or first_profile["boundary"] != second_profile["boundary"]
        or first_profile["details"] == second_profile["details"]
        or artifacts["detector_refusal_detail_a"]["artifact_id"]
        == artifacts["detector_refusal_detail_b"]["artifact_id"]
    ):
        raise ValueError("detector-refusal detail distinction is not preserved")

    multiple = artifacts["multiple_input_refusals"]
    if len(multiple["inputs"]["refused"]) != 2 or (
        multiple["outcome"]["refusals"]
        != [item["refusal"] for item in multiple["inputs"]["refused"]]
    ):
        raise ValueError("multiple refusal fixture does not retain the exact frontier")

    no_response = artifacts["provider_no_response"]["inputs"]["failed"][0]["cause"]
    acquisition = artifacts["acquisition_failure"]["inputs"]["failed"][0]["cause"]
    if (
        no_response["kind"] != "provider_no_response"
        or acquisition["kind"] != "acquisition_failed"
        or no_response["failure"]["class"] == acquisition["failure"]["class"]
    ):
        raise ValueError("provider silence and acquisition failure are not distinct")

    retained = artifacts["retained_acquisition_refusal"]
    if (
        retained["inputs"]["failed"]
        or retained["inputs"]["refused"][0]["refusal"]["origin"]["kind"]
        != "acquisition"
    ):
        raise ValueError(
            "retained acquisition refusal crossed into acquisition failure"
        )

    unsupported = artifacts["typed_unsupported"]
    cause = unsupported["inputs"]["failed"][0]["cause"]["unsupported"]
    if unsupported["outcome"]["unsupported"] != [cause]:
        raise ValueError("typed unsupported cause is not preserved exactly")


def verify(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("diagnostic-contract-v2 root is not a real directory")
    verify_inventory(root)
    manifest = read_json(root, "manifest.json")
    if manifest != expected_manifest():
        raise ValueError("diagnostic-contract-v2 manifest is not exact")
    if file_digest(root, "README.md") != README_SHA256:
        raise ValueError("diagnostic-contract-v2 README digest differs")
    schema = verify_schema(root)
    artifacts = {entry["id"]: verify_fixture(root, schema, entry) for entry in FIXTURES}
    verify_relationships(artifacts)
    return file_digest(root, "manifest.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--asset-root",
        type=Path,
        default=SOURCE_ROOT,
        help="source or staged diagnostic-contract-v2 directory",
    )
    arguments = parser.parse_args()
    manifest_digest = verify(arguments.asset_root.resolve(strict=True))
    print(
        "verified diagnostic-execution v2 schema, exact manifest, "
        f"and {len(FIXTURES)} canonical fixtures; manifest={manifest_digest}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(
            f"diagnostic-contract-v2 verification failed: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
