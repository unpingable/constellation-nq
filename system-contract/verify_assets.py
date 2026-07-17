#!/usr/bin/env python3
"""Strictly verify the versioned public system-contract asset corpus."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, RefResolver


ROOT = Path(__file__).resolve().parent
MAX_DOCUMENT_BYTES = 4 * 1_048_576
MANIFEST_FIELDS = {
    "schema",
    "digest_basis",
    "definitions_schema",
    "contracts",
    "compiled_profile_fixture",
    "synthetic_digest_inputs",
}
CONTRACT_FIELDS = {
    "schema",
    "schema_path",
    "schema_sha256",
    "fixture_path",
    "fixture_sha256",
    "semantic_digest",
}
EXPECTED_SCHEMAS = {
    "nq.system_spec.v1",
    "nq.scope_cut_proposal.v1",
    "nq.scope_cut.v1",
    "nq.observation_projection.v1",
    "nq.porter_actuation_projection.v1",
}
DIGEST_BASIS = "RFC 8785 canonical JSON; versioned artifacts hash {schema,artifact}"


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Decode an object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def asset_path(relative: str) -> Path:
    """Resolve one bounded corpus-relative regular file without traversal."""
    if not isinstance(relative, str) or not relative:
        raise ValueError("asset path must be a non-empty string")
    normalized = PurePosixPath(relative)
    if (
        normalized.is_absolute()
        or normalized.as_posix() != relative
        or any(part in {"", ".", ".."} for part in normalized.parts)
    ):
        raise ValueError(f"asset path is not normalized and relative: {relative!r}")
    path = ROOT.joinpath(*normalized.parts)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"asset is not a regular non-symlink file: {relative}")
    if path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError(f"asset exceeds {MAX_DOCUMENT_BYTES} bytes: {relative}")
    return path


def read_json(relative: str) -> Any:
    """Read one bounded, regular, non-symlink strict JSON artifact."""
    path = asset_path(relative)
    data = path.read_bytes()
    try:
        return json.loads(data, object_pairs_hook=strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid strict JSON in {relative}: {error}") from error


def file_digest(relative: str) -> str:
    """Return an algorithm-qualified digest of exact file bytes."""
    hasher = hashlib.sha256()
    with asset_path(relative).open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            hasher.update(block)
    return f"sha256:{hasher.hexdigest()}"


def read_external_json(path: Path) -> Any:
    """Strictly read one bounded external catalog without following a symlink."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"profile catalog is not a regular non-symlink file: {path}")
    if path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError(f"profile catalog exceeds {MAX_DOCUMENT_BYTES} bytes: {path}")
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid strict profile catalog JSON in {path}: {error}") from error


def verify_profile_catalog(profile: dict[str, Any], catalog_path: Path) -> None:
    """Bind the fixture obligation to the exact profile catalog being packaged."""
    catalog = read_external_json(catalog_path)
    if not isinstance(catalog, dict) or catalog.get("schema") != "nq.profile_catalog.v1":
        raise ValueError("profile catalog has the wrong schema")
    profiles = catalog.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("profile catalog profiles are not an array")
    matches = [
        entry
        for entry in profiles
        if isinstance(entry, dict)
        and entry.get("id") == profile["id"]
        and str(entry.get("version")) == profile["version"]
    ]
    if len(matches) != 1:
        raise ValueError("packaged profile catalog lacks the exact contract fixture profile")
    if matches[0].get("semantic_digest") != profile["descriptor_digest"]:
        raise ValueError("contract fixture profile digest differs from packaged catalog")


def canonical_fixture_bytes(value: Any) -> bytes:
    """Canonicalize the fixture's deliberately restricted JCS subset.

    Fixtures use only ASCII strings and exact I-JSON integers, so Python's
    compact sorted JSON is byte-identical to RFC 8785 for this corpus. The
    Rust implementation remains authoritative for unrestricted JCS input.
    """
    def inspect(child: Any) -> None:
        if child is None or isinstance(child, bool):
            return
        if isinstance(child, int):
            if abs(child) > 9_007_199_254_740_991:
                raise ValueError("fixture integer is outside exact I-JSON range")
            return
        if isinstance(child, float):
            raise ValueError("fixture verifier deliberately refuses floating-point JSON")
        if isinstance(child, str):
            if not child.isascii():
                raise ValueError("fixture verifier deliberately requires ASCII strings")
            return
        if isinstance(child, list):
            for item in child:
                inspect(item)
            return
        if isinstance(child, dict):
            for key, item in child.items():
                if not key.isascii():
                    raise ValueError("fixture verifier deliberately requires ASCII keys")
                inspect(item)
            return
        raise ValueError(f"unsupported fixture value {type(child).__name__}")

    inspect(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def semantic_digest(value: Any) -> str:
    """Digest one fixture value's canonical JSON representation."""
    return f"sha256:{hashlib.sha256(canonical_fixture_bytes(value)).hexdigest()}"


def versioned_digest(schema: str, artifact: Any) -> str:
    """Apply the crate's exact version-separating digest envelope."""
    return semantic_digest({"schema": schema, "artifact": artifact})


def require_object_closure(value: Any, path: str = "$") -> None:
    """Require every schema-defined object to close unknown properties."""
    if isinstance(value, dict):
        if value.get("type") == "object" and value.get("additionalProperties") is not False:
            raise ValueError(f"schema object is not closed at {path}")
        for key, child in value.items():
            require_object_closure(child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            require_object_closure(child, f"{path}/{index}")


def assert_schema_rejects(validator: Draft202012Validator, value: Any, reason: str) -> None:
    """Require a hostile structural mutation to fail schema validation."""
    if validator.is_valid(value):
        raise ValueError(f"schema accepted hostile mutation: {reason}")


def verify_cross_contracts(fixtures: dict[str, Any]) -> None:
    """Verify digests and exact derivation links across all five fixtures."""
    spec = fixtures["nq.system_spec.v1"]
    proposal = fixtures["nq.scope_cut_proposal.v1"]
    cut = fixtures["nq.scope_cut.v1"]
    observation = fixtures["nq.observation_projection.v1"]
    porter = fixtures["nq.porter_actuation_projection.v1"]

    spec_digest = semantic_digest(spec)
    if proposal["proposal"]["source_spec"]["spec_digest"] != spec_digest:
        raise ValueError("proposal does not cite the exact normalized system-spec fixture")
    if proposal["proposal_digest"] != versioned_digest(proposal["schema"], proposal["proposal"]):
        raise ValueError("proposal digest does not identify its versioned body")

    reconstructed_proposal = copy.deepcopy(cut["cut"])
    ratification = reconstructed_proposal.pop("ratification")
    if reconstructed_proposal != proposal["proposal"]:
        raise ValueError("published cut closure differs from the ratified proposal")
    if ratification["ratified_proposal_digest"] != proposal["proposal_digest"]:
        raise ValueError("ratification does not cite the exact proposal digest")
    ratified_at = datetime.fromisoformat(ratification["ratified_at"].replace("Z", "+00:00"))
    if any(
        datetime.fromisoformat(source["captured_at"].replace("Z", "+00:00")) > ratified_at
        for source in cut["cut"]["source_snapshots"]
    ):
        raise ValueError("ratification precedes a contributing source snapshot")
    record_body = {
        "ratified_by": ratification["ratified_by"],
        "ratified_at": ratification["ratified_at"],
        "ratified_proposal_digest": ratification["ratified_proposal_digest"],
    }
    expected_record = versioned_digest("nq.scope_cut_ratification.v1", record_body)
    if ratification["ratification_record_digest"] != expected_record:
        raise ValueError("ratification record digest does not identify its exact fields")
    if cut["cut_digest"] != versioned_digest(cut["schema"], cut["cut"]):
        raise ValueError("scope-cut digest does not identify its versioned body")

    cut_ref = {"cut_id": cut["cut"]["cut_id"], "cut_digest": cut["cut_digest"]}
    expected_observation = {
        "projection_id": observation["projection"]["projection_id"],
        "scope_cut": cut_ref,
        "system_id": cut["cut"]["system"]["system_id"],
        "targets": cut["cut"]["targets"],
        "components": cut["cut"]["components"],
        "dependencies": cut["cut"]["dependencies"],
        "observation_obligations": cut["cut"]["observation_obligations"],
        "authority": "none",
    }
    if observation["projection"] != expected_observation:
        raise ValueError("NQ projection is not the exact complete cut projection")
    if observation["projection_digest"] != versioned_digest(
        observation["schema"], observation["projection"]
    ):
        raise ValueError("NQ projection digest does not identify its versioned body")

    porter_body = porter["projection"]
    if porter_body["scope_cut"] != cut_ref:
        raise ValueError("Porter and NQ projections do not cite the same exact cut")
    if porter_body["system_id"] != cut["cut"]["system"]["system_id"]:
        raise ValueError("Porter projection names a different system")
    if porter_body["authority"] != "none":
        raise ValueError("Porter projection carries non-none authority semantics")
    cut_targets = cut["cut"]["targets"]
    cut_components = cut["cut"]["components"]
    cut_dependencies = cut["cut"]["dependencies"]
    cut_obligations = cut["cut"]["observation_obligations"]
    actuation_component_ids = {
        component["component_id"] for component in porter_body["actuation_components"]
    }
    expected_actuation_targets = {
        component["hosted_on"]
        for component in cut_components
        if component["component_id"] in actuation_component_ids
    }
    if {
        target["target_id"] for target in porter_body["actuation_targets"]
    } != expected_actuation_targets:
        raise ValueError("Porter actuation targets are not the exact selected-component hosts")
    affected_component_ids = set(actuation_component_ids)
    while True:
        before = len(affected_component_ids)
        for dependency in cut_dependencies:
            if dependency["provider_component_id"] in affected_component_ids:
                affected_component_ids.add(dependency["consumer_component_id"])
        if len(affected_component_ids) == before:
            break
    expected_affected_components = [
        component
        for component in cut_components
        if component["component_id"] in affected_component_ids
    ]
    if porter_body["affected_components"] != expected_affected_components:
        raise ValueError("Porter affected components are not the transitive consumer closure")
    affected_target_ids = {component["hosted_on"] for component in expected_affected_components}
    expected_affected_targets = [
        target for target in cut_targets if target["target_id"] in affected_target_ids
    ]
    if porter_body["affected_targets"] != expected_affected_targets:
        raise ValueError("Porter affected targets do not host the affected component closure")
    expected_boundary = [
        dependency
        for dependency in cut_dependencies
        if dependency["consumer_component_id"] in affected_component_ids
        or dependency["provider_component_id"] in affected_component_ids
    ]
    if porter_body["boundary_dependencies"] != expected_boundary:
        raise ValueError("Porter dependency boundary does not match the affected closure")
    expected_verification = [
        obligation
        for obligation in cut_obligations
        if obligation["component_id"] in affected_component_ids
    ]
    if porter_body["verification_obligations"] != expected_verification:
        raise ValueError("Porter verification obligations are incomplete for affected components")
    if porter["projection_digest"] != versioned_digest(porter["schema"], porter_body):
        raise ValueError("Porter projection digest does not identify its versioned body")
    for forbidden in ("commands", "effects", "grant", "approved", "authorized"):
        if forbidden in porter_body:
            raise ValueError(f"Porter projection contains forbidden field {forbidden!r}")


def main(profile_catalog: Path) -> None:
    """Verify exact inventory, schemas, fixtures, digests, and hostile cases."""
    manifest = read_json("manifest.json")
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS:
        raise ValueError("manifest has missing or unknown fields")
    if manifest["schema"] != "nq.system_contract_assets.v1":
        raise ValueError("manifest schema is wrong")
    if manifest["digest_basis"] != DIGEST_BASIS:
        raise ValueError("manifest digest basis is wrong")
    if set(manifest["definitions_schema"]) != {"path", "sha256"}:
        raise ValueError("definitions manifest entry has missing or unknown fields")
    definitions_path = manifest["definitions_schema"]["path"]
    if file_digest(definitions_path) != manifest["definitions_schema"]["sha256"]:
        raise ValueError("shared definitions schema file digest differs from manifest")

    contracts = manifest["contracts"]
    if not isinstance(contracts, list) or len(contracts) != len(EXPECTED_SCHEMAS):
        raise ValueError("manifest must contain exactly five contracts")
    by_schema: dict[str, dict[str, Any]] = {}
    for entry in contracts:
        if not isinstance(entry, dict) or set(entry) != CONTRACT_FIELDS:
            raise ValueError("contract manifest entry has missing or unknown fields")
        schema_name = entry["schema"]
        if schema_name in by_schema:
            raise ValueError(f"duplicate manifest contract {schema_name!r}")
        by_schema[schema_name] = entry
        if file_digest(entry["schema_path"]) != entry["schema_sha256"]:
            raise ValueError(f"schema file digest differs for {schema_name}")
        if file_digest(entry["fixture_path"]) != entry["fixture_sha256"]:
            raise ValueError(f"fixture file digest differs for {schema_name}")
    if set(by_schema) != EXPECTED_SCHEMAS:
        raise ValueError("manifest contract schema inventory is incomplete")

    expected_schema_files = {entry["schema_path"] for entry in contracts} | {definitions_path}
    actual_schema_files = {
        str(path.relative_to(ROOT)) for path in (ROOT / "schemas").rglob("*.json")
    }
    if actual_schema_files != expected_schema_files:
        raise ValueError("schema directory inventory differs from manifest")
    expected_fixture_files = {entry["fixture_path"] for entry in contracts}
    actual_fixture_files = {
        str(path.relative_to(ROOT))
        for path in (ROOT / "fixtures" / "valid").rglob("*.json")
    }
    if actual_fixture_files != expected_fixture_files:
        raise ValueError("valid fixture inventory differs from manifest")

    schemas = {path: read_json(path) for path in expected_schema_files}
    definitions = schemas[definitions_path]
    require_object_closure(definitions)
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    schema_store = {schema["$id"]: schema for schema in schemas.values()}

    fixtures: dict[str, Any] = {}
    validators: dict[str, Draft202012Validator] = {}
    for schema_name, entry in by_schema.items():
        schema = schemas[entry["schema_path"]]
        validator = Draft202012Validator(
            schema,
            resolver=RefResolver.from_schema(schema, store=schema_store),
            format_checker=FormatChecker(),
        )
        fixture = read_json(entry["fixture_path"])
        errors = sorted(validator.iter_errors(fixture), key=lambda error: list(error.path))
        if errors:
            raise ValueError(f"{schema_name} fixture fails schema: {errors[0].message}")
        if fixture["schema"] != schema_name:
            raise ValueError(f"{schema_name} fixture carries the wrong schema")
        fixtures[schema_name] = fixture
        validators[schema_name] = validator

        unknown = copy.deepcopy(fixture)
        unknown["unexpected"] = True
        assert_schema_rejects(validator, unknown, f"{schema_name} root unknown field")
        body_key = "proposal" if "proposal" in fixture else "cut" if "cut" in fixture else None
        if body_key is not None:
            authority_escape = copy.deepcopy(fixture)
            authority_escape[body_key]["authority"] = "granted"
            assert_schema_rejects(validator, authority_escape, f"{schema_name} authority escape")
        elif "projection" in fixture:
            command_escape = copy.deepcopy(fixture)
            command_escape["projection"]["commands"] = ["echo unsafe"]
            assert_schema_rejects(validator, command_escape, f"{schema_name} command field")

        confusing = copy.deepcopy(fixture)
        if schema_name == "nq.system_spec.v1":
            confusing["title"] = "confusing\u202etitle"
        elif schema_name == "nq.scope_cut_proposal.v1":
            confusing["proposal"]["system"]["title"] = "zero\u200bwidth"
        elif schema_name == "nq.scope_cut.v1":
            confusing["cut"]["source_snapshots"][0]["provenance"] = "bidi\u2066isolate"
        else:
            confusing["projection"]["system_id"] = "zero\u200bwidth"
        assert_schema_rejects(validator, confusing, f"{schema_name} confusing display text")

    for entry in contracts:
        schema_name = entry["schema"]
        fixture = fixtures[schema_name]
        if schema_name == "nq.system_spec.v1":
            actual_semantic_digest = semantic_digest(fixture)
        else:
            body = fixture.get("proposal", fixture.get("cut", fixture.get("projection")))
            actual_semantic_digest = versioned_digest(schema_name, body)
        if actual_semantic_digest != entry["semantic_digest"]:
            raise ValueError(f"manifest semantic digest differs for {schema_name}")

    verify_cross_contracts(fixtures)
    chronology_escape = copy.deepcopy(fixtures)
    escaped_cut = chronology_escape["nq.scope_cut.v1"]
    escaped_ratification = escaped_cut["cut"]["ratification"]
    escaped_ratification["ratified_at"] = "2026-07-16T11:59:59Z"
    escaped_record_body = {
        "ratified_by": escaped_ratification["ratified_by"],
        "ratified_at": escaped_ratification["ratified_at"],
        "ratified_proposal_digest": escaped_ratification["ratified_proposal_digest"],
    }
    escaped_ratification["ratification_record_digest"] = versioned_digest(
        "nq.scope_cut_ratification.v1", escaped_record_body
    )
    escaped_cut["cut_digest"] = versioned_digest(escaped_cut["schema"], escaped_cut["cut"])
    try:
        verify_cross_contracts(chronology_escape)
    except ValueError as error:
        if "ratification precedes" not in str(error):
            raise ValueError("chronology hostile case failed at the wrong boundary") from error
    else:
        raise ValueError("verifier accepted ratification before its source snapshots")

    profile = manifest["compiled_profile_fixture"]
    if set(profile) != {"purpose", "id", "version", "descriptor_digest"}:
        raise ValueError("compiled-profile fixture entry has missing or unknown fields")
    if profile != {
        "purpose": "conformance_only_not_operational_standing",
        "id": "nq.conformance",
        "version": "1",
        "descriptor_digest": "sha256:e1d808429458639aaff4a7e7fc2f0145258b0ebe1c36a28dad8ee86d36581494",
    }:
        raise ValueError("fixture must cite the exact compiled conformance-only profile")
    verify_profile_catalog(profile, profile_catalog)

    synthetic = manifest["synthetic_digest_inputs"]
    if not isinstance(synthetic, list) or len(synthetic) != 3:
        raise ValueError("manifest must identify all three synthetic digest inputs")
    for entry in synthetic:
        if set(entry) != {"purpose", "preimage_utf8", "digest"}:
            raise ValueError("synthetic digest entry has missing or unknown fields")
        actual = f"sha256:{hashlib.sha256(entry['preimage_utf8'].encode()).hexdigest()}"
        if actual != entry["digest"]:
            raise ValueError(f"synthetic digest preimage mismatch for {entry['purpose']}")

    print("verified 5 strict system-contract schemas and fixtures")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "--asset-root",
            type=Path,
            default=ROOT,
            help="exact system-contract asset directory to verify",
        )
        parser.add_argument(
            "--profile-catalog",
            type=Path,
            default=ROOT.parent / "profiles/manifest.json",
            help="exact profile manifest to which fixture obligations must bind",
        )
        arguments = parser.parse_args()
        if arguments.asset_root.is_symlink() or not arguments.asset_root.is_dir():
            raise ValueError(
                f"asset root is not a real directory: {arguments.asset_root}"
            )
        ROOT = arguments.asset_root.resolve(strict=True)
        main(arguments.profile_catalog)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"system-contract asset verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
