#!/usr/bin/env python3
"""Verify the closed labelwatch-host operation-class assessment."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT = (
    ROOT
    / "audit/provider-operation-noninterference/labelwatch-host-load-pressure-v1.json"
)
REQUIRED_DIMENSIONS = {
    "world_state",
    "evidence_attribution",
    "semantics",
    "provider_safety",
    "local_runtime",
}
QUALIFIED_STANDINGS = {"qualified", "qualified_locally"}
EXPECTED_OPERATION_CLASS_ID = (
    "sha256:e46d9c18ca22579a4e00ccfc92ad923b50a345016b7e0944c2818ddfd65d1fda"
)
EXPECTED_METHODS = [
    {"method": "read_utf8", "source": "/proc/uptime", "maximum_bytes": 4096},
    {"method": "read_utf8", "source": "/proc/loadavg", "maximum_bytes": 4096},
    {"method": "gethostname", "source": "linux_kernel_hostname"},
    {
        "method": "std_thread_available_parallelism",
        "source": "execution_environment_parallelism_estimate",
    },
]


class AssessmentError(ValueError):
    """The checked-in exact-class assessment is malformed or widened."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssessmentError(message)


def validate(document: dict[str, Any]) -> None:
    require(
        document.get("schema") == "nq.provider_operation_noninterference_assessment.v1",
        "wrong assessment schema",
    )
    basis = document.get("operation_class_basis")
    require(isinstance(basis, dict), "operation-class basis is absent")
    require(
        basis.get("schema") == "nq.provider_operation_class_basis.v1",
        "wrong operation-class basis schema",
    )
    operation_class_id = "sha256:" + hashlib.sha256(canonical_bytes(basis)).hexdigest()
    require(
        document.get("operation_class_id") == operation_class_id,
        "operation-class identity does not cover exact canonical basis bytes",
    )
    require(
        operation_class_id == EXPECTED_OPERATION_CLASS_ID,
        "assessment no longer addresses the qualified deployed operation class",
    )
    pair = document.get("pair", {})
    require(
        pair.get("active_operation_class_id") == operation_class_id
        and pair.get("candidate_operation_class_id") == operation_class_id,
        "assessment pair is not exact R-to-R",
    )
    require(
        pair.get("directionality") == "not_qualified",
        "assessment direction was widened",
    )

    dimensions = document.get("dimensions", {})
    require(
        set(dimensions) == REQUIRED_DIMENSIONS, "dimension vocabulary is not closed"
    )
    require(
        all(
            isinstance(value, dict)
            and value.get("standing")
            in {"qualified", "qualified_locally", "refuted", "unqualified"}
            and isinstance(value.get("reason"), str)
            and value["reason"]
            for value in dimensions.values()
        ),
        "dimension standing or proof reason is malformed",
    )
    fully_qualified = all(
        dimensions[name]["standing"] in QUALIFIED_STANDINGS
        for name in REQUIRED_DIMENSIONS
    )
    require(not fully_qualified, "fixture unexpectedly claims full noninterference")
    require(
        document.get("overall_standing") == "noninterference_not_qualified",
        "partial dimensions were laundered into full noninterference",
    )
    blocking = set(document.get("blocking_dimensions", []))
    require(
        blocking
        == {
            name
            for name in REQUIRED_DIMENSIONS
            if dimensions[name]["standing"] not in QUALIFIED_STANDINGS
        },
        "blocking dimensions do not equal the non-qualified dimensions",
    )

    consequence = document.get("protocol_consequence", {})
    require(consequence.get("a4_remains_outcome_unknown") is True, "A4 was classified")
    require(
        consequence.get("a4_provider_activity_remains_unknown") is True,
        "A4 provider activity was fabricated",
    )
    require(
        consequence.get("coordination_domain_remains_fenced") is True,
        "partial assessment released the domain fence",
    )
    require(
        consequence.get("future_same_class_overlap_permitted") is False,
        "unqualified overlap was permitted",
    )
    require(
        consequence.get("deployment_may_override") is False,
        "deployment policy was allowed to invent noninterference",
    )
    require(
        consequence.get("new_acquisition_permitted") is False,
        "assessment minted acquisition authority",
    )

    helper = basis.get("helper", {})
    require(basis.get("provider_kind") == "local_helper", "provider kind drifted")
    require(
        basis.get("provider_protocol_identity") == "nq.helper.v1",
        "provider protocol drifted",
    )
    require(
        basis.get("provider_semantic_id")
        == "sha256:a10a8e3da6234910ffe1c2f0a396b8481b7cc5340b78408ac5f0b9f0d7be0075",
        "provider semantic identity drifted",
    )
    require(
        basis.get("provider_artifact_digest")
        == "sha256:a0665c7ec0d21dc321f4f7e9a08183787bce55c38e92603a1160f047bef993de",
        "helper binary identity drifted",
    )
    require(
        helper.get("absolute_path")
        == "/opt/nq-ng/linode-v3-20260824/bin/nq-host-helper",
        "helper path drifted",
    )
    require(
        helper.get("execution_principal") == "nq-helper", "helper principal drifted"
    )
    require(helper.get("fixed_argv") == [], "operation class gained helper arguments")
    require(
        helper.get("network_endpoints") == [], "host helper gained a network endpoint"
    )
    profile = basis.get("profile", {})
    require(
        profile.get("id") == "nq.host"
        and profile.get("version") == "1"
        and profile.get("diagnostic_question") == "nq.host.load_pressure/v1"
        and profile.get("normalized_load_threshold_millis") == 2000,
        "profile or diagnostic proposition drifted",
    )
    binding = basis.get("binding", {})
    require(
        binding.get("watcher_instance_id") == "labelwatch-host-local"
        and binding.get("subject_ref") == "host:labelwatch-host"
        and binding.get("scope") == {"kind": "host", "value": {"id": "labelwatch-host"}}
        and binding.get("vantage") == {"kind": "local", "value": {}}
        and binding.get("substrate_coordinate_ref")
        == "substrate:linode-instance:v1:a09bf794e58b16779d67c84dc1e68d2dfb4bd6b0f3de7940df05a2dda9802e94",
        "watcher, subject, scope, vantage, or coordinate drifted",
    )
    require(
        basis.get("bounded_observation_methods") == EXPECTED_METHODS,
        "bounded observation method drifted",
    )
    require(
        basis.get("derived_proposition") == "load_1m / cpu_count >= 2.000",
        "operation class no longer binds the exact load-pressure proposition",
    )


def rehash(document: dict[str, Any]) -> None:
    operation_class_id = (
        "sha256:"
        + hashlib.sha256(canonical_bytes(document["operation_class_basis"])).hexdigest()
    )
    document["operation_class_id"] = operation_class_id
    document["pair"]["active_operation_class_id"] = operation_class_id
    document["pair"]["candidate_operation_class_id"] = operation_class_id


def expect_refused(
    source: dict[str, Any],
    label: str,
    mutate: Callable[[dict[str, Any]], None],
    *,
    recompute_identity: bool = False,
) -> None:
    hostile = deepcopy(source)
    mutate(hostile)
    if recompute_identity:
        rehash(hostile)
    try:
        validate(hostile)
    except AssessmentError:
        return
    raise AssessmentError(f"hostile substitution was accepted: {label}")


def hostile_vectors(document: dict[str, Any]) -> None:
    vectors: list[tuple[str, Callable[[dict[str, Any]], None], bool]] = [
        (
            "rehashed helper binary drift",
            lambda value: value["operation_class_basis"].__setitem__(
                "provider_artifact_digest", "sha256:" + "0" * 64
            ),
            True,
        ),
        (
            "rehashed provider semantic drift",
            lambda value: value["operation_class_basis"].__setitem__(
                "provider_semantic_id", "sha256:" + "1" * 64
            ),
            True,
        ),
        (
            "rehashed profile drift",
            lambda value: value["operation_class_basis"]["profile"].__setitem__(
                "version", "2"
            ),
            True,
        ),
        (
            "rehashed subject drift",
            lambda value: value["operation_class_basis"]["binding"].__setitem__(
                "subject_ref", "host:neighbor"
            ),
            True,
        ),
        (
            "rehashed coordinate drift",
            lambda value: value["operation_class_basis"]["binding"].__setitem__(
                "substrate_coordinate_ref", "substrate:linode-instance:v1:" + "2" * 64
            ),
            True,
        ),
        (
            "rehashed method drift",
            lambda value: value["operation_class_basis"]["bounded_observation_methods"][
                1
            ].__setitem__("source", "/tmp/loadavg"),
            True,
        ),
        (
            "rehashed arbitrary endpoint",
            lambda value: value["operation_class_basis"]["helper"].__setitem__(
                "network_endpoints", ["https://example.invalid"]
            ),
            True,
        ),
        (
            "partial dimensions laundered into qualification",
            lambda value: value.__setitem__("overall_standing", "qualified"),
            False,
        ),
        (
            "deployment invents overlap",
            lambda value: value["protocol_consequence"].__setitem__(
                "deployment_may_override", True
            ),
            False,
        ),
        (
            "future overlap enabled",
            lambda value: value["protocol_consequence"].__setitem__(
                "future_same_class_overlap_permitted", True
            ),
            False,
        ),
        (
            "A4 classified",
            lambda value: value["protocol_consequence"].__setitem__(
                "a4_remains_outcome_unknown", False
            ),
            False,
        ),
        (
            "A4 quiescence fabricated",
            lambda value: value["protocol_consequence"].__setitem__(
                "a4_provider_activity_remains_unknown", False
            ),
            False,
        ),
        (
            "domain fence released",
            lambda value: value["protocol_consequence"].__setitem__(
                "coordination_domain_remains_fenced", False
            ),
            False,
        ),
    ]
    for label, mutate, recompute_identity in vectors:
        expect_refused(
            document,
            label,
            mutate,
            recompute_identity=recompute_identity,
        )


def main() -> None:
    document = json.loads(ASSESSMENT.read_text())
    try:
        validate(document)
        hostile_vectors(document)
    except AssessmentError as error:
        raise SystemExit(f"provider-operation-noninterference: {error}") from error
    print(
        "provider-operation-noninterference: exact operation class verified; "
        "rehashed substitutions refuse; partial isolation does not qualify overlap"
    )


if __name__ == "__main__":
    main()
