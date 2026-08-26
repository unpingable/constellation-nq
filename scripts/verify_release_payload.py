#!/usr/bin/env python3
"""Verify an exact release-stage path, type, mode, and digest allowlist."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from pathlib import Path

from verify_protocol_assets import FIXTURE_FILES, SCHEMA_FILES


DESCRIPTOR_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\.json\Z")
MAX_PAYLOAD_FILE_BYTES = 256 * 1024 * 1024
MAX_PAYLOAD_BYTES = 1024 * 1024 * 1024
MAX_INNER_MANIFEST_BYTES = 4 * 1024 * 1024
SYSTEM_CONTRACT_FILES = (
    "manifest.json",
    "schemas/nq.observation_projection.v1.schema.json",
    "schemas/nq.porter_actuation_projection.v1.schema.json",
    "schemas/nq.scope_cut.v1.schema.json",
    "schemas/nq.scope_cut_proposal.v1.schema.json",
    "schemas/nq.system_contract.defs.v1.schema.json",
    "schemas/nq.system_spec.v1.schema.json",
    "fixtures/valid/nq_observation_projection.json",
    "fixtures/valid/porter_actuation_projection.json",
    "fixtures/valid/scope_cut.json",
    "fixtures/valid/scope_cut_proposal.json",
    "fixtures/valid/system_spec.json",
)
DIAGNOSTIC_CONTRACT_FILES = (
    "README.md",
    "manifest.json",
    "schemas/nq.diagnostic_execution.v1.schema.json",
    "fixtures/valid/positive.json",
    "fixtures/valid/provider_no_response.json",
    "fixtures/valid/refused.json",
    "fixtures/hostile/projection_collision_match.json",
    "fixtures/hostile/projection_collision_mismatch.json",
)
DIAGNOSTIC_CONTRACT_V2_FILES = (
    "README.md",
    "manifest.json",
    "schemas/nq.diagnostic_execution.v2.schema.json",
    "fixtures/valid/acquisition_failure.json",
    "fixtures/valid/completed_bounded_clock.json",
    "fixtures/valid/completed_unqualified_clock.json",
    "fixtures/valid/detector_refusal_detail_a.json",
    "fixtures/valid/detector_refusal_detail_b.json",
    "fixtures/valid/multiple_input_refusals.json",
    "fixtures/valid/provider_no_response.json",
    "fixtures/valid/received_input_refusal.json",
    "fixtures/valid/retained_acquisition_refusal.json",
    "fixtures/valid/typed_unsupported.json",
    "fixtures/hostile/acquisition_failure_with_timeout.json",
    "fixtures/hostile/missing_refusal_frontier_member.json",
    "fixtures/hostile/missing_unsupported_frontier.json",
    "fixtures/hostile/no_response_with_spawn.json",
    "fixtures/hostile/received_before_acquisition.json",
    "fixtures/hostile/substituted_failure_dependency.json",
)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def expected_files(descriptors: list[str]) -> dict[str, int]:
    files = {
        "bin/nq": 0o755,
        "bin/nqd": 0o755,
        "lib/nq/helpers/nq-host-helper": 0o755,
        "lib/nq/helpers/nq-linode-origin-helper": 0o755,
        "lib/nq/helpers/nq-passive-load-helper": 0o755,
        "lib/nq/helpers/nq_conformance_helper.py": 0o755,
        "lib/systemd/system/nqd.service": 0o644,
        "lib/systemd/system/nq-recurring-office.service": 0o644,
        "lib/systemd/system/nq-recurring-office.timer": 0o644,
        "lib/systemd/system/nq-passive-load-observer.service": 0o644,
        "lib/sysusers.d/nq.conf": 0o644,
        "lib/tmpfiles.d/nq.conf": 0o644,
        "share/doc/nq-ng/OPERATIONS.md": 0o644,
        "share/doc/nq-ng/README.md": 0o644,
        "share/doc/nq-ng/LICENSE": 0o644,
        "share/doc/nq-ng/copyright": 0o644,
        "share/doc/nq-ng/docs/PLAN.md": 0o644,
        "share/doc/nq-ng/docs/DEVELOPMENT.md": 0o644,
        "share/doc/nq-ng/docs/IMPLEMENTATION_STATUS.md": 0o644,
        "share/doc/nq-ng/docs/BOUNDED_RECURRING_DIAGNOSTIC_OFFICE_V1.md": 0o644,
        "share/doc/nq-ng/docs/PASSIVE_LOAD_SAMPLING_V1.md": 0o644,
        "share/doc/nq-ng/docs/PORTER_NETBOX_ADDENDUM.md": 0o644,
        "share/doc/nq-ng/examples/nq.toml": 0o644,
        "share/doc/nq-ng/examples/nq-host.toml": 0o644,
        "share/nq/profiles/manifest.json": 0o644,
        "share/nq/protocol/README.md": 0o644,
        "share/nq/MANIFEST.sha256": 0o644,
    }
    files.update(
        {f"share/nq/profiles/{descriptor}": 0o644 for descriptor in descriptors}
    )
    files.update({f"share/nq/protocol/schemas/{name}": 0o644 for name in SCHEMA_FILES})
    files.update(
        {f"share/nq/protocol/fixtures/{name}": 0o644 for name in FIXTURE_FILES}
    )
    files.update(
        {f"share/nq/system-contract/{name}": 0o644 for name in SYSTEM_CONTRACT_FILES}
    )
    files.update(
        {
            f"share/nq/diagnostic-contract/{name}": 0o644
            for name in DIAGNOSTIC_CONTRACT_FILES
        }
    )
    files.update(
        {
            f"share/nq/diagnostic-contract-v2/{name}": 0o644
            for name in DIAGNOSTIC_CONTRACT_V2_FILES
        }
    )
    return files


def expected_directories(files: dict[str, int]) -> set[str]:
    directories: set[str] = set()
    for name in files:
        parent = Path(name).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def verify_manifest(stage: Path, files: dict[str, int]) -> None:
    manifest = stage / "share/nq/MANIFEST.sha256"
    if manifest.stat().st_size > MAX_INNER_MANIFEST_BYTES:
        raise ValueError("inner SHA-256 manifest exceeds its size bound")
    expected_names = set(files) - {"share/nq/MANIFEST.sha256"}
    actual: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if len(line) < 68 or line[64:68] != "  ./":
            raise ValueError("inner SHA-256 manifest has malformed framing")
        digest = line[:64]
        name = line[68:]
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None or name in actual:
            raise ValueError("inner SHA-256 manifest has an invalid or duplicate entry")
        actual[name] = digest
    if set(actual) != expected_names:
        raise ValueError("inner SHA-256 manifest inventory differs from payload")
    for name, digest in actual.items():
        computed = sha256_file(stage / name)
        if computed != digest:
            raise ValueError(f"inner SHA-256 mismatch for {name}")


def verify(stage: Path, descriptors: list[str]) -> None:
    if stage.is_symlink() or not stage.is_dir():
        raise ValueError("release stage must be a real directory")
    if stat.S_IMODE(stage.stat().st_mode) != 0o755:
        raise ValueError("release stage root mode is not 0755")
    if len(descriptors) != len(set(descriptors)) or not descriptors:
        raise ValueError("descriptor arguments must be unique and non-empty")
    for descriptor in descriptors:
        if (
            descriptor == "manifest.json"
            or DESCRIPTOR_NAME.fullmatch(descriptor) is None
        ):
            raise ValueError(f"unsafe descriptor name {descriptor!r}")

    files = expected_files(descriptors)
    directories = expected_directories(files)
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    total_bytes = 0
    for path in stage.rglob("*"):
        relative = path.relative_to(stage).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise ValueError(f"payload file is hard-linked: {relative}")
            actual_files.add(relative)
            if metadata.st_size > MAX_PAYLOAD_FILE_BYTES:
                raise ValueError(f"payload file exceeds size bound: {relative}")
            total_bytes += metadata.st_size
            if total_bytes > MAX_PAYLOAD_BYTES:
                raise ValueError("payload exceeds aggregate size bound")
            expected_mode = files.get(relative)
            if expected_mode is None or mode != expected_mode:
                raise ValueError(
                    f"unexpected payload file or mode: {relative} mode={mode:04o}"
                )
        elif stat.S_ISDIR(metadata.st_mode):
            actual_directories.add(relative)
            if relative not in directories or mode != 0o755:
                raise ValueError(
                    f"unexpected payload directory or mode: {relative} mode={mode:04o}"
                )
        else:
            raise ValueError(f"payload contains a symlink or special file: {relative}")
    if actual_files != set(files):
        raise ValueError(
            f"payload file inventory differs; missing={sorted(set(files) - actual_files)}, "
            f"extra={sorted(actual_files - set(files))}"
        )
    if actual_directories != directories:
        raise ValueError(
            "payload directory inventory differs; "
            f"missing={sorted(directories - actual_directories)}, "
            f"extra={sorted(actual_directories - directories)}"
        )
    verify_manifest(stage, files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("descriptors", nargs="+")
    arguments = parser.parse_args()
    verify(arguments.stage.resolve(strict=True), arguments.descriptors)
    print("verified exact release payload path/type/mode/digest allowlist")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"release payload verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
