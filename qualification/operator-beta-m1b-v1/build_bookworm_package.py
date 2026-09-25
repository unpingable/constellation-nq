#!/usr/bin/env python3
"""Reproducibly build and verify the exact Debian 12 NQ qualification package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any

SCHEMA = "constellation.operator_beta.nq_bookworm_package_build.v1"
SOURCE_HEAD = "fc671a4126c5fabbf87be15dbd79d6c12132ee3f"
SOURCE_TREE = "64e118d642703fe17da4e7f959099e8a1726fe31"
IMAGE_ID = "sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379"
IMAGE_REPO_DIGEST = "rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f"
SOURCE_DATE_EPOCH = "1700000000"
BUILD_USER = "1000:1000"
VERSION = "0.1.0"
ARCH = "amd64"
PACKAGE = "nq-ng_0.1.0_amd64.deb"
TARBALL = "nq-ng-0.1.0-linux-amd64.tar.gz"
OUTPUTS = ("SHA256SUMS", PACKAGE, TARBALL, f"{PACKAGE}.sha256", f"{TARBALL}.sha256")
LIMITATIONS = ["qualification-only", "no VM or installation", "no deployment authority", "vendor snapshot is campaign-owned input"]
BINARIES = {
    "nq": "usr/bin/nq",
    "nqd": "usr/bin/nqd",
    "nq-host-helper": "usr/lib/nq/helpers/nq-host-helper",
    "nq-host-resource-helper": "usr/lib/nq/helpers/nq-host-resource-helper",
    "nq-operator-beta-helper": "usr/lib/nq/helpers/nq-operator-beta-helper",
    "nq-synthetic-cache-result-helper": "usr/lib/nq/helpers/nq-synthetic-cache-result-helper",
}
BUILD_ENV = {
    "CARGO_HOME": "/cargo-home",
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
    "CARGO_TARGET_DIR": "/build",
    "HOME": "/tmp/nq-builder-home",
    "LC_ALL": "C.UTF-8",
    "RUSTFLAGS": "--remap-path-prefix=/src=. --remap-path-prefix=/vendor=/cargo-vendor",
    "RUSTUP_TOOLCHAIN": "1.94.0",
    "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
    "TZ": "UTC",
    "USER": "nq-builder",
}
RECEIPT_KEYS = {
    "schema", "source", "vendor", "builder", "build", "binaries", "artifacts",
    "reproduction", "logs", "qualification", "limitations",
}


class Refusal(RuntimeError):
    pass


def run(command: list[str], *, cwd: pathlib.Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise Refusal(
            f"command refused ({result.returncode}): {command!r}\n"
            + result.stderr.decode(errors="replace")[-4000:]
        )
    return result


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def tree_digest(root: pathlib.Path) -> tuple[str, int]:
    if not root.is_dir() or root.is_symlink():
        raise Refusal("vendor input is not one physical directory")
    digest = hashlib.sha256(b"nq-bookworm-vendor-tree-v1\0")
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise Refusal(f"vendor input contains a non-regular entry: {path}")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update((metadata.st_mode & 0o777).to_bytes(4, "big"))
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        count += 1
    if count == 0:
        raise Refusal("vendor input is empty")
    return digest.hexdigest(), count


def source_facts(source: pathlib.Path) -> dict[str, Any]:
    if not source.is_dir() or source.is_symlink():
        raise Refusal("source is not one physical directory")
    head = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.decode().strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=source).stdout.decode().strip()
    if head != SOURCE_HEAD or tree != SOURCE_TREE:
        raise Refusal("source head/tree differs from the accepted package source")
    if run(["git", "status", "--porcelain"], cwd=source).stdout:
        raise Refusal("source worktree is not clean")
    tracked = {
        name: sha256(source / name)
        for name in ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml", "scripts/build-release-bundle.sh", "profiles/manifest.json")
    }
    return {"head": head, "tree": tree, "clean": True, "tracked_inputs_sha256": tracked}


def image_facts() -> dict[str, Any]:
    raw = run(["/usr/bin/docker", "image", "inspect", IMAGE_ID]).stdout
    records = json.loads(raw)
    if len(records) != 1 or records[0].get("Id") != IMAGE_ID:
        raise Refusal("local builder image identity differs")
    digests = records[0].get("RepoDigests", [])
    if IMAGE_REPO_DIGEST not in digests:
        raise Refusal("local builder repository digest is absent")
    return {"image_id": IMAGE_ID, "repository_digest": IMAGE_REPO_DIGEST, "network": "none", "pull": "never"}


def docker_prefix() -> list[str]:
    command = [
        "/usr/bin/docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--hostname", "nq-bookworm-builder", "--user", BUILD_USER,
    ]
    for key, value in sorted(BUILD_ENV.items()):
        command.extend(["-e", f"{key}={value}"])
    return command


def normalized_build_command() -> list[str]:
    return docker_prefix() + [
        "-v", "<SOURCE>:/src:ro", "-v", "<VENDOR>:/vendor:ro",
        "-v", "<CARGO_HOME>:/cargo-home:rw", "-v", "<BUILD>:/build:rw",
        "-w", "/src", IMAGE_ID, "cargo", "build", "--workspace", "--release",
        "--locked", "--offline", "--jobs", "4",
    ]


def build_command(source: pathlib.Path, vendor: pathlib.Path, case: pathlib.Path) -> list[str]:
    if f"{os.getuid()}:{os.getgid()}" != BUILD_USER:
        raise Refusal(f"qualification builder requires host uid:gid {BUILD_USER}")
    command = docker_prefix()
    command.extend([
        "-v", f"{source}:/src:ro", "-v", f"{vendor}:/vendor:ro",
        "-v", f"{case / 'cargo-home'}:/cargo-home:rw",
        "-v", f"{case / 'build'}:/build:rw", "-w", "/src", IMAGE_ID,
        "cargo", "build", "--workspace", "--release", "--locked", "--offline", "--jobs", "4",
    ])
    return command


def cargo_config() -> str:
    return """[net]
offline = true

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/vendor"
"""


def assembler_env() -> dict[str, str]:
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
    }


def qualification_facts() -> dict[str, Any]:
    builder = pathlib.Path(__file__).resolve(strict=True)
    tests = builder.with_name("test_build_bookworm_package.py").resolve(strict=True)
    return {
        "builder": {
            "path": "qualification/operator-beta-m1b-v1/build_bookworm_package.py",
            "sha256": sha256(builder),
        },
        "tests": {
            "path": "qualification/operator-beta-m1b-v1/test_build_bookworm_package.py",
            "sha256": sha256(tests),
        },
    }


def artifact_facts(output: pathlib.Path) -> dict[str, Any]:
    return {
        name: {"bytes": (output / name).stat().st_size, "sha256": sha256(output / name)}
        for name in OUTPUTS
    }


def log_facts(output: pathlib.Path) -> dict[str, Any]:
    return {
        label: {
            kind: {
                "file": f"{kind}-{label}.log",
                "bytes": (output / f"{kind}-{label}.log").stat().st_size,
                "sha256": sha256(output / f"{kind}-{label}.log"),
            }
            for kind in ("build", "assemble")
        }
        for label in ("a", "b")
    }


def binary_facts(package: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    root = scratch / "package-root"
    root.mkdir(parents=True)
    run(["dpkg-deb", "-x", str(package), str(root)])
    result: dict[str, Any] = {}
    for component, relative in BINARIES.items():
        path = root / relative
        versions = run(["readelf", "--version-info", str(path)]).stdout.decode()
        parsed = [(int(a), int(b)) for a, b in re.findall(r"Name: GLIBC_(\d+)\.(\d+)", versions)]
        newest = max(parsed) if parsed else None
        if newest is not None and newest > (2, 36):
            raise Refusal(f"{component} requires glibc {newest}, beyond Debian 12")
        result[component] = {
            "path": "/" + relative,
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
            "maximum_glibc": None if newest is None else f"GLIBC_{newest[0]}.{newest[1]}",
        }
    return result


def compare_receipt(expected: dict[str, Any], actual: dict[str, Any]) -> None:
    if set(actual) != RECEIPT_KEYS:
        raise Refusal("receipt root is not closed")
    if actual != expected:
        raise Refusal("receipt differs from exact recomputed evidence")


def build(source: pathlib.Path, vendor: pathlib.Path, output: pathlib.Path) -> None:
    if output.exists():
        raise Refusal("output path already exists")
    parent = output.parent.resolve(strict=True)
    source = source.resolve(strict=True)
    vendor = vendor.resolve(strict=True)
    source_record = source_facts(source)
    vendor_sha, vendor_files = tree_digest(vendor)
    builder_record = image_facts()
    scratch = pathlib.Path(tempfile.mkdtemp(prefix=".nq-bookworm-build.", dir=parent))
    try:
        cases: list[dict[str, Any]] = []
        logs: dict[str, Any] = {}
        binaries: dict[str, Any] | None = None
        for label in ("a", "b"):
            case = scratch / label
            (case / "cargo-home").mkdir(parents=True)
            (case / "build").mkdir()
            (case / "package").mkdir()
            (case / "cargo-home" / "config.toml").write_text(cargo_config(), encoding="utf-8")
            command = build_command(source, vendor, case)
            built = run(command)
            build_log = built.stdout + built.stderr
            assembler = source / "scripts/build-release-bundle.sh"
            assembled = run(
                [str(assembler), VERSION, ARCH, str(case / "build/release"), str(source / "profiles"), str(case / "package")],
                cwd=source, env=assembler_env(),
            )
            assemble_log = assembled.stdout + assembled.stderr
            facts = artifact_facts(case / "package")
            current_binaries = binary_facts(case / "package" / PACKAGE, case / "inspect")
            if binaries is None:
                binaries = current_binaries
            elif current_binaries != binaries:
                raise Refusal("independent build binary identities differ")
            cases.append(facts)
            (case / "build.log").write_bytes(build_log)
            (case / "assemble.log").write_bytes(assemble_log)
        if cases[0] != cases[1]:
            raise Refusal("independent release artifacts differ")
        assert binaries is not None
        output.mkdir(mode=0o700)
        for name in OUTPUTS:
            shutil.copyfile(scratch / "a/package" / name, output / name)
        for label in ("a", "b"):
            shutil.copyfile(scratch / label / "build.log", output / f"build-{label}.log")
            shutil.copyfile(scratch / label / "assemble.log", output / f"assemble-{label}.log")
        logs = log_facts(output)
        receipt = {
            "schema": SCHEMA,
            "source": source_record,
            "vendor": {"tree_sha256": vendor_sha, "regular_files": vendor_files, "container_path": "/vendor"},
            "builder": builder_record,
            "build": {
                "container_source": "/src", "container_vendor": "/vendor", "container_target": "/build",
                "environment": BUILD_ENV, "cargo_arguments": ["build", "--workspace", "--release", "--locked", "--offline", "--jobs", "4"],
                "normalized_docker_argv": normalized_build_command(),
                "cargo_config_sha256": hashlib.sha256(cargo_config().encode()).hexdigest(),
                "assembler_arguments": [VERSION, ARCH, "/build/release", "/src/profiles", "/output"],
                "assembler_environment": assembler_env(),
            },
            "binaries": binaries,
            "artifacts": cases[0],
            "reproduction": {"clean_builds": 2, "binary_bytes_equal": True, "artifact_bytes_equal": True},
            "logs": logs,
            "qualification": qualification_facts(),
            "limitations": LIMITATIONS,
        }
        (output / "bookworm-build-receipt.v1.json").write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        print(json.dumps({"result": "REPRODUCIBLE_BOOKWORM_PACKAGE", "package_sha256": cases[0][PACKAGE]["sha256"]}, sort_keys=True))
    except Exception:
        if output.exists():
            shutil.rmtree(output)
        raise
    finally:
        shutil.rmtree(scratch)


def verify(source: pathlib.Path, vendor: pathlib.Path, output: pathlib.Path) -> None:
    source = source.resolve(strict=True)
    vendor = vendor.resolve(strict=True)
    output = output.resolve(strict=True)
    receipt = json.loads((output / "bookworm-build-receipt.v1.json").read_text(encoding="utf-8"))
    vendor_sha, vendor_files = tree_digest(vendor)
    with tempfile.TemporaryDirectory(prefix="nq-bookworm-verify.") as temporary:
        binaries = binary_facts(output / PACKAGE, pathlib.Path(temporary))
    expected = dict(receipt)
    expected["schema"] = SCHEMA
    expected["source"] = source_facts(source)
    expected["vendor"] = {"tree_sha256": vendor_sha, "regular_files": vendor_files, "container_path": "/vendor"}
    expected["builder"] = image_facts()
    expected["binaries"] = binaries
    expected["artifacts"] = artifact_facts(output)
    expected["logs"] = log_facts(output)
    expected["qualification"] = qualification_facts()
    expected["reproduction"] = {"clean_builds": 2, "binary_bytes_equal": True, "artifact_bytes_equal": True}
    expected["limitations"] = LIMITATIONS
    expected["build"] = {
        "container_source": "/src", "container_vendor": "/vendor", "container_target": "/build",
        "environment": BUILD_ENV, "cargo_arguments": ["build", "--workspace", "--release", "--locked", "--offline", "--jobs", "4"],
        "normalized_docker_argv": normalized_build_command(),
        "cargo_config_sha256": hashlib.sha256(cargo_config().encode()).hexdigest(),
        "assembler_arguments": [VERSION, ARCH, "/build/release", "/src/profiles", "/output"],
        "assembler_environment": assembler_env(),
    }
    compare_receipt(expected, receipt)
    print(json.dumps({"result": "BOOKWORM_PACKAGE_RECEIPT_VERIFIED", "package_sha256": receipt["artifacts"][PACKAGE]["sha256"]}, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("build", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--source", type=pathlib.Path, required=True)
        command.add_argument("--vendor", type=pathlib.Path, required=True)
        command.add_argument("--output", type=pathlib.Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "build":
            build(args.source, args.vendor, args.output)
        else:
            verify(args.source, args.vendor, args.output)
        return 0
    except (OSError, ValueError, Refusal) as error:
        print(f"REFUSED: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
