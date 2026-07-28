#!/usr/bin/env python3
"""Focused hostile tests for release input and payload verification."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# This suite dynamically imports verifiers from public asset directories whose
# inventories deliberately reject runtime caches.  Prevent the test harness
# from manufacturing a forbidden file before it verifies those inventories.
sys.dont_write_bytecode = True

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_protocol_assets as protocol  # noqa: E402
import verify_release_payload as payload  # noqa: E402


ROOT = SCRIPT_DIRECTORY.parent


def load_catalog_module():
    path = ROOT / "profiles/verify_catalog.py"
    spec = importlib.util.spec_from_file_location("nq_verify_catalog", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load profile catalog verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


catalog = load_catalog_module()


def load_system_contract_module():
    path = ROOT / "system-contract/verify_assets.py"
    spec = importlib.util.spec_from_file_location("nq_verify_system_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load system-contract verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


system_contract = load_system_contract_module()


def load_diagnostic_contract_module():
    path = ROOT / "diagnostic-contract/verify_assets.py"
    spec = importlib.util.spec_from_file_location("nq_verify_diagnostic_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load diagnostic-contract verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


diagnostic_contract = load_diagnostic_contract_module()


class CatalogVerifierTest(unittest.TestCase):
    def copy_catalog(self, root: Path) -> Path:
        destination = root / "profiles"
        shutil.copytree(
            ROOT / "profiles", destination, ignore=shutil.ignore_patterns("*.py")
        )
        return destination

    def test_checked_catalog_is_strict_and_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-catalog-test-") as directory:
            destination = self.copy_catalog(Path(directory))
            self.assertEqual(len(catalog.load_manifest(destination)), 2)
            (destination / "extra.v1.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                catalog.load_manifest(destination)

            (destination / "extra.v1.json").unlink()
            descriptor = destination / "nq.conformance.v1.json"
            with descriptor.open("wb") as output:
                output.truncate(catalog.MAX_CATALOG_JSON_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "exceeds"):
                catalog.read_strict_json(descriptor)

    def test_duplicate_manifest_key_and_entry_are_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-catalog-test-") as directory:
            destination = self.copy_catalog(Path(directory))
            manifest_path = destination / "manifest.json"
            manifest = manifest_path.read_text(encoding="utf-8")
            manifest_path.write_text(
                manifest.replace(
                    '"schema": "nq.profile_catalog.v1",',
                    '"schema": "nq.profile_catalog.v1",\n  "schema": "nq.profile_catalog.v1",',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                catalog.load_manifest(destination)

            shutil.copyfile(ROOT / "profiles/manifest.json", manifest_path)
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            value["profiles"].append(value["profiles"][0])
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "duplicate catalog profile identity"
            ):
                catalog.load_manifest(destination)


class ProtocolVerifierTest(unittest.TestCase):
    def test_checked_protocol_inventory_and_schema_identities_pass(self) -> None:
        protocol_root = ROOT / "protocol"
        protocol.verify_schemas(protocol_root / "schemas")
        protocol.exact_file_inventory(
            protocol_root / "fixtures", set(protocol.FIXTURE_FILES)
        )
        self.assertEqual(
            protocol.read_json(protocol_root / "fixtures/manifest.json"),
            protocol.EXPECTED_SOURCE_MANIFEST,
        )

    def test_extra_asset_and_duplicate_manifest_key_are_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-protocol-test-") as directory:
            destination = Path(directory) / "protocol"
            shutil.copytree(ROOT / "protocol", destination)
            (destination / "fixtures/unlisted.ndjson").write_text(
                "{}\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                protocol.exact_file_inventory(
                    destination / "fixtures", set(protocol.FIXTURE_FILES)
                )

            (destination / "fixtures/unlisted.ndjson").unlink()
            schema = destination / "schemas/nq.helper.request.v1.schema.json"
            schema.write_bytes(schema.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "immutable v1 contract"):
                protocol.verify_schemas(destination / "schemas")

            manifest_path = destination / "fixtures/manifest.json"
            manifest_path.write_text(
                '{"schema":"x","schema":"y","request":"x","valid":[],"invalid":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                protocol.read_json(manifest_path)

            fixture = destination / "fixtures/valid/request.ndjson"
            with fixture.open("wb") as output:
                output.truncate(protocol.MAX_PROTOCOL_ASSET_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "fixture exceeds"):
                protocol.corpus_digest(destination / "fixtures")


class SystemContractPackagingTest(unittest.TestCase):
    def test_public_asset_inventory_and_porter_addendum_are_allowlisted(self) -> None:
        contract_root = ROOT / "system-contract"
        actual = {"manifest.json"} | {
            path.relative_to(contract_root).as_posix()
            for base in (
                contract_root / "schemas",
                contract_root / "fixtures/valid",
            )
            for path in base.rglob("*")
            if path.is_file()
        }
        self.assertEqual(set(payload.SYSTEM_CONTRACT_FILES), actual)
        release_files = payload.expected_files(["fixture.v1.json"])
        self.assertIn("share/doc/nq-ng/docs/PORTER_NETBOX_ADDENDUM.md", release_files)
        for relative in actual:
            self.assertIn(f"share/nq/system-contract/{relative}", release_files)

    def test_contract_profile_fixture_binds_to_packaged_catalog(self) -> None:
        profile = system_contract.read_json("manifest.json")["compiled_profile_fixture"]
        system_contract.verify_profile_catalog(profile, ROOT / "profiles/manifest.json")

        with tempfile.TemporaryDirectory(prefix="nq-contract-catalog-") as directory:
            catalog_path = Path(directory) / "manifest.json"
            catalog_value = json.loads(
                (ROOT / "profiles/manifest.json").read_text(encoding="utf-8")
            )
            for entry in catalog_value["profiles"]:
                if entry["id"] == profile["id"]:
                    entry["semantic_digest"] = f"sha256:{'0' * 64}"
            catalog_path.write_text(json.dumps(catalog_value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "differs from packaged catalog"):
                system_contract.verify_profile_catalog(profile, catalog_path)

    def test_custom_asset_root_refuses_a_partial_staged_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-contract-stage-") as directory:
            staged = Path(directory) / "system-contract"
            shutil.copytree(ROOT / "system-contract", staged)
            schema = staged / "schemas/nq.scope_cut.v1.schema.json"
            with schema.open("r+b") as output:
                output.truncate(37)
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "system-contract/verify_assets.py"),
                    "--asset-root",
                    str(staged),
                    "--profile-catalog",
                    str(ROOT / "profiles/manifest.json"),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("schema file digest differs", result.stderr)


class DiagnosticContractPackagingTest(unittest.TestCase):
    def test_public_inventory_is_exactly_allowlisted(self) -> None:
        contract_root = ROOT / "diagnostic-contract"
        actual = {
            path.relative_to(contract_root).as_posix()
            for path in contract_root.rglob("*")
            if path.is_file() and path.name != "verify_assets.py"
        }
        self.assertEqual(set(payload.DIAGNOSTIC_CONTRACT_FILES), actual)
        release_files = payload.expected_files(["fixture.v1.json"])
        for relative in actual:
            self.assertIn(f"share/nq/diagnostic-contract/{relative}", release_files)

    def test_frozen_corpus_and_projection_collision_pass(self) -> None:
        contract_root = ROOT / "diagnostic-contract"
        source_vectors = ROOT / "audit/nq-nightshift-stage6-foundation/vectors"
        manifest_digest = diagnostic_contract.verify(contract_root, source_vectors)
        self.assertEqual(
            manifest_digest,
            "sha256:bbf5b46b4f026380eb45679544970f9862fad15c936ea9cac985ce7c6bcfbcef",
        )

    def test_extra_asset_duplicate_key_and_source_drift_are_refused(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nq-diagnostic-contract-"
        ) as directory_name:
            directory = Path(directory_name)
            staged = directory / "diagnostic-contract"
            shutil.copytree(ROOT / "diagnostic-contract", staged)
            source_vectors = directory / "vectors"
            shutil.copytree(
                ROOT / "audit/nq-nightshift-stage6-foundation/vectors",
                source_vectors,
            )

            extra = staged / "fixtures/valid/unlisted.json"
            extra.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                diagnostic_contract.verify(staged, source_vectors)
            extra.unlink()

            manifest = staged / "manifest.json"
            original_manifest = manifest.read_text(encoding="utf-8")
            manifest.write_text(
                original_manifest.replace(
                    '"schema": "nq.diagnostic_contract_assets.v1",',
                    '"schema": "nq.diagnostic_contract_assets.v1",\n'
                    '  "schema": "nq.diagnostic_contract_assets.v1",',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                diagnostic_contract.verify(staged, source_vectors)
            manifest.write_text(original_manifest, encoding="utf-8")

            source = source_vectors / "positive.json"
            source.write_bytes(source.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "frozen source vector"):
                diagnostic_contract.verify(staged, source_vectors)

    def test_staged_partial_schema_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nq-diagnostic-contract-stage-"
        ) as directory_name:
            staged = Path(directory_name) / "diagnostic-contract"
            shutil.copytree(ROOT / "diagnostic-contract", staged)
            schema = staged / "schemas/nq.diagnostic_execution.v1.schema.json"
            with schema.open("r+b") as output:
                output.truncate(37)
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "diagnostic-contract/verify_assets.py"),
                    "--asset-root",
                    str(staged),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("schema file digest differs", result.stderr)


class PayloadVerifierTest(unittest.TestCase):
    @staticmethod
    def make_stage(root: Path) -> tuple[Path, list[str]]:
        stage = root / "stage"
        stage.mkdir(mode=0o755)
        os.chmod(stage, 0o755)
        descriptors = ["fixture.v1.json"]
        files = payload.expected_files(descriptors)
        for relative, mode in files.items():
            path = stage / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fixture:{relative}\n".encode())
            os.chmod(path, mode)
        for directory in payload.expected_directories(files):
            os.chmod(stage / directory, 0o755)

        manifest = stage / "share/nq/MANIFEST.sha256"
        lines = []
        for relative in sorted(set(files) - {"share/nq/MANIFEST.sha256"}):
            digest = hashlib.sha256((stage / relative).read_bytes()).hexdigest()
            lines.append(f"{digest}  ./{relative}\n")
        manifest.write_text("".join(lines), encoding="utf-8")
        os.chmod(manifest, 0o644)
        return stage, descriptors

    def test_exact_payload_passes_and_extra_file_or_mode_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-payload-test-") as directory:
            stage, descriptors = self.make_stage(Path(directory))
            payload.verify(stage, descriptors)

            extra = stage / "unlisted"
            extra.write_text("no\n", encoding="utf-8")
            os.chmod(extra, 0o644)
            with self.assertRaisesRegex(ValueError, "unexpected payload file"):
                payload.verify(stage, descriptors)
            extra.unlink()

            binary = stage / "bin/nq"
            os.chmod(binary, 0o700)
            with self.assertRaisesRegex(ValueError, "unexpected payload file or mode"):
                payload.verify(stage, descriptors)

            os.chmod(binary, 0o755)
            with binary.open("r+b") as output:
                output.truncate(payload.MAX_PAYLOAD_FILE_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "exceeds size bound"):
                payload.verify(stage, descriptors)


class SystemdInstalledManifestGateTest(unittest.TestCase):
    def test_unit_checks_installed_bytes_before_config_or_daemon(self) -> None:
        unit = (ROOT / "packaging/systemd/nqd.service").read_text(encoding="utf-8")
        working_directory = "WorkingDirectory=/usr"
        manifest_check = (
            "ExecStartPre=/usr/bin/sha256sum --quiet --check "
            "/usr/share/nq/MANIFEST.sha256"
        )
        config_check = "ExecStartPre=/usr/bin/nq --config=/etc/nq/nq.toml config check"
        daemon_start = "ExecStart=/usr/bin/nqd "
        self.assertIn(working_directory, unit)
        self.assertLess(unit.index(manifest_check), unit.index(config_check))
        self.assertLess(unit.index(config_check), unit.index(daemon_start))

    def test_manifest_check_refuses_packaged_byte_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-installed-manifest-") as directory:
            usr = Path(directory) / "usr"
            packaged = usr / "share/nq/system-contract/manifest.json"
            packaged.parent.mkdir(parents=True)
            packaged.write_bytes(b"ratified fixture bytes\n")
            manifest = usr / "share/nq/MANIFEST.sha256"
            digest = hashlib.sha256(packaged.read_bytes()).hexdigest()
            manifest.write_text(
                f"{digest}  ./share/nq/system-contract/manifest.json\n",
                encoding="utf-8",
            )
            command = ["/usr/bin/sha256sum", "--quiet", "--check", str(manifest)]
            accepted = subprocess.run(
                command,
                cwd=usr,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            packaged.write_bytes(b"tampered fixture bytes\n")
            refused = subprocess.run(
                command,
                cwd=usr,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("FAILED", refused.stdout)


@unittest.skipUnless(Path("/run/systemd/system").is_dir(), "systemd is not active")
class DebianPrermTest(unittest.TestCase):
    def run_prerm(
        self, directory: Path, action: str, mode: str
    ) -> subprocess.CompletedProcess[str]:
        fake = directory / "systemctl"
        log = directory / "calls"
        fake.write_text(
            f"""#!{sys.executable}
import os
import pathlib
import sys

arguments = sys.argv[1:]
with pathlib.Path(os.environ["NQ_SYSTEMCTL_LOG"]).open("a", encoding="utf-8") as output:
    output.write(" ".join(arguments) + "\\n")
mode = os.environ.get("NQ_SYSTEMCTL_MODE", "inactive")
if arguments[:1] == ["stop"] and mode == "stop_fail":
    raise SystemExit(9)
if arguments[:2] == ["disable", "--now"] and mode == "disable_fail":
    raise SystemExit(8)
if arguments[:1] == ["show"]:
    if mode == "show_fail":
        raise SystemExit(7)
    print("active" if mode == "active" else "inactive")
""",
            encoding="utf-8",
        )
        os.chmod(fake, 0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": str(directory),
                "NQ_SYSTEMCTL_LOG": str(log),
                "NQ_SYSTEMCTL_MODE": mode,
            }
        )
        return subprocess.run(
            ["/bin/sh", str(ROOT / "packaging/debian/prerm"), action],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=environment,
        )

    def test_upgrade_and_remove_require_verified_inactivity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-prerm-test-") as directory_name:
            directory = Path(directory_name)
            upgraded = self.run_prerm(directory, "upgrade", "inactive")
            self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
            self.assertEqual(
                (directory / "calls").read_text(encoding="utf-8").splitlines(),
                [
                    "stop nqd.service",
                    "show --property=ActiveState --value nqd.service",
                ],
            )

        with tempfile.TemporaryDirectory(prefix="nq-prerm-test-") as directory_name:
            directory = Path(directory_name)
            removed = self.run_prerm(directory, "remove", "inactive")
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertEqual(
                (directory / "calls").read_text(encoding="utf-8").splitlines(),
                [
                    "disable --now nqd.service",
                    "show --property=ActiveState --value nqd.service",
                ],
            )

    def test_command_failure_or_active_state_aborts(self) -> None:
        cases = (
            ("upgrade", "stop_fail"),
            ("remove", "disable_fail"),
            ("upgrade", "show_fail"),
            ("upgrade", "active"),
        )
        for action, mode in cases:
            with self.subTest(action=action, mode=mode):
                with tempfile.TemporaryDirectory(prefix="nq-prerm-test-") as directory:
                    result = self.run_prerm(Path(directory), action, mode)
                    self.assertNotEqual(result.returncode, 0)

    def test_active_systemd_without_systemctl_aborts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-prerm-test-") as directory:
            environment = os.environ.copy()
            environment["PATH"] = directory
            result = subprocess.run(
                ["/bin/sh", str(ROOT / "packaging/debian/prerm"), "upgrade"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                env=environment,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("systemctl is unavailable", result.stderr)


if __name__ == "__main__":
    unittest.main()
