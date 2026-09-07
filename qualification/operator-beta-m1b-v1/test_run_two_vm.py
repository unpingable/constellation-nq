#!/usr/bin/env python3
"""Pure-local qualification for the bounded NQ-ng M1B producer."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).with_name("run_two_vm.py")
SPEC = importlib.util.spec_from_file_location("nq_m1b_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class HarnessTests(unittest.TestCase):
    def args(self, output: pathlib.Path, run_id: str = "fixture-001") -> types.SimpleNamespace:
        return types.SimpleNamespace(
            output=output,
            run_id=run_id,
            harness_subject="a" * 40,
            producer_unit="constellation-beta-nq-m1b.service",
            controller_ssh_port=23141,
            target_ssh_port=23142,
            fixture_link_port=24567,
            preflight_only=False,
        )

    def test_service_subject_uses_exact_ag_domain_framing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            producer = RUNNER.Producer(self.args(pathlib.Path(temporary) / "run"))
            value, identity = producer.service_subject(
                {
                    "target_machine_identity": "machine:fixture-001",
                    "unit_file_sha256": "sha256:" + "c" * 64,
                }
            )
        self.assertEqual(value["fixture_run_id"], "fixture-001")
        self.assertEqual(
            identity,
            "sha256:240b8636e5d2cd5bcbe2d410bd34125c72474b2c354564a3fa0bd797e6140c87",
        )

    def test_scope_identity_changes_with_exact_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            producer = RUNNER.Producer(self.args(pathlib.Path(temporary) / "run"))
            scope = {"kind": "systemd_unit", "value": {"unit": RUNNER.UNIT}}
            first = producer.scope_identity("sha256:" + "a" * 64, scope, "nq.systemd_unit")
            changed = {"kind": "systemd_unit", "value": {"unit": "other.service"}}
            second = producer.scope_identity("sha256:" + "a" * 64, changed, "nq.systemd_unit")
        self.assertEqual(first["id"], "nq.scope.systemd_unit")
        self.assertEqual(first["version"], "1")
        self.assertNotEqual(first["digest"], second["digest"])

    def test_recovery_record_retains_owner_and_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            producer = RUNNER.Producer(self.args(output))
            producer.input_facts = {"image_sha512": RUNNER.IMAGE_SHA512}
            with mock.patch.dict(os.environ, {"INVOCATION_ID": "b" * 32}):
                producer.state("created", "retain exact inputs")
            record = json.loads((output / "RECOVERY.json").read_bytes())
        self.assertEqual(record["producer"]["invocation_id"], "b" * 32)
        self.assertEqual(record["producer"]["main_pid"], os.getpid())
        self.assertEqual(record["input_facts"]["image_sha512"], RUNNER.IMAGE_SHA512)
        self.assertEqual(record["expected_terminal_records"][0], "RESULT.json + ARTIFACTS.sha256")

    def test_runtime_bound_refuses_before_recovery_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            producer = RUNNER.Producer(self.args(output))
            producer.started = time.monotonic() - RUNNER.MAX_RUN_SECONDS - 1
            with self.assertRaisesRegex(RUNNER.Refusal, "run exceeded"):
                producer.state("created", "none")
            self.assertFalse((output / "RECOVERY.json").exists())

    def test_producer_identity_must_match_systemd_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            producer = RUNNER.Producer(self.args(pathlib.Path(temporary) / "run"))
            completed = subprocess.CompletedProcess(
                [],
                0,
                stdout=f"InvocationID={'c' * 32}\nMainPID={os.getpid()}\n".encode(),
                stderr=b"",
            )
            with mock.patch.dict(os.environ, {"INVOCATION_ID": "c" * 32}), mock.patch.object(
                RUNNER, "run", return_value=completed
            ):
                producer.verify_producer()
            wrong = subprocess.CompletedProcess(
                [], 0, stdout=f"InvocationID={'d' * 32}\nMainPID={os.getpid()}\n".encode(), stderr=b""
            )
            with mock.patch.dict(os.environ, {"INVOCATION_ID": "c" * 32}), mock.patch.object(
                RUNNER, "run", return_value=wrong
            ), self.assertRaisesRegex(RUNNER.Refusal, "invocation differs"):
                producer.verify_producer()

    def test_diagnostic_condition_and_policy_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            (output / "evidence").mkdir(parents=True)
            producer = RUNNER.Producer(self.args(output))
            artifact = {
                "schema": "nq.diagnostic_execution.v2",
                "profile": {"id": "nq.systemd_unit"},
                "threshold_policy": {"version": "fixture-001"},
                "outcome": {"condition": "explicitly_absent"},
            }
            responses = iter(
                [
                    subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
                    subprocess.CompletedProcess([], 0, stdout=RUNNER.canonical(artifact), stderr=b""),
                ]
            )
            producer.ssh = mock.Mock(side_effect=lambda *args, **kwargs: next(responses))
            observed = producer.execute_diagnostic(
                mock.Mock(),
                "systemd-post",
                "systemd-post.json",
                "nq.systemd_unit",
                "explicitly_absent",
            )
            self.assertEqual(observed, artifact)
            responses = iter(
                [
                    subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
                    subprocess.CompletedProcess([], 0, stdout=RUNNER.canonical(artifact), stderr=b""),
                ]
            )
            producer.ssh = mock.Mock(side_effect=lambda *args, **kwargs: next(responses))
            with self.assertRaisesRegex(RUNNER.Refusal, "unexpected warranted condition"):
                producer.execute_diagnostic(
                    mock.Mock(), "systemd-pre", "wrong.json", "nq.systemd_unit", "present"
                )

    def test_checksum_relation_and_file_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            image = root / "image.qcow2"
            image.write_bytes(b"image")
            digest = hashlib.sha512(b"image").hexdigest()
            checksums = root / "SHA512SUMS"
            checksums.write_text(f"{digest}  image.qcow2\n", encoding="utf-8")
            with mock.patch.object(RUNNER, "IMAGE_NAME", "image.qcow2"), mock.patch.object(
                RUNNER, "IMAGE_SHA512", digest
            ):
                RUNNER.verify_checksum_manifest(checksums, image)
                checksums.write_text(f"{'0' * 128}  image.qcow2\n", encoding="utf-8")
                with self.assertRaisesRegex(RUNNER.Refusal, "one exact selected-image relation"):
                    RUNNER.verify_checksum_manifest(checksums, image)

    def test_regular_file_refuses_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / "target"
            target.write_bytes(b"x")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(RUNNER.Refusal, "not an openable physical file"):
                RUNNER.regular_file(link, "fixture")

    def make_sealed_run(self, root: pathlib.Path) -> None:
        artifact = root / "evidence.json"
        artifact.write_bytes(b"{}\n")
        manifest = {
            "schema": "constellation.operator_beta.m1b_artifact_manifest.v1",
            "files": [
                {
                    "path": "evidence.json",
                    "bytes": artifact.stat().st_size,
                    "sha256": RUNNER.digest_file(artifact, "sha256"),
                }
            ],
        }
        manifest_path = root / "ARTIFACTS.sha256"
        manifest_path.write_bytes(RUNNER.canonical(manifest) + b"\n")
        result = {
            "schema": "constellation.operator_beta.m1b_run_result.v1",
            "run_id": "fixture-001",
            "disposition": "MECHANISM_CASES_COMPLETED_WITH_DECLARED_LIMITATIONS",
            "completed_at": "2026-09-07T12:00:00Z",
            "harness_subject": "a" * 40,
            "accepted_package_result": RUNNER.ACCEPTED_PACKAGE_RESULT,
            "signed_upstream_checksum": "NOT_QUALIFIED",
            "docket_database_occurrence": "NOT_RUN",
            "authorization_consumption": "NOT_RUN",
            "production": "NOT_RUN",
            "manifest_sha256": RUNNER.digest_file(manifest_path, "sha256"),
        }
        (root / "RESULT.json").write_bytes(RUNNER.canonical(result) + b"\n")

    def test_run_reopen_and_semantic_substitutions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                RUNNER.check_run(root)
            self.assertIn("RUN_REOPENED", output.getvalue())
            result_path = root / "RESULT.json"
            result = json.loads(result_path.read_bytes())
            result["docket_database_occurrence"] = "RECORDED"
            result_path.write_bytes(RUNNER.canonical(result) + b"\n")
            with self.assertRaisesRegex(RUNNER.Refusal, "overstates Docket"):
                RUNNER.check_run(root)

    def test_run_reopen_refuses_content_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            (root / "evidence.json").write_bytes(b"changed\n")
            with self.assertRaisesRegex(RUNNER.Refusal, "differs from manifest"):
                RUNNER.check_run(root)


if __name__ == "__main__":
    unittest.main()
