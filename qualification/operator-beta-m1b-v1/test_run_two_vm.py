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
import shlex
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
    FIXTURE_IMAGE_BYTES = b"fixture-image\n"
    FIXTURE_NQ_PACKAGE_BYTES = b"fixture-nq-package\n"
    FIXTURE_AG_PACKAGE_BYTES = b"fixture-ag-package\n"
    FIXTURE_AG_AUDIT_BINARY_BYTES = b"""#!/usr/bin/env python3
import pathlib
import sys

arguments = sys.argv[1:]
cut = pathlib.Path(arguments[arguments.index("--store-cut") + 1])
if cut.read_bytes() != b"fixture owner store cut\\n":
    print("fixture-owner-store-substitution", file=sys.stderr)
    raise SystemExit(1)
sys.stdin.buffer.read()
root = pathlib.Path(__file__).resolve().parents[5]
sys.stdout.buffer.write(
    (root / "runtime" / "ag-package" / "owner-outcome.json").read_bytes()
)
"""

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

    def service_records(self, run_id: str = "fixture-001") -> tuple[dict, dict, dict]:
        identities = {
            "schema": "constellation.operator_beta.m1b_guest_identity.v1",
            "run_id": run_id,
            "controller_machine_identity": "a" * 32,
            "target_machine_identity": "b" * 32,
            "unit_name": RUNNER.UNIT,
            "unit_file_sha256": RUNNER.sha256_bytes(RUNNER.FIXTURE_UNIT_BYTES),
            "controller_address": RUNNER.CONTROLLER_ADDRESS,
            "target_address": RUNNER.FIXTURE_ADDRESS,
        }
        service = {
            "schema": "constellation.operator_beta.service_subject.v1",
            "campaign_id": "constellation-operator-beta-2026",
            "fixture_run_id": run_id,
            "target_machine_identity": identities["target_machine_identity"],
            "unit_name": RUNNER.UNIT,
            "unit_file_sha256": identities["unit_file_sha256"],
        }
        subject = RUNNER.ag_domain_digest(
            "constellation/operator-beta/service-subject/v1", RUNNER.canonical(service)
        )
        scopes = {
            "systemd": {
                "kind": "systemd_unit",
                "value": {
                    "schema": "nq.operator_beta.systemd_unit_scope.v1",
                    "subject_identity": subject,
                    "target_machine_identity": identities["target_machine_identity"],
                    "unit_name": RUNNER.UNIT,
                    "unit_file_sha256": identities["unit_file_sha256"],
                    "manager_interface": "org.freedesktop.systemd1",
                    "properties": ["LoadState", "ActiveState", "SubState", "UnitFileState"],
                },
            },
            "http": {
                "kind": "http_endpoint",
                "value": {
                    "schema": "nq.operator_beta.http_endpoint_scope.v1",
                    "subject_identity": subject,
                    "controller_vantage_identity": "machine:" + identities["controller_machine_identity"],
                    "endpoint": f"http://{RUNNER.FIXTURE_ADDRESS}:{RUNNER.FIXTURE_PORT}/healthz",
                    "method": "GET",
                    "redirect_policy": "refuse",
                    "max_response_bytes": 1024,
                },
            },
        }
        policies = {}
        for family, profile in (("systemd", "nq.systemd_unit"), ("http", "nq.http_endpoint")):
            scope = scopes[family]
            scope_id = {
                "id": f"nq.scope.{scope['kind']}",
                "version": "1",
                "digest": RUNNER.sha256_bytes(RUNNER.canonical({
                    "schema": "nq.diagnostic_scope.v1",
                    "subject": subject,
                    "scope": scope,
                    "profile": {"id": profile, "version": "1", "digest": RUNNER.PROFILE_DIGESTS[profile]},
                })),
            }
            policies[family] = {
                "schema": f"nq.operator_beta.{family}_unit_threshold_policy.v1" if family == "systemd" else "nq.operator_beta.http_endpoint_threshold_policy.v1",
                "fixture_run_id": run_id,
                "service_subject": service,
                "subject_identity": subject,
                "request_scope": scope_id,
            }
        policies["systemd"].update({
            "expected_load_state": "loaded",
            "expected_active_state": "active",
            "expected_sub_state": "running",
            "expected_unit_file_state": "disabled",
        })
        policies["http"].update({
            "expected_status": 200,
            "expected_body_sha256": RUNNER.sha256_bytes(b"operator-beta-ok\n"),
        })
        bindings = {
            "schema": "constellation.operator_beta.m1b_bindings.v1",
            "run_id": run_id,
            "service_subject": service,
            "subject_identity": subject,
            "service_subject_plain_sha256": RUNNER.sha256_bytes(RUNNER.canonical(service)),
            "systemd_scope": scopes["systemd"],
            "systemd_policy": policies["systemd"],
            "http_scope": scopes["http"],
            "http_policy": policies["http"],
        }
        return identities, service, bindings

    def artifact(self, bindings: dict, profile: str, condition: str, instance: str) -> dict:
        family = "systemd" if profile == "nq.systemd_unit" else "http"
        policy = bindings[f"{family}_policy"]
        value = {
            "schema": "nq.diagnostic_execution.v2",
            "canonicalization": {"id": "rfc8785-jcs", "version": "1", "digest": "sha256:" + "1" * 64},
            "producer": {"node_id": "fixture", "build": {}, "cohort": {}},
            "request_id": f"request:{instance}",
            "run_id": f"run:{instance}",
            "question": {"id": f"{profile}.postcondition", "version": "1", "digest": RUNNER.QUESTION_DIGESTS[profile]},
            "subject": {"id": bindings["subject_identity"], "scope": policy["request_scope"]},
            "profile": {"id": profile, "version": "1", "digest": RUNNER.PROFILE_DIGESTS[profile]},
            "profile_semantic_id": "sha256:" + "2" * 64,
            "vantage": {"id": f"nq.vantage.fixture.node.{instance}", "version": "admission", "digest": "sha256:" + "3" * 64},
            "state_model": {},
            "evaluator": {},
            "threshold_policy": {"id": f"{profile}.postcondition.threshold_policy", "version": bindings["run_id"], "digest": RUNNER.sha256_bytes(RUNNER.canonical(policy))},
            "projection": {},
            "execution_clock": {},
            "started_at": "2026-09-07T12:00:00Z",
            "completed_at": "2026-09-07T12:00:01Z",
            "attempt_interval": {},
            "inputs": {},
            "state_bindings": [],
            "claims": [],
            "outcome": {"condition": condition},
            "limitations": [],
            "nonclaims": [],
        }
        value["artifact_id"] = RUNNER.sha256_bytes(RUNNER.canonical(value))
        return value

    def write_json(self, path: pathlib.Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(RUNNER.canonical(value) + b"\n")

    @contextlib.contextmanager
    def fixture_input_identities(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    RUNNER,
                    "IMAGE_SHA512",
                    hashlib.sha512(self.FIXTURE_IMAGE_BYTES).hexdigest(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RUNNER,
                    "NQ_DEB_SHA256",
                    hashlib.sha256(self.FIXTURE_NQ_PACKAGE_BYTES).hexdigest(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RUNNER,
                    "AG_DEB_SHA256",
                    hashlib.sha256(self.FIXTURE_AG_PACKAGE_BYTES).hexdigest(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RUNNER,
                    "AG_EXECUTABLE_SHA256",
                    hashlib.sha256(self.FIXTURE_AG_AUDIT_BINARY_BYTES).hexdigest(),
                )
            )
            yield

    def make_sealed_run(self, root: pathlib.Path) -> None:
        run_id = "fixture-001"
        identities, service, bindings = self.service_records(run_id)
        for relative in RUNNER.REQUIRED_TERMINAL_PATHS:
            artifact = root / relative
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(b"fixture\n")
        (root / "input" / RUNNER.IMAGE_NAME).write_bytes(self.FIXTURE_IMAGE_BYTES)
        (root / "input/SHA512SUMS").write_text(
            f"{RUNNER.IMAGE_SHA512}  {RUNNER.IMAGE_NAME}\n"
        )
        (root / "input/nq-ng_amd64.deb").write_bytes(
            self.FIXTURE_NQ_PACKAGE_BYTES
        )
        (
            root / "input/agent-governor-ng-systemd-executor_amd64.deb"
        ).write_bytes(self.FIXTURE_AG_PACKAGE_BYTES)
        self.write_json(root / "evidence/input-receipt.json", {
            "schema": "constellation.operator_beta.m1b_inputs.v1",
            "run_id": run_id,
            "recorded_at": "2026-09-07T12:00:00Z",
            "harness_subject": "a" * 40,
            "accepted_package_result": RUNNER.ACCEPTED_PACKAGE_RESULT,
            "image": {
                "name": RUNNER.IMAGE_NAME,
                "sha512": RUNNER.IMAGE_SHA512,
                "checksum_manifest_sha256": RUNNER.digest_file(
                    root / "input/SHA512SUMS", "sha256"
                ),
                "detached_signature": "UPSTREAM_DETACHED_SIGNATURE_NOT_PUBLISHED",
            },
            "nq_package_sha256": RUNNER.NQ_DEB_SHA256,
            "ag_package_sha256": RUNNER.AG_DEB_SHA256,
            "ag_package_version": RUNNER.AG_DEB_VERSION,
            "ag_store_audit_result": RUNNER.AG_STORE_AUDIT_RESULT,
            "ag_executable_sha256": RUNNER.AG_EXECUTABLE_SHA256,
            "ports": {
                "control_ssh": 23141,
                "target_ssh": 23142,
                "fixture_link_udp": 24567,
            },
        })
        self.write_json(root / "evidence/guest-identities.json", identities)
        self.write_json(root / "evidence/service-subject.json", service)
        self.write_json(root / "evidence/bindings.json", bindings)
        (root / "evidence" / RUNNER.UNIT).write_bytes(RUNNER.FIXTURE_UNIT_BYTES)
        (root / "evidence/healthz").write_bytes(RUNNER.FIXTURE_HEALTH_BYTES)
        (root / "evidence/target-nq.toml").write_bytes(
            RUNNER.expected_nq_config(bindings, "target")
        )
        (root / "evidence/control-nq.toml").write_bytes(
            RUNNER.expected_nq_config(bindings, "control")
        )
        cases = (
            ("systemd-pre-artifact.json", "nq.systemd_unit", "present", "systemd-pre"),
            ("http-pre-artifact.json", "nq.http_endpoint", "unresolved", "http-pre"),
            ("systemd-post-artifact.json", "nq.systemd_unit", "explicitly_absent", "systemd-post"),
            ("http-post-artifact.json", "nq.http_endpoint", "explicitly_absent", "http-post"),
            ("systemd-restart-artifact.json", "nq.systemd_unit", "present", "systemd-restart"),
            ("http-restart-artifact.json", "nq.http_endpoint", "unresolved", "http-restart"),
        )
        for name, profile, condition, instance in cases:
            self.write_json(root / "evidence" / name, self.artifact(bindings, profile, condition, instance))
        plan = RUNNER.expected_effect_plan(bindings, identities)
        dispatch, work = RUNNER.expected_effect_dispatch(run_id, plan)
        attempt = dispatch["attempt"]
        marker = dispatch["marker"]
        outcome = {
            "attempt": attempt,
            "marker": marker,
            "outcome": "success",
            "receipt": "sha256:" + "7" * 64,
        }
        occurrence = {
            "schema": "constellation.operator_beta.m1b_effect_occurrence.v1",
            "run_id": run_id,
            "owner": "AG-ng M1A adapter",
            "docket_database_occurrence": "NOT_RECORDED",
            "authorization_consumption": "NOT_RECORDED",
            "plan": plan,
            "dispatch": dispatch,
            "outcome": outcome,
        }
        self.write_json(root / "evidence/systemd-plan-v2.json", plan)
        self.write_json(root / "evidence/docket-shaped-dispatch-v1.json", dispatch)
        self.write_json(root / "evidence/executor-outcome-v1.json", outcome)
        self.write_json(root / "evidence/effect-occurrence.json", occurrence)
        audit_binary = (
            root
            / "runtime/ag-package/usr/libexec/agent-governor-ng/ag-effectd"
        )
        audit_binary.write_bytes(self.FIXTURE_AG_AUDIT_BINARY_BYTES)
        audit_binary.chmod(0o755)
        self.write_json(
            root / "runtime/ag-package/owner-outcome.json", outcome
        )
        store_cut = root / "evidence/ag-attempt-store-cut.sqlite"
        store_cut.write_bytes(b"fixture owner store cut\n")
        audit_outcome_path = root / "evidence/ag-store-audit-outcome-v1.json"
        self.write_json(audit_outcome_path, outcome)
        store_record_path = root / "evidence/ag-store-cut.json"
        self.write_json(
            store_record_path,
            {
                "schema": "constellation.operator_beta.m1b_ag_store_cut.v1",
                "run_id": run_id,
                "owner": "AG-ng",
                "owner_package_result": RUNNER.AG_STORE_AUDIT_RESULT,
                "ag_package_sha256": RUNNER.AG_DEB_SHA256,
                "ag_executable_sha256": RUNNER.AG_EXECUTABLE_SHA256,
                "source_store": "/var/lib/ag-effectd-m1b/attempts.sqlite",
                "wal": "ABSENT_OR_ZERO_LENGTH",
                "store_bytes": store_cut.stat().st_size,
                "store_sha256": "sha256:"
                + RUNNER.digest_file(store_cut, "sha256"),
                "plan_sha256": RUNNER.digest_file(
                    root / "evidence/systemd-plan-v2.json", "sha256"
                ),
                "dispatch_sha256": RUNNER.digest_file(
                    root / "evidence/docket-shaped-dispatch-v1.json", "sha256"
                ),
                "attempt": attempt,
                "marker": marker,
                "work": work,
                "subject": dispatch["subject"],
                "scope": dispatch["scope"],
                "owner_outcome_sha256": RUNNER.digest_file(
                    audit_outcome_path, "sha256"
                ),
                "receipt": outcome["receipt"],
            },
        )
        systemd_restart = self.artifact(
            bindings, "nq.systemd_unit", "present", "systemd-restart"
        )
        http_restart = self.artifact(
            bindings, "nq.http_endpoint", "unresolved", "http-restart"
        )
        self.write_json(root / "evidence/current-support-after-restart.json", {
            "schema": "constellation.operator_beta.current_support.v1",
            "historical_effect": "AG_OWNER_RECEIPT_RETAINED",
            "systemd_artifact": systemd_restart["artifact_id"],
            "systemd_current_condition": "present",
            "http_artifact": http_restart["artifact_id"],
            "http_current_condition": "unresolved",
            "aggregate_postcondition": "NOT_RECORDED",
        })
        for role, prefix in (("control", "http"), ("target", "systemd")):
            self.write_json(root / "evidence" / f"{role}-revocations.json", {
                "schema": "constellation.operator_beta.m1b_revocations.v1",
                "run_id": run_id,
                "role": role,
                "disposition": "REVOKED",
                "instances": [
                    {
                        "instance_id": f"{prefix}-{suffix}",
                        "stdout_sha256": RUNNER.sha256_bytes(b""),
                        "stderr_sha256": RUNNER.sha256_bytes(b""),
                    }
                    for suffix in ("pre", "post", "restart")
                ],
            })
            (root / "evidence" / f"{role}-package-continuity.txt").write_text(
                "store_sha256=" + "8" * 64 + "\n"
            )
            (root / "evidence" / f"{role}-boot-before.txt").write_text("before\n")
            (root / "evidence" / f"{role}-boot-after.txt").write_text("after\n")
            backup = root / "evidence" / f"{role}-nq-backup.sqlite"
            backup.unlink()
            connection = RUNNER.sqlite3.connect(backup)
            connection.execute("CREATE TABLE fixture(value TEXT NOT NULL)")
            connection.commit()
            connection.close()
        self.write_json(root / "evidence/host-final-observation.json", {
            "schema": "constellation.operator_beta.m1b_host_teardown.v1",
            "control_process_absent": True,
            "target_process_absent": True,
            "control_ssh_port_absent": True,
            "target_ssh_port_absent": True,
            "fixture_link_port_absent": True,
        })
        effect_custody = {
            "plan_sha256": RUNNER.digest_file(
                root / "evidence/systemd-plan-v2.json", "sha256"
            ),
            "dispatch_sha256": RUNNER.digest_file(
                root / "evidence/docket-shaped-dispatch-v1.json", "sha256"
            ),
            "outcome_sha256": RUNNER.digest_file(
                root / "evidence/executor-outcome-v1.json", "sha256"
            ),
            "attempt": attempt,
            "marker": marker,
            "work": work,
            "subject": dispatch["subject"],
            "scope": dispatch["scope"],
            "receipt": outcome["receipt"],
            "ag_store_cut_bytes": store_cut.stat().st_size,
            "ag_store_cut_sha256": RUNNER.digest_file(store_cut, "sha256"),
            "ag_store_cut_record_sha256": RUNNER.digest_file(
                store_record_path, "sha256"
            ),
            "ag_store_audit_outcome_sha256": RUNNER.digest_file(
                audit_outcome_path, "sha256"
            ),
            "ag_store_audit_result": RUNNER.AG_STORE_AUDIT_RESULT,
            "ag_executable_sha256": RUNNER.AG_EXECUTABLE_SHA256,
        }
        self.write_json(root / "RECOVERY.json", {
            "schema": "constellation.operator_beta.m1b_recovery.v1",
            "campaign": RUNNER.CAMPAIGN,
            "run_id": run_id,
            "paths": {"run_root": str(root)},
            "guests": [],
            "producer": {"main_pid": 999999999},
            "phase": "sealed",
            "effect_outcome": "KNOWN_EFFECT_OWNER_SUCCESS",
            "effect_custody": effect_custody,
            "next_lawful_action": "independent evidence audit",
        })
        files = []
        for artifact in sorted(root.rglob("*")):
            if artifact.is_file():
                files.append({"path": artifact.relative_to(root).as_posix(), "bytes": artifact.stat().st_size, "sha256": RUNNER.digest_file(artifact, "sha256")})
        manifest = {"schema": "constellation.operator_beta.m1b_artifact_manifest.v1", "files": files}
        manifest_path = root / "ARTIFACTS.sha256"
        manifest_path.write_bytes(RUNNER.canonical(manifest) + b"\n")
        result = {
            "schema": "constellation.operator_beta.m1b_run_result.v1",
            "run_id": run_id,
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
        self.write_json(root / "RESULT.json", result)

    def reseal(self, root: pathlib.Path) -> None:
        manifest_path = root / "ARTIFACTS.sha256"
        manifest = json.loads(manifest_path.read_bytes())
        for entry in manifest["files"]:
            artifact = root / entry["path"]
            entry["bytes"] = artifact.stat().st_size
            entry["sha256"] = RUNNER.digest_file(artifact, "sha256")
        manifest_path.write_bytes(RUNNER.canonical(manifest) + b"\n")
        result_path = root / "RESULT.json"
        result = json.loads(result_path.read_bytes())
        result["manifest_sha256"] = RUNNER.digest_file(manifest_path, "sha256")
        self.write_json(result_path, result)
    def test_compiled_question_pins_recompute_from_checked_descriptors(self) -> None:
        profiles = pathlib.Path(RUNNER.__file__).resolve().parents[2] / "profiles"
        cases = (
            (
                "systemd_unit",
                "Systemd unit postcondition mismatch",
                "systemd_unit_postcondition_not_met",
                "systemd_unit_postcondition",
                "nq.operator_beta.systemd_unit_threshold_policy.v1",
            ),
            (
                "http_endpoint",
                "HTTP endpoint postcondition mismatch",
                "http_endpoint_postcondition_not_met",
                "http_endpoint_postcondition",
                "nq.operator_beta.http_endpoint_threshold_policy.v1",
            ),
        )
        for family, title, condition, parameter, policy_schema in cases:
            profile = json.loads((profiles / f"nq.{family}.v1.json").read_bytes())
            descriptor = {
                "schema": "nq.detector_descriptor.v1",
                "id": f"nq.{family}.postcondition",
                "version": 1,
                "profile": profile["profile"],
                "profile_digest": RUNNER.sha256_bytes(RUNNER.canonical(profile)),
                "title": title,
                "condition": condition,
                "parameters": {parameter: {"threshold_policy_schema": policy_schema}},
            }
            self.assertEqual(
                RUNNER.sha256_bytes(RUNNER.canonical(descriptor)),
                RUNNER.QUESTION_DIGESTS[f"nq.{family}"],
            )


    def test_service_subject_uses_exact_ag_domain_framing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            producer = RUNNER.Producer(self.args(pathlib.Path(temporary) / "run"))
            value, identity = producer.service_subject({"target_machine_identity": "machine:fixture-001", "unit_file_sha256": "sha256:" + "c" * 64})
        self.assertEqual(value["fixture_run_id"], "fixture-001")
        self.assertEqual(identity, "sha256:240b8636e5d2cd5bcbe2d410bd34125c72474b2c354564a3fa0bd797e6140c87")

    def test_recovery_record_retains_owner_inputs_and_effect_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            producer = RUNNER.Producer(self.args(output))
            producer.input_facts = {"image_sha512": RUNNER.IMAGE_SHA512}
            producer.effect_custody = {
                "attempt": "sha256:" + "1" * 64,
                "marker": "sha256:" + "2" * 64,
                "work": "sha256:" + "3" * 64,
            }
            producer.effect_outcome = "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE"
            with mock.patch.dict(os.environ, {"INVOCATION_ID": "b" * 32}):
                producer.state("effect_dispatch_prepared", "invoke owner")
                producer.state("refused", "reopen retained state")
            record = json.loads((output / "RECOVERY.json").read_bytes())
        self.assertEqual(record["producer"]["invocation_id"], "b" * 32)
        self.assertEqual(
            record["effect_outcome"], "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE"
        )
        self.assertEqual(record["effect_custody"], producer.effect_custody)

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
            good = subprocess.CompletedProcess([], 0, stdout=f"InvocationID={'c' * 32}\nMainPID={os.getpid()}\n".encode(), stderr=b"")
            with mock.patch.dict(os.environ, {"INVOCATION_ID": "c" * 32}), mock.patch.object(RUNNER, "run", return_value=good):
                producer.verify_producer()
            wrong = subprocess.CompletedProcess([], 0, stdout=f"InvocationID={'d' * 32}\nMainPID={os.getpid()}\n".encode(), stderr=b"")
            with mock.patch.dict(os.environ, {"INVOCATION_ID": "c" * 32}), mock.patch.object(RUNNER, "run", return_value=wrong), self.assertRaisesRegex(RUNNER.Refusal, "invocation differs"):
                producer.verify_producer()

    def test_diagnostic_exact_bindings_and_substitutions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            (output / "evidence").mkdir(parents=True)
            producer = RUNNER.Producer(self.args(output))
            _, _, bindings = self.service_records()
            self.write_json(output / "evidence/bindings.json", bindings)
            artifact = self.artifact(bindings, "nq.systemd_unit", "explicitly_absent", "systemd-post")
            responses = [subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""), subprocess.CompletedProcess([], 0, stdout=RUNNER.canonical(artifact), stderr=b"")]
            producer.ssh = mock.Mock(side_effect=responses)
            producer.execute_diagnostic(mock.Mock(), "systemd-post", "systemd-post.json", "nq.systemd_unit", "explicitly_absent")
            commands = [call.args[1] for call in producer.ssh.call_args_list]
            self.assertEqual(
                commands,
                [
                    RUNNER.nq_helper_command(["watcher", "admit", "systemd-post"]),
                    RUNNER.nq_helper_command(["diagnostics", "execute", "systemd-post"]),
                ],
            )
            changed = dict(artifact)
            changed["subject"] = dict(changed["subject"])
            changed["subject"]["id"] = "sha256:" + "9" * 64
            changed["artifact_id"] = RUNNER.sha256_bytes(RUNNER.canonical({key: value for key, value in changed.items() if key != "artifact_id"}))
            responses = [subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""), subprocess.CompletedProcess([], 0, stdout=RUNNER.canonical(changed), stderr=b"")]
            producer.ssh = mock.Mock(side_effect=responses)
            with self.assertRaisesRegex(RUNNER.Refusal, "wrong subject"):
                producer.execute_diagnostic(mock.Mock(), "systemd-post", "changed.json", "nq.systemd_unit", "explicitly_absent")

    def test_helper_execution_uses_documented_transient_unit_boundary(self) -> None:
        command = RUNNER.nq_helper_command(["watcher", "admit", "systemd-pre"])
        arguments = shlex.split(command)
        self.assertEqual(arguments[:6], ["sudo", "systemd-run", "--quiet", "--wait", "--pipe", "--collect"])
        self.assertIn(
            "--property=CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL",
            arguments,
        )
        self.assertIn(
            "--property=AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL",
            arguments,
        )
        self.assertIn("--property=User=nq", arguments)
        self.assertIn("--property=NoNewPrivileges=yes", arguments)
        self.assertEqual(
            arguments[-6:],
            [
                "--",
                "/usr/bin/nq",
                "--config=/etc/nq/operator-beta.toml",
                "watcher",
                "admit",
                "systemd-pre",
            ],
        )
        self.assertNotIn("-u", arguments)

    def test_guest_install_uses_canonical_package_paths_and_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            (output / "input").mkdir(parents=True)
            (output / "evidence").mkdir()
            producer = RUNNER.Producer(self.args(output))
            producer.guests = [
                RUNNER.Guest("control", 23141, "a", "b", RUNNER.CONTROLLER_ADDRESS, output / "control"),
                RUNNER.Guest("target", 23142, "c", "d", RUNNER.FIXTURE_ADDRESS, output / "target"),
            ]
            for guest in producer.guests:
                guest.root.mkdir()
            copied = []
            commands = []
            producer.scp_to = mock.Mock(side_effect=lambda guest, sources, destination: copied.append((guest.role, [path.name for path in sources], destination)))
            def ssh(_guest, command, **_kwargs):
                commands.append(command)
                if command == "cat /etc/machine-id":
                    value = ("a" if _guest.role == "control" else "b") * 32
                    return subprocess.CompletedProcess([], 0, stdout=(value + "\n").encode(), stderr=b"")
                if command.startswith("sha256sum /etc/systemd/system/"):
                    return subprocess.CompletedProcess([], 0, stdout=(("c" * 64) + "  unit\n").encode(), stderr=b"")
                return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
            producer.ssh = mock.Mock(side_effect=ssh)
            with mock.patch.object(producer, "complete_phase"):
                producer.install_inputs()
        self.assertIn(("target", ["nq-ng_amd64.deb"], "/home/betaoperator/nq-ng.deb"), copied)
        joined = "\n".join(commands)
        self.assertIn(f"{RUNNER.NQ_DEB_SHA256}  /home/betaoperator/nq-ng.deb", joined)
        self.assertIn(f"{RUNNER.AG_DEB_SHA256}  /home/betaoperator/agent-governor-ng-systemd-executor_amd64.deb", joined)

    def test_package_continuity_checks_protected_store_as_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            (output / "evidence").mkdir(parents=True)
            producer = RUNNER.Producer(self.args(output))
            control = RUNNER.Guest(
                "control", 23141, "a", "b", RUNNER.CONTROLLER_ADDRESS, output / "control"
            )
            target = RUNNER.Guest(
                "target", 23142, "c", "d", RUNNER.FIXTURE_ADDRESS, output / "target"
            )
            commands = []
            producer.ssh = mock.Mock(
                side_effect=lambda _guest, command, **_kwargs: (
                    commands.append(command)
                    or subprocess.CompletedProcess(
                        [], 0, stdout=("store_sha256=" + "8" * 64 + "\n").encode(), stderr=b""
                    )
                )
            )
            with mock.patch.object(producer, "complete_phase"):
                producer.package_continuity(control, target, [])

        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn(
                "sudo test ! -s /var/lib/nq/operator-beta.sqlite-wal", command
            )
            self.assertIn(
                "sudo test -f /var/lib/nq/operator-beta.sqlite", command
            )
            self.assertNotIn(
                "; test ! -s /var/lib/nq/operator-beta.sqlite-wal", command
            )
            self.assertNotIn(
                "; test -f /var/lib/nq/operator-beta.sqlite", command
            )

    def test_nodefaults_launch_uses_explicit_read_only_virtio_nocloud_drive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary).resolve()
            guest_root = output / "control"
            guest_root.mkdir()
            guest = RUNNER.Guest(
                "control",
                23141,
                "52:54:00:0b:10:01",
                "52:54:00:0b:20:01",
                RUNNER.CONTROLLER_ADDRESS,
                guest_root,
            )
            producer = RUNNER.Producer(self.args(output))
            captured: dict[str, list[str]] = {}

            def launch(command, **_kwargs):
                captured["command"] = command
                (guest_root / "qemu.pid").write_text("12345\n")
                return types.SimpleNamespace(pid=12345, poll=lambda: None)

            with (
                mock.patch.object(RUNNER.subprocess, "Popen", side_effect=launch),
                mock.patch.object(RUNNER, "process_identity", return_value=67890),
                mock.patch.object(RUNNER.os, "access", return_value=True),
            ):
                producer.start_guest(guest)

            command = captured["command"]
            self.assertIn("-nodefaults", command)
            self.assertIn(
                f"if=virtio,file={guest_root / 'seed.iso'},format=raw,readonly=on",
                command,
            )
            self.assertFalse(any("ide-cd" in argument for argument in command))
            self.assertEqual(guest.start_ticks, 67890)

    def test_restart_preserves_historical_effect_and_records_actual_current_support(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            (output / "evidence").mkdir(parents=True)
            producer = RUNNER.Producer(self.args(output))
            producer.effect_outcome = "KNOWN_EFFECT_OWNER_SUCCESS"
            producer.guests = [
                RUNNER.Guest("control", 23141, "a", "b", RUNNER.CONTROLLER_ADDRESS, output / "control"),
                RUNNER.Guest("target", 23142, "c", "d", RUNNER.FIXTURE_ADDRESS, output / "target"),
            ]
            for guest in producer.guests:
                guest.root.mkdir()
            originals = []
            artifacts = []
            for guest, name in ((producer.guests[1], "systemd-post-artifact.json"), (producer.guests[0], "http-post-artifact.json")):
                original = output / "evidence" / name
                original.write_bytes(b"artifact\n")
                originals.append((guest, {"artifact_id": name}, original))
            producer.wait_ssh = mock.Mock()
            boot_reads = {"control": iter([b"before-control\n", b"after-control\n"]), "target": iter([b"before-target\n", b"after-target\n"])}
            producer.ssh = mock.Mock(side_effect=lambda guest, command, **kwargs: subprocess.CompletedProcess([], 0, stdout=next(boot_reads[guest.role]) if command.startswith("cat /proc") else b"", stderr=b""))
            producer.export_artifact = mock.Mock(return_value=b"artifact\n")
            producer.execute_diagnostic = mock.Mock(side_effect=[{"artifact_id": "systemd-restart"}, {"artifact_id": "http-restart"}])
            with mock.patch.object(producer, "complete_phase"):
                producer.restart_and_reopen(producer.guests[0], producer.guests[1], originals)
            calls = producer.execute_diagnostic.call_args_list
            self.assertEqual(calls[0].args[-1], "present")
            self.assertEqual(calls[1].args[-1], "unresolved")
            current = json.loads((output / "evidence/current-support-after-restart.json").read_bytes())
            self.assertEqual(current["historical_effect"], "AG_OWNER_RECEIPT_RETAINED")
            self.assertEqual(current["aggregate_postcondition"], "NOT_RECORDED")

    def test_producer_retains_locked_store_cut_and_uses_owner_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            output = pathlib.Path(temporary).resolve()
            (output / "evidence").mkdir()
            binary = (
                output
                / "runtime/ag-package/usr/libexec/agent-governor-ng/ag-effectd"
            )
            binary.parent.mkdir(parents=True)
            binary.write_bytes(self.FIXTURE_AG_AUDIT_BINARY_BYTES)
            binary.chmod(0o755)

            identities, _service, bindings = self.service_records()
            plan = RUNNER.expected_effect_plan(bindings, identities)
            dispatch, work = RUNNER.expected_effect_dispatch("fixture-001", plan)
            outcome = {
                "attempt": dispatch["attempt"],
                "marker": dispatch["marker"],
                "outcome": "success",
                "receipt": "sha256:" + "7" * 64,
            }
            self.write_json(output / "evidence/systemd-plan-v2.json", plan)
            self.write_json(
                output / "evidence/docket-shaped-dispatch-v1.json", dispatch
            )
            self.write_json(output / "evidence/executor-outcome-v1.json", outcome)
            self.write_json(output / "runtime/ag-package/owner-outcome.json", outcome)

            producer = RUNNER.Producer(self.args(output))
            producer.effect_custody = {
                "plan_sha256": RUNNER.digest_file(
                    output / "evidence/systemd-plan-v2.json", "sha256"
                ),
                "dispatch_sha256": RUNNER.digest_file(
                    output / "evidence/docket-shaped-dispatch-v1.json", "sha256"
                ),
                "attempt": dispatch["attempt"],
                "marker": dispatch["marker"],
                "work": work,
                "subject": dispatch["subject"],
                "scope": dispatch["scope"],
                "receipt": outcome["receipt"],
            }
            cut_bytes = b"fixture owner store cut\n"
            cut_sha256 = hashlib.sha256(cut_bytes).hexdigest()
            commands: list[str] = []

            def ssh(_guest, command, **_kwargs):
                commands.append(command)
                return subprocess.CompletedProcess(
                    [],
                    0,
                    stdout=(
                        f"source_sha256={cut_sha256}\n"
                        f"source_bytes={len(cut_bytes)}\n"
                        "wal=ABSENT_OR_ZERO_LENGTH\n"
                    ).encode(),
                    stderr=b"",
                )

            def scp_from(_guest, _source, destination):
                pathlib.Path(destination).write_bytes(cut_bytes)

            producer.ssh = mock.Mock(side_effect=ssh)
            producer.scp_from = mock.Mock(side_effect=scp_from)
            target = RUNNER.Guest(
                "target",
                23142,
                "c",
                "d",
                RUNNER.FIXTURE_ADDRESS,
                output / "target",
            )
            with mock.patch.object(producer, "complete_phase") as completed:
                producer.retain_and_audit_ag_store_cut(target)

            stable_cut = commands[0]
            syntax = subprocess.run(
                ["sh", "-n", "-c", stable_cut],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr.decode())
            self.assertIn("flock --exclusive --timeout 5", stable_cut)
            self.assertIn("PRAGMA wal_checkpoint(TRUNCATE)", stable_cut)
            self.assertIn("test ! -s /var/lib/ag-effectd-m1b/attempts.sqlite-wal", stable_cut)
            record = json.loads((output / "evidence/ag-store-cut.json").read_bytes())
            self.assertEqual(record["store_sha256"], "sha256:" + cut_sha256)
            self.assertEqual(record["owner_package_result"], RUNNER.AG_STORE_AUDIT_RESULT)
            self.assertEqual(record["owner_outcome_sha256"], RUNNER.digest_file(
                output / "evidence/ag-store-audit-outcome-v1.json", "sha256"
            ))
            self.assertEqual(
                producer.effect_custody["ag_store_cut_record_sha256"],
                RUNNER.digest_file(output / "evidence/ag-store-cut.json", "sha256"),
            )
            completed.assert_called_once_with(
                "ag_store_cut_audited", "perform bounded teardown"
            )

    def test_effect_outcome_classes_remain_distinct(self) -> None:
        self.assertEqual(RUNNER.effect_outcome_state("success"), "KNOWN_EFFECT_OWNER_SUCCESS")
        self.assertEqual(RUNNER.effect_outcome_state("failure"), "KNOWN_NO_EFFECT_OWNER_FAILURE")
        self.assertEqual(RUNNER.effect_outcome_state("indeterminate"), "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE")
        with self.assertRaisesRegex(RUNNER.Refusal, "unknown outcome"):
            RUNNER.effect_outcome_state("completed")


    def test_checksum_relation_and_file_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            image = root / "image.qcow2"
            image.write_bytes(b"image")
            digest = hashlib.sha512(b"image").hexdigest()
            checksums = root / "SHA512SUMS"
            checksums.write_text(f"{digest}  image.qcow2\n", encoding="utf-8")
            with mock.patch.object(RUNNER, "IMAGE_NAME", "image.qcow2"), mock.patch.object(RUNNER, "IMAGE_SHA512", digest):
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

    def test_inspection_distinguishes_absent_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            self.write_json(root / "RECOVERY.json", {"schema": "constellation.operator_beta.m1b_recovery.v1", "campaign": RUNNER.CAMPAIGN, "run_id": "fixture-001", "paths": {"run_root": str(root)}, "guests": [{"role": "target", "pid": 999999999, "start_ticks": 1}], "producer": {"main_pid": 999999999}, "phase": "refused", "effect_outcome": "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE", "next_lawful_action": "inspect"})
            with contextlib.redirect_stdout(io.StringIO()):
                observed = RUNNER.inspect_run(root)
            self.assertEqual(observed["producer_state"], "EXITED")
            self.assertEqual(observed["guests"][0]["state"], "EXITED")

    def test_reconcile_refuses_without_exact_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            self.write_json(root / "RECOVERY.json", {"schema": "constellation.operator_beta.m1b_recovery.v1", "campaign": RUNNER.CAMPAIGN, "run_id": "fixture-001", "paths": {"run_root": str(root)}, "guests": [{"role": "target", "pid": 999999999, "start_ticks": 1}], "producer": {"main_pid": 999999999}, "phase": "refused", "effect_outcome": "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE", "next_lawful_action": "inspect"})
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RUNNER.Refusal, "target guest is not active"):
                RUNNER.reconcile_effect(root)

    def test_reconcile_refuses_substituted_owner_outcome_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            (root / "evidence").mkdir(parents=True)
            (root / "runtime").mkdir()
            (root / "target").mkdir()
            identities, service_subject, bindings = self.service_records()
            plan = RUNNER.expected_effect_plan(bindings, identities)
            dispatch, work = RUNNER.expected_effect_dispatch("fixture-001", plan)
            self.write_json(
                root / "evidence/input-receipt.json",
                {
                    "schema": "constellation.operator_beta.m1b_inputs.v1",
                    "run_id": "fixture-001",
                    "harness_subject": "a" * 40,
                    "accepted_package_result": RUNNER.ACCEPTED_PACKAGE_RESULT,
                    "nq_package_sha256": RUNNER.NQ_DEB_SHA256,
                    "ag_package_sha256": RUNNER.AG_DEB_SHA256,
                    "ag_package_version": RUNNER.AG_DEB_VERSION,
                    "ag_store_audit_result": RUNNER.AG_STORE_AUDIT_RESULT,
                    "ag_executable_sha256": RUNNER.AG_EXECUTABLE_SHA256,
                },
            )
            self.write_json(root / "evidence/service-subject.json", service_subject)
            self.write_json(root / "evidence/bindings.json", bindings)
            self.write_json(root / "evidence/guest-identities.json", identities)
            self.write_json(root / "evidence/systemd-plan-v2.json", plan)
            self.write_json(
                root / "evidence/docket-shaped-dispatch-v1.json", dispatch
            )
            (root / f"evidence/{RUNNER.UNIT}").write_bytes(RUNNER.FIXTURE_UNIT_BYTES)
            (root / "evidence/healthz").write_bytes(RUNNER.FIXTURE_HEALTH_BYTES)
            (root / "runtime/id_ed25519").write_bytes(b"key\n")
            (root / "target/known_hosts").write_bytes(b"host\n")
            custody = {
                "plan_sha256": RUNNER.digest_file(
                    root / "evidence/systemd-plan-v2.json", "sha256"
                ),
                "dispatch_sha256": RUNNER.digest_file(
                    root / "evidence/docket-shaped-dispatch-v1.json", "sha256"
                ),
                "attempt": dispatch["attempt"],
                "marker": dispatch["marker"],
                "work": work,
                "subject": dispatch["subject"],
                "scope": dispatch["scope"],
            }
            self.write_json(
                root / "RECOVERY.json",
                {
                    "schema": "constellation.operator_beta.m1b_recovery.v1",
                    "campaign": RUNNER.CAMPAIGN,
                    "run_id": "fixture-001",
                    "harness_subject": "a" * 40,
                    "accepted_package_result": RUNNER.ACCEPTED_PACKAGE_RESULT,
                    "paths": {"run_root": str(root)},
                    "guests": [
                        {
                            "role": "target",
                            "pid": 1234,
                            "start_ticks": 10,
                            "ssh_port": 23142,
                        }
                    ],
                    "producer": {"main_pid": 999999999},
                    "phase": "refused",
                    "effect_outcome": "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE",
                    "effect_custody": custody,
                    "next_lawful_action": "reconcile",
                },
            )
            wrong = {
                "attempt": "sha256:" + "9" * 64,
                "marker": "sha256:" + "8" * 64,
                "outcome": "success",
                "receipt": "sha256:" + "7" * 64,
            }
            completed = [
                subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
                subprocess.CompletedProcess(
                    [], 0, stdout=RUNNER.canonical(wrong) + b"\n", stderr=b""
                ),
            ]
            inspection = {
                "producer_state": "EXITED",
                "guests": [{"role": "target", "state": "ACTIVE"}],
            }
            with (
                mock.patch.object(RUNNER, "inspect_run", return_value=inspection),
                mock.patch.object(RUNNER, "run", side_effect=completed),
                self.assertRaisesRegex(RUNNER.Refusal, "exact retained attempt"),
            ):
                RUNNER.reconcile_effect(root)
            self.assertFalse(
                (root / "evidence/reconciliation-outcome-v1.json").exists()
            )

    def test_reconcile_refuses_fresh_run_attempt_for_same_semantic_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            plan = json.loads((root / "evidence/systemd-plan-v2.json").read_bytes())
            dispatch, work = RUNNER.expected_effect_dispatch("fixture-002", plan)
            self.write_json(
                root / "evidence/docket-shaped-dispatch-v1.json", dispatch
            )
            recovery_path = root / "RECOVERY.json"
            recovery = json.loads(recovery_path.read_bytes())
            recovery.update(
                {
                    "run_id": "fixture-002",
                    "harness_subject": "a" * 40,
                    "effect_outcome": "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE",
                    "guests": [{"role": "target", "pid": 1234, "start_ticks": 10}],
                    "effect_custody": {
                        "plan_sha256": RUNNER.digest_file(
                            root / "evidence/systemd-plan-v2.json", "sha256"
                        ),
                        "dispatch_sha256": RUNNER.digest_file(
                            root / "evidence/docket-shaped-dispatch-v1.json", "sha256"
                        ),
                        "attempt": dispatch["attempt"],
                        "marker": dispatch["marker"],
                        "work": work,
                        "subject": dispatch["subject"],
                        "scope": dispatch["scope"],
                    },
                }
            )
            self.write_json(recovery_path, recovery)
            inspection = {
                "producer_state": "EXITED",
                "guests": [{"role": "target", "state": "ACTIVE"}],
            }
            with (
                mock.patch.object(RUNNER, "inspect_run", return_value=inspection),
                mock.patch.object(RUNNER, "run") as owner_query,
                self.assertRaisesRegex(RUNNER.Refusal, "another run occurrence"),
            ):
                RUNNER.reconcile_effect(root)
            owner_query.assert_not_called()

    def test_terminal_reopen_refuses_coherently_substituted_owner_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            outcome_path = root / "evidence/executor-outcome-v1.json"
            outcome = json.loads(outcome_path.read_bytes())
            outcome["receipt"] = "sha256:" + "9" * 64
            self.write_json(outcome_path, outcome)
            occurrence_path = root / "evidence/effect-occurrence.json"
            occurrence = json.loads(occurrence_path.read_bytes())
            occurrence["outcome"] = outcome
            self.write_json(occurrence_path, occurrence)
            audit_outcome_path = root / "evidence/ag-store-audit-outcome-v1.json"
            self.write_json(audit_outcome_path, outcome)
            store_record_path = root / "evidence/ag-store-cut.json"
            store_record = json.loads(store_record_path.read_bytes())
            store_record["receipt"] = outcome["receipt"]
            store_record["owner_outcome_sha256"] = RUNNER.digest_file(
                audit_outcome_path, "sha256"
            )
            self.write_json(store_record_path, store_record)
            recovery_path = root / "RECOVERY.json"
            recovery = json.loads(recovery_path.read_bytes())
            recovery["effect_custody"].update(
                {
                    "receipt": outcome["receipt"],
                    "outcome_sha256": RUNNER.digest_file(outcome_path, "sha256"),
                    "ag_store_audit_outcome_sha256": RUNNER.digest_file(
                        audit_outcome_path, "sha256"
                    ),
                    "ag_store_cut_record_sha256": RUNNER.digest_file(
                        store_record_path, "sha256"
                    ),
                }
            )
            self.write_json(recovery_path, recovery)
            self.reseal(root)
            with self.assertRaisesRegex(
                RUNNER.Refusal, "owner reopener disagrees"
            ):
                RUNNER.check_run(root)

    def test_terminal_reopen_refuses_coherently_substituted_store_cut(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            cut = root / "evidence/ag-attempt-store-cut.sqlite"
            cut.write_bytes(b"substituted owner store cut\n")
            store_record_path = root / "evidence/ag-store-cut.json"
            store_record = json.loads(store_record_path.read_bytes())
            store_record["store_bytes"] = cut.stat().st_size
            store_record["store_sha256"] = "sha256:" + RUNNER.digest_file(
                cut, "sha256"
            )
            self.write_json(store_record_path, store_record)
            recovery_path = root / "RECOVERY.json"
            recovery = json.loads(recovery_path.read_bytes())
            recovery["effect_custody"].update(
                {
                    "ag_store_cut_bytes": cut.stat().st_size,
                    "ag_store_cut_sha256": RUNNER.digest_file(cut, "sha256"),
                    "ag_store_cut_record_sha256": RUNNER.digest_file(
                        store_record_path, "sha256"
                    ),
                }
            )
            self.write_json(recovery_path, recovery)
            self.reseal(root)
            with self.assertRaisesRegex(
                RUNNER.Refusal, "fixture-owner-store-substitution"
            ):
                RUNNER.check_run(root)

    def test_terminal_reopen_refuses_substituted_owner_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            binary = (
                root
                / "runtime/ag-package/usr/libexec/agent-governor-ng/ag-effectd"
            )
            binary.write_bytes(b"#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            self.reseal(root)
            with self.assertRaisesRegex(RUNNER.Refusal, "accepted package"):
                RUNNER.check_run(root)

    def test_run_reopen_and_semantic_substitutions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                RUNNER.check_run(root)
            self.assertIn("RUN_REOPENED", output.getvalue())
            artifact = root / "evidence/systemd-post-artifact.json"
            changed = json.loads(artifact.read_bytes())
            changed["subject"]["id"] = "sha256:" + "9" * 64
            changed["artifact_id"] = RUNNER.sha256_bytes(RUNNER.canonical({key: value for key, value in changed.items() if key != "artifact_id"}))
            self.write_json(artifact, changed)
            self.reseal(root)
            with self.assertRaisesRegex(RUNNER.Refusal, "wrong subject"):
                RUNNER.check_run(root)

    def test_run_reopen_refuses_missing_required_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            (root / "evidence/target-revocations.json").unlink()
            manifest = json.loads((root / "ARTIFACTS.sha256").read_bytes())
            manifest["files"] = [entry for entry in manifest["files"] if entry["path"] != "evidence/target-revocations.json"]
            (root / "ARTIFACTS.sha256").write_bytes(RUNNER.canonical(manifest) + b"\n")
            result = json.loads((root / "RESULT.json").read_bytes())
            result["manifest_sha256"] = RUNNER.digest_file(root / "ARTIFACTS.sha256", "sha256")
            self.write_json(root / "RESULT.json", result)
            with self.assertRaisesRegex(RUNNER.Refusal, "inventory is incomplete"):
                RUNNER.check_run(root)

    def test_run_reopen_refuses_plan_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            plan_path = root / "evidence/systemd-plan-v2.json"
            plan = json.loads(plan_path.read_bytes())
            plan["scope"] = "sha256:" + "8" * 64
            self.write_json(plan_path, plan)
            self.reseal(root)
            with self.assertRaisesRegex(RUNNER.Refusal, "binding disagrees"):
                RUNNER.check_run(root)

    def test_run_reopen_refuses_resealed_package_content_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            (root / "input/nq-ng_amd64.deb").write_bytes(b"other-package\n")
            self.reseal(root)
            with self.assertRaisesRegex(RUNNER.Refusal, "retained package bytes"):
                RUNNER.check_run(root)

    def test_run_reopen_refuses_coherent_effect_semantic_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            plan_path = root / "evidence/systemd-plan-v2.json"
            plan = json.loads(plan_path.read_bytes())
            plan["effect"]["action"] = "stop"
            plan["effect"]["unit"] = "different.service"
            dispatch, _ = RUNNER.expected_effect_dispatch("fixture-001", plan)
            outcome = {
                "attempt": dispatch["attempt"],
                "marker": dispatch["marker"],
                "outcome": "success",
                "receipt": "sha256:" + "7" * 64,
            }
            occurrence_path = root / "evidence/effect-occurrence.json"
            occurrence = json.loads(occurrence_path.read_bytes())
            occurrence["plan"] = plan
            occurrence["dispatch"] = dispatch
            occurrence["outcome"] = outcome
            self.write_json(plan_path, plan)
            self.write_json(
                root / "evidence/docket-shaped-dispatch-v1.json", dispatch
            )
            self.write_json(root / "evidence/executor-outcome-v1.json", outcome)
            self.write_json(occurrence_path, occurrence)
            self.reseal(root)
            with self.assertRaisesRegex(RUNNER.Refusal, "binding disagrees"):
                RUNNER.check_run(root)

    def test_run_reopen_refuses_coherent_attempt_identity_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            dispatch_path = root / "evidence/docket-shaped-dispatch-v1.json"
            dispatch = json.loads(dispatch_path.read_bytes())
            dispatch["attempt"] = "sha256:" + "9" * 64
            outcome_path = root / "evidence/executor-outcome-v1.json"
            outcome = json.loads(outcome_path.read_bytes())
            outcome["attempt"] = dispatch["attempt"]
            occurrence_path = root / "evidence/effect-occurrence.json"
            occurrence = json.loads(occurrence_path.read_bytes())
            occurrence["dispatch"] = dispatch
            occurrence["outcome"] = outcome
            recovery_path = root / "RECOVERY.json"
            recovery = json.loads(recovery_path.read_bytes())
            recovery["effect_custody"]["attempt"] = dispatch["attempt"]
            self.write_json(dispatch_path, dispatch)
            self.write_json(outcome_path, outcome)
            self.write_json(occurrence_path, occurrence)
            self.write_json(recovery_path, recovery)
            self.reseal(root)
            with self.assertRaisesRegex(RUNNER.Refusal, "binding disagrees"):
                RUNNER.check_run(root)

    def test_run_reopen_refuses_resealed_config_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.fixture_input_identities():
            root = pathlib.Path(temporary).resolve()
            self.make_sealed_run(root)
            config = root / "evidence/target-nq.toml"
            config.write_bytes(config.read_bytes() + b"\n# substituted\n")
            self.reseal(root)
            with self.assertRaisesRegex(RUNNER.Refusal, "configuration differs"):
                RUNNER.check_run(root)


if __name__ == "__main__":
    unittest.main()
